//! `unraid.vm.xml` — export libvirt domain XML for backup.
//!
//! VM definitions live in `libvirt.img`, outside the `unraid-config` backup,
//! so this returns each definition with its checksum for orca to store.
//! Admin-only. Secrets are removed (see [`redact`]), so a restored
//! VM needs them set again. Reads directly when permitted, otherwise through
//! [`PrivilegedOp::ReadVmXml`], which redacts as root so raw XML never leaves
//! it; changes nothing.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use plugin_toolkit::prelude::*;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, Writer, XmlVersion};

use crate::authz::require_admin;
use crate::docker_adopt::privileged::{self, PrivilegedOp};
use crate::schema_pull::sha256_hex;
use crate::vm_autostart::validate_vm_name;
use crate::vm_inventory::inventory;

pub(crate) const QEMU_DIR: &str = "/etc/libvirt/qemu";

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidVmXmlArgs {
    /// Export only this VM; all defined VMs when omitted.
    #[arg(long)]
    #[serde(default)]
    pub vm: Option<String>,
}

/// Attributes removed from every element, matched on the local name so
/// namespaced keys are caught too.
const SECRET_ATTRS: &[&str] = &["passwd", "password"];
/// Elements whose every attribute but `type` is a credential or a reference
/// to one (libvirt `<auth username=…>`, `<secret uuid=…|usage=…>`).
const SECRET_ELEMENTS: &[&str] = &["auth", "secret"];
/// Inline credentials in URLs and option strings.
const SECRET_VALUE_MARKERS: &[&str] = &["password=", "token=", "secret="];

/// XML with its secrets removed.
#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct Redacted {
    pub xml: String,
    /// True when anything was removed.
    pub redacted: bool,
}

fn is_secret(element: &str, attr: &str, value: &str, in_cmdline: bool) -> bool {
    let lower = value.to_ascii_lowercase();
    SECRET_ATTRS.contains(&attr)
        || (SECRET_ELEMENTS.contains(&element) && attr != "type")
        // `<source query=…>` is a network disk URL query, which can carry auth.
        || (element == "source" && attr == "query")
        // `<qemu:arg value=…>` / `<qemu:env value=…>` pass raw QEMU options,
        // which can carry passwords.
        || (in_cmdline && attr == "value")
        || SECRET_VALUE_MARKERS.iter().any(|m| lower.contains(m))
}

fn strip(e: &BytesStart, in_cmdline: bool, hit: &mut bool) -> Result<BytesStart<'static>> {
    let name = e.name().into_inner().to_string();
    let element = e.local_name().into_inner().to_string();
    let mut out = BytesStart::new(name);
    for a in e.attributes().with_checks(true) {
        let a = a.map_err(|err| anyhow!("malformed attribute: {err}"))?;
        let key = a.key.into_inner().to_string();
        let local = a.key.local_name().into_inner().to_string();
        let value = a
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|err| anyhow!("malformed attribute {key}: {err}"))?;
        if is_secret(&element, &local, &value, in_cmdline) {
            *hit = true;
            continue;
        }
        out.push_attribute((key.as_str(), value.as_ref()));
    }
    Ok(out)
}

/// Text of these elements is a credential or free-form host data.
fn drops_text(open: &[String]) -> bool {
    match open {
        [.., last] if last == "cookie" => true,
        [.., parent, last] => parent == "oemStrings" && last == "entry",
        _ => false,
    }
}

/// Remove secrets, by a real XML tokenizer: console passwords,
/// `<auth>`/`<secret>` references, `qemu:commandline` values, network disk
/// queries, inline `password=`/`token=`/`secret=` values, `<cookie>` and
/// `<oemStrings><entry>` text and the whole `<metadata>` subtree (arbitrary
/// application data). Unparseable XML is an error, never returned
/// unredacted. Unchanged input is returned byte for byte.
pub(crate) fn redact(xml: &str) -> Result<Redacted> {
    let mut reader = Reader::from_str(xml);
    let mut writer = Writer::new(Vec::with_capacity(xml.len()));
    let mut hit = false;
    let mut open: Vec<String> = Vec::new();
    let mut skip_depth = 0usize;
    loop {
        let ev = reader.read_event().map_err(|e| {
            anyhow!(
                "VM XML does not parse at byte {}: {e}",
                reader.error_position()
            )
        })?;
        if skip_depth > 0 {
            match ev {
                Event::Start(_) => skip_depth += 1,
                Event::End(_) => skip_depth -= 1,
                Event::Eof => bail!("VM XML ends inside <metadata>"),
                _ => {}
            }
            continue;
        }
        let in_cmdline = open.iter().any(|n| n == "commandline");
        let out = match ev {
            Event::Eof => break,
            Event::Start(e) => {
                let local = e.local_name().into_inner().to_string();
                if local == "metadata" {
                    hit = true;
                    skip_depth = 1;
                    continue;
                }
                let inside = in_cmdline || local == "commandline";
                open.push(local);
                Event::Start(strip(&e, inside, &mut hit)?)
            }
            Event::Empty(e) => {
                let local = e.local_name().into_inner();
                if local == "metadata" {
                    hit = true;
                    continue;
                }
                let inside = in_cmdline || local == "commandline";
                Event::Empty(strip(&e, inside, &mut hit)?)
            }
            Event::End(e) => {
                open.pop();
                Event::End(e)
            }
            Event::Text(_) | Event::CData(_) if drops_text(&open) => {
                hit = true;
                continue;
            }
            other => other,
        };
        writer
            .write_event(out)
            .map_err(|e| anyhow!("re-encode VM XML: {e}"))?;
    }
    if !hit {
        return Ok(Redacted {
            xml: xml.to_string(),
            redacted: false,
        });
    }
    let xml = String::from_utf8(writer.into_inner()).context("re-encoded VM XML")?;
    Ok(Redacted {
        xml,
        redacted: true,
    })
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VmXml {
    pub name: String,
    pub autostart: bool,
    pub xml: String,
    /// Hex sha256 of `xml` as returned, for checksum-verified backup.
    pub sha256: String,
    /// True when secrets were removed from `xml`.
    pub redacted: bool,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VmXmlOutput {
    pub vms: Vec<VmXml>,
}

/// Names to export: `only` (validated, must be defined) or every defined VM.
pub(crate) fn select(qemu_dir: &str, only: Option<&str>) -> Result<Vec<(String, bool)>> {
    let all: Vec<(String, bool)> = inventory(qemu_dir)
        .map_err(|e| anyhow!(e))?
        .into_iter()
        .map(|v| (v.name, v.autostart))
        .collect();
    match only {
        None => Ok(all),
        Some(name) => {
            validate_vm_name(name)?;
            let hit: Vec<_> = all.into_iter().filter(|(n, _)| n == name).collect();
            if hit.is_empty() {
                bail!("no VM named '{name}'");
            }
            Ok(hit)
        }
    }
}

/// `Ok(None)` when the file needs root to read.
pub(crate) fn read_direct(qemu_dir: &str, name: &str) -> Result<Option<String>> {
    match fs::read_to_string(Path::new(qemu_dir).join(format!("{name}.xml"))) {
        Ok(x) => Ok(Some(x)),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Ok(None),
        Err(e) => Err(anyhow!("read {name}.xml: {e}")),
    }
}

pub(crate) fn entry(name: String, autostart: bool, r: Redacted) -> VmXml {
    VmXml {
        sha256: sha256_hex(r.xml.as_bytes()),
        redacted: r.redacted,
        name,
        autostart,
        xml: r.xml,
    }
}

/// [`PrivilegedOp::ReadVmXml`]'s root side: read and redact before replying.
pub(crate) fn read_redacted_as_root(name: &str) -> Result<String> {
    use crate::docker_adopt::safefs;
    validate_vm_name(name)?;
    let path = Path::new(QEMU_DIR).join(format!("{name}.xml"));
    let raw =
        safefs::read_file(&path)?.ok_or_else(|| anyhow!("no VM definition {}", path.display()))?;
    let raw = String::from_utf8(raw).context("VM XML is not UTF-8")?;
    Ok(plugin_toolkit::serde_json::to_string(&redact(&raw)?)?)
}

/// Export this machine's libvirt VM definitions with checksums. Read-only.
#[orca_tool(domain = "unraid", verb = "vm.xml", role = "admin", reaches = ["privileged.apply"])]
async fn unraid_vm_xml(args: UnraidVmXmlArgs, ctx: &ToolCtx) -> Result<VmXmlOutput> {
    require_admin("unraid.vm.xml", ctx.caller().as_ref())?;
    crate::vm_availability::require().await?;
    let mut vms = Vec::new();
    for (name, autostart) in select(QEMU_DIR, args.vm.as_deref())? {
        let r = match read_direct(QEMU_DIR, &name)? {
            Some(x) => redact(&x)?,
            None => {
                let runner = privileged::runner()
                    .ok_or_else(|| anyhow!(privileged::missing_runner_blocker()))?;
                let reply = runner
                    .run(&PrivilegedOp::ReadVmXml { name: name.clone() })
                    .await?;
                plugin_toolkit::serde_json::from_str(&reply).context("decode redacted VM XML")?
            }
        };
        vms.push(entry(name, autostart, r));
    }
    Ok(VmXmlOutput { vms })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeRoot;

    fn qemu() -> FakeRoot {
        let r = FakeRoot::new("vmxml");
        r.write("pbs.xml", "<domain><name>pbs</name></domain>")
            .write("ha.xml", "<domain><name>ha</name></domain>")
            .write("autostart/pbs.xml", "");
        r
    }

    #[test]
    fn selects_all_or_one_and_refuses_unknown_or_unsafe() {
        let r = qemu();
        assert_eq!(
            select(r.str(), None).unwrap(),
            [("ha".to_string(), false), ("pbs".to_string(), true)]
        );
        assert_eq!(select(r.str(), Some("pbs")).unwrap().len(), 1);
        assert!(select(r.str(), Some("nope")).is_err());
        assert!(select(r.str(), Some("../pbs")).is_err());
    }

    #[test]
    fn reads_and_checksums_definitions() {
        let r = qemu();
        let xml = read_direct(r.str(), "pbs").unwrap().unwrap();
        let e = entry("pbs".into(), true, redact(&xml).unwrap());
        assert_eq!(e.xml, "<domain><name>pbs</name></domain>");
        assert!(!e.redacted);
        assert_eq!(e.sha256, sha256_hex(xml.as_bytes()));
        assert_eq!(e.sha256.len(), 64);
        assert!(read_direct(r.str(), "missing").is_err());
    }

    #[test]
    fn privileged_read_op_wire_form() {
        let v =
            plugin_toolkit::serde_json::to_value(PrivilegedOp::ReadVmXml { name: "pbs".into() })
                .unwrap();
        assert_eq!(v["op"], "read_vm_xml");
        assert_eq!(v["payload"]["name"], "pbs");
    }

    #[test]
    fn only_root_may_read_vm_xml() {
        let op = PrivilegedOp::ReadVmXml { name: "pbs".into() };
        let passwd = "orca:x:1000:100::/h:/bin/sh\n";
        let group = "docker:x:281:orca\n";
        assert!(privileged::authorize(&op, 0, passwd, group).is_ok());
        assert!(privileged::authorize(&op, 1000, passwd, group).is_err());
    }

    #[test]
    fn passwd_attributes_are_removed_not_replaced() {
        let r = redact(
            "<devices><graphics type='vnc' port='-1' passwd='s3cret'/>\
<graphics type=\"spice\" passwd = \"p@ss\" autoport='yes'/></devices>",
        )
        .unwrap();
        assert!(r.redacted);
        assert!(!r.xml.contains("passwd"), "{}", r.xml);
        assert!(!r.xml.contains("s3cret") && !r.xml.contains("p@ss"));
        assert!(r.xml.contains("autoport=\"yes\"") && r.xml.contains("port=\"-1\""));
        let e = entry("ha".into(), false, r);
        assert_eq!(e.sha256, sha256_hex(e.xml.as_bytes()));
    }

    #[test]
    fn lookalike_attributes_are_kept() {
        let src = "<g mypasswd='keep' passwdx='keep'/>";
        let r = redact(src).unwrap();
        assert!(!r.redacted);
        assert_eq!(r.xml, src);
    }

    #[test]
    fn auth_and_secret_attributes_are_removed_but_not_domain_uuid() {
        let r = redact(
            "<domain><uuid>u-1</uuid><disk><auth username='admin'>\
<secret type='ceph' uuid='s-1' usage='pool'/></auth></disk>\
<source pool='p' password=\"pw\"/><x uuid='keep'/></domain>",
        )
        .unwrap();
        assert!(r.redacted);
        for leaked in ["admin", "s-1", "\"pool\"", "pw"] {
            assert!(!r.xml.contains(leaked), "{leaked} in {}", r.xml);
        }
        assert!(r.xml.contains("type=\"ceph\"") && r.xml.contains("uuid=\"keep\""));
        assert!(r.xml.contains("<uuid>u-1</uuid>"), "{}", r.xml);
    }

    #[test]
    fn qemu_commandline_values_are_removed() {
        let r = redact(
            "<domain xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>\
<qemu:commandline><qemu:arg value='-vnc'/>\
<qemu:arg value='password=hunter2'/><qemu:env name='K' value='tok'/>\
</qemu:commandline><x value='keep'/></domain>",
        )
        .unwrap();
        assert!(r.redacted);
        assert!(
            !r.xml.contains("hunter2") && !r.xml.contains("tok"),
            "{}",
            r.xml
        );
        assert!(r.xml.contains("name=\"K\""), "{}", r.xml);
        assert!(r.xml.contains("<x value=\"keep\"/>"), "{}", r.xml);
    }

    #[test]
    fn namespaced_password_keys_are_removed() {
        let r = redact("<d xmlns:x='urn:x'><g x:passwd='a1' x:Password='keep'/></d>").unwrap();
        assert!(r.redacted);
        assert!(!r.xml.contains("a1"), "{}", r.xml);
    }

    #[test]
    fn source_query_and_inline_credentials_are_removed() {
        let r = redact(
            "<d><source protocol='http' name='/i' query='a=1'/>\
<x url='https://h/?TOKEN=t1'/><y opt='Password=p1'/><z opt='Secret=s1'/>\
<w a='keep'/></d>",
        )
        .unwrap();
        assert!(r.redacted);
        for leaked in ["a=1", "t1", "p1", "s1"] {
            assert!(!r.xml.contains(leaked), "{leaked} in {}", r.xml);
        }
        assert!(r.xml.contains("protocol=\"http\"") && r.xml.contains("a=\"keep\""));
    }

    #[test]
    fn cookie_and_oem_entry_text_is_removed() {
        let r = redact(
            "<d><cookie>c00kie</cookie><sysinfo type='smbios'><oemStrings>\
<entry>oem-secret</entry></oemStrings><entry>keep</entry></sysinfo></d>",
        )
        .unwrap();
        assert!(r.redacted);
        assert!(
            !r.xml.contains("c00kie") && !r.xml.contains("oem-secret"),
            "{}",
            r.xml
        );
        assert!(r.xml.contains("<cookie></cookie>"), "{}", r.xml);
        assert!(r.xml.contains("<entry>keep</entry>"), "{}", r.xml);
    }

    #[test]
    fn metadata_subtree_is_removed() {
        let r = redact(
            "<d><metadata><app:x xmlns:app='urn:a'><k>v1</k></app:x></metadata>\
<name>n</name><metadata/></d>",
        )
        .unwrap();
        assert!(r.redacted);
        assert_eq!(r.xml, "<d><name>n</name></d>");
        assert!(redact("<d><metadata><k>v").is_err());
    }

    #[test]
    fn malformed_xml_fails_closed() {
        for bad in [
            "<g passwd='open/><x passwd='secret'/>",
            "<g a=unquoted passwd='secret'/>",
            "<g passwd='secret'",
            "<a><b></a>",
        ] {
            assert!(redact(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn requires_admin_in_the_body() {
        for role in [Some("user"), None] {
            let args = UnraidVmXmlArgs { vm: None };
            let ctx = crate::authz::test_ctx(role);
            let e = plugin_toolkit::reactor::block_on(unraid_vm_xml(args, &ctx)).unwrap_err();
            assert!(e.to_string().contains("unraid.vm.xml: "), "{e}");
        }
    }
}
