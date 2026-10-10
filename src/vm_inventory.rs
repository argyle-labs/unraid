//! Read-only inventory of libvirt VM definitions and their autostart flags.
//!
//! libvirt keeps one `<name>.xml` per defined domain in `/etc/libvirt/qemu` and
//! marks autostart with a same-named entry under `autostart/`. On Unraid that
//! directory lives inside `libvirt.img` on the array, not under `/boot/config`,
//! so the `unraid-config` backup kind does not capture VM definitions.
//!
//! The directory is only read when the libvirt image is mounted there: without
//! the mount it is an empty placeholder on the root fs, and the readdir must
//! not reach toward an array that may be stopped.

use std::fs;
use std::path::Path;

use plugin_toolkit::contract::diagnostics::{Finding, Severity};

use crate::checks::finding;
use crate::libvirt_stack::LibvirtStack;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VmDef {
    pub name: String,
    pub autostart: bool,
}

/// `*.xml` stems in `dir`. A missing directory is empty; any other read
/// failure is an error, so an unreadable tree never reads as "no VMs".
fn xml_stems(dir: &Path) -> Result<Vec<String>, String> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("read {}: {e}", dir.display())),
    };
    let mut v: Vec<String> = rd
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.strip_suffix(".xml").map(str::to_string)
        })
        .collect();
    v.sort();
    Ok(v)
}

pub(crate) fn inventory(qemu_dir: &str) -> Result<Vec<VmDef>, String> {
    let dir = Path::new(qemu_dir);
    let auto = xml_stems(&dir.join("autostart"))?;
    Ok(xml_stems(dir)?
        .into_iter()
        .map(|name| VmDef {
            autostart: auto.contains(&name),
            name,
        })
        .collect())
}

pub(crate) fn check(proc_root: &str, run_dir: &str, qemu_dir: &str) -> Vec<Finding> {
    if crate::libvirt_stack::probe(proc_root, run_dir) == LibvirtStack::ImageNotMounted {
        return Vec::new();
    }
    let vms = match inventory(qemu_dir) {
        Ok(v) => v,
        Err(e) => {
            return vec![finding(
                "vm-inventory",
                Severity::Warn,
                "VM definitions unreadable",
                format!("{e}. VM definitions could not be listed, so they are unverified."),
                None,
            )];
        }
    };
    if vms.is_empty() {
        return Vec::new();
    }
    let list = vms
        .iter()
        .map(|v| {
            format!(
                "{}{}",
                v.name,
                if v.autostart { " (autostart)" } else { "" }
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    vec![finding(
        "vm-inventory",
        Severity::Info,
        "Defined VMs",
        format!(
            "{} VM(s): {list}. Their definitions live in libvirt.img, which the unraid-config \
             backup does not include.",
            vms.len()
        ),
        None,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_support::FakeRoot;

    const MOUNTED: &str = "/dev/loop3 /etc/libvirt btrfs rw 0 0\n";

    fn fake(mounts: &str) -> FakeRoot {
        let r = FakeRoot::new("qemu");
        r.write("mounts", mounts)
            .mkdir("run")
            .mkdir("qemu/autostart")
            .mkdir("qemu/networks");
        for n in ["pbs.xml", "Home Assistant.xml", "notes.txt"] {
            r.write(&format!("qemu/{n}"), "<domain/>");
        }
        r.write("qemu/autostart/pbs.xml", "");
        r
    }

    fn run(r: &FakeRoot) -> Vec<Finding> {
        check(
            r.str(),
            &format!("{}/run", r.str()),
            &format!("{}/qemu", r.str()),
        )
    }

    #[test]
    fn lists_domains_with_autostart_flags() {
        let r = fake(MOUNTED);
        let inv = inventory(&format!("{}/qemu", r.str())).unwrap();
        assert_eq!(
            inv,
            [
                VmDef {
                    name: "Home Assistant".into(),
                    autostart: false
                },
                VmDef {
                    name: "pbs".into(),
                    autostart: true
                },
            ]
        );
        let f = run(&r);
        assert_eq!(f[0].severity, Severity::Info);
        assert!(f[0].detail.contains("pbs (autostart)"));
        assert!(f[0].detail.contains("backup does not include"));
    }

    #[test]
    fn unmounted_libvirt_image_is_not_read() {
        assert!(run(&fake("")).is_empty());
    }

    #[test]
    fn unreadable_dir_is_an_error_not_empty() {
        let r = fake(MOUNTED);
        // A file where the directory should be: read_dir fails, not NotFound.
        r.write("notadir", "x");
        assert!(inventory(&format!("{}/notadir", r.str())).is_err());
        assert_eq!(inventory("/nonexistent/qemu").unwrap(), []);
        let f = check(
            r.str(),
            &format!("{}/run", r.str()),
            &format!("{}/notadir", r.str()),
        );
        assert_eq!(f[0].severity, Severity::Warn);
        assert!(f[0].detail.contains("unverified"));
    }
}
