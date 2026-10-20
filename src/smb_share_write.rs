//! `unraid.smb.share.set` — set a user share's SMB security and user lists.
//!
//! An SMB share lives in two places that must agree:
//! `/boot/config/shares/<name>.cfg` (persistent intent) and the live `[<name>]` section of `/etc/samba/smb-shares.conf`. [`apply_in`] writes
//! the cfg first, then only the access keys of the existing section (every
//! other line is kept), then reloads smbd; if the conf write or the reload
//! fails, both files are put back as they were. A share with no live section
//! is refused: rendering a whole section is Unraid's job. emhttp regenerates
//! `smb-shares.conf` from the cfgs (e.g. on array start or a share edit in the
//! web UI); the cfg is written first, so a regeneration settles on the same
//! settings.
//!
//! Dry-run by default, admin required for both (see [`crate::authz`]). Both
//! files are root-only, so the write runs as [`PrivilegedOp::SetSmbShare`],
//! which re-validates everything.

use std::future::Future;
use std::path::Path;

use plugin_toolkit::prelude::*;

use crate::authz::require_admin;
use crate::docker_adopt::host;
use crate::docker_adopt::privileged::{self, PrivilegedOp};
use crate::docker_adopt::safefs;
use crate::exports::UnraidExports;
use crate::smb_shares::SHARES_CONF;

const SMBCONTROL: &str = "/usr/bin/smbcontrol";
/// Bounds the request (and the conf line it renders) per list.
pub(crate) const MAX_USERS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Security {
    Public,
    Secure,
    Private,
}

impl Security {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "public" => Ok(Self::Public),
            "secure" => Ok(Self::Secure),
            "private" => Ok(Self::Private),
            _ => bail!("invalid security '{s}'; expected public, secure or private"),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Secure => "secure",
            Self::Private => "private",
        }
    }
}

/// User names as Unraid creates them: a lowercase letter, then lowercase
/// letters, digits, '_', '-' or '.'.
pub(crate) fn validate_user(u: &str) -> Result<()> {
    let ok = u.len() <= 32
        && u.bytes().next().is_some_and(|c| c.is_ascii_lowercase())
        && u.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-' | b'.')
        });
    if !ok {
        bail!("invalid user name '{u}'");
    }
    Ok(())
}

/// Unraid share names may contain spaces. Anything that would escape the cfg
/// file name or the `[name]` header (separators, brackets, quotes, control
/// characters, a leading dot) is refused.
pub(crate) fn validate_share_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with(['.', ' '])
        && !name.ends_with(' ')
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.' | '+' | '(' | ')')
        });
    if !ok {
        bail!("invalid share name '{name}'");
    }
    Ok(())
}

/// One validated change; built identically on both sides of the privilege
/// boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SmbShareRequest {
    pub share: String,
    pub security: Security,
    pub read_list: Vec<String>,
    pub write_list: Vec<String>,
}

impl SmbShareRequest {
    pub fn new(
        share: &str,
        security: &str,
        read_list: &[String],
        write_list: &[String],
    ) -> Result<Self> {
        validate_share_name(share)?;
        let security = Security::parse(security)?;
        for (what, list) in [("readList", read_list), ("writeList", write_list)] {
            if list.len() > MAX_USERS {
                bail!(
                    "{what} has {} users; at most {MAX_USERS} are allowed",
                    list.len()
                );
            }
        }
        for u in read_list.iter().chain(write_list) {
            validate_user(u)?;
        }
        match security {
            Security::Public if !read_list.is_empty() || !write_list.is_empty() => {
                bail!("public shares admit everyone; readList and writeList would be ignored")
            }
            Security::Secure if !read_list.is_empty() => {
                bail!("secure shares are readable by everyone; readList would be ignored")
            }
            Security::Private if read_list.is_empty() && write_list.is_empty() => {
                bail!("private needs at least one user in readList or writeList")
            }
            _ => {}
        }
        Ok(Self {
            share: share.to_string(),
            security,
            read_list: read_list.to_vec(),
            write_list: write_list.to_vec(),
        })
    }

    fn cfg_updates(&self) -> Vec<(&'static str, String)> {
        vec![
            ("shareSecurity", self.security.as_str().to_string()),
            ("shareReadList", self.read_list.join(",")),
            ("shareWriteList", self.write_list.join(",")),
        ]
    }

    /// The access lines the `[share]` section gets, Unraid's mapping of each mode.
    pub fn access_lines(&self) -> Vec<String> {
        let (read, write) = (&self.read_list, &self.write_list);
        let mut v = Vec::new();
        match self.security {
            Security::Public => {
                v.push("public = yes".into());
                v.push("writeable = yes".into());
            }
            Security::Secure => {
                v.push("public = yes".into());
                v.push("writeable = no".into());
                if !write.is_empty() {
                    v.push(format!("write list = {}", write.join(",")));
                }
            }
            Security::Private => {
                let mut valid: Vec<&str> = read.iter().chain(write).map(String::as_str).collect();
                valid.sort_unstable();
                valid.dedup();
                v.push("public = no".into());
                v.push("writeable = no".into());
                v.push(format!("valid users = {}", valid.join(",")));
                if !write.is_empty() {
                    v.push(format!("write list = {}", write.join(",")));
                }
            }
        }
        v
    }
}

/// Every key that grants or restricts access or visibility, in
/// [`normalize_key`] form (Samba ignores case, spaces and `_` in names, and
/// accepts synonyms); all are replaced so no stale line can contradict the
/// requested mode.
const ACCESS_KEYS: &[&str] = &[
    "public",
    "guestok",
    "guestonly",
    "onlyuser",
    "writeable",
    "writable",
    "writeok",
    "readonly",
    "validusers",
    "invalidusers",
    "writelist",
    "readlist",
    "username",
    "user",
    "users",
    "adminusers",
    "forceuser",
    "forcegroup",
];

fn normalize_key(k: &str) -> String {
    k.chars()
        .filter(|c| !c.is_whitespace() && *c != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

/// Replace the access keys of `[share]` (matched case-insensitively, as Samba
/// does) in `conf`, keeping every other line. A trailing `\` continues a
/// line, so a removed key's continuation lines go with it.
pub(crate) fn rewrite_section(conf: &str, share: &str, access: &[String]) -> Result<String> {
    let header = share.to_ascii_lowercase();
    let mut out: Vec<String> = Vec::new();
    let (mut found, mut inside) = (false, false);
    let mut continued: Option<bool> = None;
    for line in conf.lines() {
        let t = line.trim();
        let continues = t.ends_with('\\');
        if let Some(drop) = continued {
            continued = continues.then_some(drop);
            if !drop {
                out.push(line.to_string());
            }
            continue;
        }
        if let Some(name) = t.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            inside = name.trim().to_ascii_lowercase() == header;
            out.push(line.to_string());
            if inside {
                found = true;
                out.extend(access.iter().map(|a| format!("\t{a}")));
            }
            continue;
        }
        let drop = inside
            && t.split_once('=')
                .is_some_and(|(k, _)| ACCESS_KEYS.contains(&normalize_key(k).as_str()));
        continued = continues.then_some(drop);
        if !drop {
            out.push(line.to_string());
        }
    }
    if !found {
        bail!("share '{share}' has no section in {SHARES_CONF}: enable SMB on it in Unraid first");
    }
    let mut s = out.join("\n");
    s.push('\n');
    Ok(s)
}

/// Permission bits of `path` (not following a symlink), to write it back with.
fn file_mode(path: &Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    let m = std::fs::symlink_metadata(path).map_err(|e| anyhow!("stat {}: {e}", path.display()))?;
    Ok(m.permissions().mode() & 0o7777)
}

/// Apply `req` to the cfg at `cfg` and the conf at `conf`, then `reload`.
/// The Unraid GraphQL API has no share mutation, so both files are edited.
/// Nothing is written until both new contents are computed; both files keep
/// their modes; a failed conf write or reload restores both files.
pub(crate) async fn apply_in<F, Fut>(
    cfg: &Path,
    conf: &Path,
    req: &SmbShareRequest,
    reload: F,
) -> Result<Vec<String>>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let old_cfg = safefs::read_file(cfg)?
        .ok_or_else(|| anyhow!("share '{}' has no config at {}", req.share, cfg.display()))?;
    let new_cfg =
        UnraidExports::write_cfg_keys(&String::from_utf8_lossy(&old_cfg), &req.cfg_updates());
    let old_conf =
        safefs::read_file(conf)?.ok_or_else(|| anyhow!("{} is missing", conf.display()))?;
    let access = req.access_lines();
    let new_conf = rewrite_section(&String::from_utf8_lossy(&old_conf), &req.share, &access)?;

    let (cfg_mode, conf_mode) = (file_mode(cfg)?, file_mode(conf)?);
    safefs::replace_file(cfg, new_cfg.as_bytes(), cfg_mode)?;
    let restore = |what: &str,
                   e: plugin_toolkit::anyhow::Error,
                   conf_too: bool|
     -> plugin_toolkit::anyhow::Error {
        let mut undo = safefs::replace_file(cfg, &old_cfg, cfg_mode).err();
        if conf_too {
            undo = undo.or(safefs::replace_file(conf, &old_conf, conf_mode).err());
        }
        match undo {
            None => anyhow!("{what} failed, both files restored: {e}"),
            Some(u) => anyhow!("{what} failed ({e}) AND the restore failed: {u}"),
        }
    };
    if let Err(e) = safefs::replace_file(conf, new_conf.as_bytes(), conf_mode) {
        return Err(restore("writing the smb conf", e, false));
    }
    if let Err(e) = reload().await {
        return Err(restore("reloading smbd", e, true));
    }
    Ok(access)
}

/// `smbcontrol smbd reload-config`, run as root by the privileged op.
pub(crate) async fn reload_smbd() -> Result<()> {
    host::run(SMBCONTROL, &["smbd", "reload-config"]).await?;
    Ok(())
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidSmbShareSetArgs {
    /// User share name (`/mnt/user/<share>`); may contain spaces.
    #[arg(long)]
    pub share: String,
    /// public | secure | private.
    #[arg(long)]
    pub security: String,
    /// Read-only users (private only).
    #[arg(long)]
    #[serde(default)]
    pub read_list: Vec<String>,
    /// Users with write access (secure and private).
    #[arg(long)]
    #[serde(default)]
    pub write_list: Vec<String>,
    /// Apply the change. Without it the call only reports what it would do.
    #[arg(long, default_value_t = false)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SmbShareSetOutput {
    pub share: String,
    pub security: String,
    /// The access lines the live section gets.
    pub access: Vec<String>,
    /// The root side's report; empty for a dry run.
    pub applied: String,
    pub executed: bool,
}

/// The validated request and the privileged op that applies it.
pub(crate) fn op_for(args: &UnraidSmbShareSetArgs) -> Result<(SmbShareRequest, PrivilegedOp)> {
    let req = SmbShareRequest::new(
        &args.share,
        &args.security,
        &args.read_list,
        &args.write_list,
    )?;
    let op = PrivilegedOp::SetSmbShare {
        share: args.share.clone(),
        security: args.security.clone(),
        read_list: args.read_list.clone(),
        write_list: args.write_list.clone(),
    };
    Ok((req, op))
}

/// Validate `args` and check the share has a section in the live table at
/// `conf` (world-readable), so a missing section fails in the dry run rather
/// than only once root runs the write.
pub(crate) fn plan_in(
    conf: &Path,
    args: &UnraidSmbShareSetArgs,
) -> Result<(SmbShareRequest, PrivilegedOp)> {
    let (req, op) = op_for(args)?;
    let text =
        std::fs::read_to_string(conf).map_err(|e| anyhow!("read {}: {e}", conf.display()))?;
    rewrite_section(&text, &req.share, &req.access_lines())?;
    Ok((req, op))
}

/// Set an SMB share's security and user lists. Dry-run unless `execute:
/// true`; admin is required for both.
#[orca_tool(
    domain = "unraid",
    verb = "smb.share.set",
    role = "admin",
    execute_gated = false,
    reaches = ["privileged.apply"]
)]
async fn unraid_smb_share_set(
    args: UnraidSmbShareSetArgs,
    ctx: &ToolCtx,
) -> Result<SmbShareSetOutput> {
    require_admin("unraid.smb.share.set", ctx.caller().as_ref())?;
    let (req, op) = plan_in(Path::new(SHARES_CONF), &args)?;
    let applied = if args.execute {
        let runner =
            privileged::runner().ok_or_else(|| anyhow!(privileged::missing_runner_blocker()))?;
        runner.run(&op).await?
    } else {
        String::new()
    };
    Ok(SmbShareSetOutput {
        share: args.share,
        security: args.security,
        access: req.access_lines(),
        applied,
        executed: args.execute,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smb_shares::parse;
    use crate::test_support::FakeRoot;
    use std::fs;

    const CONF: &str = "\
[global]
\tworkgroup = WORKGROUP
[Data]
\tpath = /mnt/user/Data
\tbrowseable = yes
\tpublic = yes
\twriteable = yes
\tguest only = yes
\twrite ok = yes
\tvfs objects = catia fruit streams_xattr
[My Media]
\tpath = /mnt/user/My Media
\tpublic = yes
\twriteable = yes
";

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn req(share: &str, sec: &str, r: &[&str], w: &[&str]) -> SmbShareRequest {
        SmbShareRequest::new(share, sec, &s(r), &s(w)).unwrap()
    }

    fn apply(
        cfg: &Path,
        conf: &Path,
        req: &SmbShareRequest,
        reload: &dyn Fn() -> Result<()>,
    ) -> Result<Vec<String>> {
        plugin_toolkit::reactor::block_on(apply_in(cfg, conf, req, || {
            let r = reload();
            async move { r }
        }))
    }

    fn fake() -> FakeRoot {
        let f = FakeRoot::new("smbw");
        f.write(
            "shares/Data.cfg",
            "shareComment=\"x\"\nshareSecurity=\"public\"\n",
        )
        .write("smb-shares.conf", CONF);
        f
    }

    #[test]
    fn section_match_is_case_insensitive_and_clears_every_access_key() {
        let r = req("data", "private", &["ro"], &["scott"]);
        let out = rewrite_section(CONF, "data", &r.access_lines()).unwrap();
        assert!(!out.contains("guest only") && !out.contains("write ok"));
        assert!(out.contains("vfs objects = catia fruit streams_xattr"));
        assert!(out.contains("browseable = yes"));
        let shares = parse(&out);
        let data = shares.iter().find(|x| x.name == "Data").unwrap();
        assert_eq!(data.mode(), "private");
        assert_eq!(data.write_list, ["scott"]);
        let media = shares.iter().find(|x| x.name == "My Media").unwrap();
        assert_eq!(media.mode(), "public", "other sections untouched");
    }

    #[test]
    fn synonyms_underscores_and_continuations_are_cleared() {
        let conf = "[Data]\n\tpath = /mnt/user/Data\n\tGuest_OK = yes\n\tvalid_users = a\n\
\tread_only = no\n\tforce user = root\n\tadmin users = \\\n\t  eve,\\\n\t  mallory\n\
\tusername = x\n\tcomment = keep \\\n\t  valid users = also kept\n\
\tvfs objects = fruit\n[Other]\n\tread only = no\n";
        let r = req("Data", "public", &[], &[]);
        let out = rewrite_section(conf, "Data", &r.access_lines()).unwrap();
        for gone in [
            "Guest_OK",
            "valid_users",
            "read_only",
            "force user",
            "eve",
            "mallory",
            "username",
        ] {
            assert!(!out.contains(gone), "{gone} in {out}");
        }
        assert!(
            out.contains("comment = keep \\\n\t  valid users = also kept"),
            "{out}"
        );
        assert!(out.contains("vfs objects = fruit") && out.contains("path = /mnt/user/Data"));
        assert!(out.contains("[Other]\n\tread only = no"), "{out}");
    }

    #[test]
    fn share_names_with_spaces_are_accepted_unsafe_ones_refused() {
        let r = req("My Media", "secure", &[], &["scott"]);
        let out = rewrite_section(CONF, &r.share, &r.access_lines()).unwrap();
        let m = parse(&out)
            .into_iter()
            .find(|x| x.name == "My Media")
            .unwrap();
        assert_eq!(m.mode(), "secure");
        for bad in [
            "", ".hidden", "a/b", "a]b", "a\"b", " lead", "trail ", "a\nb", "a=b",
        ] {
            assert!(validate_share_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn oversized_user_lists_are_refused() {
        let many: Vec<String> = (0..=MAX_USERS).map(|i| format!("u{i}")).collect();
        let e = SmbShareRequest::new("Data", "private", &many, &[]).unwrap_err();
        assert!(e.to_string().contains("readList"), "{e}");
        assert!(SmbShareRequest::new("Data", "private", &many[..MAX_USERS], &[]).is_ok());
        let e = SmbShareRequest::new("Data", "secure", &[], &many).unwrap_err();
        assert!(e.to_string().contains("writeList"), "{e}");
    }

    #[test]
    fn lists_the_mode_would_ignore_are_refused() {
        let e = |sec: &str, r: &[&str], w: &[&str]| {
            SmbShareRequest::new("Data", sec, &s(r), &s(w))
                .unwrap_err()
                .to_string()
        };
        assert!(e("public", &[], &["a"]).contains("would be ignored"));
        assert!(e("secure", &["a"], &[]).contains("readList would be ignored"));
        assert!(e("private", &[], &[]).contains("at least one user"));
        assert!(e("open", &[], &[]).contains("invalid security"));
        assert!(e("private", &["a b"], &[]).contains("invalid user"));
    }

    #[test]
    fn apply_writes_cfg_then_conf_then_reloads() {
        let f = fake();
        let (cfg, conf) = (
            f.path().join("shares/Data.cfg"),
            f.path().join("smb-shares.conf"),
        );
        let reloaded = std::cell::Cell::new(false);
        let access = apply(
            &cfg,
            &conf,
            &req("Data", "secure", &[], &["scott"]),
            &|| {
                reloaded.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert!(reloaded.get());
        assert!(access.contains(&"write list = scott".to_string()));
        let cfg_text = fs::read_to_string(&cfg).unwrap();
        assert!(cfg_text.contains("shareSecurity=\"secure\""));
        assert!(cfg_text.contains("shareWriteList=\"scott\""));
        assert!(
            cfg_text.contains("shareComment=\"x\""),
            "unmodelled keys kept"
        );
        let data = parse(&fs::read_to_string(&conf).unwrap())
            .into_iter()
            .find(|x| x.name == "Data")
            .unwrap();
        assert_eq!(data.mode(), "secure");
    }

    #[test]
    fn failed_reload_restores_both_files() {
        let f = fake();
        let (cfg, conf) = (
            f.path().join("shares/Data.cfg"),
            f.path().join("smb-shares.conf"),
        );
        let (cfg0, conf0) = (fs::read(&cfg).unwrap(), fs::read(&conf).unwrap());
        let e = apply(&cfg, &conf, &req("Data", "private", &["a"], &[]), &|| {
            bail!("smbd not running")
        })
        .unwrap_err()
        .to_string();
        assert!(e.contains("reloading smbd failed, both files restored"));
        assert_eq!(fs::read(&cfg).unwrap(), cfg0);
        assert_eq!(fs::read(&conf).unwrap(), conf0);
    }

    #[test]
    fn user_names_follow_unraid_rules() {
        for ok in ["scott", "a", "media_user", "u-1.x"] {
            assert!(validate_user(ok).is_ok(), "{ok}");
        }
        let long = "a".repeat(33);
        for bad in [
            "", "Scott", "1user", "_x", "-x", ".x", "a b", "a,b", "a=b", &long,
        ] {
            assert!(validate_user(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn failed_conf_write_restores_the_cfg() {
        use std::os::unix::fs::PermissionsExt;
        if crate::docker_adopt::host::euid() == Some(0) {
            return;
        }
        let f = fake();
        let (cfg, conf) = (
            f.path().join("shares/Data.cfg"),
            f.path().join("smb-shares.conf"),
        );
        let (cfg0, conf0) = (fs::read(&cfg).unwrap(), fs::read(&conf).unwrap());
        fs::set_permissions(f.path(), fs::Permissions::from_mode(0o555)).unwrap();
        let reloaded = std::cell::Cell::new(false);
        let r = apply(&cfg, &conf, &req("Data", "private", &["a"], &[]), &|| {
            reloaded.set(true);
            Ok(())
        });
        fs::set_permissions(f.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let e = r.unwrap_err().to_string();
        assert!(
            e.contains("writing the smb conf failed, both files restored"),
            "{e}"
        );
        assert!(!reloaded.get());
        assert_eq!(fs::read(&cfg).unwrap(), cfg0);
        assert_eq!(fs::read(&conf).unwrap(), conf0);
    }

    #[test]
    fn nothing_is_written_when_the_section_is_missing() {
        let f = fake();
        f.write("shares/Backups.cfg", "shareSecurity=\"public\"\n");
        let cfg = f.path().join("shares/Backups.cfg");
        let before = fs::read(&cfg).unwrap();
        let e = apply(
            &cfg,
            &f.path().join("smb-shares.conf"),
            &req("Backups", "public", &[], &[]),
            &|| Ok(()),
        )
        .unwrap_err();
        assert!(e.to_string().contains("no section"));
        assert_eq!(fs::read(&cfg).unwrap(), before);
    }

    #[test]
    fn tool_body_validates_before_reaching_root() {
        let args = |share: &str, sec: &str, r: &[&str]| UnraidSmbShareSetArgs {
            share: share.into(),
            security: sec.into(),
            read_list: s(r),
            write_list: vec![],
            execute: false,
        };
        assert!(op_for(&args("../x", "public", &[])).is_err());
        assert!(op_for(&args("Data", "secure", &["a"])).is_err());
        let (_, op) = op_for(&args("My Media", "private", &["a"])).unwrap();
        let v = plugin_toolkit::serde_json::to_value(&op).unwrap();
        assert_eq!(v["op"], "set_smb_share");
        assert_eq!(v["payload"]["share"], "My Media");
        assert_eq!(v["payload"]["read_list"][0], "a");
    }

    #[test]
    fn only_root_may_set_a_share() {
        let op = PrivilegedOp::SetSmbShare {
            share: "Data".into(),
            security: "public".into(),
            read_list: vec![],
            write_list: vec![],
        };
        let passwd = "orca:x:1000:100::/h:/bin/sh\n";
        let group = "docker:x:281:orca\n";
        assert!(privileged::authorize(&op, 0, passwd, group).is_ok());
        assert!(privileged::authorize(&op, 1000, passwd, group).is_err());
    }

    #[test]
    fn dry_run_requires_admin() {
        for role in [Some("user"), None] {
            let args = UnraidSmbShareSetArgs {
                share: "Data".into(),
                security: "secure".into(),
                read_list: vec![],
                write_list: s(&["scott"]),
                execute: false,
            };
            let ctx = crate::authz::test_ctx(role);
            let e =
                plugin_toolkit::reactor::block_on(unraid_smb_share_set(args, &ctx)).unwrap_err();
            assert!(e.to_string().contains("unraid.smb.share.set: "), "{e}");
        }
    }

    #[test]
    fn dry_run_plan_checks_the_live_section() {
        let f = fake();
        let conf = f.path().join("smb-shares.conf");
        let args = |share: &str| UnraidSmbShareSetArgs {
            share: share.into(),
            security: "secure".into(),
            read_list: vec![],
            write_list: s(&["scott"]),
            execute: false,
        };
        let (req, _) = plan_in(&conf, &args("Data")).unwrap();
        assert!(
            req.access_lines()
                .contains(&"write list = scott".to_string())
        );
        let e = plan_in(&conf, &args("Backups")).unwrap_err().to_string();
        assert!(e.contains("no section"), "{e}");
    }

    #[test]
    fn file_modes_are_preserved() {
        use std::os::unix::fs::PermissionsExt;
        let f = fake();
        let (cfg, conf) = (
            f.path().join("shares/Data.cfg"),
            f.path().join("smb-shares.conf"),
        );
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&conf, fs::Permissions::from_mode(0o604)).unwrap();
        apply(&cfg, &conf, &req("Data", "public", &[], &[]), &|| Ok(())).unwrap();
        assert_eq!(
            fs::metadata(&cfg).unwrap().permissions().mode() & 0o7777,
            0o640
        );
        assert_eq!(
            fs::metadata(&conf).unwrap().permissions().mode() & 0o7777,
            0o604
        );
    }
}
