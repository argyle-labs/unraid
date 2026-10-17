//! Unraid NFS export authoring — the `storage` facet's export read/write side.
//!
//! Reads come from `/etc/exports`, which is world-readable and is the live
//! table the kernel serves. Writes go through Unraid's own share API: the NFS
//! Security Settings forms of unraid/webgui `SecurityNFS.page`
//! (`changeShareAccessNFS`, then `changeShareSecurityNFS`), POSTed to emhttpd's
//! `/update` over its world-writable local socket, with the `csrf_token` from
//! world-readable `var.ini`, the way Unraid's `emcmd` does. emhttp persists the
//! share cfg, regenerates `/etc/exports` and re-exports, so the unprivileged
//! daemon writes directly; every write is verified against `/etc/exports` and
//! emhttp's world-readable per-share NFS state, `sec_nfs.ini`.
//!
//! `/etc/exports` keeps options **per client**, while `ExportEntry` models one
//! option set. Reads union them; authoring writes every client with one set.
//!
//! `fsid` is assigned by Unraid and cannot be set through its share API. A
//! requested fsid must already be the live one, or the write is refused.

use std::fs;
use std::path::{Path, PathBuf};

use plugin_toolkit::prelude::{Result, anyhow, bail};
use plugin_toolkit::storage::{Capability, ExportEntry, StorageBackend, StorageError, StorageKind};

use crate::share_cache::{self, EMHTTPD_SOCKET, SHARES_INI, VAR_INI};

/// Where Unraid persists per-share settings.
const SHARE_CFG_DIR: &str = "/boot/config/shares";
/// Root of the user shares an export path lives under.
const USER_SHARE_ROOT: &str = "/mnt/user";
/// The live NFS export table.
const EXPORTS_FILE: &str = "/etc/exports";
const SEC_NFS_INI: &str = "/var/local/emhttp/sec_nfs.ini";
/// `shareExportNFS` value meaning "exported". `-` means not exported.
const NFS_ENABLED: &str = "e";

/// The `storage` facet unraid registers: authoritative for the exports this
/// Unraid host serves. It deliberately does **not** implement mount/unmount —
/// Unraid is a server here, not a client.
#[derive(Debug, Clone, Default)]
pub struct UnraidExports;

impl UnraidExports {
    /// Share name for an export path (`/mnt/user/pbs` → `pbs`).
    ///
    /// Only paths under [`USER_SHARE_ROOT`] are addressable: a disk share or an
    /// arbitrary path has no `<name>.cfg` to persist into, so accepting one
    /// would produce a live export that silently vanishes on reboot.
    fn share_name(path: &str) -> Result<String, StorageError> {
        let rest = path
            .trim_end_matches('/')
            .strip_prefix(&format!("{USER_SHARE_ROOT}/"))
            .ok_or_else(|| {
                StorageError::Other(format!(
                    "'{path}' is not an Unraid user share (expected {USER_SHARE_ROOT}/<name>); \
                     only user shares have a persistent share config"
                ))
            })?;
        if rest.is_empty() || rest == "." || rest == ".." || rest.contains('/') {
            return Err(StorageError::Other(format!(
                "'{path}' is not a single user share directly under {USER_SHARE_ROOT}"
            )));
        }
        Ok(rest.to_string())
    }

    pub(crate) fn cfg_path(name: &str) -> PathBuf {
        Path::new(SHARE_CFG_DIR).join(format!("{name}.cfg"))
    }

    /// Render (clients, options) back into Unraid's `shareHostListNFS` form.
    fn render_host_list(clients: &[String], options: &[String]) -> String {
        let opts = options.join(",");
        clients
            .iter()
            .map(|c| {
                if opts.is_empty() {
                    c.clone()
                } else {
                    format!("{c}({opts})")
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Parse one `/etc/exports` line into an [`ExportEntry`].
    ///
    /// Unraid writes them as:
    /// ```text
    /// "/mnt/user/pbs" -fsid=209,async,no_subtree_check 10.0.0.17(rw,sync,no_root_squash)
    /// ```
    /// — a quoted path, a leading `-`-prefixed default option group carrying
    /// `fsid`, then one `client(opts)` group per allowed client.
    ///
    /// `fsid` is lifted out of the default group into the typed field and not
    /// repeated in `options`; it is identity, not tuning, and round-tripping it
    /// as a plain option would let a caller edit it by accident.
    ///
    /// Returns `None` for comments, blanks, and any path outside
    /// [`USER_SHARE_ROOT`] — this backend addresses user shares only, so a disk
    /// or custom export is reported by whoever owns it rather than mislabelled
    /// as ours.
    fn entry_from_exports(line: &str) -> Option<ExportEntry> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        // Path is quoted, which is what lets a share name contain spaces.
        let rest = line.strip_prefix('"')?;
        let (path, rest) = rest.split_once('"')?;
        if !path.starts_with(&format!("{USER_SHARE_ROOT}/")) {
            return None;
        }

        let mut fsid = None;
        let mut options: Vec<String> = Vec::new();
        let mut allowed_clients: Vec<String> = Vec::new();

        for tok in rest.split_whitespace() {
            if let Some(defaults) = tok.strip_prefix('-') {
                // Default option group: `-fsid=209,async,no_subtree_check`.
                for opt in defaults.split(',').filter(|s| !s.is_empty()) {
                    match opt.strip_prefix("fsid=") {
                        Some(v) => fsid = Some(v.to_string()),
                        None => options.push(opt.to_string()),
                    }
                }
            } else if let Some((client, opts)) = tok.split_once('(') {
                allowed_clients.push(client.to_string());
                // Per-client options collapse into one shared list, because
                // ExportEntry models a single option set. Identical groups (the
                // normal case) collapse losslessly; genuinely differing ones are
                // unioned, which is why authoring cannot round-trip them — see
                // the module note on per-client options.
                for opt in opts
                    .trim_end_matches(')')
                    .split(',')
                    .filter(|s| !s.is_empty())
                {
                    if !options.iter().any(|o| o == opt) {
                        options.push(opt.to_string());
                    }
                }
            }
        }
        // A path with no client group is not an export anyone can mount.
        if allowed_clients.is_empty() {
            return None;
        }
        Some(ExportEntry {
            path: path.to_string(),
            allowed_clients,
            options,
            fsid,
        })
    }

    /// Apply `updates` to a share cfg, preserving every key this plugin does not
    /// model and the file's existing ordering. Keys absent from the file are
    /// appended.
    pub(crate) fn write_cfg_keys(text: &str, updates: &[(&str, String)]) -> String {
        let mut out: Vec<String> = Vec::new();
        let mut applied: Vec<&str> = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            let key = trimmed
                .split_once('=')
                .map(|(k, _)| k.trim())
                .filter(|_| !trimmed.starts_with('#'));
            match key.and_then(|k| updates.iter().find(|(uk, _)| *uk == k)) {
                Some((k, v)) => {
                    out.push(format!("{k}=\"{v}\""));
                    applied.push(k);
                }
                None => out.push(line.to_string()),
            }
        }
        for (k, v) in updates {
            if !applied.contains(k) {
                out.push(format!("{k}=\"{v}\""));
            }
        }
        let mut joined = out.join("\n");
        joined.push('\n');
        joined
    }

    fn validate_entry(entry: &ExportEntry) -> Result<(), StorageError> {
        let bad = |what: &str, v: &str| {
            StorageError::Other(format!("invalid export {what} '{}'", v.escape_debug()))
        };
        let token_ok = |v: &str, extra: &[char]| {
            !v.is_empty()
                && v.chars().all(|c| {
                    c.is_ascii_alphanumeric() || "._-:/=@*".contains(c) || extra.contains(&c)
                })
        };
        if entry
            .path
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\\')
        {
            return Err(bad("path", &entry.path));
        }
        if entry.allowed_clients.is_empty() {
            return Err(StorageError::Other(
                "export needs at least one client".into(),
            ));
        }
        for c in &entry.allowed_clients {
            if !token_ok(c, &['[', ']']) {
                return Err(bad("client", c));
            }
        }
        for o in &entry.options {
            if !token_ok(o, &[]) || o.contains(':') || o.contains('@') || o.contains('*') {
                return Err(bad("option", o));
            }
        }
        if let Some(f) = entry.fsid.as_deref().filter(|s| !s.is_empty())
            && !token_ok(f, &[])
        {
            return Err(bad("fsid", f));
        }
        Ok(())
    }
}

fn read_live() -> Result<Vec<ExportEntry>, StorageError> {
    let text = fs::read_to_string(EXPORTS_FILE)
        .map_err(|e| StorageError::Other(format!("read {EXPORTS_FILE}: {e}")))?;
    let mut out: Vec<ExportEntry> = text
        .lines()
        .filter_map(UnraidExports::entry_from_exports)
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn nfs_form(
    share: &str,
    entry: Option<&ExportEntry>,
    security: &str,
) -> Vec<Vec<(&'static str, String)>> {
    let name = ("shareName", share.to_string());
    match entry {
        Some(e) => vec![
            vec![
                name.clone(),
                (
                    "shareHostListNFS",
                    UnraidExports::render_host_list(&e.allowed_clients, &e.options),
                ),
                ("changeShareAccessNFS", "Apply".into()),
            ],
            vec![
                name,
                ("shareExportNFS", NFS_ENABLED.into()),
                ("shareSecurityNFS", "private".into()),
                ("changeShareSecurityNFS", "Apply".into()),
            ],
        ],
        None => vec![vec![
            name,
            ("shareExportNFS", "-".into()),
            ("shareSecurityNFS", security.to_string()),
            ("changeShareSecurityNFS", "Apply".into()),
        ]],
    }
}

fn nfs_body(fields: &[(&str, String)], csrf: &str) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{k}={}", share_cache::urlencode(v)))
        .chain(std::iter::once(format!(
            "csrf_token={}",
            share_cache::urlencode(csrf)
        )))
        .collect::<Vec<_>>()
        .join("&")
}

fn emhttp_request(body: &str) -> String {
    format!(
        "POST /update HTTP/1.1\r\nHost: localhost\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn check_status(resp: &str) -> Result<()> {
    let status = resp.lines().next().unwrap_or_default();
    match status.split_whitespace().nth(1) {
        Some(code) if code.starts_with('2') => Ok(()),
        _ => bail!("emhttp /update: {status:?}"),
    }
}

fn emhttp_post(socket: &Path, body: &str) -> Result<()> {
    use std::io::{Read, Write};
    let mut s = std::os::unix::net::UnixStream::connect(socket)
        .map_err(|e| anyhow!("connect {}: {e}", socket.display()))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    s.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    s.write_all(emhttp_request(body).as_bytes())?;
    let mut resp = String::new();
    s.read_to_string(&mut resp)?;
    check_status(&resp)
}

fn check_live(exports: &str, path: &str, entry: Option<&ExportEntry>) -> Vec<String> {
    let live = exports
        .lines()
        .filter_map(UnraidExports::entry_from_exports)
        .find(|e| e.path == path);
    match (entry, live) {
        (None, None) => Vec::new(),
        (None, Some(_)) => vec![format!("{path} is still exported")],
        (Some(_), None) => vec![format!("{path} is not exported")],
        (Some(want), Some(got)) => {
            let mut problems = Vec::new();
            let mut wc = want.allowed_clients.clone();
            let mut gc = got.allowed_clients.clone();
            wc.sort();
            gc.sort();
            if wc != gc {
                problems.push(format!("clients: wanted {wc:?}, got {gc:?}"));
            }
            let missing: Vec<&String> = want
                .options
                .iter()
                .filter(|o| !got.options.contains(o))
                .collect();
            if !missing.is_empty() {
                problems.push(format!("options missing: {missing:?}"));
            }
            problems
        }
    }
}

fn sec_nfs(sec_nfs_ini: &Path, share: &str) -> Result<std::collections::BTreeMap<String, String>> {
    let text = fs::read_to_string(sec_nfs_ini)
        .map_err(|e| anyhow!("read {}: {e}", sec_nfs_ini.display()))?;
    share_cache::parse_ini(&text)
        .into_iter()
        .skip(1)
        .find(|(s, _)| s == share)
        .map(|(_, kv)| kv)
        .ok_or_else(|| anyhow!("no share '{share}' in {}", sec_nfs_ini.display()))
}

fn sec_key<'a>(
    sec: &'a std::collections::BTreeMap<String, String>,
    key: &str,
    share: &str,
) -> Result<&'a str> {
    sec.get(key)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("no {key} for share '{share}' in {SEC_NFS_INI}"))
}

fn check_sec(
    share: &str,
    sec: &std::collections::BTreeMap<String, String>,
    form: &[Vec<(&str, String)>],
) -> Vec<String> {
    let keys = [
        ("shareExportNFS", "export"),
        ("shareSecurityNFS", "security"),
        ("shareHostListNFS", "hostList"),
    ];
    form.iter()
        .flatten()
        .filter_map(|(k, v)| {
            let (_, sk) = keys.iter().find(|(f, _)| f == k)?;
            let got = sec.get(*sk).map(String::as_str);
            (got != Some(v.as_str())).then(|| format!("{share} {sk}: wanted {v:?}, got {got:?}"))
        })
        .collect()
}

fn apply_nfs_in(
    shares_ini: &Path,
    sec_nfs_ini: &Path,
    var_ini: &Path,
    exports: &Path,
    path: &str,
    entry: Option<&ExportEntry>,
    post: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<String> {
    let share = UnraidExports::share_name(path).map_err(|e| anyhow!("{e}"))?;
    if let Some(e) = entry {
        UnraidExports::validate_entry(e).map_err(|e| anyhow!("{e}"))?;
    }
    let read_exports =
        || fs::read_to_string(exports).map_err(|e| anyhow!("read {}: {e}", exports.display()));
    let ini = fs::read_to_string(shares_ini)
        .map_err(|e| anyhow!("read {}: {e}", shares_ini.display()))?;
    if !share_cache::parse_ini(&ini)
        .iter()
        .skip(1)
        .any(|(s, _)| *s == share)
    {
        if entry.is_none() && check_live(&read_exports()?, path, None).is_empty() {
            return Ok("not exported".into());
        }
        bail!("no share '{share}' in {}", shares_ini.display());
    };
    let csrf = share_cache::read_csrf(var_ini)?;
    let security = sec_key(&sec_nfs(sec_nfs_ini, &share)?, "security", &share)?.to_string();
    let forms = nfs_form(&share, entry, &security);
    for form in &forms {
        post(&nfs_body(form, &csrf))?;
    }
    let mut problems = check_sec(&share, &sec_nfs(sec_nfs_ini, &share)?, &forms);
    problems.extend(check_live(&read_exports()?, path, entry));
    if !problems.is_empty() {
        bail!(
            "emhttp did not apply the NFS export: {}",
            problems.join("; ")
        );
    }
    Ok(forms
        .iter()
        .flatten()
        .filter(|(k, _)| !k.starts_with("change") && *k != "shareName")
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; "))
}

fn apply_nfs(path: &str, entry: Option<&ExportEntry>) -> Result<String, StorageError> {
    apply_nfs_in(
        Path::new(SHARES_INI),
        Path::new(SEC_NFS_INI),
        Path::new(VAR_INI),
        Path::new(EXPORTS_FILE),
        path,
        entry,
        &mut |body| emhttp_post(Path::new(EMHTTPD_SOCKET), body),
    )
    .map_err(|e| StorageError::Other(format!("{e:#}")))
}

#[plugin_toolkit::orca_async]
impl StorageBackend for UnraidExports {
    fn name(&self) -> &str {
        "unraid"
    }

    fn kind(&self) -> StorageKind {
        StorageKind::NetworkShare
    }

    /// Exports only. Unraid is the *server* here: it publishes shares, it does
    /// not mount them, so no mount/unmount/usage capability is advertised.
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::Exports, Capability::ExportWrite]
    }

    fn endpoint(&self) -> String {
        USER_SHARE_ROOT.to_string()
    }

    /// Read the exports this host serves from the **live table**, `/etc/exports`.
    ///
    /// Deliberately not from `/boot/config/shares`: `/boot` is vfat, mounted
    /// `fmask=0177,dmask=0077`, so its permissions are synthesized by the mount
    /// and every file is 0600 root. The daemon runs unprivileged, so no chmod or
    /// chown can ever grant it access — reading the cfgs failed with EACCES on
    /// every Unraid host. `/etc/exports` is world-readable and carries strictly
    /// more than the cfg did: path, fsid, and **per-client** option sets.
    ///
    /// Reading the live table also means this reports what the kernel is
    /// actually serving rather than what the config intends — the right answer
    /// for a read, and the two can legitimately differ until `exportfs -ra`.
    async fn list_exports(&self) -> Result<Vec<ExportEntry>, StorageError> {
        read_live()
    }

    async fn upsert_export(&self, entry: &ExportEntry) -> Result<ExportEntry, StorageError> {
        let path = format!("{USER_SHARE_ROOT}/{}", Self::share_name(&entry.path)?);
        let entry = ExportEntry {
            path: path.clone(),
            ..entry.clone()
        };
        Self::validate_entry(&entry)?;
        if let Some(fsid) = entry.fsid.as_deref().filter(|s| !s.is_empty()) {
            let live = read_live()?;
            let current = live
                .iter()
                .find(|e| e.path == path)
                .and_then(|e| e.fsid.as_deref());
            if current != Some(fsid) {
                return Err(StorageError::Other(format!(
                    "fsid {fsid} cannot be set through Unraid's share API: emhttp assigns it \
                     (live fsid for {path} is {current:?})"
                )));
            }
        }
        apply_nfs(&path, Some(&entry))?;
        read_live()?
            .into_iter()
            .find(|e| e.path == path)
            .ok_or_else(|| StorageError::Other(format!("{path} is not in {EXPORTS_FILE}")))
    }

    async fn remove_export(&self, path: &str) -> Result<(), StorageError> {
        let path = format!("{USER_SHARE_ROOT}/{}", Self::share_name(path)?);
        apply_nfs(&path, None)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `/etc/exports` lines from a live Unraid host, with the LAN range
    /// replaced by the documentation range. Shape is verbatim: quoted path, a
    /// `-`-prefixed default group carrying fsid, then one group per client.
    const EXPORTS: &str = r#"# See exports(5) for a description.
# This file contains a list of all directories exported to other computers.

"/mnt/user/backups" -fsid=106,async,no_subtree_check 10.0.0.0/24(rw,async,no_subtree_check,all_squash,anonuid=99,anongid=100) 100.64.0.0/10(rw,async,no_subtree_check,all_squash,anonuid=99,anongid=100)
"/mnt/user/pbs" -fsid=209,async,no_subtree_check 10.0.0.17(rw,sync,no_subtree_check,no_root_squash)
"/mnt/disk1/scratch" -fsid=900,async 10.0.0.0/24(rw)
"#;

    #[test]
    fn reads_exports_from_the_live_table() {
        let all: Vec<_> = EXPORTS
            .lines()
            .filter_map(UnraidExports::entry_from_exports)
            .collect();
        // The /mnt/disk1 line is dropped: this backend addresses user shares only.
        assert_eq!(all.len(), 2, "got {all:?}");
        assert_eq!(all[0].path, "/mnt/user/backups");
        assert_eq!(all[1].path, "/mnt/user/pbs");
    }

    #[test]
    fn fsid_is_lifted_out_of_the_default_option_group() {
        let e = UnraidExports::entry_from_exports(
            r#""/mnt/user/pbs" -fsid=209,async,no_subtree_check 10.0.0.17(rw,sync,no_root_squash)"#,
        )
        .expect("parses");
        // fsid is identity, not tuning — typed field, and never left in options
        // where a caller could edit it by accident.
        assert_eq!(e.fsid.as_deref(), Some("209"));
        assert!(
            !e.options.iter().any(|o| o.starts_with("fsid")),
            "fsid must not round-trip as an option: {:?}",
            e.options
        );
        assert!(e.options.contains(&"async".to_string()));
    }

    #[test]
    fn every_client_is_captured_not_just_the_first() {
        // Two client groups on one line — an earlier cut of this parser kept only
        // the last, which would have silently narrowed who may mount the share.
        let e = UnraidExports::entry_from_exports(
            r#""/mnt/user/backups" -fsid=106,async 10.0.0.0/24(rw,async) 100.64.0.0/10(rw,async)"#,
        )
        .expect("parses");
        assert_eq!(e.allowed_clients, vec!["10.0.0.0/24", "100.64.0.0/10"]);
    }

    #[test]
    fn identical_per_client_options_collapse_without_duplicates() {
        let e = UnraidExports::entry_from_exports(
            r#""/mnt/user/backups" -fsid=106 10.0.0.0/24(rw,async,all_squash) 100.64.0.0/10(rw,async,all_squash)"#,
        )
        .expect("parses");
        let rw = e.options.iter().filter(|o| *o == "rw").count();
        assert_eq!(
            rw, 1,
            "shared options must not duplicate per client: {:?}",
            e.options
        );
    }

    #[test]
    fn comments_blanks_and_unmountable_lines_are_skipped() {
        for line in [
            "# a comment",
            "",
            "   ",
            // No client group: nothing can mount it, so it is not an export.
            r#""/mnt/user/pbs" -fsid=209,async"#,
            // Outside /mnt/user: not this backend's to report.
            r#""/mnt/disk1/x" -fsid=1 10.0.0.1(rw)"#,
        ] {
            assert!(
                UnraidExports::entry_from_exports(line).is_none(),
                "should skip: {line:?}"
            );
        }
    }

    /// The real `pbs` share cfg from a live Unraid host, verbatim.
    const PBS_CFG: &str = r#"# Generated settings:
shareComment="Proxmox backup server"
shareUseCache="yes"
shareCachePool="cache"
shareFloor="188586393"
shareExport="-"
shareSecurity="public"
shareExportNFS="e"
shareExportNFSFsid="209"
shareSecurityNFS="private"
shareHostListNFS="10.0.0.17(rw,sync,no_subtree_check,no_root_squash)"
"#;

    /// Keys the plugin does not model must survive a write untouched — a share
    /// cfg carries cache-pool, allocator and floor settings that losing would
    /// silently change how the array places data.
    #[test]
    fn writing_keys_preserves_unmodelled_settings() {
        let out =
            UnraidExports::write_cfg_keys(PBS_CFG, &[("shareExportNFSFsid", "309".to_string())]);
        assert!(out.contains(r#"shareExportNFSFsid="309""#));
        assert!(out.contains(r#"shareFloor="188586393""#));
        assert!(out.contains(r#"shareCachePool="cache""#));
        assert!(out.contains(r#"shareComment="Proxmox backup server""#));
    }

    /// A key absent from the file is appended rather than dropped.
    #[test]
    fn writing_appends_a_missing_key() {
        let out = UnraidExports::write_cfg_keys(
            r#"shareComment="x""#,
            &[("shareExportNFS", "e".to_string())],
        );
        assert!(out.contains(r#"shareExportNFS="e""#));
        assert!(out.contains(r#"shareComment="x""#));
    }

    fn entry(options: &[&str]) -> ExportEntry {
        ExportEntry {
            path: "/mnt/user/pbs".to_string(),
            allowed_clients: vec!["10.0.0.17".to_string()],
            options: options.iter().map(|o| o.to_string()).collect(),
            fsid: Some("209".to_string()),
        }
    }

    #[test]
    fn entries_with_injection_characters_are_rejected() {
        assert!(UnraidExports::validate_entry(&entry(&["rw"])).is_ok());
        assert!(UnraidExports::validate_entry(&entry(&["rw)\n/ *(rw"])).is_err());
        assert!(UnraidExports::validate_entry(&entry(&["rw,no_root_squash"])).is_err());
        let mut e = entry(&["rw"]);
        e.allowed_clients = vec!["10.0.0.17 *".to_string()];
        assert!(UnraidExports::validate_entry(&e).is_err());
        let mut e = entry(&["rw"]);
        e.allowed_clients = vec!["10.0.0.0/24".to_string(), "[fd00::1]".to_string()];
        assert!(UnraidExports::validate_entry(&e).is_ok());
        let mut e = entry(&["rw"]);
        e.fsid = Some("1\"x".to_string());
        assert!(UnraidExports::validate_entry(&e).is_err());
        let mut e = entry(&["rw"]);
        e.path = "/mnt/user/a\"\n/ *".to_string();
        assert!(UnraidExports::validate_entry(&e).is_err());
        e.allowed_clients.clear();
        e.path = "/mnt/user/pbs".to_string();
        assert!(UnraidExports::validate_entry(&e).is_err());
    }

    #[test]
    fn host_list_renders_one_option_set_per_client() {
        assert_eq!(
            UnraidExports::render_host_list(
                &["10.0.0.17".into(), "10.0.0.18".into()],
                &["rw".into(), "sync".into()]
            ),
            "10.0.0.17(rw,sync) 10.0.0.18(rw,sync)"
        );
    }

    fn nfs_setup() -> crate::test_support::FakeRoot {
        let f = crate::test_support::FakeRoot::new("exports");
        f.write("shares.ini", "[\"pbs\"]\nname=\"pbs\"\n")
            .write("sec_nfs.ini", &sec_nfs_text("e", "private", PBS_HOSTS))
            .write("var.ini", "version=\"7.2.0\"\ncsrf_token=\"TOK\"\n")
            .write("exports", EXPORTS);
        f
    }

    const PBS_HOSTS: &str = "10.0.0.17(rw,sync,no_subtree_check,no_root_squash)";

    fn sec_nfs_text(export: &str, security: &str, hosts: &str) -> String {
        format!(
            "[\"backups\"]\nexport=\"e\"\nsecurity=\"public\"\nhostList=\"\"\n\
             [\"pbs\"]\nexport=\"{export}\"\nsecurity=\"{security}\"\nhostList=\"{hosts}\"\n"
        )
    }

    fn nfs_run(
        f: &crate::test_support::FakeRoot,
        entry: Option<&ExportEntry>,
        after: Option<String>,
    ) -> (Result<String>, Vec<String>) {
        let sec = match entry {
            Some(_) => sec_nfs_text("e", "private", "10.0.0.13(rw)"),
            None => sec_nfs_text("-", "private", PBS_HOSTS),
        };
        nfs_run_sec(f, entry, after, Some(sec))
    }

    fn nfs_run_sec(
        f: &crate::test_support::FakeRoot,
        entry: Option<&ExportEntry>,
        after: Option<String>,
        after_sec: Option<String>,
    ) -> (Result<String>, Vec<String>) {
        let p = f.path().to_path_buf();
        let mut bodies = Vec::new();
        let n = if entry.is_some() { 2 } else { 1 };
        let out = apply_nfs_in(
            &p.join("shares.ini"),
            &p.join("sec_nfs.ini"),
            &p.join("var.ini"),
            &p.join("exports"),
            "/mnt/user/pbs",
            entry,
            &mut |body| {
                bodies.push(body.to_string());
                if bodies.len() == n {
                    if let Some(a) = &after {
                        fs::write(p.join("exports"), a).unwrap();
                    }
                    if let Some(a) = &after_sec {
                        fs::write(p.join("sec_nfs.ini"), a).unwrap();
                    }
                }
                Ok(())
            },
        );
        (out, bodies)
    }

    fn pbs_entry() -> ExportEntry {
        ExportEntry {
            path: "/mnt/user/pbs".into(),
            allowed_clients: vec!["10.0.0.13".into()],
            options: vec!["rw".into()],
            fsid: None,
        }
    }

    fn pbs_exports_as_13() -> String {
        EXPORTS.replace(
            "10.0.0.17(rw,sync,no_subtree_check,no_root_squash)",
            "10.0.0.13(rw)",
        )
    }

    #[test]
    fn request_is_a_form_post_to_update_with_exact_length() {
        let body = "shareName=pbs&csrf_token=TOK";
        assert_eq!(
            emhttp_request(body),
            "POST /update HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 28\r\nConnection: close\r\n\r\n\
             shareName=pbs&csrf_token=TOK"
        );
    }

    #[test]
    fn non_2xx_emhttp_status_is_an_error() {
        assert!(check_status("HTTP/1.1 200 OK\r\n\r\n").is_ok());
        assert!(check_status("HTTP/1.1 403 Forbidden\r\n\r\n").is_err());
        assert!(check_status("").is_err());
    }

    #[test]
    fn csrf_token_is_read_from_var_ini() {
        let f = nfs_setup();
        assert_eq!(
            share_cache::read_csrf(&f.path().join("var.ini")).unwrap(),
            "TOK"
        );
        f.write("var.ini", "version=\"7.2.0\"\ncsrf_token=\"\"\n");
        assert!(share_cache::read_csrf(&f.path().join("var.ini")).is_err());
    }

    #[test]
    fn upsert_posts_the_nfs_forms_and_verifies_exports() {
        let f = nfs_setup();
        let (out, bodies) = nfs_run(&f, Some(&pbs_entry()), Some(pbs_exports_as_13()));
        assert_eq!(
            out.unwrap(),
            "shareHostListNFS=10.0.0.13(rw); shareExportNFS=e; shareSecurityNFS=private"
        );
        assert_eq!(
            bodies,
            vec![
                "shareName=pbs&shareHostListNFS=10.0.0.13%28rw%29\
                 &changeShareAccessNFS=Apply&csrf_token=TOK",
                "shareName=pbs&shareExportNFS=e&shareSecurityNFS=private\
                 &changeShareSecurityNFS=Apply&csrf_token=TOK",
            ]
        );
    }

    #[test]
    fn upsert_that_changes_nothing_fails() {
        let f = nfs_setup();
        let (out, bodies) = nfs_run(&f, Some(&pbs_entry()), None);
        assert_eq!(bodies.len(), 2);
        let e = out.unwrap_err().to_string();
        assert!(e.contains("clients: wanted [\"10.0.0.13\"]"), "{e}");
    }

    #[test]
    fn upsert_fails_when_options_are_missing_from_the_live_table() {
        let f = nfs_setup();
        let mut want = pbs_entry();
        want.options.push("sync".into());
        let (out, _) = nfs_run(&f, Some(&want), Some(pbs_exports_as_13()));
        let e = out.unwrap_err().to_string();
        assert!(e.contains("options missing: [\"sync\"]"), "{e}");
    }

    #[test]
    fn transport_errors_propagate() {
        let f = nfs_setup();
        let p = f.path();
        let e = apply_nfs_in(
            &p.join("shares.ini"),
            &p.join("sec_nfs.ini"),
            &p.join("var.ini"),
            &p.join("exports"),
            "/mnt/user/pbs",
            Some(&pbs_entry()),
            &mut |_| bail!("emhttp /update: \"HTTP/1.1 500\""),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("500"), "{e}");
    }

    #[test]
    fn remove_sets_no_export_keeping_security_and_verifies() {
        let f = nfs_setup();
        let exports: String = EXPORTS
            .lines()
            .filter(|l| !l.contains("/mnt/user/pbs"))
            .map(|l| format!("{l}\n"))
            .collect();
        let (out, bodies) = nfs_run(&f, None, Some(exports));
        assert_eq!(out.unwrap(), "shareExportNFS=-; shareSecurityNFS=private");
        assert_eq!(
            bodies,
            vec![
                "shareName=pbs&shareExportNFS=-&shareSecurityNFS=private\
                 &changeShareSecurityNFS=Apply&csrf_token=TOK"
            ]
        );
    }

    #[test]
    fn sec_nfs_parses_the_share_section() {
        let f = nfs_setup();
        let sec = sec_nfs(&f.path().join("sec_nfs.ini"), "pbs").unwrap();
        assert_eq!(sec_key(&sec, "export", "pbs").unwrap(), "e");
        assert_eq!(sec_key(&sec, "security", "pbs").unwrap(), "private");
        assert_eq!(sec_key(&sec, "hostList", "pbs").unwrap(), PBS_HOSTS);
    }

    #[test]
    fn missing_sec_nfs_share_or_security_errors_before_posting() {
        let f = nfs_setup();
        f.write("sec_nfs.ini", "[\"backups\"]\nsecurity=\"public\"\n");
        let (out, bodies) = nfs_run(&f, None, None);
        let e = out.unwrap_err().to_string();
        assert!(e.contains("no share 'pbs'"), "{e}");
        assert!(bodies.is_empty());
        f.write("sec_nfs.ini", "[\"pbs\"]\nexport=\"e\"\n");
        let (out, bodies) = nfs_run(&f, None, None);
        let e = out.unwrap_err().to_string();
        assert!(e.contains("no security for share 'pbs'"), "{e}");
        assert!(bodies.is_empty());
    }

    #[test]
    fn upsert_fails_when_sec_nfs_host_list_does_not_match() {
        let f = nfs_setup();
        let (out, _) = nfs_run_sec(
            &f,
            Some(&pbs_entry()),
            Some(pbs_exports_as_13()),
            Some(sec_nfs_text("e", "private", PBS_HOSTS)),
        );
        let e = out.unwrap_err().to_string();
        assert!(e.contains("pbs hostList: wanted \"10.0.0.13(rw)\""), "{e}");
    }

    #[test]
    fn remove_fails_when_the_share_is_still_exported() {
        let f = nfs_setup();
        let (out, _) = nfs_run(&f, None, None);
        let e = out.unwrap_err().to_string();
        assert!(e.contains("/mnt/user/pbs is still exported"), "{e}");
    }

    #[test]
    fn nfs_writes_refuse_injection_and_unknown_shares_before_posting() {
        let f = nfs_setup();
        let mut e = pbs_entry();
        e.options = vec!["rw)\n/ *(rw".into()];
        let (out, bodies) = nfs_run(&f, Some(&e), None);
        assert!(out.is_err());
        assert!(bodies.is_empty());
        f.write("shares.ini", "");
        let (out, bodies) = nfs_run(&f, Some(&pbs_entry()), None);
        let err = out.unwrap_err().to_string();
        assert!(err.contains("no share 'pbs'"), "{err}");
        assert!(bodies.is_empty());
    }

    /// Only user shares are addressable — anything else has no cfg to persist
    /// into, so accepting it would create an export that vanishes on reboot.
    #[test]
    fn rejects_paths_that_are_not_user_shares() {
        assert!(UnraidExports::share_name("/mnt/disk1/pbs").is_err());
        assert!(UnraidExports::share_name("/mnt/user").is_err());
        assert!(UnraidExports::share_name("/mnt/user/a/b").is_err());
        assert!(UnraidExports::share_name("/mnt/user/.").is_err());
        assert!(UnraidExports::share_name("/mnt/user/..").is_err());
        assert_eq!(UnraidExports::share_name("/mnt/user/pbs").unwrap(), "pbs");
        assert_eq!(UnraidExports::share_name("/mnt/user/pbs/").unwrap(), "pbs");
    }
}
