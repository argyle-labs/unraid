//! Unraid NFS export authoring — the `storage` facet's export read/write side.
//!
//! Unraid keeps a user share's definition in two places that must agree:
//!
//! * `/boot/config/shares/<name>.cfg` — the persistent intent, surviving reboot.
//! * `/etc/exports` (+ `exportfs -ra`) — the live export table.
//!
//! **Writing one without the other is the bug this module exists to prevent.**
//! Editing the cfg alone does not re-export (the change appears only after a
//! reboot or an array restart); running `exportfs -ra` alone does not persist
//! (the change vanishes on reboot). Either half on its own leaves declared
//! intent and observed reality diverged — silently, because both files look
//! internally consistent. Every write here does both, cfg first so a crash
//! between the two leaves the durable record ahead of the live table rather
//! than behind it.
//!
//! `fsid` is carried, never invented. Uniqueness is fleet-level — no single host
//! can see that a *different* server already uses an fsid — so allocation is
//! orca's, and this backend persists exactly what it is handed. Duplicate fsids
//! across two servers give clients NFS file-handle collisions that present as
//! `Stale file handle` on whichever mount loses the race.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use plugin_toolkit::storage::{Capability, ExportEntry, StorageBackend, StorageError, StorageKind};

/// Where Unraid persists per-share settings.
const SHARE_CFG_DIR: &str = "/boot/config/shares";
/// Root of the user shares an export path lives under.
const USER_SHARE_ROOT: &str = "/mnt/user";
/// The live NFS export table.
const EXPORTS_FILE: &str = "/etc/exports";
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
        if rest.is_empty() || rest.contains('/') {
            return Err(StorageError::Other(format!(
                "'{path}' is not a single user share directly under {USER_SHARE_ROOT}"
            )));
        }
        Ok(rest.to_string())
    }

    fn cfg_path(name: &str) -> PathBuf {
        Path::new(SHARE_CFG_DIR).join(format!("{name}.cfg"))
    }

    /// Read `key="value"` pairs from a share cfg. Unknown keys are preserved by
    /// [`write_cfg_keys`], so a partial understanding of the format never drops
    /// settings this plugin does not model.
    fn parse_cfg(text: &str) -> Vec<(String, String)> {
        text.lines()
            .filter_map(|l| {
                let l = l.trim();
                if l.is_empty() || l.starts_with('#') {
                    return None;
                }
                let (k, v) = l.split_once('=')?;
                Some((k.trim().to_string(), v.trim().trim_matches('"').to_string()))
            })
            .collect()
    }

    fn cfg_get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
        pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Split `shareHostListNFS` into (clients, options).
    ///
    /// Unraid stores `10.0.0.5(rw,sync) 10.0.0.6(ro)` — per-client options.
    /// [`ExportEntry`] models one flat `options` list, so the first client's
    /// options represent the entry. Differing per-client options therefore do
    /// not round-trip; they are preserved on read (reported as the first
    /// client's) but an `upsert_export` rewrites every client with one option
    /// set. Callers that need per-client divergence must edit the cfg directly
    /// until the contract grows a per-client shape.
    fn parse_host_list(raw: &str) -> (Vec<String>, Vec<String>) {
        let mut clients = Vec::new();
        let mut options = Vec::new();
        for spec in raw.split_whitespace() {
            match spec.split_once('(') {
                Some((client, opts)) => {
                    clients.push(client.to_string());
                    if options.is_empty() {
                        options = opts
                            .trim_end_matches(')')
                            .split(',')
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .collect();
                    }
                }
                None => clients.push(spec.to_string()),
            }
        }
        (clients, options)
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

    /// Turn one share cfg into an [`ExportEntry`], or `None` when that share is
    /// not NFS-exported (`shareExportNFS` != `e`).
    fn entry_from_cfg(name: &str, text: &str) -> Option<ExportEntry> {
        let pairs = Self::parse_cfg(text);
        if Self::cfg_get(&pairs, "shareExportNFS") != Some(NFS_ENABLED) {
            return None;
        }
        let (allowed_clients, options) =
            Self::parse_host_list(Self::cfg_get(&pairs, "shareHostListNFS").unwrap_or_default());
        Some(ExportEntry {
            path: format!("{USER_SHARE_ROOT}/{name}"),
            allowed_clients,
            options,
            fsid: Self::cfg_get(&pairs, "shareExportNFSFsid")
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        })
    }

    /// Apply `updates` to a share cfg, preserving every key this plugin does not
    /// model and the file's existing ordering. Keys absent from the file are
    /// appended.
    fn write_cfg_keys(text: &str, updates: &[(&str, String)]) -> String {
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

    /// Rewrite `/etc/exports`, replacing any line for `path` with `line`.
    /// `line = None` removes the export. Returns the new file contents.
    ///
    /// Lines are matched on the quoted path Unraid writes (`"/mnt/user/pbs"`)
    /// and on the bare path, so a hand-edited table is still matched rather
    /// than silently duplicated.
    fn rewrite_exports(current: &str, path: &str, line: Option<&str>) -> String {
        let quoted = format!("\"{path}\"");
        let mut out: Vec<String> = current
            .lines()
            .filter(|l| {
                let t = l.trim();
                let first = t.split_whitespace().next().unwrap_or_default();
                first != quoted && first != path
            })
            .map(str::to_string)
            .collect();
        if let Some(l) = line {
            out.push(l.to_string());
        }
        let mut joined = out.join("\n");
        joined.push('\n');
        joined
    }

    /// The `/etc/exports` line for an entry, in Unraid's own shape.
    fn exports_line(entry: &ExportEntry) -> String {
        let mut export_opts = Vec::new();
        if let Some(fsid) = entry.fsid.as_deref().filter(|s| !s.is_empty()) {
            export_opts.push(format!("fsid={fsid}"));
        }
        export_opts.push("async".to_string());
        export_opts.push("no_subtree_check".to_string());
        format!(
            "\"{}\" -{} {}",
            entry.path,
            export_opts.join(","),
            Self::render_host_list(&entry.allowed_clients, &entry.options)
        )
    }

    /// Re-read the live export table so callers see what was actually applied.
    fn reexport() -> Result<(), StorageError> {
        let out = Command::new("exportfs")
            .arg("-ra")
            .output()
            .map_err(|e| StorageError::Other(format!("run `exportfs -ra`: {e}")))?;
        if !out.status.success() {
            return Err(StorageError::Other(format!(
                "`exportfs -ra` failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }
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

    async fn list_exports(&self) -> Result<Vec<ExportEntry>, StorageError> {
        let dir = fs::read_dir(SHARE_CFG_DIR)
            .map_err(|e| StorageError::Other(format!("read {SHARE_CFG_DIR}: {e}")))?;
        let mut out = Vec::new();
        for ent in dir.flatten() {
            let p = ent.path();
            if p.extension().and_then(|s| s.to_str()) != Some("cfg") {
                continue;
            }
            let Some(name) = p.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            // An unreadable share cfg is skipped, not fatal: one bad file must
            // not blind the caller to every other export on the host.
            let Ok(text) = fs::read_to_string(&p) else {
                continue;
            };
            if let Some(e) = Self::entry_from_cfg(name, &text) {
                out.push(e);
            }
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    async fn upsert_export(&self, entry: &ExportEntry) -> Result<ExportEntry, StorageError> {
        let name = Self::share_name(&entry.path)?;
        let cfg = Self::cfg_path(&name);
        // The share must already exist: creating one is array/disk business
        // (`Capability::Create`), not export authoring.
        let text = fs::read_to_string(&cfg).map_err(|e| {
            StorageError::Other(format!(
                "share '{name}' has no config at {}: {e}",
                cfg.display()
            ))
        })?;

        // 1. Persist intent first, so a crash between the two writes leaves the
        //    durable record ahead of the live table rather than behind it.
        let updates = vec![
            ("shareExportNFS", NFS_ENABLED.to_string()),
            ("shareExportNFSFsid", entry.fsid.clone().unwrap_or_default()),
            (
                "shareHostListNFS",
                Self::render_host_list(&entry.allowed_clients, &entry.options),
            ),
        ];
        fs::write(&cfg, Self::write_cfg_keys(&text, &updates))
            .map_err(|e| StorageError::Other(format!("write {}: {e}", cfg.display())))?;

        // 2. Make it live.
        let current = fs::read_to_string(EXPORTS_FILE).unwrap_or_default();
        let next = Self::rewrite_exports(&current, &entry.path, Some(&Self::exports_line(entry)));
        fs::write(EXPORTS_FILE, next)
            .map_err(|e| StorageError::Other(format!("write {EXPORTS_FILE}: {e}")))?;
        Self::reexport()?;

        // 3. Read back rather than echo the request, so a value the host
        //    normalized or refused is visible to the caller.
        let after = fs::read_to_string(&cfg)
            .map_err(|e| StorageError::Other(format!("re-read {}: {e}", cfg.display())))?;
        Self::entry_from_cfg(&name, &after).ok_or_else(|| {
            StorageError::Other(format!(
                "share '{name}' is still not NFS-exported after the write"
            ))
        })
    }

    async fn remove_export(&self, path: &str) -> Result<(), StorageError> {
        let name = Self::share_name(path)?;
        let cfg = Self::cfg_path(&name);

        // Idempotent: a share with no config is already not exported.
        if let Ok(text) = fs::read_to_string(&cfg) {
            let updates = vec![("shareExportNFS", "-".to_string())];
            fs::write(&cfg, Self::write_cfg_keys(&text, &updates))
                .map_err(|e| StorageError::Other(format!("write {}: {e}", cfg.display())))?;
        }

        let current = fs::read_to_string(EXPORTS_FILE).unwrap_or_default();
        let next = Self::rewrite_exports(&current, path, None);
        fs::write(EXPORTS_FILE, next)
            .map_err(|e| StorageError::Other(format!("write {EXPORTS_FILE}: {e}")))?;
        Self::reexport()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn parses_a_real_share_cfg() {
        let e = UnraidExports::entry_from_cfg("pbs", PBS_CFG).expect("exported");
        assert_eq!(e.path, "/mnt/user/pbs");
        assert_eq!(e.allowed_clients, vec!["10.0.0.17"]);
        assert_eq!(e.fsid.as_deref(), Some("209"));
        assert_eq!(
            e.options,
            vec!["rw", "sync", "no_subtree_check", "no_root_squash"]
        );
    }

    #[test]
    fn a_share_that_is_not_nfs_exported_is_not_an_entry() {
        let cfg = PBS_CFG.replace(r#"shareExportNFS="e""#, r#"shareExportNFS="-""#);
        assert!(UnraidExports::entry_from_cfg("pbs", &cfg).is_none());
    }

    #[test]
    fn host_list_round_trips() {
        let (clients, opts) =
            UnraidExports::parse_host_list("10.0.0.17(rw,sync) 10.0.0.18(rw,sync)");
        assert_eq!(clients, vec!["10.0.0.17", "10.0.0.18"]);
        assert_eq!(opts, vec!["rw", "sync"]);
        assert_eq!(
            UnraidExports::render_host_list(&clients, &opts),
            "10.0.0.17(rw,sync) 10.0.0.18(rw,sync)"
        );
    }

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

    #[test]
    fn exports_line_matches_unraid_shape() {
        let e = UnraidExports::entry_from_cfg("pbs", PBS_CFG).unwrap();
        assert_eq!(
            UnraidExports::exports_line(&e),
            "\"/mnt/user/pbs\" -fsid=209,async,no_subtree_check \
             10.0.0.17(rw,sync,no_subtree_check,no_root_squash)"
        );
    }

    #[test]
    fn rewrite_replaces_the_matching_line_only() {
        let current = "\"/mnt/user/data\" -fsid=102 10.0.0.5(rw)\n\
                       \"/mnt/user/pbs\" -fsid=209 10.0.0.17(rw)\n";
        let out = UnraidExports::rewrite_exports(current, "/mnt/user/pbs", Some("NEW"));
        assert!(out.contains("\"/mnt/user/data\""));
        assert!(!out.contains("-fsid=209"));
        assert!(out.contains("NEW"));
    }

    #[test]
    fn rewrite_removes_when_no_line_given() {
        let current = "\"/mnt/user/pbs\" -fsid=209 10.0.0.17(rw)\n";
        let out = UnraidExports::rewrite_exports(current, "/mnt/user/pbs", None);
        assert!(!out.contains("pbs"));
    }

    /// Only user shares are addressable — anything else has no cfg to persist
    /// into, so accepting it would create an export that vanishes on reboot.
    #[test]
    fn rejects_paths_that_are_not_user_shares() {
        assert!(UnraidExports::share_name("/mnt/disk1/pbs").is_err());
        assert!(UnraidExports::share_name("/mnt/user").is_err());
        assert!(UnraidExports::share_name("/mnt/user/a/b").is_err());
        assert_eq!(UnraidExports::share_name("/mnt/user/pbs").unwrap(), "pbs");
        assert_eq!(UnraidExports::share_name("/mnt/user/pbs/").unwrap(), "pbs");
    }
}
