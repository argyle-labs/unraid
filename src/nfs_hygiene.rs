//! Read-only NFS export hygiene from the live `/etc/exports` table, covering
//! every export (user shares, disks, pools), not only `/mnt/user`.
//!
//! Defects this host can see on its own:
//! - `all_squash` maps every client uid to `anonuid`, so a client that must own
//!   its files (PBS chowns datastore chunks to `backup`) fails with EPERM.
//! - a duplicated or missing fsid. Uniqueness across servers is fleet-level, so
//!   the fsids are listed for orca to compare.

use std::collections::BTreeMap;
use std::fs;

use plugin_toolkit::contract::diagnostics::{Finding, Severity};

use crate::checks::finding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Export {
    pub path: String,
    pub fsid: Option<String>,
    /// Union of the default group and every per-client option group.
    pub options: Vec<String>,
    /// Clients whose effective options include `all_squash`.
    pub squashed_clients: Vec<String>,
}

/// One `/etc/exports` line: path (quoted or bare), an optional `-defaults`
/// group, then `client(opts)` groups. `None` for comments and blanks.
pub(crate) fn parse_line(line: &str) -> Option<Export> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (path, rest) = match line.strip_prefix('"') {
        Some(r) => r.split_once('"')?,
        None => line.split_once(char::is_whitespace).unwrap_or((line, "")),
    };
    let mut options: Vec<String> = Vec::new();
    let mut squashed_clients = Vec::new();
    let mut default_squash = false;
    for tok in rest.split_whitespace() {
        let has_squash = |g: &str| g.split(',').any(|o| o == "all_squash");
        let group = match tok.strip_prefix('-') {
            Some(d) => {
                default_squash |= has_squash(d);
                d
            }
            None => {
                let (client, g) = tok
                    .split_once('(')
                    .map_or((tok, ""), |(c, o)| (c, o.trim_end_matches(')')));
                if default_squash || has_squash(g) {
                    squashed_clients.push(client.to_string());
                }
                g
            }
        };
        for o in group.split(',').filter(|o| !o.is_empty()) {
            if !options.iter().any(|x| x == o) {
                options.push(o.to_string());
            }
        }
    }
    let fsid = options
        .iter()
        .find_map(|o| o.strip_prefix("fsid="))
        .map(str::to_string);
    Some(Export {
        path: path.to_string(),
        fsid,
        options,
        squashed_clients,
    })
}

pub(crate) fn check(exports_path: &str) -> Vec<Finding> {
    let Ok(text) = fs::read_to_string(exports_path) else {
        return Vec::new();
    };
    let entries: Vec<Export> = text.lines().filter_map(parse_line).collect();
    if entries.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();

    let squashed: Vec<String> = entries
        .iter()
        .filter(|e| !e.squashed_clients.is_empty())
        .map(|e| format!("{} for {}", e.path, e.squashed_clients.join(", ")))
        .collect();
    out.push(if squashed.is_empty() {
        finding(
            "nfs-all-squash",
            Severity::Ok,
            "No NFS export squashes all users",
            "no export carries all_squash".to_string(),
            None,
        )
    } else {
        finding(
            "nfs-all-squash",
            Severity::Warn,
            "NFS exports squash every client user",
            format!(
                "all_squash on: {}. Every client uid is mapped to anonuid, so clients that need \
                 to own files (e.g. a PBS datastore) fail with EPERM. Use root_squash or \
                 no_root_squash for those exports.",
                squashed.join("; ")
            ),
            None,
        )
    });

    let mut by_fsid: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    // shfs (FUSE) has no stable device number, so a user-share export needs an
    // explicit fsid; disk and pool exports get one derived from their device.
    let (mut no_fsid_fuse, mut no_fsid_dev) = (Vec::new(), Vec::new());
    for e in &entries {
        match e.fsid.as_deref() {
            Some(f) => by_fsid.entry(f).or_default().push(&e.path),
            None if e.path.starts_with("/mnt/user/") => no_fsid_fuse.push(e.path.as_str()),
            None => no_fsid_dev.push(e.path.as_str()),
        }
    }
    let dev_note = if no_fsid_dev.is_empty() {
        String::new()
    } else {
        format!(
            " No explicit fsid on {} (disk/pool exports): the kernel derives one from the \
             device, which changes if the device is renumbered.",
            no_fsid_dev.join(", ")
        )
    };
    let dups: Vec<String> = by_fsid
        .iter()
        .filter(|(_, p)| p.len() > 1)
        .map(|(f, p)| format!("fsid {f}: {}", p.join(", ")))
        .collect();
    let table = by_fsid
        .iter()
        .map(|(f, p)| format!("{}={f}", p.join("+")))
        .collect::<Vec<_>>()
        .join(", ");
    let (sev, title, detail) = if !dups.is_empty() {
        (
            Severity::Crit,
            "Duplicate NFS fsids on this host",
            format!(
                "{}. Clients get file-handle collisions (Stale file handle). Give each export a \
                 unique fsid.",
                dups.join("; ")
            ),
        )
    } else if !no_fsid_fuse.is_empty() {
        (
            Severity::Warn,
            "User-share NFS exports without an explicit fsid",
            format!(
                "no fsid on: {}. These are shfs (FUSE) exports, which have no stable device \
                 number, so without an explicit fsid client file handles go stale.{dev_note}",
                no_fsid_fuse.join(", ")
            ),
        )
    } else {
        (
            Severity::Ok,
            "NFS fsids are unique on this host",
            format!(
                "fsids: {table}. Uniqueness across servers is not checked here; compare with \
                 other hosts before one client mounts exports from both.{dev_note}"
            ),
        )
    };
    out.push(finding("nfs-fsid", sev, title, detail, None));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeRoot;

    const CLEAN: &str = "\
# generated
\"/mnt/user/data\" -fsid=102,async,no_subtree_check 10.0.0.0/24(sec=sys,rw,root_squash)
\"/mnt/user/pbs\" -fsid=109,async,no_subtree_check 10.0.0.5(sec=sys,rw,no_root_squash)
/mnt/disk1 10.0.0.0/24(rw,fsid=1)
";

    fn run(text: &str) -> Vec<Finding> {
        let r = FakeRoot::new("exports");
        r.write("exports", text);
        check(&format!("{}/exports", r.str()))
    }

    fn by_id<'a>(f: &'a [Finding], id: &str) -> &'a Finding {
        f.iter().find(|f| f.id == id).unwrap()
    }

    #[test]
    fn parses_quoted_bare_and_per_client_fsid() {
        let e: Vec<Export> = CLEAN.lines().filter_map(parse_line).collect();
        assert_eq!(e.len(), 3);
        assert_eq!(e[0].fsid.as_deref(), Some("102"));
        assert_eq!(e[2].path, "/mnt/disk1");
        assert_eq!(e[2].fsid.as_deref(), Some("1"));
    }

    #[test]
    fn clean_table_is_ok_and_lists_fsids_including_disks() {
        let f = run(CLEAN);
        assert_eq!(by_id(&f, "nfs-all-squash").severity, Severity::Ok);
        let fsid = by_id(&f, "nfs-fsid");
        assert_eq!(fsid.severity, Severity::Ok);
        assert!(fsid.detail.contains("/mnt/user/data=102"));
        assert!(fsid.detail.contains("/mnt/disk1=1"));
    }

    #[test]
    fn all_squash_is_reported_per_client() {
        let f = run(
            "\"/mnt/user/pbs\" -fsid=109 10.0.0.5(sec=sys,rw,all_squash) 10.0.0.6(rw,root_squash)\n",
        );
        let s = by_id(&f, "nfs-all-squash");
        assert_eq!(s.severity, Severity::Warn);
        assert!(s.detail.contains("/mnt/user/pbs for 10.0.0.5."));
        assert!(!s.detail.contains("10.0.0.6"));
    }

    #[test]
    fn default_group_all_squash_applies_to_every_client() {
        let e = parse_line("\"/mnt/user/a\" -fsid=1,all_squash h1(rw) h2(ro)").unwrap();
        assert_eq!(e.squashed_clients, ["h1", "h2"]);
    }

    #[test]
    fn duplicate_fsid_across_share_and_pool_is_crit() {
        let f = run("\"/mnt/user/a\" -fsid=7 *(rw)\n/mnt/cache/b *(rw,fsid=7)\n");
        let d = by_id(&f, "nfs-fsid");
        assert_eq!(d.severity, Severity::Crit);
        assert!(d.detail.contains("fsid 7: /mnt/user/a, /mnt/cache/b"));
    }

    #[test]
    fn missing_fsid_on_user_share_warns_on_disk_only_notes() {
        let f = run("\"/mnt/user/a\" -async *(rw)\n/mnt/disk2 *(rw)\n");
        let w = by_id(&f, "nfs-fsid");
        assert_eq!(w.severity, Severity::Warn);
        assert!(w.detail.contains("shfs (FUSE)"));
        assert!(w.detail.contains("/mnt/disk2 (disk/pool exports)"));

        let f = run("/mnt/disk2 *(rw)\n");
        let o = by_id(&f, "nfs-fsid");
        assert_eq!(o.severity, Severity::Ok);
        assert!(o.detail.contains("derives one from the device"));
    }

    #[test]
    fn no_exports_yields_nothing() {
        assert!(check("/nonexistent/exports").is_empty());
        assert!(run("# nothing\n").is_empty());
    }
}
