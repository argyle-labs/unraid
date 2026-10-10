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
    for tok in rest.split_whitespace() {
        let group = match tok.strip_prefix('-') {
            Some(d) => d,
            None => tok
                .split_once('(')
                .map_or("", |(_, o)| o.trim_end_matches(')')),
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

    let squashed: Vec<&str> = entries
        .iter()
        .filter(|e| e.options.iter().any(|o| o == "all_squash"))
        .map(|e| e.path.as_str())
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
                squashed.join(", ")
            ),
            None,
        )
    });

    let mut by_fsid: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut no_fsid = Vec::new();
    for e in &entries {
        match e.fsid.as_deref() {
            Some(f) => by_fsid.entry(f).or_default().push(&e.path),
            None => no_fsid.push(e.path.as_str()),
        }
    }
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
    } else if !no_fsid.is_empty() {
        (
            Severity::Warn,
            "NFS exports without an explicit fsid",
            format!(
                "no fsid on: {}. FUSE-backed exports (/mnt/user) need an explicit fsid to be \
                 exportable and stable.",
                no_fsid.join(", ")
            ),
        )
    } else {
        (
            Severity::Ok,
            "NFS fsids are unique on this host",
            format!(
                "fsids: {table}. Uniqueness across servers is not checked here; compare with \
                 other hosts before one client mounts exports from both."
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
    fn all_squash_is_warn_naming_the_export() {
        let f = run("\"/mnt/user/pbs\" -fsid=109 10.0.0.5(sec=sys,rw,all_squash,anonuid=99)\n");
        let s = by_id(&f, "nfs-all-squash");
        assert_eq!(s.severity, Severity::Warn);
        assert!(s.detail.contains("/mnt/user/pbs"));
    }

    #[test]
    fn duplicate_fsid_across_share_and_pool_is_crit() {
        let f = run("\"/mnt/user/a\" -fsid=7 *(rw)\n/mnt/cache/b *(rw,fsid=7)\n");
        let d = by_id(&f, "nfs-fsid");
        assert_eq!(d.severity, Severity::Crit);
        assert!(d.detail.contains("fsid 7: /mnt/user/a, /mnt/cache/b"));
    }

    #[test]
    fn missing_fsid_is_warn() {
        let f = run("\"/mnt/user/a\" -async *(rw)\n");
        assert_eq!(by_id(&f, "nfs-fsid").severity, Severity::Warn);
    }

    #[test]
    fn no_exports_yields_nothing() {
        assert!(check("/nonexistent/exports").is_empty());
        assert!(run("# nothing\n").is_empty());
    }
}
