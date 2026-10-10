//! Read-only check that CIFS/SMB mounts can write names with SMB-reserved
//! characters (`:` `?` `*` `<` `>` `|` `"`).
//!
//! The Linux CIFS client remaps those characters when mounted with
//! `mapposix` (SFM private-range mapping) or `mapchars` (SFU mapping), or when
//! SMB3 POSIX extensions (`posix`) are negotiated. With any of them such names
//! write correctly, so app warnings about them are false alarms; without, the
//! writes fail. Reads the mount table only.

use plugin_toolkit::contract::diagnostics::{Finding, Severity};

use crate::checks::finding;
use crate::procfs::{MountEntry, read_mounts};

fn is_smb(m: &MountEntry) -> bool {
    m.fstype == "cifs" || m.fstype == "smb3"
}

fn is_smb3(m: &MountEntry) -> bool {
    m.fstype == "smb3"
        || m.opts
            .split(',')
            .any(|o| o.strip_prefix("vers=").is_some_and(|v| v.starts_with('3')))
}

/// Whether reserved characters survive on this mount.
pub(crate) fn maps_reserved_chars(m: &MountEntry) -> bool {
    m.has_opt("mapposix") || m.has_opt("mapchars") || (m.has_opt("posix") && is_smb3(m))
}

pub(crate) fn check(mounts_path: &str) -> Vec<Finding> {
    let mounts: Vec<MountEntry> = read_mounts(mounts_path)
        .into_iter()
        .filter(is_smb)
        .collect();
    if mounts.is_empty() {
        return Vec::new();
    }
    let (ok, bad): (Vec<&MountEntry>, Vec<&MountEntry>) =
        mounts.iter().partition(|m| maps_reserved_chars(m));
    let list = |v: &[&MountEntry]| {
        v.iter()
            .map(|m| format!("{} on {}", m.source, m.target))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let mut out = Vec::new();
    if !ok.is_empty() {
        out.push(finding(
            "cifs-mapposix",
            Severity::Ok,
            "SMB mounts map reserved characters",
            format!(
                "mapposix, mapchars or SMB3 posix is set on: {}. Filenames containing \
                 : ? * < > | \" write correctly; app warnings about such names on these paths \
                 are false alarms.",
                list(&ok)
            ),
            None,
        ));
    }
    if !bad.is_empty() {
        out.push(finding(
            "cifs-no-mapposix",
            Severity::Warn,
            "SMB mounts that cannot write reserved characters",
            format!(
                "no mapposix, mapchars or SMB3 posix on: {}. Writes of names containing \
                 : ? * < > | \" will fail. Remount with -o mapposix, or move the share to NFS.",
                list(&bad)
            ),
            None,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs::parse_mounts;
    use crate::test_support::FakeRoot;

    const MOUNTS: &str = "\
/dev/md1p1 /mnt/disk1 xfs rw,noatime 0 0
//willow/data /mnt/remotes/willow_data cifs rw,vers=3.1.1,mapposix,uid=99 0 0
//maple/My\\040Share /mnt/remotes/maple\\040share cifs rw,vers=3.0,nomapposix 0 0
//thor/dl /mnt/remotes/dl cifs rw,vers=2.1,mapchars 0 0
//odin/x /mnt/remotes/x cifs rw,vers=3.1.1,posix 0 0
//loki/y /mnt/remotes/y cifs rw,vers=2.0,posix 0 0
";

    fn by_target(t: &str) -> MountEntry {
        parse_mounts(MOUNTS)
            .into_iter()
            .find(|m| m.target == t)
            .unwrap()
    }

    #[test]
    fn mapping_options_are_recognised() {
        assert!(maps_reserved_chars(&by_target("/mnt/remotes/willow_data")));
        assert!(
            maps_reserved_chars(&by_target("/mnt/remotes/dl")),
            "mapchars"
        );
        assert!(
            maps_reserved_chars(&by_target("/mnt/remotes/x")),
            "posix on smb3"
        );
        assert!(
            !maps_reserved_chars(&by_target("/mnt/remotes/y")),
            "posix needs smb3"
        );
        assert!(
            !maps_reserved_chars(&by_target("/mnt/remotes/maple share")),
            "nomapposix"
        );
    }

    #[test]
    fn mixed_mounts_yield_ok_and_warn() {
        let r = FakeRoot::new("cifs");
        r.write("mounts", MOUNTS);
        let f = check(&format!("{}/mounts", r.str()));
        let ok = f.iter().find(|f| f.id == "cifs-mapposix").unwrap();
        assert_eq!(ok.severity, Severity::Ok);
        assert!(ok.detail.contains("//willow/data"));
        let bad = f.iter().find(|f| f.id == "cifs-no-mapposix").unwrap();
        assert_eq!(bad.severity, Severity::Warn);
        assert!(bad.detail.contains("//maple/My Share"));
        assert!(bad.detail.contains("//loki/y"));
        assert!(!bad.detail.contains("willow"));
    }

    #[test]
    fn no_smb_mounts_yields_nothing() {
        let r = FakeRoot::new("cifs-none");
        r.write("mounts", "/dev/sda1 / ext4 rw 0 0\n");
        assert!(check(&format!("{}/mounts", r.str())).is_empty());
        assert!(check("/nonexistent/mounts").is_empty());
    }
}
