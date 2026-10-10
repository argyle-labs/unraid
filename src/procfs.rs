//! Shared readers for kernel tables under `/proc`.

use std::fs;

/// One `/proc/mounts` row, with octal escapes (`\040` = space) decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub opts: String,
}

impl MountEntry {
    pub fn has_opt(&self, opt: &str) -> bool {
        self.opts.split(',').any(|o| o == opt)
    }
}

/// Decode the kernel's `\ooo` octal escapes in a mount-table field.
pub fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let oct = s
            .get(i + 1..i + 4)
            .filter(|d| d.bytes().all(|c| (b'0'..=b'7').contains(&c)));
        if b[i] == b'\\'
            && let Some(v) = oct.and_then(|d| u8::from_str_radix(d, 8).ok())
        {
            out.push(v);
            i += 4;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_mounts(text: &str) -> Vec<MountEntry> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some(MountEntry {
                source: unescape(f.next()?),
                target: unescape(f.next()?),
                fstype: f.next()?.to_string(),
                opts: f.next()?.to_string(),
            })
        })
        .collect()
}

/// Mount table at `path` (normally `/proc/mounts`); empty when unreadable.
pub fn read_mounts(path: &str) -> Vec<MountEntry> {
    fs::read_to_string(path)
        .map(|t| parse_mounts(&t))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rows_and_decodes_escapes() {
        let m = parse_mounts(
            "/dev/sda1 /boot vfat rw,fmask=0177 0 0\n//h/My\\040Share /mnt/a\\040b cifs rw,mapposix 0 0\nshort\n",
        );
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].target, "/boot");
        assert_eq!(m[0].fstype, "vfat");
        assert_eq!(m[1].source, "//h/My Share");
        assert_eq!(m[1].target, "/mnt/a b");
        assert!(m[1].has_opt("mapposix"));
        assert!(!m[1].has_opt("map"));
    }

    #[test]
    fn unescape_leaves_non_octal_backslashes() {
        assert_eq!(unescape(r"a\9zz"), r"a\9zz");
        assert_eq!(unescape(r"tail\04"), r"tail\04");
        assert_eq!(unescape(r"x\134y"), r"x\y");
    }
}
