//! Read-only SMB share inventory and guest-write check.
//!
//! Reads Unraid's generated `/etc/samba/smb-shares.conf` (world-readable) and,
//! when readable, the operator's `/boot/config/smb-extra.conf` (root-only),
//! which can define more shares. Access follows Samba's rules: a non-empty
//! `valid users` admits only those users, so guests are refused whatever
//! `public` says; `write list` grants write on a read-only share.

use std::fs;

use plugin_toolkit::contract::diagnostics::{Finding, Severity};

use crate::checks::finding;

pub(crate) const SHARES_CONF: &str = "/etc/samba/smb-shares.conf";
pub(crate) const EXTRA_CONF: &str = "/boot/config/smb-extra.conf";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct SmbShare {
    pub name: String,
    pub path: String,
    pub guest_ok: bool,
    /// `guest only`: every connection runs as the guest account.
    pub guest_only: bool,
    /// The account guests run as (`guest account`, Samba default `nobody`).
    pub guest_account: String,
    pub writeable: bool,
    pub valid_users: Vec<String>,
    pub write_list: Vec<String>,
    pub invalid_users: Vec<String>,
}

impl SmbShare {
    /// Guests can connect: `public`/`guest ok` set and no `valid users` gate.
    pub fn guests_admitted(&self) -> bool {
        self.guest_ok && self.valid_users.is_empty()
    }

    /// Anyone on the network can write without authenticating: the share is
    /// writable, or the guest account is in `write list`.
    pub fn guest_writable(&self) -> bool {
        self.guests_admitted() && (self.writeable || self.write_list.contains(&self.guest_account))
    }

    pub fn mode(&self) -> &'static str {
        if self.guest_writable() {
            "public"
        } else if self.guests_admitted() {
            "secure"
        } else {
            "private"
        }
    }
}

fn yes(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "yes" | "true" | "1")
}

fn users(v: &str) -> Vec<String> {
    v.split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

pub(crate) fn parse(text: &str) -> Vec<SmbShare> {
    let mut out: Vec<SmbShare> = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push(SmbShare {
                name: name.to_string(),
                ..SmbShare::default()
            });
            continue;
        }
        let (Some(cur), Some((k, v))) = (out.last_mut(), line.split_once('=')) else {
            continue;
        };
        match k.trim().to_ascii_lowercase().as_str() {
            "path" => cur.path = v.trim().to_string(),
            "public" | "guest ok" => cur.guest_ok = yes(v),
            "guest only" | "only guest" => cur.guest_only = yes(v),
            "guest account" => cur.guest_account = v.trim().to_string(),
            "writeable" | "writable" => cur.writeable = yes(v),
            "read only" => cur.writeable = !yes(v),
            "valid users" => cur.valid_users = users(v),
            "write list" => cur.write_list = users(v),
            "invalid users" => cur.invalid_users = users(v),
            _ => {}
        }
    }
    let account = out
        .iter()
        .find(|s| s.name == "global" && !s.guest_account.is_empty())
        .map_or_else(|| "nobody".to_string(), |g| g.guest_account.clone());
    out.retain(|s| !matches!(s.name.as_str(), "global" | "homes" | "printers"));
    for s in &mut out {
        s.guest_account.clone_from(&account);
    }
    out
}

fn describe(s: &SmbShare) -> String {
    let mut d = format!("{}={}", s.name, s.mode());
    if s.guest_only && s.guests_admitted() {
        d.push_str(" (guest only)");
    }
    if !s.write_list.is_empty() {
        d.push_str(&format!(" (writers: {})", s.write_list.join(",")));
    }
    if !s.invalid_users.is_empty() {
        d.push_str(&format!(" (denied: {})", s.invalid_users.join(",")));
    }
    d
}

pub(crate) fn check(shares_conf: &str, extra_conf: &str) -> Vec<Finding> {
    let Ok(text) = fs::read_to_string(shares_conf) else {
        return Vec::new();
    };
    let mut shares = parse(&text);
    let extra = fs::read_to_string(extra_conf).ok();
    if let Some(t) = &extra {
        shares.extend(parse(t));
    }
    if shares.is_empty() {
        return Vec::new();
    }
    let scope = if extra.is_some() {
        "smb-shares.conf and smb-extra.conf"
    } else {
        "smb-shares.conf (smb-extra.conf unreadable, not checked)"
    };
    let inventory = shares.iter().map(describe).collect::<Vec<_>>().join(", ");
    let public: Vec<&str> = shares
        .iter()
        .filter(|s| s.guest_writable())
        .map(|s| s.name.as_str())
        .collect();
    vec![if public.is_empty() {
        finding(
            "smb-share-security",
            Severity::Ok,
            "No SMB share allows guest writes",
            format!("Checked {scope}. Shares: {inventory}."),
            None,
        )
    } else {
        finding(
            "smb-share-security",
            Severity::Warn,
            "SMB shares writable by guests",
            format!(
                "Share(s) {} allow unauthenticated writes from anyone on the network. Set \
                 Security to Secure or Private under Shares -> <share> -> SMB. Checked {scope}. \
                 Shares: {inventory}.",
                public.join(", ")
            ),
            None,
        )
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeRoot;

    const CONF: &str = "\
[global]
\tpublic = yes
[data]
\tpath = /mnt/user/data
\tpublic = yes
\twriteable = yes
[media]
\tpath = /mnt/user/media
\tpublic = yes
\twriteable = no
\twrite list = scott
[backups]
\tpath = /mnt/user/backups
\tpublic = yes
\twriteable = yes
\tvalid users = scott
\tinvalid users = guest
";

    #[test]
    fn modes_follow_samba_access_rules() {
        let s = parse(CONF);
        let modes: Vec<(&str, &str)> = s.iter().map(|s| (s.name.as_str(), s.mode())).collect();
        assert_eq!(
            modes,
            [
                ("data", "public"),
                ("media", "secure"),
                ("backups", "private")
            ],
            "valid users overrides public"
        );
        assert_eq!(s[1].write_list, ["scott"]);
        assert_eq!(s[2].invalid_users, ["guest"]);
    }

    #[test]
    fn read_only_no_is_writeable() {
        assert_eq!(
            parse("[x]\nguest ok = yes\nread only = no\n")[0].mode(),
            "public"
        );
    }

    #[test]
    fn public_share_warns_and_names_the_scope() {
        let r = FakeRoot::new("smb");
        r.write("shares.conf", CONF);
        let f = check(
            &format!("{}/shares.conf", r.str()),
            "/nonexistent/extra.conf",
        );
        assert_eq!(f[0].severity, Severity::Warn);
        assert!(f[0].detail.starts_with("Share(s) data allow"));
        assert!(f[0].detail.contains("smb-extra.conf unreadable"));
        assert!(f[0].detail.contains("media=secure (writers: scott)"));
    }

    #[test]
    fn extra_conf_shares_are_included() {
        let r = FakeRoot::new("smb-extra");
        r.write("shares.conf", "[media]\npublic = yes\nwriteable = no\n")
            .write(
                "extra.conf",
                "[scratch]\npath = /mnt/cache/s\nguest ok = yes\nwritable = yes\n",
            );
        let ok = check(&format!("{}/shares.conf", r.str()), "/nonexistent/x");
        assert_eq!(ok[0].severity, Severity::Ok);
        let f = check(
            &format!("{}/shares.conf", r.str()),
            &format!("{}/extra.conf", r.str()),
        );
        assert_eq!(f[0].severity, Severity::Warn);
        assert!(f[0].detail.contains("scratch"));
        assert!(f[0].detail.contains("and smb-extra.conf"));
    }

    #[test]
    fn missing_table_yields_nothing() {
        assert!(check("/nonexistent/smb-shares.conf", "/nonexistent/x").is_empty());
    }

    #[test]
    fn guest_account_in_write_list_makes_a_secure_share_guest_writable() {
        let s = parse("[m]\npublic = yes\nwriteable = no\nwrite list = nobody\n");
        assert!(s[0].guest_writable());
        assert_eq!(s[0].mode(), "public");
        let s = parse("[global]\nguest account = guest\n[m]\npublic = yes\nwrite list = nobody\n");
        assert!(!s[0].guest_writable(), "a different guest account");
        let s = parse("[global]\nguest account = guest\n[m]\npublic = yes\nwrite list = guest\n");
        assert!(s[0].guest_writable());
    }

    #[test]
    fn guest_only_is_reported() {
        let s = parse("[m]\npublic = yes\nguest only = yes\nwriteable = no\n");
        assert!(s[0].guest_only);
        assert_eq!(describe(&s[0]), "m=secure (guest only)");
    }
}
