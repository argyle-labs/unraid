//! Read-only report of Unraid host identity and time settings from `ident.cfg`,
//! with stable `key=value` text so orca can compare hosts for drift.
//! `NAME`/`COMMENT`/`SYS_MODEL` can only be changed with the array stopped.

use std::fs;

use plugin_toolkit::contract::diagnostics::{Finding, Severity};

use crate::checks::{finding, parse_key_value};

pub(crate) const IDENT_CFG: &str = "/boot/config/ident.cfg";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct HostSettings {
    pub name: String,
    pub time_zone: String,
    pub use_ntp: bool,
    pub ntp_servers: Vec<String>,
    pub workgroup: String,
}

pub(crate) fn parse(text: &str) -> HostSettings {
    let kv = parse_key_value(text);
    let get = |k: &str| kv.get(k).cloned().unwrap_or_default();
    HostSettings {
        name: get("NAME"),
        time_zone: get("timeZone"),
        use_ntp: get("USE_NTP").eq_ignore_ascii_case("yes"),
        ntp_servers: (1..=4)
            .map(|i| get(&format!("NTP_SERVER{i}")))
            .filter(|s| !s.trim().is_empty())
            .collect(),
        workgroup: get("WORKGROUP"),
    }
}

pub(crate) fn check(path: &str) -> Finding {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            return finding(
                "host-settings",
                Severity::Info,
                "Host settings unreadable",
                format!("{path} is unreadable ({e}); /boot is root-only, so this needs root."),
                None,
            );
        }
    };
    let s = parse(&text);
    let summary = format!(
        "name={} timeZone={} useNtp={} ntpServers=[{}] workgroup={}",
        s.name,
        s.time_zone,
        s.use_ntp,
        s.ntp_servers.join(","),
        s.workgroup
    );
    let mut problems = Vec::new();
    if !s.use_ntp {
        problems.push("NTP is disabled");
    } else if s.ntp_servers.is_empty() {
        problems.push("NTP is enabled but no NTP server is set");
    }
    if s.time_zone.is_empty() {
        problems.push("no timezone is set");
    }
    if problems.is_empty() {
        finding(
            "host-settings",
            Severity::Ok,
            "Host identity and time settings",
            summary,
            None,
        )
    } else {
        finding(
            "host-settings",
            Severity::Warn,
            "Host time settings need attention",
            format!("{}. {summary}", problems.join("; ")),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeRoot;

    const IDENT: &str = "NAME=\"willow\"\nCOMMENT=\"media\"\ntimeZone=\"America/Los_Angeles\"\n\
USE_NTP=\"yes\"\nNTP_SERVER1=\"time1.google.com\"\nNTP_SERVER2=\"\"\nNTP_SERVER3=\"pool.ntp.org\"\n\
WORKGROUP=\"WORKGROUP\"\n";

    fn run(text: &str) -> Finding {
        let r = FakeRoot::new("ident");
        r.write("ident.cfg", text);
        check(&format!("{}/ident.cfg", r.str()))
    }

    #[test]
    fn parses_ident_cfg_skipping_blank_ntp_slots() {
        let s = parse(IDENT);
        assert_eq!(s.name, "willow");
        assert_eq!(s.time_zone, "America/Los_Angeles");
        assert!(s.use_ntp);
        assert_eq!(s.ntp_servers, ["time1.google.com", "pool.ntp.org"]);
        assert_eq!(s.workgroup, "WORKGROUP");
    }

    #[test]
    fn healthy_settings_report_ok_with_comparable_summary() {
        let f = run(IDENT);
        assert_eq!(f.severity, Severity::Ok);
        assert!(f.detail.contains("timeZone=America/Los_Angeles"));
    }

    #[test]
    fn ntp_off_or_serverless_or_no_timezone_warns() {
        assert_eq!(
            run("timeZone=\"UTC\"\nUSE_NTP=\"no\"\n").severity,
            Severity::Warn
        );
        let f = run("timeZone=\"UTC\"\nUSE_NTP=\"yes\"\n");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.detail.contains("no NTP server"));
        assert!(
            run("USE_NTP=\"yes\"\nNTP_SERVER1=\"a\"\n")
                .detail
                .contains("no timezone")
        );
    }

    #[test]
    fn unreadable_cfg_is_info_naming_root() {
        let f = check("/nonexistent/ident.cfg");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.detail.contains("needs root"));
    }
}
