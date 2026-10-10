//! Read-only detection of a parity check or resync competing with share I/O.
//!
//! A running parity check on a host with no I/O headroom drives load past the
//! core count and starves SMB/NFS, so client write errors and aborted
//! post-processing during it are a symptom, not independent faults. Reads
//! Unraid's `mdResync*` keys from `/proc/mdstat`, plus `/proc/loadavg` and
//! `/proc/cpuinfo`; no subprocesses.

use std::fs;
use std::path::Path;

use plugin_toolkit::contract::diagnostics::{Finding, Severity};

use crate::checks::finding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Resync {
    Idle,
    /// `mdResync > 0`: an operation is running.
    Running {
        action: String,
        pos: u64,
        total: u64,
    },
    /// `mdResync == 0` with a nonzero position: started, then paused.
    Paused {
        action: String,
        pos: u64,
        total: u64,
    },
}

/// Classify Unraid's `/proc/mdstat`. `mdResyncAction` outlives the operation,
/// so it never decides activity on its own.
pub(crate) fn parse_mdstat(text: &str) -> Resync {
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix('='))
            .map(str::trim)
    };
    let num = |k: &str| get(k).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let action = get("mdResyncAction").unwrap_or("").to_string();
    let (pos, total) = (num("mdResyncPos"), num("mdResyncSize"));
    if num("mdResync") > 0 {
        Resync::Running { action, pos, total }
    } else if pos > 0 {
        Resync::Paused { action, pos, total }
    } else {
        Resync::Idle
    }
}

pub(crate) fn parse_load1(text: &str) -> Option<f64> {
    text.split_whitespace().next()?.parse().ok()
}

pub(crate) fn count_cpus(cpuinfo: &str) -> usize {
    cpuinfo
        .lines()
        .filter(|l| l.split(':').next().map(str::trim) == Some("processor"))
        .count()
}

fn progress(action: &str, pos: u64, total: u64) -> String {
    if total > 0 {
        format!("'{action}' at {:.1}%", pos as f64 * 100.0 / total as f64)
    } else {
        format!("'{action}'")
    }
}

pub(crate) fn check(proc_root: &str) -> Vec<Finding> {
    let root = Path::new(proc_root);
    let read = |name: &str| fs::read_to_string(root.join(name)).unwrap_or_default();
    let id = "parity-io-starvation";
    // A missing mdstat means no md driver, so no array to check; any other
    // read failure leaves parity state unknown.
    let mdstat = match fs::read_to_string(root.join("mdstat")) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return vec![finding(
                id,
                Severity::Info,
                "Parity state unreadable",
                format!("{proc_root}/mdstat is unreadable ({e}); parity activity is unknown."),
                None,
            )];
        }
    };
    let (action, pos, total) = match parse_mdstat(&mdstat) {
        Resync::Idle => {
            return vec![finding(
                id,
                Severity::Ok,
                "No parity check or resync running",
                "mdResync is 0; array I/O is not competing with a parity operation".to_string(),
                None,
            )];
        }
        Resync::Paused { action, pos, total } => {
            return vec![finding(
                id,
                Severity::Info,
                "Parity check paused",
                format!(
                    "Parity operation {} is paused; it is not loading the disks now and \
                     will when resumed.",
                    progress(&action, pos, total)
                ),
                None,
            )];
        }
        Resync::Running { action, pos, total } => (action, pos, total),
    };
    let what = progress(&action, pos, total);
    let load = parse_load1(&read("loadavg")).unwrap_or(0.0);
    let cpus = count_cpus(&read("cpuinfo")).max(1);
    vec![if load > cpus as f64 {
        finding(
            id,
            Severity::Warn,
            "Parity check running while load is above the core count",
            format!(
                "Parity operation {what} is running with 1-min load {load:.1} on {cpus} CPUs. \
                 SMB/NFS clients are likely to see slow or failed writes until it finishes; \
                 treat downstream write errors and aborted post-processing as a symptom of the \
                 check. Pause it, or schedule it outside busy hours."
            ),
            None,
        )
    } else {
        finding(
            id,
            Severity::Info,
            "Parity check running",
            format!(
                "Parity operation {what} is running; 1-min load {load:.1} on {cpus} CPUs. Share \
                 I/O is slower than usual."
            ),
            None,
        )
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeRoot;

    const RUNNING: &str =
        "mdResyncAction=check P\nmdResyncSize=1000\nmdResync=1000\nmdResyncPos=250\n";
    const PAUSED: &str = "mdResyncAction=check P\nmdResyncSize=1000\nmdResync=0\nmdResyncPos=250\n";
    const IDLE: &str = "mdResyncAction=check P\nmdResyncSize=1000\nmdResync=0\nmdResyncPos=0\n";
    const CPUINFO4: &str =
        "processor\t: 0\nmodel name\t: x\n\nprocessor\t: 1\n\nprocessor\t: 2\n\nprocessor\t: 3\n";

    fn fake(mdstat: &str, loadavg: &str) -> FakeRoot {
        let r = FakeRoot::new("parity");
        r.write("mdstat", mdstat)
            .write("loadavg", loadavg)
            .write("cpuinfo", CPUINFO4);
        r
    }

    #[test]
    fn classifies_running_paused_and_idle() {
        assert_eq!(
            parse_mdstat(RUNNING),
            Resync::Running {
                action: "check P".into(),
                pos: 250,
                total: 1000
            }
        );
        assert_eq!(
            parse_mdstat(PAUSED),
            Resync::Paused {
                action: "check P".into(),
                pos: 250,
                total: 1000
            }
        );
        assert_eq!(
            parse_mdstat(IDLE),
            Resync::Idle,
            "stale action alone is idle"
        );
        assert_eq!(parse_mdstat(""), Resync::Idle);
    }

    #[test]
    fn counts_processors_and_load() {
        assert_eq!(count_cpus(CPUINFO4), 4);
        assert_eq!(parse_load1("24.31 19.02 12.00 3/900 1234\n"), Some(24.31));
    }

    #[test]
    fn overloaded_check_is_warn() {
        let r = fake(RUNNING, "24.31 19.02 12.00 3/900 1234\n");
        let f = check(r.str());
        assert_eq!(f[0].severity, Severity::Warn);
        assert_eq!(
            f[0].title,
            "Parity check running while load is above the core count"
        );
        assert!(f[0].detail.contains("'check P' at 25.0%"));
        assert!(f[0].repair.is_none());
    }

    #[test]
    fn light_check_is_info_paused_is_info_idle_is_ok() {
        let r = fake(RUNNING, "1.50 1.00 1.00 1/200 1\n");
        assert_eq!(check(r.str())[0].title, "Parity check running");
        r.write("mdstat", PAUSED)
            .write("loadavg", "24.0 1 1 1/1 1\n");
        let p = check(r.str());
        assert_eq!(p[0].severity, Severity::Info);
        assert_eq!(p[0].title, "Parity check paused");
        r.write("mdstat", IDLE);
        assert_eq!(check(r.str())[0].severity, Severity::Ok);
    }

    #[test]
    fn non_unraid_host_is_ok() {
        assert_eq!(check("/nonexistent/proc")[0].severity, Severity::Ok);
    }

    #[test]
    fn unreadable_mdstat_is_info_not_idle() {
        let r = FakeRoot::new("parity-unreadable");
        r.mkdir("mdstat");
        let f = check(r.str());
        assert_eq!(f[0].severity, Severity::Info);
        assert_eq!(f[0].title, "Parity state unreadable");
    }
}
