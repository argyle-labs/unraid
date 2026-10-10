//! Read-only detection of processes stuck in uninterruptible sleep (`D`) on
//! FUSE (shfs), and of zombie processes inside Docker containers.
//!
//! `/proc` is sampled twice, [`SAMPLE_INTERVAL`] apart; only a pid in `D` on a
//! FUSE wait path in both samples is reported, so a slow uncached read does
//! not trip it. Process age is shown as a hint only: `/proc` records when a
//! process started, not when it entered `D`. No subprocesses.

use std::fs;
use std::path::Path;
use std::time::Duration;

use plugin_toolkit::contract::diagnostics::{Finding, Severity};

use crate::checks::finding;

/// Linux `USER_HZ`; `/proc/<pid>/stat` starttime is in these ticks.
const CLK_TCK: u64 = 100;

pub(crate) const SAMPLE_INTERVAL: Duration = Duration::from_secs(2);

/// Kernel symbols a task blocks in while waiting on a FUSE request or inode.
const FUSE_WAIT_SYMBOLS: &[&str] = &["fuse_", "request_wait_answer"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FuseWait {
    Yes,
    No,
    /// wchan is opaque (`0`/empty, as under kptr restrictions) and `stack` is
    /// unreadable (root-only), so the wait channel cannot be classified.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcInfo {
    pub pid: u32,
    pub comm: String,
    pub state: char,
    /// Seconds since the process started.
    pub age_secs: u64,
    pub wchan: String,
    pub fuse: FuseWait,
    /// Short (12-char) Docker container id, when the process is in one.
    pub container: Option<String>,
}

/// Parse `/proc/<pid>/stat` into (comm, state, starttime ticks). `comm` may
/// contain spaces and parens, so fields are split after the LAST `)`.
pub(crate) fn parse_stat(text: &str) -> Option<(String, char, u64)> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let comm = text.get(open + 1..close)?.to_string();
    let rest: Vec<&str> = text.get(close + 1..)?.split_whitespace().collect();
    let state = rest.first()?.chars().next()?;
    // rest[0] is field 3 (state); starttime is field 22.
    let start = rest.get(19)?.parse().ok()?;
    Some((comm, state, start))
}

/// Docker container id from `/proc/<pid>/cgroup` (cgroup v1 `/docker/<id>` or
/// v2 `docker-<id>.scope`).
pub(crate) fn container_from_cgroup(text: &str) -> Option<String> {
    for line in text.lines() {
        let path = line.rsplit(':').next().unwrap_or("");
        for seg in path.split('/') {
            let id = seg
                .strip_prefix("docker-")
                .map(|s| s.trim_end_matches(".scope"))
                .unwrap_or(seg);
            if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(id[..12].to_string());
            }
        }
    }
    None
}

fn names_fuse_wait(s: &str) -> bool {
    FUSE_WAIT_SYMBOLS.iter().any(|sym| s.contains(sym))
}

pub(crate) fn classify(wchan: &str, stack: Option<&str>) -> FuseWait {
    if names_fuse_wait(wchan) || stack.is_some_and(names_fuse_wait) {
        return FuseWait::Yes;
    }
    let opaque = wchan.is_empty() || wchan == "0";
    if opaque && stack.is_none() {
        FuseWait::Unknown
    } else {
        FuseWait::No
    }
}

/// Read one pid directory; `None` when it vanished, is not a pid, or is in
/// neither `D` nor `Z` (only those pay for the extra file reads).
fn read_proc(pid_dir: &Path, uptime_secs: u64) -> Option<ProcInfo> {
    let pid: u32 = pid_dir.file_name()?.to_str()?.parse().ok()?;
    let (comm, state, start) = parse_stat(&fs::read_to_string(pid_dir.join("stat")).ok()?)?;
    if state != 'D' && state != 'Z' {
        return None;
    }
    let wchan = fs::read_to_string(pid_dir.join("wchan"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let stack = fs::read_to_string(pid_dir.join("stack")).ok();
    let container = fs::read_to_string(pid_dir.join("cgroup"))
        .ok()
        .and_then(|t| container_from_cgroup(&t));
    Some(ProcInfo {
        pid,
        comm,
        state,
        age_secs: uptime_secs.saturating_sub(start / CLK_TCK),
        fuse: classify(&wchan, stack.as_deref()),
        wchan,
        container,
    })
}

/// Every `D` or `Z` process under `proc_root`, sorted by pid.
pub(crate) fn scan(proc_root: &str) -> Vec<ProcInfo> {
    let uptime = fs::read_to_string(Path::new(proc_root).join("uptime"))
        .ok()
        .and_then(|t| t.split_whitespace().next()?.parse::<f64>().ok())
        .map_or(0, |f| f as u64);
    let Ok(rd) = fs::read_dir(proc_root) else {
        return Vec::new();
    };
    let mut out: Vec<ProcInfo> = rd
        .flatten()
        .filter_map(|e| read_proc(&e.path(), uptime))
        .collect();
    out.sort_by_key(|p| p.pid);
    out
}

/// Entries of `second` whose pid was in the same state in `first`.
pub(crate) fn persisted(first: &[ProcInfo], second: Vec<ProcInfo>) -> Vec<ProcInfo> {
    second
        .into_iter()
        .filter(|p| first.iter().any(|q| q.pid == p.pid && q.state == p.state))
        .collect()
}

fn describe(p: &ProcInfo) -> String {
    let ctr = p
        .container
        .as_deref()
        .map(|c| format!(", container {c}"))
        .unwrap_or_default();
    let wchan = if p.wchan.is_empty() { "?" } else { &p.wchan };
    format!(
        "pid {} ({}) wchan {wchan}, started {}s ago{ctr}",
        p.pid, p.comm, p.age_secs
    )
}

fn join(v: &[&ProcInfo]) -> String {
    v.iter().map(|p| describe(p)).collect::<Vec<_>>().join("; ")
}

/// Sample `proc_root` twice, `interval` apart, and report what persisted.
pub(crate) fn check(proc_root: &str, interval: Duration) -> Vec<Finding> {
    let first = scan(proc_root);
    if first.is_empty() {
        return findings(&[]);
    }
    std::thread::sleep(interval);
    findings(&persisted(&first, scan(proc_root)))
}

pub(crate) fn findings(procs: &[ProcInfo]) -> Vec<Finding> {
    let d = |w: FuseWait| -> Vec<&ProcInfo> {
        procs
            .iter()
            .filter(|p| p.state == 'D' && p.fuse == w)
            .collect()
    };
    let (fuse, unknown) = (d(FuseWait::Yes), d(FuseWait::Unknown));
    let mut out = Vec::new();

    out.push(if fuse.is_empty() && unknown.is_empty() {
        finding(
            "fuse-dstate",
            Severity::Ok,
            "No processes blocked on FUSE/shfs",
            "no process stayed in uninterruptible sleep on a FUSE wait path across two samples"
                .to_string(),
            None,
        )
    } else if fuse.is_empty() {
        finding(
            "fuse-dstate",
            Severity::Info,
            "Processes in D state with an unknown wait channel",
            format!(
                "{} process(es) stayed in D state, but wchan is opaque and /proc/<pid>/stack is \
                 unreadable (root-only), so whether they wait on FUSE/shfs is unknown: {}.",
                unknown.len(),
                join(&unknown)
            ),
            None,
        )
    } else {
        let mut detail = format!(
            "{} process(es) stayed in D state on a FUSE wait path across two samples: {}. \
             This is the signature of a wedged shfs request or inode lock. SIGKILL cannot clear \
             D state; if they persist, the remedy is restarting shfs (array stop/start or \
             reboot), and they will block a clean unmount, so confirm console access first. \
             Start age is a hint only, not time spent in D.",
            fuse.len(),
            join(&fuse)
        );
        if !unknown.is_empty() {
            detail.push_str(&format!(
                " {} more D-state process(es) have an unclassifiable wait channel: {}.",
                unknown.len(),
                join(&unknown)
            ));
        }
        finding(
            "fuse-dstate",
            Severity::Warn,
            "Processes blocked in uninterruptible sleep on FUSE/shfs",
            detail,
            None,
        )
    });

    let zombies: Vec<&ProcInfo> = procs
        .iter()
        .filter(|p| p.state == 'Z' && p.container.is_some())
        .collect();
    if !zombies.is_empty() {
        out.push(finding(
            "container-zombies",
            Severity::Info,
            "Zombie processes inside containers",
            format!(
                "{} defunct process(es) persisted in container cgroups: {}. If one is the \
                 container's main workload, Docker can still report the container as Up; probe \
                 the workload, not the container.",
                zombies.len(),
                join(&zombies)
            ),
            None,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeRoot;

    const CID: &str = "4f1c0e9a2b3d4f1c0e9a2b3d4f1c0e9a2b3d4f1c0e9a2b3d4f1c0e9a2b3d4f1c";

    fn fake() -> FakeRoot {
        let r = FakeRoot::new("dstate");
        r.write("uptime", "100000.00 0.00\n").mkdir("acpi");
        r
    }

    #[test]
    fn parse_stat_handles_parens_and_spaces_in_comm() {
        let r = fake();
        r.proc(7, "smbd -D (x)", 'D', 4200, &[]);
        let text = fs::read_to_string(r.path().join("7/stat")).unwrap();
        let (comm, state, start) = parse_stat(&text).unwrap();
        assert_eq!((comm.as_str(), state, start), ("smbd -D (x)", 'D', 4200));
        assert!(parse_stat("garbage").is_none());
    }

    #[test]
    fn container_id_from_v1_and_v2_cgroups() {
        assert_eq!(
            container_from_cgroup(&format!("12:memory:/docker/{CID}\n")).as_deref(),
            Some(&CID[..12])
        );
        assert_eq!(
            container_from_cgroup(&format!("0::/system.slice/docker-{CID}.scope\n")).as_deref(),
            Some(&CID[..12])
        );
        assert!(container_from_cgroup("0::/init.scope\n").is_none());
    }

    #[test]
    fn classifies_wait_channels() {
        assert_eq!(classify("fuse_lock_inode", None), FuseWait::Yes);
        assert_eq!(classify("request_wait_answer", None), FuseWait::Yes);
        assert_eq!(
            classify("0", Some("[<0>] request_wait_answer+0x1\n")),
            FuseWait::Yes
        );
        assert_eq!(classify("io_schedule", None), FuseWait::No);
        assert_eq!(classify("0", Some("[<0>] io_schedule\n")), FuseWait::No);
        assert_eq!(classify("0", None), FuseWait::Unknown);
        assert_eq!(classify("", None), FuseWait::Unknown);
    }

    #[test]
    fn persisting_fuse_dstate_warns_and_skips_running_and_non_fuse() {
        let r = fake();
        r.proc(
            101,
            "smbd",
            'D',
            1000 * CLK_TCK,
            &[("wchan", "fuse_lock_inode")],
        );
        r.proc(102, "du", 'D', 0, &[("wchan", "io_schedule")]);
        r.proc(103, "bash", 'S', 0, &[("wchan", "fuse_lock_inode")]);
        let f = check(r.str(), Duration::ZERO);
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0].severity,
            Severity::Warn,
            "capped at Warn regardless of age"
        );
        assert!(
            f[0].detail
                .contains("pid 101 (smbd) wchan fuse_lock_inode, started 99000s")
        );
        assert!(!f[0].detail.contains("pid 102"));
        assert!(!f[0].detail.contains("pid 103"));
    }

    #[test]
    fn transient_dstate_is_not_reported() {
        let r = fake();
        r.proc(201, "find", 'D', 0, &[("wchan", "fuse_readdir_uncached")]);
        let first = scan(r.str());
        r.proc(201, "find", 'S', 0, &[]);
        let f = findings(&persisted(&first, scan(r.str())));
        assert_eq!(f[0].severity, Severity::Ok);
    }

    #[test]
    fn unclassifiable_dstate_says_so() {
        let r = fake();
        r.proc(301, "find", 'D', 0, &[("wchan", "0")]);
        let f = check(r.str(), Duration::ZERO);
        assert_eq!(f[0].severity, Severity::Info);
        assert!(f[0].detail.contains("unreadable"));
    }

    #[test]
    fn container_zombie_is_info_host_zombie_is_ignored() {
        let r = fake();
        r.proc(
            401,
            "syncthing",
            'Z',
            0,
            &[("cgroup", &format!("0::/docker/{CID}\n"))],
        );
        r.proc(402, "sh", 'Z', 0, &[("cgroup", "0::/user.slice\n")]);
        let f = check(r.str(), Duration::ZERO);
        assert_eq!(f[0].severity, Severity::Ok);
        let z = f.iter().find(|f| f.id == "container-zombies").unwrap();
        assert_eq!(z.severity, Severity::Info);
        assert!(z.detail.contains(&CID[..12]));
        assert!(!z.detail.contains("pid 402"));
    }

    #[test]
    fn missing_proc_root_is_clean() {
        let f = check("/nonexistent/proc", Duration::ZERO);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Ok);
    }
}
