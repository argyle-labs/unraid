//! Read-only ZFS pool state from the SPL kstat tree.
//!
//! OpenZFS publishes one directory per imported pool under
//! `/proc/spl/kstat/zfs/<pool>/` with a `state` file (`ONLINE`, `DEGRADED`, ...).
//! Reading it needs no subprocess. Pools that are not imported have no entry,
//! so they are invisible here. Scrub age and error counts are not in kstat.

use std::fs;

use plugin_toolkit::contract::diagnostics::{Finding, Severity};

use crate::checks::finding;

/// (pool, state) for every imported pool under `kstat_root`, sorted by name.
pub(crate) fn pool_states(kstat_root: &str) -> Vec<(String, String)> {
    let Ok(rd) = fs::read_dir(kstat_root) else {
        return Vec::new();
    };
    let mut out: Vec<(String, String)> = rd
        .flatten()
        .filter_map(|e| {
            let state = fs::read_to_string(e.path().join("state")).ok()?;
            Some((
                e.file_name().to_string_lossy().into_owned(),
                state.trim().to_string(),
            ))
        })
        .collect();
    out.sort();
    out
}

pub(crate) fn severity_for(state: &str) -> Severity {
    match state {
        "ONLINE" => Severity::Ok,
        "DEGRADED" => Severity::Warn,
        _ => Severity::Crit,
    }
}

pub(crate) fn check(kstat_root: &str) -> Vec<Finding> {
    pool_states(kstat_root)
        .into_iter()
        .map(|(pool, state)| {
            let sev = severity_for(&state);
            let detail = match sev {
                Severity::Ok => format!("pool '{pool}' is ONLINE."),
                Severity::Warn => format!(
                    "pool '{pool}' is DEGRADED: it is serving data with reduced redundancy. \
                     Run `zpool status -v {pool}` to find the faulted device."
                ),
                _ => format!(
                    "pool '{pool}' is {state}. If the host rebooted in the last few minutes this \
                     can be a pool still importing; otherwise data on it is unavailable. Run \
                     `zpool status -v {pool}`."
                ),
            };
            finding(
                &format!("zfs-pool-state::{pool}"),
                sev,
                &format!("ZFS pool {pool}: {state}"),
                detail,
                None,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_support::FakeRoot;

    fn fake(pools: &[(&str, &str)]) -> FakeRoot {
        let r = FakeRoot::new("zfs");
        // Global kstat files sit beside pool dirs and must be skipped.
        r.write("arcstats", "13 1 0x01 ...\n");
        for (p, s) in pools {
            r.write(&format!("{p}/state"), &format!("{s}\n"));
        }
        r
    }

    #[test]
    fn maps_states_to_severity() {
        assert_eq!(severity_for("ONLINE"), Severity::Ok);
        assert_eq!(severity_for("DEGRADED"), Severity::Warn);
        for s in ["FAULTED", "UNAVAIL", "SUSPENDED", "REMOVED", "OFFLINE", ""] {
            assert_eq!(severity_for(s), Severity::Crit, "{s}");
        }
    }

    #[test]
    fn one_finding_per_pool_ignoring_global_kstats() {
        let root = fake(&[
            ("cache", "ONLINE"),
            ("backup", "DEGRADED"),
            ("zfs1", "SUSPENDED"),
        ]);
        let f = check(root.str());
        let ids: Vec<&str> = f.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "zfs-pool-state::backup",
                "zfs-pool-state::cache",
                "zfs-pool-state::zfs1"
            ]
        );
        assert_eq!(f[0].severity, Severity::Warn);
        assert_eq!(f[1].severity, Severity::Ok);
        assert_eq!(f[2].severity, Severity::Crit);
        assert!(f.iter().all(|f| f.repair.is_none()));
    }

    #[test]
    fn no_zfs_module_yields_nothing() {
        assert!(check("/nonexistent/kstat/zfs").is_empty());
    }
}
