//! Per-device array and pool health from the Unraid `array` query: device
//! status, read/write error counters, and filesystem free space.
//!
//! Complements [`crate::zfs_health`], which sees only pool state: the API
//! carries the per-device error counts and free space that kstat does not.

use plugin_toolkit::contract::diagnostics::{Finding, Severity};

use crate::checks::finding;
use crate::generated::v7_3_1::array_status::{ArrayDiskStatus, ArrayStatusArray};

/// Below this share of free space a device is one large write from full.
const LOW_FREE_PCT: u64 = 10;

struct Device<'a> {
    name: String,
    status: Option<&'a ArrayDiskStatus>,
    num_errors: Option<&'a str>,
    fs_size: Option<&'a str>,
    fs_free: Option<&'a str>,
}

fn status_severity(s: &ArrayDiskStatus) -> Option<Severity> {
    match s {
        ArrayDiskStatus::DISK_OK | ArrayDiskStatus::DISK_NP => None,
        ArrayDiskStatus::DISK_NEW | ArrayDiskStatus::DISK_DSBL_NEW => Some(Severity::Info),
        _ => Some(Severity::Crit),
    }
}

fn devices(a: &ArrayStatusArray) -> Vec<Device<'_>> {
    let label = |name: &Option<String>, idx: i64| name.clone().unwrap_or_else(|| format!("#{idx}"));
    let disks = a.disks.iter().map(|d| Device {
        name: label(&d.name, d.idx),
        status: d.status.as_ref(),
        num_errors: d.num_errors.as_deref(),
        fs_size: d.fs_size.as_deref(),
        fs_free: d.fs_free.as_deref(),
    });
    let parities = a.parities.iter().map(|d| Device {
        name: label(&d.name, d.idx),
        status: d.status.as_ref(),
        num_errors: d.num_errors.as_deref(),
        fs_size: None,
        fs_free: None,
    });
    let caches = a.caches.iter().map(|d| Device {
        name: label(&d.name, d.idx),
        status: d.status.as_ref(),
        num_errors: None,
        fs_size: d.fs_size.as_deref(),
        fs_free: d.fs_free.as_deref(),
    });
    disks.chain(parities).chain(caches).collect()
}

fn num(s: Option<&str>) -> Option<u64> {
    s.and_then(|v| v.trim().parse().ok())
}

pub(crate) fn findings(endpoint: &str, a: &ArrayStatusArray) -> Vec<Finding> {
    let mut out = Vec::new();
    for d in devices(a) {
        let id = |kind: &str| format!("disk-{kind}::{endpoint}::{}", d.name);
        if let Some(sev) = d.status.and_then(status_severity) {
            out.push(finding(
                &id("status"),
                sev,
                "Array device is not healthy",
                format!(
                    "'{}' on '{endpoint}' reports status {:?}. Check Main in the Unraid GUI and \
                     the device's SMART report before writing to it.",
                    d.name,
                    d.status.unwrap()
                ),
                None,
            ));
        }
        if let Some(n) = num(d.num_errors).filter(|n| *n > 0) {
            out.push(finding(
                &id("errors"),
                Severity::Warn,
                "Array device has I/O errors",
                format!(
                    "'{}' on '{endpoint}' has {n} read/write errors since the array started. \
                     Check its SMART report and cabling.",
                    d.name
                ),
                None,
            ));
        }
        if let (Some(size), Some(free)) = (num(d.fs_size), num(d.fs_free))
            && size > 0
            && free * 100 < size * LOW_FREE_PCT
        {
            out.push(finding(
                &id("free"),
                Severity::Warn,
                "Array device is nearly full",
                format!(
                    "'{}' on '{endpoint}' has {}% free ({free} of {size} KiB).",
                    d.name,
                    free * 100 / size
                ),
                None,
            ));
        }
    }
    if out.is_empty() {
        out.push(finding(
            &format!("disk-health::{endpoint}"),
            Severity::Ok,
            "Array devices are healthy",
            format!(
                "every array and pool device on '{endpoint}' is OK, error-free and below 90% full."
            ),
            None,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json::{self, Value, json};

    fn array(disks: Value, caches: Value) -> ArrayStatusArray {
        serde_json::from_value(json!({
            "id": "a", "state": "STARTED",
            "capacity": {
                "kilobytes": {"free": "0", "used": "0", "total": "0"},
                "disks": {"free": "0", "used": "0", "total": "0"}
            },
            "parityCheckStatus": {"status": "NEVER_RUN"},
            "disks": disks, "parities": [], "caches": caches
        }))
        .unwrap()
    }

    fn disk(name: &str, status: &str, errors: &str, size: &str, free: &str) -> Value {
        json!({"id": name, "idx": 1, "name": name, "status": status, "type": "DATA",
               "numErrors": errors, "fsSize": size, "fsFree": free})
    }

    #[test]
    fn healthy_array_is_one_ok() {
        let f = findings(
            "willow",
            &array(
                json!([disk("disk1", "DISK_OK", "0", "1000", "500")]),
                json!([]),
            ),
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Ok);
    }

    #[test]
    fn disabled_disk_is_crit_and_new_disk_is_info() {
        let f = findings(
            "willow",
            &array(
                json!([
                    disk("disk1", "DISK_DSBL", "0", "1000", "500"),
                    disk("disk2", "DISK_NEW", "0", "1000", "500")
                ]),
                json!([]),
            ),
        );
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, Severity::Crit);
        assert!(f[0].id.ends_with("disk1"));
        assert_eq!(f[1].severity, Severity::Info);
    }

    #[test]
    fn errors_and_low_free_space_warn() {
        let f = findings(
            "maple",
            &array(
                json!([disk("disk1", "DISK_OK", "3", "1000", "500")]),
                json!([{"id": "c", "idx": 0, "name": "pbs", "status": "DISK_OK", "type": "CACHE",
                        "fsSize": "1000", "fsFree": "50"}]),
            ),
        );
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|f| f.severity == Severity::Warn));
        assert!(f[0].detail.contains("3 read/write errors"));
        assert!(f[1].detail.contains("'pbs'") && f[1].detail.contains("5% free"));
    }

    #[test]
    fn missing_fs_fields_are_not_judged() {
        let f = findings(
            "willow",
            &array(json!([disk("disk1", "DISK_OK", "", "", "")]), json!([])),
        );
        assert_eq!(f[0].severity, Severity::Ok);
    }
}
