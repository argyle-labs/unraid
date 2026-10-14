//! Per-device array and pool health from the Unraid `array` query: device
//! status, unrecoverable error counters, and filesystem usage against each
//! device's own warning/critical thresholds.
//!
//! Complements [`crate::zfs_health`], which sees only pool state: the API
//! carries the per-device error counts and usage that kstat does not.

use plugin_toolkit::contract::diagnostics::{Finding, Severity};

use crate::checks::finding;
use crate::generated::v7_3_1::array_status::{ArrayDiskStatus, ArrayStatusArray};

/// Used-space warning percentage for a device with no threshold of its own.
const DEFAULT_WARN_USED_PCT: u64 = 90;

struct Device<'a> {
    name: String,
    status: Option<&'a ArrayDiskStatus>,
    num_errors: Option<&'a str>,
    fs_size: Option<&'a str>,
    fs_free: Option<&'a str>,
    warning: Option<i64>,
    critical: Option<i64>,
}

fn status_severity(s: &ArrayDiskStatus) -> Option<Severity> {
    match s {
        ArrayDiskStatus::DISK_OK | ArrayDiskStatus::DISK_NP => None,
        ArrayDiskStatus::DISK_NEW => Some(Severity::Info),
        ArrayDiskStatus::DISK_DSBL_NEW => Some(Severity::Warn),
        ArrayDiskStatus::DISK_DSBL
        | ArrayDiskStatus::DISK_NP_DSBL
        | ArrayDiskStatus::DISK_NP_MISSING
        | ArrayDiskStatus::DISK_INVALID
        | ArrayDiskStatus::DISK_WRONG => Some(Severity::Crit),
        ArrayDiskStatus::Other(_) => Some(Severity::Warn),
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
        warning: d.warning,
        critical: d.critical,
    });
    let parities = a.parities.iter().map(|d| Device {
        name: label(&d.name, d.idx),
        status: d.status.as_ref(),
        num_errors: d.num_errors.as_deref(),
        fs_size: None,
        fs_free: None,
        warning: None,
        critical: None,
    });
    let caches = a.caches.iter().map(|d| Device {
        name: label(&d.name, d.idx),
        status: d.status.as_ref(),
        num_errors: d.num_errors.as_deref(),
        fs_size: d.fs_size.as_deref(),
        fs_free: d.fs_free.as_deref(),
        warning: d.warning,
        critical: d.critical,
    });
    disks.chain(parities).chain(caches).collect()
}

fn num(s: Option<&str>) -> Option<u64> {
    s.and_then(|v| v.trim().parse().ok())
}

/// A threshold of null or 0 means "not set" in Unraid.
fn threshold(t: Option<i64>) -> Option<u64> {
    t.and_then(|v| u64::try_from(v).ok()).filter(|v| *v > 0)
}

/// Severity and the crossed threshold for a device's used percentage.
fn usage_severity(used_pct: u64, d: &Device) -> Option<(Severity, u64)> {
    if let Some(crit) = threshold(d.critical)
        && used_pct >= crit
    {
        return Some((Severity::Crit, crit));
    }
    let warn = threshold(d.warning).unwrap_or(DEFAULT_WARN_USED_PCT);
    (used_pct >= warn).then_some((Severity::Warn, warn))
}

/// `disk-health::<endpoint>` when the `array` query itself failed.
pub(crate) fn query_failed(endpoint: &str, err: &str) -> Finding {
    finding(
        &format!("disk-health::{endpoint}"),
        Severity::Warn,
        "Array device health could not be read",
        format!("The array query against '{endpoint}' failed, so disk health is unknown: {err}"),
        None,
    )
}

pub(crate) fn findings(endpoint: &str, a: &ArrayStatusArray) -> Vec<Finding> {
    let mut out = Vec::new();
    for d in devices(a) {
        let id = |kind: &str| format!("disk-{kind}::{endpoint}::{}", d.name);
        if let Some(status) = d.status
            && let Some(sev) = status_severity(status)
        {
            out.push(finding(
                &id("status"),
                sev,
                "Array device is not healthy",
                format!(
                    "'{}' on '{endpoint}' reports status {status:?}. Check Main in the Unraid GUI \
                     and the device's SMART report before writing to it.",
                    d.name
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
                    "'{}' on '{endpoint}' has {n} unrecoverable read/write errors reported by the \
                     driver since the counter was last cleared. Check its SMART report and \
                     cabling.",
                    d.name
                ),
                None,
            ));
        }
        if let (Some(size), Some(free)) = (num(d.fs_size), num(d.fs_free))
            && size > 0
        {
            let used_pct = size.saturating_sub(free) * 100 / size;
            if let Some((sev, limit)) = usage_severity(used_pct, &d) {
                out.push(finding(
                    &id("free"),
                    sev,
                    "Array device is nearly full",
                    format!(
                        "'{}' on '{endpoint}' is {used_pct}% used (threshold {limit}%; {free} of \
                         {size} KiB free).",
                        d.name
                    ),
                    None,
                ));
            }
        }
    }
    if out.is_empty() {
        out.push(finding(
            &format!("disk-health::{endpoint}"),
            Severity::Ok,
            "Array devices are healthy",
            format!(
                "every array and pool device on '{endpoint}' is OK, error-free and below its \
                 usage warning threshold ({DEFAULT_WARN_USED_PCT}% where none is set)."
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

    fn array(disks: Value, parities: Value, caches: Value) -> ArrayStatusArray {
        serde_json::from_value(json!({
            "id": "a", "state": "STARTED",
            "capacity": {
                "kilobytes": {"free": "0", "used": "0", "total": "0"},
                "disks": {"free": "0", "used": "0", "total": "0"}
            },
            "parityCheckStatus": {"status": "NEVER_RUN"},
            "disks": disks, "parities": parities, "caches": caches
        }))
        .unwrap()
    }

    fn disks(d: Value) -> ArrayStatusArray {
        array(d, json!([]), json!([]))
    }

    fn disk(name: &str, status: &str, errors: &str, size: &str, free: &str) -> Value {
        json!({"id": name, "idx": 1, "name": name, "status": status, "type": "DATA",
               "numErrors": errors, "fsSize": size, "fsFree": free})
    }

    fn with_thresholds(mut d: Value, warning: Option<i64>, critical: Option<i64>) -> Value {
        d["warning"] = json!(warning);
        d["critical"] = json!(critical);
        d
    }

    #[test]
    fn healthy_array_is_one_ok() {
        let f = findings(
            "willow",
            &disks(json!([disk("disk1", "DISK_OK", "0", "1000", "500")])),
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Ok);
        assert!(f[0].detail.contains("90%"));
    }

    #[test]
    fn status_mapping() {
        let f = findings(
            "willow",
            &disks(json!([
                disk("disk1", "DISK_DSBL", "0", "", ""),
                disk("disk2", "DISK_NEW", "0", "", ""),
                disk("disk3", "DISK_DSBL_NEW", "0", "", ""),
                disk("disk4", "DISK_NP_DSBL", "0", "", ""),
                disk("disk5", "DISK_NP_MISSING", "0", "", ""),
                disk("disk6", "DISK_NP", "0", "", ""),
                disk("disk7", "DISK_SOMETHING_NEW", "0", "", "")
            ])),
        );
        let sev: Vec<_> = f.iter().map(|f| (f.id.as_str(), f.severity)).collect();
        assert_eq!(
            sev,
            vec![
                ("disk-status::willow::disk1", Severity::Crit),
                ("disk-status::willow::disk2", Severity::Info),
                ("disk-status::willow::disk3", Severity::Warn),
                ("disk-status::willow::disk4", Severity::Crit),
                ("disk-status::willow::disk5", Severity::Crit),
                ("disk-status::willow::disk7", Severity::Warn),
            ]
        );
    }

    #[test]
    fn parity_devices_are_checked_and_unnamed_devices_use_their_index() {
        let f = array(
            json!([]),
            json!([{"id": "p", "idx": 0, "status": "DISK_DSBL", "type": "PARITY",
                    "numErrors": "2"}]),
            json!([]),
        );
        let f = findings("willow", &f);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].id, "disk-status::willow::#0");
        assert_eq!(f[0].severity, Severity::Crit);
        assert_eq!(f[1].id, "disk-errors::willow::#0");
    }

    #[test]
    fn errors_and_default_threshold_warn() {
        let f = findings(
            "maple",
            &array(
                json!([disk("disk1", "DISK_OK", "3", "1000", "500")]),
                json!([]),
                json!([{"id": "c", "idx": 0, "name": "pbs", "status": "DISK_OK", "type": "CACHE",
                        "numErrors": "1", "fsSize": "1000", "fsFree": "50"}]),
            ),
        );
        assert_eq!(f.len(), 3);
        assert!(f.iter().all(|f| f.severity == Severity::Warn));
        assert!(f[0].detail.contains("3 unrecoverable"));
        assert_eq!(f[1].id, "disk-errors::maple::pbs");
        assert!(f[2].detail.contains("'pbs'") && f[2].detail.contains("95% used"));
    }

    #[test]
    fn per_disk_thresholds_set_severity_and_crit_outranks_warn() {
        let used = |pct: u64| {
            let free = (100 - pct).to_string();
            with_thresholds(
                disk("disk1", "DISK_OK", "0", "100", &free),
                Some(70),
                Some(85),
            )
        };
        let sev = |pct| {
            let f = findings("w", &disks(json!([used(pct)])));
            assert_eq!(f.len(), 1);
            f[0].severity
        };
        assert_eq!(sev(60), Severity::Ok);
        assert_eq!(sev(75), Severity::Warn);
        assert_eq!(sev(90), Severity::Crit);
    }

    #[test]
    fn zero_or_null_thresholds_fall_back_to_the_default() {
        for (w, c) in [(Some(0), Some(0)), (None, None)] {
            let d = with_thresholds(disk("disk1", "DISK_OK", "0", "100", "20"), w, c);
            let f = findings("w", &disks(json!([d])));
            assert_eq!(f.len(), 1);
            assert_eq!(f[0].severity, Severity::Ok);
            let d = with_thresholds(disk("disk1", "DISK_OK", "0", "100", "5"), w, c);
            let f = findings("w", &disks(json!([d])));
            assert_eq!(f.len(), 1);
            assert_eq!(f[0].severity, Severity::Warn);
        }
    }

    #[test]
    fn missing_fs_fields_are_not_judged() {
        let f = findings(
            "willow",
            &disks(json!([disk("disk1", "DISK_OK", "", "", "")])),
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Ok);
    }

    #[test]
    fn failed_query_is_a_warn_with_the_error() {
        let f = query_failed("willow", "connection refused");
        assert_eq!(f.id, "disk-health::willow");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.detail.contains("connection refused"));
    }
}
