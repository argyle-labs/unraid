//! Local, read-only probe of the Unraid VM stack, turning "failed to connect to
//! the hypervisor" into the layer that is missing and what fixes it.
//!
//! Unraid keeps `/etc/libvirt` on a loop-mounted `libvirt.img` that only exists
//! while VM Manager is enabled, and `libvirtd` starts only after that mount.
//! The "VM Manager is off" state is already reported by `vm-manager` in
//! [`crate::checks`], so this check emits nothing for it and reports only the
//! daemon layer beneath an enabled VM Manager.

use std::fs;
use std::path::Path;

use plugin_toolkit::contract::diagnostics::{Finding, Severity};

use crate::checks::finding;
use crate::procfs::read_mounts;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LibvirtStack {
    Running {
        pid: u32,
    },
    /// `/etc/libvirt` is not mounted: VM Manager is off or its image is missing.
    ImageNotMounted,
    /// Image mounted, but no libvirtd pid file.
    DaemonStopped,
    /// Pid file names a pid that is gone or is no longer libvirtd.
    StalePid {
        pid: u32,
    },
}

pub(crate) fn probe(proc_root: &str, run_dir: &str) -> LibvirtStack {
    let mounted = read_mounts(&format!("{proc_root}/mounts"))
        .iter()
        .any(|m| m.target == "/etc/libvirt");
    if !mounted {
        return LibvirtStack::ImageNotMounted;
    }
    let Some(pid) = fs::read_to_string(Path::new(run_dir).join("libvirtd.pid"))
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok())
    else {
        return LibvirtStack::DaemonStopped;
    };
    let comm = fs::read_to_string(Path::new(proc_root).join(pid.to_string()).join("comm"))
        .unwrap_or_default();
    if comm.trim() == "libvirtd" {
        LibvirtStack::Running { pid }
    } else {
        LibvirtStack::StalePid { pid }
    }
}

pub(crate) fn check(proc_root: &str, run_dir: &str) -> Vec<Finding> {
    let (sev, title, detail) = match probe(proc_root, run_dir) {
        LibvirtStack::ImageNotMounted => return Vec::new(),
        LibvirtStack::Running { pid } => (
            Severity::Ok,
            "libvirt is running",
            format!("/etc/libvirt is mounted and libvirtd (pid {pid}) is running."),
        ),
        LibvirtStack::DaemonStopped => (
            Severity::Warn,
            "libvirtd is not running",
            "libvirt.img is mounted at /etc/libvirt but libvirtd has no pid file. Restart it \
             with `/etc/rc.d/rc.libvirt start` or toggle VM Manager off and on."
                .to_string(),
        ),
        LibvirtStack::StalePid { pid } => (
            Severity::Warn,
            "libvirtd exited",
            format!(
                "libvirtd.pid names pid {pid}, which is not a running libvirtd: the daemon \
                 crashed. Check /var/log/libvirt/libvirtd.log, then `/etc/rc.d/rc.libvirt start`."
            ),
        ),
    };
    vec![finding("libvirt-stack", sev, title, detail, None)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeRoot;

    const MOUNTED: &str =
        "/dev/loop2 /var/lib/docker btrfs rw 0 0\n/dev/loop3 /etc/libvirt btrfs rw 0 0\n";

    fn fake(mounts: &str, pid: Option<&str>) -> FakeRoot {
        let r = FakeRoot::new("libvirt");
        r.write("mounts", mounts).mkdir("run");
        if let Some(p) = pid {
            r.write("run/libvirtd.pid", p);
        }
        r
    }

    fn run(r: &FakeRoot) -> LibvirtStack {
        probe(r.str(), &format!("{}/run", r.str()))
    }

    #[test]
    fn mount_match_is_exact_on_the_target() {
        assert_eq!(
            run(&fake("/dev/loop3 /etc/libvirt-old btrfs rw 0 0\n", None)),
            LibvirtStack::ImageNotMounted
        );
    }

    #[test]
    fn classifies_each_layer() {
        assert_eq!(run(&fake("", None)), LibvirtStack::ImageNotMounted);
        assert_eq!(run(&fake(MOUNTED, None)), LibvirtStack::DaemonStopped);
        assert_eq!(
            run(&fake(MOUNTED, Some("4242\n"))),
            LibvirtStack::StalePid { pid: 4242 }
        );
        let r = fake(MOUNTED, Some("4242\n"));
        r.proc(4242, "libvirtd", 'S', 0, &[]);
        assert_eq!(run(&r), LibvirtStack::Running { pid: 4242 });
    }

    #[test]
    fn reused_pid_is_stale() {
        let r = fake(MOUNTED, Some("4242\n"));
        r.proc(4242, "bash", 'S', 0, &[]);
        assert_eq!(run(&r), LibvirtStack::StalePid { pid: 4242 });
    }

    #[test]
    fn disabled_defers_to_vm_manager_and_daemon_faults_warn() {
        let r = fake("", None);
        let rd = format!("{}/run", r.str());
        assert!(check(r.str(), &rd).is_empty());
        r.write("mounts", MOUNTED);
        let w = &check(r.str(), &rd)[0];
        assert_eq!(w.severity, Severity::Warn);
        assert!(w.detail.contains("rc.libvirt start"));
    }
}
