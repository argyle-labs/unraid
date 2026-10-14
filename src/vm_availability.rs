//! `unraid.vm.availability` — whether this host can run VMs right now, and if
//! not, which layer is missing and how to fix it.
//!
//! VM verbs return the same shape as an error when the stack is down, so a
//! caller gets a reason and steps instead of "failed to connect to the
//! hypervisor". `/boot/config/domain.cfg` is root-only, so "VM Manager off" and
//! "libvirt.img missing" both read as the image not being mounted.

use std::fs;
use std::path::Path;

use plugin_toolkit::prelude::*;

use crate::libvirt_stack::{LibvirtStack, probe};

const VIRTIOFSD: &str = "/usr/libexec/virtiofsd";

const ENABLE_WARNING: &str = "Do NOT enable by editing /boot/config/domain.cfg and running \
     rc.libvirt start: /etc/libvirt stays empty until VM Manager creates and mounts libvirt.img, \
     so libvirt dies on missing virtlogd.conf/virtlockd.conf.";

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VmRemediation {
    /// True once orca can apply the fix itself; every fix here is manual.
    pub automatic: bool,
    pub steps: Vec<String>,
    #[serde(default)]
    pub warning: Option<String>,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VmAvailability {
    pub available: bool,
    /// `vm_unsupported_host` | `vm_manager_disabled` | `libvirt_not_running`;
    /// absent when available.
    #[serde(default)]
    pub reason: Option<String>,
    pub detail: String,
    #[serde(default)]
    pub remediation: Option<VmRemediation>,
    /// `/usr/libexec/virtiofsd` exists, so share passthrough is possible.
    pub virtiofsd: bool,
}

/// CPU virtualization extensions visible to this kernel.
fn has_virt_extensions(cpuinfo: &str) -> bool {
    cpuinfo
        .lines()
        .filter(|l| l.starts_with("flags"))
        .any(|l| l.split_whitespace().any(|f| f == "vmx" || f == "svm"))
}

fn unavailable(
    reason: &str,
    detail: String,
    steps: &[&str],
    warning: Option<&str>,
) -> VmAvailability {
    VmAvailability {
        available: false,
        reason: Some(reason.to_string()),
        detail,
        remediation: Some(VmRemediation {
            automatic: false,
            steps: steps.iter().map(|s| s.to_string()).collect(),
            warning: warning.map(str::to_string),
        }),
        virtiofsd: false,
    }
}

pub(crate) fn assess(proc_root: &str, run_dir: &str, virtiofsd: &str) -> VmAvailability {
    let cpuinfo = fs::read_to_string(Path::new(proc_root).join("cpuinfo")).unwrap_or_default();
    let mut a = if !cpuinfo.is_empty() && !has_virt_extensions(&cpuinfo) {
        unavailable(
            "vm_unsupported_host",
            "This host's CPU exposes no virtualization extensions (vmx/svm). A host that is \
             itself a VM needs nested virtualization from its hypervisor."
                .to_string(),
            &[
                "Enable VT-x/AMD-V in firmware, or nested virtualization on the parent hypervisor",
                "Reboot the host, then enable VM Manager",
            ],
            None,
        )
    } else {
        match probe(proc_root, run_dir) {
            LibvirtStack::Running { pid } => VmAvailability {
                available: true,
                reason: None,
                detail: format!("libvirtd (pid {pid}) is running."),
                remediation: None,
                virtiofsd: false,
            },
            LibvirtStack::ImageNotMounted => unavailable(
                "vm_manager_disabled",
                "libvirt.img is not mounted at /etc/libvirt: Unraid VM Manager is disabled or \
                 its libvirt image is missing."
                    .to_string(),
                &[
                    "Unraid GUI -> Settings -> VM Manager",
                    "Enable VMs = Yes",
                    "Apply (creates libvirt.img, populates /etc/libvirt, starts libvirtd)",
                ],
                Some(ENABLE_WARNING),
            ),
            LibvirtStack::DaemonStopped => unavailable(
                "libvirt_not_running",
                "libvirt.img is mounted but libvirtd has no pid file.".to_string(),
                &[
                    "Unraid GUI -> Settings -> VM Manager",
                    "Set Enable VMs = No, Apply, then Yes, Apply",
                ],
                None,
            ),
            LibvirtStack::StalePid { pid } => unavailable(
                "libvirt_not_running",
                format!("libvirtd.pid names pid {pid}, which is not a running libvirtd."),
                &[
                    "Check /var/log/libvirt/libvirtd.log for the crash",
                    "Unraid GUI -> Settings -> VM Manager: set Enable VMs = No, Apply, then Yes, Apply",
                ],
                None,
            ),
        }
    };
    a.virtiofsd = Path::new(virtiofsd).exists();
    a
}

/// Err carrying the structured availability when VMs cannot be managed here.
pub(crate) fn require() -> Result<()> {
    let a = assess("/proc", "/var/run/libvirt", VIRTIOFSD);
    if a.available {
        return Ok(());
    }
    bail!("{}", plugin_toolkit::serde_json::to_string(&a)?)
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidVmAvailabilityArgs {}

/// Report whether this host can run VMs, with remediation when it cannot.
#[orca_tool(domain = "unraid", verb = "vm.availability")]
async fn unraid_vm_availability(
    _args: UnraidVmAvailabilityArgs,
    _ctx: &ToolCtx,
) -> Result<VmAvailability> {
    Ok(assess("/proc", "/var/run/libvirt", VIRTIOFSD))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeRoot;

    const MOUNTED: &str = "/dev/loop3 /etc/libvirt btrfs rw 0 0\n";
    const VMX: &str = "processor\t: 0\nflags\t\t: fpu vme vmx sse\n";

    fn run(r: &FakeRoot) -> VmAvailability {
        let root = r.str();
        assess(root, &format!("{root}/run"), &format!("{root}/virtiofsd"))
    }

    fn fake(cpuinfo: &str, mounts: &str) -> FakeRoot {
        let r = FakeRoot::new("vmavail");
        r.write("cpuinfo", cpuinfo)
            .write("mounts", mounts)
            .mkdir("run");
        r
    }

    #[test]
    fn running_libvirt_is_available_with_no_remediation() {
        let r = fake(VMX, MOUNTED);
        r.write("run/libvirtd.pid", "77\n")
            .proc(77, "libvirtd", 'S', 0, &[]);
        r.write("virtiofsd", "");
        let a = run(&r);
        assert!(a.available && a.reason.is_none() && a.remediation.is_none());
        assert!(a.virtiofsd);
    }

    #[test]
    fn no_virt_flags_is_unsupported_before_anything_else() {
        let a = run(&fake("flags\t: fpu sse\n", ""));
        assert_eq!(a.reason.as_deref(), Some("vm_unsupported_host"));
        assert!(!a.available && !a.virtiofsd);
    }

    #[test]
    fn unmounted_image_is_disabled_with_gui_steps_and_the_hand_enable_warning() {
        let a = run(&fake("flags\t: svm\n", ""));
        assert_eq!(a.reason.as_deref(), Some("vm_manager_disabled"));
        let rem = a.remediation.unwrap();
        assert!(!rem.automatic);
        assert!(rem.steps.iter().any(|s| s.contains("Enable VMs = Yes")));
        assert!(rem.warning.unwrap().contains("domain.cfg"));
    }

    #[test]
    fn mounted_without_daemon_is_not_running() {
        let a = run(&fake(VMX, MOUNTED));
        assert_eq!(a.reason.as_deref(), Some("libvirt_not_running"));
        let r = fake(VMX, MOUNTED);
        r.write("run/libvirtd.pid", "9\n")
            .proc(9, "bash", 'S', 0, &[]);
        assert_eq!(run(&r).reason.as_deref(), Some("libvirt_not_running"));
    }

    #[test]
    fn unreadable_cpuinfo_does_not_claim_unsupported() {
        let r = FakeRoot::new("vmavail");
        r.write("mounts", "").mkdir("run");
        assert_eq!(run(&r).reason.as_deref(), Some("vm_manager_disabled"));
    }
}
