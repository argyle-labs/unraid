//! `unraid.vm.availability` — whether this host can run VMs right now, and if
//! not, which layer is missing and how to fix it.
//!
//! CPU virtualization flags and the VM Manager on/off state come from the
//! Unraid API. The daemon layer beneath an enabled VM Manager has no API, so it
//! is probed locally (`/etc/libvirt` mount, libvirtd pid file, virtiofsd); the
//! local probes also stand in for the API when it is unreachable, but only when
//! no endpoint is registered or the auto-picked endpoint is loopback: probing
//! this box for a remote host would answer for the wrong machine. An endpoint
//! that cannot be resolved is an error, not an unreachable API.
//!
//! VM verbs refuse with [`VmUnavailable`] when the stack is down, so a caller
//! gets a reason and steps instead of "failed to connect to the hypervisor".

use std::fmt;
use std::fs;
use std::path::Path;

use plugin_toolkit::prelude::*;

use crate::libvirt_stack::{LibvirtStack, probe};
use crate::vm_manager::{VmManager, classify};

const VIRTIOFSD: &str = "/usr/libexec/virtiofsd";

const ENABLE_WARNING: &str = "Do NOT enable by editing /boot/config/domain.cfg and running \
     rc.libvirt start: /etc/libvirt stays empty until VM Manager creates and mounts libvirt.img, \
     so libvirt dies on missing virtlogd.conf/virtlockd.conf.";

#[derive(
    plugin_toolkit::serde::Serialize,
    plugin_toolkit::serde::Deserialize,
    plugin_toolkit::schemars::JsonSchema,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[serde(crate = "plugin_toolkit::serde", rename_all = "snake_case")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub enum VmUnavailableReason {
    VmUnsupportedHost,
    VmManagerDisabled,
    LibvirtNotRunning,
}

impl VmUnavailableReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VmUnsupportedHost => "vm_unsupported_host",
            Self::VmManagerDisabled => "vm_manager_disabled",
            Self::LibvirtNotRunning => "libvirt_not_running",
        }
    }
}

/// Operator steps for an unavailable VM stack; the only remediation shape
/// this module emits.
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

impl VmRemediation {
    fn manual(steps: &[&str], warning: Option<&str>) -> Self {
        Self {
            automatic: false,
            steps: steps.iter().map(|s| s.to_string()).collect(),
            warning: warning.map(str::to_string),
        }
    }
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VmAvailability {
    pub available: bool,
    #[serde(default)]
    pub reason: Option<VmUnavailableReason>,
    pub detail: String,
    #[serde(default)]
    pub remediation: Option<VmRemediation>,
    /// `/usr/libexec/virtiofsd` exists, so share passthrough is possible.
    pub virtiofsd: bool,
}

/// A VM verb refused because VMs cannot be managed on this host.
#[derive(Debug, Clone, PartialEq)]
pub struct VmUnavailable(pub VmAvailability);

impl fmt::Display for VmUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = &self.0;
        let reason = a.reason.map_or("unknown", VmUnavailableReason::as_str);
        write!(f, "VMs are unavailable ({reason}): {}", a.detail)?;
        if let Some(r) = &a.remediation {
            write!(f, " Steps: {}.", r.steps.join("; "))?;
            if let Some(w) = &r.warning {
                write!(f, " {w}")?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for VmUnavailable {}

/// What the Unraid API reported; `None` where it could not answer.
#[derive(Debug, Clone, Default)]
pub(crate) struct ApiView {
    pub cpu_flags: Option<Vec<String>>,
    /// `Enabled`/`Disabled` only; an unanswerable query is `None`.
    pub vm_manager: Option<VmManager>,
}

fn has_virt_flag<'a>(mut flags: impl Iterator<Item = &'a str>) -> bool {
    flags.any(|f| f == "vmx" || f == "svm")
}

/// Fallback when the API is unreachable: flags from `/proc/cpuinfo`.
fn local_virt_support(proc_root: &str) -> Option<bool> {
    let cpuinfo = fs::read_to_string(Path::new(proc_root).join("cpuinfo")).ok()?;
    let mut lines = cpuinfo
        .lines()
        .filter(|l| l.starts_with("flags"))
        .peekable();
    lines.peek()?;
    Some(lines.any(|l| has_virt_flag(l.split_whitespace())))
}

fn unavailable(
    reason: VmUnavailableReason,
    detail: String,
    remediation: VmRemediation,
) -> VmAvailability {
    VmAvailability {
        available: false,
        reason: Some(reason),
        detail,
        remediation: Some(remediation),
        virtiofsd: false,
    }
}

fn available(detail: String) -> VmAvailability {
    VmAvailability {
        available: true,
        reason: None,
        detail,
        remediation: None,
        virtiofsd: false,
    }
}

/// Availability for a libvirt daemon fault under an enabled VM Manager.
pub(crate) fn daemon_fault(stack: &LibvirtStack) -> Option<VmAvailability> {
    match stack {
        LibvirtStack::DaemonStopped => Some(unavailable(
            VmUnavailableReason::LibvirtNotRunning,
            "libvirt.img is mounted at /etc/libvirt but libvirtd has no pid file.".to_string(),
            VmRemediation::manual(
                &[
                    "Unraid GUI -> Settings -> VM Manager",
                    "Set Enable VMs = No, Apply, then Yes, Apply",
                ],
                None,
            ),
        )),
        LibvirtStack::StalePid { pid } => Some(unavailable(
            VmUnavailableReason::LibvirtNotRunning,
            format!("libvirtd.pid names pid {pid}, which is not a running libvirtd."),
            VmRemediation::manual(
                &[
                    "Check /var/log/libvirt/libvirtd.log for the crash",
                    "Unraid GUI -> Settings -> VM Manager: set Enable VMs = No, Apply, then Yes, Apply",
                ],
                None,
            ),
        )),
        LibvirtStack::Running { .. } | LibvirtStack::ImageNotMounted => None,
    }
}

fn manager_disabled() -> VmAvailability {
    unavailable(
        VmUnavailableReason::VmManagerDisabled,
        "Unraid VM Manager is disabled, or its libvirt.img is missing.".to_string(),
        VmRemediation::manual(
            &[
                "Unraid GUI -> Settings -> VM Manager",
                "Enable VMs = Yes",
                "Apply (creates libvirt.img, populates /etc/libvirt, starts libvirtd)",
            ],
            Some(ENABLE_WARNING),
        ),
    )
}

pub(crate) fn assess(
    api: &ApiView,
    proc_root: &str,
    run_dir: &str,
    virtiofsd: &str,
) -> VmAvailability {
    let virt = match &api.cpu_flags {
        Some(flags) => Some(has_virt_flag(flags.iter().map(String::as_str))),
        None => local_virt_support(proc_root),
    };
    let stack = probe(proc_root, run_dir);
    let mut a = if virt == Some(false) {
        unavailable(
            VmUnavailableReason::VmUnsupportedHost,
            "This host's CPU exposes no virtualization extensions (vmx/svm). A host that is \
             itself a VM needs nested virtualization from its hypervisor."
                .to_string(),
            VmRemediation::manual(
                &[
                    "Enable VT-x/AMD-V in firmware, or nested virtualization on the parent hypervisor",
                    "Reboot the host, then enable VM Manager",
                ],
                None,
            ),
        )
    } else {
        match (api.vm_manager, &stack) {
            (_, LibvirtStack::Running { pid }) => {
                available(format!("libvirtd (pid {pid}) is running."))
            }
            (Some(VmManager::Enabled), _) => {
                available("VM Manager is enabled and answering.".to_string())
            }
            (_, LibvirtStack::ImageNotMounted) => manager_disabled(),
            (_, s) => daemon_fault(s).unwrap_or_else(manager_disabled),
        }
    };
    a.virtiofsd = Path::new(virtiofsd).exists();
    a
}

async fn api_view(endpoint: Option<String>) -> Result<ApiView> {
    if endpoint.is_none() && crate::endpoint::endpoint_db::list()?.is_empty() {
        return Ok(ApiView::default());
    }
    let explicit = endpoint.is_some();
    let client = crate::tools::surface_client(endpoint, None, None, None).await?;
    let local = !explicit && crate::endpoint::is_loopback_url(client.endpoint());
    api_view_from(&client, local).await
}

/// Query `client`; on failure, `local` degrades to local probes instead of erroring.
async fn api_view_from(client: &crate::Client, local: bool) -> Result<ApiView> {
    let cpu_flags = match client.cpu_flags().await {
        Ok(flags) => flags,
        Err(_) if local => None,
        Err(e) => return Err(e.into()),
    };
    let vms = client.vms().await;
    let vm_manager = match (classify(&vms), vms) {
        (VmManager::Unavailable, Err(e)) if !local => return Err(e.into()),
        (VmManager::Unavailable, _) => None,
        (s, _) => Some(s),
    };
    Ok(ApiView {
        cpu_flags,
        vm_manager,
    })
}

async fn availability(endpoint: Option<String>) -> Result<VmAvailability> {
    Ok(assess(
        &api_view(endpoint).await?,
        "/proc",
        "/var/run/libvirt",
        VIRTIOFSD,
    ))
}

fn gate(a: VmAvailability) -> std::result::Result<(), VmUnavailable> {
    if a.available {
        Ok(())
    } else {
        Err(VmUnavailable(a))
    }
}

/// Refuse with [`VmUnavailable`] when VMs cannot be managed here.
pub(crate) async fn require(endpoint: Option<String>) -> Result<()> {
    require_with(&api_view(endpoint).await?, "/proc", "/var/run/libvirt")
}

pub(crate) fn require_with(api: &ApiView, proc_root: &str, run_dir: &str) -> Result<()> {
    Ok(gate(assess(api, proc_root, run_dir, VIRTIOFSD))?)
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidVmAvailabilityArgs {
    /// Registered unraid endpoint; optional when exactly one is registered.
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// Report whether this host can run VMs, with remediation when it cannot.
#[orca_tool(domain = "unraid", verb = "vm.availability")]
async fn unraid_vm_availability(
    args: UnraidVmAvailabilityArgs,
    _ctx: &ToolCtx,
) -> Result<VmAvailability> {
    availability(args.endpoint).await
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_support::FakeRoot;

    const MOUNTED: &str = "/dev/loop3 /etc/libvirt btrfs rw 0 0\n";
    const VMX: &str = "processor\t: 0\nflags\t\t: fpu vme vmx sse\n";

    fn run_with(api: &ApiView, r: &FakeRoot) -> VmAvailability {
        let root = r.str();
        assess(
            api,
            root,
            &format!("{root}/run"),
            &format!("{root}/virtiofsd"),
        )
    }

    fn run(r: &FakeRoot) -> VmAvailability {
        run_with(&ApiView::default(), r)
    }

    fn api(flags: &[&str], vm_manager: Option<VmManager>) -> ApiView {
        ApiView {
            cpu_flags: Some(flags.iter().map(|s| s.to_string()).collect()),
            vm_manager,
        }
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
    fn reason_serializes_snake_case() {
        let v =
            plugin_toolkit::serde_json::to_value(VmUnavailableReason::VmManagerDisabled).unwrap();
        assert_eq!(v, "vm_manager_disabled");
    }

    #[test]
    fn api_flags_take_precedence_over_cpuinfo() {
        let r = fake(VMX, MOUNTED);
        let a = run_with(&api(&["fpu", "sse"], Some(VmManager::Enabled)), &r);
        assert_eq!(a.reason, Some(VmUnavailableReason::VmUnsupportedHost));
        let r = fake("flags\t: fpu sse\n", "");
        let a = run_with(&api(&["svm"], Some(VmManager::Enabled)), &r);
        assert!(a.available);
    }

    #[test]
    fn cpuinfo_is_the_fallback_when_the_api_is_unreachable() {
        let a = run(&fake("flags\t: fpu sse\n", ""));
        assert_eq!(a.reason, Some(VmUnavailableReason::VmUnsupportedHost));
        assert!(!a.available && !a.virtiofsd);
    }

    #[test]
    fn no_virt_flags_is_unsupported_even_with_the_image_mounted() {
        let r = fake("flags\t: fpu sse\n", MOUNTED);
        r.write("run/libvirtd.pid", "77\n")
            .proc(77, "libvirtd", 'S', 0, &[]);
        assert_eq!(run(&r).reason, Some(VmUnavailableReason::VmUnsupportedHost));
    }

    #[test]
    fn api_disabled_is_vm_manager_disabled_with_gui_steps_and_the_hand_enable_warning() {
        let a = run_with(&api(&["svm"], Some(VmManager::Disabled)), &fake(VMX, ""));
        assert_eq!(a.reason, Some(VmUnavailableReason::VmManagerDisabled));
        let rem = a.remediation.unwrap();
        assert!(!rem.automatic);
        assert!(rem.steps.iter().any(|s| s.contains("Enable VMs = Yes")));
        assert!(rem.warning.unwrap().contains("domain.cfg"));
    }

    #[test]
    fn api_disabled_with_image_mounted_is_a_daemon_fault() {
        let a = run_with(
            &api(&["vmx"], Some(VmManager::Disabled)),
            &fake(VMX, MOUNTED),
        );
        assert_eq!(a.reason, Some(VmUnavailableReason::LibvirtNotRunning));
    }

    #[test]
    fn api_enabled_is_available_without_local_daemon_evidence() {
        let a = run_with(&api(&["vmx"], Some(VmManager::Enabled)), &fake(VMX, ""));
        assert!(a.available);
    }

    #[test]
    fn mounted_without_pid_file_is_not_running() {
        let a = run(&fake(VMX, MOUNTED));
        assert_eq!(a.reason, Some(VmUnavailableReason::LibvirtNotRunning));
    }

    #[test]
    fn stale_pid_of_a_dead_process_is_not_running() {
        let r = fake(VMX, MOUNTED);
        r.write("run/libvirtd.pid", "9\n");
        let a = run(&r);
        assert_eq!(a.reason, Some(VmUnavailableReason::LibvirtNotRunning));
        assert!(a.detail.contains("pid 9"));
    }

    #[test]
    fn stale_pid_reused_by_another_process_is_not_running() {
        let r = fake(VMX, MOUNTED);
        r.write("run/libvirtd.pid", "9\n")
            .proc(9, "bash", 'S', 0, &[]);
        assert_eq!(run(&r).reason, Some(VmUnavailableReason::LibvirtNotRunning));
    }

    #[test]
    fn unreadable_cpuinfo_does_not_claim_unsupported() {
        let r = FakeRoot::new("vmavail");
        r.write("mounts", "").mkdir("run");
        assert_eq!(run(&r).reason, Some(VmUnavailableReason::VmManagerDisabled));
    }

    #[test]
    fn gate_refuses_with_the_typed_availability() {
        let a = run(&fake(VMX, ""));
        let e = gate(a.clone()).unwrap_err();
        assert_eq!(e.0, a);
        let msg = e.to_string();
        assert!(msg.contains("vm_manager_disabled") && msg.contains("Enable VMs = Yes"));
        let mut ok = a;
        ok.available = true;
        assert!(gate(ok).is_ok());
    }

    #[test]
    fn require_with_refuses_when_unavailable() {
        let r = fake(VMX, "");
        let e =
            require_with(&ApiView::default(), r.str(), &format!("{}/run", r.str())).unwrap_err();
        let u = e.downcast_ref::<VmUnavailable>().expect("VmUnavailable");
        assert_eq!(u.0.reason, Some(VmUnavailableReason::VmManagerDisabled));
    }

    #[test]
    fn require_with_passes_when_the_api_reports_enabled() {
        let r = fake(VMX, "");
        let api = api(&["vmx"], Some(VmManager::Enabled));
        assert!(require_with(&api, r.str(), &format!("{}/run", r.str())).is_ok());
    }

    #[test]
    fn require_returns_the_endpoint_resolution_error() {
        let e = crate::endpoint::tests::isolated(|| {
            plugin_toolkit::reactor::block_on(require(Some("no-such-endpoint".into())))
        })
        .unwrap_err();
        assert!(
            e.to_string()
                .contains("no unraid endpoint named `no-such-endpoint`"),
            "{e}"
        );
    }

    /// Registers `tower-a` against a mock that fails every query, then runs
    /// `require` on it; returns the error and how many requests the mock saw.
    fn require_on_failing_endpoint() -> (plugin_toolkit::anyhow::Error, usize) {
        use crate::endpoint::tests::{isolated, register, rt};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let rt = rt();
        let server = rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(wiremock::matchers::method("POST"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&server)
                .await;
            server
        });
        let e = isolated(|| {
            rt.block_on(async {
                register("tower-a", &server.uri()).await;
                require(Some("tower-a".into())).await.unwrap_err()
            })
        });
        let seen = rt
            .block_on(server.received_requests())
            .map_or(0, |r| r.len());
        (e, seen)
    }

    #[test]
    fn require_resolves_the_named_endpoint() {
        let (_, seen) = require_on_failing_endpoint();
        assert!(seen > 0, "the registered endpoint was never queried");
    }

    #[test]
    fn named_endpoint_query_failure_is_returned_not_probed_locally() {
        let (e, _) = require_on_failing_endpoint();
        assert!(e.downcast_ref::<VmUnavailable>().is_none(), "{e}");
    }

    #[test]
    fn remote_endpoint_query_failure_is_returned_not_probed_locally() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let rt = crate::endpoint::tests::rt();
        let e = rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(wiremock::matchers::method("POST"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&server)
                .await;
            let client = crate::Client::new(crate::Config::new(server.uri(), "k"));
            api_view_from(&client, false).await.unwrap_err()
        });
        assert!(e.downcast_ref::<VmUnavailable>().is_none(), "{e}");
    }

    #[test]
    fn only_a_loopback_endpoint_counts_as_this_host() {
        use crate::endpoint::is_loopback_url;
        assert!(is_loopback_url("http://127.0.0.1/graphql"));
        assert!(is_loopback_url("http://localhost:8080/graphql"));
        assert!(!is_loopback_url("https://10.0.0.5/graphql"));
        assert!(!is_loopback_url("https://tower.local/graphql"));
    }

    #[test]
    fn no_endpoint_registered_probes_locally() {
        let a = crate::endpoint::tests::isolated(|| {
            plugin_toolkit::reactor::block_on(availability(None))
        });
        assert!(a.is_ok(), "{a:?}");
    }
}
