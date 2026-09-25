//! Tells "VM Manager is switched off" apart from "the VM query failed".
//!
//! Unraid answers a `vms` query on a host with VM Manager disabled the same way
//! it answers a genuine backend fault — a GraphQL error with
//! `code: INTERNAL_SERVER_ERROR`:
//!
//! ```text
//! Failed to retrieve VM domains: VMs are not available
//! ```
//!
//! Taken at face value that turns a deliberate operator choice into a permanent
//! red check. Measured on the fleet: maple reports exactly this, and maple is
//! **correctly configured** — it is itself a VM on frigg, so nested
//! virtualization is off on purpose. willow is the host where VMs are genuinely
//! managed. Both are reference states, and orca has to model them as states
//! rather than as success/failure.
//!
//! Pure string classification, deliberately: the transport, the endpoint loop and
//! the reactor are all IO, while "is this a disabled subsystem or a broken one"
//! is a decision — and the decision is the part that was wrong.

/// Whether a host's VM Manager is usable, from a `vms` query outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmManager {
    /// Query succeeded — VM Manager is on and answering.
    Enabled,
    /// VM Manager is switched off. A configuration state, NOT an error: no
    /// remediation is owed unless the operator wants VMs here.
    Disabled,
    /// The query failed for some other reason (auth, transport, a real backend
    /// fault). This is the only outcome that should read as a problem.
    Unavailable,
}

/// Substrings Unraid uses when VM Manager is off. Matched case-insensitively.
///
/// Kept narrow on purpose: a broad match like "not available" would swallow real
/// faults ("service not available", "host not available") and hide outages behind
/// a reassuring "disabled" label — the opposite failure of the one this fixes.
const DISABLED_MARKERS: &[&str] = &[
    // The exact message measured on maple, 2026-09-25.
    "vms are not available",
    // Emitted when libvirt itself is not running, which is what a disabled VM
    // Manager means underneath.
    "libvirt is not running",
    "vm manager is not enabled",
];

/// Classify a failed `vms` query from its error text.
///
/// Only ever returns [`VmManager::Disabled`] or [`VmManager::Unavailable`] — a
/// caller that got `Ok` already knows it is [`VmManager::Enabled`].
pub fn classify_error(err: &str) -> VmManager {
    let lower = err.to_ascii_lowercase();
    if DISABLED_MARKERS.iter().any(|m| lower.contains(m)) {
        VmManager::Disabled
    } else {
        VmManager::Unavailable
    }
}

/// Classify a `vms` query result.
pub fn classify<T, E: std::fmt::Display>(result: &Result<T, E>) -> VmManager {
    match result {
        Ok(_) => VmManager::Enabled,
        Err(e) => classify_error(&e.to_string()),
    }
}

/// Operator-facing guidance for turning VM Manager on.
///
/// Includes the nested-virtualization caveat because that is the actual reason it
/// is off on maple: a guest without CPU virtualization extensions passed through
/// cannot run VMs, so "just enable it" is wrong advice there. Saying so up front
/// stops someone chasing a setting that cannot work.
pub fn activation_instructions() -> &'static str {
    "To enable: Unraid webgui → Settings → VM Manager → set 'Enable VMs' to Yes, then Apply \
     (libvirt starts on the next array start). This requires CPU virtualization extensions \
     (VT-x/AMD-V) to be available to this host — a host that is ITSELF a virtual machine needs \
     nested virtualization exposed by its hypervisor first, and without it VM Manager cannot be \
     enabled here regardless of the setting."
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact message maple returns, measured 2026-09-25. If this stops
    /// classifying as Disabled, maple goes back to reporting a permanent fault.
    #[test]
    fn the_real_maple_message_is_disabled_not_unavailable() {
        assert_eq!(
            classify_error("Failed to retrieve VM domains: VMs are not available"),
            VmManager::Disabled
        );
    }

    #[test]
    fn libvirt_not_running_is_disabled() {
        assert_eq!(
            classify_error("Internal error: libvirt is not running"),
            VmManager::Disabled
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(
            classify_error("FAILED TO RETRIEVE VM DOMAINS: VMS ARE NOT AVAILABLE"),
            VmManager::Disabled
        );
    }

    /// The guard that stops this fix from becoming a worse bug: a real fault must
    /// NOT be relabelled as an intentional choice, or outages hide behind a
    /// reassuring "disabled".
    #[test]
    fn real_faults_stay_unavailable() {
        for err in [
            "Unauthorized",
            "No user session found",
            "Invalid CSRF token",
            "error sending request for url (http://localhost/graphql): connection refused",
            "service not available",
            "host not available",
            "timed out",
        ] {
            assert_eq!(
                classify_error(err),
                VmManager::Unavailable,
                "{err:?} must not be treated as a deliberate disable"
            );
        }
    }

    #[test]
    fn an_ok_result_is_enabled() {
        let ok: Result<u8, String> = Ok(1);
        assert_eq!(classify(&ok), VmManager::Enabled);
    }

    #[test]
    fn an_err_result_routes_through_the_error_classifier() {
        let disabled: Result<u8, String> =
            Err("Failed to retrieve VM domains: VMs are not available".into());
        assert_eq!(classify(&disabled), VmManager::Disabled);
        let broken: Result<u8, String> = Err("Unauthorized".into());
        assert_eq!(classify(&broken), VmManager::Unavailable);
    }

    /// The instructions must name the nested-virt constraint, because that is the
    /// reason it is off on maple and "just enable it" is wrong advice there.
    #[test]
    fn activation_instructions_name_the_nested_virtualization_constraint() {
        let t = activation_instructions();
        assert!(
            t.contains("VM Manager"),
            "must name where the setting lives"
        );
        assert!(t.contains("nested virtualization"));
        assert!(
            t.to_lowercase().contains("vt-x") || t.contains("AMD-V"),
            "must name the CPU requirement"
        );
    }
}
