//! Unraid libvirt VMs as a deploy target.
//!
//! Advertises no capabilities: none of the deploy verbs (launch, migrate, ...)
//! exist for this target yet, and a capability must only be listed once the
//! verb behind it does. The `DeployTarget` impl also needs a libvirt variant in
//! orca's `deploy_target::TargetKind`, which has none today.

use plugin_toolkit::deploy_target::{DeployCapability, Runtime};

/// Unraid host as a receiver of VM workloads.
#[derive(Debug, Clone)]
pub struct UnraidVmTarget {
    pub host: String,
}

impl UnraidVmTarget {
    pub fn new(host: impl Into<String>) -> Self {
        Self { host: host.into() }
    }

    pub fn runtime(&self) -> Runtime {
        Runtime::Vm
    }

    pub fn capabilities(&self) -> Vec<DeployCapability> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_a_vm_target_advertising_nothing_until_verbs_exist() {
        let t = UnraidVmTarget::new("willow");
        assert_eq!(t.host, "willow");
        assert_eq!(t.runtime(), Runtime::Vm);
        assert!(t.capabilities().is_empty());
    }
}
