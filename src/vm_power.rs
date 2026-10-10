//! `unraid.vm.power` — start/stop/reboot/pause/resume a libvirt VM through the
//! Unraid GraphQL `vm { ... }` mutations.
//!
//! Execute-gated: without `execute: true` the central gate returns a plan and
//! the body never runs. The mutation documents live here, not in `queries/`,
//! because every `queries/` operation auto-surfaces as an ungated tool.

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::json;

use crate::tools::surface_client;

/// Actions and the `VmMutations` field each one calls.
const ACTIONS: &[(&str, &str)] = &[
    ("start", "start"),
    ("stop", "stop"),
    ("force_stop", "forceStop"),
    ("reboot", "reboot"),
    ("pause", "pause"),
    ("resume", "resume"),
];

pub(crate) fn mutation_field(action: &str) -> Result<&'static str> {
    ACTIONS
        .iter()
        .find(|(a, _)| *a == action)
        .map(|(_, f)| *f)
        .ok_or_else(|| {
            let valid: Vec<&str> = ACTIONS.iter().map(|(a, _)| *a).collect();
            anyhow!(
                "unknown action '{action}'; expected one of {}",
                valid.join(", ")
            )
        })
}

pub(crate) fn document(field: &str) -> String {
    format!("mutation VmPower($id: PrefixedID!) {{ vm {{ {field}(id: $id) }} }}")
}

/// Resolve `vm` (domain id, uuid-bearing id, or exact name) to the domain id.
pub(crate) fn resolve_id(domains: &[(String, Option<String>)], vm: &str) -> Result<String> {
    if let Some((id, _)) = domains.iter().find(|(id, _)| id == vm) {
        return Ok(id.clone());
    }
    let named: Vec<&String> = domains
        .iter()
        .filter(|(_, n)| n.as_deref() == Some(vm))
        .map(|(id, _)| id)
        .collect();
    match named.as_slice() {
        [id] => Ok((*id).clone()),
        [] => bail!("no VM with id or name '{vm}'"),
        _ => bail!("VM name '{vm}' is ambiguous; pass its id"),
    }
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidVmPowerArgs {
    /// VM domain id or exact name.
    #[arg(long)]
    pub vm: String,
    /// start | stop | force_stop | reboot | pause | resume.
    #[arg(long)]
    pub action: String,
    /// Registered unraid endpoint; optional when exactly one is registered.
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VmPowerOutput {
    pub id: String,
    pub action: String,
    /// The mutation's boolean result.
    pub ok: bool,
}

/// Change a VM's power state. Dry-run unless `execute: true`.
#[orca_tool(
    domain = "unraid",
    verb = "vm.power",
    role = "admin",
    data_mutation = true,
    execute_gated = true
)]
async fn unraid_vm_power(args: UnraidVmPowerArgs, _ctx: &ToolCtx) -> Result<VmPowerOutput> {
    let field = mutation_field(&args.action)?;
    let client = surface_client(args.endpoint, None, None, None).await?;
    let domains: Vec<(String, Option<String>)> = client
        .vms()
        .await?
        .vms
        .domains
        .unwrap_or_default()
        .into_iter()
        .map(|d| (d.id, d.name))
        .collect();
    let id = resolve_id(&domains, &args.vm)?;
    let data = client
        .mutate_raw(&document(field), json!({ "id": id }))
        .await?;
    Ok(VmPowerOutput {
        ok: data["vm"][field].as_bool().unwrap_or(false),
        id,
        action: args.action,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema_field_exists(type_name: &str, field: &str) -> bool {
        let (_, schema) = crate::generated::SCHEMAS[0];
        let v: plugin_toolkit::serde_json::Value =
            plugin_toolkit::serde_json::from_str(schema).unwrap();
        let types = v
            .pointer("/data/__schema/types")
            .or_else(|| v.pointer("/__schema/types"));
        types
            .and_then(|t| t.as_array())
            .and_then(|t| t.iter().find(|t| t["name"] == type_name))
            .and_then(|t| t["fields"].as_array())
            .is_some_and(|f| f.iter().any(|f| f["name"] == field))
    }

    #[test]
    fn every_action_maps_to_a_real_vm_mutation() {
        for (action, field) in ACTIONS {
            assert_eq!(mutation_field(action).unwrap(), *field);
            assert!(
                schema_field_exists("VmMutations", field),
                "{field} not in schema"
            );
        }
        assert!(mutation_field("destroy").is_err());
    }

    #[test]
    fn document_selects_the_field_with_the_id_variable() {
        assert_eq!(
            document("forceStop"),
            "mutation VmPower($id: PrefixedID!) { vm { forceStop(id: $id) } }"
        );
    }

    #[test]
    fn resolves_by_id_or_unique_name() {
        let d = vec![
            ("vm:1".to_string(), Some("pbs".to_string())),
            ("vm:2".to_string(), Some("ha".to_string())),
            ("vm:3".to_string(), Some("ha".to_string())),
        ];
        assert_eq!(resolve_id(&d, "vm:2").unwrap(), "vm:2");
        assert_eq!(resolve_id(&d, "pbs").unwrap(), "vm:1");
        assert!(
            resolve_id(&d, "ha")
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
        );
        assert!(resolve_id(&d, "nope").is_err());
    }
}
