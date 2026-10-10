//! `unraid.vm.power` — start/stop/reboot/pause/resume a libvirt VM through the
//! Unraid GraphQL `vm { ... }` mutations.
//!
//! Dry-run unless `execute: true`, with admin required for both (see
//! [`crate::authz`]). The mutation documents live here, not in `queries/`,
//! because every `queries/` operation auto-surfaces as an ungated tool.

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{Value, json};

use crate::authz::require_admin;
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

/// The mutation's boolean from `data`. GraphQL errors are already `Err` from
/// the client; a missing/non-boolean field or `false` is an error here too.
pub(crate) fn mutation_result(data: &Value, field: &str, action: &str) -> Result<()> {
    match data["vm"][field].as_bool() {
        Some(true) => Ok(()),
        Some(false) => bail!("Unraid reported the VM {action} did not succeed"),
        None => bail!("unexpected response to vm.{field}: {data}"),
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
    /// Apply the change. Without it the call only reports what it would do.
    #[arg(long, default_value_t = false)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VmPowerOutput {
    pub id: String,
    pub action: String,
    /// False for a dry run: the VM was resolved but nothing was sent.
    pub executed: bool,
}

/// Change a VM's power state. Dry-run unless `execute: true`; admin is
/// required for both.
#[orca_tool(
    domain = "unraid",
    verb = "vm.power",
    role = "admin",
    data_mutation = true,
    execute_gated = false
)]
async fn unraid_vm_power(args: UnraidVmPowerArgs, ctx: &ToolCtx) -> Result<VmPowerOutput> {
    require_admin("unraid.vm.power", ctx.caller().as_ref())?;
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
    if !args.execute {
        return Ok(VmPowerOutput {
            id,
            action: args.action,
            executed: false,
        });
    }
    let data = client
        .mutate_raw(&document(field), json!({ "id": id }))
        .await?;
    mutation_result(&data, field, &args.action)?;
    Ok(VmPowerOutput {
        id,
        action: args.action,
        executed: true,
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

    #[test]
    fn only_a_true_result_is_success() {
        assert!(mutation_result(&json!({"vm": {"start": true}}), "start", "start").is_ok());
        let f = mutation_result(&json!({"vm": {"start": false}}), "start", "start");
        assert!(f.unwrap_err().to_string().contains("did not succeed"));
        for bad in [
            json!(null),
            json!({"vm": null}),
            json!({"vm": {"start": "yes"}}),
        ] {
            let e = mutation_result(&bad, "start", "start")
                .unwrap_err()
                .to_string();
            assert!(e.contains("unexpected response"), "{bad}");
        }
    }

    #[test]
    fn dry_run_requires_admin() {
        for role in [Some("user"), None] {
            let args = UnraidVmPowerArgs {
                vm: "pbs".into(),
                action: "start".into(),
                endpoint: None,
                execute: false,
            };
            let ctx = crate::authz::test_ctx(role);
            let e = plugin_toolkit::reactor::block_on(unraid_vm_power(args, &ctx)).unwrap_err();
            assert!(e.to_string().contains("unraid.vm.power: "), "{e}");
        }
    }
}
