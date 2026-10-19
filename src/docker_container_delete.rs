use plugin_toolkit::prelude::*;

use crate::Client;
use crate::authz::require_admin;
use crate::endpoint;
use crate::tools::surface_endpoint;
use crate::unit_provider::{ContainerDeleteOutput, container_delete_with, endpoint_protected};

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidDockerContainerDeleteArgs {
    /// Container name or id.
    #[arg(long)]
    pub name: String,
    /// Stop a running container first, and act on a protected one.
    #[arg(long, default_value_t = false)]
    #[serde(default)]
    pub force: bool,
    /// Validate and report what would be removed; change nothing.
    #[arg(long, default_value_t = false)]
    #[serde(default, alias = "dry_run")]
    pub dry_run: bool,
    /// Registered unraid endpoint; optional when exactly one is registered.
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// Delete an Unraid-managed container. Refuses a running or protected
/// container unless `force`, which stops it first. `dryRun: true` runs the
/// same checks and only reports; admin is required for both.
#[orca_tool(
    domain = "unraid",
    verb = "docker.container.delete",
    role = "admin",
    data_mutation = true,
    execute_gated = false
)]
async fn unraid_docker_container_delete(
    args: UnraidDockerContainerDeleteArgs,
    ctx: &ToolCtx,
) -> Result<ContainerDeleteOutput> {
    require_admin("unraid.docker.container.delete", ctx.caller().as_ref())?;
    let row = surface_endpoint(args.endpoint)?;
    let protected = endpoint_protected(&row.name)?;
    let client = Client::new(endpoint::resolve_config(&row).await?);
    container_delete_with(
        &client,
        &row.name,
        &protected,
        &args.name,
        args.force,
        args.dry_run,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_requires_admin() {
        for role in [Some("user"), None] {
            let args = UnraidDockerContainerDeleteArgs {
                name: "plex".into(),
                force: false,
                dry_run: true,
                endpoint: None,
            };
            let ctx = crate::authz::test_ctx(role);
            let e = plugin_toolkit::reactor::block_on(unraid_docker_container_delete(args, &ctx))
                .unwrap_err();
            assert!(
                e.to_string().contains("unraid.docker.container.delete: "),
                "{e}"
            );
        }
    }

    #[test]
    fn dry_run_parses_camel_and_snake_case() {
        use plugin_toolkit::serde_json::{from_value, json};
        let a: UnraidDockerContainerDeleteArgs =
            from_value(json!({"name": "plex", "dryRun": true})).unwrap();
        let b: UnraidDockerContainerDeleteArgs =
            from_value(json!({"name": "plex", "dry_run": true, "force": true})).unwrap();
        assert!(a.dry_run && !a.force);
        assert!(b.dry_run && b.force);
    }
}
