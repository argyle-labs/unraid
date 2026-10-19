//! Dynamic (subprocess) entrypoint for the unraid plugin.
//!
//! unraid is a **hybrid** plugin: the `unraid.` tool surface (the `schema` tool,
//! the `docker.*` adoption verbs, and the auto-generated `#[orca_tool]` GraphQL
//! operation surface) PLUS typed domain facets — a `topology` collector (docker
//! workloads per host), a `diagnostics` provider (power-loss shutdown/logging
//! checks), a `ups` provider (apcupsd via the GraphQL API), a `permissions`
//! provider (share-permission introspection for `/mnt/user`), and a
//! `backup_kind` backend (`unraid-config`, flash config capture/restore). All
//! are composed on the [`Plugin`] builder, which emits the combined
//! `backends()` payload and the single wire dispatch — the plugin hand-writes
//! no op-string routing. The plugin is a `[[bin]]`, owns no runtime, and
//! reaches orca only through the socket.
//!
//! `unraid --privileged-op` is a separate one-shot mode: orca's privileged seam
//! (orca#762) runs it as root with one `{op, payload}` request on stdin; it
//! re-validates and runs that single op and prints a JSON reply.

plugin_toolkit::instrument::bootstrap!();

use plugin_toolkit::plugin::Plugin;

// Force-link the `unraid.` #[orca_tool] surfaces so their inventory (separate
// modules from the facets referenced below) isn't dead-stripped at link time:
// the hand-written `schema` and `docker.*` tools and the codegenned GraphQL
// operation surface.
// `as _` keeps them anonymous; `#[allow(unused_imports)]` because the reference
// is purely for its link-time side effect.
#[allow(unused_imports)]
use unraid::{
    docker_adopt as _, docker_container_delete as _, host_settings_write as _, nfs_fsid as _,
    parity_control as _, share_cache as _, smb_share_write as _, surface as _, tools as _,
    vm_autostart as _, vm_availability as _, vm_power as _, vm_xml as _,
};

fn main() -> plugin_toolkit::anyhow::Result<()> {
    use unraid::docker_adopt::privileged;
    if std::env::args().nth(1).as_deref() == Some(privileged::PRIVILEGED_FLAG) {
        let mut input = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)?;
        let reply = plugin_toolkit::reactor::block_on(privileged::serve_one(&input));
        println!("{}", plugin_toolkit::serde_json::to_string(&reply)?);
        std::process::exit(if reply.ok { 0 } else { 1 });
    }
    Plugin::named("unraid")
        .version(env!("CARGO_PKG_VERSION"))
        .tools(["unraid."])
        .topology(unraid::topology::UnraidTopology)
        .unit(unraid::unit_provider::UnraidUnitProvider)
        .diagnostics(unraid::registration::UnraidDiagnostics)
        .ups(unraid::registration::UnraidUps)
        .permissions(unraid::permissions::UnraidPermissions)
        .storage(unraid::exports::UnraidExports)
        .backend(
            unraid::registration::backup_backend_def(),
            Box::new(unraid::registration::backup_dispatcher),
        )
        .serve()
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_hand_written_tool_is_linked() {
        let linked: Vec<&str> =
            plugin_toolkit::inventory::iter::<plugin_toolkit::dispatch::ToolRegistration>
                .into_iter()
                .map(|r| r.name)
                .collect();
        for verb in [
            "create",
            "update",
            "delete",
            "schema",
            "docker.adopt",
            "docker.container.delete",
            "docker.set_icon",
            "docker.status",
            "host.settings.set",
            "nfs.fsids",
            "parity.control",
            "share.cache",
            "share.cache.set",
            "smb.share.set",
            "vm.autostart",
            "vm.availability",
            "vm.power",
            "vm.xml",
        ] {
            let name = format!("unraid.{verb}");
            assert!(linked.contains(&name.as_str()), "{name} not linked");
        }
    }
}
