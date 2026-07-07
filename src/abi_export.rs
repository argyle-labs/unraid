//! ABI-stable cdylib export for the unraid plugin.
//!
//! unraid is a **hybrid** plugin: the `unraid.` tool surface (the `schema`
//! tool + the `unraid.{list,detail,create,update,delete}` endpoint registry)
//! PLUS one domain backend — a `topology` collector surfacing each host's
//! docker workloads (see [`crate::registration`]). The toolkit's
//! [`export_tool_plugin!`] hybrid arm generates the metadata fns, the
//! `unraid.`-scoped manifest, and an `invoke` that tries the backend dispatch
//! first (the `unraid.__topo.*` calls the loader makes) then falls through to
//! tool dispatch. The runtime singleton, `minimal_ctx`, prefix filtering, and
//! JSON encode/decode all live once in `plugin_toolkit::export`.
//!
//! `abi_stable` remains the crate's one direct non-orca dep because
//! `#[export_root_module]` (which the macro invokes) expands to bare
//! `::abi_stable` paths.

plugin_toolkit::export_tool_plugin! {
    name: "unraid",
    target_compat: ">=7.3",
    backends: crate::registration::backends_json(),
    backend_dispatch: crate::registration::backend_dispatch,
}
