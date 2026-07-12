//! Dynamic (subprocess) entrypoint for the unraid plugin.
//!
//! The toolkit's `serve_tool_plugin!` (hybrid arm) emits `fn main`, serving this
//! plugin over the orca socket. Dynamic replacement for the retired cdylib
//! `export_tool_plugin!` FFI export — the plugin is a `[[bin]]`, owns no
//! runtime, and reaches orca only through the socket.
//!
//! unraid is a HYBRID plugin: the `unraid.` tool surface (the `schema` tool +
//! the auto-generated `#[orca_tool]` GraphQL operation surface) PLUS one domain
//! backend — a `topology` collector surfacing each host's docker workloads. The
//! macro's hybrid `invoke` tries the backend dispatch first (the
//! `unraid.__topo.*` calls the host makes) then falls through to tool dispatch.
//! Both hooks are the same functions the retired cdylib export fed across the
//! FFI boundary — they now cross the socket instead (see [`unraid::registration`]).

plugin_toolkit::serve_tool_plugin! {
    name: "unraid",
    target_compat: ">=7.3",
    backends: unraid::registration::backends_json(),
    backend_dispatch: unraid::registration::backend_dispatch,
}
