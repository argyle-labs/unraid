//! Domain-backend registration for the hybrid export.
//!
//! unraid contributes one backend to orca's `contract` registries, routed back
//! through the FFI `invoke` under a distinct prefix:
//!
//! - `topology` (`unraid.__topo.collect_claims`) — one [`TopologyClaim`] per
//!   docker container per enabled endpoint, so the fleet inventory records which
//!   Unraid host runs which workload (see [`crate::topology`]). The GraphQL API
//!   is the supported read path because Unraid's docker socket is
//!   `root:docker`-only.
//!
//! A `unit` provider (array / shares / plugins as managed units) and a
//! `container_runtime`/deploy-target registration remain follow-ups: they need
//! typed lifecycle surfaces and dynamic per-endpoint (re)registration, so they
//! land separately from this static-descriptor topology wiring — the same
//! staging dockge used.
//!
//! [`backend_dispatch`] answers `unraid.__topo.*`; the toolkit's hybrid `invoke`
//! routes everything else (`unraid.schema`, the `unraid.{list,detail,create,
//! update,delete}` endpoint registry) to the tool surface.

use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::export::{runtime, topology_backend_def};
use plugin_toolkit::serde_json;

const TOPO_PREFIX: &str = "unraid.__topo";

/// Backend descriptors this plugin advertises: a topology collector routed back
/// under its own prefix. Derived from the live surface via the toolkit's export
/// helper so the registered provider/capabilities stay in sync automatically.
pub fn backends_json() -> String {
    let defs: Vec<BackendDef> = vec![topology_backend_def("unraid", TOPO_PREFIX)];
    serde_json::to_string(&defs).unwrap_or_else(|_| "[]".to_string())
}

/// Handle the loader's `unraid.__topo.*` backend calls. Returns `None` for
/// anything else so the toolkit falls through to the `unraid.` tool surface.
/// Async work runs on the toolkit's shared runtime behind the synchronous FFI
/// boundary.
pub fn backend_dispatch(name: &str, _args_json: &str) -> Option<Result<String, String>> {
    let op = name
        .strip_prefix(TOPO_PREFIX)
        .and_then(|s| s.strip_prefix('.'))?;
    Some(dispatch_topology(op))
}

fn dispatch_topology(op: &str) -> Result<String, String> {
    match op {
        "collect_claims" => {
            let claims = runtime()
                .block_on(crate::topology::collect_claims())
                .map_err(|e| e.to_string())?;
            serde_json::to_string(&claims).map_err(|e| e.to_string())
        }
        other => Err(format!("unknown topology op: {other}")),
    }
}
