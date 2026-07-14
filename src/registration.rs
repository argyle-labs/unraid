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
use plugin_toolkit::backend_def::topology_backend_def;
use plugin_toolkit::reactor;
use plugin_toolkit::serde_json;

const TOPO_PREFIX: &str = "unraid.__topo";
const DIAG_PREFIX: &str = "unraid.__diag";
const UPS_PREFIX: &str = "unraid.__ups";

/// Backend descriptors this plugin advertises:
/// - a `topology` collector (`unraid.__topo.collect_claims`), derived from the
///   live surface via the toolkit's export helper;
/// - a `diagnostics` provider (`unraid.__diag.{diagnose,repair}`) surfacing the
///   power-loss shutdown/logging checks (see [`crate::checks`]). Built by hand
///   like raccoon's, since the toolkit has no `diagnostics_backend_def` helper.
pub fn backends_json() -> String {
    let defs: Vec<BackendDef> = vec![
        topology_backend_def("unraid", TOPO_PREFIX),
        BackendDef {
            domain: "diagnostics".to_string(),
            name: crate::PROVIDER.to_string(),
            invoke_prefix: DIAG_PREFIX.to_string(),
            ..Default::default()
        },
        BackendDef {
            domain: "ups".to_string(),
            name: crate::PROVIDER.to_string(),
            invoke_prefix: UPS_PREFIX.to_string(),
            ..Default::default()
        },
    ];
    serde_json::to_string(&defs).unwrap_or_else(|_| "[]".to_string())
}

/// Handle the loader's `unraid.__topo.*` / `unraid.__diag.*` backend calls.
/// Returns `None` for anything else so the toolkit falls through to the
/// `unraid.` tool surface. Async work runs on the toolkit's shared runtime
/// behind the synchronous FFI boundary.
pub fn backend_dispatch(name: &str, args_json: &str) -> Option<Result<String, String>> {
    if let Some(op) = name
        .strip_prefix(TOPO_PREFIX)
        .and_then(|s| s.strip_prefix('.'))
    {
        return Some(dispatch_topology(op));
    }
    if let Some(op) = name
        .strip_prefix(DIAG_PREFIX)
        .and_then(|s| s.strip_prefix('.'))
    {
        return Some(match op {
            "diagnose" => crate::checks::diagnose(args_json),
            "repair" => crate::checks::repair(args_json),
            other => Err(format!("unknown diagnostics op: {other}")),
        });
    }
    if let Some(op) = name
        .strip_prefix(UPS_PREFIX)
        .and_then(|s| s.strip_prefix('.'))
    {
        return Some(match op {
            "state" => crate::ups::state(args_json),
            "config_get" => crate::ups::config_get(args_json),
            "config_set" => crate::ups::config_set(args_json),
            other => Err(format!("unknown ups op: {other}")),
        });
    }
    None
}

fn dispatch_topology(op: &str) -> Result<String, String> {
    match op {
        "collect_claims" => {
            let claims =
                reactor::block_on(crate::topology::collect_claims()).map_err(|e| e.to_string())?;
            serde_json::to_string(&claims).map_err(|e| e.to_string())
        }
        other => Err(format!("unknown topology op: {other}")),
    }
}
