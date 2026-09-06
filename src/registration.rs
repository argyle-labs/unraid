//! Typed capability providers for the hybrid export.
//!
//! Besides its `unraid.` tool surface and the [`crate::topology::UnraidTopology`]
//! collector, unraid contributes two more typed domain facets plus one
//! escape-hatch backend, all composed on the toolkit's `Plugin` builder (which
//! emits the merged `backends()` payload and the single wire dispatch):
//!
//! - a `diagnostics` provider ([`UnraidDiagnostics`]) — the power-loss
//!   shutdown/logging checks, delegating to [`crate::checks`];
//! - a `ups` provider ([`UnraidUps`]) — the host's apcupsd managed through the
//!   GraphQL API, delegating to [`crate::ups`];
//! - a `backup_kind` backend (`unraid-config`) — the host's flash config
//!   capture/restore ([`crate::backup`]). There is no single-instance typed
//!   builder facet for backup, so it rides the builder's `.backend(def,
//!   dispatcher)` escape hatch via [`backup_backend_def`] + [`backup_dispatcher`].
//!
//! No hand-rolled op-string dispatch or merged-backends JSON here anymore.

use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::anyhow::Result;
use plugin_toolkit::backend_def::backup_kind_backend_def;
use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::contract::diagnostics::{
    DiagnoseArgs, DiagnosticsProvider, Finding, RepairArgs, RepairOutcome,
};
use plugin_toolkit::contract::ups::{
    UpsConfig, UpsConfigOutcome, UpsProvider, UpsQueryArgs, UpsState,
};
use plugin_toolkit::serde_json::Value;

/// Bridge invoke-prefix for the `unraid-config` backup KIND.
const BACKUP_PREFIX: &str = "unraid.__backup";
/// The backup KIND this plugin contributes: an Unraid host's persistent
/// configuration (`/boot/config` and its disk-based equivalents).
const BACKUP_KIND: &str = "unraid-config";

/// The `diagnostics` provider unraid advertises (`diagnose` + `repair`).
pub struct UnraidDiagnostics;

impl DiagnosticsProvider for UnraidDiagnostics {
    fn name(&self) -> &str {
        crate::PROVIDER
    }

    fn diagnose(&self, args: DiagnoseArgs) -> BoxFuture<'_, Result<Vec<Finding>>> {
        Box::pin(async move { Ok(crate::checks::diagnose_typed(args).await) })
    }

    fn repair(&self, args: RepairArgs) -> BoxFuture<'_, Result<RepairOutcome>> {
        Box::pin(async move { Ok(crate::checks::repair_typed(args)) })
    }
}

/// The `ups` provider unraid advertises (`state` + `config_get` + `config_set`).
pub struct UnraidUps;

impl UpsProvider for UnraidUps {
    fn name(&self) -> &str {
        crate::PROVIDER
    }

    fn state(&self, args: UpsQueryArgs) -> BoxFuture<'_, Result<Vec<UpsState>>> {
        Box::pin(async move {
            crate::ups::state_typed(args)
                .await
                .map_err(|e| plugin_toolkit::anyhow::anyhow!(e))
        })
    }

    fn config_get(&self, args: UpsQueryArgs) -> BoxFuture<'_, Result<Vec<UpsConfig>>> {
        Box::pin(async move {
            crate::ups::config_get_typed(args)
                .await
                .map_err(|e| plugin_toolkit::anyhow::anyhow!(e))
        })
    }

    fn config_set(&self, config: UpsConfig) -> BoxFuture<'_, Result<UpsConfigOutcome>> {
        Box::pin(async move {
            crate::ups::config_set_typed(config)
                .await
                .map_err(|e| plugin_toolkit::anyhow::anyhow!(e))
        })
    }
}

/// Backend descriptor for the `unraid-config` backup KIND. Registered on the
/// `Plugin` builder via `.backend(backup_backend_def(), backup_dispatcher)`.
pub fn backup_backend_def() -> BackendDef {
    backup_kind_backend_def(BACKUP_KIND, BACKUP_PREFIX)
}

/// Escape-hatch dispatcher for the `unraid.__backup.*` bridge calls. Strips its
/// own invoke-prefix and answers the bare op via [`crate::backup::dispatch`];
/// returns `None` for anything else so the builder falls through to the next
/// dispatcher (and ultimately the `#[orca_tool]` surface). The backup ops are
/// synchronous file/tar work, so no reactor re-entry occurs here.
pub fn backup_dispatcher(tool: &str, args: Value) -> Option<std::result::Result<Value, Value>> {
    let op = tool
        .strip_prefix(BACKUP_PREFIX)
        .and_then(|s| s.strip_prefix('.'))?;
    let args_json = args.to_string();
    Some(
        crate::backup::dispatch(op, &args_json)
            .map(|s| plugin_toolkit::serde_json::from_str(&s).unwrap_or(Value::String(s)))
            .map_err(Value::String),
    )
}
