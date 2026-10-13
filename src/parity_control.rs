//! `unraid.parity.control` — start, pause, resume or cancel a parity check
//! through the Unraid GraphQL `parityCheck { ... }` mutations.
//!
//! Pausing is the immediate relief when a check starves share I/O (see the
//! `parity-io-starvation` finding). Dry-run by default, admin required for
//! both (see [`crate::authz`]).
//! `start` is a read-only check; writing parity corrections is the separate
//! `start_correcting` action, so an invalid action/flag combination cannot be
//! expressed and is rejected when the arguments are parsed, dry run included.

use plugin_toolkit::clap;
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{Value, json};

use crate::authz::require_admin;
use crate::tools::surface_client;

#[derive(
    clap::ValueEnum,
    plugin_toolkit::serde::Serialize,
    plugin_toolkit::serde::Deserialize,
    plugin_toolkit::schemars::JsonSchema,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[serde(crate = "plugin_toolkit::serde", rename_all = "snake_case")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub enum ParityAction {
    /// Start a read-only parity check.
    Start,
    /// Start a check that writes corrections to parity.
    StartCorrecting,
    Pause,
    Resume,
    Cancel,
}

impl ParityAction {
    /// The `ParityCheckMutations` field this action calls.
    pub fn field(self) -> &'static str {
        match self {
            Self::Start | Self::StartCorrecting => "start",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Cancel => "cancel",
        }
    }
}

/// GraphQL document and variables for `action`.
pub(crate) fn request(action: ParityAction) -> (String, Value) {
    match action {
        ParityAction::Start | ParityAction::StartCorrecting => (
            "mutation ParityStart($correct: Boolean) { parityCheck { start(correct: $correct) } }"
                .to_string(),
            json!({ "correct": action == ParityAction::StartCorrecting }),
        ),
        _ => (
            format!(
                "mutation ParityControl {{ parityCheck {{ {} }} }}",
                action.field()
            ),
            json!({}),
        ),
    }
}

/// The mutation's JSON result from `data`. It is a free-form JSON scalar, so
/// only the shapes that mean failure are rejected: missing/null, or `false`.
/// GraphQL errors are already `Err` from the client.
pub(crate) fn mutation_result(data: &Value, action: ParityAction) -> Result<Value> {
    match &data["parityCheck"][action.field()] {
        Value::Null => bail!(
            "unexpected response to parityCheck.{}: {data}",
            action.field()
        ),
        Value::Bool(false) => bail!("Unraid reported the parity {:?} did not succeed", action),
        v => Ok(v.clone()),
    }
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidParityControlArgs {
    /// Required; `Option` only because args structs must be `Default`.
    #[arg(long, value_enum)]
    #[serde(default)]
    pub action: Option<ParityAction>,
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
pub struct ParityControlOutput {
    pub action: ParityAction,
    /// Dry run: the variables that would be sent. Executed: the mutation's
    /// JSON result as returned by Unraid.
    pub result: Value,
    pub executed: bool,
}

/// Control a parity check. Dry-run unless `execute: true`; admin is required
/// for both.
#[orca_tool(
    domain = "unraid",
    verb = "parity.control",
    role = "admin",
    data_mutation = true,
    execute_gated = false
)]
async fn unraid_parity_control(
    args: UnraidParityControlArgs,
    ctx: &ToolCtx,
) -> Result<ParityControlOutput> {
    require_admin("unraid.parity.control", ctx.caller().as_ref())?;
    let action = args.action.ok_or_else(|| {
        anyhow!("`action` is required: start, start_correcting, pause, resume or cancel")
    })?;
    let (doc, vars) = request(action);
    if !args.execute {
        return Ok(ParityControlOutput {
            action,
            result: vars,
            executed: false,
        });
    }
    let client = surface_client(args.endpoint, None, None, None).await?;
    let data = client.mutate_raw(&doc, vars).await?;
    Ok(ParityControlOutput {
        result: mutation_result(&data, action)?,
        action,
        executed: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [ParityAction; 5] = [
        ParityAction::Start,
        ParityAction::StartCorrecting,
        ParityAction::Pause,
        ParityAction::Resume,
        ParityAction::Cancel,
    ];

    #[test]
    fn every_action_is_a_real_parity_mutation() {
        let (_, schema) = crate::generated::SCHEMAS[0];
        let v: Value = plugin_toolkit::serde_json::from_str(schema).unwrap();
        let fields: Vec<String> = v["data"]["__schema"]["types"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "ParityCheckMutations")
            .unwrap()["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap().to_string())
            .collect();
        for a in ALL {
            assert!(fields.iter().any(|f| f == a.field()), "{a:?}");
            assert!(request(a).0.contains(a.field()));
        }
    }

    #[test]
    fn only_start_correcting_writes_corrections() {
        assert_eq!(request(ParityAction::Start).1, json!({ "correct": false }));
        assert_eq!(
            request(ParityAction::StartCorrecting).1,
            json!({ "correct": true })
        );
        let (doc, vars) = request(ParityAction::Pause);
        assert_eq!(doc, "mutation ParityControl { parityCheck { pause } }");
        assert_eq!(vars, json!({}));
    }

    #[test]
    fn invalid_arguments_fail_at_parse_time() {
        use plugin_toolkit::serde_json::from_value;
        let ok: UnraidParityControlArgs =
            from_value(json!({"action": "start_correcting"})).unwrap();
        assert_eq!(ok.action, Some(ParityAction::StartCorrecting));
        assert!(from_value::<UnraidParityControlArgs>(json!({"action": "stop"})).is_err());
    }

    #[test]
    fn dry_run_requires_admin_then_plans_without_sending() {
        let args = || UnraidParityControlArgs {
            action: Some(ParityAction::Pause),
            endpoint: None,
            execute: false,
        };
        for role in [Some("user"), None] {
            let ctx = crate::authz::test_ctx(role);
            let e =
                plugin_toolkit::reactor::block_on(unraid_parity_control(args(), &ctx)).unwrap_err();
            assert!(e.to_string().contains("unraid.parity.control: "), "{e}");
        }
        let ctx = crate::authz::test_ctx(Some("admin"));
        let out = plugin_toolkit::reactor::block_on(unraid_parity_control(args(), &ctx)).unwrap();
        assert!(!out.executed);
        let mut missing = args();
        missing.action = None;
        let e =
            plugin_toolkit::reactor::block_on(unraid_parity_control(missing, &ctx)).unwrap_err();
        assert!(
            e.to_string().contains("`action` is required"),
            "caught in the dry run"
        );
    }

    #[test]
    fn false_or_missing_result_is_an_error() {
        let p = ParityAction::Pause;
        assert_eq!(
            mutation_result(&json!({"parityCheck": {"pause": {"ok": 1}}}), p).unwrap(),
            json!({"ok": 1})
        );
        assert!(mutation_result(&json!({"parityCheck": {"pause": true}}), p).is_ok());
        let e = mutation_result(&json!({"parityCheck": {"pause": false}}), p).unwrap_err();
        assert!(e.to_string().contains("did not succeed"));
        for bad in [
            json!(null),
            json!({"parityCheck": null}),
            json!({"parityCheck": {}}),
        ] {
            let e = mutation_result(&bad, p).unwrap_err().to_string();
            assert!(e.contains("unexpected response"), "{bad}");
        }
    }
}
