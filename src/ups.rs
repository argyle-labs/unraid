//! unraid as a core `ups` capability provider.
//!
//! Implements the three [`plugin_toolkit::contract::ups`] ops over the Unraid
//! GraphQL API — `upsDevices` (state), `upsConfiguration` (config_get), and the
//! `configureUps` mutation (config_set). This is the *other* provider of the
//! core UPS capability: on an Unraid host the native apcupsd is managed in place
//! through the API, rather than by writing NUT files. Same `ups.*` surface as
//! the nut provider — one capability, different pathways.

use plugin_toolkit::contract::ups::{UpsConfig, UpsConfigOutcome, UpsQueryArgs, UpsState};

use crate::endpoint::endpoint_db;
use crate::generated::v7_3_1::configure_ups::{UPSConfigInput, UPSKillPower};
use crate::{Client, Config, PROVIDER};

/// First enabled endpoint's client config, or `None` (not on the peer / not
/// configured). UPS management is host-local to the Unraid box.
fn first_client() -> Option<Client> {
    let row = endpoint_db::list().ok()?.into_iter().find(|e| e.enabled)?;
    let cfg = Config::new(row.base_url, row.api_key).insecure(row.insecure);
    Some(Client::new(cfg))
}

/// `state` op — live UPS readings via `upsDevices`.
pub async fn state_typed(args: UpsQueryArgs) -> Result<Vec<UpsState>, String> {
    let Some(client) = first_client() else {
        return Ok(Vec::new());
    };
    let states: Vec<UpsState> = client
        .ups_devices()
        .await
        .map_err(|e| format!("upsDevices query failed: {e}"))?
        .ups_devices
        .into_iter()
        .map(|d| {
            let status = d.status;
            let low_battery = status.split_whitespace().any(|f| f == "LB");
            let on_battery = status.split_whitespace().any(|f| f == "OB");
            UpsState {
                provider: PROVIDER.to_string(),
                id: if d.id.is_empty() {
                    d.name.clone()
                } else {
                    d.id
                },
                model: (!d.model.is_empty()).then_some(d.model),
                battery_charge: Some(d.battery.charge_level as f64),
                battery_runtime_ms: Some(d.battery.estimated_runtime * 1000),
                input_voltage: Some(d.power.input_voltage),
                load_percent: Some(d.power.load_percentage as f64),
                on_battery,
                low_battery,
                status,
            }
        })
        .filter(|s| args.id.as_ref().is_none_or(|id| &s.id == id))
        .collect();
    Ok(states)
}

/// `config_get` op — apcupsd thresholds + kill-power via `upsConfiguration`.
pub async fn config_get_typed(args: UpsQueryArgs) -> Result<Vec<UpsConfig>, String> {
    let Some(client) = first_client() else {
        return Ok(Vec::new());
    };
    let c = client
        .ups_configuration()
        .await
        .map_err(|e| format!("upsConfiguration query failed: {e}"))?
        .ups_configuration;
    let cfg = UpsConfig {
        id: args
            .id
            .or(c.ups_name)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "default".to_string()),
        battery_level: c.battery_level,
        // Unraid reports these in its native minutes/seconds; orca carries ms.
        low_runtime_ms: c.minutes.map(|m| m * 60_000),
        on_battery_timeout_ms: c.timeout.map(|s| s * 1000),
        kill_power: c.kill_ups.map(|k| k.eq_ignore_ascii_case("yes")),
        shutdown_cmd: None,
    };
    Ok(vec![cfg])
}

/// `config_set` op — apply thresholds / kill-power via the `configureUps`
/// mutation. Only the fields present in the incoming config are sent; the rest
/// are left `None` so Unraid preserves them.
pub async fn config_set_typed(cfg: UpsConfig) -> Result<UpsConfigOutcome, String> {
    let Some(client) = first_client() else {
        return Err("no Unraid endpoint registered (not on the peer?)".to_string());
    };
    // `UPSConfigInput` fields (`minutes`, `timeout`) are Unraid's own API units,
    // NOT orca units — orca carries ms and we convert to Unraid's native
    // minutes/seconds here at the API boundary (the edge).
    let input = UPSConfigInput {
        service: None,
        ups_cable: None,
        custom_ups_cable: None,
        ups_type: None,
        device: None,
        override_ups_capacity: None,
        battery_level: cfg.battery_level,
        minutes: cfg.low_runtime_ms.map(|ms| ms / 60_000),
        timeout: cfg.on_battery_timeout_ms.map(|ms| ms / 1000),
        kill_ups: cfg.kill_power.map(|k| {
            if k {
                UPSKillPower::YES
            } else {
                UPSKillPower::NO
            }
        }),
    };
    let ok = client
        .configure_ups(input)
        .await
        .map_err(|e| format!("configureUps mutation failed: {e}"))?
        .configure_ups;
    Ok(UpsConfigOutcome {
        id: cfg.id,
        provider: PROVIDER.to_string(),
        ok,
        message: if ok {
            "applied UPS config via configureUps".to_string()
        } else {
            "configureUps returned false".to_string()
        },
        restart_required: false,
    })
}
