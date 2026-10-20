//! `unraid.host.settings.set` — change server identity and time settings
//! through the Unraid GraphQL API.
//!
//! Identity (`name`/`comment`/`sysModel`) can only change while the array is
//! STOPPED; that is checked live before the mutation and refused otherwise.
//! The identity mutation sets all three fields at once, so fields not given
//! are filled from the current values rather than sent as null.
//! Time settings (timezone, NTP) have no precondition. Dry-run by default,
//! admin required for both (see [`crate::authz`]). Mutation documents stay
//! out of `queries/`, where every operation auto-surfaces as an ungated tool.

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{Map, Value, json};

use crate::authz::require_admin;
use crate::generated::v7_3_1::array_status::ArrayState;
use crate::tools::surface_client;

const IDENTITY_DOC: &str = "mutation SetIdentity($name: String!, $comment: String, $sysModel: String) \
     { updateServerIdentity(name: $name, comment: $comment, sysModel: $sysModel) { name comment } }";

const CURRENT_IDENTITY_DOC: &str = "query CurrentIdentity { vars { name comment sysModel } }";

const CURRENT_TIME_DOC: &str = "query CurrentTime { systemTime { timeZone useNtp ntpServers } }";

const TIME_DOC: &str = "mutation SetTime($input: UpdateSystemTimeInput!) \
     { updateSystemTime(input: $input) { timeZone useNtp ntpServers } }";

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidHostSettingsSetArgs {
    /// Server name. Needs the array stopped.
    #[arg(long)]
    #[serde(default)]
    pub name: Option<String>,
    /// Server description. Needs the array stopped.
    #[arg(long)]
    #[serde(default)]
    pub comment: Option<String>,
    /// Server model. Needs the array stopped.
    #[arg(long)]
    #[serde(default)]
    pub sys_model: Option<String>,
    /// IANA timezone, e.g. `America/Los_Angeles`.
    #[arg(long)]
    #[serde(default)]
    pub time_zone: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub use_ntp: Option<bool>,
    /// Up to four NTP servers.
    #[arg(long)]
    #[serde(default)]
    pub ntp_servers: Option<Vec<String>>,
    /// Registered unraid endpoint; optional when exactly one is registered.
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Apply the change. Without it the call only reports what it would do.
    #[arg(long, default_value_t = false)]
    #[serde(default)]
    pub execute: bool,
}

/// Requested identity fields; `None` keeps the current value.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct IdentityChange {
    pub name: Option<String>,
    pub comment: Option<String>,
    pub sys_model: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Plan {
    pub identity: Option<IdentityChange>,
    /// `input` for [`TIME_DOC`].
    pub time: Option<Value>,
}

/// Unraid's server-name rule: 1-15 letters, digits, '.' or '-', not
/// starting or ending with '.' or '-'.
pub(crate) fn validate_server_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 15
        || name.starts_with(['.', '-'])
        || name.ends_with(['.', '-'])
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        bail!(
            "invalid server name '{name}': 1-15 letters, digits, '.' or '-', \
             not starting or ending with '.' or '-'"
        );
    }
    Ok(())
}

/// An IP address or an RFC 1123 hostname.
pub(crate) fn validate_ntp_server(s: &str) -> Result<()> {
    if s.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let host = s.strip_suffix('.').unwrap_or(s);
    let ok = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if !ok {
        bail!("invalid NTP server '{s}': expected a hostname or IP address");
    }
    Ok(())
}

pub(crate) fn plan(a: &UnraidHostSettingsSetArgs) -> Result<Plan> {
    if let Some(n) = &a.name {
        validate_server_name(n)?;
    }
    // Both land in ident.cfg, a line-based file.
    for (field, v) in [("comment", &a.comment), ("sysModel", &a.sys_model)] {
        if v.as_deref()
            .is_some_and(|v| v.chars().any(char::is_control))
        {
            bail!("invalid {field}: control characters are not allowed");
        }
    }
    let identity = (a.name.is_some() || a.comment.is_some() || a.sys_model.is_some()).then(|| {
        IdentityChange {
            name: a.name.clone(),
            comment: a.comment.clone(),
            sys_model: a.sys_model.clone(),
        }
    });
    let mut t = Map::new();
    if let Some(tz) = &a.time_zone {
        if tz.trim().is_empty() || tz.contains(char::is_whitespace) {
            bail!("invalid time zone '{tz}'");
        }
        t.insert("timeZone".into(), json!(tz));
    }
    if let Some(u) = a.use_ntp {
        t.insert("useNtp".into(), json!(u));
    }
    if let Some(s) = &a.ntp_servers {
        if s.len() > 4 {
            bail!("at most 4 NTP servers, got {}", s.len());
        }
        for server in s {
            validate_ntp_server(server)?;
        }
        t.insert("ntpServers".into(), json!(s));
    }
    let time = (!t.is_empty()).then_some(Value::Object(t));
    if identity.is_none() && time.is_none() {
        bail!("nothing to change: pass identity and/or time settings");
    }
    Ok(Plan { identity, time })
}

/// [`IDENTITY_DOC`] variables: requested fields over the current `vars`.
pub(crate) fn identity_vars(change: &IdentityChange, current: &Value) -> Result<Value> {
    let cur = |k: &str| current["vars"][k].as_str().map(str::to_string);
    let name = change
        .name
        .clone()
        .or_else(|| cur("name"))
        .filter(|n| !n.trim().is_empty())
        .ok_or_else(|| anyhow!("current server name is unknown; pass `name`"))?;
    Ok(json!({
        "name": name,
        "comment": change.comment.clone().or_else(|| cur("comment")).unwrap_or_default(),
        "sysModel": change.sys_model.clone().or_else(|| cur("sysModel")).unwrap_or_default(),
    }))
}

/// `updateSystemTime` input with omitted fields filled from the current
/// `systemTime`. The schema does not say whether an omitted field is kept or
/// reset, so every field is always sent.
pub(crate) fn time_input(requested: &Value, current: &Value) -> Result<Value> {
    let cur = &current["systemTime"];
    let mut out = Map::new();
    for k in ["timeZone", "useNtp", "ntpServers"] {
        let v = match requested.get(k) {
            Some(v) => v.clone(),
            None if !cur[k].is_null() => cur[k].clone(),
            None => bail!("current {k} is unknown; pass it explicitly"),
        };
        out.insert(k.into(), v);
    }
    Ok(Value::Object(out))
}

/// Identity changes need the array stopped.
pub(crate) fn identity_allowed(state: &ArrayState) -> Result<()> {
    if matches!(state, ArrayState::STOPPED) {
        Ok(())
    } else {
        bail!(
            "server identity can only change with the array stopped (it is {state:?}); stop the \
             array first"
        )
    }
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HostSettingsSetOutput {
    /// Dry run: the identity variables that would be sent. Executed: the result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Value>,
    /// Dry run: the time input that would be sent. Executed: the result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<Value>,
    /// Why execute would be refused (e.g. the array is not stopped).
    pub blockers: Vec<String>,
    pub executed: bool,
}

/// The time result, or an error that says whether identity was already applied.
pub(crate) fn partial_apply(
    identity: &Option<Value>,
    time: std::result::Result<Value, crate::UnraidError>,
) -> Result<Value> {
    time.map_err(|e| match identity {
        Some(applied) => anyhow!(
            "PARTIAL APPLY: identity was changed ({applied}) but the time settings failed: {e}"
        ),
        None => anyhow!("time settings failed: {e}"),
    })
}

/// Change server identity and/or time settings. Dry-run unless `execute:
/// true`; admin is required for both.
#[orca_tool(
    domain = "unraid",
    verb = "host.settings.set",
    role = "admin",
    execute_gated = false
)]
async fn unraid_host_settings_set(
    args: UnraidHostSettingsSetArgs,
    ctx: &ToolCtx,
) -> Result<HostSettingsSetOutput> {
    require_admin("unraid.host.settings.set", ctx.caller().as_ref())?;
    let p = plan(&args)?;
    let client = surface_client(args.endpoint, None, None, None).await?;
    let mut blockers = Vec::new();
    let identity_vars = match &p.identity {
        Some(change) => {
            if let Err(e) = identity_allowed(&client.array().await?.array.state) {
                blockers.push(e.to_string());
            }
            let current = client.query_raw(CURRENT_IDENTITY_DOC, json!({})).await?;
            Some(identity_vars(change, &current)?)
        }
        None => None,
    };
    let time = match &p.time {
        Some(req) => {
            let current = client.query_raw(CURRENT_TIME_DOC, json!({})).await?;
            Some(time_input(req, &current)?)
        }
        None => None,
    };
    if !args.execute {
        return Ok(HostSettingsSetOutput {
            identity: identity_vars,
            time,
            blockers,
            executed: false,
        });
    }
    if let Some(b) = blockers.first() {
        bail!("{b}");
    }
    let mut out = HostSettingsSetOutput {
        identity: None,
        time: None,
        blockers,
        executed: true,
    };
    if let Some(vars) = identity_vars {
        out.identity = Some(client.mutate_raw(IDENTITY_DOC, vars).await?);
    }
    if let Some(input) = time {
        let res = client.mutate_raw(TIME_DOC, json!({ "input": input })).await;
        out.time = Some(partial_apply(&out.identity, res)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> UnraidHostSettingsSetArgs {
        UnraidHostSettingsSetArgs {
            name: None,
            comment: None,
            sys_model: None,
            time_zone: None,
            use_ntp: None,
            ntp_servers: None,
            endpoint: None,
            execute: false,
        }
    }

    #[test]
    fn dry_run_requires_admin() {
        for role in [Some("user"), None] {
            let mut a = args();
            a.time_zone = Some("UTC".into());
            let ctx = crate::authz::test_ctx(role);
            let e =
                plugin_toolkit::reactor::block_on(unraid_host_settings_set(a, &ctx)).unwrap_err();
            assert!(e.to_string().contains("unraid.host.settings.set: "), "{e}");
        }
    }

    #[test]
    fn time_only_plan_has_no_identity() {
        let mut a = args();
        a.time_zone = Some("America/Los_Angeles".into());
        a.use_ntp = Some(true);
        a.ntp_servers = Some(vec!["pool.ntp.org".into()]);
        let p = plan(&a).unwrap();
        assert!(p.identity.is_none());
        assert_eq!(
            p.time.unwrap(),
            json!({"timeZone": "America/Los_Angeles", "useNtp": true, "ntpServers": ["pool.ntp.org"]})
        );
    }

    #[test]
    fn unspecified_identity_fields_come_from_current_values() {
        let current = json!({"vars": {"name": "willow", "comment": "media", "sysModel": "N2"}});
        let only_name = IdentityChange {
            name: Some("thor".into()),
            ..Default::default()
        };
        assert_eq!(
            identity_vars(&only_name, &current).unwrap(),
            json!({"name": "thor", "comment": "media", "sysModel": "N2"})
        );
        let only_comment = IdentityChange {
            comment: Some("x".into()),
            ..Default::default()
        };
        let v = identity_vars(&only_comment, &current).unwrap();
        assert_eq!(
            v,
            json!({"name": "willow", "comment": "x", "sysModel": "N2"})
        );
        assert!(
            v.as_object().unwrap().values().all(|x| !x.is_null()),
            "never sends null"
        );
    }

    #[test]
    fn missing_current_values_never_become_null() {
        let v = identity_vars(
            &IdentityChange {
                name: Some("thor".into()),
                ..Default::default()
            },
            &json!({"vars": {"name": "willow", "comment": null}}),
        )
        .unwrap();
        assert_eq!(v, json!({"name": "thor", "comment": "", "sysModel": ""}));
        let e = identity_vars(&IdentityChange::default(), &json!({})).unwrap_err();
        assert!(e.to_string().contains("pass `name`"));
    }

    #[test]
    fn blank_name_is_refused() {
        let mut a = args();
        a.name = Some(" ".into());
        assert!(plan(&a).is_err());
        a.name = None;
        a.comment = Some("c".into());
        assert!(
            plan(&a).unwrap().identity.is_some(),
            "name no longer required"
        );
    }

    #[test]
    fn rejects_empty_and_invalid_input() {
        assert!(
            plan(&args())
                .unwrap_err()
                .to_string()
                .contains("nothing to change")
        );
        let mut a = args();
        a.time_zone = Some("America/Los Angeles".into());
        assert!(plan(&a).is_err());
        let mut a = args();
        a.ntp_servers = Some(vec!["a".into(); 5]);
        assert!(plan(&a).is_err());
    }

    #[test]
    fn comment_and_sys_model_refuse_control_chars() {
        for bad in ["a\nb", "a\rb", "a\0b", "a\x1bb"] {
            let mut a = args();
            a.comment = Some(bad.into());
            assert!(plan(&a).is_err(), "{bad:?}");
            let mut a = args();
            a.sys_model = Some(bad.into());
            assert!(plan(&a).is_err(), "{bad:?}");
        }
        let mut a = args();
        a.comment = Some("media server".into());
        a.sys_model = Some("N2 Pro".into());
        assert!(plan(&a).is_ok());
    }

    #[test]
    fn server_names_follow_unraid_rules() {
        for ok in ["Tower", "willow-2", "a.b", "abcdefghijklmno"] {
            assert!(validate_server_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "abcdefghijklmnop",
            "my tower",
            "tower_1",
            "t\u{e9}",
            "a;b",
            "-tower",
            "tower-",
            ".tower",
            "tower.",
        ] {
            assert!(validate_server_name(bad).is_err(), "{bad}");
        }
        let mut a = args();
        a.name = Some("bad name".into());
        assert!(plan(&a).is_err());
    }

    #[test]
    fn ntp_servers_must_be_hostnames_or_ips() {
        for ok in [
            "pool.ntp.org",
            "time1.google.com.",
            "10.0.0.1",
            "::1",
            "ntp",
        ] {
            assert!(validate_ntp_server(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a b", "-x.org", "x-.org", "a..b", "x;rm", "host:123"] {
            assert!(validate_ntp_server(bad).is_err(), "{bad}");
        }
        let mut a = args();
        a.ntp_servers = Some(vec!["pool.ntp.org".into(), "bad host".into()]);
        assert!(plan(&a).is_err());
    }

    #[test]
    fn identity_requires_a_stopped_array() {
        assert!(identity_allowed(&ArrayState::STOPPED).is_ok());
        let e = identity_allowed(&ArrayState::STARTED)
            .unwrap_err()
            .to_string();
        assert!(e.contains("array stopped") && e.contains("STARTED"));
        assert!(identity_allowed(&ArrayState::Other("STOPPED ".into())).is_err());
    }

    #[test]
    fn time_failure_after_identity_reports_partial_apply() {
        let err = || {
            Err(crate::UnraidError::GraphQl(
                plugin_toolkit::graphql::GraphQlErrors::ServerErrors {
                    summary: "boom".into(),
                    response: Box::new(plugin_toolkit::serde_json::from_value(json!({})).unwrap()),
                },
            ))
        };
        let e = partial_apply(&Some(json!({"name": "thor"})), err()).unwrap_err();
        assert!(
            e.to_string()
                .starts_with("PARTIAL APPLY: identity was changed")
        );
        assert!(e.to_string().contains("boom"));
        let e = partial_apply(&None, err()).unwrap_err();
        assert!(!e.to_string().contains("PARTIAL"));
        assert_eq!(partial_apply(&None, Ok(json!(1))).unwrap(), json!(1));
    }

    #[test]
    fn documents_name_real_schema_fields() {
        let (_, schema) = crate::generated::SCHEMAS[0];
        for f in [
            "updateServerIdentity",
            "updateSystemTime",
            "UpdateSystemTimeInput",
        ] {
            assert!(schema.contains(&format!("\"{f}\"")), "{f}");
        }
        for f in ["\"sysModel\"", "\"comment\""] {
            assert!(schema.contains(f), "{f}");
        }
        assert!(IDENTITY_DOC.contains("updateServerIdentity"));
        assert!(CURRENT_IDENTITY_DOC.contains("vars { name comment sysModel }"));
        assert!(TIME_DOC.contains("UpdateSystemTimeInput!"));
    }

    #[test]
    fn omitted_time_fields_are_filled_from_current() {
        let current = json!({"systemTime": {
            "timeZone": "America/Denver", "useNtp": true, "ntpServers": ["a", "b", "", ""]
        }});
        assert_eq!(
            time_input(&json!({"timeZone": "UTC"}), &current).unwrap(),
            json!({"timeZone": "UTC", "useNtp": true, "ntpServers": ["a", "b", "", ""]})
        );
        let e = time_input(&json!({"useNtp": false}), &json!({"systemTime": {}})).unwrap_err();
        assert!(e.to_string().contains("current timeZone is unknown"));
        assert!(CURRENT_TIME_DOC.contains("systemTime { timeZone useNtp ntpServers }"));
    }
}
