//! Unraid endpoint registry — `unraid.{list,detail,create,update,delete}`.
//!
//! `#[endpoint_resource]` generates the row struct, the `endpoint_db::*` CRUD
//! helpers and the `list`/`detail` tools. `create`/`update`/`delete` are
//! hand-written below because the shared `endpoints` table persists only
//! `routes`/`enabled`/`insecure`: a `#[secret]` column would be silently
//! dropped on write. The API key lives in the secrets domain under
//! `unraid.<endpoint>.api_key` instead.
//!
//! Addressing is the endpoint's `routes`, tried in order by
//! [`route::resolve_reachable`]. An endpoint with no routes at all, on a host
//! that is itself Unraid, is colocated: the daemon reaches the API through
//! nginx on loopback, which proxies the root-owned unix socket — see
//! [[project-unraid-graphql-unix-socket-endpoint]].

use std::path::Path;

use plugin_toolkit::prelude::*;
use plugin_toolkit::secrets;

use crate::{Config, PROVIDER};

/// GraphQL front of the host this daemon runs on.
pub const LOCAL_URL: &str = "http://127.0.0.1";

/// emhttp's state file; carries the host's current `csrf_token`.
const VAR_INI: &str = "/var/local/emhttp/var.ini";

#[endpoint_resource(plugin = "unraid", skip = "create, update, delete")]
pub struct UnraidEndpoint {
    /// Accept self-signed TLS certs on https routes.
    pub insecure: bool,
}

fn api_key_secret(name: &str) -> String {
    secrets::scoped_name(PROVIDER, name, "api_key")
}

fn set_api_key(name: &str, key: &str) -> Result<()> {
    secrets::set(
        &api_key_secret(name),
        key,
        Some(&format!("unraid API key for endpoint '{name}'")),
    )?;
    Ok(())
}

fn api_key(name: &str) -> Result<String> {
    secrets::get(&api_key_secret(name))?
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "no api_key configured for endpoint '{name}'; set one with \
                 `unraid.update --name {name} --api-key <key>`"
            )
        })
}

/// `csrf_token` from emhttp's `var.ini` contents (`csrf_token="…"`).
fn csrf_from_var_ini(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let token = line
            .trim()
            .strip_prefix("csrf_token=")?
            .trim()
            .trim_matches('"');
        (!token.is_empty()).then(|| token.to_string())
    })
}

/// Host of `scheme://[userinfo@]host[:port][/…]`, brackets stripped from IPv6.
fn url_host(url: &str) -> Option<&str> {
    let rest = url.trim().split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match host_port.strip_prefix('[') {
        Some(v6) => v6.split_once(']')?.0,
        None => host_port.split(':').next()?,
    };
    (!host.is_empty()).then_some(host)
}

fn is_loopback_url(url: &str) -> bool {
    url_host(url).is_some_and(|h| {
        h.eq_ignore_ascii_case("localhost")
            || h.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}

/// This host's emhttp CSRF token, only for a loopback `url`: the token is a
/// local browser-session credential and must never leave the box.
pub(crate) fn local_csrf(url: &str) -> Option<String> {
    local_csrf_from(url, Path::new(VAR_INI))
}

fn local_csrf_from(url: &str, var_ini: &Path) -> Option<String> {
    if !is_loopback_url(url) {
        return None;
    }
    std::fs::read_to_string(var_ini)
        .ok()
        .and_then(|s| csrf_from_var_ini(&s))
}

/// Resolve a registered endpoint into a ready [`Config`]: the first reachable
/// route (loopback only when no route is registered and this host is Unraid),
/// the API key from the secrets domain, and this host's CSRF token when the
/// resolved URL is loopback.
pub async fn resolve_config(row: &EndpointRow) -> Result<Config> {
    resolve_config_with(row, Path::new(VAR_INI)).await
}

async fn resolve_config_with(row: &EndpointRow, var_ini: &Path) -> Result<Config> {
    let api_key = api_key(&row.name)?;
    // Registered-but-unusable routes must error rather than fall back to
    // loopback, or a remote endpoint's key would be sent to this host.
    let url = if row.routes.is_empty() {
        if !var_ini.exists() {
            bail!(
                "endpoint '{}' has no routes and this host is not an Unraid server; \
                 register one with `unraid.update --name {} --route kind=scheme://host`",
                row.name,
                row.name
            );
        }
        LOCAL_URL.to_string()
    } else {
        route::resolve_reachable(&row.name, &row.routes, row.insecure).await?
    };
    let csrf = local_csrf_from(&url, var_ini);
    Ok(Config::new(url, api_key)
        .insecure(row.insecure)
        .csrf_token(csrf))
}

/// Endpoint names become the middle segment of `unraid.<name>.api_key`; a `.`
/// or other separator would split into a different secret scope.
fn validate_name(name: &str) -> Result<()> {
    let ok = (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !ok {
        bail!("invalid endpoint name '{name}': must match ^[A-Za-z0-9_-]{{1,64}}$");
    }
    Ok(())
}

fn entry(row: &EndpointRow) -> EndpointEntry {
    EndpointEntry {
        name: row.name.clone(),
        insecure: row.insecure,
        routes: row.routes.clone(),
        enabled: row.enabled,
    }
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidCreateArgs {
    #[arg(long)]
    pub name: String,
    /// Unraid API key, sent as `x-api-key` and stored in the secrets domain.
    /// Mint one with `unraid-api apikey --create --name "orca collector"`.
    #[arg(long)]
    #[serde(alias = "api_key")]
    pub api_key: String,
    /// Accept self-signed TLS certs on https routes.
    #[arg(long)]
    #[serde(default)]
    pub insecure: bool,
    /// Reachable path(s), tried in order. Repeatable: `--route kind=url` or a
    /// JSON object, e.g. `--route lan_v4=http://10.0.0.5`. Omit to reach the
    /// API on loopback when orca runs on the Unraid host itself.
    #[arg(long = "route", value_parser = route::parse_route, action = clap::ArgAction::Append)]
    #[serde(default)]
    pub routes: Vec<Route>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct UnraidCreateOutput {
    pub endpoint: EndpointEntry,
}

/// Register an Unraid endpoint. The API key goes to the secrets domain, never
/// the endpoint row.
#[orca_tool(domain = "unraid", verb = "create")]
async fn unraid_create(args: UnraidCreateArgs, _ctx: &ToolCtx) -> Result<UnraidCreateOutput> {
    validate_name(&args.name)?;
    if args.api_key.trim().is_empty() {
        bail!("api_key must not be empty");
    }
    let row = EndpointRow {
        name: args.name,
        insecure: args.insecure,
        routes: Routes::from(args.routes),
        enabled: true,
    };
    endpoint_db::insert(&row).map_err(|e| runtime::map_insert_conflict(e, PROVIDER, &row.name))?;
    if let Err(e) = set_api_key(&row.name, &args.api_key) {
        if let Err(rollback) = endpoint_db::remove(&row.name) {
            tracing::warn!(endpoint = %row.name, error = %rollback, "rollback of endpoint row failed");
        }
        return Err(e);
    }
    Ok(UnraidCreateOutput {
        endpoint: entry(&row),
    })
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidUpdateArgs {
    #[arg(long)]
    pub name: String,
    /// Replace the stored API key.
    #[arg(long)]
    #[serde(alias = "api_key")]
    pub api_key: Option<String>,
    #[arg(long)]
    pub insecure: Option<bool>,
    /// Replace the reachable-path set. Repeatable: `--route kind=url` or a JSON
    /// object. Omit to leave routes unchanged.
    #[arg(long = "route", value_parser = route::parse_route, action = clap::ArgAction::Append)]
    #[serde(default)]
    pub routes: Vec<Route>,
    #[arg(long)]
    pub enabled: Option<bool>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct UnraidUpdateOutput {
    pub endpoint: EndpointEntry,
    pub applied: Vec<String>,
}

/// Patch an Unraid endpoint. `api_key` is written to the secrets domain.
#[orca_tool(domain = "unraid", verb = "update")]
async fn unraid_update(args: UnraidUpdateArgs, _ctx: &ToolCtx) -> Result<UnraidUpdateOutput> {
    validate_name(&args.name)?;
    if args.api_key.as_deref().is_some_and(|k| k.trim().is_empty()) {
        bail!("api_key must not be empty");
    }
    let mut row = endpoint_db::get(&args.name)?
        .ok_or_else(|| runtime::missing_row_error(PROVIDER, &args.name))?;
    let mut applied = Vec::new();
    if let Some(v) = args.insecure {
        row.insecure = v;
        applied.push("insecure".to_string());
    }
    if !args.routes.is_empty() {
        row.routes = Routes::from(args.routes);
        applied.push("routes".to_string());
    }
    if let Some(v) = args.enabled {
        row.enabled = v;
        applied.push("enabled".to_string());
    }
    if applied.is_empty() && args.api_key.is_none() {
        bail!("no fields to update; pass at least one flag");
    }
    if !applied.is_empty() && !endpoint_db::update(&row)? {
        bail!("update reported no row change for `{}`", row.name);
    }
    if let Some(key) = args.api_key {
        set_api_key(&row.name, &key)?;
        applied.push("api_key".to_string());
    }
    Ok(UnraidUpdateOutput {
        endpoint: entry(&row),
        applied,
    })
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidDeleteArgs {
    #[arg(long)]
    pub name: String,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct UnraidDeleteOutput {
    pub name: String,
    pub changed: bool,
    pub secret_removed: bool,
}

/// Remove an Unraid endpoint and its stored API key.
#[orca_tool(domain = "unraid", verb = "delete")]
async fn unraid_delete(args: UnraidDeleteArgs, _ctx: &ToolCtx) -> Result<UnraidDeleteOutput> {
    validate_name(&args.name)?;
    let changed = endpoint_db::remove(&args.name)?;
    let secret_removed = secrets::delete(&api_key_secret(&args.name))?;
    Ok(UnraidDeleteOutput {
        name: args.name,
        changed,
        secret_removed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Client;
    use plugin_toolkit::abi::{DbOp, DbReply, DbRow, DbValue, SecretOp, SecretReply};
    use plugin_toolkit::capsink::with_cap_sink;
    use plugin_toolkit::contract::config::{Config as OrcaConfig, Model};
    use plugin_toolkit::serde_json;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// In-memory stand-in for core's `db.op` + `secret.op` capabilities.
    #[derive(Default)]
    struct Store {
        rows: Vec<DbRow>,
        secrets: HashMap<String, String>,
        fail_secret_set: bool,
    }

    fn handle(store: &mut Store, cap: &str, json: &str) -> Result<String, String> {
        match cap {
            "db.op" => {
                let op: DbOp = serde_json::from_str(json).map_err(|e| e.to_string())?;
                let mut reply = DbReply::default();
                match op {
                    DbOp::List { .. } => reply.rows = store.rows.clone(),
                    DbOp::Insert { row, .. } => {
                        store.rows.push(row);
                        reply.affected = 1;
                    }
                    DbOp::Update { key_col, row, .. } => {
                        if let Some(r) = store
                            .rows
                            .iter_mut()
                            .find(|r| r.get(&key_col) == row.get(&key_col))
                        {
                            *r = row;
                            reply.affected = 1;
                        }
                    }
                    DbOp::Delete { key_col, key, .. } => {
                        let before = store.rows.len();
                        store
                            .rows
                            .retain(|r| r.get(&key_col) != Some(&DbValue::Text(key.clone())));
                        reply.affected = (before - store.rows.len()) as u64;
                    }
                    other => return Err(format!("unexpected db op {}", other.kind())),
                }
                serde_json::to_string(&reply).map_err(|e| e.to_string())
            }
            "secret.op" => {
                let op: SecretOp = serde_json::from_str(json).map_err(|e| e.to_string())?;
                let mut reply = SecretReply::default();
                match op {
                    SecretOp::Get { name } => reply.value = store.secrets.get(&name).cloned(),
                    SecretOp::Set { .. } if store.fail_secret_set => {
                        return Err("secret backend unavailable".into());
                    }
                    SecretOp::Set { name, value, .. } => {
                        store.secrets.insert(name, value);
                    }
                    SecretOp::Exists { name } => reply.found = store.secrets.contains_key(&name),
                    SecretOp::Delete { name } => {
                        reply.found = store.secrets.remove(&name).is_some()
                    }
                }
                serde_json::to_string(&reply).map_err(|e| e.to_string())
            }
            other => Err(format!("unexpected capability {other}")),
        }
    }

    fn with_store<R>(store: &Rc<RefCell<Store>>, body: impl FnOnce() -> R) -> R {
        let s = store.clone();
        with_cap_sink(
            Box::new(move |cap: &str, json: &str| handle(&mut s.borrow_mut(), cap, json)),
            body,
        )
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn ctx() -> ToolCtx {
        ToolCtx::new(Arc::new(OrcaConfig {
            anthropic_api_key: None,
            lmstudio_url: String::new(),
            ollama_url: String::new(),
            default_model: Model::LMStudio {
                id: String::new(),
                url: String::new(),
            },
            app_dir: PathBuf::from("/tmp"),
            memory_root: PathBuf::from("/tmp"),
            db_path: PathBuf::from("/tmp/orca-unraid-endpoint-test.db"),
            ports: Default::default(),
        }))
    }

    /// A `var.ini` marking this host as Unraid, carrying `token` as its CSRF.
    fn var_ini(token: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("var.ini");
        std::fs::write(&path, format!("csrf_token=\"{token}\"\n")).unwrap();
        (dir, path)
    }

    fn create_args(name: &str, api_key: &str, routes: Vec<Route>) -> UnraidCreateArgs {
        UnraidCreateArgs {
            name: name.into(),
            api_key: api_key.into(),
            insecure: false,
            routes,
        }
    }

    #[test]
    fn stored_api_key_reaches_the_client_headers_via_routes() {
        let rt = rt();
        let server = rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/graphql"))
                .and(header("x-api-key", "k-stored"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "data": { "vars": { "version": "7.3.1" } }
                })))
                .expect(1)
                .mount(&server)
                .await;
            server
        });
        let store = Rc::new(RefCell::new(Store::default()));
        let route = route::parse_route(&format!("lan_v4={}", server.uri())).unwrap();

        let cfg = with_store(&store, || {
            rt.block_on(async {
                unraid_create(create_args("tower-a", "k-stored", vec![route]), &ctx())
                    .await
                    .unwrap();
                let row = endpoint_db::require("tower-a").unwrap();
                resolve_config(&row).await.unwrap()
            })
        });

        let s = store.borrow();
        assert_eq!(
            s.secrets.get("unraid.tower-a.api_key").map(String::as_str),
            Some("k-stored")
        );
        assert!(
            s.rows
                .iter()
                .all(|r| !r.values().any(|v| *v == DbValue::Text("k-stored".into()))),
            "api_key must never land in the endpoint row"
        );
        assert_eq!(cfg.url, server.uri());

        let version = rt
            .block_on(Client::new(cfg).probe_version())
            .expect("request carried the stored x-api-key");
        assert_eq!(version.as_deref(), Some("7.3.1"));
    }

    #[test]
    fn update_replaces_the_stored_api_key() {
        let rt = rt();
        let store = Rc::new(RefCell::new(Store::default()));
        let (out, cfg) = with_store(&store, || {
            rt.block_on(async {
                unraid_create(create_args("tower-b", "k-old", Vec::new()), &ctx())
                    .await
                    .unwrap();
                let out = unraid_update(
                    UnraidUpdateArgs {
                        name: "tower-b".into(),
                        api_key: Some("k-new".into()),
                        ..Default::default()
                    },
                    &ctx(),
                )
                .await
                .unwrap();
                let row = endpoint_db::require("tower-b").unwrap();
                let (_dir, ini) = var_ini("t");
                (out, resolve_config_with(&row, &ini).await.unwrap())
            })
        });
        assert_eq!(out.applied, vec!["api_key".to_string()]);
        assert_eq!(cfg.api_key, "k-new");
        assert_eq!(
            cfg.headers().get("x-api-key").map(String::as_str),
            Some("k-new")
        );
    }

    #[test]
    fn no_routes_on_an_unraid_host_resolves_to_loopback_with_csrf() {
        let rt = rt();
        let store = Rc::new(RefCell::new(Store::default()));
        let (_dir, ini) = var_ini("LOCAL-CSRF");
        let cfg = with_store(&store, || {
            rt.block_on(async {
                unraid_create(create_args("tower-c", "k", Vec::new()), &ctx())
                    .await
                    .unwrap();
                let row = endpoint_db::require("tower-c").unwrap();
                resolve_config_with(&row, &ini).await.unwrap()
            })
        });
        assert_eq!(cfg.url, LOCAL_URL);
        assert_eq!(
            cfg.headers().get("x-csrf-token").map(String::as_str),
            Some("LOCAL-CSRF")
        );
    }

    #[test]
    fn no_routes_off_an_unraid_host_errors() {
        let rt = rt();
        let store = Rc::new(RefCell::new(Store::default()));
        let dir = tempfile::tempdir().unwrap();
        let err = with_store(&store, || {
            rt.block_on(async {
                unraid_create(create_args("tower-g", "k", Vec::new()), &ctx())
                    .await
                    .unwrap();
                let row = endpoint_db::require("tower-g").unwrap();
                resolve_config_with(&row, &dir.path().join("var.ini"))
                    .await
                    .unwrap_err()
            })
        });
        assert!(
            err.to_string()
                .contains("this host is not an Unraid server"),
            "{err}"
        );
    }

    #[test]
    fn only_route_disabled_errors_instead_of_falling_back_to_loopback() {
        let rt = rt();
        let store = Rc::new(RefCell::new(Store::default()));
        let (_dir, ini) = var_ini("LOCAL-CSRF");
        let mut route = route::parse_route("lan_v4=http://10.0.0.5").unwrap();
        route.enabled = false;
        let err = with_store(&store, || {
            rt.block_on(async {
                unraid_create(create_args("tower-h", "k", vec![route]), &ctx())
                    .await
                    .unwrap();
                let row = endpoint_db::require("tower-h").unwrap();
                resolve_config_with(&row, &ini).await.unwrap_err()
            })
        });
        assert!(
            err.to_string()
                .contains("no enabled URL-addressable routes"),
            "{err}"
        );
    }

    #[test]
    fn csrf_token_only_attaches_to_loopback_urls() {
        let (_dir, ini) = var_ini("LOCAL-CSRF");
        for url in [
            LOCAL_URL,
            "http://127.0.0.1:8080/",
            "https://localhost",
            "http://[::1]:80",
        ] {
            assert_eq!(
                local_csrf_from(url, &ini).as_deref(),
                Some("LOCAL-CSRF"),
                "{url}"
            );
        }
        for url in [
            "http://10.0.0.5",
            "https://tower.example:443",
            "http://127.0.0.1.example",
            "http://localhost@10.0.0.5",
            "http://10.0.0.5/127.0.0.1",
        ] {
            assert_eq!(local_csrf_from(url, &ini), None, "{url}");
        }
    }

    #[test]
    fn invalid_names_are_rejected_before_any_write() {
        let rt = rt();
        let store = Rc::new(RefCell::new(Store::default()));
        let long = "a".repeat(65);
        for name in ["", "a.b", "a b", "a/b", long.as_str()] {
            let err = with_store(&store, || {
                rt.block_on(unraid_create(create_args(name, "k", Vec::new()), &ctx()))
                    .err()
                    .unwrap()
            });
            assert!(err.to_string().contains("invalid endpoint name"), "{err}");
        }
        let s = store.borrow();
        assert!(s.rows.is_empty());
        assert!(s.secrets.is_empty());
    }

    #[test]
    fn failed_secret_write_rolls_back_the_row() {
        let rt = rt();
        let store = Rc::new(RefCell::new(Store {
            fail_secret_set: true,
            ..Default::default()
        }));
        let err = with_store(&store, || {
            rt.block_on(unraid_create(
                create_args("tower-i", "k", Vec::new()),
                &ctx(),
            ))
            .err()
            .unwrap()
        });
        assert!(
            format!("{err:#}").contains("secret backend unavailable"),
            "{err:#}"
        );
        assert!(store.borrow().rows.is_empty());
    }

    #[test]
    fn missing_api_key_names_the_endpoint() {
        let rt = rt();
        let store = Rc::new(RefCell::new(Store::default()));
        let err = with_store(&store, || {
            let row = EndpointRow {
                name: "tower-d".into(),
                insecure: false,
                routes: Routes::default(),
                enabled: true,
            };
            endpoint_db::insert(&row).unwrap();
            rt.block_on(resolve_config(&row)).unwrap_err()
        });
        assert!(
            err.to_string()
                .contains("no api_key configured for endpoint 'tower-d'"),
            "{err}"
        );
    }

    #[test]
    fn empty_api_key_is_rejected_before_any_write() {
        let rt = rt();
        let store = Rc::new(RefCell::new(Store::default()));
        let err = with_store(&store, || {
            rt.block_on(unraid_create(
                create_args("tower-e", " ", Vec::new()),
                &ctx(),
            ))
            .err()
            .unwrap()
        });
        assert!(err.to_string().contains("api_key must not be empty"));
        assert!(store.borrow().rows.is_empty());
    }

    #[test]
    fn delete_removes_the_stored_api_key() {
        let rt = rt();
        let store = Rc::new(RefCell::new(Store::default()));
        let out = with_store(&store, || {
            rt.block_on(async {
                unraid_create(create_args("tower-f", "k", Vec::new()), &ctx())
                    .await
                    .unwrap();
                unraid_delete(
                    UnraidDeleteArgs {
                        name: "tower-f".into(),
                    },
                    &ctx(),
                )
                .await
                .unwrap()
            })
        });
        assert!(out.changed);
        assert!(out.secret_removed);
        let s = store.borrow();
        assert!(s.rows.is_empty());
        assert!(s.secrets.is_empty());
    }

    #[test]
    fn csrf_token_parsed_from_var_ini() {
        let ini = "NAME=\"tower\"\ncsrf_token=\"ABC123\"\nversion=\"7.3.1\"\n";
        assert_eq!(csrf_from_var_ini(ini).as_deref(), Some("ABC123"));
        assert_eq!(csrf_from_var_ini("csrf_token=\"\"\n"), None);
        assert_eq!(csrf_from_var_ini("NAME=\"tower\"\n"), None);
    }
}
