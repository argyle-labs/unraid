//! Unraid GraphQL client — typed facade over [`unraid_generated`].
//!
//! Transport (HTTP, headers, retries) goes through [`graphql::Client`]. Each
//! public method picks the right generated `GraphQLQuery` impl and routes
//! through [`graphql::Client::query_typed`], which round-trips a typed
//! `Response<ResponseData>` over the wire — no opaque JSON intermediate
//! (see [[feedback-no-serde-json-value]]).
//!
//! Slice A: only Unraid 7.3.1 wired. Slice B adds runtime version probe +
//! schema drift detection.

#[allow(non_camel_case_types, unused_imports, dead_code, clippy::all)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/modules.rs"));
}

/// Auto-generated orca tool surface — one `#[orca_tool]` per GraphQL operation,
/// emitted by `build/surface.rs` from the codegen'd query modules. Query
/// operations surface as read tools, mutations as `role = "admin"` tools; args
/// carry the operation's `Variables` (plus endpoint/override selection) and the
/// return is the typed `ResponseData`. Adding a `.graphql` file auto-surfaces a
/// tool — nothing here is hand-written.
#[allow(non_camel_case_types, clippy::all)]
pub mod surface {
    include!(concat!(env!("OUT_DIR"), "/unraid_surface.rs"));
}

pub mod endpoint;
pub mod registration;
pub mod schema_pull;
pub mod tools;
pub mod topology;
pub mod version;

use crate::generated::v7_3_1::{
    AddPlugin, ArrayStatus, DockerContainers, InstalledPlugins, ParityHistory, RemovePlugin,
    Shares, VarsVersion, add_plugin, array_status, docker_containers, installed_plugins,
    parity_history, remove_plugin, shares, vars_version,
};
use plugin_toolkit::graphql::{Client as GraphQlClient, GraphQLQuery, GraphQlErrors};
use plugin_toolkit::tracing;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use crate::version::UnraidVersion;

/// Which committed schema module backs a [`Client`].
///
/// Only one variant today — adding 7.4 is mechanical:
/// 1. Drop the introspection JSON in `projects/plugins/unraid/schemas/`.
/// 2. Add a `V7_4_X` variant.
/// 3. Each `Client` method `match`es on `self.api` and routes to the
///    matching `crate::generated::v7_4_X::*` types.
///
/// `#[non_exhaustive]` so future variants don't break downstream
/// `match` statements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApiVersion {
    V7_3_1,
}

impl ApiVersion {
    /// The version this enum was generated from.
    pub fn as_str(self) -> &'static str {
        match self {
            ApiVersion::V7_3_1 => "7.3.1",
        }
    }

    /// Pick an [`ApiVersion`] for a [`UnraidVersion`]. Returns `None`
    /// when the probed version has no matching committed schema — callers
    /// should warn via [`Client::warn_on_drift`] and either bail or fall
    /// back to the newest known variant (currently 7.3.1).
    pub fn from_probed(v: &UnraidVersion) -> Option<Self> {
        match v.module? {
            "v7_3_1" => Some(ApiVersion::V7_3_1),
            _ => None,
        }
    }

    /// Newest committed version. Today: `V7_3_1`.
    pub fn newest() -> Self {
        ApiVersion::V7_3_1
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub base_url: String,
    /// Unraid API key, sent as the `x-api-key` header. Generate one in
    /// Settings → Management Access → API Keys on the Unraid web UI.
    /// The `Authorization: Bearer` header is ignored by the Unraid GraphQL
    /// endpoint — calls without `x-api-key` fall through to browser-session
    /// CSRF auth and fail with `Invalid CSRF token`.
    pub api_key: String,
    pub insecure: bool,
}

impl Config {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            insecure: false,
        }
    }

    pub fn insecure(mut self, on: bool) -> Self {
        self.insecure = on;
        self
    }

    fn endpoint(&self) -> String {
        format!("{}/graphql", self.base_url.trim_end_matches('/'))
    }
}

#[derive(Debug)]
pub enum UnraidError {
    GraphQl(GraphQlErrors),
}

impl std::fmt::Display for UnraidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnraidError::GraphQl(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for UnraidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            UnraidError::GraphQl(e) => Some(e),
        }
    }
}

impl From<GraphQlErrors> for UnraidError {
    fn from(e: GraphQlErrors) -> Self {
        UnraidError::GraphQl(e)
    }
}

/// Result of [`Client::warn_on_drift`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftStatus {
    /// Live schema hash == committed schema hash for the probed version.
    Match,
    /// Live and committed both exist but their hashes differ.
    Drifted {
        version: String,
        embedded_sha: String,
        live_sha: String,
    },
    /// Live host's version has no committed schema in `unraid-generated`.
    Unsupported { version: String, live_sha: String },
    /// `vars { version }` returned null — couldn't determine the version.
    ProbeReturnedNull,
    /// Introspection POST failed (network / auth). Caller's actual query
    /// will surface the underlying error; drift check is best-effort.
    ProbeFailed,
}

fn warned_keys() -> &'static Mutex<HashSet<String>> {
    static SET: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    SET.get_or_init(|| Mutex::new(HashSet::new()))
}

#[derive(Clone)]
pub struct Client {
    endpoint: String,
    headers: HashMap<String, String>,
    insecure: bool,
    api: ApiVersion,
    gql: GraphQlClient,
}

impl Client {
    /// Build a client pinned to the newest committed schema
    /// ([`ApiVersion::newest`]). Use [`Client::new_with`] to pin a
    /// specific version, or [`Client::new_probed`] to auto-detect.
    pub fn new(cfg: Config) -> Self {
        Self::new_with(cfg, ApiVersion::newest())
    }

    /// Build a client pinned to a specific [`ApiVersion`].
    pub fn new_with(cfg: Config, api: ApiVersion) -> Self {
        let endpoint = cfg.endpoint();
        let mut headers = HashMap::new();
        headers.insert("x-api-key".to_string(), cfg.api_key);
        Self {
            endpoint,
            headers,
            insecure: cfg.insecure,
            api,
            gql: GraphQlClient::new(),
        }
    }

    /// Probe the live host's version, pick the matching [`ApiVersion`],
    /// and build a client. Returns `Err` only if the probe call itself
    /// failed (network / auth); if the probed version has no committed
    /// schema, falls back to [`ApiVersion::newest`] and emits a drift
    /// warning on first use.
    pub async fn new_probed(cfg: Config) -> Result<Self, UnraidError> {
        let probe = Self::new(cfg.clone());
        let raw = probe.probe_version().await?.unwrap_or_default();
        let v = UnraidVersion::parse(&raw);
        let api = ApiVersion::from_probed(&v).unwrap_or_else(ApiVersion::newest);
        Ok(Self::new_with(cfg, api))
    }

    /// The schema version this client routes through.
    pub fn api_version(&self) -> ApiVersion {
        self.api
    }

    pub async fn installed_plugins(&self) -> Result<installed_plugins::ResponseData, UnraidError> {
        self.run::<InstalledPlugins>(installed_plugins::Variables)
            .await
    }

    pub async fn array(&self) -> Result<array_status::ResponseData, UnraidError> {
        self.run::<ArrayStatus>(array_status::Variables).await
    }

    pub async fn shares(&self) -> Result<shares::ResponseData, UnraidError> {
        self.run::<Shares>(shares::Variables).await
    }

    /// Enumerate Docker containers managed by this Unraid host. The
    /// topology collector maps each into a `container` claim so Unraid
    /// docker workloads surface in the systems graph (the local docker
    /// socket is root:docker-only, so the GraphQL API is the supported
    /// read path on Unraid).
    pub async fn docker_containers(&self) -> Result<docker_containers::ResponseData, UnraidError> {
        self.run::<DockerContainers>(docker_containers::Variables)
            .await
    }

    pub async fn parity_history(&self) -> Result<parity_history::ResponseData, UnraidError> {
        self.run::<ParityHistory>(parity_history::Variables).await
    }

    pub async fn add_plugin(
        &self,
        input: add_plugin::PluginManagementInput,
    ) -> Result<add_plugin::ResponseData, UnraidError> {
        self.run::<AddPlugin>(add_plugin::Variables { input }).await
    }

    /// Probe the running Unraid version via `vars { version }`. Requires
    /// a valid API key (`x-api-key` header) — introspection is open but
    /// `vars` falls through to browser-session CSRF auth when unkeyed and
    /// fails. Returns the raw version string ("7.3.1", "7.3.0-rc1", etc.)
    /// so callers can route to the matching generated client module.
    pub async fn probe_version(&self) -> Result<Option<String>, UnraidError> {
        let data = self.run::<VarsVersion>(vars_version::Variables).await?;
        Ok(data.vars.version)
    }

    /// Outcome of a [`Client::warn_on_drift`] call.
    /// `unsupported` means the live host's version has no committed
    /// schema; `drifted` means we have a committed schema but its hash
    /// differs from the live introspection.
    ///
    /// Both states emit one `tracing::warn` per (endpoint, version, live
    /// sha) tuple — repeated calls within the same process are silent.
    pub async fn warn_on_drift(&self) -> Result<DriftStatus, UnraidError> {
        let version = match self.probe_version().await? {
            Some(v) => v,
            None => return Ok(DriftStatus::ProbeReturnedNull),
        };
        let embedded = schema_pull::embedded_for(&version);
        let live_raw =
            match schema_pull::introspect_raw(&self.endpoint, &self.headers, self.insecure).await {
                Ok(s) => s,
                Err(_) => return Ok(DriftStatus::ProbeFailed),
            };
        let live_sha = schema_pull::sha256_hex(live_raw.as_bytes());
        let status = match embedded {
            None => DriftStatus::Unsupported {
                version: version.clone(),
                live_sha: live_sha.clone(),
            },
            Some(e) if schema_pull::sha256_hex(e.as_bytes()) == live_sha => DriftStatus::Match,
            Some(e) => DriftStatus::Drifted {
                version: version.clone(),
                embedded_sha: schema_pull::sha256_hex(e.as_bytes()),
                live_sha: live_sha.clone(),
            },
        };
        // Dedupe key: same endpoint + same version + same live sha = one warn.
        let key = format!("{}|{}|{}", self.endpoint, version, live_sha);
        let mut set = warned_keys().lock().expect("warned_keys poisoned");
        // Cardinality is bounded in practice (few endpoints × few versions ×
        // a couple of live shas), but a long-running daemon hitting many
        // upstreams could grow this without bound. Bound it.
        const MAX_WARNED_KEYS: usize = 256;
        if set.len() >= MAX_WARNED_KEYS {
            set.clear();
        }
        if matches!(
            status,
            DriftStatus::Drifted { .. } | DriftStatus::Unsupported { .. }
        ) && set.insert(key)
        {
            drop(set);
            match &status {
                DriftStatus::Drifted { embedded_sha, .. } => tracing::warn!(
                    endpoint = %self.endpoint,
                    version = %version,
                    embedded_sha256 = %embedded_sha,
                    live_sha256 = %live_sha,
                    "unraid schema drift: live introspection differs from committed schema — \
                     queries may break; run `unraid.schema --check_drift` to confirm",
                ),
                DriftStatus::Unsupported { .. } => tracing::warn!(
                    endpoint = %self.endpoint,
                    version = %version,
                    live_sha256 = %live_sha,
                    "unraid version has no committed schema — pull one via \
                     `unraid.schema --from <url> --dir projects/plugins/unraid/schemas`",
                ),
                _ => {}
            }
        }
        Ok(status)
    }

    pub async fn remove_plugin(
        &self,
        input: remove_plugin::PluginManagementInput,
    ) -> Result<remove_plugin::ResponseData, UnraidError> {
        self.run::<RemovePlugin>(remove_plugin::Variables { input })
            .await
    }

    /// Run any generated [`GraphQLQuery`] and return its typed `ResponseData`.
    /// This is the generic entry the auto-generated tool surface
    /// (`build/surface.rs`) dispatches through; the hand-written methods above
    /// are thin typed aliases over the same path.
    pub async fn query<Q>(&self, variables: Q::Variables) -> Result<Q::ResponseData, UnraidError>
    where
        Q: GraphQLQuery,
    {
        self.run::<Q>(variables).await
    }

    async fn run<Q>(&self, variables: Q::Variables) -> Result<Q::ResponseData, UnraidError>
    where
        Q: GraphQLQuery,
    {
        Ok(self
            .gql
            .query_typed::<Q>(
                &self.endpoint,
                variables,
                Some(&self.headers),
                self.insecure,
            )
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::prelude::json;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg(uri: String) -> Config {
        Config::new(uri, "tok")
    }

    #[tokio::test]
    async fn installed_plugins_sends_api_key_and_parses_scalar() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(header("x-api-key", "tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "installedUnraidPlugins": ["foo", "bar"] }
            })))
            .mount(&server)
            .await;
        let r = Client::new(cfg(server.uri()))
            .installed_plugins()
            .await
            .unwrap();
        assert_eq!(r.installed_unraid_plugins, vec!["foo", "bar"]);
    }

    #[tokio::test]
    async fn add_plugin_serializes_input() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(body_partial_json(
                json!({"variables": {"input": {"names": ["ca.cleanup.appdata.plg"]}}}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "addPlugin": true }
            })))
            .mount(&server)
            .await;
        let out = Client::new(cfg(server.uri()))
            .add_plugin(add_plugin::PluginManagementInput {
                names: vec!["ca.cleanup.appdata.plg".into()],
                bundled: false,
                restart: false,
            })
            .await
            .unwrap();
        assert!(out.add_plugin);
    }

    #[tokio::test]
    async fn graphql_errors_propagate() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": null,
                "errors": [{"message": "array offline"}]
            })))
            .mount(&server)
            .await;
        let err = Client::new(cfg(server.uri())).array().await.unwrap_err();
        assert!(matches!(err, UnraidError::GraphQl(_)));
    }

    #[tokio::test]
    async fn probe_version_returns_string() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "vars": { "version": "7.3.1" } }
            })))
            .mount(&server)
            .await;
        let v = Client::new(cfg(server.uri()))
            .probe_version()
            .await
            .unwrap();
        assert_eq!(v.as_deref(), Some("7.3.1"));
    }

    #[tokio::test]
    async fn new_probed_selects_api_version_from_live_probe() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "vars": { "version": "7.3.1-rc4" } }
            })))
            .mount(&server)
            .await;
        let c = Client::new_probed(cfg(server.uri())).await.unwrap();
        assert_eq!(c.api_version(), ApiVersion::V7_3_1);
    }

    #[tokio::test]
    async fn new_probed_falls_back_to_newest_when_unknown_version() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "vars": { "version": "9.9.9" } }
            })))
            .mount(&server)
            .await;
        let c = Client::new_probed(cfg(server.uri())).await.unwrap();
        assert_eq!(c.api_version(), ApiVersion::newest());
    }

    #[test]
    fn api_version_round_trips_through_parsed_version() {
        let v = UnraidVersion::parse("7.3.1");
        assert_eq!(ApiVersion::from_probed(&v), Some(ApiVersion::V7_3_1));
        assert_eq!(ApiVersion::V7_3_1.as_str(), "7.3.1");
    }

    #[tokio::test]
    async fn warn_on_drift_flags_mismatch() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "vars": { "version": "7.3.1" } }
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "__schema": { "queryType": {"name": "Query"} } }
            })))
            .mount(&server)
            .await;
        let status = Client::new(cfg(server.uri()))
            .warn_on_drift()
            .await
            .unwrap();
        assert!(matches!(status, DriftStatus::Drifted { .. }));
    }

    #[tokio::test]
    async fn warn_on_drift_unsupported_for_unknown_version() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "vars": { "version": "9.9.9" } }
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;
        let status = Client::new(cfg(server.uri()))
            .warn_on_drift()
            .await
            .unwrap();
        assert!(matches!(status, DriftStatus::Unsupported { .. }));
    }

    #[test]
    fn endpoint_trims_trailing_slash() {
        let c = Config::new("http://srv/", "tok").insecure(true);
        assert_eq!(c.endpoint(), "http://srv/graphql");
        assert!(c.insecure);
    }
}
