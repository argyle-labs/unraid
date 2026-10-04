//! Unraid tool surface — `unraid.schema` covers schema management
//! (pull from a live host, drift-check against embedded). Per
//! `feedback_one_tool_per_resource`: one tool, one resource (schema),
//! actions selected via args.
//!
//! Default behaviour (no args): list embedded schema versions. With
//! `from` + `api_key`: probe the live host and either write a fresh
//! introspection JSON (`dir`) or report drift (`check_drift`).

use std::path::{Path, PathBuf};

use plugin_toolkit::prelude::*;

use crate::endpoint::{self, endpoint_db};
use crate::{Client, Config, schema_pull};

/// [`Config`] for an explicit `from` override; carries this host's CSRF token
/// only when `from` is the local loopback origin.
fn from_config(from: &str, api_key: impl Into<String>, insecure: bool) -> Result<Config> {
    from_config_with(from, api_key, insecure, Path::new(endpoint::VAR_INI))
}

fn from_config_with(
    from: &str,
    api_key: impl Into<String>,
    insecure: bool,
    var_ini: &Path,
) -> Result<Config> {
    if from.trim().is_empty() {
        bail!("`from` must not be blank");
    }
    Ok(Config::new(from, api_key)
        .insecure(insecure)
        .csrf_token(endpoint::local_csrf_from(from, var_ini)))
}

/// Resolve a [`Client`] for an auto-generated surface tool (`crate::surface`).
///
/// Connection selection, in order: an explicit `from` + `api_key` override wins
/// (paired with optional `insecure`); otherwise the named endpoint from the
/// registry (`unraid.{list,create,...}`); otherwise, when `endpoint` is omitted
/// and exactly one enabled endpoint is registered, that sole endpoint. Disabled
/// endpoints are never used. Anything else is an error naming the fix.
pub(crate) async fn surface_client(
    endpoint: Option<String>,
    from: Option<String>,
    api_key: Option<String>,
    insecure: Option<bool>,
) -> Result<Client> {
    if let Some(url) = from {
        let key = api_key.ok_or_else(|| anyhow!("`api_key` is required when `from` is set"))?;
        return Ok(Client::new(from_config(
            &url,
            key,
            insecure.unwrap_or(false),
        )?));
    }
    let row = match endpoint {
        Some(name) => endpoint_db::get(&name)?
            .ok_or_else(|| anyhow!("no unraid endpoint named `{name}` — see `unraid.list`"))?,
        None => {
            let mut all: Vec<_> = endpoint_db::list()?
                .into_iter()
                .filter(|r| r.enabled)
                .collect();
            match all.len() {
                1 => all.remove(0),
                0 => bail!(
                    "no enabled unraid endpoints registered — add one with `unraid.create`, \
                     or pass `from` + `api_key`"
                ),
                n => bail!(
                    "{n} enabled unraid endpoints registered — pass `endpoint` to pick one, \
                     or `from` + `api_key`"
                ),
            }
        }
    };
    Ok(Client::new(endpoint::resolve_config(&row).await?))
}

#[orca_struct(args)]
pub struct UnraidSchemaArgs {
    /// Base URL of a live Unraid host (e.g. `https://tower.local`).
    /// Required to do anything other than list embedded versions.
    #[arg(long)]
    pub from: Option<String>,
    /// Unraid API key (`x-api-key` header). Required when `from` is set.
    /// Generate one in the Unraid UI under Settings → Management Access →
    /// API Keys.
    #[arg(long)]
    pub api_key: Option<String>,
    /// Accept self-signed TLS certificates (common on Unraid).
    #[arg(long, default_value_t = false)]
    pub insecure: bool,
    /// When set, report drift between the live and embedded schemas
    /// without writing the live JSON to disk. Mutually exclusive with
    /// `dir`.
    #[arg(long, default_value_t = false)]
    pub check_drift: bool,
    /// Destination directory for the pulled schema. The written file is
    /// always `<probed_version>.introspection.json`. Required when
    /// `check_drift` is false and `from` is set. The default schemas
    /// directory in the orca repo is `projects/plugins/unraid/schemas`.
    #[arg(long)]
    pub dir: Option<PathBuf>,
}

#[orca_struct]
#[derive(Debug)]
pub struct PulledSchema {
    pub version: String,
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[orca_struct]
#[derive(Debug)]
pub struct DriftReport {
    pub probed_version: String,
    /// Hex sha256 of the committed introspection JSON for `probed_version`,
    /// or `None` if no embedded schema matches.
    pub embedded_sha256: Option<String>,
    pub live_sha256: String,
    pub identical: bool,
}

#[orca_struct]
#[derive(Debug)]
pub struct UnraidSchemaOutput {
    /// Versions with a committed introspection JSON inside the
    /// `unraid-generated` crate.
    pub embedded_versions: Vec<String>,
    /// Present when a fresh schema was written to disk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pulled: Option<PulledSchema>,
    /// Present when `check_drift` was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drift: Option<DriftReport>,
}

/// Inspect and refresh the Unraid GraphQL schemas used by `unraid::Client`.
/// Without args: lists embedded versions. With `from` + `api_key`: probes a
/// live host and either pulls a fresh introspection (when `dir` set) or
/// reports drift (when `check_drift` set).
#[orca_tool(domain = "unraid", verb = "schema")]
async fn unraid_schema(args: UnraidSchemaArgs, _ctx: &ToolCtx) -> Result<UnraidSchemaOutput> {
    let embedded_versions = crate::generated::SCHEMAS
        .iter()
        .map(|(v, _)| (*v).to_string())
        .collect();

    let Some(from) = args.from.as_deref() else {
        return Ok(UnraidSchemaOutput {
            embedded_versions,
            pulled: None,
            drift: None,
        });
    };

    let api_key = args
        .api_key
        .as_deref()
        .ok_or_else(|| anyhow!("`api_key` is required when `from` is set"))?;
    let cfg = from_config(from, api_key, args.insecure)?;

    if args.check_drift {
        if args.dir.is_some() {
            bail!("`check_drift` and `dir` are mutually exclusive");
        }
        let r = schema_pull::check_drift(cfg).await?;
        return Ok(UnraidSchemaOutput {
            embedded_versions,
            pulled: None,
            drift: Some(DriftReport {
                probed_version: r.probed_version,
                embedded_sha256: r.embedded_sha256,
                live_sha256: r.live_sha256,
                identical: r.identical,
            }),
        });
    }

    let dir = args
        .dir
        .as_deref()
        .ok_or_else(|| anyhow!("`dir` is required when `from` is set without `check_drift`"))?;
    let out = schema_pull::schema_pull(cfg, dir).await?;
    Ok(UnraidSchemaOutput {
        embedded_versions,
        pulled: Some(PulledSchema {
            version: out.version,
            path: out.path.display().to_string(),
            sha256: out.sha256,
            bytes: out.bytes,
        }),
        drift: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::contract::config::{Config as OrcaConfig, Model};
    use plugin_toolkit::prelude::{ToolCtx, json};
    use std::path::PathBuf;
    use std::sync::Arc;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn empty_ctx() -> ToolCtx {
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
            db_path: PathBuf::from("/tmp/orca-unraid-schema-test.db"),
            ports: Default::default(),
        }))
    }

    #[tokio::test]
    async fn lists_embedded_versions_without_args() {
        let ctx = empty_ctx();
        let out = unraid_schema(UnraidSchemaArgs::default(), &ctx)
            .await
            .unwrap();
        assert!(out.embedded_versions.contains(&"7.3.1".to_string()));
        assert!(out.pulled.is_none());
        assert!(out.drift.is_none());
    }

    #[tokio::test]
    async fn pulls_and_writes_when_dir_set() {
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
        let tmp = tempfile::tempdir().unwrap();
        let ctx = empty_ctx();
        let out = unraid_schema(
            UnraidSchemaArgs {
                from: Some(server.uri()),
                api_key: Some("tok".into()),
                dir: Some(tmp.path().to_path_buf()),
                ..Default::default()
            },
            &ctx,
        )
        .await
        .unwrap();
        let pulled = out.pulled.expect("pulled");
        assert_eq!(pulled.version, "7.3.1");
        assert!(pulled.path.ends_with("7.3.1.introspection.json"));
    }

    #[tokio::test]
    async fn check_drift_returns_report_without_writing() {
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
        let ctx = empty_ctx();
        let out = unraid_schema(
            UnraidSchemaArgs {
                from: Some(server.uri()),
                api_key: Some("tok".into()),
                check_drift: true,
                ..Default::default()
            },
            &ctx,
        )
        .await
        .unwrap();
        let drift = out.drift.expect("drift");
        assert_eq!(drift.probed_version, "7.3.1");
        assert!(!drift.identical);
        assert!(drift.embedded_sha256.is_some());
    }

    #[tokio::test]
    async fn from_without_api_key_errors() {
        let ctx = empty_ctx();
        let err = unraid_schema(
            UnraidSchemaArgs {
                from: Some("http://srv".into()),
                ..Default::default()
            },
            &ctx,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("api_key"));
    }

    #[tokio::test]
    async fn blank_from_is_rejected() {
        let err = unraid_schema(
            UnraidSchemaArgs {
                from: Some("  ".into()),
                api_key: Some("tok".into()),
                check_drift: true,
                ..Default::default()
            },
            &empty_ctx(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("`from` must not be blank"),
            "{err}"
        );
        let err = surface_client(None, Some(String::new()), Some("tok".into()), None)
            .await
            .err()
            .unwrap();
        assert!(
            err.to_string().contains("`from` must not be blank"),
            "{err}"
        );
    }

    fn var_ini() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("var.ini");
        std::fs::write(&path, "csrf_token=\"LOCAL-CSRF\"\n").unwrap();
        (dir, path)
    }

    #[test]
    fn from_carries_csrf_token_only_to_the_local_origin() {
        let (_dir, ini) = var_ini();
        let cfg = from_config_with("http://127.0.0.1", "tok", false, &ini).unwrap();
        assert_eq!(cfg.csrf_token.as_deref(), Some("LOCAL-CSRF"));
        for from in [
            "http://10.0.0.5",
            "http://evil.example\\@127.0.0.1",
            "https://evil.example\\@[::1]:443",
        ] {
            let cfg = from_config_with(from, "tok", false, &ini).unwrap();
            assert!(cfg.csrf_token.is_none(), "{from}");
        }
    }

    #[tokio::test]
    async fn from_on_a_non_local_origin_sends_no_csrf_header() {
        let server = MockServer::start().await;
        Mock::given(header_exists("x-csrf-token"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "vars": { "version": "7.3.1" } }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let (_dir, ini) = var_ini();
        let cfg = from_config_with(&server.uri(), "tok", false, &ini).unwrap();
        let version = Client::new(cfg).probe_version().await.unwrap();
        assert_eq!(version.as_deref(), Some("7.3.1"));
    }

    #[tokio::test]
    async fn check_drift_with_dir_errors() {
        let ctx = empty_ctx();
        let err = unraid_schema(
            UnraidSchemaArgs {
                from: Some("http://srv".into()),
                api_key: Some("tok".into()),
                check_drift: true,
                dir: Some(PathBuf::from("/tmp")),
                ..Default::default()
            },
            &ctx,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }
}
