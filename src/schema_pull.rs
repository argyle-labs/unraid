//! Pull a fresh introspection JSON from a live Unraid server and persist
//! it next to the committed schemas. Intended as a dev-time utility:
//! whoever runs it commits the resulting file so codegen has a stable
//! input. Slice B builds the orca CLI/tool wrapper on top of this.
//!
//! Two-step protocol:
//! 1. Probe `vars { version }` with the authenticated token. This both
//!    confirms the token works AND yields the filename
//!    (`<version>.introspection.json`).
//! 2. Run the standard introspection query (open on Unraid even without
//!    a token — but we send the token anyway, matches normal runtime).
//!
//! The output filename is derived from the probed version. Callers
//! supply the destination directory so the same primitive serves both
//! "write into the repo source tree" and "stash in a tmpdir for diffing"
//! use cases.

use crate::{Client, Config};
use plugin_toolkit::prelude::*;
use std::path::{Path, PathBuf};

/// Drift report: live server schema vs the committed one for the
/// version we generated code against. `embedded` is `None` when the
/// probed Unraid version has no matching committed schema — in that
/// case `identical` is always `false` and the caller should fetch
/// (`schema_pull`) to add support.
#[derive(Debug, Clone)]
pub struct DriftReport {
    pub probed_version: String,
    pub embedded_sha256: Option<String>,
    pub live_sha256: String,
    pub identical: bool,
}

/// Pull the live introspection and compare to the committed schema for
/// the probed Unraid version. Returns a report so callers can decide
/// whether to warn-and-continue or hard-fail.
pub async fn check_drift(cfg: Config) -> Result<DriftReport> {
    let client = Client::new(cfg.clone());
    let probed_version = client
        .probe_version()
        .await?
        .ok_or_else(|| anyhow!("unraid server returned null version"))?;
    let live = run_introspection(&cfg).await?;
    let live_sha256 = sha256_hex(live.as_bytes());
    let embedded_sha256 = embedded_for(&probed_version).map(|s| sha256_hex(s.as_bytes()));
    let identical = embedded_sha256.as_deref() == Some(&live_sha256);
    Ok(DriftReport {
        probed_version,
        embedded_sha256,
        live_sha256,
        identical,
    })
}

/// Lookup the embedded introspection JSON for a probed version, if any.
/// Pre-release suffixes are stripped (`7.3.1-rc1` → `7.3.1`).
pub fn embedded_for(probed: &str) -> Option<&'static str> {
    let trimmed = probed
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .next()
        .unwrap_or(probed);
    crate::generated::SCHEMAS
        .iter()
        .find(|(v, _)| *v == trimmed)
        .map(|(_, s)| *s)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    plugin_toolkit::hash::sha256_hex(bytes)
}

/// Result of a successful schema pull.
#[derive(Debug)]
pub struct SchemaPull {
    /// Probed Unraid version (e.g. `"7.3.1"`).
    pub version: String,
    /// Absolute path of the written JSON file.
    pub path: PathBuf,
    /// SHA-256 of the file contents (hex).
    pub sha256: String,
    /// File size in bytes.
    pub bytes: u64,
}

/// Run the schema pull. `dir` is the directory to write into — the file
/// name is always `<version>.introspection.json`. Overwrites if present.
pub async fn schema_pull(cfg: Config, dir: &Path) -> Result<SchemaPull> {
    let client = Client::new(cfg.clone());

    let version = client
        .probe_version()
        .await?
        .ok_or_else(|| anyhow!("unraid server returned null version — auth ok but vars empty"))?;

    let introspection_json = run_introspection(&cfg).await?;

    std::fs::create_dir_all(dir)
        .with_context(|| format!("create schemas dir {}", dir.display()))?;
    let path = dir.join(format!("{version}.introspection.json"));
    std::fs::write(&path, introspection_json.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;

    let sha256 = sha256_hex(introspection_json.as_bytes());

    Ok(SchemaPull {
        version,
        path,
        sha256,
        bytes: introspection_json.len() as u64,
    })
}

async fn run_introspection(cfg: &Config) -> Result<String> {
    let endpoint = format!("{}/graphql", cfg.base_url.trim_end_matches('/'));
    let mut headers = std::collections::HashMap::new();
    headers.insert("x-api-key".to_string(), cfg.api_key.clone());
    introspect_raw(&endpoint, &headers, cfg.insecure).await
}

/// Run the standard GraphQL introspection query against `endpoint` and
/// return the raw response text — verbatim bytes, no re-serialization, so
/// downstream sha256 matches what the server actually sent. `headers` is
/// passed through (typically `x-api-key`); `insecure` skips TLS cert
/// verification (Unraid ships self-signed certs by default).
pub async fn introspect_raw(
    endpoint: &str,
    headers: &std::collections::HashMap<String, String>,
    insecure: bool,
) -> Result<String> {
    let body = json!({
        "query": graphql::INTROSPECTION_QUERY,
        "operationName": "IntrospectionQuery",
    });
    let http = http::Client::new();
    let mut builder = http.post(endpoint).json(body);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    if insecure {
        builder = builder.insecure(true);
    }
    let resp = builder.send().await.with_context(|| "introspection POST")?;
    Ok(resp.text())
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::prelude::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn drift_report_flags_mismatch() {
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
        let cfg = Config::new(server.uri(), "tok");
        let r = check_drift(cfg).await.unwrap();
        assert_eq!(r.probed_version, "7.3.1");
        assert!(
            !r.identical,
            "tiny mock schema should not match embedded one"
        );
        let embedded = r.embedded_sha256.expect("7.3.1 is committed");
        assert_eq!(embedded.len(), 64);
        assert_ne!(embedded, r.live_sha256);
    }

    #[tokio::test]
    async fn writes_versioned_file_and_returns_hash() {
        let server = MockServer::start().await;
        // Both vars-version probe and introspection hit /graphql; wiremock
        // matches in registration order — register version first.
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
        let cfg = Config::new(server.uri(), "tok");
        let out = schema_pull(cfg, tmp.path()).await.unwrap();

        assert_eq!(out.version, "7.3.1");
        assert!(out.path.ends_with("7.3.1.introspection.json"));
        assert!(out.path.exists());
        assert_eq!(out.sha256.len(), 64);
        assert!(out.bytes > 0);
    }
}
