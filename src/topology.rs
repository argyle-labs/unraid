//! Unraid → TopologyClaim collector (GraphQL docker path).
//!
//! Walks every registered + enabled Unraid endpoint and emits one
//! `container` claim per docker container the host runs. The local docker
//! socket on Unraid is `root:docker`-only, so the GraphQL API is the
//! supported read path (per [[project-adapter-backends-api-first]]); this
//! collector is the Unraid analogue of `docker::topology`.
//!
//! Claims carry no MACs today — the `DockerContainer` GraphQL type exposes
//! networking only through an unmapped `JSON` scalar. That's fine: the
//! collector runs colocated with the host whose daemon reports it, so each
//! container nests directly under its reporting peer without MAC matching.
//!
//! Errors are scoped per endpoint: a broken endpoint is logged and skipped
//! so it can't blank out claims from the others. Returns empty silently
//! when no endpoints are registered.

use crate::endpoint::{endpoint_db, EndpointRow};
use crate::{Client, Config};
use plugin_toolkit::contract::TopologyClaim;
use plugin_toolkit::prelude::*;

/// Collect docker container claims from every registered Unraid endpoint.
pub async fn collect_claims() -> Result<Vec<TopologyClaim>> {
    // `endpoint_db::list()` routes through the host DB channel and manages its
    // own connection, so nothing non-`Send` crosses the awaits below.
    let endpoints = endpoint_db::list()?;

    let mut out = Vec::new();
    for ep in endpoints.into_iter().filter(|e| e.enabled) {
        match collect_for_endpoint(&ep).await {
            Ok(mut v) => out.append(&mut v),
            Err(e) => tracing::warn!(
                endpoint = %ep.name,
                error = %e,
                "unraid topology: endpoint collector failed",
            ),
        }
    }
    Ok(out)
}

async fn collect_for_endpoint(ep: &EndpointRow) -> Result<Vec<TopologyClaim>> {
    let cfg = Config::new(ep.base_url.clone(), ep.api_key.clone()).insecure(ep.insecure);
    let data = Client::new(cfg).docker_containers().await?;
    Ok(data
        .docker
        .containers
        .into_iter()
        .map(|c| TopologyClaim {
            kind: "container".to_string(),
            id: c.id.chars().take(12).collect(),
            name: first_name(&c.names),
            macs: Vec::new(),
            provider: "unraid".to_string(),
            provider_instance: ep.name.clone(),
        })
        .collect())
}

/// First container name, stripped of docker's leading `/`. Empty when the
/// container reports no names.
fn first_name(names: &[String]) -> String {
    names
        .first()
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_name_strips_leading_slash() {
        assert_eq!(first_name(&["/syncthing".to_string()]), "syncthing");
        assert_eq!(
            first_name(&["plex".to_string(), "/other".to_string()]),
            "plex"
        );
        assert_eq!(first_name(&[]), "");
    }
}
