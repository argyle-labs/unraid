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

use crate::endpoint::{EndpointRow, endpoint_db};
use crate::generated::v7_3_1::docker_containers::{
    ContainerState, DockerContainersDockerContainers,
};
use crate::{Client, Config};
use plugin_toolkit::contract::TopologyClaim;
use plugin_toolkit::prelude::*;
use std::collections::BTreeMap;

/// Label keys the Unraid facet rides on until `TopologyClaim` grows first-class
/// `icon_url`/`web_ui_url` fields (tracked separately). Consumers read these to
/// render the Unraid container icon + WebUI link + update badge.
const ICON_LABEL: &str = "orca.icon_url";
const WEBUI_LABEL: &str = "orca.web_ui_url";
const UPDATE_LABEL: &str = "orca.update_available";

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
        .map(|c| claim_from_container(c, &ep.name))
        .collect())
}

/// Map one Unraid GraphQL `DockerContainer` into a `container` claim, carrying
/// the Unraid facet: normalized run-state, image, and the container's Unraid
/// icon / WebUI link / update flag (on `labels` until first-class fields exist).
///
/// Addresses are deliberately NOT emitted: the GraphQL type's only IP source is
/// the docker-internal bridge address, which is not LAN-reachable (same rule as
/// the docker plugin). A container's reachable address is the HOST ip + its
/// published port — surfaced as endpoints once the toolkit maps the `Port`
/// scalar so this query can select `ports { ip privatePort publicPort type }`
/// (tracked follow-up). MACs are likewise absent (the type exposes them only via
/// an unmapped JSON scalar); the collector runs colocated with the reporting
/// peer, so each container nests directly under its host without MAC matching.
fn claim_from_container(c: DockerContainersDockerContainers, instance: &str) -> TopologyClaim {
    let mut labels: BTreeMap<String, String> = BTreeMap::new();
    if let Some(icon) = c.icon_url.filter(|s| !s.is_empty()) {
        labels.insert(ICON_LABEL.to_string(), icon);
    }
    if let Some(url) = c.web_ui_url.filter(|s| !s.is_empty()) {
        labels.insert(WEBUI_LABEL.to_string(), url);
    }
    if c.is_update_available == Some(true) {
        labels.insert(UPDATE_LABEL.to_string(), "true".to_string());
    }
    TopologyClaim {
        kind: "container".to_string(),
        id: c.id.chars().take(12).collect(),
        name: first_name(&c.names),
        macs: Vec::new(),
        provider: "unraid".to_string(),
        provider_instance: instance.to_string(),
        image: Some(c.image).filter(|s| !s.is_empty()),
        labels,
        state: normalize_state(&c.state),
        ..Default::default()
    }
}

/// Map Unraid's `ContainerState` onto orca's normalized run-state vocabulary
/// (shared with the docker plugin): `RUNNING` → `running`, `PAUSED` → `paused`,
/// `EXITED` → `stopped`. An unrecognized value yields `None` (Unknown, never
/// assumed down).
fn normalize_state(state: &ContainerState) -> Option<String> {
    match state {
        ContainerState::RUNNING => Some("running".to_string()),
        ContainerState::PAUSED => Some("paused".to_string()),
        ContainerState::EXITED => Some("stopped".to_string()),
        ContainerState::Other(_) => None,
    }
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

    fn container(
        name: &str,
        image: &str,
        state: ContainerState,
        icon: Option<&str>,
        webui: Option<&str>,
        update: Option<bool>,
    ) -> DockerContainersDockerContainers {
        DockerContainersDockerContainers {
            id: format!("sha256:{name}deadbeef"),
            names: vec![format!("/{name}")],
            image: image.to_string(),
            state,
            status: "Up 1 hour".to_string(),
            auto_start: false,
            icon_url: icon.map(str::to_string),
            web_ui_url: webui.map(str::to_string),
            is_update_available: update,
        }
    }

    #[test]
    fn first_name_strips_leading_slash() {
        assert_eq!(first_name(&["/syncthing".to_string()]), "syncthing");
        assert_eq!(
            first_name(&["plex".to_string(), "/other".to_string()]),
            "plex"
        );
        assert_eq!(first_name(&[]), "");
    }

    #[test]
    fn normalize_state_maps_unraid_states() {
        assert_eq!(
            normalize_state(&ContainerState::RUNNING).as_deref(),
            Some("running")
        );
        assert_eq!(
            normalize_state(&ContainerState::PAUSED).as_deref(),
            Some("paused")
        );
        assert_eq!(
            normalize_state(&ContainerState::EXITED).as_deref(),
            Some("stopped")
        );
        assert_eq!(
            normalize_state(&ContainerState::Other("weird".into())),
            None
        );
    }

    #[test]
    fn claim_carries_unraid_facet() {
        let c = container(
            "syncthing",
            "lscr.io/linuxserver/syncthing",
            ContainerState::RUNNING,
            Some("/state/plugins/dockerMan/images/syncthing-icon.png"),
            Some("http://10.10.10.10:8384"),
            Some(true),
        );
        let claim = claim_from_container(c, "willow");
        assert_eq!(claim.kind, "container");
        assert_eq!(claim.name, "syncthing");
        assert_eq!(claim.provider, "unraid");
        assert_eq!(claim.provider_instance, "willow");
        assert_eq!(claim.state.as_deref(), Some("running"));
        assert_eq!(
            claim.image.as_deref(),
            Some("lscr.io/linuxserver/syncthing")
        );
        assert_eq!(
            claim.labels.get(ICON_LABEL).map(String::as_str),
            Some("/state/plugins/dockerMan/images/syncthing-icon.png")
        );
        assert_eq!(
            claim.labels.get(WEBUI_LABEL).map(String::as_str),
            Some("http://10.10.10.10:8384")
        );
        assert_eq!(
            claim.labels.get(UPDATE_LABEL).map(String::as_str),
            Some("true")
        );
        // Reachability is not a bridge-internal address.
        assert!(claim.addresses.is_empty());
    }

    #[test]
    fn claim_omits_absent_facet_and_maps_stopped() {
        let c = container(
            "ollama",
            "ollama/ollama",
            ContainerState::EXITED,
            None,
            Some(""),
            Some(false),
        );
        let claim = claim_from_container(c, "willow");
        assert_eq!(claim.state.as_deref(), Some("stopped"));
        assert!(
            claim.labels.is_empty(),
            "no icon/webui/update → no facet labels"
        );
    }
}
