//! Typed subset of `docker inspect` / `docker image inspect` JSON, and the
//! projection of a live container into a [`RunSpec`].
//!
//! Every facet that the template cannot carry is reported as `unsupported`
//! rather than dropped, so the fidelity gate refuses a container it would
//! otherwise silently change.

use std::collections::BTreeMap;

use plugin_toolkit::prelude::*;

use super::spec::{self, MountKind, MountSpec, RunSpec};

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerInspect {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    /// Image id (`sha256:…`) the container was created from.
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub config: ContainerConfig,
    #[serde(default)]
    pub host_config: HostConfig,
    #[serde(default)]
    pub mounts: Vec<MountPoint>,
    #[serde(default)]
    pub state: ContainerState,
    #[serde(default)]
    pub network_settings: NetworkSettings,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerConfig {
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub working_dir: String,
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    /// The image reference as given at create time (`repo:tag`).
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub labels: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub tty: bool,
    #[serde(default)]
    pub open_stdin: bool,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct HostConfig {
    #[serde(default)]
    pub network_mode: String,
    #[serde(default)]
    pub privileged: bool,
    #[serde(default)]
    pub port_bindings: Option<BTreeMap<String, Option<Vec<PortBinding>>>>,
    #[serde(default)]
    pub restart_policy: RestartPolicy,
    #[serde(default)]
    pub log_config: LogConfig,
    #[serde(default)]
    pub tmpfs: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub device_requests: Option<Vec<DeviceRequest>>,
    #[serde(default)]
    pub cap_add: Option<Vec<String>>,
    #[serde(default)]
    pub cap_drop: Option<Vec<String>>,
    #[serde(default)]
    pub devices: Option<Vec<DeviceMapping>>,
    #[serde(default)]
    pub ulimits: Option<Vec<Ulimit>>,
    #[serde(default)]
    pub sysctls: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub security_opt: Option<Vec<String>>,
    #[serde(default)]
    pub extra_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub dns: Option<Vec<String>>,
    #[serde(default)]
    pub dns_search: Option<Vec<String>>,
    #[serde(default)]
    pub group_add: Option<Vec<String>>,
    #[serde(default)]
    pub links: Option<Vec<String>>,
    #[serde(default)]
    pub volumes_from: Option<Vec<String>>,
    #[serde(default)]
    pub memory: Option<i64>,
    #[serde(default)]
    pub nano_cpus: Option<i64>,
    #[serde(default)]
    pub cpuset_cpus: Option<String>,
    #[serde(default)]
    pub shm_size: Option<i64>,
    #[serde(default)]
    pub pid_mode: Option<String>,
    #[serde(default)]
    pub ipc_mode: Option<String>,
    #[serde(default)]
    pub userns_mode: Option<String>,
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub init: Option<bool>,
    #[serde(default)]
    pub readonly_rootfs: Option<bool>,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct PortBinding {
    #[serde(default)]
    pub host_ip: String,
    #[serde(default)]
    pub host_port: String,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct RestartPolicy {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub maximum_retry_count: i64,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct LogConfig {
    #[serde(default, rename = "Type")]
    pub kind: String,
    #[serde(default)]
    pub config: Option<BTreeMap<String, String>>,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DeviceRequest {
    #[serde(default)]
    pub driver: String,
    #[serde(default)]
    pub count: i64,
    #[serde(default, rename = "DeviceIDs")]
    pub device_ids: Option<Vec<String>>,
    #[serde(default)]
    pub capabilities: Option<Vec<Vec<String>>>,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DeviceMapping {
    #[serde(default)]
    pub path_on_host: String,
    #[serde(default)]
    pub path_in_container: String,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Ulimit {
    #[serde(default)]
    pub name: String,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct MountPoint {
    #[serde(default, rename = "Type")]
    pub kind: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub destination: String,
    #[serde(default, rename = "RW")]
    pub rw: bool,
    #[serde(default)]
    pub propagation: String,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerState {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub running: bool,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkSettings {
    #[serde(default)]
    pub networks: Option<BTreeMap<String, NetworkEndpoint>>,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
pub struct NetworkEndpoint {
    #[serde(default, rename = "IPAMConfig")]
    pub ipam_config: Option<IpamConfig>,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
pub struct IpamConfig {
    #[serde(default, rename = "IPv4Address")]
    pub ipv4_address: Option<String>,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ImageInspect {
    #[serde(default)]
    pub config: ImageConfig,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ImageConfig {
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub working_dir: String,
    #[serde(default)]
    pub labels: Option<BTreeMap<String, String>>,
}

/// Compose project label docker compose stamps on every container it creates.
pub const COMPOSE_PROJECT: &str = "com.docker.compose.project";
/// Compose working-directory label (the stack directory).
pub const COMPOSE_WORKING_DIR: &str = "com.docker.compose.project.working_dir";
/// Label Unraid's dockerman stamps on containers it renders.
pub const MANAGED_LABEL: &str = "net.unraid.docker.managed";
/// Label carrying the icon URL Unraid's Docker tab shows.
pub const ICON_LABEL: &str = "net.unraid.docker.icon";

impl ContainerInspect {
    /// Container name without docker's leading `/`.
    pub fn short_name(&self) -> &str {
        self.name.trim_start_matches('/')
    }

    pub fn label(&self, key: &str) -> Option<&str> {
        self.config
            .labels
            .as_ref()
            .and_then(|l| l.get(key))
            .map(String::as_str)
    }

    pub fn compose_project(&self) -> Option<&str> {
        self.label(COMPOSE_PROJECT).filter(|p| !p.is_empty())
    }

    /// Network mode with docker's `default` alias resolved to `bridge`.
    pub fn network(&self) -> String {
        match self.host_config.network_mode.as_str() {
            "" | "default" => "bridge".to_string(),
            other => other.to_string(),
        }
    }

    /// Volume-type mounts (named and anonymous).
    pub fn volumes(&self) -> impl Iterator<Item = &MountPoint> {
        self.mounts.iter().filter(|m| m.kind == "volume")
    }
}

/// A 64-hex volume name is one docker generated for an anonymous volume.
pub fn is_anonymous_volume(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

fn nonempty<T>(v: &Option<Vec<T>>) -> bool {
    v.as_ref().is_some_and(|v| !v.is_empty())
}

/// The live container as a [`RunSpec`], plus every facet the template cannot
/// express. Image-baked env/labels and Unraid-injected items are excluded so
/// the spec carries only what the operator set.
pub fn live_spec(c: &ContainerInspect, img: &ImageInspect) -> (RunSpec, Vec<String>) {
    let mut unsupported = Vec::new();
    let hc = &c.host_config;
    let network = c.network();
    if network.starts_with("container:") {
        unsupported.push(format!("network mode {network}"));
    }
    if let Some(nets) = &c.network_settings.networks {
        if nets.len() > 1 {
            let names: Vec<&str> = nets.keys().map(String::as_str).collect();
            unsupported.push(format!(
                "attached to multiple networks [{}]",
                names.join(", ")
            ));
        }
        for (net, ep) in nets {
            if let Some(ip) = ep
                .ipam_config
                .as_ref()
                .and_then(|i| i.ipv4_address.as_deref())
                .filter(|ip| !ip.is_empty())
            {
                unsupported.push(format!("static IP {ip} on network {net}"));
            }
        }
    }

    let mut ports = std::collections::BTreeSet::new();
    for (cport, binds) in hc.port_bindings.iter().flatten() {
        for b in binds.iter().flatten() {
            if b.host_port.is_empty() {
                unsupported.push(format!("port {cport} published on a random host port"));
                continue;
            }
            ports.insert(spec::port_key(&b.host_ip, &b.host_port, cport));
        }
    }

    let baked_env: std::collections::HashSet<&str> = img
        .config
        .env
        .iter()
        .flatten()
        .map(String::as_str)
        .collect();
    let mut env = BTreeMap::new();
    for kv in c.config.env.iter().flatten() {
        if baked_env.contains(kv.as_str()) {
            continue;
        }
        let (k, v) = kv.split_once('=').unwrap_or((kv.as_str(), ""));
        env.insert(k.to_string(), v.to_string());
    }

    let mut mounts = std::collections::BTreeSet::new();
    for m in &c.mounts {
        match m.kind.as_str() {
            "volume" => mounts.insert(MountSpec {
                kind: MountKind::Volume,
                source: m.name.clone().unwrap_or_default(),
                target: m.destination.clone(),
                read_only: !m.rw,
                propagation: None,
            }),
            "bind" => mounts.insert(MountSpec {
                kind: MountKind::Bind,
                source: m.source.clone(),
                target: m.destination.clone(),
                read_only: !m.rw,
                propagation: spec::non_default_propagation(&m.propagation),
            }),
            other => {
                unsupported.push(format!("{other} mount at {}", m.destination));
                false
            }
        };
    }

    let hostname = {
        let h = &c.config.hostname;
        let short_id = c.id.get(..12).unwrap_or(&c.id);
        (!h.is_empty() && h != short_id && network != "host").then(|| h.clone())
    };

    let mut gpus = None;
    for dr in hc.device_requests.iter().flatten() {
        let is_gpu = dr
            .capabilities
            .iter()
            .flatten()
            .flatten()
            .any(|c| c == "gpu");
        let ids = dr.device_ids.clone().unwrap_or_default();
        match (is_gpu, ids.len()) {
            (true, 0) if dr.count == -1 => gpus = Some("all".to_string()),
            (true, 0) if dr.count > 0 => gpus = Some(dr.count.to_string()),
            (true, 1) => gpus = Some(format!("device={}", ids[0])),
            _ => unsupported.push(format!(
                "device request driver={:?} count={} ids={ids:?}",
                dr.driver, dr.count
            )),
        }
    }

    let restart = match hc.restart_policy.name.as_str() {
        "" | "no" => None,
        "on-failure" if hc.restart_policy.maximum_retry_count > 0 => Some(format!(
            "on-failure:{}",
            hc.restart_policy.maximum_retry_count
        )),
        other => Some(other.to_string()),
    };

    let image_labels = img.config.labels.clone().unwrap_or_default();
    let labels = c
        .config
        .labels
        .iter()
        .flatten()
        .filter(|(k, v)| image_labels.get(*k) != Some(*v))
        .filter(|(k, _)| !k.starts_with("com.docker.compose."))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let cmd = if c.config.cmd != img.config.cmd {
        c.config.cmd.clone().unwrap_or_default()
    } else {
        Vec::new()
    };
    if c.config.entrypoint != img.config.entrypoint {
        unsupported.push(format!("entrypoint override {:?}", c.config.entrypoint));
    }
    if c.config.user != img.config.user {
        unsupported.push(format!("user override {:?}", c.config.user));
    }
    if c.config.working_dir != img.config.working_dir {
        unsupported.push(format!("working dir override {:?}", c.config.working_dir));
    }
    if c.config.tty || c.config.open_stdin {
        unsupported.push("tty/stdin allocation".to_string());
    }

    for (what, set) in [
        ("cap-add", nonempty(&hc.cap_add)),
        ("cap-drop", nonempty(&hc.cap_drop)),
        ("devices", nonempty(&hc.devices)),
        ("ulimits", nonempty(&hc.ulimits)),
        ("security-opt", nonempty(&hc.security_opt)),
        ("extra hosts", nonempty(&hc.extra_hosts)),
        ("dns", nonempty(&hc.dns)),
        ("dns-search", nonempty(&hc.dns_search)),
        ("group-add", nonempty(&hc.group_add)),
        ("links", nonempty(&hc.links)),
        ("volumes-from", nonempty(&hc.volumes_from)),
        (
            "sysctls",
            hc.sysctls.as_ref().is_some_and(|s| !s.is_empty()),
        ),
        ("memory limit", hc.memory.unwrap_or(0) != 0),
        ("cpu limit", hc.nano_cpus.unwrap_or(0) != 0),
        (
            "cpuset",
            hc.cpuset_cpus.as_deref().is_some_and(|s| !s.is_empty()),
        ),
        (
            "shm-size",
            !matches!(hc.shm_size, None | Some(0) | Some(67_108_864)),
        ),
        (
            "pid mode",
            hc.pid_mode.as_deref().is_some_and(|s| !s.is_empty()),
        ),
        (
            "ipc mode",
            !matches!(
                hc.ipc_mode.as_deref(),
                None | Some("") | Some("private") | Some("shareable")
            ),
        ),
        (
            "userns mode",
            hc.userns_mode.as_deref().is_some_and(|s| !s.is_empty()),
        ),
        (
            "runtime",
            !matches!(hc.runtime.as_deref(), None | Some("") | Some("runc")),
        ),
        ("init", hc.init == Some(true)),
        ("read-only rootfs", hc.readonly_rootfs == Some(true)),
    ] {
        if set {
            unsupported.push(format!("unsupported host config: {what}"));
        }
    }

    let log_driver = if hc.log_config.kind.is_empty() {
        spec::DEFAULT_LOG_DRIVER.to_string()
    } else {
        hc.log_config.kind.clone()
    };

    let spec = RunSpec {
        name: c.short_name().to_string(),
        image: c.config.image.clone(),
        network,
        privileged: hc.privileged,
        hostname,
        ports,
        env,
        mounts,
        tmpfs: hc.tmpfs.clone().unwrap_or_default(),
        log_driver,
        log_opts: hc.log_config.config.clone().unwrap_or_default(),
        gpus,
        restart,
        labels,
        cmd,
        other: Vec::new(),
    };
    (spec.normalized(), unsupported)
}
