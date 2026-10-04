//! Typed subset of `docker inspect` / `docker image inspect` / `docker volume
//! inspect` JSON, and the projection of a live container into a [`RunSpec`].
//!
//! The typed structs carry only what the template models. [`unmodelled`] walks
//! the raw JSON and reports every other key whose value differs from docker's
//! default (or, for image-derived config, from the image), so a facet this
//! module does not know about blocks the adopt instead of being dropped.

use std::collections::{BTreeMap, BTreeSet};

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{Value, json};

use super::spec::{self, MountKind, MountSpec, RunSpec};

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerInspect {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    /// Image id (`sha256:…`) the container runs.
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
    pub pids_limit: Option<i64>,
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
#[serde(rename_all = "PascalCase")]
pub struct NetworkEndpoint {
    #[serde(default)]
    pub aliases: Option<Vec<String>>,
}

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ImageInspect {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub repo_tags: Option<Vec<String>>,
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

#[orca_struct]
#[derive(Debug, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct VolumeInspect {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub driver: String,
    #[serde(default)]
    pub mountpoint: String,
    #[serde(default)]
    pub labels: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub options: Option<BTreeMap<String, String>>,
}

/// Compose project label docker compose stamps on every container it creates.
pub const COMPOSE_PROJECT: &str = "com.docker.compose.project";
/// Compose working-directory label (the stack directory).
pub const COMPOSE_WORKING_DIR: &str = "com.docker.compose.project.working_dir";
/// Label Unraid's dockerman stamps on containers it renders.
pub const MANAGED_LABEL: &str = "net.unraid.docker.managed";
/// Label carrying the icon URL Unraid's Docker tab shows.
pub const ICON_LABEL: &str = "net.unraid.docker.icon";
/// Label docker puts on volumes it created for an anonymous mount.
pub const ANONYMOUS_VOLUME_LABEL: &str = "com.docker.volume.anonymous";
/// Where the `local` volume driver keeps a volume's data.
pub const VOLUMES_ROOT: &str = "/var/lib/docker/volumes";

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

impl VolumeInspect {
    pub fn is_anonymous(&self) -> bool {
        self.labels
            .as_ref()
            .is_some_and(|l| l.contains_key(ANONYMOUS_VOLUME_LABEL))
    }

    /// The only data path a `local` volume may have.
    pub fn expected_mountpoint(name: &str) -> String {
        format!("{VOLUMES_ROOT}/{name}/_data")
    }
}

/// Image env entries (`K=V`), the set a container inherits without asking.
pub fn baked_env(img: &ImageInspect) -> BTreeSet<String> {
    img.config.env.iter().flatten().cloned().collect()
}

/// The live container as a [`RunSpec`], plus facets the typed model reads but
/// the template cannot express. Image-baked env/labels and Unraid-injected
/// items are excluded so the spec carries only what the operator set.
pub fn live_spec(c: &ContainerInspect, img: &ImageInspect) -> (RunSpec, Vec<String>) {
    let mut unsupported = Vec::new();
    let hc = &c.host_config;
    let network = c.network();
    if network.starts_with("container:") {
        unsupported.push(format!("network mode {network}"));
    }
    if let Some(nets) = &c.network_settings.networks
        && nets.len() > 1
    {
        let names: Vec<&str> = nets.keys().map(String::as_str).collect();
        unsupported.push(format!(
            "attached to multiple networks [{}]",
            names.join(", ")
        ));
    }

    let mut ports = BTreeSet::new();
    for (cport, binds) in hc.port_bindings.iter().flatten() {
        for b in binds.iter().flatten() {
            if b.host_port.is_empty() {
                unsupported.push(format!("port {cport} published on a random host port"));
                continue;
            }
            ports.insert(spec::port_key(&b.host_ip, &b.host_port, cport));
        }
    }

    let baked = baked_env(img);
    let mut env = BTreeMap::new();
    let mut tz = String::new();
    for kv in c.config.env.iter().flatten() {
        let (k, v) = kv.split_once('=').unwrap_or((kv.as_str(), ""));
        if k == "TZ" {
            tz = v.to_string();
            continue;
        }
        if baked.contains(kv) {
            continue;
        }
        env.insert(k.to_string(), v.to_string());
    }

    let mut mounts = BTreeSet::new();
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

    let short_id = c.id.get(..12).unwrap_or(&c.id);
    let h = &c.config.hostname;
    let hostname = (!h.is_empty() && network != "host").then(|| h.clone());
    let hostname_is_default = hostname.as_deref() == Some(short_id);

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
        hostname_is_default,
        ports,
        env,
        tz,
        mounts,
        tmpfs: hc.tmpfs.clone().unwrap_or_default(),
        log_driver,
        log_opts: hc.log_config.config.clone().unwrap_or_default(),
        gpus,
        restart,
        pids_limit: hc.pids_limit.filter(|n| *n > 0),
        labels,
        cmd,
        other: Vec::new(),
    };
    (spec.normalized(), unsupported)
}

/// HostConfig keys the typed model translates.
const MODELLED_HOST: &[&str] = &[
    "Binds",
    "LogConfig",
    "NetworkMode",
    "PortBindings",
    "RestartPolicy",
    "Privileged",
    "Tmpfs",
    "DeviceRequests",
    "PidsLimit",
    "Mounts",
];
/// Daemon-populated HostConfig keys that do not express operator intent.
const IGNORED_HOST: &[&str] = &["MaskedPaths", "ReadonlyPaths", "ContainerIDFile"];
/// Config keys the typed model translates or that only mirror other state.
const MODELLED_CONFIG: &[&str] = &[
    "Hostname",
    "Env",
    "Cmd",
    "Image",
    "Entrypoint",
    "Labels",
    "User",
    "WorkingDir",
    "Tty",
    "OpenStdin",
    "AttachStdin",
    "AttachStdout",
    "AttachStderr",
    "StdinOnce",
    "ArgsEscaped",
    // Mirrors image VOLUMEs plus `-v /path` mounts, which appear in Mounts.
    "Volumes",
    "ExposedPorts",
];

fn is_zero(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

/// HostConfig defaults that are not zero values.
fn host_default(key: &str, v: &Value) -> bool {
    match key {
        "ConsoleSize" => v == &json!([0, 0]),
        "ShmSize" => v == &json!(67_108_864),
        "Runtime" => v == &json!("runc"),
        "IpcMode" => v == &json!("private"),
        "CgroupnsMode" => v == &json!("private"),
        _ => false,
    }
}

const BIND_OPTS: &[&str] = &[
    "rw", "ro", "z", "Z", "rprivate", "private", "rslave", "slave", "rshared", "shared",
];

/// Every operator-set facet in the raw inspect JSON that the template model
/// does not carry. `compose_moving` suppresses compose's own network aliases,
/// which the move to `bridge` drops deliberately.
pub fn unmodelled(container: &Value, image: &Value, compose_moving: bool) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(hc) = container.get("HostConfig").and_then(Value::as_object) {
        for (k, v) in hc {
            if MODELLED_HOST.contains(&k.as_str()) || IGNORED_HOST.contains(&k.as_str()) {
                continue;
            }
            if !is_zero(v) && !host_default(k, v) {
                out.push(format!("HostConfig.{k}={v}"));
            }
        }
        for b in hc
            .get("Binds")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let opts = b.splitn(3, ':').nth(2).unwrap_or("");
            for o in opts.split(',').filter(|o| !o.is_empty()) {
                if !BIND_OPTS.contains(&o) {
                    out.push(format!("bind option {o:?} in {b:?}"));
                }
            }
        }
        for m in hc
            .get("Mounts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_object)
        {
            for (k, v) in m {
                let ok = match k.as_str() {
                    "Type" | "Source" | "Target" | "ReadOnly" | "Consistency" => true,
                    "BindOptions" => v.as_object().is_none_or(|o| {
                        o.iter().all(|(bk, bv)| bk == "Propagation" || is_zero(bv))
                    }),
                    _ => is_zero(v),
                };
                if !ok {
                    out.push(format!("mount option {k}={v}"));
                }
            }
        }
    }

    let img_cfg = image.get("Config");
    if let Some(cfg) = container.get("Config").and_then(Value::as_object) {
        for (k, v) in cfg {
            if MODELLED_CONFIG.contains(&k.as_str()) || is_zero(v) {
                continue;
            }
            if img_cfg.and_then(|i| i.get(k)) == Some(v) {
                continue;
            }
            out.push(format!("Config.{k}={v}"));
        }
        let image_exposed = img_cfg.and_then(|i| i.get("ExposedPorts"));
        let published = container
            .pointer("/HostConfig/PortBindings")
            .and_then(Value::as_object);
        for p in cfg
            .get("ExposedPorts")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|o| o.keys())
        {
            let in_image = image_exposed.and_then(|e| e.get(p)).is_some();
            let in_published = published.is_some_and(|b| b.contains_key(p));
            if !in_image && !in_published {
                out.push(format!(
                    "exposed port {p} not published and not from the image"
                ));
            }
        }
    }

    if let Some(nets) = container
        .pointer("/NetworkSettings/Networks")
        .and_then(Value::as_object)
    {
        for (net, ep) in nets {
            for key in ["IPAMConfig", "Links", "DriverOpts"] {
                if let Some(v) = ep.get(key).filter(|v| !is_zero(v)) {
                    out.push(format!("network {net} {key}={v}"));
                }
            }
            if !compose_moving && let Some(v) = ep.get("Aliases").filter(|v| !is_zero(v)) {
                out.push(format!("network {net} Aliases={v}"));
            }
        }
    }
    out
}
