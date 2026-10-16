use plugin_toolkit::anyhow::{self, Result, anyhow, bail};
use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::contract::unit::{
    ActionDecl, ActionOutcome, DeleteArgs, DetailArgs, ItemOutcome, ItemsOutcome, KindDeclaration,
    ListArgs, UnitDescriptor, UnitId, UnitProvider, UpdateArgs, Verb, VerbArgs, VerbDecl,
    VerbOutcome,
};
use plugin_toolkit::schemars::{JsonSchema, schema_for};
use plugin_toolkit::secrets;
use plugin_toolkit::serde::{Deserialize, Serialize};
use plugin_toolkit::serde_json::{self, Value, json};

use crate::Client;
use crate::authz::require_admin;
use crate::endpoint::{EndpointRow, endpoint_db};
use crate::generated::v7_3_1::docker_containers::DockerContainersDockerContainers as Container;

const KIND: &str = "container";
const MANAGER: &str = "unraid";

const SIMPLE_ACTIONS: &[(&str, &str)] = &[
    ("start", "start"),
    ("stop", "stop"),
    ("pause", "pause"),
    ("unpause", "unpause"),
];
const ACTION_RESTART: &str = "restart";
const ACTION_AUTOSTART: &str = "autostart";
const ACTION_REMOVE: &str = "remove";

const FORCE_ACTIONS: &[&str] = &[
    "stop",
    "pause",
    ACTION_RESTART,
    ACTION_REMOVE,
    ACTION_AUTOSTART,
];

pub(crate) const DEFAULT_PROTECTED: &[&str] = &[
    "orca",
    "orca-server",
    "hydra",
    "gitea",
    "gitea-runner",
    "act_runner",
    "pbs",
    "proxmox-backup-server",
    "zot",
    "adguard",
    "adguardhome",
    "pihole",
    "unbound",
    "bind9",
];

pub(crate) const MAX_AUTOSTART_WAIT: i64 = 3600;

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde", deny_unknown_fields)]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct ActionPayload {
    /// Act on a protected container.
    #[serde(default)]
    pub force: bool,
    /// Return the plan and change nothing. Omitted, applies.
    #[serde(default, rename = "dryRun", alias = "dry_run")]
    pub dry_run: bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde", deny_unknown_fields)]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct AutostartPayload {
    /// Start the container at boot.
    pub enabled: bool,
    /// Disable autostart on a protected container.
    #[serde(default)]
    pub force: bool,
    /// Seconds (0..=3600) to wait after starting it; omitted keeps the current value.
    #[serde(default)]
    pub wait: Option<i64>,
    /// Return the plan and change nothing. Omitted, applies.
    #[serde(default, rename = "dryRun", alias = "dry_run")]
    pub dry_run: bool,
}

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde", deny_unknown_fields)]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct RemovePayload {
    /// Also remove the container's image; refused while another container uses it.
    #[serde(default, rename = "withImage")]
    pub with_image: bool,
    /// Act on a protected container.
    #[serde(default)]
    pub force: bool,
    /// Return the plan and change nothing. Omitted, applies.
    #[serde(default, rename = "dryRun", alias = "dry_run")]
    pub dry_run: bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct ContainerSummary {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    #[serde(rename = "autoStart")]
    pub auto_start: bool,
}

impl From<&Container> for ContainerSummary {
    fn from(c: &Container) -> Self {
        Self {
            id: c.id.clone(),
            name: first_name(&c.names),
            image: c.image.clone(),
            state: format!("{:?}", c.state).to_lowercase(),
            status: c.status.clone(),
            auto_start: c.auto_start,
        }
    }
}

fn first_name(names: &[String]) -> String {
    names
        .first()
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_default()
}

fn bare_id(id: &str) -> &str {
    id.rsplit_once(':').map_or(id, |(_, b)| b)
}

fn server_prefix(id: &str) -> Option<&str> {
    id.rsplit_once(':').map(|(p, _)| p)
}

pub(crate) fn manager_for(endpoint: &str) -> String {
    format!("{MANAGER}@{endpoint}")
}

pub(crate) fn endpoint_of(id: &UnitId) -> Result<&str> {
    id.manager
        .strip_prefix(MANAGER)
        .and_then(|s| s.strip_prefix('@'))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("manager '{}' is not unraid@<endpoint>", id.manager))
}

fn unit_id(endpoint: &str, c: &Container) -> UnitId {
    UnitId {
        manager: manager_for(endpoint),
        kind: KIND.into(),
        id: c.id.clone(),
        name: first_name(&c.names),
    }
}

pub(crate) fn resolve<'a>(containers: &'a [Container], target: &str) -> Result<&'a Container> {
    let target = target.trim();
    if target.is_empty() {
        bail!("no container id or name given");
    }
    if let Some(want) = server_prefix(target) {
        let servers: Vec<&str> = containers
            .iter()
            .filter_map(|c| server_prefix(&c.id))
            .collect();
        if !servers.is_empty() && !servers.contains(&want) {
            bail!("container id '{target}' belongs to another Unraid server than this endpoint");
        }
    }
    if let Some(c) = containers
        .iter()
        .find(|c| c.id == target || bare_id(&c.id) == bare_id(target))
    {
        return Ok(c);
    }
    let named: Vec<&Container> = containers
        .iter()
        .filter(|c| c.names.iter().any(|n| n.trim_start_matches('/') == target))
        .collect();
    match named.as_slice() {
        [c] => Ok(c),
        [] => bail!("no container with id or name '{target}'"),
        _ => bail!("container name '{target}' is ambiguous; pass its id"),
    }
}

fn image_repo(image: &str) -> &str {
    let no_digest = image.split('@').next().unwrap_or(image);
    let last = no_digest.rsplit('/').next().unwrap_or(no_digest);
    last.split(':').next().unwrap_or(last)
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex64_in(text: &str) -> Option<String> {
    text.split(['/', '-', '.', ':', ' '])
        .find(|t| is_hex64(t))
        .map(str::to_string)
}

const RUNTIME_MOUNTS: &[&str] = &["/etc/hostname", "/etc/hosts", "/etc/resolv.conf"];

pub(crate) fn container_id_from_mountinfo(mountinfo: &str) -> Option<String> {
    mountinfo.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(' ').collect();
        let (root, mount_point) = (fields.get(3)?, fields.get(4)?);
        if !RUNTIME_MOUNTS.contains(mount_point) {
            return None;
        }
        let mut dirs = root.rsplit('/').skip(1);
        let mut id = dirs.next()?;
        if id == "userdata" {
            id = dirs.next()?;
        }
        is_hex64(id).then(|| id.to_ascii_lowercase())
    })
}

pub(crate) fn container_id_from_cgroup(cgroup: &str) -> Option<String> {
    cgroup
        .lines()
        .filter_map(|line| line.splitn(3, ':').nth(2))
        .find_map(hex64_in)
}

pub(crate) fn own_container_id_from(
    mountinfo: Option<&str>,
    cgroup: Option<&str>,
) -> Option<String> {
    cgroup
        .and_then(container_id_from_cgroup)
        .or_else(|| mountinfo.and_then(container_id_from_mountinfo))
}

fn own_container_id() -> Option<String> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok();
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok();
    own_container_id_from(mountinfo.as_deref(), cgroup.as_deref())
}

pub(crate) fn is_orca(c: &Container, own_id: Option<&str>) -> bool {
    let own = own_id.is_some_and(|id| bare_id(&c.id).eq_ignore_ascii_case(id));
    let named = c
        .names
        .iter()
        .any(|n| n.trim_start_matches('/').eq_ignore_ascii_case("orca"));
    let repo = image_repo(&c.image);
    let image = repo.eq_ignore_ascii_case("orca") || repo.eq_ignore_ascii_case("orca-server");
    own || named || image
}

fn refuse_orca(c: &Container) -> Result<()> {
    if is_orca(c, own_container_id().as_deref()) {
        bail!(
            "refusing to act on '{}' ({}): it is orca's own container",
            first_name(&c.names),
            c.id
        );
    }
    Ok(())
}

fn protected_secret(endpoint: &str) -> String {
    secrets::scoped_name(MANAGER, endpoint, "protected")
}

pub(crate) fn protected_set(extra: Option<&str>) -> Vec<String> {
    DEFAULT_PROTECTED
        .iter()
        .map(|s| s.to_string())
        .chain(
            extra
                .unwrap_or("")
                .split([',', '\n'])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        )
        .collect()
}

fn endpoint_protected(endpoint: &str) -> Result<Vec<String>> {
    let extra = secrets::get(&protected_secret(endpoint)).map_err(|e| {
        anyhow!("cannot read the protected list for endpoint '{endpoint}'; refusing to act: {e}")
    })?;
    Ok(protected_set(extra.as_deref()))
}

fn image_path(image: &str) -> &str {
    let no_digest = image.split('@').next().unwrap_or(image);
    match no_digest.rsplit_once(':') {
        Some((path, tag)) if !tag.contains('/') => path,
        _ => no_digest,
    }
}

fn protects(p: &str, c: &Container) -> bool {
    let id_prefix = p.len() >= 12
        && p.bytes().all(|b| b.is_ascii_hexdigit())
        && bare_id(&c.id)
            .to_ascii_lowercase()
            .starts_with(&p.to_ascii_lowercase());
    let image = if p.contains('/') {
        image_path(&c.image).eq_ignore_ascii_case(p)
    } else {
        image_repo(&c.image).eq_ignore_ascii_case(p)
    };
    c.id.eq_ignore_ascii_case(p)
        || id_prefix
        || image
        || c.names
            .iter()
            .any(|n| n.trim_start_matches('/').eq_ignore_ascii_case(p))
}

pub(crate) fn protected_match(c: &Container, protected: &[String]) -> Option<String> {
    protected.iter().find(|p| protects(p, c)).cloned()
}

pub(crate) fn unmatched_protected<'a>(
    containers: &[Container],
    protected: &'a [String],
) -> Vec<&'a str> {
    protected
        .iter()
        .filter(|p| !DEFAULT_PROTECTED.contains(&p.as_str()))
        .filter(|p| !containers.iter().any(|c| protects(p, c)))
        .map(String::as_str)
        .collect()
}

fn warn_unmatched(endpoint: &str, containers: &[Container], protected: &[String]) {
    for p in unmatched_protected(containers, protected) {
        plugin_toolkit::tracing::warn!(
            endpoint = %endpoint,
            entry = %p,
            "unraid protected entry matches no container"
        );
    }
}

fn is_stopped(c: &Container) -> bool {
    matches!(
        c.state,
        crate::generated::v7_3_1::docker_containers::ContainerState::EXITED
    )
}

fn state_of(c: &Container) -> String {
    format!("{:?}", c.state).to_lowercase()
}

type EndpointLocks =
    std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>;

fn autostart_lock(endpoint: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    static LOCKS: std::sync::OnceLock<EndpointLocks> = std::sync::OnceLock::new();
    LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(endpoint.to_string())
        .or_default()
        .clone()
}

pub(crate) const AUTOSTART_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AutostartVerdict {
    Applied,
    OthersChanged(Vec<String>),
    NotApplied,
}

#[derive(Debug, PartialEq, Eq)]
struct AutostartState {
    auto_start: bool,
    wait: Option<i64>,
    rank: Option<usize>,
}

fn sent_states(entries: &[Value]) -> Vec<(String, AutostartState)> {
    let mut rank = 0;
    entries
        .iter()
        .map(|e| {
            let auto_start = e["autoStart"] == true;
            let state = AutostartState {
                auto_start,
                wait: e["wait"].as_i64(),
                rank: auto_start.then_some(rank),
            };
            rank += usize::from(auto_start);
            (e["id"].as_str().unwrap_or_default().to_string(), state)
        })
        .collect()
}

fn read_states(containers: &[Container]) -> Vec<(String, AutostartState)> {
    let mut enabled: Vec<&Container> = containers.iter().filter(|c| c.auto_start).collect();
    enabled.sort_by_key(|c| c.auto_start_order.unwrap_or(i64::MAX));
    containers
        .iter()
        .map(|c| {
            let rank = c
                .auto_start_order
                .and_then(|_| enabled.iter().position(|e| e.id == c.id));
            let state = AutostartState {
                auto_start: c.auto_start,
                wait: c.auto_start_wait,
                rank,
            };
            (c.id.clone(), state)
        })
        .collect()
}

fn landed(sent: &AutostartState, read: &AutostartState) -> bool {
    sent.auto_start == read.auto_start
        && (sent.wait.is_none() || sent.wait == read.wait)
        && (read.rank.is_none() || sent.rank == read.rank)
}

pub(crate) fn verify_autostart(
    entries: &[Value],
    after: &[Container],
    target: &str,
) -> AutostartVerdict {
    let sent = sent_states(entries);
    let read = read_states(after);
    let read_of = |id: &str| read.iter().find(|(i, _)| i == id).map(|(_, s)| s);
    let name_of = |id: &str| {
        after
            .iter()
            .find(|c| c.id == id)
            .map(|c| first_name(&c.names))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| id.to_string())
    };
    let ours = sent.iter().find(|(id, _)| id == target);
    if !ours.is_some_and(|(id, s)| read_of(id).is_some_and(|r| landed(s, r))) {
        return AutostartVerdict::NotApplied;
    }
    let mut others: Vec<String> = sent
        .iter()
        .filter(|(id, _)| id != target)
        .filter(|(id, s)| !read_of(id).is_some_and(|r| landed(s, r)))
        .map(|(id, _)| name_of(id))
        .chain(
            read.iter()
                .filter(|(id, _)| !sent.iter().any(|(s, _)| s == id))
                .map(|(id, _)| name_of(id)),
        )
        .collect();
    others.sort();
    if others.is_empty() {
        AutostartVerdict::Applied
    } else {
        AutostartVerdict::OthersChanged(others)
    }
}

pub(crate) async fn write_autostart(
    client: &Client,
    endpoint: &str,
    planned: &[Container],
    entries: &[Value],
    target: &str,
    limit: std::time::Duration,
) -> Result<AutostartVerdict> {
    let section = async {
        let lock = autostart_lock(endpoint);
        let _held = lock.lock().await;
        let fresh = containers(client).await?;
        if autostart_snapshot(&fresh) != autostart_snapshot(planned) {
            bail!("autostart configuration changed while planning; nothing was written, retry");
        }
        let data = mutate(client, AUTOSTART_DOCUMENT, json!({ "entries": entries })).await?;
        expect_true(&data, "updateAutostartConfiguration")?;
        let after = containers(client).await?;
        Ok(verify_autostart(entries, &after, target))
    };
    tokio::time::timeout(limit, section).await.map_err(|_| {
        anyhow!(
            "autostart update on endpoint '{endpoint}' timed out after {}s; the lock was released \
             and the write may or may not have landed, re-check the configuration before retrying",
            limit.as_secs()
        )
    })?
}

fn require_force(action: &str, protected_by: Option<&str>, force: bool) -> Result<()> {
    match protected_by {
        Some(p) if FORCE_ACTIONS.contains(&action) && !force => {
            bail!("container is protected (matches '{p}'); {action} requires {{\"force\": true}}")
        }
        _ => Ok(()),
    }
}

fn remove_guards(protected_by: Option<&str>, c: &Container) -> Vec<String> {
    protected_by
        .map(|p| format!("protected (matches '{p}')"))
        .into_iter()
        .chain((!is_stopped(c)).then(|| format!("running (state={})", state_of(c))))
        .collect()
}

fn protection_note(protected_by: Option<&str>) -> String {
    protected_by
        .map(|p| format!("; protected (matches '{p}'), force required"))
        .unwrap_or_default()
}

pub(crate) fn image_sharers<'a>(
    containers: &'a [Container],
    target: &Container,
) -> Vec<&'a Container> {
    containers
        .iter()
        .filter(|c| c.id != target.id)
        .filter(|c| {
            image_path(&c.image).eq_ignore_ascii_case(image_path(&target.image))
                || (!target.image_id.is_empty() && c.image_id == target.image_id)
        })
        .collect()
}

fn names_of(cs: &[&Container]) -> String {
    cs.iter()
        .map(|c| first_name(&c.names))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn simple_document(field: &str) -> String {
    format!(
        "mutation DockerContainerAction($id: PrefixedID!) {{ docker {{ {field}(id: $id) {{ id state }} }} }}"
    )
}

pub(crate) const REMOVE_DOCUMENT: &str = "mutation DockerRemoveContainer($id: PrefixedID!, $withImage: Boolean) { docker { removeContainer(id: $id, withImage: $withImage) } }";

pub(crate) const AUTOSTART_DOCUMENT: &str = "mutation DockerAutostart($entries: [DockerAutostartEntryInput!]!) { docker { updateAutostartConfiguration(entries: $entries) } }";

type AutostartRow = (String, bool, Option<i64>, Option<i64>);

pub(crate) fn autostart_snapshot(containers: &[Container]) -> Vec<AutostartRow> {
    let mut rows: Vec<AutostartRow> = containers
        .iter()
        .map(|c| {
            (
                c.id.clone(),
                c.auto_start,
                c.auto_start_order,
                c.auto_start_wait,
            )
        })
        .collect();
    rows.sort();
    rows
}

pub(crate) fn autostart_entries(
    containers: &[Container],
    target: &str,
    enabled: bool,
    wait: Option<i64>,
) -> Result<Vec<Value>> {
    if containers.is_empty() {
        bail!("refusing to rewrite autostart from an empty container list");
    }
    let current = containers.iter().filter(|c| c.auto_start).count();
    let mut ordered: Vec<&Container> = containers.iter().collect();
    ordered.sort_by_key(|c| c.auto_start_order.unwrap_or(i64::MAX));
    let entries: Vec<Value> = ordered
        .into_iter()
        .map(|c| {
            let is_target = c.id == target;
            let auto = if is_target { enabled } else { c.auto_start };
            let wait = if is_target {
                wait.or(c.auto_start_wait)
            } else {
                c.auto_start_wait
            };
            let mut e = json!({ "id": c.id, "autoStart": auto });
            if let Some(w) = wait {
                e["wait"] = json!(w);
            }
            e
        })
        .collect();
    let kept = entries.iter().filter(|e| e["autoStart"] == true).count();
    let target_was_on = containers.iter().any(|c| c.id == target && c.auto_start);
    let floor = current - usize::from(target_was_on && !enabled);
    if kept < floor {
        bail!(
            "autostart entries would drop {} container(s) from autostart",
            floor - kept
        );
    }
    Ok(entries)
}

fn parse_payload<T: Default + for<'de> Deserialize<'de>>(
    action: &str,
    payload: Option<&str>,
) -> Result<T> {
    match payload.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(T::default()),
        Some(raw) => serde_json::from_str(raw).map_err(|e| anyhow!("{action} payload: {e}")),
    }
}

fn plan(id: UnitId, plan: String) -> VerbOutcome {
    let body = json!({
        "dryRun": true,
        "plan": plan,
        "howToExecute": "re-invoke without `dryRun` in the payload",
    });
    VerbOutcome::Item(ItemOutcome::new(id, body.to_string()))
}

fn changed(message: String) -> VerbOutcome {
    VerbOutcome::Action(ActionOutcome {
        changed: true,
        message,
    })
}

async fn containers(client: &Client) -> Result<Vec<Container>> {
    Ok(client.docker_containers().await?.docker.containers)
}

async fn mutate(client: &Client, document: &str, variables: Value) -> Result<Value> {
    Ok(client.mutate_raw(document, variables).await?)
}

fn expect_container(data: &Value, field: &str) -> Result<()> {
    if data["docker"][field]["id"].is_string() {
        Ok(())
    } else {
        bail!("unexpected response to docker.{field}: missing docker.{field}.id")
    }
}

fn expect_true(data: &Value, field: &str) -> Result<()> {
    match data["docker"][field].as_bool() {
        Some(true) => Ok(()),
        Some(false) => bail!("Unraid reported docker.{field} did not succeed"),
        None => bail!("unexpected response to docker.{field}: docker.{field} is not a boolean"),
    }
}

pub(crate) async fn update_with(
    client: &Client,
    endpoint: &str,
    protected: &[String],
    args: UpdateArgs,
) -> Result<VerbOutcome> {
    let all = containers(client).await?;
    let c = resolve(&all, &args.id.id)?;
    refuse_orca(c)?;
    let id = unit_id(endpoint, c);
    let name = id.name.clone();
    let action = args.action.as_str();
    let payload = args.payload.as_deref();
    warn_unmatched(endpoint, &all, protected);
    let protected_by = protected_match(c, protected);
    let note = protection_note(protected_by.as_deref());
    if let Some((_, field)) = SIMPLE_ACTIONS.iter().find(|(a, _)| *a == action) {
        let p: ActionPayload = parse_payload(action, payload)?;
        if p.dry_run {
            return Ok(plan(
                id,
                format!("docker.{field} container '{name}' ({}){note}", c.id),
            ));
        }
        require_force(action, protected_by.as_deref(), p.force)?;
        let data = mutate(client, &simple_document(field), json!({ "id": c.id })).await?;
        expect_container(&data, field)?;
        return Ok(changed(format!("{action} {name}")));
    }
    match action {
        ACTION_RESTART => {
            let p: ActionPayload = parse_payload(action, payload)?;
            if p.dry_run {
                return Ok(plan(
                    id,
                    format!(
                        "docker.stop then docker.start container '{name}' ({}){note}",
                        c.id
                    ),
                ));
            }
            require_force(action, protected_by.as_deref(), p.force)?;
            for field in ["stop", "start"] {
                let data = mutate(client, &simple_document(field), json!({ "id": c.id })).await?;
                expect_container(&data, field)?;
            }
            Ok(changed(format!("restart {name}")))
        }
        ACTION_AUTOSTART => {
            let raw = payload
                .ok_or_else(|| anyhow!("autostart requires a payload {{\"enabled\": bool}}"))?;
            let p: AutostartPayload =
                serde_json::from_str(raw).map_err(|e| anyhow!("autostart payload: {e}"))?;
            if let Some(w) = p.wait
                && !(0..=MAX_AUTOSTART_WAIT).contains(&w)
            {
                bail!("autostart wait must be 0..={MAX_AUTOSTART_WAIT} seconds, got {w}");
            }
            let entries = autostart_entries(&all, &c.id, p.enabled, p.wait)?;
            let gated_by = protected_by
                .as_deref()
                .filter(|_| c.auto_start && !p.enabled);
            let force_note = match gated_by {
                Some(g) if p.force => format!("; force overrides protected (matches '{g}')"),
                Some(g) => format!(
                    "; protected (matches '{g}'), disabling autostart requires {{\"force\": true}}"
                ),
                None => String::new(),
            };
            if p.dry_run {
                return Ok(plan(
                    id,
                    format!(
                        "docker.updateAutostartConfiguration: '{name}' autoStart {} -> {}, {} entries rewritten{force_note}",
                        c.auto_start,
                        p.enabled,
                        entries.len()
                    ),
                ));
            }
            require_force(ACTION_AUTOSTART, gated_by, p.force)?;
            match write_autostart(client, endpoint, &all, &entries, &c.id, AUTOSTART_TIMEOUT)
                .await?
            {
                AutostartVerdict::Applied => {
                    Ok(changed(format!("autostart {name} = {}", p.enabled)))
                }
                AutostartVerdict::OthersChanged(others) => Ok(changed(format!(
                    "autostart {name} = {} applied, but other containers changed concurrently: {}",
                    p.enabled,
                    others.join(", ")
                ))),
                AutostartVerdict::NotApplied => bail!(
                    "autostart for '{name}' was not applied: the configuration read back does not \
                     match what was sent (another writer overwrote it); retrying is safe"
                ),
            }
        }
        ACTION_REMOVE => {
            let p: RemovePayload = parse_payload(action, payload)?;
            let sharers = image_sharers(&all, c);
            let shared = if p.with_image && c.image_id.is_empty() {
                "; withImage refused: Unraid reported no imageId".to_string()
            } else if p.with_image && !sharers.is_empty() {
                format!(
                    "; withImage refused: image also used by {}",
                    names_of(&sharers)
                )
            } else {
                String::new()
            };
            let state = state_of(c);
            let guards = remove_guards(protected_by.as_deref(), c);
            let guard_note = match (guards.is_empty(), p.force) {
                (true, _) => String::new(),
                (false, true) => format!("; force overrides: {}", guards.join(", ")),
                (false, false) => format!("; force required by: {}", guards.join(", ")),
            };
            if p.dry_run {
                return Ok(plan(
                    id,
                    format!(
                        "docker.removeContainer '{name}' ({}), state={state}, withImage={}{shared}{guard_note}",
                        c.id, p.with_image
                    ),
                ));
            }
            if !guards.is_empty() && !p.force {
                bail!(
                    "refusing to remove '{name}': {}; pass {{\"force\": true}} to override {}",
                    guards.join(", "),
                    if guards.len() > 1 { "both" } else { "it" }
                );
            }
            if !shared.is_empty() {
                bail!("refusing withImage for '{name}'{shared}");
            }
            let data = mutate(
                client,
                REMOVE_DOCUMENT,
                json!({ "id": c.id, "withImage": p.with_image }),
            )
            .await?;
            expect_true(&data, "removeContainer")?;
            Ok(changed(format!("removed {name}")))
        }
        other => bail!("unknown container update action: {other}"),
    }
}

pub(crate) async fn delete_with(
    client: &Client,
    endpoint: &str,
    protected: &[String],
    args: DeleteArgs,
) -> Result<VerbOutcome> {
    let all = containers(client).await?;
    let c = resolve(&all, &args.id.id)?;
    refuse_orca(c)?;
    let id = unit_id(endpoint, c);
    warn_unmatched(endpoint, &all, protected);
    let note = protection_note(protected_match(c, protected).as_deref());
    let text = format!(
        "docker.removeContainer '{}' ({}); apply with update action={ACTION_REMOVE}{note}",
        id.name, c.id
    );
    Ok(plan(id, text))
}

pub(crate) async fn detail_with(
    client: &Client,
    endpoint: &str,
    args: DetailArgs,
) -> Result<VerbOutcome> {
    let all = containers(client).await?;
    let c = resolve(&all, &args.id.id)?;
    Ok(VerbOutcome::Item(ItemOutcome::new(
        unit_id(endpoint, c),
        serde_json::to_string(&ContainerSummary::from(c))?,
    )))
}

pub(crate) async fn items_with(client: &Client, endpoint: &str) -> Result<Vec<ItemOutcome>> {
    Ok(containers(client)
        .await?
        .iter()
        .map(|c| {
            ItemOutcome::new(
                unit_id(endpoint, c),
                serde_json::to_string(&ContainerSummary::from(c)).unwrap_or_default(),
            )
        })
        .collect())
}

async fn client_for(endpoint: &str) -> Result<Client> {
    let row: EndpointRow = endpoint_db::get(endpoint)?
        .ok_or_else(|| anyhow!("no unraid endpoint named `{endpoint}`"))?;
    Ok(Client::new(crate::endpoint::resolve_config(&row).await?))
}

async fn enabled_endpoints() -> Result<Vec<String>> {
    Ok(endpoint_db::list()?
        .into_iter()
        .filter(|e| e.enabled)
        .map(|e| e.name)
        .collect())
}

pub struct UnraidUnitProvider;

impl UnraidUnitProvider {
    async fn list(&self, args: ListArgs) -> Result<VerbOutcome> {
        let mut items = Vec::new();
        if args.query.kind.as_deref().is_none_or(|k| k == KIND) {
            for ep in enabled_endpoints().await? {
                let got = match client_for(&ep).await {
                    Ok(client) => items_with(&client, &ep).await,
                    Err(e) => Err(e),
                };
                match got {
                    Ok(mut got) => items.append(&mut got),
                    Err(e) => plugin_toolkit::tracing::warn!(
                        endpoint = %ep,
                        error = %format!("{e:#}"),
                        "unraid container list: endpoint failed"
                    ),
                }
            }
        }
        let total = items.len() as u64;
        Ok(VerbOutcome::Items(ItemsOutcome {
            items,
            total: Some(total),
        }))
    }

    async fn update(&self, args: UpdateArgs) -> Result<VerbOutcome> {
        require_admin("unraid container update", args.caller.as_ref())?;
        let endpoint = endpoint_of(&args.id)?.to_string();
        let client = client_for(&endpoint).await?;
        update_with(&client, &endpoint, &endpoint_protected(&endpoint)?, args).await
    }

    async fn delete(&self, args: DeleteArgs) -> Result<VerbOutcome> {
        require_admin("unraid container delete", args.caller.as_ref())?;
        let endpoint = endpoint_of(&args.id)?.to_string();
        let client = client_for(&endpoint).await?;
        delete_with(&client, &endpoint, &endpoint_protected(&endpoint)?, args).await
    }

    async fn detail(&self, args: DetailArgs) -> Result<VerbOutcome> {
        let endpoint = endpoint_of(&args.id)?.to_string();
        let client = client_for(&endpoint).await?;
        detail_with(&client, &endpoint, args).await
    }
}

fn update_actions() -> Vec<ActionDecl> {
    let mut out: Vec<ActionDecl> = SIMPLE_ACTIONS
        .iter()
        .map(|(a, _)| *a)
        .chain([ACTION_RESTART])
        .map(|a| ActionDecl {
            action: a.into(),
            payload_schema: Some(schema_for!(ActionPayload)),
            response_schema: None,
        })
        .collect();
    out.push(ActionDecl {
        action: ACTION_AUTOSTART.into(),
        payload_schema: Some(schema_for!(AutostartPayload)),
        response_schema: None,
    });
    out.push(ActionDecl {
        action: ACTION_REMOVE.into(),
        payload_schema: Some(schema_for!(RemovePayload)),
        response_schema: None,
    });
    out
}

impl UnitProvider for UnraidUnitProvider {
    fn name(&self) -> &str {
        MANAGER
    }

    fn declarations(&self) -> Vec<KindDeclaration> {
        vec![KindDeclaration {
            kind: KIND.into(),
            backup_spec: None,
            verbs: vec![
                VerbDecl::list(),
                VerbDecl::detail(),
                VerbDecl {
                    verb: Verb::Update,
                    query_schema: None,
                    actions: update_actions(),
                },
                VerbDecl {
                    verb: Verb::Delete,
                    query_schema: None,
                    actions: vec![],
                },
            ],
        }]
    }

    fn units(&self) -> BoxFuture<'_, Result<Vec<UnitDescriptor>>> {
        Box::pin(async move {
            let VerbOutcome::Items(items) = self.list(ListArgs::default()).await? else {
                return Ok(Vec::new());
            };
            Ok(items
                .items
                .into_iter()
                .map(|i| UnitDescriptor {
                    id: i.id,
                    verbs: vec![Verb::List, Verb::Detail, Verb::Update, Verb::Delete],
                    parent: None,
                })
                .collect())
        })
    }

    fn invoke(&self, args: VerbArgs) -> BoxFuture<'_, Result<VerbOutcome>> {
        Box::pin(async move {
            match args {
                VerbArgs::List(a) => self.list(a).await,
                VerbArgs::Detail(a) => self.detail(a).await,
                VerbArgs::Update(a) => self.update(a).await,
                VerbArgs::Delete(a) => self.delete(a).await,
                VerbArgs::Create(_) => Err(anyhow::anyhow!(
                    "unraid containers are created from Unraid templates; create is unsupported"
                )),
                VerbArgs::Upsert(_) => Err(anyhow::anyhow!(
                    "upsert is unsupported for unraid containers"
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests;
