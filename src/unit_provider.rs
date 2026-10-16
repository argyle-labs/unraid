use plugin_toolkit::anyhow::{self, Result, anyhow, bail};
use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::contract::unit::{
    ActionDecl, ActionOutcome, DeleteArgs, DetailArgs, ItemOutcome, ItemsOutcome, KindDeclaration,
    ListArgs, UnitDescriptor, UnitId, UnitProvider, UpdateArgs, Verb, VerbArgs, VerbDecl,
    VerbOutcome,
};
use plugin_toolkit::schemars::{JsonSchema, schema_for};
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

#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde", deny_unknown_fields)]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct DryRunOptIn {
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
    /// Seconds to wait after starting it; omitted keeps the current value.
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
    /// Also remove the container's image.
    #[serde(default, rename = "withImage")]
    pub with_image: bool,
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

pub(crate) fn is_orca(c: &Container, hostname: Option<&str>) -> bool {
    let named = c
        .names
        .iter()
        .any(|n| n.trim_start_matches('/').eq_ignore_ascii_case("orca"));
    let repo = image_repo(&c.image);
    let image = repo.eq_ignore_ascii_case("orca") || repo.eq_ignore_ascii_case("orca-server");
    let own = hostname
        .filter(|h| h.len() >= 12 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .is_some_and(|h| bare_id(&c.id).starts_with(h));
    named || image || own
}

fn refuse_orca(c: &Container) -> Result<()> {
    let hostname = std::env::var("HOSTNAME").ok();
    if is_orca(c, hostname.as_deref()) {
        bail!(
            "refusing to act on '{}' ({}): it is orca's own container",
            first_name(&c.names),
            c.id
        );
    }
    Ok(())
}

pub(crate) fn simple_document(field: &str) -> String {
    format!(
        "mutation DockerContainerAction($id: PrefixedID!) {{ docker {{ {field}(id: $id) {{ id state }} }} }}"
    )
}

pub(crate) const REMOVE_DOCUMENT: &str = "mutation DockerRemoveContainer($id: PrefixedID!, $withImage: Boolean) { docker { removeContainer(id: $id, withImage: $withImage) } }";

pub(crate) const AUTOSTART_DOCUMENT: &str = "mutation DockerAutostart($entries: [DockerAutostartEntryInput!]!) { docker { updateAutostartConfiguration(entries: $entries) } }";

pub(crate) fn autostart_entries(
    containers: &[Container],
    target: &str,
    enabled: bool,
    wait: Option<i64>,
) -> Vec<Value> {
    let mut ordered: Vec<&Container> = containers.iter().collect();
    ordered.sort_by_key(|c| c.auto_start_order.unwrap_or(i64::MAX));
    ordered
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
        .collect()
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
        bail!("unexpected response to docker.{field}: {data}")
    }
}

fn expect_true(data: &Value, field: &str) -> Result<()> {
    match data["docker"][field].as_bool() {
        Some(true) => Ok(()),
        Some(false) => bail!("Unraid reported docker.{field} did not succeed"),
        None => bail!("unexpected response to docker.{field}: {data}"),
    }
}

pub(crate) async fn update_with(
    client: &Client,
    endpoint: &str,
    args: UpdateArgs,
) -> Result<VerbOutcome> {
    let all = containers(client).await?;
    let c = resolve(&all, &args.id.id)?;
    refuse_orca(c)?;
    let id = unit_id(endpoint, c);
    let name = id.name.clone();
    let action = args.action.as_str();
    let payload = args.payload.as_deref();
    if let Some((_, field)) = SIMPLE_ACTIONS.iter().find(|(a, _)| *a == action) {
        let opt: DryRunOptIn = parse_payload(action, payload)?;
        if opt.dry_run {
            return Ok(plan(
                id,
                format!("docker.{field} container '{name}' ({})", c.id),
            ));
        }
        let data = mutate(client, &simple_document(field), json!({ "id": c.id })).await?;
        expect_container(&data, field)?;
        return Ok(changed(format!("{action} {name}")));
    }
    match action {
        ACTION_RESTART => {
            let opt: DryRunOptIn = parse_payload(action, payload)?;
            if opt.dry_run {
                return Ok(plan(
                    id,
                    format!(
                        "docker.stop then docker.start container '{name}' ({})",
                        c.id
                    ),
                ));
            }
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
            if p.dry_run {
                return Ok(plan(
                    id,
                    format!(
                        "docker.updateAutostartConfiguration: '{name}' autoStart {} -> {}",
                        c.auto_start, p.enabled
                    ),
                ));
            }
            let entries = autostart_entries(&all, &c.id, p.enabled, p.wait);
            let data = mutate(client, AUTOSTART_DOCUMENT, json!({ "entries": entries })).await?;
            expect_true(&data, "updateAutostartConfiguration")?;
            Ok(changed(format!("autostart {name} = {}", p.enabled)))
        }
        ACTION_REMOVE => {
            let p: RemovePayload = parse_payload(action, payload)?;
            if p.dry_run {
                return Ok(plan(
                    id,
                    format!(
                        "docker.removeContainer '{name}' ({}), withImage={}",
                        c.id, p.with_image
                    ),
                ));
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
    args: DeleteArgs,
) -> Result<VerbOutcome> {
    let all = containers(client).await?;
    let c = resolve(&all, &args.id.id)?;
    refuse_orca(c)?;
    let id = unit_id(endpoint, c);
    let text = format!(
        "docker.removeContainer '{}' ({}); apply with update action={ACTION_REMOVE}",
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
        update_with(&client, &endpoint, args).await
    }

    async fn delete(&self, args: DeleteArgs) -> Result<VerbOutcome> {
        require_admin("unraid container delete", args.caller.as_ref())?;
        let endpoint = endpoint_of(&args.id)?.to_string();
        let client = client_for(&endpoint).await?;
        delete_with(&client, &endpoint, args).await
    }

    async fn detail(&self, args: DetailArgs) -> Result<VerbOutcome> {
        let endpoint = endpoint_of(&args.id)?.to_string();
        let client = client_for(&endpoint).await?;
        detail_with(&client, &endpoint, args).await
    }
}

fn update_actions() -> Vec<ActionDecl> {
    let opt_in = || Some(schema_for!(DryRunOptIn));
    let mut out: Vec<ActionDecl> = SIMPLE_ACTIONS
        .iter()
        .map(|(a, _)| *a)
        .chain([ACTION_RESTART])
        .map(|a| ActionDecl {
            action: a.into(),
            payload_schema: opt_in(),
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
