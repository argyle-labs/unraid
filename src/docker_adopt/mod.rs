//! `unraid.docker.{status,set_icon,adopt}` — make containers on this Unraid
//! host dockerMan-managed (not "3rd Party" in the Docker tab).
//!
//! The plugin runs on the Unraid host, so these verbs drive the local docker
//! CLI and dockerMan's own PHP renderer and `rebuild_container` script.
//! `adopt` refuses unless the command dockerMan would render from the new
//! template reproduces the live container (the fidelity gate).
//!
//! The mutating verbs set `execute_gated = false` and own their `execute`
//! opt-in so the dry run can return the template, fidelity diff and step list
//! rather than the central gate's generic plan. Opting out of the gate also
//! opts out of its role check, so [`authorize_execute`] requires an admin
//! caller identity before anything is applied.

pub mod host;
pub mod inspect;
pub mod orphans;
pub mod spec;
pub mod template;

use std::path::Path;

use plugin_toolkit::contract::CallerIdentity;
use plugin_toolkit::contract::plan::{ExecutionPlan, PlannedChange};
use plugin_toolkit::lifecycle;
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json;

use inspect::{ContainerInspect, ICON_LABEL, ImageInspect, MANAGED_LABEL, live_spec};
use orphans::ComposeLeftovers;
use spec::{MountKind, MountSpec, RunSpec};
use template::Template;

/// Value of [`MANAGED_LABEL`] on a dockerMan-rendered container.
const MANAGED_BY_DOCKERMAN: &str = "dockerman";

/// Container and repo names: `^[A-Za-z0-9][A-Za-z0-9_.-]*$`.
pub fn validate_name(what: &str, name: &str) -> Result<()> {
    let mut b = name.bytes();
    let ok = b.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-')
        && name.len() <= 128;
    if !ok {
        bail!("invalid {what} '{name}': must match ^[A-Za-z0-9][A-Za-z0-9_.-]*$");
    }
    Ok(())
}

fn validate_icon_base(base: &str) -> Result<()> {
    let ok = (base.starts_with("https://") || base.starts_with("http://"))
        && !base
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "\"'<>`\\".contains(c));
    if !ok {
        bail!("invalid icon_base '{base}': must be an http(s) URL without quotes or spaces");
    }
    Ok(())
}

/// Fail closed: applying changes needs an identified admin caller.
pub fn authorize_execute(tool: &str, caller: Option<&CallerIdentity>) -> Result<()> {
    match caller {
        Some(c) if c.role == "admin" => Ok(()),
        Some(c) => bail!(
            "{tool}: execute requires role 'admin'; caller '{}' has '{}'",
            c.username,
            c.role
        ),
        None => bail!(
            "{tool}: execute refused: the call carries no caller identity, so admin cannot be verified"
        ),
    }
}

fn today() -> String {
    lifecycle::timestamp().chars().take(8).collect()
}

// ── steps ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    Stop,
    CopyVolume {
        volume: String,
        from: String,
        to: String,
    },
    VerifyCopy {
        volume: String,
        from: String,
        to: String,
    },
    BackupTemplate {
        from: String,
        to: String,
    },
    WriteTemplate {
        path: String,
        xml: String,
    },
    AutostartAdd,
    AutostartRemove,
    Rebuild,
    EnsureState {
        running: bool,
    },
    VerifyManaged {
        running: bool,
        icon: Option<String>,
        expect: Option<Box<RunSpec>>,
    },
    ClearIconCache,
    RefreshIcons,
    RemoveVolume {
        volume: String,
    },
    PruneAnonymousVolumes {
        candidates: Vec<String>,
    },
    PruneDanglingImages {
        candidates: Vec<String>,
    },
    RemoveNetwork {
        network: String,
    },
    RetireStack {
        from: String,
        to: String,
    },
}

impl Step {
    pub fn action(&self) -> &'static str {
        match self {
            Step::Stop => "stop",
            Step::CopyVolume { .. } => "copy-volume",
            Step::VerifyCopy { .. } => "verify-copy",
            Step::BackupTemplate { .. } => "backup-template",
            Step::WriteTemplate { .. } => "write-template",
            Step::AutostartAdd => "autostart-add",
            Step::AutostartRemove => "autostart-remove",
            Step::Rebuild => "rebuild",
            Step::EnsureState { .. } => "ensure-state",
            Step::VerifyManaged { .. } => "verify-managed",
            Step::ClearIconCache => "clear-icon-cache",
            Step::RefreshIcons => "refresh-icons",
            Step::RemoveVolume { .. } => "remove-volume",
            Step::PruneAnonymousVolumes { .. } => "prune-anonymous-volumes",
            Step::PruneDanglingImages { .. } => "prune-dangling-images",
            Step::RemoveNetwork { .. } => "remove-network",
            Step::RetireStack { .. } => "retire-stack",
        }
    }

    fn change(&self, name: &str) -> PlannedChange {
        let (target, detail) = match self {
            Step::Stop => (name.to_string(), None),
            Step::CopyVolume { volume, from, to } => {
                (volume.clone(), Some(format!("cp -a {from}/. {to}/")))
            }
            Step::VerifyCopy { volume, from, to } => (
                volume.clone(),
                Some(format!("file count + bytes of {to} == {from}")),
            ),
            Step::BackupTemplate { from, to } => (from.clone(), Some(format!("copy to {to}"))),
            Step::WriteTemplate { path, .. } => (path.clone(), None),
            Step::AutostartAdd | Step::AutostartRemove => {
                (host::AUTOSTART_FILE.to_string(), Some(name.to_string()))
            }
            Step::Rebuild => (
                name.to_string(),
                Some(format!("{} {name}", host::REBUILD_SCRIPT)),
            ),
            Step::EnsureState { running } => (
                name.to_string(),
                Some(if *running { "running" } else { "stopped" }.to_string()),
            ),
            Step::VerifyManaged { icon, .. } => (
                name.to_string(),
                Some(match icon {
                    Some(i) => format!("{MANAGED_LABEL}={MANAGED_BY_DOCKERMAN}, {ICON_LABEL}={i}"),
                    None => format!("{MANAGED_LABEL}={MANAGED_BY_DOCKERMAN}"),
                }),
            ),
            Step::ClearIconCache => (
                format!("{name}-icon.png"),
                Some(host::ICON_CACHES.join(", ")),
            ),
            Step::RefreshIcons => (
                "dockerMan".to_string(),
                Some("DockerTemplates::getAllInfo(true)".to_string()),
            ),
            Step::RemoveVolume { volume } => (
                volume.clone(),
                Some("only once the copy verified and the container runs".to_string()),
            ),
            Step::PruneAnonymousVolumes { candidates } => (
                "unused anonymous volumes".to_string(),
                Some(format!("currently [{}]", candidates.join(", "))),
            ),
            Step::PruneDanglingImages { candidates } => (
                "dangling images".to_string(),
                Some(format!("currently [{}]", candidates.join(", "))),
            ),
            Step::RemoveNetwork { network } => (
                network.clone(),
                Some("only if no container uses it".to_string()),
            ),
            Step::RetireStack { from, to } => (from.clone(), Some(format!("move to {to}"))),
        };
        PlannedChange {
            target,
            action: self.action().to_string(),
            detail,
        }
    }
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StepOutcome {
    pub action: String,
    pub target: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

async fn run_step(step: &Step, name: &str) -> Result<String> {
    match step {
        Step::Stop => host::docker(&["stop", name])
            .await
            .map(|_| "stopped".into()),
        Step::CopyVolume { from, to, .. } => {
            host::copy_tree(from, to).await?;
            Ok(format!("copied to {to}"))
        }
        Step::VerifyCopy { from, to, .. } => {
            let a = host::tree_stats(Path::new(from))?;
            let b = host::tree_stats(Path::new(to))?;
            if a != b {
                bail!(
                    "copy mismatch: {from} has {} entries/{} bytes, {to} has {}/{}",
                    a.0,
                    a.1,
                    b.0,
                    b.1
                );
            }
            Ok(format!("{} entries, {} bytes", a.0, a.1))
        }
        Step::BackupTemplate { from, to } => {
            if Path::new(to).exists() {
                return Ok(format!("{to} already exists; kept"));
            }
            std::fs::copy(from, to).with_context(|| format!("copy {from} to {to}"))?;
            Ok(to.clone())
        }
        Step::WriteTemplate { path, xml } => {
            std::fs::write(path, xml).with_context(|| format!("write {path}"))?;
            Ok(format!("{} bytes", xml.len()))
        }
        Step::AutostartAdd => Ok(if host::autostart_add(name)? {
            "added"
        } else {
            "already present"
        }
        .into()),
        Step::AutostartRemove => Ok(if host::autostart_remove(name)? {
            "removed"
        } else {
            "not present"
        }
        .into()),
        Step::Rebuild => host::rebuild(name).await.map(|o| o.trim().to_string()),
        Step::EnsureState { running } => {
            let now = host::inspect_container(name).await?.state.running;
            match (now, *running) {
                (false, true) => host::docker(&["start", name])
                    .await
                    .map(|_| "started".into()),
                (true, false) => host::docker(&["stop", name])
                    .await
                    .map(|_| "stopped".into()),
                _ => Ok("unchanged".into()),
            }
        }
        Step::VerifyManaged {
            running,
            icon,
            expect,
        } => {
            let c = host::inspect_container(name).await?;
            let managed = c.label(MANAGED_LABEL).unwrap_or_default();
            if managed != MANAGED_BY_DOCKERMAN {
                bail!("{MANAGED_LABEL} is {managed:?}, expected {MANAGED_BY_DOCKERMAN:?}");
            }
            if *running && c.state.status != "running" {
                bail!("container is {}, expected running", c.state.status);
            }
            if let Some(want) = icon {
                let got = c.label(ICON_LABEL).unwrap_or_default();
                if got != want {
                    bail!("{ICON_LABEL} is {got:?}, expected {want:?}");
                }
            }
            if let Some(want) = expect {
                let img = host::inspect_image(&c.image).await?;
                let (got, _) = live_spec(&c, &img);
                let d = spec::diff(want, &got);
                if !d.is_empty() {
                    bail!("recreated container differs: {}", d.join("; "));
                }
            }
            Ok(format!("{MANAGED_LABEL}={managed}, {}", c.state.status))
        }
        Step::ClearIconCache => {
            let removed = host::clear_icon_cache(name)?;
            Ok(format!("removed [{}]", removed.join(", ")))
        }
        Step::RefreshIcons => host::refresh_icons().await.map(|_| "refreshed".into()),
        Step::RemoveVolume { volume } => {
            if !host::inspect_container(name).await?.state.running {
                return Ok(format!("kept {volume}: container is not running"));
            }
            host::docker(&["volume", "rm", volume])
                .await
                .map(|_| format!("removed {volume}"))
        }
        Step::PruneAnonymousVolumes { .. } => {
            let all = host::inspect_all().await?;
            let vols = orphans::removable_volumes(&host::dangling_volumes().await?, &all);
            let mut removed = Vec::new();
            for v in &vols {
                host::docker(&["volume", "rm", v]).await?;
                removed.push(v.clone());
            }
            Ok(format!("removed [{}]", removed.join(", ")))
        }
        Step::PruneDanglingImages { .. } => {
            let mut removed = Vec::new();
            let mut kept = Vec::new();
            for id in host::dangling_images().await? {
                match host::docker(&["image", "rm", &id]).await {
                    Ok(_) => removed.push(id),
                    Err(_) => kept.push(id),
                }
            }
            Ok(format!(
                "removed [{}]; kept (in use) [{}]",
                removed.join(", "),
                kept.join(", ")
            ))
        }
        Step::RemoveNetwork { network } => {
            let users = orphans::network_users(network, &host::inspect_all().await?);
            if !users.is_empty() {
                return Ok(format!("kept {network}: used by [{}]", users.join(", ")));
            }
            host::docker(&["network", "rm", network])
                .await
                .map(|_| format!("removed {network}"))
        }
        Step::RetireStack { from, to } => {
            let binds = orphans::binds_under(Path::new(from), &host::inspect_all().await?);
            if !binds.is_empty() {
                return Ok(format!(
                    "kept {from}: still bind-mounted ({})",
                    binds.into_iter().collect::<Vec<_>>().join(", ")
                ));
            }
            if Path::new(to).exists() {
                bail!("{to} already exists");
            }
            if let Some(parent) = Path::new(to).parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
            std::fs::rename(from, to).with_context(|| format!("move {from} to {to}"))?;
            Ok(format!("moved to {to}"))
        }
    }
}

/// Run `steps` in order. A failed step is an error naming it and what already
/// ran: a partial apply must never read as success.
async fn apply(tool: &str, name: &str, steps: &[Step]) -> Result<Vec<StepOutcome>> {
    let mut done = Vec::new();
    for step in steps {
        let change = step.change(name);
        match run_step(step, name).await {
            Ok(detail) => done.push(StepOutcome {
                action: change.action,
                target: change.target,
                ok: true,
                detail: Some(detail),
            }),
            Err(e) => {
                let applied: Vec<String> = done
                    .iter()
                    .map(|o| format!("{} {}", o.action, o.target))
                    .collect();
                bail!(
                    "{tool} failed at `{} {}`: {e:#}. Already applied: [{}]",
                    change.action,
                    change.target,
                    applied.join("; ")
                );
            }
        }
    }
    Ok(done)
}

// ── adopt planning (pure) ────────────────────────────────────────────────────

/// Host state an adopt is planned against.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub container: ContainerInspect,
    pub image: ImageInspect,
    /// Every container on the host, including `container`.
    pub all: Vec<ContainerInspect>,
    pub dangling_volumes: Vec<String>,
    pub dangling_images: Vec<String>,
    pub existing_template: Option<String>,
    pub autostart: Vec<String>,
    /// `YYYYMMDD`, for backup and retire names.
    pub date: String,
}

#[derive(Debug, Clone)]
pub struct AdoptOpts {
    pub repo: Option<String>,
    pub icon_base: String,
    pub migrate_volumes: bool,
    pub autostart: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    pub volume: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone)]
pub struct AdoptPlan {
    pub template: Template,
    pub template_xml: String,
    /// The spec the recreated container must have.
    pub target: RunSpec,
    /// Live facets the template cannot carry; any entry blocks execute.
    pub unsupported: Vec<String>,
    /// Deliberate differences between live and target.
    pub intended: Vec<String>,
    pub migrations: Vec<Migration>,
    pub compose: Option<ComposeLeftovers>,
    pub autostart: bool,
    pub steps: Vec<Step>,
}

pub fn plan_adopt(s: &Snapshot, o: &AdoptOpts) -> AdoptPlan {
    let c = &s.container;
    let name = c.short_name();
    let (live, unsupported) = live_spec(c, &s.image);
    let mut target = live;
    let mut intended = Vec::new();

    let compose = orphans::compose_leftovers(c, &s.all, &s.date);
    if let Some(net) = compose.as_ref().and_then(|l| l.network.as_deref()) {
        target.network = "bridge".to_string();
        intended.push(format!("network {net} -> bridge"));
    }

    let mut migrations = Vec::new();
    if o.migrate_volumes {
        let vols: Vec<_> = c.volumes().collect();
        let pairs: Vec<(String, String)> = vols
            .iter()
            .map(|m| (m.name.clone().unwrap_or_default(), m.destination.clone()))
            .collect();
        let suffixes = orphans::appdata_suffixes(name, c.compose_project(), &pairs);
        for (m, suffix) in vols.iter().zip(suffixes) {
            let volume = m.name.clone().unwrap_or_default();
            let to = format!("{}/{name}/{suffix}", host::APPDATA);
            let old = target
                .mounts
                .iter()
                .find(|x| {
                    x.kind == MountKind::Volume && x.source == volume && x.target == m.destination
                })
                .cloned();
            if let Some(old) = old {
                target.mounts.remove(&old);
                target.mounts.insert(MountSpec {
                    kind: MountKind::Bind,
                    source: to.clone(),
                    ..old
                });
            }
            intended.push(format!("volume {volume} -> {to}"));
            migrations.push(Migration {
                volume,
                from: m.source.clone(),
                to,
            });
        }
    }

    let icon = match &o.repo {
        Some(repo) => template::icon_url(&o.icon_base, repo),
        None => s
            .existing_template
            .as_deref()
            .and_then(template::extract_icon)
            .or_else(|| c.label(ICON_LABEL).map(str::to_string))
            .unwrap_or_default(),
    };
    let template = Template::from_spec(&target, &icon);
    let template_xml = template.render();

    let was_running = c.state.running;
    let in_autostart = s.autostart.iter().any(|n| n == name);
    let autostart = o.autostart.unwrap_or(in_autostart || was_running);
    let want_running = autostart || was_running;
    let path = template::template_path(name);

    let mut steps = Vec::new();
    if !migrations.is_empty() && was_running {
        steps.push(Step::Stop);
    }
    for m in &migrations {
        steps.push(Step::CopyVolume {
            volume: m.volume.clone(),
            from: m.from.clone(),
            to: m.to.clone(),
        });
        steps.push(Step::VerifyCopy {
            volume: m.volume.clone(),
            from: m.from.clone(),
            to: m.to.clone(),
        });
    }
    if s.existing_template.is_some() {
        steps.push(Step::BackupTemplate {
            from: path.clone(),
            to: template::backup_path(name, &s.date),
        });
    }
    steps.push(Step::WriteTemplate {
        path,
        xml: template_xml.clone(),
    });
    // rebuild_container stops the container afterwards unless it is listed.
    match (autostart, in_autostart) {
        (true, false) => steps.push(Step::AutostartAdd),
        (false, true) => steps.push(Step::AutostartRemove),
        _ => {}
    }
    steps.push(Step::Rebuild);
    steps.push(Step::EnsureState {
        running: want_running,
    });
    steps.push(Step::VerifyManaged {
        running: want_running,
        icon: (!icon.is_empty()).then(|| icon.clone()),
        expect: Some(Box::new(target.clone())),
    });
    if !icon.is_empty() {
        steps.push(Step::ClearIconCache);
        steps.push(Step::RefreshIcons);
    }
    for m in &migrations {
        steps.push(Step::RemoveVolume {
            volume: m.volume.clone(),
        });
    }
    steps.push(Step::PruneAnonymousVolumes {
        candidates: orphans::removable_volumes(&s.dangling_volumes, &s.all),
    });
    steps.push(Step::PruneDanglingImages {
        candidates: s.dangling_images.clone(),
    });
    if let Some(l) = &compose {
        if let Some(net) = &l.network {
            steps.push(Step::RemoveNetwork {
                network: net.clone(),
            });
        }
        if let Some((from, to)) = &l.retire {
            steps.push(Step::RetireStack {
                from: from.display().to_string(),
                to: to.display().to_string(),
            });
        }
    }

    AdoptPlan {
        template,
        template_xml,
        target,
        unsupported,
        intended,
        migrations,
        compose,
        autostart,
        steps,
    }
}

/// Everything that stands between `plan` and a faithful recreate, given the
/// command dockerMan rendered for its template.
pub fn fidelity(plan: &AdoptPlan, rendered: &str) -> Vec<String> {
    let mut out: Vec<String> = plan
        .unsupported
        .iter()
        .map(|u| format!("unsupported: {u}"))
        .collect();
    match spec::parse_command(rendered) {
        Ok(got) => out.extend(spec::diff(&plan.target, &got)),
        Err(e) => out.push(format!("could not parse rendered command: {e}")),
    }
    out
}

// ── tools ────────────────────────────────────────────────────────────────────

fn icon_base(arg: Option<String>) -> Result<String> {
    let base = arg.unwrap_or_else(|| template::DEFAULT_ICON_BASE.to_string());
    validate_icon_base(&base)?;
    Ok(base)
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidDockerStatusArgs {
    /// Base URL orca icons live under, for `orcaIcon` detection.
    #[arg(long)]
    #[serde(default, alias = "icon_base")]
    pub icon_base: Option<String>,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DockerContainerStatus {
    pub name: String,
    pub state: String,
    pub has_template: bool,
    /// Value of `net.unraid.docker.managed` (`dockerman` when Unraid-managed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed: Option<String>,
    /// Template `<Icon>`, falling back to the container's icon label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    pub orca_icon: bool,
    pub autostart: bool,
    /// Docker volumes mounted by the container (stored outside appdata).
    pub volumes_outside_appdata: Vec<String>,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DockerStatusOutput {
    pub containers: Vec<DockerContainerStatus>,
    pub dangling_volumes: usize,
    pub dangling_images: usize,
}

pub fn container_status(
    c: &ContainerInspect,
    template_xml: Option<&str>,
    autostart: &[String],
    icon_base: &str,
) -> DockerContainerStatus {
    let name = c.short_name().to_string();
    let icon = template_xml
        .and_then(template::extract_icon)
        .or_else(|| c.label(ICON_LABEL).map(str::to_string));
    DockerContainerStatus {
        state: c.state.status.clone(),
        has_template: template_xml.is_some(),
        managed: c.label(MANAGED_LABEL).map(str::to_string),
        orca_icon: icon
            .as_deref()
            .is_some_and(|i| template::is_orca_icon(icon_base, i)),
        icon,
        autostart: autostart.contains(&name),
        volumes_outside_appdata: c
            .volumes()
            .filter(|m| !Path::new(&m.source).starts_with(host::APPDATA))
            .filter_map(|m| m.name.clone())
            .collect(),
        name,
    }
}

/// Per-container Unraid adoption state on this host: template, managed label,
/// icon, autostart and docker volumes, plus host-wide dangling counts.
#[orca_tool(domain = "unraid", verb = "docker.status")]
async fn unraid_docker_status(
    args: UnraidDockerStatusArgs,
    _ctx: &ToolCtx,
) -> Result<DockerStatusOutput> {
    let base = icon_base(args.icon_base)?;
    let autostart = host::read_autostart();
    let mut containers: Vec<DockerContainerStatus> = host::inspect_all()
        .await?
        .iter()
        .map(|c| {
            let xml = std::fs::read_to_string(template::template_path(c.short_name())).ok();
            container_status(c, xml.as_deref(), &autostart, &base)
        })
        .collect();
    containers.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(DockerStatusOutput {
        containers,
        dangling_volumes: host::dangling_volumes().await?.len(),
        dangling_images: host::dangling_images().await?.len(),
    })
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DockerChange {
    pub dry_run: bool,
    pub tool: String,
    pub name: String,
    /// True when execute would proceed: no fidelity diff and no blockers.
    pub ready: bool,
    pub template_path: String,
    pub template_xml: String,
    /// The `docker create` command dockerMan renders for `templateXml`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendered_command: Option<String>,
    /// Live vs rendered differences beyond `intendedChanges`. Must be empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fidelity_diff: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intended_changes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// The ordered steps, when `dryRun`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<ExecutionPlan>,
    /// Per-step results, when applied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<StepOutcome>,
}

fn execution_plan<A: Serialize>(
    tool: &str,
    args: &A,
    name: &str,
    summary: String,
    steps: &[Step],
) -> Result<ExecutionPlan> {
    let inputs = serde_json::to_value(args)?;
    Ok(ExecutionPlan::generic(tool, inputs.into())
        .detailed(summary, steps.iter().map(|s| s.change(name)).collect()))
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidDockerSetIconArgs {
    /// Container whose template gets the icon.
    #[arg(long)]
    pub name: String,
    /// argyle-labs repo whose `assets/icon-256.png` becomes the icon.
    #[arg(long)]
    pub repo: String,
    /// Base URL the repo lives under.
    #[arg(long)]
    #[serde(default, alias = "icon_base")]
    pub icon_base: Option<String>,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Point a container's existing Unraid template at an argyle-labs repo icon,
/// rebuild it (keeping its running/stopped state) and refresh both icon caches.
#[orca_tool(
    domain = "unraid",
    verb = "docker.set_icon",
    role = "admin",
    execute_gated = false
)]
async fn unraid_docker_set_icon(
    args: UnraidDockerSetIconArgs,
    ctx: &ToolCtx,
) -> Result<DockerChange> {
    const TOOL: &str = "unraid.docker.set_icon";
    validate_name("container name", &args.name)?;
    validate_name("repo", &args.repo)?;
    let base = icon_base(args.icon_base.clone())?;
    if args.execute {
        authorize_execute(TOOL, ctx.caller().as_ref())?;
    }
    let name = args.name.as_str();
    let path = template::template_path(name);
    let current = std::fs::read_to_string(&path).map_err(|e| {
        anyhow!("{name} has no Unraid template at {path} ({e}); adopt it with unraid.docker.adopt")
    })?;
    let url = template::icon_url(&base, &args.repo);
    let xml = template::set_icon(&current, &url).map_err(|e| anyhow!("{path}: {e}"))?;
    let was_running = host::inspect_container(name).await?.state.running;
    let steps = set_icon_steps(name, &path, &xml, &url, was_running, &today());

    let mut out = DockerChange {
        dry_run: !args.execute,
        tool: TOOL.to_string(),
        name: name.to_string(),
        ready: true,
        template_path: path,
        template_xml: xml,
        rendered_command: None,
        fidelity_diff: Vec::new(),
        intended_changes: vec![format!(
            "icon {} -> {url}",
            template::extract_icon(&current).unwrap_or_else(|| "(none)".to_string())
        )],
        blockers: Vec::new(),
        notes: Vec::new(),
        plan: None,
        steps: Vec::new(),
    };
    if !args.execute {
        out.plan = Some(execution_plan(
            TOOL,
            &args,
            name,
            format!("set {name}'s icon to {url} and rebuild"),
            &steps,
        )?);
        return Ok(out);
    }
    out.steps = apply(TOOL, name, &steps).await?;
    Ok(out)
}

pub fn set_icon_steps(
    name: &str,
    path: &str,
    xml: &str,
    url: &str,
    was_running: bool,
    date: &str,
) -> Vec<Step> {
    vec![
        Step::BackupTemplate {
            from: path.to_string(),
            to: template::backup_path(name, date),
        },
        Step::WriteTemplate {
            path: path.to_string(),
            xml: xml.to_string(),
        },
        Step::Rebuild,
        Step::EnsureState {
            running: was_running,
        },
        Step::VerifyManaged {
            running: was_running,
            icon: Some(url.to_string()),
            expect: None,
        },
        Step::ClearIconCache,
        Step::RefreshIcons,
    ]
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidDockerAdoptArgs {
    /// Container to adopt.
    #[arg(long)]
    pub name: String,
    /// argyle-labs repo whose `assets/icon-256.png` becomes the icon.
    #[arg(long)]
    #[serde(default)]
    pub repo: Option<String>,
    /// Copy each docker volume into `/mnt/user/appdata/<name>/` and mount that
    /// instead; the old volumes are removed once the copy is verified.
    #[arg(long)]
    #[serde(default, alias = "migrate_volumes")]
    pub migrate_volumes: bool,
    /// Start with the array (Unraid autostart). Default: on if the container
    /// is running or already listed.
    #[arg(long)]
    #[serde(default)]
    pub autostart: Option<bool>,
    /// Base URL the repo lives under.
    #[arg(long)]
    #[serde(default, alias = "icon_base")]
    pub icon_base: Option<String>,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Recreate a docker-run or compose container as an Unraid dockerMan
/// container: write `my-<name>.xml`, prove dockerMan's rendered command
/// reproduces the live container, rebuild through `rebuild_container`, then
/// clean up the leftovers. Refuses on any fidelity difference.
#[orca_tool(
    domain = "unraid",
    verb = "docker.adopt",
    role = "admin",
    execute_gated = false
)]
async fn unraid_docker_adopt(args: UnraidDockerAdoptArgs, ctx: &ToolCtx) -> Result<DockerChange> {
    const TOOL: &str = "unraid.docker.adopt";
    validate_name("container name", &args.name)?;
    if let Some(r) = &args.repo {
        validate_name("repo", r)?;
    }
    let base = icon_base(args.icon_base.clone())?;
    if args.execute {
        authorize_execute(TOOL, ctx.caller().as_ref())?;
    }
    let name = args.name.as_str();
    let container = host::inspect_container(name).await?;
    let snapshot = Snapshot {
        image: host::inspect_image(&container.image).await?,
        container,
        all: host::inspect_all().await?,
        dangling_volumes: host::dangling_volumes().await?,
        dangling_images: host::dangling_images().await?,
        existing_template: std::fs::read_to_string(template::template_path(name)).ok(),
        autostart: host::read_autostart(),
        date: today(),
    };
    let plan = plan_adopt(
        &snapshot,
        &AdoptOpts {
            repo: args.repo.clone(),
            icon_base: base,
            migrate_volumes: args.migrate_volumes,
            autostart: args.autostart,
        },
    );

    let mut blockers = Vec::new();
    for m in &plan.migrations {
        if host::is_nonempty_dir(Path::new(&m.to)) {
            blockers.push(format!("{} already has content", m.to));
        }
    }
    let (rendered_command, fidelity_diff) =
        match host::render_command(name, &plan.template_xml).await {
            Ok(cmd) => {
                let d = fidelity(&plan, &cmd);
                (Some(cmd), d)
            }
            Err(e) => {
                blockers.push(format!("dockerMan could not render the template: {e:#}"));
                (None, Vec::new())
            }
        };
    let mut notes = Vec::new();
    if let Some(l) = &plan.compose {
        notes.push(format!(
            "compose project {} is dropped; the container no longer joins its network or \
             resolves other services by name",
            l.project
        ));
        if let Some(why) = &l.keep_reason {
            notes.push(format!("compose stack kept: {why}"));
        }
    }
    notes.push(format!(
        "autostart {}",
        if plan.autostart { "on" } else { "off" }
    ));
    let ready = fidelity_diff.is_empty() && blockers.is_empty();

    let mut out = DockerChange {
        dry_run: !args.execute,
        tool: TOOL.to_string(),
        name: name.to_string(),
        ready,
        template_path: template::template_path(name),
        template_xml: plan.template_xml.clone(),
        rendered_command,
        fidelity_diff,
        intended_changes: plan.intended.clone(),
        blockers,
        notes,
        plan: None,
        steps: Vec::new(),
    };
    if !args.execute {
        let summary = if ready {
            format!("adopt {name} as an Unraid-managed container")
        } else {
            format!("adopt {name}: NOT ready — see fidelityDiff/blockers")
        };
        out.plan = Some(execution_plan(TOOL, &args, name, summary, &plan.steps)?);
        return Ok(out);
    }
    if !ready {
        let mut why = out.blockers.clone();
        why.extend(out.fidelity_diff.iter().cloned());
        bail!("{TOOL}: refusing to execute: {}", why.join("; "));
    }
    out.steps = apply(TOOL, name, &plan.steps).await?;
    Ok(out)
}

#[cfg(test)]
mod tests;
