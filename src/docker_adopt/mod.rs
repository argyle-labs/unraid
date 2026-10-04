//! `unraid.docker.{status,set_icon,adopt}` — make containers on this Unraid
//! host dockerMan-managed (not "3rd Party" in the Docker tab).
//!
//! The plugin runs on the Unraid host, so these verbs drive the local docker
//! CLI and dockerMan's own PHP renderer. Effects that need root (templates on
//! `/boot`, the autostart file, `rebuild_container`, volume copies) go through
//! [`privileged`]; docker-only steps run unprivileged.
//!
//! `adopt` and `set_icon` refuse unless the command dockerMan renders from
//! the template reproduces the live container (the fidelity gate): every
//! difference is either an intended consequence of moving under dockerMan
//! (reported in `intendedChanges`) or blocks execute. Secret-looking env
//! values are masked in everything returned.
//!
//! The mutating verbs set `execute_gated = false` and own their `execute`
//! opt-in so the dry run can return the template, fidelity diff and step list
//! rather than the central gate's generic plan. Opting out of the gate also
//! opts out of its role check, so [`authorize_execute`] requires an admin
//! caller identity before anything is applied.

pub mod host;
pub mod inspect;
pub mod orphans;
pub mod privileged;
pub mod redact;
pub mod safefs;
pub mod spec;
pub mod template;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use plugin_toolkit::contract::CallerIdentity;
use plugin_toolkit::contract::plan::{ExecutionPlan, PlannedChange};
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{self, Value};

use host::HostOps;
use inspect::{
    ContainerInspect, ICON_LABEL, ImageInspect, MANAGED_LABEL, VolumeInspect, live_spec,
};
use orphans::ComposeLeftovers;
use privileged::{PrivilegedOp, PrivilegedRunner};
use redact::Redactor;
use spec::{Delta, DiffMode, MountKind, MountSpec, RunSpec};
use template::Template;

/// Value of [`MANAGED_LABEL`] on a dockerMan-rendered container.
const MANAGED_BY_DOCKERMAN: &str = "dockerman";

/// Container, volume and repo names: `^[A-Za-z0-9][A-Za-z0-9_.-]*$`.
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

fn icon_base(arg: Option<String>) -> Result<String> {
    let base = arg.unwrap_or_else(|| template::DEFAULT_ICON_BASE.to_string());
    let extra: Vec<String> = std::env::var(template::ICON_HOSTS_ENV)
        .unwrap_or_default()
        .split(',')
        .map(str::to_string)
        .collect();
    template::validate_icon_base(&base, &extra).map_err(|e| anyhow!(e))?;
    Ok(base)
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

// ── steps ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Prove the root path works before changing anything.
    Probe,
    Stop,
    CopyVolume {
        volume: String,
        suffix: String,
        to: String,
    },
    SaveInspect {
        json: String,
    },
    WriteTemplate {
        xml: String,
    },
    SetAutostart {
        on: bool,
    },
    Rebuild,
    EnsureState {
        running: bool,
    },
    VerifyManaged {
        running: bool,
        icon: Option<String>,
        image_id: String,
        expect: Box<RunSpec>,
        mode: DiffMode,
    },
    ClearIconCache,
    RefreshIcons,
    RemoveVolume {
        volume: String,
    },
    RemoveOwnAnonymousVolumes {
        candidates: Vec<String>,
    },
    /// Move a staged copy to where the template mounts it. Runs right
    /// before `Rebuild`; an exposed copy is never rolled back.
    ExposeCopy {
        suffix: String,
    },
    RemoveNetwork {
        network: String,
    },
    RetireStack {
        project: String,
        dir: String,
        to: String,
    },
}

impl Step {
    pub fn action(&self) -> &'static str {
        match self {
            Step::Probe => "probe-root",
            Step::Stop => "stop",
            Step::CopyVolume { .. } => "copy-volume",
            Step::SaveInspect { .. } => "save-inspect",
            Step::WriteTemplate { .. } => "write-template",
            Step::SetAutostart { .. } => "set-autostart",
            Step::Rebuild => "rebuild",
            Step::EnsureState { .. } => "ensure-state",
            Step::VerifyManaged { .. } => "verify-managed",
            Step::ClearIconCache => "clear-icon-cache",
            Step::RefreshIcons => "refresh-icons",
            Step::RemoveVolume { .. } => "remove-volume",
            Step::RemoveOwnAnonymousVolumes { .. } => "remove-own-anonymous-volumes",
            Step::ExposeCopy { .. } => "expose-copy",
            Step::RemoveNetwork { .. } => "remove-network",
            Step::RetireStack { .. } => "retire-stack",
        }
    }

    fn change(&self, name: &str, run_id: &str) -> PlannedChange {
        let (target, detail) = match self {
            Step::Probe => ("root".to_string(), None),
            Step::Stop => (name.to_string(), None),
            Step::CopyVolume { volume, to, .. } => (
                volume.clone(),
                Some(format!(
                    "copy into a root-only stage for {to}; verify entries, bytes and manifest \
                     digest"
                )),
            ),
            Step::SaveInspect { .. } => (template::inspect_backup_path(name, run_id), None),
            Step::WriteTemplate { .. } => (
                template::template_path(name),
                Some(format!(
                    "an existing template is first copied to {}",
                    template::backup_path(name, run_id)
                )),
            ),
            Step::SetAutostart { on } => (
                host::AUTOSTART_FILE.to_string(),
                Some(format!("{} {name}", if *on { "add" } else { "remove" })),
            ),
            Step::Rebuild => (
                name.to_string(),
                Some(format!("{} {name}", host::REBUILD_SCRIPT)),
            ),
            Step::EnsureState { running } => (
                name.to_string(),
                Some(if *running { "running" } else { "stopped" }.to_string()),
            ),
            Step::VerifyManaged { icon, image_id, .. } => (
                name.to_string(),
                Some(format!(
                    "{MANAGED_LABEL}={MANAGED_BY_DOCKERMAN}, image {image_id}, matches the rendered command{}",
                    icon.as_ref()
                        .map(|i| format!(", {ICON_LABEL}={i}"))
                        .unwrap_or_default()
                )),
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
            Step::RemoveOwnAnonymousVolumes { candidates } => (
                format!("[{}]", candidates.join(", ")),
                Some("only those no container mounts after the rebuild".to_string()),
            ),
            Step::ExposeCopy { suffix } => (
                format!("{}/{name}/{suffix}", host::APPDATA),
                Some("move the staged copy here".to_string()),
            ),
            Step::RemoveNetwork { network } => (
                network.clone(),
                Some("only if no container uses it".to_string()),
            ),
            Step::RetireStack { dir, to, .. } => (dir.clone(), Some(format!("move to {to}"))),
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

async fn run_step(ops: &dyn HostOps, step: &Step, cx: &ApplyCtx) -> Result<String> {
    let name = cx.name.as_str();
    let name_s = cx.name.clone();
    match step {
        Step::Probe => ops.privileged(&PrivilegedOp::Ping).await,
        Step::Stop => ops.docker(&["stop", name]).await.map(|_| "stopped".into()),
        Step::CopyVolume { volume, suffix, .. } => {
            ops.privileged(&PrivilegedOp::CopyVolume {
                name: name_s,
                volume: volume.clone(),
                dest_suffix: suffix.clone(),
                nonce: cx.nonce.clone(),
            })
            .await
        }
        Step::ExposeCopy { suffix } => {
            ops.privileged(&PrivilegedOp::ExposeCopy {
                name: name_s,
                dest_suffix: suffix.clone(),
                nonce: cx.nonce.clone(),
            })
            .await
        }
        Step::SaveInspect { json } => {
            ops.privileged(&PrivilegedOp::SaveInspect {
                name: name_s,
                json: json.clone(),
                backup_id: cx.run_id.clone(),
            })
            .await
        }
        Step::WriteTemplate { xml } => {
            ops.privileged(&PrivilegedOp::WriteTemplate {
                name: name_s,
                xml: xml.clone(),
                backup_id: cx.run_id.clone(),
            })
            .await
        }
        Step::SetAutostart { on } => {
            ops.privileged(&PrivilegedOp::SetAutostart {
                name: name_s,
                on: *on,
            })
            .await
        }
        Step::Rebuild => {
            ops.privileged(&PrivilegedOp::Rebuild { name: name_s })
                .await
        }
        Step::EnsureState { running } => {
            let now = ops.inspect_container(name).await?.state.running;
            match (now, *running) {
                (false, true) => ops.docker(&["start", name]).await.map(|_| "started".into()),
                (true, false) => ops.docker(&["stop", name]).await.map(|_| "stopped".into()),
                _ => Ok("unchanged".into()),
            }
        }
        Step::VerifyManaged {
            running,
            icon,
            image_id,
            expect,
            mode,
        } => {
            let c = ops.inspect_container(name).await?;
            let managed = c.label(MANAGED_LABEL).unwrap_or_default();
            if managed != MANAGED_BY_DOCKERMAN {
                bail!("{MANAGED_LABEL} is {managed:?}, expected {MANAGED_BY_DOCKERMAN:?}");
            }
            if *running && c.state.status != "running" {
                bail!("container is {}, expected running", c.state.status);
            }
            if &c.image != image_id {
                bail!("container runs image {}, expected {image_id}", c.image);
            }
            if let Some(want) = icon {
                let got = c.label(ICON_LABEL).unwrap_or_default();
                if got != want {
                    bail!("{ICON_LABEL} is {got:?}, expected {want:?}");
                }
            }
            let img = ops.inspect_image(&c.image).await?;
            let (got, _) = live_spec(&c, &img);
            let d: Vec<String> = spec::diff(expect, &got, *mode)
                .into_iter()
                .filter(|d| !d.intended)
                .map(|d| d.msg)
                .collect();
            if !d.is_empty() {
                bail!(
                    "recreated container differs from the rendered command: {}",
                    d.join("; ")
                );
            }
            Ok(format!("{MANAGED_LABEL}={managed}, {}", c.state.status))
        }
        Step::ClearIconCache => {
            ops.privileged(&PrivilegedOp::ClearIconCache { name: name_s })
                .await
        }
        Step::RefreshIcons => ops.privileged(&PrivilegedOp::RefreshIcons).await,
        Step::RemoveVolume { volume } => {
            if !ops.inspect_container(name).await?.state.running {
                return Ok(format!("kept {volume}: container is not running"));
            }
            ops.docker(&["volume", "rm", volume])
                .await
                .map(|_| format!("removed {volume}"))
        }
        Step::RemoveOwnAnonymousVolumes { candidates } => {
            let all = ops.inspect_all().await?;
            let free = orphans::unmounted(candidates, &all);
            for v in &free {
                ops.docker(&["volume", "rm", v]).await?;
            }
            let kept: Vec<&String> = candidates.iter().filter(|c| !free.contains(c)).collect();
            Ok(format!(
                "removed [{}]; kept (still mounted) [{}]",
                free.join(", "),
                kept.iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
        Step::RemoveNetwork { network } => {
            let users = orphans::network_users(network, &ops.inspect_all().await?);
            if !users.is_empty() {
                return Ok(format!("kept {network}: used by [{}]", users.join(", ")));
            }
            ops.docker(&["network", "rm", network])
                .await
                .map(|_| format!("removed {network}"))
        }
        Step::RetireStack { project, dir, to } => {
            ops.privileged(&PrivilegedOp::RetireStack {
                name: name_s,
                project: project.clone(),
                dir: dir.clone(),
                to: to.clone(),
                run_id: cx.run_id.clone(),
            })
            .await
        }
    }
}

/// What the apply path needs to roll back or explain a failure.
pub struct ApplyCtx {
    pub tool: &'static str,
    pub name: String,
    /// This run's id: names the template backup and saved inspect.
    pub run_id: String,
    /// This run's copy-stage nonce; never shown.
    pub nonce: String,
    pub was_running: bool,
    pub autostart_before: bool,
    pub had_template: bool,
    /// The live container before anything changed, for recovery commands.
    pub original: RunSpec,
    pub redactor: Redactor,
}

impl ApplyCtx {
    fn recovery(&self) -> String {
        let name = &self.name;
        let tpl = template::template_path(name);
        let mut r = format!(
            "The original container config is saved at {}.",
            template::inspect_backup_path(name, &self.run_id)
        );
        if self.had_template {
            r.push_str(&format!(
                " To return to the previous template: cp {} {tpl} && {} {name}.",
                template::backup_path(name, &self.run_id),
                host::REBUILD_SCRIPT
            ));
        }
        r.push_str(&format!(
            " To recreate the original container: docker rm -f {name} && {} (masked secret \
             values are in the saved inspect).",
            spec::docker_run_command(&self.original)
        ));
        r
    }
}

/// Run `steps` in order. A failure before `Rebuild` rolls back what this run
/// did (template, autostart, copies, the stop); a failure after it names a
/// concrete recovery. A partial apply never reads as success.
pub async fn apply(ops: &dyn HostOps, cx: &ApplyCtx, steps: &[Step]) -> Result<Vec<StepOutcome>> {
    let name = cx.name.as_str();
    let mut done: Vec<StepOutcome> = Vec::new();
    let mut rebuilt = false;
    let mut stopped = false;
    let mut template_written = false;
    let mut autostart_changed = false;
    let mut copies: Vec<String> = Vec::new();
    let mut exposed: Vec<String> = Vec::new();
    for step in steps {
        let change = step.change(name, &cx.run_id);
        // Marked before running: a failed rebuild leaves the container in an
        // unknown state, so it is reported with recovery, not rolled back.
        // A failed copy discards its own stage and WriteTemplate replaces the
        // file by rename, so both are marked only once they succeeded.
        match step {
            Step::SetAutostart { .. } if !rebuilt => autostart_changed = true,
            Step::Rebuild => rebuilt = true,
            _ => {}
        }
        let res = run_step(ops, step, cx).await;
        let err = match res {
            Ok(detail) => {
                if step == &Step::Stop {
                    stopped = true;
                }
                if matches!(step, Step::WriteTemplate { .. }) {
                    template_written = true;
                }
                match step {
                    Step::CopyVolume { suffix, .. } => copies.push(suffix.clone()),
                    Step::ExposeCopy { suffix } => exposed.push(suffix.clone()),
                    _ => {}
                }
                done.push(StepOutcome {
                    action: change.action,
                    target: change.target,
                    ok: true,
                    detail: Some(cx.redactor.text(&detail)),
                });
                continue;
            }
            Err(e) => e,
        };
        let applied: Vec<String> = done
            .iter()
            .map(|o| format!("{} {}", o.action, o.target))
            .collect();
        let head = format!(
            "{} failed at `{} {}`: {err:#}. Already applied: [{}]",
            cx.tool,
            change.action,
            change.target,
            applied.join("; ")
        );
        if rebuilt {
            bail!(
                "{}",
                cx.redactor.text(&format!("{head}. {}", cx.recovery()))
            );
        }
        let mut rolled = Vec::new();
        let mut note = |what: String, r: Result<String>| {
            rolled.push(match r {
                Ok(_) => what,
                Err(e) => format!("{what} FAILED ({e:#})"),
            });
        };
        if template_written {
            let r = ops
                .privileged(&PrivilegedOp::RestoreTemplate {
                    name: name.into(),
                    backup_id: cx.run_id.clone(),
                })
                .await;
            note("restore template".into(), r);
        }
        if autostart_changed {
            let r = ops
                .privileged(&PrivilegedOp::SetAutostart {
                    name: name.into(),
                    on: cx.autostart_before,
                })
                .await;
            note("restore autostart".into(), r);
        }
        for suffix in &exposed {
            note(
                format!(
                    "left exposed copy {}/{name}/{suffix} in place",
                    host::APPDATA
                ),
                Ok(String::new()),
            );
        }
        for suffix in copies.iter().filter(|c| !exposed.contains(c)) {
            let r = ops
                .privileged(&PrivilegedOp::RemoveCopy {
                    name: name.into(),
                    dest_suffix: suffix.clone(),
                    nonce: cx.nonce.clone(),
                })
                .await;
            note(format!("remove copy {suffix}"), r);
        }
        if stopped && cx.was_running {
            let r = ops.docker(&["start", name]).await;
            note("start container".into(), r);
        }
        bail!(
            "{}",
            cx.redactor
                .text(&format!("{head}. Rolled back: [{}]", rolled.join("; ")))
        );
    }
    Ok(done)
}

// ── adopt planning (pure) ────────────────────────────────────────────────────

/// Host state an adopt or set_icon is planned against.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub container: ContainerInspect,
    pub container_raw: Value,
    /// The image the container runs (by id).
    pub image: ImageInspect,
    pub image_raw: Value,
    /// What the container's `Config.Image` tag resolves to now.
    pub tag_image_id: Option<String>,
    /// Every container on the host, including `container`.
    pub all: Vec<ContainerInspect>,
    /// `docker volume inspect` of the container's volumes.
    pub volumes: BTreeMap<String, VolumeInspect>,
    pub existing_template: Option<String>,
    /// `(file, <Name>)` of every template in templates-user.
    pub templates: Vec<(String, Option<String>)>,
    pub autostart: Vec<String>,
    /// This run's id (`YYYYMMDD-HHMMSS-<hex>`): backup names, retire date.
    pub run_id: String,
    /// This run's copy-stage nonce; never shown.
    pub nonce: String,
    /// Log options the docker daemon applies by default.
    pub daemon_log_opts: BTreeMap<String, String>,
    pub stacks_roots: Vec<PathBuf>,
    /// Stacks roots root may not move directories out of, and why.
    pub stacks_root_problems: BTreeMap<PathBuf, String>,
    /// Content of the compose file in the container's compose working dir.
    pub compose_file: Option<String>,
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
    pub suffix: String,
    pub to: String,
}

#[derive(Debug, Clone)]
pub struct AdoptPlan {
    pub template: Template,
    pub template_xml: String,
    /// The live container as a spec, before intended changes.
    pub live: RunSpec,
    /// The spec the recreated container must have.
    pub target: RunSpec,
    pub baked_env: BTreeSet<String>,
    /// Live facets the template cannot carry; any entry blocks execute.
    pub unsupported: Vec<String>,
    /// Deliberate differences between live and target.
    pub intended: Vec<String>,
    pub blockers: Vec<String>,
    pub migrations: Vec<Migration>,
    pub compose: Option<ComposeLeftovers>,
    pub autostart: bool,
    pub was_running: bool,
    pub steps: Vec<Step>,
}

/// B1: the container must run the image its tag resolves to now, or a
/// rebuild would silently switch images.
pub fn image_blocker(s: &Snapshot) -> Option<String> {
    let tag = &s.container.config.image;
    match &s.tag_image_id {
        None => Some(format!(
            "image tag {tag} no longer resolves to a local image; the container runs {}",
            s.container.image
        )),
        Some(id) if id != &s.container.image => Some(format!(
            "image tag {tag} now points at {id} but the container runs {}; a rebuild would \
             switch images — recreate it on the current image first, or retag",
            s.container.image
        )),
        _ => None,
    }
}

/// L2: no other template may claim this container's name or file.
pub fn template_collisions(name: &str, templates: &[(String, Option<String>)]) -> Vec<String> {
    let file = format!("my-{name}.xml");
    let mut out = Vec::new();
    for (f, n) in templates {
        if f == &file {
            continue;
        }
        if f.eq_ignore_ascii_case(&file) {
            out.push(format!(
                "template file {f} collides with {file} case-insensitively"
            ));
        } else if n.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(name)) {
            out.push(format!("template {f} also declares <Name>{name}</Name>"));
        }
    }
    out
}

fn autostart_steps(
    steps: &mut Vec<Step>,
    in_autostart: bool,
    want_running: bool,
    autostart: bool,
    rebuild: impl FnOnce(&mut Vec<Step>),
) {
    // rebuild_container leaves the container running exactly when it is
    // listed, so membership is set to the wanted state across the rebuild
    // and to the wanted autostart after it.
    if in_autostart != want_running {
        steps.push(Step::SetAutostart { on: want_running });
    }
    rebuild(steps);
    if autostart != want_running {
        steps.push(Step::SetAutostart { on: autostart });
    }
}

pub fn plan_adopt(s: &Snapshot, o: &AdoptOpts) -> AdoptPlan {
    let c = &s.container;
    let name = c.short_name();
    let (live, mut unsupported) = live_spec(c, &s.image);
    let mut target = live.clone();
    let mut intended = Vec::new();
    let mut blockers = Vec::new();

    if c.label(MANAGED_LABEL) == Some(MANAGED_BY_DOCKERMAN) && s.existing_template.is_some() {
        blockers.push(format!(
            "{name} is already dockerMan-managed with a template; use unraid.docker.set_icon"
        ));
    }
    blockers.extend(image_blocker(s));
    blockers.extend(template_collisions(name, &s.templates));

    let mut compose = orphans::compose_leftovers(
        c,
        &s.all,
        s.run_id.get(..8).unwrap_or_default(),
        &s.stacks_roots,
        s.compose_file.as_deref(),
    );
    if let Some(l) = compose.as_mut()
        && let Some((dir, _)) = &l.retire
        && let Some(why) = dir.parent().and_then(|p| s.stacks_root_problems.get(p))
    {
        l.keep_reason = Some(format!("not retiring {}: {why}", dir.display()));
        l.retire = None;
    }
    let compose_moving = compose.as_ref().is_some_and(|l| l.network.is_some());
    unsupported.extend(inspect::unmodelled(
        &s.container_raw,
        &s.image_raw,
        compose_moving,
    ));
    if let Some(l) = &compose {
        if let Some(net) = &l.network {
            target.network = "bridge".to_string();
            intended.push(format!("network {net} -> bridge"));
        }
        blockers.extend(l.network_blocker.clone());
        intended.push(format!("compose project {} labels dropped", l.project));
    }

    let mut migrations = Vec::new();
    if o.migrate_volumes {
        let vols: Vec<_> = c.volumes().collect();
        let names: Vec<String> = vols
            .iter()
            .map(|m| m.name.clone().unwrap_or_default())
            .collect();
        let suffixes = orphans::appdata_suffixes(name, c.compose_project(), &names);
        for (m, suffix) in vols.iter().zip(suffixes) {
            let volume = m.name.clone().unwrap_or_default();
            match s.volumes.get(&volume) {
                None => blockers.push(format!("volume {volume}: not inspected")),
                Some(v) => {
                    if v.driver != "local" || v.options.as_ref().is_some_and(|o| !o.is_empty()) {
                        blockers.push(format!(
                            "volume {volume}: driver {:?} with options is not a plain local volume",
                            v.driver
                        ));
                    }
                    if v.mountpoint != VolumeInspect::expected_mountpoint(&volume)
                        || m.source != v.mountpoint
                    {
                        blockers.push(format!(
                            "volume {volume}: data at {:?}, not {}",
                            v.mountpoint,
                            VolumeInspect::expected_mountpoint(&volume)
                        ));
                    }
                }
            }
            let others: Vec<&str> = s
                .all
                .iter()
                .filter(|o| o.short_name() != name)
                .filter(|o| {
                    o.volumes()
                        .any(|x| x.name.as_deref() == Some(volume.as_str()))
                })
                .map(|o| o.short_name())
                .collect();
            if !others.is_empty() {
                blockers.push(format!(
                    "volume {volume} is also mounted by [{}]",
                    others.join(", ")
                ));
            }
            let to = format!("{}/{name}/{suffix}", host::APPDATA);
            let overlapping = orphans::binds_overlapping(Path::new(&to), &s.all);
            if !overlapping.is_empty() {
                blockers.push(format!(
                    "{to} overlaps existing bind mounts [{}]",
                    overlapping.into_iter().collect::<Vec<_>>().join(", ")
                ));
            }
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
            migrations.push(Migration { volume, suffix, to });
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

    let mut steps = vec![Step::Probe];
    if !migrations.is_empty() && was_running {
        steps.push(Step::Stop);
    }
    for m in &migrations {
        steps.push(Step::CopyVolume {
            volume: m.volume.clone(),
            suffix: m.suffix.clone(),
            to: m.to.clone(),
        });
    }
    steps.push(Step::SaveInspect {
        json: s.container_raw.to_string(),
    });
    steps.push(Step::WriteTemplate {
        xml: template_xml.clone(),
    });
    autostart_steps(&mut steps, in_autostart, was_running, autostart, |st| {
        for m in &migrations {
            st.push(Step::ExposeCopy {
                suffix: m.suffix.clone(),
            });
        }
        st.push(Step::Rebuild)
    });
    steps.push(Step::EnsureState {
        running: was_running,
    });
    steps.push(Step::VerifyManaged {
        running: was_running,
        icon: (!icon.is_empty()).then(|| icon.clone()),
        image_id: c.image.clone(),
        expect: Box::new(target.clone()),
        mode: DiffMode::Adopt,
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
    let anon: Vec<String> = orphans::own_anonymous_volumes(c, &s.volumes)
        .into_iter()
        .filter(|v| !migrations.iter().any(|m| &m.volume == v))
        .collect();
    if !anon.is_empty() {
        steps.push(Step::RemoveOwnAnonymousVolumes { candidates: anon });
    }
    if let Some(l) = &compose {
        if let Some(net) = &l.network {
            steps.push(Step::RemoveNetwork {
                network: net.clone(),
            });
        }
        if let Some((from, to)) = &l.retire {
            steps.push(Step::RetireStack {
                project: l.project.clone(),
                dir: from.display().to_string(),
                to: to.display().to_string(),
            });
        }
    }

    AdoptPlan {
        template,
        template_xml,
        live,
        target,
        baked_env: inspect::baked_env(&s.image),
        unsupported,
        intended,
        blockers,
        migrations,
        compose,
        autostart,
        was_running,
        steps,
    }
}

/// The rendered command as a spec comparable to a live one: image-baked env
/// dropped, and the daemon's default log options filled in, as the new
/// container will get them.
pub fn rendered_spec(
    rendered: &str,
    baked: &BTreeSet<String>,
    daemon_log_opts: &BTreeMap<String, String>,
) -> Result<RunSpec, String> {
    let mut got = spec::parse_command(rendered)?.without_baked_env(baked);
    if got.log_driver == spec::DEFAULT_LOG_DRIVER {
        for (k, v) in daemon_log_opts {
            got.log_opts.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    Ok(got)
}

/// Compare `target` with what dockerMan rendered. Returns the rendered spec
/// (when it parsed) and every delta, unsupported facets first.
pub fn fidelity(
    target: &RunSpec,
    unsupported: &[String],
    baked: &BTreeSet<String>,
    daemon_log_opts: &BTreeMap<String, String>,
    rendered: &str,
    mode: DiffMode,
) -> (Option<RunSpec>, Vec<Delta>) {
    let mut out: Vec<Delta> = unsupported
        .iter()
        .map(|u| Delta {
            msg: format!("unsupported: {u}"),
            intended: false,
        })
        .collect();
    match rendered_spec(rendered, baked, daemon_log_opts) {
        Ok(got) => {
            out.extend(spec::diff(target, &got, mode));
            (Some(got), out)
        }
        Err(e) => {
            out.push(Delta {
                msg: format!("could not parse rendered command: {e}"),
                intended: false,
            });
            (None, out)
        }
    }
}

/// The rendered command for display: secret env, label and log-opt values
/// masked.
pub fn mask_command(cmd: &str, r: &Redactor) -> String {
    let Ok(words) = spec::shell_split(cmd.trim()) else {
        return r.text(cmd);
    };
    let mut out = Vec::with_capacity(words.len());
    let mut env_next = false;
    let mut label_next = false;
    let mut log_next = false;
    for w in words {
        let masked = if log_next {
            redact::mask_kv(&w)
        } else if let Some(kv) = w.strip_prefix("--log-opt=") {
            format!("--log-opt={}", redact::mask_kv(kv))
        } else if label_next || w.starts_with("--label=") {
            let prefix = if label_next { "" } else { "--label=" };
            let body = w.strip_prefix("--label=").unwrap_or(&w);
            match body.split_once('=') {
                Some((k, v)) => format!("{prefix}{k}={}", redact::mask_label(k, v)),
                None => w.clone(),
            }
        } else if env_next || w.starts_with("--env=") {
            let body = w.strip_prefix("--env=").unwrap_or(&w);
            match body.split_once('=') {
                Some((k, v)) => {
                    let prefix = if w.starts_with("--env=") {
                        "--env="
                    } else {
                        ""
                    };
                    format!("{prefix}{k}={}", redact::mask(k, v))
                }
                None => w.clone(),
            }
        } else {
            w.clone()
        };
        env_next = w == "-e" || w == "--env";
        label_next = w == "-l" || w == "--label";
        log_next = w == "--log-opt";
        out.push(spec::shell_quote(&masked));
    }
    r.text(&out.join(" "))
}

fn redactor_for(c: &ContainerInspect, extra: &[&RunSpec]) -> Redactor {
    let mut r = Redactor::default();
    for kv in c.config.env.iter().flatten() {
        let (k, v) = kv.split_once('=').unwrap_or((kv.as_str(), ""));
        r.add(k, v);
    }
    for (k, v) in c.config.labels.iter().flatten() {
        r.add_label(k, v);
    }
    for (k, v) in c.host_config.log_config.config.iter().flatten() {
        r.add(k, v);
    }
    r.add_cmd(c.config.cmd.as_deref().unwrap_or_default());
    for s in extra {
        r.add_spec(s);
    }
    r
}

/// Blocker when the root path cannot be used: none configured, or a
/// side-effect-free Ping through it fails.
async fn root_path_blocker(runner: Option<&dyn PrivilegedRunner>) -> Option<String> {
    let runner = match runner {
        None => return Some(privileged::missing_runner_blocker()),
        Some(r) => r,
    };
    match runner.run(&PrivilegedOp::Ping).await {
        Ok(_) => None,
        Err(e) => Some(format!(
            "root path {} failed a ping (argyle-labs/orca#762 seam): {e:#}",
            runner.kind()
        )),
    }
}

// ── tools ────────────────────────────────────────────────────────────────────

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
    /// The template to be written; secret values masked.
    pub template_xml: String,
    /// The `docker create` command dockerMan renders; secret values masked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendered_command: Option<String>,
    /// Live vs rendered differences that block. Must be empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fidelity_diff: Vec<String>,
    /// Differences that are the point of the change.
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
    run_id: &str,
    summary: String,
    steps: &[Step],
) -> Result<ExecutionPlan> {
    let inputs = serde_json::to_value(args)?;
    Ok(ExecutionPlan::generic(tool, inputs.into()).detailed(
        summary,
        steps.iter().map(|s| s.change(name, run_id)).collect(),
    ))
}

/// Inspect `name` (S13: refusing an id-prefix match) and its images.
async fn snapshot(name: &str) -> Result<Snapshot> {
    let (container, container_raw) = host::inspect_container_raw(name).await?;
    if container.short_name() != name {
        bail!(
            "`{name}` resolved to container {:?}; pass the exact container name",
            container.short_name()
        );
    }
    let (image, image_raw) = host::inspect_image_raw(&container.image).await?;
    let tag_image_id = host::inspect_image_raw(&container.config.image)
        .await
        .ok()
        .map(|(i, _)| i.id);
    let mut volumes = BTreeMap::new();
    for m in container.volumes() {
        if let Some(n) = &m.name
            && let Ok(v) = host::inspect_volume(n).await
        {
            volumes.insert(n.clone(), v);
        }
    }
    let compose_file = container
        .label(inspect::COMPOSE_WORKING_DIR)
        .and_then(|d| host::compose_file(Path::new(d)));
    Ok(Snapshot {
        image,
        image_raw,
        tag_image_id,
        all: host::inspect_all().await?,
        volumes,
        existing_template: std::fs::read_to_string(template::template_path(name)).ok(),
        templates: host::list_templates(),
        autostart: host::read_autostart(),
        run_id: privileged::new_run_id(),
        nonce: host::random_suffix(),
        daemon_log_opts: std::fs::read_to_string(host::DOCKER_CFG)
            .map(|c| host::daemon_log_opts(&c))
            .unwrap_or_default(),
        stacks_root_problems: stacks_root_problems(&orphans::stacks_roots()),
        stacks_roots: orphans::stacks_roots(),
        compose_file,
        container,
        container_raw,
    })
}

/// Why root may not retire stacks from each root: the root, or a
/// pre-existing `<root>-retired`, is not a root-owned, non-group/world-
/// writable directory.
fn stacks_root_problems(roots: &[PathBuf]) -> BTreeMap<PathBuf, String> {
    use std::os::unix::fs::MetadataExt;
    roots
        .iter()
        .filter_map(|r| {
            let md = std::fs::metadata(r).ok()?;
            if let Some(w) = safefs::root_owned_problem(r, md.uid(), md.mode()) {
                return Some((r.clone(), w));
            }
            let retired = PathBuf::from(format!("{}-retired", r.display()));
            let md = std::fs::symlink_metadata(&retired).ok()?;
            let why = if !md.is_dir() {
                Some(format!(
                    "pre-existing {} is not a real directory; remove it",
                    retired.display()
                ))
            } else {
                safefs::root_owned_problem(&retired, md.uid(), md.mode())
                    .map(|w| format!("pre-existing {w}"))
            };
            why.map(|w| (r.clone(), w))
        })
        .collect()
}

fn split_deltas(deltas: Vec<Delta>, r: &Redactor) -> (Vec<String>, Vec<String>) {
    let (intended, blocking): (Vec<_>, Vec<_>) = deltas.into_iter().partition(|d| d.intended);
    (
        blocking.into_iter().map(|d| r.text(&d.msg)).collect(),
        intended.into_iter().map(|d| r.text(&d.msg)).collect(),
    )
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
    /// https base URL the repo lives under; its host must be allowlisted.
    #[arg(long)]
    #[serde(default, alias = "icon_base")]
    pub icon_base: Option<String>,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Steps for set_icon, given the patched template and what dockerMan renders
/// from it (`expect`).
pub fn set_icon_steps(s: &Snapshot, xml: &str, url: &str, expect: RunSpec) -> Vec<Step> {
    let c = &s.container;
    let was_running = c.state.running;
    let in_autostart = s.autostart.iter().any(|n| n == c.short_name());
    let mut steps = vec![
        Step::Probe,
        Step::SaveInspect {
            json: s.container_raw.to_string(),
        },
        Step::WriteTemplate {
            xml: xml.to_string(),
        },
    ];
    autostart_steps(&mut steps, in_autostart, was_running, in_autostart, |st| {
        st.push(Step::Rebuild)
    });
    steps.push(Step::EnsureState {
        running: was_running,
    });
    steps.push(Step::VerifyManaged {
        running: was_running,
        icon: Some(url.to_string()),
        image_id: c.image.clone(),
        expect: Box::new(expect),
        mode: DiffMode::SetIcon,
    });
    steps.push(Step::ClearIconCache);
    steps.push(Step::RefreshIcons);
    steps
}

/// Blockers specific to set_icon (B2 and B1).
pub fn set_icon_blockers(s: &Snapshot) -> Vec<String> {
    let mut b = Vec::new();
    let managed = s.container.label(MANAGED_LABEL).unwrap_or_default();
    if managed != MANAGED_BY_DOCKERMAN {
        b.push(format!(
            "{} is not dockerMan-managed ({MANAGED_LABEL}={managed:?}); adopt it with unraid.docker.adopt",
            s.container.short_name()
        ));
    }
    b.extend(image_blocker(s));
    b
}

/// Point a dockerMan-managed container's template at an argyle-labs repo
/// icon, rebuild it (keeping its running/stopped state and autostart) and
/// refresh both icon caches. Refuses unless the patched template reproduces
/// the live container.
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
    let s = snapshot(name).await?;
    let current = s.existing_template.clone().ok_or_else(|| {
        anyhow!("{name} has no Unraid template at {path}; adopt it with unraid.docker.adopt")
    })?;
    let url = template::icon_url(&base, &args.repo);
    let xml = template::set_icon(&current, &url).map_err(|e| anyhow!("{path}: {e}"))?;

    let (live, mut unsupported) = live_spec(&s.container, &s.image);
    unsupported.extend(inspect::unmodelled(&s.container_raw, &s.image_raw, false));
    let baked = inspect::baked_env(&s.image);
    let mut blockers = set_icon_blockers(&s);
    let runner = privileged::runner();
    blockers.extend(root_path_blocker(runner.as_deref()).await);
    let (rendered_command, rendered, deltas) = match host::render_command(&xml).await {
        Ok(cmd) => {
            let (got, d) = fidelity(
                &live,
                &unsupported,
                &baked,
                &s.daemon_log_opts,
                &cmd,
                DiffMode::SetIcon,
            );
            (Some(cmd), got, d)
        }
        Err(e) => {
            blockers.push(format!("dockerMan could not render the template: {e:#}"));
            (None, None, Vec::new())
        }
    };
    let r = redactor_for(&s.container, &rendered.iter().collect::<Vec<_>>());
    let (fidelity_diff, mut intended_changes) = split_deltas(deltas, &r);
    intended_changes.insert(
        0,
        format!(
            "icon {} -> {url}",
            template::extract_icon(&current).unwrap_or_else(|| "(none)".to_string())
        ),
    );
    let ready = blockers.is_empty() && fidelity_diff.is_empty() && rendered.is_some();
    let steps = set_icon_steps(&s, &xml, &url, rendered.clone().unwrap_or(live.clone()));

    let mut out = DockerChange {
        dry_run: !args.execute,
        tool: TOOL.to_string(),
        name: name.to_string(),
        ready,
        template_path: path,
        template_xml: r.text(&redact::mask_template_xml(&xml)),
        rendered_command: rendered_command.as_deref().map(|c| mask_command(c, &r)),
        fidelity_diff,
        intended_changes,
        blockers: blockers.iter().map(|b| r.text(b)).collect(),
        notes: runner
            .iter()
            .map(|x| format!("root path: {}", x.kind()))
            .collect(),
        plan: None,
        steps: Vec::new(),
    };
    if !args.execute {
        out.plan = Some(execution_plan(
            TOOL,
            &args,
            name,
            &s.run_id,
            format!("set {name}'s icon to {url} and rebuild"),
            &steps,
        )?);
        return Ok(out);
    }
    if !ready {
        let mut why = out.blockers.clone();
        why.extend(out.fidelity_diff.iter().cloned());
        bail!("{TOOL}: refusing to execute: {}", why.join("; "));
    }
    let runner = runner.ok_or_else(|| anyhow!(privileged::missing_runner_blocker()))?;
    let cx = ApplyCtx {
        tool: TOOL,
        name: name.to_string(),
        run_id: s.run_id.clone(),
        nonce: s.nonce.clone(),
        was_running: s.container.state.running,
        autostart_before: s.autostart.iter().any(|n| n == name),
        had_template: true,
        original: live,
        redactor: r,
    };
    out.steps = apply(&host::LiveOps { runner }, &cx, &steps).await?;
    Ok(out)
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidDockerAdoptArgs {
    /// Container to adopt (exact name).
    #[arg(long)]
    pub name: String,
    /// argyle-labs repo whose `assets/icon-256.png` becomes the icon.
    #[arg(long)]
    #[serde(default)]
    pub repo: Option<String>,
    /// Copy each local docker volume into `/mnt/user/appdata/<name>/` and
    /// mount that instead; the old volumes are removed once the copy is
    /// verified and the recreated container runs.
    #[arg(long)]
    #[serde(default, alias = "migrate_volumes")]
    pub migrate_volumes: bool,
    /// Start with the array (Unraid autostart). Default: on if the container
    /// is running or already listed.
    #[arg(long)]
    #[serde(default)]
    pub autostart: Option<bool>,
    /// https base URL the repo lives under; its host must be allowlisted.
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
/// remove only what the container itself left behind. Refuses on any
/// unexplained difference.
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
    let s = snapshot(name).await?;
    let mut plan = plan_adopt(
        &s,
        &AdoptOpts {
            repo: args.repo.clone(),
            icon_base: base,
            migrate_volumes: args.migrate_volumes,
            autostart: args.autostart,
        },
    );

    let mut blockers = plan.blockers.clone();
    let runner = privileged::runner();
    blockers.extend(root_path_blocker(runner.as_deref()).await);
    for m in &plan.migrations {
        if host::is_nonempty_dir(Path::new(&m.to)) {
            blockers.push(format!("{} already has content", m.to));
        }
    }
    let (rendered_command, rendered, deltas) = match host::render_command(&plan.template_xml).await
    {
        Ok(cmd) => {
            let (got, d) = fidelity(
                &plan.target,
                &plan.unsupported,
                &plan.baked_env,
                &s.daemon_log_opts,
                &cmd,
                DiffMode::Adopt,
            );
            (Some(cmd), got, d)
        }
        Err(e) => {
            blockers.push(format!("dockerMan could not render the template: {e:#}"));
            (None, None, Vec::new())
        }
    };
    if let Some(got) = &rendered {
        for st in &mut plan.steps {
            if let Step::VerifyManaged { expect, .. } = st {
                **expect = got.clone();
            }
        }
    }
    let r = redactor_for(
        &s.container,
        &[&plan.target]
            .into_iter()
            .chain(rendered.iter())
            .collect::<Vec<_>>(),
    );
    let (fidelity_diff, intended) = split_deltas(deltas, &r);
    let mut intended_changes: Vec<String> = plan.intended.iter().map(|i| r.text(i)).collect();
    intended_changes.extend(intended);
    let mut notes = Vec::new();
    if let Some(l) = &plan.compose
        && let Some(why) = &l.keep_reason
    {
        notes.push(r.text(&format!("compose stack kept: {why}")));
    }
    notes.push(format!(
        "autostart {}",
        if plan.autostart { "on" } else { "off" }
    ));
    if let Some(r) = &runner {
        notes.push(format!("root path: {}", r.kind()));
    }
    let ready = blockers.is_empty() && fidelity_diff.is_empty() && rendered.is_some();

    let mut out = DockerChange {
        dry_run: !args.execute,
        tool: TOOL.to_string(),
        name: name.to_string(),
        ready,
        template_path: template::template_path(name),
        template_xml: r.text(&redact::mask_template_xml(&plan.template_xml)),
        rendered_command: rendered_command.as_deref().map(|c| mask_command(c, &r)),
        fidelity_diff,
        intended_changes,
        blockers: blockers.iter().map(|b| r.text(b)).collect(),
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
        out.plan = Some(execution_plan(
            TOOL,
            &args,
            name,
            &s.run_id,
            summary,
            &plan.steps,
        )?);
        return Ok(out);
    }
    if !ready {
        let mut why = out.blockers.clone();
        why.extend(out.fidelity_diff.iter().cloned());
        bail!("{TOOL}: refusing to execute: {}", why.join("; "));
    }
    let runner = runner.ok_or_else(|| anyhow!(privileged::missing_runner_blocker()))?;
    let cx = ApplyCtx {
        tool: TOOL,
        name: name.to_string(),
        run_id: s.run_id.clone(),
        nonce: s.nonce.clone(),
        was_running: plan.was_running,
        autostart_before: s.autostart.iter().any(|n| n == name),
        had_template: s.existing_template.is_some(),
        original: plan.live.clone(),
        redactor: r,
    };
    out.steps = apply(&host::LiveOps { runner }, &cx, &plan.steps).await?;
    Ok(out)
}

#[cfg(test)]
mod tests;
