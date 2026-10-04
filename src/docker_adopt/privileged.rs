//! The root-only half of the `unraid.docker.*` verbs.
//!
//! On Unraid the plugin runs as the unprivileged `orca` user (in the `docker`
//! group), which cannot write `/boot` templates or the autostart file, or run
//! `rebuild_container`. Those effects are a closed set of [`PrivilegedOp`]s.
//! Each carries only self-contained values; [`execute`] runs as root and
//! re-derives and re-validates every path itself, never trusting one from the
//! caller.
//!
//! Root is reached through a [`PrivilegedRunner`]: [`Direct`] when the plugin
//! already runs as root, or [`Sudo`], the core seam
//! `sudo -n $ORCA_BIN admin plugin-apply` (argyle-labs/orca#762), which runs
//! this binary as `unraid --privileged-op` with `{op, payload}` on stdin.

use std::fs;
use std::path::{Path, PathBuf};

use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::prelude::*;
use plugin_toolkit::process::Command;
use plugin_toolkit::serde_json::{self, Value};

use super::host::{self, APPDATA, AUTOSTART_FILE, REBUILD_SCRIPT};
use super::inspect::{COMPOSE_PROJECT, ContainerInspect, VolumeInspect};
use super::orphans;
use super::safefs::{self, Dir};
use super::template::{self, MANAGED_MARKER};
use super::validate_name;

/// Argument that puts the plugin binary into one-shot privileged mode.
pub const PRIVILEGED_FLAG: &str = "--privileged-op";
/// Env naming the orca binary whose `admin plugin-apply` is the sudo seam.
pub const ORCA_BIN_ENV: &str = "ORCA_BIN";
const MAX_TEMPLATE_BYTES: usize = 1 << 20;

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
#[serde(tag = "op", content = "payload", rename_all = "snake_case")]
pub enum PrivilegedOp {
    /// Proves a root path exists; changes nothing.
    Ping,
    /// Write `my-<name>.xml`, first saving the existing one (or a "there was
    /// none" sentinel) under this run's `backup_id`.
    WriteTemplate {
        name: String,
        xml: String,
        backup_id: String,
    },
    /// Save the original `docker inspect` next to the template; never overwrites.
    SaveInspect {
        name: String,
        json: String,
        backup_id: String,
    },
    /// Undo this run's WriteTemplate from its `backup_id`.
    RestoreTemplate {
        name: String,
        backup_id: String,
    },
    SetAutostart {
        name: String,
        on: bool,
    },
    Rebuild {
        name: String,
    },
    ClearIconCache {
        name: String,
    },
    RefreshIcons,
    /// Copy a stopped container's local docker volume into a root-only
    /// stage under `/mnt/user/appdata/<name>` and verify the copy.
    CopyVolume {
        name: String,
        volume: String,
        dest_suffix: String,
        nonce: String,
    },
    /// Remove this run's staged copy. Never touches an exposed one.
    RemoveCopy {
        name: String,
        dest_suffix: String,
        nonce: String,
    },
    /// Move this run's staged copy to `<name>/<dest_suffix>`, where the
    /// template mounts it.
    ExposeCopy {
        name: String,
        dest_suffix: String,
        nonce: String,
    },
    /// Move a compose stack directory to the planned `to`, which must equal
    /// `<root>-retired/<name>-compose-<date of run_id>`.
    RetireStack {
        name: String,
        project: String,
        dir: String,
        to: String,
        run_id: String,
    },
}

#[orca_struct]
#[derive(Debug, Clone)]
pub struct PrivilegedReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A per-run id: `YYYYMMDD-HHMMSS-<8 hex>`.
pub fn new_run_id() -> String {
    format!(
        "{}-{}",
        plugin_toolkit::lifecycle::timestamp(),
        &host::random_suffix()[..8]
    )
}

pub fn validate_run_id(id: &str) -> Result<()> {
    let b = id.as_bytes();
    let ok = b.len() == 24
        && b[..8].iter().all(u8::is_ascii_digit)
        && b[8] == b'-'
        && b[9..15].iter().all(u8::is_ascii_digit)
        && b[15] == b'-'
        && b[16..]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c));
    if !ok || !real_timestamp(&id[..15]) {
        bail!("invalid run id {id:?}");
    }
    Ok(())
}

/// `YYYYMMDD-HHMMSS` names a real UTC date and time.
fn real_timestamp(ts: &str) -> bool {
    let n = |r: std::ops::Range<usize>| ts[r].parse::<u32>().unwrap_or(u32::MAX);
    let (y, m, d) = (n(0..4), n(4..6), n(6..8));
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&d) && n(9..11) < 24 && n(11..13) < 60 && n(13..15) < 60
}

pub fn validate_nonce(n: &str) -> Result<()> {
    if n.len() != 16
        || !n
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        bail!("invalid nonce");
    }
    Ok(())
}

/// Validate a template body: well-formed enough for dockerMan, exactly one
/// `<Name>`, and that name is `name`.
pub fn check_template(name: &str, xml: &str) -> Result<()> {
    if xml.len() > MAX_TEMPLATE_BYTES {
        bail!("template is larger than {MAX_TEMPLATE_BYTES} bytes");
    }
    if !xml.contains("<Container") || !xml.trim_end().ends_with("</Container>") {
        bail!("template is not a <Container> document");
    }
    if xml.matches("<Name>").count() != 1 {
        bail!("template must have exactly one <Name>");
    }
    match template::extract_name(xml) {
        Some(n) if n == name => Ok(()),
        other => bail!("template <Name> is {other:?}, expected {name:?}"),
    }
}

/// Sentinel saved instead of a backup when no template existed.
fn none_sentinel(name: &str, backup_id: &str) -> String {
    format!("{}.none", template::backup_path(name, backup_id))
}

// A copy is staged in `<appdata>/<name>/.orca-stage-<h>/data`, where `<h>`
// is a hash of the run's nonce and the suffix. The stage is created 0700 by
// root and checked to be the directory just made, so nothing else can reach
// into it, and `cp -a` (which ends by giving `data` the source's owner and
// mode) never exposes the tree mid-copy. A later process recognises its stage
// by a token file inside holding the nonce, which is never shown and cannot be
// read or written by anyone else; device/inode numbers are not used, since
// shfs (FUSE) does not promise them stable across processes.
const STAGE_TOKEN: &str = ".orca-stage-token";
const STAGE_DATA: &str = "data";

fn stage_name(nonce: &str, suffix: &str) -> String {
    format!(
        ".orca-stage-{}",
        &sha256_hex(format!("{nonce}/{suffix}").as_bytes())[..16]
    )
}

fn stage_token(nonce: &str, suffix: &str) -> String {
    format!("{nonce}\n{suffix}\n")
}

/// This run's stage for `suffix` under the held `<name>` directory, after
/// checking it is root's (this process's uid), 0700, and holds this run's
/// token. `None` when there is no stage.
pub fn open_stage(app: &Dir, nonce: &str, suffix: &str) -> Result<Option<Dir>> {
    validate_name("destination", suffix)?;
    validate_nonce(nonce)?;
    let Some(stage) = app.child_opt(&stage_name(nonce, suffix))? else {
        return Ok(None);
    };
    let st = stage.stat()?;
    if st.st_uid != rustix::process::geteuid().as_raw() || stage.mode()? != 0o700 {
        bail!("{} is not this run's stage", stage.path().display());
    }
    if stage.read_file(STAGE_TOKEN)?.as_deref() != Some(stage_token(nonce, suffix).as_bytes()) {
        bail!("{} is not this run's stage", stage.path().display());
    }
    Ok(Some(stage))
}

/// Delete a stage this process holds and checked: its data by descriptor,
/// then the token, then the (now empty) stage directory.
fn discard_stage(app: &Dir, stage: &Dir, name: &str) -> Result<()> {
    if let Some(d) = stage.child_opt(STAGE_DATA)? {
        d.clear()?;
        stage.remove_empty_dir(STAGE_DATA)?;
    }
    stage.remove_file(STAGE_TOKEN)?;
    app.remove_empty_dir(name)
}

/// Create this run's empty stage for `suffix` under `<appdata>/<name>`,
/// refusing when `<name>/<suffix>` already exists. Returns `(<name>, stage)`.
pub fn create_stage(appdata: &Dir, name: &str, suffix: &str, nonce: &str) -> Result<(Dir, Dir)> {
    validate_name("container name", name)?;
    validate_name("destination", suffix)?;
    validate_nonce(nonce)?;
    let app = appdata.ensure_child(name, 0o755)?;
    if app.exists(suffix)? {
        bail!("{} already exists", app.path().join(suffix).display());
    }
    let sname = stage_name(nonce, suffix);
    let stage = app.create_child(&sname, 0o700)?;
    if let Err(e) = stage.create_file(STAGE_TOKEN, stage_token(nonce, suffix).as_bytes(), 0o600) {
        app.remove_empty_dir(&sname).ok();
        return Err(e);
    }
    Ok((app, stage))
}

/// Stage a verified copy of the held `src` under `<appdata>/<name>`:
/// refuse anything unsafe to copy as root, `cp` into the held stage through
/// `/proc/<pid>/fd/<n>` without security xattrs, re-check the copy, and
/// compare manifests. On failure the stage is removed in this process.
pub async fn stage_copy(
    appdata: &Dir,
    src: &Dir,
    name: &str,
    suffix: &str,
    volume: &str,
    nonce: &str,
) -> Result<String> {
    let from = format!("{}/.", src.proc_path()?);
    let (app, stage) = create_stage(appdata, name, suffix, nonce)?;
    let sname = stage_name(nonce, suffix);
    let copied = async {
        safefs::check_copyable(src)?;
        let to = format!("{}/{STAGE_DATA}", stage.proc_path()?);
        // `-a` would also carry security.* xattrs (file capabilities).
        host::run(
            "/bin/cp",
            &[
                "-R",
                "--no-dereference",
                "--preserve=mode,ownership,timestamps,links",
                &from,
                &to,
            ],
        )
        .await?;
        let data = stage.child(STAGE_DATA)?;
        safefs::check_copyable(&data)?;
        let a = safefs::manifest(src)?;
        let b = safefs::manifest(&data)?;
        if a != b {
            bail!(
                "copy of {volume} differs: source {} entries/{} bytes/{}, copy {}/{}/{}",
                a.entries,
                a.bytes,
                &a.digest[..12],
                b.entries,
                b.bytes,
                &b.digest[..12]
            );
        }
        Ok(format!(
            "staged {}: {} entries, {} bytes, content manifest {}",
            app.path().join(&sname).display(),
            a.entries,
            a.bytes,
            &a.digest[..12]
        ))
    }
    .await;
    if copied.is_err() {
        discard_stage(&app, &stage, &sname).ok();
    }
    copied
}

/// Remove this run's staged copy of `suffix`. An exposed copy has no stage,
/// so it is never removed here.
pub fn remove_staged(app: &Dir, nonce: &str, suffix: &str) -> Result<String> {
    let stage = open_stage(app, nonce, suffix)?.ok_or_else(|| {
        anyhow!(
            "no staged copy for {}; an exposed copy is never removed",
            app.path().join(suffix).display()
        )
    })?;
    discard_stage(app, &stage, &stage_name(nonce, suffix))?;
    Ok(format!("removed staged copy for {suffix}"))
}

/// Move this run's staged copy to `<name>/<suffix>` and drop the stage.
pub fn expose_staged(app: &Dir, nonce: &str, suffix: &str) -> Result<String> {
    let stage =
        open_stage(app, nonce, suffix)?.ok_or_else(|| anyhow!("no staged copy for {suffix}"))?;
    stage.rename_into(STAGE_DATA, app, suffix)?;
    stage.remove_file(STAGE_TOKEN)?;
    app.remove_empty_dir(&stage_name(nonce, suffix))?;
    Ok(format!("exposed {}", app.path().join(suffix).display()))
}

fn appdata_dir() -> Result<Dir> {
    Dir::open(Path::new(APPDATA))
}

fn app_dir(name: &str) -> Result<Dir> {
    validate_name("container name", name)?;
    appdata_dir()?.child(name)
}

/// Retire stack `dir_name` from the held stacks `root` into `retired`,
/// both directories root-owned and not group/world-writable.
pub fn retire_pinned(root: &Dir, dir_name: &str, retired: &Dir, to_name: &str) -> Result<()> {
    if let Some(why) = root.root_owned_problem()? {
        bail!("refusing to retire a stack: {why}");
    }
    if let Some(why) = retired.root_owned_problem()? {
        bail!(
            "refusing to retire a stack into a pre-existing {}: {why}; remove it or fix its \
             owner and mode",
            retired.path().display()
        );
    }
    root.rename_into(dir_name, retired, to_name)
}

/// `dir/<file name of path>`: the template-side paths, rooted at `dir`.
fn in_dir(dir: &Path, path: &str) -> PathBuf {
    dir.join(Path::new(path).file_name().unwrap_or_default())
}

pub fn write_template_in(dir: &Path, name: &str, xml: &str, backup_id: &str) -> Result<String> {
    validate_name("container name", name)?;
    validate_run_id(backup_id)?;
    check_template(name, xml)?;
    let path = in_dir(dir, &template::template_path(name));
    let saved = match safefs::read_file(&path)? {
        Some(old) => {
            let bak = in_dir(dir, &template::backup_path(name, backup_id));
            safefs::create_new_file(&bak, &old, 0o600)?;
            format!("backed up to {}", bak.display())
        }
        None => {
            safefs::create_new_file(&in_dir(dir, &none_sentinel(name, backup_id)), b"", 0o600)?;
            "no previous template".to_string()
        }
    };
    safefs::replace_file(&path, xml.as_bytes(), 0o600)?;
    Ok(format!("{saved}; wrote {}", path.display()))
}

pub fn save_inspect_in(dir: &Path, name: &str, json: &str, backup_id: &str) -> Result<String> {
    validate_name("container name", name)?;
    validate_run_id(backup_id)?;
    let v: Value = serde_json::from_str(json).context("inspect JSON")?;
    let c: ContainerInspect = serde_json::from_value(v.clone())?;
    if c.short_name() != name {
        bail!("inspect is for {:?}, expected {name:?}", c.short_name());
    }
    let path = in_dir(dir, &template::inspect_backup_path(name, backup_id));
    safefs::create_new_file(&path, serde_json::to_string_pretty(&v)?.as_bytes(), 0o600)?;
    Ok(format!("saved {}", path.display()))
}

/// Undo `write_template_in` for `backup_id`. Errors, changing nothing, when
/// that run left neither a backup nor a "none" sentinel.
pub fn restore_template_in(dir: &Path, name: &str, backup_id: &str) -> Result<String> {
    validate_name("container name", name)?;
    validate_run_id(backup_id)?;
    let path = in_dir(dir, &template::template_path(name));
    let bak = in_dir(dir, &template::backup_path(name, backup_id));
    if let Some(old) = safefs::read_file(&bak)? {
        safefs::replace_file(&path, &old, 0o600)?;
        return Ok(format!(
            "restored {} from {}",
            path.display(),
            bak.display()
        ));
    }
    let sentinel = in_dir(dir, &none_sentinel(name, backup_id));
    if safefs::read_file(&sentinel)?.is_some() {
        let cur = safefs::read_file(&path)?.unwrap_or_default();
        if !cur.is_empty() && !String::from_utf8_lossy(&cur).contains(MANAGED_MARKER) {
            bail!("{} is not orca's; left in place", path.display());
        }
        safefs::remove_file(&path)?;
        safefs::remove_file(&sentinel)?;
        return Ok(format!("removed orca-written {}", path.display()));
    }
    bail!(
        "no backup for run {backup_id}; {} was not restored",
        path.display()
    )
}

async fn ensure_stopped(name: &str) -> Result<()> {
    let (c, _) = host::inspect_container_raw(name).await?;
    if c.short_name() != name {
        bail!("{name} resolved to {}", c.short_name());
    }
    if c.state.running {
        bail!("{name} is running; it must stay stopped while its volumes are copied");
    }
    Ok(())
}

async fn containers_using_volume(volume: &str) -> Result<Vec<String>> {
    let out = host::docker(&[
        "ps",
        "-a",
        "--filter",
        &format!("volume={volume}"),
        "--format",
        "{{.Names}}",
    ])
    .await?;
    Ok(out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

/// Run one op as root. Every input is re-validated here, and every file
/// touched goes through [`safefs`].
pub async fn execute(op: &PrivilegedOp) -> Result<String> {
    match op {
        PrivilegedOp::Ping => Ok("root".to_string()),
        // Trust boundary: the template's ExtraParams reach `docker run` via
        // Rebuild, so writing one is equivalent to starting a root container.
        // That grants nothing beyond what the caller already has: the orca
        // user is in the docker group. The checks here pin the file's
        // identity and location, not its content.
        PrivilegedOp::WriteTemplate {
            name,
            xml,
            backup_id,
        } => write_template_in(Path::new(template::TEMPLATES_DIR), name, xml, backup_id),
        PrivilegedOp::SaveInspect {
            name,
            json,
            backup_id,
        } => save_inspect_in(Path::new(template::TEMPLATES_DIR), name, json, backup_id),
        PrivilegedOp::RestoreTemplate { name, backup_id } => {
            restore_template_in(Path::new(template::TEMPLATES_DIR), name, backup_id)
        }
        PrivilegedOp::SetAutostart { name, on } => {
            validate_name("container name", name)?;
            let file = Path::new(AUTOSTART_FILE);
            let cur = safefs::read_file(file)?.unwrap_or_default();
            match host::autostart_with(&String::from_utf8_lossy(&cur), name, *on) {
                None => Ok("unchanged".to_string()),
                Some(next) => {
                    safefs::replace_file(file, next.as_bytes(), 0o644)?;
                    Ok(if *on { "added" } else { "removed" }.to_string())
                }
            }
        }
        PrivilegedOp::Rebuild { name } => {
            validate_name("container name", name)?;
            if safefs::read_file(Path::new(&template::template_path(name)))?.is_none() {
                bail!("no template for {name}");
            }
            host::run(REBUILD_SCRIPT, &[name])
                .await
                .map(|o| o.trim().to_string())
        }
        PrivilegedOp::ClearIconCache { name } => {
            validate_name("container name", name)?;
            let mut removed = Vec::new();
            for dir in host::ICON_CACHES {
                let p = Path::new(dir).join(format!("{name}-icon.png"));
                if safefs::remove_file(&p)? {
                    removed.push(p.display().to_string());
                }
            }
            Ok(format!("removed [{}]", removed.join(", ")))
        }
        PrivilegedOp::RefreshIcons => host::refresh_icons().await.map(|_| "refreshed".into()),
        PrivilegedOp::CopyVolume {
            name,
            volume,
            dest_suffix,
            nonce,
        } => {
            validate_name("container name", name)?;
            validate_name("volume", volume)?;
            validate_name("destination", dest_suffix)?;
            validate_nonce(nonce)?;
            ensure_stopped(name).await?;
            let v = host::inspect_volume(volume).await?;
            let src_path = VolumeInspect::expected_mountpoint(volume);
            if v.driver != "local" || v.options.as_ref().is_some_and(|o| !o.is_empty()) {
                bail!("volume {volume} is not a plain local volume");
            }
            if v.mountpoint != src_path {
                bail!("volume {volume} data is not at {src_path}");
            }
            let src = Dir::open(Path::new(&src_path))?;
            src.proc_path()?;
            let users = containers_using_volume(volume).await?;
            if users.iter().any(|u| u != name) {
                bail!("volume {volume} is also used by [{}]", users.join(", "));
            }
            let planned = Path::new(APPDATA).join(name).join(dest_suffix);
            let mounted = orphans::binds_overlapping(&planned, &host::inspect_all().await?);
            if !mounted.is_empty() {
                bail!(
                    "{} overlaps bind mounts ({})",
                    planned.display(),
                    mounted.into_iter().collect::<Vec<_>>().join(", ")
                );
            }
            ensure_stopped(name).await?;
            let appdata = appdata_dir()?;
            let staged = stage_copy(&appdata, &src, name, dest_suffix, volume, nonce).await?;
            if let Err(e) = ensure_stopped(name).await {
                remove_staged(&appdata.child(name)?, nonce, dest_suffix).ok();
                return Err(e.context("container started during the copy; copy discarded"));
            }
            Ok(staged)
        }
        PrivilegedOp::RemoveCopy {
            name,
            dest_suffix,
            nonce,
        } => remove_staged(&app_dir(name)?, nonce, dest_suffix),
        PrivilegedOp::ExposeCopy {
            name,
            dest_suffix,
            nonce,
        } => expose_staged(&app_dir(name)?, nonce, dest_suffix),
        PrivilegedOp::RetireStack {
            name,
            project,
            dir,
            to,
            run_id,
        } => {
            validate_name("container name", name)?;
            validate_name("compose project", project)?;
            validate_run_id(run_id)?;
            let dir = Path::new(dir);
            let (Some(parent), Some(dir_name)) =
                (dir.parent(), dir.file_name().and_then(|n| n.to_str()))
            else {
                bail!("{} is not a stack directory", dir.display());
            };
            let root_path = orphans::stacks_roots()
                .iter()
                .filter_map(|r| fs::canonicalize(r).ok())
                .find(|r| r == parent)
                .ok_or_else(|| {
                    anyhow!(
                        "{} is not directly under a configured stacks root",
                        dir.display()
                    )
                })?;
            let root = Dir::open(&root_path)?;
            let stack = root.child(dir_name)?;
            let compose = orphans::COMPOSE_FILES
                .iter()
                .find_map(|f| stack.read_file(f).ok().flatten())
                .ok_or_else(|| anyhow!("{} has no compose file", dir.display()))?;
            if !orphans::compose_matches(dir, project, &String::from_utf8_lossy(&compose)) {
                bail!("{} is not compose project {project}", dir.display());
            }
            let members = host::docker(&[
                "ps",
                "-aq",
                "--filter",
                &format!("label={COMPOSE_PROJECT}={project}"),
            ])
            .await?;
            if !members.trim().is_empty() {
                bail!("compose project {project} still has containers");
            }
            if !orphans::binds_under(dir, &host::inspect_all().await?).is_empty() {
                bail!("{} is still bind-mounted", dir.display());
            }
            let want = orphans::retire_target(dir, name, &run_id[..8])
                .ok_or_else(|| anyhow!("no retire target for {}", dir.display()))?;
            if Path::new(to) != want {
                bail!("planned target {to} != {}", want.display());
            }
            let (Some(retired_path), Some(to_name)) =
                (want.parent(), want.file_name().and_then(|n| n.to_str()))
            else {
                bail!("{} has no parent", want.display());
            };
            let (Some(top), Some(retired_name)) = (
                retired_path.parent(),
                retired_path.file_name().and_then(|n| n.to_str()),
            ) else {
                bail!("{} has no parent", retired_path.display());
            };
            if let Some(why) = root.root_owned_problem()? {
                bail!("refusing to retire a stack: {why}");
            }
            let retired = Dir::open(top)?
                .ensure_child(retired_name, 0o755)
                .with_context(|| {
                    format!(
                        "pre-existing {} is not a usable directory; remove it",
                        retired_path.display()
                    )
                })?;
            retire_pinned(&root, dir_name, &retired, to_name)?;
            Ok(format!("moved {} to {}", dir.display(), want.display()))
        }
    }
}

/// The `--privileged-op` entry: one `{op, payload}` request (a `plugin` key
/// from the core seam is ignored) in, one [`PrivilegedReply`] out.
pub async fn serve_one(input: &str) -> PrivilegedReply {
    let result = async {
        if host::euid() != Some(0) {
            bail!("{PRIVILEGED_FLAG} must run as root");
        }
        let mut v: Value = serde_json::from_str(input).context("decode request")?;
        if let Some(o) = v.as_object_mut() {
            o.remove("plugin");
        }
        let op: PrivilegedOp = serde_json::from_value(v).context("decode op")?;
        execute(&op).await
    }
    .await;
    match result {
        Ok(detail) => PrivilegedReply {
            ok: true,
            detail: Some(detail),
            error: None,
        },
        Err(e) => PrivilegedReply {
            ok: false,
            detail: None,
            error: Some(format!("{e:#}")),
        },
    }
}

pub trait PrivilegedRunner: Send + Sync {
    fn kind(&self) -> &'static str;
    fn run<'a>(&'a self, op: &'a PrivilegedOp) -> BoxFuture<'a, Result<String>>;
}

/// The plugin already runs as root.
pub struct Direct;

impl PrivilegedRunner for Direct {
    fn kind(&self) -> &'static str {
        "direct (running as root)"
    }
    fn run<'a>(&'a self, op: &'a PrivilegedOp) -> BoxFuture<'a, Result<String>> {
        Box::pin(execute(op))
    }
}

/// `sudo -n $ORCA_BIN admin plugin-apply` with `{plugin, op, payload}` on stdin.
pub struct Sudo {
    pub orca_bin: String,
}

impl PrivilegedRunner for Sudo {
    fn kind(&self) -> &'static str {
        "sudo -n $ORCA_BIN admin plugin-apply (orca#762)"
    }
    fn run<'a>(&'a self, op: &'a PrivilegedOp) -> BoxFuture<'a, Result<String>> {
        Box::pin(self.run_sudo(op))
    }
}

impl Sudo {
    async fn run_sudo(&self, op: &PrivilegedOp) -> Result<String> {
        let mut req = serde_json::to_value(op)?;
        if let Some(o) = req.as_object_mut() {
            o.insert("plugin".to_string(), Value::from("unraid"));
        }
        let path = std::env::temp_dir().join(format!(
            "orca-unraid-privileged-{}.json",
            host::random_suffix()
        ));
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .and_then(|mut f| f.write_all(serde_json::to_string(&req)?.as_bytes()))
                .with_context(|| format!("write {}", path.display()))?;
        }
        // The seam reads the request from stdin until EOF; a file redirect gives
        // it a clean EOF. Both values are positional args, never interpolated
        // into the script, and both programs are absolute paths.
        let out = Command::new("/bin/sh")
            .args([
                "-c",
                r#"exec /usr/bin/sudo -n "$0" admin plugin-apply < "$1""#,
                &self.orca_bin,
                &path.to_string_lossy(),
            ])
            .output()
            .await;
        fs::remove_file(&path).ok();
        let out = out.context("spawn sudo")?;
        parse_reply(
            out.status.success,
            out.status.code,
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
        )
    }
}

/// Success needs both a zero exit and an `ok: true` reply.
pub fn parse_reply(success: bool, code: Option<i32>, stdout: &str, stderr: &str) -> Result<String> {
    let reply: Option<PrivilegedReply> = stdout
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str(l.trim()).ok());
    match reply {
        Some(PrivilegedReply {
            ok: true, detail, ..
        }) if success => Ok(detail.unwrap_or_default()),
        Some(PrivilegedReply { ok: true, .. }) => {
            bail!(
                "privileged seam exited {code:?} despite an ok reply: {}",
                stderr.trim()
            )
        }
        Some(PrivilegedReply { error, .. }) => {
            bail!("{}", error.unwrap_or_else(|| "privileged op failed".into()))
        }
        None => bail!(
            "privileged seam gave no reply (exit {code:?}): {}",
            stderr.trim()
        ),
    }
}

/// The root path available to this process, if any.
pub fn runner() -> Option<Box<dyn PrivilegedRunner>> {
    if host::euid() == Some(0) {
        return Some(Box::new(Direct));
    }
    let bin = std::env::var(ORCA_BIN_ENV).ok()?;
    (Path::new(&bin).is_absolute() && Path::new(&bin).is_file())
        .then(|| Box::new(Sudo { orca_bin: bin }) as Box<dyn PrivilegedRunner>)
}

/// Blocker text when no root path exists.
pub fn missing_runner_blocker() -> String {
    format!(
        "needs a root path: the plugin is not root and {ORCA_BIN_ENV} is not set, so the \
         orca#762 privileged seam (`sudo -n $ORCA_BIN admin plugin-apply`) is unavailable"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_round_trip_as_op_and_payload() {
        let op = PrivilegedOp::SetAutostart {
            name: "pbs".into(),
            on: true,
        };
        let v = serde_json::to_value(&op).unwrap();
        assert_eq!(v["op"], "set_autostart");
        assert_eq!(v["payload"]["name"], "pbs");
        let back: PrivilegedOp = serde_json::from_value(v).unwrap();
        assert_eq!(back, op);
        let ping = serde_json::to_value(PrivilegedOp::Ping).unwrap();
        assert_eq!(ping["op"], "ping");
    }

    #[test]
    fn template_check_pins_the_name() {
        let ok = "<?xml version=\"1.0\"?>\n<Container version=\"2\">\n  <Name>pbs</Name>\n</Container>\n";
        assert!(check_template("pbs", ok).is_ok());
        assert!(check_template("other", ok).is_err());
        assert!(check_template("pbs", "<Name>pbs</Name>").is_err());
        let two = ok.replace("</Container>", "<Name>x</Name></Container>");
        assert!(check_template("pbs", &two).is_err());
    }

    fn appdata() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(d.path()).unwrap();
        (d, root)
    }

    const NONCE: &str = "0123456789abcdef";

    fn open(p: &Path) -> Dir {
        Dir::open(p).unwrap()
    }

    fn stage_of(root: &Path) -> PathBuf {
        root.join("pbs").join(stage_name(NONCE, "config"))
    }

    #[test]
    fn stages_are_fresh_private_and_tokened() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, root) = appdata();
        let (_app, stage) = create_stage(&open(&root), "pbs", "config", NONCE).unwrap();
        assert_eq!(stage.path(), stage_of(&root));
        assert_eq!(
            fs::metadata(stage_of(&root)).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(!stage_of(&root).to_string_lossy().contains(NONCE));
        assert!(create_stage(&open(&root), "pbs", "config", NONCE).is_err());
        for bad in ["..", "a/b", ".hidden", ""] {
            assert!(
                create_stage(&open(&root), "pbs", bad, NONCE).is_err(),
                "{bad}"
            );
        }
        assert!(create_stage(&open(&root), "../etc", "x", NONCE).is_err());
        fs::create_dir(root.join("pbs/logs")).unwrap();
        let e = create_stage(&open(&root), "pbs", "logs", NONCE).unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
    }

    #[test]
    fn planted_symlinks_never_redirect_a_stage() {
        use std::os::unix::fs::symlink;
        let (_d, root) = appdata();
        let (_o, outside) = appdata();
        fs::create_dir(root.join("pbs")).unwrap();
        symlink(&outside, stage_of(&root)).unwrap();
        assert!(create_stage(&open(&root), "pbs", "config", NONCE).is_err());

        let (_d2, root2) = appdata();
        symlink(&outside, root2.join("pbs")).unwrap();
        assert!(create_stage(&open(&root2), "pbs", "config", NONCE).is_err());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }

    /// The attack from the review: after every check, `<appdata>/<name>` is
    /// renamed away and replaced by a symlink to somewhere else.
    fn swap_app_for_symlink(root: &Path, outside: &Path) {
        fs::rename(root.join("pbs"), root.join("pbs-moved")).unwrap();
        std::os::unix::fs::symlink(outside, root.join("pbs")).unwrap();
    }

    #[test]
    fn an_ancestor_swap_after_the_checks_cannot_redirect_writes() {
        let (_d, root) = appdata();
        let (_o, outside) = appdata();
        let (_app, stage) = create_stage(&open(&root), "pbs", "config", NONCE).unwrap();
        swap_app_for_symlink(&root, &outside);
        stage.create_child(STAGE_DATA, 0o700).unwrap();
        assert!(
            root.join("pbs-moved")
                .join(stage_name(NONCE, "config"))
                .join(STAGE_DATA)
                .exists()
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        assert!(app_dir_at(&root, "pbs").is_err());
    }

    fn app_dir_at(root: &Path, name: &str) -> Result<Dir> {
        open(root).child(name)
    }

    #[test]
    fn a_swapped_in_stage_is_refused_and_left_alone() {
        let (_d, root) = appdata();
        fs::create_dir_all(root.join("pbs/secrets/data")).unwrap();
        fs::write(root.join("pbs/secrets/data/key"), b"keep").unwrap();
        // Someone renames another directory of `<name>` to the stage's name.
        fs::rename(root.join("pbs/secrets"), stage_of(&root)).unwrap();
        use std::os::unix::fs::PermissionsExt;
        // Same owner and mode as a real stage; only the token is missing.
        fs::set_permissions(stage_of(&root), fs::Permissions::from_mode(0o700)).unwrap();
        let app = app_dir_at(&root, "pbs").unwrap();
        assert!(remove_staged(&app, NONCE, "config").is_err());
        assert!(expose_staged(&app, NONCE, "config").is_err());
        assert!(stage_of(&root).join("data/key").exists());
        assert!(!root.join("pbs/config").exists());

        // Right owner and token, wrong mode: still refused.
        fs::remove_dir_all(stage_of(&root)).unwrap();
        let (_a, _s) = create_stage(&open(&root), "pbs", "config", NONCE).unwrap();
        fs::set_permissions(stage_of(&root), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(remove_staged(&app, NONCE, "config").is_err());
    }

    #[test]
    fn staged_copies_are_removed_only_by_their_own_run() {
        let (_d, root) = appdata();
        let (app, stage) = create_stage(&open(&root), "pbs", "config", NONCE).unwrap();
        let data = stage.create_child(STAGE_DATA, 0o755).unwrap();
        data.create_child("a", 0o755)
            .unwrap()
            .create_file("f", b"x", 0o644)
            .unwrap();
        assert!(remove_staged(&app, "fedcba9876543210", "config").is_err());
        assert!(stage_of(&root).exists());
        remove_staged(&app, NONCE, "config").unwrap();
        assert!(!stage_of(&root).exists());
        assert!(remove_staged(&app, NONCE, "config").is_err());
    }

    #[test]
    fn exposed_copies_cannot_be_removed() {
        let (_d, root) = appdata();
        let (app, stage) = create_stage(&open(&root), "pbs", "config", NONCE).unwrap();
        stage
            .create_child(STAGE_DATA, 0o755)
            .unwrap()
            .create_file("f", b"x", 0o644)
            .unwrap();
        expose_staged(&app, NONCE, "config").unwrap();
        assert!(root.join("pbs/config/f").exists());
        assert!(!stage_of(&root).exists());
        let e = remove_staged(&app, NONCE, "config")
            .unwrap_err()
            .to_string();
        assert!(e.contains("never removed"), "{e}");
        assert!(root.join("pbs/config/f").exists());
    }

    #[test]
    fn expose_never_replaces_an_existing_destination() {
        let (_d, root) = appdata();
        let (app, stage) = create_stage(&open(&root), "pbs", "config", NONCE).unwrap();
        stage.create_child(STAGE_DATA, 0o755).unwrap();
        fs::create_dir(root.join("pbs/config")).unwrap();
        assert!(expose_staged(&app, NONCE, "config").is_err());
        assert!(stage_of(&root).join(STAGE_DATA).exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stage_copy_drops_extended_attributes() {
        let (_d, root) = appdata();
        let (_s, src) = appdata();
        fs::write(src.join("f"), b"x").unwrap();
        let set = rustix::fs::setxattr(
            src.join("f").as_path(),
            "user.orca-test",
            b"1",
            rustix::fs::XattrFlags::empty(),
        );
        if set.is_err() {
            return; // filesystem without user xattrs
        }
        stage_copy(&open(&root), &open(&src), "pbs", "config", "v", NONCE)
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        let got = rustix::fs::getxattr(
            stage_of(&root).join("data/f").as_path(),
            "user.orca-test",
            &mut buf[..],
        );
        assert!(got.is_err(), "xattrs were carried into the copy");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stage_copy_copies_verifies_and_discards_on_refusal() {
        let (_d, root) = appdata();
        let (_s, src) = appdata();
        fs::create_dir(src.join("sub")).unwrap();
        fs::write(src.join("sub/f"), b"payload").unwrap();
        stage_copy(&open(&root), &open(&src), "pbs", "config", "v", NONCE)
            .await
            .unwrap();
        assert_eq!(
            fs::read(stage_of(&root).join("data/sub/f")).unwrap(),
            b"payload"
        );

        let (_d2, root2) = appdata();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(src.join("p"))
                .status()
                .unwrap()
                .success()
        );
        let e = stage_copy(&open(&root2), &open(&src), "pbs", "config", "v", NONCE)
            .await
            .unwrap_err()
            .to_string();
        // Refused while scanning the source, before anything is copied.
        assert!(e.contains(&src.join("p").display().to_string()), "{e}");
        assert!(!root2.join("pbs").join(stage_name(NONCE, "config")).exists());
    }

    #[test]
    fn retire_moves_between_held_directories_and_checks_ownership() {
        let (_d, root) = appdata();
        fs::create_dir_all(root.join("stacks/web")).unwrap();
        fs::create_dir(root.join("stacks-retired")).unwrap();
        let stacks = open(&root.join("stacks"));
        let retired = open(&root.join("stacks-retired"));
        let r = retire_pinned(&stacks, "web", &retired, "web-compose-20261004");
        if host::euid() == Some(0) {
            r.unwrap();
            assert!(root.join("stacks-retired/web-compose-20261004").exists());
            use std::os::unix::fs::PermissionsExt;
            fs::create_dir(root.join("stacks/api")).unwrap();
            fs::set_permissions(
                root.join("stacks-retired"),
                fs::Permissions::from_mode(0o777),
            )
            .unwrap();
            let e = retire_pinned(&stacks, "api", &retired, "api-x")
                .unwrap_err()
                .to_string();
            assert!(e.contains("pre-existing"), "{e}");
        } else {
            let e = r.unwrap_err().to_string();
            assert!(e.contains("must be root-owned"), "{e}");
            assert!(root.join("stacks/web").exists());
        }
    }

    const RUN: &str = "20261004-120000-0123abcd";
    const TPL: &str = "<?xml version=\"1.0\"?>\n<Container version=\"2\">\n  <Name>pbs</Name>\n  <!-- managed-by: orca -->\n</Container>\n";

    #[test]
    fn template_writes_back_up_per_run_and_restore_exactly_that() {
        let (_d, dir) = appdata();
        let tpl = dir.join("my-pbs.xml");
        fs::write(&tpl, "old").unwrap();
        write_template_in(&dir, "pbs", TPL, RUN).unwrap();
        assert_eq!(fs::read_to_string(&tpl).unwrap(), TPL);
        assert_eq!(
            fs::read_to_string(dir.join(format!("my-pbs.xml.bak-{RUN}"))).unwrap(),
            "old"
        );
        // A second write in the same run must not clobber the backup.
        assert!(write_template_in(&dir, "pbs", TPL, RUN).is_err());
        assert!(restore_template_in(&dir, "pbs", "20261004-120001-0123abcd").is_err());
        assert_eq!(fs::read_to_string(&tpl).unwrap(), TPL);
        restore_template_in(&dir, "pbs", RUN).unwrap();
        assert_eq!(fs::read_to_string(&tpl).unwrap(), "old");
    }

    #[test]
    fn restore_without_a_prior_template_removes_only_orcas() {
        let (_d, dir) = appdata();
        let tpl = dir.join("my-pbs.xml");
        write_template_in(&dir, "pbs", TPL, RUN).unwrap();
        restore_template_in(&dir, "pbs", RUN).unwrap();
        assert!(!tpl.exists());

        write_template_in(&dir, "pbs", TPL, "20261004-120002-0123abcd").unwrap();
        fs::write(&tpl, "<Container><Name>pbs</Name></Container>").unwrap();
        assert!(restore_template_in(&dir, "pbs", "20261004-120002-0123abcd").is_err());
        assert!(tpl.exists());
    }

    #[test]
    fn saved_inspect_is_never_overwritten() {
        let (_d, dir) = appdata();
        let json = r#"{"Id":"x","Name":"/pbs"}"#;
        save_inspect_in(&dir, "pbs", json, RUN).unwrap();
        assert!(save_inspect_in(&dir, "pbs", json, RUN).is_err());
        assert!(
            save_inspect_in(
                &dir,
                "pbs",
                r#"{"Id":"x","Name":"/other"}"#,
                "20261004-120003-0123abcd"
            )
            .is_err()
        );
        assert!(save_inspect_in(&dir, "pbs", json, "../../etc/passwd").is_err());
    }

    #[test]
    fn run_ids_and_nonces_are_strict() {
        let id = new_run_id();
        assert!(validate_run_id(&id).is_ok(), "{id}");
        for bad in [
            "20261304-120000-0123abcd",
            "20260230-120000-0123abcd",
            "20261004-250000-0123abcd",
            "20261004-126000-0123abcd",
            "",
            "20261004",
            "20261004-120000-ABCDEF12",
            "20261004-120000-abcdef1/",
            "../../etc/x",
        ] {
            assert!(validate_run_id(bad).is_err(), "{bad}");
        }
        assert!(validate_run_id("20240229-235959-0123abcd").is_ok());
        assert!(validate_run_id("20230229-000000-0123abcd").is_err());
        assert!(validate_nonce(NONCE).is_ok());
        assert!(validate_nonce("xyz").is_err());
    }

    #[test]
    fn replies_need_zero_exit_and_ok() {
        let ok = r#"{"ok":true,"detail":"root"}"#;
        assert_eq!(parse_reply(true, Some(0), ok, "").unwrap(), "root");
        assert!(parse_reply(false, Some(1), ok, "").is_err());
        assert!(parse_reply(true, Some(0), r#"{"ok":false,"error":"no"}"#, "").is_err());
        assert!(parse_reply(true, Some(0), "", "").is_err());
    }

    #[tokio::test]
    async fn privileged_mode_refuses_non_root_and_garbage() {
        let r = serve_one(r#"{"plugin":"unraid","op":"ping"}"#).await;
        if host::euid() != Some(0) {
            assert!(!r.ok);
            assert!(r.error.unwrap().contains("must run as root"));
        }
        let r = serve_one("not json").await;
        assert!(!r.ok);
    }
}
