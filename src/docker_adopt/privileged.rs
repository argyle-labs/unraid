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
use std::io::Write;
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
    /// Copy a stopped container's local docker volume into
    /// `/mnt/user/appdata/<name>/<dest_suffix>` and verify the copy.
    CopyVolume {
        name: String,
        volume: String,
        dest_suffix: String,
        nonce: String,
    },
    /// Remove a copy this run's CopyVolume made, while nothing mounts it.
    RemoveCopy {
        name: String,
        dest_suffix: String,
        nonce: String,
    },
    /// Accept this run's copy: drop its marker so it can no longer be removed.
    CommitCopy {
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

fn marker_name(suffix: &str) -> String {
    format!(".orca-copy-{suffix}")
}

/// A copy in progress: `<appdata>/<name>` and its fresh destination, both
/// held open so a swapped path cannot redirect the copy.
#[derive(Debug)]
pub struct CopyDest {
    pub app: Dir,
    pub dest: Dir,
}

/// The appdata side of CopyVolume, under the held `appdata` directory: open
/// (or create) `<name>`, claim the copy with an exclusive marker holding the
/// volume and this run's nonce, create the destination 0700 so nothing else
/// can write into it mid-copy, and record its identity in the marker.
pub fn prepare_copy_dest(
    appdata: &Dir,
    name: &str,
    suffix: &str,
    volume: &str,
    nonce: &str,
) -> Result<CopyDest> {
    validate_name("container name", name)?;
    validate_name("destination", suffix)?;
    validate_nonce(nonce)?;
    let app = appdata.ensure_child(name, 0o755)?;
    let mut marker = app
        .create_file_open(&marker_name(suffix), 0o600)
        .context("a copy marker already exists (stale run?); inspect it before retrying")?;
    marker.write_all(format!("{volume}\n{nonce}\n").as_bytes())?;
    let dest = app.create_child(suffix, 0o700)?;
    let (dev, ino) = dest.identity()?;
    marker.write_all(format!("{dev}:{ino}\n").as_bytes())?;
    marker.sync_all()?;
    Ok(CopyDest { app, dest })
}

/// `cp -a` the held `src` into the held destination and verify the copy.
/// Both are passed to `cp` as `/proc/<pid>/fd/<n>`, so it writes exactly
/// where the descriptors point.
pub async fn copy_pinned(src: &Dir, cd: &CopyDest, volume: &str) -> Result<String> {
    let from = format!("{}/.", src.proc_path()?);
    host::run("/bin/cp", &["-a", &from, &cd.dest.proc_path()?]).await?;
    let a = safefs::manifest(src)?;
    let b = safefs::manifest(&cd.dest)?;
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
        "copied to {}: {} entries, {} bytes, content manifest {}",
        cd.dest.path().display(),
        a.entries,
        a.bytes,
        &a.digest[..12]
    ))
}

/// Check this run's marker for `suffix` in the held `<name>` directory;
/// returns the destination identity it recorded, if it got that far.
pub fn check_copy_marker(app: &Dir, suffix: &str, nonce: &str) -> Result<Option<(u64, u64)>> {
    validate_name("destination", suffix)?;
    validate_nonce(nonce)?;
    let body = app
        .read_file(&marker_name(suffix))?
        .ok_or_else(|| anyhow!("{} has no copy marker", app.path().join(suffix).display()))?;
    let body = String::from_utf8_lossy(&body);
    let mut lines = body.lines();
    if lines.nth(1) != Some(nonce) {
        bail!("copy marker for {suffix} belongs to another run");
    }
    Ok(lines.next().and_then(|l| {
        let (d, i) = l.split_once(':')?;
        Some((d.parse().ok()?, i.parse().ok()?))
    }))
}

/// Remove this run's copy `<name>/<suffix>` unless `mounted`. Only the very
/// directory this run created is emptied, by descriptor.
pub fn remove_copy(app: &Dir, suffix: &str, nonce: &str, mounted: &[String]) -> Result<String> {
    let id = check_copy_marker(app, suffix, nonce)?;
    let shown = app.path().join(suffix);
    if !mounted.is_empty() {
        bail!("{} is mounted ({})", shown.display(), mounted.join(", "));
    }
    if let Some(dest) = app.child_opt(suffix)? {
        if Some(dest.identity()?) != id {
            bail!("{} is not the directory this run created", shown.display());
        }
        dest.clear()?;
        if Some(app.child(suffix)?.identity()?) != id {
            bail!("{} was replaced during removal", shown.display());
        }
        app.remove_empty_dir(suffix)?;
    }
    app.remove_file(&marker_name(suffix))?;
    Ok(format!("removed {}", shown.display()))
}

/// Accept this run's copy: drop its marker so it can no longer be removed.
pub fn commit_copy(app: &Dir, suffix: &str, nonce: &str) -> Result<String> {
    check_copy_marker(app, suffix, nonce)?;
    app.remove_file(&marker_name(suffix))?;
    Ok(format!("committed {suffix}"))
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
    for d in [root, retired] {
        if let Some(why) = d.root_owned_problem()? {
            bail!("refusing to retire a stack: {why}");
        }
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
            let (c, _) = host::inspect_container_raw(name).await?;
            if c.short_name() != name {
                bail!("{name} resolved to {}", c.short_name());
            }
            if c.state.running {
                bail!("{name} is running; stop it before copying its volumes");
            }
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
            let cd = prepare_copy_dest(&appdata_dir()?, name, dest_suffix, volume, nonce)?;
            copy_pinned(&src, &cd, volume).await
        }
        PrivilegedOp::RemoveCopy {
            name,
            dest_suffix,
            nonce,
        } => {
            let app = app_dir(name)?;
            let planned = Path::new(APPDATA).join(name).join(dest_suffix);
            let mounted: Vec<String> =
                orphans::binds_overlapping(&planned, &host::inspect_all().await?)
                    .into_iter()
                    .collect();
            remove_copy(&app, dest_suffix, nonce, &mounted)
        }
        PrivilegedOp::CommitCopy {
            name,
            dest_suffix,
            nonce,
        } => commit_copy(&app_dir(name)?, dest_suffix, nonce),
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
            let retired = Dir::open(top)?.ensure_child(retired_name, 0o755)?;
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

    #[test]
    fn copy_destination_is_created_fresh_private_and_claimed() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, root) = appdata();
        let cd = prepare_copy_dest(&open(&root), "pbs", "config", "pbs-config", NONCE).unwrap();
        assert_eq!(cd.dest.path(), root.join("pbs/config"));
        assert_eq!(
            fs::metadata(root.join("pbs/config"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let id = check_copy_marker(&cd.app, "config", NONCE).unwrap();
        assert_eq!(id, Some(cd.dest.identity().unwrap()));
        assert!(prepare_copy_dest(&open(&root), "pbs", "config", "pbs-config", NONCE).is_err());
        for bad in ["..", "a/b", ".hidden", ""] {
            assert!(
                prepare_copy_dest(&open(&root), "pbs", bad, "v", NONCE).is_err(),
                "{bad}"
            );
        }
        assert!(prepare_copy_dest(&open(&root), "../etc", "x", "v", NONCE).is_err());
    }

    #[test]
    fn planted_symlinks_never_redirect_a_copy() {
        use std::os::unix::fs::symlink;
        let (_d, root) = appdata();
        let outside = root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::create_dir(root.join("pbs")).unwrap();

        symlink(&outside, root.join("pbs/config")).unwrap();
        assert!(prepare_copy_dest(&open(&root), "pbs", "config", "v", NONCE).is_err());
        fs::remove_file(root.join("pbs/.orca-copy-config")).ok();

        let victim = outside.join("go");
        fs::write(&victim, b"keep").unwrap();
        symlink(&victim, root.join("pbs/.orca-copy-logs")).unwrap();
        assert!(prepare_copy_dest(&open(&root), "pbs", "logs", "v", NONCE).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"keep");

        let (_d2, root2) = appdata();
        symlink(&outside, root2.join("pbs")).unwrap();
        assert!(prepare_copy_dest(&open(&root2), "pbs", "config", "v", NONCE).is_err());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
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
        let cd = prepare_copy_dest(&open(&root), "pbs", "config", "v", NONCE).unwrap();
        swap_app_for_symlink(&root, &outside);
        // Writes go through the held descriptor, into the moved directory.
        cd.dest.create_file("data", b"x", 0o600).unwrap();
        assert!(root.join("pbs-moved/config/data").exists());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_ancestor_swap_cannot_redirect_cp() {
        let (_d, root) = appdata();
        let (_o, outside) = appdata();
        let (_s, src) = appdata();
        fs::create_dir(src.join("sub")).unwrap();
        fs::write(src.join("sub/f"), b"payload").unwrap();
        let cd = prepare_copy_dest(&open(&root), "pbs", "config", "v", NONCE).unwrap();
        swap_app_for_symlink(&root, &outside);
        copy_pinned(&open(&src), &cd, "v").await.unwrap();
        assert_eq!(
            fs::read(root.join("pbs-moved/config/sub/f")).unwrap(),
            b"payload"
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[test]
    fn an_ancestor_swap_cannot_redirect_removal() {
        let (_d, root) = appdata();
        let (_o, outside) = appdata();
        fs::write(outside.join("precious"), b"keep").unwrap();
        fs::create_dir(outside.join("config")).unwrap();
        fs::write(outside.join("config/precious"), b"keep").unwrap();
        let cd = prepare_copy_dest(&open(&root), "pbs", "config", "v", NONCE).unwrap();
        cd.dest.create_file("f", b"x", 0o600).unwrap();
        drop(cd);
        swap_app_for_symlink(&root, &outside);
        // A fresh open (the RemoveCopy op) refuses the symlinked <name>.
        assert!(open(&root).child("pbs").is_err());
        // A directory held from before the swap removes only its own copy.
        let app = open(&root.join("pbs-moved"));
        remove_copy(&app, "config", NONCE, &[]).unwrap();
        assert!(!root.join("pbs-moved/config").exists());
        assert!(outside.join("precious").exists());
        assert!(outside.join("config/precious").exists());
    }

    #[test]
    fn removal_refuses_a_directory_this_run_did_not_create() {
        let (_d, root) = appdata();
        let cd = prepare_copy_dest(&open(&root), "pbs", "config", "v", NONCE).unwrap();
        // Someone renames our copy away and moves other data into its name.
        fs::rename(root.join("pbs/config"), root.join("pbs/ours")).unwrap();
        fs::create_dir(root.join("pbs/config")).unwrap();
        fs::write(root.join("pbs/config/theirs"), b"keep").unwrap();
        assert!(remove_copy(&cd.app, "config", NONCE, &[]).is_err());
        assert!(root.join("pbs/config/theirs").exists());
    }

    #[test]
    fn copies_are_removed_only_by_their_own_run_and_when_unmounted() {
        let (_d, root) = appdata();
        let cd = prepare_copy_dest(&open(&root), "pbs", "config", "pbs-config", NONCE).unwrap();
        cd.dest.create_file("f", b"x", 0o600).unwrap();
        fs::create_dir_all(root.join("pbs/config/a/b")).unwrap();
        let app = &cd.app;
        assert!(remove_copy(app, "config", "fedcba9876543210", &[]).is_err());
        assert!(remove_copy(app, "config", NONCE, &["/mnt/user/appdata/pbs".into()]).is_err());
        assert!(root.join("pbs/config").exists());
        remove_copy(app, "config", NONCE, &[]).unwrap();
        assert!(!root.join("pbs/config").exists());
        assert!(!root.join("pbs/.orca-copy-config").exists());
        assert!(remove_copy(app, "config", NONCE, &[]).is_err());
    }

    #[test]
    fn committed_copies_cannot_be_removed() {
        let (_d, root) = appdata();
        let cd = prepare_copy_dest(&open(&root), "pbs", "config", "v", NONCE).unwrap();
        assert!(commit_copy(&cd.app, "config", "fedcba9876543210").is_err());
        commit_copy(&cd.app, "config", NONCE).unwrap();
        assert!(remove_copy(&cd.app, "config", NONCE, &[]).is_err());
        assert!(root.join("pbs/config").exists());
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
