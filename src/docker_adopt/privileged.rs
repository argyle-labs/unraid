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
    /// Proves a root path exists before anything is changed.
    Ping,
    /// Write `my-<name>.xml`, first backing up an existing one to
    /// `.bak-<date>` (kept if today's backup already exists).
    WriteTemplate {
        name: String,
        xml: String,
    },
    /// Save the original `docker inspect` next to the template.
    SaveInspect {
        name: String,
        json: String,
    },
    /// Undo a WriteTemplate from today: restore the backup, or remove an
    /// orca-written template that had none.
    RestoreTemplate {
        name: String,
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
    /// Copy a local docker volume's data into `/mnt/user/appdata/<name>/<dest_suffix>`
    /// and verify the copy.
    CopyVolume {
        name: String,
        volume: String,
        dest_suffix: String,
    },
    /// Remove a copy CopyVolume made, while nothing mounts it.
    RemoveCopy {
        name: String,
        dest_suffix: String,
    },
    /// Move a compose stack directory to `<root>-retired/<name>-compose-<date>`.
    RetireStack {
        name: String,
        project: String,
        dir: String,
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

fn today() -> String {
    plugin_toolkit::lifecycle::timestamp()
        .chars()
        .take(8)
        .collect()
}

fn appdata_dest(name: &str, suffix: &str) -> Result<PathBuf> {
    validate_name("container name", name)?;
    validate_name("destination", suffix)?;
    Ok(Path::new(APPDATA).join(name).join(suffix))
}

fn copy_marker(name: &str, suffix: &str) -> PathBuf {
    Path::new(APPDATA)
        .join(name)
        .join(format!(".orca-copy-{suffix}"))
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

/// Run one op as root. Every input is re-validated here.
pub async fn execute(op: &PrivilegedOp) -> Result<String> {
    match op {
        PrivilegedOp::Ping => Ok("root".to_string()),
        PrivilegedOp::WriteTemplate { name, xml } => {
            validate_name("container name", name)?;
            check_template(name, xml)?;
            let path = PathBuf::from(template::template_path(name));
            let mut detail = String::new();
            if path.exists() {
                let bak = PathBuf::from(template::backup_path(name, &today()));
                if bak.exists() {
                    detail = format!("backup {} already exists; kept; ", bak.display());
                } else {
                    host::atomic_write(&bak, &fs::read(&path)?, 0o600)?;
                    detail = format!("backed up to {}; ", bak.display());
                }
            }
            host::atomic_write(&path, xml.as_bytes(), 0o600)?;
            Ok(format!("{detail}wrote {}", path.display()))
        }
        PrivilegedOp::SaveInspect { name, json } => {
            validate_name("container name", name)?;
            let v: Value = serde_json::from_str(json).context("inspect JSON")?;
            let c: ContainerInspect = serde_json::from_value(v.clone())?;
            if c.short_name() != name {
                bail!("inspect is for {:?}, expected {name:?}", c.short_name());
            }
            let path = PathBuf::from(template::inspect_backup_path(name, &today()));
            host::atomic_write(&path, serde_json::to_string_pretty(&v)?.as_bytes(), 0o600)?;
            Ok(format!("saved {}", path.display()))
        }
        PrivilegedOp::RestoreTemplate { name } => {
            validate_name("container name", name)?;
            let path = PathBuf::from(template::template_path(name));
            let bak = PathBuf::from(template::backup_path(name, &today()));
            if bak.exists() {
                host::atomic_write(&path, &fs::read(&bak)?, 0o600)?;
                return Ok(format!(
                    "restored {} from {}",
                    path.display(),
                    bak.display()
                ));
            }
            match fs::read_to_string(&path) {
                Ok(x) if x.contains(MANAGED_MARKER) => {
                    fs::remove_file(&path)?;
                    Ok(format!("removed orca-written {}", path.display()))
                }
                _ => Ok("nothing to restore".to_string()),
            }
        }
        PrivilegedOp::SetAutostart { name, on } => {
            validate_name("container name", name)?;
            let cur = fs::read_to_string(AUTOSTART_FILE).unwrap_or_default();
            match host::autostart_with(&cur, name, *on) {
                None => Ok("unchanged".to_string()),
                Some(next) => {
                    host::atomic_write(Path::new(AUTOSTART_FILE), next.as_bytes(), 0o644)?;
                    Ok(if *on { "added" } else { "removed" }.to_string())
                }
            }
        }
        PrivilegedOp::Rebuild { name } => {
            validate_name("container name", name)?;
            if !Path::new(&template::template_path(name)).is_file() {
                bail!("no template for {name}");
            }
            host::run(REBUILD_SCRIPT, &[name])
                .await
                .map(|o| o.trim().to_string())
        }
        PrivilegedOp::ClearIconCache { name } => {
            validate_name("container name", name)?;
            let removed = host::clear_icon_cache(name)?;
            Ok(format!("removed [{}]", removed.join(", ")))
        }
        PrivilegedOp::RefreshIcons => host::refresh_icons().await.map(|_| "refreshed".into()),
        PrivilegedOp::CopyVolume {
            name,
            volume,
            dest_suffix,
        } => {
            validate_name("volume", volume)?;
            let dest = appdata_dest(name, dest_suffix)?;
            let v = host::inspect_volume(volume).await?;
            let src = VolumeInspect::expected_mountpoint(volume);
            if v.driver != "local" || v.options.as_ref().is_some_and(|o| !o.is_empty()) {
                bail!("volume {volume} is not a plain local volume");
            }
            if v.mountpoint != src || fs::canonicalize(&src)? != Path::new(&src) {
                bail!("volume {volume} data is not at {src}");
            }
            let users = containers_using_volume(volume).await?;
            if users.iter().any(|u| u != name) {
                bail!("volume {volume} is also used by [{}]", users.join(", "));
            }
            let parent = Path::new(APPDATA).join(name);
            fs::create_dir_all(&parent)?;
            if !fs::canonicalize(&parent)?.starts_with(fs::canonicalize(APPDATA)?) {
                bail!("{} escapes {APPDATA}", parent.display());
            }
            if host::is_nonempty_dir(&dest) {
                bail!("{} already has content", dest.display());
            }
            fs::write(copy_marker(name, dest_suffix), volume)?;
            fs::create_dir_all(&dest)?;
            let dest_s = dest.to_string_lossy().into_owned();
            host::run("cp", &["-a", &format!("{src}/."), &dest_s]).await?;
            let a = host::manifest(Path::new(&src))?;
            let b = host::manifest(&dest)?;
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
                "copied to {dest_s}: {} entries, {} bytes, manifest {}",
                a.entries,
                a.bytes,
                &a.digest[..12]
            ))
        }
        PrivilegedOp::RemoveCopy { name, dest_suffix } => {
            let dest = appdata_dest(name, dest_suffix)?;
            let marker = copy_marker(name, dest_suffix);
            if !marker.is_file() {
                bail!("{} was not made by CopyVolume", dest.display());
            }
            let binds = orphans::binds_under(&dest, &host::inspect_all().await?);
            if !binds.is_empty() {
                bail!(
                    "{} is mounted ({})",
                    dest.display(),
                    binds.into_iter().collect::<Vec<_>>().join(", ")
                );
            }
            if dest.exists() {
                fs::remove_dir_all(&dest)?;
            }
            fs::remove_file(&marker)?;
            Ok(format!("removed {}", dest.display()))
        }
        PrivilegedOp::RetireStack { name, project, dir } => {
            validate_name("container name", name)?;
            validate_name("compose project", project)?;
            let dir = fs::canonicalize(dir).with_context(|| format!("resolve {dir}"))?;
            let parent = dir
                .parent()
                .ok_or_else(|| anyhow!("{} has no parent", dir.display()))?;
            let under_root = orphans::stacks_roots()
                .iter()
                .filter_map(|r| fs::canonicalize(r).ok())
                .any(|r| r == parent);
            if !under_root {
                bail!(
                    "{} is not directly under a configured stacks root",
                    dir.display()
                );
            }
            let compose = host::compose_file(&dir)
                .ok_or_else(|| anyhow!("{} has no compose file", dir.display()))?;
            if !orphans::compose_matches(&dir, project, &compose) {
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
            let binds = orphans::binds_under(&dir, &host::inspect_all().await?);
            if !binds.is_empty() {
                bail!("{} is still bind-mounted", dir.display());
            }
            let to = orphans::retire_target(&dir, name, &today())
                .ok_or_else(|| anyhow!("no retire target for {}", dir.display()))?;
            if to.exists() {
                bail!("{} already exists", to.display());
            }
            if let Some(p) = to.parent() {
                fs::create_dir_all(p)?;
            }
            fs::rename(&dir, &to)?;
            Ok(format!("moved {} to {}", dir.display(), to.display()))
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
        // it a clean EOF. Both values are passed as positional args, not
        // interpolated into the script.
        let out = Command::new("sh")
            .args([
                "-c",
                r#"exec sudo -n "$0" admin plugin-apply < "$1""#,
                &self.orca_bin,
                &path.to_string_lossy(),
            ])
            .output()
            .await;
        fs::remove_file(&path).ok();
        let out = out.context("spawn sudo")?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let reply: Option<PrivilegedReply> = stdout
            .lines()
            .rev()
            .find_map(|l| serde_json::from_str(l.trim()).ok());
        match reply {
            Some(PrivilegedReply {
                ok: true, detail, ..
            }) => Ok(detail.unwrap_or_default()),
            Some(PrivilegedReply { error, .. }) => {
                bail!("{}", error.unwrap_or_else(|| "privileged op failed".into()))
            }
            None => bail!(
                "privileged seam gave no reply (exit {:?}): {}",
                out.status.code,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        }
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

    #[test]
    fn destinations_stay_under_appdata() {
        assert_eq!(
            appdata_dest("pbs", "config").unwrap(),
            PathBuf::from("/mnt/user/appdata/pbs/config")
        );
        for bad in ["..", "../x", "a/b", ".hidden", ""] {
            assert!(appdata_dest("pbs", bad).is_err(), "{bad}");
        }
        assert!(appdata_dest("../etc", "x").is_err());
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
