//! Side effects on the Unraid host: the docker CLI, Unraid's dockerMan PHP and
//! scripts, and the files they read. Every process is spawned argv-style.
//!
//! [`HostOps`] is the seam the apply path drives, so it can be tested with a
//! mock; [`LiveOps`] is the real host, with privileged work delegated to a
//! [`PrivilegedRunner`](super::privileged::PrivilegedRunner).

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::prelude::*;
use plugin_toolkit::process::Command;
use plugin_toolkit::serde_json::{self, Value};

use super::inspect::{ContainerInspect, ImageInspect, VolumeInspect};
use super::privileged::{PrivilegedOp, PrivilegedRunner};

pub const AUTOSTART_FILE: &str = "/var/lib/docker/unraid-autostart";
pub const REBUILD_SCRIPT: &str =
    "/usr/local/emhttp/plugins/dynamix.docker.manager/scripts/rebuild_container";
pub const ICON_CACHES: &[&str] = &[
    "/var/lib/docker/unraid/images",
    "/usr/local/emhttp/state/plugins/dynamix.docker.manager/images",
];
pub const APPDATA: &str = "/mnt/user/appdata";
/// Unraid's Docker settings, including the daemon's default log rotation.
pub const DOCKER_CFG: &str = "/boot/config/docker.cfg";

/// The exact prologue of `scripts/rebuild_container`: dockerMan's helpers
/// need these globals before `xmlToCommand` or `getAllInfo` will run. Every
/// render and refresh goes through this one constant.
pub const PHP_PROLOGUE: &str = r#"$docroot="/usr/local/emhttp";
require_once "$docroot/plugins/dynamix.docker.manager/include/DockerClient.php";
$DockerClient = new DockerClient(); $DockerTemplates = new DockerTemplates();
$custom = DockerUtil::custom(); $subnet = DockerUtil::network($custom); $cpus = DockerUtil::cpus();
"#;

/// Keeps PHP notices out of stdout, which carries the rendered command.
const PHP_STDERR_ERRORS: &str = "-ddisplay_errors=stderr";

pub async fn run(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .run_checked()
        .await
        .map_err(|e| anyhow!("{program} {}: {e}", args.join(" ")))?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

pub async fn docker(args: &[&str]) -> Result<String> {
    run("docker", args).await
}

fn lines(s: &str) -> Vec<String> {
    s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

fn first_of(raw: Value, what: &str) -> Result<Value> {
    match raw {
        Value::Array(mut v) if !v.is_empty() => Ok(v.swap_remove(0)),
        _ => bail!("{what}: empty result"),
    }
}

/// `docker container inspect`, typed and raw.
pub async fn inspect_container_raw(name: &str) -> Result<(ContainerInspect, Value)> {
    let out = docker(&["container", "inspect", name]).await?;
    let raw = first_of(
        serde_json::from_str(&out).context("decode docker container inspect")?,
        name,
    )?;
    Ok((serde_json::from_value(raw.clone())?, raw))
}

pub async fn inspect_image_raw(id: &str) -> Result<(ImageInspect, Value)> {
    let out = docker(&["image", "inspect", id]).await?;
    let raw = first_of(
        serde_json::from_str(&out).context("decode docker image inspect")?,
        id,
    )?;
    Ok((serde_json::from_value(raw.clone())?, raw))
}

pub async fn inspect_all() -> Result<Vec<ContainerInspect>> {
    let ids = lines(&docker(&["ps", "-aq", "--no-trunc"]).await?);
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut args = vec!["container", "inspect"];
    args.extend(ids.iter().map(String::as_str));
    let out = docker(&args).await?;
    serde_json::from_str(&out).context("decode docker container inspect")
}

pub async fn inspect_volume(name: &str) -> Result<VolumeInspect> {
    let out = docker(&["volume", "inspect", name]).await?;
    let raw = first_of(
        serde_json::from_str(&out).context("decode docker volume inspect")?,
        name,
    )?;
    Ok(serde_json::from_value(raw)?)
}

pub async fn dangling_volumes() -> Result<Vec<String>> {
    Ok(lines(
        &docker(&["volume", "ls", "-q", "--filter", "dangling=true"]).await?,
    ))
}

pub async fn dangling_images() -> Result<Vec<String>> {
    Ok(lines(
        &docker(&[
            "image",
            "ls",
            "-q",
            "--no-trunc",
            "--filter",
            "dangling=true",
        ])
        .await?,
    ))
}

pub fn read_autostart() -> Vec<String> {
    fs::read_to_string(AUTOSTART_FILE)
        .map(|s| parse_autostart(&s))
        .unwrap_or_default()
}

/// Container names from the autostart file. A line may carry a trailing wait
/// value after the name.
pub fn parse_autostart(s: &str) -> Vec<String> {
    s.lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// The autostart file with `name` present or absent; `None` when unchanged.
pub fn autostart_with(cur: &str, name: &str, on: bool) -> Option<String> {
    let present = parse_autostart(cur).iter().any(|n| n == name);
    if present == on {
        return None;
    }
    let mut next = if on {
        let mut s = cur.to_string();
        if !s.is_empty() && !s.ends_with('\n') {
            s.push('\n');
        }
        s.push_str(name);
        s
    } else {
        cur.lines()
            .filter(|l| l.split_whitespace().next() != Some(name))
            .collect::<Vec<_>>()
            .join("\n")
    };
    next.push('\n');
    Some(next)
}

/// Daemon-wide default log options from Unraid's Docker settings; a new
/// container inherits these unless the command overrides them.
pub fn daemon_log_opts(cfg: &str) -> BTreeMap<String, String> {
    let get = |key: &str| {
        cfg.lines().find_map(|l| {
            l.trim()
                .strip_prefix(key)
                .and_then(|r| r.strip_prefix('='))
                .map(|v| v.trim().trim_matches('"').to_string())
        })
    };
    let mut out = BTreeMap::new();
    if get("DOCKER_LOG_ROTATION").as_deref() == Some("yes") {
        if let Some(s) = get("DOCKER_LOG_SIZE").filter(|s| !s.is_empty()) {
            out.insert("max-size".to_string(), s);
        }
        if let Some(f) = get("DOCKER_LOG_FILES").filter(|f| !f.is_empty()) {
            out.insert("max-file".to_string(), f);
        }
    }
    out
}

/// 16 random hex chars (urandom; time/pid/counter as a fallback): temp
/// names, run ids and copy nonces.
pub fn random_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    let mut b = [0u8; 8];
    if fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut b))
        .is_ok()
    {
        return plugin_toolkit::hash::hex_encode(&b);
    }
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = format!(
        "{nanos}-{}-{}-{:p}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed),
        &nanos
    );
    sha256_hex(seed.as_bytes())[..16].to_string()
}

/// The `docker create` command dockerMan would run for `xml`. The candidate is
/// written to a private, randomly named temp file because `xmlToCommand`
/// takes a path.
pub async fn render_command(xml: &str) -> Result<String> {
    let path = std::env::temp_dir().join(format!("orca-unraid-render-{}.xml", random_suffix()));
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| f.write_all(xml.as_bytes()))
        .with_context(|| format!("write {}", path.display()))?;
    let code = format!("{PHP_PROLOGUE}[$cmd] = xmlToCommand($argv[1]); echo $cmd;");
    let path_s = path.to_string_lossy().into_owned();
    let out = run("php", &[PHP_STDERR_ERRORS, "-r", &code, "--", &path_s]).await;
    fs::remove_file(&path).ok();
    let out = out?;
    let cmd = out.trim();
    if cmd.is_empty() {
        bail!("xmlToCommand rendered an empty command");
    }
    Ok(cmd.to_string())
}

pub async fn refresh_icons() -> Result<()> {
    let code = format!("{PHP_PROLOGUE}$DockerTemplates->getAllInfo(true);");
    run("php", &[PHP_STDERR_ERRORS, "-r", &code])
        .await
        .map(|_| ())
}

/// A content summary of a tree: entry count, regular-file bytes, and the
/// sha256 of the sorted `(path, type, size, mode, uid, gid, content)` list,
/// where content is a file's sha256 or a symlink's target. Symlinks are not
/// followed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub entries: u64,
    pub bytes: u64,
    pub digest: String,
}

pub fn manifest(root: &Path) -> Result<Manifest> {
    use std::os::unix::fs::MetadataExt;
    let mut rows = Vec::new();
    let mut bytes = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
            let e = e?;
            let md = fs::symlink_metadata(e.path())?;
            let rel = e.path().strip_prefix(root)?.to_string_lossy().into_owned();
            let kind = if md.is_dir() {
                stack.push(e.path());
                'd'
            } else if md.is_file() {
                bytes += md.len();
                'f'
            } else if md.file_type().is_symlink() {
                'l'
            } else {
                'o'
            };
            let size = if kind == 'f' { md.len() } else { 0 };
            let content = if kind == 'f' {
                plugin_toolkit::hash::sha256_file(&e.path())?
            } else if kind == 'l' {
                fs::read_link(e.path())?.to_string_lossy().into_owned()
            } else {
                String::new()
            };
            rows.push(format!(
                "{rel}\t{kind}\t{size}\t{:o}\t{}\t{}\t{content}",
                md.mode() & 0o7777,
                md.uid(),
                md.gid()
            ));
        }
    }
    rows.sort();
    Ok(Manifest {
        entries: rows.len() as u64,
        bytes,
        digest: sha256_hex(rows.join("\n").as_bytes()),
    })
}

pub fn is_nonempty_dir(p: &Path) -> bool {
    fs::read_dir(p).is_ok_and(|mut d| d.next().is_some())
}

/// `my-*.xml` templates and the `<Name>` each declares.
pub fn list_templates() -> Vec<(String, Option<String>)> {
    let Ok(rd) = fs::read_dir(super::template::TEMPLATES_DIR) else {
        return Vec::new();
    };
    rd.filter_map(|e| e.ok())
        .filter_map(|e| {
            let file = e.file_name().to_string_lossy().into_owned();
            file.ends_with(".xml").then(|| {
                let name = fs::read_to_string(e.path())
                    .ok()
                    .and_then(|x| super::template::extract_name(&x));
                (file, name)
            })
        })
        .collect()
}

/// Content of the first compose file in `dir`.
pub fn compose_file(dir: &Path) -> Option<String> {
    super::orphans::COMPOSE_FILES
        .iter()
        .find_map(|f| fs::read_to_string(dir.join(f)).ok())
}

/// Effective uid of this process, from procfs; `None` off Linux.
pub fn euid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|r| r.split_whitespace().nth(1))
        .and_then(|u| u.parse().ok())
}

/// What the apply path does to the host.
pub trait HostOps: Send + Sync {
    fn docker<'a>(&'a self, args: &'a [&'a str]) -> BoxFuture<'a, Result<String>>;
    fn inspect_container<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<ContainerInspect>>;
    fn inspect_image<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<ImageInspect>>;
    fn inspect_all(&self) -> BoxFuture<'_, Result<Vec<ContainerInspect>>>;
    fn privileged<'a>(&'a self, op: &'a PrivilegedOp) -> BoxFuture<'a, Result<String>>;
}

pub struct LiveOps {
    pub runner: Box<dyn PrivilegedRunner>,
}

impl HostOps for LiveOps {
    fn docker<'a>(&'a self, args: &'a [&'a str]) -> BoxFuture<'a, Result<String>> {
        Box::pin(docker(args))
    }
    fn inspect_container<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<ContainerInspect>> {
        Box::pin(async move { Ok(inspect_container_raw(name).await?.0) })
    }
    fn inspect_image<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<ImageInspect>> {
        Box::pin(async move { Ok(inspect_image_raw(id).await?.0) })
    }
    fn inspect_all(&self) -> BoxFuture<'_, Result<Vec<ContainerInspect>>> {
        Box::pin(inspect_all())
    }
    fn privileged<'a>(&'a self, op: &'a PrivilegedOp) -> BoxFuture<'a, Result<String>> {
        self.runner.run(op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autostart_parse_tolerates_blank_and_wait_values() {
        assert_eq!(
            parse_autostart("\npbs\nwhisper 10\n\n"),
            vec!["pbs", "whisper"]
        );
    }

    #[test]
    fn autostart_edits_are_minimal() {
        assert_eq!(autostart_with("\npbs\n", "pbs", true), None);
        assert_eq!(
            autostart_with("\npbs", "x", true).as_deref(),
            Some("\npbs\nx\n")
        );
        assert_eq!(
            autostart_with("\npbs\nx 5\n", "x", false).as_deref(),
            Some("\npbs\n")
        );
    }

    #[test]
    fn daemon_log_opts_follow_rotation_setting() {
        let cfg = "DOCKER_LOG_ROTATION=\"yes\"\nDOCKER_LOG_SIZE=\"50m\"\nDOCKER_LOG_FILES=\"1\"\n";
        let o = daemon_log_opts(cfg);
        assert_eq!(o.get("max-size").map(String::as_str), Some("50m"));
        assert_eq!(o.get("max-file").map(String::as_str), Some("1"));
        assert!(daemon_log_opts("DOCKER_LOG_ROTATION=\"no\"\nDOCKER_LOG_SIZE=\"50m\"").is_empty());
    }

    #[test]
    fn manifest_detects_content_shape_changes() {
        let a = tempfile::tempdir().unwrap();
        fs::create_dir(a.path().join("sub")).unwrap();
        fs::write(a.path().join("x"), b"12345").unwrap();
        fs::write(a.path().join("sub/y"), b"123").unwrap();
        let m = manifest(a.path()).unwrap();
        assert_eq!((m.entries, m.bytes), (3, 8));
        fs::rename(a.path().join("x"), a.path().join("z")).unwrap();
        let m2 = manifest(a.path()).unwrap();
        assert_eq!((m2.entries, m2.bytes), (3, 8));
        assert_ne!(m.digest, m2.digest);
        // Same names, sizes and modes, different bytes.
        let mtime = fs::metadata(a.path().join("z"))
            .unwrap()
            .modified()
            .unwrap();
        fs::write(a.path().join("z"), b"54321").unwrap();
        fs::File::options()
            .write(true)
            .open(a.path().join("z"))
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        assert_ne!(manifest(a.path()).unwrap().digest, m2.digest);
    }

    #[test]
    fn random_suffixes_differ() {
        assert_ne!(random_suffix(), random_suffix());
    }
}
