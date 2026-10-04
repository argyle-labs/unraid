//! Side effects on the Unraid host: the docker CLI, Unraid's dockerMan PHP and
//! scripts, and the files they read. Every process is spawned argv-style.

use std::fs;
use std::io::Write;
use std::path::Path;

use plugin_toolkit::prelude::*;
use plugin_toolkit::process::Command;
use plugin_toolkit::serde_json;

use super::inspect::{ContainerInspect, ImageInspect};

pub const AUTOSTART_FILE: &str = "/var/lib/docker/unraid-autostart";
pub const REBUILD_SCRIPT: &str =
    "/usr/local/emhttp/plugins/dynamix.docker.manager/scripts/rebuild_container";
pub const ICON_CACHES: &[&str] = &[
    "/var/lib/docker/unraid/images",
    "/usr/local/emhttp/state/plugins/dynamix.docker.manager/images",
];
pub const APPDATA: &str = "/mnt/user/appdata";

/// dockerMan's helpers need these globals before `xmlToCommand` will run;
/// this mirrors the prologue of `scripts/rebuild_container`.
const PHP_PROLOGUE: &str = r#"$docroot="/usr/local/emhttp";
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

pub async fn inspect_container(name: &str) -> Result<ContainerInspect> {
    let out = docker(&["container", "inspect", name]).await?;
    let mut v: Vec<ContainerInspect> =
        serde_json::from_str(&out).context("decode docker container inspect")?;
    if v.is_empty() {
        bail!("no container named {name}");
    }
    Ok(v.remove(0))
}

pub async fn inspect_image(id: &str) -> Result<ImageInspect> {
    let out = docker(&["image", "inspect", id]).await?;
    let mut v: Vec<ImageInspect> =
        serde_json::from_str(&out).context("decode docker image inspect")?;
    if v.is_empty() {
        bail!("no image {id}");
    }
    Ok(v.remove(0))
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

pub fn autostart_add(name: &str) -> Result<bool> {
    let cur = fs::read_to_string(AUTOSTART_FILE).unwrap_or_default();
    if parse_autostart(&cur).iter().any(|n| n == name) {
        return Ok(false);
    }
    let mut next = cur;
    if !next.is_empty() && !next.ends_with('\n') {
        next.push('\n');
    }
    next.push_str(name);
    next.push('\n');
    fs::write(AUTOSTART_FILE, next).with_context(|| format!("write {AUTOSTART_FILE}"))?;
    Ok(true)
}

pub fn autostart_remove(name: &str) -> Result<bool> {
    let Ok(cur) = fs::read_to_string(AUTOSTART_FILE) else {
        return Ok(false);
    };
    let kept: Vec<&str> = cur
        .lines()
        .filter(|l| l.split_whitespace().next() != Some(name))
        .collect();
    if kept.len() == cur.lines().count() {
        return Ok(false);
    }
    let mut next = kept.join("\n");
    next.push('\n');
    fs::write(AUTOSTART_FILE, next).with_context(|| format!("write {AUTOSTART_FILE}"))?;
    Ok(true)
}

/// The `docker create` command dockerMan would run for `xml`. The candidate is
/// written to a private temp file because `xmlToCommand` takes a path.
pub async fn render_command(name: &str, xml: &str) -> Result<String> {
    let path = std::env::temp_dir().join(format!(
        "orca-unraid-adopt-{name}-{}.xml",
        std::process::id()
    ));
    // create_new: never follow a file someone planted at the predictable path.
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
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

pub async fn rebuild(name: &str) -> Result<String> {
    run(REBUILD_SCRIPT, &[name]).await
}

/// Remove both cached copies of the container's icon.
pub fn clear_icon_cache(name: &str) -> Result<Vec<String>> {
    let mut removed = Vec::new();
    for dir in ICON_CACHES {
        let p = Path::new(dir).join(format!("{name}-icon.png"));
        match fs::remove_file(&p) {
            Ok(()) => removed.push(p.display().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => bail!("remove {}: {e}", p.display()),
        }
    }
    Ok(removed)
}

pub async fn refresh_icons() -> Result<()> {
    let code = format!("{PHP_PROLOGUE}$DockerTemplates->getAllInfo(true);");
    run("php", &[PHP_STDERR_ERRORS, "-r", &code])
        .await
        .map(|_| ())
}

/// `(entries, bytes)` under `root`, not following symlinks.
pub fn tree_stats(root: &Path) -> Result<(u64, u64)> {
    let mut entries = 0;
    let mut bytes = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
            let e = e?;
            let md = fs::symlink_metadata(e.path())?;
            entries += 1;
            if md.is_dir() {
                stack.push(e.path());
            } else if md.is_file() {
                bytes += md.len();
            }
        }
    }
    Ok((entries, bytes))
}

pub fn is_nonempty_dir(p: &Path) -> bool {
    fs::read_dir(p).is_ok_and(|mut d| d.next().is_some())
}

/// Copy a volume's data into `to`, preserving ownership, modes and links.
pub async fn copy_tree(from: &str, to: &str) -> Result<()> {
    if is_nonempty_dir(Path::new(to)) {
        bail!("{to} already has content; refusing to merge into it");
    }
    fs::create_dir_all(to).with_context(|| format!("create {to}"))?;
    let src = format!("{}/.", from.trim_end_matches('/'));
    run("cp", &["-a", &src, to]).await.map(|_| ())
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
    fn tree_stats_counts_entries_and_bytes() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("sub")).unwrap();
        fs::write(d.path().join("a"), b"12345").unwrap();
        fs::write(d.path().join("sub/b"), b"123").unwrap();
        assert_eq!(tree_stats(d.path()).unwrap(), (3, 8));
    }
}
