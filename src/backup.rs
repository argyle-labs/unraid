//! `unraid-config` backup KIND — captures an Unraid host's persistent
//! configuration and restores it, over the toolkit's backup-kind bridge.
//!
//! Unraid keeps its persistent configuration under the flash boot device that is
//! mounted at `/boot`, specifically `/boot/config` (`network.cfg`, `ident.cfg`,
//! `disk.cfg`, `super.dat`, the `shares/` tree, plugins, ssh keys, …). This
//! module resolves that directory robustly for both the normal flash-booted case
//! and disk-based / relocated installs — it locates the config via the actual
//! mount table rather than assuming a fixed device — then tars the tree into the
//! host-local `payload_dir` the generic backup store shares with this
//! subprocess. Restore reverses that, extracting the tree back to its resolved
//! parent.
//!
//! The host's `BackupKindProxy` drives four ops over the socket as
//! `unraid.__backup.{op}` (see [`crate::registration`]):
//! `instances` → `["default"]`, `layout` → the `<category>/<class>/<name>` path
//! segments, `backup` → a `{checksum, note}` outcome after writing the payload,
//! and `restore` → `null` after extracting it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use plugin_toolkit::serde_json::{self, Value, json};

/// The normal flash-booted config directory.
const BOOT_CONFIG: &str = "/boot/config";
/// The kernel mount table this module reads to resolve the config location.
const MOUNTS: &str = "/proc/mounts";
/// The tar written into `payload_dir` holding the captured config tree.
const PAYLOAD_TAR: &str = "config.tar";
/// The sidecar recording where the config tree was captured from, so restore
/// targets the exact location even if live resolution would drift.
const MANIFEST: &str = "manifest.json";

/// A resolved config directory plus a human-readable note on how it was found.
struct Resolved {
    dir: PathBuf,
    note: String,
}

/// Look up the source device and fstype backing `mountpoint` in [`MOUNTS`].
fn mount_source(mountpoint: &str) -> Option<(String, String)> {
    let txt = fs::read_to_string(MOUNTS).ok()?;
    for line in txt.lines() {
        let mut f = line.split_whitespace();
        let dev = f.next()?;
        let mp = f.next()?;
        let fstype = f.next()?;
        if mp == mountpoint {
            return Some((dev.to_string(), fstype.to_string()));
        }
    }
    None
}

/// Resolve the Unraid config directory for both flash-booted and disk-based
/// installs. Prefers `/boot/config` (the flash case); otherwise scans the mount
/// table for a mount whose `config/` subtree carries Unraid's config markers.
/// Returns an `Err` describing the failure when nothing resolvable is found, so
/// a backup fails loud rather than silently capturing nothing.
fn resolve_config_dir() -> Result<Resolved, String> {
    let boot_cfg = Path::new(BOOT_CONFIG);
    if boot_cfg.is_dir() {
        return Ok(match mount_source("/boot") {
            Some((dev, fstype)) => Resolved {
                dir: boot_cfg.to_path_buf(),
                note: format!("flash-booted: {BOOT_CONFIG} on {dev} ({fstype}) mounted at /boot"),
            },
            None => Resolved {
                dir: boot_cfg.to_path_buf(),
                note: format!(
                    "{BOOT_CONFIG} present but /boot is not a separate mount \
                     (relocated/disk install); captured {BOOT_CONFIG}"
                ),
            },
        });
    }

    if let Ok(txt) = fs::read_to_string(MOUNTS) {
        for line in txt.lines() {
            let mut f = line.split_whitespace();
            let (dev, mp) = match (f.next(), f.next()) {
                (Some(d), Some(m)) => (d, m),
                _ => continue,
            };
            let fstype = f.next().unwrap_or("");
            let cand = Path::new(mp).join("config");
            if cand.join("ident.cfg").is_file() || cand.join("super.dat").is_file() {
                return Ok(Resolved {
                    note: format!(
                        "disk/relocated install: resolved config to {} on {dev} ({fstype}) \
                         mounted at {mp}",
                        cand.display()
                    ),
                    dir: cand,
                });
            }
        }
    }

    Err(format!(
        "could not resolve unraid config directory: {BOOT_CONFIG} absent and no mount in \
         {MOUNTS} carries config/ident.cfg or config/super.dat"
    ))
}

/// This host's name, used as the `<class>` layout segment. Cheap: a single
/// sysfs read, falling back to `unraid`.
fn hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unraid".to_string())
}

/// Tar `base` (a child of `parent`) into `tar_path`, preserving permissions.
fn tar_create(parent: &Path, base: &std::ffi::OsStr, tar_path: &Path) -> Result<(), String> {
    let status = Command::new("tar")
        .arg("-cpf")
        .arg(tar_path)
        .arg("-C")
        .arg(parent)
        .arg(base)
        .status()
        .map_err(|e| format!("spawn tar: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "tar create failed (-C {} {}) exit {:?}",
            parent.display(),
            base.to_string_lossy(),
            status.code()
        ))
    }
}

/// Extract `tar_path` into `dest_parent`, preserving permissions.
fn tar_extract(tar_path: &Path, dest_parent: &Path) -> Result<(), String> {
    let status = Command::new("tar")
        .arg("-xpf")
        .arg(tar_path)
        .arg("-C")
        .arg(dest_parent)
        .status()
        .map_err(|e| format!("spawn tar: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "tar extract failed (-C {}) exit {:?}",
            dest_parent.display(),
            status.code()
        ))
    }
}

/// Capture the resolved config tree into `payload_dir`, returning the
/// `{checksum, note}` outcome JSON the host records.
fn do_backup(payload_dir: &str) -> Result<String, String> {
    let resolved = resolve_config_dir()?;
    let parent = resolved
        .dir
        .parent()
        .ok_or_else(|| format!("config dir {} has no parent", resolved.dir.display()))?;
    let base = resolved
        .dir
        .file_name()
        .ok_or_else(|| format!("config dir {} has no basename", resolved.dir.display()))?;

    let tar_path = Path::new(payload_dir).join(PAYLOAD_TAR);
    tar_create(parent, base, &tar_path)?;

    let manifest = json!({
        "config_dir": resolved.dir.display().to_string(),
        "base": base.to_string_lossy(),
    });
    fs::write(
        Path::new(payload_dir).join(MANIFEST),
        serde_json::to_vec(&manifest).map_err(|e| format!("encode manifest: {e}"))?,
    )
    .map_err(|e| format!("write manifest: {e}"))?;

    let outcome = json!({
        "checksum": Value::Null,
        "note": format!(
            "captured unraid config tree {} into {} via tar; {}",
            resolved.dir.display(),
            tar_path.display(),
            resolved.note
        ),
    });
    serde_json::to_string(&outcome).map_err(|e| format!("encode outcome: {e}"))
}

/// Restore the config tree from `payload_dir` back to its location. Targets the
/// parent recorded in the manifest, falling back to live resolution.
fn do_restore(payload_dir: &str) -> Result<String, String> {
    let tar_path = Path::new(payload_dir).join(PAYLOAD_TAR);
    if !tar_path.is_file() {
        return Err(format!("restore payload missing: {}", tar_path.display()));
    }

    let dest_parent: PathBuf = match fs::read_to_string(Path::new(payload_dir).join(MANIFEST)) {
        Ok(txt) => {
            let v: Value =
                serde_json::from_str(&txt).map_err(|e| format!("parse manifest: {e}"))?;
            let cd = v
                .get("config_dir")
                .and_then(Value::as_str)
                .ok_or_else(|| "manifest missing config_dir".to_string())?;
            Path::new(cd)
                .parent()
                .ok_or_else(|| format!("manifest config_dir {cd} has no parent"))?
                .to_path_buf()
        }
        Err(_) => resolve_config_dir()?
            .dir
            .parent()
            .ok_or_else(|| "resolved config dir has no parent".to_string())?
            .to_path_buf(),
    };

    tar_extract(&tar_path, &dest_parent)?;
    Ok("null".to_string())
}

/// Extract the required `payload_dir` field from a backup/restore arg object.
fn payload_dir_arg(args_json: &str) -> Result<String, String> {
    let v: Value = serde_json::from_str(args_json).map_err(|e| format!("decode args: {e}"))?;
    v.get("payload_dir")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "args missing `payload_dir`".to_string())
}

/// Dispatch a `unraid.__backup.*` op to the config backup implementation and
/// encode the result. Called by [`crate::registration::backend_dispatch`].
pub fn dispatch(op: &str, args_json: &str) -> Result<String, String> {
    match op {
        "instances" => serde_json::to_string(&["default"]).map_err(|e| e.to_string()),
        "layout" => {
            serde_json::to_string(&vec!["hosts".to_string(), hostname(), "config".to_string()])
                .map_err(|e| e.to_string())
        }
        "backup" => do_backup(&payload_dir_arg(args_json)?),
        "restore" => do_restore(&payload_dir_arg(args_json)?),
        other => Err(format!("unknown backup op: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tar_round_trips_a_config_tree() {
        let root = std::env::temp_dir().join(format!("unraid-backup-{}", std::process::id()));
        let src_parent = root.join("src");
        let cfg = src_parent.join("config");
        let shares = cfg.join("shares");
        fs::create_dir_all(&shares).unwrap();
        fs::write(cfg.join("ident.cfg"), b"NAME=\"tower\"\n").unwrap();
        fs::write(cfg.join("super.dat"), b"\x00\x01\x02").unwrap();
        fs::write(shares.join("appdata.cfg"), b"shareUseCache=\"yes\"\n").unwrap();

        let payload = root.join("payload");
        fs::create_dir_all(&payload).unwrap();
        let tar_path = payload.join(PAYLOAD_TAR);
        tar_create(&src_parent, cfg.file_name().unwrap(), &tar_path).unwrap();
        assert!(tar_path.is_file());

        let dest_parent = root.join("dest");
        fs::create_dir_all(&dest_parent).unwrap();
        tar_extract(&tar_path, &dest_parent).unwrap();

        let restored = dest_parent.join("config");
        assert_eq!(
            fs::read(restored.join("super.dat")).unwrap(),
            b"\x00\x01\x02"
        );
        assert_eq!(
            fs::read_to_string(restored.join("shares/appdata.cfg")).unwrap(),
            "shareUseCache=\"yes\"\n"
        );

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn instances_is_single_default() {
        assert_eq!(dispatch("instances", "{}").unwrap(), r#"["default"]"#);
    }

    #[test]
    fn layout_has_three_segments() {
        let out = dispatch("layout", r#"{"instance":"default"}"#).unwrap();
        let segs: Vec<String> = serde_json::from_str(&out).unwrap();
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0], "hosts");
        assert_eq!(segs[2], "config");
    }

    #[test]
    fn backup_args_require_payload_dir() {
        let err = dispatch("backup", r#"{"instance":"default"}"#).unwrap_err();
        assert!(err.contains("payload_dir"), "{err}");
    }

    #[test]
    fn restore_missing_payload_errors() {
        let dir = std::env::temp_dir().join(format!("unraid-restore-miss-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let err = dispatch(
            "restore",
            &format!(
                r#"{{"payload_dir":"{}","instance":"default"}}"#,
                dir.display()
            ),
        )
        .unwrap_err();
        assert!(err.contains("payload missing"), "{err}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_op_errors() {
        assert!(dispatch("frobnicate", "{}").is_err());
    }
}
