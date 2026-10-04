//! Root-side file operations that never follow a symlink an unprivileged
//! user could plant.
//!
//! `/mnt/user/appdata` is writable by containers and SMB users, so a path
//! there must not be trusted to stay what it was. Every helper pins the
//! parent directory to its canonical path, then acts on the final component
//! with `O_NOFOLLOW` / `O_EXCL` (or `unlink`/`mkdir`/`rename`, which do not
//! follow a final symlink).

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use plugin_toolkit::prelude::*;

// The plugin depends only on plugin-toolkit, which does not re-export libc.
#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
const O_NOFOLLOW: i32 = 0o100000;
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "aarch64", target_arch = "arm"))
))]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(not(target_os = "linux"))]
const O_NOFOLLOW: i32 = 0x0100;

/// `path` with its parent resolved to the canonical directory.
pub fn pin(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent", path.display()))?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("{} has no file name", path.display()))?;
    let parent =
        fs::canonicalize(parent).with_context(|| format!("resolve {}", parent.display()))?;
    Ok(parent.join(name))
}

/// `path` is a real directory (not a symlink) whose canonical path is `expected`.
pub fn real_dir_at(path: &Path, expected: &Path) -> Result<()> {
    let md = fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if md.file_type().is_symlink() || !md.is_dir() {
        bail!("{} is not a real directory", path.display());
    }
    let canon = fs::canonicalize(path)?;
    if canon != expected {
        bail!(
            "{} resolves to {}, expected {}",
            path.display(),
            canon.display(),
            expected.display()
        );
    }
    Ok(())
}

/// Create `path` exclusively; fails if anything, including a symlink, is there.
pub fn create_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let path = pin(path)?;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Read a regular file without following a final symlink. `Ok(None)` when absent.
pub fn read_file(path: &Path) -> Result<Option<Vec<u8>>> {
    let path = pin(path)?;
    match fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(&path)
    {
        Ok(mut f) => {
            if !f.metadata()?.is_file() {
                bail!("{} is not a regular file", path.display());
            }
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            Ok(Some(buf))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("open {}", path.display())),
    }
}

/// Replace `path` atomically via an exclusive sibling temp file and rename.
/// An existing `path` must be a regular file.
pub fn replace_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let path = pin(path)?;
    match fs::symlink_metadata(&path) {
        Ok(md) if !md.is_file() => bail!("{} is not a regular file", path.display()),
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let tmp = PathBuf::from(format!(
        "{}.orca-tmp-{}",
        path.display(),
        super::host::random_suffix()
    ));
    create_new_file(&tmp, bytes, mode)?;
    fs::rename(&tmp, &path)
        .inspect_err(|_| {
            fs::remove_file(&tmp).ok();
        })
        .with_context(|| format!("replace {}", path.display()))
}

/// Unlink a non-directory entry (never its symlink target). `Ok(false)` when absent.
pub fn remove_file(path: &Path) -> Result<bool> {
    let path = pin(path)?;
    match fs::symlink_metadata(&path) {
        Ok(md) if md.is_dir() => bail!("{} is a directory", path.display()),
        Ok(_) => {
            fs::remove_file(&path)?;
            Ok(true)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Create one new directory level; fails if anything is already there.
pub fn create_dir_new(path: &Path) -> Result<PathBuf> {
    let path = pin(path)?;
    fs::create_dir(&path).with_context(|| format!("create {}", path.display()))?;
    real_dir_at(&path, &path)?;
    Ok(path)
}

/// `path` as a real directory, created (one level) if missing.
pub fn ensure_dir(path: &Path) -> Result<PathBuf> {
    let pinned = pin(path)?;
    match fs::symlink_metadata(&pinned) {
        Err(e) if e.kind() == ErrorKind::NotFound => create_dir_new(&pinned),
        _ => {
            real_dir_at(&pinned, &pinned)?;
            Ok(pinned)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn writes_refuse_planted_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(d.path()).unwrap();
        let victim = root.join("victim");
        fs::write(&victim, b"keep").unwrap();
        let link = root.join("link");
        symlink(&victim, &link).unwrap();

        assert!(create_new_file(&link, b"x", 0o600).is_err());
        assert!(read_file(&link).is_err());
        assert!(replace_file(&link, b"x", 0o600).is_err());
        assert!(create_dir_new(&link).is_err());
        assert!(real_dir_at(&link, &link).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"keep");

        assert!(remove_file(&link).unwrap());
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
    }

    #[test]
    fn symlinked_parents_are_pinned_to_their_target() {
        let d = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(d.path()).unwrap();
        fs::create_dir(root.join("real")).unwrap();
        symlink(root.join("real"), root.join("alias")).unwrap();
        assert_eq!(pin(&root.join("alias/f")).unwrap(), root.join("real/f"));
        assert!(real_dir_at(&root.join("alias"), &root.join("alias")).is_err());
    }

    #[test]
    fn replace_and_dirs_work_on_plain_paths() {
        let d = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(d.path()).unwrap();
        let f = root.join("f");
        assert_eq!(read_file(&f).unwrap(), None);
        replace_file(&f, b"a", 0o600).unwrap();
        replace_file(&f, b"b", 0o600).unwrap();
        assert_eq!(read_file(&f).unwrap().unwrap(), b"b");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        let sub = ensure_dir(&root.join("sub")).unwrap();
        assert_eq!(ensure_dir(&root.join("sub")).unwrap(), sub);
        assert!(create_dir_new(&root.join("sub")).is_err());
        assert!(remove_file(&sub).is_err());
    }
}
