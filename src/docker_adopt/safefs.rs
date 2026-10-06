//! Root-side file operations that act through directory descriptors, so a
//! path an unprivileged user swaps mid-operation is never followed.
//!
//! `/mnt/user` and `/mnt/user/appdata` are world-writable without the sticky
//! bit: anyone with access can rename any entry and plant a symlink in its
//! place, at any depth. A path that was checked and is then reused can name a
//! different place by the time it is used. Everything here instead walks from
//! `/` one component at a time with `O_NOFOLLOW` (on Linux via `openat2` with
//! `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`), then acts relative to the
//! resulting descriptor. A later swap can move or replace a directory entry,
//! but cannot redirect a descriptor already held.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use plugin_toolkit::hash::hex_encode;
use plugin_toolkit::prelude::*;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags, Stat};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

/// Deepest tree walked; deeper trees are refused rather than exhausting fds.
const MAX_DEPTH: usize = 256;

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Open one directory component of `at` without following a symlink.
/// `openat2` is preferred; where it is unavailable, a single-component
/// `openat(O_NOFOLLOW | O_DIRECTORY)` gives the same guarantee, because the
/// name never contains `/` or `..`.
fn open_component(at: BorrowedFd<'_>, name: &OsStr) -> rustix::io::Result<OwnedFd> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::ResolveFlags;
        match rustix::fs::openat2(
            at,
            name,
            dir_flags(),
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::BENEATH,
        ) {
            Err(Errno::NOSYS) => {}
            r => return r,
        }
    }
    rustix::fs::openat(at, name, dir_flags(), Mode::empty())
}

/// `name` as one path component: not empty, `.` or `..`, and no `/` or NUL.
fn component(name: &str) -> Result<&OsStr> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        bail!("{name:?} is not a single path component");
    }
    Ok(OsStr::new(name))
}

#[allow(clippy::unnecessary_cast)]
fn perm(mode: u32) -> Mode {
    Mode::from_raw_mode((mode & 0o7777) as _)
}

fn file_type(st: &Stat) -> FileType {
    FileType::from_raw_mode(st.st_mode)
}

// `st_mode`/`st_dev`/`st_ino` widths differ between Linux and macOS.
#[allow(clippy::useless_conversion)]
fn mode_bits(st: &Stat) -> u32 {
    u32::from(st.st_mode) & 0o7777
}

/// Why a directory with this owner and mode is unsafe to act on as root, if it is.
pub fn root_owned_problem(path: &Path, uid: u32, mode: u32) -> Option<String> {
    if uid != 0 || mode & 0o022 != 0 {
        Some(format!(
            "{} is owned by uid {uid} with mode {:o}; it must be root-owned and not \
             group/world-writable",
            path.display(),
            mode & 0o7777
        ))
    } else {
        None
    }
}

/// An open directory, reached without following any symlink.
#[derive(Debug)]
pub struct Dir {
    fd: OwnedFd,
    path: PathBuf,
}

impl Dir {
    /// Open an absolute path, refusing a symlink at any component.
    pub fn open(path: &Path) -> Result<Dir> {
        if !path.is_absolute() {
            bail!("{} is not absolute", path.display());
        }
        let mut fd = rustix::fs::open("/", dir_flags(), Mode::empty())?;
        for c in path.components() {
            match c {
                Component::RootDir => {}
                Component::Normal(n) => {
                    fd = open_component(fd.as_fd(), n).map_err(|e| {
                        anyhow!("open {} without following symlinks: {e}", path.display())
                    })?;
                }
                _ => bail!("{} is not a plain absolute path", path.display()),
            }
        }
        Ok(Dir {
            fd,
            path: path.to_path_buf(),
        })
    }

    /// Resolve `path` first, then [`Dir::open`] the result. Only for trees
    /// whose every ancestor is root-owned (`/boot`, `/var/lib/docker`,
    /// `/usr/local/emhttp`), where the legitimate symlinks are root's own.
    pub fn open_canonical(path: &Path) -> Result<Dir> {
        let canon =
            std::fs::canonicalize(path).with_context(|| format!("resolve {}", path.display()))?;
        Dir::open(&canon)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn stat(&self) -> Result<Stat> {
        Ok(rustix::fs::fstat(&self.fd)?)
    }

    /// Permission bits (`0o7777`) of this directory.
    pub fn mode(&self) -> Result<u32> {
        Ok(mode_bits(&self.stat()?))
    }

    /// Owner and mode problem of this directory, if root should not act in it.
    pub fn root_owned_problem(&self) -> Result<Option<String>> {
        let st = self.stat()?;
        Ok(root_owned_problem(&self.path, st.st_uid, mode_bits(&st)))
    }

    fn child_os(&self, name: &OsStr) -> Result<Dir> {
        let path = self.path.join(name);
        let fd = open_component(self.fd.as_fd(), name)
            .map_err(|e| anyhow!("open {} without following symlinks: {e}", path.display()))?;
        Ok(Dir { fd, path })
    }

    /// The subdirectory `name`; a symlink there is refused.
    pub fn child(&self, name: &str) -> Result<Dir> {
        self.child_os(component(name)?)
    }

    /// Like [`Dir::child`], `None` when nothing is there.
    pub fn child_opt(&self, name: &str) -> Result<Option<Dir>> {
        match self.stat_entry(name)? {
            None => Ok(None),
            Some(_) => self.child(name).map(Some),
        }
    }

    fn stat_entry(&self, name: &str) -> Result<Option<Stat>> {
        let n = component(name)?;
        match rustix::fs::statat(&self.fd, n, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => Ok(Some(st)),
            Err(Errno::NOENT) => Ok(None),
            Err(e) => Err(anyhow!("stat {}: {e}", self.path.join(n).display())),
        }
    }

    pub fn exists(&self, name: &str) -> Result<bool> {
        Ok(self.stat_entry(name)?.is_some())
    }

    /// Create the subdirectory `name` (failing if anything is there) with
    /// `mode`, and confirm the directory opened is the one just made: owned
    /// by this process's uid and empty. Someone without that uid cannot have
    /// swapped in a directory that passes.
    pub fn create_child(&self, name: &str, mode: u32) -> Result<Dir> {
        let n = component(name)?;
        rustix::fs::mkdirat(&self.fd, n, perm(0o700))
            .map_err(|e| anyhow!("create {}: {e}", self.path.join(n).display()))?;
        #[cfg(test)]
        tests::after_mkdir(&self.path.join(n));
        let d = self.child_os(n)?;
        let st = d.stat()?;
        if st.st_uid != rustix::process::geteuid().as_raw() || !d.entries()?.is_empty() {
            bail!("{} changed while it was created", d.path.display());
        }
        rustix::fs::fchmod(&d.fd, perm(mode))?;
        Ok(d)
    }

    /// The subdirectory `name`, created with `mode` if missing.
    pub fn ensure_child(&self, name: &str, mode: u32) -> Result<Dir> {
        match self.child_opt(name)? {
            Some(d) => Ok(d),
            None => self.create_child(name, mode),
        }
    }

    /// Names in this directory, without `.` and `..`.
    pub fn entries(&self) -> Result<Vec<OsString>> {
        let mut out = Vec::new();
        for e in rustix::fs::Dir::read_from(&self.fd)? {
            let e = e?;
            let n = e.file_name().to_bytes();
            if n != b"." && n != b".." {
                out.push(OsStr::from_bytes(n).to_os_string());
            }
        }
        Ok(out)
    }

    /// Create the regular file `name` exclusively (never through a symlink)
    /// and return it open for writing.
    pub fn create_file_open(&self, name: &str, mode: u32) -> Result<File> {
        let n = component(name)?;
        let fd = rustix::fs::openat(
            &self.fd,
            n,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            perm(mode),
        )
        .map_err(|e| anyhow!("create {}: {e}", self.path.join(n).display()))?;
        rustix::fs::fchmod(&fd, perm(mode))?;
        Ok(File::from(fd))
    }

    pub fn create_file(&self, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
        let mut f = self.create_file_open(name, mode)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }

    fn open_regular(&self, name: &OsStr) -> Result<Option<File>> {
        let fd = match rustix::fs::openat(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => bail!("open {}: {e}", self.path.join(name).display()),
        };
        if file_type(&rustix::fs::fstat(&fd)?) != FileType::RegularFile {
            bail!("{} is not a regular file", self.path.join(name).display());
        }
        Ok(Some(File::from(fd)))
    }

    /// Read the regular file `name`; `None` when absent. A symlink is refused.
    pub fn read_file(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let Some(mut f) = self.open_regular(component(name)?)? else {
            return Ok(None);
        };
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(Some(buf))
    }

    /// Replace `name` atomically via an exclusive temp file and `renameat`.
    /// An existing `name` must be a regular file.
    pub fn replace_file(&self, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
        if let Some(st) = self.stat_entry(name)?
            && file_type(&st) != FileType::RegularFile
        {
            bail!("{} is not a regular file", self.path.join(name).display());
        }
        let tmp = format!("{name}.orca-tmp-{}", super::host::random_suffix());
        self.create_file(&tmp, bytes, mode)?;
        rustix::fs::renameat(&self.fd, tmp.as_str(), &self.fd, name).map_err(|e| {
            rustix::fs::unlinkat(&self.fd, tmp.as_str(), AtFlags::empty()).ok();
            anyhow!("replace {}: {e}", self.path.join(name).display())
        })
    }

    /// Unlink a non-directory `name` (a symlink itself, never its target).
    /// `Ok(false)` when absent.
    pub fn remove_file(&self, name: &str) -> Result<bool> {
        match self.stat_entry(name)? {
            None => Ok(false),
            Some(st) if file_type(&st) == FileType::Directory => {
                bail!("{} is a directory", self.path.join(name).display())
            }
            Some(_) => {
                rustix::fs::unlinkat(&self.fd, name, AtFlags::empty())?;
                Ok(true)
            }
        }
    }

    /// Delete everything inside this directory, walking by descriptor.
    pub fn clear(&self) -> Result<()> {
        self.clear_depth(0)
    }

    fn clear_depth(&self, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            bail!("{} is nested deeper than {MAX_DEPTH}", self.path.display());
        }
        for n in self.entries()? {
            let st = rustix::fs::statat(&self.fd, &n, AtFlags::SYMLINK_NOFOLLOW)?;
            let removed = if file_type(&st) == FileType::Directory {
                self.child_os(&n)?.clear_depth(depth + 1)?;
                rustix::fs::unlinkat(&self.fd, &n, AtFlags::REMOVEDIR)
            } else {
                rustix::fs::unlinkat(&self.fd, &n, AtFlags::empty())
            };
            removed.map_err(|e| anyhow!("remove {}: {e}", self.path.join(&n).display()))?;
        }
        Ok(())
    }

    /// Names in this directory; `None`, read no further, once there are
    /// more than `max`.
    fn entries_max(&self, max: u64) -> Result<Option<Vec<OsString>>> {
        let mut out = Vec::new();
        for e in rustix::fs::Dir::read_from(&self.fd)? {
            let e = e?;
            let n = e.file_name().to_bytes();
            if n != b"." && n != b".." {
                if out.len() as u64 >= max {
                    return Ok(None);
                }
                out.push(OsStr::from_bytes(n).to_os_string());
            }
        }
        Ok(Some(out))
    }

    /// Give this directory `src`'s owner, group and permission bits, never
    /// setuid. The sticky bit is kept.
    pub fn copy_owner_mode_from(&self, src: &Dir) -> Result<()> {
        let st = src.stat()?;
        rustix::fs::fchown(
            &self.fd,
            Some(rustix::fs::Uid::from_raw(st.st_uid)),
            Some(rustix::fs::Gid::from_raw(st.st_gid)),
        )
        .map_err(|e| anyhow!("chown {}: {e}", self.path.display()))?;
        rustix::fs::fchmod(&self.fd, perm(mode_bits(&st) & 0o3777))
            .map_err(|e| anyhow!("chmod {}: {e}", self.path.display()))
    }

    /// This directory's extended attributes, sorted by name, within
    /// [`MANIFEST_LIMITS`].
    pub fn xattrs(&self) -> Result<Xattrs> {
        fd_xattrs(self.fd.as_fd(), &self.path, MANIFEST_LIMITS.xattr)
    }

    /// Remove the empty subdirectory `name`.
    pub fn remove_empty_dir(&self, name: &str) -> Result<()> {
        let n = component(name)?;
        rustix::fs::unlinkat(&self.fd, n, AtFlags::REMOVEDIR)
            .map_err(|e| anyhow!("remove {}: {e}", self.path.join(n).display()))
    }

    /// Move `name` to `to/to_name`, both relative to held descriptors.
    /// Fails if `to/to_name` exists: `RENAME_NOREPLACE` where the filesystem
    /// supports it, else a check just before the rename.
    pub fn rename_into(&self, name: &str, to: &Dir, to_name: &str) -> Result<()> {
        let (n, t) = (component(name)?, component(to_name)?);
        if to.exists(to_name)? {
            bail!("{} already exists", to.path.join(t).display());
        }
        let r = match rustix::fs::renameat_with(&self.fd, n, &to.fd, t, RenameFlags::NOREPLACE) {
            Err(Errno::INVAL | Errno::NOSYS) => rustix::fs::renameat(&self.fd, n, &to.fd, t),
            r => r,
        };
        r.map_err(|e| {
            anyhow!(
                "move {} to {}: {e}",
                self.path.join(n).display(),
                to.path.join(t).display()
            )
        })
    }

    /// A path naming this exact directory for a child process:
    /// `/proc/<pid>/fd/<n>`, valid while `self` is open.
    pub fn proc_path(&self) -> Result<String> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            Ok(format!(
                "/proc/{}/fd/{}",
                std::process::id(),
                self.fd.as_raw_fd()
            ))
        }
        #[cfg(not(target_os = "linux"))]
        bail!(
            "{}: passing a pinned directory to a child process needs Linux /proc",
            self.path.display()
        )
    }
}

fn split(path: &Path) -> Result<(Dir, &str)> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent", path.display()))?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("{} has no file name", path.display()))?;
    Ok((Dir::open_canonical(parent)?, name))
}

// Path forms for files in root-owned trees (see [`Dir::open_canonical`]).

pub fn create_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let (d, n) = split(path)?;
    d.create_file(n, bytes, mode)
}

pub fn read_file(path: &Path) -> Result<Option<Vec<u8>>> {
    let (d, n) = split(path)?;
    d.read_file(n)
}

pub fn replace_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let (d, n) = split(path)?;
    d.replace_file(n, bytes, mode)
}

pub fn remove_file(path: &Path) -> Result<bool> {
    let (d, n) = split(path)?;
    d.remove_file(n)
}

/// Refuse a tree root should not copy: anything but regular files,
/// directories and symlinks (device nodes, FIFOs, sockets), setuid/setgid
/// files, setuid directories, and nesting deeper than [`MAX_DEPTH`].
/// A setgid directory only sets group inheritance and is allowed.
pub fn check_copyable(root: &Dir) -> Result<()> {
    if root.mode()? & 0o4000 != 0 {
        bail!("{} is a setuid directory", root.path.display());
    }
    check_copyable_depth(root, 0)
}

fn check_copyable_depth(dir: &Dir, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("{} is nested deeper than {MAX_DEPTH}", dir.path.display());
    }
    for n in dir.entries()? {
        let st = rustix::fs::statat(&dir.fd, &n, AtFlags::SYMLINK_NOFOLLOW)?;
        let shown = dir.path.join(&n);
        let mode = mode_bits(&st);
        match file_type(&st) {
            FileType::Directory if mode & 0o4000 != 0 => {
                bail!("{} is a setuid directory", shown.display())
            }
            FileType::Directory => check_copyable_depth(&dir.child_os(&n)?, depth + 1)?,
            FileType::RegularFile if mode & 0o6000 != 0 => {
                bail!("{} is setuid/setgid (mode {mode:o})", shown.display())
            }
            FileType::RegularFile | FileType::Symlink => {}
            other => bail!(
                "{} is a {other:?}, not a regular file, directory or symlink",
                shown.display()
            ),
        }
    }
    Ok(())
}

/// A content summary of a tree: entry count, regular-file bytes, and a
/// sha256 over one row per entry, `(path, type, size, mode, uid, gid,
/// content[, xattrs])`, where content is a file's sha256 or a symlink's
/// target. Rows are hashed as the tree is walked, each directory's entries in
/// byte order, so no list of rows is held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub entries: u64,
    pub bytes: u64,
    pub digest: String,
}

/// Bounds on one manifest walk; exceeding any fails it.
#[derive(Debug, Clone, Copy)]
pub struct ManifestLimits {
    pub entries: u64,
    /// Regular-file bytes read.
    pub bytes: u64,
    /// One entry's xattr name list and values together.
    pub xattr: usize,
    pub time: Duration,
}

/// Linux caps one xattr name list and one value at 64 KiB each, so a
/// legitimate entry with a few attributes fits.
pub const MANIFEST_LIMITS: ManifestLimits = ManifestLimits {
    entries: 2_000_000,
    bytes: 1 << 40,
    xattr: 256 * 1024,
    time: Duration::from_secs(60 * 60),
};

/// [`Manifest`] of everything under `root`, read by descriptor: no symlink
/// is followed, and each file is hashed from the fd that was checked to be a
/// regular file.
pub fn manifest(root: &Dir) -> Result<Manifest> {
    manifest_within(root, false, MANIFEST_LIMITS)
}

/// [`manifest`] with every entry's extended attributes (file capabilities,
/// ACLs, …) in its row, for copies that preserve them.
pub fn manifest_with_xattrs(root: &Dir) -> Result<Manifest> {
    manifest_within(root, true, MANIFEST_LIMITS)
}

pub fn manifest_within(root: &Dir, xattrs: bool, limits: ManifestLimits) -> Result<Manifest> {
    let mut w = Walk {
        h: Sha256::new(),
        entries: 0,
        bytes: 0,
        xattrs,
        limits,
        deadline: Instant::now() + limits.time,
        root: root.path.clone(),
    };
    manifest_into(root, &[], 0, &mut w)?;
    Ok(Manifest {
        entries: w.entries,
        bytes: w.bytes,
        digest: hex_encode(&w.h.finalize()),
    })
}

struct Walk {
    h: Sha256,
    entries: u64,
    bytes: u64,
    xattrs: bool,
    limits: ManifestLimits,
    deadline: Instant,
    root: PathBuf,
}

impl Walk {
    fn check_time(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            bail!(
                "reading {} took longer than {}s",
                self.root.display(),
                self.limits.time.as_secs()
            );
        }
        Ok(())
    }

    /// Length-prefixed, so no field's bytes can be read as another's.
    fn field(&mut self, b: &[u8]) {
        self.h.update((b.len() as u64).to_le_bytes());
        self.h.update(b);
    }

    fn row(&mut self, path: &[u8], kind: u8, size: u64, st: &Stat, content: &[u8], attrs: &Xattrs) {
        self.field(path);
        self.h.update([kind]);
        self.h.update(size.to_le_bytes());
        self.h.update(mode_bits(st).to_le_bytes());
        self.h.update(st.st_uid.to_le_bytes());
        self.h.update(st.st_gid.to_le_bytes());
        self.field(content);
        self.h.update((attrs.len() as u64).to_le_bytes());
        for (k, v) in attrs {
            self.field(k);
            self.field(v);
        }
    }
}

fn manifest_into(dir: &Dir, rel: &[u8], depth: usize, w: &mut Walk) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("{} is nested deeper than {MAX_DEPTH}", dir.path.display());
    }
    let over = |w: &Walk| {
        anyhow!(
            "{} has more than {} entries",
            w.root.display(),
            w.limits.entries
        )
    };
    let Some(mut names) = dir.entries_max(w.limits.entries - w.entries)? else {
        return Err(over(w));
    };
    names.sort();
    for n in names {
        w.check_time()?;
        w.entries += 1;
        // A subdirectory walked earlier may have used up the budget.
        if w.entries > w.limits.entries {
            return Err(over(w));
        }
        let st = rustix::fs::statat(&dir.fd, &n, AtFlags::SYMLINK_NOFOLLOW)?;
        let mut path = rel.to_vec();
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(n.as_bytes());
        let shown = dir.path.join(&n);
        let max_xattr = w.limits.xattr;
        match file_type(&st) {
            FileType::Directory => {
                let child = dir.child_os(&n)?;
                let attrs = if w.xattrs {
                    fd_xattrs(child.fd.as_fd(), &child.path, max_xattr)?
                } else {
                    Vec::new()
                };
                w.row(&path, b'd', 0, &st, &[], &attrs);
                manifest_into(&child, &path, depth + 1, w)?;
            }
            FileType::RegularFile => {
                let mut f = dir
                    .open_regular(&n)?
                    .ok_or_else(|| anyhow!("{} vanished", shown.display()))?;
                let attrs = if w.xattrs {
                    fd_xattrs(f.as_fd(), &shown, max_xattr)?
                } else {
                    Vec::new()
                };
                let mut h = Sha256::new();
                let mut len = 0u64;
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let k = f.read(&mut buf)?;
                    if k == 0 {
                        break;
                    }
                    h.update(&buf[..k]);
                    len += k as u64;
                    w.bytes += k as u64;
                    if w.bytes > w.limits.bytes {
                        bail!(
                            "{} holds more than {} bytes",
                            w.root.display(),
                            w.limits.bytes
                        );
                    }
                    w.check_time()?;
                }
                w.row(&path, b'f', len, &st, &h.finalize(), &attrs);
            }
            FileType::Symlink => {
                let attrs = if w.xattrs {
                    symlink_xattrs(dir, &n, max_xattr)?
                } else {
                    Vec::new()
                };
                let t = rustix::fs::readlinkat(&dir.fd, &n, Vec::new())?;
                w.row(&path, b'l', 0, &st, t.to_bytes(), &attrs);
            }
            _ => bail!(
                "{} is not a regular file, directory or symlink",
                shown.display()
            ),
        }
    }
    Ok(())
}

/// Extended attributes as sorted `(name, value)` pairs.
pub type Xattrs = Vec<(Vec<u8>, Vec<u8>)>;

/// Every extended attribute, at most `max` bytes of names and values
/// together. A filesystem without xattr support has none.
fn fd_xattrs(fd: BorrowedFd<'_>, shown: &Path, max: usize) -> Result<Xattrs> {
    collect_xattrs(
        shown,
        max,
        |b| rustix::fs::flistxattr(fd, b),
        |n, b| rustix::fs::fgetxattr(fd, n, b),
    )
}

/// A symlink's own extended attributes, read without following it.
#[cfg(target_os = "linux")]
fn symlink_xattrs(dir: &Dir, name: &OsStr, max: usize) -> Result<Xattrs> {
    use std::os::fd::AsRawFd;
    let path = Path::new(&format!("/proc/self/fd/{}", dir.fd.as_raw_fd())).join(name);
    collect_xattrs(
        &dir.path.join(name),
        max,
        |b| rustix::fs::llistxattr(&path, b),
        |n, b| rustix::fs::lgetxattr(&path, n, b),
    )
}

#[cfg(not(target_os = "linux"))]
fn symlink_xattrs(_dir: &Dir, _name: &OsStr, _max: usize) -> Result<Xattrs> {
    Ok(Vec::new())
}

fn collect_xattrs(
    shown: &Path,
    max: usize,
    list: impl FnMut(&mut [u8]) -> rustix::io::Result<usize>,
    mut get: impl FnMut(&[u8], &mut [u8]) -> rustix::io::Result<usize>,
) -> Result<Xattrs> {
    let err = |e: Errno| match e {
        Errno::TOOBIG => anyhow!(
            "extended attributes of {} exceed {max} bytes",
            shown.display()
        ),
        e => anyhow!("read extended attributes of {}: {e}", shown.display()),
    };
    let names = match read_sized(max, list) {
        Ok(n) => n,
        Err(Errno::NOTSUP) => return Ok(Vec::new()),
        Err(e) => return Err(err(e)),
    };
    let mut left = max - names.len();
    let mut out = Vec::new();
    for name in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let value = read_sized(left, |b| get(name, b)).map_err(err)?;
        left -= value.len();
        out.push((name.to_vec(), value));
    }
    out.sort();
    Ok(out)
}

/// Call a size-then-fill xattr syscall, retrying while the value grows.
/// `TOOBIG` when it needs more than `max` bytes.
fn read_sized(
    max: usize,
    mut f: impl FnMut(&mut [u8]) -> rustix::io::Result<usize>,
) -> Result<Vec<u8>, Errno> {
    for _ in 0..8 {
        let n = f(&mut [])?;
        if n > max {
            return Err(Errno::TOOBIG);
        }
        let mut buf = vec![0u8; n];
        match f(&mut buf) {
            Ok(k) => {
                buf.truncate(k);
                return Ok(buf);
            }
            Err(Errno::RANGE) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(Errno::RANGE)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;

    type Hook = Box<dyn FnOnce(&Path)>;

    thread_local! {
        static AFTER_MKDIR: RefCell<Option<Hook>> = RefCell::new(None);
    }

    /// Runs a test's swap between `mkdirat` and the open in `create_child`.
    pub(crate) fn after_mkdir(p: &Path) {
        if let Some(f) = AFTER_MKDIR.with(|h| h.borrow_mut().take()) {
            f(p);
        }
    }

    pub(crate) fn on_next_mkdir(f: impl FnOnce(&Path) + 'static) {
        AFTER_MKDIR.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    #[test]
    fn create_child_refuses_a_directory_swapped_in_after_mkdir() {
        let (_d, r) = root();
        let d = Dir::open(&r).unwrap();
        on_next_mkdir(|p| {
            fs::rename(p, p.with_file_name("ours")).unwrap();
            fs::create_dir(p).unwrap();
            fs::write(p.join("theirs"), b"x").unwrap();
        });
        let e = d.create_child("new", 0o700).unwrap_err().to_string();
        assert!(e.contains("changed while it was created"), "{e}");
    }

    fn mkfifo(p: &Path) {
        assert!(
            std::process::Command::new("mkfifo")
                .arg(p)
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    fn reading_a_fifo_fails_fast_instead_of_blocking() {
        let (_d, r) = root();
        mkfifo(&r.join("fifo"));
        let (tx, rx) = std::sync::mpsc::channel();
        let dir = r.clone();
        std::thread::spawn(move || {
            let d = Dir::open(&dir).unwrap();
            tx.send(d.read_file("fifo").is_err()).ok();
        });
        let refused = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("opening a FIFO blocked");
        assert!(refused, "a FIFO was read as a regular file");
    }

    #[test]
    fn copy_check_refuses_special_and_setid_files_and_deep_trees() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, r) = root();
        fs::create_dir_all(r.join("ok/sub")).unwrap();
        fs::write(r.join("ok/sub/f"), b"x").unwrap();
        symlink("/etc/passwd", r.join("ok/l")).unwrap();
        fs::create_dir(r.join("ok/g")).unwrap();
        fs::set_permissions(r.join("ok/g"), fs::Permissions::from_mode(0o2775)).unwrap();
        assert!(check_copyable(&Dir::open(&r.join("ok")).unwrap()).is_ok());

        fs::create_dir(r.join("fifo")).unwrap();
        mkfifo(&r.join("fifo/p"));
        assert!(check_copyable(&Dir::open(&r.join("fifo")).unwrap()).is_err());
        assert!(manifest(&Dir::open(&r.join("fifo")).unwrap()).is_err());

        for mode in [0o4755, 0o2755] {
            let d = r.join(format!("suid{mode:o}"));
            fs::create_dir(&d).unwrap();
            fs::write(d.join("bin"), b"x").unwrap();
            fs::set_permissions(d.join("bin"), fs::Permissions::from_mode(mode)).unwrap();
            let e = check_copyable(&Dir::open(&d).unwrap())
                .unwrap_err()
                .to_string();
            assert!(e.contains("setuid/setgid"), "{e}");
        }

        let mut deep = r.join("deep");
        for _ in 0..=MAX_DEPTH + 1 {
            deep.push("d");
        }
        fs::create_dir_all(&deep).unwrap();
        let e = check_copyable(&Dir::open(&r.join("deep")).unwrap())
            .unwrap_err()
            .to_string();
        assert!(e.contains("deeper than"), "{e}");
    }

    #[test]
    fn copy_check_refuses_fifos() {
        let (_d, r) = root();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(r.join("pipe"))
                .status()
                .unwrap()
                .success()
        );
        let e = check_copyable(&Dir::open(&r).unwrap())
            .unwrap_err()
            .to_string();
        assert!(e.contains("Fifo"), "{e}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn copy_check_refuses_device_nodes() {
        if super::super::host::euid() != Some(0) {
            return;
        }
        let (_d, r) = root();
        // Root inside a user namespace (an unprivileged LXC, or a CI job in one) may not create devices.
        if rustix::fs::mknodat(
            rustix::fs::CWD,
            r.join("null"),
            FileType::CharacterDevice,
            Mode::from_raw_mode(0o600),
            rustix::fs::makedev(1, 3),
        )
        .is_err()
        {
            return;
        }
        let e = check_copyable(&Dir::open(&r).unwrap())
            .unwrap_err()
            .to_string();
        assert!(e.contains("CharacterDevice"), "{e}");
    }
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn root() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let r = fs::canonicalize(d.path()).unwrap();
        (d, r)
    }

    #[test]
    fn open_refuses_a_symlink_at_any_component() {
        let (_d, r) = root();
        fs::create_dir_all(r.join("real/sub")).unwrap();
        symlink(r.join("real"), r.join("alias")).unwrap();
        assert!(Dir::open(&r.join("real/sub")).is_ok());
        assert!(Dir::open(&r.join("alias/sub")).is_err());
        assert!(Dir::open(&r.join("alias")).is_err());
        assert!(Dir::open(&r.join("real/../real")).is_err());
        assert!(Dir::open(Path::new("relative")).is_err());
        assert!(Dir::open_canonical(&r.join("alias/sub")).is_ok());
    }

    #[test]
    fn file_ops_refuse_planted_symlinks() {
        let (_d, r) = root();
        let victim = r.join("victim");
        fs::write(&victim, b"keep").unwrap();
        symlink(&victim, r.join("link")).unwrap();
        let d = Dir::open(&r).unwrap();

        assert!(d.create_file("link", b"x", 0o600).is_err());
        assert!(d.read_file("link").is_err());
        assert!(d.replace_file("link", b"x", 0o600).is_err());
        assert!(d.create_child("link", 0o700).is_err());
        assert!(d.child("link").is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert!(d.remove_file("link").unwrap());
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        for bad in ["", ".", "..", "a/b"] {
            assert!(d.child(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn plain_paths_work() {
        let (_d, r) = root();
        let d = Dir::open(&r).unwrap();
        assert_eq!(d.read_file("f").unwrap(), None);
        d.replace_file("f", b"a", 0o600).unwrap();
        d.replace_file("f", b"b", 0o600).unwrap();
        assert_eq!(d.read_file("f").unwrap().unwrap(), b"b");
        assert_eq!(d.entries().unwrap().len(), 1);
        let sub = d.create_child("sub", 0o700).unwrap();
        assert_eq!(
            fs::metadata(r.join("sub")).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(d.create_child("sub", 0o700).is_err());
        assert_eq!(d.ensure_child("sub", 0o700).unwrap().path(), sub.path());
        assert!(d.remove_file("sub").is_err());
    }

    #[test]
    fn clear_never_leaves_the_held_directory() {
        let (_d, r) = root();
        let outside = r.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"x").unwrap();
        fs::create_dir_all(r.join("t/a/b")).unwrap();
        fs::write(r.join("t/a/b/f"), b"x").unwrap();
        symlink(&outside, r.join("t/a/link")).unwrap();
        let t = Dir::open(&r.join("t")).unwrap();
        t.clear().unwrap();
        assert!(t.entries().unwrap().is_empty());
        assert!(outside.join("keep").exists());
    }

    #[test]
    fn manifest_hashes_contents_and_never_follows_links() {
        let (_d, r) = root();
        fs::create_dir(r.join("sub")).unwrap();
        fs::write(r.join("x"), b"12345").unwrap();
        fs::write(r.join("sub/y"), b"123").unwrap();
        symlink("/etc/passwd", r.join("l")).unwrap();
        let d = Dir::open(&r).unwrap();
        let m = manifest(&d).unwrap();
        assert_eq!((m.entries, m.bytes), (4, 8));
        fs::rename(r.join("x"), r.join("z")).unwrap();
        let m2 = manifest(&d).unwrap();
        assert_eq!((m2.entries, m2.bytes), (4, 8));
        assert_ne!(m.digest, m2.digest);
        // Same names, sizes and modes, different bytes.
        let mtime = fs::metadata(r.join("z")).unwrap().modified().unwrap();
        fs::write(r.join("z"), b"54321").unwrap();
        File::options()
            .write(true)
            .open(r.join("z"))
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        assert_ne!(manifest(&d).unwrap().digest, m2.digest);
    }

    #[test]
    fn manifest_is_independent_of_creation_order() {
        let (_a, a) = root();
        let (_b, b) = root();
        for n in ["x", "y", "z"] {
            fs::write(a.join(n), n).unwrap();
        }
        for n in ["z", "x", "y"] {
            fs::write(b.join(n), n).unwrap();
        }
        assert_eq!(
            manifest(&Dir::open(&a).unwrap()).unwrap(),
            manifest(&Dir::open(&b).unwrap()).unwrap()
        );
    }

    #[test]
    fn manifest_fails_closed_past_any_limit() {
        let (_d, r) = root();
        fs::create_dir(r.join("sub")).unwrap();
        fs::write(r.join("sub/a"), b"1234").unwrap();
        fs::write(r.join("sub/b"), b"5678").unwrap();
        let d = Dir::open(&r).unwrap();
        let within = |l: ManifestLimits| manifest_within(&d, false, l);
        assert_eq!(within(MANIFEST_LIMITS).unwrap().entries, 3);
        for entries in [1, 2] {
            let e = within(ManifestLimits {
                entries,
                ..MANIFEST_LIMITS
            })
            .unwrap_err()
            .to_string();
            assert!(e.contains(&format!("more than {entries} entries")), "{e}");
        }
        fs::write(r.join("z"), b"").unwrap();
        let e = within(ManifestLimits {
            entries: 3,
            ..MANIFEST_LIMITS
        })
        .unwrap_err()
        .to_string();
        assert!(e.contains("more than 3 entries"), "{e}");
        let e = within(ManifestLimits {
            bytes: 7,
            ..MANIFEST_LIMITS
        })
        .unwrap_err()
        .to_string();
        assert!(e.contains("more than 7 bytes"), "{e}");
        let e = within(ManifestLimits {
            time: Duration::ZERO,
            ..MANIFEST_LIMITS
        })
        .unwrap_err()
        .to_string();
        assert!(e.contains("took longer than"), "{e}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn manifest_refuses_oversized_extended_attributes() {
        let (_d, r) = root();
        fs::write(r.join("f"), b"x").unwrap();
        let set = rustix::fs::setxattr(
            r.join("f").as_path(),
            "user.orca-test",
            &[7u8; 512],
            rustix::fs::XattrFlags::empty(),
        );
        if set.is_err() {
            return; // filesystem without user xattrs
        }
        let d = Dir::open(&r).unwrap();
        assert!(manifest_within(&d, true, MANIFEST_LIMITS).is_ok());
        let e = manifest_within(
            &d,
            true,
            ManifestLimits {
                xattr: 256,
                ..MANIFEST_LIMITS
            },
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("exceed 256 bytes"), "{e}");
    }

    /// Names and link targets that differ only in bytes invalid as UTF-8
    /// must not hash alike.
    #[cfg(target_os = "linux")]
    #[test]
    fn manifest_rows_use_raw_name_and_target_bytes() {
        let digest = |name: &[u8], target: &[u8]| {
            let (_d, r) = root();
            fs::write(r.join(OsStr::from_bytes(name)), b"x").unwrap();
            symlink(OsStr::from_bytes(target), r.join("l")).unwrap();
            manifest(&Dir::open(&r).unwrap()).unwrap().digest
        };
        let base = digest(b"a\xff", b"t\xff");
        assert_ne!(base, digest(b"a\xfe", b"t\xff"));
        assert_ne!(base, digest(b"a\xff", b"t\xfe"));
    }

    #[test]
    fn copied_owner_mode_keeps_the_sticky_bit() {
        let (_d, r) = root();
        fs::create_dir(r.join("src")).unwrap();
        fs::create_dir(r.join("dst")).unwrap();
        fs::set_permissions(r.join("src"), fs::Permissions::from_mode(0o1777)).unwrap();
        let dst = Dir::open(&r.join("dst")).unwrap();
        dst.copy_owner_mode_from(&Dir::open(&r.join("src")).unwrap())
            .unwrap();
        assert_eq!(dst.mode().unwrap(), 0o1777);
    }

    #[test]
    fn root_owned_problem_flags_foreign_or_writable_dirs() {
        let p = Path::new("/x");
        assert!(root_owned_problem(p, 0, 0o755).is_none());
        assert!(root_owned_problem(p, 99, 0o755).is_some());
        assert!(root_owned_problem(p, 0, 0o775).is_some());
        assert!(root_owned_problem(p, 0, 0o757).is_some());
    }
}
