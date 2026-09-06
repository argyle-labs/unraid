//! Share-permission introspection for the Unraid user shares (`/mnt/user`).
//!
//! The plugin side of orca's `permissions` capability domain (see
//! `contract::permissions`): the host that actually serves the shares owns the
//! answer for its own filesystem. This provider runs **on the Unraid peer** (like
//! [`crate::checks`]), reading `/mnt/user/<share>` directly, so the write-denied
//! share repair can *detect what comparable shares are doing* — the modes the
//! sibling shares carry — and present a candidate to confirm rather than guess.
//!
//! An Unraid user share is a `shfs` FUSE union over the array + cache, but its
//! directory perms stat like plain POSIX, so read/peer enumeration is ordinary
//! `stat`/`readdir`. The value of exposing it from the plugin is ownership: named
//! `"unraid"` (not `"posix"`), the resolver prefers it for `/mnt/user` paths, and
//! it is the seam where any future non-POSIX enrichment (share-config intended
//! mode, SMB export security) would live. Paths outside `/mnt/user` return `None`,
//! so core's `posix` fallback still answers for them.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::contract::permissions::{PermInfo, PermissionsProvider};

/// The Unraid user-share root. Shares are its immediate children.
const SHARE_ROOT: &str = "/mnt/user";

/// The `permissions` provider unraid advertises (`read` + `reference_peers`),
/// scoped to `/mnt/user`.
pub struct UnraidPermissions;

impl PermissionsProvider for UnraidPermissions {
    fn name(&self) -> &str {
        crate::PROVIDER
    }

    fn read(&self, path: &str) -> BoxFuture<'_, Option<PermInfo>> {
        let path = path.to_string();
        Box::pin(async move {
            if !under_share_root(&path) {
                return None; // not ours — core's `posix` provider answers
            }
            stat_perm(&path)
        })
    }

    fn reference_peers(&self, path: &str) -> BoxFuture<'_, Vec<(String, PermInfo)>> {
        let path = path.to_string();
        Box::pin(async move { sibling_perms(&path) })
    }
}

/// The sibling shares of `path` (its reference peers) with their perms. Empty
/// when `path` is not a share under `/mnt/user`.
fn sibling_perms(path: &str) -> Vec<(String, PermInfo)> {
    if !under_share_root(path) {
        return Vec::new();
    }
    let p = Path::new(path);
    let Some(parent) = p.parent() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|sib| sib.as_path() != p) // exclude the target itself
        .filter(|sib| sib.is_dir()) // shares are directories
        .filter_map(|sib| {
            let s = sib.to_string_lossy().to_string();
            stat_perm(&s).map(|info| (s, info))
        })
        .collect()
}

/// Whether `path` lies under `/mnt/user` (lexical prefix check — the resolver
/// only calls this for candidate share paths, and a non-owned path merely yields
/// `None`/empty, so a stricter canonicalizing guard buys nothing here).
fn under_share_root(path: &str) -> bool {
    Path::new(path).starts_with(SHARE_ROOT)
}

/// Read POSIX mode/uid/gid for a path. `None` if it can't be stat'd.
fn stat_perm(path: &str) -> Option<PermInfo> {
    let meta = std::fs::metadata(path).ok()?;
    Some(PermInfo {
        mode: meta.permissions().mode() & 0o7777,
        uid: meta.uid(),
        gid: meta.gid(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_answers_for_share_root_paths() {
        assert!(sibling_perms("/tmp/x").is_empty(), "not under /mnt/user");
    }

    #[test]
    fn under_share_root_matches_children_only() {
        assert!(under_share_root("/mnt/user/photos"));
        assert!(under_share_root("/mnt/user"));
        assert!(!under_share_root("/mnt/user0/photos")); // sibling mount, not a child
        assert!(!under_share_root("/mnt/disk1/photos"));
    }
}
