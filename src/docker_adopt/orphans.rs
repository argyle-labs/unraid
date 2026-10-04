//! Which leftovers an adopt may remove: the container's own anonymous
//! volumes and image once unused, its compose network, and its compose stack
//! directory. Nothing outside what the container owned is ever a candidate.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use super::inspect::{COMPOSE_PROJECT, COMPOSE_WORKING_DIR, ContainerInspect, VolumeInspect};

/// Stack roots a compose working dir may be retired from, besides those
/// listed one per line in [`STACKS_ROOTS_FILE`].
pub const DEFAULT_STACKS_ROOTS: &[&str] = &["/opt/stacks", "/mnt/user/appdata/dockge/stacks"];
/// Root-owned (flash) list of extra stack roots, readable by both sides.
pub const STACKS_ROOTS_FILE: &str = "/boot/config/plugins/orca/unraid-stacks-roots";
pub const COMPOSE_FILES: &[&str] = &[
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
];

pub fn stacks_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = DEFAULT_STACKS_ROOTS.iter().map(PathBuf::from).collect();
    if let Ok(s) = std::fs::read_to_string(STACKS_ROOTS_FILE) {
        roots.extend(
            s.lines()
                .map(str::trim)
                .filter(|l| l.starts_with('/'))
                .map(PathBuf::from),
        );
    }
    roots
}

/// The `/mnt/user` path for a pool or `user0` path to the same share
/// (`/mnt/cache/appdata/x` → `/mnt/user/appdata/x`), so binds compare by share.
/// A bare `/mnt/<x>` is kept: it may be a pool root or any other mount point
/// (e.g. a remote backup target), and only a share path can be aliased.
pub fn share_alias(p: &Path) -> PathBuf {
    let mut c = p.components();
    let (Some(Component::RootDir), Some(Component::Normal(mnt)), Some(Component::Normal(pool))) =
        (c.next(), c.next(), c.next())
    else {
        return p.to_path_buf();
    };
    let pool = pool.to_string_lossy();
    if c.as_path().as_os_str().is_empty()
        || mnt != "mnt"
        || matches!(
            pool.as_ref(),
            "user" | "disks" | "remotes" | "addons" | "rootshare"
        )
    {
        return p.to_path_buf();
    }
    Path::new("/mnt/user").join(c.as_path())
}

/// Bind sources of any container that lie under `dir`, comparing shares by
/// their `/mnt/user` alias.
pub fn binds_under(dir: &Path, all: &[ContainerInspect]) -> BTreeSet<String> {
    let dir = share_alias(dir);
    all.iter()
        .flat_map(|c| c.mounts.iter())
        .filter(|m| m.kind == "bind" && share_alias(Path::new(&m.source)).starts_with(&dir))
        .map(|m| m.source.clone())
        .collect()
}

/// Bind sources of any container that contain `path` or lie inside it.
pub fn binds_overlapping(path: &Path, all: &[ContainerInspect]) -> BTreeSet<String> {
    let path = share_alias(path);
    all.iter()
        .flat_map(|c| c.mounts.iter())
        .filter(|m| {
            let s = share_alias(Path::new(&m.source));
            m.kind == "bind" && (s.starts_with(&path) || path.starts_with(&s))
        })
        .map(|m| m.source.clone())
        .collect()
}

/// Containers attached to `network`, in any state.
pub fn network_users(network: &str, all: &[ContainerInspect]) -> Vec<String> {
    all.iter()
        .filter(|c| {
            c.host_config.network_mode == network
                || c.network_settings
                    .networks
                    .as_ref()
                    .is_some_and(|n| n.contains_key(network))
        })
        .map(|c| c.short_name().to_string())
        .collect()
}

/// The container's anonymous volumes (by docker's anonymous-volume label).
pub fn own_anonymous_volumes(
    c: &ContainerInspect,
    volumes: &BTreeMap<String, VolumeInspect>,
) -> Vec<String> {
    c.volumes()
        .filter_map(|m| m.name.as_deref())
        .filter(|n| volumes.get(*n).is_some_and(VolumeInspect::is_anonymous))
        .map(str::to_string)
        .collect()
}

/// Candidates no container mounts any more.
pub fn unmounted(candidates: &[String], all: &[ContainerInspect]) -> Vec<String> {
    let in_use: BTreeSet<&str> = all
        .iter()
        .flat_map(|c| c.volumes())
        .filter_map(|m| m.name.as_deref())
        .collect();
    candidates
        .iter()
        .filter(|v| !in_use.contains(v.as_str()))
        .cloned()
        .collect()
}

/// The compose resources an adopted container leaves behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeLeftovers {
    pub project: String,
    /// `<project>_default`, if that is the network the container used.
    pub network: Option<String>,
    /// Why the container cannot leave its compose network.
    pub network_blocker: Option<String>,
    /// The stack directory and its retire target, when it may be retired.
    pub retire: Option<(PathBuf, PathBuf)>,
    /// Why the stack directory is kept, when it is.
    pub keep_reason: Option<String>,
}

/// Whether a compose file's content names `project` (or the directory does).
pub fn compose_matches(dir: &Path, project: &str, compose: &str) -> bool {
    let by_dir = dir.file_name().and_then(|b| b.to_str()) == Some(project);
    let by_name = compose.lines().any(|l| {
        l.strip_prefix("name:")
            .map(|v| v.trim().trim_matches(['"', '\'']))
            == Some(project)
    });
    by_dir || by_name
}

/// Compose leftovers for `c`, judged against every container on the host
/// (`all`, which may include `c`). `compose_file` is the content of the
/// stack's compose file, if one exists.
pub fn compose_leftovers(
    c: &ContainerInspect,
    all: &[ContainerInspect],
    date: &str,
    roots: &[PathBuf],
    compose_file: Option<&str>,
) -> Option<ComposeLeftovers> {
    let project = c.compose_project()?.to_string();
    let default_net = format!("{project}_default");
    let name = c.short_name();
    let (network, network_blocker) = if c.network() == default_net {
        let others: Vec<String> = network_users(&default_net, all)
            .into_iter()
            .filter(|n| n != name)
            .collect();
        let blocker = (!others.is_empty()).then(|| {
            format!(
                "{default_net} is shared with [{}]; moving {name} to bridge would cut it off",
                others.join(", ")
            )
        });
        (Some(default_net), blocker)
    } else {
        (None, None)
    };

    let mut retire = None;
    let keep_reason = match c.label(COMPOSE_WORKING_DIR).filter(|d| !d.is_empty()) {
        None => Some("container carries no compose working_dir".to_string()),
        Some(dir) => {
            let dir = Path::new(dir);
            let siblings: Vec<&str> = all
                .iter()
                .filter(|o| {
                    o.short_name() != name && o.label(COMPOSE_PROJECT) == Some(project.as_str())
                })
                .map(|o| o.short_name())
                .collect();
            let mounted_from: Vec<String> = binds_under(dir, all).into_iter().collect();
            let under_root = dir.parent().is_some_and(|p| roots.iter().any(|r| r == p));
            if !under_root {
                Some(format!(
                    "{} is not directly under a configured stacks root",
                    dir.display()
                ))
            } else if !compose_file.is_some_and(|f| compose_matches(dir, &project, f)) {
                Some(format!(
                    "{} has no compose file for project {project}",
                    dir.display()
                ))
            } else if !siblings.is_empty() {
                Some(format!(
                    "project {project} still has containers [{}]",
                    siblings.join(", ")
                ))
            } else if !mounted_from.is_empty() {
                Some(format!(
                    "{} is still bind-mounted ({})",
                    dir.display(),
                    mounted_from.join(", ")
                ))
            } else {
                match retire_target(dir, name, date) {
                    Some(to) => {
                        retire = Some((dir.to_path_buf(), to));
                        None
                    }
                    None => Some(format!("{} has no parent directory", dir.display())),
                }
            }
        }
    };
    Some(ComposeLeftovers {
        project,
        network,
        network_blocker,
        retire,
        keep_reason,
    })
}

/// `/x/stacks/<dir>` → `/x/stacks-retired/<name>-compose-<date>`.
pub fn retire_target(dir: &Path, name: &str, date: &str) -> Option<PathBuf> {
    let stacks = dir.parent()?;
    let stacks_name = stacks.file_name()?.to_str()?;
    let root = stacks.parent()?;
    Some(
        root.join(format!("{stacks_name}-retired"))
            .join(format!("{name}-compose-{date}")),
    )
}

/// Per-volume folder name under `/mnt/user/appdata/<name>/`. Drops a
/// `<name>`/`<project>` prefix; collisions get a numeric suffix.
pub fn appdata_suffixes(name: &str, project: Option<&str>, volumes: &[String]) -> Vec<String> {
    let mut used = BTreeSet::new();
    let mut out = Vec::new();
    for vol in volumes {
        let mut s = vol.as_str();
        for p in [Some(name), project].into_iter().flatten() {
            for sep in ['-', '_'] {
                if let Some(rest) = s.strip_prefix(&format!("{p}{sep}")) {
                    s = rest;
                }
            }
        }
        let base = if s.is_empty() { "data" } else { s }.to_string();
        let mut cand = base.clone();
        let mut n = 2;
        while !used.insert(cand.clone()) {
            cand = format!("{base}-{n}");
            n += 1;
        }
        out.push(cand);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_counts_ancestor_and_descendant_binds() {
        let c = |src: &str| ContainerInspect {
            mounts: vec![crate::docker_adopt::inspect::MountPoint {
                kind: "bind".into(),
                source: src.into(),
                destination: "/x".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let dest = Path::new("/mnt/user/appdata/pbs/config");
        for src in [
            "/mnt/user/appdata/pbs",
            "/mnt/cache/appdata",
            "/mnt/user/appdata/pbs/config/sub",
            "/mnt/user/appdata/pbs/config",
        ] {
            assert_eq!(binds_overlapping(dest, &[c(src)]).len(), 1, "{src}");
        }
        assert!(binds_overlapping(dest, &[c("/mnt/user/appdata/pbs2")]).is_empty());
        assert!(binds_overlapping(dest, &[c("/mnt/user/appdata/pbs/logs")]).is_empty());
        assert!(binds_under(dest, &[c("/mnt/user/appdata/pbs")]).is_empty());
    }

    #[test]
    fn retire_target_is_a_sibling_of_stacks() {
        assert_eq!(
            retire_target(Path::new("/opt/stacks/dockge"), "dockge", "20261004"),
            Some(PathBuf::from("/opt/stacks-retired/dockge-compose-20261004"))
        );
    }

    #[test]
    fn appdata_suffixes_strip_prefixes_and_dedupe() {
        let got = appdata_suffixes(
            "whisper-ai",
            Some("stack"),
            &[
                "whisper-ai_whisper_cache".into(),
                "stack_data".into(),
                "data".into(),
                "other".into(),
            ],
        );
        assert_eq!(got, vec!["whisper_cache", "data", "data-2", "other"]);
    }

    #[test]
    fn share_alias_maps_pools_to_user() {
        assert_eq!(
            share_alias(Path::new("/mnt/cache/appdata/x")),
            PathBuf::from("/mnt/user/appdata/x")
        );
        assert_eq!(
            share_alias(Path::new("/mnt/user0/appdata")),
            PathBuf::from("/mnt/user/appdata")
        );
        assert_eq!(
            share_alias(Path::new("/mnt/user/appdata")),
            PathBuf::from("/mnt/user/appdata")
        );
        assert_eq!(
            share_alias(Path::new("/mnt/disks/ssd/x")),
            PathBuf::from("/mnt/disks/ssd/x")
        );
        assert_eq!(share_alias(Path::new("/opt/x")), PathBuf::from("/opt/x"));
        assert_eq!(
            share_alias(Path::new("/mnt/pbs-remote")),
            PathBuf::from("/mnt/pbs-remote")
        );
    }

    #[test]
    fn compose_match_by_dir_or_name() {
        assert!(compose_matches(
            Path::new("/opt/stacks/dockge"),
            "dockge",
            ""
        ));
        assert!(compose_matches(
            Path::new("/opt/stacks/x"),
            "dockge",
            "name: \"dockge\"\nservices: {}"
        ));
        assert!(!compose_matches(
            Path::new("/opt/stacks/x"),
            "dockge",
            "services: {}"
        ));
    }
}
