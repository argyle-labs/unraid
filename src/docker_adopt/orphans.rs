//! Which leftovers an adopt may remove: dangling anonymous volumes, the old
//! compose network, the self-stack directory, and the migrated named volumes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::inspect::{COMPOSE_PROJECT, COMPOSE_WORKING_DIR, ContainerInspect, is_anonymous_volume};

/// Dangling volumes that are anonymous and mounted by no container. Named
/// dangling volumes are left alone: a name means someone meant to keep it.
pub fn removable_volumes(dangling: &[String], all: &[ContainerInspect]) -> Vec<String> {
    let in_use: BTreeSet<&str> = all
        .iter()
        .flat_map(|c| c.volumes())
        .filter_map(|m| m.name.as_deref())
        .collect();
    dangling
        .iter()
        .filter(|v| is_anonymous_volume(v) && !in_use.contains(v.as_str()))
        .cloned()
        .collect()
}

/// The compose resources an adopted container leaves behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeLeftovers {
    pub project: String,
    /// `<project>_default`, if that is the network the container used.
    pub network: Option<String>,
    /// `(stack dir, retire-to dir)` when the stack is this container's own.
    pub retire: Option<(PathBuf, PathBuf)>,
    /// Why the stack directory is kept, when it is.
    pub keep_reason: Option<String>,
}

/// Compose leftovers for `c`, judged against every container on the host
/// (`all`, which may include `c`). The stack directory is retired only when
/// no other container belongs to the project and nothing mounts from inside it.
pub fn compose_leftovers(
    c: &ContainerInspect,
    all: &[ContainerInspect],
    date: &str,
) -> Option<ComposeLeftovers> {
    let project = c.compose_project()?.to_string();
    let default_net = format!("{project}_default");
    let network = (c.network() == default_net).then_some(default_net);
    let name = c.short_name();

    let mut retire = None;
    let mut keep_reason = None;
    match c.label(COMPOSE_WORKING_DIR).filter(|d| !d.is_empty()) {
        None => keep_reason = Some("container carries no compose working_dir".to_string()),
        Some(dir) => {
            let dir = Path::new(dir);
            let base = dir.file_name().and_then(|b| b.to_str()).unwrap_or("");
            let siblings: Vec<&str> = all
                .iter()
                .filter(|o| {
                    o.short_name() != name && o.label(COMPOSE_PROJECT) == Some(project.as_str())
                })
                .map(|o| o.short_name())
                .collect();
            let mounted_from: Vec<String> = binds_under(dir, all).into_iter().collect();
            if base != name && base != project {
                keep_reason = Some(format!(
                    "{} is not {name}'s own stack directory",
                    dir.display()
                ));
            } else if !siblings.is_empty() {
                keep_reason = Some(format!(
                    "project {project} still has containers [{}]",
                    siblings.join(", ")
                ));
            } else if !mounted_from.is_empty() {
                keep_reason = Some(format!(
                    "{} is still bind-mounted ({})",
                    dir.display(),
                    mounted_from.join(", ")
                ));
            } else if let Some(to) = retire_target(dir, name, date) {
                retire = Some((dir.to_path_buf(), to));
            } else {
                keep_reason = Some(format!("{} has no parent directory", dir.display()));
            }
        }
    }
    Some(ComposeLeftovers {
        project,
        network,
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

/// Per-volume destination under `/mnt/user/appdata/<name>/`. The suffix drops
/// a `<name>`/`<project>` prefix; anonymous volumes are named after their
/// mount target. Collisions get a numeric suffix.
pub fn appdata_suffixes(
    name: &str,
    project: Option<&str>,
    volumes: &[(String, String)],
) -> Vec<String> {
    let mut used = BTreeSet::new();
    let mut out = Vec::new();
    for (vol, target) in volumes {
        let mut base = if is_anonymous_volume(vol) {
            Path::new(target)
                .file_name()
                .and_then(|b| b.to_str())
                .unwrap_or("data")
                .to_string()
        } else {
            let mut s = vol.as_str();
            for p in [Some(name), project].into_iter().flatten() {
                for sep in ['-', '_'] {
                    if let Some(rest) = s.strip_prefix(&format!("{p}{sep}")) {
                        s = rest;
                    }
                }
            }
            s.to_string()
        };
        if base.is_empty() {
            base = "data".to_string();
        }
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

/// Bind sources of any container that lie under `dir`.
pub fn binds_under(dir: &Path, all: &[ContainerInspect]) -> BTreeSet<String> {
    all.iter()
        .flat_map(|c| c.mounts.iter())
        .filter(|m| m.kind == "bind" && Path::new(&m.source).starts_with(dir))
        .map(|m| m.source.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retire_target_is_a_sibling_of_stacks() {
        assert_eq!(
            retire_target(Path::new("/opt/stacks/dockge"), "dockge", "20261004"),
            Some(PathBuf::from("/opt/stacks-retired/dockge-compose-20261004"))
        );
    }

    #[test]
    fn appdata_suffixes_strip_prefixes_and_dedupe() {
        let anon = "a".repeat(64);
        let got = appdata_suffixes(
            "pbs",
            Some("stack"),
            &[
                ("pbs-config".into(), "/etc/x".into()),
                ("stack_data".into(), "/data".into()),
                (anon, "/data".into()),
                ("other".into(), "/o".into()),
            ],
        );
        assert_eq!(got, vec!["config", "data", "data-2", "other"]);
    }
}
