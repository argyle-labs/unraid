//! The orca ownership labels `adopt` and `set_icon` write, and the
//! conversion of a container's anonymous volumes into labeled ones.
//!
//! An adopted container is its own stack: `orca.stack` and `orca.service`
//! are the template (container) name, `orca.owner` is `unraid`.
//!
//! Labels on an existing volume cannot change, so an anonymous volume is
//! converted: a new volume `<name>_<path-slug>` is created with the labels,
//! the stopped container's data is copied into it and verified, and the
//! template mounts it with `--mount …,volume-label=…`, so docker recreates
//! it labeled if it is ever removed. The volume is named because a source-less
//! `--mount` would give every dockerMan rebuild a fresh, empty volume.

use std::collections::{BTreeMap, BTreeSet};

use super::inspect::{self, ContainerInspect, VolumeInspect};
use super::template::{self, LabeledVolume};
use super::validate_name;
use crate::labels::{Labels, MANAGED, MOUNT, OWNER, OWNER_UNRAID, SERVICE, STACK};

/// Labels every container orca deploys must carry.
pub const CONTAINER_KEYS: &[&str] = &[MANAGED, OWNER, STACK, SERVICE];
/// Labels every volume orca creates must carry.
pub const VOLUME_KEYS: &[&str] = &[MANAGED, OWNER, STACK, SERVICE, MOUNT];

pub fn container_labels(name: &str) -> BTreeMap<String, String> {
    Labels::for_(OWNER_UNRAID, name, Some(name), None).to_map()
}

pub fn volume_labels(name: &str, target: &str) -> BTreeMap<String, String> {
    Labels::for_(OWNER_UNRAID, name, Some(name), None)
        .with_mount(target)
        .to_map()
}

/// `/var/lib/app data` → `var_lib_app_data`, as the docker plugin names
/// converted volumes.
pub fn slug(path: &str) -> String {
    let s: String = path
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    let s = s
        .split('_')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    if s.is_empty() { "root".to_string() } else { s }
}

/// One anonymous volume converted to a labeled named volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversion {
    pub old: String,
    pub new: String,
    pub target: String,
    pub read_only: bool,
    pub labels: BTreeMap<String, String>,
    /// `new` already exists with exactly these labels and no container
    /// uses it (a re-run after a failed one), so it is not created again.
    pub reuse: bool,
    /// `old` is empty, so the mount sets `volume-nocopy`.
    pub nocopy: bool,
}

impl Conversion {
    pub fn mount(&self) -> LabeledVolume {
        LabeledVolume {
            labels: self.labels.clone(),
            nocopy: self.nocopy,
        }
    }

    pub fn mount_arg(&self) -> String {
        template::volume_mount_arg(&self.new, &self.target, self.read_only, &self.mount())
    }
}

/// The name `old`, mounted at `target` in `name`, converts to.
pub fn converted_name(name: &str, target: &str) -> String {
    format!("{name}_{}", slug(target))
}

/// Conversions for `c`'s anonymous volumes except `skip`, and why any of
/// them cannot be converted. `existing` holds the planned names that
/// already exist as volumes; `empty` the anonymous volumes found empty.
pub fn plan_conversions(
    c: &ContainerInspect,
    volumes: &BTreeMap<String, VolumeInspect>,
    existing: &BTreeMap<String, VolumeInspect>,
    empty: &BTreeSet<String>,
    all: &[ContainerInspect],
    skip: &[String],
) -> (Vec<Conversion>, Vec<String>) {
    let name = c.short_name();
    let mut out = Vec::new();
    let mut blockers = Vec::new();
    let mut taken = BTreeSet::new();
    for m in c.volumes() {
        let Some(old) = m.name.clone() else { continue };
        if skip.contains(&old) || !volumes.get(&old).is_some_and(VolumeInspect::is_anonymous) {
            continue;
        }
        let new = converted_name(name, &m.destination);
        let target = m.destination.clone();
        let mut problems = inspect::local_volume_problems(&old, volumes.get(&old), &m.source);
        let others = inspect::mounted_by_others(&old, name, all);
        if !others.is_empty() {
            problems.push(format!(
                "volume {old} is also mounted by [{}]",
                others.join(", ")
            ));
        }
        if !template::mount_safe(&target) {
            problems.push(format!(
                "anonymous volume {old} at {target:?}: the path cannot be a --mount field; \
                 convert it by hand"
            ));
        }
        if let Err(e) = validate_name("volume", &new) {
            problems.push(format!("anonymous volume {old}: {e:#}"));
        }
        if !taken.insert(new.to_lowercase()) {
            problems.push(format!(
                "anonymous volumes of {name} both convert to {new}; convert them by hand"
            ));
        }
        let labels = volume_labels(name, &target);
        let reuse = match existing.get(&new) {
            None => false,
            Some(v) => {
                let users = all
                    .iter()
                    .filter(|o| o.volumes().any(|x| x.name.as_deref() == Some(new.as_str())))
                    .count();
                if v.labels() == labels && users == 0 {
                    true
                } else {
                    problems.push(format!(
                        "volume {new} already exists and is not an unused one orca labeled for \
                         {name}:{target}"
                    ));
                    false
                }
            }
        };
        blockers.extend(problems);
        out.push(Conversion {
            nocopy: empty.contains(&old),
            old,
            new,
            target,
            read_only: !m.rw,
            labels,
            reuse,
        });
    }
    (out, blockers)
}

/// What writing `want` over `have` changes, for `intendedChanges`.
pub fn label_changes(
    what: &str,
    have: &BTreeMap<String, String>,
    want: &BTreeMap<String, String>,
) -> Vec<String> {
    want.iter()
        .filter_map(|(k, v)| match have.get(k) {
            None => Some(format!("{what}: label {k}={v} added")),
            Some(h) if h != v => Some(format!("{what}: label {k} {h} -> {v}")),
            _ => None,
        })
        .collect()
}

/// `required` keys `labels` lacks.
pub fn missing(labels: &BTreeMap<String, String>, required: &[&str]) -> Vec<String> {
    required
        .iter()
        .filter(|k| !labels.contains_key(**k))
        .map(|k| k.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker_adopt::inspect::{ANONYMOUS_VOLUME_LABEL, MountPoint};

    const ANON: &str = "0f3a5c0e9b7d4e21a6c8b2f1d3e5a7c9b1d3f5e7a9c1b3d5f7e9a1c3b5d7f9e1";

    fn anon_volume(name: &str) -> VolumeInspect {
        VolumeInspect {
            name: name.into(),
            driver: "local".into(),
            mountpoint: VolumeInspect::expected_mountpoint(name),
            labels: Some(BTreeMap::from([(
                ANONYMOUS_VOLUME_LABEL.to_string(),
                String::new(),
            )])),
            options: None,
            created_at: String::new(),
        }
    }

    fn container(mounts: &[(&str, &str)]) -> ContainerInspect {
        ContainerInspect {
            name: "/app".into(),
            mounts: mounts
                .iter()
                .map(|(n, d)| MountPoint {
                    kind: "volume".into(),
                    name: Some(n.to_string()),
                    source: VolumeInspect::expected_mountpoint(n),
                    destination: d.to_string(),
                    rw: true,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn anonymous_volumes_convert_to_labeled_named_volumes() {
        let c = container(&[(ANON, "/var/lib/app data"), ("named", "/cfg")]);
        let vols = BTreeMap::from([
            (ANON.to_string(), anon_volume(ANON)),
            (
                "named".to_string(),
                VolumeInspect {
                    labels: None,
                    ..anon_volume("named")
                },
            ),
        ]);
        let (conv, blockers) = plan_conversions(
            &c,
            &vols,
            &BTreeMap::new(),
            &BTreeSet::new(),
            std::slice::from_ref(&c),
            &[],
        );
        assert!(blockers.is_empty(), "{blockers:?}");
        assert_eq!(conv.len(), 1, "only the anonymous volume converts");
        let cv = &conv[0];
        assert_eq!(cv.old, ANON);
        assert_eq!(cv.new, "app_var_lib_app_data");
        assert!(!cv.reuse);
        assert_eq!(cv.labels[MANAGED], "true");
        assert_eq!(cv.labels[OWNER], "unraid");
        assert_eq!(cv.labels[STACK], "app");
        assert_eq!(cv.labels[SERVICE], "app");
        assert_eq!(cv.labels[MOUNT], "/var/lib/app data");
        assert_eq!(
            cv.mount_arg(),
            "type=volume,src=app_var_lib_app_data,dst=/var/lib/app data,\
             volume-label=orca.managed=true,volume-label=orca.mount=/var/lib/app data,\
             volume-label=orca.owner=unraid,volume-label=orca.service=app,\
             volume-label=orca.stack=app"
        );
    }

    #[test]
    fn an_existing_target_is_reused_only_when_it_is_orcas_and_unused() {
        let c = container(&[(ANON, "/data")]);
        let vols = BTreeMap::from([(ANON.to_string(), anon_volume(ANON))]);
        let mut ours = anon_volume("app_data");
        ours.labels = Some(volume_labels("app", "/data"));
        let existing = BTreeMap::from([("app_data".to_string(), ours.clone())]);
        let (conv, b) = plan_conversions(
            &c,
            &vols,
            &existing,
            &BTreeSet::new(),
            std::slice::from_ref(&c),
            &[],
        );
        assert!(b.is_empty(), "{b:?}");
        assert!(conv[0].reuse);

        let user = container(&[("app_data", "/x")]);
        let (_, b) = plan_conversions(
            &c,
            &vols,
            &existing,
            &BTreeSet::new(),
            &[c.clone(), user],
            &[],
        );
        assert!(b[0].contains("already exists"), "{b:?}");

        ours.labels = None;
        let existing = BTreeMap::from([("app_data".to_string(), ours)]);
        let (_, b) = plan_conversions(
            &c,
            &vols,
            &existing,
            &BTreeSet::new(),
            std::slice::from_ref(&c),
            &[],
        );
        assert!(b[0].contains("already exists"), "{b:?}");
    }

    #[test]
    fn unconvertible_anonymous_volumes_block() {
        let other = "1".repeat(64);
        let c = container(&[(ANON, "/a,b"), (&other, "/A_B")]);
        let mut shared = c.clone();
        shared.name = "/sidecar".into();
        shared.mounts.truncate(1);
        let mut vols = BTreeMap::from([
            (ANON.to_string(), anon_volume(ANON)),
            (other.clone(), anon_volume(&other)),
        ]);
        vols.get_mut(&other).unwrap().driver = "nfs".into();
        let (_, b) = plan_conversions(
            &c,
            &vols,
            &BTreeMap::new(),
            &BTreeSet::new(),
            &[c.clone(), shared],
            &[],
        );
        let all = b.join(" | ");
        assert!(all.contains("cannot be a --mount field"), "{all}");
        assert!(all.contains("also mounted by [sidecar]"), "{all}");
        assert!(all.contains("not a plain local volume"), "{all}");
        assert!(all.contains("both convert to app_a_b"), "{all}");
    }

    #[test]
    fn skipped_volumes_are_not_converted() {
        let c = container(&[(ANON, "/data")]);
        let vols = BTreeMap::from([(ANON.to_string(), anon_volume(ANON))]);
        let (conv, _) = plan_conversions(
            &c,
            &vols,
            &BTreeMap::new(),
            &BTreeSet::new(),
            std::slice::from_ref(&c),
            &[ANON.to_string()],
        );
        assert!(conv.is_empty());
    }

    #[test]
    fn label_changes_name_only_what_differs() {
        let want = container_labels("pbs");
        let mut have = BTreeMap::from([
            (OWNER.to_string(), "docker".to_string()),
            (STACK.to_string(), "pbs".to_string()),
        ]);
        let ch = label_changes("container pbs", &have, &want);
        assert_eq!(
            ch,
            vec![
                "container pbs: label orca.managed=true added",
                "container pbs: label orca.owner docker -> unraid",
                "container pbs: label orca.service=pbs added",
            ]
        );
        have.extend(want.clone());
        assert!(label_changes("container pbs", &have, &want).is_empty());
        assert_eq!(missing(&BTreeMap::new(), &[MANAGED]), vec![MANAGED]);
    }

    #[test]
    fn slugs_match_the_docker_plugin() {
        assert_eq!(slug("/var/lib/app data"), "var_lib_app_data");
        assert_eq!(slug("/"), "root");
        assert_eq!(slug("/Config"), "config");
    }
}
