use std::sync::Mutex;

use plugin_toolkit::contract::BoxFuture;

use super::*;
use crate::docker_adopt::inspect::{ContainerInspect, ImageInspect, MountPoint, VolumeInspect};
use crate::docker_adopt::template::{ConfigKind, Template};
use crate::labels;

fn first(raw: &str) -> Value {
    match serde_json::from_str::<Value>(raw).unwrap() {
        Value::Array(mut v) => v.swap_remove(0),
        v => v,
    }
}

struct Fx {
    c: ContainerInspect,
    c_raw: Value,
    img: ImageInspect,
    img_raw: Value,
    rendered: &'static str,
}

fn fx(c: &str, img: &str, rendered: &'static str) -> Fx {
    let c_raw = first(c);
    let img_raw = first(img);
    Fx {
        c: serde_json::from_value(c_raw.clone()).unwrap(),
        img: serde_json::from_value(img_raw.clone()).unwrap(),
        c_raw,
        img_raw,
        rendered,
    }
}

fn pbs() -> Fx {
    fx(
        include_str!("fixtures/fx-pbs.container.json"),
        include_str!("fixtures/fx-pbs.image.json"),
        include_str!("fixtures/fx-pbs.rendered.txt"),
    )
}

fn whisper() -> Fx {
    fx(
        include_str!("fixtures/fx-whisper-ai.container.json"),
        include_str!("fixtures/fx-whisper-ai.image.json"),
        include_str!("fixtures/fx-whisper-ai.rendered.txt"),
    )
}

/// Real, already dockerMan-managed dockge.
fn dockge() -> Fx {
    fx(
        include_str!("fixtures/fx-dockge.container.json"),
        include_str!("fixtures/fx-dockge.image.json"),
        include_str!("fixtures/fx-dockge.rendered.txt"),
    )
}

/// Synthetic compose-created container (dockge-like, before adoption).
fn compose() -> Fx {
    fx(
        include_str!("fixtures/compose-synthetic.container.json"),
        include_str!("fixtures/compose-synthetic.image.json"),
        "",
    )
}

/// Unraid's daemon log rotation on the fixture host (50m, 1 file).
fn daemon_opts() -> BTreeMap<String, String> {
    [("max-size", "50m"), ("max-file", "1")]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn local_volume(name: &str) -> VolumeInspect {
    VolumeInspect {
        name: name.to_string(),
        driver: "local".into(),
        mountpoint: VolumeInspect::expected_mountpoint(name),
        labels: None,
        options: None,
        created_at: String::new(),
    }
}

fn snapshot(f: &Fx) -> Snapshot {
    let volumes =
        f.c.volumes()
            .filter_map(|m| m.name.clone())
            .map(|n| (n.clone(), local_volume(&n)))
            .collect();
    Snapshot {
        container: f.c.clone(),
        container_raw: f.c_raw.clone(),
        image: f.img.clone(),
        image_raw: f.img_raw.clone(),
        tag_image_id: Some(f.c.image.clone()),
        all: vec![f.c.clone()],
        volumes,
        run_id: RUN_ID.to_string(),
        nonce: NONCE.to_string(),
        daemon_log_opts: daemon_opts(),
        stacks_roots: orphans::DEFAULT_STACKS_ROOTS
            .iter()
            .map(PathBuf::from)
            .collect(),
        ..Snapshot::default()
    }
}

fn opts(repo: Option<&str>, migrate: bool) -> AdoptOpts {
    AdoptOpts {
        repo: repo.map(str::to_string),
        icon_base: template::DEFAULT_ICON_BASE.to_string(),
        migrate_volumes: migrate,
        autostart: None,
    }
}

const RUN_ID: &str = "20261004-120000-0123abcd";
const NONCE: &str = "0123456789abcdef";

fn gate_mode(plan: &AdoptPlan, rendered: &str, mode: DiffMode) -> (Vec<String>, Vec<String>) {
    let (_, d) = fidelity(
        &plan.target,
        &plan.unsupported,
        &plan.baked_env,
        &daemon_opts(),
        rendered,
        mode,
    );
    split_deltas(d, &Redactor::default())
}

/// The adopt gate: what dockerMan renders from orca's generated template.
fn gate(plan: &AdoptPlan, rendered: &str) -> (Vec<String>, Vec<String>) {
    gate_mode(plan, rendered, DiffMode::Adopt)
}

/// The set_icon gate: what dockerMan renders from a template someone else wrote.
fn gate_existing(plan: &AdoptPlan, rendered: &str) -> (Vec<String>, Vec<String>) {
    gate_mode(plan, rendered, DiffMode::SetIcon)
}

/// The fixture's real rendered command as dockerMan renders it once the
/// template carries orca's ownership labels.
fn labeled(f: &Fx) -> String {
    let flags: String = ownership::container_labels(f.c.short_name())
        .iter()
        .map(|(k, v)| format!("--label={k}={v} "))
        .collect();
    f.rendered
        .replacen(" create ", &format!(" create {flags}"), 1)
}

/// Escape like PHP's `escapeshellarg`, which dockerMan uses for every value.
fn esc(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// What dockerMan's `xmlToCommand` emits for a template, in the order the
/// real fixtures show: its own env, labels and pids limit first, then
/// Configs, ExtraParams, image and PostArgs.
fn simulate_render(t: &Template) -> String {
    let mut p = vec![
        "/usr/local/emhttp/plugins/dynamix.docker.manager/scripts/docker".to_string(),
        "create".to_string(),
        format!("--name={}", esc(&t.name)),
        format!("--net={}", esc(&t.network)),
    ];
    if t.privileged {
        p.push("--privileged=true".to_string());
    }
    p.push("--pids-limit 2048".to_string());
    p.push(r#"-e TZ="""#.to_string());
    p.push(r#"-e HOST_OS="Unraid""#.to_string());
    p.push(r#"-e HOST_HOSTNAME="""#.to_string());
    p.push(format!(r#"-e HOST_CONTAINERNAME="{}""#, t.name));
    for c in t.configs.iter().filter(|c| c.kind == ConfigKind::Variable) {
        p.push(format!("-e {}={}", esc(&c.target), esc(&c.value)));
    }
    p.push("-l net.unraid.docker.managed=dockerman".to_string());
    p.push(format!("-l net.unraid.docker.icon={}", esc(&t.icon)));
    for c in &t.configs {
        match c.kind {
            ConfigKind::Port => p.push(format!(
                "-p {}",
                esc(&format!("{}:{}/{}", c.value, c.target, c.mode))
            )),
            ConfigKind::Path => p.push(format!(
                "-v {}:{}:{}",
                esc(&c.value),
                esc(&c.target),
                esc(&c.mode)
            )),
            ConfigKind::Variable => {}
        }
    }
    if !t.extra_params.is_empty() {
        p.push(t.extra_params.clone());
    }
    p.push(esc(&t.repository));
    if !t.post_args.is_empty() {
        p.push(t.post_args.clone());
    }
    p.join(" ")
}

// ── real fixtures: dockerMan's own rendered command vs the live container ──

#[test]
fn real_pbs_passes_the_gate() {
    let f = pbs();
    let plan = plan_adopt(&snapshot(&f), &opts(Some("pbs"), false));
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(plan.unsupported.is_empty(), "{:?}", plan.unsupported);
    let (blocking, intended) = gate(&plan, &simulate_render(&plan.template));
    assert!(blocking.is_empty(), "{blocking:?}");
    assert_eq!(
        intended,
        vec!["pids-limit unlimited -> 2048 (dockerMan default)"]
    );

    // The hand-written template on willow omits --restart: fine for
    // set_icon, which keeps that template's state, but adopt must keep it.
    let (blocking, intended) = gate_existing(&plan, &labeled(&f));
    assert!(blocking.is_empty(), "{blocking:?}");
    assert_eq!(
        intended,
        vec![
            "restart policy unless-stopped dropped; Unraid autostart starts it with the array",
            "pids-limit unlimited -> 2048 (dockerMan default)",
        ]
    );
    let (blocking, _) = gate(&plan, &labeled(&f));
    assert_eq!(
        blocking,
        vec![r#"restart: live Some("unless-stopped"), rendered None"#]
    );
    // An old-id hostname that is not this container's own id is pinned.
    assert_eq!(plan.live.hostname.as_deref(), Some("62c7f1883665"));
    assert!(!plan.live.hostname_is_default);
}

#[test]
fn real_whisper_passes_the_gate() {
    let f = whisper();
    let plan = plan_adopt(&snapshot(&f), &opts(Some("whisper-ai"), false));
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(plan.unsupported.is_empty(), "{:?}", plan.unsupported);
    let (blocking, intended) = gate(&plan, &simulate_render(&plan.template));
    assert!(blocking.is_empty(), "{blocking:?}");
    assert_eq!(intended.len(), 1, "{intended:?}");
    assert!(intended[0].starts_with("pids-limit"));

    let (blocking, intended) = gate_existing(&plan, &labeled(&f));
    assert!(blocking.is_empty(), "{blocking:?}");
    assert_eq!(intended.len(), 3, "{intended:?}");
    assert!(intended[0].starts_with("hostname bc405da8c18f (docker's default)"));
    let (blocking, _) = gate(&plan, &labeled(&f));
    assert_eq!(blocking.len(), 1, "{blocking:?}");
    assert!(blocking[0].starts_with("restart:"));
    assert_eq!(plan.live.tz, "America/Denver");
    assert_eq!(plan.live.gpus.as_deref(), Some("all"));
    assert!(!plan.live.env.contains_key("NVIDIA_VISIBLE_DEVICES"));
    assert!(!plan.live.env.contains_key("PATH"));
}

#[test]
fn real_rendered_parses_and_drops_unraid_injections() {
    let got = spec::parse_command(pbs().rendered).unwrap();
    assert_eq!(got.pids_limit, Some(2048));
    assert_eq!(got.tz, "");
    assert!(!got.env.contains_key("HOST_OS"));
    assert!(!got.labels.keys().any(|k| k.starts_with("net.unraid")));
    let w = spec::parse_command(whisper().rendered).unwrap();
    assert_eq!(
        w.tz, "America/Denver",
        "the template TZ comes after Unraid's TZ=\"\""
    );
}

#[test]
fn real_pbs_dropping_tmpfs_blocks() {
    let f = pbs();
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    let dropped = labeled(&f).replace("--tmpfs /run/proxmox-backup:rw,nosuid,nodev,mode=0755 ", "");
    let (blocking, _) = gate_existing(&plan, &dropped);
    assert_eq!(blocking.len(), 1, "{blocking:?}");
    assert!(blocking[0].starts_with("tmpfs /run/proxmox-backup"));
}

#[test]
fn real_whisper_without_gpus_blocks() {
    let f = whisper();
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    let (blocking, _) = gate_existing(&plan, &labeled(&f).replace("--gpus all ", ""));
    assert_eq!(blocking, vec![r#"gpus: live Some("all"), rendered None"#]);
}

#[test]
fn real_dockge_is_managed_so_adopt_refuses_and_set_icon_passes() {
    let f = dockge();
    let mut s = snapshot(&f);
    s.existing_template = Some("<Container><Name>dockge</Name></Container>".into());
    let plan = plan_adopt(&s, &opts(Some("dockge"), false));
    assert!(
        plan.blockers
            .iter()
            .any(|b| b.contains("use unraid.docker.set_icon")),
        "{:?}",
        plan.blockers
    );

    assert!(set_icon_blockers(&s).is_empty());
    let (live, unsupported) = live_spec(&f.c, &f.img);
    let mut unsupported = unsupported;
    unsupported.extend(inspect::unmodelled(&f.c_raw, &f.img_raw, false));
    let (got, d) = fidelity(
        &live,
        &unsupported,
        &inspect::baked_env(&f.img),
        &daemon_opts(),
        f.rendered,
        DiffMode::SetIcon,
    );
    let (blocking, _) = split_deltas(d, &Redactor::default());
    assert!(blocking.is_empty(), "{blocking:?}");
    let steps = set_icon_steps(&s, "<x/>", "u", got.unwrap(), &[]);
    let actions: Vec<&str> = steps.iter().map(Step::action).collect();
    assert_eq!(
        actions,
        vec![
            "probe-root",
            "save-inspect",
            "write-template",
            "set-autostart",
            "rebuild",
            "set-autostart",
            "ensure-state",
            "verify-managed",
            "clear-icon-cache",
            "refresh-icons"
        ]
    );
}

#[test]
fn set_icon_refuses_unmanaged_and_moved_tags() {
    let f = pbs();
    let mut s = snapshot(&f);
    assert!(set_icon_blockers(&s)[0].contains("not dockerMan-managed"));
    s.tag_image_id = Some("sha256:other".into());
    assert!(set_icon_blockers(&s)[1].contains("would switch images"));
}

// ── generated templates (secondary: simulated dockerMan render) ─────────────

#[test]
fn generated_pbs_template_round_trips() {
    let f = pbs();
    let plan = plan_adopt(&snapshot(&f), &opts(Some("pbs"), false));
    let t = &plan.template;
    for want in [
        "--mount type=bind,src=/mnt/pbs-remote,dst=/mnt/pbs-remote,bind-propagation=rslave",
        "--hostname 62c7f1883665",
        "--tmpfs /run/proxmox-backup:rw,nosuid,nodev,mode=0755",
        "--log-opt max-file=1",
        "--restart unless-stopped",
    ] {
        assert!(
            t.extra_params.contains(want),
            "{want} in {}",
            t.extra_params
        );
    }
    assert!(!t.extra_params.contains("--pids-limit"));
    assert!(
        !t.configs
            .iter()
            .any(|c| c.kind == ConfigKind::Path && c.target == "/mnt/pbs-remote")
    );
    assert!(!t.configs.iter().any(|c| c.target == "TZ"));
    let xml = &plan.template_xml;
    assert!(xml.contains(template::MANAGED_MARKER));
    assert!(xml.contains(
        r#"<Config Name="Path /etc/proxmox-backup" Target="/etc/proxmox-backup" Default="pbs-config" Mode="rw""#
    ));
    let (blocking, _) = gate(&plan, &simulate_render(t));
    assert!(blocking.is_empty(), "{blocking:?}");
}

#[test]
fn generated_whisper_template_pins_hostname_and_tz() {
    let f = whisper();
    let plan = plan_adopt(&snapshot(&f), &opts(Some("whisper-ai"), false));
    let t = &plan.template;
    assert!(t.extra_params.contains("--hostname bc405da8c18f"));
    assert!(t.extra_params.contains("--gpus all"));
    assert!(
        t.configs
            .iter()
            .any(|c| c.target == "TZ" && c.value == "America/Denver")
    );
    let (blocking, intended) = gate(&plan, &simulate_render(t));
    assert!(blocking.is_empty(), "{blocking:?}");
    assert!(!intended.iter().any(|i| i.starts_with("hostname")));
}

#[test]
fn baked_tz_is_written_so_unraid_cannot_blank_it() {
    let mut f = pbs();
    f.img.config.env.as_mut().unwrap().push("TZ=UTC".into());
    f.c.config.env.as_mut().unwrap().push("TZ=UTC".into());
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    assert_eq!(plan.target.tz, "UTC");
    assert!(plan.template.configs.iter().any(|c| c.target == "TZ"));
    let (blocking, _) = gate_existing(&plan, &labeled(&f));
    assert_eq!(blocking, vec![r#"TZ: live "UTC", rendered """#]);
    let (blocking, _) = gate(&plan, &simulate_render(&plan.template));
    assert!(blocking.is_empty(), "{blocking:?}");
}

#[test]
fn pids_limit_other_than_unraids_is_carried_or_blocks() {
    let mut f = pbs();
    f.c.host_config.pids_limit = Some(500);
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    assert!(plan.template.extra_params.contains("--pids-limit 500"));
    let (blocking, _) = gate(&plan, &simulate_render(&plan.template));
    assert!(blocking.is_empty(), "{blocking:?}");
    let (blocking, _) = gate_existing(&plan, &labeled(&f));
    assert_eq!(
        blocking,
        vec!["pids-limit: live Some(500), rendered Some(2048)"]
    );
}

// ── blockers ────────────────────────────────────────────────────────────────

#[test]
fn moved_image_tag_blocks() {
    let f = pbs();
    let mut s = snapshot(&f);
    s.tag_image_id = Some("sha256:newer".into());
    assert!(image_blocker(&s).unwrap().contains("would switch images"));
    s.tag_image_id = None;
    assert!(image_blocker(&s).unwrap().contains("no longer resolves"));
}

#[test]
fn unmodelled_facets_block() {
    let f = pbs();
    assert!(inspect::unmodelled(&f.c_raw, &f.img_raw, false).is_empty());
    let mut raw = f.c_raw.clone();
    raw["HostConfig"]["CapAdd"] = serde_json::json!(["NET_ADMIN"]);
    raw["HostConfig"]["IpcMode"] = serde_json::json!("shareable");
    raw["HostConfig"]["OomScoreAdj"] = serde_json::json!(-500);
    raw["Config"]["StopSignal"] = serde_json::json!("SIGINT");
    raw["Config"]["Healthcheck"]["Retries"] = serde_json::json!(9);
    raw["NetworkSettings"]["Networks"]["bridge"]["Aliases"] = serde_json::json!(["pbs"]);
    raw["HostConfig"]["Binds"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("v:/x:nocopy"));
    raw["HostConfig"]["Mounts"][0]["BindOptions"]["CreateMountpoint"] = serde_json::json!(true);
    let u = inspect::unmodelled(&raw, &f.img_raw, false);
    for want in [
        "HostConfig.CapAdd",
        "HostConfig.IpcMode",
        "HostConfig.OomScoreAdj",
        "Config.StopSignal",
        "Config.Healthcheck",
        "Aliases",
        "nocopy",
        "BindOptions",
    ] {
        assert!(u.iter().any(|x| x.contains(want)), "{want} in {u:?}");
    }
    assert!(
        !inspect::unmodelled(&raw, &f.img_raw, true)
            .iter()
            .any(|x| x.contains("Aliases"))
    );
}

#[test]
fn template_name_collisions_block() {
    let t = vec![
        ("my-pbs.xml".to_string(), Some("pbs".to_string())),
        ("my-PBS.xml".to_string(), Some("x".to_string())),
        ("my-other.xml".to_string(), Some("Pbs".to_string())),
        ("my-fine.xml".to_string(), Some("fine".to_string())),
    ];
    assert_eq!(template_collisions("pbs", &t).len(), 2);
}

// ── compose ─────────────────────────────────────────────────────────────────

fn compose_snapshot() -> Snapshot {
    let f = compose();
    let mut s = snapshot(&f);
    s.tag_image_id = Some(f.c.image.clone());
    s.compose_file = Some("services:\n  dockge: {}\n".into());
    s
}

#[test]
fn compose_container_moves_to_bridge_and_retires_its_stack() {
    let s = compose_snapshot();
    let plan = plan_adopt(&s, &opts(Some("dockge"), false));
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert_eq!(plan.target.network, "bridge");
    assert_eq!(
        plan.intended,
        vec![
            "network dockge_default -> bridge",
            "compose project dockge labels dropped",
            "container dockge: label orca.managed=true added",
            "container dockge: label orca.owner=unraid added",
            "container dockge: label orca.service=dockge added",
            "container dockge: label orca.stack=dockge added",
        ]
    );
    assert!(plan.steps.contains(&Step::RemoveNetwork {
        network: "dockge_default".into()
    }));
    assert!(plan.steps.contains(&Step::RetireStack {
        project: "dockge".into(),
        dir: "/opt/stacks/dockge".into(),
        to: "/opt/stacks-retired/dockge-compose-20261004".into(),
    }));
    let (blocking, _) = gate(&plan, &simulate_render(&plan.template));
    assert!(blocking.is_empty(), "{blocking:?}");
}

#[test]
fn stacks_under_a_writable_root_are_not_retired() {
    let mut s = compose_snapshot();
    s.stacks_root_problems.insert(
        PathBuf::from("/opt/stacks"),
        "/opt/stacks is owned by uid 99".into(),
    );
    let plan = plan_adopt(&s, &opts(None, false));
    let l = plan.compose.unwrap();
    assert!(l.retire.is_none());
    assert!(l.keep_reason.unwrap().contains("uid 99"));
    assert!(!plan.steps.iter().any(|st| st.action() == "retire-stack"));
}

#[test]
fn a_bad_pre_existing_retired_dir_is_a_plan_problem() {
    if host::euid() != Some(0) {
        return; // only root can make a root-owned stacks root
    }
    let d = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(d.path()).unwrap().join("stacks");
    std::fs::create_dir(&root).unwrap();
    assert!(stacks_root_problems(std::slice::from_ref(&root)).is_empty());
    let retired = root.with_file_name("stacks-retired");
    std::fs::write(&retired, b"").unwrap();
    let p = stacks_root_problems(std::slice::from_ref(&root));
    assert!(p[&root].contains("not a real directory"), "{p:?}");
    std::fs::remove_file(&retired).unwrap();
    std::os::unix::fs::symlink("/etc", &retired).unwrap();
    let p = stacks_root_problems(std::slice::from_ref(&root));
    assert!(p[&root].contains("pre-existing"), "{p:?}");
}

#[test]
fn compose_network_shared_with_another_container_blocks() {
    let mut s = compose_snapshot();
    let mut other = s.container.clone();
    other.name = "/dockge-db".into();
    other.config.labels = None;
    s.all.push(other);
    let plan = plan_adopt(&s, &opts(None, false));
    assert!(
        plan.blockers.iter().any(|b| b.contains("dockge-db")),
        "{:?}",
        plan.blockers
    );
}

#[test]
fn compose_stack_kept_unless_rooted_with_compose_file_and_unmounted() {
    let mut s = compose_snapshot();
    s.compose_file = None;
    let l = plan_adopt(&s, &opts(None, false)).compose.unwrap();
    assert!(l.retire.is_none());
    assert!(l.keep_reason.unwrap().contains("no compose file"));

    let mut s = compose_snapshot();
    s.stacks_roots = vec![PathBuf::from("/elsewhere")];
    let l = plan_adopt(&s, &opts(None, false)).compose.unwrap();
    assert!(l.keep_reason.unwrap().contains("stacks root"));

    let mut s = compose_snapshot();
    s.container.config.labels.as_mut().unwrap().insert(
        inspect::COMPOSE_WORKING_DIR.into(),
        "/mnt/user/appdata/dockge/stacks/dockge".into(),
    );
    s.stacks_roots = vec![PathBuf::from("/mnt/user/appdata/dockge/stacks")];
    s.container.mounts.push(MountPoint {
        kind: "bind".into(),
        source: "/mnt/cache/appdata/dockge/stacks/dockge/data".into(),
        destination: "/app/data2".into(),
        ..Default::default()
    });
    s.all = vec![s.container.clone()];
    let l = plan_adopt(&s, &opts(None, false)).compose.unwrap();
    assert!(
        l.keep_reason
            .as_deref()
            .unwrap()
            .contains("still bind-mounted"),
        "{l:?}"
    );
}

// ── migrate-volumes ─────────────────────────────────────────────────────────

#[test]
fn migrate_rewrites_paths_and_orders_steps() {
    let f = pbs();
    let plan = plan_adopt(&snapshot(&f), &opts(Some("pbs"), true));
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert_eq!(
        plan.migrations,
        vec![
            Migration {
                volume: "pbs-config".into(),
                suffix: "config".into(),
                to: "/mnt/user/appdata/pbs/config".into(),
            },
            Migration {
                volume: "pbs-logs".into(),
                suffix: "logs".into(),
                to: "/mnt/user/appdata/pbs/logs".into(),
            },
        ]
    );
    assert!(!plan.template_xml.contains("pbs-config"));
    let (blocking, _) = gate(&plan, &simulate_render(&plan.template));
    assert!(blocking.is_empty(), "{blocking:?}");
    let actions: Vec<&str> = plan.steps.iter().map(Step::action).collect();
    assert_eq!(
        actions,
        vec![
            "probe-root",
            "stop",
            "copy-volume",
            "copy-volume",
            "save-inspect",
            "write-template",
            "set-autostart",
            "expose-copy",
            "expose-copy",
            "ensure-stopped",
            "rebuild",
            "ensure-state",
            "verify-managed",
            "clear-icon-cache",
            "refresh-icons",
            "remove-volume",
            "remove-volume",
        ]
    );
}

#[test]
fn migrate_refuses_unsafe_volumes() {
    let f = pbs();
    let mut s = snapshot(&f);
    s.volumes.get_mut("pbs-config").unwrap().driver = "nfs".into();
    s.volumes.get_mut("pbs-logs").unwrap().mountpoint = "/".into();
    let mut other = f.c.clone();
    other.name = "/pbs-sidecar".into();
    s.all.push(other);
    let b = plan_adopt(&s, &opts(None, true)).blockers;
    assert!(
        b.iter().any(|x| x.contains("not a plain local volume")),
        "{b:?}"
    );
    assert!(b.iter().any(|x| x.contains("data at \"/\"")), "{b:?}");
    assert!(
        b.iter()
            .any(|x| x.contains("also mounted by [pbs-sidecar]")),
        "{b:?}"
    );
}

// ── autostart and cleanup scope ─────────────────────────────────────────────

#[test]
fn stopped_autostart_container_stays_stopped_across_rebuild() {
    let mut f = pbs();
    f.c.state.running = false;
    f.c.state.status = "exited".into();
    let mut s = snapshot(&f);
    s.autostart = vec!["pbs".into()];
    let plan = plan_adopt(&s, &opts(None, false));
    let i = plan.steps.iter().position(|x| x == &Step::Rebuild).unwrap();
    assert_eq!(plan.steps[i - 1], Step::SetAutostart { on: false });
    assert_eq!(plan.steps[i + 1], Step::SetAutostart { on: true });
    assert_eq!(plan.steps[i + 2], Step::EnsureState { running: false });
}

#[test]
fn cleanup_only_targets_the_containers_own_anonymous_volumes() {
    let f = pbs();
    let mut s = snapshot(&f);
    let anon = "a".repeat(64);
    s.container.mounts.push(MountPoint {
        kind: "volume".into(),
        name: Some(anon.clone()),
        destination: "/anon".into(),
        ..Default::default()
    });
    let mut v = local_volume(&anon);
    v.labels = Some(BTreeMap::from([(
        inspect::ANONYMOUS_VOLUME_LABEL.to_string(),
        String::new(),
    )]));
    s.volumes.insert(anon.clone(), v);
    let plan = plan_adopt(&s, &opts(None, false));
    assert!(plan.steps.contains(&Step::RemoveOwnAnonymousVolumes {
        candidates: vec![anon]
    }));
    assert!(!plan.steps.iter().any(|x| x.action().contains("prune")));
}

// ── secrets ─────────────────────────────────────────────────────────────────

#[test]
fn secrets_are_masked_in_every_output() {
    let mut f = pbs();
    f.c.config
        .env
        .as_mut()
        .unwrap()
        .push("API_TOKEN=hunter2-secret".into());
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    assert!(
        plan.template_xml
            .contains(r#"Mask="true">hunter2-secret</Config>"#)
    );
    let r = redactor_for(&f.c, &[&plan.target]);
    let shown = r.text(&redact::mask_template_xml(&plan.template_xml));
    assert!(!shown.contains("hunter2"), "{shown}");

    let cmd = simulate_render(&plan.template);
    let masked = mask_command(&cmd, &r);
    assert!(!masked.contains("hunter2"), "{masked}");
    assert!(masked.contains("API_TOKEN=<redacted:"), "{masked}");

    let (blocking, _) = gate(&plan, f.rendered);
    let joined = blocking.join(" ");
    assert!(joined.contains("API_TOKEN"), "{joined}");
    assert!(!joined.contains("hunter2"), "{joined}");
}

#[test]
fn ampersands_are_double_escaped_for_dockerman() {
    let mut f = pbs();
    f.c.config.labels = Some(BTreeMap::from([(
        "traefik.rule".to_string(),
        "Host(`x`) && Path(`/a b`)".to_string(),
    )]));
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    assert!(
        plan.template_xml.contains("&amp;amp;&amp;amp;"),
        "{}",
        plan.template_xml
    );
    let (blocking, _) = gate(&plan, &simulate_render(&plan.template));
    assert!(blocking.is_empty(), "{blocking:?}");
}

// ── apply path, against a mock host ─────────────────────────────────────────

struct Mock {
    calls: Mutex<Vec<String>>,
    ops: Mutex<Vec<PrivilegedOp>>,
    fail_on: Option<&'static str>,
    /// `docker stop`/`start` flip its running state.
    container: Mutex<ContainerInspect>,
    image: ImageInspect,
    /// Output of a call with this prefix.
    outputs: Vec<(String, String)>,
}

impl Mock {
    fn new(
        container: ContainerInspect,
        image: ImageInspect,
        fail_on: Option<&'static str>,
    ) -> Self {
        Mock {
            calls: Mutex::new(Vec::new()),
            ops: Mutex::new(Vec::new()),
            fail_on,
            container: Mutex::new(container),
            image,
            outputs: Vec::new(),
        }
    }
    fn with_output(mut self, prefix: &str, out: &str) -> Self {
        self.outputs.push((prefix.to_string(), out.to_string()));
        self
    }
    fn record(&self, call: String) -> Result<String> {
        self.calls.lock().unwrap().push(call.clone());
        match self.fail_on {
            Some(f) if call == f => bail!("boom {}", "hunter2-secret"),
            _ => Ok(self
                .outputs
                .iter()
                .find(|(p, _)| call.starts_with(p.as_str()))
                .map(|(_, o)| o.clone())
                .unwrap_or_default()),
        }
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

fn op_name(op: &PrivilegedOp) -> String {
    serde_json::to_value(op).unwrap()["op"]
        .as_str()
        .unwrap()
        .to_string()
}

impl HostOps for Mock {
    fn docker<'a>(&'a self, args: &'a [&'a str]) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            let out = self.record(format!("docker {}", args.join(" ")))?;
            match args.first() {
                Some(&"stop") => self.container.lock().unwrap().state.running = false,
                Some(&"start") => self.container.lock().unwrap().state.running = true,
                _ => {}
            }
            Ok(out)
        })
    }
    fn inspect_container<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Result<ContainerInspect>> {
        Box::pin(async move { Ok(self.container.lock().unwrap().clone()) })
    }
    fn inspect_image<'a>(&'a self, _id: &'a str) -> BoxFuture<'a, Result<ImageInspect>> {
        Box::pin(async move { Ok(self.image.clone()) })
    }
    fn inspect_all(&self) -> BoxFuture<'_, Result<Vec<ContainerInspect>>> {
        Box::pin(async move { Ok(vec![self.container.lock().unwrap().clone()]) })
    }
    fn privileged<'a>(&'a self, op: &'a PrivilegedOp) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            self.ops.lock().unwrap().push(op.clone());
            self.record(format!("priv {}", op_name(op)))
        })
    }
}

fn ctx(plan: &AdoptPlan, f: &Fx) -> ApplyCtx {
    ApplyCtx {
        tool: "unraid.docker.adopt",
        name: f.c.short_name().to_string(),
        run_id: RUN_ID.into(),
        nonce: NONCE.into(),
        was_running: plan.was_running,
        autostart_before: false,
        had_template: false,
        original: plan.live.clone(),
        conversions: plan.conversions.clone(),
        redactor: redactor_for(&f.c, &[&plan.target]),
        state: Mutex::new(ApplyState::new(&f.c)),
    }
}

#[tokio::test]
async fn failure_before_rebuild_rolls_back_this_runs_changes() {
    let mut f = pbs();
    f.c.config
        .env
        .as_mut()
        .unwrap()
        .push("API_TOKEN=hunter2-secret".into());
    let plan = plan_adopt(&snapshot(&f), &opts(None, true));
    let mock = Mock::new(f.c.clone(), f.img.clone(), Some("priv set_autostart"));
    let err = apply(&mock, &ctx(&plan, &f), &plan.steps)
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        mock.calls(),
        vec![
            "priv ping",
            "docker stop pbs",
            "priv copy_volume",
            "priv copy_volume",
            "priv save_inspect",
            "priv write_template",
            "priv set_autostart",
            "priv restore_template",
            "priv set_autostart",
            "priv remove_copy",
            "priv remove_copy",
            "docker start pbs",
        ]
    );
    assert!(err.contains("failed at `set-autostart"), "{err}");
    assert!(
        err.contains("Rolled back: [restore template; restore autostart FAILED"),
        "{err}"
    );
    assert!(
        err.contains("remove copy config; remove copy logs; start container"),
        "{err}"
    );
    assert!(!err.contains("hunter2"), "{err}");

    // Every op that names a backup or a copy carries this run's id/nonce.
    for op in mock.ops.lock().unwrap().iter() {
        match op {
            PrivilegedOp::WriteTemplate { backup_id, .. }
            | PrivilegedOp::SaveInspect { backup_id, .. }
            | PrivilegedOp::RestoreTemplate { backup_id, .. } => assert_eq!(backup_id, RUN_ID),
            PrivilegedOp::CopyVolume { nonce, .. } | PrivilegedOp::RemoveCopy { nonce, .. } => {
                assert_eq!(nonce, NONCE)
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn migrated_copies_are_exposed_right_before_the_rebuild() {
    let mut f = pbs();
    f.c.config.labels = Some(BTreeMap::from([(
        MANAGED_LABEL.to_string(),
        MANAGED_BY_DOCKERMAN.to_string(),
    )]));
    f.c.state.running = true;
    f.c.state.status = "running".into();
    let mut plan = plan_adopt(&snapshot(&f), &opts(None, true));
    // The mock returns the same container after rebuild; verify against it.
    let (live, _) = live_spec(&f.c, &f.img);
    for st in plan.steps.iter_mut() {
        if let Step::VerifyManaged { expect, .. } = st {
            **expect = live.clone();
        }
    }
    let mock = Mock::new(f.c.clone(), f.img.clone(), None);
    apply(&mock, &ctx(&plan, &f), &plan.steps).await.unwrap();
    let calls = mock.calls();
    let rebuild = calls.iter().position(|c| c == "priv rebuild").unwrap();
    assert_eq!(
        &calls[rebuild - 2..rebuild],
        &["priv expose_copy", "priv expose_copy"],
        "{calls:?}"
    );
    assert!(
        mock.ops
            .lock()
            .unwrap()
            .iter()
            .any(|o| matches!(o, PrivilegedOp::ExposeCopy { nonce, .. } if nonce == NONCE))
    );
}

#[tokio::test]
async fn exposed_copies_are_left_in_place_by_a_rollback() {
    let f = pbs();
    let plan = plan_adopt(&snapshot(&f), &opts(None, true));
    let copy = |suffix: &str| Step::CopyVolume {
        volume: format!("pbs-{suffix}"),
        suffix: suffix.into(),
        to: format!("/mnt/user/appdata/pbs/{suffix}"),
    };
    let steps = vec![
        copy("config"),
        copy("logs"),
        Step::ExposeCopy {
            suffix: "config".into(),
        },
        Step::Stop,
    ];
    let mock = Mock::new(f.c.clone(), f.img.clone(), Some("docker stop pbs"));
    let err = apply(&mock, &ctx(&plan, &f), &steps)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("left exposed copy /mnt/user/appdata/pbs/config in place"),
        "{err}"
    );
    assert!(err.contains("remove copy logs"), "{err}");
    assert!(!err.contains("remove copy config"), "{err}");
    let removed: Vec<PrivilegedOp> = mock
        .ops
        .lock()
        .unwrap()
        .iter()
        .filter(|o| matches!(o, PrivilegedOp::RemoveCopy { .. }))
        .cloned()
        .collect();
    assert_eq!(removed.len(), 1);
}

#[tokio::test]
async fn verify_enforces_restart_for_adopt_but_not_set_icon() {
    let mut f = dockge();
    f.c.host_config.restart_policy = Default::default();
    let (got, _) = live_spec(&f.c, &f.img);
    let mut want = got.clone();
    want.restart = Some("unless-stopped".into());
    let mock = Mock::new(f.c.clone(), f.img.clone(), None);
    let cx = ApplyCtx {
        tool: "t",
        name: "dockge".into(),
        run_id: RUN_ID.into(),
        nonce: NONCE.into(),
        was_running: true,
        autostart_before: true,
        had_template: true,
        original: got.clone(),
        conversions: Vec::new(),
        redactor: Redactor::default(),
        state: Default::default(),
    };
    let verify = |mode| Step::VerifyManaged {
        running: false,
        icon: None,
        image_id: f.c.image.clone(),
        expect: Box::new(want.clone()),
        mode,
    };
    assert!(
        apply(&mock, &cx, &[verify(DiffMode::SetIcon)])
            .await
            .is_ok()
    );
    let err = apply(&mock, &cx, &[verify(DiffMode::Adopt)])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("restart:"), "{err}");
}

struct FakeRunner(bool);

impl PrivilegedRunner for FakeRunner {
    fn kind(&self) -> &'static str {
        "fake"
    }
    fn run<'a>(&'a self, _op: &'a PrivilegedOp) -> BoxFuture<'a, Result<String>> {
        let ok = self.0;
        Box::pin(async move {
            if ok {
                Ok("root".into())
            } else {
                bail!("sudo: a password is required")
            }
        })
    }
}

#[tokio::test]
async fn dry_run_pings_the_root_path() {
    assert!(root_path_blocker(Some(&FakeRunner(true))).await.is_none());
    let b = root_path_blocker(Some(&FakeRunner(false))).await.unwrap();
    assert!(b.contains("failed a ping") && b.contains("orca#762"), "{b}");
    assert!(b.contains("password is required"), "{b}");
    let b = root_path_blocker(None).await.unwrap();
    assert!(b.contains("orca#762"), "{b}");
}

#[tokio::test]
async fn failure_after_rebuild_gives_recovery_not_rollback() {
    let f = pbs();
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    // The mock container lacks the dockerman label, so verification fails.
    let mock = Mock::new(f.c.clone(), f.img.clone(), None);
    let err = apply(&mock, &ctx(&plan, &f), &plan.steps)
        .await
        .unwrap_err()
        .to_string();
    let calls = mock.calls();
    assert_eq!(calls.last().unwrap(), "priv rebuild");
    assert!(!calls.iter().any(|c| c.contains("restore")), "{calls:?}");
    assert!(err.contains("failed at `verify-managed"), "{err}");
    assert!(
        err.contains("original container config is saved at"),
        "{err}"
    );
    assert!(err.contains("docker rm -f pbs && docker run"), "{err}");
}

#[tokio::test]
async fn failed_rebuild_is_reported_with_recovery() {
    let f = pbs();
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    let mock = Mock::new(f.c.clone(), f.img.clone(), Some("priv rebuild"));
    let err = apply(&mock, &ctx(&plan, &f), &plan.steps)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("To recreate the original container"), "{err}");
    assert!(!err.contains("Rolled back"), "{err}");
}

#[tokio::test]
async fn set_icon_applies_end_to_end_on_a_managed_container() {
    let f = dockge();
    let s = snapshot(&f);
    let (live, _) = live_spec(&f.c, &f.img);
    let url = f.c.label(ICON_LABEL).unwrap().to_string();
    let steps = set_icon_steps(&s, "<x/>", &url, live.clone(), &[]);
    let mock = Mock::new(f.c.clone(), f.img.clone(), None);
    let cx = ApplyCtx {
        tool: "unraid.docker.set_icon",
        name: "dockge".into(),
        run_id: RUN_ID.into(),
        nonce: NONCE.into(),
        was_running: true,
        autostart_before: false,
        had_template: true,
        original: live,
        conversions: Vec::new(),
        redactor: Redactor::default(),
        state: Default::default(),
    };
    let out = apply(&mock, &cx, &steps).await.unwrap();
    assert_eq!(out.len(), steps.len());
    assert_eq!(
        mock.calls(),
        vec![
            "priv ping",
            "priv save_inspect",
            "priv write_template",
            "priv set_autostart",
            "priv rebuild",
            "priv set_autostart",
            "priv clear_icon_cache",
            "priv refresh_icons",
        ]
    );
}

// ── shared ──────────────────────────────────────────────────────────────────

#[test]
fn status_reports_template_icon_and_volumes() {
    let f = pbs();
    let xml = Template {
        icon: template::icon_url(template::DEFAULT_ICON_BASE, "pbs"),
        ..Template::default()
    }
    .render();
    let s = container_status(
        &f.c,
        Some(&xml),
        &["pbs".to_string()],
        template::DEFAULT_ICON_BASE,
        &BTreeMap::new(),
    );
    assert!(s.has_template && s.orca_icon && s.autostart);
    assert_eq!(s.managed, None);
    assert_eq!(s.volumes_outside_appdata, vec!["pbs-config", "pbs-logs"]);
}

#[test]
fn icon_base_must_be_https_on_an_allowlisted_host() {
    let ok = |b: &str, extra: &[&str]| {
        template::validate_icon_base(b, &extra.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .is_ok()
    };
    assert!(ok("https://gitea.scottkey.me/argyle-labs", &[]));
    assert!(!ok("http://gitea.scottkey.me/argyle-labs", &[]));
    assert!(!ok("https://evil.example/argyle-labs", &[]));
    assert!(ok("https://icons.lan/x", &["icons.lan"]));
    assert!(!ok("https://gitea.scottkey.me/a'b", &[]));
}

#[test]
fn names_are_validated() {
    assert!(validate_name("container name", "pbs").is_ok());
    assert!(validate_name("container name", "a_b.c-1").is_ok());
    for bad in ["", "-x", ".x", "a b", "a;b", "a/b", "$(x)"] {
        assert!(validate_name("container name", bad).is_err(), "{bad}");
    }
}

#[test]
fn execute_requires_an_admin_caller() {
    let caller = |role: &str| CallerIdentity {
        user_id: "1".into(),
        username: "u".into(),
        role: role.into(),
        can_mutate: true,
    };
    assert!(authorize_execute("t", None).is_err());
    assert!(authorize_execute("t", Some(&caller("read"))).is_err());
    assert!(authorize_execute("t", Some(&caller("admin"))).is_ok());
}

#[test]
fn tools_are_registered_with_their_own_execute_opt_in() {
    use plugin_toolkit::dispatch as registry;
    let names = registry::names();
    for n in [
        "unraid.docker.status",
        "unraid.docker.set_icon",
        "unraid.docker.adopt",
    ] {
        assert!(names.contains(&n), "{n} not registered");
    }
    assert_eq!(registry::required_role("unraid.docker.status"), Some("any"));
    let gated = registry::execute_gated_names();
    let defs = registry::mcp_definitions();
    for n in ["unraid.docker.set_icon", "unraid.docker.adopt"] {
        assert_eq!(registry::required_role(n), Some("admin"));
        assert!(!gated.contains(&n), "{n} must own its execute flag");
        let def = defs.iter().find(|d| d["name"] == n).unwrap();
        assert!(
            def["inputSchema"]["properties"]["execute"].is_object(),
            "{def}"
        );
    }
}

// ── ownership labels and anonymous volumes ──────────────────────────────────

const ANON: &str = "0f3a5c0e9b7d4e21a6c8b2f1d3e5a7c9b1d3f5e7a9c1b3d5f7e9a1c3b5d7f9e1";

/// pbs with an extra anonymous volume at `/var/cache/pbs`.
fn with_anonymous(f: &mut Fx) -> Snapshot {
    f.c.mounts.push(MountPoint {
        kind: "volume".into(),
        name: Some(ANON.into()),
        source: VolumeInspect::expected_mountpoint(ANON),
        destination: "/var/cache/pbs".into(),
        rw: true,
        ..Default::default()
    });
    let mut s = snapshot(f);
    s.volumes.get_mut(ANON).unwrap().labels = Some(BTreeMap::from([(
        inspect::ANONYMOUS_VOLUME_LABEL.to_string(),
        String::new(),
    )]));
    s
}

fn pbs_labels() -> BTreeMap<String, String> {
    BTreeMap::from([
        (labels::MANAGED.to_string(), "true".to_string()),
        (labels::OWNER.to_string(), "unraid".to_string()),
        (labels::SERVICE.to_string(), "pbs".to_string()),
        (labels::STACK.to_string(), "pbs".to_string()),
    ])
}

#[test]
fn adopt_labels_the_container_and_converts_anonymous_volumes() {
    let mut f = pbs();
    f.c.state.running = true;
    let s = with_anonymous(&mut f);
    let plan = plan_adopt(&s, &opts(Some("pbs"), false));
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);

    let mut vol_labels = pbs_labels();
    vol_labels.insert(labels::MOUNT.into(), "/var/cache/pbs".into());
    assert_eq!(
        label_writes("pbs", &plan.labels, &plan.conversions),
        vec![
            LabelWrite {
                kind: "container".into(),
                name: "pbs".into(),
                labels: pbs_labels(),
            },
            LabelWrite {
                kind: "volume".into(),
                name: "pbs_var_cache_pbs".into(),
                labels: vol_labels.clone(),
            },
        ]
    );

    // The template mounts the new volume by name and never the hex one.
    assert!(!plan.template_xml.contains(ANON), "{}", plan.template_xml);
    assert!(
        plan.template.extra_params.contains(
            "--mount type=volume,src=pbs_var_cache_pbs,dst=/var/cache/pbs,\
             volume-label=orca.managed=true,volume-label=orca.mount=/var/cache/pbs,\
             volume-label=orca.owner=unraid,volume-label=orca.service=pbs,\
             volume-label=orca.stack=pbs"
        ),
        "{}",
        plan.template.extra_params
    );
    for (k, v) in pbs_labels() {
        assert!(
            plan.template
                .extra_params
                .contains(&format!("--label {k}={v}")),
            "{k}: {}",
            plan.template.extra_params
        );
    }

    // The fidelity gate passes: the labels and the new volume are intended.
    let rendered = simulate_render(&plan.template);
    let (blocking, intended) = gate(&plan, &rendered);
    assert!(blocking.is_empty(), "{blocking:?}");
    assert_eq!(
        intended,
        vec!["pids-limit unlimited -> 2048 (dockerMan default)"]
    );
    for want in [
        format!("anonymous volume {ANON} at /var/cache/pbs -> volume pbs_var_cache_pbs"),
        "container pbs: label orca.owner=unraid added".to_string(),
        "container pbs: label orca.managed=true added".to_string(),
    ] {
        assert!(plan.intended.contains(&want), "{want}: {:?}", plan.intended);
    }

    let actions: Vec<&str> = plan.steps.iter().map(Step::action).collect();
    assert_eq!(
        actions,
        vec![
            "probe-root",
            "stop",
            "create-volume",
            "copy-into-volume",
            "save-inspect",
            "write-template",
            "set-autostart",
            "ensure-stopped",
            "rebuild",
            "ensure-state",
            "verify-managed",
            "clear-icon-cache",
            "refresh-icons",
            "remove-own-anonymous-volumes",
        ]
    );
    assert!(plan.steps.contains(&Step::CreateVolume {
        volume: "pbs_var_cache_pbs".into(),
        labels: vol_labels,
    }));
    assert!(plan.steps.contains(&Step::RemoveOwnAnonymousVolumes {
        candidates: vec![ANON.into()]
    }));
    // The dry-run plan names each label written to the new volume.
    let detail = plan
        .steps
        .iter()
        .map(|st| st.change("pbs", RUN_ID))
        .find(|c| c.action == "create-volume")
        .unwrap()
        .detail
        .unwrap();
    assert_eq!(
        detail,
        "labels orca.managed=true, orca.mount=/var/cache/pbs, orca.owner=unraid, \
         orca.service=pbs, orca.stack=pbs"
    );
}

#[test]
fn migrate_volumes_copies_anonymous_volumes_to_appdata_instead() {
    let mut f = pbs();
    let s = with_anonymous(&mut f);
    let plan = plan_adopt(&s, &opts(None, true));
    assert!(plan.conversions.is_empty());
    assert_eq!(plan.migrations.len(), 3);
}

#[test]
fn a_rerun_reuses_its_own_empty_volume_and_refuses_a_foreign_one() {
    let mut f = pbs();
    let mut s = with_anonymous(&mut f);
    let mut ours = local_volume("pbs_var_cache_pbs");
    ours.labels = Some(ownership::volume_labels("pbs", "/var/cache/pbs"));
    s.conversion_targets
        .insert("pbs_var_cache_pbs".into(), ours.clone());
    let plan = plan_adopt(&s, &opts(None, false));
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(!plan.steps.iter().any(|x| x.action() == "create-volume"));
    assert!(plan.steps.iter().any(|x| x.action() == "copy-into-volume"));

    ours.labels = None;
    s.conversion_targets
        .insert("pbs_var_cache_pbs".into(), ours);
    let plan = plan_adopt(&s, &opts(None, false));
    assert!(
        plan.blockers.iter().any(|b| b.contains("already exists")),
        "{:?}",
        plan.blockers
    );
}

/// dockge's template as dockerMan has it, with an anonymous volume added.
fn dockge_template() -> String {
    "<?xml version=\"1.0\"?>\n<Container version=\"2\">\n  <Name>dockge</Name>\n  \
     <Repository>louislam/dockge:1</Repository>\n  <Network>bridge</Network>\n  \
     <Icon>https://gitea.scottkey.me/argyle-labs/dockge/raw/branch/main/assets/icon-256.png</Icon>\n  \
     <ExtraParams/>\n  \
     <Config Name=\"Cache\" Target=\"/cache\" Default=\"\" Mode=\"rw\" Description=\"\" Type=\"Path\" \
     Display=\"always\" Required=\"false\" Mask=\"false\">0f3a5c0e9b7d4e21a6c8b2f1d3e5a7c9b1d3f5e7a9c1b3d5f7e9a1c3b5d7f9e1</Config>\n\
     </Container>\n"
        .to_string()
}

fn dockge_with_anonymous() -> (Fx, Snapshot) {
    let mut f = dockge();
    f.c.mounts.push(MountPoint {
        kind: "volume".into(),
        name: Some(ANON.into()),
        source: VolumeInspect::expected_mountpoint(ANON),
        destination: "/cache".into(),
        rw: true,
        ..Default::default()
    });
    let mut s = snapshot(&f);
    s.volumes.get_mut(ANON).unwrap().labels = Some(BTreeMap::from([(
        inspect::ANONYMOUS_VOLUME_LABEL.to_string(),
        String::new(),
    )]));
    (f, s)
}

#[test]
fn set_icon_writes_labels_and_converts_path_entries_idempotently() {
    let (f, s) = dockge_with_anonymous();
    let (live, _) = live_spec(&f.c, &f.img);
    let p = set_icon_patch(&s, &live, &dockge_template());
    assert!(p.blockers.is_empty(), "{:?}", p.blockers);
    assert_eq!(p.conversions.len(), 1);
    assert!(!p.xml.contains(ANON), "{}", p.xml);
    assert!(p.xml.contains("--mount"), "{}", p.xml);
    assert!(p.xml.contains("orca.owner=unraid"), "{}", p.xml);
    assert_eq!(p.target.labels[labels::OWNER], "unraid");
    assert!(
        p.target
            .mounts
            .iter()
            .any(|m| m.source == "dockge_cache" && m.target == "/cache")
    );
    assert!(p.intended.contains(&format!(
        "anonymous volume {ANON} at /cache -> volume dockge_cache"
    )));

    // dockerMan's render of the patched template passes the gate.
    let rendered = format!(
        "{} {}",
        f.rendered.trim().trim_end_matches("'louislam/dockge:1'"),
        "--label orca.managed=true --label orca.owner=unraid --label orca.service=dockge \
         --label orca.stack=dockge --mount type=volume,src=dockge_cache,dst=/cache,\
         volume-label=orca.managed=true,volume-label=orca.mount=/cache,\
         volume-label=orca.owner=unraid,volume-label=orca.service=dockge,\
         volume-label=orca.stack=dockge 'louislam/dockge:1'"
    );
    let (blocking, _) = gate_spec(&p.target, &f, &rendered);
    assert!(blocking.is_empty(), "{blocking:?}");

    // Once applied, the live container has the labels and the named volume:
    // a second set_icon patch changes nothing.
    let mut after = f.c.clone();
    after
        .config
        .labels
        .as_mut()
        .unwrap()
        .extend(ownership::container_labels("dockge"));
    after.mounts.last_mut().unwrap().name = Some("dockge_cache".into());
    let mut s2 = s.clone();
    s2.container = after.clone();
    s2.volumes = BTreeMap::from([(
        "dockge_cache".to_string(),
        VolumeInspect {
            labels: Some(ownership::volume_labels("dockge", "/cache")),
            ..local_volume("dockge_cache")
        },
    )]);
    let (live2, _) = live_spec(&after, &f.img);
    let p2 = set_icon_patch(&s2, &live2, &p.xml);
    assert!(p2.blockers.is_empty(), "{:?}", p2.blockers);
    assert_eq!(p2.xml, p.xml);
    assert!(p2.conversions.is_empty());
    assert!(p2.intended.is_empty(), "{:?}", p2.intended);
}

fn gate_spec(target: &RunSpec, f: &Fx, rendered: &str) -> (Vec<String>, Vec<String>) {
    let (_, d) = fidelity(
        target,
        &[],
        &inspect::baked_env(&f.img),
        &daemon_opts(),
        rendered,
        DiffMode::SetIcon,
    );
    split_deltas(d, &Redactor::default())
}

#[test]
fn set_icon_steps_stop_copy_and_clean_up_for_conversions() {
    let (f, s) = dockge_with_anonymous();
    let (live, _) = live_spec(&f.c, &f.img);
    let p = set_icon_patch(&s, &live, &dockge_template());
    let steps = set_icon_steps(&s, &p.xml, "u", p.target.clone(), &p.conversions);
    let actions: Vec<&str> = steps.iter().map(Step::action).collect();
    assert_eq!(
        actions,
        vec![
            "probe-root",
            "stop",
            "create-volume",
            "copy-into-volume",
            "save-inspect",
            "write-template",
            "set-autostart",
            "ensure-stopped",
            "rebuild",
            "set-autostart",
            "ensure-state",
            "verify-managed",
            "clear-icon-cache",
            "refresh-icons",
            "remove-own-anonymous-volumes",
        ]
    );
}

#[test]
fn a_template_that_cannot_take_labels_still_gets_its_icon() {
    let (f, s) = dockge_with_anonymous();
    let (live, _) = live_spec(&f.c, &f.img);
    let xml = dockge_template().replace(ANON, "/mnt/user/appdata/dockge/cache");
    let p = set_icon_patch(&s, &live, &xml);
    assert!(p.blockers.is_empty(), "{:?}", p.blockers);
    assert!(p.conversions.is_empty());
    assert!(
        p.not_applied[0].contains("not converted: no Path entry"),
        "{:?}",
        p.not_applied
    );
    assert!(p.xml.contains("orca.owner=unraid"), "labels still written");

    let amp = dockge_template().replace(
        "<ExtraParams/>",
        "<ExtraParams>-e A=&amp;amp;</ExtraParams>",
    );
    let p = set_icon_patch(&s, &live, &amp);
    assert!(p.blockers.is_empty(), "{:?}", p.blockers);
    assert_eq!(p.xml, amp, "the icon-only patch is kept");
    assert_eq!(p.target, live);
    assert!(p.labels.is_empty() && p.conversions.is_empty());
    assert!(
        p.not_applied[0]
            .starts_with("ownership labels and anonymous-volume conversions not applied")
            && p.not_applied[0].contains("'&'"),
        "{:?}",
        p.not_applied
    );
    assert!(label_writes("dockge", &p.labels, &p.conversions).is_empty());
    let summary = set_icon_summary(
        "dockge",
        "u",
        false,
        &p.labels,
        &p.conversions,
        &p.not_applied,
    );
    assert!(
        summary.starts_with("set dockge's icon to u and rebuild; not applied: ownership labels"),
        "{summary}"
    );
}

#[test]
fn set_icon_summary_names_only_what_is_applied() {
    let mut f = pbs();
    let s = with_anonymous(&mut f);
    let plan = plan_adopt(&s, &opts(None, false));
    let labels = ownership::container_labels("pbs");
    assert_eq!(
        set_icon_summary("pbs", "u", false, &BTreeMap::new(), &[], &[]),
        "set pbs's icon to u and rebuild"
    );
    assert_eq!(
        set_icon_summary("pbs", "u", false, &labels, &plan.conversions, &[]),
        format!(
            "set pbs's icon to u, write orca's ownership labels, convert anonymous volumes \
             [{ANON}] to labeled volumes and rebuild"
        )
    );
    let s = set_icon_summary("pbs", "u", true, &BTreeMap::new(), &[], &["x: why".into()]);
    assert!(s.contains("nothing to change; not applied: x: why"), "{s}");
}

/// `docker volume inspect` output for a volume carrying `labels`.
fn volume_json(name: &str, labels: &BTreeMap<String, String>, created: &str) -> String {
    serde_json::json!([{
        "Name": name, "Driver": "local",
        "Mountpoint": VolumeInspect::expected_mountpoint(name),
        "Labels": labels, "CreatedAt": created,
    }])
    .to_string()
}

fn digest_reply(d: char) -> String {
    format!(
        "v: 1 entries, 1 bytes, {}{}",
        privileged::MANIFEST_TAG,
        d.to_string().repeat(64)
    )
}

#[tokio::test]
async fn a_failed_copy_removes_the_volume_this_run_created() {
    let mut f = pbs();
    f.c.state.running = true;
    let s = with_anonymous(&mut f);
    let plan = plan_adopt(&s, &opts(None, false));
    let labels = ownership::volume_labels("pbs", "/var/cache/pbs");
    let mock = Mock::new(f.c.clone(), f.img.clone(), Some("priv copy_into_volume"))
        .with_output(
            "docker volume inspect",
            &volume_json("pbs_var_cache_pbs", &labels, "2026-10-04T12:00:00Z"),
        )
        .with_output("priv volume_empty", privileged::VOLUME_EMPTY);
    let err = apply(&mock, &ctx(&plan, &f), &plan.steps)
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        mock.calls(),
        vec![
            "priv ping",
            "docker stop pbs",
            "docker volume ls -q --filter name=pbs_var_cache_pbs",
            "docker volume create --label orca.managed=true --label orca.mount=/var/cache/pbs \
             --label orca.owner=unraid --label orca.service=pbs --label orca.stack=pbs \
             pbs_var_cache_pbs",
            "docker volume inspect pbs_var_cache_pbs",
            "priv volume_empty",
            "priv copy_into_volume",
            "docker volume inspect pbs_var_cache_pbs",
            "docker volume rm pbs_var_cache_pbs",
            "docker start pbs",
        ]
    );
    assert!(
        err.contains("Rolled back: [remove volume pbs_var_cache_pbs; start container]"),
        "{err}"
    );
    assert!(
        mock.ops
            .lock()
            .unwrap()
            .contains(&PrivilegedOp::CopyIntoVolume {
                name: "pbs".into(),
                from: ANON.into(),
                to: "pbs_var_cache_pbs".into(),
            })
    );
}

#[tokio::test]
async fn rollback_keeps_a_volume_recreated_by_someone_else() {
    let f = pbs();
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    let mock = Mock::new(f.c.clone(), f.img.clone(), Some("docker stop pbs")).with_output(
        "docker volume inspect",
        &volume_json("v", &BTreeMap::new(), "2026-10-04T13:00:00Z"),
    );
    let cx = ctx(&plan, &f);
    cx.state
        .lock()
        .unwrap()
        .created
        .push(("v".into(), "2026-10-04T12:00:00Z".into()));
    let err = apply(&mock, &cx, &[Step::Stop])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("remove volume v FAILED"), "{err}");
    assert!(
        err.contains("no longer the volume this run created"),
        "{err}"
    );
    assert!(!mock.calls().contains(&"docker volume rm v".to_string()));
}

#[tokio::test]
async fn a_created_volume_must_be_this_runs() {
    let f = pbs();
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    let step = || Step::CreateVolume {
        volume: "v".into(),
        labels: pbs_labels(),
    };
    // Someone else created `v` first; `docker volume create` still succeeds.
    let mock = Mock::new(f.c.clone(), f.img.clone(), None).with_output(
        "docker volume inspect",
        &volume_json("v", &BTreeMap::new(), "t"),
    );
    let cx = ctx(&plan, &f);
    let err = apply(&mock, &cx, &[step()]).await.unwrap_err().to_string();
    assert!(err.contains("not the requested ones"), "{err}");
    assert!(cx.state.lock().unwrap().created.is_empty());
    assert!(!err.contains("remove volume"), "{err}");

    // Right labels but data in it: also not this run's.
    let mock = Mock::new(f.c.clone(), f.img.clone(), None)
        .with_output(
            "docker volume inspect",
            &volume_json("v", &pbs_labels(), "t"),
        )
        .with_output("priv volume_empty", "not empty");
    let cx = ctx(&plan, &f);
    let err = apply(&mock, &cx, &[step()]).await.unwrap_err().to_string();
    assert!(err.contains("is not empty"), "{err}");
    assert!(cx.state.lock().unwrap().created.is_empty());

    let mock = Mock::new(f.c.clone(), f.img.clone(), None)
        .with_output(
            "docker volume inspect",
            &volume_json("v", &pbs_labels(), "t0"),
        )
        .with_output("priv volume_empty", privileged::VOLUME_EMPTY);
    let cx = ctx(&plan, &f);
    apply(&mock, &cx, &[step()]).await.unwrap();
    assert_eq!(
        cx.state.lock().unwrap().created,
        vec![("v".to_string(), "t0".to_string())]
    );
}

#[tokio::test]
async fn create_volume_refuses_an_existing_volume() {
    let f = pbs();
    let mock = Mock::new(f.c.clone(), f.img.clone(), None)
        .with_output("docker volume ls", "pbs_data_other\npbs_data\n");
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    let step = Step::CreateVolume {
        volume: "pbs_data".into(),
        labels: pbs_labels(),
    };
    let err = apply(&mock, &ctx(&plan, &f), &[step])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("volume pbs_data already exists"), "{err}");
    assert!(!mock.calls().iter().any(|c| c.contains("volume create")));
    // Only an exact name match counts.
    let mock = Mock::new(f.c.clone(), f.img.clone(), None)
        .with_output("docker volume ls", "pbs_data_other\n")
        .with_output(
            "docker volume inspect",
            &volume_json("pbs_data", &pbs_labels(), "t"),
        )
        .with_output("priv volume_empty", privileged::VOLUME_EMPTY);
    let step = Step::CreateVolume {
        volume: "pbs_data".into(),
        labels: pbs_labels(),
    };
    apply(&mock, &ctx(&plan, &f), &[step]).await.unwrap();
}

#[tokio::test]
async fn old_volumes_are_removed_only_when_unchanged_since_their_copy() {
    let f = pbs();
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    let (same, changed, unrecorded, gone) = (
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64),
    );
    let mock = Mock::new(f.c.clone(), f.img.clone(), None)
        .with_output(
            "docker volume ls",
            &format!("{same}\n{changed}\n{unrecorded}\n"),
        )
        .with_output("priv manifest_volume", &digest_reply('1'));
    let cx = ctx(&plan, &f);
    {
        let mut st = cx.state.lock().unwrap();
        st.manifests.insert(same.clone(), "1".repeat(64));
        st.manifests.insert(changed.clone(), "2".repeat(64));
    }
    let out = apply(
        &mock,
        &cx,
        &[Step::RemoveOwnAnonymousVolumes {
            candidates: vec![
                same.clone(),
                changed.clone(),
                unrecorded.clone(),
                gone.clone(),
            ],
        }],
    )
    .await
    .unwrap();
    let rm: Vec<String> = mock
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("docker volume rm"))
        .collect();
    assert_eq!(rm, vec![format!("docker volume rm {same}")]);
    let detail = out[0].detail.clone().unwrap();
    assert!(detail.contains(&format!("removed [{same}]")), "{detail}");
    assert!(
        detail.contains(&format!("already gone [{gone}]")),
        "{detail}"
    );
    assert!(
        detail.contains(&format!(
            "{changed} (changed since it was copied (manifest 222222222222 then, 111111111111 now))"
        )),
        "{detail}"
    );
    assert!(
        detail.contains(&format!(
            "{unrecorded} (no verified copy of it was recorded)"
        )),
        "{detail}"
    );
    // Converted volumes are compared with their extended attributes.
    assert!(
        mock.ops
            .lock()
            .unwrap()
            .iter()
            .any(|o| matches!(o, PrivilegedOp::ManifestVolume { xattrs: true, .. }))
    );
}

#[tokio::test]
async fn a_migrated_volume_changed_since_its_copy_is_kept() {
    let mut f = pbs();
    f.c.state.running = true;
    let plan = plan_adopt(&snapshot(&f), &opts(None, true));
    let mock = Mock::new(f.c.clone(), f.img.clone(), None)
        .with_output("priv manifest_volume", &digest_reply('9'));
    let cx = ctx(&plan, &f);
    cx.state
        .lock()
        .unwrap()
        .manifests
        .insert("pbs-config".into(), "1".repeat(64));
    let out = apply(
        &mock,
        &cx,
        &[Step::RemoveVolume {
            volume: "pbs-config".into(),
        }],
    )
    .await
    .unwrap();
    assert!(
        out[0]
            .detail
            .as_deref()
            .unwrap()
            .starts_with("kept pbs-config: changed since"),
        "{out:?}"
    );
    assert!(!mock.calls().iter().any(|c| c.contains("volume rm")));
    assert!(
        mock.ops
            .lock()
            .unwrap()
            .contains(&PrivilegedOp::ManifestVolume {
                volume: "pbs-config".into(),
                xattrs: false
            })
    );
}

#[tokio::test]
async fn copies_record_their_manifest_for_the_later_removal() {
    let mut f = pbs();
    f.c.state.running = true;
    let plan = plan_adopt(&snapshot(&f), &opts(None, true));
    let mock = Mock::new(f.c.clone(), f.img.clone(), None)
        .with_output("priv copy_volume", &digest_reply('7'));
    let cx = ctx(&plan, &f);
    let steps = [Step::CopyVolume {
        volume: "pbs-config".into(),
        suffix: "config".into(),
        to: "/mnt/user/appdata/pbs/config".into(),
    }];
    apply(&mock, &cx, &steps).await.unwrap();
    assert_eq!(
        cx.state.lock().unwrap().manifests.get("pbs-config"),
        Some(&"7".repeat(64))
    );
}

#[tokio::test]
async fn a_container_started_after_the_copy_is_not_rebuilt() {
    let mut f = pbs();
    f.c.state.running = true;
    let s = with_anonymous(&mut f);
    let plan = plan_adopt(&s, &opts(None, false));
    let mock = Mock::new(f.c.clone(), f.img.clone(), None);
    // Running, as if something started it after the copy.
    let err = apply(
        &mock,
        &ctx(&plan, &f),
        &[Step::EnsureStopped, Step::Rebuild],
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("failed at `ensure-stopped"), "{err}");
    assert!(err.contains("Rolled back"), "a pre-rebuild failure: {err}");
    assert!(!mock.calls().contains(&"priv rebuild".to_string()));
}

#[test]
fn recovery_after_a_rebuild_names_the_converted_volumes() {
    let mut f = pbs();
    let s = with_anonymous(&mut f);
    let plan = plan_adopt(&s, &opts(None, false));
    let r = ctx(&plan, &f).recovery();
    assert!(
        r.contains(
            "Data for /var/cache/pbs is in volume pbs_var_cache_pbs; use -v \
             pbs_var_cache_pbs:/var/cache/pbs"
        ),
        "{r}"
    );
}

#[tokio::test]
async fn stop_records_when_the_container_stopped() {
    let mut f = pbs();
    f.c.state.running = true;
    f.c.state.started_at = "s1".into();
    f.c.state.finished_at = "f0".into();
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    let cx = ctx(&plan, &f);
    assert_eq!(cx.state.lock().unwrap().stopped, None);
    let mock = Mock::new(f.c.clone(), f.img.clone(), None);
    apply(&mock, &cx, &[Step::Stop]).await.unwrap();
    assert_eq!(
        cx.state.lock().unwrap().stopped,
        Some(("s1".to_string(), "f0".to_string()))
    );
}

#[tokio::test]
async fn a_container_that_ran_or_a_source_that_changed_since_the_copy_is_not_rebuilt() {
    let mut f = pbs();
    f.c.state.running = false;
    f.c.state.started_at = "2026-10-04T11:00:00Z".into();
    f.c.state.finished_at = "2026-10-04T11:30:00Z".into();
    let s = with_anonymous(&mut f);
    let plan = plan_adopt(&s, &opts(None, false));
    let steps = [Step::EnsureStopped, Step::Rebuild];
    let run = |reply: char, ran: bool| {
        let mock = Mock::new(f.c.clone(), f.img.clone(), None)
            .with_output("priv manifest_volume", &digest_reply(reply));
        if ran {
            mock.container.lock().unwrap().state.finished_at = "2026-10-04T12:05:00Z".into();
        }
        let cx = ctx(&plan, &f);
        cx.state
            .lock()
            .unwrap()
            .manifests
            .insert(ANON.into(), "1".repeat(64));
        (mock, cx)
    };

    let (mock, cx) = run('1', true);
    let err = apply(&mock, &cx, &steps).await.unwrap_err().to_string();
    assert!(err.contains("ran after its volumes were copied"), "{err}");
    assert!(err.contains("Rolled back"), "{err}");
    assert!(!mock.calls().contains(&"priv rebuild".to_string()));

    let (mock, cx) = run('2', false);
    let err = apply(&mock, &cx, &steps).await.unwrap_err().to_string();
    assert!(
        err.contains(&format!("volume {ANON} changed since it was copied")),
        "{err}"
    );
    assert!(!mock.calls().contains(&"priv rebuild".to_string()));

    let (mock, cx) = run('1', false);
    cx.state.lock().unwrap().manifests.clear();
    let err = apply(&mock, &cx, &steps).await.unwrap_err().to_string();
    assert!(err.contains("no verified copy of it was recorded"), "{err}");

    let (mock, cx) = run('1', false);
    apply(&mock, &cx, &steps).await.unwrap();
    assert!(mock.calls().contains(&"priv rebuild".to_string()));
    assert!(
        mock.ops
            .lock()
            .unwrap()
            .contains(&PrivilegedOp::ManifestVolume {
                volume: ANON.into(),
                xattrs: true
            })
    );
}

#[tokio::test]
async fn a_failed_removal_reports_the_volumes_already_removed() {
    let f = pbs();
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    let (first, second) = ("a".repeat(64), "b".repeat(64));
    let fail: &'static str = Box::leak(format!("docker volume rm {second}").into_boxed_str());
    let mock = Mock::new(f.c.clone(), f.img.clone(), Some(fail))
        .with_output("docker volume ls", &format!("{first}\n{second}\n"))
        .with_output("priv manifest_volume", &digest_reply('1'));
    let cx = ctx(&plan, &f);
    {
        let mut st = cx.state.lock().unwrap();
        st.manifests.insert(first.clone(), "1".repeat(64));
        st.manifests.insert(second.clone(), "1".repeat(64));
    }
    let err = apply(
        &mock,
        &cx,
        &[Step::RemoveOwnAnonymousVolumes {
            candidates: vec![first.clone(), second.clone()],
        }],
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains(&format!("already removed [{first}]")), "{err}");
}

#[test]
fn a_non_admin_dry_run_leaves_nocopy_to_execute() {
    let mut f = pbs();
    let mut s = with_anonymous(&mut f);
    s.empty_unknown.insert(ANON.into());
    let plan = plan_adopt(&s, &opts(None, false));
    assert!(!plan.conversions[0].nocopy);
    let note = nocopy_note(&s, &plan.conversions).unwrap();
    assert!(
        note.contains(ANON) && note.contains("decided at execute"),
        "{note}"
    );
    assert_eq!(
        nocopy_note(&with_anonymous(&mut pbs()), &plan.conversions),
        None
    );
}

#[test]
fn an_empty_anonymous_volume_mounts_without_copy_up() {
    let mut f = pbs();
    let mut s = with_anonymous(&mut f);
    s.empty_volumes.insert(ANON.into());
    let plan = plan_adopt(&s, &opts(None, false));
    assert!(plan.conversions[0].nocopy);
    assert!(
        plan.template
            .extra_params
            .contains("dst=/var/cache/pbs,volume-nocopy,volume-label="),
        "{}",
        plan.template.extra_params
    );
    let (blocking, _) = gate(&plan, &simulate_render(&plan.template));
    assert!(blocking.is_empty(), "{blocking:?}");
}

#[test]
fn ownership_volume_labels_on_mounts_are_not_unmodelled() {
    let f = pbs();
    let mut raw = f.c_raw.clone();
    let mounts = raw["HostConfig"]["Mounts"].as_array_mut().unwrap();
    mounts.push(serde_json::json!({
        "Type": "volume", "Source": "pbs_x", "Target": "/x",
        "VolumeOptions": {"NoCopy": true, "Labels": {"orca.managed": "true", "orca.mount": "/x"}}
    }));
    assert!(inspect::unmodelled(&raw, &f.img_raw, false).is_empty());
    raw["HostConfig"]["Mounts"][1]["VolumeOptions"]["Labels"]["color"] = "red".into();
    let u = inspect::unmodelled(&raw, &f.img_raw, false);
    assert_eq!(u.len(), 1, "{u:?}");
    assert!(u[0].starts_with("mount option VolumeOptions="), "{u:?}");
}

#[test]
fn status_reports_label_coverage_per_container_and_volume() {
    let mut f = pbs();
    let s = with_anonymous(&mut f);
    let mut volumes = s.volumes.clone();
    volumes.get_mut("pbs-config").unwrap().labels =
        Some(ownership::volume_labels("pbs", "/etc/proxmox-backup"));
    let st = container_status(&f.c, None, &[], template::DEFAULT_ICON_BASE, &volumes);
    assert_eq!(
        st.missing_labels,
        vec!["orca.managed", "orca.owner", "orca.stack", "orca.service"]
    );
    let by_name: BTreeMap<&str, &VolumeLabelStatus> =
        st.volumes.iter().map(|v| (v.name.as_str(), v)).collect();
    assert!(by_name["pbs-config"].missing_labels.is_empty());
    assert!(!by_name["pbs-config"].anonymous);
    assert_eq!(by_name["pbs-logs"].missing_labels.len(), 5);
    assert!(by_name[ANON].anonymous);
    assert_eq!(by_name[ANON].target, "/var/cache/pbs");

    let mut labeled = f.c.clone();
    labeled.config.labels = Some(ownership::container_labels("pbs"));
    let st2 = container_status(&labeled, None, &[], template::DEFAULT_ICON_BASE, &volumes);
    assert!(st2.missing_labels.is_empty());
    let cov = label_coverage(&[st, st2], &volumes);
    assert_eq!(
        (
            cov.containers,
            cov.containers_labeled,
            cov.volumes,
            cov.volumes_labeled
        ),
        (2, 1, 3, 1)
    );
}
