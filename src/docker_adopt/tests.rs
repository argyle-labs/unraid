use std::sync::Mutex;

use plugin_toolkit::contract::BoxFuture;

use super::*;
use crate::docker_adopt::inspect::{ContainerInspect, ImageInspect, MountPoint, VolumeInspect};
use crate::docker_adopt::template::{ConfigKind, Template};

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
        date: "20261004".to_string(),
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

fn gate(plan: &AdoptPlan, rendered: &str) -> (Vec<String>, Vec<String>) {
    let (_, d) = fidelity(
        &plan.target,
        &plan.unsupported,
        &plan.baked_env,
        &daemon_opts(),
        rendered,
    );
    split_deltas(d, &Redactor::default())
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
    let (blocking, intended) = gate(&plan, f.rendered);
    assert!(blocking.is_empty(), "{blocking:?}");
    assert_eq!(
        intended,
        vec![
            "restart policy unless-stopped dropped; Unraid autostart starts it with the array",
            "pids-limit unlimited -> 2048 (dockerMan default)",
        ]
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
    let (blocking, intended) = gate(&plan, f.rendered);
    assert!(blocking.is_empty(), "{blocking:?}");
    assert_eq!(intended.len(), 3, "{intended:?}");
    assert!(intended[0].starts_with("hostname bc405da8c18f (docker's default)"));
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
    let dropped = f
        .rendered
        .replace("--tmpfs /run/proxmox-backup:rw,nosuid,nodev,mode=0755 ", "");
    let (blocking, _) = gate(&plan, &dropped);
    assert_eq!(blocking.len(), 1, "{blocking:?}");
    assert!(blocking[0].starts_with("tmpfs /run/proxmox-backup"));
}

#[test]
fn real_whisper_without_gpus_blocks() {
    let f = whisper();
    let plan = plan_adopt(&snapshot(&f), &opts(None, false));
    let (blocking, _) = gate(&plan, &f.rendered.replace("--gpus all ", ""));
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
    );
    let (blocking, _) = split_deltas(d, &Redactor::default());
    assert!(blocking.is_empty(), "{blocking:?}");
    let steps = set_icon_steps(&s, "<x/>", "u", got.unwrap());
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
    let (blocking, _) = gate(&plan, f.rendered);
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
    let (blocking, _) = gate(&plan, f.rendered);
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
            "compose project dockge labels dropped"
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
            "rebuild",
            "ensure-state",
            "verify-managed",
            "clear-icon-cache",
            "refresh-icons",
            "remove-volume",
            "remove-volume",
            "remove-old-image",
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
    fail_on: Option<&'static str>,
    container: ContainerInspect,
    image: ImageInspect,
}

impl Mock {
    fn new(
        container: ContainerInspect,
        image: ImageInspect,
        fail_on: Option<&'static str>,
    ) -> Self {
        Mock {
            calls: Mutex::new(Vec::new()),
            fail_on,
            container,
            image,
        }
    }
    fn record(&self, call: String) -> Result<String> {
        self.calls.lock().unwrap().push(call.clone());
        match self.fail_on {
            Some(f) if call == f => bail!("boom {}", "hunter2-secret"),
            _ => Ok(String::new()),
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
        Box::pin(async move { self.record(format!("docker {}", args.join(" "))) })
    }
    fn inspect_container<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Result<ContainerInspect>> {
        Box::pin(async move { Ok(self.container.clone()) })
    }
    fn inspect_image<'a>(&'a self, _id: &'a str) -> BoxFuture<'a, Result<ImageInspect>> {
        Box::pin(async move { Ok(self.image.clone()) })
    }
    fn inspect_all(&self) -> BoxFuture<'_, Result<Vec<ContainerInspect>>> {
        Box::pin(async move { Ok(vec![self.container.clone()]) })
    }
    fn privileged<'a>(&'a self, op: &'a PrivilegedOp) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move { self.record(format!("priv {}", op_name(op))) })
    }
}

fn ctx(plan: &AdoptPlan, f: &Fx) -> ApplyCtx {
    ApplyCtx {
        tool: "unraid.docker.adopt",
        name: f.c.short_name().to_string(),
        date: "20261004".into(),
        was_running: plan.was_running,
        autostart_before: false,
        had_template: false,
        original: plan.live.clone(),
        redactor: redactor_for(&f.c, &[&plan.target]),
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
    let steps = set_icon_steps(&s, "<x/>", &url, live.clone());
    let mock = Mock::new(f.c.clone(), f.img.clone(), None);
    let cx = ApplyCtx {
        tool: "unraid.docker.set_icon",
        name: "dockge".into(),
        date: "20261004".into(),
        was_running: true,
        autostart_before: false,
        had_template: true,
        original: live,
        redactor: Redactor::default(),
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
