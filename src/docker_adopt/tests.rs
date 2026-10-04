use super::*;
use crate::docker_adopt::inspect::{ContainerInspect, ImageInspect};
use crate::docker_adopt::template::{ConfigKind, Template};

fn container(json: &str) -> ContainerInspect {
    serde_json::from_str(json).unwrap()
}

fn image(json: &str) -> ImageInspect {
    serde_json::from_str(json).unwrap()
}

fn pbs() -> (ContainerInspect, ImageInspect) {
    (
        container(include_str!("fixtures/pbs.container.json")),
        image(include_str!("fixtures/pbs.image.json")),
    )
}

fn whisper() -> (ContainerInspect, ImageInspect) {
    (
        container(include_str!("fixtures/whisper.container.json")),
        image(include_str!("fixtures/whisper.image.json")),
    )
}

fn dockge() -> (ContainerInspect, ImageInspect) {
    (
        container(include_str!("fixtures/dockge.container.json")),
        image(include_str!("fixtures/dockge.image.json")),
    )
}

fn snapshot(c: ContainerInspect, img: ImageInspect) -> Snapshot {
    let mut all = vec![c.clone()];
    for (o, _) in [pbs(), whisper(), dockge()] {
        if o.short_name() != c.short_name() {
            all.push(o);
        }
    }
    Snapshot {
        container: c,
        image: img,
        all,
        date: "20261004".to_string(),
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

/// Escape like PHP's `escapeshellarg`, which dockerMan uses for every value.
fn esc(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// What dockerMan's `xmlToCommand` emits for a template: its own env, labels
/// and pids limit first, then Configs, ExtraParams, image and PostArgs.
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
    p.push(r#"-e TZ="America/Los_Angeles""#.to_string());
    p.push(r#"-e HOST_OS="Unraid""#.to_string());
    p.push(r#"-e HOST_HOSTNAME="willow""#.to_string());
    p.push(format!(r#"-e HOST_CONTAINERNAME="{}""#, t.name));
    p.push("-l net.unraid.docker.managed=dockerman".to_string());
    p.push("-l net.unraid.docker.webui=".to_string());
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
            ConfigKind::Variable => p.push(format!("-e {}={}", esc(&c.target), esc(&c.value))),
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

fn round_trip_diff(plan: &AdoptPlan) -> Vec<String> {
    fidelity(plan, &simulate_render(&plan.template))
}

// ── pbs-like: named volumes, bind, rslave mount, tmpfs, hostname, log-opts ──

#[test]
fn pbs_live_spec_captures_every_facet() {
    let (c, img) = pbs();
    let (s, unsupported) = live_spec(&c, &img);
    assert!(unsupported.is_empty(), "{unsupported:?}");
    assert_eq!(s.name, "pbs");
    assert_eq!(s.image, "ayufan/proxmox-backup-server:latest");
    assert_eq!(s.hostname.as_deref(), Some("pbs"));
    assert_eq!(s.ports.iter().collect::<Vec<_>>(), vec!["8007:8007/tcp"]);
    assert_eq!(
        s.env.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["PGID", "PUID"]
    );
    assert_eq!(
        s.tmpfs.get("/run/proxmox-backup").map(String::as_str),
        Some("rw,nosuid,nodev,size=64m")
    );
    assert_eq!(s.log_opts.get("max-size").map(String::as_str), Some("50m"));
    assert_eq!(s.log_opts.get("max-file").map(String::as_str), Some("3"));
    assert_eq!(s.restart.as_deref(), Some("unless-stopped"));
    assert!(s.labels.is_empty(), "{:?}", s.labels);
    assert!(s.cmd.is_empty());
    let rslave: Vec<_> = s
        .mounts
        .iter()
        .filter(|m| m.propagation.is_some())
        .collect();
    assert_eq!(rslave.len(), 1);
    assert_eq!(rslave[0].source, "/mnt/pbs-remote");
    assert_eq!(
        s.mounts
            .iter()
            .filter(|m| m.kind == MountKind::Volume)
            .map(|m| m.source.as_str())
            .collect::<Vec<_>>(),
        vec!["pbs-config", "pbs-logs"]
    );
}

#[test]
fn pbs_template_routes_rslave_to_extra_params() {
    let (c, img) = pbs();
    let plan = plan_adopt(&snapshot(c, img), &opts(Some("pbs"), false));
    let t = &plan.template;
    assert!(
        t.extra_params.contains(
            "--mount type=bind,src=/mnt/pbs-remote,dst=/mnt/pbs-remote,bind-propagation=rslave"
        ),
        "{}",
        t.extra_params
    );
    assert!(
        !t.configs
            .iter()
            .any(|c| c.kind == ConfigKind::Path && c.target == "/mnt/pbs-remote")
    );
    for want in [
        "--hostname pbs",
        "--tmpfs /run/proxmox-backup:rw,nosuid,nodev,size=64m",
        "--log-opt max-file=3",
        "--log-opt max-size=50m",
        "--restart unless-stopped",
    ] {
        assert!(
            t.extra_params.contains(want),
            "{want} in {}",
            t.extra_params
        );
    }
    let xml = &plan.template_xml;
    assert!(xml.contains(template::MANAGED_MARKER));
    assert!(xml.contains(
        "<Icon>https://gitea.scottkey.me/argyle-labs/pbs/raw/branch/main/assets/icon-256.png</Icon>"
    ));
    assert!(xml.contains(
        r#"<Config Name="Path /etc/proxmox-backup" Target="/etc/proxmox-backup" Default="pbs-config" Mode="rw""#
    ));
    assert!(xml.contains(r#"Target="8007" Default="8007" Mode="tcp""#));
    assert!(
        xml.contains(
            r#"Type="Variable" Display="always" Required="false" Mask="false">99</Config>"#
        )
    );
    assert!(
        round_trip_diff(&plan).is_empty(),
        "{:?}",
        round_trip_diff(&plan)
    );
}

#[test]
fn pbs_matches_a_dockerman_rendered_command() {
    let (c, img) = pbs();
    let plan = plan_adopt(&snapshot(c, img), &opts(Some("pbs"), false));
    let rendered = "/usr/local/emhttp/plugins/dynamix.docker.manager/scripts/docker create \
        --name='pbs' --net='bridge' --pids-limit 2048 -e TZ=\"America/Los_Angeles\" \
        -e HOST_OS=\"Unraid\" -e HOST_HOSTNAME=\"willow\" -e HOST_CONTAINERNAME=\"pbs\" \
        -e 'PGID'='100' -e 'PUID'='99' -l net.unraid.docker.managed=dockerman \
        -l net.unraid.docker.webui='' \
        -l net.unraid.docker.icon='https://gitea.scottkey.me/argyle-labs/pbs/raw/branch/main/assets/icon-256.png' \
        -p '8007:8007/tcp' -v 'pbs-config':'/etc/proxmox-backup':'rw' \
        -v 'pbs-logs':'/var/log/proxmox-backup':'rw' -v '/mnt/user/pbs':'/mnt/willow-pbs':'rw' \
        --mount type=bind,src=/mnt/pbs-remote,dst=/mnt/pbs-remote,bind-propagation=rslave \
        --hostname pbs --tmpfs /run/proxmox-backup:rw,nosuid,nodev,size=64m \
        --log-opt max-file=3 --log-opt max-size=50m --restart unless-stopped \
        'ayufan/proxmox-backup-server:latest'";
    assert_eq!(fidelity(&plan, rendered), Vec::<String>::new());

    let dropped = rendered.replace("--tmpfs /run/proxmox-backup:rw,nosuid,nodev,size=64m ", "");
    let d = fidelity(&plan, &dropped);
    assert_eq!(d.len(), 1, "{d:?}");
    assert!(d[0].starts_with("tmpfs /run/proxmox-backup"), "{d:?}");
}

#[test]
fn pbs_migrate_volumes_rewrites_paths_and_orders_steps() {
    let (c, img) = pbs();
    let plan = plan_adopt(&snapshot(c, img), &opts(Some("pbs"), true));
    assert_eq!(
        plan.migrations,
        vec![
            Migration {
                volume: "pbs-config".into(),
                from: "/var/lib/docker/volumes/pbs-config/_data".into(),
                to: "/mnt/user/appdata/pbs/config".into(),
            },
            Migration {
                volume: "pbs-logs".into(),
                from: "/var/lib/docker/volumes/pbs-logs/_data".into(),
                to: "/mnt/user/appdata/pbs/logs".into(),
            },
        ]
    );
    assert!(
        plan.template_xml
            .contains(r#"Default="/mnt/user/appdata/pbs/config" Mode="rw""#)
    );
    assert!(!plan.template_xml.contains("pbs-config"));
    assert!(
        round_trip_diff(&plan).is_empty(),
        "{:?}",
        round_trip_diff(&plan)
    );

    let actions: Vec<&str> = plan.steps.iter().map(Step::action).collect();
    assert_eq!(
        actions,
        vec![
            "stop",
            "copy-volume",
            "verify-copy",
            "copy-volume",
            "verify-copy",
            "write-template",
            "autostart-add",
            "rebuild",
            "ensure-state",
            "verify-managed",
            "clear-icon-cache",
            "refresh-icons",
            "remove-volume",
            "remove-volume",
            "prune-anonymous-volumes",
            "prune-dangling-images",
        ]
    );
}

#[test]
fn hostname_kept_unless_it_is_the_containers_own_id() {
    let (mut c, img) = pbs();
    c.config.hostname = "0123456789ab".into();
    assert_eq!(
        live_spec(&c, &img).0.hostname.as_deref(),
        Some("0123456789ab")
    );
    c.config.hostname = c.id[..12].to_string();
    assert_eq!(live_spec(&c, &img).0.hostname, None);
}

#[test]
fn existing_template_is_backed_up_before_rewrite() {
    let (c, img) = pbs();
    let mut s = snapshot(c, img);
    s.existing_template = Some("<Container><Icon>old</Icon></Container>".into());
    s.autostart = vec!["pbs".into()];
    let plan = plan_adopt(&s, &opts(None, false));
    assert_eq!(
        plan.steps[0],
        Step::BackupTemplate {
            from: "/boot/config/plugins/dockerMan/templates-user/my-pbs.xml".into(),
            to: "/boot/config/plugins/dockerMan/templates-user/my-pbs.xml.bak-20261004".into(),
        }
    );
    assert!(!plan.steps.contains(&Step::AutostartAdd));
    assert_eq!(plan.template.icon, "old");
}

// ── whisper-like: GPU, two named volumes, ro bind, remapped port, baked env ──

#[test]
fn whisper_drops_baked_env_and_keeps_gpu() {
    let (c, img) = whisper();
    let (s, unsupported) = live_spec(&c, &img);
    assert!(unsupported.is_empty(), "{unsupported:?}");
    assert_eq!(s.gpus.as_deref(), Some("all"));
    assert_eq!(s.hostname, None);
    assert_eq!(s.ports.iter().collect::<Vec<_>>(), vec!["10300:9000/tcp"]);
    assert_eq!(
        s.env.keys().map(String::as_str).collect::<Vec<_>>(),
        vec![
            "ASR_DEVICE",
            "ASR_ENGINE",
            "ASR_MODEL",
            "HF_HOME",
            "MODEL_IDLE_TIMEOUT"
        ]
    );
    assert!(s.cmd.is_empty());
    assert!(s.labels.is_empty());
    let zone = s
        .mounts
        .iter()
        .find(|m| m.target == "/usr/share/zoneinfo")
        .unwrap();
    assert!(zone.read_only && zone.kind == MountKind::Bind && zone.propagation.is_none());

    let plan = plan_adopt(&snapshot(c, img), &opts(Some("whisper"), false));
    assert!(plan.template.extra_params.contains("--gpus all"));
    assert!(
        plan.template_xml
            .contains(r#"Target="9000" Default="10300" Mode="tcp""#)
    );
    assert!(
        plan.template_xml
            .contains(r#"Default="/usr/share/zoneinfo" Mode="ro""#)
    );
    assert!(!plan.template_xml.contains("NVIDIA_VISIBLE_DEVICES"));
    assert!(
        round_trip_diff(&plan).is_empty(),
        "{:?}",
        round_trip_diff(&plan)
    );
}

#[test]
fn whisper_rendered_without_gpus_is_refused() {
    let (c, img) = whisper();
    let mut plan = plan_adopt(&snapshot(c, img), &opts(None, false));
    plan.template.extra_params = plan.template.extra_params.replace("--gpus all", "");
    let d = round_trip_diff(&plan);
    assert_eq!(d, vec![r#"gpus: live Some("all"), rendered None"#]);
}

// ── compose-created (dockge-like) ───────────────────────────────────────────

#[test]
fn compose_container_moves_to_bridge_and_retires_its_stack() {
    let (c, img) = dockge();
    let (live, unsupported) = live_spec(&c, &img);
    assert!(unsupported.is_empty(), "{unsupported:?}");
    assert!(live.labels.is_empty(), "{:?}", live.labels);
    assert_eq!(live.network, "dockge_default");

    let plan = plan_adopt(&snapshot(c, img), &opts(Some("dockge"), false));
    assert_eq!(plan.target.network, "bridge");
    assert_eq!(plan.intended, vec!["network dockge_default -> bridge"]);
    let l = plan.compose.as_ref().unwrap();
    assert_eq!(l.network.as_deref(), Some("dockge_default"));
    assert_eq!(
        l.retire,
        Some((
            "/opt/stacks/dockge".into(),
            "/opt/stacks-retired/dockge-compose-20261004".into()
        ))
    );
    assert!(plan.steps.contains(&Step::RemoveNetwork {
        network: "dockge_default".into()
    }));
    assert!(plan.steps.contains(&Step::RetireStack {
        from: "/opt/stacks/dockge".into(),
        to: "/opt/stacks-retired/dockge-compose-20261004".into(),
    }));
    assert!(plan.template_xml.contains("<Network>bridge</Network>"));
    assert!(
        round_trip_diff(&plan).is_empty(),
        "{:?}",
        round_trip_diff(&plan)
    );
}

#[test]
fn compose_stack_kept_while_bind_mounted_or_shared() {
    let (mut c, img) = dockge();
    c.mounts.push(inspect::MountPoint {
        kind: "bind".into(),
        source: "/opt/stacks/dockge/data".into(),
        destination: "/app/data2".into(),
        rw: true,
        ..Default::default()
    });
    let plan = plan_adopt(&snapshot(c, img.clone()), &opts(None, false));
    let l = plan.compose.unwrap();
    assert!(l.retire.is_none());
    assert!(l.keep_reason.unwrap().contains("still bind-mounted"));

    let (c, _) = dockge();
    let mut sibling = c.clone();
    sibling.name = "/dockge-db".into();
    let mut s = snapshot(c, img);
    s.all.push(sibling);
    let l = plan_adopt(&s, &opts(None, false)).compose.unwrap();
    assert!(l.retire.is_none());
    assert!(l.keep_reason.unwrap().contains("dockge-db"));
}

#[test]
fn compose_migrate_strips_project_prefix() {
    let (c, img) = dockge();
    let plan = plan_adopt(&snapshot(c, img), &opts(None, true));
    assert_eq!(plan.migrations[0].to, "/mnt/user/appdata/dockge/data");
    assert!(
        round_trip_diff(&plan).is_empty(),
        "{:?}",
        round_trip_diff(&plan)
    );
}

// ── shared ──────────────────────────────────────────────────────────────────

#[test]
fn unsupported_facets_block_adopt() {
    let (mut c, img) = pbs();
    c.host_config.cap_add = Some(vec!["NET_ADMIN".into()]);
    c.config.entrypoint = Some(vec!["/bin/sh".into()]);
    let plan = plan_adopt(&snapshot(c, img), &opts(None, false));
    let d = round_trip_diff(&plan);
    assert!(d.iter().any(|x| x.contains("cap-add")), "{d:?}");
    assert!(d.iter().any(|x| x.contains("entrypoint")), "{d:?}");
}

#[test]
fn values_are_xml_and_shell_escaped() {
    let (mut c, img) = pbs();
    c.config
        .env
        .as_mut()
        .unwrap()
        .push(r#"WEIRD=a&b<c>"d" 'e'"#.into());
    c.config.labels.as_mut().unwrap().insert(
        "traefik.http.routers.x.rule".into(),
        "Host(`x.lan`) && Path(`/a b`)".into(),
    );
    let plan = plan_adopt(&snapshot(c, img), &opts(None, false));
    assert!(
        plan.template_xml
            .contains("&gt;&quot;d&quot; &apos;e&apos;</Config>")
    );
    assert!(plan.template_xml.contains("a&amp;b&lt;c"));
    assert!(
        round_trip_diff(&plan).is_empty(),
        "{:?}",
        round_trip_diff(&plan)
    );
}

#[test]
fn anonymous_dangling_volumes_only_when_unused() {
    let (mut c, _) = pbs();
    let used = "b".repeat(64);
    c.mounts.push(inspect::MountPoint {
        kind: "volume".into(),
        name: Some(used.clone()),
        destination: "/x".into(),
        ..Default::default()
    });
    let free = "a".repeat(64);
    let got = orphans::removable_volumes(&[free.clone(), used, "named-vol".into()], &[c]);
    assert_eq!(got, vec![free]);
}

#[test]
fn status_reports_template_icon_and_volumes() {
    let (c, _) = pbs();
    let xml = Template {
        icon: template::icon_url(template::DEFAULT_ICON_BASE, "pbs"),
        ..Template::default()
    }
    .render();
    let s = container_status(
        &c,
        Some(&xml),
        &["pbs".to_string()],
        template::DEFAULT_ICON_BASE,
    );
    assert!(s.has_template && s.orca_icon && s.autostart);
    assert_eq!(s.managed, None);
    assert_eq!(s.volumes_outside_appdata, vec!["pbs-config", "pbs-logs"]);
    let s = container_status(&c, None, &[], template::DEFAULT_ICON_BASE);
    assert!(!s.has_template && !s.orca_icon && !s.autostart && s.icon.is_none());
}

#[test]
fn set_icon_preserves_stopped_state() {
    let steps = set_icon_steps("pbs", "/t/my-pbs.xml", "<x/>", "u", false, "20261004");
    assert_eq!(steps[3], Step::EnsureState { running: false });
    assert_eq!(steps[0].action(), "backup-template");
    assert_eq!(steps[2], Step::Rebuild);
}

#[test]
fn names_are_validated() {
    assert!(validate_name("container name", "pbs").is_ok());
    assert!(validate_name("container name", "a_b.c-1").is_ok());
    for bad in ["", "-x", ".x", "a b", "a;b", "a/b", "$(x)"] {
        assert!(validate_name("container name", bad).is_err(), "{bad}");
    }
    assert!(validate_icon_base("https://gitea.scottkey.me/argyle-labs").is_ok());
    assert!(validate_icon_base("https://x/'y").is_err());
    assert!(validate_icon_base("file:///etc").is_err());
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
