use super::*;
use crate::test_support::rt;
use wiremock::matchers::{body_string_contains, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SERVER: &str = "abc123";
const PLEX: &str = "abc123:1111111111111111111111111111111111111111111111111111111111111111";
const ORCA: &str = "abc123:2222222222222222222222222222222222222222222222222222222222222222";
const SAB: &str = "abc123:3333333333333333333333333333333333333333333333333333333333333333";
const ZOT: &str = "abc123:4444444444444444444444444444444444444444444444444444444444444444";
const PLEX2: &str = "abc123:5555555555555555555555555555555555555555555555555555555555555555";

fn fixture() -> Value {
    json!({ "data": { "docker": { "id": SERVER, "containers": [
        { "id": SAB, "names": ["/sabnzbd"], "image": "lscr.io/linuxserver/sabnzbd:latest", "imageId": "sha256:aa",
          "state": "EXITED", "status": "Exited (0)", "autoStart": true,
          "autoStartOrder": 1, "autoStartWait": 0, "iconUrl": null, "webUiUrl": null,
          "isUpdateAvailable": false },
        { "id": PLEX, "names": ["/plex"], "image": "plexinc/pms-docker:latest", "imageId": "sha256:bb",
          "state": "RUNNING", "status": "Up 2 days", "autoStart": true,
          "autoStartOrder": 0, "autoStartWait": 10, "iconUrl": null, "webUiUrl": null,
          "isUpdateAvailable": false },
        { "id": ORCA, "names": ["/orca"], "image": "gitea.example/argyle-labs/orca:rc", "imageId": "sha256:cc",
          "state": "RUNNING", "status": "Up", "autoStart": true,
          "autoStartOrder": null, "autoStartWait": null, "iconUrl": null, "webUiUrl": null,
          "isUpdateAvailable": false },
        { "id": ZOT, "names": ["/registry"], "image": "ghcr.io/project-zot/zot:v2", "imageId": "sha256:dd",
          "state": "RUNNING", "status": "Up", "autoStart": false,
          "autoStartOrder": null, "autoStartWait": null, "iconUrl": null, "webUiUrl": null,
          "isUpdateAvailable": false },
        { "id": PLEX2, "names": ["/plex-dev"], "image": "plexinc/pms-docker:beta", "imageId": "sha256:bb",
          "state": "EXITED", "status": "Exited", "autoStart": false,
          "autoStartOrder": null, "autoStartWait": null, "iconUrl": null, "webUiUrl": null,
          "isUpdateAvailable": false }
    ] } } })
}

fn containers_fixture() -> Vec<Container> {
    serde_json::from_value(fixture()["data"]["docker"]["containers"].clone()).unwrap()
}

async fn server(mutation_field: &str, mutation_result: Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("DockerContainers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains(mutation_field))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({ "data": { "docker": { mutation_field: mutation_result } } }),
            ),
        )
        .mount(&server)
        .await;
    server
}

async fn autostart_server(original_reads: u64, after: impl FnOnce(&mut Value)) -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("DockerContainers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture()))
        .up_to_n_times(original_reads)
        .mount(&s)
        .await;
    let mut later = fixture();
    after(&mut later);
    Mock::given(method("POST"))
        .and(body_string_contains("DockerContainers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(later))
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("updateAutostartConfiguration"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": {"docker": {"updateAutostartConfiguration": true}}})),
        )
        .mount(&s)
        .await;
    s
}

fn prot() -> Vec<String> {
    protected_set(Some("sabnzbd-extra"))
}

fn client(server: &MockServer) -> Client {
    Client::new(crate::Config::new(server.uri(), "k"))
}

fn uid(id: &str) -> UnitId {
    UnitId {
        manager: manager_for("willow"),
        kind: KIND.into(),
        id: id.into(),
        name: String::new(),
    }
}

fn update(id: &str, action: &str, payload: Option<&str>) -> UpdateArgs {
    UpdateArgs {
        id: uid(id),
        action: action.into(),
        payload: payload.map(str::to_string),
        caller: None,
    }
}

async fn mutation_bodies(server: &MockServer) -> Vec<Value> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| serde_json::from_slice::<Value>(&r.body).unwrap())
        .filter(|b| b["query"].as_str().unwrap_or("").starts_with("mutation"))
        .collect()
}

fn schema_args(type_name: &str, field: &str) -> Option<Vec<String>> {
    let (_, schema) = crate::generated::SCHEMAS[0];
    let v: Value = serde_json::from_str(schema).unwrap();
    let types = v
        .pointer("/data/__schema/types")
        .or_else(|| v.pointer("/__schema/types"))?;
    let f = types.as_array()?.iter().find(|t| t["name"] == type_name)?["fields"]
        .as_array()?
        .iter()
        .find(|f| f["name"] == field)?
        .clone();
    Some(
        f["args"]
            .as_array()?
            .iter()
            .map(|a| a["name"].as_str().unwrap().to_string())
            .collect(),
    )
}

#[test]
fn every_mutation_exists_in_the_schema() {
    for (_, field) in SIMPLE_ACTIONS {
        assert_eq!(
            schema_args("DockerMutations", field).as_deref(),
            Some(&["id".to_string()][..]),
            "{field}"
        );
    }
    assert_eq!(
        schema_args("DockerMutations", "removeContainer").unwrap(),
        vec!["id", "withImage"]
    );
    assert!(
        schema_args("DockerMutations", "updateAutostartConfiguration")
            .unwrap()
            .contains(&"entries".to_string())
    );
}

#[test]
fn resolves_by_exact_id_bare_id_or_name_only() {
    let all = containers_fixture();
    assert_eq!(resolve(&all, PLEX).unwrap().id, PLEX);
    assert_eq!(resolve(&all, bare_id(PLEX)).unwrap().id, PLEX);
    assert_eq!(resolve(&all, "plex").unwrap().id, PLEX);
    assert!(resolve(&all, "ple").is_err());
    assert!(resolve(&all, "111111111111").is_err());
    assert!(resolve(&all, "").is_err());
}

#[test]
fn orca_is_recognized_by_name_or_image() {
    let all = containers_fixture();
    let orca = resolve(&all, ORCA).unwrap();
    let plex = resolve(&all, PLEX).unwrap();
    assert!(is_orca(orca, None));
    assert!(!is_orca(plex, None));
}

#[test]
fn manager_names_the_endpoint() {
    assert_eq!(endpoint_of(&uid(PLEX)).unwrap(), "willow");
    let mut bad = uid(PLEX);
    bad.manager = "docker@willow".into();
    assert!(endpoint_of(&bad).is_err());
}

#[test]
fn autostart_entries_keep_every_other_container() {
    let all = containers_fixture();
    let e = autostart_entries(&all, SAB, false, None).unwrap();
    assert_eq!(e[0], json!({"id": PLEX, "autoStart": true, "wait": 10}));
    assert_eq!(e[1], json!({"id": SAB, "autoStart": false, "wait": 0}));
    assert_eq!(e[2], json!({"id": ORCA, "autoStart": true}));
    assert_eq!(e.len(), 5);
}

#[test]
fn stop_executes_by_default() {
    let rt = rt();
    let (out, bodies) = rt.block_on(async {
        let s = server("stop", json!({"id": PLEX, "state": "EXITED"})).await;
        let out = update_with(&client(&s), "willow", &prot(), update("plex", "stop", None)).await;
        (out, mutation_bodies(&s).await)
    });
    let VerbOutcome::Action(a) = out.unwrap() else {
        panic!("expected action outcome")
    };
    assert!(a.changed);
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0]["variables"]["id"], PLEX);
    assert!(
        bodies[0]["query"]
            .as_str()
            .unwrap()
            .contains("stop(id: $id)")
    );
}

#[test]
fn dry_run_sends_no_mutation() {
    let rt = rt();
    let (out, bodies) = rt.block_on(async {
        let s = server("removeContainer", json!(true)).await;
        let out = update_with(
            &client(&s),
            "willow",
            &prot(),
            update("plex", "remove", Some(r#"{"dryRun":true}"#)),
        )
        .await;
        (out, mutation_bodies(&s).await)
    });
    let VerbOutcome::Item(i) = out.unwrap() else {
        panic!("expected plan")
    };
    assert!(i.payload.contains("removeContainer"));
    assert!(bodies.is_empty());
}

#[test]
fn remove_passes_with_image() {
    let rt = rt();
    let bodies = rt.block_on(async {
        let s = server("removeContainer", json!(true)).await;
        update_with(
            &client(&s),
            "willow",
            &prot(),
            update(SAB, "remove", Some(r#"{"withImage":true}"#)),
        )
        .await
        .unwrap();
        mutation_bodies(&s).await
    });
    assert_eq!(
        bodies[0]["variables"],
        json!({"id": SAB, "withImage": true})
    );
}

#[test]
fn restart_is_stop_then_start() {
    let rt = rt();
    let bodies = rt.block_on(async {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("DockerContainers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(fixture()))
            .mount(&s)
            .await;
        for f in ["stop", "start"] {
            Mock::given(method("POST"))
                .and(body_string_contains(format!("{f}(id")))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    json!({"data": {"docker": {f: {"id": PLEX, "state": "RUNNING"}}}}),
                ))
                .mount(&s)
                .await;
        }
        update_with(
            &client(&s),
            "willow",
            &prot(),
            update("plex", "restart", None),
        )
        .await
        .unwrap();
        mutation_bodies(&s).await
    });
    let q: Vec<&str> = bodies
        .iter()
        .map(|b| b["query"].as_str().unwrap())
        .collect();
    assert!(q[0].contains("stop(id") && q[1].contains("start(id"));
}

#[test]
fn autostart_sends_the_full_list() {
    let rt = rt();
    let bodies = rt.block_on(async {
        let s = autostart_server(2, |f| {
            f["data"]["docker"]["containers"][0]["autoStart"] = json!(false);
        })
        .await;
        update_with(
            &client(&s),
            "willow",
            &prot(),
            update("sabnzbd", "autostart", Some(r#"{"enabled":false}"#)),
        )
        .await
        .unwrap();
        mutation_bodies(&s).await
    });
    let entries = bodies[0]["variables"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 5);
    assert!(
        entries
            .iter()
            .any(|e| e["id"] == PLEX && e["autoStart"] == true)
    );
    assert!(
        entries
            .iter()
            .any(|e| e["id"] == SAB && e["autoStart"] == false)
    );
}

#[test]
fn a_false_result_is_an_error() {
    let rt = rt();
    let e = rt.block_on(async {
        let s = server("removeContainer", json!(false)).await;
        update_with(
            &client(&s),
            "willow",
            &prot(),
            update("sabnzbd", "remove", None),
        )
        .await
        .unwrap_err()
    });
    assert!(e.to_string().contains("did not succeed"), "{e}");
}

#[test]
fn refuses_orca_and_unknown_targets_without_mutating() {
    let rt = rt();
    for (target, want) in [("orca", "orca's own"), ("nope", "no container")] {
        let (e, bodies) = rt.block_on(async {
            let s = server("stop", json!({"id": ORCA, "state": "EXITED"})).await;
            let e = update_with(&client(&s), "willow", &prot(), update(target, "stop", None))
                .await
                .unwrap_err();
            (e, mutation_bodies(&s).await)
        });
        assert!(e.to_string().contains(want), "{e}");
        assert!(bodies.is_empty());
    }
}

#[test]
fn delete_only_plans() {
    let rt = rt();
    let (out, bodies) = rt.block_on(async {
        let s = server("removeContainer", json!(true)).await;
        let out = delete_with(
            &client(&s),
            "willow",
            &prot(),
            DeleteArgs {
                id: uid("plex"),
                caller: None,
            },
        )
        .await;
        (out, mutation_bodies(&s).await)
    });
    let VerbOutcome::Item(i) = out.unwrap() else {
        panic!("expected plan")
    };
    assert!(i.payload.contains("action=remove"));
    assert!(bodies.is_empty());
}

#[test]
fn mutations_require_admin_dry_run_included() {
    let p = UnraidUnitProvider;
    for role in [Some("user"), None] {
        let caller = crate::authz::test_ctx(role).caller();
        let mut u = update(PLEX, "stop", Some(r#"{"dryRun":true}"#));
        u.caller = caller.clone();
        let e = plugin_toolkit::reactor::block_on(p.invoke(VerbArgs::Update(u))).unwrap_err();
        assert!(e.to_string().contains("unraid container update"), "{e}");
        let d = DeleteArgs {
            id: uid(PLEX),
            caller,
        };
        let e = plugin_toolkit::reactor::block_on(p.invoke(VerbArgs::Delete(d))).unwrap_err();
        assert!(e.to_string().contains("unraid container delete"), "{e}");
    }
}

#[test]
fn declares_every_update_action() {
    let d = UnraidUnitProvider.declarations();
    let update = d[0].verbs.iter().find(|v| v.verb == Verb::Update).unwrap();
    let names: Vec<&str> = update.actions.iter().map(|a| a.action.as_str()).collect();
    assert_eq!(
        names,
        [
            "start",
            "stop",
            "pause",
            "unpause",
            "restart",
            "autostart",
            "remove"
        ]
    );
    assert!(d[0].verbs.iter().any(|v| v.verb == Verb::Delete));
}

const H: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn own_container_id_comes_from_the_kernel() {
    let mountinfo = format!(
        "1 0 0:1 / / rw - overlay overlay rw\n2 1 8:1 /var/lib/docker/containers/{H}/hostname /etc/hostname rw - ext4 /dev/sda1 rw\n"
    );
    assert_eq!(container_id_from_mountinfo(&mountinfo).as_deref(), Some(H));
    let v1 = format!("12:memory:/docker/{H}\n11:cpu:/docker/{H}\n");
    assert_eq!(container_id_from_cgroup(&v1).as_deref(), Some(H));
    let v2 = format!("0::/system.slice/docker-{H}.scope\n");
    assert_eq!(container_id_from_cgroup(&v2).as_deref(), Some(H));
    assert_eq!(container_id_from_cgroup("0::/\n"), None);
    assert_eq!(
        container_id_from_cgroup("0::/user.slice/user-1000.slice/session-2.scope\n"),
        None
    );
    assert_eq!(
        own_container_id_from(
            Some("1 0 0:1 / / rw - ext4 /dev/sda1 rw\n"),
            Some("0::/init.scope\n")
        ),
        None
    );
    assert_eq!(
        own_container_id_from(Some(&mountinfo), Some("0::/\n")).as_deref(),
        Some(H)
    );
}

#[test]
fn own_id_must_match_the_full_bare_id() {
    let all = containers_fixture();
    let plex = resolve(&all, PLEX).unwrap();
    assert!(is_orca(plex, Some(bare_id(PLEX))));
    assert!(!is_orca(plex, Some("111111111111")));
    assert!(!is_orca(plex, Some(H)));
}

#[test]
fn with_image_is_refused_while_another_container_uses_it() {
    let rt = rt();
    let (plan_out, err, bodies) = rt.block_on(async {
        let s = server("removeContainer", json!(true)).await;
        let plan_out = update_with(
            &client(&s),
            "willow",
            &prot(),
            update(
                "plex",
                "remove",
                Some(r#"{"withImage":true,"dryRun":true}"#),
            ),
        )
        .await
        .unwrap();
        let err = update_with(
            &client(&s),
            "willow",
            &prot(),
            update("plex", "remove", Some(r#"{"withImage":true,"force":true}"#)),
        )
        .await
        .unwrap_err();
        (plan_out, err, mutation_bodies(&s).await)
    });
    let VerbOutcome::Item(i) = plan_out else {
        panic!("expected plan")
    };
    assert!(i.payload.contains("plex-dev"), "{}", i.payload);
    assert!(err.to_string().contains("plex-dev"), "{err}");
    assert!(bodies.is_empty());
}

#[test]
fn autostart_aborts_when_the_config_changes_before_writing() {
    let rt = rt();
    let (e, bodies) = rt.block_on(async {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("DockerContainers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(fixture()))
            .up_to_n_times(1)
            .mount(&s)
            .await;
        let mut changed = fixture();
        changed["data"]["docker"]["containers"][1]["autoStart"] = json!(false);
        Mock::given(method("POST"))
            .and(body_string_contains("DockerContainers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(changed))
            .mount(&s)
            .await;
        let e = update_with(
            &client(&s),
            "willow",
            &prot(),
            update("sabnzbd", "autostart", Some(r#"{"enabled":false}"#)),
        )
        .await
        .unwrap_err();
        (e, mutation_bodies(&s).await)
    });
    assert!(e.to_string().contains("changed while planning"), "{e}");
    assert!(bodies.is_empty());
}

#[test]
fn autostart_refuses_an_empty_list_and_an_unbounded_wait() {
    assert!(autostart_entries(&[], SAB, false, None).is_err());
    let rt = rt();
    let e = rt.block_on(async {
        let s = server("updateAutostartConfiguration", json!(true)).await;
        update_with(
            &client(&s),
            "willow",
            &prot(),
            update(
                "sabnzbd",
                "autostart",
                Some(r#"{"enabled":true,"wait":3601}"#),
            ),
        )
        .await
        .unwrap_err()
    });
    assert!(e.to_string().contains("0..=3600"), "{e}");
}

#[test]
fn protected_targets_need_force_and_the_plan_says_so() {
    let all = containers_fixture();
    let zot = resolve(&all, ZOT).unwrap();
    assert_eq!(protected_match(zot, &prot()).as_deref(), Some("zot"));
    let sab = resolve(&all, SAB).unwrap();
    assert!(protected_match(sab, &protected_set(None)).is_none());
    assert!(protected_match(sab, &protected_set(Some("gitea, sabnzbd"))).is_some());
    assert!(protected_match(sab, &protected_set(Some(SAB))).is_some());

    let rt = rt();
    let (plan_out, refused, forced, bodies) = rt.block_on(async {
        let s = server("stop", json!({"id": ZOT, "state": "EXITED"})).await;
        let c = client(&s);
        let plan_out = update_with(
            &c,
            "willow",
            &prot(),
            update("registry", "stop", Some(r#"{"dryRun":true}"#)),
        )
        .await
        .unwrap();
        let refused = update_with(&c, "willow", &prot(), update("registry", "stop", None))
            .await
            .unwrap_err();
        let before = mutation_bodies(&s).await.len();
        let forced = update_with(
            &c,
            "willow",
            &prot(),
            update("registry", "stop", Some(r#"{"force":true}"#)),
        )
        .await;
        (
            plan_out,
            refused,
            forced,
            (before, mutation_bodies(&s).await.len()),
        )
    });
    let VerbOutcome::Item(i) = plan_out else {
        panic!("expected plan")
    };
    assert!(i.payload.contains("protected"), "{}", i.payload);
    assert!(refused.to_string().contains("force"), "{refused}");
    assert!(forced.is_ok());
    assert_eq!(bodies, (0, 1));
}

#[test]
fn start_on_a_protected_target_needs_no_force() {
    let rt = rt();
    let out = rt.block_on(async {
        let s = server("start", json!({"id": ZOT, "state": "RUNNING"})).await;
        update_with(
            &client(&s),
            "willow",
            &prot(),
            update("registry", "start", None),
        )
        .await
    });
    assert!(out.is_ok());
}

#[test]
fn errors_name_fields_not_data() {
    let data = json!({"docker": {"stop": {"secret": "s3cr3t"}}});
    let e = expect_container(&data, "stop").unwrap_err().to_string();
    assert!(!e.contains("s3cr3t") && e.contains("docker.stop.id"), "{e}");
    let data = json!({"docker": {"removeContainer": {"secret": "s3cr3t"}}});
    let e = expect_true(&data, "removeContainer")
        .unwrap_err()
        .to_string();
    assert!(!e.contains("s3cr3t"), "{e}");
}

#[test]
fn a_foreign_server_prefix_is_rejected() {
    let all = containers_fixture();
    let foreign = format!("other:{}", bare_id(PLEX));
    let e = resolve(&all, &foreign).unwrap_err().to_string();
    assert!(e.contains("another Unraid server"), "{e}");
    assert_eq!(
        resolve(&all, &format!("{SERVER}:{}", bare_id(PLEX)))
            .unwrap()
            .id,
        PLEX
    );
}

#[test]
fn mountinfo_id_comes_only_from_runtime_file_mounts() {
    let docker = format!(
        "1 0 0:1 / / rw - overlay overlay rw\n\
         2 1 8:1 /var/lib/docker/containers/{H}/resolv.conf /etc/resolv.conf rw - ext4 /dev/sda1 rw\n"
    );
    assert_eq!(container_id_from_mountinfo(&docker).as_deref(), Some(H));
    let podman = format!(
        "3 1 0:2 /containers/storage/overlay-containers/{H}/userdata/hostname /etc/hostname rw - tmpfs tmpfs rw\n"
    );
    assert_eq!(container_id_from_mountinfo(&podman).as_deref(), Some(H));
    let other = format!("4 1 8:1 /var/lib/docker/containers/{H}/x /data rw - ext4 /dev/sda1 rw\n");
    assert_eq!(container_id_from_mountinfo(&other), None);
}

#[test]
fn cgroup_id_wins_when_sources_disagree() {
    let other = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let mountinfo = format!(
        "2 1 8:1 /var/lib/docker/containers/{other}/hostname /etc/hostname rw - ext4 /dev/sda1 rw\n"
    );
    let cgroup = format!("0::/system.slice/docker-{H}.scope\n");
    assert_eq!(
        own_container_id_from(Some(&mountinfo), Some(&cgroup)).as_deref(),
        Some(H)
    );
}

#[test]
fn remove_needs_a_stopped_container_unless_forced() {
    let rt = rt();
    let (plan_out, refused, forced, n) = rt.block_on(async {
        let s = server("removeContainer", json!(true)).await;
        let c = client(&s);
        let plan_out = update_with(
            &c,
            "willow",
            &prot(),
            update("plex", "remove", Some(r#"{"dryRun":true}"#)),
        )
        .await
        .unwrap();
        let refused = update_with(&c, "willow", &prot(), update("plex", "remove", None))
            .await
            .unwrap_err();
        let forced = update_with(
            &c,
            "willow",
            &prot(),
            update("plex", "remove", Some(r#"{"force":true}"#)),
        )
        .await;
        (plan_out, refused, forced, mutation_bodies(&s).await.len())
    });
    let VerbOutcome::Item(i) = plan_out else {
        panic!("expected plan")
    };
    assert!(i.payload.contains("state=running"), "{}", i.payload);
    assert!(
        refused.to_string().contains("running (state=running)"),
        "{refused}"
    );
    assert!(forced.is_ok());
    assert_eq!(n, 1);
}

#[test]
fn with_image_needs_an_image_id() {
    let rt = rt();
    let e = rt.block_on(async {
        let s = MockServer::start().await;
        let mut f = fixture();
        f["data"]["docker"]["containers"][0]["imageId"] = json!("");
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(f))
            .mount(&s)
            .await;
        update_with(
            &client(&s),
            "willow",
            &prot(),
            update("sabnzbd", "remove", Some(r#"{"withImage":true}"#)),
        )
        .await
        .unwrap_err()
    });
    assert!(e.to_string().contains("no imageId"), "{e}");
}

async fn autostart_outcome(after: impl FnOnce(&mut Value)) -> Result<VerbOutcome> {
    let s = autostart_server(2, after).await;
    update_with(
        &client(&s),
        "willow",
        &prot(),
        update("sabnzbd", "autostart", Some(r#"{"enabled":false}"#)),
    )
    .await
}

#[test]
fn autostart_confirms_our_write_landed() {
    let out = rt()
        .block_on(autostart_outcome(|f| {
            f["data"]["docker"]["containers"][0]["autoStart"] = json!(false);
        }))
        .unwrap();
    let VerbOutcome::Action(a) = out else {
        panic!("expected action outcome")
    };
    assert_eq!(a.message, "autostart sabnzbd = false");
}

#[test]
fn autostart_reports_others_changed_concurrently() {
    let out = rt()
        .block_on(autostart_outcome(|f| {
            f["data"]["docker"]["containers"][0]["autoStart"] = json!(false);
            f["data"]["docker"]["containers"][1]["autoStart"] = json!(false);
            f["data"]["docker"]["containers"][3]["autoStartWait"] = json!(5);
        }))
        .unwrap();
    let VerbOutcome::Action(a) = out else {
        panic!("expected action outcome")
    };
    assert!(a.changed);
    assert!(
        a.message.ends_with("changed concurrently: plex"),
        "{}",
        a.message
    );
}

#[test]
fn autostart_reports_not_applied_when_our_entry_is_lost() {
    let e = rt()
        .block_on(autostart_outcome(|f| {
            f["data"]["docker"]["containers"][1]["autoStart"] = json!(false);
        }))
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("not applied") && e.contains("retrying is safe"),
        "{e}"
    );
}

#[test]
fn verify_autostart_checks_wait_and_order() {
    let all = containers_fixture();
    let entries = autostart_entries(&all, SAB, true, Some(7)).unwrap();
    assert_eq!(
        verify_autostart(&entries, &all, SAB),
        AutostartVerdict::NotApplied
    );
    let mut after = containers_fixture();
    after[0].auto_start_wait = Some(7);
    assert_eq!(
        verify_autostart(&entries, &after, SAB),
        AutostartVerdict::Applied
    );
    after[0].auto_start_order = Some(0);
    after[1].auto_start_order = Some(1);
    assert_eq!(
        verify_autostart(&entries, &after, SAB),
        AutostartVerdict::NotApplied
    );
}

#[test]
fn autostart_times_out_and_releases_the_lock() {
    let rt = rt();
    let e = rt.block_on(async {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(fixture())
                    .set_delay(std::time::Duration::from_secs(5)),
            )
            .mount(&s)
            .await;
        let all = containers_fixture();
        let entries = autostart_entries(&all, SAB, false, None).unwrap();
        let e = write_autostart(
            &client(&s),
            "timeout-ep",
            &all,
            &entries,
            SAB,
            std::time::Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        assert!(autostart_lock("timeout-ep").try_lock().is_ok());
        e
    });
    assert!(e.to_string().contains("timed out"), "{e}");
}

#[test]
fn autostart_dry_run_states_when_force_is_needed() {
    let rt = rt();
    let mut f = fixture();
    f["data"]["docker"]["containers"][3]["autoStart"] = json!(true);
    let (needs, overrides, enabling) = rt.block_on(async {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(f))
            .mount(&s)
            .await;
        let c = client(&s);
        let mut out = Vec::new();
        for payload in [
            r#"{"enabled":false,"dryRun":true}"#,
            r#"{"enabled":false,"force":true,"dryRun":true}"#,
            r#"{"enabled":true,"dryRun":true}"#,
        ] {
            let VerbOutcome::Item(i) = update_with(
                &c,
                "willow",
                &prot(),
                update("registry", "autostart", Some(payload)),
            )
            .await
            .unwrap() else {
                panic!("expected plan")
            };
            out.push(i.payload);
        }
        (out[0].clone(), out[1].clone(), out[2].clone())
    });
    assert!(needs.contains("requires"), "{needs}");
    assert!(
        overrides.contains("force overrides protected"),
        "{overrides}"
    );
    assert!(!enabling.contains("force"), "{enabling}");
}

#[test]
fn forced_remove_names_both_guards() {
    let rt = rt();
    let (refused, planned) = rt.block_on(async {
        let s = server("removeContainer", json!(true)).await;
        let c = client(&s);
        let refused = update_with(&c, "willow", &prot(), update("registry", "remove", None))
            .await
            .unwrap_err()
            .to_string();
        let VerbOutcome::Item(i) = update_with(
            &c,
            "willow",
            &prot(),
            update(
                "registry",
                "remove",
                Some(r#"{"force":true,"dryRun":true}"#),
            ),
        )
        .await
        .unwrap() else {
            panic!("expected plan")
        };
        (refused, i.payload)
    });
    for text in [&refused, &planned] {
        assert!(
            text.contains("protected (matches 'zot')") && text.contains("running (state=running)"),
            "{text}"
        );
    }
    assert!(refused.contains("override both"), "{refused}");
    assert!(planned.contains("force overrides"), "{planned}");
}

#[test]
fn autostart_lock_is_per_endpoint() {
    let a = autostart_lock("willow");
    let b = autostart_lock("willow");
    let c = autostart_lock("maple");
    assert!(std::sync::Arc::ptr_eq(&a, &b));
    assert!(!std::sync::Arc::ptr_eq(&a, &c));
}

#[test]
fn disabling_autostart_on_a_protected_container_needs_force() {
    let rt = rt();
    let mut f = fixture();
    f["data"]["docker"]["containers"][3]["autoStart"] = json!(true);
    let (refused, n) = rt.block_on(async {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("DockerContainers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(f))
            .mount(&s)
            .await;
        let e = update_with(
            &client(&s),
            "willow",
            &prot(),
            update("registry", "autostart", Some(r#"{"enabled":false}"#)),
        )
        .await
        .unwrap_err();
        (e, mutation_bodies(&s).await.len())
    });
    assert!(refused.to_string().contains("force"), "{refused}");
    assert_eq!(n, 0);
}

#[test]
fn protected_entries_match_id_prefixes_and_full_repo_paths() {
    let all = containers_fixture();
    let zot = resolve(&all, ZOT).unwrap();
    let plex = resolve(&all, PLEX).unwrap();
    assert!(protects("444444444444", zot));
    assert!(protects("444444444444".to_uppercase().as_str(), zot));
    assert!(!protects("44444444444", zot));
    assert!(protects("ghcr.io/project-zot/zot", zot));
    assert!(!protects("docker.io/project-zot/zot", zot));
    assert!(!protects("ghcr.io/project-zot/zot", plex));
    let list = protected_set(Some("plex, ghost-thing"));
    assert_eq!(unmatched_protected(&all, &list), vec!["ghost-thing"]);
}

#[test]
fn a_secret_backend_error_fails_closed() {
    let e = endpoint_protected("willow").unwrap_err().to_string();
    assert!(e.contains("refusing to act"), "{e}");
}

#[test]
fn a_missing_protected_secret_means_defaults_only() {
    let got = crate::test_support::isolated(|| endpoint_protected("willow")).unwrap();
    assert_eq!(got.len(), DEFAULT_PROTECTED.len());
}
