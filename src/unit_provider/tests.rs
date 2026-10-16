use super::*;
use crate::test_support::rt;
use wiremock::matchers::{body_string_contains, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SERVER: &str = "abc123";
const PLEX: &str = "abc123:1111111111111111111111111111111111111111111111111111111111111111";
const ORCA: &str = "abc123:2222222222222222222222222222222222222222222222222222222222222222";
const SAB: &str = "abc123:3333333333333333333333333333333333333333333333333333333333333333";

fn fixture() -> Value {
    json!({ "data": { "docker": { "id": SERVER, "containers": [
        { "id": SAB, "names": ["/sabnzbd"], "image": "lscr.io/linuxserver/sabnzbd:latest",
          "state": "EXITED", "status": "Exited (0)", "autoStart": true,
          "autoStartOrder": 1, "autoStartWait": 0, "iconUrl": null, "webUiUrl": null,
          "isUpdateAvailable": false },
        { "id": PLEX, "names": ["/plex"], "image": "plexinc/pms-docker:latest",
          "state": "RUNNING", "status": "Up 2 days", "autoStart": true,
          "autoStartOrder": 0, "autoStartWait": 10, "iconUrl": null, "webUiUrl": null,
          "isUpdateAvailable": false },
        { "id": ORCA, "names": ["/orca"], "image": "gitea.example/argyle-labs/orca:rc",
          "state": "RUNNING", "status": "Up", "autoStart": true,
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
fn orca_is_recognized_by_name_image_or_hostname() {
    let all = containers_fixture();
    let orca = resolve(&all, ORCA).unwrap();
    let plex = resolve(&all, PLEX).unwrap();
    assert!(is_orca(orca, None));
    assert!(!is_orca(plex, None));
    assert!(is_orca(plex, Some("111111111111")));
    assert!(!is_orca(plex, Some("tower")));
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
    let e = autostart_entries(&all, SAB, false, None);
    assert_eq!(e[0], json!({"id": PLEX, "autoStart": true, "wait": 10}));
    assert_eq!(e[1], json!({"id": SAB, "autoStart": false, "wait": 0}));
    assert_eq!(e[2], json!({"id": ORCA, "autoStart": true}));
}

#[test]
fn stop_executes_by_default() {
    let rt = rt();
    let (out, bodies) = rt.block_on(async {
        let s = server("stop", json!({"id": PLEX, "state": "EXITED"})).await;
        let out = update_with(&client(&s), "willow", update("plex", "stop", None)).await;
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
            update(PLEX, "remove", Some(r#"{"withImage":true}"#)),
        )
        .await
        .unwrap();
        mutation_bodies(&s).await
    });
    assert_eq!(
        bodies[0]["variables"],
        json!({"id": PLEX, "withImage": true})
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
        update_with(&client(&s), "willow", update("plex", "restart", None))
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
        let s = server("updateAutostartConfiguration", json!(true)).await;
        update_with(
            &client(&s),
            "willow",
            update("sabnzbd", "autostart", Some(r#"{"enabled":false}"#)),
        )
        .await
        .unwrap();
        mutation_bodies(&s).await
    });
    let entries = bodies[0]["variables"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
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
        update_with(&client(&s), "willow", update("plex", "remove", None))
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
            let e = update_with(&client(&s), "willow", update(target, "stop", None))
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
