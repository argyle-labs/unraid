//! Live typed-deserialization sweep against a real Unraid GraphQL API.
//!
//! Skipped unless `UNRAID_TEST_URL` is set (so CI stays green with no live
//! host). Point it at the host's DIRECT LAN IP, not an FQDN behind a reverse
//! proxy:
//!   UNRAID_TEST_URL=https://<lan-ip> \
//!   UNRAID_TEST_KEY=<x-api-key> UNRAID_TEST_INSECURE=1 \
//!   cargo test --test live_unraid -- --nocapture
//!
//! For every read the plugin performs, it drives the real GraphQL client (the
//! exact typed layer the topology collector + tools delegate to) and asserts
//! the response deserializes into the generated `ResponseData`. A typed-parse
//! failure is the bug class this test exists to catch; a GraphQL permission
//! error (the key's role lacks a resource) is reported, not failed.

use unraid::{Client, Config};

#[derive(Debug, Clone, Copy, PartialEq)]
enum Outcome {
    Ok,
    Denied,
    Deser,
    Other,
}

/// Classify a client result. `Ok` = typed body parsed. A permission/auth
/// GraphQL error is `Denied` (role gap, not a surface defect). A message that
/// smells like a schema mismatch is `Deser` — the failure a wrong/stale
/// generated query produces.
fn classify<T>(r: Result<T, unraid::UnraidError>) -> (Outcome, String) {
    match r {
        Ok(_) => (Outcome::Ok, String::new()),
        Err(e) => {
            let m = e.to_string();
            let lc = m.to_lowercase();
            let out = if lc.contains("forbidden")
                || lc.contains("unauthor")
                || lc.contains("permission")
                || lc.contains("not allowed")
            {
                Outcome::Denied
            } else if lc.contains("missing field")
                || lc.contains("invalid type")
                || lc.contains("unknown variant")
                || lc.contains("expected")
                || lc.contains("deserial")
            {
                Outcome::Deser
            } else {
                Outcome::Other
            };
            (out, m.chars().take(200).collect())
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn live_read_sweep() {
    let Ok(url) = std::env::var("UNRAID_TEST_URL") else {
        eprintln!("SKIP live_unraid: UNRAID_TEST_URL not set");
        return;
    };
    let key = std::env::var("UNRAID_TEST_KEY").expect("UNRAID_TEST_KEY");
    let insecure = std::env::var("UNRAID_TEST_INSECURE").is_ok();
    // Best-effort: a provider may already be installed process-wide.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("live_unraid: rustls provider already installed");
    }

    let cfg = Config::new(url, key).insecure(insecure);
    let client = Client::new_probed(cfg).await.expect("probe unraid version");
    eprintln!("probed api version: {:?}", client.api_version());

    let mut results: Vec<(&str, Outcome, String)> = Vec::new();
    macro_rules! chk {
        ($name:expr, $call:expr) => {{
            let (o, d) = classify($call.await.map(|_| ()));
            results.push(($name, o, d));
        }};
    }

    chk!("installed_plugins", client.installed_plugins());
    chk!("array", client.array());
    chk!("shares", client.shares());
    chk!("docker_containers", client.docker_containers());
    chk!("parity_history", client.parity_history());

    let mut ok = 0;
    let mut denied = 0;
    let mut other = 0;
    let deser: Vec<_> = results
        .iter()
        .filter(|(_, o, _)| *o == Outcome::Deser)
        .collect();
    eprintln!("\n── unraid live read sweep ──");
    for (name, o, d) in &results {
        match o {
            Outcome::Ok => ok += 1,
            Outcome::Denied => denied += 1,
            Outcome::Other => other += 1,
            Outcome::Deser => {}
        }
        let tag = match o {
            Outcome::Ok => "OK    ",
            Outcome::Denied => "DENIED",
            Outcome::Deser => "DESER ",
            Outcome::Other => "OTHER ",
        };
        eprintln!("  {tag} {name} {d}");
    }
    eprintln!(
        "\n{ok} OK · {denied} DENIED(role) · {other} OTHER · {} DESER-FAIL",
        deser.len()
    );

    assert!(
        deser.is_empty(),
        "{} query(ies) returned a body the generated model could not deserialize: {:#?}",
        deser.len(),
        deser
    );
}
