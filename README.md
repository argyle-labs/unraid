<p align="center">
  <img src="assets/icon-256.png" width="120" alt="unraid" />
</p>

# unraid

Unraid is a NAS/virtualization OS with a flexible array, Docker, and VM support.

A first-party [orca](https://github.com/argyle-labs/orca) plugin (appliance integration).

This plugin **connects orca to an existing unraid install** — there's nothing to deploy here. Stand up unraid from the upstream project, then point orca at it.

---

## Run it without orca

Install unraid per the upstream project: <https://unraid.net/>. It listens on port `443` by default; this plugin talks to that endpoint (host, credentials/token) — no container is deployed.


## With orca

orca talks to a live Unraid host through its **GraphQL API** (typed queries, no opaque JSON). The plugin is a **hybrid**: a small tool surface plus one registered domain backend.

**Tool surface** (`unraid.*`):

| Command | What it does |
| --- | --- |
| `unraid.list` / `unraid.detail` / `unraid.create` / `unraid.update` / `unraid.delete` | Endpoint registry — register the Unraid hosts orca reads (base URL, `x-api-key`, self-signed TLS). The API key is stored secret-side. |
| `unraid.schema` | Inspect the embedded GraphQL schemas, pull a fresh introspection from a live host, or check drift between live and committed. |

**Topology backend** — a `topology` collector (registered via the toolkit's `topology_backend_def`) emits one `container` claim per Docker workload per enabled endpoint, so Unraid hosts and the containers they run surface in orca's systems graph. The GraphQL API is the read path because Unraid's Docker socket is `root:docker`-only.

Because the client pins a committed schema per Unraid version, it detects **schema drift**: when a live host's introspection diverges from the embedded schema (or its version has no committed schema at all), it warns once per host so stale generated queries surface early.

### Get an API key

Mint one on the host — `unraid-api apikey --create --name "orca collector"` — or in the web UI under **Settings → Management Access → API Keys**. It is sent as the `x-api-key` header (the GraphQL endpoint ignores `Authorization: Bearer`).

## Layout

- `src/lib.rs` — typed GraphQL client facade (per-version schema routing, drift detection).
- `src/endpoint.rs` — `#[endpoint_resource]` registry: the `unraid.{list,detail,create,update,delete}` tools.
- `src/tools.rs` — the `unraid.schema` tool (pull / drift-check).
- `src/topology.rs` — the `TopologyClaim` collector (Docker workloads via GraphQL).
- `src/registration.rs` — advertises the `topology` backend and dispatches its `collect_claims` op.
- `src/schema_pull.rs` / `src/version.rs` — introspection pull + version parsing.
- `schemas/` + `queries/` — committed introspection JSON and `.graphql` queries, codegenned by `build.rs`.
- `assets/` — plugin icon.
