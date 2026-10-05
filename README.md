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
| `unraid.list` / `unraid.detail` / `unraid.create` / `unraid.update` / `unraid.delete` | Endpoint registry — register the Unraid hosts orca reads (`--route`s, `--api-key`, self-signed TLS). The API key is stored in the secrets domain (`unraid.<endpoint>.api_key`), never on the endpoint row. |
| `unraid.schema` | Inspect the embedded GraphQL schemas, pull a fresh introspection from a live host, or check drift between live and committed. |
| `unraid.<operation>` | **Auto-generated, one per GraphQL operation** — e.g. `unraid.array_status`, `unraid.shares`, `unraid.docker_containers`, `unraid.parity_history`. Args carry the operation's typed variables; the return is its typed response. Mutations require `role = "admin"`. See below. |
| `unraid.plugins` / `unraid.installed_plugins` / `unraid.add_plugin` / `unraid.remove_plugin` / `unraid.install_plugin` / `unraid.plugin_install_operations` | **Plugin management** over the Unraid plugin manager: list (with versions), add, remove, and install/update by `.plg` URL. `unraid.install_plugin` with `forced: true` is the update path — because the plugin manager runs as root and owns the USB `/boot` write, routing orca's **own** update through it is what makes a self-update survive reboot (vs. the unprivileged daemon, which can't write flash). Installs are async — poll `unraid.plugin_install_operations` for `QUEUED → RUNNING → SUCCEEDED`. |
| `unraid.docker.status` / `unraid.docker.set_icon` / `unraid.docker.adopt` | **Unraid-native Docker containers** on the host the plugin runs on — see below. |

### Auto-generated operation tools

Every `.graphql` operation in `queries/` becomes an `#[orca_tool]` at build time (`build/surface.rs` walks the codegen'd query modules). Add a `.graphql` file → a new typed tool appears next build; nothing is hand-wired. Query operations surface as read tools, mutations as `role = "admin"` tools, and the full request/response shape is runtime-introspectable via each tool's arg/output JSON Schema.

Each tool resolves its connection in this order: an explicit `from` + `api_key` override wins; otherwise the named `endpoint` from the registry; otherwise, the sole registered endpoint when exactly one exists.

A registered endpoint is addressed by its `routes`, tried in order (enabled ones only, last-good first). An endpoint with no routes at all is treated as colocated and reached on loopback (`http://127.0.0.1`, nginx in front of the API's unix socket) — only when this host is itself Unraid (`/var/local/emhttp/var.ini` exists); otherwise resolution errors. An endpoint whose routes are all disabled or not URL-addressable errors rather than falling back to loopback. The `csrf_token` from `var.ini` is sent as `x-csrf-token` alongside `x-api-key` only when the resolved URL is loopback. Endpoint names must match `^[A-Za-z0-9_-]{1,64}$`.

```sh
orca unraid.create --name tower --api-key "$KEY"                                  # colocated
orca unraid.create --name tower --api-key "$KEY" --route lan_v4=http://10.0.0.5   # remote
orca unraid.update --name tower --api-key "$NEW_KEY"                               # rotate the key
```

### Unraid-native Docker containers

A container created with `docker run` or compose shows as "3rd Party" in Unraid's Docker tab. These verbs run on the Unraid host itself and drive the local `docker` CLI plus dockerMan's own PHP renderer (`xmlToCommand`, with the same setup as `scripts/rebuild_container`).

- `unraid.docker.status` (read-only) — per container: whether `my-<name>.xml` exists, the `net.unraid.docker.managed` label, the icon (and whether it is an argyle-labs repo icon), autostart membership, the docker volumes it mounts, the orca ownership labels it lacks, and for each volume whether it is anonymous and which ownership labels it lacks; plus host-wide dangling volume/image counts and `labelCoverage` (containers and volumes carrying every ownership label).
- `unraid.docker.set_icon --name <c> --repo <r>` — for a container already managed by dockerMan: sets its template's `<Icon>` to `<icon_base>/<r>/raw/branch/main/assets/icon-256.png`, writes orca's ownership labels into its ExtraParams and converts its anonymous volumes (see below), renders the patched template and refuses unless it reproduces the live container, rebuilds keeping the running/stopped state and autostart, verifies, and refreshes both icon caches. When the container already has that icon, the labels and no anonymous volumes, it changes nothing.
- `unraid.docker.adopt --name <c> [--repo <r>] [--migrate-volumes] [--autostart <bool>]` — builds a template from `docker inspect` (ports, env minus image-baked values, effective `TZ`, binds, named volumes, GPU requests, hostname, tmpfs, log options, restart policy, pids limit, labels, non-default bind propagation as `--mount`), renders it, and **refuses unless the rendered command reproduces the live container**. Differences that come with moving under dockerMan are listed as `intendedChanges` (`--pids-limit 2048`, a docker-default hostname, a compose network → `bridge`); the restart policy is carried and verified; anything else, and any inspect key the template cannot carry (capabilities, devices, healthcheck or stop-signal overrides, resource limits, static IPs, aliases, …), blocks. It also refuses when the image tag no longer resolves to the image the container runs, when another template claims the name, when a compose network is shared with other containers, and when the container is already dockerMan-managed (use `set_icon`).

  **Ownership labels.** `adopt` and `set_icon` give the container orca's ownership labels (the orca#772 contract, keys shared with the docker plugin): `orca.managed=true`, `orca.owner=unraid`, and `orca.stack` and `orca.service` set to the container name. They are listed per container and volume in `labels` and as `intendedChanges`, so they never block the fidelity gate. Each anonymous volume is converted, since the labels on an existing volume cannot change: a new volume `<name>_<path-slug>` is created with those labels plus `orca.mount=<container path>`, the stopped container's data is copied into it as root, and the template mounts it as `--mount type=volume,src=<new>,dst=<path>,volume-label=orca.…` instead of a Path entry with the hex name (plus `volume-nocopy` when the old volume is empty, so docker does not fill it from the image). The volume is named so a rebuild keeps its data; `volume-label` makes docker recreate it labeled if it is removed. Right after `docker volume create` the volume must carry exactly the requested labels and be empty, or it is not treated as this run's; a rollback removes it only if its `CreatedAt` is unchanged. As root, the copy re-checks that the old volume is anonymous, used only by this container and mounted at the path the new volume's `orca.mount` names; it carries extended attributes (file capabilities, ACLs) and compares them in the manifest, refusing a target that cannot hold them, and the new volume's root takes the source's owner and mode without setuid or sticky bits (a setuid source root is refused). The container is checked to still be stopped right before the rebuild. A conversion is refused when the volume is not plain `local`, another container mounts it, the path contains `,`, `"` or `&`, or a volume of the new name already exists (one orca labeled for the same mount and no container uses is reused). With `--migrate-volumes`, anonymous volumes are copied to appdata instead.

  Every copied volume, migrated or converted, is removed after the rebuild only when no container mounts it and a fresh manifest taken as root matches the one recorded at copy time; otherwise it is kept and the reason reported. A failure after the rebuild names, for each converted volume, the volume now holding its data. If `set_icon` cannot rewrite a template's ExtraParams (for example one containing `&`), it still sets the icon and reports the labels and conversions as not applied; a Path entry it cannot find leaves that volume unconverted, also reported.

  On execute it saves the original inspect to `my-<name>.xml.inspect-<run>.json`, backs up any existing template to `my-<name>.xml.bak-<run>` (or records that there was none in `….bak-<run>.none`), where `<run>` is a per-run id (`YYYYMMDD-HHMMSS-<hex>`) and neither file is ever overwritten; writes the template (marked `<!-- managed-by: orca -->`), sets autostart so `rebuild_container` leaves the container in its previous running/stopped state, rebuilds, and verifies it is `dockerman`-managed, on the same image, and matches the rendered command, restart policy included. It then removes only what the container owned: its own anonymous volumes, its compose `<project>_default` network, and its compose stack directory (moved to the planned `<root>-retired/<name>-compose-<date>`, re-derived and compared as root, when it sits directly under a configured stacks root, has a compose file for the project, and nothing else uses or mounts it). A failure before the rebuild rolls back what that run changed; a failure after it reports a concrete recovery command. `rebuild_container` itself removes the previous image when the image id changed, and keeps anonymous volumes (it removes the container without `v=1`).

  `--migrate-volumes` requires plain `local` volumes used by no other container, and destinations that overlap no existing bind mount (above or below) and do not exist yet. It stops the container. As root it then:
  - re-checks that the container is stopped (again after the copy; if it started meanwhile, the copy is discarded);
  - refuses a volume holding anything but regular files, directories and symlinks (device nodes, FIFOs, sockets), setuid/setgid files, setuid directories, or nesting deeper than 256;
  - copies `_data` into a fresh stage `/mnt/user/appdata/<name>/.orca-stage-<hash>/data`. The stage is root-owned 0700, so nothing else can reach into it. It holds a token with this run's nonce, which is never shown and is unreadable to anyone else. The copy uses `cp -R --no-dereference --preserve=mode,ownership,timestamps,links`, so extended attributes such as file capabilities are dropped;
  - re-checks the copy and verifies entries, bytes, modes, owners and a sha256 of every file's contents.

  Right before the rebuild, each staged copy is moved to `/mnt/user/appdata/<name>/<suffix>` (never replacing anything there) and the stage is removed. Once the recreated container is running, the old volumes are removed. A rollback removes only stages carrying its own run's token, deleting inside them by descriptor. A copy that was already moved into place is never removed; it is reported as left in place. The stage is recognised by its token, not by device/inode numbers, which shfs (FUSE) does not promise to keep stable across processes.

`set_icon` and `adopt` are **dry-run by default**: without `--execute` they return the template XML, the rendered command, the fidelity diff, intended changes, blockers, every label written to each container and volume, and the ordered step list, and change nothing. `--execute` requires an admin caller. Env values whose name looks secret (`pass`, `token`, `secret`, `key`, `auth`, `cred`, `cookie`, `session`, `private`) are shown as `<redacted:…>` in every output and written with `Mask="true"`; The secret-looking name parts are `pass`, `pwd`, `pw` (as a whole word), `token`, `secret`, `key`, `auth`, `cred`, `cookie`, `session`, `private`, `jwt`, `salt`, `dsn`, `webhook`, `signing`, `encrypt` and `claim`. The same masking applies to label values (the same parts plus `users`), log options (`--log-opt`, including in ExtraParams), template Variables marked `Mask="true"`, command arguments after secret-looking flags (`--flag value`, `--flag=value`, `-p value`, `-p<value>`), the password in every `scheme://user:password@` URL in a value, and `password=`/`pwd=` values in connection strings. The `…` is a keyed digest prefix with a per-process random key: equal values match within one output, and it cannot be checked against guesses.

A dry run pings the root path (a no-op operation); if that fails it reports `ready: false` with the orca#762 blocker.

The icon base must be `https` on an allowlisted host (`gitea.scottkey.me`, plus any in `ORCA_UNRAID_ICON_HOSTS`). Extra stacks roots (besides `/opt/stacks` and `/mnt/user/appdata/dockge/stacks`) are read from `/boot/config/plugins/orca/unraid-stacks-roots`.

**Root access.** Writing `/boot` templates and the autostart file, rebuilding, clearing icon caches, copying volumes and retiring stacks need root; the plugin runs as the unprivileged `orca` user. These effects are a closed set of operations that `unraid --privileged-op` runs as root, re-validating every input. Root acts through directory descriptors, never through a path it checked earlier: `/mnt/user` and `/mnt/user/appdata` are world-writable without the sticky bit, so any component could be swapped for a symlink mid-operation. Each directory is reached from `/` one component at a time with `O_NOFOLLOW` (`openat2` with `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH` on Linux). Files are then created with `O_EXCL|O_NOFOLLOW`, replaced with `renameat`, read and hashed from an fd opened `O_NONBLOCK` and checked to be a regular file, and deleted by an fd-relative walk. `cp` writes into the held stage through `/proc/<pid>/fd/<n>`. Docker is run as `/usr/bin/docker` and `cp` as `/bin/cp`. Stacks are retired with `renameat` between held directories, and only from a stacks root (and into a `-retired` directory) that is root-owned and not group/world-writable; otherwise the plan keeps the stack and says why. A template's ExtraParams reach `docker run`, so writing one is equivalent to starting a root container; this grants nothing new, because the `orca` user is already in the `docker` group. They are reached directly when the plugin already runs as root, or through orca's privileged seam `sudo -n $ORCA_BIN admin plugin-apply` (argyle-labs/orca#762) when `ORCA_BIN` is set; success needs both a zero exit and an `ok: true` reply. With neither, execute is blocked up front.

**Topology backend** — a `topology` collector (registered via the toolkit's `topology_backend_def`) emits one `container` claim per Docker workload per enabled endpoint, so Unraid hosts and the containers they run surface in orca's systems graph. The GraphQL API is the read path because Unraid's Docker socket is `root:docker`-only.

Because the client pins a committed schema per Unraid version, it detects **schema drift**: when a live host's introspection diverges from the embedded schema (or its version has no committed schema at all), it warns once per host so stale generated queries surface early.

### Get an API key

Mint one on the host — `unraid-api apikey --create --name "orca collector"` — or in the web UI under **Settings → Management Access → API Keys**. It is sent as the `x-api-key` header (the GraphQL endpoint ignores `Authorization: Bearer`).

## Layout

- `src/lib.rs` — typed GraphQL client facade (per-version schema routing, drift detection).
- `src/endpoint.rs` — `#[endpoint_resource]` registry (`unraid.{list,detail,create,update,delete}`) and route + secret resolution into a client `Config`.
- `src/tools.rs` — the `unraid.schema` tool (pull / drift-check).
- `src/docker_adopt/` — the `unraid.docker.*` verbs: inspect → template mapping, dockerMan command parsing + fidelity diff, leftover selection and secret masking (pure, tested against real fixtures), the host side effects, and the root-only operations behind `--privileged-op`.
- `src/topology.rs` — the `TopologyClaim` collector (Docker workloads via GraphQL).
- `src/registration.rs` — advertises the `topology` backend and dispatches its `collect_claims` op.
- `src/schema_pull.rs` / `src/version.rs` — introspection pull + version parsing.
- `schemas/` + `queries/` — committed introspection JSON and `.graphql` queries, codegenned by `build.rs`.
- `assets/` — plugin icon.
