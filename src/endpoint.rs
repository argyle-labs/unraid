//! Unraid endpoint registry — `unraid.{list,detail,create,update,delete}`.
//!
//! Generated wholesale by `#[endpoint_resource]` (the row struct, the
//! `endpoint_db::*` CRUD helpers, the schema fragment, args/output types,
//! and the five `#[orca_tool]` functions) per
//! [[feedback-plugin-toolkit-max-power-min-boilerplate]].
//!
//! Each registered endpoint points the docker topology collector at one
//! Unraid host's GraphQL API. On Unraid the daemon runs locally and reaches
//! the API through nginx at `http://127.0.0.1/graphql`, which proxies the
//! root-owned unix socket — see [[project-unraid-graphql-unix-socket-endpoint]].
//! `api_key` is sent as the `x-api-key` header and is stored secret-side
//! (excluded from the public `EndpointEntry`).

use plugin_toolkit::prelude::*;

#[endpoint_resource(plugin = "unraid")]
pub struct UnraidEndpoint {
    /// Base URL of the Unraid GraphQL API, e.g. `http://127.0.0.1`. The
    /// `/graphql` path is appended by [`crate::Config::endpoint`].
    pub base_url: String,
    /// Unraid API key, sent as `x-api-key`. Mint one with
    /// `unraid-api apikey --create --name "orca collector"`.
    #[secret]
    pub api_key: String,
    /// Accept self-signed TLS certs (only needed when `base_url` is https).
    pub insecure: bool,
}
