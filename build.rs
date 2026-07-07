//! Build-time GraphQL codegen for the typed Unraid client.
//!
//! Walks every `<version>.introspection.json` in `../unraid/schemas/`,
//! runs `graphql_client_codegen` over the `.graphql` query files in
//! `queries/` against each schema, and emits one module per version
//! into `OUT_DIR`. `lib.rs` includes the aggregated output. The set of
//! supported versions is whatever is committed on disk — adding 7.3.0
//! means dropping `schemas/7.3.0.introspection.json` in and rebuilding.
//!
//! Codegen plumbing is centralised in `orca-plugin-toolkit-build` per
//! [[feedback-plugin-toolkit-is-the-gateway]].
//!
//! After codegen, the shared `plugin_toolkit_build::surface::graphql` pass walks
//! the emitted query modules and generates one `#[orca_tool]` per GraphQL
//! operation (the GraphQL analogue of proxmox's OpenAPI surface pass).

fn main() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schemas_dir = manifest_dir.join("schemas");
    let queries_dir = manifest_dir.join("queries");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    plugin_toolkit_build::graphql::generate(&schemas_dir, &queries_dir)
        .expect("unraid graphql codegen");

    // Generate the orca tool surface from the just-emitted query modules via the
    // shared toolkit pass (was the local `build/surface.rs` prototype). Mutations
    // surface as `data_mutation = true` + `role = "admin"`; a specific operation
    // can opt out to `role = "read"` via a `# @orca:user-callable` comment in its
    // `.graphql` file.
    plugin_toolkit_build::surface::graphql::generate(&out_dir, &queries_dir, "unraid")
        .expect("unraid surface codegen");
}
