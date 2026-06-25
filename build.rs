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

fn main() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schemas_dir = manifest_dir.join("schemas");
    let queries_dir = manifest_dir.join("queries");
    plugin_toolkit_build::graphql::generate(schemas_dir, queries_dir)
        .expect("unraid graphql codegen");
}
