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
    println!("cargo:rerun-if-changed=queries");
    println!("cargo:rerun-if-changed=schemas");
    plugin_toolkit_build::graphql::generate(&schemas_dir, &queries_dir)
        .expect("unraid graphql codegen");
    let modules = out_dir.join("modules.rs");
    let src = std::fs::read_to_string(&modules).expect("read modules.rs");
    let src = src
        .replace(
            "pub type DateTime = String;\n",
            "pub type DateTime = String;\npub type JSON = ::plugin_toolkit::serde_json::Value;\npub type Port = i64;\npub type URL = String;\n",
        )
        .replace(
            "use super::{BigInt, DateTime, PrefixedID};",
            "use super::{BigInt, DateTime, JSON, Port, PrefixedID, URL};",
        );
    std::fs::write(&modules, src).expect("write modules.rs");

    // Generate the orca tool surface from the just-emitted query modules via the
    // shared toolkit pass (was the local `build/surface.rs` prototype). Mutations
    // surface as `data_mutation = true` + `role = "admin"`; a specific operation
    // can opt out to `role = "read"` via a `# @orca:user-callable` comment in its
    // `.graphql` file.
    plugin_toolkit_build::surface::graphql::generate(&out_dir, &queries_dir, "unraid")
        .expect("unraid surface codegen");
    let surface = out_dir.join("unraid_surface.rs");
    let mut src = std::fs::read_to_string(&surface).expect("read unraid_surface.rs");
    for scalar in ["BigInt", "DateTime", "JSON", "Port", "PrefixedID", "URL"] {
        src = hoist_scalar(&src, scalar);
    }
    std::fs::write(&surface, src).expect("write unraid_surface.rs");
}

fn hoist_scalar(src: &str, scalar: &str) -> String {
    let tail = format!("::{scalar}");
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(at) = rest.find("crate::generated::") {
        out.push_str(&rest[..at]);
        let path_len = rest[at..]
            .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
            .unwrap_or(rest.len() - at);
        let path = &rest[at..at + path_len];
        let segments: Vec<&str> = path.split("::").collect();
        if segments.len() == 5 && path.ends_with(&tail) {
            out.push_str(&format!("crate::generated::{}{tail}", segments[2]));
        } else {
            out.push_str(path);
        }
        rest = &rest[at + path_len..];
    }
    out.push_str(rest);
    out
}
