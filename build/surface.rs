//! Prototype: generate the orca tool surface from the GraphQL-derived modules.
//!
//! Runs in `build.rs` *after* `plugin_toolkit_build::graphql::generate` has
//! written `<OUT_DIR>/modules.rs`. Rather than hand-write one `#[orca_tool]` per
//! GraphQL operation (as `src/lib.rs`'s `Client` methods used to), this walks the
//! codegen'd query modules and emits one tool per operation:
//!
//!   1. `unraid_surface.rs` — an `#[orca_tool]` wrapper per operation. Query
//!      operations surface as read tools; mutations as `role = "admin"`. The args
//!      struct carries the operation's `Variables` **as typed fields** plus the
//!      endpoint/override selection, and the return is the operation's typed
//!      `ResponseData`.
//!   2. JsonSchema (and, on the variables side, Deserialize) anchored onto every
//!      type in each surfaced operation module, so the full request/response
//!      shape is runtime-introspectable via the tool's `args_schema` /
//!      `output_schema`.
//!
//! Every type in a `graphql_client` operation module belongs to either the
//! request tree (`Variables` + input objects, `Serialize`-only) or the response
//! tree (`ResponseData` + nested structs, `Deserialize`). So anchoring the whole
//! module is exactly the transitive closure — no graph walk needed. The
//! variables side additionally gets `Deserialize` so its types are usable as
//! tool-arg inputs.
//!
//! This is the unraid-local prototype of what will become a reusable
//! `plugin-toolkit-build` GraphQL-surface pass, the analogue of proxmox's
//! `build/surface.rs` OpenAPI pass.

#![allow(clippy::disallowed_types)]

use anyhow::{Context, Result};

/// GraphQL scalar type aliases `graphql_client` emits inside every operation
/// module (`type Boolean = bool;` …). They are **not** `pub`, so a `Variables`
/// field typed as one must render to its primitive, not to a module path.
fn scalar_primitive(ident: &str) -> Option<&'static str> {
    Some(match ident {
        "Boolean" => "bool",
        "Float" => "f64",
        "Int" => "i64",
        "ID" | "String" => "String",
        _ => return None,
    })
}

/// Rust primitives a `Variables` field can already be, rendered as-is.
const PRIMITIVES: &[&str] = &[
    "bool", "String", "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64",
];

/// One surfaceable GraphQL operation.
struct Op {
    /// Snake-case module name (`add_plugin`) — also the tool verb.
    module: String,
    /// PascalCase marker struct implementing `GraphQLQuery` (`AddPlugin`).
    marker: String,
    /// `true` for `mutation` operations → `role = "admin"`.
    is_mutation: bool,
    /// `Variables` fields as `(name, rendered_type)`. Empty ⇒ unit `Variables`
    /// (no arguments).
    var_fields: Vec<(String, String)>,
}

pub fn generate() -> Result<()> {
    let out_dir = std::env::var("OUT_DIR").context("OUT_DIR not set")?;
    println!("cargo:rerun-if-changed=build/surface.rs");
    let modules_path = format!("{out_dir}/modules.rs");
    let src =
        std::fs::read_to_string(&modules_path).with_context(|| format!("read {modules_path}"))?;
    let mut file: syn::File = syn::parse_file(&src).context("parse generated modules.rs")?;

    // Newest committed version module (`v7_3_1`); ties break to the max ident,
    // matching the toolkit codegen's sort + `ApiVersion::newest`.
    let version =
        newest_version(&file).context("no `v<version>` module in generated modules.rs")?;
    let qualifier = format!("crate::generated::{version}");

    let gen_items = generated_items_mut(&mut file, &version)
        .context("no `generated` module inside the version module")?;

    let mut ops = Vec::new();
    let mut anchored = 0usize;
    for item in gen_items.iter_mut() {
        let syn::Item::Mod(m) = item else { continue };
        let Some((_, items)) = m.content.as_mut() else {
            continue;
        };
        let module = m.ident.to_string();
        let Some((marker, is_mutation)) = op_meta(items) else {
            continue;
        };
        let mod_qualifier = format!("{qualifier}::{module}");
        let var_fields = match variables_fields(items, &mod_qualifier) {
            Some(f) => f,
            None => {
                println!(
                    "cargo:warning=surface: skipped `{module}` — unrenderable Variables shape"
                );
                continue;
            }
        };
        anchored += anchor_module(items);
        ops.push(Op {
            module,
            marker,
            is_mutation,
            var_fields,
        });
    }

    std::fs::write(&modules_path, prettyplease::unparse(&file))
        .with_context(|| format!("rewrite {modules_path}"))?;

    let surface = emit_surface(&ops, &qualifier);
    let surface_path = format!("{out_dir}/unraid_surface.rs");
    std::fs::write(&surface_path, surface).with_context(|| format!("write {surface_path}"))?;

    println!(
        "cargo:warning=surface: {} tool(s) emitted from {version}, JsonSchema anchored on {anchored} type(s)",
        ops.len()
    );
    Ok(())
}

/// The lexicographically-greatest `v*` module ident (newest version).
fn newest_version(file: &syn::File) -> Option<String> {
    file.items
        .iter()
        .filter_map(|it| match it {
            syn::Item::Mod(m) => {
                let id = m.ident.to_string();
                (id.starts_with('v') && id[1..].starts_with(|c: char| c.is_ascii_digit()))
                    .then_some(id)
            }
            _ => None,
        })
        .max()
}

/// Mutable access to the items inside `<version>::generated { ... }`.
fn generated_items_mut<'a>(
    file: &'a mut syn::File,
    version: &str,
) -> Option<&'a mut Vec<syn::Item>> {
    let ver_items = file.items.iter_mut().find_map(|it| match it {
        syn::Item::Mod(m) if m.ident == version => m.content.as_mut().map(|(_, i)| i),
        _ => None,
    })?;
    ver_items.iter_mut().find_map(|it| match it {
        syn::Item::Mod(m) if m.ident == "generated" => m.content.as_mut().map(|(_, i)| i),
        _ => None,
    })
}

/// Read an operation module's `OPERATION_NAME` (marker struct) and classify
/// `QUERY` as query vs mutation. `None` when the module isn't an operation
/// module (no `OPERATION_NAME` const).
fn op_meta(items: &[syn::Item]) -> Option<(String, bool)> {
    let marker = const_str_value(items, "OPERATION_NAME")?;
    let query = const_str_value(items, "QUERY").unwrap_or_default();
    let is_mutation = query.trim_start().starts_with("mutation");
    Some((marker, is_mutation))
}

/// Value of a `pub const <name>: &str = "...";` item.
fn const_str_value(items: &[syn::Item], name: &str) -> Option<String> {
    items.iter().find_map(|it| match it {
        syn::Item::Const(c) if c.ident == name => match &*c.expr {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) => Some(s.value()),
            _ => None,
        },
        _ => None,
    })
}

/// Collect the `Variables` struct's fields as `(name, rendered_type)`. Returns
/// `Some(vec![])` for a unit `Variables` (no args), and `None` if any field type
/// can't be confidently rendered (⇒ skip surfacing that op rather than emit
/// broken code).
fn variables_fields(items: &[syn::Item], mod_qualifier: &str) -> Option<Vec<(String, String)>> {
    let vars = items.iter().find_map(|it| match it {
        syn::Item::Struct(s) if s.ident == "Variables" => Some(s),
        _ => None,
    })?;
    match &vars.fields {
        syn::Fields::Unit => Some(vec![]),
        syn::Fields::Named(named) => {
            let mut out = Vec::new();
            for f in &named.named {
                let name = f.ident.as_ref()?.to_string();
                let rendered = render_type(&f.ty, mod_qualifier)?;
                out.push((name, rendered));
            }
            Some(out)
        }
        syn::Fields::Unnamed(_) => None,
    }
}

/// Render a `Variables` field type into a path usable from the emitted surface
/// module. Rust primitives pass through; GraphQL scalar aliases map to their
/// primitive; a bare local ident (an input object) qualifies to its module
/// path. Anything else (generics, references) ⇒ `None`.
fn render_type(ty: &syn::Type, mod_qualifier: &str) -> Option<String> {
    let syn::Type::Path(p) = ty else { return None };
    if p.qself.is_some() || p.path.segments.len() != 1 {
        return None;
    }
    let seg = &p.path.segments[0];
    if !matches!(seg.arguments, syn::PathArguments::None) {
        return None;
    }
    let ident = seg.ident.to_string();
    if PRIMITIVES.contains(&ident.as_str()) {
        return Some(ident);
    }
    if let Some(prim) = scalar_primitive(&ident) {
        return Some(prim.to_string());
    }
    // A locally-defined input object — reachable at the module path once we
    // anchor Deserialize/JsonSchema on it.
    Some(format!("{mod_qualifier}::{ident}"))
}

/// Make every struct/enum in an operation module a full tool type: derive
/// `Serialize + Deserialize + JsonSchema`. `graphql_client` emits only one serde
/// direction per type (variables side = `Serialize`, response side =
/// `Deserialize`), but `#[orca_tool]` needs args to *deserialize* and outputs to
/// *serialize*, and both need `JsonSchema`. `#[serde(crate = ...)]` is already
/// present on every generated type, so the added impls resolve serde correctly.
/// Returns the count touched.
fn anchor_module(items: &mut [syn::Item]) -> usize {
    let mut n = 0;
    for it in items.iter_mut() {
        let attrs = match it {
            syn::Item::Struct(s) => &mut s.attrs,
            syn::Item::Enum(e) => &mut e.attrs,
            _ => continue,
        };
        let derives = derive_list(attrs);
        let has = |name: &str| derives.iter().any(|d| d == name);
        if !has("JsonSchema") {
            attrs.push(syn::parse_quote!(
                #[derive(::plugin_toolkit::schemars::JsonSchema)]
            ));
            attrs.push(syn::parse_quote!(
                #[schemars(crate = "::plugin_toolkit::schemars")]
            ));
        }
        // Only *derive-based* serde types (which carry `#[serde(crate = ...)]`)
        // may gain a missing serde derive — it honors that crate anchor.
        // GraphQL enums instead ship hand-written `Serialize` + `Deserialize`
        // impls (both directions) and carry no `#[serde(crate)]`; adding a serde
        // derive there emits a bare `serde` reference (E0463) and collides with
        // the manual impl. They already round-trip, so JsonSchema is all they
        // need.
        if has_serde_crate_attr(attrs) {
            if !has("Serialize") {
                attrs.push(syn::parse_quote!(
                    #[derive(::plugin_toolkit::serde::Serialize)]
                ));
            }
            if !has("Deserialize") {
                attrs.push(syn::parse_quote!(
                    #[derive(::plugin_toolkit::serde::Deserialize)]
                ));
            }
        }
        n += 1;
    }
    n
}

/// True if the item carries `#[serde(crate = ...)]`, marking it a derive-based
/// serde type (as opposed to a GraphQL enum with hand-written serde impls).
fn has_serde_crate_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        if !a.path().is_ident("serde") {
            return false;
        }
        let mut found = false;
        // Discard the parse result (accumulation happens in the closure); the
        // crate denies `let _ = <must_use>`, so consume it via `drop`.
        drop(a.parse_nested_meta(|meta| {
            if meta.path.is_ident("crate") {
                found = true;
            }
            Ok(())
        }));
        found
    })
}

/// The trailing idents of every `#[derive(...)]` on an item (`Serialize`,
/// `JsonSchema`, …), regardless of path qualification.
fn derive_list(attrs: &[syn::Attribute]) -> Vec<String> {
    let mut out = Vec::new();
    for a in attrs {
        if !a.path().is_ident("derive") {
            continue;
        }
        drop(a.parse_nested_meta(|meta| {
            if let Some(last) = meta.path.segments.last() {
                out.push(last.ident.to_string());
            }
            Ok(())
        }));
    }
    out
}

fn emit_surface(ops: &[Op], qualifier: &str) -> String {
    let mut s = String::from(
        "// @generated by build/surface.rs — do not edit. Regenerated every build.\n\
         use plugin_toolkit::prelude::*;\n\n",
    );
    for op in ops {
        s.push_str(&emit_one(op, qualifier));
        s.push('\n');
    }
    s
}

fn emit_one(op: &Op, qualifier: &str) -> String {
    let Op {
        module,
        marker,
        is_mutation,
        var_fields,
    } = op;
    let args_ident = format!("SurfaceArgs_{module}");
    let mod_path = format!("{qualifier}::{module}");
    let marker_path = format!("{qualifier}::{marker}");

    let mut fields = String::from(
        "    /// Registered endpoint name (from `unraid.list`); used when no explicit `from`.\n    \
         pub endpoint: Option<String>,\n    \
         /// Explicit base-URL override (wins over `endpoint`); pair with `api_key`.\n    \
         pub from: Option<String>,\n    \
         /// Explicit API key for the `from` override.\n    \
         pub api_key: Option<String>,\n    \
         /// Accept self-signed TLS for the `from` override.\n    \
         pub insecure: Option<bool>,\n",
    );
    for (name, ty) in var_fields {
        fields.push_str(&format!("    pub {name}: {ty},\n"));
    }

    let vars_expr = if var_fields.is_empty() {
        format!("{mod_path}::Variables")
    } else {
        let inits = var_fields
            .iter()
            .map(|(name, _)| format!("{name}: args.{name}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{mod_path}::Variables {{ {inits} }}")
    };

    let role = if *is_mutation {
        ", role = \"admin\""
    } else {
        ""
    };
    let kind = if *is_mutation { "mutation" } else { "query" };

    format!(
        "#[derive(Serialize, Deserialize, JsonSchema)]\n\
         #[serde(crate = \"::plugin_toolkit::serde\")]\n\
         #[schemars(crate = \"::plugin_toolkit::schemars\")]\n\
         #[allow(non_camel_case_types)]\n\
         pub struct {args_ident} {{\n{fields}}}\n\n\
         /// Auto-generated from the `{marker}` GraphQL {kind}.\n\
         #[orca_tool(domain = \"unraid\", verb = \"{module}\", cli = \"skip\"{role})]\n\
         async fn surface_{module}(args: {args_ident}, _ctx: &ToolCtx) -> Result<{mod_path}::ResponseData> {{\n    \
         let client = crate::tools::surface_client(args.endpoint, args.from, args.api_key, args.insecure).await?;\n    \
         let vars = {vars_expr};\n    \
         client\n        \
         .query::<{marker_path}>(vars)\n        \
         .await\n        \
         .map_err(|e| anyhow!(\"unraid.{module}: {{e}}\"))\n}}\n",
    )
}
