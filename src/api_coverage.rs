use std::collections::BTreeSet;

use plugin_toolkit::serde_json::Value;

const EXCLUDED: &[(&str, &str)] = &[
    ("Query", "apiKey"),
    ("Query", "apiKeys"),
    ("Query", "connect"),
    ("Query", "oidcConfiguration"),
    ("Query", "oidcProvider"),
    ("Query", "oidcProviders"),
    ("Query", "pluginInstallOperation"),
    ("Query", "rclone"),
    ("Query", "registration"),
    ("Query", "server"),
    ("Query", "servers"),
    ("Query", "settings"),
    ("Query", "validateOidcSession"),
    ("UnraidPluginsMutations", "installPlugin"),
];

#[derive(Debug, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Open,
    Close,
    ParenOpen,
    ParenClose,
    Colon,
}

fn tokens(doc: &str) -> Vec<Tok> {
    let text: String = doc
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' => out.push(Tok::Open),
            '}' => out.push(Tok::Close),
            '(' => out.push(Tok::ParenOpen),
            ')' => out.push(Tok::ParenClose),
            ':' => out.push(Tok::Colon),
            '"' => {
                for n in chars.by_ref() {
                    if n == '"' {
                        break;
                    }
                }
            }
            c if c.is_alphanumeric() || c == '_' || c == '$' => {
                let mut ident = c.to_string();
                while let Some(&n) = chars.peek() {
                    if n.is_alphanumeric() || n == '_' {
                        ident.push(n);
                        chars.next();
                    } else {
                        break;
                    }
                }
                out.push(Tok::Ident(ident));
            }
            _ => {}
        }
    }
    out
}

struct Selection {
    field: String,
    children: Vec<String>,
}

fn operation(doc: &str) -> (String, Vec<Selection>) {
    let toks = tokens(doc);
    let kind = match toks.first() {
        Some(Tok::Ident(k)) => k.clone(),
        _ => "query".into(),
    };
    let mut roots: Vec<Selection> = Vec::new();
    let (mut depth, mut parens) = (0usize, 0usize);
    for (i, t) in toks.iter().enumerate() {
        match t {
            Tok::ParenOpen => parens += 1,
            Tok::ParenClose => parens -= 1,
            Tok::Open if parens == 0 => depth += 1,
            Tok::Close if parens == 0 => depth -= 1,
            Tok::Ident(name) if parens == 0 && !name.starts_with('$') => {
                if toks.get(i + 1) == Some(&Tok::Colon) {
                    continue;
                }
                match depth {
                    1 => roots.push(Selection {
                        field: name.clone(),
                        children: Vec::new(),
                    }),
                    2 => {
                        if let Some(r) = roots.last_mut() {
                            r.children.push(name.clone());
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    (kind, roots)
}

fn schema() -> Value {
    let (_, raw) = crate::generated::SCHEMAS
        .iter()
        .find(|(v, _)| *v == "7.3.1")
        .expect("7.3.1 schema is committed");
    let v: Value = plugin_toolkit::serde_json::from_str(raw).unwrap();
    v.pointer("/data/__schema").unwrap().clone()
}

fn type_fields(schema: &Value, name: &str) -> Vec<Value> {
    schema["types"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == name)
        .and_then(|t| t["fields"].as_array().cloned())
        .unwrap_or_default()
}

fn base_type(t: &Value) -> &Value {
    if t["ofType"].is_object() {
        base_type(&t["ofType"])
    } else {
        t
    }
}

fn namespace(field: &Value) -> Option<String> {
    let b = base_type(&field["type"]);
    let name = b["name"].as_str()?;
    (b["kind"] == "OBJECT"
        && name.ends_with("Mutations")
        && field["args"].as_array().is_some_and(|a| a.is_empty()))
    .then(|| name.to_string())
}

fn schema_ops(schema: &Value) -> BTreeSet<(String, String)> {
    let mut ops = BTreeSet::new();
    let query = schema["queryType"]["name"].as_str().unwrap();
    for f in type_fields(schema, query) {
        ops.insert((query.to_string(), f["name"].as_str().unwrap().to_string()));
    }
    let mutation = schema["mutationType"]["name"].as_str().unwrap();
    for f in type_fields(schema, mutation) {
        match namespace(&f) {
            Some(ns) => {
                for nf in type_fields(schema, &ns) {
                    ops.insert((ns.clone(), nf["name"].as_str().unwrap().to_string()));
                }
            }
            None => {
                ops.insert((
                    mutation.to_string(),
                    f["name"].as_str().unwrap().to_string(),
                ));
            }
        }
    }
    ops
}

fn bound_ops(schema: &Value) -> BTreeSet<(String, String)> {
    let query = schema["queryType"]["name"].as_str().unwrap().to_string();
    let mutation = schema["mutationType"]["name"].as_str().unwrap().to_string();
    let mutation_fields = type_fields(schema, &mutation);
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("queries");
    let mut bound = BTreeSet::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("graphql") {
            continue;
        }
        let (kind, roots) = operation(&std::fs::read_to_string(&path).unwrap());
        for root in roots {
            if kind != "mutation" {
                bound.insert((query.clone(), root.field));
                continue;
            }
            let ns = mutation_fields
                .iter()
                .find(|f| f["name"] == root.field.as_str())
                .and_then(namespace);
            match ns {
                Some(ns) => {
                    for child in root.children {
                        bound.insert((ns.clone(), child));
                    }
                }
                None => {
                    bound.insert((mutation.clone(), root.field));
                }
            }
        }
    }
    bound
}

#[test]
fn every_schema_operation_is_bound_or_excluded() {
    let schema = schema();
    let ops = schema_ops(&schema);
    let bound = bound_ops(&schema);
    let excluded: BTreeSet<(String, String)> = EXCLUDED
        .iter()
        .map(|(t, f)| (t.to_string(), f.to_string()))
        .collect();
    let stale: Vec<_> = excluded.difference(&ops).collect();
    assert!(stale.is_empty(), "exclusions not in the schema: {stale:?}");
    let unknown: Vec<_> = bound.difference(&ops).collect();
    assert!(
        unknown.is_empty(),
        "bound ops not in the schema: {unknown:?}"
    );
    let unbound: Vec<String> = ops
        .iter()
        .filter(|op| !bound.contains(*op) && !excluded.contains(*op))
        .map(|(t, f)| format!("{t}.{f}"))
        .collect();
    println!(
        "unraid api coverage: {}/{} bound, {} excluded",
        ops.intersection(&bound).count(),
        ops.len(),
        excluded.len()
    );
    assert!(
        unbound.is_empty(),
        "{} unbound ops: {unbound:#?}",
        unbound.len()
    );
}

#[test]
fn operation_parser_reads_roots_and_namespaces() {
    let (kind, roots) = operation(
        "# c { x }\nmutation M($id: PrefixedID!) { docker { start(id: $id) { id } a: stop(id: $id) { id } } }",
    );
    assert_eq!(kind, "mutation");
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].field, "docker");
    assert_eq!(roots[0].children, vec!["start", "stop"]);
}

const SECRET_FIELDS: &[&str] = &[
    "key",
    "clientSecret",
    "apikey",
    "contents",
    "config",
    "parameters",
    "password",
    "token",
    "secret",
    "csrfToken",
];

fn query_docs() -> Vec<(String, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("queries");
    let mut docs = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("graphql") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_str().unwrap().to_string();
        docs.push((stem, std::fs::read_to_string(&path).unwrap()));
    }
    docs
}

fn selected_leaves(doc: &str) -> Vec<String> {
    let toks = tokens(doc);
    let mut depth = 0usize;
    let mut parens = 0usize;
    let mut out = Vec::new();
    for (i, tok) in toks.iter().enumerate() {
        match tok {
            Tok::Open => depth += 1,
            Tok::Close => depth -= 1,
            Tok::ParenOpen => parens += 1,
            Tok::ParenClose => parens -= 1,
            Tok::Ident(id) if depth > 0 && parens == 0 => {
                let mut j = i + 1;
                if toks.get(j) == Some(&Tok::ParenOpen) {
                    while toks.get(j).is_some_and(|t| *t != Tok::ParenClose) {
                        j += 1;
                    }
                    j += 1;
                }
                if !matches!(toks.get(j), Some(Tok::Open) | Some(Tok::Colon)) {
                    out.push(id.clone());
                }
            }
            _ => {}
        }
    }
    out
}

fn surface_source() -> String {
    std::fs::read_to_string(concat!(env!("OUT_DIR"), "/unraid_surface.rs")).unwrap()
}

#[test]
fn every_mutation_tool_is_admin() {
    let surface = surface_source();
    let attrs: Vec<&str> = surface
        .lines()
        .filter(|l| l.starts_with("#[orca_tool("))
        .collect();
    for attr in &attrs {
        if attr.contains("data_mutation = true") {
            assert!(attr.contains("role = \"admin\""), "{attr}");
        }
    }
    for (stem, doc) in query_docs() {
        if operation(&doc).0 != "mutation" {
            continue;
        }
        let verb = format!("verb = \"{stem}\"");
        let Some(attr) = attrs.iter().find(|a| a.contains(&verb)) else {
            continue;
        };
        assert!(
            attr.contains("role = \"admin\"") && attr.contains("data_mutation = true"),
            "{attr}"
        );
    }
}

#[test]
fn no_operation_selects_a_secret_leaf() {
    for (stem, doc) in query_docs() {
        for field in selected_leaves(&doc) {
            assert!(
                !SECRET_FIELDS.contains(&field.as_str()),
                "{stem} selects secret field `{field}`"
            );
        }
    }
}

#[test]
fn install_plugin_is_not_surfaced() {
    let surface = surface_source();
    assert!(!surface.contains("verb = \"install_plugin\""));
}

#[test]
fn every_operation_file_starts_with_its_operation() {
    for (stem, doc) in query_docs() {
        let head = doc.trim_start();
        assert!(
            head.starts_with("query") || head.starts_with("mutation"),
            "{stem}.graphql must start with `query` or `mutation`"
        );
    }
}

fn rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn every_hand_written_write_tool_is_admin() {
    const WRITE_VERBS: &[&str] = &["create", "update", "delete", "set", "adopt"];
    let mut files = Vec::new();
    rust_sources(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut seen = 0;
    for path in files {
        let src = std::fs::read_to_string(&path).unwrap();
        let mut rest = src.as_str();
        while let Some(at) = rest.find("\n#[orca_tool(") {
            let attr_start = &rest[at + 1..];
            let end = attr_start.find(")]").unwrap();
            let attr: String = attr_start[..end]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            rest = &attr_start[end..];
            seen += 1;
            let verb = attr
                .split("verb = \"")
                .nth(1)
                .and_then(|v| v.split('"').next())
                .unwrap_or_default();
            let last = verb.rsplit('.').next().unwrap_or_default();
            let writes = attr.contains("data_mutation = true")
                || WRITE_VERBS.iter().any(|w| last.starts_with(w));
            if writes {
                assert!(
                    attr.contains("role = \"admin\""),
                    "{}: {attr}",
                    path.display()
                );
            }
        }
    }
    assert!(seen > 0);
}
