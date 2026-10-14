//! Throwaway fake `/proc` (or any) directory tree for unit tests.

use plugin_toolkit::abi::{DbOp, DbReply, DbRow, DbValue, SecretOp, SecretReply};
use plugin_toolkit::capsink::with_cap_sink;
use plugin_toolkit::contract::config::{Config as OrcaConfig, Model};
use plugin_toolkit::prelude::ToolCtx;
use plugin_toolkit::serde_json;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// A temp directory removed on drop. Unique per process and per instance, so
/// parallel tests never share one.
pub struct FakeRoot(PathBuf);

impl FakeRoot {
    pub fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "unraid-fake-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::remove_dir_all(&root).ok();
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn str(&self) -> &str {
        self.0.to_str().unwrap()
    }

    /// Write `contents` at `rel`, creating parent directories.
    pub fn write(&self, rel: &str, contents: &str) -> &Self {
        let p = self.0.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, contents).unwrap();
        self
    }

    pub fn mkdir(&self, rel: &str) -> &Self {
        fs::create_dir_all(self.0.join(rel)).unwrap();
        self
    }

    /// A `/proc/<pid>` with `stat` (state, starttime ticks), `comm`, and any
    /// extra `(file, contents)` pairs such as `wchan`, `stack`, `cgroup`.
    pub fn proc(&self, pid: u32, comm: &str, state: char, start: u64, extra: &[(&str, &str)]) {
        // Fields 4..21 are filler; field 22 is starttime.
        let filler = vec!["0"; 18].join(" ");
        self.write(
            &format!("{pid}/stat"),
            &format!("{pid} ({comm}) {state} {filler} {start} 0 0\n"),
        );
        self.write(&format!("{pid}/comm"), &format!("{comm}\n"));
        for (f, c) in extra {
            self.write(&format!("{pid}/{f}"), c);
        }
    }
}

impl Drop for FakeRoot {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
}

/// In-memory stand-in for core's `db.op` + `secret.op` capabilities.
#[derive(Default)]
pub(crate) struct Store {
    pub rows: Vec<DbRow>,
    pub secrets: HashMap<String, String>,
    pub fail_secret_set: bool,
}

fn handle(store: &mut Store, cap: &str, json: &str) -> Result<String, String> {
    match cap {
        "db.op" => {
            let op: DbOp = serde_json::from_str(json).map_err(|e| e.to_string())?;
            let mut reply = DbReply::default();
            match op {
                DbOp::List { .. } => reply.rows = store.rows.clone(),
                DbOp::Insert { row, .. } => {
                    store.rows.push(row);
                    reply.affected = 1;
                }
                DbOp::Update { key_col, row, .. } => {
                    if let Some(r) = store
                        .rows
                        .iter_mut()
                        .find(|r| r.get(&key_col) == row.get(&key_col))
                    {
                        *r = row;
                        reply.affected = 1;
                    }
                }
                DbOp::Delete { key_col, key, .. } => {
                    let before = store.rows.len();
                    store
                        .rows
                        .retain(|r| r.get(&key_col) != Some(&DbValue::Text(key.clone())));
                    reply.affected = (before - store.rows.len()) as u64;
                }
                other => return Err(format!("unexpected db op {}", other.kind())),
            }
            serde_json::to_string(&reply).map_err(|e| e.to_string())
        }
        "secret.op" => {
            let op: SecretOp = serde_json::from_str(json).map_err(|e| e.to_string())?;
            let mut reply = SecretReply::default();
            match op {
                SecretOp::Get { name } => reply.value = store.secrets.get(&name).cloned(),
                SecretOp::Set { .. } if store.fail_secret_set => {
                    return Err("secret backend unavailable".into());
                }
                SecretOp::Set { name, value, .. } => {
                    store.secrets.insert(name, value);
                }
                SecretOp::Exists { name } => reply.found = store.secrets.contains_key(&name),
                SecretOp::Delete { name } => reply.found = store.secrets.remove(&name).is_some(),
            }
            serde_json::to_string(&reply).map_err(|e| e.to_string())
        }
        other => Err(format!("unexpected capability {other}")),
    }
}

pub(crate) fn with_store<R>(store: &Rc<RefCell<Store>>, body: impl FnOnce() -> R) -> R {
    let s = store.clone();
    with_cap_sink(
        Box::new(move |cap: &str, json: &str| handle(&mut s.borrow_mut(), cap, json)),
        body,
    )
}

/// Runs `body` against an empty in-memory endpoint registry.
pub(crate) fn isolated<R>(body: impl FnOnce() -> R) -> R {
    with_store(&Rc::new(RefCell::new(Store::default())), body)
}

/// Registers endpoint `name` with a single `lan_v4` route to `uri`.
pub(crate) async fn register(name: &str, uri: &str) {
    let route = plugin_toolkit::prelude::route::parse_route(&format!("lan_v4={uri}")).unwrap();
    let args = crate::endpoint::UnraidCreateArgs {
        name: name.into(),
        api_key: "k".into(),
        insecure: false,
        routes: vec![route],
    };
    crate::endpoint::unraid_create(args, &ctx()).await.unwrap();
}

pub(crate) fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

pub(crate) fn ctx() -> ToolCtx {
    ToolCtx::new(Arc::new(OrcaConfig {
        anthropic_api_key: None,
        lmstudio_url: String::new(),
        ollama_url: String::new(),
        default_model: Model::LMStudio {
            id: String::new(),
            url: String::new(),
        },
        app_dir: PathBuf::from("/tmp"),
        memory_root: PathBuf::from("/tmp"),
        db_path: PathBuf::from("/tmp/orca-unraid-endpoint-test.db"),
        ports: Default::default(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_proc_entry_and_cleans_up() {
        let path = {
            let r = FakeRoot::new("self");
            r.mkdir("acpi");
            r.proc(7, "smbd -D", 'D', 42, &[("wchan", "fuse_lock_inode")]);
            let stat = fs::read_to_string(r.path().join("7/stat")).unwrap();
            assert!(stat.starts_with("7 (smbd -D) D "));
            assert_eq!(stat.split_whitespace().nth(22), Some("42"));
            assert!(Path::new(r.str()).join("7/wchan").is_file());
            r.path().to_path_buf()
        };
        assert!(!path.exists());
    }
}
