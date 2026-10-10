//! Throwaway fake `/proc` (or any) directory tree for unit tests.

use std::fs;
use std::path::{Path, PathBuf};
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
