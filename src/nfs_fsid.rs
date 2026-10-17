//! `unraid.nfs.fsids` — NFS fsid uniqueness, read-only.
//!
//! Unraid derives a user share's fsid from its name, so two servers with the
//! same share names serve the same fsids and a client mounting both gets
//! `Stale file handle`. This reports the host's fsids, duplicates among them,
//! and a non-identifying `serverKey` so orca can compare across servers: an
//! HMAC-SHA256 of the flash GUID under a per-install secret held in orca's
//! secrets store, never on the flash. It
//! also reports the fsid each user share would be given by a per-server hash
//! plan, and which clients hold mounts.
//!
//! Sources are the kernel's own interfaces: `/etc/exports` (the live table),
//! `rmtab` (rpc.mountd's NFSv3 mount table) and `/proc/fs/nfsd/clients`
//! (nfsd's NFSv4 client list). Client addresses are shown only to callers
//! above `read`; `read` callers get counts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use plugin_toolkit::prelude::*;

use plugin_toolkit::{hash, secrets};

use crate::share_cache::{self, VAR_INI};

const EXPORTS_FILE: &str = "/etc/exports";
const RMTAB: &str = "/var/lib/nfs/rmtab";
const NFSD_CLIENTS: &str = "/proc/fs/nfsd/clients";
const USER_SHARE_PREFIX: &str = "/mnt/user/";
const FSID_BASE: u32 = 1000;
const FSID_SPAN: u32 = 1 << 30;
const URANDOM: &str = "/dev/urandom";
const SERVER_KEY_CONTEXT: &[u8] = b"unraid.nfs.serverKey/v1";
const SERVER_KEY_SECRET: &str = "nfs_server_key_secret";
const SECRET_INSTANCE: &str = "local";
const CLIENT_ROLES: &[&str] = &["user", "member", "admin", "super-admin"];

pub(crate) struct Paths {
    pub exports: PathBuf,
    pub var_ini: PathBuf,
    pub rmtab: PathBuf,
    pub nfsd_clients: PathBuf,
}

impl Paths {
    fn live() -> Self {
        Self {
            exports: EXPORTS_FILE.into(),
            var_ini: VAR_INI.into(),
            rmtab: RMTAB.into(),
            nfsd_clients: NFSD_CLIENTS.into(),
        }
    }
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FsidExport {
    pub path: String,
    /// User share name; empty for disk and pool exports.
    pub share: String,
    pub fsid: String,
    /// The fsid the per-server plan gives this share; empty for non-share exports.
    pub planned_fsid: String,
    /// Clients holding a mount of this path or below it (NFSv3), plus every
    /// NFSv4 client, which cannot be attributed to one export. Empty for
    /// `read` callers, who get only `mountCount`.
    pub mounted_by: Vec<String>,
    pub mount_count: u32,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FsidDuplicate {
    pub fsid: String,
    pub paths: Vec<String>,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FsidReport {
    /// HMAC-SHA256(install secret, context || flashGUID), first 128 bits, hex.
    pub server_key: String,
    pub exports: Vec<FsidExport>,
    pub duplicates: Vec<FsidDuplicate>,
    /// Why client mounts could not be read; empty when they were.
    pub mounts_unknown: String,
}

pub(crate) fn fnv1a(s: &str) -> u32 {
    s.bytes().fold(0x811c_9dc5u32, |h, b| {
        (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
    })
}

pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&hash::sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let pad = |b: u8| k.iter().map(|x| x ^ b).collect::<Vec<u8>>();
    let mut inner = pad(0x36);
    inner.extend_from_slice(msg);
    let mut outer = pad(0x5c);
    outer.extend_from_slice(&hash::sha256(&inner));
    hash::sha256(&outer)
}

fn hashed_fsid(server_key: &str, share: &str) -> u32 {
    FSID_BASE + fnv1a(&format!("{server_key}/{share}")) % FSID_SPAN
}

/// Plan an fsid per share. Shares already at their hash value keep it and are
/// placed first; the rest step from their hash past every fsid in `reserved`
/// and every one already placed, in name order.
pub(crate) fn plan_fsids(
    server_key: &str,
    current: &BTreeMap<String, Option<u32>>,
    reserved: &BTreeSet<u32>,
) -> BTreeMap<String, u32> {
    let mut used = reserved.clone();
    let mut out = BTreeMap::new();
    let (fixed, moving): (Vec<_>, Vec<_>) = current
        .iter()
        .partition(|(s, f)| **f == Some(hashed_fsid(server_key, s)));
    for (share, fsid) in fixed {
        let f = fsid.expect("fixed shares have an fsid");
        used.insert(f);
        out.insert(share.clone(), f);
    }
    for (share, _) in moving {
        let mut off = hashed_fsid(server_key, share) - FSID_BASE;
        while used.contains(&(FSID_BASE + off)) {
            off = (off + 1) % FSID_SPAN;
        }
        used.insert(FSID_BASE + off);
        out.insert(share.clone(), FSID_BASE + off);
    }
    out
}

/// Unraid's flash GUID: hex groups joined by `-` (`0781-5571-...`).
pub(crate) fn valid_guid(g: &str) -> bool {
    (9..=64).contains(&g.len())
        && g.contains('-')
        && g.split('-')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn flash_guid(var_ini: &Path) -> Result<String> {
    let text =
        fs::read_to_string(var_ini).map_err(|e| anyhow!("read {}: {e}", var_ini.display()))?;
    let guid = share_cache::parse_ini(&text)
        .into_iter()
        .find_map(|(_, kv)| kv.get("flashGUID").cloned())
        .filter(|g| !g.is_empty())
        .ok_or_else(|| anyhow!("no flashGUID in {}", var_ini.display()))?;
    if !valid_guid(&guid) {
        bail!(
            "flashGUID in {} is malformed (expected hex groups joined by '-')",
            var_ini.display()
        );
    }
    Ok(guid)
}

pub(crate) fn server_key(secret: &str, guid: &str) -> String {
    let mut msg = SERVER_KEY_CONTEXT.to_vec();
    msg.extend_from_slice(guid.as_bytes());
    hash::hex_encode(&hmac_sha256(secret.as_bytes(), &msg)[..16])
}

/// The per-install HMAC secret, generated from the kernel CSPRNG on first use
/// and kept in orca's secrets store.
pub(crate) fn install_secret(urandom: &Path) -> Result<String> {
    let name = secrets::scoped_name("unraid", SECRET_INSTANCE, SERVER_KEY_SECRET);
    if let Some(s) = secrets::get(&name)?.filter(|s| !s.is_empty()) {
        return Ok(s);
    }
    use std::io::Read;
    let mut buf = [0u8; 32];
    fs::File::open(urandom)
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| anyhow!("read {}: {e}", urandom.display()))?;
    let secret = hash::hex_encode(&buf);
    secrets::set(&name, &secret, Some("unraid NFS serverKey HMAC secret"))?;
    Ok(secret)
}

pub(crate) fn shows_clients(ctx: &ToolCtx) -> bool {
    ctx.caller()
        .is_some_and(|c| CLIENT_ROLES.contains(&c.role.as_str()))
}

/// An `rmtab` line, `client:path:0xcount`, split from the right so an IPv6
/// client keeps its colons. `None` for malformed lines and count 0 (unmounted).
pub(crate) fn rmtab_entry(line: &str) -> Option<(&str, &str)> {
    let mut it = line.trim().rsplitn(3, ':');
    let (count, path, client) = (it.next()?, it.next()?, it.next()?);
    let n = u32::from_str_radix(count.trim_start_matches("0x"), 16).ok()?;
    (n > 0 && !client.is_empty() && path.starts_with('/')).then_some((client, path))
}

/// Host part of an nfsd `address:` value: `"10.0.0.5:801"` or `"[fe80::1]:801"`.
pub(crate) fn v4_host(addr: &str) -> &str {
    let a = addr.trim().trim_matches('"');
    match a.strip_prefix('[') {
        Some(r) => r.split_once(']').map_or(r, |(h, _)| h),
        None => a.rsplit_once(':').map_or(a, |(h, _)| h),
    }
}

fn under(path: &str, export: &str) -> bool {
    path == export
        || path
            .strip_prefix(export)
            .is_some_and(|r| r.starts_with('/'))
}

struct Mounts {
    v3: Vec<(String, String)>,
    v4: Vec<String>,
    unknown: String,
}

fn mounts(rmtab: &Path, nfsd_clients: &Path) -> Mounts {
    let mut v3 = Vec::new();
    let mut unknown = Vec::new();
    match fs::read_to_string(rmtab) {
        Ok(text) => {
            for (c, p) in text.lines().filter_map(rmtab_entry) {
                v3.push((c.to_string(), p.to_string()));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => unknown.push(format!("read {}: {e}", rmtab.display())),
    }
    let mut v4 = Vec::new();
    match fs::read_dir(nfsd_clients) {
        Ok(dir) => {
            for d in dir.flatten() {
                let info = d.path().join("info");
                match fs::read_to_string(&info) {
                    Ok(t) => {
                        if let Some(a) = t.lines().find_map(|l| l.strip_prefix("address:")) {
                            v4.push(format!("nfsv4:{}", v4_host(a)));
                        }
                    }
                    Err(e) => unknown.push(format!("read {}: {e}", info.display())),
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => unknown.push(format!("read {}: {e}", nfsd_clients.display())),
    }
    v4.sort();
    v4.dedup();
    Mounts {
        v3,
        v4,
        unknown: unknown.join("; "),
    }
}

fn share_of(path: &str) -> Option<String> {
    path.strip_prefix(USER_SHARE_PREFIX)
        .filter(|s| !s.is_empty() && !s.contains('/'))
        .map(str::to_string)
}

pub(crate) fn report_in(p: &Paths, secret: &str, show_clients: bool) -> Result<FsidReport> {
    let server_key = server_key(secret, &flash_guid(&p.var_ini)?);
    let text =
        fs::read_to_string(&p.exports).map_err(|e| anyhow!("read {}: {e}", p.exports.display()))?;
    let parsed: Vec<_> = text
        .lines()
        .filter_map(crate::nfs_hygiene::parse_line)
        .collect();
    let current: BTreeMap<String, Option<u32>> = parsed
        .iter()
        .filter_map(|e| Some((share_of(&e.path)?, e.fsid.as_deref()?.parse().ok())))
        .chain(
            parsed
                .iter()
                .filter(|e| e.fsid.is_none())
                .filter_map(|e| Some((share_of(&e.path)?, None))),
        )
        .collect();
    let reserved: BTreeSet<u32> = parsed
        .iter()
        .filter(|e| match share_of(&e.path) {
            None => true,
            Some(s) => current.get(&s).copied().flatten() == Some(hashed_fsid(&server_key, &s)),
        })
        .filter_map(|e| e.fsid.as_deref()?.parse().ok())
        .collect();
    let plan = plan_fsids(&server_key, &current, &reserved);
    let m = mounts(&p.rmtab, &p.nfsd_clients);
    let mut by_fsid: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let exports = parsed
        .iter()
        .map(|e| {
            let fsid = e.fsid.clone().unwrap_or_default();
            if !fsid.is_empty() {
                by_fsid
                    .entry(fsid.clone())
                    .or_default()
                    .push(e.path.clone());
            }
            let share = share_of(&e.path).unwrap_or_default();
            let mut mounted_by: Vec<String> = Vec::new();
            for (c, _) in m.v3.iter().filter(|(_, mp)| under(mp, &e.path)) {
                if !mounted_by.contains(c) {
                    mounted_by.push(c.clone());
                }
            }
            mounted_by.extend(m.v4.iter().cloned());
            let mount_count = mounted_by.len() as u32;
            if !show_clients {
                mounted_by.clear();
            }
            FsidExport {
                planned_fsid: plan.get(&share).map(u32::to_string).unwrap_or_default(),
                path: e.path.clone(),
                share,
                fsid,
                mounted_by,
                mount_count,
            }
        })
        .collect();
    let duplicates = by_fsid
        .into_iter()
        .filter(|(_, p)| p.len() > 1)
        .map(|(fsid, paths)| FsidDuplicate { fsid, paths })
        .collect();
    Ok(FsidReport {
        server_key,
        exports,
        duplicates,
        mounts_unknown: m.unknown,
    })
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidNfsFsidsArgs {}

/// Report this host's NFS fsids, duplicates among them, the planned fsid for
/// each user share, and which clients hold mounts.
#[orca_tool(domain = "unraid", verb = "nfs.fsids", role = "read")]
async fn unraid_nfs_fsids(_args: UnraidNfsFsidsArgs, ctx: &ToolCtx) -> Result<FsidReport> {
    let secret = install_secret(Path::new(URANDOM))?;
    let show = shows_clients(ctx);
    tokio::task::spawn_blocking(move || report_in(&Paths::live(), &secret, show)).await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeRoot;

    const EXPORTS: &str = "\
\"/mnt/user/backups\" -fsid=106,async,no_subtree_check 10.0.0.0/24(rw)
\"/mnt/user/pbs\" -fsid=106,async,no_subtree_check 10.0.0.17(rw,no_root_squash)
\"/mnt/user/My Media\" -fsid=103,async 10.0.0.0/24(rw)
/mnt/disk1 10.0.0.0/24(rw,fsid=1)
";

    fn fake(rmtab: &str) -> FakeRoot {
        let f = FakeRoot::new("nfsfsid");
        f.write("exports", EXPORTS)
            .write("var.ini", "flashGUID=\"0781-5571-AAAA\"\n")
            .write("rmtab", rmtab);
        f
    }

    fn paths(f: &FakeRoot) -> Paths {
        Paths {
            exports: f.path().join("exports"),
            var_ini: f.path().join("var.ini"),
            rmtab: f.path().join("rmtab"),
            nfsd_clients: f.path().join("clients"),
        }
    }

    const SECRET: &str = "test-secret";

    fn report(f: &FakeRoot) -> Result<FsidReport> {
        report_in(&paths(f), SECRET, true)
    }

    fn export(r: &FsidReport, path: &str) -> FsidExport {
        r.exports.iter().find(|e| e.path == path).unwrap().clone()
    }

    fn cur(v: &[(&str, Option<u32>)]) -> BTreeMap<String, Option<u32>> {
        v.iter().map(|(s, f)| (s.to_string(), *f)).collect()
    }

    #[test]
    fn fnv1a_golden_vectors() {
        assert_eq!(fnv1a(""), 0x811c_9dc5);
        assert_eq!(fnv1a("a"), 0xe40c_292c);
        assert_eq!(fnv1a("foobar"), 0xbf9c_f968);
    }

    #[test]
    fn hmac_sha256_matches_rfc4231() {
        let out = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hash::hex_encode(&out),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        let long = hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            hash::hex_encode(&long),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn server_key_is_stable_per_secret_and_hides_the_guid() {
        let g = "0781-5571-AAAA";
        let a = server_key("s1", g);
        assert_eq!(a, server_key("s1", g));
        assert_eq!(a.len(), 32);
        assert_ne!(a, server_key("s2", g));
        assert_ne!(a, server_key("s1", "0781-5571-BBBB"));
        assert!(!a.to_lowercase().contains("0781") && !a.contains("5571"));
        assert!(!a.to_lowercase().contains("aaaa"));
    }

    #[test]
    fn malformed_guid_is_rejected() {
        assert!(valid_guid("0781-5571-AAAA-1234567890AB"));
        for bad in ["", "07815571", "0781--5571", "0781-55Z1-AAAA", "-0781-5571"] {
            assert!(!valid_guid(bad), "{bad}");
        }
        let f = fake("");
        f.write("var.ini", "flashGUID=\"../etc\"\n");
        let err = report(&f).unwrap_err().to_string();
        assert!(err.contains("malformed"), "{err}");
    }

    #[test]
    fn install_secret_is_generated_once_and_reused() {
        use crate::test_support::{Store, with_store};
        use std::cell::RefCell;
        use std::rc::Rc;
        let f = FakeRoot::new("nfsfsid-rand");
        f.write("urandom", &"x".repeat(64));
        let store = Rc::new(RefCell::new(Store::default()));
        let (a, b) = with_store(&store, || {
            let a = install_secret(&f.path().join("urandom")).unwrap();
            f.write("urandom", &"y".repeat(64));
            (a, install_secret(&f.path().join("urandom")).unwrap())
        });
        assert_eq!(a, b);
        assert_eq!(a, hash::hex_encode(&[b'x'; 32]));
        assert_eq!(
            store
                .borrow()
                .secrets
                .get("unraid.local.nfs_server_key_secret"),
            Some(&a)
        );
    }

    #[test]
    fn plan_golden_vectors() {
        let plan = plan_fsids(
            "k",
            &cur(&[("backups", None), ("pbs", None)]),
            &BTreeSet::new(),
        );
        assert_eq!(plan["backups"], hashed_fsid("k", "backups"));
        assert_eq!(plan["pbs"], hashed_fsid("k", "pbs"));
        assert_eq!(
            hashed_fsid("k", "pbs"),
            FSID_BASE + fnv1a("k/pbs") % FSID_SPAN
        );
        assert_eq!(fnv1a("k/pbs"), 0x4811_3b5a);
        assert_eq!(plan["pbs"], 135_348_034);
    }

    #[test]
    fn duplicates_are_reported_with_a_hashed_server_key() {
        let f = fake("");
        let r = report(&f).unwrap();
        assert_eq!(r.server_key, server_key(SECRET, "0781-5571-AAAA"));
        assert_eq!(
            r.duplicates,
            vec![FsidDuplicate {
                fsid: "106".into(),
                paths: vec!["/mnt/user/backups".into(), "/mnt/user/pbs".into()],
            }]
        );
        assert_eq!(export(&r, "/mnt/disk1").planned_fsid, "");
        assert!(r.mounts_unknown.is_empty());
    }

    #[test]
    fn share_names_with_spaces_are_planned() {
        let f = fake("");
        let r = report(&f).unwrap();
        let e = export(&r, "/mnt/user/My Media");
        assert_eq!(e.share, "My Media");
        assert_eq!(e.fsid, "103");
        assert_eq!(
            e.planned_fsid,
            hashed_fsid(&r.server_key, "My Media").to_string()
        );
    }

    #[test]
    fn plan_differs_per_server_and_is_unique() {
        let c = cur(&[
            ("backups", Some(106)),
            ("data", Some(102)),
            ("pbs", Some(106)),
        ]);
        let none = BTreeSet::new();
        let a = plan_fsids("willow", &c, &none);
        assert_eq!(a, plan_fsids("willow", &c, &none));
        assert_ne!(a, plan_fsids("maple", &c, &none));
        assert_eq!(a.values().collect::<BTreeSet<_>>().len(), 3);
    }

    #[test]
    fn shares_at_their_hash_stay_fixed_and_others_step() {
        let h = hashed_fsid("k", "pbs");
        let c = cur(&[("pbs", Some(h)), ("aaa", None)]);
        let reserved: BTreeSet<u32> = [h].into();
        let mut plan = plan_fsids("k", &c, &reserved);
        assert_eq!(plan["pbs"], h);
        let new_share_hash = hashed_fsid("k", "aaa");
        assert_eq!(plan.remove("aaa"), Some(new_share_hash));

        let squatter = cur(&[("pbs", Some(h)), ("zzz", None)]);
        let plan = plan_fsids("k", &squatter, &[h].into());
        assert_eq!(plan["pbs"], h);
        assert_ne!(plan["zzz"], h);

        let disk: BTreeSet<u32> = [hashed_fsid("k", "zzz")].into();
        let plan = plan_fsids("k", &cur(&[("zzz", None)]), &disk);
        assert_eq!(plan["zzz"], hashed_fsid("k", "zzz") + 1);
    }

    #[test]
    fn plan_is_stable_once_applied() {
        let f = fake("");
        let r = report(&f).unwrap();
        let mut applied = EXPORTS.to_string();
        for e in r.exports.iter().filter(|e| !e.share.is_empty()) {
            applied = applied.replace(
                &format!("\"{}\" -fsid={},", e.path, e.fsid),
                &format!("\"{}\" -fsid={},", e.path, e.planned_fsid),
            );
        }
        f.write("exports", &applied);
        let again = report(&f).unwrap();
        assert!(again.duplicates.is_empty());
        assert!(
            again
                .exports
                .iter()
                .all(|e| e.fsid == e.planned_fsid || e.share.is_empty())
        );
    }

    #[test]
    fn rmtab_ipv6_and_subdir_mounts_attribute_to_the_export() {
        let f = fake(
            "fd00::17:/mnt/user/pbs:0x00000001\n\
             10.0.0.9:/mnt/user/backups/host1:0x00000002\n\
             10.0.0.8:/mnt/user/backupsX:0x00000001\n\
             10.0.0.7:/mnt/user/backups:0x00000000\n",
        );
        let r = report(&f).unwrap();
        assert_eq!(export(&r, "/mnt/user/pbs").mounted_by, vec!["fd00::17"]);
        assert_eq!(export(&r, "/mnt/user/backups").mounted_by, vec!["10.0.0.9"]);
        assert!(export(&r, "/mnt/user/My Media").mounted_by.is_empty());
    }

    #[test]
    fn rmtab_entries_parse_from_the_right() {
        assert_eq!(
            rmtab_entry("fe80::1:/mnt/user/a:0x00000001"),
            Some(("fe80::1", "/mnt/user/a"))
        );
        assert_eq!(rmtab_entry("h:/mnt/user/a:0x00000000"), None);
        assert_eq!(rmtab_entry("garbage"), None);
    }

    #[test]
    fn nfsv4_addresses_drop_port_and_brackets() {
        assert_eq!(v4_host("\"10.0.0.5:801\""), "10.0.0.5");
        assert_eq!(v4_host("\"[fd00::5]:801\""), "fd00::5");
        let f = fake("");
        f.write(
            "clients/7/info",
            "clientid: 0x1\naddress: \"[fd00::5]:801\"\n",
        )
        .write("clients/8/info", "address: \"10.0.0.5:900\"\n");
        let r = report(&f).unwrap();
        assert_eq!(
            export(&r, "/mnt/user/pbs").mounted_by,
            vec!["nfsv4:10.0.0.5", "nfsv4:fd00::5"]
        );
    }

    #[test]
    fn unreadable_mount_tables_are_reported() {
        let f = FakeRoot::new("nfsfsid-unknown");
        f.write("exports", EXPORTS)
            .write("var.ini", "flashGUID=\"0781-5571-CCCC\"\n")
            .mkdir("rmtab");
        let r = report(&f).unwrap();
        assert!(r.mounts_unknown.contains("rmtab"), "{}", r.mounts_unknown);
    }

    #[test]
    fn tool_is_registered_with_read_role() {
        assert_eq!(
            plugin_toolkit::dispatch::required_role("unraid.nfs.fsids"),
            Some("read")
        );
        assert!(!plugin_toolkit::dispatch::data_mutation_names().contains(&"unraid.nfs.fsids"));
    }

    #[test]
    fn read_callers_get_counts_and_users_get_clients() {
        let f = fake("10.0.0.17:/mnt/user/pbs:0x00000001\n");
        let pbs = |show| {
            export(
                &report_in(&paths(&f), SECRET, show).unwrap(),
                "/mnt/user/pbs",
            )
        };
        let hidden = pbs(false);
        assert!(hidden.mounted_by.is_empty());
        assert_eq!(hidden.mount_count, 1);
        let shown = pbs(true);
        assert_eq!(shown.mounted_by, vec!["10.0.0.17"]);
        assert_eq!(shown.mount_count, 1);
        let ctx = |r| crate::authz::test_ctx(r);
        assert!(!shows_clients(&ctx(Some("read"))));
        assert!(!shows_clients(&ctx(None)));
        assert!(shows_clients(&ctx(Some("user"))));
        assert!(shows_clients(&ctx(Some("admin"))));
    }
}
