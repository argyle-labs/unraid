//! `unraid.share.cache` / `unraid.share.cache.set` — per-share cache tiering:
//! `shareUseCache`, `shareCachePool` and `shareFloor`.
//!
//! The GraphQL `Share` type carries only a `cache` boolean and `floor`, with no
//! cache mode or pool, and the API has no share mutation. Reads therefore come
//! from emhttp's world-readable `shares.ini` (the settings emhttp loaded).
//! Writes go through emhttp itself, as [`PrivilegedOp::SetShareCache`]: the
//! same `cmdEditShare` request the web UI's Share settings page sends to
//! `/update.htm`, over emhttpd's local socket the way Unraid's `emcmd` does.
//! emhttp then writes the share cfg and applies it live. Editing the cfg file
//! directly instead would be overwritten by emhttp's in-memory copy on its
//! next share save.
//!
//! `cmdEditShare` sets every share field it is given, so the request carries
//! the share's current values from `shares.ini` with only the changed ones
//! replaced; the result is read back from `shares.ini` to verify.
//!
//! Executes by default; `dryRun: true` only reports. Admin is required for
//! both (see [`crate::authz`]).

use std::collections::BTreeMap;
use std::path::Path;

use plugin_toolkit::prelude::*;

use crate::authz::require_admin;
use crate::docker_adopt::privileged::{self, PrivilegedOp};
use crate::smb_share_write::validate_share_name;

/// emhttp's per-share state, one `["name"]` section per user share.
pub(crate) const SHARES_INI: &str = "/var/local/emhttp/shares.ini";
const USE_CACHE_MODES: &[&str] = &["no", "yes", "only", "prefer"];
const VAR_INI: &str = "/var/local/emhttp/var.ini";
const EMHTTPD_SOCKET: &str = "/var/run/emhttpd.socket";
/// The Share settings form's fields, paired with their `shares.ini` keys:
/// the inputs unraid/webgui `emhttp/plugins/dynamix/ShareEdit.page` submits
/// for an existing share (`shareCOW` is disabled there, so never sent).
const EDIT_FIELDS: &[(&str, &str)] = &[
    ("shareName", "name"),
    ("shareNameOrig", "name"),
    ("shareComment", "comment"),
    ("shareAllocator", "allocator"),
    ("shareFloor", "floor"),
    ("shareSplitLevel", "splitLevel"),
    ("shareInclude", "include"),
    ("shareExclude", "exclude"),
    ("shareUseCache", "useCache"),
    ("shareCachePool", "cachePool"),
    ("shareCachePool2", "cachePool2"),
];

#[orca_struct]
#[derive(Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ShareCache {
    pub share: String,
    /// no | yes | only | prefer.
    pub use_cache: String,
    pub cache_pool: String,
    /// Minimum free space, in KiB, before a disk stops receiving new files.
    pub floor: String,
}

type Sections = Vec<(String, BTreeMap<String, String>)>;

/// Parse an emhttp ini: optional `["name"]` headers, then `key="value"` lines.
/// Keys before any header land in a section named "".
fn parse_ini(text: &str) -> Sections {
    let mut out: Sections = vec![(String::new(), BTreeMap::new())];
    for line in text.lines() {
        let t = line.trim();
        if let Some(name) = t.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            out.push((name.trim_matches('"').to_string(), BTreeMap::new()));
        } else if let Some((k, v)) = t.split_once('=') {
            let kv = &mut out.last_mut().expect("non-empty").1;
            kv.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    out
}

fn to_share(share: &str, kv: &BTreeMap<String, String>) -> ShareCache {
    let get = |k: &str| kv.get(k).cloned().unwrap_or_default();
    ShareCache {
        share: share.to_string(),
        use_cache: get("useCache"),
        cache_pool: get("cachePool"),
        floor: get("floor"),
    }
}

pub(crate) fn parse_shares_ini(text: &str) -> Vec<ShareCache> {
    parse_ini(text)
        .iter()
        .skip(1)
        .map(|(s, kv)| to_share(s, kv))
        .collect()
}

fn read_shares(ini: &Path) -> Result<Vec<ShareCache>> {
    let text = std::fs::read_to_string(ini).map_err(|e| anyhow!("read {}: {e}", ini.display()))?;
    Ok(parse_shares_ini(&text))
}

/// Pool names as Unraid accepts them: a lowercase letter, then lowercase
/// letters, digits or '_'.
fn validate_pool(p: &str) -> Result<()> {
    let ok = p.len() <= 40
        && p.bytes().next().is_some_and(|c| c.is_ascii_lowercase())
        && p.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_');
    if !ok {
        bail!("invalid cache pool '{p}'");
    }
    Ok(())
}

/// One validated change; built identically on both sides of the privilege
/// boundary. `None` fields are left as they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShareCacheRequest {
    pub share: String,
    pub use_cache: Option<String>,
    pub cache_pool: Option<String>,
    pub floor_kib: Option<u64>,
}

impl ShareCacheRequest {
    pub fn new(
        share: &str,
        use_cache: Option<&str>,
        cache_pool: Option<&str>,
        floor_kib: Option<u64>,
    ) -> Result<Self> {
        validate_share_name(share)?;
        if use_cache.is_none() && cache_pool.is_none() && floor_kib.is_none() {
            bail!("nothing to set: give useCache, cachePool and/or floorKib");
        }
        if let Some(m) = use_cache
            && !USE_CACHE_MODES.contains(&m)
        {
            bail!(
                "invalid useCache '{m}' (expected one of {})",
                USE_CACHE_MODES.join(", ")
            );
        }
        if let Some(p) = cache_pool {
            validate_pool(p)?;
        }
        Ok(Self {
            share: share.to_string(),
            use_cache: use_cache.map(str::to_string),
            cache_pool: cache_pool.map(str::to_string),
            floor_kib,
        })
    }

    fn cfg_updates(&self) -> Vec<(&'static str, String)> {
        let mut v = Vec::new();
        if let Some(m) = &self.use_cache {
            v.push(("shareUseCache", m.clone()));
        }
        if let Some(p) = &self.cache_pool {
            v.push(("shareCachePool", p.clone()));
        }
        if let Some(f) = self.floor_kib {
            v.push(("shareFloor", f.to_string()));
        }
        v
    }
}

fn urlencode(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The `/update.htm` query for `req`: every form field at its current value,
/// the requested ones replaced.
fn edit_query(current: &BTreeMap<String, String>, req: &ShareCacheRequest, csrf: &str) -> String {
    let updates = req.cfg_updates();
    let mut q: Vec<String> = EDIT_FIELDS
        .iter()
        .map(|(field, key)| {
            let v = updates
                .iter()
                .find(|(f, _)| f == field)
                .map(|(_, v)| v.clone())
                .or_else(|| current.get(*key).cloned())
                .unwrap_or_default();
            format!("{field}={}", urlencode(&v))
        })
        .collect();
    q.push("cmdEditShare=Apply".into());
    q.push(format!("csrf_token={}", urlencode(csrf)));
    q.join("&")
}

/// Send one GET to emhttpd's unix socket, as `emcmd` does with curl.
fn emhttp_get(socket: &Path, query: &str) -> Result<()> {
    use std::io::{Read, Write};
    let mut s = std::os::unix::net::UnixStream::connect(socket)
        .map_err(|e| anyhow!("connect {}: {e}", socket.display()))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    write!(
        s,
        "GET /update.htm?{query} HTTP/1.0\r\nHost: localhost\r\n\r\n"
    )?;
    let mut resp = String::new();
    s.read_to_string(&mut resp)?;
    let status = resp.lines().next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        bail!("emhttp update.htm: {status:?}");
    }
    Ok(())
}

/// Apply `req` through emhttp, then confirm it in `shares.ini`. Returns the
/// fields changed.
pub(crate) fn apply_in(
    ini: &Path,
    var_ini: &Path,
    socket: &Path,
    req: &ShareCacheRequest,
) -> Result<String> {
    let read =
        |p: &Path| std::fs::read_to_string(p).map_err(|e| anyhow!("read {}: {e}", p.display()));
    let sections = parse_ini(&read(ini)?);
    let current = sections
        .iter()
        .skip(1)
        .find(|(s, _)| *s == req.share)
        .map(|(_, kv)| kv)
        .ok_or_else(|| anyhow!("no share '{}' in {}", req.share, ini.display()))?;
    let csrf = parse_ini(&read(var_ini)?)
        .into_iter()
        .find_map(|(_, kv)| kv.get("csrf_token").cloned())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| anyhow!("no csrf_token in {}", var_ini.display()))?;
    emhttp_get(socket, &edit_query(current, req, &csrf))?;

    let before = current.clone();
    let after = parse_ini(&read(ini)?)
        .into_iter()
        .skip(1)
        .find(|(s, _)| *s == req.share)
        .map(|(_, kv)| kv)
        .unwrap_or_default();
    check_read_back(&before, &after, req)?;
    Ok(req
        .cfg_updates()
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; "))
}

/// Require the requested keys at their new values and every other key of
/// the share unchanged, so a field missing from [`EDIT_FIELDS`] (reset by
/// emhttp) is caught rather than silently clobbering a setting.
fn check_read_back(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
    req: &ShareCacheRequest,
) -> Result<()> {
    let wanted: BTreeMap<&str, String> = req
        .cfg_updates()
        .into_iter()
        .filter_map(|(f, v)| {
            EDIT_FIELDS
                .iter()
                .find(|(field, _)| *field == f)
                .map(|(_, k)| (*k, v))
        })
        .collect();
    let mut problems = Vec::new();
    for (k, v) in &wanted {
        let got = after.get(*k).map(String::as_str);
        if got != Some(v.as_str()) {
            problems.push(format!("{k}: wanted {v:?}, got {got:?}"));
        }
    }
    let keys: std::collections::BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    for k in keys {
        if wanted.contains_key(k.as_str()) {
            continue;
        }
        let (b, a) = (before.get(k), after.get(k));
        if b != a {
            problems.push(format!("{k} changed unexpectedly: {b:?} -> {a:?}"));
        }
    }
    if !problems.is_empty() {
        bail!(
            "emhttp did not apply the change cleanly: {}",
            problems.join("; ")
        );
    }
    Ok(())
}

pub(crate) fn apply(req: &ShareCacheRequest) -> Result<String> {
    apply_in(
        Path::new(SHARES_INI),
        Path::new(VAR_INI),
        Path::new(EMHTTPD_SOCKET),
        req,
    )
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidShareCacheArgs {
    /// Only this share; all shares when omitted.
    #[arg(long)]
    #[serde(default)]
    pub share: Option<String>,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ShareCacheOutput {
    pub shares: Vec<ShareCache>,
}

pub(crate) fn list_in(ini: &Path, share: Option<&str>) -> Result<Vec<ShareCache>> {
    let all = read_shares(ini)?;
    match share {
        None => Ok(all),
        Some(s) => {
            let one: Vec<_> = all.into_iter().filter(|c| c.share == s).collect();
            if one.is_empty() {
                bail!("no share '{s}' in {}", ini.display());
            }
            Ok(one)
        }
    }
}

/// Report each share's cache mode, pool and floor.
#[orca_tool(domain = "unraid", verb = "share.cache")]
async fn unraid_share_cache(
    args: UnraidShareCacheArgs,
    _ctx: &ToolCtx,
) -> Result<ShareCacheOutput> {
    Ok(ShareCacheOutput {
        shares: list_in(Path::new(SHARES_INI), args.share.as_deref())?,
    })
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct UnraidShareCacheSetArgs {
    /// User share name (`/mnt/user/<share>`).
    #[arg(long)]
    pub share: String,
    /// no | yes | only | prefer.
    #[arg(long)]
    #[serde(default)]
    pub use_cache: Option<String>,
    /// Pool the share caches to.
    #[arg(long)]
    #[serde(default)]
    pub cache_pool: Option<String>,
    /// Minimum free space in KiB.
    #[arg(long)]
    #[serde(default)]
    pub floor_kib: Option<u64>,
    /// Only report what would change.
    #[arg(long, default_value_t = false)]
    #[serde(default)]
    pub dry_run: bool,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ShareCacheSetOutput {
    /// The share's settings as emhttp currently has them.
    pub current: ShareCache,
    /// The fields set (or that would be).
    pub changes: Vec<String>,
    /// The root side's report, verified against `shares.ini`; empty for a dry run.
    pub applied: String,
    pub executed: bool,
}

pub(crate) fn op_for(args: &UnraidShareCacheSetArgs) -> Result<(ShareCacheRequest, PrivilegedOp)> {
    let req = ShareCacheRequest::new(
        &args.share,
        args.use_cache.as_deref(),
        args.cache_pool.as_deref(),
        args.floor_kib,
    )?;
    let op = PrivilegedOp::SetShareCache {
        share: args.share.clone(),
        use_cache: args.use_cache.clone(),
        cache_pool: args.cache_pool.clone(),
        floor_kib: args.floor_kib,
    };
    Ok((req, op))
}

/// Validate `args` against the share as emhttp has it, so an unknown share or
/// a cached mode without a pool fails in the dry run.
pub(crate) fn plan_in(
    ini: &Path,
    args: &UnraidShareCacheSetArgs,
) -> Result<(ShareCache, ShareCacheRequest, PrivilegedOp)> {
    let (req, op) = op_for(args)?;
    let current = list_in(ini, Some(&req.share))?.remove(0);
    let mode = req.use_cache.as_deref().unwrap_or(&current.use_cache);
    let pool = req.cache_pool.as_deref().unwrap_or(&current.cache_pool);
    if mode != "no" && pool.is_empty() {
        bail!("useCache '{mode}' needs a cachePool");
    }
    Ok((current, req, op))
}

/// Set a share's cache mode, pool and/or floor, live through emhttp.
/// `dryRun: true` only reports; admin is required for both.
#[orca_tool(
    domain = "unraid",
    verb = "share.cache.set",
    role = "admin",
    data_mutation = true,
    execute_gated = false
)]
async fn unraid_share_cache_set(
    args: UnraidShareCacheSetArgs,
    ctx: &ToolCtx,
) -> Result<ShareCacheSetOutput> {
    require_admin("unraid.share.cache.set", ctx.caller().as_ref())?;
    let (current, req, op) = plan_in(Path::new(SHARES_INI), &args)?;
    let applied = if !args.dry_run {
        let runner =
            privileged::runner().ok_or_else(|| anyhow!(privileged::missing_runner_blocker()))?;
        runner.run(&op).await?
    } else {
        String::new()
    };
    Ok(ShareCacheSetOutput {
        current,
        changes: req
            .cfg_updates()
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect(),
        applied,
        executed: !args.dry_run,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeRoot;
    use std::fs;

    const INI: &str = "\
[\"appdata\"]
name=\"appdata\"
useCache=\"only\"
cachePool=\"cache\"
floor=\"0\"
[\"pbs\"]
name=\"pbs\"
useCache=\"no\"
cachePool=\"\"
floor=\"\"
";

    fn args(
        share: &str,
        mode: Option<&str>,
        pool: Option<&str>,
        floor: Option<u64>,
    ) -> UnraidShareCacheSetArgs {
        UnraidShareCacheSetArgs {
            share: share.into(),
            use_cache: mode.map(Into::into),
            cache_pool: pool.map(Into::into),
            floor_kib: floor,
            dry_run: true,
        }
    }

    fn fake() -> FakeRoot {
        let f = FakeRoot::new("sharecache");
        f.write("shares.ini", INI);
        f
    }

    #[test]
    fn parses_every_share_section() {
        let s = parse_shares_ini(INI);
        assert_eq!(s.len(), 2);
        assert_eq!(
            s[0],
            ShareCache {
                share: "appdata".into(),
                use_cache: "only".into(),
                cache_pool: "cache".into(),
                floor: "0".into(),
            }
        );
        assert_eq!(s[1].use_cache, "no");
        assert!(s[1].cache_pool.is_empty());
    }

    #[test]
    fn requests_are_validated() {
        let e = |m: Option<&str>, p: Option<&str>, f: Option<u64>| {
            ShareCacheRequest::new("pbs", m, p, f)
                .unwrap_err()
                .to_string()
        };
        assert!(e(None, None, None).contains("nothing to set"));
        assert!(e(Some("always"), None, None).contains("invalid useCache"));
        for bad in ["", "Cache", "1pool", "a-b", "a b"] {
            assert!(
                e(None, Some(bad), None).contains("invalid cache pool"),
                "{bad:?}"
            );
        }
        assert!(ShareCacheRequest::new("../x", None, None, Some(1)).is_err());
        assert!(ShareCacheRequest::new("pbs", Some("yes"), Some("nvme_2"), Some(0)).is_ok());
    }

    #[test]
    fn plan_refuses_unknown_share_and_cache_without_pool() {
        let f = fake();
        let ini = f.path().join("shares.ini");
        let e = plan_in(&ini, &args("media", None, None, Some(1)))
            .unwrap_err()
            .to_string();
        assert!(e.contains("no share 'media'"), "{e}");
        let e = plan_in(&ini, &args("pbs", Some("yes"), None, None))
            .unwrap_err()
            .to_string();
        assert!(e.contains("needs a cachePool"), "{e}");
        let (cur, req, _) = plan_in(&ini, &args("appdata", Some("prefer"), None, None)).unwrap();
        assert_eq!(cur.cache_pool, "cache");
        assert_eq!(
            req.cfg_updates(),
            vec![("shareUseCache", "prefer".to_string())]
        );
    }

    /// A fake emhttpd: records the request line and rewrites `shares.ini`
    /// with `after` before answering, as emhttp does on `cmdEditShare`.
    fn fake_emhttp(f: &FakeRoot, after: &'static str) -> std::thread::JoinHandle<String> {
        use std::io::{BufRead, BufReader, Write};
        let sock = f.path().join("emhttpd.sock");
        let ini = f.path().join("shares.ini");
        let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&s).read_line(&mut line).unwrap();
            fs::write(&ini, after).unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            line
        })
    }

    const FULL: &str = "\
[\"pbs\"]
name=\"pbs\"
comment=\"a b&c\"
allocator=\"highwater\"
floor=\"0\"
splitLevel=\"1\"
include=\"disk1\"
exclude=\"\"
useCache=\"no\"
cachePool=\"\"
cachePool2=\"\"
";

    #[test]
    fn apply_posts_every_field_and_verifies_the_read_back() {
        let f = fake();
        f.write("shares.ini", FULL)
            .write("var.ini", "csrf_token=\"TOK\"\n");
        let after = FULL
            .replace("useCache=\"no\"", "useCache=\"yes\"")
            .replace("cachePool=\"\"", "cachePool=\"cache\"");
        let srv = fake_emhttp(&f, after.leak());
        let req = ShareCacheRequest::new("pbs", Some("yes"), Some("cache"), None).unwrap();
        let p = f.path();
        let out = apply_in(
            &p.join("shares.ini"),
            &p.join("var.ini"),
            &p.join("emhttpd.sock"),
            &req,
        )
        .unwrap();
        assert_eq!(out, "shareUseCache=yes; shareCachePool=cache");
        let line = srv.join().unwrap();
        assert_eq!(
            line,
            "GET /update.htm?shareName=pbs&shareNameOrig=pbs&shareComment=a%20b%26c\
             &shareAllocator=highwater&shareFloor=0&shareSplitLevel=1&shareInclude=disk1\
             &shareExclude=&shareUseCache=yes&shareCachePool=cache&shareCachePool2=\
             &cmdEditShare=Apply&csrf_token=TOK HTTP/1.0\r\n"
        );
    }

    #[test]
    fn apply_fails_when_emhttp_did_not_change_shares_ini() {
        let f = fake();
        f.write("shares.ini", FULL)
            .write("var.ini", "csrf_token=\"TOK\"\n");
        let srv = fake_emhttp(&f, FULL);
        let req = ShareCacheRequest::new("pbs", None, None, Some(5)).unwrap();
        let p = f.path();
        let e = apply_in(
            &p.join("shares.ini"),
            &p.join("var.ini"),
            &p.join("emhttpd.sock"),
            &req,
        )
        .unwrap_err();
        srv.join().unwrap();
        assert!(e.to_string().contains("floor: wanted \"5\""), "{e}");
    }

    #[test]
    fn apply_fails_naming_an_unrelated_key_emhttp_reset() {
        let f = fake();
        f.write("shares.ini", FULL)
            .write("var.ini", "csrf_token=\"TOK\"\n");
        let after = FULL
            .replace("floor=\"0\"", "floor=\"5\"")
            .replace("comment=\"a b&c\"", "comment=\"\"");
        let srv = fake_emhttp(&f, after.leak());
        let req = ShareCacheRequest::new("pbs", None, None, Some(5)).unwrap();
        let p = f.path();
        let e = apply_in(
            &p.join("shares.ini"),
            &p.join("var.ini"),
            &p.join("emhttpd.sock"),
            &req,
        )
        .unwrap_err()
        .to_string();
        srv.join().unwrap();
        assert!(
            e.contains("comment changed unexpectedly: Some(\"a b&c\") -> Some(\"\")"),
            "{e}"
        );
        assert!(!e.contains("floor"), "{e}");
    }

    #[test]
    fn apply_refuses_unknown_share_or_missing_csrf() {
        let f = fake();
        f.write("var.ini", "csrf_token=\"\"\n");
        let p = f.path();
        let go = |share: &str| {
            let req = ShareCacheRequest::new(share, None, None, Some(1)).unwrap();
            apply_in(
                &p.join("shares.ini"),
                &p.join("var.ini"),
                &p.join("none.sock"),
                &req,
            )
            .unwrap_err()
            .to_string()
        };
        assert!(go("media").contains("no share 'media'"));
        assert!(go("pbs").contains("no csrf_token"));
    }

    #[test]
    fn op_round_trips_and_is_root_only() {
        let (_, op) = op_for(&args("pbs", None, None, Some(5))).unwrap();
        let v = plugin_toolkit::serde_json::to_value(&op).unwrap();
        assert_eq!(v["op"], "set_share_cache");
        assert_eq!(v["payload"]["floor_kib"], 5);
        let passwd = "orca:x:1000:100::/h:/bin/sh\n";
        let group = "docker:x:281:orca\n";
        assert!(privileged::authorize(&op, 0, passwd, group).is_ok());
        assert!(privileged::authorize(&op, 1000, passwd, group).is_err());
    }

    #[test]
    fn dry_run_requires_admin() {
        for role in [Some("user"), None] {
            let ctx = crate::authz::test_ctx(role);
            let e = plugin_toolkit::reactor::block_on(unraid_share_cache_set(
                args("pbs", None, None, Some(1)),
                &ctx,
            ))
            .unwrap_err();
            assert!(e.to_string().contains("unraid.share.cache.set: "), "{e}");
        }
    }
}
