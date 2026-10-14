//! `unraid.share.cache` / `unraid.share.cache.set` — per-share cache tiering:
//! `shareUseCache`, `shareCachePool` and `shareFloor`.
//!
//! The GraphQL `Share` type carries only a `cache` boolean and `floor`, with no
//! cache mode or pool, and the API has no share mutation. Reads therefore come
//! from emhttp's world-readable `shares.ini` (the settings emhttp loaded), and
//! writes edit the root-only `/boot/config/shares/<name>.cfg` as
//! [`PrivilegedOp::SetShareCache`], which re-validates everything.
//!
//! emhttp applies a share cfg when it loads it (array start, or a share edit in
//! the web UI), so a write persists immediately but takes effect on the next
//! load; the output says so rather than claiming a live change.
//!
//! Dry-run by default, admin required for both (see [`crate::authz`]).

use std::collections::BTreeMap;
use std::path::Path;

use plugin_toolkit::prelude::*;

use crate::authz::require_admin;
use crate::docker_adopt::privileged::{self, PrivilegedOp};
use crate::docker_adopt::safefs;
use crate::exports::UnraidExports;
use crate::smb_share_write::validate_share_name;

/// emhttp's per-share state, one `["name"]` section per user share.
pub(crate) const SHARES_INI: &str = "/var/local/emhttp/shares.ini";
const USE_CACHE_MODES: &[&str] = &["no", "yes", "only", "prefer"];
const PENDING: &str = "persisted; emhttp applies it on the next array start or share edit";

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

/// Parse `shares.ini`: `["name"]` headers, then `key="value"` lines.
pub(crate) fn parse_shares_ini(text: &str) -> Vec<ShareCache> {
    let mut out: Vec<ShareCache> = Vec::new();
    let mut cur: Option<(String, BTreeMap<String, String>)> = None;
    let mut flush = |cur: Option<(String, BTreeMap<String, String>)>| {
        if let Some((share, kv)) = cur {
            let get = |k: &str| kv.get(k).cloned().unwrap_or_default();
            out.push(ShareCache {
                share,
                use_cache: get("useCache"),
                cache_pool: get("cachePool"),
                floor: get("floor"),
            });
        }
    };
    for line in text.lines() {
        let t = line.trim();
        if let Some(name) = t.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            flush(cur.take());
            cur = Some((name.trim_matches('"').to_string(), BTreeMap::new()));
        } else if let (Some((_, kv)), Some((k, v))) = (cur.as_mut(), t.split_once('=')) {
            kv.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    flush(cur);
    out
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

/// Apply `req` to the share cfg at `cfg`, keeping every other key and the
/// file's mode. Returns the keys written.
pub(crate) fn apply_in(cfg: &Path, req: &ShareCacheRequest) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;
    let old = safefs::read_file(cfg)?
        .ok_or_else(|| anyhow!("share '{}' has no config at {}", req.share, cfg.display()))?;
    let updates = req.cfg_updates();
    let new = UnraidExports::write_cfg_keys(&String::from_utf8_lossy(&old), &updates);
    let mode = std::fs::symlink_metadata(cfg)
        .map_err(|e| anyhow!("stat {}: {e}", cfg.display()))?
        .permissions()
        .mode()
        & 0o7777;
    safefs::replace_file(cfg, new.as_bytes(), mode)?;
    Ok(updates
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; "))
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
    /// Apply the change. Without it the call only reports what it would do.
    #[arg(long, default_value_t = false)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ShareCacheSetOutput {
    /// The share's settings as emhttp currently has them.
    pub current: ShareCache,
    /// The cfg keys written (or that would be).
    pub changes: Vec<String>,
    /// The root side's report; empty for a dry run.
    pub applied: String,
    /// When the change takes effect.
    pub effective: String,
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

/// Set a share's cache mode, pool and/or floor. Dry-run unless `execute:
/// true`; admin is required for both.
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
    let applied = if args.execute {
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
        effective: PENDING.to_string(),
        executed: args.execute,
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
            execute: false,
        }
    }

    fn fake() -> FakeRoot {
        let f = FakeRoot::new("sharecache");
        f.write("shares.ini", INI).write(
            "shares/pbs.cfg",
            "shareComment=\"x\"\nshareUseCache=\"no\"\n",
        );
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

    #[test]
    fn apply_writes_only_the_given_keys_and_keeps_the_rest() {
        use std::os::unix::fs::PermissionsExt;
        let f = fake();
        let cfg = f.path().join("shares/pbs.cfg");
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o600)).unwrap();
        let req =
            ShareCacheRequest::new("pbs", Some("yes"), Some("cache"), Some(104_857_600)).unwrap();
        let out = apply_in(&cfg, &req).unwrap();
        assert!(out.contains("shareFloor=104857600"), "{out}");
        let text = fs::read_to_string(&cfg).unwrap();
        assert!(text.contains("shareComment=\"x\""));
        assert!(text.contains("shareUseCache=\"yes\""));
        assert!(!text.contains("shareUseCache=\"no\""));
        assert!(text.contains("shareCachePool=\"cache\""));
        assert!(text.contains("shareFloor=\"104857600\""));
        assert_eq!(
            fs::metadata(&cfg).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[test]
    fn apply_refuses_a_share_without_a_cfg() {
        let f = fake();
        let req = ShareCacheRequest::new("media", None, None, Some(1)).unwrap();
        let e = apply_in(&f.path().join("shares/media.cfg"), &req).unwrap_err();
        assert!(e.to_string().contains("has no config"), "{e}");
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
