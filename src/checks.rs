//! Detection + remediation for the Unraid conditions that make a UPS-triggered
//! shutdown hang and erase its own evidence.
//!
//! Background: an Unraid host can accept a UPS shutdown, tear down networking,
//! then wedge forever on the array unmount because the force-unmount safety net
//! (`shutdownTimeout`) is missing or too high — and since `/var/log/syslog` is
//! tmpfs, the power-cycle needed to recover erases the record of what hung.
//!
//! This provider runs **on the Unraid peer** (like raccoon reads local sysfs),
//! so host-local flash config (`/boot/config/*.cfg`) and `/proc` are read and
//! written directly. The GraphQL client is used only for array/docker/vm state
//! the API exposes. Everything is synchronous except the GraphQL check, whose
//! async work is driven on the toolkit's shared runtime; the core proxy runs the
//! whole op on a blocking pool.
//!
//! Config-writing repairs are `privileged: true`, `automatic: false`
//! (suggest-then-confirm) and idempotent — re-running a repair on an
//! already-correct config is a no-op that reports success. Report-only checks
//! (`array-unmount-blockers`, `unclean-shutdown`) carry no [`RepairSpec`].

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use plugin_toolkit::contract::diagnostics::{
    DiagnoseArgs, Finding, RepairArgs, RepairOutcome, RepairSpec, Severity,
};
use plugin_toolkit::reactor;
use plugin_toolkit::serde_json;

use crate::endpoint::{EndpointRow, endpoint_db};
use crate::{Client, Config};

/// Unraid flash config that holds `shutdownTimeout`.
const DISK_CFG: &str = "/boot/config/disk.cfg";
/// Unraid flash config for the syslog server (Settings → Syslog Server).
const RSYSLOG_CFG: &str = "/boot/config/rsyslog.cfg";

/// Force-unmount safety-net ceiling, in seconds. Above this (or disabled) the
/// array unmount can wedge past any reasonable UPS runtime; this is also the
/// value the repair writes.
const SHUTDOWN_TIMEOUT_MAX: u64 = 120;

/// Placeholder remote-syslog target the repair writes when none is set. A real
/// fleet host is supplied via the `UNRAID_REMOTE_SYSLOG` env at deploy time —
/// never hardcoded here (open-source repo).
const DEFAULT_REMOTE_SYSLOG: &str = "remote-syslog-host";
/// Env override for the remote-syslog target the `syslog-mirror` repair sets.
const REMOTE_SYSLOG_ENV: &str = "UNRAID_REMOTE_SYSLOG";

/// Unraid persists its Samba passdb to flash here; the live daemon reads/writes
/// [`RUNTIME_SMBPASSWD`] instead, so this is the copy a reboot restores. Its
/// presence is also the tell-tale that we are running on an Unraid host.
const FLASH_SMBPASSWD: &str = "/boot/config/smbpasswd";
/// The passdb smbd actually serves from at runtime. A plain `smbpasswd` writes
/// here only — it is never propagated back to [`FLASH_SMBPASSWD`].
const RUNTIME_SMBPASSWD: &str = "/var/lib/samba/private/smbpasswd";
/// Unix account database, read for the passdb→unix mapping check and written
/// (in place) by the Mode-1 heal.
const PASSWD_FILE: &str = "/etc/passwd";
/// Unix group database the managed SMB user's membership is converged in.
const GROUP_FILE: &str = "/etc/group";
/// Group the managed SMB user must belong to (the willow incident: `orca` was
/// absent from `users`/gid 100 despite `/boot/config/go` claiming otherwise).
const EXPECTED_GROUP: &str = "users";
/// Primary gid written when (re)creating a managed SMB unix user.
const EXPECTED_GID: u32 = 100;
/// Samba control script; a `restart` rebuilds smbd's passdb→unix mapping cache.
const RC_SAMBA: &str = "/etc/rc.d/rc.samba";
/// Optional override for the managed-user list (comma/space separated). The
/// primary source is the account list parsed from [`FLASH_SMBPASSWD`].
const SMB_USERS_ENV: &str = "UNRAID_SMB_USERS";

// ── diagnose ─────────────────────────────────────────────────────────────────

/// Run every check and return the findings as JSON (`Vec<Finding>`). The
/// `provider` filter is applied core-side, so args are only validated here.
pub fn diagnose(args_json: &str) -> Result<String, String> {
    let _: DiagnoseArgs = if args_json.trim().is_empty() {
        DiagnoseArgs::default()
    } else {
        serde_json::from_str(args_json).unwrap_or_default()
    };
    let findings: Vec<Finding> = [
        check_shutdown_timeout(DISK_CFG),
        check_syslog_mirror(RSYSLOG_CFG),
        check_array_unmount_blockers("/proc"),
        check_docker_vm_autostart(),
        check_unclean_shutdown(),
        check_samba_account_mapping(FLASH_SMBPASSWD, RUNTIME_SMBPASSWD),
    ]
    .into_iter()
    .flatten()
    .collect();
    serde_json::to_string(&findings).map_err(|e| format!("encode findings: {e}"))
}

fn finding(
    id: &str,
    severity: Severity,
    title: &str,
    detail: String,
    repair: Option<RepairSpec>,
) -> Finding {
    Finding {
        id: id.to_string(),
        provider: crate::PROVIDER.to_string(),
        severity,
        title: title.to_string(),
        detail,
        repair,
    }
}

/// A config-writing repair: privileged (writes flash config) and non-automatic
/// (suggest-then-confirm). unraid repairs in place — no unit delegation.
fn config_repair(id: &str, description: &str) -> RepairSpec {
    RepairSpec {
        id: id.to_string(),
        description: description.to_string(),
        automatic: false,
        privileged: true,
        delegate: None,
    }
}

// ── checks ───────────────────────────────────────────────────────────────────

/// The force-unmount safety net: `shutdownTimeout` in `disk.cfg`. Missing/`0`
/// (disabled) or higher than [`SHUTDOWN_TIMEOUT_MAX`] means a wedged array
/// unmount is never force-completed — *the* reason a UPS shutdown hangs forever.
fn check_shutdown_timeout(path: &str) -> Option<Finding> {
    let cfg = match read_key_value_cfg(path) {
        Ok(c) => c,
        // No flash config here → not an Unraid host / not running on the peer.
        Err(_) => return None,
    };
    let repair = Some(config_repair(
        "shutdown-timeout",
        &format!(
            "Set shutdownTimeout={SHUTDOWN_TIMEOUT_MAX} in {DISK_CFG} (force-unmount safety net)"
        ),
    ));
    match cfg.get("shutdownTimeout").map(|v| v.parse::<u64>()) {
        None => Some(finding(
            "shutdown-timeout",
            Severity::Crit,
            "Shutdown force-unmount timeout not set",
            format!(
                "no shutdownTimeout in {path}; a wedged array unmount is never force-completed \
                 — a UPS shutdown can hang forever"
            ),
            repair,
        )),
        Some(Ok(0)) => Some(finding(
            "shutdown-timeout",
            Severity::Crit,
            "Shutdown force-unmount timeout disabled",
            format!("shutdownTimeout=0 in {path} disables the force-unmount safety net"),
            repair,
        )),
        Some(Ok(n)) if n > SHUTDOWN_TIMEOUT_MAX => Some(finding(
            "shutdown-timeout",
            Severity::Warn,
            "Shutdown force-unmount timeout too high",
            format!(
                "shutdownTimeout={n}s in {path} exceeds {SHUTDOWN_TIMEOUT_MAX}s; the array can \
                 wedge past a UPS's remaining runtime before force-unmount fires"
            ),
            repair,
        )),
        Some(Ok(n)) => Some(finding(
            "shutdown-timeout",
            Severity::Ok,
            "Shutdown force-unmount timeout set",
            format!(
                "shutdownTimeout={n}s (≤{SHUTDOWN_TIMEOUT_MAX}s) — a wedged unmount is force-completed"
            ),
            None,
        )),
        Some(Err(e)) => Some(finding(
            "shutdown-timeout",
            Severity::Warn,
            "Shutdown timeout unparseable",
            format!("shutdownTimeout in {path} is not an integer: {e}"),
            repair,
        )),
    }
}

/// Survivable logging: syslog must mirror to flash (`MIRROR`) AND ship to a
/// remote target (`REMOTESERVER`), so the evidence of a hung shutdown survives
/// the power-cycle that recovery requires (syslog is tmpfs) and total loss of
/// the host.
fn check_syslog_mirror(path: &str) -> Option<Finding> {
    let cfg = match read_key_value_cfg(path) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let mirror_on = cfg.get("MIRROR").is_some_and(|v| is_truthy(v));
    let remote = cfg.get("REMOTESERVER").map(String::as_str).unwrap_or("");
    let remote_on = !remote.is_empty();
    let repair = Some(config_repair(
        "syslog-mirror",
        &format!(
            "Enable mirror-to-flash and set a remote syslog target in {RSYSLOG_CFG} \
             (survivable logging across a power-cycle)"
        ),
    ));
    if mirror_on && remote_on {
        return Some(finding(
            "syslog-mirror",
            Severity::Ok,
            "Syslog survives a power loss",
            format!("mirror-to-flash on and remote target '{remote}' set in {path}"),
            None,
        ));
    }
    let mut missing = Vec::new();
    if !mirror_on {
        missing.push("mirror-to-flash");
    }
    if !remote_on {
        missing.push("remote target");
    }
    Some(finding(
        "syslog-mirror",
        Severity::Warn,
        "Syslog will not survive a power loss",
        format!(
            "{} off in {path}; syslog is tmpfs, so the power-cycle that recovers a hung \
             shutdown erases the evidence of what hung it",
            missing.join(" + ")
        ),
        repair,
    ))
}

/// Array-unmount blockers: processes holding open files under the array mounts.
/// Walks `/proc/*/fd` for symlink targets under `/mnt/user`, `/mnt/disk*`,
/// `/mnt/cache*`. Suggest-only (no auto-repair): killing holders is operator
/// judgement, so this reports the offenders and ordered-stop guidance.
fn check_array_unmount_blockers(proc_root: &str) -> Option<Finding> {
    let blockers = array_fd_blockers(proc_root);
    if blockers.is_empty() {
        return Some(finding(
            "array-unmount-blockers",
            Severity::Ok,
            "No array-unmount blockers",
            "no processes hold open files under /mnt/user, /mnt/disk*, or /mnt/cache*".to_string(),
            None,
        ));
    }
    let list = blockers
        .iter()
        .map(|b| format!("pid {} ({}) → {}", b.pid, b.comm, b.path))
        .collect::<Vec<_>>()
        .join("; ");
    Some(finding(
        "array-unmount-blockers",
        Severity::Warn,
        "Processes hold open files on the array",
        format!(
            "{} open handle(s) under the array will block an unmount: {list}. \
             Stop Docker/VMs and NFS/SMB clients (ordered: containers → VMs → shares) before \
             array stop; these are not auto-killed.",
            blockers.len()
        ),
        None,
    ))
}

/// Autostart Docker containers (and running VMs) that stall an array stop. The
/// 7.3.1 `VmDomain` type exposes no autostart flag, so VMs are flagged only when
/// currently running. Suggest-only: disabling autostart is an operator choice.
fn check_docker_vm_autostart() -> Option<Finding> {
    let rows = match endpoint_db::list() {
        Ok(r) => r.into_iter().filter(|e| e.enabled).collect::<Vec<_>>(),
        // No endpoint registry (not on the peer / not configured) → skip.
        Err(_) => return None,
    };
    if rows.is_empty() {
        return None;
    }
    let (offenders, errors) = reactor::block_on(collect_autostart(&rows));
    if offenders.is_empty() {
        if errors.is_empty() {
            return Some(finding(
                "docker-vm-autostart",
                Severity::Ok,
                "No autostart workloads stall array stop",
                "no autostart Docker containers or running VMs found".to_string(),
                None,
            ));
        }
        // Couldn't read state — inconclusive, not a clean pass.
        return Some(finding(
            "docker-vm-autostart",
            Severity::Info,
            "Autostart state could not be read",
            format!(
                "GraphQL query failed for every endpoint: {}",
                errors.join("; ")
            ),
            None,
        ));
    }
    Some(finding(
        "docker-vm-autostart",
        Severity::Info,
        "Autostart workloads can stall array stop",
        format!(
            "{}. These start with the array and must be torn down before it can stop cleanly; \
             consider disabling autostart on non-essential ones.",
            offenders.join("; ")
        ),
        None,
    ))
}

/// Unclean shutdown / parity check in progress. Info only: the last parity
/// history entry flags whether the array is mid-check (a running or correcting
/// parity check is the tell-tale of an unclean boot / forced resync).
fn check_unclean_shutdown() -> Option<Finding> {
    let rows = match endpoint_db::list() {
        Ok(r) => r.into_iter().filter(|e| e.enabled).collect::<Vec<_>>(),
        Err(_) => return None,
    };
    let row = rows.into_iter().next()?;
    let running = reactor::block_on(async move {
        let cfg = Config::new(row.base_url, row.api_key).insecure(row.insecure);
        Client::new(cfg)
            .parity_history()
            .await
            .ok()
            .and_then(|d| d.parity_history.into_iter().next())
            .map(|h| h.running.unwrap_or(false) || h.correcting.unwrap_or(false))
    });
    match running {
        Some(true) => Some(finding(
            "unclean-shutdown",
            Severity::Info,
            "Parity check running (likely unclean shutdown)",
            "the latest parity history entry is running/correcting — the last boot was probably \
             unclean (forced resync). Let it complete before another power event."
                .to_string(),
            None,
        )),
        _ => None,
    }
}

// ── repair ───────────────────────────────────────────────────────────────────

/// Run one repair by id and return a [`RepairOutcome`] as JSON.
pub fn repair(args_json: &str) -> Result<String, String> {
    let args: RepairArgs =
        serde_json::from_str(args_json).map_err(|e| format!("invalid repair args: {e}"))?;
    let (ok, message) = match args.repair_id.as_str() {
        "shutdown-timeout" => repair_shutdown_timeout(DISK_CFG),
        "syslog-mirror" => repair_syslog_mirror(RSYSLOG_CFG),
        "samba-account-mapping" => repair_samba_account_mapping(RUNTIME_SMBPASSWD),
        "samba-passdb-flash" => repair_samba_passdb_flash(RUNTIME_SMBPASSWD, FLASH_SMBPASSWD),
        other => (false, format!("unraid has no repair '{other}'")),
    };
    let outcome = RepairOutcome {
        id: args.repair_id,
        provider: crate::PROVIDER.to_string(),
        ok,
        message,
    };
    serde_json::to_string(&outcome).map_err(|e| format!("encode outcome: {e}"))
}

/// Set `shutdownTimeout=SHUTDOWN_TIMEOUT_MAX` in `disk.cfg`. Idempotent: rewrites
/// the key in place (or appends it) and is a no-op when already correct.
fn repair_shutdown_timeout(path: &str) -> (bool, String) {
    let want = SHUTDOWN_TIMEOUT_MAX.to_string();
    match set_cfg_keys(path, &[("shutdownTimeout", &want)]) {
        Ok(false) => (
            true,
            format!("shutdownTimeout already {want}s in {path} (no change)"),
        ),
        Ok(true) => (true, format!("set shutdownTimeout={want}s in {path}")),
        Err(e) => (false, e),
    }
}

/// Enable mirror-to-flash and set a remote syslog target in `rsyslog.cfg`.
/// Idempotent: only writes keys that differ. The remote target comes from the
/// `UNRAID_REMOTE_SYSLOG` env (a fleet host at deploy time), never hardcoded.
fn repair_syslog_mirror(path: &str) -> (bool, String) {
    let remote =
        std::env::var(REMOTE_SYSLOG_ENV).unwrap_or_else(|_| DEFAULT_REMOTE_SYSLOG.to_string());
    match set_cfg_keys(path, &[("MIRROR", "yes"), ("REMOTESERVER", &remote)]) {
        Ok(false) => (
            true,
            format!("mirror-to-flash on and remote '{remote}' already set in {path} (no change)"),
        ),
        Ok(true) => (
            true,
            format!("enabled mirror-to-flash and set remote syslog target '{remote}' in {path}"),
        ),
        Err(e) => (false, e),
    }
}

// ── samba passdb→unix mapping ──────────────────────────────

/// One account row from an Unraid/Samba `smbpasswd` file: the uid the passdb
/// believes the user maps to and the NT hash it authenticates against.
#[derive(Debug, PartialEq, Eq)]
struct SmbEntry {
    user: String,
    uid: u32,
    nt_hash: String,
}

/// Parse an `smbpasswd` file (`user:uid:LM:NT:flags:LCT:` per line). Blank/`#`
/// lines and malformed rows are skipped; NT hashes are upper-cased so later
/// comparisons are case-stable.
fn parse_smbpasswd(text: &str) -> Vec<SmbEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split(':');
        let (Some(user), Some(uid), Some(_lm), Some(nt)) = (f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };
        let Ok(uid) = uid.parse::<u32>() else {
            continue;
        };
        out.push(SmbEntry {
            user: user.to_string(),
            uid,
            nt_hash: nt.trim().to_ascii_uppercase(),
        });
    }
    out
}

/// The passdb uid recorded for `user`, if present.
fn smb_uid(entries: &[SmbEntry], user: &str) -> Option<u32> {
    entries.iter().find(|e| e.user == user).map(|e| e.uid)
}

/// The NT hash recorded for `user`, if present.
fn smb_nt_hash<'a>(entries: &'a [SmbEntry], user: &str) -> Option<&'a str> {
    entries
        .iter()
        .find(|e| e.user == user)
        .map(|e| e.nt_hash.as_str())
}

/// Managed SMB users: the `UNRAID_SMB_USERS` override (comma/space separated)
/// when set and non-empty, else every account in the flash passdb.
fn managed_users(flash_text: &str, env_override: Option<String>) -> Vec<String> {
    if let Some(raw) = env_override {
        let users: Vec<String> = raw
            .split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if !users.is_empty() {
            return users;
        }
    }
    parse_smbpasswd(flash_text)
        .into_iter()
        .map(|e| e.user)
        .collect()
}

/// Per-user verdict for the passdb→unix mapping check. `Ok` = passdb uid,
/// getent uid, and NT hashes all agree.
#[derive(Debug, PartialEq, Eq)]
enum MappingVerdict {
    Ok,
    /// Mode 1: the passdb maps `user` to `passdb_uid` but the unix account is
    /// missing (`getent` = None) or maps to a different uid — smbd caches the
    /// broken mapping and every fresh tree-connect is denied (`rc=-13`).
    Corrupt {
        passdb_uid: u32,
        getent: Option<u32>,
    },
    /// Mode 2: the user's NT hash on flash differs from the running passdb, so a
    /// reboot restores the stale flash copy and re-breaks auth.
    FlashDivergence,
}

/// Classify one managed user. Mode-1 corruption outranks Mode-2 divergence: a
/// broken mapping denies auth *now*; the flash revert only bites on reboot.
fn classify_user(
    passdb_uid: Option<u32>,
    getent_uid: Option<u32>,
    runtime_hash: Option<&str>,
    flash_hash: Option<&str>,
) -> MappingVerdict {
    if let Some(uid) = passdb_uid
        && getent_uid != Some(uid)
    {
        return MappingVerdict::Corrupt {
            passdb_uid: uid,
            getent: getent_uid,
        };
    }
    if let (Some(r), Some(f)) = (runtime_hash, flash_hash)
        && !r.eq_ignore_ascii_case(f)
    {
        return MappingVerdict::FlashDivergence;
    }
    MappingVerdict::Ok
}

/// Detect the two faults behind `mount error(13)` / `reconnect tcon failed
/// rc=-13`: a corrupt passdb→unix mapping (Mode 1, Crit) and an NT hash that
/// diverges between the running passdb and flash (Mode 2, Warn). Off-box (no
/// flash passdb) this is a no-op.
fn check_samba_account_mapping(flash_path: &str, runtime_path: &str) -> Option<Finding> {
    // Gate: no flash passdb → not an Unraid host / not on the peer.
    let flash_text = fs::read_to_string(flash_path).ok()?;
    let runtime_text = fs::read_to_string(runtime_path).unwrap_or_default();
    let flash = parse_smbpasswd(&flash_text);
    let runtime = parse_smbpasswd(&runtime_text);
    let users = managed_users(&flash_text, std::env::var(SMB_USERS_ENV).ok());

    let mut corrupt = Vec::new();
    let mut diverged = Vec::new();
    for user in &users {
        match classify_user(
            smb_uid(&runtime, user),
            getent_uid(user),
            smb_nt_hash(&runtime, user),
            smb_nt_hash(&flash, user),
        ) {
            MappingVerdict::Corrupt { passdb_uid, getent } => corrupt.push(match getent {
                Some(u) => format!("{user} (passdb uid {passdb_uid} ≠ unix uid {u})"),
                None => format!("{user} (passdb uid {passdb_uid}, no unix account)"),
            }),
            MappingVerdict::FlashDivergence => diverged.push(user.clone()),
            MappingVerdict::Ok => {}
        }
    }

    if !corrupt.is_empty() {
        return Some(finding(
            "samba-account-mapping",
            Severity::Crit,
            "Samba passdb→unix mapping is corrupt",
            format!(
                "smbd caches a broken passdb→unix mapping for {} — every fresh SMB tree-connect \
                 is denied (mount error(13) / reconnect tcon failed rc=-13). The unix user must be \
                 (re)created at its passdb uid and samba restarted once.",
                corrupt.join(", ")
            ),
            Some(config_repair(
                "samba-account-mapping",
                "Ensure the managed SMB unix user exists at its passdb uid + group, then restart \
                 samba once (briefly drops SMB serving)",
            )),
        ));
    }
    if !diverged.is_empty() {
        return Some(finding(
            "samba-account-mapping",
            Severity::Warn,
            "Samba passdb differs from the flash copy",
            format!(
                "the NT hash for {} differs between {runtime_path} and {flash_path}; a runtime \
                 smbpasswd change was never propagated to flash, so a reboot restores the stale \
                 copy and re-breaks SMB auth.",
                diverged.join(", ")
            ),
            Some(config_repair(
                "samba-passdb-flash",
                &format!(
                    "Propagate the running passdb to flash ({flash_path}) so it survives a reboot"
                ),
            )),
        ));
    }
    Some(finding(
        "samba-account-mapping",
        Severity::Ok,
        "Samba passdb→unix mapping is consistent",
        format!(
            "passdb uid, unix uid, group, and NT hashes agree for {} managed SMB user(s)",
            users.len()
        ),
        None,
    ))
}

/// Look up the unix uid for `user` via `getent passwd`. `None` when the account
/// is absent (or getent is unavailable, e.g. off-box under test).
fn getent_uid(user: &str) -> Option<u32> {
    let out = std::process::Command::new("getent")
        .arg("passwd")
        .arg(user)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_getent_uid(&String::from_utf8_lossy(&out.stdout))
}

/// Parse the uid (3rd colon field) from a `getent passwd` line.
fn parse_getent_uid(line: &str) -> Option<u32> {
    line.trim().split(':').nth(2)?.parse().ok()
}

/// Mode-1 heal: ensure each managed SMB unix user exists at its passdb uid and
/// is in the expected group, then restart samba once so smbd rebuilds the
/// mapping. The account is (re)written in place at the passdb uid — never a
/// freshly allocated uid — and no password is touched. A no-op (still `ok`)
/// when the unix accounts already match.
fn repair_samba_account_mapping(runtime_path: &str) -> (bool, String) {
    let runtime_text = match fs::read_to_string(runtime_path) {
        Ok(t) => t,
        Err(e) => return (false, format!("read {runtime_path}: {e}")),
    };
    let flash_text = fs::read_to_string(FLASH_SMBPASSWD).unwrap_or_default();
    let runtime = parse_smbpasswd(&runtime_text);
    let users = managed_users(&flash_text, std::env::var(SMB_USERS_ENV).ok());

    let mut actions = Vec::new();
    for user in &users {
        let Some(uid) = smb_uid(&runtime, user) else {
            continue;
        };
        if getent_uid(user) != Some(uid) {
            match ensure_passwd_user(PASSWD_FILE, user, uid, EXPECTED_GID) {
                Ok(true) => actions.push(format!("set unix user {user} to uid {uid}")),
                Ok(false) => {}
                Err(e) => return (false, e),
            }
        }
        match ensure_group_member(GROUP_FILE, EXPECTED_GROUP, user) {
            Ok(true) => actions.push(format!("added {user} to group {EXPECTED_GROUP}")),
            Ok(false) => {}
            Err(e) => return (false, e),
        }
    }

    if actions.is_empty() {
        return (
            true,
            "unix accounts already match the passdb; no change".to_string(),
        );
    }
    if let Err(e) = restart_samba() {
        return (false, format!("{}; but {e}", actions.join("; ")));
    }
    (true, format!("{}; restarted samba", actions.join("; ")))
}

/// Mode-2 heal: propagate the running passdb to flash so it survives a reboot.
/// Backs the flash copy up to `.bak`, copies runtime→flash, then verifies the
/// managed users' NT hashes now agree. A no-op (still `ok`) when they already
/// match.
fn repair_samba_passdb_flash(runtime_path: &str, flash_path: &str) -> (bool, String) {
    let runtime_text = match fs::read_to_string(runtime_path) {
        Ok(t) => t,
        Err(e) => return (false, format!("read {runtime_path}: {e}")),
    };
    let flash_text = match fs::read_to_string(flash_path) {
        Ok(t) => t,
        Err(e) => return (false, format!("read {flash_path}: {e}")),
    };
    let users = managed_users(&flash_text, std::env::var(SMB_USERS_ENV).ok());
    if !passdb_diverges(&runtime_text, &flash_text, &users) {
        return (
            true,
            format!("flash passdb {flash_path} already matches runtime; no change"),
        );
    }
    let bak = format!("{flash_path}.bak");
    if let Err(e) = fs::copy(flash_path, &bak) {
        return (false, format!("back up {flash_path} → {bak}: {e}"));
    }
    if let Err(e) = fs::copy(runtime_path, flash_path) {
        return (false, format!("copy {runtime_path} → {flash_path}: {e}"));
    }
    let flash_after = fs::read_to_string(flash_path).unwrap_or_default();
    if passdb_diverges(&runtime_text, &flash_after, &users) {
        return (
            false,
            format!("copied {runtime_path} → {flash_path} but hashes still diverge"),
        );
    }
    (
        true,
        format!("propagated running passdb to {flash_path} (backup at {bak})"),
    )
}

/// Whether any managed user's NT hash differs between the two passdb texts.
fn passdb_diverges(runtime_text: &str, flash_text: &str, users: &[String]) -> bool {
    let runtime = parse_smbpasswd(runtime_text);
    let flash = parse_smbpasswd(flash_text);
    users.iter().any(
        |u| match (smb_nt_hash(&runtime, u), smb_nt_hash(&flash, u)) {
            (Some(r), Some(f)) => !r.eq_ignore_ascii_case(f),
            _ => false,
        },
    )
}

/// Restart samba via its rc script so smbd rebuilds the passdb→unix mapping.
fn restart_samba() -> Result<(), String> {
    let status = std::process::Command::new(RC_SAMBA)
        .arg("restart")
        .status()
        .map_err(|e| format!("spawn {RC_SAMBA}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{RC_SAMBA} restart exit {:?}", status.code()))
    }
}

/// Ensure `/etc/passwd` has `user` at `uid`/`gid`: append when absent, rewrite
/// the uid/gid fields in place when present but mismatched, no-op when correct.
/// Returns the new text and whether it changed.
fn apply_passwd_user(text: &str, user: &str, uid: u32, gid: u32) -> (String, bool) {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut changed = false;
    if let Some(line) = lines.iter_mut().find(|l| l.split(':').next() == Some(user)) {
        let f: Vec<String> = line.split(':').map(str::to_string).collect();
        if f.len() >= 4 && (f[2] != uid.to_string() || f[3] != gid.to_string()) {
            let mut nf = f;
            nf[2] = uid.to_string();
            nf[3] = gid.to_string();
            *line = nf.join(":");
            changed = true;
        }
    } else {
        lines.push(format!("{user}:x:{uid}:{gid}::/:/bin/false"));
        changed = true;
    }
    (lines.join("\n"), changed)
}

/// Add `user` to `group`'s member list in `/etc/group` text if the group exists
/// and the user is absent. Returns the new text and whether it changed.
fn apply_group_member(text: &str, group: &str, user: &str) -> (String, bool) {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut changed = false;
    for line in lines.iter_mut() {
        let f: Vec<String> = line.split(':').map(str::to_string).collect();
        if f.len() >= 4 && f[0] == group {
            let mut members: Vec<&str> = f[3].split(',').filter(|m| !m.is_empty()).collect();
            if !members.contains(&user) {
                members.push(user);
                *line = format!("{}:{}:{}:{}", f[0], f[1], f[2], members.join(","));
                changed = true;
            }
            break;
        }
    }
    (lines.join("\n"), changed)
}

/// [`apply_passwd_user`] applied to a file, preserving a trailing newline.
fn ensure_passwd_user(path: &str, user: &str, uid: u32, gid: u32) -> Result<bool, String> {
    write_if_changed(path, |text| apply_passwd_user(text, user, uid, gid))
}

/// [`apply_group_member`] applied to a file, preserving a trailing newline.
fn ensure_group_member(path: &str, group: &str, user: &str) -> Result<bool, String> {
    write_if_changed(path, |text| apply_group_member(text, group, user))
}

/// Read `path`, apply a pure `(text) -> (new_text, changed)` transform, and
/// write back only when it changed, preserving any trailing newline.
fn write_if_changed(
    path: &str,
    transform: impl FnOnce(&str) -> (String, bool),
) -> Result<bool, String> {
    let original = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let (mut out, changed) = transform(&original);
    if !changed {
        return Ok(false);
    }
    if original.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    fs::write(path, out).map_err(|e| format!("write {path}: {e}"))?;
    Ok(true)
}

// ── GraphQL state ────────────────────────────────────────────────────────────

/// Query every endpoint for autostart containers + running VMs. Returns
/// `(offender descriptions, per-endpoint errors)`; a broken endpoint contributes
/// an error string rather than blanking the others.
async fn collect_autostart(rows: &[EndpointRow]) -> (Vec<String>, Vec<String>) {
    let mut offenders = Vec::new();
    let mut errors = Vec::new();
    for ep in rows {
        let cfg = Config::new(ep.base_url.clone(), ep.api_key.clone()).insecure(ep.insecure);
        let client = Client::new(cfg);
        match client.docker_containers().await {
            Ok(d) => {
                for c in d.docker.containers.into_iter().filter(|c| c.auto_start) {
                    offenders.push(format!(
                        "autostart container '{}' on {}",
                        container_name(&c.names),
                        ep.name
                    ));
                }
            }
            Err(e) => errors.push(format!("{}: docker: {e}", ep.name)),
        }
        match client.vms().await {
            Ok(d) => {
                for dom in d
                    .vms
                    .domains
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|dom| is_vm_running(&dom.state))
                {
                    offenders.push(format!(
                        "running VM '{}' on {}",
                        dom.name.unwrap_or_default(),
                        ep.name
                    ));
                }
            }
            Err(e) => errors.push(format!("{}: vms: {e}", ep.name)),
        }
    }
    (offenders, errors)
}

/// First container name, stripped of docker's leading `/`.
fn container_name(names: &[String]) -> String {
    names
        .first()
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_default()
}

/// Whether a `VmState` is a running/active state that blocks an array stop.
fn is_vm_running(state: &crate::generated::v7_3_1::vms::VmState) -> bool {
    use crate::generated::v7_3_1::vms::VmState;
    matches!(
        state,
        VmState::RUNNING | VmState::IDLE | VmState::PAUSED | VmState::PMSUSPENDED
    )
}

// ── /proc walk ───────────────────────────────────────────────────────────────

/// A process holding an open file that will block an array unmount.
#[derive(Debug, PartialEq, Eq)]
struct FdBlocker {
    pid: String,
    comm: String,
    path: String,
}

/// Array mount prefixes an open file under which blocks an unmount.
fn is_array_path(target: &str) -> bool {
    target.starts_with("/mnt/user")
        || target.starts_with("/mnt/disk")
        || target.starts_with("/mnt/cache")
}

/// Walk `<proc_root>/<pid>/fd/*` for symlink targets under the array mounts,
/// returning one [`FdBlocker`] per (pid, holding path). Best-effort: unreadable
/// pids/fds are skipped (they vanish or are privileged).
fn array_fd_blockers(proc_root: &str) -> Vec<FdBlocker> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(proc_root) else {
        return out;
    };
    for pid_entry in rd.flatten() {
        let pid = pid_entry.file_name().to_string_lossy().into_owned();
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue; // not a pid dir
        }
        let fd_dir = pid_entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };
        let mut comm = None;
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            if !is_array_path(&target) {
                continue;
            }
            let comm = comm.get_or_insert_with(|| read_comm(&pid_entry.path()));
            out.push(FdBlocker {
                pid: pid.clone(),
                comm: comm.clone(),
                path: target.into_owned(),
            });
        }
    }
    out.sort_by(|a, b| (&a.pid, &a.path).cmp(&(&b.pid, &b.path)));
    out
}

/// Process name from `<pid_dir>/comm`, trimmed; empty when unreadable.
fn read_comm(pid_dir: &Path) -> String {
    fs::read_to_string(pid_dir.join("comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

// ── config I/O ───────────────────────────────────────────────────────────────

/// Parse an Unraid `KEY="value"` (or bare `KEY=value`) flash config into a map.
/// Blank lines and `#` comments are ignored; surrounding double quotes are
/// stripped from values.
fn read_key_value_cfg(path: &str) -> Result<BTreeMap<String, String>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    Ok(parse_key_value(&text))
}

fn parse_key_value(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches('"');
            map.insert(k.trim().to_string(), v.to_string());
        }
    }
    map
}

/// Idempotently set `KEY="value"` pairs in an Unraid flash config, preserving
/// unrelated lines and order. Returns `Ok(true)` when the file changed,
/// `Ok(false)` when every key already held the wanted value. Missing keys are
/// appended.
fn set_cfg_keys(path: &str, pairs: &[(&str, &str)]) -> Result<bool, String> {
    let original = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut lines: Vec<String> = original.lines().map(|l| l.to_string()).collect();
    let mut changed = false;

    for (key, want) in pairs {
        let want_line = format!("{key}=\"{want}\"");
        let mut found = false;
        for line in lines.iter_mut() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix(key)
                && rest.trim_start().starts_with('=')
            {
                found = true;
                if *line != want_line {
                    *line = want_line.clone();
                    changed = true;
                }
                break;
            }
        }
        if !found {
            lines.push(want_line);
            changed = true;
        }
    }

    if !changed {
        return Ok(false);
    }
    let mut out = lines.join("\n");
    if original.ends_with('\n') {
        out.push('\n');
    }
    fs::write(path, out).map_err(|e| format!("write {path}: {e}"))?;
    Ok(true)
}

fn is_truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "yes" | "true" | "1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn write_tmp(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("unraid-diag-{name}-{}", std::process::id()));
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn parses_quoted_and_bare_key_values() {
        let m = parse_key_value("# comment\nshutdownTimeout=\"90\"\n\nMIRROR=yes\n");
        assert_eq!(m.get("shutdownTimeout").unwrap(), "90");
        assert_eq!(m.get("MIRROR").unwrap(), "yes");
    }

    #[test]
    fn shutdown_timeout_missing_is_crit_with_repair() {
        let p = write_tmp("st-missing", "startArray=\"yes\"\n");
        let f = check_shutdown_timeout(p.to_str().unwrap()).unwrap();
        assert_eq!(f.severity, Severity::Crit);
        assert_eq!(f.id, "shutdown-timeout");
        assert!(f.repair.is_some());
        fs::remove_file(p).ok();
    }

    #[test]
    fn shutdown_timeout_disabled_is_crit() {
        let p = write_tmp("st-zero", "shutdownTimeout=\"0\"\n");
        let f = check_shutdown_timeout(p.to_str().unwrap()).unwrap();
        assert_eq!(f.severity, Severity::Crit);
        fs::remove_file(p).ok();
    }

    #[test]
    fn shutdown_timeout_too_high_is_warn() {
        let p = write_tmp("st-high", "shutdownTimeout=\"300\"\n");
        let f = check_shutdown_timeout(p.to_str().unwrap()).unwrap();
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.repair.is_some());
        fs::remove_file(p).ok();
    }

    #[test]
    fn shutdown_timeout_in_range_is_ok_no_repair() {
        let p = write_tmp("st-ok", "shutdownTimeout=\"90\"\n");
        let f = check_shutdown_timeout(p.to_str().unwrap()).unwrap();
        assert_eq!(f.severity, Severity::Ok);
        assert!(f.repair.is_none());
        fs::remove_file(p).ok();
    }

    #[test]
    fn shutdown_timeout_repair_is_idempotent() {
        let p = write_tmp("st-repair", "shutdownTimeout=\"0\"\nstartArray=\"yes\"\n");
        let path = p.to_str().unwrap();
        // First run flips it and reports a change.
        let (ok, msg) = repair_shutdown_timeout(path);
        assert!(ok, "{msg}");
        // It is now Ok.
        assert_eq!(check_shutdown_timeout(path).unwrap().severity, Severity::Ok);
        // Unrelated key preserved.
        let cfg = read_key_value_cfg(path).unwrap();
        assert_eq!(cfg.get("startArray").unwrap(), "yes");
        assert_eq!(cfg.get("shutdownTimeout").unwrap(), "120");
        // Second run is a no-op.
        let (ok2, msg2) = repair_shutdown_timeout(path);
        assert!(ok2);
        assert!(msg2.contains("no change"), "{msg2}");
        fs::remove_file(p).ok();
    }

    #[test]
    fn syslog_mirror_both_off_is_warn() {
        let p = write_tmp("sl-off", "MIRROR=\"no\"\nREMOTESERVER=\"\"\n");
        let f = check_syslog_mirror(p.to_str().unwrap()).unwrap();
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.detail.contains("mirror-to-flash"));
        assert!(f.detail.contains("remote target"));
        assert!(f.repair.is_some());
        fs::remove_file(p).ok();
    }

    #[test]
    fn syslog_mirror_both_on_is_ok() {
        let p = write_tmp(
            "sl-on",
            "MIRROR=\"yes\"\nREMOTESERVER=\"remote-syslog-host\"\n",
        );
        let f = check_syslog_mirror(p.to_str().unwrap()).unwrap();
        assert_eq!(f.severity, Severity::Ok);
        assert!(f.repair.is_none());
        fs::remove_file(p).ok();
    }

    #[test]
    fn syslog_mirror_repair_is_idempotent_and_uses_placeholder() {
        let p = write_tmp("sl-repair", "MIRROR=\"no\"\nREMOTESERVER=\"\"\n");
        let path = p.to_str().unwrap();
        // Ensure no fleet host bleeds in from the environment during the test.
        unsafe {
            std::env::remove_var(REMOTE_SYSLOG_ENV);
        }
        let (ok, msg) = repair_syslog_mirror(path);
        assert!(ok, "{msg}");
        assert!(msg.contains(DEFAULT_REMOTE_SYSLOG), "{msg}");
        assert_eq!(check_syslog_mirror(path).unwrap().severity, Severity::Ok);
        let (ok2, msg2) = repair_syslog_mirror(path);
        assert!(ok2);
        assert!(msg2.contains("no change"), "{msg2}");
        fs::remove_file(p).ok();
    }

    #[test]
    fn set_cfg_keys_appends_missing_and_preserves_others() {
        let p = write_tmp("cfg-append", "startArray=\"yes\"\n");
        let path = p.to_str().unwrap();
        let changed = set_cfg_keys(path, &[("shutdownTimeout", "120")]).unwrap();
        assert!(changed);
        let cfg = read_key_value_cfg(path).unwrap();
        assert_eq!(cfg.get("startArray").unwrap(), "yes");
        assert_eq!(cfg.get("shutdownTimeout").unwrap(), "120");
        fs::remove_file(p).ok();
    }

    #[test]
    fn is_array_path_matches_array_mounts_only() {
        assert!(is_array_path("/mnt/user/appdata/foo"));
        assert!(is_array_path("/mnt/disk1/bar"));
        assert!(is_array_path("/mnt/cache/baz"));
        assert!(!is_array_path("/var/log/syslog"));
        assert!(!is_array_path("/boot/config/disk.cfg"));
    }

    #[test]
    fn array_fd_blockers_reports_open_array_handles() {
        // Build a fake /proc/<pid>/fd tree with one array symlink and one not.
        let root = std::env::temp_dir().join(format!("unraid-proc-{}", std::process::id()));
        fs::remove_dir_all(&root).ok();
        let target = root.join("mnt-user-appdata-db");
        fs::create_dir_all(&target).unwrap();
        // A non-array target to prove filtering.
        let other = root.join("var-log");
        fs::create_dir_all(&other).unwrap();

        let pid_dir = root.join("4242");
        let fd_dir = pid_dir.join("fd");
        fs::create_dir_all(&fd_dir).unwrap();
        fs::write(pid_dir.join("comm"), "smbd\n").unwrap();
        // fd 3 → an array path (via a symlink whose target string starts /mnt/user);
        // we can't create a literal /mnt/user symlink target dir, so point the link
        // at a path *string* under /mnt/user that need not exist (read_link reads the
        // target, not the destination).
        std::os::unix::fs::symlink("/mnt/user/appdata/db/data.mdb", fd_dir.join("3")).unwrap();
        std::os::unix::fs::symlink("/var/log/syslog", fd_dir.join("4")).unwrap();
        // A non-pid dir must be ignored.
        fs::create_dir_all(root.join("acpi")).unwrap();

        let blockers = array_fd_blockers(root.to_str().unwrap());
        assert_eq!(blockers.len(), 1, "only the array handle counts");
        assert_eq!(blockers[0].pid, "4242");
        assert_eq!(blockers[0].comm, "smbd");
        assert_eq!(blockers[0].path, "/mnt/user/appdata/db/data.mdb");

        // The corresponding finding is a suggest-only Warn (no repair).
        let f = check_array_unmount_blockers(root.to_str().unwrap()).unwrap();
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.repair.is_none());

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn no_flash_config_yields_no_finding() {
        assert!(check_shutdown_timeout("/nonexistent/disk.cfg").is_none());
        assert!(check_syslog_mirror("/nonexistent/rsyslog.cfg").is_none());
    }

    #[test]
    fn repair_unknown_id_reports_not_ok() {
        let out = repair(r#"{"provider":"unraid","repair_id":"nope"}"#).expect("encodes");
        let o: RepairOutcome = serde_json::from_str(&out).unwrap();
        assert!(!o.ok);
        assert!(o.message.contains("no repair"));
    }

    // ── samba passdb→unix mapping ──────────────────────────

    const SMB_LINE: &str = "orca:999:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:31D6CFE0D16AE931B73C59D7E0C089C0:[U          ]:LCT-00000000:";

    #[test]
    fn parse_smbpasswd_reads_user_uid_hash() {
        let e = parse_smbpasswd(&format!("# comment\n\n{SMB_LINE}\n"));
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].user, "orca");
        assert_eq!(e[0].uid, 999);
        assert_eq!(e[0].nt_hash, "31D6CFE0D16AE931B73C59D7E0C089C0");
        // Malformed rows are dropped.
        assert!(parse_smbpasswd("garbage\norca:notanint:a:b:c:d:").is_empty());
    }

    #[test]
    fn managed_users_prefers_env_override() {
        let flash = format!("{SMB_LINE}\n");
        assert_eq!(managed_users(&flash, None), vec!["orca".to_string()]);
        assert_eq!(
            managed_users(&flash, Some("alice, bob".to_string())),
            vec!["alice".to_string(), "bob".to_string()]
        );
        // Empty override falls back to the flash list.
        assert_eq!(
            managed_users(&flash, Some("  ".to_string())),
            vec!["orca".to_string()]
        );
    }

    #[test]
    fn classify_flags_uid_mismatch_and_missing_account() {
        // Mode 1: unix account missing.
        assert_eq!(
            classify_user(Some(999), None, Some("A"), Some("A")),
            MappingVerdict::Corrupt {
                passdb_uid: 999,
                getent: None
            }
        );
        // Mode 1: uid mismatch (outranks a concurrent hash divergence).
        assert_eq!(
            classify_user(Some(999), Some(1000), Some("A"), Some("B")),
            MappingVerdict::Corrupt {
                passdb_uid: 999,
                getent: Some(1000)
            }
        );
    }

    #[test]
    fn classify_flags_nt_hash_divergence() {
        assert_eq!(
            classify_user(Some(999), Some(999), Some("aaaa"), Some("bbbb")),
            MappingVerdict::FlashDivergence
        );
    }

    #[test]
    fn classify_ok_when_everything_agrees() {
        // Hashes compared case-insensitively.
        assert_eq!(
            classify_user(Some(999), Some(999), Some("abcd"), Some("ABCD")),
            MappingVerdict::Ok
        );
        // No passdb entry and no runtime hash → nothing to flag.
        assert_eq!(
            classify_user(None, None, None, Some("ABCD")),
            MappingVerdict::Ok
        );
    }

    #[test]
    fn check_mapping_off_box_is_none() {
        assert!(check_samba_account_mapping("/nonexistent/smbpasswd", "/nonexistent/rt").is_none());
    }

    #[test]
    fn passdb_diverges_detects_hash_drift() {
        let rt = "orca:999:X:AAAA:[U]:LCT-0:\n";
        let flash = "orca:999:X:BBBB:[U]:LCT-0:\n";
        assert!(passdb_diverges(rt, flash, &["orca".to_string()]));
        assert!(!passdb_diverges(rt, rt, &["orca".to_string()]));
        // Unknown managed user → no divergence.
        assert!(!passdb_diverges(rt, flash, &["nobody".to_string()]));
    }

    #[test]
    fn parse_getent_uid_reads_third_field() {
        assert_eq!(parse_getent_uid("orca:x:999:100::/:/bin/false"), Some(999));
        assert_eq!(parse_getent_uid(""), None);
    }

    #[test]
    fn apply_passwd_user_appends_when_absent() {
        let (out, changed) = apply_passwd_user("root:x:0:0::/root:/bin/bash\n", "orca", 999, 100);
        assert!(changed);
        assert!(out.contains("orca:x:999:100::/:/bin/false"));
        // Idempotent: correct entry present → no change.
        let (_, changed2) = apply_passwd_user(&out, "orca", 999, 100);
        assert!(!changed2);
    }

    #[test]
    fn apply_passwd_user_rewrites_uid_in_place() {
        let (out, changed) = apply_passwd_user("orca:x:1000:100::/:/bin/false", "orca", 999, 100);
        assert!(changed);
        assert_eq!(out, "orca:x:999:100::/:/bin/false");
        // Only one entry — no duplicate appended.
        assert_eq!(out.lines().filter(|l| l.starts_with("orca:")).count(), 1);
    }

    #[test]
    fn apply_group_member_adds_once() {
        let (out, changed) = apply_group_member("users:x:100:bob\nwheel:x:10:\n", "users", "orca");
        assert!(changed);
        assert_eq!(out.lines().next().unwrap(), "users:x:100:bob,orca");
        // Idempotent.
        let (_, changed2) = apply_group_member(&out, "users", "orca");
        assert!(!changed2);
        // Missing group → no change.
        let (_, changed3) = apply_group_member("wheel:x:10:\n", "users", "orca");
        assert!(!changed3);
    }

    #[test]
    fn samba_repairs_are_privileged_suggest_only() {
        for id in ["samba-account-mapping", "samba-passdb-flash"] {
            let r = config_repair(id, "x");
            assert!(
                !r.automatic,
                "{id} must never auto-run (rc.samba restart drops SMB)"
            );
            assert!(r.privileged, "{id} must be privileged");
        }
    }

    #[test]
    fn passdb_flash_repair_is_noop_when_equal() {
        let rt = write_tmp("pdb-rt-eq", "orca:999:X:AAAA:[U]:LCT-0:\n");
        let flash = write_tmp("pdb-flash-eq", "orca:999:X:AAAA:[U]:LCT-0:\n");
        unsafe {
            std::env::remove_var(SMB_USERS_ENV);
        }
        let (ok, msg) = repair_samba_passdb_flash(rt.to_str().unwrap(), flash.to_str().unwrap());
        assert!(ok, "{msg}");
        assert!(msg.contains("no change"), "{msg}");
        assert!(!fs::exists(format!("{}.bak", flash.to_str().unwrap())).unwrap_or(false));
        fs::remove_file(rt).ok();
        fs::remove_file(flash).ok();
    }

    #[test]
    fn passdb_flash_repair_propagates_and_backs_up() {
        let rt = write_tmp("pdb-rt-div", "orca:999:X:AAAA:[U]:LCT-0:\n");
        let flash = write_tmp("pdb-flash-div", "orca:999:X:BBBB:[U]:LCT-0:\n");
        unsafe {
            std::env::remove_var(SMB_USERS_ENV);
        }
        let (ok, msg) = repair_samba_passdb_flash(rt.to_str().unwrap(), flash.to_str().unwrap());
        assert!(ok, "{msg}");
        // Backup captured the stale copy; flash now matches runtime.
        let bak = format!("{}.bak", flash.to_str().unwrap());
        assert!(fs::read_to_string(&bak).unwrap().contains("BBBB"));
        assert!(fs::read_to_string(&flash).unwrap().contains("AAAA"));
        // Second run is a no-op.
        let (ok2, msg2) = repair_samba_passdb_flash(rt.to_str().unwrap(), flash.to_str().unwrap());
        assert!(ok2 && msg2.contains("no change"), "{msg2}");
        fs::remove_file(rt).ok();
        fs::remove_file(flash).ok();
        fs::remove_file(bak).ok();
    }
}
