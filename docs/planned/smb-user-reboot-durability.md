# SMB user must be reboot-durable

Status: **PARTIAL** — finding from the 2026-08-27 `data` NFS→SMB cutover incident
on the orca fleet. The **runtime self-heal is implemented** in the unraid
diagnostics provider (`src/checks.rs`): the `samba-account-mapping` check +
repair heal the corrupt passdb→unix mapping (Mode 1, restart samba once), and
the `samba-passdb-flash` check + repair propagate the running passdb to flash
so it survives a reboot (Mode 2). The **boot-ordering** item (creating the
unix user before smbd starts via the `go`-script/boot hook) remains separate
and unimplemented.

## Problem

After a willow reboot (rc.8 plugin update), every fresh SMB tree-connect for the
`orca` user was denied — `mount error(13)`, dmesg `reconnect tcon failed rc =
-13`. smbd logged:

```
build_sam_account: smbpasswd database is corrupt! username orca with uid 999
is not in unix passwd database!
```

The reboot recreated the unix `orca` user (uid 999) *after* smbd started, so
samba's passdb→unix mapping was corrupt. `getent passwd orca` later showed the
user present, but smbd had cached the broken state; only `/etc/rc.d/rc.samba
restart` cleared it. Existing mounts survived on cached tree-connects, masking
the break until something reconnected.

## Fix

The plugin's user / SMB provisioning must:

1. Ensure the unix user exists **before** samba starts (order the `go`-script /
   boot hook so user creation precedes smbd), or restart samba once the user is
   present. — **still separate / not implemented** (boot-ordering).
2. Restart samba after (re)provisioning an SMB user, so the passdb→unix mapping
   is rebuilt. — **done** (Mode-1 repair restarts samba once after healing).
3. Self-heal the corrupt-mapping state: detect the corrupt mapping (passdb uid
   present but `getent passwd <user>` missing or uid-mismatched) and restart
   samba. — **done** (`samba-account-mapping` check + repair, Crit).
4. Verify group membership converges — `orca` was not in `users` (gid 100)
   despite `/boot/config/go` claiming it. — **done** (Mode-1 repair converges
   `/etc/group` membership for the managed user).

Additionally, a second fault sharing the same `mount error(13)` symptom is now
covered: the flash-revert (Mode 2). Unraid persists the passdb to
`/boot/config/smbpasswd`, but a runtime `smbpasswd` only writes
`/var/lib/samba/private/smbpasswd`, so a reboot restores the stale flash copy.
The `samba-passdb-flash` check (Warn) detects the NT-hash divergence and its
repair backs up + propagates runtime→flash.

## Cross-reference

orca-side follow-ups (daemon-side mount privilege, convergence gaps, plugin
install not restarting the daemon): `argyle-labs/orca`
`docs/planned/storage-serving-followups.md`.
