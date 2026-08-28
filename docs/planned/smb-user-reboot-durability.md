# SMB user must be reboot-durable

Status: **BACKLOG** — finding from the 2026-08-27 `data` NFS→SMB cutover incident
on the orca fleet. Not yet implemented.

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
   present.
2. Restart samba after (re)provisioning an SMB user, so the passdb→unix mapping
   is rebuilt.
3. Self-heal the corrupt-mapping state: detect `build_sam_account ... not in unix
   passwd database` in the smbd log (or a failed `pdbedit -Lv <user>`) and
   restart samba.
4. Verify group membership converges — `orca` was not in `users` (gid 100)
   despite `/boot/config/go` claiming it.

## Cross-reference

orca-side follow-ups (daemon-side mount privilege, convergence gaps, plugin
install not restarting the daemon): `argyle-labs/orca`
`docs/planned/storage-serving-followups.md`.
