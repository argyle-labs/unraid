# Unraid SMB user & share-permission management — proposed capabilities

Field notes from a real incident (2026-08-16) where an SMB write-permission
regression on an unraid host silently took down a downstream service (immich).
Like [diagnostics.md](diagnostics.md), each item below is something this plugin
**should manage / detect / remediate** but does not yet — written as an
implementation spec, not as documentation of shipped behaviour.

This is the concrete backing for the standing requirement that the unraid plugin
**fully manages SMB users, group membership, and per-share read/write
permissions** (not just array/docker/plugin state).

---

## The incident

After the fleet cut its `data` share from NFS to SMB, immich on **baldur**
(CIFS-mounting `//willow/data` → `/mnt/data/photos`) fell into a crash loop:

```
StorageService  Failed to write /usr/src/app/upload/encoded-video/.immich:
                Error: EACCES: permission denied
microservices worker exited with code 1   # repeated → restart loop
```

The write was denied by the SMB server (willow). Under the old NFS export the
app wrote as root and bypassed permissions; SMB writes as the mount's
authenticated user (`orca`), which **is** permission-checked. Two independent
misconfigurations both had to be fixed:

### Cause 1 — `read list` silently overrides `write list`

The `[data]` share had `orca` in **both** lists:

```
read list  = orca
write list = skey,orca
```

In Samba, **`read list` wins**: a user named there is forced read-only no matter
what `write list` or `writeable` say. Someone had already added `orca` to
`write list` to "fix" it — that can never take effect while `orca` remains in
`read list`. This is a foot-gun the plugin should refuse to let a host sit in.

### Cause 2 — SMB user not in the share's writable group

The share tree is owned `99:100` (`nobody:users`), mode `0775`. The `orca` SMB
user was uid `999`, gid `999`, **not a member of `users` (gid 100)** — so it fell
to "other" (`r-x`, no write bit). Adding `orca` to `users` restored write.

> smbd caches a user's group list at **authentication** time. After changing
> group membership a `reload-config` / `close-share` is **not** enough — a full
> `samba restart` (or dropping the user's session) is required for it to take
> effect. The plugin's remediation must account for this.

---

## Durability — where the truth actually lives (unraid is stateless)

The live files are regenerated at boot/array-start, so remediation MUST write the
durable `/boot/config` sources, not just the running config:

| Setting | Live (ephemeral) | Durable source (must edit) |
| --- | --- | --- |
| Share read/write lists | `/etc/samba/smb-shares.conf` | `/boot/config/shares/<share>.cfg` → `shareReadList` / `shareWriteList` |
| SMB user group membership | `/etc/group` (ramdisk) | a `usermod -aG <group> <user>` line in `/boot/config/go` |
| SMB users themselves | `/etc/passwd`,`/etc/samba/smbpasswd` | `/boot/config/passwd`, `/boot/config/smbpasswd` |

> Note: `<share>.cfg` files are CRLF-terminated — preserve line endings when
> editing. The existing fleet pattern already persists `usermod -aG docker orca`
> in `/boot/config/go`; a group-membership remediation should follow the same
> shape.

---

## What the plugin should detect

1. **Read/write-list contradiction** — any user present in BOTH a share's
   `read list` and `write list`. Report it: the user is effectively read-only,
   which almost always contradicts intent. (Parse `shareReadList` /
   `shareWriteList` from each `/boot/config/shares/<share>.cfg`.)
2. **Write-list user lacking filesystem write** — a user in a share's
   `write list` whose uid is neither the owner nor a member of the tree's group,
   on a group-writable-but-not-other-writable tree (`07 7 5`/`0664`). This is the
   silent EACCES class. Cross-check SMB user gid membership against the share
   path's owner/group/mode.
3. **Ephemeral-only fix drift** — live `smb-shares.conf` / `/etc/group` grants
   write, but the durable `/boot/config` source does not (or vice-versa) → the
   grant will not survive a reboot. Flag as non-durable.

## What the plugin should remediate

- Set/clear a share's `read list` / `write list` durably (edit the share `.cfg`,
  then reload) — with a guard that refuses to add a user to `write list` while it
  remains in `read list`.
- Add an SMB user to a group durably (`/boot/config/go` line + live `usermod`),
  then **restart samba** so the new group list is honoured.
- Report both the live and durable state so an operator can see they agree.

## Surface / mechanism notes

- `queries/shares.graphql` already reads share definitions. Confirm whether the
  Unraid GraphQL API exposes **mutations** for share access-lists and user/group
  management. If it does not, this remediation follows the same privileged path
  as `unraid.install_plugin`: it needs root + flash (`/boot`) write, which the
  unprivileged daemon can't do directly — route through the root-capable plugin
  manager / an exec op, exactly as the self-update path already does.
- Any change touching `/boot/config/shares/*.cfg` or `/boot/config/go` is an
  admin-role mutation.
