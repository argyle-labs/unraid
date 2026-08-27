# Unraid host failure modes

Field notes on how an Unraid host actually breaks at the storage and share
layer, and what this plugin does about each. Every mode below was observed on a
real host during a single cascading incident: a corrupt btrfs cache pool wedged
the `/mnt/user` union, an SMB user's password reverted across the recovery
reboot, and the cache corruption counter kept climbing throughout.

The modes are independent but reinforce each other. Mode 3 (cache corruption) is
the root that triggers Mode 1 (union crash); Mode 2 (password reversion) is what
turns a reboot — the usual fix for Mode 1 — into a second outage.

---

## 1. shfs `/mnt/user` union crash from cache-pool corruption

**Symptom.** Any access to `/mnt/user` returns `Transport endpoint is not
connected`:

```
$ ls /mnt/user
ls: cannot access '/mnt/user': Transport endpoint is not connected
$ stat -f /mnt/user
stat: cannot read file system information for '/mnt/user': Transport endpoint is not connected
```

That is `ENOTCONN` — errno 107, surfaced as `-107` in kernel traces. SMB and
NFS exports of anything under `/mnt/user` fail with the union path unreadable:

```
vfs_ChDir(/mnt/user/data) failed: Transport endpoint is not connected
```

The tell that isolates this mode: `/mnt/user0` — the user-share union built from
**array disks only, no cache pool** — stays alive and readable, and every
underlying array disk (`/mnt/disk1` … `/mnt/diskN`) reads directly with no
error. The data is intact on the array; only the union daemon is down.

**Cause.** `/mnt/user` is a FUSE union served by the shfs daemon, and that union
includes the cache pool. When shfs touched a corrupt btrfs cache pool it wedged,
tearing down the FUSE transport and leaving every path under `/mnt/user`
answering `ENOTCONN`. The separate shfs instance backing `/mnt/user0` does not
include the cache pool, so it is unaffected — which is exactly why the
`/mnt/user` dead / `/mnt/user0` alive split is diagnostic rather than
coincidental.

As the failure propagates into the export path, nfsd logs a non-standard errno
warning:

```
nfsd: non-standard errno: -107
WARNING: ... nfserrno ...
```

**What the plugin does / should do.** DETECT this specifically rather than as a
generic mount failure: a short-timeout `stat -f /mnt/user` returning `ENOTCONN`
while `/mnt/user0` stats clean, or the `ENOTCONN` / `-107` signature in syslog.
NOTIFY on the finding. Remediation is a wedged-FUSE recovery, not a filesystem
repair — a wedged shfs typically needs an array stop/start or a host reboot, and
because array-stop can itself hang on the busy wedged mount, a reboot is often
the more reliable path. This is not a ZFS or array data problem: the array disks
are healthy and the data is safe. Cross-reference the existing
detect-nfsd-hang / NFS-flap capability, which observes the same `ENOTCONN`
signature from the export side.

---

## 2. SMB user password reverts on every reboot

**Symptom.** After a reboot, CIFS clients that mounted fine before now fail:

```
mount error(13): Permission denied
```

The user account still exists and is still a `valid users` member of the share
— it is not a missing-account problem:

```
$ pdbedit -L
orca:1001:
```

The account is present; the password simply no longer matches the credential
clients hold. Anything set after the last boot is gone.

**Cause.** Unraid's Samba passdb backend is `smbpasswd`, and the persistent copy
lives on the USB flash at `/boot/config/smbpasswd`. A password set at runtime
with `smbpasswd` only writes the **running** database at
`/var/lib/samba/private/smbpasswd`; it is never propagated back to flash. On the
next boot Unraid restores the running database from the stale flash copy, so the
runtime password change is silently discarded.

**What the plugin does / should do.** When managing SMB user passwords, ALWAYS
persist to flash. After setting the password, copy the running database onto the
flash copy (backing up the existing flash file first):

```
smbpasswd -s <user>
cp /boot/config/smbpasswd /boot/config/smbpasswd.bak
cp /var/lib/samba/private/smbpasswd /boot/config/smbpasswd
```

Verify by comparing the managed user's NT-hash field in both files — the running
and flash copies must agree before the change is considered durable. This is
part of the plugin's manage-users-and-SMB-permissions responsibility; a password
change that is not written to flash is not actually applied.

---

## 3. btrfs cache-pool corruption

**Symptom.** `dmesg` / syslog shows checksum failures and a climbing corruption
counter on the cache device:

```
BTRFS warning (device nvme0n1p1): csum failed root ... ino ... off ...
BTRFS error (device nvme0n1p1): bdev /dev/nvme0n1p1 errs: wr 0, rd 0, flush 0, corrupt 42, gen 0
```

`btrfs dev stats` confirms the shape — corruption errors accumulating while I/O
error counters and drive SMART stay clean:

```
$ btrfs dev stats /mnt/cache
[/dev/nvme0n1p1].write_io_errs    0
[/dev/nvme0n1p1].read_io_errs     0
[/dev/nvme0n1p1].flush_io_errs    0
[/dev/nvme0n1p1].corruption_errs  42
[/dev/nvme0n1p1].generation_errs  0
```

Nonzero `corruption_errs` with zero read/write/flush `io_errs` and NVMe SMART
`PASSED` points at filesystem- or RAM-level corruption, not a dying disk. This
same corruption is what wedges shfs in Mode 1.

**What the plugin does / should do.** Monitor `btrfs dev stats` on cache pools
and alert on any nonzero `corruption_errs`. Recommend a `btrfs scrub` — on a
single-device pool scrub can **detect** corruption but cannot **repair** it
(there is no second copy to rebuild from), so the corrupt file must be removed
and restored from backup. After a clean scrub, reset the counter so the next
occurrence is distinguishable:

```
btrfs scrub start /mnt/cache
btrfs dev stats -z /mnt/cache
```

Recurrent corruption on non-ECC consumer hardware points at RAM rather than the
SSD — flag it as such rather than treating the drive as failed.

---

## Operator checklist

When `/mnt/user` reports `Transport endpoint is not connected`:

1. **Confirm the split.** `stat -f /mnt/user` fails with `ENOTCONN` but
   `stat -f /mnt/user0` succeeds, and `/mnt/disk1` … reads directly. That
   isolates the failure to the shfs union, not the array data.
2. **Check the cache pool.** `btrfs dev stats /mnt/cache` — nonzero
   `corruption_errs` with clean `io_errs` is Mode 3, the usual root of the
   wedge.
3. **Reboot to recover the union.** Array-stop can hang on the wedged mount;
   a reboot is the reliable path.
4. **Verify SMB passwords survived the reboot.** Compare the managed user's
   NT-hash in `/var/lib/samba/private/smbpasswd` against
   `/boot/config/smbpasswd`. If they disagree, re-set and copy to flash before
   clients reconnect (Mode 2).
5. **Scrub and reset.** After recovery, `btrfs scrub start /mnt/cache`, restore
   any corrupt file from backup, then `btrfs dev stats -z /mnt/cache` to reset
   the counter.

The data is safe on the array disks throughout — every mode here is a union,
credential, or cache-pool problem, not an array-data-loss problem.
