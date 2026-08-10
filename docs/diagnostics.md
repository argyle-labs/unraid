# Unraid storage diagnostics — proposed capabilities

Field notes from a real incident (2026-08-10) on an unraid NAS where ZFS-on-array
corruption wedged NFS and took down a downstream Plex server. Each mode below is
something this plugin **should detect and/or remediate** but does not yet. They
are written as an implementation spec, not as documentation of shipped behaviour.

The array in question: each data disk is a **single-vdev ZFS pool on an unraid md
device** (`diskN` = `mdNp1`, `diskFsType=zfs`). Redundancy lives at unraid's
md/parity layer, invisible to ZFS — so ZFS has **no way to self-heal** a bad
block, while still carrying ZFS's full crash surface. This layout is an
anti-pattern worth flagging on its own.

---

## 1. ZFS pool corruption (no self-heal on single-vdev-on-md)

**Symptom.** `zpool status -v diskN` reports CKSUM errors and:

```
errors: Permanent errors have been detected in the following files:
        /mnt/disk1/data/.../<file>
        disk1/data@<snap>:/.../<file>
```

**Detection.** Parse `zpool status -x` (fast, "all pools healthy" or names the
sick ones) and `zpool status -v <pool>` for the permanent-error file list and
per-vdev READ/WRITE/CKSUM counters. Non-zero CKSUM on a single-vdev pool =
unrepairable by ZFS; the block must be restored from a replica.

**Remediation.** Restore the affected file(s) from a healthy replica, then
`zpool clear <pool>`. If the bad block is also pinned by a **snapshot**, the
snapshot must be `zfs destroy`ed too — overwriting the live file alone leaves the
snapshot reference and the error persists. Verify the restored file's checksum
against the replica **after** writing (a bad-RAM box can corrupt the write
itself). A clean `zpool status` without a completed scrub is provisional — run
one scrub once the hardware cause is ruled out.

## 2. ZFS read-path kernel Oops → NFS serves bad handles

**Symptom.** `dmesg` shows a NULL-pointer deref in the ZFS read path:

```
BUG: kernel NULL pointer dereference ... zio_vdev_io_assess+0x5b [zfs]
```

Downstream: NFS clients log `NFS: server <ip> error: fileid changed` and hard
mounts stall; anything reading the bad file (e.g. Plex transcode) wedges.

**Detection.** Scan the kernel ring buffer for `zio_`, `NULL pointer`,
`z_rd_int`, and `deadman` strings. This is a **read-path** fault triggered by
reading a corrupt block — correlate it with the pool's permanent-error list.

**Remediation.** Removing the bad block (mode 1) removes the trigger. The
orphaned in-flight zio from the Oops does **not** clear at runtime — it takes a
reboot. Detect the orphan as a `txg_sync` process stuck in `D` (uninterruptible)
state (mode 4).

## 3. ZFS deadman — hung I/O > 60s

**Symptom.** I/O to a pool stops making progress; `zpool events` shows
`ereport.fs.zfs.deadman`.

**Detection.** Poll `zpool events` for `deadman` classes and watch for stalled
`txg` progress. Deadman firing = the pool has I/O that has been outstanding
longer than `zfs_deadman_synctime_ms` — a hang, not a slow disk.

**Remediation.** Notify immediately; a deadman-hung pool will hang every client
that touches it. If the cause is an orphaned zio (mode 2), only a reboot clears
it — fail dependent services over to a replica first.

## 4. `txg_sync` / nfsd stuck in D-state (uninterruptible)

**Symptom.** `zpool scrub -s`, array stop, and even `kill -9` do nothing to a
`txg_sync` or `nfsd` thread; a graceful reboot hangs on array stop.

**Detection.** `ps -eo pid,stat,comm | awk '$2 ~ /D/'` — any `txg_sync` /
`nfsd` / `z_*` thread in `D` for more than a few seconds is wedged. TCP reachable
and `showmount` answering does **not** mean the server is healthy — v4 I/O can be
wedged while the port still accepts connections (see the nfs plugin's
`failover-and-release.md`, "hang ≠ down").

**Remediation.** These require a reboot to clear. Because a graceful stop hangs
on the wedged thread, arm a `sysrq-b` failsafe before issuing `reboot` so the box
comes back rather than hanging indefinitely. Only reboot after dependents are on
a replica.

## 5. Scan storm (concurrent scrubs + parity check)

**Symptom.** Load spikes; corruption-triggered Oopses become far more likely.

**Detection.** Count active `zpool scrub` operations across pools plus
`mdcmd status` `mdResyncAction` (a running parity `check`). Multiple scrubs **and**
a parity check at once hammer the same spindles and repeatedly hit bad blocks.

**Remediation.** Serialize: never run more than one scrub, and never a scrub
concurrently with a parity check. Cancel with `zpool scrub -s <pool>` and
`mdcmd nocheck`. If a scrub won't cancel, its pool is wedged (mode 4).

## 6. Multi-disk simultaneous corruption ⇒ systemic cause (RAM/controller/power)

**Symptom.** More than one disk shows CKSUM errors at the same time; ZFS *and*
btrfs device stats both report corruption.

**Detection.** When corruption appears on multiple independent devices in the
same window, do **not** conclude "N disks are failing." Simultaneous multi-device
corruption points at a shared component: non-ECC RAM in a bad config, the HBA, or
power. Surface SMART (clean SMART + multi-disk corruption strongly implicates
RAM) and the DIMM layout (asymmetric channel population, XMP instability).

**Remediation.** Flag for an **offline RAM test** (Memtest86+, built into unraid's
boot menu — UEFI-capable). Do not trust `zpool clear` or a scrub until the memory
is proven good; a bad-RAM box re-corrupts what it repairs.
