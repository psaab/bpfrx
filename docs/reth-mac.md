# Consistent RETH MAC Addresses

## Problem

In the HA cluster, RETH interfaces use VRRP on physical member interfaces (no bond devices). Each node has a different physical MAC on its RETH member interface, causing problems during failover:

1. **IPv6 link-local addresses differ** -- EUI-64 link-local (`fe80::...`) is derived from MAC. After failover, the new primary has a different link-local address, breaking neighbor caches on LAN hosts.
2. **Neighbor cache invalidation** -- Clients must update both VIP->MAC and gateway link-local->MAC mappings. Unsolicited NA only covers the VIP.
3. **`bpf_fib_lookup` smac** -- XDP forwarding uses `fib.smac` from the kernel. Different MACs mean forwarded packets have different source MACs after failover.

## Solution

Program a deterministic virtual MAC on RETH physical member interfaces at daemon startup. Both nodes present the same MAC for each RETH, making IPv6 link-local addresses identical and eliminating neighbor cache issues.

## MAC Format

```
02:bf:72:CC:RR:00
```

| Byte | Value | Meaning |
|------|-------|---------|
| 0 | `02` | Locally-administered unicast (U/L bit set) |
| 1 | `bf` | xpf identifier |
| 2 | `72` | ASCII 'r' (bpf**r**x) |
| 3 | `CC` | cluster_id (from config) |
| 4 | `RR` | redundancy_group_id |
| 5 | `00` | Reserved |

Example for cluster_id=1:
- reth0 (RG1): `02:bf:72:01:01:00` -> link-local `fe80::bf:72ff:fe01:100`
- reth1 (RG2): `02:bf:72:01:02:00` -> link-local `fe80::bf:72ff:fe01:200`

## Ordering

1. **`.link` files** (udev/networkd) -- match physical MAC for interface rename (e.g. enp6s0 -> ge-0-0-0)
2. **`networkctl reload`** -- applies the rename
3. **Virtual MAC** -- `netlink.LinkSetHardwareAddr()` programs the deterministic MAC
4. **VRRP `UpdateInstances()`** -- picks up new MAC via `net.InterfaceByName()`
5. **GARP/NA** -- automatically use the kernel MAC (called at send time)
6. **`bpf_fib_lookup`** -- automatically returns new MAC as `fib.smac`

## Rename Owns the Link UP (#3920)

A RETH member must be administratively DOWN to be renamed (kernel
requirement). `renameRethMember` therefore downs the link, renames it,
and then brings it back UP — the function that downs a link owns
bringing it back up.

It must NOT delegate the UP to the subsequent `programRethMAC`.
`programRethMAC` early-returns (no UP) when the virtual MAC already
matches, and that is precisely the situation after a rename:
`renameRethMember` locates the interface by matching that same virtual
MAC, so on a just-renamed member the MAC always already matches and
`programRethMAC` always no-ops. (A second facet: even in the MAC-change
path, `programRethMAC`'s fast path sets the MAC while the link is still
DOWN, which succeeds without a cycle and returns without an UP.) If the
UP were skipped, the RETH data link would be left DOWN → the interface
track detects link-down → the redundancy group demotes → traffic
blackhole.

There is no flap: whenever a rename happens the MAC already matches so
`programRethMAC` no-ops, leaving `renameRethMember`'s UP as the final
state; and even in the defensive case where `programRethMAC` does cycle,
the member still ends UP. Bringing the member UP before `programRethMAC`
also restores that function's live-address-change detection, which
requires an UP link to distinguish `IFF_LIVE_ADDR_CHANGE` drivers from
those that need a cycle.

## Deferred AF_XDP Worker Arming After a Live MAC Change (#5134)

Programming the virtual MAC can happen two ways:

- **Link cycle** (`programRethMAC` had to bring the member DOWN/UP): the old
  AF_XDP sockets die with the cycle. The daemon calls `NotifyLinkCycle()`,
  which sends `rebind` to the helper and recreates the workers with fresh
  sockets. This path arms the workers via the rebind, independent of the
  published snapshot's `DeferWorkers` flag.
- **Live MAC set** (`IFF_LIVE_ADDR_CHANGE` driver, or the fast path that sets
  the MAC while the link is still DOWN — no cycle): the initial dataplane
  apply of the commit ran with `SetDeferWorkers(true)` so worker startup was
  skipped (avoids the mlx5 zero-copy double-bind EBUSY). The published
  snapshot therefore carries `DeferWorkers=true` and is **workerless /
  non-forwarding**. The daemon then issues a MANDATORY second `ApplyConfig`
  (`reapplyAfterDeferredMAC`) with the correct MAC and `DeferWorkers` cleared —
  that re-apply is what actually starts the workers.

The re-apply is failure-critical. The userspace manager only advances its
snapshot bookkeeping (`lastSnapshot` / `publishedSnapshot` / `lastSnapshotHash`)
on a **successful** `apply_snapshot` publish. If the re-apply's publish fails
(helper rejects it, control-socket error, resource pressure) and the daemon
swallows the error, the manager keeps the workerless `DeferWorkers=true`
snapshot as the published/last state, status reconciliation replays it, the
workers never bind, and the commit still reports success — a silent forwarding
outage on that node.

**Contract:** `reapplyAfterDeferredMAC` never swallows the re-apply error. On
failure it records **generation debt** via `RecordDeferredWorkerArmDebt()`
(`Manager.pendingWorkerArm`). The 1 Hz status reconcile loop calls
`retryDeferredWorkerArmLocked()`, which republishes the retained snapshot with
`DeferWorkers=false` and a bumped generation until the workers bind, then clears
the debt. A transient helper error self-heals without failing the commit; the
node never terminally publishes a workerless snapshot while reporting success.

| File | Function |
|------|----------|
| `pkg/daemon/daemon_apply.go` | `reapplyAfterDeferredMAC()` — mandatory re-apply; records debt on failure |
| `pkg/daemon/daemon_apply.go` | `recordDataplaneWorkerArmDebt()` — routes the debt to the dataplane |
| `pkg/dataplane/userspace/manager_worker_arm_5134.go` | `RecordDeferredWorkerArmDebt()` / `retryDeferredWorkerArmLocked()` |
| `pkg/dataplane/userspace/process_status.go` | status loop drives the retry each tick |

## Reboot Safety

- Bootstrap `.link` files (from `setup.sh`) use the physical MAC for udev rename
- After daemon programs the virtual MAC, the kernel MAC changes
- On next `applyConfig()`, if the kernel MAC is a virtual RETH MAC (`02:bf:72:...`), the compiler skips writing a `.link` file for that interface
- This preserves the bootstrap `.link` file with the physical MAC
- On reboot, udev matches the physical MAC (NIC resets to factory MAC) and renames correctly
- Daemon starts and re-programs the virtual MAC

## Implementation

| File | Function |
|------|----------|
| `pkg/cluster/reth.go` | `RethMAC(clusterID, rgID)` -- returns deterministic MAC |
| `pkg/cluster/reth.go` | `IsVirtualRethMAC(mac)` -- detects virtual RETH pattern |
| `pkg/daemon/daemon_reth.go` | `renameRethMember()` -- renames a member found by virtual MAC (down → rename → **up**, #3920) |
| `pkg/daemon/daemon_reth.go` | `programRethMAC()` -- sets MAC via netlink (step 2.6 in applyConfig) |
| `pkg/dataplane/compiler.go` | Skips `.link` file when RETH member has virtual MAC |

## Impact

- **XDP forwarding**: `bpf_fib_lookup` automatically returns the virtual MAC as `fib.smac` -- no BPF changes needed
- **GARP/NA**: `net.InterfaceByName()` returns the virtual MAC -- no code changes needed
- **VRRP**: advertisements use the virtual MAC -- neighbor caches stay valid across failover
- **IPv6 link-local**: both nodes derive the same `fe80::bf:72ff:fe01:RR00` -- seamless failover
