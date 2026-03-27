# Power Cycle Recovery Bugs (2026-03-27)

Three related bugs found during hard-crash (sysrq-trigger) testing of the HA
cluster on the loss (mlx5 SR-IOV) environment.

---

## Bug 1: Heartbeat Socket Invalidation on VRF Rebind — FIXED

**Severity:** Critical (dual-primary / split-brain on power cycle recovery)
**Affected code:** `pkg/cluster/cluster.go`, `pkg/daemon/daemon.go`
**Status:** Fixed and deployed

### Symptom

After a power cycle of the primary node, both nodes declared themselves primary
— split-brain. The 30-second heartbeat grace period delayed it but could not
prevent it.

### Root Cause

The heartbeat UDP sockets are bound to `vrf-mgmt` via `SO_BINDTODEVICE`. During
DHCP-triggered recompile, `networkd.Apply()` strips VRF bindings from em0, then
step 2.7 of `applyConfig()` re-binds em0 to vrf-mgmt. The existing heartbeat
sockets were created before this disruption and become permanently deaf — the
kernel doesn't retroactively fix socket routing when interfaces move between
VRFs.

### Timeline

```
23:56:46.691  heartbeat started (socket bound to vrf-mgmt)
23:56:46.760  peer heartbeat received (ONE packet — socket works initially)
23:56:48.xxx  DHCP recompile: networkd strips em0 from vrf-mgmt then re-binds
              ... socket dead — no more packets received ...
23:57:16.692  30s grace expires → peer marked lost → SPLIT-BRAIN
```

### Fix

1. Added `hbLocalAddr`, `hbPeerAddr`, `hbVRFDevice` fields to `Manager` struct
   to remember heartbeat connection parameters.

2. Added `RestartHeartbeat()` method — stops old sender/receiver, opens fresh
   sockets with same params. Retries up to 5× with 1s delay if bind fails
   (IP may briefly disappear during VRF transition).

3. After VRF re-bind in `applyConfig()` step 2.7, call
   `d.cluster.RestartHeartbeat()` to replace the dead sockets.

### Verification

```
00:08:56.102  heartbeat started
00:08:56.159  peer heartbeat received (works)
00:09:00.750  restarting heartbeat after VRF rebind
00:09:00.753  heartbeat started (fresh sockets)
              ... NO timeout, NO peer-lost — heartbeat continues ...
```

Power cycle test: node0 crashed, node1 took primary. node0 recovered as
secondary. No split-brain. Heartbeat survived two consecutive VRF rebinds.

---

## Bug 2: XSK Rebind EBUSY After RETH MAC Programming — FIXED

**Severity:** Critical (userspace dataplane permanently dead after boot)
**Affected code:** `pkg/daemon/daemon.go`, `pkg/dataplane/userspace/manager.go`, `pkg/dataplane/userspace/protocol.go`, `userspace-dp/src/main.rs`, `userspace-dp/src/afxdp.rs`
**Status:** Fixed — three-part fix eliminates the EBUSY on cold boot

### Symptom

fw1's userspace dataplane shows `allBindingsBound=false` permanently after
startup. The `xdp_main_prog` (eBPF pipeline) is active instead of
`xdp_userspace_prog`. This was the actual cause of "traffic went to 0" on
failover — fw1 had VIPs but was forwarding through the slower eBPF path.

### Root Cause

During startup, the daemon creates XSK bindings (all 18 succeed), then
immediately triggers a RETH MAC link cycle via `PrepareLinkCycle()` →
`NotifyLinkCycle()`. The rebind attempts to create new XSK sockets on the
same NIC queues, but gets:

```
xsk_socket__create_shared(flags=0x000c): Device or resource busy
```

on every queue (mlx5 zero-copy). The copy-mode fallback also fails with EBUSY.
24 consecutive EBUSY errors across two rebind attempts, zero successful
bindings. The workers are running but have no sockets — dead.

### Why EBUSY

mlx5 zero-copy XSK binds exclusively to a hardware queue. When the old sockets
are closed, the kernel should release the queue's XSK context. But the release
may be asynchronous — the old FD is closed, the worker join completes, but the
kernel hasn't finished tearing down the DMA mapping. The new bind arrives before
the queue is free.

The copy-mode (generic) fallback also fails because mlx5 may still hold the
queue in zero-copy mode during the transition.

### Fix (three parts)

**Part A: Skip spurious NotifyLinkCycle when MAC hasn't changed.**

The 2.6b2 step called `NotifyLinkCycle()` unconditionally for any cluster
config. On restarts where the RETH MAC was already set (from previous boot),
this triggered a completely unnecessary rebind. Fixed by gating on
`needLinkCycleRecovery || rethMACPending`.

**Part B: Defer worker startup when RETH MAC change is imminent.**

Added `DeferWorkers` flag to `ConfigSnapshot`. Before `Compile()`, the daemon
pre-checks whether any RETH MAC change is needed. If yes, sets
`deferWorkers=true` on the snapshot. The Rust helper sees this flag and skips
`reconcile_status_bindings()` — workers are planned but not started. The
first `NotifyLinkCycle()` after MAC programming sends `rebind` which starts
workers for the first time, binding to queues that were never previously held.

**Part C: Increase EBUSY retry window.**

For the DHCP-triggered recompile (which does a second rebind while the first
is still settling), increased retry parameters:
- `BIND_RETRY_DELAY`: 50ms → 250ms
- `BIND_RETRY_ATTEMPTS`: 10 → 20
- `NotifyLinkCycle` delay: 200ms → 1s

Total retry window: 1s + 20×250ms = 6s (was 200ms + 500ms = 700ms).

### Verification

Both fw0 and fw1 now show `allBindingsBound=true` and
`xdpEntryProg=xdp_userspace_prog` after startup. iperf3: 14+ Gbps through
the userspace dataplane.

---

## Bug 3: Fabric Peer Neighbor Missing After Recovery — FIXED

**Severity:** High (recovering node stays "not ready" — can't take primary)
**Affected code:** `pkg/daemon/daemon.go` (fabric probe + refresh)
**Status:** Fixed — IPv6 NDP multicast fallback for fabric peer discovery

### Symptom

After fw0 recovers from a crash, the fabric IPVLAN overlay (fab0) cannot find
the peer's ARP entry (10.99.13.2). All RGs stay "not ready" with reason
`fabric forwarding path not ready`. The fabric refresh retries every 4 seconds
but never succeeds.

### Root Cause

The fabric overlay `fab0` is an IPVLAN child of ge-0-0-0. After a crash
reboot, ge-0-0-0 comes up but the ARP entry for the peer (10.99.13.2) doesn't
exist. The daemon's "proactive neighbor resolution" tries to resolve it but the
peer may not respond to ARP on the IPVLAN overlay (it's a point-to-point
config).

Additionally, the RETH MAC change on ge-0-0-0 may invalidate existing neighbor
entries on the peer side, and the IPVLAN overlay uses the parent's MAC for ARP
which changes with RETH MAC programming.

### Log Evidence

```
00:13:38.406  fabric refresh failed (missing peer neighbor) peer=10.99.13.2
00:13:41.918  fabric refresh failed (missing peer neighbor) — retry
00:13:43.919  fabric refresh failed (missing peer neighbor) — retry
              ... continues every ~4s indefinitely ...
```

### Fix

Added IPv6 NDP multicast as a fallback for fabric peer MAC discovery:

1. **`sendIPv6MulticastProbe()`**: sends ICMPv6 echo to `ff02::1` (all-nodes
   link-local multicast) on the fabric overlay. This is more reliable than
   unicast ARP because multicast always works at L2 regardless of IPVLAN
   state or stale MAC caches.

2. **IPv6 neighbor table fallback in `refreshFabricFwd()`**: if IPv4 ARP
   lookup fails, checks the IPv6 NDP neighbor table on the same overlay
   interface. Finds any non-local link-local neighbor entry — that's the
   peer. Uses its MAC for the `fabric_fwd` BPF map entry.

### Why IPv6 multicast works when ARP fails

After crash recovery with RETH MAC changes:
- IPv4 ARP is unicast to a specific IP — if the peer's ARP table has a stale
  MAC, or the IPVLAN overlay doesn't forward the ARP correctly, resolution
  fails silently
- IPv6 NDP uses multicast solicitation — `ff02::1` reaches ALL nodes on the
  link at L2, bypassing any unicast forwarding issues
- Link-local addresses are always present (kernel auto-configures them)
- The peer's response populates the NDP table with its current MAC

---

## Combined Impact

When all three bugs fire together during a power cycle:

1. fw0 (primary) crashes
2. fw1 takes all RGs (VRRP MASTER) — but its userspace DP has been dead since
   boot (Bug 2: EBUSY). Traffic goes through eBPF pipeline.
3. fw0 recovers, heartbeat restarts correctly (Bug 1: fixed). But fabric never
   comes up (Bug 3: missing peer neighbor).
4. fw0 stays "not ready" forever. fw1 continues serving traffic via eBPF
   fallback at degraded performance.

### Priority

Bug 2 (XSK EBUSY) is the most impactful — it means the secondary node is never
running the userspace dataplane, so failover always hits the slower eBPF path.
Fixing the double-bind (option 3: skip initial bind before RETH MAC) would
eliminate this entirely.
