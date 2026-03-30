# Failover Hardening Progress

## Problem Statement

Manual RG failover under sustained iperf3 -P 8 load (20+ Gbps) kills
existing TCP sessions. Traffic drops to 0 and never recovers. This must work
seamlessly — zero zero-throughput intervals, all streams surviving, across
repeated failover/failback cycles.

## Test Matrix

| Scenario | Status | Notes |
|----------|--------|-------|
| Both RGs to node1 (single cycle) | **PASS** | 0 zeros, 22→52Mbps dip→12 Gbps recovery |
| RG1-only to node1 (split-RG) | **FAIL** | Traffic dies permanently — fabric bottleneck |
| RG1 failover 10 cycles | **FAIL** | 120/132 zeros — same root cause |
| Crash recovery (sysrq-b) | **PASS** | 2s outage, sub-second with 100ms heartbeat |
| Crash + rejoin | **PASS** | 0 drops during rejoin |

## Root Causes Found and Fixed (8 total)

### 1. Event stream idle disconnect (FIXED, `19824440`)

Rust event stream I/O thread disconnected every 30s from Go read deadline
timeout. Added MSG_KEEPALIVE (type 10) every 10s. Go side ignores keepalive.

### 2. Bulk sync priming never completing (FIXED)

`syncPeerBulkPrimed` never becoming true due to event stream disconnect cycle.
Keepalive fix stabilized connection, allowing bulk ack to complete.

### 3. Manual failover demotion timeout too short (FIXED, `b2285a9c`)

5s timeout → 15s. Quiescence loop needs multiple barrier round-trips (~1-3s
each). Was consistently timing out at 5s.

### 4. HAInactive packets dropped as exceptions (FIXED, `96cca96d`)

`enforce_ha_resolution_snapshot` returns `HAInactive` for demoted-RG sessions.
Was treated as exception (recorded + dropped). Now converted to
`FabricRedirect` before the forward/drop branch in `poll_binding()`.

### 5. Synced sessions not re-resolved on new owner (FIXED, `96cca96d`)

`UpsertSynced` handler in session_glue.rs re-resolves egress using local
`ForwardingState` when the owner RG is locally active. Prevents using stale
remote node interface indices and MACs.

### 6. USERSPACE_SESSIONS BPF map stale on demotion (FIXED, `b22152fa`)

XDP shim found stale entries and redirected to XSK, bypassing eBPF fabric
redirect. Added USERSPACE_SESSIONS map flush before `rg_active=0` in Go
daemon's `UpdateRGActive()`. Also immediate shared_sessions cleanup in Rust
coordinator's `update_ha_state()`.

### 7. Flow cache serves stale decisions during HA transition (FIXED, `aeeccc7c`)

**The critical breakthrough.** Userspace flow cache serves cached
ForwardCandidate at line rate (~20 Gbps). HA state update goes through
synchronous RPC (~100ms under load). During this window, millions of packets
hit stale cache → TCP window collapse → permanent session death.

**Fix:** Disable ctrl + swap to `xdp_main_prog` BEFORE `rg_active=0`. The
eBPF pipeline checks `rg_active` per-packet (nanoseconds) and fabric-
redirects immediately. No flow cache, no RPC latency, no 100ms gap.

### 8. Promoting node also needs ctrl disable (FIXED, `ff2bf120`)

The promoting node (new owner) also has stale synced sessions in its flow
cache. Disabling ctrl on BOTH nodes during ANY RG transition ensures the eBPF
pipeline handles both sides correctly.

## Additional Fixes Found During Investigation

### 9. Ctrl re-enable after transition (IMPLEMENTED, not yet committed)

After disabling ctrl for the transition, the helper's liveness state is now
reset (`neighborsPrewarmed`, `xskLivenessProven`, `xskLivenessFailed`,
`xskProbeStart`, `lastXSKRX`, `ctrlWasEnabled`) so the status loop can
re-enable ctrl and swap back to `xdp_userspace_prog` once the helper
processes the HA update and XSK shows liveness.

### 10. UMEM frame leak on flow cache invalidation (FOUND by stream-fixer)

`afxdp.rs:2645` — when `cached_flow_decision_valid()` returns false, the
`continue` skipped frame recycle. Fixed by adding
`binding.scratch_recycle.push(desc.addr)` before continue.

### 11. Fabric jumbo frames for throughput (IMPLEMENTED, not yet tested)

Set MTU 9000 on fabric bridge + IPVLAN overlays + parent interfaces.
Expected ~6x improvement in fabric throughput (3-4 Gbps → 18-24 Gbps).

## Remaining Failure: Split-RG Fabric Throughput Cliff

### Root Cause (identified by fabric-investigator)

The fabric parent interface (ge-X-0-0) binds AF_XDP in **copy mode** because
the IPVLAN overlay (fab0/fab1) prevents the kernel from granting zerocopy.
The virtio_net driver rejects zerocopy when upper devices exist.

| Path | Mode | Throughput |
|------|------|-----------|
| Data interfaces (ge-X-0-1, ge-X-0-2) | Zerocopy | ~22 Gbps |
| Fabric parent (ge-X-0-0) with IPVLAN | Copy mode | ~3-4 Gbps |
| Raw kernel TCP over same bridge | TSO/GSO | ~44 Gbps |

When 8 TCP streams at 22 Gbps suddenly need the 3-4 Gbps fabric link during
split-RG failover, the massive congestion causes permanent TCP window collapse
on all streams.

### Proposed Fixes (not yet validated)

1. **Jumbo frames (MTU 9000)** — 6x fewer frames through TX ring → ~18-24 Gbps
2. **Delayed IPVLAN creation** — create IPVLAN after XSK bind to get zerocopy
3. **Remove IPVLAN** — put sync IP on parent, XDP shim passthrough for sync
4. **Both jumbo + zerocopy** — best practical option, ~20-25 Gbps expected

## Architecture of the HA Transition Fix

### Before (broken)
```
RG demotion:
1. rg_active[RG] = 0                  (BPF map, instant)
2. syncHAStateLocked()                 (RPC to helper, ~100ms under load)
3. Helper: update_ha_state             (stores HA state, sends worker commands)
4. Workers: DemoteOwnerRG              (invalidate flow cache, delete BPF entries)

During steps 2-4 (~100ms): flow cache serves stale ForwardCandidate → TCP death
```

### After (working for same-node failover)
```
RG transition (BOTH nodes):
1. ctrl = 0                            (BPF map, instant)
2. SwapXDPEntryProg(xdp_main)          (BPF prog swap, instant)
   → ALL packets go through eBPF pipeline
3. rg_active[RG] = 0/1                 (BPF map, instant)
   → eBPF checks rg_active → fabric redirect for inactive RGs
4. syncHAStateLocked                   (RPC, can be slow now)
5. Helper processes demotion            (eventual consistency)
6. Status loop re-enables ctrl          (when XSK liveness proven)
```

## Commits (chronological)

| Commit | Description |
|--------|-------------|
| `19824440` | Event stream keepalive + idle disconnect fix |
| `b22152fa` | USERSPACE_SESSIONS flush + HAInactive fabric redirect (WIP) |
| `b2285a9c` | Demotion timeout 5s→15s + HA tracing |
| `96cca96d` | Synced session re-resolution + HAInactive→FabricRedirect |
| `aeeccc7c` | **Breakthrough: disable ctrl + swap to eBPF before demotion** |
| `ff2bf120` | Disable ctrl on BOTH nodes during RG transition |
| `90371473` | Failover hardening progress doc (first version) |
| `e3d093c5` | Comprehensive progress doc with all findings |

## Files Modified

### Go daemon (`pkg/daemon/daemon.go`)
- `prepareUserspaceManualFailover`: timeout 5s → 15s
- Kernel session journal during demotion prep (flush before barrier)

### Go userspace manager (`pkg/dataplane/userspace/manager.go`)
- `UpdateRGActive()`: disable ctrl + swap to eBPF on BOTH activation and demotion
- USERSPACE_SESSIONS BPF map flush before rg_active=0
- Liveness state reset after RG transition (ctrl re-enable support)

### Rust coordinator (`userspace-dp/src/afxdp.rs`)
- `update_ha_state()`: immediate USERSPACE_SESSIONS cleanup for demoted RGs
- HAInactive → FabricRedirect conversion before forward/drop branch
- `let mut decision` for mutability during HA redirect
- HA disposition tracing and logging

### Rust session glue (`userspace-dp/src/afxdp/session_glue.rs`)
- `UpsertSynced`: re-resolve egress for locally-active RGs
- `DemoteOwnerRG`: logging for session counts and demoted counts
- UMEM frame recycle on flow cache invalidation

### Rust event stream (`userspace-dp/src/event_stream.rs`)
- MSG_KEEPALIVE (type 10) sent every 10s during idle
- Improved FullResync logging with acked_seq and oldest_buffered

### Go event stream (`pkg/dataplane/userspace/eventstream.go`)
- Handle MSG_KEEPALIVE frames (no-op)

### Go protocol (`pkg/dataplane/userspace/protocol.go`)
- Added EventTypeKeepalive constant

### Fabric (`pkg/daemon/daemon.go`, `test/incus/cluster-setup.sh`)
- MTU 9000 on fabric IPVLAN + parent + bridge (not yet validated)
