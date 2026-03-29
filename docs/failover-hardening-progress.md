# Failover Hardening Progress

## Problem Statement

Manual RG failover under sustained iperf3 -P 8 load (20+ Gbps) kills
existing TCP sessions. Traffic drops to 0 and never recovers. This must work
seamlessly — zero zero-throughput intervals, all streams surviving, across
repeated failover/failback cycles.

## Test Matrix

| Scenario | Status | Notes |
|----------|--------|-------|
| Both RGs to node1 (single cycle) | **PASS** | 0 zeros, 22→12 Gbps |
| RG1-only to node1 (split-RG, single) | **FAIL** | Traffic dies permanently |
| RG1 failover 10 cycles | **FAIL** | 120/132 zeros |
| Crash recovery (sysrq-b) | **PASS** | 2s outage, sub-second with 100ms heartbeat |
| Crash + rejoin | **PASS** | 0 drops during rejoin |

## Root Causes Found and Fixed

### 1. Event stream idle disconnect (FIXED, `19824440`)

Rust event stream I/O thread disconnected every 30s from Go read deadline
timeout. Added MSG_KEEPALIVE (type 10) every 10s. Go side ignores keepalive.

### 2. Bulk sync priming never completing (FIXED)

`syncPeerBulkPrimed` never becoming true due to event stream disconnect cycle.
Keepalive fix stabilized connection.

### 3. Manual failover demotion timeout too short (FIXED, `b2285a9c`)

5s timeout → 15s. Quiescence loop needs multiple barrier round-trips.

### 4. HAInactive packets dropped as exceptions (FIXED, `96cca96d`)

`enforce_ha_resolution_snapshot` returns `HAInactive` for demoted-RG sessions.
Was treated as exception (dropped). Now converted to `FabricRedirect` before
the forward/drop branch in `poll_binding()`.

### 5. Synced sessions not re-resolved on new owner (FIXED, `96cca96d`)

`UpsertSynced` handler re-resolves egress using local `ForwardingState` when
the owner RG is locally active. Prevents using stale remote interface indices.

### 6. USERSPACE_SESSIONS BPF map stale on demotion (FIXED, `b22152fa`)

XDP shim found stale entries and redirected to XSK, bypassing eBPF fabric
redirect. Added map flush before `rg_active=0`. Also immediate
shared_sessions cleanup in Rust coordinator.

### 7. Flow cache serves stale decisions during transition (ROOT CAUSE, `aeeccc7c`)

**The critical fix.** Userspace flow cache serves cached ForwardCandidate at
line rate. HA state update goes through synchronous RPC (~100ms under load).
During this window, millions of packets hit stale cache → TCP collapse.

**Fix:** Disable ctrl + swap to `xdp_main_prog` BEFORE `rg_active=0`. The
eBPF pipeline checks `rg_active` per-packet (nanoseconds) and fabric-
redirects immediately. No flow cache, no RPC latency.

### 8. Promoting node also needs ctrl disable (FIXED, `ff2bf120`)

The promoting node (new owner) also has stale synced sessions in its flow
cache. Disabling ctrl on both nodes during ANY RG transition ensures the eBPF
pipeline handles both sides of the transition.

## Remaining Failure: Split-RG Fabric Throughput Cliff

### Symptom

When only RG1 (WAN) moves to node1 while RG2 (LAN) stays on node0, existing
8-stream TCP sessions at 22 Gbps die permanently. ALL 8 streams go to zero.

### Root Cause

The fabric link between nodes can carry ~3-4 Gbps. When 8 TCP streams at
22 Gbps suddenly need to traverse the fabric (split-RG), the massive
congestion causes:

1. Thousands of packet drops at the fabric bottleneck
2. TCP retransmit timeouts on all 8 streams simultaneously
3. TCP windows collapse to minimum (1.41 KB)
4. TCP slow start from minimum window takes too long
5. Streams never recover because the fabric can't sustain the aggregate demand

### Why Same-Node Failover Works

When BOTH RGs move together, traffic stays on one node (no fabric). The path
is: host → fw1 (LAN) → fw1 (WAN) → server, all same-node. Throughput drops
from 22 Gbps (userspace DP) to 12 Gbps (eBPF pipeline) but TCP survives.

### Possible Fixes

1. **Always move both RGs together** — eliminates fabric path entirely. But
   defeats the purpose of per-RG active-active.

2. **Improve fabric throughput** — the fabric is a virtio/IPVLAN overlay.
   Current limit is ~3-4 Gbps. Needs investigation into whether this is a
   NIC ring size, NAPI budget, or IPVLAN overhead issue.

3. **TCP-aware fabric congestion management** — instead of dropping packets at
   the fabric bottleneck, queue them with ECN marking so TCP backs off
   gracefully instead of collapsing.

4. **Gradual traffic migration** — instead of instant RG move, gradually shift
   traffic from one node to the other to prevent the congestion spike.

5. **Keep existing sessions on the old node during split-RG** — the old owner
   continues forwarding existing sessions via its now-inactive RG while the
   new owner handles new sessions. Sessions naturally drain as they expire.

## Commits

| Commit | Description |
|--------|-------------|
| `19824440` | Event stream keepalive + idle disconnect fix |
| `b22152fa` | USERSPACE_SESSIONS flush + HAInactive fabric redirect (WIP) |
| `b2285a9c` | Demotion timeout increase + HA tracing |
| `96cca96d` | Synced session re-resolution + HAInactive fabric redirect |
| `aeeccc7c` | **Breakthrough: disable ctrl + swap to eBPF before demotion** |
| `ff2bf120` | Disable ctrl on BOTH nodes during RG transition |

## Architecture

### RG Transition Sequence (Current)

```
1. Go daemon: ctrl = 0 on BOTH nodes        (BPF map, instant)
2. Go daemon: SwapXDPEntryProg(xdp_main)     (BPF prog swap, instant)
   → ALL packets on BOTH nodes go through eBPF pipeline
3. Go daemon: rg_active[RG] = 0/1            (BPF map, instant)
   → eBPF pipeline checks rg_active → fabric redirect for inactive RGs
4. Go daemon: syncHAStateLocked              (RPC, can be slow)
5. Helper: update_ha_state                   (eventual)
6. Helper status loop: re-enables ctrl       (when XSK ready)
```

### What Passes vs Fails

| Test | ctrl disable | Both RGs | Split RG | Result |
|------|-------------|----------|----------|--------|
| Before all fixes | No | N/A | N/A | 28 zeros |
| ctrl disable on demotion only | Demoting node | PASS (0 zeros) | FAIL (120 zeros) |
| ctrl disable on both nodes | Both nodes | PASS (0 zeros) | FAIL (120 zeros) |

The split-RG failure is NOT a ctrl/flow-cache issue — it's a fabric
throughput constraint. The eBPF pipeline correctly redirects to fabric, but
the fabric can't carry 22 Gbps.

## Event Stream Status

Phase 1 of the session sync redesign is complete:
- Binary event stream over Unix socket (Rust → Go)
- 10 frame types including keepalive
- Sequence numbers + replay buffer
- Ack/Pause/Resume/DrainRequest flow control
- Integrated with demotion prep
- Automatic fallback to RPC polling when disconnected

The event stream is NOT used for HA state transitions — those still go through
the JSON RPC control socket. Could be optimized to use the event stream for
lower latency.

## Files Modified (Full List)

### Go
- `pkg/daemon/daemon.go` — demotion timeout, kernel session journal, sync readiness
- `pkg/dataplane/userspace/manager.go` — ctrl disable on RG transition, USERSPACE_SESSIONS flush
- `pkg/dataplane/userspace/eventstream.go` — keepalive handling
- `pkg/dataplane/userspace/protocol.go` — EventTypeKeepalive

### Rust
- `userspace-dp/src/afxdp.rs` — HAInactive→FabricRedirect, immediate shared_sessions cleanup, HA tracing
- `userspace-dp/src/afxdp/session_glue.rs` — UpsertSynced re-resolution, DemoteOwnerRG logging
- `userspace-dp/src/event_stream.rs` — MSG_KEEPALIVE, improved FullResync logging

### Docs
- `docs/failover-hardening-progress.md` — this document
