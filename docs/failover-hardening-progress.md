# Failover Hardening Progress

## Problem Statement

Manual RG failover under sustained iperf3 -P 8 load (20+ Gbps) kills
existing TCP sessions. Traffic drops to 0 and never recovers. This must work
seamlessly — zero zero-throughput intervals, all streams surviving.

## Root Causes Found and Fixed

### 1. Event stream idle disconnect (FIXED, `19824440`)

The Rust event stream I/O thread disconnected every 30s due to Go-side read
deadline timeout. Added MSG_KEEPALIVE (type 10) sent every 10s from Rust.
Go side handles keepalive as no-op.

### 2. Bulk sync priming never completing (FIXED, event stream keepalive)

`syncPeerBulkPrimed` was never becoming true because the event stream kept
disconnecting and reconnecting, preventing bulk sync from completing. The
keepalive fix stabilized the connection, allowing bulk ack to flow.

### 3. Manual failover demotion timeout too short (FIXED, `b2285a9c`)

Demotion prep timeout was 5 seconds. The quiescence loop needs multiple
barrier round-trips (~1-3s each) and was consistently timing out. Increased
to 15 seconds.

### 4. HAInactive packets dropped as exceptions (FIXED, `96cca96d`)

When a session's owner RG is demoted, `enforce_ha_resolution_snapshot`
returns `HAInactive`. This was treated as an exception (recorded + dropped)
instead of redirecting to fabric. Added HAInactive → FabricRedirect
conversion before the forward/drop branch in `poll_binding()`.

### 5. Synced sessions not re-resolved on new owner (FIXED, `96cca96d`)

Synced sessions arrive with the remote node's egress interface indices and
MACs. When the owner RG activates locally, the `UpsertSynced` handler now
re-resolves egress using local `ForwardingState` instead of keeping stale
remote resolution.

### 6. USERSPACE_SESSIONS BPF map not flushed on demotion (FIXED, `b22152fa`)

The XDP shim finds sessions in `USERSPACE_SESSIONS` and redirects to XSK,
bypassing the eBPF pipeline's `rg_active` check and fabric redirect. Added
map flush before `rg_active=0` in the Go daemon's `UpdateRGActive()`. Also
added immediate shared_sessions cleanup in the Rust coordinator.

### 7. Flow cache serves stale decisions during HA transition (ROOT CAUSE, `aeeccc7c`)

**This was the critical bug.** The userspace flow cache serves cached
`ForwardCandidate` decisions at line rate (~20 Gbps). After RG demotion, the
flow cache should invalidate via `cached_flow_decision_valid()`. But:

- The HA state update goes through a synchronous RPC (single-use Unix socket
  JSON) to the Rust helper.
- The helper's control socket uses nonblocking accept with 100ms poll.
- Under 20+ Gbps load, the RPC takes ~100ms to be processed.
- During this 100ms window, the flow cache serves millions of packets with
  stale ForwardCandidate decisions (old egress, wrong node).
- TCP suffers massive retransmits from these 100ms of misdirected packets.
- TCP windows collapse to minimum (1.41 KB) and never recover.

**Fix:** Disable the userspace ctrl flag AND swap to `xdp_main_prog` (eBPF
pipeline entry) BEFORE setting `rg_active=0`. The eBPF pipeline checks
`rg_active` in real-time per-packet (single BPF map lookup, ~nanoseconds)
and redirects to fabric immediately via `try_fabric_redirect()`. No flow
cache, no RPC latency, no 100ms gap.

Sequence: `ctrl=0` → `SwapXDPEntryProg("xdp_main_prog")` → `rg_active=0` →
sync to helper (eventually).

Result: Zero zero-throughput intervals. Sessions survive failover. Throughput
drops from 22 Gbps (userspace) to 12 Gbps (eBPF pipeline) during transition,
then should recover when userspace ctrl re-enables.

## Current Test Results

### Single RG failover (both RGs to node1)
```
Seconds 1-11:  21-22 Gbits/sec (fw0, userspace DP)
Second 12:     52 Mbits/sec    (transition dip)
Second 13:     3.8 Gbits/sec   (recovery starting)
Seconds 14-40: 11-12 Gbits/sec (fw1, eBPF pipeline)
Zero intervals: 0
```

### Known Remaining Issues

1. **Throughput drops from 22 to 12 Gbps after failover** — The ctrl disable
   + eBPF swap is not reversed after the helper processes demotion. The
   helper's status loop should re-enable ctrl once XSK bindings are ready on
   the new owner. Need to implement ctrl re-enable after demotion settles.

2. **Per-stream zero intervals** — Some individual streams may hit 0 while
   others sustain multi-Gbps. The aggregate SUM may be non-zero but
   per-stream health varies. Need per-stream analysis.

3. **Multi-cycle failover** — Single failover passes but repeated
   failover/failback cycles may accumulate state (stale sessions, flow cache
   pollution, synced session conflicts). Need 10+ iteration stress test.

4. **Ctrl re-enable timing** — After disabling ctrl for the transition, when
   should it re-enable? Too early = stale flow cache. Too late = permanent
   eBPF pipeline (lower throughput). Need the helper to signal readiness.

5. **Reverse path on new owner** — Server replies arrive at the new WAN owner
   (fw1). fw1 needs synced reverse sessions to be correctly resolved for the
   LAN path (back to fw0 via fabric if split-RG, or directly if both RGs on
   fw1).

## Architecture of the Fix

### Before (broken)
```
RG demotion sequence:
1. Go daemon: rg_active[1] = 0         (BPF map, instant)
2. Go daemon: syncHAStateLocked()      (RPC to helper, ~100ms under load)
3. Helper: update_ha_state()           (stores HA state, sends worker commands)
4. Workers: process DemoteOwnerRG      (invalidate flow cache, delete BPF entries)

During steps 2-4 (~100ms): flow cache serves stale ForwardCandidate → TCP collapse
```

### After (working)
```
RG demotion sequence:
1. Go daemon: ctrl = 0                 (BPF map, instant)
2. Go daemon: SwapXDPEntryProg         (BPF prog swap, instant)
   → ALL packets now go through eBPF pipeline
3. Go daemon: rg_active[1] = 0         (BPF map, instant)
   → eBPF pipeline checks rg_active per-packet → fabric redirect
4. Go daemon: syncHAStateLocked()      (RPC to helper, can be slow)
5. Helper: update_ha_state()           (eventual consistency)
6. Workers: process DemoteOwnerRG      (cleanup, not time-critical)

During steps 4-6: eBPF pipeline handles all traffic correctly via rg_active + fabric redirect
```

## Files Modified

### Go daemon (`pkg/daemon/daemon.go`)
- `prepareUserspaceManualFailover`: increased timeout 5s → 15s
- Kernel session journal during demotion prep (flush before barrier)

### Go userspace manager (`pkg/dataplane/userspace/manager.go`)
- `UpdateRGActive()`: disable ctrl + swap to eBPF before rg_active=0

### Rust coordinator (`userspace-dp/src/afxdp.rs`)
- `update_ha_state()`: immediate USERSPACE_SESSIONS cleanup for demoted RGs
- HAInactive → FabricRedirect conversion before forward/drop branch
- HA disposition tracing and logging

### Rust session glue (`userspace-dp/src/afxdp/session_glue.rs`)
- `UpsertSynced`: re-resolve egress for locally-active RGs
- `DemoteOwnerRG`: logging for session counts and demoted counts

### Rust event stream (`userspace-dp/src/event_stream.rs`)
- MSG_KEEPALIVE (type 10) sent every 10s during idle
- Improved FullResync logging

### Go event stream (`pkg/dataplane/userspace/eventstream.go`)
- Handle MSG_KEEPALIVE frames (no-op)

### Go protocol (`pkg/dataplane/userspace/protocol.go`)
- Added EventTypeKeepalive constant

## Commits

| Commit | Description |
|--------|-------------|
| `19824440` | Event stream keepalive + idle disconnect fix |
| `b22152fa` | USERSPACE_SESSIONS flush + HAInactive fabric redirect (WIP) |
| `b2285a9c` | Demotion timeout increase + HA tracing |
| `96cca96d` | Synced session re-resolution + HAInactive fabric redirect |
| `aeeccc7c` | **Breakthrough: disable ctrl + swap to eBPF before demotion** |
