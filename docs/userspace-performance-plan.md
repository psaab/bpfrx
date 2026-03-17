# Userspace AF_XDP Dataplane: Performance and Correctness Hardening Plan

Date: 2026-03-17

This document is the phased execution plan for addressing ten identified issues
in the Rust AF_XDP userspace dataplane, organized by priority. It builds on the
completed cleanup work in [userspace-dataplane-cleanup-plan.md](userspace-dataplane-cleanup-plan.md)
(Phases 1-5 complete, Phase 6 in progress) and the HA failover work in
[userspace-ha-failover-parity-plan.md](userspace-ha-failover-parity-plan.md).

## Status Snapshot

All issues described here were identified via code audit on 2026-03-17 against
current `master`. No fixes have been started.

## Issue Inventory

### CRITICAL

| ID | Issue | Location | Impact |
|----|-------|----------|--------|
| C1 | TX backpressure starves fill ring | `poll_binding()` backpressure path | Fill ring exhausts under burst; kernel fallback emits RSTs |
| C2 | Hot-path lock contention on shared state | `Arc<Mutex<>>` on shared sessions + neighbors | Per-packet mutex across all workers; contention at scale |

### HIGH

| ID | Issue | Location | Impact |
|----|-------|----------|--------|
| H1 | In-flight TX timeout missing | `in_flight_prepared_recycles` in tx.rs | Kernel never completing TX → permanent UMEM frame leak |
| H2 | Session sync race between shared map and BPF map | `upsert_synced_session()` | Window during HA failover where BPF/shared maps disagree |
| H3 | Incomplete reverse session metadata | `build_reverse_session_from_forward_match()` | Routing table + DSCP lost on reverse path |
| H4 | SYN cookies not implemented | screen.rs | SYN flood protection degrades to rate-limiting only |

### MEDIUM

| ID | Issue | Location | Impact |
|----|-------|----------|--------|
| M1 | Cross-binding forwards always copy (2x memcpy) | `enqueue_pending_forwards()` | Performance: extra memcpy on every cross-interface forward |
| M2 | Session lifecycle mismatch userspace vs BPF | `expire_stale()` + BPF map | Stale BPF map entries after session expiry or crash |
| M3 | Frame ownership audit for all paths | `enqueue_pending_forwards()` all `continue` paths | Verify no other NAT64-style frame leaks exist |
| M4 | No frame leak detection in production builds | Frame accounting debug-gated | Progressive exhaustion invisible until stall |

## Phase 1: Fill Ring Starvation Fix (C1)

Status: Not Started

### Root Cause

In `poll_binding()`, when TX backpressure triggers, the function drains TX
completions and returns early. But frames consumed by RX sit in `scratch_recycle`
across the entire batch and are only moved to `pending_fill_frames` after the
batch completes. Under sustained forwarding bursts, the fill ring starves because
recycled frames never reach it.

### Fix

1. Move `scratch_recycle` drain into `pending_fill_frames` after each RX batch
   iteration, not just at the end of all batches.
2. Under backpressure, drain `scratch_recycle` into `pending_fill_frames` before
   returning early.
3. Add fill ring watermark check: if available fill frames < total/4, force
   immediate fill ring drain even mid-batch.

### Files

- `userspace-dp/src/afxdp.rs` — backpressure path + post-batch recycle drain
- `userspace-dp/src/afxdp/tx.rs` — `drain_pending_fill()`

### Test Criteria

- `iperf3 -P 8 -t 30` does not collapse
- Frame accounting balanced under sustained load
- `rx_fill_ring_empty_descs` does not grow monotonically

## Phase 2: Lock Contention Reduction (C2)

Status: Not Started

### Root Cause

Four `Arc<Mutex<>>` maps acquired per-packet: `shared_sessions`,
`shared_nat_sessions`, `shared_forward_wire_sessions`, `dynamic_neighbors`.

### Fix

**Phase 2A:** Batch shared session publishes — collect during poll cycle,
lock once per batch instead of per-session.

**Phase 2B:** Replace `dynamic_neighbors` `Arc<Mutex<>>` with `ArcSwap` —
reads are lock-free (atomic pointer load), writes clone-and-swap. The
`last_learned_neighbor` dedup already eliminates most writes.

**Phase 2C (if needed):** Replace shared session maps with `ArcSwap` if
profiling confirms they remain a bottleneck after 2A.

### Files

- `userspace-dp/src/afxdp.rs` — Coordinator struct fields
- `userspace-dp/src/afxdp/session_glue.rs` — `lookup_session_across_scopes()`,
  `publish_shared_session()`

### Test Criteria

- `perf stat` shows reduced mutex lock time
- Throughput does not regress
- HA failover tests pass

## Phase 3: In-Flight TX Timeout (H1)

Status: Not Started

### Root Cause

`in_flight_prepared_recycles` tracks UMEM frames submitted to the TX ring.
If the kernel never completes them (driver bug, hardware reset), those frames
are permanently leaked. No timeout or recovery exists.

### Fix

1. Add timestamp alongside `PreparedTxRecycle` entries.
2. Forcibly recycle frames outstanding > 5 seconds.
3. Expose overflow counter in production status.

### Files

- `userspace-dp/src/afxdp/tx.rs` — `recycle_completed_tx_offset()`,
  `transmit_prepared_batch()`
- `userspace-dp/src/afxdp.rs` — `BindingWorker` periodic check

### Test Criteria

- Under artificial TX stall, frames are recovered after timeout
- Frame accounting balanced after 60s sustained forwarding

## Phase 4: Session Sync Atomicity (H2)

Status: Not Started

### Root Cause

`publish_shared_session()` and `publish_live_session_entry()` are called
sequentially but not atomically. During HA failover, XDP shim may redirect
a packet before the shared session is installed (or vice versa).

### Fix

Reorder: always write BPF map before shared session map. A session miss
in the worker is handled gracefully (policy eval or slow-path fallback).
For deletion: delete shared session before BPF map entry.

### Files

- `userspace-dp/src/afxdp.rs` — `upsert_synced_session()`,
  `delete_synced_session()`
- `userspace-dp/src/afxdp/session_glue.rs` — publication order

### Test Criteria

- HA failover: 0 zero-throughput intervals
- Repeated 3-cycle failover/failback stress passes

## Phase 5: Reverse Session Metadata Completeness (H3)

Status: Not Started

### Root Cause

`build_reverse_session_from_forward_match()` loses routing table, DSCP,
and MSS clamp info from the forward session. Reverse path does a fresh
FIB lookup which may return different results in multi-VRF deployments.

### Fix

1. Add `routing_table` to `ForwardingResolution`.
2. Use forward session's egress zone routing table for reverse FIB lookup.
3. Preserve DSCP rewrite decisions through session metadata.

### Files

- `userspace-dp/src/afxdp/session_glue.rs` — reverse session construction
- `userspace-dp/src/afxdp.rs` — `ForwardingResolution` struct

### Test Criteria

- VRF-aware reverse session lookup returns correct egress interface
- DSCP rewrite applied correctly on both paths

## Phase 6: SYN Cookie Implementation (H4)

Status: Not Started

### Root Cause

Screen module drops SYN floods but cannot issue SYN-ACK cookies like the
eBPF dataplane (`xdp_screen.c`).

### Fix

**6A:** Add `ScreenVerdict::SynCookie`. Build SYN-ACK frame with cookie
sequence number, enqueue as hairpin TX. No session created.

**6B:** On non-SYN ACK without session, validate ACK as SYN cookie.
Extract MSS/window scale, create session, forward.

### Files

- `userspace-dp/src/screen.rs` — `ScreenVerdict` enum
- `userspace-dp/src/afxdp.rs` — screen handling in `poll_binding()`
- `bpf/xdp/xdp_screen.c` — reference cookie algorithm

### Test Criteria

- SYN flood to protected zone results in SYN-ACK cookies
- Legitimate connections complete through cookie path
- `deriveUserspaceCapabilities()` gate updated

## Phase 7: Cross-Binding Forward Optimization (M1)

Status: Not Started

### Root Cause

Each binding owns its own UMEM. Cross-interface forwards must copy into
heap then into target UMEM (2x memcpy). Direct TX into target UMEM exists
but fails when free TX frames exhausted.

### Fix

Near-term: aggressively drain all bindings' TX completions before falling
back to copy path.

Long-term: shared UMEM per worker — all bindings share one UMEM, enabling
in-place rewrite for cross-interface forwards (0 memcpy).

### Files

- `userspace-dp/src/afxdp/frame.rs` — `enqueue_pending_forwards()`
- `userspace-dp/src/afxdp.rs` — `BindingWorker::create()`, UMEM allocation

### Test Criteria

- Direct TX ratio > 90% under sustained forwarding
- Throughput improvement measured by `userspace-perf-compare.sh`

## Phase 8: Session Lifecycle BPF Map Sync (M2)

Status: Not Started

### Fix

1. Startup sweep: iterate BPF `USERSPACE_SESSIONS` map, remove entries not
   in preserved synced sessions.
2. Verify reverse session BPF cleanup handles already-removed forward entries.
3. Tighten GC interval for TCP CLOSING sessions.

### Test Criteria

- After restart, BPF map reflects only active synced sessions
- No stale entries after 120s idle

## Phase 9: Frame Ownership Audit (M3)

Status: Not Started

### Fix

Audit every `continue` in `enqueue_pending_forwards()` and every early
return in `transmit_batch()`/`transmit_prepared_batch()`. Verify
`source_offset` is always returned to fill or retained.

### Test Criteria

- Frame accounting balanced after NAT64 traffic for 60s
- No `FRAME_LEAK` messages

## Phase 10: Production Frame Leak Detection (M4)

Status: Not Started

### Fix

1. Move `FRAME_LEAK` detection to production code (one integer comparison).
2. Expose `frame_deficit` counter in `BindingLiveState`.
3. Add `frame_leak_detected` to `BindingStatus` for Go manager alerting.

### Test Criteria

- Frame leak counter visible in `show system dataplane userspace`
- No false positives under normal forwarding

## Execution Order

1. **Phase 1** (C1) — fill ring starvation, highest throughput impact
2. **Phase 3** (H1) — in-flight TX timeout, same file area
3. **Phase 9** (M3) — frame audit, validates Phase 1+3
4. **Phase 10** (M4) — production visibility for frame issues
5. **Phase 2** (C2) — lock contention, second highest measured impact
6. **Phase 4** (H2) — session sync atomicity, HA correctness
7. **Phase 5** (H3) — reverse session metadata, HA correctness
8. **Phase 8** (M2) — session lifecycle cleanup
9. **Phase 7** (M1) — cross-binding optimization, requires stable frames
10. **Phase 6** (H4) — SYN cookies, eBPF fallback provides coverage

Frame lifecycle correctness first, lock contention second, HA correctness
third, performance optimization fourth, feature gap last.

## Measurement Discipline

All changes measured using:
- `scripts/userspace-perf-compare.sh` for A/B throughput
- `iperf3 -P 4 -t 30` (min 3 runs)
- `perf record`/`perf report` for hot-symbol validation
- Frame accounting in periodic debug report
- `scripts/userspace-ha-failover-validation.sh` for HA regression
