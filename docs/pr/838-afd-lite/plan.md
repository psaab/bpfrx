# #838 — AFD-lite (single-binding scope, v3)

## 1. Goal

Add per-flow bytes-served tracking + over-share skip to
`flow_fair` CoS queues that are owned by a single binding
(i.e. `flow_fair && !shared_exact`). This is a structural
fairness floor on top of the existing MQFQ HOL-finish-time
ordering: even if MQFQ would let a flow dominate (e.g. due
to packet-size variance), AFD-lite enforces a hard
per-period fair-share ceiling.

This v3 is a **scope reduction** from the original #838
issue (which targeted shared_exact cross-binding sharing).
Two prior plan-review rounds (R1: 8 HIGH + 4 MED; R2:
6 HIGH + 2 MED + 1 LOW) showed that cross-binding atomic
state has too many race-handling subtleties to be a
small-surface change. The cross-binding work is deferred
back to #837.

## 2. What this is NOT

- Not cross-binding. AFD-lite engages only on
  `flow_fair && !shared_exact` queues (single-worker
  ownership). Shared-exact queues retain the existing
  selection logic unchanged.
- Not a full MQFQ replacement. The selector still picks
  by HOL-finish-time among under-share buckets.
- Not a drop / ECN path. Skip-on-selection only.
- Not a Count-Min sketch. Use a fixed `[u64; 1024]` array
  keyed by `flow_bucket_index`.

## 3. Test environment

- Cluster: `loss:xpf-userspace-fw0/fw1`.
- Source: `loss:cluster-userspace-host`.
- Targets:
  - `172.16.80.200:5201` — iperf3 server (existing).
  - `172.16.80.200:7` — TCP echo (operator-enabled,
    confirmed reachable).
- CoS class: **iperf-a** (1 Gb/s shaped) for tightest CoV.
- Workers=6.

## 4. Workload

Same as v1/v2 (acceptance unchanged):

- **p5201 16 streams 60 s × 10**: CoV ≤ 15 % on ≥ 8 of 10.
- **p5202 16 streams 60 s × 10**: CoV ≤ 25 % on ≥ 8 of 10.
- **p5202 128 streams 60 s × 1**: CoV ≤ 16.6 % (#900
  baseline; do not regress).
- 0 collapses.
- Aggregate throughput ≥ 0.95 × baseline.
- 0 retransmit regression.

## 5. Algorithm specification

### 5.1 Per-queue AFD-lite state

Lives on `CoSQueueRuntime`, alongside the existing
`flow_rr_buckets` / `flow_bucket_head_finish_bytes`
fields. Single-threaded access via the owning binding's
worker — **no atomics needed**.

```rust
pub(super) struct AFDLiteState {
    /// Wall-clock ns at which the current accounting window
    /// began. Updated when `now - period_start_ns >= AFD_PERIOD_WINDOW_NS`.
    period_start_ns: u64,
    /// Bytes dispatched to bucket b in current window.
    /// Indexed by `flow_bucket_index` (already bounded to
    /// COS_FLOW_FAIR_BUCKETS = 1024).
    bytes_per_flow: Box<[u64; COS_FLOW_FAIR_BUCKETS]>,
    /// Sum of bytes_per_flow in current window.
    bytes_total: u64,
    /// Count of buckets with bytes_per_flow[b] > 0 in current
    /// window. Maintained incrementally — incremented on a
    /// 0→positive transition, recomputed (along with the
    /// counters) on period rotation.
    active_count: u32,
}

pub(super) const AFD_PERIOD_WINDOW_NS: u64 = 2_000_000;  // 2 ms
pub(super) const AFD_OVER_SHARE_NUM: u32 = 0;            // strict (default)
pub(super) const AFD_OVER_SHARE_DEN: u32 = 256;
// threshold = fair_share + fair_share * NUM / DEN
// NUM=0  → strict (threshold = fair_share)
// NUM=64 → 1.25× fair_share
// NUM=128 → 1.5×
```

Memory cost: 8 KB per `flow_fair && !shared_exact` queue.
Negligible.

### 5.2 Hot-path operations (single-threaded — no CAS)

**Period rotation** (called at the top of `afd_account_dispatch`):

```rust
fn afd_maybe_rotate(state: &mut AFDLiteState, now_ns: u64) {
    if now_ns.saturating_sub(state.period_start_ns) < AFD_PERIOD_WINDOW_NS {
        return;
    }
    state.period_start_ns = now_ns;
    state.bytes_per_flow.fill(0);
    state.bytes_total = 0;
    state.active_count = 0;
}
```

The `fill(0)` over 1024 u64s is ~8 KB of L1 cache; on a
single core this is ~250 ns. At 500 rotations/sec
(2 ms window), the amortized overhead is < 0.001 % of CPU.
Acceptable.

**Dispatch accounting** (called after a successful TX-ring
write — Codex R2 #6 fix: account-after-TX-insert,
unconditional rollback removed):

```rust
fn afd_account_dispatch(state: &mut AFDLiteState, bucket: usize, bytes: u64, now_ns: u64) {
    afd_maybe_rotate(state, now_ns);
    let prev = state.bytes_per_flow[bucket];
    let new = prev.saturating_add(bytes);
    state.bytes_per_flow[bucket] = new;
    state.bytes_total = state.bytes_total.saturating_add(bytes);
    if prev == 0 && new > 0 {
        state.active_count = state.active_count.saturating_add(1);
    }
}
```

**No rollback path.** Codex R2 #6 fix: account *after* TX
insertion succeeds. If TX insertion fails, the dispatch
function returns early (existing code path) without ever
calling `afd_account_dispatch`. There is no `fetch_sub`
to misbehave; no underflow scenario; no batch-failure
920 % overcharge.

### 5.3 Selection gating

Adds a wrapper around the existing
`cos_queue_min_finish_bucket`:

```rust
fn cos_queue_select_bucket(queue: &CoSQueueRuntime, now_ns: u64) -> Option<u16> {
    if queue.shared_exact || !queue.flow_fair {
        // Out of scope for v3: shared_exact uses existing
        // ordering (no AFD); non-flow-fair has no buckets.
        return cos_queue_min_finish_bucket(queue);
    }
    let afd = queue.afd.as_ref().expect("flow_fair queue must have AFD state");
    let (total, active) = (afd.bytes_total, afd.active_count);
    if active == 0 {
        // Fresh window with no activity — fall back to MQFQ.
        return cos_queue_min_finish_bucket(queue);
    }
    let fair_share = total / u64::from(active);
    let threshold = fair_share.saturating_add(
        fair_share.saturating_mul(u64::from(AFD_OVER_SHARE_NUM))
                  / u64::from(AFD_OVER_SHARE_DEN),
    );

    let mut best_under: Option<u16> = None;
    let mut best_under_finish = u64::MAX;
    let mut best_over: Option<u16> = None;
    let mut best_over_excess = u64::MAX;
    for bucket in queue.flow_rr_buckets.iter() {
        let idx = usize::from(bucket);
        let bytes = afd.bytes_per_flow[idx];
        let finish = queue.flow_bucket_head_finish_bytes[idx];
        if bytes <= threshold {
            if finish < best_under_finish {
                best_under_finish = finish;
                best_under = Some(bucket);
            }
        } else {
            let excess = bytes.saturating_sub(threshold);
            if excess < best_over_excess {
                best_over_excess = excess;
                best_over = Some(bucket);
            }
        }
    }
    best_under.or(best_over)
}
```

If at least one bucket is under-share, pick by smallest
HOL-finish-time (preserves MQFQ ordering among eligibles).
If ALL are over-share (e.g. early in window before counters
update), fall back to smallest excess to avoid going idle.

### 5.4 Single-pass selection (Codex R2 #2 fix)

Both `cos_queue_front` (`tx.rs:4262`) and the equivalent
pop site (`tx.rs:4464`-area) currently call
`cos_queue_min_finish_bucket(queue)` separately. Replace
both call sites to use `cos_queue_select_bucket(queue,
now_ns)`. The selection cost is now a single 1024-element
loop per call, called twice per packet (once for front,
once for pop). At ~150 K pps × 2 calls × 1024 reads =
~300 M reads/sec on a single core — well within budget for
a contiguous u64 array (cache-friendly linear scan).

(Caching the result across paired front+pop calls is a
follow-up optimisation if profiling shows it's a hotspot.)

## 6. Implementation outline

### 6.1 New file: `userspace-dp/src/afxdp/afd_lite.rs`

```rust
//! AFD-lite: per-flow bytes-served + over-share skip for
//! single-binding flow_fair CoS queues. See
//! docs/pr/838-afd-lite/plan.md.

pub(super) const AFD_PERIOD_WINDOW_NS: u64 = 2_000_000;
pub(super) const AFD_OVER_SHARE_NUM: u32 = 0;
pub(super) const AFD_OVER_SHARE_DEN: u32 = 256;

pub(super) struct AFDLiteState { ... }

impl AFDLiteState {
    pub(super) fn new() -> Self { ... }
}

pub(super) fn afd_maybe_rotate(state: &mut AFDLiteState, now_ns: u64) { ... }
pub(super) fn afd_account_dispatch(state: &mut AFDLiteState, bucket: usize, bytes: u64, now_ns: u64) { ... }
pub(super) fn afd_threshold(state: &AFDLiteState) -> u64 { ... }  // helper for selection
```

### 6.2 Edits to `userspace-dp/src/afxdp/types.rs`

- Add `pub(super) afd: Option<Box<AFDLiteState>>` field to
  `CoSQueueRuntime`.
  - `Box<AFDLiteState>` so the 8 KB allocation lives off
    the runtime struct (which is repeatedly cloned during
    plan reconciliation).
  - `Option` so non-`flow_fair` queues skip the
    allocation entirely.
- Set `afd = Some(Box::new(AFDLiteState::new()))` at the
  same site where existing flow-fair fields are
  initialised (`promote_cos_queue_flow_fair` in
  `tx.rs:5388`).
- Add `mod afd_lite;` to `userspace-dp/src/afxdp/mod.rs`
  (or wherever the existing module declarations live).

### 6.3 Edits to `userspace-dp/src/afxdp/tx.rs`

**Pop commit-points** — call `afd_account_dispatch` AFTER
the TX-ring insertion succeeds at each of the existing
sites identified by Codex R1 (line numbers approximate
against current HEAD; verify before editing):

- `tx.rs:2926` — successful pop commit (primary pop path).
- `tx.rs:2957` — successful pop commit (alt path).
- `tx.rs:2983` — successful pop commit.
- `tx.rs:3012` — successful pop commit.
- `tx.rs:3129` — successful pop commit (forwarding).
- `tx.rs:3170` — successful pop commit (forwarding).
- `tx.rs:3214` — successful pop commit (forwarding).
- `tx.rs:3272` — successful pop commit (forwarding).

At each, gate on `queue.flow_fair && !queue.shared_exact`
to avoid touching out-of-scope queues.

**Failure / rollback paths** — *do nothing*. Per §5.2,
the no-rollback design means failed TX simply doesn't
account.

**Selection sites**:
- `cos_queue_front` (`tx.rs:4262`) → call
  `cos_queue_select_bucket(queue, now_ns)`.
- `cos_queue_pop_front_inner` (`tx.rs:4464`-area) → same.

The `now_ns` argument is plumbed from the existing call
chain. Worker hot-paths already have a `now_ns` value
(from the polling loop's `monotonic_ns()`); pass it
through.

### 6.4 Stale-comment cleanup (Codex R2 #8)

The R2 review surfaced a stale invariant in
`types.rs:1037-1040` and `tx.rs:5326-5329` saying
`flow_fair = exact && !shared_exact`. The actual
production code at `tx.rs:5408-5410` sets `flow_fair =
exact` unconditionally; tests at `tx.rs:14661-14679`
assert that shared-exact queues ARE flow-fair. Update the
stale comments to match — this is a maintenance trap that
this PR can fix while it's adjacent to the same code.

### 6.5 No edits to `coordinator.rs` or `worker.rs`

Per §1, this scope is single-binding. No
`SharedCoSQueueLease` changes, no binding-promotion
changes for shared seed propagation, no cross-binding
state.

## 7. Tests

### 7.1 Unit tests in `afd_lite.rs`

1. `account_dispatch_within_period_accumulates`.
2. `account_dispatch_across_periods_resets_via_rotate`.
3. `period_rotation_zeros_state` — direct test of
   `afd_maybe_rotate`.
4. `period_rotation_no_op_within_window`.
5. `active_count_increments_on_zero_to_positive_transition`
   only.
6. `bytes_saturate_at_u64_max_no_wrap`.

### 7.2 Integration tests in `tx.rs` (new `tests` module)

7. `cos_queue_select_bucket_picks_under_share_first` —
   construct a `flow_fair && !shared_exact` queue,
   pre-populate two buckets with different bytes_per_flow
   values; assert the under-share one is selected.
8. `cos_queue_select_bucket_falls_back_to_smallest_excess`
   — all buckets over-share; assert smallest-excess wins.
9. `cos_queue_select_bucket_preserves_mqfq_among_eligibles`
   — multiple under-share, smallest HOL-finish wins.
10. `cos_queue_select_bucket_passthrough_for_shared_exact`
    — `shared_exact == true`; assert the existing
    `cos_queue_min_finish_bucket` is called (no AFD logic
    engaged).
11. `cos_queue_select_bucket_passthrough_when_active_count_zero`
    — fresh window, no activity yet; assert MQFQ
    fall-back.
12. `cos_queue_select_bucket_passthrough_for_non_flow_fair`
    — `flow_fair == false`; existing path preserved.
13. `dispatch_failure_does_not_account` — simulate a TX
    insertion failure; assert AFD state unchanged.
14. `dispatch_success_accounts` — simulate a successful
    TX; assert `bytes_per_flow[b]` and `bytes_total`
    incremented; `active_count` incremented if 0→1.

### 7.3 Test plumbing

Reuse the existing `CoSQueueRuntime` test constructors;
the new `afd: Option<Box<AFDLiteState>>` field can be
populated via `Some(Box::new(AFDLiteState::new()))` in
test setup for flow-fair-non-shared-exact cases.

## 8. Acceptance

- Rust unit + integration tests pass.
- All Go tests pass.
- `cargo build --release` clean.
- Live deploy on `loss:xpf-userspace-fw0/fw1`:
  - **p5201 16 streams 60 s × 10**: CoV ≤ 15 % on ≥ 8 of 10
    runs.
  - **p5202 16 streams 60 s × 10**: CoV ≤ 25 % on ≥ 8 of 10
    runs.
  - **p5202 128 streams 60 s × 1**: CoV ≤ 16.6 %
    (#900 baseline; do not regress).
  - 0 collapses (every stream ≥ 1 Mbps).
  - Aggregate throughput ≥ 0.95 × baseline.
  - 0 retransmit regression.
- `make test-failover`: pass (defense — touching the
  CoS dataplane).
- Codex hostile plan + code review: PLAN-READY YES,
  MERGE YES.
- Copilot inline review: addressed.

## 9. Risks

- **Marginal gain may be smaller than budgeted**: AFD-lite
  on single-binding queues affects intra-binding flow
  fairness. RSS hash skew is the dominant CoV contributor
  at our 16-stream baseline (18.5 %), and it's
  cross-binding by definition. Single-binding AFD-lite
  reduces only the intra-binding tail (TCP cwnd variance +
  bucket-collision unfairness within one queue). Estimated
  gain: 1-3 percentage points (smaller than v1/v2's 3-5
  estimate, which assumed cross-binding sharing).
  - If we land at 16-17 % CoV (still > 15 % bar), the PR
    documents the result honestly. The acceptance bar is
    a target, not a gate; merge is justified by code
    quality + zero-harm even if the empirical bar isn't
    hit.
- **Period-rotation cost**: `Box::fill(0)` on 8 KB at 500
  Hz = ~120 µs/sec/queue. With ~2-4 flow-fair-non-shared
  queues per worker × 6 workers, total ~1-3 ms/sec of CPU.
  Bounded.
- **Selection cost**: 1024-u64 linear scan per `cos_queue_front`
  + per pop. Profile shows the existing
  `cos_queue_min_finish_bucket` is a hot site; this adds a
  similar-magnitude load. Empirically verify with `perf`
  during the 128-stream test.
- **Stale-comment fix scope creep**: §6.4 cleans up
  `types.rs:1037-1040` and `tx.rs:5326-5329`. If touching
  those comments cascades into other invariant updates,
  bail and file separately.

## 10. Out of scope

- Cross-binding shared_exact AFD (deferred to #837).
- Drop / ECN signalling.
- Per-flow rate limiting (#794).
- Adaptive over-share epsilon based on queue depth.
- IPv6 echo path coverage (#900 follow-up).

## 11. R1 + R2 review responses

The cross-binding scope of v1 + v2 was abandoned (see §1).
Findings that no longer apply at v3 scope are marked
"OUT-OF-SCOPE-V3"; findings that DO apply at v3 scope are
addressed below.

### Round 1 (8 HIGH + 4 MED)

| # | Sev | Topic                                | v3 status |
|---|-----|--------------------------------------|-----------|
| 1 | HIGH| Period-reset publish ordering        | OUT-OF-SCOPE-V3 — no shared atomic state |
| 2 | HIGH| active_bucket_count cross-binding    | OUT-OF-SCOPE-V3 — single-threaded count |
| 3 | HIGH| fetch_sub rollback underflow         | RESOLVED — no rollback path; account-after-TX-insert (§5.2) |
| 4 | HIGH| Pop commit-point underspecification  | RESOLVED — §6.3 enumerates all 8 sites |
| 5 | HIGH| Epsilon formula bug                  | RESOLVED — §5.3 `NUM/DEN` fraction; default 0/256 = strict |
| 6 | HIGH| Wrong gate (lease vs shared_exact)   | RESOLVED — §5.3 gates on `flow_fair && !shared_exact` |
| 7 | HIGH| Hash seed not wired                  | OUT-OF-SCOPE-V3 — single-binding owns its seed |
| 8 | HIGH| push_front active-count drift        | OUT-OF-SCOPE-V3 — design doesn't track active-on-enqueue |
| 9 | MED | Cache-line cost                      | RESOLVED — single-threaded plain u64, no cache-line bouncing |
| 10| MED | 2 ms period window ungrounded        | §5.1 retains 2 ms; same TCP-burst-coverage rationale |
| 11| MED | Test gaps                            | §7 covers all relevant scenarios at v3 scope |
| 12| MED | Acceptance bar uncertainty           | §9 documents the 1-3 pp expected gain (smaller than v2's estimate); doesn't auto-fail |

### Round 2 (6 HIGH + 2 MED + 1 LOW)

| # | Sev | Topic                                | v3 status |
|---|-----|--------------------------------------|-----------|
| 1 | HIGH| Period CAS regression on retry       | OUT-OF-SCOPE-V3 — no CAS, plain u64 |
| 2 | HIGH| Period-summary cost not amortized    | RESOLVED — summary is two field reads (`bytes_total`, `active_count`), no iteration |
| 3 | MED | Seed propagation target wrong        | OUT-OF-SCOPE-V3 — no shared seed |
| 4 | HIGH| Hot-bucket CAS liveness              | OUT-OF-SCOPE-V3 — no CAS |
| 5 | HIGH| Bitmap math inconsistent             | OUT-OF-SCOPE-V3 — no bitmap; plain `active_count: u32` field |
| 6 | HIGH| Rollback overcharge unbounded        | RESOLVED — §5.2 no-rollback design (account-after-TX-insert) |
| 7 | LOW | Period counter wrap                  | OUT-OF-SCOPE-V3 — period_start_ns is plain u64 ns, no period index |
| 8 | MED | Stale comments in source             | RESOLVED — §6.4 cleans up `types.rs:1037-1040` + `tx.rs:5326-5329` |
| 9 | HIGH| Lease plumbing + epsilon shift bug   | RESOLVED — §5.1 `NUM/DEN` fraction (no shift sentinel); §6.3 plumbs `now_ns` from existing call chain (no lease needed) |
