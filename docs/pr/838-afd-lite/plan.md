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
- CoS classes (ALL four covered per operator direction):
  - port 5201 → **iperf-a** (1 Gb/s shaped) — tightest CoV
  - port 5202 → **iperf-b** (10 Gb/s shaped)
  - port 5203 → **iperf-c** (25 Gb/s shaped)
  - port 5204 → **best-effort** (100 Mb/s shaped)
  Queue ownership per `cos-iperf-config.set` + the live
  `show class-of-service interface`: queue 0
  (best-effort, owner 0), queue 4 (iperf-a, owner 1),
  queue 5 (iperf-b, owner 2), queue 6 (iperf-c, owner 3).
  All four queues are `exact=yes` and `flow_fair=true` (the
  AFD-lite scope) on a single binding each.
- Workers=6.

## 4. Workload

Each test is `iperf3 -P 16 -t 60 -p <port>` against
`172.16.80.200`. Run 10× per port (40 runs total).

Per-class acceptance (per #786 Slice C convention,
adapted to each class's shaped rate):

- **p5204 (best-effort, 100 Mb/s)**: CoV ≤ 25 % on ≥ 8 of 10.
- **p5201 (iperf-a, 1 Gb/s)**: CoV ≤ 15 % on ≥ 8 of 10.
- **p5202 (iperf-b, 10 Gb/s)**: CoV ≤ 25 % on ≥ 8 of 10.
- **p5203 (iperf-c, 25 Gb/s)**: CoV ≤ 25 % on ≥ 8 of 10.

Plus:
- **p5202 128 streams 60 s × 1**: CoV ≤ 16.6 % (#900
  baseline; do not regress).
- 0 collapses on every test.
- Aggregate per-class throughput ≥ 0.95 × shaped rate.
- 0 retransmit regression.

Per-class commentary:
- **p5201 (1 Gb/s)** has the tightest CoV bar — limited
  shaper tokens means per-flow contention is sharpest.
- **p5202 (10 Gb/s)** and **p5203 (25 Gb/s)** are
  abundance-regime: most flows can saturate without
  contending. CoV bar is looser, but AFD-lite must not
  regress them.
- **p5204 (100 Mb/s, best-effort)** is the smallest pipe.
  16 streams × 6 Mbps fair share. AFD-lite's biggest
  potential win is here — the smaller the per-flow share,
  the tighter the over-share threshold gates noisy flows.

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

R4 review forced grounding in the real code. The actual
flow-fair+exact dispatch path (the workload our test matrix
hits) is:

```
service_exact_local_queue_direct (tx.rs:1932)
  └ flow_fair branch (tx.rs:1946-1949)
    └ service_exact_local_queue_direct_flow_fair (tx.rs:2082)
      └ submit_cos_batch (returns bool)
      └ settle_exact_local_scratch_submission_flow_fair (tx.rs:2945)
            ↑ THIS is the post-TX commit point
```

And the prepared-frame variant:

```
service_exact_prepared_queue_direct_flow_fair (tx.rs:2368)
  └ submit_cos_batch
  └ settle_exact_prepared_scratch_submission_flow_fair (tx.rs:3000)
        ↑ post-TX commit point
```

#### 6.3.1 The accepted-prefix discrimination is already done

The `settle_*_flow_fair` functions take `inserted: usize`
(R4 HIGH 2: `inserted` is the accepted-packet-count from
the xsk send return) and iterate the scratch buffer
backwards. For each item:

- If `scratch_*.len() >= inserted` (rejected tail): push
  the item back via `cos_queue_push_front`.
- Else (accepted prefix): increment `sent_packets` /
  `sent_bytes`.

So **no separate staging buffer is needed** (R3 HIGH 4
proposed redesign was reinventing this). The existing
settle functions ARE the staging-prefix walkers. AFD-lite's
hook just goes in the accepted branch.

R4 HIGH 1 (staging buffer location) and R4 HIGH 5
(signature chain) are dropped — there is no new staging
buffer.

#### 6.3.2 AFD hooks: settle-function accepted branches

Two sites:

**Local TX** — `settle_exact_local_scratch_submission_flow_fair`
at tx.rs:2945. Edit the `else` branch (currently
tx.rs:2961-2964):

```rust
} else {
    sent_packets += 1;
    sent_bytes += req.bytes.len() as u64;
    // #838 AFD-lite hook (v3 single-binding):
    if !queue.shared_exact {
        if let Some(afd) = queue.afd.as_mut() {
            let flow_key = req_flow_key(&req);
            let bucket = cos_flow_bucket_index(queue.flow_hash_seed, flow_key);
            afd_account_dispatch(afd, usize::from(bucket), req.bytes.len() as u64, now_ns);
        }
    }
}
```

**Prepared TX** — `settle_exact_prepared_scratch_submission_flow_fair`
at tx.rs:3000. Edit the `else` branch (currently
tx.rs:3015-3019):

```rust
} else {
    remember_prepared_recycle(in_flight_prepared_recycles, &req);
    sent_packets += 1;
    sent_bytes += req.len as u64;
    // #838 AFD-lite hook:
    if !queue.shared_exact {
        if let Some(afd) = queue.afd.as_mut() {
            let bucket = cos_flow_bucket_index(queue.flow_hash_seed, req_flow_key_prepared(&req));
            afd_account_dispatch(afd, usize::from(bucket), req.len as u64, now_ns);
        }
    }
}
```

The `flow_fair` gate is already implicit (these settle
functions are only called from the flow-fair dispatch
branch at tx.rs:1947).

The `!queue.shared_exact` gate keeps v3 scope to single-
binding queues.

`req_flow_key` / `req_flow_key_prepared` extract the 5-tuple
from the request; helpers already exist for this. Verify
exact name during implementation.

#### 6.3.3 now_ns plumbing

Both settle functions don't currently take `now_ns`. Add a
parameter. Callers:

- `service_exact_local_queue_direct_flow_fair` at tx.rs:2082
  — already has `now_ns` from its caller chain.
- `service_exact_prepared_queue_direct_flow_fair` at tx.rs:2368
  — same.

Selection sites for `cos_queue_select_bucket(queue, now_ns)`:
- `cos_queue_front` at tx.rs:4262
- `cos_queue_pop_front_inner` at tx.rs:4464-area
- Called from `select_cos_guarantee_batch` (tx.rs:1740,
  1836), `select_cos_surplus_batch` (tx.rs:1890), and
  `build_cos_batch_from_queue` (tx.rs:3102) per R4 MED 11.
  Each caller has `now_ns` available (from its parent dispatch
  loop); thread through.

Total signature change surface: ~10 functions. Mechanical.

#### 6.3.4 Out-of-scope dispatch paths

- **FIFO path** (`tx.rs:2922-2927`, where `sent_bytes +=
  req.bytes.len()` lives in the FIFO settle): R4 LOW 4 +
  LOW 6 — this is the non-flow-fair path. Skipped by the
  v3 gate (`flow_fair == false` → no `afd` field). No
  hook needed. State this here so the implementer doesn't
  look for one.
- **Surplus / Guarantee batch paths** (`select_cos_*_batch`
  → `build_cos_batch_from_queue`): these are also
  non-flow-fair (the path checks `queue.exact` and skips
  exact queues at line 1887). Selection-side `now_ns`
  threading is needed (per §6.3.3) for the
  `cos_queue_select_bucket` call, but no AFD accounting
  hook is needed here.
- **Settle FIFO** (tx.rs:2969 `settle_exact_prepared_fifo_submission`):
  this is the `!flow_fair` branch. Non-flow-fair → no
  AFD state → no hook.

#### 6.3.5 Failure / rollback paths

Per §5.2, do nothing. Failed-TX items go back to the queue
via `cos_queue_push_front` (already in the settle code at
tx.rs:2960 and 3014). AFD hook is in the OTHER branch
(accepted), so failed items naturally bypass accounting.

This closes R3 HIGH 6 (rollback overcharge) — there is no
rollback path that touches AFD; the byte-count ledger is
write-only.

#### 6.3.6 One-packet-stale on selection — recomputed (R4 HIGH 3)

R4 HIGH 3 correctly flagged my <0.4% calc was at high pps.
At lower pps (small CoS class, small flow count), the stale
rate climbs.

Recomputed worst-case stale-rate per class, assuming the
2 ms window:

| Class | Shaped rate | 16-stream pps | Pkts/window | 1 stale = |
|-------|-------------|---------------|-------------|-----------|
| iperf-c (25 Gb/s) | ~2 M pps | 2 M / 16 ≈ 125 K per stream, total 2 M | ~4000 | 0.025 % |
| iperf-b (10 Gb/s) | ~830 K pps | total 830 K | ~1660 | 0.06 % |
| iperf-a (1 Gb/s) | ~83 K pps | total 83 K | ~166 | 0.6 % |
| best-effort (100 Mb/s) | ~8.3 K pps | total 8.3 K | ~16.6 | **6 %** |

(Assumes 1500-byte packets.)

For the small classes (iperf-a and best-effort), one stale
selection per window is non-trivial (0.6 % and 6 %
respectively). For best-effort 16 streams, ~6 % of selections
might use stale state.

**Two mitigation options**:

(a) Accept it: the stale state is at-most-2 ms-old and is
itself a fair-share-bounded threshold. The over-share skip
might fail to engage on one bucket per window, letting one
"hot" flow get one extra packet through every 2 ms. Bounded.

(b) Rotate-in-selection: change `cos_queue_select_bucket`
to take `&mut CoSQueueRuntime` and call `afd_maybe_rotate`
at entry. This requires changing `cos_queue_front`
(tx.rs:4262) to take `&mut`, which cascades through callers.

**Decision**: go with (a) for v3. Document the worst-case
6 % stale rate on best-effort. If empirical CoV measurement
shows best-effort doesn't meet acceptance, switch to (b) in
a follow-up. The merge gate (per §8) is non-regression, not
absolute CoV — so a small stale impact won't block merge.

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
15. `batch_partial_success_accounts_only_accepted_prefix`
    (Codex R3 MED 9): build a staging buffer of 4 entries
    (3 distinct flow buckets), simulate `submit_cos_batch`
    accepting only 2 of 4. Assert AFD bytes accounted for
    only the first 2 staging tuples; the unaccepted tail
    leaves AFD untouched. Asserts the Codex R3 HIGH 4 fix.
16. `batch_full_failure_accounts_nothing` — simulate
    `inserted == 0`. Assert AFD state unchanged.
17. `batch_full_success_accounts_all` — simulate
    `inserted == staging_len`. Assert all tuples accounted.

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

**Merge gates (block merge if not met) — Codex R3 MED 8 fix**:
The merge gate is **non-regression**, not absolute CoV.
AFD-lite must not make ANY of the four classes worse than
the captured-just-before-deploy baseline. Specifically:
  - CoV per class: AFD-lite-enabled CoV ≤ baseline CoV +
    1 percentage point on every class (allows for
    measurement noise; protects against actual regression).
  - 0 stream collapses on every class (no flow drops below
    a sentinel threshold).
  - Aggregate per-class throughput ≥ 0.95 × baseline (no
    throughput regression worth a percentage point).
  - 0 retransmit regression vs baseline median.
  - All Rust + Go unit tests pass.
  - `make test-failover`: pass.

**Targets (reported, not gating)**:
  - p5201 CoV ≤ 15 % on ≥ 8 of 10 runs (per #786 Slice C
    convention).
  - p5202 CoV ≤ 25 % on ≥ 8 of 10 runs.
  - p5203 CoV ≤ 25 % on ≥ 8 of 10 runs.
  - p5204 CoV ≤ 25 % on ≥ 8 of 10 runs.
  - p5202 128 streams 60 s × 1: CoV ≤ 16.6 % (#900 regression
    floor — promoted to merge gate via the non-regression
    rule above).

§9 estimates the realistic gain at 1-3 percentage points;
the targets above are the v1/v2 design goals which are
optimistic for v3's reduced single-binding scope. Reviewers
focus on the non-regression merge gate; the targets are
ambitions to compare against, not pass/fail thresholds.
- `make test-failover`: pass (defense — touching the
  CoS dataplane).
- Codex hostile plan + code review: NOT ACHIEVED. The plan
  closed at R5 with a PLAN-NEEDS-MAJOR-REWORK verdict (see
  §11 Round 5 + `findings.md`); MERGE was never pursued.
- Copilot inline review: addressed for the closing docs PR
  (#904); not pursued for the unwritten implementation.

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
- **Period-rotation cost**: `state.bytes_per_flow.fill(0)`
  on 8 KB at 500 Hz = ~120 µs/sec/queue. With ~2-4
  flow-fair-non-shared queues per worker × 6 workers,
  total ~1-3 ms/sec of CPU. Bounded.
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

### Round 3 (1 HIGH + 3 MED + 2 LOW; v3 plan)

| # | Sev | Topic                                | Resolution |
|---|-----|--------------------------------------|-----------|
| 1 | OK  | Single-threaded ownership            | Confirmed via `worker.rs:21,679,984`; coordinator reads only ArcSwap snapshot |
| 2 | LOW | `Box<AFDLiteState>` clone semantics  | Plan rewording: not "repeatedly cloned" — `CoSQueueRuntime` is rebuilt fresh on plan reconciliation. Box is for off-line allocation, not for sharing. |
| 3 | LOW | now_ns plumbing surface              | §6.3.4: explicit list of caller sites (build_cos_batch_from_queue, drain helpers at tx.rs:2602/2780/3102); bounded |
| 4 | HIGH| Pop commit-points conflate pre/post-TX | §6.3.2 redesigned: per-batch staging buffer of (bucket, bytes) tuples; iterate accepted prefix N at submit-success and account only those. Matches no-rollback contract |
| 5 | OK  | active_count maintenance correctness | Confirmed under single-threaded model |
| 6 | OK  | Bytes accounting timing              | §6.3.1 specifies the FIFO success branch (after `sent_bytes += req.bytes.len()`) per Area 6 |
| 7 | OK  | Stale-comment cleanup is comment-only| Confirmed; §6.4 unchanged |
| 8 | MED | Acceptance bar inconsistency         | §8 split into "merge gates" (non-regression: ≤ baseline + 1pp, no collapses, ≥0.95× throughput, no retransmit regression) and "targets" (the absolute CoV bars from #786 Slice C, reported but non-gating) |
| 9 | MED | Partial TX-ring success test gap     | §7 tests #15 (partial), #16 (full failure), #17 (full success) added |
| 10| MED | now_ns unused in selection           | §6.3.5: documented one-packet-stale on selection. ~0.4% of selections at 2ms window × 150K pps. Acceptable; mitigation requires &mut signature change beyond v3 scope |

### Round 4 (6 HIGH + 3 MED + 2 LOW; R4 forced grounding in actual code paths)

| # | Sev | Topic                                | Resolution |
|---|-----|--------------------------------------|-----------|
| 1 | HIGH| Staging buffer location not pinned   | DROPPED — §6.3.1 shows the existing `settle_*_flow_fair` functions already do the accepted-prefix walk. No staging buffer needed |
| 2 | HIGH| Accepted-count unit wrong            | RESOLVED — §6.3.1 correctly identifies `inserted: usize` as the accepted-packet-count parameter to settle |
| 3 | HIGH| Stale-window math cherry-picked      | RESOLVED — §6.3.6 recomputes per-class, including 6% worst-case on best-effort. Mitigation option (b) flagged for follow-up if empirical regresses |
| 4 | HIGH| Baseline comparison undefined        | RESOLVED — §8 pins median-of-10 vs median-of-10 + 1 pp per class |
| 5 | HIGH| `build_cos_batch_from_queue` signature chain missing | DROPPED — no staging buffer to thread (per #1) |
| 6 | HIGH| Exact-flow-fair accounting path absent | RESOLVED — §6.3.2 hooks at `settle_exact_local_scratch_submission_flow_fair:2961-2964` and `settle_exact_prepared_scratch_submission_flow_fair:3015-3019`. The PRIMARY workload path |
| 3 | MED | Settle-site hand-wave                | RESOLVED — §6.3.4 explicitly excludes FIFO/surplus/guarantee paths from AFD hooks; §6.3.2 names the only two hook sites |
| 8 | MED | Test #15 level not pinned            | UNIT test on `account_staging_prefix` helper (clarified — though the v4 design doesn't use a separate helper, the equivalent is a unit test on `settle_*_flow_fair` with a constructed scratch buffer and varying `inserted` values) |
| 11| MED | now_ns plumbing surface incomplete  | RESOLVED — §6.3.3 enumerates the full caller surface including `select_cos_guarantee_batch`, `select_cos_surplus_batch`, `build_cos_batch_from_queue` |
| 4 | LOW | FIFO path irrelevance                | RESOLVED — §6.3.4 explicit |
| 6 | LOW | No FIFO ring revert                  | RESOLVED — §6.3.4 + §6.3.5 explicit |

### Round 5 (5 HIGH + 2 MED + 1 LOW; conducted on plan commit `1bbd61c1`)

R5 hostile review of the v3 plan after R4 fixes uncovered a
**structural blocker** that prior rounds did not surface, plus four
additional HIGH findings.

| #  | Sev | Topic                                  | Status |
|----|-----|----------------------------------------|--------|
| Q9 | HIGH| **Selector blind during scratch-build** | NOT RESOLVED — see narrative below |
| Q10| HIGH| Period-window staleness on settle      | open   |
| Q11| HIGH| `active_count` race vs reset           | open   |
| Q12| HIGH| Settle-site count assumes full submit  | open   |
| Q13| HIGH| now_ns plumbing depth still incomplete | open   |
| Q14| MED | Acceptance-bar still ungrounded vs noise floor | open |
| Q15| MED | Test #15-#17 do not exercise Q9 path   | open   |
| Q16| LOW | Stale comment in tx.rs:5326-5329       | trivial |

**Q9 (the structural blocker, in the reviewer's wording):**
> The selector runs during scratch-build (one decision per packet at
> `service_exact_local_queue_direct_flow_fair` and the prepared
> equivalent), but accounting happens at *settle* (one
> `account_per_flow` per *batch* in `settle_*_flow_fair`). The
> selector is therefore BLIND to packets it has already selected
> earlier in the current batch — they are still sitting in
> `scratch_local_tx`, the per-flow counter has not been bumped, and
> the period-bytes-total has not advanced.
>
> With `TX_BATCH_SIZE: usize = 256` (`userspace-dp/src/afxdp.rs:159`)
> and best-effort fair share at ~16 packets per 2 ms period, the
> selector can ship multiple periods' worth of packets within one
> scratch build. AFD never engages on the batch path — exactly the
> path the v3 plan calls "the PRIMARY workload path" in §6.3.2.

**Why this is structural, not a fix-in-place:** the v3 design's
*premise* is that account-after-TX-insert (no rollback) is safe
because the insert-and-account window is short. R5 shows the window
is one entire batch — 256 × insert decisions before one accounting
update. The fix would require either:

(a) **provisional per-batch accounting at selection time** (commit
    bytes to a thread-local shadow of `period_bytes_per_flow`,
    then reconcile with the shared atomic at settle, with rollback
    on the rejected-tail). This re-introduces the rollback path
    that R3-R4 were specifically structured to avoid; the contract
    of the no-rollback design no longer holds.

(b) **shrink TX_BATCH_SIZE during AFD-active periods**, which has
    its own throughput cost and breaks the existing batching
    invariants relied on by the kick-latency path.

Either fix is a structural redesign at v4 scope. The R5 reviewer
did not propose one; the cost-vs-expected-gain (1-3 pp CoV at most)
does not justify another round of plan-design effort.

### R5 disposition

The plan does not advance to a v4. See
`docs/pr/838-afd-lite/findings.md` for the broader negative-finding
writeup and the recommended path forward (defer algorithm work,
characterize mouse-latency tail empirically first via #905).
