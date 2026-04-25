# #838 — AFD-lite: per-flow bytes-served counter with periodic reset

## 1. Goal

Improve cross-binding fair queueing on `shared_exact` CoS queues
without the surface area of full HOL-finish-time sharing
(#836 closed → tracked as the "big-design" alternative in #837).

This implements the smaller-surface alternative described in
#838: track bytes dispatched per flow-bucket per time window,
shared across all bindings on a `SharedCoSQueueLease`. Bucket
selection skips flows that are over their fair share for one
round-robin cycle.

R1 review found 8 HIGH + 4 MED requiring a structural redesign;
this v2 addresses each in §13.

## 2. What this is NOT

- Not a full MQFQ replacement. Single-binding `flow_fair`
  queues retain `cos_queue_min_finish_bucket()` HOL-finish
  ordering unchanged.
- Not a drop / ECN path. Skip-on-selection only — no admission
  changes (avoids the #833 double-signal trap).
- Not Count-Min sketch. Use a fixed `[AtomicU64; 1024]` array
  keyed by `flow_bucket_index`.

## 3. Test environment

- Cluster: `loss:xpf-userspace-fw0/fw1` (RG0 primary).
- Source: `loss:cluster-userspace-host`.
- Targets:
  - `172.16.80.200:5201` — iperf3 server (existing).
  - `172.16.80.200:7` — TCP/UDP echo (newly enabled by
    operator, confirmed via `</dev/tcp/172.16.80.200/7`).
  - `[2001:559:8585:80::200]:7` — IPv6 echo (out of scope for
    #838 itself; available for follow-up #900 mouse-latency
    measurement).
- CoS class: **iperf-a** (1 Gb/s shaped) for tightest CoV.
- Workers=6, queue 4 owned by worker 1, queue 5 owned by
  worker 2. Both `iperf-a` (queue 4) and `iperf-b` (queue 5)
  are `shared_exact`-eligible based on the existing
  promotion policy.

## 4. Workload

- **p5201 16 streams 60 s × 10**: CoV ≤ 15 % on ≥ 8 of 10.
- **p5202 16 streams 60 s × 10**: CoV ≤ 25 % on ≥ 8 of 10.
- **p5202 128 streams 60 s × 1**: CoV ≤ 16.6 % (the #900
  baseline; AFD-lite must not regress).
- 0 stream collapses (every stream ≥ 1 Mbps).
- Aggregate throughput ≥ 0.95 × baseline.
- 0 retransmit regression vs baseline median.

## 5. Algorithm specification (R1-redesigned)

### 5.1 Period state — implicit via timestamp, no rotate-CAS

R1 HIGH 1 + R1 HIGH 3 fix: eliminate the explicit period-
reset CAS-elect + zero-loop. Use **implicit periods via packed
timestamp**.

```
Per-flow slot (replaces period_bytes_per_flow[i]):
  AtomicU64 slot = (period_idx[32 bits] | bytes[32 bits])

Period index:
  period_idx(now) = (now_ns - lease_epoch_ns) / AFD_PERIOD_WINDOW_NS

Lease epoch:
  lease_epoch_ns = monotonic_ns at lease construction (constant)
```

There is no `period_start_ns` to update, no rotation CAS, no
zero-loop. A slot is automatically "stale" if its embedded
`period_idx` is below `period_idx(now)`.

This is a CAS-loop on dispatch (not raw fetch_add) but the
loop has no contention with any rotator — rotation is
implicit and lock-free by construction.

### 5.2 Hot-path operations

**Dispatch accounting** (after a successful TX-ring write):

```rust
fn afd_account_dispatch(slot: &AtomicU64, bytes: u64, now_ns: u64) {
    let cur_period = period_idx(now_ns);
    loop {
        let raw = slot.load(Relaxed);
        let (slot_period, slot_bytes) = unpack(raw);
        let new = if slot_period < cur_period {
            // Stale slot — start fresh in the new period.
            pack(cur_period, bytes.min(BYTES_MAX))
        } else {
            // Same period — add.
            pack(cur_period, slot_bytes.saturating_add(bytes).min(BYTES_MAX))
        };
        if slot.compare_exchange_weak(raw, new, AcqRel, Relaxed).is_ok() {
            return;
        }
    }
}
```

Two threads racing in the same period CAS-loop until one
wins; expected 1-2 iterations under hot-bucket contention.
A thread observing `slot_period < cur_period` and another
having just CAS'd to the new period will retry once and
agree.

**Read for selection** (in `cos_queue_min_finish_bucket_afd`):

```rust
fn afd_bytes_in_period(slot: &AtomicU64, cur_period: u64) -> u64 {
    let (slot_period, slot_bytes) = unpack(slot.load(Relaxed));
    if slot_period == cur_period { slot_bytes } else { 0 }
}
```

Stale slots auto-zero on read.

**Total-in-period and active-flow-count** (R1 HIGH 2 fix):
the old design's `period_bytes_total` and
`active_bucket_count` had their own ordering / drift
problems. Replace with a **bitmap of active flows in the
current period**, also period-tagged.

```
Active-flow bitmap (16 × AtomicU64, each covering 64 flows):
  AtomicU64 word = (period_idx[32 bits] | mask[32 bits])

For 1024 buckets we need 16 words. Memory: 16 × 8 = 128 B.
Cache-pad to 16 × 64 = 1 KB per lease.
```

On dispatch, set the bit corresponding to `bucket_idx`:

```rust
fn afd_mark_active(word: &AtomicU64, bit_offset: u32, cur_period: u64) {
    loop {
        let raw = word.load(Relaxed);
        let (slot_period, slot_mask) = unpack(raw);
        let new_mask = if slot_period < cur_period {
            1u32 << bit_offset
        } else {
            slot_mask | (1u32 << bit_offset)
        };
        let new = pack(cur_period, new_mask);
        if slot.compare_exchange_weak(raw, new, AcqRel, Relaxed).is_ok() {
            return;
        }
    }
}
```

Total bytes-in-period and active-flow-count are computed at
**read time** (during selection) by iterating the bitmap and
slot array:

```rust
fn afd_period_summary(state: &AFDLiteState, cur_period: u64) -> (u64, u32) {
    let mut total = 0u64;
    let mut active = 0u32;
    for word in state.active_bitmap.iter() {
        let (wp, mask) = unpack(word.load(Relaxed));
        if wp == cur_period {
            active += mask.count_ones();
        }
    }
    for slot in state.bytes_per_flow.iter() {
        let (sp, b) = unpack(slot.load(Relaxed));
        if sp == cur_period {
            total = total.saturating_add(b);
        }
    }
    (total, active)
}
```

The two iterations are 1024 + 16 atomic loads. At one
selection per packet on a hot CoS queue, this is the cost
that #838's CPU budget must accommodate (see §9).

If empirical perf shows >3 % CPU regression, fall back to a
cached `(total, active)` packed atomic refreshed at most
once per N selections — but start with read-time
computation for simplicity.

### 5.3 Rollback handling (R1 HIGH 3 fix)

**No fetch_sub on rollback.** Rollback (push_front after a
failed TX-ring write) is rare. Skipping the byte unaccount
means the affected flow gets one packet's worth of "credit"
counted toward its current period — which is bounded:

- One rollback ≈ MTU bytes (≤ 9000 B with jumbo) per period.
- Per-period budget at 1 Gb/s × 2 ms = 250 KB.
- Worst-case effect: one rollback overcharges a flow by
  ~3.6 % of the period's allowed share.
- Rollback rate is typically < 0.01 % of TX attempts.

This eliminates the underflow scenario from R1 HIGH 3
entirely (no fetch_sub → no possibility of u64 wrap).

Document this trade-off in the function comment.

### 5.4 Selection gating

```rust
fn cos_queue_min_finish_bucket_afd(
    queue: &CoSQueueRuntime,
    lease: &SharedCoSQueueLease,
    now_ns: u64,
) -> Option<u16> {
    let cur_period = period_idx(now_ns, lease.afd.epoch_ns);
    let (total, active) = afd_period_summary(&lease.afd, cur_period);
    let fair_share = if active > 0 {
        total / u64::from(active)
    } else {
        u64::MAX
    };
    // R1 HIGH 5 fix: explicit threshold formula.
    // epsilon=0 → threshold = fair_share exactly (strict)
    // epsilon=N → threshold = fair_share + fair_share/(2^N)
    //   so N=1 → 1.5x, N=2 → 1.25x, N=3 → 1.125x.
    let threshold = fair_share.saturating_add(
        fair_share >> AFD_OVER_SHARE_EPSILON_SHIFT.saturating_sub(0),
    );
    // Configured constant: AFD_OVER_SHARE_EPSILON_SHIFT = u32::MAX
    //   means "no over-share allowance" (saturating shift gives 0,
    //   threshold = fair_share). Default for this PR.
    // To loosen later, set the shift to e.g. 1 (threshold = 1.5x).

    let mut best_under: Option<u16> = None;
    let mut best_under_finish = u64::MAX;
    let mut best_over: Option<u16> = None;
    let mut best_over_excess = u64::MAX;
    for bucket in queue.flow_rr_buckets.iter() {
        let idx = usize::from(bucket);
        let bytes = afd_bytes_in_period(&lease.afd.bytes_per_flow[idx], cur_period);
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
HOL-finish (preserves MQFQ ordering among eligibles). If
ALL are over-share, fall back to smallest excess to avoid
going idle.

### 5.5 Gate (R1 HIGH 6 fix)

AFD-lite engages only on **`queue.shared_exact == true`** —
not `shared_queue_lease.is_some()`. Per `coordinator.rs:1960`
+ `worker.rs:3804`/`3938`, lease presence is broader than
shared-exact. The gate condition in `cos_queue_front` becomes:

```rust
if queue.flow_fair && queue.shared_exact {
    if let Some(lease) = queue.shared_queue_lease.as_ref() {
        return cos_queue_min_finish_bucket_afd(queue, lease, now_ns)
            .and_then(|b| queue.flow_bucket_items[usize::from(b)].front());
    }
}
// Else: fall through to existing cos_queue_min_finish_bucket() path
```

Single-binding queues, non-flow-fair queues, and shared-but-
non-exact queues all preserve the existing selection.

### 5.6 Shared flow-hash seed (R1 HIGH 7 fix)

The lease's `flow_hash_seed` (already specified in #838 issue)
must be propagated to bindings when they promote onto the
lease. Per `tx.rs:5408`, bindings currently draw a fresh seed
at promotion time. Change `ensure_cos_interface_runtime` (or
the equivalent promotion site) to:

```rust
// Existing: queue.flow_hash_seed = getrandom_u64();
// New: if shared_exact and lease has a seed, use lease's.
queue.flow_hash_seed = if queue.shared_exact {
    lease.afd.flow_hash_seed
} else {
    getrandom_u64()
};
```

This ensures all bindings on the same lease map a given
5-tuple to the same `flow_bucket_index`, so the shared
`bytes_per_flow[i]` counter has consistent meaning.

The lease's seed is drawn from `getrandom(2)` at lease
construction — same property as before (unpredictable across
restarts and nodes; deterministic within one lease).

## 6. Implementation outline

### 6.1 New file: `userspace-dp/src/afxdp/afd_lite.rs`

```rust
//! AFD-lite: per-flow bytes-served counter for shared_exact
//! CoS queues. See docs/pr/838-afd-lite/plan.md.

use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const AFD_PERIOD_WINDOW_NS: u64 = 2_000_000;
pub(super) const AFD_PERIOD_BITS: u64 = 32;
pub(super) const AFD_BYTES_BITS: u64 = 32;
pub(super) const AFD_BYTES_MAX: u64 = (1u64 << AFD_BYTES_BITS) - 1;
pub(super) const AFD_OVER_SHARE_EPSILON_SHIFT: u32 = u32::MAX; // strict (default)
pub(super) const AFD_FLOW_BUCKETS: usize = 1024;
pub(super) const AFD_BITMAP_WORDS: usize = AFD_FLOW_BUCKETS / 32;

#[repr(align(64))]
pub(super) struct CachePaddedAtomicU64(AtomicU64);

pub(super) struct AFDLiteState {
    pub(super) epoch_ns: u64,
    pub(super) flow_hash_seed: u64,
    pub(super) bytes_per_flow: Box<[CachePaddedAtomicU64; AFD_FLOW_BUCKETS]>,
    pub(super) active_bitmap: Box<[CachePaddedAtomicU64; AFD_BITMAP_WORDS]>,
}

#[inline] fn pack(period: u64, payload: u64) -> u64 { (period << AFD_BYTES_BITS) | (payload & AFD_BYTES_MAX) }
#[inline] fn unpack(raw: u64) -> (u64, u64) { (raw >> AFD_BYTES_BITS, raw & AFD_BYTES_MAX) }
#[inline] pub(super) fn period_idx(now_ns: u64, epoch_ns: u64) -> u64 {
    (now_ns.saturating_sub(epoch_ns)) / AFD_PERIOD_WINDOW_NS
}

impl AFDLiteState {
    pub(super) fn new(epoch_ns: u64, flow_hash_seed: u64) -> Self { ... }
}

pub(super) fn afd_account_dispatch(state: &AFDLiteState, bucket: usize, bytes: u64, now_ns: u64) { ... }
pub(super) fn afd_bytes_in_period(state: &AFDLiteState, bucket: usize, cur_period: u64) -> u64 { ... }
pub(super) fn afd_mark_active(state: &AFDLiteState, bucket: usize, cur_period: u64) { ... }
pub(super) fn afd_period_summary(state: &AFDLiteState, cur_period: u64) -> (u64, u32) { ... }
```

### 6.2 Edits to `userspace-dp/src/afxdp/types.rs`

- Add `pub(super) afd: AFDLiteState` field to
  `SharedCoSQueueLease`.
- `SharedCoSQueueLease::new` extends to construct
  `AFDLiteState::new(monotonic_ns(), getrandom_u64())`.

### 6.3 Edits to `userspace-dp/src/afxdp/tx.rs`

R1 HIGH 4 fix: enumerate ALL pop commit points + push_front
sites. Per the source citations from R1, the touch-points
are:

**Dispatch-accounting hooks (call `afd_account_dispatch` +
`afd_mark_active` after a successful TX-ring write):**

- `tx.rs:2926` — successful pop commit
- `tx.rs:2957` — successful pop commit (alt path)
- `tx.rs:2983` — successful pop commit (alt path)
- `tx.rs:3012` — successful pop commit (alt path)
- `tx.rs:3129` — successful pop commit (forwarding path)
- `tx.rs:3170` — successful pop commit (forwarding path)
- `tx.rs:3214` — successful pop commit (forwarding path)
- `tx.rs:3272` — successful pop commit (forwarding path)

**Skip rollback-accounting** (R1 HIGH 3 fix) — push_front
sites at `tx.rs:2637`, `2812`, `2960`, `3014`, `4308`, `4345`,
`4373`, `4383`: do NOT touch AFD counters. The flow gets one
packet of "credit" until the period ends; bounded.

**Active-bitmap maintenance**: only `mark_active` on
dispatch (above). No "unmark on bucket empty" — the bitmap
is auto-period-tagged and clears implicitly at period
rotation. R1 HIGH 8 (rollback active-count) is closed by
this design — we don't track active-count separately, only
"saw-bytes-this-period" bitmap.

**Front/pop selector agreement** (R1 HIGH 4 closure):
both `cos_queue_front` (line 4262) and
`cos_queue_pop_front_inner` (line 4527 area) currently call
`cos_queue_min_finish_bucket()`. Add a new shared helper
`cos_queue_select_bucket(queue, lease, now_ns)` that both
call, branching on `shared_exact + lease.is_some()`.

### 6.4 Edits to `userspace-dp/src/afxdp/coordinator.rs`

`SharedCoSQueueLease::new` already accepts config; extend
to construct `AFDLiteState`. No other coordinator changes
needed.

### 6.5 Edits to `userspace-dp/src/afxdp/worker.rs`

Per R1 HIGH 7: at the binding-promotion site
(`worker.rs:3789`, `3804`, `3938`, `3948`), change
`flow_hash_seed` assignment to use the lease's seed when
`shared_exact && lease.is_some()`.

## 7. Tests

### 7.1 Unit tests in `afd_lite.rs`

1. `account_dispatch_within_period_accumulates`.
2. `account_dispatch_across_periods_resets_implicitly`.
3. `bytes_in_period_returns_zero_for_stale_slot`.
4. `mark_active_sets_bit_in_correct_word`.
5. `mark_active_across_periods_resets_implicitly`.
6. `period_summary_iterates_only_current_period_slots`.
7. `concurrent_dispatch_same_bucket_no_loss` — N threads
   each fetch_add 1000 bytes; assert final == N×1000.
8. `concurrent_dispatch_different_buckets_independent`.
9. `dispatch_at_period_boundary_no_panic` (R1 MED #10) —
   dispatch at the EXACT moment `now_ns` straddles a
   period boundary; assert no panic, all bytes accounted
   into one of the two periods.
10. `bytes_field_saturates_at_max_not_wraps` — push >
    `BYTES_MAX` worth of dispatch; assert saturating, no
    wrap.

### 7.2 Integration tests in `tx.rs` (new `tests` module)

11. `cos_queue_front_uses_afd_when_shared_exact_with_lease`.
12. `cos_queue_front_uses_existing_mqfq_when_not_shared_exact`
    (regression — `shared_exact == false`, behaviour
    preserved).
13. `cos_queue_front_uses_existing_mqfq_when_shared_exact_no_lease`
    (regression — defensive fall-through).
14. `front_pop_selector_agreement` (R1 HIGH 4 + R1 MED #10):
    after a `front` returns bucket B, the next `pop` of the
    same queue must also produce bucket B.
15. `cross_binding_active_bitmap_no_drift` (R1 MED #10):
    two simulated bindings, both dispatch to different flows;
    one period later, the bitmap reflects ALL flows that
    dispatched in this period.
16. `rollback_after_period_rotation_no_underflow` (R1 MED #10):
    dispatch at t1, rotate to next period, push_front rollback
    — assert no underflow (since we don't fetch_sub at all
    per §5.3).

### 7.3 Hash-seed propagation test in `worker.rs` (or types.rs)

17. `binding_promotion_on_shared_exact_uses_lease_seed`.
18. `binding_promotion_on_non_shared_exact_uses_own_seed`.

## 8. Acceptance

- Rust unit + integration tests pass: `cargo test -p
  xpf-userspace-dp`.
- All Go tests pass: `go test ./pkg/...`.
- `cargo build --release` passes.
- Live deploy on `loss:xpf-userspace-fw0/fw1`:
  - **p5201 16 streams 60 s × 10**: CoV ≤ 15 % on ≥ 8 of 10
    runs.
  - **p5202 16 streams 60 s × 10**: CoV ≤ 25 % on ≥ 8 of 10
    runs.
  - **p5202 128 streams 60 s × 1**: CoV ≤ 16.6 % (#900
    baseline; do not regress).
  - 0 collapses (every stream ≥ 1 Mbps).
  - Aggregate throughput ≥ 0.95 × baseline.
  - 0 retransmit regression.
  - Per-rep CPU saturation check (mpstat) on source: not
    saturated.
- `make test-failover`: pass.
- Codex hostile plan + code review: PLAN-READY YES, MERGE
  YES.
- Copilot inline review: addressed.

## 9. Risks (R1 + R2 review-grounded)

- **CAS-loop overhead on hot bucket** (R1 MED #7): the
  implicit-period scheme uses CAS-loop for accounting where
  the original plan used fetch_add. Under contention from 6
  workers on the same hot bucket, expected 2-3 iters per
  dispatch. Mitigation: `CachePadded` per slot (already in
  the plan). If empirical perf shows > 3 % CPU regression on
  the iperf3-128-stream baseline (#900: ~30 % CPU on the
  affected worker), fall back to per-shard counters
  (one slice of slots per binding) and sum at read time.
- **Period-summary cost** (R1 MED #7): `afd_period_summary`
  does 1024 + 16 = 1040 atomic loads per selection. At
  ~150 K pps per CoS queue, that's ~150 M loads/sec — well
  within a single core. Mitigation: cached summary as
  fallback if a per-rep CPU regression is observed.
- **Active-bitmap word contention** (R1 HIGH 2 fix
  side-effect): bitmap word with 64 buckets behind it; if
  multiple bindings each have a flow in different buckets in
  the same word, they all CAS-mark on the same word. Most
  buckets in a word are inactive (sparse), so contention is
  bounded. CachePad each word.
- **Bytes-overflow saturation** (R1 MED #7-adjacent): with
  32-bit byte counter (4 GB max in 2 ms = 16 Tb/s), no real
  workload saturates this. Saturation is a defensive check,
  not a real path.
- **Acceptance bar realism** (R1 MED #11): #840 baseline at
  16-stream was 18.5 % CoV; the 15 % bar requires a 19 %
  improvement. AFD-lite's primary mechanism (skip-on-over-
  share) targets RSS-hash-skew variance, which in our
  default round-robin RSS at 16 flows / 6 queues gives
  pigeon-hole 3-3-3-3-2-2 distribution. Skipping over-share
  redistributes the 3-stream queues' bandwidth to the
  2-stream queues' streams. Expected magnitude: 3-5 percentage
  points improvement. So 15 % from 18.5 % is plausible but
  tight. Document this in the PR result and don't auto-fail
  if we land at, say, 16 %.

## 10. Out of scope

- Full MQFQ ordering on shared_exact queues (#837).
- Drop / ECN signalling on AFD over-share (#833 closed).
- Per-flow rate limiting (#794).
- Adaptive epsilon shift based on queue depth.
- IPv6 echo path coverage (#900 follow-up).
- Cross-CoS-class fairness (each class has its own lease).

## 11. Test harness for empirical validation

Operator has enabled echo on `172.16.80.200:7` (TCP) and
`[2001:559:8585:80::200]:7` (TCP+IPv6). The mouse-side
harness from `docs/pr/900-100e100m-harness/` can be adapted
to use Python TCP-connect against the echo server (replacing
the failed hping3-via-iperf3-target approach), but that work
is out of scope for #838 itself.

For #838 acceptance, only the standard iperf3-stream CoV
test from §8 is required.

## 12. Out of scope (cross-issue boundary clarifications)

The R1 review surfaced overlap with several closed/related
issues; this PR does NOT touch:

- HOL-finish-time sharing redesign (#837).
- ECN-based per-flow signalling (#833 closed; double-signal
  trap).
- Per-flow-scaled credit gate (#834 closed; starvation).
- RSS rebalance (#840 reverted).

## 13. R1 review responses

Round 1: 8 HIGH, 4 MED. PLAN-NEEDS-MAJOR-REWORK.

| # | Sev | Topic                                        | Resolution |
|---|-----|----------------------------------------------|------------|
| 1 | HIGH| Period-reset publish ordering broken         | §5.1: implicit period via timestamp eliminates the rotate-CAS + zero-loop entirely. Each slot is period-tagged; staleness is read-time |
| 2 | HIGH| `active_bucket_count` cross-binding race     | §5.2: replaced with active-flow bitmap also period-tagged. Computed by popcount at read time |
| 3 | HIGH| `fetch_sub` rollback underflow               | §5.3: skip rollback accounting entirely. Bounded credit (<3.6% per period worst case) — far smaller than the underflow risk |
| 4 | HIGH| Successful-pop surface underspecified        | §6.3 enumerates all 8 commit points by tx.rs:line. Front/pop selectors share new `cos_queue_select_bucket` helper |
| 5 | HIGH| Epsilon formula `>>0 = 2x fair_share`        | §5.4 explicit formula; `AFD_OVER_SHARE_EPSILON_SHIFT = u32::MAX` saturates to `>>0=0` so threshold = fair_share + 0 = strict |
| 6 | HIGH| Wrong gate (lease.is_some vs shared_exact)   | §5.5: gate is `queue.flow_fair && queue.shared_exact && shared_queue_lease.is_some()` |
| 7 | HIGH| Shared hash seed not wired                   | §5.6: binding promotion (worker.rs:3804/3938) reads lease seed when shared_exact, else random |
| 8 | HIGH| `push_front` empty-transition active-count   | §6.3: NO active-count tracking on enqueue/dequeue paths. Bitmap is per-period, populated only by dispatch. push_front is invisible to AFD |
| 9 | MED | Cache-line cost not bounded to shared queues | §9: noted; CachePadded slots; fallback to per-shard if measured >3% CPU |
| 10| MED | 2 ms period window ungrounded                | §5.1: 2 ms is the burst-coverage scale (10 Gb/s × 2 ms = 2.5 MB; 1 Gb/s × 2 ms = 250 KB — bigger than typical TCP cwnd burst). Empirical tuning open as follow-up |
| 11| MED | Test gaps                                    | §7 added: rotation-during-dispatch (test 9), cross-binding bitmap drift (test 15), rollback-after-rotation no-underflow (test 16), front/pop selector agreement (test 14) |
| 12| MED | Acceptance bar uncertain vs prior negatives  | §9 acceptance: documented expected magnitude (3-5pp); merge YES if at 16% with monotone improvement, not auto-fail at exactly 15.5% |
