# #838 — AFD-lite: per-flow bytes-served counter with periodic reset

## 1. Goal

Improve cross-binding fair queueing on `shared_exact` CoS queues
without the surface area of full HOL-finish-time sharing
(#836 → 7 HIGH findings → closed; tracked in #837 as the
"big-design" alternative).

This implements the **smaller-surface alternative** described in
#838: track bytes dispatched per flow-bucket per time window,
shared across all bindings on a `SharedCoSQueueLease`. Bucket
selection skips flows that are over their fair share for one
round-robin cycle.

## 2. What this is NOT

- Not a full MQFQ replacement. Single-binding `flow_fair` queues
  retain their existing `cos_queue_min_finish_bucket()` HOL-
  finish-time selection (proven correct in #785).
- Not a drop / ECN path. Skip-on-selection only — no admission
  changes (avoids the #833 double-signal trap).
- Not Count-Min sketch. Use a fixed `[AtomicU64; 1024]` array
  keyed by `flow_bucket_index` — already bounded by
  `COS_FLOW_FAIR_BUCKETS`.
- Not RSS rebalance. Orthogonal to #840 (closed); operates inside
  the dataplane regardless of NIC RSS distribution.

## 3. Test environment

- Cluster: `loss:xpf-userspace-fw0/fw1` (RG0 primary).
- Source: `loss:cluster-userspace-host`.
- Targets:
  - `172.16.80.200` — iperf3 server on port 5201 (existing) +
    TCP/UDP echo on port 7 (newly enabled by operator,
    confirmed reachable).
  - `2001:559:8585:80::200` — same hosts, IPv6.
- CoS class: **iperf-a** (1 Gb/s shaped) for the tightest
  acceptance target; **iperf-b** (10 Gb/s) for higher-aggregate
  characterisation.
- Workers=6, queue 4 owned by worker 1, queue 5 owned by
  worker 2 (per live `show class-of-service interface`).

## 4. Workload

Acceptance reproduces the #786 Slice C test:

- **p5201 16 streams 60 s** (CoV ≤ 15 % on ≥ 8 of 10 runs).
- **p5202 16 streams 60 s** (CoV ≤ 25 % on ≥ 8 of 10 runs).
- **p5202 128 streams 60 s** (additional characterisation —
  current baseline 16.6 % CoV, see #900 finding).

## 5. Algorithm specification

### 5.1 Shared state added to `SharedCoSQueueLease`

```rust
// In userspace-dp/src/afxdp/types.rs, alongside existing
// SharedCoSLeaseState fields:

struct AFDLiteState {
    period_start_ns: AtomicU64,
    period_bytes_total: AtomicU64,
    period_bytes_per_flow: Box<[CachePadded<AtomicU64>; COS_FLOW_FAIR_BUCKETS]>,
    /// Cached active-bucket count for fair_share = total / active.
    /// Updated on bucket 0→N and N→0 transitions; ≤ one window stale.
    active_bucket_count: AtomicU32,
    /// Locked at lease construction; bindings on the same lease
    /// MUST use this seed so flow→bucket maps consistently.
    flow_hash_seed: u64,
}

const AFD_PERIOD_WINDOW_NS: u64 = 2_000_000;  // 2 ms
const AFD_OVER_SHARE_EPSILON: u64 = 0;         // skip when bytes > fair_share*1.0; tunable
```

`COS_FLOW_FAIR_BUCKETS = 1024` × 64 bytes (cache-line padded
AtomicU64) = **64 KB** per shared lease. Acceptable.

### 5.2 Hot-path operations

**On every successful packet dispatch** (post-write to TX
ring, per existing `cos_queue_pop_*` paths):

```rust
// 1. Account bytes
state.period_bytes_per_flow[bucket].fetch_add(bytes, Relaxed);
state.period_bytes_total.fetch_add(bytes, Relaxed);

// 2. Maybe rotate window
let now = monotonic_ns();
let start = state.period_start_ns.load(Relaxed);
if now.saturating_sub(start) >= AFD_PERIOD_WINDOW_NS {
    // CAS-elect a single rotator; losers fall through
    if state.period_start_ns
        .compare_exchange(start, now, AcqRel, Relaxed)
        .is_ok()
    {
        // Winner zeros all per-flow counters and total.
        // Relaxed stores: any racer's adds during this rotation
        // window land in the new period; transient skew bounded
        // by 2 ms.
        state.period_bytes_total.store(0, Relaxed);
        for slot in state.period_bytes_per_flow.iter() {
            slot.store(0, Relaxed);
        }
    }
}
```

**On packet rollback** (`push_front` after a failed write):

```rust
state.period_bytes_per_flow[bucket].fetch_sub(bytes, Relaxed);
state.period_bytes_total.fetch_sub(bytes, Relaxed);
```

`fetch_sub` is the inverse of `fetch_add` and is also
commutative — unlike HOL-finish-time, byte counts are a
proper ledger that supports rollback (this is the key safety
property that makes AFD-lite race-tolerant where the #836
HOL-finish design wasn't).

### 5.3 Selection gating in `cos_queue_min_finish_bucket`

The existing `cos_queue_min_finish_bucket` iterates
`flow_rr_buckets` picking the smallest `head_finish_bytes`.
With AFD-lite, on a `shared_exact` queue **with a shared
lease**:

```rust
fn cos_queue_min_finish_bucket_afd(queue: &CoSQueueRuntime, lease: &SharedCoSQueueLease) -> Option<u16> {
    let total = lease.afd.period_bytes_total.load(Relaxed);
    let active = lease.afd.active_bucket_count.load(Relaxed) as u64;
    let fair_share = if active > 0 { total / active } else { u64::MAX };
    let threshold = fair_share + (fair_share >> AFD_OVER_SHARE_EPSILON);
    // Threshold = fair_share * 1.0 with epsilon=0 (initial conservative);
    // becomes fair_share * 1.5 with epsilon=1 if needed.

    let mut best_finish = u64::MAX;
    let mut best: Option<u16> = None;
    let mut best_excess = u64::MAX;
    let mut best_excess_bucket: Option<u16> = None;
    for bucket in queue.flow_rr_buckets.iter() {
        let finish = queue.flow_bucket_head_finish_bytes[usize::from(bucket)];
        let bytes_served = lease.afd.period_bytes_per_flow[usize::from(bucket)].load(Relaxed);
        if bytes_served <= threshold {
            // Eligible; pick by HOL-finish (existing MQFQ rule).
            if finish < best_finish {
                best_finish = finish;
                best = Some(bucket);
            }
        } else {
            // Over-share; track smallest excess as fallback.
            let excess = bytes_served.saturating_sub(threshold);
            if excess < best_excess {
                best_excess = excess;
                best_excess_bucket = Some(bucket);
            }
        }
    }
    best.or(best_excess_bucket)
}
```

If at least one bucket is under-share, pick the eligible
bucket with smallest HOL-finish-time (preserves MQFQ
ordering among eligibles). If ALL buckets are over-share
(e.g. start of window before counters drop), fall back to
the smallest-excess bucket so we don't go idle.

### 5.4 Active-bucket-count maintenance

`flow_rr_buckets` already tracks the set of non-empty
buckets — bucket added on first push to empty bucket
(`was_empty == true`), removed on last pop. Mirror this into
`active_bucket_count` via `fetch_add`/`fetch_sub` at the same
sites:

```rust
// On bucket 0 → 1 transition (push to empty bucket):
state.active_bucket_count.fetch_add(1, Relaxed);

// On bucket 1 → 0 transition (pop last item from bucket):
state.active_bucket_count.fetch_sub(1, Relaxed);
```

Cached count is used only for fair_share computation (an
approximation); ≤ one window stale is fine.

### 5.5 Single-binding queues unchanged

`!shared_exact` queues (single binding owns the queue) keep
the existing `cos_queue_min_finish_bucket()` MQFQ ordering
unchanged. AFD-lite only engages when
`shared_queue_lease.is_some()`.

## 6. Implementation outline

### 6.1 New file: `userspace-dp/src/afxdp/afd_lite.rs`

- `pub(super) struct AFDLiteState { ... }` (per §5.1).
- `pub(super) const AFD_PERIOD_WINDOW_NS: u64 = 2_000_000;`
- `pub(super) const AFD_OVER_SHARE_EPSILON: u32 = 0;`
- `impl AFDLiteState { fn new(seed: u64) -> Self; }`
- Free fn `afd_account_dispatch(state, bucket, bytes, now_ns)`.
- Free fn `afd_account_rollback(state, bucket, bytes)`.
- Free fn `afd_active_inc(state)` / `afd_active_dec(state)`.
- Free fn `afd_select_bucket(queue, state) -> Option<u16>`.

### 6.2 Edits to existing files

- `userspace-dp/src/afxdp/types.rs`:
  - Add `afd: AFDLiteState` to `SharedCoSQueueLease`.
  - Add `mod afd_lite;` import.
- `userspace-dp/src/afxdp/tx.rs`:
  - In `cos_queue_front` (line 4262): when `queue.flow_fair`
    AND `shared_queue_lease.is_some()`, call
    `afd_select_bucket(queue, lease)` instead of the existing
    `cos_queue_min_finish_bucket(queue)`.
  - In every successful pop path (after the kernel ring write
    succeeds): call `afd_account_dispatch`.
  - In every `push_front` rollback path: call
    `afd_account_rollback`.
  - In `cos_queue_push_back` at the `was_empty` transition
    (line ~4302): call `afd_active_inc` if shared lease.
  - In the bucket-empty transition on pop: call
    `afd_active_dec` if shared lease.

### 6.3 Coordinator

`SharedCoSQueueLease::new()` (currently constructs only
`SharedCoSLeaseConfig`/`State`) extends to also build the
AFD-lite state with `flow_hash_seed` drawn from
`getrandom(2)` — same seed all bindings on the lease use.

## 7. Tests

In `userspace-dp/src/afxdp/afd_lite.rs` (new module tests):

1. `account_dispatch_increments_total_and_bucket`.
2. `account_rollback_inverts_dispatch`.
3. `period_rotation_zeros_counters`.
4. `concurrent_rotators_only_one_wins` (CAS race test with
   spawned threads).
5. `active_inc_dec_round_trip` (idempotent under matched
   inc/dec).
6. `select_picks_under_share_first` — synthetic state where
   bucket A is over-share and bucket B is under-share; assert
   B is picked.
7. `select_falls_back_to_smallest_excess_when_all_over_share`.
8. `select_preserves_mqfq_among_eligibles` — multiple under-
   share buckets, smallest HOL-finish wins.
9. `select_at_period_boundary_no_panic` — stress test where
   the period rotates during a select call.

In `userspace-dp/src/afxdp/tx.rs` (integration):

10. `cos_queue_front_uses_afd_when_shared_lease`: build a
    queue with `shared_queue_lease.is_some()`, fill two
    buckets with different head-finish times, mark one as
    over-share via direct `afd.period_bytes_per_flow` write,
    assert `cos_queue_front` returns the under-share one.
11. `cos_queue_front_uses_mqfq_when_no_shared_lease`:
    regression — `shared_queue_lease.is_none()`, the existing
    behaviour is preserved exactly.

## 8. Acceptance

- All Rust unit tests pass (`cargo test -p xpf-userspace-dp`).
- All Go tests pass.
- Live deploy on `loss:xpf-userspace-fw0/fw1`:
  - **p5201 16 streams 60 s × 10**: CoV ≤ 15 % on ≥ 8 of 10
    runs.
  - **p5202 16 streams 60 s × 10**: CoV ≤ 25 % on ≥ 8 of 10
    runs.
  - **p5202 128 streams 60 s × 1**: CoV ≤ baseline (16.6 %
    from #900 finding).
  - 0 collapses (every stream ≥ 1 Mbps).
  - Aggregate throughput ≥ 0.95× baseline (no regression).
  - 0 retransmit regression vs baseline median.
- `make test-failover`: pass (defense — touching dataplane
  cross-binding state).
- Codex hostile plan + code review rounds: PLAN-READY YES,
  MERGE YES.
- Copilot inline review: addressed.

## 9. Risks

- **Active-bucket-count drift**: cached count can fall out of
  sync with reality if a `fetch_add`/`fetch_sub` is missed.
  Mitigation: place the inc/dec at the SAME control-flow site
  as `flow_rr_buckets.push_back` / pop (which is the
  authoritative source). Pin via test #5.
- **Period-boundary thrash**: at the exact rotation moment,
  one thread observes pre-rotation counters while another
  observes post-rotation. Bounded by 2 ms; no correctness
  consequence (counters are commutative). Pin via test #9.
- **Over-share threshold sensitivity**: epsilon=0 with strict
  fair_share may oscillate under high contention. Start with
  epsilon=0, tune up to 1 (fair_share × 1.5) only if
  empirical data shows oscillation.
- **MQFQ ordering loss on shared queues**: AFD-lite decouples
  the long-run byte-share from per-packet HOL-finish-time on
  shared queues. Slight unfairness vs pure MQFQ for bursty
  mixed-size workloads. Quantify in §8 with the standard
  acceptance suite.
- **Cache-line contention**: 1024 atomics × per-dispatch
  fetch_add. With 6 workers all dispatching on the same lease
  simultaneously, hot buckets (1-2 elephants) will see
  cross-CPU cacheline bouncing. Bound by `CachePadded` and by
  the fact that elephants are bursty (not lockstep on a
  single bucket). If empirical perf shows >3% CPU regression,
  fall back to per-shard counters (one slice per binding) and
  sum at read time.

## 10. Out of scope

- Full MQFQ ordering preservation on shared queues (#837).
- Drop / ECN signalling on AFD over-share (#833 closed; double-
  signal trap).
- Per-flow rate limiting (#794 covers AFD policer; this issue
  is selection-time skip only).
- Adaptive epsilon based on queue depth.
- IPv6 echo path coverage (the harness uses TCP-connect to
  `172.16.80.200:7`; IPv6 to `[2001:559:8585:80::200]:7` is a
  follow-up if needed).

## 11. Test harness for empirical validation

Now that the operator has enabled echo on `172.16.80.200:7`
(TCP) and `[2001:559:8585:80::200]:7` (IPv6+TCP), the
mouse-side harness from `docs/pr/900-100e100m-harness/` can
be adapted to use Python TCP-connect against the echo server
(replacing the failed hping3-and-iperf3-target approach). Out
of scope for #838 itself but unblocks the empirical mouse-
latency-tail measurement once #838 lands.

For #838 acceptance, only the standard iperf3-stream CoV
test from §8 is required.
