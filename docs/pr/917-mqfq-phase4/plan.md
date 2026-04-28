# Plan: #917 — MQFQ Phase 4: cross-worker V_min synchronization

Issue: #917
Parent: #793 (Phase 4 umbrella), #786 (cross-worker fair-queueing research)
Diagnosis: `docs/pr/917-mqfq-phase4/diagnostic.md`
Predecessor: #913 (within-worker MQFQ vtime fix, shipped)

## 1. Problem

Per-worker MQFQ (post-#913) correctly equalizes flows _within
each worker_ but cannot see across workers. With RSS-driven flow
assignment, cross-worker imbalance is the dominant source of
per-flow CoV at iperf-c P=12 (measured 35–68 % CoV vs the #789
≤ 20 % gate). The diagnostic doc records the empirical evidence:
worker 0 sat fully idle for 20 s while worker 5 carried 27 % of
the traffic.

Per-worker MQFQ has no mechanism to throttle a fast worker so a
slower peer can catch up. Each worker's `queue_vtime` advances
purely from local pop activity. When workers carry unequal flow
counts, the fast worker's vtime sprints ahead of the slow worker's
— and since per-flow finish-times are anchored to `queue_vtime`,
the fast worker's flows accumulate more service while the slow
worker's flows lag.

## 2. Goal

Add a cross-worker virtual-time floor (V_min) to each shared_exact
CoS queue. Workers throttle when their local `queue_vtime`
advances more than `LAG_THRESHOLD` past V_min, giving slower
peers time to catch up.

**Honest scope note.** V_min sync does NOT lift the aggregate
throughput ceiling when one worker is fully idle (RSS gives that
worker zero flows). It improves per-flow CoV across workers in
the multi-flow-per-worker case. The aggregate ceiling lifter
(re-steering flows away from idle workers) requires changes to
the AF_XDP topology that are out of scope for #917 — tracked in
#899 / future work.

Quantitative target:

- Per-flow CoV at iperf-c P=12 drops from 35–68 % to ≤ 20 %
  when the RSS distribution is non-degenerate (every worker
  has at least one flow).
- iperf-c P=12 throughput in the non-degenerate case improves
  to within 10 % of the same-workload P=128 measurement.
- No throughput regression in the degenerate case (idle worker)
  vs current behavior — at minimum, the existing cap of
  `(N-idle)/N × shaper_rate` is preserved.

## 3. Approach

### 3.1 Design overview

Per shared_exact CoS queue, add a fixed-size array of
`AtomicU64` slots — one per worker — co-located with the
existing `SharedCoSQueueLease`. Each worker writes its OWN
slot's value (its current local `queue_vtime`) and reads peers'
slots (atomic loads). V_min is computed locally on each
scheduling decision as the minimum across the slots whose worker
is currently `participating` (i.e., has a non-empty bucket on
this queue).

```
struct SharedCoSQueueVtimeFloor {
    // One slot per worker, on its own cache line to avoid
    // false sharing.
    slots: [PaddedAtomicU64; MAX_WORKERS],
    // Epoch counter — workers bump this when entering/leaving
    // "participating" state so peer reads can observe the
    // membership change without scanning a separate flag array.
    epoch: AtomicU64,
}
```

### 3.2 Publish path (per-worker)

**v2 rewrite (Codex R1 BLOCKING).** v1 said "publish on every
pop." That is wrong: post-#913 the pop hot path performs a
SPECULATIVE vtime advance during scratch-batch building, which
is later rolled back via `cos_queue_push_front` if the scratch
builder retracts. Publishing at the speculative pop would leak
uncommitted vtime advance to peers, falsely throttling them.

Publication semantics must be defined at the COMMIT boundary,
not the speculative pop. The two production paths are:

- **Snapshot-stack pop** (`cos_queue_pop_front` at
  `tx.rs:~4400`): pushes a `CoSQueuePopSnapshot` onto the
  stack at speculative pop; the snapshot is later cleared by
  the commit helper (`cos_queue_clear_orphan_snapshot_after_drop`
  on the no-rollback path) when TX submission succeeds, or
  consumed by `cos_queue_push_front` on rollback. Hook the
  V_min publish into the commit-clear path so peers only see
  vtime advance after TX commit.

- **No-snapshot pop** (`cos_queue_pop_front_no_snapshot` at
  `tx.rs:~4670`): used by drains that visit > TX_BATCH_SIZE
  items where snapshots can't be retained. These pops
  immediately advance vtime with no rollback path; publish
  inline at the vtime-advance site.

Both paths converge on:

```rust
// Single helper, called at commit boundary:
fn publish_v_min(floor: &SharedCoSQueueVtimeFloor, worker_id: u32, vtime: u64) {
    floor.slots[worker_id as usize].publish(vtime); // Release store
}
```

**Cost reasoning.** At commit-boundary publish on a 25 Gb/s
queue with TX_BATCH_SIZE = 64, that's ~32 K commits/s/worker
(2 Mpps / 64). One Release store per commit ≈ 2 ns × 32 K =
64 µs/s = 0.006 % of one core. Negligible.

**Rollback path** must also publish — the rolled-back vtime is
the new "last committed" vtime. `cos_queue_push_front` already
restores `queue.queue_vtime` from the snapshot; add the same
publish there.

**Speculative-pop visibility (Gemini R2 Q7 clarification).**
Peers read the per-worker SLOT, not the local
`queue.queue_vtime` directly. The speculative pop's vtime
advance is purely thread-local until commit publishes it. So
peers never see the speculative value — the speculative window
is invisible by construction. The "publish only at commit"
intent is preserved; the slot atomic is the single point of
visibility.

### 3.3 Read path (per-worker)

**v2 (Codex R1 — commit to read cadence K).** The naive "check
on every pop" multiplies cache-line traffic with every per-flow
scheduling decision. At 2 Mpps with N-1 = 5 cache-line pulls
per check, K=1 → 10 M peer-line reads/s/worker; K=16 → 625 K/s.

**Decision: K = 8 + mandatory check at drain-batch start.**

Bounded-drift rule: `K × MTU ≤ LAG_THRESHOLD / 4`. The bound
must hold for the WORST-case MTU we configure on this cluster.
With jumbo frames (9000 B) supported (Gemini R2 caught my v2
error of K=16 violating the bound at jumbo MTU):

- iperf-c LAG_THRESHOLD = 520 KB at 6 participating workers.
  130 KB / 9000 B = 14.4 → K ≤ 14 at jumbo.
- iperf-c LAG_THRESHOLD = 625 KB at 5 workers (one idle).
  156 KB / 9000 B = 17.3 → K ≤ 17 at jumbo.
- iperf-b LAG_THRESHOLD = 208 KB at 6 workers.
  52 KB / 9000 B = 5.7 → K ≤ 5 at jumbo (binding case).

K = 8 satisfies non-iperf-b bounds at jumbo MTU and gives a
clean 4× cache-line-traffic reduction vs K = 1. iperf-b at
jumbo MTU + 6 participating workers technically violates the
formal bound (K = 8 > 5); since iperf-b on the loss cluster
runs 1500 B MTU and the bound is a safety factor (already
includes a /4 margin), K = 8 is acceptable in practice. If
jumbo + iperf-b becomes a real configuration, recompute.

iperf-a (1 Gbps) is out of scope here: per §3.5 the V_min
read path is gated on `queue.shared_exact == true`, and
iperf-a queues are owner-local-exact (single-owner; below
the 2.5 Gbps `COS_SHARED_EXACT_MIN_RATE_BYTES` promotion
threshold). The K bound is never evaluated for iperf-a.

Tradeoff if K = 14 (jumbo-safe at iperf-c only): cache-line
traffic only 7 % lower than K = 8 at higher pop count. Not
worth the small win.

```rust
fn maybe_check_v_min(
    queue: &mut CoSQueueRuntime,
    floor: &SharedCoSQueueVtimeFloor,
    worker_id: u32,
    drain_pop_count: &mut u32,
) -> VMinDecision {
    *drain_pop_count = drain_pop_count.wrapping_add(1);
    // Check on every Kth pop, plus mandatory check at batch start.
    if *drain_pop_count % V_MIN_READ_CADENCE != 0
        && *drain_pop_count != 1
    {
        return VMinDecision::Continue;
    }

    let mut participating = 0u32;
    let mut v_min = u64::MAX;
    for (w, slot) in floor.slots.iter().enumerate() {
        if w == worker_id as usize { continue; }
        if let Some(peer_vtime) = slot.read() {
            participating += 1;
            v_min = v_min.min(peer_vtime);
        }
    }
    if participating == 0 {
        // No peers active on this queue; trivially lead.
        return VMinDecision::Continue;
    }
    let lag = compute_lag_threshold(
        queue.transmit_rate_bytes, participating + 1);
    if queue.queue_vtime > v_min.saturating_add(lag) {
        VMinDecision::Throttle { until_vtime: v_min + lag }
    } else {
        VMinDecision::Continue
    }
}

const V_MIN_READ_CADENCE: u32 = 8;
```

**Cost reasoning.** N-1 Acquire loads at distinct cache lines
(per-slot padding). At MAX_WORKERS = 8 that's 7 cache-line
pulls per check, ~5–20 ns depending on coherence state.
Throttled to 1-in-K=16 pops; with batch-start check the
amortized cost on the hot path is well under 1 ns/pop.

**Reading worker_id == self_id is skipped**; reading own slot
is meaningless and risks self-throttle.

**Honest note**: peer cache lines flicker between Modified
(when peer publishes) and Shared (when this worker reads).
Each read tends to invalidate the peer's M-state, forcing
the peer to refetch on its next publish. At small
LAG_THRESHOLD this could cause MOESI ping-pong. The §7 risk
section flags this for cluster-side measurement.

### 3.4 The "participating" predicate

**v2 (Codex R1 BLOCKING — pick one, define ordering).** A
worker is `participating` on a queue if it has any flow with
positive `flow_bucket_bytes` for that queue.

**Decision: Option B with explicit Release/Acquire ordering.**
The slot holds `u64::MAX` when not participating, otherwise
holds the live committed `queue_vtime`. Single u64 atomic per
slot — simpler than a paired (bool + u64).

Memory ordering, made explicit:

```rust
struct PaddedSlot {
    // u64::MAX = not participating; any other value = live vtime
    vtime: AtomicU64,
    _pad: [u8; 56],  // pad to 64-byte cache line
}
const NOT_PARTICIPATING: u64 = u64::MAX;

impl PaddedSlot {
    /// Worker calls this when its bucket count for this queue
    /// transitions 0 → ≥1 (first enqueue) AND on every commit
    /// boundary publish (§3.2). Release store ensures any
    /// prior writes to flow_bucket_bytes etc. are visible to
    /// readers that observe this slot.
    fn publish(&self, vtime: u64) {
        debug_assert_ne!(vtime, NOT_PARTICIPATING,
            "live vtime must not equal sentinel");
        self.vtime.store(vtime, Ordering::Release);
    }

    /// Worker calls this when its bucket count transitions
    /// ≥1 → 0 (last drain).
    fn vacate(&self) {
        self.vtime.store(NOT_PARTICIPATING, Ordering::Release);
    }

    /// Peer reads. If MAX, treat as not-participating and skip
    /// in the V_min reduction.
    fn read(&self) -> Option<u64> {
        let v = self.vtime.load(Ordering::Acquire);
        if v == NOT_PARTICIPATING { None } else { Some(v) }
    }
}
```

**Race-window analysis** (Codex R1 demanded):

- _join race_: worker bumps bucket count 0 → 1, slot is still
  MAX for one instruction. Peer reading at this point sees MAX
  → skips worker → no false throttling on the peer. After the
  first publish in the same drain cycle, peer sees the live
  vtime. **Bounded**: peer over-tolerates lag for one drain
  tick. Acceptable.

- _leave race_: worker bumps bucket count 1 → 0, then vacates
  (stores MAX). Peer reading between commit and vacate sees
  the last live vtime. Peer's V_min may use a stale low value
  (the worker's vtime at last commit), causing minor
  over-throttling on peers. Bounded: peer pessimizes for one
  drain tick, then on its next read sees MAX and the
  participating-set drops. Acceptable.

- _re-join race_: worker leaves and immediately re-joins
  before a peer's next read. Peer reads the new live vtime
  (correct). No corruption.

**No race causes scheduler-correctness violation.** All races
are bounded over-throttle / under-throttle of at most one drain
tick per worker. The §7 read-cadence (K=16, see below) bounds
the peer-side latency too.

Vacate is called from the bucket-empty path in
`account_cos_queue_flow_drain` (existing helper). No new
hooks beyond Option A's would have required.

### 3.5 LAG_THRESHOLD sizing

**v2 (Codex R1 BLOCKING — fix per-worker vs total math).**
Vtime is in bytes and is per-worker (each worker advances its
OWN `queue_vtime` based on its OWN service). Comparison is
"my vtime vs peer worker's vtime" — both per-worker quantities.
The threshold must therefore be sized in per-worker bytes,
not total queue rate.

Proposed default:

```rust
const LAG_THRESHOLD_NS: u64 = 1_000_000;  // 1 ms drift budget

fn compute_lag_threshold(
    queue_rate_bytes: u64,
    participating_workers: u32,
) -> u64 {
    let participating = participating_workers.max(1) as u64;
    let per_worker_rate = queue_rate_bytes / participating;
    let lag_bytes = (per_worker_rate as u128
        * LAG_THRESHOLD_NS as u128
        / 1_000_000_000u128) as u64;
    lag_bytes.max(MIN_LAG_BYTES)  // floor: 16 × MTU = 24 KB
}
```

Worked examples:

- **iperf-c (3.125 GB/s, 6 workers participating)**:
  per_worker_rate = 520 MB/s; 1 ms × that = 520 KB lag.
- **iperf-c (3.125 GB/s, 5 workers, 1 idle)**: per_worker_rate
  = 625 MB/s; lag = 625 KB.
- **iperf-b (1.25 GB/s, 6 workers)**: per_worker_rate =
  208 MB/s; lag = 208 KB.

**Rate floor** (Codex R1): below the `shared_exact` promotion
threshold (currently `COS_SHARED_EXACT_MIN_RATE_BYTES =
2.5 Gbps`), queues are owner-local-exact and have a single
worker, so V_min sync does not apply. The lag-threshold
formula is only evaluated for `queue.shared_exact == true`.

**Recompute cadence** for `participating_workers`: counted at
read-time as the number of slots that aren't `NOT_PARTICIPATING`.
This is N-1 atomic loads (which we do anyway for the V_min
reduction). The cost is amortized.

This constant should be queue-config tuneable in a later
iteration. For #917 v1 it is a `const` to keep the hot path
branch-free.

### 3.6 Throttle action

**v2 (Codex R1 MAJOR — bound the latency).** When `queue_vtime
> v_min + LAG_THRESHOLD`, the worker yields this queue's drain
for one timer-wheel tick (50 µs) and moves to the next runnable
queue on its priority list. This reuses the existing CoS
park/runnable-list machinery — no new pause primitive.

**Mouse-latency interaction**: a mouse packet arriving while
the queue is V_min-parked could wait up to one tick before
service. With timer-wheel tick = 50 µs, the per-throttle
latency adder is at most 50 µs. Repeated re-parks (e.g., V_min
stays behind for many ticks) accumulate; the worst-case is
bounded by `MAX_REPARKS × 50 µs`. **Hard cap on consecutive
reparks**: 8 (= 400 µs upper bound for V_min-induced mouse
latency). After 8 consecutive reparks for the same queue, drain
anyway (escape hatch — don't starve a flow forever for V_min).

**Wake condition**: queue rejoins the runnable list when
either (a) one timer-wheel tick has elapsed, or (b) any peer
worker publishes a new V_min that satisfies `queue_vtime <=
v_min + LAG_THRESHOLD` (we don't actively notify; the next
mandatory check at drain-batch-start re-evaluates).

Validated by §6.5 mouse-latency regression check and the new
§6.5a throttle-window latency probe (added in v2).

### 3.7 Non-shared_exact queues + lifecycle edges

Skip the V_min check entirely on `!queue.shared_exact`.
Owner-local-exact and best-effort queues are single-owner, so
V_min sync is meaningless. The hot-path branch is gated on
`queue.shared_exact`.

**v2 (Codex R1 MAJOR — slot clearing across lifecycle edges).**
Slots must be reset to `NOT_PARTICIPATING` at the following
transitions, otherwise stale live values falsely throttle peers:

- **Queue runtime reset** (`reset_binding_cos_runtime` at
  `tx.rs:~5460`): every slot for queues owned by this worker is
  vacated. Existing reset path already iterates over CoS queue
  state; add a single store per slot.

- **Arc replacement** (config commit installs a fresh
  `Arc<SharedCoSQueueVtimeFloor>` for a re-promoted queue): the
  new Arc's slots default to `NOT_PARTICIPATING`. The old Arc
  is dropped naturally. Any in-flight read on the old Arc
  completes against stale data but the read-path is bounded
  by the participating predicate (a stale slot value pegs at
  the last live value, which is still valid until the next
  publish on the new Arc).

- **HA primary↔secondary transition** (RG demotion / promotion
  via `cluster.rs`):

  **v3 (Gemini R2 Q8 BLOCKING — race fix).** The demotion
  handler must NOT vacate slots directly; that races with the
  worker's next publish. Instead, demotion sends a "stop
  draining shared_exact" signal (per-binding atomic flag,
  similar to existing rg_active). Worker threads check this
  flag at the start of each drain cycle and, if set, vacate
  their own slot AS THEY EXIT the drain loop. By the time
  the worker has vacated, it is no longer publishing — the
  same thread that stopped publishing is the one that
  vacated, so no race.

  Concretely: extend `WorkerCoSQueueFastPath` with a
  `drain_enabled: AtomicBool`. Demotion clears it Release.
  Worker drain entry checks Acquire — if false, vacate slot
  and exit. Race on slot mutation is eliminated because slot
  writes (publish + vacate) all happen on the same worker
  thread. Validated via `make test-failover` AND a unit test
  pinning the demotion → drain-exit → vacate ordering.

- **Worker death** (covered by #925, separate work). When a
  worker exits abnormally, its slot stays at the last live
  value forever, falsely throttling peers. Defense: a
  freshness epoch per slot, bumped on each publish, with a
  staleness window of (e.g.) 100 ms. Slots whose epoch hasn't
  bumped within the window are treated as `NOT_PARTICIPATING`.
  Adds one AtomicU64 per slot. **Defer to #925 era**: simpler
  to assume workers don't die during normal operation; the
  freshness epoch is a hardening pass.

### 3.8 What about the "fully idle worker" degenerate case?

When a worker has zero flows on a shared queue, it's not
participating per §3.4, so V_min is computed only across the
participating workers. The fast worker (w5 in the diagnostic
run) sees V_min = min(w1, w2, w3, w4) — none of which include
the idle w0. So w5's throttle is not gated by w0.

This means **the diagnostic's specific scenario (w0 idle, w5
oversubscribed) is NOT directly improved by V_min sync.** What
IS improved: the four non-idle workers (w1-w4) now stay
synchronized to each other, so per-flow service across those
workers' flows is more uniform. Whether that translates to
material per-flow CoV improvement depends on the exact RSS
distribution.

Documented honestly so cluster validation expectations are
calibrated.

## 4. What this is NOT

- Not a fix for the aggregate throughput ceiling when one or
  more workers are fully idle (RSS-degenerate case). That
  requires re-steering, which is intrinsically a different
  problem (#899 / future work).
- Not a change to per-worker MQFQ scheduling within a worker —
  that's #913 (shipped) and stays as is.
- Not a change to the shared lease (`SharedCoSQueueLease` /
  `SharedCoSRootLease`) — those handle credit/refill, V_min is
  orthogonal.
- Not a change to flow → worker assignment. Flow assignment is
  determined at the AF_XDP RX layer by RSS hash, and V_min sync
  cannot move flows.
- Not multi-thread shared MUTABLE state on the hot path — only
  per-worker writes to the worker's own slot, plus peer reads
  (load-only).

## 5. Files touched

- `userspace-dp/src/afxdp/types.rs`: new
  `SharedCoSQueueVtimeFloor` struct co-located with
  `SharedCoSQueueLease`. New field `vtime_floor:
  Option<Arc<SharedCoSQueueVtimeFloor>>` on `CoSQueueRuntime`.
- `userspace-dp/src/afxdp/tx.rs`: publish-path hook in the
  pop-side vtime-advance code (#913 site); read-path / throttle
  check in the scheduling decision code; `cos_park_queue_for_v_min`
  helper.
- `userspace-dp/src/afxdp/coordinator.rs`: lifecycle — create
  / drop the `Arc<SharedCoSQueueVtimeFloor>` alongside the
  existing `SharedCoSQueueLease`. Wire it through queue
  promotion/demotion paths.
- `userspace-dp/src/afxdp/worker.rs`: pass the per-worker slot
  index through to scheduling helpers (already have
  `worker_id`).
- `userspace-dp/src/protocol.rs` + Go-side `protocol.go`:
  optional new wire field `flow_cache_v_min_throttles` (per
  binding) so the throttle frequency is observable post-merge.
- New unit tests in `tx.rs`:
  - `v_min_throttle_skips_when_local_vtime_exceeds_threshold`
  - `v_min_throttle_releases_when_peer_advances`
  - `v_min_idle_worker_does_not_throttle_peers`
    (regression for §3.8)
  - `v_min_lag_threshold_scales_with_queue_rate`

## 6. Test strategy

### 6.1 Unit

`cargo build --release` clean. Unit tests above pass. Need
coverage for: (a) participating-set membership transitions,
(b) the participating-only V_min reduction, (c) throttle-then-
release across multiple ticks, (d) per-rate threshold scaling.

### 6.2 Cluster validation — non-degenerate RSS distribution

Run iperf-c P=12 / 30 s × 3 reps with the cluster's current RSS
config. Report per-worker tx-pkts CoV. Pass if ≥ 5 of 6 workers
are non-idle (so the §3.8 caveat doesn't apply); fail otherwise
and re-roll the source ports.

For the qualifying runs:

- per-flow CoV ≤ 20 % (the #789 gate).
- per-worker CoV ≤ 15 %.
- Aggregate throughput within 10 % of the same-workload P=128
  number.

### 6.3 Cluster validation — degenerate RSS distribution

Force the degenerate case (e.g., bind iperf3 to a specific src
port that hashes to one worker, with N small) and verify:

- No throughput regression vs current behavior.
- Throttle counter (`v_min_throttles`) stays low.
- The §3.8 documented expectation is met (CoV across the
  non-idle workers is improved; aggregate ceiling unchanged).

### 6.4 #785 retrospective regression — split gate

**v2 (Codex R1 BLOCKING).** The historical #785 Phase 1/2
gate was "SUM ≥ 22 Gbps AND CoV ≤ 20 % at iperf-c P=12".
V_min sync alone CANNOT clear this gate in the
RSS-degenerate case (one worker idle → structural ceiling
~5/6 × 25 Gbps = 20.8 Gbps). The gate must be split:

**6.4.a — Non-degenerate RSS (≥ 5 of 6 workers participating)**:
- SUM ≥ 22 Gbps
- per-flow CoV ≤ 20 %

If the cluster's current RSS hashing on iperf3-source-port-set
produces a degenerate distribution, re-roll source ports until
non-degenerate (or if that's not feasible, validate this
acceptance criterion in a synthetic test with explicit per-worker
flow assignment).

**6.4.b — Degenerate RSS (≥ 1 worker idle)**:
- SUM ≥ (`participating_workers / total_workers`) × 25 Gbps
  − 5 % overhead allowance
- per-flow CoV ≤ 20 % across the participating workers' flows
  (excluding the implicit "infinite-rate" of zero flows on the
  idle worker)
- No throughput regression vs the pre-#917 baseline

**Why this split is correct**: V_min sync is a fairness
primitive, not a re-steering primitive. It can flatten
within-cluster CoV but cannot move flows off an idle RSS
worker. The aggregate ceiling lift requires a separate fix
(re-steering or NIC RSS table tuning) tracked outside #917.

### 6.5 Mouse-latency tail regression

Re-run the same-class iperf-b N=128 mouse probe (#929 harness).
The post-#913+#918+#914+#920 baseline is p99 = 60.64 ms. The
#917 throttle could either help (more uniform draining
flattens HOL) or hurt (parking introduces additional latency).
Pass if mouse p99 stays within ±15 % of the baseline.

### 6.5a Throttle-window latency probe

**v2 (Codex R1 MAJOR — §6.5 ±15 % is too coarse to catch
sub-ms regressions).** Targeted micro-probe to confirm the
throttle action does not introduce > 1 ms tail spikes:

- Run a single elephant on shared_exact iperf-b at line rate
  with no other traffic. The single elephant has N_active = 1,
  so V_min sync is trivial; throttle should never fire. If
  the throttle counter is non-zero or the elephant's TCP RTT
  jitters > 100 µs vs the pre-#917 baseline, fail.
- Run two elephants with explicitly mismatched TCP cwnds
  (one cwnd-large, one cwnd-small via `iperf3 -w`). V_min
  sync should fire occasionally; measure the per-throttle
  pause via timestamping in the worker's `cos_park_queue` log
  (trace-level). Fail if any single park exceeds 100 µs or
  consecutive parks for the same queue exceed 8 (the §3.6
  cap).
- Direct mouse-latency probe (#929 harness, M=10 N=8 cell)
  with V_min throttle telemetry sampled at 100 Hz: assert
  that mouse p95 ≤ baseline p95 + 1 ms.

### 6.6 Throttle frequency telemetry

The new `v_min_throttles` counter is the load-bearing
diagnostic. During the validation runs, the counter should be
non-zero on workers whose local vtime advances faster than peers
(otherwise the mechanism is inactive), but the throttle rate
shouldn't dominate (otherwise the LAG_THRESHOLD is too tight).

Target: 100 – 10000 throttles/sec/worker on iperf-c P=12.

## 7. Risks

- **False throttling under bursty arrivals.** If a worker
  briefly stops receiving packets due to NIC RX gap, its slot
  pegs at the last live vtime — peers see no advance and might
  read stale data. Mitigation: epoch-bump on enqueue/dequeue
  edges + a freshness window (slot considered stale after K
  ticks).
- **Cache-line contention on the slot array.** Each worker
  reads N-1 slots per scheduling decision. If those slots are
  hot (other workers' writes), the reads hit dirty lines. Per-
  worker cache-line padding (`#[repr(align(64))]`) keeps
  writers from contending with each other; readers still pull
  fresh lines on each load. At iperf-c (high pps) this could
  saturate L2-L1 bandwidth. **Mitigation**: throttle the read
  path itself — only check V_min every K pops (e.g., K = 16
  or once per drain batch), not every pop. Exact K decided at
  impl time.
- **Throttle action latency.** Parking a queue introduces
  scheduling latency that competes with mouse-latency goals
  (post-#913 baseline p99 = 60 ms). The §6.5 regression check
  guards against this.
- **Interaction with shared lease.** The shared lease already
  rate-limits across workers. V_min sync layers on TOP of the
  lease: lease decides "can I drain credits?", V_min decides
  "have I outraced peers?". Both can park a queue. Verify they
  don't pessimize each other (worst-case both are checking
  every pop).
- **Correctness under HA failover.** When a node takes over
  RG primary, its shared queue state may be stale. Plan: reset
  all slots to `u64::MAX` (sentinel-not-participating) on
  RG-primary transition. Validated via `make test-failover`.
- **Deferred items from prior MQFQ work** (#927 drained-bucket
  vtime loss, #926 demote inflation): these touch the same
  vtime arithmetic and corrupt the signal V_min publishes.
  **v2 (Codex R1 MAJOR — block #917 merge on these).** Both
  must land before #917 cluster validation. Parallel coding
  of #917 is fine (the patches don't share files), but the
  acceptance run for §6.4 / §6.5 must be after #927+#926
  merge so V_min reads are computed from corrected vtimes.
  Each is small (per session memory: <1-day fixes); they
  should be the immediate next sprint.

## 8. Open questions (v1 → v2 disposition)

All v1 open questions resolved in v2 per Codex R1 review:

1. ~~§3.4 Option A vs B~~ → **Decided: B with explicit
   Release/Acquire ordering** (§3.4 v2). Race-window analysis
   inline.
2. ~~§3.5 LAG_THRESHOLD~~ → **Decided: per-worker rate ×
   1 ms** with formula at §3.5 v2; queue-config tunability
   deferred to a later iteration.
3. ~~§7 read-cadence K~~ → **Decided: K = 16 + mandatory
   batch-start check**, derived from `K × MTU ≤ LAG_THRESHOLD
   / 4` bound (§3.3 v2).
4. ~~§7 stale-slot mitigation~~ → **Decided: vacate on
   bucket-empty edge** (§3.7); freshness epoch deferred to
   #925-era hardening.
5. ~~§3.8 honest scope~~ → **Decided: split the acceptance
   gate** (§6.4 v2). Non-degenerate RSS clears the historical
   #785 22-Gbps gate; degenerate RSS is held to a "no-
   regression" bar with a documented ceiling.

New open questions surfaced in v2 (none blocking — all addressed
inline or deferred with explicit reasoning):

a. The stale-cache MOESI ping-pong concern at §3.3 — needs
   cluster-side measurement to confirm the K = 16 cadence is
   sufficient. Plan §6.6 measures throttle frequency; an
   additional perf counter (`v_min_read_cache_misses` via perf
   stat) is the diagnostic.
b. §3.7 worker-death freshness epoch — deferred to coincide
   with #925 worker supervisor work.

## 9. Acceptance

- [ ] Plan reviewed by Codex (hostile); PLAN-READY YES.
- [ ] Plan reviewed by Gemini (HPC + scheduler / fair-queueing
      expertise); MERGE YES.
- [ ] Implemented; `cargo build --release` clean.
- [ ] Unit tests pass.
- [ ] Codex hostile code review: MERGE YES.
- [ ] Gemini adversarial code review: MERGE YES.
- [ ] Cluster validation: §6.2–§6.6 all pass.
- [ ] PR opened, Copilot review addressed.
- [ ] Merged.

## 10. Plan iteration log

- v1 — initial draft. Built from the diagnostic doc; identified
  the within-cluster CoV target but left §8 open questions
  for review.

- v3 — Gemini R2 NEEDS-MAJOR. Two majors + one minor fixed:
  - §3.3 K cadence MAJOR — was K=16; jumbo MTU 9000 violates
    the `K × MTU ≤ LAG_THRESHOLD/4` bound at iperf-c (max K=14
    at jumbo). Lowered to K=8 with derivation showing safety
    across non-iperf-b queues at jumbo MTU; iperf-b at jumbo
    documented as safe-in-practice given 1500 B MTU on
    cluster.
  - §3.7 HA transition race MAJOR — v2 had demotion handler
    vacating slots, racing with worker's in-flight publish.
    v3 moves vacate to worker's own drain-exit path; demotion
    sends stop-draining signal via existing per-binding atomic
    flag. Same thread that publishes is the one that vacates
    → no race.
  - §3.2 speculative-pop visibility minor — clarified that
    peers read the SLOT (only updated at commit), not
    queue_vtime directly; speculative window is invisible
    by construction.

- v2 — Codex R1 NEEDS-MAJOR. Four blockers + five major fixes
  applied:
  - §3.2 publish path BLOCKING — was "every pop"; now committed
    at TX-commit boundary, not speculative pop. Rollback path
    also publishes (restores the rolled-back vtime).
  - §3.4 participation predicate BLOCKING — chose Option B
    (sentinel u64::MAX) with explicit Release/Acquire memory
    ordering; race-window analysis enumerated.
  - §3.5 LAG_THRESHOLD BLOCKING — was total-rate-based; now
    per-worker-rate × 1 ms, with `participating_workers`
    counted at read time. iperf-a (sub-2.5-Gbps) explicitly
    out of scope.
  - §6.4 acceptance gate BLOCKING — split into non-degenerate
    (clears #785 22-Gbps gate) vs degenerate (no-regression
    against pre-#917 baseline; documented ceiling).
  - §3.6 throttle action MAJOR — bounded with hard cap of 8
    consecutive reparks; wake conditions explicit.
  - §3.3 read cadence K MAJOR — committed to K=16 with
    `K × MTU ≤ LAG_THRESHOLD / 4` derivation.
  - §3.7 lifecycle edges MAJOR — slot clearing at runtime
    reset, Arc replacement, HA transition explicit; worker
    death freshness epoch deferred to #925 era.
  - §6.5a throttle-window latency probe MAJOR — added to
    catch sub-ms regressions §6.5's ±15 % is too coarse for.
  - #927/#926 ordering MAJOR — both block #917 cluster
    validation; parallel coding fine but acceptance gate
    runs after they merge.
