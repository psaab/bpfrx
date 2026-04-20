# Plan: Restore 21–23 Gbps aggregate throughput while hitting per-flow CoV ≤ 20 %

Tracking: [#786](https://github.com/psaab/xpf/issues/786) (parent research);
this document is the canonical source for the phased plan.

Related: [`cross-worker-flow-fairness-research.md`](./cross-worker-flow-fairness-research.md),
[`785-cross-worker-drr-retrospective.md`](./785-cross-worker-drr-retrospective.md).

---

## Goals

- **Throughput:** 21–23 Gbps aggregate on `iperf3 -P 12 -t 20 -p 5203` through
  a 25 Gbps `shared_exact` CoS queue (the baseline range master hits today
  without any rate-gate machinery).
- **Fairness:** per-flow coefficient of variation ≤ 20 % across the 12 flows
  in the same test (the target from
  [`cross-worker-flow-fairness-research.md`](./cross-worker-flow-fairness-research.md)).
- **Correctness:** no regressions, adversarial Codex review on every merge,
  Copilot review on every merge, comprehensive anti-regression tests for
  every invariant cemented.

## Constraints

### What we've proven doesn't work

1. **Per-worker rate gates** (slice-2 WIP branch `pr/785-cross-worker-drr`)
   cap at CoV ~30 % regardless of burst-window tuning. Proven by the
   retrospective: SFQ DRR is packet-count fair, not byte-rate fair, under
   TCP pacing. Workers with cwnd-disparate flows do not equalise via
   round-robin because the smaller-cwnd flow sits idle waiting for ACKs
   during DRR polls. See
   [`785-cross-worker-drr-retrospective.md`](./785-cross-worker-drr-retrospective.md)
   §4 for the mechanism.
2. **Any form of time-based peak decay** on the rate-gate denominator
   injects per-worker ratio bounce that desyncs workers, inflating CoV from
   19 % (non-decay best case) to 40–50 % (every decay variant tried). See
   retrospective §3.4.
3. **NIC-side fix via more RX queues:** hardware-capped at 6 combined
   channels on the current Mellanox ConnectX-class VF passthrough. Cannot
   escape RSS pigeonholing with 12+ flows by asking for more queues.

### What's available to build on

- **PR #787** (merged) — `CompileConfig` rejects duplicate FC↔queue
  mappings. This removes the three-way rate-source inconsistency that
  confounded slice-2 measurements; any baseline taken before PR #787
  has unknown rate provenance and must be discarded.
- **PR #785** (merged) — `shared_exact` shadow on `CoSQueueRuntime`,
  `apply_cos_queue_flow_fair_promotion` helper, 4 integration tests.
  Pure refactor; no runtime behavior change. Ready for later phases to
  branch on the shadow.
- **Slice-2 branch** `pr/785-cross-worker-drr` (unmerged, WIP) —
  `shared_lease` Arc cache on `CoSQueueRuntime`, `active_flow_count`
  atomic with idle-only reset, rate-gate plumbed through drain paths,
  7 anti-regression tests. Reusable under MQFQ; retire or stay as
  safety net depending on which phase hits the target.
- Two prior documents:
  [`cross-worker-flow-fairness-research.md`](./cross-worker-flow-fairness-research.md)
  (11-algorithm survey, MQFQ ranked top) and
  [`785-cross-worker-drr-retrospective.md`](./785-cross-worker-drr-retrospective.md)
  (five-approach rollback record + cemented invariants).

---

## Plan: five phases with measured exit criteria

Every phase exits as soon as its exit criteria are met — we stop early if
targets are already hit, and only pay the complexity cost of later phases
if earlier ones fall short.

### Phase 1 — Re-baseline after PR #787 (1 day)

**Hypothesis:** the bug PR #787 fixed was a material contributor to
observed CoV. With three inconsistent rate views reconciled into one,
baseline master may already be closer to target than previously measured.

**Work:**

1. Redeploy current master to the loss userspace cluster
   (`BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
   test/incus/cluster-setup.sh deploy all`).
2. Apply a clean CoS config with exactly one forwarding-class per queue
   (no `iperf-b`+`iperf-c` on queue 5). Confirm `CompileConfig` accepts.
3. Run three back-to-back `iperf3 -c 172.16.80.200 -P 12 -t 20 -p 5203`
   at the 25 Gbps `shared_exact` queue. Record per-flow rate table,
   aggregate SUM, retrans count.
4. Supplemental: `-P 1` and `-P 4` to map out the flow-count-vs-throughput
   curve.
5. Cross-check with `show class-of-service interface` post-run —
   `admission_ecn_marked`, `flow_share`, `buffer` drop counters. Zero
   retrans must correlate with zero admission drops.

**Exit criteria:** documented baseline table posted as a comment on
issue #786 and appended to the retrospective. **If baseline ≥ 21 Gbps
SUM AND CoV ≤ 20 % on all three runs, STOP — the bug was the problem.**

**Risk:** none. Measurement only.

**Deliverables:** measurement table + retrospective update.

---

### Phase 2 — Symmetric Toeplitz RSS audit (1 day)

**Hypothesis:** default Mellanox ConnectX RSS key is asymmetric —
forward and reverse traffic for the same 5-tuple hash to different RX
queues. If any test workload exercises reverse-path traffic, or if the
key itself happens to pigeonhole the specific port sequence iperf3 uses,
CoV inflates independently of anything the scheduler does. Research doc
§2.2 recommends this as the #1 baseline step.

**Work:**

1. Audit current key: `ethtool -x mlx0` (indirection table),
   `ethtool -n mlx0 rx-flow-hash tcp4` (hash field set — expect `sdfn`),
   `ethtool -X mlx0 hkey` (Toeplitz key).
2. If key is asymmetric, deploy symmetric: McAfee `6D:5A:6D:5A:6D:5A:…`
   pattern (40 bytes for ConnectX) via
   `ethtool -X mlx0 hkey 6d:5a:6d:5a:…`.
3. Confirm indirection table is flat (weights all equal). Reweight if
   skewed.
4. Re-run Phase 1 tests and record delta.

**Exit criteria:** symmetric key confirmed in place via ethtool. Phase 1
test table re-run. **If targets hit, document and stop.**

**Risk:** low. Pure config change, reversible. Zero code.

**Deliverables:** RSS audit in operator runbook (new
`docs/rss-tuning.md`); measurement update on issue #786.

---

### Phase 3 — Minimal MQFQ: per-worker virtual-finish-time ordering (5–7 days)

**Hypothesis:** before paying the full-MQFQ complexity cost, the
cheapest algorithmic fix is to replace within-worker SFQ DRR with
finish-time ordering using existing bucket state. This closes the
packet-count-vs-byte-rate gap inside a single worker, which the
retrospective identifies as the residual CoV driver once cross-worker
rate gating is in place.

**Design:**

1. Add `virtual_finish_ns: u64` per SFQ bucket
   (in `CoSQueueRuntime.flow_bucket_items[i]`, or a parallel
   `[u64; COS_FLOW_FAIR_BUCKETS]` array — decide based on cache layout
   profiling).
2. On enqueue (shared_exact, flow-fair path):
   ```rust
   let finish_delta = (bytes as u128 * 8_000_000_000) /
                      (fair_share_rate as u128).max(1);
   bucket.virtual_finish_ns = max(bucket.virtual_finish_ns, now_ns)
                            + finish_delta as u64;
   ```
3. Drain-side pops the bucket with smallest `virtual_finish_ns`, not
   round-robin. Candidate structures: small min-heap (16–32 entries
   since active buckets rarely exceed 64), or re-sort the DRR ring on
   each pop (O(active) per pop, ~2 μs at 12 flows).
4. Shared `SharedCoSQueueLease` rate cap unchanged — still enforces
   aggregate.
5. **Keep slice-2's rate gate OFF** (remain on current master state).
   The MQFQ ordering is the fairness primitive; the rate gate was a
   weaker stand-in.

**Correctness concerns to pre-empt:**

- **Overflow:** at 100 Gbps sustained, `virtual_finish_ns` grows
  ~12.5 units per byte; over a multi-day daemon uptime the u64 will
  eventually wrap. Either periodic normalisation (subtract
  `min_finish_time` from all buckets when `min > 2^60`) or u128
  arithmetic throughout. Pick one before implementation.
- **Monotonicity under concurrent enqueue + dequeue:** buckets are
  per-worker non-atomic, so only one writer per queue per worker at a
  time. Safe without locking, but must hold within a single drain
  batch (don't read a bucket's finish time twice and observe
  different values).
- **Empty-bucket behaviour:** when a bucket drains to 0, set
  `virtual_finish_ns = 0` so the next enqueue re-anchors to `now_ns`,
  not the stale finish time (which would let the bucket jump the queue
  on re-arrival).

**Anti-regression tests (must all pass before merge):**

- `enqueue_bumps_finish_time_by_byte_ratio` — finish-time delta is
  exactly `bytes × 8e9 / fair_share_rate`.
- `drain_pops_smallest_finish_time_bucket` — mixed-finish-time buckets
  drain in strict finish-time order.
- `idempotent_enqueue_dequeue_preserves_finish_monotonicity` —
  bucket finish time is non-decreasing across any round-trip.
- `bucket_empty_resets_finish_time` — drained bucket's finish resets
  to 0, next enqueue re-anchors.
- `finish_time_no_overflow_at_100gbps_24h` — synthetic 24-hour
  accumulation at 100 Gbps does not wrap u64 (either by design or via
  normalisation).

**Exit criteria:** three consecutive `iperf3 -P 12 -t 20 -p 5203` runs,
SUM ≥ 21 Gbps each, per-flow CoV ≤ 20 % each. Drop counters zero.
Codex HIGH/MEDIUM findings addressed before merge.

**Risk:** medium.

- Finish-time arithmetic is tricky (overflow, monotonicity edge cases).
- Min-heap maintenance on the hot path is measurable — profile
  before/after, expect ≤ 1 % CPU at 25 Gbps.
- Wrong tuning of `fair_share_rate` (still has to be computed from
  something — either `lease.rate_bytes() / active_flow_count_peak`
  from slice 2, or a simpler per-flow target rate).

**Adversarial review focus:**

- Finish-time overflow analysis across the daemon's lifetime.
- Heap consistency under drain batching (one batch must see a coherent
  heap state even if enqueues arrive concurrently on the worker).
- The interaction with `maybe_mark_ecn_ce` and
  `flow_share_exceeded` — finish-time ordering must not bypass those
  gates.

**Deliverables:** PR with full measurement table; retrospective update;
new tests.

---

### Phase 4 — Full MQFQ with shared `V_min` + lag throttle (2–3 weeks)

**Hypothesis:** if Phase 3's per-worker MQFQ doesn't close the gap, the
remaining imbalance is genuinely cross-worker — workers with more flows
drain faster than the shared-lease's FCFS token allocation allows them
to be fair. Full MQFQ per Hedayati & Shen ATC '19 solves this via a
shared virtual-time anchor.

**Design:**

1. `SharedCoSQueueLease` gains `v_min: AtomicU64`. On every dequeue,
   a worker CAS-updates `v_min` to the drained packet's finish time
   (monotonic max via compare-exchange loop).
2. Each worker maintains `v_local: u64` tracking its
   most-recently-drained finish time.
3. **Lag throttle:** when `v_local - V_min > T`, the worker pauses
   its drain until V_min catches up. `T` is the fairness bound — the
   paper measures optimal `T ≈ queue_rate × 10 ms` (i.e. ~30 MB at
   25 Gbps). Tune empirically.
4. Builds on slice-2 infrastructure:
   `active_flow_count` atomic with idle-only reset is the signal that
   tells workers when to re-anchor; `shared_lease` Arc cache is the
   direct path to `v_min`.
5. Retire or keep per-worker rate gate: MQFQ's throttle is strictly
   tighter. Decide post-measurement.

**Correctness concerns:**

- V_min monotonicity under concurrent drain: every worker CAS-es to
  `max(current, my_finish)`; paper proves this converges.
- Lag-threshold `T` vs per-packet cost: too-tight → workers throttle
  mid-drain-batch, losing TX-ring fullness; too-loose → fairness
  bound widens. Profile `T ∈ [5, 50] ms` equivalents.
- CAS contention on `v_min` — one CAS per drain (not per packet), so
  contention is bounded by worker count × drain-rate, not line rate.
  Paper measures 20× scalability over BFQ specifically for this
  reason. Profile to confirm on our workload.

**Anti-regression tests:**

- `v_min_monotonic_under_concurrent_drain` (stress test with
  synthetic workers).
- `throttle_fires_when_lag_exceeds_threshold`.
- `drained_packet_updates_v_min_to_finish_time`.
- `idle_queue_resets_v_min_to_zero` (matches the idle-only reset
  contract from slice 2).
- **Analytical pin:** O(T) bound — construct a state where one
  worker is maximally ahead, verify drained bytes across all workers
  within any T-sized window differ by ≤ T.
- **Empirical pin:** inject a stalled worker (simulate via a
  `SendMessage` hold); verify V_min pauses; verify other workers
  don't accelerate beyond `V_min + T`.

**Exit criteria:** five consecutive iperf3 -P 12 runs at 25 Gbps:
SUM ≥ 22 Gbps sustained, CoV ≤ 15 % (tighter than 20 % — MQFQ's
provable bound gives headroom). Drop counters zero. No retrans.

**Risk:** high.

- Concurrency-heavy: one CAS loop on the hot path per drain, multiple
  workers contending. Hedayati & Shen bounds it, but our shape
  (different workload, different hardware) may be different.
- The `T` tuning is per-deployment — a wrong choice hurts either
  throughput or fairness. Need a principled default and a way to
  expose `T` as operator config.
- Lots of new code. Adversarial review must be comprehensive.

**Adversarial review focus:**

- V_min CAS correctness under concurrent workers — walk through
  races on stalled workers, late-arriving drain completions, and
  queue transitions to/from idle.
- Throttle fairness vs throughput trade-off at multiple `T` values.
- Fallback when CAS contention spikes — does the algorithm degrade
  gracefully or cliff?
- Interaction with the #784 owner-local-exact path (MUST remain
  untouched).

**Deliverables:** PR with MQFQ primitives + full measurement sweep
across `T ∈ [1, 100] ms` equivalents; retrospective update;
operator-facing doc on tuning `T`.

---

### Phase 5 — AFD policer for misbehaving flows (optional, 1–2 weeks)

**Hypothesis:** MQFQ schedules well-behaved flows fairly but can't
protect against pathological flows (TCP CUBIC burst during loss
recovery, UDP floods, misconfigured clients). Research doc §3.3
recommends AFD (Approximate Fair Dropping) as the complementary
primitive.

**Design:**

1. Per-`shared_exact` queue Count-Min sketch: depth 4, width 4096
   buckets (~32 KB memory, fits in L2 on modern CPUs).
2. On enqueue: sketch-increment for packet's flow key. If sketch
   count > (fair-share threshold × some multiplier), ECN-CE-mark
   the packet; drop if non-ECT.
3. Slow-timer decay: halve all sketch counts on a 500 ms tick.
   Bounds memory usage and lets recovered flows re-accumulate fair
   share.

**Anti-regression tests:**

- `count_min_sketch_bounds_estimate_below_ratio` — false-positive
  rate bounded by the sketch's proven error rate.
- `decay_halves_sketch_bounded_memory`.
- `pathological_flow_does_not_starve_well_behaved` (integration).

**Exit criteria:** pathological-flow test (one UDP flow at 2× fair
share) doesn't starve TCP flows; TCP flows still CoV ≤ 15 %.

**Risk:** medium.

- Sketch collisions mis-attribute bytes; hurts well-behaved flows
  in the collision group. Count-Min bounds this probabilistically
  but we need to pick a depth × width that's safe for our worst-case
  flow count.
- Runtime cost: 4 hash lookups + 4 compare-exchange per enqueue on
  shared_exact. Profile.

**Deliverables:** PR; AFD tuning guide in operator runbook.

---

## Correctness discipline (applies to every phase)

1. **Adversarial Codex review BEFORE merge.** Posture: "Uber-scale
   network perf engineer + HOSTILE reviewer", explicit HIGH/MEDIUM/LOW
   triage, file:line citations. Every finding either addressed or
   explicitly deferred with rationale.
2. **Copilot review on the PR.** Docblock accuracy, test fragility,
   missing edge cases. Address all findings.
3. **Anti-regression tests for every invariant cemented.** Structural
   pins, not tautological assertions. Pattern established in slice-1
   and slice-2: drive the production path end-to-end (not isolated
   helpers); tie WHY comments back to measured regressions;
   fail loudly if the invariant is silently relaxed.
4. **Empirical validation via the userspace cluster.** `make
   cluster-deploy` → `iperf3` → record per-flow rates + aggregate +
   retrans + drop counters. At least three runs per measurement.
5. **No merge until exit criteria hit.** Measurements table in PR
   description; abortable at any phase without touching earlier
   phases.

## Risk management

| Failure at phase | Fallback |
|---|---|
| Phase 1 — baseline worse than expected | Still proceed to Phase 2 (symmetric RSS audit); might close the gap |
| Phase 2 — RSS already symmetric / no delta | Phase 3 (minimal MQFQ) |
| Phase 3 — CoV target missed | Phase 4 (full MQFQ with V_min) |
| Phase 4 — CoV hit but pathological flows regress | Phase 5 (AFD) |
| Phase 4 — CoV missed | Re-evaluate: research doc §5 lists alternatives (RSS++, shared-SFQ-ring) |

## Deliverables summary

- Per-phase PR with full before/after measurement table.
- Per-phase retrospective update (append, don't rewrite).
- Per-phase anti-regression tests.
- Final state: master hits 21–23 Gbps + CoV ≤ 20 %, four to five
  merged PRs, updated research + retrospective + operator docs.

## Recommendation

**Start with Phase 1.** The baseline may already be closer to target
than we think — PR #787 removed a material rate-source confound, and
all our prior measurements are against the buggy config. Measurement
is cheap; rebuilding architecture is not. Don't pay complexity costs
until we know the actual gap.
