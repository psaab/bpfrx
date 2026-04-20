# Issue #785 Retrospective: Cross-Worker Fair-Queueing on Shared-Exact CoS Queues

This document is the complete engineering record of everything attempted for
issue #785. It covers the root-cause investigation, five distinct code
approaches, the empirical measurements that ruled each one in or out, and
what the experience implies for the next slice of work (MQFQ, tracked in
#786).

Audience: the future engineer who picks this up. Read this before touching
`promote_cos_queue_flow_fair`, `cos_queue_flow_share_limit`, or
`maybe_top_up_local_fair_share`.

---

## 1. The problem statement

xpf's userspace dataplane has a CoS shaper with two service paths for
`exact` queues:

- **Owner-local-exact**: one worker owns the queue, drains from its own
  local pending-TX ring. SFQ DRR (from #784) enforces per-flow fairness
  within that worker. Works well at low rates (≤ 2.5 Gbps per queue).
- **Shared-exact**: multiple workers cooperatively drain the queue; a
  shared token-bucket lease (`SharedCoSQueueLease`) gates the aggregate
  rate. Used for high-rate queues (≥ `COS_SHARED_EXACT_MIN_RATE_BYTES` =
  2.5 Gbps).

User-visible symptom on a 25 Gbps `shared_exact` queue with
`iperf3 -P 12 -t 20 -p 5203`:

- SUM aggregate throughput 22.3 Gbps (correct, at cap).
- Zero retransmits (no drops).
- Per-flow rates tiered: **1 × 4.5 Gbps, 2 × 2.8 Gbps, 2 × 1.8 Gbps,
  7 × 1.2 Gbps**. Coefficient of variation ~33 %.

Target: every parallel flow gets roughly its fair share
(25 Gbps / 12 ≈ 2.08 Gbps), with CoV ≤ 20 %.

---

## 2. Why the baseline distribution is tiered

Established before touching any code, from the test environment topology:

- NIC is Mellanox ConnectX-class, 6 RX queues (`ethtool -l` max == current ==
  6), pinned by RSS.
- 12 TCP flows from iperf3 distribute across 6 RX queues via Toeplitz hash.
  Perfectly-even distribution (2 per queue) is rare at this scale;
  pigeonhole + hash collisions produce distributions like
  `(3, 3, 2, 2, 1, 1)` or more-skewed.
- Each worker owns one RX queue. A worker with 3 flows has 3× the per-flow
  demand of a worker with 1 flow.
- The shared rate lease is a token bucket shared across workers with
  **no per-worker weighting**. Workers compete first-come-first-served
  for tokens.
- In equilibrium, the lease ends up roughly proportional to per-worker
  *demand* (TCP cwnd × RTT), not flow count. Bigger-cwnd flows on less
  crowded workers amass more tokens; smaller-cwnd flows on crowded
  workers back off.
- Positive-feedback loop: a flow that gets slightly more tokens grows its
  cwnd, which lets it grab even more tokens on the next round. Flows that
  get less end up in an under-rated steady state.

**The tiered distribution is cross-worker RSS imbalance plus token-lease
FCFS**, not a scheduler bug per se. This was not obvious at first; the
first two approaches tried to fix it at the wrong layer (within-worker
SFQ).

---

## 3. What was tried, in order, with measurements

All measurements on `loss:xpf-userspace-fw0/1` + `loss:cluster-userspace-host`,
`iperf3 -P 12 -t 20 -p 5203`, 25 Gbps `shared_exact` queue (iperf-c class).
Baseline = master branch without any slice-2 changes.

### 3.1 Approach A — Naïve SFQ flip (rolled back)

Change: set `queue.flow_fair = queue.exact` unconditionally
(`promote_cos_queue_flow_fair`), no other changes.

Hypothesis: if DRR round-robins flows within each worker, the within-
worker unfairness disappears, and cross-worker imbalance is the only
remaining source.

**Measured regression: 22.3 Gbps → 16.3 Gbps, 25k+ retrans.**

Root cause: `cos_queue_flow_share_limit` and the per-flow ECN arm in
`apply_cos_admission_ecn_policy` are rate-unaware. They clamp per-flow
byte counts at `COS_FLOW_FAIR_MIN_SHARE_BYTES` (24 KB). On a 25 Gbps
queue with 12 flows, the per-flow cap is ~24 KB, far below the ~5 MB BDP
a 2 Gbps TCP flow at 20 ms RTT needs. Admission drops + ECN CE marks
fire on nearly every packet; cwnd never opens.

Lesson: **SFQ admission gates that were sized for 1 Gbps workloads do
not scale to 25 Gbps just by flipping the gate**. If we want SFQ on
shared_exact, admission has to downgrade to aggregate-only — the rate
gate enforces per-flow fairness via a different mechanism.

### 3.2 Approach B — SFQ + aggregate-only admission (rolled back)

Change: A, plus `cos_queue_flow_share_limit` returns `buffer_limit` on
`shared_exact` queues (no per-flow clamp), and `apply_cos_admission_ecn_policy`
uses the aggregate arm on `shared_exact`.

Hypothesis: DRR handles per-flow ordering within a worker; aggregate-
only admission lets TCP cwnd open freely; cross-worker lease stays
unchanged.

**Measured: throughput preserved at 22-23 Gbps, but per-flow CoV *went up*
from ~33 % (baseline) to 40-51 % over three runs.**

Root cause: per-worker SFQ cannot equalise flows that NIC RSS has
distributed unevenly across workers. Workers still compete FCFS for the
shared lease with bigger-cwnd flows winning.

Lesson: **within-worker fairness mechanisms are orthogonal to cross-
worker fairness**. SFQ DRR inside a single worker doesn't help when
the worker next door has a bigger cwnd pool.

### 3.3 Approach C — Per-worker rate gate with instantaneous counts (rolled back)

Change: B, plus new machinery:

- `SharedCoSQueueLease::active_flow_count: AtomicU32` tracking the global
  concurrent flow count across all workers. Incremented by
  `add_active_flow` on SFQ bucket 0→>0 transitions, decremented by
  `remove_active_flow` on >0→0.
- `CoSQueueRuntime::shared_lease: Option<Arc<SharedCoSQueueLease>>`
  cached on the runtime so accounting hooks have O(1) access.
- `CoSQueueRuntime::local_drain_tokens` + `local_drain_rate_bytes` —
  per-worker token bucket. Rate =
  `queue_rate × local_active_flow_buckets / active_flow_count` (the
  fair share for this worker given its share of concurrent flows).
- `drain_exact_*_items_to_scratch_flow_fair` breaks on exhausted
  `local_drain_tokens`, forcing the worker to idle between refills.

Hypothesis: if each worker is capped at its proportional fair share of
the aggregate rate, no worker can out-compete others for lease tokens,
and per-flow rates converge to `queue_rate / total_flows`.

**Measured: at 1 ms burst size, CoV dropped to 4.5 % (excellent), but SUM
collapsed from 22.3 Gbps to 7.8 Gbps. At 10 ms burst, throughput
recovered to 21.9 Gbps but CoV inflated to 63 %.**

Root cause of throughput collapse: two independent bugs:

1. **Wrong rate source.** The fair-share math computed off
   `queue.transmit_rate_bytes`. When multiple forwarding classes with
   different scheduler rates map to the same queue ID (the test config
   had iperf-b at 10 Gbps and iperf-c at 25 Gbps both → queue 5),
   `transmit_rate_bytes` took on one scheduler's rate — the lower one
   — while the shaper actually enforced the full 25 Gbps via the
   shared lease. Workers were capped at 40 % of their true fair share.
2. **Denominator oscillation.** SFQ bucket bytes transition to 0 between
   TCP packet arrivals, which fires `account_cos_queue_flow_dequeue` →
   `remove_active_flow`. The next packet triggers the reverse. Live
   diagnostic traces: `active_flow_count` oscillating 1-5 when the true
   count was 12. Instantaneous reads made workers over-rate during dips
   (brief "I'm the only flow!" windows) and under-rate during spikes.

Root cause of the CoV vs throughput trade-off on burst size: burst too
tight → TX ring idles between refills → throughput collapses. Burst
too loose → workers accumulate enough tokens to burst at full queue
rate during the refill window, so fairness only averages over the
window and within-window rates are uneven.

Lesson: **per-worker rate gates need (a) the right rate source —
`lease.rate_bytes()`, not `queue.transmit_rate_bytes` — and (b) a
stable division denominator**. SFQ bucket oscillation means
instantaneous counts are useless for the division.

### 3.4 Approach D — Peak-based denominator with continuous decay (rolled back)

Change: C, plus:

- `CoSQueueRuntime::local_fair_share_peak: u16` — bumped on bucket
  0→>0 in lockstep with `active_flow_buckets_peak` (kept separate
  because the #784 diagnostic peak has a "never reset during daemon
  lifetime" operator contract).
- `SharedCoSQueueLease::active_flow_count_peak: AtomicU32` — bumped via
  CAS loop inside `add_active_flow`.
- Rate gate reads PEAK values for both local and total.
- Continuous decay: every `COS_FAIR_SHARE_PEAK_WINDOW_NS`, each worker
  tries to pull its `local_fair_share_peak` down by 1 and calls
  `lease.snap_peak_to_current()` to similarly decay the shared peak.
- Codex MEDIUM fix also landed here: `cos_flow_aware_buffer_limit`
  switched to `lease.rate_bytes()` on `shared_exact` so the admission
  delay cap agrees with the drain-side rate.

Hypothesis: peaks absorb SFQ oscillation (sticky within a window);
slow decay addresses Codex's HIGH finding that never-decaying peaks
pin at lifetime max on flow-churn workloads.

**Measured (500 ms / 2 s / 5 s windows all tested): SUM 14-22 Gbps,
CoV 27-50 % (run-to-run variance, much worse than the non-decay
version's stable 19 %).**

Root cause: per-worker decay boundaries are **not synchronized**. At
any moment, some workers' peaks have just decayed while others are
still mid-window. The (local_peak / shared_peak) ratios diverge
across workers, and the worker with the freshest (largest) peak
computes its fair share against a stale (smaller) total. It briefly
over-rates, TCP cwnd captures the burst, the win persists for the
rest of the test.

Every continuous decay mechanism had this problem. Changing the
window size only slid where the bouncing showed up in time, not
whether it showed up.

Lesson: **any decay based on sampled live counts re-introduces the
SFQ bucket-oscillation noise the peaks exist to absorb**. Time-based
decay is the wrong primitive for this architecture.

### 3.5 Approach E — Idle-only peak reset (shipped as WIP on branch)

Change: D, with decay replaced by:

```rust
// In maybe_top_up_local_fair_share:
if queue.active_flow_buckets == 0 {
    queue.local_fair_share_peak = 0;
}
lease.snap_peak_to_current();  // only resets if lease.active_flow_count == 0
```

Hypothesis: peaks only drop when the queue is GENUINELY idle (no flows
anywhere on any worker). During any non-idle workload, peaks are
rock-stable and the rate gate has a stable denominator. Between work
bursts, peaks reset so the next burst rebuilds them from scratch —
addressing Codex HIGH's "lifetime-pinned max" case.

**Measured: SUM 15-20 Gbps, per-flow CoV 49-61 %.** Peak stability does
not help because the remaining unfairness is not denominator noise —
it is **within-worker TCP dynamics + SFQ DRR**.

This was the revelation. See §4.

---

## 4. The actual root cause of the residual CoV

SFQ DRR is **packet-count fair**, not **byte-rate fair**, under TCP
pacing. When two flows share a single worker:

- DRR gives each flow one packet per round.
- If both flows always have a packet ready at dequeue time, DRR is fair
  at the byte level (assuming similar packet sizes, which holds for
  iperf3).
- **Under TCP pacing, a flow with smaller cwnd is often waiting for an
  ACK when DRR polls its bucket**. The larger-cwnd flow, which has
  packets queued, gets the slot.
- DRR never "makes up" the skipped round. Over many rounds, a
  cwnd-disparate pair yields a per-flow byte rate roughly proportional
  to cwnd.

This is independent of cross-worker concerns. Even if cross-worker rate
gating were perfect, within-worker DRR cannot equalise flows whose TCP
cwnd has drifted apart. And TCP cwnd on two flows sharing a worker DOES
drift — cwnd is a random walk around BDP with correlated feedback from
ECN/loss, and the walks don't stay synchronized.

The `(local_fair_share_peak / active_flow_count_peak)` math in slice 2
enforces per-worker throughput caps correctly (unit-tested). What it
CANNOT fix is this within-worker byte-rate-vs-packet-count gap.

**The rate-gate-based approach tops out somewhere in the 20-30 % CoV
range on steady-state workloads; the only path below that is a
scheduler primitive that gives packet-byte fairness, not just
packet-count fairness.** This is what MQFQ provides.

---

## 5. Why MQFQ (the next slice)

Per the research doc `docs/cross-worker-flow-fairness-research.md`,
Hedayati & Shen's MQFQ (ATC '19) is architected for exactly xpf's
shape: per-worker local queues + one shared aggregate cap. Key
difference from slice 2:

- **Virtual finish time** on every packet: when flow F's `k`-th packet
  arrives, its finish time is `F(k) = max(F(k-1), V_min) + bytes_k /
  flow_weight_F`. (V_min is shared across workers.)
- **Drain-side**: dequeue the flow whose head packet has the smallest
  finish time. Not round-robin; explicit virtual-time ordering.
- **Shared V_min**: updated on each dequeue to the drained packet's
  finish time. Any worker seeing `v_local - V_min > T` pauses — this
  is the bounded-lag throttle.

MQFQ is byte-rate fair (virtual time is in byte units, not packet
units), which is the exact property DRR doesn't provide. Hedayati &
Shen's paper proves an O(T) bound on per-flow fairness where T is the
lag threshold.

Infrastructure that slice 2 landed — `shared_lease` Arc cache on
`CoSQueueRuntime`, `active_flow_count` atomic with idle-only reset,
rate-gate plumbing through the drain paths — is reusable under MQFQ.
What changes is the drain-side ordering: a min-heap or finish-time-
sorted ring per worker, plus the shared V_min. The existing SFQ
bucket-bytes accounting can be repurposed as the per-flow virtual-time
state.

---

## 6. Invariants established along the way (don't break these)

Each rollback cemented an invariant that any future work must respect:

1. **Per-flow share cap (`cos_queue_flow_share_limit`) must downgrade
   to aggregate on `shared_exact`** — otherwise rate-unaware 24 KB
   caps on a 25 Gbps queue kill throughput. Proven by approach A.
2. **Per-flow ECN arm (`apply_cos_admission_ecn_policy`) must use the
   aggregate arm on `shared_exact`** — same rationale. Proven by
   approach A.
3. **Rate sources must be consistent.** Admission and drain paths must
   both derive rate from `lease.rate_bytes()` on `shared_exact` (not
   `queue.transmit_rate_bytes`). Proven by approach C.
4. **Division denominators must be stable.** SFQ bucket oscillation
   makes instantaneous counts unusable. Approach D rules out
   time-based decay. Approach E works for steady-state but pins on
   sustained churn — MQFQ's V_min is the architecturally-correct fix.
5. **Peak accounting is SEPARATE from the #784 diagnostic.**
   `active_flow_buckets_peak` has a "never reset during daemon lifetime"
   operator contract. Scheduler-internal peaks
   (`local_fair_share_peak`, `active_flow_count_peak`) are distinct
   fields with different lifecycle.

All five invariants are pinned by unit tests in slice 2.

---

## 7. Code state as of this retrospective

**Slice 1 (`pr/785-shared-exact-flow-fair`, PR #785):**
- Refactor only, no runtime behavior change.
- Helpers `apply_cos_queue_flow_fair_promotion` /
  `promote_cos_queue_flow_fair`; `shared_exact` shadow on
  `CoSQueueRuntime`; 4 integration tests.
- Copilot review addressed (see commit `f07409e7`). 719 tests pass.

**Slice 2 (`pr/785-cross-worker-drr`, WIP branch, not merged):**
- Rate gate with idle-only peak reset (approach E).
- Extended infrastructure: `active_flow_count` atomic, `shared_lease`
  cache, rate gate in drain paths, aggregate-only admission on
  `shared_exact`, rate source from `lease.rate_bytes()`.
- 7 new unit tests pinning the invariants in §6.
- **Does not meet the ≤ 20 % CoV target** on iperf3 -P 12 at 25 Gbps
  (measures 49-61 %). Throughput 15-20 Gbps (slightly below baseline's
  22 Gbps). 726 tests pass.

**Decision on merging:** slice 1 is a clean cleanup and ships. Slice 2
does not meet its primary goal — merging it would regress throughput
marginally for no CoV gain. Leave the branch as-is for the MQFQ slice
to build on. The infrastructure is proven reusable; what it lacks is
the right scheduler primitive on top.

---

## 8. References

- `docs/cross-worker-flow-fairness-research.md` — pre-slice-2 algorithm
  survey. MQFQ, AFD, shared-SFQ ranked.
- PR #785 — slice 1 cleanup.
- Branch `pr/785-cross-worker-drr` — slice 2 WIP (this commit).
- Issue #786 — follow-up tracking, will be updated with this
  retrospective.
- Hedayati & Shen, *Multi-Queue Fair Queueing*, USENIX ATC '19.
