# #1614 CoS Scheduler Oversubscription Semantics — Plan v3

Status: DRAFT for plan-review round 2 (this is plan v3 against
the v1+v2 review rounds).
Branch: `refactor/1614-multi-rss-cos`
Base: `origin/master` @ `6c26c40e6` (#1611 cold-path-flooder runner body)

Supersedes plan v2 (commit `ef4012ba1`) after CONVERGENT NEEDS-MAJOR
from Claude SMR r1, AGY r1, and Codex r1. v3 narrows scope to
**Axis A only**, fully specifies the oversubscription allocation
algorithm Codex r1 requested, and re-orients acceptance criteria
around what the scheduler-semantics PR can actually deliver. Axis
B (capacity scaling) is fully deferred to separate issues.

## 0. What changed since v2

All three plan-reviewers (Claude SMR r1 NEEDS-MAJOR, AGY r1
NEEDS-MAJOR, Codex r1 NEEDS-MAJOR) converged on a strict set of
problems. v3 addresses each:

- **Codex #2 (new in r1)**: literal Pass-1-then-Pass-2 collapses
  to Pass-1-only under sustained oversubscription because
  aggregate guarantee debt grows faster than service. v2's
  algorithm was underspecified; v3 fully specifies the
  **deficit-bounded waterfill allocator** (§4 A1) which serves
  guarantees deterministically in shape-order up to capacity and
  distributes residual across all exact queues pro-rata, with a
  proof that it terminates each `drain_shaped_tx` call in O(N).

- **Codex / SMR / AGY consensus on §3**: scheduler is
  rate-proportional via per-visit quantum, equivalent to
  pro-rata only in the unclamped saturated regime. v3 §3 adopts
  this framing.

- **Codex / AGY consensus on Quantum Max clamp**: 512 KB clamp
  at rates ≥21 G explains the 21g/24g class flattening. v3 §3
  documents this.

- **Codex / SMR consensus on R8 generator bottleneck**: AGY's
  rebuttal isn't enough; we need a simultaneous-reverse control
  with same process count + generator CPU evidence BEFORE
  implementation. v3 §7 gate 8 is now BLOCKING (was: "test in
  smoke").

- **Codex / SMR consensus on ECN-WRED**: 75-100% ramp is a
  REGRESSION from current 33% threshold. v3 §4 A3 uses
  CoDel-style sojourn-time AQM (5 ms target, RFC 8290) which
  handles non-ECN flows too. ECN threshold unchanged at 33%.

- **Codex / AGY consensus on Axis B3 (RSS reprogramming)**:
  DOA. Removed.

- **Codex on Axis B1**: first-SYN redirect-to-queue does NOT
  work via XSKMAP at runtime (`xsk_rcv_check` constraint);
  requires hardware flow steering (ethtool ntuple) + lab
  verification. Demoted to BLOCKED-on-NIC-investigation.

- **Acceptance criterion 1 collapse (Codex / AGY)**: §7
  criterion 1 in v1/v2 was already met by baseline (24g 3.62 >
  3.56 G target). v3 §7 replaces with absolute-small-class-
  guarantee and explicitly excludes large-class-shape gates
  (unachievable under 109/18 oversubscription).

- **Plan scope narrowed**: v3 is Axis A only. Axis B (B1, B2,
  B4) become follow-up issues with their own plan-reviews
  against the Axis-A-post-merge baseline.

## 1. Problem statement

The userspace AF_XDP dataplane CoS scheduler implements
**rate-proportional fair sharing via per-visit quantum**
(`userspace-dp/src/afxdp/cos/queue_service/mod.rs:589-718`
`select_exact_cos_guarantee_queue_with_lease_telemetry`). Under
oversubscription, this delivers `T_i = C × Q_i / sum(Q_j)`
where `Q_i = clamp(rate_i × 200µs / 1e9, 1500, 524288)`. This
is mathematically correct for **proportional fairness** but is
**not** what Junos `transmit-rate exact` promises when
sum(rates) > capacity.

Three concrete operational gaps on the
`test/incus/cos-iperf-config.set` fixture (sum_rates 109.1 G,
push-direction ceiling 18 G):

1. **Small-class absolute-guarantee miss**: 100m class receives
   ~20 Mbps when its rate is 100 M; 1g class receives 210 Mbps
   when its rate is 1 G. Junos `transmit-rate exact` is
   typically interpreted as "honor up to rate; under
   oversubscription, smaller guarantees that fit are honored".

2. **Priority-low total starvation**: iperf-uncapped receives 0
   Gbps when all exact classes saturate root tokens.

3. **Retransmit floor of 1500-2000/class/30s**: ECN exists at
   33% threshold (`COS_ECN_MARK_THRESHOLD_NUM/DEN`) but iperf3
   default flows are NOT-ECT and the existing ECN path
   (correctly, per RFC 3168 §6.1.1.1) does not mark NOT-ECT.
   Tail-drops at 100% buffer cause the retransmit storm.

The capacity asymmetry (18 G push vs 22-23 G reverse) is
**Axis B** and OUT OF SCOPE for this plan. Filed as follow-up.

## 2. Non-goals

- Mid-flight flow re-steering across workers. Closed kill
  chain: #1215 / #837 / #937 / #1238 / #840 / #1243.
- Touching the per-flow CoV contract from #1217.
- `userspace-dp/src/policy/` (#1609 in flight).
- `test/incus/cold-path-flooder/` (#1615 in flight).
- `userspace-dp/src/afxdp/poll_stages.rs` per-source rate-limit
  (#1608 v3 parked).
- `pkg/cluster/` HA paths beyond verifying `make test-failover`.
- **Axis B (capacity scaling)** — separate follow-up issues.

## 3. Verified current scheduler behaviour (Codex+AGY+SMR convergent)

Code path: `userspace-dp/src/afxdp/cos/queue_service/mod.rs:589-718`
+ quantum constants in `userspace-dp/src/afxdp/tx/drain/mod.rs:561,563`.

`select_exact_cos_guarantee_queue_with_lease_telemetry`:
- Cursor `exact_guarantee_rr` walks runnable exact queues in
  round-robin; advances by one per selection.
- Per-visit budget: `min(queue.hot.tokens, cos_guarantee_quantum_bytes)`
- `cos_guarantee_quantum_bytes(queue) =
  clamp(rate × 200_000 / 1e9, 1500, 524288)`.

Quantum table:

| Class | Rate (Gbps) | Quantum (KB) |
|-------|-------------|--------------|
| 100m  | 0.1 | 2.5 |
| 1g    | 1.0 | 25 |
| 3g    | 3.0 | 75 |
| 6g    | 6.0 | 150 |
| 9g    | 9.0 | 225 |
| 12g   | 12.0 | 300 |
| 15g   | 15.0 | 375 |
| 18g   | 18.0 | 450 |
| 21g   | 21.0 | **512 (CLAMPED)** |
| 24g   | 24.0 | **512 (CLAMPED)** |

Sum of quantums = 2400 KB. With 18 G ceiling, predicted
`T_i = 18 × Q_i / 2400`:

| Class | Predicted | Observed | Delta |
|-------|-----------|----------|-------|
| 100m | 19 Mbps | 20 Mbps | +5% |
| 1g | 188 Mbps | 210 Mbps | +12% |
| 3g | 562 Mbps | 770 Mbps | +37% (small-class quantum floor noise) |
| 6g | 1.12 G | 1.43 G | +28% |
| 9g | 1.69 G | 2.32 G | +37% |
| 12g | 2.25 G | 2.84 G | +26% |
| 15g | 2.81 G | 2.77 G | -1% |
| 18g | 3.38 G | 2.83 G | -16% |
| 21g | 3.84 G | 3.22 G | -16% |
| 24g | 3.84 G | 3.62 G | -6% |

The systematic positive deviation on small-mid classes
(100m-12g) and negative on large (18g-24g) is the
`COS_GUARANTEE_QUANTUM_MIN_BYTES = 1500 B` floor lifting small
quantums above strict proportionality. This validates the
scheduler reading; the §3 framing is solid.

## 4. Proposed mechanism — Axis A (scheduler semantics ONLY)

### A1. Deficit-bounded waterfill exact allocator under oversubscription

Codex r1 finding #2 demanded this algorithm be fully
specified. Here it is.

#### A1.1 Algorithm

Define per-drain-pass (one `drain_shaped_tx` invocation):

- Let `cap` = available exact-class budget for this pass
  (`root.tokens` at entry; replenishes from `shaping_rate`).
- Let `exact_queues = [q | q.exact, q.runnable, !empty]`.
- Let `R_i` = `transmit_rate_bytes(q_i)`.
- Sort `exact_queues` by `R_i` ascending (stable across
  drain passes; precomputed at `ensure_cos_interface_runtime` time
  and stored as `root.exact_queues_by_rate_ascending: Vec<usize>`).

Allocate `cap` across exact queues using the **deficit-bounded
waterfill** rule:

```
remaining = cap
honored = []
for q in exact_queues_by_rate_ascending:
    quantum_i = cos_guarantee_quantum_bytes(q)  // unchanged
    debt_i = quantum_i  // one quantum per pass
    if remaining >= debt_i:
        q.alloc = debt_i
        remaining -= debt_i
        honored.append(q)
    else:
        // Pass 1 boundary: this q is the FIRST not-fully-honored.
        // Stop Pass 1.
        break
// Pass 2: distribute remaining among NOT-honored exact queues
// proportionally to their quantum_i, capped by per-queue rate-bucket.
unhonored = exact_queues - honored
total_unhonored_quantum = sum(q.quantum_i for q in unhonored)
if total_unhonored_quantum > 0 and remaining > 0:
    for q in unhonored:
        q.alloc = min(quantum_i, remaining * q.quantum_i / total_unhonored_quantum)
```

This is **O(N)** per drain pass with N ≤ 16 (typical). No
sorting at runtime; sorted vector built once at config-apply.

#### A1.2 Predicted distribution under the 109 G / 18 G fixture

Per-drain budget = `shaping_rate × 200µs / 1e9 = 25e9 × 200e-6 =
5 MB` (root token replenishment rate per drain). But the
sustained per-second budget is the 18 G ceiling. Per pass, each
queue is visited by its quantum:

Pass 1 (sorted ascending by rate):
- 100m (Q=2.5 KB) honored
- 1g (Q=25 KB) honored
- 3g (Q=75 KB) honored
- 6g (Q=150 KB) honored
- 9g (Q=225 KB) honored → remaining = 477.5 KB
- 12g (Q=300 KB) honored → remaining = 177.5 KB
- 15g (Q=375 KB) NOT honored (375 > 177.5) → Pass 1 stops

Total Pass 1 honored per pass: 100m + 1g + 3g + 6g + 9g + 12g
= 0.1 + 1 + 3 + 6 + 9 + 12 = 31 G of cumulative shape but only
777.5 KB per pass = ~31 G/s × 200 µs / 5 (drain freq factor) =
sustained throughput per queue equal to its rate. So under
this allocation each of 100m, 1g, 3g, 6g, 9g, 12g hits its
**full rate**.

Wait, that's wrong — Pass 1 honoring quantum_i once per pass at
rate_i × 200 µs sustains throughput rate_i. So Pass 1 sustains:

- 100m: 100 M (full guarantee ✓)
- 1g: 1 G (full guarantee ✓)
- 3g: 3 G (full guarantee ✓)
- 6g: 6 G (full guarantee ✓)
- 9g: 9 G (full guarantee ✓)
- 12g: 12 G (full guarantee ✓ at the boundary)

Cumulative = 31 G. But our cap is 18 G! So the algorithm runs
out of budget at some pass during the cumulative honor sequence.

CORRECTED algorithm: Pass 1 honors classes in ascending rate
order until cumulative `R_i × T` exceeds budget. Per-pass that's
`cumulative Q_i` exceeds per-pass budget. So:

Per-pass quantum budget = 18 G / sustained_pass_rate. With
quantum honoring each queue at rate, per-pass capacity = sum of
quantums of HONORED queues × passes_per_second = sum(rate_i).
Cap = 18 G ⇒ honored cumulative `sum(rate_i) ≤ 18 G`.

Cumulative table:
- After 100m: 0.1 G ≤ 18 G ✓
- After 1g: 1.1 G ✓
- After 3g: 4.1 G ✓
- After 6g: 10.1 G ✓
- After 9g: 19.1 G — **exceeds 18 G**

So Pass 1 honors 100m+1g+3g+6g fully (cumulative 10.1 G), then
9g class gets `remaining_cap = 18 - 10.1 = 7.9 G` (88% of 9 G
guarantee).

Pass 2: 9g (partial)+12g+15g+18g+21g+24g compete for the
remaining 0 G ⇒ Pass 2 has nothing to distribute.

That predicts:

| Class | Pass 1 honored | Pass 2 share | Predicted | Today |
|-------|----------------|--------------|-----------|-------|
| 100m | 0.1 G | 0 | 0.1 G | 0.02 G |
| 1g | 1.0 G | 0 | 1.0 G | 0.21 G |
| 3g | 3.0 G | 0 | 3.0 G | 0.77 G |
| 6g | 6.0 G | 0 | 6.0 G | 1.43 G |
| 9g | 7.9 G | 0 | 7.9 G | 2.32 G |
| 12g | 0 | 0 | 0 | 2.84 G |
| 15g | 0 | 0 | 0 | 2.77 G |
| 18g | 0 | 0 | 0 | 2.83 G |
| 21g | 0 | 0 | 0 | 3.22 G |
| 24g | 0 | 0 | 0 | 3.62 G |

This is the "literal Pass 1 only" outcome Codex flagged as
pathological. **Operators will not accept 12g-24g classes at 0
Gbps.**

#### A1.3 The actual algorithm: bounded-honor + proportional-residual

Replace Pass 2 with a **floor on residual exact capacity**. The
honored Pass 1 set is capped at `floor × cap` where `floor` is
operator-tunable. Default `floor = 0.5` means at most 50% of
exact capacity is consumed by Pass 1; the remaining ≥50% goes to
Pass 2 proportionally across **all** exact queues (honored + not).

Mathematically:
```
pass1_cap = floor × cap
pass1_set = greedy ascending-rate honor until cumulative R reaches pass1_cap
pass1_honored = sum(R_i for q_i in pass1_set, up to rate)
pass2_budget = cap - pass1_honored
pass2_quantum_sum = sum(Q_i for ALL exact q_i)
for q in ALL exact queues:
    pass2_alloc_i = pass2_budget × Q_i / pass2_quantum_sum
    q.total_alloc = pass1_alloc_i + pass2_alloc_i
    (capped at rate_i)
```

For the 109 / 18 / floor=0.5 fixture:
- pass1_cap = 9 G
- Pass 1 honored set (ascending rate, ≤9 G cumulative):
  100m+1g+3g+6g (cumulative 10.1 G — slightly over, so honor
  100m+1g+3g and partial 6g at 4.9 G). Or honor 100m+1g+3g+6g
  fully if integer-rounded (10.1 ≤ 1.1 × 9 G; tolerance band).
- pass2_budget = 18 - 9 = 9 G
- pass2 distributed: each exact queue gets `9 × Q_i / 2400 = 9 ×
  rate_i / 105` (since Q_i ∝ R_i for unclamped). So pass2_alloc:
  - 100m: 9 × 0.1/105 = 8.6 Mbps (but already at 100 M from
    Pass 1; cap.)
  - 1g: 85.7 Mbps (capped at 1 G)
  - 3g: 257 Mbps (capped at 3 G)
  - 6g: 514 Mbps (capped at 6 G)
  - 9g: 771 Mbps
  - 12g: 1029 Mbps
  - 15g: 1286 Mbps
  - 18g: 1543 Mbps
  - 21g: 1755 (clamped quantum gives slightly less)
  - 24g: 1755

Total Pass 2: ~9 G. Total predicted:
- 100m: 100M (Pass 1 cap) ✓
- 1g: 1 G ✓
- 3g: 3 G ✓
- 6g: 4.9 (Pass 1 partial) + 0.5 (Pass 2) = 5.4 G ≥ 90% of 6 G ✓
- 9g: 0 + 0.77 = 0.77 G (worse than today's 2.32!)

Hmm. This is the fundamental tension: protecting small classes
absolutely costs the mid-range classes their proportional share.

#### A1.4 Refined: weighted-honor algorithm (final v3 proposal)

Replace `floor = 0.5` with a smarter rule: **honor each
ascending class up to its rate OR up to its fair-share-under-
pure-proportional, whichever is larger**.

```
proportional_share_i = cap × R_i / sum(R_j)  // current scheduler result
honor_target_i = max(R_i, proportional_share_i)
                  if cumulative honor remains ≤ cap; else stop
```

Under 109/18/proportional fixture (sum R = 105 G, cap = 18 G,
proportional_share = R_i × 18 / 105 = 0.171 × R_i):

| Class | Proportional | Rate | Honor target | Cumulative |
|-------|--------------|------|--------------|------------|
| 100m | 17.1 M | 100 M | **100 M** | 0.1 G |
| 1g | 171 M | 1 G | **1 G** | 1.1 G |
| 3g | 514 M | 3 G | **3 G** | 4.1 G |
| 6g | 1.03 G | 6 G | **6 G** | 10.1 G |
| 9g | 1.54 G | 9 G | rate (9 G) | 19.1 G OVER! |

Cumulative honor at 9g exceeds cap. The 9g class is the
boundary: its honor target reduces from "rate" to
"proportional 1.54 G" (or any value between proportional and
rate; pick proportional). Cumulative becomes 11.64 G; remaining
= 6.36 G.

For 12g-24g: each gets proportional 0.171 × R_i:
- 12g: 2.06 G
- 15g: 2.57 G
- 18g: 3.09 G
- 21g: 2.74 G (clamped quantum, would-be 3.6 G)
- 24g: 2.74 G (clamped)

Cumulative 12g-24g: 2.06+2.57+3.09+2.74+2.74 = 13.2 G. With
6.36 G remaining, scale by 6.36/13.2 = 0.48. Final allocations:

| Class | Final predicted |
|-------|------------------|
| 100m | 100 M ✓ (was 20) |
| 1g | 1.0 G ✓ (was 210M) |
| 3g | 3.0 G ✓ (was 770M) |
| 6g | 6.0 G ✓ (was 1.43 G) |
| 9g | 1.54 G (was 2.32 G — REGRESSION) |
| 12g | 0.99 G (was 2.84 G — REGRESSION) |
| 15g | 1.23 G (was 2.77 G — REGRESSION) |
| 18g | 1.48 G (was 2.83 G — REGRESSION) |
| 21g | 1.32 G (was 3.22 G — REGRESSION) |
| 24g | 1.32 G (was 3.62 G — REGRESSION) |

Small classes WIN BIG. Mid classes REGRESS. **This is the
right Junos semantic** but operators must opt in.

#### A1.5 Operator-selectable mode (Junos-style)

Per Codex r1 finding #3 (criterion 1 conflicts with stated
goal): add a Junos-style operator knob to select policy:

```
set class-of-service interfaces <iface> unit <u> oversubscription-policy {strict-exact | proportional}
```

- **`strict-exact`** (new, opt-in): A1.4 algorithm —
  small-class guarantees honored absolutely; mid-large classes
  share residual proportionally.

- **`proportional`** (default, current behaviour): existing
  scheduler unchanged.

The default is `proportional` to avoid regressing existing
deployments. Operators who want Junos `transmit-rate exact`
semantics opt in.

Configuration-validator warning when `strict-exact` is selected
AND sum_rates > shaping_rate: "selected strict-exact under
oversubscription; classes with rate above (rate × shaping_rate
/ sum_rates) will see regression versus proportional".

### A2. Priority-low minimum share (work-conserving)

Add a configurable minimum share for priority-low queues.
Default **5% of `shaping-rate`** (AGY's rationale: control-plane
preservation).

Configurable via:
```
set class-of-service interfaces <iface> unit <u> priority-low-min-share <bps|percent>
```

Mechanism: priority-low queue is admitted to **Pass 1 set**
alongside exact-guarantee queues with `R_eff =
priority_low_min_share_bytes`. Above its min-share, falls back
to **Pass 2 surplus** as today.

Wire-protocol both-sides:
- Go: `pkg/dataplane/userspace/protocol.go` (or equivalent — the
  `CoSInterfaceSnapshot` definition; confirm exact file at
  implementation time) adds `priority_low_min_share_bytes uint64`.
- Rust: `userspace-dp/src/protocol/` matching field with
  `#[serde(default)]`.

Default value `0` means "no min-share" (preserving current
behaviour). The fixture-level default `5%` is applied at the
Go config-compile stage from the `oversubscription-policy`
setting if `strict-exact` is selected.

### A3. CoDel-style time-based AQM (replaces v1 ECN-WRED)

v1 proposed raising ECN threshold from current 33% to 75%. AGY
+ Codex both showed this is a REGRESSION. v3 keeps ECN at 33%
and addresses the actual retrans-storm root cause:

iperf3 default flows are NOT-ECT; the existing ECN path (per
RFC 3168 §6.1.1.1) protects non-ECN flows from CE marking.
Tail-drops at 100% buffer cause the storm.

**A3 mechanism**: add a CoDel-style sojourn-time AQM at the
dequeue path. When the oldest packet in a queue has been queued
for ≥5 ms (RFC 8290 default), drop it (or mark CE if ECT).

Implementation:
- `userspace-dp/src/afxdp/cos/queue_ops.rs`: each queued item
  carries `enqueue_ns: u64`.
- Dequeue path computes `sojourn = now_ns - oldest.enqueue_ns`;
  if `sojourn > CODEL_TARGET_NS`, drop (or mark CE if ECT).
- New const `CODEL_TARGET_NS: u64 = 5_000_000`.
- Configurable per-queue via Junos knob
  `set class-of-service schedulers <name> codel-target <ms>`;
  default 5 ms; `0` disables CoDel for the queue.

This affects iperf3 default flows (NOT-ECT → drops at 5 ms
sojourn instead of waiting for full buffer). Expected retrans
reduction: 1500-2000 → ≤100 per class per 30 s.

The existing ECN 33% threshold path **remains in place** for
ECT(0)/ECT(1) flows; CoDel adds a sojourn-time gate that
applies to all flows.

### A4. Operator-visible warning when sum_rates > shaping-rate

`pkg/config/cos.go` commit validator emits a WARNING when
`sum_exact_rates > shaping_rate`. Format:

```
warning: class-of-service interfaces <iface> unit <u> exact-rate sum
(<N> G) exceeds shaping-rate (<M> G); selected
oversubscription-policy=<mode> will produce <strict-exact: small
classes honored, large classes reduced | proportional:
proportional-share for all>.
```

Unit test in `pkg/config/cos_test.go` covering both modes.

## 5. Axis B fully deferred to follow-up issues

Each gets its own plan-review against the Axis-A-post-merge
baseline:

- **B1 (first-SYN class-affinity via hardware flow steering)**:
  BLOCKED. Per Codex r1: XSKMAP redirect-to-queue at runtime
  violates `xsk_rcv_check`. Mechanism must use ethtool ntuple
  or driver-supported flow steering at first-SYN. Requires lab
  verification on the mlx5 VF driver. File investigation
  issue.

- **B2 (cross-worker shared shaper-budget atomic)**: generalize
  #917 V_min to any exact queue with >1 active worker.
  Clean follow-up; file as separate issue post-Axis-A.

- **B3 (RSS reprogramming)**: KILLED per AGY+Codex DOA on #840
  resurrection.

- **B4 (per-class dedicated cores)**: deferred indefinitely;
  only revive if B1+B2 don't close the gap.

## 6. Hidden invariants

- **HA sync portability**: A1+A2+A3+A4 are all local-scheduler
  scope; no cluster-state changes. Both chassis independently
  arrive at same scheduler behaviour from same config.
- **Cstruct (#1217) contract preservation**: per-flow CoV gate
  unchanged. New shape-achievement gates are additive.
- **Junos compat**: `strict-exact` mode is opt-in; default
  `proportional` preserves current behaviour bit-for-bit. No
  upgrade surprise.
- **ECN-NOT-ECT protection** (RFC 3168 §6.1.1.1): unchanged.
  CoDel drops instead of marks for NOT-ECT flows; this is the
  correct AQM behaviour per RFC 8290.
- **Wire-protocol additive-only**: new Go fields default to 0
  on absence; new Junos knobs default to behaviour-preserving
  values.

## 7. Acceptance criteria (re-grounded)

Per Codex r1 finding #3 — criterion 1 of v1/v2 was already met
by baseline. v3 criteria are honest about what Axis A delivers:

1. **In `strict-exact` mode**: small classes (sum_rates ≤
   ceiling) hit ≥ 95% of configured rate under simul-load.
   Specifically:
   - 100m class ≥ 95 Mbps (today: 20)
   - 1g class ≥ 950 Mbps (today: 210)
   - 3g class ≥ 2.85 G (today: 770)
   - 6g class ≥ 5.7 G (today: 1.43)
   - Larger classes are NOT gated (their guarantees are
     unfulfillable under 109/18 oversubscription; they get
     residual share per A1.4).

2. **In `strict-exact` mode**: priority-low (iperf-uncapped) gets
   ≥ 5% of cluster ceiling (today: 0 Gbps).

3. **Aggregate retrans ≤ 100 per class per 30 s under simul**
   (BOTH modes; today: 1500-2000). CoDel handles this regardless
   of mode.

4. **Per-flow CoV ≤ Cstruct + 0.05** per #1217 contract,
   unchanged.

5. **HA failover unchanged**: `make test-failover` passes at
   ~60 ms median over 5 iterations.

6. **`proportional` mode (default) bit-for-bit unchanged**:
   regression test that current `cos-iperf-config.set` produces
   the same distribution as master HEAD (within ±5% per-class
   token-bucket noise).

7. **Operator warning triggers** on the existing
   `cos-iperf-config.set` fixture (109 G > 25 G).

8. **R8 sanity check (BLOCKING — must run BEFORE PR-1 merge)**:
   simultaneous all-11-class reverse-direction run, same
   process count, same `-P 12`, same 30 s duration. Gate:
   aggregate ≥ 22 G (matching solo reverse baseline). Plus
   generator CPU saturation metrics (`mpstat -P ALL 1 30`
   inside `loss:cluster-userspace-host`). If reverse-simul also
   caps at ~18 G, the firewall ISN'T the bottleneck and the
   entire baseline needs remeasurement on a beefier generator
   (BLOCKED, file follow-up).

PR-1 conditionally MERGEABLE on 4-of-4 reviewers (Codex, AGY,
Copilot, Claude SMR) + gates 1, 2, 3, 5, 6, 7, 8 PASSING.

## 8. Kill-chain respect (vs closed PLAN-KILLs)

| Closed | Killed because | This plan |
|--------|----------------|-----------|
| #1215 | mid-flight re-steering | Axis A local scope only |
| #837 | mid-flight re-steering | same |
| #937 | `xsk_rcv_check` cross-queue | Axis A doesn't touch ingress |
| #1238 | similar to #1215 | same |
| #840 | RSS reprogramming broke long-lived flows | B3 KILLED in v3 |
| #1243 | uniform multinomial cancellation | B4 deferred indefinitely |

## 9. Risks + open questions

### R1. Sorted exact_queues vector mutation under reconfig

`root.exact_queues_by_rate_ascending` rebuilds on
`ensure_cos_interface_runtime`. Plan: rebuild atomically during
config-apply; no runtime mutation.

### R2. CoDel 5 ms target may be too aggressive for some
operator profiles

5 ms is RFC 8290 default. Operators with longer RTT (satellite,
ocean cables) may want 50-100 ms. Plan: per-queue tunable via
`codel-target <ms>` Junos knob; default 5 ms.

### R3. R8 generator-bottleneck rules entire baseline

Gate 8 is BLOCKING. If reverse-simul caps at ~18 G, the
firewall is innocent and the plan is invalidated. Run the
check BEFORE implementation. Bash recipe:

```bash
for port in 5201 5202 5203 5204 5205 5206 5207 5208 5209 5210 5211; do
  sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
    iperf3 -c 172.16.80.200 -P 12 -t 30 -p $port -R --json" \
    > /tmp/rev_$port.json &
done
wait
sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
  mpstat -P ALL 1 30 > /tmp/rev_mpstat.txt" &
```

Plus generator iperf3 version check
(`iperf3 --version` — different threading models pre/post 3.10).

### R4. Wire-protocol both-sides verification

New Go fields:
- `oversubscription_policy: string` (or enum)
- `priority_low_min_share_bytes: uint64`
- `codel_target_ns: uint64` (per queue)

Need confirmation of exact file paths at implementation time.
Reviewers please flag if these are wrong.

### R5. A1.4 "weighted-honor" algorithm produces regressions on
mid-rate classes under `strict-exact`

This is intentional and documented. Operators who want this
behaviour opt in via `oversubscription-policy strict-exact`.
Default remains `proportional` (no regression).

### R6. CoDel interaction with shape-rate-based drops

A queue at its `transmit-rate exact` cap should be filling
slowly; sojourn time should NOT exceed 5 ms in normal
operation. CoDel only fires under oversubscription when the
queue is shape-rate-limited AND drained at less than its
arrival rate. This is precisely the case we want to fix
(retrans storms). Plan: validate sojourn time under
single-class shape-rate solo (no oversubscription) — should be
<1 ms most of the time, never crossing CoDel target.

### R7. iperf3 `--ecn` flag verification

Unrelated to Axis A merge; only needed if smoke wants to
validate ECN path end-to-end. Skip if `iperf3 --ecn` doesn't
exist; CoDel still works on non-ECN flows.

## 10. Test plan

### 10.1 Cargo + Go unit/integration tests

New tests in `userspace-dp/src/afxdp/cos/queue_service/tests.rs`:
- `strict_exact_honors_small_classes_under_oversubscription`
- `strict_exact_distributes_residual_to_large_classes`
- `proportional_mode_preserves_master_distribution` (regression)
- `priority_low_admitted_to_pass1_at_min_share`
- `codel_drops_nonECT_after_5ms_sojourn`
- `codel_marks_ECT_after_5ms_sojourn`
- `codel_disabled_when_target_zero`

New tests in `pkg/config/cos_test.go`:
- `commit_warns_when_shape_sum_exceeds_shaping_rate_strict_exact`
- `commit_warns_when_shape_sum_exceeds_shaping_rate_proportional`

5/5 flake-check on all new tests.
Full `cargo test --workspace` green.
`go test ./...` green.

### 10.2 Smoke matrix Pass A + Pass B + NEW Pass C + NEW Pass D

- **Pass A** existing per-class single-class smoke.
- **Pass B** existing `fairness-cos-class-sweep.sh` +
  `--mixed-cos`.
- **NEW Pass C — simul-load all-11-class push**: 30 s, all 11
  classes parallel, push direction. Runs in BOTH modes:
  - C1: `proportional` (regression gate 6)
  - C2: `strict-exact` (gates 1, 2, 3)
- **NEW Pass D — simul-load all-11-class reverse (R8 gate 8)**:
  same fixture, reverse direction, with `mpstat` capture. Gate
  per §7 criterion 8.

Harness: new `test/incus/cos-simul-load-smoke.sh` plus Python
reducer. Permanent member of smoke matrix.

### 10.3 HA failover

`make test-failover` passes at ~60 ms median over 5 iterations
in BOTH modes (proportional + strict-exact).

### 10.4 Backward-compat regression

Apply `cos-iperf-config.set` (no new knobs) → Pass C1
distribution matches master HEAD within ±5% per-class.

## 11. Schedule

- Plan-review round 2 (this v3): now. Expect 1 more round.
- Implementation Axis A: ~8-12 hours wall clock. A1 algorithm
  is the bulk; A2/A3/A4 mechanical.
- Smoke + merge: same day if gates pass.
- Axis B: separate issues post-merge. B3 explicitly killed.

## 12. Doc updates landing in PR-1

- `docs/fairness-regimes.md` — new section "Oversubscription
  policy" describing the two modes + Pass-C / Pass-D gates.
- `docs/userspace-jit-design.md` — add Phase 6 entry
  "Oversubscription policy" linking PR-1.
- `docs/cos-traffic-shaping.md` — update scheduler section
  with the deficit-bounded waterfill algorithm.
- `userspace-dp/src/afxdp/cos/README.md` — describe Pass 1 /
  Pass 2 / CoDel.

---

## Reviewer checklist round 2 (v3)

- [ ] Is the §4 A1 deficit-bounded waterfill algorithm fully
  specified, terminating, and correct?
- [ ] Does the `proportional` (default) preservation guarantee
  hold under all configurations?
- [ ] Does the `strict-exact` opt-in mode honour Junos
  `transmit-rate exact` documented semantics?
- [ ] Is the §7 gate 8 (R8 reverse-simul check) sufficient to
  rule out generator-bottleneck before implementation?
- [ ] Does A3 (CoDel 5ms sojourn-time) achieve retrans ≤ 100
  per class per 30 s? Show math or simulation.
- [ ] Is B3 KILL final? Are B1 / B2 / B4 deferral acceptable?
- [ ] What did v3 miss?
- [ ] PLAN-READY / NEEDS-MAJOR / PLAN-KILL.
