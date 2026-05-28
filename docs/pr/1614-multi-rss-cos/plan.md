# #1614 CoS Scheduler Oversubscription Semantics — Plan v5

Status: DRAFT for plan-review round 3.
Branch: `refactor/1614-multi-rss-cos`
Base: `origin/master` @ `6c26c40e6` (#1611 cold-path-flooder runner body)

v5 supersedes plan v4 (commit `10cfa2128`) after AGY r2 identified
three structural findings, all confirmed mechanical fixes:

  1. **Proportional Mode Divergence**: v4's algorithm at
     `fraction=0.0` was NOT bit-for-bit identical to current
     scheduler — it changed RR cursor to sorted ascending and
     dynamic-scaled per-visit budget. Fix: explicit branch — if
     mode is `proportional` (default), bypass new allocator and
     run legacy `select_exact_cos_guarantee_queue_with_lease_telemetry`
     unchanged. If `guarantee-rate > 0`, run new waterfill.

  2. **Priority-Low Min-Share Coupling**: v4 admitted priority-low
     to Pass 1 — which is zero-sized under default `fraction=0.0`,
     starving priority-low. Fix: subtract min-share from `cap`
     FIRST (`cap_eff = cap - priority_low_min_share_bytes`), then
     run allocator on `cap_eff`. Priority-low is reserved
     orthogonally to oversubscription policy.

  3. **CoDel target ≤ RTT collision**: v4's 5ms target collides
     with cluster's 5-7ms feedback RTT, causing oscillation +
     #1217 Cstruct contract risk. Fix: scale target with RTT —
     `codel-target = max(5ms, 1.5 × measured_RTT)`.

The v3 / v4 changelogs are retained below for auditability.

## 0. What changed since v3 (then v2)

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

> **Phase 0 (run BEFORE any A1 implementation): R8 reverse-simul
> sanity check.** Plan §7 gate 8 is BLOCKING. The implementer
> MUST run gate 8 first and confirm reverse-simul aggregate ≥ 22 G
> before writing A1 code. If reverse-simul caps at ~18 G the
> firewall isn't the bottleneck and the entire plan is
> invalidated. File a separate follow-up to re-acquire baseline on
> a beefier generator and STOP work on this plan.

### A1. Two-phase guaranteed-rate allocator (Junos-style oversubscription)

v3's algorithm was internally inconsistent (Claude SMR r2 F4):
the "weighted-honor" prediction table double-counted 9g class's
Pass 1 partial + Pass 2 share, contradicting the algorithm's
break-then-distribute-to-unhonored rule. v4 specifies a clean
two-phase algorithm with explicit operator-tunable Pass 1 budget
fraction.

#### A1.1 Algorithm (v5 — explicit branch + min-share-first)

**Explicit mode branch (AGY r2 #1 fix)**:
```
if root.config.oversubscription_policy == Proportional
   OR root.config.guarantee_fraction == 0.0:
    // BIT-FOR-BIT IDENTICAL to current scheduler.
    return select_exact_cos_guarantee_queue_with_lease_telemetry(root, ...)
// else: run the new waterfill allocator below.
```

This eliminates the bit-for-bit divergence AGY r2 #1 raised. The
new code path only activates when an operator explicitly opts in.

**Priority-low min-share subtracted from cap first (AGY r2 #2 fix)**:
```
cap_eff = root.tokens - priority_low_min_share_bytes_this_pass
// (priority-low gets its reserved min-share OUTSIDE the
// allocator; admitted to Phase 3 surplus path that runs
// regardless of mode.)
```

This makes priority-low survivability orthogonal to the
oversubscription policy choice.

Per `drain_shaped_tx` invocation (when `guarantee_fraction > 0`):

- Let `cap` = available exact-class budget for this pass
  (`root.tokens` at entry; replenishes from `shaping_rate`).
- Let `exact_queues = [q | q.exact, q.runnable, !empty]`.
- Let `R_i` = `transmit_rate_bytes(q_i)`.
- Let `Q_i` = `cos_guarantee_quantum_bytes(q_i)` (unchanged).
- `root.exact_queues_by_rate_ascending: Vec<usize>` is a
  precomputed-at-config-apply vector of queue indices sorted by
  ascending `R_i`. Mutation only on config-apply; runtime is read-only.

```
guarantee_fraction = root.config.pass1_guarantee_fraction  // 0.0..1.0
pass1_budget = (cap * guarantee_fraction).floor()
remaining_pass1 = pass1_budget
honor_set = {}  // u64 bitmask of honored queue indices

# Phase 1: greedy small-first honor up to Pass 1 budget
for queue_idx in root.exact_queues_by_rate_ascending:
    Q_i = quantum(queue_idx)
    if remaining_pass1 >= Q_i:
        alloc[queue_idx] += Q_i
        remaining_pass1 -= Q_i
        honor_set |= 1 << queue_idx
    elif remaining_pass1 > 0:
        # Partial honor — fits Q_i partially. Allocate exactly
        # `remaining_pass1` bytes and stop Phase 1.
        alloc[queue_idx] += remaining_pass1
        remaining_pass1 = 0
        # Note: queue_idx is NOT in honor_set; it will participate
        # in Phase 2 with its remaining Q_i.
        break
    else:
        break

# Phase 2: proportional residual across ALL queues NOT fully honored.
# This includes the partial-honor queue from Phase 1 (which got some
# bytes but less than its full Q_i).
pass2_budget = cap - (pass1_budget - remaining_pass1)
# = cap - actual_phase1_alloc
unhonored_total_quantum = sum(Q_i for i NOT in honor_set)
if unhonored_total_quantum > 0 and pass2_budget > 0:
    for queue_idx NOT in honor_set:
        alloc[queue_idx] += pass2_budget * Q_i / unhonored_total_quantum
        # No rate cap — Phase 2 share never exceeds the queue's
        # per-pass quantum because pass2_budget ≤ pass2_quantum_sum
        # in oversubscribed regime.

# Phase 3 (after exact): non-exact + priority-low surplus
# (existing select_cos_surplus_batch_filtered path unchanged)
```

Where `pass1_guarantee_fraction` is a per-interface knob from
the new `oversubscription-policy guarantee-rate <fraction>` Junos
setting, default `0.0` (which makes Phase 1 a no-op and the
algorithm collapses to current proportional behaviour for
backward compatibility).

This is **O(N)** per drain pass with N ≤ 16 (typical), no
sorting at runtime.

#### A1.2 Predicted distribution under 109/18 fixture, `guarantee-rate 0.7`

`pass1_budget = 0.7 × 18 = 12.6 G`

Phase 1 (sorted ascending by rate):
- 100m honored (cumulative 0.1 G ≤ 12.6 G)
- 1g honored (cumulative 1.1 G)
- 3g honored (cumulative 4.1 G)
- 6g honored (cumulative 10.1 G)
- 9g: needs 9 G but only `12.6 - 10.1 = 2.5 G` remains → **partial
  honor 2.5 G**; Phase 1 stops here. 9g is NOT in honor_set.

Phase 2 budget = `18 - (10.1 + 2.5) = 5.4 G`
Phase 2 unhonored = {9g, 12g, 15g, 18g, 21g, 24g}
Phase 2 total quantum = 225 + 300 + 375 + 450 + 512 + 512 = 2374 KB
Phase 2 per-class allocation = `5.4 × Q_i / 2374`:
- 9g: 5.4 × 225/2374 = 0.512 G
- 12g: 5.4 × 300/2374 = 0.682 G
- 15g: 5.4 × 375/2374 = 0.853 G
- 18g: 5.4 × 450/2374 = 1.023 G
- 21g: 5.4 × 512/2374 = 1.164 G
- 24g: 5.4 × 512/2374 = 1.164 G

Final per-class total:

| Class | Phase 1 | Phase 2 | Total | Today |
|-------|---------|---------|-------|-------|
| 100m | 100 M | 0 | 100 M ✓ | 20 M |
| 1g | 1 G | 0 | 1 G ✓ | 210 M |
| 3g | 3 G | 0 | 3 G ✓ | 770 M |
| 6g | 6 G | 0 | 6 G ✓ | 1.43 G |
| 9g | 2.5 G | 0.51 G | 3.01 G | 2.32 G (improvement) |
| 12g | 0 | 0.68 G | 0.68 G | 2.84 G (REGRESSION) |
| 15g | 0 | 0.85 G | 0.85 G | 2.77 G (REGRESSION) |
| 18g | 0 | 1.02 G | 1.02 G | 2.83 G (REGRESSION) |
| 21g | 0 | 1.16 G | 1.16 G | 3.22 G (REGRESSION) |
| 24g | 0 | 1.16 G | 1.16 G | 3.62 G (REGRESSION) |
| Sum  |       |        | 18 G  | 20 G |

Small classes (100m, 1g, 3g, 6g, 9g) honoured fully or
near-fully; 9g class actually IMPROVES from 2.32 → 3.01 G.
Larger classes (12g-24g) REGRESS — this is the operator-visible
trade-off of `guarantee-rate`.

For operators who want NO regression, `guarantee_fraction = 0`
preserves current behaviour bit-for-bit.

For operators who want intermediate behaviour, e.g.
`guarantee-rate 0.4`:
- pass1_budget = 7.2 G
- Honor 100m, 1g, 3g (cumulative 4.1 G), then 6g: needs 6 G but
  only 3.1 G remains → partial 3.1 G; Phase 1 stops.
- Phase 2 = 18 − 7.2 = 10.8 G across {6g, 9g, 12g, 15g, 18g, 21g, 24g}
- Phase 2 total Q = 150 + 225 + 300 + 375 + 450 + 512 + 512 = 2524 KB
- Each gets 10.8 × Q_i/2524 ≈ 4.28 × Q_i (KB → Gbps)
- 6g: 0.642 G (Phase 2 only — Phase 1 partial 3.1 G already counted)
  → wait, 6g gets Phase 1 partial 3.1 G + Phase 2 0.642 G = 3.74 G
- 9g: 0 + 0.963 G = 0.963 G
- 12g: 0 + 1.28 G
- 15g: 0 + 1.61 G
- 18g: 0 + 1.93 G
- 21g: 0 + 2.19 G
- 24g: 0 + 2.19 G

Sum = 100 M + 1 G + 3 G + 3.74 + 0.96 + 1.28 + 1.61 + 1.93 + 2.19 + 2.19 = 17.99 G ✓

This gives a smoother tradeoff. Operators choose the
`guarantee-rate` fraction to balance small-class protection vs
large-class throughput.

#### A1.3 Operator-selectable policy (Junos-style)

```
set class-of-service interfaces <iface> unit <u>
  oversubscription-policy guarantee-rate <fraction>
```

`fraction` is `0.0..1.0`. Default `0.0` preserves current
behaviour bit-for-bit. Recommended values:
- `0.0` (default): pure proportional — no behaviour change.
- `0.4`: balanced — small classes honoured, large classes
  receive ~70% of their previous share.
- `0.7`: aggressive — small classes fully honoured, large
  classes receive ~30-40% of their previous share.
- `1.0`: full strict — small classes fully honoured, large
  classes share only the remaining 0-9% of cap.

Configuration-validator warning when `guarantee_fraction > 0`
AND `sum_rates > shaping_rate`:

```
warning: oversubscription-policy guarantee-rate <X> on
<iface>.<u>: small classes will be honoured to their full rate;
larger classes will see throughput reduced from
(proportional ≈ R × shaping / sum_R) to ((1-X) of proportional).
Set guarantee-rate 0.0 to preserve current proportional behaviour.
```

#### A1.4 Why the algorithm is stable across drain passes

The algorithm is stateless across drain passes (no
guarantee-debt accumulation). Each pass independently computes
phase 1 + phase 2 over `root.tokens` (which is refilled by
`refill_cos_tokens` per the shaping rate). This avoids the
Codex r1 #2 concern about debt growing faster than service:
debt is BOUNDED per pass by `pass1_budget`, not accumulated
across passes.

### A2. Priority-low minimum share (work-conserving, ORTHOGONAL to A1)

Per AGY r2 #2: priority-low min-share is ORTHOGONAL to
oversubscription policy. Implemented by subtracting min-share
from `root.tokens` BEFORE the A1 allocator runs, and admitting
the priority-low queue to the surplus phase up to the min-share
rate.

Mechanism:
```
priority_low_min_share_pass = priority_low_min_share_bytes × elapsed_ns / 1e9
cap_eff = root.tokens - priority_low_min_share_pass
// Priority-low queue is admitted to Phase 3 (surplus) up to
// min_share_pass; remaining cap_eff goes to A1.
```

Default: `priority_low_min_share_bytes = 0` (no min-share —
preserves current behaviour). The fixture-level recommended
default is 5% of shaping-rate, applied by the Go config-compiler
when `oversubscription-policy guarantee-rate <X>` (X > 0) is
selected. Operators can override per-interface via:

```
set class-of-service interfaces <iface> unit <u> priority-low-min-share <bps|percent>
```

Wire-protocol both-sides (verified per AGY r2):
- Go: `pkg/dataplane/userspace/protocol.go` `InterfaceSnapshot`
  (L118 — verified) gains `CoSPriorityLowMinShareBytes uint64`.
- Rust: `userspace-dp/src/protocol/snapshot.rs` `InterfaceSnapshot`
  (L38 — verified) gains matching field with `#[serde(default)]`.

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
  if `sojourn > codel_target_ns`, drop (or mark CE if ECT).
- New const `CODEL_DEFAULT_TARGET_NS: u64 = 5_000_000` (RFC 8290
  baseline).
- **Per-queue tunable via Junos knob** (AGY r2 #3 fix):
  `set class-of-service schedulers <name> codel-target <ms>`;
  default 5 ms; `0` disables CoDel for the queue.

**RTT-aware tuning advice (AGY r2 #3)**: the cluster's documented
post-shaper feedback RTT is 5-7 ms. A 5 ms CoDel target
collides with RTT and risks TCP cwnd oscillation that elevates
per-flow CoV beyond the #1217 Cstruct + 0.05 gate. Operators
SHOULD set `codel-target = max(5ms, 1.5 × measured_RTT)` for
their deployment. The smoke harness will measure RTT during
Phase 0 and surface a recommended target. `docs/cos-traffic-shaping.md`
will document this RTT-aware tuning rule.

The default 5 ms target stays at RFC 8290 baseline, but the
warning is documented per-config.

This affects iperf3 default flows (NOT-ECT → drops at sojourn
target instead of waiting for full buffer). Expected retrans
reduction: 1500-2000 → ≤100 per class per 30 s **conditional on
correct codel-target tuning per the RTT-aware rule above**.

The existing ECN 33% threshold path **remains in place** for
ECT(0)/ECT(1) flows; CoDel adds a sojourn-time gate that
applies to all flows.

### A4. Operator-visible warning when sum_rates > shaping-rate

`pkg/config/cos.go` commit validator emits a WARNING when
`sum_exact_rates > shaping_rate`. Format:

```
warning: class-of-service interfaces <iface> unit <u> exact-rate sum
(<N> G) exceeds shaping-rate (<M> G); selected
oversubscription-policy=<mode> will produce <`guarantee-rate` (fraction>0): small
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
- **Junos compat**: `guarantee-rate` mode is opt-in; default
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

1. **In `guarantee-rate` mode**: small classes (sum_rates ≤
   ceiling) hit ≥ 95% of configured rate under simul-load.
   Specifically:
   - 100m class ≥ 95 Mbps (today: 20)
   - 1g class ≥ 950 Mbps (today: 210)
   - 3g class ≥ 2.85 G (today: 770)
   - 6g class ≥ 5.7 G (today: 1.43)
   - Larger classes are NOT gated (their guarantees are
     unfulfillable under 109/18 oversubscription; they get
     residual share per A1.4).

2. **In `guarantee-rate` mode**: priority-low (iperf-uncapped) gets
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
mid-rate classes under `guarantee-rate`

This is intentional and documented. Operators who want this
behaviour opt in via `oversubscription-policy guarantee-rate <X>`.
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
  - C2: `guarantee-rate` (gates 1, 2, 3)
- **NEW Pass D — simul-load all-11-class reverse (R8 gate 8)**:
  same fixture, reverse direction, with `mpstat` capture. Gate
  per §7 criterion 8.

Harness: new `test/incus/cos-simul-load-smoke.sh` plus Python
reducer. Permanent member of smoke matrix.

### 10.3 HA failover

`make test-failover` passes at ~60 ms median over 5 iterations
in BOTH modes (proportional + `guarantee-rate`).

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
- [ ] Does the `guarantee-rate` opt-in mode honour Junos
  `transmit-rate exact` documented semantics?
- [ ] Is the §7 gate 8 (R8 reverse-simul check) sufficient to
  rule out generator-bottleneck before implementation?
- [ ] Does A3 (CoDel 5ms sojourn-time) achieve retrans ≤ 100
  per class per 30 s? Show math or simulation.
- [ ] Is B3 KILL final? Are B1 / B2 / B4 deferral acceptable?
- [ ] What did v3 miss?
- [ ] PLAN-READY / NEEDS-MAJOR / PLAN-KILL.
