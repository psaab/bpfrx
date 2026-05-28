# #1614 Multi-RSS Multi-Core CoS — Plan v1

Status: DRAFT for plan-review round 1.
Branch: `refactor/1614-multi-rss-cos`
Base: `origin/master` @ `6c26c40e6` (#1611 cold-path-flooder runner body)

## 1. Goal

Close the CoS regression empirically captured on `loss:xpf-userspace-fw0/fw1`
that is documented in issue #1614 body + the all-11-class follow-up
comment. The regression is structural and has two independent axes,
both of which the plan addresses:

- **Axis A — scheduler semantics under oversubscription** (PRIMARY,
  fixable inside current AF_XDP per-queue UMEM ownership envelope):
  today's exact-class root drain is approximately pro-rata-by-shape
  (≈19-26% of each shape, scaling with the rate), priority-low
  (`iperf-uncapped`) is completely starved (0 Gbps), and there is no
  guarantee-honoring fallback for small classes. The 100M and 1G
  classes get 20-43% of their *guarantee*, not just their *shape*,
  which is the most surprising failure: a 1 G guarantee is well below
  the 18 G push-direction cluster ceiling, yet only 210 Mbps lands.

- **Axis B — capacity (multi-RSS multi-core distribution)**: even if
  Axis A is perfectly fixed, the push-direction cluster ceiling is
  ~18 Gbps vs 22-23 Gbps reverse. Sum of configured exact-class
  shapes is 109 G (6.1× oversubscription against the push ceiling).
  Distributing high-rate class work across more RSS queues / cores
  should narrow the asymmetry. Mechanisms here resurrect ideas from
  #840 / #1243 / #937 / #1215 but constrained to mechanisms that do
  NOT require mid-flight flow re-steering (see §8 explicit kill-respect
  table).

The plan ships **Axis A first** (independent, no kernel feature
required, fixable inside `userspace-dp/src/afxdp/cos/queue_service/`)
as PR-1. Axis B is decomposed into 3-4 follow-up PRs once Axis A is
stable, each gated on a separate plan-review against the post-Axis-A
baseline.

This plan-review's first job is to **agree or kill on Axis A**. If
reviewers converge "Axis A as proposed cannot achieve the acceptance
criteria", we stop and pivot. Axis B is sketched here for context but
its mechanisms are deferred — each gets its own plan-review against
the Axis-A-fixed baseline so we don't double-count savings.

## 2. Non-goals

- Mid-flight flow re-steering across workers. Closed kill chain:
  #1215 / #837 / #937 / #1238 / #840 / #1243. AF_XDP kernel
  `xsk_rcv_check()` validates `xs->dev == xdp->rxq->dev` and
  `xs->queue_id == xdp->rxq->queue_index`; this design respects it
  unconditionally.
- Re-litigating `Cstruct + 0.05` as the per-flow CoV contract. The
  #1217 contract holds; this work adds a separate per-class
  shape-achievement contract on TOP of #1217, not in place of it.
- Touching `userspace-dp/src/policy/` (#1609 in flight).
- Touching `test/incus/cold-path-flooder/` or the
  `cluster-userspace-host` incus profile (#1615 in flight, sub-agent
  is running).
- Touching `userspace-dp/src/afxdp/poll_stages.rs` per-source
  rate-limit / verdict cache (#1608 v3 parked).
- Touching `pkg/cluster/` HA paths beyond verifying HA failover still
  passes.

## 3. Empirical baseline (as of `6c26c40e6`)

From issue #1614 follow-up comment, 30 s simultaneous all-11-class
load on the loss userspace cluster, push direction via the
`bandwidth-output` filter on `reth0 unit 80` (shape-rate cap 25 G,
push ceiling ≈ 18 G):

| Port | Class | Shape | Achieved | % of shape | % of pro-rata @ 18G | CoV | Retr |
|------|-------|-------|----------|------------|---------------------|------|------|
| 5201 | iperf-100m | 0.1 G | 0.02 G | 20% | 121% (over pro-rata) | 1.8% | 19 |
| 5202 | iperf-1g | 1.0 G | 0.21 G | 21% | 127% | 7.8% | 298 |
| 5203 | iperf-3g | 3.0 G | 0.77 G | 26% | 156% | 8.1% | 369 |
| 5204 | iperf-6g | 6.0 G | 1.43 G | 24% | 144% | 20.2% | 554 |
| 5205 | iperf-9g | 9.0 G | 2.32 G | 26% | 156% | 37.1% | 1366 |
| 5206 | iperf-12g | 12.0 G | 2.84 G | 24% | 143% | 41.5% | 1595 |
| 5207 | iperf-15g | 15.0 G | 2.77 G | 18% | 112% | 30.7% | 1263 |
| 5208 | iperf-18g | 18.0 G | 2.83 G | 16% | 95% | 38.0% | 977 |
| 5209 | iperf-21g | 21.0 G | 3.22 G | 15% | 93% | 40.6% | 1670 |
| 5210 | iperf-24g | 24.0 G | 3.62 G | 15% | 91% | 39.0% | 2119 |
| 5211 | iperf-uncapped | uncap | 0.00 G | — | -100% | 92.5% | 84 |
| Sum  | | 109.1 G | 20.04 G | | | | |

Solo per-class (one at a time): 74-90% of shape, 0-8% CoV. So the
regression is specifically the **simultaneous-load mode**.

Push-direction ceiling solo: 17.9 Gbps best-effort. Reverse direction
(no filter): 22-23 Gbps consistent. Push:reverse asymmetry is ~4-5 G.

### Reading of the scheduler's current behaviour against this data

`userspace-dp/src/afxdp/cos/queue_service/mod.rs` `drain_shaped_tx`
loops by `cos_interface_rr`, then calls
`service_exact_guarantee_queue_direct_with_info` which selects via
`select_exact_cos_guarantee_queue_with_lease_telemetry` using
`exact_guarantee_rr % queue_count`. Each runnable exact queue gets a
service round capped by `cos_guarantee_quantum_bytes(queue)`, which is
rate-proportional (`transmit_rate × COS_GUARANTEE_VISIT_NS` clamped
between `COS_GUARANTEE_QUANTUM_MIN_BYTES` and
`COS_GUARANTEE_QUANTUM_MAX_BYTES`). After all exact queues drain their
guarantee budget, the surplus phase
(`select_cos_surplus_batch_filtered`) iterates by
`queue_indices_by_priority[priority]`. Priority-low (iperf-uncapped) is
in a higher priority numeric value, scanned last; under
oversubscription, root tokens are already gone when surplus phase
reaches it.

The observed approximately-proportional-to-shape distribution
(15-26% of each shape, scaling with rate) is the **rate-proportional
quantum** dividing the 18 G ceiling roughly in proportion to each
queue's `transmit_rate_bytes`. Mathematically: with 10 exact queues
and shape sum 109 G, each class gets roughly `(shape / 109) × 18 G`,
which gives:

| Class | Predicted (shape/109)×18G | Observed | Match? |
|-------|---------------------------|----------|--------|
| 100m | 16.5 Mb/s | 20 Mb/s | yes |
| 1g | 165 Mb/s | 210 Mb/s | yes |
| 3g | 495 Mb/s | 770 Mb/s | within token-bucket noise |
| 6g | 990 Mb/s | 1430 Mb/s | mostly |
| 9g | 1485 Mb/s | 2320 Mb/s | mostly |
| 12g | 1980 Mb/s | 2840 Mb/s | mostly |
| 15g | 2475 Mb/s | 2770 Mb/s | yes |
| 18g | 2970 Mb/s | 2830 Mb/s | yes |
| 21g | 3465 Mb/s | 3220 Mb/s | yes |
| 24g | 3960 Mb/s | 3620 Mb/s | yes |

The deviation on small classes (100m, 1g, 3g, 6g) trends *above*
pro-rata — small classes get a relative boost from the
`COS_GUARANTEE_QUANTUM_MIN_BYTES` floor and from extra refill
rounds during root-token sleeps. So the scheduler is approximately
**pro-rata-by-shape** under oversubscription, which is reasonable
WFQ behaviour but is NOT guarantee-honoring (small classes never
hit their guarantee because the larger classes consume their
proportional share first, even though the larger classes can't
hit their full shape either).

Verification request to reviewers: confirm this reading of
`select_exact_cos_guarantee_queue_with_lease_telemetry` is correct.
If the actual distribution mechanism is different, the rest of the
plan changes.

## 4. Proposed mechanism — Axis A (scheduler semantics)

The single Axis-A PR ships three intertwined sub-mechanisms in
`userspace-dp/src/afxdp/cos/queue_service/mod.rs` +
`userspace-dp/src/afxdp/cos/builders.rs` +
`userspace-dp/src/afxdp/cos/token_bucket.rs`. Order within the PR:

### A1. Guarantee-honoring scheduling under oversubscription

Replace the current single-pass `exact_guarantee_rr` round-robin
with a **two-pass exact-guarantee phase**:

- **Pass 1 (guarantee-only, runs to completion before Pass 2)**:
  iterate exact queues in `exact_guarantee_rr` order. For each
  queue, the per-visit budget is `min(remaining_guarantee_bytes,
  cos_guarantee_quantum_bytes)` where `remaining_guarantee_bytes`
  is the queue's accrued guarantee debt: `transmit_rate × elapsed_ns
  - bytes_drained_this_epoch`. A class with rate 100 M and a 1 ms
  epoch has accrued 100 M × 1 ms / 1e9 ≈ 12.5 KB of guarantee debt
  per epoch; the scheduler must drain this BEFORE giving any visit
  to a higher-rate class. Pass 1 advances `exact_guarantee_rr` only
  when a queue's guarantee debt is fully serviced.

- **Pass 2 (surplus / proportional, runs only after Pass 1 has no
  runnable queue with positive guarantee debt)**: existing
  `select_cos_surplus_batch_filtered` semantics, but with the
  surplus-eligible set EXTENDED to include all exact queues that
  have drained their guarantee in Pass 1 AND have `surplus_sharing`
  flag set (#915 path). Exact queues without `surplus_sharing` are
  capped at their guarantee (current Junos hard-cap behaviour).
  Best-effort (priority-low) is in this pass too, but receives any
  remaining surplus AFTER exact-surplus claimants.

This makes "transmit-rate exact" semantics consistent: when sum of
exact rates < capacity, every exact class hits its rate (today's
solo-class behavior). When sum > capacity, every exact class is
**honored to its rate or pro-rata, whichever smaller** — small
classes which can be honored are honored first; large classes
which can't be honored share what's left proportionally.

The accrued-guarantee-debt computation uses the same
`refill_cos_tokens` mechanism that already exists on
`queue.hot.tokens` (queue token bucket) — no new atomics, no new
per-packet costs. Pass 1 reads `queue.hot.tokens` directly as the
guarantee debt; Pass 2 reads `root.tokens` as the available surplus.

Hot-path cost: Pass 1 is the same loop body as today's
`select_exact_cos_guarantee_queue_with_lease_telemetry` with one
extra `if queue.hot.tokens > 0` check at the head; Pass 2 is
already there. Expected per-iteration cost: +0 ns (one branch
already pred-friendly under saturation).

### A2. Priority-low minimum share (work-conserving)

Priority-low queues (today: iperf-uncapped) get a **configurable
minimum share** when ANY exact queue is in Pass 2 (proportional
surplus). The minimum is implemented as a **token-bucket guarantee**
on the priority-low queue with default rate = `ceiling - sum(exact_rates)`
clamped to a floor of `5% of root.shaping_rate_bytes` per the
#1614 acceptance criterion. Above this floor, priority-low gets all
remaining surplus.

Implementation: introduce a new `priority_low_min_share_bytes` field
on `CoSInterfaceConfig` (Go-side wire field
`priority_low_min_share_bps`), populated from a NEW Junos knob
`set class-of-service interfaces <iface> unit <u> priority-low-min-share <bps|percent>`.
Default value when omitted: `5% of shaping-rate`.

The runtime applies this min-share as a token-bucket replenishment
at refresh-tick cadence; the priority-low queue is admitted to
**Pass 1** (alongside exact-guarantee queues) up to the min-share
rate, then falls back to **Pass 2** (surplus) for anything above.

Wire-protocol both-sides: `pkg/config/cos.go` adds the new field;
`userspace-dp/src/protocol/cos.rs` (note: `CoSInterfaceConfig`
serde shape — exact file path determined during implementation) adds
the matching field with `#[serde(default)]`; cross-version smoke
checks both shapes parse cleanly.

### A3. ECN marking + early-drop before retransmit storm

Today's data shows 1500-2000 retransmits per class per 30 s on
mid-large classes. That's the queue dropping tail packets after
the `buffer_size` admission gate (which already exists in
`userspace-dp/src/afxdp/cos/admission.rs`). The fix is to
**mark ECN-capable flows** when admission depth crosses a
**threshold below the hard drop cap** instead of waiting for
buffer exhaustion to drop. This is RED-style early signaling.

The existing `userspace-dp/src/afxdp/cos/ecn.rs` module
(`apply_cos_admission_ecn_policy`) already has a marking path —
the fix is to lower the **mark threshold** to `~75% of buffer_size`
and increase the mark probability with depth from there. Flows
that don't carry ECT(0)/ECT(1) fall through to tail-drop as today.

Implementation: refactor `apply_cos_admission_ecn_policy` to take
a current-depth parameter and apply WRED-style probability
(linear ramp from p=0 at 75% to p=1.0 at 100%) instead of binary
threshold.

This sub-mechanism is the smallest-LOC of the three but it's the
one that directly attacks the high retransmit count. Retransmits
should drop from 1500-2000 → ≤100 per class per 30 s.

## 5. Proposed mechanism — Axis B (capacity, deferred)

Sketched here for plan-review concurrence on the *direction*; each
ships as its own PR with its own plan-review against the
Axis-A-fixed baseline.

### B1. First-SYN class-affinity placement via XDP redirect-to-queue

When the `xdp_redirect_map` to AF_XDP target supports per-queue
delivery (already true on the mlx5/i40e drivers in use; needs
verification), the userspace shim's first-SYN handler can choose
which RX queue receives the SYN based on per-class load. Existing
flows stay where RSS placed them (no re-steering — kill-respect).

Mechanism: extend `userspace-xdp/src/lib.rs` to maintain a
per-class CPU-MAP. First-SYN gets redirected to the queue with the
lowest current class load via a new `per_class_load[NUM_QUEUES]`
shared map updated 1×/s from userspace.

Plan-review-pending: confirm `bpf_redirect_map(&xskmap, queue_idx, 0)`
with explicit queue_idx works on the kernel + driver combination
we ship (we believe yes; need lab confirmation).

### B2. Cross-worker shared shaper-budget atomic (generalizes #917 V_min)

For exact CoS queues whose flows distribute across multiple
workers, generalize the #917 V_min pattern. Each shared exact queue
already has a `SharedCoSQueueVtimeFloor` Arc per
`coordinator/cos_state.rs:queue_vtime_floors`. The generalization
makes the V_min vtime advance with **bytes consumed across ALL
workers**, not just the current worker's bytes.

Today's pattern (#917) does this for the "shared_exact" queue
variant. B2 extends it to any exact queue whose flow distribution
spans >1 worker for ≥30 s (detected at status-snapshot cadence,
1 Hz). Re-uses `xpf_userspace_cos_active_flow_count` to count
active workers per class.

### B3. RSS table reprogramming on persistent class skew

Resurrect #840's idea, BOUNDED to new flows only. When the
firewall detects a class's active-flow distribution is
concentrated on ≤Nv/2 workers for ≥60 s (live metric:
`xpf_fairness_max_worker_flow_share > 0.5`), reprogram the NIC RSS
indirection table for that class's destination-port range to
distribute new connection hashes across more queues. Existing
flows continue on their bound worker.

Operator-visible: new `show class-of-service rss-rebalance`
showing per-class rebalance history.

### B4. Per-class dedicated cores via XDP CPU-MAP

Resurrect #1243's idea constrained to CPU-MAP assignment of
high-rate exact classes BEFORE RSS. The XDP program inspects
destination-port at first-SYN, looks up the class, and redirects
to the class's dedicated CPU's queue. Existing flows untouched.

This is the largest of the four B mechanisms and only proceeds if
B1+B2+B3 still leave a measurable gap. Plan-review must agree to
this gate explicitly before starting B4.

## 6. Operator-visible warning when shape-sum > ceiling (PR-1 in Axis A)

`pkg/config/cos.go` commit validator emits a WARNING (not error,
not silent) when sum of configured exact-class shape rates >
the interface's `shaping-rate`. Format:

```
warning: class-of-service interfaces <iface> unit <u> exact-rate sum
(<N> G) exceeds shaping-rate (<M> G); during oversubscription,
small classes will be honored first per per-class guarantees.
```

This makes the operator-facing contract explicit: oversubscription
is allowed (Junos does too), but the operator is told.

## 7. Acceptance criteria

Per the issue body + the follow-up comment, the gate for PR-1
(Axis A merge) is:

1. **Simul-load all-11-class smoke**: each exact class hits ≥ its
   configured shape OR ≥ 90% of pro-rata-by-rate, whichever is
   smaller. (today: 15-26% of shape; varies vs pro-rata.)
2. **Priority-low (iperf-uncapped) gets ≥ 5% of cluster ceiling**
   under simul load. (today: 0.)
3. **Per-flow CoV ≤ 10% under simul** on any class with shape ≤
   cluster ceiling. (today: up to 42%.)
4. **Aggregate retransmits ≤ 100 per class per 30 s**. (today:
   1500-2000 on mid-large.)
5. **HA failover unchanged**: `make test-failover` passes at the
   same ~60 ms median.
6. **No regression on existing fairness sweeps**: `Cstruct + 0.05`
   contract from #1217 holds on `fairness-cos-class-sweep.sh` and
   the `--mixed-cos` mode.
7. **Operator warning triggers** on the existing
   `cos-iperf-config.set` fixture (109 G sum > 25 G shaping-rate).

PR-1 is conditionally MERGEABLE on 4-of-4 reviewers (Codex, AGY,
Copilot, Claude SMR) + simul-load smoke gate above. If gate 1 or 3
fails, no merge — sub-mechanism redesign or PLAN-KILL.

## 8. Kill-chain respect (vs closed PLAN-KILLs)

Each closed kill mechanism and how this plan respects it:

| Closed | Killed because | This plan |
|--------|----------------|-----------|
| #1215 (cross-worker shared per-flow signal) | required mid-flight re-steering | Axis A does NO re-steering; B2 only updates shared atomic, no flow movement |
| #837 (cross-worker shared finish-time table) | required mid-flight re-steering | same as above; B2 is finish-time-on-shared-atomic, no re-steering |
| #937 (ingress XDP_REDIRECT) | kernel `xsk_rcv_check` rejects cross-queue delivery | Axis A doesn't touch ingress; B1 uses redirect-to-queue at FIRST-SYN only, RX queue is then bound for flow lifetime |
| #1238 (similar) | same as #1215 | same |
| #840 (RSS indirection rebalance) | broke existing long-lived flows | B3 reprograms RSS for NEW connections only via destination-port matcher; existing flows continue on bound queue |
| #1243 (per-class dedicated cores via uniform multinomial) | uniform multinomial cancellation made win cancel out | B4 combines with B1 first-SYN affinity to make distribution non-uniform — and is the LAST mechanism shipped, gated on B1+B2+B3 not closing the gap |

If reviewers find any of these claims wrong (e.g. B1 actually
requires `xsk_rcv_check` violation), that specific mechanism is
PLAN-KILLED on this round and the plan retreats to the others.

## 9. Hidden invariants (load-bearing)

- **HA sync portability**: per-class core assignment (B4) must
  survive RETH MAC swap on failover. Both chassis must
  independently arrive at the same class-to-core mapping (config-
  driven, not RSS-hash-driven), OR the secondary must re-derive
  on takeover.
- **Generation-counter atomicity** (B3): NIC RSS table update is
  not atomic across queues; existing flows must not be re-hashed.
  Strategy: only reprogram the indirection entries that map to
  the destination-port range of the affected class.
- **Flow placement persistence**: a new flow placed on worker_K
  at first-SYN STAYS on worker_K for its lifetime. Re-steering is
  not allowed even after RSS table reprograms.
- **Cstruct contract preservation**: per-flow CoV gate from #1217
  is unchanged. New per-class shape-achievement gate is additive.
- **Junos compat**: `transmit-rate exact` still means hard upper
  bound when sum < capacity; under oversubscription the new
  semantic is "honor guarantee; cap at rate; surplus per
  surplus-sharing flag". This is consistent with Junos behaviour
  on platforms that support it (verified against documentation;
  no Junos VM available for empirical confirmation).

## 10. Risks + open questions for plan-review

### R1. Pass 1 / Pass 2 accounting may double-count

If a queue services its guarantee in Pass 1 and then is admitted
to Pass 2 surplus on the same drain pass, careful accounting is
needed to avoid double-charging root tokens. Approach: Pass 1
increments a per-pass `guarantee_bytes_consumed` counter; Pass 2
visits subtract this from each queue's available surplus budget.
Reviewers please verify the math is sound.

### R2. Refill cadence vs pass length

The current `refill_cos_tokens` runs on each visit. If Pass 1
takes longer than one refill tick, small classes accumulate
larger guarantee debt than expected, which is good but means
Pass 1 may not "complete" in single-drain semantics. Approach:
treat each `drain_shaped_tx` call as one pass-1+pass-2 cycle
bounded by `COS_GUARANTEE_VISIT_NS` total budget.

### R3. Per-class admission counter contention

`xpf_userspace_cos_active_flow_count` is currently a Prometheus
metric updated at status-snapshot cadence (1 Hz). B2 mechanism
needs it on the hot path; that requires a new shared atomic per
class. Hot-path cost estimate: 1 RMW per drain pass per active
exact class = ~10 RMW/drain on the 109-G fixture = ~1 µs added
latency on the saturated path. Acceptable but reviewers must
agree.

### R4. ECN marking on flows that signal but don't react

If TCP endpoints negotiate ECN but don't react to CE marks, the
WRED-style probability ramp just adds CPU cost with no
back-pressure benefit. Mitigation: keep tail-drop at 100% buffer
as the unconditional fallback. ECN is additive, not replacement.

### R5. Junos compat warning vs error on shape-sum > ceiling

Issue suggests "warning"; reviewers may argue for "error". Plan
keeps it as warning for compat with operators who intentionally
oversubscribe expecting Junos-style WFQ residual; if reviewers
demand error, that's a one-line change.

### R6. Pro-rata math vs actual data

Plan §3 claims "approximately pro-rata-by-shape, with small-class
bonus from quantum floor". If this reading is wrong (e.g. the
actual distribution is being shaped by some OTHER mechanism in
the queue-service code we haven't identified), the entire Axis A
design changes. Reviewers PLEASE verify against the real code
path, not just our model.

### R7. Cluster ceiling vs per-binding ceiling

We've been calling 18 G the "cluster ceiling". It's actually the
push-direction per-RX-queue UMEM-bound limit on the mlx5 VF
passthrough. Reverse goes through a different path and hits 22-
23 G. Confirming whether 18 G is binding-limited (improvable via
Axis B) or wire-limited (not improvable, push direction has a
structural cost like sg/MSS that reverse doesn't) is a separate
question that B4 must answer before starting.

### R8. Test environment confounders

The simul-load measurement runs 11 iperf3 processes ON
`loss:cluster-userspace-host`, a 16-CPU virtio incus container.
At 109 G aggregate generator load, the host itself may be the
bottleneck. Plan must add a sanity check: aggregate reverse on
same fixture (which is 22+ G effortlessly), and per-CPU
utilization of the generator host. If generator CPU is the
bottleneck, the 109-G simul case isn't actually oversubscribing
the firewall, and the data needs re-acquiring on a beefier
generator.

This was flagged in #1611+#1615 work for the cold-path flooder;
the same concern applies here. The plan-review should pause on
this: if R8 isn't ruled out, the entire empirical baseline may
be on shifting sand.

## 11. Test plan

### 11.1 Cargo + Go unit/integration tests

- New tests in `cos/queue_service/tests.rs`:
  - `exact_pass_1_honors_guarantee_before_surplus` — fixture with
    rate(A)+rate(B)+rate(C) > capacity, assert each gets its
    guarantee before any surplus given out.
  - `priority_low_min_share_honored_under_oversubscription` —
    fixture with exact-sum > capacity, assert priority-low gets
    ≥5% of root.
  - `surplus_sharing_exact_queue_admitted_to_pass_2` — verify
    #915 semantics preserved.
  - `ecn_wred_marks_below_drop_cap` — admission depth at 80%
    of buffer marks with non-zero probability, at 50% marks zero.

- 5/5 flake-check on the new tests.
- Full `cargo test --workspace` green.
- `go test ./...` green (covers Go-side new wire field + commit
  validator warning).

### 11.2 Smoke matrix (Pass A + Pass B + NEW Pass C)

- **Pass A** (existing per-class smoke): IPv4 + IPv6 × push +
  reverse × CoS-off + CoS-on, single-class iperf3.
- **Pass B** (existing fairness sweep):
  `fairness-cos-class-sweep.sh` and `fairness-harness.sh
  --mixed-cos`.
- **NEW Pass C (simul-load all-class)**: new harness
  `test/incus/cos-simul-load-smoke.sh`:

  ```bash
  for port in 5201..5211; do
    incus exec loss:cluster-userspace-host -- iperf3 -c 172.16.80.200 \
      -P 12 -t 30 -p $port --json > $ART/sim_$port.json &
  done
  wait
  python3 reduce.py $ART/*.json > $ART/verdict.json
  ```

  Gate verdict.json against:
  - per-class shape achievement ≥ min(shape, pro_rata × 0.9)
  - priority-low aggregate ≥ 5% of root
  - per-class CoV ≤ 10% for classes with shape ≤ ceiling
  - per-class retrans ≤ 100/30s

  This harness becomes part of the canonical smoke matrix
  going forward.

### 11.3 HA failover

- `make test-failover` passes with the same ~60 ms median over 5
  iterations.

## 12. Schedule

- **Plan-review** round 1: now. Expect 3-5 rounds; difficulty bar
  is high (this is the major dataplane work).
- **Implementation** (Axis A): 4-8 hours wall clock once
  PLAN-READY. The bulk is `queue_service/mod.rs` + tests; wire
  field is mechanical; ECN refactor is small.
- **Smoke + merge**: same day as implementation if smoke gates
  pass.
- **Axis B**: separate issues filed post-Axis-A. Filing the
  followups is part of PR-1.

## 13. Out-of-scope acknowledgements

- #1609 multi-stage policy DAG: orthogonal (pre-shaper decision).
- #1608 v3 cold-path: orthogonal.
- #1615 flooder multi-thread virtio: orthogonal but parallel-in-
  flight; do not touch the same files.
- Reverse direction CoV at multinomial floor (38-60%): per #1217
  structural physics, not in scope.

## 14. Doc updates landing in PR-1

- `docs/fairness-regimes.md` — add new section "Multi-class
  oversubscription" between current "Acceptance gates" and
  "Required metrics" describing the new Pass-1/Pass-2 semantics
  and the simul-load Pass-C gate.
- `docs/userspace-jit-design.md` — add new Phase 6 entry
  "CoS scheduler oversubscription semantics" status DONE with
  link to PR-1.
- `docs/cos-traffic-shaping.md` — update the scheduler section
  describing strict-priority semantics with the new two-pass
  flow.
- `userspace-dp/src/afxdp/cos/README.md` (if exists, else
  inline doc in mod.rs) — describe Pass 1 vs Pass 2.

---
## Reviewer checklist (please fill in your verdict round)

Each reviewer (Codex, AGY, Copilot via inline-review, Claude SMR)
must answer:

- [ ] Is the §3 "approximately pro-rata-by-shape" reading of the
  current scheduler correct? If wrong, where?
- [ ] Does Axis A actually fix the §3 data, or does it break Junos
  exact semantics?
- [ ] Are the §8 kill-chain claims correct, or does a mechanism
  resurrect a killed pattern?
- [ ] Is the §10 R8 (generator-bottleneck) concern blocking the
  empirical baseline? If yes, BLOCKED on a remeasure with beefier
  generator.
- [ ] What did this plan miss?
- [ ] PLAN-READY / NEEDS-MAJOR / PLAN-KILL.
