# #1614 Multi-RSS Multi-Core CoS — Plan v2

Status: DRAFT for plan-review round 2.
Branch: `refactor/1614-multi-rss-cos`
Base: `origin/master` @ `6c26c40e6` (#1611 cold-path-flooder runner body)

Supersedes plan v1 (commit `ccf651633`) after convergent NEEDS-MAJOR
from Claude SMR r1 and AGY r1. Codex r1 result pending; if Codex
returns NEEDS-MAJOR with substantively new findings, plan v3 will
fold those in.

## 0. What changed since v1

v1 had three fatal classes of finding flagged by Claude SMR + AGY:

- **F1 (SMR)**: §3 framed current scheduler as "approximately
  pro-rata-by-shape WFQ". AGY math-proved this is **identical**
  to SMR's "rate-proportional-via-quantum" reading under
  saturated work-conserving steady-state: both yield
  `T_i = C × R_i / sum(R_j)`. v2 §3 adopts the cleaner
  rate-proportional framing AND adds the `COS_GUARANTEE_QUANTUM_MAX_BYTES`
  (512 KB) clamp finding both reviews missed.

- **F2 (SMR)**: §10 R8 generator-bottleneck. AGY rebutted with
  the retransmit-overhead-on-generator argument: the 18-20 G
  generator ceiling is *caused by* firewall drops triggering
  high TCP retransmit / cwnd recovery CPU on the generator.
  v2 still requires a reverse-simul check before merging the
  Axis A PR, but no longer treats it as BLOCKED — AGY's
  rebuttal is plausible and the smoke matrix change covers it
  directly.

- **F3 (SMR)**: ECN-WRED 75%-100% ramp. AGY found this is a
  REGRESSION from the existing 33% ECN threshold
  (`userspace-dp/src/afxdp/cos/admission.rs:77-78`); raising it
  would *increase* retransmits, not decrease them. v2 §4 A3 is
  rewritten around the ACTUAL ECN problem: iperf3 default
  flows are NOT-ECT, so the existing 33% mark threshold marks
  zero packets and tail-drops are unavoidable. v2 A3 either
  enables ECN on senders OR adopts CoDel-style time-based AQM
  that affects non-ECN flows too.

- **Axis B3 killed by AGY**: dynamic RSS indirection
  reprogramming reroutes existing flows mid-hash and resurrects
  #840's exact failure. v2 §5 removes B3.

- **Acceptance criterion clarification (AGY F)**: criterion 1
  (pro-rata-by-rate) is ALREADY met at baseline (24g hits 3.62
  vs 3.56 G target). The real broken acceptance is small-class
  **absolute guarantees** (100m gets 20 Mbps when its
  guarantee is 100 Mbps). v2 §7 rewrites criteria to be honest
  about which classes are which problem.

## 1. Problem statement (rewritten)

The dataplane CoS scheduler implements proportional fair sharing
under oversubscription. With shape-sum 109.1 G against a push
ceiling of ~18 G (109/18 = 6.1× oversubscription), each exact class
receives `T_i = C_ceiling × R_i / sum(R_j)`. This is *mathematically
correct* for proportional fairness but is *operationally wrong* for
Junos `transmit-rate exact` semantics:

- **Small classes miss their guarantee absolutely**: 100m class
  receives 20 Mbps when its rate is 100 M; 1g class receives 210
  Mbps when its rate is 1 G. The 100 M and 1 G shapes are well
  below the 18 G ceiling and should be honored absolutely.

- **Priority-low (iperf-uncapped) starves to 0 Gbps**: under
  saturated proportional sharing among exact classes, no root
  tokens reach priority-low. `priority low` ≠ `weight 0`; complete
  starvation breaks control-plane traffic on real deployments.

- **Mid-rate buffer-drop storm**: ~1500-2000 retransmits per class
  per 30 s on mid-large classes. ECN marking exists at 33% (via
  `COS_ECN_MARK_THRESHOLD_NUM/DEN`), but iperf3 default flows are
  NOT-ECT (RFC 3168 §6.1.1.1 protects non-ECN flows from CE
  marking), so the ECN path never fires. Tail-drops at 100%
  buffer cause the retransmit storm.

The §7 acceptance criteria as stated in the issue body are partly
already-satisfied at baseline (pro-rata target). The actually-broken
gates are absolute-guarantee, priority-low min-share, and retrans
floor.

The capacity asymmetry (push 18 G vs reverse 22-23 G) is a separate
concern (Axis B) addressed in a follow-up PR after Axis A.

## 2. Non-goals (unchanged from v1)

- Mid-flight flow re-steering across workers. Closed kill chain:
  #1215 / #837 / #937 / #1238 / #840 / #1243.
- Re-litigating the `Cstruct + 0.05` per-flow CoV contract (#1217).
- `userspace-dp/src/policy/` (#1609 in flight).
- `test/incus/cold-path-flooder/` (#1615 in flight).
- `userspace-dp/src/afxdp/poll_stages.rs` per-source rate-limit
  (#1608 v3 parked).
- `pkg/cluster/` HA paths beyond verifying `make test-failover`
  still passes.

## 3. Verified current scheduler behaviour

AGY r1's math walk on
`userspace-dp/src/afxdp/cos/queue_service/mod.rs:589-718`
(`select_exact_cos_guarantee_queue_with_lease_telemetry`):

- `exact_guarantee_rr` walks runnable exact queues in
  round-robin. Per visit, budget is
  `cos_guarantee_quantum_bytes(queue) =
  min(max(rate × COS_GUARANTEE_VISIT_NS / 1e9,
  COS_GUARANTEE_QUANTUM_MIN_BYTES),
  COS_GUARANTEE_QUANTUM_MAX_BYTES)` per
  `userspace-dp/src/afxdp/tx/drain/mod.rs:561,563`.
- `COS_GUARANTEE_VISIT_NS = 200_000` (200 µs).
- `COS_GUARANTEE_QUANTUM_MAX_BYTES = 512 * 1024` (512 KB).

Computed quantum per class:

| Class | Rate (Gbps) | Quantum unclamped | Quantum clamped |
|-------|-------------|-------------------|-----------------|
| 100m  | 0.1 | 2.5 KB | 2.5 KB |
| 1g    | 1.0 | 25 KB | 25 KB |
| 3g    | 3.0 | 75 KB | 75 KB |
| 6g    | 6.0 | 150 KB | 150 KB |
| 9g    | 9.0 | 225 KB | 225 KB |
| 12g   | 12.0 | 300 KB | 300 KB |
| 15g   | 15.0 | 375 KB | 375 KB |
| 18g   | 18.0 | 450 KB | 450 KB |
| 21g   | 21.0 | 525 KB | **512 KB (CLAMPED)** |
| 24g   | 24.0 | 600 KB | **512 KB (CLAMPED)** |

The clamp explains why 21g and 24g receive nearly identical
baseline throughput (3.22 G vs 3.62 G — variance from token-bucket
phase, not steady-state mean): they have IDENTICAL per-visit
quantum despite differing configured rates.

Steady-state throughput (saturated, work-conserving) for queue i:
`T_i = C × Q_i / sum(Q_j)`. For the 10-exact-queue fixture:

| Class | Quantum (KB) | Predicted (C=18G) | Observed |
|-------|--------------|--------------------|----------|
| 100m  | 2.5  | 18 G × 2.5/2400 ≈ 18.75 Mbps | 20 Mbps |
| 1g    | 25   | 187.5 Mbps | 210 Mbps |
| 3g    | 75   | 562.5 Mbps | 770 Mbps |
| 6g    | 150  | 1.125 Gbps | 1.43 Gbps |
| 9g    | 225  | 1.69 Gbps | 2.32 Gbps |
| 12g   | 300  | 2.25 Gbps | 2.84 Gbps |
| 15g   | 375  | 2.81 Gbps | 2.77 Gbps |
| 18g   | 450  | 3.38 Gbps | 2.83 Gbps |
| 21g   | 512  | 3.84 Gbps | 3.22 Gbps |
| 24g   | 512  | 3.84 Gbps | 3.62 Gbps |
| sum   | 2400 | 18 G | 20 G (≈ ceiling) |

Small-class deviation (predictions undershoot for 100m-9g,
overshoot for 18g-24g) is the `COS_GUARANTEE_QUANTUM_MIN_BYTES`
floor lifting small classes slightly above linear prediction. The
overall fit confirms: the current scheduler is a **proportional-
fair / rate-proportional-quantum DRR**.

This is **not a bug** for a proportional-fair scheduler. It IS a
bug for Junos `transmit-rate exact` contract, which says: "honor
guarantee up to rate; under oversubscription, smaller guarantees
that fit are honored absolutely."

## 4. Proposed mechanism — Axis A (scheduler semantics)

Three intertwined sub-mechanisms. Order within the single Axis A
PR:

### A1. Junos-style guarantee-honoring under oversubscription

Replace the current single-pass `exact_guarantee_rr` proportional
RR with a **two-pass exact-guarantee phase**:

- **Pass 1 (absolute guarantee)**: iterate exact queues in
  `exact_guarantee_rr` order. Per visit, the budget is
  `min(remaining_guarantee_per_epoch, per_visit_quantum_unclamped)`
  where `remaining_guarantee_per_epoch = R_i × epoch_ns / 1e9 -
  bytes_sent_this_epoch`. Pass 1 advances the cursor only when the
  current queue's per-epoch guarantee is fully serviced OR the
  queue has no more pending work.

- **Pass 2 (proportional surplus)**: the existing
  `select_cos_surplus_batch_filtered` path, restricted to:
  - exact queues with `surplus_sharing == true` (#915 path)
  - non-exact queues (best-effort + priority-low)

Under the 109 G shape sum / 18 G ceiling fixture, Pass 1 services
guarantees in order: 100m (0.1 G), 1g (1.1 G cumulative), 3g (4.1
G), 6g (10.1 G), 9g (19.1 G). Pass 1 stops servicing at the
ceiling — 9g class gets ~7.9 G of its 9 G guarantee (88%). All
larger classes (12g-24g) get **nothing** from Pass 1.

This is correct Junos semantics under oversubscription per
documented vSRX behaviour, but it's not what the user data shows
the current cluster doing, and it's a significant operator-visible
change in distribution. To avoid catastrophic large-class
starvation, **Axis A also ships a config-driven knob to choose
between**:

- **`guarantee-honoring`** (new default for new configs):
  Pass-1-then-Pass-2 as above. Small classes get absolute
  guarantee; large classes get only what Pass 2 surplus
  distributes among `surplus_sharing` queues.

- **`proportional`** (current behaviour preserved for existing
  configs): current rate-proportional DRR. Small classes
  under-deliver; large classes get proportional share.

The mode is selectable via a new Junos knob
`set class-of-service interfaces <iface> unit <u>
oversubscription-policy {guarantee-honoring | proportional}`.
Default for new configs is `guarantee-honoring` (Junos-consistent).
Default for existing configs without the knob is `proportional`
(current behaviour, no surprise during upgrade).

Per-epoch counter implementation: `queue.hot.tokens` already
implements per-queue rate accumulation; we add a sibling
`queue.hot.guarantee_bytes_this_epoch` field that the Pass-1 path
decrements as it services. The epoch length is `COS_GUARANTEE_VISIT_NS
× num_exact_queues` (one full RR cycle), set per-drain-pass.

Hot-path cost: Pass 1 is the same loop body as today with one
extra `if guarantee_bytes_this_epoch > 0` check; expected +0 ns on
the saturated path.

### A2. Priority-low minimum share (work-conserving)

Add a configurable minimum share for priority-low queues. Default
is **5% of the interface's `shaping-rate`**, justified per AGY:
control-plane preservation (SSH, NTP, ARP, DNS, BGP keepalive).
Operators can tune.

Mechanism: priority-low queues are admitted to **Pass 1** alongside
exact-guarantee queues up to their min-share rate. Above min-share,
they fall back to **Pass 2** surplus.

Implementation:
- New `priority_low_min_share_bytes` field on `CoSInterfaceConfig`,
  populated from a new Junos knob
  `set class-of-service interfaces <iface> unit <u>
  priority-low-min-share <bps|percent>`.
- Default value: 5% of `shaping-rate` (computed at config-compile
  time, not runtime).
- Wire field both-sides:
  - Go: `pkg/dataplane/userspace/protocol.go` (or wherever the
    `CoSInterfaceSnapshot` lives — to be confirmed at
    implementation time) adds the field with the matching
    serde tag. Reverse-compat: omit emits `0`.
  - Rust: `userspace-dp/src/protocol/` matching field with
    `#[serde(default)]`.

The min-share is realized via Pass-1 admission, NOT a separate
token bucket; this avoids duplicating bucket state and keeps the
mechanism aligned with how exact queues compete.

### A3. CoDel-style time-based AQM for retransmit floor (rewritten)

v1 proposed raising ECN threshold to 75%. AGY noted this is a
REGRESSION from current 33% (`COS_ECN_MARK_THRESHOLD_NUM/DEN` in
`userspace-dp/src/afxdp/cos/admission.rs:77-78`). v2 keeps ECN at
33% **and addresses the actual root cause of high retransmits**:

The current ECN path only marks ECT(0)/ECT(1) frames; iperf3
default flows are NOT-ECT. So the existing 33% threshold marks 0
packets in the fixture. The retransmit floor of 1500-2000 per
class per 30 s is from unmarkable tail-drops at 100% buffer.

Two complementary mechanisms:

- **A3a (mandatory)**: add CoDel-style sojourn-time AQM. When the
  oldest packet in a queue has been queued for >5 ms (CoDel
  default target), drop it (or mark if ECT). The 5 ms target is
  RFC 8290 baseline and the standard Linux CoDel default. This
  mechanism drops non-ECN flows too, providing back-pressure to
  iperf3 default flows.

  Hot-path cost: one extra `now_ns - packet.enqueue_ns > 5ms`
  branch on the dequeue path. Already O(1).

- **A3b (operator-visible test enablement)**: the simul-load
  smoke test must enable `iperf3 --ecn` (TBD: confirm iperf3
  supports `--ecn` flag — if not, use `setsockopt(IP_TOS,
  ECT(0))` wrapper). This validates the ECN path end-to-end.

Both mechanisms together should bring retrans ≤ 100 per class
per 30 s; CoDel handles the bulk drop reduction; ECN handles
TCP_ECN-capable flows with milder mark-not-drop signaling.

Implementation:
- `userspace-dp/src/afxdp/cos/admission.rs` gains an
  `enqueue_ns` field on each queued item (already exists per
  recent refactor — confirm at implementation time, else add).
- Dequeue path checks `now_ns - oldest.enqueue_ns > CODEL_TARGET_NS`
  (CODEL_TARGET_NS = 5_000_000) and drops if so. ECN flows get
  marked instead per the existing 33% rule.
- New const `CODEL_TARGET_NS: u64 = 5_000_000`.

### A4. Operator-visible warning when shape-sum > shaping-rate

Same as v1. `pkg/config/cos.go` commit validator emits a
WARNING when sum of exact-class shape rates exceeds
`shaping-rate`. Adds a unit test in `pkg/config/cos_test.go`.

## 5. Proposed mechanism — Axis B (capacity, deferred, with B3 KILLED)

Each Axis B mechanism ships as a separate follow-up issue with
its own plan-review against the Axis-A-fixed baseline.

### B1. First-SYN class-affinity placement via XDP CPU-MAP

AGY r1 flagged B1 as "SUSPECT" because `xsk_rcv_check` enforces
queue binding on subsequent packets. The mechanism must be
restricted to:

- The first-SYN packet (only) is redirected via XDP CPU-MAP to
  a class-affined CPU.
- The kernel then steers the connection's RSS hash to that CPU
  ONLY IF the NIC's flow steering supports per-flow override
  (e.g., ethtool ntuple rules on mlx5).
- WITHOUT NIC flow steering support, B1 cannot work — the
  second packet hashes to RSS queue X but the connection's
  socket lives on queue Y, and the kernel drops on the
  mismatch.

Conclusion: B1 is BLOCKED-on-kernel/NIC-support and requires
lab verification on the mlx5 VF driver before it can be planned.
File a separate investigation issue.

### B2. Cross-worker shared shaper-budget atomic (extends #917 V_min)

Generalize the #917 V_min Arc pattern (per
`userspace-dp/src/afxdp/coordinator/cos_state.rs:queue_vtime_floors`)
to any exact queue whose flow distribution spans >1 worker.

Mechanism: when a class's `xpf_userspace_cos_active_flow_count`
metric shows >1 active worker for ≥30 s, allocate a per-class
`SharedCoSQueueVtimeFloor` Arc and have all workers consult the
shared bucket before sending. The shared bucket replenishes at
the class's `transmit_rate`.

This is the cleanest extension of an already-shipped pattern and
ships as its own follow-up.

### B3. RSS table reprogramming on persistent skew — KILLED

AGY r1 audited this as DOA: NIC RSS indirection table changes
re-hash existing flows mid-flight, violating `xsk_rcv_check`
and dropping active connections. Resurrects #840's exact
structural failure.

Removed from the Axis B roadmap. If a future redesign restricts
RSS reprogramming to NEW-connection-only via
destination-port-range matching with cooperation from the NIC
flow steering hardware, that's a different mechanism with a
different plan-review.

### B4. Per-class dedicated cores via XDP CPU-MAP

Same as v1: gated on B1 + B2 not closing the gap. Requires lab
verification of XDP CPU-MAP + per-class CPU assignment under HA.

## 6. Hidden invariants (load-bearing)

- **HA sync portability**: any per-class core / queue assignment
  must survive RETH MAC swap on failover. Config-driven mapping
  (not RSS-hash-driven) so both chassis derive the same mapping.
- **Cstruct contract preservation**: per-flow CoV gate from
  #1217 is unchanged. The new per-class shape-achievement gate
  is additive.
- **Junos compat**: `transmit-rate exact` under oversubscription
  is now operator-selectable between `guarantee-honoring`
  (Junos-style) and `proportional` (current). Existing configs
  default to `proportional` to avoid upgrade surprise.
- **ECN protection of NOT-ECT**: never mark a NOT-ECT packet
  (RFC 3168 §6.1.1.1). CoDel drops instead for those flows.
- **Wire-protocol additive-only**: new Go struct fields default
  to 0 on absence; new Junos knobs default to behaviour-preserving
  values.

## 7. Acceptance criteria (rewritten per AGY F)

Per AGY F: criterion 1 ("≥ 90% of shape OR ≥ 90% of pro-rata") is
**already met** at baseline for all classes. The actually-broken
gates are:

1. **Absolute small-class guarantee under oversubscription**
   (when `guarantee-honoring` mode is selected): for classes whose
   cumulative-shape ≤ ceiling, each class hits ≥ 95% of its
   configured rate. With the 109 G / 18 G fixture and
   `guarantee-honoring`:
   - 100m: hits ≥ 95 Mbps (today: 20 Mbps)
   - 1g: hits ≥ 950 Mbps (today: 210 Mbps)
   - 3g: hits ≥ 2.85 G (today: 770 Mbps)
   - 6g: hits ≥ 5.7 G (today: 1.43 G)
   - 9g: hits ≥ 7 G (today: 2.32 G; full 9 G unachievable since
     cumulative 19 G > 18 G ceiling)
   - 12g-24g: get only Pass 2 surplus; aggregate ≥ 0 G is
     acceptable since these classes' guarantees are
     unfulfillable in oversubscription.

2. **Priority-low (iperf-uncapped) gets ≥ 5% of cluster ceiling**
   when both modes are active. Today: 0 Gbps.

3. **Per-class retrans ≤ 100 per 30 s under simul** (today:
   1500-2000 on mid-large classes). Achieved by A3 CoDel.

4. **Per-flow CoV ≤ Cstruct + 0.05** per #1217 contract,
   unchanged. New per-class shape-achievement gate is additive.

5. **HA failover unchanged**: `make test-failover` passes at
   ~60 ms median over 5 iterations.

6. **`proportional` mode preserves current behaviour**:
   regression test that a config without the new knob produces
   the same per-class distribution as master HEAD on the
   109 G / 18 G fixture (within token-bucket noise, ±10%).

7. **Operator warning triggers** on the existing
   `cos-iperf-config.set` fixture (109 G > 25 G).

8. **R8 sanity check**: reverse-simul (all 11 classes
   reverse-direction in parallel) reaches aggregate ≥ 18 G on
   the same generator. If it doesn't, the generator IS the
   bottleneck and the entire baseline needs re-measurement on
   a beefier generator (BLOCKED, file follow-up).

PR-1 is conditionally MERGEABLE on 4-of-4 reviewers (Codex, AGY,
Copilot, Claude SMR) + gates 1, 2, 3, 5, 6, 7, 8 above passing on
loss userspace cluster smoke.

## 8. Kill-chain respect (vs closed PLAN-KILLs) — updated

| Closed | Killed because | This plan |
|--------|----------------|-----------|
| #1215 | required mid-flight re-steering | Axis A does NO re-steering; B2 only updates shared atomic |
| #837  | required mid-flight re-steering | same as above |
| #937  | `xsk_rcv_check` cross-queue delivery | Axis A doesn't touch ingress; B1 is BLOCKED on NIC flow steering support |
| #1238 | similar to #1215 | same |
| #840  | RSS reprogramming broke long-lived flows | **B3 KILLED in v2** (AGY r1) |
| #1243 | uniform multinomial cancellation | B4 still on the table but gated on B1+B2; not in v2 scope |

## 9. Risks + open questions for plan-review

### R1. Pass-1 epoch boundary semantics

Pass 1 tracks `guarantee_bytes_this_epoch` and resets each
`COS_GUARANTEE_VISIT_NS × num_exact_queues` epoch. If the epoch
length is mis-tuned, Pass 1 either drains insufficient
guarantee per epoch (small classes still starve) or hogs root
tokens preventing Pass 2. Plan: instrument
`xpf_userspace_cos_pass1_guarantee_satisfied_total` and
`xpf_userspace_cos_pass2_surplus_bytes_total` so operators can
tune.

### R2. CoDel target tunability

5 ms is the Linux CoDel default. Some operators may want longer
(e.g., satellite WAN with 200 ms RTT). Plan: make
`CODEL_TARGET_NS` per-queue configurable via Junos knob
`set class-of-service schedulers <name> codel-target <ms>`.
Default 5 ms.

### R3. R8 generator-bottleneck remeasurement gate

AGY argues the generator saturation is *caused by* firewall
drops. v2 makes this testable: gate 8 above requires reverse-simul
≥ 18 G aggregate on same generator. If reverse-simul ALSO caps at
~18 G, the firewall is innocent and the entire baseline needs
remeasurement.

### R4. Wire-protocol both-sides

New Go fields: `priority_low_min_share_bytes`,
`oversubscription_policy`, `codel_target_ns`. Need confirmation
of exact file paths (`pkg/dataplane/userspace/protocol.go` and
`userspace-dp/src/protocol/cos.rs` are the candidates) at
implementation time. Reviewers please flag if wrong.

### R5. `guarantee-honoring` mode and large-class disengagement

Under `guarantee-honoring` on the 109 G fixture, classes 12g-24g
get only Pass 2 surplus (proportionally split). If TCP cwnd
collapses on those classes from sustained 0-bps periods,
recovery may be slow. Plan: explicitly validate cwnd behavior on
large classes during the smoke run.

### R6. iperf3 `--ecn` flag verification

Need to confirm iperf3 supports `--ecn` or equivalent. If not,
the smoke harness wraps iperf3 with `setsockopt(IP_TOS, ECT(0))`.

### R7. Pass 2 with mixed exact-surplus-sharing + non-exact

Pass 2 currently iterates by priority level. With Pass-1
honoring eating most of root tokens, Pass 2 has limited surplus.
Need to verify Pass 2 distributes that surplus among
`surplus_sharing` exact + best-effort + priority-low in a sane
order. Plan: priority-low gets min-share first (gate 2 above),
then surplus_sharing exact, then best-effort.

## 10. Test plan

### 10.1 Cargo + Go unit/integration tests

- New tests in `userspace-dp/src/afxdp/cos/queue_service/tests.rs`:
  - `pass1_honors_small_class_guarantee_before_pass2_starts`
  - `pass1_stops_at_root_token_starvation_and_pass2_resumes`
  - `priority_low_admitted_to_pass1_at_min_share`
  - `proportional_mode_preserves_master_distribution` (regression
    against today's behaviour)
  - `codel_drops_nonECT_after_5ms_sojourn`
  - `codel_marks_ECT_after_5ms_sojourn_within_33pct_threshold`
- New tests in `pkg/config/cos_test.go`:
  - `commit_warns_when_shape_sum_exceeds_shaping_rate`
- 5/5 flake-check on all new tests.
- Full `cargo test --workspace` green.
- `go test ./...` green.

### 10.2 Smoke matrix Pass A + Pass B + NEW Pass C + NEW Pass D

- **Pass A** (existing per-class single-class smoke).
- **Pass B** (existing fairness sweep).
- **NEW Pass C — simul-load all-11-class push**: 30 s, all 11
  classes parallel, push direction. Gate per §7 criteria 1, 2, 3.
- **NEW Pass D — simul-load all-11-class reverse**: 30 s, all
  11 classes parallel, REVERSE direction (R8 sanity check). Gate
  per §7 criterion 8 (aggregate ≥ 18 G).

Harness: new `test/incus/cos-simul-load-smoke.sh` plus a Python
reducer that computes per-class shape achievement + CoV + retrans
+ aggregate. Becomes permanent member of the smoke matrix.

### 10.3 HA failover

`make test-failover` passes at ~60 ms median over 5 iterations.

### 10.4 Backward-compat regression

Apply the current `test/incus/cos-iperf-config.set` (which
doesn't have the new knobs) and verify Pass C distribution
matches master HEAD within ±10% per-class (i.e., `proportional`
mode is the default and unchanged).

## 11. Schedule

- Plan-review round 2: now. With v2's significantly tightened
  framing, expect 1-2 more rounds.
- Implementation (Axis A): ~6-10 hours wall clock. A1 + A2 are
  the bulk; A3 CoDel is small; wire fields mechanical.
- Smoke + merge: same day if smoke gates pass.
- Axis B: filed as follow-up issues post-Axis-A. B3 explicitly
  killed. B1 BLOCKED on NIC flow steering verification.

## 12. Doc updates landing in PR-1

- `docs/fairness-regimes.md` — new section "Multi-class
  oversubscription policy" describing Pass 1 / Pass 2 +
  `guarantee-honoring` vs `proportional` + the simul-load Pass-C
  / Pass-D gates.
- `docs/userspace-jit-design.md` — add Phase 6 entry "CoS
  scheduler oversubscription semantics" linking PR-1.
- `docs/cos-traffic-shaping.md` — update scheduler section with
  the two-pass flow.
- `userspace-dp/src/afxdp/cos/README.md` (or inline doc) —
  describe Pass 1 vs Pass 2 + CoDel.

---

## Reviewer checklist round 2

- [ ] Does §3 (rate-proportional + 512 KB clamp) correctly
  characterize the current scheduler?
- [ ] Does A1 (Pass-1 guarantee-honoring + mode knob) honour
  Junos `transmit-rate exact` semantics?
- [ ] Is A2 (priority-low min-share at 5%) sufficient and
  configurable?
- [ ] Does A3 (CoDel + ECT preservation) actually reduce
  retransmits to ≤100/30s? Show math.
- [ ] Is B3 KILL final in v2 (or does some restricted form
  survive)?
- [ ] §7 criterion 8 (reverse-simul ≥ 18 G) — is this the right
  gate to rule out R8?
- [ ] What did v2 miss?
- [ ] PLAN-READY / NEEDS-MAJOR / PLAN-KILL.
