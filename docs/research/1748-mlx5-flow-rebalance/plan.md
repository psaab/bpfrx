# Research plan — #1748 Cross-worker per-flow REBALANCE (re-steer of established flows) on mlx5 VFs

- **Revision**: r2 (CONVERGED). Round-1: Codex + Claude SMR PLAN-READY-kill, AGY PLAN-KILL-OVERTURNED. Round-2: all three converge on **PLAN-NEEDS-WORK (overturn correct, R1-spike gate)**.
- **Status**: **PLAN-NEEDS-WORK → scoped feasibility-prototype** for Path 2 (ntuple HW re-pin), gated on the R1 spike. Kill WITHDRAWN. NOT yet PLAN-READY-to-ship.
- **Converged verdicts**: Codex r2 = PLAN-NEEDS-WORK (overturn correct, R1-spike gate); AGY r2 = PLAN-NEEDS-WORK (overturn correct, R1-spike gate); Claude SMR r2 = PLAN-NEEDS-WORK (kill withdrawn, R1-spike gate).
- **Skill**: `/research` (research-only; stop at PLAN-READY or PLAN-KILL; no code; docs only)
- **Issue**: #1748 (label `perf`)
- **Worktree**: `.claude/worktrees/1748-mlx5-flow-rebalance`, branch `research/1748-mlx5-flow-rebalance`
- **Base**: origin/master @ `ecdc16f2e`

---

## 0. What changed in r2 (the load-bearing finding)

r1 proposed PLAN-KILL on two walls. **Codex + Claude SMR ratified the kill;
AGY overturned it** by falsifying Wall B with quoted code, and I independently
verified AGY's claims against master. The verification stands:

- **Wall A still holds** (XDP_REDIRECT path dead): `xsk_rcv_check()` enforces
  `xs->queue_id == xdp->rxq->queue_index`; mlx5 native XDP / `ndo_xdp_xmit` /
  CPUMAP do not bypass. Codex re-cited current 7.x source; the shim encodes it
  at `userspace-xdp/src/lib.rs:1364`. Path 1 (XDP_REDIRECT) and Path 3 (hybrid)
  are permanently blocked. **Conceded by all three reviewers.**

- **Wall B is FALSIFIED for the same-node, active-node case** (Path 2, ntuple
  re-pin). The original Wall-B claim ("re-steer strands the session, splits
  conntrack, creates a duplicate on the cold worker") is materially wrong on
  this dataplane, because the HA session-replication machinery already
  pre-installs a *forwarding-ready* replica of every session on every sibling
  worker:

  - **Forward AND reverse entries are replicated to all peer workers on
    creation** — `replicate_session_upsert(worker_ctx.peer_worker_commands,
    &forward_entry)` (`poll_descriptor/mod.rs:1267`) and the reverse companion
    via `replicate_session_upsert(peer_worker_commands, &reverse_entry)`
    (`shared_ops.rs:618`).
  - **The receiving worker re-resolves with LOCAL egress** in
    `handle_upsert_synced` (`session_glue/commands/upsert_synced.rs`): doc
    comment "By resolving on receipt (even on standby), sessions are
    immediately forwarding-ready." The replica origin is
    `SessionOrigin::WorkerLocalImport` (`shared_ops.rs:51` →
    `worker_replica_origin()`; test `tests.rs:473`), which
    `is_peer_synced() == true`.
  - **The active-node packet path has NO per-worker ownership gate.**
    `enforce_ha_resolution_snapshot` (`forwarding/mod.rs:524`) and
    `owner_rg_is_locally_active` (`session_glue/mod.rs:137`) gate forwarding on
    the **owner RG being forwarding-active on this node** — never on *which
    worker* holds the session. So any worker on the active node can forward any
    session whose RG is locally active. A re-steered packet on worker 5 misses
    the flow cache once, finds the pre-replicated locally-resolved session in
    its `SessionTable`, passes HA enforcement, and forwards. No duplicate, no
    split conntrack.
  - **Organic handoff via local GC**: local expiration
    (`worker/loop_body/mod.rs`) does NOT broadcast deletes, so worker 2's stale
    copy ages out while worker 5's copy stays alive on the new stream — zero
    cross-worker locks (consistent with the `flow_cache.rs:143` shared-nothing
    non-goal, which is about the per-tick hot path, not this slow handoff).
  - **CoS rate-estimator skip-ramp** (`cos/fairness.rs:93`) initializes
    `observed_bps` from `inst_bps` on the first post-idle sample, so the moved
    flow's scheduling state converges immediately on worker 5.

  **This is a genuine research discovery: #1649 forbade re-steer "by fiat",
  and that fiat hid the fact that the HA replication substrate already makes a
  same-node worker handoff safe.** The mlx5 ntuple primitive (exact-5-tuple →
  RX-queue, cap 1024, ~1 ms/rule, verified #1649 + re-probed this session)
  provides the steering mechanism; the session substrate provides the safe
  landing. Path 2 is therefore NOT killable on Wall B.

This plan is rewritten as a **scoped feasibility-prototype** for Path 2, with
the real remaining risks (which AGY underweighted) called out honestly so the
user can decide whether to fund the prototype.

## 1. Problem statement (unchanged)

Per-flow CoV 14–29% on `-P12` shaped ports from RSS flow-count imbalance across
the 6 VF workers (1-flow worker → ~1.8 G/flow, 4-flow → ~0.87 G/flow). A rate
**cap** (#1746 equal-flow) only clips fast flows down; it cannot lift slow
flows because the spare capacity is on a different worker's queue. The only
mechanism that lifts slow flows without aggregate loss is moving an established
flow off an overloaded worker onto an idle one — cross-worker rebalance. #1748.

## 2. Hardware capability (verified — see r1 §2, re-probed 2026-06-01)

`ge-0-0-2` = mlx5_core VF, kernel 7.0.0-rc7+, 6 combined RX queues, ntuple
togglable, rule cap 1024 (#1649 probed to exhaustion), ~1 ms/rule firmware
cost. Exact-5-tuple and masked-residue steering both accepted (#1649). Daemon
already has an `ethtool -X` RSS-programming abstraction (`rssExecutor`,
`pkg/daemon/rss_indirection.go`) with mlx5-allowlist guards — a precedent for
adding `ethtool -N` ntuple programming on the same plumbing.

## 3. Recommended mechanism — Path 2: reactive ntuple HW re-pin

When a controller detects worker load imbalance, install an exact-5-tuple
`ethtool -N` rule mapping a chosen long-lived flow's 5-tuple → the least-loaded
worker's RX queue. The flow's future packets steer to the new RX queue, where
the pre-replicated session is already forwarding-ready (§0). No mid-flight
state migration code is required (the substrate exists); the new code is the
**controller + ntuple programming + HA mirroring + safety bounds**.

Why Path 2 and not Path 1/3: Path 1/3 require XDP_REDIRECT across RX queues,
which Wall A permanently blocks. Path 2 changes the *hardware* steering
upstream of `xsk_rcv_check`, so the packet legitimately arrives on the target
queue's socket and the check passes.

## 4. The genuinely-open risks (must be resolved in the prototype — AGY underweighted these)

AGY's "no code changes needed, just turn it on" is too strong. The session
substrate is ready, but a *shippable* rebalancer must close these:

### R1. Does it actually beat the floor, or did #1203/#789 already prove it doesn't?
#1649's converged multinomial theorem says *static* placement = RSS floor
(CoV ≈ 0.87 at N=6 M=6 for ephemeral ports; Codex independently exact-
enumerated 6^6 → E[CoV]=0.8740). Path 2 is **reactive**, not static — it
*observes occupancy and moves the offending flow*, which is exactly the
negative-dependence the theorem says only a reactive controller can create. BUT
#1203/#789 *built and measured a reactive closed-loop placement controller on
this exact cluster and got 49–55% CoV at P=12* (gate ≤20% not met), closing
with "per-flow CoV is bounded by within-queue scheduling, not placement." The
prototype's FIRST gate must answer: was #1203's 49–55% a property of placement
itself (→ Path 2 also fails the gate → KILL), or of #1203's specific controller
design / convergence speed / hysteresis (→ Path 2 with a better controller may
clear it)? This requires reading the #1203 controller (`feature/1215-...`
branch) and either reproducing its limit or identifying the fixable defect.
**If R1 shows placement itself is floor-bound, Path 2 is killed here** — and
this is the most likely kill point.

**Decisive disambiguating evidence found in r2 (Codex):** the #789 work tree
holds TWO contradictory data points on the SAME cluster:
- `refactor/789-fairness-via-ntuple:docs/pr/789-fairness-via-ntuple/findings-experiment-1.md`
  — *manual* exact mlx5 ntuple rules dropped per-flow CoV **62.5% → 3.8%** on
  iperf-c P=12 (12 flows within ±5% of mean), concluding "within-worker
  fairness is excellent; the 62.5% baseline is dominated by CROSS-worker
  variance, not within-worker scheduling." Aggregate dropped 24% only because
  the crude port-bitmask scheme idled 3 queues — not a mechanism cost.
- `refactor/789-phase2-byte-rate:docs/pr/789-phase2-byte-rate/plan.md` — the
  *closed-loop controller* reached only **49–55% CoV** while "correctly driving
  each queue to 2 flows."

The contradiction localizes R1's risk precisely: **the placement MECHANISM is
not floor-bound (manual = 3.8%); the #1203 CONTROLLER was the limiter.** R1's
job is to confirm the manual 3.8% reproduces for *established-flow exact re-pin*
(not just connect-time placement) and then identify why the closed-loop
controller regressed to 49–55% (convergence lag? re-steer-during-flight churn?
hysteresis? the very Wall-B transient R3?). This makes the spike high-value:
it is likely to *pass* the mechanism check and turn the work toward fixing the
controller, OR to reveal that established-flow re-pin specifically (vs
connect-time placement) hits the 49–55% wall — either is a clean decision.

**Root cause of the #1203 controller regression (AGY r2, quoted PR history):**
the #1203 controller flattened per-queue *flow count* only
(`pr-history.md:19239`) and **deferred byte-rate-aware candidate selection to
Phase 2** because it added a per-packet cache-line write to the worker hot path
(`pr-history.md:19283`). An even *count* partition (2,2,2,2,2,2) still yields
high CoV when one flow is a 3 Gb/s elephant and its queue-mate is a mouse. So
the 49–55% was a **count-blind controller defect**, not a placement-physics
floor. R1's controller-side requirement is therefore concrete: candidate
selection must be **byte-rate aware** (move the flow whose transfer most
flattens the per-worker *byte-rate*, not flow-count), which re-opens the
hot-path-telemetry-write cost question #1203 deferred. This is the substance the
follow-on controller design (post-R1) must solve.

### R2. Reverse direction is not moved.
Re-pinning the forward 5-tuple does not move the reverse flow (server→client),
which RSS-hashes independently to a possibly-different worker. For a push test
the forward direction carries the data, so forward-only re-pin may suffice for
the throughput-CoV symptom — but `-R` (reverse) tests and bidirectional
workloads need the reverse rule too, doubling rule consumption and adding a
second steering decision. The prototype must measure both push and `-R`
(per `feedback_smoke_push_and_reverse`).

### R3. Transient correctness window.
Between rule install (~1 ms firmware) and the old worker's in-flight TX
draining, packets of the same flow can briefly arrive on BOTH workers
(reordering risk) or the flow-cache on worker 5 is cold (one-time miss → slow
path). Must verify no TCP reset and bounded reordering under a real transfer
(bpftrace on `xdp:xdp_redirect_err` is NOT the right tool here — packets are
not redirected, they are HW-steered — so verify via per-worker RX counters +
iperf3 retransmit count).

### R4. HA double-homing.
A moved flow must steer to the matching worker on BOTH cluster nodes or
session-sync's reverse-companion resolution diverges. The ntuple rule must be
mirrored to the peer node's NIC (peer uses `ge-7-0-1`/`ge-7-0-2`, same mlx5
model). Cross-node RSS placement differs, so "matching worker" means matching
*queue index* — the controller must program identical (5-tuple → queue) rules
on both nodes and verify the peer's worker N holds the replica (it does, via
the same replication path). `make test-failover` must stay clean.

### R5. Rule-cap + cost + control-socket contention.
1024-rule cap vs production flow counts (vastly >1024 → only the heaviest-
imbalance flows get rules, rest fall back to RSS floor — acceptable, but the
selection policy must be bounded). ~1 ms/rule synchronous firmware cost means
the controller cannot churn rules per-tick; needs hysteresis + a low rebalance
cadence (≪1 Hz of rule writes) and must NOT add a high-frequency control-socket
caller (CLAUDE.md control-socket contention rule). #840's lesson: a rebalancer
that thrashes *degrades* fairness (CoV 37.7% vs 18.5%). Hysteresis/convergence-
detection (#897 line) is mandatory, not optional.

### R6. Flow-selection policy.
Which flow to move (heaviest on the hot worker? the one whose move most
flattens `{aᵢ}`?), when (occupancy threshold + dwell), and stop conditions.
Must converge, not oscillate. This is the substance of RQ3.

## 5. Multiple Path Options (final)

- **Path 1 — XDP_REDIRECT rebalance.** DEAD (Wall A). All three reviewers agree.
- **Path 2 — reactive ntuple HW re-pin of established flows.** VIABLE substrate
  (Wall B falsified §0); gated on R1–R6, especially **R1 (does it beat the
  floor — the #1203 49–55% precedent is the main kill risk)**. **Recommended
  feasibility-prototype target.**
- **Path 3 — hybrid.** DEAD (inherits Wall A).

## 6. Interaction with #1746 cap + #1230 fair-share lease (RQ4)

#1746 equal-flow cap (default-OFF) clips fast flows — a within-worker lever.
PR #1230 fair-share lease coordinates per-flow share across workers via
`epoch_total_granted` *without moving packets* — already shipped. Path 2 is
complementary: it changes `{aᵢ}` (the placement) so the *structural ceiling*
`Cstruct` itself improves, which neither the cap nor the lease can do (they
operate within a fixed `{aᵢ}`). If Path 2 ships and flattens `{aᵢ}`, the #1746
cap becomes largely unnecessary for the RSS-skew symptom; until then the cap is
the only operator lever. They do not conflict.

## 7. Cost/benefit at absolute scale (RQ5)

- **Benefit (if R1 passes):** lift `-P12` shaped-port CoV from 14–29% toward
  the balanced-`{aᵢ}` floor (~0% for a perfect spread), WITHOUT the aggregate
  loss the #1746 cap incurs — by moving the slow flows to idle workers rather
  than clipping the fast ones. This is the only mechanism that improves the
  structural ceiling.
- **Benefit ceiling / main risk:** bounded by R1. #1203's realized 49–55% CoV
  is a below-gate data point for a reactive placement controller on this exact
  cluster. The prototype must beat it or the line dies at R1.
- **Cost:** controller + `ethtool -N` programming (extends existing
  `rssExecutor` plumbing) + HA peer-mirroring + hysteresis + telemetry. No
  cross-worker session-migration subsystem is needed (the substrate exists) —
  this is materially LESS code than r1 assumed. Bounded rule churn (≪1 Hz),
  1024-rule cap with graceful RSS fallback.

**Cost/benefit: conditionally positive, gated on R1.** The substrate discovery
(§0) removes the largest cost item r1 assumed. The dominant risk is now
empirical (does reactive placement beat the floor), not architectural.

## 8. Recommended next step

Move #1748 to a **bounded feasibility prototype** that resolves R1 FIRST and
cheaply (before any production controller code):

1. **R1 spike (read-only + manual ethtool, no daemon code):** on the loss
   cluster during a maintenance window, run `-P6 -p5210`, read live `{aᵢ}` from
   `xpf_userspace_binding_active_flow_count`, then *manually* `ethtool -N` re-pin
   the 5-tuples of the flows on the most-loaded worker to idle queues, and
   measure per-flow CoV before/after over a 60 s steady-state window per
   `docs/fairness-regimes.md` gates. If CoV does NOT materially improve (stays
   near the #1203 49–55% band or the floor), **PLAN-KILL at R1** with the
   measurement as the kill evidence. If it improves toward the balanced floor,
   proceed.
2. Only if R1 passes: design the controller (R2–R6), re-review, then `/engineer`.

This R1 spike is itself a research step (manual ethtool, no production code) and
can be run under `/research` follow-up or as the first `/engineer` gate. It is
the cheapest possible falsification of the whole line.

## 9. Verdict and convergence path

r2 verdict: **PLAN-NEEDS-WORK** — the kill is withdrawn (Wall B falsified and
verified), but Path 2 is NOT yet PLAN-READY-to-ship because R1 (does reactive
placement beat the floor) is unresolved and is the historical kill point
(#1203 49–55%). The convergent landing the reviewers should converge ON is:
"Path 1/3 dead (Wall A); Path 2 substrate viable (Wall B falsified); fund the
R1 spike as the next gate." Reviewers: confirm Wall A, confirm the Wall-B
falsification is correctly verified (not over-claimed), and stress-test whether
R1 can plausibly pass given the #1203 precedent, or whether R1's likely failure
means we should KILL now rather than spend the spike.

## 10. Reviewer falsification targets (r2 — be hostile)

1. **Re-attack Wall-B falsification:** find a packet-path code site where a
   `WorkerLocalImport` / peer-synced session on the *active* node is rejected
   for forwarding by a per-worker (not per-RG) check, OR where the
   reverse-companion replica is NOT present on sibling workers. If you find
   one, Wall B is back and the kill is restored. (I checked
   `enforce_ha_resolution_snapshot` and `owner_rg_is_locally_active` — no
   per-worker gate. Prove me wrong with a quoted line.)
2. **Pre-judge R1:** argue from the #1203 controller design (on
   `feature/1215-per5tuple-fairness`) + the multinomial theorem whether reactive
   re-pin can plausibly beat 49–55% CoV, or whether placement is floor-bound
   regardless of controller quality → if the latter, recommend KILL-NOW over
   the spike.
3. **Re-attack Wall A:** any current-kernel cross-RX-queue AF_XDP delivery that
   passes `xsk_rcv_check`. (Path 1 revival.)
