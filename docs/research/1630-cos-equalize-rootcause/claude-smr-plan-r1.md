# Claude SMR hostile plan-review — #1630 r1

Reviewer role: CoS-scheduler / WFQ / DRR / token-bucket / AF_XDP
multi-worker-shaper domain expert. Hostile by mandate
(`feedback_triple_review_includes_claude_smr`): no soft first-pass.

**VERDICT: PLAN-NEEDS-MAJOR**

The verified root cause (multi-worker queue-ownership fragmentation +
flat root shaper) is CORRECT and well-evidenced — that part survives
hostile review. But the plan v1 has three load-bearing defects that make
it not-ready, and I independently reach the same conclusion as Codex r1
on the gate and the "no selector change" claim.

## What is right (and survives)

- §2/§3 root cause is mechanically sound. coordinator/mod.rs:935-938
  round-robin ownership + cross-binding redirect + worker-local selector
  (queue_service/mod.rs:811 cos_queue_is_empty skip) genuinely make
  interface-wide small-first impossible for a worker-local selector. I
  re-derived this from the code; it holds.
- The shared root shaper (one flat FCFS pool, rate=full shaping,
  shared_cos_lease/mod.rs:738-771) genuinely ignores guarantee priority.
  That is a real second-order arbiter that the guarantee knob never
  touches.
- The per-class v8 lease analysis is correct: cap = rate×elapsed, and
  with one owner per queue my_fair_share == cap, so the lease is NOT the
  small-class limiter. Good.

## MAJOR findings

### M1 — §1/§3 numeric framing is wrong and self-contradicting (matches Codex #1)
§1 says demand 19.1 G is "below ... the Phase-1 budget (17.5 G)". That
is FALSE: 19.1 > 17.5. What fits under 17.5 G is the small-FOUR sum
(10.1 G), not the 5-class total. The §3 table is internally fine, but
the prose in §1 and the §6 reasoning lean on the false "19.1 ≤ 17.5"
claim. This is exactly the kind of arithmetic slip the project has
burned on before. Rewrite: the binding facts are (a) small-four 10.1 G
≤ 17.5 G budget, (b) 5-class total 19.1 G ≤ 25 G shaper but ABOVE the
~18 G push ceiling. The "below the ~18 G ceiling" line in §1 is also
wrong — 19.1 > 18. Fix both.

### M2 — the solo-84% "quantum-efficiency floor" is asserted, not proven; the whole Q1 dichotomy rests on it
§3 and §6 treat "solo iperf-1g = 84% is a quantum/MTU carry-forward
floor" as established. It is not. As Codex notes, at 1 G the per-visit
quantum is ~25,000 B (cos_guarantee_quantum_bytes, queue_service/mod.rs:1534);
whole-frame rounding loses ~1 MTU/visit ≈ 6% at most, not 16%. A 16%
solo shortfall with NO competition points at a DIFFERENT limiter —
candidates I can see in the code that the plan never ruled out:
  - the per-class v8 lease epoch cap interaction with the 512 KB root
    lease_bytes top-up cadence and the seqlock-rotation `cap = rate ×
    min(elapsed, EPOCH_DURATION)` clamp (rotate_epoch_v8.rs:215-222) —
    if epochs rotate slightly late, cap is under-provisioned;
  - flow-fair / V_min throttle (the drain has a flow-fair path,
    drain.rs:144/400) deliberately holding back a worker;
  - TX-ring / completion backpressure (the 84% could be the AF_XDP
    fill/completion ceiling for a single flow-set).
The plan MUST identify the solo-84% mechanism with a measurement or a
worked calculation BEFORE Q1's dichotomy ("root-starvation vs
quantum-floor") is even well-posed. As written, Q1 offers a false binary
between one proven cause and one unproven one. This is the single
biggest gap.

### M3 — "No selector change" (§7 step 4) is unsafe; the waterfill Phase-2 is semantically broken regardless of scope (matches Codex #3)
The plan's Path 2 thesis is "the selector is already correct within
single-worker scope; just give it visibility." But the selector's Phase
2 is NOT correct even in single-worker scope: honored_mask is a local
reset to 0 every call (queue_service/mod.rs:806) and the code comment at
913-921 openly admits Phase 2 cannot tell which queues were honored and
"approximates" via pass1_remaining < quantum. With one owner holding all
11 classes, Phase 1 returns on the FIRST honored small queue (line 907),
so honored_mask is ALWAYS empty when Phase 2 runs on a later call —
Phase 2's skip-honored logic (line 938) is dead. The descending walk
will re-serve large queues that were never gated against the honored
set. So single-owner does NOT automatically yield small-first; it yields
"first ascending queue that fits, then descending large queues" with no
persistent honored bookkeeping across the calls that make up one epoch.
Path 2 therefore REQUIRES a selector correctness fix (persistent
honored set across the per-epoch call sequence, or a single-pass
multi-return design), not just an ownership change. The plan must move
this from "no change" to "in scope."

### M4 — Q2 (single-owner CPU ceiling) is a precondition, not an open question (matches Codex #5)
If one core cannot sustain CoS-shaped TX above the 10.1 G small-class
guarantee sum, Path 2 cannot meet its own Gate 1 — the small classes
would be starved by the owner's CPU, not by the scheduler. The #1183
memory entry shows a forced single-owner CoS funnel collapsed reverse
throughput to ~2 G on this exact cluster. ~2 G << 10.1 G. That single
historical data point is nearly disqualifying for Path 2 and the plan
buries it as a risk bullet (§9) and an open question (Q2) instead of
treating it as a gating precondition. The plan must require a
single-owner CPU-ceiling measurement BEFORE recommending Path 2, and
must reconcile with the #1183 ~2 G collapse: was that a different funnel
(cross-binding redirect of ALL tx, vs CoS-queue ownership)? If the
#1183 collapse mechanism also applies here, Path 2 is dead on arrival.

### M5 — Gate 1 "≥95% of configured shape" is likely unachievable and the plan knows it (matches Codex #1)
§6 explicitly concedes Path 2 may not reach 95% if the quantum-floor
dominates, yet §8 Gate 1/1b still demand ≥95% of CONFIGURED shape. If
solo (zero competition) is 84%, ≥95%-of-shape is unreachable by
construction. The gate must be reframed as "≥95% of the
solo-achievable ceiling for that class" OR the solo-84% must first be
fixed (M2) so the configured-shape gate becomes meaningful. A gate that
is unachievable regardless of fix is not an acceptance gate.

## MEDIUM

### Md1 — Q5 hot-path allocation is real and Path 2 amplifies it (matches Codex #7)
queue_service/mod.rs:807 `let sorted_indices: Vec<usize> =
root.exact_queues_by_rate_ascending.clone();` allocates on every
guarantee-selector call, which is on the drain hot path
(drain_shaped_tx → service_exact_guarantee_queue_direct_with_info →
select...waterfill). Single-owner routes ALL interface drain traffic
through this one allocation site with 11+ entries. engineering-style
forbids hot-path allocation. This must be fixed (borrow the slice;
honored bookkeeping can be a fixed-size bitmask already present) as part
of Path 2, not deferred.

### Md2 — root-token park telemetry is needed to confirm §3 for the 5-class case
The plan's §3 claims root-pool proportional-starvation but, as Codex #4
notes, for 5-class the per-class caps sum to 19.1 G < 25 G root rate, so
in pure token terms the root pool is NOT exhausted. The plan's escape
hatch ("the ~18 G TX ceiling makes it mildly oversubscribed at the
wire") is plausible but unproven. The drain_park_root_tokens counter
(queue_service/mod.rs:653) already exists — the plan should require
reading it (per-class) in the Q1 A/B to PROVE whether root-token parking
is the dominant gate or a red herring.

## What I'd require for PLAN-READY

1. Fix M1 arithmetic throughout (§1, §6).
2. Resolve M2: identify the solo-84% mechanism with a measurement or
   worked calc (read per-class drain_park_root_tokens /
   drain_park_queue_tokens + lease-grant telemetry on a throwaway debug
   build). This is the load-bearing experiment; do it in research, not
   at /engineer.
3. Promote M4 (single-owner CPU ceiling) and the #1183 collapse
   reconciliation to gating preconditions. If single-owner can't clear
   10.1 G on one core, recommend Path 4, not Path 2.
4. Move M3 (selector Phase-2 correctness) + Md1 (hot-path alloc) into
   Path 2 scope; drop the "no selector change" claim.
5. Reframe Gate 1 (M5) to a solo-achievable-ceiling basis, or gate it
   behind the M2 solo-fix.
6. Honestly re-weight Path 4: given M2 (solo floor) + M4 (#1183
   collapse) + M3 (broken Phase-2), Path 4 (document + B2 follow-up) may
   be the correct outcome and the plan should say so unless the research
   measurements clear M2 and M4.

The root cause is solid; the FIX recommendation is premature. This is a
NEEDS-MAJOR because the research has not yet run the one experiment that
decides whether Path 2 is even viable.
