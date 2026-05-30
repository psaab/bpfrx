# Claude SMR hostile plan-review — #1614 simul-load diagnosis, round 2 (v2)

Reviewer: Claude SMR, HOSTILE. Plan: plan.md v2.

## Verdict: PLAN-READY

v2 corrects a wrong v1 mechanism (single-owner funnel) that my own r1
flagged as PLAN-READY-WITH-RESIDUALS. The R1 residual I raised (1g at
63%) drove the follow-up A/B that REFUTED v1's core claim. This is the
measurement-first discipline working as intended — I am ratifying the
CORRECTED v2, not rubber-stamping.

## The self-correction that earns PLAN-READY

My r1 demanded the 1g cell be resolved before declaring the architecture.
Running it (1g solo=95%, 1g+18g: 1g=95% / **18g=14.25 G from one worker**)
killed v1. A single worker pushing 14 G destroys "per-class capped at one
worker's ~4 G." The competitor-count sweep (§2.4) then localized the real
mechanism: even-division of the ~22-24 G ceiling among N backlogged
classes, with guarantee-rate small-first protecting only 100m/1g.

This is the correct lesson from MEMORY `feedback_verify_whole_function_body`
and the #1630 wrong-tree errors: a single A/B can refute a plausible
static-reasoning conclusion. v1 reasoned from the queue→worker map; the
A/B falsified it.

## Hostile attack on v2's claims

1. **§3.A ceiling = physics — survives.** Matches Phase-0 reverse 22.72 G
   and #1578. `park_root=0` confirms it's upstream of the root token gate.
   Cannot manufacture a CoS bug from the aggregate ceiling.

2. **§3.B small-first under-protects 3g/6g — survives and is the live
   defect.** The small4+24g test is the right experiment: small-sum 10.1 G
   << achieved 18.2 G means there was room to honor 3g/6g, yet they sat at
   ~52% alongside the unguaranteed 24g. The monotonic degradation
   (3g: 94→69→54% with competitor count) is the even-division signature.
   This is a genuine guarantee-rate semantics gap, not physics.

3. **The #1630-r4 "Phase-1 relegation falsified" reconciliation — I
   checked this hostilely.** #1630-r4 falsified relegation for SOLO/4-class
   because `quantum_sum` is built once at config-apply over ALL configured
   queues (`builders.rs:80-83`). v2's claim is that the PER-WORKER Phase-1
   BUDGET split (`pass1 = quantum_sum × 0.7` consumed per-worker) is what
   relegates 3g/6g under full contention. These are NOT the same mechanism
   and not contradictory: #1630 was about the quantum_sum DENOMINATOR
   (global, so 3g/6g are eligible); v2 is about the per-worker budget
   CONSUMPTION (a worker hosting small+large splits its 0.7 budget). v2 is
   careful to state this. ACCEPTED, but flagged for Codex/AGY to verify
   against the actual selector code — this is the load-bearing claim and
   it rests on a read of `queue_service/mod.rs:793-959`, not a measurement
   that isolates the per-worker budget directly. (A throwaway-counter
   confirmation of per-worker pass1 consumption would harden it; the
   /engineer round should do this before committing to candidate 1.)

4. **Per-flow CoV PLAN-KILL — survives.** #1220/#1244 precedent is solid;
   the gate is structurally unreachable; dropping it is correct.

## MAJOR residual (carry to /engineer, not blocking the plan)

- **The §3.B mechanism is inferred from code + the small4+24g black-box
  result, not yet directly instrumented.** The plan correctly defers
  candidate selection (§4-Path-A 1/2/3) to an /engineer measurement and
  §7-Q2 names this. I require the /engineer round to ADD a per-worker
  Phase-1-budget-consumption counter (the #1628 counters are per-class
  aggregated across workers, which HIDES the per-worker split — exactly
  why the diagnosis had to use black-box A/Bs). Without that, candidate 1
  could be the wrong fix. This is a /engineer gate, not a plan defect.

## MINOR

- M1 (r1, still): worker 0's best-effort=0 is a harness artifact (no port
  5200 offered). v2 §2.2 should note it; cosmetic.
- M2: the recommendation drops the per-flow-CoV gate — ensure the issue
  re-scope comment explicitly supersedes the #1614 body's "CoV ≤ 5/10%"
  acceptance lines so a future reader doesn't resurrect them.

## Disposition

PLAN-READY. Mechanism is correctly decomposed and falsification-tested;
the fixable component (§3.B) is real and bounded; the unfixable components
(§3.A ceiling, §3.2 per-flow CoV) are correctly PLAN-KILL-by-precedent.
The sub-issue decomposition (Path B first, Path A as a fresh research
chain, Path C deferred) matches the heavily-killed history's discipline.
The one load-bearing inference (per-worker Phase-1 budget split) is
code-read + black-box-confirmed and explicitly deferred to a direct
/engineer measurement before any fix commits — acceptable for a /research
deliverable.
