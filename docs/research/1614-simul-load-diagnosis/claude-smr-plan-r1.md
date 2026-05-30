# Claude SMR hostile plan-review — #1614 simul-load diagnosis, round 1

Reviewer: Claude SMR (domain SMR + CPU/arch + SW design), HOSTILE.
Plan: docs/research/1614-simul-load-diagnosis/plan.md v1.

## Verdict: PLAN-READY-WITH-RESIDUALS (measurement-first; two MAJOR open cells)

The diagnosis is measurement-grounded and the falsification chain is
sound. I am NOT soft-passing: I attacked each leg below and they held,
EXCEPT two cells that must be named as risks, not papered over.

## What survives hostile attack

1. **"Root shaper not the limiter" — survives.** `park_root=0` is
   unambiguous and present on every class in BOTH runs. The aggregate
   (24 G) < root cap (25 G) corroborates. Cannot manufacture a root-shaper
   bug from this data.

2. **"Not Phase-1/Phase-2 split" — survives, and this is the most
   important kill.** The #1625 and #1630-r3 hypotheses both fingered the
   waterfill Phase-2 relegation. The #1628 counters now DIRECTLY refute
   it: phase2_admit is ≤16% of admits even for the worst class, ~0% for
   the classes that are MOST starved relative to a flat-rate expectation.
   If Phase-2 relegation drove the regression, the starved large classes
   would be phase2_admit-dominated. They are phase1_admit-dominated. The
   counters #1628 was built to provide did their job. This is the single
   strongest result in the plan.

3. **"Single-owner funnel" — survives the decisive A/B.** Large-six-alone
   is the right experiment: it removes the small-class Phase-1-budget
   competition entirely. If the deficit were scheduler-internal
   (Phase-1 budget, fair-share, lease), removing competitors would lift
   the large classes. It did NOT (9g 30%→35%, 24g 11%→16% — marginal).
   The per-class ceiling tracks one-worker capacity, not configured shape.
   This is consistent with project_1183 and the AF_XDP physics in
   fairness-regimes.md. I could not construct a competing explanation that
   survives this A/B.

## MAJOR residuals (must stay as named risks, not resolved on paper)

- **R1 — 1g at 63%.** This is the one cell that does NOT fit "structural
  single-owner ceiling cleanly." 1g's shape (1 G) is FAR below one-worker
  ceiling (~4 G), so single-owner does not explain its 37% shortfall. The
  plan's §7 Q1 flags it but does not resolve it. 1g shares worker 2 with
  18g — but 100m shares worker 1 with 15g and reaches 86%. So co-tenancy
  with a large class is not a uniform explanation. This could be (a) a
  residual cause-1 carry gap at the 1 G rate, (b) the cause-2 mid-rate
  transport floor extending to 1 G under contention, or (c) something the
  diagnosis missed. A cause-1-class scheduler issue at 1 G is NOT fully
  ruled out. The plan is honest that this is open; I require it stay
  BLOCKING for Path B's gate (a Path B that ships a "63% is fine" gate
  without explaining 1g would be premature). Recommend one more targeted
  run: 1g SOLO and 1g+18g pair, to isolate co-tenancy from rate-floor.

- **R2 — single run, no repeat.** Both core results are single 30 s runs.
  The #1217/#1220 discipline demands repeated runs before declaring a CoV
  structural. The aggregate (22-24 G) is stable across the two runs which
  is reassuring, but per-class achievement variance run-to-run is
  unmeasured. The structural-CoV claim (§3.2) leans on prior #1220/#1244
  measurements, not this session's — acceptable for the CoV FLOOR claim
  (well-established) but the per-class achievement numbers should be
  confirmed with a second run before the re-scoped gate in §6 is set.

## MINOR

- M1: §2.2 worker 0 owns best-effort+12g but best-effort=0.00 G — because
  no best-effort traffic was offered (the harness skips port 5200). So
  worker 0 effectively only served 12g. Fine, but the plan should note the
  best-effort idle is a harness artifact, not evidence.
- M2: DUR=33 hardcoded for the delta-Gbps in §2.1 (pre/post wall incl
  snapshot overhead). The iperf-reported recv (§2.1 recv column) is the
  authoritative throughput; the counter-delta Gbps is corroborating. State
  which is load-bearing (iperf recv is).

## Disposition

PLAN-READY for the RECOMMENDATION STRUCTURE (decompose; Path B primary;
Path A gated spike; do NOT ship a new scheduler mechanism). The mechanism
diagnosis is correct and the kill-the-scheduler-fix posture is right and
matches every precedent in this space. R1 (1g) must remain a BLOCKING
open question on the Path B sub-issue, and R2 (repeat run) should gate the
final re-scoped numbers. Neither overturns the architecture conclusion.
