# Claude SMR hostile plan-review — #1614, round 3 (v3)

Reviewer: Claude SMR, HOSTILE. Plan: plan.md v3.

## Verdict: PLAN-READY

v3 folds Codex r1 (PLAN-NEEDS-MAJOR) and AGY r1 (PLAN-READY), and — most
importantly — I empirically adjudicated the Codex↔AGY disagreement against
the live telemetry rather than picking a side on paper.

## What changed v2→v3 and why it is correct

1. **Codex r1 was RIGHT and v2 was WRONG.** v2's §3.B mechanism
   ("per-worker owner-local eligible quantum_sum relegates 3g/6g") is
   false in code: `quantum_sum` sums `exact_queues_by_rate_ascending`
   with no owner/eligible filter (`mod.rs:793-797`), built over ALL
   configured exact queues (`builders.rs:80-83`). v3 retracts the
   mechanism and the #1630-r4 reconciliation built on it. This is the
   exact wrong-tree / wrong-mechanism class the #1630 chain hit repeatedly;
   catching it at /research (zero code written) is the point of this skill.

2. **AGY r1's epoch-lockout mechanism is REFUTED as the active cause.** I
   did not accept it. The live `waterfill_epochs` counter climbs ~52K/s
   and phase1_admit dominates for every class — both impossible under a
   permanently-wedged epoch. v3 §3.B.1 records the refutation with the
   counter evidence; §7-Q5 keeps the wedge as a candidate LATENT bug for
   independent hardening. This is `feedback_verify_whole_function_body`
   applied to a reviewer's claim: the burden is the running system, not a
   code excerpt.

3. **v3 reframes §3.B as a CONFIRMED SIGNAL with an UNRESOLVED
   MECHANISM.** This is the honest disposition. The signal is rock-solid
   (small4+24g: 3g/6g at ~52% with ~6 G ceiling headroom, park_root=0,
   Phase-1-admitted). The mechanism is genuinely open (per-worker budget
   interaction / v8 lease grant / root FCFS — none isolated by the
   aggregated #1628 counters). v3 makes Path A INSTRUMENT-FIRST with an
   explicit PLAN-KILL exit if no per-worker headroom is recoverable. This
   matches the #1630 four-mechanism-falsification discipline exactly.

## Hostile attack on v3

- **Is the §3.B signal itself an artifact?** I tried to break it. The
  small4+24g run: small-sum 10.1 G, aggregate 18.2 G, so 6+ G of the
  ~24 G ceiling was unused while 3g/6g sat at 52%. If the limiter were
  purely §3.A, the aggregate would have been pushed to ~24 G. It was not —
  there was demonstrable unused capacity AND 3g/6g were below guarantee.
  The signal survives: something prevented 3g/6g from claiming available
  ceiling. SIGNAL CONFIRMED.

- **Could §3.B be demand-bound (iperf not offering enough)?** No — 3g/6g
  queues were persistently backlogged in the full run (the #1630 §5.0
  offered-load gate already established these classes are offered well
  above rate at -P12), and park_queue is high (the bucket gate fired
  constantly). Not demand-bound.

- **Does v3 over-claim Path A viability?** No — v3 explicitly says Path A
  "could itself PLAN-KILL" if instrumentation finds no recoverable
  per-worker headroom. That is the correct hedge given two falsified
  mechanisms.

## MINOR (carry to /engineer, non-blocking)

- M1: the Codex↔AGY counter-aggregation disagreement (§7-Q2) is correctly
  deferred to an empirical per-worker dump. My read: both are partially
  right — each queue's counter is one owner's (AGY), but a worker hosting
  TWO queues has a shared `pass1` budget state that NO per-queue counter
  exposes (Codex's "hidden split" is the per-worker budget, not the
  per-queue admit). The /engineer dump must expose the per-worker
  `waterfill_pass1_remaining_bytes` trajectory, not just per-queue admits.

## Disposition

PLAN-READY. v3 is the honest measurement-first deliverable: one refuted
architectural hypothesis (single-owner funnel), one code-falsified
mechanism (per-worker quantum_sum), one telemetry-refuted mechanism (epoch
lock-in), a CONFIRMED defect signal (3g/6g under-protection with
headroom), and an instrument-first Path A charter with a PLAN-KILL exit.
The sub-issue decomposition (Path B framing first, Path A instrument-first,
Path C deferred, per-flow-CoV dropped by #1220/#1244) is correct. No fix
is pre-committed — exactly right for /research in this heavily-killed
space.
