# Claude SMR hostile plan-review — round 45 (v9.9.35 @ 22b7b5724)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.35 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.35-as-committed** — four precision pins (all LOW; no design defect
found). The v9.9.35 mechanisms verify sound in direction against code.

## Finding 1 (nit — the pending-rejection set: bound, latch, and ONE notification point)

State: the pending-rejection set is latched per cohort (deduped by
`(flow key, SessionIdentity)`) and bounded by the shared-table capacity
(a rejection can only follow a legitimate peer install attempt — blind
packets fail earlier at identity/gen checks, so no blind-reject flood
exists; a legitimate wide config skew producing many pending cohorts is
the CORRECT conservative posture — the standby genuinely lacks them);
and the release notification is ONE hook at the hold CELL's zero
transition (the single release point the whole design already routes
through — reap, rollback, GC, migration, and conversion all release
through it, so coverage is total by construction, not N hooks to
enumerate).

## Finding 2 (nit — the freeze drains in-flight commits before the preflight)

State: the admission freeze stops NEW commits but lets in-flight
slow-path commits complete (that IS the quiesce), so the frozen-interval
preflight counts them exactly — no in-flight install can slip past the
count.

## Finding 3 (nit — the replace transaction is atomic; failure leaves T1 live)

State: `replace(slot, T1, T2, token_epoch)` revokes T1 and registers T2
in ONE helper-acknowledged transaction — on failure (helper unreachable)
NOTHING changes (T1 remains live, T2 is not installed, the install
retries); the epoch validation on the publication path is a single
atomic load, negligible against the map operation.

## Finding 4 (nit — the retained-forever terminal state is recoverable)

State: a worker that never exits leaves XSK disabled, dataplane down,
readiness degraded, and the failure operator-visible via the existing
reconcile-stage reporting (#6244); the old generation's retention is
what lets the NEXT reconcile attempt retry with a fresh generation —
the terminal state is recoverable, and force-killing the worker is
explicitly rejected (kernel-state corruption risk).

## Verified sound this round (my own re-trace)

- r44-B1 fold: rejection-obligation composition with the resend path is
  coherent (with Finding 1).
- r44-B2 fold: freeze→quiesce→repreflight is exact (with Finding 2).
- r44-B3 fold: §5.8 consolidation + legacy-only bare-ACK scoping is
  internally consistent.
- r44-H4/H5/H6 folds: setup ownership, replace transaction, one deadline
  are coherent (with Findings 3-4).

## Verdict

**PLAN NO for v9.9.35** — fold Findings 1-4 as v9.9.36 (precision pins;
no design change). Part A remains converged and untouched.
