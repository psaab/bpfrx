# Claude SMR hostile plan-review — round 59 (v9.9.54.10 @ 934e11ac9)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.10 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.10-as-committed** — three precision pins (all LOW; no design
defect found). The v9.9.54.10 mechanisms verify sound in direction
against code.

## Finding 1 (nit — the baseline buffer settles permanently legacy on the first ordinary frame)

State: a baseline peer that never advertises never flaps — the arrival
of the FIRST ordinary legacy frame (ClockSync or a session frame) IS
the proof of the baseline class: the connection latches legacy
permanently for the connection's lifetime and dispatches the buffered
frame in order; there is no advertisement-timeout retry cycle because
the latch settles at the first ordinary frame, not on a timer.

## Finding 2 (nit — the aggregate's "locally relevant" enumeration)

State: the aggregate's locally relevant obligations are exactly THREE —
the inbound repair obligation (peer→local table completeness), the
outbound bulk obligation (local→peer state), and every cohort in the
pending-rejection set (which gates readiness per the earlier folds) —
and the hold releases only when ALL THREE are discharged at the current
generation.

## Finding 3 (nit — every generation-tagged effect is idempotent by design)

State: the effect set contains NO counters and NO one-shots — the hold
release is a state (release twice = no-op), the mirror write is a value
(write twice = same value), the primed flag is a flag (set twice =
no-op), and the timer cancellation is a cancel (twice = no-op) — so an
abandoned ticket's retry re-runs the whole effect set idempotently with
no double-execution hazard.

## Verified sound this round (my own re-trace)

- r58-B1 fold: the advertisement-gated entry + buffered dispatch closes
  the mixed-version establishment loop (with Finding 1's settle rule).
- r58-B2 fold: the inbound-JOURNAL_END discharge closes the directional
  error (with Finding 2's enumeration).
- r58-H3 fold: the Completing ticket closes the live-stuck bundle (with
  Finding 3's idempotence).
- r58-H4/H5/M6/M7 folds are internally consistent.

## Verdict

**PLAN NO for v9.9.54.10** — fold Findings 1-3 as v9.9.54.11
(precision pins; no design change). Part A remains converged and
untouched.
