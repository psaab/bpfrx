# Claude SMR hostile plan-review — round 46 (v9.9.37 @ 60007eabc)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.37 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.37-as-committed** — four precision pins (all LOW; no design defect
found). The v9.9.37 mechanisms verify sound in direction against code.

## Finding 1 (nit — authoritative-absence requires a VALIDATED snapshot; re-arm names the new holder)

State: the authoritative-absence cancellation fires only on a VALIDATED
snapshot (a current, repair-ID-correct bulk whose `BulkEnd` validates) —
a stale/wrong-ID repair is non-mutating and can never cancel a pending
entry; and a retried cohort that loses P to a third flow re-arms against
the NEW conflicting holder with the same lifecycle rules (each churn
cycle requires a legitimate owner for P, and the bounded timer
independently drives retries — no livelock).

## Finding 2 (nit — an unknown/expired repair ID never validates)

State the duplicate-after-expiry rule explicitly: a `JOURNAL_END` whose
repair ID matches no current obligation and no live receipt is DISCARDED
(not processed as a repair) — the sender's fresh-ID re-drive is the only
repair that proceeds, so a very-late duplicate of an expired repair can
never mutate state.

## Finding 3 (nit — the cleanup record's capture ordering)

State: the reverse companion is synthesized and pre-published BEFORE
fan-out (`session_import.rs:104` synthesizes, `:115` publishes forward,
`:187` publishes the reverse), and the quarantine record is captured at
fan-out completion (all replicas rejected) — so R1 is always inside the
record; no capture-time window exists.

## Finding 4 (nit — the replace query keys on the exact T2 value; the exempt lane is type-constrained and incarnation-bound)

State: the lost-ACK registry query keys on the EXACT T2 VALUE (monotone
never-reused tokens — T2-present means THIS attempt's commit, never a
stale aborted attempt's); and the barrier-exempt reset lane accepts ONLY
the `RESET_GEN`/`RESET_ACK` frame types (every other type is dropped at
demux) and is bound to the peer's authenticated current incarnation (a
stale-incarnation `RESET_GEN` is discarded), so the exemption cannot
smuggle session frames past the barrier.

## Verified sound this round (my own re-trace)

- r45-B1 fold: cancel rules + GC notification + bounded timer are
  coherent (with Finding 1).
- r45-B2 fold: the two-frame terminal exchange + full-triple receipt +
  fresh-ID-after-expiry are coherent (with Finding 2).
- r45-B3/B4 folds: immutable cleanup records + teardown-failed latch are
  coherent (with Finding 3).
- r45-H5/H6/H7 folds: replace CAS, exempt lane, and version negotiation
  are coherent (with Finding 4).

## Verdict

**PLAN NO for v9.9.37** — fold Findings 1-4 as v9.9.38 (precision pins;
no design change). Part A remains converged and untouched.
