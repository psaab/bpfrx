# Claude SMR hostile plan-review — round 58 (v9.9.54.9 @ 62ae6bd59)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.9 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.9-as-committed** — three precision pins (all LOW; no design
defect found). The v9.9.54.9 mechanisms verify sound in direction
against code.

## Finding 1 (nit — planned failover bypasses the election hold)

State: the generation-scoped election hold constrains only SPONTANEOUS
priority-driven preemption; a PLANNED/manual failover
(`request mastership`, `ForceRGMaster`) and priority-0 takeover are
operator-authoritative and bypass the hold exactly as they bypass the
sync-hold preempt gate today (the same existing exemption class) — the
repair continues or is superseded by the failover's own state
transition, never blocks an operator.

## Finding 2 (nit — the activation's bundle wait is bounded by construction)

State: the packed word's critical section contains only in-memory
operations (timer cancellation, flag sets, hold release, mirror write —
no I/O, µs-scale), so a LIVE writer cannot hang inside it; the only
mid-bundle stall is a process crash, which the restart-time rebuild
covers — the activation's wait is therefore bounded by construction and
needs no separate deadline.

## Finding 3 (nit — complete-late-CONFIRM is ignored only on tuple match)

State: a complete late CONFIRM is consumed and ignored ONLY when its
tuple equals the connection's negotiated tuple (a duplicate); a
mismatched tuple is not "late" — it is a protocol violation and closes
the connection.

## Verified sound this round (my own re-trace)

- r57-B1 fold: the generation-scoped election hold closes the
  preemption-during-repair window (with Finding 1's exemption class).
- r57-H2 fold: the one-shot writer + activation-CAS-loop + wait-then-
  re-arm closes the CAS-order race (with Finding 2's bound).
- r57-H3 fold: the allowlisted authenticated reader + exact byte rules
  close the trailer/lifecycle gap (with Finding 3's match rule).
- r57-H4 fold: the totality sweep + equal-ID rejection is clean (my
  grep finds no remaining "address-ordered" mention outside historical
  attribution).

## Verdict

**PLAN NO for v9.9.54.9** — fold Findings 1-3 as v9.9.54.10 (precision
pins; no design change). Part A remains converged and untouched.
