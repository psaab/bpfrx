# Claude SMR hostile plan-review — round 60 (v9.9.54.12 @ 0aefd6ac6)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.12 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.12-as-committed** — five precision pins (all LOW; no design
defect found). The v9.9.54.12 mechanisms verify sound in direction
against code.

## Finding 1 (nit — bit 5 follows the same v1-proof rule as every capability)

State: BIT 5 is advertised in the capability record like every other
bit, and on a v1-proof connection it is MASKED like every other
capability (advertised, not active) until the matching authenticated
`CAPABILITY_CONFIRM` — the decision phase requires BOTH bit 5 present
AND (on a v1-proof connection) the post-wrapper CONFIRM.

## Finding 2 (nit — each hold generation is minted fresh; releases are generation-validated)

State: every true→false transition mints a FRESH hold generation, and a
completion releases ONLY the exact generation it armed (the release is
generation-validated) — an earlier hold's release can never race a
newer hold because a release for generation N is a no-op when the
current hold is generation N+K.

## Finding 3 (nit — the forced repair never gates on the barrier)

State: the forced-and-validated repair runs through the NORMAL
obligation machinery (arm → drive → `JOURNAL_END`) and is never gated
by the barrier; the barrier only gates the override's issue — so there
is no wait cycle (barrier → repair ✓, repair ↛ barrier).

## Finding 4 (nit — the token carries the transfer-generation and is validated like the readiness writers)

State: the transfer-generation token carries its generation and is
consumed one-shot via the same packed-word CAS discipline (the override
validates `token.gen == current transfer-generation for the RG` before
consuming) — a token from an OLD generation fails the validation
deterministically.

## Finding 5 (nit — the watchdog never blocks; it dispatches per-ticket workers)

State: the executor dispatches effects to per-ticket WORKERS that
validate ticket+generation, and the watchdog itself NEVER calls any
effect API (it cannot block on `vrrp.Manager.mu` or anything else) —
it monitors worker deadlines, and a hung WORKER's ticket is abandoned
by deadline, never by the watchdog blocking.

## Verified sound this round (my own re-trace)

- r59-B1/B2/B3 folds are coherent (with Findings 1-3).
- r59-H4 fold is coherent (with Finding 5; Finding 4's validation was
  already in the fold).
- r59-H5 fold is coherent (with Finding 4).

## Verdict

**PLAN NO for v9.9.54.12** — fold Findings 1-5 as v9.9.54.13
(precision pins; no design change). Part A remains converged and
untouched.
