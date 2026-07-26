# Claude SMR hostile plan-review — round 55 (v9.9.54.2 @ cd616a909)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.2 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.2-as-committed** — two precision pins (all LOW; no design defect
found). The v9.9.54.2 mechanisms verify sound in direction against code.

## Finding 1 (nit — the legacy latch's upgrade path is the NEXT connection, stated)

The fold already says "a later v2-capable connection re-runs the full
negotiation" — make the dual rule explicit: the latch binds for the
CONNECTION's lifetime with no in-connection escape (a peer that upgrades
to v2 mid-connection still finishes this connection in the legacy
class), and the upgrade takes effect only on the NEXT connection (new
incarnation → full renegotiation: hello, v2 proof, CONFIRM, repair-era)
— so the latch can never strand a capable peer (the next connection
unlocks it) and never lets a mid-connection protocol flip happen.

## Finding 2 (nit — the mint-and-arm serializes under the sync state machine's lock domain)

State: the repair-ID mint, the outbound-obligation arm, and the
not-ready assertion are one critical section under the same lock domain
that owns the sync state (the `SessionSync` mutex that owns obligations
and cold-prime state); the readiness gate reads under the same lock, so
a takeover decision observes either (armed, not-ready) or (unarmed,
legacy-complete) — never (armed, ready).

## Verified sound this round (my own re-trace)

- r54-B1 fold: HMAC-SHA256 + the literal vectors (I recomputed both
  digests — they match the formula's byte grammar) close the
  interoperability oracle gap.
- r54-H2 fold: the tracked/deadlined confirmation phase + the legacy
  latch close the untracked-wait and flap schedules (with Finding 1's
  pin).
- r54-H3 fold: the mint-and-arm-first rule closes the readiness
  interval (with Finding 2's pin).

## Verdict

**PLAN NO for v9.9.54.2** — fold Findings 1-2 as v9.9.54.3 (precision
pins; no design change). Part A remains converged and untouched.
