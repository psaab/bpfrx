# Claude SMR hostile plan-review — round 57 (v9.9.54.7 @ 9fa07c8ec)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.54.7 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.54.7-as-committed** — four precision pins (all LOW; no design
defect found). The v9.9.54.7 mechanisms verify sound in direction
against code.

## Finding 1 (nit — pin follows token, obligation follows incarnation)

State: a pinned connection's death mid-repair fails the ATTEMPT (its
`JOURNAL_ACK` can't arrive), but never strands the repair: the repair
ID is sender-INCARNATION-scoped (a connection death is not an
incarnation change), the obligation is durable, and the NEXT
connection's negotiation re-arms the repair drive pinned to the NEW
token — the pin follows the token, the obligation follows the
incarnation.

## Finding 2 (nit — the completion bundle is staleness-atomic; crash recovery rides the restart rebuild)

State: the generation check gates the whole bundle atomically against
STALENESS (current callback → all effects + ready; stale → none), and a
PROCESS crash mid-bundle is a different failure class covered by the
restart-time state rebuild (the VRRP hold is re-acquired, primed
recomputed, the timer re-armed, readiness recomputed from current
state) — no persistent inconsistency is possible in either class.

## Finding 3 (nit — node-ID collision detected at the transcript)

State: the transcript carries BOTH cap records (dialer_cap and
acceptor_cap each carry `node_id`), so a misconfigured collision (both
sides provisioned the same ID) is DETECTED at the transcript — the
decision rule refuses the repair-era class on collision (falls back to
legacy with an operator-visible alarm, since owner selection would be
undefined).

## Finding 4 (nit — the packed-word race's winner rule)

State: the activation's bump is a CAS LOOP (`{gen, *} → {gen+1,
not-ready}`, retrying on contention) and always wins by monotonicity
(the generation only increases): a writer's
`{gen, not-ready} → {gen, ready}` CAS can succeed only for an OLD
generation's completion BEFORE the bump lands, after which the bump's
`{gen+1, not-ready}` is authoritative — the takeover decision reads the
final state (armed, not-ready), never a stale ready.

## Verified sound this round (my own re-trace)

- r56-B1 fold: the token binding closes the fabric-preference trace
  (with Finding 1's pin).
- r56-H2 fold: the completion transaction closes the hold-release race
  (with Finding 2's pin).
- r56-H3/M4 folds: owner totality + transport-close-on-partial are
  coherent (with Finding 3's pin).
- AGY-Q2's packed word holds (with Finding 4's pin).

## Verdict

**PLAN NO for v9.9.54.7** — fold Findings 1-4 as v9.9.54.8 (precision
pins; no design change). Part A remains converged and untouched.
