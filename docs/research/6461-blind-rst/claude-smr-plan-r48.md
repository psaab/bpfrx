# Claude SMR hostile plan-review — round 48 (v9.9.41 @ 459412e33)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.41 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.41-as-committed** — three precision pins (all LOW; no design defect
found). The v9.9.41 mechanisms verify sound in direction against code.

## Finding 1 (nit — the drain cannot hang: a natural connection death completes it)

State: the drain of a superseded incarnation's handlers/lanes is bounded
by the connection lifecycle itself — n1's connection dying naturally
(TCP reset, silence teardown) completes the drain automatically (the
handlers die with the connection), so the atomic retire-current/
promote-pending step never waits on anything other than an already
dying lane.

## Finding 2 (nit — the per-incarnation high-water starts fresh per incarnation)

State: the reset-generation high-water is per `(node_id, incarnation)`
and a NEW incarnation starts with a FRESH high-water (it inherits
nothing from its predecessor — the old incarnation's high-water retires
with it), so n3 can never be confused with n2's retired state nor
starved by it.

## Finding 3 (nit — the hello transcript's canonical encoding)

State: the transcript is an ORDERED field list with explicit encoding
(each field length-prefixed, fields in the tuple's declared order:
node_id, process_incarnation, capacity, capacity_config_generation, the
capability bits, nonces) — two implementations then compute
byte-identical transcripts and verify the same `AUTH_PROOF`.

## Verified sound this round (my own re-trace)

- r47-B1 fold: the discharge sweep is complete — my grep finds no
  remaining generic discharge clause that isn't direction-explicit.
- r47-H2 fold: the {current, pending, retired} machine + per-incarnation
  high-water close the overlapping-setup interleaving (with Findings
  1-2's pins).
- r47-M3 fold: the transcript binding closes the proof-exclusion
  problem (with Finding 3's encoding pin).

## Verdict

**PLAN NO for v9.9.41** — fold Findings 1-3 as v9.9.42 (precision pins;
no design change). Part A remains converged and untouched.
