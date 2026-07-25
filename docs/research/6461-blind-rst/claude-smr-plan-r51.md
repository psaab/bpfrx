# Claude SMR hostile plan-review — round 51 (v9.9.47 @ 4064fa3f7)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.47 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.47-as-committed** — four precision pins (all LOW; no design defect
found). The v9.9.47 mechanisms verify sound in direction against code.

## Finding 1 (nit — flap behavior and the supersede's prime defined)

State: a v2↔legacy flapping peer never clears the v2-incarnation
obligation (the obligation keys include both incarnations, so a legacy
incarnation's completion can't touch it; each legacy→v2 flap re-arms
the negotiated path and the obligation discharges on the next
negotiated repair — the takeover fence and operator visibility bound
the degraded interval); and the supersede path's "post-reset prime" is
defined concretely: the fresh incarnation-scoped close-both + cold-prime
cycle (the legacy baseline's own reset), whose completion is the
lossless INSTALL-only emission — the supersede converts the obligation
into that baseline ATOMICALLY at downgrade detection, never lazily.

## Finding 2 (nit — the provisional pending slot's expiry and bound)

State: a pre-auth admission that never authenticates dies at the
handshake deadline (the auth handshake's own failure path closes the
connection), and the provisional pending set is bounded by the existing
admission cap (`sync_admission.go:66`'s slot limit), so stalled
admissions can neither leak nor exhaust it.

## Finding 3 (nit — CAPABILITY_CONFIRM is per-connection)

State: feature state negotiated by `CAPABILITY_CONFIRM` is per-connection
and never persists: a reconnect re-runs the full negotiation (hello,
proof, wrapper, CONFIRM) before any feature enables — there is no
cross-connection feature memory to race a downgrade.

## Finding 4 (nit — the proof's record pair is identical for both sides)

State the formula's disambiguation: each side computes over the SAME
pair — `prover_record` is the prover's OWN sent HELLO (which the
verifier also holds as received), `verifier_record` is the peer's HELLO
as received — both in (dialer-first) order, so the dialer and the
acceptor compute byte-identical inputs despite each HELLO carrying
per-side nonces.

## Verified sound this round (my own re-trace)

- r50-B1 fold: obligation keying + the two downgrade paths close the
  negotiated→legacy transition (with Finding 1's pins).
- r50-B2 fold: the admission-generation CAS closes the pre-auth
  regression (with Finding 2's pin).
- r50-H3/H4 folds: the total v1 mask / CAPABILITY_CONFIRM and the exact
  HMAC formula are coherent (with Findings 3-4).

## Verdict

**PLAN NO for v9.9.47** — fold Findings 1-4 as v9.9.48 (precision pins;
no design change). Part A remains converged and untouched.
