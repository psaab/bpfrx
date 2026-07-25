# Claude SMR hostile plan-review — round 50 (v9.9.45/v9.9.45.1 @ adc943390)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.45 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.45-as-originally-committed** — one self-found MEDIUM (the
"APPENDED via trailing-field tolerance" phrasing presumed a HELLO-frame
tolerance that does not exist in that form; the v1 HELLO is fixed-layout
and in-frame appended bytes would be misread as the next frame) — already
repaired as v9.9.45.1 (the v2 fields ride a NEW FRAME TYPE after the
untouched legacy HELLO; the length-prefixed demux skips unknown frame
types by length because `handleMessage`'s switch has no default arm) —
plus two LOW pins.

## Finding 1 (nit — the new→legacy prime's readiness ownership)

State: the new node's transfer-readiness for the install-only prime is
gated on its OWN sync state and the lossless emission only — it never
gates on the legacy peer's state (the legacy peer's readiness is its own
business and converges by its own invalidation/aging); and when a
legacy→new bulk completes while the new node ALSO has a negotiated
repair obligation outstanding, the two completion classes are
independent — the legacy bulk's completion does not touch the armed
obligation, and the node's readiness is the CONJUNCTION (every armed
obligation discharged per its own rule, plus the legacy completion).

## Finding 2 (nit — the "post-authenticated" capability alternative defined)

State: "post-authenticated" means concretely — on a v1-proof connection,
the capability fields are exchanged but not transcript-covered; a peer
wanting them authenticated performs the v2 transcript proof as a SECOND
proof exchange once the connection's authenticated wrapper is installed
(the wrapper exists by then, so the v2 proof can ride it); until then
the fields are advisory-only (a v1 peer treats them as hints and keeps
v1 behavior for anything security-relevant).

## Verified sound this round (my own re-trace)

- r49-B1 fold: the three-class completion matrix closes the
  mixed-version completion gap (with Finding 1's readiness pin).
- r49-H2 fold: the legacy-prefix preservation + v1-selection + byte
  vectors + the new-frame-type mechanism (v9.9.45.1) close the
  mixed-version negotiation gap.
- The incarnation transition (r48-3 RESOLVED) holds.

## Verdict

**PLAN NO for v9.9.45** — the mechanism phrasing defect is repaired as
v9.9.45.1; fold Findings 1-2 as v9.9.46 (precision pins; no design
change). Part A remains converged and untouched.
