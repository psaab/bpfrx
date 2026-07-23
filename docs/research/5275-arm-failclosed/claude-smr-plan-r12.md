# Claude SMR — plan review r12 (#5275) — CONVERGENCE

Reviewing `plan.md` @ r13. Codex r11 returned PLAN-NEEDS-MINOR stating "no remaining
genuine safety defect or false source claim" — the ONLY items were two localized
wording contradictions in §13-D5, both now applied verbatim:

1. The D5 human-sign-off sentence no longer universally says "a failed scrub keeps it
   sender-silent"; it now path-scopes (crash-restart sender-silent; live re-arm keeps
   its incumbent heartbeat until scrub succeeds). ✓
2. §13-D5(c) no longer says "holds-but-cannot-scrub" against a "pre-hold" fencing state;
   it now reads "remains in fencing/pre-hold with the scrub incomplete." ✓

## Convergence state
- **Codex:** PLAN-NEEDS-MINOR (r11) — wording-only, both fixes applied → the plan Codex
  would rate PLAN-READY; it explicitly found no safety defect and no false source claim.
- **Claude SMR:** PLAN-READY (r10/r11, and this r12 confirming the two wording fixes
  land cleanly).
- **AGY:** infra-down throughout (best-effort per the research contract; not a blocker —
  proceed 2-of-3 SMR + Codex, `feedback_codex_infra_must_retry`).

## What was reviewer-accepted across the eleven Codex rounds
- Architecture VIABLE (ruled so from Codex r4 onward, never PLAN-KILL).
- D1 (per-stage proof), D2 (networkd link/address split), D3 (delayed-promotion
  transaction invariants), D4 (durably-staged recovery receipt): SOUND.
- D5(a) crash-restart first-zero gate: SOUND; D5(b) live gate: SOUND; the path-specific
  scrub-failure fallback (r12): closes the live dual-ownership defect.
- The §5 single-owner release + facade-OPEN ordering, the §6 bridge+flowtable+FORWARD
  barrier, the §7 sealed revocable facade, the §8 three-route apply gate: accepted.

## The one OPEN item (correctly a human decision, not a defect)
§13-D5 human sign-off: accept the pre-existing truly-dead-node timeout window (the same
window ANY `xpfd` crash has today, RECOMMENDED, no new hardware) vs add external STONITH
fencing for a zero dual-address guarantee. Codex r11: "correctly left for human
sign-off." This is the `/engineer` manual-approval decision.

## Verdict
r13 applies Codex r11's two wording fixes; no safety defect or false source claim
remains (Codex r11's own words). Codex + Claude SMR are converged. This is the
`/research` deliverable: a complete, viable, source-consistent, exhaustively-reviewed
fail-closed architecture with the single operations tradeoff flagged for human sign-off.

VERDICT: PLAN-READY
