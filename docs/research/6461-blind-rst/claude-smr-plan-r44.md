# Claude SMR hostile plan-review — round 44 (v9.9.33 @ 8194bbaa9)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.33 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.33-as-committed** — three precision pins (all LOW; no design defect
found). The v9.9.33 mechanisms verify sound in direction against code.

## Finding 1 (nit — the preflight runs INSIDE the quiesce; the rejected cohort retries on resend)

The K + L ≤ C preflight has a TOCTOU unless it is stated: local
admissions freeze at quiesce entry (workers stop committing, so L stops
growing), and the preflight evaluates INSIDE the quiesce — exact by
construction. And E1's rejected cohort is not stranded: the peer's
periodic resend retries the exact reserve (which succeeds once E2's local
flow dies and its hold releases), and the undischarged obligation also
re-drives the repair — both paths are already in the design; state them.

## Finding 2 (nit — the quarantine flag shares the canonical lock domain)

The same-identity re-import's atomic cancel is only atomic if the
quarantine flag lives in the SAME canonical lock domain as the
publication (the canonical store mutex) — not an ordered pair. State it.

## Finding 3 (nit — the post-backstop re-open's first install IS the next cold-prime)

Codex r44-Q1's residual ("what drives the next handshake after the
backstop re-opens admission") needs one sentence: the first install after
the drain computes both-empty and cold-primes by the existing per-install
gate, and that cold-prime's bulk re-drive IS the next repair attempt —
the backstop never needs a separate driver, and the obligation discharges
only when that (or a later) repair completes with JOURNAL-END.

## Verified sound this round (my own re-trace)

- r43-B1 fold: retransmit + timeout-never-proof + direction-scoped
  triples close the loss schedules.
- r43-B2 fold: the internal sweep (Arc = detection only, swap-back undo,
  per-entry row version) is now consistent — my grep shows remaining
  `install_epoch` mentions are the correct admission-generation contexts
  (plan.md:2795-2797) and historical round attributions.
- r43-B3 fold: generation-tagged capacity + local-authority-wins
  conflict rule are coherent (with Finding 1).
- r43-B4/H5/H6 folds: §5.8 schema, token lifecycle, quarantine tuple are
  coherent (with Finding 2).
- r43-H7/M8 folds: identity adoption and the stop contract are clean.

## Verdict

**PLAN NO for v9.9.33** — fold Findings 1-3 as v9.9.34 (precision pins;
no design change). Part A remains converged and untouched.
