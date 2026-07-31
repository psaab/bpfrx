# Claude SMR hostile plan-review — round 114 (v10.29.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — thirty-fourth
pass; I authored the v10.29.0 fold of Codex r113's 3B/1H/2M. Verdict:
**PLAN YES**.

## 1. Fold verification

**r113-1 (B — alias-safe matched identity).** Verified: the lookup
resolves the reverse-translated alias, captures the canonical
`actual_key` (`lookup.rs:62-68`, `:85-102`, `:194-219`), and discards
it on return; downstream wraps the hit as `QueryKey`
(`shared_ops.rs:602-612`); table mutation requires the canonical key
(`session/mod.rs:1022-1051`); cache entries retain the query key
(`flow_cache.rs:201-224`, `:578-581`). The fold: the canonical
matched key now RIDES the resolution result and the flow-cache entry,
so the commit hook's clear/refresh/overdue evaluation always targets
the canonical entry; §9 tests canonical, translated, and cache-alias
hits.

**r113-2/4 (B/H — the admission-point promote retracted).** Codex is
right on both counts: the enqueue is not a commit-to-deliver point
(timeout untransmitted, `neighbor_dispatch.rs:208-232`; post-resolution
failures, `:294-325`, `:344-404`), and no producer/carrier exists for
an enqueue-time apply (`shared_ops.rs:563-578`,
`poll_descriptor/mod.rs:883`, `:5017-5069`). The correct answer was
simpler than my v10.28.0 invention: master's OWN promote fires at the
lookup (`lookup.rs:129-149`), BEFORE any disposition or buffering
decision — so the §5.5 post-borrow proof-gated promote at the lookup
phase preserves master's timing modulo the borrow boundary, a
cold-neighbor SYN-ACK promotes at arrival exactly as master's does,
no token or carrier is needed, and the forward half never lingers
OPENING (`session/mod.rs:2135`). The pre-filter timing is master's
own (a filter-dropped but PROVEN SYN-ACK can promote —
master-identical, stated); the companion promote deliberately sets
only `established` and preserves the short opening deadline until the
forward ACK (`session/mod.rs:1243-1252` — stated). The contradictory
texts (the "pending machinery untouched" claim, the enqueue-promotion
claim, the "remains OPENING until the next packet" claim, the §9
"NEVER drives the establishment promote" claim) are all reconciled to
this single story.

**r113-3 (B — sixth consumer).** The establishment promote is now
consumer (vi) in the normative list: it consumes the effective
transition and is suppressed for `OverdueSkipped` AND `UpsertRefused`
(a shadowed-placeholder / divergent-identity dispatch must not mutate
the surviving K or its companion) and for a probation-flagged matched
entry — alongside the refusal/closing and identity gates.

**r113-5 (M) and r113-6 (L).** The contradictory texts are
reconciled; the refusal promotion gate is site-qualified
(`report.site == Some(Site2c) && validation == Some(Refused)`).

## 2. Consistency sweep

Assertion-checked replacements; the promote story now reads as one
account (lookup-phase, proof-gated, master's timing) across §5.2,
§5.5, §5.8, and §9. The gate (§5.1–§5.4, §5.7) is untouched for the
twenty-ninth consecutive round.

## 3. Bottom line

PLAN YES for v10.29.0.
