# Claude SMR hostile plan-review — round 110 (v10.26.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — thirtieth
pass; I authored the v10.26.0 fold of Codex r109's 1B/2H/1M. Verdict:
**PLAN YES**.

## 1. Fold verification

**r109-1 (B — the post-state S2 producer).** Verified the trace:
FIN/RST skips the cache lookup (`flow_cache.rs:352-358`), so a close
can materialize S2 while an older cache entry survives, and the
following ACK consults the cache before session resolution
(`poll_descriptor/mod.rs:298-327`) — without S2 in the displaced set,
the stale entry would keep serving the tuple (exact-key invalidation,
`flow_cache.rs:1105-1120`). The fold makes the new S2 family a
first-class producer: added by the materialize/upsert on ANY
successful install/adopt (the materializer has S2 in hand,
`session_glue/mod.rs:1098-1119`) and by a successful promotion (which
can contribute both the preimage K and the resulting S2 — total
capacity remains 3 per the uniqueness accounting). The
no-P/no-predecessor `(Refused, Installed)` case now produces
{S2} — matching §9's requirement.

**r109-2 (H — fallback before promotion).** Verified: the pre-poller
gates inspected only the raw fields, so an invalid `(Some(Site2c),
Accepted, Installed)` satisfied neither gate and could reach
promotion (`promote.rs:86-139`). The fold: the producer writes ONE
derived `effective_transition` — every consumer, INCLUDING the
pre-resolved-result promotion, reads the effective transition, never
the raw fields; an invalid site-2c report's effective transition is
`OverdueSkipped`.

**r109-3 (H — second composition clause).** Now site-qualified
(`report.site == Some(Site2c)`; an impossible `site=None` report
follows master's own dispatch).

**r109-4 (M — unconditional clear/install claims).** All three
surviving spots carry the qualification: the §5.6 probation-clear
sentence ("clears on the first COMMITTED non-close packet whose
transition is NOT OverdueSkipped"), the §5.6 "the install cannot be
skipped" (now "EXCEPT by the overdue rule"), and the §9 clear test
("never on an OverdueSkipped transition").

## 2. Consistency sweep

Assertion-checked replacements; the contract block plus the three
outside-SSOT claims now agree. The gate (§5.1–§5.4, §5.7) is
untouched for the twenty-fifth consecutive round.

## 3. Bottom line

PLAN YES for v10.26.0.
