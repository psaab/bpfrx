# Claude SMR hostile plan-review — round 111 (v10.27.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — thirty-first
pass; I authored the v10.27.0 fold of Codex r110's 1B/1M/1L. Verdict:
**PLAN YES**.

## 1. Fold verification

**r110-1 (B — effective_transition not a carried field at every
consumer).** The fold: `effective_transition` is now a carried struct
field — initialized in `MaterializeReport::NONE` at both constructors
and written by the producer — and EVERY consumer read names it:
promotion (the explicit gate), the poller carriage bullet, the
MissingNeighbor composition (both clauses now read
`effective_transition ∈ {OverdueSkipped, UpsertRefused}`), the
teardown guards, the cache-insert suppression, and the commit hooks.
The invalid `(Some(Site2c), Accepted, Installed)` case cannot reach
promotion because the promote reads the effective transition
(`OverdueSkipped` for an invalid site-2c report).

**r110-2 (M — outside-SSOT contradictions).** Each categorical claim
is now qualified: the site-2c table row ("UNLESS the existing entry
is overdue — the materialize is skipped wholesale"), the §5.2
retry-path claim ("PROVIDED its effective transition is not
OverdueSkipped"), the §5.5/§5.6 clear statements (v10.26.1), the
§5.6-adopt clear sentence, the §7 commit-hook sentence, the §9
promotion note, and the §9 clear test — all carry the
`effective_transition != OverdueSkipped` qualification.

**r110-3 (L — the e2e fixture).** §9 (ix-d): pre-seed an old cache
descriptor, process a cache-ineligible close that installs S2 with no
P/predecessor, and assert the following ACK misses the old descriptor
on the current AND sibling bindings — the exact r109-1 regression
sequence (close bypasses the cache lookup, `flow_cache.rs:352-358`;
the ACK consults it first, `poll_descriptor/mod.rs:298-327`;
exact-key invalidation, `flow_cache.rs:1105-1120`).

## 2. Consistency sweep

Assertion-checked replacements (each verified present before
substitution); the consumer-read enumeration is now identical in the
carriage bullet and the consumer bullets. The gate (§5.1–§5.4, §5.7)
is untouched for the twenty-sixth consecutive round.

## 3. Bottom line

PLAN YES for v10.27.0.
