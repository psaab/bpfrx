# Claude SMR hostile plan-review — round 108 (v10.24.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — twenty-
eighth pass; I authored the v10.24.0 fold of Codex r107's 2B/2H/2M.
Verdict: **PLAN YES**.

## 1. Fold verification

**r107-1 (B — normalization too late / promote ungated).** Verified
the mechanism: the materializer's upsert (`install.rs:310-322`,
`:345-400`) mutates before the report exists, and the promote
(`session_glue/mod.rs:1235-1253`, gating only on origin/disposition,
`promote.rs:86-107`) follows immediately. The fold makes the product
valid BY CONSTRUCTION: the materialize computes the validation
verdict (packet + anchor) and the overdue check (K's timing) BEFORE
calling the state-changing upsert, and selects the transition action
from that decision first — out-of-product combinations are
unreachable because the producer cannot create them, so nothing ever
needs undoing. The promotion path gains the explicit
`transition == OverdueSkipped` gate (independent of K's probation
flag — covering the normalized-invalid-with-non-probation-K case
Codex named).

**r107-2 (H — fallback unsafe on purge paths).** Verified: `site=None`
covers valid local hits AND purged retained lookups; mapping a purge
report to OverdueSkipped would force the MissingNeighbor into the
buffer-only arm and replay a released tuple
(`poll_descriptor/mod.rs:5057-5068`, `neighbor_dispatch.rs:272-292`).
The fold scopes the consumer-side fallback to `Some(Site2c)` reports;
an impossible `site=None` report follows master's own dispatch.

**r107-3 (B — two carriers/two drains).** The single carrier is now
stated: `displaced` lives ONLY inside `MaterializeReport`, the
resolved result carries the whole report (no separate field), and the
current-binding drain consumes exactly the current descriptor's
`report.displaced` — the `WorkerScratch` accumulator is union-only
for the once-per-batch sibling fan-out (never per-descriptor, so
descriptor 2 can never re-invalidate descriptor 1's fresh S2 alias).

**r107-4 (H — §9 empty case).** Corrected: `UpsertRefused` with no
shadowed P and a no-op promote (non-ForwardCandidate,
`promote.rs:86-90`) displaces nothing → EMPTY, and K's aliases remain
valid; K's family enters the set only when the promote actually
overwrites it.

**r107-5/6 (M/M — terminology remnants).** The §5.6 summary, the SSOT
heading (`MaterializeReport`), the §9 `ValidatorRefused` remnant, and
the "initialized None ... set only by the overdue skip" text (now
`MaterializeReport::NONE`, set from all four transitions) are all
corrected.

## 2. Consistency sweep

Assertion-checked replacements; the contract block now reads as one
coherent specification (producer ordering → report shape → carriage →
consumers → composition → set carrier → drain → timing). The gate
(§5.1–§5.4, §5.7) is untouched for the twenty-third consecutive
round.

## 3. Bottom line

PLAN YES for v10.24.0.
