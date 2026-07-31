# Claude SMR hostile plan-review — round 109 (v10.25.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — twenty-ninth
pass; I authored the v10.25.0 fold (the wholesale contract-block
rewrite) of Codex r108's 1B/2H/2M. Verdict: **PLAN YES**.

## 0. Process note

r108's findings were all contradictions BETWEEN my own splice
generations — the surgical-edit approach had accumulated five
mutually inconsistent sub-bullets in the contract block. The v10.25.0
answer is a wholesale rewrite of the block as one coherent
specification, which deletes the contradiction class rather than
patching it. Every other section's folds remain assertion-checked
targeted edits.

## 1. Fold verification

**r108-1 (B — two-drain contradiction).** The rewritten block has
exactly one drain description: the current-binding drain consumes
exactly the current descriptor's `report.displaced` (inline), and the
`WorkerScratch` batch accumulator feeds ONLY the once-per-batch
sibling fan-out at the `poll_binding` level over `left + right`
(`worker/lifecycle.rs:53-55`, `:209-225`) — never per-descriptor, so
descriptor 2 cannot re-invalidate descriptor 1's fresh S2 alias.

**r108-2 (H — fallback scoped everywhere).** The legal-product
bullet now carries the `Some(Site2c)` scope inline (an impossible
`site=None` report follows master's own dispatch, with the
released-tuple replay trace named), and the composition bullet states
that both gated transitions exist only on `Some(Site2c)` reports.

**r108-3 (H — consumer guards).** The consumer list now has the
explicit gates: (iv) the commit-time refresh checks
`report.transition == OverdueSkipped` (not only "an overdue entry");
(v) the promote is suppressed by the explicit transition gate AND
the rule-5 `validation == Some(Refused)` gate, with the §5.5
probation flag named as the third independent suppression. §9 tests
the valid-by-construction ordering (the upsert is never called on a
skipped path) and carries the `site=None` master-dispatch regression
(a purged retained lookup with a cold neighbor takes master's seed
transaction).

**r108-4/5 (M/M — terminology).** The rewrite uses only the declared
fields (`validation == Some(Refused)`, `transition == OverdueSkipped`)
— the `ValidatorRefused`-class and "normalized-invalid" phrasings are
gone; site 2b is described as reporting installation success only.

## 2. Consistency sweep

The rewritten block was read top-to-bottom as an implementer would:
the ordering (producer computes verdict+overdue pre-upsert → report
available pre-promotion → constructors initialize NONE → poller
carriage → five consumers → composition → set producers → drain →
timing → reap) is a single monotone specification with no forward
references to retracted shapes. The gate (§5.1–§5.4, §5.7) is
untouched for the twenty-fourth consecutive round.

## 3. Bottom line

PLAN YES for v10.25.0.
