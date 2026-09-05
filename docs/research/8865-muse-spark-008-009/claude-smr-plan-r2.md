# Claude SMR — hostile plan review r2 (#8865)

**Subject:** plan.md r3 (`0fb63ae95`)
**Posture:** hostile. I am the plan's author; this pass exists to attack the
parts of r3 that are self-serving, and the r3 revision has one.

**Verdict: PLAN-REVISE.** Three findings, one of which is the plan committing
the exact defect it was revised to fix.

---

## S1 (blocking) — I ROUTED nine findings into a class by reading their TITLES, in the same revision that forbids routing from adjudicating

r3's headline structural claim is *"nine of 008's eleven Highs are one class"*,
and §5b of the same document now says, in bold, that file matching **routes** a
candidate and only a stated **discriminator** adjudicates it.

**I assigned H6-H11 to the packed-fold class from their section titles.** Titles
are metadata about a finding in exactly the way a file path is metadata about a
defect. The correction I wrote for Codex's objection 1 applies verbatim to the
evidence I used to satisfy Codex's objection 1.

This is not a hypothetical. **H10's title is the counterexample**: *"Multi-statement
`from` headed by declared-but-unadmitted `next-header`"*. Read as a title, the
load-bearing phrase is `declared-but-unadmitted` — that is the **admission**
mechanism, a different class, and a title-router could reasonably place H10 there.

**Adjudicated against the stated discriminator** (*does the tail fold to one
statement?*) the bodies do decide it, and they decide it my way:

| finding | body evidence for the packed-fold discriminator |
|---|---|
| H9 | "folds to one child, `discard` buried, `Action=""`"; fix: "opt `then` into packedStatements" |
| H10 | "`packedBodyChildren` chains statements … whole body discarded"; fix: "harden `packedBodyChildren`" |
| H11 | "keeps the first statement only"; fix: "opt `inet`/`inet6` into `packedStatements`" |

So the class holds. **The claim was right and the evidence was the wrong kind**,
which is the harder failure to notice because the conclusion survives
verification and therefore never asks to be re-derived.

**Two things the adjudication produced that the title-routing could not:**

1. **H10 is a DUAL member.** Its own fix line is *"admit (`from`,`next-header`)
   **AND** harden `packedBodyChildren`"* — admission class **and** packed-fold
   class, and fixing either alone leaves it live. §2b files it under one class
   and therefore under one step. **A finding needing two remedies filed under one
   is how a landed partial fix removes the reason anyone looks again** — the
   failure mode r3 itself cites, as H9, three paragraphs earlier.
2. **H9 and H10 are both ORDER-DEPENDENT, and in opposite directions.** H9:
   "Reverse order never folds." H10: "Reversed order strict-REJECTS (same leaf,
   opposite verdicts by order)." A fixture that fixes one statement order proves
   nothing about the other, and an invariant assertion cannot see order at all.
   **Step 3 owes both orders per member**, and nothing in r3 says so.

**Required:** §2b re-derived by discriminator with the body evidence shown per
row; H10 marked dual-class; both statement orders added to §6.

---

## S2 (blocking) — the eleven-High derivation is arithmetic over six quoted counts

§2b presents the derivation as `5 + (1+2+2+1) = 11`. Every one of those five
numbers is **quoted from a section header** — the same class of artifact as the
`(5)` heading and the `109 findings, 11 High` summary that §7 warns against. The
plan corrects a quoted count by quoting six more and adding them.

**The sound derivation is available and is not the one written down.** `H6`
through `H11` exist as **literal labels in the report body** (`**H6 (D2-F2,
High)**`, `**H9 (D4-F1, High)**`, …). Eleven distinct High-labelled IDs is a
count of *things*, and it is robust to any header being wrong. The arithmetic is
a coincidental cross-check that happens to agree.

That agreement is worth exactly what
[[feedback_an_independent_transcription_from_a_non_authoritative_source_agrees_with_itself]]
says it is: two readings of the same authored summary layer, not two channels.

**Required:** replace the arithmetic in §2b with the enumerated IDs, and keep the
arithmetic beside it labelled as the weaker check.

---

## S3 (non-blocking, but it is the claim most likely to be wrong) — H4 + CSA-R is a RESEMBLANCE until a discriminator decides it

r3 promotes 008 H4 and 009 CSA-R-CONFIGSTORE-002 to *"the same mechanism found
independently by two reviewers"*, and makes that pairing load-bearing: it is why
step 1 claims "a second independent member is a better instrument than a longer
look at the first".

**The evidence is a shared shape** — a write path accepts what a read path
refuses. H4's specific mechanism is a size ceiling living on the read side
(`bounded_read.go`) with no corresponding gate in `commitWithDescriptionLocked`.
CSA-R's is *same-build unreadable recovery record*. **Same-build** is the part
that does not obviously fit a size ceiling, and I have not read CSA-R's body
closely enough to say it does.

By the plan's own §5b this pairing is a **candidate routed into the class**, not
an adjudicated member — and the discriminator (*does a write path accept what a
read path refuses?*) is stated but has not been **run** against CSA-R.

The pairing may well hold; the objection is that r3 states it as established and
spends it. **If it does not hold, step 1 loses its second instrument and 009
CSA-R belongs in the residue — which would make the reported residue 3 of 15, not
2 of 15**, and the residue is the number r3 nominates as the honest output.

**Required:** mark the pairing PROVISIONAL in §2b, state that step 1 adjudicates
it before relying on it, and note that the residue count moves if it fails.

---

## What r3 got right, briefly

- **Objections 1 (process half), 2 and 5 are genuinely resolved**, not narrated.
  §5b's route/adjudicate split is a real mechanism change with a stated
  discriminator per class; §4's coverage argument now has two admissible forms
  and the packed-fold class is filed under UNKNOWN rather than assumed complete;
  §8 defers to §4 instead of contradicting it.
- **Declaring the packed-fold class incomplete is the single most valuable line
  in r3**, and it costs the plan its cleanest-looking result. Nine members across
  three rounds is evidence the boundary is still moving, and step 3 is explicitly
  barred from closing on them.
- **§7's "derive counts; do not quote them" caught its own author** — one screen
  above it. That is the rule working, at the only moment a rule can work.

## Verdict

**PLAN-REVISE.** S1 and S2 are cheap — both are re-deriving a conclusion I
already believe from evidence of the right kind, and neither changes the plan's
recommendation. S3 is a downgrade from established to provisional. **None of the
three threatens Path B**; they threaten the quality of the evidence r3 offers for
it, which after two rounds of exactly this objection is the thing under review.
