# Plan of action — muse-spark reviews 008 + 009 (#8865)

- **Revision:** r2 (revised after Claude SMR + Codex both returned PLAN-REVISE)
- **Base:** `b24e26d3b` (master at drafting)
- **Reports:** `muse-spark-review-008` (109 findings across 5 rounds), `muse-spark-review-009` (4 High). 009 excludes 007 and 008, so the three are disjoint.
- **Status:** revised. Reviewer verdicts r1: Claude SMR PLAN-REVISE, Codex PLAN-REVISE, AGY infra-blocked (2 documented retries, known `--print`/`--print-timeout` defect).
- **Scope (r2, narrowed):** this plan covers the **9 Highs and the one enumerated class**. It is NOT a plan for 113 findings; the remaining ~104 are governed by the inventory process in §5b, which is a process, not a schedule.

## 1. Problem statement

113 findings arrive against a tree that has moved **128+ commits** since either
report's tip, during a campaign that closed **41 issues** concentrated in exactly
the areas both reports target. The question is not "how do we work 113 findings"
but **"which of them still describe this tree, and what is the smallest set of
changes that closes them."**

## 2. What has been established before planning

**Verified LIVE at `b24e26d3b`:**

| finding | evidence |
|---|---|
| 008 H1 | elided `security-zone z1 description hi screen s1;` -> `screen=""`, strict clean |
| 008 H2 | elided form **evades** the strict undefined-interface gate the braced form fails |
| 008 H3 | `packedStatements` opt-ins 3 -> 8, `security-zone` still not among them |
| 008 M17 | `decodeIPsecSAPayload` does an **unbounded** `strings.Split` on wire payload |
| 009 PHA-001 | DHCP `SyncLease` decoder **clamps** a wire count and allocates it |
| 008 H5 (mech) | `mgmtVRFName = "mgmt"` hardcoded, no reserved-name check in `pkg/config` |

**Not established:** 008 H4 (self-brick) is consistent with the code — the 16 MiB
ceiling lives in `bounded_read.go` on the *read* side and no size gate is visible
in `commitWithDescriptionLocked` — but has not been reproduced end-to-end here.

## 3. The finding that reframes the work: both reports found ONE member each of ONE class

Enumerating every wire-count-driven allocation in `pkg/cluster` — four commands —
partitions completely:

```
sync.go:1365, :1397                    SAFE   length check -> REJECT, count <= 255
sync_persistent_nat_lease_8121.go:152  FIXED  -> REJECT            (#8792/#8805, from report 007)
sync_protocol.go:1231   SyncLease      LIVE   -> CLAMP then allocate   (009 PHA-001)
sync_protocol.go:806    decodeIPsecSA  LIVE   -> unbounded Split       (008 M17)
```

**The discriminator is reject-versus-clamp.** The fixed site rejects; both live
sites bound the count by a *cheaper unit than the thing allocated* and proceed.
`len(payload)/4` prefixes vs a 168-byte `SyncLease` is a **42x** amplification
inside a bound that looks like a bound.

Three independent facts follow:

1. **Report 007's fix landed on one member of a class nobody enumerated.** Its
   own comment cites the "#7175 discipline"; so does the still-live `SyncLease`
   site. The discipline was cited and not applied.
2. **Two separate reviewers each found one different live member.** Neither found
   both. An enumeration finds all of them in minutes.
3. **The safe sites show the correct pattern already exists in the same file
   family** — this is not a design question, it is an application question.

## 4. Path options

### Path A — finding-first triage (the default, NOT recommended)

Adjudicate all 113 in severity order, file per finding.

- **Cost:** the 007 triage is running ~3 findings/hour with genuine measurement.
  113 findings is weeks, and the board goes to ~100 rows.
- **Against:** it re-derives per finding what a class enumeration establishes
  once. It also **repeats the exact failure that produced these reports** — 007's
  finding 03 was fixed as one instance, and its siblings are 008 M17 and 009
  PHA-001.

### Path B — class-first (RECOMMENDED)

Group findings into **mechanism classes**, enumerate each class completely, and
fix the class.

**Claim, narrowed to what is demonstrated:** the one worked example closes **two**
findings (009 PHA-001, 008 M17). That is coordinated treatment of a pair, not an
efficiency forecast for the unclassified remainder. **The stronger argument is
prevention, not multiplication:** three independent reviews each found one member
of this class, so the cost of not enumerating is a fourth report finding the
fourth member.

Known classes, with today's evidence:

| class | members | status |
|---|---|---|
| wire-count allocation | 5 enumerated | 3 safe/fixed, 2 live — *fix is one shape* |
| multi-statement packed fold | H1, H2, H3, + M-rows | mechanism understood; `packedStatements` opt-in per container |
| reserved-name collision | H5 | single instance; enumerate other hardcoded names |
| commit/load asymmetry | H4 | single instance; enumerate other accept-then-refuse gates |

- **For:** the wire-count class is already enumerated and partitioned. The
  brace-elision class produced 6 defects and 2 instruments today, and the
  instruments found what enumeration missed.
- **Against:** classing is a judgement, and a wrong class boundary hides members.
  Mitigated by requiring an **enumeration with a published ratio** per class, the
  discipline this board used on #8859 (64 swept, 43 silent, 18 SAME as negative
  control).

### Path C — instrument-first

Build a detector per class before fixing anything.

- **For:** today's two instruments (positional predicate, blind-pair guard) each
  caught live defects, and the blind-pair guard caught one within an hour on
  another lane's change.
- **Against:** instruments cost real iteration — #8830 needed two corrections to
  itself. **But its 1-defect-from-32 is a YIELD measurement, not a value
  measurement**, and the one defect was a live IPsec PFS silent-disable that
  enumeration had missed. Cost is not an argument against a method that worked.
- **Choose on effort x consequence x ADDITIONAL COVERAGE, never on candidate
  ratio.** An apparently-enumerable class still warrants an instrument where
  enumeration has been observed to miss members — which is exactly what happened
  on #8830.

**Recommendation: Path B as the default, decided PER CLASS by a stated test —
not as a global preference.** The four-grep enumeration establishes that class
enumeration *can* be cheap, not that it generally is; the brace-elision class is
the counterexample, having needed two purpose-built instruments and remaining
35-of-45 unverified.

**The per-class test, applied before choosing:**

1. **Can the class be enumerated by a mechanical predicate?** If no -> Path C.
2. **Does the enumeration have a NEGATIVE CONTROL** — members it correctly
   reports as sound? Without one it is a list, not a census. (#8859's 18 SAME
   rows are the model.)
3. **Has enumeration on a comparable class been observed to MISS members?** If
   yes -> Path C regardless of (1), because apparent enumerability is what
   #8830 disproved for its class.
4. **A published sweep ratio establishes the yield of the predicate. It does NOT
   establish that the candidate universe was complete** — that requires the
   negative control in (2) plus a positive control that re-finds a known member.

Apply the #8859 **gate column** — *does the strict path refuse, or the lenient
path warn?* — to every candidate before calling it a defect. That column found
two already-handled rows in a 45-row set today, and independently re-derived a
third that had been disqualified by hand.

## 5. Proposed sequencing

1. **008 H4 — BOUNDED VERIFICATION FIRST (time-boxed, 30 min).** It is the
   highest-consequence finding in either report (an accepted commit that bricks
   the next boot) and the only High still unverified. **Consequence sets
   verification urgency; confidence does not.** Reproduce or refute, then
   sequence remediation on the result. If it does not reproduce inside the box,
   say so and move on rather than extending.
2. **Wire-count allocation class** — fix `sync_protocol.go:1231` and `:806`
   to the reject-shape the sibling already uses. Closes 009 PHA-001 and 008 M17.
   Guard: assert **rejection**, not clamping, with the payload/element size ratio
   in the failure text.
3. **Multi-statement packed fold (H1/H2/H3)** — this is live work already
   understood by the lane that landed #8856; the remaining question is which
   containers need `packedStatements` and whether the opt-in is the right shape
   or the fold should refuse.
4. **H5 reserved names** — enumerate hardcoded infrastructure names before fixing
   `mgmt` alone.
5. **The remaining ~104** — governed by §5b, which defines the process. This
   plan does not schedule them and does not claim to cover them.

## 5b. Inventory process for the unclassified remainder

The r1 defect was scheduling ~104 findings as one step. This replaces it with a
**bounded process with completion criteria**, not a batch plan:

- **Inventory before adjudication.** Extract every finding ID, its cited files,
  and its claimed severity into one table — mechanically, from the report text.
  **Derive counts; do not quote them** (008's own header says "109 findings, 11
  High" while its method header says "37 not 100" and its HIGH section is headed
  "(5)").
- **Classify by CITED FILE, not by reading.** A finding whose files fall inside an
  already-enumerated class joins that class and inherits its verdict. This is
  cheap and it is how the remainder shrinks without per-finding judgement.
- **Findings outside every known class are the residue**, and the residue size is
  the reportable number. A class map derived from 8 findings cannot be assumed to
  cover the rest — the residue is where new classes come from.
- **Completion criterion:** every finding is either (a) in a class with a
  published enumeration, (b) adjudicated individually with a measurement, or
  (c) in the residue with its files named. **No finding is "batched".**
- **Batch size is 3-4 findings with a posted verdict table**, per the #8791
  triage, because an aggregate is not reviewable and the sample is.

## 6. Acceptance criteria (per class)

- Enumeration published with its **ratio** and its **negative control**.
- A **gate column**: does the strict path refuse, or the lenient path warn?
- Fixes asserted on **contents**, never on "commit succeeded".
- **Liveness** beside every equality assertion.
- Both elision depths where the class is elision-shaped; two instances where the
  leaf is `multi:true`.
- `Store.Load` must still accept everything it accepts today.

## 7. Risks

- **Class boundaries drawn wrong** — mitigated by published enumerations.
- **Board inflation** — 113 findings must not become 113 issues; adjudications go
  in one comment per class, issues only for confirmed defects.
- **Report numbers inherited** — 008's own header says "109 findings, 11 High"
  while its method header says "why the count is 37 and not 100" and its HIGH
  section is headed "(5)". **Derive counts; do not quote them.**

## 8. What this plan does NOT propose

- No `Format()` canonicalisation (open decision on #8850, user's call).
- No work on the 39 Low findings until the Highs and the classes are closed.
- No new instrument unless a class resists enumeration.
