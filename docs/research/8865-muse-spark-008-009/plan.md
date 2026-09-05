# Plan of action — muse-spark reviews 008 + 009 (#8865)

- **Revision:** r4 (revised after Claude SMR r2 returned PLAN-REVISE on r3)
- **Base:** `b24e26d3b` (master at drafting)
- **Reports:** `muse-spark-review-008` (109 findings across 5 rounds), `muse-spark-review-009` (4 High). 009 excludes 007 and 008, so the three are disjoint.
- **Status:** revised. Verdicts r1: Claude SMR PLAN-REVISE, Codex PLAN-REVISE. r2: Codex PLAN-REVISE (objections 3 and 4 RESOLVED; 1, 2, 5 carried here). AGY infra-blocked throughout (2 documented retries, known `--print`/`--print-timeout` defect) — 2-of-3 exception applies.
- **Scope (r3, corrected):** this plan covers the **15 Highs** and the classes they fall into. It is NOT a plan for 113 findings; the remainder is governed by the routing process in §5b, which is a process, not a schedule.

> **r3 correction — the count in the r2 scope line was quoted, not derived, and it was wrong.**
> Codex r2 objected that the plan left "three of the nine Highs" undisposed. The number
> nine was mine, and it does not survive derivation. **008 has ELEVEN Highs, not five:**
> its `## HIGH findings (5)` heading covers round 1 only, and the four round sections
> add `+1, +2, +2, +1` more — H6 through H11, enumerated in §2. 009 has four. **The
> derived total is 15.**
>
> §7 of this plan already carried the rule *"derive counts; do not quote them"*, citing
> 008's own header discrepancy — and the scope line one screen above it quoted a count.
> **A rule stated in a document does not check the document.** The count is now derived
> in §2 with its per-section arithmetic shown, so the next reader can re-derive it
> instead of trusting it.

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

### 2b. The 15 Highs, derived and dispositioned (r3)

**Derivation (r4, corrected — the r3 derivation was arithmetic over quoted
headers).** r3 derived eleven as `5 + (1+2+2+1)`, every term of which is a
**section-header count** — the same artifact class §7 warns against. It corrected
a quoted count by quoting six more and adding them.

**The sound derivation counts THINGS, not headers.** `H1` … `H11` exist as
literal High-labelled IDs in 008's body (`**H6 (D2-F2, High)**`, `**H9 (D4-F1,
High)**`, …). **Eleven distinct labelled IDs**, robust to every header being
wrong. 009's Outcome table names its four by ID (`PHA-001`, `PHA-002`, `DBK-001`,
`CSA-R-CONFIGSTORE-002`). **Total 15, all fifteen named in the table below.**

The header arithmetic happens to agree, and it is kept only as the **weaker
cross-check** — two readings of one authored summary layer are one channel, not
two. Every High has a row; nothing is "batched".

| # | finding | class | disposition |
|---|---|---|---|
| 008 H1 | zone screen profile dropped, strict-clean | packed fold | §5 step 3 |
| 008 H2 | zone interface binding dropped, evades strict gate | packed fold | §5 step 3 |
| 008 H3 | packed tail drops at admitted non-opted-in sites | packed fold | §5 step 3 |
| 008 H6 | `security ipsec gateway` twin never splits; `ike-policy` loss | packed fold | §5 step 3 |
| 008 H7 | routing-instance tail with `routing-options`/`protocols` drops | packed fold | §5 step 3 |
| 008 H8 | elided BGP group `peer-as`-first drops ENTIRE neighbor set | packed fold | §5 step 3 |
| 008 H9 | REGRESSION from #8793: modifier-first `then` multi-tail | packed fold | §5 step 3 |
| 008 H10 | multi-statement `from` headed by unadmitted `next-header` | packed fold **+ admission (DUAL)** | §5 step 3 **and** step 3b |
| 008 H11 | elided `family inet` tail keeps first statement only | packed fold | §5 step 3 |
| 008 H4 | commit persists a config the boot loader refuses | commit/load asymmetry | §5 step 1 |
| 009 CSA-R-CONFIGSTORE-002 | commit-confirmed writes a same-build-unreadable recovery record | commit/load asymmetry — **PROVISIONAL** | §5 step 1 (adjudicate first) |
| 009 PHA-001 | DHCP `SyncLease` clamps a wire count and allocates it | wire-count allocation | §5 step 2 |
| 008 M17 | `decodeIPsecSAPayload` unbounded `Split` (Medium, same class) | wire-count allocation | §5 step 2 |
| 008 H5 | routing-instance `mgmt` collides with hardcoded mgmt VRF | reserved-name collision | §5 step 4 |
| 009 PHA-002 | origin-only HA strict validation permits peer policy bypass | **residue** | §5 step 5 |
| 009 DBK-001 | peer-reboot classifiers retire the corpse, never re-prime | **residue** | §5 step 5 |

**Two things this derivation changed, neither of which was visible at r2:**

0. **(r4) The class assignment above was re-derived BY DISCRIMINATOR, because
   r3 made it from the findings' section TITLES** — and a title is metadata about
   a finding in exactly the way a file path is metadata about a defect. **r3
   committed §5b's own defect inside the revision that fixed it.** H10 is the
   counterexample: its title's load-bearing phrase is *declared-but-unadmitted*,
   which reads as the **admission** class, and a title-router could reasonably
   place it there.

   Adjudicated against the stated discriminator — *does the tail fold to one
   statement?* — the bodies decide it, and they decide it the same way:

   | finding | body evidence |
   |---|---|
   | H9 | "folds to one child, `discard` buried, `Action=""`"; fix: "opt `then` into `packedStatements`" |
   | H10 | "`packedBodyChildren` chains statements … whole body discarded"; fix: "harden `packedBodyChildren`" |
   | H11 | "keeps the first statement only"; fix: "opt `inet`/`inet6` into `packedStatements`" |

   **The claim was right and the evidence was the wrong kind** — the hardest
   version to catch, because the conclusion survives verification and so never
   asks to be re-derived. **Two facts the title pass could not have produced:**

   - **H10 is DUAL-CLASS.** Its own fix line reads *"admit (`from`,`next-header`)
     **AND** harden `packedBodyChildren`"*. **Fixing either alone leaves it
     live**, so it is filed under two steps, not one. A finding needing two
     remedies filed under one is precisely how a landed partial fix removes the
     reason anyone looks again.
   - **H9 and H10 are ORDER-DEPENDENT IN OPPOSITE DIRECTIONS.** H9: *"Reverse
     order never folds."* H10: *"Reversed order strict-REJECTS — same leaf,
     opposite verdicts by order."* A fixture at one statement order proves
     nothing about the other, and an invariant assertion cannot see order at all.
     **§6 now requires both orders per member.**

1. **Nine of 008's eleven Highs are ONE class.** H6-H11 are all multi-statement
   packed-fold / brace-elision losses — ipsec gateway, routing-instance, BGP
   group, firewall `then`, firewall `from`, `family inet`. At r2 the class held
   three members drawn from the round-1 section; it holds **nine**, spread across
   six unrelated containers, and one of them (H9) is a **regression from this
   campaign's own #8793**. This is the strongest available argument for Path B,
   and it is stronger than the argument r2 actually made — which was built on the
   wire-count pair because that was the class I had enumerated.
2. **008 H4 and 009 CSA-R-CONFIGSTORE-002 are PROVISIONALLY the same mechanism,
   found independently by two reviewers** — commit accepts a record that a
   subsequent read refuses. *(r4: r3 stated this as established and spent it.
   The evidence is a shared **shape**; the class discriminator has not been RUN
   against CSA-R. H4's mechanism is a size ceiling on the read side
   (`bounded_read.go`) with no gate in `commitWithDescriptionLocked`; CSA-R's is
   a **same-build-unreadable** record, and "same-build" does not obviously reduce
   to a size ceiling.* **By this plan's own §5b that makes CSA-R a routed
   candidate, not an adjudicated member.** Step 1 adjudicates it before relying
   on it, and **if it fails, the reported residue is 3 of 15, not 2** — which
   matters because the residue is the number this plan nominates as its honest
   output.)* That is the wire-count class's exact signature (§3: two
   reviewers, one member each, neither finding both), arriving in a second class
   before this plan finished being written. **If it holds, H4's verification in step 1 gains a
   sibling to check against** — a stronger instrument than either finding alone.
   That benefit is contingent on the adjudication, and step 1 must not assume it.

**Two Highs are residue, and are named as residue rather than absorbed.**
009 PHA-002 (HA strict-validation origin gating) and DBK-001 (peer-reboot session
re-priming) belong to no class this plan has enumerated. Per §5b they stay in the
residue with their files named, and the residue is the reportable number: **2 of
15**. They are not deferred by severity — both are High — they are deferred
because *no enumerated class covers them*, which is the only honest reason.

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
   establish that the candidate universe was complete.** *(r3, per Codex r2
   objection 2 — the r2 wording said completeness "requires" the two controls,
   which asserts that passing them delivers it. It does not.)*

   **The two controls bound SOUNDNESS, not COVERAGE.** A negative control shows
   the predicate does not fire on sound members; a positive control shows it
   re-finds a member already known. **Both can pass while an entire syntactic or
   semantic variant is invisible to the predicate** — which is not hypothetical
   here: #8830's inventory was blind by construction to heads its own pass never
   asked about, and every control it had was green.

   **Coverage is therefore a SEPARATE claim needing a separate argument**, and it
   has exactly two admissible forms:

   - **(a) An independently bounded universe** — the candidate set is derived
     from something *other than the predicate itself* (a type, a generated
     table, a grammar production, a file-level enumeration), so membership does
     not depend on the predicate noticing it. The wire-count class has this: the
     universe is "every allocation sized from a wire-supplied count in
     `pkg/cluster`", bounded by the package, not by the grep.
   - **(b) An explicit statement that completeness is UNKNOWN**, with the reason.

   **There is no third form, and (b) is not a failure state** — it is the correct
   record for a class whose universe cannot be bounded independently. A class
   published under (b) is still actionable; what it may not do is claim its
   members are all of them. **A set assembled by NOTICING is not a population.**

   Applied to this plan's own classes: the wire-count class is **(a)** — package
   bounded, four commands, partitions completely. The **packed-fold class is (b)**
   — its universe is "containers whose packed tail folds lossily", which is
   discovered by probing, and nine members arriving from six unrelated containers
   across three review rounds is evidence the boundary is still moving. **This
   plan does not claim the packed-fold class is completely enumerated, and step 3
   must not be closed on the nine.**

Apply the #8859 **gate column** — *does the strict path refuse, or the lenient
path warn?* — to every candidate before calling it a defect. That column found
two already-handled rows in a 45-row set today, and independently re-derived a
third that had been disqualified by hand.

## 5. Proposed sequencing

1. **Commit/load asymmetry — BOUNDED VERIFICATION FIRST (time-boxed, 30 min).**
   Highest consequence in either report: a commit the system accepts and a
   subsequent read refuses. **Consequence sets verification urgency; confidence
   does not.**

   **r3 change: this step now has TWO members, not one.** 008 H4 (boot loader
   refuses a persisted config) and 009 CSA-R-CONFIGSTORE-002 (commit-confirmed
   writes a same-build-unreadable recovery record) are the same mechanism found
   independently by two reviewers. Verify **H4 first** — it is the one with a
   located ceiling (`bounded_read.go`, read side) and no visible size gate in
   `commitWithDescriptionLocked` — then check CSA-R against the *same*
   discriminator rather than from scratch. **A second independent member is a
   better instrument than a longer look at the first**, and at r2 this step had
   no second member because the Highs had not been derived.

   **A timeout leaves the status `unverified` — never `refuted`, never closed.**
   If it does not reproduce inside the box, record non-reproduction with what was
   tried and move on rather than extending. *(Codex r2 objection 4, RESOLVED,
   restated here because the distinction is the whole value of the time box.)*
2. **Wire-count allocation class** — fix `sync_protocol.go:1231` and `:806`
   to the reject-shape the sibling already uses. Closes 009 PHA-001 and 008 M17.
   Guard: assert **rejection**, not clamping, with the payload/element size ratio
   in the failure text.
3. **Multi-statement packed fold — NINE Highs (H1, H2, H3, H6, H7, H8, H9, H10,
   H11), not three.** Live work already understood by the lane that landed #8856.
   The remaining question is which containers need `packedStatements` and whether
   the opt-in is the right shape or the fold should **refuse** rather than
   silently keep the first statement.

   **What the r3 derivation adds to this step:**
   - The nine span six unrelated containers — ipsec gateway, routing-instance,
     BGP group, firewall `then`, firewall `from`, `family inet`. **A per-container
     opt-in scales with the containers, and the containers are still being
     discovered.** That is an argument about the *shape* of the remedy, and it
     belongs in this step rather than being settled by it.
   - **H9 is a REGRESSION from this campaign's own #8793.** A fix in this family
     re-opened a case in the same family. That is the third instance today of a
     landed partial fix removing the reason anyone would look again, and it means
     step 3 owes a **regression cell over #8793's own case**, not only over the
     new ones.
   - **This class is published under §4(b): completeness UNKNOWN.** Nine members
     arriving across three review rounds is not convergence. **Do not close step 3
     on the nine** — close it on the *discriminator* being guarded, with the nine
     as cells.
4. **H5 reserved names** — enumerate hardcoded infrastructure names before fixing
   `mgmt` alone.
3b. **(r4) The admission half of H10** — `(from, next-header)` is *declared but
   unadmitted*, and admitting it is a separate remedy from hardening
   `packedBodyChildren`. **Both are required; neither alone closes H10.** This
   step belongs to the same lane as step 3 but is a distinct cell, so that a
   green on the fold does not read as a green on the admission.

5. **The residue — 009 PHA-002 and 009 DBK-001 — and then the remaining ~98.**
   The two residue Highs are named in §2b with their mechanisms; they belong to no
   enumerated class and get individual adjudication under §5b(b), not batching.
   Everything below High is governed by §5b as a process. **This plan does not
   schedule the remainder and does not claim to cover it.**

## 5b. Inventory process for the unclassified remainder

The r1 defect was scheduling ~104 findings as one step. This replaces it with a
**bounded process with completion criteria**, not a batch plan:

- **Inventory before adjudication.** Extract every finding ID, its cited files,
  and its claimed severity into one table — mechanically, from the report text.
  **Derive counts; do not quote them** (008's own header says "109 findings, 11
  High" while its method header says "37 not 100" and its HIGH section is headed
  "(5)").
- **ROUTE by cited file. ADJUDICATE by mechanism. These are different steps and
  the r2 plan collapsed them.** *(r3, per Codex r2 objection 1.)*

  The r2 text said a finding whose files fall inside an enumerated class "joins
  that class and inherits its verdict". **A file is not a mechanism.** One file
  holds unrelated defects, and an enumerated class holds both safe and live
  members — which this very plan demonstrates in §3, where four sites in two
  files partition into SAFE, FIXED, and two LIVE. Under inherit-by-file,
  `sync_protocol.go:806` inherits from `sync.go:1365` and is marked safe. **It is
  the live one.**

  The corrected two-step:

  1. **Route (cheap, mechanical).** Cited file falls inside class C's enumerated
     file set -> the finding becomes a *candidate* of C. This is the only thing
     file matching is entitled to do.
  2. **Adjudicate (per finding, against C's discriminator).** Apply the class's
     **stated discriminator** — for wire-count, *reject vs clamp*; for packed
     fold, *does the tail fold to one statement*; for commit/load asymmetry,
     *does a write path accept what a read path refuses*. A candidate that the
     discriminator does not decide **is not a member** and drops to the residue.

  **A class without a stated discriminator cannot adjudicate anything**, so
  naming the discriminator is part of publishing the class, alongside the
  enumeration and the negative control. **Inheritance is of the DISCRIMINATOR,
  never of the VERDICT.**

- **Routing cannot shrink the residue; only adjudication can.** The r2 process
  would have reported a small residue by absorbing findings on file evidence
  alone — concealing residue rather than measuring it, which is Codex's phrasing
  and is correct. Under the corrected process the residue can *grow* when a
  candidate fails its discriminator, and that is the process working.
- **Findings outside every known class are the residue**, and the residue size is
  the reportable number. A class map derived from 8 findings cannot be assumed to
  cover the rest — the residue is where new classes come from.
- **Completion criterion:** every finding is either (a) **adjudicated into** a
  class by that class's discriminator, (b) adjudicated individually with a
  measurement, or (c) in the residue with its files named. **No finding is
  "batched", and none is placed by file alone** — (a) now requires the
  discriminator to have decided it, which is the r3 correction.
- **The residue size is a REPORTED OUTPUT, not a leftover.** §2b reports it for
  the Highs today: **2 of 15** (009 PHA-002, 009 DBK-001). A process that cannot
  produce that number is not measuring coverage.
- **Batch size is 3-4 findings with a posted verdict table**, per the #8791
  triage, because an aggregate is not reviewable and the sample is.

## 6. Acceptance criteria (per class)

- Enumeration published with its **ratio** and its **negative control**.
- A **gate column**: does the strict path refuse, or the lenient path warn?
- Fixes asserted on **contents**, never on "commit succeeded".
- **Liveness** beside every equality assertion.
- Both elision depths where the class is elision-shaped; two instances where the
  leaf is `multi:true`.
- **(r4) BOTH STATEMENT ORDERS for every packed-fold member.** H9 and H10 are
  order-dependent in opposite directions — one never folds reversed, the other
  strict-REJECTS reversed. **A cell at one order passes against the other order's
  defect**, and an invariant assertion cannot see order at all.
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
- **(r3, per Codex r2 objection 5 — this line previously read "no new instrument
  unless a class resists enumeration", which is the pre-revision policy and
  contradicts §4's selection rule two sections above it. §4 was corrected and §8
  was left standing; a corrected argument beside an uncorrected policy leaves the
  policy operative, because the policy is what someone acts on.)**
  **Instrument selection follows §4's rule and nothing else: effort x consequence
  x ADDITIONAL COVERAGE.** Resistance to enumeration is one trigger among several,
  not the precondition. An apparently-enumerable class still warrants an
  instrument where a comparable class has been observed to miss members — the
  #8830 case — and a class published under §4(b) with completeness UNKNOWN is
  itself a standing argument for one. What this plan excludes is an instrument
  built *speculatively*, with no class and no named coverage gap behind it.
