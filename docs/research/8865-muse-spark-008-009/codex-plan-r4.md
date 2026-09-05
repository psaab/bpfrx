OpenAI Codex v0.153.1
--------
workdir: /var/tmp/RES8865
model: gpt-6-astra
provider: openai
approval: never
sandbox: read-only
reasoning effort: xhigh
reasoning summaries: none
session id: 01a07164-10ba-7762-b037-4d02174934d7
--------
user
HOSTILE round-4 plan review. REASONING ONLY. Do NOT explore the repository,
do NOT run commands, do NOT read files. Everything needed is in the text below.

IMPORTANT CONTEXT: your round-3 review judged plan revision r3. The author had
already written r4 (from an independent hostile self-review) before your r3
verdict arrived, so your r3 objections about the High count and the H4/CSA-R
pairing were fixed in parallel, not in response to you. The text below is r5.

Your r3 verdict was PLAN-REVISE with objection 1 RESOLVED, objection 5 RESOLVED,
objection 2 NOT RESOLVED:

(2) The wire-count class is declared complete because it is "package bounded".
    A package supplies an outer search boundary, not an independently
    established inventory, nor an argument that four commands cover it.
    Publish the coverage argument or mark that class's completeness unknown.

You also made two remarks outside the numbered objections:
  (a) observed enumeration misses trigger Path C under the plan's own section 4
      test; nine noticed examples do not independently strengthen Path B.
  (b) section 4's class table was stale -- still listing packed fold as three
      findings and commit/load asymmetry as a single instance.

JUDGE r5 ON EXACTLY THREE THINGS.

FIRST: is objection 2 now resolved, and is remark (b) fixed? Answer each
RESOLVED or NOT RESOLVED with reasons grounded in specific r5 text.

SECOND -- and this is the one that matters most. In response to remark (a) the
author REVERSED the plan's central recommendation, from Path B (class-first
enumeration) to Path C (instrument-first) for both classes. ATTACK THAT
REVERSAL FROM BOTH SIDES:

  - Is it correct? Does the section 4 test genuinely return Path C for these two
    classes on the evidence given, or has the author over-applied a reviewer's
    aside into a flip the evidence does not support?
  - Is it a CAPITULATION? A reviewer remark is not a finding. Reversing a
    recommendation because a reviewer gestured at it, rather than because the
    evidence moved, is a worse failure than the original error -- it spends a
    real conclusion to buy agreement, and the plan then carries a recommendation
    nobody actually derived. Say plainly if that is what happened.
  - If Path C is right, is the plan's carve-out coherent -- "Path C for the
    class, but fix the two live wire-count sites in parallel because the remedy
    is known"? Or does that carve-out quietly restore Path B under another name?

THIRD: the author claims a general failure -- "a rule stated in a document does
not run itself" -- citing two instances in this plan (the section 7 count rule
missing the scope line one screen above it, and the section 4 class test never
being run on its own classes). Is that diagnosis right, or is it a flattering
abstraction that converts two concrete errors into a maxim and thereby stops
anyone looking for a third?

Finish with exactly one of PLAN-READY, PLAN-REVISE, PLAN-KILL, then numbered
dispositions.

=== PLAN r5 ===
# Plan of action — muse-spark reviews 008 + 009 (#8865)

- **Revision:** r5 (revised after Codex r3 — its objection 2 and the unrun §4 test both hold against r4)
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
| wire-count allocation | 4 sites found | 1 safe-pair, 1 fixed, 2 live — *fix is one shape*; completeness **UNKNOWN** (r5) |
| multi-statement packed fold | **9 Highs: H1, H2, H3, H6-H11**, + M-rows | completeness **UNKNOWN**; `packedStatements` opt-in per container |
| reserved-name collision | H5 | single instance; enumerate other hardcoded names |
| commit/load asymmetry | H4 + **009 CSA-R (PROVISIONAL)** | discriminator stated, not yet run against CSA-R |

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

### (r5) Running the §4 test on this plan's OWN classes — which r3 never did

*(Codex r3: "observed enumeration misses trigger Path C under §4's own test; nine
noticed examples do not independently strengthen the case for Path B." Correct,
and it changes the recommendation.)*

r2 through r4 stated a **per-class test** and then a **global recommendation**,
without running the test on either class. Running it:

| | wire-count | packed fold |
|---|---|---|
| **(1) mechanical predicate?** | yes — but see (3) | no; universe discovered by probing |
| **(2) negative control?** | yes — 2 SAFE sites correctly not flagged | partial; #8859's 18 SAME rows |
| **(3) comparable class observed to MISS?** | **YES** — the live member is `Split`, which a sized-allocation predicate does not match | **YES** — new members in all three review rounds |
| **(4) coverage** | **UNKNOWN** (r5) | **UNKNOWN** |

**Test (3) fires for BOTH classes, and test (3) says Path C regardless of (1).**
So the plan's own rule returns:

- **packed fold -> Path C (instrument-first).** Nine members across three rounds
  with a moving boundary is the strongest possible trigger. **The nine were being
  used as an argument FOR Path B; under the stated test they are an argument
  AGAINST it** — noticing nine members of an unbounded class is evidence the
  class resists enumeration, not evidence enumeration works.
- **wire-count -> Path C as well**, on the `Split` miss — though here the fix
  itself is trivial and known, so the instrument is owed *for the class*, not as
  a precondition for fixing the two live sites. **Fix them; do not close the
  class on them.**

**This is what "decided per class by a stated test" is for**, and it took an
external reviewer to point out that the plan had not once applied its own test to
its own classes. **A rule stated in a document does not run itself** — the second
instance of that in this plan, after §7's derive-don't-quote rule failed to catch
the scope line one screen above it.

**Revised recommendation: Path C for both enumerated classes, with Path B's fixes
proceeding in parallel for the two live wire-count sites.**

**On the residual preference between B and C:** The four-grep enumeration establishes that class
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
     not depend on the predicate noticing it.

     **(r5) The wire-count class was claimed under (a) and does not qualify.**
     *(Codex r3 objection 2, correct.)* r3 said its universe is "every allocation
     sized from a wire-supplied count in `pkg/cluster`, **bounded by the package,
     not by the grep**". **A package is an outer search boundary, not an
     inventory.** It says where to look; it does not enumerate what is there. The
     four commands still have to *find* every site inside it, so membership
     depends on the predicate noticing — the exact property (a) exists to
     exclude. The claim was self-exempting: I applied the standard to the class I
     was less sure of and skipped it on the one I had already published.

     **And the class carries an observed miss, visible in its own §3 table.** Of
     the four sites, three are `make(...)` and the live one is **`strings.Split`
     — not an allocation call at all**. A predicate keyed on sized allocation
     does not match `Split`, so **the member that is genuinely unbounded is the
     member such a predicate misses.** Whether the Split grep was among the
     original four or added after M17 was noticed, the class's coverage rests on
     someone having thought of a second syntactic form — **a set assembled by
     noticing.**
   - **(b) An explicit statement that completeness is UNKNOWN**, with the reason.

   **There is no third form, and (b) is not a failure state** — it is the correct
   record for a class whose universe cannot be bounded independently. A class
   published under (b) is still actionable; what it may not do is claim its
   members are all of them. **A set assembled by NOTICING is not a population.**

   Applied to this plan's own classes: **the wire-count class is (b) —
   completeness UNKNOWN** *(r5; r3 claimed (a) and was wrong, above)*. It
   partitions the four sites it found completely, and "partitions what it found"
   is a different claim from "found them all". The **packed-fold class is (b)**
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

codex
I’ll review only the supplied r5 text, testing whether the reversal follows from the evidence and whether it reaches the sequencing and acceptance criteria.
codex
The wire-count argument has a gap: showing that `Split` escapes a predicate limited to sized allocations does not show that the actual four-command enumeration missed it. Packed fold has a stronger basis for Path C, but repeated discoveries alone do not establish enumeration failure.
codex
PLAN-REVISE

1. **Objection 2 — RESOLVED.** §4 explicitly rejects “package bounded” as an inventory argument, selects form (b), and marks wire-count completeness **UNKNOWN**. It also distinguishes “partitions what it found” from “found them all.” That supplies exactly the alternative the objection requested.

   The opening of §3—“Enumerating every wire-count-driven allocation … partitions completely”—still needs reconciliation with that withdrawal. This is stale contradictory wording, not a reason to demand another coverage proof after completeness has been disclaimed.

   **Remark (b) — RESOLVED.** The §4 table now lists **nine packed-fold Highs, H1–H3 and H6–H11**, and **H4 plus CSA-R, explicitly PROVISIONAL**. Both requested table corrections are present.

2. **The reversal is justified for packed fold; it has not been derived for wire-count.**

   **Packed fold:** On the plan’s stated assessment that no usable mechanical enumeration predicate is available, §4 test (1) already selects C. The text also explicitly reports that instruments found defects brace-elision enumeration missed. Those are defensible grounds for the change.

   The replacement argument about nine discoveries is nevertheless wrong. “New members in all three review rounds” does not establish that an enumeration omitted members present within its scope when it ran. These could be successive discoveries without an intervening census, or defects introduced as the tree changed. Nine examples establish recurrence; they independently establish neither successful nor failed enumeration. Calling them “the strongest possible trigger” overstates the evidence.

   **Wire-count:** The decisive **YES** in test (3) is unsupported. A predicate restricted to explicit sized allocations would miss `Split`. But r5 expressly leaves unknown whether the actual four commands included a `Split` search from the beginning. Its sentence beginning **“Whether the Split grep was among the original four…”** concedes the missing fact.

   That establishes a possible blind spot and an inadequate completeness argument. It does **not** establish an observed enumeration miss. A search covering multiple syntactic forms does not become a demonstrated failure merely because someone had to identify those forms. This distinction resolves objection 2 without automatically selecting C.

   An argument from a *comparable* class remains possible, but r5 must establish the relevant comparability and explain what additional coverage the proposed instrument supplies. Otherwise almost any search failure anywhere becomes an unconditional instruction to instrument everything. §8’s “standing argument” from unknown completeness is a reason to consider an instrument, not evidence that test (3) passed.

   **Capitulation:** The packed-fold reversal is a legitimate correction. New observations are unnecessary when an existing rule was previously misapplied. For wire-count, **yes, the written argument makes an unsupported concession to the reviewer**: it accepts the reviewer’s conclusion by promoting a hypothetical miss into an observed one. That is the substantive failure you warned about; it does not establish the author’s private motive. My earlier aside cannot supply the missing observation. Removing this justification also does not automatically establish B: the wire-count choice needs an actual derivation.

   **The carve-out is coherent in principle but incomplete in this plan.** Fixing two confirmed sites while developing class-level detection does not restore B. Known-member remediation and establishing class coverage are separate obligations.

   However, C currently means **“Build a detector per class before fixing anything,”** so the exception changes its definition. More consequentially, §5 step 2 schedules only the fixes, and §6 requires neither a wire-count instrument nor evaluation of its additional coverage. The parallel instrument track exists only in the recommendation.

   Revise C’s definition, put each retained instrument track into §5, and give it a named coverage gap and acceptance condition in §6. Successful fixes must not discharge that obligation. Nor should an instrument’s success on known examples silently upgrade UNKNOWN completeness to complete coverage.

3. **The diagnosis is true as a symptom and inadequate as an explanation.**

   “A rule stated in a document does not run itself” accurately describes an omitted check. It does not distinguish **failing to run a check, running it on unsupported premises, and failing to propagate its result into operative instructions**. Those require different corrections.

   R5 supplies a concrete third failure immediately: it now runs the class test, but feeds it an unestablished “observed miss.” Execution alone did not protect the conclusion. The document also already records another example in §2b(0): assigning classes from titles despite §5b’s mechanism requirement.

   Recommendation propagation remains broken too: §4 still labels B **RECOMMENDED**, §2b still calls the nine findings the strongest argument for B, and the new C recommendation lacks its corresponding delivery requirements.

   The maxim becomes a flattering abstraction if these confessions substitute for checking the revised document. The required repair is concrete: substantiate each decisive test input, derive the recommendation, and reconcile that result across the active recommendation, sequencing, and acceptance criteria. R5 has not completed that chain.
tokens used
17,313
PLAN-REVISE

1. **Objection 2 — RESOLVED.** §4 explicitly rejects “package bounded” as an inventory argument, selects form (b), and marks wire-count completeness **UNKNOWN**. It also distinguishes “partitions what it found” from “found them all.” That supplies exactly the alternative the objection requested.

   The opening of §3—“Enumerating every wire-count-driven allocation … partitions completely”—still needs reconciliation with that withdrawal. This is stale contradictory wording, not a reason to demand another coverage proof after completeness has been disclaimed.

   **Remark (b) — RESOLVED.** The §4 table now lists **nine packed-fold Highs, H1–H3 and H6–H11**, and **H4 plus CSA-R, explicitly PROVISIONAL**. Both requested table corrections are present.

2. **The reversal is justified for packed fold; it has not been derived for wire-count.**

   **Packed fold:** On the plan’s stated assessment that no usable mechanical enumeration predicate is available, §4 test (1) already selects C. The text also explicitly reports that instruments found defects brace-elision enumeration missed. Those are defensible grounds for the change.

   The replacement argument about nine discoveries is nevertheless wrong. “New members in all three review rounds” does not establish that an enumeration omitted members present within its scope when it ran. These could be successive discoveries without an intervening census, or defects introduced as the tree changed. Nine examples establish recurrence; they independently establish neither successful nor failed enumeration. Calling them “the strongest possible trigger” overstates the evidence.

   **Wire-count:** The decisive **YES** in test (3) is unsupported. A predicate restricted to explicit sized allocations would miss `Split`. But r5 expressly leaves unknown whether the actual four commands included a `Split` search from the beginning. Its sentence beginning **“Whether the Split grep was among the original four…”** concedes the missing fact.

   That establishes a possible blind spot and an inadequate completeness argument. It does **not** establish an observed enumeration miss. A search covering multiple syntactic forms does not become a demonstrated failure merely because someone had to identify those forms. This distinction resolves objection 2 without automatically selecting C.

   An argument from a *comparable* class remains possible, but r5 must establish the relevant comparability and explain what additional coverage the proposed instrument supplies. Otherwise almost any search failure anywhere becomes an unconditional instruction to instrument everything. §8’s “standing argument” from unknown completeness is a reason to consider an instrument, not evidence that test (3) passed.

   **Capitulation:** The packed-fold reversal is a legitimate correction. New observations are unnecessary when an existing rule was previously misapplied. For wire-count, **yes, the written argument makes an unsupported concession to the reviewer**: it accepts the reviewer’s conclusion by promoting a hypothetical miss into an observed one. That is the substantive failure you warned about; it does not establish the author’s private motive. My earlier aside cannot supply the missing observation. Removing this justification also does not automatically establish B: the wire-count choice needs an actual derivation.

   **The carve-out is coherent in principle but incomplete in this plan.** Fixing two confirmed sites while developing class-level detection does not restore B. Known-member remediation and establishing class coverage are separate obligations.

   However, C currently means **“Build a detector per class before fixing anything,”** so the exception changes its definition. More consequentially, §5 step 2 schedules only the fixes, and §6 requires neither a wire-count instrument nor evaluation of its additional coverage. The parallel instrument track exists only in the recommendation.

   Revise C’s definition, put each retained instrument track into §5, and give it a named coverage gap and acceptance condition in §6. Successful fixes must not discharge that obligation. Nor should an instrument’s success on known examples silently upgrade UNKNOWN completeness to complete coverage.

3. **The diagnosis is true as a symptom and inadequate as an explanation.**

   “A rule stated in a document does not run itself” accurately describes an omitted check. It does not distinguish **failing to run a check, running it on unsupported premises, and failing to propagate its result into operative instructions**. Those require different corrections.

   R5 supplies a concrete third failure immediately: it now runs the class test, but feeds it an unestablished “observed miss.” Execution alone did not protect the conclusion. The document also already records another example in §2b(0): assigning classes from titles despite §5b’s mechanism requirement.

   Recommendation propagation remains broken too: §4 still labels B **RECOMMENDED**, §2b still calls the nine findings the strongest argument for B, and the new C recommendation lacks its corresponding delivery requirements.

   The maxim becomes a flattering abstraction if these confessions substitute for checking the revised document. The required repair is concrete: substantiate each decisive test input, derive the recommendation, and reconcile that result across the active recommendation, sequencing, and acceptance criteria. R5 has not completed that chain.
CODEX_EXIT=0
