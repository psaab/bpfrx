OpenAI Codex v0.153.1
--------
workdir: /var/tmp/RES8865
model: gpt-6-astra
provider: openai
approval: never
sandbox: read-only
reasoning effort: xhigh
reasoning summaries: none
session id: 01a07172-3df0-7852-84ac-8d9e3f5f6ba4
--------
user
HOSTILE round-6 plan review. REASONING ONLY. Do NOT explore the repository, do
NOT run commands, do NOT read files. Everything needed is in the text below.

Your round-5 verdict on r6 was PLAN-REVISE. You found:
 - §3's opening RESOLVED; the three-failure diagnosis RESOLVED (you said you
   would not block implementation over the maxim's wording).
 - The wire-count "NO -- measured" was NOT established: running new
   Split-aware predicates cannot establish what the ORIGINAL commands did; test
   (3) says "miss MEMBERS" while the author concluded from "no missed DEFECTS";
   and the revision gap b24e26d3b -> f36be93c5 was not addressed.
 - P3 is not independent of P1 (still requires a nearby make, adds a 12-line
   window), detects proximity rather than dataflow (heartbeat's count is
   int(data[8]), not the matched Uint read), and contains neither known LIVE
   site so has shown no sensitivity.
 - "the NEGATIVE CONTROL the class did not have" was false -- §3 and test (2)
   already had SAFE sites.
 - "bounded residual doubt" was an unsupported confidence upgrade.
 - "returned the OPPOSITE answer" was wrong, and the measurement lesson was
   overstated; "cost is not an argument against a method that worked"
   contradicts the plan's own effort x consequence x coverage rule.

The text below is r7, which accepts all of the above. Judge it on THREE things.

FIRST: for each of your r5 points, RESOLVED or NOT RESOLVED against specific r7
text. Be strict about whether r7 actually withdrew the claim or merely
annotated it while leaving the conclusion standing.

SECOND: r7 keeps the SAME recommendation (Path B for wire-count) while
withdrawing the evidence r6 offered for it, and now calls it "a decision under
acknowledged uncertainty" derived from tests (1) and (2) because test (3),
being UNKNOWN, does not fire. Is that a legitimate derivation or a third
attempt to reach a predetermined answer? Specifically: if test (3) is UNKNOWN
rather than NO, is it sound to treat it as not firing, or does an UNKNOWN on a
test whose YES forces Path C mean the plan cannot select a path at all?

THIRD: this plan has now been revised seven times, and each round you have found
either a stale claim or an over-read. Is r7 converged enough to hand to a human
for an implementation decision, or is the revision process itself now the
problem -- i.e. is the author producing ever-finer epistemic hedging on a plan
whose ACTIONS (fix two wire-count sites, opt containers into packedStatements,
verify H4, adjudicate two residue Highs) have not changed since r2 and are not
in dispute?

Answer the third question directly. If the actions are sound and the remaining
disagreement is about how confidently the evidence is described, say
PLAN-READY. Reserve PLAN-REVISE for a defect that would change what someone
DOES.

Finish with exactly one of PLAN-READY, PLAN-REVISE, PLAN-KILL, then numbered
dispositions.

=== PLAN r7 ===
# Plan of action — muse-spark reviews 008 + 009 (#8865)

- **Revision:** r7 (after Codex r5: the r6 measurement was over-read; test (3) is UNKNOWN, not NO)
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
   campaign's own #8793**. *(r6: r3-r5 called this "the strongest available argument for Path B". It is not
   an argument for either path — see §4's corrected test. Nine members establish
   that the class keeps yielding; the path choice turns on whether a mechanical
   predicate exists, and for packed fold it does not. Codex r4, correct.)*
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

Four commands over `pkg/cluster` found the sites below and **partition what they
found** completely. *(r6: r2-r4 said "enumerating **every** wire-count-driven
allocation"; §4 withdrew that completeness claim and this sentence was left
asserting it. Codex r4, correct.)*

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

### Path A — finding-first triage (NOT recommended for either class)

Adjudicate all 113 in severity order, file per finding.

- **Cost:** the 007 triage is running ~3 findings/hour with genuine measurement.
  113 findings is weeks, and the board goes to ~100 rows.
- **Against:** it re-derives per finding what a class enumeration establishes
  once. It also **repeats the exact failure that produced these reports** — 007's
  finding 03 was fixed as one instance, and its siblings are 008 M17 and 009
  PHA-001.

### Path B — class-first *(recommended for wire-count only — see the r6 test below)*

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

Build a detector for the class before **closing** it. *(r6: this previously read
"before fixing anything", which the r5 carve-out silently contradicted — Codex
r4, correct. Remediating known members and establishing class coverage are
**separate obligations**, and fixing the known members discharges neither the
instrument nor the coverage claim. C blocks the CLASS CLOSING, not the fixes.)*

- **For:** today's two instruments (positional predicate, blind-pair guard) each
  caught live defects, and the blind-pair guard caught one within an hour on
  another lane's change.
- **Against:** instruments cost real iteration — #8830 needed two corrections to
  itself. **But its 1-defect-from-32 is a YIELD measurement, not a value
  measurement**, and the one defect was a live IPsec PFS silent-disable that
  enumeration had missed. *(r7: this previously ended "cost is not an argument
  against a method that worked", which contradicts the effort x consequence x
  coverage rule two paragraphs below — **an effective method can still cost more
  than its expected benefit warrants.** Codex r5, correct. Cost is a legitimate
  input; what it is not is a substitute for the rule.)*
- **Choose on effort x consequence x ADDITIONAL COVERAGE, never on candidate
  ratio.** An apparently-enumerable class still warrants an instrument where
  enumeration has been observed to miss members — which is exactly what happened
  on #8830.

### (r5, corrected at r6) Running the §4 test on this plan's OWN classes

*(r2-r4 stated a per-class test and never applied it to either class. r5 applied
it and **fed it an input it had already conceded was unknown**. Codex r4 caught
that; the correction is below and it changes one of the two answers back.)*

| | wire-count | packed fold |
|---|---|---|
| **(1) mechanical predicate?** | yes | **no** — universe discovered by probing |
| **(2) negative control?** | yes — 2 SAFE sites correctly not flagged | partial (#8859's 18 SAME rows) |
| **(3) comparable class observed to MISS?** | **UNKNOWN — no demonstrated prior miss** (r7; r6 read this as NO and over-claimed) | yes — instruments found what enumeration missed on brace-elision |
| **(4) coverage** | **UNKNOWN** | **UNKNOWN** |

**Packed fold -> Path C, and r5 gave the right answer for a wrong reason.**
r5 argued from "nine members across three review rounds". **Recurrence is not an
enumeration failure**: successive discoveries with no census between them, or
defects introduced as the tree moved, produce the same nine. Nine examples
establish that the class keeps yielding; they establish nothing about whether a
census would have found them. *(Codex r4, correct — and this is the same
over-reach as* [[not sufficient is not not the mechanism]] *, run forwards.)*
**Test (1) already selects C on its own**: there is no mechanical predicate for
"containers whose packed tail folds lossily". That is the derivation, and it does
not need the nine.

**Wire-count -> Path B, with completeness UNKNOWN. r5's Path C was a
capitulation and is withdrawn.**

r5 scored test (3) **YES** on the `strings.Split` site, in a sentence that
**concedes the fact it needs**: *"Whether the Split grep was among the original
four or added after M17 was noticed…"*. **A predicate that would miss `Split` is
a possible blind spot; it is an observed miss only if the enumeration actually
ran without a Split search.** r5 promoted the hypothetical to an observation
because a reviewer gestured at it — **which is worse than the original error,
because the plan then carries a recommendation nobody derived.** The reviewer's
aside cannot supply the missing observation, and withdrawing it does not
automatically restore B either: B has to be derived, and it is, from tests (1)
and (2) passing and (3) not established.

### (r6, corrected at r7) Step 2a was run. Here is what it does and does NOT establish.

Three predicates over non-test `pkg/cluster` at `f36be93c5`, recorded as the
**actual commands** so this is re-runnable rather than trusted:

```
P1  grep -rnE 'make\(\[\][A-Za-z0-9_.\[\]]+, 0?,? ?count\)|make\(\[\][A-Za-z0-9_.\[\]]+, count\)' pkg/cluster/*.go
P2  grep -rnE 'strings\.(Split|Fields|SplitN)\(string\((payload|buf|b)\)'          pkg/cluster/*.go
P3  awk '/binary\.(Little|Big|Native)Endian\.Uint/{n=NR}
         n && NR>n && NR<=n+12 && /make\(\[\]/{print FILENAME":"NR; n=0}'           pkg/cluster/*.go
```

| | sites | note |
|---|---|---|
| **P1** | `sync.go:1365`, `sync.go:1397`, `sync_persistent_nat_lease_8121.go:152`, `sync_protocol.go:1231` | the class table's four |
| **P2** | `sync_protocol.go:806` | the live 008 M17 site; **P1 provably cannot reach it** — `Split` is not an allocation call |
| **P3** | `heartbeat.go:376`, `sync_auth.go:416`, `sync_conn_read.go:66`, `sync.go:1376` | 3 new, **all SAFE** — but see the corrections below |

**What this DOES establish:** the class spans **at least two syntactic forms**, so
any single-shape predicate misses one of them; and among P3's additional
candidates, **no additional live defect was found**.

**What r6 claimed and r7 withdraws — three separate over-readings, all correct
per Codex r5:**

1. **It does not resolve test (3) to NO.** The disputed fact was whether *the
   original four commands* included a Split search. **Running new, explicitly
   Split-aware predicates cannot establish what the original commands did**, and
   nothing recovers that provenance. r6 replaced an unsupported YES with an
   over-interpreted NO. **Test (3) is UNKNOWN — specifically "no demonstrated
   prior miss", which is a permissible evidentiary status and not a negative
   result.**

   There is also a reading r6 skipped: **test (3) says "miss MEMBERS", not "miss
   DEFECTS".** SAFE sites *are* members. If P3's three sites lay within the
   earlier enumeration's scope and were omitted, they are misses under the
   literal test — and the revision gap (`b24e26d3b` -> `f36be93c5`) means even
   that is not settled. **Whichever reading is intended must be stated
   consistently; r6 used the defect reading silently.**

2. **P3 is NOT independent of P1, and one of its hits is an artifact.** It still
   requires a nearby `make` and adds a 12-line window, so it shares P1's blind
   spots — indirect allocation, helper boundaries, allocation outside `make` —
   and adds one. **It detects PROXIMITY, not dataflow**, and `heartbeat.go:376`
   proves it:

   ```
   :366   ClusterID: binary.LittleEndian.Uint16(data[6:8])   <- the read P3 matched
   :370   numGroups := int(data[8])                          <- what actually sizes it
   :376   pkt.Groups = make([]HeartbeatGroup, numGroups)     <- the make P3 matched
   ```

   **The matched read and the matched allocation are unrelated values.** That
   site is not a class candidate at all, so P3's "3 new sites" is really 2 plus
   one false positive of my own predicate. *(Codex derived this from the code r6
   quoted, without running anything — the defect was legible in my own evidence.)*

   **P3 also contains neither known LIVE site**, so it has demonstrated no
   sensitivity to a live defect in the wider population it claims to reach.

3. **"The NEGATIVE CONTROL the class did not have" is false.** §3's table already
   carried SAFE sites, and test (2) already scored "yes — 2 SAFE sites". P3
   supplies **additional** controls. And a control validates the *safety
   discriminator*; it does not establish *recall*, which is what test (3) asks
   about.

**Residual doubt, stated without the upgrade r6 smuggled in.** r6 wrote "bounded
residual doubt with two cross-checking predicates behind it", which asserts a
bound it has not earned and an independence P3 does not have. **The defensible
statement: three additional sites were inspected and classified SAFE; the
syntactic forms searched are the three written above; the space of unsearched
forms is UNBOUNDED by this evidence.** Coverage stays **§4(b) UNKNOWN**.

**So how is Path B derived, if test (3) is UNKNOWN?** Not from a NO. Test (3)
gates a *forced* move to C; with no demonstrated miss it does not fire, and the
choice falls to tests (1) and (2), which wire-count passes — a mechanical
predicate exists and has negative controls. **Path B is the decision under
acknowledged uncertainty, not a derivation from evidence of coverage**, and §8's
rule stands: unknown completeness is a standing reason to *consider* an
instrument for this class, which §4b now carries.

> **The method note, corrected.** r6 said the measurement "returned the OPPOSITE
> answer" to r5's reasoning. It did not: **r5's YES lacked evidence and r6's
> search found no additional defect in a restricted candidate set — those are not
> opposite measurements of the same proposition.** The lesson r6 drew ("measure,
> don't reason about which way it goes") is also too strong, since reasoning is
> what determines whether an observation bears on the disputed input at all —
> and here it did not. **The correct lesson: replace an unsupported premise with
> a DISCRIMINATING observation when one is available at a cost worth paying;
> otherwise preserve UNKNOWN and say what you are deciding under it.** Three cheap
> greps show these greps were cheap. They show nothing about coverage questions
> in general.

**Recommendation (r7 — unchanged in action since r6, corrected in its
justification): Path C for packed fold, Path B for wire-count.** Packed fold is
derived from test (1); wire-count is a **decision under acknowledged uncertainty**
with test (3) UNKNOWN, not a derivation from a measured NO.

**On instruments under either path:** unknown completeness is, per §8, a reason
to **consider** an instrument — it is not evidence that test (3) passed, and a
retained instrument track owes a **named coverage gap** and an acceptance
condition (§6), not merely a slot in the recommendation.

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
2a. **(r6) DONE — the decisive input was measured, not scheduled.** Three
   predicates (P1 allocation-shaped, P2 `Split`-shaped, P3 count-read-shaped)
   run over non-test `pkg/cluster` at `f36be93c5`; full result in §4. **P3 found
   3 further candidates, 2 real and 1 a proximity artifact of the predicate
   itself, none of them live defects.** **§4 test (3) stays UNKNOWN — no
   demonstrated prior miss — and wire-count is Path B as a decision under that
   uncertainty**, not a derivation from a measured NO. The three predicates are
   recorded as **executable commands** in §4.

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

4b. **(r6) INSTRUMENT TRACK — packed fold (Path C), and wire-count only if
   step 2a says so.** Codex r4: the parallel instrument existed only in the
   recommendation, in no step, with no acceptance condition. Each retained
   instrument owes, before the class may be **closed**:
   - a **named coverage gap** — which variants the enumeration provably does not
     reach, stated before the instrument is built, not after;
   - a **negative control** — members it correctly does not flag;
   - **and the standing bar: success on the known members does NOT upgrade
     completeness from UNKNOWN.** An instrument that re-finds the nine has
     re-found the nine.

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
- **(r6) A class may be CLOSED only with: its enumeration, its negative control,
  its coverage form declared ((a) bounded universe or (b) UNKNOWN), and — where
  Path C applies — its instrument's named coverage gap.** Fixing every known
  member closes the members, not the class. **Remediation and coverage are
  separate obligations and neither discharges the other.**

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
I’ll review only the supplied text, distinguishing surviving overclaims from defects that would change the implementation work.
codex
The main corrections are explicit, but two old claims survive: §4(a) still asserts an “observed miss,” and step 2a still says the decisive input was measured. Those need cleanup. Neither establishes a reason to change the implementation work.
codex
PLAN-READY

1. **§3’s opening and three-failure diagnosis: RESOLVED.** “Partition what they found” limits the claim to the discovered set. The diagnosis remains usable; I would not reopen the previously accepted wording objection.

2. **Wire-count “NO — measured”: NOT RESOLVED document-wide.** The explicit withdrawal in §4 is substantive: new commands cannot establish original-command provenance; missing members differs from missing defects; and the revision gap prevents attributing omissions to the earlier enumeration. Preserving UNKNOWN adequately handles those limitations.

   But §4(a) still asserts **“the class carries an observed miss, visible in its own §3 table”**, followed by the original concession about whether the Split search existed. That is precisely the unsupported observation the correction withdraws. Under the literal selection rule, that surviving assertion would trigger C. Delete the assertion; retain the explanation of a possible blind spot.

3. **P3’s independence, dataflow, and sensitivity claims: RESOLVED, with a new overcorrection.** R7 explicitly acknowledges shared blind spots, the arbitrary window, proximity rather than dataflow, and failure to recover either known LIVE site.

   However, **“That site is not a class candidate at all” does not follow.** The supplied heartbeat snippet shows `int(data[8])` sizing `make([]HeartbeatGroup, numGroups)`: it remains a wire-count allocation candidate. The unrelated Uint read invalidates P3’s explanation of the match, not membership established through the actual count. Correct that inventory classification without inferring a new defect.

4. **“The negative control the class did not have”: RESOLVED.** R7 explicitly recognizes the pre-existing SAFE sites and distinguishes additional controls from evidence of recall. The original novelty claim is withdrawn.

5. **“Bounded residual doubt”: RESOLVED.** “The space of unsearched forms is UNBOUNDED by this evidence” genuinely withdraws the claimed bound. UNKNOWN remains the published coverage status.

6. **“Returned the opposite answer”: RESOLVED. Measurement lesson: NOT RESOLVED throughout.** The corrected method note properly distinguishes different propositions and requires a discriminating observation. But step 2a still begins **“DONE — the decisive input was measured, not scheduled.”** That heading preserves the discredited measurement claim. The searches were completed; the disputed historical input was not measured.

7. **Cost objection: RESOLVED.** R7 expressly accepts that an effective instrument can cost more than its expected benefit warrants. That is consistent with the effort × consequence × additional-coverage rule.

8. **UNKNOWN permits a decision; it does not derive B uniquely.** A rule making demonstrated misses sufficient to force C does not automatically make proof of no misses a prerequisite for B. R7 explicitly adopts an evidence-triggered override: without a demonstrated miss, that override is not activated. Under that policy, choosing B while retaining UNKNOWN is legitimate.

   Tests (1) and (2) support using the available enumeration method; they do not establish its completeness or its superiority to instrumentation. Thus **“B has to be derived, and it is” remains too strong** if presented as an evidentiary conclusion. The defensible position is a discretionary choice under incomplete evidence. UNKNOWN still requires the instrument consideration specified in §8; it cannot silently become evidence against an instrument.

   Keeping the same recommendation after withdrawing one justification does not establish predetermination. It does require acknowledging that the replacement justification supports a choice, not a uniquely compelled answer.

9. **Hand this to a human for an implementation decision now.** The stated remediation, validation, and adjudication work is sound enough to proceed. None of the surviving errors establishes a need to change that work or mandates a wire-count instrument.

   At this point, the revision process is becoming counterproductive: accumulated correction history keeps superseded assertions alive. Make the targeted textual and inventory corrections above, retain the explicit coverage uncertainty and existing acceptance obligations, and stop requiring another comprehensive plan-review round. These findings warrant cleanup of the decision record, not another implementation-design rejection.
tokens used
19,556
PLAN-READY

1. **§3’s opening and three-failure diagnosis: RESOLVED.** “Partition what they found” limits the claim to the discovered set. The diagnosis remains usable; I would not reopen the previously accepted wording objection.

2. **Wire-count “NO — measured”: NOT RESOLVED document-wide.** The explicit withdrawal in §4 is substantive: new commands cannot establish original-command provenance; missing members differs from missing defects; and the revision gap prevents attributing omissions to the earlier enumeration. Preserving UNKNOWN adequately handles those limitations.

   But §4(a) still asserts **“the class carries an observed miss, visible in its own §3 table”**, followed by the original concession about whether the Split search existed. That is precisely the unsupported observation the correction withdraws. Under the literal selection rule, that surviving assertion would trigger C. Delete the assertion; retain the explanation of a possible blind spot.

3. **P3’s independence, dataflow, and sensitivity claims: RESOLVED, with a new overcorrection.** R7 explicitly acknowledges shared blind spots, the arbitrary window, proximity rather than dataflow, and failure to recover either known LIVE site.

   However, **“That site is not a class candidate at all” does not follow.** The supplied heartbeat snippet shows `int(data[8])` sizing `make([]HeartbeatGroup, numGroups)`: it remains a wire-count allocation candidate. The unrelated Uint read invalidates P3’s explanation of the match, not membership established through the actual count. Correct that inventory classification without inferring a new defect.

4. **“The negative control the class did not have”: RESOLVED.** R7 explicitly recognizes the pre-existing SAFE sites and distinguishes additional controls from evidence of recall. The original novelty claim is withdrawn.

5. **“Bounded residual doubt”: RESOLVED.** “The space of unsearched forms is UNBOUNDED by this evidence” genuinely withdraws the claimed bound. UNKNOWN remains the published coverage status.

6. **“Returned the opposite answer”: RESOLVED. Measurement lesson: NOT RESOLVED throughout.** The corrected method note properly distinguishes different propositions and requires a discriminating observation. But step 2a still begins **“DONE — the decisive input was measured, not scheduled.”** That heading preserves the discredited measurement claim. The searches were completed; the disputed historical input was not measured.

7. **Cost objection: RESOLVED.** R7 expressly accepts that an effective instrument can cost more than its expected benefit warrants. That is consistent with the effort × consequence × additional-coverage rule.

8. **UNKNOWN permits a decision; it does not derive B uniquely.** A rule making demonstrated misses sufficient to force C does not automatically make proof of no misses a prerequisite for B. R7 explicitly adopts an evidence-triggered override: without a demonstrated miss, that override is not activated. Under that policy, choosing B while retaining UNKNOWN is legitimate.

   Tests (1) and (2) support using the available enumeration method; they do not establish its completeness or its superiority to instrumentation. Thus **“B has to be derived, and it is” remains too strong** if presented as an evidentiary conclusion. The defensible position is a discretionary choice under incomplete evidence. UNKNOWN still requires the instrument consideration specified in §8; it cannot silently become evidence against an instrument.

   Keeping the same recommendation after withdrawing one justification does not establish predetermination. It does require acknowledging that the replacement justification supports a choice, not a uniquely compelled answer.

9. **Hand this to a human for an implementation decision now.** The stated remediation, validation, and adjudication work is sound enough to proceed. None of the surviving errors establishes a need to change that work or mandates a wire-count instrument.

   At this point, the revision process is becoming counterproductive: accumulated correction history keeps superseded assertions alive. Make the targeted textual and inventory corrections above, retain the explicit coverage uncertainty and existing acceptance obligations, and stop requiring another comprehensive plan-review round. These findings warrant cleanup of the decision record, not another implementation-design rejection.
CODEX_EXIT=0
