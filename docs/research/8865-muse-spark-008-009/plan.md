# Plan of action — muse-spark reviews 008 + 009 (#8865)

- **Revision:** r1
- **Base:** `b24e26d3b` (master at drafting)
- **Reports:** `muse-spark-review-008` (109 findings across 5 rounds), `muse-spark-review-009` (4 High). 009 excludes 007 and 008, so the three are disjoint.
- **Status:** DRAFT — awaiting 3-way hostile review.

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

Group findings into **mechanism classes**, enumerate each class completely, fix
the class, and let one change close many findings.

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
- **Against:** #8830 showed an instrument can cost two corrections and return
  1 defect from 32 candidate rows. **An instrument is worth building when the
  class is large and the members are not enumerable by grep.** The wire-count
  class was enumerable in four commands; a detector for it would be ceremony.

**Recommendation: Path B, with Path C reserved for classes that resist
enumeration.** Apply the #8859 gate column — *does an existing gate already
handle this?* — to every candidate before calling it a defect. That column found
two already-handled rows in a 45-row set today.

## 5. Proposed sequencing

1. **Wire-count allocation class** — fix `sync_protocol.go:1231` and `:806`
   to the reject-shape the sibling already uses. Closes 009 PHA-001 and 008 M17.
   Guard: assert **rejection**, not clamping, with the payload/element size ratio
   in the failure text.
2. **008 H4** — reproduce the self-brick end to end first; it is the only
   unverified High and it is the highest consequence (a node that will not boot).
3. **Multi-statement packed fold (H1/H2/H3)** — this is live work already
   understood by the lane that landed #8856; the remaining question is which
   containers need `packedStatements` and whether the opt-in is the right shape
   or the fold should refuse.
4. **H5 reserved names** — enumerate hardcoded infrastructure names before fixing
   `mgmt` alone.
5. **The remaining ~104** — staleness-partition in batches, publishing the ratio,
   per the #8791 method: measure at the report's base AND at master, because a
   current quote settles nothing.

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
