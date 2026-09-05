# Plan of action — gemini-review-049 (#8869)

- **Revision:** r2 (after Codex r1 PLAN-REVISE — 8 findings, all applied)
- **Base:** `f36be93c5` (origin/master at drafting)
- **Report base:** `b0f3aba21`, which was master-identical when the review ran
- **Status:** revised. Codex r1 `PLAN-REVISE` (8 findings). AGY infra-blocked (2-of-3 exception).
- **PINNED COMPARISON SHA: `f36be93c5`.** *(Codex r1 #8.)* The census is a snapshot of **one** commit. The procedure says "the pinned tip", never "master" — master moved **142 commits in 6h15m** during this campaign, so a distribution assembled against a moving tip would be built from different repository states. Every cell records **both** SHAs: report base `b0f3aba21` and pinned tip `f36be93c5`. **If relevant changes land, affected conclusions are revalidated before implementation or closure — an older snapshot is never silently presented as current.**

## 1. What is actually in this report — derived, not quoted

Every number below is derived from the report text. **008 taught this the hard
way**: its summary header, its method header and its section heading gave three
different counts, and #8865's plan quoted one of them into its own scope line.

| property | derived | report claims | agree? |
|---|---|---|---|
| distinct finding IDs | **100** (`GEMINI-049-001`..`-100`, counted as labels) | 100 | yes |
| High | **69** | 69 | yes |
| Medium | **30** | 30 | yes |
| Low | **1** | 1 | yes |

**049's counts are honest.** That is worth stating plainly because it is the
opposite of 008, and it means the *disposition* work here does not also have to
be *reconciliation* work.

## 2. Three measured facts that set the plan's shape

### 2.1 The report is 142 commits stale, and it was 0 commits stale when written

`b0f3aba21` -> `f36be93c5` is **142 commits in 6 hours 15 minutes**. The report's
claim of *"0 commits skew; 100% verified identical to origin/master"* was **true
when it ran**. This is not a sloppy review; it is a correct review overtaken by
an unusually fast campaign that is landing fixes in exactly these files.

**Consequence: staleness must be MEASURED per finding, never assumed in either
direction.** Both errors are live — dismissing a real defect as "probably fixed",
and re-fixing something already fixed.

### 2.2 The first High sampled is already fixed — and was correct when written

`GEMINI-049-051` reports `decodePersistentNatLeasePayload` allocating from an
unchecked wire count. Checked at **the report's own base**:

```
b0f3aba21  pkg/cluster/sync_persistent_nat_lease_8121.go
           count := int(binary.LittleEndian.Uint32(buf))
           out   := make([]userspace.IdleLeaseWire, 0, count)     <- no guard
           grep -c maxRecords  ->  0
```

and at master:

```
f36be93c5  :149  if maxRecords := (len(buf)-4)/4; count < 0 || count > maxRecords {
           :150      return nil, false                            <- REJECTS
           :152  out := make([]userspace.IdleLeaseWire, 0, count)
```

Fixed by `1f75cf09c`. **The finding was right, its remedy is the one that landed,
and it is now closed by someone else's commit.**

> **A methodological note, recorded because it nearly went the other way.** I
> first called this "stale" from the master read alone, then my own routing table
> said the file had not changed — a contradiction that turned out to be neither
> instrument's fault (§2.3). Only reading the file **at the report's own base
> commit** distinguished *"wrong when written"* from *"correct then, fixed
> since"*. Those two verdicts look identical from master and mean opposite things
> about the reviewer. **Every staleness call in this plan is made at the base, not
> at the tip.**

### 2.3 The index table's Location column is not a reliable routing key

The report's §4 index table is the artifact a human reads first. In the **10
findings whose Evidence block my parser resolved, 4 name a different file** than
the index table's `Target Symbol / Location`:

| finding | index-table Location | Evidence path |
|---|---|---|
| GEMINI-049-051 | `sync_protocol.go` | `pkg/cluster/sync_persistent_nat_lease_8121.go` |
| GEMINI-049-052 | `sync.go` | `pkg/cluster/sync_conn_gen.go` |
| GEMINI-049-054 | `instance_preempt.go` | `pkg/vrrp/instance_rx.go` |
| GEMINI-049-060 | `sync_failover.go` | `pkg/cluster/sync_fence_ack_7147.go` |

**051 is the instructive one: its Location column names the file holding the
CORRECT pattern**, which the finding cites as the model to copy. A router keyed on
that column sends the finding to the file that is already right.

**This is a SAMPLE, not a census — 10 of 100, and the 10 are exactly those whose
Evidence block matched one regex, so they are biased toward one formatting.** The
claim is therefore *"the index column is unreliable"*, **not** *"40% of it is
wrong"*. Widening the parser is step 1.

**Consequence, corrected at r2 *(Codex r1 #3)*.** r1 concluded "route on the
Evidence path, never on the index table". **The counterexample is sufficient to
reject the index as authoritative; it is not sufficient to install Evidence as
its replacement.** Four differing filenames establish **disagreement, not four
index errors**, and an Evidence block can name a caller, a *safe comparison
implementation* (051 does exactly that in the other direction), or several
relevant files.

**And the 6 agreements are NOT independent negative controls — both fields can
agree on the wrong target.**

So the artifact is a **resolved-target record** per finding: the implicated
**symbol**, the relevant **paths**, and each path's **role** (defect site /
caller / comparison / test). **Ambiguous and multi-target cases are preserved as
such, never collapsed to one path.** Validate the parser against manually
resolved examples that deliberately include a misleading comparison path.
**Publish disagreement rate and resolution coverage separately; neither is an
accuracy rate.** #8865 established that a file routes and a discriminator
adjudicates; 049 adds that **you must first establish which file the report even
means, and that resolution is itself a claim needing a control.**

### 2.4 This is NOT primarily a Rust dataplane report

By cited path across all 100 index rows: **52 `pkg/` (Go control plane), 28
`userspace-dp/` (Rust), 2 `cmd/`, 1 `userspace-xdp/`**, remainder bare filenames
that are predominantly `.go`.

**Issue #8869's title says "in the RUST DATAPLANE". That is wrong and I wrote
it.** The title is being corrected. It matters operationally: it sets who reviews
this, which suites gate it, and whether `make test-rust` is even the relevant leg.

## 3. Path options

### Path A — work the 69 Highs in ID order (NOT recommended)

**Against:** §2.2 shows the first High sampled is already fixed by an unrelated
commit. ID order carries no information about liveness, and at 142 commits of
skew the *first* question for every finding is liveness.

### Path B — liveness-first triage (RECOMMENDED)

Establish a **liveness column** for all 100 before adjudicating any, using the
cheapest sound test, then work only what survives.

- **For:** the expensive step here is judgement, and staleness is decidable
  mechanically-ish and in bulk. #8859's gate column found two already-handled rows
  in a 45-row set and independently re-derived a third; the same shape applies.
- **For:** it produces a *number* the user can act on — "N of 100 still live" —
  which is what "meaningful progress" means on a 100-finding report.
- **Against:** the cheap test is unsound alone (§2.3), so step 1 must fix the
  routing key before the column is trustworthy.

### Path C — sample-and-calibrate, then decide

Adjudicate a stratified sample of ~10, publish the live/stale ratio, and choose
between A and B on the result.

- **For:** two data points already exist and they **disagree** — `GEMINI-049-004`
  (IPv6 extension-header chain exhaustion) sampled credible against master;
  `GEMINI-049-051` sampled stale. **1 of 2 is not a calibration**, it is a coin.
- **Against:** Path B's liveness column *is* this, run over the whole population
  instead of a sample, for not much more cost once the routing key is fixed.

**Recommendation: Path B**, with Path C's calibration folded in as its first
output rather than run separately.

**Running the #8865 §4 test on this plan's own class candidates** — because
#8865 spent three revisions stating a per-class test without ever applying it to
its own classes:

| | wire-count (049 members) | routing-key defect |
|---|---|---|
| mechanical predicate? | yes | yes — compare two columns |
| negative control? | yes — the fixed and safe sites | yes — the 6 of 10 that agree |
| comparable class observed to MISS? | **YES** (#8865 §4: the live member was a `strings.Split`, which no sized-allocation predicate matches) | no |
| coverage | **UNKNOWN** | sample only, **UNKNOWN** |

So the wire-count members of 049 inherit #8865's **Path C** disposition, and this
plan does not re-litigate that class.

## 4. Sequencing

1. **Fix the routing key (blocking, cheap).** Widen the Evidence-path parser to
   all 100 findings and publish the index-vs-Evidence disagreement rate as a
   **census with its own negative control** (the rows that agree). Until this
   lands, no triage column is trustworthy. **Report the parser's failure count as
   a third state — "did not resolve" is not "agrees".**
2. **Build TWO INDEPENDENT JUDGMENTS per finding — not one four-way label.**
   *(Codex r1 #1, and this is the plan's most important correction.)*

   r1's four-way column (LIVE / FIXED-SINCE / WRONG-WHEN-WRITTEN / UNRESOLVED)
   **conflates three different questions and its categories are not mutually
   exclusive.** A finding can be **wrong at the base AND currently live**, if it
   mis-described a defect that a later commit then introduced. A multi-part
   finding can be **partly fixed and partly live**. A construct can survive while
   a caller-side check removes the defect; it can disappear while a refactor
   preserves it. Forcing one label with precedence rules would produce a headline
   "N still live" that is **misleading rather than merely imprecise.**

   | judgment | question | values |
   |---|---|---|
   | **A — validity at report base `b0f3aba21`** | did the finding correctly describe the tree it claims to have read? | VALID / INVALID / **UNKNOWN** |
   | **B — defect status at pinned tip `f36be93c5`** | is there a defect there now? | LIVE / NOT-PRESENT / **UNKNOWN** |

   **Both allow UNKNOWN, and UNKNOWN is a recorded state, not a gap.** Historical
   labels are *derived* afterwards (`VALID + NOT-PRESENT` = fixed since;
   `INVALID + LIVE` = wrong description of a real defect). **Split a finding when
   its parts disagree.** Text matching produces **candidates** for A and B; it
   never establishes either.

   **Judgment B does not wait on judgment A** *(Codex r1 #2)*. Establishing an
   actionable current defect does not require proving when it originated. Only a
   **closure** as fixed-since needs both — and it needs the original defect to
   have existed *and* the current behaviour to address it. **Naming an apparent
   fix commit is evidence, not proof.**

2b. **First batch is an EFFORT CALIBRATION, not just a classification.**
   *(Codex r1 #4.)* r1 asserted the column is cheap because extraction is
   automated. **Extraction is cheap; deciding whether a claimed defect existed,
   remained reachable, and was fully corrected can cost as much as adjudication
   itself**, so "classify all 100 before adjudicating any" promises a separation
   that may not exist. Take **8-10 findings spanning straightforward,
   ambiguous, and cross-file shapes** and measure: time per defensible verdict,
   manual routing effort, and unresolved rate. **Publish those three numbers
   before committing to the full census.** Two prior samples are not calibration
   — which is an argument for measuring effort, not for skipping the measurement.

   **Confirmed serious defects are worked as they are found.** Finding 100 must
   never block action on one.

3. **Publish the A x B distribution**, with UNKNOWN counts shown as their own
   cells rather than folded. That table governs everything after it.
4. **Adjudicate the LIVE Highs**, in consequence order, 3-4 per posted verdict
   table — an aggregate is not reviewable, the sample is.

4b. **UNKNOWN Highs get an explicit investigation queue, not silence.**
   *(Codex r1 #5.)* r1's step 4 adjudicated only LIVE Highs, which **rewards
   findings that were easy to classify and strands the most consequential ones
   behind unresolved routing or semantics** — precisely the wrong selection
   pressure. Queue them by *plausible consequence x uncertainty*, with an owner
   and a revisit condition each. **An unadjudicated severity label is never
   reported as confirmed.**

   **Contract, stated once to remove r1's internal contradiction** (§4 required
   all 100 classified before any adjudication; §7 waited only on the Highs):
   **the census MAY be published with unresolved and deferred entries**, and
   prioritized investigation follows it. Classification does not gate
   adjudication of anything already resolved.
5. **Cross-report dedup — PER FINDING, and it happens EARLY, not last.**
   *(Codex r1 #6.)* 049 overlaps 007/008/009 at least at the wire-count class,
   and #8869's body claimed disjointness — **now known false and corrected on the
   issue.**

   **Sharing a defect PATTERN does not establish duplicate root cause, affected
   path, or fix coverage.** #8865's wire-count class publishes its own coverage
   as explicitly **UNKNOWN**, so it **cannot discharge** these findings by
   delegation. Each deferred finding needs a **per-ID owner, a linked
   disposition, and a coverage status**, recorded *before* expensive
   adjudication, and the census must distinguish **"confirmed resolved
   elsewhere"** from **"delegated; still unresolved"**. Unmatched members stay
   active here.

## 5. Acceptance criteria

- Every staleness verdict made **at the report's base commit**, with the base SHA
  in the cell. A verdict from the tip alone is not accepted.
- The liveness census publishes its **ratio**, its **negative control**, and its
  **unresolved count** as a separate state.
- Contents, never counts; a **liveness assertion beside every equality** — two
  arms returning zero satisfies an equality and is indistinguishable from the
  defect.
- No finding closed on "the file changed"; a file changing is routing, not
  adjudication.
- **Validation is PROPORTIONAL TO THE CLAIMED BEHAVIOUR, not to the report's
  language totals.** *(Codex r1 #7.)* r1 selected suites from the 52/28 path
  split, which is a routing signal, not an acceptance criterion.
  - A **triage census** needs no cluster run; requiring one per historical
    verdict would be waste.
  - A **local defect fix** needs focused regression checks.
  - **Anything whose correctness depends on replication, failover, rejoin or
    forwarding continuity — the HA session-sync and VRRP findings — needs
    integration/cluster validation**, and `make test-go` passing is not
    acceptance for those.
  - Cells assert **successful behaviour as well as rejection**.
  - Suites are chosen from the **resolved target and its dependencies**,
    including both languages where the target spans them.
  - **Where a conclusion depends on runtime behaviour and that validation is
    unavailable, the limitation is reported explicitly** rather than absorbed.

## 6. Risks

- **Board inflation.** 100 findings must not become 100 issues. One issue per
  confirmed class or confirmed High; adjudications live in issue comments.
- **Dismissal by staleness.** 142 commits makes "probably fixed" cheap and wrong.
  §2.2 shows a finding that WAS fixed; `GEMINI-049-004` shows one that is not.
- **The routing key.** §2.3 is unresolved until step 1; every downstream column
  inherits it.
- **My own issue text is a source of error** — the title's "RUST DATAPLANE" and
  the body's "disjoint" claim are both wrong. **A stale premise inside an issue
  body is the second most common defect on this board.**

## 7. What this plan does NOT propose

- No re-litigation of the wire-count class (owned by #8865, disposition Path C).
- No work on the 30 Medium / 1 Low until the Highs have a liveness column.
- No new instrument beyond the Evidence-path parser, which is required by step 1
  rather than speculative — per #8865 §8, selection is effort x consequence x
  additional coverage.
