# muse-spark-007 triage plan — 22 verified Major findings

**Status:** DRAFT v1 — pending adversarial plan review

Tracking issue: #8791 · Source report: `muse-spark-review-007` (132K, external)
Base verified at: `f565c569f` (report's own base) and `b0f3aba21` (current master)

---

## 1. Issue framing

An external deep-review report asserts **22 accepted Major, High-confidence
findings** against this tree, each with a `file:line` evidence quote, a trace, a
refutation attempt, a fix direction, and a dedup note. The question this plan
answers is **not** "are they real" — the evidence is verified — but **which are
live, which are genuinely Major, and in what order they should be worked.**

The report is unusually disciplined in one respect worth recording: it was asked
for 100 findings, produced 22, and says so explicitly — *"The evidence did not
substantiate 100, so this report does not pad the result."* Eight further units
were excluded for failing review or lacking a verdict. A report that declines its
own target is more credible than one that meets it.

## 2. Honest scope/value framing

**What is verified, by me, mechanically:**

| check | result |
|---|---|
| all 22 evidence quotes vs the report's base `f565c569f` | **22/22 MATCH** |
| all 22 evidence quotes vs current master `b0f3aba21` | **22/22 MATCH** |
| finding 03 causal claim, end-to-end at current master | **CONFIRMED, figure exact** |

Finding 03 in full, because it sets the standard for what "verified" means here:
`decodePersistentNatLeasePayload` does `make([]userspace.IdleLeaseWire, 0, count)`
with `count` read straight from 4 wire bytes and no bounds check before the
allocation. `sizeof(IdleLeaseWire)` measured at 112 bytes, so `ff ff ff ff`
requests 481,036,337,040 bytes = **448.0 GiB**. The report said 448 GiB.

**What is NOT verified: twenty-one of the twenty-two causal claims.**

This is the whole value question. A verified quote establishes that the code says
what the report says it says. It does not establish that the consequence follows.
**This distinction is the single most expensive failure mode this codebase's
review process hit today** — four separate findings in one afternoon were real
observations with a mechanism attached that nobody had measured:

* a fold "producing a correct split structure that a reader ignores" — the
  container does not fold at all
* `schemaForPath` "failing on paths crossing `family`" — three successive wrong
  attributions, no defect at all
* a commit-gate "hole" — a documented, closed, deliberate posture (#4313)
* a "silent dead tunnel" on the tolerant path — it warns, by name

Every one had correct observations. **Adopting 22 fix directions on the strength
of 22 verified quotes would repeat that pattern 21 more times**, at fix-shaped
cost rather than message-shaped cost.

*If reviewers conclude the perf gain is too small to justify the churn, PLAN-KILL
is an acceptable verdict.* Here the analogous kill is: *if reviewers conclude the
report's findings cannot be verified more cheaply than they can be re-derived,
PLAN-KILL and discard the report rather than half-adopt it.*

## 3. What's already shipped / partially batched

* **Finding 03's sibling is already fixed.** The decoder's own doc comment cites
  "the #7175 discipline" — the DHCP decoder that received a physical-count clamp.
  The class is known and owned here; this instance lacks the clamp. The report
  classifies it `NEW_SIBLING_RESIDUAL`, which matches
  `feedback_the_nth_fix_in_a_family_shares_a_premise_with_the_first_three`.
* **Findings 20 and 22 sit in `pkg/config`**, where the brace-elision campaign
  (#8755/#8763/#8768/#8778/#8781/#8787) has been active all week. Re-verification
  at current master shows their evidence unchanged, but their *reachability* may
  have moved — #8781 declared `next-header`, #8778 fixed a chain-walk, #8790
  re-keyed the opt-in registry.
* **The 22 do not overlap the open board** (#8129, #8755, #8763, #8787).

## 4. Concrete design — the triage mechanism

Three gates per finding, in order, cheapest first. A finding advances only by
passing the previous gate.

**Gate A — freshness (done, mechanical).** Evidence quote still present at current
master. 22/22 pass. Cost: one script, already run and reproducible from
`docs/research/8791-muse-spark-007/verify.py`.

**Gate B — mechanism verification (the expensive gate, and the point of this plan).**
For each finding, construct the *smallest* executable check that would distinguish
"the consequence follows" from "the code says this and the consequence does not
follow". **Each check must include a positive control that fires** — an input for
which the answer is known in advance — because a check that returns "no problem"
is otherwise indistinguishable from a check that did not run.

Concretely, per class:

* **03, 04, 18** (resource exhaustion): a bounded unit test asserting the
  allocation/iteration is refused. Positive control: the pre-fix input must blow up.
* **05, 12, 16** (dataplane): these need the loss userspace cluster; a unit-level
  check can establish the code path but not the emitted packet.
* **07, 08, 10, 21** (deploy/image): hermetic, `make selftest` territory.
* **01, 02, 11, 17** (HA): `make test-failover` and siblings — these are the
  expensive ones and should be batched into one cluster session, not four.
* **20, 22** (config): unit-testable today, and closest to the team's current context.

**Gate C — severity adjudication.** Reachability and blast radius, stated as a
column and not a caveat. A finding that requires an authenticated peer is not the
same as one reachable from an unkeyed control segment; the report is careful about
this distinction already (see 03's refutation attempt) and it should be preserved.

## 5. Public API preservation

**Not applicable — this plan proposes no code.** Deliberately stated rather than
omitted: `/research` stops at PLAN-READY, and the sequencing decision belongs to
the user. Per-finding API impact is assessed in the per-finding issues that Gate C
graduates.

## 6. Hidden invariants the triage must preserve

* **Do not open 22 issues.** The board is being driven to zero; 22 unverified
  issues would invert that and each would carry an unmeasured mechanism. Issues
  are opened by Gate C, one per graduated finding.
* **Do not batch fixes across areas.** Findings 01/02/11/16/17 all touch HA sync;
  fixing them together makes a failure un-bisectable on a cluster whose smoke
  tests take minutes per run.
* **The report is evidence, not authority.** Its verdicts ("independently reviewed
  as fileable") were produced by a process this team did not run and cannot audit.
  Gate B exists precisely because those verdicts cannot be inherited.
* **Preserve the report's own self-limitation when quoting it.** It says it is
  "the validated finding set, not a claim of formal whole-tree coverage." A
  downstream reader who drops that clause converts a careful report into a
  coverage claim it never made.

## 7. Risk assessment

| class | level | reasoning |
|---|---|---|
| **Behavioral regression risk** | **LOW** (this plan) / HIGH (naive adoption) | The plan itself changes nothing. The risk lives in adopting 22 fix directions without Gate B — several fix directions are structural (e.g. 05's "ordered NAT64-then-tunnel pipeline", 16's "make the snapshot end-to-end transactional") and would be large changes justified by an unverified mechanism. |
| **Lifetime / borrow-checker risk** | **MED** | Findings 05, 12, 16 are in `userspace-dp` Rust and 12's fix direction explicitly involves frame ownership (`allocation_ptr` comparison, acquiring a frame from a different pool). That is exactly the class where a plausible fix introduces a use-after-free. |
| **Performance regression risk** | **LOW-MED** | 04 and 18 are *about* performance under lock; their fixes touch the commit path. 03's fix is a bounds check on a cold path and is free. |
| **Architectural mismatch risk** | **MED-HIGH** | 06 proposes bumping the config-snapshot wire version to 9 with a new gate; 02 proposes rejecting a live endpoint change outright. Both are policy decisions with rolling-upgrade consequences, and both are the shape that should not ride in on a bug fix. |

## 8. Test plan

* Gate A: `verify.py` re-run at whatever master is current when this plan is read.
* Gate B, per finding: the smallest executable check + a firing positive control.
* Whole-suite baseline before and after any graduated fix: **`go test ./...`
  counted by `ok` lines, not by absence of `FAIL`** — a grep for FAIL is green
  when nothing ran. Current baseline: 72 packages ok, 5 no-test-files, 0 FAIL at
  `b0f3aba21`, tree hash identical at suite start and end.
* HA findings: one batched `make test-failover` / `test-ha-crash` session on the
  loss userspace cluster, under the #1875 lock.
* Rust findings: `make test-rust` plus the dataplane canaries.

## 9. Out of scope (explicitly)

* Any code change. This is `/research`.
* The 8 units the report excluded — two needing revision, two below Major, four
  lacking a verdict. If they matter, they are a separate request.
* A whole-tree audit. The report explicitly does not claim one and neither does this.
* Re-running the external review process itself.

## 10. Open questions for adversarial review

Each of these is invitable to PLAN-KILL.

1. **Is Gate B affordable at all?** 21 mechanism verifications, several needing
   cluster time, is plausibly larger than the fixes themselves. If the honest
   answer is "verification costs more than the defects", the correct verdict may
   be to fix the three cheap security ones (03, 20, 21) and discard the rest
   unverified — which is a PLAN-KILL of this plan's central premise.
2. **Is "verified quote + unverified mechanism" actually the right model of the
   risk?** The four failures cited in §2 were produced by *this team's own lanes*
   under time pressure. An external report with a stated independent-review gate
   may have a materially lower base rate, in which case Gate B is over-engineered
   and the plan is too conservative.
3. **Does finding 03 deserve to jump the queue and ship now?** It is verified,
   the fix is a two-line bounds check on a cold path, and it is remotely
   reachable. Arguments against: it presupposes an attacker on the HA fabric,
   which is a trusted segment by design.
4. **Are 20 and 22 already dead?** Both are `pkg/config`, the area that has
   changed most this week. If the brace-elision work has already closed their
   reachability, they should be struck rather than triaged — and the check is
   cheap.
5. **Is one tracking issue right, or does it hide the findings?** #8791 keeps the
   board small but makes 22 findings invisible to anyone browsing issues. The
   alternative — 22 issues — is honest and inverts the campaign's goal.
6. **Should the HA cluster findings (01, 02, 11, 16, 17) be treated as one
   finding?** They may share a root cause in epoch/generation handling, in which
   case five fix directions are four too many.

## 11. Recommendation (pending review)

Sequence: **03 → 20/22 → 21 → the HA batch → the rest.** Rationale: 03 is verified
and cheap; 20/22 are in the team's current context and cheap to check; 21 is
security-relevant and hermetic; the HA batch needs one cluster session and should
be adjudicated for shared root cause first.
