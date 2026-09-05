# Claude SMR — hostile plan review r1 (#8869)

**Subject:** plan.md r2 (`959ab1d54`)
**Posture:** hostile. I authored r1 and r2; this pass exists to attack them.

**Verdict: PLAN-REVISE.** Four findings. The first is the one that could make the
whole plan the wrong shape, and it survived Codex's pass because Codex attacked
the census's *soundness* and never asked whether the census should be run at all.

---

## S1 (blocking) — the plan rejects the cheap sizing step by claiming the expensive one subsumes it

§3 dismisses Path C (sample-and-calibrate) with:

> *"Path B's liveness column **is** this, run over the whole population instead of
> a sample, for not much more cost once the routing key is fixed."*

**That is an argument that B subsumes C, not an argument that C is wrong to do
first** — and those differ exactly when B is expensive, which r2's own §2b now
concedes it may be.

**The unasked question is prevalence.** Two findings are sampled: `GEMINI-049-004`
credible, `GEMINI-049-051` stale. r2 correctly says *"1 of 2 is not a calibration,
it is a coin"* — and then commits to **100 classifications anyway**. Run the
arithmetic the plan never runs:

| live rate | defects found | judgments spent |
|---|---|---|
| 60% | 60 | 100 |
| 10% | **10** | **100** |

**At the low end the census costs ten judgments per defect, and a 15-finding
stratified sample would have said so for 15.** The plan cannot distinguish these
worlds and does not try. **"Not much more cost" is an estimate of the *extraction*
step**, which is cheap and automated; §2b now admits the *judgment* step may cost
as much as adjudication. **The dismissal of C was written against the cheap half.**

**Required:** either produce a prevalence estimate from the calibration batch
*before* committing to all 100 — which makes §2b a genuine gate rather than a
measurement taken en route — or state explicitly that the census is being run for
**completeness** rather than efficiency, and that its cost is accepted on those
terms. Both are defensible. Neither is what r2 says.

---

## S2 (blocking) — the calibration sample's stratification requires the classification it is meant to cost

§2b says take *"8-10 findings spanning straightforward, ambiguous, and cross-file
shapes."*

**You cannot know a finding is ambiguous or cross-file until you have resolved its
target — which is the work being measured.** The stratification presupposes its own
output. Selected by hand from titles, the sample is chosen by the same faculty
whose cost is in question, and it will be biased toward findings that *look*
tractable.

This is the trap I hit twice today in another form: **a sample assembled by
noticing is not a population**, and here it is worse, because the noticing is
performed by the process being timed.

**Required:** stratify on something available **before** resolution — cited-path
count from the index table, severity, and area code (`A1`/`C1`/`A5`…) are all
mechanical. Then report how the resolved shapes fell out **against** that
stratification. If mechanical strata do not predict effort, that is itself the
finding, and it is more useful than the timing.

---

## S3 — the pinned SHA is correct in principle and may already be operationally void

§0 pins `f36be93c5` and requires every cell to record it. **The reasoning is right
and Codex's objection was right.** But this repo moved **142 commits in 6h15m**,
and it has moved again since the pin was written — master is past `ae773cf45`
already.

So the plan requires a snapshot against a tree that will be tens of commits stale
before the census finishes, and §4 simultaneously says *"confirmed serious defects
are worked as they are found."* **Those two commitments are in direct tension:
working defects during the census changes the tree the census describes.**

r2 papers this with *"revalidate affected conclusions if relevant changes land"* —
which, at this velocity, is **continuous revalidation**, i.e. not a procedure.

**Required:** say which the artifact is. Either
**(a)** the census is a **historical snapshot** at `f36be93c5`, explicitly not a
statement about current master, and rows are revalidated only when someone acts
on them; or
**(b)** the census is **living**, each row carries its own asOf SHA, and there is
no single pinned tip. **(a) is cheaper and honest; (b) is more useful and more
work.** r2 currently claims (a)'s rigour while operating like (b).

---

## S4 — the resolved-target record moves judgment into the step the plan calls cheap

§2.3's remedy is a record carrying *"the implicated symbol, the relevant paths, and
each path's role (defect site / caller / comparison / test)."*

**Assigning a role is a judgement about the finding's content.** The plan's whole
cost model rests on routing being mechanical and adjudication being expensive; a
routing artifact that requires reading the finding well enough to classify each
path's role **has moved the expensive step earlier and renamed it.**

That may be correct — 051 proves you cannot route on a filename — but then the
model should say so rather than preserve a separation it has abandoned.

**Required:** split it. **A mechanical part** (every path the finding mentions,
extracted, no roles) is genuinely cheap and is what the parser produces. **The role
assignment is part of adjudication** and should be counted there, in §2b's timing.

---

## What r2 got right

- **Splitting the four-way column into two independent judgments is correct and
  was the plan's most important defect.** "Wrong at base AND currently live" is a
  real combination and the single label would have made the headline number
  misleading rather than imprecise.
- **Decoupling judgment B from judgment A** is the right call and makes the plan
  actionable: a current defect does not wait on its own archaeology.
- **Refusing to install Evidence as the new authority** after one counterexample
  is the correct scope for the evidence — and noting that *both fields can agree
  on the wrong target*, so the six agreements are not controls, is the sharpest
  line in the document.
- **Per-finding dedup rather than delegation**, on the grounds that #8865's
  wire-count class publishes its own coverage as UNKNOWN and therefore cannot
  discharge anything, is exactly right and is the kind of cross-issue reasoning
  that normally goes missing.

## Verdict

**PLAN-REVISE.** S1 and S2 are cheap and change what gets done first. S3 and S4
are honesty repairs to the cost model rather than changes to the work. **None of
them threatens the two-judgment column, which is the plan's real content.**
