# Claude SMR hostile plan review — r1

**Verdict: PLAN-REVISE.**

Not READY-WITH-NITS. The plan has one disqualifying scope defect and three
weaker claims that would each survive a nit-level pass and should not.

---

## F1 (DISQUALIFYING) — This is a plan for 8 findings presented as a plan for 113

The plan examined **5 Highs from 008, 1 Medium (M17), and 1 High from 009** —
roughly **8 of 113**. From those it derives a **four-class map** and then
schedules "the remaining ~104" as step 5 with the words *"staleness-partition in
batches"*.

That is not a plan for 104 findings. It is a placeholder wearing a plan's
formatting, and it is exactly the shape this board has been correcting all day:
**a property of the sample described as a property of the population.**

The plan's own risk section says *"derive counts; do not quote them"* — and then
its class map is quoted from a sample it did not derive. **The four classes are
the classes visible in the Highs.** A report with 59 Mediums and 39 Lows across
five rounds and 22 batch reports will contain classes the Highs do not exhibit;
008's own R2 section is organised by *subsystem batch* (`D1-sync`, `A2-nat`,
`A7-daemon`), which is a different partition than mechanism, and the plan never
looks at it.

**Required revision:** either (a) restrict the plan's stated scope to the Highs
plus the one enumerated class and say so in the title, or (b) do a cheap
mechanical pass over all 113 finding headers to derive the class map before
claiming one. Option (a) is honest and available now; (b) is better and costs an
hour.

## F2 — Class-first is generalised from the single most cooperative class

The wire-count class enumerated in four `grep`s and partitioned completely. The
plan then recommends class-first **for all four classes**.

But the plan's own evidence contradicts the generality: the **brace-elision
class did not enumerate cheaply**. It took two purpose-built instruments, a
64-pair sweep, three census corrections, and a day — and #8859's sweep still
reports **35 of 45 rows unverified**. If class-first had been cheap there, that
class would have closed this morning.

So the recommendation should read: **class-first WHERE THE CLASS ENUMERATES;
instrument-first where it does not** — and the plan needs a stated test for
which case it is in, applied per class, before the sequencing is meaningful.

## F3 — "One change closes many findings" is not supported at the strength stated

The wire-count fix closes **two** findings (009 PHA-001, 008 M17). Two is not
"many", and it is the plan's only worked example. The claim should be dropped to
what is demonstrated: *one change closes the two live members of one class, and
prevents the next sibling from being found by a fourth report.*

The **prevention** argument is the strong one and the plan buries it. Three
independent reviews each found one member of this class; that is the cost of not
enumerating, and it is a better argument than a multiplier the evidence does not
support.

## F4 — Path C is dismissed with a statistic from an instrument that worked

The plan cites #8830's "1 defect from 32 candidate rows" against instrument-first.
That instrument found **#8844 — a live IPsec PFS silent-disable** that enumeration
had not found, and it found it only after two corrections to itself. Its cost is
real; using its *ratio* to argue against the method inverts what it demonstrated.

The honest version of the trade-off is the one the plan half-states and then
abandons: **an instrument earns its cost when the members are not enumerable by
grep.** Say that and drop the ratio.

## F5 — H4 is the highest-consequence finding, is unverified, and is sequenced second

008 H4 claims an accepted commit that **bricks the next boot** — a node that will
not come up. The plan sequences it **after** the wire-count class and marks it
"not established".

Those two facts do not sit together. If H4 is real it outranks everything else in
both reports; if it is not, that is a five-minute measurement. **Verification
order should follow consequence, not confidence** — the plan has it backwards, and
"we verified the cheap ones first" is how the expensive one waits.

---

## What the plan gets right, and should keep

- **Establishing liveness before sequencing.** Both reports are 128+ commits
  stale against a tree that closed 41 issues in their target areas; planning
  before measuring would have been the error.
- **The reject-versus-clamp discriminator.** `len(payload)/4` prefixes bounding a
  168-byte element is a bound that is 42x smaller than the thing it bounds. That
  is a genuine and reusable mechanism statement, not a restatement of the report.
- **Catching the report's internal inconsistency** — "109 findings, 11 High" vs a
  method header saying "37 not 100" vs a HIGH section headed "(5)". Deriving
  rather than quoting is correct and the plan should apply that rule to its own
  class map (see F1).
- **Refusing to convert 113 findings into 113 issues.**

## Required for PLAN-READY

1. Fix F1 by narrowing the stated scope or deriving the class map. **Blocking.**
2. Restate F2 as a per-class test rather than a global recommendation.
3. Downgrade F3's claim to what is demonstrated; promote the prevention argument.
4. Remove the #8830 ratio from the Path C argument.
5. Re-sequence H4 first, or justify in the plan why consequence does not drive
   verification order.
