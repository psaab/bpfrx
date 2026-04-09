# Summary: How `docs/cos-traffic-shaping.md` Was Produced

## Purpose

This document summarizes the prompt sequence, review steps, and design pivots that led from the original hierarchical policer idea to the current `docs/cos-traffic-shaping.md`.

The design was developed iteratively in scratch review documents before the conclusions were folded back into the repo doc. The original prompts wrote those working notes into `/tmp/*.md`. The surviving copies have now been archived under `docs/cos/` so the history can be referenced directly from the repository.

It is based on these archived working artifacts:

- [`docs/cos/hierarchical-policer-review.md`](cos/hierarchical-policer-review.md)
- [`docs/cos/cos-traffic-shaping-review-v1.md`](cos/cos-traffic-shaping-review-v1.md)
- [`docs/cos/cos-traffic-shaping-review-v2-adversarial-goals.md`](cos/cos-traffic-shaping-review-v2-adversarial-goals.md)
- [`docs/cos/cos-traffic-shaping-review-v3-admission-and-accounting.md`](cos/cos-traffic-shaping-review-v3-admission-and-accounting.md)
- [`docs/cos/cos-traffic-shaping-review-v4-many-core.md`](cos/cos-traffic-shaping-review-v4-many-core.md)
- [`docs/cos/cos-traffic-shaping-many-core-alternative.md`](cos/cos-traffic-shaping-many-core-alternative.md)
- [`docs/cos/cos-traffic-shaping-hierarchy-reset-plan.md`](cos/cos-traffic-shaping-hierarchy-reset-plan.md)
- [`docs/cos/cos-traffic-shaping-replacement-section.md`](cos/cos-traffic-shaping-replacement-section.md)
- the prompt history that produced those files

## About the Archived Working Files

The original `/tmp` files were used as design checkpoints. Each one captured either:

- a critique of the current draft
- a concrete replacement proposal
- a reset plan after the design drifted

They matter because several important ideas were introduced, rejected, or corrected there before the final repo doc was rewritten. The repository copies under `docs/cos/` preserve that surviving design trail.

The role of each archived file was:

- [`docs/cos/hierarchical-policer-review.md`](cos/hierarchical-policer-review.md): review of the original `hierarchical-policer.md` design
- [`docs/cos/cos-traffic-shaping-review-v1.md`](cos/cos-traffic-shaping-review-v1.md): first extensive review of `cos-traffic-shaping.md` after the shift from policing to shaping
- [`docs/cos/cos-traffic-shaping-review-v2-adversarial-goals.md`](cos/cos-traffic-shaping-review-v2-adversarial-goals.md): second review, focusing more explicitly on adversarial-flow behavior, queue skew, and protocol-oblivious constraints
- [`docs/cos/cos-traffic-shaping-review-v3-admission-and-accounting.md`](cos/cos-traffic-shaping-review-v3-admission-and-accounting.md): surviving archive of the later review written to the reused `cos3.md` temp path
- [`docs/cos/cos-traffic-shaping-review-v4-many-core.md`](cos/cos-traffic-shaping-review-v4-many-core.md): many-core-focused review, especially around fairness semantics under RSS spread
- [`docs/cos/cos-traffic-shaping-many-core-alternative.md`](cos/cos-traffic-shaping-many-core-alternative.md): concrete many-core alternative centered on fairness-key ownership and hierarchical leasing
- [`docs/cos/cos-traffic-shaping-hierarchy-reset-plan.md`](cos/cos-traffic-shaping-hierarchy-reset-plan.md): reset plan after the design drifted away from hierarchy and toward a CIR shortcut model
- [`docs/cos/cos-traffic-shaping-replacement-section.md`](cos/cos-traffic-shaping-replacement-section.md): cleaned-up replacement section that became the immediate source material for rewriting `docs/cos-traffic-shaping.md`

Two important caveats:

- the quoted `/tmp` paths below are historical prompt destinations, not dependencies of the final doc
- because `cos3.md` was reused, the archived file [`docs/cos/cos-traffic-shaping-review-v3-admission-and-accounting.md`](cos/cos-traffic-shaping-review-v3-admission-and-accounting.md) does not preserve the first version that was written there

This summary keeps the original `/tmp` destinations inside prompt quotes because they record what was actually requested at the time. For readability, some checkout-specific source paths are normalized, and obvious typos in quoted prompts are marked with `[sic]`. Outside those quotes, the summary points to the archived repository copies.

## High-Level Trajectory

The work moved through six stages:

1. Start with a hierarchical policer / rate limiter concept.
2. Reject that framing after finding correctness and work-conserving problems.
3. Reframe the problem as CoS traffic shaping instead of policing.
4. Iterate on fairness, enqueue control, tail latency, and scale under adversarial traffic.
5. Notice the many-core and hierarchy drift problems.
6. Reset the design around a true hierarchy and rewrite `docs/cos-traffic-shaping.md` accordingly.

## Original Design Intent

The original user intent was:

> Implement a work-conserving rate limiter, with hierarhical [sic] borrowing.  
> The system should perform well with many competing, adverserial [sic] flows while being performant, and maintain tail latency and throughput with minimal CPU cost  
> Where you have flows that unevenly hash to queues and such  
> think one elephant, versus a hundred mice or a hundred elephants vs. one mouse  
> or 100 elephants vs. 100 mice

Those goals stayed constant throughout the later CoS/shaping work, with two additional constraints reinforced repeatedly:

- it must be protocol oblivious
- it cannot rely on fast-path style exceptions

## Step-by-Step Prompt and Review History

### 1. Review the hierarchical policer design

Prompt used (normalized for repo-doc clarity):

> can you read the earlier hierarchical policer design draft and review and make suggestions in `/tmp/review.md`

Artifact:

- [`docs/cos/hierarchical-policer-review.md`](cos/hierarchical-policer-review.md)

Historical note:

- that earlier `hierarchical-policer.md` draft is not present in the current repository; the surviving review is archived in [`docs/cos/hierarchical-policer-review.md`](cos/hierarchical-policer-review.md)

Main findings:

- the borrowing/accounting model was not truly work-conserving
- the DRR fallback could admit packets after token failure without charging any real budget
- the per-worker `rate / N` model conflicted with uneven RSS and adversarial flow goals
- the design looked closer to an invalid hybrid than a correct hierarchical policer

Design impact:

- this review was the first major break from the original “hierarchical policer” framing
- it established that the design needed to move toward shaping / CoS instead of a loose token + DRR policer hybrid

### 2. Reframe the design as CoS traffic shaping

Prompt used:

> can you read `../bpfrx/docs/cos-traffic-shaping.md`
>
> this came about because I realized the following
>
> maybe this design is actually not a policer but under CoS (Class of Service) and more of a shape
>
> after you're done with what you're doing redesign
>
> so review this doc and see what i missed, what is wrong, what could be improved. Generally be really extensive in your examination of this design
>
> write your review in `/tmp/cos.md`

Artifact:

- [`docs/cos/cos-traffic-shaping-review-v1.md`](cos/cos-traffic-shaping-review-v1.md)

Main findings:

- the prose and pseudocode disagreed on CIR/PIR and scheduler semantics
- per-worker CIR broke global guarantees under RSS skew
- the host DRR structure was internally inconsistent
- the shaping point was in the wrong place in the TX pipeline
- memory, buffer, UMEM, and fairness semantics were underspecified

Design impact:

- confirmed that CoS/shaping was the right direction
- shifted the problem from “can we police?” to “how do we shape fairly and predictably?”

### 3. Re-review the CoS doc against the original adversarial goals

Prompt used:

> can you read `../bpfrx/docs/cos-traffic-shaping.md` again  
> review it for errors, enhancemenents [sic] and scale and keep in mind the original design goals are
>
> The system should perform well with many competing, adverserial [sic] flows while being performant, and maintain tail latency and throughput with minimal CPU cost  
> Where you have flows that unevenly hash to queues and such  
> think one elephant, versus a hundred mice or a hundred elephants vs. one mouse  
> or 100 elephants vs. 100 mice  
> It can’t use any fast-path style mechanisms to achieve it either. It has to be protocol oblivious
>
> write the review in `/tmp/cos2.md`

Artifact:

- [`docs/cos/cos-traffic-shaping-review-v2-adversarial-goals.md`](cos/cos-traffic-shaping-review-v2-adversarial-goals.md)

Main findings:

- the document was much better than the first CoS draft
- the largest remaining problem was that fairness was still mostly enforced at dequeue time
- under overload, elephants could still occupy the queue before mice ever got service
- DRR round length still scaled badly with host count
- the Phase 1 guarantee story was still not strong enough
- token cache / token lease design could still distort fairness and latency

Design impact:

- moved the design discussion from “better scheduler” to “fair admission and queue occupancy control”
- highlighted that queue protection is as important as dequeue arbitration

### 4. Produce a concrete revised architecture

Prompt used:

> sure but you should write that out as `/tmp/cos3.md`

Artifact at the time:

- an earlier concrete architecture draft was written to `/tmp/cos3.md`

Important note:

- that earlier draft was later overwritten by a newer review request that reused the same path
- the archived file [`docs/cos/cos-traffic-shaping-review-v3-admission-and-accounting.md`](cos/cos-traffic-shaping-review-v3-admission-and-accounting.md) contains the later review, not that original architecture draft

Design impact:

- this was the first step where the work moved from critique into replacement design
- the focus was on admission control, fairness preservation, and bounded CPU cost

### 5. Re-review a newer version of the CoS doc

Prompt used:

> can you read `../bpfrx/docs/cos-traffic-shaping.md` again  
> review it for errors, enhancemenents [sic] and scale and keep in mind the original design goals are
>
> ...same adversarial / protocol-oblivious goals...
>
> write the review in `/tmp/cos3.md`

Artifact:

- [`docs/cos/cos-traffic-shaping-review-v3-admission-and-accounting.md`](cos/cos-traffic-shaping-review-v3-admission-and-accounting.md) (the surviving archived copy)

Main findings:

- soft-cap reclaim still failed if many elephants filled the queue but none individually exceeded soft cap
- payload-byte accounting did not match UMEM frame pressure
- low-rate token leases could fall below MTU and become nonsensical
- “heaviest-host-first” was not what the reclaim algorithm actually implemented
- overflow fairness and churn costs were still weakly specified

Design impact:

- tightened the need for dual accounting, reclaim precision, and low-rate correctness
- forced the design to be more explicit about what is actually bounded in memory and service terms

### 6. Review again with many-core scaling as the main lens

Prompt used:

> can you read `../bpfrx/docs/cos-traffic-shaping.md` again  
> make sure that we support many cores to do this and remember the design doc
>
> The system should perform well with many competing, adverserial flows while being performant, and maintain tail latency and throughput with minimal CPU cost  
> ...elephants vs mice...  
> It can’t use any fast-path style mechanisms to achieve it either. It has to be protocol oblivious
>
> write the review in `/tmp/cos4.md`

Artifact:

- [`docs/cos/cos-traffic-shaping-review-v4-many-core.md`](cos/cos-traffic-shaping-review-v4-many-core.md)

Main findings:

- class fairness had become global, but host fairness was still effectively per-worker
- on many-core RSS systems, a large sender could multiply its share by spreading across workers
- global atomics and shared budgets risked cache-line ping-pong
- total leased tokens and host state could scale badly with worker count

Design impact:

- exposed the biggest scale hole in the then-current design
- made “many-core fairness semantics” a first-class design question rather than an implementation detail

### 7. Produce a concrete alternative for the many-core problem

Prompt used:

> yes to concrete alternative and write it out into `/tmp/cos5.md`

Artifact:

- [`docs/cos/cos-traffic-shaping-many-core-alternative.md`](cos/cos-traffic-shaping-many-core-alternative.md)

Main proposal:

- fairness-key ownership for fairness-enabled classes
- latency-sensitive classes remain local FIFO
- hierarchical token leasing from `global -> socket -> worker`

Design impact:

- this was an attempt to close the many-core fairness gap
- however, it introduced a new problem: the design started drifting away from an explicit hierarchy and toward ownership / special-case routing mechanics

### 8. Reset the design after hierarchy drift

Prompt used:

> It seems youe [sic] have lost the plot on hierarchical and it seems you are taking a fast path with the CIR feature, write your plan to `/tmp/cos6.md`

Artifact:

- [`docs/cos/cos-traffic-shaping-hierarchy-reset-plan.md`](cos/cos-traffic-shaping-hierarchy-reset-plan.md)

Main reset principles:

- restore a real hierarchy: `root -> class -> leaf`
- use one unified packet path
- make CIR a scheduler budget, not a shortcut
- keep the design protocol oblivious
- support many cores by sharding the hierarchy and leasing shared parent budgets, not by bypassing the hierarchy

Design impact:

- this was the decisive reset
- it corrected the two biggest conceptual drifts:
  - away from hierarchical scheduling
  - toward a CIR “fast path”

### 9. Turn the reset into a replacement section

Prompt used:

> yes and write that to `/tmp/cos7.md`

Artifact:

- [`docs/cos/cos-traffic-shaping-replacement-section.md`](cos/cos-traffic-shaping-replacement-section.md)

Main output:

- a replacement section for `docs/cos-traffic-shaping.md`
- the replacement centered the document on:
  - `root -> class -> leaf`
  - a unified scheduler
  - guarantee and surplus phases
  - no fast-path bypass
  - many-core scaling via hierarchy sharding and shared-budget leasing

Design impact:

- this became the direct template for the later rewrite of the actual doc

### 10. Patch the real document

Prompt used:

> sure

Action taken:

- `docs/cos-traffic-shaping.md` was rewritten directly to match the `cos6` reset and the `cos7` replacement section

What was changed in the doc:

- restored the explicit hierarchy
- removed the drift toward ownership-specific or shortcut semantics
- made CIR part of the normal hierarchy scheduler instead of a special path
- described the scheduler in guarantee and surplus terms
- stated clearly that shaped interfaces use one unified packet path
- preserved the core constraints:
  - protocol oblivious
  - adversarial-flow aware
  - no fast-path escape hatch
  - many-core capable

### 11. Prepare the commit message

Prompt used:

> make a commit-message for this in `/tmp/commit.md`

Artifact:

- `/tmp/commit.md`

Design impact:

- none on the design itself
- this was the final packaging step after the rewrite

## What Each Artifact Contributed

### [`docs/cos/hierarchical-policer-review.md`](cos/hierarchical-policer-review.md)

Contribution:

- killed the loose hierarchical policer approach
- established that the original model was not sound enough to keep iterating on directly

Why it mattered:

- it was the first point where the design direction changed rather than merely being tuned
- it made clear that “work-conserving with hierarchical borrowing” needed a cleaner service model than the original draft provided

### [`docs/cos/cos-traffic-shaping-review-v1.md`](cos/cos-traffic-shaping-review-v1.md)

Contribution:

- validated the CoS/shaper reframing
- identified spec contradictions and missing operational semantics

Why it mattered:

- it established that the next design needed to be an explicit shaper, not just a renamed policer
- it surfaced internal contradictions early enough that later reviews could focus on fairness and scale instead of terminology alone

### [`docs/cos/cos-traffic-shaping-review-v2-adversarial-goals.md`](cos/cos-traffic-shaping-review-v2-adversarial-goals.md)

Contribution:

- pushed the design toward fairness-aware admission and queue occupancy control

Why it mattered:

- it sharpened the distinction between dequeue fairness and overload fairness
- it made “protect mice before the queue is already full” part of the design target

### [`docs/cos/cos-traffic-shaping-review-v3-admission-and-accounting.md`](cos/cos-traffic-shaping-review-v3-admission-and-accounting.md)

Contribution:

- stressed reclaim correctness, byte/frame accounting, low-rate behavior, and overflow semantics

Why it mattered:

- it forced the design to describe real resource accounting instead of only scheduler intent
- it highlighted that correctness under pressure requires matching queue accounting to the resources that are actually exhausted

Historical note:

- [`docs/cos/cos-traffic-shaping-review-v3-admission-and-accounting.md`](cos/cos-traffic-shaping-review-v3-admission-and-accounting.md) is the archived artifact whose content comes from the later document written to the reused `cos3.md` temp path

### [`docs/cos/cos-traffic-shaping-review-v4-many-core.md`](cos/cos-traffic-shaping-review-v4-many-core.md)

Contribution:

- forced the design to confront many-core fairness and scalability directly

Why it mattered:

- it exposed that “global class fairness” was not enough if hosts could multiply their share across workers
- it turned many-core behavior into a first-order architecture concern

### [`docs/cos/cos-traffic-shaping-many-core-alternative.md`](cos/cos-traffic-shaping-many-core-alternative.md)

Contribution:

- explored a many-core alternative, but also revealed how easy it was to drift away from a real hierarchy

Why it mattered:

- it was useful as an exploration of the scale problem
- it also triggered the later reset because it showed the design was starting to solve scale by introducing special structure instead of preserving the core hierarchy

### [`docs/cos/cos-traffic-shaping-hierarchy-reset-plan.md`](cos/cos-traffic-shaping-hierarchy-reset-plan.md)

Contribution:

- reset the architecture around the actual invariant the design needed to preserve: hierarchy first

Why it mattered:

- this was the clearest corrective instruction in the entire sequence
- it explicitly rejected both hierarchy drift and a CIR “fast path” interpretation

### [`docs/cos/cos-traffic-shaping-replacement-section.md`](cos/cos-traffic-shaping-replacement-section.md)

Contribution:

- served as the direct replacement blueprint for the final doc rewrite

Why it mattered:

- it translated the reset principles into concrete replacement text
- it was the last temporary design artifact before the repo doc itself was rewritten

## Design Principles That Survived Into the Current Doc

The current `docs/cos-traffic-shaping.md` is the result of filtering all prior critique through the final hierarchy reset. The main principles that survived are:

- the design is a shaper, not a policer
- the scheduler is explicitly hierarchical: `root -> class -> leaf`
- CIR is guaranteed service budget within the same scheduler, not a side channel
- excess capacity is distributed in a surplus phase after guarantees
- fairness cannot rely only on dequeue order; admission and queue occupancy matter too
- the design must be protocol oblivious
- there can be no fast-path bypass for shaped traffic
- many-core support must come from hierarchy sharding and shared-budget leasing, not shortcut mechanisms
- the system must be robust to RSS skew and adversarial flow distributions

## Main Corrections Made Over Time

The overall design was corrected in these ways:

- from policer thinking to shaper thinking
- from token/DRR hybrid ambiguity to an explicit hierarchy
- from per-worker guarantees to globally meaningful budgeting
- from dequeue-only fairness to admission-aware fairness
- from vague scale claims to explicit many-core concerns
- from ownership-heavy special cases back to one unified packet path
- from CIR as a shortcut back to CIR as scheduler budget

## Bottom Line

`docs/cos-traffic-shaping.md` was not produced in one pass. It came from repeated critique-and-reset cycles:

- first reject the original hierarchical policer semantics
- then reframe as CoS shaping
- then harden the design against adversarial flows, queue skew, and many-core RSS
- then reset again when the design drifted away from a true hierarchy
- finally rewrite the doc around the restored hierarchical model

The key turning point was the user correction captured in [`docs/cos/cos-traffic-shaping-hierarchy-reset-plan.md`](cos/cos-traffic-shaping-hierarchy-reset-plan.md): the design had drifted away from hierarchy and was starting to treat CIR like a fast path. The final doc rewrite exists primarily to correct that drift while keeping the original performance, fairness, and protocol-oblivious goals intact.
