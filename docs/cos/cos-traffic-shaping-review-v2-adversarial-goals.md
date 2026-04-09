Review: `docs/cos-traffic-shaping.md`

Overall assessment

This revision is substantially better than the previous one. The document fixed several of the largest structural issues:

- it now models a shaper, not a policer
- the service model is more explicit
- per-worker `rate/N` partitioning is gone
- the queue/host data structure is now coherent
- the shaper owns TX ordering instead of feeding a persistent FIFO after itself
- the benchmark plan is much more honest than the old nanosecond tables

So directionally, this is much closer to something implementable.

However, against the original design goals:

- many competing adversarial flows
- uneven RSS / queue hashing
- minimal CPU cost
- preserved throughput and tail latency
- no "fast-path style" escape hatches
- protocol-oblivious behavior

there are still several serious problems. The biggest remaining issue is that the document is still stronger on dequeue fairness than on admission fairness, and under adversarial overload that distinction matters a lot.

Bottom line

I would not reject this design outright. I would say it is now a strong draft with a handful of still-critical issues that need to be resolved before implementation. The most important ones are:

1. queue-level tail drop still lets elephants crowd mice out before DRR can help
2. DRR host-round length scales badly and can destroy tail latency at high host counts
3. Phase 1 CIR guarantees are not actually guaranteed by the current loop structure
4. shared token caches create token hoarding, coarse bursts, and low-rate distortion
5. several scale claims undercount the real atomic, hash, and churn overhead

What improved

Compared to the earlier version, these are real improvements:

- The scope/non-goals section at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L5) is clearer and more honest.
- The service model at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L41) is much better defined.
- Shared class/aggregate buckets at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L139) now match the stated RSS-skew goal.
- The queue ownership fix at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L220) removes the old impossible "host ranges into parent VecDeque" design.
- Direct TX ownership at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L248) is the right call.
- The benchmark section at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1331) is much better than pretending exact hot-path costs are already known.

Critical findings

1. Queue-level tail drop means mice are not actually protected under overload.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L787)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L823)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1183)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1211)

The doc claims outcomes like:

- "mice get 0% loss"
- "mouse is NEVER dropped"

But the actual enqueue path enforces queue-level byte/frame limits, not per-host limits. That means:

- a few heavy hosts can fill the queue buffer first
- later mouse packets can be dropped at enqueue before DRR ever sees them
- DRR only decides who gets service among already-admitted packets

This is the single biggest mismatch between the stated goal and the proposed design.

If you really want one elephant vs 100 mice to behave well under queue pressure, you need an admission control story such as:

- per-host byte/frame caps
- per-host reserved minimum queue budget
- longest-queue drop or heaviest-host drop
- head-drop on dominant hosts instead of pure queue tail-drop

Without one of those, the dequeue scheduler is too late to protect mice.

2. The DRR round length explodes with active host count and directly conflicts with the tail-latency goal.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1191)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1218)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1307)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1396)

The document itself computes a 50 ms round in the `100 elephants vs 1 mouse` example. That is already a warning sign.

At larger host counts, this gets much worse:

- `101 hosts * 64 KB` at `1 Gbps` is about `50 ms` per round
- `1000 hosts * 64 KB` at `10 Gbps` is about `51 ms` per round
- `10,000 hosts * 64 KB` at `10 Gbps` is about `512 ms` per round
- `10,000 hosts * 64 KB` at `1 Gbps` is about `5.1 s` per round

That means a newly arrived mouse packet can wait up to roughly one host-round before service if it misses its turn. That is fundamentally at odds with "maintain tail latency" at large host counts.

This is the main scaling tradeoff the doc still underestimates:

- large quantum: lower CPU, worse latency/fairness granularity
- small quantum: better latency, much higher CPU

The doc needs to confront that directly instead of treating 64 KB as if it obviously scales.

I would recommend:

- host DRR only on BE/bulk queues, never on latency-sensitive queues
- quantum tied to queue rate and active host count, not a fixed static number
- explicit worst-case inter-service-delay analysis per queue class

3. Phase 1 CIR guarantees are not actually guaranteed by the current loop structure.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L86)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L102)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L487)

The prose says all backlogged queues are served up to CIR before priority applies to surplus.

But the implementation sketch does:

- fixed queue order `0..8`
- a shared frame budget
- stop when `budget == 0`

That means:

- earlier queues can consume the cycle budget first
- later queues may receive no Phase 1 service this cycle
- if this repeats, short-term guarantee and latency become queue-index dependent

Even if long-term throughput averages out, that is not the same as honoring the guarantee as described.

To make the guarantee phase credible, I would recommend:

- a rotating start index across cycles
- or Phase 1 deficit counters too, not just Phase 2
- or a byte-budget service plan per queue rather than "walk queues until budget is gone"

As written, the semantics are stronger than the algorithm.

4. Shared token caches will strand tokens and distort both fairness and low-rate shaping.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L139)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L425)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L687)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1358)

The fully shared buckets are conceptually right, but the local caching story is still too optimistic.

Two concrete problems:

1. Token hoarding

A worker can claim:

- aggregate tokens
- queue CIR tokens
- queue PIR tokens

and then go idle or become temporarily unschedulable. Those claimed tokens are now stranded locally rather than available to the actually busy worker.

That weakens the "true global guarantees regardless of RSS distribution" claim unless you define:

- when unused local tokens are returned
- whether local caches expire
- whether idle workers flush caches back to shared pools

2. Low-rate burst distortion

The fixed 64 KB batch is too coarse at low rates:

- at `10 Mbps`, `64 KB` is about `52 ms` of traffic
- at `100 Mbps`, `64 KB` is about `5.2 ms`

So a worker can claim tens of milliseconds worth of service in one atomic batch. That is bad for:

- shaping smoothness
- tail latency for competing queues
- short-window rate accuracy

The batch size needs to be dynamic, probably bounded by something like:

- `min(max_batch, burst/8, rate * target_interval)`

not a single hard-coded number for all rates and queues.

5. The CPU cost model is still too optimistic for the actual scale target.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L169)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L351)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1307)

The document correctly moved away from fake nanosecond tables, but the narrative is still a little too optimistic.

What the doc undercounts:

- there are not just aggregate atomics, but also per-queue CIR and PIR atomics
- refill CAS happens per pool, not just once
- host DRR requires per-packet hash lookup on enqueue
- per-host `VecDeque` allocation/churn is not free
- cache locality gets worse with thousands of active hosts

In a many-host adversarial case, the real hot path is not just:

- "O(1) enqueue + O(1) dequeue"

It is:

- hash lookup on hostile keys
- pointer chasing in active lists
- poor locality across many host subqueues
- multiple shared-pool refills

Asymptotic `O(1)` is fine, but the doc should stop short of implying that means "cheap enough" automatically.

6. `FxHashMap` is a poor default if "adversarial" is part of the requirement.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L448)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1328)

If the requirement explicitly includes adversarial flows, then using `FxHashMap` for public traffic keys needs stronger justification.

`FxHashMap` is fast, but it is not collision-hardened. If the threat model includes an attacker controlling many source keys, then a collision-friendly hash choice is the wrong default.

At minimum the doc should justify the choice. More likely, it should use:

- a randomized hash
- or a fixed-size shard table with bounded collision chains
- or another structure with more predictable hostile-key behavior

7. The design still has a bypass inconsistency for locally generated and cross-binding traffic.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L248)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L263)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1158)

The doc says:

- every forwarded packet goes through the shaper

But earlier it also says `drain_pending_tx()` still handles:

- locally generated packets
- cross-binding forwards

If any of those ultimately egress the shaped interface without being enqueued into CoS, then the "every forwarded packet" claim is false, and rate accounting can be violated.

This needs a crisp rule:

- either every packet that egresses a shaped interface must go through the CoS queueing point
- or the doc must explicitly carve out exceptions and explain their accounting impact

Right now the two sections do not fully agree.

8. The TX-ring backpressure story is missing essential requeue metadata.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L274)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L663)

The design says frames that could not be inserted are returned to the front of their class queues, which is correct in principle.

But the implementation note explicitly says:

- this requires `queue_id` stored in `QueuedFrame`
- omitted for brevity

That is not a minor omission. It is necessary state. And if host fairness is enabled, you also need to restore the frame to:

- the correct queue
- the correct host subqueue
- the correct head position relative to earlier packets for that host

The doc should include the actual required metadata rather than hand-waving this away.

9. The runtime UMEM reclaim policy does not match the fairness goal.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L812)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L852)

The current reclaim policy is:

- find the lowest-priority non-empty queue
- drop one packet from it

But inside a fair queue, that is too blunt. It does not answer:

- which host loses the packet
- whether the drop hits the dominant elephant or a mouse
- whether the packet is really the oldest packet in the queue

Also, `reclaim_lowest_priority()` uses `dequeue()`, which sounds like scheduler dequeue order, not necessarily oldest packet order.

If the system is meant to be resilient to elephants, then UMEM-pressure reclaim should probably prefer:

- the deepest host subqueue in the lowest-priority class
- or the largest offending host

not just whichever packet `dequeue()` happens to return.

10. The doc mentions host-state eviction in the service model, but the actual design never defines it.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L67)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L446)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1350)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1396)

The service model says extreme host count may evict cold fairness state. But the actual structure only exposes:

- a slab
- a map
- a free list
- a capacity

There is no actual policy for:

- when a host slot is evicted
- how coldness is measured
- what happens if a packet arrives for a full map
- whether packets are dropped, merged, or treated FIFO

For adversarial churn, this is a major omission. The implementation needs an explicit bounded-memory policy.

11. The design is mostly protocol oblivious, but it is not actually protocol agnostic in the broad sense.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1135)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1143)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L995)

The good news:

- scheduling itself is byte-based
- elephant detection is rate-based
- no protocol-specific behavior appears in the scheduler

The caveat:

- fairness keys still assume IP identity
- classifiers may be protocol-specific
- non-IP traffic is not really discussed

So "protocol oblivious" is true for the shaping algorithm, but only within an IP-forwarding model. The doc should say that explicitly.

A better phrasing would be:

- scheduler decisions are protocol-oblivious once a packet has been classified and assigned a fairness key

12. Queue classification caching needs an invalidation story.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1165)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1172)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L914)

Caching `queue_id` in the flow cache is fine as an optimization. It is not a shaper bypass.

But the doc does not explain:

- how cached `queue_id` values are invalidated on filter/classifier change
- whether DSCP changes mid-flow can move traffic to a different queue
- whether scheduler-map changes flush or version those cached values

Given the requirement that the design should not depend on fragile fast-path tricks, this invalidation story should be explicit.

13. Worker skew is solved for tokens, not for CPU.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1262)

The doc says a hot worker can claim the full configured rate under skew because token pools are shared.

That is only half the story.

It solves correctness of budget ownership, but not actual throughput if:

- one worker receives all 10 Gbps worth of traffic
- DRR / hashing / TX work on that worker becomes CPU-bound

So the document should say:

- shared pools solve the correctness problem under RSS skew
- they do not eliminate the single-worker CPU bottleneck

That distinction matters because the original goal includes uneven hash distribution.

14. The config-change and HA-drain failure-mode timing is too optimistic.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L912)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L921)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L929)

The doc says queued frames are drained before:

- config change takes effect
- VRRP demotion completes

and suggests this is only microseconds.

That is not generally true.

With MB-scale buffers and low shaping rates, queue drain time can be:

- milliseconds
- hundreds of milliseconds
- or seconds

Examples:

- `16 MB` at `10 Gbps` is roughly `13 ms`
- `16 MB` at `1 Gbps` is roughly `128 ms`
- `16 MB` at `100 Mbps` is roughly `1.28 s`
- `16 MB` at `10 Mbps` is roughly `12.8 s`

So the current failure-mode text is only valid for high-rate, lightly buffered cases.

You need a real policy choice here:

- drain with timeout
- flush and drop
- hand off backlog
- or block role change for bounded time only

The same applies to config reload.

15. The benchmark plan is good, but it is still missing the admission-fairness cases that matter most.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1331)

The benchmark plan focuses mostly on dequeue correctness. It needs explicit overload-admission tests too:

- elephants fill queue first, mice arrive later
- host churn during queue saturation
- per-host cap behavior under UMEM pressure
- queue full with mixed priority and host fairness enabled

Without those, you can "pass" the benchmark plan and still fail the actual mice-protection goal.

Design improvements I would recommend

1. Add per-host admission control, not just per-host dequeue fairness.

Options:

- per-host byte cap
- per-host frame cap
- drop from largest host first
- head-drop from dominant hosts
- weighted admission threshold based on active host count

This is the highest-priority improvement.

2. Make host DRR queue-specific and optional by class.

For example:

- `strict-high` and `high`: FIFO only, small buffers, low latency
- `low` and `best-effort`: host DRR enabled

Trying to use the same host DRR design for all traffic classes is likely the wrong tradeoff.

3. Add a formal active-host scaling rule.

The doc should define what happens when `active_count` gets very large:

- shrink quantum
- bound quantum by latency target
- cap active fairness state
- or degrade gracefully to simpler queue fairness

4. Make token batch size dynamic.

Suggested rule of thumb:

- aggregate batch: based on interface rate and target scheduling horizon
- queue batch: based on queue CIR/PIR and target shaping precision

Do not use a universal 64 KB batch for all rates.

5. Add token-cache return semantics.

Examples:

- return local tokens when queue becomes idle
- return all local tokens on worker quiesce
- return tokens on config change and HA transition
- optionally lease tokens with age-based reclamation

6. Harden the hostile-key story.

Either:

- avoid `FxHashMap`
- or document exactly why the traffic key space is trusted enough that it is safe

7. Clarify what "guarantee" means in time terms.

It probably means something like:

- guaranteed over windows larger than one scheduling cycle plus burst horizon

not "every queue gets exact CIR every cycle".

8. Define shaped-interface handling for locally generated packets.

If ICMP errors, TCP RSTs, or HA control packets leave on a shaped interface, say whether they:

- go through CoS queues
- use a reserved control queue
- or bypass and are accounted separately

9. Replace the reclaim policy with fairness-aware reclaim.

Suggested policy:

- reclaim from the lowest-priority queue
- within that queue, reclaim from the deepest host subqueue
- reclaim from the tail of that host queue

That aligns much better with the adversarial-flow goal.

10. Add explicit memory-bound host-state behavior.

For example:

- max host slots per queue
- idle timeout
- eviction priority
- behavior when full

Potential doc errors or places to tighten wording

1. `show class-of-service ... queue 0 hosts` still uses the label `Host` and IP examples even though the fairness key is configurable. That is fine for `source-address`, but the CLI design probably needs a generic label when fairness mode is not host IP.

2. The statement at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L899) that backpressure impact is "bounded by one poll cycle" is too strong if the TX ring stays full across multiple cycles.

3. The statement at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L907) that "no special handling needed" for worker skew is too strong because it ignores CPU saturation on the hot worker.

4. The phrase "mouse is NEVER dropped" at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1223) is not justified unless admission fairness exists.

Recommended additional tests

1. Queue already full of elephant traffic, then mice arrive:
   verify mice still admit at a non-zero rate.

2. 10,000 active hosts, low-rate queue:
   measure worst-case inter-service delay for a newly arrived mouse packet.

3. Dynamic batch-size accuracy:
   verify low-rate shaping remains smooth when rates are 10 Mbps, 50 Mbps, 100 Mbps.

4. Idle-worker token return:
   worker 0 hoards local cache then goes idle; worker 1 becomes hot; verify no long-lived stranded budget.

5. Host-state capacity exhaustion:
   churn through more fairness keys than slab capacity; verify bounded memory and defined behavior.

6. Control-plane/generated packets on shaped interface:
   verify they do not bypass shaping unexpectedly.

7. Queue-index fairness in Phase 1:
   all eight queues backlogged at CIR; verify later queue numbers are not cycle-starved.

8. Admission fairness under UMEM pressure:
   verify reclaim targets dominant hosts, not mice.

Final recommendation

This document is now much closer to the right architecture, but it still solves the easier half of the problem better than the harder half.

It solves:

- queueing instead of policing
- shared budgeting instead of `rate/N`
- protocol-oblivious scheduling much better than before

It still does not fully solve:

- mice admission under overload
- tail latency at very high active-host counts
- low-rate accuracy with shared token caches
- bounded hostile-key and host-churn behavior

If I were rewriting it for implementation readiness, the next step would be:

1. explicitly add per-host admission control
2. define active-host scaling and cache-return semantics
3. narrow the latency promise to queues that do not enable large-host DRR
4. harden the hostile-key and state-capacity story

That would turn this from a strong concept doc into something I would be comfortable using as an implementation contract.
