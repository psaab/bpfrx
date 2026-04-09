Review: `docs/cos-traffic-shaping.md`

Overall assessment

This version is much stronger than the earlier drafts. It now directly addresses several of the biggest earlier flaws:

- it is clearly a shaper, not a policer
- it explicitly forbids shaping bypass on shaped interfaces
- it uses shared class and aggregate budgets instead of `rate / N`
- it adds enqueue-time admission control, not just dequeue-time DRR
- it bounds host state and introduces an overflow path
- it is more honest about protocol-oblivious scope and CPU-vs-latency tradeoffs

So the document is no longer “wrong in direction”. It is now close to an implementable design.

However, against the actual requirements:

- many competing adversarial flows
- uneven RSS / queue hashing
- protocol-oblivious behavior
- minimal CPU overhead
- preserved throughput and tail latency

there are still several important gaps and a few outright errors. The biggest remaining problem is that the current admission-control design still fails in one of the exact target cases: many elephants can fill the queue while each remains below soft cap, leaving no reclaim candidate for a newly arriving mouse.

That means the document is improved, but it still does not fully satisfy the stated “one elephant vs 100 mice / 100 elephants vs 1 mouse / 100 elephants vs 100 mice” goal set.

What is good in the current draft

1. Shared budgets across workers at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L164) are the right correction for RSS skew. This fixes the old conceptual error where guarantees were implicitly partitioned per worker.

2. The explicit “no bypass on shaped interfaces” rule at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L480) is correct and necessary. That is aligned with the requirement that this cannot depend on fast-path shortcuts.

3. Admission control at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L304) is the right direction. This is the first version that acknowledges DRR alone is too late under overload.

4. The direct-TX ownership model at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L480) is much better than staging into a FIFO after the scheduler.

5. Bounding host state with `max_host_slots` and an overflow bucket at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L761) is the right kind of scaling valve.

6. The benchmark plan at [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1125) is much more credible than the older fake-nanosecond cost tables.

Critical findings

1. The current admission-control design still fails the “many elephants then one mouse” case.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L318)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L336)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L393)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1146)

The soft-cap design only helps if at least one host is already over soft cap.

Counterexample:

- queue buffer = `16 MB`
- `100` active elephants
- `cap_factor = 2`
- soft cap per host = about `320 KB`
- hard cap per host = about `640 KB`

The queue can be completely full at `16 MB` while each elephant only holds about `160 KB`, which is below soft cap. In that state:

- the queue is full
- no host is on the reclaim list
- a newly arriving mouse packet triggers rule 4
- rule 4 finds no over-cap host
- the packet falls through to tail-drop

So the current design still does not actually guarantee mouse admission in one of the main target scenarios.

This is the most important remaining design gap.

What would fix it:

- reserve a fraction of queue space for under-cap or new hosts
- use `cap_factor <= 1` for fairness-enabled queues
- maintain explicit “new entrant” headroom
- or use a reclaim policy based on relative share, not just “over soft cap”

Without one of those, the design still fails under many-elephant equilibrium load.

2. Queue occupancy is measured in payload bytes, but actual UMEM consumption is frame-based, and the fairness path does not enforce the queue frame cap.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L579)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L792)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L382)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L800)

This is a real correctness and scale problem in an AF_XDP system.

Each queued packet consumes one UMEM frame, which is usually fixed-size memory, not `pkt.len` bytes. A queue full of `64B` packets consumes almost the same UMEM memory as a queue full of `1500B` packets.

But the design:

- uses `queue.total_bytes` based on packet payload length
- says `buffer_frames` is a secondary safety cap
- then does not enforce `buffer_frames` at all in the fairness-enabled enqueue path

That means a small-packet adversary can:

- stay within `buffer_bytes`
- consume far more UMEM frames than the payload-byte accounting implies
- stress the global UMEM budget much earlier than the queue-byte model suggests

This is a major gap relative to the “many adversarial flows” goal.

The fix should be:

- always enforce both queue byte cap and queue frame cap, including the fairness-enabled path
- explicitly distinguish “scheduling bytes” from “UMEM frame consumption”
- possibly validate buffer sizing in both bytes and frames

3. The dynamic token-lease formula breaks down below MTU-sized leases.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L187)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L203)

The document gives this table:

- `10 Mbps` -> `31 B` lease
- `100 Mbps` -> `312 B` lease

That is not a workable lease size for packet transmission unless the charging code is explicitly prepared to accumulate multiple lease claims before a single packet can pass.

A `1500B` packet cannot be covered by a `31B` or `312B` claim. If the charging path only claims once per miss, the packet never transmits. If it loops until enough tokens are accumulated, then low-rate queues are suddenly doing dozens of atomics per packet.

So the design goal here is right, but the current formulation is incomplete.

It needs one of:

- minimum lease >= MTU
- direct shared-bucket charging for low-rate pools
- or explicit multi-claim accumulation semantics

Right now the doc claims correctness here, but it has not actually closed the loop.

4. The document still oversells the admission-control policy as “heaviest-host-first drop”, but that is not what the mechanism actually does.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L89)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L351)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L863)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L872)

The actual mechanism is:

- maintain an over-cap reclaim list
- reclaim from the head of that list

That is “over-cap-host-first”, not “heaviest-host-first”.

Those are not equivalent.

If you want true heaviest-host-first drop, you need:

- a heap
- an approximate heavy-hitter structure
- or at least periodic max-host refresh

If you want O(1), then rename the behavior honestly to “over-cap-host-first reclaim”.

As written, the prose is stronger than the algorithm.

5. There is a factual error in the hash-table discussion.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L693)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L754)

The document says:

- `AHashMap (keyed SipHash-based)`

That is incorrect.

`AHashMap` is not SipHash-based. It uses `ahash`, which is randomized and fast, often AES-assisted on x86, but it is not “SipHash-based”.

The security claim is also too strong:

- “collision attacks computationally infeasible”

For a document explicitly concerned with adversarial inputs, that wording is too confident. Randomized hashing helps, but if you want hostile-key robustness as a design property, you should either:

- use a hash implementation with stronger documented collision-attack posture
- or state the choice more carefully

This is a real documentation error, not just a style issue.

6. The latency story is still not tied tightly enough to the configured buffer sizes.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L246)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L889)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L921)

The document correctly warns against enabling host DRR on latency-sensitive queues, but it still allows very large buffers without a latency-derived validation rule.

Examples:

- `16 MB` at `10 Mbps` is about `12.8 s` of drain time
- `16 MB` at `100 Mbps` is about `1.28 s`
- `16 MB` at `1 Gbps` is about `128 ms`

If the design goal includes maintaining tail latency, then queue buffers should not just be bounded by memory. They should also be bounded by a target queueing-delay budget.

Suggested enhancement:

- validate `buffer_bytes <= class_rate * max_queue_delay`
- or at least warn when queue depth implies excessive queueing delay at configured CIR

Without that, operators can configure a “correct” shape with unacceptable latency.

7. The target round units are inconsistent across the document.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L281)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L586)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L939)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1019)

The main text recommends:

- `target_host_round_us = 250`

But the config example uses:

- `target-round-ms 5`

and the CLI example reports:

- `target round: 5ms`

That is a `20x` difference. It materially changes:

- worst-case inter-service delay
- CPU cost
- fairness granularity

This needs to be normalized. Right now the doc is internally inconsistent.

8. The overflow-bucket story is practical, but the fairness and benchmark claims do not fully account for it.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L458)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L775)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1162)

The design says:

- default `max_host_slots = 4096`
- excess fairness keys go to overflow FIFO

But the benchmark plan includes:

- `10,000 active hosts`

At that point, a large fraction of the population is no longer in host DRR at all. They are in overflow service, which has degraded fairness by design.

That is acceptable as a bounded-memory tradeoff, but then the benchmark and fairness claims need to say explicitly:

- what fairness is expected for overflow traffic
- how often overflow is serviced
- whether overflow can be starved by DRR hosts

Right now the overflow path is introduced as a safety valve, but its fairness contract is still underspecified.

9. Phase 1 is much better than before, but the “proportional to CIR” wording is still too loose.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L106)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L121)

The doc says:

- each class gets one quantum per visit
- a `10 Gbps` and a `100 Mbps` queue get one quantum per visit, proportional to CIR

But the actual quantum is clamped:

- floor at MTU
- cap at `32 KB`

So it is not really proportional over the full range. For low-rate queues, the MTU floor dominates. For high-rate queues, the `32 KB` ceiling dominates.

That may be fine in practice, but the prose should be more precise:

- it is bounded, rate-informed fairness, not exact proportional per-visit service

This is not a blocker, but the wording should be tightened.

10. The doc now handles CPU correctness better, but it still understates the throughput cost of hostile host churn.

Relevant lines:
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L696)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L761)
- [cos-traffic-shaping.md](../cos-traffic-shaping.md#L1164)

The design is careful about bounded memory, but not yet explicit enough about the CPU cost of:

- very high host churn
- repeated reclaim-list link/unlink
- repeated overflow promotion/demotion
- repeated epoch invalidation with cached `queue_id`

These are likely acceptable, but the doc should distinguish:

- steady-state many-host behavior
- churn-heavy adversarial behavior

because those are not the same cost envelope.

Important enhancements I would recommend

1. Add protected admission headroom for new or under-cap hosts.

This is the highest-value change.

For example:

- reserve `X%` of queue capacity for packets from hosts below soft cap
- or maintain a “reclaimable reserve” that cannot be entirely consumed by below-soft-cap incumbents

Without this, the many-elephants equilibrium case still defeats the design.

2. Enforce queue frame limits in the fairness-enabled path.

Right now only the FIFO path visibly checks `buffer_frames`. The fairness path needs the same protection.

3. Separate payload-byte accounting from UMEM-frame accounting explicitly.

The document should say:

- scheduling fairness uses payload bytes
- memory safety uses frames and/or UMEM-byte equivalents

Those are different resource models.

4. Fix the dynamic token-lease section so low-rate queues have a defined, implementable charging path.

Right now the concept is good, but the mechanics are incomplete.

5. Rename “heaviest-host-first” unless the implementation really does track heaviest hosts.

The current O(1) reclaim-list design is good, but it is not the same algorithm.

6. Normalize the host-round configuration units.

Pick one:

- microseconds everywhere
- or milliseconds everywhere

and make the examples and defaults match.

7. Define overflow service precisely.

At minimum:

- how many overflow packets per DRR round
- whether overflow has its own byte cap
- whether overflow packets can be reclaimed preferentially

Recommended additional tests

1. Many-elephants equilibrium, then new mouse arrival:
   queue is full, no host over soft cap, mouse arrives. Verify whether the design still protects the mouse.

2. Small-packet adversary:
   `64B` packets in a fairness-enabled queue. Verify queue frame cap and UMEM safety are enforced, not just payload-byte cap.

3. Low-rate lease correctness:
   `10 Mbps`, `50 Mbps`, `100 Mbps` queues with `1500B` packets. Verify the lease design is implementable and rate accurate.

4. Overflow fairness:
   more hosts than `max_host_slots`, sustained load, confirm overflow does not silently become starvation.

5. Worst-case latency under configured `target_host_round`:
   verify measured inter-service delay actually matches the document’s math.

6. New-host admission under full queue:
   repeated arrival of first packets from new hosts while queue is full of incumbents.

Bottom line

This draft is now close to a serious implementation spec. It fixed most of the conceptual errors from the earlier versions.

But there are still three things I would not sign off on yet:

1. the many-elephants/full-queue/no-overcap-host case
2. the UMEM/frame-accounting mismatch in the fairness path
3. the incomplete low-rate token-lease mechanics

Those are directly tied to the original requirements. If those three are fixed, the document will be much closer to actually meeting the “adversarial, protocol-oblivious, low-CPU, skew-tolerant” goal rather than just describing something directionally similar.
