Review: `docs/cos-traffic-shaping.md`

Overall assessment

The shift from "policer" to "shaper" is the right conceptual correction. The document is much closer to the right problem statement than the earlier hierarchical-policer design, especially around queueing, work conservation, and host fairness.

That said, the current design still has several major correctness and feasibility problems. The most important ones are:

1. The scheduler semantics in the prose do not match the pseudocode.
2. The per-worker CIR model breaks the stated RSS-skew/global-guarantee goals.
3. The host-DRR data structure is internally inconsistent and is not implementable as written.
4. The shaping point is too early in the TX pipeline, so later queues can bypass the intended scheduling semantics.
5. Buffering, UMEM accounting, and "Junos compatibility" are underspecified relative to the claims.

I would not implement this exactly as written. I would keep the overall direction, but tighten the contract around hierarchy, queue ownership, and the actual scheduling point.

Major findings

1. The doc claims global per-class guarantees, but the implementation gives each worker `rate / N`.

Relevant lines:
- `43-45`
- `205-209`
- `355-360`
- `458-459`
- `810-820`

The design goal says a hot worker should be able to use the full guarantee, not just `1/N`. But the actual state says:

- `cir_tokens` are per-worker
- they refill at `rate / N_workers`
- PIR is also refilled per-worker

That creates a contradiction:

- If all traffic for one class lands on one worker, that worker only has a local CIR of `rate / N`.
- The doc then says the worker can "borrow from the shared aggregate" to reach the full shaping rate.

That is not the same as preserving the class guarantee. It means class guarantees become contingent on:

- the queue having borrowing enabled
- spare aggregate capacity existing
- other queues not already consuming it

In other words, the design does not actually provide a global per-class guarantee under RSS skew. It only provides a local guarantee plus opportunistic borrowing.

If the goal is true global guarantees, you need one of:

- shared per-class budgets across workers, not just a shared aggregate
- explicit worker-to-worker budget borrowing for each class
- a design statement that queue CIR is only approximate under RSS skew

Right now the prose says one thing and the pseudocode implements another.

2. The algorithm described for borrowing is not the algorithm implemented.

Relevant lines:
- `126-138`
- `238-243`
- `536-560`
- `707-708`

The prose says:

- CIR transmit: charge queue CIR + aggregate
- PIR transmit: charge queue PIR + aggregate
- `exact`: only CIR, no borrowing

But the code does:

- if CIR is available, use it
- then always subtract `queue.pir_tokens -= pkt_len`

That means PIR is always charged, even for in-profile traffic, and even when `exact` is set.

This creates several problems:

- `exact` queues still drive `pir_tokens` negative
- queues with `ceiling_rate_bpns = 0` cannot borrow as promised, because `pir_ok` can never be true
- the semantics of PIR are unclear: is it a separate excess bucket, or a total ceiling bucket?

If you want a two-rate shaper, define it explicitly. The current text sounds like "borrow only from PIR", but the code behaves more like "every packet is charged against peak".

That needs to be made consistent before implementation.

3. Strict priority plus the current loop structure can starve lower classes far more than the prose suggests.

Relevant lines:
- `36-38`
- `235-245`
- `462-504`
- `786-808`

The pseudocode:

- scans priorities high to low
- serves the first priority level that dequeues anything
- then `break`s, so lower priorities get nothing that round

This is not just "EF first". It means:

- a continuously backlogged high-priority queue can monopolize rounds
- lower classes may receive much less than their stated CIR
- scenario 2's claimed proportional sharing is not what the code does

The example in scenario 2 says AF and BE share surplus proportional to CIR. But AF and BE are at different priorities in the config example. The implementation would not produce that proportional split. High priority traffic would dominate until it blocks on its own tokens or empties.

If this is intended, the doc should say clearly:

- lower-priority CIR is not guaranteed under sustained higher-priority demand

If that is not intended, then strict priority needs to be bounded by a scheduler that first meets guaranteed rates and only then applies priority to surplus.

4. The "WRR within same priority" is not actually WRR.

Relevant lines:
- `98`
- `462-499`

The current algorithm computes:

- `total_cir`
- `queue_budget = (remaining_budget * weight)`
- then walks queues once

That is not weighted round robin or deficit round robin. It is a one-pass proportional budget split whose result depends on queue order and how much earlier queues actually dequeue.

Problems:

- later queues inherit a smaller "remaining budget"
- earlier queues can consume most of the round even when peers are equally entitled
- no deficit carry exists for queues that were under-served

If you want WRR, use a real per-queue deficit/counter. The current code is closer to "single-pass weighted apportionment".

5. The host-DRR data structure is internally inconsistent and likely unimplementable as written.

Relevant lines:
- `146-152`
- `248-258`
- `354`
- `389-390`
- `417-420`
- `527-543`
- `667-670`

This is the biggest structural issue in the document.

The queue is described as:

- one parent `VecDeque<QueuedFrame>`
- host state stores "indices into the parent buffer"
- scheduler pops the next frame for a host
- on token failure, the code pushes the frame back to the front of the parent queue

That cannot be correct as written:

- `VecDeque` indices/ranges are not stable across `push_front`, `pop_front`, wraparound, or removal from arbitrary host streams
- host subqueues cannot cheaply point into a single parent FIFO unless packets are immutable nodes with stable linkage
- if `hosts.next_frame()` removes from host state, `queue.buffer.push_front(frame)` does not restore host state on requeue
- `hosts.enqueue(&frame)` is called before `q.buffer.push_back(frame)`, but no stable index exists yet

So the claimed O(1) DRR structure is not actually defined.

I would strongly recommend one of these instead:

- `ClassQueue` contains only `HostDrr`, and each host owns its own `VecDeque<QueuedFrame>`
- or use intrusive packet nodes in a slab, with per-host linked lists and no parent `VecDeque`

Do not try to maintain host ranges into a mutating parent `VecDeque`.

6. The shaping point is too early; `pending_tx_prepared` can undermine the scheduler.

Relevant lines:
- `260-277`
- `561-570`

The shaper admits packets from class queues into `pending_tx_prepared`, then the existing TX pipeline drains that queue.

That introduces a second queue after the scheduler:

- once a packet is in `pending_tx_prepared`, it is no longer subject to class priority or host fairness
- if `drain_pending_tx()` cannot fully submit to the TX ring, backlog accumulates outside the shaper
- later high-priority packets can end up behind earlier best-effort packets already staged in `pending_tx_prepared`

That is a fundamental architecture problem. A shaper needs to own the packet until actual TX-ring submission, or at least until the final per-cycle batching decision.

Recommended fix:

- either have the CoS scheduler submit directly to the TX ring
- or make `pending_tx_prepared` a same-cycle scratch vector, not a persistent FIFO
- or make `pending_tx_prepared` itself class-aware and scheduler-owned

Without that, the scheduler is not truly the last arbiter of egress order.

7. "Smooth output" is overstated; this is still poll-cycle and batch-limited shaping.

Relevant lines:
- `19`
- `24-25`
- `229-246`
- `464`
- `619`

This design can shape average rate, but not necessarily smooth the wire-time stream in a fine-grained way.

Reasons:

- packets are released in batches (`TX_BATCH_SIZE`)
- scheduling happens on poll cycles, not a dedicated pacing clock
- refill granularity is coarse (`10µs minimum`)
- once packets are posted to the NIC TX ring, wire timing is owned by the NIC

This is still useful, but the doc should be more precise:

- it is a queueing rate limiter with average-rate shaping and bounded burst release
- it is not perfect packet pacing

That matters because the document currently implies smoother egress than the implementation can guarantee.

8. The document does not explain who drives the scheduler when there is queued backlog but no new RX work.

Relevant lines:
- `229-230`
- `275-277`

`drain_shaped_tx()` runs "at the start of each poll cycle". That may be fine if workers are busy-spinning continuously, but it is not spelled out.

You need an explicit statement about scheduler liveness:

- if RX goes idle but queues are still non-empty, does the worker continue polling and draining?
- if not, shaped traffic can stall until new RX arrives

If the worker loop is always active, say so. If it can block, you need a timer or explicit reschedule source.

9. The fairness key is too simplistic for a generic egress shaper.

Relevant lines:
- `39-41`
- `143-145`
- `428-430`
- `822-832`

Using `{src_ip}` is reasonable for one specific case: outbound subscriber fairness where the source is the inside host.

It is wrong or at least incomplete for:

- inbound/download shaping, where `src_ip` is the remote server
- NAT scenarios, where the meaningful subscriber identity may differ from packet source
- tunnel egress, where "host" may need to be inner-source, not outer-source
- dual-stack or multi-tenant deployments that want fairness by subscriber, VRF, or zone

The design should not hard-code fairness to `src_ip`. It should define a fairness-key policy, for example:

- `subscriber`
- `inside-src-ip`
- `inside-dst-ip`
- `5-tuple`
- disabled

Even if only one mode is implemented first, the doc should acknowledge that `src_ip` is a policy choice, not a universal truth.

10. Buffer sizing is in the wrong units for what the config claims to model.

Relevant lines:
- `312-313`
- `641-646`
- `693-704`
- `927-931`

The config examples use `buffer-size percent`, which implies a percentage of some shared buffer resource. But the actual queue structure stores `buffer_packets: u32`.

That mismatch matters:

- packet-count limits behave differently for 64B and 1500B frames
- latency and memory consumption depend on bytes, not packet count
- Junos-style CoS queue buffers are much closer to byte/shared-buffer semantics than packet counts

If you want percent-based queue buffers, the runtime representation should probably be bytes, with an optional packet cap as a secondary guard.

11. UMEM budgeting is not actually enforced as designed.

Relevant lines:
- `637-650`
- `652-672`

The doc says:

- total queued frames must stay within a fraction of UMEM
- if total queued frames exceeds the budget, drop from the lowest-priority queue first
- coordinator enforces this at config time

That is not enough.

Config-time validation cannot enforce runtime occupancy. You need runtime accounting for:

- total queued frames/bytes per worker
- total queued frames/bytes per interface
- possibly global UMEM pressure across workers

And the provided enqueue code does not implement lowest-priority reclamation or any global UMEM accounting. So this is currently a design aspiration, not a defined mechanism.

12. `QueuedFrame` does not clearly preserve all data needed for deferred transmission.

Relevant lines:
- `218-223`
- `262-277`
- `370-376`
- `561-570`

Packets are queued after forwarding/classification, but `QueuedFrame` only stores:

- offset
- len
- recycle
- host_ip
- enqueue timestamp

When dequeued, `PreparedTxRequest` is reconstructed with:

- `expected_ports: None`
- `expected_addr_family: 0`
- `expected_protocol: 0`
- `flow_key: None`

That looks suspiciously incomplete. If the current TX path relies on any of that metadata for:

- validation
- accounting
- offload behavior
- traceability

then the shaped path is losing information.

The doc should either:

- show that those fields are genuinely optional on the egress path
- or add the missing metadata to `QueuedFrame`

13. The DSCP classifier section contains a factual inconsistency.

Relevant lines:
- `293-295`
- `966`

The config says:

- `dscp_classifier: [u8; 64]`

which is correct for DSCP codepoints.

But the comments say:

- "256 entries, one per DSCP codepoint"
- "256-entry lookup table"

That should be cleaned up. DSCP is 6 bits, not 8.

14. The performance numbers are too confident and likely not credible.

Relevant lines:
- `834-882`

The tables give extremely precise nanosecond costs for:

- `VecDeque` operations
- hash lookups/inserts
- atomics
- DRR logic

Those numbers are not defensible without measurement on the target hardware, compiler settings, and load shape. In practice, the cache-miss profile and branch behavior will dominate.

I would replace these tables with:

- asymptotic costs
- expected hot-path characteristics
- a benchmark plan

Otherwise this section weakens the doc because it overstates certainty.

15. Several example outcomes are not actually justified by the algorithm.

Relevant lines:
- `769-808`

Examples 1 and 2 are directionally useful, but not rigorous.

Specific issues:

- "DRR quantum: `1G/101 ≈ 10 Mbps per host per round`" is not how DRR quantum is normally reasoned about
- the analysis mixes quantum, fair share, and residual-rate arguments
- scenario 2 assumes proportional surplus sharing across AF and BE, which the priority scheduler does not implement

I would keep the scenarios, but rewrite them as intuition, not proof.

16. Configuration compatibility is narrower than "Junos CoS compatibility" suggests.

Relevant lines:
- `46-47`
- `676-765`
- `916-923`

What is described here is closer to:

- a Junos-inspired subset of CoS

than full compatibility.

Missing or materially different semantics include:

- precise queue buffer semantics
- loss-priority-aware drop behavior
- exact scheduling semantics for strict priority + guaranteed rates
- byte vs packet queue accounting
- hierarchical profiles beyond one interface/class/host tree

I would soften the claim to avoid over-promising.

Design improvements I would strongly recommend

1. Move the actual shaping decision to the final TX submission point.

The scheduler should own packets until they are actually handed to the TX ring. Do not let a persistent FIFO exist after the shaper.

2. Replace `VecDeque + host ranges` with real per-host queues.

A cleaner structure would be:

- root/interface shaper
- class queue
- per-host subqueue
- each subqueue holds `VecDeque<QueuedFrame>`

That makes DRR straightforward and keeps O(1) honest.

3. Define hierarchy semantics precisely.

Pick one model and write it down explicitly:

- root aggregate bucket
- class guaranteed bucket
- class excess/ceiling bucket
- optional host fairness only within admitted class service

Right now CIR, PIR, strict priority, and borrowing are mixed in a way that is not mathematically crisp.

4. If RSS-skew tolerance is a real goal, share class budgets across workers too.

A shared aggregate alone is not enough. You need either:

- shared per-class tokens
- or a documented acceptance that per-class guarantees are approximate under skew

5. Make the fairness key configurable or at least direction-aware.

Hard-coding `src_ip` is too narrow for a generic CoS subsystem.

6. Use byte-based buffer accounting.

If you keep packet limits, make them secondary safety rails, not the primary queue-size model.

7. Add explicit flush semantics.

The doc should say what happens to queued packets on:

- interface down
- config change
- queue/scheduler-map rebind
- worker restart
- HA role change

8. Treat low-latency goals as a function of queue budget, not just priority.

If you want credible tail-latency claims, specify:

- max per-class queued bytes
- max burst per scheduling round
- interaction with `TX_BATCH_SIZE`
- whether high-priority queues have smaller buffers by design

9. Rework observability around scheduler decisions, not just counters.

Missing metrics that would matter during debugging:

- bytes sent from CIR vs PIR
- borrowed bytes per queue
- aggregate-token starvation count
- queue-token starvation count
- time/bytes spent in `pending_tx_prepared`
- queue sojourn time histogram
- active hosts per queue
- UMEM budget pressure / forced eviction counts

10. Replace the performance section with a benchmark plan.

For example:

- single worker, single queue line rate
- multi worker, skewed RSS
- many-host DRR with host churn
- mixed MTUs
- saturated TX ring
- low-rate shaping accuracy

Suggested doc edits

1. Rewrite the hierarchy section to state the exact service model:

- what is guaranteed
- what is only opportunistic
- what strict priority can starve
- what "exact" means formally

2. Rewrite the scheduling pseudocode after choosing one of:

- strict priority over excess only
- or strict priority over total service with no lower-class guarantees

Right now it says both.

3. Rewrite the `ClassQueue`/`HostDrr` structures so the dequeue path is implementable.

4. Add a short "non-goals / scope" section.

That would help clarify that the first version is:

- userspace only
- egress only
- subset of CoS
- no perfect wire pacing

5. Add a "failure modes" section.

Examples:

- queue overflow
- UMEM exhaustion
- TX ring backpressure
- worker skew
- config changes while queued packets exist

Recommended additional tests

Beyond the current list, add:

1. TX-ring saturation:
   shaped queues remain priority-correct when TX submissions are only partially accepted.

2. No-RX backlog drain:
   queued traffic continues to drain when no fresh RX packets arrive.

3. Mixed MTU fairness:
   64B mice versus 1500B elephants and vice versa.

4. Runtime UMEM pressure:
   verify lowest-priority reclamation and that RX fill starvation is prevented.

5. Worker skew with competing classes:
   one class hot on worker 0, another class hot on worker 1, confirm guarantees.

6. `exact` plus priority:
   confirm an exact high-priority queue does not accidentally consume more than configured.

7. Config reload with backlog:
   queued packets are either safely flushed or preserved with correct semantics.

Bottom line

The document is directionally right in identifying that this should live under CoS and be built as a shaper, not a policer. That part is a real improvement.

But the current design still needs a substantial redesign before implementation, mainly around:

- shared-vs-local budgets
- true scheduler semantics
- host-queue data structures
- final TX ownership
- runtime memory pressure handling

If you want, I can turn this into a concrete redesign proposal next: a smaller, implementable CoS shaper architecture that preserves the good parts of this doc while removing the contradictions.
