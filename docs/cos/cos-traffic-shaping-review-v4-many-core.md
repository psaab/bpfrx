Review: `docs/cos-traffic-shaping.md`

Overall assessment

This draft is materially better than the earlier versions. It now gets several important things right:

- it is explicitly an egress shaper, not a policer
- it forbids bypass on shaped interfaces
- it uses shared class and aggregate budgets across workers
- it adds admission control, not just dequeue fairness
- it acknowledges protocol-oblivious scope and single-worker CPU limits

However, with the additional requirement to support many cores well, there is still one major architectural hole and several important scaling issues:

1. class fairness is global, but host fairness is still only per worker
2. the shared atomic budget design will hit cache-coherence limits on many cores unless it is padded and benchmarked carefully
3. total leased tokens and host state scale with worker count in ways the doc does not yet bound
4. overflow/reclaim behavior is still too weak under many-core adversarial churn

If the target is really “many competing adversarial flows on many cores, protocol oblivious, no fast-path escape hatches”, the document is close, but not done.

Most important finding

1. Per-host fairness is still not global across workers, so an elephant can multiply its share by spreading across cores.

Relevant lines:
- `58-62`
- `258-313`
- `695-706`
- `712-717`
- `761-789`

The doc correctly makes class CIR/PIR and aggregate budgets shared across workers. That solves the class-budget side of RSS skew.

But host fairness state lives inside each worker’s `CosState` and `ClassQueue`:

- each worker has its own `queues: [ClassQueue; 8]`
- each `ClassQueue` has its own `HostDrr`
- each `HostDrr` has its own `AHashMap<FairnessKey, u32>`

That means a single source host can get:

- one DRR entry per worker
- one soft/hard cap per worker
- one overflow opportunity per worker

So the exact adversarial case you care about is still not solved:

- one elephant opens many flows
- flows hash across many workers
- each worker sees “one elephant entry” locally
- globally, that host gets multiple quanta and multiple queue shares

This is not a minor edge case. It is the core many-core version of the flow-splitting problem.

The same issue applies to admission control:

- soft cap is per worker
- hard cap is per worker
- headroom is per worker

So a host can occupy `soft_cap * num_workers` worth of queue budget across the interface.

This is the biggest remaining design flaw relative to the original requirements.

What to do about it

You need to choose one of these explicitly:

1. Shared host fairness state across workers
   This preserves fairness semantics, but it is expensive and complicated.

2. Ownership by fairness key
   All packets for the same fairness key are redirected to one shaping owner worker.
   This is the cleanest correctness model, but it adds cross-worker forwarding cost.

3. Admit that host fairness is only per worker
   Then the doc must weaken its adversarial-flow claims substantially.

Right now the doc promises more than the architecture actually delivers.

High-severity scaling issues

2. Shared atomic token pools will cause heavy cache-line ping-pong on many cores.

Relevant lines:
- `167-235`
- `682-691`
- `1242-1244`

The design uses one shared atomic pool per:

- aggregate bucket
- class CIR bucket
- class PIR bucket

That is fine conceptually, but on many cores it creates hot cache lines:

- all workers sending the same class contend on the same `queue_cir[i]`
- all workers borrowing surplus contend on the same `queue_pir[i]`
- every transmitted byte path also touches the same aggregate bucket

Even with leasing, this can still become a coherence hotspot on 16, 32, or 64 workers.

The doc needs to say more about this, and the implementation must at minimum:

- align each shared bucket and timestamp to a separate cache line
- avoid arrays of adjacent atomics that false-share between queues
- benchmark same-class many-core contention, not just single-worker skew

Right now [SharedTokenPools] at lines `684-691` is written as packed arrays of atomics. That is a false-sharing hazard by itself.

Recommended change:

- replace the arrays with a per-bucket struct like `AlignedTokenPool`
- add `#[repr(align(64))]` or stronger padding
- keep timestamps in the same padded unit only if they are always touched with that bucket

3. The benchmark plan is still too weak for many-core validation.

Relevant lines:
- `1242-1244`
- `1272-1289`

The current plan has:

- single worker
- multi-worker skew
- 10,000 active hosts

But it still misses the most important many-core fairness tests:

1. One source host spread across many workers.
   Example: one elephant with 1000 flows, each hashing to different workers, versus many mice each with one flow.

2. Same-class many-core contention.
   Example: 16 or 32 workers all pushing the same class at line rate, measuring atomic contention and throughput collapse.

3. Cross-socket NUMA contention.
   If workers span sockets, the aggregate/class token lines will bounce across NUMA boundaries.

4. Per-worker admission caps versus global fairness.
   Verify whether a host can occupy `soft_cap * Nworkers`.

Without these tests, the design is not yet validated for “many cores”.

4. Total outstanding leased tokens grow with worker count and can reintroduce burstiness and fairness drift.

Relevant lines:
- `173-235`
- `698-756`

The doc improved this a lot by adding:

- dynamic lease sizing
- MTU floor
- idle return

But the many-core effect is still missing:

- each worker can hold aggregate lease
- each worker can hold class CIR lease
- each worker can hold class PIR lease

Across many workers, total outstanding unspent tokens can be large enough to matter.

Example:

- `32` workers
- aggregate lease about `31 KB`
- class CIR lease about `16 KB`
- class PIR lease about `16 KB`

That is about `63 KB` per worker, or about `2 MB` of outstanding credit on one hot class/interface path.

At `10 Gbps`, `2 MB` is roughly `1.6 ms` of traffic.
At `1 Gbps`, it is roughly `16 ms`.

That is large enough to affect:

- short-window rate accuracy
- fairness during transitions
- tail latency for suddenly active competitors

The doc should define a bound on total leased-but-unspent tokens, not just per-worker lease size.

Recommended change:

- cap total distributed leases per bucket as a fraction of bucket burst
- or scale per-worker lease down with estimated active workers

5. Host-state memory scales with worker count much faster than the doc discusses.

Relevant lines:
- `598-602`
- `712-717`
- `773-789`
- `848-867`

`max_host_slots` is per fairness-enabled queue per worker.

If you enable host fairness on multiple queues across many workers, total interface memory can explode.

Illustrative order of magnitude:

- `4096` host slots
- `32` workers
- `2` fairness-enabled queues

That is `262,144` host slots for one interface before accounting for:

- the hash maps
- per-host packet queues
- overflow buckets
- queued frames themselves

If the slot footprint lands anywhere near `96-128` bytes in practice, you are already in tens of MB before packet buffers and maps. With more fairness-enabled queues or more workers, it rises quickly.

The doc should add:

- a per-interface host-state budget
- guidance that host fairness should only be enabled on a small subset of queues
- memory estimates as a function of `workers * fairness_queues * max_host_slots`

Otherwise this will look cheap on a 4-core box and become expensive on a 32-core box.

Medium-severity issues

6. The `deepest_host_idx` fallback is not really stable under churn and many-core adversarial load.

Relevant lines:
- `401-407`
- `503-505`

The doc says `deepest_host_idx` is:

- updated on enqueue when the new host exceeds current max
- possibly stale after dequeue
- refreshed on fallback miss

That is workable as a heuristic, but it is not a strong correctness story under hostile churn. In many-core adversarial load, the “deepest” host can change constantly.

So the fallback is not truly O(1) in a robust sense. It is:

- O(1) optimistic
- occasional repair work on miss

That is fine if documented honestly, but the doc still reads a bit stronger than the mechanism really is.

7. Overflow service is bounded, but the contract is still weak for many-core churn.

Relevant lines:
- `848-862`
- `1288-1298`

Serving `1 overflow packet per DRR round` is simple, but under:

- large active host counts
- large worker counts
- sustained slab-full churn

overflow traffic may effectively become starvation-adjacent.

The doc itself notes overflow can be starved if the DRR round consumes the queue budget.

That means the current overflow contract is:

- degraded but nonzero only when the queue is not already fully consumed by active hosts

If that is the intended tradeoff, say it more plainly. Otherwise consider:

- fixed percentage service for overflow
- or a byte budget per cycle rather than one packet per round

8. The doc now handles protocol obliviousness well, but the many-core fairness issue effectively reintroduces a “hash-path dependency”.

Relevant lines:
- `541-555`

The scheduler itself is protocol oblivious, which is good.

But because fairness is per worker, service now depends heavily on:

- how flows hash across workers

That is not protocol-specific, but it is still a path-dependent behavior that undermines the intended fairness model.

In other words:

- the design is protocol oblivious
- but not yet worker-placement oblivious

That matters for the original “unevenly hash to queues” goal.

Concrete enhancements I recommend

1. Add a section called `Global vs Per-Worker Fairness`.

It should explicitly say whether:

- class fairness is global
- host fairness is global
- or host fairness is only local to one worker

Right now the document implies host fairness is stronger than it really is.

2. Decide how fairness keys map across workers.

Recommended options to evaluate in the doc:

- `per-worker fairness only`:
  simplest, but weaker semantics

- `shared host accounting only`:
  global soft/hard caps, local DRR

- `single-owner worker per fairness key`:
  strongest semantics, higher forwarding cost

3. Add cache-line alignment requirements to the token-pool structs.

This should be a concrete implementation requirement, not just an optimization note.

4. Add a per-interface memory budget section.

Show total host-state memory as:

- `workers × fairness_enabled_queues × max_host_slots × slot_size`

and explicitly recommend limiting host fairness to BE/bulk queues only.

5. Strengthen the benchmark plan for many-core contention.

At minimum add:

- `1 host spread across N workers`
- `same queue hot on 16/32 workers`
- `cross-socket token contention`
- `global host-cap semantics across workers`

6. Bound total leased credit per bucket.

This is necessary if the design wants to preserve latency and smoothness on many cores.

Bottom line

This draft is now substantially better and much closer to implementation-ready than the earlier versions.

But for a many-core system, the central remaining issue is fundamental:

the design globalizes class budgets, but it does not globalize host fairness

That means the adversarial elephant-vs-mice goal is still not truly satisfied once flows spread across workers, which is exactly what happens on a real many-core RSS system.

If you fix that, plus:

- cache-line layout for shared atomics
- total leased-credit bounds
- stronger many-core benchmarks
- explicit memory scaling limits

then the document will be much closer to a design that actually matches the stated goals rather than only approximating them on lightly loaded or low-core-count systems.
