Concrete Alternative: Many-Core Global Host Fairness for CoS Shaping

Purpose

This is a concrete alternative to the current `cos-traffic-shaping.md` design, focused on the main remaining gap:

- class fairness is global across workers
- host fairness is still only local to each worker

On a real many-core RSS system, that means one elephant can spread across workers and get:

- multiple DRR entries
- multiple soft/hard caps
- multiple overflow opportunities

That breaks the original goal in exactly the adversarial cases we care about.

This alternative fixes that without introducing a protocol-specific fast path.

Recommendation

Use **fairness-key ownership** for fairness-enabled classes:

- every fairness key is assigned to exactly one owner worker
- all packets for that key are enqueued and scheduled only on that owner
- host DRR, host caps, reclaim, and overflow all become effectively global per key

Then combine that with **hierarchical token leasing**:

- global shared class/aggregate token pools remain authoritative
- per-socket lease pools reduce many-core cache-line contention
- per-worker caches lease from the local socket pool

This is the design I would recommend implementing.

Why this alternative

There are three obvious ways to fix the per-worker host-fairness problem:

1. Shared global host state across all workers
2. Single-owner worker per fairness key
3. Weaken the contract and accept per-worker host fairness

I would choose `2`.

Why not `1`

Shared global host state means:

- shared host maps
- shared host deficits
- shared host byte counters
- shared host reclaim state

That creates:

- locks or atomics on every enqueue/dequeue
- heavy cache-line bouncing
- difficult many-core scaling
- much higher complexity than the rest of the design

It solves correctness, but it is the wrong performance tradeoff for AF_XDP userspace.

Why not `3`

If fairness remains per worker, the document has to weaken its claims substantially:

- one elephant can get one share per worker
- one host can get `soft_cap * Nworkers`
- mice protection becomes hash-dependent

That does not meet the original adversarial-flow goal.

Why `2` is the best fit

Fairness-key ownership gives:

- one host/key = one DRR entry
- one host/key = one admission cap
- one host/key = one overflow position

without requiring a globally shared hot host table.

It preserves:

- protocol obliviousness
- no shaping bypass
- many-core scalability via sharding by key

Chosen design

1. Classes are split into two kinds:

- `local classes`: latency-sensitive FIFO classes, scheduled locally on the current worker
- `fairness-owned classes`: BE/bulk-style classes, where fairness key ownership applies

2. For fairness-owned classes:

- compute `owner_worker = hash(interface, queue_id, fairness_key) mod fairness_workers`
- if packet arrives on the owner, enqueue locally
- if packet arrives on a different worker, forward only the descriptor/metadata to the owner via a lock-free ring
- owner worker performs admission control, host DRR, reclaim, overflow handling, and TX submission

3. For many-core token scaling:

- authoritative token pools stay global
- workers do not all hit global atomics directly in the steady state
- each socket has a lease pool per aggregate/class bucket
- each worker leases from its local socket pool

This reduces coherence traffic while keeping rate correctness global.

Result

- class fairness is global
- host fairness is global for fairness-enabled classes
- CPU scaling is better than a fully shared host state design

Architecture

Data path for fairness-owned classes

```
RX worker
  -> parse / classify / derive fairness key
  -> owner = hash(interface, class, fairness_key)
  -> if owner == current worker:
       enqueue locally into owned host queue
     else:
       push RemoteQueuedFrame into owner ingress ring

Owner worker
  -> drain remote ingress rings
  -> apply host admission control
  -> enqueue into HostDrr / overflow
  -> class scheduler (phase 1 + phase 2)
  -> TX ring submission
```

Data path for local classes

```
RX worker
  -> parse / classify
  -> enqueue into local FIFO class queue
  -> local scheduler / TX ring
```

Why this works

One elephant across 32 workers:

- all packets hash to one owner worker for that fairness key
- elephant gets one DRR state, not 32
- elephant gets one soft/hard cap, not 32
- elephant cannot multiply its share by spraying flows across workers

100 elephants vs 100 mice:

- each fairness key is independently sharded
- load spreads naturally across workers by key
- each host still has exactly one fairness state globally
- many hosts use many workers, one host uses one owner

This matches the original goal much better than per-worker host fairness.

Protocol obliviousness

This remains protocol oblivious:

- owner is chosen from `{interface, class, fairness_key}`
- fairness key is policy, not protocol behavior
- scheduler decisions are still based on bytes, queue, and fairness key
- no TCP/UDP/ESP/GRE-specific scheduling logic exists

This is not a fast-path bypass:

- packets may cache `queue_id`, `fairness_key`, and `owner_worker`
- but every packet still goes through enqueue, admission control, and scheduling

Owner selection

Owner formula

```
owner_worker =
  rendezvous_hash(interface_id, queue_id, fairness_key) over fairness_workers
```

Use rendezvous hashing or jump consistent hash, not plain modulo, so:

- worker-set changes move minimal keys
- fairness ownership is stable
- rebalance is less disruptive

Recommended policy

- use all workers attached to the shaped interface as fairness owners
- optionally prefer same-NUMA-socket owners if topology is known

Why not use RSS queue identity directly

RSS placement is:

- not fairness-aware
- not stable for adversarial flow spray
- not guaranteed to keep one host on one worker

So owner selection must be independent of packet arrival worker.

Remote enqueue mechanism

Each worker needs one MPSC or SPSC ring per owner destination:

```
remote_ingress[owner_worker]
```

Each ring element should carry:

- UMEM/frame reference
- packet length
- queue_id
- fairness_key
- enqueue timestamp
- TX metadata needed later

Important prerequisite

This design assumes one of:

1. workers on the same interface can share UMEM frame ownership safely
2. frame references can be transferred between workers without copying
3. there is an explicit move/clone mechanism for remote-owned packets

If the current implementation cannot transfer a frame reference between workers, that must be solved first. Without that, fairness-key ownership becomes much more expensive.

Admission control under ownership

This becomes much cleaner:

- host byte cap is per owner, therefore global for that host
- headroom is per owner queue, therefore global for that class shard
- reclaim list is per owner queue
- overflow is per owner queue

That means the current admission design now actually matches its intended semantics.

One caveat remains:

- per-owner queue headroom is only global within the owner shard

That is okay because each fairness key belongs to exactly one owner. The earlier cross-worker multiplication problem is gone.

Scheduler semantics

Keep the current two-phase scheduler model:

- phase 1: guarantee pass
- phase 2: surplus pass

But apply it differently:

- local classes are scheduled only from local queues
- fairness-owned classes are scheduled only from owner queues

This means a fairness-owned class on one worker contains packets for many remote RX workers, but still only one scheduler state for each fairness key.

Many-core token scaling

The current global atomic pools are conceptually correct but will become a coherence hotspot on many cores.

Use a 3-level structure:

```
GlobalTokenPool (authoritative, per interface/class)
  -> SocketLeasePool[NUMA node]
    -> WorkerLocalLease
```

Rules

1. Global pool refills by elapsed time and configured rate.
2. Socket pool leases chunks from the global pool.
3. Worker local cache leases smaller chunks from the socket pool.
4. Idle worker returns local lease to socket pool.
5. Idle socket pool returns unused credit to global pool.

Why this helps

- workers on the same socket mostly contend on local socket cache lines
- cross-socket traffic is reduced
- global atomics are touched much less often
- correctness remains global because socket pools are leases, not allocations

Required implementation detail

All token-pool structs must be cache-line padded:

- one bucket per cache line
- no packed arrays of atomics
- timestamps padded with their bucket if always accessed together

Without that, false sharing will erase most of the benefit.

Memory scaling

This design also improves memory scaling.

Current per-worker host fairness means:

- `workers * fairness_queues * max_host_slots`

host-state explosion.

With fairness-key ownership:

- each fairness key exists on exactly one worker
- total host-state becomes closer to:
  `fairness_queues * total_active_keys`

rather than:
  `workers * fairness_queues * duplicated_active_keys`

That is a major win on many cores.

Tradeoffs

This design is not free.

Costs introduced

1. Remote enqueue traffic
   Some packets will be handed from arrival worker to owner worker.

2. Hot-host concentration
   One very large elephant is intentionally concentrated on one owner worker.
   That means one host cannot scale across all cores.

3. Additional per-worker rings
   You need cross-worker ingress rings and flow control.

Why those costs are acceptable

- Remote enqueue is descriptor movement, not full packet reprocessing.
- Concentrating one host on one owner is desirable for fairness; otherwise the host multiplies its share by core count.
- Many independent hosts still scale across many workers because ownership is by key.

This is the correct tradeoff for adversarial fairness.

Recommended policy by class

Use ownership only where it matters.

Recommended:

- `network-control`, `expedited-forwarding`:
  local FIFO only

- `assured-forwarding`:
  local FIFO by default, fairness-owned only if operator explicitly enables it

- `best-effort`, `bulk-data`:
  fairness-owned by default

This minimizes remote enqueue overhead on the latency-sensitive path.

Failure and backpressure behavior

Remote ingress rings need explicit pressure handling:

1. If owner ingress ring is full:
   apply admission drop at sender side for fairness-owned classes

2. If owner worker is overloaded:
   its queue caps and overflow bucket apply normally

3. If owner worker fails or is removed:
   consistent hash remaps keys to new owners after epoch bump

This must be versioned alongside the existing config epoch.

Alternatives if remote ownership is impossible

If worker-to-worker frame transfer turns out to be too expensive or impossible in the current AF_XDP layout, the fallback alternative is:

- shared global host admission accounting
- local per-worker DRR service

That gives:

- global soft/hard caps
- still-local dequeue fairness

This is weaker than full ownership, but stronger than current per-worker-only fairness. I would only choose it if descriptor transfer is not viable.

Implementation sketch

Phase A

- add `owner_worker` calculation for fairness-enabled queues
- add remote ingress rings
- transfer fairness-owned packets to owner
- keep current local DRR/admission logic on owner only

Phase B

- add socket lease pools for aggregate/class token buckets
- pad token structures to cache lines
- add lease return up the hierarchy

Phase C

- benchmark same-class many-core contention
- benchmark one elephant across many workers
- benchmark 100 elephants / 100 mice across many workers

Benchmarks required for this design

1. One elephant across 16/32 workers:
   verify it gets one fairness share, not one per worker.

2. 100 elephants vs 100 mice across 16/32 workers:
   verify fairness remains key-based, not worker-based.

3. Same-class many-core hot load:
   verify socket lease pools reduce global atomic contention.

4. Cross-socket case:
   verify NUMA-local socket pools help.

5. Remote ingress ring saturation:
   verify bounded drops and no deadlock.

6. Hot elephant on one owner:
   verify one host does not exceed its intended share, even if it becomes owner-hotspot bound.

Bottom line

If the design must truly satisfy:

- many-core operation
- adversarial fairness
- uneven RSS distribution
- protocol obliviousness
- no shaping bypass

then the current document should move from:

- global class fairness + per-worker host fairness

to:

- global class fairness + ownership-based global host fairness

with:

- fairness-key owner workers for BE/bulk queues
- local FIFO for latency-sensitive queues
- hierarchical token leasing for many-core scaling

That is the cleanest concrete alternative that preserves the spirit of the current design while actually closing the many-core fairness hole.
