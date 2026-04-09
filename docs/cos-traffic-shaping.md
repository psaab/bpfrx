# Class of Service — Egress Traffic Shaping

Userspace-only implementation in the Rust AF_XDP forwarding plane.

## Scope and Non-Goals

**This is:**
- Userspace-only (Rust AF_XDP workers)
- Egress-only (shapes outbound traffic per interface)
- A Junos-inspired subset of CoS (not full Junos compatibility)
- Average-rate shaping with bounded burst release (not wire-level pacing)
- Protocol-oblivious at the scheduling layer (see below for precise scoping)

**This is not:**
- A replacement for ingress policers (flat policers remain for ingress)
- Perfect packet pacing (NIC TX ring owns wire timing after submission)
- A full Junos CoS implementation (no loss-priority-aware WRED, no
  multi-level hierarchical profiles, no per-VLAN schedulers in v1)
- A solution for single-worker CPU saturation under RSS skew (shared
  budgets solve correctness, not throughput — RSS rebalancing is the
  correct mitigation for CPU skew)

## Problem Statement

The current policer is a flat token bucket that drops excess packets on
arrival. There is no queuing, no bandwidth sharing between classes, and no
protection for low-rate flows competing with elephants.

What we need is **egress traffic shaping**: buffer packets in per-class
queues and transmit them at controlled rates.

| Aspect        | Policer              | Shaper                          |
|---------------|----------------------|---------------------------------|
| Action        | Drop on arrival      | Buffer and delay                |
| Burst         | Hard burst limit     | Absorbs bursts into queues      |
| Output        | Bursty drops         | Rate-controlled (batch-level)   |
| Bandwidth     | Wasted when idle     | Redistributed (work-conserving) |
| Direction     | Ingress or egress    | Egress only                     |
| Fairness      | None (random drops)  | Per-queue scheduling            |

The AF_XDP dataplane owns the TX ring, so we can implement real queuing and
scheduling. Packets are released in TX batches on poll cycles — smoother
than drop-on-arrival, but not NIC-level pacing.

## Service Model

This section defines what is **guaranteed**, what is **opportunistic**, and
what can be **starved**. The implementation must match these semantics exactly.

### Guaranteed

- Every queue's CIR (transmit-rate) is guaranteed as long as the queue has
  backlog. The scheduler serves all queues up to their CIR before applying
  priority to surplus. Guarantees hold over windows longer than one scheduling
  cycle plus burst horizon — not per-cycle. Phase 1 uses a rotating start
  index to prevent queue-index bias.

- Class budgets are shared across workers. A hot worker can claim the full
  class guarantee regardless of RSS distribution. This solves budget
  correctness. It does not eliminate single-worker CPU bottlenecks — if one
  worker receives all traffic, throughput is bounded by that worker's
  processing capacity.

### Opportunistic

- Surplus bandwidth (aggregate minus sum of active CIRs) is distributed to
  queues that have backlog, in strict priority order. High-priority queues
  get surplus first. This is not guaranteed — it depends on other queues'
  demand.

- `transmit-rate exact` queues never receive surplus. They are capped at CIR.

### Can Be Starved

- A queue's surplus share can be zero if higher-priority queues consume all
  available aggregate bandwidth above their CIR. CIR is still guaranteed.

- Per-host fairness within a queue is bounded by slab capacity. When the
  slab is full, the least-recently-active host is evicted (see Host State
  Lifecycle below).

## Architecture

### Component Chain

```
RX worker
  → parse / classify / derive fairness key + queue

  Local class (FIFO, latency-sensitive):
    → enqueue locally → scheduler → TX ring

  Fairness-owned class (BE/bulk):
    → compute owner = jump_hash(iface, class, key)
    → if owner == self: enqueue locally
      else: copy packet to owner's ingress ring
    → owner drains ingress → admission control → HostDrr → scheduler → TX ring

Admission control (on owner only):
  per-host soft/hard cap, over-cap-first reclaim, admission headroom

Scheduler (per worker):
  phase 1 (guarantee) + phase 2 (priority surplus)
  → aggregate shaping-rate (hierarchical token lease)
  → TX ring submission
```

### Two-Phase Scheduling

The scheduler runs two passes per cycle. This is the core algorithm.

**Phase 1 — Guarantee pass**: Serve each backlogged queue up to its CIR.
Uses a rotating active-class round-robin with a bounded per-class quantum
per visit. This ensures no queue is systematically favored by iteration
order, and no single queue can consume the entire cycle budget.

```
cir_quantum = max(mtu, min(class_cir * 100µs, 32 KB))

phase_1_guarantee(queues, aggregate, cir_cursor):
  repeat while batch_budget > 0 and any queue has CIR tokens + backlog:
    qi = cir_cursor.next_eligible()
    dequeue up to min(cir_quantum, queue[qi].cir_tokens, aggregate_tokens)
    charge queue[qi].cir + aggregate
```

Each class gets at most `cir_quantum` bytes per visit. The cursor advances
round-robin. Multiple rounds per cycle are possible if budget remains. This
gives bounded, rate-informed fairness among classes — not exact proportional
per-visit service, because the quantum is clamped between MTU and 32 KB.
Low-rate queues are dominated by the MTU floor; high-rate queues by the
32 KB ceiling. Over multiple rounds, service converges toward CIR-proportional.

**Phase 2 — Surplus pass**: Distribute remaining aggregate tokens by strict
priority. Highest-priority non-empty queues with PIR tokens get surplus
first. Within the same priority level, Deficit Weighted Round Robin (DWRR)
distributes surplus proportionally to CIR weight, with deficit carry across
rounds.

```
phase_2_surplus(queues, aggregate, remaining_budget):
  for priority in [strict-high, high, medium, low, best-effort]:
    active = queues at this priority with backlog and PIR tokens and !exact
    if active is empty: continue

    if len(active) == 1:
      dequeue up to min(queue.pir_tokens, aggregate_tokens, remaining_budget)
      charge queue.pir + aggregate
    else:
      DWRR round across active queues (see below)

    if dequeued anything: break  // strict priority for surplus only
```

**Deficit Weighted Round Robin (within same priority)**:

Each queue at the same priority level has a `surplus_deficit` counter that
carries across scheduling rounds. Per round:

```
for each queue in active set:
  queue.surplus_deficit += queue.cir_weight_fraction * round_quantum
  while queue.surplus_deficit >= next_pkt_len and budget remains:
    dequeue packet
    queue.surplus_deficit -= pkt_len
    charge queue.pir + aggregate
```

This is real WRR with deficit carry. Earlier queues do not starve later
queues because deficit is persistent.

### Token Buckets — All Shared, No Per-Worker Partitioning

**Every token bucket in the hierarchy is shared across all workers via
`AtomicI64`**. There are no per-worker rate fractions. This provides true
global guarantees regardless of RSS distribution.

Each worker maintains a **local batch cache** per bucket to amortize atomic
operations. The cache is just a local copy of claimed tokens — not a separate
rate allocation.

```
Shared (AtomicI64):
  aggregate.CIR     ← total interface budget
  queue[0].CIR      ← queue 0 guaranteed budget
  queue[0].PIR      ← queue 0 ceiling budget
  ...

Per-worker (local cache only, returned when idle):
  aggregate_cache    ← batch of tokens claimed from aggregate.CIR
  queue_cir_cache[N] ← batch of tokens claimed from queue[N].CIR
  queue_pir_cache[N] ← batch of tokens claimed from queue[N].PIR
```

**Dynamic lease size**: The lease (local cache batch) is **not** a fixed
64 KB. It is computed per pool based on rate and target precision:

```
lease_bytes = clamp(
    rate_bytes_per_us * target_lease_us,
    min_lease_bytes,       // floor: 1 MTU (1500 bytes)
    min(configured_burst / 8, max_lease_bytes)
)
```

Recommended defaults:
- `target_lease_us = 25` (25µs of traffic per claim)
- `min_lease_bytes = 1500` (one MTU — a packet must always be coverable)
- `max_lease_bytes = 64 KB` for aggregate
- `max_lease_bytes = 16 KB` for class buckets

| Rate     | Raw (25µs) | Clamped  | Notes                        |
|----------|-----------|----------|-------------------------------|
| 10 Gbps  | 31.25 KB  | 31.25 KB | ~20 packets per claim        |
| 1 Gbps   | 3.125 KB  | 3.125 KB | ~2 packets per claim         |
| 100 Mbps | 312 B     | 1500 B   | clamped to MTU floor         |
| 10 Mbps  | 31 B      | 1500 B   | clamped to MTU floor         |

**Why the MTU floor matters**: A token lease smaller than one MTU means a
single packet can never be covered by one claim. Without the floor, a
1500-byte packet on a 10 Mbps queue would require ~48 atomic claims. The
MTU floor ensures that every lease can cover at least one packet. At low
rates this means one atomic per packet, which is acceptable — low-rate
queues have low packet rates by definition.

**Alternative for very low rates**: Below `min_lease_bytes / target_lease_us`
(i.e., below ~60 Mbps), the worker can optionally skip the local cache
entirely and charge directly from the shared pool. This is simpler and
equally fast because the packet rate is low enough that per-packet atomics
are not a bottleneck.

**Lease return**: Workers return unused local tokens to the shared pool when:
- The corresponding queue becomes idle (no backlog for that pool)
- The worker quiesces (no work for `IDLE_QUIESCE_ITERS` iterations)
- Lease age exceeds `lease_idle_us` (default 100µs) without being used
- Config change or HA transition triggers a full flush

This prevents stranding tokens on idle workers. A worker that claims
aggregate tokens then goes idle returns them within 100µs, making them
available to the actually-busy worker.

**Total lease credit bound**: The maximum total leased-but-unspent tokens
across all workers is bounded per bucket:

```
max_total_leased = min(bucket_burst / 4, lease_per_worker * max_active_workers)
```

When claiming, if the shared pool's tokens minus `max_total_leased` would
go negative, the worker receives a smaller lease (only what's available).
This prevents N workers from collectively draining the pool far beyond
what's immediately needed.

| Workers | Aggregate lease | Total leased | At 10 Gbps | At 1 Gbps |
|---------|----------------|--------------|------------|-----------|
| 4       | 31 KB          | 124 KB       | ~0.1 ms    | ~1 ms     |
| 16      | 31 KB          | 496 KB       | ~0.4 ms    | ~4 ms     |
| 32      | 31 KB          | 992 KB       | ~0.8 ms    | ~8 ms     |

At 32 workers and 1 Gbps, ~8ms of outstanding credit. This is bounded by
`burst / 4`, so a 125 MB burst cap limits total leased to ~31 MB regardless
of worker count. At high worker counts, per-worker lease size should be
reduced: `lease_per_worker = min(computed_lease, max_total_leased / active_workers)`.

### CIR and PIR Bucket Semantics

Each queue has two independent token buckets:

- **CIR bucket**: Refills at `transmit-rate`. Tracks guaranteed bandwidth.
  Consumed during Phase 1 (guarantee pass).

- **PIR bucket**: Refills at `ceiling-rate` (or aggregate rate if no ceiling
  configured). Tracks total bandwidth including surplus. Consumed during
  Phase 2 (surplus pass) only.

CIR and PIR are **not both charged for the same packet**:
- Phase 1 (within guarantee): charge CIR + aggregate. PIR is not touched.
- Phase 2 (surplus/borrowing): charge PIR + aggregate. CIR was already empty.

`transmit-rate exact`: PIR bucket is unused. Queue is capped at CIR.
No surplus service in Phase 2.

`ceiling-rate 0` (or unset): PIR refills at aggregate rate. No per-queue
ceiling — queue can use any surplus up to aggregate availability.

### Per-Host Fair Queuing

Within each class queue, traffic is sub-queued by a configurable fairness
key. Each sub-queue is served via Deficit Round Robin on the dequeue side.

**Recommendation**: Host DRR is most useful on `low` and `best-effort`
queues with large buffers. Latency-sensitive queues (`strict-high`, `high`)
should use FIFO with small buffers. Do not enable host DRR on queues where
tail latency matters — DRR round length grows with active host count.

**Fairness key options** (configured per scheduler):

| Key               | Semantics                              | Use case               |
|-------------------|----------------------------------------|------------------------|
| `source-address`  | `{src_ip}` — default                   | Outbound subscriber    |
| `destination-address` | `{dst_ip}`                          | Inbound/download       |
| `source-prefix N` | `{src_ip masked to /N}`                | Aggregate by subnet    |
| `5-tuple`          | Full flow key                          | Per-connection fairness|
| disabled           | FIFO within queue (no per-host DRR)   | Simple / low-latency   |

Only `source-address` is implemented in Phase 3. The others are listed to
establish that the fairness key is a policy choice, not hardcoded. The
data structures use a generic `FairnessKey` type.

**Dynamic quantum**: The quantum is not a fixed static number. It adapts
to active host count and queue rate to bound worst-case inter-service delay:

```
quantum = clamp(
    queue_rate_bytes_per_us * target_host_round_us / max(active_hosts, 1),
    min_quantum_bytes,     // floor: 2 × MTU = 3000 bytes
    max_quantum_bytes      // ceiling: 32 KB
)
```

Recommended defaults:
- `target_host_round_us = 250` (250µs worst-case round)
- `min_quantum_bytes = 3000` (2 × MTU)
- `max_quantum_bytes = 32768` (32 KB)

| Active hosts | Queue CIR | Target round | Quantum   |
|-------------|-----------|--------------|-----------|
| 10          | 1 Gbps   | 250µs        | 3.125 KB  |
| 100         | 1 Gbps   | 250µs        | 3000 B*   |
| 10          | 10 Gbps  | 250µs        | 31.25 KB  |
| 100         | 10 Gbps  | 250µs        | 3.125 KB  |
| 1000        | 10 Gbps  | 250µs        | 3000 B*   |

\* clamped to `min_quantum_bytes`

At 1000 hosts on a 10 Gbps queue: worst-case inter-service delay is
1000 × 3000 / 1.25 GB/s = 2.4ms. At 100 hosts on 1 Gbps: 100 × 3000 /
125 MB/s = 2.4ms. Both are bounded by the quantum floor.

DRR is recommended **only** for `low` and `best-effort` queues. Latency-
sensitive queues (`strict-high`, `high`) should use FIFO with small buffers
where inter-service delay is simply queue depth / rate.

### Global vs Per-Worker Fairness

**Class fairness is global.** CIR, PIR, and aggregate token pools are shared
across all workers. A class guarantee is honored regardless of which workers
process that class's traffic.

**Host fairness uses fairness-key ownership.** Each fairness key is assigned
to exactly one **owner worker**. All packets for that key are enqueued and
scheduled only on the owner. This gives true global per-host fairness
without shared mutable host state.

The problem: if host fairness were purely per-worker, an elephant spreading
flows across N workers would get N× the DRR quantum, N× the soft cap, and
N× the queue share. This is the core many-core flow-multiplication problem.

Three options were evaluated:

1. **Shared global host state** (locks/atomics on every enqueue/dequeue):
   Correct but heavy. Shared mutable host maps, deficits, byte counters,
   and reclaim state across all workers creates cache-line bouncing and
   scaling issues on many-core systems. Wrong performance tradeoff for
   AF_XDP userspace.

2. **Fairness-key ownership** (chosen): Each fairness key has one owner
   worker. All packets for that key route to the owner. One host = one DRR
   entry, one admission cap, one overflow position. No shared mutable host
   state. Many independent hosts scale across many workers naturally.

3. **Accept per-worker host fairness**: Would require substantially weakened
   adversarial claims. Does not meet the original requirements.

#### Class Modes

Not every class uses ownership. Classes are split by scheduling policy:

- **Local classes** (`network-control`, `expedited-forwarding`): Latency-
  sensitive FIFO. Scheduled locally on the current worker. No host DRR.
  No ownership overhead.

- **Fairness-owned classes** (`best-effort`, `bulk-data`): Host fairness
  enabled. Fairness-key ownership applies. Packets may be forwarded to
  their owner worker before enqueue.

- **Optionally owned** (`assured-forwarding`): Local FIFO by default.
  Operators can enable fairness ownership if needed.

#### Owner Selection

```
owner_worker = jump_consistent_hash(
    hash(interface_id, queue_id, fairness_key),
    num_fairness_workers
)
```

Jump consistent hash (not plain modulo) so worker-set changes move
minimal keys. Ownership is stable and rebalance is less disruptive.

When a worker is added or removed, only `~1/N` of keys remap. The remap
is versioned alongside the existing config epoch — stale `owner_worker`
values in the flow cache are invalidated on epoch bump.

#### Remote Enqueue

When a packet arrives on a non-owner worker for a fairness-owned class:

```
RX worker (non-owner):
  1. Parse, classify, derive fairness_key
  2. Compute owner = jump_hash(interface, class, key)
  3. Copy packet data + metadata into owner's ingress ring
  4. Recycle local UMEM frame immediately

Owner worker:
  1. Drain remote ingress rings (bounded per cycle)
  2. Allocate local UMEM frame, copy packet in
  3. Apply admission control (host caps, headroom)
  4. Enqueue into local HostDrr
  5. Schedule and submit to TX ring
```

**UMEM constraint**: Each worker has its own UMEM (per-worker `Rc<MmapArea>`,
not shared across threads). Frame references cannot be transferred between
workers. Remote enqueue requires a **packet copy** — the arrival worker
copies packet bytes into a cross-worker ring, and the owner allocates a
local UMEM frame and copies in. This is the same pattern as the existing
`TxRequest { bytes: Vec<u8> }` path for locally-generated packets.

**Ring structure**: Each worker maintains one SPSC ring per peer worker for
each fairness-owned class. Ring elements carry:

```rust
struct RemoteEnqueueEntry {
    packet_data: [u8; MAX_FRAME_SIZE],  // or heap-allocated Vec<u8>
    len: u32,
    queue_id: u8,
    fairness_key: FairnessKey,
    enqueue_ns: u64,
    // TX metadata:
    expected_ports: Option<(u16, u16)>,
    expected_addr_family: u8,
    expected_protocol: u8,
    flow_key: Option<SessionKey>,
}
```

**Backpressure**: If the owner's ingress ring is full, the sending worker
applies admission drop at the sender side. This is equivalent to queue-full
tail-drop but happens earlier.

**Cost**: The packet copy adds ~100-300ns per packet (depending on size).
This only applies to fairness-owned classes where the packet lands on a
non-owner worker. With good RSS distribution, most packets land on or near
their owner. The copy cost is acceptable because fairness-owned classes
(BE/bulk) are not latency-sensitive — the entire point is that they trade
latency for fairness.

#### What This Means for Adversarial Scenarios

- **One elephant across 32 workers**: All packets hash to one owner.
  Elephant gets one DRR entry, one soft cap, one overflow slot. It cannot
  multiply its share by spreading flows. Non-owner workers just forward
  to the owner.

- **100 elephants vs 100 mice across 32 workers**: Each fairness key is
  independently owned. Load spreads naturally across workers by key.
  Each host has exactly one fairness state globally.

- **Hot elephant on one owner**: The elephant's owner worker may become
  CPU-bound. This is intentional — concentrating one host on one owner
  is the mechanism that prevents share multiplication. The elephant cannot
  exceed its share even if it becomes the owner's bottleneck.

#### Memory Scaling Under Ownership

With per-worker host fairness, memory scales as `workers × queues × slots`.
With ownership, each fairness key exists on exactly one worker:

```
Owned:   fairness_queues × total_active_keys × slot_size
Per-worker: workers × fairness_queues × duplicated_keys × slot_size
```

On a 32-worker system with 10,000 active hosts and 2 fairness queues:
- Owned: 2 × 10,000 × 128B = ~2.5 MB
- Per-worker: 32 × 2 × 10,000 × 128B = ~80 MB

Ownership reduces host-state memory by the worker count factor.

### Admission Control — Two-Tier Per-Host Caps

DRR only controls dequeue order among already-enqueued packets. Without
admission control, elephants can fill the queue buffer before DRR ever
runs, causing mice to be tail-dropped on arrival.

**This is the single most important mechanism for adversarial resilience.**
Dequeue fairness alone is not enough. Admission fairness decides who gets
into the queue in the first place.

Finite buffers mean no design can promise literal zero drop for mice under
infinite overload. The target is: **mice retain admission and low drop
probability even when elephants saturate the queue.**

#### Soft Cap, Hard Cap, and Admission Headroom

Each active host gets two dynamic admission thresholds:

```
host_soft_cap = clamp(
    queue_buffer_bytes / max(active_hosts, 1),
    min_host_cap_bytes,     // floor: 8 KB
    max_host_cap_bytes      // ceiling: 512 KB
)
host_hard_cap = 2 * host_soft_cap
```

Note: `cap_factor` is 1, not 2. This is critical. With `cap_factor = 1`,
the sum of all soft caps equals the queue buffer. Any host that receives
one more packet beyond its fair share immediately crosses soft cap and
becomes reclaimable. With `cap_factor = 2`, hosts can fill the queue
while all remaining below soft cap, leaving no reclaim candidate.

With 10 active hosts on a 16 MB queue: `soft_cap = 1.6 MB`, `hard_cap = 3.2 MB`.
With 100 hosts: `soft_cap = 160 KB`, `hard_cap = 320 KB`.

**Admission headroom**: A fraction of the queue buffer is reserved for
new or under-cap hosts. Over-cap incumbents cannot consume this headroom:

```
incumbents_cap = queue_buffer_bytes * (1 - headroom_pct)   // e.g. 90%
headroom = queue_buffer_bytes * headroom_pct                // e.g. 10%
```

Default `headroom_pct = 0.10` (10%). This guarantees that even when all
incumbent hosts are at or below soft cap and the queue is 90% full, 10%
of buffer space is reserved for new arrivals. Over-cap hosts are rejected
when total queue bytes exceed `incumbents_cap`, even if the absolute buffer
limit has not been reached.

**Why this fixes the many-elephants case**: 100 elephants on a 16 MB queue
with `soft_cap = 160 KB`. If they fill 14.4 MB (90% incumbents cap), the
headroom kicks in: elephants at soft_cap boundary are rejected or reclaimed.
The remaining 1.6 MB is available for mice. Even if all elephants are exactly
at soft_cap (unlikely — any slight imbalance pushes the largest over), the
headroom ensures mice can still enqueue.

#### Admission Policy

For fairness-enabled classes:

1. **Host below soft cap, queue below incumbents cap**: Admit unconditionally.
2. **Host exceeds hard cap**: Drop immediately.
3. **Host above soft cap and queue above incumbents cap**: Reclaim from
   this host's tail, or drop incoming.
4. **Incoming host below soft cap but queue full**: Reclaim from an over-cap
   host via the reclaim list. If reclaim list is empty, reclaim from the
   deepest host (see fallback below).
5. **No reclaimable host and queue truly full**: Fall back to tail-drop.
   This can only happen when the queue is entirely consumed by the protected
   headroom — i.e., many under-cap mice, which means fairness is already
   being served.

#### Over-Cap Reclaim List

Hosts that cross soft cap are linked into a **per-class reclaim list**
for O(1) reclaim candidate selection:

- When a host's `queued_bytes` crosses `soft_cap` on enqueue: mark
  `over_cap = true`, link into `reclaim_list_head`.
- When a host's `queued_bytes` falls below `soft_cap` on dequeue: unmark,
  unlink from reclaim list.
- On queue-full reclaim: pop from `reclaim_list_head`, drop from that
  host's tail. **O(1)**.

**Deepest-host fallback**: When the reclaim list is empty but the queue is
full (all hosts at or below soft cap), maintain a `deepest_host_idx` that
tracks the host with the most queued bytes. Updated on every enqueue (if
the enqueuing host's `queued_bytes` exceeds the current max, update the
tracker). On reclaim-list-empty, reclaim from `deepest_host_idx`.

This is a **heuristic, not an exact max-tracker**. The tracker is O(1)
optimistic: updated on enqueue, but may be stale after dequeue (the deepest
host may have drained). On a stale miss (tracked host is now empty or below
threshold), the fallback does one O(N_active) scan to find the true deepest
host and refreshes the tracker. Under steady-state, stale misses are rare
because the deepest host typically stays deep. Under adversarial churn, the
occasional O(N) scan is acceptable because it only fires when the reclaim
list is empty — which itself means no host is over soft cap, a scenario
that's bounded by the admission headroom mechanism.

```rust
fn enqueue_frame(
    cos: &mut CosState,
    queue_id: u8,
    frame: QueuedFrame,
    config: &CosInterfaceConfig,
) -> bool {
    let sched = &config.queues[queue_id as usize];
    let queue = &mut cos.queues[queue_id as usize];
    let pkt_bytes = frame.len as u64;

    // Global UMEM pressure check
    if cos.total_queued_frames >= cos.umem_budget_frames {
        if !reclaim_from_overcap_host(cos, config, queue_id) {
            queue.stats.dropped_admission += 1;
            return false;
        }
    }

    // Per-host admission control (when host fairness enabled)
    if let Some(ref mut hosts) = queue.hosts {
        let host_bytes = hosts.queued_bytes(&frame.fairness_key);
        let (soft_cap, hard_cap) = hosts.caps(sched);
        let incumbents_cap = sched.incumbents_cap();

        // Always enforce frame cap (UMEM safety — see finding #2)
        if queue.total_frames >= sched.buffer_frames {
            queue.stats.dropped_frame_cap += 1;
            return false;
        }

        // Rule 2: hard cap — always drop
        if host_bytes + pkt_bytes > hard_cap {
            queue.stats.dropped_hard_cap += 1;
            return false;
        }

        // Headroom enforcement: over-cap hosts rejected above incumbents_cap
        if host_bytes >= soft_cap && queue.total_bytes > incumbents_cap {
            // Rule 3: over-cap host in headroom zone — reclaim from self
            hosts.drop_from_host_tail(&frame.fairness_key, queue);
            queue.stats.dropped_overcap_reclaim += 1;
        }

        if queue.total_bytes + pkt_bytes > sched.buffer_bytes {
            // Queue truly full
            if host_bytes >= soft_cap {
                queue.stats.dropped_overcap_reclaim += 1;
                hosts.drop_from_host_tail(&frame.fairness_key, queue);
            } else {
                // Rule 4: under-cap host — reclaim from over-cap or deepest
                if !hosts.reclaim_from_overcap_or_deepest(queue) {
                    // Rule 5: all hosts under cap, headroom exhausted
                    queue.stats.dropped_tail += 1;
                    return false;
                }
                queue.stats.dropped_overcap_reclaim += 1;
            }
        } else if host_bytes + pkt_bytes > soft_cap {
            // Not full, but host crossing soft cap — admit, mark over-cap
            hosts.mark_overcap(&frame.fairness_key);
        }

        hosts.enqueue(frame.fairness_key, frame);
    } else {
        // No host fairness — plain byte/frame limit
        if queue.total_bytes + pkt_bytes > sched.buffer_bytes {
            queue.stats.dropped_tail += 1;
            return false;
        }
        if queue.total_frames >= sched.buffer_frames {
            queue.stats.dropped_tail += 1;
            return false;
        }
        queue.fifo.push_back(frame);
    }

    queue.total_bytes += pkt_bytes;
    queue.total_frames += 1;
    cos.total_queued_bytes += pkt_bytes;
    cos.total_queued_frames += 1;
    queue.stats.enqueued_pkts += 1;
    queue.stats.enqueued_bytes += pkt_bytes;
    true
}
```

**How admission control protects mice under every scenario**:

- **Elephant crosses soft cap**: Linked into reclaim list. On queue-full,
  O(1) reclaim from list head.
- **Many elephants, all at soft cap boundary**: The 10% headroom ensures
  mice can still enqueue. Over-cap hosts are rejected above `incumbents_cap`
  (90%). The remaining 10% is reserved for under-cap arrivals.
- **Many elephants, all below soft cap, queue full**: `reclaim_from_overcap_or_deepest()`
  falls back to `deepest_host_idx` — the host with the most queued bytes is
  reclaimed even if technically below soft cap. This covers the equilibrium
  case where `cap_factor=1` and hosts are exactly at their fair share.

### Queue Data Structure

Each host within a class queue owns its own packet buffer. There is no
shared parent `VecDeque` with host index ranges.

```
ClassQueue:
  hosts: HostDrr
    ├── active list (DRR round-robin, doubly-linked)
    │   ├── Host A: VecDeque<QueuedFrame>  [over_cap=true]
    │   ├── Host B: VecDeque<QueuedFrame>
    │   └── Host C: VecDeque<QueuedFrame>
    ├── reclaim list (over-cap hosts, doubly-linked, O(1) pop)
    │   └── Host A ← linked when queued_bytes > soft_cap
    └── free list (slab reuse)
  overflow: VecDeque<QueuedFrame>  (bounded FIFO for excess fairness keys)
  fifo: VecDeque<QueuedFrame>      (used when host fairness disabled)
  total_bytes: u64
  total_frames: u32
```

Packets are enqueued into the host's own VecDeque. The DRR scheduler
round-robins across hosts, dequeuing from each host's buffer. Overflow
packets (from hosts that couldn't get a DRR slot) are served FIFO,
interleaved with DRR service at a configurable ratio.

All operations are O(1):

- Enqueue: AHashMap lookup → host VecDeque push_back
- Dequeue: follow active-list pointer → host VecDeque pop_front
- Round-robin advance: follow `active_next` pointer
- Host activation: append to active list tail
- Host removal (empty): unlink from active list, move to free list
- Over-cap mark: link into reclaim list head
- Over-cap unmark: unlink from reclaim list
- Reclaim candidate: pop reclaim list head — **O(1)**, no scanning

### TX Ownership — Scheduler Submits Directly to TX Ring

The shaper does **not** feed into `pending_tx_prepared`. It submits directly
to the TX ring via the same `tx.transmit()` + `writer.insert()` path, but
from the scheduler's own dequeue loop.

```
Shaped interface:
  RX → forward decision → classify → cos_queues[class].enqueue()
  ...
  poll cycle: drain_shaped_tx() → tx.transmit() → TX ring

Unshaped interface (unchanged):
  RX → forward decision → pending_tx_prepared → drain_pending_tx → TX ring
```

**Every packet that egresses a shaped interface goes through CoS queuing.**
This includes:

- Forwarded traffic (session hit and miss): classified, then enqueued
  locally (local class) or forwarded to owner (fairness-owned class)
- Locally generated packets (TCP RST, ICMP errors): enqueued into the
  network-control queue (queue 3, local FIFO, strict-high priority)
- Cross-binding forwards: classified and routed to the appropriate
  owner worker if fairness-owned, otherwise enqueued locally

No traffic bypasses the shaper on a shaped interface. The aggregate token
bucket accounts for all egress bytes, including remote-enqueued packets.

**TX ring full**: If the TX ring cannot accept all dequeued frames, the
excess frames are returned to the **front** of their respective class queues
and host subqueues. `QueuedFrame` stores `queue_id` for this purpose (see
struct definition below). Host ordering is preserved because frames are
pushed to the front of the host's VecDeque.

If the TX ring stays full across multiple cycles, queued packets accumulate
and eventually trigger per-host caps or queue byte limits. This is bounded
by the UMEM budget, not by cycle count.

### Scheduler Liveness

The worker loop runs continuously (busy-poll or 1µs sleep). Key guarantee:

**`drain_shaped_tx()` sets `did_work = true` whenever any class queue is
non-empty**, even if no packets could be transmitted this cycle (e.g.,
all token buckets empty). This prevents the worker from sleeping while
queued packets wait for token refill.

When tokens refill (elapsed time × rate), the next cycle's `drain_shaped_tx()`
will dequeue and transmit.

### Queue Classification Caching

The flow cache stores `queue_id` to avoid re-running the classifier on
every session-hit packet. This is a performance optimization, not a shaper
bypass — the enqueue and scheduling path is identical for hits and misses.

**Invalidation**: Cached `queue_id` values are invalidated by the existing
epoch mechanism. When `ForwardingState` changes (config reload, HA
transition, classifier change), the flow cache epoch increments and all
stale entries are discarded on next access. No separate invalidation needed.

## Protocol Obliviousness

Scheduler decisions are protocol-oblivious once a packet has been classified
and assigned a fairness key. Specifically:

- Token buckets and DRR deficits operate on byte count. No protocol-specific
  weighting, no TCP-vs-UDP differentiation, no header-length adjustments.
- Elephant detection uses EWMA of bytes/time. A host sending 500 Mbps of
  ESP looks identical to one sending 500 Mbps of TCP.
- The scheduler never inspects L4 headers, protocol numbers, or payload.

**Scope**: This applies within the IP forwarding model. Classification
itself may be protocol-aware (DSCP, L4 ports in firewall filters). Non-IP
traffic is not supported by the fairness key layer but can be queued in a
class with fairness disabled (FIFO mode).

## Rust Data Structures

### Configuration (Shared, Read-Only via ArcSwap)

```rust
pub(crate) struct CosInterfaceConfig {
    pub shaping_rate_bpns: f64,
    pub shaping_burst_bytes: u64,
    pub queues: [QueueSchedulerConfig; 8],
    /// DSCP→queue classifier (64 entries, one per 6-bit DSCP codepoint).
    /// 0xFF = use default queue (0).
    pub dscp_classifier: [u8; 64],
}

pub(crate) struct QueueSchedulerConfig {
    pub name: String,
    pub cir_rate_bpns: f64,
    pub cir_burst_bytes: u64,
    pub pir_rate_bpns: f64,
    pub pir_burst_bytes: u64,
    pub exact: bool,
    pub priority: u8,
    /// Maximum queue depth in bytes. Primary limit.
    pub buffer_bytes: u64,
    /// Maximum queue depth in frames (secondary safety cap).
    pub buffer_frames: u32,
    pub fairness: FairnessMode,
    /// Maximum DRR quantum (bytes). Actual quantum is dynamic.
    pub max_quantum_bytes: u32,
    /// Target worst-case inter-service delay (µs). Default 250.
    pub target_host_round_us: u32,
    /// Minimum quantum (bytes). Default 3000 (2× MTU).
    pub min_quantum_bytes: u32,
    pub elephant_threshold: u32,
    pub elephant_quantum_div: u32,
    /// Soft cap factor. soft_cap = buffer / active_hosts * cap_factor.
    pub cap_factor: u32,          // default 1
    /// Admission headroom fraction (0-100). Default 10 (10%).
    pub headroom_pct: u32,
    /// Minimum per-host soft cap (bytes). Default 8192.
    pub min_host_cap_bytes: u64,
    /// Maximum per-host soft cap (bytes). Default 524288 (512 KB).
    pub max_host_cap_bytes: u64,
    /// Maximum host slots for this queue's DRR slab. Default 4096.
    pub max_host_slots: u32,
    /// Host idle timeout (ns). Default 10s.
    pub host_idle_timeout_ns: u64,
    pub active: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FairnessMode {
    Disabled,
    SourceAddress,
    DestinationAddress,
    SourcePrefix(u8),
    FiveTuple,
}
```

### Hierarchical Token Pools

On many-core systems, all workers hitting the same global atomics causes
cache-line ping-pong. A three-level hierarchy reduces cross-socket
coherence traffic while keeping rate correctness global:

```
GlobalTokenPool (authoritative, per interface/class)
  → SocketLeasePool[NUMA node]    (per-socket intermediate)
    → WorkerLocalLease             (per-worker cache)
```

Rules:
1. Global pool refills by elapsed time and configured rate.
2. Socket pool leases chunks from the global pool.
3. Worker local cache leases smaller chunks from the socket pool.
4. Idle worker returns local lease to socket pool.
5. Idle socket pool returns unused credit to global pool.

Workers on the same socket contend on local socket cache lines. Cross-socket
traffic is reduced to socket-pool ↔ global-pool leasing, which happens
infrequently.

Each pool level is cache-line padded:

```rust
/// One token pool: tokens + refill timestamp on the same cache line.
#[repr(align(128))]  // 2× cache line to avoid adjacent-sector prefetch
pub(crate) struct AlignedTokenPool {
    pub tokens: AtomicI64,
    pub last_refill_ns: AtomicU64,
    _pad: [u8; 112],
}

/// Global authoritative token pools for one shaped interface.
pub(crate) struct GlobalTokenPools {
    pub aggregate: AlignedTokenPool,
    pub queue_cir: [AlignedTokenPool; 8],
    pub queue_pir: [AlignedTokenPool; 8],
}

/// Per-NUMA-socket intermediate lease pool.
/// Workers on this socket lease from here, not directly from global.
pub(crate) struct SocketLeasePool {
    pub aggregate: AlignedTokenPool,
    pub queue_cir: [AlignedTokenPool; 8],
    pub queue_pir: [AlignedTokenPool; 8],
}
```

On a 2-socket system with 16 cores per socket: each socket pool handles
up to 16 workers locally. Global pool is touched only when a socket pool
runs dry (~once per `socket_lease_size / socket_aggregate_rate`).

On single-socket systems, the socket layer is a no-op passthrough — workers
lease directly from global.

### Per-Worker Mutable State

```rust
pub(crate) struct CosState {
    queues: [ClassQueue; 8],
    agg_cache: LocalBatchCache,
    queue_cir_cache: [LocalBatchCache; 8],
    queue_pir_cache: [LocalBatchCache; 8],
    global_pools: Arc<GlobalTokenPools>,
    socket_pool: Arc<SocketLeasePool>,
    surplus_deficit: [i64; 8],
    /// Rotating start index for Phase 1 guarantee fairness.
    phase1_start: u8,
    total_queued_bytes: u64,
    total_queued_frames: u32,
    umem_budget_frames: u32,
    /// Remote ingress rings for fairness-owned classes.
    /// Packets from non-owner workers arrive here.
    remote_ingress: Vec<spsc::Consumer<RemoteEnqueueEntry>>,
    /// Outbound rings to other workers (for packets we don't own).
    remote_egress: Vec<spsc::Producer<RemoteEnqueueEntry>>,
    /// This worker's ID (for owner calculation).
    worker_id: u32,
    /// Number of fairness workers for this interface.
    num_fairness_workers: u32,
}

struct ClassQueue {
    hosts: Option<HostDrr>,
    fifo: VecDeque<QueuedFrame>,
    /// Overflow bucket for fairness keys that exceed max_host_slots.
    /// Bounded FIFO — hosts that can't get a DRR slot still make progress.
    overflow: VecDeque<QueuedFrame>,
    total_bytes: u64,
    total_frames: u32,
    stats: QueueStats,
}

struct QueueStats {
    enqueued_pkts: u64,
    enqueued_bytes: u64,
    dequeued_pkts: u64,
    dequeued_bytes: u64,
    cir_served_bytes: u64,
    pir_served_bytes: u64,
    dropped_tail: u64,
    dropped_frame_cap: u64,
    dropped_hard_cap: u64,
    dropped_overcap_reclaim: u64,
    dropped_admission: u64,
    overflow_admissions: u64,
}

struct QueuedFrame {
    offset: u64,
    len: u32,
    queue_id: u8,              // for requeue on TX backpressure
    recycle: PreparedTxRecycle,
    fairness_key: FairnessKey,
    enqueue_ns: u64,
    // TX metadata preserved for deferred transmission:
    expected_ports: Option<(u16, u16)>,
    expected_addr_family: u8,
    expected_protocol: u8,
    flow_key: Option<SessionKey>,
}

struct LocalBatchCache {
    tokens: i64,
    batch_size: i64,    // dynamic, computed per pool
    last_claim_ns: u64, // for cache-age-based return
}
```

### Host DRR (Per-Host Owned Sub-Queues)

```rust
/// Deficit Round Robin across hosts within a class queue.
///
/// Uses AHashMap (randomized, AES-accelerated on x86) instead of FxHashMap
/// to resist adversarial hash collision attacks on public traffic keys.
///
/// All operations O(1):
///   - enqueue: AHashMap lookup + VecDeque push_back
///   - dequeue: active-list pointer + VecDeque pop_front
///   - round-robin advance: doubly-linked list next pointer
///   - host byte cap check: per-host queued_bytes field
///   - heaviest-host lookup: O(N_active) — congestion path only
struct HostDrr {
    slab: Vec<HostSlot>,
    /// AHashMap: randomized key, collision-hardened for adversarial input.
    map: AHashMap<FairnessKey, u32>,
    /// Active host list (DRR round-robin order).
    active_head: u32,
    active_count: u32,
    /// Current host being served (DRR cursor).
    current: u32,
    /// Free list for slab reuse.
    free_head: u32,
    capacity: u32,
    /// Over-cap reclaim list: hosts whose queued_bytes > soft_cap.
    /// Used for O(1) reclaim candidate selection on queue-full events.
    reclaim_head: u32,
    reclaim_count: u32,
}

struct HostSlot {
    key: FairnessKey,
    /// This host's owned packet buffer.
    packets: VecDeque<QueuedFrame>,
    /// Per-host byte tracking for admission control.
    queued_bytes: u64,
    queued_frames: u32,
    deficit: i32,
    ewma_rate_kbps: u32,
    byte_count: u64,
    last_seen_ns: u64,
    is_elephant: bool,
    /// Whether this host is currently over its soft cap.
    over_cap: bool,
    // Doubly-linked active list (DRR round-robin).
    active_prev: u32,
    active_next: u32,
    // Doubly-linked reclaim list (over-cap hosts).
    reclaim_prev: u32,
    reclaim_next: u32,
    occupied: bool,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
enum FairnessKey {
    Addr(IpAddr),
    Prefix(u128, u8),
    FiveTuple { src: IpAddr, dst: IpAddr, sport: u16, dport: u16, proto: u8 },
}
```

**Why AHashMap, not FxHashMap**: The requirement explicitly includes
adversarial flows. FxHashMap uses a non-randomized multiplicative hash
that is vulnerable to collision attacks — an attacker controlling source
IPs can craft keys that all land in the same bucket, degrading O(1) to O(N).
AHashMap uses a per-instance randomly-seeded hash (hardware-accelerated AES
on x86, fallback to a fast randomized algorithm elsewhere). This makes
targeted collision attacks significantly harder, though not provably
impossible. For stronger guarantees, SipHash (`std::collections::HashMap`)
could be used at a modest performance cost. AHashMap is a reasonable
default for traffic keys where the threat is opportunistic, not
cryptographic.

### Host State Lifecycle

When the slab is full and a new host arrives:

1. If an idle host exists (no queued packets, `last_seen_ns` older than
   `host_idle_timeout_ns`): evict it, reuse the slab slot.
2. Otherwise: enqueue the packet into the **overflow bucket** instead of
   creating a new host entry. The overflow bucket is a bounded FIFO that
   gives excess keys degraded-but-nonzero service.

**Idle timeout**: Hosts with no queued packets and `last_seen_ns` older than
`host_idle_timeout_ns` (default 10s) are proactively cleaned up during the
scheduling cycle. This prevents dead hosts from consuming slab slots.

**Overflow bucket**: Each fairness-enabled class has a bounded overflow FIFO
(byte cap: `buffer_bytes / 8`, frame cap: `buffer_frames / 8`). Packets
from keys that can't get a host slot are enqueued here.

Overflow service contract:
- The scheduler reserves a **minimum overflow byte budget per scheduling
  cycle**: `overflow_budget = max(mtu, queue_cir_bytes_per_cycle * 0.05)`.
  This is 5% of the queue's per-cycle CIR service, with a floor of one MTU.
  The overflow budget is served after the DRR round completes but before
  moving to the next priority level.
- Overflow packets are subject to the same queue byte/frame caps as
  regular traffic. They can be reclaimed under UMEM pressure (lowest
  priority for reclaim, after over-cap hosts).
- Under extreme load where DRR active hosts consume the entire queue budget,
  the 5% overflow reservation is deducted from the DRR round, not added on
  top. This means DRR hosts collectively lose 5% to guarantee overflow
  service — a small cost for preventing overflow starvation.
- Overflow byte cap: `buffer_bytes / 8`. Overflow frame cap: `buffer_frames / 8`.
  Packets exceeding these are dropped with `overflow_drops` stat.

This ensures:
- Memory stays bounded (`max_host_slots` is a hard cap)
- Churn attacks cannot create unbounded hash/slab growth
- Rare/cold hosts still make progress, with less individualized fairness

**Why not drop on slab-full**: Dropping traffic solely because the host
table is full punishes new arrivals unfairly. The overflow bucket degrades
fairness granularity but preserves forwarding. A host that appears
frequently enough will eventually get a slab slot when an idle host is
evicted.

**CPU cost note**: Host churn (repeated slab eviction + reinsertion) is
more expensive than steady-state DRR. Each eviction involves: drop all
host's queued packets → recycle UMEM frames → free slab slot → AHashMap
remove. Each new host: AHashMap insert → slab allocate. Under sustained
adversarial churn (e.g., spoofed source IPs), the overflow bucket absorbs
the churn without per-key slab allocation. The benchmark plan includes a
dedicated host-churn test (benchmark #18) to validate that throughput
remains acceptable under adversarial churn rates.

## Per-Interface Memory Budget

With fairness-key ownership, host state scales with
`fairness_queues × total_active_keys` (not multiplied by worker count).
Each fairness key exists on exactly one worker.

**Per-host slot size** (approximate): 96-128 bytes (key, counters, linked-list
pointers, VecDeque header — excluding queued packet buffers).

| Active keys | Fairness queues | Total slots | Slot memory |
|-------------|----------------|-------------|-------------|
| 1,000       | 2              | 2,000       | ~256 KB     |
| 10,000      | 2              | 20,000      | ~2.5 MB     |
| 100,000     | 2              | 200,000     | ~25 MB      |

Plus per-worker: remote ingress/egress rings ≈ 64 KB per peer per class.
With 32 workers and 2 fairness classes: 32 × 2 × 64 KB = ~4 MB per worker.

Plus hierarchical token pools: ~17 × 128 bytes per level per interface.

**Recommendation**: Enable host fairness on **at most 2 queues** (typically
`best-effort` and one bulk/custom queue). Do not enable on all 8 queues.
The `max_host_slots` limit is per-queue across the entire interface (not
per worker), so 4096 slots means 4096 unique fairness keys globally.

The coordinator validates at config time:

```
total_host_memory = fairness_queues * max_host_slots * ~128
total_ring_memory = num_workers * (num_workers - 1) * fairness_queues * ring_size
```

If the sum exceeds a configurable per-interface memory budget (default:
64 MB), the commit is rejected with a warning.

## Buffer Management and UMEM Pressure

### Dual Accounting: Scheduling Bytes vs UMEM Frames

Queue depth is tracked in **two independent dimensions**:

- **Scheduling fairness** uses payload bytes (`total_bytes`, `queued_bytes`
  per host). This controls admission caps, DRR deficits, and service
  proportionality.
- **Memory safety** uses UMEM frame count (`total_frames`, `queued_frames`
  per host). This controls actual memory consumption.

Both limits are **always enforced**, including in the fairness-enabled
enqueue path. A small-packet adversary sending 64-byte packets consumes
the same UMEM memory per packet as a 1500-byte sender (one frame each),
even though the byte accounting is 23× lower. Without dual enforcement,
an attacker can stay within `buffer_bytes` while exhausting UMEM frames.

Per-host byte cap (when fairness enabled) is the primary admission control
mechanism for scheduling fairness. The frame cap is the primary guard for
memory safety. See "Admission Control" section above.

### UMEM Budget Enforcement

The coordinator computes `umem_budget_frames` per worker at config time:

```
total_umem_frames = binding.umem.frame_count
cos_budget = total_umem_frames / 2
```

At runtime, `total_queued_frames` is maintained incrementally. When it hits
the budget, `reclaim_from_overcap_host()` uses the over-cap reclaim list
for O(1) candidate selection:

```rust
fn reclaim_from_overcap_host(
    cos: &mut CosState,
    config: &CosInterfaceConfig,
    skip_queue: u8,
) -> bool {
    // 1. Try lowest-priority fairness-enabled queue with over-cap hosts
    for priority in (0..=5u8).rev() {
        for qi in 0..8 {
            if qi as u8 == skip_queue { continue; }
            let sched = &config.queues[qi];
            if !sched.active || sched.priority != priority { continue; }
            let queue = &mut cos.queues[qi];

            if let Some(ref mut hosts) = queue.hosts {
                // O(1): pop from over-cap reclaim list
                if hosts.reclaim_from_overcap_list(queue) {
                    cos.total_queued_frames -= 1;
                    queue.stats.dropped_overcap_reclaim += 1;
                    return true;
                }
            }
        }
    }

    // 2. No over-cap hosts — fall back to oldest packet from
    //    lowest-priority non-empty queue
    for priority in (0..=5u8).rev() {
        for qi in 0..8 {
            if qi as u8 == skip_queue { continue; }
            let sched = &config.queues[qi];
            if !sched.active || sched.priority != priority { continue; }
            let queue = &mut cos.queues[qi];
            if queue.is_empty() { continue; }

            if let Some(ref mut hosts) = queue.hosts {
                if let Some(frame) = hosts.dequeue_any_oldest() {
                    recycle_frame_and_update(cos, queue, frame);
                    return true;
                }
            } else if let Some(frame) = queue.fifo.pop_front() {
                recycle_frame_and_update(cos, queue, frame);
                return true;
            }
        }
    }
    false
}
```

**Why over-cap first**: The over-cap reclaim list gives O(1) access to hosts
that are consuming more than their fair share. Reclaiming from them first
aligns UMEM pressure response with fairness — elephants lose frames before
mice.

## Failure Modes

### Queue Overflow

When a queue's byte limit is reached:
- With host fairness: over-cap-first reclaim (or deepest-host fallback)
  makes room for the incoming packet.
- Without host fairness: plain tail-drop.

### UMEM Exhaustion

Heaviest-host reclamation from the lowest-priority queue. If no reclaimable
frames exist, the incoming packet is dropped.

### TX Ring Backpressure

Frames that couldn't be submitted are returned to the front of their
respective class queues and host subqueues (using `queue_id` and
`fairness_key` stored in `QueuedFrame`). If the TX ring stays full across
multiple cycles, the queue byte limits eventually trigger admission control.

### Config Change with Queued Backlog

On config change:
1. Drain queued frames with a **bounded timeout** (default 100ms).
2. After timeout: drop remaining frames, recycle UMEM.
3. Re-initialize CosState with new config.
4. Reset shared token pools.

The timeout prevents low-rate queues (e.g. 16 MB at 10 Mbps = 12.8s) from
blocking config application. Dropped frames are accounted in stats.

### Interface Down

All queued frames immediately recycled. No drain attempt.

### HA Role Change

On demotion: drain queued frames with a **bounded timeout** (default 200ms,
bounded by VRRP masterDown interval). After timeout: drop remaining.
On activation: CosState freshly initialized, shared token pools reset to
burst capacity.

## Configuration Syntax

### Forwarding Classes

```
set class-of-service forwarding-classes queue 0 best-effort
set class-of-service forwarding-classes queue 1 expedited-forwarding
set class-of-service forwarding-classes queue 2 assured-forwarding
set class-of-service forwarding-classes queue 3 network-control
```

### Schedulers

```
set class-of-service schedulers ef-sched transmit-rate 3g
set class-of-service schedulers ef-sched priority strict-high
set class-of-service schedulers ef-sched buffer-size 4m

set class-of-service schedulers af-sched transmit-rate 4g
set class-of-service schedulers af-sched transmit-rate exact
set class-of-service schedulers af-sched priority high
set class-of-service schedulers af-sched buffer-size 8m

set class-of-service schedulers be-sched transmit-rate 3g
set class-of-service schedulers be-sched priority low
set class-of-service schedulers be-sched buffer-size 16m
set class-of-service schedulers be-sched host-fairness source-address
set class-of-service schedulers be-sched host-fairness elephant-threshold 4
set class-of-service schedulers be-sched host-fairness target-round-us 250
set class-of-service schedulers be-sched host-fairness max-hosts 4096
```

### Scheduler Maps

```
set class-of-service scheduler-maps my-map forwarding-class best-effort scheduler be-sched
set class-of-service scheduler-maps my-map forwarding-class expedited-forwarding scheduler ef-sched
set class-of-service scheduler-maps my-map forwarding-class assured-forwarding scheduler af-sched
```

### Interface Binding

```
set class-of-service interfaces ge-0-0-1 unit 0 shaping-rate 10g
set class-of-service interfaces ge-0-0-1 unit 0 shaping-rate burst-size 125m
set class-of-service interfaces ge-0-0-1 unit 0 scheduler-map my-map
```

### Traffic Control Profiles

```
set class-of-service traffic-control-profiles wan-shape shaping-rate 1g
set class-of-service traffic-control-profiles wan-shape burst-size 15m
set class-of-service interfaces ge-0-0-1 output-traffic-control-profile wan-shape
```

### Classification (Firewall Filter)

```
set firewall family inet filter classify term voip from dscp ef
set firewall family inet filter classify term voip then forwarding-class expedited-forwarding
set firewall family inet filter classify term voip then accept

set firewall family inet filter classify term default then forwarding-class best-effort
set firewall family inet filter classify term default then accept

set interfaces ge-0-0-1 unit 0 family inet filter output classify
```

## Validation Constraints

Enforced at config commit:

- `sum(scheduler.cir) <= interface.shaping_rate` — no over-subscription.
- `scheduler.cir <= interface.shaping_rate` — no single queue exceeds aggregate.
- `scheduler.pir >= scheduler.cir` (when PIR is configured) — ceiling ≥ guarantee.
- `sum(scheduler.buffer_bytes) <= worker_umem_budget * frame_size` — buffer
  fits in UMEM budget.
- `scheduler-map` references only defined forwarding classes and schedulers.
- `shaping-rate` is required when `scheduler-map` is applied.
- Host DRR should not be enabled on `strict-high` priority queues (warning).
- `buffer_bytes > cir_rate * max_queue_delay` emits a warning. Default
  `max_queue_delay = 100ms`. This prevents operators from configuring
  buffers that imply unacceptable queueing delay at the configured CIR
  (e.g., 16 MB at 10 Mbps = 12.8s drain time).

## Observability

### CLI

```
show class-of-service interface ge-0-0-1
  Shaping rate: 10 Gbps (burst 125 MB)
  Scheduler map: my-map

  Queue  Name           Priority     CIR      Exact  Queued    TX        Drops
  0      best-effort    low          3 Gbps   no     48 KB     845K      320
  1      expedited-fwd  strict-high  3 Gbps   no     0 B       1.2M      0
  2      assured-fwd    high         4 Gbps   yes    12 KB     350K      45
  3      network-ctrl   strict-high  100 Mbps no     0 B       12K       0

  CIR served:  2.1M pkts (3.15 GB)    PIR served: 450K pkts (675 MB)
  Aggregate starvation events: 12
  UMEM pressure reclaims: 0

show class-of-service interface ge-0-0-1 queue 0 detail
  Buffer: 48 KB / 16 MB max (0.3%)
  Frames: 32 / 10922 max
  Sojourn time: avg 1.2ms, p99 4.8ms, max 12ms
  CIR served:  800K pkts    PIR served: 120K pkts
  Tail drops: 0     Host-cap drops: 280    Heaviest-host drops: 40
  Active hosts: 47 / 4096 max
  Dynamic quantum: 3.1 KB (target round: 250µs)

show class-of-service interface ge-0-0-1 queue 0 hosts
  Fairness  Rate      Deficit  Elephant  Queued  TX
  10.0.1.5  450 Mbps  -12KB    YES       4.0 MB  420K
  10.0.2.1  2.1 Mbps  9.8KB    no        1.5 KB  24K
  10.0.2.2  0.8 Mbps  9.9KB    no        1.5 KB  12K
```

### Prometheus

```
bpfrx_cos_queue_tx_packets_total{iface,queue,name}
bpfrx_cos_queue_tx_bytes_total{iface,queue,name}
bpfrx_cos_queue_drops_tail_total{iface,queue,name}
bpfrx_cos_queue_drops_host_cap_total{iface,queue,name}
bpfrx_cos_queue_drops_heaviest_total{iface,queue,name}
bpfrx_cos_queue_drops_admission_total{iface,queue,name}
bpfrx_cos_queue_depth_bytes{iface,queue,name}
bpfrx_cos_queue_depth_frames{iface,queue,name}
bpfrx_cos_queue_cir_served_bytes{iface,queue,name}
bpfrx_cos_queue_pir_served_bytes{iface,queue,name}
bpfrx_cos_queue_sojourn_avg_ns{iface,queue,name}
bpfrx_cos_queue_sojourn_p99_ns{iface,queue,name}
bpfrx_cos_aggregate_starvation_total{iface}
bpfrx_cos_aggregate_tokens{iface}
bpfrx_cos_umem_pressure_reclaims{iface}
bpfrx_cos_umem_pressure_drops{iface}
bpfrx_cos_active_hosts{iface,queue}
bpfrx_cos_elephant_hosts{iface,queue}
bpfrx_cos_overcap_hosts{iface,queue}
bpfrx_cos_host_evictions{iface,queue}
bpfrx_cos_overflow_admissions{iface,queue}
bpfrx_cos_overflow_drops{iface,queue}
bpfrx_cos_token_lease_returns{iface}
bpfrx_cos_token_lease_age_expirations{iface}
bpfrx_cos_max_observed_host_round_us{iface,queue}
```

## Implementation Plan

### Phase 1: Queue Buffers + Aggregate Shaping (Local Classes Only)

- `CosInterfaceConfig`, `CosState`, `ClassQueue` structures
- `GlobalTokenPools` with aggregate-only (no per-queue CIR/PIR yet)
- `enqueue_frame()` with byte+frame limits (dual accounting)
- `drain_shaped_tx()` → direct TX ring submission
- All packets on shaped interfaces go through CoS (including locally generated)
- Wire `forwarding-class` from `FilterResult` into queue selection
- Flow cache `queue_id` caching with epoch invalidation
- Dynamic lease size for `LocalBatchCache`
- Lease return on idle / quiesce / config change
- Tests: single queue, aggregate rate cap, UMEM budget, drain timeout

### Phase 2: Per-Queue CIR/PIR + Two-Phase Scheduling

- Shared per-queue CIR and PIR token pools (cache-line-aligned)
- Phase 1 with CIR quantum round-robin + Phase 2 with DWRR deficit carry
- `transmit-rate exact` enforcement
- Tests: multi-queue guarantee, priority preemption, borrowing, exact mode,
  queue-index fairness (all 8 queues backlogged)

### Phase 3: Fairness-Key Ownership + Remote Enqueue

- Owner selection via `jump_consistent_hash(iface, class, key)`
- SPSC cross-worker ingress rings for remote enqueue
- Packet copy path (arrival UMEM → ring → owner UMEM)
- Owner drains ingress rings bounded per cycle
- Backpressure: admission drop at sender when ring full
- Epoch-based owner invalidation on worker set change
- Tests: remote enqueue latency, ring saturation, owner remap

### Phase 4: Per-Host Fair Queuing (Dequeue Fairness on Owner)

- `HostDrr` with AHashMap + per-host owned VecDeques (on owner only)
- `FairnessKey` type (`source-address` mode first)
- Dynamic quantum (target 250µs round / active hosts)
- Elephant detection (EWMA, reduced quantum)
- Bounded host table with `max_host_slots` (global, not per-worker)
- Overflow bucket for excess fairness keys
- Host idle timeout + LRU eviction
- Tests: DRR fairness, elephant detection, slab exhaustion, overflow service

### Phase 5: Admission Control (Enqueue Fairness on Owner)

- Two-tier per-host caps (soft cap + hard cap) — global by construction
- Over-cap reclaim list (O(1) reclaim candidate on queue-full)
- Fairness-aware UMEM reclamation
- Per-host admission policy (rules 1-5)
- Tests: 1e/100m, 100e/1m, 1 elephant across 32 workers, flow splitting,
  mixed MTU, queue-full-then-mice, host churn, over-cap reclaim

### Phase 6: Hierarchical Token Leasing

- `SocketLeasePool` per NUMA node
- Workers lease from socket pool, socket leases from global
- Total lease credit bounds
- Cache-line-padded `AlignedTokenPool` structs
- Tests: same-class 16/32-worker contention, cross-socket NUMA, lease
  credit bounds

### Phase 7: Classification + Observability

- DSCP-based BA classifier (64-entry table)
- Egress DSCP rewrite rules
- Traffic control profiles
- `show class-of-service interface` CLI
- Queue detail + host detail + remote enqueue stats
- Prometheus metrics (per-queue, per-host, aggregate, reclaim, overflow,
  remote enqueue, lease returns)

### Phase 8: Advanced (Future)

- RED/WRED drop profiles
- Additional fairness modes (`destination-address`, `source-prefix`, `5-tuple`)
- Per-subscriber fairness
- Shared UMEM pool for zero-copy remote enqueue
- Dynamic buffer pool sharing across queues

## Benchmark Plan

Performance claims must be validated on target hardware before quoting
specific costs. The following benchmarks define what "fast enough" means:

**Throughput and rate accuracy:**

1. Single worker, single queue, line rate: <1% error at 10 Gbps.
2. Multi-worker, skewed RSS: full class guarantee on one worker.
3. Low-rate accuracy: <5% error at 10/50/100 Mbps over 10s windows.

**Scheduling correctness:**

4. Multi-queue priority: EF gets CIR + surplus, BE gets CIR under contention.
5. DWRR fairness: two queues same priority, 2:1 CIR. Surplus split ≈ 2:1.
6. `exact` plus priority: exact queue never exceeds CIR.
7. Queue-index fairness: all 8 queues backlogged at CIR, rotating start
   prevents any queue from being cycle-starved.

**Adversarial / fairness:**

8. 1 elephant vs 100 mice: mice retain admission and low drop rate.
9. 100 elephants vs 1 mouse: mouse retains admission; near-zero drop.
10. Flow splitting: 1000 connections vs 1 connection, equal dequeue share.
11. Protocol mix: TCP/UDP/ESP/GRE/ICMP competing, byte-fair allocation.
12. Mixed MTU: 64B vs 1500B, byte-fair (not packet-fair).
13. Queue full of elephant, then mice arrive: mice admit at >0 rate
    (over-cap reclaim + headroom makes room).

**Admission control:**

14. Per-host cap enforcement: single host cannot exceed cap even at line rate.
15. UMEM pressure reclaim: targets heaviest host, not mice.
16. Host churn at slab capacity: bounded memory, defined eviction.

**Scaling:**

17. 10,000 active hosts, 1 Gbps queue: worst-case inter-service bounded
    by quantum floor × host count / rate.
18. Host DRR with 50% churn, 1-hour run: no memory growth, no drift.
19. Dynamic batch size: low-rate shaping smooth at 10 Mbps.

**Infrastructure:**

20. Saturated TX ring: no priority inversion during backpressure.
21. Config reload with backlog: drain timeout + no UMEM leak.
22. HA failover with shaped queues: drain before demotion completes.
23. Worker skew with competing classes: both get full CIR.
24. Idle-worker token return: no long-lived stranded budget (100µs reclaim).
25. Locally generated packets on shaped interface: go through CoS.
26. Over-cap reclaim list correctness: O(1) reclaim, correct unlink on dequeue.
27. Overflow bucket service: excess hosts make progress, bounded memory.
28. Soft/hard cap transitions: hosts correctly linked/unlinked from reclaim list
    as queued bytes cross thresholds.
29. Phase 1 CIR quantum fairness: 8 backlogged queues, each gets bounded
    service per cycle regardless of queue index.
30. Many-elephants equilibrium then mouse: queue full, no host over soft cap,
    mouse arrives — verify mouse admits via headroom + deepest-host fallback.
31. Small-packet adversary: 64B packets in fairness queue — verify frame cap
    prevents UMEM exhaustion even within byte cap.
32. Low-rate lease correctness: 10/50/100 Mbps queues with MTU packets —
    verify lease floor is workable and rate is accurate.
33. Overflow fairness: more hosts than max_host_slots under sustained load —
    verify overflow gets nonzero service, not starvation.
34. Worst-case latency under configured target_host_round: measured
    inter-service delay matches design math within 2×.
35. New-host admission under full queue: repeated first-packet arrivals from
    new hosts — verify headroom allows admission.

**Many-core and ownership:**

36. One elephant across 16/32 workers: 1 host with 1000 flows hashing to
    different RX workers. Verify all packets route to one owner, elephant
    gets one fairness share (not one per worker).
37. 100 elephants vs 100 mice across 16/32 workers: verify fairness is
    key-based, not worker-based. Each host gets one share regardless of
    which workers receive its traffic.
38. Same-class hot on 16/32 workers: all workers pushing same class at line
    rate. Verify socket-level lease pools reduce global atomic contention.
39. Cross-socket NUMA: workers on socket 0 and socket 1. Verify
    hierarchical leasing reduces cross-socket cache-line traffic.
40. Remote ingress ring saturation: owner's ring is full. Verify bounded
    drops at sender side, no deadlock, no data corruption.
41. Hot elephant on one owner: one host becomes owner-hotspot-bound. Verify
    it does not exceed its configured share even under CPU pressure.
42. Total leased credit: 32 workers each holding maximum lease. Verify
    total outstanding stays within bound.
43. Host-state memory at scale: 2 fairness queues × 4096 global slots.
    Verify ownership eliminates worker-count memory multiplication.
44. Owner remap on worker add/remove: verify jump-hash moves ~1/N keys,
    queued packets for remapped keys are drained or safely discarded.
