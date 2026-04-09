# Class of Service — Hierarchical Egress Traffic Shaping

Userspace-only implementation in the Rust AF_XDP forwarding plane.

## Scope and Non-Goals

**This is:**
- Userspace-only (Rust AF_XDP workers)
- Egress-only (shapes outbound traffic per interface)
- A hierarchical shaper: `interface -> class -> optional fairness leaf`
- Protocol-oblivious at the scheduling layer
- Designed to scale across many workers/cores without bypassing shaping
- Average-rate shaping with bounded burst release, not wire-level pacing

**This is not:**
- A replacement for ingress policers
- Perfect packet pacing
- A full Junos CoS implementation
- A cure for single-worker CPU saturation under pathological RSS skew

## Problem Statement

The current flat policer drops excess traffic on arrival. It provides:

- no egress queueing
- no work-conserving surplus sharing
- no protection for low-rate flows against elephants
- no robust behavior under uneven RSS placement

What we need instead is a real egress shaper that:

- buffers packets
- transmits under hierarchical budgets
- remains protocol oblivious
- preserves fairness under adversarial flow patterns
- scales across many workers without introducing a shaping bypass

The motivating cases are:

- one elephant versus one hundred mice
- one hundred elephants versus one mouse
- one hundred elephants versus one hundred mice
- all of the above with uneven hashing across workers

## Design Goals

1. **Hierarchical**: every transmitted byte is accounted against:
   - interface aggregate budget
   - class budget
   - optional fairness leaf state

2. **Work-conserving**: idle classes do not waste interface bandwidth.

3. **Protocol-oblivious**: scheduling decisions depend on queue assignment,
   fairness key, packet size, and queue state; not on TCP/UDP/ESP/GRE/ICMP
   semantics.

4. **No fast-path bypass**: every packet that egresses a shaped interface
   follows the same logical path:
   `classify -> enqueue -> admit -> schedule -> transmit`

5. **Adversarial resilience**: fairness must hold even when a sender opens
   many flows or lands traffic unevenly across workers.

6. **Many-core support**: class guarantees must remain correct across workers,
   and fairness behavior must not silently multiply with worker count.

7. **Low CPU cost**: the hot path must stay O(1) expected per packet with
   bounded constant factors and bounded shared-memory contention.

## Hierarchical Service Model

The shaper is a tree:

```
Interface root
  -> forwarding class
    -> optional fairness leaf
```

### Root Node

The root node represents the shaped interface.

Responsibilities:

- enforce interface shaping-rate and burst
- cap aggregate transmitted bytes
- track total queued bytes and frames
- enforce interface-level UMEM budget

### Class Node

A class node represents a forwarding class / queue.

Responsibilities:

- guarantee service up to CIR
- receive surplus service under PIR / ceiling rules
- define surplus priority
- define class buffer budget
- optionally enable fairness leaves

### Leaf Node

A leaf node is:

- a fairness bucket when fairness is enabled, or
- the implicit FIFO leaf when fairness is disabled

Leaf responsibilities:

- hold queued packets
- enforce per-leaf admission caps
- participate in per-class dequeue fairness
- provide reclaim candidates under overload

### Invariants

These invariants define the design:

1. Every packet on a shaped interface follows one logical path:
   `classify -> enqueue -> admit -> schedule -> transmit`

2. `CIR` is not a fast path or a separate queue. It is only the guaranteed
   service budget of a class node inside the same scheduler.

3. A packet may transmit only if:
   - the root has budget
   - the selected class has budget for the active phase
   - the selected leaf has a dequeuable packet

4. Multi-core scaling may shard the hierarchy, but it may not bypass it.

5. Session hits, generated traffic, and cross-binding forwards do not bypass
   shaping on a shaped interface.

## Service Semantics

### Guaranteed

- A backlogged class receives service up to its configured `transmit-rate`
  over windows larger than one scheduling cycle plus burst horizon.
- Class guarantees hold regardless of RSS placement because class budgets are
  shared across workers.

### Opportunistic

- Surplus bandwidth above active class CIR is distributed by class priority
  and same-priority DWRR.
- `transmit-rate exact` classes never receive surplus.

### Can Be Starved

- Surplus service for a lower-priority class can be zero if higher-priority
  classes consume all available surplus.
- Fairness leaves can be dropped under finite-buffer overload; the goal is
  not literal zero drop under infinite overload, but robust protection of
  under-cap leaves against dominant senders.

## Unified Packet Path

Every packet that egresses a shaped interface follows:

```
RX
  -> parse / route / session / NAT
  -> classify to forwarding class
  -> derive fairness key if class uses fairness
  -> place packet into the correct scheduler shard
  -> class/leaf admission control
  -> class/leaf scheduling
  -> TX ring submission
```

This applies to:

- forwarded packets on session hit
- forwarded packets on session miss
- locally generated packets on a shaped interface
- cross-binding forwards targeting a shaped interface

Caching may avoid repeated classification work, but it may not bypass queue
admission or scheduling.

## Scheduler

There is one scheduler with two service phases.

### Phase 1: Guarantee Service

Purpose:

- satisfy class CIR guarantees
- ensure every backlogged class with available CIR makes forward progress

Rules:

1. Walk active classes in rotating round-robin order.
2. Give each class a bounded `cir_quantum` per visit.
3. Inside the selected class:
   - FIFO classes dequeue FIFO
   - fairness-enabled classes dequeue from their leaf DRR
4. Charge:
   - root aggregate budget
   - class CIR budget

Recommended per-visit quantum:

```
cir_quantum_bytes = clamp(
    class_cir_bytes_per_us * 100,
    mtu_bytes,
    32 * 1024
)
```

This keeps:

- low-rate classes from being permanently postponed
- high-rate classes from consuming the entire cycle
- queue-index order from biasing service

### Phase 2: Surplus Service

Purpose:

- distribute bandwidth above active CIR

Rules:

1. Scan classes by priority.
2. The first priority level with eligible surplus demand wins the cycle's
   surplus service.
3. Within that level, use DWRR across classes.
4. Inside the selected class:
   - FIFO classes dequeue FIFO
   - fairness-enabled classes dequeue from their leaf DRR
5. Charge:
   - root aggregate budget
   - class PIR budget

Strict priority applies only to surplus service.

### Same-Priority DWRR Across Classes

Each class at a priority level has a persistent `surplus_deficit`.

Per DWRR round:

```
for each active class at this priority:
  class.surplus_deficit += class.weight * round_quantum
  while class.surplus_deficit >= next_pkt_len and budget remains:
    dequeue packet from class leaf
    class.surplus_deficit -= pkt_len
    charge root + class PIR
```

This provides stable same-priority surplus sharing without queue-order bias.

## Leaf Scheduling

Within a fairness-enabled class, leaves are served with DRR.

### Fairness Modes

Supported policy modes:

- `source-address`
- `destination-address`
- `source-prefix`
- `5-tuple`
- disabled

The scheduler remains protocol oblivious because fairness depends only on the
configured key and packet size, not protocol behavior.

### Dynamic Leaf Quantum

Leaf DRR quantum should adapt to:

- class rate
- active leaf count
- latency target

Recommended formula:

```
leaf_quantum_bytes = clamp(
    class_rate_bytes_per_us * target_leaf_round_us / max(active_leaves, 1),
    2 * mtu_bytes,
    32 * 1024
)
```

Reasonable defaults:

- `target_leaf_round_us = 250`
- `min_quantum = 2 * MTU`
- `max_quantum = 32 KB`

### Queue Policy by Class

Recommended policy split:

- `network-control`, `expedited-forwarding`:
  local FIFO, small buffers, no leaf DRR

- `assured-forwarding`:
  FIFO by default, fairness optional

- `best-effort`, `bulk-data`:
  fairness enabled by default

This is deliberate:

- FIFO high-priority classes optimize latency
- fairness-enabled low-priority classes optimize starvation resistance

## Admission Control

Admission control belongs inside the hierarchy.

### Class-Level Admission

Each class enforces:

- byte limit
- frame limit
- incumbents budget
- reserved headroom

Headroom prevents incumbents from completely occupying the class buffer and
blocking all new arrivals.

### Leaf-Level Admission

Each fairness leaf enforces:

- soft cap
- hard cap
- reclaim eligibility

Recommended caps:

```
soft_cap_bytes = clamp(
    class_buffer_bytes / max(active_leaves, 1),
    min_leaf_cap_bytes,
    max_leaf_cap_bytes
)
hard_cap_bytes = 2 * soft_cap_bytes
```

Use `cap_factor = 1`, not `2`. With `cap_factor = 2`, all incumbents can
fill the class while remaining under soft cap, leaving no reclaim candidate.

### Admission Headroom

Reserve a fraction of class buffer for new or under-cap leaves:

```
incumbents_cap_bytes = class_buffer_bytes * (1 - headroom_pct)
headroom_bytes       = class_buffer_bytes * headroom_pct
```

Recommended:

- `headroom_pct = 0.10`

### Admission Policy

For a fairness-enabled class:

1. If the incoming leaf is below soft cap and the class is below the
   incumbents budget:
   admit

2. If the incoming leaf exceeds hard cap:
   drop

3. If the class is above incumbents budget and the incoming leaf is already
   reclaimable:
   reclaim from that leaf

4. If the incoming leaf is under cap and the class is full:
   reclaim from another reclaimable leaf

5. If no reclaimable leaf exists:
   reclaim from the deepest leaf in the same class

6. If reclaim still fails:
   class tail-drop

This keeps the fairness decision inside the class. Leaves compete within the
class; classes compete only through the root/class scheduler.

### Reclaim Structures

Maintain:

- a reclaim list for over-cap leaves
- a deepest-leaf tracker as fallback

The reclaim list should be O(1) in the common case. The deepest-leaf fallback
may be O(1) optimistic with occasional repair scans.

### Finite-Buffer Realism

The goal is not “mice can never be dropped under infinite overload”.

The goal is:

- mice retain admission and low drop probability
- dominant leaves absorb reclaim pressure first
- fairness survives adversarial overload substantially better than plain
  class tail-drop

## Many-Core Scaling Without Breaking Hierarchy

The right multi-core model is **hierarchy sharding**, not a CIR fast path.

### Scheduler Shards

Each shaped interface is implemented as a set of scheduler shards.

Each shard owns:

- shard-local class queues
- shard-local leaf queues
- shard-local DRR state
- shard-local scheduler cursors
- shard-local leased budgets

Shared parent budgets remain authoritative:

- interface aggregate budget
- class CIR budgets
- class PIR budgets

So the service hierarchy is:

```
shared root/class budgets
  -> shard-local class/leaf state
```

### Why This Preserves Hierarchy

Shards do not own independent rates. They only hold temporary leases from
shared parent budgets. Packets still flow through:

- class node
- leaf node
- root/class accounting

### Shard Placement

For fairness-enabled traffic, place packets into shards by:

```
shard = hash(interface_id, class_id, fairness_key)
```

This is hierarchy sharding, not a separate fast path. The packet still enters
the same class and leaf semantics; it is simply routed to the shard that owns
that portion of the queue tree.

For FIFO-only latency-sensitive classes, packets may remain on the local shard
if that preserves the same class/root accounting and avoids unnecessary
cross-shard movement.

### Cross-Shard Enqueue

If a packet arrives on a worker that is not the correct shard for its
fairness-enabled class:

- the packet is internally forwarded to the correct shard before enqueue
- admission control happens on that shard
- scheduling happens on that shard

This is not a shaping bypass. It is only internal placement before the packet
enters the same hierarchical queueing logic.

### What This Solves

This prevents the many-core fairness multiplication problem:

- one fairness key maps to one shard
- therefore one fairness key has one leaf state
- therefore one sender does not get one DRR share per worker

That is essential for:

- one elephant vs one hundred mice
- one hundred elephants vs one mouse
- many-flow adversaries under RSS skew

### What This Does Not Solve

If one fairness key is extremely hot, the shard that owns it can still become
CPU-bound. That is acceptable and expected:

- class correctness remains intact
- fairness remains intact
- but throughput may still be bounded by the hot shard's CPU

This is better than allowing one sender to multiply its share across all
workers.

## Shared Budget Leasing

Shared parent budgets should not be touched directly on every packet.

### Lease Hierarchy

Recommended implementation:

```
global token pool
  -> optional socket-local lease pool
    -> shard-local lease
```

This gives:

- global correctness
- reduced cross-core cache-line contention
- better NUMA behavior

### Lease Size

Shard-local lease size should be dynamic:

```
lease_bytes = clamp(
    rate_bytes_per_us * target_lease_us,
    mtu_bytes,
    min(burst_bytes / 8, max_lease_bytes)
)
```

Recommended defaults:

- `target_lease_us = 25`
- `min_lease_bytes = MTU`
- `max_lease_bytes = 64 KB` for aggregate
- `max_lease_bytes = 16 KB` for class pools

At very low rates, a shard may bypass local caching and charge directly
against the shared pool, because packet rate is low enough that per-packet
shared charging is acceptable.

### Lease Return

Unused local leases must be returned when:

- the class/leaf queue goes idle
- the shard goes quiescent
- lease age exceeds a threshold
- config reload or HA transition occurs

### Total Lease Bound

Total leased-but-unspent credit per shared bucket must be bounded:

```
max_total_leased = min(bucket_burst / 4, lease_per_shard * active_shards)
```

This prevents many shards from hoarding too much shared budget at once.

### Cache-Line Isolation

All shared buckets must be padded and isolated per cache line.

Requirements:

- one hot bucket per cache line
- no packed arrays of hot atomics
- timestamps isolated with their bucket if always touched together

Without this, many-core coherence traffic will dominate the hot path.

## Memory Model

Track queue occupancy in two dimensions:

- **payload bytes** for fairness and rate logic
- **UMEM frames** for actual memory safety

Both must be enforced in both FIFO and fairness-enabled classes.

This matters because:

- `64B` packets and `1500B` packets both consume one UMEM frame
- payload-byte fairness and UMEM consumption are not the same resource

## Failure Modes

### Queue Overflow

For fairness-enabled classes:

- reclaim from dominant or reclaimable leaves first
- fall back to class tail-drop only if necessary

For FIFO classes:

- class tail-drop

### UMEM Exhaustion

Under interface-level UMEM pressure:

1. reclaim from the lowest-priority fairness-enabled class
2. within that class, reclaim from reclaimable leaves first
3. then deepest-leaf fallback
4. then FIFO fallback

### TX Ring Backpressure

If TX ring submission is partial:

- return unsent packets to the front of the same shard/class/leaf
- preserve class and leaf ordering

### Config Reload

On config reload:

1. drain queued packets for a bounded timeout
2. drop remaining packets if timeout expires
3. recycle UMEM
4. reset shard-local state and shared leases

### HA Transition

On demotion:

1. bounded drain
2. drop remaining packets after timeout
3. recycle UMEM

On activation:

- initialize empty shard state
- reset shared lease state

## Configuration Model

The configuration remains Junos-inspired:

- forwarding classes
- schedulers
- scheduler maps
- interface shaping-rate
- optional classifier bindings

### Example

```
set class-of-service forwarding-classes queue 0 best-effort
set class-of-service forwarding-classes queue 1 expedited-forwarding
set class-of-service forwarding-classes queue 2 assured-forwarding
set class-of-service forwarding-classes queue 3 network-control

set class-of-service schedulers ef-sched transmit-rate 3g
set class-of-service schedulers ef-sched priority strict-high
set class-of-service schedulers ef-sched buffer-size 4m

set class-of-service schedulers be-sched transmit-rate 3g
set class-of-service schedulers be-sched priority low
set class-of-service schedulers be-sched buffer-size 16m
set class-of-service schedulers be-sched host-fairness source-address

set class-of-service scheduler-maps my-map forwarding-class best-effort scheduler be-sched
set class-of-service scheduler-maps my-map forwarding-class expedited-forwarding scheduler ef-sched

set class-of-service interfaces ge-0-0-1 unit 0 shaping-rate 10g
set class-of-service interfaces ge-0-0-1 unit 0 shaping-rate burst-size 125m
set class-of-service interfaces ge-0-0-1 unit 0 scheduler-map my-map
```

## Observability

Observability must reflect the hierarchy.

### CLI

Required views:

- interface/root state
- class state
- fairness leaf state for fairness-enabled classes
- shard state for many-core debugging

Examples:

```
show class-of-service interface ge-0-0-1
show class-of-service interface ge-0-0-1 queue 0 detail
show class-of-service interface ge-0-0-1 queue 0 leaves
show class-of-service interface ge-0-0-1 shards
```

### Metrics

At minimum:

- root aggregate tokens
- class CIR/PIR served bytes
- class queue depth bytes/frames
- leaf active count
- reclaim counts
- tail drops
- UMEM pressure drops/reclaims
- lease returns and lease expirations
- shard-local backlog and service

## Implementation Plan

### Phase 1: Root + FIFO Classes

- root aggregate shaping
- class FIFO queues
- direct scheduler ownership of TX ordering
- no bypass for generated packets on shaped interfaces

### Phase 2: Class CIR/PIR Scheduling

- phase 1 guarantee service
- phase 2 surplus service
- shared class/root budgets
- dynamic shard-local leases

### Phase 3: Fairness Leaves

- fairness key derivation
- leaf DRR
- soft/hard caps
- reclaim list and deepest-leaf fallback

### Phase 4: Hierarchy Sharding

- shard placement for fairness-enabled classes
- internal cross-shard enqueue
- shared parent budgets + leases
- cache-line isolation for shared pools

### Phase 5: Observability and Tuning

- shard metrics
- queue/leaf CLI
- lease tuning
- latency/fairness benchmark tuning

## Validation Plan

The design is only correct if all of these pass:

### Throughput and Accuracy

1. Single shard, single class, line-rate shaping
2. Low-rate shaping accuracy at `10/50/100 Mbps`
3. Same-class multi-shard contention on shared budgets

### Scheduling Correctness

4. Phase 1 queue-index fairness across all classes
5. Same-priority DWRR surplus split
6. `transmit-rate exact` never exceeds CIR

### Adversarial Fairness

7. One elephant vs one hundred mice
8. One hundred elephants vs one mouse
9. One hundred elephants vs one hundred mice
10. Flow splitting: one sender opens many connections

### Many-Core Behavior

11. One fairness key spread across many arrival workers still gets one leaf
12. Many fairness keys spread across many workers scale across shards
13. Shared-budget leasing does not collapse under many-core contention
14. No long-lived stranded lease credit

### Infrastructure

15. No-bypass validation for session hits and generated packets
16. TX ring backpressure preserves class/leaf ordering
17. Config reload and HA transition honor bounded drain behavior
18. UMEM pressure reclaim targets dominant leaves first

## Summary

The correct model is:

- a hierarchical shaper
- one unified packet path
- one scheduler with two phases
- no CIR fast path
- many-core support via hierarchy sharding plus shared parent leases

That keeps the design aligned with the actual goals:

- protocol oblivious
- adversarially robust
- many-core capable
- no shaping bypass
