# Class of Service — Hierarchical Egress Traffic Shaping

Userspace-only implementation in the Rust AF_XDP forwarding plane.

## Scope and Non-Goals

**This is:**
- userspace-only
- egress-only
- a hierarchical shaper with the service tree `root(interface) -> reservation -> container`
- protocol oblivious at the scheduling layer
- work-conserving across reservations
- designed to support many cores without introducing a shaping bypass
- average-rate shaping with bounded bursts, not wire-level pacing

**This is not:**
- an ingress policer
- perfect packet pacing
- a full Junos CoS implementation
- per-flow fair queueing in the first pass
- a cure for a single hot reservation saturating the CPU of its owning scheduler

## Problem Statement

The current flat policer drops excess traffic on arrival. It does not provide:

- egress queueing
- work-conserving surplus sharing
- class-level isolation under overload
- robust behavior when traffic lands unevenly across workers

What we need instead is a real egress shaper that:

- buffers packets
- transmits under hierarchical budgets
- remains protocol oblivious
- shares unused bandwidth across configured classes through their reservations
- scales across many cores without multiplying guarantees by worker count

The motivating cases remain:

- one elephant versus one hundred mice
- one hundred elephants versus one mouse
- one hundred elephants versus one hundred mice
- all of the above with uneven hashing across workers

Important first-pass constraint:

- the first implementation should use a single FIFO queue per container
- weighted scheduling happens among reservations
- it does **not** attempt micro-flow fairness inside a container

That means the first pass protects configured classes from each other much
better than it protects individual flows that share the same container.

## Design Goals

1. **Hierarchical**: every transmitted byte is accounted against:
   - the interface root
   - one reservation node
   - one container node

2. **Work-conserving**: idle reservations do not waste interface bandwidth.

3. **Protocol-oblivious**: scheduling decisions depend on queue assignment,
   packet size, and queue state, not on TCP/UDP/ESP/GRE/ICMP semantics.

4. **No fast-path bypass**: every packet that egresses a shaped interface
   follows the same logical path:
   `classify -> enqueue -> admit -> schedule -> transmit`

5. **Adversarial resilience at class granularity**: elephants in one configured
   class should not destroy latency and throughput for other classes.

6. **Many-core support**: guarantees must remain correct across workers, and
   the behavior of a reservation must not silently multiply with worker count.

7. **Low CPU cost**: the hot path should remain O(1) expected per packet with
   bounded contention on shared state.

8. **Incremental complexity**: the baseline design should be implementable
   without per-flow fair queueing. Finer-grained fairness can be a later
   extension if class-level FIFO proves insufficient.

## Hierarchical Service Model

The service tree is:

```text
Interface root
  -> reservation
    -> container
```

### Root Node

The root node represents the shaped interface.

Responsibilities:

- enforce the interface shaping-rate and burst
- cap aggregate transmitted bytes
- track total queued bytes and frames
- enforce interface-level UMEM budget

### Reservation Node

A reservation node is the intermediate scheduling object.

Conceptually, this is where the service guarantee lives.

Responsibilities:

- own the class reservation (`transmit-rate`, optional ceiling, priority, weight)
- participate in the scheduler's guarantee and surplus phases
- own reservation-level buffer limits and admission policy
- define how much service the attached containers may consume

In a Junos-like model, this is closest to the scheduler attached to a
forwarding class on a shaped interface.

### Container Node

A container node is the leaf queue that actually holds packets.

First-pass responsibilities:

- hold queued packets
- preserve FIFO ordering
- enforce container byte/frame limits
- provide the packet dequeued when its reservation is selected

In the first pass, a container is intentionally simple:

- one FIFO queue
- no per-flow buckets
- no micro-flow DRR
- no flow-key-based fairness accounting

In the first pass, each reservation has exactly one container:

```text
containers_per_reservation = 1
```

So the `reservation -> container` split is structural and future-proofing, not
an immediate claim that one reservation already contains multiple independently
scheduled queues.

### Invariants

These invariants define the design:

1. Every packet on a shaped interface follows one logical path:
   `classify -> map to reservation/container -> enqueue -> admit -> schedule -> transmit`

2. `CIR` is not a fast path or a separate queue. It is only the guaranteed
   service budget of a reservation node inside the same scheduler.

3. A packet may transmit only if:
   - the root has budget
   - the selected reservation has budget for the active phase
   - the selected container has a dequeuable packet

4. A container belongs to exactly one scheduler owner at a time.

5. Session hits, generated traffic, and cross-binding forwards do not bypass
   shaping on a shaped interface.

6. In the first pass, fairness stops at the container boundary. Packets within
   one container are FIFO, not micro-flow scheduled.

## Service Semantics

### Guaranteed Service

- A backlogged reservation receives service up to its configured
  `transmit-rate` over windows larger than one scheduling cycle plus burst
  horizon.
- Reservation guarantees hold regardless of RSS placement because the
  reservation budget is shared and authoritative.

### Opportunistic Service

- Surplus bandwidth above active reservation guarantees is distributed by
  reservation priority and same-priority weighted DWRR.
- `transmit-rate exact` reservations never receive surplus.

### First-Pass Fairness Boundary

This design is intentionally honest about what it does and does not solve.

It does help with:

- one elephant in `best-effort` versus mice in `expedited-forwarding`
- multiple busy low-priority classes contending for surplus
- uneven worker placement that would otherwise multiply class behavior

It does **not** fully solve:

- one elephant versus one hundred mice if they all land in the **same**
  container
- one sender opening many micro-flows inside one FIFO container

That is accepted in the first pass. The design should say so explicitly rather
than pretending class FIFO somehow gives micro-flow fairness.

## Unified Packet Path

Every packet that egresses a shaped interface follows:

```text
RX
  -> parse / route / session / NAT
  -> classify to forwarding class
  -> map class to reservation and container
  -> enqueue on the reservation/container owner
  -> reservation/container admission control
  -> reservation scheduling
  -> transmit from selected container
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

There is one scheduler with two service phases. Both operate on
**reservations**, not on micro-flows.

### Phase 1: Guarantee Service

Purpose:

- satisfy reservation guarantees
- ensure every backlogged reservation with available guarantee budget makes
  forward progress

Rules:

1. Walk active reservations in rotating round-robin order.
2. Give each reservation a bounded `cir_quantum` per visit.
3. Within the selected reservation, dequeue from its container FIFO.
4. Charge:
   - root aggregate budget
   - reservation CIR budget

Recommended per-visit quantum:

```text
cir_quantum_bytes = clamp(
    reservation_cir_bytes_per_us * 100,
    mtu_bytes,
    32 * 1024
)
```

This keeps:

- low-rate reservations from being permanently postponed
- high-rate reservations from consuming the entire cycle
- queue-order bias from dominating service

### Phase 2: Surplus Service

Purpose:

- distribute bandwidth above active guarantees

Rules:

1. Scan reservations by priority.
2. The first priority level with eligible surplus demand wins the cycle's
   surplus service.
3. Within that level, use weighted DWRR across reservations.
4. Within the selected reservation, dequeue from its container FIFO.
5. Charge:
   - root aggregate budget
   - reservation surplus budget / ceiling

Strict priority applies only to surplus service.

The ceiling should be modeled as a reservation-level token bucket distinct from
the guarantee bucket. In other words:

- the guarantee phase spends the reservation's CIR bucket
- the surplus phase spends a separate ceiling/PIR bucket

That keeps "exact" and ceiling semantics explicit instead of treating surplus as
an unbounded borrow from the root.

### Same-Priority Weighted DWRR Across Reservations

Each reservation at a priority level has a persistent `surplus_deficit`.

Per DWRR round:

```text
for each active reservation at this priority:
  reservation.surplus_deficit += reservation.weight * round_quantum
  while reservation.surplus_deficit >= next_pkt_len and budget remains:
    dequeue packet from reservation.container
    reservation.surplus_deficit -= pkt_len
    charge root + reservation surplus budget
```

This gives stable weighted sharing among reservations without implying any
micro-flow logic inside a container.

## Container Scheduling

The first pass should stay simple:

- one FIFO queue per container
- one active dequeue head per container
- no fairness key derivation
- no per-flow DRR
- no host buckets

If a reservation later needs multiple containers, container selection inside
that reservation can still remain simple, for example:

- fixed-priority among containers, or
- round-robin among containers

But that is a later extension. The current baseline should not be written as
if per-flow fair queueing already exists.

## Admission Control

Admission control belongs inside the hierarchy.

### Root-Level Admission

The root enforces:

- interface-level byte limit
- interface-level frame limit
- interface-level UMEM budget

### Reservation-Level Admission

Each reservation enforces:

- byte limit
- frame limit
- optional reserved headroom

Reservation headroom prevents one reservation from consuming all of the shared
buffering and making the interface unusable for every other reservation.

### Container-Level Admission

Each container enforces:

- FIFO byte limit
- FIFO frame limit

First-pass overflow policy:

- tail-drop within the same container

This is intentionally simpler than reclaim lists or dominant-flow scavenging.
Those mechanisms are only worth introducing after the basic class-based shaper
works and we have evidence they are needed.

### Memory Accounting

Track queue occupancy in two dimensions:

- **payload bytes** for shaping and scheduling logic
- **UMEM frames** for actual memory safety

Both must be enforced even in FIFO-only mode.

## Many-Core Scaling

The previous draft used the word "sharding" too abstractly. The concrete model
should be:

- a **shard** is just a scheduler owner for some reservations/containers on
  one shaped interface
- a shard is **not** a second policy layer
- a shard is **not** a fast path
- a shard does **not** create independent rates

### Concrete Example

Phase 1 does not require multiple shards. The simplest valid implementation is
one scheduler owner per shaped interface, with every reservation on that one
owner.

The example below is intentionally a later many-core example for Phase 3, where
several scheduler shards exist for one interface.

Suppose interface `ge-0-0-1` has four scheduler shards:

- shard 0 owns `network-control`
- shard 1 owns `expedited-forwarding`
- shard 2 owns `assured-forwarding`
- shard 3 owns `best-effort`

Any worker that classifies a packet into `best-effort` does this:

1. map packet to the `best-effort` reservation/container
2. enqueue it to shard 3, because shard 3 owns that queue
3. shard 3 runs FIFO queueing for that container
4. when shard 3 dequeues, it spends:
   - root lease from the shared interface bucket
   - reservation lease from the shared `best-effort` bucket

So the queue is local to one shard, but the budget authority is still global.

### Ownership Rules

To keep semantics correct:

1. A container belongs to exactly one shard at a time.
2. All packets for that container enqueue to that shard.
3. The root and reservation budgets remain shared and authoritative.
4. A reservation must not silently exist as independent schedulers on several
   workers, because that would multiply its effective share.

### Why This Supports Many Cores

This model still uses many cores:

- parse, route, NAT, and classification can run on all workers
- different reservations can be owned by different scheduler shards
- shared budgets are touched through leases rather than on every packet
- semantics do not change when the number of arrival workers changes

### What It Does Not Solve

This first-pass many-core model is intentionally coarse-grained.

If one reservation is extremely hot:

- its owner shard can become CPU-bound
- throughput for that reservation can be bounded by that shard
- correctness is still preserved
- class behavior does not multiply across workers

That is acceptable for the first implementation. It is much easier to reason
about than splitting one reservation across many workers before the core
algorithm is stable.

### Recommended Rollout

The implementation plan should be explicit:

1. **Simplest valid version**: one scheduler owner per shaped interface
2. **Next step**: multiple scheduler shards with static reservation/container
   ownership
3. **Later only if needed**: more sophisticated ownership or sub-queue models

Do not start with per-flow shard placement.

## Shared Budget Leasing

Shared root and reservation budgets should not be touched directly on every
packet.

### Lease Hierarchy

Recommended implementation:

```text
shared root/reservation buckets
  -> optional socket-local lease cache
    -> shard-local lease
```

This gives:

- global correctness
- reduced cross-core cache-line contention
- better NUMA behavior

### Lease Size

Shard-local lease size should be dynamic:

```text
lease_bytes = clamp(
    rate_bytes_per_us * target_lease_us,
    mtu_bytes,
    min(burst_bytes / 8, max_lease_bytes)
)
```

Recommended defaults:

- `target_lease_us = 25`
- `min_lease_bytes = MTU`
- `max_lease_bytes = 64 KB` for root aggregate
- `max_lease_bytes = 16 KB` for reservation pools

At very low rates, direct charging against the shared bucket may be acceptable
because packet rate is already low.

### Lease Return

Unused leases must be returned when:

- the reservation/container goes idle
- the shard goes quiescent
- lease age exceeds a threshold
- config reload or HA transition occurs

### Total Lease Bound

Total leased-but-unspent credit per shared bucket must be bounded:

```text
max_total_leased = min(bucket_burst / 4, lease_per_shard * active_shards)
```

This prevents many shards from hoarding too much shared credit at once.

### Cache-Line Isolation

All shared buckets should be padded and isolated per cache line.

Without that, coherence traffic will dominate the hot path on many-core boxes.

## Failure Modes

### Queue Overflow

First-pass policy:

- container tail-drop on container overflow
- reservation admission failure if reservation-level caps are exceeded
- root/interface admission failure if interface-level UMEM or queue caps are
  exceeded

### TX Ring Backpressure

If TX ring submission is partial:

- return unsent packets to the front of the same shard/reservation/container
- preserve FIFO ordering

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

Internal mapping:

- the interface shaping-rate becomes the **root**
- the scheduler attached to a forwarding class becomes the **reservation**
- the actual queue instance on that interface becomes the **container**

Future knobs for finer-grained fairness, such as something like
`host-fairness source-address`, are intentionally out of scope for Phase 1 and
should be treated as reserved future extensions rather than active baseline
behavior.

### Example

```text
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

set class-of-service scheduler-maps my-map forwarding-class best-effort scheduler be-sched
set class-of-service scheduler-maps my-map forwarding-class expedited-forwarding scheduler ef-sched

set class-of-service interfaces ge-0-0-1 unit 0 shaping-rate 10g
set class-of-service interfaces ge-0-0-1 unit 0 shaping-rate burst-size 125m
set class-of-service interfaces ge-0-0-1 unit 0 scheduler-map my-map
```

## Observability

Observability should reflect the actual hierarchy.

### CLI

Required views:

- interface/root state
- reservation state
- container state
- shard state for many-core debugging

Examples:

```text
show class-of-service interface ge-0-0-1
show class-of-service interface ge-0-0-1 reservation best-effort detail
show class-of-service interface ge-0-0-1 container best-effort
show class-of-service interface ge-0-0-1 shards
```

### Metrics

At minimum:

- root aggregate tokens
- reservation CIR/PIR served bytes
- reservation queue depth bytes/frames
- container queue depth bytes/frames
- container tail drops
- UMEM pressure drops
- lease returns and lease expirations
- shard-local backlog and service

## Implementation Plan

### Phase 1: Root + Reservation + Container FIFO

- root aggregate shaping
- one reservation per class
- one FIFO container per reservation
- no bypass for generated packets on shaped interfaces
- valid implementation may use one scheduler owner per interface

### Phase 2: Reservation Guarantees and Surplus

- guarantee service phase
- surplus service phase
- strict priority between reservation levels
- weighted DWRR within the same priority
- shared root/reservation budgets

### Phase 3: Many-Core Ownership and Leasing

- static reservation/container ownership by scheduler shard
- internal enqueue to the owning shard
- shared parent budgets plus shard-local leases
- cache-line isolation for shared pools

### Phase 4: Observability and Tuning

- root/reservation/container CLI
- shard metrics
- lease tuning
- latency and throughput tuning

### Future Extension, Not Phase 1

If class-level FIFO proves insufficient, later work can add:

- multiple containers per reservation
- more advanced admission/reclaim
- finer-grained fairness below the container level

But that should be justified by evidence, not assumed into the baseline design.

## Validation Plan

The design is only correct if all of these pass.

### Throughput and Accuracy

1. Single interface, single reservation, line-rate shaping
2. Low-rate shaping accuracy at `10/50/100 Mbps`
3. Multi-reservation contention on shared root budget

### Scheduling Correctness

4. Guarantee phase gives every backlogged reservation forward progress
5. Same-priority weighted DWRR surplus split matches configured weights
6. `transmit-rate exact` never exceeds its guarantee

### Adversarial Class Behavior

7. One elephant in low priority does not destroy a small high-priority class
8. One hundred elephants across several low-priority reservations still allow
   high-priority reservations to meet guarantees
9. Uneven RSS placement does not multiply reservation guarantees

### Many-Core Behavior

10. Packets from many arrival workers still enqueue to the correct owning
    shard for their reservation/container
11. Shared-budget leasing remains stable under many-core contention
12. No long-lived stranded lease credit

### Infrastructure

13. No-bypass validation for session hits and generated packets
14. TX ring backpressure preserves FIFO ordering
15. Config reload and HA transition honor bounded drain behavior
16. UMEM accounting remains correct under mixed packet sizes

### Known First-Pass Limitation to Measure Explicitly

17. Elephant-versus-mice within the **same** container should be benchmarked
    and documented as FIFO behavior, not misrepresented as solved fairness

## Summary

The first-pass design should be framed as:

- a hierarchical shaper
- one unified packet path
- one service tree: `root(interface) -> reservation -> container`
- FIFO queueing inside containers
- weighted scheduling among reservations
- no CIR fast path
- many-core support through queue ownership and shared-budget leasing
- no claim of micro-flow fairness in phase 1

That keeps the document aligned with the actual intent:

- protocol oblivious
- class-oriented and work-conserving
- understandable on many-core systems
- implementable without jumping straight into expensive per-flow machinery
