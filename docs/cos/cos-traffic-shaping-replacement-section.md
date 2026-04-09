Replacement Section for `docs/cos-traffic-shaping.md`

This section rewrites the core design around a true hierarchical shaper:

- root -> class -> leaf
- one unified packet path
- one scheduler with two service phases
- no CIR fast path
- many-core scaling by sharding the hierarchy, not bypassing it

---

## Hierarchical Service Model

The CoS subsystem is a **hierarchical egress shaper**, not a policer and not a collection of independent queues.

Every shaped packet belongs to this tree:

```
Interface root
  -> Forwarding class
    -> Optional fairness leaf
```

The hierarchy is:

1. **Root node**: interface shaping-rate and burst
2. **Class node**: queue/class guarantee and surplus policy
3. **Leaf node**: optional fairness bucket inside a class

Every transmitted byte is accounted at every relevant level:

- root aggregate budget
- class CIR or class PIR
- leaf dequeue / admission state

There is no alternate service path for guaranteed traffic. `CIR` is not a fast path. It is only the guaranteed service budget for a class node inside the same scheduler.

### Invariants

The implementation must preserve these invariants:

1. Every packet on a shaped interface follows one unified path:
   classify -> enqueue -> admit -> schedule -> transmit

2. No session-hit, cache-hit, or generated packet bypasses shaping.

3. A packet may only transmit if all relevant ancestors allow it:
   - root has budget
   - class has budget for the selected phase
   - leaf has a dequeuable packet

4. Multi-core scaling must not weaken the hierarchy.
   Workers may shard the hierarchy, but they may not bypass it.

5. Scheduling is protocol oblivious.
   Decisions depend on:
   - class assignment
   - fairness key
   - byte count
   - queue state
   - token state

   They do not depend on TCP/UDP/ESP/GRE/ICMP semantics.

---

## Packet Lifecycle

Every packet on a shaped interface follows the same logical path:

```
RX
  -> parse / session / route / NAT
  -> classify to forwarding class
  -> derive fairness key if class uses fairness
  -> enqueue into class leaf
  -> admission control

poll cycle
  -> phase 1 guarantee service
  -> phase 2 surplus service
  -> TX ring submission
```

This applies to:

- forwarded packets on session hit
- forwarded packets on session miss
- locally generated packets on a shaped interface
- cross-binding forwards targeting a shaped interface

Caching may avoid repeated classification work, but not queue admission or scheduling.

---

## Node Types

### Root Node

The root node represents the shaped interface.

Responsibilities:

- enforce aggregate shaping-rate and burst
- bound total transmitted bytes across all classes
- bound total queue occupancy for the interface

Root state includes:

- aggregate token bucket
- aggregate burst
- total queued bytes
- total queued frames
- UMEM budget accounting

### Class Node

A class node represents a forwarding class / egress queue.

Responsibilities:

- provide guaranteed service via CIR
- receive surplus service via PIR / ceiling rules
- define priority for surplus competition
- define queue buffer budget
- define whether fairness is enabled

Class state includes:

- CIR tokens
- PIR tokens
- priority
- byte/frame queue budget
- admission headroom
- class stats

### Leaf Node

A leaf node is either:

- a fairness bucket keyed by policy, or
- the implicit FIFO leaf when fairness is disabled

Examples of fairness keys:

- source-address
- destination-address
- source-prefix
- 5-tuple

Leaf responsibilities:

- hold queued packets
- participate in dequeue fairness inside the class
- enforce per-leaf admission caps
- expose reclaim candidates under overload

---

## Scheduler

There is one scheduler with two service phases.

### Phase 1: Guarantee Service

Purpose:

- satisfy class CIR guarantees
- ensure every backlogged class with available CIR makes forward progress

This phase operates across class nodes, not packets directly.

Rules:

1. Walk active classes in rotating round-robin order.
2. Give each class a bounded `cir_quantum` per visit.
3. Within the selected class:
   - FIFO classes dequeue FIFO
   - fairness-enabled classes dequeue from their leaf scheduler
4. Charge:
   - root aggregate
   - class CIR

This is not a fast path. It is just the first pass of the same scheduler.

### Phase 2: Surplus Service

Purpose:

- distribute bandwidth above active CIR

Rules:

1. Scan classes by priority.
2. First priority level with eligible surplus demand wins the cycle's surplus service.
3. Within that priority level, distribute surplus by DWRR across classes.
4. Inside each selected class:
   - FIFO classes dequeue FIFO
   - fairness-enabled classes dequeue from their leaf scheduler
5. Charge:
   - root aggregate
   - class PIR

Strict priority applies to surplus service only, not guaranteed service.

### Why This Preserves Hierarchy

Both phases:

- select a class node
- then select a leaf inside that class
- then transmit a packet only if root and class accounting allow it

So the hierarchy remains intact in both guaranteed and surplus service.

---

## Admission Control

Admission control is part of the hierarchy, not a side mechanism.

### Class-Level Admission

Each class has:

- byte limit
- frame limit
- reserved headroom

Class headroom prevents incumbents from fully consuming the buffer and blocking all new arrivals.

### Leaf-Level Admission

Each fairness leaf has:

- soft cap
- hard cap
- reclaim eligibility

Admission policy:

1. If leaf is under soft cap and class is below incumbents budget:
   admit

2. If leaf exceeds hard cap:
   drop

3. If class is full and the leaf is reclaimable:
   reclaim from that leaf

4. If incoming leaf is under cap and class is full:
   reclaim from another reclaimable leaf in the same class

5. If no reclaimable leaf exists:
   reclaim from deepest leaf in the same class

6. If reclaim still fails:
   class tail-drop

This keeps fairness local to the class:

- leaves compete within a class
- classes compete only through the root/class scheduler

### Important Property

Dequeue fairness alone is not enough.

If mice are to survive overload, admission must also be fairness-aware. That is why the class/leaf hierarchy includes both:

- enqueue-time admission control
- dequeue-time fairness

---

## Leaf Scheduling

Within a fairness-enabled class, leaves are served with DRR.

Leaf DRR is:

- byte-based
- protocol oblivious
- adaptive in quantum size

Quantum is chosen to balance:

- CPU cost
- inter-service delay
- active leaf count

Fairness-enabled classes should normally be:

- low
- best-effort
- bulk-style classes

Latency-sensitive classes should normally use:

- FIFO
- small buffers
- no leaf DRR

This is an intentional policy split:

- fairness classes optimize starvation resistance
- FIFO high-priority classes optimize latency

---

## Multi-Core Scaling Without Breaking Hierarchy

Many-core support is achieved by **sharding the hierarchy**, not by introducing a CIR fast path.

### Sharded Scheduler Tree

For each shaped interface, the scheduler tree is sharded across workers.

Each shard owns:

- local class queues
- local leaf queues
- local scheduler cursors / deficits
- local leased token caches

Shared parent budgets remain authoritative:

- root aggregate bucket
- class CIR buckets
- class PIR buckets

So the hierarchy becomes:

```
Shared root/class budgets
  -> worker-local class/leaf shards
```

### Key Rule

Workers do not own independent rates.
They only hold temporary leases from shared parent budgets.

That preserves:

- global class correctness under RSS skew
- local scheduler efficiency

### Shard Placement

For fairness-enabled traffic, the implementation may shard by:

- interface
- class
- fairness key

For FIFO / latency-sensitive traffic, the implementation may keep packets on the local worker if that preserves the same hierarchical semantics.

But in all cases:

- packets still enter a class node
- packets still enter a leaf node
- packets still consume shared parent budgets

### Shared Budget Leasing

Workers lease small local budgets from shared parent pools to reduce atomic traffic.

Leases are:

- dynamic
- short-lived
- returned aggressively when idle

This is where many-core efficiency lives:

- in sharding and leasing
- not in bypassing the scheduler

### Cache-Line Isolation

All shared token pools must be padded/aligned per bucket.

Requirements:

- one hot token pool per cache line
- no packed arrays of hot atomics
- timestamps isolated with their associated bucket if always accessed together

Without this, many-core coherence traffic will dominate.

---

## Protocol Obliviousness

The shaper is protocol oblivious at the scheduling layer.

Scheduling decisions may depend on:

- class assignment
- fairness key
- packet length
- queue occupancy
- token availability

They may not depend on:

- transport protocol semantics
- TCP state
- UDP state
- GRE vs ESP vs ICMP

Classification can still be policy-driven by firewall filter or DSCP, but once the packet enters the hierarchy, service decisions are byte-based and protocol-neutral.

---

## Implementation Guidance

The implementation should proceed in this order:

1. Define the hierarchy and invariants in code:
   root, class, leaf

2. Implement the unified packet path:
   classify -> enqueue -> admit -> schedule -> transmit

3. Implement phase 1 and phase 2 as class-node scheduling, not packet shortcuts

4. Implement leaf scheduling and leaf admission inside the class node

5. Implement multi-core sharding and shared-budget leasing

6. Validate that no packet on a shaped interface bypasses the hierarchy

---

## Validation Requirements

The design is only correct if these tests pass:

1. One elephant vs 100 mice in one fairness-enabled class
2. 100 elephants vs 1 mouse in one fairness-enabled class
3. 100 elephants vs 100 mice across many workers
4. Same-class many-core load with shared budgets
5. Uneven RSS skew: one worker hot, others idle
6. No-bypass validation for session hits and generated packets
7. Low-rate shaping accuracy with leased shared budgets
8. Queue-index fairness in phase 1

---

## Summary

The core model should be:

- one hierarchical shaper
- one unified packet path
- one scheduler with two phases
- no CIR fast path
- many-core scaling by sharding the tree and leasing shared parent budgets

That keeps the design aligned with the actual goals:

- protocol oblivious
- adversarially robust
- many-core capable
- no fast-path escape hatches
