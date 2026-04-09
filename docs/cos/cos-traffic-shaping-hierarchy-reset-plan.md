Plan: Re-Center CoS on a Hierarchical Shaper

What I think is wrong with my current direction

1. I drifted away from the actual hierarchy.
   The design should be a tree:
   interface aggregate -> forwarding class -> optional fairness leaf

2. I treated CIR too much like a privileged service path.
   CIR is not a fast path. It is just the guaranteed portion of service inside the same scheduler.

3. I over-focused on worker ownership mechanics before locking the hierarchical semantics.
   That is implementation detail. The hierarchy and invariants need to come first.

Reset principles

1. Every packet on a shaped interface follows the same path:
   classify -> enqueue -> admit -> schedule -> transmit

2. CIR is not a bypass and not a separate queue.
   CIR means "guaranteed service budget for this node", nothing more.

3. The hierarchy must be explicit and preserved in both accounting and scheduling.

4. Multi-core support must shard the hierarchy, not bypass it.

5. The design remains protocol oblivious:
   no TCP/UDP/ESP/GRE-specific scheduling logic and no session-hit bypass.

Target hierarchy

1. Root node: interface shaper
   Fields:
   - shaping rate / burst
   - global queued bytes / frames
   - global parent token state

2. Class node: forwarding class scheduler
   Fields:
   - CIR / PIR
   - priority
   - buffer budget
   - admission headroom
   - stats

3. Leaf node: optional fairness bucket inside class
   Examples:
   - source-address
   - destination-address
   - prefix
   - disabled -> class FIFO

The packet must only transmit if all relevant ancestors allow it.

Unified packet lifecycle

1. Classify packet to forwarding class.
2. Derive fairness key if that class uses fairness.
3. Enqueue into class leaf.
4. Admission control runs at the class/leaf level.
5. Scheduler selects class, then leaf, then packet.
6. On transmit, charge:
   - root aggregate
   - class CIR or class PIR
   - leaf DRR / admission state

No alternate "CIR path" exists. There is one scheduler, with two service phases.

Scheduling plan

Phase 1: guarantee service

- Purpose: satisfy class CIR guarantees.
- This is not "fast path service"; it is the first pass of the same scheduler.
- Use bounded round-robin across active classes so queue index does not bias service.
- Within each class:
  - FIFO classes dequeue FIFO
  - fairness classes dequeue via leaf DRR

Phase 2: surplus service

- Purpose: distribute bandwidth above active CIR.
- Strict priority applies only here.
- Within same priority, use DWRR across classes.
- Inside each class, use the same leaf selection policy as Phase 1.

Important invariant:

- a packet chosen in either phase still goes through the same class/leaf dequeue and the same root/class accounting.

Admission-control plan

Admission control belongs inside the hierarchy, not beside it.

At class level:

- class buffer bytes
- class buffer frames
- class headroom reserved for new / under-cap leaves

At leaf level:

- soft cap
- hard cap
- reclaim eligibility

Reclaim order:

1. reclaim over-cap leaf in same class
2. reclaim deepest leaf in same class
3. fall back to class tail-drop

This keeps the admission logic hierarchical:

- leaves compete inside a class
- classes compete only through the root/class scheduler

Multi-core plan

The right many-core model is:

- shard the scheduler tree
- not CIR service

Concrete plan:

1. Define scheduler shards per shaped interface.
   Each shard owns a full local copy of:
   - class queues
   - leaf queues
   - local scheduler state

2. Hash fairness-enabled traffic to a scheduler shard by:
   - interface
   - class
   - fairness key

3. FIFO-only / latency-sensitive classes can stay local to the current TX worker if desired, but that should still be modeled as a class node in the same hierarchy.

4. Shared parent budgets remain global:
   - root aggregate shared across shards
   - class CIR/PIR shared across shards

5. Shards lease from shared parent budgets.

Why this is different from the earlier drift:

- I am not proposing a CIR fast path.
- I am not proposing a separate non-hierarchical owner pipeline.
- I am proposing sharding the entire class/leaf subtree so each shard still runs the same hierarchical scheduler.

This keeps hierarchy intact while scaling to many cores.

Token/accounting plan

1. Root aggregate budget is authoritative and shared.
2. Class CIR/PIR budgets are authoritative and shared.
3. Workers/shards only hold temporary leases.
4. Leases are dynamic and returned aggressively when idle.
5. Shared pools must be cache-line isolated.

Implementation detail:

- all shared token buckets become padded per-bucket structs
- no packed arrays of hot atomics

This is where many-core support lives:

- in leasing and cache layout
- not in bypassing the scheduler

What I will remove from the current direction

1. Any wording that suggests CIR is a shortcut or privileged path.
2. Any design that makes fairness semantics depend on packet hitting a “special” worker path outside the hierarchy.
3. Any optimization that bypasses enqueue/admission/scheduling for established traffic.

What I will keep

1. Shared class/root budgets across workers.
2. Protocol-oblivious fairness keys.
3. Admission control, because dequeue fairness alone is not enough.
4. Direct scheduler ownership of TX ordering.

Rewrite plan for the design doc

1. Start with explicit tree semantics and invariants.
2. Define node types: root, class, leaf.
3. Rewrite CIR/PIR as node budgets, not paths.
4. Rewrite scheduler as:
   - phase 1 guarantee over class nodes
   - phase 2 surplus over class nodes
   - same leaf dequeue logic in both phases
5. Add a dedicated section:
   Multi-Core Scaling Without Breaking Hierarchy
6. Move worker/shard ownership discussion after the hierarchy is defined.
7. Add explicit “no bypass / no fast path” invariants.

Validation plan

1. One elephant vs 100 mice in one class, one shard.
2. One elephant vs 100 mice spread across many workers.
3. 100 elephants vs 1 mouse across many shards.
4. 100 elephants vs 100 mice across many shards.
5. Same-class many-core contention on shared root/class budgets.
6. Queue-index fairness in phase 1.
7. Low-rate shaping accuracy with leases.
8. No-bypass validation for session hits and generated traffic.

Success criteria

I will consider the design back on track when:

1. the hierarchy is explicit in the doc
2. CIR is described only as guaranteed service budget, not as a special path
3. all packets on shaped interfaces use one unified queue/admit/schedule/transmit path
4. many-core scaling is described as sharding the hierarchy plus shared parent leases
5. protocol obliviousness remains true

Bottom line

The plan is to reset the design around a true hierarchical shaper:

- root -> class -> leaf
- one scheduler
- two service phases
- no CIR fast path
- multi-core achieved by sharding the tree and leasing shared parent budgets

That is the direction I should have stayed on.
