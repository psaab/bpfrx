# Review: `docs/hierarchical-policer.md`

## Overall

The document is strong on motivation and gives a concrete first-pass data model,
but the current algorithm has several correctness problems that would show up
quickly under the exact adversarial cases the prompt cares about.

The biggest issues are:

1. the borrowing model double-counts capacity instead of redistributing unused
   capacity,
2. the DRR fallback can admit packets even after all token checks failed,
3. the per-worker `rate/N` approximation directly conflicts with the stated
   requirement to behave well under uneven queue hashing.

Those are design-level issues, not tuning issues.

## Findings

### 1. Borrowing math is not work-conserving; it appears to mint extra bandwidth

- Severity: high
- Where:
  - lines 88-90
  - lines 96-100
  - lines 337-343
  - lines 354-372
- Problem:
  - The doc says unused child bandwidth "accumulates in the parent's excess
    pool", but the implementation shown does not derive excess from unused child
    service.
  - Instead, parent and root excess pools are independently refilled at their
    own guaranteed rates.
  - That means a leaf can spend:
    - its own guaranteed tokens,
    - plus parent "excess" that was never earned from idle siblings,
    - plus root "excess" that was also refilled independently.
  - This is not redistribution of unused bandwidth. It is additive budgeting.
- Why it matters:
  - The hierarchy can oversubscribe relative to the actual root/interface rate.
  - Sibling idleness is not the thing controlling borrowing; elapsed time is.
  - The design goal "work-conserving" becomes mathematically incorrect.
- Suggestion:
  - Model each node as an actual token bucket that must be charged on admit.
  - On admission, consume along the ancestor chain:
    - leaf CIR bucket,
    - then parent spare budget,
    - then root spare budget.
  - Or equivalently, keep a single root budget and per-node entitlement/spare
    accounting derived from real service, not independently refilled "excess"
    pools.
  - If you want borrowing, define it as "unused parent service budget visible to
    children", not as another free-running bucket.

### 2. The DRR fallback admits traffic after the policer has already decided there are no tokens

- Severity: high
- Where:
  - lines 95-104
  - lines 326-328
  - lines 376-377
  - lines 430-443
- Problem:
  - The token flow section says:
    - if no tokens anywhere, run DRR,
    - if DRR says admit, admit.
  - The code mirrors that:
    - ceiling failure or borrow failure calls `drr_check(...)`,
    - `drr_check()` can return `true`,
    - no bucket is charged when that happens.
- Why it matters:
  - That is not policing. It admits packets after the rate limiter has already
    concluded the budget is exhausted.
  - Under load, aggregate throughput can exceed CIR/PIR because DRR is creating
    admission without consuming scarce budget.
- Suggestion:
  - DRR should choose *which flow gets the next scarce tokenized opportunity*,
    not bypass the token system.
  - If you stay queue-less, use DRR-like logic only as a fair drop/admission
    gate around a real shared budget:
    - first determine a shared admissible budget,
    - then let DRR decide which flow may consume that budget.
  - Do not return `ADMIT` from DRR unless a parent/root budget unit is actually
    available and deducted.

### 3. Option A (`rate/N` per worker) violates the stated adversarial and uneven-RSS requirements

- Severity: high
- Where:
  - lines 39-41
  - lines 96
  - lines 123-124
  - lines 450-467
- Problem:
  - The design goal explicitly calls out uneven hashing to queues/workers.
  - But the chosen implementation gives each worker an independent `1/N` share
    of every guarantee and every excess pool.
  - Under skew, the hot worker can only use its local slice even when sibling
    workers are idle.
- Why it matters:
  - A leaf/class guarantee is not actually guaranteed if its flows land on one
    worker.
  - This is not a corner case; it is part of the problem statement.
  - The document says guarantees are still honored and the error is negligible,
    but for adversarial queue skew that is not true.
- Suggestion:
  - If adversarial skew matters, Option A cannot be the final design.
  - Better directions:
    - a per-interface coordinator worker that owns the hierarchy,
    - batched cross-worker budget transfer on a short scheduler tick,
    - or a shared atomic budget model with local caches/refills.
  - If you keep Option A temporarily, the doc should explicitly state:
    - guarantees become "per-worker approximations",
    - uneven RSS can materially reduce delivered rate,
    - this does not satisfy the stated adversarial goal.

### 4. The 1 ms fixed ceiling window is likely wrong for low rates and will add aliasing/jitter

- Severity: medium-high
- Where:
  - lines 318-326
- Problem:
  - Ceiling is enforced via a 1 ms window and `window_bytes`.
  - At low configured rates, a 1 ms allowance can be smaller than one MTU-sized
    packet.
  - Example: 10 Mbps is about 1250 bytes/ms, which is smaller than a 1500-byte
    packet.
- Why it matters:
  - Legitimate packets can become impossible to admit in-window.
  - Behavior becomes dependent on arbitrary wall-clock window boundaries.
  - Burstiness and tail latency will be worse than with a proper PIR/CBS token
    bucket.
- Suggestion:
  - Use a second token bucket for PIR/CBS instead of a fixed 1 ms accounting
    window.
  - If you want a time-window guard, make it an implementation detail layered on
    top of a real token bucket, not the only ceiling mechanism.

### 5. The fairness key is still a 5-tuple, so a sender can win by splitting into many flows

- Severity: medium-high
- Where:
  - lines 33-37
  - lines 205-213
  - lines 224-227
- Problem:
  - The text says fairness is not session-keyed and is per "source flow".
  - The actual `FlowKey` is still `{src_ip, dst_ip, src_port, dst_port, proto,
    leaf_id}` which is a standard transport 5-tuple.
  - That means a single sender can open many parallel flows and get many DRR
    entries.
- Why it matters:
  - The design goal says "adversarial resilience".
  - A flow-splitting sender can inflate its share relative to a sender using a
    single flow.
  - This is exactly the sort of elephant-vs-mice gaming the document says it
    wants to resist.
- Suggestion:
  - Decide explicitly what the fairness domain is:
    - per 5-tuple,
    - per source host,
    - per destination,
    - per subscriber,
    - or two-level fairness (host first, flows second).
  - If the goal is adversarial resilience, a host/subscriber fairness layer is
    likely needed ahead of or above per-flow DRR.

### 6. The LRU and active-flow accounting story is underspecified relative to the performance claims

- Severity: medium
- Where:
  - lines 196-203
  - lines 423-425
  - lines 684-690
- Problem:
  - `VecDeque<FlowKey>` plus hash map is not enough to justify the quoted `~20ns`
    LRU path unless recency updates and evictions are carefully engineered.
  - `active_count_for_leaf()` is used in the hot congested path, but the doc
    does not explain whether it is O(1), approximate, or maintained incrementally.
- Why it matters:
  - Congested mode is exactly where CPU cost matters.
  - If LRU recency maintenance or per-leaf active counts require scans or extra
    hash churn, the quoted cost model will be far too optimistic.
- Suggestion:
  - Document the intended complexity of:
    - lookup/update,
    - recency bump,
    - eviction,
    - `active_count_for_leaf()`.
  - If you want predictable cost, keep per-leaf active counters and use an
    intrusive LRU list or slab+index structure rather than a plain
    `VecDeque<FlowKey>` design sketch.

## Suggested Changes To The Doc

- Reframe the design around "hierarchical admission control" unless true
  work-conserving scheduling is actually implemented with real shared budgets.
- Replace the current borrowing pseudocode with one that charges ancestor
  budgets on every admit.
- Be explicit that queue-less DRR is not classic DRR; describe it as a
  fair-admission mechanism and define exactly what resource it gates.
- Either:
  - remove the claim that Option A satisfies uneven-hash adversarial goals, or
  - make cross-worker borrowing a required part of the design rather than a
    future optimization.
- Add a section on fairness scope and flow-splitting attacks.
- Add test cases specifically for:
  - all elephant traffic hashing to one worker while siblings are idle,
  - low-rate PIR below one MTU per 1 ms window,
  - many parallel flows from one source vs one flow from another source,
  - aggregate-rate validation that proves DRR cannot admit beyond root PIR.

## Bottom Line

I would not implement the algorithm exactly as written. The core idea is
salvageable, but the design should be revised before coding so that:

- ancestor budgets are real, not independently refilled "excess" buckets,
- fairness never admits packet bytes that were not budgeted,
- uneven worker hashing is treated as a primary correctness constraint,
- fairness semantics are robust against flow splitting.
