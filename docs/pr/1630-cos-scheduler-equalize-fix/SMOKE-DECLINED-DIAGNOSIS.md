# #1630 PR #1634 smoke-declined — architectural diagnosis

## Smoke verdict from cluster operator

PR #1634 (`0c54a707ed2f`) was DECLINED after independent smoke
verification on `loss:xpf-userspace-fw0`. The 5-class simul-load
(demand 19.1 G ≤ 17.5 G phase-1 budget) showed ~65-80 % per class
— proportional, NOT small-class-first. The waterfill code is
correct in isolation but the runtime behavior matches
proportional mode.

## Live `show class-of-service` output (cluster after PR #1634 deploy)

```
Interface: reth0.80
  Shaping rate:             25.00 Gb/s
  Runtime workers:          6
  Queues:
    Queue  Owner  Class           Priority  Exact  ...
    0      0      best-effort     5         no
    1      1      iperf-100m      5         yes
    2      2      iperf-1g        5         yes
    3      3      iperf-3g        5         yes
    4      4      iperf-6g        5         yes
    5      5      iperf-9g        5         yes
    6      0      iperf-12g       5         yes
    7      1      iperf-15g       5         yes
    ...
```

**Each queue has a DIFFERENT `Owner` worker.** Workers 0-5 each
own ~2 queues. Queues are assigned via round-robin in
`build_cos_owner_worker_by_queue_with_fallback_ifindexes`
(`userspace-dp/src/afxdp/coordinator/mod.rs:935-938`):

```rust
for queue in &iface.queues {
    let owner_worker_id = eligible_workers[*next_slot % eligible_workers.len()];
    *next_slot += 1;
    owner_by_queue.insert((egress_ifindex, queue.queue_id), owner_worker_id);
}
```

## The architectural bug

Packets for queue X are redirected via
`redirect_local_cos_request_to_owner`
(`userspace-dp/src/afxdp/cos/cross_binding.rs:112-135`) to the
owner worker. After redirect, queue X's backlog lives ONLY on
its owner.

When that owner runs `select_exact_cos_guarantee_queue_waterfill`,
it walks `root.exact_queues_by_rate_ascending` (which contains
all 12 queue indices), but only its OWN queue has packets — all
others are skipped via `cos_queue_is_empty(queue)` at
`queue_service/mod.rs:845`.

**The waterfill selector's "small-class-first ascending walk"
is meaningless within a single worker** because the worker
doesn't see the other classes' backlog. Each worker independently
drains its single queue at the per-class lease cap (the v8
`SharedCoSQueueLease` ON THE owner worker only).

## Why solo iperf-1g is 84 % but multi-class is 65-80 %

Solo iperf-1g: worker 2 owns iperf-1g, drains it via the v8 lease
which grants 1 G/sec (in 25 KB chunks per 200 µs epoch). Achievement
is 84 % because of `cos_guarantee_quantum_bytes` vs MTU misalignment
(lease grants `R × VISIT_NS = 25 KB`, drain sends ≤ 16 MTU packets,
small carry-forward losses accumulate).

Multi-class simul: 5 classes saturate 5 workers. Total demand
19.1 G + uncapped traffic. The shared **root shaper at 25 G**
becomes the aggregate bottleneck. When `root.tokens < head_len`
at `queue_service/mod.rs:864`, all queues park. Root tokens are
distributed across workers in a **proportional** way (FIFO
acquisition by demand). So per-class throughput = configured
rate × shaper-share-fraction.

This IS proportional behaviour. The waterfill selector's logic
to break to Phase 2 never matters because the selector only sees
one queue per worker.

## Why #1614 plan §5.B2 anticipated this

`docs/pr/1614-multi-rss-cos/plan.md:526-528`:

> **B2 (cross-worker shared shaper-budget atomic)**: generalize
> #917 V_min to any exact queue with >1 active worker.
> Clean follow-up; file as separate issue post-Axis-A.

The Axis-A waterfill selector is **local-scheduler scope**
(`claude-smr-code-r1.md:148`: "worker-local; no cross-worker
coordination touched"). It cannot, by construction, enforce
small-class-first under the standard owner-worker queue
distribution.

## Fixes considered

### Option 1 — Force all CoS queues to one owner worker

Change `build_cos_owner_worker_by_queue_with_fallback_ifindexes`
to assign all queues on an interface to the SAME owner worker.
The waterfill selector then sees all 12 queue backlogs and can
honor small classes first.

**Cost**: defeats the per-worker parallelism the system was
designed for. One worker pinned at 25 G with 11 backlog queues
becomes a single-CPU bottleneck. The whole reason for owner-
worker round-robin is to spread the drain work across cores.

### Option 2 — Implement Axis B2 (cross-worker shaper-budget atomic)

Add a cross-worker coordination layer so each worker knows the
demand at every queue across all workers. The selector consults
this shared state to decide whether to defer to a smaller class
on another worker.

**Cost**: substantial new mechanism (per #1614 plan §5.B2,
explicitly filed as follow-up). Requires shared atomics for
per-queue demand, a new throttle mechanism per worker that
queues-up when a smaller-rate class wants service on a peer
worker. This is at least a multi-week design effort.

### Option 3 — Single-owner CoS interface mode (opt-in)

Add a config knob `set class-of-service interfaces reth0 unit 80
single-owner` that flips the owner-worker distribution to assign
all queues to ONE owner. Operators who want guarantee-rate
semantics opt in and accept the parallelism cost; operators who
need parallelism stay on the default proportional behavior.

**Cost**: smaller scope. New config knob + Go control plane
wiring + change to `build_cos_owner_worker_by_queue_*`. Documents
the trade-off explicitly. Aligns with the existing "opt-in"
posture for guarantee-rate.

### Option 4 — Document the limitation, close #1630, accept proportional

Recognize that the documented contract assumes single-owner; the
multi-worker distribution implicitly violates the contract. Update
`docs/fairness-regimes.md:848-865` to state that guarantee-rate
mode requires single-worker ownership OR cross-worker
coordination (B2, future). Close #1630 with a follow-up tracker
for B2.

## Recommended path

Option 3 (`single-owner` opt-in knob) is the smallest-scope fix
that unblocks the #1630 contract. Risk surface is small (one
new config knob, one branch in
`build_cos_owner_worker_by_queue_*`). Operators who want
guarantee-rate semantics will accept the single-worker
performance trade-off because they already accept the
oversubscription envelope.

PR #1634's waterfill correction is still correct and should
remain in-tree as the foundation for either Option 2 or
Option 3.

## Methodology lesson

The 5-round plan-review + 1-round code-review missed this
because every reviewer operated within the single-worker scope.
The waterfill code IS correct within that scope. The
consumer-success-criterion test (`cos-simul-load-smoke.sh push`)
exercises multi-worker behaviour and reveals the gap. Per
`feedback_review_scaffolding_against_consumer`, reviewers must
evaluate against the smoke-fixture consumer scenario — that
means understanding the queue-to-worker distribution model
BEFORE evaluating selector semantics in isolation.
