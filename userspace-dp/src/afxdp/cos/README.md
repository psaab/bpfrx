# userspace-dp/src/afxdp/cos/

Class-of-Service scheduler. Per-egress-interface shaping, per-queue
priorities, per-flow fair share inside a queue, ECN CE-marking, and
the cross-binding redirect path that gets a TX request to the
worker that owns the egress interface.

This is the most complex sub-module in the dataplane and the place
where every recent fairness mechanism kill happened (#1236, #1237,
#1239, #1243, #1244 — see `docs/per-5-tuple/state.md`).

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Re-export hub for the sub-modules. |
| `admission.rs` | Per-flow admission gates (share / buffer caps, ECN CE-marking) + flow-fair (SFQ) queue promotion. |
| `builders.rs` | CoS interface-runtime construction. `ensure_cos_interface_runtime` sits on the steady-state enqueue path (every enqueue checks whether the runtime exists for the egress ifindex) and is `#[inline]`. |
| `cross_binding.rs` | Cross-binding redirect: routes a TX request to the owner binding of the egress, for both `Local` and `Prepared` variants. Prepared redirects release source UMEM frames through the TX shared-recycle accumulator so foreign-slot frames return to their owning fill rings. |
| `ecn.rs` | ECN CE-marking + Ethernet L3 parser. Threshold constants and the `apply_cos_admission_ecn_policy` gate live in `admission.rs` (a byte-mutation module shouldn't own admission tuning). |
| `fairness.rs` | #1229 v7 per-bucket TX rate accounting + threshold-gated EWMA. Tracks observed bits/sec per FlowFair bucket so the cap-aware MQFQ selector can compare against `Queue_BW_bps / max(1, active_flow_buckets)`. Single-writer per `FlowFairState`. |
| `flow_hash.rs` | Per-queue flow-hash machinery for SFQ admission + promotion. |
| `queue_ops/` | CoS queue primitives: accessors, enqueue/dequeue, MQFQ ordering bookkeeping, V-min slot lifecycle. Per-byte hot-path fns carry `#[inline]` to preserve cross-module inlining. |
| `queue_service/` | CoS dispatch / drain / submit subsystem. Hot-path call chain: `drain_shaped_tx → select_cos_*_batch → service_exact_*_queue_direct → drain_exact_*_to_scratch → submit_cos_batch → settle_exact_*`. |
| `token_bucket.rs` | Token-bucket lease / refill plumbing for TX pacing. Owns `COS_MIN_BURST_BYTES` (64 × MTU) — the universal floor for both root and per-queue burst caps. |
| `tx_completion.rs` | TX-completion + interface timer wheel. Owns the wheel advance / cascade / wake-due slot management, the apply paths (`apply_direct_exact_send_result`, `apply_cos_send_result`, `apply_cos_prepared_result`), and the queue-scoped `DrainShape` phase counters (`guarantee`, `surplus`, `nonexact_while_exact_backlogged`). |

`queue_ops/` and `queue_service/` are sub-directories; see their own
mod.rs for further file-level breakdown.

## Where it sits

- Reads decisions from `policy.rs` (forwarding-class + DSCP rewrite).
- Driven from `tx/dispatch.rs` and `worker/lifecycle.rs::poll_binding`.
- Writes per-queue / per-binding state held in `types/cos.rs`.
- Owner-only writes; cross-binding `cross_binding.rs` is the only
  legitimate path that crosses worker boundaries.

## Notable invariants

- **Flow-fair gate is `flow_fair_state.is_some()` (#1735).** The runtime
  `CoSQueueRuntime::flow_fair()` accessor returns
  `flow_fair_state.is_some()`, NOT `config.flow_fair`. The invariant
  `flow_fair() == flow_fair_state.is_some()` is therefore structurally
  unbreakable — a `None`-state queue always dispatches the cheap FIFO
  branch and allocation is the only thing that flips the gate.
  `config.flow_fair_eligible` (the renamed `config.flow_fair`) means
  "this shaped queue MAY ever run flow-fair MQFQ" and is decoupled from
  the runtime gate.
- **Per-flow MQFQ runs on ALL shaped queues, not just exact (#1735).**
  `promote_cos_queue_flow_fair` marks every queue that reaches it
  (exact AND non-exact) `flow_fair_eligible`. Exact queues promote
  EAGERLY at build (allocate `FlowFairState` immediately, never demote —
  their V_min / v8-lease coordination assumes stable state). Non-exact
  eligible queues (best-effort / residual) promote LAZILY: a hash-free
  front-key contention probe in `cos_queue_push_back`
  (`maybe_promote_best_effort`) compares the incoming item's
  `Option<&SessionKey>` to the FIFO front structurally (NO hash) and
  promotes only on the FIRST genuinely-distinct flow. A single-flow /
  uncontended best-effort queue stays a trivial FIFO and pays zero hash
  and zero `FlowFairState` footprint — the #1183 best-effort fast-path
  boundary. Forwarding-only / transparent interfaces never build a
  `CoSInterfaceRuntime`, so their queues never become eligible.
  `promote_to_flow_fair` migrates the resident FIFO by re-enqueueing
  each item through the normal MQFQ accounting path (hashing each into
  its own bucket — correct for any flow mix). When a lazily-promoted
  non-exact queue settles fully drained for
  `COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS` consecutive batch settles,
  `maybe_demote_drained_best_effort` (called at the end of
  `apply_cos_send_result` / `apply_cos_prepared_result`, after the retry
  restore) drops its `FlowFairState` box so idle queues release the
  ~232 KB footprint. Surplus DWRR across queues + MQFQ inside the
  selected queue compose for free: `build_cos_batch_from_queue` and the
  cap-aware exact drains pop via the fused select+pop pair
  `cos_queue_peek_min_bucket` + `cos_queue_pop_known_bucket` (#1763),
  both dispatching on `flow_fair()`. The MQFQ min-head-finish scan
  (`cos_queue_min_finish_bucket`, an O(N) linear scan over the active
  flow-bucket ring, N≈14 measured under iperf3 -P48) used to run twice
  per dequeue — once for the `cos_queue_front*` peek and again inside the
  `cos_queue_pop_front*` re-scan, with no queue mutation between — so the
  fused pair hands the peek's selected bucket straight to the pop and
  removes the redundant scan. A `target_bps == u64::MAX` no-cap fast path
  scans only `flow_bucket_head_finish_bytes`, skipping the dead
  `flow_bucket_observed_bps` load. Both levers are fairness-neutral by
  construction (byte-identical bucket selection and dequeue order),
  pinned by the `fused_diff_tests.rs` differential test against the
  retained `cos_queue_pop_front*` reference oracle. This also folds in
  the residual/best-effort
  queue-level → flow-level item from the #1731 research plan (its
  finding #7; NOT GitHub issue #7, which is an unrelated SNAT bug).
- Single-writer per FlowFairState. The owner worker that polls a
  binding is the same worker that owns the queue's
  `FlowFairState`; therefore `observed_bps` updates and reads do not
  need atomic synchronization.
- Prepared CoS items may carry frames from another binding in the same
  shared-UMEM group. Queue overflow, capacity rejection, local
  demotion, cross-binding copy, and runtime reset must thread the
  worker shared-recycle accumulator to avoid returning a foreign slot's
  frame to the current binding.
- Hot-path constants pinned in code: `RX_BATCH_SIZE = 64`,
  `TX_BATCH_SIZE = 64` (the latter paired with the CoS guarantee
  quantum). See `userspace-dp/README.md`.
- Per-byte hot-path fns are `#[inline]` to preserve cross-module
  inlining across the `pub(in crate::afxdp)` boundary; the larger
  drain/settle bodies aren't inlined (LLVM heuristics suffice).
- The TX drain caller enters `drain_shaped_tx` only while the binding
  reports at least one nonempty CoS interface and has an interface order.
  Configured-but-idle bindings skip the no-op shaped-drain call path
  entirely; nonempty bindings still call into CoS so runnable work,
  due parked queues, and shared lease epoch progress are preserved.
- `drain_shaped_tx` primes an interface root only when queued work is
  runnable now or a parked queue's wake tick is due. Not-yet-due
  parked queues skip timer-wheel advance and shared-root lease top-up
  because no queue can service on that drain call.
- Scheduler-map queues without a positive explicit scheduler
  `transmit-rate` are residual-only under a shaped root. They keep an
  effective rate for burst sizing and surplus weight, but
  `queue_service` skips them in guarantee selectors via
  `queue.config.guarantee_enabled == false`.
- Residual-only / non-exact queues keep their explicit guarantee
  service, but their surplus service is bounded while exact queues
  have demand on the same shaped interface. The bound is the residual
  root rate after reserving each backlogged exact queue's configured
  guarantee rate once. Cross-binding demand is imported through
  `SharedCoSExactBacklog` as an exact-queue mask, not a per-worker
  rate, so one shared exact queue does not multiply its reservation by
  the number of workers. Shared interfaces also use a shared residual
  token bucket for non-exact surplus; private/local fallbacks use the
  per-root residual bucket. Exact queues that explicitly enable
  `surplus-sharing` remain eligible for surplus service outside the
  non-exact residual budget.
- `COS_MIN_BURST_BYTES` (64 × MTU) is canonically owned by
  `token_bucket.rs`; siblings import it via the `cos/mod.rs`
  re-export.
- Scheduler `buffer-size <n>%` is resolved before runtime queue creation
  as `<n>%` of the interface CoS burst pool. The pool is the explicit
  `class-of-service interfaces ... shaping-rate burst-size` value when
  configured, otherwise the same `default_cos_burst_bytes` root-burst
  fallback used by the shaper. The legacy `buffer_size_bytes` protocol
  field still wins when present; `buffer_size_percent` is additive for
  #1336 compatibility. Go-side config validation rejects per-interface
  scheduler-map percent totals above 100%, so Rust only receives
  already-admitted percent allocations. xpf rejects `0%` before the
  snapshot because zero is the additive field's legacy absent value.
