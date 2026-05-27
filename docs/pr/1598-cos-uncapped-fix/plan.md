# Plan v1 — #1598 CoS `iperf-uncapped` capped at ~10 Gbps

Status: DRAFT v2 — addresses round-1 Codex PLAN-KILL concern about Step2 `tx_owner_live` funnel by tracing `build_worker_cos_owner_live_by_tx_ifindex` and the per-worker binding topology of the loss userspace cluster. AGY round-1 verdict: PLAN-READY.

## Issue framing

Issue #1598: the `iperf-uncapped` forwarding class (queue 11) is mapped
to `scheduler-uncapped` which has no transmit-rate (only `priority low`).
Per Junos semantics the class should be uncapped — it should be able to
consume whatever bandwidth the parent shaper allows minus what other
classes need. In the current userspace-dp implementation push-direction
P=12 on port 5211 caps at ~10 Gbps despite the cluster being able to
push ~22+ Gb/s without CoS (per #1594 baseline).

The prior #1578 investigation missed this because it measured `iperf3
-R` (reverse) on port 5211 and saw 23.2 Gb/s. The `bandwidth-output`
filter is bound as `family inet filter output` on `reth0.80`; in
reverse mode the server sends data INTO reth0.80 (ingress on that
interface), which is not filtered, so the 23.2 Gb/s was unfiltered
fast path. The bug is on the push direction, which is the filtered
direction.

## Honest scope/value framing

This is a real correctness bug, not a churn optimization. The current
implementation hard-caps every CoS class at ~10 Gbps regardless of
configuration, because all traffic in a single non-exact class is
funneled to one owner worker that is bound by the per-worker AF_XDP
UMEM ceiling. The user has explicitly called this out as a major CoS
bug.

If the proposed fix introduces a packet-ordering regression on shaped
non-exact classes, or breaks the per-class rate enforcement on
classes WITH a configured transmit-rate, PLAN-KILL is an acceptable
verdict and we should iterate the plan to address that.

## Root-cause analysis

### Code walk

1. `userspace-dp/src/afxdp/forwarding_build/cos.rs:269-274` — when a
   scheduler has no transmit-rate, `guarantee_enabled = false` and
   `transmit_rate_bytes` falls back to the interface shaping rate
   (`iface.cos_shaping_rate_bytes_per_sec`, here 25 Gbps = 3.125 GB/s).
   This is correct as a residual-rate floor for surplus sizing.

2. `userspace-dp/src/afxdp/worker/cos/mod.rs:126-131` —
   `queue_uses_shared_exact_service` is the gate that decides whether
   a queue runs under shared multi-worker drain (`shared_exact = true`,
   each worker drains its own enqueue locally) or single-owner drain
   (`shared_exact = false`, one owner worker is the funnel for the
   whole queue). The gate is currently `queue.exact && rate >= 312 MB/s`.

3. `userspace-dp/src/afxdp/coordinator/mod.rs:900-904` — every CoS
   queue gets a single `owner_worker_id` via round-robin across
   eligible workers. This is THE funnel: regardless of which worker
   classifies a packet to this queue, the cross-binding redirect
   routes the request to that one owner.

4. `userspace-dp/src/afxdp/cos/cross_binding.rs:58-90` —
   `resolve_local_routing_decision` returns Step1 routing to the
   queue's `owner_worker_id` when `!shared_exact` (or when
   `tx_owner_live.is_none()`). Step3 (`enqueue_local_into_cos` — drain
   locally on the current worker) is only reached when both Step1 and
   Step2 bail.

5. `userspace-dp/src/afxdp/cos/cross_binding.rs:69` — the bail
   condition for shared_exact is `queue_fast.shared_exact &&
   iface_fast.tx_owner_live.is_some()`. So for `shared_exact=true`
   queues without a tx_owner_live on the interface, Step1 STILL
   routes to owner. The shared-exact escape only fires when the
   interface itself has an owner binding that differs.

The iperf-uncapped queue (`exact=false`, `guarantee_enabled=false`):
- Hits the `!queue.exact` early-return in
  `queue_uses_shared_exact_service` → `shared_exact = false`
- Gets one `owner_worker_id` via the round-robin in
  `build_cos_owner_by_queue` (line 901)
- Cross-binding redirect routes 100% of class-11 traffic to that
  one worker → that worker's AF_XDP UMEM ceiling (~6-10 Gbps per
  the [[feedback_cross_binding_impossible]] memory entry) is the
  hard cap

This explains the symptom exactly: P=12 push on port 5211 caps at
~10 Gbps because every stream's class-11 packets are funneled to a
single worker that cannot push faster than one AF_XDP UMEM allows.

### Why this didn't show up for the 24g class (queue 10)

`scheduler-24g` is `transmit-rate 24g exact`. `guarantee_enabled=true`,
`exact=true`, `transmit_rate_bytes = 3 GB/s = 24 Gbps`. At 24 Gbps
the `queue_uses_shared_exact_service` gate fires (rate >= 312 MB/s),
the queue runs `shared_exact=true`, and each worker drains its own
portion of class-10 traffic locally — no single-owner funnel.

Same for any exact queue at or above 2.5 Gbps. The funnel collapse
only happens for queues that escape the `shared_exact` regime.

### Why this didn't show up for the 100m / 1g / 3g classes

`scheduler-100m`, `scheduler-1g`, `scheduler-3g` are below the
2.5 Gbps `COS_SHARED_EXACT_MIN_RATE_BYTES` threshold. They are
single-owner by design — see the PR #690 / #680 history note in
`worker/cos/mod.rs:98-118`. The single-owner funnel was the
deliberate choice for low-rate exact queues so they have one FIFO
arbitration domain. At 100m or 1g the per-worker AF_XDP UMEM cap
(~6-10 Gbps) is well above the configured shape rate, so the
funnel is invisible — the shape rate is the binding constraint,
not the UMEM ceiling.

The bug only surfaces when a non-shared-exact queue's *real*
desired rate exceeds the per-worker UMEM ceiling. That's exactly
the iperf-uncapped case.

## Proposed fix

Extend the shared-exact treatment to non-exact queues whose
effective rate also exceeds `COS_SHARED_EXACT_MIN_RATE_BYTES`.
Concretely, change `queue_uses_shared_exact_service` in
`userspace-dp/src/afxdp/worker/cos/mod.rs` from

```rust
fn queue_uses_shared_exact_service(_iface: &CoSInterfaceConfig, queue: &CoSQueueConfig) -> bool {
    if !queue.exact {
        return false;
    }
    queue.transmit_rate_bytes >= COS_SHARED_EXACT_MIN_RATE_BYTES
}
```

to also admit non-exact queues whose effective rate (the residual
fallback `iface.cos_shaping_rate_bytes_per_sec` when no scheduler
rate is configured) is above the same per-worker UMEM ceiling:

```rust
fn queue_uses_shared_exact_service(_iface: &CoSInterfaceConfig, queue: &CoSQueueConfig) -> bool {
    queue.transmit_rate_bytes >= COS_SHARED_EXACT_MIN_RATE_BYTES
}
```

Behavior change scope:

- **Exact queues**: identical. The gate is unchanged for
  `queue.exact == true`.
- **Non-exact queues with explicit transmit-rate (guarantee_enabled=true)**:
  `transmit_rate_bytes` equals the configured rate. Currently
  rejected by the `!queue.exact` early return; the configured rate
  is what gates whether sharded service is appropriate.
- **Non-exact queues with no transmit-rate (guarantee_enabled=false)**:
  `transmit_rate_bytes` equals the interface shaping rate fallback
  (25 Gbps in this fixture). Trips the threshold → sharded service →
  no single-owner funnel.

Side effect to verify: when `shared_exact=true`, `vtime_floor` /
`shared_queue_lease` / V_min coordination Arcs are normally
allocated only for *exact* queues (see
`build_shared_cos_queue_leases_reusing_existing` filter at
coordinator/mod.rs:1058: `if !queue.exact || queue.transmit_rate_bytes == 0 { continue; }`).
Non-exact queues never get these structures, so the only effect of
flipping `shared_exact=true` for them is to skip the single-owner
funnel in the cross-binding redirect path. The exact-specific
mechanisms (V_min synchronization, per-queue lease) are still
gated on `queue.exact == true` and remain untouched.

Need to also verify: the `Step1` bail condition at
`cross_binding.rs:69` includes `iface_fast.tx_owner_live.is_some()`.
If the interface still has a tx_owner_live set, Step2 will still
funnel. The current logic establishes tx_owner_live from
`tx_owner_live_by_tx_ifindex`. We must trace whether non-exact
queues being shared_exact actually leaves tx_owner_live unset (i.e.,
the bug is fixed) or whether we also need to teach the cross-binding
decision to honor non-exact-shared-exact as a Step1 + Step2 bail.

## Public API preservation

- `queue_uses_shared_exact_service` signature unchanged.
- `WorkerCoSQueueFastPath.shared_exact` semantics unchanged
  (still "this queue runs sharded across workers"); the population
  rule for non-exact queues changes.
- No protocol changes. No control-socket changes. No Go-side changes.

## Hidden invariants the change must preserve

- **Per-class rate enforcement on exact queues**: exact queues retain
  their `transmit_rate_bytes` cap via `shared_queue_lease`. Non-exact
  queues never have a `shared_queue_lease` (filter at
  coordinator/mod.rs:1058), so no leak path.
- **Surplus-sharing semantics for exact queues**: exact-with-surplus
  queues still consume from root tokens. Non-exact queues already
  consume residual-only and that doesn't change.
- **Shaping-rate cap**: the SharedCoSRootLease at the interface root
  is still 25 Gbps total across all `active_shards` workers. The fix
  doesn't change the root cap; it changes which worker enqueues the
  packet for the first time, not how the parent shaper enforces its
  rate.
- **Side-effect ordering**: packets within one queue from one worker
  stay FIFO (local enqueue, local drain). Cross-worker ordering for
  the same TCP 5-tuple is preserved because RSS pins each 5-tuple
  to one worker — same as today's `shared_exact=true` regime for
  high-rate exact queues.
- **Burst sizing**: the per-queue `buffer_bytes` continues to bound
  how much one worker can backlog locally; unchanged.

## Risk assessment

| Class | Level | Note |
|-------|-------|------|
| Behavioral regression risk | MEDIUM | The threshold flip changes routing for non-exact queues; must verify other classes (5202-5210) hit their configured rates. |
| Lifetime / borrow risk | LOW | One-line predicate change, no new types or Arc clones. |
| Performance regression risk | LOW | Removes a funnel; only path that gets slower is `shared_exact=true` workers losing one extra cross-binding hop for a no-op case (already taken by exact queues). |
| Architectural mismatch risk | LOW | Same mechanism #680/#690 already established for exact queues; we're admitting non-exact queues into the same regime. |

## Test plan

1. cargo build clean.
2. cargo test --release: must stay green (952+ tests).
3. cargo test 5/5 on every CoS test that mentions `shared_exact`,
   `queue_uses_shared_exact_service`, or `owner_worker`.
4. Go test suite: 30 packages must stay green.
5. Smoke matrix on `loss:xpf-userspace-fw0/fw1`:
   - Pass A: CoS disabled — `iperf3 -P 12 -t 10` v4 + v6 push and
     reverse → expect line rate (22+ Gbps), 0 retrans. Confirms no
     fast-path regression.
   - Pass B: CoS enabled — per-port push direction P=12 on every
     port 5201-5211:
     - 5201 (iperf-100m): hit shape rate, 0 retrans.
     - 5202-5209 (iperf-1g .. iperf-21g): hit configured rate, 0 retrans.
     - 5210 (iperf-24g): hit 24 Gbps (or interface-shaping-bound).
     - 5211 (iperf-uncapped): hit ≥22 Gbps. THIS is the bug we're fixing.
   - `make test-failover` must pass — the fix touches no HA / VRRP /
     session-sync code, but the CoS runtime structures are shared with
     the cluster path and we verify no regression on HA.

## Out of scope (explicitly)

- We do NOT change how exact queues' rates are enforced.
- We do NOT touch `transmit-rate exact` semantics.
- We do NOT touch flow_fair / SFQ admission.
- We do NOT touch the per-binding UMEM cap (it's a kernel/hardware
  property, not a code property).
- We do NOT touch the `shared_queue_lease` / `vtime_floor` allocation
  filter — non-exact queues continue to skip those.
- We do NOT harden `resolve_local_routing_decision` against the
  hypothetical non-binding-worker case (Step1 bail without
  `tx_owner_live.is_some()` for `shared_exact=true` queues). The
  current loss userspace cluster has every worker bound to the
  egress's tx_ifindex, so the threshold flip is sufficient. If a
  future topology breaks that assumption, a follow-up PR can
  un-gate the Step1 bail.

## Round-1 review outcomes (preserved before re-dispatch)

### Codex round 1 (task-mpnbg9oh-c7q5iu): PLAN-KILL (infra-blocked)

Codex reported its sandbox runner was missing and could not perform
verified file reads. Based on the supplied plan facts alone it would
PLAN-KILL because the plan's open-question §2 left the Step2
`tx_owner_live` funnel unresolved at file:line. Codex did not have
access to walk the actual code that resolves the concern.

### AGY round 1 (review-mpnbgnt3-l6tlm1): PLAN-READY

AGY walked the actual files at the commit and verified every claim
in the root-cause analysis. The key clarification on the Step2
`tx_owner_live` question:

* `tx_owner_live_by_tx_ifindex` is populated **per-worker, locally**
  inside `userspace-dp/src/afxdp/worker/loop_body/mod.rs:91-95` by
  iterating ONLY this worker's own bindings:
  `bindings.iter().map(|b| (b.ifindex, b.live.clone()))`.
* Consequently `iface_fast.tx_owner_live` is either `None` (worker
  has no binding on the egress's tx_ifindex) or `Some(self.live)`
  (worker is bound to that interface). In the latter case
  `Arc::ptr_eq(owner_live, current_live)` is `true`, so `step2`
  evaluates to `None`.
* Step2 NEVER funnels to a foreign worker. Only Step1's
  `owner_worker_id` clause funnels.

### Residual concern from round 1: non-binding workers

For workers WITHOUT a binding on the egress's tx_ifindex,
`tx_owner_live = None`, so the Step1 bail clause
`shared_exact && tx_owner_live.is_some()` is false (second AND
operand fails). Such workers would still route to `owner_worker_id`
even after the threshold flip, re-creating the funnel.

The loss userspace cluster (`loss:xpf-userspace-fw0/fw1`) has every
worker bound to reth0.80's underlying mlx5 VF tx_ifindex (one binding
per worker per RSS queue), so this concern doesn't apply to the
target cluster. But the general fix surface is still
`queue_uses_shared_exact_service` — flipping `shared_exact=true` for
the uncapped class fires the Step1 bail on every worker that has a
binding on the egress, which is every worker in the production loss
cluster.

If a future deployment had non-binding workers (e.g., a worker that
serves a different ingress NIC and only redirects to this egress), a
follow-up patch may be needed to bail Step1 in
`resolve_local_routing_decision` based on `shared_exact` alone (not
gated on `tx_owner_live.is_some()`). That hardening is out of scope
for this PR — see "Out of scope" below.

## Open questions for adversarial review

1. **Is the threshold flip the right fix surface?** Could the same
   effect be achieved less invasively by skipping cross-binding for
   non-exact queues directly in `resolve_local_routing_decision` —
   for example, return Step1=None, Step2=None when the queue is
   non-exact AND `transmit_rate_bytes` equals the interface fallback
   rate? Verify which surface preserves more invariants.

2. **Does the `tx_owner_live` Step2 path still funnel?** Step2 routes
   to `iface_fast.tx_owner_live` when set, independent of the
   queue's `shared_exact` flag. If the interface itself has a
   tx_owner_live set, the fix at `queue_uses_shared_exact_service`
   alone may not be enough — we need to also bail Step2 for
   uncapped non-exact queues. Trace and confirm.

3. **What is `tx_owner_live` for the test cluster?** On the loss
   userspace cluster, reth0.80 is the egress interface. Does that
   interface have a tx_owner_live set in the runtime configuration?
   If yes, Step2 funnels regardless of `shared_exact`. The fix must
   handle that.

4. **Does the parent SharedCoSRootLease still enforce the 25g shape?**
   When all workers drain locally, each consumes from the same
   `SharedCoSRootLease`. The shared lease is sized at full 25 Gbps
   and the workers compete for tokens via CAS. Verify that this still
   correctly enforces the parent shape and doesn't allow N workers to
   each draw 25 Gbps of tokens.

5. **Does the per-class rate enforcement on classes 5201-5210
   regress?** For exact queues (5201-5210), the gate behavior is
   unchanged. But the residual-rate computation
   (`nonexact_surplus_budget_under_exact_demand` at
   queue_service/mod.rs:339-367) returns a SHARED budget for
   non-exact surplus. With non-exact uncapped queue now sharded
   across N workers, does the residual budget get N× consumption?
   This needs explicit modeling — the residual budget is the
   ONLY mechanism preventing class-11 from starving classes
   5201-5210 when those exact queues are also backlogged.

6. **Should the fix make the threshold a tunable?** The current
   2.5 Gbps threshold is hardcoded; the value comes from PR #680
   experiments. The fix extends that threshold to a new class of
   queues — is 2.5 Gbps still the right number when a non-exact
   queue can have effective_rate = 25 Gbps (interface shaping)?

7. **Stale-handle hazard.** When a non-exact queue's owner changes
   from single-owner to shared (config reload), are any of the
   queue runtimes / live state Arcs stale? Trace the
   `reset_binding_cos_runtime` path to confirm.
