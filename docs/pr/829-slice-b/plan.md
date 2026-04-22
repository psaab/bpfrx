# Issue #829 — Plan: cross-worker virtual-time gate for shared_exact CoS queues (#786 Slice B)

> **Status.** Architect R3 (post-Codex R2 cycle: 3 HIGH + 1 MED).
> R3 switches from per-worker slots to **per-binding slots**
> (sidesteps R2 HIGH-2 multi-binding semantics and HIGH-3
> non-dense worker_id), restates the fairness bound as
> `T + max_batch_advance` (R2 HIGH-1), and moves the bring-up
> seed from `build_cos_interface_runtime` into
> `apply_cos_queue_flow_fair_promotion` where the lease IS in
> scope (R2 MED-1).

## 1. Goal

Per-stream throughput on `shared_exact` CoS queues should converge
to fair shares regardless of which worker dispatches a given
flow's packets. Pre-registered acceptance: per-stream CoV ≤ 15%
on `iperf-a` (1 Gbps) AND `iperf-b` (10 Gbps), no aggregate
throughput regression below 95% of baseline, no retransmit
increase.

## 2. Non-goals

- AFD overlay (#786 Slice C) — separate issue.
- RSS++ dynamic indirection (#786 Slice D) — deferred.
- Single-owner exact queues — fair by construction.
- Non-`flow_fair` shared_exact queues — gate is wired only into
  the `flow_fair` drain selection path.
- Per-queue dynamic T_bytes auto-tuning — initial pass uses one
  operator-tunable constant.
- Cross-host (HA peer) coordination — out of scope.
- Worker-count > 8 scalability — current target is N ∈ {1, 4, 8};
  larger N may need sharded reduction (research doc §2.1, future
  PR).

## 3. Files

### 3.1 New files

- `docs/pr/829-slice-b/plan.md` — this file.
- `docs/pr/829-slice-b/codex-plan-review.md` — review trail.
- `docs/pr/829-slice-b/codex-code-review.md` — review trail.
- `docs/pr/829-slice-b/rust-code-review.md` — second-angle review.
- `docs/pr/829-slice-b/findings.md` — fairness re-measurement
  results.

### 3.2 Existing files touched

- `userspace-dp/src/afxdp/types.rs`
  - Extend `SharedCoSQueueLease` with a `binding_frontiers:
    Box<[CachePadded<AtomicU64>; MAX_BINDINGS_PER_LEASE]>`. Each
    slot is owned by one binding (single-writer per slot).
    Init `u64::MAX` ("this slot's binding has nothing pending or
    no binding has registered this slot yet"). Constant
    `MAX_BINDINGS_PER_LEASE = 64` — comfortable headroom over
    typical 4-12 worker × few-bindings-per-worker scale, ~4 KB
    per lease (negligible).
  - New helper `SharedCoSQueueLease::register_binding(&self) ->
    Option<u32>`: atomic-fetch-add of a `next_slot: AtomicU32`,
    returns the slot index for this binding to use. Returns
    `None` if `MAX_BINDINGS_PER_LEASE` exhausted (counts in a
    new `register_overflow: AtomicU64` for observability + the
    binding falls back to "no gate" mode for this lease).
  - New helper `SharedCoSQueueLease::publish_binding_frontier(slot:
    u32, v_local: u64)`: `Release` store of `v_local` into the
    binding's slot.
  - New helper `SharedCoSQueueLease::mark_binding_idle(slot: u32)`:
    `Release` store of `u64::MAX` into the binding's slot.
  - New helper `SharedCoSQueueLease::current_min_frontier() ->
    u64`: iterate the active prefix `[0..next_slot.load()]` with
    `Acquire` loads, return min; if all `u64::MAX`, return
    `u64::MAX` (sentinel "no active bindings other than self").

- `userspace-dp/src/afxdp/tx.rs`
  - In `select_exact_cos_guarantee_queue_with_fast_path` (line
    1717), insert the lag-gate check inside the per-queue loop
    AFTER `cos_queue_is_empty()`/`runnable`/`exact` checks (~line
    1730) and BEFORE `maybe_top_up_cos_queue_lease` (line 1733).
    If lag exceeds T, `continue` to the next queue (skip without
    touching this queue's lease tokens).
  - Same insert in the corresponding code path for non-fast-path
    selection (audit any siblings of `select_exact_cos_guarantee_queue`).
  - In `drain_exact_local_items_to_scratch_flow_fair` (~line 2602)
    and `drain_exact_prepared_items_to_scratch_flow_fair`
    (~line 2780): AFTER the dispatch batch, call
    `lease.publish_binding_frontier(queue.frontier_slot,
    queue.queue_vtime)`. If `cos_queue_is_empty(queue)`, instead
    call `mark_binding_idle(queue.frontier_slot)` (idle so this
    binding's slot doesn't pin the cross-binding min).
  - On binding shutdown / runtime teardown: call
    `mark_binding_idle(queue.frontier_slot)` so no stale frontier
    pins v_min permanently.
  - Add const `COS_CROSS_BINDING_LAG_LIMIT_BYTES`. Default value
    justified in §4.4.

- `userspace-dp/src/afxdp/tx.rs::apply_cos_queue_flow_fair_promotion`
  (called immediately after `build_cos_interface_runtime` from
  `ensure_cos_interface_runtime` at line 5283) — this is the
  bring-up hook (R2 MED-1 fix; moved from `build_cos_interface_runtime`
  per Codex which lacks lease access). For each queue whose
  `iface_fast.queue_fast_path[idx].shared_queue_lease` is
  `Some(lease)` AND `flow_fair`:
  1. Call `lease.register_binding()` to obtain a `frontier_slot`.
  2. Store `frontier_slot` on the new `CoSQueueRuntime`.
  3. Seed `queue.queue_vtime = lease.current_min_frontier()` if
     non-MAX, else leave `queue_vtime = 0`.
  This prevents a freshly-built binding from yielding
  indefinitely while peer bindings are advanced. Add a
  `frontier_slot: Option<u32>` field on `CoSQueueRuntime` (None
  for non-shared / non-flow-fair queues, Some(slot) for the
  gated queues).

### 3.3 Explicitly not touched

- Wire format / protocol — no new RPC, no new status fields.
- Go daemon side. Pure Rust dataplane change.
- BPF / xdp / tc programs.
- Single-owner exact path.
- Non-flow_fair (FIFO) drains on shared_exact queues.

## 4. Algorithm

### 4.1 State

Per `SharedCoSQueueLease` (one Arc shared across all bindings):

- `binding_frontiers: Box<[CachePadded<AtomicU64>; MAX_BINDINGS_PER_LEASE]>`
  — fixed-size 64-slot array. Each slot owned by exactly one
  binding (single-writer-per-slot is guaranteed by the
  one-time `register_binding` slot assignment). Init `u64::MAX`.
- `next_slot: AtomicU32` — slot allocator cursor.
- `register_overflow: AtomicU64` — observability counter for
  bindings that requested a slot after the array was full.

Per `CoSQueueRuntime`:

- Existing `queue_vtime: u64` is the per-binding WFQ frontier
  (this binding's `v_local`).
- New `frontier_slot: Option<u32>` — the lease slot index this
  binding writes to. `None` for non-shared or non-flow-fair
  queues (gate disabled). `Some(slot)` for shared_exact +
  flow_fair queues, assigned at `apply_cos_queue_flow_fair_promotion`.

This sidesteps R2 HIGH-2's multi-binding-per-worker problem:
each binding has its own slot and writes only its own
`queue_vtime`. Two bindings on the same worker → two distinct
slots → no slot is overwritten by an unrelated binding. It also
sidesteps R2 HIGH-3's non-dense `worker_id`: slots are dense
within the lease (assigned via `register_binding` fetch-add).

### 4.2 Drain-loop integration

**Gate (in queue selection, BEFORE lease top-up — HIGH-3 fix):**

```rust
// inside select_exact_cos_guarantee_queue_with_fast_path's
// per-queue loop, after cos_queue_is_empty/runnable/exact checks:
if let Some(slot) = queue.frontier_slot {
    if let Some(lease) = queue_fast_path
        .get(queue_idx)
        .and_then(|qfp| qfp.shared_queue_lease.as_ref())
    {
        let v_local = queue.queue_vtime;
        let v_min   = lease.current_min_frontier();
        // v_min == u64::MAX means "no other binding is active on
        // this lease" → no gate, fall through to dispatch.
        if v_min < u64::MAX {
            let lag = v_local.saturating_sub(v_min);
            if lag > COS_CROSS_BINDING_LAG_LIMIT_BYTES {
                count_park_reason(root, queue_idx,
                    ParkReason::CrossBindingLag);  // new variant
                continue;  // skip this queue — no lease tokens taken
            }
        }
        let _ = slot;  // slot is used in the publish path below
    }
}
maybe_top_up_cos_queue_lease(...);  // EXISTING line 1733
```

**Publish (in drain, AFTER dispatch batch):**

```rust
// at end of drain_exact_local_items_to_scratch_flow_fair (and
// drain_exact_prepared_items_to_scratch_flow_fair):
if let Some(slot) = queue.frontier_slot {
    if let Some(lease) = lease_for_this_queue {
        if cos_queue_is_empty(queue) {
            lease.mark_binding_idle(slot);
        } else {
            lease.publish_binding_frontier(slot, queue.queue_vtime);
        }
    }
}
```

### 4.3 Correctness & liveness

- **Frontier rises (R1 HIGH-1 fix).** `current_min_frontier()` is
  computed fresh on every gate-check by reducing across active
  binding slots. As slow bindings dispatch and update their
  slots, the min rises. As bindings go idle
  (`mark_binding_idle` → u64::MAX), they drop out of the min.
- **Fairness bound (R2 HIGH-1 restated; R3-4 invariant pin).**
  The exact bound is `spread ≤ T + max_batch_advance`, NOT
  `spread ≤ T`. Per `cos_guarantee_quantum_bytes` at
  tx.rs:3894-3901, `max_batch_advance ≤
  COS_GUARANTEE_QUANTUM_MAX_BYTES = 512 KB`. So worst-case
  transient spread = T + 512 KB.
  **Loop-structural invariant (load-bearing for the bound).**
  The worker poll loop (worker.rs:1180-1315) drains AT MOST
  ONE binding per lease per poll iteration. If a future
  refactor batches multiple drains in one tick, the bound
  becomes `T + N × 512 KB`. Test #26 pins this invariant; a
  refactor that breaks it must re-derive T.
  **Steady-state time-averaged spread ≈ T** because the fast
  binding yields its NEXT batch as soon as the gate fires. We
  size T against fair-share over the iperf3 test window, not
  against any single batch.
- **Single-binding degenerate case.** Lease has 1 binding → that
  binding's slot is the only non-MAX slot; `current_min_frontier`
  returns its own value; `lag = 0`; gate never fires.
- **Bring-up (R2 MED-1 fix).** New binding's `frontier_slot` is
  registered in `apply_cos_queue_flow_fair_promotion`; its
  `queue_vtime` is seeded to `current_min_frontier()` (or 0 if
  the lease has no other active bindings). First drain sees
  `lag = 0` rather than `lag = v_min`.
- **Slot exhaustion.** If `register_binding` returns `None`
  (more than 64 bindings on one lease), that binding sets
  `frontier_slot = None` and the gate is disabled for it
  (degraded fairness for that binding only). `register_overflow`
  counter surfaces this for ops alerting.
  **Churn assumption (R3-2 documented).** Production interface
  churn is observed at <100 events / daemon lifetime (per HA
  failover + occasional config commits). 64 slots gives ~64x
  headroom on the typical lease binding count of 4-12. Slot
  reclamation on binding teardown is out of scope; the
  `register_overflow > 0` counter triggers an ops follow-up
  PR if hit.

### 4.4 T_bytes sizing (MED-2 fix)

Per #786 Slice B initial: `T = 2 × per_flow_BDP(queue_rate)`.

For the test environment:
- iperf-a (1 Gbps × 200 µs intra-host RTT) ≈ 25 KB BDP per flow.
  T_target ≈ 50 KB.
- iperf-b (10 Gbps × 200 µs) ≈ 250 KB BDP. T_target ≈ 500 KB.

**Choice of single global default: 64 KB** (the 1 Gbps cell's
target rounded up to a power of two). Rationale: a tighter T at
high rates means more frequent yields, but per-batch advance is
proportional to rate, so the gate-fire frequency in *time* is
roughly constant across rates. Pre-registering the conservative
(low-rate-target) default favours fairness over throughput
headroom on the low-rate cell. The §6.4 sweep confirms.

**Operator override:** `BPFRX_COS_CROSS_BINDING_LAG_BYTES` env
read once at process start in `xpf-userspace-dp::main`. Persisted
in a `OnceLock<u64>` for the gate to read. Sweep target values:
`{16k, 64k, 256k, 1M}`. Note: when sizing T, account for the
restated bound `T + 512 KB` (R2 HIGH-1 fix); steady-state
fairness target T = 64 KB still gives a transient bound of
~576 KB, which is fine for fair-share averaging over 30 s
iperf3 windows.

### 4.5 Memory ordering

- Per-slot writes: `Release` store (worker publishing). Pairs
  with peers' `Acquire` loads in `current_min_frontier`.
- Per-slot reads in `current_min_frontier`: `Acquire`. Stricter
  than strictly necessary for the scalar min itself, BUT future
  refactors may piggy-back per-flow state behind the same
  publish, so the conservative choice is documented and locked
  in. (Per Codex R1 LOW-1: this is "deliberate conservatism" —
  we are not claiming we synchronise other data through it.)
- `u64::MAX` sentinel is a plain store/load — no atomicity
  required across the sentinel boundary because the worker's
  publish/mark-idle pair is serial within the worker.

### 4.6 False sharing isolation (LOW-3 fix)

Each `worker_frontiers[i]` is wrapped in `CachePadded` (existing
`mpsc_inbox::CachePadded` pattern at #715, `#[repr(align(64))]`).
This isolates worker writes onto separate cachelines so
publish-side stores from one worker don't invalidate another
worker's slot. Total memory: `N_workers × 64 B` per shared
lease; for N=4 workers with ~4 shared_exact queues = ~1 KB
per-process overhead. Trivial.

`SharedCoSLeaseState` is left unchanged — `v_min` machinery is
on the `SharedCoSQueueLease` parent struct, not co-located with
`credits`. No size growth on the existing `SharedCoSLeaseState`
hot cacheline.

## 5. Tests

### 5.1 Unit tests in `userspace-dp/src/afxdp/types.rs`

1. `test_lease_binding_frontiers_init_to_max` — fresh lease;
   every slot is `u64::MAX`; `next_slot == 0`.
2. `test_register_binding_returns_dense_slot_indexes` — three
   `register_binding()` calls return `Some(0)`, `Some(1)`,
   `Some(2)`; `next_slot == 3`.
3. `test_register_binding_overflow_returns_none_increments_counter`
   — exhaust MAX_BINDINGS_PER_LEASE; the next call returns
   `None`; `register_overflow == 1`.
4. `test_publish_binding_frontier_writes_slot` — publish(slot=2,
   100); slot 2 == 100, others u64::MAX.
5. `test_current_min_frontier_skips_idle_slots` — publish(0,100),
   publish(2,50); min = 50; slots 1, 3 are u64::MAX so ignored.
6. `test_current_min_frontier_returns_max_when_no_active_slots`
   — fresh lease; current_min_frontier == u64::MAX.
7. `test_current_min_frontier_rises_when_slow_binding_advances`
   — publish(0,100), publish(1,50); min = 50. Then publish(1,
   200); min = 100. R1 HIGH-1 pin (frontier rises).
8. `test_mark_binding_idle_drops_slot` — publish(1,50); min=50.
   `mark_binding_idle(1)`; min reverts to slot 0's value (or
   u64::MAX if no other active).
9. `test_publish_concurrent_two_bindings` — spawn 2 threads each
   calling publish on its own slot 100k times; final min matches
   the smaller of the two final slot values.

### 5.2 Unit tests in `userspace-dp/src/afxdp/tx.rs`

10. `test_select_yields_when_lag_exceeds_limit` — queue with
    `queue_vtime = T + 1`, peer binding's slot = 0; select
    returns next queue (skip), no lease tokens acquired.
11. `test_select_does_not_yield_when_lag_within_limit` —
    `queue_vtime = T - 1`, peer slot = 0; select proceeds.
12. `test_select_does_not_yield_when_alone_on_lease` — this
    binding's slot = self; all other slots u64::MAX;
    `current_min_frontier == u64::MAX` path; no yield even if
    `queue_vtime` is huge.
13. `test_drain_publishes_v_local_after_nonempty_batch` — drain
    advances `queue_vtime` 0 → N, queue still non-empty after;
    binding's slot == N.
14. `test_drain_marks_binding_idle_when_queue_drained_to_empty`
    — drain empties cos_queue; binding's slot == u64::MAX.
15. `test_select_does_not_yield_on_first_drain_with_max_v_min` —
    fresh lease, `queue_vtime = T + 999`; no yield (the only
    active slot is self).
16. `test_yield_path_does_not_consume_lease_credits` — gate
    fires; `queue.tokens` and lease `credits` unchanged from
    pre-gate values. R1 HIGH-3 pin.
17. `test_park_reason_cross_binding_lag_counted` — counter
    incremented on yield; observability pin.

### 5.3 Multi-binding-per-worker tests (R2 HIGH-2 pin)

18. `test_same_worker_multi_binding_each_has_own_slot` — build
    a worker with 2 bindings on the same lease; each binding's
    `frontier_slot` is distinct; each writes only its own slot;
    the other binding's slot is independent.
19. `test_one_binding_idle_does_not_drop_peer_binding_slot` —
    same-worker multi-binding fixture; binding A drains empty
    (mark_binding_idle); binding B's slot is unchanged.
20. `test_two_bindings_synchronise_within_T_plus_batch_advance`
    — two bindings on different workers, sharing a lease, with
    binding A getting twice the dispatch rate of B. After enough
    drain rounds, assert `|v_local_A - v_local_B| ≤ T +
    COS_GUARANTEE_QUANTUM_MAX_BYTES`. Pinning the restated
    bound (R2 HIGH-1).

### 5.4 Bring-up + regression tests

21. `test_bringup_seeds_v_local_to_lease_min_in_promotion` —
    `apply_cos_queue_flow_fair_promotion` invocation on a
    runtime with an existing lease whose other bindings are at
    `v_local = 1_000_000`; the new binding's `queue_vtime` is
    seeded to that value. R2 MED-1 pin.
22. `test_non_shared_queue_unaffected_by_gate` — single-owner
    exact queue (no shared lease); selection + dispatch
    behaviour matches pre-#829.
23. `test_non_flow_fair_shared_queue_unaffected_by_gate` —
    shared lease but FIFO (not flow_fair); gate is disabled
    (`frontier_slot = None`); behaviour matches pre-#829.

### 5.5 Additional R3 pins

24. `test_register_binding_overflow_disables_gate` (R3 finding
    test gap) — exhaust `MAX_BINDINGS_PER_LEASE` registrations;
    next binding gets `frontier_slot = None`; that binding's
    `select_exact_cos_guarantee_queue_with_fast_path` proceeds
    without yielding (gate disabled); `register_overflow == 1`.
25. `test_concurrent_registration_returns_unique_slots` —
    spawn N threads all calling `register_binding()` once; each
    gets a distinct slot index in `0..N`; `next_slot == N`. Pins
    the fetch-add allocator under contention (config-reload
    race scenario).
26. `test_single_poll_iteration_drains_one_binding_for_lease` —
    pin the loop-structural invariant that the worker poll loop
    drains AT MOST ONE binding per lease per poll iteration
    (which is what makes the `T + 512 KB` bound hold; per
    R3-4 finding). If future refactors batch multiple drains in
    one tick, this test fails and forces re-derivation of the
    bound.

Target: 26 new tests (vs R3 mid-pass's 23). All pass with `cargo
test -p xpf-userspace-dp`.

Target: 18 new tests. All pass with `cargo test -p xpf-userspace-dp`.

## 6. Validation protocol

### 6.1 Pre-flight

- Confirm cluster on master at PR #828 head.
- Apply canonical `cos-iperf-config.set` via apply-cos-config.sh.
- Sanity-check baseline fairness on the pre-deploy daemon (one
  iperf3 -P 16 -t 30 -p 5202; record per-stream CoV).

### 6.2 Build + deploy

```bash
make build-userspace-dp
sg incus-admin -c "BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
    ./test/incus/cluster-setup.sh deploy all"
```

### 6.3 Re-measurement

```bash
sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
    iperf3 -c 172.16.80.200 -P 16 -t 30 -p 5202 -J" \
    | python3 <inline CoV/Jain analysis>
```

Repeat for port 5201.

### 6.4 T_bytes sweep (only if initial 64 KB fails)

```bash
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- bash -c \
    'systemctl stop xpfd; \
     BPFRX_COS_CROSS_WORKER_LAG_BYTES=16384 \
     /usr/local/sbin/xpf-userspace-dp <args> &'"
# Re-measure; iterate {16k, 64k, 256k, 1M}; record findings.
```

### 6.5 Acceptance criteria

- Per-stream CoV ≤ 15% on BOTH iperf-a (5201) AND iperf-b (5202).
- Aggregate Gbps within ±5% of baseline.
- Per-stream max/min spread ≤ 2× (vs ~5× pre-#829).
- 0 retransmit-count increase from baseline.
- 18 new unit tests pass.
- Existing 760 Rust tests still pass (no regression).
- `make test-failover` passes (CLAUDE.md mandatory for cluster-
  touching changes).

## 7. Workflow

1. Architect R2 (this file).
2. Codex hostile plan review R2 → iterate to PLAN-READY YES.
3. Implement (single PR; tests can be one or many commits).
4. Two-angle code review (Codex behavioral + Rust craftsmanship).
5. Deploy + iperf3 sweep until CoV ≤ 15%.
6. Findings doc → PR → merge → close #829.

## 8. Risks & pre-registered outs

- **R1 — yield rate too high collapses throughput.** Mitigation:
  T_bytes ≥ 2× BDP keeps gate-fire rare; §6.5 acceptance catches
  regression.
- **R2 — `current_min_frontier` reduction cost at scale.**
  O(MAX_BINDINGS_PER_LEASE) = O(64) per gate-check. At realistic
  scale (4-12 active slots) this is a few atomic Acquire loads
  per drain selection — well below the existing per-drain
  bookkeeping cost. At >32 active slots may need sharded
  reduction (research doc §2.1 future work).
- **R3 — false sharing on `binding_frontiers`.** Mitigated by
  per-slot CachePadded wrapper (§4.6). 64 KB per lease for full
  64 slots = trivial vs ~MB-scale UMEM.
- **R4 — bring-up hook timing.** Hook moved to
  `apply_cos_queue_flow_fair_promotion` (R2 MED-1 fix) which is
  called from `ensure_cos_interface_runtime` AFTER
  `iface_fast.queue_fast_path` is fully wired and lease is in
  scope. Test 21 pins.
- **R5 — single-writer-per-slot.** Each binding owns its own
  slot; per-binding poll-loop dispatches are inherently
  serialised within a worker's single thread. No atomicity issue.
  Multi-binding-per-worker case (R2 HIGH-2) handled by
  per-binding slot assignment — bindings never write to each
  other's slots. Tests 18-19 pin.
- **R6 — failover regression.** Non-failover-touching code path,
  but `make test-failover` runs anyway per CLAUDE.md.
- **R7 — env-override race.** `OnceLock` initialised in main
  before any worker spawns. No race.
- **R8 — `make test-failover` regression risk for cross-worker
  state.** New shared atomic state in `SharedCoSQueueLease`
  could deadlock if HA failover races with frontier publication.
  Plan: HA failover triggers binding teardown → `mark_worker_idle`
  on each binding → frontier slot reverts to u64::MAX. Pinned
  by §6.5 `make test-failover` requirement.

## 8a. R3-1 procedural note

Codex R3 finding 1: "slot design is plan-only, single-writer-per-
slot proof cannot be confirmed against actual code, only the
plan's description." This is intrinsic to plan-time review;
we cannot pin design properties against non-existent code.
The R3 plan adds tests #18, #19, #25 that EACH pin a property
of the slot design at implementation time:
- #18 pins per-binding distinct slot ownership.
- #19 pins idle-mark independence.
- #25 pins concurrent registration race-freedom under
  `fetch_add` allocation.
The implementation phase MUST land these tests; if any fail,
the design is wrong and the implementation goes back to plan.

## 9. Open questions for plan review

- **Q1.** R3 design uses fixed-size 64-slot `Box<[...]>`. Acceptable
  given expected scale (4-16 active bindings per lease)? Or grow to
  configurable via env? **Draft:** Fixed 64 is sufficient; doc
  the limit + overflow counter; revisit if `register_overflow > 0`
  in production.
- **Q2.** R3 bring-up seed equals `current_min_frontier()` exactly.
  Equality case (`lag = 0`) does not yield — verified §4.3.
  Confirmed safe.
- **Q3.** Slot reclamation on binding teardown. R3 plan does NOT
  reclaim slots — when a binding is destroyed, its slot stays
  at `u64::MAX` forever (slot is "leaked" until process restart).
  Consequence: a long-lived process with config churn could
  exhaust the 64-slot budget. **Draft:** Acceptable for now;
  config churn is rare; the overflow counter surfaces the case;
  follow-up PR can add slot reclamation if needed in production.
