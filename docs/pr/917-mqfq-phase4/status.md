# #917 status — pickup notes

Last touched: 2026-04-27. Use this doc to resume work without
re-reading the conversation log.

## Goal

Per-flow Gbps should be EVEN across all flows in the same
iperf class (= per-flow CoV ≤ 20 %, the historical #785 / #789
gate). Currently failing at iperf-c P=12 (CoV 35–68 %), close
at iperf-c P=128 (CoV 22.9 %).

## What landed

| PR | Issue | What it does |
|---|---|---|
| #930 | #920 | RX/TX_BATCH_SIZE 256 → 64 (L1d residency + mouse HOL) |
| #931 | #914 | rate-aware shared_exact admission cap |
| #932 | #929 | same-class iperf-b mouse-latency harness |
| #933 | #918 | 4-way set-associative flow cache w/ LRU |
| #934 | #927 | MQFQ drained-bucket orphan-cleanup served_finish preserve |
| #935 | #926 | demote_prepared queue MQFQ frontier preservation |

All on master. Cluster was last deployed BEFORE #927 and #926
merged; redeploy + remeasure is the immediate next step.

## What's not done

- **#917 V_min cross-worker sync** — plan v3 PLAN-READY YES
  (Codex R4 + Gemini R3); Phase 1 implementation (types + Arc
  helpers) on `sprint/917-mqfq-phase4`, NOT pushed. Phases 2–5
  remaining: lifecycle wiring, publish/read hooks, throttle
  action, telemetry, tests.

- **#899 cross-binding flow re-steering** — open issue. The
  architectural lever for moving flows OFF an idle RSS worker
  ONTO a busy one. Project memory currently flags this as
  "impossible due to AF_XDP UMEM ownership". The diagnostic
  below shows it is the only path to even per-flow CoV when
  RSS gives at least one worker zero flows.

## Diagnostic findings

(Full data: `docs/pr/917-mqfq-phase4/diagnostic.md`.)

The bottleneck for "even flows at iperf-c P=12" is **RSS
hashing flow-to-worker mapping**. Measured one run: 12 source
ports → workers 0/2/2/2/3/3. Worker 0 sat idle for the full
20 s; worker 5 carried 27 % of the traffic. **Per-worker CoV
56.1 %** at P=12 vs 9.2 % at P=128.

What this means for the fairness levers:

- **#917 V_min sync** (per-flow CoV across non-idle workers) —
  helps when all workers have ≥ 1 flow. With one worker fully
  idle, V_min reduction skips that worker (per
  `read_v_min` in types.rs Phase 1) so it doesn't peg the floor
  at 0 — but it also can't move flows to that worker. So #917
  improves the 2-flow-worker vs 3-flow-worker disparity but
  CANNOT lift the aggregate ceiling.

- **#899 cross-binding redirect** (move flows) — would let an
  idle worker pick up flows that RSS sent to a busy one.
  **The only path to even flows in the field-degenerate
  scenario.** Currently labeled "impossible" in project
  memory; needs an architectural revisit.

What gates #917 cluster-validate gates:
- Non-degenerate RSS (every worker has ≥ 1 flow): #785 22 Gbps
  + 20 % CoV gate. Plausibly clearable.
- Degenerate RSS (one worker idle): no-regression bar only.
  Aggregate ceiling stays at `(N_active / N_total) × shaper_rate`.

## Remeasure first

Before committing more time to #917 / #899, redeploy current
master (which now has #927+#926, both touching MQFQ vtime
arithmetic) to the userspace cluster and remeasure. The
prior cluster smoke was on `sprint/combined-validation` from
BEFORE those two merged. #927 fixes drained-bucket vtime
loss; #926 fixes demote-path vtime inflation. Either could
material-move CoV.

Suggested measurement matrix:

```bash
# Redeploy first
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all

# Apply cross-class CoS
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0

# Sweep
for p in 12 32 64 128; do
  sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
    iperf3 -c 172.16.80.200 -p 5203 -P $p -t 30 -J" \
    > /tmp/post-927-926-iperf-$p.json
done
```

Per-flow CoV is the load-bearing metric. Pull from
`end.streams[*].receiver.bits_per_second` and compute stdev /
mean.

## Pickup checklist

When resuming this work:

- [ ] Read `docs/pr/917-mqfq-phase4/diagnostic.md` for the
      empirical context.
- [ ] Read `docs/pr/917-mqfq-phase4/plan.md` v3.1 for the
      design (Codex R4 + Gemini R3 PLAN-READY YES).
- [ ] Check `sprint/917-mqfq-phase4` for Phase 1 (types).
      Phase 2-5 remaining.
- [ ] **First action: redeploy current master and remeasure**
      to see if #927+#926 alone moved the per-flow CoV.
      If CoV ≤ 20 % already, we're done.
- [ ] If not done: weigh #917 implementation (helps non-
      degenerate RSS) vs revisiting #899 feasibility (the
      actual ceiling-lifter).

## Phase 2a complete (committed)

`vtime_floor: Option<Arc<SharedCoSQueueVtimeFloor>>` field
added to `WorkerCoSQueueFastPath` (types.rs). Defaults to
`None` at all four initializer sites:

- `worker.rs:1734` (production builder)
- `frame_tx.rs:1536` (test scaffolding)
- `tx.rs:6824` (test helper `make_queue_fast_path_for_test`)
- `tx.rs:15758` (test helper `test_queue_fast_path_for_promotion`)

Build clean; 780/780 tests pass. The field is dormant —
no allocator, no caller reads it. Functionally equivalent
to before Phase 2a.

## Phase 2b remaining

The actual lifecycle wiring:

- New `shared_cos_queue_vtime_floors: Arc<ArcSwap<BTreeMap<(i32, u8),
  Arc<SharedCoSQueueVtimeFloor>>>>` field on `ServerState` in
  coordinator.rs (mirror of `shared_cos_queue_leases`).
- New `build_shared_cos_queue_vtime_floors_reusing_existing()`
  function in coordinator.rs (mirror of
  `build_shared_cos_queue_leases_reusing_existing`). Allocates
  one `Arc<SharedCoSQueueVtimeFloor>` per shared_exact queue,
  sized by `num_workers`.
- Thread the map through `build_worker_cos_fast_interfaces`
  in worker.rs (param + 2 caller updates + 3 test caller
  updates). Replace the current `vtime_floor: None` with
  `shared_queue_vtime_floors.get(&queue_key).cloned()`.

Once Phase 2b lands, the Arc is allocated and reaches every
worker's fast-path struct — but no publish/read happens yet.

## Phase 1 details (already on this branch, uncommitted)

`userspace-dp/src/afxdp/types.rs` adds:

- `PaddedVtimeSlot` (`#[repr(align(64))]`, AtomicU64, 56-byte
  pad) — per-worker cache-line-aligned slot.
- `NOT_PARTICIPATING = u64::MAX` sentinel.
- `PaddedVtimeSlot::publish/vacate/read` with explicit
  Release / Acquire memory ordering per plan §3.4.
- `SharedCoSQueueVtimeFloor` struct with `Box<[PaddedVtimeSlot]>`.
- `SharedCoSQueueVtimeFloor::read_v_min(worker_id)` — V_min
  reduction skipping own slot and `NOT_PARTICIPATING` slots.
- `SharedCoSQueueVtimeFloor::participating_peer_count(worker_id)` —
  for plan §3.5 LAG_THRESHOLD scaling.

No callers wired yet. `cargo build --release` clean (5 new
"unused" warnings expected).

## Phase 2-5 remaining work

Per plan v3.1 §3.7 / §5:

**Phase 2 — Lifecycle**:
- Add `vtime_floor: Option<Arc<SharedCoSQueueVtimeFloor>>` to
  `WorkerCoSQueueFastPath` next to `shared_queue_lease`.
- Allocate Arc on shared_exact promotion (in coordinator.rs);
  drop on demotion.
- Add `drain_enabled: AtomicBool` for HA-shutdown signal
  (per §3.7 v3 worker-self-vacate ordering).
- HA demotion path clears `drain_enabled` Release; worker
  drain entry checks Acquire and self-vacates on exit.

**Phase 3 — Publish path** (plan §3.2):
- Hook `floor.slots[worker_id].publish(queue.queue_vtime)` at
  the commit boundary in
  `cos_queue_clear_orphan_snapshot_after_drop` (after the
  same-bucket frontier clamp #927 added).
- Hook same publish at the no-snapshot pop site
  (`cos_queue_pop_front_no_snapshot`) since that path commits
  inline.
- Hook publish in `cos_queue_push_front` AFTER the rollback
  vtime restore — peers must see the rolled-back value.
- Vacate slot when bucket count for this worker on this queue
  transitions ≥1 → 0.

**Phase 4 — Read path + throttle** (plan §3.3, §3.5, §3.6):
- New helper `maybe_check_v_min` per the §3.3 v2 pseudocode.
  K = 8 cadence + mandatory check at drain-batch start.
- LAG_THRESHOLD computed at read time:
  `per_worker_rate × 1ms` where
  `per_worker_rate = transmit_rate_bytes / (participating + 1)`.
- Throttle action: park queue for one timer-wheel tick
  (50 µs) if `queue_vtime > v_min + LAG_THRESHOLD`. Hard cap 8
  consecutive reparks to bound mouse-latency tail at 400 µs
  (per §3.6 v3).

**Phase 5 — Telemetry + tests**:
- Plumb `flow_cache_v_min_throttles` (or
  `mqfq_v_min_throttles` — pick) end-to-end through umem.rs
  → BindingStatus → BindingCountersSnapshot → Go protocol.go.
  Same pipeline as #918's `flow_cache_collision_evictions`
  reference.
- Unit tests per plan §6.1:
  - `v_min_throttle_skips_when_local_vtime_exceeds_threshold`
  - `v_min_throttle_releases_when_peer_advances`
  - `v_min_idle_worker_does_not_throttle_peers`
  - `v_min_lag_threshold_scales_with_queue_rate`
- Cluster validation per plan §6.4 (split gate non-degenerate
  vs degenerate), §6.5 mouse-latency regression, §6.5a
  throttle-window probe.

## File-by-file scope (Phase 2-5)

- `userspace-dp/src/afxdp/types.rs` — already has Phase 1.
  Add `vtime_floor` field on `WorkerCoSQueueFastPath`,
  `drain_enabled: AtomicBool`.
- `userspace-dp/src/afxdp/tx.rs` — publish hooks at three
  sites; new `maybe_check_v_min` helper at `~tx.rs:4400`;
  `cos_park_queue_for_v_min` reusing existing timer-wheel.
- `userspace-dp/src/afxdp/coordinator.rs` — Arc lifecycle on
  promotion/demotion; HA demotion `drain_enabled` clear.
- `userspace-dp/src/afxdp/worker.rs` — pass per-worker
  `worker_id` and `drain_enabled` flag check through to
  scheduling helpers; vacate on drain-loop exit.
- `userspace-dp/src/afxdp/umem.rs` — new
  `flow_cache_v_min_throttles` AtomicU64 on
  `BindingLiveCounters`; flush hook in
  `update_binding_debug_state`.
- `userspace-dp/src/protocol.rs` — new wire field on
  `BindingStatus` and `BindingCountersSnapshot`.
- `pkg/dataplane/userspace/protocol.go` — Go-side mirror.
- New unit tests in `tx.rs`.
