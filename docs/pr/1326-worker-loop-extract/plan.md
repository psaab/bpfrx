# #1326 — Extract worker_loop body into worker/loop_body/

**Status:** DRAFT v2 — addressing AGY r1 PLAN-NEEDS-MAJOR findings

### v1→v2 changelog

AGY r1 (review-mpmurh2n-sfmiks) returned PLAN-NEEDS-MAJOR with 4
action items. v2 addresses all four:

1. **Borrow-shape barrier removed.** Phase fns no longer take
   `&mut LoopState` wholesale. They take only the specific fields
   they touch (e.g. `&mut state.shared_recycles`,
   `&state.binding_lookup`, `&state.forwarding`). LLVM no longer
   has to assume every call mutates all 25 fields. The orchestrator
   is the sole owner of `&mut LoopState`; phase fns get
   field-specific borrows. This particularly matters at the
   non-inlined `poll_drive::drive_one_round` boundary where AGY
   flagged spill-fill risk.

2. **`#[inline]` → `#[inline(always)]`** on hot-path phase wrappers.
   `#[inline]` is only a hint and LLVM can decline at large bodies;
   `inline(always)` guarantees the hot per-tick branch budget.
   Applies to: `tick::arc_refresh`, `tick::commands_drain`,
   `tick::expiry`, `tick::deltas`, `tick::runtime_publish`,
   `idle::handle`.

3. **File tree consolidated** from 10 files to 6. Fold non-polling
   tick sub-phases (arc_refresh + commands + expiry + deltas +
   runtime publish) into a single `tick.rs` module with
   `pub(super) fn` helpers, each `#[inline(always)]`. New tree:
   setup, tick, poll_drive, debug_report, idle, shutdown.
   poll_drive stays non-inlined (too big); debug_report cold; idle
   inlined into orchestrator; shutdown cold post-loop.

4. **runtime.rs discrepancy fixed.** The per-tick runtime-atomics
   publish (#869 wr_counters / wr_state) lives in `tick.rs` as
   `tick::runtime_publish(...)` — it shares LoopState fields with
   the other tick helpers and is part of the same per-tick atomic
   sequence. There is no separate `runtime.rs`.

## Issue framing

`userspace-dp/src/afxdp/worker/mod.rs` is 2635 production LOC, with a
single `worker_loop` function spanning L995-L2273 (~1278 LOC). The
engineering-style modularity gate is: files >2000 LOC trigger refactor,
single fn >200 LOC triggers refactor. Issue #1326 mandates splitting
the long fn body into named per-tick phases under a
`worker/loop_body/` directory module while keeping the signature and
hot-path semantics intact.

This is a continuation of the #959 BindingWorker decomposition pattern
(struct fields already split into 11 sub-files) and the #1189 /
Phase-1 #946 stage-extraction pattern (logical phases get their own
files for perf-top visibility).

## Honest scope/value framing

Win is structural: mod.rs drops from 2635 → ~700-900 prod LOC,
worker_loop becomes a ~250 LOC orchestrator + 6-8 single-responsibility
sub-fns, perf-top finally gets per-phase symbols (currently every
cycle in this 1.3k-LOC fn shows up under a single symbol).

There is no shipped perf gain. This is a maintainability / hot-path
observability refactor.

*If reviewers conclude the perf gain is too small to justify the
churn — and crucially, if reviewers conclude the inliner spill-fill
risk from splitting hot phase-boundaries into separate fns is not
mitigatable — PLAN-KILL is an acceptable verdict.*

## What's already shipped / partially batched

- **#959 (closed)** — BindingWorker fields decomposed into sub-structs
  (telemetry, scratch, cos_state, tx_counters, bpf_maps, timers,
  tx_pipeline, bind_meta, flow_cache_state, xsk_rings). The struct
  is no longer the LOC source — the long fn is.
- **#1188 (merged)** — per-tick Arc short-circuit refresh via
  `load_arc_if_changed` (helper already in mod.rs at L970-L978).
  Plan keeps this helper and references it from `arc_refresh.rs`.
- **#1189 (merged)** — Coordinator decompose Phase 1 established the
  "lift body into named sibling file" pattern.
- **lifecycle.rs already exists** with `poll_binding` — the per-binding
  poll orchestrator. worker_loop calls it from inside its
  `for offset in 0..bindings.len()` loop.

## Concrete design

### File tree (post-split, v2)

```
userspace-dp/src/afxdp/worker/
  mod.rs              # BindingWorker struct + impl{create, identity,
                      #  new_for_cos_drain_test}; XskBindMode + impl;
                      #  SharedGroupBindError + Display/Debug;
                      #  BindingLiveSnapshot, SyncedSessionEntry;
                      #  pub(crate) helpers
                      #  push_recent_exception, push_recent_session_delta;
                      #  shared-binding helpers (partition_binding_plans,
                      #  create_private_binding_from_plan,
                      #  create_shared_binding_group, …);
                      #  inline `mod tests` (kept) — 10 tests
                      #  pub(crate) use loop_body::worker_loop;
                      # Target: ~900-1100 LOC after extraction.
  loop_body/
    mod.rs            # pub(crate) fn worker_loop — top-level structure
                      # ~280-340 LOC: pre-loop init + the
                      # `while !stop.load(...)` orchestration with
                      # delegated phase calls. Defines pub(super)
                      # LoopState. The orchestrator is the sole
                      # holder of &mut LoopState — phase fns borrow
                      # specific fields, never the whole struct.
    setup.rs          # Pre-loop initialization extracted from
                      # L1023-L1228 of today's worker_loop:
                      # validation/forwarding/CoS Arc snapshot,
                      # SessionTable + ScreenState construction,
                      # private/shared binding plan materialization
                      # (returns Vec<BindingWorker>), binding sort,
                      # binding_lookup, cos_owner_live_by_tx_ifindex
                      # build, initial cos_fast_interfaces install
                      # onto every binding, interrupt_poll_fds vector
                      # init, BPF map FD cache, initial cos_status
                      # publish, wr_counters init. Returns
                      # (Vec<BindingWorker>, LoopState).
    tick.rs           # Per-tick helpers (all #[inline(always)]):
                      #   runtime_publish(&mut LoopState fields,
                      #     &Arc<WorkerRuntimeAtomics>, bindings, now_ns)
                      #   arc_refresh(&mut LoopState fields, &mut bindings,
                      #     &shared_*…, &peer_worker_commands,
                      #     &shared_sessions, …, worker_id, now_ns)
                      #   commands_drain(&mut LoopState fields,
                      #     &mut bindings, &commands, ha_runtime,
                      #     &dynamic_neighbors, now_ns)
                      #     → Vec<u64> exported_sequences
                      #   expiry(&mut LoopState fields, &mut bindings,
                      #     &shared_fabrics, now_ns)
                      #   deltas(&mut LoopState fields, &mut bindings,
                      #     &exported_sequences, &cos_status,
                      #     &session_export_ack, &shared_*…, now_ns)
                      # Each helper signature names only the fields it
                      # touches — LLVM gets clean alias info. Includes
                      # the cos_fast_interfaces rebuild block (only
                      # reachable from arc_refresh's flag tally).
    poll_drive.rs     # The `for offset in 0..bindings.len()` loop that
                      # calls `poll_binding` for each binding, plus the
                      # `flush_recorded_filter_counters` call and the
                      # `dbg_poll`→cumulative debug counter merge.
                      # Returns `did_work: bool`. NOT inlined — too
                      # big. Signature takes only the specific
                      # references it needs (&mut bindings,
                      # &mut sessions, &mut screen_state,
                      # &mut shared_recycles, &mut dbg_poll counters,
                      # validation, forwarding, ha_runtime, etc.) —
                      # NOT the whole LoopState. LLVM sees a clean
                      # call boundary.
    debug_report.rs   # The DBG_REPORT_INTERVAL_NS-gated periodic
                      # summary report (today's L1724-L2215). Outer
                      # wrapper `pub(super) fn maybe_emit(...)` is
                      # `#[inline(always)]` and contains only the
                      # elapsed-ns gate. Inner emitter
                      # `fn emit_report(...)` is `#[cold]` and holds
                      # the full body. Includes #802 per-binding
                      # live-state telemetry publish, #878 UMEM
                      # in-flight gauge publish, worker debug-counter
                      # reset, and the worker-runtime publish
                      # block. Stays cold — fires ≤1×/sec.
    idle.rs           # The post-tick idle handling block (today's
                      # L2217-L2260): wr_state classify, spin/sleep/
                      # poll() branches for BusyPoll vs Interrupt
                      # mode. Mutates `idle_iters`, `interrupt_poll_fds`.
                      # Outer `pub(super) fn handle(...)` is
                      # `#[inline(always)]` so the BusyPoll-spin fast
                      # path is inlined into the orchestrator.
    shutdown.rs       # The post-loop shutdown block (today's
                      # L2262-L2272): flush filter counters, release
                      # per-binding CoS leases, final cos_status
                      # republish, heartbeat tombstone.
                      # `#[cold]`.
    tests.rs          # Colocated tests for any new helper logic.
                      # If extraction is pure code-motion no new tests
                      # are required — this file may be omitted;
                      # existing inline tests in mod.rs stay.
```

Total module files: 6 (mod, setup, tick, poll_drive, debug_report,
idle, shutdown — counted excluding optional tests.rs).

### LoopState struct (the avoiding-16-param-fn pattern)

worker_loop has ~20 mutable locals that persist across phases. Passing
them all as `&mut` references through 7+ sub-fn calls every tick would
re-blow the param-count budget. Solution: a non-public typed
`LoopState` struct that lives in `loop_body/mod.rs` and is borrowed
mutably into every phase. Hot-state-only — does NOT hold any
references back to `BindingWorker`s (those are pinned to `&mut bindings`
on the orchestrator stack frame to preserve the existing borrow
shape).

```rust
// In loop_body/mod.rs
pub(super) struct LoopState {
    pub(super) validation: ValidationState,
    pub(super) forwarding: Arc<ForwardingState>,
    pub(super) cos_owner_worker_by_queue: Arc<BTreeMap<(i32, u8), u32>>,
    pub(super) cos_owner_live_by_queue: Arc<BTreeMap<(i32, u8), Arc<BindingLiveState>>>,
    pub(super) cos_shared_root_leases: Arc<BTreeMap<i32, Arc<SharedCoSRootLease>>>,
    pub(super) cos_shared_exact_backlogs: Arc<BTreeMap<i32, Arc<SharedCoSExactBacklog>>>,
    pub(super) cos_shared_queue_leases: Arc<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>,
    pub(super) cos_shared_queue_vtime_floors: Arc<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>,
    pub(super) mirror_targets: Arc<MirrorTargetMap>,
    pub(super) sessions: SessionTable,
    pub(super) screen_state: ScreenState,
    pub(super) binding_lookup: WorkerBindingLookup,
    pub(super) interrupt_poll_fds: Vec<libc::pollfd>,
    pub(super) shared_recycles: Vec<(u32, u64)>,
    pub(super) session_map_fd: i32,
    pub(super) conntrack_v4_fd: i32,
    pub(super) conntrack_v6_fd: i32,
    pub(super) last_ct_refresh_ns: u64,
    pub(super) last_cos_status_ns: u64,
    pub(super) poll_start: usize,
    pub(super) idle_iters: u32,
    pub(super) ha_startup_grace_until_secs: u64,
    // #869 worker runtime telemetry
    pub(super) wr_counters: WorkerRuntimeCounters,
    pub(super) wr_state: WorkerRuntimeState,
    pub(super) wr_last_loop_ns: u64,
    pub(super) wr_last_publish_ns: u64,
    // Debug report cadence + cumulative counters
    pub(super) dbg_last_report_ns: u64,
    pub(super) dbg_rx_total: u64,
    pub(super) dbg_forward_total: u64,
    pub(super) prev_rx_total: u64,
    pub(super) prev_fwd_total: u64,
    pub(super) stall_prev_fwd: u64,
    pub(super) stall_reported: bool,
    #[cfg(feature = "debug-log")]
    pub(super) dbg_counters: DebugCounters,  // bundle of all `dbg_*` cfg counters
}
```

Builder: `setup::initialize_loop_state(&worker_ctx, &mut bindings)`
returns `(Vec<BindingWorker>, LoopState)`.

### Orchestrator (loop_body/mod.rs) — v2 narrow-borrow shape

Every phase fn takes only the LoopState fields it actually mutates +
the orchestrator-local refs (Arc Guards, shared Arcs from the
worker_loop signature). The orchestrator splat-borrows from
`&mut state` at the call site so the compiler can see disjoint
borrows. This is the same pattern the cilium/ebpf hot paths use and
what AGY r1 asked for.

```rust
pub(crate) fn worker_loop(
    /* same 38-param signature as today — unchanged */
) {
    pin_current_thread(worker_id);
    let (mut bindings, mut state) = setup::initialize(
        binding_plans,
        &shared_validation, &shared_forwarding,
        &shared_cos_owner_worker_by_queue,
        &shared_cos_owner_live_by_queue,
        &shared_cos_root_leases, &shared_cos_exact_backlogs,
        &shared_cos_queue_leases, &shared_cos_queue_vtime_floors,
        &shared_mirror_targets,
        worker_id, poll_mode, &cos_status,
    );
    runtime_atomics.set_tid(super::worker_runtime::current_tid());

    while !stop.load(Ordering::Relaxed) {
        let loop_now_ns = monotonic_nanos();
        let loop_now_secs = loop_now_ns / 1_000_000_000;

        // #869 runtime telemetry publish (1s gate inside)
        tick::runtime_publish(
            &mut state.wr_counters,
            &mut state.wr_state,
            &mut state.wr_last_loop_ns,
            &mut state.wr_last_publish_ns,
            &state.sessions,           // for sessions.len()
            &bindings,                 // for cos queue lease counters
            &runtime_atomics,
            loop_now_ns,
        );

        // #1188 Arc short-circuit refresh + cos_fast_interfaces rebuild
        tick::arc_refresh(
            &mut state.validation,
            &mut state.forwarding,
            &mut state.mirror_targets,
            &mut state.cos_owner_worker_by_queue,
            &mut state.cos_owner_live_by_queue,
            &mut state.cos_shared_root_leases,
            &mut state.cos_shared_exact_backlogs,
            &mut state.cos_shared_queue_leases,
            &mut state.cos_shared_queue_vtime_floors,
            &mut state.sessions,
            &mut state.screen_state,
            &mut state.shared_recycles,
            &mut bindings,
            &state.binding_lookup,
            state.session_map_fd,
            state.conntrack_v4_fd,
            state.conntrack_v6_fd,
            &shared_validation, &shared_forwarding,
            &shared_mirror_targets,
            &shared_cos_owner_worker_by_queue,
            &shared_cos_owner_live_by_queue,
            &shared_cos_root_leases,
            &shared_cos_exact_backlogs,
            &shared_cos_queue_leases,
            &shared_cos_queue_vtime_floors,
            &shared_sessions, &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            worker_id, loop_now_ns,
        );

        let ha_runtime = ha_state.load();

        let exported_sequences = tick::commands_drain(
            &mut state.sessions,
            &mut state.shared_recycles,
            &mut bindings,
            &state.binding_lookup,
            &state.forwarding,
            state.session_map_fd,
            state.conntrack_v4_fd,
            state.conntrack_v6_fd,
            &commands,
            ha_runtime.as_ref(),
            &dynamic_neighbors,
            loop_now_ns,
        );

        heartbeat.store(loop_now_ns, Ordering::Relaxed);

        tick::expiry(
            &mut state.sessions,
            &mut state.forwarding,   // for fabric rebuild
            &mut state.last_ct_refresh_ns,
            &mut bindings,
            state.session_map_fd,
            state.conntrack_v4_fd,
            state.conntrack_v6_fd,
            &shared_fabrics,
            loop_now_ns,
        );

        let did_work = poll_drive::drive_one_round(
            &mut bindings,
            &state.binding_lookup,
            &mut state.sessions,
            &mut state.screen_state,
            &mut state.shared_recycles,
            &mut state.poll_start,
            state.validation,
            &state.forwarding,
            &state.mirror_targets,
            state.cos_owner_worker_by_queue.as_ref(),
            state.cos_owner_live_by_queue.as_ref(),
            state.session_map_fd,
            state.conntrack_v4_fd,
            state.conntrack_v6_fd,
            state.ha_startup_grace_until_secs,
            ha_runtime.as_ref(),
            &dynamic_neighbors,
            &shared_sessions, &shared_nat_sessions,
            &shared_forward_wire_sessions, &shared_owner_rg_indexes,
            slow_path.as_ref(),
            event_stream.as_ref(),
            &local_tunnel_deliveries,
            &recent_exceptions, &recent_session_deltas,
            &last_resolution,
            &peer_worker_commands,
            worker_id,
            worker_commands_by_id.as_ref(),
            &dnat_fds,
            &rg_epochs,
            #[cfg(feature = "debug-log")]
            &mut state.dbg_counters,
            &mut state.dbg_rx_total,
            &mut state.dbg_forward_total,
            loop_now_ns, loop_now_secs,
        );

        tick::deltas(
            &mut state.sessions,
            &mut state.last_cos_status_ns,
            &mut state.shared_recycles,
            &mut bindings,
            &state.binding_lookup,
            &state.forwarding,
            state.conntrack_v4_fd, state.conntrack_v6_fd,
            &exported_sequences,
            &cos_status, &session_export_ack,
            &shared_sessions, &shared_nat_sessions,
            &shared_forward_wire_sessions, &shared_owner_rg_indexes,
            &recent_session_deltas, &peer_worker_commands,
            &event_stream,
            loop_now_ns,
        );

        debug_report::maybe_emit(
            &mut state,           // takes &mut state because the cold
                                  // path needs ALL fields — the gate
                                  // is the only fast path and is
                                  // inlined; the body is #[cold] +
                                  // out-of-line so LLVM doesn't have
                                  // to assume the fast path mutates
                                  // anything.
            &mut bindings,
            worker_id, loop_now_ns,
        );

        idle::handle(
            &mut state.idle_iters,
            &mut state.interrupt_poll_fds,
            &mut state.wr_state,
            did_work, poll_mode,
        );
    }
    shutdown::tear_down(&mut bindings, &cos_status, &heartbeat);
}
```

**Borrow shape note:** every phase fn takes disjoint `&mut` borrows
of LoopState fields. The compiler can prove non-aliasing because the
fields are distinct paths off `&mut state`. AGY r1 specifically
flagged the alternative (`&mut state` whole-struct) as a LLVM
optimization barrier; this signature shape mitigates it.

### Allocation audit (per-tick)

Searched `worker_loop` body (L1229-L2261) for hot-path allocations.
Findings:

- `Vec::new()` in `WorkerCommandResults` empty-init at L1434-L1437 —
  only runs when commands queue is empty. **Already present
  pre-refactor.** Plan does NOT add new per-tick Vec allocations:
  `shared_recycles` is initialized once at setup with
  `Vec::with_capacity(RX_BATCH_SIZE * 2)` and reused in place. The
  Vec stays on the `LoopState` field — moving struct ownership does
  NOT allocate.
- `Arc::new(...)` for cos_status — runs at 100ms cadence
  (COS_STATUS_INTERVAL_NS), NOT every tick. Stays in `deltas.rs`.
  Plan preserves the 100ms gate.
- `String::new()` / `format!()` — all inside the
  `DBG_REPORT_INTERVAL_NS` (1s) gate AND mostly inside
  `cfg!(feature = "debug-log")`. **Not per-tick.** Plan keeps every
  one of these inside `debug_report.rs` behind the same 1s gate
  and same feature gates.
- `(*forwarding).clone()` at L1541 in the fabric rebuild branch —
  fires only when `live_fabrics != forwarding.fabrics`, i.e. on
  fabric link change. Cold path. Preserved as-is in `expiry.rs`.
- `purge_queued_flows_for_closed_deltas` + `flush_session_deltas` —
  allocate inside `drain_deltas(256)` (Vec) at L1666/L1697. Pre-existing.
  Plan preserves call sites in `deltas.rs`.

**Affirmation: zero NEW per-tick allocations introduced by this
refactor.** The orchestrator's `state.shared_recycles` is the SAME
Vec as today's `let mut shared_recycles = Vec::with_capacity(...)`,
just rehomed onto LoopState (which is itself stack-allocated by the
orchestrator and never cloned).

### Cold-path annotation (v2)

- `debug_report::maybe_emit` — outer is
  `#[inline(always)] pub(super) fn maybe_emit(...)` and contains
  ONLY the elapsed-ns gate. Inner `fn emit_report(...)` is
  `#[cold]` and `#[inline(never)]`, holding the full body. LLVM
  sees: `if loop_now_ns - state.dbg_last_report_ns < 1e9 { return; }`
  inlined into the orchestrator, with `emit_report(...)` left out-
  of-line. This is the canonical Rust pattern for "1s gate + cold
  body" and is what the codebase uses elsewhere
  (`cilium/ebpf`-style rare-path emit).
- `shutdown::tear_down` — `#[cold]`. Runs once on exit.
- The non-empty-queue branch inside `tick::commands_drain` — `#[cold]`
  on the inner `apply_non_empty(...)` helper because most ticks have
  no pending commands. The empty-queue short-circuit is the fast
  path and stays inlined.
- The fabric-rebuild branch inside `tick::expiry` is also `#[cold]` —
  fires only when `live_fabrics != forwarding.fabrics`.

### Hot-path inline annotation (v2)

All per-tick wrappers use `#[inline(always)]` — `#[inline]` is only
a hint and LLVM may decline. `inline(always)` is a directive (modulo
recursion / variadic / interleaved-binding hazards, none of which
apply here).

- `tick::runtime_publish` — `#[inline(always)]`. 1s publish gate
  dominates; the gate itself must be local.
- `tick::arc_refresh` — `#[inline(always)]`. The `Arc::ptr_eq`
  short-circuits are the bottleneck; LLVM needs to see them at the
  call site to skip the `.load_full()` clone.
- `tick::commands_drain` — `#[inline(always)]` on the outer empty-
  queue fast-path; `#[cold]` on the inner non-empty body.
- `tick::expiry` — `#[inline(always)]`. heartbeat semantics, BPF
  conntrack refresh gate, and fabric rebuild are all branch-heavy
  + cheap.
- `tick::deltas` — `#[inline(always)]`. The 100ms cos_status gate is
  the only non-trivial work most ticks.
- `idle::handle` — `#[inline(always)]`. The BusyPoll-spin path is
  ~3 instructions; inlining is essential.
- `poll_drive::drive_one_round` — NOT inlined (no annotation, let
  LLVM decide; expect inline-never given its size). This is the
  perf-top observability win — a single fn symbol for the per-binding
  poll round. AGY r1 explicitly called out the LoopState whole-struct
  borrow as the spill-fill barrier at this boundary; v2 fixes that
  by giving `drive_one_round` a narrow ref signature.

## Public API preservation

- `pub(crate) fn worker_loop(...)` — exact same 38-parameter signature
  and exact same `use` site in `worker_runtime.rs` / coordinator. The
  fn body moves into `loop_body/mod.rs` and the original is replaced
  by a `pub(crate) use loop_body::worker_loop;` re-export.
- `BindingWorker` struct + all `impl` blocks — stay in `mod.rs`.
- `XskBindMode`, `SyncedSessionEntry`, `SharedGroupBindError`,
  `BindingLiveSnapshot` — stay in `mod.rs`.
- All `pub(crate)` helpers — stay in `mod.rs` (push_recent_exception,
  push_recent_session_delta, fabric_queue_hash). Plan does NOT
  re-home them.

Caller-visible: nothing changes. `use crate::afxdp::worker::worker_loop`
keeps working.

## Hidden invariants the change must preserve

1. **Per-tick phase ordering.** wr_state classification depends on
   computing `delta = loop_now_ns - wr_last_loop_ns` BEFORE any
   blocking call. Today this happens at the top of the loop; plan
   preserves the order: `runtime::tick_publish` is called first,
   inside the `while`, before `arc_refresh`.
2. **Forwarding-site ordering on Arc rotation.** L1284-L1288:
   `screen_state.update_profiles(new_forwarding.screen_profiles)`
   must run BEFORE the `forwarding = new_forwarding` assignment so
   the screen state sees the new profiles, AND the input-DSCP purge
   at L1289 must run AFTER the assignment so it reads the new
   forwarding. Plan preserves this exact sequence inside
   `arc_refresh::refresh_per_tick`.
3. **#941 VacateAllSharedExactSlots flag dispatch.** Flag is read out
   of `WorkerCommandResults` inside `commands.rs` and applied to
   `&mut bindings` in the SAME phase. Single-writer-only invariant
   holds: only this worker's `commands::drain_pending` mutates its
   own slots, regardless of file boundary.
4. **shared_recycles reuse.** The Vec must NOT be re-created per
   tick — it holds frame-recycle metadata across the apply_recycles
   call boundaries within a single tick. Plan keeps it as a
   `LoopState` field, initialized once in `setup`.
5. **interrupt_poll_fds reuse.** Same as above. Initialized once,
   reused. Plan keeps it on LoopState.
6. **cos_fast_interfaces rebuild predicate.** The
   `rebuild_cos_fast_interfaces` flag is OR'd across 5 different Arc
   refresh sites (forwarding, owner_worker_by_queue, owner_live_by_queue,
   root_leases, queue_leases, queue_vtime_floors). Plan computes the
   flag inside `arc_refresh::refresh_per_tick` and the rebuild
   happens in the SAME fn before return. Cannot be split across
   phase boundaries because the rebuild needs `&mut bindings` AND
   the freshly-loaded Arcs.
7. **HA load lifetime.** `let ha_runtime = ha_state.load();` is a
   `Guard` that must outlive the poll_drive call (passed as
   `ha_runtime.as_ref()`). Plan keeps `ha_runtime` on the
   orchestrator stack frame (NOT on LoopState — it's a per-tick
   Guard, not persistent state). Passed by ref through
   `commands::drain_pending` and `poll_drive::drive_one_round`.
8. **prev_rx_total / prev_fwd_total cadence.** These are sampled
   inside the debug-log report path BEFORE the per-interval reset.
   Plan preserves the read-then-reset order inside `debug_report.rs`.
9. **`heartbeat.store(loop_now_ns, …)` placement.** Currently at
   L1494, between commands and expiry. Plan keeps it in the
   orchestrator at the same spot (not pushed into commands.rs)
   because the heartbeat semantically belongs to the orchestrator
   tick, not to any specific phase.
10. **Inliner spill-fill risk.** All `#[inline]` annotations on the
    fast-path phase fns. The hot read sequence is
    `loop_now_ns → wr update → arc_refresh → expiry → poll_drive → idle`.
    Plan asserts that compiler keeps the inner loop body roughly
    equivalent in spill-fill count to today by inlining everything
    except `poll_drive` (which is too big to inline anyway). Acceptance
    test: cargo asm + Pass A multi-stream throughput within 1% of
    baseline.

## Risk assessment

| Risk | Class | Notes |
|---|---|---|
| Behavioral regression | **MED** | Pure code motion of 1278 LOC with 7+ files is high-mechanical-error surface. Mitigation: cargo test --release (~960 tests) + 5x flake + full smoke matrix. |
| Lifetime / borrow-checker | **MED** | `&mut bindings` + `&mut state` must not alias (they don't — different fields). The Arc Guards (`ha_state.load()`) stay on the orchestrator stack. Risk that the compiler complains when `LoopState.sessions` and `&mut bindings` are borrowed simultaneously by `arc_refresh::refresh_per_tick` (the input-DSCP purge needs both). Mitigation: pass `&mut state.sessions` and `&mut bindings` as explicit separate params, not `&mut state`. |
| Performance regression | **MED-HIGH** | Inliner spill-fill on phase-boundary fn calls. If the compiler refuses to inline the fast-path phases, the per-tick branch+call overhead adds up at 12-worker, ~100k/sec polls/worker scale. Mitigation: `#[inline]` annotations + cargo asm spot-check + smoke iperf3 multi-stream. |
| Architectural mismatch (#961 / #946 Phase 2) | **LOW** | Issue is purely structural code-motion. No new abstractions, no new batched-iteration premise. Existing #959 and #1189 patterns are direct precedents. |

## Test plan

- `cargo build` clean with no new warnings
- `cargo test --release` — full Rust suite passes
- 5× named-test flake on
  `worker::tests::shared_binding_plan_create_publishes_live_status`
  AND `worker::tests::publish_tx_completion_ring_telemetry_stores_before_reset`
- `go test ./...` — Go suite green
- Deploy on `loss:xpf-userspace-fw0/fw1`
- Pass A (CoS disabled): v4+v6 × push+reverse + 12-stream reverse v4
  + 12-stream reverse v6 — all line rate, 0 retrans
- Pass B (CoS enabled): per-class 5201-5206 × v4+v6 × push+reverse
  = 24 cells — all pass shape with 0 buffer drops

(Per wave-1 rules this PR posts `<!-- AWAITING-BATCH-MERGE -->`
instead of waiting for a per-PR smoke runner — final batched smoke
runs after the wave is merged.)

## Out of scope (explicitly)

- **`BindingWorker::create` 207-LOC ctor refactor.** Issue body says
  "tracked under #961". This PR carves out a `create.rs` *location*
  but does not touch the 16-param ctor reshape; that's #961's
  mandate. Conservative scope.
- **Sub-struct layout changes.** #959 settled the BindingWorker
  field decomposition. No fields move between sub-structs.
- **Algorithm changes.** Pure code motion. No phase reorder,
  no new gating, no new fast paths.
- **`fabric_queue_hash`, `load_arc_if_changed`,
  `refresh_worker_cos_queue_lease_runtime_counters`.** Tight, named,
  already extracted. Stay in mod.rs (or move only if Codex+Gemini
  specifically request it).
- **`apply_worker_shaped_tx_requests`, `publish_tx_completion_ring_telemetry`,
  `partition_binding_plans`, `register_binding_xsk`, the shared
  binding helpers.** Stay in mod.rs as-is. Touching them belongs to a
  separate ticket; #1326 is about the LONG FN body.
- **Removing the inline `mod tests` from mod.rs.** Tests exercise
  items that remain in mod.rs (shared binding helpers and
  publish_tx_completion_ring_telemetry). They stay inline.

## Open questions for adversarial review (v2)

1. **Inliner spill-fill (v2).** With `#[inline(always)]` on all hot
   phase wrappers AND narrow disjoint-field borrows on
   `poll_drive::drive_one_round`, is the spill-fill barrier AGY r1
   flagged adequately mitigated? Specifically: does LLVM still see
   the per-tick loop body as roughly equivalent to today's monolith
   after MIR optimization + LLVM inlining? Acceptance: `cargo asm`
   spot-check on the orchestrator + Pass A multi-stream within 1%
   of baseline. PLAN-KILL acceptable if reviewer believes the
   answer is no and can show a counter-example.

2. **`#[inline(always)]` correctness.** Is there any pessimism
   risk from forcing inline on the `tick::*` family — e.g. blowing
   the orchestrator's stack frame, defeating tail-call optimization,
   or forcing the compiler into a corner where it inlines a path
   that would have been better left out-of-line under PGO? Rust's
   `inline(always)` semantics differ from C's; please verify on this
   per-tick path.

3. **Phase boundary ordering.** Is there ANY current side-effect
   dependency I've missed across the L1229→L2261 sweep? Specifically
   the order of `heartbeat.store`, expiry, poll_drive, deltas,
   debug_report, idle — each pair must be commutatively reorderable
   under the plan's borrow shape OR the orchestrator must enforce
   the existing order verbatim. Plan goes with the latter; please
   verify nothing is missed.

4. **shared_recycles cross-phase use.** Today `shared_recycles` is
   filled and drained inside the same tick across multiple call sites
   (commands → poll_drive → deltas). Plan keeps it on LoopState so
   all phases mutate it. Confirm there is no "drain at end of phase"
   contract being broken — i.e. confirm that letting recycles
   persist across phase boundaries within a tick is identical to
   current behaviour.

5. **Should this even be split into 8 files?** Alternative: collapse
   debug_report + idle + shutdown into a single `tail.rs`, fold
   expiry into commands. Net: 5 files instead of 8. Is the issue's
   8-file sketch (init/arc_refresh/commands/bpf_refresh/
   telemetry_publish/tx_apply/shared_binding/create) the right
   granularity, or is finer/coarser better? Plan deviated to 8 files
   organized by tick-phase rather than by struct-area — argue
   against if appropriate.

6. **`pub(crate) use loop_body::worker_loop;` vs moving the fn entirely.**
   Either works. The re-export keeps the call site
   `use crate::afxdp::worker::worker_loop` working. Confirm there's
   no rustc edition gotcha here. (Edition 2024 in this crate.)

7. **`use super::*;` in every loop_body submodule.** Every existing
   worker sub-file uses this. `loop_body/mod.rs` will need `use
   super::*;` (which brings worker/mod.rs items) AND each
   `loop_body/<phase>.rs` will need `use super::*;` plus
   `use crate::afxdp::worker::*;`. Or restructure so loop_body is a
   child of worker/mod.rs and the `use super::*;` chain works
   transparently. Plan goes with the latter — loop_body lives at
   `worker/loop_body/` so `super` for phase files is
   `worker/loop_body/mod.rs` and `super::super` is `worker/mod.rs`.
   Acceptable?
