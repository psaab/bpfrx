# #6241 — Typed worker-launch bundles (research plan v1, DRAFT)

> Base: `origin/master` @ `5b4f1c768` (includes #6348). Research branch
> `research/6241-typed-launch-bundles`. No production code touched — this
> doc is the blast-radius survey + design for adversarial plan review.

---

## 1. Status

**PLAN-DRAFT / awaiting hostile plan-review.** This is a **Refactor class A**
(behavior-preserving) change. The deliverable of the eventual PR is: replace the
positional **38-argument** `worker_loop(...)` launch protocol with a handful of
**named typed bundles**, destructured at `worker_loop` entry into the *exact same*
local variables that exist today, so `worker_loop_setup` and the steady per-tick
loop body are **textually unchanged**.

Prerequisite-for: **#6240** (decompose `bring_up_workers`) will *consume* these
bundle types. Sibling: **#6242** (per-worker transactional runtime record) —
determined **disjoint** below (§3, §Cross-issue).

**PLAN-KILL is acceptable** if hostile review concludes the bundling adds
indirection without real swap-safety value (see §3 honest-value and the open
questions in §11). The whole justification rests on whether named-field
construction meaningfully reduces the silent-misroute risk that the 38-wide
positional protocol carries; if it does not, this is churn.

---

## 2. Issue framing (CW-B1-02)

`worker_loop` (`userspace-dp/src/afxdp/worker/loop_body/mod.rs:36-85`) takes **38
positional parameters**. Several are **swap-compatible** — two parameters share
the exact same Rust type, so a positional reorder or a mis-inserted argument
**compiles silently** and misroutes a value to the wrong destination. The
compiler checks *type*, not *semantic role*.

The **sole production caller** is the 40-line positional call inside the worker
spawn closure at `coordinator/reconcile/bringup.rs:437-478`. Confirmed
firsthand: `grep -rn "worker_loop(" userspace-dp/src` returns exactly two hits —
the definition (`loop_body/mod.rs:36`) and this one call (`bringup.rs:437`).
There are **no test callers** and no second production site. The launch boundary
is therefore a single, well-contained protocol between coordinator-owned state
and worker-thread ownership.

`worker_loop_setup` (`worker/loop_body/setup.rs:68-88`) is a *second* positional
protocol: it takes a **15-reference** subset of the launch args and returns a
**19-field** `WorkerLoopSetup` bundle (`setup.rs:28-61`) that `worker_loop`
destructures into same-named locals (`loop_body/mod.rs:88-134`).

---

## 3. Honest scope & value

This is a **class-A mechanical bundling**. It is **not** a perf change, **not** a
behavior change, **not** a new abstraction layer. The win is narrow and specific:

**The real, firsthand-verified swap hazard is smaller than the issue title
implies.** I enumerated all 38 types (§5 census). The truly *type-identical*
(silent-swap-compatible) parameter sets are only:

- **The three shared session maps** — `shared_sessions`, `shared_nat_sessions`,
  `shared_forward_wire_sessions` are **all** exactly
  `Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>`. Any positional swap of
  two of them compiles and silently misroutes NAT sessions into the forward-wire
  map (or vice-versa) — a **HA session-sync correctness bug** with no compiler
  signal. This is the single highest-value grouping.
- **The two `Arc<AtomicU64>`** — `heartbeat` (param 21) and `session_export_ack`
  (param 22) are identical types. A swap makes the coordinator read the
  export-ack counter as the liveness heartbeat → false failover. Second-highest
  value.

**The six CoS `Arc<ArcSwap<BTreeMap<...>>>` are NOT mutually swap-compatible.**
Contrary to the issue's "six CoS ArcSwap" framing, each has a *distinct inner
value type* (`u32`, `Arc<BindingLiveState>`, `Arc<SharedCoSRootLease>`,
`Arc<SharedCoSExactBacklog>`, `Arc<SharedCoSQueueLease>`,
`Arc<SharedCoSQueueVtimeFloor>`), so `ArcSwap<T>` invariance already makes a
cross-swap a **compile error**. Bundling them is *organizational* (grouping a
coherent subsystem), not *swap-safety*. Same is true of the seven other
`Arc<ArcSwap<…>>` params (validation/forwarding/ha/tunnels/fabrics/mirror/
cos_status) — all type-distinct.

**Honest value statement for the reviewer:** the bundling converts a **38-wide
positional protocol** (where reorder/insertion drift can silently misroute the 3
session maps and the 2 atomics) into **~5 named struct-literal bundles** where
each field is named at construction. This:

1. Eliminates positional-order drift for the 5 genuinely-hazardous params.
2. Makes the coordinator→worker ownership boundary *readable* (5 cohesive
   bundles vs. a 50-line flat arg list).
3. **Unblocks #6240** — the bundle constructors collapse ~14 clone-and-pass
   lines into a few `from_coord`-style calls, which is exactly the seam #6240's
   launch-helper extraction needs.

**Caveat the reviewer must weigh (PLAN-KILL pivot):** a named-field struct does
**not** prevent a *same-typed source* mistake at construction —
`WorkerSharedSessions { synced: coord.sessions.nat.clone(), … }` still compiles.
Full role-safety would need per-role newtypes, which the issue explicitly
excludes ("keep concrete types and private fields; this is not a service-locator
or trait abstraction"). So the swap-safety is **positional→named**, not
**named→newtype**. If the reviewer judges positional→named insufficient to
justify the churn, PLAN-KILL is the right call. My read (§below) is that it *is*
justified, because the fail-on-revert wiring test (§9) pins the exact
misroute-prone site and #6240 needs the seam regardless.

---

## 4. What's shipped (the launch boundary as-is)

- **#1326** extracted `worker_loop` out of `worker/mod.rs` into `loop_body/`
  (pure code motion, ~1278 LOC function).
- **#1776** carved the one-shot cold setup into `loop_body/setup.rs`
  (`worker_loop_setup` → `WorkerLoopSetup`) and the debug report into
  `debug_report.rs`. Round-1 plan review established: **no `#[inline(never)]`
  call boundary may be added to the per-tick path** (`load_arc_if_changed` runs
  10K–100K ticks/s). Setup is `#[inline(never)]` and cold by construction.
- **#4952 / #5143 / #5165 / #5289 / #6245** grew `bring_up_workers` into the
  626-line post-teardown transaction (spawn fail-closed, in-thread bind
  readiness barrier, per-worker exception rings, explicit binding-failure
  diagnostics). Several of these *added* launch args — the arg count has been
  ratcheting up, which is the pressure #6241 relieves.
- **#6348** (in base) grew bringup further; `bringup.rs` is now **870 LOC**,
  `bring_up_workers` spans `bringup.rs:96-764`.

Current shape: the spawn loop at `bringup.rs:349-435` builds ~38 per-worker
locals (mix of `coord.*.clone()`, fresh per-worker allocations, and
`worker_command_queues` projections), then the `move ||` closure at
`bringup.rs:436-479` calls `worker_loop(...)` positionally.

---

## 5. The 38-parameter census (firsthand, `loop_body/mod.rs:36-85`)

Grouped by **ownership + lifetime + purpose**. "Source" = where `bringup.rs`
gets the value. **Swap?** flags a type-identical sibling in the list.

### A. Per-worker launch plan (moved/Copy — not shared coordinator state)
| # | Param | Type | Source | Swap? |
|---|-------|------|--------|-------|
| 1 | `worker_id` | `u32` | loop key | — |
| 2 | `binding_plans` | `Vec<BindingPlan>` | loop value (moved) | — |
| 23 | `poll_mode` | `crate::PollMode` (Copy) | `coord.poll_mode` | — |
| 24 | `dnat_fds` | `DnatTableFds` (`Copy`; two `Option<c_int>`) | built pre-loop | — |

### B. Shared dataplane state (coordinator-published, worker reads via ArcSwap load)
| # | Param | Type | Source | Swap? |
|---|-------|------|--------|-------|
| 3 | `shared_validation` | `Arc<ArcSwap<ValidationState>>` | `coord.shared_validation` | type-distinct |
| 4 | `shared_forwarding` | `Arc<ArcSwap<ForwardingState>>` | `coord.ha.forwarding` | type-distinct |
| 5 | `ha_state` | `Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>` | `coord.ha.rg_runtime` | type-distinct |
| 13 | `local_tunnel_deliveries` | `Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>` | `coord.local_tunnel_deliveries` | type-distinct |
| 25 | `shared_fabrics` | `Arc<ArcSwap<Vec<FabricLink>>>` | `coord.ha.fabrics` | type-distinct |
| 34 | `shared_mirror_targets` | `Arc<ArcSwap<MirrorTargetMap>>` | `coord.mirror_targets` | type-distinct |
| 27 | `rg_epochs` | `Arc<[AtomicU32; MAX_RG_EPOCHS]>` | `coord.rg_epochs` | — |
| 12 | `slow_path` | `Option<Arc<SlowPathReinjector>>` | `coord.slow_path` | — |

### C. Shared sessions (⚠ THE swap hazard — 3 identical types)
| # | Param | Type | Source | Swap? |
|---|-------|------|--------|-------|
| 8 | `shared_sessions` | `Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>` | `coord.sessions.synced` | **⚠ = 9,10** |
| 9 | `shared_nat_sessions` | `Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>` | `coord.sessions.nat` | **⚠ = 8,10** |
| 10 | `shared_forward_wire_sessions` | `Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>` | `coord.sessions.forward_wire` | **⚠ = 8,9** |
| 11 | `shared_owner_rg_indexes` | `SharedSessionOwnerRgIndexes` | `coord.sessions.owner_rg_indexes` | type-distinct |

### D. Neighbors
| # | Param | Type | Source | Swap? |
|---|-------|------|--------|-------|
| 6 | `dynamic_neighbors` | `Arc<ShardedNeighborMap>` | `coord.neighbors.dynamic` | — |
| 7 | `neighbor_resolver` | `Option<Arc<NeighborResolver>>` | `coord.neighbors.resolver` | — |

### E. Control channels (bidirectional)
| # | Param | Type | Source | Swap? |
|---|-------|------|--------|-------|
| 17 | `commands` | `Arc<Mutex<VecDeque<WorkerCommand>>>` | `worker_command_queues[id]` | type-distinct |
| 18 | `peer_worker_commands` | `Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>` | queues − self | type-distinct |
| 19 | `worker_commands_by_id` | `Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>>` | `worker_command_queues` | type-distinct |
| 20 | `stop` | `Arc<AtomicBool>` | fresh per-worker | — |
| 21 | `heartbeat` | `Arc<AtomicU64>` | fresh per-worker | **⚠ = 22** |
| 22 | `session_export_ack` | `Arc<AtomicU64>` | fresh per-worker | **⚠ = 21** |
| 26 | `event_stream` | `Option<EventStreamWorkerHandle>` | `coord.event_stream_worker_handle()` | — |
| 38 | `startup_report_tx` | `mpsc::Sender<WorkerStartupReport>` | per-reconcile channel | — |

### F. Published telemetry / status slots (worker writes, coordinator reads)
| # | Param | Type | Source | Swap? |
|---|-------|------|--------|-------|
| 14 | `recent_exceptions` | `Arc<Mutex<ExceptionEventRing>>` | fresh; also stored in `coord.worker_exception_rings` | — |
| 15 | `recent_session_deltas` | `Arc<Mutex<VecDeque<SessionDeltaInfo>>>` | `coord.recent_session_deltas` | — |
| 16 | `last_resolution` | `Arc<Mutex<Option<ResolutionEvent>>>` | fresh; also stored in `coord.worker_last_resolution` | — |
| 35 | `cos_status` | `Arc<ArcSwap<Vec<CoSInterfaceStatus>>>` | fresh per-worker | — |
| 36 | `runtime_atomics` | `Arc<WorkerRuntimeAtomics>` | fresh per-worker | — |
| 37 | `cold_path_atomics` | `Arc<WorkerColdPathAtomics>` | fresh per-worker | — |

### G. CoS shared scheduler state (6 ArcSwaps — type-DISTINCT, organizational grouping)
| # | Param | Type | Source |
|---|-------|------|--------|
| 28 | `shared_cos_owner_worker_by_queue` | `Arc<ArcSwap<BTreeMap<(i32,u8), u32>>>` | `coord.cos.owner_worker_by_queue` |
| 29 | `shared_cos_owner_live_by_queue` | `Arc<ArcSwap<BTreeMap<(i32,u8), Arc<BindingLiveState>>>>` | `coord.cos.owner_live_by_queue` |
| 30 | `shared_cos_root_leases` | `Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSRootLease>>>>` | `coord.cos.root_leases` |
| 31 | `shared_cos_exact_backlogs` | `Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSExactBacklog>>>>` | `coord.cos.exact_backlogs` |
| 32 | `shared_cos_queue_leases` | `Arc<ArcSwap<BTreeMap<(i32,u8), Arc<SharedCoSQueueLease>>>>` | `coord.cos.queue_leases` |
| 33 | `shared_cos_queue_vtime_floors` | `Arc<ArcSwap<BTreeMap<(i32,u8), Arc<SharedCoSQueueVtimeFloor>>>>` | `coord.cos.queue_vtime_floors` |

**Census total: 38 = 4(A) + 8(B) + 4(C) + 2(D) + 8(E) + 6(F) + 6(G).**
Genuinely silent-swap-compatible: **{8,9,10}** and **{21,22}** only.

---

## 6. Concrete design

### 6.1 Bundle structs (new file `worker/launch.rs`)

Recommended **5 bundles** (with two nested sub-bundles isolating the swap
hazard). All fields `pub(crate)`/`pub(super)`, concrete types, no traits.

```rust
// worker/launch.rs  (new)
use super::*;

/// Per-worker launch plan: identity + the plan/FD values MOVED or COPIED
/// into the worker thread (not shared coordinator state).
pub(crate) struct WorkerLaunchPlan {
    pub(crate) worker_id: u32,
    pub(crate) binding_plans: Vec<BindingPlan>,
    pub(crate) poll_mode: crate::PollMode,
    pub(crate) dnat_fds: DnatTableFds,
}

/// The three swap-compatible session maps + owner-rg indexes, named so a
/// mis-wire is caught at the single construction site (fail-on-revert §9).
pub(crate) struct WorkerSharedSessions {
    pub(crate) synced: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(crate) nat: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(crate) forward_wire: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(crate) owner_rg_indexes: SharedSessionOwnerRgIndexes,
}

pub(crate) struct WorkerNeighbors {
    pub(crate) dynamic: Arc<ShardedNeighborMap>,
    pub(crate) resolver: Option<Arc<NeighborResolver>>,
}

/// Coordinator-published shared dataplane state (worker reads via ArcSwap).
pub(crate) struct WorkerSharedDataplane {
    pub(crate) validation: Arc<ArcSwap<ValidationState>>,
    pub(crate) forwarding: Arc<ArcSwap<ForwardingState>>,
    pub(crate) ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    pub(crate) local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    pub(crate) fabrics: Arc<ArcSwap<Vec<FabricLink>>>,
    pub(crate) mirror_targets: Arc<ArcSwap<MirrorTargetMap>>,
    pub(crate) rg_epochs: Arc<[AtomicU32; MAX_RG_EPOCHS]>,
    pub(crate) slow_path: Option<Arc<SlowPathReinjector>>,
    pub(crate) neighbors: WorkerNeighbors,
    pub(crate) sessions: WorkerSharedSessions,
}

/// Bidirectional control: command queues, stop/heartbeat/ack atomics,
/// event stream, one-shot startup-readiness sender.
pub(crate) struct WorkerControlChannels {
    pub(crate) commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    pub(crate) peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    pub(crate) worker_commands_by_id: Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>>,
    pub(crate) stop: Arc<AtomicBool>,
    pub(crate) heartbeat: Arc<AtomicU64>,
    pub(crate) session_export_ack: Arc<AtomicU64>,
    pub(crate) event_stream: Option<crate::event_stream::EventStreamWorkerHandle>,
    pub(crate) startup_report_tx: std::sync::mpsc::Sender<WorkerStartupReport>,
}

/// Worker-written status/telemetry publish slots + the 6 CoS scheduler
/// ArcSwaps (type-distinct; grouped for coherence, not swap-safety).
pub(crate) struct WorkerPublishedTelemetry {
    pub(crate) recent_exceptions: Arc<Mutex<ExceptionEventRing>>,
    pub(crate) recent_session_deltas: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    pub(crate) last_resolution: Arc<Mutex<Option<ResolutionEvent>>>,
    pub(crate) cos_status: Arc<ArcSwap<Vec<crate::protocol::CoSInterfaceStatus>>>,
    pub(crate) runtime_atomics: Arc<crate::afxdp::worker_runtime::WorkerRuntimeAtomics>,
    pub(crate) cold_path_atomics: Arc<crate::afxdp::cold_path_hist::WorkerColdPathAtomics>,
    pub(crate) cos_owner_worker_by_queue: Arc<ArcSwap<BTreeMap<(i32, u8), u32>>>,
    pub(crate) cos_owner_live_by_queue: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<BindingLiveState>>>>,
    pub(crate) cos_root_leases: Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSRootLease>>>>,
    pub(crate) cos_exact_backlogs: Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSExactBacklog>>>>,
    pub(crate) cos_queue_leases: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>>,
    pub(crate) cos_queue_vtime_floors: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>>,
}
```

> Open design choice (§11 Q2): whether the 6 CoS ArcSwaps live in
> `WorkerPublishedTelemetry` or a **6th bundle `WorkerCoSState`**. They are
> read-shared scheduler state, arguably closer to `WorkerSharedDataplane` than to
> "telemetry". The 4-bundle vs 5-bundle vs 6-bundle split is the main
> reviewer-tunable knob. The issue's own suggestion was **4** bundles
> (`WorkerLaunchPlan`, `WorkerSharedDataplane`, `WorkerControlChannels`,
> `WorkerPublishedTelemetry`) folding CoS into telemetry; I lean **5** to keep
> `WorkerSharedDataplane` from ballooning, but flag it as a judgment call.

### 6.2 New `worker_loop` signature (5 params)

```rust
pub(crate) fn worker_loop(
    plan: WorkerLaunchPlan,
    shared: WorkerSharedDataplane,
    control: WorkerControlChannels,
    telemetry: WorkerPublishedTelemetry,
) {
    // Destructure at ENTRY into the EXACT same locals that exist today.
    // After this block, setup call + steady loop body are TEXTUALLY UNCHANGED.
    let WorkerLaunchPlan { worker_id, binding_plans, poll_mode, dnat_fds } = plan;
    let WorkerSharedDataplane {
        validation: shared_validation,
        forwarding: shared_forwarding,
        ha_state,
        local_tunnel_deliveries,
        fabrics: shared_fabrics,
        mirror_targets: shared_mirror_targets,
        rg_epochs,
        slow_path,
        neighbors: WorkerNeighbors { dynamic: dynamic_neighbors, resolver: neighbor_resolver },
        sessions: WorkerSharedSessions {
            synced: shared_sessions,
            nat: shared_nat_sessions,
            forward_wire: shared_forward_wire_sessions,
            owner_rg_indexes: shared_owner_rg_indexes,
        },
    } = shared;
    let WorkerControlChannels {
        commands, peer_worker_commands, worker_commands_by_id,
        stop, heartbeat, session_export_ack, event_stream, startup_report_tx,
    } = control;
    let WorkerPublishedTelemetry {
        recent_exceptions, recent_session_deltas, last_resolution,
        cos_status, runtime_atomics, cold_path_atomics,
        cos_owner_worker_by_queue: shared_cos_owner_worker_by_queue,
        cos_owner_live_by_queue: shared_cos_owner_live_by_queue,
        cos_root_leases: shared_cos_root_leases,
        cos_exact_backlogs: shared_cos_exact_backlogs,
        cos_queue_leases: shared_cos_queue_leases,
        cos_queue_vtime_floors: shared_cos_queue_vtime_floors,
    } = telemetry;

    // ── from here down: byte-for-byte the CURRENT loop_body/mod.rs:88+ ──
    let setup::WorkerLoopSetup { .. } = setup::worker_loop_setup(worker_id, binding_plans, &shared_validation, …);
    // … steady loop unchanged …
}
```

`peer_worker_commands` is bound but currently the closure passes
`peer_commands_clone`; the destructure name simply becomes `peer_worker_commands`
(the loop already uses that param name). Field-rename destructuring (`validation:
shared_validation`) keeps every downstream identifier unchanged.

### 6.3 `worker_loop_setup` — STAYS UNCHANGED

**Decision: setup does not take a bundle.** Because the destructure in §6.2
rebuilds the *exact* `shared_validation`, `shared_forwarding`, `poll_mode`,
`cos_status`, `runtime_atomics`, `cold_path_atomics`, and the six
`shared_cos_*` locals, the existing `worker_loop_setup(worker_id, binding_plans,
&shared_validation, …)` call (`loop_body/mod.rs:112-127`) compiles and behaves
identically with **zero edits**. Keeping setup's 15-ref signature untouched
minimizes blast radius and keeps the diff auditable. (An optional follow-up could
make setup borrow `&shared` sub-bundles, but that is NOT part of #6241 — it adds
diff without swap-safety, since setup's refs are already type-distinct.)

### 6.4 Rewritten call site (`bringup.rs`)

The per-worker local construction (`bringup.rs:349-435`) is **unchanged** — the
same `coord.*.clone()` / fresh-alloc / queue-projection locals are built. Only
the final closure changes from a 40-line positional `worker_loop(a, b, c, …)`
into named bundle literals:

```rust
let body = move || {
    worker_loop(
        WorkerLaunchPlan { worker_id, binding_plans, poll_mode: worker_poll_mode, dnat_fds },
        WorkerSharedDataplane {
            validation: shared_validation,
            forwarding: shared_forwarding,
            ha_state,
            local_tunnel_deliveries,
            fabrics: shared_fabrics,
            mirror_targets: shared_mirror_targets,
            rg_epochs,
            slow_path,
            neighbors: WorkerNeighbors { dynamic: dynamic_neighbors, resolver: neighbor_resolver },
            sessions: WorkerSharedSessions {
                synced: shared_sessions,
                nat: shared_nat_sessions,
                forward_wire: shared_forward_wire_sessions,
                owner_rg_indexes: shared_owner_rg_indexes,
            },
        },
        WorkerControlChannels {
            commands: commands_clone,
            peer_worker_commands: peer_commands_clone,
            worker_commands_by_id,
            stop: stop_clone,
            heartbeat: heartbeat_clone,
            session_export_ack: session_export_ack_clone,
            event_stream: event_stream_handle,
            startup_report_tx: startup_report_tx_worker,
        },
        WorkerPublishedTelemetry {
            recent_exceptions, recent_session_deltas, last_resolution,
            cos_status: cos_status_clone,
            runtime_atomics: runtime_atomics_clone,
            cold_path_atomics: cold_path_atomics_clone,
            cos_owner_worker_by_queue: shared_cos_owner_worker_by_queue,
            cos_owner_live_by_queue: shared_cos_owner_live_by_queue,
            cos_root_leases: shared_cos_root_leases,
            cos_exact_backlogs: shared_cos_exact_backlogs,
            cos_queue_leases: shared_cos_queue_leases,
            cos_queue_vtime_floors: shared_cos_queue_vtime_floors,
        },
    );
};
```

### 6.5 Counts (before / after)

| Metric | Before | After |
|--------|--------|-------|
| `worker_loop` params | **38** | **4** (or 5 if CoS split out) |
| Bundle structs introduced | 0 | **5** (3 top + 2 nested) |
| Silent-swap-compatible params | 5 (`{8,9,10}`,`{21,22}`) | **0** at the call boundary (named fields) |
| Call-site `worker_loop(...)` block | ~40 lines positional | ~40 lines named struct-literal |
| `worker_loop_setup` signature | 15 refs (unchanged) | **15 refs (unchanged)** |
| Steady loop body | — | **textually unchanged** |
| Added `Arc` clones / allocs on launch path | — | **0** (move + destructure, no clone) |

---

## 7. Public API preservation

- `worker_loop` is `pub(crate)` and called from exactly one production site; no
  external/FFI/wire surface. The *behavior* is unchanged: every value reaches the
  same destination local, in the same order of construction, with the same
  ownership. Only the *grouping* of the parameter list changes.
- No protobuf, gRPC, control-socket, or on-wire message changes. No config
  grammar changes. No `repr(C)` / BPF struct changes.
- The `WorkerLoopSetup` bundle and `worker_loop_setup` are untouched.

---

## 8. Hidden invariants (must be preserved)

1. **Every arg routes to the EXACT same destination.** The destructure in §6.2
   must bind each field to the identical local name the loop body uses today.
   Field-rename destructuring (`validation: shared_validation`) is the mechanism.
   The fail-on-revert wiring test (§9) exists to prove this.
2. **No new clone/alloc on the launch path.** Bundles are *moved* into
   `worker_loop` and *destructured* (not cloned). `Arc` strong counts must be
   identical before/after — the bundle construction consumes the same
   already-cloned locals the positional call consumes today. Verify no
   `.clone()` sneaks into a bundle constructor.
3. **No per-tick indirection.** Nothing bundle-shaped may survive the entry
   destructure into the steady loop. This is the #1776 constraint restated: the
   10K–100K ticks/s loop reads `shared_validation` etc. as plain locals; a
   `self.shared.validation` field access per tick would regress it. The
   destructure-at-entry design guarantees this — the loop body is unchanged.
4. **Move-order / drop-order.** Today the closure moves 38 locals in; with
   bundles it moves the same values wrapped in structs. Drop order at worker exit
   must not change observably (all are `Arc`/`Vec`/`Copy`; `Sender` drop closes
   the startup channel — must still drop at the same scope end).
5. **`dnat_fds` / raw FDs.** `WorkerLaunchPlan.dnat_fds` carries raw `c_int`
   values (`DnatTableFds` is `Copy`); ownership of the underlying FDs stays on
   the coordinator (`coord.bpf_maps`). The bundle must carry *values*, not take
   ownership of any `OwnedFd`.
6. **`heartbeat` vs `session_export_ack` identity.** These two identical-typed
   atomics must land in the correctly-named fields — the exact misroute the
   bundle is meant to prevent, and a fail-on-revert target.
7. **Session-map identity.** `synced`/`nat`/`forward_wire` must map 1:1 to
   `coord.sessions.{synced,nat,forward_wire}`. Any swap is an HA-sync
   correctness bug; the wiring test pins it by `Arc::ptr_eq`.
8. **`neighbor_resolver` install-before-clone ordering (cross-issue).**
   `coord.neighbors.resolver` must already be `Some` before the closure clones
   it (per #6240's amendment, `bringup.rs:403`). #6241 does not move the resolver
   install; it only wraps the already-cloned `neighbor_resolver` into
   `WorkerNeighbors`. Preserve the existing ordering.

---

## 9. Test plan

**Behavior-preserving ⇒ the gate must prove the bundling routes every value
identically, and that nothing on the hot path changed.**

### 9.1 Fail-on-revert wiring tests (the core gate)
Add `worker/launch.rs` unit tests that construct each bundle with
**distinguishable** values and assert each field holds the intended value —
so a field swap (the revert) turns the assertion RED:

- **Session-map identity by pointer:** build a `Coordinator` (or minimal harness)
  with three *distinct* session-map `Arc`s, construct `WorkerSharedSessions` the
  way `bringup.rs` does, and assert
  `Arc::ptr_eq(&b.synced, &coord.sessions.synced)`, `…nat…`, `…forward_wire…`.
  Revert = swap `nat`/`forward_wire` at the construction site → `ptr_eq` fails.
  This is the highest-value fail-on-revert — it binds the exact silent-swap the
  issue names.
- **Atomic identity:** construct `WorkerControlChannels` with
  `heartbeat`=Arc(0xA), `session_export_ack`=Arc(0xB); assert
  `b.heartbeat.load()==0xA && b.session_export_ack.load()==0xB` (or `ptr_eq`).
  Revert = swap → RED.
- **Full-field coverage:** a `WorkerSharedDataplane`/`WorkerPublishedTelemetry`
  `ptr_eq`-per-field test so any future field misroute in a `from_coord`-style
  constructor fails.

> If a `from_coord(&coord)` constructor is added (recommended for #6240, §10),
> the wiring test targets *it* — one central, testable wiring site. Without a
> constructor, the test targets a small `build_worker_bundles(...)` helper the
> closure calls. Either way there must be **one** named-construction site to bind.

### 9.2 Existing suites (regression)
- `cargo test --manifest-path userspace-dp/Cargo.toml` — **full** Rust suite
  (`make test-rust`). Must stay green. Includes the coordinator readiness/spawn
  tests: `reconcile_post_teardown_worker_spawn_failure_fails_closed_4952`,
  `post_spawn_inthread_bind_failure_fails_closed_5143`, and the #6245 binding
  diagnostics — all exercise the launch path.
- `make test` (Go + Rust) before PR.
- Release build (`make build-userspace-dp`) — confirm it compiles under the
  no-LTO release profile.

### 9.3 Hot-path / no-regression evidence
- Diff-audit the destructure: confirm the steady loop body is byte-identical
  (a `git diff` on `loop_body/mod.rs` should show only the new signature +
  entry destructure block; the `loop {}` region unchanged).
- Optional per the issue amendment: compare optimized `worker_loop` symbol size /
  stack usage before-after; assert no new allocation/indirect-call in the hot
  block. Cheap and high-signal since the design claims *zero* hot-path change.

### 9.4 Loss-cluster deploy (worker-launch path is exercised)
Behavior-preserving, but this **is** the worker-spawn path, so run a real
deploy + sustained-iperf3 smoke on the **loss userspace cluster** per the
project rule (v4 **and** v6, push + reverse). Not a throughput claim — a
"workers still bind, forward, and fail over" gate. Reassert node0 master before
`make test-failover` (memory: post-deploy node0 stays SECONDARY).

---

## 10. Coordination with siblings

### 10.1 #6240 (decompose `bring_up_workers`) — CONSUMES these bundles
#6240 extracts a per-worker **launch helper** from the `bringup.rs:349-479` spawn
body. That helper's clean shape is: *given `coord` + `worker_id` + per-worker
freshly-allocated slots, build the four bundles and spawn the closure.* So #6241
should make the bundles **easy for #6240 to build**:

- Provide **`WorkerSharedDataplane::from_coord(&coord)`** and
  **`WorkerCoS*`/telemetry-CoS `from_coord`** constructors — these fields are all
  `coord.*.clone()` today, so a `from_coord` collapses ~14 clone lines into one
  call. **This is the seam #6240 wants** and simultaneously gives §9.1 its single
  testable wiring site. Strongly recommended to land the `from_coord`
  constructors *in #6241*.
- `WorkerControlChannels` / the fresh-alloc telemetry fields (`stop`,
  `heartbeat`, `cos_status`, `runtime_atomics`, `cold_path_atomics`,
  `recent_exceptions`, `last_resolution`) are **per-worker**, not from coord —
  #6240's spawn loop builds those. Design note: keep those out of `from_coord`.

Net: #6241 draws the boundary so #6240's spawn loop shrinks from ~90 lines of
clone-and-pass to a few bundle constructions. **#6241 must land first.**

### 10.2 #6242 (per-worker transactional runtime record) — DISJOINT
#6242 (CW-B1-03) groups the **coordinator-side storage** maps
(`WorkerManager::handles` + `coord.worker_panics` + `coord.worker_exception_rings`
+ `coord.worker_last_resolution`) into one `WorkerRuntimeRecord` keyed by worker
id, so register/rollback/stop is one atomic operation.

**Firsthand boundary determination: #6241 and #6242 are DISJOINT and ship
independently.**
- **Different sides of the same Arcs.** `recent_exceptions` (param 14) and
  `last_resolution` (param 16) are cloned twice at spawn: one clone → the worker
  (via #6241's `WorkerPublishedTelemetry`), one clone → the coordinator's map
  (via #6242's `WorkerRuntimeRecord`). #6241 owns the *worker-facing argument
  bundle*; #6242 owns the *coordinator-facing storage record*. Neither
  restructures the other's data; they share **no type**.
- The `panic_slot` (#6242's fourth field) is **not** a `worker_loop` param at all
  — it's captured by the spawn wrapper, never passed to `worker_loop`. Zero
  overlap with #6241.
- **Only physical adjacency:** both edit `bring_up_workers`, but in different
  regions — #6241 rewrites the `worker_loop(...)` call (`bringup.rs:436-479`);
  #6242 rewrites the map insert/remove/clear sites (`bringup.rs:~366-433`,
  `:575-583`, and `coordinator/mod.rs` teardown). A textual merge conflict is
  possible if both are in flight; there is **no semantic coupling**.
- This matches the cross-issue ownership order stated in #6240's own amendment
  ("#6242: worker-id runtime record only; #6241: construction-time argument
  bundle only").

**Sequencing recommendation:** ship #6241 first (smaller, class-A, unblocks
#6240); #6242 independently; #6240 last as the umbrella that consumes both. If
#6241 and #6242 run concurrently, coordinate the `bringup.rs` edit windows.

### 10.3 Docs (module contract)
`worker/README.md` (lines 5-9, 31-33) and `coordinator/README.md` (lines
184-246) both document the launch boundary. The PR **must** update:
- `worker/README.md`: add a `loop_body/` / `launch.rs` row describing the bundle
  types and note `worker_loop`'s signature is now bundle-based (behavior
  unchanged).
- `coordinator/README.md`: note the `bring_up_workers` spawn closure now
  constructs typed bundles (`from_coord` constructors) — behavior-preserving.

---

## 11. Out of scope

- **Any hot-path change.** No touching the steady `loop {}` body, `poll_binding`,
  ArcSwap refresh cadence, or `worker_loop_setup`'s internals.
- **Newtype/role-typed wrappers** per session map (would give named→newtype
  safety) — explicitly excluded by the issue ("concrete types, private fields,
  not a service-locator or trait abstraction").
- **`bring_up_workers` decomposition** — that is #6240. #6241 only rewrites the
  final `worker_loop(...)` call and adds the bundle types + constructors.
- **`WorkerManager` runtime record** — that is #6242.
- **Fixing any latent behavior** (e.g. the warmer's ignored spawn result,
  spawn-vs-bind rollback asymmetry) — behavior-preserving means *preserve*, not
  repair.
- Reworking `worker_loop_setup`'s 15-ref signature into a bundle.

---

## 12. Open questions (each PLAN-KILL-invitable)

1. **Is positional→named swap-safety worth the churn?** The genuine silent-swap
   surface is only 5 params (`{8,9,10}`, `{21,22}`); the other 33 are already
   type-distinct and a positional error among them fails to compile. If the
   reviewer judges the 5-param hazard too small to justify a 5-struct refactor,
   **PLAN-KILL** and instead just add the two nested sub-bundles
   (`WorkerSharedSessions`, and pair the two atomics) *inside the existing
   38-arg call* — a far smaller change that kills the actual hazard. Is the full
   bundling over-engineered relative to a targeted 2-substruct fix?
2. **4 vs 5 vs 6 bundles.** The issue proposed 4 (CoS folded into telemetry); I
   lean 5 (CoS as read-shared state, or its own 6th bundle). Which grouping does
   the reviewer want as the contract? (Bikeshed-prone; needs a decision to avoid
   #6240 building against a moving target.)
3. **`from_coord` constructors in #6241 or #6240?** Landing them in #6241 gives
   the single testable wiring site (§9.1) and pre-builds #6240's seam, but adds
   surface to a "pure bundling" PR. Should the constructors ship with #6241 or be
   deferred to #6240? (My rec: #6241, because the fail-on-revert test needs one
   central wiring site.)
4. **Does the entry-destructure actually stay zero-cost?** The design claims the
   move+destructure compiles to the same code as 38 positional moves. Do we
   require the §9.3 symbol-size/stack/asm comparison as a *merge gate*, or is a
   diff-audit ("loop body byte-identical") sufficient? If the asm shows *any* new
   hot-block work, **PLAN-KILL** (the #1776 constraint is absolute).
5. **Nested vs flat bundles.** `WorkerSharedDataplane` nests `WorkerNeighbors` +
   `WorkerSharedSessions`. Nesting isolates the hazard but complicates the
   destructure. Flat (all 14 fields in `WorkerSharedDataplane`) is simpler but
   loses the sub-group naming. Which does the reviewer prefer?
6. **Merge-conflict management with #6242.** If both touch `bring_up_workers`,
   do we serialize (#6241 then #6242) or accept a rebase? (Recommend serialize;
   #6241 is smaller and first.)
7. **`peer_worker_commands` naming.** The param is `peer_worker_commands` but the
   closure builds `peer_commands_clone`. Confirm the destructure field name and
   downstream identifier stay consistent so the loop body is unchanged.

---

*End of plan v1.*
