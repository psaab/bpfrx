# #1328 Coordinator decompose Phase 2 — split reconcile() + refresh_bindings()

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

`userspace-dp/src/afxdp/coordinator/mod.rs` is 2026 LOC of production
code (zero inline tests — `coordinator/tests.rs` already holds the
1089 LOC test suite from the #1046 P1 colocation pattern). Two
functions dominate:

- `pub fn reconcile()` (L314–L820): 506 LOC — orchestrates teardown,
  binding counter reset, snapshot installation, slow-path
  preservation, BPF-map opening, worker plan construction, worker
  spawn, neighbor-monitor start, and a trailing `refresh_bindings()`
  call.
- `pub fn refresh_bindings()` (L1156–L1482): 326 LOC — copies per-slot
  live snapshots into the operator-facing `BindingStatus`, with a
  parallel zero-out branch for unregistered slots.

Both exceed the `docs/engineering-style.md` god-function threshold
(>100 LOC) by 3–5×. The file as a whole is ~26 LOC under the 2000
LOC monolith threshold and accreting; the issue body cites #1189's
established `coordinator/` mod-dir layout (Phase 1 pulled supervisor
helpers into `coordinator/supervisor.rs`) as the natural template
for Phase 2.

## Honest scope/value framing

This is a **pure code-motion refactor**. There is no perf win on
the wire — `reconcile()` runs on snapshot installs and HA role
changes (occasional, not hot path); `refresh_bindings()` runs on
the ~1Hz status poll plus once per `reconcile()`. Neither is
allocation-sensitive in the steady state beyond the rule that a
no-op reconcile must not allocate (the existing implementation
already doesn't — the bringup work happens after the early
returns that handle `None` snapshot and missing-map-pin cases).

The win is reviewability + future-feature locality. A snapshot-field
addition (the most common reason these functions grow) currently
has to be read against ~500 LOC of unrelated state. After this
refactor it lands in a focused sub-file.

**If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict.** This is explicitly a
maintainability play and the issue body frames it that way.

## What's already shipped / partially batched

- **#1189 Phase 1** (PR #1200, merged 2026-05-05) established the
  `coordinator/` mod-dir layout. Three supervisor helpers extracted
  into `coordinator/supervisor.rs`; `WorkerManager` grew
  `stop_and_clear` + accessors. `mod.rs` went down 149 LOC.
- **#1046 P1** test colocation pattern is already applied:
  `coordinator/tests.rs` (1089 LOC) holds the existing test suite.
  No test moves are required.
- **Sub-files already extracted**: `bpf_maps.rs`, `cos_state.rs`,
  `ha_state.rs`, `inject.rs`, `neighbor_manager.rs`,
  `session_manager.rs`, `status.rs`, `supervisor.rs`,
  `worker_manager.rs`. These are out of scope per the issue body.

## Concrete design

### New layout

```
userspace-dp/src/afxdp/coordinator/
  mod.rs                 // Coordinator struct + thin public API
                         // Target: ~1100 LOC after extraction
                         // (helper free-fns at L1492+ stay here for
                         // now — see "Out of scope" §)
  reconcile.rs           // Top-level orchestrator (~150 LOC)
                         //  - reconcile() public entry
                         //  - PreservedState struct
                         //  - dispatch helpers
  reconcile_teardown.rs  // Phase 1: preserve state + stop_inner
                         //  - snapshot_synced_sessions
                         //  - preserve_healthy_slow_path
                         //  - stop_and_quiesce (~60 LOC)
  reconcile_reset.rs     // Phase 2: binding counter zero-pass
                         //  - reset_binding_counters (~70 LOC,
                         //    pure fn over `&mut BindingStatus`)
  reconcile_snapshot.rs  // Phase 3: validation + forwarding state
                         //  rebuild + slow-path re-init
                         //  - apply_snapshot_state
                         //  - rebuild_slow_path
                         //  - open_required_bpf_maps (returns Result
                         //    so early-error branches stay typed)
  reconcile_bringup.rs   // Phase 4: per-worker plan + spawn loop
                         //  - build_worker_plans
                         //  - apply_shared_umem_status
                         //  - spawn_worker (#925 panic slot included)
                         //  - start_neighbor_monitor
  refresh_bindings.rs    // pub fn refresh_bindings split into:
                         //  - copy_live_snapshot (~140 LOC)
                         //  - zero_unbound_slot (~120 LOC)
                         //  Plus the public dispatcher that picks one
                         //  per slot and calls
                         //  refresh_cos_owner_worker_map_from_binding_statuses
                         //  at the end.
```

### Orchestrator shape (per issue body)

```rust
// in coordinator/reconcile.rs
pub(in crate::afxdp) struct PreservedReconcileState {
    pub synced_sessions: Vec<SyncedSessionEntry>,
    pub slow_path: Option<Arc<SlowPathReinjector>>,
    pub had_live_workers: bool,
}

impl Coordinator {
    pub fn reconcile(
        &mut self,
        snapshot: Option<&ConfigSnapshot>,
        bindings: &mut [BindingStatus],
        ring_entries: usize,
    ) {
        self.reconcile_calls += 1;
        self.last_reconcile_stage = "start".to_string();

        let preserved = self.reconcile_teardown(bindings);
        self.reconcile_reset_bindings(bindings);

        let Some(snapshot) = snapshot else {
            self.policy_counters.reconcile_rules(&[]);
            self.last_reconcile_stage = "no_snapshot".to_string();
            return;
        };

        let Some(fds) = self.reconcile_apply_snapshot(
            snapshot, bindings, preserved.slow_path,
        ) else {
            // last_reconcile_stage + binding.last_error already set
            return;
        };

        self.reconcile_bringup_workers(
            snapshot, bindings, fds, ring_entries,
            preserved.synced_sessions,
        );
        self.refresh_bindings(bindings);
    }
}
```

Each phase is a `pub(super) fn` method on `Coordinator` defined in
its own module. The free `mod` declarations in `coordinator/mod.rs`
gain four new lines.

### Sub-file contents (per phase)

**`reconcile_teardown.rs`** — preserve synced sessions + healthy
slow-path, call `stop_inner(false)`, sleep 500ms if there were
live workers (the mlx5 quiesce). Returns a `PreservedReconcileState`.

**`reconcile_reset.rs`** — single function
`reset_binding_counters(bindings: &mut [BindingStatus])`. Pure
function over the binding slice; no `&mut self` dependency.

**`reconcile_snapshot.rs`** — installs the
`ValidationState`/`ForwardingState`, re-arms the slow path, opens
the required BPF map pins. The four early-return error legs (no
xsk pin / no heartbeat pin / no session pin / open-fd failures)
become a single `Option<DnatTableFds + OwnedFd handles>` return,
with the function itself setting `last_reconcile_stage` + per-binding
`last_error` on failure. Caller gets `Option<ReconcileSnapshotFds>`
and bails early when `None`.

**`reconcile_bringup.rs`** — the worker-plan loop, shared-UMEM
status backfill, mirror-target map publish, CoS runtime-map
refresh, replay of preserved synced sessions, per-worker spawn
loop (including the #925 panic slot insert/remove), and the
neighbor-monitor + local-tunnel-source start. Ends without calling
`refresh_bindings` — that call is moved up to the orchestrator so
the order of operations is visible at one read.

**`refresh_bindings.rs`** — `refresh_bindings` becomes the
dispatcher:

```rust
pub fn refresh_bindings(&mut self, bindings: &mut [BindingStatus]) {
    for binding in bindings.iter_mut() {
        match self.workers.live.get(&binding.slot).cloned() {
            Some(live) => copy_live_snapshot(binding, &live.snapshot()),
            None => zero_unbound_slot(binding),
        }
    }
    self.refresh_cos_owner_worker_map_from_binding_statuses(bindings);
}
```

`copy_live_snapshot` and `zero_unbound_slot` are pure functions
over the binding + (for the first) `BindingLiveSnapshot`. The
existing `eprintln!` on the `bound: false → true` transition stays
inside `copy_live_snapshot` so the operator-visible log is
preserved verbatim.

### Allocation discipline on the steady-state no-op path

There are two no-op paths to verify:

1. `reconcile(None, bindings, _)` — current code: writes
   `last_reconcile_stage = "start"` (allocation), calls
   `snapshot_shared_session_entries()` (allocates a Vec — but
   needed for the `preserve_healthy_slow_path` flow that follows),
   calls `stop_inner(false)`, runs the binding reset loop (no
   allocation), then writes `last_reconcile_stage = "no_snapshot"`
   (allocation). Refactor must preserve this exact shape — *no
   new* allocations in the None path.

2. `refresh_bindings()` on a fully-bound binding set — current code
   copies live snapshots into `BindingStatus`, the only allocation
   is the `tx_submit_latency_hist.resize()` + `copy_from_slice()`
   pair (which only allocates if capacity is insufficient — steady
   state reuses the same backing buffer). After refactor, the
   `copy_live_snapshot` helper must take the histogram by reference
   to avoid a clone, and the unbound branch must continue to use
   `.clear()` rather than `= Vec::new()`.

The plan explicitly preserves these. No new `Box::new`,
`Arc::new`, `String::from`, or `vec![]` calls are introduced on
either no-op path. Two of the existing `last_reconcile_stage`
writes (the `"start"` and the `"no_snapshot"`) are pre-existing
allocations and stay where they are.

## Public API preservation

These signatures are unchanged:

```rust
impl Coordinator {
    pub fn reconcile(
        &mut self,
        snapshot: Option<&ConfigSnapshot>,
        bindings: &mut [BindingStatus],
        ring_entries: usize,
    );
    pub fn refresh_bindings(&mut self, bindings: &mut [BindingStatus]);
}
```

External callers (`server/helpers.rs:17,312`; `main_tests.rs:993,
1016`; `coordinator/tests.rs:1254,1310`) all reference them as
methods on `Coordinator`. No callsite is touched.

## Hidden invariants the change must preserve

1. **Side-effect ordering inside `reconcile`.** The current order is:
   `reconcile_calls += 1` → preserve synced sessions → preserve
   healthy slow-path → `stop_inner(false)` → 500ms quiesce →
   binding counter reset → snapshot None bail-out → install
   validation/forwarding → reinit slow-path → publish HA fabrics
   snapshot → check xsk/heartbeat/session pins → open BPF map FDs
   → build worker plans + shared-UMEM backfill →
   `last_planned_*` bookkeeping → mirror-target store → CoS
   runtime-map refresh → replay preserved synced sessions → per-worker
   spawn loop (with panic-slot insert + remove-on-spawn-failure) →
   start neighbor monitor → `spawn_local_tunnel_sources()` →
   `refresh_bindings(bindings)`. The refactor preserves this order
   verbatim. Each sub-file's body is a contiguous slice of the
   current function body — no reordering.

2. **`last_reconcile_stage` write ordering** is part of the
   operator-visible contract (status poll exposes it). Every existing
   write stays where it is. New helpers do not introduce new
   `last_reconcile_stage` writes.

3. **#925 panic-slot insert/remove pairing.** The current
   spawn-loop inserts a panic slot into `self.worker_panics`
   *before* calling `spawn_supervised_worker`, and removes it on
   the `Err(err)` arm. This pairing must stay. Plan keeps the
   insert + spawn + Err-remove inside a single helper
   `spawn_worker_with_panic_slot` so reviewers can verify the
   pairing at one site.

4. **`preserved_synced_sessions` lifetime.** This `Vec` outlives
   `stop_inner(false)` and is consumed by `replay_synced_sessions`
   after worker_command_queues exist. Refactor must thread it
   through the orchestrator's return value, not store it on
   `self`. Storing it on `self` would change ownership semantics
   and risk a double-replay on a back-to-back reconcile.

5. **`preserved_slow_path` lifetime.** Identical — `Option<Arc<…>>`
   threaded through, not stored.

6. **`refresh_bindings` final callout.** The trailing
   `refresh_bindings(bindings)` inside `reconcile` is currently the
   last statement. Moving it into the orchestrator (rather than
   into `reconcile_bringup_workers`) is a deliberate choice — it
   keeps the orchestrator's body readable as a 7-line phase list.
   Semantically identical.

7. **`refresh_cos_owner_worker_map_from_binding_statuses` final
   callout inside `refresh_bindings`.** Stays at the tail of the
   dispatcher.

## Risk assessment

| Risk class | Level | Mitigation |
|------------|-------|------------|
| Behavioral regression | MEDIUM | The teardown→reset→snapshot→bringup ordering is load-bearing for slow-path preservation across HA role changes. Mitigation: pure code motion verified by `git diff --stat` (line count ≈ 0 net delta excluding new file headers), 1089 LOC of existing `coordinator/tests.rs`, `make test-failover`, `make test-ha-crash`. |
| Lifetime / borrow-checker | MEDIUM | `&mut self` plus `&mut [BindingStatus]` across phase boundaries means each new helper takes both. The two `Vec<…>` preserved fields (`synced_sessions`, `slow_path`) are passed by value through the `PreservedReconcileState`, so no lifetime extension is needed. Smoke: `cargo build --release` clean. |
| Performance regression | LOW | Functions are off the packet hot path. The only concern is the no-op `reconcile(None, …)` allocation discipline; covered by the no-op test in `coordinator/tests.rs:1254` (refresh_bindings) and `1310` (a no-snapshot reconcile case if present — we will add one if missing). |
| Architectural mismatch (#961 / #946-Phase-2 dead-end) | LOW | Pure code motion has no architectural premise to fail. The decomposition target (per-phase sub-files matching the comment-block structure of the current function) is what the issue body explicitly proposes; no novel design. |

## Test plan

1. `cargo build --release` clean.
2. `cargo test --release` — full userspace-dp test suite (target:
   952+ tests pass).
3. 5× flake check on the most affected named tests:
   `cargo test --release coordinator::tests` (the full 1089-LOC
   suite). Five consecutive clean runs required.
4. `go test ./...` — Go side untouched, but run the suite to
   confirm no protocol breakage (30 packages).
5. **Smoke on loss userspace cluster (loss:xpf-userspace-fw0/fw1)**
   — full matrix per `docs/engineering-style.md`:
   - Pass A (CoS disabled): v4+v6 × push+reverse single-stream
     baselines (4 cells, 0 retrans);
     `iperf3 -P 12 -t 10 -R` multi-stream reverse v4 + v6 (line
     rate, 0 retrans).
   - Pass B (CoS enabled): per-class 5201–5206 × v4+v6 ×
     push+reverse (24 cells).
6. (Optional) `make test-failover` — this PR touches the reconcile
   path, which is exactly what failover exercises. If smoke passes
   cleanly we will run failover on the loss userspace cluster as a
   confidence pass before requesting merge.

**Per the standing batch-merge rule, smoke is deferred to the
batch via `<!-- AWAITING-BATCH-MERGE -->`. PR will not run smoke
itself — it ships on 4-of-4 reviewer attestation.**

## Out of scope (explicitly)

- Helper free-fns at L1492+ in `mod.rs` (the
  `aggregate_cos_statuses_across_workers` block + 15 CoS-build
  helpers, ~520 LOC) stay where they are. They are tightly coupled
  to `CoSInterfaceStatus`/`CoSQueueStatus` types and have their
  own test coverage in `coordinator/tests.rs`. A follow-up issue
  (post-#1325 protocol split) is the right home for them.
- The `BindingStatus::reset_for_reconcile(&mut self)` migration
  the issue body mentions is *not* in this PR. Today the binding
  counter reset is field-by-field; pushing that into `BindingStatus`
  is a protocol.rs change, blocked on #1325 per the issue body.
- The `Coordinator` struct field layout (53 lines of fields at the
  top of `mod.rs`) is not touched. Sub-state extraction is a
  separate concern.
- `worker_manager.rs`, `supervisor.rs`, `neighbor_manager.rs`,
  `session_manager.rs`, `bpf_maps.rs`, `cos_state.rs`, `ha_state.rs`,
  `inject.rs`, `status.rs` are not touched.
- `refresh_runtime_snapshot()` (L940) and `bump_fib_generation()`
  (L1151) — these are short (~60 LOC and ~5 LOC) and not in scope.

## Open questions for adversarial review

1. **Is the perf justification sound at absolute scale?** Reconcile
   runs on snapshot installs and HA role changes (occasional, not
   hot path); refresh_bindings runs on the ~1Hz status poll. Pure
   maintainability win. **Is this enough to justify the churn,
   or is this a PLAN-KILL?**

2. **Should the four new files be `coordinator/reconcile/{teardown,
   reset, snapshot, bringup}.rs` (a sub-mod-dir) instead of flat
   `reconcile_*.rs` siblings?** The issue body proposes a
   sub-mod-dir (`coordinator/reconcile/mod.rs +
   teardown.rs/binding_reset.rs/snapshot_apply.rs/panic_slot.rs/
   binding_bringup.rs`). The plan above flattens that to top-level
   `reconcile_*.rs` for shallower nesting. The wave-1 rules
   directive says coordinator/ is already a dir and prefers
   *sub-aspects as needed* — does that admit either shape?

3. **Is the `PreservedReconcileState` struct worth the type or
   should the orchestrator stash the two preserved values in
   locals?** A struct is more readable but adds 8 lines of type
   definition for two fields used in two places.

4. **`reconcile_apply_snapshot` returning `Option<ReconcileSnapshotFds>`
   collapses four early-return error legs into one type. Is this
   too clever — should each error leg stay its own `pub(super) fn`
   to mirror the current code shape?**

5. **Allocation discipline on the no-op `reconcile(None, …)` path.**
   The plan claims zero new allocations. Is there a hidden allocation
   in any of the helper-call boundaries (e.g., a struct field that
   ends up cloned in a `format!` argument)?

6. **`refresh_bindings` zero-out branch.** The current code writes
   ~60 field assignments and clears two `Vec`s. The proposed
   `zero_unbound_slot(binding: &mut BindingStatus)` is pure
   code-motion of that block. Should it instead use
   `BindingStatus::reset_for_unbound()` on the `BindingStatus`
   type itself (which the issue body proposes for the
   `reset_for_reconcile` case)? That would push the field list
   into `protocol.rs`, but the issue body explicitly defers that
   to a post-#1325 follow-up.

7. **#925 panic-slot pairing.** The plan keeps the insert + spawn
   + Err-remove inside a single helper. Is that helper's name
   (`spawn_worker_with_panic_slot`) carrying its weight, or should
   the panic-slot insert/remove be inlined into the spawn-loop in
   `reconcile_bringup.rs` to reduce indirection?

8. **Architectural mismatch test (#961 / #946-Phase-2 pattern).**
   This is pure code motion of comment-block boundaries that
   already exist in the function body. Are there any signs that
   the comment-block boundaries don't match the *actual*
   side-effect boundaries — i.e., is there a side effect in
   "snapshot install" that depends on the binding-reset phase
   having already run? (We claim no, based on the binding-reset
   loop only touching counter fields.)
