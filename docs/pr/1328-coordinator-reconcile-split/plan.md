# #1328 Coordinator decompose Phase 2 — split reconcile() + refresh_bindings()

**Status:** v2 — round-1 review addressed (Codex PLAN-NEEDS-MAJOR + AGY PLAN-NEEDS-MINOR), re-dispatching adversarial review

## Round-1 review summary

- **Codex** (task `task-mpmuqp90-xi2crk`): PLAN-NEEDS-MAJOR. 8 findings,
  all addressed below.
- **AGY** (job `review-mpmuqxve-5cmvqa`): PLAN-NEEDS-MINOR. Main ask
  (sub-mod-dir layout) addressed below.

Concrete v2 deltas:

1. **Layout:** flat `coordinator/reconcile_*.rs` siblings → sub-mod-dir
   `coordinator/reconcile/{mod,teardown,reset,snapshot,bringup}.rs`
   plus sibling `coordinator/refresh_bindings.rs`. Both reviewers
   asked for this.
2. **`copy_live_snapshot` signature:** take `BindingLiveSnapshot` **by
   value**, not by reference. `BindingLiveSnapshot` owns `String`
   fields (`xsk_bind_mode`, `shared_umem_*`, `last_error`) at
   `userspace-dp/src/afxdp/worker/mod.rs:2373`; borrowing would
   either fail to compile or force string clones. Plan v1 was wrong.
3. **`last_reconcile_stage` write inventory:** add the indirect
   `"stopped"` write from `stop_inner` at L281. Full sequence:
   `start` (L321) → indirect `stopped` (L281, set by `stop_inner`) →
   `no_snapshot` (L397) → `missing_xsk_pin` (L437) →
   `missing_heartbeat_pin` (L446) → `missing_session_pin` (L455) →
   `open_xsk_map_failed:{err}` (L466) → `open_heartbeat_map_failed:{err}`
   (L478) → `open_session_map_failed:{err}` (L490) → `planned:...`
   (L594) → optional `replayed_synced:...` (L652) →
   `spawn_worker_failed:{worker_id}:{err}` (L777, overwritten by
   final `spawned:...` write — operator-visible quirk that must be
   preserved verbatim) → `spawned:...` (L795).
4. **Allocation analysis:** rephrase from "no allocations" to
   "no additional allocations beyond existing code motion".
   `stop_inner(false)` already does `Arc::new(BTreeMap::new())`
   stores at L204/L210/L217/L241 and similar; the refactor does not
   add or remove any. The no-op claim is preserved for *new*
   allocations only.
5. **Test plan:** drop the bogus `coordinator/tests.rs:1310`
   citation. `:1310` is a `refresh_bindings` zero-out test, not a
   `reconcile(None, ...)` test. Add a new
   `coordinator::tests::reconcile_with_none_snapshot_preserves_stage_sequence`
   test that asserts the `start`→`stopped`→`no_snapshot` stage
   sequence and zero new bindings in `workers.live`.
6. **`PreservedReconcileState`:** drop `had_live_workers`. The
   500ms quiesce check lives entirely inside the teardown helper;
   the orchestrator does not need to see the flag. Two fields:
   `synced_sessions: Vec<SyncedSessionEntry>`,
   `slow_path: Option<Arc<SlowPathReinjector>>`.
7. **#925 panic-slot pairing:** keep insert+spawn+remove-on-Err
   **inline inside `reconcile/bringup.rs`** rather than wrapping in
   a `spawn_worker_with_panic_slot` helper. Codex flagged the
   helper would have dozens of captured deps and hide more than
   it clarifies. Adding a code comment at the insert site that
   names the L777 Err-arm remove keeps the pairing one screen
   from the spawn call.
8. **Side-effect boundary documentation:** replaced the
   "comment-block boundaries" framing with an explicit
   load-bearing-side-effect inventory in the "Hidden invariants"
   section. The four phase boundaries are anchored to the actual
   state transitions, not the comment formatting.

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
the ~1Hz status poll plus once per `reconcile()`. Neither path is
on the packet hot loop. The refactor introduces **no additional
allocations beyond the existing code-motion baseline**; the
no-op `reconcile(None, …)` path retains its pre-existing
`stop_inner`-driven `Arc::new(BTreeMap::new())` / `Arc::new(Vec::new())`
stores (the refactor does not add or remove any). See the
"Allocation discipline" section below for the exact inventory.

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

### New layout (v2 — sub-mod-dir per both reviewers)

```
userspace-dp/src/afxdp/coordinator/
  mod.rs                       // Coordinator struct + thin public API
                               // Target: ~1100 LOC after extraction
                               // (helper free-fns at L1492+ stay here for
                               // now — see "Out of scope" §)
  refresh_bindings.rs          // sibling: copy_live_snapshot +
                               // zero_unbound_slot + dispatcher
  reconcile/
    mod.rs                     // pub fn reconcile() orchestrator
                               // (~80 LOC) + PreservedReconcileState
                               // struct + ReconcileSnapshotFds struct
    teardown.rs                // Phase 1: preserve state + stop_inner
                               //  - snapshot synced sessions
                               //  - preserve healthy slow path
                               //  - call stop_inner(false)
                               //  - 500ms mlx5 quiesce (when had
                               //    live workers)
                               //  Returns PreservedReconcileState
    reset.rs                   // Phase 2: binding counter zero-pass
                               //  - reset_binding_counters
                               //    (pure fn over &mut [BindingStatus])
    snapshot.rs                // Phase 3: validation + forwarding state
                               //  rebuild + slow-path re-init + map opens
                               //  - apply_snapshot_state
                               //  - rebuild_slow_path
                               //  - open_required_bpf_maps
                               //    returns Option<ReconcileSnapshotFds>;
                               //    sets last_reconcile_stage +
                               //    per-binding last_error on failure
    bringup.rs                 // Phase 4: per-worker plan + spawn loop
                               //  - build_worker_plans
                               //  - apply_shared_umem_status
                               //  - replay_synced_sessions tail
                               //  - per-worker spawn loop with
                               //    #925 panic-slot insert+remove
                               //    INLINE (no wrapper helper)
                               //  - start_neighbor_monitor
                               //  - spawn_local_tunnel_sources
```

The new `coordinator/reconcile/` sub-mod-dir is added to
`coordinator/mod.rs` with two new `mod` lines:

```rust
mod reconcile;
mod refresh_bindings;
```

`reconcile::reconcile` is exposed via the `impl Coordinator` block
that the `reconcile/mod.rs` file declares (Rust permits split impl
blocks across modules). The public method signature
`Coordinator::reconcile(&mut self, ...)` is preserved verbatim.

### Orchestrator shape (per issue body)

```rust
// in coordinator/reconcile/mod.rs
pub(in crate::afxdp) struct PreservedReconcileState {
    pub synced_sessions: Vec<SyncedSessionEntry>,
    pub slow_path: Option<Arc<SlowPathReinjector>>,
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
dispatcher. **Codex r1 #1 correction:** take `BindingLiveSnapshot`
**by value** (it owns `String` fields), and reuse the existing
`.get()` (no `.cloned()` on the `Arc` — current code accesses the
snapshot through `&Arc<BindingLiveState>` without a refcount bump):

```rust
pub(super) fn copy_live_snapshot(
    binding: &mut BindingStatus,
    snap: BindingLiveSnapshot,
);

pub(super) fn zero_unbound_slot(binding: &mut BindingStatus);

pub fn refresh_bindings(&mut self, bindings: &mut [BindingStatus]) {
    for binding in bindings.iter_mut() {
        if let Some(live) = self.workers.live.get(&binding.slot) {
            let snap = live.snapshot();
            copy_live_snapshot(binding, snap);
        } else {
            zero_unbound_slot(binding);
        }
    }
    self.refresh_cos_owner_worker_map_from_binding_statuses(bindings);
}
```

`copy_live_snapshot` and `zero_unbound_slot` are pure functions
over the binding + (for the first) `BindingLiveSnapshot` (by
value). The existing `eprintln!` on the `bound: false → true`
transition stays inside `copy_live_snapshot` so the operator-visible
log is preserved verbatim. The `tx_submit_latency_hist` and
`tx_kick_latency_hist` `Vec`s are *resized* in place via
`.resize(new_len, 0) + .copy_from_slice(&snap.x)`, reusing the
existing backing buffer when capacity is sufficient (steady state).

### Allocation discipline on the steady-state no-op path

There are two no-op paths to verify. The refactor adds **zero new
allocations beyond the existing code-motion baseline**. Existing
allocations stay as-is.

1. `reconcile(None, bindings, _)` — current code: writes
   `last_reconcile_stage = "start"` (allocation), calls
   `snapshot_shared_session_entries()` (allocates a Vec — but
   needed for the `preserve_healthy_slow_path` flow that follows),
   calls `stop_inner(false)` which itself does several
   `Arc::new(BTreeMap::new())` / `Arc::new(Vec::new())` / `.to_string()`
   stores at L204/L210/L217/L223–L226/L241/L243/L245/L246/L281
   (these are pre-existing — the refactor does not add or remove
   any), runs the binding reset loop (no allocation), then writes
   `last_reconcile_stage = "no_snapshot"` (allocation). Refactor
   must preserve this exact shape — *no new* allocations introduced
   in the None path, and the indirect `stop_inner` allocations stay
   where they are.

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

   **Load-bearing side effects per phase boundary** (replaces v1's
   comment-block framing per Codex r1 #5):
   - **Teardown finishes when:** workers stopped + tunnel sources
     joined + mirror_targets cleared + worker_panics cleared + CoS
     ArcSwap fields reset + slow_path = None + bpf_maps cleared +
     ha.forwarding/ha.fabrics/shared_validation reset + neighbors
     cleared + `last_reconcile_stage = "stopped"` set by stop_inner.
   - **Reset finishes when:** every binding's counter fields are
     zero, `ready=false`, `last_error` cleared. No state writes to
     `self`.
   - **Snapshot apply finishes when:** validation/forwarding
     installed on self + shared_validation/ha.forwarding stored +
     slow_path re-armed + ha.fabrics published + xsk/heartbeat/session
     map FDs open + optional conntrack/dnat FDs open. Snapshot
     phase does NOT write `last_reconcile_stage` except on its
     own error-leg failures (`missing_*_pin`, `open_*_failed`);
     on success it leaves the stage set to the value written by
     the preceding teardown phase (`stopped`). The `planned:...`
     write belongs to the bringup phase, not snapshot apply.
   - **Bringup finishes when:** worker_plans assembled +
     shared-UMEM backfilled into bindings + cos_owner_worker_by_queue
     mapping installed + mirror_targets stored + replay_synced_sessions
     ran + per-worker spawn loop completed (panic-slot insert+remove
     paired with spawn outcome) + neighbor monitor started +
     local tunnel sources spawned + `last_reconcile_stage = "spawned:..."`.

2. **`last_reconcile_stage` write ordering** is part of the
   operator-visible contract (status poll exposes it). **Codex r1 #2
   correction:** the inventory includes the **indirect** `"stopped"`
   write at L281 inside `stop_inner`, which is called from reconcile
   at L335. The full sequence (line numbers vs current master):

   - `start` (L321, in `reconcile/mod.rs`)
   - `stopped` (L281 indirect via `stop_inner`, untouched by this PR)
   - `no_snapshot` (L397, in `reconcile/mod.rs` early-return)
   - `missing_xsk_pin` (L437, in `reconcile/snapshot.rs`)
   - `missing_heartbeat_pin` (L446, in `reconcile/snapshot.rs`)
   - `missing_session_pin` (L455, in `reconcile/snapshot.rs`)
   - `open_xsk_map_failed:{err}` (L466, in `reconcile/snapshot.rs`)
   - `open_heartbeat_map_failed:{err}` (L478, in `reconcile/snapshot.rs`)
   - `open_session_map_failed:{err}` (L490, in `reconcile/snapshot.rs`)
   - `planned:workers=N:bindings=M:live=K` (L594, in `reconcile/bringup.rs`)
   - optional `replayed_synced:N:workers=M` (L652, in `reconcile/bringup.rs`)
   - `spawn_worker_failed:{worker_id}:{err}` (L777, in `reconcile/bringup.rs`,
     **overwritten by the final `spawned:...` write** — this is a
     pre-existing operator-visible quirk and must be preserved
     verbatim)
   - `spawned:workers=N:identities=M:live=K` (L795, in `reconcile/bringup.rs`)

   Every existing write stays at the equivalent logical position
   inside the new sub-file. New helpers do not introduce new
   `last_reconcile_stage` writes.

3. **#925 panic-slot insert/remove pairing.** The current
   spawn-loop inserts a panic slot into `self.worker_panics`
   *before* calling `spawn_supervised_worker`, and removes it on
   the `Err(err)` arm. **Codex r1 #7 + AGY q7:** keep the
   insert+spawn+remove **inline inside `reconcile/bringup.rs`**
   rather than wrapping in a helper. The spawn closure captures
   ~30 worker-scoped state Arcs; a helper signature with that
   many parameters or a captured-state struct would hide more
   than it clarifies. Mitigation: add a one-line comment at the
   insert site that names the matching Err-arm remove ("paired
   with `worker_panics.remove(&worker_id)` on the spawn-Err arm
   below").

4. **`preserved_synced_sessions` lifetime.** This `Vec` outlives
   `stop_inner(false)` and is consumed by `replay_synced_sessions`
   inside `reconcile/bringup.rs`. Threaded as a field of
   `PreservedReconcileState`, returned by
   `reconcile/teardown.rs::tear_down(...)`, consumed by
   `reconcile/bringup.rs::bring_up_workers(...)`. Not stored on
   `self` (would risk double-replay on back-to-back reconciles).

5. **`preserved_slow_path` lifetime.** Identical pattern — second
   field of `PreservedReconcileState`. Consumed inside
   `reconcile/snapshot.rs::apply_snapshot_state(...)` (which is
   the new home of L413–L430's slow-path re-init).

   **Codex r1 #6 + AGY:** v2 drops `had_live_workers` from the
   struct. The 500ms quiesce check belongs entirely inside
   `reconcile/teardown.rs::tear_down(...)` — the orchestrator
   does not need to see the flag.

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
| Performance regression | LOW | Functions are off the packet hot path. The only concern is the no-op `reconcile(None, …)` allocation discipline; covered by adding a new `coordinator::tests::reconcile_with_none_snapshot_preserves_stage_sequence` test (see Test plan §). |
| Architectural mismatch (#961 / #946-Phase-2 dead-end) | LOW | Pure code motion has no architectural premise to fail. The decomposition target (per-phase sub-files matching the comment-block structure of the current function) is what the issue body explicitly proposes; no novel design. |

## Test plan

1. `cargo build --release` clean.
2. `cargo test --release` — full userspace-dp test suite (target:
   952+ tests pass).
3. 5× flake check on the full `coordinator::tests` module.
4. **Codex r1 #4 correction — new test:** add
   `coordinator::tests::reconcile_with_none_snapshot_preserves_stage_sequence`
   that calls `reconcile(None, &mut bindings, 64)` and asserts:
   - final `last_reconcile_stage == "no_snapshot"`.
   - `reconcile_calls == 1` afterwards.
   - `workers.live` empty.
   - `slow_path` is `None`.
   - The bindings the test passed in have their `ready=false` and
     `bound=false` flags zeroed.

   v1's claim that `coordinator/tests.rs:1310` covered this case
   was wrong — `:1310` is a `refresh_bindings` zero-out test.

5. `go test ./...` — Go side untouched, but run the suite to
   confirm no protocol breakage (30 packages).
6. **Smoke** — deferred to batch per the standing
   `<!-- AWAITING-BATCH-MERGE -->` rule. PR will not run smoke
   itself — it ships on 4-of-4 reviewer attestation.

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

## Open questions for adversarial review (v2 — round-2 resolved)

The following Round-1 questions are now decided. Listed here for
audit, with the round-1 reviewer rulings.

1. **Perf justification at absolute scale.** Reconcile runs on
   snapshot installs / HA role changes (off hot path);
   `refresh_bindings` runs at ~1 Hz. Round-1 verdict from both
   reviewers: maintainability case is sound; not PLAN-KILL.

2. **Layout — sub-mod-dir vs flat siblings.** Decided
   sub-mod-dir `coordinator/reconcile/{mod,teardown,reset,
   snapshot,bringup}.rs` plus sibling `coordinator/refresh_bindings.rs`.
   Both reviewers asked for this and it matches the issue body's
   proposal.

3. **`PreservedReconcileState` struct vs locals.** Decided keep
   the struct (two fields: `synced_sessions` + `slow_path`) as a
   typed contract documenting what survives teardown. Codex r1 #6
   asked to drop `had_live_workers`; done.

4. **`reconcile_apply_snapshot` collapsed error legs.** Decided
   keep `Option<ReconcileSnapshotFds>` return. The helper body
   keeps each explicit `missing_*_pin` / `open_*_failed` error
   leg with its exact `last_reconcile_stage` string and
   per-binding `last_error` write — only the return type
   collapses. AGY r1 explicitly endorsed this shape.

5. **Allocation discipline on no-op path.** Decided "no
   additional allocations beyond existing code motion". Existing
   `stop_inner`-driven `Arc::new(BTreeMap::new())` stores at
   L204–L246 are pre-existing and stay; the refactor adds none.

6. **`refresh_bindings` zero-out branch.** Decided keep
   `zero_unbound_slot(binding)` local to `refresh_bindings.rs`
   for now. Pushing the reset into `BindingStatus::reset_for_unbound()`
   is blocked on #1325 (protocol.rs split) per issue body.

7. **#925 panic-slot pairing.** Decided INLINE inside
   `reconcile/bringup.rs` (no `spawn_worker_with_panic_slot`
   wrapper). Codex r1 #7 + AGY r1 q7 both agreed: the spawn
   closure captures ~30 worker-scoped Arcs; a helper would hide
   more than it clarifies. One-line comment at the insert site
   names the matching Err-arm remove.

8. **Architectural mismatch test (#961 / #946-Phase-2 pattern).**
   Decided NO mismatch. The phase boundaries are anchored to
   the load-bearing side effects documented in the "Hidden
   invariants" section, not to the comment-block formatting.
   AGY r1 explicitly verified this.
