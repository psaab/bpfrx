# #6240 — decompose `bring_up_workers` (v2, re-planned post-prerequisites)

## 1. Status

`DRAFT v2 — pending adversarial plan review`

Research + plan-draft only. No production source touched. This is a **re-plan**
of the v1 plan (`research/6240-decompose-bring-up-workers:docs/research/6240-decompose-bring-up-workers/plan.md`),
which deferred the hard half of the work behind two then-open prerequisites.
Those prerequisites — **and three siblings** — have since MERGED, reshaping
`bring_up_workers`. This plan re-censuses the CURRENT function and re-scopes the
decomposition against it.

Base: `origin/master` @ `b8fd010b8` ("Merge PR #6360 … 6236-pr2a-foundations").
Worktree: `.claude/worktrees/6240-research-v2`, branch `research/6240-decompose-v2`.

## 2. Issue framing (re-plan)

`bring_up_workers` (`userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs`)
is the tail phase of `Coordinator::reconcile`, run on the **post-teardown
destructive path**: `teardown::tear_down` has already stopped/joined the
previous workers and dropped the old BPF-map FDs, so by the time this function
runs the data plane has already moved. Every failure it raises is a failure
with **no prior state to restore** — only fail-closed bookkeeping plus a
retry/last-good reconcile. That is what makes it load-bearing out of proportion
to its size, and why it is **FAILOVER-CRITICAL** (it runs on the recovering
node after a failover).

The v1 census recorded 626 LOC. On CURRENT master the function is lines
**96–803** (708 LOC) and the file is **909 LOC** with three functions. The
growth is the merged prerequisite work (typed stages, explicit binding
failures, launch bundles, runtime record, map-pin preflight), which added
**structure**, not just lines. CW-B1-01 asks for a class-B refactor with
A-only cold extractions: keep a short explicit transaction shell and outline
the cohesive phases into named helpers. The re-plan's finding is that the merged
prerequisites have **shifted this decomposition from class-B toward near
code-motion** — see §3/§5.

## 3. Honest scope / value framing (the re-plan delta)

**The hard type-work is already shipped.** v1 correctly judged that the
transactional core could not be cleanly extracted while (a) `worker_loop` took
a 38/40-argument positional protocol and (b) per-worker runtime state lived in
four parallel coordinator maps unwound by three manual `.remove` calls on the
spawn-error arm. Both are now gone on master:

- **#6241 (MERGED, PR #6351)** replaced the 40-arg call with five typed bundles
  built via `WorkerLaunchPlan::new` / `WorkerSharedDataplane::from_coord` /
  `WorkerControlChannels::new` / `WorkerCoSState::from_coord` /
  `WorkerPublishedTelemetry::new`. The `from_coord` builders **encapsulate every
  `coord.*.clone()` the spawn closure used to inline** (`worker/launch.rs`), and
  `Arc::ptr_eq` wiring tests pin each field. The launch call is now
  `worker_loop(launch_plan, shared_dataplane, control_channels, cos_state,
  published_telemetry)` (bringup.rs:456–462) — **5 args, not 40**.
- **#6242 (MERGED, PR #6357)** replaced the four owner-maps + three manual
  removes with **one** `coord.workers.records.insert(worker_id,
  WorkerRuntimeRecord { handle, panic, exception_ring, last_resolution })`
  (bringup.rs:598–615), performed **AFTER spawn success**. The spawn-error arm
  (bringup.rs:617–653) now has **nothing to unwind** — the failed worker's
  `Arc` locals just drop. **The #4952 differential is now structural.**

The consequence for #6240: the launch loop that v1 called "283 LOC with 25
`coord.*` clones and a 40-arg closure" is now a **per-worker allocation block +
five bundle builds + one call + one post-success record insert**. Extracting a
`spawn_one_worker(...)` helper is now tractable in a way it was not at v1 time.

**Value is still readability/testability of a transaction, not performance.**
Every proposed boundary runs once per reconcile, never per packet / per worker
tick — there is no hot path to protect and no allocation budget to respect
(the bundles are *moved* in and destructured; zero added clone/alloc on the
launch path, per #6241's design note). The win is being able to reason about
and unit-test each phase in isolation. The residual risk is the failover
bring-up path, and it is now **materially lower** than v1 assessed because the
differential is structural AND already pinned by a fail-on-revert test (§9).

Verbatim, per the parent's standing instruction:

> If reviewers conclude the decomposition risks the failover bring-up path more
> than the modularity win justifies, PLAN-KILL is acceptable.

## 4. What is already shipped (the plan must compose with all of it)

| Issue | Owns | State |
|-------|------|-------|
| #1328 | original per-phase `reconcile/{teardown,reset,snapshot,bringup}.rs` split | shipped |
| #4952 | post-teardown SPAWN failure fails closed; launched workers RETAINED | shipped |
| #5143 | startup-readiness barrier (HEARTBEAT != READINESS); bind-incomplete → `stop_inner(false)` clears all | shipped |
| #5165 / #6314 | retain+join neighbor MONITOR / WARMER handles | shipped |
| #5289 | per-worker exception ring + last-resolution slot | shipped (folded into the record by #6242) |
| **#6244** | typed `ReconcileStage` (replaces the stage `String` side-channel; legacy strings preserved via `Display`) | **MERGED (PR #6347)** |
| **#6245** | explicit `BindingSetupFailure` (slot+phase+reason) surfaced through the barrier | **MERGED (PR #6348)** |
| **#6241** | typed 5-bundle worker-launch protocol | **MERGED (PR #6351)** |
| **#6242** | one transactional `WorkerRuntimeRecord` per worker (post-spawn-success insert) | **MERGED (PR #6357)** |
| **#6243** | unified activated+deferred map-pin preflight (`open_snapshot_maps`) | **MERGED (PR #6361)** |

The two issues v1 identified as the hard block (#6241 launch bundle, #6242
runtime record) are the two most important MERGES here. v1's PR-2 gate ("hold
until #6241/#6242 land") is therefore **lifted**. Per the issue's own
design-review amendment, #6240 is the umbrella that **consumes** these types and
performs the remaining mechanical phase extraction — it "must not independently
redesign launch bundles, runtime records, setup outcomes, or reconcile status."
That is exactly what is now possible: the redesign is done; #6240 is the
consume-and-extract.

## 5. Concrete design — phase helpers over the CURRENT function

Target module layout (the file is 909 LOC, above the modularity threshold for a
single file that also holds the transaction): convert `reconcile/bringup.rs`
into a `reconcile/bringup/` directory with a short shell in `mod.rs` and one
file per phase. `bring_up_workers`'s **signature and its sole caller
(`reconcile/mod.rs:391`) stay byte-identical** (§6). Every extracted helper
preserves side-effect ordering and every `last_reconcile_stage` write verbatim.

### CURRENT phase census (LOC ranges on master @ b8fd010b8)

| # | Phase | Lines | Touches | Extract class |
|---|-------|-------|---------|---------------|
| 0 | destructure `fds`, ring clamp | 104–132 | pure (+one eprintln) | **A cold** |
| 1 | build `workers` map + `live`/`identities` insert; sort | 133–168 | `&mut coord.workers` | A/B cohesive |
| 2 | shared-UMEM policy + status projection onto `bindings` | 169–192 | `bindings`, local (`apply_shared_umem_policy_to_workers` already a free fn) | **A cold** |
| 3 | sizing (`last_planned_*`) + `Planned` stage + eprintln | 193–215 | `&mut coord.workers`, `last_reconcile_stage` | A/B cohesive |
| 4 | BPF-FD ownership transfer into `coord.bpf_maps` | 216–223 | `&mut coord.bpf_maps` | A/B cohesive |
| 5 | `worker_binding_ifindexes` | 224–235 | pure local | **A cold** |
| 6 | CoS owner + mirror + active-shards + `refresh_cos_runtime_maps` | 236–249 | `&mut coord` (sub-builders already free fns / methods) | A/B cohesive |
| 7 | build `worker_command_queues` | 250–256 | pure local alloc | **A cold** |
| 8 | `replay_synced_sessions` + `ReplayedSynced` stage | 257–267 | `&mut coord` (method exists) | A/B cohesive |
| 9 | resolver launch — **PRE-worker** (guarded, install-on-success) | 268–331 | `&mut coord.neighbors` | A cold + ORDERING |
| 10 | **worker spawn loop** (per-worker alloc + 5 bundles + spawn + record insert / spawn-err break) | 332–655 | `&mut coord`, shared `worker_command_queues`, loop-local barrier state | **B transactional** |
| 11 | spawn-fail early return — **differential arm 1: NO `stop_inner`** | 656–669 | returns `Err(Spawn)` | B (differential) |
| 12 | readiness barrier + **differential arm 2: `stop_inner(false)`** | 670–701 | `&mut coord` | B (differential) |
| 13 | `Spawned` stage | 702–708 | `last_reconcile_stage` | A/B cohesive |
| 14 | monitor launch — **POST-readiness** (guarded) | 709–751 | `&mut coord.neighbors` | A cold + ORDERING |
| 15 | warmer launch — **POST-readiness** (guarded) | 752–795 | `&mut coord.neighbors` | A cold + ORDERING |
| 16 | `reconcile_local_tunnel_sources` + `spawn_wg_control_threads` | 796–802 | `&mut coord` (methods exist) | **A cold** |

### Proposed helpers (shell = a short sequence of named calls)

```
bring_up_workers(coord, snapshot, bindings, fds, ring_entries, preserved):
    let ring = clamp_ring_entries(ring_entries);                       // phase 0
    let (workers, session_map_raw_fd) =
        plan_workers(coord, bindings, &fds, ring);                     // phases 1–3
    publish_runtime(coord, &workers, fds);                             // phases 4,6 (FD xfer + CoS/mirror)
    let cmd_queues = build_worker_command_queues(workers.keys());      // phase 7
    replay_preserved_sessions(coord, &preserved, &cmd_queues, fd);     // phase 8
    ensure_resolver_before_worker_launch(coord);                       // phase 9 (PRE)
    match spawn_workers(coord, workers, &cmd_queues, dnat_fds,
                        &startup_report_tx):                           // phases 10–11
        LaunchOutcome::SpawnFailed(stage) =>
            return Err(WorkerBringUpError::Spawn(stage));  // arm 1: NO stop_inner
        LaunchOutcome::AllSpawned { spawned_ids, planned_by_worker } =>
            if let Some(stage) = await_readiness(&rx, &spawned_ids,
                                                 &planned_by_worker):  // phase 12
                coord.stop_inner(false);                   // arm 2: clear all
                coord.last_reconcile_stage = stage.clone();
                return Err(WorkerBringUpError::BindIncomplete(stage));
    coord.last_reconcile_stage = ReconcileStage::Spawned { … };        // phase 13
    start_post_readiness_neighbor_services(coord);                     // phases 14–15
    coord.reconcile_local_tunnel_sources();                            // phase 16
    coord.spawn_wg_control_threads();
    Ok(())
```

The single remaining transactional seam is `spawn_workers` + `await_readiness`.
Crucially, the **differential decision stays in the shell** (arm 1 returns
without `stop_inner`; arm 2 calls it) — the extraction makes the two-armed
rollback *more* visible, not less. `spawn_workers` returns a typed
`LaunchOutcome` enum; it never calls `stop_inner` itself.

### `spawn_one_worker` — now a clean per-iteration helper

Inside `spawn_workers`, the loop body (bringup.rs:350–654) extracts to
`spawn_one_worker(coord, worker_id, binding_plans, cmd_queues, dnat_fds,
&startup_report_tx) -> Result<SpawnedWorker, ReconcileStage>` because:

- the five `from_coord`/`new` bundle builders already encapsulate the shared
  `coord` borrows (no hand-threading of ~25 refs);
- the success path is one `records.insert` (returns the `planned_slots` +
  `worker_id` the barrier needs);
- the error path is: set `SpawnWorkerFailed` stage, push the control-notice
  exception, return `Err(stage)` — **no `.remove` unwinding**.

The `#[cfg(test)]` force-failure seams (bringup.rs:464–578, ~110 LOC) ride
`&mut coord` and travel with `spawn_one_worker`; they are already localized and
mutually exclusive per worker.

### Increment split

- **PR-1 — cold + cohesive phases (behavior-preserving).** Phases 0,2,5,7,16
  (pure) plus the cohesive `plan_workers` / `publish_runtime` /
  `replay_preserved_sessions` / `ensure_resolver` / `start_post_readiness_…`
  outlines. No change to *when/how* rollback fires. Smoke may batch with the
  next dataplane PR.
- **PR-2 — the transactional seam.** `spawn_workers` (+ `spawn_one_worker`) and
  `await_readiness`, with the differential kept in the shell. Mandatory
  `make test-failover` (v4+v6, push+reverse, CoS on/off). This is the only PR
  that touches the rollback path.

The split is now **prudent but optional** rather than blocked: PR-2's former
prerequisite gate is lifted, and the differential is structural + test-pinned.
A single-PR path is defensible if a reviewer prefers it; the recommendation is
the 2-PR increment so the one transactional seam gets its own failover smoke.

### Proposed pure signatures (PR-1 subset)

```rust
fn clamp_ring_entries(ring_entries: usize) -> u32;                    // pure
fn project_shared_umem_status(workers: &BTreeMap<u32, Vec<BindingPlan>>,
                              bindings: &mut [BindingStatus]);         // borrows bindings mut
fn worker_binding_ifindexes(workers: &BTreeMap<u32, Vec<BindingPlan>>)
    -> BTreeMap<u32, std::collections::BTreeSet<i32>>;                // pure
fn build_worker_command_queues(worker_ids: impl Iterator<Item = u32>)
    -> Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>>;       // pure
```

## 6. Public API preservation

- `pub(super) fn bring_up_workers(coord, snapshot, bindings, fds, ring_entries,
  preserved_synced_sessions) -> Result<(), WorkerBringUpError>` — signature
  unchanged.
- Sole caller `reconcile/mod.rs:391` unchanged; the unconditional
  `self.refresh_bindings(bindings)` at `:402` (runs on BOTH success and error)
  and the `bringup_result.map_err(...)` variant mapping at `:412–415` stay
  outside the function and are untouched.
- `WorkerBringUpError` (`Spawn(ReconcileStage)` / `BindIncomplete(ReconcileStage)`)
  and its → `ReconcileError::{WorkerSpawn, WorkerBindIncomplete}` mapping
  unchanged.
- `planned_worker_slots` and `collect_worker_startup_readiness` (already free
  fns in this module — the latter is the natural body of `await_readiness`)
  keep their behavior; `collect_worker_startup_readiness` can simply be renamed
  or wrapped.

## 7. Hidden invariants — each MUST be preserved

1. **The distinct post-teardown rollback contract (the #1 invariant).** The two
   failures roll back **differently**, deliberately, and #6242 made this
   **structural**:
   - *Spawn failure* (bringup.rs:617–669): sets `SpawnWorkerFailed`, `break`s,
     returns `Err(Spawn)` **WITHOUT** `stop_inner`. Already-launched workers'
     records stay in `coord.workers.records`; the next reconcile's teardown
     reclaims them. `reconcile/mod.rs` then `refresh_bindings` the partial
     state. Because registration is a post-spawn-success `records.insert`, the
     failed worker never registered — there is nothing to unwind.
   - *Bind-incomplete* (bringup.rs:680–701): `stop_inner(false)` stops+joins+
     clears ALL new workers (keeps preserved synced sessions).
   Any decomposition that unifies these into one "central rollback that always
   stops every launched worker" **changes documented #4952 behavior** and is a
   regression. The differential must stay in the shell.
2. **FD ownership vs. raw descriptors.** `OwnedFd`s move into `coord.bpf_maps`
   (bringup.rs:216–223); `BindingPlan` / `DnatTableFds` (`Copy`) carry the **raw
   integer** fds into workers. No phase output or rollback guard may drop an
   `OwnedFd` while a worker can still touch its raw descriptor. `stop_inner`
   encodes the safe order (`coordinator/mod.rs`): join workers → `stop_and_clear`
   (deletes XSK/heartbeat slots while FDs live) → only then set `bpf_maps.*_fd =
   None` (:673–679). Preserve it.
3. **Resolver-before-launch / monitor+warmer-after-readiness ordering.**
   `coord.neighbors.resolver` must exist before `spawn_workers` runs, because
   `WorkerSharedDataplane::from_coord` clones `coord.neighbors.resolver`
   (`worker/launch.rs:133`) for every worker. Monitor + warmer start only after
   the readiness barrier passes. The "launch → prove readiness → launch
   auxiliaries" gloss is **false for the resolver** — it is a *pre-launch*
   auxiliary. Type-enforce if feasible (open question §11.4).
4. **#5143 readiness barrier semantics.** Bounded 10s deadline
   (`WORKER_STARTUP_BARRIER_TIMEOUT_NS`), `bound == planned` per spawned worker,
   fail-closed on shortfall/timeout. The `startup_report` channel: the barrier
   relies on per-worker count + deadline, not on `tx` drop (the original `tx`
   stays alive in scope during the barrier). If the channel moves into
   `spawn_workers`, the `rx` must stay in the shell and the `tx` semantics must
   be preserved exactly (§11.3).
5. **#6245 explicit-failure render.** `WorkerBindShortfall.failures` →
   `ReconcileStage::WorkerBindIncomplete` `Display` (`failures=[…]` /
   `[no-explicit-failure]`), surfaced by `collect_worker_startup_readiness`.
6. **CoS/mirror publication before launch** (bringup.rs:236–249) — workers read
   these immutable inputs; must precede the spawn loop.
7. **Preserved-session replay timing** (bringup.rs:250–267) — seeds the session
   map + command queues before workers launch; count feeds `ReplayedSynced`.
8. **The record is ONE post-success `insert`; the spawn-err arm has NO
   `.remove`** (#6242). Any extraction that reintroduces a pre-spawn insert (and
   therefore a spawn-err unwind) regresses the structural differential — pinned
   by the test in §9.
9. **Sparse worker-id sizing** — `planned_worker_slots = max(id)+1`, not
   `len()` (bringup.rs:903–909; v8 lease arrays index by id).
10. **Stage-write ordering** — `Planned` → (`ReplayedSynced`) →
    `SpawnWorkerFailed` | `Spawned` | `WorkerBindIncomplete`; #6244 removed the
    `stop_inner` stage write, so the typed identity is recorded once and
    survives (bringup.rs:694–700).
11. **Warmer's best-effort spawn result** (bringup.rs:783–794) — do NOT
    incidentally "fix" the logged-`Err` arm; that is behavior, not motion.

## 8. Risk table

| Risk | Level (v1 → v2) | Notes |
|------|-----------------|-------|
| Behavioral — rollback semantics changed (unify differential) | HIGH → **HIGH but well-fenced** | Only PR-2 touches it; #6242 made it structural + it is pinned by `reconcile_partial_spawn_failure_preserves_launched_records_6242` (fail-on-revert already GREEN on master). |
| Failover-path regression (post-teardown bring-up on recovering node) | HIGH → **MED for PR-2 / LOW for PR-1** | PR-2 mandates `make test-failover`; PR-1 is behavior-preserving motion. |
| Borrow-checker — extracting the launch body | HIGH → **LOW** | #6241 bundles encapsulate the coord borrows; #6242 record is one insert. `spawn_one_worker` no longer threads ~25 refs — this is the core v1→v2 change. |
| Architectural mismatch — is "explicit pipeline" the right shape? | MED–HIGH → **LOW–MED** | The bundles/record supply real phase boundaries; the shell keeps the one shared-transaction seam (`spawn_workers`) explicit rather than pretending it decomposes further. |
| Coupled-issue ordering — racing/duplicating siblings | MED → **NONE** | #6241–#6245 all MERGED; #6240 now purely consumes them. |
| Test blind spot — no partial-success characterization | MED → **CLOSED** | #6242 shipped the N-worker fail-at-K test + the symmetric bind-incomplete-clears-all test (§9). |
| `#[cfg(test)]` seams travel with `spawn_one_worker` (~110 LOC) | new / LOW | Already localized + mutually exclusive per worker; carry verbatim. |
| Docs drift — architecture / coordinator README / packet-processing docs describe bringup | LOW | Update the module map in the PR that moves code (per CLAUDE.md docs contract). |

## 9. Test plan

- **Full cargo suite** — `TMPDIR=/tmp cargo test --manifest-path
  userspace-dp/Cargo.toml --bin xpf-userspace-dp` (short TMPDIR per the
  socket-bind gotcha).
- **The fail-on-revert anchors already exist on master and must stay green:**
  - `reconcile_post_teardown_worker_spawn_failure_fails_closed_4952`
    (tests.rs:3791)
  - `post_spawn_inthread_bind_failure_fails_closed_5143` (tests.rs:3879)
  - **`reconcile_partial_spawn_failure_preserves_launched_records_6242`
    (tests.rs:3990)** — the N-worker fail-at-K partial-success test v1 said was
    a MISSING prerequisite. #6242 shipped it: it launches workers 0/1 as healthy
    stubs, forces worker 2's spawn to fail, and pins that records 0/1 SURVIVE
    (differential arm 1) while worker 2 has none. **This is the primary
    fail-on-revert for any PR-2 rollback motion — and it is already GREEN.**
  - `reconcile_bind_incomplete_clears_all_records_6242` (tests.rs:4069) — the
    symmetric pin: bind-incomplete clears ALL records (differential arm 2).
  - `stop_inner_drops_worker_record_owners_exactly_once_6242` (tests.rs:4110)
  - `worker_bind_incomplete_report_carries_explicit_failure_6245` (tests.rs:4176)
  - the `Arc::ptr_eq` bundle wiring tests in `worker/launch.rs`.
- **Server no-persist tests** (`server/tests.rs`) — `…spawn_failure_fails_closed_
  no_persist_4952` / `…6140` / the bind-incomplete server test.
- **New unit tests for the shell (PR-2):** assert no auxiliaries (monitor/warmer)
  start before the readiness barrier passes; assert the resolver exists before
  `spawn_workers` (ordering guard); assert `spawn_workers` returns
  `SpawnFailed` WITHOUT calling `stop_inner` and `await_readiness` shortfall DOES.
- **Loss-cluster `make test-failover` (MANDATORY for PR-2)** — this is the
  failover bring-up path; batched v4+v6, push+reverse, CoS on/off. PR-1 (pure
  motion) may batch its smoke with the next dataplane PR.

## 10. Out of scope / deferred

- Any change to *when* rollback fires or *which* workers it stops (a #4952
  correctness decision, not this refactor).
- Re-designing the launch bundles (#6241), the runtime record (#6242), the
  setup-failure type (#6245), the reconcile stage (#6244), or the map-pin
  preflight (#6243) — all MERGED; #6240 CONSUMES them.
- The warmer's best-effort spawn-result handling (behavior, not motion).
- A staged spawn-before-teardown (a possible follow-up noted in the function
  doc, out of scope here).
- Moving the neighbor-service launches onto `NeighborManager` (the amendment's
  suggestion) — a first cut may keep them as `bringup/` free fns; the promotion
  is a nice-to-have, not required.

## 11. Open questions for adversarial review (each PLAN-KILL-invitable)

1. **Is this now DRIVEABLE-TO-MERGE, or still class-B-risky?** My firsthand read:
   the merged bundles (#6241) + record (#6242) did the hard type-work, so the
   decomposition is now **near code-motion** for phases 0–9,13–16 and one
   contained transactional seam (`spawn_workers`/`await_readiness`) whose
   differential is structural + test-pinned. Is that read correct, or does the
   shared `&mut coord` transaction still resist clean phase extraction badly
   enough to warrant PLAN-KILL / staying inline?
2. **Is PR-1 net-positive, or churn?** The pure cold blocks are ~55–70 LOC; the
   cohesive `plan_workers`/`publish_runtime`/`replay` outlines are larger but
   still `&mut coord`. Does splitting them into named helpers meaningfully
   shrink the transaction's cognitive load, or just add call sites to a body
   whose complexity lives entirely in `spawn_workers`? If the latter, PR-1 could
   be dropped and only `spawn_workers`/`await_readiness` extracted.
3. **Startup-report channel ownership.** The barrier currently relies on
   per-worker count + a bounded deadline, with the original `startup_report_tx`
   still alive in scope during `collect_worker_startup_readiness`. If the
   channel + `tx` clones move into `spawn_workers`, does keeping `rx` in the
   shell preserve the exact fail-fast/timeout semantics, or does a subtly
   different `tx`-drop lifetime change when `recv_timeout` sees `Disconnected`?
   (A concrete trace is needed before PR-2.)
4. **Resolver ordering trap.** With `ensure_resolver_before_worker_launch` and
   `spawn_workers` as separate helpers, what *statically* stops a future edit
   from calling them out of order (silently breaking the
   `WorkerSharedDataplane::from_coord` resolver clone)? Is a doc-comment + an
   ordering unit test enough, or should the resolver handle be threaded INTO
   `spawn_workers` as a required argument so the ordering is type-enforced?
5. **1 PR or 2?** Given the differential is structural + already test-pinned, is
   the 2-PR increment (cold/cohesive, then transactional-with-failover-smoke)
   the right call, or is a single behavior-preserving PR with the mandatory
   `make test-failover` simpler and equally safe? (Recommendation: 2-PR, but
   invite the reviewer to collapse it.)
6. **Does #6240 still have a coherent standalone identity?** With #6241–#6245
   merged, is `spawn_workers`/`await_readiness` + the cohesive phase outlines
   enough distinct work to justify a standalone #6240, or should it be reframed
   as a thin final cleanup (or closed as substantially-satisfied-by-its-
   siblings, with only the shell extraction remaining)?
7. **`#[cfg(test)]` seam placement.** The ~110 LOC of force-failure seams are
   interleaved in the spawn decision. Should `spawn_one_worker` carry them
   verbatim (simplest, preserves the mutual-exclusion), or is there a cleaner
   seam boundary that does not risk the #4952/#5143/#6242 test contracts that
   depend on the exact seam ordering (`force_worker_bind_incomplete` checked
   before `force_worker_spawn_fail`, `_skip` decrement on the healthy-stub arm)?
