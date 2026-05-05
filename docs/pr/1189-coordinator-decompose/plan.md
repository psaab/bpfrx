---
status: REVISED v3 — Codex round-2 PLAN-NEEDS-MINOR; deleted v1 residue, reframed stop extraction with fd inputs, moved spawn_supervised_aux out of WorkerManager, documented test path updates
issue: #1189
phase: First incremental migration of one manager surface
---

## 1. Issue framing

Issue #1189: `coordinator/mod.rs` is currently 1,959 lines
("3,000-line monolith" in the issue body — actual count is
1,959, with manager stubs already split out as separate files
totalling ~290 LOC). Codex's Tier D review confirmed direction
is right but premise is partially stale (decomposition started,
just not finished).

Current state:

```
coordinator/
  bpf_maps.rs            16 LOC
  cos_state.rs           26 LOC
  ha_state.rs            25 LOC
  inject.rs              154 LOC  (active — packet inject path)
  mod.rs                 1959 LOC (the monolith)
  neighbor_manager.rs    19 LOC   (stub)
  session_manager.rs     30 LOC   (stub)
  status.rs              191 LOC  (active — status surface)
  tests.rs               1016 LOC
  worker_manager.rs      31 LOC   (stub)
```

The named manager files exist as types but are mostly empty
shells; the real logic lives in `mod.rs`'s `Coordinator` impl.

## 2. Honest scope/value framing — v2 (narrowed per Codex round-1)

**Important correction:** `WorkerManager` already exists as a
struct (`coordinator/worker_manager.rs:13-19`) with the right
fields (`live`, `identities`, `handles`, `last_planned_*`).
`Coordinator` already owns it via `pub(in crate::afxdp) workers:
WorkerManager` field. This PR is NOT "create WorkerManager" —
it's **migrate selected worker-related METHODS from `impl
Coordinator` into `impl WorkerManager`**.

**Codex round-1 narrowed the scope.** The original plan said
"extract worker supervision" but Codex caught:

1. The named `Coordinator::spawn_worker` doesn't exist — worker
   spawn is embedded in `Coordinator::reconcile`
   (`mod.rs:322,630`) which passes 12+ deps to `worker_loop`
   (HA runtime, shared forwarding, fabrics, RG epochs, sessions,
   neighbors, slow path, local tunnel, CoS shared maps, event
   stream, panic slots, recent status queues).
2. `WorkerCommand` dispatch is owned by HA paths
   (`ha.rs:40,102,171,310,366`), not just worker supervision.
3. Tests reach private worker state directly
   (`coordinator/tests.rs:312,840,958`,
   `ha_tests.rs:235`).

So `reconcile` and HA command dispatch CANNOT migrate cleanly
in Phase 1. They span too many managers' state.

**Phase 1 v2 — concrete movable slices only:**

- `panic_payload_message` helper (free function or method;
  pure formatting)
- `spawn_supervised_worker` / `spawn_supervised_aux` (the panic-
  catch wrapper; depends only on `WorkerHandle` lifecycle, no
  cross-manager state)
- Worker stop/clear loops at `mod.rs:202-222` (iterate
  `self.workers.handles` to send shutdown / await joins / clear)
- `last_planned_workers` / `last_planned_bindings` accessor
  methods (currently inline; pure getter wrappers)

**Stays on `Coordinator` for Phase 1:**

- `reconcile` (multi-manager state)
- HA command dispatch in `ha.rs` (HA-owned)
- `refresh_bindings` (CoS / forwarding / worker state span)
- CoS refresh
- Neighbor monitor
- Local tunnel source spawning

**Follow-up phases (not this PR):** larger extractions of
`reconcile` or HA dispatch require a `WorkerSpawnDeps` /
context type design — out of scope here.

Win for Phase 1:
- `coordinator/mod.rs` shrinks by ~50-150 LOC (the panic /
  shutdown / accessor helpers)
- `worker_manager.rs` grows from 31 LOC stub with `new()` only
  to ~120-200 LOC with the migrated methods
- Validates the migration shape (delegation pattern + test
  access via `pub(in crate::afxdp)` field) before larger
  extractions
- Each migrated method is **pure code motion** — body verbatim,
  receiver type changes from `&mut Coordinator` (or `&self`) to
  `&mut WorkerManager` (or `&self`). No behavior change.

**Hard rule (Codex round-1 #4):** WorkerManager methods MUST
NOT take `&mut Coordinator`. If a method needs Coordinator-only
state, it stays on Coordinator.

## 3. Code paths affected

### `coordinator/mod.rs` — items leaving the file

Phase 1 v3 moves four concrete slices out of `mod.rs`:

1. **`panic_payload_message(payload: &Box<dyn Any + Send>) -> String`**
   — pure free function (`mod.rs:~1080`). Becomes a `pub(super)`
   free function in a new `coordinator/supervisor.rs` (rationale
   below).
2. **`spawn_supervised_worker(...)`** — the panic-catch wrapper
   for the per-worker `worker_loop` thread. Pure code motion to
   `coordinator/supervisor.rs` as a `pub(super)` free function.
   It already takes its dependencies as parameters and does not
   touch `Coordinator` or `WorkerManager` state.
3. **`spawn_supervised_aux(...)`** — the panic-catch wrapper for
   *non-worker* aux threads (currently used by the neighbor
   monitor at `mod.rs:780` and the local-tunnel source at
   `mod.rs:830`). This is **not** worker-lifecycle and must not
   live on `WorkerManager`. Lands in `coordinator/supervisor.rs`
   alongside `spawn_supervised_worker` as a `pub(super)` free
   function.
4. **Worker stop/clear loop** at `mod.rs:202-222` (iterate
   `self.workers.handles` to send shutdown / await joins / drop
   `xsk_map`/`heartbeat_map` entries / clear `handles`). Becomes
   a method `WorkerManager::stop_and_clear(&mut self,
   xsk_map_fd: BorrowedFd<'_>, heartbeat_map_fd: BorrowedFd<'_>)`.
   The map fds are passed in because they live on `Coordinator`
   (or one of its sub-managers), not `WorkerManager`.
5. **Accessor wrappers** for `last_planned_workers` /
   `last_planned_bindings` — trivial `&self` getters added on
   `WorkerManager`, then `mod.rs` reads `self.workers.last_planned_workers()`
   instead of `self.workers.last_planned_workers` directly. Pure
   wrapper change; no behavior change.

### What **stays on `Coordinator`** in Phase 1

- `Coordinator::reconcile` (multi-manager state).
- HA `WorkerCommand` dispatch in `ha.rs:40,102,171,310,366` (HA-owned).
- `refresh_bindings` (CoS / forwarding / worker state span).
- `worker_panics.clear()` — the panic-tracking map is a
  `Coordinator` field, not a `WorkerManager` field. Phase 1 keeps
  the clear in `Coordinator` and only moves the handle-iteration
  / join / map-cleanup loop into `WorkerManager::stop_and_clear`.
- Neighbor monitor and local-tunnel source supervision (they
  call `spawn_supervised_aux` after this PR; `Coordinator` still
  owns the join handles).

### `coordinator/supervisor.rs` (new file, ~80-120 LOC)

New sibling of `worker_manager.rs` holding the three free
functions above. Visibility: `pub(super)` so `mod.rs` and
`worker_manager.rs` can call into it without exposing the
helpers crate-wide.

### `worker_manager.rs` grows

From 31 LOC stub (struct + `new()`) to ~60-90 LOC: add
`stop_and_clear(...)` plus `last_planned_workers()` /
`last_planned_bindings()` accessors.

### Test surface

Existing tests at `coordinator/tests.rs:312,840,958` and
`ha_tests.rs:235` reach into worker-related items directly:

- `tests.rs:312,840,958` reference `super::panic_payload_message`
  and `super::spawn_supervised_worker` /
  `super::spawn_supervised_aux` from inside the
  `coordinator::tests` module.

After the move, `super::panic_payload_message` etc. resolve into
`coordinator::supervisor::panic_payload_message`. Two equally
valid options — pick one in implementation:

- **Option A (preferred):** update test paths to
  `super::supervisor::panic_payload_message` etc. Cleaner; no
  re-export.
- **Option B:** add `pub(super) use supervisor::{panic_payload_message,
  spawn_supervised_worker, spawn_supervised_aux};` in `mod.rs`
  so test paths stay unchanged. Smaller diff but adds a
  coordinator-module re-export.

`ha_tests.rs:235` reaches `super::ha::*` worker-command sites
which are NOT moved in Phase 1 — those tests are unaffected.

## 4. Concrete design

1. Create `coordinator/supervisor.rs`. Move
   `panic_payload_message`, `spawn_supervised_worker`, and
   `spawn_supervised_aux` into it as `pub(super)` free
   functions. Body verbatim (these already take their deps as
   parameters; no receiver change needed).
2. Add `mod supervisor;` to `coordinator/mod.rs`.
3. Add method `pub(super) fn stop_and_clear(&mut self,
   xsk_map_fd: BorrowedFd<'_>, heartbeat_map_fd: BorrowedFd<'_>)`
   to `WorkerManager`. Body is the existing `mod.rs:202-222`
   loop with `self.workers.` references rewritten to `self.`.
   `Coordinator::shutdown` (or wherever the loop lives today)
   becomes:

   ```rust
   self.workers.stop_and_clear(
       self.xsk_map.as_fd(),
       self.heartbeat_map.as_fd(),
   );
   self.worker_panics.clear();   // stays on Coordinator
   ```

4. Add `last_planned_workers(&self) -> usize` and
   `last_planned_bindings(&self) -> usize` accessors on
   `WorkerManager`. Update mod.rs read sites to call the
   accessors. (Field visibility unchanged: still
   `pub(in crate::afxdp)` for write access in `reconcile`.)
5. Update test paths per Option A or Option B above.
6. Verify nothing else references `Coordinator::panic_payload_message`,
   `Coordinator::spawn_supervised_worker`, or
   `Coordinator::spawn_supervised_aux`.

**Hard rule (Codex round-1 #4):** WorkerManager methods MUST NOT
take `&mut Coordinator`. `stop_and_clear` complies — it takes
borrowed fds, not the parent.

**Honesty about "pure code motion":** the supervisor functions
move verbatim. `stop_and_clear` is **not** byte-identical to the
old loop body — it loses the implicit `self.workers.` qualifier
on every reference and gains explicit fd parameters at the call
site. Behaviorally identical, but the body is rewritten, not
copy-pasted. Accessor wrappers are obviously not byte-identical
either. Phase 1 is "behavior-preserving refactor", not "byte-
verbatim move".

## 5. Public API preservation

No external (non-`afxdp`) signatures change. Within `afxdp`:

- `Coordinator::shutdown` (or whichever entry owns the
  stop loop) keeps its signature; its body now calls
  `self.workers.stop_and_clear(...)` and then
  `self.worker_panics.clear()`.
- `panic_payload_message`, `spawn_supervised_worker`,
  `spawn_supervised_aux` change resolution path from
  `coordinator::*` to `coordinator::supervisor::*`. With
  Option B re-exports their old paths still resolve.
- New: `WorkerManager::stop_and_clear`,
  `WorkerManager::last_planned_workers`,
  `WorkerManager::last_planned_bindings` — all `pub(super)` /
  `pub(in crate::afxdp)`.

## 6. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | Supervisor helpers move verbatim; `stop_and_clear` is the same loop with explicit fd params; accessors are trivial getters |
| Borrow-checker / lifetime | LOW-MED | `stop_and_clear` takes `BorrowedFd<'_>` so it does not double-borrow `self` while mutating `self.workers`. The map fds live on `Coordinator`, not under `self.workers`, so the split-borrow is clean |
| Cross-manager coupling | LOW | Phase 1 explicitly excludes anything that spans multiple managers (reconcile, HA dispatch, refresh_bindings, neighbor/tunnel supervision lifecycle) |
| Test path breakage | LOW | Predictable: tests need either updated `super::supervisor::*` paths or a re-export in `mod.rs`. Documented above |
| Performance regression | LOW | `stop_and_clear` runs at shutdown only; accessor wrappers compile to direct field reads |

## 7. Test plan

**Cargo build**: clean.

**Cargo tests**: `cargo test --release` — all 952+ pass.

**5x flake check** on the most affected named test (probably
something in `coordinator/tests.rs`).

**Go tests**: unaffected (Rust-only).

**Smoke matrix on loss userspace cluster**:
- Pass A (CoS off): 6 cells, 0 retrans
- Pass B (CoS on): 24 cells, 0 retrans
- Total: 30 cells, 0 retrans (this is pure code motion + delegation)

**Failover smoke**: `make test-failover` if accessible — the
worker-supervision path is exercised heavily during failover.

## 8. Out of scope

- Migrating ConfigManager, NeighborManager, SessionManager —
  each is its own follow-up PR
- Adding tests for `WorkerManager` in isolation (the issue body
  cites "untestable"; making it testable is part of the value
  but adding new unit tests is follow-up work, not blocking
  this PR)
- Renaming any methods or changing signatures
- Splitting `tests.rs` into per-manager test files

## 9. Open questions for adversarial review

1. Is `WorkerManager` the right first target, or would
   `NeighborManager` / `SessionManager` be lower-coupling and
   thus a better Phase 1?
2. How tangled is worker supervision with HA state in the
   current `mod.rs`? If extraction requires touching HA state
   too, that's a Phase 1.5 (or a different first target).
3. Will the 1016-line `tests.rs` break in non-obvious ways?
   Specifically, do any tests construct `Coordinator` and then
   call worker-related private methods?
4. Does the existing `worker_manager.rs` (31 LOC stub) have any
   committed direction the migration must follow, or is it an
   empty starting point?

## 10. Verdict request

PLAN-READY → execute Phase 1 (WorkerManager only).
PLAN-NEEDS-MINOR → tweak choice or scope, then execute.
PLAN-NEEDS-MAJOR → revise (e.g., different first manager).
PLAN-KILL → premise wrong; e.g., extraction structurally
impossible due to coupling.
