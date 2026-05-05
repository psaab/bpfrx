---
status: REVISED v2 — Codex round-1 PLAN-NEEDS-MAJOR; scope narrowed per Codex's findings
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

### Coordinator's worker-supervision surface

Need to identify which methods on `Coordinator` are
worker-supervision concerns. Candidates (subject to
implementation-phase audit):

- `spawn_worker(...)` and the supervision loop
- `WorkerCommand` dispatch path
- Worker liveness tracking
- Per-worker init / shutdown ordering

These methods become methods on `WorkerManager`, with
`Coordinator` owning a `WorkerManager` field and delegating.

### `worker_manager.rs` grows

Currently 31 LOC of stub. Will absorb the migrated methods.

### Call sites

`Coordinator::spawn_worker` callers (etc.) keep their interface
via delegation: `Coordinator::spawn_worker` → `self.worker_manager.spawn(...)`.
External callers see no change.

## 4. Concrete design

1. **Audit `mod.rs` for worker-related methods** — produce a
   list with line numbers (do this in implementation phase, not
   plan).

2. **Lift each method to `WorkerManager`**, preserving behavior.
   Where a method needs access to fields outside
   `WorkerManager`'s scope, pass them as `&mut` parameters
   rather than absorbing the field into `WorkerManager` (avoids
   ownership refactor cascade).

3. **`Coordinator` keeps a thin delegation layer**: each old
   `Coordinator::method()` becomes
   `self.worker_manager.method(self.peer_field, ...)`.

4. **Tests**: existing `coordinator/tests.rs` (1016 LOC) covers
   the public-API behavior; should pass unchanged. If any test
   reaches into private worker-state directly, relocate it.

5. **No behavior change**: every method's body moves verbatim;
   only the receiver type changes.

## 5. Public API preservation

`Coordinator::spawn_worker(...)` (etc.) — keep all public
signatures unchanged. Internal call site changes from `self.x`
to `self.worker_manager.x`.

## 6. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | Pure code motion + delegation |
| Borrow-checker / lifetime | **MEDIUM** | If a method needs `&mut self.coordinator_field` AND `&mut self.worker_manager`, Rust's split-borrow may refuse |
| Cross-manager coupling | **MEDIUM** | Worker supervision may touch HA state, neighbor state, etc. — split-borrow concerns multiply |
| Test breakage | LOW | `tests.rs` should pass unchanged; relocate any private-field reaches |
| Performance regression | LOW | Delegation adds one indirection per call; not on per-packet hot path |

The Rust borrow-checker risk is the dominant one. Mitigation:
where a method spans multiple managers' state, keep it on
`Coordinator` with a comment "spans multiple managers' state;
not migrated to a manager" — leave for future refactor with a
proper redesign.

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
