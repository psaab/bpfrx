---
status: DRAFT v1 — pending adversarial plan review (Phase 1 / WorkerManager only)
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

## 2. Honest scope/value framing

**This PR ships ONE manager surface only — `WorkerManager`** —
to validate the migration shape before committing to the full
4-manager decomposition. Migrating all four at once would be a
multi-thousand-line PR with high merge-conflict surface.

Win:

- `coordinator/mod.rs` shrinks by the worker-supervision LOC
  (estimated ~300-500 lines)
- `worker_manager.rs` grows from 31 LOC stub to a real
  `WorkerManager` with the moved methods
- Future PRs can do `ConfigManager`, `NeighborManager`,
  `SessionManager` as independent migrations
- Each migration is **pure code motion + delegation** — no
  behavior change

**If reviewers find any cross-manager state coupling that
prevents clean extraction (e.g., `WorkerManager` methods access
private fields of `Coordinator` that other managers also need),
PLAN-NEEDS-MAJOR is the right call.**

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
