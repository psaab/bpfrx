# #1345 Step 1 — Split `server/handlers.rs` 415-LOC `handle_stream` dispatcher into per-verb modules

**Status:** v3 — addresses AGY r1 PLAN-KILL (v2) + AGY r2 PLAN-NEEDS-MINOR
(helper call substitution clarification) + Codex r2 PLAN-NEEDS-MAJOR
findings on v1 (all already addressed in v2 by dropping HandlerCtx
in favor of by-value moves). Pending Codex r3 plan-review on v3.

## Round-1 AGY findings — disposition

AGY r1 returned PLAN-KILL with 5 findings. Disposition:

1. **"Thin Rust test coverage — only apply_snapshot has e2e handle_stream coverage."**
   **ACCEPTED.** Confirmed by `grep request_type userspace-dp/src/main_tests.rs`:
   only `apply_snapshot` is exercised end-to-end (lines 986, 1009, 1053, 1100).
   18 other verbs have zero direct Rust e2e tests. Mitigation: the refactor
   is **pure code motion** — each per-verb file gets the same byte-identical
   body that lives inside the match arm today. The Go control plane is the
   real consumer of these verbs and its test suite (`pkg/dataplane/userspace/`,
   `pkg/cluster/`) drives them transitively via the wire protocol. The
   plan now documents the coverage gap explicitly in §Test plan and lists
   it as a non-blocker for code motion.
2. **"16 files is over-fragmentation; many arms are 3-5 LOC."**
   **PARTIALLY ACCEPTED.** Wave-1 rule from the user says one file per
   protocol verb. Project memory `feedback_refactor_module_dir_layout`
   ratifies the directory-with-`mod.rs` shape. But trivial arms (≤5 LOC
   body, single helper call) stay inline in `mod.rs`'s match — spinning
   out a 1-3 LOC file is silly cohesion. New cut: substantive verbs get
   their own file; trivial ones stay in the dispatcher. Counted below.
3. **"ConfigSnapshot.clone() is wasteful — apply_snapshot is large."**
   **ACCEPTED.** v2 takes each `Option<T>` field by value (move) into
   the per-verb handler. Zero new clones. Borrow shape becomes simpler
   too (no `HandlerCtx<'_>` lifetime struct).
4. **"`mod.rs` is outdated style."**
   **REJECTED — project counter-evidence.** `feedback_refactor_module_dir_layout`
   in user's memory codifies the directory-with-`mod.rs` style as the
   project standard. The wave-1 instruction also explicitly mandates
   `handlers/mod.rs`, not `handlers.rs` + sibling `handlers/`.
5. **"refresh_status double-call is wasteful, not invariant."**
   **REJECTED for THIS PR — out of scope.** This refactor is pure code
   motion. Deduplicating refresh_status calls would convert the PR
   into a behavior change. Deduplication is a separate follow-up that
   needs its own analysis (some arms rely on the eager call to update
   `binding.last_change` before the post-match status snapshot reads
   it).

## Issue framing

`userspace-dp/src/server/handlers.rs` is 461 LOC and consists almost
entirely of one function: `handle_stream()` at lines 16-461. It is a
single `match request.request_type.as_str()` dispatcher over 19
verbs on the control-socket wire.

`docs/engineering-style.md` defines the soft cap at 100 LOC per
function and the hard Tier-1 cap at 200 LOC. The body is >4x the
soft cap and >2x the hard cap.

## Honest scope/value framing

This is **pure code motion**. The transport (BufReader/BufWriter),
request decode, response encode, locking discipline (`state.lock()`
guard, single critical section, optional `write_state` after) all
stay byte-identical. Substantive match arms become per-verb files;
trivial arms stay inline.

The win is **readability and review tractability**: today nobody
reviews the 415-LOC body end-to-end; tomorrow each substantive verb
is independently inspectable in 20-100 LOC.

No perf claim — control-socket path, not per-packet. **No new
clones** in v2 (changed from v1 after AGY r1 finding).

If reviewers conclude the readability gain is not worth the file
multiplication churn, PLAN-KILL is an acceptable verdict.

## Verb inventory (per current `handlers.rs`)

| # | Verb | Lines | Body LOC | Disposition |
|---|---|---|---|---|
| 1 | `ping` \| `status` | 52 | 0 (no-op) | INLINE — empty arm |
| 2 | `apply_snapshot` | 53-131 | 78 | **FILE** snapshot.rs |
| 3 | `set_forwarding_state` | 132-155 | 23 | **FILE** forwarding.rs |
| 4 | `update_ha_state` | 156-179 | 23 | **FILE** ha.rs |
| 5 | `update_fabrics` | 180-185 | 5 | INLINE — single helper call |
| 6 | `update_neighbors` | 186-208 | 22 | **FILE** neighbors.rs |
| 7 | `bump_fib_generation` | 209-225 | 16 | **FILE** snapshot.rs (joins apply_snapshot) |
| 8 | `clear_policy_counters` | 226-230 | 4 | INLINE — 3-line body |
| 9 | `set_queue_state` | 231-264 | 33 | **FILE** queue.rs |
| 10 | `set_binding_state` | 265-291 | 26 | **FILE** binding.rs |
| 11 | `inject_packet` | 292-308 | 16 | **FILE** inject_packet.rs |
| 12 | `sync_session` | 309-342 | 33 | **FILE** sync_session.rs |
| 13 | `drain_session_deltas` | 343-353 | 10 | **FILE** session_deltas.rs |
| 14 | `export_owner_rg_sessions` | 354-370 | 16 | **FILE** export.rs |
| 15 | `export_all_sessions` | 371-379 | 8 | **FILE** export.rs (joins export_owner_rg) |
| 16 | `rebind` | 380-408 | 28 | **FILE** rebind.rs |
| 17 | `stop_workers` | 409-433 | 24 | **FILE** stop_workers.rs |
| 18 | `shutdown` | 434-438 | 4 | INLINE — 3-line body, only `running` toucher |
| 19 | catch-all `other` | 439-442 | 3 | INLINE — error path |

**File count: 13** (down from v1's 16). Trivial arms (`ping`/`status`,
`update_fabrics`, `clear_policy_counters`, `shutdown`, catch-all)
stay inline in `mod.rs`'s match. **The `shutdown` arm staying inline
also keeps `running: Arc<AtomicBool>` private to `handlers/mod.rs`**
— no per-verb file needs to touch it.

`apply_snapshot` + `bump_fib_generation` share `snapshot.rs` (both
pivot on `request.snapshot`). `export_owner_rg_sessions` +
`export_all_sessions` share `export.rs` (both produce session
deltas). Other verbs get their own file.

## Concrete design (v2)

### Target layout

```
userspace-dp/src/server/
├── handlers/
│   ├── mod.rs                       # handle_stream + dispatch shell + trivial arms
│   ├── snapshot.rs                  # apply_snapshot, bump_fib_generation
│   ├── forwarding.rs                # set_forwarding_state
│   ├── ha.rs                        # update_ha_state
│   ├── neighbors.rs                 # update_neighbors
│   ├── queue.rs                     # set_queue_state
│   ├── binding.rs                   # set_binding_state
│   ├── inject_packet.rs             # inject_packet
│   ├── sync_session.rs              # sync_session (upsert + delete branches)
│   ├── session_deltas.rs            # drain_session_deltas
│   ├── export.rs                    # export_owner_rg_sessions, export_all_sessions
│   ├── rebind.rs                    # rebind
│   └── stop_workers.rs              # stop_workers
├── helpers.rs                       # unchanged
├── lifecycle.rs                     # unchanged
├── mod.rs                           # unchanged re-exports
└── state.rs                         # unchanged
```

### Dispatch shell (v2)

```rust
pub(crate) fn handle_stream(
    stream: UnixStream,
    state_file: &str,
    state: Arc<Mutex<ServerState>>,
    running: Arc<AtomicBool>,
) -> Result<(), String> {
    // (timeouts, reader, decode — byte-identical to today)
    let request: ControlRequest = ...;

    let mut response = ControlResponse {
        ok: true,
        error: String::new(),
        status: None,
        session_deltas: Vec::new(),
    };
    let mut persist_state = false;
    let suppress_status = request.suppress_status;

    {
        let mut guard = state.lock().expect("server state poisoned");
        match request.request_type.as_str() {
            "ping" | "status" => {}
            "apply_snapshot" =>
                snapshot::apply(&mut guard, request.snapshot, &mut response, &mut persist_state),
            "set_forwarding_state" =>
                forwarding::set(&mut guard, request.forwarding, &mut response, &mut persist_state),
            "update_ha_state" =>
                ha::update(&mut guard, request.ha_state, &mut response, &mut persist_state),
            "update_fabrics" => {
                if let Some(fabrics) = request.fabrics.as_ref() {
                    guard.afxdp.refresh_fabric_links(fabrics);
                    refresh_status(&mut guard);
                }
            }
            "update_neighbors" =>
                neighbors::update(&mut guard, request.neighbors.as_ref(), request.neighbor_replace),
            "bump_fib_generation" =>
                snapshot::bump_fib(&mut guard, request.snapshot.as_ref(), &mut response),
            "clear_policy_counters" => {
                guard.afxdp.clear_policy_counters();
                refresh_status(&mut guard);
                persist_state = true;
            }
            "set_queue_state" =>
                queue::set(&mut guard, request.queue, &mut response, &mut persist_state),
            "set_binding_state" =>
                binding::set(&mut guard, request.binding, &mut response, &mut persist_state),
            "inject_packet" =>
                inject_packet::handle(&mut guard, request.packet, &mut response, &mut persist_state),
            "sync_session" =>
                sync_session::handle(&mut guard, request.session_sync, &mut response),
            "drain_session_deltas" =>
                session_deltas::drain(&mut guard, request.session_deltas.as_ref(),
                                      &mut response, &mut persist_state),
            "export_owner_rg_sessions" =>
                export::owner_rg(&mut guard, request.session_export,
                                 &mut response, &mut persist_state),
            "export_all_sessions" =>
                export::all(&mut guard, &mut response),
            "rebind" =>
                rebind::handle(&mut guard, &mut persist_state),
            "stop_workers" =>
                stop_workers::handle(&mut guard, &mut persist_state),
            "shutdown" => {
                guard.afxdp.stop_with_event_stream();
                running.store(false, Ordering::SeqCst);
                persist_state = true;
            }
            other => {
                response.ok = false;
                response.error = format!("unknown request type {other}");
            }
        }
        if !suppress_status {
            refresh_status(&mut guard);
            response.status = Some(guard.status.clone());
        }
    }

    if persist_state {
        write_state(state_file, &state)?;
    }
    // (writer + serde_json + newline + flush — byte-identical)
}
```

**Why pass-by-value request fields → per-verb handler:**

- Eliminates AGY r1's clone concern: each handler takes ownership
  of its `Option<T>` field (e.g. `snapshot::apply` receives
  `Option<ConfigSnapshot>` by value, destructures, and moves
  the inner snapshot directly into `guard.snapshot = Some(snapshot);`
  byte-identical to today).
- No `HandlerCtx<'_>` lifetime struct needed — fewer borrows to
  reason about. Each handler takes a small fixed parameter list
  of the things it actually touches.
- Borrow conflict surface shrinks: a handler needs at most
  `&mut guard` AND `&mut response`, OR just `&mut guard`. No
  struct that holds both simultaneously.

### Per-verb file shape (example: `snapshot.rs`)

```rust
use super::super::helpers::{
    refresh_status, reconcile_status_bindings, replan_queues,
    same_plan_apply_needs_binding_reconcile, snapshot_binding_plan_key,
    wait_for_binding_settle,
};
use super::super::ServerState;
use super::super::super::{
    ConfigSnapshot, ControlResponse, CONFIG_SNAPSHOT_PROTOCOL_VERSION,
};
use std::time::Duration;

pub(super) fn apply(
    guard: &mut ServerState,
    snapshot: Option<ConfigSnapshot>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
) {
    let Some(snapshot) = snapshot else {
        response.ok = false;
        response.error = "missing snapshot".to_string();
        return;
    };
    if snapshot.version != CONFIG_SNAPSHOT_PROTOCOL_VERSION {
        response.ok = false;
        response.error = format!(
            "unsupported snapshot protocol version {} (want {})",
            snapshot.version, CONFIG_SNAPSHOT_PROTOCOL_VERSION
        );
        return;
    }
    // ... rest of body byte-identical to handlers.rs lines 62-126,
    // with `guard.` substituted for the in-place `guard.` references.
    *persist_state = true;
}

pub(super) fn bump_fib(
    guard: &mut ServerState,
    snapshot: Option<&ConfigSnapshot>,
    response: &mut ControlResponse,
) {
    let Some(snapshot) = snapshot else {
        response.ok = false;
        response.error = "missing snapshot".to_string();
        return;
    };
    guard.status.last_fib_generation = snapshot.fib_generation;
    if let Some(ref mut snap) = guard.snapshot {
        snap.fib_generation = snapshot.fib_generation;
    }
    guard.afxdp.bump_fib_generation(snapshot.fib_generation);
    refresh_status(guard);
}
```

Each per-verb file's body is **byte-identical to the corresponding
match arm in `handlers.rs`** modulo:
- replace `guard` MutexGuard with `guard: &mut ServerState` parameter,
- replace `response.foo = ...` with the parameter-passed version,
- replace `persist_state = true` with `*persist_state = true;`,
- early-return guards via `let Some(...) = field else { return; }`,
- **replace `&mut guard` in helper call sites with `guard` directly**
  — since `guard` is now `&mut ServerState`, helpers that expect
  `&mut ServerState` (e.g. `reconcile_status_bindings`,
  `refresh_status`, `wait_for_binding_settle`) are called as
  `helper(guard)` not `helper(&mut guard)`. AGY r2 flagged this as
  a literal-substitution hazard; the snapshot::bump_fib example
  above already models the correct shape.

### Public API preservation

- `crate::server::handle_stream(stream, state_file, state, running)
  -> Result<(), String>` — signature byte-identical.
- `server/mod.rs`'s `pub(crate) use handlers::handle_stream;` stays
  identical. The `mod handlers;` declaration there now resolves to
  `server/handlers/mod.rs` instead of `server/handlers.rs`.
- Wire protocol unchanged: verb strings, request fields, response
  fields all identical.
- `main_tests.rs` tests at lines 919, 1049, 1096 pass unchanged.

## Hidden invariants the refactor must preserve

1. **Single dispatcher critical section.** `state.lock()` is taken
   once at line 50 inside the dispatch shell, released when the
   guard scope ends at line 448. `write_state` at line 451 then
   re-locks via `helpers.rs:708` for the persistence step — that
   is a SEPARATE, post-dispatch critical section. Refactor preserves
   this two-phase shape: per-verb handlers take `&mut ServerState`
   (the deref target of the dispatcher's guard) and never see the
   `Arc<Mutex<ServerState>>` or `state_file` parameters. Only the
   dispatch shell in `mod.rs` calls `write_state`.
2. **`refresh_status` call ordering.** Today the body has 16 eager
   `refresh_status(&mut guard)` calls inside arms (lines 105, 123,
   148, 167, 183, 206, 220, 228, 254, 281, 296, 351, 362, 373, 401,
   427) PLUS a post-match call at line 445 gated by
   `!request.suppress_status` (line 444). Eager calls are NOT
   gated by `suppress_status`. Successful arms (e.g. apply_snapshot)
   do a double refresh when status isn't suppressed: eager + post.
   Refactor preserves **every site verbatim**: eager calls stay
   where they are inside each per-verb body; the post-match call
   stays inline in `mod.rs`'s shell.
3. **`persist_state` is sticky.** Confirmed by grep
   `persist_state = false` in handlers.rs: ONE occurrence, the
   initialization at line 47. No arm sets it to false. Refactor
   uses `*persist_state = true` with the same one-way write.
4. **`response.error` + `response.ok = false` are paired.** Every
   error path sets both. Per-verb files preserve the pairing.
5. **`running.store(false, Ordering::SeqCst)` is `shutdown`-only.**
   Confirmed by grep — only line 436. **shutdown stays inline in
   `mod.rs`** so the `running` Arc doesn't need to be threaded
   through any per-verb file.
6. **`eprintln!` log strings.** Spot-checked:
   - `apply_snapshot`: 4 eprintln sites (lines 62-67, 82-86, 96-98,
     117-119) — refactor copies strings byte-identical into
     `snapshot.rs`.
   - `rebind`: 2 sites (line 389, 403-407) — copied byte-identical
     into `rebind.rs`.
   - `stop_workers`: 2 sites (line 416, 429-431) — copied
     byte-identical into `stop_workers.rs`.
   - `update_ha_state`: 1 conditional eprintln behind
     `#[cfg(feature = "debug-log")]` (lines 158-163) — preserved
     with the cfg attribute.
7. **`request.suppress_status` and `request.neighbor_replace`** are
   read on the dispatch shell. `suppress_status` is read into a
   local `let suppress_status = request.suppress_status;` BEFORE
   the match so the post-match check doesn't conflict with the
   per-arm moves. `neighbor_replace` is `Copy`; passed by value
   to `neighbors::update`.
8. **`request.session_export.unwrap_or_default()` semantics.**
   Today the arm runs `let export_req = request.session_export.unwrap_or_default();`
   — moves out of `request`. Refactor v2 passes
   `request.session_export` (an `Option<SessionExportRequest>`) by
   value to `export::owner_rg`, which calls `.unwrap_or_default()`
   inside. Byte-identical semantics, no clone.

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Pure code motion; per-arm bodies byte-identical modulo parameter-passing. `request` consumed by value preserves all today's `.take()` / `.unwrap_or_default()` semantics. |
| Lifetime / borrow-checker | LOW | v2 dropped `HandlerCtx<'_>` in favor of explicit per-handler parameter lists. Each handler holds `&mut guard` and `&mut response` (when needed) as distinct borrows — same shape as today's flat match. No new lifetime introduced. The `request.snapshot` / `request.queue` / etc. moves happen INSIDE the match arm's expression, mirror to today. |
| Performance regression | NONE | Control-plane path. v2 has **zero new clones**. Move semantics for `Option<ConfigSnapshot>`, `Option<ForwardingReq>`, etc. cost a single struct move (same as today). |
| Architectural mismatch (#961 / #946 Phase 2) | LOW | Canonical command-dispatcher refactor. AGY's r1 counter-proposal (domain grouping) is rejected because (a) user's wave-1 instruction explicitly mandates per-verb files, and (b) we've already conceded the over-fragmentation point by inlining 6 trivial arms. The 13-file shape is the compromise. |
| Test coverage gap | MEDIUM (documented) | Only `apply_snapshot` has Rust-side e2e coverage via `main_tests.rs:919/1049/1096`. 18 other verbs are covered transitively via Go-side tests in `pkg/dataplane/userspace/*_test.go` (drives apply_snapshot, set_forwarding_state, update_ha_state, set_queue_state, set_binding_state, bump_fib_generation, etc. via the wire). Pure-code-motion property + Go-side coverage mitigates; we deliberately do not add new Rust tests as part of this refactor (issue body §"Test handling" defers them). |

## Test plan

1. `cargo build --release` clean inside the worktree.
2. `cargo test --release` — full Rust suite (target: same pass count
   as origin/master). Particular focus:
   - 4 existing `apply_snapshot` e2e tests in `main_tests.rs`
     (the ONLY e2e handle_stream tests).
   - All `same_binding_plan_*`, `queue_planner_*`,
     `build_synced_session_entry_*` tests (drive helpers that the
     refactor MOVES but does not modify).
3. 5x flake check on one apply_snapshot e2e test.
4. `go test ./...` — all 30 Go packages. The Go control plane is
   the wire producer; if the wire is unchanged the Go side can't
   care.
5. **No smoke per wave-1 rule.** AWAITING-BATCH-MERGE after 4-of-4
   reviewer attestation. The refactor-chain batch smoke runs once
   at the end.

## Out of scope (explicitly)

- Adding per-verb Rust tests for the 18 currently-uncovered verbs.
  (Issue body's "Test handling" section says inline tests only when
  density warrants; this PR doesn't add them.)
- Deduplicating the `refresh_status` double-call (eager + post-match).
- Renaming any verb wire name.
- Changing `ControlRequest` / `ControlResponse` shape.
- Touching `helpers.rs`, `lifecycle.rs`, `state.rs`, `mod.rs`'s
  re-exports.
- Per-verb error/logging wording changes — `eprintln!` strings stay
  byte-identical.

## Open questions for adversarial review (v2)

1. **Per-handler parameter-list verbosity.** v2 takes 3-4 explicit
   parameters per handler. Is this preferable to a bundled
   `Shell { response, persist }` ref struct? Reviewers may push
   back on either side.
2. **`request.snapshot` move into `snapshot::apply`.** v2 takes
   `snapshot: Option<ConfigSnapshot>` by value. Byte-identical to
   today (line 54 `if let Some(snapshot) = request.snapshot`
   already moves). Confirmed nothing else reads
   `request.snapshot` after the match arm.
3. **Inline-vs-file boundary.** Drawn at "≤5 LOC body and single
   helper call → INLINE; ≥10 LOC OR error-path branches → FILE."
   `update_fabrics` (5 LOC) inline, `inject_packet` (16 LOC, error
   branch) file. Reviewers may push back on the boundary.
4. **`export.rs` grouping.** Both verbs produce session deltas but
   bodies differ. Could be split into export_owner_rg.rs +
   export_all.rs. Plan groups them; reviewers may disagree.
5. **`sync_session.rs` inner match preservation.** Today the
   `sync_session` arm has a nested match on
   `sync_req.operation.as_str()` ("upsert" / "delete" / other).
   The refactor preserves the nested match inside one fn.
6. **Visibility.** Per-verb fns use `pub(super)` — strictly
   module-private. Project memory `feedback_refactor_module_dir_layout`
   ratifies this choice.
7. **Test coverage gap acceptance.** AGY r1 flagged this. Moving
   forward because (a) pure code motion doesn't change semantics,
   and (b) Go-side coverage is the de-facto integration test for
   these verbs. Reviewers may still PLAN-KILL on this axis.
8. **Dual-file-vs-directory module switch.** The commit must
   `git mv userspace-dp/src/server/handlers.rs userspace-dp/src/server/handlers/mod.rs`
   in the same change that adds per-verb files. Rust edition
   per project `Cargo.toml` supports both `foo.rs` and `foo/mod.rs`
   shapes but NOT BOTH SIMULTANEOUSLY. The commit removes the flat
   file in the same step.
