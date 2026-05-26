# #1345 Step 1 — Split `server/handlers.rs` 415-LOC `handle_stream` dispatcher into per-verb modules

**Status:** DRAFT v1 — pending adversarial plan review (Codex + Antigravity).

## Issue framing

`userspace-dp/src/server/handlers.rs` is 461 LOC and consists almost
entirely of one function: `handle_stream()` at lines 16-461 (~445 LOC
body). It is a single `match request.request_type.as_str()` dispatcher
over 19 protocol verbs on the control-socket wire.

`docs/engineering-style.md` defines the soft cap at 100 LOC per
function and the hard Tier-1 cap at 200 LOC. `handle_stream` is >4x
the soft cap and >2x the hard cap. The issue requests a textbook
command-dispatcher refactor: one file per verb under a new
`server/handlers/` directory module, with `handlers/mod.rs` holding
the slim reader/writer + line-loop + dispatch shell.

## Honest scope/value framing

This is **pure code motion**. The transport (BufReader/BufWriter),
request decode, response encode, and the locking discipline
(`state.lock()` guard, single critical section, optional `write_state`
after) all stay byte-identical. Every match arm becomes one
`pub(super) fn handle_<verb>(...)` in its own file; `handle_stream`'s
match dispatches to it.

The win is **readability and review tractability**: today nobody can
review the function end-to-end; tomorrow each verb is independently
inspectable in 20-80 LOC. Add-a-verb churn touches one file plus a
one-line entry in `mod.rs`'s match.

There is no perf claim: this is a control-socket path, not per-packet.
Allocation/Vec churn changes nothing — every arm's existing
`Vec::with_capacity`, `format!`, `serde_json::to_writer`, etc. stays
where it is.

If reviewers conclude the readability gain is not worth the
file-multiplication churn, PLAN-KILL is an acceptable verdict. The
file already passes `cargo build` and `cargo test` and is not blocking
any other work; #1345 is a maintainability-only ticket.

## What is already in place

- `server/` is already a directory module (`mod.rs`, `state.rs`,
  `helpers.rs`, `lifecycle.rs`, `handlers.rs`).
- `helpers.rs` already holds the >20 `pub(crate)` helper fns the
  arms call: `refresh_status`, `reconcile_status_bindings`,
  `wait_for_binding_settle`, `build_synced_session_entry`,
  `build_synced_session_key`, `set_bindings_forwarding_armed`,
  `forwarding_unsupported_error`, `snapshot_binding_plan_key`,
  `same_plan_apply_needs_binding_reconcile`, `replan_queues`,
  `write_state`. These remain untouched in `helpers.rs`.
- `server::handle_stream` is re-exported from `server/mod.rs` and
  called from `server/lifecycle.rs` (2 sites) plus `main_tests.rs`
  (3 sites). The external entry point stays at
  `crate::server::handle_stream(stream, state_file, state, running)`.
- Test harness in `main_tests.rs` exercises `handle_stream`
  end-to-end via a real UnixStream pair.

## Concrete design

### Target layout

```
userspace-dp/src/server/
├── handlers/
│   ├── mod.rs                       # handle_stream + dispatch shell
│   ├── snapshot.rs                  # apply_snapshot, bump_fib_generation
│   ├── forwarding.rs                # set_forwarding_state
│   ├── ha.rs                        # update_ha_state
│   ├── fabrics.rs                   # update_fabrics
│   ├── neighbors.rs                 # update_neighbors
│   ├── policy_counters.rs           # clear_policy_counters
│   ├── queue.rs                     # set_queue_state
│   ├── binding.rs                   # set_binding_state
│   ├── inject_packet.rs             # inject_packet
│   ├── sync_session.rs              # sync_session (upsert + delete)
│   ├── session_deltas.rs            # drain_session_deltas
│   ├── export_owner_rg.rs           # export_owner_rg_sessions
│   ├── export_all.rs                # export_all_sessions
│   ├── rebind.rs                    # rebind
│   ├── stop_workers.rs              # stop_workers
│   └── shutdown.rs                  # shutdown
├── helpers.rs                       # unchanged
├── lifecycle.rs                     # unchanged
├── mod.rs                           # unchanged re-exports
└── state.rs                         # unchanged
```

Verbs `ping` and `status` are no-op arms in the current code (the
default `refresh_status` + status attach at the end handles them).
They stay inline in `mod.rs`'s match as `"ping" | "status" => {}` —
spinning out a 1-line file would be silly cohesion.

### `handlers/mod.rs` shape

```rust
// Submodules: one per protocol verb.
mod binding;
mod export_all;
mod export_owner_rg;
mod fabrics;
mod forwarding;
mod ha;
mod inject_packet;
mod neighbors;
mod policy_counters;
mod queue;
mod rebind;
mod session_deltas;
mod shutdown;
mod snapshot;
mod stop_workers;
mod sync_session;

use super::super::*;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Shared scratchpad passed to each per-verb handler. Lets handlers
/// signal back whether `persist_state` should fire and mutate the
/// response that gets serialized on the way out.
pub(super) struct HandlerCtx<'a> {
    pub guard: &'a mut ServerState,
    pub request: &'a ControlRequest,
    pub response: &'a mut ControlResponse,
    pub persist_state: &'a mut bool,
    pub running: &'a Arc<AtomicBool>,
}

pub(crate) fn handle_stream(
    stream: UnixStream,
    state_file: &str,
    state: Arc<Mutex<ServerState>>,
    running: Arc<AtomicBool>,
) -> Result<(), String> {
    // timeouts, reader, decode (byte-identical to today)
    ...
    let mut response = ControlResponse { ... };
    let mut persist_state = false;

    {
        let mut guard = state.lock().expect("server state poisoned");
        let mut ctx = HandlerCtx {
            guard: &mut *guard,
            request: &request,
            response: &mut response,
            persist_state: &mut persist_state,
            running: &running,
        };
        match request.request_type.as_str() {
            "ping" | "status" => {}
            "apply_snapshot"             => snapshot::apply(&mut ctx),
            "set_forwarding_state"       => forwarding::set(&mut ctx),
            "update_ha_state"            => ha::update(&mut ctx),
            "update_fabrics"             => fabrics::update(&mut ctx),
            "update_neighbors"           => neighbors::update(&mut ctx),
            "bump_fib_generation"        => snapshot::bump_fib(&mut ctx),
            "clear_policy_counters"      => policy_counters::clear(&mut ctx),
            "set_queue_state"            => queue::set(&mut ctx),
            "set_binding_state"          => binding::set(&mut ctx),
            "inject_packet"              => inject_packet::handle(&mut ctx),
            "sync_session"               => sync_session::handle(&mut ctx),
            "drain_session_deltas"       => session_deltas::drain(&mut ctx),
            "export_owner_rg_sessions"   => export_owner_rg::handle(&mut ctx),
            "export_all_sessions"        => export_all::handle(&mut ctx),
            "rebind"                     => rebind::handle(&mut ctx),
            "stop_workers"               => stop_workers::handle(&mut ctx),
            "shutdown"                   => shutdown::handle(&mut ctx),
            other => {
                ctx.response.ok = false;
                ctx.response.error = format!("unknown request type {other}");
            }
        }
        if !request.suppress_status {
            refresh_status(ctx.guard);
            ctx.response.status = Some(ctx.guard.status.clone());
        }
    }

    if persist_state {
        write_state(state_file, &state)?;
    }
    // writer + serde_json + newline + flush (byte-identical)
    ...
}
```

`HandlerCtx` is a private struct in `handlers::mod` (not re-exported);
each handler module reaches it via `use super::HandlerCtx;`.

### Per-verb file shape (example: `snapshot.rs`)

```rust
use super::super::super::*;            // climbs handlers → server → crate
use super::super::helpers::*;          // refresh_status, reconcile_*
use super::HandlerCtx;
use std::time::Duration;               // only where needed

pub(super) fn apply(ctx: &mut HandlerCtx<'_>) {
    let Some(snapshot) = ctx.request.snapshot.clone() else {
        ctx.response.ok = false;
        ctx.response.error = "missing snapshot".to_string();
        return;
    };
    if snapshot.version != CONFIG_SNAPSHOT_PROTOCOL_VERSION {
        ctx.response.ok = false;
        ctx.response.error = format!(
            "unsupported snapshot protocol version {} (want {})",
            snapshot.version, CONFIG_SNAPSHOT_PROTOCOL_VERSION
        );
        return;
    }
    // ... existing body, with ctx.guard / ctx.response / *ctx.persist_state
    // replacing the in-place lookups.
}

pub(super) fn bump_fib(ctx: &mut HandlerCtx<'_>) { ... }
```

Two arms (`apply_snapshot` and `bump_fib_generation`) share the
`snapshot.rs` module because they both pivot on `request.snapshot` and
the issue body explicitly groups them. This is the only group >1 verb
per file; every other file is one verb. Cohesion principle: a verb
gets its own file unless two verbs share both data shape and
side-effect family (snapshot install vs FIB bump are both "snapshot
update intents").

### Borrow shape and `request.snapshot.clone()`

Today the match holds `request` by value and several arms take
ownership of `request.snapshot`, `request.forwarding`,
`request.queue`, etc. — these are `Option<T>` fields that get
unwrapped via `if let Some(...) = request.field`.

To pass `request` as `&'a ControlRequest` inside `HandlerCtx`, each
handler that consumed an `Option<T>` field by value must either
`.clone()` it (cheap — these are small enums/structs already crossed
the serde boundary) or `.as_ref()` it and work through `&T`. Audit
per arm:

| Arm | Consumed today | Resolution |
|---|---|---|
| `apply_snapshot` | `request.snapshot` (`ConfigSnapshot`) | `clone()` — body is small; on hot path? No, snapshot apply is bounded by Go control-plane rate (≪1 Hz typically). |
| `set_forwarding_state` | `request.forwarding` (`ForwardingReq`) | `.as_ref()` — tiny struct, fields read once. |
| `update_ha_state` | `request.ha_state` (`HaStateReq`) | `.as_ref()` plus `.groups.clone()` (already cloned today on `guard.status.ha_groups = ha_req.groups.clone()`). |
| `update_fabrics` | `request.fabrics.as_ref()` | already by ref. |
| `update_neighbors` | `request.neighbors.as_ref()` | already by ref. Plus `request.neighbor_replace` is `Copy`. |
| `bump_fib_generation` | `request.snapshot.as_ref()` | already by ref. |
| `set_queue_state` | `request.queue` | `.as_ref()` — `QueueReq` fields all `Copy`. |
| `set_binding_state` | `request.binding` | `.as_ref()`. |
| `inject_packet` | `request.packet` (`PacketReq`) | needs ownership to pass into `afxdp.inject_test_packet(packet_req)`. Use `request.packet.clone()`. Test-only path, called once per injected packet — clone cost negligible. |
| `sync_session` | `request.session_sync` (`SessionSyncReq`) | `.as_ref()`. |
| `drain_session_deltas` | `request.session_deltas.as_ref().map(...)` | already by ref. |
| `export_owner_rg_sessions` | `request.session_export.unwrap_or_default()` | replace with `request.session_export.clone().unwrap_or_default()`. Small struct (a `Vec<u8>` of owner_rgs + a `max: u32`). |

Note `request.snapshot` and `request.session_export` are not on any
per-packet path. The two clones cost less than the I/O syscalls
flanking them.

If a reviewer flags this as a behavioral risk, the alternative is to
pass `request: ControlRequest` (by value) into the dispatch and have
each handler destructure the field it needs. Open question Q5 below.

### Public API preservation

- `crate::server::handle_stream(stream, state_file, state, running)
  -> Result<(), String>` — signature byte-identical.
- `server::mod.rs`'s `pub(crate) use handlers::handle_stream;` line
  becomes `pub(crate) use handlers::handle_stream;` (same path — the
  `mod handlers;` declaration there now resolves to
  `server/handlers/mod.rs` instead of `server/handlers.rs`, which is
  how Rust's filename-vs-directory module ambiguity is resolved).
- Wire protocol unchanged: verb strings, request fields, response
  fields all identical. Tests in `main_tests.rs` MUST pass without
  modification.

### What stays at `handlers/mod.rs`'s top level

- Stream timeout setup (5 s read / 5 s write).
- BufReader / `read_line` / `serde_json::from_str(line.trim_end())`.
- `ControlResponse` initialization.
- The `state.lock()` + match shell.
- The `if !request.suppress_status` status attach.
- The post-lock `if persist_state { write_state(...) }` write.
- BufWriter + `serde_json::to_writer` + newline + flush.

These all keep the existing order — the dispatch is the only thing
that changes shape, not the surrounding I/O.

## Hidden invariants

1. **Single critical section per request.** `state.lock()` is taken
   once; all handlers run under the same guard; the lock is released
   before `write_state` and the response write. Refactor preserves
   this by passing `&mut ServerState` (the guard's deref target)
   through `HandlerCtx.guard`. No handler may re-lock.
2. **`refresh_status` + status attach ordering.** Today the
   `if !request.suppress_status` block runs AFTER the match (and may
   re-run `refresh_status` that some arms already called inside).
   This double-call is intentional — some arms call it eagerly to
   write follow-on state (e.g. `binding.last_change = Some(Utc::now())`)
   and the post-match call is the suppress-controlled status export.
   Refactor preserves both call sites verbatim.
3. **`persist_state` is sticky.** Once any arm sets `persist_state =
   true`, the post-lock write_state fires. No arm sets it to false.
   Refactor uses `*ctx.persist_state = true` with the same
   stickiness.
4. **`response.error` + `response.ok = false` are paired.** Every
   error path in the current code sets both. Refactor preserves
   the pairing inside each handler.
5. **`running.store(false, Ordering::SeqCst)` is `shutdown`-only.**
   Only the `shutdown` arm flips `running`. Refactor preserves: only
   `shutdown::handle()` touches `ctx.running`.
6. **`eprintln!` debug logs.** Several arms emit `eprintln!` for
   journald visibility (`CTRL_REQ: apply_snapshot ...`,
   `rebind: stopping workers ...`, etc.). Refactor preserves
   message strings byte-identical so log scrapers and ops runbooks
   keep working.
7. **`request.suppress_status` and `request.neighbor_replace`** are
   read after the per-arm body. They stay on the dispatch shell,
   not inside any handler.

## Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Pure code motion; per-arm bodies byte-identical modulo `&mut ctx.guard` substitution. Coverage from `main_tests.rs` end-to-end tests on UnixStream pairs. |
| Lifetime / borrow-checker | LOW-MED | New `HandlerCtx<'a>` introduces one new lifetime tying the request, response, persist flag, and guard together. The current code already binds these to the match block's lifetime; the refactor lifts that binding to a struct. Risk: `ctx.guard` reborrows inside helpers may conflict with `ctx.response` reborrows if a handler tries `helpers::foo(ctx.guard)` while holding `&mut ctx.response`. Mitigation: each handler computes error strings into temporaries first, writes them to `ctx.response` last. The `request.snapshot.clone()` audit above also avoids partial moves out of `&ctx.request`. |
| Performance regression | NONE | Control-plane path (typically <1 Hz on `apply_snapshot`, ~1 Hz on status poll, bursts on session_sync). No per-packet path touched. The two `.clone()` calls (`request.snapshot`, `request.session_export`) are bounded by request rate and amortized by I/O syscalls. |
| Architectural mismatch (#961 / #946 Phase 2) | LOW | This is the canonical command-dispatcher refactor recommended by the issue itself. The issue body provides the target layout. There is no "wrong target" axis here: the function IS the dispatcher, the verbs ARE independent. Unlike #946 Phase 2 (batching across state-coupled stages) or #961 (PacketContext for a per-packet type), the verbs in `handle_stream` have no cross-arm coupling beyond the shared guard and response, both of which fit cleanly into a per-call ctx. |

## Test plan

1. `cargo build --release` clean inside the worktree.
2. `cargo test --release` — full Rust suite (target: same pass count
   as origin/master, ~952 tests). Particular focus:
   - `main_tests.rs` end-to-end UnixStream handler tests (4-5 tests
     that drive `handle_stream` directly).
   - Any `server::handlers::*` direct tests (current code has none
     inline; refactor will not add tests, per the issue's "no inline
     tests" stance).
3. 5x flake check on the named test from main_tests.rs that drives
   the broadest verb mix (likely `test_handle_stream_apply_snapshot`
   or similar — confirm name once enumerated).
4. `go test ./...` — all 30 Go packages. The Go control plane is the
   only producer of these wire requests; if the wire is unchanged
   the Go side cannot care.
5. **No smoke** — per the user's wave-1 rules for this issue:
   `AWAITING-BATCH-MERGE` after 4-of-4 reviewer attestation. The
   refactor-chain batch smoke runs once at the end.

## Out of scope (explicitly)

- Adding per-verb tests (issue body says inline tests only when
  density warrants; this PR doesn't add them).
- Renaming any verb wire name. (`set_queue_state` /
  `set_binding_state` etc. stay as-is.)
- Changing `ControlRequest` / `ControlResponse` shape.
- Touching `helpers.rs`, `lifecycle.rs`, `state.rs`, `mod.rs`'s
  re-exports.
- Splitting `handle_stream`'s pre-match I/O setup or post-match
  response write — those stay inline in `handlers/mod.rs`.
- Any per-verb error/logging wording change. `eprintln!` strings
  stay byte-identical.

## Open questions for adversarial review

1. **`HandlerCtx` design.** Is bundling
   `(guard, request, response, persist_state, running)` into a
   single `&mut HandlerCtx<'_>` the right shape, or would five
   separate parameters per handler be cleaner? The struct trades
   per-handler signature noise for one extra named type. Counter-
   proposal: each handler takes `(&mut ServerState, &ControlRequest,
   &mut ControlResponse, &mut bool, &Arc<AtomicBool>)`. The
   `shutdown` arm is the only one that needs `running`; the
   `inject_packet`/`sync_session`/etc. arms only need three of the
   five. **PLAN-KILL invitable** if reviewers think the struct is
   cargo-culted ceremony.
2. **`request.snapshot.clone()` / `request.session_export.clone()`
   cost.** Are these clones acceptable on the apply_snapshot and
   owner_rg export paths? `ConfigSnapshot` can be large (interfaces,
   zones, policies, routes, etc. — easily 10s of KB serialized).
   Cloning before consuming would add one extra allocation +
   recursive struct copy. Alternative: pass `ControlRequest` into
   the dispatch by value (`let request = ...; match request.request_type {...}`)
   and have each handler destructure the field it needs by value.
   That keeps zero clones at the cost of moving the request into
   each arm. **PLAN-KILL invitable** if reviewers think the clone
   cost matters on apply_snapshot (it fires on every Junos commit).
3. **One verb per file vs. cohesion groups.** Currently the design
   groups `apply_snapshot` + `bump_fib_generation` into
   `snapshot.rs` because they share the `request.snapshot` pivot.
   Should `set_queue_state` + `set_binding_state` likewise share
   `bindings.rs`? They have near-identical body structure (find
   binding(s) by id, mutate registration/armed, reconcile if
   changed). Counter-argument: the issue body's example layout
   put them in separate `queues.rs` and `bindings.rs` files. The
   plan follows the issue body verbatim.
4. **`ping` / `status` no-op arms.** Should these become explicit
   `handlers::ping::handle()` (1-line file) for symmetry? The plan
   says no — empty arms next to a single `_ => format!("unknown")`
   are cleaner in the dispatch than 1-line files. Reviewers may
   disagree on symmetry vs. minimalism.
5. **`use super::super::super::*;` chain depth.** Per-verb files
   live at `server/handlers/<verb>.rs`, three levels deep, so they
   import crate-root items via `super::super::super::*`. Today
   `server/handlers.rs` uses `super::super::*` (two levels).
   Is the deeper glob acceptable, or should the refactor first
   replace it with explicit `use crate::*` imports? The issue body
   doesn't mandate the import style; the existing convention is
   `super::super::*` so the plan follows it. **PLAN-KILL invitable**
   if reviewers want explicit `use crate::{...}` enumeration in
   each new file — that would multiply the diff and is out of scope
   for "pure code motion".
6. **Test coverage assertion.** The plan claims `main_tests.rs`
   exercises handlers end-to-end. Should I enumerate the exact test
   functions and their verb coverage before plan-ready, so reviewers
   can verify the safety net? (Yes if asked — quick to do.)
7. **Dual-file-vs-directory module switch hazard.** Changing
   `server/handlers.rs` to `server/handlers/mod.rs` requires
   deleting the old file in the same commit as creating the new
   directory. If the diff lands `handlers/` without deleting
   `handlers.rs`, Rust resolves to the file and the dispatch shell
   never runs (cargo errors at build, but the build error message
   is sometimes cryptic). The commit must remove the old file in
   the same change. Mitigation: `git mv userspace-dp/src/server/handlers.rs userspace-dp/src/server/handlers/mod.rs` as the first step, then split.
