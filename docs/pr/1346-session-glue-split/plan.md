# #1346 session_glue dispatcher split + parameter-cluster collapse

**Status:** DRAFT v1 — pending adversarial plan review.

## 1. Issue framing

`userspace-dp/src/afxdp/session_glue/mod.rs` carries three independent
violations of `docs/engineering-style.md` ("function with >100 lines or
>8 parameters is a refactor cue"), all clustered around the same
synced-session ingestion pipeline:

1. `apply_worker_commands` at `mod.rs:429` — **329-LOC** body that
   dispatches **8 `WorkerCommand` variants** inside one `match` arm
   (Tier-1 hard hit).
2. `maybe_promote_synced_session` at `mod.rs:1044` — **17-param**
   private helper (16 explicit + `&mut sessions`). Called from two
   sites inside `resolve_flow_session_decision`.
3. `purge_translated_synced_hit` at `mod.rs:1129` — **11-param**
   private helper. Called from one site inside
   `resolve_flow_session_decision`.

The issue body proposes one sibling file per variant under
`session_glue/commands/<variant>.rs`. The wave-5 instruction tightens
that to **no `apply_` prefix anti-pattern**, so the per-variant files
will live in **`session_glue/apply/<variant>.rs`** with bare names
(`demote_owner_rgs.rs`, `refresh_owner_rgs.rs`, `upsert_synced.rs`,
…), and the dispatcher inside `mod.rs` stays as the one place that
matches on `WorkerCommand`.

## 2. Honest scope / value framing

This is **pure refactor for readability**, not a perf win. The control
plane impact is zero — `apply_worker_commands` runs once per
poll-loop tick under a `try_lock` on a per-worker `Mutex<VecDeque>`
that is empty on the steady-state hot path. The only times the body
runs at all are on:

- HA-state transitions (DemoteOwnerRGS, RefreshOwnerRGS,
  VacateAllSharedExactSlots) — rare;
- session-sync ingestion (UpsertSynced, UpsertLocal, DeleteSynced) —
  control-plane-bounded at session-install rate (≤ a few thousand /s
  during bulk sync, single-digit /s steady state);
- export sequence drain (ExportOwnerRGSessions) — one per HA group
  activation;
- shaped-TX request enqueue (EnqueueShapedLocal) — one per drain
  cycle, not per packet.

Code motion is mechanical. The only semantic-touching change is
collapsing the 17-/11-param clusters into context structs, which the
issue body explicitly suggests:

```rust
struct PromoteSyncedSessionCtx<'a> { … }
struct PurgeTranslatedSyncedHitCtx<'a> { … }
```

Both call sites are inside `resolve_flow_session_decision` (which
itself is 17 params and is **explicitly out of scope** for this PR —
its decomposition belongs to a future #1346 follow-up or a sibling
issue). The signatures of `pub(super) fn apply_worker_commands` and
`pub(super) fn resolve_flow_session_decision` are **preserved
byte-for-byte** so callers in `worker/loop_body/mod.rs` and the rest
of the dataplane do not change.

If reviewers conclude the perf gain (literally zero, pure
readability) is too small to justify the churn, **PLAN-KILL is an
acceptable verdict.** The counterweight: #1346 sits squarely inside
the HA session-sync path, and shrinking the per-variant blast radius
is a real auditability win for future HA work.

## 3. What's already shipped / partially batched

- `session_glue/` is already a directory module (not a single .rs
  file). `session_glue/mod.rs` + `session_glue/tests.rs` (3725 LOC of
  tests, already extracted via `#[path = "tests.rs"] mod tests;`).
- `WorkerCommandResults` already exists as the per-tick accumulator
  shape — no need to invent one.
- `WorkerCommand` enum lives in `userspace-dp/src/afxdp/types/runtime.rs`
  (`pub(in crate::afxdp) enum WorkerCommand`) — no enum changes
  needed.
- Wave-4 PRs in this stream landed pure code motion under sibling
  directories with no `apply_` prefix (e.g. PR #1592 split
  `pkg/dataplane/userspace/snapshot.go` into 14 sibling files). This
  PR follows the same shape on the Rust side.

## 4. Concrete design

### 4.1 Layout

```
userspace-dp/src/afxdp/session_glue/
├── mod.rs                       # everything except the 8 per-variant
│                                # handlers and the two collapsed
│                                # helpers; apply_worker_commands stays
│                                # here as the dispatcher
├── tests.rs                     # unchanged (3725 LOC)
├── apply/
│   ├── mod.rs                   # pub(super) re-exports of per-variant
│   │                            # handle_* fns; sibling-file declarations
│   ├── demote_owner_rgs.rs      # handle_demote_owner_rgs(...)
│   ├── refresh_owner_rgs.rs     # handle_refresh_owner_rgs(...)
│   ├── export_owner_rg_sessions.rs
│   ├── upsert_synced.rs         # handle_upsert_synced(...)
│   ├── upsert_local.rs          # handle_upsert_local(...) (3-liner)
│   ├── delete_synced.rs         # handle_delete_synced(...) (~12 lines)
│   ├── enqueue_shaped_local.rs  # handle_enqueue_shaped_local(...) (1 line; pushes onto accumulator)
│   └── vacate_all_shared_exact_slots.rs  # handle_vacate_all_shared_exact_slots(...) (sets flag)
└── promote.rs                   # maybe_promote_synced_session +
                                 # PromoteSyncedSessionCtx +
                                 # purge_translated_synced_hit +
                                 # PurgeTranslatedSyncedHitCtx +
                                 # is_translated_forward_session_key +
                                 # should_keep_synced_hit_transient +
                                 # materialize_shared_session_hit
```

`promote.rs` is the natural home for the collapsed cluster — the 17-
and 11-param helpers, plus the small predicates (`is_translated_forward_session_key`,
`should_keep_synced_hit_transient`) that exist only to support them,
plus `materialize_shared_session_hit` which is also part of the
synced-hit promotion path. This keeps the cluster physically next to
the helpers it calls into.

The `apply/mod.rs` per-variant file naming intentionally **omits the
`apply_` prefix** per wave-5 rule §1. The file's path
(`session_glue/apply/upsert_synced.rs`) already encodes the "apply"
context — duplicating it in the function name would be exactly the
anti-pattern the rule guards against.

### 4.2 Per-variant handler signatures

The dispatcher passes in everything each handler needs explicitly.
Most handlers take only what they touch (so most signatures are
narrow); `handle_demote_owner_rgs` and `handle_refresh_owner_rgs` are
the wide ones because they reach into the full set of forwarding +
ha_state + neighbor + session-map state.

```rust
// apply/upsert_local.rs
pub(super) fn handle_upsert_local(
    sessions: &mut SessionTable,
    entry: SessionInstallRequest,
    now_ns: u64,
) { /* ~7 lines, byte-equivalent to the existing match arm */ }

// apply/delete_synced.rs
pub(super) fn handle_delete_synced(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    key: SessionKey,
    now_ns: u64,
) { /* ~12 lines */ }

// apply/enqueue_shaped_local.rs
pub(super) fn handle_enqueue_shaped_local(
    results: &mut WorkerCommandResults,
    req: TxRequest,
) { results.shaped_tx_requests.push(req); }

// apply/vacate_all_shared_exact_slots.rs
pub(super) fn handle_vacate_all_shared_exact_slots(
    results: &mut WorkerCommandResults,
) { results.vacate_all_shared_exact_slots = true; }

// apply/export_owner_rg_sessions.rs
pub(super) fn handle_export_owner_rg_sessions(
    sessions: &mut SessionTable,
    results: &mut WorkerCommandResults,
    sequence: u64,
    owner_rgs: Vec<i32>,
) { /* delegates to existing private export_forward_sessions_for_owner_rgs */ }

// apply/upsert_synced.rs
pub(super) fn handle_upsert_synced(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    entry: SyncedSessionEntry,
    now_ns: u64,
    now_secs: u64,
) { /* ~70 lines, byte-equivalent to existing match arm */ }

// apply/demote_owner_rgs.rs
pub(super) fn handle_demote_owner_rgs(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    owner_rgs: Vec<i32>,
    now_ns: u64,
    now_secs: u64,
    cancelled_keys: &mut Vec<SessionKey>,
) { /* ~85 lines, byte-equivalent */ }

// apply/refresh_owner_rgs.rs
pub(super) fn handle_refresh_owner_rgs(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    owner_rgs: Vec<i32>,
    now_ns: u64,
    now_secs: u64,
) { /* ~80 lines, byte-equivalent */ }
```

Each handler is **purely lifted** from the existing match arm — same
body, same locals, same call order, same side effects. The
dispatcher's `match cmd { … }` becomes:

```rust
match cmd {
    WorkerCommand::DemoteOwnerRGS { owner_rgs } => {
        apply::handle_demote_owner_rgs(
            sessions, session_map_fd, forwarding, ha_state,
            dynamic_neighbors, owner_rgs, now_ns, now_secs,
            &mut cancelled_keys,
        );
    }
    /* … one arm per variant … */
}
```

After the lift, `apply_worker_commands` itself shrinks from 329 LOC
to ~50 LOC (the try_lock + early returns + the dispatch match + the
final `WorkerCommandResults { … }`).

### 4.3 Context-struct collapse for the 17/11-param helpers

The shared/peer pointer cluster appears in both helpers and is the
right thing to group:

```rust
// promote.rs

/// Shared-session backing storage shared across workers. These four
/// references travel together at every site that touches synced
/// sessions; grouping them removes the canonical 17-param smell that
/// triggered #1346.
pub(super) struct SharedSessionRefs<'a> {
    pub sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub nat_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub forward_wire_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub owner_rg_indexes: &'a SharedSessionOwnerRgIndexes,
}

pub(super) fn maybe_promote_synced_session(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared: SharedSessionRefs<'_>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forwarding: &ForwardingState,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
    origin: SessionOrigin,
    fabric_ingress: bool,
    now_ns: u64,
    protocol: u8,
    tcp_flags: u8,
) -> SessionMetadata { /* body unchanged except shared.sessions / shared.nat_sessions / etc. */ }
//   ^ 13 params (was 17)

pub(super) fn purge_translated_synced_hit(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared: SharedSessionRefs<'_>,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
) { /* body unchanged */ }
//   ^ 7 params (was 11)
```

Both new signatures are **under the >8-param soft cap**. The struct
is `pub(super)` and lives in `promote.rs` next to the helpers; it is
not part of any public API.

Call sites inside `resolve_flow_session_decision` change from
positional 17-arg calls to:

```rust
let shared = SharedSessionRefs {
    sessions: shared_sessions,
    nat_sessions: shared_nat_sessions,
    forward_wire_sessions: shared_forward_wire_sessions,
    owner_rg_indexes: shared_owner_rg_indexes,
};
maybe_promote_synced_session(sessions, session_map_fd, shared, …);
```

`resolve_flow_session_decision` itself stays at 17 params for this
PR (out of scope; see §10).

## 5. Public API preservation

Preserved signatures:

- `pub(super) fn apply_worker_commands(...) -> WorkerCommandResults`
  — identical signature; called by `worker/loop_body/mod.rs:453,460`.
- `pub(super) fn resolve_flow_session_decision(...) -> Option<ResolvedFlowSessionDecision>`
  — identical signature.
- All other `pub(super)` fns in `session_glue/mod.rs` — identical.
- `pub(super) struct WorkerCommandResults` — identical fields.

Newly introduced `pub(super) struct SharedSessionRefs` and the
`pub(super) fn handle_*` per-variant handlers are **module-private**
(visible only within `session_glue/`); they are not part of the
session-glue public API.

## 6. Hidden invariants the change must preserve

1. **Per-tick accumulator ordering** — `cancelled_keys`,
   `exported_sequences`, `shaped_tx_requests`,
   `vacate_all_shared_exact_slots` are filled in the same insertion
   order across the same `WorkerCommand` stream. `DemoteOwnerRGS`'s
   `cancelled_keys.push` happens inside the existing
   `!cancelled_keys.iter().any(|key| key == &demoted_key)` dedup loop
   — the lifted handler must take `&mut Vec<SessionKey>` and preserve
   the same dedup contract (the unit test in `tests.rs` exercises
   this).
2. **`try_lock` + early-return contract** — empty queue and
   `Err(TryLockError)` both return an empty `WorkerCommandResults`.
   Code motion preserves this exactly.
3. **`now_ns` / `now_secs` are sampled once per tick** — the
   `monotonic_nanos()` call stays in the dispatcher, and both values
   are passed into each handler so no handler re-samples (avoids
   intra-tick clock skew).
4. **Single mutable borrow of `sessions`** — Rust's borrow checker
   already enforces this; the per-variant lift preserves the same
   borrow shape (`&mut SessionTable` flows into one handler at a
   time, returned before the next loop iteration).
5. **HA session-sync semantics** — the `UpsertSynced` arm includes
   the `#326` synced-forward-session re-resolution dance (lines
   648–719). The lifted `handle_upsert_synced` must preserve the
   `is_reverse` short-circuit, the `is_active = !allow_replace_local`
   gate, and the `HAInactive` skip — these are byte-equivalent code
   motion.
6. **`replicate_session_upsert`** inside
   `maybe_promote_synced_session` — must continue to fire after a
   successful `promote_synced_with_origin`. The context-struct change
   does not reorder anything.

## 7. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Code motion + struct collapse. No reordering, no allocation change, no new abstractions. |
| Lifetime / borrow-checker | LOW-MED | `SharedSessionRefs<'a>` adds one lifetime parameter. The four refs are already lifetime-bound at the call site; the struct only repackages them. The risk is if any caller wants to mutably reborrow `shared_sessions` while also passing `&shared` — neither call site does. |
| Performance regression | NONE | Same code, same call graph. The context struct is 4×`&Arc` + 1×`&` = 40 bytes on stack, identical to the 4 explicit args it replaces (each `&Arc` is one pointer). Borrow checker passes through; no heap traffic. |
| Architectural mismatch (#961 / #946-Phase-2) | LOW | This is the same shape as recent merged refactors in this stream (#1410 / #1592). The issue body itself specifies the design. |
| HA-sensitive (session-sync path) | MED | `apply_worker_commands` is the entry point for HA-replicated session installs (UpsertSynced) and HA-state transitions (Demote/Refresh OwnerRGS). Code motion must preserve every side effect in order. **Mitigated by** byte-equivalent lift + existing `tests.rs` coverage + planned smoke. |

## 8. Test plan

1. `cargo build --release` clean.
2. `cargo test --release` — full suite (currently 952 + N tests).
3. 5× flake check on
   `afxdp::session_glue::tests::apply_worker_commands_*` (the
   tests that directly exercise the dispatcher and its variants).
4. Full Go suite `go test ./...` (30 packages).
5. Per-wave-5 rule §3, the call here is whether this warrants
   **AWAITING-SMOKE + test-failover** or **AWAITING-BATCH-MERGE**:
   - Code motion is byte-equivalent.
   - The two new context structs collapse positional args but do not
     change side-effect order or call ordering.
   - `apply_worker_commands` is the HA session-sync ingestion
     entrypoint; if the lift introduces a subtle ordering bug it
     surfaces under failover, not under steady-state forwarding.
   - **Recommendation:** AWAITING-SMOKE with `scope:
     smoke-plus-test-failover`. The HA-sensitive scope tips this
     above the bar for batch-merge despite the code-motion claim.
     Reviewers can override to batch-merge if they read the diff and
     conclude the byte-equivalence is unambiguous.

## 9. Out of scope (explicitly)

- `resolve_flow_session_decision` 17-param collapse — separate issue
  / future PR. It mixes session-table state, shared-session state, HA
  state, and ingress context; collapsing it needs a wider context
  struct that is its own design exercise.
- `purge_sessions_for_input_dscp_filter_revalidation` (12 params at
  `mod.rs:261`) — also over the bar but unrelated to the
  `apply_worker_commands` cluster.
- `WorkerCommand` enum reshape — not needed for the split.
- `SessionTable` storage layout — #964 territory.
- Variant-handler test colocation (sibling-`tests` files per handler)
  — the test count is 3725 LOC of mostly cross-cutting cases; the
  cost-benefit of splitting them by variant on this PR is wrong.
  Leave `tests.rs` as the single sibling for now.

## 10. Open questions for adversarial review

1. **Is `session_glue/apply/<variant>.rs` the right home, or should
   the per-variant handlers live in `session_glue/commands/<variant>.rs`
   per the issue body?** Wave-5 rule §1 says no `apply_` prefix; the
   issue body suggests `commands/`. `apply/` matches the function
   semantics (these are the bodies of "apply this command") and is
   short. KILL the choice if it conflicts with project convention.
2. **Does the `SharedSessionRefs` collapse hide an opportunity to
   move the shared-session backing into a single
   `Arc<SharedSessionState>`?** That would be a deeper refactor —
   each of the four `Arc<Mutex<…>>` is locked independently today.
   Collapsing the *storage* is out of scope; collapsing the *passing
   convention* (this PR) is the cheap win. If a reviewer thinks the
   passing-convention collapse is premature without the storage
   collapse, that's a legitimate KILL.
3. **Should `materialize_shared_session_hit` move with the cluster?**
   The plan moves it into `promote.rs` because it is only called from
   `resolve_flow_session_decision` and only on the synced-hit path.
   If a reviewer believes it belongs with the rest of the session
   resolution helpers (`session_glue/mod.rs`), call it out.
4. **AWAITING-SMOKE vs AWAITING-BATCH-MERGE.** §8 recommends SMOKE
   based on the HA-sensitivity of the dispatcher. A reviewer with a
   stronger byte-equivalence argument can downgrade to BATCH-MERGE.
5. **Is the 8-handler split overkill for the smaller variants?**
   `UpsertLocal` is 3 lines, `EnqueueShapedLocal` is 1 line. A
   reviewer could legitimately argue these stay inline in the
   dispatcher (so the file would have 8 match arms but only 6 lifted
   handlers). The plan moves them all out for consistency; KILL or
   MAJOR if you disagree.
6. **PLAN-KILL acceptance.** This is a control-plane readability
   refactor on a 329-LOC dispatcher. If a reviewer concludes the
   parameter-cluster smell is overstated and the dispatcher's current
   shape is fine, **PLAN-KILL is the right call.**
