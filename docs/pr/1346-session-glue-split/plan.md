# #1346 session_glue dispatcher split + parameter-cluster collapse

**Status:** DRAFT v2 — addresses round-1 Codex PLAN-KILL + Gemini /
AGY PLAN-NEEDS-MINOR findings.

## Round-1 reviewer findings → v2 disposition

### Codex (PLAN-KILL → salvage)

| # | Finding | v2 disposition |
|---|---|---|
| 1 | **BLOCKER** — Plan's "control-plane only" framing is false. `resolve_flow_session_decision` (which calls all three helpers) is invoked from `poll_descriptor/mod.rs:613` after flow-cache miss. That's the packet **slow path**, not control plane. | **ACCEPTED.** v2 reclassifies scope: dispatcher split = control plane; helper-collapse = packet slow path. Adds codegen + smoke verification gates for the helper-collapse half. Does NOT split the PR; both halves still ship together but with explicit risk acknowledgement. |
| 2 | **MAJOR** — `SharedSessionRefs<'a>` by-value used 3× in `resolve_flow_session_decision` (mod.rs:1200, 1257, 1336). Needs `#[derive(Clone, Copy)]`, `&SharedSessionRefs`, or construct-per-call. | **ACCEPTED.** v2 declares `SharedSessionRefs` as `#[derive(Clone, Copy)]`. Struct is 5 `&` references (40 B on stack); `Copy` is sound and free. |
| 3 | **MEDIUM** — No interleaved-variant dispatcher test pinning insertion order across all four result fields. | **ACCEPTED.** v2 adds one new test in `session_glue/tests.rs` that queues 6+ variants in a mixed order and asserts `cancelled_keys`, `exported_sequences`, `shaped_tx_requests`, and `vacate_all_shared_exact_slots` are filled in the correct order. |
| 4 | Prefer `commands/<variant>.rs` over `apply/<variant>.rs` — issue body uses `commands/`, and the no-`apply_`-prefix rule is about function/file names not directory names. | **ACCEPTED.** v2 renames the directory to `commands/`. |

### Gemini (PLAN-NEEDS-MINOR)

| # | Finding | v2 disposition |
|---|---|---|
| 1 | **Signature contradiction** — handlers can't take `&mut WorkerCommandResults` if the struct is built at the end. Need to either (a) instantiate `let mut results = WorkerCommandResults::default()` up front and pass `&mut results`, or (b) keep separate local mutable refs and pass narrow `&mut Vec<...>` arguments. | **ACCEPTED.** v2 chooses option (b): each handler takes the narrow `&mut Vec<...>` / `&mut bool` it actually mutates. The dispatcher keeps four locals and packs them into `WorkerCommandResults` at the end (preserves the existing shape). |
| 2 | Lift all variants for consistency. | **OVERRIDDEN** — see AGY #3 below; v2 inlines the trivial 1-3 line variants. |
| 3 | Note: Gemini claims "control-plane only" — overridden by Codex's evidence-cited finding. The helper-collapse is on the packet slow path. The dispatcher split is control plane. v2 keeps both classifications. | — |

### Antigravity (PLAN-NEEDS-MINOR)

| # | Finding | v2 disposition |
|---|---|---|
| 1 | **Compile-breaking** — `session_glue/tests.rs:348` and `:393` directly call `maybe_promote_synced_session` with positional args. Plan must update these. | **ACCEPTED.** v2 explicitly enumerates this work. The helper-collapse step builds a `SharedSessionRefs { … }` literal at each test call site. |
| 2 | Moving `materialize_shared_session_hit` to `promote.rs` is counter-productive — it has only one caller (`resolve_flow_session_decision` at mod.rs:1216) which stays in `mod.rs`. The move increases cross-module coupling. | **ACCEPTED.** v2 keeps `materialize_shared_session_hit` in `mod.rs`. Only the three helpers that use `SharedSessionRefs` move to `promote.rs`. |
| 3 | Inline the trivial 1-3 line variants (`EnqueueShapedLocal`, `VacateAllSharedExactSlots`, `UpsertLocal`). | **ACCEPTED.** v2 inlines those three. The five non-trivial variants (`DemoteOwnerRGS`, `RefreshOwnerRGS`, `ExportOwnerRGSessions`, `UpsertSynced`, `DeleteSynced`) become sibling-file handlers. (`DeleteSynced` is ~12 lines — borderline, but it touches `session_map_fd` + lookup-then-delete logic worth extracting.) |
| 4 | Pass narrow refs not `&mut WorkerCommandResults`. | **ACCEPTED** (same as Gemini #1). |
| 5 | Rename directory to `commands/`. | **ACCEPTED** (same as Codex #4). |

---

## 1. Issue framing

`userspace-dp/src/afxdp/session_glue/mod.rs` carries three violations
of `docs/engineering-style.md` ("function with >100 lines or >8
parameters is a refactor cue"):

1. `apply_worker_commands` at `mod.rs:429` — **329-LOC** body that
   dispatches **8 `WorkerCommand` variants** in one match (Tier-1).
2. `maybe_promote_synced_session` at `mod.rs:1044` — **17 params**.
   Called from two sites inside `resolve_flow_session_decision`.
3. `purge_translated_synced_hit` at `mod.rs:1129` — **11 params**.
   Called once inside `resolve_flow_session_decision`.

Per-variant files live under **`session_glue/commands/<variant>.rs`**
with **no `apply_` prefix**; the dispatcher stays in `mod.rs`.

## 2. Honest scope / value framing

**Scope split:**

- **Dispatcher split** (apply_worker_commands → `commands/`) — pure
  control-plane refactor. `apply_worker_commands` runs once per
  poll-loop tick under a `try_lock` that's empty on the steady-state
  hot path. Body only runs on HA transitions, session-sync ingest,
  shaped-TX enqueue, export drain. **Zero perf impact.**
- **Helper collapse** (`SharedSessionRefs` for maybe_promote /
  purge_translated) — these helpers ride the **packet slow path**.
  Per Codex's evidence: `poll_descriptor/mod.rs:613` calls
  `resolve_flow_session_decision` after a flow-cache miss. That's
  per-flow-first-packet rate (not per-packet steady-state because the
  flow cache absorbs most packets), but still on a packet path. The
  `SharedSessionRefs` change must therefore be either zero-cost or
  empirically verified.

**Zero-cost claim for `SharedSessionRefs`:**

The new type is `#[derive(Clone, Copy)]` and is 5 `&` references
(`4 × &Arc<…> + 1 × &SharedSessionOwnerRgIndexes`) = 40 bytes on
stack on x86-64. The compiler must inline-or-spill these 5 pointers
the same way it spills 5 individual arguments. No heap traffic, no
vtable, no atomic ops.

**Verification gates:**

1. `cargo asm` (or `cargo +nightly rustc -- --emit=asm`) on
   `resolve_flow_session_decision` before and after, diff the
   instruction count. Expected: identical or differ only by register
   allocation. (Documented in PR body.)
2. Smoke v4+v6 × push+reverse × CoS-off+CoS-on (the full 30-cell
   matrix per skill §6).
3. **`test-failover`** loop (HA-sensitivity per wave-5 §3).

If reviewers still conclude that touching packet-slow-path helper
signatures is too risky for the readability win, **PLAN-KILL is an
acceptable verdict.**

## 3. What's already shipped / partially batched

Unchanged from v1:
- `session_glue/` is a directory module.
- `tests.rs` (3725 LOC) already extracted via `#[path]` attr.
- `WorkerCommand` lives in `userspace-dp/src/afxdp/types/runtime.rs`
  as `pub(in crate::afxdp) enum`.
- Wave-4 sibling-file split landed (PR #1592).

## 4. Concrete design

### 4.1 Layout

```
userspace-dp/src/afxdp/session_glue/
├── mod.rs                       # dispatcher + everything not below
├── tests.rs                     # existing; v2 ADDS test changes:
│                                #   - dispatcher interleave test
│                                #   - 2 SharedSessionRefs site updates
│                                #     (tests.rs:348, tests.rs:393)
├── commands/
│   ├── mod.rs                   # re-exports of the 5 non-trivial
│   │                            # handlers
│   ├── demote_owner_rgs.rs      # handle_demote_owner_rgs(...)
│   ├── refresh_owner_rgs.rs     # handle_refresh_owner_rgs(...)
│   ├── export_owner_rg_sessions.rs  # handle_export_owner_rg_sessions(...)
│   ├── upsert_synced.rs         # handle_upsert_synced(...)
│   └── delete_synced.rs         # handle_delete_synced(...)
└── promote.rs                   # SharedSessionRefs + maybe_promote_synced_session
                                 # + purge_translated_synced_hit
                                 # + is_translated_forward_session_key
                                 # + should_keep_synced_hit_transient
                                 # (NOT materialize_shared_session_hit —
                                 #  AGY #2 says keep that in mod.rs)
```

**Inlined in dispatcher (not lifted):** `WorkerCommand::UpsertLocal`
(3 lines), `WorkerCommand::EnqueueShapedLocal` (1 line),
`WorkerCommand::VacateAllSharedExactSlots` (1 line).

### 4.2 Per-variant handler signatures (narrow refs per Gemini #1 / AGY #4)

```rust
// commands/demote_owner_rgs.rs
pub(super) fn handle_demote_owner_rgs(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    owner_rgs: Vec<i32>,
    now_ns: u64,
    now_secs: u64,
    cancelled_keys: &mut Vec<SessionKey>,  // narrow ref
)

// commands/refresh_owner_rgs.rs
pub(super) fn handle_refresh_owner_rgs(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    owner_rgs: Vec<i32>,
    now_ns: u64,
    now_secs: u64,
)

// commands/export_owner_rg_sessions.rs
pub(super) fn handle_export_owner_rg_sessions(
    sessions: &mut SessionTable,
    exported_sequences: &mut Vec<u64>,  // narrow ref per AGY #4
    sequence: u64,
    owner_rgs: Vec<i32>,
)

// commands/upsert_synced.rs
pub(super) fn handle_upsert_synced(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    entry: SyncedSessionEntry,
    now_ns: u64,
    now_secs: u64,
)

// commands/delete_synced.rs
pub(super) fn handle_delete_synced(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    key: SessionKey,
    now_ns: u64,
)
```

The dispatcher body becomes (≈ 60 LOC total, down from 329):

```rust
pub(super) fn apply_worker_commands(
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    _conntrack_v4_fd: c_int,
    _conntrack_v6_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> WorkerCommandResults {
    // try_lock + empty/Err early returns unchanged
    let pending = match commands.try_lock() { /* same as before */ };
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let mut cancelled_keys: Vec<SessionKey> = Vec::new();
    let mut exported_sequences = Vec::new();
    let mut shaped_tx_requests = Vec::new();
    let mut vacate_all_shared_exact_slots = false;
    for cmd in pending {
        match cmd {
            WorkerCommand::DemoteOwnerRGS { owner_rgs } => {
                commands::handle_demote_owner_rgs(
                    sessions, session_map_fd, forwarding, ha_state,
                    dynamic_neighbors, owner_rgs, now_ns, now_secs,
                    &mut cancelled_keys,
                );
            }
            WorkerCommand::RefreshOwnerRGS { owner_rgs } => {
                commands::handle_refresh_owner_rgs(
                    sessions, session_map_fd, forwarding, ha_state,
                    dynamic_neighbors, owner_rgs, now_ns, now_secs,
                );
            }
            WorkerCommand::ExportOwnerRGSessions { sequence, owner_rgs } => {
                commands::handle_export_owner_rg_sessions(
                    sessions, &mut exported_sequences, sequence, owner_rgs,
                );
            }
            WorkerCommand::UpsertSynced(entry) => {
                commands::handle_upsert_synced(
                    sessions, session_map_fd, forwarding, ha_state,
                    dynamic_neighbors, entry, now_ns, now_secs,
                );
            }
            WorkerCommand::UpsertLocal(entry) => {
                // 3-liner — inline per AGY #3
                sessions.install_with_protocol_with_origin(
                    entry.key, entry.decision, entry.metadata, entry.origin,
                    now_ns, entry.protocol, entry.tcp_flags,
                );
            }
            WorkerCommand::DeleteSynced(key) => {
                commands::handle_delete_synced(sessions, session_map_fd, key, now_ns);
            }
            WorkerCommand::EnqueueShapedLocal(req) => {
                shaped_tx_requests.push(req);  // inline per AGY #3
            }
            WorkerCommand::VacateAllSharedExactSlots => {
                vacate_all_shared_exact_slots = true;  // inline per AGY #3
            }
        }
    }
    WorkerCommandResults {
        cancelled_keys, exported_sequences, shaped_tx_requests,
        vacate_all_shared_exact_slots,
    }
}
```

### 4.3 Context-struct collapse with `Copy` (Codex #2)

```rust
// promote.rs

/// Shared-session backing references. Travels together at every site
/// that touches synced sessions. `Copy` because it is 5 pointer-width
/// fields with no destructor — passing it by value is identical to
/// passing 5 explicit references.
#[derive(Clone, Copy)]
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
) -> SessionMetadata
//   ^ 13 params (was 17)

pub(super) fn purge_translated_synced_hit(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared: SharedSessionRefs<'_>,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
)
//   ^ 7 params (was 11)
```

Call sites in `resolve_flow_session_decision`:

```rust
let shared = SharedSessionRefs {
    sessions: shared_sessions,
    nat_sessions: shared_nat_sessions,
    forward_wire_sessions: shared_forward_wire_sessions,
    owner_rg_indexes: shared_owner_rg_indexes,
};
// Three call sites can each take `shared` by Copy:
purge_translated_synced_hit(sessions, session_map_fd, shared, key, decision, metadata, origin);
maybe_promote_synced_session(sessions, session_map_fd, shared, /* … */);
maybe_promote_synced_session(sessions, session_map_fd, shared, /* … */);
```

### 4.4 Test changes

1. **Update `tests.rs:348` and `tests.rs:393`** — build a
   `SharedSessionRefs { … }` literal at each site before calling
   `maybe_promote_synced_session` with the new signature. (Both tests
   declare the four shared maps as locals already; this is purely
   wrapping them up.)
2. **Add `apply_worker_commands_dispatch_order_pin` test** (Codex
   #3) — queue 6 commands in the order `[Demote, Upsert, Export,
   ShapedLocal, Refresh, Vacate]`, run dispatcher, assert:
   - `cancelled_keys[0..n]` contains the demoted keys in the
     iteration order of `demote_owner_rg`,
   - `exported_sequences == vec![sequence]`,
   - `shaped_tx_requests.len() == 1` with the expected `TxRequest`,
   - `vacate_all_shared_exact_slots == true`.
3. **Optional codegen pin** — `cargo asm
   userspace_dp::afxdp::session_glue::resolve_flow_session_decision`
   before/after; document the diff (if any) in the PR body.

## 5. Public API preservation

Identical to v1:
- `pub(super) fn apply_worker_commands(...) -> WorkerCommandResults`
- `pub(super) fn resolve_flow_session_decision(...) -> Option<...>`
- All other `pub(super)` fns unchanged.
- `WorkerCommandResults` field order unchanged.

New `pub(super)` items (module-private):
- `struct SharedSessionRefs<'a>` in `promote.rs`.
- `handle_*` fns in `commands/<variant>.rs`.

## 6. Hidden invariants the change must preserve

Same six as v1, with two additions:

7. **`SharedSessionRefs` is zero-cost.** `#[derive(Copy)]` plus
   `repr(Rust)` plus 5 pointer fields = 40 B on stack. Passing it by
   value vs. passing 5 explicit args must produce identical (modulo
   register allocation) asm. Verified with `cargo asm` diff.
8. **Test call-site updates are mechanical.** `tests.rs:348` and
   `:393` wrap existing locals in a `SharedSessionRefs { … }` literal
   — no test behavior change.

## 7. Risk assessment (updated)

| Class | Level | Notes |
|---|---|---|
| Behavioral regression — dispatcher | LOW | Code motion; new dispatcher test pins order. |
| Behavioral regression — helpers | LOW | Body unchanged; only signature collapsed via `Copy` struct. |
| Lifetime / borrow-checker | LOW | `SharedSessionRefs<'a>` bundles immutable references. `Copy` removes any move-after-use concern. |
| Performance regression — control plane | NONE | Dispatcher is control-plane. |
| Performance regression — packet slow path | LOW (verified) | `SharedSessionRefs` is `Copy` and pointer-only. `cargo asm` diff in PR body. Codex's BLOCKER specifically called this scope error; v2 acknowledges and adds the gate. |
| Architectural mismatch | LOW | Same shape as #1592 sibling-split. |
| HA-sensitive (session-sync path) | MED | Same as v1. Mitigated by AWAITING-SMOKE + test-failover. |

## 8. Test plan

1. `cargo build --release` clean.
2. `cargo test --release` — full suite.
3. 5× flake check on the two affected tests plus the new dispatcher
   order pin (3 tests × 5 runs).
4. Full Go suite.
5. **`cargo asm` diff** on `resolve_flow_session_decision` and
   `apply_worker_commands` — paste before/after byte counts in PR
   body. Investigate any non-trivial divergence.
6. **AWAITING-SMOKE + `scope: smoke-plus-test-failover`** (per
   wave-5 §3 and reviewer consensus).
7. Smoke matrix: v4+v6 × push+reverse × CoS-off+CoS-on, plus
   per-class 5201-5206.
8. `test-failover` (HA-sensitive).

## 9. Out of scope (explicitly)

- `resolve_flow_session_decision`'s own 17 params — separate issue.
- `purge_sessions_for_input_dscp_filter_revalidation` (12 params).
- `WorkerCommand` enum reshape.
- `SessionTable` storage layout (#964 territory).
- Per-handler test colocation.
- `materialize_shared_session_hit` move (AGY #2) — stays in `mod.rs`.

## 10. Open questions for adversarial review (round 2)

1. Does the `cargo asm` codegen gate sufficiently address Codex's
   packet-slow-path BLOCKER, or does the helper-collapse still need
   to be a separate PR?
2. Is the trivial-variant-inline split (5 lifted, 3 inlined) the
   right cohesion call, or should all 8 lift (Gemini #2)?
3. Does the new interleaved-variant test cover the order semantics
   Codex flagged, or does it need to expand to e.g. dedup of repeated
   `DemoteOwnerRGS` arms?
4. `SharedSessionRefs` is `#[derive(Clone, Copy)]` — any way the
   compiler could fail to optimize the by-value pass at any of the 3
   call sites that the explicit-argument form would not?
5. PLAN-KILL acceptance — if a reviewer still believes touching
   packet-slow-path helper signatures is too risky for a readability
   refactor on a 329-LOC dispatcher, **PLAN-KILL is the right call.**
