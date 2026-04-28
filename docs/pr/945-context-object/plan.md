# #945: Context Object refactor of `poll_binding_process_descriptor`

Plan v2 — 2026-04-28. Addresses Codex hostile review (task-moivkfnx-5e9v6g).

## Problem

`poll_binding_process_descriptor` at `userspace-dp/src/afxdp.rs:667-699`
takes 31 parameters. This is unergonomic, hard to test, and pushes
arguments to the stack on common ABIs. The function is also
deliberately split out as its own perf-visible compilation unit
(`afxdp.rs:659-664`), so codegen behavior matters.

## Scope

This is **PR 1 of 2**:

- **PR 1 (this plan)**: introduce `WorkerContext<'a>` (16
  shared-references) and `TelemetryContext<'a>` (`dbg` + `counters`).
  Reduces signature from **31 → 15 physical params** (13 direct + 2
  contexts). Mechanical refactor with no semantic change.
- **PR 2 (deferred)**: address the `binding` / `*const MmapArea`
  aliasing only if perf data justifies it. Wrapping a raw pointer in
  a struct does not solve the borrow conflict; only a non-mechanical
  decomposition (e.g. consume `binding` and re-borrow `umem.area()`
  inside, or split `BindingWorker` into disjoint field borrows) would
  help. Defer.

## Investigation summary (Codex task-moivb75o-yxckca)

- Single caller: `userspace-dp/src/afxdp.rs:526-558`.
- 16 params are shared-references — **`WorkerContext` candidates**:
  `ident`, `binding_lookup`, `forwarding`, `ha_state`,
  `dynamic_neighbors`, `shared_sessions`, `shared_nat_sessions`,
  `shared_forward_wire_sessions`, `shared_owner_rg_indexes`,
  `slow_path`, `local_tunnel_deliveries`, `recent_exceptions`,
  `last_resolution`, `peer_worker_commands`, `dnat_fds`, `rg_epochs`.
- 2 params are mutable telemetry — **`TelemetryContext`**:
  `dbg`, `counters` (`afxdp.rs:696-698`, written at `759-763`,
  `1206-1212`, `1372-1376`).
- Remaining 13 stay as direct params: `binding` (`&mut`), `area`
  (raw ptr — see safety invariant below), `sessions` (`&mut`),
  `screen` (`&mut`), `available`, `validation` (`Copy`), three
  timestamps, `worker_id`, `binding_index`, two conntrack fds.

## Naming clarification (Codex Style finding)

`WorkerContext` is a **shared/passed-through context**, not "read-only"
in the strict sense. Several fields mutate state behind locks (e.g.
`dynamic_neighbors.lock().insert(...)` at `afxdp.rs:928,996`,
`last_resolution.lock()` at `afxdp.rs:3812`). What `WorkerContext`
actually provides is:

- Outer-borrow lifetime (`'a`) is shared, no mutable aliasing at the
  Rust level.
- Interior mutability via `Mutex` / `Arc` is preserved exactly as
  today.

Doc-comment on the struct will state this explicitly.

## Construction lifetime

The contexts are constructed **per RX batch call** at `afxdp.rs:526`
(corrected from v1's "per outer poll iteration" claim per Codex
Style finding). Construction cost is 16 pointer copies (~64 bytes);
this is a single rep-stos in optimized codegen.

## Safety invariant: `area: *const MmapArea`

Currently `area = binding.umem.area()` (`afxdp.rs:421`,
`umem.rs:42-44`) and is then passed alongside `&mut binding` into
`poll_binding_process_descriptor`. The raw pointer exists because
Rust forbids `&MmapArea` co-existing with `&mut BindingWorker`.

Safety invariant (must be documented in code):
- `area` remains valid for the duration of the call as long as
  `binding.umem` is not moved, replaced, or dropped.
- The `WorkerUmem` / `MmapArea` lifecycle is owned by `binding` and
  is not modified during the per-batch poll (`umem.rs:15-17`,
  `42-44`, `511-514`).

PR 1 adds a `// SAFETY: ...` comment at the call site capturing this
invariant. Refactoring the pointer into a borrow is PR 2 work.

## Design

### `WorkerContext<'a>`

Covariant in `'a` (Codex Q1 confirmed). No `for<'a>` needed; use
`&WorkerContext<'_>` at call sites.

```rust
pub(crate) struct WorkerContext<'a> {
    pub ident: &'a BindingIdentity,
    pub binding_lookup: &'a WorkerBindingLookup,
    pub forwarding: &'a ForwardingState,
    pub ha_state: &'a BTreeMap<i32, HAGroupRuntime>,
    pub dynamic_neighbors: &'a Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    pub shared_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub shared_nat_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub shared_forward_wire_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub shared_owner_rg_indexes: &'a SharedSessionOwnerRgIndexes,
    pub slow_path: Option<&'a Arc<SlowPathReinjector>>,
    pub local_tunnel_deliveries: &'a Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    pub recent_exceptions: &'a Arc<Mutex<VecDeque<ExceptionStatus>>>,
    pub last_resolution: &'a Arc<Mutex<Option<PacketResolution>>>,
    pub peer_worker_commands: &'a [Arc<Mutex<VecDeque<WorkerCommand>>>],
    pub dnat_fds: &'a DnatTableFds,
    pub rg_epochs: &'a [AtomicU32; MAX_RG_EPOCHS],
}
```

### `TelemetryContext<'a>`

```rust
pub(crate) struct TelemetryContext<'a> {
    pub dbg: &'a mut DebugPollCounters,
    pub counters: &'a mut BatchCounters,
}
```

### New signature (15 params)

```rust
fn poll_binding_process_descriptor(
    binding: &mut BindingWorker,
    binding_index: usize,
    area: *const MmapArea,
    available: u32,
    sessions: &mut SessionTable,
    screen: &mut ScreenState,
    validation: ValidationState,
    now_ns: u64,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
    worker_id: u32,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    worker_ctx: &WorkerContext,
    telemetry: &mut TelemetryContext,
)
```

13 direct params + 2 contexts = **15 physical params** (corrected per
Codex Q7 — earlier draft incorrectly said "~10").

## Same-type wiring hazard (Codex Q3 — DISAGREE on prior compile-gate claim)

The compile gate alone does NOT catch wrong-type-but-same-type
swaps. Specific risk groups identified by Codex:

- `shared_sessions` / `shared_nat_sessions` / `shared_forward_wire_sessions`
  — all `&Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>`.
  Swapping any pair compiles cleanly but breaks NAT / forward-wire
  semantics silently.
- `conntrack_v4_fd` / `conntrack_v6_fd` — both `c_int`.
- `now_ns` / `now_secs` / `ha_startup_grace_until_secs` — all `u64`.

**Mitigation**: the refactor will be done as a single mechanical pass
where the field name in the struct **matches the parameter name** in
the original signature. Construction at the call site uses
**named-field shorthand** (`WorkerContext { forwarding, ... }`) which
the compiler verifies against the local-variable identifiers,
catching any swap. Reviewer checklist explicitly verifies each field
assignment against the original parameter order.

## Implementation steps

1. **Add `WorkerContext` + `TelemetryContext`** in
   `userspace-dp/src/afxdp/types.rs`. Doc-comment notes the "interior
   mutability via locks" semantic.
2. **Construct at call site** (`afxdp.rs:526`). Build both contexts
   with named-field shorthand syntax so the compiler enforces no
   positional-swap mistakes.
3. **Rewrite the function signature** at `afxdp.rs:667`.
4. **Mechanical body rewrite**: every reference to `forwarding` →
   `worker_ctx.forwarding`, `dbg` → `telemetry.dbg`, etc. **Several
   hundred line-level edits** (corrected from v1's "~80" per Codex
   Style finding) — `dbg` and `forwarding` references dominate.
5. **Add safety comment** at the `area` raw-pointer construction site
   capturing the `WorkerUmem` invariant.
6. **Run `cargo build --release`** and `cargo test --release`.

## Test plan

- `cargo test --release` (800 tests) — primary correctness gate.
- `cargo check --release --features debug-log` — exercises the
  `dbg` codepaths under the `debug-log` feature flag.
- **Codegen inspection (HARD gate per Codex Q4)**: `cargo rustc
  --release -- --emit=asm` on `afxdp.rs`, diff the assembly of
  `poll_binding_process_descriptor` before/after. Acceptance: no
  significant rise in stack-spill count or function epilogue size.
  Per Codex: "If both are stack-resident and the function is not
  inlined, direct `forwarding` is one stack load; `worker_ctx.forwarding`
  is load context pointer, then load field." Codegen diff is the
  oracle.
- **`perf stat -e instructions,cycles,ipc,branch-misses`** before/after
  on a 60s iperf3 run. Acceptance: IPC within ±1% (noise floor).
- **Cluster smoke** (HARD gate):
  - iperf-c P=12 ≥ 22 Gb/s
  - iperf-c P=1 ≥ 6 Gb/s
  - iperf-b P=12 ≥ 9.5 Gb/s, 0 retx
  - mouse p99 within ±5% of 27.77 ms (post-#941 baseline)

## Risk

**Medium.** (Corrected from v1's "Medium-low" per Codex Q8.)

- Hot-path function with a deliberate codegen-stable footprint.
- Same-type-swap hazard requires careful review (mitigation above).
- `area: *const MmapArea` raw-pointer invariant must remain valid; PR
  doesn't change this but adds documentation.
- Compiler is the correctness oracle for unbound-name typos but not
  for same-type wiring swaps.

## Out of scope (PR 2 follow-up)

- `PacketContext` for `desc` / `meta` — these are loop-local, not
  function params. No win from grouping.
- Restructuring `binding` / `area` aliasing — requires non-mechanical
  decomposition (consume + re-borrow, or split `BindingWorker`).
- Splitting `sessions` / `screen` — they are genuinely mutable
  cross-packet state; no fit with `&'a` shared context shape.

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` 800/800 pass.
3. Codegen diff: no significant regression in spill count / epilogue size.
4. `perf stat` IPC: within ±1%.
5. Cluster smoke: all four gates green.
6. Codex hostile review: AGREE-TO-MERGE.
7. Gemini adversarial review: AGREE-TO-MERGE.
