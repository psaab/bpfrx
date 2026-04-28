# #945: Context Object refactor of `poll_binding_process_descriptor`

Plan v1 — 2026-04-28.

## Problem

`poll_binding_process_descriptor` at `userspace-dp/src/afxdp.rs:667-699`
takes 31 parameters. This is unergonomic, hard to test, and pushes
arguments to the stack on common ABIs.

Codex investigation confirmed the count and grouped them; see
"Investigation summary" below.

## Scope

This is **PR 1 of 2**:

- **PR 1 (this plan)**: introduce `WorkerContext` for read-only/lock-
  protected references and `TelemetryContext` for `dbg` + `counters`.
  Reduces signature from 31 → ~10 params. Mechanical, compile-time-
  enforced, no semantic change.
- **PR 2 (deferred to a follow-up)**: address the `binding` /
  `*const MmapArea` aliasing constraint by introducing `PacketContext`
  if measurement shows it's worth the borrow-shape risk. The current
  raw pointer for `area` exists specifically because Rust's borrow
  checker forbids `&MmapArea` co-existing with `&mut BindingWorker`
  (since `area = binding.umem.area()`). Wrapping it in a struct does
  NOT solve that — it just moves the raw pointer. Defer.

## Investigation summary (Codex task-moivb75o-yxckca)

- Single caller: `userspace-dp/src/afxdp.rs:526-558`.
- 16 params are read-only or `&Arc<>` — **`WorkerContext` candidates**:
  `ident`, `binding_lookup`, `forwarding`, `ha_state`,
  `dynamic_neighbors`, `shared_sessions`, `shared_nat_sessions`,
  `shared_forward_wire_sessions`, `shared_owner_rg_indexes`,
  `slow_path`, `local_tunnel_deliveries`, `recent_exceptions`,
  `last_resolution`, `peer_worker_commands`, `dnat_fds`, `rg_epochs`.
- 2 params are mutable telemetry — **`TelemetryContext`**:
  `dbg`, `counters`.
- The remaining ~13 stay as direct params: `binding` (`&mut`), `area`
  (raw ptr — see PR 2 deferral), `sessions` (`&mut`), `screen`
  (`&mut`), `available`, `validation` (Copy), three timestamps,
  `worker_id`, `binding_index`, two conntrack fds.

## Design

### `WorkerContext<'a>`

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

All fields are `Copy`-by-reference. The struct itself is constructed
once per outer poll iteration at `afxdp.rs:526` and passed by `&` into
`poll_binding_process_descriptor`. No lifetime cycles, no aliasing.

### `TelemetryContext<'a>`

```rust
pub(crate) struct TelemetryContext<'a> {
    pub dbg: &'a mut DebugPollCounters,
    pub counters: &'a mut BatchCounters,
}
```

The `&mut` on the struct itself ensures exclusive access, and the
internal `&mut` fields stay borrow-distinct because they are different
types.

### New signature

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

13 direct params + 2 contexts = 15 logical inputs. The 16 fields in
`WorkerContext` are addressed by name (`worker_ctx.forwarding`, etc.),
which is no worse than the current style at the call sites and makes
new dependencies visible.

## Implementation steps

1. **Add the structs** in `userspace-dp/src/afxdp/types.rs` next to the
   existing context-flavored types. Verify `cargo check` clean.
2. **Construct at call site** (`afxdp.rs:526`). Build `WorkerContext`
   and `TelemetryContext` from the existing locals; pass into the
   refactored function.
3. **Rewrite the function signature** at `afxdp.rs:667`. The body
   replaces direct `forwarding` / `dbg` / etc. references with
   `worker_ctx.forwarding` / `telemetry.dbg` / etc.
4. **Mechanical search-and-replace** of the ~80 references inside the
   function body. Compile-driven: any miss is a compile error.
5. **Run `cargo build --release`** and `cargo test --release`.
   Compiler is the correctness oracle here — no behavior changes.

## Test plan

- `cargo test --release` (800 tests). Must pass with no new flakes.
  This is the primary correctness gate because the refactor is purely
  mechanical.
- Cluster smoke (deploy + acceptance gates) — required because the
  function is on the hot path and we want to prove no perf regression:
  - iperf-c P=12 ≥ 22 Gb/s
  - iperf-c P=1 ≥ 6 Gb/s
  - iperf-b P=12 ≥ 9.5 Gb/s, 0 retx
  - mouse p99 within ±5% of 27.77 ms (post-#941 baseline)
- `perf stat -e instructions,cycles,branch-misses` ideally, to check
  IPC unchanged. Not a hard gate; if cycles vary by ±2% it's noise.

## Risk

**Medium-low.**

- Compile gate catches every parameter omission.
- No semantic change: the function body still receives every value it
  did before; only addressing changes.
- Hot path concern: the compiler may now load `worker_ctx.X` from a
  struct field instead of from a register-cached arg. With 31 args,
  most were already stack-passed on x86_64 SysV ABI (only first 6
  integer args go into registers). Worst case: zero net change.
  Best case: the struct sits in L1d and lookups hit cache.

## Out of scope (for PR 2 follow-up)

- `PacketContext` for `desc` / `meta` — these are loop-local, not
  function params. No win.
- Restructuring `binding` / `area` aliasing — the raw `*const
  MmapArea` is intentional (borrow checker), and wrapping in a context
  doesn't help.
- Splitting `sessions` / `screen` — they are genuinely mutable
  cross-packet state and don't fit the read-only context shape.

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` 800/800 pass.
3. Cluster smoke: all gates green.
4. Codex hostile review: AGREE-TO-MERGE.
5. Gemini adversarial review: AGREE-TO-MERGE.
