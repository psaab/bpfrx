# Plan: #959 Phase 1 — extract `dbg_*` into `WorkerTelemetry`

## Status

Phase 1 of #959 BindingWorker decomposition. Closes #1125 (already
closed as duplicate). Sequenced before #1127 (PacketBatch) per the
note on that issue.

## Problem

`BindingWorker` (`userspace-dp/src/afxdp/worker/mod.rs:34`) has 80+
fields. The 23 `dbg_*` counters are the cleanest extraction target:

- Almost all write-only (incremented from many sites). Three
  exceptions are read for comparison or formatting:
  - `dbg_rx_avail_max` — comparison at `worker/lifecycle.rs:124`.
  - `dbg_sendto_enobufs`, `dbg_sendto_err` — formatted in
    `tx/rings.rs` ENOBUFS / error log paths.
- No aliasing concerns: counters are accessed independently of any
  XSK ring, scratch buffer, or CoS state.
- Many access patterns: `binding.dbg_*`, `self.dbg_*`,
  `b.dbg_*` (dominant in worker/mod.rs:1156-1599), `worker.dbg_*`.
  Total raw `\.dbg_` matches in `userspace-dp/src/afxdp`: ~120
  (incl. comments, tests, and `BindingLiveState`'s own mirror
  fields which must NOT change).

## Scope

Move these 23 fields out of `BindingWorker` into a new
`WorkerTelemetry` struct, aggregated at one field
`pub(crate) telemetry: WorkerTelemetry`:

```
dbg_fill_submitted, dbg_fill_failed,
dbg_poll_cycles, dbg_backpressure,
dbg_rx_empty, dbg_rx_wakeups,
dbg_tx_ring_submitted, dbg_tx_ring_full,
dbg_completions_reaped,
dbg_sendto_calls, dbg_sendto_err,
dbg_sendto_eagain, dbg_sendto_enobufs,
dbg_bound_pending_overflow, dbg_cos_queue_overflow,
dbg_tx_tcp_rst,
dbg_rx_avail_nonzero, dbg_rx_avail_max,
dbg_fill_pending, dbg_device_avail,
dbg_rx_wake_sendto_ok, dbg_rx_wake_sendto_err,
dbg_rx_wake_sendto_errno
```

23 fields total. (Note: there are `dbg_*` mirror fields in a
separate publish-snapshot struct at `worker/mod.rs:1851+` and in
`BindingLiveState` atomics at `umem/mod.rs:763+` — both **out of
scope**. Those are different types and the Rust compiler distinguishes
them by type, not by name.)

## Methodology — compiler-driven, NOT sed-driven

This was the major change after round-1 plan review:

1. Add `pub(crate) struct WorkerTelemetry { … }` with the 23 fields
   and `#[derive(Default)]`. Place in
   `userspace-dp/src/afxdp/worker/telemetry.rs` (new file).
2. Add `pub(crate) telemetry: WorkerTelemetry` field to BindingWorker.
3. **Remove** the 23 `dbg_*` fields from `BindingWorker`. The
   compiler now flags every callsite that accesses a removed field.
4. Update the `Self { … }` constructor literal at
   `worker/mod.rs:421-443` (BindingWorker is constructed via
   `BindingWorker::create` which uses an explicit struct literal,
   not `Default`/`new`/builder). Remove the 23 field initializers
   from the literal; add one `telemetry: WorkerTelemetry::default()`
   line.
5. Walk every compile error and rewrite the access:
   `binding.dbg_X` → `binding.telemetry.dbg_X`,
   `self.dbg_X` → `self.telemetry.dbg_X`,
   `b.dbg_X` → `b.telemetry.dbg_X`,
   `worker.dbg_X` → `worker.telemetry.dbg_X`,
   etc.
   The compiler is exhaustive — every miss fails the build.
6. **Important**: do NOT touch `snap.dbg_X` (publish snapshot at
   `coordinator/mod.rs:1218`), `live.dbg_X` (BindingLiveState in
   tests), or any access on the `BindingLiveState` mirror at
   `umem/mod.rs:763`. These are different types; the compiler
   protects us.
7. `cargo build --release` clean.
8. `cargo test --release` clean.
9. Smoke v4 + v6.

## Why compiler-driven beats sed

- **Sed risk**: `binding` and `self` are not unique tokens. A
  separate `BindingStatus` snapshot struct in `coordinator/mod.rs`
  is read into a local also named `binding` (see lines 1218-1225,
  1348-1351). A regex `s/binding\.dbg_/.../g` would corrupt those
  callsites.
- **Compiler risk**: zero. The compiler knows the type of each
  receiver. Removing the fields from BindingWorker fails every
  BindingWorker access; the snapshot/atomic mirrors keep their own
  fields and are unaffected.
- **Cost**: the compiler walks ~30-50 callsites to fix manually
  instead of one-shot sed. Trade safety for editing time. For a
  refactor that must not regress the data-plane, compiler-driven is
  the right choice.

## Acceptance

- `go build ./...` (Go side untouched, but verify nothing leaked).
- `cargo build --release` clean.
- `cargo test --release` — all tests pass.
- v4 smoke against `172.16.80.200` — 0 retr.
- v6 smoke against `2001:559:8585:80::200` — 0 retr.
- Codex + Gemini hostile code review on the resulting PR.

## Risks

1. **Sed misses.** Fields that appear in `format!` / `info!` /
   `eprintln!` calls (unlikely but possible). Mitigation: build will
   fail on any miss; fix and re-build.
2. **Other structs mirror these field names.** The publish-snapshot
   struct at `worker/mod.rs:1851+` has `dbg_tx_ring_full`,
   `dbg_sendto_enobufs`, etc. Sed must NOT touch that struct's
   fields. Mitigation: scope sed to BindingWorker call sites only;
   those use `binding.dbg_*` / `self.dbg_*` patterns, not
   `snapshot.dbg_*`. Verify by grep before sed.
3. **Future merge conflicts.** This PR moves 24 fields. If a separate
   PR adds a new `dbg_*` field, it'll conflict. Mitigation: small
   focused PR, ship fast.

## NOT in scope (deferred to Phase 2+)

- `scratch_*` extraction into `WorkerScratch` (Phase 2).
- `cos_*` extraction into `CosEngine` / `ShaperEngine` (Phase 3).
- XSK rings / device / umem extraction (Phase 4).
- `pending_direct_tx_*` counters — these are TX-path counters, not
  generic debug counters; their semantic affinity is different and
  they may belong with the TX engine extraction in a later phase.
- `flow_cache*` — flow-cache state, not telemetry.
- `last_*_ns` timestamps — these gate retry logic, not pure
  telemetry; out of scope.
- `#[repr(align(64))]` on the new struct — that's a Phase N
  optimization once the cache-line layout is measured. Phase 1 just
  makes the struct exist; alignment is non-functional and adds
  review surface.

## Phase 2+ preview (not in this PR)

After Phase 1 lands, candidate extractions in priority order:
- Phase 2: `scratch_*` (11 fields) → `WorkerScratch`
- Phase 3: `cos_*` (5 fields) → `CosEngine`
- Phase 4: `pending_direct_tx_*` + `pending_*_packets` counters (6
  fields) → `TxPipelineCounters`
- Phase 5: XSK rings (`device`, `rx`, `tx`) → `XskRings` (highest
  risk; ring borrows are heavily aliased through the codebase)
