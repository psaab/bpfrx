# Plan: #959 Phase 4 — extract `pending_*_tx_*` into `WorkerTxCounters`

## Status

Phase 4 of #959. Phase 1 (#1167) extracted `dbg_*` → `WorkerTelemetry`.
Phase 2 (#1168) extracted `scratch_*` → `WorkerScratch`.
Phase 3 (#1169) extracted `cos_*` → `WorkerCos`.

## Scope

Move 6 `pending_*_tx_*` per-binding TX-disposition packet counters
out of `BindingWorker` into a new `WorkerTxCounters` sub-struct
accessed via `binding.tx_counters.pending_X`:

```
pending_direct_tx_packets, pending_copy_tx_packets,
pending_in_place_tx_packets,
pending_direct_tx_no_frame_fallback_packets,
pending_direct_tx_build_fallback_packets,
pending_direct_tx_disallowed_fallback_packets
```

These are incremented from the descriptor loop and TX dispatch
pipeline; drained on the per-second debug tick into the
`BindingLiveState` atomic mirrors.

## Methodology

Same compiler-driven approach as Phases 1-3.

- New file `userspace-dp/src/afxdp/worker/tx_counters.rs`.
- Replace 6 BindingWorker fields with `pub(crate) tx_counters: WorkerTxCounters`.
- 3 files affected for callsite rewrite; 29 callsites total
  (smallest phase yet).
- `WorkerTxCounters` has NO `Default` derive (per Phase 2 lesson).

The `BindingLiveState` mirror at `umem/mod.rs:996+` reads
`binding.pending_X` and feeds `b.live.pending_X.fetch_add(...)`. After
this PR, only the read side becomes `binding.tx_counters.pending_X`;
the atomic side `b.live.pending_X` is unchanged (different struct).

## Acceptance

- `cargo build --release` clean.
- `cargo test --release` — 952 passed.
- `cargo test --release flush_clears_records_and_increments_sequence`
  — 5 named runs (per the standing rule that test failures must be
  proven before merge).
- `go build ./...` + `go test ./...` clean.
- v4 + v6 smoke against `172.16.80.200` / `2001:559:8585:80::200`.
- Codex + Gemini hostile review.

## NOT in scope

- XSK rings (device, rx, tx) → Phase 5 (highest risk).
- `flow_cache*` → separate concern (cache, not counter).
- `last_*_ns` timestamps → gating logic, out of scope.
- `#[repr(align(64))]` cache-line alignment — late phase.
