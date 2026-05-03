# Plan: #959 Phase 3 — extract `cos_*` into `WorkerCos`

## Status

Phase 3 of #959. Phase 1 (#1167) extracted `dbg_*` → `WorkerTelemetry`.
Phase 2 (#1168) extracted `scratch_*` → `WorkerScratch`.

## Scope

Move 5 `cos_*` per-binding CoS scheduling fields out of
`BindingWorker` into a new `WorkerCos` sub-struct accessed via
`binding.cos.cos_X`:

```
cos_fast_interfaces, cos_interfaces, cos_interface_order,
cos_interface_rr, cos_nonempty_interfaces
```

## Methodology

Same compiler-driven approach as Phases 1-2.

- New file `userspace-dp/src/afxdp/worker/cos_state.rs`
  (filename is `cos_state.rs` not `cos.rs` because the
  `worker::cos` module name is already taken by
  `worker/cos.rs` which holds runtime helpers — the
  data-holding sub-struct gets its own file).
- Replace 5 BindingWorker fields with `pub(crate) cos: WorkerCos`.
- 12 files affected for callsite rewrite; 102 callsites total.
- `WorkerCos` has NO `Default` derive (per Phase 2 lesson — the
  legitimate construction goes through the explicit
  `BindingWorker::create` literal).

## Acceptance

- `cargo build --release` clean.
- `cargo test --release` — 952 passed.
- `go build ./...` + `go test ./...` clean.
- v4 + v6 smoke against `172.16.80.200` / `2001:559:8585:80::200`.
- Codex + Gemini hostile review.

## NOT in scope

- `pending_direct_tx_*` counters → Phase 4.
- XSK rings → Phase 5.
- `#[repr(align(64))]` cache-line alignment — late phase.
