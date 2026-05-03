# Plan: #959 Phase 2 — extract `scratch_*` into `WorkerScratch`

## Status

Phase 2 of #959 BindingWorker decomposition. Phase 1 shipped via
#1167 (23 `dbg_*` counters → `WorkerTelemetry`).

## Scope

Move the 11 `scratch_*` reusable buffers out of `BindingWorker` into
a new `WorkerScratch` sub-struct accessed via
`binding.scratch.scratch_X`:

```
scratch_recycle, scratch_forwards, scratch_fill,
scratch_prepared_tx, scratch_local_tx,
scratch_exact_prepared_tx, scratch_exact_local_tx,
scratch_completed_offsets, scratch_post_recycles,
scratch_cross_binding_tx, scratch_rst_teardowns
```

These are pre-allocated in `BindingWorker::create` and reused every
poll cycle (cleared at the top, pushed-to as the descriptor loop
produces work). No allocation pattern change; pure structural
extraction.

## Methodology

Same compiler-driven approach as Phase 1 (#1167):

1. New file `userspace-dp/src/afxdp/worker/scratch.rs` defining
   `pub(crate) struct WorkerScratch` with `Default` derived.
2. Add `pub(crate) scratch: WorkerScratch` to `BindingWorker`.
3. Remove the 11 individual `scratch_*` fields.
4. Update the `Self { … }` initializer at
   `worker/mod.rs:348-376` (BindingWorker::create) to populate the
   nested `scratch: WorkerScratch { … }` block. The capacity hints
   stay attached to each Vec — no runtime change.
5. Compiler walks every E0609. Each error rewrites
   `X.scratch_Y` → `X.scratch.scratch_Y`. Mechanical sed scoped to
   the 6 affected files.

## Files affected (6 edited + 1 new)

- new: `userspace-dp/src/afxdp/worker/scratch.rs`
- edit: `userspace-dp/src/afxdp/worker/mod.rs`
- edit: `userspace-dp/src/afxdp/worker/lifecycle.rs`
- edit: `userspace-dp/src/afxdp/poll_descriptor.rs`
- edit: `userspace-dp/src/afxdp/cos/queue_service/service.rs`
- edit: `userspace-dp/src/afxdp/tx/transmit.rs`
- edit: `userspace-dp/src/afxdp/tx/rings.rs`

118 callsites total.

## Acceptance

- `cargo build --release` clean.
- `cargo test --release` — 952 passed (no count change vs Phase 1).
- `go build ./... && go test ./...` clean.
- v4 + v6 smoke against `172.16.80.200` / `2001:559:8585:80::200`.
- Codex + Gemini hostile review.

## NOT in scope

- `cos_*` (5 fields) → Phase 3.
- `pending_direct_tx_*` counters → Phase 4.
- XSK rings → Phase 5.
- `#[repr(align(64))]` — deferred.
