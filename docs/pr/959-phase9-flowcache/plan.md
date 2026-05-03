# Plan: #959 Phase 9 — extract flow-cache state into `WorkerFlowCacheState`

## Status

Phase 9 of #959. Phases 1-8 (#1167-#1174) extracted dbg_*,
scratch_*, cos_*, pending_*_tx_*, BPF FDs, timers, TX pipeline,
bind metadata.

## Scope

Move 2 flow-cache state fields out of `BindingWorker` into a new
`WorkerFlowCacheState` sub-struct accessed via `binding.flow.X`:

```
flow_cache, flow_cache_session_touch
```

`flow_cache` is the per-worker FlowCache lookup. `flow_cache_session_touch`
counts session touches; the 64-touch boundary triggers a session-table
refresh in the descriptor loop.

Filename is `flow_cache_state.rs` because `flow_cache.rs` is taken
by the FlowCache data structure itself (in
`userspace-dp/src/afxdp/flow_cache.rs`).

## Methodology

Same compiler-driven approach as Phases 1-8. 18 callsites across 3
files (poll_descriptor.rs, worker/lifecycle.rs, umem/mod.rs).

`WorkerFlowCacheState` has NO `Default` derive — for consistency
with the other #959 sub-structs.

## Acceptance

- `cargo build --release` clean.
- `cargo test --release` — 952 passed.
- `cargo test --release flush_clears_records_and_increments_sequence`
  — 5/5 named runs.
- `go build ./...` + `go test ./...` clean.
- v4 + v6 smoke against 172.16.80.200 / 2001:559:8585:80::200.
- Codex hostile review.

## NOT in scope

- `outstanding_tx` → tiny followup phase.
- XSK rings (`device`, `rx`, `tx`) → still highest-risk; deferred.
