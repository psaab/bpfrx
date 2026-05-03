# Plan: #959 Phase 7 — extract TX pipeline state into `WorkerTxPipeline`

## Status

Phase 7 of #959. Phases 1-6 (#1167-#1172) extracted dbg_*, scratch_*,
cos_*, pending_*_tx_*, BPF FDs, timers.

## Scope

Move 7 TX pipeline fields out of `BindingWorker` into a new
`WorkerTxPipeline` sub-struct accessed via `binding.tx_pipeline.X`:

```
free_tx_frames, pending_tx_prepared, pending_tx_local,
max_pending_tx, pending_fill_frames, in_flight_prepared_recycles,
tx_submit_ns
```

**`outstanding_tx` deliberately excluded** — it collides with the
`BindingStatus.outstanding_tx` snapshot mirror at
`coordinator/mod.rs:1227,1353` and `protocol.rs:1611`. Will handle
in a tiny followup phase that disambiguates by type.

## Methodology

Same compiler-driven approach as Phases 1-6. **158 callsites across
13 files** — largest phase by far.

`WorkerTxPipeline` has NO `Default` derive — `tx_submit_ns` must be
sized to `total_frames` at construction (`Box<[u64]>` of
`TX_SIDECAR_UNSTAMPED` sentinels), not zero-length. Construction
goes through the explicit literal in `BindingWorker::create`.

Collision-avoidance: `live.max_pending_tx` accesses on
`BindingLiveState` (atomic mirror) at `umem/tests.rs:41,86,107` and
similar must NOT be rewritten. The compiler protects: BindingLiveState
doesn't have a `tx_pipeline` field, so any over-replacement fails to
build.

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
- `flow_cache*`, `pending_neigh`, bind metadata → separate phases.
