# Plan: #959 Phase 6 — extract timing/wake state into `WorkerTimers`

## Status

Phase 6 of #959. Phases 1-5 (#1167, #1168, #1169, #1170, #1171)
extracted dbg_*, scratch_*, cos_*, pending_*_tx_*, BPF FDs.

## Scope

Move 5 timing/wake-pacing fields out of `BindingWorker` into a new
`WorkerTimers` sub-struct:

```
last_heartbeat_update_ns, debug_state_counter,
last_rx_wake_ns, last_tx_wake_ns, empty_rx_polls
```

Access pattern: `binding.timers.last_X_ns` etc.

These fields gate per-binding pacing decisions: when to TX wake-up
syscall, when to RX wake, when to update the BPF heartbeat map, and
the per-second debug-tick counter.

## NOT moved

`outstanding_tx` stays at the BindingWorker level — it's a TX
pipeline counter (sequenced for Phase 7 alongside `free_tx_frames`,
`pending_tx_*`, etc.), not a timer.

## Methodology

Same compiler-driven approach as Phases 1-5. 13 callsites across 4
files (worker/lifecycle.rs, tx/rings.rs, umem/mod.rs, bpf_map.rs) —
smallest phase yet.

`WorkerTimers` has NO `Default` — derived Default would seed the
last-wake timestamps with 0, causing the first heartbeat / RX-wake /
TX-wake decisions to fire immediately as if the binding had been
idle since epoch.

## Acceptance

- `cargo build --release` clean.
- `cargo test --release` — 952 passed.
- `cargo test --release flush_clears_records_and_increments_sequence`
  — 5/5 named runs.
- `go build ./...` + `go test ./...` clean.
- v4 + v6 smoke against 172.16.80.200 / 2001:559:8585:80::200.
- Codex hostile review.

## NOT in scope

- TX pipeline state (`free_tx_frames`, `pending_tx_*`,
  `max_pending_tx`, `pending_fill_frames`,
  `in_flight_prepared_recycles`, `outstanding_tx`,
  `tx_submit_ns`) → Phase 7.
- XSK rings (`device`, `rx`, `tx`) → still highest-risk; deferred.
- `flow_cache*`, `pending_neigh`, bind metadata → separate phases.
