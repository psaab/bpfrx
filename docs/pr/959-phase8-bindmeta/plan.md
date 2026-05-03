# Plan: #959 Phase 8 — extract bind metadata into `WorkerBindMeta`

## Status

Phase 8 of #959. Phases 1-7 (#1167-#1173) extracted dbg_*,
scratch_*, cos_*, pending_*_tx_*, BPF FDs, timers, TX pipeline.

## Scope

Move 3 binding registration / identity fields out of `BindingWorker`
into a new `WorkerBindMeta` sub-struct:

```
bind_time_ns, bind_mode, xsk_rx_confirmed
```

Access pattern: `binding.bind_meta.X`.

These three fields hold per-binding state set at registration:
- `bind_time_ns` — monotonic creation timestamp; used by
  heartbeat-gating logic.
- `bind_mode` — copy vs zero-copy XSK bind result; used by
  TX-wake gating.
- `xsk_rx_confirmed` — flips true once the XSK RX ring delivers
  the first packet, proving the NIC's XSK queue is live.

## Methodology

Same compiler-driven approach as Phases 1-7. **6 callsites across 3
files** — smallest phase yet.

`WorkerBindMeta` has NO `Default` derive — `bind_time_ns` must be
seeded with the actual monotonic-now sample.

**Collision caught at build time**: `BindingLiveState.bind_mode` (an
AtomicU8 mirror) at `umem/mod.rs:564,634,637` and `tx/rings.rs:212`
was over-replaced by the perl pass. The compiler rejected those
sites; reverted to keep the BindingLiveState atomic accesses
unchanged. Only BindingWorker.bind_mode → BindingWorker.bind_meta.bind_mode
moved.

## Acceptance

- `cargo build --release` clean.
- `cargo test --release` — 952 passed.
- `cargo test --release flush_clears_records_and_increments_sequence`
  — 5/5 named runs.
- `go build ./...` + `go test ./...` clean.
- v4 + v6 smoke against 172.16.80.200 / 2001:559:8585:80::200.
- Codex hostile review.

## NOT in scope

- `outstanding_tx` → tiny followup phase (collides with BindingStatus mirror).
- XSK rings (`device`, `rx`, `tx`) → still highest-risk; deferred.
- `flow_cache*` → separate small phase (2 fields).
