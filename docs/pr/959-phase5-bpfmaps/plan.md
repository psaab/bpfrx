# Plan: #959 Phase 5 — extract BPF map FDs into `WorkerBpfMaps`

## Status

Phase 5 of #959. Phases 1-4 (#1167, #1168, #1169, #1170) extracted
`dbg_*`, `scratch_*`, `cos_*`, `pending_*_tx_*`.

## Scope

Move 4 BPF map file descriptors out of `BindingWorker` into a new
`WorkerBpfMaps` sub-struct:

```
heartbeat_map_fd, session_map_fd, conntrack_v4_fd, conntrack_v6_fd
```

Access pattern: `binding.bpf_maps.X_fd`.

These FDs are opened once at binding construction (from the
coordinator's pinned BPF map paths) and used through the binding's
lifetime for: heartbeat updates (per-second), session table deltas
(per-RX-batch), and conntrack v4/v6 lookups during fast-path session
resolution.

## Methodology

Same compiler-driven approach as Phases 1-4. 24 callsites across 4
files (worker/mod.rs, poll_descriptor.rs, session_glue/mod.rs,
bpf_map.rs).

`WorkerBpfMaps` has NO `Default` derive — these are real OS FDs and
a `c_int = 0` default would alias `stdin`, with potentially
destructive consequences if any later BPF syscall used it.

The `BindingPlan` struct (in `runtime.rs`) also has fields named
`heartbeat_map_fd` etc. but is a different type. The compiler's
type-level distinction protects us; a perl over-replacement that hit
`plan.heartbeat_map_fd → plan.bpf_maps.heartbeat_map_fd` was caught
by the build and reverted. (Plan stays a flat-field struct;
BindingWorker gains the nested sub-struct.)

## Acceptance

- `cargo build --release` clean.
- `cargo test --release` — 952 passed.
- `cargo test --release flush_clears_records_and_increments_sequence`
  — 5/5 named runs.
- `go build ./...` + `go test ./...` clean.
- v4 + v6 smoke against `172.16.80.200` / `2001:559:8585:80::200`.
- Codex hostile review.

## NOT in scope

- XSK rings (`device`, `rx`, `tx`) → still highest-risk; deferred.
- `flow_cache` → cache, not FD.
- TX pipeline state (`free_tx_frames`, `pending_tx_*`) — separate
  group, deferred.
