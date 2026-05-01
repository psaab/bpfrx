# #985 — Decompose Coordinator god struct (3,101 LOC, 40 fields)

## Why

`userspace-dp/src/afxdp/coordinator.rs::Coordinator` has 40
fields covering BPF FDs, HA state, neighbors, sessions, workers,
CoS coordination, slow-path, tunnels, and observability. Per
the new "Modularity discipline" section, a 40-field struct is a
god struct. The 3,101 LOC file also crosses the >~2,000 LOC
threshold.

## Field grouping (proposed manager components)

Surveyed all 40 fields; natural responsibility clusters:

### `BpfMaps` (~7 fields)
- `map_fd`, `heartbeat_map_fd`, `session_map_fd`,
  `conntrack_v4_fd`, `conntrack_v6_fd`, `dnat_table_fd`,
  `dnat_table_v6_fd`
- All `Option<OwnedFd>` BPF map descriptors. Trivial extraction.

### `HaState` (~3 fields)
- `ha_state`, `shared_fabrics`, `shared_forwarding`
- All `Arc<ArcSwap<...>>`. Reconciliation entry-point lives
  here (the FRR + VRRP fabric maps).

### `CoSState` (~5 fields)
- `shared_cos_owner_worker_by_queue`,
  `shared_cos_owner_live_by_queue`, `shared_cos_root_leases`,
  `shared_cos_queue_leases`, `shared_cos_queue_vtime_floors`,
  `cos_owner_worker_by_queue`
- Cross-binding CoS coordination Arcs. Cohesive.

### `NeighborManager` (~4 fields)
- `dynamic_neighbors`, `neighbor_generation`,
  `manager_neighbor_keys`, `neigh_monitor_stop`
- Already named "manager" in field names.

### `SessionManager` (~5 fields)
- `shared_sessions`, `shared_nat_sessions`,
  `shared_forward_wire_sessions`, `shared_owner_rg_indexes`,
  `session_export_seq`
- All shared session tables + the export sequence number.

### `WorkerManager` (~5 fields)
- `live`, `identities`, `workers`, `last_planned_workers`,
  `last_planned_bindings`
- Per-worker lifecycle / planning state.

### `SlowPathState` (~2 fields)
- `slow_path`, `last_slow_path_status`

### `TunnelState` (~2 fields)
- `local_tunnel_deliveries`, `tunnel_sources`

### `ValidationState` (~2 fields)
- `shared_validation`, `validation`

### `Observability` (~4 fields)
- `recent_exceptions`, `recent_session_deltas`,
  `last_resolution`, `event_stream`

### `ReconcileState` (~4 fields)
- `reconcile_calls`, `last_reconcile_stage`,
  `last_cache_flush_at`, `forwarding`

### Stays on `Coordinator` (~2 fields)
- `poll_mode` — top-level configuration, naturally lives on
  the coordinator.

Total: 11 manager structs absorb ~38 fields; 2 fields stay on
`Coordinator` itself.

## Phasing

**Phase 0** — convert `coordinator.rs` → `coordinator/mod.rs`
directory module. Mechanical only.

**Phase 1** — extract `BpfMaps` (the trivial Option<OwnedFd>
cluster). 7 fields move into a struct that `Coordinator`
contains. Smallest, lowest-risk first slice.

**Phase 2** — extract `NeighborManager` (already named
"manager" in field comments — this is the design that was
intended). 4 fields, mostly Arcs.

**Phase 3** — extract `CoSState` (5 fields, cohesive
cross-binding Arcs).

**Phase 4** — extract `WorkerManager`. Touches the worker
lifecycle paths (which the test_failover suite exercises);
needs cluster smoke before merge.

**Phase 5** — extract `SessionManager`. Touches the session-sync
path; cluster smoke + `make test-failover` required.

**Phase 6** — extract the remaining smaller managers (HaState,
SlowPathState, TunnelState, ValidationState, Observability,
ReconcileState) — likely 2-3 PRs depending on coupling.

Tests for each extracted manager live alongside it in a
sibling `mod tests` per the #984 P3 pattern.

## Open questions

- Some fields are `pub(crate)`; the manager structs need to
  preserve that access level for callers in `pkg/grpcapi/`,
  `pkg/api/`, etc. Manager fields will likely also be
  `pub(crate)` initially; tightening is a follow-up issue.
- `forwarding` (line 44) is a non-Arc `ForwardingState` separate
  from `shared_forwarding` (line 17, `Arc<ArcSwap<...>>`). The
  duplication merits investigation in Phase 6 — may be a real
  bug rather than just two fields.
- `last_planned_workers` / `last_planned_bindings` /
  `reconcile_calls` are reconcile bookkeeping; they may belong
  on a `ReconcileLog` struct in Phase 6 rather than dispersed.
