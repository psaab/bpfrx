# userspace-dp/src/afxdp/coordinator/

The single owner of cross-worker state and lifecycle. Constructs the
binding plan, spawns workers under the supervisor, holds the shared
BPF map handles and HA snapshot, and exposes the operator-facing
status surface to `server/` for the daemon's gRPC / HTTP queries.

This is the orchestration layer that sits *above* the per-worker
dataplane: workers take ownership of an AF_XDP socket and a
binding's hot path (see `worker/`); the coordinator owns everything
the workers share.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | `Coordinator` struct + worker-spawn + reconcile entry. |
| `bpf_maps.rs` | `BpfMaps` — pinned BPF map FDs (XSK map, heartbeat, session, conntrack v4/v6) opened once and shared with every worker. |
| `cos_state.rs` | `SharedCoSState` — Arcs that workers consult to find owner-by-queue, live owner, root/queue leases, vtime floors. |
| `ha_state.rs` | `HaState`: HA snapshot, shared fabrics, forwarding state. (RG epoch counters live on `Coordinator` itself in `mod.rs`, not here.) |
| `inject.rs` | `request inject-packet` RPC handler — synthesizes a packet against the live state, reports disposition. |
| `neighbor_manager.rs` | `NeighborManager` — sharded ARP/NDP cache + netlink monitor for incremental updates. |
| `session_manager.rs` | Cross-thread session-table state shared between coordinator, HA worker, and packet workers via `Arc<Mutex<...>>`. Holds the synced + nat + forward-wire tables together because they're written and queried as a unit. |
| `status.rs` | Read-side snapshots for `show ...` queries. The exception is `drain_session_deltas`, which mutates per-binding state. |
| `supervisor.rs` | `spawn_supervised_worker` / `spawn_supervised_aux` — catches panics, marks the worker dead on its `WorkerRuntimeAtomics`, captures a panic message into a per-worker slot. (#925 Phase 1.) |
| `tunnel_supervision.rs` | GRE local-origin + WG control-thread LIFECYCLE (three-pass reconcile, tombstone backoff, periodic liveness sweeps, defer-branch snapshot prunes — see "Aux tunnel threads" below). The thread bodies live in `wg_control.rs` / `afxdp/tunnel.rs`; the entry maps (`tunnel_sources`, `wg_control_threads`) stay on `Coordinator` in `mod.rs`. (#1890 split.) |
| `worker_manager.rs` | Per-worker lifecycle and planning state. **Two key spaces:** `live` and `identities` are keyed by binding `slot`; `handles` is keyed by `worker_id`. Don't conflate them. |

## Where it sits

- Above: `server/handlers/` modules call into `Coordinator::*` for every
  control-socket RPC.
- Below: spawns and manages the per-worker poll loop in `worker/`.
- Sideways: shares `BpfMaps` and `SharedCoSState` Arcs with workers.

## Aux tunnel threads (WG control + GRE local-origin)

Both families are coordinator-owned aux threads keyed by
tunnel_endpoint_id with the same three-pass lifecycle (#1866 for WG,
#1881 for GRE): finished sweep → tombstone (backoff + attachment
retained), stale prune, spawn with backoff — reconciled at bring-up
AND on every armed `refresh_runtime_snapshot` (tunnel interfaces are
excluded from the binding plan, so tunnel-only commits never reach a
full reconcile), plus a tombstone-only periodic liveness pass from
`refresh_status` and a narrow prune on the defer-workers apply leg.

Differences that matter (#1881):

- WG threads restart when the engine Arc identity OR attachment
  changes; GRE threads restart ONLY on attachment drift — endpoint
  content (destination/source/key, routes, CoS) reaches the live GRE
  loop through the shared `ha.forwarding` ArcSwap (one
  `load_arc_if_changed` per loop iteration, the #1188 pattern).
- The GRE loop carries a rotation gate (`endpoint_attachment_valid`,
  `tunnel.rs`): on every forwarding-Arc rotation it re-validates that
  the loaded state still describes its TUN attachment (id present,
  mode gre/ip6gre, ifindex+name match) and PARKS — drops without
  building — when it does not. This closes the store-to-join window:
  the #1873 owner check compares the endpoint row against a
  resolution from the SAME loaded state and cannot detect a thread
  reading the wrong TUN.
- GRE spawn is gated on live worker handles (the deferred same-plan
  window reaches refresh with zero workers; a thread spawned there
  would freeze empty binding captures). WG has no such gate — WG
  control threads use kernel UDP+TUN and have no binding dependency.
- `local_tunnel_deliveries` publication is live-handles-only and
  follows unpublish-before-join: the stale set is removed from the
  published map BEFORE stop+join (so a busy worker producer cannot
  extend the join — the delivery drain also observes `stop` per
  chunk), with a final republish after spawns.

## Notable invariants

- The coordinator is the single owner; workers hold `Arc` clones.
  Lifetime hazards from breaking that invariant are how cross-binding
  redirect designs have died historically (see `docs/per-5-tuple/state.md`).
- Worker spawn happens via the supervisor; never call
  `std::thread::spawn` directly for a worker — it bypasses the panic
  capture.
- `defer_workers=true` on `apply_snapshot` skips spawn until the next
  reconcile (used during RETH MAC programming so workers don't bind
  to an interface that's about to drop and re-add its MAC).
