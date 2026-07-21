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
| `cos_leases.rs` | CoS runtime-map plumbing: `refresh_cos_owner_worker_map_*` / `refresh_cos_runtime_maps` (diff-and-store of the `SharedCoSState` Arcs) plus the owner-by-queue / active-shard / root- and queue-lease / exact-backlog / vtime-floor builders with their Arc-reuse match predicates, and the #710 cross-worker status aggregation used by `status.rs`. (#1890 split.) |
| `cos_state.rs` | `SharedCoSState` — Arcs that workers consult to find owner-by-queue, live owner, root/queue leases, vtime floors. |
| `ha_state.rs` | `HaState`: HA snapshot, shared fabrics, forwarding state. (RG epoch counters live on `Coordinator` itself in `mod.rs`, not here.) |
| `inject.rs` | `request inject-packet` RPC handler — synthesizes a packet against the live state, reports disposition. The operator/API-supplied `packet_length` is bounded by `MAX_INJECT_PACKET_LENGTH` (= `UMEM_FRAME_SIZE`, 4096): an injected packet is a single unfragmented frame that must fit in one UMEM frame on TX, and 4096 keeps the IPv4 total-length / IPv6 payload-length wire fields within u16. `check_inject_packet_length` REJECTS an over-max request up front (it is NOT clamped, so an API misuse / DoS attempt surfaces as an error); the 64-byte minimum still applies. The frame builders (`frame/mod.rs`) additionally clamp the allocation to the maximum and use `u16::try_from` for the wire length as a defense-in-depth backstop so a bypassed bound can never emit a wrapped on-wire length. (#2443) |
| `neighbor_manager.rs` | `NeighborManager` — sharded ARP/NDP cache + netlink monitor for incremental updates. **#5165: the monitor thread's `JoinHandle` is now retained (`monitor_join`, no longer discarded via `.ok()`) and `stop_inner` signals + JOINs it via `stop_and_join_monitor` — mirroring `resolver_join`. Joining (bounded by the monitor's 500ms `SO_RCVTIMEO`) is what enforces no-mutation-after-stop: a retired old-generation monitor blocked in `recv()` can no longer apply a queued kernel neighbor event to `dynamic` after a reconcile cleared/rebuilt the baseline. The steady-state loop also re-checks `stop` AFTER `recv()`, before mutating, as belt-and-suspenders.** |
| `session_manager.rs` | Cross-thread session-table state shared between coordinator, HA worker, and packet workers via `Arc<Mutex<...>>`. Holds the synced + nat + forward-wire tables together because they're written and queried as a unit. |
| `snapshot_refresh.rs` | `refresh_runtime_snapshot{,_disarmed,_inner}` (armed/disarmed same-plan snapshot-apply legs: preflight, #1873 tunnel-remap purge, forwarding swap + stores, aux-thread reconcile, CoS owner-map + warm passes) and `refresh_fabric_links`. (#1890 split.) **#3766: `_inner` is a FALLIBLE atomic swap — it returns `Result<(), SnapshotIntegrityError>`, builds the new forwarding state FIRST, and only then bumps `self.validation` + rotates the neighbor-manager keys + publishes; on a build integrity error nothing mutates and the error is returned so the handler fails closed (no split-brain, no persisted reject).** |
| `status.rs` | Read-side snapshots for `show ...` queries. **#5289: `recent_exceptions()` / `last_resolution()` drain the per-worker POD exception rings (`Coordinator::worker_exception_rings` / `worker_last_resolution`, one `Arc<Mutex<ExceptionEventRing>>` per worker, mirroring `worker_panics`) plus the control-thread ring, format each compact `ExceptionEvent`/`ResolutionEvent` into the operator-visible `ExceptionStatus`/`PacketResolution` HERE (interface/reason/IP/zone strings + monotonic→wall-clock via a single captured `MonoWallAnchor`), and merge by timestamp. The retired inline path formatted + locked a process-global mutex on EVERY terminal packet — the cross-worker DoS closed by #5289. The record path (`disposition::record_exception`) now writes a `&'static`-reason / `Arc<str>`-interface / `Copy`-`IpAddr` / numeric-zone POD event under a per-worker mutex with a per-(reason,5-tuple) sampler; the batched `BindingLiveState` counters stay the lossless signal. #6101: the slow-path reinject-failure sites (`_rate_limited` / `_queue_full` / `_slow_path_mtu_exceeded` / `_enqueue_failed`) record via `disposition::record_exception_suffixed`, which stores a `&'static` base reason + a `&'static` suffix (new `ExceptionEvent::reason_suffix`) so the record path stays alloc-free under a reinject-failure flood — the operator text `"{reason}{suffix}"` is reconstructed byte-identically by `ExceptionEvent::reason()` on the status thread. `record_exception_owned` remains ONLY for genuinely dynamic reasons (the `cfg!(feature = "debug-log")` forward-tuple-mismatch diagnostic). The cross-worker merge/sort/cap (`recent_exceptions`/`last_resolution` across ≥2 per-worker rings + the control ring) and the bring-up insert / teardown `.remove` are unit-tested in `status_tests.rs::exception_ring_merge_6101`.** The other read-side exception is `drain_session_deltas`, which mutates per-binding state. **#5290: this RPC-fallback drain is FAIR — it spreads a `budget/num_bindings` quantum across live bindings via a rotating cursor (`WorkerManager::session_delta_drain_cursor`) using the shared `session_delta::drain_session_deltas_fair` helper, instead of handing the whole budget to the first slot with an early break. A low-slot worker can no longer consume the caller-wide budget and starve higher slots during the event-stream fallback. On budget overflow (undrained deltas remain) it arms `BindingLiveState::set_delta_loss` on the residual bindings; the owning worker loop folds that latch into `SessionTable::set_delta_loss` for the existing #2442 owner-RG resync, so no delta is silently lost. The owner-RG bulk-export mirror `ha.rs::drain_session_deltas_from_live` shares the same fair helper but does NOT arm the latch (it IS the resync).** |
| `supervisor.rs` | `spawn_supervised_worker` / `spawn_supervised_aux` — catches panics, marks the worker dead on its `WorkerRuntimeAtomics`, captures a panic message into a per-worker slot. (#925 Phase 1.) |
| `tunnel_supervision.rs` | GRE local-origin + WG control-thread LIFECYCLE (three-pass reconcile, tombstone backoff, periodic liveness sweeps, defer-branch snapshot prunes — see "Aux tunnel threads" below). The thread bodies live in `wg_control.rs` / `afxdp/tunnel.rs`; the entry maps (`tunnel_sources`, `wg_control_threads`) stay on `Coordinator` in `mod.rs`. (#1890 split.) |
| `worker_manager.rs` | Per-worker lifecycle and planning state. **Two key spaces:** `live` and `identities` are keyed by binding `slot`; `handles` is keyed by `worker_id`. Don't conflate them. Also holds `session_delta_drain_cursor` (#5290), the persistent rotating cursor for the fair RPC-fallback session-delta drain. |

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
- #2412: the published value is a `LocalTunnelDelivery` (the mpsc
  sender PLUS an eventfd `TunnelWake`), not a bare sender. The GRE
  local-origin loop blocks in `poll(2)` on {TUN fd, eventfd} instead
  of the former 1ms `thread::sleep` busy-poll (~1000 wakeups/sec/tunnel
  when idle). The worker slow path signals the eventfd on a successful
  enqueue, and the stop/join path signals it after setting `stop`, so a
  queued delivery and a shutdown both wake the loop immediately rather
  than after the poll cap. WG control threads keep their own socket-poll
  cap and carry no eventfd (`LocalTunnelSourceHandle.wake == None`).

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
- **A deferred apply still runs the pre-teardown integrity build before
  ack/persist (#5171).** `defer_workers=true` skips the worker spawn but
  the snapshot is still ACKed + persisted as the boot baseline, so it must
  be fully BUILDABLE with all mandatory resources first. The disarmed
  defer path cannot borrow `reconcile` for this (with forwarding not yet
  armed, `reconcile_status_bindings` takes the disarmed STOP path — a
  teardown with no integrity build; when armed it would spawn workers,
  violating the defer contract). `Coordinator::validate_snapshot_buildable`
  (`reconcile/mod.rs`) factors out the SAME three pre-teardown legs
  `reconcile` runs — policy preflight (`preflight_policy_state`, shared
  verbatim), mandatory + present-optional map-pin openability
  (`validate_map_pins`), and the full forwarding build
  (`validate_forwarding_buildable`) — as a side-effect-free `&self` check
  (map FDs opened then dropped; scratch policy/NAT counter stores so a
  rejected snapshot leaks no handles; no teardown, no spawn, no binding
  mutation, no `last_reconcile_stage` write). The defer `apply_snapshot`
  handler runs it BEFORE the tunnel/WG prunes and the `guard.snapshot`
  swap and fails closed on error (restore the bumped status generation,
  `ok=false`, no persist). A parity test locks that validate and reconcile
  reject the identical non-buildable snapshot (no drift). Pre-#5171 the
  defer path skipped the build entirely, so a non-buildable config (bad
  interface address / CoS queue / NAT64 / NPTv6 rule, or a
  MISSING/UNOPENABLE mandatory map pin) was acked `ok=true` and persisted,
  only to fail-OPEN at the later deferred bring-up.
- **Same-plan refresh is a fail-closed atomic swap (#3766).** The
  same-plan `apply_snapshot` leg (binding plan unchanged) runs
  `refresh_runtime_snapshot{,_disarmed}` instead of a full reconcile.
  Like the full reconcile's pre-teardown `build_reconcile_forwarding`
  (#2484), it builds the new `ForwardingState` FIRST and only commits
  the observable mutations — `self.validation` bump (H2), neighbor-
  manager key rotation + stale-key delete (H3), forwarding swap, and the
  `shared_validation` / `ha.forwarding` publishes — AFTER the build
  succeeds. A non-policy integrity fault (invalid interface address,
  CoS queue, NAT64 / NPTv6 rule) that only the full build catches now
  returns `Err(SnapshotIntegrityError)`; the handler reports `ok=false`,
  restores the bumped status generation, and does NOT persist the
  rejected snapshot. The prior good state stays live and consistent —
  no split-brain (validation ahead of a stale forwarding table), no
  deleted-neighbor blackhole, no `ok=true` on a rejected snapshot.
  Distinct from #2484 (full-apply teardown) and #2916 (queue replan).
- **A POST-teardown worker-spawn failure fails closed (#4952).** The
  #2440/#2484/#3789 fail-closed legs above all abort BEFORE `tear_down`,
  so the prior workers stay live. `bring_up_workers` runs AFTER teardown:
  its per-worker `spawn_supervised_worker` (→ `pthread_create`) can return
  EAGAIN/ENOMEM under resource exhaustion, and the old workers are already
  gone — a queue set left with no XSK-bound worker is a silent forwarding
  outage. Pre-#4952 `bring_up_workers` returned `()`, only LOGGED the
  failure + recorded an exception, then UNCONDITIONALLY overwrote
  `last_reconcile_stage` with `spawned:workers=..` and returned success —
  so `reconcile` returned `Ok(())`, the control handler acked `ok=true`,
  and PERSISTED the broken snapshot as the boot baseline (no retry). Now
  `bring_up_workers` returns `Result<(), WorkerBringUpError>`: on the FIRST spawn
  failure it ABORTS the remaining launches (the data plane is already
  broken; more XSK-bound workers cannot restore forwarding and only widen
  the resource pressure), PRESERVES the `spawn_worker_failed:<id>:<err>`
  stage (no `spawned:..` overwrite), skips the auxiliary-thread bring-up,
  and returns the stage. `reconcile` maps it to
  `ReconcileError::WorkerSpawn` — one of two `ReconcileError` variants
  raised AFTER teardown (`WorkerBindIncomplete` (#5143) is the other; the
  data plane HAS moved; there is no prior-state restore
  that brings the torn-down workers back, only fail-closed bookkeeping +
  a retry/last-good reconcile). Full pre-teardown preflight of the spawn is
  not tractable (a real `pthread_create` cannot be probed without spawning,
  and the old workers must free the XSK queue bindings first), so this is
  the minimal fail-closed guarantee: do not persist a known-broken
  snapshot. A per-instance `#[cfg(test)] force_worker_spawn_fail` seam
  drives the regression tests (coordinator-level
  `reconcile_post_teardown_worker_spawn_failure_fails_closed_4952` +
  handler-level `post_teardown_spawn_failure_fails_closed_no_persist_4952`).
- **A POST-SPAWN in-thread worker bind failure fails closed via the
  startup readiness barrier (#5143). HEARTBEAT != READINESS.** #4952 above
  catches only the SPAWN failure — the thread that never starts. But a
  worker that spawns SUCCESSFULLY can still fail its IN-THREAD XSK/UMEM
  binds inside `worker_loop_setup` (the private-binding `Err` arm records
  the failure by leaving the binding out of the worker's `bindings` vec)
  and then enter its steady loop with an EMPTY/PARTIAL binding set — yet it
  keeps HEARTBEATING, so the thread-death supervisor is satisfied and
  (pre-#5143) `bring_up_workers` returned `Ok`, the reconcile committed, and
  the handler ACKed `ok=true` + PERSISTED the snapshot: a SILENT forwarding
  outage (a queue set with a live worker but no XSK-bound binding). #4952's
  spawn-error propagation does NOT catch it (the spawn succeeded). Now each
  newly-started worker REPORTS its actual bound-slot set (a
  `WorkerStartupReport` over a per-reconcile `mpsc` channel) after its binds
  and BEFORE its steady loop; after the spawn loop `bring_up_workers` WAITS
  (bounded by `WORKER_STARTUP_BARRIER_TIMEOUT_NS` = 10s — a worker that
  never reports in time is treated as failed, it does NOT block forever) and
  requires `bound == planned` per worker. On ANY shortfall/timeout it FAILS
  CLOSED: `stop_inner(false)` STOPS + JOINS the newly-started workers (no
  leaked live-but-unbound worker), preserves the `worker_bind_incomplete:..`
  stage, and returns `WorkerBringUpError::BindIncomplete`, which `reconcile`
  maps to `ReconcileError::WorkerBindIncomplete` — the SECOND post-teardown
  `ReconcileError` variant (alongside `WorkerSpawn`), handled the same way
  by the control handler (`ok=false`, do NOT persist). `bring_up_workers`
  now returns `Result<(), WorkerBringUpError>` (was `Result<(), String>`) so
  the two post-teardown classes map to distinct variants. A per-instance
  `#[cfg(test)] force_worker_bind_incomplete` seam (spawns a joinable stub
  worker that reports a bound set short by one slot, then heartbeats until
  stopped) drives the regression tests (coordinator-level
  `post_spawn_inthread_bind_failure_fails_closed_5143` + handler-level
  `full_apply_post_spawn_inthread_bind_failure_fails_closed_no_persist_5143`).
