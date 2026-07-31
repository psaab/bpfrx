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
| `mod.rs` | `Coordinator` struct + worker-spawn + reconcile entry. The per-worker spawn closure (in `reconcile/bringup.rs`) launches `worker_loop` via 5 typed bundles (#6241): `WorkerSharedDataplane::from_coord` / `WorkerCoSState::from_coord` clone the coordinator-published shared state, and the `::new` builders carry the per-worker fresh slots — behavior-preserving, no extra clone/alloc vs. the old positional call. |
| `bpf_maps.rs` | `BpfMaps` — pinned BPF map FDs (XSK map, heartbeat, session, conntrack v4/v6) opened once and shared with every worker. |
| `cos_leases.rs` | CoS runtime-map plumbing: `refresh_cos_owner_worker_map_*` / `refresh_cos_runtime_maps` (diff-and-store of the `SharedCoSState` Arcs) plus the owner-by-queue / active-shard / root- and queue-lease / exact-backlog / vtime-floor builders with their Arc-reuse match predicates, and the #710 cross-worker status aggregation used by `status.rs`. (#1890 split.) |
| `cos_state.rs` | `SharedCoSState` — Arcs that workers consult to find owner-by-queue, live owner, root/queue leases, vtime floors. |
| `ha_state.rs` | `HaState`: HA snapshot, shared fabrics, forwarding state. (RG epoch counters live on `Coordinator` itself in `mod.rs`, not here.) |
| `inject.rs` | `request inject-packet` RPC handler — synthesizes a packet against the live state, reports disposition. The operator/API-supplied `packet_length` is bounded by `MAX_INJECT_PACKET_LENGTH` (= `UMEM_FRAME_SIZE`, 4096): an injected packet is a single unfragmented frame that must fit in one UMEM frame on TX, and 4096 keeps the IPv4 total-length / IPv6 payload-length wire fields within u16. `check_inject_packet_length` REJECTS an over-max request up front (it is NOT clamped, so an API misuse / DoS attempt surfaces as an error); the 64-byte minimum still applies. The frame builders (`frame/mod.rs`) additionally clamp the allocation to the maximum and use `u16::try_from` for the wire length as a defense-in-depth backstop so a bypassed bound can never emit a wrapped on-wire length. (#2443) |
| `neighbor_manager.rs` | `NeighborManager` — sharded ARP/NDP cache + netlink monitor for incremental updates. **#5165: the monitor thread's `JoinHandle` is now retained (`monitor_join`, no longer discarded via `.ok()`) and `stop_inner` signals + JOINs it via `stop_and_join_monitor` — mirroring `resolver_join`. Joining (bounded by the monitor's 500ms `SO_RCVTIMEO`) is what enforces no-mutation-after-stop: a retired old-generation monitor blocked in `recv()` can no longer apply a queued kernel neighbor event to `dynamic` after a reconcile cleared/rebuilt the baseline. The steady-state loop also re-checks `stop` AFTER `recv()`, before mutating, as belt-and-suspenders.** **#6314: the #1636 neighbor WARMER — the third neighbor aux thread — now follows the SAME pattern (it was the pre-#5165 odd-one-out). Its `JoinHandle` is retained (`warm_join`, no longer discarded via `.ok()`), a spawn failure is now logged instead of swallowed (leaving `warm_queue`/`warm_stop`/`warm_join` all `None` so the next reconcile retries), and `stop_inner` signals `warm_stop` + drops the producer + JOINs it via `stop_and_join_warmer`. Joining (bounded by the warmer loop's 500ms recv timeout) guarantees a detached warmer can never fire a stray ARP/NDP solicit or mutate `last_probed_at` after teardown. Fail-on-revert: `neighbor_warmer_joined_at_teardown_6314`.** |
| `session_manager.rs` | Cross-thread session-table state shared between coordinator, HA worker, and packet workers via `Arc<Mutex<...>>`. Holds the synced + nat + forward-wire tables together because they're written and queried as a unit. |
| `snapshot_refresh.rs` | `refresh_runtime_snapshot{,_disarmed,_inner}` (armed/disarmed same-plan snapshot-apply legs: preflight, #1873 tunnel-remap purge, forwarding swap + stores, aux-thread reconcile, CoS owner-map + warm passes) and `refresh_fabric_links`. (#1890 split.) **#5166: the CoS owner/lease maps + `ha.fabrics` are published BEFORE the `ha.forwarding` worker-visible store — a live worker (loop_body loads forwarding then CoS in one tick) must never observe new queue config without its matching CoS owners/leases (else transient class blackhole / stale-rate / over-admission).** **#3766: `_inner` is a FALLIBLE atomic swap — it returns `Result<(), SnapshotIntegrityError>`, builds the new forwarding state FIRST, and only then bumps `self.validation` + rotates the neighbor-manager keys + publishes; on a build integrity error nothing mutates and the error is returned so the handler fails closed (no split-brain, no persisted reject).** |
| `status.rs` | Read-side snapshots for `show ...` queries. **#5289: `recent_exceptions()` / `last_resolution()` drain the per-worker POD exception rings (#6242: one `Arc<Mutex<ExceptionEventRing>>` per worker, now on each `WorkerRuntimeRecord` in `workers.records` — was the standalone `Coordinator::worker_exception_rings` / `worker_last_resolution` maps, mirroring the also-consolidated `worker_panics`) plus the control-thread ring, format each compact `ExceptionEvent`/`ResolutionEvent` into the operator-visible `ExceptionStatus`/`PacketResolution` HERE (interface/reason/IP/zone strings + monotonic→wall-clock via a single captured `MonoWallAnchor`), and merge by timestamp. The retired inline path formatted + locked a process-global mutex on EVERY terminal packet — the cross-worker DoS closed by #5289. The record path (`disposition::record_exception`) now writes a `&'static`-reason / `Arc<str>`-interface / `Copy`-`IpAddr` / numeric-zone POD event under a per-worker mutex with a per-(reason,5-tuple) sampler; the batched `BindingLiveState` counters stay the lossless signal. #6101: the slow-path reinject-failure sites (`_rate_limited` / `_queue_full` / `_slow_path_mtu_exceeded` / `_enqueue_failed`) record via `disposition::record_exception_suffixed`, which stores a `&'static` base reason + a `&'static` suffix (new `ExceptionEvent::reason_suffix`) so the record path stays alloc-free under a reinject-failure flood — the operator text `"{reason}{suffix}"` is reconstructed byte-identically by `ExceptionEvent::reason()` on the status thread. `record_exception_owned` remains ONLY for genuinely dynamic reasons (the `cfg!(feature = "debug-log")` forward-tuple-mismatch diagnostic). The cross-worker merge/sort/cap (`recent_exceptions`/`last_resolution` across ≥2 per-worker rings + the control ring) and the bring-up insert / teardown record-drop are unit-tested in `status_tests.rs::exception_ring_merge_6101`.** The other read-side exception is `drain_session_deltas`, which mutates per-binding state. **#5290: this RPC-fallback drain is FAIR — it spreads a `budget/num_bindings` quantum across live bindings via a rotating cursor (`WorkerManager::session_delta_drain_cursor`) using the shared `session_delta::drain_session_deltas_fair` helper, instead of handing the whole budget to the first slot with an early break. A low-slot worker can no longer consume the caller-wide budget and starve higher slots during the event-stream fallback. On budget overflow (undrained deltas remain) it arms `BindingLiveState::set_delta_loss` on the residual bindings; the owning worker loop folds that latch into `SessionTable::set_delta_loss` for the existing #2442 owner-RG resync, so no delta is silently lost. The owner-RG bulk-export mirror `ha.rs::drain_session_deltas_from_live` shares the same fair helper but does NOT arm the latch (it IS the resync).** |
| `supervisor.rs` | `spawn_supervised_worker` / `spawn_supervised_aux` — catches panics, marks the worker dead on its `WorkerRuntimeAtomics`, captures a panic message into a per-worker slot. (#925 Phase 1.) |
| `tunnel_supervision.rs` | GRE local-origin + WG control-thread LIFECYCLE (three-pass reconcile, tombstone backoff, periodic liveness sweeps, defer-branch snapshot prunes — see "Aux tunnel threads" below). The thread bodies live in `wg_control/` / `afxdp/tunnel.rs`; the entry maps (`tunnel_sources`, `wg_control_threads`) stay on `Coordinator` in `mod.rs`. (#1890 split.) |
| `wg_control/` | WG datapath control-thread BODY (one supervised aux thread per `mode == "wireguard"` endpoint, kernel UDP socket + wgN TUN). `mod.rs` holds the thread entry (`wg_control_loop`) and the orchestrating `run_wg_control_loop` (socket RX burst → TUN-read burst → 1s timer arm → idle poll(2)); the fused layers are split into `mtu.rs` (pad-aware encapped-size formula + per-peer outer-MTU guard), `sock.rs` (dual-stack bind, v4-mapped send shim, #2317 outer-TOS cmsg codec, poll(2) wait layer), `attempt.rs` (#1888 S5 handshake attempt machine + keepalive emit/pace), and `dispatch.rs` (inbound type-byte dispatch with the auth-before-roam `InboundOutcome` contract + the TUN-read encap-and-send). (#6438 split; `pad_to_16` is SSOT in `afxdp/wg/mod.rs`.) |
| `worker_manager.rs` | Per-worker lifecycle and planning state. **Two key spaces:** `live` and `identities` are keyed by binding `slot`; `records` is keyed by `worker_id`. Don't conflate them. **#6242: `records: BTreeMap<u32, WorkerRuntimeRecord>` is the SINGLE per-worker runtime registry** — it consolidates the former `handles` map plus the three sibling `Coordinator` observability maps (`worker_panics` #925 / `worker_exception_rings` / `worker_last_resolution` #5289) so a worker's handle + panic slot + exception ring + last-resolution slot register and roll back as ONE unit (`records.insert` / `records.clear`). Registration is POST-spawn-success (see `reconcile/bringup.rs`), so a failed worker never has a record to unwind (the #4952 differential is structural) and `stop_and_clear` drops all four owners of every worker in one `records.clear()`. Cold-path only: the packet path holds direct `Arc` clones and never looks up a record. Also holds `session_delta_drain_cursor` (#5290), the persistent rotating cursor for the fair RPC-fallback session-delta drain. |

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

- **The worker launch boundary is 5 typed bundles, constructed via named
  builders — not a positional arg list (#6241).** The `bring_up_workers`
  spawn closure (`reconcile/bringup.rs`) builds `WorkerLaunchPlan`,
  `WorkerSharedDataplane`, `WorkerControlChannels`, `WorkerCoSState`, and
  `WorkerPublishedTelemetry` (defined in `worker/launch.rs`) and moves them
  into `worker_loop`, which destructures them back into the same locals at
  entry. Construct them ONLY via `WorkerSharedDataplane::from_coord` /
  `WorkerCoSState::from_coord` (coordinator-published state) and the `::new`
  builders (per-worker fresh slots) — NOT inline struct literals — so the
  `Arc::ptr_eq` wiring tests in `worker/launch.rs` bind the exact
  session-map (`synced`/`nat`/`forward_wire`) and heartbeat/export-ack
  silent-swap hazards the old 38-parameter positional protocol carried.
  Behavior-preserving: one `Arc::clone` per field, exactly as the old
  inline call did. **#6242 (integrated):** `recent_exceptions` /
  `last_resolution` (and the `panic` slot) are allocated ONCE, one clone
  RETAINED for the worker's `WorkerRuntimeRecord` and the original MOVED into
  `WorkerPublishedTelemetry` / `spawn_supervised_worker` — the record and the
  live worker SHARE the allocation. The record is registered as ONE
  `records.insert` POST-spawn-success, so a failed worker never publishes a
  record (the #4952 differential is structural — no pre-spawn insert, no
  spawn-Err `.remove`).
- **Reconcile progress + failure identity are a TYPED value, not a free-form
  string (#6244).** `Coordinator::last_reconcile_stage` is a
  `ReconcileStage` enum (`reconcile/stage.rs`) — one variant per progress
  step (`Idle`/`Start`/`NoSnapshot`/`Planned`/`ReplayedSynced`/`Spawned`) and
  per failure identity (`MissingPin`/`OpenMapFailed`/`SnapshotIntegrityError`
  {,`Detail`}/`SpawnWorkerFailed`/`WorkerBindIncomplete`). The legacy operator
  string is produced in exactly one place — the enum's `Display` — and is
  rendered ONLY at the `reconcile_debug` / wire `debug_reconcile_stage`
  boundary (`status.rs`) and inside `ReconcileError`'s `Display`; the strings
  are preserved byte-for-byte. `ReconcileError::{MapSetup,WorkerSpawn,
  WorkerBindIncomplete}` carry the typed `ReconcileStage` rather than a cloned
  string, so a failure identity cannot be silently reinterpreted as informal
  success text (the #4952 overwrite class). #6244 also moved the `"stopped"`
  write OUT of `stop_inner` (which is called mid-reconcile by `tear_down` and
  by the bring-up fail path): an EXPLICIT stop records `ReconcileStage::Stopped`
  in `stop`/`stop_with_event_stream`, so a terminal failure identity is never
  clobbered by a teardown that is part of the same reconcile attempt — the
  bring-up fail path no longer needs the old overwrite-then-restore dance.
  Fail-on-revert: `reconcile_stage_renders_byte_identical_legacy_strings`.
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
- **The map-pin gate is ONE opener shared by both callers (#6243).** The
  activated `preflight_map_fds` and the deferred `validate_map_pins` used
  to carry two hand-kept copies of the seven-pin contract (3 mandatory
  xsk/heartbeat/sessions + 4 optional conntrack v4/v6, dnat_table[/v6]).
  They now both route through one pure `open_snapshot_maps(&MapPins) ->
  Result<OpenedSnapshotMaps, MapPinFault>` (`reconcile/snapshot.rs`), so
  they can never drift on which snapshots pass or how a fault is
  classified. The opener is side-effect-free and returns the opened FD
  bundle; the ONLY per-caller difference is keep-vs-drop of that bundle
  (RAII — the activated path assembles it into `ReconcileSnapshotFds`, the
  deferred path `.map(|_| ())` drops it), so no `mode` parameter is
  needed. On a fault a thin COLD ADAPTER on the activated caller stamps
  `last_reconcile_stage` (from `MapPinFault::stage()` — the typed #6244
  `ReconcileStage`) plus every registered binding's `last_error` (from
  `MapPinFault::binding_error()`, which owns the byte-parity trap that the
  xsk per-binding label is uppercase `XSK` while its stage token is
  lowercase `xsk`). Unifying FIXES two latent divergences (both normalize
  the deferred path toward the activated SSOT, both stay fail-closed):
  (1) the deferred walk was ONE-pass (empty-then-open per pin) while
  activated was TWO-pass (check all mandatory emptiness first, then open),
  so a multi-fault snapshot could report a different stage from each path;
  the shared two-pass order makes them identical. (2) the deferred walk
  dropped each FD immediately, so under FD-table pressure it could PASS
  where activated (retaining all seven FDs simultaneously) FAILED; the
  shared bundle now holds every opened FD until the whole contract
  succeeds, giving the deferred path the same low-FD failure. Fail-on-
  revert: `reconcile_all_seven_pin_faults_lock_stage_and_binding_strings_6243`,
  `map_pin_faults_react_identically_activated_and_deferred_6243`,
  `multi_fault_map_pins_use_two_pass_precedence_from_both_paths_6243`,
  `both_paths_open_full_seven_pin_bundle_before_ok_6243`. (Follow-up:
  #6246's `ReconcileSnapshotFds` state-representability cleanup — no
  `default()` placeholder, non-`Option` `apply_snapshot` return — is a
  SEPARATE concern tracked on #6243, not done here.)
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
- **CoS maps are published BEFORE forwarding becomes worker-visible
  (#5166).** In the same-plan refresh the workers KEEP RUNNING (no
  teardown), so a live worker observes the coordinator's ArcSwap stores
  per tick. `worker/loop_body` loads `shared_forwarding` FIRST, then the
  CoS map Arcs (`owner_worker_by_queue` / `owner_live_by_queue` /
  `root_leases` / `exact_backlogs` / `queue_leases` / `queue_vtime_floors`),
  and rebuilds `cos_fast_interfaces` from whichever CoS maps it holds.
  The commit therefore stores the derived CoS maps
  (`refresh_cos_owner_worker_map_from_identities`) and `ha.fabrics`
  BEFORE `shared_validation` / `ha.forwarding`. Because the worker reads
  forwarding-then-CoS in one tick and the coordinator stores
  CoS-then-forwarding, any worker that observes the new forwarding is
  guaranteed by ArcSwap acquire/release ordering to also observe the
  matching CoS maps — closing the pre-#5166 window where a worker saw the
  new queue config with a stale/empty CoS owner map (transient class
  blackhole for a newly added queue, stale-rate meter, or N-worker
  lease over-admission). The reverse window (new CoS maps visible while a
  worker still reads the old forwarding) is benign: an added queue is not
  classified-to until forwarding rotates, and a removed queue merely loses
  a dying CoS entry for one tick. This is a pure reorder of the
  coordinator-side stores — no new per-tick worker cost, no worker-side
  lock — matching the full-reconcile bring-up, which already refreshes the
  CoS maps before spawning workers. The WG/GRE aux-thread reconcile still
  runs AFTER the forwarding store (a fresh control thread's first
  `load_full()` must see the new state). A per-instance
  `#[cfg(test)] cos_owner_at_forwarding_publish` seam records the CoS
  owner map at the forwarding-publish instant so the ordering regression
  test (`refresh_runtime_snapshot_publishes_cos_owner_map_before_forwarding`)
  goes RED if the reorder is reverted.
- **Validation is published BEFORE forwarding becomes worker-visible
  (#6291).** The sibling of the #5166 CoS pair. The same-plan refresh
  stores `shared_validation` BEFORE `ha.forwarding` (both already in this
  order pre-#6291 — the bug was the WORKER read order), and the worker now
  acquire-loads forwarding FIRST, then validation
  (`refresh_forwarding_then_validation`, worker/loop_body). For a
  producer/consumer pair the acquire/release message-passing must run in
  OPPOSITE orders: producer stores validation-then-forwarding, consumer
  reads forwarding-then-validation, so observing the new forwarding Arc
  implies observing new-or-newer validation. This closes the ≤1-tick window
  where a worker saw OLD validation with NEW forwarding — a packet stamped
  at the old `config_generation`/`fib_generation` would pass
  `classify_metadata` (validation still at the old generation) and then be
  classified/forwarded under the new forwarding state. Pre-#6291 the store
  order (validation-then-forwarding) MATCHED the read order
  (validation-then-forwarding), so new-forwarding could pair with
  old-validation. The residual `(new-validation, old-forwarding)` window is
  benign: the generation guard errs toward a one-tick
  `ConfigGenerationMismatch` drop, never a stale forward. The deterministic
  regression test
  (`snapshot_refresh_no_torn_validation_forwarding_6291`, worker/loop_body)
  drives `refresh_forwarding_then_validation` with a coordinator publish
  injected between the two acquire-loads and asserts the worker never
  adopts new forwarding with old validation; swapping the two loads back
  makes it RED. The invariant is two-sided, so BOTH halves are
  RED-on-revert guarded: the producer half has its own per-instance
  `#[cfg(test)] validation_at_forwarding_publish` seam (the twin of the
  #5166 CoS seam) recording the WORKER-VISIBLE `shared_validation` at the
  forwarding-publish instant, asserted by
  `refresh_runtime_snapshot_publishes_validation_before_forwarding` —
  swapping the two coordinator stores makes THAT one RED. The worker's
  startup seed (`worker/loop_body/setup.rs`) reads in the same
  forwarding-then-validation order, and `stop_inner`'s teardown stores use
  the same validation-then-forwarding order (no live readers there — the
  worker threads are already joined — but one order everywhere keeps the
  rule true at every site).
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
  **#6242 makes the DIFFERENTIAL structural.** The launched workers
  `0..K-1` stay live because their `WorkerRuntimeRecord`s are registered
  ONLY on spawn-success (`records.insert` in the `Ok` arm) — the failed
  worker `K` never inserted a record, so the spawn-Err arm has NOTHING to
  unwind (the pre-#6242 three `.remove(&worker_id)` calls are gone) and
  never touches the launched records. The `force_worker_spawn_fail_skip`
  (fail the Kth, not the 1st) + `force_worker_healthy_stub` seams drive the
  PARTIAL-success test
  (`reconcile_partial_spawn_failure_preserves_launched_records_6242`), which
  asserts workers 0..K-1 keep their records and worker K has none; the
  symmetric `reconcile_bind_incomplete_clears_all_records_6242` pins the
  other side (bind-incomplete → `stop_inner` clears ALL).
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

- **Explicit binding-setup failures in the startup report (#6245).** #5143
  reported a bind failure ONLY by OMISSION — the failed slot was simply absent
  from `WorkerStartupReport.bound_slots`, so the barrier could prove
  incompleteness (`bound != planned`) but not say WHY (`worker_loop_setup`
  merely logged + mutated `BindingLiveState.last_error`, discarding the causal
  error, the phase, and the fallback path). The report now ALSO carries the
  EXPLICIT cause: `binding_failures: Vec<BindingSetupFailure>` — one
  `{ slot, phase, reason }` per TERMINAL per-slot failure
  (`BindingSetupPhase::Private` for a private-UMEM bind, `SharedFallback` for a
  shared-group bind whose private fallback ALSO failed), sorted by slot — plus
  `recovered_fallbacks: Vec<BindingRecoveredFallback>` recording shared-UMEM
  groups that failed their group bind but FULLY recovered via private fallback
  (a diagnostic DEGRADATION, sorted by group, that does NOT affect readiness —
  all slots still bound). The readiness criterion is UNCHANGED (`bound ==
  planned` set equality); on a shortfall the barrier records the EXPLICIT cause
  on the typed `ReconcileStage::WorkerBindIncomplete` identity — its
  `WorkerBindShortfall` now carries `failures: Vec<BindingSetupFailure>` cloned
  from the worker's report. Per #6244 the legacy operator string is produced in
  exactly one place: `ReconcileStage`'s `Display`, which appends the rendered
  cause (`render_binding_setup_failures`, co-located with `Display` in
  `reconcile/stage.rs`) for the partial-bind case, so
  `worker_bind_incomplete:<id>:bound=N:planned=M:failures=[private:slot=1:..]`
  names the slot, phase, and reason instead of only the set-difference counts
  (a shortfall with no recorded failure renders `failures=[no-explicit-failure]`
  rather than a blank; the timeout/no-report case keeps the counts-only
  `worker_bind_incomplete:<id>:timeout:planned=M`). The SUCCESS path is
  behavior-identical: a worker that bound its full planned set reports both vecs
  empty. The `force_worker_bind_incomplete` stub now emits a matching explicit
  failure for the dropped slot, so the report->barrier->stage explicit path is
  verified end-to-end without CAP_NET_ADMIN
  (`worker_bind_incomplete_report_carries_explicit_failure_6245`); the pure
  renderer is unit-tested in `reconcile::stage::tests`.

- **`bring_up_workers` is decomposed into cohesive phase helpers (#6240).**
  The 708-line transaction is now a short SHELL that sequences named phase
  helpers, all kept IN `reconcile/bringup.rs` (no one-file-per-phase). The
  helpers are behavior-preserving VERBATIM moves of the pre-#6240 inline
  blocks — only the shell + the helper boundaries change. In shell order:
  `clamp_ring_entries` (the #2524 ring-depth clamp), `plan_workers` (build the
  per-worker `BindingPlan` lists + `live`/`identities` + sizing + the `Planned`
  stage; TAKES the snapshot, reads the map FDs by RAW descriptor while `fds`
  still owns the `OwnedFd`s), `publish_runtime` (MOVE the `OwnedFd`s onto
  `coord.bpf_maps` + publish the mirror-target/CoS owner/active-shard maps),
  `replay_preserved_sessions` (build the command queues + replay preserved
  synced sessions), `ensure_resolver` (best-effort on-demand resolver,
  ATTEMPTED before launch), `spawn_workers` (the ~323-line per-worker spawn
  loop → a typed `LaunchOutcome`), the #5143 `await_readiness` barrier (renamed
  from `collect_worker_startup_readiness`), then
  `start_post_readiness_neighbor_services` (neighbor monitor + warmer + the
  #1881 local tunnel/WG reconcile). The load-bearing ORDER is preserved
  exactly: FD ownership transfer BEFORE any launch; mirror/CoS publication
  BEFORE replay/launch; sessions/queues BEFORE launch; resolver ATTEMPT BEFORE
  worker launch; ALL launches BEFORE the readiness barrier.
  **The #4952 two-armed rollback DECISION stays in the SHELL, distinct and
  visible — `spawn_workers` NEVER calls `stop_inner`.** `LaunchOutcome::SpawnFailed`
  → the shell returns `Err(Spawn)` WITHOUT `stop_inner` (launched records
  survive — structural via #6242's post-spawn-success insert);
  `LaunchOutcome::AllSpawned` → the shell runs the barrier and, on a shortfall,
  calls `stop_inner(false)` (clears ALL). Unifying the arms or moving
  `stop_inner` into a helper REDs
  `reconcile_partial_spawn_failure_preserves_launched_records_6242`. The
  resolver is BEST-EFFORT: `ensure_resolver` returns the installed handle as an
  `Option` (`None` on a spawn failure) and is NOT threaded into `spawn_workers`
  as a required input — the invariant is attempt-before-launch, NOT
  resolver-must-exist (`ensure_resolver_attempts_before_launch_best_effort_6240`).
  The startup-report SENDER is owned by the shell and passed by reference into
  `spawn_workers`, so it stays alive through the barrier — preserving
  `await_readiness`'s exact channel-disconnect semantics.
