//! #1328 Phase 2 — worker bringup phase.
//!
//! Pure code motion of the tail of the pre-#1328 monolithic
//! `Coordinator::reconcile` body (lines 529–819 of the old
//! `mod.rs`): build per-worker `BindingPlan` lists, apply shared
//! UMEM policy, store BPF map FDs on `self.bpf_maps`, publish
//! mirror-target + CoS owner maps, replay preserved synced
//! sessions, spawn worker threads (with the #925 panic-slot
//! insert + remove pairing kept inline), start the neighbor
//! monitor, and spawn the local tunnel sources. Final
//! `refresh_bindings` is invoked by the orchestrator, not here.
use super::ReconcileSnapshotFds;
// Pull everything the bringup body needs from afxdp scope via the
// coordinator's own re-imports. coordinator/mod.rs starts with
// `use super::*;` which makes all afxdp items visible there; doing
// the same here brings them into bringup's scope.
use super::super::super::*;
use super::super::supervisor::{spawn_supervised_aux, spawn_supervised_worker};
use super::super::{Coordinator, WorkerHandle};

/// #5143: how long `bring_up_workers` waits for every newly-started worker to
/// report its startup readiness (the set of planned bindings whose XSK
/// actually bound) before it fails the reconcile closed. A worker that never
/// reports within this bound is treated as failed — the barrier does NOT block
/// forever. 10s mirrors the HA sync-hold ceiling: comfortably above a healthy
/// worker's setup cost (per-worker TSC calibration ~10ms + UMEM mmap + XSK
/// bind, well under a second even for a full 6-queue VF) yet bounded so a hung
/// worker cannot wedge the control socket indefinitely. The COMMON failure — a
/// worker that finished setup with a PARTIAL binding set — reports immediately,
/// so the barrier fails fast without approaching this deadline; only a worker
/// that dies/hangs inside setup consumes the full budget.
const WORKER_STARTUP_BARRIER_TIMEOUT_NS: u64 = 10_000_000_000;

/// #5143: the two DISTINCT post-teardown worker-bringup failures, both raised
/// AFTER `tear_down` has stopped the old workers (so the data plane HAS moved
/// and there is no prior-state restore — only fail-closed bookkeeping + a
/// retry/last-good reconcile). `reconcile` maps each to its own
/// [`ReconcileError`] variant so the control handler can fail closed and NOT
/// persist the broken snapshot as the boot baseline.
pub(super) enum WorkerBringUpError {
    /// #4952: a worker thread failed to SPAWN (`spawn_supervised_worker` ->
    /// `pthread_create` EAGAIN/ENOMEM). Carries the preserved
    /// `spawn_worker_failed:<id>:<err>` stage.
    Spawn(String),
    /// #5143: a worker SPAWNED successfully but its in-thread XSK/UMEM bind
    /// did not bring up its FULL planned binding set (a partial/empty bind), or
    /// it never reported readiness within the bounded deadline. HEARTBEAT !=
    /// READINESS — a live heartbeat over an incomplete binding set is the
    /// silent forwarding outage this guards. Carries the
    /// `worker_bind_incomplete:<id>:..` stage.
    BindIncomplete(String),
}

/// Bring up the worker threads for the just-applied snapshot.
///
/// #4952: this runs on the POST-TEARDOWN destructive path — `tear_down`
/// has already stopped the previous workers, so a worker-thread spawn
/// failure here leaves the affected queue set with NO XSK-bound worker
/// (a silent forwarding outage). The spawn (`spawn_supervised_worker` ->
/// `thread::Builder::spawn` -> `pthread_create`) can return EAGAIN/ENOMEM
/// under resource exhaustion. On the FIRST such failure this ABORTS the
/// remaining launches (the data plane is already broken — spawning more
/// XSK-bound workers cannot restore forwarding and only compounds the
/// pressure), PRESERVES the `spawn_worker_failed:<id>:<err>` stage (it does
/// NOT overwrite it with `spawned:..`), skips the auxiliary-thread bring-up,
/// and returns `Err(WorkerBringUpError::Spawn(stage))`. The caller
/// (`reconcile`) maps that to `ReconcileError::WorkerSpawn` so the control
/// handler fails closed and does NOT persist the broken snapshot as the boot
/// baseline. On success returns `Ok(())`.
///
/// #5143: a SPAWN success only proves the thread exists — NOT that its
/// in-thread XSK/UMEM binds brought up the full planned queue set. A worker
/// that bound a PARTIAL/EMPTY set still HEARTBEATS, so the thread-death
/// supervisor is satisfied and (pre-#5143) this returned `Ok`, committing a
/// silent forwarding outage. #4952's spawn-error propagation does not catch it
/// (the spawn succeeded). So after the spawn loop this runs a STARTUP READINESS
/// BARRIER: every spawned worker reports the slot set it actually bound (a
/// `WorkerStartupReport` over a per-reconcile `mpsc` channel, sent from
/// `worker_loop` after setup), and the barrier waits — under a bounded deadline
/// ([`WORKER_STARTUP_BARRIER_TIMEOUT_NS`]; a worker that never reports in time
/// is treated as failed, NOT blocked forever) — for `bound == planned` per
/// worker. On ANY shortfall/timeout it FAILS CLOSED: `stop_inner(false)` stops +
/// joins the newly-started workers (no leaked live-but-unbound worker), preserves
/// the `worker_bind_incomplete:..` stage, and returns
/// `Err(WorkerBringUpError::BindIncomplete(stage))`, which `reconcile` maps to
/// `ReconcileError::WorkerBindIncomplete` (handled the same fail-closed way as
/// `WorkerSpawn`). HEARTBEAT != READINESS: the reconcile transaction now
/// requires one READY binding per required plan.
///
/// Full pre-teardown preflight of the spawn is not tractable — a real
/// `pthread_create` cannot be probed without spawning the thread, and the
/// old workers must be torn down first to free the XSK queue bindings the
/// new workers claim. So this is the minimal fail-closed guarantee (do not
/// persist a known-broken snapshot); a staged spawn-before-teardown is a
/// possible follow-up.
pub(super) fn bring_up_workers(
    coord: &mut Coordinator,
    snapshot: &ConfigSnapshot,
    bindings: &mut [BindingStatus],
    fds: ReconcileSnapshotFds,
    ring_entries: usize,
    preserved_synced_sessions: Vec<SyncedSessionEntry>,
) -> Result<(), WorkerBringUpError> {
    let ReconcileSnapshotFds {
        map_fd,
        heartbeat_map_fd,
        session_map_fd,
        conntrack_v4_fd,
        conntrack_v6_fd,
        dnat_table_fd,
        dnat_table_v6_fd,
        dnat_fds,
        // #2484: forwarding was consumed by apply_snapshot (built in the
        // pre-teardown preflight, moved into coord.forwarding); bring-up
        // reads coord.forwarding, not this field.
        forwarding: _,
    } = fds;
    // #2524: clamp to the shared sanity ceiling (MAX_RING_ENTRIES) as the
    // helper-side backstop for the Go commit-time bound. Floor stays 64.
    // The Go gate rejects any normally-committed value > MAX_RING_ENTRIES, so
    // a clamp here only fires on a config persisted by an older binary (before
    // the bound landed). Warn so an operator on the stale-binary path can see
    // the configured ring depth was capped rather than silently running a
    // smaller ring than configured.
    if ring_entries > MAX_RING_ENTRIES as usize {
        eprintln!(
            "xpf-dp: ring-entries {ring_entries} exceeds MAX_RING_ENTRIES {}; \
             capping (config predates the #2524 commit-time bound)",
            MAX_RING_ENTRIES
        );
    }
    let ring_entries = ring_entries.max(64).min(MAX_RING_ENTRIES as usize) as u32;
    let mut workers: BTreeMap<u32, Vec<BindingPlan>> = BTreeMap::new();
    for binding in bindings.iter_mut() {
        if !binding.registered || binding.ifindex <= 0 {
            binding.ready = false;
            continue;
        }
        let live = Arc::new(BindingLiveState::new());
        coord.workers.live.insert(binding.slot, live.clone());
        let identity = BindingIdentity {
            slot: binding.slot,
            queue_id: binding.queue_id,
            worker_id: binding.worker_id,
            interface: Arc::<str>::from(binding.interface.as_str()),
            ifindex: binding.ifindex,
        };
        coord.workers.identities.insert(binding.slot, identity);
        workers
            .entry(binding.worker_id)
            .or_default()
            .push(BindingPlan {
                status: binding.clone(),
                live,
                xsk_map_fd: map_fd.fd,
                heartbeat_map_fd: heartbeat_map_fd.fd,
                session_map_fd: session_map_fd.fd,
                conntrack_v4_fd: conntrack_v4_fd.as_ref().map(|f| f.fd).unwrap_or(-1),
                conntrack_v6_fd: conntrack_v6_fd.as_ref().map(|f| f.fd).unwrap_or(-1),
                ring_entries,
                bind_strategy: preferred_bind_strategy(binding),
                poll_mode: coord.poll_mode,
                shared_umem: SharedUmemBindingPlan::private(),
            });
    }
    for plans in workers.values_mut() {
        plans.sort_by_key(|plan| (plan.status.queue_id, plan.status.ifindex, plan.status.slot));
    }
    apply_shared_umem_policy_to_workers(snapshot, &mut workers);
    let shared_umem_status_by_slot = workers
        .values()
        .flat_map(|plans| plans.iter())
        .map(|plan| {
            (
                plan.status.slot,
                (
                    plan.status.shared_umem_mode.clone(),
                    plan.status.shared_umem_group.clone(),
                    plan.status.shared_umem_socket_role.clone(),
                    plan.status.shared_umem_disabled_reason.clone(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for binding in bindings.iter_mut() {
        if let Some((mode, group, role, reason)) = shared_umem_status_by_slot.get(&binding.slot) {
            binding.shared_umem_mode.clone_from(mode);
            binding.shared_umem_group.clone_from(group);
            binding.shared_umem_socket_role.clone_from(role);
            binding.shared_umem_disabled_reason.clone_from(reason);
        }
    }
    let planned_bindings: usize = workers.values().map(|group| group.len()).sum();
    coord.workers.last_planned_workers = workers.len();
    coord.workers.last_planned_bindings = planned_bindings;
    // #1830 follow-up (Codex review on PR #1841): record the SIZING
    // value for per-worker-id-indexed structures separately from the
    // count. Worker ids can be sparse here — the binding loop above
    // skips unregistered/invalid bindings, so a surviving high-id
    // worker can outlive every lower id (reachable via the runtime
    // binding/queue unregister handlers). Sizing the v8 lease arrays /
    // rotation scratch / V_min floors from workers.len() would put
    // that worker out of range (acquire_v8 returns 0 + debug-panics).
    coord.workers.last_planned_worker_slots = planned_worker_slots(&workers);
    coord.last_reconcile_stage = format!(
        "planned:workers={}:bindings={}:live={}",
        coord.workers.last_planned_workers(),
        coord.workers.last_planned_bindings(),
        coord.workers.live.len()
    );
    eprintln!(
        "xpf-userspace-dp: reconcile planned_workers={} planned_bindings={} live_slots={}",
        workers.len(),
        planned_bindings,
        coord.workers.live.len()
    );
    let session_map_raw_fd = session_map_fd.fd;
    coord.bpf_maps.map_fd = Some(map_fd);
    coord.bpf_maps.heartbeat_map_fd = Some(heartbeat_map_fd);
    coord.bpf_maps.session_map_fd = Some(session_map_fd);
    coord.bpf_maps.conntrack_v4_fd = conntrack_v4_fd;
    coord.bpf_maps.conntrack_v6_fd = conntrack_v6_fd;
    coord.bpf_maps.dnat_table_fd = dnat_table_fd;
    coord.bpf_maps.dnat_table_v6_fd = dnat_table_v6_fd;
    let worker_binding_ifindexes = workers
        .iter()
        .map(|(worker_id, binding_plans)| {
            (
                *worker_id,
                binding_plans
                    .iter()
                    .map(|plan| plan.status.ifindex)
                    .collect::<std::collections::BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let owner_map = super::super::build_cos_owner_worker_by_queue(&coord.forwarding, &workers);
    coord
        .mirror_targets
        .store(Arc::new(super::super::build_mirror_target_map(
            &coord.workers.identities,
            &coord.workers.live,
        )));
    let active_shards_by_egress_ifindex =
        super::super::build_cos_active_shards_by_egress_ifindex_with_fallback_ifindexes(
            &coord.forwarding,
            &worker_binding_ifindexes,
            &worker_binding_ifindexes,
        );
    coord.refresh_cos_runtime_maps(owner_map, active_shards_by_egress_ifindex);
    let worker_command_queues: Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>> = Arc::new(
        workers
            .keys()
            .copied()
            .map(|worker_id| (worker_id, Arc::new(Mutex::new(VecDeque::new()))))
            .collect(),
    );
    let replayed_synced_sessions = coord.replay_synced_sessions(
        &preserved_synced_sessions,
        worker_command_queues.as_ref(),
        session_map_raw_fd,
    );
    if replayed_synced_sessions > 0 {
        coord.last_reconcile_stage = format!(
            "replayed_synced:{}:workers={}",
            replayed_synced_sessions,
            worker_command_queues.len()
        );
    }
    // #1769: spawn the shared on-demand neighbor resolver BEFORE the
    // worker spawn loop so every worker captures a clone of the resolver
    // handle. Guarded like the monitor/warmer so a re-reconcile reuses
    // the existing thread. The resolver issues single-key RTM_GETNEIGH +
    // probe-on-stale off the hot path when a worker's negative-cache
    // fast-fail nudges a wedged dst.
    if coord.neighbors.resolver.is_none() {
        let (tx, rx) = mpsc::sync_channel::<ResolveItem>(
            super::super::neighbor_resolver::RESOLVER_QUEUE_DEPTH,
        );
        let resolver_stop = Arc::new(AtomicBool::new(false));
        let resolver_stop_clone = resolver_stop.clone();
        let dynamic_neighbors = coord.neighbors.dynamic.clone();
        let neighbor_generation = coord.neighbors.generation.clone();
        let neighbor_generation_handle = neighbor_generation.clone();
        let counters = coord.neighbors.resolver_counters.clone();
        let counters_clone = counters.clone();
        // #1772: latency telemetry shared into the resolver thread + the
        // worker-facing handle. `get_rtt_hist` is resolver-thread-only;
        // the dwell/drop/depth counters ride the worker-facing handle.
        let get_rtt_hist = coord.neighbors.resolver_get_rtt_hist.clone();
        let pending_dwell_hist = coord.neighbors.pending_dwell_hist.clone();
        let pending_timeout_drops = coord.neighbors.pending_timeout_drops.clone();
        let pending_max_depth = coord.neighbors.pending_max_depth.clone();
        // Retain the join handle so stop_inner can join the resolver and
        // enforce no-mutation-after-stop (the bare stop re-check is a
        // check-then-act race; joining is the real guard). Only install
        // the resolver handle when the thread actually spawned: on spawn
        // failure leave `resolver`/`resolver_stop`/`resolver_join` as
        // `None` so the NEXT reconcile retries (the `is_none()` guard
        // above stays true) and workers see `None` and skip on-demand
        // resolution — they never enqueue into a permanently-dead resolver
        // (Copilot). The dst still fast-fails normally; no availability
        // regression.
        match spawn_supervised_aux("neigh-resolver", move || {
            neighbor_resolver_loop(
                rx,
                dynamic_neighbors,
                neighbor_generation,
                counters_clone,
                get_rtt_hist,
                resolver_stop_clone,
            )
        }) {
            Ok(join) => {
                coord.neighbors.resolver = Some(Arc::new(NeighborResolver::new(
                    tx,
                    counters,
                    neighbor_generation_handle,
                    pending_dwell_hist,
                    pending_timeout_drops,
                    pending_max_depth,
                )));
                coord.neighbors.resolver_stop = Some(resolver_stop);
                coord.neighbors.resolver_join = Some(join);
            }
            Err(err) => {
                eprintln!(
                    "xpf-userspace-dp: neighbor resolver thread spawn failed: {err}; \
                     on-demand resolution disabled this reconcile (will retry)"
                );
            }
        }
    }
    // #4952: set on the FIRST worker-spawn failure; carries the preserved
    // `spawn_worker_failed:<id>:<err>` stage. Once set, the loop breaks
    // (abort remaining launches) and the tail returns Err(stage) so the
    // reconcile fails closed instead of persisting a broken snapshot.
    let mut spawn_failure: Option<String> = None;
    // #5143: per-worker STARTUP READINESS barrier. Each spawned worker reports
    // (over this channel, after its in-thread binds) the set of planned slots
    // whose XSK actually bound. `planned_slots_by_worker` records the set the
    // reconcile DISPATCHED to each worker; `spawned_worker_ids` is the set of
    // workers whose spawn succeeded (only those are expected to report). After
    // the spawn loop the barrier waits for every spawned worker's report under
    // a bounded deadline and checks bound == planned — a heartbeat alone no
    // longer counts as ready.
    let (startup_report_tx, startup_report_rx) = mpsc::channel::<WorkerStartupReport>();
    let mut planned_slots_by_worker: BTreeMap<u32, std::collections::BTreeSet<u32>> =
        BTreeMap::new();
    let mut spawned_worker_ids: Vec<u32> = Vec::new();
    for (worker_id, binding_plans) in workers {
        let plan_count = binding_plans.len();
        // #5143: the slot set this worker is REQUIRED to bind. Captured before
        // `binding_plans` is moved into the worker body so the barrier can
        // compare it against the worker's reported bound set.
        let planned_slots: std::collections::BTreeSet<u32> =
            binding_plans.iter().map(|plan| plan.status.slot).collect();
        let stop = Arc::new(AtomicBool::new(false));
        let heartbeat = Arc::new(AtomicU64::new(monotonic_nanos()));
        let session_export_ack = Arc::new(AtomicU64::new(0));
        let cos_status = Arc::new(ArcSwap::from_pointee(Vec::new()));
        let commands = worker_command_queues
            .get(&worker_id)
            .cloned()
            .unwrap_or_else(|| Arc::new(Mutex::new(VecDeque::new())));
        // #5289: give each worker its OWN exception ring + last-resolution
        // slot (registered in the coordinator so the ~1 Hz status thread can
        // drain them). This replaces the shared process-global
        // `recent_exceptions`/`last_resolution` mutexes whose cross-worker
        // contention was the DoS. The per-worker mutex is locked only by its
        // owning worker plus the status reader — no cross-worker false
        // sharing. Paired with the `.remove(&worker_id)` on the spawn-Err arm
        // and the teardown clear.
        let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
        coord
            .worker_exception_rings
            .insert(worker_id, recent_exceptions.clone());
        let last_resolution = Arc::new(Mutex::new(None));
        coord
            .worker_last_resolution
            .insert(worker_id, last_resolution.clone());
        let recent_session_deltas = coord.recent_session_deltas.clone();
        let slow_path = coord.slow_path.clone();
        let local_tunnel_deliveries = coord.local_tunnel_deliveries.clone();
        let shared_forwarding = coord.ha.forwarding.clone();
        let shared_validation = coord.shared_validation.clone();
        let shared_sessions = coord.sessions.synced.clone();
        let shared_nat_sessions = coord.sessions.nat.clone();
        let shared_forward_wire_sessions = coord.sessions.forward_wire.clone();
        let shared_owner_rg_indexes = coord.sessions.owner_rg_indexes.clone();
        let stop_clone = stop.clone();
        let heartbeat_clone = heartbeat.clone();
        let session_export_ack_clone = session_export_ack.clone();
        let commands_clone = commands.clone();
        let peer_commands_clone = worker_command_queues
            .iter()
            .filter(|(id, _)| **id != worker_id)
            .map(|(_, queue)| queue.clone())
            .collect::<Vec<_>>();
        let worker_commands_by_id = worker_command_queues.clone();
        let ha_state = coord.ha.rg_runtime.clone();
        let dynamic_neighbors = coord.neighbors.dynamic.clone();
        let neighbor_resolver = coord.neighbors.resolver.clone();
        let worker_poll_mode = coord.poll_mode;
        let shared_fabrics = coord.ha.fabrics.clone();
        let rg_epochs = coord.rg_epochs.clone();
        let event_stream_handle = coord.event_stream_worker_handle();
        let cos_status_clone = cos_status.clone();
        let shared_cos_owner_worker_by_queue = coord.cos.owner_worker_by_queue.clone();
        let shared_cos_owner_live_by_queue = coord.cos.owner_live_by_queue.clone();
        let shared_cos_root_leases = coord.cos.root_leases.clone();
        let shared_cos_exact_backlogs = coord.cos.exact_backlogs.clone();
        let shared_cos_queue_leases = coord.cos.queue_leases.clone();
        let shared_cos_queue_vtime_floors = coord.cos.queue_vtime_floors.clone();
        let shared_mirror_targets = coord.mirror_targets.clone();
        let runtime_atomics =
            std::sync::Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new());
        let runtime_atomics_clone = runtime_atomics.clone();
        // #1621: sibling per-worker WorkerColdPathAtomics, allocated
        // alongside the runtime_atomics so the publish + snapshot
        // contract is symmetric across the two seqlocks (window_gen +
        // cold_window_gen). Worker thread writes via
        // publish_from_local() each ~1s tick; coordinator status path
        // reads via snapshot() at each /metrics scrape.
        let cold_path_atomics =
            std::sync::Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new());
        let cold_path_atomics_clone = cold_path_atomics.clone();
        // #925 Phase 1: per-worker panic slot, keyed by worker_id.
        // Paired with `coord.worker_panics.remove(&worker_id)` on
        // the spawn-Err arm below — DO NOT split that pairing across
        // a helper without re-validating the panic-payload contract.
        let panic_slot = Arc::new(Mutex::new(None::<String>));
        coord.worker_panics.insert(worker_id, panic_slot.clone());
        // #5143: the worker's end of the startup-readiness channel. Moved into
        // the worker body; `worker_loop` sends the achieved bound-slot set on
        // it after setup, before entering the steady loop.
        let startup_report_tx_worker = startup_report_tx.clone();
        let body = move || {
            worker_loop(
                worker_id,
                binding_plans,
                shared_validation,
                shared_forwarding,
                ha_state,
                dynamic_neighbors,
                neighbor_resolver,
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                shared_owner_rg_indexes,
                slow_path,
                local_tunnel_deliveries,
                recent_exceptions,
                recent_session_deltas,
                last_resolution,
                commands_clone,
                peer_commands_clone,
                worker_commands_by_id,
                stop_clone,
                heartbeat_clone,
                session_export_ack_clone,
                worker_poll_mode,
                dnat_fds,
                shared_fabrics,
                event_stream_handle,
                rg_epochs,
                shared_cos_owner_worker_by_queue,
                shared_cos_owner_live_by_queue,
                shared_cos_root_leases,
                shared_cos_exact_backlogs,
                shared_cos_queue_leases,
                shared_cos_queue_vtime_floors,
                shared_mirror_targets,
                cos_status_clone,
                runtime_atomics_clone,
                cold_path_atomics_clone,
                startup_report_tx_worker,
            );
        };
        // #4952 test seam: force the fallible worker spawn to fail so the
        // post-teardown fail-closed propagation is unit-verifiable without a
        // real (unprovokable) pthread_create EAGAIN/ENOMEM. Declines the real
        // spawn, drops the worker body unspawned, and synthesizes the same
        // `std::io::Error` a resource-exhausted spawn returns. Always 0 in
        // release builds (`force_worker_spawn_fail` is `#[cfg(test)]`).
        //
        // #5143 test seam: force a SPAWNED worker to report an INCOMPLETE
        // startup bound-slot set (a worker whose in-thread XSK/UMEM bind failed
        // for one or more planned bindings but keeps heartbeating). A real
        // `worker_loop` cannot bind a real XSK in-process, so instead spawn a
        // joinable STUB thread that reports a bound set MISSING one planned
        // slot, then heartbeats until stopped — exercising the readiness
        // barrier's fail-close + stop/join end to end. Checked BEFORE the
        // spawn-fail seam so the two are mutually exclusive per worker.
        #[cfg(test)]
        let join = if coord.force_worker_bind_incomplete > 0 {
            coord.force_worker_bind_incomplete -= 1;
            drop(body);
            // Report every planned slot EXCEPT one (`skip(1)`), so with a
            // single planned binding the reported set is empty and with N it
            // is short by one — either way bound != planned -> barrier fails
            // closed.
            let incomplete_bound: Vec<u32> = planned_slots.iter().copied().skip(1).collect();
            let stub_stop = stop.clone();
            let stub_heartbeat = heartbeat.clone();
            let stub_tx = startup_report_tx.clone();
            let stub_worker_id = worker_id;
            spawn_supervised_worker(
                worker_id,
                runtime_atomics.clone(),
                panic_slot,
                move || {
                    let _ = stub_tx.send(WorkerStartupReport {
                        worker_id: stub_worker_id,
                        bound_slots: incomplete_bound,
                    });
                    // Heartbeat while "live-but-unbound" until the barrier
                    // stops us — bounded so a REVERTED (barrier removed) build
                    // does not leak a thread forever.
                    let mut ticks = 0u32;
                    while !stub_stop.load(std::sync::atomic::Ordering::Relaxed) && ticks < 5_000 {
                        stub_heartbeat.store(monotonic_nanos(), std::sync::atomic::Ordering::Relaxed);
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        ticks += 1;
                    }
                },
            )
        } else if coord.force_worker_spawn_fail > 0 {
            coord.force_worker_spawn_fail -= 1;
            drop(body);
            Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "forced worker spawn failure (test seam #4952)",
            ))
        } else {
            spawn_supervised_worker(worker_id, runtime_atomics.clone(), panic_slot, body)
        };
        #[cfg(not(test))]
        let join = spawn_supervised_worker(worker_id, runtime_atomics.clone(), panic_slot, body);
        match join {
            Ok(join) => {
                eprintln!(
                    "xpf-userspace-dp: started worker thread worker_id={} planned_bindings={}",
                    worker_id, plan_count
                );
                // #5143: this worker spawned, so it is EXPECTED to report its
                // startup bound-slot set; record its dispatched plan for the
                // barrier's bound-vs-planned check below.
                planned_slots_by_worker.insert(worker_id, planned_slots);
                spawned_worker_ids.push(worker_id);
                coord.workers.handles.insert(
                    worker_id,
                    WorkerHandle {
                        stop,
                        heartbeat,
                        commands,
                        session_export_ack,
                        cos_status,
                        runtime_atomics,
                        cold_path_atomics,
                        join: Some(join),
                    },
                );
            }
            Err(err) => {
                eprintln!(
                    "xpf-userspace-dp: failed to start worker thread worker_id={} err={}",
                    worker_id, err
                );
                let stage = format!("spawn_worker_failed:{worker_id}:{err}");
                coord.last_reconcile_stage = stage.clone();
                // #925 Phase 1: the panic slot was inserted before
                // spawn; drop it now so a snapshot reader doesn't
                // see a phantom slot for a worker that never ran.
                coord.worker_panics.remove(&worker_id);
                // #5289: the per-worker ring/last-resolution slots were
                // inserted before spawn; drop them so a status reader does
                // not see phantom slots for a worker that never ran.
                coord.worker_exception_rings.remove(&worker_id);
                coord.worker_last_resolution.remove(&worker_id);
                if let Ok(mut recent) = coord.recent_exceptions.lock() {
                    push_recent_exception(&mut recent, control_notice_event("", stage.clone()));
                }
                // #4952: a spawn failed on the POST-TEARDOWN destructive
                // path — the old workers are gone, so this queue set now has
                // NO XSK-bound worker (silent forwarding outage). ABORT the
                // remaining launches (the data plane is already broken;
                // spawning more XSK-bound workers cannot restore forwarding
                // and only compounds the resource pressure) and remember the
                // preserved stage so the tail returns Err and the caller
                // fails closed instead of persisting a broken snapshot.
                spawn_failure = Some(stage);
                break;
            }
        }
    }
    // #4952: on a post-teardown spawn failure, PRESERVE the
    // "spawn_worker_failed:.." stage (do NOT overwrite it with
    // "spawned:.."), skip the auxiliary-thread bring-up (forwarding is
    // down — the next successful reconcile starts them), and return the
    // failure so `reconcile` maps it to `ReconcileError::WorkerSpawn` and
    // the control handler fails closed, NOT persisting this broken snapshot
    // as the boot baseline.
    if let Some(stage) = spawn_failure {
        eprintln!(
            "xpf-userspace-dp: worker bring-up FAILED ({stage}); a queue set has no \
             XSK-bound worker after teardown — failing reconcile closed"
        );
        return Err(WorkerBringUpError::Spawn(stage));
    }
    // #5143: STARTUP READINESS BARRIER. Every worker SPAWNED (the #4952
    // spawn-failure fast-path above already returned otherwise), but a spawn
    // only proves the thread exists — NOT that its in-thread XSK/UMEM binds
    // brought up the full planned queue set. Wait (under a bounded deadline)
    // for each spawned worker to report the slot set it actually bound, then
    // require bound == planned. A worker that bound a PARTIAL/EMPTY set (the
    // #5143 silent forwarding outage: a live-but-unbound worker whose
    // heartbeat satisfied the supervisor) or never reported in time fails the
    // reconcile CLOSED — the same post-teardown fail-closed contract #4952
    // established for spawn failures, extended to the post-spawn bind failure.
    if let Some(stage) = collect_worker_startup_readiness(
        &startup_report_rx,
        &spawned_worker_ids,
        &planned_slots_by_worker,
    ) {
        eprintln!(
            "xpf-userspace-dp: worker bring-up FAILED ({stage}); a spawned worker did not \
             bind its full planned queue set after teardown — failing reconcile closed"
        );
        // Stop + JOIN the newly-started workers (the teardown path) so no
        // live-but-unbound worker keeps heartbeating past this fail-closed
        // reconcile, and clear the coordinator worker state so a retry /
        // last-good reconcile starts from a coherent baseline. Preserved
        // synced sessions are kept (`clear_synced_state=false`), matching the
        // reconcile teardown. `stop_inner` overwrites `last_reconcile_stage`
        // with "stopped", so restore the diagnostic stage AFTER it.
        coord.stop_inner(false);
        coord.last_reconcile_stage = stage.clone();
        return Err(WorkerBringUpError::BindIncomplete(stage));
    }
    coord.last_reconcile_stage = format!(
        "spawned:workers={}:identities={}:live={}",
        coord.workers.handles.len(),
        coord.workers.identities.len(),
        coord.workers.live.len()
    );
    // Start the helper-owned neighbor sync path. It does an initial
    // RTM_GETNEIGH dump so startup sees the existing kernel table, then
    // subscribes to RTM_{NEW,DEL}NEIGH for incremental updates.
    if coord.neighbors.monitor_stop.is_none() {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let dynamic_neighbors = coord.neighbors.dynamic.clone();
        let neighbor_generation = coord.neighbors.generation.clone();
        // #1771 §2.6: ENOBUFS/re-dump telemetry rides the shared
        // resolver-counter block (same status wire path).
        let monitor_counters = coord.neighbors.resolver_counters.clone();
        // #925-A: wrap aux thread in catch_unwind so a panic in the
        // netlink path doesn't kill the daemon. No respawn — see
        // spawn_supervised_aux doc for operator-visible degradation.
        //
        // #5165: RETAIN the join handle (was discarded via `.ok()`), mirroring
        // the sibling `neigh-resolver` above. Install `monitor_stop` +
        // `monitor_join` together ONLY when the thread actually spawned, so
        // `stop_inner` can JOIN the monitor after signalling stop and enforce
        // no-mutation-after-stop. On spawn failure leave BOTH `None` so the
        // `monitor_stop.is_none()` guard above lets the NEXT reconcile retry —
        // the neighbor cache still fills from the workers' RX-learned path and
        // the on-demand resolver, so there is no availability regression.
        match spawn_supervised_aux("neigh-monitor", move || {
            neigh_monitor_thread(
                stop_clone,
                dynamic_neighbors,
                neighbor_generation,
                monitor_counters,
            )
        }) {
            Ok(join) => {
                coord.neighbors.monitor_stop = Some(stop);
                coord.neighbors.monitor_join = Some(join);
            }
            Err(err) => {
                eprintln!(
                    "xpf-userspace-dp: neighbor monitor thread spawn failed: {err}; \
                     kernel neighbor sync disabled this reconcile (will retry)"
                );
            }
        }
    }
    // #1636 option C: spawn the long-lived neighbor-warmer worker. Fed
    // by Coordinator::queue_warm_pass via a bounded MPSC queue; fires
    // ARP/NDP solicits for configured next-hops off the hot path so the
    // neighbor cache is warm before the first user flow.
    if coord.neighbors.warm_queue.is_none() {
        let (tx, rx) = mpsc::sync_channel::<WarmItem>(WARM_QUEUE_DEPTH);
        let warm_stop = Arc::new(AtomicBool::new(false));
        let warm_stop_clone = warm_stop.clone();
        let last_probed = coord.neighbors.last_probed_at.clone();
        let warm_generation = coord.neighbors.warm_generation.clone();
        let rg_runtime = coord.ha.rg_runtime.clone();
        spawn_supervised_aux("neigh-warmer", move || {
            neighbor_warmer_loop(
                rx,
                last_probed,
                warm_generation,
                rg_runtime,
                warm_stop_clone,
            )
        })
        .ok();
        coord.neighbors.warm_queue = Some(tx);
        coord.neighbors.warm_stop = Some(warm_stop);
    }
    // #1881: three-pass reconcile (degenerates to pure spawn here —
    // stop_inner cleared the entry map before this bring-up, and the
    // worker spawn loop above populated `workers.handles`, satisfying
    // the spawn-pass worker gate).
    coord.reconcile_local_tunnel_sources();
    coord.spawn_wg_control_threads();
    Ok(())
}

/// #5143: the STARTUP READINESS BARRIER. Wait for every SPAWNED worker to
/// report the slot set its in-thread XSK/UMEM binds actually brought up, under
/// a bounded deadline ([`WORKER_STARTUP_BARRIER_TIMEOUT_NS`]), then check
/// `bound == planned` for each. Returns `None` when every worker bound its full
/// planned set (the reconcile may proceed), or `Some(stage)` — a
/// `worker_bind_incomplete:<id>:..` descriptor — on the FIRST worker that bound
/// a partial/empty set OR never reported in time (fail closed).
///
/// The barrier does NOT block forever: it stops waiting at the deadline and
/// treats any worker with no report as failed. A worker that finished setup
/// with a partial binding set reports IMMEDIATELY (the common failure), so this
/// returns fast without approaching the deadline; only a worker that
/// hangs/dies inside setup consumes the full budget. Reads a moved-value report
/// off the channel — no shared mutable state, so the channel's send→recv
/// establishes the happens-before for the reported set.
fn collect_worker_startup_readiness(
    startup_report_rx: &mpsc::Receiver<WorkerStartupReport>,
    spawned_worker_ids: &[u32],
    planned_slots_by_worker: &BTreeMap<u32, std::collections::BTreeSet<u32>>,
) -> Option<String> {
    if spawned_worker_ids.is_empty() {
        return None;
    }
    // Collect one report per spawned worker (last write wins per id) until we
    // have them all or the deadline elapses.
    let deadline_ns = monotonic_nanos().saturating_add(WORKER_STARTUP_BARRIER_TIMEOUT_NS);
    let mut bound_by_worker: BTreeMap<u32, std::collections::BTreeSet<u32>> = BTreeMap::new();
    while bound_by_worker.len() < spawned_worker_ids.len() {
        let now = monotonic_nanos();
        if now >= deadline_ns {
            break;
        }
        match startup_report_rx.recv_timeout(std::time::Duration::from_nanos(deadline_ns - now)) {
            Ok(report) => {
                bound_by_worker.insert(report.worker_id, report.bound_slots.into_iter().collect());
            }
            // Timed out with reports still outstanding, or every sender was
            // dropped (a worker panicked in setup before reporting). Either
            // way the missing worker(s) are treated as failed below.
            Err(mpsc::RecvTimeoutError::Timeout)
            | Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    for &worker_id in spawned_worker_ids {
        let planned = planned_slots_by_worker
            .get(&worker_id)
            .cloned()
            .unwrap_or_default();
        match bound_by_worker.get(&worker_id) {
            Some(bound) if *bound == planned => {}
            Some(bound) => {
                return Some(format!(
                    "worker_bind_incomplete:{worker_id}:bound={}:planned={}",
                    bound.len(),
                    planned.len()
                ));
            }
            None => {
                return Some(format!(
                    "worker_bind_incomplete:{worker_id}:timeout:planned={}",
                    planned.len()
                ));
            }
        }
    }
    None
}

/// #1830 follow-up (Codex review on PR #1841): array length needed to
/// index every planned worker id — `max(worker_id) + 1`, 0 when no
/// workers are planned. NOT the worker count: ids can be sparse after
/// partial binding unregister (the bring-up loop skips
/// unregistered/invalid bindings), and the v8 lease contract
/// (`SharedCoSQueueLease::new_v8`) requires the TRUE max id so its
/// per-worker arrays and rotation scratch cover every live worker.
/// Generic over the map value so the sparse-id derivation is unit
/// testable without constructing `BindingPlan`s.
pub(in crate::afxdp) fn planned_worker_slots<V>(workers: &BTreeMap<u32, V>) -> usize {
    workers
        .keys()
        .next_back()
        .map(|&id| id as usize + 1)
        .unwrap_or(0)
}
