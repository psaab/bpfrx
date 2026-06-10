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

pub(super) fn bring_up_workers(
    coord: &mut Coordinator,
    snapshot: &ConfigSnapshot,
    bindings: &mut [BindingStatus],
    fds: ReconcileSnapshotFds,
    ring_entries: usize,
    preserved_synced_sessions: Vec<SyncedSessionEntry>,
) {
    let ReconcileSnapshotFds {
        map_fd,
        heartbeat_map_fd,
        session_map_fd,
        conntrack_v4_fd,
        conntrack_v6_fd,
        dnat_table_fd,
        dnat_table_v6_fd,
        dnat_fds,
    } = fds;
    let ring_entries = ring_entries.max(64).min(u32::MAX as usize) as u32;
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
    for (worker_id, binding_plans) in workers {
        let plan_count = binding_plans.len();
        let stop = Arc::new(AtomicBool::new(false));
        let heartbeat = Arc::new(AtomicU64::new(monotonic_nanos()));
        let session_export_ack = Arc::new(AtomicU64::new(0));
        let cos_status = Arc::new(ArcSwap::from_pointee(Vec::new()));
        let commands = worker_command_queues
            .get(&worker_id)
            .cloned()
            .unwrap_or_else(|| Arc::new(Mutex::new(VecDeque::new())));
        let recent_exceptions = coord.recent_exceptions.clone();
        let recent_session_deltas = coord.recent_session_deltas.clone();
        let last_resolution = coord.last_resolution.clone();
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
        let join =
            spawn_supervised_worker(worker_id, runtime_atomics.clone(), panic_slot, move || {
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
                );
            });
        match join {
            Ok(join) => {
                eprintln!(
                    "xpf-userspace-dp: started worker thread worker_id={} planned_bindings={}",
                    worker_id, plan_count
                );
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
                coord.last_reconcile_stage = format!("spawn_worker_failed:{worker_id}:{err}");
                // #925 Phase 1: the panic slot was inserted before
                // spawn; drop it now so a snapshot reader doesn't
                // see a phantom slot for a worker that never ran.
                coord.worker_panics.remove(&worker_id);
                if let Ok(mut recent) = coord.recent_exceptions.lock() {
                    push_recent_exception(
                        &mut recent,
                        ExceptionStatus {
                            timestamp: Utc::now(),
                            reason: format!("spawn_worker_failed:{worker_id}:{err}"),
                            ..ExceptionStatus::default()
                        },
                    );
                }
            }
        }
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
        spawn_supervised_aux("neigh-monitor", move || {
            neigh_monitor_thread(
                stop_clone,
                dynamic_neighbors,
                neighbor_generation,
                monitor_counters,
            )
        })
        .ok();
        coord.neighbors.monitor_stop = Some(stop);
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
    coord.spawn_local_tunnel_sources();
    coord.spawn_wg_control_threads();
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
