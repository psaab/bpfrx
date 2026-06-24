// #1326 — extracted from worker/mod.rs (pure code motion).
// The `worker_loop` per-tick orchestrator was previously a ~1278 LOC
// function in worker/mod.rs (L995-L2273), moved here verbatim as the
// first phase of the #1326 refactor.
//
// #1776 (Phase 2, narrowed v3.1 scope) carved out the two cold
// extractions: the one-shot setup phase (setup.rs) and the
// cfg(debug-log) verbose report / stall dump (debug_report.rs).
// Everything per-tick — telemetry publish, ArcSwap config refresh,
// HA load, command drain, the hot `poll_binding` sweep, heartbeat,
// the always-on binding diagnostics + BindingLiveState publish, and
// idle regulation — deliberately stays INLINE in this file: the
// round-1 plan review (Codex r1-4) established that an
// #[inline(never)] call boundary in front of the per-tick
// `load_arc_if_changed` path risks regressing the 10K-100K ticks/s
// loop, so no call was added to the per-tick path.
//
// `use super::*;` brings every type, helper, and sibling-submodule
// item from worker/mod.rs into scope — the same pattern lifecycle.rs
// and cos.rs use. Pure relocation — no production logic touched.

use super::*;

// #1776: the one-shot setup phase (thread pin, TSC calibration,
// initial ArcSwap load_fulls, binding construction, BPF-map-FD
// cache, initial cos_status publish) lives in loop_body/setup.rs.
mod setup;

// #1776: the cfg(debug-log) verbose per-second report + stall dump +
// per-interval DbgCounters live in loop_body/debug_report.rs. The
// module is feature-gated at the declaration so release builds
// compile none of it.
#[cfg(feature = "debug-log")]
mod debug_report;

pub(crate) fn worker_loop(
    worker_id: u32,
    binding_plans: Vec<BindingPlan>,
    shared_validation: Arc<ArcSwap<ValidationState>>,
    shared_forwarding: Arc<ArcSwap<ForwardingState>>,
    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    dynamic_neighbors: Arc<ShardedNeighborMap>,
    neighbor_resolver: Option<Arc<NeighborResolver>>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: SharedSessionOwnerRgIndexes,
    slow_path: Option<Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    recent_session_deltas: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    last_resolution: Arc<Mutex<Option<PacketResolution>>>,
    commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    worker_commands_by_id: Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>>,
    stop: Arc<AtomicBool>,
    heartbeat: Arc<AtomicU64>,
    session_export_ack: Arc<AtomicU64>,
    poll_mode: crate::PollMode,
    dnat_fds: DnatTableFds,
    shared_fabrics: Arc<ArcSwap<Vec<FabricLink>>>,
    event_stream: Option<crate::event_stream::EventStreamWorkerHandle>,
    rg_epochs: Arc<[AtomicU32; MAX_RG_EPOCHS]>,
    shared_cos_owner_worker_by_queue: Arc<ArcSwap<BTreeMap<(i32, u8), u32>>>,
    shared_cos_owner_live_by_queue: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<BindingLiveState>>>>,
    shared_cos_root_leases: Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSRootLease>>>>,
    shared_cos_exact_backlogs: Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSExactBacklog>>>>,
    shared_cos_queue_leases: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>>,
    shared_cos_queue_vtime_floors: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>>,
    shared_mirror_targets: Arc<ArcSwap<MirrorTargetMap>>,
    cos_status: Arc<ArcSwap<Vec<crate::protocol::CoSInterfaceStatus>>>,
    // #869: worker-runtime telemetry publish slot.  Worker writes its
    // local counters here on a ~1s cadence; coordinator reads for status.
    runtime_atomics: Arc<crate::afxdp::worker_runtime::WorkerRuntimeAtomics>,
    // #1621: sibling per-worker cold-path histogram publish slot.
    // Worker calls publish_from_local() each ~1s tick alongside the
    // runtime_atomics.publish(). Coordinator status path reads via
    // snapshot() at each /metrics scrape.
    cold_path_atomics: Arc<crate::afxdp::cold_path_hist::WorkerColdPathAtomics>,
) {
    // #1776: one-shot setup moved verbatim to setup.rs. The returned
    // WorkerLoopSetup is destructured into the same-named locals so
    // the loop body below is textually unchanged.
    let setup::WorkerLoopSetup {
        ha_startup_grace_until_secs,
        mut validation,
        mut forwarding,
        mut cos_owner_worker_by_queue,
        mut cos_owner_live_by_queue,
        mut cos_shared_root_leases,
        mut cos_shared_exact_backlogs,
        mut cos_shared_queue_leases,
        mut cos_shared_queue_vtime_floors,
        mut mirror_targets,
        mut sessions,
        mut screen_state,
        mut bindings,
        binding_lookup,
        mut interrupt_poll_fds,
        session_map_fd,
        conntrack_v4_fd,
        conntrack_v6_fd,
        mut last_cos_status_ns,
    } = setup::worker_loop_setup(
        worker_id,
        binding_plans,
        &shared_validation,
        &shared_forwarding,
        &shared_cos_owner_worker_by_queue,
        &shared_cos_owner_live_by_queue,
        &shared_cos_root_leases,
        &shared_cos_exact_backlogs,
        &shared_cos_queue_leases,
        &shared_cos_queue_vtime_floors,
        &shared_mirror_targets,
        poll_mode,
        &cos_status,
        &runtime_atomics,
        &cold_path_atomics,
    );
    const COS_STATUS_INTERVAL_NS: u64 = 100_000_000;
    let mut idle_iters = 0u32;
    let mut poll_start = 0usize;
    let mut shared_recycles = Vec::with_capacity((RX_BATCH_SIZE as usize).saturating_mul(2));
    // Debug: periodic summary counters
    let mut dbg_last_report_ns = monotonic_nanos();
    // #1776: the per-interval cfg(debug-log) dbg_* counters are
    // consolidated into debug_report::DbgCounters (single-line
    // default() reset each report tick). dbg_last_report_ns above and
    // the stall baselines below are PERSISTENT debug state that
    // survives across report intervals — deliberately NOT DbgCounters
    // fields, so the interval reset cannot wipe them (plan v3.1 AGY
    // CORRECTNESS-1).
    #[cfg(feature = "debug-log")]
    let mut dbg = debug_report::DbgCounters::default();
    #[cfg(feature = "debug-log")]
    let mut stall_prev_fwd = 0u64;
    #[cfg(feature = "debug-log")]
    let mut stall_reported = false;
    const DBG_REPORT_INTERVAL_NS: u64 = 1_000_000_000; // 1 second
    // Throttle for BPF conntrack last_seen refresh (~10s).
    // Keeps `show security flow session` idle times accurate without
    // per-second syscall overhead per session.  See issue #333.
    const CT_REFRESH_INTERVAL_NS: u64 = 10_000_000_000;
    let mut last_ct_refresh_ns: u64 = 0;
    // #869: worker-runtime telemetry.  Local counters, published to
    // `runtime_atomics` on the ~1s cadence below.
    use crate::afxdp::worker_runtime::{
        WorkerRuntimeCounters, WorkerRuntimeState, sample_thread_cpu_ns,
    };
    let mut wr_counters = WorkerRuntimeCounters::default();
    let mut wr_state = WorkerRuntimeState::IdleBlock;
    let mut wr_last_loop_ns = monotonic_nanos();
    let mut wr_last_publish_ns = wr_last_loop_ns;
    // #1760 W1: previous-snapshot values for the durable journald
    // collision warn. Compared on the ~1s publish cadence below — zero
    // per-packet work, one u64 compare per publish while the counters
    // stay 0. The shared-displacement value is process-global, so every
    // worker tracks its own prev and the process-global CAS throttle in
    // shared_ops bounds emission to <=1 line/min regardless of how many
    // workers observe the same increment.
    let mut wr_prev_nat_collisions: u64 = 0;
    let mut wr_prev_shared_displacements: u64 = 0;
    const WR_PUBLISH_INTERVAL_NS: u64 = 1_000_000_000;
    while !stop.load(Ordering::Relaxed) {
        let loop_now_ns = monotonic_nanos();
        // #869: attribute elapsed delta to the previous loop's state.
        {
            let delta = loop_now_ns.saturating_sub(wr_last_loop_ns);
            wr_counters.wall_ns = wr_counters.wall_ns.wrapping_add(delta);
            match wr_state {
                WorkerRuntimeState::Active => {
                    wr_counters.active_ns = wr_counters.active_ns.wrapping_add(delta);
                }
                WorkerRuntimeState::IdleSpin => {
                    wr_counters.idle_spin_ns = wr_counters.idle_spin_ns.wrapping_add(delta);
                }
                WorkerRuntimeState::IdleBlock => {
                    wr_counters.idle_block_ns = wr_counters.idle_block_ns.wrapping_add(delta);
                }
            }
            wr_last_loop_ns = loop_now_ns;
            if loop_now_ns.saturating_sub(wr_last_publish_ns) >= WR_PUBLISH_INTERVAL_NS {
                // Skip on transient clock_gettime failure (sample == 0):
                // overwriting a previously-published nonzero value with 0
                // would make the Prometheus counter go backwards and
                // break `rate()` queries.
                let sampled_cpu_ns = sample_thread_cpu_ns();
                if sampled_cpu_ns != 0 {
                    wr_counters.thread_cpu_ns = sampled_cpu_ns;
                }
                refresh_worker_cos_queue_lease_runtime_counters(&mut wr_counters, &bindings);
                wr_counters.session_table_entries = sessions.len() as u64;
                wr_counters.max_sessions = sessions.max_sessions() as u64;
                wr_counters.nat_reverse_key_collisions = sessions.nat_reverse_key_collisions();
                // #1861: install-refusal trio from the worker's
                // SessionTable (create_drops was write-only before).
                wr_counters.session_create_drops = sessions.create_drops();
                wr_counters.session_install_admission_refused = sessions.admission_refused();
                wr_counters.session_install_partial = sessions.install_partial();
                // #1760 W1: durable artifact for the reverse-key-collision
                // watch. The in-process counters reset on every restart
                // and the lab has no long-term Prometheus store, so a
                // collision that happened before a redeploy would be
                // unobservable without a journald line. Rate-limited by
                // the process-global 60s CAS throttle; honest-semantics
                // text per docs/research/1760-reverse-key-v2/plan.md §2.3.
                let shared_displacements =
                    crate::afxdp::shared_ops::NAT_REVERSE_KEY_SHARED_DISPLACEMENTS
                        .load(Ordering::Relaxed);
                if wr_counters.nat_reverse_key_collisions > wr_prev_nat_collisions
                    || shared_displacements > wr_prev_shared_displacements
                {
                    // Only consume the pending increment when the warn was
                    // actually emitted: a throttled increment keeps the
                    // prevs unchanged and retries on later publish ticks,
                    // so a burst inside one 60s window (or during the
                    // first window after start, when the CAS slot is
                    // still warming) still produces its journald line
                    // instead of being silently swallowed.
                    if crate::afxdp::shared_ops::try_claim_nat_reverse_key_warn(loop_now_ns) {
                        eprintln!(
                            "xpf-dp: NAT reverse-key collision detected (worker={} \
                             local_total={} shared_total={}) — #1760 latent 1:N \
                             reverse-path corruption; counts are displacement \
                             events (>=1 means a real collision occurred; not a \
                             pair census — standing collisions against an \
                             already-unindexed session are not counted)",
                            worker_id, wr_counters.nat_reverse_key_collisions, shared_displacements,
                        );
                        wr_prev_nat_collisions = wr_counters.nat_reverse_key_collisions;
                        wr_prev_shared_displacements = shared_displacements;
                    }
                }
                runtime_atomics.publish(&wr_counters, loop_now_ns);
                // #1621: alongside the runtime publish, merge each
                // binding's cold-path worker-local counters into a
                // single WorkerColdPathCounters and publish via the
                // sibling atomics' own cold_window_gen seqlock.
                //
                // Per plan v1 §4.2: saturating_add buckets / sum_ns /
                // samples / sample_phase / wrapper_underflow_count;
                // OR alias_seen; first-non-zero first_key (cross-
                // binding aliasing detected when bindings disagree).
                {
                    use crate::afxdp::cold_path_hist as cph;
                    let mut merged = cph::WorkerColdPathCounters::default();
                    for binding in bindings.iter() {
                        let src = &binding.cold_path;
                        merged.sample_phase = merged.sample_phase.saturating_add(src.sample_phase);
                        merged.wrapper_underflow_count = merged
                            .wrapper_underflow_count
                            .saturating_add(src.wrapper_underflow_count);
                        for slot in 0..cph::POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
                            merged.sum_ns[slot] =
                                merged.sum_ns[slot].saturating_add(src.sum_ns[slot]);
                            merged.samples[slot] =
                                merged.samples[slot].saturating_add(src.samples[slot]);
                            for b in 0..cph::POLICY_COLD_PATH_HIST_BUCKETS {
                                merged.buckets[slot][b] =
                                    merged.buckets[slot][b].saturating_add(src.buckets[slot][b]);
                            }
                            // first_key + builder_collision cross-binding merge.
                            if merged.first_key[slot] == 0 {
                                merged.first_key[slot] = src.first_key[slot];
                            } else if src.first_key[slot] != 0
                                && src.first_key[slot] != merged.first_key[slot]
                            {
                                merged.builder_collision[slot] = true;
                            }
                            merged.builder_collision[slot] |= src.builder_collision[slot];
                        }
                    }
                    // All bindings on this worker share the same pinned
                    // core ⇒ same TSC calibration. Take any binding's
                    // value (default = 0 if no bindings — calibration
                    // not yet installed).
                    if let Some(first) = bindings.first() {
                        merged.ns_per_tsc_q32 = first.cold_path.ns_per_tsc_q32;
                        merged.wrapper_ns_baseline = first.cold_path.wrapper_ns_baseline;
                        merged.clock_source = first.cold_path.clock_source;
                    }
                    cold_path_atomics.publish_from_local(&merged);
                }
                wr_last_publish_ns = loop_now_ns;
            }
        }
        let loop_now_secs = loop_now_ns / 1_000_000_000;
        let live_validation = shared_validation.load();
        if **live_validation != validation {
            validation = **live_validation;
        }
        let mut rebuild_cos_fast_interfaces = false;
        // #1188: per-tick Arc refresh — `.load() + Arc::ptr_eq`
        // short-circuits the unconditional `.load_full()` clone
        // when the coordinator hasn't rotated the Arc.
        if let Some(new_forwarding) = load_arc_if_changed(&forwarding, &shared_forwarding) {
            // Compare BEFORE assignment — needs both old and new.
            let cos_changed =
                cos_runtime_config_changed(forwarding.as_ref(), new_forwarding.as_ref());
            let (dscp_changed_v4, dscp_changed_v6) =
                crate::filter::input_dscp_filter_families_changed(
                    &forwarding.filter_state,
                    &new_forwarding.filter_state,
                );
            // #2362: a per-packet-L4 (tcp-flags / is-fragment / icmp-type /
            // icmp-code) input filter rotation has the same revalidation
            // requirement as a DSCP filter rotation — established sessions whose
            // first packet was admitted under the old term set must be purged so
            // the new term is re-evaluated. Fold the two change-sets into one
            // purge per family.
            let (per_packet_changed_v4, per_packet_changed_v6) =
                crate::filter::input_per_packet_l4_filter_families_changed(
                    &forwarding.filter_state,
                    &new_forwarding.filter_state,
                );
            let purge_input_dscp_v4 = dscp_changed_v4 || per_packet_changed_v4;
            let purge_input_dscp_v6 = dscp_changed_v6 || per_packet_changed_v6;

            // Use NEW values for dependent state updates (forwarding-site
            // ordering — old `forwarding` is stale once rotated).
            screen_state.update_profiles(new_forwarding.screen_profiles.clone());
            screen_state.update_syn_cookie_master_key(new_forwarding.syn_cookie_master_key);
            sessions.set_timeouts(new_forwarding.session_timeouts);
            // #2134: re-derive the per-IP session-limit OFF-gate on every
            // runtime forwarding-snapshot rotation. A runtime ON->OFF
            // transition (operator removes `limit-session`) clears the
            // stale count maps via set_session_limit_active so a later
            // re-enable starts clean and cannot spuriously block an
            // under-limit IP.
            sessions.set_session_limit_active(screen_state.any_session_limit_configured());

            // #1635 (plan §2.4): a config apply may have reassigned
            // cold-path histogram slots to new zone-pairs. Zero those
            // slots in every binding's worker-local accumulator BEFORE
            // any record_sample into the reused slot, so a reused slot
            // never carries the previous zone-pair's counts.
            //
            // Copilot code-r2: derive the zero-set from THIS WORKER's
            // OWN old map vs the new map, NOT from the coordinator's
            // `slots_to_zero` list. A worker can skip intermediate
            // ForwardingState generations (ArcSwap only ever delivers
            // the latest), and the coordinator computes `slots_to_zero`
            // relative to its immediately-previous map — so a slot
            // reassigned in a skipped generation would be absent from
            // the latest list (it now looks "retained"). Comparing the
            // worker's actual old slot-map inverse against the new one
            // is generation-independent: any slot whose mapping changed
            // since the worker last observed it gets zeroed. The
            // sibling atomics are overwritten at the next publish merge
            // from the freshly-zeroed local accumulator.
            {
                let old_inverse = &forwarding.cold_path_slot_map.inverse;
                let new_inverse = &new_forwarding.cold_path_slot_map.inverse;
                for slot in 0..crate::afxdp::cold_path_hist::POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
                    let new_pair = new_inverse.get(slot).copied().flatten();
                    // Zero when the slot now maps to a pair that differs
                    // from what the worker last saw there. A freed slot
                    // (new == None) keeps its stale local data harmlessly
                    // — it is unmapped, never sampled, and gets zeroed
                    // when next reassigned.
                    if new_pair.is_some() && new_pair != old_inverse.get(slot).copied().flatten() {
                        for binding in bindings.iter_mut() {
                            binding.cold_path.zero_slot(slot);
                        }
                    }
                }
            }

            forwarding = new_forwarding;
            let purged_input_dscp = purge_sessions_for_input_dscp_filter_revalidation(
                &mut sessions,
                session_map_fd,
                conntrack_v4_fd,
                conntrack_v6_fd,
                &shared_sessions,
                &shared_nat_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &peer_worker_commands,
                &forwarding,
                purge_input_dscp_v4,
                purge_input_dscp_v6,
                loop_now_ns,
            );
            if purged_input_dscp > 0 {
                debug_log!(
                    "INPUT_DSCP_FILTER_PURGE: worker={} sessions={}",
                    worker_id,
                    purged_input_dscp,
                );
            }
            let republished = republish_local_delivery_sessions_for_lo0_filter(
                &sessions,
                session_map_fd,
                &forwarding,
            );
            if republished > 0 {
                debug_log!(
                    "LO0_FILTER_REPUBLISH: worker={} local_delivery_sessions={}",
                    worker_id,
                    republished,
                );
            }

            if cos_changed {
                reset_worker_cos_runtimes(&mut bindings, &mut shared_recycles);
                apply_shared_recycles_to_bindings(
                    &mut bindings,
                    &binding_lookup,
                    &mut shared_recycles,
                );
                rebuild_cos_fast_interfaces = true;
            }
        }
        if let Some(new_x) = load_arc_if_changed(&mirror_targets, &shared_mirror_targets) {
            mirror_targets = new_x;
        }
        if let Some(new_x) = load_arc_if_changed(
            &cos_owner_worker_by_queue,
            &shared_cos_owner_worker_by_queue,
        ) {
            cos_owner_worker_by_queue = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) =
            load_arc_if_changed(&cos_owner_live_by_queue, &shared_cos_owner_live_by_queue)
        {
            cos_owner_live_by_queue = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) = load_arc_if_changed(&cos_shared_root_leases, &shared_cos_root_leases) {
            for binding in bindings.iter_mut() {
                release_all_cos_root_leases(binding);
                release_all_cos_queue_leases(binding);
            }
            cos_shared_root_leases = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) =
            load_arc_if_changed(&cos_shared_exact_backlogs, &shared_cos_exact_backlogs)
        {
            cos_shared_exact_backlogs = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) = load_arc_if_changed(&cos_shared_queue_leases, &shared_cos_queue_leases)
        {
            for binding in bindings.iter_mut() {
                release_all_cos_queue_leases(binding);
            }
            cos_shared_queue_leases = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) = load_arc_if_changed(
            &cos_shared_queue_vtime_floors,
            &shared_cos_queue_vtime_floors,
        ) {
            // #917: Arc-replacement of the V_min floors map.
            // Each shared_exact queue's per-worker slots default
            // to NOT_PARTICIPATING in the new Arc. Workers will
            // re-publish their committed vtime on the next
            // commit-boundary publish; until then peers reading
            // this slot see "not participating" and skip it in
            // V_min reduction (per plan §3.4 / §3.7 lifecycle
            // rules).
            cos_shared_queue_vtime_floors = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if rebuild_cos_fast_interfaces {
            let cos_owner_live_by_tx_ifindex = build_worker_cos_owner_live_by_tx_ifindex(
                bindings
                    .iter()
                    .map(|binding| (binding.ifindex, binding.live.clone())),
            );
            let cos_fast_interfaces = build_worker_cos_fast_interfaces(
                forwarding.as_ref(),
                worker_id,
                &cos_owner_live_by_tx_ifindex,
                cos_owner_worker_by_queue.as_ref(),
                cos_owner_live_by_queue.as_ref(),
                cos_shared_root_leases.as_ref(),
                cos_shared_exact_backlogs.as_ref(),
                cos_shared_queue_leases.as_ref(),
                cos_shared_queue_vtime_floors.as_ref(),
            );
            for binding in bindings.iter_mut() {
                binding.cos.cos_fast_interfaces = cos_fast_interfaces.clone();
            }
            // The new SharedCoSExactBacklog slots in the freshly built
            // cos_fast_interfaces start at zero. Republish the current
            // exact-queue backlog for every binding/ifindex so peer workers
            // do not observe a false-zero window until the next organic
            // enqueue or drain refresh.
            for binding in bindings.iter() {
                for &root_ifindex in binding.cos.cos_interfaces.keys() {
                    publish_cos_exact_backlog(binding, root_ifindex);
                }
            }
        }
        let ha_runtime = ha_state.load();
        // Only apply commands when pending — avoids lock overhead on
        // every loop iteration in the common (empty-queue) case.
        // #1807: a poisoned mutex is recovered (and the poison cleared)
        // instead of reading as "no commands" — that turned one worker
        // panic into permanent deafness to coordinator commands.
        let has_commands = crate::afxdp::worker_queue::try_lock_recover(&commands)
            .map(|q| !q.is_empty())
            .unwrap_or(false);
        let command_results = if has_commands {
            apply_worker_commands(
                &commands,
                &mut sessions,
                session_map_fd,
                conntrack_v4_fd,
                conntrack_v6_fd,
                &forwarding,
                ha_runtime.as_ref(),
                &dynamic_neighbors,
            )
        } else {
            WorkerCommandResults {
                cancelled_keys: Vec::new(),
                exported_sequences: Vec::new(),
                shaped_tx_requests: Vec::new(),
                vacate_all_shared_exact_slots: false,
            }
        };
        let WorkerCommandResults {
            cancelled_keys,
            exported_sequences,
            shaped_tx_requests,
            vacate_all_shared_exact_slots,
        } = command_results;
        // #941 Work item C: HA-demotion vacate. The
        // VacateAllSharedExactSlots WorkerCommand cannot be processed
        // inside `apply_worker_commands` (no BindingWorker access);
        // it sets this flag and the dispatch happens here, where we
        // hold `&mut bindings`. Single-writer invariant: only this
        // worker writes its own slots.
        if vacate_all_shared_exact_slots {
            for binding in bindings.iter_mut() {
                vacate_all_shared_exact_slots_for_binding(binding);
            }
        }
        if !shaped_tx_requests.is_empty() {
            apply_worker_shaped_tx_requests(
                &mut bindings,
                forwarding.as_ref(),
                &binding_lookup,
                loop_now_ns,
                shaped_tx_requests,
                &mut shared_recycles,
            );
            apply_shared_recycles_to_bindings(&mut bindings, &binding_lookup, &mut shared_recycles);
        }
        if !cancelled_keys.is_empty() {
            for key in &cancelled_keys {
                for binding in bindings.iter_mut() {
                    cancel_queued_flow_on_binding(binding, key, key, Some(&mut shared_recycles));
                }
                apply_shared_recycles_to_bindings(
                    &mut bindings,
                    &binding_lookup,
                    &mut shared_recycles,
                );
                if let Some((decision, metadata, origin)) = sessions.entry_with_origin(key) {
                    // Demotion keeps the session in the standby table, but the
                    // stale owner must stop advertising local XSK redirect
                    // aliases immediately or XDP will keep steering packets to
                    // the old node after RG handoff.
                    delete_session_map_redirect_for_session(
                        session_map_fd,
                        key,
                        decision,
                        &metadata,
                        origin,
                    );
                }
            }
        }
        heartbeat.store(loop_now_ns, Ordering::Relaxed);
        // #2120: build the standby retention context so the wheel HOLDS
        // peer-synced sessions this node does not forward (restoring the
        // dead Go-GC `IsLocalPrimary` contract), self-heals them on RG
        // promotion (edge via rg_epochs), and reaps them at a bounded
        // ceiling if a primary delete is lost. The HA-forwarding logic
        // stays here (HAGroupRuntime's lease predicate is afxdp-private);
        // the session wheel only sees the closures + node_active.
        let ha_map = ha_runtime.as_ref();
        let rg_epochs_for_gate = &rg_epochs;
        // node_active: does this node forward at least one RG right now?
        // Excludes a standalone node (empty/all-inactive map) from ever
        // holding (mirrors session_glue's forwards-any pattern).
        let node_active = ha_map
            .values()
            .any(|group| group.is_forwarding_active(loop_now_secs));
        let forwards_rg = |rg: i32| -> bool {
            if rg > 0 {
                ha_map
                    .get(&rg)
                    .map(|group| group.is_forwarding_active(loop_now_secs))
                    .unwrap_or(false)
            } else {
                // owner_rg_id <= 0 (fabric / unresolved-owner reverse):
                // "forwards here" == the node forwards anything.
                node_active
            }
        };
        let epoch_of = |rg: i32| -> u32 {
            // A valid per-RG index uses rg_epochs[rg]; everything else
            // (rg <= 0 or out of range) uses the node-level rg_epochs[0]
            // activation edge. NOTE: this differs from the flow-cache
            // consumer guard, which maps an out-of-range owner_rg_id to
            // epoch=0 (no per-RG invalidation) rather than to
            // rg_epochs[0]. Here the rg_epochs[0] fallback is intentional
            // so the self-heal still fires for owner_rg_id == 0
            // (fabric / unresolved-owner reverse) entries.
            let idx = if rg > 0 && (rg as usize) < rg_epochs_for_gate.len() {
                rg as usize
            } else {
                0
            };
            rg_epochs_for_gate[idx].load(Ordering::Relaxed)
        };
        let ha_ctx = crate::session::ExpireHaContext {
            node_active,
            forwards_rg: &forwards_rg,
            epoch_of: &epoch_of,
            ceiling_mult: crate::session::STALE_SYNCED_CEILING_MULT,
            ceiling_abs_ns: crate::session::STALE_SYNCED_CEILING_ABS_NS,
        };
        let expired_entries = sessions.expire_stale_entries_ha(loop_now_ns, Some(&ha_ctx));
        // #2428: the "Current sessions" gauge Go derives as
        // (session_creates - session_expires) is a LOCAL-forwarding gauge.
        // `session_creates` is bumped ONLY on the four local poll-descriptor
        // install paths (ForwardFlow / ReverseFlow / LocalMiss /
        // MissingNeighborSeed). Every synced-derived origin (SyncImport /
        // SharedMaterialize / WorkerLocalImport / SharedPromote) is never
        // create-counted, so counting its expiry drives session_expires past
        // session_creates, wrapping the unsigned Go subtraction to ~1.8e19.
        // count_local_session_expiries (exhaustive match, no wildcard) counts
        // only the create-counted locals so accounting is balanced on the
        // SAME node and the standby gauge stays 0.
        let local_expired =
            count_local_session_expiries(expired_entries.iter().map(|e| e.origin));
        for expired_entry in expired_entries {
            release_source_nat_allocation(
                &forwarding.source_nat_rules,
                &expired_entry.key,
                expired_entry.decision.nat,
                expired_entry.metadata.is_reverse,
                loop_now_ns,
            );
            delete_session_map_entry_for_removed_session_with_origin(
                session_map_fd,
                &expired_entry.key,
                expired_entry.decision,
                &expired_entry.metadata,
                expired_entry.origin,
                conntrack_v4_fd,
                conntrack_v6_fd,
            );
        }
        if local_expired > 0 {
            if let Some(binding) = bindings.first() {
                binding
                    .live
                    .session_expires
                    .fetch_add(local_expired, Ordering::Relaxed);
            }
        }
        // Periodically refresh last_seen in BPF conntrack entries so Go-side
        // callers of IterateSessions (CLI, gRPC, Prometheus) see accurate
        // session idle times.  Issue #333.
        if loop_now_ns.saturating_sub(last_ct_refresh_ns) >= CT_REFRESH_INTERVAL_NS {
            last_ct_refresh_ns = loop_now_ns;
            refresh_bpf_conntrack_last_seen(
                conntrack_v4_fd,
                conntrack_v6_fd,
                &sessions,
                loop_now_ns,
            );
        }
        // Check if fabric links were updated by the coordinator (e.g. after
        // RG failover when peer MAC was resolved). If so, rebuild the
        // forwarding Arc with the new fabric links so fabric redirect works.
        {
            let live_fabrics = shared_fabrics.load();
            if !live_fabrics.is_empty() && live_fabrics.as_ref() != &forwarding.fabrics {
                let mut updated = (*forwarding).clone();
                updated.fabrics = live_fabrics.as_ref().clone();
                forwarding = Arc::new(updated);
            }
        }
        let mut did_work = false;
        let mut dbg_poll = DebugPollCounters::default();
        // #1620: read the cold-path sample mask from forwarding state once
        // per poll cycle (rather than per-binding) — it's a daemon-wide
        // setting and rarely changes. Workers load the ArcSwap-protected
        // forwarding state above so this is L1-hot.
        let cold_path_sample_mask = forwarding.cold_path_sample_mask;
        for offset in 0..bindings.len() {
            let idx = if bindings.is_empty() {
                0
            } else {
                (poll_start + offset) % bindings.len()
            };
            if poll_binding(
                idx,
                &mut bindings,
                &binding_lookup,
                mirror_targets.as_ref(),
                &mut sessions,
                &mut screen_state,
                validation,
                loop_now_ns,
                loop_now_secs,
                ha_startup_grace_until_secs,
                &forwarding,
                ha_runtime.as_ref(),
                &dynamic_neighbors,
                neighbor_resolver.as_ref(),
                &shared_sessions,
                &shared_nat_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                slow_path.as_ref(),
                event_stream.as_ref(),
                &local_tunnel_deliveries,
                &recent_exceptions,
                &recent_session_deltas,
                &last_resolution,
                &peer_worker_commands,
                worker_id,
                worker_commands_by_id.as_ref(),
                &mut shared_recycles,
                &dnat_fds,
                conntrack_v4_fd,
                conntrack_v6_fd,
                &mut dbg_poll,
                &rg_epochs,
                cold_path_sample_mask,
            ) {
                did_work = true;
            }
        }
        crate::filter::flush_recorded_filter_counters();
        #[cfg(feature = "debug-log")]
        {
            dbg.accumulate(&dbg_poll);
        }
        if !bindings.is_empty() {
            poll_start = (poll_start + 1) % bindings.len();
        }
        if loop_now_ns.saturating_sub(last_cos_status_ns) >= COS_STATUS_INTERVAL_NS {
            cos_status.store(Arc::new(build_worker_cos_statuses(
                &bindings,
                forwarding.as_ref(),
                loop_now_ns,
            )));
            last_cos_status_ns = loop_now_ns;
        }
        // #2442: loss-of-sync resync. If `push_delta` dropped any delta since
        // the last drain, the in-worker session-delta ring overflowed and the
        // downstream session-sync consumer missed HA-relevant open/close
        // events — its view may have silently diverged from the table truth.
        // Re-emit an open delta for every owned forward session (the same
        // table-truth walk `ExportOwnerRGSessions` performs) so the peer
        // re-derives a complete snapshot. The latch is read-and-cleared, so a
        // sustained overflow raises one resync per drain cycle, not per dropped
        // delta. We first drain the backlog to make room, then export; the
        // standard drain/flush block below ships the freshly-emitted deltas.
        if sessions.take_delta_loss() {
            // Drain (and flush) the existing backlog so the ring has headroom
            // for the full export — otherwise the export's own pushes would
            // immediately re-overflow and re-arm the latch.
            while sessions.has_pending_deltas() {
                let deltas = sessions.drain_deltas(256);
                purge_queued_flows_for_closed_deltas(
                    &mut bindings,
                    &binding_lookup,
                    &mut shared_recycles,
                    &deltas,
                );
                if let Some(binding) = bindings.first() {
                    let ident = binding.identity();
                    flush_session_deltas(
                        &ident,
                        &binding.live,
                        binding.bpf_maps.session_map_fd,
                        conntrack_v4_fd,
                        conntrack_v6_fd,
                        &deltas,
                        &shared_sessions,
                        &shared_nat_sessions,
                        &shared_forward_wire_sessions,
                        &shared_owner_rg_indexes,
                        &recent_session_deltas,
                        &peer_worker_commands,
                        &event_stream,
                        forwarding.as_ref(),
                    );
                }
            }
            let owner_rgs = sessions.all_owner_rg_ids();
            if !owner_rgs.is_empty() {
                crate::afxdp::export_forward_sessions_for_owner_rgs(&mut sessions, &owner_rgs);
            }
        }
        if !exported_sequences.is_empty() {
            while sessions.has_pending_deltas() {
                let deltas = sessions.drain_deltas(256);
                purge_queued_flows_for_closed_deltas(
                    &mut bindings,
                    &binding_lookup,
                    &mut shared_recycles,
                    &deltas,
                );
                if let Some(binding) = bindings.first() {
                    let ident = binding.identity();
                    flush_session_deltas(
                        &ident,
                        &binding.live,
                        binding.bpf_maps.session_map_fd,
                        conntrack_v4_fd,
                        conntrack_v6_fd,
                        &deltas,
                        &shared_sessions,
                        &shared_nat_sessions,
                        &shared_forward_wire_sessions,
                        &shared_owner_rg_indexes,
                        &recent_session_deltas,
                        &peer_worker_commands,
                        &event_stream,
                        forwarding.as_ref(),
                    );
                }
            }
            if let Some(sequence) = exported_sequences.iter().copied().max() {
                session_export_ack.store(sequence, Ordering::Release);
            }
        } else if sessions.has_pending_deltas() {
            let deltas = sessions.drain_deltas(256);
            purge_queued_flows_for_closed_deltas(
                &mut bindings,
                &binding_lookup,
                &mut shared_recycles,
                &deltas,
            );
            if let Some(binding) = bindings.first() {
                let ident = binding.identity();
                flush_session_deltas(
                    &ident,
                    &binding.live,
                    binding.bpf_maps.session_map_fd,
                    conntrack_v4_fd,
                    conntrack_v6_fd,
                    &deltas,
                    &shared_sessions,
                    &shared_nat_sessions,
                    &shared_forward_wire_sessions,
                    &shared_owner_rg_indexes,
                    &recent_session_deltas,
                    &peer_worker_commands,
                    &event_stream,
                    forwarding.as_ref(),
                );
            }
        }
        // Debug: periodic summary report
        {
            let elapsed = loop_now_ns.saturating_sub(dbg_last_report_ns);
            if elapsed >= DBG_REPORT_INTERVAL_NS {
                #[cfg(feature = "debug-log")]
                let session_count = sessions.len();
                let mut binding_summary = String::new();
                for (i, b) in bindings.iter().enumerate() {
                    use std::fmt::Write;
                    let fill_pending = b.xsk.device.pending();
                    let rx_avail = b.xsk.rx.available_relaxed();
                    let xsk_stats = b.xsk.device.statistics_v2().ok();
                    let inflight_recycles = b.tx_pipeline.in_flight_prepared_recycles.len() as u32;
                    let scratch_recycle_len = b.scratch.scratch_recycle.len() as u32;
                    let ptx_prepared = b.tx_pipeline.pending_tx_prepared.len() as u32;
                    let ptx_local = b.tx_pipeline.pending_tx_local.len() as u32;
                    let total_accounted = b.tx_pipeline.pending_fill_frames.len() as u32
                        + fill_pending
                        + rx_avail
                        + b.tx_pipeline.free_tx_frames.len() as u32
                        + b.tx_pipeline.outstanding_tx
                        + inflight_recycles
                        + scratch_recycle_len
                        + ptx_prepared; // prepared TX holds UMEM frames
                    let expected_total = b.umem.total_frames();
                    let _ = write!(
                        binding_summary,
                        " [{}:if{}q{} pfill={} fring={} rxring={} free_tx={} otx={} ifl={} scr={} ptxp={} ptxl={} total={}/{} fill_ok={} polls={} bp={} rx_empty={} wake={}",
                        i,
                        b.ifindex,
                        b.queue_id,
                        b.tx_pipeline.pending_fill_frames.len(),
                        fill_pending,
                        rx_avail,
                        b.tx_pipeline.free_tx_frames.len(),
                        b.tx_pipeline.outstanding_tx,
                        inflight_recycles,
                        scratch_recycle_len,
                        ptx_prepared,
                        ptx_local,
                        total_accounted,
                        expected_total,
                        b.telemetry.dbg_fill_submitted,
                        b.telemetry.dbg_poll_cycles,
                        b.telemetry.dbg_backpressure,
                        b.telemetry.dbg_rx_empty,
                        b.telemetry.dbg_rx_wakeups,
                    );
                    // TX pipeline debug counters
                    #[cfg(feature = "debug-log")]
                    {
                        dbg.tx_tcp_rst += b.telemetry.dbg_tx_tcp_rst;
                    }
                    let _ = write!(
                        binding_summary,
                        " TX:ring_sub={}/ring_full={}/compl={}/sendto={}/err={}/eagain={}/enobufs={}/bp_overflow={}/cos_overflow={}",
                        b.telemetry.dbg_tx_ring_submitted,
                        b.telemetry.dbg_tx_ring_full,
                        b.telemetry.dbg_completions_reaped,
                        b.telemetry.dbg_sendto_calls,
                        b.telemetry.dbg_sendto_err,
                        b.telemetry.dbg_sendto_eagain,
                        b.telemetry.dbg_sendto_enobufs,
                        b.telemetry.dbg_bound_pending_overflow,
                        b.telemetry.dbg_cos_queue_overflow,
                    );
                    #[cfg(feature = "debug-log")]
                    let _ = write!(binding_summary, "/rst={}", b.telemetry.dbg_tx_tcp_rst);
                    if let Some(s) = xsk_stats {
                        let _ = write!(
                            binding_summary,
                            " xsk:drop={}/inv={}/rfull={}/fempty={}/tinv={}/tempty={}",
                            s.rx_dropped,
                            s.rx_invalid_descs,
                            s.rx_ring_full,
                            s.rx_fill_ring_empty_descs,
                            s.tx_invalid_descs,
                            s.tx_ring_empty_descs,
                        );
                    }
                    // Socket error check (SO_ERROR) — detect kernel-side errors
                    {
                        let fd = b.xsk.rx.as_raw_fd();
                        let mut so_err: c_int = 0;
                        let mut so_err_len: libc::socklen_t = core::mem::size_of::<c_int>() as _;
                        let rc = unsafe {
                            libc::getsockopt(
                                fd,
                                libc::SOL_SOCKET,
                                libc::SO_ERROR,
                                &mut so_err as *mut c_int as *mut c_void,
                                &mut so_err_len,
                            )
                        };
                        if rc == 0 && so_err != 0 {
                            let _ = write!(binding_summary, " SO_ERR={so_err}");
                        }
                    }
                    // Ring diagnostics from xsk_ffi API
                    if cfg!(feature = "debug-log") {
                        let _ = write!(
                            binding_summary,
                            " RING:rx_nz={}/rx_max={}/fill_pend={}/dev_avail={} RX_WAKE:ok={}/err={}/errno={}",
                            b.telemetry.dbg_rx_avail_nonzero,
                            b.telemetry.dbg_rx_avail_max,
                            b.telemetry.dbg_fill_pending,
                            b.telemetry.dbg_device_avail,
                            b.telemetry.dbg_rx_wake_sendto_ok,
                            b.telemetry.dbg_rx_wake_sendto_err,
                            b.telemetry.dbg_rx_wake_sendto_errno,
                        );
                        // Direct mmap diagnosis: read raw ring producer/consumer
                        if let Some((rxp, rxc, frp, frc, txp, txc, crp, crc)) =
                            diagnose_raw_ring_state(b.xsk.rx.as_raw_fd())
                        {
                            let _ = write!(
                                binding_summary,
                                " RAW:rxP={rxp}/rxC={rxc}/frP={frp}/frC={frc}/txP={txp}/txC={txc}/crP={crp}/crC={crc}"
                            );
                        }
                    }
                    // Frame leak detection
                    if total_accounted != expected_total {
                        let _ = write!(
                            binding_summary,
                            " FRAME_LEAK:{}",
                            expected_total as i64 - total_accounted as i64,
                        );
                    }
                    binding_summary.push(']');
                }
                // #1776: the cfg(debug-log) verbose per-second report —
                // the giant DBG summary eprintln + degraded-path dump —
                // lives in debug_report.rs. Release builds skip it, as
                // before (the eprintln was already cfg-gated; the
                // always-on binding_summary build above is unchanged).
                #[cfg(feature = "debug-log")]
                debug_report::emit_periodic_report(
                    worker_id,
                    elapsed,
                    &dbg,
                    session_count,
                    &bindings,
                    &binding_summary,
                );
                // Save prev counters BEFORE reset for stall detection below
                #[cfg(feature = "debug-log")]
                let (prev_rx_total, prev_fwd_total) = (dbg.rx_total, dbg.forward_total);
                dbg_last_report_ns = loop_now_ns;
                // #1776 (plan v3.1 AGY CORRECTNESS-1 guard): DbgCounters
                // holds ONLY per-interval counters, so this single-line
                // reset must NOT touch the persistent debug state —
                // dbg_last_report_ns (re-armed above) and the cross-
                // interval stall baselines stall_prev_fwd /
                // stall_reported, which live in plain locals; the
                // same-interval prev_rx_total / prev_fwd_total snapshot
                // was taken from `dbg` above, BEFORE this reset.
                #[cfg(feature = "debug-log")]
                {
                    dbg = debug_report::DbgCounters::default();
                }
                // Stall detection: stall_prev_fwd is PREVIOUS interval's fwd count,
                // prev_fwd_total is THIS interval's fwd count (saved before reset).
                #[cfg(feature = "debug-log")]
                debug_report::check_and_dump_stall(
                    worker_id,
                    prev_rx_total,
                    prev_fwd_total,
                    &mut stall_prev_fwd,
                    &mut stall_reported,
                    session_count,
                    &bindings,
                    &sessions,
                );
                for b in bindings.iter_mut() {
                    // #802: publish ring-pressure counters into BindingLiveState
                    // BEFORE resetting the worker-local window. The worker-local
                    // counters (b.telemetry.dbg_tx_ring_full, etc.) are accumulated by the
                    // hot path and reset each ~1s debug tick; without this
                    // publish they'd never be visible outside the worker thread.
                    // fetch_add is used because the atomic holds the cumulative
                    // total while the local counter holds only the current
                    // window. Relaxed is sufficient — diagnostic counters, no
                    // synchronization contract.
                    if b.telemetry.dbg_tx_ring_full != 0 {
                        b.live
                            .dbg_tx_ring_full
                            .fetch_add(b.telemetry.dbg_tx_ring_full, Ordering::Relaxed);
                    }
                    if b.telemetry.dbg_sendto_enobufs != 0 {
                        b.live
                            .dbg_sendto_enobufs
                            .fetch_add(b.telemetry.dbg_sendto_enobufs, Ordering::Relaxed);
                    }
                    if b.telemetry.dbg_bound_pending_overflow != 0 {
                        b.live
                            .dbg_bound_pending_overflow
                            .fetch_add(b.telemetry.dbg_bound_pending_overflow, Ordering::Relaxed);
                    }
                    if b.telemetry.dbg_cos_queue_overflow != 0 {
                        b.live
                            .dbg_cos_queue_overflow
                            .fetch_add(b.telemetry.dbg_cos_queue_overflow, Ordering::Relaxed);
                    }
                    // #802: kernel xdp_statistics.rx_fill_ring_empty_descs is
                    // already absolute (kernel-cumulative), so publish with
                    // store() not fetch_add. Sampling failures are silently
                    // ignored — the atomic simply retains its last good value.
                    if let Ok(stats) = b.xsk.device.statistics_v2() {
                        b.live
                            .rx_fill_ring_empty_descs
                            .store(stats.rx_fill_ring_empty_descs, Ordering::Relaxed);
                    }
                    // #802: outstanding_tx is a transient gauge on
                    // BindingWorker.tx_pipeline (current in-flight TX).
                    // Publish to the existing atomic mirror on
                    // BindingLiveState so the snapshot reader sees a
                    // recent value. store() because it's a gauge, not a
                    // counter. (#959 Phase 10 moved the field from
                    // BindingWorker to WorkerTxPipeline.)
                    b.live
                        .debug_outstanding_tx
                        .store(b.tx_pipeline.outstanding_tx, Ordering::Relaxed);
                    publish_tx_completion_ring_telemetry(&b.live, &mut b.telemetry);
                    // #878: publish UMEM in-flight gauge as a single atomic
                    // so the daemon's `show chassis forwarding` Buffer% can
                    // divide by `umem_total_frames` without torn-load risk.
                    // Computed in this thread from worker-local state, so
                    // the inputs are mutually consistent at sample time.
                    //
                    // "Idle" frames are: free_tx_frames (worker's TX-available
                    // pool), pending_fill_frames (worker's queue waiting to
                    // push to the kernel's fill ring), AND fill_pending (the
                    // kernel's fill ring itself, which holds frames the
                    // kernel can place RX data into — those are NOT in
                    // flight). Without subtracting fill_pending the gauge
                    // reads ~70-80% at idle because AF_XDP keeps the fill
                    // ring pre-populated by design.
                    let total = b.umem.total_frames();
                    let free_tx = b.tx_pipeline.free_tx_frames.len() as u32;
                    let pending_fill = b.tx_pipeline.pending_fill_frames.len() as u32;
                    let kernel_fill = b.xsk.device.pending();
                    let inflight = total
                        .saturating_sub(free_tx)
                        .saturating_sub(pending_fill)
                        .saturating_sub(kernel_fill);
                    b.live
                        .umem_inflight_frames
                        .store(inflight, Ordering::Relaxed);

                    b.telemetry.dbg_fill_submitted = 0;
                    b.telemetry.dbg_fill_failed = 0;
                    b.telemetry.dbg_poll_cycles = 0;
                    b.telemetry.dbg_backpressure = 0;
                    b.telemetry.dbg_rx_empty = 0;
                    b.telemetry.dbg_rx_wakeups = 0;
                    b.telemetry.dbg_tx_ring_submitted = 0;
                    b.telemetry.dbg_tx_ring_full = 0;
                    b.telemetry.dbg_completions_reaped = 0;
                    b.telemetry.dbg_sendto_calls = 0;
                    b.telemetry.dbg_sendto_err = 0;
                    b.telemetry.dbg_sendto_eagain = 0;
                    b.telemetry.dbg_sendto_enobufs = 0;
                    b.telemetry.dbg_bound_pending_overflow = 0;
                    b.telemetry.dbg_cos_queue_overflow = 0;
                    #[cfg(feature = "debug-log")]
                    {
                        b.telemetry.dbg_tx_tcp_rst = 0;
                    }
                    b.telemetry.dbg_rx_avail_nonzero = 0;
                    b.telemetry.dbg_rx_avail_max = 0;
                    b.telemetry.dbg_rx_wake_sendto_ok = 0;
                    b.telemetry.dbg_rx_wake_sendto_err = 0;
                    b.telemetry.dbg_rx_wake_sendto_errno = 0;
                }
            }
        }
        if did_work {
            idle_iters = 0;
            // #869: classify this iteration for next-loop-top accounting.
            wr_state = WorkerRuntimeState::Active;
            wr_counters.work_loops = wr_counters.work_loops.wrapping_add(1);
            continue;
        }
        idle_iters = idle_iters.saturating_add(1);
        wr_counters.idle_loops = wr_counters.idle_loops.wrapping_add(1);
        match poll_mode {
            crate::PollMode::BusyPoll => {
                if idle_iters <= IDLE_SPIN_ITERS {
                    wr_state = WorkerRuntimeState::IdleSpin;
                    std::hint::spin_loop();
                } else {
                    wr_state = WorkerRuntimeState::IdleBlock;
                    thread::sleep(Duration::from_micros(IDLE_SLEEP_US));
                }
            }
            crate::PollMode::Interrupt => {
                // Interrupt mode still needs a short local spin before blocking.
                // Firewall-local TCP flows are ACK-latency-sensitive; blocking
                // immediately on the first empty poll collapses cwnd badly.
                if idle_iters <= IDLE_SPIN_ITERS {
                    wr_state = WorkerRuntimeState::IdleSpin;
                    std::hint::spin_loop();
                } else if !interrupt_poll_fds.is_empty() {
                    wr_state = WorkerRuntimeState::IdleBlock;
                    for pfd in &mut interrupt_poll_fds {
                        pfd.revents = 0;
                    }
                    unsafe {
                        libc::poll(
                            interrupt_poll_fds.as_mut_ptr(),
                            interrupt_poll_fds.len() as libc::nfds_t,
                            INTERRUPT_POLL_TIMEOUT_MS,
                        );
                    }
                } else {
                    wr_state = WorkerRuntimeState::IdleBlock;
                    thread::sleep(Duration::from_millis(INTERRUPT_POLL_TIMEOUT_MS as u64));
                }
            }
        }
    }
    crate::filter::flush_recorded_filter_counters();
    for binding in bindings.iter_mut() {
        clear_all_cos_exact_backlogs_for_binding(binding);
        release_all_cos_root_leases(binding);
        release_all_cos_queue_leases(binding);
    }
    cos_status.store(Arc::new(build_worker_cos_statuses(
        &bindings,
        forwarding.as_ref(),
        monotonic_nanos(),
    )));
    heartbeat.store(monotonic_nanos(), Ordering::Relaxed);
}

/// #2428: count only the create-counted LOCAL-origin expired sessions for
/// the `session_expires` counter (which the Go control plane reads as
/// `GlobalCtrSessionsClosed`).
///
/// `session_creates` is bumped ONLY on the four local poll-descriptor install
/// paths — `ForwardFlow` / `ReverseFlow` / `LocalMiss` /
/// `MissingNeighborSeed`. Every other origin is synced-derived and never
/// create-counted:
///   - `SyncImport` / `SharedMaterialize` / `WorkerLocalImport` — installed
///     via the HA sync path (`upsert_synced_with_origin` /
///     `WorkerCommand::UpsertLocal`);
///   - `SharedPromote` — a re-tag of an already-synced (uncounted) entry by
///     `maybe_promote_synced_session` (`session_glue/promote.rs`); its
///     `promote_synced_with_origin` install does NOT touch `session_creates`.
///     `is_peer_synced()` returns FALSE for `SharedPromote`, so an earlier
///     `!is_peer_synced()` filter would have COUNTED a promote expiry that
///     was never create-counted — re-introducing the underflow on a node
///     that promotes synced sessions post-failover. `shared_ops.rs` already
///     groups `SharedPromote` with the peer-synced set for the wire-alias
///     contract; this counter is consistent with that.
///
/// Counting any non-create-counted origin's expiry inflates `session_expires`
/// past `session_creates`, wrapping the unsigned Go subtraction
/// `session_creates - session_expires` to ~1.8e19. We therefore match on the
/// EXACT complement of the create-counted set via an exhaustive `match` (NO
/// wildcard) so a future 9th `SessionOrigin` variant forces a compile-time
/// decision here rather than silently defaulting to "counted". The Go-side
/// `dataplane.CurrentSessions` saturating floor is the defense-in-depth
/// backstop.
fn count_local_session_expiries(
    origins: impl Iterator<Item = crate::session::SessionOrigin>,
) -> u64 {
    use crate::session::SessionOrigin;
    origins
        .filter(|o| match o {
            // The four create-counted local install paths: count their expiry.
            SessionOrigin::ForwardFlow
            | SessionOrigin::ReverseFlow
            | SessionOrigin::LocalMiss
            | SessionOrigin::MissingNeighborSeed => true,
            // Synced-derived, never create-counted: must NOT be expire-counted.
            SessionOrigin::SyncImport
            | SessionOrigin::SharedMaterialize
            | SessionOrigin::SharedPromote
            | SessionOrigin::WorkerLocalImport => false,
        })
        .count() as u64
}

#[cfg(test)]
mod expiry_count_tests {
    use super::count_local_session_expiries;
    use crate::session::SessionOrigin;

    #[test]
    fn local_origin_expiries_are_counted() {
        let origins = [
            SessionOrigin::ForwardFlow,
            SessionOrigin::ReverseFlow,
            SessionOrigin::LocalMiss,
            SessionOrigin::MissingNeighborSeed,
        ];
        assert_eq!(count_local_session_expiries(origins.into_iter()), 4);
    }

    #[test]
    fn synced_derived_expiries_are_not_counted() {
        // #2428: the standby (and any node) reaps synced-derived sessions it
        // never create-counted. None of these may bump session_expires, or
        // the Go-derived `session_creates - session_expires` underflows to a
        // wrapped u64. ALL FOUR synced-derived origins must be excluded —
        // including SharedPromote, whose is_peer_synced() returns false.
        let origins = [
            SessionOrigin::SyncImport,
            SessionOrigin::SharedMaterialize,
            SessionOrigin::WorkerLocalImport,
            SessionOrigin::SharedPromote,
        ];
        assert_eq!(
            count_local_session_expiries(origins.into_iter()),
            0,
            "synced-derived expiries must not bump session_expires (would \
             underflow the Current-sessions gauge)"
        );
    }

    #[test]
    fn shared_promote_expiry_is_not_counted() {
        // #2428 review fold: SharedPromote is a re-tag of an already-synced
        // (uncounted) entry — promote_synced_with_origin does NOT bump
        // session_creates. is_peer_synced() returns FALSE for it, so the
        // earlier `!is_peer_synced()` filter wrongly COUNTED a promote
        // expiry, re-introducing the underflow on a promoting node.
        // fail-on-revert: restoring `!o.is_peer_synced()` makes this case
        // return 1 instead of 0.
        assert_eq!(
            count_local_session_expiries([SessionOrigin::SharedPromote].into_iter()),
            0,
            "a SharedPromote expiry must NOT bump session_expires (never \
             create-counted)"
        );
    }

    #[test]
    fn mixed_batch_counts_only_create_counted_locals() {
        let origins = [
            SessionOrigin::ForwardFlow,       // local: +1
            SessionOrigin::SyncImport,        // synced: 0
            SessionOrigin::ReverseFlow,       // local: +1
            SessionOrigin::SharedMaterialize, // synced: 0
            SessionOrigin::WorkerLocalImport, // synced: 0
            SessionOrigin::SharedPromote,     // synced: 0
        ];
        assert_eq!(count_local_session_expiries(origins.into_iter()), 2);
    }

    #[test]
    fn taxonomy_is_eight_variants() {
        // #2428: pin the SessionOrigin taxonomy at 8. The exhaustive match in
        // count_local_session_expiries (no wildcard) already forces a
        // compile-time decision on a new variant; this enumerates every
        // variant and asserts it classifies exactly once into local (4) or
        // synced-derived (4). A 9th variant breaks BOTH the match (compile
        // error) and this count (8 -> 9) — a loud double signal.
        let all = [
            SessionOrigin::ForwardFlow,
            SessionOrigin::ReverseFlow,
            SessionOrigin::LocalMiss,
            SessionOrigin::MissingNeighborSeed,
            SessionOrigin::SyncImport,
            SessionOrigin::SharedMaterialize,
            SessionOrigin::SharedPromote,
            SessionOrigin::WorkerLocalImport,
        ];
        assert_eq!(all.len(), 8, "SessionOrigin taxonomy is 8 variants");
        // Exactly the four create-counted locals are counted.
        assert_eq!(count_local_session_expiries(all.into_iter()), 4);
    }
}
