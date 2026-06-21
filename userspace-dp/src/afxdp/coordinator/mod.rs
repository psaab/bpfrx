use super::*;
mod bpf_maps;
mod cos_leases;
mod cos_state;
mod ha_state;
mod inject;
mod neighbor_manager;
mod reconcile;
mod refresh_bindings;
mod session_manager;
mod snapshot_refresh;
mod status;
mod supervisor;
mod tunnel_supervision;
mod wg_control;
mod worker_manager;
pub(crate) use bpf_maps::BpfMaps;
// #1890: re-import the split-out CoS builders at coordinator scope so
// pre-split references keep resolving unchanged — `status.rs` and
// `tests.rs` reach them through `use super::*`, and
// `reconcile/bringup.rs` through `super::super::` paths.
use cos_leases::{
    aggregate_cos_statuses_across_workers,
    build_cos_active_shards_by_egress_ifindex_with_fallback_ifindexes,
    build_cos_owner_worker_by_queue,
};
// #1890: these builders' only out-of-file consumers are `tests.rs`
// fixtures — gate the re-import so release builds don't carry an
// unused-imports warning.
#[cfg(test)]
use cos_leases::{
    build_cos_owner_worker_by_queue_from_binding_ifindexes,
    build_cos_owner_worker_by_queue_with_fallback_ifindexes,
    build_shared_cos_queue_leases_reusing_existing,
    build_shared_cos_queue_vtime_floors_reusing_existing, build_shared_cos_root_leases,
    build_shared_cos_root_leases_reusing_existing, build_worker_binding_ifindexes_from_identities,
    unique_interface_owner_worker_id,
};
pub(crate) use cos_state::SharedCoSState;
pub(in crate::afxdp) use ha_state::HaState;
pub(crate) use neighbor_manager::NeighborManager;
pub(crate) use neighbor_manager::WarmItem;
pub(in crate::afxdp) use neighbor_manager::{
    WARM_GC_INTERVAL_NS, WARM_GC_MAX_AGE_NS, WARM_PER_KEY_RATE_LIMIT_NS, WARM_QUEUE_DEPTH,
    WARM_SWEEP_RATE_LIMIT_NS,
};
pub(in crate::afxdp) use session_manager::SessionManager;
use supervisor::spawn_supervised_aux;
pub(in crate::afxdp) use worker_manager::WorkerManager;

/// #1866 D3: canonical `id:port@ifindex` summary of a forwarding
/// state's WireGuard endpoint set, for transition logging.
fn wg_endpoint_set_summary(state: &ForwardingState) -> String {
    let mut parts: Vec<String> = state
        .tunnel_endpoints
        .values()
        .filter(|ep| ep.mode == "wireguard")
        .map(|ep| format!("{}:{}@{}", ep.id, ep.wg_listen_port, ep.logical_ifindex))
        .collect();
    parts.sort();
    parts.join(",")
}

/// #1873 R-D: ids whose owner changed across a snapshot apply — absent
/// in `next`, present with a DIFFERENT logical interface name, or
/// NEWLY APPEARING in `next` (absent in `previous` — Codex code r2:
/// an id with no owner in the previous state cannot have a
/// legitimately live session, so any entry still storing it — e.g. a
/// synced copy installed with an unresolvable id during an HA config
/// skew — predates `previous` and must be purged before the new
/// owner's row becomes reachable). Compared on the LOGICAL config
/// name (never linux_name — a cosmetic kernel rename must not purge
/// sessions).
///
/// `include_new_appearances` must be FALSE for the first snapshot
/// apply of a helper's life (previous state is the pristine default):
/// there every configured id "appears", and purging would wipe
/// legitimately synced sessions installed before the first apply.
pub(in crate::afxdp) fn tunnel_remap_purge_ids(
    previous: &ForwardingState,
    next: &ForwardingState,
    include_new_appearances: bool,
) -> Vec<u16> {
    let owners: Vec<(u16, String)> = previous
        .tunnel_endpoints
        .iter()
        .map(|(id, ep)| (*id, ep.interface.clone()))
        .collect();
    tunnel_remap_purge_ids_from_owners(&owners, next, include_new_appearances)
}

/// #1873 R-D (AGY code r3): owners-list flavor for the reconcile path,
/// where `stop_inner(false)` has already defaulted `coord.forwarding`
/// and the diff baseline must be the owner map captured before
/// teardown.
pub(in crate::afxdp) fn tunnel_remap_purge_ids_from_owners(
    prior_owners: &[(u16, String)],
    next: &ForwardingState,
    include_new_appearances: bool,
) -> Vec<u16> {
    let mut purge_ids: Vec<u16> = Vec::new();
    for (id, prev_interface) in prior_owners {
        match next.tunnel_endpoints.get(id) {
            None => purge_ids.push(*id),
            Some(next_ep) if next_ep.interface != *prev_interface => purge_ids.push(*id),
            Some(_) => {}
        }
    }
    if include_new_appearances {
        for id in next.tunnel_endpoints.keys() {
            if !prior_owners.iter().any(|(prev_id, _)| prev_id == id) {
                purge_ids.push(*id);
            }
        }
    }
    purge_ids
}

/// #1873 R-D (AGY code r4): filter the preserved synced-session replay
/// list by the remap purge set, MIRRORING delete_synced_session's
/// companion semantics — drop every entry whose stored id is purged,
/// plus the derived reverse companion (reverse_session_key over the
/// forward key + NAT decision) of each dropped FORWARD entry, which
/// itself carries tunnel_endpoint_id == 0 in asymmetric topologies and
/// would otherwise be resurrected as a half-dead pair by the bringup
/// replay. A reverse-marked entry drops standalone (its unmarked
/// forward keeps forwarding without the tunnel), matching the live
/// purge's delete_synced_session(is_reverse) behavior.
pub(in crate::afxdp) fn filter_replayed_synced_sessions(
    entries: &mut Vec<SyncedSessionEntry>,
    purge_ids: &[u16],
) {
    if purge_ids.is_empty() || entries.is_empty() {
        return;
    }
    let mut drop_keys: Vec<crate::session::SessionKey> = Vec::new();
    for entry in entries.iter() {
        let id = entry.decision.resolution.tunnel_endpoint_id;
        if id != 0 && purge_ids.contains(&id) {
            drop_keys.push(entry.key.clone());
            if !entry.metadata.is_reverse {
                drop_keys.push(crate::session::reverse_session_key(
                    &entry.key,
                    entry.decision.nat,
                ));
            }
        }
    }
    if !drop_keys.is_empty() {
        entries.retain(|entry| !drop_keys.contains(&entry.key));
    }
}

/// #1866 D3: log a WG endpoint-set transition between two forwarding
/// states. Silent when the set is unchanged (the common case) — fires
/// only on real add/remove/port/attachment changes, so the cadence is
/// state-transition-only per the logging rules.
pub(in crate::afxdp) fn log_wg_endpoint_set_transition(
    path: &str,
    old: &ForwardingState,
    new: &ForwardingState,
) {
    let old_set = wg_endpoint_set_summary(old);
    let new_set = wg_endpoint_set_summary(new);
    if old_set != new_set {
        eprintln!("xpf-userspace-dp: WG endpoint set changed ({path}): [{old_set}] => [{new_set}]");
    }
}

pub struct Coordinator {
    pub(crate) bpf_maps: BpfMaps,
    pub(crate) slow_path: Option<Arc<SlowPathReinjector>>,
    pub(crate) local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    /// #1881: GRE local-origin thread lifecycle entries keyed by
    /// tunnel_endpoint_id. Reconciled by the same three-pass shape as
    /// `wg_control_threads` (finished sweep → attachment-stale prune →
    /// spawn with backoff); content changes never restart a thread —
    /// the loop tracks the shared forwarding ArcSwap (plan D.1).
    pub(crate) tunnel_sources: BTreeMap<u16, LocalTunnelSourceEntry>,
    /// #1432 S2a / #1866: WG control-thread lifecycle entries keyed by
    /// tunnel_endpoint_id. Each entry records the engine Arc address +
    /// TUN attachment the thread was spawned with (so the apply-time
    /// stale prune detects identity AND attachment changes), survives
    /// thread exit as a tombstone carrying the respawn backoff stamp,
    /// and is removed only when the endpoint leaves the desired set.
    pub(crate) wg_control_threads: BTreeMap<u16, WgControlEntry>,
    pub(crate) last_slow_path_status: SlowPathStatus,
    pub(in crate::afxdp) ha: HaState,
    pub(crate) cos: SharedCoSState,
    pub(crate) shared_validation: Arc<ArcSwap<ValidationState>>,
    pub(crate) neighbors: NeighborManager,
    pub(in crate::afxdp) sessions: SessionManager,
    pub(in crate::afxdp) workers: WorkerManager,
    pub(crate) mirror_targets: Arc<ArcSwap<MirrorTargetMap>>,
    pub(crate) forwarding: ForwardingState,
    pub(crate) policy_counters: PolicyCounterStore,
    /// #2218: per-rule NAT translation hit counters (SNAT/DNAT/static),
    /// owned alongside `policy_counters` and threaded into the
    /// forwarding-state build so parsed rules share its `Arc`s.
    pub(crate) nat_counters: crate::nat::NatCounterStore,
    pub(crate) recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    pub(crate) recent_session_deltas: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    pub(crate) last_resolution: Arc<Mutex<Option<PacketResolution>>>,
    pub(crate) validation: ValidationState,
    pub(crate) reconcile_calls: u64,
    pub(crate) last_reconcile_stage: String,
    pub(crate) poll_mode: crate::PollMode,
    pub(crate) event_stream: Option<crate::event_stream::EventStreamSender>,
    pub(crate) cos_owner_worker_by_queue: BTreeMap<(i32, u8), u32>,
    /// Monotonic timestamp (secs) of the last HA flow cache flush (#312).
    pub(crate) last_cache_flush_at: Arc<AtomicU64>,
    /// Per-RG epoch counters for O(1) flow cache invalidation on demotion.
    /// Shared with all worker threads; bumped atomically on demotion/activation.
    pub(crate) rg_epochs: Arc<[AtomicU32; MAX_RG_EPOCHS]>,
    /// #925 Phase 1: panic-payload slot per worker, keyed by `worker_id`.
    /// `BTreeMap` (not `Vec`) so non-contiguous or reused worker IDs map
    /// stably; written exactly once when the worker dies, read at most
    /// once per gRPC status poll (~1 Hz). Not on the packet hot path.
    pub(crate) worker_panics: BTreeMap<u32, Arc<Mutex<Option<String>>>>,
}

impl Coordinator {
    pub fn new() -> Self {
        Self {
            bpf_maps: BpfMaps::default(),
            slow_path: None,
            local_tunnel_deliveries: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            tunnel_sources: BTreeMap::new(),
            wg_control_threads: BTreeMap::new(),
            last_slow_path_status: SlowPathStatus::default(),
            ha: HaState::new(),
            cos: SharedCoSState::new(),
            shared_validation: Arc::new(ArcSwap::from_pointee(ValidationState::default())),
            neighbors: NeighborManager::new(),
            sessions: SessionManager::new(),
            workers: WorkerManager::new(),
            mirror_targets: Arc::new(ArcSwap::from_pointee(MirrorTargetMap::default())),
            forwarding: ForwardingState::default(),
            policy_counters: PolicyCounterStore::default(),
            nat_counters: crate::nat::NatCounterStore::default(),
            recent_exceptions: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_RECENT_EXCEPTIONS))),
            recent_session_deltas: Arc::new(Mutex::new(VecDeque::with_capacity(
                MAX_RECENT_SESSION_DELTAS,
            ))),
            last_resolution: Arc::new(Mutex::new(None)),
            validation: ValidationState::default(),
            reconcile_calls: 0,
            last_reconcile_stage: "idle".to_string(),
            poll_mode: crate::PollMode::BusyPoll,
            event_stream: None,
            cos_owner_worker_by_queue: BTreeMap::new(),
            last_cache_flush_at: Arc::new(AtomicU64::new(0)),
            rg_epochs: Arc::new(std::array::from_fn(|_| AtomicU32::new(0))),
            worker_panics: BTreeMap::new(),
        }
    }

    pub fn stop(&mut self) {
        self.stop_inner(true);
        // NOTE: Do NOT tear down event_stream here. The event stream must
        // survive across XSK bind/unbind cycles (e.g. when forwarding_armed
        // is temporarily false during startup). Use stop_with_event_stream()
        // for final process shutdown.
    }

    /// Full shutdown including the event stream. Called only on process exit.
    pub fn stop_with_event_stream(&mut self) {
        self.stop_inner(true);
        if let Some(mut es) = self.event_stream.take() {
            es.stop();
        }
    }

    /// Start the event stream sender. The I/O thread connects to the daemon
    /// listener at `socket_path` and pushes binary-framed session events.
    pub fn start_event_stream(&mut self, socket_path: &str) {
        self.event_stream = Some(crate::event_stream::EventStreamSender::new(socket_path));
    }

    /// Get a lightweight handle for worker threads to push events.
    pub fn event_stream_worker_handle(
        &self,
    ) -> Option<crate::event_stream::EventStreamWorkerHandle> {
        self.event_stream.as_ref().map(|es| es.worker_handle())
    }

    /// Event stream statistics for status reporting.
    pub fn event_stream_stats(&self) -> Option<crate::event_stream::EventStreamStats> {
        self.event_stream.as_ref().map(|es| es.stats())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn dynamic_neighbors_ref(&self) -> &Arc<ShardedNeighborMap> {
        &self.neighbors.dynamic
    }

    /// #919: zone name → ID lookup, used by main.rs's
    /// `build_synced_session_entry` to translate legacy
    /// `SessionSyncRequest.ingress_zone` strings to u16 IDs when
    /// older peers don't populate the new ID fields.
    pub fn zone_name_to_id_ref(&self) -> &FastMap<String, u16> {
        &self.forwarding.zone_name_to_id
    }

    pub fn apply_manager_neighbors(
        &mut self,
        replace: bool,
        neighbors: &[(i32, IpAddr, NeighborEntry)],
    ) {
        let old_manager_keys = if replace {
            self.neighbors
                .manager_keys
                .lock()
                .map(|manager_keys| manager_keys.iter().copied().collect::<Vec<_>>())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        if let Ok(mut manager_keys) = self.neighbors.manager_keys.lock() {
            if replace {
                manager_keys.clear();
            }
            for (ifindex, ip, _) in neighbors {
                manager_keys.insert((*ifindex, *ip));
            }
        }
        // #949: replace + insert under a single bulk acquisition so
        // readers see either the pre-replace or post-replace state,
        // never a half-replaced set. `with_all_shards` locks all 64
        // shards in shard-index order (deadlock-free invariant).
        self.neighbors.dynamic.with_all_shards(|bulk| {
            if replace {
                for key in &old_manager_keys {
                    bulk.remove(key);
                }
            }
            for (ifindex, ip, entry) in neighbors {
                bulk.insert((*ifindex, *ip), *entry);
            }
        });
        if replace {
            for key in &old_manager_keys {
                self.forwarding.neighbors.remove(key);
            }
        }
        for (ifindex, ip, entry) in neighbors {
            self.forwarding.neighbors.insert((*ifindex, *ip), *entry);
        }
        if replace || !neighbors.is_empty() {
            // Clone the full ForwardingState to publish neighbor changes.
            // This copies routes/policies too, but update_neighbors fires
            // infrequently (only when kernel ARP/NDP changes, gated by
            // neighborsEqual in the Go manager). The clone cost is
            // negligible vs packet processing.
            self.ha.forwarding.store(Arc::new(self.forwarding.clone()));
        }
        self.neighbors.generation.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn stop_inner(&mut self, clear_synced_state: bool) {
        if let Some(stop) = self.neighbors.monitor_stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
        // #1636: stop the neighbor warmer and drop the producer handle so
        // the worker's recv side disconnects and it exits cleanly. The
        // 500ms recv timeout bounds the join latency.
        if let Some(warm_stop) = self.neighbors.warm_stop.take() {
            warm_stop.store(true, Ordering::Relaxed);
        }
        self.neighbors.warm_queue = None;
        // #1769: stop the on-demand resolver. Signal stop, drop the
        // producer handle so the recv side disconnects promptly, then
        // JOIN the worker before returning. Joining (not just signalling)
        // is what enforces no-mutation-after-stop: a detached resolver
        // blocked in its GET could otherwise insert/remove on
        // dynamic_neighbors after a subsequent reconcile spawned a fresh
        // resolver. Join latency is bounded by the 500ms recv timeout +
        // the 200ms GET timeout, well under TimeoutStopSec.
        if let Some(resolver_stop) = self.neighbors.resolver_stop.take() {
            resolver_stop.store(true, Ordering::Relaxed);
        }
        self.neighbors.resolver = None;
        if let Some(join) = self.neighbors.resolver_join.take() {
            let _ = join.join();
        }
        // Note: the resolver is joined here BEFORE workers.stop_and_clear
        // below, so a worker still running during teardown could observe
        // the resolver thread gone and `try_send` into a consumer-dropped
        // channel. That is harmless: enqueue is non-blocking and a failed
        // send is counted as enqueue_drops/disconnected, never blocks the
        // worker, and the resolver thread is provably gone so no stale
        // mutation can occur. The next reconcile spawns a fresh resolver
        // and re-installs the handle on every worker.
        // #1881: entries may be tombstones (`handle == None`); stop
        // then join live handles, clear everything (tombstones too —
        // after a stop the next reconcile re-legitimates entries).
        for entry in self.tunnel_sources.values_mut() {
            if let Some(handle) = entry.handle.as_ref() {
                handle.stop.store(true, Ordering::Relaxed);
            }
        }
        for entry in self.tunnel_sources.values_mut() {
            if let Some(handle) = entry.handle.as_mut() {
                if let Some(join) = handle.join.take() {
                    let _ = join.join();
                }
            }
        }
        self.tunnel_sources.clear();
        self.local_tunnel_deliveries
            .store(Arc::new(BTreeMap::new()));
        // #1432 S2a: stop + join WG control threads. The persistent wgN
        // TUN is owned by the Go control plane and intentionally NOT
        // torn down here (it must survive a reload — AGY r3 Hazard B).
        // #1866: tombstones are cleared too — after a stop the next
        // reconcile re-legitimates entries from a coherent snapshot.
        for entry in self.wg_control_threads.values_mut() {
            if let Some(handle) = entry.handle.as_ref() {
                handle.stop.store(true, Ordering::Relaxed);
            }
        }
        for entry in self.wg_control_threads.values_mut() {
            if let Some(handle) = entry.handle.as_mut() {
                if let Some(join) = handle.join.take() {
                    let _ = join.join();
                }
            }
        }
        self.wg_control_threads.clear();
        self.workers.stop_and_clear(
            self.bpf_maps.map_fd.as_ref(),
            self.bpf_maps.heartbeat_map_fd.as_ref(),
        );
        self.mirror_targets
            .store(Arc::new(MirrorTargetMap::default()));
        // #925 Phase 1: drop the per-worker panic slots alongside the
        // workers themselves so a long-running daemon that reconciles
        // through many worker-id sets doesn't accumulate stale slots.
        self.worker_panics.clear();
        self.cos_owner_worker_by_queue.clear();
        self.cos
            .owner_worker_by_queue
            .store(Arc::new(BTreeMap::new()));
        self.cos
            .owner_live_by_queue
            .store(Arc::new(BTreeMap::new()));
        self.cos.root_leases.store(Arc::new(BTreeMap::new()));
        self.cos.exact_backlogs.store(Arc::new(BTreeMap::new()));
        self.cos.queue_leases.store(Arc::new(BTreeMap::new()));
        self.cos.queue_vtime_floors.store(Arc::new(BTreeMap::new()));
        self.last_slow_path_status = self
            .slow_path
            .as_ref()
            .map(|slow| slow.status())
            .unwrap_or_default();
        self.slow_path = None;
        self.bpf_maps.map_fd = None;
        self.bpf_maps.heartbeat_map_fd = None;
        self.bpf_maps.session_map_fd = None;
        self.bpf_maps.conntrack_v4_fd = None;
        self.bpf_maps.conntrack_v6_fd = None;
        self.bpf_maps.dnat_table_fd = None;
        self.bpf_maps.dnat_table_v6_fd = None;
        self.forwarding = ForwardingState::default();
        self.ha
            .forwarding
            .store(Arc::new(ForwardingState::default()));
        self.shared_validation
            .store(Arc::new(ValidationState::default()));
        self.ha.fabrics.store(Arc::new(Vec::new()));
        self.neighbors.generation.store(0, Ordering::Relaxed);
        // #949: clear all shards atomically vs readers.
        self.neighbors.dynamic.with_all_shards(|bulk| {
            for shard in bulk.each_shard_mut() {
                shard.clear();
            }
        });
        if let Ok(mut manager_keys) = self.neighbors.manager_keys.lock() {
            manager_keys.clear();
        }
        // #1636: reset warmer rate-limit + telemetry so a re-bind starts
        // clean. The worker thread itself is torn down above; a fresh one
        // is spawned on the next bring-up.
        if let Ok(mut probed) = self.neighbors.last_probed_at.lock() {
            probed.clear();
        }
        self.neighbors
            .last_warm_sweep_ns
            .store(0, Ordering::Relaxed);
        self.neighbors
            .warned_disconnect
            .store(false, Ordering::Relaxed);
        if clear_synced_state {
            if let Ok(mut sessions) = self.sessions.synced.lock() {
                sessions.clear();
            }
            if let Ok(mut nat_sessions) = self.sessions.nat.lock() {
                nat_sessions.clear();
            }
            if let Ok(mut forward_wire_sessions) = self.sessions.forward_wire.lock() {
                forward_wire_sessions.clear();
            }
            self.sessions.owner_rg_indexes.clear();
        }
        if let Ok(mut recent) = self.recent_exceptions.lock() {
            recent.clear();
        }
        if let Ok(mut recent) = self.recent_session_deltas.lock() {
            recent.clear();
        }
        if let Ok(mut last) = self.last_resolution.lock() {
            *last = None;
        }
        self.validation = ValidationState::default();
        self.workers.last_planned_workers = 0;
        self.workers.last_planned_bindings = 0;
        self.workers.last_planned_worker_slots = 0;
        self.last_reconcile_stage = "stopped".to_string();
    }

    pub(crate) fn snapshot_shared_session_entries(&self) -> Vec<SyncedSessionEntry> {
        self.sessions
            .synced
            .lock()
            .map(|sessions| sessions.values().cloned().collect())
            .unwrap_or_default()
    }

    pub(crate) fn replay_synced_sessions(
        &self,
        entries: &[SyncedSessionEntry],
        worker_command_queues: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
        session_map_fd: c_int,
    ) -> usize {
        if entries.is_empty() {
            return 0;
        }
        let worker_queues = worker_command_queues.values().cloned().collect::<Vec<_>>();
        for entry in entries {
            // #1789: a failed replay publish silently loses an arbitrary
            // prefix of synced state after reconcile (was `let _ =`). No
            // binding context here — shared counter.
            if publish_live_session_entry(
                session_map_fd,
                &entry.key,
                entry.decision.nat,
                entry.metadata.is_reverse,
            )
            .is_err()
            {
                SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
            }
            replicate_session_upsert(&worker_queues, entry);
        }
        entries.len()
    }

    /// #1636 option C: proactive neighbor warm at config-apply.
    ///
    /// Walks the current forwarding state's configured next-hops (static
    /// + dynamic routes, fabric peers) and enqueues a warm probe for each
    /// `(egress_ifindex, hop)` that is NOT already resolved, NOT recently
    /// probed, and whose owning RG is currently forwarding-active on this
    /// node. The warmer worker fires the probes off the coordinator hot
    /// path.
    ///
    /// `force = true` bypasses the 1s snapshot-level rate-limit (used by
    /// the RG-promote path so a newly-active RG gets warmed immediately
    /// without waiting for the next snapshot apply). Per-key 5s
    /// rate-limit and per-RG gate always apply.
    ///
    /// Takes `&self` (not `&mut self`): `last_warm_sweep_ns` and
    /// `warm_generation` are atomics so this can be called from both
    /// `refresh_runtime_snapshot` (`&mut self`) and the RG-promote path.
    pub(in crate::afxdp) fn queue_warm_pass(&self, force: bool) {
        // Nothing to do until the warmer worker is spawned.
        let Some(tx) = self.neighbors.warm_queue.as_ref() else {
            return;
        };
        let now = monotonic_nanos();
        if !force {
            let last = self.neighbors.last_warm_sweep_ns.load(Ordering::Acquire);
            if now.saturating_sub(last) < WARM_SWEEP_RATE_LIMIT_NS {
                return;
            }
            // CAS to claim the sweep slot; if another caller raced us,
            // let them run the sweep.
            if self
                .neighbors
                .last_warm_sweep_ns
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return;
            }
        } else {
            self.neighbors
                .last_warm_sweep_ns
                .store(now, Ordering::Release);
        }

        // Generation bump only on ADMITTED sweeps. In-flight items from
        // prior generations are dropped on dequeue by the warmer worker.
        let sweep_gen = self
            .neighbors
            .warm_generation
            .fetch_add(1, Ordering::Release)
            + 1;

        let snapshot = &self.forwarding;
        let rg_runtime = self.ha.rg_runtime.load();
        let now_secs = now / 1_000_000_000;
        let mut seen: FastSet<(i32, IpAddr)> = FastSet::default();

        let mut enqueue = |egress_ifindex: i32, hop: IpAddr| {
            if egress_ifindex <= 0 {
                return;
            }
            // Never warm broadcast/multicast/loopback/unspecified.
            match hop {
                IpAddr::V4(v4) => {
                    if v4.is_unspecified()
                        || v4.is_loopback()
                        || v4.is_multicast()
                        || v4.is_broadcast()
                    {
                        return;
                    }
                }
                IpAddr::V6(v6) => {
                    if v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() {
                        return;
                    }
                }
            }
            let key = (egress_ifindex, hop);
            if !seen.insert(key) {
                return;
            }
            // Already resolved (static/manager neighbor or dynamic cache)?
            if snapshot.neighbors.contains_key(&key) || self.neighbors.dynamic.contains_key(&key) {
                return;
            }
            // Per-RG HA gate: only warm next-hops whose owning RG is
            // forwarding-active on this node. Standby RGs are skipped.
            let rg_id = owner_rg_for_flow(snapshot, egress_ifindex);
            let rg_active = rg_runtime
                .get(&rg_id)
                .map(|group| group.is_forwarding_active(now_secs))
                .unwrap_or(false);
            if !rg_active {
                return;
            }
            let Some(name) = snapshot.ifindex_to_name.get(&egress_ifindex) else {
                return;
            };
            let item = WarmItem {
                ifindex: egress_ifindex,
                hop,
                iface_name: name.clone(),
                generation: sweep_gen,
                rg_id,
            };
            match tx.try_send(item) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(_)) => {
                    self.neighbors.warm_drops.fetch_add(1, Ordering::Relaxed);
                    #[cfg(feature = "debug-log")]
                    eprintln!(
                        "xpf-userspace-dp: warm queue full (cap={}); dropping {:?}",
                        WARM_QUEUE_DEPTH, key
                    );
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    self.neighbors
                        .warm_disconnected
                        .fetch_add(1, Ordering::Relaxed);
                    // Once-only operator-visible log (not debug-gated):
                    // under route churn this would otherwise fire per key.
                    if !self
                        .neighbors
                        .warned_disconnect
                        .swap(true, Ordering::Relaxed)
                    {
                        eprintln!(
                            "xpf-userspace-dp: ERROR: neighbor warmer worker disconnected; \
                             proactive neighbor warming is DISABLED until restart"
                        );
                    }
                }
            }
        };

        // Static + dynamic (FRR-populated) route next-hops, both families.
        // Tunnel routes (tunnel_endpoint_id != 0) are skipped: their HA
        // ownership is the tunnel endpoint's RG, not the underlay egress
        // RG (forwarding uses owner_rg_for_resolution, which switches on
        // tunnel_endpoint_id) — gating them via owner_rg_for_flow(egress)
        // here would warm on the wrong RG (Codex r1 High #1). Tunnel
        // endpoints are also explicitly out of warm scope per the plan
        // (AGY plan r1 #3); their underlay next-hops, if relevant, appear
        // as ordinary (tunnel_endpoint_id == 0) routes.
        for routes in snapshot.routes_v4.values() {
            for route in routes {
                if route.tunnel_endpoint_id != 0 {
                    continue;
                }
                if let Some(hop) = route.next_hop {
                    enqueue(route.ifindex, IpAddr::V4(hop));
                }
            }
        }
        for routes in snapshot.routes_v6.values() {
            for route in routes {
                if route.tunnel_endpoint_id != 0 {
                    continue;
                }
                if let Some(hop) = route.next_hop {
                    enqueue(route.ifindex, IpAddr::V6(hop));
                }
            }
        }
        // Fabric peers: warm the peer over the fabric parent ifindex
        // (AGY r7 #3 — FabricLink.parent_ifindex is the egress ifindex).
        for fabric in &snapshot.fabrics {
            enqueue(fabric.parent_ifindex, fabric.peer_addr);
        }
    }

    /// #1636: called from the cluster RG-promote path when an RG
    /// transitions to forwarding-active on this node. Clears the
    /// per-key rate-limit (so probes that failed during the transient
    /// down state are not locked out for 5s) and triggers an immediate
    /// forced warm pass for the newly-active RG's next-hops.
    pub(in crate::afxdp) fn on_rg_promote_active(&self) {
        if let Ok(mut map) = self.neighbors.last_probed_at.lock() {
            map.clear();
        }
        self.queue_warm_pass(true);
    }

    // NOTE (#1636): a per-ifindex `last_probed_at` clear on link-UP was
    // specified in the plan (AGY plan r3 #3) to drop probes fired during
    // a link-negotiation window. It is NOT wired here: there is no
    // userspace link-state (RTM_NEWLINK) monitor to call it from, and the
    // RG-promote clear already covers the dominant failover case. Shipping
    // an unwired helper would be a false guarantee (Copilot r1), so it is
    // deferred until a link-state monitor exists. The 5s per-key window
    // self-heals a transient-down lockout regardless.

    pub fn policy_rule_counters(&self) -> Vec<crate::protocol::PolicyRuleCounterStatus> {
        self.forwarding.policy.counter_snapshots()
    }

    pub fn clear_policy_counters(&self) {
        self.policy_counters.clear();
    }

    /// #2218: per-rule NAT translation hit-counter snapshots reported back
    /// to the Go control plane via `ProcessStatus.nat_rule_counters`.
    pub fn nat_rule_counters(&self) -> Vec<crate::protocol::NatRuleCounterStatus> {
        self.nat_counters.snapshots()
    }

    /// #2218: operator clear of NAT translation hit counters (the Go side
    /// also clears the corresponding offset entries; this resets the
    /// helper-side atomics).
    pub fn clear_nat_counters(&self) {
        self.nat_counters.clear();
    }

    /// Bump just the FIB generation counter without a full snapshot rebuild.
    /// Workers will invalidate flow cache entries with stale FIB generations.
    pub fn bump_fib_generation(&mut self, fib_generation: u32) {
        self.validation.fib_generation = fib_generation;
        self.shared_validation.store(Arc::new(self.validation));
    }
}

/// #2218: collect the nonzero per-rule NAT counter ids referenced by a
/// snapshot (SNAT + DNAT + static), for `NatCounterStore::reconcile_ids`.
/// Mirrors `policy_counters.reconcile_rules(&snapshot.policies)`.
pub(super) fn snapshot_active_nat_counter_ids(
    snapshot: &crate::protocol::ConfigSnapshot,
) -> Vec<u16> {
    let mut ids: Vec<u16> = Vec::new();
    for rule in &snapshot.source_nat_rules {
        if rule.counter_id != 0 {
            ids.push(rule.counter_id);
        }
    }
    for rule in &snapshot.destination_nat_rules {
        if rule.counter_id != 0 {
            ids.push(rule.counter_id);
        }
    }
    for rule in &snapshot.static_nat_rules {
        if rule.counter_id != 0 {
            ids.push(rule.counter_id);
        }
    }
    ids
}

fn build_mirror_target_map(
    identities: &BTreeMap<u32, BindingIdentity>,
    live: &BTreeMap<u32, Arc<BindingLiveState>>,
) -> MirrorTargetMap {
    let mut out = MirrorTargetMap::default();
    for (slot, ident) in identities {
        let Some(binding_live) = live.get(slot) else {
            continue;
        };
        out.insert(ident, binding_live.clone());
    }
    out
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
