use super::*;
mod bpf_maps;
mod cos_state;
mod ha_state;
mod inject;
mod neighbor_manager;
mod rebalance;
mod reconcile;
mod refresh_bindings;
mod session_manager;
mod status;
mod supervisor;
mod wg_control;
mod worker_manager;
pub(crate) use bpf_maps::BpfMaps;
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

pub struct Coordinator {
    pub(crate) bpf_maps: BpfMaps,
    pub(crate) slow_path: Option<Arc<SlowPathReinjector>>,
    pub(crate) local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    pub(crate) tunnel_sources: BTreeMap<u16, LocalTunnelSourceHandle>,
    /// #1432 S2a: WG control threads keyed by tunnel_endpoint_id. The
    /// `usize` is the address of the `Arc<WgEngine>` the thread was
    /// spawned with, so the runtime-refresh reconcile can detect a
    /// config change (fresh engine ⇒ different Arc ⇒ restart) vs an
    /// unchanged endpoint (reused Arc ⇒ keep the thread running).
    pub(crate) wg_control_threads: BTreeMap<u16, (LocalTunnelSourceHandle, usize)>,
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
    /// #1748: opt-in reactive ntuple rebalance config from the
    /// `class-of-service flow-rebalance` leaf. `None` => default-OFF: the
    /// controller is never constructed, no ioctl socket, no per-tick work.
    pub(in crate::afxdp) rebalance_config: Option<crate::afxdp::rebalance::RebalanceConfig>,
    /// #1748: per-ifindex live rebalance controllers, constructed lazily on
    /// the first tick after the knob is enabled and a worker is bound to that
    /// interface. Each owns its ethtool ntuple socket + rule ledger.
    pub(in crate::afxdp) rebalance_controllers:
        BTreeMap<i32, crate::afxdp::rebalance::RebalanceController>,
    /// #1748: last per-(worker) tx_bytes sample + monotonic ns, for deriving
    /// byte-rate across the controller tick window. Keyed by worker_id.
    pub(in crate::afxdp) rebalance_last_tx_bytes: BTreeMap<u32, (u64, u64)>,
    /// #1748 review #8: last per-FLOW cumulative observed_bytes sample +
    /// monotonic ns, for deriving each flow's byte-RATE across the tick window.
    /// FlowCacheEntry.observed_bytes is CUMULATIVE, so a long-lived idle flow
    /// would otherwise look "hottest"; the controller selects on rate, not
    /// cumulative bytes. Keyed by the flow's SessionKey.
    pub(in crate::afxdp) rebalance_last_flow_bytes:
        std::collections::HashMap<crate::session::SessionKey, (u64, u64)>,
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
            rebalance_config: None,
            rebalance_controllers: BTreeMap::new(),
            rebalance_last_tx_bytes: BTreeMap::new(),
            rebalance_last_flow_bytes: std::collections::HashMap::new(),
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
        // #1748: remove every installed ntuple rule here so no orphan HW rule
        // survives. PLAIN deletes (no reverse barrier) are correct on BOTH
        // paths this runs on — final shutdown AND reconcile-teardown
        // (stop_inner(false)) — for the same reason (#1748 review #3, verified):
        // stop_inner stops + joins ALL worker threads via
        // `self.workers.stop_and_clear(...)` below, which destroys each
        // worker's per-thread SessionTable, and with it every RebalancedOut /
        // RebalancedOwner origin (those local-only rebalance origins are NEVER
        // published to the shared synced-session table — that is the whole
        // point of the suppression set). On reconcile bring-up the worker
        // SessionTables are rebuilt fresh by replaying the preserved SHARED
        // synced sessions, which carry SyncImport origins, not the rebalance
        // origins. So there is no live ownership to hand back across a reconcile
        // either: no RebalancedOut/Owner entry can be stranded, because none
        // survives the worker teardown. The reverse barrier protects a leak
        // that requires the owning worker to keep running, which cannot happen
        // when every worker is joined here.
        self.teardown_all_rebalance_rules_plain();
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
        for handle in self.tunnel_sources.values_mut() {
            handle.stop.store(true, Ordering::Relaxed);
        }
        for (_, handle) in self.tunnel_sources.iter_mut() {
            if let Some(join) = handle.join.take() {
                let _ = join.join();
            }
        }
        self.tunnel_sources.clear();
        self.local_tunnel_deliveries
            .store(Arc::new(BTreeMap::new()));
        // #1432 S2a: stop + join WG control threads. The persistent wgN
        // TUN is owned by the Go control plane and intentionally NOT
        // torn down here (it must survive a reload — AGY r3 Hazard B).
        for (handle, _) in self.wg_control_threads.values_mut() {
            handle.stop.store(true, Ordering::Relaxed);
        }
        for (_, (handle, _)) in self.wg_control_threads.iter_mut() {
            if let Some(join) = handle.join.take() {
                let _ = join.join();
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
        self.neighbors.last_warm_sweep_ns.store(0, Ordering::Relaxed);
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
            let _ = publish_live_session_entry(
                session_map_fd,
                &entry.key,
                entry.decision.nat,
                entry.metadata.is_reverse,
            );
            replicate_session_upsert(&worker_queues, entry);
        }
        entries.len()
    }


    fn spawn_local_tunnel_sources(&mut self) {
        let mut local_tunnel_deliveries = BTreeMap::new();
        for endpoint in self.forwarding.tunnel_endpoints.values() {
            if endpoint.mode != "gre" && endpoint.mode != "ip6gre" {
                continue;
            }
            let Some(tunnel_name) = self
                .forwarding
                .ifindex_to_name
                .get(&endpoint.logical_ifindex)
                .cloned()
            else {
                continue;
            };
            let stop = Arc::new(AtomicBool::new(false));
            let stop_clone = stop.clone();
            let forwarding = self.forwarding.clone();
            let ha_state = self.ha.rg_runtime.clone();
            let dynamic_neighbors = self.neighbors.dynamic.clone();
            let live = self.workers.live.clone();
            let identities = self.workers.identities.clone();
            let shared_sessions = self.sessions.synced.clone();
            let shared_nat_sessions = self.sessions.nat.clone();
            let shared_forward_wire_sessions = self.sessions.forward_wire.clone();
            let shared_owner_rg_indexes = self.sessions.owner_rg_indexes.clone();
            let worker_commands = self
                .workers
                .handles
                .values()
                .map(|handle| handle.commands.clone())
                .collect::<Vec<_>>();
            let recent_exceptions = self.recent_exceptions.clone();
            let tunnel_endpoint_id = endpoint.id;
            let thread_tunnel_name = tunnel_name.clone();
            let logical_ifindex = endpoint.logical_ifindex;
            let (delivery_tx, delivery_rx) = mpsc::sync_channel(LOCAL_TUNNEL_DELIVERY_QUEUE_DEPTH);
            // #925-A: wrap aux tunnel-origin thread in catch_unwind.
            // A panic here would otherwise silently stop locally-
            // generated GRE traffic on this tunnel; transit packets
            // continue through worker_loop unaffected.
            let join = spawn_supervised_aux(
                format!("xpf-native-gre-origin-{}", tunnel_name),
                move || {
                    local_tunnel_source_loop(
                        thread_tunnel_name,
                        tunnel_endpoint_id,
                        forwarding,
                        ha_state,
                        dynamic_neighbors,
                        live,
                        identities,
                        shared_sessions,
                        shared_nat_sessions,
                        shared_forward_wire_sessions,
                        shared_owner_rg_indexes,
                        worker_commands,
                        delivery_rx,
                        recent_exceptions,
                        stop_clone,
                    );
                },
            );
            match join {
                Ok(join) => {
                    local_tunnel_deliveries.insert(logical_ifindex, delivery_tx);
                    self.tunnel_sources.insert(
                        tunnel_endpoint_id,
                        LocalTunnelSourceHandle {
                            stop,
                            join: Some(join),
                        },
                    );
                }
                Err(err) => {
                    if let Ok(mut recent) = self.recent_exceptions.lock() {
                        push_recent_exception(
                            &mut recent,
                            ExceptionStatus {
                                timestamp: Utc::now(),
                                interface: tunnel_name,
                                reason: format!(
                                    "spawn_local_tunnel_source_failed:{tunnel_endpoint_id}:{err}"
                                ),
                                ..ExceptionStatus::default()
                            },
                        );
                    }
                }
            }
        }
        self.local_tunnel_deliveries
            .store(Arc::new(local_tunnel_deliveries));
    }

    /// #1432 S2a: reconcile WG control threads against the current
    /// `forwarding.wg_engines`. Called from both initial worker bring-up
    /// AND `refresh_runtime_snapshot` (Copilot C1: a same-plan apply that
    /// adds/removes/changes a WG endpoint must not leave stale threads).
    ///
    /// Per endpoint id:
    ///   - running thread whose endpoint vanished, is no longer WG, or
    ///     whose engine `Arc` address changed (a config change rebuilt a
    ///     fresh engine — `forwarding_build::wg`) ⇒ stop + join + drop.
    ///   - a WG engine with no running thread (or just stopped above) ⇒
    ///     spawn a fresh control thread bound to the current engine.
    /// An unchanged endpoint (reused engine Arc, §4.2) keeps its thread.
    fn spawn_wg_control_threads(&mut self) {
        // Current WG engines keyed by id, with their Arc address identity.
        let mut desired: BTreeMap<u16, usize> = BTreeMap::new();
        for endpoint in self.forwarding.tunnel_endpoints.values() {
            if endpoint.mode != "wireguard" {
                continue;
            }
            if let Some(engine) = self.forwarding.wg_engines.get(&endpoint.id) {
                desired.insert(endpoint.id, Arc::as_ptr(engine) as usize);
            }
        }

        // Stop + join threads that are stale (gone, or engine Arc changed).
        let stale: Vec<u16> = self
            .wg_control_threads
            .iter()
            .filter(|(id, (_, engine_ptr))| desired.get(id) != Some(engine_ptr))
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            if let Some((mut handle, _)) = self.wg_control_threads.remove(&id) {
                handle.stop.store(true, Ordering::Relaxed);
                if let Some(join) = handle.join.take() {
                    let _ = join.join();
                }
            }
        }

        // Spawn threads for WG engines that have none running.
        for endpoint in self.forwarding.tunnel_endpoints.values() {
            if endpoint.mode != "wireguard" {
                continue;
            }
            let id = endpoint.id;
            if self.wg_control_threads.contains_key(&id) {
                continue;
            }
            let Some(engine) = self.forwarding.wg_engines.get(&id).cloned() else {
                continue;
            };
            let engine_ptr = Arc::as_ptr(&engine) as usize;
            let Some(tunnel_name) = self
                .forwarding
                .ifindex_to_name
                .get(&endpoint.logical_ifindex)
                .cloned()
            else {
                continue;
            };
            let stop = Arc::new(AtomicBool::new(false));
            let stop_clone = stop.clone();
            let recent_exceptions = self.recent_exceptions.clone();
            let tunnel_endpoint_id = id;
            let listen_port = endpoint.wg_listen_port;
            let peer_endpoint = endpoint.wg_endpoint;
            let thread_tunnel_name = tunnel_name.clone();
            let join = spawn_supervised_aux(
                format!("xpf-wg-control-{tunnel_name}"),
                move || {
                    wg_control::wg_control_loop(
                        thread_tunnel_name,
                        tunnel_endpoint_id,
                        engine,
                        listen_port,
                        peer_endpoint,
                        recent_exceptions,
                        stop_clone,
                    );
                },
            );
            match join {
                Ok(join) => {
                    self.wg_control_threads.insert(
                        tunnel_endpoint_id,
                        (
                            LocalTunnelSourceHandle {
                                stop,
                                join: Some(join),
                            },
                            engine_ptr,
                        ),
                    );
                }
                Err(err) => {
                    if let Ok(mut recent) = self.recent_exceptions.lock() {
                        push_recent_exception(
                            &mut recent,
                            ExceptionStatus {
                                timestamp: Utc::now(),
                                interface: tunnel_name,
                                reason: format!(
                                    "spawn_wg_control_failed:{tunnel_endpoint_id}:{err}"
                                ),
                                ..ExceptionStatus::default()
                            },
                        );
                    }
                }
            }
        }
    }

    /// Refresh fabric link info from updated snapshots. Called when the
    /// Go daemon's refreshFabricFwd resolves a peer MAC that wasn't
    /// available at initial snapshot build time.
    ///
    /// This updates both the coordinator's local forwarding state and the
    /// shared Arc-backed state used by workers, so refreshed fabric links
    /// become visible to workers as soon as the new values are published.
    pub fn refresh_fabric_links(&mut self, snapshots: &[crate::FabricSnapshot]) {
        let new_fabrics = resolve_fabric_links_from_snapshots(
            snapshots,
            &self.forwarding.egress,
            &self.neighbors.dynamic,
        );
        if !new_fabrics.is_empty() {
            self.forwarding.fabrics = new_fabrics.clone();
            self.ha.fabrics.store(Arc::new(new_fabrics));
            // Also update shared_forwarding so workers see the new fabric
            // links for fabric redirect resolution. Without this, workers
            // use the snapshot's forwarding state which may have empty fabrics
            // if the peer MAC wasn't resolved at snapshot time.
            self.ha.forwarding.store(Arc::new(self.forwarding.clone()));
        }
    }

    pub fn refresh_runtime_snapshot(&mut self, snapshot: &crate::ConfigSnapshot) {
        // #1606: preflight policy validation BEFORE any
        // side-effecting mutation (neighbor manager keys,
        // validation, policy_counters). If integrity errors fire,
        // keep ALL existing state.
        //
        // CRITICAL (Codex code-review F2): use a SCRATCH counter
        // store for the preflight so we don't leak counter
        // registry entries on rejected snapshots.
        let preflight_counters = crate::policy::PolicyCounterStore::default();
        if let Err(err) = crate::policy::parse_policy_state_with_counters(
            &snapshot.default_policy,
            &snapshot.policies,
            &self.forwarding.zone_name_to_id,
            &snapshot.address_books,
            &preflight_counters,
        ) {
            eprintln!(
                "xpf-userspace-dp: snapshot integrity error during refresh_runtime_snapshot preflight: {} — keeping previous state",
                err
            );
            return;
        }

        let next_manager_keys = snapshot
            .neighbors
            .iter()
            .filter_map(|neigh| {
                if neigh.ifindex <= 0
                    || !neighbor_state_usable_str(&neigh.state)
                    || neigh.mac.is_empty()
                    || parse_mac_str(&neigh.mac).is_none()
                {
                    return None;
                }
                neigh
                    .ip
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| (neigh.ifindex, ip))
            })
            .collect::<FastSet<_>>();
        let old_manager_keys = if let Ok(mut manager_keys) = self.neighbors.manager_keys.lock() {
            let old = manager_keys.iter().copied().collect::<Vec<_>>();
            *manager_keys = next_manager_keys;
            old
        } else {
            Vec::new()
        };
        // #949: bulk-remove stale manager keys atomically vs readers.
        self.neighbors.dynamic.with_all_shards(|bulk| {
            for key in &old_manager_keys {
                bulk.remove(key);
            }
        });
        self.validation = ValidationState {
            snapshot_installed: true,
            config_generation: snapshot.generation,
            fib_generation: snapshot.fib_generation,
        };
        // Preserve existing fabric links — they are resolved separately
        // via refresh_fabric_links (SyncFabricState) and the snapshot
        // may not include them if the peer MAC wasn't resolved at
        // snapshot build time. Always keep the better-resolved set.
        let preserved_fabrics = self.forwarding.fabrics.clone();
        // #1606: preflight policy build. If integrity errors fire,
        // keep the existing forwarding state.
        let new_forwarding = match build_forwarding_state_with_policy_counters_and_previous(
            snapshot,
            &self.policy_counters,
            Some(&self.forwarding),
        ) {
            Ok(fwd) => fwd,
            Err(err) => {
                eprintln!(
                    "xpf-userspace-dp: snapshot integrity error during runtime-snapshot refresh: {} — keeping previous forwarding state",
                    err
                );
                return;
            }
        };
        self.policy_counters.reconcile_rules(&snapshot.policies);
        self.forwarding = new_forwarding;
        if self.forwarding.fabrics.is_empty() && !preserved_fabrics.is_empty() {
            self.forwarding.fabrics = preserved_fabrics;
        } else if !preserved_fabrics.is_empty() {
            // Merge: for each preserved fabric, if the new snapshot
            // doesn't have a matching parent_ifindex, keep the old one.
            for old in &preserved_fabrics {
                if !self
                    .forwarding
                    .fabrics
                    .iter()
                    .any(|f| f.parent_ifindex == old.parent_ifindex)
                {
                    self.forwarding.fabrics.push(*old);
                }
            }
        }
        self.shared_validation.store(Arc::new(self.validation));
        self.ha.forwarding.store(Arc::new(self.forwarding.clone()));
        // #1432 S2a (Copilot C1): reconcile WG control threads on every
        // runtime-snapshot refresh, not just initial bring-up, so a
        // same-plan apply that adds/removes/changes a WG endpoint starts,
        // stops, or restarts the matching UDP/TUN control thread.
        self.spawn_wg_control_threads();
        self.refresh_cos_owner_worker_map_from_identities();
        self.ha
            .fabrics
            .store(Arc::new(self.forwarding.fabrics.clone()));
        // #1636 option C: proactively warm configured next-hops so the
        // neighbor cache is hot before the first user flow. Non-forced:
        // the 1s snapshot-level rate-limit coalesces config storms.
        self.queue_warm_pass(false);
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

    fn refresh_cos_owner_worker_map_from_identities(&mut self) {
        let worker_binding_ifindexes =
            build_worker_binding_ifindexes_from_identities(&self.workers.identities);
        let owner_map = build_cos_owner_worker_by_queue_from_binding_ifindexes(
            &self.forwarding,
            &worker_binding_ifindexes,
        );
        let active_shards_by_egress_ifindex =
            build_cos_active_shards_by_egress_ifindex_with_fallback_ifindexes(
                &self.forwarding,
                &worker_binding_ifindexes,
                &worker_binding_ifindexes,
            );
        self.refresh_cos_runtime_maps(owner_map, active_shards_by_egress_ifindex);
    }

    fn refresh_cos_owner_worker_map_from_binding_statuses(&mut self, bindings: &[BindingStatus]) {
        let ready_worker_binding_ifindexes = bindings.iter().filter(|binding| binding.ready).fold(
            BTreeMap::<u32, std::collections::BTreeSet<i32>>::new(),
            |mut out, binding| {
                out.entry(binding.worker_id)
                    .or_default()
                    .insert(binding.ifindex);
                out
            },
        );
        let fallback_worker_binding_ifindexes =
            build_worker_binding_ifindexes_from_identities(&self.workers.identities);
        let owner_map = build_cos_owner_worker_by_queue_with_fallback_ifindexes(
            &self.forwarding,
            &ready_worker_binding_ifindexes,
            &fallback_worker_binding_ifindexes,
        );
        let active_shards_by_egress_ifindex =
            build_cos_active_shards_by_egress_ifindex_with_fallback_ifindexes(
                &self.forwarding,
                &ready_worker_binding_ifindexes,
                &fallback_worker_binding_ifindexes,
            );
        self.refresh_cos_runtime_maps(owner_map, active_shards_by_egress_ifindex);
    }

    fn refresh_cos_runtime_maps(
        &mut self,
        owner_map: BTreeMap<(i32, u8), u32>,
        active_shards_by_egress_ifindex: BTreeMap<i32, usize>,
    ) {
        let owner_changed = owner_map != self.cos_owner_worker_by_queue;
        let owner_map_for_runtime = if owner_changed {
            &owner_map
        } else {
            &self.cos_owner_worker_by_queue
        };
        let current_owner_live = self.cos.owner_live_by_queue.load();
        let next_owner_live = build_cos_owner_live_by_queue(
            &self.forwarding,
            owner_map_for_runtime,
            &self.workers.identities,
            &self.workers.live,
        );
        let current_leases = self.cos.root_leases.load();
        let next_leases = build_shared_cos_root_leases_reusing_existing(
            &self.forwarding,
            &active_shards_by_egress_ifindex,
            current_leases.as_ref(),
        );
        let current_exact_backlogs = self.cos.exact_backlogs.load();
        // #917: V_min coordination Arcs sized by worker count.
        // workers.last_planned_workers is set in apply_planned_workers
        // before this reconcile fires; defaults to 0 at first
        // boot which produces zero-slot floors (the reconcile
        // re-fires once workers are planned).
        // #1229 Phase 6 v8: lease construction also needs num_workers
        // for max_worker_id sizing of per-worker arrays. Hoisted
        // ahead of the queue_leases build site.
        let current_queue_vtime_floors = self.cos.queue_vtime_floors.load();
        let num_workers = self.workers.last_planned_workers().max(1);
        let current_queue_leases = self.cos.queue_leases.load();
        let max_binding_slot = self
            .workers
            .identities
            .keys()
            .next_back()
            .copied()
            .unwrap_or(0) as usize;
        let next_exact_backlogs = build_shared_cos_exact_backlogs_reusing_existing(
            &self.forwarding,
            max_binding_slot,
            current_exact_backlogs.as_ref(),
        );
        let next_queue_leases = build_shared_cos_queue_leases_reusing_existing(
            &self.forwarding,
            &active_shards_by_egress_ifindex,
            num_workers,
            current_queue_leases.as_ref(),
        );
        let next_queue_vtime_floors = build_shared_cos_queue_vtime_floors_reusing_existing(
            &self.forwarding,
            num_workers,
            current_queue_vtime_floors.as_ref(),
        );
        if owner_changed {
            self.cos_owner_worker_by_queue = owner_map.clone();
            self.cos.owner_worker_by_queue.store(Arc::new(owner_map));
        }
        if !shared_cos_owner_live_by_queue_match(current_owner_live.as_ref(), &next_owner_live) {
            self.cos
                .owner_live_by_queue
                .store(Arc::new(next_owner_live));
        }
        if !shared_cos_root_leases_match(current_leases.as_ref(), &next_leases) {
            self.cos.root_leases.store(Arc::new(next_leases));
        }
        if !shared_cos_exact_backlogs_match(current_exact_backlogs.as_ref(), &next_exact_backlogs) {
            self.cos.exact_backlogs.store(Arc::new(next_exact_backlogs));
        }
        if !shared_cos_queue_leases_match(current_queue_leases.as_ref(), &next_queue_leases) {
            self.cos.queue_leases.store(Arc::new(next_queue_leases));
        }
        if !shared_cos_queue_vtime_floors_match(
            current_queue_vtime_floors.as_ref(),
            &next_queue_vtime_floors,
        ) {
            self.cos
                .queue_vtime_floors
                .store(Arc::new(next_queue_vtime_floors));
        }
    }

    /// Bump just the FIB generation counter without a full snapshot rebuild.
    /// Workers will invalidate flow cache entries with stale FIB generations.
    pub fn bump_fib_generation(&mut self, fib_generation: u32) {
        self.validation.fib_generation = fib_generation;
        self.shared_validation.store(Arc::new(self.validation));
    }

}

// #710: pure-function extraction of the coordinator-level aggregation
// so it can be unit-tested without constructing a full `Coordinator`
// fixture. The live bug this PR closes escaped CI because this exact
// summation layer lacked a regression; the function form lets us pin
// it in isolation. `Coordinator::cos_statuses` reads per-worker
// snapshots from `worker.cos_status` (built by
// `build_worker_cos_statuses` on the worker side) and sums them here.
pub(super) fn aggregate_cos_statuses_across_workers(
    worker_snapshots: &[Vec<crate::protocol::CoSInterfaceStatus>],
    owner_by_queue: &BTreeMap<(i32, u8), u32>,
) -> Vec<crate::protocol::CoSInterfaceStatus> {
    let mut interfaces = BTreeMap::<i32, crate::protocol::CoSInterfaceStatus>::new();
    let mut queue_maps = BTreeMap::<i32, BTreeMap<u8, crate::protocol::CoSQueueStatus>>::new();
    // #1628: tracks, per ifindex, whether the backlog-guarded
    // `waterfill_min_epochs_per_worker` MIN has been seeded by a first
    // active-exact-backlog worker yet. Cannot use `entry.worker_instances`
    // (counts idle workers too) nor `or_default()` (seeds 0, which would
    // pin a `.min()` to 0 forever — the r3 finding).
    let mut min_epochs_seeded = std::collections::HashSet::<i32>::new();
    for snapshot in worker_snapshots {
        for iface in snapshot.iter() {
            let entry = interfaces.entry(iface.ifindex).or_default();
            entry.ifindex = iface.ifindex;
            if entry.interface_name.is_empty() {
                entry.interface_name = iface.interface_name.clone();
            }
            entry.shaping_rate_bytes = entry.shaping_rate_bytes.max(iface.shaping_rate_bytes);
            entry.burst_bytes = entry.burst_bytes.max(iface.burst_bytes);
            entry.worker_instances = entry
                .worker_instances
                .saturating_add(iface.worker_instances);
            entry.timer_level0_sleepers = entry
                .timer_level0_sleepers
                .saturating_add(iface.timer_level0_sleepers);
            entry.timer_level1_sleepers = entry
                .timer_level1_sleepers
                .saturating_add(iface.timer_level1_sleepers);
            // #1628: per-interface waterfill counters. epochs +
            // phase1_budget_breaks SUM across workers (cluster event
            // counters, like timer_level*_sleepers).
            entry.waterfill_epochs =
                entry.waterfill_epochs.saturating_add(iface.waterfill_epochs);
            entry.waterfill_phase1_budget_breaks = entry
                .waterfill_phase1_budget_breaks
                .saturating_add(iface.waterfill_phase1_budget_breaks);
            // #1628 (code-review MAJOR): MIN-combine the PER-WORKER
            // `waterfill_min_epochs_per_worker` values, which the worker
            // side (interface_row.rs) already computed as the MIN over
            // each worker's OWN bindings-with-active-backlog — so a
            // healthy binding cannot mask a sibling locked binding within
            // one worker. A worker reports u64::MAX when it has NO
            // active-backlog binding (skip it); a backlogged binding that
            // completed 0 epochs reports 0 (the strongest lock-in signal,
            // which MUST be captured). Using the worker's per-binding MIN
            // (NOT iface.waterfill_epochs, the cross-binding SUM) is the
            // fix for the multi-binding masking the code review flagged.
            // Interfaces with at least one candidate are tracked in
            // `min_epochs_seeded`; interfaces with NO candidate are set to
            // u64::MAX after the loop (NOT 0) so an idle interface stays
            // distinguishable from a real 0-epoch lock-in.
            if iface.waterfill_min_epochs_per_worker != u64::MAX {
                if min_epochs_seeded.insert(iface.ifindex) {
                    entry.waterfill_min_epochs_per_worker =
                        iface.waterfill_min_epochs_per_worker;
                } else {
                    entry.waterfill_min_epochs_per_worker = entry
                        .waterfill_min_epochs_per_worker
                        .min(iface.waterfill_min_epochs_per_worker);
                }
            }
            let queue_map = queue_maps.entry(iface.ifindex).or_default();
            for queue in &iface.queues {
                let q = queue_map.entry(queue.queue_id).or_default();
                q.queue_id = queue.queue_id;
                if q.owner_worker_id.is_none() {
                    q.owner_worker_id = owner_by_queue
                        .get(&(iface.ifindex, queue.queue_id))
                        .copied();
                }
                if q.forwarding_class.is_empty() {
                    q.forwarding_class = queue.forwarding_class.clone();
                }
                if q.worker_instances == 0 {
                    q.priority = queue.priority;
                } else {
                    q.priority = q.priority.min(queue.priority);
                }
                q.exact = queue.exact;
                q.guarantee_enabled = queue.guarantee_enabled;
                // #784: flow_fair is per-worker-queue-runtime; OR
                // across workers so any worker with flow_fair=true
                // surfaces. active_flow_buckets_peak is already
                // max-aggregated by the worker snapshot; take max
                // here across workers too.
                if queue.flow_fair {
                    q.flow_fair = true;
                }
                if queue.active_flow_buckets_peak > q.active_flow_buckets_peak {
                    q.active_flow_buckets_peak = queue.active_flow_buckets_peak;
                }
                q.transmit_rate_bytes = q.transmit_rate_bytes.max(queue.transmit_rate_bytes);
                q.buffer_bytes = q.buffer_bytes.saturating_add(queue.buffer_bytes);
                q.worker_instances = q.worker_instances.saturating_add(queue.worker_instances);
                q.queued_packets = q.queued_packets.saturating_add(queue.queued_packets);
                q.queued_bytes = q.queued_bytes.saturating_add(queue.queued_bytes);
                q.runnable_instances = q
                    .runnable_instances
                    .saturating_add(queue.runnable_instances);
                q.parked_instances = q.parked_instances.saturating_add(queue.parked_instances);
                if q.next_wakeup_tick == 0
                    || (queue.next_wakeup_tick > 0 && queue.next_wakeup_tick < q.next_wakeup_tick)
                {
                    q.next_wakeup_tick = queue.next_wakeup_tick;
                }
                q.surplus_deficit_bytes = q
                    .surplus_deficit_bytes
                    .saturating_add(queue.surplus_deficit_bytes);
                // #710: aggregate drop-reason counters across per-worker
                // snapshots. The worker builder already summed across
                // queues within its local runtime; this layer sums
                // across workers for the final operator-facing view.
                q.admission_flow_share_drops = q
                    .admission_flow_share_drops
                    .saturating_add(queue.admission_flow_share_drops);
                q.admission_buffer_drops = q
                    .admission_buffer_drops
                    .saturating_add(queue.admission_buffer_drops);
                // #718: cross-worker aggregation for the ECN-marked
                // counter. Mirrors the other admission counters above.
                q.admission_ecn_marked = q
                    .admission_ecn_marked
                    .saturating_add(queue.admission_ecn_marked);
                q.root_token_starvation_parks = q
                    .root_token_starvation_parks
                    .saturating_add(queue.root_token_starvation_parks);
                q.queue_token_starvation_parks = q
                    .queue_token_starvation_parks
                    .saturating_add(queue.queue_token_starvation_parks);
                q.tx_ring_full_submit_stalls = q
                    .tx_ring_full_submit_stalls
                    .saturating_add(queue.tx_ring_full_submit_stalls);
                // #1628: per-class waterfill trace counters, summed across
                // worker snapshots (same as the drop/park counters above).
                q.waterfill_phase1_admissions = q
                    .waterfill_phase1_admissions
                    .saturating_add(queue.waterfill_phase1_admissions);
                q.waterfill_phase2_admissions = q
                    .waterfill_phase2_admissions
                    .saturating_add(queue.waterfill_phase2_admissions);
                q.waterfill_eligible_visits = q
                    .waterfill_eligible_visits
                    .saturating_add(queue.waterfill_eligible_visits);
                // #709: cross-worker aggregation for owner-profile
                // counters is sum, not max. Histograms and invocation
                // counters must stay coherent after aggregation;
                // per-bucket max can synthesize a profile no worker
                // observed while breaking `sum(hist) == invocations`.
                // See `merge_owner_profile_sum` /
                // `merge_cos_queue_owner_profile_sum`.
                super::worker::merge_cos_queue_owner_profile_sum(q, queue);
            }
        }
    }
    let mut out = Vec::with_capacity(interfaces.len());
    for (ifindex, mut iface) in interfaces {
        // #1628 (code-review r2, both reviewers): keep the u64::MAX
        // "no active-exact-backlog candidate" sentinel on the AGGREGATED
        // output too, rather than letting it collapse to the or_default()
        // 0. Otherwise an idle interface (0) and a hard 0-epoch lock-in
        // (0) collide and the metric is unalertable. With MAX preserved,
        // Prometheus suppresses the idle case (no series) and `0`
        // unambiguously means a backlogged binding that completed zero
        // epochs. An interface seeded by at least one active-backlog
        // worker keeps its real MIN (including a genuine 0).
        if !min_epochs_seeded.contains(&ifindex) {
            iface.waterfill_min_epochs_per_worker = u64::MAX;
        }
        if let Some(queue_map) = queue_maps.remove(&ifindex) {
            iface.queues = queue_map.into_values().collect();
            iface.owner_worker_id = unique_interface_owner_worker_id(&iface.queues);
            iface.nonempty_queues = iface
                .queues
                .iter()
                .filter(|queue| queue.queued_packets > 0 || queue.queued_bytes > 0)
                .count();
            iface.runnable_queues = iface
                .queues
                .iter()
                .filter(|queue| queue.runnable_instances > 0)
                .count();
        }
        out.push(iface);
    }
    out.sort_by(|a, b| {
        a.interface_name
            .cmp(&b.interface_name)
            .then(a.ifindex.cmp(&b.ifindex))
    });
    out
}

fn unique_interface_owner_worker_id(queues: &[crate::protocol::CoSQueueStatus]) -> Option<u32> {
    let mut owner_worker_id = None;
    for queue in queues {
        let queue_owner = queue.owner_worker_id?;
        match owner_worker_id {
            None => owner_worker_id = Some(queue_owner),
            Some(existing) if existing == queue_owner => {}
            Some(_) => return None,
        }
    }
    owner_worker_id
}

fn build_cos_owner_worker_by_queue(
    forwarding: &ForwardingState,
    workers: &BTreeMap<u32, Vec<BindingPlan>>,
) -> BTreeMap<(i32, u8), u32> {
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
    build_cos_owner_worker_by_queue_from_binding_ifindexes(forwarding, &worker_binding_ifindexes)
}

fn build_worker_binding_ifindexes_from_identities(
    identities: &BTreeMap<u32, BindingIdentity>,
) -> BTreeMap<u32, std::collections::BTreeSet<i32>> {
    let mut out = BTreeMap::<u32, std::collections::BTreeSet<i32>>::new();
    for ident in identities.values() {
        out.entry(ident.worker_id)
            .or_default()
            .insert(ident.ifindex);
    }
    out
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

fn build_cos_owner_worker_by_queue_from_binding_ifindexes(
    forwarding: &ForwardingState,
    worker_binding_ifindexes: &BTreeMap<u32, std::collections::BTreeSet<i32>>,
) -> BTreeMap<(i32, u8), u32> {
    build_cos_owner_worker_by_queue_with_fallback_ifindexes(
        forwarding,
        worker_binding_ifindexes,
        worker_binding_ifindexes,
    )
}

fn build_cos_owner_worker_by_queue_with_fallback_ifindexes(
    forwarding: &ForwardingState,
    preferred_worker_binding_ifindexes: &BTreeMap<u32, std::collections::BTreeSet<i32>>,
    fallback_worker_binding_ifindexes: &BTreeMap<u32, std::collections::BTreeSet<i32>>,
) -> BTreeMap<(i32, u8), u32> {
    let mut owner_by_queue = BTreeMap::new();
    let mut next_owner_slot_by_tx_ifindex = BTreeMap::<i32, usize>::new();
    let mut egress_ifindexes = forwarding
        .cos
        .interfaces
        .keys()
        .copied()
        .collect::<Vec<_>>();
    egress_ifindexes.sort_unstable();
    for egress_ifindex in egress_ifindexes {
        let tx_ifindex = resolve_tx_binding_ifindex(forwarding, egress_ifindex);
        let preferred_workers = preferred_worker_binding_ifindexes
            .iter()
            .filter_map(|(worker_id, ifindexes)| {
                ifindexes.contains(&tx_ifindex).then_some(*worker_id)
            })
            .collect::<Vec<_>>();
        let eligible_workers = if preferred_workers.is_empty() {
            fallback_worker_binding_ifindexes
                .iter()
                .filter_map(|(worker_id, ifindexes)| {
                    ifindexes.contains(&tx_ifindex).then_some(*worker_id)
                })
                .collect::<Vec<_>>()
        } else {
            preferred_workers
        };
        if eligible_workers.is_empty() {
            continue;
        }
        let next_slot = next_owner_slot_by_tx_ifindex.entry(tx_ifindex).or_default();
        let Some(iface) = forwarding.cos.interfaces.get(&egress_ifindex) else {
            continue;
        };
        for queue in &iface.queues {
            let owner_worker_id = eligible_workers[*next_slot % eligible_workers.len()];
            *next_slot += 1;
            owner_by_queue.insert((egress_ifindex, queue.queue_id), owner_worker_id);
        }
    }
    owner_by_queue
}

fn build_cos_active_shards_by_egress_ifindex_with_fallback_ifindexes(
    forwarding: &ForwardingState,
    preferred_worker_binding_ifindexes: &BTreeMap<u32, std::collections::BTreeSet<i32>>,
    fallback_worker_binding_ifindexes: &BTreeMap<u32, std::collections::BTreeSet<i32>>,
) -> BTreeMap<i32, usize> {
    let mut out = BTreeMap::new();
    let mut egress_ifindexes = forwarding
        .cos
        .interfaces
        .keys()
        .copied()
        .collect::<Vec<_>>();
    egress_ifindexes.sort_unstable();
    for egress_ifindex in egress_ifindexes {
        let tx_ifindex = resolve_tx_binding_ifindex(forwarding, egress_ifindex);
        let preferred_count = preferred_worker_binding_ifindexes
            .values()
            .filter(|ifindexes| ifindexes.contains(&tx_ifindex))
            .count();
        let fallback_count = fallback_worker_binding_ifindexes
            .values()
            .filter(|ifindexes| ifindexes.contains(&tx_ifindex))
            .count();
        let active_shards = if preferred_count > 0 {
            preferred_count
        } else {
            fallback_count
        }
        .max(1);
        out.insert(egress_ifindex, active_shards);
    }
    out
}

fn build_shared_cos_root_leases(
    forwarding: &ForwardingState,
    active_shards_by_egress_ifindex: &BTreeMap<i32, usize>,
) -> BTreeMap<i32, Arc<SharedCoSRootLease>> {
    build_shared_cos_root_leases_reusing_existing(
        forwarding,
        active_shards_by_egress_ifindex,
        &BTreeMap::new(),
    )
}

fn build_cos_owner_live_by_queue(
    forwarding: &ForwardingState,
    owner_by_queue: &BTreeMap<(i32, u8), u32>,
    identities: &BTreeMap<u32, BindingIdentity>,
    live: &BTreeMap<u32, Arc<BindingLiveState>>,
) -> BTreeMap<(i32, u8), Arc<BindingLiveState>> {
    let mut live_by_worker_ifindex = BTreeMap::<(u32, i32), Arc<BindingLiveState>>::new();
    for (slot, ident) in identities {
        let Some(binding_live) = live.get(slot) else {
            continue;
        };
        live_by_worker_ifindex
            .entry((ident.worker_id, ident.ifindex))
            .or_insert_with(|| binding_live.clone());
    }

    let mut out = BTreeMap::new();
    for (&(egress_ifindex, queue_id), &worker_id) in owner_by_queue {
        let tx_ifindex = resolve_tx_binding_ifindex(forwarding, egress_ifindex);
        let Some(owner_live) = live_by_worker_ifindex.get(&(worker_id, tx_ifindex)) else {
            continue;
        };
        out.insert((egress_ifindex, queue_id), owner_live.clone());
    }
    out
}

fn build_shared_cos_root_leases_reusing_existing(
    forwarding: &ForwardingState,
    active_shards_by_egress_ifindex: &BTreeMap<i32, usize>,
    existing: &BTreeMap<i32, Arc<SharedCoSRootLease>>,
) -> BTreeMap<i32, Arc<SharedCoSRootLease>> {
    let mut out = BTreeMap::new();
    for (&ifindex, iface) in &forwarding.cos.interfaces {
        let active_shards = active_shards_by_egress_ifindex
            .get(&ifindex)
            .copied()
            .unwrap_or(1)
            .max(1);
        let burst_bytes = iface.burst_bytes.max(64 * 1500);
        if let Some(lease) = existing.get(&ifindex).filter(|lease| {
            lease.matches_config(iface.shaping_rate_bytes, burst_bytes, active_shards)
        }) {
            out.insert(ifindex, lease.clone());
            continue;
        }
        out.insert(
            ifindex,
            Arc::new(SharedCoSRootLease::new(
                iface.shaping_rate_bytes,
                burst_bytes,
                active_shards,
            )),
        );
    }
    out
}

fn build_shared_cos_exact_backlogs_reusing_existing(
    forwarding: &ForwardingState,
    max_binding_slot: usize,
    existing: &BTreeMap<i32, Arc<SharedCoSExactBacklog>>,
) -> BTreeMap<i32, Arc<SharedCoSExactBacklog>> {
    let mut out = BTreeMap::new();
    for (&ifindex, iface) in &forwarding.cos.interfaces {
        if !iface.queues.iter().any(|queue| queue.exact) {
            continue;
        }
        if let Some(backlog) = existing
            .get(&ifindex)
            .filter(|backlog| backlog.matches_config(max_binding_slot))
        {
            out.insert(ifindex, backlog.clone());
            continue;
        }
        out.insert(
            ifindex,
            Arc::new(SharedCoSExactBacklog::new(max_binding_slot)),
        );
    }
    out
}

fn build_shared_cos_queue_leases_reusing_existing(
    forwarding: &ForwardingState,
    active_shards_by_egress_ifindex: &BTreeMap<i32, usize>,
    num_workers: usize,
    existing: &BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>,
) -> BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>> {
    // #1229 Phase 6 v8: max_worker_id = num_workers - 1 under the
    // current topology where worker IDs are dense from 0 to N-1.
    // If sparse worker IDs are ever introduced, this needs to flip
    // to true `max(worker_id)` over the worker map. last_planned_workers
    // is the same source V_min floors size against
    // (build_shared_cos_queue_vtime_floors_reusing_existing).
    let max_worker_id = num_workers.saturating_sub(1);
    let mut out = BTreeMap::new();
    for (&ifindex, iface) in &forwarding.cos.interfaces {
        let active_shards = active_shards_by_egress_ifindex
            .get(&ifindex)
            .copied()
            .unwrap_or(1)
            .max(1);
        for queue in &iface.queues {
            if !queue.exact || queue.transmit_rate_bytes == 0 {
                continue;
            }
            let burst_bytes = queue.buffer_bytes.max(64 * 1500);
            let key = (ifindex, queue.queue_id);
            let rate_mode = if queue.equal_flow_enforcement {
                V8RateMode::EqualFlowSuppress
            } else {
                V8RateMode::CstructDefault
            };
            // #1229 Phase 6 v8: emit v8 leases for guarantee-phase
            // exact queues. Reuse existing lease only if v8 mode AND
            // max_worker_id/mode match (otherwise rebuild).
            if let Some(lease) = existing.get(&key).filter(|lease| {
                lease.matches_config_v8(
                    queue.transmit_rate_bytes,
                    burst_bytes,
                    active_shards,
                    max_worker_id,
                    rate_mode,
                )
            }) {
                out.insert(key, lease.clone());
                continue;
            }
            out.insert(
                key,
                Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode(
                    queue.transmit_rate_bytes,
                    burst_bytes,
                    active_shards,
                    max_worker_id,
                    rate_mode,
                )),
            );
        }
    }
    out
}

fn shared_cos_root_leases_match(
    current: &BTreeMap<i32, Arc<SharedCoSRootLease>>,
    next: &BTreeMap<i32, Arc<SharedCoSRootLease>>,
) -> bool {
    current.len() == next.len()
        && current.iter().all(|(ifindex, lease)| {
            next.get(ifindex)
                .is_some_and(|next| Arc::ptr_eq(lease, next))
        })
}

fn shared_cos_exact_backlogs_match(
    current: &BTreeMap<i32, Arc<SharedCoSExactBacklog>>,
    next: &BTreeMap<i32, Arc<SharedCoSExactBacklog>>,
) -> bool {
    current.len() == next.len()
        && current.iter().all(|(ifindex, backlog)| {
            next.get(ifindex)
                .is_some_and(|next| Arc::ptr_eq(backlog, next))
        })
}

/// #917: build/reuse the per-shared_exact-queue V_min
/// coordination Arcs. Mirror of
/// `build_shared_cos_queue_leases_reusing_existing` — same
/// keying ((ifindex, queue_id)), same Arc-reuse discipline.
/// Each queue's `SharedCoSQueueVtimeFloor` is sized by the
/// configured worker count; if the worker count changes we
/// reallocate (slot count is fixed for the Arc's lifetime).
fn build_shared_cos_queue_vtime_floors_reusing_existing(
    forwarding: &ForwardingState,
    num_workers: usize,
    existing: &BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>,
) -> BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>> {
    let num_workers = num_workers.max(1);
    let mut out = BTreeMap::new();
    for (&ifindex, iface) in &forwarding.cos.interfaces {
        for queue in &iface.queues {
            // #917 Codex Q8: gate on shared_exact at allocation
            // time so owner-local-exact queues don't carry a
            // V_min floor. Owner-local queues have no peers
            // (single-owner by definition); a floor on those
            // would only consume memory and risk false
            // throttling if the read-path gate ever
            // regresses.
            //
            // #1598: this filter is intentionally STRICTER than the
            // routing-side `queue_uses_shared_exact_service` gate in
            // `worker/cos/mod.rs`. The routing-side gate admits
            // high-rate non-exact queues (e.g. uncapped class with a
            // fallback rate equal to the interface shaping rate) to
            // sharded multi-worker drain. V_min coordination is an
            // exact-only concept (per-queue lease serves the
            // configured rate cap); allocating a floor for non-exact
            // queues would be useless work. So both gates keep their
            // own predicate: shared_exact-routing is broader,
            // V_min-floor is exact-only.
            if !queue.exact
                || queue.transmit_rate_bytes < super::worker::COS_SHARED_EXACT_MIN_RATE_BYTES
            {
                continue;
            }
            let key = (ifindex, queue.queue_id);
            if let Some(floor) = existing.get(&key).filter(|f| f.slots.len() == num_workers) {
                out.insert(key, floor.clone());
                continue;
            }
            out.insert(key, Arc::new(SharedCoSQueueVtimeFloor::new(num_workers)));
        }
    }
    out
}

fn shared_cos_queue_vtime_floors_match(
    current: &BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>,
    next: &BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>,
) -> bool {
    current.len() == next.len()
        && current
            .iter()
            .all(|(key, floor)| next.get(key).is_some_and(|next| Arc::ptr_eq(floor, next)))
}

fn shared_cos_queue_leases_match(
    current: &BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>,
    next: &BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>,
) -> bool {
    current.len() == next.len()
        && current
            .iter()
            .all(|(key, lease)| next.get(key).is_some_and(|next| Arc::ptr_eq(lease, next)))
}

fn shared_cos_owner_live_by_queue_match(
    current: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
    next: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
) -> bool {
    current.len() == next.len()
        && current.iter().all(|(key, live)| {
            next.get(key)
                .is_some_and(|next_live| Arc::ptr_eq(live, next_live))
        })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
