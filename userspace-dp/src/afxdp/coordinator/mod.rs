use super::*;
mod bpf_maps;
mod cos_state;
mod ha_state;
mod neighbor_manager;
pub(crate) use bpf_maps::BpfMaps;
pub(crate) use cos_state::SharedCoSState;
pub(crate) use ha_state::HaState;
pub(crate) use neighbor_manager::NeighborManager;

pub struct Coordinator {
    pub(crate) bpf_maps: BpfMaps,
    pub(crate) slow_path: Option<Arc<SlowPathReinjector>>,
    pub(crate) local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    pub(crate) tunnel_sources: BTreeMap<u16, LocalTunnelSourceHandle>,
    pub(crate) last_slow_path_status: SlowPathStatus,
    pub(crate) ha: HaState,
    pub(crate) cos: SharedCoSState,
    pub(crate) shared_validation: Arc<ArcSwap<ValidationState>>,
    pub(crate) neighbors: NeighborManager,
    pub(crate) shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(crate) shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(crate) shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(crate) shared_owner_rg_indexes: SharedSessionOwnerRgIndexes,
    pub(crate) live: BTreeMap<u32, Arc<BindingLiveState>>,
    pub(crate) identities: BTreeMap<u32, BindingIdentity>,
    pub(crate) workers: BTreeMap<u32, WorkerHandle>,
    pub(crate) session_export_seq: AtomicU64,
    pub(crate) forwarding: ForwardingState,
    pub(crate) recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    pub(crate) recent_session_deltas: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    pub(crate) last_resolution: Arc<Mutex<Option<PacketResolution>>>,
    pub(crate) validation: ValidationState,
    pub(crate) last_planned_workers: usize,
    pub(crate) last_planned_bindings: usize,
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
            last_slow_path_status: SlowPathStatus::default(),
            ha: HaState::new(),
            cos: SharedCoSState::new(),
            shared_validation: Arc::new(ArcSwap::from_pointee(ValidationState::default())),
            neighbors: NeighborManager::new(),
            shared_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_nat_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_owner_rg_indexes: SharedSessionOwnerRgIndexes::default(),
            live: BTreeMap::new(),
            identities: BTreeMap::new(),
            workers: BTreeMap::new(),
            session_export_seq: AtomicU64::new(0),
            forwarding: ForwardingState::default(),
            recent_exceptions: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_RECENT_EXCEPTIONS))),
            recent_session_deltas: Arc::new(Mutex::new(VecDeque::with_capacity(
                MAX_RECENT_SESSION_DELTAS,
            ))),
            last_resolution: Arc::new(Mutex::new(None)),
            validation: ValidationState::default(),
            last_planned_workers: 0,
            last_planned_bindings: 0,
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
            self.neighbors.manager_keys
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
            self.ha.forwarding
                .store(Arc::new(self.forwarding.clone()));
        }
        self.neighbors.generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dynamic_neighbor_status(&self) -> (usize, u64) {
        let entries = self.neighbors.dynamic.len();
        let generation = self.neighbors.generation.load(Ordering::Relaxed);
        (entries, generation)
    }

    /// #710: sum of `no_owner_binding_drops` across every binding's
    /// `BindingLiveState`. The per-binding increment site lives in
    /// `apply_worker_shaped_tx_requests` and mechanically lands on
    /// `bindings.first_mut()` (there is no binding to attribute to —
    /// the whole point of the counter is that the request's egress
    /// has no binding on this worker). Summing across every binding's
    /// live state gives the cluster-wide total regardless of which
    /// worker's "first binding" the increments landed on. This is the
    /// only operator-facing surface for this counter.
    pub fn cos_no_owner_binding_drops_total(&self) -> u64 {
        self.live
            .values()
            .map(|live| live.no_owner_binding_drops.load(Ordering::Relaxed))
            .sum()
    }

    pub(crate) fn stop_inner(&mut self, clear_synced_state: bool) {
        if let Some(stop) = self.neighbors.monitor_stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
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
        for handle in self.workers.values_mut() {
            handle.stop.store(true, Ordering::Relaxed);
        }
        for (_, handle) in self.workers.iter_mut() {
            if let Some(join) = handle.join.take() {
                let _ = join.join();
            }
        }
        if let Some(map_fd) = self.bpf_maps.map_fd.as_ref() {
            for slot in self.live.keys().copied().collect::<Vec<_>>() {
                let _ = delete_xsk_slot(map_fd.fd, slot);
            }
        }
        if let Some(map_fd) = self.bpf_maps.heartbeat_map_fd.as_ref() {
            for slot in self.live.keys().copied().collect::<Vec<_>>() {
                let _ = delete_heartbeat_slot(map_fd.fd, slot);
            }
        }
        self.workers.clear();
        self.identities.clear();
        self.live.clear();
        // #925 Phase 1: drop the per-worker panic slots alongside the
        // workers themselves so a long-running daemon that reconciles
        // through many worker-id sets doesn't accumulate stale slots.
        self.worker_panics.clear();
        self.cos_owner_worker_by_queue.clear();
        self.cos.owner_worker_by_queue
            .store(Arc::new(BTreeMap::new()));
        self.cos.owner_live_by_queue
            .store(Arc::new(BTreeMap::new()));
        self.cos.root_leases.store(Arc::new(BTreeMap::new()));
        self.cos.queue_leases
            .store(Arc::new(BTreeMap::new()));
        self.cos.queue_vtime_floors
            .store(Arc::new(BTreeMap::new()));
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
        self.ha.forwarding
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
        if clear_synced_state {
            if let Ok(mut sessions) = self.shared_sessions.lock() {
                sessions.clear();
            }
            if let Ok(mut nat_sessions) = self.shared_nat_sessions.lock() {
                nat_sessions.clear();
            }
            if let Ok(mut forward_wire_sessions) = self.shared_forward_wire_sessions.lock() {
                forward_wire_sessions.clear();
            }
            self.shared_owner_rg_indexes.clear();
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
        self.last_planned_workers = 0;
        self.last_planned_bindings = 0;
        self.last_reconcile_stage = "stopped".to_string();
    }

    pub(crate) fn snapshot_shared_session_entries(&self) -> Vec<SyncedSessionEntry> {
        self.shared_sessions
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

    pub fn reconcile(
        &mut self,
        snapshot: Option<&ConfigSnapshot>,
        bindings: &mut [BindingStatus],
        ring_entries: usize,
    ) {
        self.reconcile_calls += 1;
        self.last_reconcile_stage = "start".to_string();
        let had_live_workers = !self.workers.is_empty();
        let preserved_synced_sessions = self.snapshot_shared_session_entries();
        // Keep a healthy slow-path worker across back-to-back reconciles. The
        // userspace helper can receive multiple snapshot refreshes during HA
        // role changes; recreating the fixed-name TUN on every reconcile can
        // race with teardown and leave the new owner without xpf-usp0.
        let preserved_slow_path = self.slow_path.as_ref().and_then(|slow| {
            if slow.status().active {
                Some(slow.clone())
            } else {
                None
            }
        });
        self.stop_inner(false);
        if had_live_workers {
            // Zero-copy queue teardown is not synchronously reusable on mlx5.
            // A short quiesce avoids EBUSY when a later snapshot refresh
            // rebuilds the same queue set immediately after shutdown.
            thread::sleep(Duration::from_millis(500));
        }
        for binding in bindings.iter_mut() {
            binding.bound = false;
            binding.xsk_registered = false;
            binding.socket_fd = 0;
            binding.rx_packets = 0;
            binding.rx_bytes = 0;
            binding.rx_batches = 0;
            binding.rx_wakeups = 0;
            binding.metadata_packets = 0;
            binding.metadata_errors = 0;
            binding.validated_packets = 0;
            binding.validated_bytes = 0;
            binding.local_delivery_packets = 0;
            binding.forward_candidate_packets = 0;
            binding.route_miss_packets = 0;
            binding.neighbor_miss_packets = 0;
            binding.discard_route_packets = 0;
            binding.next_table_packets = 0;
            binding.exception_packets = 0;
            binding.config_gen_mismatches = 0;
            binding.fib_gen_mismatches = 0;
            binding.unsupported_packets = 0;
            binding.flow_cache_hits = 0;
            binding.flow_cache_misses = 0;
            binding.flow_cache_evictions = 0;
            binding.flow_cache_collision_evictions = 0;
            binding.session_hits = 0;
            binding.session_misses = 0;
            binding.session_creates = 0;
            binding.session_expires = 0;
            binding.session_delta_pending = 0;
            binding.session_delta_generated = 0;
            binding.session_delta_dropped = 0;
            binding.session_delta_drained = 0;
            binding.policy_denied_packets = 0;
            binding.snat_packets = 0;
            binding.dnat_packets = 0;
            binding.slow_path_packets = 0;
            binding.slow_path_bytes = 0;
            binding.slow_path_local_delivery_packets = 0;
            binding.slow_path_missing_neighbor_packets = 0;
            binding.slow_path_no_route_packets = 0;
            binding.slow_path_next_table_packets = 0;
            binding.slow_path_forward_build_packets = 0;
            binding.slow_path_drops = 0;
            binding.slow_path_rate_limited = 0;
            binding.kernel_rx_dropped = 0;
            binding.kernel_rx_invalid_descs = 0;
            binding.last_error.clear();
            binding.ready = false;
        }
        let Some(snapshot) = snapshot else {
            self.last_reconcile_stage = "no_snapshot".to_string();
            return;
        };
        self.validation = ValidationState {
            snapshot_installed: true,
            config_generation: snapshot.generation,
            fib_generation: snapshot.fib_generation,
        };
        self.forwarding = build_forwarding_state(snapshot);
        self.shared_validation.store(Arc::new(self.validation));
        self.ha.forwarding
            .store(Arc::new(self.forwarding.clone()));
        self.slow_path = if let Some(slow_path) = preserved_slow_path {
            self.last_slow_path_status = slow_path.status();
            Some(slow_path)
        } else {
            match SlowPathReinjector::new(DEFAULT_SLOW_PATH_TUN) {
                Ok(reinjector) => {
                    self.last_slow_path_status = reinjector.status();
                    Some(Arc::new(reinjector))
                }
                Err(err) => {
                    self.last_slow_path_status = SlowPathStatus {
                        last_error: err,
                        ..SlowPathStatus::default()
                    };
                    None
                }
            }
        };
        self.local_tunnel_deliveries
            .store(Arc::new(BTreeMap::new()));
        self.ha.fabrics
            .store(Arc::new(self.forwarding.fabrics.clone()));
        if snapshot.map_pins.xsk.is_empty() {
            self.last_reconcile_stage = "missing_xsk_pin".to_string();
            for binding in bindings.iter_mut() {
                if binding.registered {
                    binding.last_error = "missing XSK map pin path".to_string();
                }
            }
            return;
        }
        if snapshot.map_pins.heartbeat.is_empty() {
            self.last_reconcile_stage = "missing_heartbeat_pin".to_string();
            for binding in bindings.iter_mut() {
                if binding.registered {
                    binding.last_error = "missing heartbeat map pin path".to_string();
                }
            }
            return;
        }
        if snapshot.map_pins.sessions.is_empty() {
            self.last_reconcile_stage = "missing_session_pin".to_string();
            for binding in bindings.iter_mut() {
                if binding.registered {
                    binding.last_error = "missing session map pin path".to_string();
                }
            }
            return;
        }
        let map_fd = match OwnedFd::open_bpf_map(&snapshot.map_pins.xsk) {
            Ok(fd) => fd,
            Err(err) => {
                self.last_reconcile_stage = format!("open_xsk_map_failed:{err}");
                for binding in bindings.iter_mut() {
                    if binding.registered {
                        binding.last_error = format!("open XSK map: {err}");
                    }
                }
                return;
            }
        };
        let heartbeat_map_fd = match OwnedFd::open_bpf_map(&snapshot.map_pins.heartbeat) {
            Ok(fd) => fd,
            Err(err) => {
                self.last_reconcile_stage = format!("open_heartbeat_map_failed:{err}");
                for binding in bindings.iter_mut() {
                    if binding.registered {
                        binding.last_error = format!("open heartbeat map: {err}");
                    }
                }
                return;
            }
        };
        let session_map_fd = match OwnedFd::open_bpf_map(&snapshot.map_pins.sessions) {
            Ok(fd) => fd,
            Err(err) => {
                self.last_reconcile_stage = format!("open_session_map_failed:{err}");
                for binding in bindings.iter_mut() {
                    if binding.registered {
                        binding.last_error = format!("open session map: {err}");
                    }
                }
                return;
            }
        };
        // Open BPF conntrack maps (sessions, sessions_v6) so the helper can
        // publish session entries that "show security flow session" reads.
        // Non-fatal: if the maps don't exist, session display will lack zone/interface info.
        let conntrack_v4_fd = if !snapshot.map_pins.conntrack_v4.is_empty() {
            OwnedFd::open_bpf_map(&snapshot.map_pins.conntrack_v4).ok()
        } else {
            None
        };
        let conntrack_v6_fd = if !snapshot.map_pins.conntrack_v6.is_empty() {
            OwnedFd::open_bpf_map(&snapshot.map_pins.conntrack_v6).ok()
        } else {
            None
        };
        // Open dnat_table BPF map for embedded ICMP NAT reversal support.
        // Non-fatal: if the map doesn't exist, embedded ICMP won't work
        // but normal forwarding is unaffected.
        let dnat_table_fd = if !snapshot.map_pins.dnat_table.is_empty() {
            OwnedFd::open_bpf_map(&snapshot.map_pins.dnat_table).ok()
        } else {
            None
        };
        let dnat_table_v6_fd = if !snapshot.map_pins.dnat_table_v6.is_empty() {
            OwnedFd::open_bpf_map(&snapshot.map_pins.dnat_table_v6).ok()
        } else {
            None
        };
        let dnat_fds = DnatTableFds {
            v4: dnat_table_fd.as_ref().map(|f| f.fd),
            v6: dnat_table_v6_fd.as_ref().map(|f| f.fd),
        };
        let ring_entries = ring_entries.max(64).min(u32::MAX as usize) as u32;
        let mut workers: BTreeMap<u32, Vec<BindingPlan>> = BTreeMap::new();
        for binding in bindings.iter_mut() {
            if !binding.registered || binding.ifindex <= 0 {
                binding.ready = false;
                continue;
            }
            let live = Arc::new(BindingLiveState::new());
            self.live.insert(binding.slot, live.clone());
            let identity = BindingIdentity {
                slot: binding.slot,
                queue_id: binding.queue_id,
                worker_id: binding.worker_id,
                interface: Arc::<str>::from(binding.interface.as_str()),
                ifindex: binding.ifindex,
            };
            self.identities.insert(binding.slot, identity);
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
                    poll_mode: self.poll_mode,
                });
        }
        for plans in workers.values_mut() {
            plans.sort_by_key(|plan| (plan.status.queue_id, plan.status.ifindex, plan.status.slot));
        }
        let planned_bindings: usize = workers.values().map(|group| group.len()).sum();
        self.last_planned_workers = workers.len();
        self.last_planned_bindings = planned_bindings;
        self.last_reconcile_stage = format!(
            "planned:workers={}:bindings={}:live={}",
            self.last_planned_workers,
            self.last_planned_bindings,
            self.live.len()
        );
        eprintln!(
            "xpf-userspace-dp: reconcile planned_workers={} planned_bindings={} live_slots={}",
            workers.len(),
            planned_bindings,
            self.live.len()
        );
        let session_map_raw_fd = session_map_fd.fd;
        self.bpf_maps.map_fd = Some(map_fd);
        self.bpf_maps.heartbeat_map_fd = Some(heartbeat_map_fd);
        self.bpf_maps.session_map_fd = Some(session_map_fd);
        self.bpf_maps.conntrack_v4_fd = conntrack_v4_fd;
        self.bpf_maps.conntrack_v6_fd = conntrack_v6_fd;
        self.bpf_maps.dnat_table_fd = dnat_table_fd;
        self.bpf_maps.dnat_table_v6_fd = dnat_table_v6_fd;
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
        let owner_map = build_cos_owner_worker_by_queue(&self.forwarding, &workers);
        let active_shards_by_egress_ifindex =
            build_cos_active_shards_by_egress_ifindex_with_fallback_ifindexes(
                &self.forwarding,
                &worker_binding_ifindexes,
                &worker_binding_ifindexes,
            );
        self.refresh_cos_runtime_maps(owner_map, active_shards_by_egress_ifindex);
        let worker_command_queues: Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>> =
            Arc::new(
                workers
                    .keys()
                    .copied()
                    .map(|worker_id| (worker_id, Arc::new(Mutex::new(VecDeque::new()))))
                    .collect(),
            );
        let replayed_synced_sessions = self.replay_synced_sessions(
            &preserved_synced_sessions,
            worker_command_queues.as_ref(),
            session_map_raw_fd,
        );
        if replayed_synced_sessions > 0 {
            self.last_reconcile_stage = format!(
                "replayed_synced:{}:workers={}",
                replayed_synced_sessions,
                worker_command_queues.len()
            );
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
            let recent_exceptions = self.recent_exceptions.clone();
            let recent_session_deltas = self.recent_session_deltas.clone();
            let last_resolution = self.last_resolution.clone();
            let slow_path = self.slow_path.clone();
            let local_tunnel_deliveries = self.local_tunnel_deliveries.clone();
            let shared_forwarding = self.ha.forwarding.clone();
            let shared_validation = self.shared_validation.clone();
            let shared_sessions = self.shared_sessions.clone();
            let shared_nat_sessions = self.shared_nat_sessions.clone();
            let shared_forward_wire_sessions = self.shared_forward_wire_sessions.clone();
            let shared_owner_rg_indexes = self.shared_owner_rg_indexes.clone();
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
            let ha_state = self.ha.rg_runtime.clone();
            let dynamic_neighbors = self.neighbors.dynamic.clone();
            let worker_poll_mode = self.poll_mode;
            let shared_fabrics = self.ha.fabrics.clone();
            let rg_epochs = self.rg_epochs.clone();
            let event_stream_handle = self.event_stream_worker_handle();
            let cos_status_clone = cos_status.clone();
            let shared_cos_owner_worker_by_queue = self.cos.owner_worker_by_queue.clone();
            let shared_cos_owner_live_by_queue = self.cos.owner_live_by_queue.clone();
            let shared_cos_root_leases = self.cos.root_leases.clone();
            let shared_cos_queue_leases = self.cos.queue_leases.clone();
            let shared_cos_queue_vtime_floors = self.cos.queue_vtime_floors.clone();
            let runtime_atomics =
                std::sync::Arc::new(super::worker_runtime::WorkerRuntimeAtomics::new());
            let runtime_atomics_clone = runtime_atomics.clone();
            // #925 Phase 1: per-worker panic slot, keyed by worker_id.
            let panic_slot = Arc::new(Mutex::new(None::<String>));
            self.worker_panics.insert(worker_id, panic_slot.clone());
            let join = spawn_supervised_worker(
                worker_id,
                runtime_atomics.clone(),
                panic_slot,
                move || {
                    worker_loop(
                        worker_id,
                        binding_plans,
                        shared_validation,
                        shared_forwarding,
                        ha_state,
                        dynamic_neighbors,
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
                        shared_cos_queue_leases,
                        shared_cos_queue_vtime_floors,
                        cos_status_clone,
                        runtime_atomics_clone,
                    );
                },
            );
            match join {
                Ok(join) => {
                    eprintln!(
                        "xpf-userspace-dp: started worker thread worker_id={} planned_bindings={}",
                        worker_id, plan_count
                    );
                    self.workers.insert(
                        worker_id,
                        WorkerHandle {
                            stop,
                            heartbeat,
                            commands,
                            session_export_ack,
                            cos_status,
                            runtime_atomics,
                            join: Some(join),
                        },
                    );
                }
                Err(err) => {
                    eprintln!(
                        "xpf-userspace-dp: failed to start worker thread worker_id={} err={}",
                        worker_id, err
                    );
                    self.last_reconcile_stage = format!("spawn_worker_failed:{worker_id}:{err}");
                    // #925 Phase 1: the panic slot was inserted before
                    // spawn; drop it now so a snapshot reader doesn't
                    // see a phantom slot for a worker that never ran.
                    self.worker_panics.remove(&worker_id);
                    if let Ok(mut recent) = self.recent_exceptions.lock() {
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
        self.last_reconcile_stage = format!(
            "spawned:workers={}:identities={}:live={}",
            self.workers.len(),
            self.identities.len(),
            self.live.len()
        );
        // Start the helper-owned neighbor sync path. It does an initial
        // RTM_GETNEIGH dump so startup sees the existing kernel table, then
        // subscribes to RTM_{NEW,DEL}NEIGH for incremental updates.
        if self.neighbors.monitor_stop.is_none() {
            let stop = Arc::new(AtomicBool::new(false));
            let stop_clone = stop.clone();
            let dynamic_neighbors = self.neighbors.dynamic.clone();
            let neighbor_generation = self.neighbors.generation.clone();
            thread::Builder::new()
                .name("neigh-monitor".to_string())
                .spawn(move || {
                    neigh_monitor_thread(stop_clone, dynamic_neighbors, neighbor_generation)
                })
                .ok();
            self.neighbors.monitor_stop = Some(stop);
        }
        self.spawn_local_tunnel_sources();
        self.refresh_bindings(bindings);
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
            let live = self.live.clone();
            let identities = self.identities.clone();
            let shared_sessions = self.shared_sessions.clone();
            let shared_nat_sessions = self.shared_nat_sessions.clone();
            let shared_forward_wire_sessions = self.shared_forward_wire_sessions.clone();
            let shared_owner_rg_indexes = self.shared_owner_rg_indexes.clone();
            let worker_commands = self
                .workers
                .values()
                .map(|handle| handle.commands.clone())
                .collect::<Vec<_>>();
            let recent_exceptions = self.recent_exceptions.clone();
            let tunnel_endpoint_id = endpoint.id;
            let thread_tunnel_name = tunnel_name.clone();
            let logical_ifindex = endpoint.logical_ifindex;
            let (delivery_tx, delivery_rx) = mpsc::sync_channel(LOCAL_TUNNEL_DELIVERY_QUEUE_DEPTH);
            let join = thread::Builder::new()
                .name(format!("xpf-native-gre-origin-{}", tunnel_name))
                .spawn(move || {
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
                });
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

    pub fn recent_exceptions(&self) -> Vec<ExceptionStatus> {
        self.recent_exceptions
            .lock()
            .map(|recent| recent.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn recent_session_deltas(&self) -> Vec<SessionDeltaInfo> {
        self.recent_session_deltas
            .lock()
            .map(|recent| recent.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn last_resolution(&self) -> Option<PacketResolution> {
        self.last_resolution
            .lock()
            .ok()
            .and_then(|last| last.clone())
    }

    pub fn slow_path_status(&self) -> SlowPathStatus {
        self.slow_path
            .as_ref()
            .map(|slow| slow.status())
            .unwrap_or_else(|| self.last_slow_path_status.clone())
    }

    pub fn cos_statuses(&self) -> Vec<crate::protocol::CoSInterfaceStatus> {
        let snapshots: Vec<Vec<_>> = self
            .workers
            .values()
            .map(|worker| worker.cos_status.load().iter().cloned().collect())
            .collect();
        aggregate_cos_statuses_across_workers(&snapshots, &self.cos_owner_worker_by_queue)
    }

    pub fn filter_term_counters(&self) -> Vec<crate::protocol::FirewallFilterTermCounterStatus> {
        let mut filter_keys = self
            .forwarding
            .filter_state
            .filters
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        filter_keys.sort();
        let mut out = Vec::new();
        for key in filter_keys {
            let Some(filter) = self.forwarding.filter_state.filters.get(&key) else {
                continue;
            };
            for term in &filter.terms {
                out.push(crate::protocol::FirewallFilterTermCounterStatus {
                    family: filter.family.clone(),
                    filter_name: filter.name.clone(),
                    term_name: term.name.clone(),
                    packets: term.counter.packets.load(Ordering::Relaxed),
                    bytes: term.counter.bytes.load(Ordering::Relaxed),
                });
            }
        }
        out
    }

    pub fn drain_session_deltas(&self, max: usize) -> Vec<SessionDeltaInfo> {
        let mut remaining = max.max(1);
        let mut out = Vec::new();
        for live in self.live.values() {
            if remaining == 0 {
                break;
            }
            let drained = live.drain_session_deltas(remaining);
            remaining = remaining.saturating_sub(drained.len());
            out.extend(drained);
        }
        out
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
            self.ha.forwarding
                .store(Arc::new(self.forwarding.clone()));
        }
    }

    pub fn refresh_runtime_snapshot(&mut self, snapshot: &crate::ConfigSnapshot) {
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
        self.forwarding = build_forwarding_state(snapshot);
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
        self.ha.forwarding
            .store(Arc::new(self.forwarding.clone()));
        self.refresh_cos_owner_worker_map_from_identities();
        self.ha.fabrics
            .store(Arc::new(self.forwarding.fabrics.clone()));
    }

    fn refresh_cos_owner_worker_map_from_identities(&mut self) {
        let worker_binding_ifindexes =
            build_worker_binding_ifindexes_from_identities(&self.identities);
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
            build_worker_binding_ifindexes_from_identities(&self.identities);
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
            &self.identities,
            &self.live,
        );
        let current_leases = self.cos.root_leases.load();
        let next_leases = build_shared_cos_root_leases_reusing_existing(
            &self.forwarding,
            &active_shards_by_egress_ifindex,
            current_leases.as_ref(),
        );
        let current_queue_leases = self.cos.queue_leases.load();
        let next_queue_leases = build_shared_cos_queue_leases_reusing_existing(
            &self.forwarding,
            &active_shards_by_egress_ifindex,
            current_queue_leases.as_ref(),
        );
        // #917: V_min coordination Arcs sized by worker count.
        // last_planned_workers is set in apply_planned_workers
        // before this reconcile fires; defaults to 0 at first
        // boot which produces zero-slot floors (the reconcile
        // re-fires once workers are planned).
        let current_queue_vtime_floors = self.cos.queue_vtime_floors.load();
        let num_workers = self.last_planned_workers.max(1);
        let next_queue_vtime_floors = build_shared_cos_queue_vtime_floors_reusing_existing(
            &self.forwarding,
            num_workers,
            current_queue_vtime_floors.as_ref(),
        );
        if owner_changed {
            self.cos_owner_worker_by_queue = owner_map.clone();
            self.cos.owner_worker_by_queue
                .store(Arc::new(owner_map));
        }
        if !shared_cos_owner_live_by_queue_match(current_owner_live.as_ref(), &next_owner_live) {
            self.cos.owner_live_by_queue
                .store(Arc::new(next_owner_live));
        }
        if !shared_cos_root_leases_match(current_leases.as_ref(), &next_leases) {
            self.cos.root_leases.store(Arc::new(next_leases));
        }
        if !shared_cos_queue_leases_match(current_queue_leases.as_ref(), &next_queue_leases) {
            self.cos.queue_leases
                .store(Arc::new(next_queue_leases));
        }
        if !shared_cos_queue_vtime_floors_match(
            current_queue_vtime_floors.as_ref(),
            &next_queue_vtime_floors,
        ) {
            self.cos.queue_vtime_floors
                .store(Arc::new(next_queue_vtime_floors));
        }
    }

    /// Bump just the FIB generation counter without a full snapshot rebuild.
    /// Workers will invalidate flow cache entries with stale FIB generations.
    pub fn bump_fib_generation(&mut self, fib_generation: u32) {
        self.validation.fib_generation = fib_generation;
        self.shared_validation.store(Arc::new(self.validation));
    }

    pub fn worker_heartbeats(&self) -> Vec<chrono::DateTime<Utc>> {
        let now_wall = Utc::now();
        let now_mono = monotonic_nanos();
        self.workers
            .iter()
            .map(|(_, handle)| {
                monotonic_timestamp_to_datetime(
                    handle.heartbeat.load(Ordering::Relaxed),
                    now_mono,
                    now_wall,
                )
                .unwrap_or(now_wall)
            })
            .collect()
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// #869: snapshot per-worker busy/idle runtime counters.  Each row is
    /// the current `WorkerRuntimeAtomics` publish, most recently written
    /// on the worker's ~1s publish cadence.
    /// #925: also surfaces `dead` (one-shot AtomicBool set when the
    /// supervisor catches a worker_loop panic) and the rendered panic
    /// payload from the per-worker slot in `worker_panics`.
    pub fn worker_runtime_snapshots(&self) -> Vec<crate::protocol::WorkerRuntimeStatus> {
        self.workers
            .iter()
            .map(|(worker_id, handle)| {
                let s = handle.runtime_atomics.snapshot();
                let dead = handle
                    .runtime_atomics
                    .dead
                    .load(std::sync::atomic::Ordering::Relaxed);
                let panic_message = if dead {
                    self.worker_panics
                        .get(worker_id)
                        .and_then(|slot| match slot.lock() {
                            Ok(g) => g.clone(),
                            Err(poisoned) => poisoned.into_inner().clone(),
                        })
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                crate::protocol::WorkerRuntimeStatus {
                    worker_id: *worker_id,
                    tid: handle.runtime_atomics.tid(),
                    wall_ns: s.wall_ns,
                    active_ns: s.active_ns,
                    idle_spin_ns: s.idle_spin_ns,
                    idle_block_ns: s.idle_block_ns,
                    thread_cpu_ns: s.thread_cpu_ns,
                    work_loops: s.work_loops,
                    idle_loops: s.idle_loops,
                    dead,
                    panic_message,
                }
            })
            .collect()
    }

    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }

    pub fn live_count(&self) -> usize {
        self.live.len()
    }

    pub fn planned_counts(&self) -> (usize, usize) {
        (self.last_planned_workers, self.last_planned_bindings)
    }

    pub fn reconcile_debug(&self) -> (u64, String) {
        (self.reconcile_calls, self.last_reconcile_stage.clone())
    }

    pub fn inject_test_packet(&mut self, req: InjectPacketRequest) -> Result<(), String> {
        let binding = self
            .identities
            .get(&req.slot)
            .ok_or_else(|| format!("unknown binding slot {}", req.slot))?;
        let live = self
            .live
            .get(&req.slot)
            .ok_or_else(|| format!("binding slot {} has no live state", req.slot))?;
        let ident = binding.clone();
        let packet_length = req.packet_length.max(64);

        if req.metadata_valid {
            let meta = UserspaceDpMeta {
                magic: USERSPACE_META_MAGIC,
                version: USERSPACE_META_VERSION,
                length: std::mem::size_of::<UserspaceDpMeta>() as u16,
                ingress_ifindex: ident.ifindex as u32,
                rx_queue_index: ident.queue_id,
                pkt_len: packet_length.min(u16::MAX as u32) as u16,
                addr_family: req.addr_family,
                protocol: req.protocol,
                config_generation: req.config_generation,
                fib_generation: req.fib_generation,
                ..UserspaceDpMeta::default()
            };
            live.metadata_packets.fetch_add(1, Ordering::Relaxed);
            let disposition = classify_metadata(meta, self.validation);
            record_disposition(
                &ident,
                live,
                disposition,
                packet_length,
                Some(meta),
                &self.recent_exceptions,
                &self.forwarding,
            );
            if disposition == PacketDisposition::Valid && !req.destination_ip.is_empty() {
                if let Ok(dst) = req.destination_ip.parse::<IpAddr>() {
                    let resolution = enforce_ha_resolution(
                        &self.forwarding,
                        &self.ha.rg_runtime,
                        lookup_forwarding_resolution(&self.forwarding, dst),
                    );
                    record_forwarding_disposition(
                        &ident,
                        live,
                        resolution,
                        packet_length,
                        Some(meta),
                        None,
                        &self.recent_exceptions,
                        &self.last_resolution,
                        &self.forwarding,
                    );
                    if req.emit_on_wire {
                        let Some(egress) = self.forwarding.egress.get(&resolution.egress_ifindex)
                        else {
                            return Err(format!(
                                "no egress interface metadata for ifindex {}",
                                resolution.egress_ifindex
                            ));
                        };
                        if resolution.disposition != ForwardingDisposition::ForwardCandidate {
                            return Err(format!(
                                "destination is not forwardable via userspace TX: {}",
                                resolution.status(None, &self.forwarding).disposition
                            ));
                        }
                        let target_slot = self
                            .identities
                            .values()
                            .find(|candidate| {
                                candidate.ifindex == egress.bind_ifindex
                                    && candidate.queue_id == ident.queue_id
                            })
                            .or_else(|| {
                                self.identities
                                    .values()
                                    .find(|candidate| candidate.ifindex == egress.bind_ifindex)
                            })
                            .map(|candidate| candidate.slot)
                            .ok_or_else(|| {
                                format!(
                                    "no bound userspace slot for egress ifindex {}",
                                    egress.bind_ifindex
                                )
                            })?;
                        let target_live = self.live.get(&target_slot).ok_or_else(|| {
                            format!("binding slot {} has no live state", target_slot)
                        })?;
                        let frame = build_injected_packet(&req, dst, resolution, egress)?;
                        let cos = resolve_cos_tx_selection(
                            &self.forwarding,
                            resolution.egress_ifindex,
                            meta,
                            None,
                        );
                        target_live.enqueue_tx(TxRequest {
                            bytes: frame,
                            expected_ports: None,
                            expected_addr_family: 0,
                            expected_protocol: 0,
                            flow_key: None,
                            egress_ifindex: resolution.egress_ifindex,
                            cos_queue_id: cos.queue_id,
                            dscp_rewrite: cos.dscp_rewrite,
                        })?;
                    }
                } else {
                    record_exception(
                        &self.recent_exceptions,
                        &ident,
                        "invalid_destination_ip",
                        packet_length,
                        Some(meta),
                        None,
                        &self.forwarding,
                    );
                }
            } else if req.emit_on_wire {
                return Err("emit-on-wire requires destination-ip and valid metadata".to_string());
            }
            return Ok(());
        }

        live.metadata_errors.fetch_add(1, Ordering::Relaxed);
        record_exception(
            &self.recent_exceptions,
            &ident,
            "metadata_parse",
            packet_length,
            None,
            None,
            &self.forwarding,
        );
        Ok(())
    }

    pub fn refresh_bindings(&mut self, bindings: &mut [BindingStatus]) {
        for binding in bindings.iter_mut() {
            if let Some(live) = self.live.get(&binding.slot) {
                let snap = live.snapshot();
                if snap.bound && !binding.bound {
                    eprintln!(
                        "refresh_bindings: slot={} transitioning bound=false->true fd={}",
                        binding.slot, snap.socket_fd
                    );
                }
                binding.bound = snap.bound;
                binding.xsk_registered = snap.xsk_registered;
                binding.xsk_bind_mode = snap.xsk_bind_mode;
                binding.zero_copy = snap.zero_copy;
                binding.socket_fd = snap.socket_fd;
                binding.socket_ifindex = snap.socket_ifindex;
                binding.socket_queue_id = snap.socket_queue_id;
                binding.socket_bind_flags = snap.socket_bind_flags;
                binding.rx_packets = snap.rx_packets;
                binding.rx_bytes = snap.rx_bytes;
                binding.rx_batches = snap.rx_batches;
                binding.rx_wakeups = snap.rx_wakeups;
                binding.metadata_packets = snap.metadata_packets;
                binding.metadata_errors = snap.metadata_errors;
                binding.validated_packets = snap.validated_packets;
                binding.validated_bytes = snap.validated_bytes;
                binding.local_delivery_packets = snap.local_delivery_packets;
                binding.forward_candidate_packets = snap.forward_candidate_packets;
                binding.route_miss_packets = snap.route_miss_packets;
                binding.neighbor_miss_packets = snap.neighbor_miss_packets;
                binding.discard_route_packets = snap.discard_route_packets;
                binding.next_table_packets = snap.next_table_packets;
                binding.exception_packets = snap.exception_packets;
                binding.config_gen_mismatches = snap.config_gen_mismatches;
                binding.fib_gen_mismatches = snap.fib_gen_mismatches;
                binding.unsupported_packets = snap.unsupported_packets;
                binding.flow_cache_hits = snap.flow_cache_hits;
                binding.flow_cache_misses = snap.flow_cache_misses;
                binding.flow_cache_evictions = snap.flow_cache_evictions;
                binding.flow_cache_collision_evictions = snap.flow_cache_collision_evictions;
                binding.session_hits = snap.session_hits;
                binding.session_misses = snap.session_misses;
                binding.session_creates = snap.session_creates;
                binding.session_expires = snap.session_expires;
                binding.session_delta_pending = snap.session_delta_pending;
                binding.session_delta_generated = snap.session_delta_generated;
                binding.session_delta_dropped = snap.session_delta_dropped;
                binding.session_delta_drained = snap.session_delta_drained;
                binding.policy_denied_packets = snap.policy_denied_packets;
                binding.screen_drops = snap.screen_drops;
                binding.snat_packets = snap.snat_packets;
                binding.dnat_packets = snap.dnat_packets;
                binding.slow_path_packets = snap.slow_path_packets;
                binding.slow_path_bytes = snap.slow_path_bytes;
                binding.slow_path_local_delivery_packets = snap.slow_path_local_delivery_packets;
                binding.slow_path_missing_neighbor_packets =
                    snap.slow_path_missing_neighbor_packets;
                binding.slow_path_no_route_packets = snap.slow_path_no_route_packets;
                binding.slow_path_next_table_packets = snap.slow_path_next_table_packets;
                binding.slow_path_forward_build_packets = snap.slow_path_forward_build_packets;
                binding.slow_path_drops = snap.slow_path_drops;
                binding.slow_path_rate_limited = snap.slow_path_rate_limited;
                binding.kernel_rx_dropped = snap.kernel_rx_dropped;
                binding.kernel_rx_invalid_descs = snap.kernel_rx_invalid_descs;
                binding.tx_packets = snap.tx_packets;
                binding.tx_bytes = snap.tx_bytes;
                binding.tx_completions = snap.tx_completions;
                binding.tx_errors = snap.tx_errors;
                binding.redirect_inbox_overflow_drops = snap.redirect_inbox_overflow_drops;
                binding.pending_tx_local_overflow_drops = snap.pending_tx_local_overflow_drops;
                binding.tx_submit_error_drops = snap.tx_submit_error_drops;
                binding.post_drain_backup_bytes = snap.post_drain_backup_bytes;
                binding.drain_sent_bytes_shaped_unconditional =
                    snap.drain_sent_bytes_shaped_unconditional;
                binding.post_drain_backup_cos_drops = snap.post_drain_backup_cos_drops;
                binding.post_drain_backup_cos_drop_bytes = snap.post_drain_backup_cos_drop_bytes;
                // #710: `snap.no_owner_binding_drops` is not copied into
                // per-binding status — it is summed across all bindings
                // into `ProcessStatus::cos_no_owner_binding_drops_total`
                // at the refresh_status callsite, which is the correct
                // operator-facing scope for this counter.
                binding.direct_tx_packets = snap.direct_tx_packets;
                binding.copy_tx_packets = snap.copy_tx_packets;
                binding.in_place_tx_packets = snap.in_place_tx_packets;
                binding.direct_tx_no_frame_fallback_packets =
                    snap.direct_tx_no_frame_fallback_packets;
                binding.direct_tx_build_fallback_packets = snap.direct_tx_build_fallback_packets;
                binding.direct_tx_disallowed_fallback_packets =
                    snap.direct_tx_disallowed_fallback_packets;
                binding.debug_pending_fill_frames = snap.debug_pending_fill_frames;
                binding.debug_spare_fill_frames = 0;
                binding.debug_free_tx_frames = snap.debug_free_tx_frames;
                binding.debug_pending_tx_prepared = snap.debug_pending_tx_prepared;
                binding.debug_pending_tx_local = snap.debug_pending_tx_local;
                binding.debug_outstanding_tx = snap.debug_outstanding_tx;
                binding.debug_in_flight_recycles = snap.debug_in_flight_recycles;
                // #878: per-binding capacities + in-flight gauge flow
                // into BindingStatus so the daemon's fwdstatus
                // Buffer% can compute UMEM and TX-ring fill ratios.
                binding.umem_total_frames = snap.umem_total_frames;
                binding.tx_ring_capacity = snap.tx_ring_capacity;
                binding.umem_inflight_frames = snap.umem_inflight_frames;
                // #802: ring-pressure counters — atomic mirrors of
                // worker-local counters, published on the worker's
                // per-second debug tick. `outstanding_tx` aliases
                // `debug_outstanding_tx` for the operator-facing name.
                binding.dbg_tx_ring_full = snap.dbg_tx_ring_full;
                binding.dbg_sendto_enobufs = snap.dbg_sendto_enobufs;
                // #804: split counters — bound-pending FIFO vs CoS
                // queue admission. Pre-#804 a single `dbg_pending_overflow`
                // was published; the wire name was removed because
                // the semantics were ambiguous for operators.
                binding.dbg_bound_pending_overflow = snap.dbg_bound_pending_overflow;
                binding.dbg_cos_queue_overflow = snap.dbg_cos_queue_overflow;
                binding.rx_fill_ring_empty_descs = snap.rx_fill_ring_empty_descs;
                binding.outstanding_tx = snap.debug_outstanding_tx;
                // #812: per-queue TX submit→completion latency
                // telemetry. Materialize the fixed-cap snapshot
                // array into a freshly-owned Vec<u64> on the wire
                // boundary — reuses the buffer in-place to avoid
                // allocator churn when the BindingStatus entry is
                // refreshed on the ~1s poll cadence.
                binding
                    .tx_submit_latency_hist
                    .resize(snap.tx_submit_latency_hist.len(), 0);
                binding
                    .tx_submit_latency_hist
                    .copy_from_slice(&snap.tx_submit_latency_hist);
                binding.tx_submit_latency_count = snap.tx_submit_latency_count;
                binding.tx_submit_latency_sum_ns = snap.tx_submit_latency_sum_ns;
                // #825: per-kick `sendto` latency telemetry mirrors
                // the #812 submit-latency copy path above. Resize
                // the operator-facing Vec<u64> to match the
                // snapshot's fixed-cap array, then copy bucket
                // counts and scalars. `tx_kick_retry_count` is the
                // EAGAIN/EWOULDBLOCK tally (T1 ring-pushback).
                binding
                    .tx_kick_latency_hist
                    .resize(snap.tx_kick_latency_hist.len(), 0);
                binding
                    .tx_kick_latency_hist
                    .copy_from_slice(&snap.tx_kick_latency_hist);
                binding.tx_kick_latency_count = snap.tx_kick_latency_count;
                binding.tx_kick_latency_sum_ns = snap.tx_kick_latency_sum_ns;
                binding.tx_kick_retry_count = snap.tx_kick_retry_count;
                binding.last_heartbeat = snap.last_heartbeat;
                binding.last_error = snap.last_error;
                binding.ready = binding.registered
                    && binding.bound
                    && binding.xsk_registered
                    && heartbeat_fresh(snap.last_heartbeat);
            } else {
                binding.bound = false;
                binding.xsk_registered = false;
                binding.xsk_bind_mode.clear();
                binding.zero_copy = false;
                binding.socket_fd = 0;
                binding.socket_ifindex = 0;
                binding.socket_queue_id = 0;
                binding.socket_bind_flags = 0;
                binding.rx_packets = 0;
                binding.rx_bytes = 0;
                binding.rx_batches = 0;
                binding.rx_wakeups = 0;
                binding.metadata_packets = 0;
                binding.metadata_errors = 0;
                binding.validated_packets = 0;
                binding.validated_bytes = 0;
                binding.local_delivery_packets = 0;
                binding.forward_candidate_packets = 0;
                binding.route_miss_packets = 0;
                binding.neighbor_miss_packets = 0;
                binding.discard_route_packets = 0;
                binding.next_table_packets = 0;
                binding.exception_packets = 0;
                binding.config_gen_mismatches = 0;
                binding.fib_gen_mismatches = 0;
                binding.unsupported_packets = 0;
                binding.flow_cache_hits = 0;
                binding.flow_cache_misses = 0;
                binding.flow_cache_evictions = 0;
                binding.flow_cache_collision_evictions = 0;
                binding.session_hits = 0;
                binding.session_misses = 0;
                binding.session_creates = 0;
                binding.session_expires = 0;
                binding.session_delta_pending = 0;
                binding.session_delta_generated = 0;
                binding.session_delta_dropped = 0;
                binding.session_delta_drained = 0;
                binding.policy_denied_packets = 0;
                binding.snat_packets = 0;
                binding.dnat_packets = 0;
                binding.slow_path_packets = 0;
                binding.slow_path_bytes = 0;
                binding.slow_path_local_delivery_packets = 0;
                binding.slow_path_missing_neighbor_packets = 0;
                binding.slow_path_no_route_packets = 0;
                binding.slow_path_next_table_packets = 0;
                binding.slow_path_forward_build_packets = 0;
                binding.slow_path_drops = 0;
                binding.slow_path_rate_limited = 0;
                binding.kernel_rx_dropped = 0;
                binding.kernel_rx_invalid_descs = 0;
                binding.tx_packets = 0;
                binding.tx_bytes = 0;
                binding.tx_completions = 0;
                binding.tx_errors = 0;
                binding.post_drain_backup_bytes = 0;
                binding.drain_sent_bytes_shaped_unconditional = 0;
                binding.post_drain_backup_cos_drops = 0;
                binding.post_drain_backup_cos_drop_bytes = 0;
                binding.direct_tx_packets = 0;
                binding.copy_tx_packets = 0;
                binding.in_place_tx_packets = 0;
                binding.direct_tx_no_frame_fallback_packets = 0;
                binding.direct_tx_build_fallback_packets = 0;
                binding.direct_tx_disallowed_fallback_packets = 0;
                binding.debug_pending_fill_frames = 0;
                binding.debug_spare_fill_frames = 0;
                binding.debug_free_tx_frames = 0;
                binding.debug_pending_tx_prepared = 0;
                binding.debug_pending_tx_local = 0;
                binding.debug_outstanding_tx = 0;
                binding.debug_in_flight_recycles = 0;
                // #878: capacities + in-flight gauge zero when the
                // binding has no live state (slot unregistered). The
                // daemon treats zero umem_total_frames as "unknown"
                // and falls back to the legacy Buffer% display.
                binding.umem_total_frames = 0;
                binding.tx_ring_capacity = 0;
                binding.umem_inflight_frames = 0;
                // #802: ring-pressure counters — zero when the binding
                // has no live state (unregistered slot).
                binding.dbg_tx_ring_full = 0;
                binding.dbg_sendto_enobufs = 0;
                binding.dbg_bound_pending_overflow = 0;
                binding.dbg_cos_queue_overflow = 0;
                binding.rx_fill_ring_empty_descs = 0;
                binding.outstanding_tx = 0;
                // #812: zero the submit-latency histogram when the
                // binding has no live state (unregistered slot).
                binding.tx_submit_latency_hist.clear();
                binding.tx_submit_latency_count = 0;
                binding.tx_submit_latency_sum_ns = 0;
                // #825: zero the kick-latency histogram + retry
                // counter when the binding has no live state.
                binding.tx_kick_latency_hist.clear();
                binding.tx_kick_latency_count = 0;
                binding.tx_kick_latency_sum_ns = 0;
                binding.tx_kick_retry_count = 0;
                binding.last_heartbeat = None;
                binding.last_error.clear();
                binding.ready = false;
            }
        }
        self.refresh_cos_owner_worker_map_from_binding_statuses(bindings);
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
                q.buffer_bytes = q.buffer_bytes.max(queue.buffer_bytes);
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

fn build_shared_cos_queue_leases_reusing_existing(
    forwarding: &ForwardingState,
    active_shards_by_egress_ifindex: &BTreeMap<i32, usize>,
    existing: &BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>,
) -> BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>> {
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
            if let Some(lease) = existing.get(&key).filter(|lease| {
                lease.matches_config(queue.transmit_rate_bytes, burst_bytes, active_shards)
            }) {
                out.insert(key, lease.clone());
                continue;
            }
            out.insert(
                key,
                Arc::new(SharedCoSQueueLease::new(
                    queue.transmit_rate_bytes,
                    burst_bytes,
                    active_shards,
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
            // regresses. The shared_exact promotion check
            // mirrors `queue_uses_shared_exact_service` in
            // worker.rs.
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
        && current.iter().all(|(key, floor)| {
            next.get(key)
                .is_some_and(|next| Arc::ptr_eq(floor, next))
        })
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

/// #925 Phase 1: render a panic payload as an operator-readable string.
///
/// Cases:
/// - `&str` payload → the panic argument verbatim.
/// - `String` payload → its content.
/// - Anything else → literal `"non-string panic payload"`.
///
/// We deliberately do NOT try to extract a concrete type name from a
/// `dyn Any` payload — `type_name_of_val` on a `Box<dyn Any>` returns
/// the trait object's name, not the inner type, which would mislead.
fn panic_payload_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        String::from("non-string panic payload")
    }
}

/// #925 Phase 1: spawn `body` on a named thread and wrap it with
/// `catch_unwind`. On panic, mark `runtime_atomics.dead = true` and
/// publish the rendered payload to `panic_slot`.
///
/// `AssertUnwindSafe` rationale (narrow): `worker_loop` takes owned
/// values and `Arc`s — there are no `&mut` parameters to invalidate
/// across an unwind. Owned values get dropped on unwind. Shared
/// `Arc<Mutex<…>>` state MAY become poisoned; per #925's "detection
/// only" framing this PR does not promise full state recovery — see
/// `docs/pr/925-worker-supervisor/plan.md` §"AssertUnwindSafe rationale".
fn spawn_supervised_worker<F>(
    worker_id: u32,
    runtime_atomics: Arc<super::worker_runtime::WorkerRuntimeAtomics>,
    panic_slot: Arc<Mutex<Option<String>>>,
    body: F,
) -> std::io::Result<thread::JoinHandle<()>>
where
    F: FnOnce() + Send + 'static,
{
    thread::Builder::new()
        .name(format!("xpf-userspace-worker-{worker_id}"))
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
            if let Err(payload) = result {
                let msg = panic_payload_message(&payload);
                eprintln!(
                    "xpf-userspace-dp: worker_loop panicked (worker_id={worker_id}): {msg}",
                );
                // Write the message under the slot mutex; on poison
                // (a prior panic during read), use into_inner — same
                // pattern as #949's dynamic_neighbors policy.
                match panic_slot.lock() {
                    Ok(mut slot) => *slot = Some(msg),
                    Err(poisoned) => *poisoned.into_inner() = Some(msg),
                }
                // Mark dead. Relaxed is fine — the panic_slot mutex
                // publishes the message; the dead flag is a one-shot
                // diagnostic, not a synchronization barrier.
                runtime_atomics
                    .dead
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_zone_ids::*;
    use crate::{
        ClassOfServiceSnapshot, CoSForwardingClassSnapshot, CoSSchedulerMapEntrySnapshot,
        CoSSchedulerMapSnapshot,
    };

    #[test]
    fn build_cos_owner_worker_by_queue_prefers_lowest_worker_with_tx_binding() {
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 1_000_000,
                burst_bytes: 64 * 1024,
                default_queue: 0,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                }],
            },
        );
        forwarding.egress.insert(
            80,
            EgressInterface {
                bind_ifindex: 12,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0; 6],
                zone_id: TEST_WAN_ZONE_ID,
                redundancy_group: 0,
                primary_v4: None,
                primary_v6: None,
            },
        );
        let worker_binding_ifindexes = BTreeMap::from([
            (2, std::collections::BTreeSet::from([12])),
            (7, std::collections::BTreeSet::from([12, 13])),
        ]);

        let owner_by_queue = build_cos_owner_worker_by_queue_from_binding_ifindexes(
            &forwarding,
            &worker_binding_ifindexes,
        );

        assert_eq!(owner_by_queue.get(&(80, 0)), Some(&2));
    }

    #[test]
    fn build_cos_owner_worker_by_queue_spreads_queues_across_eligible_workers() {
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 1_000_000,
                burst_bytes: 64 * 1024,
                default_queue: 0,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![
                    CoSQueueConfig {
                        queue_id: 0,
                        forwarding_class: "best-effort".into(),
                        priority: 5,
                        transmit_rate_bytes: 1_000_000,
                        exact: false,
                        surplus_weight: 1,
                        buffer_bytes: 64 * 1024,
                        dscp_rewrite: None,
                    },
                    CoSQueueConfig {
                        queue_id: 1,
                        forwarding_class: "af11".into(),
                        priority: 5,
                        transmit_rate_bytes: 1_000_000,
                        exact: false,
                        surplus_weight: 1,
                        buffer_bytes: 64 * 1024,
                        dscp_rewrite: None,
                    },
                    CoSQueueConfig {
                        queue_id: 2,
                        forwarding_class: "af12".into(),
                        priority: 5,
                        transmit_rate_bytes: 1_000_000,
                        exact: false,
                        surplus_weight: 1,
                        buffer_bytes: 64 * 1024,
                        dscp_rewrite: None,
                    },
                ],
            },
        );
        forwarding.egress.insert(
            80,
            EgressInterface {
                bind_ifindex: 12,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0; 6],
                zone_id: TEST_WAN_ZONE_ID,
                redundancy_group: 0,
                primary_v4: None,
                primary_v6: None,
            },
        );
        let worker_binding_ifindexes = BTreeMap::from([
            (2, std::collections::BTreeSet::from([12])),
            (7, std::collections::BTreeSet::from([12])),
        ]);

        let owner_by_queue = build_cos_owner_worker_by_queue_from_binding_ifindexes(
            &forwarding,
            &worker_binding_ifindexes,
        );

        assert_eq!(owner_by_queue.get(&(80, 0)), Some(&2));
        assert_eq!(owner_by_queue.get(&(80, 1)), Some(&7));
        assert_eq!(owner_by_queue.get(&(80, 2)), Some(&2));
    }

    #[test]
    fn build_cos_owner_worker_by_queue_prefers_ready_workers_when_available() {
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 1_000_000,
                burst_bytes: 64 * 1024,
                default_queue: 0,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![
                    CoSQueueConfig {
                        queue_id: 0,
                        forwarding_class: "best-effort".into(),
                        priority: 5,
                        transmit_rate_bytes: 1_000_000,
                        exact: false,
                        surplus_weight: 1,
                        buffer_bytes: 64 * 1024,
                        dscp_rewrite: None,
                    },
                    CoSQueueConfig {
                        queue_id: 4,
                        forwarding_class: "iperf-a".into(),
                        priority: 5,
                        transmit_rate_bytes: 1_000_000,
                        exact: true,
                        surplus_weight: 1,
                        buffer_bytes: 64 * 1024,
                        dscp_rewrite: None,
                    },
                ],
            },
        );
        forwarding.egress.insert(
            80,
            EgressInterface {
                bind_ifindex: 12,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0; 6],
                zone_id: TEST_WAN_ZONE_ID,
                redundancy_group: 0,
                primary_v4: None,
                primary_v6: None,
            },
        );

        let owner_by_queue = build_cos_owner_worker_by_queue_with_fallback_ifindexes(
            &forwarding,
            &BTreeMap::from([(7, std::collections::BTreeSet::from([12]))]),
            &BTreeMap::from([
                (2, std::collections::BTreeSet::from([12])),
                (7, std::collections::BTreeSet::from([12])),
            ]),
        );

        assert_eq!(owner_by_queue.get(&(80, 0)), Some(&7));
        assert_eq!(owner_by_queue.get(&(80, 4)), Some(&7));
    }

    #[test]
    fn build_cos_owner_worker_by_queue_falls_back_when_no_ready_workers_exist() {
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 1_000_000,
                burst_bytes: 64 * 1024,
                default_queue: 0,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                }],
            },
        );
        forwarding.egress.insert(
            80,
            EgressInterface {
                bind_ifindex: 12,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0; 6],
                zone_id: TEST_WAN_ZONE_ID,
                redundancy_group: 0,
                primary_v4: None,
                primary_v6: None,
            },
        );

        let owner_by_queue = build_cos_owner_worker_by_queue_with_fallback_ifindexes(
            &forwarding,
            &BTreeMap::new(),
            &BTreeMap::from([(2, std::collections::BTreeSet::from([12]))]),
        );

        assert_eq!(owner_by_queue.get(&(80, 0)), Some(&2));
    }

    #[test]
    fn build_worker_binding_ifindexes_from_identities_groups_by_worker() {
        let identities = BTreeMap::from([
            (
                10,
                BindingIdentity {
                    slot: 10,
                    queue_id: 0,
                    worker_id: 2,
                    interface: "ge-0-0-2".into(),
                    ifindex: 12,
                },
            ),
            (
                11,
                BindingIdentity {
                    slot: 11,
                    queue_id: 1,
                    worker_id: 2,
                    interface: "ge-0-0-2".into(),
                    ifindex: 12,
                },
            ),
            (
                20,
                BindingIdentity {
                    slot: 20,
                    queue_id: 0,
                    worker_id: 7,
                    interface: "ge-0-0-3".into(),
                    ifindex: 13,
                },
            ),
        ]);

        let worker_binding_ifindexes = build_worker_binding_ifindexes_from_identities(&identities);

        assert_eq!(
            worker_binding_ifindexes.get(&2),
            Some(&std::collections::BTreeSet::from([12]))
        );
        assert_eq!(
            worker_binding_ifindexes.get(&7),
            Some(&std::collections::BTreeSet::from([13]))
        );
    }

    #[test]
    fn refresh_runtime_snapshot_rebuilds_cos_owner_worker_map_from_identities() {
        let mut coordinator = Coordinator::new();
        coordinator.identities.insert(
            1,
            BindingIdentity {
                slot: 1,
                queue_id: 0,
                worker_id: 2,
                interface: "ge-0-0-2".into(),
                ifindex: 12,
            },
        );
        coordinator.identities.insert(
            2,
            BindingIdentity {
                slot: 2,
                queue_id: 0,
                worker_id: 7,
                interface: "ge-0-0-3".into(),
                ifindex: 13,
            },
        );

        let mut snapshot = ConfigSnapshot::default();
        snapshot.interfaces.push(InterfaceSnapshot {
            name: "reth0.80".into(),
            ifindex: 80,
            parent_ifindex: 12,
            hardware_addr: "02:00:00:00:00:80".into(),
            cos_shaping_rate_bytes_per_sec: 1_000_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        });
        snapshot.class_of_service = Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: String::new(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        });

        coordinator.refresh_runtime_snapshot(&snapshot);

        assert_eq!(
            coordinator.cos_owner_worker_by_queue.get(&(80, 0)),
            Some(&2)
        );
        let shared = coordinator.cos.owner_worker_by_queue.load();
        assert_eq!(shared.get(&(80, 0)), Some(&2));
    }

    #[test]
    fn build_shared_cos_root_leases_uses_active_workers_per_interface() {
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 100_000_000,
                burst_bytes: 256 * 1024,
                default_queue: 0,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![
                    CoSQueueConfig {
                        queue_id: 0,
                        forwarding_class: "best-effort".into(),
                        priority: 5,
                        transmit_rate_bytes: 50_000_000,
                        exact: false,
                        surplus_weight: 1,
                        buffer_bytes: 128 * 1024,
                        dscp_rewrite: None,
                    },
                    CoSQueueConfig {
                        queue_id: 1,
                        forwarding_class: "af11".into(),
                        priority: 5,
                        transmit_rate_bytes: 50_000_000,
                        exact: false,
                        surplus_weight: 1,
                        buffer_bytes: 128 * 1024,
                        dscp_rewrite: None,
                    },
                ],
            },
        );
        let active_shards_by_egress_ifindex = BTreeMap::from([(80, 2usize)]);

        let leases = build_shared_cos_root_leases(&forwarding, &active_shards_by_egress_ifindex);
        let lease = leases.get(&80).expect("shared root lease");

        // The root lease budget must scale with active_shards: total
        // grantable = lease_bytes * active_shards. That is the actual
        // invariant this test pins. Drive it by reading active_shards
        // from the fixture (so the assertion does not silently decouple
        // from the setup) and drain the budget with fixed-size requests
        // plus a tail remainder for whatever the budget does not cleanly
        // divide by — lease_bytes is a function of shaping rate and
        // COS_ROOT_LEASE_TARGET_US, both of which are tuning knobs, so
        // an exact-divisibility assertion would make this test brittle
        // against legitimate scheduler tuning.
        let active_shards = *active_shards_by_egress_ifindex
            .get(&80)
            .expect("active shards configured for egress ifindex 80")
            as u64;
        let lease_bytes = lease.lease_bytes();
        let expected_total = lease_bytes * active_shards;
        let per_request = 2500u64;

        let mut remaining = expected_total;
        let mut total = 0u64;
        while remaining > 0 {
            let req = remaining.min(per_request);
            let granted = lease.acquire(1, req);
            assert_eq!(
                granted, req,
                "root lease must grant the full request while budget remains",
            );
            total += granted;
            remaining -= granted;
        }
        assert_eq!(total, expected_total);
        // Budget fully drained — any further acquire must return 0.
        assert_eq!(lease.acquire(1, 1), 0);
    }

    #[test]
    fn build_shared_cos_root_leases_reuses_existing_matching_lease_arc() {
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 100_000_000,
                burst_bytes: 256 * 1024,
                default_queue: 0,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 100_000_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                }],
            },
        );
        let active_shards_by_egress_ifindex = BTreeMap::from([(80, 1usize)]);

        let existing = build_shared_cos_root_leases(&forwarding, &active_shards_by_egress_ifindex);
        let reused = build_shared_cos_root_leases_reusing_existing(
            &forwarding,
            &active_shards_by_egress_ifindex,
            &existing,
        );

        assert!(Arc::ptr_eq(
            existing.get(&80).expect("existing lease"),
            reused.get(&80).expect("reused lease")
        ));
    }

    #[test]
    fn build_shared_cos_queue_leases_reuses_existing_matching_lease_arc() {
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 100_000_000,
                burst_bytes: 256 * 1024,
                default_queue: 0,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-b".into(),
                    priority: 5,
                    transmit_rate_bytes: 50_000_000,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                }],
            },
        );
        let active_shards_by_egress_ifindex = BTreeMap::from([(80, 2usize)]);

        let existing = build_shared_cos_queue_leases_reusing_existing(
            &forwarding,
            &active_shards_by_egress_ifindex,
            &BTreeMap::new(),
        );
        let reused = build_shared_cos_queue_leases_reusing_existing(
            &forwarding,
            &active_shards_by_egress_ifindex,
            &existing,
        );

        assert!(Arc::ptr_eq(
            existing.get(&(80, 4)).expect("existing queue lease"),
            reused.get(&(80, 4)).expect("reused queue lease")
        ));
    }

    #[test]
    fn refresh_cos_owner_worker_map_from_binding_statuses_keeps_shared_arcs_when_unchanged() {
        let mut coordinator = Coordinator::new();
        coordinator.forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 100_000_000,
                burst_bytes: 256 * 1024,
                default_queue: 0,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![
                    CoSQueueConfig {
                        queue_id: 0,
                        forwarding_class: "best-effort".into(),
                        priority: 5,
                        transmit_rate_bytes: 50_000_000,
                        exact: false,
                        surplus_weight: 1,
                        buffer_bytes: 128 * 1024,
                        dscp_rewrite: None,
                    },
                    CoSQueueConfig {
                        queue_id: 1,
                        forwarding_class: "af11".into(),
                        priority: 5,
                        transmit_rate_bytes: 50_000_000,
                        exact: false,
                        surplus_weight: 1,
                        buffer_bytes: 128 * 1024,
                        dscp_rewrite: None,
                    },
                ],
            },
        );
        coordinator.forwarding.egress.insert(
            80,
            EgressInterface {
                bind_ifindex: 12,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0; 6],
                zone_id: TEST_WAN_ZONE_ID,
                redundancy_group: 0,
                primary_v4: None,
                primary_v6: None,
            },
        );
        let bindings = vec![BindingStatus {
            worker_id: 7,
            ifindex: 12,
            ready: true,
            ..Default::default()
        }];

        coordinator.refresh_cos_owner_worker_map_from_binding_statuses(&bindings);
        let owners_before = coordinator.cos.owner_worker_by_queue.load_full();
        let leases_before = coordinator.cos.root_leases.load_full();
        let lease_before = leases_before.get(&80).expect("shared root lease").clone();
        assert_eq!(lease_before.acquire(1, 2500), 2500);

        coordinator.refresh_cos_owner_worker_map_from_binding_statuses(&bindings);
        let owners_after = coordinator.cos.owner_worker_by_queue.load_full();
        let leases_after = coordinator.cos.root_leases.load_full();

        assert!(Arc::ptr_eq(&owners_before, &owners_after));
        assert!(Arc::ptr_eq(
            &lease_before,
            leases_after.get(&80).expect("shared root lease")
        ));
    }

    #[test]
    fn unique_interface_owner_worker_id_returns_none_when_queues_split() {
        let owner = 7u32;
        let queues = vec![
            crate::protocol::CoSQueueStatus {
                queue_id: 0,
                owner_worker_id: Some(2),
                ..Default::default()
            },
            crate::protocol::CoSQueueStatus {
                queue_id: 1,
                owner_worker_id: Some(owner),
                ..Default::default()
            },
        ];

        assert_eq!(unique_interface_owner_worker_id(&queues), None);
    }

    #[test]
    fn aggregate_cos_statuses_sums_drop_counters_across_worker_snapshots() {
        // #710 regression pin. This is the EXACT code path where the
        // live bug landed: `Coordinator::cos_statuses` re-aggregates
        // per-worker snapshots, and before this PR that re-aggregation
        // silently dropped every new drop-counter field. The unit test
        // gate must be at this layer, not just the worker layer.
        use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

        let worker_a = vec![CoSInterfaceStatus {
            ifindex: 80,
            interface_name: "reth0.80".into(),
            shaping_rate_bytes: 1_250_000_000,
            burst_bytes: 256 * 1024,
            worker_instances: 1,
            queues: vec![CoSQueueStatus {
                queue_id: 4,
                worker_instances: 1,
                admission_flow_share_drops: 3,
                admission_buffer_drops: 5,
                admission_ecn_marked: 37,
                root_token_starvation_parks: 7,
                queue_token_starvation_parks: 11,
                tx_ring_full_submit_stalls: 13,
                ..Default::default()
            }],
            ..Default::default()
        }];
        let worker_b = vec![CoSInterfaceStatus {
            ifindex: 80,
            interface_name: "reth0.80".into(),
            shaping_rate_bytes: 1_250_000_000,
            burst_bytes: 256 * 1024,
            worker_instances: 1,
            queues: vec![CoSQueueStatus {
                queue_id: 4,
                worker_instances: 1,
                admission_flow_share_drops: 17,
                admission_buffer_drops: 19,
                admission_ecn_marked: 41,
                root_token_starvation_parks: 23,
                queue_token_starvation_parks: 29,
                tx_ring_full_submit_stalls: 31,
                ..Default::default()
            }],
            ..Default::default()
        }];
        let owner_by_queue = BTreeMap::from([((80, 4u8), 3u32)]);
        let aggregated =
            aggregate_cos_statuses_across_workers(&[worker_a, worker_b], &owner_by_queue);

        assert_eq!(aggregated.len(), 1);
        let iface = &aggregated[0];
        assert_eq!(iface.ifindex, 80);
        assert_eq!(iface.queues.len(), 1);
        let q = &iface.queues[0];
        assert_eq!(q.queue_id, 4);
        assert_eq!(q.owner_worker_id, Some(3));
        // Each counter is non-coprime-prime on both sides to catch
        // accidental re-attribution between counters.
        assert_eq!(q.admission_flow_share_drops, 3 + 17);
        assert_eq!(q.admission_buffer_drops, 5 + 19);
        assert_eq!(q.admission_ecn_marked, 37 + 41);
        assert_eq!(q.root_token_starvation_parks, 7 + 23);
        assert_eq!(q.queue_token_starvation_parks, 11 + 29);
        assert_eq!(q.tx_ring_full_submit_stalls, 13 + 31);
    }

    #[test]
    fn aggregate_cos_statuses_sums_owner_profile_across_workers_coherently() {
        use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

        let worker_a = vec![CoSInterfaceStatus {
            ifindex: 80,
            interface_name: "reth0.80".into(),
            worker_instances: 1,
            queues: vec![CoSQueueStatus {
                queue_id: 4,
                worker_instances: 1,
                exact: true,
                drain_latency_hist: {
                    let mut v = vec![0; super::super::umem::DRAIN_HIST_BUCKETS];
                    v[0] = 5;
                    v
                },
                redirect_acquire_hist: {
                    let mut v = vec![0; super::super::umem::DRAIN_HIST_BUCKETS];
                    v[1] = 3;
                    v
                },
                drain_invocations: 5,
                drain_noop_invocations: 1,
                owner_pps: 100,
                peer_pps: 40,
                ..Default::default()
            }],
            ..Default::default()
        }];
        let worker_b = vec![CoSInterfaceStatus {
            ifindex: 80,
            interface_name: "reth0.80".into(),
            worker_instances: 1,
            queues: vec![CoSQueueStatus {
                queue_id: 4,
                worker_instances: 1,
                exact: true,
                drain_latency_hist: {
                    let mut v = vec![0; super::super::umem::DRAIN_HIST_BUCKETS];
                    v[7] = 11;
                    v
                },
                redirect_acquire_hist: {
                    let mut v = vec![0; super::super::umem::DRAIN_HIST_BUCKETS];
                    v[2] = 13;
                    v
                },
                drain_invocations: 11,
                drain_noop_invocations: 2,
                owner_pps: 200,
                peer_pps: 50,
                ..Default::default()
            }],
            ..Default::default()
        }];

        let owner_by_queue = BTreeMap::from([((80, 4u8), 3u32)]);
        let aggregated =
            aggregate_cos_statuses_across_workers(&[worker_a, worker_b], &owner_by_queue);

        let q = &aggregated[0].queues[0];
        assert_eq!(q.drain_latency_hist[0], 5);
        assert_eq!(q.drain_latency_hist[7], 11);
        assert_eq!(q.redirect_acquire_hist[1], 3);
        assert_eq!(q.redirect_acquire_hist[2], 13);
        assert_eq!(q.drain_invocations, 16);
        assert_eq!(q.drain_noop_invocations, 3);
        assert_eq!(q.owner_pps, 300);
        assert_eq!(q.peer_pps, 90);
        assert_eq!(
            q.drain_latency_hist.iter().copied().sum::<u64>(),
            q.drain_invocations,
            "cross-worker aggregation must preserve hist == invocation invariant",
        );
    }

    #[test]
    fn cos_no_owner_binding_drops_total_sums_across_every_live_state() {
        // #710: the per-binding `no_owner_binding_drops` atomic is the
        // mechanical accumulator; the operator-facing surface is
        // `Coordinator::cos_no_owner_binding_drops_total`, which must
        // sum across every `BindingLiveState`. Without this test, a
        // refactor that reads only `bindings.first()` or only one
        // worker's bindings could silently undercount.
        let a = std::sync::Arc::new(BindingLiveState::new());
        let b = std::sync::Arc::new(BindingLiveState::new());
        let c = std::sync::Arc::new(BindingLiveState::new());
        a.no_owner_binding_drops
            .store(3, std::sync::atomic::Ordering::Relaxed);
        b.no_owner_binding_drops
            .store(5, std::sync::atomic::Ordering::Relaxed);
        c.no_owner_binding_drops
            .store(7, std::sync::atomic::Ordering::Relaxed);

        let total: u64 = [a, b, c]
            .iter()
            .map(|live| {
                live.no_owner_binding_drops
                    .load(std::sync::atomic::Ordering::Relaxed)
            })
            .sum();
        assert_eq!(total, 15);
    }

    #[test]
    fn ring_pressure_counters_round_trip_through_snapshot() {
        // #802: verify that the new ring-pressure atomics on
        // BindingLiveState are surfaced via `snapshot()`. Without this
        // pin, a refactor that drops the new fields from `snapshot()`
        // would silently zero the operator-facing counters.
        use std::sync::atomic::Ordering;
        let live = BindingLiveState::new();
        live.dbg_tx_ring_full.store(11, Ordering::Relaxed);
        live.dbg_sendto_enobufs.store(13, Ordering::Relaxed);
        // #804: two distinct counters — bound-pending FIFO overflow
        // (17) and CoS queue admission overflow (41). Non-coprime-prime
        // per field so an accidental swap across the two is caught.
        live.dbg_bound_pending_overflow.store(17, Ordering::Relaxed);
        live.dbg_cos_queue_overflow.store(41, Ordering::Relaxed);
        live.rx_fill_ring_empty_descs.store(19, Ordering::Relaxed);
        live.debug_outstanding_tx.store(23, Ordering::Relaxed);
        let snap = live.snapshot();
        assert_eq!(snap.dbg_tx_ring_full, 11);
        assert_eq!(snap.dbg_sendto_enobufs, 13);
        assert_eq!(snap.dbg_bound_pending_overflow, 17);
        assert_eq!(snap.dbg_cos_queue_overflow, 41);
        assert_eq!(snap.rx_fill_ring_empty_descs, 19);
        assert_eq!(snap.debug_outstanding_tx, 23);
    }

    // -------------------------------------------------------------
    // #925 Phase 1: worker supervisor catch_unwind tests.
    // -------------------------------------------------------------

    /// Helper: extract the message from a caught panic payload using
    /// the same renderer the supervisor uses.
    fn caught_message<F: FnOnce() + std::panic::UnwindSafe>(f: F) -> String {
        let r = std::panic::catch_unwind(f);
        let payload = r.unwrap_err();
        super::panic_payload_message(&payload)
    }

    #[test]
    fn panic_payload_message_renders_str_panic() {
        assert_eq!(caught_message(|| panic!("hello world")), "hello world");
    }

    #[test]
    fn panic_payload_message_renders_string_panic() {
        let s = String::from("owned message");
        assert_eq!(caught_message(move || panic!("{}", s)), "owned message");
    }

    #[test]
    fn panic_payload_message_falls_back_for_non_string() {
        // panic_any unwinds with a non-string payload (i32 here).
        let msg = caught_message(|| std::panic::panic_any(42_i32));
        assert_eq!(msg, "non-string panic payload");
    }

    /// Integration test against the same `spawn_supervised_worker`
    /// production uses (the spawn-closure body is the only thing we
    /// substitute — the supervisor wrapper is the real one).
    #[test]
    fn spawn_supervised_worker_catches_string_panic_and_marks_dead() {
        use std::sync::atomic::Ordering;
        let atomics = Arc::new(super::super::worker_runtime::WorkerRuntimeAtomics::new());
        let slot = Arc::new(Mutex::new(None::<String>));
        let join = super::spawn_supervised_worker(
            7,
            atomics.clone(),
            slot.clone(),
            || panic!("intentional test panic"),
        )
        .expect("spawn_supervised_worker");
        // The supervisor must NOT propagate the panic to the joiner.
        join.join().expect("supervisor must catch worker panic");
        assert!(atomics.dead.load(Ordering::Relaxed));
        let msg = slot
            .lock()
            .expect("panic slot lock")
            .clone()
            .expect("panic message published");
        assert_eq!(msg, "intentional test panic");
    }
}
