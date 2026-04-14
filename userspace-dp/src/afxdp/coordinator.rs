use super::*;

pub struct Coordinator {
    pub(crate) map_fd: Option<OwnedFd>,
    pub(crate) heartbeat_map_fd: Option<OwnedFd>,
    pub(crate) session_map_fd: Option<OwnedFd>,
    pub(crate) conntrack_v4_fd: Option<OwnedFd>,
    pub(crate) conntrack_v6_fd: Option<OwnedFd>,
    pub(crate) dnat_table_fd: Option<OwnedFd>,
    pub(crate) dnat_table_v6_fd: Option<OwnedFd>,
    pub(crate) slow_path: Option<Arc<SlowPathReinjector>>,
    pub(crate) local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    pub(crate) tunnel_sources: BTreeMap<u16, LocalTunnelSourceHandle>,
    pub(crate) last_slow_path_status: SlowPathStatus,
    pub(crate) ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    pub(crate) shared_fabrics: Arc<ArcSwap<Vec<FabricLink>>>,
    pub(crate) shared_forwarding: Arc<ArcSwap<ForwardingState>>,
    pub(crate) shared_cos_owner_worker_by_ifindex: Arc<ArcSwap<BTreeMap<i32, u32>>>,
    pub(crate) shared_validation: Arc<ArcSwap<ValidationState>>,
    pub(crate) dynamic_neighbors: Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    pub(crate) neighbor_generation: Arc<AtomicU64>,
    pub(crate) manager_neighbor_keys: Arc<Mutex<FastSet<(i32, IpAddr)>>>,
    pub(crate) neigh_monitor_stop: Option<Arc<AtomicBool>>,
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
    pub(crate) cos_owner_worker_by_ifindex: BTreeMap<i32, u32>,
    /// Monotonic timestamp (secs) of the last HA flow cache flush (#312).
    pub(crate) last_cache_flush_at: Arc<AtomicU64>,
    /// Per-RG epoch counters for O(1) flow cache invalidation on demotion.
    /// Shared with all worker threads; bumped atomically on demotion/activation.
    pub(crate) rg_epochs: Arc<[AtomicU32; MAX_RG_EPOCHS]>,
}

impl Coordinator {
    pub fn new() -> Self {
        Self {
            map_fd: None,
            heartbeat_map_fd: None,
            session_map_fd: None,
            conntrack_v4_fd: None,
            conntrack_v6_fd: None,
            dnat_table_fd: None,
            dnat_table_v6_fd: None,
            slow_path: None,
            local_tunnel_deliveries: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            tunnel_sources: BTreeMap::new(),
            last_slow_path_status: SlowPathStatus::default(),
            ha_state: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            shared_fabrics: Arc::new(ArcSwap::from_pointee(Vec::new())),
            shared_forwarding: Arc::new(ArcSwap::from_pointee(ForwardingState::default())),
            shared_cos_owner_worker_by_ifindex: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            shared_validation: Arc::new(ArcSwap::from_pointee(ValidationState::default())),
            dynamic_neighbors: Arc::new(Mutex::new(FastMap::default())),
            neighbor_generation: Arc::new(AtomicU64::new(0)),
            manager_neighbor_keys: Arc::new(Mutex::new(FastSet::default())),
            neigh_monitor_stop: None,
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
            cos_owner_worker_by_ifindex: BTreeMap::new(),
            last_cache_flush_at: Arc::new(AtomicU64::new(0)),
            rg_epochs: Arc::new(std::array::from_fn(|_| AtomicU32::new(0))),
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
    pub fn dynamic_neighbors_ref(&self) -> &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>> {
        &self.dynamic_neighbors
    }

    pub fn apply_manager_neighbors(
        &mut self,
        replace: bool,
        neighbors: &[(i32, IpAddr, NeighborEntry)],
    ) {
        let old_manager_keys = if replace {
            self.manager_neighbor_keys
                .lock()
                .map(|manager_keys| manager_keys.iter().copied().collect::<Vec<_>>())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        if let Ok(mut manager_keys) = self.manager_neighbor_keys.lock() {
            if replace {
                manager_keys.clear();
            }
            for (ifindex, ip, _) in neighbors {
                manager_keys.insert((*ifindex, *ip));
            }
        }
        if let Ok(mut cache) = self.dynamic_neighbors.lock() {
            if replace {
                for key in &old_manager_keys {
                    cache.remove(key);
                }
            }
            for (ifindex, ip, entry) in neighbors {
                cache.insert((*ifindex, *ip), *entry);
            }
        }
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
            self.shared_forwarding
                .store(Arc::new(self.forwarding.clone()));
        }
        self.neighbor_generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dynamic_neighbor_status(&self) -> (usize, u64) {
        let entries = self.dynamic_neighbors.lock().map(|n| n.len()).unwrap_or(0);
        let generation = self.neighbor_generation.load(Ordering::Relaxed);
        (entries, generation)
    }

    pub(crate) fn stop_inner(&mut self, clear_synced_state: bool) {
        if let Some(stop) = self.neigh_monitor_stop.take() {
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
        if let Some(map_fd) = self.map_fd.as_ref() {
            for slot in self.live.keys().copied().collect::<Vec<_>>() {
                let _ = delete_xsk_slot(map_fd.fd, slot);
            }
        }
        if let Some(map_fd) = self.heartbeat_map_fd.as_ref() {
            for slot in self.live.keys().copied().collect::<Vec<_>>() {
                let _ = delete_heartbeat_slot(map_fd.fd, slot);
            }
        }
        self.workers.clear();
        self.identities.clear();
        self.live.clear();
        self.cos_owner_worker_by_ifindex.clear();
        self.shared_cos_owner_worker_by_ifindex
            .store(Arc::new(BTreeMap::new()));
        self.last_slow_path_status = self
            .slow_path
            .as_ref()
            .map(|slow| slow.status())
            .unwrap_or_default();
        self.slow_path = None;
        self.map_fd = None;
        self.heartbeat_map_fd = None;
        self.session_map_fd = None;
        self.conntrack_v4_fd = None;
        self.conntrack_v6_fd = None;
        self.dnat_table_fd = None;
        self.dnat_table_v6_fd = None;
        self.forwarding = ForwardingState::default();
        self.shared_forwarding
            .store(Arc::new(ForwardingState::default()));
        self.shared_validation
            .store(Arc::new(ValidationState::default()));
        self.shared_fabrics.store(Arc::new(Vec::new()));
        self.neighbor_generation.store(0, Ordering::Relaxed);
        if let Ok(mut neighbors) = self.dynamic_neighbors.lock() {
            neighbors.clear();
        }
        if let Ok(mut manager_keys) = self.manager_neighbor_keys.lock() {
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
        self.shared_forwarding
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
        self.shared_fabrics
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
        self.map_fd = Some(map_fd);
        self.heartbeat_map_fd = Some(heartbeat_map_fd);
        self.session_map_fd = Some(session_map_fd);
        self.conntrack_v4_fd = conntrack_v4_fd;
        self.conntrack_v6_fd = conntrack_v6_fd;
        self.dnat_table_fd = dnat_table_fd;
        self.dnat_table_v6_fd = dnat_table_v6_fd;
        let cos_owner_worker_by_ifindex = Arc::new(build_cos_owner_worker_by_ifindex(
            &self.forwarding,
            &workers,
        ));
        self.cos_owner_worker_by_ifindex = cos_owner_worker_by_ifindex.as_ref().clone();
        self.shared_cos_owner_worker_by_ifindex
            .store(cos_owner_worker_by_ifindex.clone());
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
            let shared_forwarding = self.shared_forwarding.clone();
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
            let ha_state = self.ha_state.clone();
            let dynamic_neighbors = self.dynamic_neighbors.clone();
            let worker_poll_mode = self.poll_mode;
            let shared_fabrics = self.shared_fabrics.clone();
            let rg_epochs = self.rg_epochs.clone();
            let event_stream_handle = self.event_stream_worker_handle();
            let cos_status_clone = cos_status.clone();
            let shared_cos_owner_worker_by_ifindex =
                self.shared_cos_owner_worker_by_ifindex.clone();
            let join = thread::Builder::new()
                .name(format!("xpf-userspace-worker-{worker_id}"))
                .spawn(move || {
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
                        shared_cos_owner_worker_by_ifindex,
                        cos_status_clone,
                    );
                });
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
        if self.neigh_monitor_stop.is_none() {
            let stop = Arc::new(AtomicBool::new(false));
            let stop_clone = stop.clone();
            let dynamic_neighbors = self.dynamic_neighbors.clone();
            let neighbor_generation = self.neighbor_generation.clone();
            thread::Builder::new()
                .name("neigh-monitor".to_string())
                .spawn(move || {
                    neigh_monitor_thread(stop_clone, dynamic_neighbors, neighbor_generation)
                })
                .ok();
            self.neigh_monitor_stop = Some(stop);
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
            let ha_state = self.ha_state.clone();
            let dynamic_neighbors = self.dynamic_neighbors.clone();
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
        let mut interfaces = BTreeMap::<i32, crate::protocol::CoSInterfaceStatus>::new();
        let mut queue_maps = BTreeMap::<i32, BTreeMap<u8, crate::protocol::CoSQueueStatus>>::new();
        for worker in self.workers.values() {
            let snapshot = worker.cos_status.load();
            for iface in snapshot.iter() {
                let entry = interfaces.entry(iface.ifindex).or_default();
                entry.ifindex = iface.ifindex;
                if entry.interface_name.is_empty() {
                    entry.interface_name = iface.interface_name.clone();
                }
                if entry.owner_worker_id.is_none() {
                    entry.owner_worker_id = self
                        .cos_owner_worker_by_ifindex
                        .get(&iface.ifindex)
                        .copied();
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
                    if q.forwarding_class.is_empty() {
                        q.forwarding_class = queue.forwarding_class.clone();
                    }
                    if q.worker_instances == 0 {
                        q.priority = queue.priority;
                    } else {
                        q.priority = q.priority.min(queue.priority);
                    }
                    q.exact = queue.exact;
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
                        || (queue.next_wakeup_tick > 0
                            && queue.next_wakeup_tick < q.next_wakeup_tick)
                    {
                        q.next_wakeup_tick = queue.next_wakeup_tick;
                    }
                    q.surplus_deficit_bytes = q
                        .surplus_deficit_bytes
                        .saturating_add(queue.surplus_deficit_bytes);
                }
            }
        }
        let mut out = Vec::with_capacity(interfaces.len());
        for (ifindex, mut iface) in interfaces {
            if let Some(queue_map) = queue_maps.remove(&ifindex) {
                iface.queues = queue_map.into_values().collect();
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
            &self.dynamic_neighbors,
        );
        if !new_fabrics.is_empty() {
            self.forwarding.fabrics = new_fabrics.clone();
            self.shared_fabrics.store(Arc::new(new_fabrics));
            // Also update shared_forwarding so workers see the new fabric
            // links for fabric redirect resolution. Without this, workers
            // use the snapshot's forwarding state which may have empty fabrics
            // if the peer MAC wasn't resolved at snapshot time.
            self.shared_forwarding
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
        let old_manager_keys = if let Ok(mut manager_keys) = self.manager_neighbor_keys.lock() {
            let old = manager_keys.iter().copied().collect::<Vec<_>>();
            *manager_keys = next_manager_keys;
            old
        } else {
            Vec::new()
        };
        if let Ok(mut cache) = self.dynamic_neighbors.lock() {
            for key in &old_manager_keys {
                cache.remove(key);
            }
        }
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
        self.shared_forwarding
            .store(Arc::new(self.forwarding.clone()));
        self.refresh_cos_owner_worker_map_from_identities();
        self.shared_fabrics
            .store(Arc::new(self.forwarding.fabrics.clone()));
    }

    fn refresh_cos_owner_worker_map_from_identities(&mut self) {
        let worker_binding_ifindexes =
            build_worker_binding_ifindexes_from_identities(&self.identities);
        let owner_map = build_cos_owner_worker_by_ifindex_from_binding_ifindexes(
            &self.forwarding,
            &worker_binding_ifindexes,
        );
        self.cos_owner_worker_by_ifindex = owner_map.clone();
        self.shared_cos_owner_worker_by_ifindex
            .store(Arc::new(owner_map));
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
            );
            if disposition == PacketDisposition::Valid && !req.destination_ip.is_empty() {
                if let Ok(dst) = req.destination_ip.parse::<IpAddr>() {
                    let resolution = enforce_ha_resolution(
                        &self.forwarding,
                        &self.ha_state,
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
                                resolution.status(None).disposition
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
                        target_live.enqueue_tx(TxRequest {
                            bytes: frame,
                            expected_ports: None,
                            expected_addr_family: 0,
                            expected_protocol: 0,
                            flow_key: None,
                            egress_ifindex: resolution.egress_ifindex,
                            cos_queue_id: resolve_cos_queue_id(
                                &self.forwarding,
                                resolution.egress_ifindex,
                                meta,
                                None,
                            ),
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
        );
        Ok(())
    }

    pub fn refresh_bindings(&self, bindings: &mut [BindingStatus]) {
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
                binding.last_heartbeat = None;
                binding.last_error.clear();
                binding.ready = false;
            }
        }
    }
}

fn build_cos_owner_worker_by_ifindex(
    forwarding: &ForwardingState,
    workers: &BTreeMap<u32, Vec<BindingPlan>>,
) -> BTreeMap<i32, u32> {
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
    build_cos_owner_worker_by_ifindex_from_binding_ifindexes(forwarding, &worker_binding_ifindexes)
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

fn build_cos_owner_worker_by_ifindex_from_binding_ifindexes(
    forwarding: &ForwardingState,
    worker_binding_ifindexes: &BTreeMap<u32, std::collections::BTreeSet<i32>>,
) -> BTreeMap<i32, u32> {
    let mut owner_by_ifindex = BTreeMap::new();
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
        let eligible_workers = worker_binding_ifindexes
            .iter()
            .filter_map(|(worker_id, ifindexes)| {
                ifindexes.contains(&tx_ifindex).then_some(*worker_id)
            })
            .collect::<Vec<_>>();
        if eligible_workers.is_empty() {
            continue;
        }
        let next_slot = next_owner_slot_by_tx_ifindex.entry(tx_ifindex).or_default();
        let owner_worker_id = eligible_workers[*next_slot % eligible_workers.len()];
        *next_slot += 1;
        owner_by_ifindex.insert(egress_ifindex, owner_worker_id);
    }
    owner_by_ifindex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ClassOfServiceSnapshot, CoSForwardingClassSnapshot, CoSSchedulerMapEntrySnapshot,
        CoSSchedulerMapSnapshot,
    };

    #[test]
    fn build_cos_owner_worker_by_ifindex_prefers_lowest_worker_with_tx_binding() {
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 1_000_000,
                burst_bytes: 64 * 1024,
                default_queue: 0,
                dscp_classifier: String::new(),
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![],
            },
        );
        forwarding.egress.insert(
            80,
            EgressInterface {
                bind_ifindex: 12,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0; 6],
                zone: "wan".to_string(),
                redundancy_group: 0,
                primary_v4: None,
                primary_v6: None,
            },
        );
        let worker_binding_ifindexes = BTreeMap::from([
            (2, std::collections::BTreeSet::from([12])),
            (7, std::collections::BTreeSet::from([12, 13])),
        ]);

        let owner_by_ifindex = build_cos_owner_worker_by_ifindex_from_binding_ifindexes(
            &forwarding,
            &worker_binding_ifindexes,
        );

        assert_eq!(owner_by_ifindex.get(&80), Some(&2));
    }

    #[test]
    fn build_cos_owner_worker_by_ifindex_spreads_interfaces_across_eligible_workers() {
        let mut forwarding = ForwardingState::default();
        for ifindex in [82, 80, 81] {
            forwarding.cos.interfaces.insert(
                ifindex,
                CoSInterfaceConfig {
                    shaping_rate_bytes: 1_000_000,
                    burst_bytes: 64 * 1024,
                    default_queue: 0,
                    dscp_classifier: String::new(),
                    queue_by_forwarding_class: FastMap::default(),
                    queues: vec![],
                },
            );
            forwarding.egress.insert(
                ifindex,
                EgressInterface {
                    bind_ifindex: 12,
                    vlan_id: 0,
                    mtu: 1500,
                    src_mac: [0; 6],
                    zone: "wan".to_string(),
                    redundancy_group: 0,
                    primary_v4: None,
                    primary_v6: None,
                },
            );
        }
        let worker_binding_ifindexes = BTreeMap::from([
            (2, std::collections::BTreeSet::from([12])),
            (7, std::collections::BTreeSet::from([12])),
        ]);

        let owner_by_ifindex = build_cos_owner_worker_by_ifindex_from_binding_ifindexes(
            &forwarding,
            &worker_binding_ifindexes,
        );

        assert_eq!(owner_by_ifindex.get(&80), Some(&2));
        assert_eq!(owner_by_ifindex.get(&81), Some(&7));
        assert_eq!(owner_by_ifindex.get(&82), Some(&2));
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
        });

        coordinator.refresh_runtime_snapshot(&snapshot);

        assert_eq!(coordinator.cos_owner_worker_by_ifindex.get(&80), Some(&2));
        let shared = coordinator.shared_cos_owner_worker_by_ifindex.load();
        assert_eq!(shared.get(&80), Some(&2));
    }
}
