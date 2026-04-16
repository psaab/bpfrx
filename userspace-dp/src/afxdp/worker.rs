use super::*;

pub(crate) struct BindingWorker {
    pub(crate) slot: u32,
    pub(crate) queue_id: u32,
    pub(crate) worker_id: u32,
    pub(crate) interface: Arc<str>,
    pub(crate) ifindex: i32,
    pub(crate) umem: WorkerUmem,
    pub(crate) live: Arc<BindingLiveState>,
    #[allow(dead_code)]
    pub(crate) user: User,
    pub(crate) device: crate::xsk_ffi::DeviceQueue,
    pub(crate) rx: crate::xsk_ffi::RingRx,
    pub(crate) tx: crate::xsk_ffi::RingTx,
    pub(crate) free_tx_frames: VecDeque<u64>,
    pub(crate) pending_tx_prepared: VecDeque<PreparedTxRequest>,
    pub(crate) pending_tx_local: VecDeque<TxRequest>,
    pub(crate) max_pending_tx: usize,
    pub(crate) cos_fast_interfaces: FastMap<i32, WorkerCoSInterfaceFastPath>,
    pub(crate) cos_interfaces: FastMap<i32, CoSInterfaceRuntime>,
    pub(crate) cos_interface_order: Vec<i32>,
    pub(crate) cos_interface_rr: usize,
    pub(crate) cos_nonempty_interfaces: usize,
    pub(crate) pending_fill_frames: VecDeque<u64>,
    pub(crate) scratch_recycle: Vec<u64>,
    pub(crate) scratch_forwards: Vec<PendingForwardRequest>,
    pub(crate) scratch_fill: Vec<u64>,
    pub(crate) scratch_prepared_tx: Vec<PreparedTxRequest>,
    pub(crate) scratch_local_tx: Vec<(u64, TxRequest)>,
    pub(crate) scratch_exact_prepared_tx: Vec<ExactPreparedScratchTxRequest>,
    pub(crate) scratch_exact_local_tx: Vec<ExactLocalScratchTxRequest>,
    pub(crate) scratch_completed_offsets: Vec<u64>,
    pub(crate) scratch_post_recycles: Vec<(u32, u64)>,
    /// Packets waiting for neighbor resolution. The UMEM frame is held
    /// (not recycled) until the neighbor resolves or the entry times out.
    pub(crate) pending_neigh: VecDeque<PendingNeighPacket>,
    /// Flow cache fast-path: cross-binding in-place rewrites deferred
    /// until after the RX batch (borrow checker prevents mutable access
    /// to two bindings simultaneously inside the RX loop).
    #[allow(dead_code)] // reserved for cross-binding fast-path
    pub(crate) scratch_cross_binding_tx: Vec<(usize, PreparedTxRequest)>,
    pub(crate) scratch_rst_teardowns: Vec<(SessionKey, NatDecision)>,
    pub(crate) in_flight_prepared_recycles: FastMap<u64, PreparedTxRecycle>,
    pub(crate) heartbeat_map_fd: c_int,
    pub(crate) session_map_fd: c_int,
    pub(crate) conntrack_v4_fd: c_int,
    pub(crate) conntrack_v6_fd: c_int,
    pub(crate) last_heartbeat_update_ns: u64,
    pub(crate) debug_state_counter: u32,
    pub(crate) last_rx_wake_ns: u64,
    pub(crate) last_tx_wake_ns: u64,
    pub(crate) outstanding_tx: u32,
    pub(crate) empty_rx_polls: u32,
    pub(crate) last_learned_neighbor: Option<LearnedNeighborKey>,
    pub(crate) dbg_fill_submitted: u64,
    pub(crate) dbg_fill_failed: u64,
    pub(crate) dbg_poll_cycles: u64,
    pub(crate) dbg_backpressure: u64,
    pub(crate) dbg_rx_empty: u64,
    pub(crate) dbg_rx_wakeups: u64,
    // TX pipeline debug counters
    pub(crate) dbg_tx_ring_submitted: u64, // descriptors inserted into TX ring
    pub(crate) dbg_tx_ring_full: u64,      // times TX ring insert returned 0
    pub(crate) dbg_completions_reaped: u64, // completion descriptors read
    pub(crate) dbg_sendto_calls: u64,      // number of sendto/wake calls
    pub(crate) dbg_sendto_err: u64,        // sendto returned error (non-EAGAIN/ENOBUFS)
    pub(crate) dbg_sendto_eagain: u64,     // sendto returned EAGAIN/EWOULDBLOCK
    pub(crate) dbg_sendto_enobufs: u64,    // sendto returned ENOBUFS (kernel TX drop)
    pub(crate) dbg_pending_overflow: u64,  // drops from bound_pending overflow
    pub(crate) dbg_tx_tcp_rst: u64,        // TCP RST packets transmitted
    // Ring diagnostics — raw values from xsk_ffi API
    pub(crate) dbg_rx_avail_nonzero: u64, // times rx.available() > 0
    pub(crate) dbg_rx_avail_max: u32,     // max rx.available() seen this interval
    pub(crate) dbg_fill_pending: u32,     // fill ring: userspace produced - kernel consumed
    pub(crate) dbg_device_avail: u32,     // device queue available (completion ring pending)
    pub(crate) dbg_rx_wake_sendto_ok: u64, // sendto() returned >= 0 in maybe_wake_rx
    pub(crate) dbg_rx_wake_sendto_err: u64, // sendto() returned < 0 in maybe_wake_rx
    pub(crate) dbg_rx_wake_sendto_errno: i32, // last errno from sendto in maybe_wake_rx
    pub(crate) pending_direct_tx_packets: u64,
    pub(crate) pending_copy_tx_packets: u64,
    pub(crate) pending_in_place_tx_packets: u64,
    pub(crate) pending_direct_tx_no_frame_fallback_packets: u64,
    pub(crate) pending_direct_tx_build_fallback_packets: u64,
    pub(crate) pending_direct_tx_disallowed_fallback_packets: u64,
    pub(crate) flow_cache: FlowCache,
    pub(crate) flow_cache_session_touch: u64,
    /// Timestamp when this binding was created.
    #[allow(dead_code)] // reserved for heartbeat gating logic
    pub(crate) bind_time_ns: u64,
    /// Zero-copy vs copy mode (affects heartbeat gating).
    #[allow(dead_code)] // reserved for heartbeat gating logic
    pub(crate) bind_mode: XskBindMode,
    /// Set true once the XSK RX ring has delivered at least one packet,
    /// proving the NIC's XSK receive queue is active for this binding.
    pub(crate) xsk_rx_confirmed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum XskBindMode {
    Unknown,
    Copy,
    ZeroCopy,
}

impl XskBindMode {
    pub(crate) fn as_u8(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Copy => 1,
            Self::ZeroCopy => 2,
        }
    }

    pub(crate) fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Copy,
            2 => Self::ZeroCopy,
            _ => Self::Unknown,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "",
            Self::Copy => "copy",
            Self::ZeroCopy => "zerocopy",
        }
    }

    pub(crate) fn is_zerocopy(self) -> bool {
        matches!(self, Self::ZeroCopy)
    }
}

pub(crate) fn fabric_queue_hash(
    flow: Option<&SessionFlow>,
    expected_ports: Option<(u16, u16)>,
    meta: UserspaceDpMeta,
) -> u64 {
    fn mix(seed: &mut u64, value: u64) {
        *seed ^= value
            .wrapping_add(0x9e3779b97f4a7c15)
            .wrapping_add(*seed << 6)
            .wrapping_add(*seed >> 2);
    }

    let mut seed = meta.protocol as u64;
    if let Some(flow) = flow {
        match flow.src_ip {
            IpAddr::V4(ip) => mix(&mut seed, u32::from(ip) as u64),
            IpAddr::V6(ip) => {
                for chunk in ip.octets().chunks_exact(8) {
                    mix(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
                }
            }
        }
        match flow.dst_ip {
            IpAddr::V4(ip) => mix(&mut seed, u32::from(ip) as u64),
            IpAddr::V6(ip) => {
                for chunk in ip.octets().chunks_exact(8) {
                    mix(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
                }
            }
        }
        mix(&mut seed, flow.forward_key.src_port as u64);
        mix(&mut seed, flow.forward_key.dst_port as u64);
        return seed;
    }
    let (src_port, dst_port) = expected_ports.unwrap_or((meta.flow_src_port, meta.flow_dst_port));
    mix(&mut seed, src_port as u64);
    mix(&mut seed, dst_port as u64);
    seed
}

#[derive(Clone, Debug)]
pub(crate) struct SyncedSessionEntry {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) protocol: u8,
    pub(crate) tcp_flags: u8,
}

impl BindingWorker {
    fn create(
        binding: &BindingStatus,
        ring_entries: u32,
        xsk_map_fd: c_int,
        heartbeat_map_fd: c_int,
        session_map_fd: c_int,
        conntrack_v4_fd: c_int,
        conntrack_v6_fd: c_int,
        live: Arc<BindingLiveState>,
        bind_strategy: AfXdpBindStrategy,
        poll_mode: crate::PollMode,
        mut worker_umem: WorkerUmem,
        frame_pool: &mut VecDeque<u64>,
        shared_umem: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let driver_name = interface_driver_name(&binding.interface);
        let total_frames =
            binding_frame_count_for_driver(driver_name.as_deref(), ring_entries).max(1);
        let reserved_tx =
            reserved_tx_frames_for_driver(driver_name.as_deref(), ring_entries).min(total_frames);
        let mut reserved_tx_frames = VecDeque::with_capacity(reserved_tx as usize);
        for _ in 0..reserved_tx {
            let Some(offset) = frame_pool.pop_front() else {
                return Err(format!(
                    "insufficient shared UMEM frames for reserved TX on {} if{}q{}",
                    binding.interface, binding.ifindex, binding.queue_id
                )
                .into());
            };
            reserved_tx_frames.push_back(offset);
        }
        // Pre-populate fill ring with ALL remaining frames — no spare held back.
        // This maximizes the kernel's ability to place received packets and
        // prevents fill ring starvation under burst conditions (copy-mode fix).
        let mut initial_fill_frames = Vec::with_capacity((total_frames - reserved_tx) as usize);
        for _ in reserved_tx..total_frames {
            let Some(offset) = frame_pool.pop_front() else {
                return Err(format!(
                    "insufficient shared UMEM frames for fill ring on {} if{}q{}",
                    binding.interface, binding.ifindex, binding.queue_id
                )
                .into());
            };
            initial_fill_frames.push(offset);
        }
        let info = ifinfo_from_binding(binding)?;
        let (user, rx, tx, bind_mode, actual_bind_strategy, device) = open_binding_worker_rings(
            &mut worker_umem,
            &info,
            ring_entries,
            bind_strategy,
            driver_name.as_deref(),
            poll_mode,
            Some(&initial_fill_frames),
        )
        .map_err(|err| format!("configure AF_XDP rings: {err}"))?;

        let user_fd = user.as_raw_fd();
        live.set_bound(user_fd);
        live.set_bind_mode(bind_mode);
        // getsockname() returns ENOTSUP on AF_XDP sockets (kernel doesn't
        // implement it for this family).  Use the binding plan's expected
        // ifindex/queue_id directly — umem.bind() already validated these.
        live.set_socket_binding(binding.ifindex, binding.queue_id, 0);
        eprintln!(
            "xpf-userspace-dp: binding slot={} fd={} strategy={} bound if{}q{} mode={:?} shared_umem={}",
            binding.slot,
            user_fd,
            actual_bind_strategy.describe(),
            binding.ifindex,
            binding.queue_id,
            bind_mode,
            shared_umem,
        );
        if let Err(err) = register_xsk_slot(xsk_map_fd, binding.slot, user_fd) {
            eprintln!(
                "xpf-userspace-dp: ERROR register_xsk_slot slot={} fd={}: {}",
                binding.slot, user_fd, err,
            );
            live.set_error(format!("register XSK slot: {err}"));
        } else {
            eprintln!(
                "xpf-userspace-dp: registered slot={} fd={} in XSKMAP",
                binding.slot, user_fd,
            );
            live.set_xsk_registered(true);
            live.clear_error();
        }
        let init_now = monotonic_nanos();
        let max_pending_tx = pending_tx_capacity(ring_entries);
        if let Err(err) = touch_heartbeat(heartbeat_map_fd, binding.slot, &live, init_now) {
            live.set_error(format!("update heartbeat slot: {err}"));
        }
        live.set_max_pending_tx(max_pending_tx);
        let mut binding = Self {
            slot: binding.slot,
            queue_id: binding.queue_id,
            worker_id: binding.worker_id,
            interface: Arc::<str>::from(binding.interface.as_str()),
            ifindex: binding.ifindex,
            umem: worker_umem,
            live,
            user,
            device,
            rx,
            tx,
            free_tx_frames: reserved_tx_frames,
            pending_tx_prepared: VecDeque::new(),
            pending_tx_local: VecDeque::new(),
            max_pending_tx,
            cos_fast_interfaces: FastMap::default(),
            cos_interfaces: FastMap::default(),
            cos_interface_order: Vec::new(),
            cos_interface_rr: 0,
            cos_nonempty_interfaces: 0,
            pending_fill_frames: VecDeque::new(),
            scratch_recycle: Vec::with_capacity(RX_BATCH_SIZE as usize),
            scratch_forwards: Vec::with_capacity(RX_BATCH_SIZE as usize),
            scratch_fill: Vec::with_capacity(FILL_BATCH_SIZE),
            scratch_prepared_tx: Vec::with_capacity(TX_BATCH_SIZE),
            scratch_local_tx: Vec::with_capacity(TX_BATCH_SIZE),
            scratch_exact_prepared_tx: Vec::with_capacity(TX_BATCH_SIZE),
            scratch_exact_local_tx: Vec::with_capacity(TX_BATCH_SIZE),
            scratch_completed_offsets: Vec::with_capacity(ring_entries as usize),
            scratch_post_recycles: Vec::with_capacity(RX_BATCH_SIZE as usize),
            pending_neigh: VecDeque::with_capacity(MAX_PENDING_NEIGH),
            scratch_cross_binding_tx: Vec::with_capacity(RX_BATCH_SIZE as usize),
            scratch_rst_teardowns: Vec::with_capacity(16),
            in_flight_prepared_recycles: FastMap::default(),
            heartbeat_map_fd,
            session_map_fd,
            conntrack_v4_fd,
            conntrack_v6_fd,
            last_heartbeat_update_ns: init_now,
            debug_state_counter: 0,
            last_rx_wake_ns: init_now,
            last_tx_wake_ns: init_now,
            outstanding_tx: 0,
            empty_rx_polls: 0,
            last_learned_neighbor: None,
            dbg_fill_submitted: 0,
            dbg_fill_failed: 0,
            dbg_poll_cycles: 0,
            dbg_backpressure: 0,
            dbg_rx_empty: 0,
            dbg_rx_wakeups: 0,
            dbg_tx_ring_submitted: 0,
            dbg_tx_ring_full: 0,
            dbg_completions_reaped: 0,
            dbg_sendto_calls: 0,
            dbg_sendto_err: 0,
            dbg_sendto_eagain: 0,
            dbg_sendto_enobufs: 0,
            dbg_pending_overflow: 0,
            dbg_tx_tcp_rst: 0,
            dbg_rx_avail_nonzero: 0,
            dbg_rx_avail_max: 0,
            dbg_fill_pending: 0,
            dbg_device_avail: 0,
            dbg_rx_wake_sendto_ok: 0,
            dbg_rx_wake_sendto_err: 0,
            dbg_rx_wake_sendto_errno: 0,
            pending_direct_tx_packets: 0,
            pending_copy_tx_packets: 0,
            pending_in_place_tx_packets: 0,
            pending_direct_tx_no_frame_fallback_packets: 0,
            pending_direct_tx_build_fallback_packets: 0,
            pending_direct_tx_disallowed_fallback_packets: 0,
            flow_cache: FlowCache::new(),
            flow_cache_session_touch: 0,
            bind_time_ns: {
                let mut ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
                ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
            },
            xsk_rx_confirmed: false,
            bind_mode,
        };
        update_binding_debug_state(&mut binding);
        Ok(binding)
    }

    pub(crate) fn identity(&self) -> BindingIdentity {
        BindingIdentity {
            slot: self.slot,
            queue_id: self.queue_id,
            worker_id: self.worker_id,
            interface: self.interface.clone(),
            ifindex: self.ifindex,
        }
    }
}
pub(crate) fn worker_loop(
    worker_id: u32,
    binding_plans: Vec<BindingPlan>,
    shared_validation: Arc<ArcSwap<ValidationState>>,
    shared_forwarding: Arc<ArcSwap<ForwardingState>>,
    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    dynamic_neighbors: Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
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
    shared_cos_queue_leases: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>>,
    cos_status: Arc<ArcSwap<Vec<crate::protocol::CoSInterfaceStatus>>>,
) {
    pin_current_thread(worker_id);
    const COS_STATUS_INTERVAL_NS: u64 = 100_000_000;
    let ha_startup_grace_until_secs =
        (monotonic_nanos() / 1_000_000_000).saturating_add(TUNNEL_HA_STARTUP_GRACE_SECS);
    let mut validation = **shared_validation.load();
    let mut forwarding = shared_forwarding.load_full();
    let mut cos_owner_worker_by_queue = shared_cos_owner_worker_by_queue.load_full();
    let mut cos_owner_live_by_queue = shared_cos_owner_live_by_queue.load_full();
    let mut cos_shared_root_leases = shared_cos_root_leases.load_full();
    let mut cos_shared_queue_leases = shared_cos_queue_leases.load_full();
    let mut sessions = SessionTable::new();
    let mut screen_state = ScreenState::new();
    screen_state.update_profiles(forwarding.screen_profiles.clone());
    sessions.set_timeouts(forwarding.session_timeouts);
    let mut bindings = Vec::with_capacity(binding_plans.len());
    for plan in binding_plans {
        let driver_name = interface_driver_name(&plan.status.interface);
        let total_frames =
            binding_frame_count_for_driver(driver_name.as_deref(), plan.ring_entries).max(1);
        let binding = match WorkerUmemPool::new(total_frames)
            .map_err(|err| format!("create binding umem: {err}"))
        {
            Ok(WorkerUmemPool {
                umem,
                mut free_frames,
            }) => BindingWorker::create(
                &plan.status,
                plan.ring_entries,
                plan.xsk_map_fd,
                plan.heartbeat_map_fd,
                plan.session_map_fd,
                plan.conntrack_v4_fd,
                plan.conntrack_v6_fd,
                plan.live.clone(),
                plan.bind_strategy,
                plan.poll_mode,
                umem,
                &mut free_frames,
                false,
            ),
            Err(err) => Err(err.to_string().into()),
        };
        match binding {
            Ok(binding) => bindings.push(binding),
            Err(err) => plan.live.set_error(err.to_string()),
        }
    }
    let binding_lookup = WorkerBindingLookup::from_bindings(&bindings);
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
        cos_shared_queue_leases.as_ref(),
    );
    for binding in bindings.iter_mut() {
        binding.cos_fast_interfaces = cos_fast_interfaces.clone();
    }
    let mut interrupt_poll_fds = if poll_mode == crate::PollMode::Interrupt {
        bindings
            .iter()
            .map(|binding| libc::pollfd {
                fd: binding.device.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mut idle_iters = 0u32;
    let mut poll_start = 0usize;
    let mut shared_recycles = Vec::with_capacity((RX_BATCH_SIZE as usize).saturating_mul(2));
    // Debug: periodic summary counters
    let mut dbg_last_report_ns = monotonic_nanos();
    let mut dbg_rx_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_total = 0u64;
    let mut dbg_forward_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_local_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_session_hit = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_session_miss = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_session_create = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_no_route = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_missing_neigh = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_policy_deny = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_ha_inactive = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_no_egress_binding = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_build_fail = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_err = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_metadata_err = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_disposition_other = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_ok = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_inplace = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_direct = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_copy = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_from_trust = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_from_wan = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_trust_to_wan = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_wan_to_trust = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_nat_snat = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_nat_dnat = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_nat_none = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_frame_build_none = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_rst = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_tcp_rst = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_fin = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_synack = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_zero_window = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_tcp_fin = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_tcp_rst = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_tcp_zero_window = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_bytes_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_bytes_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_oversized = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_max_frame = 0u32;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_max_frame = 0u32;
    #[cfg(feature = "debug-log")]
    let mut dbg_seg_needed_but_none = 0u64;
    let mut prev_rx_total = 0u64;
    let mut prev_fwd_total = 0u64;
    let mut stall_prev_fwd = 0u64;
    let mut stall_reported = false;
    const DBG_REPORT_INTERVAL_NS: u64 = 1_000_000_000; // 1 second
    // Throttle for BPF conntrack last_seen refresh (~10s).
    // Keeps `show security flow session` idle times accurate without
    // per-second syscall overhead per session.  See issue #333.
    const CT_REFRESH_INTERVAL_NS: u64 = 10_000_000_000;
    // Cache BPF map FDs — they don't change during the worker's lifetime.
    let session_map_fd = bindings
        .first()
        .map(|binding| binding.session_map_fd)
        .unwrap_or(-1);
    let conntrack_v4_fd = bindings
        .first()
        .map(|binding| binding.conntrack_v4_fd)
        .unwrap_or(-1);
    let conntrack_v6_fd = bindings
        .first()
        .map(|binding| binding.conntrack_v6_fd)
        .unwrap_or(-1);
    let mut last_ct_refresh_ns: u64 = 0;
    cos_status.store(Arc::new(build_worker_cos_statuses(
        &bindings,
        forwarding.as_ref(),
    )));
    let mut last_cos_status_ns = monotonic_nanos();
    while !stop.load(Ordering::Relaxed) {
        let loop_now_ns = monotonic_nanos();
        let loop_now_secs = loop_now_ns / 1_000_000_000;
        let live_validation = shared_validation.load();
        if **live_validation != validation {
            validation = **live_validation;
        }
        let live_forwarding = shared_forwarding.load_full();
        let mut rebuild_cos_fast_interfaces = false;
        if !Arc::ptr_eq(&forwarding, &live_forwarding) {
            let cos_changed =
                cos_runtime_config_changed(forwarding.as_ref(), live_forwarding.as_ref());
            forwarding = live_forwarding;
            screen_state.update_profiles(forwarding.screen_profiles.clone());
            sessions.set_timeouts(forwarding.session_timeouts);
            if cos_changed {
                reset_worker_cos_runtimes(&mut bindings);
                rebuild_cos_fast_interfaces = true;
            }
        }
        let live_cos_owner_worker_by_queue = shared_cos_owner_worker_by_queue.load_full();
        if !Arc::ptr_eq(&cos_owner_worker_by_queue, &live_cos_owner_worker_by_queue) {
            cos_owner_worker_by_queue = live_cos_owner_worker_by_queue;
            rebuild_cos_fast_interfaces = true;
        }
        let live_cos_owner_live_by_queue = shared_cos_owner_live_by_queue.load_full();
        if !Arc::ptr_eq(&cos_owner_live_by_queue, &live_cos_owner_live_by_queue) {
            cos_owner_live_by_queue = live_cos_owner_live_by_queue;
            rebuild_cos_fast_interfaces = true;
        }
        let live_cos_shared_root_leases = shared_cos_root_leases.load_full();
        if !Arc::ptr_eq(&cos_shared_root_leases, &live_cos_shared_root_leases) {
            for binding in bindings.iter_mut() {
                release_all_cos_root_leases(binding);
                release_all_cos_queue_leases(binding);
            }
            cos_shared_root_leases = live_cos_shared_root_leases;
            rebuild_cos_fast_interfaces = true;
        }
        let live_cos_shared_queue_leases = shared_cos_queue_leases.load_full();
        if !Arc::ptr_eq(&cos_shared_queue_leases, &live_cos_shared_queue_leases) {
            for binding in bindings.iter_mut() {
                release_all_cos_queue_leases(binding);
            }
            cos_shared_queue_leases = live_cos_shared_queue_leases;
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
                cos_shared_queue_leases.as_ref(),
            );
            for binding in bindings.iter_mut() {
                binding.cos_fast_interfaces = cos_fast_interfaces.clone();
            }
        }
        let ha_runtime = ha_state.load();
        // Only apply commands when pending — avoids lock overhead on
        // every loop iteration in the common (empty-queue) case.
        let has_commands = commands.try_lock().map(|q| !q.is_empty()).unwrap_or(false);
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
            }
        };
        let WorkerCommandResults {
            cancelled_keys,
            exported_sequences,
            shaped_tx_requests,
        } = command_results;
        if !shaped_tx_requests.is_empty() {
            apply_worker_shaped_tx_requests(
                &mut bindings,
                forwarding.as_ref(),
                &binding_lookup,
                loop_now_ns,
                shaped_tx_requests,
            );
        }
        if !cancelled_keys.is_empty() {
            for key in &cancelled_keys {
                for binding in bindings.iter_mut() {
                    cancel_queued_flow_on_binding(binding, key, key);
                }
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
        let expired_entries = sessions.expire_stale_entries(loop_now_ns);
        let expired = expired_entries.len() as u64;
        for expired_entry in expired_entries {
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
        if expired > 0 {
            if let Some(binding) = bindings.first() {
                binding
                    .live
                    .session_expires
                    .fetch_add(expired, Ordering::Relaxed);
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
                &mut sessions,
                &mut screen_state,
                validation,
                loop_now_ns,
                loop_now_secs,
                ha_startup_grace_until_secs,
                &forwarding,
                ha_runtime.as_ref(),
                &dynamic_neighbors,
                &shared_sessions,
                &shared_nat_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                slow_path.as_ref(),
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
                cos_owner_worker_by_queue.as_ref(),
                cos_owner_live_by_queue.as_ref(),
            ) {
                did_work = true;
            }
        }
        crate::filter::flush_recorded_filter_counters();
        dbg_rx_total += dbg_poll.rx;
        #[cfg(feature = "debug-log")]
        {
            dbg_tx_total += dbg_poll.tx;
        }
        dbg_forward_total += dbg_poll.forward;
        #[cfg(feature = "debug-log")]
        {
            dbg_local_total += dbg_poll.local;
            dbg_session_hit += dbg_poll.session_hit;
            dbg_session_miss += dbg_poll.session_miss;
            dbg_session_create += dbg_poll.session_create;
            dbg_no_route += dbg_poll.no_route;
            dbg_missing_neigh += dbg_poll.missing_neigh;
            dbg_policy_deny += dbg_poll.policy_deny;
            dbg_ha_inactive += dbg_poll.ha_inactive;
            dbg_no_egress_binding += dbg_poll.no_egress_binding;
            dbg_build_fail += dbg_poll.build_fail;
            dbg_tx_err += dbg_poll.tx_err;
            dbg_metadata_err += dbg_poll.metadata_err;
        }
        #[cfg(feature = "debug-log")]
        {
            dbg_disposition_other += dbg_poll.disposition_other;
            dbg_enqueue_ok += dbg_poll.enqueue_ok;
            dbg_enqueue_inplace += dbg_poll.enqueue_inplace;
            dbg_enqueue_direct += dbg_poll.enqueue_direct;
            dbg_enqueue_copy += dbg_poll.enqueue_copy;
            dbg_rx_from_trust += dbg_poll.rx_from_trust;
            dbg_rx_from_wan += dbg_poll.rx_from_wan;
            dbg_fwd_trust_to_wan += dbg_poll.fwd_trust_to_wan;
            dbg_fwd_wan_to_trust += dbg_poll.fwd_wan_to_trust;
            dbg_nat_snat += dbg_poll.nat_applied_snat;
            dbg_nat_dnat += dbg_poll.nat_applied_dnat;
            dbg_nat_none += dbg_poll.nat_applied_none;
            dbg_frame_build_none += dbg_poll.frame_build_none;
        }
        #[cfg(feature = "debug-log")]
        {
            dbg_rx_tcp_rst += dbg_poll.rx_tcp_rst;
            dbg_rx_tcp_fin += dbg_poll.rx_tcp_fin;
            dbg_rx_tcp_synack += dbg_poll.rx_tcp_synack;
            dbg_rx_tcp_zero_window += dbg_poll.rx_tcp_zero_window;
            dbg_fwd_tcp_fin += dbg_poll.fwd_tcp_fin;
            dbg_fwd_tcp_rst += dbg_poll.fwd_tcp_rst;
            dbg_fwd_tcp_zero_window += dbg_poll.fwd_tcp_zero_window;
        }
        #[cfg(feature = "debug-log")]
        {
            dbg_rx_bytes_total += dbg_poll.rx_bytes_total;
            dbg_tx_bytes_total += dbg_poll.tx_bytes_total;
            dbg_rx_oversized += dbg_poll.rx_oversized;
            if dbg_poll.rx_max_frame > dbg_rx_max_frame {
                dbg_rx_max_frame = dbg_poll.rx_max_frame;
            }
            if dbg_poll.tx_max_frame > dbg_tx_max_frame {
                dbg_tx_max_frame = dbg_poll.tx_max_frame;
            }
            dbg_seg_needed_but_none += dbg_poll.seg_needed_but_none;
        }
        if !bindings.is_empty() {
            poll_start = (poll_start + 1) % bindings.len();
        }
        if loop_now_ns.saturating_sub(last_cos_status_ns) >= COS_STATUS_INTERVAL_NS {
            cos_status.store(Arc::new(build_worker_cos_statuses(
                &bindings,
                forwarding.as_ref(),
            )));
            last_cos_status_ns = loop_now_ns;
        }
        if !exported_sequences.is_empty() {
            while sessions.has_pending_deltas() {
                let deltas = sessions.drain_deltas(256);
                purge_queued_flows_for_closed_deltas(&mut bindings, &deltas);
                if let Some(binding) = bindings.first() {
                    let ident = binding.identity();
                    flush_session_deltas(
                        &ident,
                        &binding.live,
                        binding.session_map_fd,
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
                        &forwarding.zone_name_to_id,
                    );
                }
            }
            if let Some(sequence) = exported_sequences.iter().copied().max() {
                session_export_ack.store(sequence, Ordering::Release);
            }
        } else if sessions.has_pending_deltas() {
            let deltas = sessions.drain_deltas(256);
            purge_queued_flows_for_closed_deltas(&mut bindings, &deltas);
            if let Some(binding) = bindings.first() {
                let ident = binding.identity();
                flush_session_deltas(
                    &ident,
                    &binding.live,
                    binding.session_map_fd,
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
                    &forwarding.zone_name_to_id,
                );
            }
        }
        // Debug: periodic summary report
        {
            let elapsed = loop_now_ns.saturating_sub(dbg_last_report_ns);
            if elapsed >= DBG_REPORT_INTERVAL_NS {
                #[cfg(feature = "debug-log")]
                let secs = elapsed as f64 / 1_000_000_000.0;
                let session_count = sessions.len();
                let mut binding_summary = String::new();
                for (i, b) in bindings.iter().enumerate() {
                    use std::fmt::Write;
                    let fill_pending = b.device.pending();
                    let rx_avail = b.rx.available_relaxed();
                    let xsk_stats = b.device.statistics_v2().ok();
                    let inflight_recycles = b.in_flight_prepared_recycles.len() as u32;
                    let scratch_recycle_len = b.scratch_recycle.len() as u32;
                    let ptx_prepared = b.pending_tx_prepared.len() as u32;
                    let ptx_local = b.pending_tx_local.len() as u32;
                    let total_accounted = b.pending_fill_frames.len() as u32
                        + fill_pending
                        + rx_avail
                        + b.free_tx_frames.len() as u32
                        + b.outstanding_tx
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
                        b.pending_fill_frames.len(),
                        fill_pending,
                        rx_avail,
                        b.free_tx_frames.len(),
                        b.outstanding_tx,
                        inflight_recycles,
                        scratch_recycle_len,
                        ptx_prepared,
                        ptx_local,
                        total_accounted,
                        expected_total,
                        b.dbg_fill_submitted,
                        b.dbg_poll_cycles,
                        b.dbg_backpressure,
                        b.dbg_rx_empty,
                        b.dbg_rx_wakeups,
                    );
                    // TX pipeline debug counters
                    #[cfg(feature = "debug-log")]
                    {
                        dbg_tx_tcp_rst += b.dbg_tx_tcp_rst;
                    }
                    let _ = write!(
                        binding_summary,
                        " TX:ring_sub={}/ring_full={}/compl={}/sendto={}/err={}/eagain={}/enobufs={}/overflow={}",
                        b.dbg_tx_ring_submitted,
                        b.dbg_tx_ring_full,
                        b.dbg_completions_reaped,
                        b.dbg_sendto_calls,
                        b.dbg_sendto_err,
                        b.dbg_sendto_eagain,
                        b.dbg_sendto_enobufs,
                        b.dbg_pending_overflow,
                    );
                    #[cfg(feature = "debug-log")]
                    let _ = write!(binding_summary, "/rst={}", b.dbg_tx_tcp_rst);
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
                        let fd = b.rx.as_raw_fd();
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
                            b.dbg_rx_avail_nonzero,
                            b.dbg_rx_avail_max,
                            b.dbg_fill_pending,
                            b.dbg_device_avail,
                            b.dbg_rx_wake_sendto_ok,
                            b.dbg_rx_wake_sendto_err,
                            b.dbg_rx_wake_sendto_errno,
                        );
                        // Direct mmap diagnosis: read raw ring producer/consumer
                        if let Some((rxp, rxc, frp, frc, txp, txc, crp, crc)) =
                            diagnose_raw_ring_state(b.rx.as_raw_fd())
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
                #[cfg(feature = "debug-log")]
                eprintln!(
                    "DBG w{}: {:.1}s rx={} tx={} fwd={} local={} sess_hit={} sess_miss={} sess_create={} \
                     no_route={} miss_neigh={} pol_deny={} ha_inact={} no_egress={} build_fail={} \
                     tx_err={} meta_err={} other={} enq_ok={} enq_ip={} enq_dir={} enq_cp={} sessions={} \
                     DIR:trust_rx={}/wan_rx={}/t2w={}/w2t={} NAT:snat={}/dnat={}/none={}/bld_none={} RST:rx={}/tx={} \
                     SIZE:rx_avg={}/rx_max={}/tx_avg={}/tx_max={}/rx_over={}/seg_miss={} \
                     TCP_RX:fin={}/synack={}/zwin={} TCP_FWD:fin={}/rst={}/zwin={} \
                     CSUM:verified={}/bad_ip={}/bad_l4={} \
                     SESS_BPF:verify_ok={}/verify_fail={}/bpf_entries={} bindings:{}",
                    worker_id,
                    secs,
                    dbg_rx_total,
                    dbg_tx_total,
                    dbg_forward_total,
                    dbg_local_total,
                    dbg_session_hit,
                    dbg_session_miss,
                    dbg_session_create,
                    dbg_no_route,
                    dbg_missing_neigh,
                    dbg_policy_deny,
                    dbg_ha_inactive,
                    dbg_no_egress_binding,
                    dbg_build_fail,
                    dbg_tx_err,
                    dbg_metadata_err,
                    dbg_disposition_other,
                    dbg_enqueue_ok,
                    dbg_enqueue_inplace,
                    dbg_enqueue_direct,
                    dbg_enqueue_copy,
                    session_count,
                    dbg_rx_from_trust,
                    dbg_rx_from_wan,
                    dbg_fwd_trust_to_wan,
                    dbg_fwd_wan_to_trust,
                    dbg_nat_snat,
                    dbg_nat_dnat,
                    dbg_nat_none,
                    dbg_frame_build_none,
                    dbg_rx_tcp_rst,
                    dbg_tx_tcp_rst,
                    if dbg_rx_total > 0 {
                        dbg_rx_bytes_total / dbg_rx_total
                    } else {
                        0
                    },
                    dbg_rx_max_frame,
                    if dbg_enqueue_ok > 0 {
                        dbg_tx_bytes_total / dbg_enqueue_ok
                    } else {
                        0
                    },
                    dbg_tx_max_frame,
                    dbg_rx_oversized,
                    dbg_seg_needed_but_none,
                    dbg_rx_tcp_fin,
                    dbg_rx_tcp_synack,
                    dbg_rx_tcp_zero_window,
                    dbg_fwd_tcp_fin,
                    dbg_fwd_tcp_rst,
                    dbg_fwd_tcp_zero_window,
                    CSUM_VERIFIED_TOTAL.swap(0, Ordering::Relaxed),
                    CSUM_BAD_IP_TOTAL.swap(0, Ordering::Relaxed),
                    CSUM_BAD_L4_TOTAL.swap(0, Ordering::Relaxed),
                    SESSION_PUBLISH_VERIFY_OK.swap(0, Ordering::Relaxed),
                    SESSION_PUBLISH_VERIFY_FAIL.swap(0, Ordering::Relaxed),
                    if let Some(b) = bindings.first() {
                        count_bpf_session_entries(b.session_map_fd)
                    } else {
                        0
                    },
                    binding_summary,
                );
                // Non-debug builds: no per-second stats dump (use debug-log feature for verbose output).
                // Print XDP shim fallback stats — tells us WHY packets stop
                // being redirected to XSK.
                if cfg!(feature = "debug-log") {
                    if let Some(stats) = read_fallback_stats() {
                        if !stats.is_empty() {
                            let s: Vec<String> =
                                stats.iter().map(|(n, v)| format!("{n}={v}")).collect();
                            eprintln!("DBG w{}: XDP_FALLBACK: {}", worker_id, s.join(" "));
                        }
                    }
                }
                // Save prev counters BEFORE reset for stall detection below
                if cfg!(feature = "debug-log") {
                    prev_rx_total = dbg_rx_total;
                    prev_fwd_total = dbg_forward_total;
                }
                dbg_last_report_ns = loop_now_ns;
                dbg_rx_total = 0;
                #[cfg(feature = "debug-log")]
                {
                    dbg_tx_total = 0;
                }
                dbg_forward_total = 0;
                #[cfg(feature = "debug-log")]
                {
                    dbg_local_total = 0;
                    dbg_session_hit = 0;
                    dbg_session_miss = 0;
                    dbg_session_create = 0;
                    dbg_no_route = 0;
                    dbg_missing_neigh = 0;
                    dbg_policy_deny = 0;
                    dbg_ha_inactive = 0;
                    dbg_no_egress_binding = 0;
                    dbg_build_fail = 0;
                    dbg_tx_err = 0;
                    dbg_metadata_err = 0;
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_disposition_other = 0;
                    dbg_enqueue_ok = 0;
                    dbg_enqueue_inplace = 0;
                    dbg_enqueue_direct = 0;
                    dbg_enqueue_copy = 0;
                    dbg_rx_from_trust = 0;
                    dbg_rx_from_wan = 0;
                    dbg_fwd_trust_to_wan = 0;
                    dbg_fwd_wan_to_trust = 0;
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_rx_bytes_total = 0;
                    dbg_tx_bytes_total = 0;
                    dbg_rx_oversized = 0;
                    dbg_rx_max_frame = 0;
                    dbg_tx_max_frame = 0;
                    dbg_seg_needed_but_none = 0;
                }
                // Stall detection: stall_prev_fwd is PREVIOUS interval's fwd count,
                // prev_fwd_total is THIS interval's fwd count (saved before reset).
                if cfg!(feature = "debug-log") {
                    if stall_prev_fwd > 10 && prev_fwd_total == 0 && !stall_reported {
                        stall_reported = true;
                        eprintln!(
                            "DBG STALL_DETECTED: w{} two_ago_fwd={} this_interval_fwd={} this_interval_rx={} sessions={}",
                            worker_id, stall_prev_fwd, prev_fwd_total, prev_rx_total, session_count
                        );
                        // Dump comprehensive per-binding state at stall moment
                        for (si, sb) in bindings.iter().enumerate() {
                            use std::fmt::Write;
                            let fill_p = sb.device.pending();
                            let rx_a = sb.rx.available_relaxed();
                            let ifl = sb.in_flight_prepared_recycles.len() as u32;
                            let ptxp = sb.pending_tx_prepared.len() as u32;
                            let ptxl = sb.pending_tx_local.len() as u32;
                            let total = sb.pending_fill_frames.len() as u32
                                + fill_p
                                + rx_a
                                + sb.free_tx_frames.len() as u32
                                + sb.outstanding_tx
                                + ifl
                                + sb.scratch_recycle.len() as u32
                                + ptxp;
                            let raw = diagnose_raw_ring_state(sb.rx.as_raw_fd());
                            let mut stall_line = format!(
                                "DBG STALL_BINDING[{}]: if={} q={} pfill={} fring={} rxring={} free_tx={} otx={} ifl={} ptxp={} ptxl={} total={}/{}",
                                si,
                                sb.ifindex,
                                sb.queue_id,
                                sb.pending_fill_frames.len(),
                                fill_p,
                                rx_a,
                                sb.free_tx_frames.len(),
                                sb.outstanding_tx,
                                ifl,
                                ptxp,
                                ptxl,
                                total,
                                sb.umem.total_frames(),
                            );
                            if let Some((rxp, rxc, frp, frc, txp, txc, crp, crc)) = raw {
                                let _ = write!(
                                    stall_line,
                                    " RAW:rxP={rxp}/rxC={rxc}/frP={frp}/frC={frc}/txP={txp}/txC={txc}/crP={crp}/crC={crc}"
                                );
                            }
                            if let Ok(Some(stats)) = sb.device.statistics_v2().map(Some) {
                                let _ = write!(
                                    stall_line,
                                    " xsk:drop={}/rfull={}/fempty={}/tempty={}",
                                    stats.rx_dropped,
                                    stats.rx_ring_full,
                                    stats.rx_fill_ring_empty_descs,
                                    stats.tx_ring_empty_descs
                                );
                            }
                            eprintln!("{stall_line}");
                        }
                        // Dump all session keys for this worker
                        let mut sess_dump = String::new();
                        let mut count = 0;
                        sessions.iter_with_origin(|key, decision, metadata, origin| {
                            if count < 20 {
                                use std::fmt::Write;
                                let _ = write!(
                                    sess_dump,
                                    "\n  SESS: {}:{} -> {}:{} proto={} nat=({:?},{:?}) is_rev={} origin={}",
                                    key.src_ip,
                                    key.src_port,
                                    key.dst_ip,
                                    key.dst_port,
                                    key.protocol,
                                    decision.nat.rewrite_src,
                                    decision.nat.rewrite_dst,
                                    metadata.is_reverse,
                                    origin.as_str(),
                                );
                                count += 1;
                            }
                        });
                        if !sess_dump.is_empty() {
                            eprintln!("DBG STALL_SESSIONS:{sess_dump}");
                        }
                        // Dump fallback stats at stall time
                        if let Some(stats) = read_fallback_stats() {
                            if !stats.is_empty() {
                                let s: Vec<String> =
                                    stats.iter().map(|(n, v)| format!("{n}={v}")).collect();
                                eprintln!("DBG STALL_FALLBACK: {}", s.join(" "));
                            }
                        }
                        // Also dump BPF session count
                        if let Some(b) = bindings.first() {
                            eprintln!(
                                "DBG STALL_BPF_SESSIONS: entries={}",
                                count_bpf_session_entries(b.session_map_fd)
                            );
                        }
                    } else if prev_fwd_total > 0 {
                        stall_reported = false;
                    }
                    stall_prev_fwd = prev_fwd_total;
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_nat_snat = 0;
                    dbg_nat_dnat = 0;
                    dbg_nat_none = 0;
                    dbg_frame_build_none = 0;
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_rx_tcp_rst = 0;
                    dbg_tx_tcp_rst = 0;
                    dbg_rx_tcp_fin = 0;
                    dbg_rx_tcp_synack = 0;
                    dbg_rx_tcp_zero_window = 0;
                    dbg_fwd_tcp_fin = 0;
                    dbg_fwd_tcp_rst = 0;
                    dbg_fwd_tcp_zero_window = 0;
                }
                for b in bindings.iter_mut() {
                    b.dbg_fill_submitted = 0;
                    b.dbg_fill_failed = 0;
                    b.dbg_poll_cycles = 0;
                    b.dbg_backpressure = 0;
                    b.dbg_rx_empty = 0;
                    b.dbg_rx_wakeups = 0;
                    b.dbg_tx_ring_submitted = 0;
                    b.dbg_tx_ring_full = 0;
                    b.dbg_completions_reaped = 0;
                    b.dbg_sendto_calls = 0;
                    b.dbg_sendto_err = 0;
                    b.dbg_sendto_eagain = 0;
                    b.dbg_sendto_enobufs = 0;
                    b.dbg_pending_overflow = 0;
                    #[cfg(feature = "debug-log")]
                    {
                        b.dbg_tx_tcp_rst = 0;
                    }
                    b.dbg_rx_avail_nonzero = 0;
                    b.dbg_rx_avail_max = 0;
                    b.dbg_rx_wake_sendto_ok = 0;
                    b.dbg_rx_wake_sendto_err = 0;
                    b.dbg_rx_wake_sendto_errno = 0;
                }
            }
        }
        if did_work {
            idle_iters = 0;
            continue;
        }
        idle_iters = idle_iters.saturating_add(1);
        match poll_mode {
            crate::PollMode::BusyPoll => {
                if idle_iters <= IDLE_SPIN_ITERS {
                    std::hint::spin_loop();
                } else {
                    thread::sleep(Duration::from_micros(IDLE_SLEEP_US));
                }
            }
            crate::PollMode::Interrupt => {
                // Interrupt mode still needs a short local spin before blocking.
                // Firewall-local TCP flows are ACK-latency-sensitive; blocking
                // immediately on the first empty poll collapses cwnd badly.
                if idle_iters <= IDLE_SPIN_ITERS {
                    std::hint::spin_loop();
                } else if !interrupt_poll_fds.is_empty() {
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
                    thread::sleep(Duration::from_millis(INTERRUPT_POLL_TIMEOUT_MS as u64));
                }
            }
        }
    }
    crate::filter::flush_recorded_filter_counters();
    for binding in bindings.iter_mut() {
        release_all_cos_root_leases(binding);
        release_all_cos_queue_leases(binding);
    }
    cos_status.store(Arc::new(build_worker_cos_statuses(
        &bindings,
        forwarding.as_ref(),
    )));
    heartbeat.store(monotonic_nanos(), Ordering::Relaxed);
}

fn apply_worker_shaped_tx_requests(
    bindings: &mut [BindingWorker],
    forwarding: &ForwardingState,
    binding_lookup: &WorkerBindingLookup,
    now_ns: u64,
    requests: Vec<TxRequest>,
) {
    for req in requests {
        let binding_index = bindings
            .first()
            .and_then(|binding| binding.cos_fast_interfaces.get(&req.egress_ifindex))
            .and_then(|iface_fast| {
                binding_lookup
                    .first_by_if
                    .get(&iface_fast.tx_ifindex)
                    .copied()
            })
            .or_else(|| {
                let tx_ifindex = resolve_tx_binding_ifindex(forwarding, req.egress_ifindex);
                binding_lookup.first_by_if.get(&tx_ifindex).copied()
            });
        let Some(binding) = binding_index.and_then(|idx| bindings.get_mut(idx)) else {
            if let Some(binding) = bindings.first_mut() {
                binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            }
            if cfg!(feature = "debug-log") {
                debug_log!(
                    "DBG COS_OWNER_MISSING_BINDING: egress_ifindex={}",
                    req.egress_ifindex,
                );
            }
            continue;
        };
        match enqueue_local_into_cos(binding, forwarding, req, now_ns) {
            Ok(()) => {}
            Err(req) => {
                binding.pending_tx_local.push_back(req);
                bound_pending_tx_local(binding);
            }
        }
    }
}

fn build_worker_cos_owner_live_by_tx_ifindex<I>(bindings: I) -> FastMap<i32, Arc<BindingLiveState>>
where
    I: IntoIterator<Item = (i32, Arc<BindingLiveState>)>,
{
    let mut out = FastMap::default();
    for (ifindex, live) in bindings {
        out.entry(ifindex).or_insert(live);
    }
    out
}

// Empirical per-worker sustained exact throughput ceiling in bytes/sec. A
// single owner worker can reliably drive an exact queue up to about this rate
// before the drain loop backs up and throughput collapses (the collapse case
// motivated shared-worker execution in PR #680). Queues below this floor get
// deterministic single-owner arbitration; queues at or above it get sharded
// across eligible workers so one worker is not the bottleneck.
const COS_SHARED_EXACT_MIN_RATE_BYTES: u64 = 2_500_000_000 / 8;

/// Decide whether an exact queue runs under shared-worker execution.
///
/// Policy:
/// - Non-exact queues are never shared (they run through the non-exact
///   guarantee batch path regardless).
/// - Exact queues below `shared_threshold` route to a single owner worker
///   (one FIFO arbitration domain, SFQ inside). See issue #690 for why
///   low-rate exact queues want one arbitration domain rather than N
///   racing worker-local FIFOs.
/// - Exact queues at or above `shared_threshold` run sharded across every
///   eligible worker with shared root/queue leases, avoiding the single-
///   worker throughput collapse from PR #680.
///
/// `shared_threshold = max(iface_rate / 4, COS_SHARED_EXACT_MIN_RATE_BYTES)`.
/// The absolute `MIN` is a per-worker capacity ceiling and is the primary
/// gate. The `iface_rate / 4` term is an iface-rate-relative floor intended
/// to keep very-small queues single-owner on fast interfaces.
///
/// Known rough edge (#690 follow-on): at iface rates well above 10g the
/// `/4` component dominates `MIN` and will classify a genuinely high-rate
/// queue (e.g. 10g exact on a 100g iface) as single-owner, regressing to
/// PR #680's throughput collapse shape. Current lab runs 10g interfaces
/// where `/4 == MIN`, so this is latent; the test
/// `queue_uses_shared_exact_service_high_iface_rate_keeps_large_queues_single_owner`
/// pins the current behavior so a future fix is an explicit policy change
/// rather than a silent drift.
#[inline]
fn queue_uses_shared_exact_service(iface: &CoSInterfaceConfig, queue: &CoSQueueConfig) -> bool {
    if !queue.exact {
        return false;
    }
    let shared_threshold = iface
        .shaping_rate_bytes
        .saturating_div(4)
        .max(COS_SHARED_EXACT_MIN_RATE_BYTES);
    queue.transmit_rate_bytes >= shared_threshold
}

fn build_worker_cos_fast_interfaces(
    forwarding: &ForwardingState,
    current_worker_id: u32,
    tx_owner_live_by_tx_ifindex: &FastMap<i32, Arc<BindingLiveState>>,
    owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
    owner_live_by_queue: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
    shared_root_leases: &BTreeMap<i32, Arc<SharedCoSRootLease>>,
    shared_queue_leases: &BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>,
) -> FastMap<i32, WorkerCoSInterfaceFastPath> {
    let mut out = FastMap::default();
    for (&egress_ifindex, iface) in &forwarding.cos.interfaces {
        let tx_ifindex = resolve_tx_binding_ifindex(forwarding, egress_ifindex);
        let mut queue_index_by_id = [COS_FAST_QUEUE_INDEX_MISS; 256];
        let mut queue_fast_path = Vec::with_capacity(iface.queues.len());
        for (queue_idx, queue) in iface.queues.iter().enumerate() {
            queue_index_by_id[usize::from(queue.queue_id)] = queue_idx as u16;
            let queue_key = (egress_ifindex, queue.queue_id);
            let shared_exact = queue_uses_shared_exact_service(iface, queue);
            queue_fast_path.push(WorkerCoSQueueFastPath {
                shared_exact,
                owner_worker_id: owner_worker_by_queue
                    .get(&queue_key)
                    .copied()
                    .unwrap_or(current_worker_id),
                owner_live: owner_live_by_queue.get(&queue_key).cloned(),
                shared_queue_lease: queue
                    .exact
                    .then(|| shared_queue_leases.get(&queue_key).cloned())
                    .flatten(),
            });
        }
        let default_queue_index = match queue_index_by_id[usize::from(iface.default_queue)] {
            COS_FAST_QUEUE_INDEX_MISS => 0,
            idx => idx as usize,
        };
        out.insert(
            egress_ifindex,
            WorkerCoSInterfaceFastPath {
                tx_ifindex,
                default_queue_index,
                queue_index_by_id,
                tx_owner_live: tx_owner_live_by_tx_ifindex.get(&tx_ifindex).cloned(),
                shared_root_lease: shared_root_leases.get(&egress_ifindex).cloned(),
                queue_fast_path,
            },
        );
    }
    out
}

fn build_worker_cos_statuses(
    bindings: &[BindingWorker],
    forwarding: &ForwardingState,
) -> Vec<crate::protocol::CoSInterfaceStatus> {
    build_worker_cos_statuses_from_maps(
        bindings.iter().map(|binding| &binding.cos_interfaces),
        forwarding,
    )
}

fn cos_runtime_config_changed(current: &ForwardingState, next: &ForwardingState) -> bool {
    current.cos != next.cos
}

fn reset_binding_cos_runtime(binding: &mut BindingWorker) {
    release_all_cos_root_leases(binding);
    release_all_cos_queue_leases(binding);
    let mut dropped_local = 0u64;
    let mut dropped_prepared = Vec::new();
    for root in binding.cos_interfaces.values_mut() {
        for queue in &mut root.queues {
            while let Some(item) = cos_queue_pop_front(queue) {
                match item {
                    CoSPendingTxItem::Local(_) => {
                        dropped_local = dropped_local.saturating_add(1);
                    }
                    CoSPendingTxItem::Prepared(req) => dropped_prepared.push(req),
                }
            }
            queue.queued_bytes = 0;
            queue.runnable = false;
            queue.parked = false;
            queue.next_wakeup_tick = 0;
        }
        root.nonempty_queues = 0;
        root.runnable_queues = 0;
    }
    binding.cos_interfaces.clear();
    binding.cos_interface_order.clear();
    binding.cos_interface_rr = 0;
    binding.cos_nonempty_interfaces = 0;

    let dropped_total = dropped_local.saturating_add(dropped_prepared.len() as u64);
    if dropped_total > 0 {
        binding
            .live
            .tx_errors
            .fetch_add(dropped_total, Ordering::Relaxed);
    }
    for req in dropped_prepared {
        recycle_prepared_immediately(binding, &req);
    }
}

fn reset_worker_cos_runtimes(bindings: &mut [BindingWorker]) {
    for binding in bindings {
        reset_binding_cos_runtime(binding);
    }
}

fn build_worker_cos_statuses_from_maps<'a, I>(
    cos_maps: I,
    forwarding: &ForwardingState,
) -> Vec<crate::protocol::CoSInterfaceStatus>
where
    I: IntoIterator<Item = &'a FastMap<i32, CoSInterfaceRuntime>>,
{
    let mut interfaces = BTreeMap::<i32, crate::protocol::CoSInterfaceStatus>::new();
    let mut queue_maps = BTreeMap::<i32, BTreeMap<u8, crate::protocol::CoSQueueStatus>>::new();
    for cos_map in cos_maps {
        for (&ifindex, root) in cos_map {
            let entry = interfaces.entry(ifindex).or_default();
            entry.ifindex = ifindex;
            if entry.interface_name.is_empty() {
                entry.interface_name = forwarding
                    .ifindex_to_config_name
                    .get(&ifindex)
                    .cloned()
                    .or_else(|| forwarding.ifindex_to_name.get(&ifindex).cloned())
                    .unwrap_or_else(|| format!("ifindex-{ifindex}"));
            }
            entry.shaping_rate_bytes = entry.shaping_rate_bytes.max(root.shaping_rate_bytes);
            entry.burst_bytes = entry.burst_bytes.max(root.burst_bytes);
            entry.worker_instances = entry.worker_instances.saturating_add(1);
            entry.timer_level0_sleepers = entry.timer_level0_sleepers.saturating_add(
                root.timer_wheel
                    .level0
                    .iter()
                    .map(std::vec::Vec::len)
                    .sum::<usize>(),
            );
            entry.timer_level1_sleepers = entry.timer_level1_sleepers.saturating_add(
                root.timer_wheel
                    .level1
                    .iter()
                    .map(std::vec::Vec::len)
                    .sum::<usize>(),
            );
            let interface_config = forwarding.cos.interfaces.get(&ifindex);
            let queue_map = queue_maps.entry(ifindex).or_default();
            for queue in &root.queues {
                let status = queue_map.entry(queue.queue_id).or_default();
                status.queue_id = queue.queue_id;
                if let Some(config) = interface_config.and_then(|cfg| {
                    cfg.queues
                        .iter()
                        .find(|config| config.queue_id == queue.queue_id)
                }) {
                    if status.forwarding_class.is_empty() {
                        status.forwarding_class = config.forwarding_class.clone();
                    }
                }
                if status.worker_instances == 0 {
                    status.priority = queue.priority;
                }
                status.exact = queue.exact;
                status.transmit_rate_bytes =
                    status.transmit_rate_bytes.max(queue.transmit_rate_bytes);
                status.buffer_bytes = status.buffer_bytes.max(queue.buffer_bytes);
                status.worker_instances = status.worker_instances.saturating_add(1);
                status.queued_packets = status
                    .queued_packets
                    .saturating_add(cos_queue_len(queue) as u64);
                status.queued_bytes = status.queued_bytes.saturating_add(queue.queued_bytes);
                if queue.runnable {
                    status.runnable_instances = status.runnable_instances.saturating_add(1);
                }
                if queue.parked {
                    status.parked_instances = status.parked_instances.saturating_add(1);
                }
                if status.next_wakeup_tick == 0
                    || (queue.next_wakeup_tick > 0
                        && queue.next_wakeup_tick < status.next_wakeup_tick)
                {
                    status.next_wakeup_tick = queue.next_wakeup_tick;
                }
                status.surplus_deficit_bytes = status
                    .surplus_deficit_bytes
                    .saturating_add(queue.surplus_deficit);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tx_request(ifindex: i32) -> TxRequest {
        TxRequest {
            bytes: vec![0; 128],
            expected_ports: None,
            expected_addr_family: 0,
            expected_protocol: 0,
            flow_key: None,
            egress_ifindex: ifindex,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        }
    }

    #[test]
    fn build_worker_cos_statuses_aggregates_runtime_by_interface_and_queue() {
        let mut forwarding = ForwardingState::default();
        forwarding
            .ifindex_to_config_name
            .insert(80, "reth0.80".to_string());
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 1_875_000,
                burst_bytes: 64 * 1024,
                default_queue: 0,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "bandwidth-10mb".to_string(),
                    priority: 1,
                    transmit_rate_bytes: 1_250_000,
                    exact: false,
                    surplus_weight: 1,
                    buffer_bytes: 32 * 1024,
                    dscp_rewrite: None,
                }],
            },
        );

        let make_root = |queued_bytes, runnable, parked, wake_tick| CoSInterfaceRuntime {
            shaping_rate_bytes: 1_875_000,
            burst_bytes: 64 * 1024,
            tokens: 0,
            default_queue: 0,
            nonempty_queues: 1,
            runnable_queues: usize::from(runnable),
            guarantee_rr: 0,
            queues: vec![CoSQueueRuntime {
                queue_id: 4,
                priority: 1,
                transmit_rate_bytes: 1_250_000,
                exact: false,
                flow_fair: false,
                surplus_weight: 1,
                surplus_deficit: 512,
                buffer_bytes: 32 * 1024,
                dscp_rewrite: None,
                tokens: 0,
                last_refill_ns: 0,
                queued_bytes,
                active_flow_buckets: 0,
                flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_rr_buckets: VecDeque::new(),
                flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                runnable,
                parked,
                next_wakeup_tick: wake_tick,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::from([CoSPendingTxItem::Local(test_tx_request(80))]),
            }],
            queue_indices_by_priority: std::array::from_fn(|_| Vec::new()),
            rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
            timer_wheel: CoSTimerWheelRuntime {
                current_tick: 0,
                level0: std::array::from_fn(|idx| if idx == 3 { vec![0] } else { Vec::new() }),
                level1: std::array::from_fn(|idx| if idx == 1 { vec![0] } else { Vec::new() }),
            },
        };

        let mut first = FastMap::default();
        first.insert(80, make_root(1024, true, false, 0));
        let mut second = FastMap::default();
        second.insert(80, make_root(2048, false, true, 77));

        let statuses = build_worker_cos_statuses_from_maps([&first, &second], &forwarding);
        assert_eq!(statuses.len(), 1);
        let iface = &statuses[0];
        assert_eq!(iface.interface_name, "reth0.80");
        assert_eq!(iface.worker_instances, 2);
        assert_eq!(iface.timer_level0_sleepers, 2);
        assert_eq!(iface.timer_level1_sleepers, 2);
        assert_eq!(iface.nonempty_queues, 1);
        assert_eq!(iface.runnable_queues, 1);
        assert_eq!(iface.queues.len(), 1);
        let queue = &iface.queues[0];
        assert_eq!(queue.queue_id, 4);
        assert_eq!(queue.forwarding_class, "bandwidth-10mb");
        assert_eq!(queue.queued_packets, 2);
        assert_eq!(queue.queued_bytes, 3072);
        assert_eq!(queue.runnable_instances, 1);
        assert_eq!(queue.parked_instances, 1);
        assert_eq!(queue.next_wakeup_tick, 77);
        assert_eq!(queue.surplus_deficit_bytes, 1024);
    }

    #[test]
    fn build_worker_cos_owner_live_by_tx_ifindex_prefers_first_binding_per_tx_ifindex() {
        let live_a = Arc::new(BindingLiveState::new());
        let live_b = Arc::new(BindingLiveState::new());
        let live_c = Arc::new(BindingLiveState::new());
        let owners = build_worker_cos_owner_live_by_tx_ifindex([
            (12, live_a.clone()),
            (12, live_b.clone()),
            (13, live_c.clone()),
        ]);

        assert!(Arc::ptr_eq(owners.get(&12).unwrap(), &live_a));
        assert!(Arc::ptr_eq(owners.get(&13).unwrap(), &live_c));
    }

    #[test]
    fn build_worker_cos_fast_interfaces_flattens_owner_and_lease_state() {
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 25_000_000_000 / 8,
                burst_bytes: 256 * 1024,
                default_queue: 5,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![
                    CoSQueueConfig {
                        queue_id: 4,
                        forwarding_class: "best-effort".into(),
                        priority: 5,
                        transmit_rate_bytes: 1_000_000_000 / 8,
                        exact: false,
                        surplus_weight: 1,
                        buffer_bytes: 64 * 1024,
                        dscp_rewrite: None,
                    },
                    CoSQueueConfig {
                        queue_id: 5,
                        forwarding_class: "iperf-b".into(),
                        priority: 5,
                        transmit_rate_bytes: 10_000_000_000 / 8,
                        exact: true,
                        surplus_weight: 1,
                        buffer_bytes: 128 * 1024,
                        dscp_rewrite: None,
                    },
                ],
            },
        );
        forwarding.egress.insert(
            80,
            EgressInterface {
                bind_ifindex: 12,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0; 6],
                zone: "wan".into(),
                redundancy_group: 0,
                primary_v4: None,
                primary_v6: None,
            },
        );

        let tx_owner_live = Arc::new(BindingLiveState::new());
        let queue_owner_live = Arc::new(BindingLiveState::new());
        let root_lease = Arc::new(SharedCoSRootLease::new(25_000_000_000 / 8, 256 * 1024, 4));
        let queue_lease = Arc::new(SharedCoSQueueLease::new(10_000_000_000 / 8, 128 * 1024, 4));

        let tx_owner_live_by_tx_ifindex = FastMap::from_iter([(12, tx_owner_live.clone())]);
        let owner_worker_by_queue = BTreeMap::from([((80, 5), 7)]);
        let owner_live_by_queue = BTreeMap::from([((80, 5), queue_owner_live.clone())]);
        let shared_root_leases = BTreeMap::from([(80, root_lease.clone())]);
        let shared_queue_leases = BTreeMap::from([((80, 5), queue_lease.clone())]);

        let fast = build_worker_cos_fast_interfaces(
            &forwarding,
            3,
            &tx_owner_live_by_tx_ifindex,
            &owner_worker_by_queue,
            &owner_live_by_queue,
            &shared_root_leases,
            &shared_queue_leases,
        );

        let iface = fast.get(&80).expect("fast cos interface");
        assert_eq!(iface.tx_ifindex, 12);
        assert_eq!(iface.default_queue_index, 1);
        assert!(Arc::ptr_eq(
            iface.tx_owner_live.as_ref().expect("tx owner live"),
            &tx_owner_live
        ));
        assert!(Arc::ptr_eq(
            iface.shared_root_lease.as_ref().expect("shared root lease"),
            &root_lease
        ));

        let queue4 = iface.queue_fast_path(Some(4)).expect("queue 4");
        assert!(!queue4.shared_exact);
        assert_eq!(queue4.owner_worker_id, 3);
        assert!(queue4.owner_live.is_none());
        assert!(queue4.shared_queue_lease.is_none());

        let queue5 = iface.queue_fast_path(Some(5)).expect("queue 5");
        assert!(queue5.shared_exact);
        assert_eq!(queue5.owner_worker_id, 7);
        assert!(Arc::ptr_eq(
            queue5.owner_live.as_ref().expect("queue owner live"),
            &queue_owner_live
        ));
        assert!(Arc::ptr_eq(
            queue5
                .shared_queue_lease
                .as_ref()
                .expect("shared queue lease"),
            &queue_lease
        ));
        assert!(std::ptr::eq(
            iface.queue_fast_path(None).expect("default queue"),
            queue5
        ));
    }

    #[test]
    fn build_worker_cos_fast_interfaces_keeps_low_rate_exact_queue_owner_local() {
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 25_000_000_000 / 8,
                burst_bytes: 256 * 1024,
                default_queue: 4,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![
                    CoSQueueConfig {
                        queue_id: 4,
                        forwarding_class: "iperf-a".into(),
                        priority: 5,
                        transmit_rate_bytes: 1_000_000_000 / 8,
                        exact: true,
                        surplus_weight: 1,
                        buffer_bytes: 128 * 1024,
                        dscp_rewrite: None,
                    },
                    CoSQueueConfig {
                        queue_id: 5,
                        forwarding_class: "iperf-b".into(),
                        priority: 5,
                        transmit_rate_bytes: 10_000_000_000 / 8,
                        exact: true,
                        surplus_weight: 1,
                        buffer_bytes: 128 * 1024,
                        dscp_rewrite: None,
                    },
                ],
            },
        );
        forwarding.egress.insert(
            80,
            EgressInterface {
                bind_ifindex: 12,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0; 6],
                zone: "wan".into(),
                redundancy_group: 0,
                primary_v4: None,
                primary_v6: None,
            },
        );

        let queue4_owner_live = Arc::new(BindingLiveState::new());
        let queue5_owner_live = Arc::new(BindingLiveState::new());
        let tx_owner_live_by_tx_ifindex = FastMap::from_iter([(12, queue4_owner_live.clone())]);
        let owner_worker_by_queue = BTreeMap::from([((80, 4), 4), ((80, 5), 7)]);
        let owner_live_by_queue = BTreeMap::from([
            ((80, 4), queue4_owner_live.clone()),
            ((80, 5), queue5_owner_live.clone()),
        ]);
        let shared_root_leases = BTreeMap::from([(
            80,
            Arc::new(SharedCoSRootLease::new(25_000_000_000 / 8, 256 * 1024, 4)),
        )]);
        let shared_queue_leases = BTreeMap::from([
            (
                (80, 4),
                Arc::new(SharedCoSQueueLease::new(1_000_000_000 / 8, 128 * 1024, 4)),
            ),
            (
                (80, 5),
                Arc::new(SharedCoSQueueLease::new(10_000_000_000 / 8, 128 * 1024, 4)),
            ),
        ]);

        let fast = build_worker_cos_fast_interfaces(
            &forwarding,
            3,
            &tx_owner_live_by_tx_ifindex,
            &owner_worker_by_queue,
            &owner_live_by_queue,
            &shared_root_leases,
            &shared_queue_leases,
        );

        let iface = fast.get(&80).expect("fast cos interface");
        let queue4 = iface.queue_fast_path(Some(4)).expect("queue 4");
        assert!(!queue4.shared_exact);
        assert_eq!(queue4.owner_worker_id, 4);
        assert!(queue4.shared_queue_lease.is_some());

        let queue5 = iface.queue_fast_path(Some(5)).expect("queue 5");
        assert!(queue5.shared_exact);
        assert_eq!(queue5.owner_worker_id, 7);
        assert!(queue5.shared_queue_lease.is_some());
    }

    fn test_cos_iface_with_rate(shaping_bits: u64) -> CoSInterfaceConfig {
        CoSInterfaceConfig {
            shaping_rate_bytes: shaping_bits / 8,
            burst_bytes: 64 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: Vec::new(),
        }
    }

    fn test_exact_queue_at_rate(queue_id: u8, rate_bits: u64) -> CoSQueueConfig {
        CoSQueueConfig {
            queue_id,
            forwarding_class: format!("q{queue_id}"),
            priority: 5,
            transmit_rate_bytes: rate_bits / 8,
            exact: true,
            surplus_weight: 1,
            buffer_bytes: 64 * 1024,
            dscp_rewrite: None,
        }
    }

    #[test]
    fn queue_uses_shared_exact_service_rejects_non_exact_queue() {
        let iface = test_cos_iface_with_rate(10_000_000_000);
        let mut q = test_exact_queue_at_rate(4, 10_000_000_000);
        q.exact = false;
        assert!(!queue_uses_shared_exact_service(&iface, &q));
    }

    #[test]
    fn queue_uses_shared_exact_service_10g_iface_pins_5201_config_policy() {
        // Mirrors the live loss HA CoS config:
        //   reth0.80 shaper 10g
        //   best-effort 100m exact  -> single owner
        //   iperf-a     1.0g exact  -> single owner  (this is 5201)
        //   iperf-b     10.0g exact -> shared
        // Threshold on a 10g iface = max(10g/4, 2.5g) = 2.5g.
        let iface = test_cos_iface_with_rate(10_000_000_000);
        let be = test_exact_queue_at_rate(0, 100_000_000);
        let iperf_a = test_exact_queue_at_rate(4, 1_000_000_000);
        let iperf_b = test_exact_queue_at_rate(5, 10_000_000_000);
        assert!(!queue_uses_shared_exact_service(&iface, &be));
        assert!(!queue_uses_shared_exact_service(&iface, &iperf_a));
        assert!(queue_uses_shared_exact_service(&iface, &iperf_b));
    }

    #[test]
    fn queue_uses_shared_exact_service_10g_iface_threshold_is_exactly_inclusive() {
        // Threshold = 2.5 Gbps = 312_500_000 bytes/s. Exactly at threshold
        // selects the shared path; one byte below stays single-owner. The
        // boundary must be deterministic — a fairness fix that accidentally
        // flips classification for a queue at the stated threshold will
        // silently regress 5201 or 5202.
        let iface = test_cos_iface_with_rate(10_000_000_000);
        let mut q = test_exact_queue_at_rate(4, 0);
        q.transmit_rate_bytes = COS_SHARED_EXACT_MIN_RATE_BYTES - 1;
        assert!(!queue_uses_shared_exact_service(&iface, &q));
        q.transmit_rate_bytes = COS_SHARED_EXACT_MIN_RATE_BYTES;
        assert!(queue_uses_shared_exact_service(&iface, &q));
    }

    #[test]
    fn queue_uses_shared_exact_service_slow_iface_absolute_floor_applies() {
        // 1g iface -> /4 = 250m; MIN = 2.5g dominates. Every exact queue
        // on a 1g iface is at or below 1g, which is below the 2.5g floor,
        // so all of them run single-owner. This documents the slow-iface
        // case where the absolute MIN term is what matters.
        let iface = test_cos_iface_with_rate(1_000_000_000);
        let q_100m = test_exact_queue_at_rate(0, 100_000_000);
        let q_1g = test_exact_queue_at_rate(4, 1_000_000_000);
        assert!(!queue_uses_shared_exact_service(&iface, &q_100m));
        assert!(!queue_uses_shared_exact_service(&iface, &q_1g));
    }

    #[test]
    fn queue_uses_shared_exact_service_high_iface_rate_keeps_large_queues_single_owner() {
        // KNOWN ROUGH EDGE (#690 follow-on). On a 100g iface the /4 term
        // dominates: threshold = max(25g, 2.5g) = 25g. A 10g or 20g exact
        // queue is classified as single-owner, even though a single worker
        // cannot sustain 10g exact throughput (the collapse case from
        // PR #680). The policy scales UP with iface rate, which is the
        // wrong direction relative to per-worker capacity.
        //
        // This test asserts the CURRENT behavior on purpose so a future
        // policy fix is an explicit decision rather than a silent flip.
        // Do not change these assertions without a corresponding live
        // validation on a >10g iface that the change does not regress
        // 5202-class throughput.
        let iface = test_cos_iface_with_rate(100_000_000_000);
        let q_10g = test_exact_queue_at_rate(5, 10_000_000_000);
        let q_20g = test_exact_queue_at_rate(6, 20_000_000_000);
        let q_25g = test_exact_queue_at_rate(7, 25_000_000_000);
        assert!(!queue_uses_shared_exact_service(&iface, &q_10g));
        assert!(!queue_uses_shared_exact_service(&iface, &q_20g));
        assert!(queue_uses_shared_exact_service(&iface, &q_25g));
    }

    #[test]
    fn queue_uses_shared_exact_service_zero_iface_rate_falls_back_to_absolute_floor() {
        // Bootstrap / pathological case: iface shaper is 0 (unconfigured).
        // saturating_div(4) == 0, MIN dominates, behavior is the absolute
        // 2.5g floor. Verifies there is no divide-by-zero or underflow path
        // and that a brand-new iface at startup does not accidentally mark
        // every exact queue as shared.
        let iface = test_cos_iface_with_rate(0);
        let q_2g = test_exact_queue_at_rate(4, 2_000_000_000);
        let q_3g = test_exact_queue_at_rate(5, 3_000_000_000);
        assert!(!queue_uses_shared_exact_service(&iface, &q_2g));
        assert!(queue_uses_shared_exact_service(&iface, &q_3g));
    }

    #[test]
    fn cos_runtime_config_changed_detects_queue_rate_change() {
        let iface = CoSInterfaceConfig {
            shaping_rate_bytes: 1_250_000_000,
            burst_bytes: 1_000_000,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: [("iperf-b".to_string(), 5)].into_iter().collect(),
            queues: vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 1_250_000_000,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 1_000_000,
                dscp_rewrite: None,
            }],
        };
        let mut current = ForwardingState::default();
        current.cos.interfaces.insert(12, iface.clone());

        let mut next = current.clone();
        next.cos
            .interfaces
            .get_mut(&12)
            .expect("cos interface")
            .queues[0]
            .transmit_rate_bytes = 1_875_000_000;

        assert!(cos_runtime_config_changed(&current, &next));
        assert!(!cos_runtime_config_changed(&current, &current));
    }
}

pub(crate) fn push_recent_exception(
    recent_exceptions: &mut VecDeque<ExceptionStatus>,
    exception: ExceptionStatus,
) {
    if recent_exceptions.len() >= MAX_RECENT_EXCEPTIONS {
        recent_exceptions.pop_front();
    }
    recent_exceptions.push_back(exception);
}

pub(crate) fn push_recent_session_delta(
    recent_session_deltas: &mut VecDeque<SessionDeltaInfo>,
    delta: SessionDeltaInfo,
) {
    if recent_session_deltas.len() >= MAX_RECENT_SESSION_DELTAS {
        recent_session_deltas.pop_front();
    }
    recent_session_deltas.push_back(delta);
}

pub(crate) struct BindingLiveSnapshot {
    pub(crate) bound: bool,
    pub(crate) xsk_registered: bool,
    pub(crate) xsk_bind_mode: String,
    pub(crate) zero_copy: bool,
    pub(crate) socket_fd: c_int,
    pub(crate) socket_ifindex: i32,
    pub(crate) socket_queue_id: u32,
    pub(crate) socket_bind_flags: u32,
    pub(crate) rx_packets: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) rx_batches: u64,
    pub(crate) rx_wakeups: u64,
    pub(crate) metadata_packets: u64,
    pub(crate) metadata_errors: u64,
    pub(crate) validated_packets: u64,
    pub(crate) validated_bytes: u64,
    pub(crate) local_delivery_packets: u64,
    pub(crate) forward_candidate_packets: u64,
    pub(crate) route_miss_packets: u64,
    pub(crate) neighbor_miss_packets: u64,
    pub(crate) discard_route_packets: u64,
    pub(crate) next_table_packets: u64,
    pub(crate) exception_packets: u64,
    pub(crate) config_gen_mismatches: u64,
    pub(crate) fib_gen_mismatches: u64,
    pub(crate) unsupported_packets: u64,
    pub(crate) flow_cache_hits: u64,
    pub(crate) flow_cache_misses: u64,
    pub(crate) flow_cache_evictions: u64,
    pub(crate) session_hits: u64,
    pub(crate) session_misses: u64,
    pub(crate) session_creates: u64,
    pub(crate) session_expires: u64,
    pub(crate) session_delta_pending: u64,
    pub(crate) session_delta_generated: u64,
    pub(crate) session_delta_dropped: u64,
    pub(crate) session_delta_drained: u64,
    pub(crate) policy_denied_packets: u64,
    pub(crate) screen_drops: u64,
    pub(crate) snat_packets: u64,
    pub(crate) dnat_packets: u64,
    pub(crate) slow_path_packets: u64,
    pub(crate) slow_path_bytes: u64,
    pub(crate) slow_path_local_delivery_packets: u64,
    pub(crate) slow_path_missing_neighbor_packets: u64,
    pub(crate) slow_path_no_route_packets: u64,
    pub(crate) slow_path_next_table_packets: u64,
    pub(crate) slow_path_forward_build_packets: u64,
    pub(crate) slow_path_drops: u64,
    pub(crate) slow_path_rate_limited: u64,
    pub(crate) kernel_rx_dropped: u64,
    pub(crate) kernel_rx_invalid_descs: u64,
    pub(crate) tx_packets: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) tx_completions: u64,
    pub(crate) tx_errors: u64,
    pub(crate) direct_tx_packets: u64,
    pub(crate) copy_tx_packets: u64,
    pub(crate) in_place_tx_packets: u64,
    pub(crate) direct_tx_no_frame_fallback_packets: u64,
    pub(crate) direct_tx_build_fallback_packets: u64,
    pub(crate) direct_tx_disallowed_fallback_packets: u64,
    pub(crate) debug_pending_fill_frames: u32,
    #[allow(dead_code)]
    pub(crate) debug_spare_fill_frames: u32,
    pub(crate) debug_free_tx_frames: u32,
    pub(crate) debug_pending_tx_prepared: u32,
    pub(crate) debug_pending_tx_local: u32,
    pub(crate) debug_outstanding_tx: u32,
    pub(crate) debug_in_flight_recycles: u32,
    pub(crate) last_heartbeat: Option<chrono::DateTime<Utc>>,
    pub(crate) last_error: String,
}
