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
    /// #812: per-UMEM-frame submit timestamp sidecar. Indexed by
    /// `offset >> UMEM_FRAME_SHIFT`. Pre-allocated once at binding
    /// construction (length = total UMEM frames) so the hot-path
    /// stamp write is a single store — NO allocation, NO grow.
    ///
    /// Single-writer invariant (plan §3.3): submit and completion for
    /// one frame offset are the same thread (the owner worker that
    /// owns this binding's `free_tx_frames` via
    /// `pop_front`/`push_front`), so plain `Vec<u64>` is correct —
    /// no atomic needed. `WorkerUmem` is `Rc` (not `Arc`) at
    /// `umem.rs:16-18`, enforcing single-owner semantics even when
    /// multiple bindings share a UMEM under the mlx5 special case.
    ///
    /// Unstamped slots hold `TX_SIDECAR_UNSTAMPED` (`u64::MAX`) — the
    /// reap path (`reap_tx_completions`) skips the histogram
    /// increment for these to avoid biasing the tail toward bucket 0
    /// (plan §5.4). A `monotonic_nanos() == 0` return (VDSO failure,
    /// plan §3.4a / §6.1 test #5) causes `stamp_submits` to early-
    /// return without writing the slot (Codex round-1 MED + Rust
    /// round-1 MED-2) — the slot's pre-existing UNSTAMPED state
    /// (from the previous reap or from worker construction) is what
    /// the reap checks.
    /// Rust round-1 MED-1: `Box<[u64]>` rather than `Vec<u64>` to
    /// convey single-size intent at the type level. The sidecar is
    /// pre-allocated to `total_frames` at binding construction and
    /// NEVER grown. A future refactor that naively added `push` to
    /// `Vec<u64>` would silently allocate on the hot path; `Box<[u64]>`
    /// has no `push` method, so the mistake fails to compile.
    pub(crate) tx_submit_ns: Box<[u64]>,
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
    // #802/#804: per-binding bound-pending FIFO overflow — incremented at
    // the `bound_pending_tx_local`/`bound_pending_tx_prepared` evict
    // sites only. Pre-#804 this counter was named `dbg_pending_overflow`
    // and also doubled as the CoS admission overflow accumulator; the
    // two semantics are now tracked on separate fields so operators can
    // tell which path is dropping.
    pub(crate) dbg_bound_pending_overflow: u64,
    // #804: per-binding class-of-service queue admission overflow —
    // incremented in `enqueue_cos_item()` when the CoS admission gate
    // rejects the item.
    pub(crate) dbg_cos_queue_overflow: u64,
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
        // #878: publish per-binding capacities so the snapshot path can
        // expose them via the wire BindingStatus. These are write-once
        // (set here at worker construction) and read-many.
        live.umem_total_frames
            .store(total_frames, std::sync::atomic::Ordering::Relaxed);
        live.tx_ring_capacity
            .store(ring_entries, std::sync::atomic::Ordering::Relaxed);
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
            // #812: pre-allocate the submit-timestamp sidecar once,
            // sized to the binding's total UMEM frame count so every
            // legal `offset >> UMEM_FRAME_SHIFT` index lands inside
            // the vec. Initial contents are the unstamped sentinel so
            // any stray pre-existing offset in flight (cross-restart
            // completion) is skipped by the reap path (plan §5.4).
            // Allocation happens here — NEVER on the hot path.
            // Rust round-1 MED-1: Box<[u64]> — allocate-once, never
            // grow. `vec![...].into_boxed_slice()` produces an
            // exactly-sized heap allocation with no spare capacity.
            tx_submit_ns: vec![TX_SIDECAR_UNSTAMPED; total_frames as usize].into_boxed_slice(),
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
            dbg_bound_pending_overflow: 0,
            dbg_cos_queue_overflow: 0,
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
    shared_cos_queue_vtime_floors: Arc<
        ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>,
    >,
    cos_status: Arc<ArcSwap<Vec<crate::protocol::CoSInterfaceStatus>>>,
    // #869: worker-runtime telemetry publish slot.  Worker writes its
    // local counters here on a ~1s cadence; coordinator reads for status.
    runtime_atomics: Arc<super::worker_runtime::WorkerRuntimeAtomics>,
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
    let mut cos_shared_queue_vtime_floors = shared_cos_queue_vtime_floors.load_full();
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
        cos_shared_queue_vtime_floors.as_ref(),
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
    // #869: worker-runtime telemetry.  Local counters, published to
    // `runtime_atomics` on the ~1s cadence below.
    use super::worker_runtime::{
        WorkerRuntimeCounters, WorkerRuntimeState, current_tid, sample_thread_cpu_ns,
    };
    let mut wr_counters = WorkerRuntimeCounters::default();
    let mut wr_state = WorkerRuntimeState::IdleBlock;
    let mut wr_last_loop_ns = monotonic_nanos();
    let mut wr_last_publish_ns = wr_last_loop_ns;
    const WR_PUBLISH_INTERVAL_NS: u64 = 1_000_000_000;
    runtime_atomics.set_tid(current_tid());
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
                runtime_atomics.publish(&wr_counters);
                wr_last_publish_ns = loop_now_ns;
            }
        }
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
        let live_cos_shared_queue_vtime_floors = shared_cos_queue_vtime_floors.load_full();
        if !Arc::ptr_eq(
            &cos_shared_queue_vtime_floors,
            &live_cos_shared_queue_vtime_floors,
        ) {
            // #917: Arc-replacement of the V_min floors map.
            // Each shared_exact queue's per-worker slots default
            // to NOT_PARTICIPATING in the new Arc. Workers will
            // re-publish their committed vtime on the next
            // commit-boundary publish; until then peers reading
            // this slot see "not participating" and skip it in
            // V_min reduction (per plan §3.4 / §3.7 lifecycle
            // rules).
            cos_shared_queue_vtime_floors = live_cos_shared_queue_vtime_floors;
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
                cos_shared_queue_vtime_floors.as_ref(),
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
                        " TX:ring_sub={}/ring_full={}/compl={}/sendto={}/err={}/eagain={}/enobufs={}/bp_overflow={}/cos_overflow={}",
                        b.dbg_tx_ring_submitted,
                        b.dbg_tx_ring_full,
                        b.dbg_completions_reaped,
                        b.dbg_sendto_calls,
                        b.dbg_sendto_err,
                        b.dbg_sendto_eagain,
                        b.dbg_sendto_enobufs,
                        b.dbg_bound_pending_overflow,
                        b.dbg_cos_queue_overflow,
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
                    // #802: publish ring-pressure counters into BindingLiveState
                    // BEFORE resetting the worker-local window. The worker-local
                    // counters (b.dbg_tx_ring_full, etc.) are accumulated by the
                    // hot path and reset each ~1s debug tick; without this
                    // publish they'd never be visible outside the worker thread.
                    // fetch_add is used because the atomic holds the cumulative
                    // total while the local counter holds only the current
                    // window. Relaxed is sufficient — diagnostic counters, no
                    // synchronization contract.
                    if b.dbg_tx_ring_full != 0 {
                        b.live
                            .dbg_tx_ring_full
                            .fetch_add(b.dbg_tx_ring_full, Ordering::Relaxed);
                    }
                    if b.dbg_sendto_enobufs != 0 {
                        b.live
                            .dbg_sendto_enobufs
                            .fetch_add(b.dbg_sendto_enobufs, Ordering::Relaxed);
                    }
                    if b.dbg_bound_pending_overflow != 0 {
                        b.live
                            .dbg_bound_pending_overflow
                            .fetch_add(b.dbg_bound_pending_overflow, Ordering::Relaxed);
                    }
                    if b.dbg_cos_queue_overflow != 0 {
                        b.live
                            .dbg_cos_queue_overflow
                            .fetch_add(b.dbg_cos_queue_overflow, Ordering::Relaxed);
                    }
                    // #802: kernel xdp_statistics.rx_fill_ring_empty_descs is
                    // already absolute (kernel-cumulative), so publish with
                    // store() not fetch_add. Sampling failures are silently
                    // ignored — the atomic simply retains its last good value.
                    if let Ok(stats) = b.device.statistics_v2() {
                        b.live
                            .rx_fill_ring_empty_descs
                            .store(stats.rx_fill_ring_empty_descs, Ordering::Relaxed);
                    }
                    // #802: outstanding_tx is a transient gauge on BindingWorker
                    // (current in-flight TX). Publish to the existing atomic
                    // mirror on BindingLiveState so the snapshot reader sees
                    // a recent value. store() because it's a gauge, not a
                    // counter.
                    b.live
                        .debug_outstanding_tx
                        .store(b.outstanding_tx, Ordering::Relaxed);
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
                    let free_tx = b.free_tx_frames.len() as u32;
                    let pending_fill = b.pending_fill_frames.len() as u32;
                    let kernel_fill = b.device.pending();
                    let inflight = total
                        .saturating_sub(free_tx)
                        .saturating_sub(pending_fill)
                        .saturating_sub(kernel_fill);
                    b.live
                        .umem_inflight_frames
                        .store(inflight, Ordering::Relaxed);

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
                    b.dbg_bound_pending_overflow = 0;
                    b.dbg_cos_queue_overflow = 0;
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
                // #710: dedicated counter — a cross-worker shaped TX
                // request arrived for an egress this worker has no
                // binding to drain. Subset of tx_errors.
                binding
                    .live
                    .no_owner_binding_drops
                    .fetch_add(1, Ordering::Relaxed);
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
// that motivated shared-worker execution in PR #680). This is the sole
// shared-exact threshold: a queue at or above this rate shards across every
// eligible worker; a queue below it runs under a single owner.
//
// Evidence basis (#698):
// - Drain-path userspace micro-bench `cos_exact_drain_throughput_micro_bench`
//   (in `afxdp::tx::tests`, run with
//   `cargo test --release -- --ignored --nocapture`; debug-build numbers are
//   not meaningful for this baseline) measures the inner
//   `drain_exact_local_fifo_items_to_scratch` +
//   `settle_exact_local_fifo_submission` loop in isolation with setup work
//   excluded from the timed region. Baseline on the development host is
//   comfortably above MIN (order of a few Mpps / tens of Gbps at 1500 B);
//   drain alone is not the limiter there.
// - This bench only rules out the inner drain loop as the immediate
//   limiter on the development host. It does NOT by itself validate MIN
//   on other deployment hardware, and it does not fully attribute the
//   remaining ceiling to non-drain work without a live single-worker
//   measurement.
// - The 2.5 Gbps figure is best read as a per-worker *aggregate* budget
//   threshold consistent with the PR #680 collapse shape: there the drain
//   loop failed to absorb 10g line-rate despite drain alone being able
//   to go much faster, because non-drain per-packet work (RX, forwarding,
//   NAT, session-lookup, conntrack) consumed the per-packet cycle budget
//   that drain+completion needed to keep up.
// - The ceiling is a property of the full per-worker pipeline, not of
//   the interface shaper — it does not scale with iface rate.
pub(super) const COS_SHARED_EXACT_MIN_RATE_BYTES: u64 = 2_500_000_000 / 8;

/// Decide whether an exact queue runs under shared-worker execution.
///
/// Policy:
/// - Non-exact queues are never shared (they run through the non-exact
///   guarantee batch path regardless).
/// - Exact queues below `COS_SHARED_EXACT_MIN_RATE_BYTES` route to a single
///   owner worker (one FIFO arbitration domain, SFQ inside). See issue
///   #690 for why low-rate exact queues want one arbitration domain rather
///   than N racing worker-local FIFOs.
/// - Exact queues at or above the threshold run sharded across every
///   eligible worker with shared root/queue leases, avoiding the single-
///   worker throughput collapse from PR #680.
///
/// Before PR #697 the threshold was `max(iface_rate / 4, MIN)`. That scaled
/// the threshold up with iface rate, which is the wrong direction: the
/// single-worker drain ceiling is an absolute property of the loop, not a
/// fraction of the iface. Once `iface_rate / 4` exceeded `MIN`, the policy
/// would classify a genuinely high-rate queue (e.g. a 10g exact queue on a
/// 100g iface) as single-owner — routing it straight back into the PR #680
/// collapse shape. The `/ 4` term is now gone; the threshold is just the
/// absolute per-worker ceiling.
///
/// The old and new policies classify queues identically whenever
/// `iface_rate / 4 <= COS_SHARED_EXACT_MIN_RATE_BYTES` (both evaluate to
/// `MIN`). Behavior diverges only in the `iface_rate / 4 > MIN` regime,
/// which is the regime that previously mis-classified mid/high-rate exact
/// queues as single-owner.
#[inline]
fn queue_uses_shared_exact_service(_iface: &CoSInterfaceConfig, queue: &CoSQueueConfig) -> bool {
    if !queue.exact {
        return false;
    }
    queue.transmit_rate_bytes >= COS_SHARED_EXACT_MIN_RATE_BYTES
}

fn build_worker_cos_fast_interfaces(
    forwarding: &ForwardingState,
    current_worker_id: u32,
    tx_owner_live_by_tx_ifindex: &FastMap<i32, Arc<BindingLiveState>>,
    owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
    owner_live_by_queue: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
    shared_root_leases: &BTreeMap<i32, Arc<SharedCoSRootLease>>,
    shared_queue_leases: &BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>,
    shared_queue_vtime_floors: &BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>,
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
                // #917 Phase 2b: V_min coordination Arc, allocated
                // once per shared_exact CoS queue by the coordinator
                // (per `build_shared_cos_queue_vtime_floors_reusing_existing`
                // in coordinator.rs). Cloned to every worker servicing
                // this queue. Single-owner / non-shared queues get
                // None — V_min sync only applies to shared_exact.
                vtime_floor: shared_queue_vtime_floors.get(&queue_key).cloned(),
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
    // #709: pair each cos_map with its owner-binding's live state so the
    // per-queue telemetry fields (drain_latency_hist, owner_pps, ...)
    // can be populated from the binding that actually did the work.
    build_worker_cos_statuses_from_maps(
        bindings
            .iter()
            .map(|binding| (&binding.cos_interfaces, Some(binding.live.as_ref()))),
        forwarding,
    )
}

/// Return the single `(ifindex, queue_id)` that can truthfully inherit
/// a binding-scoped owner-profile snapshot, scanning **all** interfaces
/// on the binding's `cos_map`.
///
/// The snapshot source is `BindingLiveState`, which is binding-local,
/// not queue-local. A binding can drain multiple interfaces (via
/// `drain_shaped_tx` round-robining `binding.cos_interface_order`), so
/// attribution has to be unambiguous at the BINDING level, not the
/// interface level: if two interfaces on the same binding each have
/// one owner-local exact queue, the binding-wide snapshot still has
/// no single queue to land on, and the whole export must stay zero.
///
/// We return `Some((ifindex, queue_id))` only when exactly one queue
/// across the whole binding is owner-local exact. Shared-exact,
/// non-exact, and any multi-owner-local shape — whether within one
/// interface or spread across interfaces — keep the binding silent.
fn unique_owner_profile_row(
    cos_map: &FastMap<i32, CoSInterfaceRuntime>,
    forwarding: &ForwardingState,
) -> Option<(i32, u8)> {
    let mut eligible = None;
    for (&ifindex, root) in cos_map {
        let iface = match forwarding.cos.interfaces.get(&ifindex) {
            Some(iface) => iface,
            None => {
                // Missing config for a runtime is ambiguous — we can't
                // confirm the queue is exact from the config side, so
                // if the runtime claims any exact queues we silence
                // the whole binding.
                if root.queues.iter().any(|q| q.exact) {
                    return None;
                }
                continue;
            }
        };
        for queue in &root.queues {
            if !queue.exact {
                continue;
            }
            let Some(config) = iface
                .queues
                .iter()
                .find(|cfg| cfg.queue_id == queue.queue_id)
            else {
                return None;
            };
            if !config.exact {
                return None;
            }
            if queue_uses_shared_exact_service(iface, config) {
                continue;
            }
            if eligible.replace((ifindex, queue.queue_id)).is_some() {
                return None;
            }
        }
    }
    eligible
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
            // #785 Phase 3 — Codex round-3 NEW-2 / Rust reviewer
            // LOW: teardown drains the whole queue without a
            // matching push_front rollback, so no snapshots are
            // ever consumed. Use the no-snapshot pop variant so
            // we don't grow pop_snapshot_stack past its documented
            // TX_BATCH_SIZE bound (the queue may hold more items
            // than that). The runtime is replaced below anyway.
            while let Some(item) = cos_queue_pop_front_no_snapshot(queue) {
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
    // FIXME(#941 work item D): vacate any V_min slots owned by
    // this worker before clearing cos_interfaces. The
    // coordinator's `build_shared_cos_queue_vtime_floors_reusing_existing`
    // (coordinator.rs ~2061) reuses an existing floor Arc when
    // the (ifindex, queue_id, worker_count) tuple matches across
    // rebuilds. After this clear, the next runtime starts with
    // queue_vtime=0 but the floor's slot for this worker still
    // holds the OLD high vtime. Peers reading the slot will use
    // the stale value in their V_min calculation until the first
    // post-reset post-settle publish (potentially > 100 ms on
    // sparse traffic). Without vacate, peers may erroneously
    // throttle for one or more drain batches at reset-epoch.
    // See `docs/issue-refinements/941-body.md` Work item D and
    // `docs/pr/940-942-vmin-correctness/plan.md` "Known gap".
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

/// #709: snapshot the owner-profile counter set from a `BindingLiveState`
/// into a struct-local copy. Histograms are fixed-cap arrays on both
/// sides; copying into an owned value lets the caller attribute the
/// same snapshot to multiple queues without re-reading the atomics
/// (which would tear across queues in the same scrape).
pub(super) struct OwnerProfileSnapshot {
    pub(super) drain_latency_hist: [u64; DRAIN_HIST_BUCKETS],
    pub(super) drain_invocations: u64,
    pub(super) drain_noop_invocations: u64,
    pub(super) redirect_acquire_hist: [u64; DRAIN_HIST_BUCKETS],
    pub(super) owner_pps: u64,
    pub(super) peer_pps: u64,
    /// #760 instrumentation, binding-scoped. Bytes delivered via
    /// the post-CoS backup transmit paths in `drain_pending_tx`
    /// — these never passed a queue's token gate. Surfaced on
    /// the same "unambiguous owner-local exact queue" row the
    /// other binding-scoped fields use.
    pub(super) post_drain_backup_bytes: u64,
    /// #760 instrumentation, binding-scoped. Bytes observed at the
    /// three `apply_*` tx_bytes sites, incremented unconditionally.
    /// Compare against the sum of per-queue `drain_sent_bytes`; any
    /// gap is shaped traffic that bypassed the per-queue write via
    /// an `apply_*` early-return.
    pub(super) drain_sent_bytes_shaped_unconditional: u64,
}

#[inline]
pub(super) fn owner_profile_snapshot(live: &BindingLiveState) -> OwnerProfileSnapshot {
    // #746: atomics now live on cacheline-isolated `owner_profile_owner`
    // / `owner_profile_peer` nested structs. This snapshot reads from
    // both but the shape it produces is byte-identical to pre-refactor.
    OwnerProfileSnapshot {
        drain_latency_hist: std::array::from_fn(|i| {
            live.owner_profile_owner.drain_latency_hist[i].load(Ordering::Relaxed)
        }),
        drain_invocations: live
            .owner_profile_owner
            .drain_invocations
            .load(Ordering::Relaxed),
        drain_noop_invocations: live
            .owner_profile_owner
            .drain_noop_invocations
            .load(Ordering::Relaxed),
        redirect_acquire_hist: std::array::from_fn(|i| {
            live.owner_profile_peer.redirect_acquire_hist[i].load(Ordering::Relaxed)
        }),
        owner_pps: live.owner_profile_owner.owner_pps.load(Ordering::Relaxed),
        peer_pps: live.owner_profile_peer.peer_pps.load(Ordering::Relaxed),
        post_drain_backup_bytes: live
            .owner_profile_owner
            .post_drain_backup_bytes
            .load(Ordering::Relaxed),
        drain_sent_bytes_shaped_unconditional: live
            .owner_profile_owner
            .drain_sent_bytes_shaped_unconditional
            .load(Ordering::Relaxed),
    }
}

/// #709: sum-merge the owner-profile fields of one `CoSQueueStatus`
/// into another. Used by `coordinator::aggregate_cos_statuses_across_workers`
/// to fold per-worker snapshots into the operator-facing view while
/// preserving the histogram invariant that
/// `sum(drain_latency_hist) == drain_invocations`.
///
/// `max` across workers is wrong for histograms and counters: it can
/// synthesize a profile no worker actually observed (bucket 0 from one
/// worker, bucket 7 from another) while leaving `drain_invocations` at
/// only the larger side's count. Summation preserves a coherent queue-
/// level view for both owner-local and shared-exact service.
/// Signature mirrors `merge_owner_profile_sum` so both layers share the
/// same contract.
pub(crate) fn merge_cos_queue_owner_profile_sum(
    dst: &mut crate::protocol::CoSQueueStatus,
    src: &crate::protocol::CoSQueueStatus,
) {
    if dst.drain_latency_hist.len() < DRAIN_HIST_BUCKETS {
        dst.drain_latency_hist.resize(DRAIN_HIST_BUCKETS, 0);
    }
    if dst.redirect_acquire_hist.len() < DRAIN_HIST_BUCKETS {
        dst.redirect_acquire_hist.resize(DRAIN_HIST_BUCKETS, 0);
    }
    for i in 0..DRAIN_HIST_BUCKETS {
        let src_drain = src.drain_latency_hist.get(i).copied().unwrap_or(0);
        dst.drain_latency_hist[i] = dst.drain_latency_hist[i].saturating_add(src_drain);
        let src_redirect = src.redirect_acquire_hist.get(i).copied().unwrap_or(0);
        dst.redirect_acquire_hist[i] = dst.redirect_acquire_hist[i].saturating_add(src_redirect);
    }
    dst.drain_invocations = dst.drain_invocations.saturating_add(src.drain_invocations);
    dst.drain_noop_invocations = dst
        .drain_noop_invocations
        .saturating_add(src.drain_noop_invocations);
    dst.owner_pps = dst.owner_pps.saturating_add(src.owner_pps);
    dst.peer_pps = dst.peer_pps.saturating_add(src.peer_pps);
    // #760 sum-merge the new per-queue + binding-scoped counters
    // across workers. Same saturating-add discipline as the rest of
    // this function — a single queue can be owned by at most one
    // worker per scrape, so cross-worker aggregation is almost
    // always sum-of-single-non-zero, but saturating_add keeps us
    // safe if the ownership ever shifts mid-scrape.
    dst.drain_sent_bytes = dst.drain_sent_bytes.saturating_add(src.drain_sent_bytes);
    dst.drain_park_root_tokens = dst
        .drain_park_root_tokens
        .saturating_add(src.drain_park_root_tokens);
    dst.drain_park_queue_tokens = dst
        .drain_park_queue_tokens
        .saturating_add(src.drain_park_queue_tokens);
    dst.post_drain_backup_bytes = dst
        .post_drain_backup_bytes
        .saturating_add(src.post_drain_backup_bytes);
    dst.drain_sent_bytes_shaped_unconditional = dst
        .drain_sent_bytes_shaped_unconditional
        .saturating_add(src.drain_sent_bytes_shaped_unconditional);
}

/// #709: sum-merge a binding's owner-profile snapshot into a per-queue
/// `CoSQueueStatus`.
///
/// For owner-local exact queues, only one binding contributes non-zero
/// values so sum and max are equivalent. For shared-exact queues or any
/// future topology where multiple bindings contribute to the same queue,
/// summation preserves a coherent aggregate distribution and keeps
/// `sum(histogram) == invocations` intact. A per-bucket `max` breaks
/// that invariant and can manufacture an impossible mixed profile.
///
/// Post-#751: this still merges the full owner profile into the
/// destination status. It's retained for call sites that snapshot a
/// binding wholesale (tests, the coordinator fold-across-workers path).
/// Production `build_worker_cos_statuses_from_maps` no longer uses this
/// for drain_latency_hist / drain_invocations — those are now populated
/// per-queue from the per-queue atomics — but it still applies to the
/// binding-scoped fields (owner_pps, peer_pps, redirect_acquire_hist,
/// drain_noop_invocations) via `merge_binding_scoped_owner_profile`.
pub(super) fn merge_owner_profile_sum(
    status: &mut crate::protocol::CoSQueueStatus,
    profile: &OwnerProfileSnapshot,
) {
    // Lazily size the histogram vectors on first touch; every queue
    // serialised with #709 fields populated has exactly
    // DRAIN_HIST_BUCKETS entries. A queue that was never merged stays
    // `Vec::new()` and serialises as an empty array — readers gate
    // on `owner_pps || drain_invocations` being > 0 before
    // interpreting the histogram.
    if status.drain_latency_hist.len() < DRAIN_HIST_BUCKETS {
        status.drain_latency_hist.resize(DRAIN_HIST_BUCKETS, 0);
    }
    for i in 0..DRAIN_HIST_BUCKETS {
        status.drain_latency_hist[i] =
            status.drain_latency_hist[i].saturating_add(profile.drain_latency_hist[i]);
    }
    status.drain_invocations = status
        .drain_invocations
        .saturating_add(profile.drain_invocations);
    merge_binding_scoped_owner_profile(status, profile);
}

/// #751: merge only the binding-scoped fields from a binding's
/// owner-profile snapshot into a per-queue status. The fields
/// covered — `redirect_acquire_hist`, `owner_pps`, `peer_pps`,
/// `drain_noop_invocations` — are inherently per-binding: producers
/// do not know the target queue at redirect time (so
/// `redirect_acquire_hist` and `peer_pps` cannot be queue-scoped),
/// `owner_pps` measures binding-wide TX arrivals, and
/// `drain_noop_invocations` counts drain calls that made no
/// progress on *any* queue (so no queue to attribute them to).
///
/// The per-queue drain fields (`drain_latency_hist`,
/// `drain_invocations`) are populated separately from the queue's
/// own atomics — see `build_worker_cos_statuses_from_maps`.
pub(super) fn merge_binding_scoped_owner_profile(
    status: &mut crate::protocol::CoSQueueStatus,
    profile: &OwnerProfileSnapshot,
) {
    if status.redirect_acquire_hist.len() < DRAIN_HIST_BUCKETS {
        status.redirect_acquire_hist.resize(DRAIN_HIST_BUCKETS, 0);
    }
    for i in 0..DRAIN_HIST_BUCKETS {
        status.redirect_acquire_hist[i] =
            status.redirect_acquire_hist[i].saturating_add(profile.redirect_acquire_hist[i]);
    }
    status.drain_noop_invocations = status
        .drain_noop_invocations
        .saturating_add(profile.drain_noop_invocations);
    status.owner_pps = status.owner_pps.saturating_add(profile.owner_pps);
    status.peer_pps = status.peer_pps.saturating_add(profile.peer_pps);
    // #760 smoking gun. Surfaced once per binding on the same
    // unambiguous owner-local exact queue row the other
    // binding-scoped fields ride on, so we don't multiply-count
    // the same binding-wide atomic across several queues of a
    // shared-exact shape.
    status.post_drain_backup_bytes = status
        .post_drain_backup_bytes
        .saturating_add(profile.post_drain_backup_bytes);
    status.drain_sent_bytes_shaped_unconditional = status
        .drain_sent_bytes_shaped_unconditional
        .saturating_add(profile.drain_sent_bytes_shaped_unconditional);
}

fn build_worker_cos_statuses_from_maps<'a, I>(
    cos_maps: I,
    forwarding: &ForwardingState,
) -> Vec<crate::protocol::CoSInterfaceStatus>
where
    I: IntoIterator<
        Item = (
            &'a FastMap<i32, CoSInterfaceRuntime>,
            Option<&'a BindingLiveState>,
        ),
    >,
{
    let mut interfaces = BTreeMap::<i32, crate::protocol::CoSInterfaceStatus>::new();
    let mut queue_maps = BTreeMap::<i32, BTreeMap<u8, crate::protocol::CoSQueueStatus>>::new();
    for (cos_map, binding_live) in cos_maps {
        // #709: snapshot the binding's owner-profile counters ONCE per
        // binding per scrape. The source is binding-scoped, so we only
        // surface it on an unambiguous queue row: exactly one owner-local
        // exact queue ACROSS THE WHOLE BINDING (all interfaces it drains).
        // Shared-exact, non-exact, and multi-owner-local exact shapes —
        // whether within one interface or spread across interfaces —
        // stay zero here until the telemetry becomes queue-scoped.
        let binding_profile = binding_live.map(owner_profile_snapshot);
        let owner_profile_row = unique_owner_profile_row(cos_map, forwarding);
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
                let queue_config = interface_config.and_then(|cfg| {
                    cfg.queues
                        .iter()
                        .find(|config| config.queue_id == queue.queue_id)
                });
                if let Some(config) = queue_config {
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
                // #784: use MAX across worker instances (not sum) —
                // the peak is per-worker observed; aggregating by
                // max gives the worst-case collision visibility
                // without inflating the number by double-counting.
                let peak = u64::from(queue.active_flow_buckets_peak);
                if peak > status.active_flow_buckets_peak {
                    status.active_flow_buckets_peak = peak;
                }
                // #784: surface flow_fair so we can detect queues
                // that were expected to run SFQ but aren't.
                if queue.flow_fair {
                    status.flow_fair = true;
                }
                // #710: aggregate drop-reason counters across worker
                // instances for this queue. Each worker's per-queue
                // runtime is single-writer (only the owner worker
                // increments the counter for its own queue), so
                // summing across workers gives the cluster-wide totals.
                status.admission_flow_share_drops = status
                    .admission_flow_share_drops
                    .saturating_add(queue.drop_counters.admission_flow_share_drops);
                status.admission_buffer_drops = status
                    .admission_buffer_drops
                    .saturating_add(queue.drop_counters.admission_buffer_drops);
                // #718: aggregate ECN CE-mark counter across workers.
                // Same single-writer invariant as the other admission
                // counters — owner worker only.
                status.admission_ecn_marked = status
                    .admission_ecn_marked
                    .saturating_add(queue.drop_counters.admission_ecn_marked);
                status.root_token_starvation_parks = status
                    .root_token_starvation_parks
                    .saturating_add(queue.drop_counters.root_token_starvation_parks);
                status.queue_token_starvation_parks = status
                    .queue_token_starvation_parks
                    .saturating_add(queue.drop_counters.queue_token_starvation_parks);
                status.tx_ring_full_submit_stalls = status
                    .tx_ring_full_submit_stalls
                    .saturating_add(queue.drop_counters.tx_ring_full_submit_stalls);
                // #751: the owner-side drain telemetry
                // (drain_latency_hist + drain_invocations) now lives
                // per-queue on CoSQueueRuntime.owner_profile — each
                // exact queue gets its OWN histogram populated
                // directly from its own atomics, with no eligibility
                // gate. Pre-#751 these came from a binding-wide
                // rollup that was only surfaced on the single
                // "unambiguous owner-local exact queue" row; as a
                // result #732 showed every queue row of a
                // multi-queue binding with identical values.
                //
                // HFT notes on the atomic loads below:
                //   * Single-writer (owner worker thread) + cross-
                //     thread read (snapshot path). Relaxed is the
                //     correct ordering: the reader tolerates ~1
                //     count of tearing between the hist buckets
                //     and drain_invocations, and Prometheus scrape
                //     semantics are "best effort at scrape time".
                //   * The owner_profile atomics sit alongside the
                //     plain u64 fields in CoSQueueRuntime that the
                //     same owner also mutates each tick, so there is
                //     no false-sharing cost internal to the worker.
                //     The snapshot reader pulls the cache line
                //     once per scrape — negligible.
                //   * Load invocations first so an untouched queue
                //     (zero counter) skips the histogram walk and
                //     keeps the on-wire status vector empty — saves
                //     the resize + 16 bucket copies plus the 128
                //     bytes of serde overhead on queues that never
                //     drained. The writer always bumps both hist and
                //     invocations under Relaxed, so
                //     invocations==0 ⇒ all buckets are zero; the
                //     reverse may briefly be false due to tearing,
                //     but a ~1-count under-report from a single
                //     reader is within the tolerance documented on
                //     CoSQueueOwnerProfile.
                let queue_invocations =
                    queue.owner_profile.drain_invocations.load(Ordering::Relaxed);
                if queue_invocations > 0 {
                    if status.drain_latency_hist.len() < DRAIN_HIST_BUCKETS {
                        status.drain_latency_hist.resize(DRAIN_HIST_BUCKETS, 0);
                    }
                    for i in 0..DRAIN_HIST_BUCKETS {
                        let bucket_count =
                            queue.owner_profile.drain_latency_hist[i].load(Ordering::Relaxed);
                        status.drain_latency_hist[i] =
                            status.drain_latency_hist[i].saturating_add(bucket_count);
                    }
                    status.drain_invocations =
                        status.drain_invocations.saturating_add(queue_invocations);
                }
                // #760 overshoot-hunt instrumentation. Same Relaxed
                // load pattern as drain_invocations — single writer
                // (owner worker, at the queue-token decrement sites
                // in tx.rs) + single reader (this snapshot path).
                // drain_sent_bytes is the authoritative per-queue
                // "bytes the scheduler actually shaped out"; pair it
                // with `queue.transmit_rate_bytes` over a scrape
                // window to detect a direct cap bypass on this row.
                // drain_park_root_tokens / drain_park_queue_tokens
                // both rising with drain_sent_bytes sustaining above
                // configured rate would mean the gate fires but the
                // refill/accounting is wrong; both near zero with
                // drain_sent_bytes above rate means the gate never
                // ran for this queue.
                status.drain_sent_bytes = status.drain_sent_bytes.saturating_add(
                    queue.owner_profile.drain_sent_bytes.load(Ordering::Relaxed),
                );
                status.drain_park_root_tokens = status.drain_park_root_tokens.saturating_add(
                    queue
                        .owner_profile
                        .drain_park_root_tokens
                        .load(Ordering::Relaxed),
                );
                status.drain_park_queue_tokens = status.drain_park_queue_tokens.saturating_add(
                    queue
                        .owner_profile
                        .drain_park_queue_tokens
                        .load(Ordering::Relaxed),
                );

                // #709 / #748 / #751: the *binding-scoped* fields
                // (redirect_acquire_hist, owner_pps, peer_pps,
                // drain_noop_invocations) are surfaced only on the
                // single unambiguous owner-local exact queue row on
                // the whole binding. Producers don't know the target
                // queue at redirect time so these fields cannot be
                // queue-scoped and still stay truthful; any
                // shared-exact, non-exact, or multi-owner-local
                // shape keeps them at zero rather than surfacing a
                // binding-wide mixed profile under an arbitrary row.
                if owner_profile_row == Some((ifindex, queue.queue_id)) {
                    if let Some(profile) = binding_profile.as_ref() {
                        merge_binding_scoped_owner_profile(status, profile);
                    }
                }
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

    // Rates used to force owner-local vs shared-exact classification in
    // the owner-profile export tests. Defined relative to the boundary
    // constant so the tests remain valid if `COS_SHARED_EXACT_MIN_RATE_BYTES`
    // moves, and so `CoSQueueConfig.transmit_rate_bytes` stays identical
    // to `CoSQueueRuntime.transmit_rate_bytes` by construction (no
    // config/runtime drift, per #753 Copilot review finding).
    const OWNER_LOCAL_EXACT_RATE: u64 = COS_SHARED_EXACT_MIN_RATE_BYTES - 1;
    const SHARED_EXACT_RATE: u64 = COS_SHARED_EXACT_MIN_RATE_BYTES;

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

        let make_root =
            |queued_bytes, runnable, parked, wake_tick, drop_counters| CoSInterfaceRuntime {
                shaping_rate_bytes: 1_875_000,
                burst_bytes: 64 * 1024,
                tokens: 0,
                default_queue: 0,
                nonempty_queues: 1,
                runnable_queues: usize::from(runnable),
                exact_guarantee_rr: 0,
                nonexact_guarantee_rr: 0,
                #[cfg(test)]
                legacy_guarantee_rr: 0,
                queues: vec![CoSQueueRuntime {
                    queue_id: 4,
                    priority: 1,
                    transmit_rate_bytes: 1_250_000,
                    exact: false,
                    flow_fair: false,
                    shared_exact: false,
                    flow_hash_seed: 0,
                    surplus_weight: 1,
                    surplus_deficit: 512,
                    buffer_bytes: 32 * 1024,
                    dscp_rewrite: None,
                    tokens: 0,
                    last_refill_ns: 0,
                    queued_bytes,
                    active_flow_buckets: 0,
                    active_flow_buckets_peak: 0,
                    flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    queue_vtime: 0,
                    pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                    flow_rr_buckets: FlowRrRing::default(),
                    flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                    runnable,
                    parked,
                    next_wakeup_tick: wake_tick,
                    wheel_level: 0,
                    wheel_slot: 0,
                    items: VecDeque::from([CoSPendingTxItem::Local(test_tx_request(80))]),
                    local_item_count: 1,

                    vtime_floor: None,

                    worker_id: 0,
                    drop_counters,
                    owner_profile: CoSQueueOwnerProfile::new(),
                }],
                queue_indices_by_priority: std::array::from_fn(|_| Vec::new()),
                rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
                timer_wheel: CoSTimerWheelRuntime {
                    current_tick: 0,
                    level0: std::array::from_fn(|idx| if idx == 3 { vec![0] } else { Vec::new() }),
                    level1: std::array::from_fn(|idx| if idx == 1 { vec![0] } else { Vec::new() }),
                },
            };

        // #710 regression pin: worker-level aggregation must sum every
        // drop-reason counter across runtime instances. Use distinct
        // non-zero values per runtime and assert the sum, not a bool,
        // so a silent re-attribution between counters is caught.
        let counters_a = CoSQueueDropCounters {
            admission_flow_share_drops: 3,
            admission_buffer_drops: 1,
            admission_ecn_marked: 37,
            root_token_starvation_parks: 5,
            queue_token_starvation_parks: 7,
            tx_ring_full_submit_stalls: 11,
        };
        let counters_b = CoSQueueDropCounters {
            admission_flow_share_drops: 13,
            admission_buffer_drops: 17,
            admission_ecn_marked: 41,
            root_token_starvation_parks: 19,
            queue_token_starvation_parks: 23,
            tx_ring_full_submit_stalls: 29,
        };

        let mut first = FastMap::default();
        first.insert(80, make_root(1024, true, false, 0, counters_a));
        let mut second = FastMap::default();
        second.insert(80, make_root(2048, false, true, 77, counters_b));

        let statuses =
            build_worker_cos_statuses_from_maps([(&first, None), (&second, None)], &forwarding);
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
        // Drop-reason aggregation across workers — this is the layer
        // that the live bug in #710 review occurred in.
        assert_eq!(queue.admission_flow_share_drops, 3 + 13);
        assert_eq!(queue.admission_buffer_drops, 1 + 17);
        assert_eq!(queue.admission_ecn_marked, 37 + 41);
        assert_eq!(queue.root_token_starvation_parks, 5 + 19);
        assert_eq!(queue.queue_token_starvation_parks, 7 + 23);
        assert_eq!(queue.tx_ring_full_submit_stalls, 11 + 29);
    }

    #[test]
    fn build_worker_cos_statuses_sums_owner_profile_without_breaking_hist_invariant() {
        let mut forwarding = ForwardingState::default();
        forwarding
            .ifindex_to_config_name
            .insert(80, "reth0.80".to_string());
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 1_250_000_000,
                burst_bytes: 256 * 1024,
                default_queue: 0,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".to_string(),
                    priority: 1,
                    transmit_rate_bytes: 1_250_000,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: 32 * 1024,
                    dscp_rewrite: None,
                }],
            },
        );

        let make_root = || CoSInterfaceRuntime {
            shaping_rate_bytes: 1_250_000_000,
            burst_bytes: 256 * 1024,
            tokens: 0,
            default_queue: 0,
            nonempty_queues: 1,
            runnable_queues: 1,
            exact_guarantee_rr: 0,
            nonexact_guarantee_rr: 0,
            #[cfg(test)]
            legacy_guarantee_rr: 0,
            queues: vec![CoSQueueRuntime {
                queue_id: 4,
                priority: 1,
                transmit_rate_bytes: 1_250_000,
                exact: true,
                flow_fair: false,
                shared_exact: false,
                flow_hash_seed: 0,
                surplus_weight: 1,
                surplus_deficit: 0,
                buffer_bytes: 32 * 1024,
                dscp_rewrite: None,
                tokens: 0,
                last_refill_ns: 0,
                queued_bytes: 0,
                active_flow_buckets: 0,
                active_flow_buckets_peak: 0,
                flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                queue_vtime: 0,
                pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                flow_rr_buckets: FlowRrRing::default(),
                flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                runnable: true,
                parked: false,
                next_wakeup_tick: 0,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::new(),
                local_item_count: 0,

                vtime_floor: None,

                worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                owner_profile: CoSQueueOwnerProfile::new(),
            }],
            queue_indices_by_priority: std::array::from_fn(|_| Vec::new()),
            rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
            timer_wheel: CoSTimerWheelRuntime {
                current_tick: 0,
                level0: std::array::from_fn(|_| Vec::new()),
                level1: std::array::from_fn(|_| Vec::new()),
            },
        };

        let live_a = BindingLiveState::new();
        // binding-scoped fields (unchanged by #751): redirect_acquire
        // histogram, owner_pps, peer_pps, drain_noop_invocations.
        live_a.owner_profile_peer.redirect_acquire_hist[1].store(3, Ordering::Relaxed);
        live_a
            .owner_profile_owner
            .drain_noop_invocations
            .store(1, Ordering::Relaxed);
        live_a
            .owner_profile_owner
            .owner_pps
            .store(100, Ordering::Relaxed);
        live_a
            .owner_profile_peer
            .peer_pps
            .store(40, Ordering::Relaxed);

        let live_b = BindingLiveState::new();
        live_b.owner_profile_peer.redirect_acquire_hist[2].store(13, Ordering::Relaxed);
        live_b
            .owner_profile_owner
            .drain_noop_invocations
            .store(2, Ordering::Relaxed);
        live_b
            .owner_profile_owner
            .owner_pps
            .store(200, Ordering::Relaxed);
        live_b
            .owner_profile_peer
            .peer_pps
            .store(50, Ordering::Relaxed);

        let mut first = FastMap::default();
        first.insert(80, make_root());
        // #751: seed per-queue drain stats directly on the first
        // worker's queue runtime. This is what the TX drain loop
        // writes in production (tx.rs line ~250); tests pin the
        // aggregated value rather than the old binding-wide rollup.
        first
            .get_mut(&80)
            .unwrap()
            .queues[0]
            .owner_profile
            .drain_latency_hist[0]
            .store(5, Ordering::Relaxed);
        first
            .get_mut(&80)
            .unwrap()
            .queues[0]
            .owner_profile
            .drain_invocations
            .store(5, Ordering::Relaxed);

        let mut second = FastMap::default();
        second.insert(80, make_root());
        second
            .get_mut(&80)
            .unwrap()
            .queues[0]
            .owner_profile
            .drain_latency_hist[7]
            .store(11, Ordering::Relaxed);
        second
            .get_mut(&80)
            .unwrap()
            .queues[0]
            .owner_profile
            .drain_invocations
            .store(11, Ordering::Relaxed);

        let statuses = build_worker_cos_statuses_from_maps(
            [(&first, Some(&live_a)), (&second, Some(&live_b))],
            &forwarding,
        );
        let queue = &statuses[0].queues[0];

        // #751: drain_latency_hist + drain_invocations come from
        // per-queue atomics, summed across workers servicing the
        // same (ifindex, queue_id).
        assert_eq!(queue.drain_latency_hist[0], 5);
        assert_eq!(queue.drain_latency_hist[7], 11);
        assert_eq!(queue.drain_invocations, 16);
        assert_eq!(
            queue.drain_latency_hist.iter().copied().sum::<u64>(),
            queue.drain_invocations,
            "per-queue histogram must stay coherent with invocation count",
        );

        // Binding-scoped fields still attributed to the eligible
        // queue (there's only one in this fixture) and summed
        // across workers.
        assert_eq!(queue.redirect_acquire_hist[1], 3);
        assert_eq!(queue.redirect_acquire_hist[2], 13);
        assert_eq!(queue.drain_noop_invocations, 3);
        assert_eq!(queue.owner_pps, 300);
        assert_eq!(queue.peer_pps, 90);
    }

    #[test]
    fn build_worker_cos_statuses_owner_profile_only_surfaces_on_unambiguous_owner_local_exact_queue(
    ) {
        let mut forwarding = ForwardingState::default();
        forwarding
            .ifindex_to_config_name
            .insert(80, "reth0.80".to_string());
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 10_000_000_000 / 8,
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
                        forwarding_class: "best-effort".to_string(),
                        priority: 1,
                        transmit_rate_bytes: 100_000_000 / 8,
                        exact: false,
                        surplus_weight: 1,
                        buffer_bytes: 32 * 1024,
                        dscp_rewrite: None,
                    },
                    CoSQueueConfig {
                        queue_id: 4,
                        forwarding_class: "iperf-a".to_string(),
                        priority: 1,
                        transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
                        exact: true,
                        surplus_weight: 1,
                        buffer_bytes: 64 * 1024,
                        dscp_rewrite: None,
                    },
                    CoSQueueConfig {
                        queue_id: 5,
                        forwarding_class: "iperf-b".to_string(),
                        priority: 1,
                        transmit_rate_bytes: SHARED_EXACT_RATE,
                        exact: true,
                        surplus_weight: 1,
                        buffer_bytes: 128 * 1024,
                        dscp_rewrite: None,
                    },
                ],
            },
        );

        let root = CoSInterfaceRuntime {
            shaping_rate_bytes: 10_000_000_000 / 8,
            burst_bytes: 256 * 1024,
            tokens: 0,
            default_queue: 0,
            nonempty_queues: 0,
            runnable_queues: 0,
            exact_guarantee_rr: 0,
            nonexact_guarantee_rr: 0,
            #[cfg(test)]
            legacy_guarantee_rr: 0,
            queues: vec![
                CoSQueueRuntime {
                    queue_id: 0,
                    priority: 1,
                    transmit_rate_bytes: 100_000_000 / 8,
                    exact: false,
                    flow_fair: false,
                    shared_exact: false,
                    flow_hash_seed: 0,
                    surplus_weight: 1,
                    surplus_deficit: 0,
                    buffer_bytes: 32 * 1024,
                    dscp_rewrite: None,
                    tokens: 0,
                    last_refill_ns: 0,
                    queued_bytes: 0,
                    active_flow_buckets: 0,
                    active_flow_buckets_peak: 0,
                    flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    queue_vtime: 0,
                    pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                    flow_rr_buckets: FlowRrRing::default(),
                    flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                    runnable: false,
                    parked: false,
                    next_wakeup_tick: 0,
                    wheel_level: 0,
                    wheel_slot: 0,
                    items: VecDeque::new(),
                    local_item_count: 0,

                    vtime_floor: None,

                    worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                    owner_profile: CoSQueueOwnerProfile::new(),
                },
                CoSQueueRuntime {
                    queue_id: 4,
                    priority: 1,
                    transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
                    exact: true,
                    flow_fair: false,
                    shared_exact: false,
                    flow_hash_seed: 0,
                    surplus_weight: 1,
                    surplus_deficit: 0,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                    tokens: 0,
                    last_refill_ns: 0,
                    queued_bytes: 0,
                    active_flow_buckets: 0,
                    active_flow_buckets_peak: 0,
                    flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    queue_vtime: 0,
                    pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                    flow_rr_buckets: FlowRrRing::default(),
                    flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                    runnable: false,
                    parked: false,
                    next_wakeup_tick: 0,
                    wheel_level: 0,
                    wheel_slot: 0,
                    items: VecDeque::new(),
                    local_item_count: 0,

                    vtime_floor: None,

                    worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                    owner_profile: CoSQueueOwnerProfile::new(),
                },
                CoSQueueRuntime {
                    queue_id: 5,
                    priority: 1,
                    transmit_rate_bytes: SHARED_EXACT_RATE,
                    exact: true,
                    flow_fair: false,
                    shared_exact: false,
                    flow_hash_seed: 0,
                    surplus_weight: 1,
                    surplus_deficit: 0,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                    tokens: 0,
                    last_refill_ns: 0,
                    queued_bytes: 0,
                    active_flow_buckets: 0,
                    active_flow_buckets_peak: 0,
                    flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    queue_vtime: 0,
                    pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                    flow_rr_buckets: FlowRrRing::default(),
                    flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                    runnable: false,
                    parked: false,
                    next_wakeup_tick: 0,
                    wheel_level: 0,
                    wheel_slot: 0,
                    items: VecDeque::new(),
                    local_item_count: 0,

                    vtime_floor: None,

                    worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                    owner_profile: CoSQueueOwnerProfile::new(),
                },
            ],
            queue_indices_by_priority: std::array::from_fn(|_| Vec::new()),
            rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
            timer_wheel: CoSTimerWheelRuntime {
                current_tick: 0,
                level0: std::array::from_fn(|_| Vec::new()),
                level1: std::array::from_fn(|_| Vec::new()),
            },
        };

        let live = BindingLiveState::new();
        // Binding-scoped fields (unchanged by #751).
        live.owner_profile_owner
            .drain_noop_invocations
            .store(1, Ordering::Relaxed);
        live.owner_profile_peer.redirect_acquire_hist[4].store(7, Ordering::Relaxed);
        live.owner_profile_owner
            .owner_pps
            .store(123, Ordering::Relaxed);
        live.owner_profile_peer
            .peer_pps
            .store(45, Ordering::Relaxed);

        let mut cos_map = FastMap::default();
        cos_map.insert(80, root);
        // #751: seed per-queue drain stats on queue_id=4 only
        // (the owner-local exact queue in this fixture).
        {
            let runtime = cos_map.get_mut(&80).unwrap();
            let q4 = runtime
                .queues
                .iter_mut()
                .find(|q| q.queue_id == 4)
                .unwrap();
            q4.owner_profile.drain_latency_hist[2].store(9, Ordering::Relaxed);
            q4.owner_profile
                .drain_invocations
                .store(9, Ordering::Relaxed);
        }

        let statuses = build_worker_cos_statuses_from_maps([(&cos_map, Some(&live))], &forwarding);
        let queues = &statuses[0].queues;
        let q0 = queues.iter().find(|q| q.queue_id == 0).unwrap();
        let q4 = queues.iter().find(|q| q.queue_id == 4).unwrap();
        let q5 = queues.iter().find(|q| q.queue_id == 5).unwrap();

        // q0 is non-exact: no per-queue drain stats seeded and not
        // the eligible row for binding-scoped fields.
        assert_eq!(q0.drain_invocations, 0);
        assert_eq!(q0.owner_pps, 0);

        // q4 is the owner-local exact queue: it gets BOTH its own
        // per-queue drain stats (seeded on the runtime) AND the
        // binding-scoped fields (redirect_acquire, owner_pps,
        // peer_pps, drain_noop) because it's the unambiguous row.
        assert_eq!(q4.drain_latency_hist[2], 9);
        assert_eq!(q4.drain_invocations, 9);
        assert_eq!(q4.redirect_acquire_hist[4], 7);
        assert_eq!(q4.owner_pps, 123);
        assert_eq!(q4.peer_pps, 45);
        assert_eq!(q4.drain_noop_invocations, 1);

        // q5 is shared-exact (via SHARED_EXACT_RATE fixture): no
        // per-queue drain stats seeded, and it's not the eligible
        // row for binding-scoped fields.
        assert_eq!(q5.drain_invocations, 0);
        assert_eq!(q5.owner_pps, 0);
    }

    #[test]
    fn build_worker_cos_statuses_owner_profile_stays_zero_for_ambiguous_multi_exact_binding() {
        let mut forwarding = ForwardingState::default();
        forwarding
            .ifindex_to_config_name
            .insert(80, "reth0.80".to_string());
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 10_000_000_000 / 8,
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
                        forwarding_class: "iperf-a".to_string(),
                        priority: 1,
                        transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
                        exact: true,
                        surplus_weight: 1,
                        buffer_bytes: 64 * 1024,
                        dscp_rewrite: None,
                    },
                    CoSQueueConfig {
                        queue_id: 6,
                        forwarding_class: "iperf-c".to_string(),
                        priority: 1,
                        // Also owner-local-exact — any rate < boundary works;
                        // differ from queue 4 only for readability.
                        transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE / 2,
                        exact: true,
                        surplus_weight: 1,
                        buffer_bytes: 64 * 1024,
                        dscp_rewrite: None,
                    },
                ],
            },
        );

        let root = CoSInterfaceRuntime {
            shaping_rate_bytes: 10_000_000_000 / 8,
            burst_bytes: 256 * 1024,
            tokens: 0,
            default_queue: 4,
            nonempty_queues: 0,
            runnable_queues: 0,
            exact_guarantee_rr: 0,
            nonexact_guarantee_rr: 0,
            #[cfg(test)]
            legacy_guarantee_rr: 0,
            queues: vec![
                CoSQueueRuntime {
                    queue_id: 4,
                    priority: 1,
                    transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
                    exact: true,
                    flow_fair: false,
                    shared_exact: false,
                    flow_hash_seed: 0,
                    surplus_weight: 1,
                    surplus_deficit: 0,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                    tokens: 0,
                    last_refill_ns: 0,
                    queued_bytes: 0,
                    active_flow_buckets: 0,
                    active_flow_buckets_peak: 0,
                    flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    queue_vtime: 0,
                    pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                    flow_rr_buckets: FlowRrRing::default(),
                    flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                    runnable: false,
                    parked: false,
                    next_wakeup_tick: 0,
                    wheel_level: 0,
                    wheel_slot: 0,
                    items: VecDeque::new(),
                    local_item_count: 0,

                    vtime_floor: None,

                    worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                    owner_profile: CoSQueueOwnerProfile::new(),
                },
                CoSQueueRuntime {
                    queue_id: 6,
                    priority: 1,
                    transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE / 2,
                    exact: true,
                    flow_fair: false,
                    shared_exact: false,
                    flow_hash_seed: 0,
                    surplus_weight: 1,
                    surplus_deficit: 0,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                    tokens: 0,
                    last_refill_ns: 0,
                    queued_bytes: 0,
                    active_flow_buckets: 0,
                    active_flow_buckets_peak: 0,
                    flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    queue_vtime: 0,
                    pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                    flow_rr_buckets: FlowRrRing::default(),
                    flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                    runnable: false,
                    parked: false,
                    next_wakeup_tick: 0,
                    wheel_level: 0,
                    wheel_slot: 0,
                    items: VecDeque::new(),
                    local_item_count: 0,

                    vtime_floor: None,

                    worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                    owner_profile: CoSQueueOwnerProfile::new(),
                },
            ],
            queue_indices_by_priority: std::array::from_fn(|_| Vec::new()),
            rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
            timer_wheel: CoSTimerWheelRuntime {
                current_tick: 0,
                level0: std::array::from_fn(|_| Vec::new()),
                level1: std::array::from_fn(|_| Vec::new()),
            },
        };

        let live = BindingLiveState::new();
        live.owner_profile_owner.drain_latency_hist[1].store(5, Ordering::Relaxed);
        live.owner_profile_owner
            .drain_invocations
            .store(5, Ordering::Relaxed);
        live.owner_profile_owner
            .owner_pps
            .store(77, Ordering::Relaxed);

        let mut cos_map = FastMap::default();
        cos_map.insert(80, root);

        let statuses = build_worker_cos_statuses_from_maps([(&cos_map, Some(&live))], &forwarding);
        for queue in &statuses[0].queues {
            assert_eq!(
                queue.drain_invocations, 0,
                "ambiguous binding-scoped profile must stay zero on queue {}",
                queue.queue_id
            );
            assert!(queue.drain_latency_hist.is_empty());
            assert_eq!(queue.owner_pps, 0);
        }
    }

    /// #753 Copilot review: the first revision of the export gate scoped
    /// uniqueness per-interface, which missed the case where a binding
    /// drains multiple interfaces each with exactly one owner-local
    /// exact queue — the binding-level attribution is still ambiguous,
    /// but the per-interface gate would stamp the same snapshot onto
    /// both queue rows. This test drives that exact shape (two
    /// interfaces, one owner-local exact queue each, same binding) and
    /// asserts every queue stays zero.
    #[test]
    fn build_worker_cos_statuses_owner_profile_stays_zero_for_ambiguous_multi_interface_binding() {
        let mut forwarding = ForwardingState::default();
        forwarding
            .ifindex_to_config_name
            .insert(80, "reth0.80".to_string());
        forwarding
            .ifindex_to_config_name
            .insert(81, "reth0.81".to_string());

        // Two interfaces on the same binding, each carrying one
        // owner-local exact queue. Each interface on its own would
        // satisfy the old per-interface gate (single owner-local
        // exact). Together they're ambiguous at the binding level.
        let make_iface_config = || CoSInterfaceConfig {
            shaping_rate_bytes: SHARED_EXACT_RATE,
            burst_bytes: 256 * 1024,
            default_queue: 4,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".to_string(),
                priority: 1,
                transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
            }],
        };
        forwarding.cos.interfaces.insert(80, make_iface_config());
        forwarding.cos.interfaces.insert(81, make_iface_config());

        let make_runtime = || CoSInterfaceRuntime {
            shaping_rate_bytes: SHARED_EXACT_RATE,
            burst_bytes: 256 * 1024,
            tokens: 0,
            default_queue: 4,
            nonempty_queues: 0,
            runnable_queues: 0,
            exact_guarantee_rr: 0,
            nonexact_guarantee_rr: 0,
            #[cfg(test)]
            legacy_guarantee_rr: 0,
            queues: vec![CoSQueueRuntime {
                queue_id: 4,
                priority: 1,
                transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
                exact: true,
                flow_fair: false,
                shared_exact: false,
                flow_hash_seed: 0,
                surplus_weight: 1,
                surplus_deficit: 0,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
                tokens: 0,
                last_refill_ns: 0,
                queued_bytes: 0,
                active_flow_buckets: 0,
                active_flow_buckets_peak: 0,
                flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                queue_vtime: 0,
                pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                flow_rr_buckets: FlowRrRing::default(),
                flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                runnable: false,
                parked: false,
                next_wakeup_tick: 0,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::new(),
                local_item_count: 0,

                vtime_floor: None,

                worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                owner_profile: CoSQueueOwnerProfile::new(),
            }],
            queue_indices_by_priority: std::array::from_fn(|_| Vec::new()),
            rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
            timer_wheel: CoSTimerWheelRuntime {
                current_tick: 0,
                level0: std::array::from_fn(|_| Vec::new()),
                level1: std::array::from_fn(|_| Vec::new()),
            },
        };

        let live = BindingLiveState::new();
        live.owner_profile_owner.drain_latency_hist[2].store(11, Ordering::Relaxed);
        live.owner_profile_owner
            .drain_invocations
            .store(11, Ordering::Relaxed);
        live.owner_profile_owner
            .owner_pps
            .store(222, Ordering::Relaxed);
        live.owner_profile_peer
            .peer_pps
            .store(88, Ordering::Relaxed);

        let mut cos_map = FastMap::default();
        cos_map.insert(80, make_runtime());
        cos_map.insert(81, make_runtime());

        let statuses = build_worker_cos_statuses_from_maps([(&cos_map, Some(&live))], &forwarding);
        assert_eq!(statuses.len(), 2, "both interfaces should appear in output");
        for iface in &statuses {
            for queue in &iface.queues {
                assert_eq!(
                    queue.drain_invocations, 0,
                    "binding drains multiple interfaces with owner-local exact queues \
                     — attribution is ambiguous at the binding level, export must stay \
                     zero on {}:{}",
                    iface.interface_name, queue.queue_id,
                );
                assert!(queue.drain_latency_hist.is_empty());
                assert_eq!(queue.owner_pps, 0);
                assert_eq!(queue.peer_pps, 0);
            }
        }

        // Counter-factual: the pre-#753-Copilot-review per-interface
        // gate would have returned `Some(4)` for each interface
        // independently and stamped the snapshot onto both queue rows.
        // Pinning the NEW behaviour: the binding-wide scan returns
        // None because the eligible slot gets .replace()'d on the
        // second interface's queue 4.
        let row = unique_owner_profile_row(&cos_map, &forwarding);
        assert!(
            row.is_none(),
            "unique_owner_profile_row must return None when the binding has \
             multiple owner-local exact queues across interfaces; got {:?}",
            row
        );
    }

    /// #751 / #732: per-queue drain telemetry.
    ///
    /// Pre-#751 (symptom of #732): the same drain_latency_hist /
    /// drain_invocations read from BindingLiveState and stamped under
    /// every queue row of a multi-queue binding. The on-wire status
    /// repeated identical values on each queue even when the owner
    /// worker was draining two queues with wildly different latency
    /// profiles — e.g. a low-rate "iperf-a" queue with ~8 µs drains
    /// and a high-rate "iperf-b" queue with ~1 µs drains collapsed
    /// into a single flat shape.
    ///
    /// Post-#751: each queue carries its own per-queue atomics
    /// (CoSQueueRuntime::owner_profile). The snapshot reads from the
    /// queue itself; distinct queues report distinct distributions.
    ///
    /// This test pins that behaviour by seeding two owner-local
    /// exact queues on the same binding with disjoint latency
    /// histograms (non-overlapping bucket sets) and invocation
    /// counts, running the snapshot path, and asserting the two
    /// on-wire queue rows carry different values. The counter-factual
    /// pre-#751 behaviour (both queues showing the same profile)
    /// would fail the disjoint-bucket assertion loudly.
    #[test]
    fn build_worker_cos_statuses_surfaces_distinct_per_queue_drain_telemetry() {
        let mut forwarding = ForwardingState::default();
        forwarding
            .ifindex_to_config_name
            .insert(80, "reth0.80".to_string());
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 10_000_000_000 / 8,
                burst_bytes: 256 * 1024,
                default_queue: 0,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![
                    CoSQueueConfig {
                        queue_id: 4,
                        forwarding_class: "iperf-a".into(),
                        priority: 1,
                        transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
                        exact: true,
                        surplus_weight: 1,
                        buffer_bytes: 64 * 1024,
                        dscp_rewrite: None,
                    },
                    CoSQueueConfig {
                        queue_id: 6,
                        forwarding_class: "iperf-c".into(),
                        priority: 1,
                        // Also owner-local-exact — same shape as the
                        // ambiguous-multi-exact fixture above.
                        transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE / 2,
                        exact: true,
                        surplus_weight: 1,
                        buffer_bytes: 64 * 1024,
                        dscp_rewrite: None,
                    },
                ],
            },
        );

        let mut root = CoSInterfaceRuntime {
            shaping_rate_bytes: 10_000_000_000 / 8,
            burst_bytes: 256 * 1024,
            tokens: 0,
            default_queue: 0,
            nonempty_queues: 0,
            runnable_queues: 0,
            exact_guarantee_rr: 0,
            nonexact_guarantee_rr: 0,
            #[cfg(test)]
            legacy_guarantee_rr: 0,
            queues: vec![
                CoSQueueRuntime {
                    queue_id: 4,
                    priority: 1,
                    transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
                    exact: true,
                    flow_fair: false,
                    shared_exact: false,
                    flow_hash_seed: 0,
                    surplus_weight: 1,
                    surplus_deficit: 0,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                    tokens: 0,
                    last_refill_ns: 0,
                    queued_bytes: 0,
                    active_flow_buckets: 0,
                    active_flow_buckets_peak: 0,
                    flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    queue_vtime: 0,
                    pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                    flow_rr_buckets: FlowRrRing::default(),
                    flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                    runnable: false,
                    parked: false,
                    next_wakeup_tick: 0,
                    wheel_level: 0,
                    wheel_slot: 0,
                    items: VecDeque::new(),
                    local_item_count: 0,

                    vtime_floor: None,

                    worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                    owner_profile: CoSQueueOwnerProfile::new(),
                },
                CoSQueueRuntime {
                    queue_id: 6,
                    priority: 1,
                    transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE / 2,
                    exact: true,
                    flow_fair: false,
                    shared_exact: false,
                    flow_hash_seed: 0,
                    surplus_weight: 1,
                    surplus_deficit: 0,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                    tokens: 0,
                    last_refill_ns: 0,
                    queued_bytes: 0,
                    active_flow_buckets: 0,
                    active_flow_buckets_peak: 0,
                    flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                    queue_vtime: 0,
                    pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                    flow_rr_buckets: FlowRrRing::default(),
                    flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                    runnable: false,
                    parked: false,
                    next_wakeup_tick: 0,
                    wheel_level: 0,
                    wheel_slot: 0,
                    items: VecDeque::new(),
                    local_item_count: 0,

                    vtime_floor: None,

                    worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                    owner_profile: CoSQueueOwnerProfile::new(),
                },
            ],
            queue_indices_by_priority: std::array::from_fn(|_| Vec::new()),
            rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
            timer_wheel: CoSTimerWheelRuntime {
                current_tick: 0,
                level0: std::array::from_fn(|_| Vec::new()),
                level1: std::array::from_fn(|_| Vec::new()),
            },
        };

        // Queue 4: "slow drain" profile — landings in high bucket.
        {
            let q = root.queues.iter_mut().find(|q| q.queue_id == 4).unwrap();
            q.owner_profile.drain_latency_hist[12].store(7, Ordering::Relaxed);
            q.owner_profile
                .drain_invocations
                .store(7, Ordering::Relaxed);
        }
        // Queue 6: "fast drain" profile — landings in low bucket.
        // Disjoint from queue 4's bucket so a regression that collapses
        // to a single profile fails the per-queue distinctness check.
        {
            let q = root.queues.iter_mut().find(|q| q.queue_id == 6).unwrap();
            q.owner_profile.drain_latency_hist[2].store(23, Ordering::Relaxed);
            q.owner_profile
                .drain_invocations
                .store(23, Ordering::Relaxed);
        }

        // Binding-scoped fields: ambiguous shape (two owner-local
        // exact queues), so these stay at zero on all queues
        // regardless of what we seed — the test does NOT seed
        // BindingLiveState to make that invariant explicit.
        let live = BindingLiveState::new();
        let mut cos_map = FastMap::default();
        cos_map.insert(80, root);

        let statuses =
            build_worker_cos_statuses_from_maps([(&cos_map, Some(&live))], &forwarding);
        let queues = &statuses[0].queues;
        let q4 = queues.iter().find(|q| q.queue_id == 4).unwrap();
        let q6 = queues.iter().find(|q| q.queue_id == 6).unwrap();

        // Per-queue distinctness.
        assert_eq!(q4.drain_invocations, 7);
        assert_eq!(q4.drain_latency_hist[12], 7);
        assert_eq!(q4.drain_latency_hist[2], 0);

        assert_eq!(q6.drain_invocations, 23);
        assert_eq!(q6.drain_latency_hist[2], 23);
        assert_eq!(q6.drain_latency_hist[12], 0);

        // Counter-factual: if the snapshot collapsed both queues to
        // a shared profile (the pre-#751 / #732 behaviour), q4 would
        // carry q6's bucket[2] count and vice versa. Assert both
        // hists are disjoint in their non-zero buckets.
        assert!(
            q4.drain_latency_hist[12] > 0 && q4.drain_latency_hist[2] == 0
                && q6.drain_latency_hist[2] > 0 && q6.drain_latency_hist[12] == 0,
            "queues must surface their own per-queue hist, not share a \
             binding-wide rollup (pre-#751 regression)",
        );

        // Binding-scoped fields stay at zero on ambiguous shapes.
        assert_eq!(q4.owner_pps, 0);
        assert_eq!(q6.owner_pps, 0);
        assert_eq!(q4.peer_pps, 0);
        assert_eq!(q6.peer_pps, 0);
        assert_eq!(q4.drain_noop_invocations, 0);
        assert_eq!(q6.drain_noop_invocations, 0);
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
            &BTreeMap::new(),
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
            &BTreeMap::new(),
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

    #[test]
    fn build_worker_cos_fast_interfaces_high_iface_rate_shards_mid_rate_exact_queue() {
        // #697 regression: a mid-rate exact queue on a >10g iface must end
        // up on the shared-worker path end-to-end. The helper predicate is
        // tested directly elsewhere in this module, but the runtime effect
        // of this PR lands in `build_worker_cos_fast_interfaces` and is
        // later consumed by `ensure_cos_interface_runtime` to set
        // `flow_fair` and by the dispatch path to pick shared vs owner-
        // local service. Pin the assembled output for the new regime
        // (`iface_rate / 4 > MIN`) so a future refactor of either the
        // predicate or the assembly cannot quietly re-introduce the
        // PR #680 collapse shape.
        //
        // Shape: 100g iface, 5g exact queue on queue_id=6. Under the
        // pre-fix policy the threshold was 25g and a 5g exact queue would
        // have assembled with `shared_exact=false` and `shared_queue_lease
        // = None`. Under the fix the 5g queue crosses the 2.5g absolute
        // floor and assembles as shared.
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 100_000_000_000 / 8,
                burst_bytes: 1 * 1024 * 1024,
                default_queue: 6,
                dscp_classifier: String::new(),
                ieee8021_classifier: String::new(),
                dscp_queue_by_dscp: [u8::MAX; 64],
                ieee8021_queue_by_pcp: [u8::MAX; 8],
                queue_by_forwarding_class: FastMap::default(),
                queues: vec![CoSQueueConfig {
                    queue_id: 6,
                    forwarding_class: "mid-rate".into(),
                    priority: 5,
                    transmit_rate_bytes: 5_000_000_000 / 8,
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: 256 * 1024,
                    dscp_rewrite: None,
                }],
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

        let queue_owner_live = Arc::new(BindingLiveState::new());
        let tx_owner_live = Arc::new(BindingLiveState::new());
        let tx_owner_live_by_tx_ifindex = FastMap::from_iter([(12, tx_owner_live.clone())]);
        let owner_worker_by_queue = BTreeMap::from([((80, 6), 5)]);
        let owner_live_by_queue = BTreeMap::from([((80, 6), queue_owner_live.clone())]);
        let shared_root_leases = BTreeMap::from([(
            80,
            Arc::new(SharedCoSRootLease::new(
                100_000_000_000 / 8,
                1 * 1024 * 1024,
                4,
            )),
        )]);
        let queue_lease = Arc::new(SharedCoSQueueLease::new(5_000_000_000 / 8, 256 * 1024, 4));
        let shared_queue_leases = BTreeMap::from([((80, 6), queue_lease.clone())]);

        let fast = build_worker_cos_fast_interfaces(
            &forwarding,
            3,
            &tx_owner_live_by_tx_ifindex,
            &owner_worker_by_queue,
            &owner_live_by_queue,
            &shared_root_leases,
            &shared_queue_leases,
            &BTreeMap::new(),
        );

        let iface = fast.get(&80).expect("fast cos interface");
        let queue6 = iface.queue_fast_path(Some(6)).expect("queue 6");
        assert!(
            queue6.shared_exact,
            "5g exact queue on 100g iface must be classified as shared after #697"
        );
        assert!(
            queue6.shared_queue_lease.is_some(),
            "shared queue lease must be wired up for a sharded exact queue"
        );
        assert_eq!(queue6.owner_worker_id, 5);
    }

    #[test]
    fn build_worker_cos_fast_interfaces_matches_live_loss_ha_3_queue_shape() {
        // #698 regression: end-to-end dispatch coverage for the exact
        // live loss HA CoS config every other PR in this series has
        // validated against. Prior predicate tests pin the
        // `queue_uses_shared_exact_service` output; the earlier 2-queue
        // assembly test pins the shared-lease plumbing for one mixed
        // case. Neither exercises all three production queues in
        // their production interface shape at once.
        //
        // Wiring matches what the coordinator actually produces.
        // `build_shared_cos_queue_leases_reusing_existing` creates a
        // `SharedCoSQueueLease` for *every* exact queue with a nonzero
        // rate — regardless of whether `shared_exact` is true. So on
        // the live path, owner-local exact queues (queues 0 and 4 here)
        // carry a shared queue lease *object* that simply isn't used
        // by their dispatch path. That's the real contract this test
        // pins: `shared_exact` flips the *execution* policy, not the
        // *lease presence*.
        //
        // Shape:
        //   reth0.80 shaper 10g
        //     queue 0  best-effort  100m exact
        //                  -> shared_exact=false (owner-local service)
        //                  -> shared_queue_lease=Some(_)  (coordinator always wires)
        //     queue 4  iperf-a      1g   exact
        //                  -> shared_exact=false (owner-local service)
        //                  -> shared_queue_lease=Some(_)
        //     queue 5  iperf-b      10g  exact
        //                  -> shared_exact=true  (sharded service)
        //                  -> shared_queue_lease=Some(_)
        //
        // Threshold on a 10g iface = `COS_SHARED_EXACT_MIN_RATE_BYTES`
        // = 2.5 Gbps. queues 0 and 4 are below; queue 5 is at 10g.
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(
            80,
            CoSInterfaceConfig {
                shaping_rate_bytes: 10_000_000_000 / 8,
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
                        transmit_rate_bytes: 100_000_000 / 8,
                        exact: true,
                        surplus_weight: 1,
                        buffer_bytes: 64 * 1024,
                        dscp_rewrite: None,
                    },
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
                        buffer_bytes: 256 * 1024,
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
        let q0_owner_live = Arc::new(BindingLiveState::new());
        let q4_owner_live = Arc::new(BindingLiveState::new());
        let q5_owner_live = Arc::new(BindingLiveState::new());

        let tx_owner_live_by_tx_ifindex = FastMap::from_iter([(12, tx_owner_live.clone())]);
        let owner_worker_by_queue = BTreeMap::from([((80, 0), 2), ((80, 4), 4), ((80, 5), 7)]);
        let owner_live_by_queue = BTreeMap::from([
            ((80, 0), q0_owner_live.clone()),
            ((80, 4), q4_owner_live.clone()),
            ((80, 5), q5_owner_live.clone()),
        ]);
        let shared_root_leases = BTreeMap::from([(
            80,
            Arc::new(SharedCoSRootLease::new(10_000_000_000 / 8, 256 * 1024, 4)),
        )]);
        // Coordinator wires a shared queue lease for every non-zero-rate
        // exact queue, not only the shared ones. Mirror that here so the
        // test exercises the live shape rather than a hand-pruned one.
        let q0_shared_queue_lease =
            Arc::new(SharedCoSQueueLease::new(100_000_000 / 8, 64 * 1024, 4));
        let q4_shared_queue_lease =
            Arc::new(SharedCoSQueueLease::new(1_000_000_000 / 8, 128 * 1024, 4));
        let q5_shared_queue_lease =
            Arc::new(SharedCoSQueueLease::new(10_000_000_000 / 8, 256 * 1024, 4));
        let shared_queue_leases = BTreeMap::from([
            ((80, 0), q0_shared_queue_lease.clone()),
            ((80, 4), q4_shared_queue_lease.clone()),
            ((80, 5), q5_shared_queue_lease.clone()),
        ]);

        let fast = build_worker_cos_fast_interfaces(
            &forwarding,
            3,
            &tx_owner_live_by_tx_ifindex,
            &owner_worker_by_queue,
            &owner_live_by_queue,
            &shared_root_leases,
            &shared_queue_leases,
            &BTreeMap::new(),
        );

        let iface = fast.get(&80).expect("fast cos interface");
        assert_eq!(iface.tx_ifindex, 12);

        let q0 = iface.queue_fast_path(Some(0)).expect("queue 0");
        assert!(
            !q0.shared_exact,
            "best-effort 100m exact must be owner-local (single-owner service) on 10g iface"
        );
        assert_eq!(q0.owner_worker_id, 2);
        assert!(Arc::ptr_eq(
            q0.owner_live.as_ref().expect("q0 owner live"),
            &q0_owner_live,
        ));
        assert!(
            Arc::ptr_eq(
                q0.shared_queue_lease
                    .as_ref()
                    .expect("q0 shared queue lease"),
                &q0_shared_queue_lease,
            ),
            "coordinator wires a shared queue lease for every non-zero-rate exact queue, \
             including owner-local ones; the lease object must survive fast-path assembly"
        );

        let q4 = iface.queue_fast_path(Some(4)).expect("queue 4");
        assert!(
            !q4.shared_exact,
            "iperf-a 1g exact must be owner-local (single-owner service) on 10g iface"
        );
        assert_eq!(q4.owner_worker_id, 4);
        assert!(Arc::ptr_eq(
            q4.owner_live.as_ref().expect("q4 owner live"),
            &q4_owner_live,
        ));
        assert!(Arc::ptr_eq(
            q4.shared_queue_lease
                .as_ref()
                .expect("q4 shared queue lease"),
            &q4_shared_queue_lease,
        ));

        let q5 = iface.queue_fast_path(Some(5)).expect("queue 5");
        assert!(
            q5.shared_exact,
            "iperf-b 10g exact must be sharded on 10g iface"
        );
        assert_eq!(q5.owner_worker_id, 7);
        assert!(Arc::ptr_eq(
            q5.owner_live.as_ref().expect("q5 owner live"),
            &q5_owner_live,
        ));
        assert!(Arc::ptr_eq(
            q5.shared_queue_lease
                .as_ref()
                .expect("q5 shared queue lease"),
            &q5_shared_queue_lease
        ));
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
        // Threshold is the absolute per-worker ceiling (2.5g) on any iface.
        let iface = test_cos_iface_with_rate(10_000_000_000);
        let be = test_exact_queue_at_rate(0, 100_000_000);
        let iperf_a = test_exact_queue_at_rate(4, 1_000_000_000);
        let iperf_b = test_exact_queue_at_rate(5, 10_000_000_000);
        assert!(!queue_uses_shared_exact_service(&iface, &be));
        assert!(!queue_uses_shared_exact_service(&iface, &iperf_a));
        assert!(queue_uses_shared_exact_service(&iface, &iperf_b));
    }

    #[test]
    fn queue_uses_shared_exact_service_threshold_is_exactly_inclusive() {
        // Threshold = COS_SHARED_EXACT_MIN_RATE_BYTES (2.5 Gbps =
        // 312_500_000 bytes/s). Exactly at threshold selects the shared
        // path; one byte below stays single-owner. The boundary must be
        // deterministic — a fairness fix that accidentally flips
        // classification for a queue at the stated threshold will silently
        // regress 5201 or 5202. Pinned across a slow and a fast iface so
        // the boundary cannot re-gain an iface-dependent term without
        // being caught.
        for iface_bits in [1_000_000_000u64, 10_000_000_000, 100_000_000_000] {
            let iface = test_cos_iface_with_rate(iface_bits);
            let mut q = test_exact_queue_at_rate(4, 0);
            q.transmit_rate_bytes = COS_SHARED_EXACT_MIN_RATE_BYTES - 1;
            assert!(
                !queue_uses_shared_exact_service(&iface, &q),
                "iface {iface_bits}: one byte below threshold must stay single-owner"
            );
            q.transmit_rate_bytes = COS_SHARED_EXACT_MIN_RATE_BYTES;
            assert!(
                queue_uses_shared_exact_service(&iface, &q),
                "iface {iface_bits}: at threshold must be shared"
            );
        }
    }

    #[test]
    fn queue_uses_shared_exact_service_slow_iface_below_threshold_is_single_owner() {
        // 1g iface, every exact queue is below the 2.5g ceiling → single
        // owner. Documents that the predicate does not depend on the
        // queue/iface ratio, only on the queue's absolute rate.
        let iface = test_cos_iface_with_rate(1_000_000_000);
        let q_100m = test_exact_queue_at_rate(0, 100_000_000);
        let q_1g = test_exact_queue_at_rate(4, 1_000_000_000);
        assert!(!queue_uses_shared_exact_service(&iface, &q_100m));
        assert!(!queue_uses_shared_exact_service(&iface, &q_1g));
    }

    #[test]
    fn queue_uses_shared_exact_service_zero_rate_exact_queue_is_single_owner() {
        // Config validation should normally reject a 0-rate exact queue,
        // but if one ever reaches the predicate (race during reload, test
        // fixture, malformed journal replay) the policy is "single owner":
        // a queue with no budget cannot justify burning a shared-lease
        // slot, and the threshold is strictly positive.
        let iface_10g = test_cos_iface_with_rate(10_000_000_000);
        let iface_100g = test_cos_iface_with_rate(100_000_000_000);
        let mut q = test_exact_queue_at_rate(4, 0);
        q.transmit_rate_bytes = 0;
        assert!(!queue_uses_shared_exact_service(&iface_10g, &q));
        assert!(!queue_uses_shared_exact_service(&iface_100g, &q));
    }

    #[test]
    fn queue_uses_shared_exact_service_threshold_does_not_scale_with_iface_rate() {
        // #697: the pre-fix policy was `max(iface_rate / 4, MIN)` which
        // scaled the threshold up with iface rate. A 10g exact queue on a
        // 100g iface got classified as single-owner (threshold was 25g),
        // routing a genuinely high-rate queue straight into PR #680's
        // throughput-collapse shape. The fix removes the `/ 4` term; the
        // threshold is now the absolute per-worker ceiling regardless of
        // iface rate. Exercise that: a 10g exact queue must be shared on
        // every realistic iface rate, not just on a 10g iface.
        let q_10g = test_exact_queue_at_rate(5, 10_000_000_000);
        for iface_bits in [10u64, 25, 40, 50, 100, 200, 400].map(|g| g * 1_000_000_000) {
            let iface = test_cos_iface_with_rate(iface_bits);
            assert!(
                queue_uses_shared_exact_service(&iface, &q_10g),
                "iface {iface_bits}: 10g exact queue must be shared — single-owner would \
                 reintroduce the PR #680 throughput collapse"
            );
        }
    }

    #[test]
    fn queue_uses_shared_exact_service_high_iface_rate_shards_mid_rate_queues() {
        // Same shape as the scale-invariance test but pinned byte-precise
        // at the threshold for a specific fast iface. On a 100g iface a
        // 2.5g exact queue must shard (it crosses the per-worker ceiling),
        // and a 2.5g-minus-one-byte queue must not. Under the pre-fix
        // policy this iface had threshold 25g and both of these would have
        // been single-owner.
        let iface = test_cos_iface_with_rate(100_000_000_000);
        let mut q = test_exact_queue_at_rate(4, 0);
        q.transmit_rate_bytes = COS_SHARED_EXACT_MIN_RATE_BYTES - 1;
        assert!(!queue_uses_shared_exact_service(&iface, &q));
        q.transmit_rate_bytes = COS_SHARED_EXACT_MIN_RATE_BYTES;
        assert!(queue_uses_shared_exact_service(&iface, &q));
        q.transmit_rate_bytes = 5_000_000_000 / 8; // 5 Gbps
        assert!(queue_uses_shared_exact_service(&iface, &q));
    }

    #[test]
    fn queue_uses_shared_exact_service_zero_iface_rate_uses_absolute_threshold() {
        // Bootstrap / pathological case: iface shaper is 0 (unconfigured).
        // Predicate is iface-rate-independent, so this is just the absolute
        // threshold applied to the queue rate. Verifies there is no
        // divide-by-zero or underflow on any code path the previous
        // `saturating_div(4)` branch used to guard.
        let iface = test_cos_iface_with_rate(0);
        let q_2g = test_exact_queue_at_rate(4, 2_000_000_000);
        let q_3g = test_exact_queue_at_rate(5, 3_000_000_000);
        assert!(!queue_uses_shared_exact_service(&iface, &q_2g));
        assert!(queue_uses_shared_exact_service(&iface, &q_3g));
    }

    #[test]
    fn queue_uses_shared_exact_service_queue_rate_above_iface_rate_uses_queue_rate() {
        // #698 misconfig pin. Junos config validation does not cap the
        // queue's `transmit-rate` at the iface `shaping-rate`, so a
        // 10g exact queue can appear on a 1g iface. The predicate does
        // not read iface rate, so classification is a function of the
        // queue's absolute rate only — in this case 10g ≥ 2.5g → shared.
        // Whether such a queue can actually achieve 10g on a 1g iface
        // is a separate shaper question; the predicate's job is to
        // produce a deterministic classification even under
        // malformed config, not to reject the config.
        let iface = test_cos_iface_with_rate(1_000_000_000);
        let q_10g = test_exact_queue_at_rate(5, 10_000_000_000);
        assert!(
            queue_uses_shared_exact_service(&iface, &q_10g),
            "a 10g exact queue on a 1g iface must classify on its own rate (shared), \
             not on queue/iface ratio"
        );
        // Same logic holds at the exact threshold — nothing about the
        // iface rate influences the decision.
        let mut q = test_exact_queue_at_rate(6, 0);
        q.transmit_rate_bytes = COS_SHARED_EXACT_MIN_RATE_BYTES;
        assert!(queue_uses_shared_exact_service(&iface, &q));
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
    pub(crate) flow_cache_collision_evictions: u64,
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
    pub(crate) redirect_inbox_overflow_drops: u64,
    pub(crate) pending_tx_local_overflow_drops: u64,
    pub(crate) tx_submit_error_drops: u64,
    // #760 triage: surfaced on BindingStatus so operators can
    // compare binding-level vs per-queue drain accounting.
    pub(crate) post_drain_backup_bytes: u64,
    pub(crate) drain_sent_bytes_shaped_unconditional: u64,
    // #760 (PR #773): drop-filter counters for CoS-bound items
    // that reached the post-CoS backup paths. Non-zero indicates
    // a cross-worker routing failure the bounded ingest-drain
    // loop did not absorb.
    pub(crate) post_drain_backup_cos_drops: u64,
    pub(crate) post_drain_backup_cos_drop_bytes: u64,
    // #710: `no_owner_binding_drops` is intentionally NOT snapshotted
    // per-binding. The atomic on `BindingLiveState` accumulates drops
    // for mechanical accounting (the increment site can only write to
    // `bindings.first_mut()`), but the operator-facing aggregate lives
    // at `ProcessStatus::cos_no_owner_binding_drops_total`, summed
    // across every live state by
    // `Coordinator::cos_no_owner_binding_drops_total()`.
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
    /// #878: per-binding UMEM total frames (set once at worker
    /// construction). Used as the denominator for the `show chassis
    /// forwarding` Buffer% display; numerator comes from
    /// `umem_inflight_frames` published once per second by the
    /// owning worker.
    pub(crate) umem_total_frames: u32,
    /// #878: configured TX-ring depth (set once at worker
    /// construction). `outstanding_tx / tx_ring_capacity` is the
    /// second pressure signal aggregated by Buffer%.
    pub(crate) tx_ring_capacity: u32,
    /// #878: UMEM in-flight gauge published in a single store from
    /// the worker's per-second debug tick — no torn-load risk on
    /// the read side.
    pub(crate) umem_inflight_frames: u32,
    // #802: ring-pressure snapshot fields. Mirrored from BindingLiveState
    // atomics that are published by the worker's per-second debug tick.
    pub(crate) dbg_tx_ring_full: u64,
    pub(crate) dbg_sendto_enobufs: u64,
    // #802/#804: split — see `BindingLiveState` for write-site semantics.
    pub(crate) dbg_bound_pending_overflow: u64,
    pub(crate) dbg_cos_queue_overflow: u64,
    pub(crate) rx_fill_ring_empty_descs: u64,
    pub(crate) last_heartbeat: Option<chrono::DateTime<Utc>>,
    pub(crate) last_error: String,
    // #709: owner-profile telemetry snapshot. Fixed-size arrays (no
    // `Vec`) to keep the snapshot allocation-free on the hot path;
    // readers that want a `Vec` for JSON can copy on demand.
    pub(crate) drain_latency_hist: [u64; DRAIN_HIST_BUCKETS],
    pub(crate) drain_invocations: u64,
    pub(crate) drain_noop_invocations: u64,
    pub(crate) redirect_acquire_hist: [u64; DRAIN_HIST_BUCKETS],
    pub(crate) owner_pps: u64,
    pub(crate) peer_pps: u64,
    /// #812: per-queue TX submit→completion latency histogram +
    /// count + sum-ns. Fixed-size array (same pattern as
    /// `drain_latency_hist`). The array is materialized into a
    /// `Vec<u64>` only at the JSON/protocol boundary; the snapshot
    /// itself stays allocation-free.
    pub(crate) tx_submit_latency_hist: [u64; TX_SUBMIT_LAT_BUCKETS],
    pub(crate) tx_submit_latency_count: u64,
    pub(crate) tx_submit_latency_sum_ns: u64,
    /// #825: per-kick `sendto` latency histogram + count +
    /// sum-ns + EAGAIN-retry count. Fixed-size array matches
    /// `tx_submit_latency_hist`; materialized into a `Vec<u64>`
    /// at the JSON/protocol boundary, the snapshot itself stays
    /// allocation-free.
    pub(crate) tx_kick_latency_hist: [u64; TX_SUBMIT_LAT_BUCKETS],
    pub(crate) tx_kick_latency_count: u64,
    pub(crate) tx_kick_latency_sum_ns: u64,
    pub(crate) tx_kick_retry_count: u64,
}
