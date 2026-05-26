use super::*;

// Issue 73 step 2: per-poll BindingWorker lifecycle (the central
// `poll_binding` orchestrator) lives in worker/lifecycle.rs.
mod lifecycle;
use lifecycle::poll_binding;

// #959 Phase 1: per-worker debug counters live in worker/telemetry.rs.
mod telemetry;
pub(crate) use telemetry::WorkerTelemetry;

// #959 Phase 2: per-binding reusable scratch buffers live in
// worker/scratch.rs.
mod scratch;
pub(crate) use scratch::WorkerScratch;

// #959 Phase 3: per-binding CoS scheduling state lives in
// worker/cos_state.rs (the `cos` module name is taken by
// worker/cos.rs which holds runtime helpers).
mod cos_state;
pub(crate) use cos_state::WorkerCos;

// #959 Phase 4: per-binding TX-disposition packet counters live in
// worker/tx_counters.rs.
mod tx_counters;
pub(crate) use tx_counters::WorkerTxCounters;

// #959 Phase 5: per-binding BPF map FDs live in worker/bpf_maps.rs.
mod bpf_maps;
pub(crate) use bpf_maps::WorkerBpfMaps;

// #959 Phase 6: per-binding timing / wake-pacing state lives in
// worker/timers.rs.
mod timers;
pub(crate) use timers::WorkerTimers;

// #959 Phase 7: per-binding TX pipeline state lives in
// worker/tx_pipeline.rs.
mod tx_pipeline;
pub(crate) use tx_pipeline::WorkerTxPipeline;

// #959 Phase 8: per-binding registration / identity metadata lives
// in worker/bind_meta.rs.
mod bind_meta;
pub(crate) use bind_meta::WorkerBindMeta;

// #959 Phase 9: per-binding flow-cache state lives in
// worker/flow_cache_state.rs (the `flow_cache` name is taken by
// the `FlowCache` data structure in src/afxdp/flow_cache.rs).
mod flow_cache_state;
pub(crate) use flow_cache_state::WorkerFlowCacheState;

// #959 Phase 11 — XSK kernel-ring handles in
// worker/xsk_rings.rs. Holds the three socket-ring objects
// `device`, `rx`, `tx` (was held back as highest-risk because
// of the `off.rx`/`off.tx` and `telemetry.dbg.rx`/`.tx`
// snapshot/diagnostic name collisions).
mod xsk_rings;
pub(crate) use xsk_rings::WorkerXskRings;

// #957 P1: worker-side CoS runtime helpers split out into a sibling
// submodule. Note this module is `worker::cos`, separate from the
// `afxdp::cos` directory module imported below as `super::cos`.
mod cos;
pub(in crate::afxdp) use cos::COS_SHARED_EXACT_MIN_RATE_BYTES;
pub(crate) use cos::merge_cos_queue_owner_profile_sum;
pub(in crate::afxdp) use cos::{
    OwnerProfileSnapshot, merge_binding_scoped_owner_profile, merge_owner_profile_sum,
    owner_profile_snapshot,
};
use cos::{
    build_worker_cos_fast_interfaces, build_worker_cos_owner_live_by_tx_ifindex,
    build_worker_cos_statuses, cos_runtime_config_changed, reset_binding_cos_runtime,
    reset_worker_cos_runtimes, vacate_all_shared_exact_slots_for_binding,
};

// #956 Phase 4-5: explicit imports for items that moved out of tx.rs into
// cos/token_bucket.rs (Phase 4) and cos/queue_ops.rs (Phase 5). Without
// this, neither the local `use super::*;` glob nor afxdp.rs's
// `use self::tx::*;` parent-module glob still reaches them — the items
// no longer originate from tx.rs after the moves.
use super::cos::{
    clear_all_cos_exact_backlogs_for_binding, cos_queue_len, cos_queue_pop_front_no_snapshot,
    publish_cos_exact_backlog, release_all_cos_queue_leases, release_all_cos_root_leases,
};

pub(crate) struct BindingWorker {
    pub(crate) slot: u32,
    pub(crate) queue_id: u32,
    pub(crate) worker_id: u32,
    pub(crate) interface: Arc<str>,
    pub(crate) ifindex: i32,
    pub(crate) live: Arc<BindingLiveState>,
    #[allow(dead_code)]
    pub(crate) user: User,
    /// #959 Phase 11: 3 XSK kernel-ring handles extracted into
    /// `WorkerXskRings`. Field semantics unchanged; access via
    /// `binding.xsk.device`, `binding.xsk.rx`, `binding.xsk.tx`.
    pub(crate) xsk: WorkerXskRings,
    /// Keep UMEM after the XSK handles in declaration order. Rust drops
    /// struct fields in declaration order, and libxdp sockets must be deleted
    /// before the backing UMEM can be deleted in shared mode.
    pub(crate) umem: WorkerUmem,
    /// #959 Phase 7 + Phase 10: 8 TX pipeline fields extracted into
    /// `WorkerTxPipeline` (Phase 7 brought 7; Phase 10 added
    /// `outstanding_tx` once the BindingStatus mirror collision was
    /// resolved by type-level disambiguation). Field semantics
    /// unchanged; access via `binding.tx_pipeline.X`.
    pub(crate) tx_pipeline: WorkerTxPipeline,
    /// #959 Phase 3: 5 `cos_*` per-binding CoS scheduling fields
    /// extracted into `WorkerCos`. Field semantics unchanged;
    /// access via `binding.cos.cos_X`.
    pub(crate) cos: WorkerCos,
    /// #959 Phase 2: 11 `scratch_*` reusable buffers extracted into
    /// `WorkerScratch`. Field semantics unchanged; access via
    /// `binding.scratch.scratch_X`.
    pub(crate) scratch: WorkerScratch,
    /// Packets waiting for neighbor resolution. The UMEM frame is held
    /// (not recycled) until the neighbor resolves or the entry times out.
    pub(crate) pending_neigh: VecDeque<PendingNeighPacket>,
    /// #959 Phase 5: 4 BPF map FDs extracted into `WorkerBpfMaps`.
    /// Field semantics unchanged; access via `binding.bpf_maps.X_fd`.
    pub(crate) bpf_maps: WorkerBpfMaps,
    /// #959 Phase 6: 6 timing / wake-pacing fields extracted into
    /// `WorkerTimers`. Field semantics unchanged; access via
    /// `binding.timers.last_X_ns` etc.
    pub(crate) timers: WorkerTimers,
    pub(crate) last_learned_neighbor: Option<LearnedNeighborKey>,
    /// #959 Phase 1: 23 `dbg_*` debug counters extracted into
    /// `WorkerTelemetry` to reduce BindingWorker's mutable surface
    /// area. Field semantics unchanged; access via `binding.telemetry.dbg_X`.
    pub(crate) telemetry: WorkerTelemetry,
    /// #959 Phase 4: 6 `pending_*_tx_*` packet counters extracted
    /// into `WorkerTxCounters`. Field semantics unchanged; access
    /// via `binding.tx_counters.pending_X`.
    pub(crate) tx_counters: WorkerTxCounters,
    /// #959 Phase 9: 2 flow-cache state fields extracted into
    /// `WorkerFlowCacheState`. Field semantics unchanged; access
    /// via `binding.flow.flow_cache` and `binding.flow.flow_cache_session_touch`.
    pub(crate) flow: WorkerFlowCacheState,
    /// #1376: per-worker/per-binding mirror sampler. Reset on worker
    /// restart and intentionally not synchronized across workers.
    pub(crate) mirror_sample_counter: u64,
    /// #959 Phase 8: 3 binding registration / identity fields
    /// (bind_time_ns, bind_mode, xsk_rx_confirmed) extracted into
    /// `WorkerBindMeta`. Field semantics unchanged; access via
    /// `binding.bind_meta.X`.
    pub(crate) bind_meta: WorkerBindMeta,
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
        socket_role: XskSocketRole,
        poll_mode: crate::PollMode,
        mut worker_umem: WorkerUmem,
        frame_pool: &mut VecDeque<u64>,
        shared_umem: bool,
        register_xsk_now: bool,
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
        // Safety: `BindingWorker` declares `xsk` before `umem`, so Rust drops
        // the socket/ring handles before the UMEM. That satisfies the UMEM
        // lifetime/drop-order contract enforced by `open_binding_worker_rings`.
        let (user, rx, tx, bind_mode, bind_flags, actual_bind_strategy, device) = unsafe {
            open_binding_worker_rings(
                &mut worker_umem,
                &info,
                ring_entries,
                bind_strategy,
                socket_role,
                driver_name.as_deref(),
                poll_mode,
                Some(&initial_fill_frames),
            )
        }
        .map_err(|err| format!("configure AF_XDP rings: {err}"))?;

        let user_fd = user.as_raw_fd();
        live.set_bound(user_fd);
        live.set_bind_mode(bind_mode);
        // getsockname() returns ENOTSUP on AF_XDP sockets (kernel doesn't
        // implement it for this family).  Use the binding plan's expected
        // ifindex/queue_id directly — umem.bind() already validated these.
        live.set_socket_binding(binding.ifindex, binding.queue_id, u32::from(bind_flags));
        // #878: publish per-binding capacities so the snapshot path can
        // expose them via the wire BindingStatus. These are write-once
        // (set here at worker construction) and read-many.
        live.umem_total_frames
            .store(total_frames, std::sync::atomic::Ordering::Relaxed);
        live.tx_ring_capacity
            .store(ring_entries, std::sync::atomic::Ordering::Relaxed);
        eprintln!(
            "xpf-userspace-dp: binding slot={} fd={} strategy={} role={} bound if{}q{} mode={:?} flags=0x{:04x} shared_umem={}",
            binding.slot,
            user_fd,
            actual_bind_strategy.describe(),
            socket_role.describe(),
            binding.ifindex,
            binding.queue_id,
            bind_mode,
            bind_flags,
            shared_umem,
        );
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
            xsk: WorkerXskRings { device, rx, tx },
            tx_pipeline: WorkerTxPipeline {
                free_tx_frames: reserved_tx_frames,
                pending_tx_prepared: VecDeque::new(),
                pending_tx_local: VecDeque::new(),
                max_pending_tx,
                outstanding_tx: 0,
                pending_fill_frames: VecDeque::new(),
                in_flight_prepared_recycles: FastMap::default(),
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
            },
            cos: WorkerCos {
                cos_fast_interfaces: FastMap::default(),
                cos_interfaces: FastMap::default(),
                cos_interface_order: Vec::new(),
                cos_interface_rr: 0,
                cos_nonempty_interfaces: 0,
                cos_queue_lease_acquire_v8_calls: 0,
                cos_queue_lease_acquire_v8_granted_bytes: 0,
            },
            scratch: WorkerScratch {
                scratch_recycle: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_forwards: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_fill: Vec::with_capacity(FILL_BATCH_SIZE),
                scratch_prepared_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_local_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_exact_prepared_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_exact_local_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_completed_offsets: Vec::with_capacity(ring_entries as usize),
                scratch_post_recycles: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_cross_binding_tx: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_rst_teardowns: Vec::with_capacity(16),
            },
            // GEMINI-NEXT.md Section 3 cold start: lazy allocation. The
            // 4096-cap is enforced at admission (poll_descriptor.rs check
            // against MAX_PENDING_NEIGH), so pre-allocating that capacity
            // up front would burn ~576 KB per binding at startup even when
            // idle. Start at 0 capacity and let VecDeque grow on push as
            // packets actually queue up.
            pending_neigh: VecDeque::new(),
            bpf_maps: WorkerBpfMaps {
                heartbeat_map_fd,
                session_map_fd,
                conntrack_v4_fd,
                conntrack_v6_fd,
            },
            timers: WorkerTimers {
                last_heartbeat_update_ns: init_now,
                debug_state_counter: 0,
                last_idle_debug_publish_ns: init_now,
                last_rx_wake_ns: init_now,
                last_tx_wake_ns: init_now,
                empty_rx_polls: 0,
            },
            last_learned_neighbor: None,
            telemetry: WorkerTelemetry::default(),
            tx_counters: WorkerTxCounters {
                pending_direct_tx_packets: 0,
                pending_copy_tx_packets: 0,
                pending_in_place_tx_packets: 0,
                pending_in_place_vlan_push_desc_packets: 0,
                pending_in_place_vlan_pop_desc_packets: 0,
                pending_in_place_vlan_push_no_headroom_packets: 0,
                pending_in_place_l2_memmove_fallback_packets: 0,
                pending_direct_tx_no_frame_fallback_packets: 0,
                pending_direct_tx_build_fallback_packets: 0,
                pending_direct_tx_disallowed_fallback_packets: 0,
            },
            flow: WorkerFlowCacheState {
                flow_cache: FlowCache::new(),
                flow_cache_session_touch: 0,
            },
            mirror_sample_counter: 0,
            bind_meta: WorkerBindMeta {
                bind_time_ns: {
                    let mut ts = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    };
                    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
                    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
                },
                bind_mode,
                xsk_rx_confirmed: false,
            },
        };
        if register_xsk_now {
            register_binding_xsk(&binding, xsk_map_fd)?;
        }
        update_binding_debug_state(&mut binding);
        Ok(binding)
    }

    #[cfg(test)]
    pub(in crate::afxdp) fn new_for_cos_drain_test(
        slot: u32,
        worker_id: u32,
        root_ifindex: i32,
        root: CoSInterfaceRuntime,
        fast_path: WorkerCoSInterfaceFastPath,
    ) -> Self {
        let ring_entries = 64;
        let total_frames = 64;
        let live = Arc::new(BindingLiveState::new());
        live.set_bound(-1);
        live.set_bind_mode(XskBindMode::Copy);
        live.set_socket_binding(root_ifindex, 0, 0);
        live.set_max_pending_tx(pending_tx_capacity(ring_entries));
        live.umem_total_frames
            .store(total_frames, std::sync::atomic::Ordering::Relaxed);
        live.tx_ring_capacity
            .store(ring_entries, std::sync::atomic::Ordering::Relaxed);

        let mut cos_interfaces = FastMap::default();
        let cos_nonempty_interfaces = usize::from(root.nonempty_queues > 0);
        cos_interfaces.insert(root_ifindex, root);
        let mut cos_fast_interfaces = FastMap::default();
        cos_fast_interfaces.insert(root_ifindex, fast_path);
        let init_now = monotonic_nanos();
        Self {
            slot,
            queue_id: 0,
            worker_id,
            interface: Arc::<str>::from("test0"),
            ifindex: root_ifindex,
            live,
            user: User::new_for_test(-1),
            xsk: WorkerXskRings {
                device: crate::xsk_ffi::DeviceQueue::new_for_test(-1, ring_entries),
                rx: crate::xsk_ffi::RingRx::new_for_test(-1, ring_entries),
                tx: crate::xsk_ffi::RingTx::new_for_test(-1, ring_entries),
            },
            umem: WorkerUmem::new_for_test(total_frames).expect("test worker umem"),
            tx_pipeline: WorkerTxPipeline {
                free_tx_frames: (0..total_frames)
                    .map(|idx| (idx as u64) << UMEM_FRAME_SHIFT)
                    .collect(),
                pending_tx_prepared: VecDeque::new(),
                pending_tx_local: VecDeque::new(),
                max_pending_tx: pending_tx_capacity(ring_entries),
                outstanding_tx: 0,
                pending_fill_frames: VecDeque::new(),
                in_flight_prepared_recycles: FastMap::default(),
                tx_submit_ns: vec![TX_SIDECAR_UNSTAMPED; total_frames as usize].into_boxed_slice(),
            },
            cos: WorkerCos {
                cos_fast_interfaces,
                cos_interfaces,
                cos_interface_order: vec![root_ifindex],
                cos_interface_rr: 0,
                cos_nonempty_interfaces,
                cos_queue_lease_acquire_v8_calls: 0,
                cos_queue_lease_acquire_v8_granted_bytes: 0,
            },
            scratch: WorkerScratch {
                scratch_recycle: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_forwards: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_fill: Vec::with_capacity(FILL_BATCH_SIZE),
                scratch_prepared_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_local_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_exact_prepared_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_exact_local_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_completed_offsets: Vec::with_capacity(ring_entries as usize),
                scratch_post_recycles: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_cross_binding_tx: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_rst_teardowns: Vec::with_capacity(16),
            },
            pending_neigh: VecDeque::new(),
            bpf_maps: WorkerBpfMaps {
                heartbeat_map_fd: -1,
                session_map_fd: -1,
                conntrack_v4_fd: -1,
                conntrack_v6_fd: -1,
            },
            timers: WorkerTimers {
                last_heartbeat_update_ns: init_now,
                debug_state_counter: 0,
                last_idle_debug_publish_ns: init_now,
                last_rx_wake_ns: init_now,
                last_tx_wake_ns: init_now,
                empty_rx_polls: 0,
            },
            last_learned_neighbor: None,
            telemetry: WorkerTelemetry::default(),
            tx_counters: WorkerTxCounters {
                pending_direct_tx_packets: 0,
                pending_copy_tx_packets: 0,
                pending_in_place_tx_packets: 0,
                pending_in_place_vlan_push_desc_packets: 0,
                pending_in_place_vlan_pop_desc_packets: 0,
                pending_in_place_vlan_push_no_headroom_packets: 0,
                pending_in_place_l2_memmove_fallback_packets: 0,
                pending_direct_tx_no_frame_fallback_packets: 0,
                pending_direct_tx_build_fallback_packets: 0,
                pending_direct_tx_disallowed_fallback_packets: 0,
            },
            flow: WorkerFlowCacheState {
                flow_cache: FlowCache::new(),
                flow_cache_session_touch: 0,
            },
            mirror_sample_counter: 0,
            bind_meta: WorkerBindMeta {
                bind_time_ns: init_now,
                bind_mode: XskBindMode::Copy,
                xsk_rx_confirmed: false,
            },
        }
    }

    #[cfg(test)]
    pub(in crate::afxdp) fn new_for_mirror_test(
        slot: u32,
        worker_id: u32,
        ifindex: i32,
        queue_id: u32,
    ) -> Self {
        let ring_entries = 128;
        let total_frames = 256;
        let live = Arc::new(BindingLiveState::new());
        live.set_bound(-1);
        live.set_bind_mode(XskBindMode::Copy);
        live.set_socket_binding(ifindex, queue_id, 0);
        live.set_max_pending_tx(pending_tx_capacity(ring_entries));
        live.umem_total_frames
            .store(total_frames, std::sync::atomic::Ordering::Relaxed);
        live.tx_ring_capacity
            .store(ring_entries, std::sync::atomic::Ordering::Relaxed);
        let init_now = monotonic_nanos();
        Self {
            slot,
            queue_id,
            worker_id,
            interface: Arc::<str>::from("mirror-test"),
            ifindex,
            live,
            user: User::new_for_test(-1),
            xsk: WorkerXskRings {
                device: crate::xsk_ffi::DeviceQueue::new_for_test(-1, ring_entries),
                rx: crate::xsk_ffi::RingRx::new_for_test(-1, ring_entries),
                tx: crate::xsk_ffi::RingTx::new_for_test(-1, ring_entries),
            },
            umem: WorkerUmem::new_for_test(total_frames).expect("test worker umem"),
            tx_pipeline: WorkerTxPipeline {
                free_tx_frames: (0..total_frames)
                    .map(|idx| (idx as u64) << UMEM_FRAME_SHIFT)
                    .collect(),
                pending_tx_prepared: VecDeque::new(),
                pending_tx_local: VecDeque::new(),
                max_pending_tx: pending_tx_capacity(ring_entries),
                outstanding_tx: 0,
                pending_fill_frames: VecDeque::new(),
                in_flight_prepared_recycles: FastMap::default(),
                tx_submit_ns: vec![TX_SIDECAR_UNSTAMPED; total_frames as usize].into_boxed_slice(),
            },
            cos: WorkerCos {
                cos_fast_interfaces: FastMap::default(),
                cos_interfaces: FastMap::default(),
                cos_interface_order: Vec::new(),
                cos_interface_rr: 0,
                cos_nonempty_interfaces: 0,
                cos_queue_lease_acquire_v8_calls: 0,
                cos_queue_lease_acquire_v8_granted_bytes: 0,
            },
            scratch: WorkerScratch {
                scratch_recycle: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_forwards: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_fill: Vec::with_capacity(FILL_BATCH_SIZE),
                scratch_prepared_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_local_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_exact_prepared_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_exact_local_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_completed_offsets: Vec::with_capacity(ring_entries as usize),
                scratch_post_recycles: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_cross_binding_tx: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_rst_teardowns: Vec::with_capacity(16),
            },
            pending_neigh: VecDeque::new(),
            bpf_maps: WorkerBpfMaps {
                heartbeat_map_fd: -1,
                session_map_fd: -1,
                conntrack_v4_fd: -1,
                conntrack_v6_fd: -1,
            },
            timers: WorkerTimers {
                last_heartbeat_update_ns: init_now,
                debug_state_counter: 0,
                last_idle_debug_publish_ns: init_now,
                last_rx_wake_ns: init_now,
                last_tx_wake_ns: init_now,
                empty_rx_polls: 0,
            },
            last_learned_neighbor: None,
            telemetry: WorkerTelemetry::default(),
            tx_counters: WorkerTxCounters {
                pending_direct_tx_packets: 0,
                pending_copy_tx_packets: 0,
                pending_in_place_tx_packets: 0,
                pending_in_place_vlan_push_desc_packets: 0,
                pending_in_place_vlan_pop_desc_packets: 0,
                pending_in_place_vlan_push_no_headroom_packets: 0,
                pending_in_place_l2_memmove_fallback_packets: 0,
                pending_direct_tx_no_frame_fallback_packets: 0,
                pending_direct_tx_build_fallback_packets: 0,
                pending_direct_tx_disallowed_fallback_packets: 0,
            },
            flow: WorkerFlowCacheState {
                flow_cache: FlowCache::new(),
                flow_cache_session_touch: 0,
            },
            mirror_sample_counter: 0,
            bind_meta: WorkerBindMeta {
                bind_time_ns: init_now,
                bind_mode: XskBindMode::Copy,
                xsk_rx_confirmed: false,
            },
        }
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

fn register_binding_xsk(
    binding: &BindingWorker,
    xsk_map_fd: c_int,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let user_fd = binding.user.as_raw_fd();
    if let Err(err) = register_xsk_slot(xsk_map_fd, binding.slot, user_fd) {
        eprintln!(
            "xpf-userspace-dp: ERROR register_xsk_slot slot={} fd={}: {}",
            binding.slot, user_fd, err,
        );
        binding.live.clear_socket_state();
        binding.live.set_error(format!("register XSK slot: {err}"));
        return Err(format!("register XSK slot {} fd {}: {err}", binding.slot, user_fd).into());
    }
    eprintln!(
        "xpf-userspace-dp: registered slot={} fd={} in XSKMAP",
        binding.slot, user_fd,
    );
    binding.live.set_xsk_registered(true);
    binding.live.clear_error();
    Ok(())
}

fn xsk_role_for_shared_plan(plan: &SharedUmemBindingPlan) -> XskSocketRole {
    match plan.socket_role {
        SharedUmemSocketRole::Private => XskSocketRole::Private,
        SharedUmemSocketRole::Owner => XskSocketRole::SharedOwner,
        SharedUmemSocketRole::Secondary => XskSocketRole::SharedSecondary,
    }
}

fn partition_binding_plans(
    binding_plans: Vec<BindingPlan>,
) -> (Vec<BindingPlan>, BTreeMap<String, Vec<BindingPlan>>) {
    let mut private = Vec::new();
    let mut shared = BTreeMap::new();
    for plan in binding_plans {
        if plan.shared_umem.is_shared() {
            shared
                .entry(plan.shared_umem.group_key.clone())
                .or_insert_with(Vec::new)
                .push(plan);
        } else {
            private.push(plan);
        }
    }
    (private, shared)
}

fn publish_plan_shared_umem_status(live: &BindingLiveState, status: &BindingStatus) {
    live.set_shared_umem_status(
        status.shared_umem_mode.clone(),
        status.shared_umem_group.clone(),
        status.shared_umem_socket_role.clone(),
        status.shared_umem_disabled_reason.clone(),
    );
}

fn shared_umem_socket_role_for_xsk_role(socket_role: XskSocketRole) -> SharedUmemSocketRole {
    match socket_role {
        XskSocketRole::Private => SharedUmemSocketRole::Private,
        XskSocketRole::SharedOwner => SharedUmemSocketRole::Owner,
        XskSocketRole::SharedSecondary => SharedUmemSocketRole::Secondary,
    }
}

fn prepare_shared_binding_plan_for_create(
    group_key: &str,
    mut plan: BindingPlan,
    socket_role: XskSocketRole,
) -> BindingPlan {
    let planned_role = xsk_role_for_shared_plan(&plan.shared_umem);
    let actual_role = shared_umem_socket_role_for_xsk_role(socket_role);
    if plan.shared_umem.socket_role != actual_role {
        eprintln!(
            "xpf-userspace-dp: shared UMEM group {group_key} corrected planned role for slot={} from {} to {}",
            plan.status.slot,
            planned_role.describe(),
            socket_role.describe(),
        );
        plan.shared_umem = SharedUmemBindingPlan::shared(
            plan.shared_umem.mode,
            plan.shared_umem.group_key.clone(),
            actual_role,
        );
        publish_shared_umem_plan_to_binding_status(&mut plan.status, &plan.shared_umem);
    }
    publish_plan_shared_umem_status(&plan.live, &plan.status);
    plan
}

fn create_private_binding_from_plan(
    plan: BindingPlan,
) -> Result<BindingWorker, Box<dyn std::error::Error + Send + Sync>> {
    publish_plan_shared_umem_status(&plan.live, &plan.status);
    let driver_name = interface_driver_name(&plan.status.interface);
    let total_frames =
        binding_frame_count_for_driver(driver_name.as_deref(), plan.ring_entries).max(1);
    match WorkerUmemPool::new(total_frames).map_err(|err| format!("create binding umem: {err}")) {
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
            XskSocketRole::Private,
            plan.poll_mode,
            umem,
            &mut free_frames,
            false,
            true,
        ),
        Err(err) => Err(err.to_string().into()),
    }
}

struct SharedGroupBindError {
    group_key: String,
    plans: Vec<BindingPlan>,
    reason: String,
}

impl SharedGroupBindError {
    fn new(group_key: &str, plans: Vec<BindingPlan>, reason: String) -> Self {
        Self {
            group_key: group_key.to_string(),
            plans,
            reason,
        }
    }
}

impl std::fmt::Display for SharedGroupBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "shared UMEM group {} failed: {}",
            self.group_key, self.reason
        )
    }
}

impl std::fmt::Debug for SharedGroupBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedGroupBindError")
            .field("group_key", &self.group_key)
            .field("plan_count", &self.plans.len())
            .field("reason", &self.reason)
            .finish()
    }
}

impl std::error::Error for SharedGroupBindError {}

fn create_shared_binding_group(
    group_key: &str,
    mut plans: Vec<BindingPlan>,
) -> Result<Vec<BindingWorker>, SharedGroupBindError> {
    plans.sort_by_key(|plan| (plan.status.queue_id, plan.status.ifindex, plan.status.slot));
    let group_lives = plans
        .iter()
        .map(|plan| plan.live.clone())
        .collect::<Vec<_>>();
    let total_frames = plans.iter().fold(0u32, |acc, plan| {
        let driver_name = interface_driver_name(&plan.status.interface);
        acc.saturating_add(
            binding_frame_count_for_driver(driver_name.as_deref(), plan.ring_entries).max(1),
        )
    });
    let WorkerUmemPool {
        umem,
        mut free_frames,
    } = WorkerUmemPool::new(total_frames).map_err(|err| {
        SharedGroupBindError::new(group_key, plans.clone(), format!("create UMEM: {err}"))
    })?;

    let mut created: Vec<(BindingWorker, c_int)> = Vec::with_capacity(plans.len());
    for plan in plans.iter().cloned() {
        let socket_role = if created.is_empty() {
            XskSocketRole::SharedOwner
        } else {
            XskSocketRole::SharedSecondary
        };
        let plan = prepare_shared_binding_plan_for_create(group_key, plan, socket_role);
        match BindingWorker::create(
            &plan.status,
            plan.ring_entries,
            plan.xsk_map_fd,
            plan.heartbeat_map_fd,
            plan.session_map_fd,
            plan.conntrack_v4_fd,
            plan.conntrack_v6_fd,
            plan.live.clone(),
            plan.bind_strategy,
            socket_role,
            plan.poll_mode,
            umem.clone(),
            &mut free_frames,
            true,
            false,
        ) {
            Ok(binding) => created.push((binding, plan.xsk_map_fd)),
            Err(err) => {
                let msg = format!("shared UMEM group {group_key} bind failed: {err}");
                for live in &group_lives {
                    live.clear_socket_state();
                    live.set_error(msg.clone());
                }
                return Err(SharedGroupBindError::new(group_key, plans, msg));
            }
        }
    }

    let mut registered = Vec::new();
    for (binding, xsk_map_fd) in &created {
        if let Err(err) = register_binding_xsk(binding, *xsk_map_fd) {
            let msg = format!("shared UMEM group {group_key} XSKMAP registration failed: {err}");
            for (map_fd, slot) in registered {
                let _ = delete_xsk_slot(map_fd, slot);
            }
            for live in &group_lives {
                live.clear_socket_state();
                live.set_error(msg.clone());
            }
            return Err(SharedGroupBindError::new(group_key, plans, msg));
        }
        registered.push((*xsk_map_fd, binding.slot));
    }

    Ok(created.into_iter().map(|(binding, _)| binding).collect())
}

fn fallback_shared_group_to_private(err: SharedGroupBindError, bindings: &mut Vec<BindingWorker>) {
    let SharedGroupBindError {
        group_key,
        plans,
        reason,
    } = err;
    let fallback_reason =
        format!("shared UMEM group {group_key} failed; using private UMEM: {reason}");
    eprintln!("xpf-userspace-dp: {fallback_reason}");
    for mut plan in plans {
        let live = plan.live.clone();
        let mode = plan.shared_umem.mode;
        plan.shared_umem = SharedUmemBindingPlan::disabled(mode, fallback_reason.clone());
        publish_shared_umem_plan_to_binding_status(&mut plan.status, &plan.shared_umem);
        match create_private_binding_from_plan(plan) {
            Ok(binding) => bindings.push(binding),
            Err(err) => {
                let msg = format!("private fallback after shared UMEM failure failed: {err}");
                eprintln!("xpf-userspace-dp: {msg}");
                live.set_error(msg);
            }
        }
    }
}

/// #1188: replace per-tick `.load_full() + Arc::ptr_eq` with `.load() +
/// Arc::ptr_eq` short-circuit. Returns `Some(new_arc)` when the
/// `ArcSwap` has been rotated since `cached` was observed; returns
/// `None` when the cached Arc is still current.
///
/// Steady state (no rotation): the `Arc::ptr_eq` short-circuit avoids
/// the unconditional Arc clone that `.load_full()` performs. At ~10K-
/// 100K worker ticks/sec × 8 workers, this eliminates ~12 atomic RMW
/// operations per tick (6 sites × 2 ops for clone + drop) on the
/// shared Arc control blocks — the bus-saturation issue the ticket
/// describes.
///
/// On actual change: `Guard::into_inner` consumes the observed Guard
/// and yields the exact Arc snapshot we just compared, avoiding a
/// second `.load_full()` (which could otherwise return a *newer* Arc
/// if the coordinator rotated between the `ptr_eq` check and the
/// second load — small TOCTOU window). Note: `load_full()` is itself
/// implemented as `Guard::into_inner(self.load())` (arc-swap 1.8.2
/// `src/lib.rs:414`), so the on-change branch may pay the same as
/// today. The win is the steady-state short-circuit, not the
/// on-change path.
#[inline]
fn load_arc_if_changed<T>(cached: &Arc<T>, shared: &ArcSwap<T>) -> Option<Arc<T>> {
    let guard = shared.load();
    if Arc::ptr_eq(cached, &*guard) {
        None
    } else {
        Some(arc_swap::Guard::into_inner(guard))
    }
}

#[inline]
fn refresh_worker_cos_queue_lease_runtime_counters(
    counters: &mut super::worker_runtime::WorkerRuntimeCounters,
    bindings: &[BindingWorker],
) {
    let mut calls = 0u64;
    let mut granted_bytes = 0u64;
    for binding in bindings {
        calls = calls.wrapping_add(binding.cos.cos_queue_lease_acquire_v8_calls);
        granted_bytes =
            granted_bytes.wrapping_add(binding.cos.cos_queue_lease_acquire_v8_granted_bytes);
    }
    counters.cos_queue_lease_acquire_v8_calls = calls;
    counters.cos_queue_lease_acquire_v8_granted_bytes = granted_bytes;
}

mod loop_body;
pub(crate) use loop_body::worker_loop;


fn apply_worker_shaped_tx_requests(
    bindings: &mut [BindingWorker],
    forwarding: &ForwardingState,
    binding_lookup: &WorkerBindingLookup,
    now_ns: u64,
    requests: Vec<TxRequest>,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    for req in requests {
        let binding_index = bindings
            .first()
            .and_then(|binding| binding.cos.cos_fast_interfaces.get(&req.egress_ifindex))
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
        match enqueue_local_into_cos(
            binding,
            forwarding,
            req,
            now_ns,
            Some(&mut *shared_recycles),
        ) {
            Ok(()) => {}
            Err(req) => {
                binding.tx_pipeline.pending_tx_local.push_back(req);
                bound_pending_tx_local(binding);
            }
        }
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

fn publish_tx_completion_ring_telemetry(live: &BindingLiveState, telemetry: &mut WorkerTelemetry) {
    // #1241: publish owner-local AF_XDP TX completion-ring availability
    // samples on the same low-frequency debug cadence as the existing
    // ring-pressure gauges. These are gauges, not counters: current is
    // the last sampled CQ depth before a reap, max is the peak in this
    // debug window. Reset happens only after both stores so current and
    // max are published from the same telemetry window; a future reorder
    // must not clear either local sample before both live gauges are
    // updated.
    live.tx_completion_ring_available.store(
        telemetry.dbg_tx_completion_ring_available,
        Ordering::Relaxed,
    );
    live.tx_completion_ring_available_max.store(
        telemetry.dbg_tx_completion_ring_available_max,
        Ordering::Relaxed,
    );
    telemetry.dbg_tx_completion_ring_available = 0;
    telemetry.dbg_tx_completion_ring_available_max = 0;
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
    pub(crate) shared_umem_mode: String,
    pub(crate) shared_umem_group: String,
    pub(crate) shared_umem_socket_role: String,
    pub(crate) shared_umem_disabled_reason: String,
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
    /// #1219: snapshot count of distinct active flows on this binding's
    /// flow_cache (refreshed at the ~65ms debug-state tick).
    pub(crate) active_flow_count: u32,
    /// Rust-owned per-binding flow-cache capacity.
    pub(crate) flow_cache_capacity: u32,
    /// #941 Work item D: count of V_min hard-cap activations on this
    /// binding (per `update_binding_debug_state` flush of each queue's
    /// scratch counter). Acceptance gate: under normal load, the
    /// override-rate (this / `drain_invocations` aggregated across
    /// queues) stays below 5 %.
    pub(crate) v_min_throttle_hard_cap_overrides: u64,
    /// #943: regular V_min throttle decisions on this binding (i.e.
    /// `cos_queue_v_min_continue` returned `false` and the drain
    /// loop early-broke). Counted distinctly from hard-cap overrides
    /// so operators can tell the fairness brake is engaged from the
    /// escape-hatch firing.
    pub(crate) v_min_throttles: u64,
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
    /// #1374: SYN-cookie challenge decisions selected by userspace screen
    /// runtime.
    pub(crate) syn_cookie_challenges: u64,
    pub(crate) syn_cookie_secret_unavailable: u64,
    pub(crate) syn_cookie_syn_ack_sent: u64,
    pub(crate) syn_cookie_ack_rst_sent: u64,
    pub(crate) syn_cookie_reply_budget_drops: u64,
    pub(crate) syn_cookie_ack_valid: u64,
    pub(crate) syn_cookie_ack_invalid: u64,
    pub(crate) syn_cookie_bypass: u64,
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
    pub(crate) tx_shared_recycle_unknown_slot_drops: u64,
    pub(crate) redirect_inbox_overflow_drops: u64,
    pub(crate) pending_tx_local_overflow_drops: u64,
    pub(crate) tx_submit_error_drops: u64,
    pub(crate) mirrored_packets: u64,
    pub(crate) mirrored_bytes: u64,
    pub(crate) mirror_drops_no_frame: u64,
    pub(crate) mirror_drops_tx_frame_reserve: u64,
    pub(crate) mirror_drops_no_binding: u64,
    pub(crate) mirror_drops_queue_full: u64,
    pub(crate) mirror_drops_queue_full_same_worker: u64,
    pub(crate) mirror_drops_queue_full_cross_worker: u64,
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
    pub(crate) in_place_vlan_push_desc_packets: u64,
    pub(crate) in_place_vlan_pop_desc_packets: u64,
    pub(crate) in_place_vlan_push_no_headroom_packets: u64,
    pub(crate) in_place_l2_memmove_fallback_packets: u64,
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
    /// #1241: last sampled AF_XDP TX completion-ring availability
    /// before the owner worker drained completions.
    pub(crate) tx_completion_ring_available: u32,
    /// #1241: maximum sampled completion-ring availability in the
    /// last debug window.
    pub(crate) tx_completion_ring_available_max: u32,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_binding_plan_create_publishes_live_status() {
        let live = Arc::new(BindingLiveState::new());
        let group = "cross-nic:w0:ge-0-0-1,ge-0-0-2".to_string();
        let shared = SharedUmemBindingPlan::shared(
            SharedUmemMode::CrossNic,
            group.clone(),
            SharedUmemSocketRole::Secondary,
        );
        let mut status = BindingStatus {
            slot: 1,
            queue_id: 0,
            worker_id: 0,
            interface: "ge-0-0-2".to_string(),
            ifindex: 6,
            ..Default::default()
        };
        publish_shared_umem_plan_to_binding_status(&mut status, &shared);
        let plan = BindingPlan {
            status,
            live: live.clone(),
            xsk_map_fd: -1,
            heartbeat_map_fd: -1,
            session_map_fd: -1,
            conntrack_v4_fd: -1,
            conntrack_v6_fd: -1,
            ring_entries: 2048,
            bind_strategy: AfXdpBindStrategy::UmemOwnerSocket,
            poll_mode: crate::PollMode::Interrupt,
            shared_umem: shared,
        };

        let plan = prepare_shared_binding_plan_for_create(&group, plan, XskSocketRole::SharedOwner);
        let snap = live.snapshot();

        assert_eq!(plan.status.shared_umem_mode, "cross-nic");
        assert_eq!(plan.status.shared_umem_group, group);
        assert_eq!(plan.status.shared_umem_socket_role, "owner");
        assert_eq!(snap.shared_umem_mode, "cross-nic");
        assert_eq!(snap.shared_umem_group, plan.status.shared_umem_group);
        assert_eq!(snap.shared_umem_socket_role, "owner");
        assert_eq!(snap.shared_umem_disabled_reason, "");
    }

    #[test]
    fn publish_tx_completion_ring_telemetry_stores_before_reset() {
        let live = BindingLiveState::new();
        let mut telemetry = WorkerTelemetry {
            dbg_tx_completion_ring_available: 5,
            dbg_tx_completion_ring_available_max: 9,
            ..Default::default()
        };

        publish_tx_completion_ring_telemetry(&live, &mut telemetry);

        assert_eq!(live.tx_completion_ring_available.load(Ordering::Relaxed), 5);
        assert_eq!(
            live.tx_completion_ring_available_max
                .load(Ordering::Relaxed),
            9
        );
        assert_eq!(telemetry.dbg_tx_completion_ring_available, 0);
        assert_eq!(telemetry.dbg_tx_completion_ring_available_max, 0);
    }
}
