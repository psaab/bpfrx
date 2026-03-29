use super::*;

pub(super) struct WorkerUmemInner {
    area: MmapArea,
    umem: Umem,
    total_frames: u32,
}

impl WorkerUmemInner {
    fn umem_mut(&mut self) -> &mut Umem {
        &mut self.umem
    }
}

#[derive(Clone)]
pub(super) struct WorkerUmem {
    inner: Rc<WorkerUmemInner>,
}

impl WorkerUmem {
    pub(super) fn new(total_frames: u32) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let area = MmapArea::new((total_frames as usize) * (UMEM_FRAME_SIZE as usize))?;
        let ring_size = umem_ring_size(total_frames);
        let umem_cfg = UmemConfig {
            fill_size: ring_size,
            complete_size: ring_size,
            frame_size: UMEM_FRAME_SIZE,
            headroom: UMEM_HEADROOM,
            flags: 0,
        };
        let umem = unsafe { Umem::new(umem_cfg, area.as_nonnull_slice()) }
            .map_err(|e| format!("create umem: {e}"))?;
        Ok(Self {
            inner: Rc::new(WorkerUmemInner {
                area,
                umem,
                total_frames,
            }),
        })
    }

    pub(super) fn area(&self) -> &MmapArea {
        &self.inner.area
    }

    pub(super) fn umem(&self) -> &Umem {
        &self.inner.umem
    }

    pub(super) fn umem_mut(&mut self) -> &mut Umem {
        Rc::get_mut(&mut self.inner)
            .expect("single-owner umem")
            .umem_mut()
    }

    pub(super) fn total_frames(&self) -> u32 {
        self.inner.total_frames
    }

    pub(super) fn shares_allocation_with(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }

    pub(super) fn allocation_ptr(&self) -> *const WorkerUmemInner {
        Rc::as_ptr(&self.inner)
    }
}

pub(super) struct WorkerUmemPool {
    pub(super) umem: WorkerUmem,
    pub(super) free_frames: VecDeque<u64>,
}

impl WorkerUmemPool {
    pub(super) fn new(total_frames: u32) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let umem = WorkerUmem::new(total_frames.max(1))?;
        let mut free_frames = VecDeque::with_capacity(total_frames.max(1) as usize);
        for idx in 0..total_frames.max(1) {
            if let Some(frame) = umem.umem().frame(BufIdx(idx)) {
                free_frames.push_back(frame.offset);
            }
        }
        Ok(Self { umem, free_frames })
    }
}

pub(super) struct MmapArea {
    ptr: NonNull<u8>,
    len: usize,
}

impl MmapArea {
    pub(super) fn new(len: usize) -> io::Result<Self> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr =
            NonNull::new(ptr.cast::<u8>()).ok_or_else(|| io::Error::other("null mmap pointer"))?;
        Ok(Self { ptr, len })
    }

    pub(super) fn as_nonnull_slice(&self) -> NonNull<[u8]> {
        NonNull::from(unsafe {
            &mut *std::ptr::slice_from_raw_parts_mut(self.ptr.as_ptr(), self.len)
        })
    }

    pub(super) fn slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let end = offset.checked_add(len)?;
        if end > self.len {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().add(offset), len) })
    }

    pub(super) fn slice_mut(&mut self, offset: usize, len: usize) -> Option<&mut [u8]> {
        unsafe { self.slice_mut_unchecked(offset, len) }
    }

    pub(super) unsafe fn slice_mut_unchecked(
        &self,
        offset: usize,
        len: usize,
    ) -> Option<&mut [u8]> {
        let end = offset.checked_add(len)?;
        if end > self.len {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr().add(offset), len) })
    }
}

impl Drop for MmapArea {
    fn drop(&mut self) {
        let _ = unsafe { libc::munmap(self.ptr.as_ptr().cast::<c_void>(), self.len) };
    }
}

/// Raw ring state: (rxP, rxC, frP, frC, txP, txC, crP, crC)
pub(super) struct BindingLiveState {
    pub(super) bound: AtomicBool,
    pub(super) xsk_registered: AtomicBool,
    pub(super) bind_mode: AtomicU8,
    pub(super) socket_fd: AtomicI32,
    pub(super) socket_ifindex: AtomicI32,
    pub(super) socket_queue_id: AtomicU32,
    pub(super) socket_bind_flags: AtomicU32,
    pub(super) rx_packets: AtomicU64,
    pub(super) rx_bytes: AtomicU64,
    pub(super) rx_batches: AtomicU64,
    pub(super) rx_wakeups: AtomicU64,
    pub(super) metadata_packets: AtomicU64,
    pub(super) metadata_errors: AtomicU64,
    pub(super) validated_packets: AtomicU64,
    pub(super) validated_bytes: AtomicU64,
    pub(super) local_delivery_packets: AtomicU64,
    pub(super) forward_candidate_packets: AtomicU64,
    pub(super) route_miss_packets: AtomicU64,
    pub(super) neighbor_miss_packets: AtomicU64,
    pub(super) discard_route_packets: AtomicU64,
    pub(super) next_table_packets: AtomicU64,
    pub(super) exception_packets: AtomicU64,
    pub(super) config_gen_mismatches: AtomicU64,
    pub(super) fib_gen_mismatches: AtomicU64,
    pub(super) unsupported_packets: AtomicU64,
    pub(super) flow_cache_hits: AtomicU64,
    pub(super) flow_cache_misses: AtomicU64,
    pub(super) flow_cache_evictions: AtomicU64,
    pub(super) session_hits: AtomicU64,
    pub(super) session_misses: AtomicU64,
    pub(super) session_creates: AtomicU64,
    pub(super) session_expires: AtomicU64,
    pub(super) session_delta_generated: AtomicU64,
    pub(super) session_delta_dropped: AtomicU64,
    pub(super) session_delta_drained: AtomicU64,
    pub(super) policy_denied_packets: AtomicU64,
    pub(super) screen_drops: AtomicU64,
    pub(super) snat_packets: AtomicU64,
    pub(super) dnat_packets: AtomicU64,
    pub(super) slow_path_packets: AtomicU64,
    pub(super) slow_path_bytes: AtomicU64,
    pub(super) slow_path_local_delivery_packets: AtomicU64,
    pub(super) slow_path_missing_neighbor_packets: AtomicU64,
    pub(super) slow_path_no_route_packets: AtomicU64,
    pub(super) slow_path_next_table_packets: AtomicU64,
    pub(super) slow_path_forward_build_packets: AtomicU64,
    pub(super) slow_path_drops: AtomicU64,
    pub(super) slow_path_rate_limited: AtomicU64,
    pub(super) kernel_rx_dropped: AtomicU64,
    pub(super) kernel_rx_invalid_descs: AtomicU64,
    pub(super) tx_packets: AtomicU64,
    pub(super) tx_bytes: AtomicU64,
    pub(super) tx_completions: AtomicU64,
    pub(super) tx_errors: AtomicU64,
    pub(super) direct_tx_packets: AtomicU64,
    pub(super) copy_tx_packets: AtomicU64,
    pub(super) in_place_tx_packets: AtomicU64,
    pub(super) direct_tx_no_frame_fallback_packets: AtomicU64,
    pub(super) direct_tx_build_fallback_packets: AtomicU64,
    pub(super) direct_tx_disallowed_fallback_packets: AtomicU64,
    pub(super) debug_pending_fill_frames: AtomicU32,
    pub(super) debug_spare_fill_frames: AtomicU32,
    pub(super) debug_free_tx_frames: AtomicU32,
    pub(super) debug_pending_tx_prepared: AtomicU32,
    pub(super) debug_pending_tx_local: AtomicU32,
    pub(super) debug_outstanding_tx: AtomicU32,
    pub(super) debug_in_flight_recycles: AtomicU32,
    pub(super) last_heartbeat: AtomicU64,
    pub(super) max_pending_tx: AtomicU32,
    pub(super) pending_tx_len: AtomicU32,
    pub(super) last_error: Mutex<String>,
    pub(super) pending_tx: Mutex<VecDeque<TxRequest>>,
    pub(super) pending_session_deltas: Mutex<VecDeque<SessionDeltaInfo>>,
}

impl BindingLiveState {
    pub(super) fn new() -> Self {
        Self {
            bound: AtomicBool::new(false),
            xsk_registered: AtomicBool::new(false),
            bind_mode: AtomicU8::new(XskBindMode::Unknown.as_u8()),
            socket_fd: AtomicI32::new(0),
            socket_ifindex: AtomicI32::new(0),
            socket_queue_id: AtomicU32::new(0),
            socket_bind_flags: AtomicU32::new(0),
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            rx_batches: AtomicU64::new(0),
            rx_wakeups: AtomicU64::new(0),
            metadata_packets: AtomicU64::new(0),
            metadata_errors: AtomicU64::new(0),
            validated_packets: AtomicU64::new(0),
            validated_bytes: AtomicU64::new(0),
            local_delivery_packets: AtomicU64::new(0),
            forward_candidate_packets: AtomicU64::new(0),
            route_miss_packets: AtomicU64::new(0),
            neighbor_miss_packets: AtomicU64::new(0),
            discard_route_packets: AtomicU64::new(0),
            next_table_packets: AtomicU64::new(0),
            exception_packets: AtomicU64::new(0),
            config_gen_mismatches: AtomicU64::new(0),
            fib_gen_mismatches: AtomicU64::new(0),
            unsupported_packets: AtomicU64::new(0),
            flow_cache_hits: AtomicU64::new(0),
            flow_cache_misses: AtomicU64::new(0),
            flow_cache_evictions: AtomicU64::new(0),
            session_hits: AtomicU64::new(0),
            session_misses: AtomicU64::new(0),
            session_creates: AtomicU64::new(0),
            session_expires: AtomicU64::new(0),
            session_delta_generated: AtomicU64::new(0),
            session_delta_dropped: AtomicU64::new(0),
            session_delta_drained: AtomicU64::new(0),
            policy_denied_packets: AtomicU64::new(0),
            screen_drops: AtomicU64::new(0),
            snat_packets: AtomicU64::new(0),
            dnat_packets: AtomicU64::new(0),
            slow_path_packets: AtomicU64::new(0),
            slow_path_bytes: AtomicU64::new(0),
            slow_path_local_delivery_packets: AtomicU64::new(0),
            slow_path_missing_neighbor_packets: AtomicU64::new(0),
            slow_path_no_route_packets: AtomicU64::new(0),
            slow_path_next_table_packets: AtomicU64::new(0),
            slow_path_forward_build_packets: AtomicU64::new(0),
            slow_path_drops: AtomicU64::new(0),
            slow_path_rate_limited: AtomicU64::new(0),
            kernel_rx_dropped: AtomicU64::new(0),
            kernel_rx_invalid_descs: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            tx_completions: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
            direct_tx_packets: AtomicU64::new(0),
            copy_tx_packets: AtomicU64::new(0),
            in_place_tx_packets: AtomicU64::new(0),
            direct_tx_no_frame_fallback_packets: AtomicU64::new(0),
            direct_tx_build_fallback_packets: AtomicU64::new(0),
            direct_tx_disallowed_fallback_packets: AtomicU64::new(0),
            debug_pending_fill_frames: AtomicU32::new(0),
            debug_spare_fill_frames: AtomicU32::new(0),
            debug_free_tx_frames: AtomicU32::new(0),
            debug_pending_tx_prepared: AtomicU32::new(0),
            debug_pending_tx_local: AtomicU32::new(0),
            debug_outstanding_tx: AtomicU32::new(0),
            debug_in_flight_recycles: AtomicU32::new(0),
            last_heartbeat: AtomicU64::new(0),
            max_pending_tx: AtomicU32::new(0),
            pending_tx_len: AtomicU32::new(0),
            last_error: Mutex::new(String::new()),
            pending_tx: Mutex::new(VecDeque::new()),
            pending_session_deltas: Mutex::new(VecDeque::new()),
        }
    }

    pub(super) fn set_bound(&self, socket_fd: c_int) {
        self.bound.store(true, Ordering::Relaxed);
        self.socket_fd.store(socket_fd, Ordering::Relaxed);
    }

    pub(super) fn set_socket_binding(&self, ifindex: i32, queue_id: u32, flags: u32) {
        self.socket_ifindex.store(ifindex, Ordering::Relaxed);
        self.socket_queue_id.store(queue_id, Ordering::Relaxed);
        self.socket_bind_flags.store(flags, Ordering::Relaxed);
    }

    pub(super) fn set_xsk_registered(&self, value: bool) {
        self.xsk_registered.store(value, Ordering::Relaxed);
    }

    pub(super) fn set_bind_mode(&self, mode: XskBindMode) {
        self.bind_mode.store(mode.as_u8(), Ordering::Relaxed);
    }

    pub(super) fn set_last_heartbeat_at(&self, now_ns: u64) {
        self.last_heartbeat.store(now_ns, Ordering::Relaxed);
    }

    pub(super) fn set_max_pending_tx(&self, max_pending: usize) {
        self.max_pending_tx
            .store(max_pending.min(u32::MAX as usize) as u32, Ordering::Relaxed);
    }

    pub(super) fn clear_error(&self) {
        if let Ok(mut err) = self.last_error.lock() {
            err.clear();
        }
    }

    pub(super) fn set_error(&self, msg: String) {
        if let Ok(mut err) = self.last_error.lock() {
            *err = msg;
        }
    }

    pub(super) fn record_slow_path_accept(
        &self,
        disposition: ForwardingDisposition,
        reason: &str,
        packet_len: u64,
    ) {
        self.slow_path_packets.fetch_add(1, Ordering::Relaxed);
        self.slow_path_bytes
            .fetch_add(packet_len, Ordering::Relaxed);
        if reason == "forward_build_slow_path" {
            self.slow_path_forward_build_packets
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        match disposition {
            ForwardingDisposition::LocalDelivery => {
                self.slow_path_local_delivery_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            ForwardingDisposition::MissingNeighbor => {
                self.slow_path_missing_neighbor_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            ForwardingDisposition::NoRoute => {
                self.slow_path_no_route_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            ForwardingDisposition::NextTableUnsupported => {
                self.slow_path_next_table_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub(super) fn snapshot(&self) -> BindingLiveSnapshot {
        let now_wall = Utc::now();
        let now_mono = monotonic_nanos();
        let session_delta_pending = self
            .pending_session_deltas
            .lock()
            .map(|pending| pending.len() as u64)
            .unwrap_or(0);
        BindingLiveSnapshot {
            bound: self.bound.load(Ordering::Relaxed),
            xsk_registered: self.xsk_registered.load(Ordering::Relaxed),
            xsk_bind_mode: XskBindMode::from_u8(self.bind_mode.load(Ordering::Relaxed))
                .as_str()
                .to_string(),
            zero_copy: XskBindMode::from_u8(self.bind_mode.load(Ordering::Relaxed)).is_zerocopy(),
            socket_fd: self.socket_fd.load(Ordering::Relaxed),
            socket_ifindex: self.socket_ifindex.load(Ordering::Relaxed),
            socket_queue_id: self.socket_queue_id.load(Ordering::Relaxed),
            socket_bind_flags: self.socket_bind_flags.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            rx_batches: self.rx_batches.load(Ordering::Relaxed),
            rx_wakeups: self.rx_wakeups.load(Ordering::Relaxed),
            metadata_packets: self.metadata_packets.load(Ordering::Relaxed),
            metadata_errors: self.metadata_errors.load(Ordering::Relaxed),
            validated_packets: self.validated_packets.load(Ordering::Relaxed),
            validated_bytes: self.validated_bytes.load(Ordering::Relaxed),
            local_delivery_packets: self.local_delivery_packets.load(Ordering::Relaxed),
            forward_candidate_packets: self.forward_candidate_packets.load(Ordering::Relaxed),
            route_miss_packets: self.route_miss_packets.load(Ordering::Relaxed),
            neighbor_miss_packets: self.neighbor_miss_packets.load(Ordering::Relaxed),
            discard_route_packets: self.discard_route_packets.load(Ordering::Relaxed),
            next_table_packets: self.next_table_packets.load(Ordering::Relaxed),
            exception_packets: self.exception_packets.load(Ordering::Relaxed),
            config_gen_mismatches: self.config_gen_mismatches.load(Ordering::Relaxed),
            fib_gen_mismatches: self.fib_gen_mismatches.load(Ordering::Relaxed),
            unsupported_packets: self.unsupported_packets.load(Ordering::Relaxed),
            flow_cache_hits: self.flow_cache_hits.load(Ordering::Relaxed),
            flow_cache_misses: self.flow_cache_misses.load(Ordering::Relaxed),
            flow_cache_evictions: self.flow_cache_evictions.load(Ordering::Relaxed),
            session_hits: self.session_hits.load(Ordering::Relaxed),
            session_misses: self.session_misses.load(Ordering::Relaxed),
            session_creates: self.session_creates.load(Ordering::Relaxed),
            session_expires: self.session_expires.load(Ordering::Relaxed),
            session_delta_pending,
            session_delta_generated: self.session_delta_generated.load(Ordering::Relaxed),
            session_delta_dropped: self.session_delta_dropped.load(Ordering::Relaxed),
            session_delta_drained: self.session_delta_drained.load(Ordering::Relaxed),
            policy_denied_packets: self.policy_denied_packets.load(Ordering::Relaxed),
            screen_drops: self.screen_drops.load(Ordering::Relaxed),
            snat_packets: self.snat_packets.load(Ordering::Relaxed),
            dnat_packets: self.dnat_packets.load(Ordering::Relaxed),
            slow_path_packets: self.slow_path_packets.load(Ordering::Relaxed),
            slow_path_bytes: self.slow_path_bytes.load(Ordering::Relaxed),
            slow_path_local_delivery_packets: self
                .slow_path_local_delivery_packets
                .load(Ordering::Relaxed),
            slow_path_missing_neighbor_packets: self
                .slow_path_missing_neighbor_packets
                .load(Ordering::Relaxed),
            slow_path_no_route_packets: self.slow_path_no_route_packets.load(Ordering::Relaxed),
            slow_path_next_table_packets: self.slow_path_next_table_packets.load(Ordering::Relaxed),
            slow_path_forward_build_packets: self
                .slow_path_forward_build_packets
                .load(Ordering::Relaxed),
            slow_path_drops: self.slow_path_drops.load(Ordering::Relaxed),
            slow_path_rate_limited: self.slow_path_rate_limited.load(Ordering::Relaxed),
            kernel_rx_dropped: self.kernel_rx_dropped.load(Ordering::Relaxed),
            kernel_rx_invalid_descs: self.kernel_rx_invalid_descs.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            tx_completions: self.tx_completions.load(Ordering::Relaxed),
            tx_errors: self.tx_errors.load(Ordering::Relaxed),
            direct_tx_packets: self.direct_tx_packets.load(Ordering::Relaxed),
            copy_tx_packets: self.copy_tx_packets.load(Ordering::Relaxed),
            in_place_tx_packets: self.in_place_tx_packets.load(Ordering::Relaxed),
            direct_tx_no_frame_fallback_packets: self
                .direct_tx_no_frame_fallback_packets
                .load(Ordering::Relaxed),
            direct_tx_build_fallback_packets: self
                .direct_tx_build_fallback_packets
                .load(Ordering::Relaxed),
            direct_tx_disallowed_fallback_packets: self
                .direct_tx_disallowed_fallback_packets
                .load(Ordering::Relaxed),
            debug_pending_fill_frames: self.debug_pending_fill_frames.load(Ordering::Relaxed),
            debug_spare_fill_frames: self.debug_spare_fill_frames.load(Ordering::Relaxed),
            debug_free_tx_frames: self.debug_free_tx_frames.load(Ordering::Relaxed),
            debug_pending_tx_prepared: self.debug_pending_tx_prepared.load(Ordering::Relaxed),
            debug_pending_tx_local: self.debug_pending_tx_local.load(Ordering::Relaxed),
            debug_outstanding_tx: self.debug_outstanding_tx.load(Ordering::Relaxed),
            debug_in_flight_recycles: self.debug_in_flight_recycles.load(Ordering::Relaxed),
            last_heartbeat: monotonic_timestamp_to_datetime(
                self.last_heartbeat.load(Ordering::Relaxed),
                now_mono,
                now_wall,
            ),
            last_error: self
                .last_error
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default(),
        }
    }

    pub(super) fn enqueue_tx(&self, req: TxRequest) -> Result<(), String> {
        match self.pending_tx.lock() {
            Ok(mut pending) => {
                let max_pending = self.max_pending_tx.load(Ordering::Relaxed) as usize;
                if max_pending > 0 && pending.len() >= max_pending {
                    if pending.pop_front().is_some() {
                        self.tx_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
                pending.push_back(req);
                self.pending_tx_len.store(
                    pending.len().min(u32::MAX as usize) as u32,
                    Ordering::Relaxed,
                );
                Ok(())
            }
            Err(_) => Err("pending_tx lock poisoned".to_string()),
        }
    }

    pub(super) fn take_pending_tx(&self) -> VecDeque<TxRequest> {
        if self.pending_tx_len.load(Ordering::Relaxed) == 0 {
            return VecDeque::new();
        }
        match self.pending_tx.lock() {
            Ok(mut pending) => {
                let drained = core::mem::take(&mut *pending);
                self.pending_tx_len.store(0, Ordering::Relaxed);
                drained
            }
            Err(_) => VecDeque::new(),
        }
    }

    pub(super) fn pending_tx_empty(&self) -> bool {
        self.pending_tx_len.load(Ordering::Relaxed) == 0
    }

    pub(super) fn push_session_delta(&self, delta: SessionDeltaInfo) {
        self.session_delta_generated.fetch_add(1, Ordering::Relaxed);
        match self.pending_session_deltas.lock() {
            Ok(mut pending) => {
                if pending.len() >= MAX_PENDING_SESSION_DELTAS {
                    self.session_delta_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                pending.push_back(delta);
            }
            Err(_) => {
                self.session_delta_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(super) fn drain_session_deltas(&self, max: usize) -> Vec<SessionDeltaInfo> {
        let drain = max.max(1);
        match self.pending_session_deltas.lock() {
            Ok(mut pending) => {
                let count = drain.min(pending.len());
                let mut out = Vec::with_capacity(count);
                for _ in 0..count {
                    if let Some(delta) = pending.pop_front() {
                        out.push(delta);
                    }
                }
                self.session_delta_drained
                    .fetch_add(out.len() as u64, Ordering::Relaxed);
                out
            }
            Err(_) => Vec::new(),
        }
    }
}

pub(super) fn update_binding_debug_state(binding: &mut BindingWorker) {
    // Use a simple modular counter to avoid 7 atomic stores on every call.
    // At ~1M calls/sec, checking every 65536 calls ~= every 65ms.
    binding.debug_state_counter = binding.debug_state_counter.wrapping_add(1);
    if binding.debug_state_counter & 0xFFFF != 0 {
        return;
    }
    if binding.pending_direct_tx_packets != 0 {
        binding
            .live
            .direct_tx_packets
            .fetch_add(binding.pending_direct_tx_packets, Ordering::Relaxed);
        binding.pending_direct_tx_packets = 0;
    }
    if binding.pending_copy_tx_packets != 0 {
        binding
            .live
            .copy_tx_packets
            .fetch_add(binding.pending_copy_tx_packets, Ordering::Relaxed);
        binding.pending_copy_tx_packets = 0;
    }
    if binding.pending_in_place_tx_packets != 0 {
        binding
            .live
            .in_place_tx_packets
            .fetch_add(binding.pending_in_place_tx_packets, Ordering::Relaxed);
        binding.pending_in_place_tx_packets = 0;
    }
    if binding.pending_direct_tx_no_frame_fallback_packets != 0 {
        binding.live.direct_tx_no_frame_fallback_packets.fetch_add(
            binding.pending_direct_tx_no_frame_fallback_packets,
            Ordering::Relaxed,
        );
        binding.pending_direct_tx_no_frame_fallback_packets = 0;
    }
    if binding.pending_direct_tx_build_fallback_packets != 0 {
        binding.live.direct_tx_build_fallback_packets.fetch_add(
            binding.pending_direct_tx_build_fallback_packets,
            Ordering::Relaxed,
        );
        binding.pending_direct_tx_build_fallback_packets = 0;
    }
    if binding.pending_direct_tx_disallowed_fallback_packets != 0 {
        binding
            .live
            .direct_tx_disallowed_fallback_packets
            .fetch_add(
                binding.pending_direct_tx_disallowed_fallback_packets,
                Ordering::Relaxed,
            );
        binding.pending_direct_tx_disallowed_fallback_packets = 0;
    }
    if binding.flow_cache.hits != 0 {
        binding
            .live
            .flow_cache_hits
            .fetch_add(binding.flow_cache.hits, Ordering::Relaxed);
        binding.flow_cache.hits = 0;
    }
    if binding.flow_cache.misses != 0 {
        binding
            .live
            .flow_cache_misses
            .fetch_add(binding.flow_cache.misses, Ordering::Relaxed);
        binding.flow_cache.misses = 0;
    }
    if binding.flow_cache.evictions != 0 {
        binding
            .live
            .flow_cache_evictions
            .fetch_add(binding.flow_cache.evictions, Ordering::Relaxed);
        binding.flow_cache.evictions = 0;
    }
}
