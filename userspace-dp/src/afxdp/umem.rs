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

    #[cfg_attr(not(test), allow(dead_code))]
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
    /// Original requested size (passed to XSK via as_nonnull_slice).
    len: usize,
    /// Actual mmap size (may be rounded up for hugepage alignment).
    mapped_len: usize,
    /// Whether the region is backed by explicit 2 MB hugepages.
    hugepage: bool,
}

/// 2 MB hugepage size.
const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

/// Hard capacity of the per-binding redirect inbox (`BindingLiveState::
/// pending_tx`). Sized to cover the highest expected soft cap produced
/// by `pending_tx_capacity()` in prod (`ring_entries = 2048` →
/// `2 * ring_entries = 4096`). The MPSC ring is allocated once at
/// `BindingLiveState::new()` with this capacity, then the soft cap from
/// `set_max_pending_tx()` gates admissions inside `enqueue_tx` /
/// `enqueue_tx_owned`. If a caller ever requests a soft cap larger than
/// the hard cap, the effective cap clamps here and excess pushes drop
/// with a `redirect_inbox_overflow_drops` counter bump.
pub(super) const PENDING_TX_INBOX_HARD_CAP: usize = 4096;

impl MmapArea {
    pub(super) fn new(len: usize) -> io::Result<Self> {
        // Round up to 2 MB boundary for hugepage eligibility.
        let aligned_len = (len + HUGE_PAGE_SIZE - 1) & !(HUGE_PAGE_SIZE - 1);

        // Attempt 1: explicit 2 MB hugepages (requires system reservation).
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                aligned_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE
                    | libc::MAP_ANONYMOUS
                    | libc::MAP_HUGETLB
                    | libc::MAP_POPULATE
                    | (21 << libc::MAP_HUGE_SHIFT), // MAP_HUGE_2MB
                -1,
                0,
            )
        };
        if ptr != libc::MAP_FAILED {
            let ptr = NonNull::new(ptr.cast::<u8>())
                .ok_or_else(|| io::Error::other("null mmap pointer"))?;
            eprintln!(
                "xpf-ha: umem alloc {} bytes ({} MB, 2MB hugepages)",
                aligned_len,
                aligned_len / (1024 * 1024)
            );
            return Ok(Self {
                ptr,
                len,
                mapped_len: aligned_len,
                hugepage: true,
            });
        }

        // Attempt 2: standard pages with MAP_POPULATE + THP advisory hint.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                aligned_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        // Request transparent hugepage backing (advisory, cannot fail).
        unsafe {
            libc::madvise(ptr, aligned_len, libc::MADV_HUGEPAGE);
        }
        let ptr =
            NonNull::new(ptr.cast::<u8>()).ok_or_else(|| io::Error::other("null mmap pointer"))?;
        eprintln!(
            "xpf-ha: umem alloc {} bytes ({} MB, standard pages + THP hint)",
            aligned_len,
            aligned_len / (1024 * 1024)
        );
        Ok(Self {
            ptr,
            len,
            mapped_len: aligned_len,
            hugepage: false,
        })
    }

    /// Returns the original requested length (for XSK registration).
    pub(super) fn as_nonnull_slice(&self) -> NonNull<[u8]> {
        NonNull::slice_from_raw_parts(self.ptr, self.len)
    }

    /// Whether this region is backed by explicit 2 MB hugepages.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn is_hugepage_backed(&self) -> bool {
        self.hugepage
    }

    pub(super) fn slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let end = offset.checked_add(len)?;
        if end > self.len {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().add(offset), len) })
    }

    #[cfg_attr(not(test), allow(dead_code))]
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
        let _ = unsafe { libc::munmap(self.ptr.as_ptr().cast::<c_void>(), self.mapped_len) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmap_area_rejects_access_beyond_registered_len_even_if_mapping_is_rounded() {
        let area = MmapArea::new(128).expect("mmap");

        assert!(area.slice(0, 128).is_some());
        assert!(area.slice(128, 1).is_none());
        assert!(area.slice(512, 1).is_none());
    }

    fn test_tx_request_for_inbox(payload: u8) -> TxRequest {
        TxRequest {
            bytes: vec![payload; 16],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: 6,
            flow_key: None,
            egress_ifindex: 0,
            cos_queue_id: None,
            dscp_rewrite: None,
        }
    }

    #[test]
    fn enqueue_tx_owned_increments_redirect_inbox_overflow_counter_when_soft_cap_drops_newcomer() {
        // #710 / #706: pin that a redirect-inbox overflow in
        // `enqueue_tx_owned` increments both `redirect_inbox_overflow_drops`
        // (dedicated view) and `tx_errors` (generic), regardless of
        // which request gets dropped. Post-#706 the policy is drop-
        // newest (the incoming push is discarded); pre-#706 it was
        // drop-oldest (the head of the queue was evicted). Either way,
        // every push must return `Ok(())` and both counters advance in
        // lockstep.
        let live = BindingLiveState::new();
        live.max_pending_tx.store(2, Ordering::Relaxed);

        // Fill to cap — no overflow yet.
        live.enqueue_tx_owned(test_tx_request_for_inbox(1))
            .expect("push 1");
        live.enqueue_tx_owned(test_tx_request_for_inbox(2))
            .expect("push 2");
        assert_eq!(
            live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
            0
        );
        assert_eq!(live.tx_errors.load(Ordering::Relaxed), 0);

        // Third push hits the soft cap — drop-newest, counters advance.
        live.enqueue_tx_owned(test_tx_request_for_inbox(3))
            .expect("push 3 drops newest");
        assert_eq!(
            live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            live.tx_errors.load(Ordering::Relaxed),
            1,
            "generic tx_errors stays in lockstep with the dedicated drop \
             counter on this path — the dedicated counter is a subset view"
        );

        // Fourth push, another overflow — both counters advance again.
        live.enqueue_tx_owned(test_tx_request_for_inbox(4))
            .expect("push 4 drops newest");
        assert_eq!(
            live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
            2
        );
        assert_eq!(live.tx_errors.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn enqueue_tx_owned_below_cap_does_not_touch_overflow_counter() {
        let live = BindingLiveState::new();
        live.max_pending_tx.store(8, Ordering::Relaxed);

        for payload in 0..4 {
            live.enqueue_tx_owned(test_tx_request_for_inbox(payload))
                .expect("push below cap");
        }
        assert_eq!(
            live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
            0
        );
        assert_eq!(live.tx_errors.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn binding_live_snapshot_propagates_710_drop_counters() {
        // #710: `refresh_bindings` in the coordinator copies
        // `snap.redirect_inbox_overflow_drops`, `pending_tx_local_overflow_drops`,
        // and `tx_submit_error_drops` onto the per-binding `BindingStatus`.
        // This test pins the contract that BindingLiveState::snapshot() actually
        // reads those atomics and writes them into the BindingLiveSnapshot
        // struct — the middle layer between the counter increments and
        // the operator-facing BindingStatus. `no_owner_binding_drops` is
        // intentionally NOT in the snapshot (see the rustdoc on
        // `BindingLiveSnapshot` for why), so it is not asserted here.
        let live = BindingLiveState::new();
        live.redirect_inbox_overflow_drops
            .store(3, Ordering::Relaxed);
        live.pending_tx_local_overflow_drops
            .store(5, Ordering::Relaxed);
        live.tx_submit_error_drops.store(7, Ordering::Relaxed);
        live.no_owner_binding_drops.store(11, Ordering::Relaxed);

        let snap = live.snapshot();
        assert_eq!(snap.redirect_inbox_overflow_drops, 3);
        assert_eq!(snap.pending_tx_local_overflow_drops, 5);
        assert_eq!(snap.tx_submit_error_drops, 7);
        // `no_owner_binding_drops` has no per-binding protocol surface;
        // it is read directly from the atomic by
        // `Coordinator::cos_no_owner_binding_drops_total()`.
        assert_eq!(
            live.no_owner_binding_drops.load(Ordering::Relaxed),
            11,
            "atomic remains readable for the coordinator-level aggregation"
        );
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
    /// #710: counts packets that hit the redirect-inbox overflow path
    /// in `enqueue_tx` / `enqueue_tx_owned`. Multi-writer (every
    /// redirecting worker writes; the owner reads). Atomic because
    /// cross-thread. A non-zero value indicates the owner worker is
    /// not draining redirects fast enough — see #706 (mutex
    /// contention) and #709 (owner-worker hotspot).
    pub(super) redirect_inbox_overflow_drops: AtomicU64,
    /// #710: counts packets dropped from `pending_tx_local` /
    /// `pending_tx_prepared` when those bounded FIFOs overflow their
    /// `max_pending_tx` cap. Single-writer per binding (the worker
    /// that owns this binding), but exposed via atomic for cross-
    /// thread readers (status snapshotter). Indicates the worker is
    /// receiving redirected-in traffic faster than it can ingest into
    /// its CoS queues — upstream contributing cause is usually
    /// #706 / #709 (owner worker not keeping up) or #707 / #708
    /// (CoS enqueue throttled by buffer/admission caps).
    pub(super) pending_tx_local_overflow_drops: AtomicU64,
    /// #710: packets dropped at the TX submit path with a
    /// frame-level error (capacity exceeded, slice out of range, or
    /// other `TxError::Drop` from `transmit_batch` / transmit_prepared
    /// paths). Distinct from admission and redirect-inbox drops; a
    /// non-zero value usually indicates a frame-building bug upstream
    /// or a legitimate oversize packet. Subset of `tx_errors`.
    pub(super) tx_submit_error_drops: AtomicU64,
    /// #710: packets dropped in `apply_worker_shaped_tx_requests`
    /// because the worker could not locate any binding for the
    /// request's egress_ifindex. Happens when a cross-worker CoS
    /// redirect lands on a worker whose bound interfaces do not
    /// include the target. Typically reveals a binding-registration
    /// race during config reload or helper restart. Subset of
    /// `tx_errors`.
    pub(super) no_owner_binding_drops: AtomicU64,
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
    pub(super) last_error: Mutex<String>,
    /// Cross-worker redirect inbox (#706). N producer workers push
    /// redirected `TxRequest`s; the single owner worker drains. Bounded
    /// lock-free ring — replaces the pre-#706 `Mutex<VecDeque>` that
    /// serialised every producer against every other producer and
    /// against the owner's drain.
    pub(super) pending_tx: MpscInbox<TxRequest>,
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
            redirect_inbox_overflow_drops: AtomicU64::new(0),
            pending_tx_local_overflow_drops: AtomicU64::new(0),
            tx_submit_error_drops: AtomicU64::new(0),
            no_owner_binding_drops: AtomicU64::new(0),
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
            last_error: Mutex::new(String::new()),
            pending_tx: MpscInbox::new(PENDING_TX_INBOX_HARD_CAP),
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
            redirect_inbox_overflow_drops: self
                .redirect_inbox_overflow_drops
                .load(Ordering::Relaxed),
            pending_tx_local_overflow_drops: self
                .pending_tx_local_overflow_drops
                .load(Ordering::Relaxed),
            tx_submit_error_drops: self.tx_submit_error_drops.load(Ordering::Relaxed),
            // `no_owner_binding_drops` is read directly from the atomic
            // by `Coordinator::cos_no_owner_binding_drops_total()` — not
            // snapshotted here because it is not exposed per-binding.
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
        self.push_redirect_inbox(req);
        Ok(())
    }

    pub(super) fn enqueue_tx_owned(&self, req: TxRequest) -> Result<(), TxRequest> {
        self.push_redirect_inbox(req);
        Ok(())
    }

    /// Shared push path for `enqueue_tx` and `enqueue_tx_owned`.
    /// Drop-newest on overflow: if the soft cap or ring hard cap is hit,
    /// drop the incoming request and bump the overflow counters. This is
    /// a deliberate change from the pre-#706 drop-oldest behaviour —
    /// older queued packets are closer to being serviced by the owner
    /// worker, so evicting them just extends tail latency. The counter
    /// contract (`tx_errors` as the generic error, `redirect_inbox_
    /// overflow_drops` as the dedicated view) is preserved.
    #[inline]
    fn push_redirect_inbox(&self, req: TxRequest) {
        let max_pending = self.max_pending_tx.load(Ordering::Relaxed) as usize;
        if max_pending > 0 && self.pending_tx.len() >= max_pending {
            self.record_redirect_inbox_overflow();
            return;
        }
        if self.pending_tx.push(req).is_err() {
            // Hard cap hit — ring is full. Rare: the hard cap sits at
            // `PENDING_TX_INBOX_HARD_CAP`, so a non-zero soft cap
            // normally fires first. This branch is reachable only under
            // concurrent producers racing past the soft-cap check, or
            // when the caller has set `max_pending_tx = 0` (treat as
            // unlimited → hard cap is the only brake).
            self.record_redirect_inbox_overflow();
        }
    }

    #[inline]
    fn record_redirect_inbox_overflow(&self) {
        self.tx_errors.fetch_add(1, Ordering::Relaxed);
        // #710 / #706: non-zero values here indicate the owner worker
        // cannot drain redirects fast enough relative to producer push
        // rate. After #706 the path is lock-free, so contention is no
        // longer the bottleneck — further growth typically points at
        // owner-worker hotspot (#709) or CoS admission (#707 / #708).
        self.redirect_inbox_overflow_drops
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn take_pending_tx(&self) -> VecDeque<TxRequest> {
        if self.pending_tx.is_empty() {
            return VecDeque::new();
        }
        let mut drained = VecDeque::new();
        // SAFETY: `MpscInbox::pop` requires the single-consumer
        // invariant. The per-binding redirect inbox has exactly one
        // consumer — the owner worker — which is also the sole caller
        // of `take_pending_tx`. Enforced by convention (see the doc
        // comment on `pending_tx` in `BindingLiveState`).
        while let Some(req) = unsafe { self.pending_tx.pop() } {
            drained.push_back(req);
        }
        drained
    }

    pub(super) fn pending_tx_empty(&self) -> bool {
        self.pending_tx.is_empty()
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
