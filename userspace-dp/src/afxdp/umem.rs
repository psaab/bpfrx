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

/// Hard capacity of the per-binding redirect inbox
/// (`BindingLiveState::pending_tx`). Sized to cover the highest expected
/// soft cap produced by `pending_tx_capacity()` in prod
/// (`ring_entries = 2048` → `2 * ring_entries = 4096`). The MPSC ring is
/// allocated once at `BindingLiveState::new()` with this capacity, then
/// the soft cap from `set_max_pending_tx()` gates admissions inside
/// `enqueue_tx` / `enqueue_tx_owned`. If a caller ever requests a soft
/// cap larger than the hard cap, the effective cap clamps here and
/// excess pushes drop with a `redirect_inbox_overflow_drops` counter bump.
pub(super) const PENDING_TX_INBOX_HARD_CAP: usize = 4096;

/// #709: owner-drain / redirect-acquire latency histogram bucket count.
///
/// Bucket layout (produced by `bucket_index_for_ns`):
/// - Bucket 0: `[0, 1024 ns)` — the sub-1 µs catch-all.
/// - Bucket 1: `[1024, 2048)` = `[2^10, 2^11)` ns.
/// - Bucket N (N >= 1): `[2^(N+9), 2^(N+10))` ns.
/// - Bucket 15: saturation — any ns ≥ 2^24 (~16 ms) lands here.
///
/// Indexed branchlessly (one `leading_zeros` + one saturating subtract
/// + one min). Sized `[AtomicU64; DRAIN_HIST_BUCKETS]` on
/// `BindingLiveState` so the entire histogram lives inline in the
/// owner's `Arc<BindingLiveState>` — no heap allocation, no bucket-
/// search loop on the hot path. The const-assert below exists because
/// the bucket layout is part of the wire contract (protocol.rs +
/// Prometheus labels): any future change must propagate through both
/// sides, so force a compile error on a silent edit.
pub(super) const DRAIN_HIST_BUCKETS: usize = 16;
const _: () = assert!(DRAIN_HIST_BUCKETS == 16);

/// #709: sample mask for the redirect-acquire timer. We sample the
/// timer 1-in-(MASK+1) = 1-in-256 pushes. The mask is required to be a
/// power-of-two minus one so `counter & MASK == 0` fires uniformly on
/// exactly one value per wrap. Producer-local counter is seeded from
/// `worker_id` so samples from different workers don't lockstep onto
/// the same slot.
pub(super) const REDIRECT_SAMPLE_MASK: u64 = 0xff;
const _: () = assert!(REDIRECT_SAMPLE_MASK.count_ones() == REDIRECT_SAMPLE_MASK.trailing_ones());

/// #709: branchless power-of-two bucket select for nanosecond deltas.
///
/// Mapping (see `DRAIN_HIST_BUCKETS` for the layout):
/// - `ns ∈ [0, 1024)` → bucket 0 (sub-1 µs catch-all).
/// - `ns ∈ [2^(N+9), 2^(N+10))` → bucket N, for N ∈ [1, 15).
/// - `ns ≥ 2^24` → bucket 15 (saturation).
///
/// Formula:
/// - `(ns | 1)` ensures `leading_zeros` sees at least one set bit —
///   `leading_zeros(0) == 64` would otherwise land us one bucket off
///   at the bottom. With the OR, `ns=0` behaves like `ns=1` (bucket 0).
/// - `clz = (ns | 1).leading_zeros()`: for `ns=1024 (2^10)`,
///   `clz = 64 - 11 = 53`; for `ns=2^24` (top bucket lower bound),
///   `clz = 64 - 25 = 39`.
/// - `b = 54 - clz` gives bucket 1 for `ns=1024` and bucket 15 for
///   `ns=2^24`. Sub-1024 ns delta yields `clz >= 54` → `b <= 0`, which
///   the `.max(0)` saturating subtract clamps at 0. Above 2^24, `b`
///   grows past 15, which `.min(DRAIN_HIST_BUCKETS - 1)` clamps.
///
/// One `leading_zeros` + one saturating subtract + one min. No loop,
/// no branch. Hot-path OK per plan §5.
#[inline]
pub(super) fn bucket_index_for_ns(ns: u64) -> usize {
    let clz = (ns | 1).leading_zeros() as i32;
    let b = (54 - clz).max(0) as usize;
    b.min(DRAIN_HIST_BUCKETS - 1)
}

/// #746: owner-worker-written owner-profile telemetry. The owner of a
/// binding is the sole writer of these atomics (the single drain caller
/// for this binding); peer workers only read via `snapshot()`. Isolated
/// onto its own 64-byte cacheline so owner writes do not invalidate
/// peer-writer cachelines (see `OwnerProfilePeerWrites`) and so
/// telemetry updates do not ping-pong unrelated `BindingLiveState`
/// fields.
///
/// Matches the in-repo `#[repr(align(64))]` idiom established in
/// `mpsc_inbox.rs::CachePadded` (#715). We use a freestanding struct
/// here instead of wrapping each atomic individually because the
/// grouped atomics are updated together on one code path — isolating
/// the whole group on one line is the alignment contract that matters.
///
/// Counter semantics are unchanged from #709 / #731 (`drain_latency_hist`
/// buckets sum to `drain_invocations`; `drain_noop_invocations` is a
/// subset counter). See `BindingLiveState::snapshot()` for how these
/// values flow into `BindingLiveSnapshot`.
#[repr(align(64))]
pub(super) struct OwnerProfileOwnerWrites {
    pub(super) drain_latency_hist: [AtomicU64; DRAIN_HIST_BUCKETS],
    pub(super) drain_invocations: AtomicU64,
    pub(super) drain_noop_invocations: AtomicU64,
    /// #709: owner-local pps window. Formerly `pps_owner_vs_peer[0]`;
    /// split by writer for cacheline isolation (#746). The owner is
    /// the only writer; peers read through `snapshot()`.
    pub(super) owner_pps: AtomicU64,
    /// #760 instrumentation (Codex adversarial review, PR #773):
    /// moved here from `BindingLiveState` so owner-only writes
    /// don't ping-pong on the cacheline that holds multi-writer
    /// `redirect_inbox_overflow_drops`.
    ///
    /// Bytes observed at the three `apply_*` tx_bytes sites,
    /// incremented unconditionally. Sum of this + `post_drain_backup_bytes`
    /// equals `tx_bytes` on the shaped path. Gap vs the per-queue
    /// `drain_sent_bytes` reveals apply_* queue-miss bytes.
    ///
    /// Read skew note (Codex adversarial review, PR #773): these
    /// three atomics (`tx_bytes`, `drain_sent_bytes_shaped_unconditional`,
    /// `post_drain_backup_bytes`) are written at separate sites
    /// and loaded at separate scrape instants. A snapshot that
    /// lands between the `tx_bytes.fetch_add` and the companion
    /// `fetch_add` will show a transient "bypass gap" that is
    /// pure read skew, not a real bypass event. Interpret these
    /// as DELTA-OVER-WINDOW diagnostics rather than point-in-
    /// time equalities. The window needs to span many cache-line
    /// writes (microseconds) to amortise the skew to negligible.
    pub(super) drain_sent_bytes_shaped_unconditional: AtomicU64,
    /// #760 instrumentation. Bytes delivered by the post-CoS
    /// backup transmit paths in `drain_pending_tx`
    /// (transmit_prepared_batch + transmit_batch). Post-fix (PR
    /// #773) this reflects non-CoS traffic only; CoS-bound items
    /// are dropped before reaching those sites.
    pub(super) post_drain_backup_bytes: AtomicU64,
    /// #760 (PR #773) drop-filter counters: items with
    /// `cos_queue_id.is_some()` that reached the post-drain
    /// backup paths and were dropped instead of transmitted
    /// unshaped. Non-zero indicates a cross-worker routing
    /// failure that the bounded ingest-drain loop did not
    /// absorb.
    pub(super) post_drain_backup_cos_drops: AtomicU64,
    pub(super) post_drain_backup_cos_drop_bytes: AtomicU64,
}

/// #746: peer-worker-written owner-profile telemetry. Every redirecting
/// worker is a writer of these atomics. Isolated onto its own 64-byte
/// cacheline so peer writes do not invalidate the owner's cacheline
/// (see `OwnerProfileOwnerWrites`) and so the redirect-sample counter
/// churn does not ping-pong unrelated `BindingLiveState` fields.
///
/// The owner reads the peer-written counters only via `snapshot()`;
/// there is no owner-write path into this struct.
#[repr(align(64))]
pub(super) struct OwnerProfilePeerWrites {
    pub(super) redirect_acquire_hist: [AtomicU64; DRAIN_HIST_BUCKETS],
    pub(super) redirect_sample_counter: AtomicU64,
    /// #709: peer-redirect pps window. Formerly `pps_owner_vs_peer[1]`;
    /// split by writer for cacheline isolation (#746). Any worker that
    /// redirects into this binding is a writer; the owner reads via
    /// `snapshot()`.
    pub(super) peer_pps: AtomicU64,
}

// #746: compile-time layout enforcement. A silent drop of the
// `#[repr(align(64))]` attribute — or a future refactor that inlines
// a packed neighbor — is caught at build time, not at runtime.
const _: () = assert!(core::mem::align_of::<OwnerProfileOwnerWrites>() == 64);
const _: () = assert!(core::mem::align_of::<OwnerProfilePeerWrites>() == 64);
// Size ceiling: owner struct is 16 hist + 3 scalar AtomicU64 = 152 B,
// padded to 192 B (3 cachelines) at 64-B alignment. Peer struct is
// 16 hist + 2 scalar AtomicU64 = 144 B, padded to 192 B. Allow up to
// 5 cachelines (320 B) so a follow-up can add one or two atomics
// without this assert breaking — but if someone drops a giant field
// in here, the build fails loudly and forces a reshape decision.
const _: () = assert!(core::mem::size_of::<OwnerProfileOwnerWrites>() <= 320);
const _: () = assert!(core::mem::size_of::<OwnerProfilePeerWrites>() <= 320);

impl OwnerProfileOwnerWrites {
    /// Inline zero-init. `AtomicU64` is not `Copy`, so `[AtomicU64::new(0); N]`
    /// does not compile; `from_fn` builds the array inline on the caller's
    /// stack — no heap.
    #[inline]
    fn new() -> Self {
        Self {
            drain_latency_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            drain_invocations: AtomicU64::new(0),
            drain_noop_invocations: AtomicU64::new(0),
            owner_pps: AtomicU64::new(0),
            drain_sent_bytes_shaped_unconditional: AtomicU64::new(0),
            post_drain_backup_bytes: AtomicU64::new(0),
            post_drain_backup_cos_drops: AtomicU64::new(0),
            post_drain_backup_cos_drop_bytes: AtomicU64::new(0),
        }
    }
}

impl OwnerProfilePeerWrites {
    #[inline]
    fn new() -> Self {
        Self {
            redirect_acquire_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            redirect_sample_counter: AtomicU64::new(0),
            peer_pps: AtomicU64::new(0),
        }
    }
}

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
    fn take_pending_tx_into_appends_without_resetting_caller_buffer() {
        // #706: pin that `take_pending_tx_into` preserves the caller's
        // existing `VecDeque` contents. The owner-worker drain feeds its
        // `pending_tx_local` buffer through the call; if the new API ever
        // regressed to `*out = drained` or `out.clear()`, items already
        // queued locally would be dropped on every poll.
        let live = BindingLiveState::new();
        live.max_pending_tx.store(8, Ordering::Relaxed);
        live.enqueue_tx_owned(test_tx_request_for_inbox(10))
            .expect("push inbox");
        live.enqueue_tx_owned(test_tx_request_for_inbox(11))
            .expect("push inbox");

        let mut out = VecDeque::from([
            test_tx_request_for_inbox(1),
            test_tx_request_for_inbox(2),
        ]);
        live.take_pending_tx_into(&mut out);

        let payloads: Vec<u8> = out.iter().map(|req| req.bytes[0]).collect();
        assert_eq!(
            payloads,
            vec![1, 2, 10, 11],
            "caller-provided items must come first; inbox items appended in FIFO order"
        );
        assert!(live.pending_tx_empty(), "inbox fully drained");
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
    fn bucket_index_for_ns_covers_powers_of_two_from_1us_to_32ms() {
        // #709: pin the bucket layout. Bucket 0 covers ns in
        // [0, 1024); bucket 1 covers [1024, 2048); ... bucket 15
        // saturates at >= 2^25 ns. Anyone editing the formula in
        // `bucket_index_for_ns` must either keep this layout or
        // renumber the wire contract — this test fails loudly on
        // either.
        // Bucket 0 is the "<= 1024 ns" catch-all: ns ∈ [0, 1024) lands
        // here, ns = 1024 promotes to bucket 1.
        assert_eq!(bucket_index_for_ns(0), 0);
        assert_eq!(bucket_index_for_ns(1), 0);
        assert_eq!(bucket_index_for_ns(1023), 0);
        assert_eq!(bucket_index_for_ns(1024), 1);
        assert_eq!(bucket_index_for_ns(2047), 1);
        assert_eq!(bucket_index_for_ns(2048), 2);
        assert_eq!(bucket_index_for_ns(4095), 2);
        assert_eq!(bucket_index_for_ns(4096), 3);
        // Walk each bucket boundary [2^(N+9), 2^(N+10)) for
        // N ∈ [1, 15). Expect `bucket_index_for_ns(2^(N+9)) == N`
        // and `bucket_index_for_ns(2^(N+10) - 1) == N`. We skip N=0
        // because bucket 0 is the sub-1024 catch-all (its `lo` is 0
        // not `2^9`), covered by the explicit asserts above.
        for n in 1..(DRAIN_HIST_BUCKETS - 1) {
            let lo = 1u64 << (n + 9);
            let hi = (1u64 << (n + 10)).saturating_sub(1);
            assert_eq!(
                bucket_index_for_ns(lo),
                n,
                "lo boundary for bucket {n}: ns={lo}",
            );
            assert_eq!(
                bucket_index_for_ns(hi),
                n,
                "hi boundary for bucket {n}: ns={hi}",
            );
        }
        // Top bucket: ns >= 2^24 saturates at 15.
        assert_eq!(bucket_index_for_ns(1u64 << 24), DRAIN_HIST_BUCKETS - 1);
        assert_eq!(bucket_index_for_ns(1u64 << 25), DRAIN_HIST_BUCKETS - 1);
        assert_eq!(bucket_index_for_ns(u64::MAX), DRAIN_HIST_BUCKETS - 1);
    }

    #[test]
    fn bucket_index_for_ns_handles_zero() {
        // #709: `ns = 0` must land in bucket 0 and MUST NOT panic. The
        // implementation uses `(ns | 1).leading_zeros()` specifically
        // to avoid `leading_zeros(0) == 64` which would cascade into a
        // negative subtraction after the `54 - clz` step. This pins
        // that the OR-with-1 guard is still in place after future
        // edits.
        assert_eq!(bucket_index_for_ns(0), 0);
    }

    #[test]
    fn bucket_index_for_ns_saturates_above_top_bucket() {
        // #709: ns = 1 trillion (~17 minutes) must clamp at bucket 15.
        // If a future refactor ever turned the `.min(DRAIN_HIST_BUCKETS - 1)`
        // into a subtraction, this would underflow silently on release
        // builds — the min clamp is the wire-contract guard.
        assert_eq!(bucket_index_for_ns(1_000_000_000_000), DRAIN_HIST_BUCKETS - 1);
    }

    #[test]
    fn drain_latency_hist_increments_on_recorded_drain() {
        // #709: exercise the hist-update path in isolation. We do not
        // call `drain_shaped_tx` here (requires a fully-constructed
        // BindingWorker fixture); instead, we recreate the exact shape
        // tx.rs uses — bucket_index_for_ns + fetch_add — and assert
        // the bucket landed in the right slot.
        let live = BindingLiveState::new();
        let delta_ns = 1500u64; // bucket 1 ([1024, 2048))
        let bucket = bucket_index_for_ns(delta_ns);
        live.owner_profile_owner.drain_latency_hist[bucket].fetch_add(1, Ordering::Relaxed);
        live.owner_profile_owner
            .drain_invocations
            .fetch_add(1, Ordering::Relaxed);
        assert_eq!(bucket, 1);
        assert_eq!(
            live.owner_profile_owner.drain_latency_hist[1].load(Ordering::Relaxed),
            1
        );
        // Counter-factual: surrounding buckets must stay at 0. A prior
        // draft that used the wrong shift constant (e.g. `55 - clz`)
        // would light up bucket 0 or 2 here — this assertion catches
        // the off-by-one.
        assert_eq!(
            live.owner_profile_owner.drain_latency_hist[0].load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            live.owner_profile_owner.drain_latency_hist[2].load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            live.owner_profile_owner
                .drain_invocations
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn redirect_acquire_hist_samples_one_in_mask_plus_one() {
        // #709: drive `enqueue_tx_owned` exactly `REDIRECT_SAMPLE_MASK
        // + 1` times and assert exactly one bucket increment. The
        // sample counter is seeded to 0 by `new()`, so on the first
        // push `(counter & MASK) == 0` fires; subsequent MASK pushes
        // skip, and the (MASK+1)-th push would fire again.
        let live = BindingLiveState::new();
        live.max_pending_tx.store(8192, Ordering::Relaxed);
        let iterations = (REDIRECT_SAMPLE_MASK + 1) as usize;
        for _ in 0..iterations {
            live.enqueue_tx_owned(test_tx_request_for_inbox(0xab))
                .expect("push");
        }
        let total_samples: u64 = live
            .owner_profile_peer
            .redirect_acquire_hist
            .iter()
            .map(|slot| slot.load(Ordering::Relaxed))
            .sum();
        assert_eq!(
            total_samples, 1,
            "exactly one sample per (REDIRECT_SAMPLE_MASK + 1) pushes"
        );

        // Counter-factual: a pre-#709 path (no sampling, no bucket
        // increment) would leave the histogram at zero after the same
        // push count. Reset and demonstrate by skipping the hist update
        // inline — this proves the test's positive assertion above is
        // actually exercising the #709-added code path, not some
        // always-live fallback.
        let live2 = BindingLiveState::new();
        live2.max_pending_tx.store(8192, Ordering::Relaxed);
        // Replicate the non-sampled producer: raw MPSC push without
        // the sample/timer wrapper.
        for _ in 0..iterations {
            live2
                .pending_tx
                .push(test_tx_request_for_inbox(0xcd))
                .expect("push raw");
        }
        let pre_709_total: u64 = live2
            .owner_profile_peer
            .redirect_acquire_hist
            .iter()
            .map(|slot| slot.load(Ordering::Relaxed))
            .sum();
        assert_eq!(
            pre_709_total, 0,
            "raw MPSC push (pre-#709 shape) must not touch the redirect-acquire histogram"
        );
    }

    #[test]
    fn new_seeded_initialises_redirect_sample_counter_from_worker_id() {
        // #709: per-worker seeding prevents lockstep sampling. Two
        // workers with different ids must start at different positions
        // in the 1-in-(MASK+1) cycle. Seed with 0 and 1 and verify
        // both new_seeded instances hold distinct initial counter
        // values.
        let a = BindingLiveState::new_seeded(0);
        let b = BindingLiveState::new_seeded(1);
        assert_eq!(
            a.owner_profile_peer
                .redirect_sample_counter
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            b.owner_profile_peer
                .redirect_sample_counter
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn binding_live_snapshot_propagates_709_owner_profile_counters() {
        // #709: pin that the snapshot() path copies all owner-profile
        // atomics into the BindingLiveSnapshot. A future edit that
        // misses one field would silently under-surface telemetry to
        // the operator CLI / Prometheus — this test fails fast on the
        // missing field.
        let live = BindingLiveState::new();
        live.owner_profile_owner.drain_latency_hist[3].store(7, Ordering::Relaxed);
        live.owner_profile_owner.drain_latency_hist[15].store(2, Ordering::Relaxed);
        live.owner_profile_owner
            .drain_invocations
            .store(100, Ordering::Relaxed);
        live.owner_profile_owner
            .drain_noop_invocations
            .store(50, Ordering::Relaxed);
        live.owner_profile_peer.redirect_acquire_hist[1].store(11, Ordering::Relaxed);
        live.owner_profile_owner
            .owner_pps
            .store(1234, Ordering::Relaxed);
        live.owner_profile_peer
            .peer_pps
            .store(567, Ordering::Relaxed);

        let snap = live.snapshot();
        assert_eq!(snap.drain_latency_hist[3], 7);
        assert_eq!(snap.drain_latency_hist[15], 2);
        assert_eq!(snap.drain_invocations, 100);
        assert_eq!(snap.drain_noop_invocations, 50);
        assert_eq!(snap.redirect_acquire_hist[1], 11);
        assert_eq!(snap.owner_pps, 1234);
        assert_eq!(snap.peer_pps, 567);
    }

    #[test]
    fn owner_profile_telemetry_is_cacheline_isolated_from_binding_live_state() {
        // #746: pin the alignment invariant this PR is buying. If a
        // future refactor silently drops the `#[repr(align(64))]`
        // attribute on either of the owner-profile structs — or
        // reshuffles `BindingLiveState` fields so the two groups
        // land on the same cacheline as their neighbor — this test
        // fails loudly.
        //
        // The two assertions are complementary: alignment on the
        // struct types alone is not enough if the containing
        // `BindingLiveState` somehow mis-places them, and field-offset
        // alignment alone is not enough if the struct itself lost its
        // `#[repr(align(64))]`.
        use core::mem::{align_of, offset_of, size_of};

        assert_eq!(align_of::<OwnerProfileOwnerWrites>(), 64);
        assert_eq!(align_of::<OwnerProfilePeerWrites>(), 64);

        let owner_off = offset_of!(BindingLiveState, owner_profile_owner);
        let peer_off = offset_of!(BindingLiveState, owner_profile_peer);
        assert_eq!(
            owner_off % 64,
            0,
            "owner_profile_owner must sit on a 64-byte cacheline boundary",
        );
        assert_eq!(
            peer_off % 64,
            0,
            "owner_profile_peer must sit on a 64-byte cacheline boundary",
        );

        // The two profile structs must NOT share a cacheline: their
        // offset difference must be at least the larger struct size
        // (both are padded to 64-B alignment, so this also implies
        // rounded-up cacheline distance).
        let gap = peer_off.abs_diff(owner_off);
        assert!(
            gap >= size_of::<OwnerProfileOwnerWrites>().max(size_of::<OwnerProfilePeerWrites>()),
            "owner and peer profile structs must not share a cacheline (gap={gap}, \
             owner_size={}, peer_size={})",
            size_of::<OwnerProfileOwnerWrites>(),
            size_of::<OwnerProfilePeerWrites>(),
        );
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
    /// #709 / #746: owner-written telemetry, cacheline-isolated.
    /// `drain_latency_hist` buckets sum to `drain_invocations` (pinned
    /// in unit tests); `drain_noop_invocations` is a subset counter
    /// (drains that returned `false`). `owner_pps` is the owner-local
    /// pps window.
    ///
    /// Written only by the owner worker (the sole caller of
    /// `drain_shaped_tx` on this binding); read by the snapshot path
    /// and by Prometheus scrape. Owner-only write + Relaxed load/store
    /// is sufficient: the snapshot reader tolerates monotonic counter
    /// tearing across a bucket array, and Prometheus semantics are
    /// "best effort at scrape time".
    pub(super) owner_profile_owner: OwnerProfileOwnerWrites,
    /// #709 / #746: peer-written telemetry, cacheline-isolated.
    /// `redirect_acquire_hist` is the redirect-acquire latency
    /// histogram, sampled 1-in-(`REDIRECT_SAMPLE_MASK`+1) on
    /// producers. `redirect_sample_counter` is the producer-local
    /// sample counter; seeded from `worker_id` at construction so
    /// different producer workers don't lockstep their samples onto
    /// the same call. `peer_pps` is the peer-redirect pps window.
    ///
    /// Multi-writer: every worker that redirects a TX request into
    /// this binding's inbox increments a bucket on a sampled push.
    /// The owner reads via `snapshot()`.
    pub(super) owner_profile_peer: OwnerProfilePeerWrites,
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
    /// #802: ring-pressure instrumentation. Cumulative monotonic counters
    /// mirrored from the worker-local `BindingWorker` fields of the same
    /// name. Worker increments `b.dbg_tx_ring_full += 1` (etc.) on the hot
    /// path; the published value here is updated via `fetch_add(delta)`
    /// at the existing ~1s debug-report tick, BEFORE the local counter is
    /// reset for the next window. The control-socket snapshot reads from
    /// these atomics. No hot-path code is touched — this is purely a new
    /// read-side publish sink.
    pub(super) dbg_tx_ring_full: AtomicU64,
    pub(super) dbg_sendto_enobufs: AtomicU64,
    /// #802/#804: per-binding `bound_pending` FIFO overflow counter —
    /// incremented when `bound_pending_tx_local`/`bound_pending_tx_prepared`
    /// evict an item because the FIFO is above `max_pending_tx`. This is
    /// strictly the bound-pending path; the class-of-service admission
    /// overflow has its own counter below. Pre-#804 builds published a
    /// single `dbg_pending_overflow` that conflated the two sites; that
    /// wire key was removed in #804 in favor of the split names.
    pub(super) dbg_bound_pending_overflow: AtomicU64,
    /// #804: class-of-service queue admission overflow counter —
    /// incremented in `enqueue_cos_item()` when the CoS admission gate
    /// rejects the item (flow-share cap + buffer cap exhausted) but the
    /// caller still needs to account the drop. Separate from
    /// `dbg_bound_pending_overflow` so operators can disambiguate
    /// bound-pending pressure from CoS shaping pressure at triage time.
    pub(super) dbg_cos_queue_overflow: AtomicU64,
    /// #802: kernel XDP statistics v2 `rx_fill_ring_empty_descs` — the
    /// kernel's native cumulative counter of RX fill-ring starvation
    /// events. Published via `store()` (not fetch_add) because the
    /// kernel-side value is already absolute. Sampled from
    /// `device.statistics_v2()` at the same ~1s debug-report tick as
    /// the local counters above.
    pub(super) rx_fill_ring_empty_descs: AtomicU64,
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
            // #709 / #746: owner-profile telemetry, split by writer
            // into two cacheline-isolated groups. Histograms are zero-
            // init fixed-cap arrays; sum of buckets == drain_invocations
            // invariant holds at `new()` (both 0). The redirect-sample
            // counter seed is left at zero by `new()`; call sites that
            // have a worker_id in hand should use `new_seeded()` instead
            // so per-worker samples don't lockstep onto the same push.
            owner_profile_owner: OwnerProfileOwnerWrites::new(),
            owner_profile_peer: OwnerProfilePeerWrites::new(),
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
            // #802: ring-pressure instrumentation sinks. Zero-init;
            // published by the worker's per-second debug tick.
            dbg_tx_ring_full: AtomicU64::new(0),
            dbg_sendto_enobufs: AtomicU64::new(0),
            dbg_bound_pending_overflow: AtomicU64::new(0),
            dbg_cos_queue_overflow: AtomicU64::new(0),
            rx_fill_ring_empty_descs: AtomicU64::new(0),
            last_heartbeat: AtomicU64::new(0),
            max_pending_tx: AtomicU32::new(0),
            last_error: Mutex::new(String::new()),
            pending_tx: MpscInbox::new(PENDING_TX_INBOX_HARD_CAP),
            pending_session_deltas: Mutex::new(VecDeque::new()),
        }
    }

    /// #709: construct a binding live state with the redirect-sample
    /// counter pre-seeded from `worker_id`. Seeding is cosmetic — the
    /// sample mask fires exactly 1-in-(MASK+1) regardless of start
    /// value — but it prevents every worker from firing its first
    /// sample on its very first push, which avoids an early-startup
    /// lockstep burst that would bias bucket 0 heavily on the first
    /// scrape.
    pub(super) fn new_seeded(worker_id: u32) -> Self {
        let mut state = Self::new();
        // `worker_id as u64` preserves the distinct-per-worker property
        // we care about without needing a randomness source. The mask
        // treats the counter modulo (MASK+1), so any seed ∈ [0, MASK]
        // suffices; larger worker_ids just wrap cheaply.
        //
        // #746: the sample counter moved into `owner_profile_peer`
        // when the owner/peer split landed; seeding writes through the
        // new nested path but the effect is identical.
        state.owner_profile_peer.redirect_sample_counter = AtomicU64::new(worker_id as u64);
        state
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
            post_drain_backup_bytes: self
                .owner_profile_owner
                .post_drain_backup_bytes
                .load(Ordering::Relaxed),
            drain_sent_bytes_shaped_unconditional: self
                .owner_profile_owner
                .drain_sent_bytes_shaped_unconditional
                .load(Ordering::Relaxed),
            post_drain_backup_cos_drops: self
                .owner_profile_owner
                .post_drain_backup_cos_drops
                .load(Ordering::Relaxed),
            post_drain_backup_cos_drop_bytes: self
                .owner_profile_owner
                .post_drain_backup_cos_drop_bytes
                .load(Ordering::Relaxed),
            // Compile-time check: these four counters live on the
            // owner-only cacheline-isolated block to avoid ping-
            // pong with multi-writer overflow counters.
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
            // #802: ring-pressure counters published from the worker's
            // periodic debug tick. Relaxed load is sufficient — these
            // are monotonic diagnostic counters, not part of any
            // load-bearing synchronization.
            dbg_tx_ring_full: self.dbg_tx_ring_full.load(Ordering::Relaxed),
            dbg_sendto_enobufs: self.dbg_sendto_enobufs.load(Ordering::Relaxed),
            dbg_bound_pending_overflow: self.dbg_bound_pending_overflow.load(Ordering::Relaxed),
            dbg_cos_queue_overflow: self.dbg_cos_queue_overflow.load(Ordering::Relaxed),
            rx_fill_ring_empty_descs: self.rx_fill_ring_empty_descs.load(Ordering::Relaxed),
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
            // #709 / #746: owner-profile telemetry snapshot.
            // Histograms are copied bucket-by-bucket under `Relaxed`
            // through the cacheline-isolated owner/peer structs.
            // Read-side tearing is acceptable — these are diagnostic
            // counters, not a load-bearing arithmetic invariant; the
            // only "invariant" (sum of buckets ≈ drain_invocations)
            // holds within a single-thread read only in steady-state,
            // which is how operators consume the values anyway.
            drain_latency_hist: Self::snapshot_hist(
                &self.owner_profile_owner.drain_latency_hist,
            ),
            drain_invocations: self
                .owner_profile_owner
                .drain_invocations
                .load(Ordering::Relaxed),
            drain_noop_invocations: self
                .owner_profile_owner
                .drain_noop_invocations
                .load(Ordering::Relaxed),
            redirect_acquire_hist: Self::snapshot_hist(
                &self.owner_profile_peer.redirect_acquire_hist,
            ),
            owner_pps: self.owner_profile_owner.owner_pps.load(Ordering::Relaxed),
            peer_pps: self.owner_profile_peer.peer_pps.load(Ordering::Relaxed),
        }
    }

    /// #709: copy a histogram bucket array under `Relaxed`. Inline to
    /// keep the fixed-size array on the caller's stack — no `Vec`.
    #[inline]
    fn snapshot_hist(hist: &[AtomicU64; DRAIN_HIST_BUCKETS]) -> [u64; DRAIN_HIST_BUCKETS] {
        std::array::from_fn(|i| hist[i].load(Ordering::Relaxed))
    }

    pub(super) fn enqueue_tx(&self, req: TxRequest) -> Result<(), String> {
        self.push_redirect_inbox(req);
        Ok(())
    }

    pub(super) fn enqueue_tx_owned(&self, req: TxRequest) -> Result<(), TxRequest> {
        // #709: redirect-acquire latency, sampled 1-in-256.
        //
        // Hot-path cost on the non-sampled branch: one
        // `fetch_add(1, Relaxed)` + one `&` + one `==`. Under a few ns
        // on modern x86_64. On the sampled branch: two
        // `monotonic_nanos()` (VDSO `clock_gettime(MONOTONIC)`, ~15 ns
        // each) + one bucket write. 1-in-256 sampling amortises to
        // `~(2 * 15 + 2) / 256 ≈ 0.13 ns` per push — well below the
        // noise floor of the redirect path itself.
        //
        // The timer wraps only `push_redirect_inbox`. We do NOT add a
        // second atomic to the MPSC inbox itself; the sample counter
        // lives on `BindingLiveState` next to the other per-binding
        // atomics. MPSC invariants from #715 are preserved.
        let sample = (self
            .owner_profile_peer
            .redirect_sample_counter
            .fetch_add(1, Ordering::Relaxed)
            & REDIRECT_SAMPLE_MASK)
            == 0;
        let start = if sample {
            Some(monotonic_nanos())
        } else {
            None
        };
        self.push_redirect_inbox(req);
        if let Some(start) = start {
            let delta = monotonic_nanos().saturating_sub(start);
            let bucket = bucket_index_for_ns(delta);
            self.owner_profile_peer.redirect_acquire_hist[bucket]
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Shared push path for `enqueue_tx` and `enqueue_tx_owned`.
    /// Drop-newest on overflow: if the soft cap or ring hard cap is hit,
    /// drop the incoming request and bump the overflow counters. This is
    /// a deliberate change from the pre-#706 drop-oldest behaviour —
    /// older queued packets are closer to being serviced by the owner
    /// worker, so evicting them just extends tail latency. The counter
    /// contract (`tx_errors` as the generic error,
    /// `redirect_inbox_overflow_drops` as the dedicated view) is preserved.
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

    /// Drain the redirect inbox into a caller-provided `VecDeque`, so the
    /// owner worker's drain stays allocation-free on the hot path. The
    /// caller reuses its existing `pending_tx_local` buffer across polls
    /// — calling `VecDeque::new()` / growing a fresh buffer on every drain
    /// put allocator noise back on the exact thread #706 is trying to
    /// keep quiet.
    pub(super) fn take_pending_tx_into(&self, out: &mut VecDeque<TxRequest>) {
        if self.pending_tx.is_empty() {
            return;
        }
        // SAFETY: `MpscInbox::pop` requires the single-consumer
        // invariant. The per-binding redirect inbox has exactly one
        // consumer — the owner worker — which is also the sole caller
        // of `take_pending_tx_into`. Enforced by convention (see the doc
        // comment on `pending_tx` in `BindingLiveState`).
        while let Some(req) = unsafe { self.pending_tx.pop() } {
            out.push_back(req);
        }
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
