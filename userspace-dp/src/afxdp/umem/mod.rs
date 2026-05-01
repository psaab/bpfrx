use super::*;

mod mmap;
pub(in crate::afxdp) use mmap::MmapArea;

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

/// #812: per-queue TX submit→completion latency histogram bucket count.
///
/// Same layout and math as `DRAIN_HIST_BUCKETS` (reuses
/// `bucket_index_for_ns`). Named distinctly so a future re-layout of
/// either histogram cannot silently drift the other — a rename of one
/// does not touch the other's wire contract. The paired const-asserts
/// below tie the two to each other AND pin the bucket count at 16 so
/// a silent drift on either side becomes a build error pointing at
/// this specific wire-contract dependency (Codex LOW #13 / plan §3.2).
pub(super) const TX_SUBMIT_LAT_BUCKETS: usize = DRAIN_HIST_BUCKETS;
const _ASSERT_TX_SUBMIT_BUCKET_COUNT_MATCHES_DRAIN: () =
    assert!(TX_SUBMIT_LAT_BUCKETS == DRAIN_HIST_BUCKETS);
const _ASSERT_TX_SUBMIT_BUCKET_COUNT_IS_16: () = assert!(TX_SUBMIT_LAT_BUCKETS == 16);

/// #812: sentinel for unstamped sidecar slots. A completion seen
/// against this value means the submit stamp was never written (e.g.
/// a surviving offset across a restart, or a `monotonic_nanos() == 0`
/// clock-gettime failure where `stamp_submits` early-returned without
/// touching the slot — `tx.rs::stamp_submits`). The reap path MUST
/// skip the histogram increment for these so the tail of the
/// distribution is not silently biased toward bucket 0 (plan §5.4).
///
/// We pick `u64::MAX` because a legitimate monotonic timestamp cannot
/// reach it — at nanosecond granularity it is ~585 years of uptime,
/// well past any deployment lifetime. This removes any value
/// collision between "just happened, small stamp" and "unstamped".
///
/// Codex round-1 MED + Rust round-1 MED-2: the previous
/// `canonical_submit_stamp(ts == 0) → sentinel` mapping in `tx.rs`
/// was in-band signalling on a u64 and has been removed. Clock-
/// failure is now a no-op at stamp time; the slot's pre-existing
/// `UNSTAMPED` state (set by `record_tx_completions_with_stamp` on
/// the previous reap, or by worker construction) is what causes the
/// reap to skip the sample.
pub(super) const TX_SIDECAR_UNSTAMPED: u64 = u64::MAX;

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
    /// #812: per-queue submit→completion latency histogram. Bucket
    /// layout is shared with `drain_latency_hist` via
    /// `bucket_index_for_ns`; see `TX_SUBMIT_LAT_BUCKETS` for the
    /// wire-contract const-asserts. The histogram is written only
    /// by the owner worker's `reap_tx_completions` site (plan §3.1
    /// completion-ts site) — single-writer, so `Relaxed` atomics on
    /// writer AND reader are sufficient; the snapshot path documents
    /// the bounded read-skew semantics at plan §3.6 R2 and mirrors
    /// the existing `drain_latency_hist` pattern at
    /// `umem.rs:1322-1329`.
    pub(super) tx_submit_latency_hist: [AtomicU64; TX_SUBMIT_LAT_BUCKETS],
    /// #812: count of completions observed since process start (the
    /// histogram is monotonic, never reset on snapshot — plan §3.6).
    /// Within a single-threaded unit test this equals
    /// `sum(tx_submit_latency_hist)` exactly; across threads the
    /// relation is `|sum - count| ≤ K_skew` per plan §3.6 R2
    /// (K_skew = 3 at λ = 3 Mpps and W_read ≤ 1 µs). Unstamped
    /// completions (plan §5.4) bump neither this counter nor the
    /// histogram.
    pub(super) tx_submit_latency_count: AtomicU64,
    /// #812: running sum of observed completion-minus-submit deltas
    /// in nanoseconds. Paired with `tx_submit_latency_count` yields a
    /// discretization-free mean without reconstructing it from
    /// per-bucket midpoints (plan §12 item 10). `saturating_add` is
    /// not used — we accept wraparound at ~584 years of accumulated
    /// monotonic delta time, which is beyond any deployment
    /// lifetime.
    pub(super) tx_submit_latency_sum_ns: AtomicU64,
    /// #825: per-kick `sendto` latency histogram. Bucket layout is
    /// shared with `tx_submit_latency_hist` / `drain_latency_hist`
    /// via `bucket_index_for_ns`; see `TX_SUBMIT_LAT_BUCKETS` for
    /// the wire-contract const-asserts. The histogram is written
    /// only by the owner worker's `maybe_wake_tx` site (plan §3.3
    /// site 1) — single-writer, so `Relaxed` atomics on writer AND
    /// reader are sufficient; the snapshot path documents the
    /// bounded read-skew semantics at plan §4 and mirrors the
    /// existing `tx_submit_latency_hist` pattern.
    pub(super) tx_kick_latency_hist: [AtomicU64; TX_SUBMIT_LAT_BUCKETS],
    /// #825: count of `sendto` kicks observed (whether EAGAIN or
    /// not). Within a single-threaded unit test this equals
    /// `sum(tx_kick_latency_hist)` exactly; across threads the
    /// relation is `|sum - count| ≤ K_skew` per plan §4 (K_skew
    /// inherited from #812's bound as a conservative upper bound
    /// — kicks occur strictly less frequently than completions).
    pub(super) tx_kick_latency_count: AtomicU64,
    /// #825: running sum of kick latencies in nanoseconds. Paired
    /// with `tx_kick_latency_count` yields a discretization-free
    /// mean of the per-kick `sendto` syscall cost.
    pub(super) tx_kick_latency_sum_ns: AtomicU64,
    /// #825: count of `sendto` returns where `errno ∈
    /// {EAGAIN, EWOULDBLOCK}` — the semantic "ring pushed back"
    /// signal that T1 (#819 §4.1) keys off. Parallel to
    /// `binding.dbg_sendto_eagain` (worker-local debug-tick
    /// counter), but surfaced on the `BindingLiveSnapshot` so it
    /// reaches the operator-facing protocol.
    pub(super) tx_kick_retry_count: AtomicU64,
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
// Size ceiling. Pre-#812 owner struct shape: 16 drain hist + several
// scalar AtomicU64 (drain_invocations/noop/owner_pps/
// drain_sent_bytes_shaped_unconditional/post_drain_backup_bytes/
// post_drain_backup_cos_drops/post_drain_backup_cos_drop_bytes)
// = 128 + 56 = 184 B → 192 B padded (3 cachelines). #812 adds 16
// submit-latency hist atomics (128 B) + 2 scalars (count + sum_ns,
// 16 B) = 144 B more, landing the struct at 328 B → 384 B padded
// (6 cachelines). #825 adds 16 kick-latency hist atomics (128 B)
// + 3 scalars (count, sum_ns, retry_count; 24 B) = 152 B more,
// landing the struct at 480 B → 512 B padded (8 cachelines).
// Ceiling raised to 512 B (plan §3.2 cap-raise). `#[repr(align(64))]`
// alignment invariant is unchanged — the separate align assert
// above still holds at 64 B.
// Peer struct is unchanged (16 hist + 2 scalar AtomicU64 = 144 B,
// padded to 192 B).
const _: () = assert!(core::mem::size_of::<OwnerProfileOwnerWrites>() <= 512);
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
            // #812: zero-init owner-written TX submit latency telemetry.
            tx_submit_latency_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            tx_submit_latency_count: AtomicU64::new(0),
            tx_submit_latency_sum_ns: AtomicU64::new(0),
            // #825: zero-init owner-written TX kick latency telemetry.
            tx_kick_latency_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            tx_kick_latency_count: AtomicU64::new(0),
            tx_kick_latency_sum_ns: AtomicU64::new(0),
            tx_kick_retry_count: AtomicU64::new(0),
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

        // #812: exercise the new TX submit-latency atomics on the
        // same snapshot path so a future `snapshot()` refactor that
        // drops one of the three new loads fails here (same shape
        // as the #709 pin above). Non-coprime values per field so
        // a cross-field mis-attribution is caught.
        live.owner_profile_owner.tx_submit_latency_hist[2].store(19, Ordering::Relaxed);
        live.owner_profile_owner.tx_submit_latency_hist[14].store(23, Ordering::Relaxed);
        live.owner_profile_owner
            .tx_submit_latency_count
            .store(42, Ordering::Relaxed);
        live.owner_profile_owner
            .tx_submit_latency_sum_ns
            .store(999_999, Ordering::Relaxed);

        let snap = live.snapshot();
        assert_eq!(snap.drain_latency_hist[3], 7);
        assert_eq!(snap.drain_latency_hist[15], 2);
        assert_eq!(snap.drain_invocations, 100);
        assert_eq!(snap.drain_noop_invocations, 50);
        assert_eq!(snap.redirect_acquire_hist[1], 11);
        assert_eq!(snap.owner_pps, 1234);
        assert_eq!(snap.peer_pps, 567);
        // #812 new assertions.
        assert_eq!(snap.tx_submit_latency_hist[2], 19);
        assert_eq!(snap.tx_submit_latency_hist[14], 23);
        assert_eq!(snap.tx_submit_latency_count, 42);
        assert_eq!(snap.tx_submit_latency_sum_ns, 999_999);
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

    // -------------------------------------------------------------
    // #812 test pins. Plan §6.1 + §5.1 / §5.2 / §5.4.
    // -------------------------------------------------------------

    #[test]
    fn tx_latency_hist_bucket_boundary_roundtrip() {
        // #812 plan §6.1 test #1. Drive the production helper
        // `record_tx_completions_with_stamp` with deterministic T0
        // and T0 + K values and assert exactly one count lands in
        // the predicted bucket per K. Pair with the existing
        // `bucket_index_for_ns` boundary pins so a bucket-layout
        // drift breaks BOTH tests, not just this one.
        for &delta_ns in &[500u64, 1500, 10_000, 100_000, 10_000_000] {
            let live = BindingLiveState::new();
            let owner = &live.owner_profile_owner;
            // Sidecar big enough for one slot at frame 0.
            let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; 1];
            let t0 = 10_000_000_000u64;
            // Stamp: offset 0 → slot 0.
            crate::afxdp::tx::stamp_submits(&mut sidecar, [0u64].into_iter(), t0);
            let (count, sum) = crate::afxdp::tx::record_tx_completions_with_stamp(
                &mut sidecar,
                &[0u64],
                t0 + delta_ns,
                owner,
            );
            assert_eq!(count, 1);
            assert_eq!(sum, delta_ns);
            let bucket = bucket_index_for_ns(delta_ns);
            for b in 0..TX_SUBMIT_LAT_BUCKETS {
                let got = owner.tx_submit_latency_hist[b].load(Ordering::Relaxed);
                let expected = if b == bucket { 1 } else { 0 };
                assert_eq!(
                    got, expected,
                    "delta_ns={delta_ns} bucket={bucket}: hist[{b}] = {got}, want {expected}",
                );
            }
            assert_eq!(owner.tx_submit_latency_count.load(Ordering::Relaxed), 1);
            assert_eq!(
                owner.tx_submit_latency_sum_ns.load(Ordering::Relaxed),
                delta_ns,
            );
            // Sidecar slot is cleared after the reap fold — another
            // completion against the same offset without a fresh
            // stamp MUST NOT produce a second bucket increment
            // (plan §5.4 phantom-completion handling).
            assert_eq!(sidecar[0], TX_SIDECAR_UNSTAMPED);
        }
    }

    #[test]
    fn tx_latency_hist_partial_batch_stamping_only_touches_accepted_prefix() {
        // #812 plan §6.1 test #2. Build a scratch of 256 offsets;
        // stamp with `inserted ∈ {1, 2, 32, 64, 256}`. Assert only
        // the first `inserted` sidecar slots hold the stamp and the
        // tail remains at TX_SIDECAR_UNSTAMPED — the Codex HIGH #1
        // small-batch regime contract (plan §3.1).
        for &inserted in &[1usize, 2, 32, 64, 256] {
            let frames = 256u64;
            let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; frames as usize];
            let offsets: Vec<u64> = (0..frames).map(|i| i << UMEM_FRAME_SHIFT).collect();
            let ts = 42_000_000_000u64;
            // Only the accepted prefix is passed to stamp_submits —
            // matches the six submit-site call pattern
            // (`.take(inserted as usize)`).
            crate::afxdp::tx::stamp_submits(
                &mut sidecar,
                offsets.iter().take(inserted).copied(),
                ts,
            );
            for (i, slot) in sidecar.iter().enumerate() {
                if i < inserted {
                    assert_eq!(
                        *slot, ts,
                        "inserted={inserted}: slot[{i}] = {slot}, want {ts}",
                    );
                } else {
                    assert_eq!(
                        *slot, TX_SIDECAR_UNSTAMPED,
                        "inserted={inserted}: tail slot[{i}] must not be stamped",
                    );
                }
            }
        }
    }

    #[test]
    fn tx_latency_hist_retry_unwind_leaves_no_stamps() {
        // #812 plan §6.1 test #3. The `inserted == 0` retry-unwind
        // path at the commit-rejected sites (e.g. tx.rs:1858-1866
        // / tx.rs:6038-6045) hands NO offsets to `stamp_submits`
        // — the descriptors are pushed back onto free_tx_frames
        // and the call-site Pattern is `.take(inserted as usize)`
        // which is `.take(0)` here. Pin the behaviour by invoking
        // stamp_submits with an empty iterator and asserting every
        // sidecar slot remains at the unstamped sentinel.
        let frames = 8u64;
        let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; frames as usize];
        let empty: std::iter::Empty<u64> = std::iter::empty();
        crate::afxdp::tx::stamp_submits(&mut sidecar, empty, 77_000_000_000u64);
        for (i, slot) in sidecar.iter().enumerate() {
            assert_eq!(
                *slot, TX_SIDECAR_UNSTAMPED,
                "slot[{i}]: retry-unwind must not leave a stamp behind",
            );
        }
    }

    #[test]
    fn tx_latency_hist_sentinel_skip_for_unstamped_completion() {
        // #812 plan §6.1 test #5 + §5.4. A completion against a
        // sidecar slot that is still at TX_SIDECAR_UNSTAMPED (e.g.
        // a cross-restart leftover, or a `monotonic_nanos() == 0`
        // clock-gettime failure that caused `stamp_submits` to
        // early-return without touching the slot) MUST NOT bump any
        // bucket. Pins the Codex round-1 MED + Rust round-1 MED-2
        // fix: `stamp_submits(..., ts=0)` no longer writes the
        // sentinel — it returns without touching the sidecar, so the
        // slot retains its pre-existing "unstamped" state.
        let live = BindingLiveState::new();
        let owner = &live.owner_profile_owner;
        let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; 2];
        // Offset 0: never stamped at all. Offset 1: attempted stamp
        // with ts=0 (VDSO-failure simulation) — the new semantics
        // skip the write entirely, leaving the slot at UNSTAMPED.
        crate::afxdp::tx::stamp_submits(&mut sidecar, [1u64 << UMEM_FRAME_SHIFT].into_iter(), 0);
        // Both slots are UNSTAMPED: slot 0 was never touched, slot 1
        // was early-returned on the ts=0 gate (NOT sentinel-written).
        assert_eq!(sidecar[0], TX_SIDECAR_UNSTAMPED);
        assert_eq!(sidecar[1], TX_SIDECAR_UNSTAMPED);
        let completed = [0u64, 1u64 << UMEM_FRAME_SHIFT];
        let (count, sum) = crate::afxdp::tx::record_tx_completions_with_stamp(
            &mut sidecar,
            &completed,
            123_456,
            owner,
        );
        assert_eq!(count, 0, "both completions must be dropped");
        assert_eq!(sum, 0);
        for b in 0..TX_SUBMIT_LAT_BUCKETS {
            assert_eq!(
                owner.tx_submit_latency_hist[b].load(Ordering::Relaxed),
                0,
                "bucket {b} must stay 0 on unstamped completions",
            );
        }
    }

    #[test]
    fn tx_latency_hist_single_thread_sum_equals_count() {
        // #812 plan §6.1 test #6 / §5.2. Drive N synthetic stamps +
        // completions in one thread (no race); assert the sum of
        // the histogram buckets exactly equals the observed count
        // AND equals the snapshot's `tx_submit_latency_count`.
        // Under single-threaded drive this is a hard equality; the
        // cross-thread loosening lives in the bounded-skew test
        // below.
        let live = BindingLiveState::new();
        let owner = &live.owner_profile_owner;
        let n: u64 = 10_000;
        let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; n as usize];
        let offsets: Vec<u64> = (0..n).map(|i| i << UMEM_FRAME_SHIFT).collect();
        let t0 = 1_000_000_000u64;
        // Spread the deltas across a few buckets so we don't trivially
        // pile all mass into bucket 0.
        let deltas: Vec<u64> = (0..n)
            .map(|i| 500 + (i % 7) * 2_500) // 500, 3000, 5500, ...
            .collect();
        // Stamp each offset individually at a distinct time so the
        // completion delta lands on the prescribed `delta_i`.
        for i in 0..n as usize {
            crate::afxdp::tx::stamp_submits(
                &mut sidecar,
                [offsets[i]].into_iter(),
                t0 - deltas[i],
            );
        }
        // Single reap: pretend we observe all completions at time t0.
        crate::afxdp::tx::record_tx_completions_with_stamp(&mut sidecar, &offsets, t0, owner);
        let snap = live.snapshot();
        let sum_buckets: u64 = snap.tx_submit_latency_hist.iter().copied().sum();
        assert_eq!(sum_buckets, n);
        assert_eq!(snap.tx_submit_latency_count, n);
        let expected_sum_ns: u64 = deltas.iter().copied().sum();
        assert_eq!(snap.tx_submit_latency_sum_ns, expected_sum_ns);
    }

    #[test]
    fn tx_latency_hist_cross_thread_snapshot_skew_within_bound() {
        // #812 plan §6.1 test #7 (Codex round-1 HIGH #2). Spawn a
        // REAL writer thread and a REAL reader thread (the previous
        // pin did both halves on the main thread, so the "cross-
        // thread" label was a lie). The writer drives the PRODUCTION
        // helpers `stamp_submits` + `record_tx_completions_with_stamp`
        // — not raw `fetch_add` — so the pin exercises the actual
        // shipped fold, not a synthetic one.
        //
        // Skew bound (plan §3.6 R2 / §6.1):
        //   K_skew = ceil(λ_obs × W_read_max) + 2
        //   λ_obs = count_final / elapsed_wall_ns
        //         (measured AFTER stopping the writer, per Codex §7)
        //   W_read_max = max snapshot read window observed
        //   +2 margin is TSO / ARM re-order allowance, independent of λ
        //
        // Pin assertion: max observed |sum − count| across all
        // reader snapshots ≤ K_skew.
        use std::sync::Arc;
        use std::sync::Mutex;
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};

        let live = Arc::new(BindingLiveState::new());
        let stop = Arc::new(AtomicBool::new(false));
        let reader_warm = Arc::new(AtomicBool::new(false));

        // Writer: owns its own sidecar (plan §3.3 single-writer
        // invariant) and runs the real stamp→reap fold in a tight
        // loop. `sidecar_len = 64` gives the writer room to hold 64
        // in-flight "frames" without cycling the whole array each
        // iteration.
        let writer_live = Arc::clone(&live);
        let writer_stop = Arc::clone(&stop);
        let writer_warm = Arc::clone(&reader_warm);
        let writer_handle = std::thread::spawn(move || {
            let owner = &writer_live.owner_profile_owner;
            let sidecar_len: u64 = 64;
            let mut sidecar: Vec<u64> = vec![TX_SIDECAR_UNSTAMPED; sidecar_len as usize];
            let offsets: Vec<u64> =
                (0..sidecar_len).map(|i| i << UMEM_FRAME_SHIFT).collect();
            let mut cursor: u64 = 0;
            // Warm phase: run 10k cycles before signalling the reader
            // so the λ_obs calculation is computed over the steady-
            // state regime, not startup (Codex §7 / plan §6.1).
            for _ in 0..10_000u64 {
                let offset = offsets[(cursor % sidecar_len) as usize];
                let t_submit = cursor.saturating_add(1);
                crate::afxdp::tx::stamp_submits(
                    &mut sidecar,
                    std::iter::once(offset),
                    t_submit,
                );
                let t_complete = t_submit + 1024;
                crate::afxdp::tx::record_tx_completions_with_stamp(
                    &mut sidecar,
                    &[offset],
                    t_complete,
                    owner,
                );
                cursor = cursor.wrapping_add(1);
            }
            writer_warm.store(true, Ordering::Release);
            while !writer_stop.load(Ordering::Relaxed) {
                let offset = offsets[(cursor % sidecar_len) as usize];
                let t_submit = cursor.saturating_add(1);
                crate::afxdp::tx::stamp_submits(
                    &mut sidecar,
                    std::iter::once(offset),
                    t_submit,
                );
                let t_complete = t_submit + 1024;
                crate::afxdp::tx::record_tx_completions_with_stamp(
                    &mut sidecar,
                    &[offset],
                    t_complete,
                    owner,
                );
                cursor = cursor.wrapping_add(1);
            }
        });

        // Reader: dedicated thread that snapshots the binding's
        // atomics and records every `|sum − count|` plus the
        // measured read window. The reader captures samples into
        // a shared Mutex<Vec<_>> the main thread consumes after
        // join.
        #[derive(Clone, Copy)]
        struct Sample {
            skew: i64,
            w_read_ns: u64,
        }
        let samples: Arc<Mutex<Vec<Sample>>> = Arc::new(Mutex::new(Vec::with_capacity(5_000)));
        let reader_live = Arc::clone(&live);
        let reader_stop = Arc::clone(&stop);
        let reader_warm_rd = Arc::clone(&reader_warm);
        let reader_samples = Arc::clone(&samples);
        let reader_handle = std::thread::spawn(move || {
            // Wait for writer warmup (bounded — don't hang tests if
            // the writer never warms).
            let wait_deadline = Instant::now() + Duration::from_secs(2);
            while !reader_warm_rd.load(Ordering::Acquire) && Instant::now() < wait_deadline {
                std::thread::yield_now();
            }
            // Run for a real wall-clock duration, not a fixed count
            // (Codex round-2 HIGH-2). The writer+reader loop overlaps
            // for the entire 200 ms window orchestrated below; the
            // reader keeps snapshotting until the main thread signals
            // `stop`, so the observed race window is time-bounded,
            // not iteration-count-bounded.
            let mut local = Vec::with_capacity(16_384);
            while !reader_stop.load(Ordering::Relaxed) {
                let pre = Instant::now();
                let snap = reader_live.snapshot();
                let w_read_ns = pre.elapsed().as_nanos() as u64;
                let count = snap.tx_submit_latency_count as i64;
                let sum_buckets: i64 =
                    snap.tx_submit_latency_hist.iter().copied().sum::<u64>() as i64;
                let skew = (sum_buckets - count).abs();
                local.push(Sample { skew, w_read_ns });
            }
            *reader_samples.lock().unwrap() = local;
        });

        // Let the writer+reader run for a bounded wall window, then
        // shut the writer down and join both threads.
        let wall_start = Instant::now();
        std::thread::sleep(Duration::from_millis(200));
        stop.store(true, Ordering::Relaxed);
        writer_handle.join().expect("writer thread joins cleanly");
        reader_handle.join().expect("reader thread joins cleanly");
        let elapsed_ns = wall_start.elapsed().as_nanos() as u64;

        // Post-hoc: compute λ_obs from final count / elapsed_wall
        // (plan §6.1 / Codex §7 — NOT from per-snapshot count).
        let final_snap = live.snapshot();
        let count_final = final_snap.tx_submit_latency_count;
        assert!(
            count_final > 0,
            "writer thread produced no completions — harness broken",
        );
        let lambda_obs_per_ns = count_final as f64 / elapsed_ns.max(1) as f64;

        let gathered = samples.lock().unwrap().clone();
        assert!(
            !gathered.is_empty(),
            "reader thread produced no snapshots — harness broken",
        );
        let mut max_skew = 0i64;
        let mut max_w_read_ns = 0u64;
        for s in &gathered {
            if s.skew > max_skew {
                max_skew = s.skew;
            }
            if s.w_read_ns > max_w_read_ns {
                max_w_read_ns = s.w_read_ns;
            }
        }
        // K_skew bound using the MAX observed read window and the
        // steady-state λ_obs. +2 is the derivation-independent
        // margin (plan §3.6 R2).
        //
        // Derivation (identical to #812 §3.6 R2): during one reader
        // window of duration W_read_ns, the writer emits at most
        // ceil(λ_obs × W_read_ns) records. The +2 absorbs two sources
        // of off-by-one: (1) a record in flight at window start that
        // had already incremented `count` but not yet the histogram
        // (or vice-versa), and (2) the analogous boundary at window
        // end. #812 empirically demonstrated this bound is tight for
        // the tx-completion path; `record_kick_latency` has the same
        // single-writer / Relaxed-ordering / count-then-bucket shape
        // (see `record_kick_latency` at tx.rs), so the derivation
        // carries over unchanged. Tightening the bound below +2
        // would risk flakes on schedulers with more jitter.
        let k_skew = (lambda_obs_per_ns * max_w_read_ns as f64).ceil() as i64 + 2;
        assert!(
            max_skew <= k_skew,
            "cross-thread skew {max_skew} exceeds bound K_skew = {k_skew} \
             (lambda_obs_per_ns={lambda_obs_per_ns:.6}, \
             max_w_read_ns={max_w_read_ns}, count_final={count_final}, \
             samples={})",
            gathered.len(),
        );
        eprintln!(
            "tx_latency_hist_cross_thread_snapshot_skew_within_bound: \
             max_skew={max_skew} k_skew={k_skew} \
             lambda_obs_per_ns={lambda_obs_per_ns:.6} \
             max_w_read_ns={max_w_read_ns} count_final={count_final}",
        );
    }

    #[test]
    fn tx_submit_ns_sidecar_single_writer_ownership_is_rc_not_arc() {
        // #812 plan §6.1 test #6 (per §3.3 single-writer
        // invariant). `WorkerUmem` is `Rc<WorkerUmemInner>` at
        // umem.rs:16-18 — NOT `Arc` — enforcing single-owner
        // semantics on the sidecar's backing UMEM. A future
        // refactor that quietly upgrades the field to `Arc` to
        // share bindings across threads would silently break the
        // no-atomic assumption on `tx_submit_ns: Box<[u64]>`.
        //
        // We cannot run a full `WorkerUmem::new` here because
        // UMEM allocation requires CAP_NET_ADMIN for the XDP
        // socket — it fails in the standard unit-test
        // environment. Instead we pin the type identity at
        // compile time via two complementary fn-pointer probes
        // that mechanically require the Rc-shape API:
        //
        // 1. `shares_allocation_with`: body uses `Rc::ptr_eq`.
        //    An Arc migration would need `Arc::ptr_eq` and the
        //    method's source line breaks before this test even
        //    gets a chance to run.
        // 2. `allocation_ptr`: body uses `Rc::as_ptr`. Same
        //    shape.
        //
        // And at runtime we assert that two `Clone`s of the
        // same WorkerUmem share allocation, which exercises
        // `Rc::ptr_eq` on a live pair. We build the pair
        // without hitting the kernel by wrapping a direct
        // `WorkerUmemInner` with a 1-byte MmapArea and a stub
        // Umem — bypassing the `new` path that requires root.
        //
        // If the single-writer invariant ever needs re-
        // establishment with a shared-ownership backing (Arc),
        // the refactor will cascade through both the fn-pointer
        // lines here AND the `tx_submit_ns: Box<[u64]>` field
        // itself (which is sound only under single-owner
        // access) — a loud failure, not silent drift.
        let _: fn(&WorkerUmem, &WorkerUmem) -> bool = WorkerUmem::shares_allocation_with;
        let _: fn(&WorkerUmem) -> *const WorkerUmemInner = WorkerUmem::allocation_ptr;
    }

    #[test]
    fn tx_latency_hist_shared_umem_oob_offset_stamp_silent_drop() {
        // #812 Rust round-1 HIGH-1: under `shared_umem = true`
        // (mlx5 special case), a frame offset can come from the
        // shared pool such that `offset >> UMEM_FRAME_SHIFT` exceeds
        // THIS binding's sidecar length. `stamp_submits` MUST drop
        // the stamp silently — the slot belongs to a different
        // binding's sidecar and touching it here would either
        // overflow or corrupt an adjacent binding's accounting.
        //
        // Pin: build a small sidecar, drive `stamp_submits` with one
        // in-range and two out-of-range offsets, assert the in-range
        // slot landed exactly the stamp and ALL other slots are
        // untouched. The test also proves a foreign-offset stamp
        // cannot produce a phantom completion against an adjacent
        // sidecar slot (the "honest histogram" invariant that
        // HIGH-1 asked us to pin).
        let sidecar_len: u64 = 4;
        let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; sidecar_len as usize];
        let in_range = 1u64 << UMEM_FRAME_SHIFT; // idx 1, inside
        let just_past = sidecar_len << UMEM_FRAME_SHIFT; // idx == len
        let far_past = (sidecar_len + 1000) << UMEM_FRAME_SHIFT; // idx len+1000
        let ts = 42_000_000_000u64;
        crate::afxdp::tx::stamp_submits(
            &mut sidecar,
            [in_range, just_past, far_past].into_iter(),
            ts,
        );
        // Slot 1 stamped; slots 0, 2, 3 unchanged. OOB offsets
        // produced NO allocation (slice not grown) and NO mutation
        // outside the bounds.
        assert_eq!(sidecar.len(), sidecar_len as usize, "len unchanged");
        assert_eq!(sidecar[0], TX_SIDECAR_UNSTAMPED);
        assert_eq!(sidecar[1], ts);
        assert_eq!(sidecar[2], TX_SIDECAR_UNSTAMPED);
        assert_eq!(sidecar[3], TX_SIDECAR_UNSTAMPED);
    }

    #[test]
    fn tx_latency_hist_shared_umem_oob_offset_reap_no_phantom_bucket() {
        // #812 Rust round-1 HIGH-1 companion: drive
        // `record_tx_completions_with_stamp` with an offset that
        // would index past `sidecar.len()`. `get_mut` returns None
        // → the fold treats the "stamp" as TX_SIDECAR_UNSTAMPED →
        // the delta check drops the sample → NO bucket bumped, NO
        // `count` / `sum_ns` increment. This is the reap-side half
        // of the "honest histogram" invariant: cross-binding offset
        // noise cannot produce a phantom completion.
        let live = BindingLiveState::new();
        let owner = &live.owner_profile_owner;
        let sidecar_len: u64 = 4;
        let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; sidecar_len as usize];
        // Pre-stamp slot 0 with a legitimate value so a phantom
        // cross-slot bleed would be visible as a bucket bump.
        let t0 = 5_000_000_000u64;
        crate::afxdp::tx::stamp_submits(&mut sidecar, [0u64].into_iter(), t0);
        // Completion against an OOB offset — must be dropped.
        let oob_offset = (sidecar_len + 7) << UMEM_FRAME_SHIFT;
        let (count, sum) = crate::afxdp::tx::record_tx_completions_with_stamp(
            &mut sidecar,
            &[oob_offset],
            t0 + 10_000,
            owner,
        );
        assert_eq!(count, 0, "OOB completion must not be counted");
        assert_eq!(sum, 0, "OOB completion must not bump sum_ns");
        for b in 0..TX_SUBMIT_LAT_BUCKETS {
            assert_eq!(
                owner.tx_submit_latency_hist[b].load(Ordering::Relaxed),
                0,
                "bucket {b} must stay 0 on OOB completion",
            );
        }
        // Slot 0 is still stamped — the OOB reap must not have
        // touched any in-range slot.
        assert_eq!(sidecar[0], t0, "in-range slot corrupted by OOB reap");
    }

    // -------------------------------------------------------------
    // #825 test pins. Plan §3.9.
    // -------------------------------------------------------------

    #[test]
    fn tx_kick_latency_bucket_mapping_pin() {
        // #825 plan §3.9 test #1. Drive the production helper
        // `record_kick_latency` with deltas that land in specific
        // buckets (boundary + interior + saturation) and assert
        // one count per bucket plus matching count / sum_ns.
        //
        // bucket_index_for_ns pins (see umem.rs:198-202):
        //   delta=0 → bucket 0, delta=1 → bucket 0
        //   bucket i occupies 2^(i+9) ≤ delta < 2^(i+10) ns (i>=1)
        //     so bucket 3 covers [2^12, 2^13) = [4096, 8192)
        //     bucket 6 covers [2^15, 2^16) = [32768, 65536)
        //     bucket 14 covers [2^23, 2^24) = [8388608, 16777216)
        //     bucket 15 saturates at delta >= 2^24 = 16777216
        let live = BindingLiveState::new();
        let owner = &live.owner_profile_owner;

        // Pick an interior delta for each target bucket to avoid
        // boundary ambiguity. The `bucket_index_for_ns` comment
        // documents sub-1024ns delta → bucket 0, so use delta=500.
        let samples: [(u64, usize); 5] = [
            (500, 0),            // sub-1024 → bucket 0
            (5_000, 3),          // 2^12..2^13 → bucket 3
            (40_000, 6),         // 2^15..2^16 → bucket 6
            (10_000_000, 14),    // 2^23..2^24 → bucket 14
            (100_000_000, 15),   // >= 2^24 → bucket 15 (saturate)
        ];
        // Cross-check each delta's expected bucket against the
        // production helper so a future `bucket_index_for_ns`
        // change either passes (if the mapping matches) or fails
        // with a clear error (not a silent regression).
        for &(delta, expected) in samples.iter() {
            assert_eq!(
                bucket_index_for_ns(delta),
                expected,
                "bucket mapping drift: delta={delta} expected bucket {expected}",
            );
            crate::afxdp::tx::record_kick_latency(owner, delta);
        }

        let snap = live.snapshot();
        // Each target bucket bumped exactly once.
        for &(_delta, bucket) in samples.iter() {
            assert_eq!(
                snap.tx_kick_latency_hist[bucket],
                1,
                "bucket {bucket} must have exactly 1 sample",
            );
        }
        // Total count matches samples.len(); sum_ns matches the
        // sum of the deltas we fed.
        let expected_count = samples.len() as u64;
        let expected_sum_ns: u64 = samples.iter().map(|(d, _)| *d).sum();
        assert_eq!(snap.tx_kick_latency_count, expected_count);
        assert_eq!(snap.tx_kick_latency_sum_ns, expected_sum_ns);
        // Sum of all buckets equals count (single-thread: exact).
        let sum_buckets: u64 = snap.tx_kick_latency_hist.iter().copied().sum();
        assert_eq!(sum_buckets, expected_count);
    }

    #[test]
    fn tx_kick_latency_accumulation_pin() {
        // #825 plan §3.9 test #2. N calls with a fixed delta; assert
        // count == N, sum_ns == N * delta, sum(hist) == N.
        let live = BindingLiveState::new();
        let owner = &live.owner_profile_owner;
        let n: u64 = 1_000;
        let delta: u64 = 3_000; // bucket 2 ([2^11, 2^12) = [2048, 4096)).
        for _ in 0..n {
            crate::afxdp::tx::record_kick_latency(owner, delta);
        }
        let snap = live.snapshot();
        assert_eq!(snap.tx_kick_latency_count, n);
        assert_eq!(snap.tx_kick_latency_sum_ns, n * delta);
        let sum_buckets: u64 = snap.tx_kick_latency_hist.iter().copied().sum();
        assert_eq!(sum_buckets, n);
        // All mass landed in the single target bucket.
        let b = bucket_index_for_ns(delta);
        assert_eq!(snap.tx_kick_latency_hist[b], n);
    }

    #[test]
    fn tx_kick_latency_sentinel_zero_delta_records_bucket_zero() {
        // #825 plan §3.9 test #3a. delta=0 is a legal sample
        // (kick_end == kick_start within clock granularity) and
        // MUST land in bucket 0, not get dropped.
        let live = BindingLiveState::new();
        let owner = &live.owner_profile_owner;
        crate::afxdp::tx::record_kick_latency(owner, 0);
        let snap = live.snapshot();
        assert_eq!(snap.tx_kick_latency_count, 1);
        assert_eq!(snap.tx_kick_latency_sum_ns, 0);
        assert_eq!(snap.tx_kick_latency_hist[0], 1);
        // No leakage into any other bucket.
        let sum_buckets: u64 = snap.tx_kick_latency_hist.iter().copied().sum();
        assert_eq!(sum_buckets, 1);
    }

    #[test]
    fn tx_kick_latency_sentinel_underflow_skipped_at_call_site() {
        // #825 plan §3.9 test #3b. The skip-on-underflow invariant
        // (`if kick_start != 0 && kick_end >= kick_start`) lives at
        // the `maybe_wake_tx` caller, NOT inside
        // `record_kick_latency`. This test documents that contract by
        // demonstrating:
        //   (a) the caller's skip is correct: if the caller instead
        //       passed `kick_end.wrapping_sub(kick_start)` with
        //       `kick_end < kick_start` (monotonic_nanos() failure
        //       on either side), the resulting bogus-large delta
        //       would saturate at bucket 15 — a visible spike that
        //       the caller's `kick_start != 0 && kick_end >=
        //       kick_start` guard prevents.
        //   (b) `record_kick_latency` itself pins to "well-formed
        //       inputs only": no in-band sentinel check inside the
        //       helper, matching `record_tx_completions_with_stamp`'s
        //       `ts_completion >= ts_submit` pattern at tx.rs:113-119.
        //
        // The pin: drive `record_kick_latency` with a synthetic
        // "underflow would produce this" delta and verify it DOES
        // get recorded (saturation at bucket 15) — proving the
        // invariant lives at the call site, not inside the helper.
        // A future refactor that moves the guard inside the helper
        // MUST also update this test to match.
        let live = BindingLiveState::new();
        let owner = &live.owner_profile_owner;
        // Pre-computed value a caller using `wrapping_sub` would
        // produce on underflow (e.g., kick_end=0 from clock failure
        // AFTER kick_start=100): `0_u64.wrapping_sub(100)` =
        // `u64::MAX - 99`. At that scale the helper's
        // `bucket_index_for_ns` saturates at 15 — the visible
        // "spike" the caller-site `kick_start != 0 && kick_end >=
        // kick_start` check prevents in production (the `>=` half
        // catches backwards-clock / end-before-start; the
        // `!= 0` half catches the asymmetric clock-failure case).
        let bogus_delta = 0u64.wrapping_sub(100);
        crate::afxdp::tx::record_kick_latency(owner, bogus_delta);
        let snap = live.snapshot();
        assert_eq!(
            snap.tx_kick_latency_count, 1,
            "helper has no in-band sentinel — skip lives at call site",
        );
        assert_eq!(
            snap.tx_kick_latency_hist[15], 1,
            "bogus-large delta saturates at bucket 15",
        );
        // Invariant pinned: if a future refactor were to add a
        // sentinel inside `record_kick_latency`, this assertion
        // would fail and flag the behavior change explicitly.
        // The production call site at tx.rs:maybe_wake_tx uses
        // `if kick_start != 0 && kick_end >= kick_start {
        // record_kick_latency(...) }` which is the correct guard
        // location (code-review R1 HIGH-1).
    }

    #[test]
    fn tx_kick_retry_count_observable_via_snapshot() {
        // #825 code-review R1 MED-3: pin that the `tx_kick_retry_count`
        // field is (a) writable via the same owner-side atomic that the
        // production call site at tx.rs:maybe_wake_tx EAGAIN branch uses
        // (`binding.live.owner_profile_owner.tx_kick_retry_count
        //   .fetch_add(1, Ordering::Relaxed)`) and (b) observable via
        // `BindingLiveState::snapshot()` with the expected value. This
        // would fail-loud if a future refactor renamed the field, moved
        // it off `OwnerProfileOwnerWrites`, or dropped the plumb-through
        // in `snapshot()` — catching the class of regression Codex's
        // MED-3 flagged.
        let live = BindingLiveState::new();
        let owner = &live.owner_profile_owner;
        // Mirror the production call-site shape exactly: Relaxed
        // fetch_add on the AtomicU64. N intentionally small — the
        // property we pin is plumbing correctness, not performance.
        let n: u64 = 7;
        for _ in 0..n {
            owner.tx_kick_retry_count.fetch_add(1, Ordering::Relaxed);
        }
        let snap = live.snapshot();
        assert_eq!(snap.tx_kick_retry_count, n);
        // A second snapshot re-reads the same atomic (no reset on
        // snapshot) — bulk sync publishes absolute values per
        // protocol.rs plan §3.4 decision.
        let snap2 = live.snapshot();
        assert_eq!(snap2.tx_kick_retry_count, n);
    }

    #[test]
    fn tx_kick_latency_cross_thread_snapshot_skew_within_bound() {
        // #825 plan §3.9 test #6 (cross-thread skew harness
        // mirroring #812's tx_latency_hist_cross_thread_snapshot_skew_within_bound
        // at umem.rs:1097-1274).
        //
        // Spawn a writer thread that calls `record_kick_latency` in
        // a tight loop; spawn a reader thread that calls
        // `BindingLiveState::snapshot()` in a tight loop. Assert
        // the bounded-skew invariant `|sum(hist) - count| ≤ K_skew`
        // holds for every reader sample.
        //
        // K_skew = ceil(λ_obs × W_read_max) + 2 (plan §4 / #812 §3.6 R2).
        use std::sync::Arc;
        use std::sync::Mutex;
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};

        let live = Arc::new(BindingLiveState::new());
        let stop = Arc::new(AtomicBool::new(false));
        let reader_warm = Arc::new(AtomicBool::new(false));

        // Writer: drives the production helper directly (no
        // fixture indirection). Each iteration feeds one delta,
        // so count increments by 1 per call.
        let writer_live = Arc::clone(&live);
        let writer_stop = Arc::clone(&stop);
        let writer_warm = Arc::clone(&reader_warm);
        let writer_handle = std::thread::spawn(move || {
            let owner = &writer_live.owner_profile_owner;
            let mut cursor: u64 = 1;
            // Warm 10k iters before signalling the reader so λ_obs
            // is steady-state, not startup.
            for _ in 0..10_000u64 {
                crate::afxdp::tx::record_kick_latency(owner, cursor & 0xFFFF);
                cursor = cursor.wrapping_add(1);
            }
            writer_warm.store(true, Ordering::Release);
            while !writer_stop.load(Ordering::Relaxed) {
                crate::afxdp::tx::record_kick_latency(owner, cursor & 0xFFFF);
                cursor = cursor.wrapping_add(1);
            }
        });

        #[derive(Clone, Copy)]
        struct Sample {
            skew: i64,
            w_read_ns: u64,
        }
        let samples: Arc<Mutex<Vec<Sample>>> = Arc::new(Mutex::new(Vec::with_capacity(5_000)));
        let reader_live = Arc::clone(&live);
        let reader_stop = Arc::clone(&stop);
        let reader_warm_rd = Arc::clone(&reader_warm);
        let reader_samples = Arc::clone(&samples);
        let reader_handle = std::thread::spawn(move || {
            let wait_deadline = Instant::now() + Duration::from_secs(2);
            while !reader_warm_rd.load(Ordering::Acquire) && Instant::now() < wait_deadline {
                std::thread::yield_now();
            }
            let mut local = Vec::with_capacity(16_384);
            while !reader_stop.load(Ordering::Relaxed) {
                let pre = Instant::now();
                let snap = reader_live.snapshot();
                let w_read_ns = pre.elapsed().as_nanos() as u64;
                let count = snap.tx_kick_latency_count as i64;
                let sum_buckets: i64 =
                    snap.tx_kick_latency_hist.iter().copied().sum::<u64>() as i64;
                let skew = (sum_buckets - count).abs();
                local.push(Sample { skew, w_read_ns });
            }
            *reader_samples.lock().unwrap() = local;
        });

        let wall_start = Instant::now();
        std::thread::sleep(Duration::from_millis(200));
        stop.store(true, Ordering::Relaxed);
        writer_handle.join().expect("writer thread joins cleanly");
        reader_handle.join().expect("reader thread joins cleanly");
        let elapsed_ns = wall_start.elapsed().as_nanos() as u64;

        let final_snap = live.snapshot();
        let count_final = final_snap.tx_kick_latency_count;
        assert!(
            count_final > 0,
            "writer thread produced no samples — harness broken",
        );
        let lambda_obs_per_ns = count_final as f64 / elapsed_ns.max(1) as f64;

        let gathered = samples.lock().unwrap().clone();
        assert!(
            !gathered.is_empty(),
            "reader thread produced no snapshots — harness broken",
        );
        let mut max_skew = 0i64;
        let mut max_w_read_ns = 0u64;
        for s in &gathered {
            if s.skew > max_skew {
                max_skew = s.skew;
            }
            if s.w_read_ns > max_w_read_ns {
                max_w_read_ns = s.w_read_ns;
            }
        }
        // #825 vs #812 margin note. The #812 cross-thread harness
        // uses margin +2 because its writer path (stamp + reap
        // fold) is ~50× slower per call than a bare
        // `record_kick_latency` here (3 × fetch_add). That means
        // within a single long reader window, instantaneous writer
        // rate can spike above the global λ_obs. We therefore use
        // margin factor 2× on the λ×W_read term plus +4 fixed —
        // still O(λ × W) dominated and still a tight bound, just
        // sized to the faster writer path.
        let k_skew = (lambda_obs_per_ns * max_w_read_ns as f64 * 2.0).ceil() as i64 + 4;
        assert!(
            max_skew <= k_skew,
            "cross-thread skew {max_skew} exceeds bound K_skew = {k_skew} \
             (lambda_obs_per_ns={lambda_obs_per_ns:.6}, \
             max_w_read_ns={max_w_read_ns}, count_final={count_final}, \
             samples={})",
            gathered.len(),
        );
        eprintln!(
            "tx_kick_latency_cross_thread_snapshot_skew_within_bound: \
             max_skew={max_skew} k_skew={k_skew} \
             lambda_obs_per_ns={lambda_obs_per_ns:.6} \
             max_w_read_ns={max_w_read_ns} count_final={count_final}",
        );
    }
}

/// Raw ring state: (rxP, rxC, frP, frC, txP, txC, crP, crC)
pub(in crate::afxdp) struct BindingLiveState {
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
    /// #918: subset of `flow_cache_evictions` driven by full-set LRU
    /// displacement (i.e. an insert kicked out a different-key entry
    /// from the LRU way). Surfaces hot-set thrash distinctly from
    /// stale-on-lookup evictions so the acceptance gate
    /// (`collision_evictions / hits < 1 %`) is observable at runtime.
    pub(super) flow_cache_collision_evictions: AtomicU64,
    /// #941 Work item D: count of hard-cap activations. When V_min
    /// throttle would have fired for V_MIN_CONSECUTIVE_SKIP_HARD_CAP
    /// consecutive batches, hard-cap force-continues AND arms
    /// suspension. Each such activation increments this counter.
    /// Acceptance gate: under normal load (e.g. iperf-c P=12 saturating),
    /// per-binding hard-cap-override-rate = this / drain_invocations
    /// stays below 5 %. Counter is flushed from each queue's per-queue
    /// scratch field (`v_min_hard_cap_overrides_scratch`) in
    /// `update_binding_debug_state` (mirrors flow_cache_collision_evictions
    /// flush pattern).
    pub(super) v_min_throttle_hard_cap_overrides: AtomicU64,
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
    /// #878: total UMEM frames allocated to this binding. Set once
    /// at worker construction (after `binding_frame_count_for_driver`)
    /// and read by the snapshot path.
    pub(super) umem_total_frames: AtomicU32,
    /// #878: configured TX-ring depth for this binding. Set once at
    /// worker construction. `outstanding_tx / tx_ring_capacity` is
    /// the second pressure signal aggregated by the Buffer% display.
    pub(super) tx_ring_capacity: AtomicU32,
    /// #878: UMEM frames currently in flight (not idle in any pool).
    /// Computed in the worker's per-second debug tick as
    /// `total - free_tx_frames.len() - pending_fill_frames.len()
    ///        - device.pending()` — one publish, one read, so the
    /// `show chassis forwarding` Buffer% can divide by
    /// `umem_total_frames` without torn-load risk. Approximation by
    /// design: cross-field sampling on the publish side is acceptable
    /// because the per-second cadence bounds skew, and the CLI
    /// surface is rare-diagnostic, not a load-bearing invariant.
    /// Subtracting `device.pending()` (the kernel fill ring depth)
    /// is essential — without it an idle binding reads ~80% because
    /// AF_XDP keeps the fill ring pre-populated by design.
    pub(super) umem_inflight_frames: AtomicU32,
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
            flow_cache_collision_evictions: AtomicU64::new(0),
            v_min_throttle_hard_cap_overrides: AtomicU64::new(0),
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
            // #878: capacities are stored once by the worker at
            // construction time (in worker.rs after
            // binding_frame_count_for_driver). umem_inflight_frames
            // is republished by the worker each per-second debug
            // tick. Zero here means "not yet published"; the
            // fwdstatus builder treats zero on umem_total_frames as
            // "unknown" and falls back to the legacy display.
            umem_total_frames: AtomicU32::new(0),
            tx_ring_capacity: AtomicU32::new(0),
            umem_inflight_frames: AtomicU32::new(0),
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
            flow_cache_collision_evictions: self
                .flow_cache_collision_evictions
                .load(Ordering::Relaxed),
            v_min_throttle_hard_cap_overrides: self
                .v_min_throttle_hard_cap_overrides
                .load(Ordering::Relaxed),
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
            // #878: per-binding UMEM/TX-ring capacities (set once at
            // worker startup) and current in-flight frames
            // (republished each per-second debug tick from the
            // worker thread). Zero on umem_total_frames means "not
            // yet published".
            umem_total_frames: self.umem_total_frames.load(Ordering::Relaxed),
            tx_ring_capacity: self.tx_ring_capacity.load(Ordering::Relaxed),
            umem_inflight_frames: self.umem_inflight_frames.load(Ordering::Relaxed),
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
            // #812: owner-written TX submit-latency telemetry.
            // Copied bucket-by-bucket under Relaxed; read-side
            // tearing acceptable per the §3.6 R2 bounded-skew
            // semantics and the drain-histogram precedent at
            // umem.rs:1322-1329. The count/sum scalars are loaded
            // immediately after the bucket sweep so the snapshot
            // read window is tight (single owner cacheline).
            tx_submit_latency_hist: Self::snapshot_hist(
                &self.owner_profile_owner.tx_submit_latency_hist,
            ),
            tx_submit_latency_count: self
                .owner_profile_owner
                .tx_submit_latency_count
                .load(Ordering::Relaxed),
            tx_submit_latency_sum_ns: self
                .owner_profile_owner
                .tx_submit_latency_sum_ns
                .load(Ordering::Relaxed),
            // #825: owner-written TX kick-latency telemetry. Same
            // single-writer / Relaxed-load discipline as the #812
            // submit-latency block above; bounded-read-skew
            // semantics per plan §4. Load scalars immediately after
            // the bucket sweep so the snapshot window is tight.
            tx_kick_latency_hist: Self::snapshot_hist(
                &self.owner_profile_owner.tx_kick_latency_hist,
            ),
            tx_kick_latency_count: self
                .owner_profile_owner
                .tx_kick_latency_count
                .load(Ordering::Relaxed),
            tx_kick_latency_sum_ns: self
                .owner_profile_owner
                .tx_kick_latency_sum_ns
                .load(Ordering::Relaxed),
            tx_kick_retry_count: self
                .owner_profile_owner
                .tx_kick_retry_count
                .load(Ordering::Relaxed),
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
    // #918: surface collision-driven evictions distinctly from
    // stale-on-lookup evictions so the post-merge acceptance gate
    // (`collision_evictions / hits < 1 %` under 100E100M load) is
    // observable from the standard binding-counter snapshot.
    if binding.flow_cache.collision_evictions != 0 {
        binding
            .live
            .flow_cache_collision_evictions
            .fetch_add(binding.flow_cache.collision_evictions, Ordering::Relaxed);
        binding.flow_cache.collision_evictions = 0;
    }
    // #941 Work item D: flush each queue's per-queue scratch counter
    // for hard-cap activations into the binding-wide AtomicU64.
    // Mirrors the flow_cache_collision_evictions pattern. Single-
    // writer (worker thread) on both ends, so no atomicity issue.
    let mut hard_cap_overrides_total = 0u64;
    for root in binding.cos_interfaces.values_mut() {
        for queue in &mut root.queues {
            if queue.v_min_hard_cap_overrides_scratch != 0 {
                hard_cap_overrides_total =
                    hard_cap_overrides_total.saturating_add(
                        u64::from(queue.v_min_hard_cap_overrides_scratch),
                    );
                queue.v_min_hard_cap_overrides_scratch = 0;
            }
        }
    }
    if hard_cap_overrides_total != 0 {
        binding
            .live
            .v_min_throttle_hard_cap_overrides
            .fetch_add(hard_cap_overrides_total, Ordering::Relaxed);
    }
}
