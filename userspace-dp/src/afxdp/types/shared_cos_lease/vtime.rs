// #2158 (P2): cross-worker MQFQ V_min coordination, extracted from
// shared_cos_lease/mod.rs as a pure code-motion split. The
// `SharedCoSQueueVtimeFloor` / `PaddedVtimeSlot` cluster is self-contained
// (it reaches no sibling-submodule item), so this move requires NO
// visibility widening. Type/impl bodies are byte-identical to the
// pre-split form; atomic orderings are preserved exactly.

use std::sync::atomic::{AtomicU64, Ordering};

/// #917 — cross-worker MQFQ V_min synchronization. Per-worker
/// slot of the most recent committed `queue_vtime` for a
/// shared_exact CoS queue. Each worker writes its OWN slot
/// (Release store, single-writer) and reads peers' slots
/// (Acquire load) on each scheduling decision (subject to
/// the K-cadence throttle in tx.rs). The minimum across
/// participating workers' slots is the cross-worker V_min;
/// a worker whose local `queue_vtime` advances more than
/// `LAG_THRESHOLD` past V_min throttles itself for one
/// timer-wheel tick to let slower peers catch up.
///
/// Sentinel value `NOT_PARTICIPATING = u64::MAX` means the
/// slot's worker has no flows on this queue. Peers skip
/// `NOT_PARTICIPATING` slots in the V_min reduction so an
/// idle worker doesn't peg V_min near zero.
///
/// Memory ordering (plan §3.4): `publish` and `vacate` use
/// Release stores; readers use Acquire loads. This
/// establishes a happens-before ordering so any observed
/// vtime is paired with the corresponding pre-vtime queue
/// state mutations.
///
/// Cache layout: each `PaddedVtimeSlot` is 64-byte aligned
/// to prevent false sharing across the worker writers; reads
/// pull each peer's line into Shared once per K-cadence
/// check. See plan §3.3 for the cost analysis.
#[repr(align(64))]
pub(in crate::afxdp) struct PaddedVtimeSlot {
    pub(in crate::afxdp) vtime: AtomicU64,
    _pad: [u8; 56],
}

pub(in crate::afxdp) const NOT_PARTICIPATING: u64 = u64::MAX;

impl PaddedVtimeSlot {
    pub(in crate::afxdp) const fn not_participating() -> Self {
        Self {
            vtime: AtomicU64::new(NOT_PARTICIPATING),
            _pad: [0; 56],
        }
    }

    /// Worker calls this on commit boundary publish. Six call
    /// sites total:
    ///   - 4 post-settle TX-ring commit sites in
    ///     `cos/queue_service/service.rs` (each immediately after
    ///     `settle_*`/commit), via the `publish_committed_queue_vtime`
    ///     helper.
    ///   - 1 demote-restore site in `tx/cos_classify.rs:641` (after
    ///     `demote_prepared_cos_queue_to_local` restores the saved
    ///     `queue_vtime`), via the same helper.
    ///   - 1 direct call in `cos/queue_ops/push.rs:126` on the
    ///     rollback path of `cos_queue_push_front`, restoring the
    ///     pre-pop `queue_vtime` so peers don't see the inflated
    ///     speculative value.
    ///
    /// Release ordering ensures any prior writes to
    /// `flow_bucket_*_finish_bytes` and `queue_vtime` are
    /// visible to peers that observe this slot Acquire.
    ///
    /// **No first-enqueue publish.** #941 Work item A's "symmetric
    /// publish on bucket-count 0 → ≥1 transition" was deliberately
    /// dropped during implementation. Rationale: a freshly-enqueued
    /// (or freshly-vacated-then-re-entering) worker has no committed
    /// vtime to broadcast, and peers correctly skip its slot via
    /// `slot.read() == None` (NOT_PARTICIPATING) in the V_min
    /// reduction (see `participating_v_min_snapshot` and its caller
    /// `cos_queue_v_min_continue`). Publishing the stale
    /// pre-vacate `queue_vtime` would broadcast a value that does
    /// NOT correspond to committed work, falsely throttling peers.
    /// The test `vmin_no_first_enqueue_publish` enforces this
    /// invariant.
    pub(in crate::afxdp) fn publish(&self, vtime: u64) {
        debug_assert_ne!(
            vtime, NOT_PARTICIPATING,
            "live vtime must not equal sentinel"
        );
        self.vtime.store(vtime, Ordering::Release);
    }

    /// Worker calls this when the queue's last bucket drains
    /// for this worker — i.e., the worker has no more
    /// flows on this queue.
    pub(in crate::afxdp) fn vacate(&self) {
        self.vtime.store(NOT_PARTICIPATING, Ordering::Release);
    }

    /// Peer reads. Returns `Some(vtime)` if the slot's
    /// worker is participating, `None` otherwise (skip in
    /// the V_min reduction).
    pub(in crate::afxdp) fn read(&self) -> Option<u64> {
        let v = self.vtime.load(Ordering::Acquire);
        if v == NOT_PARTICIPATING {
            None
        } else {
            Some(v)
        }
    }
}

/// #917 V_min coordination structure for a shared_exact CoS
/// queue. Allocated lazily on shared_exact promotion (see
/// `coordinator.rs`). The slot count is fixed at construction
/// time and matches the configured worker count. Holding an
/// `Arc` of this structure pins it across HA / config-commit
/// transitions.
pub(in crate::afxdp) struct SharedCoSQueueVtimeFloor {
    /// One slot per worker. Index by the worker's
    /// 0-based id.
    pub(in crate::afxdp) slots: Box<[PaddedVtimeSlot]>,
    /// #2624 test seam: counts how many times the expensive
    /// `participating_v_min_snapshot` peer-slot scan actually ran.
    /// This is the exact cost the V_MIN_READ_CADENCE filter throttles,
    /// so tests assert the cadence (1st pop, then every Kth) is honored
    /// ACROSS drain calls by reading this counter. Test-only; no
    /// hot-path cost in release builds.
    #[cfg(test)]
    pub(in crate::afxdp) snapshot_calls: std::sync::atomic::AtomicU64,
}

impl SharedCoSQueueVtimeFloor {
    pub(in crate::afxdp) fn new(num_workers: usize) -> Self {
        let slots = (0..num_workers)
            .map(|_| PaddedVtimeSlot::not_participating())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            slots,
            #[cfg(test)]
            snapshot_calls: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Single-pass snapshot of the participating peers' V_min
    /// state, excluding `worker_id`'s own slot.
    ///
    /// Returns `(participating_count, Some(v_min))` if at least
    /// one peer is participating, `(0, None)` if every peer is
    /// `NOT_PARTICIPATING` (caller treats the queue as unthrottled).
    /// `v_min` is the minimum across only participating peers.
    ///
    /// **Memory ordering**: each `slot.read()` is an independent
    /// `Ordering::Acquire` load, paired with the corresponding
    /// `Ordering::Release` store inside `PaddedVtimeSlot::publish` /
    /// `vacate`. The iteration is **non-atomic across slots** —
    /// a slot can transition `vtime → NOT_PARTICIPATING` (or
    /// vice versa) between two reads in the same iteration. There
    /// is no lock, seqlock, retry, or epoch; the result is the set
    /// of values observed during the scan, where each individual
    /// value is a valid Acquire-load of that slot at some moment
    /// within the scan window. Cross-slot atomicity is not
    /// provided. The throttle decision is a hint with staleness
    /// bounded by the K-cadence read interval, not a hard barrier.
    /// Introducing a global lock or seqlock would re-introduce
    /// the contention the algorithm was designed to eliminate.
    ///
    /// Single-pass helper that `cos_queue_v_min_continue` calls
    /// for the (count, v_min) pair on each cadence tick.
    /// Centralizes the memory-ordering contract in one place.
    #[inline]
    pub(in crate::afxdp) fn participating_v_min_snapshot(
        &self,
        worker_id: u32,
    ) -> (u32, Option<u64>) {
        #[cfg(test)]
        self.snapshot_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut participating = 0u32;
        let mut v_min = u64::MAX;
        for (idx, slot) in self.slots.iter().enumerate() {
            if idx == worker_id as usize {
                continue;
            }
            if let Some(peer) = slot.read() {
                participating += 1;
                v_min = v_min.min(peer);
            }
        }
        if participating == 0 {
            (0, None)
        } else {
            (participating, Some(v_min))
        }
    }
}
