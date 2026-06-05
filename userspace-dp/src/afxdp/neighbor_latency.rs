//! #1772: neighbor/ARP resolution LATENCY histograms.
//!
//! #1769 added neighbor-resolver COUNT metrics but no timing. The
//! operator's intermittent slow-new-connection symptom is invisible
//! without latency: we cannot see how long a packet waited for its
//! neighbor, nor how long the kernel took to answer a GETNEIGH.
//!
//! This module provides a CHEAP, fixed-bucket, shared-aggregate
//! histogram (`NeighborLatencyHist`). Design choices:
//!
//! - **Aggregate, not per-binding/per-zone.** Neighbor misses/retries
//!   are RARE events (not per forwarded packet). One shared set of
//!   atomics across all 6 WAN workers + the single resolver thread keeps
//!   cardinality bounded (one histogram series, no per-flow / per-zone
//!   explosion) and contention negligible.
//! - **No seqlock, no TSC infra.** The buckets are monotonic counters;
//!   the status reader does Relaxed loads and tolerates an eventually-
//!   consistent read — exactly the discipline the existing #1769
//!   `ResolverCounters` already use. The heavy per-zone-pair
//!   `cold_path_hist` seqlock + RDTSCP machinery is policy-eval-scoped
//!   and deliberately NOT reused here; it would be wildly oversized for
//!   a rare-event aggregate.
//! - **No per-sample allocation.** `record()` is one `bucket_index`,
//!   three `fetch_add(Relaxed)` (bucket + sum + count). Inlined.
//!
//! ## Bucket layout
//!
//! 16-bucket pow2-ns ladder. Bucket `i` (0..=14) has inclusive upper
//! bound `2^(16+i)` ns; bucket 15 is the `+Inf` saturate bucket:
//!
//! | idx | upper bound (ns) | ≈        |
//! |-----|------------------|----------|
//! | 0   | 2^16  = 65536    | 65.5 µs  |
//! | 7   | 2^23             | 8.4 ms   |
//! | 13  | 2^29             | 537 ms   |
//! | 14  | 2^30             | 1.07 s   |
//! | 15  | +Inf             | ≥ 1.07 s |
//!
//! The 3 s blackout class from #1769 lands in bucket 15 (the `+Inf`
//! multi-second tail) — clearly visible as a multi-second tail, which is
//! the whole point of the metric.

use std::sync::atomic::{AtomicU64, Ordering};

/// Number of histogram buckets. 15 finite pow2 buckets + 1 saturate.
pub(in crate::afxdp) const NEIGH_LATENCY_BUCKETS: usize = 16;
const _: () = assert!(NEIGH_LATENCY_BUCKETS == 16);

/// Exponent of the first (lowest) finite bucket's upper bound: 2^16 ns.
const NEIGH_LATENCY_BASE_SHIFT: u32 = 16;

/// Select the histogram bucket for `ns`.
///
/// Bucket `i` (0..=14) covers `(2^(15+i), 2^(16+i)]` ns (with bucket 0
/// also capturing everything `<= 2^16`); bucket 15 is `> 2^30` ns
/// (≈ ≥ 1.07 s), the multi-second saturate tail.
///
/// Branchless after the leading-zero compute; one `min` clamp.
#[inline]
pub(in crate::afxdp) fn neigh_latency_bucket_index(ns: u64) -> usize {
    if ns == 0 {
        return 0;
    }
    // floor(log2(ns)) = 63 - clz(ns).
    let log2 = 63u32.saturating_sub(ns.leading_zeros());
    // Anything <= 2^16 ns → bucket 0. Otherwise bucket = log2 - 15
    // (so ns in (2^16, 2^17] → log2=16 (for 2^17-ish) ... we want the
    // upper-bound-2^(16+i) mapping: ns just above 2^(16+i-1) lands in i).
    if log2 < NEIGH_LATENCY_BASE_SHIFT {
        0
    } else {
        // log2 == 16 → ns in [2^16, 2^17): upper bound 2^17 = bucket 1,
        // except exactly 2^16 belongs in bucket 0. Use a boundary nudge:
        // values <= 2^16 already returned bucket 0 above only when log2 <
        // 16; 2^16 itself has log2 == 16. Treat the inclusive upper bound
        // 2^(16) as bucket 0 by checking the exact-power case.
        let idx = (log2 - NEIGH_LATENCY_BASE_SHIFT + 1) as usize;
        // ns exactly equal to a power-of-two upper bound belongs to the
        // bucket whose upper bound it is (inclusive), i.e. one lower.
        let idx = if ns == (1u64 << log2) && log2 >= NEIGH_LATENCY_BASE_SHIFT {
            idx.saturating_sub(1)
        } else {
            idx
        };
        idx.min(NEIGH_LATENCY_BUCKETS - 1)
    }
}

/// Inclusive upper bound in nanoseconds for bucket `idx`, for the
/// Prometheus `le` label. Bucket 15 → `u64::MAX` (rendered `+Inf`).
#[inline]
pub(in crate::afxdp) fn neigh_latency_bucket_upper_ns(idx: usize) -> u64 {
    if idx >= NEIGH_LATENCY_BUCKETS - 1 {
        u64::MAX
    } else {
        1u64 << (NEIGH_LATENCY_BASE_SHIFT + idx as u32)
    }
}

/// Shared, lock-free aggregate latency histogram. Writers (the per-
/// binding retry sweep and the single resolver thread) call [`record`];
/// the status path reads a [`NeighborLatencySnapshot`]. All atomics are
/// monotonic counters under Relaxed ordering — the same eventually-
/// consistent discipline as the #1769 `ResolverCounters`.
///
/// [`record`]: NeighborLatencyHist::record
#[derive(Default)]
pub(crate) struct NeighborLatencyHist {
    buckets: [AtomicU64; NEIGH_LATENCY_BUCKETS],
    /// Sum of all recorded latencies in nanoseconds (for `_sum`).
    sum_ns: AtomicU64,
    /// Total number of recorded samples (for `_count`).
    count: AtomicU64,
}

impl NeighborLatencyHist {
    /// Record a latency observation of `delta_ns`. Hot-path cost: one
    /// bucket-index compute + three `fetch_add(Relaxed)`. Fires only on
    /// rare neighbor-miss/retry/resolver events, never on the forwarded-
    /// packet fast path.
    #[inline]
    pub(crate) fn record(&self, delta_ns: u64) {
        let idx = neigh_latency_bucket_index(delta_ns);
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.sum_ns.fetch_add(delta_ns, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Take a plain snapshot for the status path.
    pub(crate) fn snapshot(&self) -> NeighborLatencySnapshot {
        let mut buckets = [0u64; NEIGH_LATENCY_BUCKETS];
        for (i, b) in self.buckets.iter().enumerate() {
            buckets[i] = b.load(Ordering::Relaxed);
        }
        NeighborLatencySnapshot {
            buckets,
            sum_ns: self.sum_ns.load(Ordering::Relaxed),
            count: self.count.load(Ordering::Relaxed),
        }
    }
}

/// Plain `Copy` snapshot of a [`NeighborLatencyHist`] for the status
/// path. `buckets[i]` is the NON-cumulative count of samples whose
/// latency fell in bucket `i`; the Go side computes the cumulative
/// `le`-labelled Prometheus buckets.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NeighborLatencySnapshot {
    pub(crate) buckets: [u64; NEIGH_LATENCY_BUCKETS],
    pub(crate) sum_ns: u64,
    pub(crate) count: u64,
}

/// #1772: the full neighbor-latency telemetry bundle carried to the
/// status path (coordinator → server/helpers → protocol → Go).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NeighborLatencyTelemetry {
    /// pending_neigh dwell-time histogram (`now_ns - queued_ns` at the
    /// moment a buffered packet's neighbor resolves).
    pub(crate) pending_dwell: NeighborLatencySnapshot,
    /// Resolver single-key RTM_GETNEIGH round-trip-time histogram.
    pub(crate) resolver_get_rtt: NeighborLatencySnapshot,
    /// pending_neigh packets dropped after PENDING_NEIGH_TIMEOUT.
    pub(crate) pending_timeout_drops: u64,
    /// High-water mark of `pending_neigh.len()` at retry-sweep entry.
    pub(crate) pending_max_depth: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_zero_covers_sub_65us() {
        assert_eq!(neigh_latency_bucket_index(0), 0);
        assert_eq!(neigh_latency_bucket_index(1), 0);
        assert_eq!(neigh_latency_bucket_index(1_000), 0); // 1 µs
        assert_eq!(neigh_latency_bucket_index(65_535), 0);
        // Exactly 2^16 is the inclusive upper bound of bucket 0.
        assert_eq!(neigh_latency_bucket_index(1u64 << 16), 0);
    }

    #[test]
    fn bucket_boundaries_are_pow2_upper_bounds() {
        // ns just above 2^16 → bucket 1 (upper bound 2^17).
        assert_eq!(neigh_latency_bucket_index((1u64 << 16) + 1), 1);
        assert_eq!(neigh_latency_bucket_index(1u64 << 17), 1);
        // 4 ms ≈ 2^22 region.
        let four_ms = 4_000_000u64;
        let idx = neigh_latency_bucket_index(four_ms);
        // 2^21 = 2.1ms, 2^22 = 4.19ms → 4ms is in (2^21, 2^22] → bucket 6.
        assert_eq!(idx, 6);
        assert!(neigh_latency_bucket_upper_ns(idx) >= four_ms);
    }

    /// THE key acceptance: the #1769 3 s blackout class MUST land in the
    /// visible multi-second tail (the +Inf saturate bucket).
    #[test]
    fn three_second_blackout_lands_in_saturate_tail() {
        let three_s = 3_000_000_000u64;
        let idx = neigh_latency_bucket_index(three_s);
        assert_eq!(
            idx,
            NEIGH_LATENCY_BUCKETS - 1,
            "3 s dwell must land in the +Inf multi-second tail bucket",
        );
        assert_eq!(neigh_latency_bucket_upper_ns(idx), u64::MAX);
        // And a 4 ms warm connect (the issue's "fast" case) must NOT.
        assert!(neigh_latency_bucket_index(4_000_000) < NEIGH_LATENCY_BUCKETS - 1);
    }

    #[test]
    fn one_second_is_below_the_saturate_tail() {
        // 1 s = 1e9 ns; 2^29 ≈ 537 ms, 2^30 ≈ 1.07 s → 1e9 in (2^29,2^30]
        // → bucket 14, NOT the saturate tail.
        assert_eq!(neigh_latency_bucket_index(1_000_000_000), 14);
        assert!(neigh_latency_bucket_index(1_000_000_000) < NEIGH_LATENCY_BUCKETS - 1);
    }

    #[test]
    fn record_increments_correct_bucket_sum_and_count() {
        let h = NeighborLatencyHist::default();
        h.record(3_000_000_000); // saturate tail
        h.record(1_000); // bucket 0
        let snap = h.snapshot();
        assert_eq!(snap.count, 2);
        assert_eq!(snap.sum_ns, 3_000_001_000);
        assert_eq!(snap.buckets[0], 1, "1 µs sample in bucket 0");
        assert_eq!(
            snap.buckets[NEIGH_LATENCY_BUCKETS - 1],
            1,
            "3 s sample in the saturate tail",
        );
    }

    #[test]
    fn upper_bounds_are_strictly_increasing_then_inf() {
        let mut prev = 0u64;
        for i in 0..(NEIGH_LATENCY_BUCKETS - 1) {
            let ub = neigh_latency_bucket_upper_ns(i);
            assert!(ub > prev, "bucket {i} upper bound must increase");
            prev = ub;
        }
        assert_eq!(
            neigh_latency_bucket_upper_ns(NEIGH_LATENCY_BUCKETS - 1),
            u64::MAX
        );
    }
}
