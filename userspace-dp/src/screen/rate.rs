//! Per-zone rate counters used by ICMP/UDP/SYN flood detection and
//! SYN-cookie standby ACK rate limiting.
//!
//! The limiter is a two-bucket **sliding-window counter** keyed on a
//! 1-second granularity clock (`now_secs`). It bounds the admitted event
//! rate across any rolling 1-second interval, not just within a fixed
//! calendar second.
//!
//! ## Why not a fixed wall-second window (#2937)
//!
//! The previous implementation reset `count` to zero whenever `now_secs`
//! advanced. That is a fixed wall-clock window, and it admits a boundary
//! double-burst: a sender consuming the full budget at the end of second
//! N and another full budget at the start of second N+1 passes ~2x the
//! nominal threshold in an arbitrarily short interval straddling the
//! boundary. For flood screens that delays enforcement during exactly the
//! burst shape an attacker uses; for standby SYN-cookie ACK validation it
//! permits roughly twice the intended number of plausible ACKs before the
//! standby refuses to spend CPU validating cookies.
//!
//! ## Sliding-window counter
//!
//! Two adjacent 1-second buckets are retained: the count for the current
//! second (`count`) and the count for the immediately preceding second
//! (`prev_count`). An event is admitted only when
//! `prev_count + count <= threshold`. Because the previous second's tally
//! still contributes for the whole of the current second, a sender that
//! exhausts the budget just before a boundary cannot immediately spend a
//! fresh budget just after it — the trailing 1-second sum stays bounded by
//! `threshold` regardless of where the boundary falls.
//!
//! A gap of two or more seconds clears the previous bucket (no stale
//! carryover from an idle period).
//!
//! The hot path is allocation-free and integer-only (two `u32` adds and a
//! compare per event).
//!
//! ## `RateCounter` over-throttles a sender parked AT the threshold (#3607)
//!
//! Because `RateCounter` counts *rejected* events (the offending packet is
//! always counted) and gives the whole previous second constant weight for
//! the entire current second, a sender delivering exactly `threshold`
//! events/second is admitted only in the first second and then dropped to ~0
//! until a fully idle second resets the window — the true sustained ceiling
//! is `threshold/2`, not `threshold`. That over-throttle is acceptable (and
//! deliberately retained) for the consumers where "admitted" means "skip a
//! security response" — the SYN-flood aggregate that activates SYN cookies
//! when `syn-cookie` is ON (a challenge is a recoverable extra RTT), the
//! alarm-threshold arrival-rate measurement, and the #3315 per-source /
//! per-destination sketch. Consumers where "admitted" is a pure shaper /
//! validate-budget decision (ICMP/UDP flood aggregate, the standby
//! SYN-cookie ACK validation budget, and the SYN-flood aggregate drop path
//! when `syn-cookie` is OFF) instead use [`TokenBucket`] below, which admits
//! a sustained-at-threshold stream correctly while still bounding a burst to
//! the capacity. See `docs/syn-cookie-flood-protection.md` and
//! `docs/research/3607-screen-rate/plan.md`.

/// Sliding-window rate counter over two adjacent 1-second buckets.
#[derive(Debug, Clone, Default)]
pub(super) struct RateCounter {
    /// Events counted in the current 1-second bucket.
    pub(super) count: u32,
    /// Events counted in the immediately preceding 1-second bucket.
    /// Contributes to the admission decision for the whole current second
    /// so a boundary crossing cannot reset the budget to zero.
    prev_count: u32,
    /// Wall-clock second that `count` accumulates into.
    window_start_secs: u64,
}

impl RateCounter {
    /// Roll the buckets forward so `count` tracks `now_secs`.
    ///
    /// Advancing by exactly one second demotes the current bucket to the
    /// previous bucket. Advancing by two or more seconds means a full
    /// rolling window elapsed with no events in between, so both buckets
    /// are cleared (no stale carryover).
    fn advance(&mut self, now_secs: u64) {
        if now_secs == self.window_start_secs {
            return;
        }
        if now_secs == self.window_start_secs.wrapping_add(1) {
            self.prev_count = self.count;
        } else {
            self.prev_count = 0;
        }
        self.count = 0;
        self.window_start_secs = now_secs;
    }

    /// Increment and return true if admitting this event would exceed the
    /// threshold over the trailing 1-second sliding window.
    ///
    /// The event is always counted (so a sustained over-limit sender keeps
    /// the window saturated), mirroring the original fixed-window
    /// behaviour where the offending packet incremented the counter.
    pub(super) fn increment(&mut self, now_secs: u64, threshold: u32) -> bool {
        self.advance(now_secs);
        self.count = self.count.saturating_add(1);
        self.prev_count.saturating_add(self.count) > threshold
    }

    /// Advance the window ONCE, count this event, and classify the trailing
    /// 1-second sum against TWO thresholds in a single pass (#3315 D7).
    ///
    /// Returns `(over_attack, over_alarm)`. This avoids a peek-then-increment
    /// double-advance: `increment` rolls the buckets forward on each call, so
    /// comparing against a second threshold via a separate call would advance
    /// the window twice and could miscount across a second boundary. The event
    /// is always counted (same as `increment`). Both compares read the same
    /// already-computed trailing sum, so the classification is internally
    /// consistent: a sum can never be "over attack" without also being "over
    /// alarm" when `alarm <= attack` (the validated Junos ordering, though the
    /// caller does not rely on that — it gates the alarm on `!over_attack`).
    pub(super) fn increment_and_classify(
        &mut self,
        now_secs: u64,
        attack: u32,
        alarm: u32,
    ) -> (bool, bool) {
        self.advance(now_secs);
        self.count = self.count.saturating_add(1);
        let trailing = self.prev_count.saturating_add(self.count);
        (trailing > attack, trailing > alarm)
    }

    /// Reset counter (used in tests).
    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn reset(&mut self) {
        self.count = 0;
        self.prev_count = 0;
        self.window_start_secs = 0;
    }
}

/// Fixed-point scale for [`TokenBucket`]: `tokens_q` units per whole token.
/// Chosen equal to nanoseconds-per-second so the per-nanosecond refill rate
/// at `threshold`/second is exactly `threshold` fixed-point units
/// (`threshold * ONE / NANOS_PER_SEC == threshold`), i.e. the refill over
/// `elapsed_ns` is simply `elapsed_ns * threshold` — an integer multiply with
/// NO per-packet 64-bit divide.
const ONE: u64 = 1_000_000_000;

/// Cap the refill window at one second. Any gap of >= 1s already refills a
/// bucket to capacity (capacity == `threshold` whole tokens, and one second
/// accrues exactly `threshold` tokens), and capping the elapsed term keeps
/// `elapsed_ns * threshold` from overflowing `u64` at very high thresholds
/// (AGY round-4 hardening).
const MAX_REFILL_ELAPSED_NS: u64 = 1_000_000_000;

/// Bucket capacity in fixed-point units for `threshold` whole tokens.
#[inline]
fn capacity_q(threshold: u32) -> u64 {
    (threshold as u64).saturating_mul(ONE)
}

/// Fixed-point tokens accrued over `elapsed_ns` nanoseconds at `threshold`
/// tokens/second. `elapsed_ns` is pre-capped at [`MAX_REFILL_ELAPSED_NS`] by
/// the caller, so the multiply cannot overflow `u64` for any realistic
/// threshold; `saturating_mul` is a belt-and-braces guard.
#[inline]
fn refill_q(elapsed_ns: u64, threshold: u32) -> u64 {
    elapsed_ns.saturating_mul(threshold as u64)
}

/// Monotonic-nanosecond **token bucket** (#3607).
///
/// Admits a sustained sender at exactly `threshold` events/second while
/// bounding a burst to `threshold` (the capacity), fixing the [`RateCounter`]
/// sustained-at-threshold over-throttle for the shaper / validate-budget
/// consumers (see the module doc). The bucket refills continuously, so an
/// at-threshold stream never runs dry, and a sub-millisecond boundary
/// straddle sees at most `threshold` tokens — preserving the #2937
/// anti-micro-burst property without the sliding window's count-all defect.
///
/// Fixed-point: `tokens_q` counts tokens scaled by [`ONE`]; one whole token
/// is `ONE` units. The hot path is one multiply-add, a clamp, and a
/// conditional subtract — integer-only, allocation-free, no per-packet clock
/// syscall (it reuses the batch-cached `loop_now_ns`), and no divide.
///
/// 16 bytes; per-worker; never serialized, persisted, or HA-synced.
#[derive(Debug, Clone, Default)]
pub(super) struct TokenBucket {
    /// Fixed-point available tokens (scaled by [`ONE`]). Clamped to
    /// `capacity_q(threshold)` on every refill.
    tokens_q: u64,
    /// Monotonic nanoseconds at the last refill. `0` is the "uninitialised"
    /// sentinel: a fresh bucket cold-starts FULL on first use so a new zone
    /// admits the first `threshold` events, matching `RateCounter`'s
    /// first-window behaviour.
    last_refill_ns: u64,
}

impl TokenBucket {
    /// Charge one event against the bucket. Returns `true` when the event is
    /// OVER LIMIT (drop / limited) and `false` when admitted — the SAME
    /// polarity as [`RateCounter::increment`], so it is a drop-in at the
    /// existing `true == drop` screen call sites.
    ///
    /// `now_ns` is the batch-cached `CLOCK_MONOTONIC` nanosecond already read
    /// once per poll loop (`loop_now_ns`); there is no per-packet clock read.
    /// A non-monotonic `now_ns` (`< last_refill_ns`) is absorbed with
    /// `saturating_sub` (no underflow; that event simply accrues no refill).
    /// `threshold` is passed per call (a config change needs no realloc), so
    /// the capacity clamp always tracks the live threshold.
    pub(super) fn admit_is_over(&mut self, now_ns: u64, threshold: u32) -> bool {
        if self.last_refill_ns == 0 {
            // Cold start: begin FULL so a fresh zone admits the first
            // `threshold` events. `max(1)` never leaves the sentinel behind
            // even if the monotonic clock reports 0 on the first read.
            self.tokens_q = capacity_q(threshold);
            self.last_refill_ns = now_ns.max(1);
        } else {
            let elapsed = now_ns
                .saturating_sub(self.last_refill_ns)
                .min(MAX_REFILL_ELAPSED_NS);
            // `saturating_add` before the `.min` clamp: `tokens_q` (<= capacity)
            // plus a full-second refill only approaches `u64` at extreme
            // thresholds, but saturate defensively so the accumulation cannot
            // wrap before the clamp (Codex round-5).
            self.tokens_q = self
                .tokens_q
                .saturating_add(refill_q(elapsed, threshold))
                .min(capacity_q(threshold));
            self.last_refill_ns = now_ns.max(1);
        }
        if self.tokens_q >= ONE {
            self.tokens_q -= ONE; // consume only on admit
            false // admitted
        } else {
            true // over limit — do NOT consume
        }
    }

    /// Whole tokens currently available (fixed-point value floored). Test seam.
    #[cfg(test)]
    pub(super) fn available_tokens(&self) -> u64 {
        self.tokens_q / ONE
    }

    /// True if the bucket has never been charged (cold — no refill latched).
    /// Distinguishes "untouched" from "drained" (both report 0 available).
    #[cfg(test)]
    pub(super) fn is_cold(&self) -> bool {
        self.last_refill_ns == 0
    }

    /// Reset (used in tests).
    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn reset(&mut self) {
        self.tokens_q = 0;
        self.last_refill_ns = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One whole nanosecond-second, for readable `now_ns` arithmetic in tests.
    const NS: u64 = 1_000_000_000;

    /// Within a single second the sliding window behaves like the old
    /// fixed window: `threshold` events pass, the next one trips.
    #[test]
    fn within_window_allows_up_to_threshold() {
        let mut rc = RateCounter::default();
        for _ in 0..5 {
            assert!(!rc.increment(100, 5), "first 5 events must be admitted");
        }
        assert!(rc.increment(100, 5), "6th event in the same second trips");
    }

    /// FAIL-ON-REVERT (#2937): a boundary double-burst must NOT admit 2x
    /// the threshold. `threshold` events at the end of second N followed
    /// by another `threshold` at the start of second N+1 straddle the
    /// window boundary in a sub-millisecond interval. The fixed-window
    /// reset admitted all 2N; the sliding window trips on the first event
    /// of second N+1 because second N's tally still counts.
    ///
    /// Against the reverted (fixed-window) code this assertion is RED: the
    /// fixed window resets `count` at the boundary so all 2N pass and
    /// `tripped_after_boundary` stays 0.
    #[test]
    fn boundary_double_burst_is_bounded() {
        const THRESHOLD: u32 = 100;
        let mut rc = RateCounter::default();

        // End of second N: consume the full budget. None trip.
        let mut admitted_n = 0u32;
        for _ in 0..THRESHOLD {
            if !rc.increment(0, THRESHOLD) {
                admitted_n += 1;
            }
        }
        assert_eq!(admitted_n, THRESHOLD, "full budget admitted in second N");

        // Start of second N+1 (boundary crossing): a second full burst.
        // The trailing 1-second sum is prev(THRESHOLD) + current, so the
        // very first event already exceeds the threshold.
        let mut tripped_after_boundary = 0u32;
        for _ in 0..THRESHOLD {
            if rc.increment(1, THRESHOLD) {
                tripped_after_boundary += 1;
            }
        }
        assert_eq!(
            tripped_after_boundary, THRESHOLD,
            "every event in the post-boundary burst must trip (fixed \
             window would admit all 2N and trip none)"
        );
    }

    /// A two-second idle gap clears the previous bucket — a sender that
    /// goes quiet and returns gets a fresh full budget (the carryover is
    /// only one second deep, matching the sliding-window definition).
    #[test]
    fn gap_clears_previous_bucket() {
        const THRESHOLD: u32 = 10;
        let mut rc = RateCounter::default();
        for _ in 0..THRESHOLD {
            assert!(!rc.increment(0, THRESHOLD));
        }
        // Jump two seconds ahead: second 1 was empty, so the trailing
        // window no longer contains second 0's events.
        let mut admitted = 0u32;
        for _ in 0..THRESHOLD {
            if !rc.increment(2, THRESHOLD) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, THRESHOLD, "fresh budget after a full-window gap");
    }

    /// #3315 D7: `increment_and_classify` advances the window exactly ONCE and
    /// classifies the same trailing sum against both thresholds. Each call
    /// counts exactly one event, so the sum climbs 1,2,3,... and crosses the
    /// alarm threshold before the (higher) attack threshold. A peek-then-
    /// increment implementation that advanced the window twice would miscount;
    /// this sequence pins the single-advance, dual-compare contract.
    #[test]
    fn increment_and_classify_single_advance_dual_threshold() {
        const ATTACK: u32 = 5;
        const ALARM: u32 = 2;
        let mut rc = RateCounter::default();
        // sum 1,2: under both (2 > 2 is false — boundary is ">").
        assert_eq!(rc.increment_and_classify(0, ATTACK, ALARM), (false, false));
        assert_eq!(rc.increment_and_classify(0, ATTACK, ALARM), (false, false));
        // sum 3: over alarm (3 > 2), under attack (3 > 5 false).
        assert_eq!(rc.increment_and_classify(0, ATTACK, ALARM), (false, true));
        // sum 4, 5: still over alarm, under/at attack (5 > 5 false).
        assert_eq!(rc.increment_and_classify(0, ATTACK, ALARM), (false, true));
        assert_eq!(rc.increment_and_classify(0, ATTACK, ALARM), (false, true));
        // sum 6: over both.
        assert_eq!(rc.increment_and_classify(0, ATTACK, ALARM), (true, true));
    }

    /// A sustained sender at exactly the threshold rate stays admitted:
    /// the configured `N/sec` semantic is preserved across many seconds.
    #[test]
    fn sustained_at_threshold_is_admitted() {
        const THRESHOLD: u32 = 50;
        // Split the per-second budget half before and half after each
        // boundary; the trailing-window sum is THRESHOLD/2 + THRESHOLD/2
        // == THRESHOLD, which is admitted (the boundary case is "> not
        // >=").
        let mut rc = RateCounter::default();
        let half = THRESHOLD / 2;
        for sec in 0..20u64 {
            for _ in 0..half {
                assert!(
                    !rc.increment(sec, THRESHOLD),
                    "sustained sender at threshold must stay admitted at sec {sec}"
                );
            }
        }
    }

    /// #3607 CONTRAST: `RateCounter` fed a FULL `threshold` events/second at
    /// the second boundary over-throttles to ~0 after the first second — the
    /// bug that motivates the token bucket. `sustained_at_threshold_is_admitted`
    /// only passes because it feeds `threshold/2`; at the real threshold the
    /// window saturates and rejects nearly everything.
    #[test]
    fn rate_counter_over_throttles_full_threshold() {
        const THRESHOLD: u32 = 100;
        let mut rc = RateCounter::default();
        let mut admitted = 0u32;
        for sec in 0..10u64 {
            for _ in 0..THRESHOLD {
                if !rc.increment(sec, THRESHOLD) {
                    admitted += 1;
                }
            }
        }
        // Only the very first second's budget gets through; every later second
        // stays saturated by the prior second's count-all tally.
        assert!(
            admitted <= THRESHOLD,
            "RateCounter admits only ~one window of a sustained at-threshold \
             stream (got {admitted} over 10 windows of {THRESHOLD})"
        );
    }

    /// #3607 (M09): the token bucket admits a sustained sender parked at
    /// EXACTLY `threshold` events/second — the case `RateCounter` throttles to
    /// ~0. Events are evenly spaced at the real monotonic rate (`1s/threshold`
    /// apart), so each event accrues exactly one token before it is spent.
    #[test]
    fn token_bucket_sustained_at_threshold_admits() {
        const THRESHOLD: u32 = 1000;
        let interval_ns = NS / THRESHOLD as u64; // 1_000_000 ns == 1ms
        let mut tb = TokenBucket::default();
        let mut now = 5 * NS; // arbitrary non-zero monotonic base
        let mut admitted = 0u32;
        let total = THRESHOLD * 20; // 20 seconds of sustained at-threshold load
        for _ in 0..total {
            if !tb.admit_is_over(now, THRESHOLD) {
                admitted += 1;
            }
            now += interval_ns;
        }
        // Continuous refill keeps the bucket topped up: essentially everything
        // is admitted (>= 99%), versus RateCounter which would drop ~95%.
        assert!(
            admitted as f64 >= 0.99 * total as f64,
            "sustained at-threshold must stay admitted: {admitted}/{total}"
        );
    }

    /// Low-threshold sanity: `threshold == 1` sustained at 1 pps admits every
    /// second (the `T=1` roughness that killed the weighted-window option).
    #[test]
    fn token_bucket_low_threshold_sustained_admits() {
        let mut tb = TokenBucket::default();
        let mut now = NS;
        for sec in 0..30u64 {
            assert!(
                !tb.admit_is_over(now, 1),
                "1 pps at threshold 1 must be admitted every second (sec {sec})"
            );
            now += NS;
        }
    }

    /// A fresh bucket cold-starts FULL: the first `threshold` events at one
    /// instant are admitted, matching `RateCounter`'s first window.
    #[test]
    fn token_bucket_cold_start_admits_first_threshold() {
        const THRESHOLD: u32 = 50;
        let mut tb = TokenBucket::default();
        let now = 7 * NS;
        for i in 0..THRESHOLD {
            assert!(
                !tb.admit_is_over(now, THRESHOLD),
                "cold-start event {i} within capacity must be admitted"
            );
        }
        assert!(
            tb.admit_is_over(now, THRESHOLD),
            "the (threshold+1)th event at the same instant is over capacity"
        );
    }

    /// #2937 RETAINED: a burst ABOVE capacity at a single instant (and a
    /// sub-millisecond straddle) is bounded to `threshold` — the bucket never
    /// hands out 2x the budget across a boundary the way a fixed window would.
    #[test]
    fn token_bucket_burst_above_capacity_is_bounded() {
        const THRESHOLD: u32 = 100;
        let mut tb = TokenBucket::default();
        let now = 3 * NS;
        let mut admitted = 0u32;
        for _ in 0..(THRESHOLD * 3) {
            if !tb.admit_is_over(now, THRESHOLD) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, THRESHOLD, "instantaneous burst bounded to capacity");
        // Sub-millisecond straddle 100us later: negligible refill, still bounded.
        let later = now + 100_000; // 100us
        let mut admitted2 = 0u32;
        for _ in 0..THRESHOLD {
            if !tb.admit_is_over(later, THRESHOLD) {
                admitted2 += 1;
            }
        }
        assert!(
            admitted2 <= 1,
            "a sub-ms micro-burst must not refill a second budget (got {admitted2})"
        );
    }

    /// After an over-limit burst, dropping back to <= threshold recovers WITHOUT
    /// needing a fully idle second (the RateCounter suppress-until-idle defect).
    #[test]
    fn token_bucket_recovers_without_idle_second() {
        const THRESHOLD: u32 = 10;
        let mut tb = TokenBucket::default();
        let mut now = NS;
        // Drain the bucket with an instantaneous 5x burst.
        for _ in 0..(THRESHOLD * 5) {
            tb.admit_is_over(now, THRESHOLD);
        }
        // 200ms later at <= threshold pacing: 200ms accrues 0.2*threshold == 2
        // tokens, so at least the next couple of events are admitted again
        // (no full idle second required).
        now += NS / 5;
        assert!(
            !tb.admit_is_over(now, THRESHOLD),
            "partial refill after 200ms must admit again without an idle second"
        );
    }

    /// An out-of-order (`now_ns < last_refill_ns`) clock sample must not panic
    /// and must not over-credit — `saturating_sub` yields 0 elapsed.
    #[test]
    fn token_bucket_clock_underflow_no_panic() {
        const THRESHOLD: u32 = 8;
        let mut tb = TokenBucket::default();
        // Initialise at a high base.
        assert!(!tb.admit_is_over(100 * NS, THRESHOLD));
        // A sample far in the past: no refill, no panic; the surviving tokens
        // still admit up to capacity-1 more.
        for _ in 0..(THRESHOLD - 1) {
            assert!(!tb.admit_is_over(1, THRESHOLD));
        }
        assert!(
            tb.admit_is_over(1, THRESHOLD),
            "no spurious refill from a backwards clock"
        );
    }

    /// A multi-second idle gap at a very high threshold does not overflow the
    /// `elapsed * threshold` fixed-point multiply (elapsed capped at 1s), and
    /// the bucket refills to exactly capacity.
    #[test]
    fn token_bucket_high_threshold_gap_no_overflow() {
        const THRESHOLD: u32 = 1_000_000;
        let mut tb = TokenBucket::default();
        assert!(!tb.admit_is_over(NS, THRESHOLD)); // cold start full
        // Drain a bit.
        for _ in 0..100 {
            tb.admit_is_over(NS, THRESHOLD);
        }
        // Jump 5 seconds ahead: elapsed caps at 1s, refills to full capacity.
        let now = 6 * NS;
        let mut admitted = 0u64;
        for _ in 0..THRESHOLD {
            if !tb.admit_is_over(now, THRESHOLD) {
                admitted += 1;
            }
        }
        assert_eq!(
            admitted, THRESHOLD as u64,
            "a >=1s gap refills to exactly capacity with no overflow"
        );
    }
}
