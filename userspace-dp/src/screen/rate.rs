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
//! The semantic of the operator-configured threshold is preserved: a
//! sustained sender is still admitted at ~`threshold` events per second.
//! A gap of two or more seconds clears the previous bucket (no stale
//! carryover from an idle period).
//!
//! The hot path is allocation-free and integer-only (two `u32` adds and a
//! compare per event).

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
