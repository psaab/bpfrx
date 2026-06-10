// #1829 Phase 1: unit tests for the per-queue dequeue-time sojourn
// telemetry state (`CoSQueueSojourn`). Loaded as a sibling submodule
// via `#[path = "cos_sojourn_tests.rs"]` from types/cos.rs.
//
// These pin the contract the Phase-2 gate evidence depends on:
//   * `enqueue_ns == 0` is "no data", never a huge bogus sojourn
//     (plan invariant 10);
//   * the windowed minimum is a two-bucket flip-flop with lazy flips
//     off the pass `now_ns`, an idle gap of ≥ 2 windows discards
//     stale buckets, and the snapshot export zeroes once the queue
//     has gone ≥ 2 windows without a pop — a stale standing-queue
//     reading can never outlive the backlog that produced it.

use super::{COS_SOJOURN_WINDOW_NS, CoSQueueSojourn};

#[test]
fn zero_enqueue_ns_records_nothing() {
    let mut s = CoSQueueSojourn::default();
    s.record(0, 5_000_000_000);
    assert_eq!(s, CoSQueueSojourn::default());
    assert_eq!(s.windowed_min_export(5_000_000_000), 0);
}

#[test]
fn ewma_and_peak_track_samples() {
    let mut s = CoSQueueSojourn::default();
    let base = 10 * COS_SOJOURN_WINDOW_NS;
    // One 8 ms sample: EWMA does the shift-add warm-up step, peak
    // jumps straight to the sample.
    s.record(base - 8_000_000, base);
    assert_eq!(s.ewma_ns, 1_000_000); // 8 ms / 8
    assert_eq!(s.peak_ns, 8_000_000);
    // A smaller second sample never lowers the peak.
    s.record(base - 1_000_000, base);
    assert_eq!(s.peak_ns, 8_000_000);
    // EWMA converges towards a constant input.
    let mut s = CoSQueueSojourn::default();
    for _ in 0..200 {
        s.record(base - 8_000_000, base);
    }
    assert!(
        s.ewma_ns > 7_900_000 && s.ewma_ns <= 8_000_000,
        "EWMA must converge to the constant 8 ms input, got {}",
        s.ewma_ns
    );
}

#[test]
fn windowed_min_tracks_current_window_running_min() {
    let mut s = CoSQueueSojourn::default();
    let base = 10 * COS_SOJOURN_WINDOW_NS;
    s.record(base - 5_000_000, base); // 5 ms
    s.record(base - 2_000_000, base); // 2 ms — new min
    s.record(base - 9_000_000, base); // 9 ms — not a min
    assert_eq!(s.windowed_min_export(base), 2_000_000);
    assert_eq!(s.peak_ns, 9_000_000);
}

#[test]
fn windowed_min_flip_covers_previous_and_current_window() {
    let mut s = CoSQueueSojourn::default();
    let base = 10 * COS_SOJOURN_WINDOW_NS;
    // Window 1: min 3 ms.
    s.record(base - 3_000_000, base);
    // One window later: the flip promotes window 1's min to the
    // previous bucket; the new sample (7 ms) starts the current
    // bucket. Export = min(prev=3 ms, cur=7 ms).
    let t2 = base + COS_SOJOURN_WINDOW_NS;
    s.record(t2 - 7_000_000, t2);
    assert_eq!(s.win_prev_min_ns, 3_000_000);
    assert_eq!(s.win_cur_min_ns, 7_000_000);
    assert_eq!(s.windowed_min_export(t2), 3_000_000);
    // Another flip: 7 ms becomes the previous bucket; a 4 ms sample
    // starts the new current bucket. The 3 ms reading has aged out.
    let t3 = t2 + COS_SOJOURN_WINDOW_NS;
    s.record(t3 - 4_000_000, t3);
    assert_eq!(s.windowed_min_export(t3), 4_000_000);
}

#[test]
fn idle_gap_of_two_windows_discards_stale_buckets() {
    let mut s = CoSQueueSojourn::default();
    let base = 10 * COS_SOJOURN_WINDOW_NS;
    s.record(base - 1_000_000, base); // 1 ms standing reading
    // Queue idles for 2 full windows, then a 6 ms sample arrives.
    // The flip must DISCARD the stale 1 ms bucket rather than
    // promote it — the export reflects only the fresh sample.
    let t2 = base + 2 * COS_SOJOURN_WINDOW_NS;
    s.record(t2 - 6_000_000, t2);
    assert_eq!(s.win_prev_min_ns, u64::MAX);
    assert_eq!(s.windowed_min_export(t2), 6_000_000);
}

#[test]
fn export_zeroes_when_no_recent_pops() {
    let mut s = CoSQueueSojourn::default();
    // Never recorded → 0.
    assert_eq!(s.windowed_min_export(10 * COS_SOJOURN_WINDOW_NS), 0);
    let base = 10 * COS_SOJOURN_WINDOW_NS;
    s.record(base - 5_000_000, base);
    // Fresh → the reading.
    assert_eq!(s.windowed_min_export(base + 1), 5_000_000);
    // Snapshot ≥ 2 windows after the last flip → stale, export 0.
    // EWMA/peak keep their values (lifetime/supporting context).
    assert_eq!(
        s.windowed_min_export(base + 2 * COS_SOJOURN_WINDOW_NS),
        0
    );
    assert_eq!(s.peak_ns, 5_000_000);
}

#[test]
fn clock_skew_enqueue_after_now_saturates_to_zero() {
    // An item stamped "after" the drain pass's now_ns (possible
    // only via pass-boundary skew) must saturate to 0, not wrap.
    let mut s = CoSQueueSojourn::default();
    let base = 10 * COS_SOJOURN_WINDOW_NS;
    s.record(base + 1_000_000, base);
    assert_eq!(s.peak_ns, 0);
    assert_eq!(s.windowed_min_export(base), 0);
}
