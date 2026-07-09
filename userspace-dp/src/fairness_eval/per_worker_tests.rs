//! Codex round-5 finding #1: these tests exercise the
//! production aggregation helper and the direction multiplier
//! gate end-to-end, not just the parser shape. They will
//! catch:
//!   - per-worker grouping replaced by per-binding grouping;
//!   - direction_multiplier reverted from 1 → 2 when iface
//!     filter is active;
//!   - iface_filter_active misclassifying legacy 3-col input;
//!   - sum-then-median replaced by raw count.
use super::*;

fn row(ts: u64, slot: u32, qid: u32, wid: u32, iface: &str, count: u32) -> BindingFlowsRow {
    BindingFlowsRow {
        timestamp: ts,
        binding_slot: slot,
        queue_id: qid,
        worker_id: wid,
        iface: iface.to_string(),
        count,
    }
}

fn cos_row(ts: u64, ifindex: i32, qid: u32, wid: u32, count: u32) -> CosFlowsRow {
    CosFlowsRow {
        timestamp: ts,
        ifindex,
        queue_id: qid,
        worker_id: wid,
        count,
    }
}

#[test]
fn aggregate_per_worker_filters_iface_and_groups_by_worker() {
    // 3 timestamps × 6 workers, one row per worker per ts on
    // ge-0-0-2 with count = worker_id+1, plus noise on ge-0-0-3
    // with very large counts that MUST NOT contaminate the
    // filtered distribution.
    let mut rows = Vec::new();
    for ts in 1000u64..1003 {
        for w in 0u32..6 {
            rows.push(row(ts, w, 0, w, "ge-0-0-2", w + 1));
            rows.push(row(ts, 100 + w, 0, w, "ge-0-0-3", 999));
        }
    }
    let r = aggregate_per_worker(&rows, "ge-0-0-2", 6, 0, 0, 0, 0).unwrap();
    assert!(r.iface_filter_active);
    assert_eq!(r.distribution_a_i, vec![1, 2, 3, 4, 5, 6]);
}

#[test]
fn aggregate_per_worker_sums_multiple_queues_per_worker() {
    // Same worker has 2 queue bindings on the same iface — the
    // per-(ts,worker) accumulator must SUM those, not replace.
    let mut rows = Vec::new();
    for ts in 1000u64..1003 {
        // worker 0: q0 contributes 2, q1 contributes 3 → expect 5
        rows.push(row(ts, 0, 0, 0, "ge-0-0-2", 2));
        rows.push(row(ts, 1, 1, 0, "ge-0-0-2", 3));
        // workers 1..5: single queue, count=1
        for w in 1u32..6 {
            rows.push(row(ts, w + 1, 0, w, "ge-0-0-2", 1));
        }
    }
    let r = aggregate_per_worker(&rows, "ge-0-0-2", 6, 0, 0, 0, 0).unwrap();
    assert_eq!(r.distribution_a_i, vec![5, 1, 1, 1, 1, 1]);
}

#[test]
fn aggregate_per_worker_legacy_3col_disables_filter() {
    // Legacy parser produces iface="" and worker_id == binding_slot.
    // Even with --iface set, iface_filter_active should be false
    // because no row carries a non-empty iface label.
    let rows: Vec<_> = (0u32..6)
        .flat_map(|w| (1000u64..1003).map(move |ts| row(ts, w, 0, w, "", 7)))
        .collect();
    let r = aggregate_per_worker(&rows, "ge-0-0-2", 6, 0, 0, 0, 0).unwrap();
    assert!(!r.iface_filter_active, "legacy 3-col must collapse filter");
    // Each worker still appears at its slot/wid index with count 7.
    assert_eq!(r.distribution_a_i, vec![7, 7, 7, 7, 7, 7]);
}

#[test]
fn aggregate_per_worker_missing_workers_default_to_zero() {
    // Only workers 0, 2, 4 produce samples; workers 1, 3, 5 are
    // expected to report 0 in the output Vec at indices 1, 3, 5.
    let rows: Vec<_> = (1000u64..1003)
        .flat_map(|ts| {
            [0u32, 2, 4]
                .iter()
                .map(move |&w| row(ts, w, 0, w, "ge-0-0-2", 4))
        })
        .collect();
    let r = aggregate_per_worker(&rows, "ge-0-0-2", 6, 0, 0, 0, 0).unwrap();
    assert_eq!(r.distribution_a_i, vec![4, 0, 4, 0, 4, 0]);
}

#[test]
fn aggregate_per_worker_median_smooths_jitter() {
    // worker 0 sees counts 1, 5, 5 over 3 ts → median 5.
    // worker 1 sees 5, 1, 1 → median 1. (Filters out single
    // outliers on either side.)
    let rows = vec![
        row(1000, 0, 0, 0, "ge-0-0-2", 1),
        row(1001, 0, 0, 0, "ge-0-0-2", 5),
        row(1002, 0, 0, 0, "ge-0-0-2", 5),
        row(1000, 1, 0, 1, "ge-0-0-2", 5),
        row(1001, 1, 0, 1, "ge-0-0-2", 1),
        row(1002, 1, 0, 1, "ge-0-0-2", 1),
    ];
    let r = aggregate_per_worker(&rows, "ge-0-0-2", 2, 0, 0, 0, 0).unwrap();
    assert_eq!(r.distribution_a_i, vec![5, 1]);
}

#[test]
fn aggregate_per_worker_rejects_out_of_range_worker_id() {
    // A row with worker_id >= n_total_workers must produce Err, not
    // silently produce a zero entry. Silently ignoring would allow a
    // misconfigured --n-workers to yield a false PASS verdict.
    let rows = vec![
        row(1000, 0, 0, 0, "ge-0-0-2", 3),
        row(1000, 1, 0, 6, "ge-0-0-2", 5), // worker_id=6 out of range for n=6
    ];
    let result = aggregate_per_worker(&rows, "ge-0-0-2", 6, 0, 0, 0, 0);
    assert!(result.is_err(), "out-of-range worker_id should return Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("worker_id=6"),
        "error should mention the bad worker_id: {msg}"
    );
}

#[test]
fn aggregate_per_worker_anchors_window_to_iperf_epoch_not_scrape_extent() {
    // V-6: the scrape file spans ts 900..1060, but the iperf run is
    // epoch=1000, duration=60 → run interval [1000, 1060]. Stale
    // pre-run samples (worker 0 pile-up at ts 900..999) must be
    // excluded by epoch anchoring. On the min/max scrape-extent
    // fallback (the bug) they would enter the window and inflate
    // worker 0's median.
    let mut rows = Vec::new();
    for ts in 900u64..1000 {
        rows.push(row(ts, 0, 0, 0, "ge-0-0-2", 99));
    }
    for ts in 1000u64..1061 {
        for w in 0u32..6 {
            rows.push(row(ts, w, 0, w, "ge-0-0-2", 1));
        }
    }
    let r = aggregate_per_worker(&rows, "ge-0-0-2", 6, 0, 0, 1000, 60).unwrap();
    assert_eq!(
        r.distribution_a_i,
        vec![1, 1, 1, 1, 1, 1],
        "stale pre-run worker-0 pile-up must be excluded by iperf-epoch anchoring"
    );
}

#[test]
fn aggregate_cos_per_worker_filters_ifindex_and_queue() {
    let mut rows = Vec::new();
    for ts in 1000u64..1003 {
        rows.push(cos_row(ts, 80, 4, 0, 3));
        rows.push(cos_row(ts, 80, 4, 1, 5));
        rows.push(cos_row(ts, 80, 5, 0, 99));
        rows.push(cos_row(ts, 81, 4, 1, 99));
    }
    let r = aggregate_cos_per_worker(&rows, 80, 4, 3, 0, 0, 0, 0).unwrap();
    assert_eq!(r, vec![3, 5, 0]);
}

#[test]
fn aggregate_cos_per_worker_zero_fills_dead_worker_across_window() {
    // V-5: worker 0's flows die after the first 10 of 100 scrapes;
    // workers 1-5 stay live on the same queue for the whole window.
    // Median over PRESENT samples (the bug) keeps worker 0 at 2;
    // zero-filling across the full scrape universe correctly reports
    // it inactive (median 0).
    let mut rows = Vec::new();
    for ts in 1000u64..1100 {
        if ts < 1010 {
            rows.push(cos_row(ts, 80, 4, 0, 2));
        }
        for w in 1u32..6 {
            rows.push(cos_row(ts, 80, 4, w, 2));
        }
    }
    let r = aggregate_cos_per_worker(&rows, 80, 4, 6, 0, 0, 0, 0).unwrap();
    assert_eq!(
        r[0], 0,
        "dead worker must be seen as inactive (median 0), not its stale live value"
    );
    assert_eq!(&r[1..], &[2, 2, 2, 2, 2]);
}

#[test]
fn direction_multiplier_iface_filter_active_is_one() {
    assert_eq!(direction_multiplier(true), 1);
}

#[test]
fn direction_multiplier_no_iface_filter_is_two() {
    assert_eq!(direction_multiplier(false), 2);
}

#[test]
fn guard_sum_tolerances_are_asymmetric_for_stale_overcount() {
    assert_eq!(guard_sum_tolerances(12), (2, 3));
    assert_eq!(guard_sum_tolerances(2), (2, 2));
    assert_eq!(guard_sum_tolerances(40), (4, 10));
}

#[test]
fn trim_distribution_to_sum_removes_accepted_overcount_from_largest_buckets() {
    assert_eq!(
        trim_distribution_to_sum(&[4, 4, 4, 3, 0, 0], 12),
        vec![3, 3, 3, 3, 0, 0]
    );
    assert_eq!(trim_distribution_to_sum(&[1, 2, 3], 3), vec![1, 1, 1]);
    assert_eq!(trim_distribution_to_sum(&[1, 2, 3], 10), vec![1, 2, 3]);
    assert_eq!(trim_distribution_to_sum(&[0, 0, 0], 0), vec![0, 0, 0]);
}
