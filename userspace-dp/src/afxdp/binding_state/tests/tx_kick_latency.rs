// #825 TX kick-latency histogram tests. Split from
// umem/tests.rs (#4667).

use super::*;

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
    // bucket_index_for_ns pins (see binding_state/latency.rs):
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
        (500, 0),          // sub-1024 → bucket 0
        (5_000, 3),        // 2^12..2^13 → bucket 3
        (40_000, 6),       // 2^15..2^16 → bucket 6
        (10_000_000, 14),  // 2^23..2^24 → bucket 14
        (100_000_000, 15), // >= 2^24 → bucket 15 (saturate)
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
            snap.tx_kick_latency_hist[bucket], 1,
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
    //       `ts_completion >= ts_submit` pattern at tx/stats.rs::record_tx_completions_with_stamp.
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
    // The production call site at tx/rings.rs::maybe_wake_tx uses
    // `if kick_start != 0 && kick_end >= kick_start {
    // record_kick_latency(...) }` which is the correct guard
    // location (code-review R1 HIGH-1).
}

#[test]
fn tx_kick_retry_count_observable_via_snapshot() {
    // #825 code-review R1 MED-3: pin that the `tx_kick_retry_count`
    // field is (a) writable via the same owner-side atomic that the
    // production call site at tx/rings.rs::maybe_wake_tx EAGAIN branch uses
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
    // at binding_state/tests/tx_submit_latency.rs).
    //
    // Spawn a writer thread that calls `record_kick_latency` in
    // a tight loop; spawn a reader thread that calls
    // `BindingLiveState::snapshot()` in a tight loop. Assert
    // the bounded-skew invariant `|sum(hist) - count| ≤
    // window_delta + K_MARGIN` holds for every reader sample.
    //
    // Deterministic bound (#4011): identical rationale to the
    // tx-submit sibling `tx_latency_hist_cross_thread_snapshot_
    // skew_within_bound`. `record_kick_latency` has the same
    // single-writer / Relaxed / bucket-then-count shape
    // (stats.rs: tx_kick_latency_hist fetch_add, then
    // tx_kick_latency_count fetch_add), so the old
    // ceil(λ_obs × W_read_max) model was the same load-sensitive
    // flake (average rate × max window under-estimates a single
    // window whose instantaneous rate spiked). We replace it with
    // the per-sample directly-measured `window_delta = count_after
    // − count_before` bound: |sum(hist) − count| ≤ window_delta +
    // K_MARGIN, K_MARGIN = 2. Load-independent, and a dropped
    // bucket/count increment still drives skew toward count_final
    // (unbounded relative to any window_delta) → loud failure.
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
        window_delta: u64,
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
        // Bracket each snapshot with a raw `count` load before and
        // after (#4011): window_delta = count_after − count_before
        // is the writer's actual publication count during this
        // snapshot's read window (measured, not modelled).
        let mut local = Vec::with_capacity(16_384);
        while !reader_stop.load(Ordering::Relaxed) {
            let count_before = reader_live
                .owner_profile_owner
                .tx_kick_latency_count
                .load(Ordering::Relaxed);
            let snap = reader_live.snapshot();
            let count_after = reader_live
                .owner_profile_owner
                .tx_kick_latency_count
                .load(Ordering::Relaxed);
            let count = snap.tx_kick_latency_count as i64;
            let sum_buckets: i64 = snap.tx_kick_latency_hist.iter().copied().sum::<u64>() as i64;
            let skew = (sum_buckets - count).abs();
            let window_delta = count_after.saturating_sub(count_before);
            local.push(Sample { skew, window_delta });
        }
        *reader_samples.lock().unwrap() = local;
    });

    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);
    writer_handle.join().expect("writer thread joins cleanly");
    reader_handle.join().expect("reader thread joins cleanly");

    let count_final = live.snapshot().tx_kick_latency_count;
    assert!(
        count_final > 0,
        "writer thread produced no samples — harness broken",
    );

    let gathered = samples.lock().unwrap().clone();
    assert!(
        !gathered.is_empty(),
        "reader thread produced no snapshots — harness broken",
    );

    // Per-sample deterministic bound (#4011): |sum(hist) − count|
    // ≤ window_delta + K_MARGIN for every snapshot. K_MARGIN = 2 =
    // the proven +1 in-flight boundary (one record "hist done,
    // count pending" under TSO's single sequential writer) plus one
    // unit of weak-memory reorder slack. Load-independent.
    const K_MARGIN: i64 = 2;
    let mut max_skew = 0i64;
    let mut max_window_delta = 0u64;
    let mut max_excess = i64::MIN;
    let mut worst = Sample {
        skew: 0,
        window_delta: 0,
    };
    for s in &gathered {
        let excess = s.skew - s.window_delta as i64;
        if excess > max_excess {
            max_excess = excess;
            worst = *s;
        }
        if s.skew > max_skew {
            max_skew = s.skew;
        }
        if s.window_delta > max_window_delta {
            max_window_delta = s.window_delta;
        }
    }
    assert!(
        max_excess <= K_MARGIN,
        "cross-thread skew exceeds per-window bound: worst sample \
         skew={} window_delta={} excess={} (> K_MARGIN={}); \
         max_skew={max_skew} max_window_delta={max_window_delta} \
         count_final={count_final} samples={}",
        worst.skew,
        worst.window_delta,
        max_excess,
        K_MARGIN,
        gathered.len(),
    );
    eprintln!(
        "tx_kick_latency_cross_thread_snapshot_skew_within_bound: \
         max_excess={max_excess} K_MARGIN={K_MARGIN} \
         max_skew={max_skew} max_window_delta={max_window_delta} \
         count_final={count_final} samples={}",
        gathered.len(),
    );
}
