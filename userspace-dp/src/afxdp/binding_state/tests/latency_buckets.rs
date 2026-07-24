// bucket_index_for_ns layout + drain/redirect-acquire histogram
// sampling + per-worker seed tests. Split from umem/tests.rs (#4667).

use super::*;

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
    assert_eq!(
        bucket_index_for_ns(1_000_000_000_000),
        DRAIN_HIST_BUCKETS - 1
    );
}

#[test]
fn drain_latency_hist_increments_on_recorded_drain() {
    // #709: exercise the hist-update path in isolation. We do not
    // call `drain_shaped_tx` here (requires a fully-constructed
    // BindingWorker fixture); instead, we recreate the exact shape
    // binding_state/latency.rs::bucket_index_for_ns uses + fetch_add — and assert
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

// #5160 FAIL-ON-REVERT: the redirect sample sequence must be PRODUCER-LOCAL
// (thread-local), NOT a shared atomic on the destination BindingLiveState.
//
// Proof: PRODUCERS independent producer threads each do exactly ONE enqueue
// into the SAME destination binding. With a producer-local sequence, every
// fresh thread's counter starts at 0, so its first (and only) enqueue is the
// sampled 1-in-(MASK+1) op — PRODUCERS samples land in the destination
// histogram. With the pre-#5160 SHARED counter, the PRODUCERS enqueues bump ONE
// counter (0..PRODUCERS-1) so only the first is sampled — 1 sample. Asserting
// the total == PRODUCERS goes RED if the shared per-destination RMW is
// restored (it would read 1). PRODUCERS < REDIRECT_SAMPLE_MASK+1 so the shared
// counter would not wrap into a second sample.
#[test]
fn redirect_sample_sequence_is_producer_local_not_destination_shared() {
    const PRODUCERS: usize = 4;
    let live = std::sync::Arc::new(BindingLiveState::new());
    live.max_pending_tx.store(8192, Ordering::Relaxed);
    let handles: Vec<_> = (0..PRODUCERS)
        .map(|p| {
            let live = std::sync::Arc::clone(&live);
            std::thread::spawn(move || {
                // Each fresh thread's REDIRECT_SAMPLE_SEQ starts at 0, so this
                // single enqueue is the sampled op for that producer.
                live.enqueue_tx_owned(test_tx_request_for_inbox(p as u8))
                    .expect("push");
            })
        })
        .collect();
    for h in handles {
        h.join().expect("producer thread join");
    }
    let total_samples: u64 = live
        .owner_profile_peer
        .redirect_acquire_hist
        .iter()
        .map(|slot| slot.load(Ordering::Relaxed))
        .sum();
    assert_eq!(
        total_samples, PRODUCERS as u64,
        "each producer thread must sample its OWN first enqueue \
         (producer-local sequence); a shared destination counter would sample \
         only 1-in-{} across all producers",
        REDIRECT_SAMPLE_MASK + 1
    );
}
