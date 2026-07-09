use super::*;

/// #4259 (hb166 R-1) — the positive action of the cap-aware MQFQ
/// selector: with a FINITE `target_bps`, a bucket whose observed rate
/// exceeds the target is deferred in favor of a less-served (under-cap)
/// bucket, even though the over-cap bucket has the LOWER virtual-finish
/// time. Before this test the cap-aware branch of
/// `cos_queue_min_finish_bucket` had no direct coverage — only the
/// `target_bps == u64::MAX` no-op fast path was exercised.
#[test]
fn cap_aware_selector_defers_over_cap_bucket() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 25_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 128 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    enable_test_flow_fair(queue);

    // Two flows in DISTINCT buckets (seed 0 after enable_test_flow_fair).
    let src_a: u16 = 9999;
    let bucket_a = cos_flow_bucket_index(0, Some(&test_session_key(src_a, 5201)));
    let mut src_b: u16 = 9000;
    let bucket_b = loop {
        let b = cos_flow_bucket_index(0, Some(&test_session_key(src_b, 5201)));
        if b != bucket_a {
            break b;
        }
        src_b += 1;
    };

    // Enqueue A small (500 B) then B large (1500 B). With queue_vtime at
    // 0 the head-finish anchors at bytes, so head_a=500 < head_b=1500 —
    // the over-cap bucket is the LOWER-finish one, which a naive
    // min-finish selector would pick.
    cos_queue_push_back(queue, test_flow_cos_item(src_a, 500));
    cos_queue_push_back(queue, test_flow_cos_item(src_b, 1500));
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        500,
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_b],
        1500,
    );

    // A over cap (2 Gbps), B under cap (10 Mbps); target 100 Mbps.
    {
        let ff = test_flow_fair_state_mut(queue);
        ff.flow_bucket_observed_bps[bucket_a] = 2_000_000_000;
        ff.flow_bucket_observed_bps[bucket_b] = 10_000_000;
    }

    // No-cap selector: lowest finish wins → over-cap bucket A.
    assert_eq!(
        cos_queue_min_finish_bucket(test_flow_fair_state(queue), u64::MAX),
        Some(bucket_a as u16),
        "no-cap selection must pick the lowest-finish bucket",
    );
    // Cap-aware selector: defers over-cap A, picks under-cap B despite
    // its higher finish — the positive cap action.
    assert_eq!(
        cos_queue_min_finish_bucket(test_flow_fair_state(queue), 100_000_000),
        Some(bucket_b as u16),
        "cap-aware selector must defer the over-cap bucket in favor of \
         the under-cap one",
    );

    // All-over-cap: raise B over the target too. The selector is
    // work-conserving — it falls back to the lowest-finish bucket (A)
    // rather than stalling.
    {
        let ff = test_flow_fair_state_mut(queue);
        ff.flow_bucket_observed_bps[bucket_b] = 3_000_000_000;
    }
    assert_eq!(
        cos_queue_min_finish_bucket(test_flow_fair_state(queue), 100_000_000),
        Some(bucket_a as u16),
        "all-over-cap must fall back to the lowest-finish bucket \
         (work-conserving, no stall)",
    );
}

/// #4259 (hb166 R-1) — a recycled bucket must not inherit a departed
/// flow's observed-rate EWMA. When a bucket drains to 0 (the flow ends),
/// `account_cos_queue_flow_dequeue` now zeros the per-bucket EWMA state
/// so the next flow that hashes into the bucket starts clean instead of
/// being deferred by the cap-aware selector as if it were the old
/// elephant.
///
/// RED-on-revert: without the reset the `observed_bps`/`last_tx_ns`/
/// `pending_bytes` assertions below fail — the departed elephant's
/// 2 Gbps survives flow death indefinitely.
#[test]
fn bucket_recycle_zeros_stale_observed_rate() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 25_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 128 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    enable_test_flow_fair(queue);

    let src = 9999u16;
    let bucket = cos_flow_bucket_index(0, Some(&test_session_key(src, 5201)));

    // Elephant fills the bucket and drives its EWMA state high.
    cos_queue_push_back(queue, test_flow_cos_item(src, 1500));
    {
        let ff = test_flow_fair_state_mut(queue);
        ff.flow_bucket_observed_bps[bucket] = 2_000_000_000;
        ff.flow_bucket_last_tx_ns[bucket] = 123_456;
        ff.flow_bucket_pending_bytes[bucket] = 4096;
        // Monotonic lifetime counter — must be preserved across recycle.
        ff.flow_bucket_tx_bytes[bucket] = 9_000_000;
    }

    // Flow ends: drain the bucket to 0 through the real pop path (which
    // calls account_cos_queue_flow_dequeue).
    let popped = cos_queue_pop_front(queue);
    assert!(popped.is_some(), "expected the queued item back");
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket],
        0,
        "bucket must drain to 0 (nonzero→0 transition triggers reset)",
    );

    // Bucket identity ended — EWMA state zeroed so a newcomer is clean.
    let ff = test_flow_fair_state(queue);
    assert_eq!(
        ff.flow_bucket_observed_bps[bucket], 0,
        "recycled bucket must not carry the departed flow's observed rate",
    );
    assert_eq!(
        ff.flow_bucket_last_tx_ns[bucket], 0,
        "recycled bucket last_tx_ns must reset so the next commit takes \
         the first-commit stamp path",
    );
    assert_eq!(
        ff.flow_bucket_pending_bytes[bucket], 0,
        "recycled bucket pending accumulation must be dropped",
    );
    // Lifetime diagnostic counter is monotonic — NOT reset on recycle.
    assert_eq!(
        ff.flow_bucket_tx_bytes[bucket], 9_000_000,
        "monotonic lifetime tx_bytes must survive recycle",
    );
}
