use super::*;

/// #785 Phase 3 — pin that a high-rate exact queue
/// (shared_exact=true) IS promoted onto the flow-fair path AND
/// has its `shared_exact` shadow cached. The shadow drives the
/// admission-gate downgrade (aggregate-only) in
/// `cos_queue_flow_share_limit` and
/// `apply_cos_admission_ecn_policy`. The MQFQ VFT ordering in
/// `cos_queue_pop_front` is what actually enforces per-flow
/// fairness on this queue — the share cap + per-flow ECN arm
/// are rate-unaware (24 KB floor) and would tail-drop TCP at
/// 25 Gbps. Retrospective Attempt A measured 22.3 → 16.3 Gbps +
/// 25 k retrans when the cap was enforced on shared_exact;
/// Phase 3 replaces the cap's fairness role with VFT ordering.
#[test]
fn queue_flow_fair_enabled_on_shared_exact() {
    use crate::afxdp::worker::COS_SHARED_EXACT_MIN_RATE_BYTES;

    let high_rate_bytes = 25_000_000_000u64 / 8;
    assert!(
        high_rate_bytes >= COS_SHARED_EXACT_MIN_RATE_BYTES,
        "fixture must be above the shared_exact threshold or the \
         test does not exercise the regression surface",
    );

    let mut runtime = test_cos_runtime_with_queues(
        100_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: high_rate_bytes,
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
    assert!(!runtime.queues[0].flow_fair());
    assert!(!runtime.queues[0].shared_exact());

    // Drive the full ensure_cos_interface_runtime promotion loop.
    let fast_path = vec![test_queue_fast_path_for_promotion(true)];
    apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path, 0);

    assert!(
        runtime.queues[0].flow_fair(),
        "#785 Phase 3: shared_exact queue MUST be promoted onto \
         the flow-fair path so MQFQ virtual-finish-time ordering \
         runs in the dequeue path. Regression here re-opens the \
         CoV gap we just measured closed.",
    );
    assert!(
        runtime.queues[0].shared_exact(),
        "#785 Phase 3: shared_exact shadow MUST be cached onto \
         the runtime so the admission gates in \
         cos_queue_flow_share_limit and \
         apply_cos_admission_ecn_policy downgrade to \
         aggregate-only. Per-flow admission gates are rate-\
         unaware (24 KB floor) and would tail-drop TCP at \
         multi-Gbps per-flow rates.",
    );
    assert_ne!(
        test_flow_fair_state(&runtime.queues[0]).flow_hash_seed,
        0,
        "seed must be drawn on flow-fair promotion so MQFQ \
         bucket assignment is not an externally-probeable \
         pure function of the 5-tuple",
    );
}

/// Pin that a low-rate exact queue (shared_exact=false) IS
/// promoted onto the SFQ path AND has `shared_exact=false` on
/// its runtime. The #784 fairness fix on the 1 Gbps iperf-a
/// queue depends on BOTH halves: flow_fair=true so DRR orders
/// per-flow, and shared_exact=false so the per-flow share cap
/// + per-flow ECN arm still run (at 1 Gbps / 12 flows the cap is
/// ~24 KB which matches TCP cwnd at 77 Mbps flows cleanly).
#[test]
fn queue_flow_fair_enabled_on_owner_local_exact() {
    use crate::afxdp::worker::COS_SHARED_EXACT_MIN_RATE_BYTES;

    let low_rate_bytes = 1_000_000_000u64 / 8;
    assert!(
        low_rate_bytes < COS_SHARED_EXACT_MIN_RATE_BYTES,
        "fixture must be below the shared_exact threshold to \
         exercise the owner-local-exact path",
    );

    let mut runtime = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: low_rate_bytes,
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
    let fast_path = vec![test_queue_fast_path_for_promotion(false)];
    apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path, 0);

    assert!(
        runtime.queues[0].flow_fair(),
        "owner-local-exact queue MUST be promoted onto the SFQ \
         path — #784 fairness fix depends on it",
    );
    assert!(
        !runtime.queues[0].shared_exact(),
        "owner-local-exact queue MUST keep shared_exact=false so \
         the per-flow share cap and per-flow ECN arm continue to \
         run — #784 depends on the per-flow cap firing at 1 Gbps",
    );
    assert_ne!(
        test_flow_fair_state(&runtime.queues[0]).flow_hash_seed,
        0,
        "seed must be drawn on flow-fair promotion — otherwise \
         every binding hashes flows identically and one flow's \
         RSS bucket collides across the whole deployment",
    );
}

/// Pin that a non-exact (best-effort) queue is NOT promoted onto
/// the flow-fair path. SFQ would be wasted work on these queues:
/// there is no per-flow rate contract, so per-flow isolation is
/// meaningless, and drawing an OS random seed for every
/// non-exact queue on every runtime build would add a syscall
/// per queue for zero benefit. This pin also doubles as a sanity
/// check that the gate did not collapse to
/// `queue.flow_fair = true` unconditionally.
#[test]
fn queue_flow_fair_disabled_on_non_exact() {
    let mut runtime = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 3,
            transmit_rate_bytes: 0,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 128 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );

    // Drive the production loop with shared_exact=false first,
    // then again with shared_exact=true — both MUST leave a
    // non-exact queue off the flow-fair path, because the gate's
    // LHS (`queue.exact`) fails regardless of the fast-path bit.
    let fast_path_owner_local = vec![test_queue_fast_path_for_promotion(false)];
    apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path_owner_local, 0);
    assert!(
        !runtime.queues[0].flow_fair(),
        "non-exact queues must stay off the flow-fair path: SFQ \
         has no rate contract to enforce there, and draws an OS \
         random seed per queue",
    );

    let fast_path_shared = vec![test_queue_fast_path_for_promotion(true)];
    apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path_shared, 0);
    assert!(
        !runtime.queues[0].flow_fair(),
        "non-exact queues must stay off the flow-fair path \
         regardless of the shared_exact signal",
    );
}

