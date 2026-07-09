use super::*;

/// #942: Prepared flow-fair drain MUST honor the V_min throttle.
/// Mirrors Local-flow's `vmin_throttle_function_fires_on_lag_breach`
/// pattern: synthetic peer slot pegged at 0; local qvtime well past
/// LAG_THRESHOLD; cos_queue_v_min_continue must return false. Then
/// the suspended path: when v_min_suspended_remaining is non-zero,
/// the drain consumes one slot and skips V_min entirely.
#[test]
fn vmin_prepared_flow_fair_throttle_and_suspension() {
    let mut umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    floor.slots[0].publish(0);
    test_flow_fair_state_mut(queue).queue_vtime = 100 * 1024 * 1024;

    // Push a Prepared item so the preflight passes.
    let packet = vec![0u8; 1500];
    let prepared = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
    cos_queue_push_back(queue, prepared);

    let mut scratch: Vec<PreparedTxRequest> = Vec::new();
    let mut free_tx: VecDeque<u64> = VecDeque::new();
    let mut pending_fill: VecDeque<u64> = VecDeque::new();
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(
        scratch.is_empty(),
        "V_min throttle must break Prepared drain before any item is committed",
    );
    assert_eq!(queue.v_min.consecutive_v_min_skips, 1);

    // Arm suspension; next drain consumes one slot and skips V_min,
    // draining the pending Prepared item.
    queue.v_min.v_min_suspended_remaining = 5;
    let mut scratch2: Vec<PreparedTxRequest> = Vec::new();
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch2,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );
    assert_eq!(
        queue.v_min.v_min_suspended_remaining, 4,
        "drain MUST consume one suspension slot",
    );
    assert!(
        !scratch2.is_empty(),
        "with suspension active, drain must NOT throttle; Prepared item must reach scratch",
    );
}

/// #942: preflight returns early without consuming suspension when
/// queue head is Local (not Prepared). Mirrors Local-flow's
/// `vmin_suspension_not_decremented_on_empty_tx_frames`.
#[test]
fn vmin_prepared_no_suspension_burn_when_head_is_local() {
    let umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    let _floor = attach_test_vtime_floor(queue, 4, 1);
    queue.v_min.v_min_suspended_remaining = 100;
    let initial = queue.v_min.v_min_suspended_remaining;

    // Queue head is Local — preflight returns Ready early.
    cos_queue_push_back(queue, test_cos_item(1500));

    let mut scratch: Vec<PreparedTxRequest> = Vec::new();
    let mut free_tx: VecDeque<u64> = VecDeque::new();
    let mut pending_fill: VecDeque<u64> = VecDeque::new();
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );
    assert_eq!(
        queue.v_min.v_min_suspended_remaining, initial,
        "Prepared drain with non-Prepared head MUST NOT consume a suspension slot",
    );
}

/// #942 (Codex/Gemini Q4): hard-cap arms via the Prepared drain
/// itself, not just via direct `cos_queue_v_min_continue` calls.
/// After V_MIN_CONSECUTIVE_SKIP_HARD_CAP repeated drain attempts
/// under throttle conditions, the next drain force-continues, arms
/// suspension, and successfully commits the head Prepared item.
#[test]
fn vmin_prepared_drain_arms_hard_cap_after_repeated_throttle() {
    let mut umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    floor.slots[0].publish(0);
    test_flow_fair_state_mut(queue).queue_vtime = 100 * 1024 * 1024;

    let packet = vec![0u8; 1500];
    let prepared = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
    cos_queue_push_back(queue, prepared);

    let mut free_tx: VecDeque<u64> = VecDeque::new();
    let mut pending_fill: VecDeque<u64> = VecDeque::new();

    // First (HARD_CAP - 1) drain calls each throttle and bump
    // consecutive_v_min_skips. The head Prepared item must NOT be
    // committed during these calls.
    for n in 1..V_MIN_CONSECUTIVE_SKIP_HARD_CAP {
        let mut scratch: Vec<PreparedTxRequest> = Vec::new();
        let _ = drain_exact_prepared_items_to_scratch_flow_fair(
            queue,
            &mut scratch,
            &umem,
            &mut free_tx,
            &mut pending_fill,
            0,
            &mut Vec::new(),
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(
            scratch.is_empty(),
            "drain {} of {}: throttle must keep scratch empty",
            n,
            V_MIN_CONSECUTIVE_SKIP_HARD_CAP,
        );
        assert_eq!(
            queue.v_min.consecutive_v_min_skips, n,
            "drain {}: consecutive_v_min_skips must increment",
            n,
        );
        assert_eq!(
            queue.v_min.v_min_suspended_remaining, 0,
            "drain {}: suspension must NOT yet be armed",
            n,
        );
    }

    // The HARD_CAP-th drain hits the cap: force-continues at
    // pop_count=1, arms suspension, drains the item.
    let mut scratch: Vec<PreparedTxRequest> = Vec::new();
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(
        !scratch.is_empty(),
        "hard-cap drain must commit the head Prepared item",
    );
    assert_eq!(
        queue.v_min.v_min_suspended_remaining, V_MIN_SUSPENSION_BATCHES,
        "hard-cap drain must arm suspension to V_MIN_SUSPENSION_BATCHES",
    );
    assert_eq!(
        queue.v_min.consecutive_v_min_skips, 0,
        "hard-cap drain must reset consecutive_v_min_skips",
    );
    assert_eq!(
        queue.v_min.v_min_hard_cap_overrides_scratch, 1,
        "hard-cap drain must increment the override counter",
    );
}

/// #942 (Gemini Q6 missing test): when a peer slot vacates to
/// NOT_PARTICIPATING mid-drain, the next V_min check observes the
/// vacated state through the `Arc<AtomicU64>` and stops throttling.
/// This is the dynamic-correctness counterpart to
/// `vmin_throttle_function_fires_on_lag_breach`.
#[test]
fn vmin_prepared_drain_unblocks_when_peer_slot_vacates() {
    let mut umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    // Peer 0 publishes a tiny vtime — guarantees throttle.
    floor.slots[0].publish(0);
    test_flow_fair_state_mut(queue).queue_vtime = 100 * 1024 * 1024;

    let packet = vec![0u8; 1500];
    let prepared = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
    cos_queue_push_back(queue, prepared);

    // First drain: throttle fires, nothing committed.
    let mut scratch: Vec<PreparedTxRequest> = Vec::new();
    let mut free_tx: VecDeque<u64> = VecDeque::new();
    let mut pending_fill: VecDeque<u64> = VecDeque::new();
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(
        scratch.is_empty(),
        "throttle must hold the Prepared item before vacate",
    );

    // Peer 0 vacates (Work item A path: bucket-empty transition).
    // The Arc<AtomicU64> publishes immediately to all readers.
    floor.slots[0].vacate();

    // Second drain: peer is NOT_PARTICIPATING, V_min returns true,
    // the head item drains.
    let mut scratch2: Vec<PreparedTxRequest> = Vec::new();
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch2,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(
        !scratch2.is_empty(),
        "peer vacate must clear the throttle and let drain proceed",
    );
    assert_eq!(
        queue.v_min.v_min_suspended_remaining, 0,
        "vacate-then-drain must NOT arm suspension (no hard-cap path)",
    );
}

/// #942 (Codex Q4): suspension state is queue-level, not per-drain-
/// function. If the Local drain arms suspension via hard-cap, the
/// subsequent Prepared drain on the same queue MUST see and consume
/// that suspension (rather than re-throttling). Validates the
/// shared `queue.v_min.v_min_suspended_remaining` lifecycle across both
/// drain entry points.
#[test]
fn vmin_local_hard_cap_suspension_carries_into_prepared_drain() {
    let mut umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    floor.slots[0].publish(0);
    test_flow_fair_state_mut(queue).queue_vtime = 100 * 1024 * 1024;

    // Simulate Local hard-cap firing: arm consecutive_v_min_skips
    // to one short of cap, then call cos_queue_v_min_continue
    // directly (matching what Local drain would do at pop_count=1).
    queue.v_min.consecutive_v_min_skips = V_MIN_CONSECUTIVE_SKIP_HARD_CAP - 1;
    let _ = cos_queue_v_min_continue(queue, 1);
    assert_eq!(
        queue.v_min.v_min_suspended_remaining, V_MIN_SUSPENSION_BATCHES,
        "Local hard-cap path must arm queue-level suspension",
    );

    // Now call Prepared drain. With suspension active, V_min check
    // is skipped (no throttle), and the item drains. Suspension is
    // consumed once at drain entry.
    let packet = vec![0u8; 1500];
    let prepared = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
    cos_queue_push_back(queue, prepared);
    let suspension_before = queue.v_min.v_min_suspended_remaining;

    let mut scratch: Vec<PreparedTxRequest> = Vec::new();
    let mut free_tx: VecDeque<u64> = VecDeque::new();
    let mut pending_fill: VecDeque<u64> = VecDeque::new();
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(
        !scratch.is_empty(),
        "Prepared drain under inherited Local-armed suspension must drain",
    );
    assert_eq!(
        queue.v_min.v_min_suspended_remaining,
        suspension_before - 1,
        "Prepared drain must consume exactly one queue-level suspension slot",
    );
}

