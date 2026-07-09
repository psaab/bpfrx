use super::*;

/// #941 Work item D: hard-cap activation. After
/// V_MIN_CONSECUTIVE_SKIP_HARD_CAP back-to-back throttle decisions,
/// the function force-continues AND arms suspension.
#[test]
fn vmin_hard_cap_force_continue_activates_suspension() {
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
    // Peer 0 publishes a tiny vtime — guarantees the throttle path.
    floor.slots[0].publish(0);
    test_flow_fair_state_mut(queue).queue_vtime = 100 * 1024 * 1024; // 100 MB ahead, way past lag.
    // Each call returns false (throttle) until consecutive_v_min_skips
    // reaches HARD_CAP. The Nth call returns true (force-continue) and
    // arms suspension.
    for n in 1..V_MIN_CONSECUTIVE_SKIP_HARD_CAP {
        let cont = cos_queue_v_min_continue(queue, 1);
        assert!(
            !cont,
            "throttle must fire on call {} of {}",
            n, V_MIN_CONSECUTIVE_SKIP_HARD_CAP
        );
    }
    // The Nth call hits the hard-cap.
    let final_cont = cos_queue_v_min_continue(queue, 1);
    assert!(final_cont, "hard-cap activation must force-continue");
    assert_eq!(
        queue.v_min.v_min_suspended_remaining, V_MIN_SUSPENSION_BATCHES,
        "hard-cap must arm suspension to V_MIN_SUSPENSION_BATCHES",
    );
    assert_eq!(
        queue.v_min.consecutive_v_min_skips, 0,
        "hard-cap must reset consecutive skips to 0",
    );
    assert_eq!(
        queue.v_min.v_min_hard_cap_overrides_scratch, 1,
        "hard-cap activation must increment the override counter",
    );
}

// #hb166 T-6(a): consecutive hard-cap activations (no intervening
// passing V_min check) must DECAY the suspension re-arm window — halving
// it toward V_MIN_SUSPENSION_MIN_BATCHES — so a persistently-skewed queue
// re-engages the fairness brake progressively sooner instead of parking
// it off for the fixed 1000-batch window every time. A clean V_min check
// resets the window to full.
//
// FAIL-ON-REVERT: restoring the fixed
// `v_min_suspended_remaining = V_MIN_SUSPENSION_BATCHES` arm flips the
// 2nd/3rd activation assertions from 500/250 back to 1000.
#[test]
fn vmin_hard_cap_rearm_decays_suspension_window() {
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

    // Drive one full hard-cap cycle: 7 throttles then the force-continue.
    let fire_hard_cap = |queue: &mut CoSQueueRuntime| {
        for _ in 1..V_MIN_CONSECUTIVE_SKIP_HARD_CAP {
            assert!(!cos_queue_v_min_continue(queue, 1), "throttle expected");
        }
        assert!(cos_queue_v_min_continue(queue, 1), "hard-cap force-continue");
    };

    fire_hard_cap(queue);
    assert_eq!(
        queue.v_min.v_min_suspended_remaining, V_MIN_SUSPENSION_BATCHES,
        "1st activation arms the full window",
    );
    fire_hard_cap(queue);
    assert_eq!(
        queue.v_min.v_min_suspended_remaining,
        V_MIN_SUSPENSION_BATCHES / 2,
        "2nd consecutive activation halves the window",
    );
    fire_hard_cap(queue);
    assert_eq!(
        queue.v_min.v_min_suspended_remaining,
        V_MIN_SUSPENSION_BATCHES / 4,
        "3rd consecutive activation halves again",
    );

    // A clean V_min check (queue within lag of the peer) resets the window.
    test_flow_fair_state_mut(queue).queue_vtime = 0;
    assert!(cos_queue_v_min_continue(queue, 1), "queue is now within lag");
    assert_eq!(
        queue.v_min.v_min_suspension_window, V_MIN_SUSPENSION_BATCHES,
        "a passing V_min check restores the full window",
    );
    // ...and the next activation re-arms at the full window.
    test_flow_fair_state_mut(queue).queue_vtime = 100 * 1024 * 1024;
    fire_hard_cap(queue);
    assert_eq!(
        queue.v_min.v_min_suspended_remaining, V_MIN_SUSPENSION_BATCHES,
        "after reset the window re-arms at full",
    );
}

// #hb166 T-6(a): every consumed suspension slot must increment the
// per-queue scratch counter so telemetry stops reading "brake idle" while
// the brake is actually suppressed.
//
// FAIL-ON-REVERT: dropping the scratch increment in
// `cos_queue_v_min_consume_suspension` leaves the counter at 0.
#[test]
fn vmin_consume_suspension_counts_suspended_batches() {
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
    queue.v_min.v_min_suspended_remaining = 5;
    for _ in 0..5 {
        assert!(cos_queue_v_min_consume_suspension(queue));
    }
    // Drained — no further count.
    assert!(!cos_queue_v_min_consume_suspension(queue));
    assert_eq!(
        queue.v_min.v_min_suspended_batches_scratch, 5,
        "each consumed suspension slot must be counted exactly once",
    );
}

/// #941 Work item D: `cos_queue_v_min_consume_suspension` decrements
/// the counter once per call and returns the suspension state.
#[test]
fn vmin_consume_suspension_decrements_once() {
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
    // No suspension active initially — returns false, no change.
    assert!(!cos_queue_v_min_consume_suspension(queue));
    assert_eq!(queue.v_min.v_min_suspended_remaining, 0);
    // Arm suspension manually (simulating hard-cap).
    queue.v_min.v_min_suspended_remaining = 5;
    // Each call decrements by 1 and returns true.
    for expected_remaining in (0..5).rev() {
        assert!(cos_queue_v_min_consume_suspension(queue));
        assert_eq!(queue.v_min.v_min_suspended_remaining, expected_remaining);
    }
    // Drained — next call returns false.
    assert!(!cos_queue_v_min_consume_suspension(queue));
    assert_eq!(queue.v_min.v_min_suspended_remaining, 0);
}

/// #941 Work item D + Gemini Q6: the drain-call preflight must NOT
/// burn a suspension slot when free_tx_frames is empty (no work
/// can be done). Validates `cos_queue_v_min_consume_suspension`
/// is called AFTER the preflight, not before.
#[test]
fn vmin_suspension_not_decremented_on_empty_tx_frames() {
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
    // Arm suspension at a known value.
    queue.v_min.v_min_suspended_remaining = 100;
    let initial = queue.v_min.v_min_suspended_remaining;
    let area = MmapArea::new(2 * 1024 * 1024).expect("mmap");
    let mut empty_free: VecDeque<u64> = VecDeque::new();
    let mut scratch: Vec<(u64, TxRequest)> = Vec::new();
    // Call drain with empty free_tx_frames. The function should
    // return early WITHOUT consuming a suspension slot.
    let _ = drain_exact_local_items_to_scratch_flow_fair(
        queue,
        &mut empty_free,
        &mut scratch,
        &area,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert_eq!(
        queue.v_min.v_min_suspended_remaining, initial,
        "drain with empty free_tx_frames must NOT consume a suspension slot",
    );
}

/// #941 Work item D: hard-cap counter increments and is reset on a
/// successful pop (V_min returns true with no peers participating).
#[test]
fn vmin_hard_cap_counter_resets_on_success() {
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
    // 3 throttles increment the counter to 3.
    for _ in 0..3 {
        assert!(!cos_queue_v_min_continue(queue, 1));
    }
    assert_eq!(queue.v_min.consecutive_v_min_skips, 3);
    // Now make the check succeed: vacate the peer, so participating==0.
    floor.slots[0].vacate();
    assert!(cos_queue_v_min_continue(queue, 1));
    assert_eq!(
        queue.v_min.consecutive_v_min_skips, 0,
        "successful V_min check must reset consecutive_v_min_skips",
    );
}

/// #941: confirms Work item B was correctly dropped. After Work
/// item A vacates, the slot stays NOT_PARTICIPATING until the next
/// post-settle publish (#940's hook). No first-enqueue publish.
#[test]
fn vmin_no_first_enqueue_publish() {
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
    // Establish slot at NOT_PARTICIPATING (initial state from
    // SharedCoSQueueVtimeFloor::new()).
    assert!(floor.slots[1].read().is_none());
    // Enqueue an item — Work item A's hook does NOT fire on enqueue,
    // and Work item B was dropped so no first-enqueue publish either.
    let key = test_session_key(1234, 5201);
    account_cos_queue_flow_enqueue(queue, Some(&key), 1500);
    assert!(
        floor.slots[1].read().is_none(),
        "no first-enqueue publish: slot must remain NOT_PARTICIPATING after enqueue (Work item B was DROPPED)",
    );
}

