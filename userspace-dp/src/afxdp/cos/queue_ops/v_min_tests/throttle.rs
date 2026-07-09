use super::*;

/// #942 (deferred): pin the cos_queue_v_min_continue throttle
/// behavior in isolation. The Prepared flow-fair scratch builder
/// does NOT actually call this in production yet — wiring it
/// caused a severe shared_exact regression that bisection traced
/// to this exact wiring (see plan.md "#942 deferred"). The
/// underlying cos_queue_v_min_continue function still works
/// correctly when called directly, as this test confirms.
#[test]
fn vmin_throttle_function_fires_on_lag_breach() {
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
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);

    // Peer worker 0 pegged at vtime 0. Local worker 1 has
    // queue_vtime well past LAG_THRESHOLD (~1.25 MB at 10 Gb/s).
    floor.slots[0].publish(0);
    test_flow_fair_state_mut(queue).queue_vtime = 100 * 1024 * 1024; // 100 MB ahead

    // V_min check at pop_count==1 must throttle (return false).
    assert!(
        !cos_queue_v_min_continue(queue, 1),
        "throttle MUST fire when local vtime >> peer V_min + LAG",
    );

    // Reset queue_vtime to within LAG and confirm the check passes.
    test_flow_fair_state_mut(queue).queue_vtime = 0;
    assert!(
        cos_queue_v_min_continue(queue, 1),
        "throttle MUST NOT fire when local vtime <= V_min + LAG",
    );
}

/// #943: every regular V_min throttle decision (i.e. not a hard-cap
/// override) bumps `v_min_throttles_scratch`. The scratch flushes
/// to `BindingLiveState::v_min_throttles` in `update_binding_debug_state`
/// (covered separately under the umem flush tests). This test pins
/// just the increment site so a future refactor that drops the
/// counter increment from the throttle path surfaces here.
#[test]
fn vmin_throttle_increments_v_min_throttles_scratch() {
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
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    floor.slots[0].publish(0);
    test_flow_fair_state_mut(queue).queue_vtime = 100 * 1024 * 1024; // 100 MB ahead → throttle

    assert_eq!(
        queue.v_min.v_min_throttles_scratch, 0,
        "scratch starts at zero"
    );

    // Throttle decision (not a hard-cap override).
    let cont = cos_queue_v_min_continue(queue, 1);
    assert!(!cont, "expected throttle decision");
    assert_eq!(
        queue.v_min.v_min_throttles_scratch, 1,
        "regular throttle MUST bump v_min_throttles_scratch by 1"
    );
    assert_eq!(
        queue.v_min.v_min_hard_cap_overrides_scratch, 0,
        "regular throttle MUST NOT bump the hard-cap counter"
    );

    // Two more throttles — counter increments by exactly +1 each.
    // V_MIN_CONSECUTIVE_SKIP_HARD_CAP is fixed at 8 (mod.rs:112) so
    // we're well below the hard-cap boundary; assert the exact
    // count to catch off-by-one or dropped increments
    // (Copilot review).
    let _ = cos_queue_v_min_continue(queue, 1);
    let _ = cos_queue_v_min_continue(queue, 1);
    assert_eq!(
        queue.v_min.v_min_throttles_scratch, 3,
        "three throttles → scratch == 3 (not >= 2 — exact count catches off-by-one)"
    );
}

/// #943: when the hard-cap override fires (after
/// V_MIN_CONSECUTIVE_SKIP_HARD_CAP back-to-back throttles), only
/// `v_min_hard_cap_overrides_scratch` increments — the regular
/// `v_min_throttles_scratch` does NOT. The two counters are
/// disjoint diagnostics; double-counting would muddy the
/// LAG_THRESHOLD ratio metric.
#[test]
fn vmin_hard_cap_override_does_not_double_count_throttle() {
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
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    floor.slots[0].publish(0);
    test_flow_fair_state_mut(queue).queue_vtime = 100 * 1024 * 1024;

    // Drive the throttle counter to V_MIN_CONSECUTIVE_SKIP_HARD_CAP - 1
    // back-to-back throttle decisions. Each bumps v_min_throttles_scratch.
    for _ in 0..(V_MIN_CONSECUTIVE_SKIP_HARD_CAP - 1) {
        let cont = cos_queue_v_min_continue(queue, 1);
        assert!(!cont, "expected throttle (not yet at hard-cap)");
    }
    let throttles_before_cap = queue.v_min.v_min_throttles_scratch;
    let hard_cap_before = queue.v_min.v_min_hard_cap_overrides_scratch;
    assert_eq!(hard_cap_before, 0, "hard-cap not yet fired");

    // The next throttle decision triggers the hard-cap override:
    // function returns true, hard-cap counter bumps, throttle counter
    // does NOT bump (the override path is taken instead).
    let cont = cos_queue_v_min_continue(queue, 1);
    assert!(cont, "hard-cap override force-continues");
    assert_eq!(
        queue.v_min.v_min_hard_cap_overrides_scratch, 1,
        "hard-cap counter bumps exactly once"
    );
    assert_eq!(
        queue.v_min.v_min_throttles_scratch, throttles_before_cap,
        "throttle counter MUST NOT increment on the hard-cap path"
    );
}

/// #940: full pop → push_front (rollback) → re-pop → publish-via-
/// post-settle sequence. Pins that the rollback hook in
/// `cos_queue_push_front` and the new post-settle publish compose
/// correctly under partial-rollback workloads. Per Gemini
/// adversarial review.
#[test]
fn vmin_pop_rollback_repop_postsettle_compose() {
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

    // Push 2 items.
    cos_queue_push_back(queue, test_cos_item(1500));
    cos_queue_push_back(queue, test_cos_item(1500));
    let v0 = test_flow_fair_state(queue).queue_vtime;
    assert_eq!(floor.slots[1].read(), None, "fresh slot");

    // Pop 1: snapshot variant (NO publish).
    let popped1 = cos_queue_pop_front(queue);
    let v1 = test_flow_fair_state(queue).queue_vtime;
    assert!(v1 > v0, "pop must advance vtime");
    assert_eq!(floor.slots[1].read(), None, "snapshot pop must not publish");

    // Roll back via push_front: republishes via existing rollback
    // hook. Slot now holds the rolled-back vtime (back to v0).
    if let Some(item) = popped1 {
        cos_queue_push_front(queue, item);
    }
    let v_after_rollback = test_flow_fair_state(queue).queue_vtime;
    assert_eq!(v_after_rollback, v0, "rollback must restore vtime");
    assert_eq!(
        floor.slots[1].read(),
        Some(v0),
        "rollback hook must publish corrected vtime",
    );

    // Re-pop (snapshot). queue_vtime advances again. Slot stays at
    // v0 because the snapshot pop doesn't publish.
    let _popped2 = cos_queue_pop_front(queue);
    assert!(
        test_flow_fair_state(queue).queue_vtime > v_after_rollback,
        "re-pop advances vtime"
    );
    assert_eq!(
        floor.slots[1].read(),
        Some(v0),
        "re-pop snapshot must not publish",
    );

    // Post-settle publish: slot reflects the new committed vtime.
    publish_committed_queue_vtime(Some(&*queue));
    assert_eq!(
        floor.slots[1].read(),
        Some(test_flow_fair_state(queue).queue_vtime),
        "post-settle publish broadcasts the new committed vtime",
    );
}

