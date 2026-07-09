use super::*;

/// #2624: the V_min cadence (`participating_v_min_snapshot`, the
/// expensive Acquire-load peer-slot scan) must be honored ACROSS many
/// small drain calls — not re-armed on the first pop of every call.
///
/// `v_min_pop_count` persists on `queue.v_min`, so popping one item per
/// drain call across 17 calls runs the snapshot only at pops 1, 8, 16
/// (3 times), not once per call. fail-on-revert: restoring the old
/// per-call `let mut v_min_pop_count = 0u32;` re-arms the mandatory
/// first-pop snapshot every call → 17 snapshots → assertion fails.
#[test]
fn vmin_cadence_persists_across_small_drain_calls() {
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
    let floor = attach_test_vtime_floor(queue, 4, 1);
    // A peer participates with a HIGH v_min and the local queue_vtime
    // sits at 0, so the lag check always passes (continue == true) and
    // every cadence pop reaches the snapshot — isolating the cadence
    // counter, not the throttle decision.
    floor.slots[0].publish(u64::MAX - 1);
    test_flow_fair_state_mut(queue).queue_vtime = 0;

    const PKT: usize = 1500;
    const CALLS: usize = 17;
    // One free TX frame and a budget of exactly one packet per call →
    // each drain pops exactly one item, modelling the many-small-drains
    // regime under low/medium load where the defect bites.
    let mut scratch: Vec<(u64, TxRequest)> = Vec::new();
    for _ in 0..CALLS {
        cos_queue_push_back(queue, test_cos_item(PKT));
    }

    for call in 0..CALLS {
        scratch.clear();
        let mut free_tx: VecDeque<u64> = VecDeque::new();
        // Distinct UMEM offset per call so the frame copy succeeds.
        free_tx.push_back((call as u64) * 2048);
        let _ = drain_exact_local_items_to_scratch_flow_fair(
            queue,
            &mut free_tx,
            &mut scratch,
            &umem,
            PKT as u64,
            PKT as u64,
            None,
        );
        assert_eq!(
            scratch.len(),
            1,
            "each small drain call should pop exactly one item (call {call})",
        );
    }

    // Persistent counter advanced once per pop across all calls.
    assert_eq!(
        queue.v_min.v_min_pop_count, CALLS as u32,
        "v_min_pop_count must persist and count every pop across drain calls",
    );
    // Snapshot ran only at pops 1, 8, 16 — three times, NOT once per call.
    let snapshots = floor
        .snapshot_calls
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        snapshots, 3,
        "V_min snapshot must run at the cadence (pops 1, 8, 16) across {CALLS} small \
         drains, not once per call; got {snapshots}",
    );
}

/// #2646 (Local flow-fair): the V_min cadence counter
/// (`v_min_pop_count`) must advance only on a pop that ACTUALLY
/// PROCEEDS. When the gate (`cos_queue_v_min_continue`) PASSES but the
/// budget check fails (head packet larger than the remaining root/
/// secondary budget), the drain breaks WITHOUT popping — and the
/// counter must NOT advance, so the cadence position is preserved for
/// the next real pop. A subsequent drain with adequate budget pops the
/// same head and advances the counter exactly once.
///
/// fail-on-revert: moving the `queue.v_min.v_min_pop_count =
/// candidate_pop_count` commit back ABOVE the budget break (the pre-
/// #2646 placement) makes the budget-miss drain advance the counter →
/// the first assertion (`== 0`) goes red.
#[test]
fn vmin_local_drain_budget_miss_does_not_advance_cadence() {
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
    let floor = attach_test_vtime_floor(queue, 4, 1);
    // Gate PASSES: a peer participates with a high v_min and the local
    // queue_vtime sits at 0, so the lag check always returns continue ==
    // true. This isolates the post-gate budget break from the gate-
    // throttle path.
    floor.slots[0].publish(u64::MAX - 1);
    test_flow_fair_state_mut(queue).queue_vtime = 0;

    const PKT: usize = 1500;
    cos_queue_push_back(queue, test_cos_item(PKT));
    assert_eq!(queue.v_min.v_min_pop_count, 0, "counter starts at 0");

    // Drain with a root budget SMALLER than the head packet. The gate
    // passes, the peek succeeds, but the budget check (remaining_root <
    // len) breaks WITHOUT popping.
    let mut scratch: Vec<(u64, TxRequest)> = Vec::new();
    let mut free_tx: VecDeque<u64> = VecDeque::new();
    free_tx.push_back(0);
    let _ = drain_exact_local_items_to_scratch_flow_fair(
        queue,
        &mut free_tx,
        &mut scratch,
        &umem,
        (PKT as u64) - 1, // root budget one byte short
        u64::MAX,
        None,
    );
    assert!(scratch.is_empty(), "budget miss must not pop");
    assert_eq!(
        queue.v_min.v_min_pop_count, 0,
        "a post-gate budget miss must NOT advance the V_min cadence counter",
    );

    // Now drain with adequate budget — the head pops and the counter
    // advances exactly once.
    let mut free_tx2: VecDeque<u64> = VecDeque::new();
    free_tx2.push_back(0);
    let _ = drain_exact_local_items_to_scratch_flow_fair(
        queue,
        &mut free_tx2,
        &mut scratch,
        &umem,
        PKT as u64,
        u64::MAX,
        None,
    );
    assert_eq!(scratch.len(), 1, "adequate budget must pop the head");
    assert_eq!(
        queue.v_min.v_min_pop_count, 1,
        "a confirmed pop must advance the V_min cadence counter exactly once",
    );
}

/// #2646 (Prepared flow-fair): same contract as the Local case above —
/// a post-gate budget miss must NOT burn a cadence position. The gate
/// passes, the budget check fails, the drain breaks without popping,
/// and `v_min_pop_count` stays put; the next adequate-budget drain pops
/// and advances it once.
///
/// fail-on-revert: restoring the commit above the budget break makes
/// the first (`== 0`) assertion red.
#[test]
fn vmin_prepared_drain_budget_miss_does_not_advance_cadence() {
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
    // Gate PASSES (see the Local test for the rationale).
    floor.slots[0].publish(u64::MAX - 1);
    test_flow_fair_state_mut(queue).queue_vtime = 0;

    const PKT: usize = 1500;
    let packet = vec![0u8; PKT];
    let prepared = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
    cos_queue_push_back(queue, prepared);
    assert_eq!(queue.v_min.v_min_pop_count, 0, "counter starts at 0");

    // Budget one byte short of the head — gate passes, budget breaks.
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
        (PKT as u64) - 1,
        u64::MAX,
        None,
    );
    assert!(scratch.is_empty(), "budget miss must not pop");
    assert_eq!(
        queue.v_min.v_min_pop_count, 0,
        "a post-gate budget miss must NOT advance the V_min cadence counter (Prepared)",
    );

    // Adequate budget — head pops, counter advances once.
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        &mut Vec::new(),
        PKT as u64,
        u64::MAX,
        None,
    );
    assert_eq!(scratch.len(), 1, "adequate budget must pop the head (Prepared)");
    assert_eq!(
        queue.v_min.v_min_pop_count, 1,
        "a confirmed pop must advance the V_min cadence counter exactly once (Prepared)",
    );
}

/// #2981: an UNSHAPED shared-exact queue (`transmit_rate_bytes == 0`)
/// must NOT be throttled by the V_min lag check, even when the local
/// worker's vtime is far past a participating peer's V_min — much
/// further than the 24 KB `V_MIN_MIN_LAG_BYTES` floor that the
/// collapsed (rate-0) threshold would otherwise enforce. With no
/// configured rate there is nothing to be fair to, so the brake is
/// skipped entirely (mirroring the `!shared_exact()` disposition).
///
/// fail-on-revert: removing the `transmit_rate_bytes == 0` early
/// return in `cos_queue_v_min_continue` makes this queue throttle
/// against the 24 KB floor → the assertion goes RED.
#[test]
fn vmin_unshaped_queue_not_throttled() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            // UNSHAPED: 0 == "unshaped/full bucket" (types/cos.rs).
            transmit_rate_bytes: 0,
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

    // Peer worker 0 pegged at vtime 0; local worker 1 is 100 MB ahead
    // — vastly past the 24 KB floor a rate-0 threshold would impose.
    floor.slots[0].publish(0);
    test_flow_fair_state_mut(queue).queue_vtime = 100 * 1024 * 1024;

    assert!(
        cos_queue_v_min_continue(queue, 1),
        "UNSHAPED shared-exact queue MUST NOT be throttled by V_min \
         (no configured rate → no fairness brake)",
    );
    // No throttle accounting should fire on the skip path.
    assert_eq!(
        queue.v_min.v_min_throttles_scratch, 0,
        "unshaped skip must not count a throttle",
    );
    assert_eq!(
        queue.v_min.consecutive_v_min_skips, 0,
        "unshaped skip must not arm the hard-cap counter",
    );
}

/// #2981 regression: a SHAPED shared-exact queue
/// (`transmit_rate_bytes > 0`) STILL applies the V_min throttle at
/// the same drift that the unshaped test above tolerates. This is the
/// byte-for-byte unchanged shaped behavior — the fix must touch only
/// the unshaped (rate-0) case.
///
/// fail-on-revert: this test stays GREEN under the revert (shaped
/// gating is not what changed); it is the guard that the fix did not
/// over-broaden the skip to shaped queues.
#[test]
fn vmin_shaped_queue_still_throttles() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            // SHAPED: a real configured rate (10 Gb/s).
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

    // Same peer/local drift as the unshaped test — a shaped queue
    // throttles here exactly as before the fix.
    floor.slots[0].publish(0);
    test_flow_fair_state_mut(queue).queue_vtime = 100 * 1024 * 1024;

    assert!(
        !cos_queue_v_min_continue(queue, 1),
        "SHAPED shared-exact queue MUST still throttle when local \
         vtime >> peer V_min + LAG",
    );
    assert_eq!(
        queue.v_min.v_min_throttles_scratch, 1,
        "shaped throttle still bumps the throttle counter",
    );
}

/// #2981: the lag-threshold computation for SHAPED queues is
/// byte-identical to before the fix. The fix lives in
/// `cos_queue_v_min_continue`, not in `compute_v_min_lag_threshold`;
/// this pins the representative shaped value so a future refactor of
/// either site can't silently change shaped fairness.
///
/// 10 Gb/s = 1_250_000_000 B/s over 2 participating workers →
/// 625_000_000 B/s per worker × 1 ms = 625_000 B, well above the
/// 24 KB floor. The rate-0 (unshaped) input still returns the floor —
/// the helper is unchanged; the throttle is skipped upstream instead.
#[test]
fn vmin_shaped_threshold_is_byte_identical() {
    // Representative shaped rate: 10 Gb/s across 2 workers.
    assert_eq!(
        compute_v_min_lag_threshold(10_000_000_000 / 8, 2),
        625_000,
        "shaped per-worker-rate × 1 ms threshold must be unchanged",
    );
    // Single participant takes the whole rate.
    assert_eq!(
        compute_v_min_lag_threshold(10_000_000_000 / 8, 1),
        1_250_000,
        "single-worker shaped threshold must be unchanged",
    );
    // A small shaped rate where per-worker × 1 ms falls below the
    // floor still clamps to V_MIN_MIN_LAG_BYTES (unchanged).
    assert_eq!(
        compute_v_min_lag_threshold(1_000_000, 1),
        V_MIN_MIN_LAG_BYTES,
        "shaped rate below the floor still clamps to V_MIN_MIN_LAG_BYTES",
    );
    // The rate-0 helper input is unchanged (returns the floor); the
    // unshaped behavior change is in cos_queue_v_min_continue, not here.
    assert_eq!(
        compute_v_min_lag_threshold(0, 4),
        V_MIN_MIN_LAG_BYTES,
        "compute_v_min_lag_threshold(0, _) is unchanged — clamps to the floor",
    );
}

// ---- #4254 (R-7): rejoining-worker V_min reseed ----

