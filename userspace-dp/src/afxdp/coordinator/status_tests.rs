use super::*;
use crate::afxdp::types::V8RateMode;
use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

#[test]
fn equal_flow_overlay_skips_non_equal_flow_v8_leases() {
    let mut statuses = vec![CoSInterfaceStatus {
        ifindex: 80,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let leases = BTreeMap::from([(
        (80, 4),
        Arc::new(SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 8, 1)),
    )]);

    overlay_shared_cos_queue_lease_statuses(&mut statuses, &leases);

    let queue = &statuses[0].queues[0];
    assert!(!queue.equal_flow_enforcement);
    assert!(queue.equal_flow_fail_open_reason.is_empty());
}

#[test]
fn claim_flow_overlay_populates_every_v8_lease() {
    // #1863 Step-0: the per-worker claim-flow vectors are populated
    // for ANY v8 lease — including non-equal-flow ones the
    // equal-flow gate below skips.
    let mut statuses = vec![CoSInterfaceStatus {
        ifindex: 80,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let lease = Arc::new(SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 8, 1));
    lease.rehydrate_worker_active_count(0, 1);
    let granted = lease.acquire_v8(0, 200_000, 512);
    assert!(granted > 0, "test premise: the ask grants");
    let leases = BTreeMap::from([((80, 4), lease)]);

    overlay_shared_cos_queue_lease_statuses(&mut statuses, &leases);

    let queue = &statuses[0].queues[0];
    assert_eq!(queue.lease_v8_worker_requested_bytes, vec![512, 0]);
    assert_eq!(queue.lease_v8_worker_granted_bytes[0], granted);
    assert!(!queue.equal_flow_enforcement, "equal-flow gate untouched");
}

#[test]
fn equal_flow_overlay_populates_active_equal_flow_leases() {
    let mut statuses = vec![CoSInterfaceStatus {
        ifindex: 80,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode(
        50_000_000,
        256 * 1024,
        8,
        1,
        V8RateMode::EqualFlowSuppress,
    ));
    let leases = BTreeMap::from([((80, 4), lease)]);

    overlay_shared_cos_queue_lease_statuses(&mut statuses, &leases);

    let queue = &statuses[0].queues[0];
    assert!(queue.equal_flow_enforcement);
    assert_eq!(queue.equal_flow_fail_open_reason, "disabled");
    assert_eq!(queue.equal_flow_stale_or_tag_mismatch_events, 0);
    // #1746: default-policy lease surfaces the "slowest" label.
    assert_eq!(queue.equal_flow_target_policy, "slowest");
}

/// #1746: a Mean-policy lease surfaces "mean" on the status row,
/// and non-equal-flow leases leave the field empty (wire
/// byte-identical for non-equal-flow queues).
#[test]
fn equal_flow_overlay_populates_target_policy_label() {
    let mut statuses = vec![CoSInterfaceStatus {
        ifindex: 80,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode_and_policy(
        50_000_000,
        256 * 1024,
        8,
        1,
        V8RateMode::EqualFlowSuppress,
        crate::afxdp::types::EqualFlowTargetPolicy::Mean,
    ));
    let leases = BTreeMap::from([((80, 4), lease)]);

    overlay_shared_cos_queue_lease_statuses(&mut statuses, &leases);

    let queue = &statuses[0].queues[0];
    assert!(queue.equal_flow_enforcement);
    assert_eq!(queue.equal_flow_target_policy, "mean");
}

/// #1830 (g): the flow-count overlay writes only matching
/// (ifindex, queue) rows and leaves non-matching rows at the serde
/// default 0 (idle / no flow-cache rows), never touching
/// flow_fair_buckets_occupied (the worker-snapshot half).
#[test]
fn flow_fair_flow_count_overlay_targets_matching_queue_rows() {
    let mut statuses = vec![CoSInterfaceStatus {
        ifindex: 80,
        queues: vec![
            CoSQueueStatus {
                queue_id: 4,
                flow_fair_buckets_occupied: 6,
                ..Default::default()
            },
            CoSQueueStatus {
                queue_id: 5,
                ..Default::default()
            },
        ],
        ..Default::default()
    }];
    // Sums across workers were pre-aggregated by the caller.
    let flow_counts = BTreeMap::from([((80, 4u8), 12u64), ((81, 4u8), 99u64)]);

    overlay_cos_flow_fair_flow_counts(&mut statuses, &flow_counts);

    let q4 = &statuses[0].queues[0];
    assert_eq!(q4.flow_fair_flows_active, 12);
    assert_eq!(
        q4.flow_fair_buckets_occupied, 6,
        "overlay must not disturb the worker-snapshot bucket half"
    );
    let q5 = &statuses[0].queues[1];
    assert_eq!(
        q5.flow_fair_flows_active, 0,
        "queue with no flow-cache rows stays at the serde default"
    );
}

// -------------------------------------------------------------
// #5290: fair, rotating-cursor RPC-fallback session-delta drain.
// -------------------------------------------------------------

/// Insert `n` live bindings (slots `0..n`) into `coord`, each pre-loaded with
/// `per_binding` pending session deltas, and return the Arcs so a test can
/// inspect their residual state after a drain.
fn seed_pending_delta_bindings(
    coord: &mut Coordinator,
    n: u32,
    per_binding: usize,
) -> Vec<Arc<BindingLiveState>> {
    let mut out = Vec::new();
    for slot in 0..n {
        let live = Arc::new(BindingLiveState::new());
        for _ in 0..per_binding {
            live.push_session_delta(SessionDeltaInfo::default());
        }
        coord.workers.live.insert(slot, live.clone());
        out.push(live);
    }
    out
}

#[test]
fn drain_session_deltas_serves_every_worker_and_arms_overflow() {
    // #5290 fail-on-revert: a budget strictly below the aggregate pending count
    // must be spread FAIRLY across every live binding (each gets budget/N),
    // never handed whole to the first slot. Reverting to the old
    // whole-budget-first-slot drain would drain all 40 from binding 0 and leave
    // bindings 1..4 untouched — failing both the per-binding fairness assertion
    // AND the overflow loss-of-sync arming (the old code armed nothing).
    let mut coord = Coordinator::new();
    let bindings = seed_pending_delta_bindings(&mut coord, 4, 50); // 200 total

    let drained = coord.drain_session_deltas(40); // 40 < 200, quantum = 10
    assert_eq!(drained.len(), 40, "drain must return exactly the budget");

    // FAIRNESS: every binding was served its 10-delta quantum, so each has
    // exactly 40 left. The old whole-budget-first drain would leave binding 0
    // with 10 and bindings 1..4 with 50.
    for (i, live) in bindings.iter().enumerate() {
        let residual = live.drain_session_deltas(usize::MAX).len();
        assert_eq!(
            residual, 40,
            "binding {i} must have been served an equal 10-delta quantum \
             (fair drain), leaving 40 — a whole-budget-first drain would not"
        );
    }
}

#[test]
fn drain_session_deltas_overflow_arms_loss_of_sync_latch() {
    // #5290: when the budget cannot drain everything, the residual bindings
    // must be latched loss-of-sync so the owning worker's `take_delta_loss`
    // resync recovers the undrained deltas (never a silent drop). The old drain
    // armed no latch at all.
    let mut coord = Coordinator::new();
    let bindings = seed_pending_delta_bindings(&mut coord, 3, 20); // 60 total

    let _ = coord.drain_session_deltas(9); // 9 < 60 => overflow

    for (i, live) in bindings.iter().enumerate() {
        assert!(
            live.take_delta_loss(),
            "binding {i} still holds undrained deltas after a budget overflow, \
             so its loss-of-sync latch must be armed for a resync"
        );
    }
}

#[test]
fn drain_session_deltas_cursor_rotates_so_no_worker_is_starved() {
    // #5290 fail-on-revert: with a tiny budget (< N) only some bindings are
    // served per drain, but the rotating cursor resumes at the next binding, so
    // across successive drains EVERY binding is served. Reverting to the old
    // no-cursor whole-budget-first drain would serve only binding 0 every drain,
    // starving bindings 1 and 2 indefinitely.
    let mut coord = Coordinator::new();
    let bindings = seed_pending_delta_bindings(&mut coord, 3, 10); // 30 total

    // budget 2 < 3 bindings => quantum 1, two bindings served per drain.
    for _ in 0..3 {
        let _ = coord.drain_session_deltas(2);
    }

    for (i, live) in bindings.iter().enumerate() {
        let residual = live.drain_session_deltas(usize::MAX).len();
        assert!(
            residual < 10,
            "binding {i} must have been served at least once across three \
             cursor-rotated drains (residual {residual} < 10) — a no-cursor \
             drain would starve every binding but slot 0"
        );
    }
}

#[test]
fn drain_session_deltas_no_overflow_leaves_latch_clear() {
    // A budget >= aggregate pending drains everything and must NOT arm a
    // spurious resync (no thundering-resync when the fallback keeps up).
    let mut coord = Coordinator::new();
    let bindings = seed_pending_delta_bindings(&mut coord, 3, 5); // 15 total

    let drained = coord.drain_session_deltas(100); // 100 >= 15
    assert_eq!(drained.len(), 15, "generous budget drains everything");

    for (i, live) in bindings.iter().enumerate() {
        assert!(
            !live.has_pending_session_deltas(),
            "binding {i} fully drained"
        );
        assert!(
            !live.take_delta_loss(),
            "binding {i} fully drained — no overflow, latch must stay clear"
        );
    }
}
