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
