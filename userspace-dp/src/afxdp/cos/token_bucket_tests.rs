// Tests for afxdp/cos/token_bucket.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep token_bucket.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "token_bucket_tests.rs"]` from token_bucket.rs.

use super::*;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::CoSQueueConfig;

#[test]
fn shared_cos_root_lease_bounds_total_outstanding_credit() {
    let lease = SharedCoSRootLease::new(400_000_000, 256 * 1024, 2);
    let lease_bytes = lease.lease_bytes();

    let first = lease.acquire(1, lease_bytes);
    let second = lease.acquire(1, lease_bytes);
    let third = lease.acquire(1, lease_bytes);

    assert_eq!(first, lease_bytes);
    assert_eq!(second, lease_bytes);
    assert_eq!(third, 0);

    lease.release_unused(lease_bytes);
    let fourth = lease.acquire(1, lease_bytes);
    assert_eq!(fourth, lease_bytes);
}

#[test]
fn shared_cos_queue_lease_bounds_total_outstanding_credit() {
    let lease = SharedCoSQueueLease::new(10_000_000, 128 * 1024, 2);
    let request = 2500;

    let first = lease.acquire(1, request);
    let second = lease.acquire(1, request);
    let third = lease.acquire(1, request);
    let fourth = lease.acquire(1, request);
    let fifth = lease.acquire(1, 1);

    assert_eq!(first, request);
    assert_eq!(second, request);
    assert_eq!(third, request);
    assert_eq!(
        first + second + third + fourth,
        (tx_frame_capacity() as u64) * 2
    );
    assert_eq!(fifth, 0);

    lease.release_unused(request);
    let sixth = lease.acquire(1, request);
    assert_eq!(sixth, request);
}

#[test]
fn exact_queue_without_shared_lease_does_not_locally_refill() {
    let mut root = test_cos_runtime_with_queues(
        400_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 100_000_000 / 8,
            exact: true,
            surplus_weight: 1,
            buffer_bytes: 125_000,
            dscp_rewrite: None,
        }],
    );
    root.tokens = 1500;
    root.queues[0].tokens = 0;
    root.queues[0].items.push_back(test_cos_item(1500));
    root.queues[0].queued_bytes = 1500;
    root.queues[0].runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;
    let queue_fast_path = vec![test_queue_fast_path(true, 0, None, None)];

    let batch =
        select_cos_guarantee_batch_with_fast_path(&mut root, &queue_fast_path, 1_000_000_000);

    assert!(
        batch.is_none(),
        "exact queues must not locally refill when the shared queue lease is unavailable"
    );
    assert_eq!(root.queues[0].tokens, 0);
    assert_eq!(root.queues[0].last_refill_ns, 0);
}

use crate::afxdp::cos::queue_service::{
    select_cos_guarantee_batch, select_cos_guarantee_batch_with_fast_path,
};

#[test]
fn maybe_top_up_cos_root_lease_unblocks_large_frame_exceeding_lease_bytes() {
    // Pick a shaping rate low enough that lease_bytes() floors to COS_ROOT_LEASE_MIN_BYTES
    // (1500) and stays below tx_frame_capacity() (4096).  At 50 Mbps / 256 KB burst / 1 shard
    // the raw target lease is rate*TARGET_US/1e6 = 1250 bytes, which floors up to 1500.
    // Without the .max(tx_frame_capacity()) fix in maybe_top_up_cos_root_lease, root.tokens
    // could never exceed 1500 and any frame with len > 1500 would deadlock the CoS queue.
    let rate_bytes = 50_000_000u64 / 8;
    let lease = Arc::new(SharedCoSRootLease::new(rate_bytes, 256 * 1024, 1));
    assert!(
        lease.lease_bytes() < tx_frame_capacity() as u64,
        "precondition: lease_bytes must be below tx_frame_capacity for this regression"
    );

    let mut root = test_cos_runtime_with_queues(
        rate_bytes,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: rate_bytes,
            exact: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let frame_len = tx_frame_capacity();
    root.queues[0].tokens = 64 * 1024;
    root.queues[0].runnable = true;
    root.queues[0].items.push_back(test_cos_item(frame_len));
    root.queues[0].queued_bytes = frame_len as u64;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    maybe_top_up_cos_root_lease(&mut root, &lease, 1_000_000_000);

    assert!(
        root.tokens >= frame_len as u64,
        "root tokens ({}) must cover frame len ({}) after lease top-up",
        root.tokens,
        frame_len
    );
    let batch = select_cos_guarantee_batch(&mut root, 1_000_000_000);
    assert!(
        batch.is_some(),
        "large frame must be dequeued after lease top-up"
    );
}

#[test]
fn maybe_top_up_cos_queue_lease_unblocks_local_exact_queue_without_tokens() {
    let mut root = test_cos_runtime_with_queues(
        400_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 400_000_000 / 8,
            exact: true,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    root.tokens = 1500;
    root.queues[0].tokens = 0;
    root.queues[0].items.push_back(test_cos_item(1500));
    root.queues[0].queued_bytes = 1500;
    root.queues[0].runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;
    let shared_queue_lease = Arc::new(SharedCoSQueueLease::new(
        400_000_000 / 8,
        COS_MIN_BURST_BYTES,
        2,
    ));
    let queue_fast_path = vec![test_queue_fast_path(
        true,
        0,
        None,
        Some(shared_queue_lease.clone()),
    )];

    maybe_top_up_cos_queue_lease(
        &mut root.queues[0],
        Some(&shared_queue_lease),
        1_000_000_000,
    );

    assert!(
        root.queues[0].tokens >= 1500,
        "shared exact queue lease must replenish local queue tokens"
    );
    assert!(
        select_cos_guarantee_batch_with_fast_path(&mut root, &queue_fast_path, 1_000_000_000,)
            .is_some()
    );
}
