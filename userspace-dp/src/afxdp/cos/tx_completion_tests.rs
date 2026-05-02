// Tests for afxdp/cos/tx_completion.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep tx_completion.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tx_completion_tests.rs"]` from tx_completion.rs.

use super::*;
use crate::afxdp::cos::queue_service::{
    select_cos_guarantee_batch, select_exact_cos_guarantee_queue_with_fast_path,
};
use crate::afxdp::cos::token_bucket::COS_MIN_BURST_BYTES;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::{
    CoSQueueDropCounters, CoSQueueOwnerProfile, FlowRrRing, COS_FLOW_FAIR_BUCKETS,
};
use crate::afxdp::TX_BATCH_SIZE;

#[test]
fn normalize_cos_queue_state_repairs_nonempty_unparked_queue_to_runnable() {
    let mut queue = CoSQueueRuntime {
        queue_id: 5,
        priority: 5,
        transmit_rate_bytes: 11_000_000_000 / 8,
        exact: true,
        flow_fair: false,
        shared_exact: false,
        flow_hash_seed: 0,
        surplus_weight: 1,
        surplus_deficit: 0,
        buffer_bytes: COS_MIN_BURST_BYTES,
        dscp_rewrite: None,
        tokens: 0,
        last_refill_ns: 0,
        queued_bytes: 1500,
        active_flow_buckets: 0,
        active_flow_buckets_peak: 0,
        flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
        flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
        flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
        queue_vtime: 0,
        pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
        flow_rr_buckets: FlowRrRing::default(),
        flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
        runnable: false,
        parked: false,
        next_wakeup_tick: 0,
        wheel_level: 0,
        wheel_slot: 0,
        items: VecDeque::from([test_cos_item(1500)]),
        local_item_count: 0,

        vtime_floor: None,

        worker_id: 0,
        drop_counters: CoSQueueDropCounters::default(),
        owner_profile: CoSQueueOwnerProfile::new(),
        consecutive_v_min_skips: 0,
        v_min_suspended_remaining: 0,
        v_min_hard_cap_overrides_scratch: 0,
    };

    normalize_cos_queue_state(&mut queue);

    assert!(queue.runnable);
    assert!(!queue.parked);
    assert_eq!(queue.next_wakeup_tick, 0);
}

#[test]
fn count_park_reason_helper_advances_exact_counter() {
    // Low-level test of the helper itself — paranoia pin against a
    // refactor that accidentally writes to the wrong field.
    let mut root = test_cos_runtime_with_exact(true);
    let before = snapshot_counters(&root.queues[0]);

    count_park_reason(&mut root, 0, ParkReason::RootTokenStarvation);
    let mid = snapshot_counters(&root.queues[0]);
    assert_eq!(
        mid.root_token_starvation_parks,
        before.root_token_starvation_parks + 1
    );
    assert_eq!(
        mid.queue_token_starvation_parks,
        before.queue_token_starvation_parks
    );

    count_park_reason(&mut root, 0, ParkReason::QueueTokenStarvation);
    let after = snapshot_counters(&root.queues[0]);
    assert_eq!(
        after.queue_token_starvation_parks,
        before.queue_token_starvation_parks + 1
    );
    assert_eq!(
        after.root_token_starvation_parks,
        mid.root_token_starvation_parks
    );

    // Out-of-range queue_idx is a no-op, not a panic.
    count_park_reason(&mut root, 999, ParkReason::RootTokenStarvation);
    assert_eq!(
        snapshot_counters(&root.queues[0]).root_token_starvation_parks,
        after.root_token_starvation_parks
    );
}

#[test]
fn timer_wheel_wakes_short_parked_queue() {
    let mut root = test_cos_interface_runtime(0);
    root.queues[0].items.push_back(test_cos_item(1500));
    root.queues[0].queued_bytes = 1500;
    root.queues[0].runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    park_cos_queue(&mut root, 0, 5);

    assert!(root.queues[0].parked);
    assert!(!root.queues[0].runnable);
    assert_eq!(root.runnable_queues, 0);

    advance_cos_timer_wheel(&mut root, 4 * COS_TIMER_WHEEL_TICK_NS);
    assert!(root.queues[0].parked);
    assert!(!root.queues[0].runnable);

    advance_cos_timer_wheel(&mut root, 5 * COS_TIMER_WHEEL_TICK_NS);
    assert!(!root.queues[0].parked);
    assert!(root.queues[0].runnable);
    assert_eq!(root.runnable_queues, 1);
}

#[test]
fn timer_wheel_cascades_long_parked_queue() {
    let mut root = test_cos_interface_runtime(0);
    root.queues[0].items.push_back(test_cos_item(1500));
    root.queues[0].queued_bytes = 1500;
    root.queues[0].runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let wake_tick = COS_TIMER_WHEEL_L0_SLOTS as u64 + 10;
    park_cos_queue(&mut root, 0, wake_tick);

    assert_eq!(root.queues[0].wheel_level, 1);
    assert!(root.queues[0].parked);

    advance_cos_timer_wheel(&mut root, (wake_tick - 1) * COS_TIMER_WHEEL_TICK_NS);
    assert!(root.queues[0].parked);
    assert!(!root.queues[0].runnable);

    advance_cos_timer_wheel(&mut root, wake_tick * COS_TIMER_WHEEL_TICK_NS);
    assert!(!root.queues[0].parked);
    assert!(root.queues[0].runnable);
    assert_eq!(root.runnable_queues, 1);
}

#[test]
fn park_counter_root_token_starvation_ticks_only_its_reason() {
    let mut root = test_cos_runtime_with_exact(true);
    root.tokens = 0;
    root.queues[0].tokens = 0;
    root.queues[0].runnable = true;
    root.queues[0].items.push_back(test_cos_item(1500));
    root.queues[0].queued_bytes = 1500;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let before = snapshot_counters(&root.queues[0]);
    // Drive a selector that will park on root-token starvation.
    assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
    let after = snapshot_counters(&root.queues[0]);

    assert_eq!(
        after.root_token_starvation_parks,
        before.root_token_starvation_parks + 1,
        "root-token park counter must advance by 1"
    );
    assert_eq!(
        after.queue_token_starvation_parks,
        before.queue_token_starvation_parks
    );
    assert_eq!(
        after.admission_flow_share_drops,
        before.admission_flow_share_drops
    );
    assert_eq!(after.admission_buffer_drops, before.admission_buffer_drops);
    assert_eq!(
        after.tx_ring_full_submit_stalls,
        before.tx_ring_full_submit_stalls
    );
}

#[test]
fn park_counter_queue_token_starvation_ticks_only_its_reason_on_exact() {
    let mut root = test_cos_runtime_with_exact(true);
    // Root has headroom; per-queue tokens do not. Forces the
    // queue-token park branch on the exact selector.
    root.tokens = 1_000_000;
    root.queues[0].tokens = 0;
    root.queues[0].last_refill_ns = 1; // skip the first-refill init path
    root.queues[0].runnable = true;
    root.queues[0].items.push_back(test_cos_item(1500));
    root.queues[0].queued_bytes = 1500;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let before = snapshot_counters(&root.queues[0]);
    let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    assert!(
        selection.is_none(),
        "exact selector must park, not return a queue"
    );
    let after = snapshot_counters(&root.queues[0]);

    assert_eq!(
        after.queue_token_starvation_parks,
        before.queue_token_starvation_parks + 1,
        "queue-token park counter must advance by 1"
    );
    assert_eq!(
        after.root_token_starvation_parks,
        before.root_token_starvation_parks
    );
    assert_eq!(
        after.admission_flow_share_drops,
        before.admission_flow_share_drops
    );
    assert_eq!(after.admission_buffer_drops, before.admission_buffer_drops);
    assert_eq!(
        after.tx_ring_full_submit_stalls,
        before.tx_ring_full_submit_stalls
    );
}
