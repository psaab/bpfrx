use super::*;

/// #785 Phase 3 Codex round-3 NEW-2 / Rust reviewer LOW —
/// pop-snapshot stack must remain bounded by `TX_BATCH_SIZE`
/// across a committed-only drain (no push_front rollback).
///
/// Setup:
///   * Flow-fair queue with `TX_BATCH_SIZE + 64` items enqueued
///     (spread across two buckets so MQFQ selection gets
///     meaningful coverage).
///   * First "drain batch": pop TX_BATCH_SIZE items via direct
///     `cos_queue_pop_front`, never call push_front — this is
///     the committed-submit pattern where every scratch item
///     was accepted by the TX ring. The snapshot stack should
///     never exceed `TX_BATCH_SIZE` during the drain.
///   * Second "drain batch": drain the remaining 64 items.
///     Before the second batch starts, simulate the helper
///     contract by clearing the stack (what
///     `drain_exact_*_flow_fair` does at batch start). The
///     stack must then stay bounded through the second batch
///     too.
///
/// Without the fix, every committed pop would leave a stale
/// snapshot on the stack and the second batch would grow it
/// past `TX_BATCH_SIZE` (reallocating on each push and
/// violating the documented bound).
///
/// This pin validates (1) the bound during a single batch,
/// (2) the bound across batches once the drain-start clear
/// runs, and (3) that no realloc grows capacity past the
/// pre-allocated `TX_BATCH_SIZE`.
#[test]
fn mqfq_pop_snapshot_stack_bounded_to_tx_batch_size() {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 8 * 1024 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    enable_test_flow_fair(queue);

    let pre_cap = test_flow_fair_state(queue).pop_snapshot_stack.capacity();
    assert_eq!(
        pre_cap, TX_BATCH_SIZE,
        "stack must be preallocated to TX_BATCH_SIZE",
    );

    // Enqueue TX_BATCH_SIZE + 64 items across two flows so the
    // MQFQ min-finish scan exercises real selection, not a
    // single-bucket shortcut.
    let total = TX_BATCH_SIZE + 64;
    for i in 0..total {
        let src_port = if i % 2 == 0 { 9001u16 } else { 9002u16 };
        cos_queue_push_back(queue, test_flow_cos_item(src_port, 100));
    }

    // Batch 1: committed drain — pop TX_BATCH_SIZE items and
    // DROP them (simulates the "TX ring accepted all of them"
    // path where scratch is cleared with no push_front).
    for _ in 0..TX_BATCH_SIZE {
        let popped = cos_queue_pop_front(queue);
        assert!(popped.is_some(), "queue still has items");
        assert!(
            test_flow_fair_state(queue).pop_snapshot_stack.len() <= TX_BATCH_SIZE,
            "NEW-2: pop_snapshot_stack must never exceed \
             TX_BATCH_SIZE during a single drain batch",
        );
    }
    assert_eq!(
        test_flow_fair_state(queue).pop_snapshot_stack.len(),
        TX_BATCH_SIZE,
        "full-batch commit should leave exactly TX_BATCH_SIZE \
         snapshots (no push_front rollback consumed any)",
    );

    // Simulate what `drain_exact_*_flow_fair` does at batch
    // start: clear the stack before the next batch drains.
    // This is the fix point.
    test_flow_fair_state_mut(queue).pop_snapshot_stack.clear();

    // Batch 2: drain the remaining 64 items. Stack must stay
    // bounded; without the batch-start clear this would grow
    // from TX_BATCH_SIZE → TX_BATCH_SIZE + 64 and realloc.
    for _ in 0..64 {
        let popped = cos_queue_pop_front(queue);
        assert!(popped.is_some());
        assert!(
            test_flow_fair_state(queue).pop_snapshot_stack.len() <= TX_BATCH_SIZE,
            "NEW-2: cross-batch drain must stay bounded after \
             the drain-start clear",
        );
    }

    // No realloc: capacity must equal the preallocated
    // TX_BATCH_SIZE exactly. A realloc would prove the bound
    // was violated at some point.
    assert_eq!(
        test_flow_fair_state(queue).pop_snapshot_stack.capacity(),
        pre_cap,
        "NEW-2: stack must not realloc past TX_BATCH_SIZE",
    );
}

/// #785 Phase 3 Codex round-3 NEW-2 / Rust reviewer LOW —
/// teardown/reconfigure drain path (`reset_binding_cos_runtime`
/// style) must not grow the pop-snapshot stack past its bound
/// and must leave the stack cleared afterwards.
///
/// We exercise `cos_queue_drain_all` directly — it's the shared
/// teardown helper used by `demote_prepared_cos_queue_to_local`
/// and mirrors the direct-`cos_queue_pop_front_no_snapshot` loop
/// in `reset_binding_cos_runtime`. Both paths drain all items
/// without a matching push_front rollback.
///
/// Pre-fix: drain-all pushed a snapshot per pop and never
/// cleared them; with a queue holding > TX_BATCH_SIZE items
/// the stack would realloc past its preallocated capacity
/// (the documented-and-preallocated bound) and leave stale
/// snapshots resident until the next push_back cleared them.
///
/// Post-fix: drain-all uses `cos_queue_pop_front_no_snapshot`
/// so the stack is never grown. Teardown leaves the stack at
/// its pre-drain state (empty in this test).
#[test]
fn mqfq_drain_all_teardown_clears_stack() {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 8 * 1024 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    enable_test_flow_fair(queue);

    let pre_cap = test_flow_fair_state(queue).pop_snapshot_stack.capacity();
    assert_eq!(pre_cap, TX_BATCH_SIZE);

    // Enqueue more items than the snapshot stack could hold
    // under the old always-push-snapshot policy.
    let total = TX_BATCH_SIZE + 300;
    for i in 0..total {
        let src_port = if i % 3 == 0 {
            9101u16
        } else if i % 3 == 1 {
            9102u16
        } else {
            9103u16
        };
        cos_queue_push_back(queue, test_flow_cos_item(src_port, 100));
    }
    // push_back clears the stack; confirm pre-condition.
    assert!(test_flow_fair_state(queue).pop_snapshot_stack.is_empty());

    // Drain via the teardown helper. Must NOT grow the stack
    // and must NOT trip the pop_front debug_assert on overflow.
    let drained = cos_queue_drain_all(queue);
    assert_eq!(
        drained.len(),
        total,
        "drain_all must yield every enqueued item",
    );
    assert!(
        test_flow_fair_state(queue).pop_snapshot_stack.is_empty(),
        "NEW-2: teardown drain path must leave the snapshot \
         stack empty — no stale snapshots resident",
    );
    assert_eq!(
        test_flow_fair_state(queue).pop_snapshot_stack.capacity(),
        pre_cap,
        "NEW-2: teardown must not realloc past TX_BATCH_SIZE",
    );
}

/// #785 Phase 3 Codex round-2 MEDIUM — brief-idle re-entry pin.
/// Previous pins covered the LARGE-idle case (bucket drains,
/// lots of other traffic flows, bucket re-enqueues far in the
/// future). This pin covers the BRIEF-idle case where a bucket
/// drains, another bucket drains advancing vtime modestly, the
/// first bucket re-enqueues — the `max(tail_finish, queue_vtime)
/// + bytes` anchor formula must exercise BOTH arms of the max
/// over the lifetime of this bucket:
///
///   * First re-enqueue after drain: tail_finish was reset to 0,
///     queue_vtime > 0 → max picks queue_vtime, anchor =
///     queue_vtime + bytes.
///   * Second enqueue (to now-active bucket): tail_finish >
///     queue_vtime, max picks tail_finish, anchor =
///     tail_finish + bytes.
#[test]
fn mqfq_brief_idle_reentry_exercises_both_max_arms() {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
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

    let flow_a = test_session_key(1001, 5201);
    let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
    let flow_b = test_session_key(1002, 5201);
    let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
    assert_ne!(bucket_a, bucket_b, "test hash collision");

    // Flow A: single packet. Enqueue + drain fully. Bucket A
    // goes idle with head/tail=0.
    cos_queue_push_back(queue, test_flow_cos_item(1001, 1500));
    let _ = cos_queue_pop_front(queue);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        0
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        0
    );
    assert_eq!(test_flow_fair_state(queue).queue_vtime, 1500);

    // Flow B: one packet, drain it. Advances queue_vtime to
    // 1500 + 800 = 2300 (small amount vs. flow A's lifetime).
    cos_queue_push_back(queue, test_flow_cos_item(1002, 800));
    let _ = cos_queue_pop_front(queue);
    assert_eq!(test_flow_fair_state(queue).queue_vtime, 2300);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_b],
        0
    );

    // Flow A returns with a 1200-byte packet. tail_finish[A]=0,
    // queue_vtime=2300 → max picks vtime → head = tail = 2300
    // + 1200 = 3500. This is the "brief-idle" re-anchor.
    cos_queue_push_back(queue, test_flow_cos_item(1001, 1200));
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        3500,
        "#785 Phase 3 brief-idle re-entry: first arm of max \
         (tail_finish=0 < queue_vtime=2300) must anchor at \
         queue_vtime + bytes",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        3500
    );

    // Flow A appends a second 900-byte packet on its now-
    // active bucket. tail_finish=3500 > queue_vtime=2300 →
    // max picks tail_finish → tail = 3500 + 900 = 4400. Head
    // unchanged (head packet is still the first one, 3500).
    cos_queue_push_back(queue, test_flow_cos_item(1001, 900));
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        3500,
        "#785 Phase 3 brief-idle re-entry: active-bucket \
         enqueue must NOT alter head (head packet didn't \
         change)",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        4400,
        "#785 Phase 3 brief-idle re-entry: second arm of max \
         (tail_finish=3500 > queue_vtime=2300) must anchor at \
         tail_finish + bytes",
    );
}
