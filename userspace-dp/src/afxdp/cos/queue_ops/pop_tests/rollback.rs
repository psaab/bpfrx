use super::*;

/// #913 — Codex code review HIGH regression. Scratch-builder
/// Drop must preserve the dropped item's vtime contribution
/// across multi-survivor restore, otherwise a new idle flow
/// can jump ahead of the restored active buckets — exactly
/// the temporal-inversion class of bug #913 was supposed to
/// fix.
///
/// Setup: 3 distinct flows X (head 1500), Y (head 2000), Z
/// (head 3000). Pop in MQFQ order (X→Y→Z); `queue_vtime`
/// advances 0 → 1500 → 2000 → 3000.
///
/// Simulate Z dropped: invoke
/// `cos_queue_clear_orphan_snapshot_after_drop` (the helper
/// the four scratch-builder Drop sites call). Z's snapshot is
/// removed and remaining (X, Y) snapshots get clamped so
/// their `pre_pop_queue_vtime` ≥ 3000.
///
/// Restore Y, then X via `cos_queue_push_front`. After both
/// restores, `queue_vtime` MUST be ≥ 3000 (Z's commit
/// preserved). Bucket heads/tails restored exactly.
///
/// Then enqueue a new idle flow W (small bytes) and assert
/// W's head_finish ≥ X/Y's head_finish so W cannot jump the
/// restored active set.
#[test]
fn mqfq_scratch_drop_preserves_vtime_for_multi_survivor_restore() {
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

    // Distinct buckets X / Y / Z with mixed packet sizes so
    // each has a unique head_finish (avoids the "all-equal"
    // numeric-coincidence case). Copilot review: select flow
    // IDs dynamically so the test doesn't couple to a
    // specific hash distribution.
    let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut picks: Vec<u16> = Vec::with_capacity(3);
    for flow_id in 7001u16..8001u16 {
        let bucket = cos_flow_bucket_index(0, Some(&test_session_key(flow_id, 5201)));
        if seen.insert(bucket) {
            picks.push(flow_id);
            if picks.len() == 3 {
                break;
            }
        }
    }
    assert_eq!(
        picks.len(),
        3,
        "test setup: 3 distinct buckets must be selectable in [7001, 8001)"
    );
    let (flow_x_id, flow_y_id, flow_z_id) = (picks[0], picks[1], picks[2]);
    cos_queue_push_back(queue, test_flow_cos_item(flow_x_id, 1500));
    cos_queue_push_back(queue, test_flow_cos_item(flow_y_id, 2000));
    cos_queue_push_back(queue, test_flow_cos_item(flow_z_id, 3000));
    let key_x = test_session_key(flow_x_id, 5201);
    let key_y = test_session_key(flow_y_id, 5201);
    let key_z = test_session_key(flow_z_id, 5201);
    let bucket_x = cos_flow_bucket_index(0, Some(&key_x));
    let bucket_y = cos_flow_bucket_index(0, Some(&key_y));
    let bucket_z = cos_flow_bucket_index(0, Some(&key_z));

    let pre_batch_head_x = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_x];
    let pre_batch_head_y = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_y];
    let pre_batch_head_z = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_z];
    assert_eq!(pre_batch_head_x, 1500);
    assert_eq!(pre_batch_head_y, 2000);
    assert_eq!(pre_batch_head_z, 3000);

    // Pop X, Y, Z in MQFQ order.
    let popped_x = cos_queue_pop_front(queue).expect("pop X");
    let popped_y = cos_queue_pop_front(queue).expect("pop Y");
    let _popped_z = cos_queue_pop_front(queue).expect("pop Z");
    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        3000,
        "after X→Y→Z pops, vtime tracks served-finish frontier (max=3000)"
    );
    assert_eq!(test_flow_fair_state(queue).pop_snapshot_stack.len(), 3);

    // Simulate Z dropped (e.g., frame too big in scratch builder).
    cos_queue_clear_orphan_snapshot_after_drop(queue);
    assert_eq!(test_flow_fair_state(queue).pop_snapshot_stack.len(), 2);
    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        3000,
        "Drop preserves the committed vtime advance"
    );

    // Restore Y first (LIFO), then X.
    cos_queue_push_front(queue, popped_y);
    assert!(
        test_flow_fair_state(queue).queue_vtime >= 3000,
        "after Y restore, vtime must NOT regress below Z's commit \
         (got {})",
        test_flow_fair_state(queue).queue_vtime
    );
    cos_queue_push_front(queue, popped_x);
    assert!(
        test_flow_fair_state(queue).queue_vtime >= 3000,
        "after X restore, vtime must NOT regress below Z's commit \
         (got {})",
        test_flow_fair_state(queue).queue_vtime
    );
    assert!(
        test_flow_fair_state(queue).pop_snapshot_stack.is_empty(),
        "all snapshots consumed by restore"
    );

    // X and Y bucket head_finish restored to pre-pop values.
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_x],
        pre_batch_head_x
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_y],
        pre_batch_head_y
    );

    // Now enqueue a new idle flow W with a small packet. Pick
    // its flow ID dynamically so its bucket is distinct from
    // the restored X and Y buckets.
    let mut flow_w_id: u16 = 0;
    for candidate in 8001u16..9001u16 {
        let bucket = cos_flow_bucket_index(0, Some(&test_session_key(candidate, 5201)));
        if bucket != bucket_x && bucket != bucket_y && bucket != bucket_z {
            flow_w_id = candidate;
            break;
        }
    }
    assert_ne!(flow_w_id, 0, "test setup: distinct W bucket selectable");
    cos_queue_push_back(queue, test_flow_cos_item(flow_w_id, 100));
    let key_w = test_session_key(flow_w_id, 5201);
    let bucket_w = cos_flow_bucket_index(0, Some(&key_w));
    let w_head = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_w];

    // CORE ASSERTION: W cannot jump ahead of the restored
    // active buckets X/Y. Pre-#913 (or pre-Drop-vtime-fix),
    // vtime would have regressed to 0 and W would anchor at
    // max(0,0)+100 = 100, jumping ahead of X (1500) and Y
    // (2000). With Drop's vtime preserved at ≥ 3000, W
    // anchors at max(0, 3000) + 100 = 3100, which is past
    // X and Y.
    assert!(
        w_head >= pre_batch_head_x,
        "Codex regression: new idle flow W (head={}) must NOT \
         jump ahead of restored bucket X (head={}) — \
         dropped Z's vtime contribution must be preserved",
        w_head,
        pre_batch_head_x
    );
    assert!(
        w_head >= pre_batch_head_y,
        "Codex regression: new idle flow W (head={}) must NOT \
         jump ahead of restored bucket Y (head={})",
        w_head,
        pre_batch_head_y
    );
}

/// #913 — Codex code review R8/R9 regression. Same-bucket
/// multi-pop with intermediate Drop: under MQFQ
/// "drops consume virtual service" semantics, the dropped
/// item's contribution must be preserved so that surviving
/// packets in the same bucket retain their original
/// finish-time positions.
///
/// Setup: bucket A has 3 packets [1000, 2000, 1500].
/// Initial state at enqueue: head_A=1000, tail_A=4500.
/// Original finish times: A1=1000, A2=3000, A3=4500.
///
/// Pop A1 (1000-byte): head advances to 3000 (bytes(A2)).
/// Pop A2 (2000-byte): head advances to 4500 (bytes(A3)).
/// Drop A2 (frame too big). Orphan-cleanup helper pops
/// snap_2 and clamps snap_1.pre_pop_queue_vtime.
///
/// Restore A1 via push_front. Bucket has [A3] at this point
/// (was_empty=false), so the active-bucket arithmetic runs:
/// `head -= bytes(current_head=A3=1500) = 4500-1500 = 3000`.
///
/// THIS IS CORRECT under MQFQ drops-consume semantics:
/// head=3000 means "the bucket's frontier is at 3000 (post-
/// A2's virtual service)." When A1 is then popped:
/// `head += bytes(A3=1500) = 4500`. A3 ends up at finish=4500
/// — its ORIGINAL position — preserving A2's contribution.
/// Competing buckets with finish 3000-4500 correctly drain
/// before A3, no scheduling inversion.
///
/// (Naive alternative: restore head from snap.pre_pop_head=1000
/// would lose A2's contribution. After pop A1: head=1000+1500=
/// 2500; A3 ends up at 2500 instead of 4500. Competing buckets
/// at finish 2500-4500 would unfairly drain after A3 — that's
/// the scheduling inversion Codex R9 flagged.)
#[test]
fn mqfq_same_bucket_multipop_drop_preserves_dropped_item_finish() {
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

    // Single bucket A, 3 packets with mixed sizes.
    cos_queue_push_back(queue, test_flow_cos_item(8001, 1000));
    cos_queue_push_back(queue, test_flow_cos_item(8001, 2000));
    cos_queue_push_back(queue, test_flow_cos_item(8001, 1500));
    let key_a = test_session_key(8001, 5201);
    let bucket_a = cos_flow_bucket_index(0, Some(&key_a));

    // Pop A1 (1000B). head_finish advances to 3000.
    let popped_a1 = cos_queue_pop_front(queue).expect("pop A1");
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        3000
    );

    // Pop A2 (2000B). head_finish advances to 4500.
    let _popped_a2 = cos_queue_pop_front(queue).expect("pop A2");
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        4500
    );
    assert_eq!(test_flow_fair_state(queue).pop_snapshot_stack.len(), 2);

    // Simulate A2 dropped via the scratch-builder Drop helper.
    cos_queue_clear_orphan_snapshot_after_drop(queue);
    assert_eq!(test_flow_fair_state(queue).pop_snapshot_stack.len(), 1);

    // Restore A1 via push_front. Active-bucket arithmetic:
    // head=4500 - bytes(A3=1500) = 3000. This is the
    // post-A2-pop value; A2's "virtual service" is preserved.
    cos_queue_push_front(queue, popped_a1);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        3000,
        "post-restore head_finish should be 3000 (post-A2-pop \
         value, preserving A2's virtual-service contribution)"
    );

    // Critical Codex R9 assertion: pop A1 again, then verify
    // A3 lands at its original finish=4500, NOT 2500.
    // This is the scheduling-correctness gate — A3 must NOT
    // jump ahead of competing buckets that were originally
    // scheduled between A2's and A3's finish times.
    let _popped_a1_again = cos_queue_pop_front(queue).expect("pop A1 again");
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        4500,
        "Codex R9 regression: after dropping A2 and re-popping \
         A1, A3 must remain at its original finish=4500 (not \
         2500). Otherwise A3 jumps ahead of competing buckets \
         that were originally scheduled in the [3000, 4500) \
         window — exactly the temporal inversion #913 was \
         supposed to prevent."
    );
}

/// #927: drained-bucket scenario. Bucket A holds [A1=1000B,
/// A2=2000B], bucket C holds [C=2500B]. Scratch builder pops
/// A1+C+A2 in that order. A2's pop drains bucket A (last item).
/// A2 is then dropped (frame too big, etc.). The orphan-cleanup
/// helper must preserve A2's served_finish = 3000 across the
/// restore so that A1's restored frontier is ≥ 3000. Otherwise
/// the `was_empty` snapshot path in `cos_queue_push_front`
/// would restore A.head=1000 (the snap_1.pre_pop_head_finish
/// captured before A2's pop), and MQFQ would pop A1 BEFORE
/// C — inverting their original scheduling order.
#[test]
fn mqfq_drained_bucket_orphan_drop_preserves_served_finish() {
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

    // Bucket A: [A1=1000, A2=2000]. Bucket C: [C=2500].
    // Two distinct flow keys so they hash to distinct buckets.
    cos_queue_push_back(queue, test_flow_cos_item(8001, 1000));
    cos_queue_push_back(queue, test_flow_cos_item(8001, 2000));
    cos_queue_push_back(queue, test_flow_cos_item(8002, 2500));
    let key_a = test_session_key(8001, 5201);
    let key_c = test_session_key(8002, 5201);
    let bucket_a = cos_flow_bucket_index(0, Some(&key_a));
    let bucket_c = cos_flow_bucket_index(0, Some(&key_c));
    assert_ne!(
        bucket_a, bucket_c,
        "test setup: ports 8001/8002 must hash to distinct buckets"
    );

    // Pre-pop frontier:
    //   A.head=1000 (A1 finish), A.tail=3000 (A2 finish).
    //   C.head=C.tail=2500.
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        1000
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        3000
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_c],
        2500
    );

    // Pop A1: head_finish[A] advances to 3000 (A2 finish-time).
    let popped_a1 = cos_queue_pop_front(queue).expect("pop A1");
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        3000
    );

    // Pop C: MQFQ picks min-finish-first; with A.head=3000
    // and C.head=2500, C.head < A.head so C is the next pop.
    // After pop: bucket C empty; C.head_finish reset to 0.
    let popped_c = cos_queue_pop_front(queue).expect("pop C");
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_c],
        0
    );

    // Pop A2 (last in A): bucket A drains, A.head_finish reset
    // to 0. queue_vtime reflects all three pops.
    let _popped_a2 = cos_queue_pop_front(queue).expect("pop A2");
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        0
    );
    assert_eq!(test_flow_fair_state(queue).pop_snapshot_stack.len(), 3);

    // Simulate A2 dropped (e.g., frame too big to transmit).
    cos_queue_clear_orphan_snapshot_after_drop(queue);
    assert_eq!(test_flow_fair_state(queue).pop_snapshot_stack.len(), 2);

    // Restore C via push_front: bucket C is empty so the
    // `was_empty` snapshot path applies. C.head should restore
    // to snap_C.pre_pop_head_finish = 2500.
    cos_queue_push_front(queue, popped_c);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_c],
        2500
    );

    // Restore A1 via push_front: bucket A is empty so the
    // `was_empty` snapshot path applies. WITHOUT #927, A.head
    // would restore to snap_1.pre_pop_head_finish = 1000 —
    // inverting MQFQ order vs C (1000 < 2500). WITH #927, the
    // orphan-cleanup helper bumped snap_1.pre_pop_head_finish
    // up to A2's served_finish = 3000, so the restored A.head
    // = 3000 > C.head = 2500 — MQFQ correctly picks C first.
    cos_queue_push_front(queue, popped_a1);
    assert!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a]
            > test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_c],
        "#927 regression: A.head ({}) must be strictly greater than \
         C.head ({}) so MQFQ picks C first. Without the orphan-cleanup \
         same-bucket frontier bump, A.head would restore to 1000 and \
         A1 would pop before C — inverting their original schedule.",
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_c],
    );
}

/// Pin that on a shared_exact flow-fair queue, the admission
/// gates downgrade to aggregate-only — rate-unaware per-flow
/// cap would tail-drop TCP at the 24 KB floor on a 25 Gbps
/// queue with 12 flows. Retrospective Attempt A measured 8 Gbps
/// throughput regression when this downgrade was absent.
#[test]
fn mqfq_shared_exact_admission_downgrades_to_aggregate() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 25_000_000_000 / 8,
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
    queue.config.shared_exact = true;

    let target = 0usize;
    seed_sixteen_flow_buckets(queue, target, 1);
    let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
    let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);

    assert_eq!(
        share_cap, buffer_limit,
        "#785 Phase 3: shared_exact + flow_fair queues MUST use \
         aggregate-only admission (share_cap == buffer_limit). \
         Regression re-introduces the 24 KB per-flow floor that \
         tail-drops TCP at multi-Gbps per-flow rates.",
    );
}

/// #785 Phase 3 Codex round-2 HIGH: push_front onto an active
/// bucket must be finish-time-neutral — a pop-and-restore
/// round-trip must leave the queue in the same state it started.
///
/// Without this invariant, TX-ring-full restoration paths
/// (every flow-fair drain has one) corrupt the MQFQ selection
/// key: push_front leaves head stale, subsequent non-drain pops
/// advance head off the stale base, and bucket ordering drifts
/// arbitrarily. Codex traced it with a three-packet bucket
/// where a push_front mid-drain produced a 500-byte discrepancy
/// on a 1500-byte packet's finish time.
///
/// Round-3 extension (Codex HIGH): also pin `queue_vtime`
/// neutrality. The prior revision advanced `queue_vtime` on
/// pop-time but never rewound on push_front, biasing newly-
/// active flows behind a phantom amount of drained bytes
/// whenever TX-ring-full rolled a pop back onto the queue.
///
/// Test: pop the head, observe advanced head-finish and vtime,
/// push_front the popped item back, observe ALL of head-finish,
/// tail-finish, bucket-bytes, AND queue_vtime returned to their
/// pre-pop values.
#[test]
fn mqfq_push_front_is_finish_time_neutral_on_active_bucket() {
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

    // Enqueue three packets on one flow.
    cos_queue_push_back(queue, test_flow_cos_item(4444, 1000));
    cos_queue_push_back(queue, test_flow_cos_item(4444, 2000));
    cos_queue_push_back(queue, test_flow_cos_item(4444, 1500));

    let flow = test_session_key(4444, 5201);
    let bucket = cos_flow_bucket_index(0, Some(&flow));

    // Bucket state: head=1000, tail=4500.
    let pre_pop_head = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket];
    let pre_pop_tail = test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket];
    let pre_pop_bytes = test_flow_fair_state(queue).flow_bucket_bytes[bucket];
    let pre_pop_vtime = test_flow_fair_state(queue).queue_vtime;
    assert_eq!(pre_pop_head, 1000);
    assert_eq!(pre_pop_tail, 4500);
    assert_eq!(pre_pop_bytes, 4500);
    assert_eq!(pre_pop_vtime, 0);

    // Pop head (the 1000-byte packet). Head advances to 3000
    // (= pre_pop_head + bytes(new head = 2000)). vtime += 1000.
    let popped = cos_queue_pop_front(queue).expect("pop");
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket],
        3000
    );
    assert_eq!(test_flow_fair_state(queue).queue_vtime, 1000);

    // Push the same item back onto the front. Head-finish MUST
    // return to the pre-pop value (1000), AND queue_vtime MUST
    // return to its pre-pop value (0) — Codex round-3 HIGH.
    cos_queue_push_front(queue, popped);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket],
        pre_pop_head,
        "#785 Phase 3 Codex HIGH: push_front must be finish-\
         time-neutral on active buckets. Regression re-opens \
         the MQFQ ordering corruption on TX-ring-full retry.",
    );
    // Tail unchanged — we didn't add at tail.
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket],
        pre_pop_tail
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket],
        pre_pop_bytes
    );
    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        pre_pop_vtime,
        "#785 Phase 3 Codex round-3 HIGH: queue_vtime must be \
         round-trip neutral on pop→push_front. Without this, \
         newly-active flows inherit an inflated vtime anchor \
         and start behind established traffic even though zero \
         bytes were actually transmitted during the rollback.",
    );
}

/// #785 Phase 3 Codex round-3 HIGH — companion pin for the
/// DRAINED-bucket case (Rust reviewer MEDIUM #1). When the
/// popped item is the SOLE packet in its bucket, the pop
/// path's `account_cos_queue_flow_dequeue` resets head=tail=0
/// AND the bucket deregisters from the active set. A naive
/// push_front would hit the `was_empty` branch and re-anchor
/// head=tail=`max(0, queue_vtime) + bytes`, which overshoots
/// the pre-pop head by up to one packet and leaves the
/// bucket competing at the wrong virtual-time.
///
/// Fix: the last-pop snapshot records pre-pop head/tail at
/// pop time; push_front restores them exactly when the
/// snapshot's bucket matches.
#[test]
fn mqfq_push_front_is_neutral_on_drained_bucket_round_trip() {
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

    // Simulate a vtime that's already advanced (as it would
    // be mid-stream when other flows have drained), then
    // enqueue a single packet on flow A. The idle-bucket
    // re-anchor writes head=tail=max(tail=0, vtime=5000)+1500
    // = 6500.
    test_flow_fair_state_mut(queue).queue_vtime = 5000;
    let flow_a = test_session_key(7777, 5201);
    let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
    cos_queue_push_back(queue, test_flow_cos_item(7777, 1500));

    let pre_pop_head = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a];
    let pre_pop_tail = test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a];
    let pre_pop_bytes = test_flow_fair_state(queue).flow_bucket_bytes[bucket_a];
    let pre_pop_vtime = test_flow_fair_state(queue).queue_vtime;
    let pre_pop_active = test_flow_fair_state(queue).active_flow_buckets;
    assert_eq!(pre_pop_head, 6500);
    assert_eq!(pre_pop_tail, 6500);
    assert_eq!(pre_pop_bytes, 1500);
    assert_eq!(pre_pop_vtime, 5000);

    // Pop the sole item. Bucket drains: head=tail=0, active
    // count -=1, vtime advances to 6500.
    let popped = cos_queue_pop_front(queue).expect("pop");
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        0
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        0
    );
    assert_eq!(test_flow_fair_state(queue).flow_bucket_bytes[bucket_a], 0);
    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        pre_pop_vtime + 1500
    );
    assert!(test_flow_fair_state(queue).flow_bucket_items[bucket_a].is_empty());

    // Restore it via push_front. Without the snapshot fix this
    // re-anchors to vtime+bytes = 6500+1500 = 8000 — one packet
    // past the pre-pop head of 6500. With the fix, head/tail
    // restore to 6500 exactly.
    cos_queue_push_front(queue, popped);

    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        pre_pop_head,
        "#785 Phase 3 Codex round-3 HIGH / Rust MEDIUM #1: \
         push_front on a drained bucket must restore pre-pop \
         head exactly, not re-anchor one packet past it.",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        pre_pop_tail
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket_a],
        pre_pop_bytes
    );
    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        pre_pop_vtime,
        "#785 Phase 3: queue_vtime must rewind to pre-pop on \
         drained-bucket round-trip too.",
    );
    assert_eq!(
        test_flow_fair_state(queue).active_flow_buckets,
        pre_pop_active
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_items[bucket_a].len(),
        1
    );
}

/// #785 Phase 3 Codex round-2 NEW-1 — batched rollback on a
/// SINGLE bucket must restore every pre-pop snapshot exactly,
/// not just the most recent one.
///
/// Scenario: N (=4) items enqueued on one flow, drained into
/// scratch in one batch (simulating the TX-ring-full drain
/// path), then rolled back in LIFO order via push_front.
/// After rollback, every per-bucket field and `queue_vtime`
/// must equal its pre-batch value.
///
/// Prior revision kept a single `Option<CoSQueuePopSnapshot>`
/// that each pop overwrote. On rollback only the FIRST
/// push_front (matching the LAST pop) got its snapshot; all
/// earlier restorations fell back to the idle-bucket
/// `max(tail, queue_vtime) + bytes` re-anchor. For this
/// single-bucket case the earlier restorations' ACTIVE branch
/// did happen to produce the right answer (the restored item
/// took over as the new head via `head -= bytes(front)`), BUT
/// the drained-bucket case in the cross-bucket pin below
/// overshoots without a per-pop stack. Both pins together
/// cover single-bucket and multi-bucket correctness.
#[test]
fn mqfq_batched_rollback_restores_queue_vtime() {
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

    // Advance `queue_vtime` so that later flows anchor ahead
    // of zero (stresses the cross-bucket bug — an earlier pop
    // whose bucket drains resets head/tail to 0, then
    // `max(0, queue_vtime) + bytes` on re-enqueue overshoots
    // the pre-pop head).
    test_flow_fair_state_mut(queue).queue_vtime = 3000;

    let flow_a = test_session_key(5555, 5201);
    let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));

    cos_queue_push_back(queue, test_flow_cos_item(5555, 1000));
    cos_queue_push_back(queue, test_flow_cos_item(5555, 1200));
    cos_queue_push_back(queue, test_flow_cos_item(5555, 800));
    cos_queue_push_back(queue, test_flow_cos_item(5555, 1400));

    let pre_batch_head = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a];
    let pre_batch_tail = test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a];
    let pre_batch_bytes = test_flow_fair_state(queue).flow_bucket_bytes[bucket_a];
    let pre_batch_vtime = test_flow_fair_state(queue).queue_vtime;
    let pre_batch_active = test_flow_fair_state(queue).active_flow_buckets;
    let pre_batch_peak = test_flow_fair_state(queue).active_flow_buckets_peak;
    let pre_batch_items = test_flow_fair_state(queue).flow_bucket_items[bucket_a].len();
    assert_eq!(pre_batch_items, 4);

    // Drain all 4 into scratch. Stack grows to 4 snapshots.
    let mut scratch: Vec<CoSPendingTxItem> = Vec::with_capacity(4);
    while let Some(item) = cos_queue_pop_front(queue) {
        scratch.push(item);
    }
    assert_eq!(scratch.len(), 4);
    assert_eq!(
        test_flow_fair_state(queue).pop_snapshot_stack.len(),
        4,
        "NEW-1: every pop must push its own snapshot onto the \
         per-queue LIFO stack",
    );

    // Roll back all 4 in LIFO order (scratch.pop()). This
    // mirrors `restore_exact_local_scratch_to_queue_head_flow_fair`.
    while let Some(item) = scratch.pop() {
        cos_queue_push_front(queue, item);
    }

    assert!(
        test_flow_fair_state(queue).pop_snapshot_stack.is_empty(),
        "NEW-1: snapshot stack must be fully consumed after a \
         complete rollback",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        pre_batch_head,
        "#785 Phase 3 NEW-1: batched rollback must restore \
         bucket HEAD finish exactly (single-bucket case)",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        pre_batch_tail,
        "#785 Phase 3 NEW-1: batched rollback must restore \
         bucket TAIL finish exactly (single-bucket case)",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket_a],
        pre_batch_bytes,
        "#785 Phase 3 NEW-1: batched rollback must restore \
         bucket byte count exactly",
    );
    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        pre_batch_vtime,
        "#785 Phase 3 NEW-1: batched rollback must restore \
         queue_vtime exactly — symmetric per-item rewind",
    );
    assert_eq!(
        test_flow_fair_state(queue).active_flow_buckets,
        pre_batch_active,
        "#785 Phase 3 NEW-1: batched rollback must leave \
         active_flow_buckets unchanged",
    );
    assert_eq!(
        test_flow_fair_state(queue).active_flow_buckets_peak,
        pre_batch_peak,
        "#785 Phase 3 NEW-1: peak counter is monotonic — \
         rollback must not bump it (no fresh high-water mark)",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_items[bucket_a].len(),
        pre_batch_items
    );
}

/// #785 Phase 3 Codex round-2 NEW-1 — batched rollback across
/// MULTIPLE buckets. This is the case the prior single-
/// `Option<CoSQueuePopSnapshot>` implementation got wrong:
/// earlier drained buckets (i.e. not the MOST-recently-popped
/// one) had no snapshot at rollback time and fell back to the
/// idle re-anchor `max(tail=0, queue_vtime) + bytes`, which
/// overshoots the pre-pop head whenever `queue_vtime` has
/// advanced past the bucket's original enqueue point.
///
/// Scenario construction:
///   1. Pre-advance `queue_vtime=100`; enqueue A (1500) and B
///      (900) at that frontier. pre-pop head[A]=1600,
///      head[B]=1000.
///   2. Force-advance `queue_vtime=5000` to simulate a long
///      period of other-flow drain activity between enqueue
///      and batch.
///   3. Drain both: pop B (head 1000 < 1600), then pop A.
///      vtime goes 5000 → 5900 → 7400. Both buckets drain,
///      head/tail=0.
///   4. Roll back LIFO. scratch.pop() returns A first, then B.
///
/// With per-pop snapshots: A's restore pops snap_A from the
/// stack and writes head[A]=1600. B's restore pops snap_B and
/// writes head[B]=1000.
///
/// Without per-pop snapshots (old single-`Option` impl):
/// snapshot held {A, 1600, 1600} (last overwrote). A's restore
/// uses it and succeeds. B's restore finds snapshot=None,
/// falls through to `account_cos_queue_flow_enqueue`:
/// head[B] = max(0, vtime_at_that_point=5000) + 900 = 5900,
/// overshooting the pre-pop head of 1000 by 4900. THIS PIN
/// TRIPS: without the fix the assertion on B's head-finish
/// fails at 5900 != 1000.
#[test]
fn mqfq_batched_rollback_across_multiple_buckets() {
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

    // Step 1: low vtime so A and B anchor near 0.
    test_flow_fair_state_mut(queue).queue_vtime = 100;

    let flow_a = test_session_key(6001, 5201);
    let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
    let flow_b = test_session_key(6002, 5201);
    let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
    assert_ne!(bucket_a, bucket_b, "test hash collision");

    cos_queue_push_back(queue, test_flow_cos_item(6001, 1500));
    cos_queue_push_back(queue, test_flow_cos_item(6002, 900));
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        1600
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_b],
        1000
    );

    // Step 2: simulate other-flow drain activity. vtime
    // advances past both buckets' head finish times. This is
    // the condition that makes the old single-Option rollback
    // overshoot on the earlier-popped bucket.
    test_flow_fair_state_mut(queue).queue_vtime = 5000;

    let pre_batch_head_a = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a];
    let pre_batch_tail_a = test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a];
    let pre_batch_bytes_a = test_flow_fair_state(queue).flow_bucket_bytes[bucket_a];
    let pre_batch_head_b = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_b];
    let pre_batch_tail_b = test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_b];
    let pre_batch_bytes_b = test_flow_fair_state(queue).flow_bucket_bytes[bucket_b];
    let pre_batch_vtime = test_flow_fair_state(queue).queue_vtime;
    let pre_batch_active = test_flow_fair_state(queue).active_flow_buckets;
    let pre_batch_peak = test_flow_fair_state(queue).active_flow_buckets_peak;
    assert_eq!(pre_batch_head_a, 1600);
    assert_eq!(pre_batch_head_b, 1000);
    assert_eq!(pre_batch_vtime, 5000);
    assert_eq!(pre_batch_active, 2);

    // Drain both into scratch. MQFQ picks min-finish-first;
    // B's head (1400) < A's head (2000), so pop order is B
    // then A. Both buckets drain to head=tail=0.
    let mut scratch: Vec<CoSPendingTxItem> = Vec::with_capacity(2);
    while let Some(item) = cos_queue_pop_front(queue) {
        scratch.push(item);
    }
    assert_eq!(scratch.len(), 2);
    assert_eq!(test_flow_fair_state(queue).pop_snapshot_stack.len(), 2);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        0
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_b],
        0
    );
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 0);

    // Roll back LIFO. scratch.pop() returns A (popped second)
    // first, then B. Each push_front consumes its own
    // snapshot off the stack.
    while let Some(item) = scratch.pop() {
        cos_queue_push_front(queue, item);
    }

    assert!(
        test_flow_fair_state(queue).pop_snapshot_stack.is_empty(),
        "NEW-1: snapshot stack must be fully consumed after a \
         complete cross-bucket rollback",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        pre_batch_head_a,
        "#785 Phase 3 NEW-1: cross-bucket rollback — A's HEAD \
         must restore from A's OWN per-pop snapshot, not re- \
         anchor off the rewound vtime (that overshoots).",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        pre_batch_tail_a,
        "#785 Phase 3 NEW-1: cross-bucket rollback — A's TAIL \
         must restore exactly.",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket_a],
        pre_batch_bytes_a
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_b],
        pre_batch_head_b,
        "#785 Phase 3 NEW-1: cross-bucket rollback — B's HEAD \
         must restore exactly (this is the 'most recent pop' \
         case that worked with the single-snapshot impl too).",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_b],
        pre_batch_tail_b,
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket_b],
        pre_batch_bytes_b
    );
    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        pre_batch_vtime,
        "#785 Phase 3 NEW-1: vtime must rewind symmetrically \
         across a cross-bucket batch rollback.",
    );
    assert_eq!(
        test_flow_fair_state(queue).active_flow_buckets,
        pre_batch_active,
        "#785 Phase 3 NEW-1: cross-bucket rollback must re- \
         activate both buckets.",
    );
    assert_eq!(
        test_flow_fair_state(queue).active_flow_buckets_peak,
        pre_batch_peak
    );
}

