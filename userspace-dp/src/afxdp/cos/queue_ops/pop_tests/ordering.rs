use super::*;

#[test]
fn flow_fair_exact_queue_limits_dominant_flow_share() {
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
    let buffer_limit = queue.config.buffer_bytes.max(COS_MIN_BURST_BYTES);
    let flow_a = test_session_key(1111, 5201);
    let flow_b = test_session_key(1112, 5201);
    let bucket_a = cos_flow_bucket_index(test_flow_fair_state(queue).flow_hash_seed, Some(&flow_a));
    let bucket_b = cos_flow_bucket_index(test_flow_fair_state(queue).flow_hash_seed, Some(&flow_b));
    assert_ne!(bucket_a, bucket_b);

    assert_eq!(
        cos_queue_flow_share_limit(queue, buffer_limit, bucket_a),
        buffer_limit
    );
    account_cos_queue_flow_enqueue(queue, Some(&flow_a), 64 * 1024);
    account_cos_queue_flow_enqueue(queue, Some(&flow_a), 32 * 1024);
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 1);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket_a],
        96 * 1024
    );

    account_cos_queue_flow_enqueue(queue, Some(&flow_b), 16 * 1024);
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 2);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket_b],
        16 * 1024
    );

    let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, bucket_a);
    assert_eq!(share_cap, buffer_limit / 2);
    assert!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket_a].saturating_add(16 * 1024)
            > share_cap
    );

    account_cos_queue_flow_dequeue(queue, Some(&flow_b), 16 * 1024);
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 1);
    assert_eq!(test_flow_fair_state(queue).flow_bucket_bytes[bucket_b], 0);
}

/// #785 Phase 3 — head-keyed MQFQ ordering with equal-byte
/// packets. Three flows, equal 1500-byte packets, 1111 has
/// two packets, 1112 and 1113 have one each.
///
/// Post-enqueue HEAD finish times (the selection key):
///   bucket(1111) head=1500 tail=3000 (head unchanged when
///     second packet arrives at tail of active bucket)
///   bucket(1112) head=tail=1500
///   bucket(1113) head=tail=1500
///
/// All heads tie at 1500. Ties broken by ring insertion
/// order (1111 enqueued first, wins). After pop of 1111
/// pkt1, bucket 1111 is still active; head advances to
/// `old_head + bytes(new head packet) = 1500 + 1500 = 3000`.
/// Now 1112 and 1113 lead at head=1500, so they drain before
/// 1111 pkt2.
///
/// For equal-byte packets, MQFQ produces the SAME service
/// order as DRR — they're byte-rate equivalent when all
/// packets are the same size. The MQFQ divergence from DRR
/// shows up on mixed-size packets (see
/// `flow_fair_queue_mqfq_bytes_rate_fair_on_mixed_packet_sizes`).
///
/// This test's value is pinning the head-finish mechanism's
/// internal correctness: head advances on non-drain pop,
/// tail advances on enqueue, tie-break = insertion order.
/// Codex HIGH on the first revision keyed selection off TAIL
/// finish, which broke this equivalence and produced an
/// A,A,B,B burst pattern.
#[test]
fn flow_fair_queue_pops_in_virtual_finish_order_local() {
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

    cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));
    cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));
    cos_queue_push_back(queue, test_flow_cos_item(1112, 1500));
    cos_queue_push_back(queue, test_flow_cos_item(1113, 1500));

    let mut order = Vec::new();
    while let Some(CoSPendingTxItem::Local(req)) = cos_queue_pop_front(queue) {
        order.push(req.flow_key.expect("flow key").src_port);
    }

    // Equal-byte packets: MQFQ order matches DRR round-robin.
    // After popping 1111 pkt1, bucket 1111's head advances to
    // 3000; 1112 and 1113 still sit at 1500 and drain next.
    assert_eq!(
        order,
        vec![1111, 1112, 1113, 1111],
        "#785 Phase 3: with equal-byte packets the head-keyed \
         MQFQ order matches DRR round-robin — both are byte-\
         rate fair on uniform packet sizes. Regression here = \
         MQFQ ordering is broken (e.g. TAIL-keyed selection \
         produces the A,A,B,B burst [1111, 1111, 1112, 1113]).",
    );
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 0);
    assert!(test_flow_fair_state(queue).flow_rr_buckets.is_empty());
    // #913 — MQFQ served-finish semantics: vtime tracks the
    // finish time of the last served packet, not the
    // aggregate bytes drained. With pop order
    // [1111, 1112, 1113, 1111] each picking a bucket whose
    // head_finish=1500 (and the last pop seeing head_finish=
    // 3000 after head-advance), `max(0,1500,1500,1500,3000)
    // = 3000`. Pre-#913 (aggregate-bytes) would have given
    // Σbytes = 6000.
    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        3000,
        "vtime tracks last served packet's finish-time \
         (MQFQ served-finish), not aggregate bytes drained \
         (pre-#913 SFQ V(t))"
    );
}

/// #785 Phase 3 — MQFQ byte-rate fairness on MIXED packet sizes.
/// This is where MQFQ actually diverges from DRR.
///
/// Flow 1111: one 3000-byte packet (e.g. GSO-coalesced).
/// Flow 1112: one 1500-byte packet.
/// Flow 1113: one 1500-byte packet.
///
/// DRR (packet-count fair) order: [1111, 1112, 1113] — one
/// packet per round. Flow 1111 gets 3000 bytes drained while
/// flows 1112/1113 get only 1500 each → NOT byte-rate fair.
///
/// MQFQ (byte-rate fair) order: [1112, 1113, 1111] — 1111's
/// finish is 3000 (byte count) while 1112/1113 sit at 1500,
/// so 1111 drains LAST. Over 6000 bytes of drain, every flow
/// gets exactly 1/3 = 2000 bytes of virtual time budget, not
/// 1/3 of the packet count.
///
/// This is the property that closes the #785 CoV gap under TCP
/// pacing: a flow with smaller cwnd sends fewer/smaller packets
/// per RTT; DRR lets the busier flow sweep its polls, while
/// MQFQ reserves drain slots proportional to byte rate.
#[test]
fn flow_fair_queue_mqfq_bytes_rate_fair_on_mixed_packet_sizes() {
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

    cos_queue_push_back(queue, test_flow_cos_item(1111, 3000));
    cos_queue_push_back(queue, test_flow_cos_item(1112, 1500));
    cos_queue_push_back(queue, test_flow_cos_item(1113, 1500));

    // Head finishes: 1111=3000, 1112=1500, 1113=1500.
    // MQFQ pops smallest: 1112, then 1113 (tie-break on ring
    // insertion order), then 1111 last.
    let mut order = Vec::new();
    while let Some(CoSPendingTxItem::Local(req)) = cos_queue_pop_front(queue) {
        order.push(req.flow_key.expect("flow key").src_port);
    }

    assert_eq!(
        order,
        vec![1112, 1113, 1111],
        "#785 Phase 3: MQFQ MUST pop the larger-byte packet \
         LAST so all three flows get equal byte share over the \
         test window. DRR order [1111, 1112, 1113] is packet-\
         count fair but NOT byte-rate fair — flow 1111 gets 2× \
         the bytes of the others. Regression here collapses \
         MQFQ to DRR and re-opens the #785 CoV gap.",
    );
}

/// #785 Phase 3 Rust reviewer MEDIUM #3 — golden-vector table
/// pinning MQFQ pop order across a small matrix of mixed-size
/// inputs. Each row encodes (packet_sizes_per_flow,
/// expected_mqfq_pop_order_by_src_port,
/// reference_drr_pop_order_by_src_port).
///
/// The DRR reference column is a static assertion of "what
/// packet-count-fair DRR would produce" for the same input —
/// kept as a golden vector rather than executed against a live
/// DRR implementation (the old DRR path has been removed from
/// this tree). The value of the table is regression-testing
/// the tie-break rule in `cos_queue_min_finish_bucket` and
/// locking the MQFQ-vs-DRR divergence into the test surface.
///
/// Flow-to-bucket hashing depends on `flow_hash_seed=0` and
/// the current `cos_flow_bucket_index` formula; if that hash
/// changes, `insertion_port_order` below may need updating —
/// test will fail with a clear "bucket collision" or
/// "wrong port drains first" message.
#[test]
fn mqfq_golden_vector_pop_order_vs_drr() {
    struct GoldenRow {
        name: &'static str,
        // (src_port, bytes) tuples in push_back order.
        packets: &'static [(u16, usize)],
        // Expected MQFQ pop order (by src_port).
        mqfq_order: &'static [u16],
        // Reference DRR order (documented, not asserted against
        // live DRR).
        drr_order: &'static [u16],
    }

    const TABLE: &[GoldenRow] = &[
        // All packets same size: MQFQ and DRR produce identical
        // orderings (both are byte-rate fair on uniform sizes).
        GoldenRow {
            name: "equal-1500-two-flows",
            packets: &[(2001, 1500), (2001, 1500), (2002, 1500), (2002, 1500)],
            mqfq_order: &[2001, 2002, 2001, 2002],
            drr_order: &[2001, 2002, 2001, 2002],
        },
        // 2x size disparity, two flows. MQFQ pops the smaller
        // packet first (head=1500 vs 3000). After that pop,
        // flow B's second packet becomes its head at
        // head=1500+1500=3000 (active-bucket head advance on
        // non-drain pop). Flow A's head is still 3000. Tie on
        // head — insertion-order tie-break picks A (its bucket
        // was added to the ring first). Then B's last packet
        // drains. Order: B, A, B.
        //
        // DRR rotation would be A, B, B (larger inserted first;
        // DRR walks ring insertion order per round, not finish
        // time). Orders differ → this row proves MQFQ's
        // tie-break and non-drain-head-advance invariants
        // diverge from DRR on size-disparate traffic.
        GoldenRow {
            name: "mixed-3000-1500-two-flows",
            packets: &[(2101, 3000), (2102, 1500), (2102, 1500)],
            mqfq_order: &[2102, 2101, 2102],
            drr_order: &[2101, 2102, 2102],
        },
        // 3-way mixed: 2000 vs 1000 vs 500. MQFQ orders by
        // head finish (500, 1000, 2000) and then catches up.
        // DRR rotates insertion order (2201, 2202, 2203, ...).
        GoldenRow {
            name: "mixed-three-flows-progressive-sizes",
            packets: &[(2201, 2000), (2202, 1000), (2203, 500)],
            mqfq_order: &[2203, 2202, 2201],
            drr_order: &[2201, 2202, 2203],
        },
    ];

    for row in TABLE {
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

        for (src_port, bytes) in row.packets {
            cos_queue_push_back(queue, test_flow_cos_item(*src_port, *bytes));
        }

        let mut mqfq_order = Vec::with_capacity(row.packets.len());
        while let Some(CoSPendingTxItem::Local(req)) = cos_queue_pop_front(queue) {
            mqfq_order.push(req.flow_key.expect("flow key").src_port);
        }

        assert_eq!(
            mqfq_order, row.mqfq_order,
            "#785 Phase 3 golden vector '{}': MQFQ pop order \
             mismatch. Expected {:?} (byte-rate fair), got \
             {:?}. DRR reference would be {:?} — if the actual \
             matches DRR, MQFQ has collapsed to packet-count \
             fairness and the #785 CoV gap has reopened.",
            row.name, row.mqfq_order, mqfq_order, row.drr_order,
        );
    }

    // Separately assert that AT LEAST ONE row in the table
    // diverges MQFQ from DRR — otherwise the golden vector
    // isn't demonstrating the MQFQ advantage at all (equal-
    // size rows are expected to match; mixed-size rows are
    // the discriminating cases). A regression that collapses
    // MQFQ to DRR flips at least one mixed-size row's output
    // to the drr_order column, failing the assert_eq above.
    let any_divergent = TABLE.iter().any(|row| row.mqfq_order != row.drr_order);
    assert!(
        any_divergent,
        "#785 Phase 3 golden vector table must include at \
         least one row where MQFQ diverges from DRR; otherwise \
         the table is not demonstrating byte-rate fairness vs. \
         packet-count fairness.",
    );
}

/// #785 Phase 3 Rust reviewer LOW — idle-return anchor pin.
/// Complements `mqfq_queue_vtime_advances_by_drained_bytes`
/// and `mqfq_bucket_drain_resets_finish_time` by asserting the
/// CONSEQUENCE of those invariants: a flow that idles while
/// others drain must re-anchor at `queue_vtime + bytes`, NOT
/// sweep past established flows by re-entering at 0.
///
/// Without the idle re-anchor, a bursty flow that goes silent
/// and returns would drain all its packets before the active
/// flow got another slot (anchor=0+bytes wins every min-scan
/// for several rounds). With it, the returning flow competes
/// at the current frontier and interleaves correctly.
#[test]
fn mqfq_idle_flow_reanchors_at_frontier_not_zero() {
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

    let flow_a = test_session_key(3301, 5201);
    let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
    let flow_b = test_session_key(3302, 5201);
    let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
    assert_ne!(bucket_a, bucket_b, "test hash collision");

    // Drain flow A for 3 x 1500 = 4500 bytes. vtime reaches
    // 4500.
    for _ in 0..3 {
        cos_queue_push_back(queue, test_flow_cos_item(3301, 1500));
    }
    for _ in 0..3 {
        let _ = cos_queue_pop_front(queue);
    }
    assert_eq!(test_flow_fair_state(queue).queue_vtime, 4500);

    // Flow B was idle the whole time. It now returns with a
    // 1200-byte packet. It MUST anchor at queue_vtime+bytes =
    // 4500+1200 = 5700, NOT at 0+1200 = 1200.
    cos_queue_push_back(queue, test_flow_cos_item(3302, 1200));
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_b],
        5700,
        "#785 Phase 3: idle-returning bucket MUST re-anchor at \
         current queue_vtime, not 0. Anchoring at 0 lets the \
         returning flow sweep past all established flows for \
         several rounds (#785 CoV regression).",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_b],
        5700
    );
}

/// #785 Phase 3 — same mixed-size byte-rate ordering on the
/// Prepared (zero-copy) path. Both Local and Prepared variants
/// must share MQFQ ordering; the pop path picks by finish time
/// regardless of item kind.
#[test]
fn flow_fair_queue_pops_in_virtual_finish_order_prepared() {
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

    // 3000-byte packet on 1111, 1500-byte packets on 1112.
    cos_queue_push_back(queue, test_flow_prepared_cos_item(1111, 3000, 64));
    cos_queue_push_back(queue, test_flow_prepared_cos_item(1112, 1500, 192));

    let mut order = Vec::new();
    while let Some(CoSPendingTxItem::Prepared(req)) = cos_queue_pop_front(queue) {
        order.push(req.flow_key.expect("flow key").src_port);
    }

    assert_eq!(
        order,
        vec![1112, 1111],
        "Prepared-path MQFQ ordering must match Local-path: \
         smaller-finish drains first regardless of variant.",
    );
}

/// Pin the enqueue-side VFT formula:
/// `finish[b] = max(finish[b], queue.vtime) + bytes`.
///
/// Three sub-properties:
/// 1. On first packet of a newly-active bucket, finish = vtime + bytes.
/// 2. Subsequent packets on the same bucket advance finish by bytes.
/// 3. Different flow sizes produce proportional finish-time deltas.
///
/// Regression: if the formula loses either the `max(finish, vtime)`
/// anchor (idle bucket re-anchor) or the `+ bytes` step (cumulative
/// byte accounting), ordering silently mis-sorts under TCP pacing.
#[test]
fn mqfq_enqueue_bumps_finish_time_by_byte_count() {
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
    // Simulate the queue having already drained to vtime=5000.
    test_flow_fair_state_mut(queue).queue_vtime = 5000;

    let flow_a = test_session_key(1111, 5201);
    let flow_b = test_session_key(2222, 5201);
    let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
    let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
    assert_ne!(bucket_a, bucket_b, "fixture flow keys must not collide");

    // Packet 1 of flow A — bucket was idle (finish=0). Re-anchor
    // to queue.vtime (5000) then + 1500.
    account_cos_queue_flow_enqueue(queue, Some(&flow_a), 1500);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        6500,
        "first packet on an idle bucket re-anchors to queue.vtime \
         + bytes (5000 + 1500 = 6500)",
    );

    // Packet 2 of flow A — already-active. finish advances by bytes.
    account_cos_queue_flow_enqueue(queue, Some(&flow_a), 1500);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        8000,
        "subsequent packet on the same active bucket advances by \
         exactly bytes (6500 + 1500 = 8000)",
    );

    // Packet 1 of flow B — independent bucket, same re-anchor.
    account_cos_queue_flow_enqueue(queue, Some(&flow_b), 500);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_b],
        5500,
        "different-sized packet produces proportional finish \
         delta (5000 + 500 = 5500)",
    );
}

/// Pin that a bucket's finish-time is RESET to 0 when the last
/// packet drains from it. Without this reset, a bucket that goes
/// idle and later re-activates would inherit its stale lifetime
/// finish-time — the enqueue-side `max(finish, vtime)` anchor
/// would be no-op'd (finish >> vtime), letting the returning flow
/// skip ahead of all established flows in bounded rounds.
#[test]
fn mqfq_bucket_drain_resets_finish_time() {
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

    let flow = test_session_key(3333, 5201);
    let bucket = cos_flow_bucket_index(0, Some(&flow));

    cos_queue_push_back(queue, test_flow_cos_item(3333, 1500));
    assert!(test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket] > 0);
    assert!(test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket] > 0);

    // Drain the only packet. Bucket is now empty.
    let _ = cos_queue_pop_front(queue);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket],
        0,
        "bucket drain to 0 MUST reset head-finish-time",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket],
        0,
        "bucket drain to 0 MUST reset tail-finish-time so the \
         next enqueue re-anchors at queue.vtime, not the stale \
         lifetime finish",
    );
}

/// #913 — Pin the `queue.vtime` semantics: MQFQ served-finish.
/// Vtime advances to track the served packet's finish time
/// (which equals the smallest head_finish across active
/// buckets at pop time, since MQFQ pops min-finish-first).
/// This is the "system frontier" — re-enqueued idle buckets
/// compare against it in `max(bucket_finish, queue_vtime) +
/// bytes` so a returning flow starts at the current
/// frontier, not back at 0.
///
/// In this single-flow test, served_finish progresses
/// 1500 → 3000 → 4500 (head advances by next-packet bytes
/// after each pop). vtime = max(prev, served) tracks the
/// progression — same numerical result as the pre-#913
/// aggregate-bytes formulation, by coincidence in the
/// single-flow case. The cross-flow test
/// `mqfq_vtime_does_not_accumulate_across_flows` (below)
/// shows where the two semantics actually diverge.
#[test]
fn mqfq_queue_vtime_tracks_served_finish_time() {
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

    // Three packets on one flow. After enqueue, bucket_finish
    // = 4500 (the 3rd packet's finish). But queue.vtime should
    // advance by 1500 per pop, not jump to 4500 on the first.
    cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));
    cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));
    cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));

    assert_eq!(test_flow_fair_state(queue).queue_vtime, 0);

    let _ = cos_queue_pop_front(queue);
    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        1500,
        "first pop: vtime tracks served packet's finish_time \
         (1500 = head_finish of the 1st packet)",
    );
    let _ = cos_queue_pop_front(queue);
    assert_eq!(test_flow_fair_state(queue).queue_vtime, 3000);
    let _ = cos_queue_pop_front(queue);
    assert_eq!(test_flow_fair_state(queue).queue_vtime, 4500);
}

/// #913 — Distinguishing test: vtime must NOT accumulate
/// across flows. This test would FAIL under the pre-#913
/// aggregate-bytes formulation and PASS under the new MQFQ
/// served-finish formulation. It's the bug-trip that would
/// have caught the original SFQ-V(t) implementation if it
/// had existed at the time the original code landed.
///
/// Setup: 10 distinct flows, one 1500-byte packet each. Pop
/// one packet from each flow in MQFQ order (10 pops). Every
/// flow's bucket has head_finish=1500 at enqueue (vtime=0).
///
/// Pre-#913 (aggregate-bytes): vtime advances by 1500 per
/// pop → final = 10 × 1500 = 15000.
///
/// New (MQFQ served-finish): each pop sees served_finish=
/// 1500 (every flow's first packet); `vtime = max(prev,
/// 1500)` never advances past the first round → final =
/// 1500.
///
/// Why this matters for #911: under the old semantics, a
/// mouse arriving after N rounds of elephant draining
/// anchored at vtime + bytes = N × MTU + small ≫ active
/// buckets' head_finish, so MQFQ served the mouse LAST.
/// Under new semantics, vtime tracks the served frontier
/// and the mouse interleaves with elephants.
#[test]
fn mqfq_vtime_does_not_accumulate_across_flows() {
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

    // Enqueue one 1500-byte packet on each of 10 distinct
    // flows. After enqueue, every bucket has head=tail=1500.
    // Copilot review: select flow IDs dynamically so the test
    // doesn't couple to a specific hash distribution. We
    // sweep candidate IDs and accept the first 10 that land
    // in distinct buckets.
    let mut buckets: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut accepted: Vec<u16> = Vec::with_capacity(10);
    for flow_id in 1000u16..2000u16 {
        let key = test_session_key(flow_id, 5201);
        let bucket = cos_flow_bucket_index(0, Some(&key));
        if buckets.insert(bucket) {
            accepted.push(flow_id);
            if accepted.len() == 10 {
                break;
            }
        }
    }
    assert_eq!(
        accepted.len(),
        10,
        "test setup: 10 distinct buckets must be selectable in [1000, 2000)"
    );
    for flow_id in accepted {
        cos_queue_push_back(queue, test_flow_cos_item(flow_id, 1500));
    }
    assert_eq!(test_flow_fair_state(queue).queue_vtime, 0);
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 10);

    // Pop all 10 items via MQFQ (min head_finish first).
    for _ in 0..10 {
        assert!(cos_queue_pop_front(queue).is_some());
    }

    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        1500,
        "#913 MQFQ: vtime tracks served-packet finish, \
         not aggregate bytes drained. Each pop sees the \
         same head_finish=1500 across the 10 distinct \
         flows; max(0,1500,1500,...,1500) = 1500. \
         Pre-#913 aggregate-bytes would have given \
         10 × 1500 = 15000."
    );
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 0);
}

