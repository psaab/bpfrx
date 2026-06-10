// Tests for afxdp/cos/queue_ops/mod.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep mod.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tests.rs"]` from mod.rs.

use super::*;
use crate::afxdp::PROTO_TCP;
use crate::afxdp::cos::admission::{
    apply_cos_queue_flow_fair_promotion, cos_flow_aware_buffer_limit, cos_queue_flow_share_limit,
};
use crate::afxdp::cos::queue_service::ExactCoSScratchBuild;
use crate::afxdp::cos::queue_service::{
    drain_exact_local_fifo_items_to_scratch, drain_exact_local_items_to_scratch_flow_fair,
    drain_exact_prepared_fifo_items_to_scratch, drain_exact_prepared_items_to_scratch_flow_fair,
    settle_exact_local_fifo_submission, settle_exact_local_scratch_submission_flow_fair,
    settle_exact_prepared_fifo_submission,
};
use crate::afxdp::cos::token_bucket::COS_MIN_BURST_BYTES;
use crate::afxdp::tx::cos_classify::{
    cos_queue_accepts_prepared, demote_prepared_cos_queue_to_local,
};
use crate::afxdp::tx::test_support::*;
use crate::afxdp::tx_frame_capacity;
use crate::afxdp::types::{
    COS_FLOW_FAIR_BUCKETS, CoSInterfaceRuntime, CoSQueueConfig, FastMap, FlowRrRing,
    PreparedTxRecycle, PreparedTxRequest, TxRequest,
};
use crate::afxdp::umem::MmapArea;

#[test]
fn cos_queue_rejects_prepared_once_local_items_enter_queue() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    // #774: use cos_queue_push_back so local_item_count
    // stays in sync. Previously this test poked queue.hot.items
    // directly, which bypassed the counter maintenance.
    cos_queue_push_back(
        &mut root.queues[0],
        CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 64,
            len: 1500,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }),
    );
    cos_queue_push_back(
        &mut root.queues[0],
        CoSPendingTxItem::Local(TxRequest {
            bytes: vec![0; 1500],
            expected_ports: None,
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }),
    );

    assert!(!cos_queue_accepts_prepared(&root, Some(5)));
}

#[test]
fn exact_local_fifo_boundary_survives_partial_commit() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![1],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![2],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 256,
            len: 1,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));

    let mut free_tx_frames = VecDeque::from([64, 128, 192]);
    let mut scratch_local_tx = Vec::new();

    let build = drain_exact_local_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &area,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_local_tx.len(), 2);

    let (sent_packets, sent_bytes) = settle_exact_local_fifo_submission(
        Some(&mut root.queues[0]),
        &mut free_tx_frames,
        &mut scratch_local_tx,
        1,
    );
    assert_eq!(sent_packets, 1);
    assert_eq!(sent_bytes, 1);
    assert_eq!(free_tx_frames, VecDeque::from([128, 192]));
    assert!(matches!(
        root.queues[0].hot.items.front(),
        Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![2]
    ));
    assert!(matches!(
        root.queues[0].hot.items.get(1),
        Some(CoSPendingTxItem::Prepared(req)) if req.offset == 256
    ));

    let build = drain_exact_local_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &area,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_local_tx.len(), 1);
    assert_eq!(scratch_local_tx[0].offset, 128);
    assert_eq!(free_tx_frames, VecDeque::from([192]));
    assert!(matches!(
        root.queues[0].hot.items.front(),
        Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![2]
    ));
    assert!(matches!(
        root.queues[0].hot.items.get(1),
        Some(CoSPendingTxItem::Prepared(req)) if req.offset == 256
    ));
}

#[test]
fn drain_exact_prepared_items_to_scratch_recycles_dropped_prepared_frame() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 64,
            len: (tx_frame_capacity() + 1) as u32,
            recycle: PreparedTxRecycle::FillOnSlot(7),
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));

    let mut scratch_prepared_tx = Vec::new();
    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();

    let build = drain_exact_prepared_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut scratch_prepared_tx,
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );

    match build {
        ExactCoSScratchBuild::Drop { dropped_bytes, .. } => {
            assert_eq!(dropped_bytes, (tx_frame_capacity() + 1) as u64);
        }
        ExactCoSScratchBuild::Ready => panic!("oversized prepared frame must drop"),
        ExactCoSScratchBuild::MirrorTxFrameReserve { .. } => {
            panic!("prepared frame must not trip mirror reserve handling")
        }
    }
    assert!(scratch_prepared_tx.is_empty());
    assert!(free_tx_frames.is_empty());
    assert_eq!(pending_fill_frames, VecDeque::from([64]));
    assert!(root.queues[0].hot.items.is_empty());
}

#[test]
fn exact_prepared_fifo_boundary_survives_partial_commit() {
    let area = MmapArea::new(4096).expect("mmap");
    unsafe { area.slice_mut_unchecked(64, 1) }
        .expect("prepared frame 1")
        .copy_from_slice(&[1]);
    unsafe { area.slice_mut_unchecked(128, 1) }
        .expect("prepared frame 2")
        .copy_from_slice(&[2]);

    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 64,
            len: 1,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 128,
            len: 1,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![9],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));

    let mut scratch_prepared_tx = Vec::new();
    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();

    let build = drain_exact_prepared_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut scratch_prepared_tx,
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_prepared_tx.len(), 2);

    let mut in_flight_prepared_recycles = FastMap::default();
    let (sent_packets, sent_bytes) = settle_exact_prepared_fifo_submission(
        Some(&mut root.queues[0]),
        &mut scratch_prepared_tx,
        &mut in_flight_prepared_recycles,
        1,
    );
    assert_eq!(sent_packets, 1);
    assert_eq!(sent_bytes, 1);
    assert!(matches!(
        root.queues[0].hot.items.front(),
        Some(CoSPendingTxItem::Prepared(req)) if req.offset == 128
    ));
    assert!(matches!(
        root.queues[0].hot.items.get(1),
        Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![9]
    ));

    let build = drain_exact_prepared_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut scratch_prepared_tx,
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_prepared_tx.len(), 1);
    assert_eq!(scratch_prepared_tx[0].offset, 128);
    assert!(matches!(
        root.queues[0].hot.items.front(),
        Some(CoSPendingTxItem::Prepared(req)) if req.offset == 128
    ));
    assert!(matches!(
        root.queues[0].hot.items.get(1),
        Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![9]
    ));
}

#[test]
fn cos_queue_push_and_pop_track_flow_bucket_bytes() {
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
            surplus_weight: 1,
            buffer_bytes: 128 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    enable_test_flow_fair(queue);

    let req_a = TxRequest {
        bytes: vec![0; 1500],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: Some(test_session_key(1111, 5201)),
        egress_ifindex: 80,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
        mirror_clone: false,
        enqueue_ns: 0,
    };
    let req_b = TxRequest {
        bytes: vec![0; 1500],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: Some(test_session_key(1112, 5201)),
        egress_ifindex: 80,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
        mirror_clone: false,
        enqueue_ns: 0,
    };
    let bucket_a = cos_flow_bucket_index(
        test_flow_fair_state(queue).flow_hash_seed,
        req_a.flow_key.as_ref(),
    );
    let bucket_b = cos_flow_bucket_index(
        test_flow_fair_state(queue).flow_hash_seed,
        req_b.flow_key.as_ref(),
    );
    assert_ne!(bucket_a, bucket_b);

    cos_queue_push_back(queue, CoSPendingTxItem::Local(req_a));
    cos_queue_push_back(queue, CoSPendingTxItem::Local(req_b));
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 2);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket_a],
        1500
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket_b],
        1500
    );

    let Some(CoSPendingTxItem::Local(req)) = cos_queue_pop_front(queue) else {
        panic!("expected first queued local request");
    };
    assert_eq!(req.flow_key.as_ref().map(|flow| flow.src_port), Some(1111));
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 1);
    assert_eq!(test_flow_fair_state(queue).flow_bucket_bytes[bucket_a], 0);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket_b],
        1500
    );
}

/// Pin that `FlowRrRing::remove` correctly de-registers a bucket
/// from an arbitrary position. The MQFQ pop path calls this when
/// a bucket at non-head position (determined by finish-time, not
/// ring order) drains to empty.
#[test]
fn flow_rr_ring_remove_from_middle() {
    let mut ring = FlowRrRing::default();
    ring.push_back(10);
    ring.push_back(20);
    ring.push_back(30);
    ring.push_back(40);
    assert_eq!(ring.len(), 4);

    // Remove from the middle.
    assert!(ring.remove(20));
    assert_eq!(ring.len(), 3);
    let ids: Vec<u16> = ring.iter().collect();
    assert_eq!(ids, vec![10, 30, 40]);

    // Remove head-adjacent.
    assert!(ring.remove(10));
    assert_eq!(ring.len(), 2);
    let ids: Vec<u16> = ring.iter().collect();
    assert_eq!(ids, vec![30, 40]);

    // Remove missing (no-op).
    assert!(!ring.remove(999));
    assert_eq!(ring.len(), 2);

    // Remove tail.
    assert!(ring.remove(40));
    assert_eq!(ring.len(), 1);
    let ids: Vec<u16> = ring.iter().collect();
    assert_eq!(ids, vec![30]);

    // Remove last.
    assert!(ring.remove(30));
    assert_eq!(ring.len(), 0);
    assert!(ring.is_empty());
}

/// Pin the overflow bound on `flow_bucket_{head,tail}_finish_bytes`
/// by driving the ACTUAL runtime field near `u64::MAX` and
/// exercising the real enqueue path through
/// `cos_queue_push_back`/`account_cos_queue_flow_enqueue`.
///
/// Rust reviewer MEDIUM #2 (round-2): the prior revision
/// recomputed the wrap-interval math in the test body and
/// asserted `years_to_wrap > 40`. That is a calculator, not a
/// pin — a regression that narrowed the field to u32, or swapped
/// `saturating_add` for `+`, would have left this test green
/// because the test never touched the field. This revision:
///
///   1. Drives `test_flow_fair_state(queue).queue_vtime` to `u64::MAX - 10_000`.
///   2. Enqueues a 9000-byte packet (MTU-size upper bound).
///   3. Asserts the bucket's head/tail finish DID NOT wrap AND
///      landed at exactly `u64::MAX - 10_000 + 9_000`.
///   4. Enqueues again at u64::MAX-adjacent vtime and asserts
///      the saturating_add path keeps the field bounded.
///
/// A regression that changes the accumulator type to u32,
/// replaces `saturating_add` with `+`, or widens the per-enqueue
/// delta (e.g. by dividing by a small weight) will fail THIS
/// test, not a recomputed calculator.
#[test]
fn mqfq_finish_time_u64_has_decades_of_headroom() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 25_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: 128 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    enable_test_flow_fair(queue);

    // Largest plausible single enqueue: MTU 9000 at weight 1.
    const MAX_SINGLE_DELTA: usize = 9_000;
    const SLACK: u64 = 10_000;
    let near_wrap = u64::MAX - SLACK;

    // Drive the runtime field near wrap by setting queue_vtime
    // (the re-anchor source for idle-bucket enqueue). The first
    // enqueue re-anchors head=tail=max(0, near_wrap)+9000 =
    // near_wrap + 9000 — well within u64 and exactly one delta
    // past queue_vtime.
    test_flow_fair_state_mut(queue).queue_vtime = near_wrap;

    let flow_a = test_session_key(9999, 5201);
    let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));

    cos_queue_push_back(queue, test_flow_cos_item(9999, MAX_SINGLE_DELTA));
    let expected_first = near_wrap + MAX_SINGLE_DELTA as u64;
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        expected_first,
        "first enqueue near u64 wrap must anchor at queue_vtime \
         + bytes; regression to u32 or non-saturating add would \
         fail here with a wrapped or truncated value",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        expected_first,
    );
    assert!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a] > near_wrap,
        "finish time did not advance past pre-enqueue vtime — \
         type narrowed or wrap occurred",
    );

    // Second enqueue onto the ACTIVE bucket: tail advances by
    // MAX_SINGLE_DELTA, but saturating_add caps at u64::MAX.
    // With near_wrap + 2*9000 = u64::MAX - 10_000 + 18_000 =
    // u64::MAX + 8_000 — this SHOULD saturate to u64::MAX.
    cos_queue_push_back(queue, test_flow_cos_item(9999, MAX_SINGLE_DELTA));
    let new_tail = test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a];
    assert!(
        new_tail >= expected_first,
        "tail must monotonically advance; got {} < {}",
        new_tail,
        expected_first,
    );
    assert_eq!(
        new_tail,
        u64::MAX,
        "second enqueue must saturate at u64::MAX (input was \
         near_wrap + 2*9000 > u64::MAX); regression that replaces \
         saturating_add with `+` would panic on overflow in debug \
         builds or wrap in release builds",
    );

    // Head unchanged on active-bucket enqueue (head packet is
    // still the first one).
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        expected_first,
        "active-bucket enqueue must not alter head",
    );

    // Sanity-check the original calculator claim — 40+ years at
    // 100 Gbps — is still true. Kept alongside the real-field
    // pin above; the pin above is what would fail on regression.
    const WRAP_BYTES: u128 = 1u128 << 64;
    let bytes_per_sec: u128 = 100_000_000_000u128 / 8;
    let years_to_wrap = WRAP_BYTES / bytes_per_sec / 60 / 60 / 24 / 365;
    assert!(
        years_to_wrap > 40,
        "u64 finish-time headroom at 100 Gbps should exceed 40 \
         years of uptime, got {} years",
        years_to_wrap,
    );
}

/// #785 Phase 3 — pin that a high-rate exact queue
/// (shared_exact=true) IS promoted onto the flow-fair path AND
/// has its `shared_exact` shadow cached. The shadow drives the
/// admission-gate downgrade (aggregate-only) in
/// `cos_queue_flow_share_limit` and
/// `apply_cos_admission_ecn_policy`. The MQFQ VFT ordering in
/// `cos_queue_pop_front` is what actually enforces per-flow
/// fairness on this queue — the share cap + per-flow ECN arm
/// are rate-unaware (24 KB floor) and would tail-drop TCP at
/// 25 Gbps. Retrospective Attempt A measured 22.3 → 16.3 Gbps +
/// 25 k retrans when the cap was enforced on shared_exact;
/// Phase 3 replaces the cap's fairness role with VFT ordering.
#[test]
fn queue_flow_fair_enabled_on_shared_exact() {
    use crate::afxdp::worker::COS_SHARED_EXACT_MIN_RATE_BYTES;

    let high_rate_bytes = 25_000_000_000u64 / 8;
    assert!(
        high_rate_bytes >= COS_SHARED_EXACT_MIN_RATE_BYTES,
        "fixture must be above the shared_exact threshold or the \
         test does not exercise the regression surface",
    );

    let mut runtime = test_cos_runtime_with_queues(
        100_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: high_rate_bytes,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: 128 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    assert!(!runtime.queues[0].flow_fair());
    assert!(!runtime.queues[0].shared_exact());

    // Drive the full ensure_cos_interface_runtime promotion loop.
    let fast_path = vec![test_queue_fast_path_for_promotion(true)];
    apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path, 0);

    assert!(
        runtime.queues[0].flow_fair(),
        "#785 Phase 3: shared_exact queue MUST be promoted onto \
         the flow-fair path so MQFQ virtual-finish-time ordering \
         runs in the dequeue path. Regression here re-opens the \
         CoV gap we just measured closed.",
    );
    assert!(
        runtime.queues[0].shared_exact(),
        "#785 Phase 3: shared_exact shadow MUST be cached onto \
         the runtime so the admission gates in \
         cos_queue_flow_share_limit and \
         apply_cos_admission_ecn_policy downgrade to \
         aggregate-only. Per-flow admission gates are rate-\
         unaware (24 KB floor) and would tail-drop TCP at \
         multi-Gbps per-flow rates.",
    );
    assert_ne!(
        test_flow_fair_state(&runtime.queues[0]).flow_hash_seed,
        0,
        "seed must be drawn on flow-fair promotion so MQFQ \
         bucket assignment is not an externally-probeable \
         pure function of the 5-tuple",
    );
}

/// Pin that a low-rate exact queue (shared_exact=false) IS
/// promoted onto the SFQ path AND has `shared_exact=false` on
/// its runtime. The #784 fairness fix on the 1 Gbps iperf-a
/// queue depends on BOTH halves: flow_fair=true so DRR orders
/// per-flow, and shared_exact=false so the per-flow share cap
/// + per-flow ECN arm still run (at 1 Gbps / 12 flows the cap is
/// ~24 KB which matches TCP cwnd at 77 Mbps flows cleanly).
#[test]
fn queue_flow_fair_enabled_on_owner_local_exact() {
    use crate::afxdp::worker::COS_SHARED_EXACT_MIN_RATE_BYTES;

    let low_rate_bytes = 1_000_000_000u64 / 8;
    assert!(
        low_rate_bytes < COS_SHARED_EXACT_MIN_RATE_BYTES,
        "fixture must be below the shared_exact threshold to \
         exercise the owner-local-exact path",
    );

    let mut runtime = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: low_rate_bytes,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: 128 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let fast_path = vec![test_queue_fast_path_for_promotion(false)];
    apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path, 0);

    assert!(
        runtime.queues[0].flow_fair(),
        "owner-local-exact queue MUST be promoted onto the SFQ \
         path — #784 fairness fix depends on it",
    );
    assert!(
        !runtime.queues[0].shared_exact(),
        "owner-local-exact queue MUST keep shared_exact=false so \
         the per-flow share cap and per-flow ECN arm continue to \
         run — #784 depends on the per-flow cap firing at 1 Gbps",
    );
    assert_ne!(
        test_flow_fair_state(&runtime.queues[0]).flow_hash_seed,
        0,
        "seed must be drawn on flow-fair promotion — otherwise \
         every binding hashes flows identically and one flow's \
         RSS bucket collides across the whole deployment",
    );
}

/// Pin that a non-exact (best-effort) queue is NOT promoted onto
/// the flow-fair path. SFQ would be wasted work on these queues:
/// there is no per-flow rate contract, so per-flow isolation is
/// meaningless, and drawing an OS random seed for every
/// non-exact queue on every runtime build would add a syscall
/// per queue for zero benefit. This pin also doubles as a sanity
/// check that the gate did not collapse to
/// `queue.flow_fair = true` unconditionally.
#[test]
fn queue_flow_fair_disabled_on_non_exact() {
    let mut runtime = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 3,
            transmit_rate_bytes: 0,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: 128 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );

    // Drive the production loop with shared_exact=false first,
    // then again with shared_exact=true — both MUST leave a
    // non-exact queue off the flow-fair path, because the gate's
    // LHS (`queue.exact`) fails regardless of the fast-path bit.
    let fast_path_owner_local = vec![test_queue_fast_path_for_promotion(false)];
    apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path_owner_local, 0);
    assert!(
        !runtime.queues[0].flow_fair(),
        "non-exact queues must stay off the flow-fair path: SFQ \
         has no rate contract to enforce there, and draws an OS \
         random seed per queue",
    );

    let fast_path_shared = vec![test_queue_fast_path_for_promotion(true)];
    apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path_shared, 0);
    assert!(
        !runtime.queues[0].flow_fair(),
        "non-exact queues must stay off the flow-fair path \
         regardless of the shared_exact signal",
    );
}

// ---------------------------------------------------------------------
// #698 — per-worker exact-drain micro-bench
//
// Home: this file (`cos/queue_ops.rs`) rather than
// `cos/queue_service.rs`. The benches DO call drain_exact_local_*
// / settle_exact_local_* (which live in `cos/queue_service.rs`),
// but the steady-state cost they measure is dominated by the
// queue-side machinery owned here: V-min publish/consume slot
// bookkeeping, MQFQ pop snapshot/rollback, queue-vtime updates.
// Colocated with the queue_ops V-min + MQFQ unit-test suite so a
// future microarch tweak to either subsystem can be validated
// against the perf signal in the same file.
//
// Purpose: establish an in-tree, reproducible measurement of the
// userspace drain-path cost per packet. The value of
// `COS_SHARED_EXACT_MIN_RATE_BYTES` (2.5 Gbps) is cited in commit
// history as "the single-worker sustained exact throughput ceiling";
// before this harness existed there was no checked-in data supporting
// that number.
//
// Scope (what this measures):
//   - `drain_exact_local_fifo_items_to_scratch`
//       VecDeque indexed read, pattern match, free-frame pop, UMEM
//       `slice_mut_unchecked` + `copy_from_slice` (the 1500-byte
//       memcpy that dominates `memmove` in the live profile),
//       scratch Vec push, running root/secondary budget decrement.
//   - `settle_exact_local_fifo_submission`
//       queue.hot.items.pop_front per sent packet, scratch Vec pop.
//   - Re-prime between iterations — simulates a steady inflow of
//       new items from the upstream CoS enqueue path.
//
// Scope (what this does NOT measure):
//   - TX ring insert + commit (no XDP socket in unit tests; this
//     is a ring-buffer write + release store on the producer index,
//     ~20 ns combined on x86-64, amortized away at TX_BATCH_SIZE).
//   - The `sendto()` syscall used for kernel TX wakeup (amortized
//     over TX_BATCH_SIZE packets — ~2–4 ns per packet at the
//     pre-#920 batch of 256; ~10–15 ns per packet at the new
//     batch of 64).
//   - Completion ring reap (`reap_tx_completions`) — ~20–50 ns per
//     completion, mostly ring-buffer read + VecDeque push-back.
//   - All non-drain per-worker cost: RX, forwarding, NAT, session
//     lookup, conntrack. Measured in the live cluster profile, not
//     here. Those costs dominate in production and are the real
//     gate on per-worker aggregate throughput.
//
// What this tells us about the MIN constant:
//   - If drain-path Gbps is >> 2.5 Gbps, the constant is NOT gated
//     by drain speed. MIN reflects "what's left after RX + forward
//     + NAT consume 80%+ of the per-worker budget" — consistent
//     with the PR #680 collapse shape where the drain loop couldn't
//     absorb aggregate line-rate because of *other* per-packet work.
//   - If drain-path Gbps is < 2.5 Gbps, MIN is provably too high
//     and must drop. (Unlikely — drain is tightly bounded by a
//     1500-byte memcpy and a few VecDeque ops.)
//
// Running (release is mandatory — debug build numbers are not
// meaningful for this baseline):
//   cargo test --release --manifest-path userspace-dp/Cargo.toml \
//       cos_exact_drain_throughput_micro_bench -- --ignored --nocapture
//
// The bench reports two separate timings:
//   - "drain+settle (measured)" — the inner loop only. Setup work
//     (VecDeque priming, packet cloning, free-frame pool rebuild)
//     is excluded.
//   - "setup (per batch, unmeasured)" — setup cost printed for
//     reference so future changes to the setup path are visible.
//
// Hardware and noise: numbers depend on the box's core frequency
// and L1/L2 cache state. Run on quiet hardware; the published
// baseline in this commit's message was captured under those
// conditions. A repeat run after a refactor should stay within
// ~15% of the baseline on the same host — larger deltas warrant
// investigation. A single development-host measurement does NOT
// validate the MIN constant on other deployment hardware; it only
// rules out the inner drain loop as the limiter on this host.
// ---------------------------------------------------------------------
#[test]
#[ignore]
fn cos_exact_drain_throughput_micro_bench() {
    use std::time::Instant;

    // Single source of truth — `worker::COS_SHARED_EXACT_MIN_RATE_BYTES`
    // is `pub(super)` so the bench asserts against the production
    // constant directly rather than carrying a mirror that could drift.
    use crate::afxdp::worker::COS_SHARED_EXACT_MIN_RATE_BYTES;
    const PACKET_LEN: usize = 1500;
    const BATCHES: usize = 10_000;
    // Each drain call takes TX_BATCH_SIZE items. Prime enough items
    // for one batch; after each iteration we repopulate the queue
    // and free-frame pool so the measurement reflects steady state,
    // not a cold-start transient.
    const ITEMS_PER_BATCH: usize = TX_BATCH_SIZE;

    // UMEM: 2 MB is the hugepage-aligned minimum in MmapArea. That
    // fits TX_BATCH_SIZE * 4096 = 1 MB of frame slots with headroom.
    let area = MmapArea::new(2 * 1024 * 1024).expect("mmap umem");

    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.tokens = u64::MAX;
    root.queues[0].hot.tokens = u64::MAX;
    root.queues[0].hot.runnable = true;

    let packet_bytes = vec![0xABu8; PACKET_LEN];
    let mut scratch = Vec::with_capacity(ITEMS_PER_BATCH);
    let mut free_frames: VecDeque<u64> = (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();

    // Prime: one full batch of items. Each iteration below drains
    // them all and then re-primes both the items and the free frames
    // to the same initial state.
    let prime_queue = |queue: &mut CoSQueueRuntime, packet: &[u8]| {
        queue.hot.items.clear();
        queue.hot.queued_bytes = 0;
        for _ in 0..ITEMS_PER_BATCH {
            queue
                .hot
                .items
                .push_back(CoSPendingTxItem::Local(TxRequest {
                    bytes: packet.to_vec(),
                    expected_ports: None,
                    expected_addr_family: libc::AF_INET as u8,
                    expected_protocol: PROTO_TCP,
                    flow_key: None,
                    egress_ifindex: 80,
                    cos_queue_id: Some(5),
                    dscp_rewrite: None,
                    mirror_clone: false,
                    enqueue_ns: 0,
                }));
            queue.hot.queued_bytes += packet.len() as u64;
        }
    };

    // Warmup: 1000 batches to settle caches and branch predictors.
    for _ in 0..1000 {
        prime_queue(&mut root.queues[0], &packet_bytes);
        scratch.clear();
        free_frames = (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();
        let build = drain_exact_local_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut free_frames,
            &mut scratch,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        let inserted = scratch.len();
        settle_exact_local_fifo_submission(
            Some(&mut root.queues[0]),
            &mut free_frames,
            &mut scratch,
            inserted,
        );
    }

    // Measurement. Setup (priming, packet cloning, free-frame pool
    // rebuild) happens outside the `iter_start.elapsed()` window so
    // the reported ns/packet reflects only drain+settle. Setup cost
    // is separately accumulated and printed for reference.
    use std::time::Duration;
    let mut measured = Duration::ZERO;
    let mut setup_time = Duration::ZERO;
    let mut total_packets = 0u64;
    let mut total_bytes = 0u64;
    for _ in 0..BATCHES {
        let setup_start = Instant::now();
        prime_queue(&mut root.queues[0], &packet_bytes);
        scratch.clear();
        free_frames.clear();
        free_frames.extend((0..ITEMS_PER_BATCH as u64).map(|i| i * 4096));
        setup_time += setup_start.elapsed();

        let iter_start = Instant::now();
        let build = drain_exact_local_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut free_frames,
            &mut scratch,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );
        let inserted = scratch.len();
        let (sent_pkts, sent_bytes) = settle_exact_local_fifo_submission(
            Some(&mut root.queues[0]),
            &mut free_frames,
            &mut scratch,
            inserted,
        );
        measured += iter_start.elapsed();

        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        total_packets += sent_pkts;
        total_bytes += sent_bytes;
    }

    let ns_per_packet = measured.as_nanos() as f64 / total_packets as f64;
    let mpps = total_packets as f64 / measured.as_secs_f64() / 1.0e6;
    let gbps = (total_bytes as f64 * 8.0) / measured.as_secs_f64() / 1.0e9;
    let setup_ns_per_packet = setup_time.as_nanos() as f64 / total_packets as f64;

    eprintln!(
        "\n=== #698 exact-drain userspace micro-bench ===\n\
         packet len              : {} B\n\
         batches                 : {}\n\
         packets per batch       : {}\n\
         total packets           : {}\n\
         total bytes             : {} ({:.2} MB)\n\
         drain+settle (measured) : {:?}\n\
         setup (per batch, unmeasured): {:?}\n\
         ns/packet (drain+settle): {:.2}\n\
         ns/packet (setup only)  : {:.2}\n\
         throughput (pps)        : {:.3} Mpps\n\
         throughput (line rate)  : {:.3} Gbps\n\
         min-constant gate       : {:.3} Gbps (COS_SHARED_EXACT_MIN_RATE_BYTES)\n\
         verdict (this host)     : {}\n\
         scope note              : userspace drain path only; excludes TX\n\
                                   ring insert/commit, kernel wakeup, and\n\
                                   completion ring reap. Single-host number\n\
                                   only — does not validate MIN on other\n\
                                   deployment hardware.\n\
         ================================================\n",
        PACKET_LEN,
        BATCHES,
        ITEMS_PER_BATCH,
        total_packets,
        total_bytes,
        total_bytes as f64 / (1024.0 * 1024.0),
        measured,
        setup_time,
        ns_per_packet,
        setup_ns_per_packet,
        mpps,
        gbps,
        (COS_SHARED_EXACT_MIN_RATE_BYTES * 8) as f64 / 1.0e9,
        if gbps > (COS_SHARED_EXACT_MIN_RATE_BYTES * 8) as f64 / 1.0e9 {
            "drain alone exceeds MIN on this host — rules out drain as \
             the immediate limiter here"
        } else {
            "drain alone below MIN on this host — constant is TOO HIGH, \
             lower it and re-validate live"
        },
    );

    assert!(
        total_packets as usize == BATCHES * ITEMS_PER_BATCH,
        "every batch must fully drain: {} != {}",
        total_packets,
        BATCHES * ITEMS_PER_BATCH
    );
}

// ---------------------------------------------------------------------
// #940 microbenchmark: pop + commit + settle + publish
//
// Per Gemini adversarial review: measure the FULL pop+commit+settle
// cycle so we capture the publish cost relocation (publish moved
// from pop time to post-settle).
//
// Run: cargo test --release -p xpf-userspace-dp -- bench_pop_commit_settle_publish --nocapture --ignored
// ---------------------------------------------------------------------
#[test]
#[ignore]
fn bench_pop_commit_settle_publish() {
    use std::time::Instant;
    const PACKET_LEN: usize = 1500;
    const BATCHES: usize = 10_000;
    const ITEMS_PER_BATCH: usize = TX_BATCH_SIZE;

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
            surplus_weight: 1,
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.tokens = u64::MAX;
    // Promote to flow_fair + shared_exact + attach floor to
    // exercise the V_min publish path.
    let queue = &mut root.queues[0];
    queue.hot.tokens = u64::MAX;
    enable_test_flow_fair(queue);
    queue.config.exact = true;
    queue.config.shared_exact = true;
    let _floor = attach_test_vtime_floor(queue, 4, 0);
    queue.hot.runnable = true;

    let area = MmapArea::new(2 * 1024 * 1024).expect("mmap umem");
    let packet_bytes = vec![0xABu8; PACKET_LEN];
    let mut scratch: Vec<(u64, TxRequest)> = Vec::with_capacity(ITEMS_PER_BATCH);
    let mut free_frames: VecDeque<u64> = (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();

    let prime_queue = |queue: &mut CoSQueueRuntime, packet: &[u8]| {
        queue.hot.items.clear();
        queue.hot.queued_bytes = 0;
        test_flow_fair_state_mut(queue).queue_vtime = 0;
        test_flow_fair_state_mut(queue).flow_bucket_bytes = [0; COS_FLOW_FAIR_BUCKETS];
        test_flow_fair_state_mut(queue).flow_bucket_head_finish_bytes = [0; COS_FLOW_FAIR_BUCKETS];
        test_flow_fair_state_mut(queue).flow_bucket_tail_finish_bytes = [0; COS_FLOW_FAIR_BUCKETS];
        test_flow_fair_state_mut(queue).flow_rr_buckets = FlowRrRing::default();
        test_flow_fair_state_mut(queue).flow_bucket_items =
            std::array::from_fn(|_| VecDeque::new());
        test_flow_fair_state_mut(queue).active_flow_buckets = 0;
        queue.hot.local_item_count = 0;
        test_flow_fair_state_mut(queue).pop_snapshot_stack.clear();
        for i in 0..ITEMS_PER_BATCH {
            let mut req = TxRequest {
                bytes: packet.to_vec(),
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: Some(test_session_key((1000 + i) as u16, 5201)),
                egress_ifindex: 80,
                cos_queue_id: Some(0),
                dscp_rewrite: None,
                mirror_clone: false,
                enqueue_ns: 0,
            };
            let _ = req.bytes.len();
            cos_queue_push_back(queue, CoSPendingTxItem::Local(req));
        }
    };

    // Warmup.
    for _ in 0..1000 {
        prime_queue(&mut root.queues[0], &packet_bytes);
        scratch.clear();
        free_frames = (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();
        let _ = drain_exact_local_items_to_scratch_flow_fair(
            &mut root.queues[0],
            &mut free_frames,
            &mut scratch,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );
        let inserted = scratch.len();
        settle_exact_local_scratch_submission_flow_fair(
            Some(&mut root.queues[0]),
            &mut free_frames,
            &mut scratch,
            inserted,
            0, // now_ns: tests don't depend on EWMA accounting
        );
        publish_committed_queue_vtime(Some(&root.queues[0]));
    }

    let mut measured = std::time::Duration::ZERO;
    let mut total_packets = 0u64;
    for _ in 0..BATCHES {
        prime_queue(&mut root.queues[0], &packet_bytes);
        scratch.clear();
        free_frames.clear();
        free_frames.extend((0..ITEMS_PER_BATCH as u64).map(|i| i * 4096));

        let iter_start = Instant::now();
        let _ = drain_exact_local_items_to_scratch_flow_fair(
            &mut root.queues[0],
            &mut free_frames,
            &mut scratch,
            &area,
            u64::MAX,
            u64::MAX,
            None,
        );
        let inserted = scratch.len();
        settle_exact_local_scratch_submission_flow_fair(
            Some(&mut root.queues[0]),
            &mut free_frames,
            &mut scratch,
            inserted,
            0, // now_ns: tests don't depend on EWMA accounting
        );
        publish_committed_queue_vtime(Some(&root.queues[0]));
        measured += iter_start.elapsed();
        total_packets += inserted as u64;
    }

    let ns_per_pkt = measured.as_nanos() as f64 / total_packets as f64;
    eprintln!(
        "bench_pop_commit_settle_publish: {} packets in {:?} = {:.1} ns/pkt",
        total_packets, measured, ns_per_pkt
    );
}

// ===================================================================
// #1735: lazy MQFQ generalization to non-exact shaped queues.
//
// These pin the four pieces of the design: (1) flow_fair() == is_some();
// (2) eligibility; (3) the hash-free front-key contention probe with
// single-flow-stays-FIFO + promote-on-first-differing-flow + correct
// migration; (4) lazy demotion with hysteresis. Plus a best-effort
// elephant-vs-mice per-flow fairness acceptance test (the headline gate
// proxy at unit scale).
// ===================================================================

/// Build a single NON-exact shaped queue and mark it
/// `flow_fair_eligible` (as `promote_cos_queue_flow_fair` would for any
/// queue reaching it on an interface with a CoSInterfaceRuntime). It
/// starts with `flow_fair_state == None` — the lazy-promotion subject.
fn test_nonexact_eligible_root() -> CoSInterfaceRuntime {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 4,
            transmit_rate_bytes: 1_000_000_000 / 8,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: 1024 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    root.queues[0].config.flow_fair_eligible = true;
    root
}

#[test]
fn flow_fair_gate_is_state_is_some_not_config() {
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    // Eligible but unpromoted: flow_fair() must be FALSE.
    assert!(queue.config.flow_fair_eligible);
    assert!(queue.flow_fair_state.is_none());
    assert!(!queue.flow_fair(), "None state must gate as non-flow-fair");
    // Allocate state directly: flow_fair() flips true with no config touch.
    enable_test_flow_fair(queue);
    assert!(queue.flow_fair());
    disable_test_flow_fair(queue);
    assert!(!queue.flow_fair());
}

#[test]
fn best_effort_single_flow_never_promotes() {
    // The #1183 fast-path guard: a single-flow best-effort queue stays
    // FIFO (flow_fair_state == None) no matter how many packets arrive.
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    for _ in 0..64 {
        cos_queue_push_back(queue, test_flow_cos_item(40000, 1500));
    }
    assert!(
        queue.flow_fair_state.is_none(),
        "single-flow best-effort must NOT promote (no hash, no FlowFairState)"
    );
    assert_eq!(queue.hot.items.len(), 64, "items stay in the FIFO");
    assert_eq!(queue.hot.local_item_count, 64);
}

#[test]
fn best_effort_keyless_traffic_never_promotes() {
    // Keyless items (flow_key == None) compare equal under the probe
    // (None == None) and must NOT promote — matches today's bucket-0
    // semantics and avoids promoting on keyless noise.
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    for _ in 0..16 {
        cos_queue_push_back(queue, test_cos_item(1500));
    }
    assert!(queue.flow_fair_state.is_none());
    assert_eq!(queue.hot.items.len(), 16);
}

#[test]
fn best_effort_promotes_on_first_differing_flow_with_correct_migration() {
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    // Three packets of flow A (src_port 100) — stays FIFO.
    for _ in 0..3 {
        cos_queue_push_back(queue, test_flow_cos_item(100, 1500));
    }
    assert!(queue.flow_fair_state.is_none(), "single flow stays FIFO");
    let total_a = 3 * 1500u64;
    // First packet of flow B (src_port 200) — triggers promotion.
    cos_queue_push_back(queue, test_flow_cos_item(200, 1000));
    assert!(queue.flow_fair_state.is_some(), "second flow promotes");
    let ff = test_flow_fair_state(queue);
    // Collision-aware: the OS-seeded hash MAY (rarely) collide flow A and
    // flow B into the same 4096-bucket slot. Derive the expected bucket
    // layout from the ACTUAL runtime seed so the assertions are
    // deterministic regardless of collision (Copilot review).
    let seed = ff.flow_hash_seed;
    let bucket_a = cos_flow_bucket_index(seed, Some(&test_session_key(100, 5201)));
    let bucket_b = cos_flow_bucket_index(seed, Some(&test_session_key(200, 5201)));
    if bucket_a == bucket_b {
        // Hash collision: both flows share one bucket. Bytes accumulate
        // there; one active bucket. (Migration + accounting still correct.)
        assert_eq!(ff.active_flow_buckets, 1, "collision: single shared bucket");
        assert_eq!(
            ff.flow_bucket_bytes[bucket_a],
            total_a + 1000,
            "collision: A+B bytes share the bucket, none lost"
        );
    } else {
        assert_eq!(ff.active_flow_buckets, 2, "A and B each in their own bucket");
        assert_eq!(ff.flow_bucket_bytes[bucket_a], total_a, "migrated A bytes intact");
        assert_eq!(ff.flow_bucket_bytes[bucket_b], 1000, "B accounted once");
    }
    // FIFO is drained into buckets; local_item_count nets to all 4 items.
    assert!(queue.hot.items.is_empty(), "FIFO emptied by migration");
    assert_eq!(queue.hot.local_item_count, 4, "no double-count / loss");
    // No v8 lease / V_min on a non-exact queue.
    assert!(queue.queue_lease_v8.is_none());
    assert!(queue.v_min.vtime_floor.is_none());
}

#[test]
fn promoted_best_effort_pops_in_mqfq_interleave_not_fifo_bursts() {
    // Elephant (flow A, many packets) interleaved with a mouse (flow B,
    // one packet) must NOT drain A,A,...,A,B (FIFO) — MQFQ gives the
    // mouse a fair turn near the front.
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    for _ in 0..8 {
        cos_queue_push_back(queue, test_flow_cos_item(100, 1500)); // elephant A
    }
    cos_queue_push_back(queue, test_flow_cos_item(200, 1500)); // mouse B (promotes)
    assert!(queue.flow_fair());
    let seed = test_flow_fair_state(queue).flow_hash_seed;
    let bucket_e = cos_flow_bucket_index(seed, Some(&test_session_key(100, 5201)));
    let bucket_m = cos_flow_bucket_index(seed, Some(&test_session_key(200, 5201)));
    // Pop everything; record the flow of each popped item by src_port.
    let mut order = Vec::new();
    while let Some(item) = cos_queue_pop_front(queue) {
        let port = cos_item_flow_key(&item).map(|k| k.src_port).unwrap_or(0);
        order.push(port);
    }
    assert_eq!(order.len(), 9);
    if bucket_e == bucket_m {
        // Rare hash collision: both flows share one bucket, so MQFQ
        // degenerates to FIFO within it and the mouse (enqueued last) is
        // legitimately last. The cross-flow interleave property only
        // applies to distinct buckets; nothing to assert here.
        return;
    }
    // Distinct buckets: the mouse (200) must appear before the LAST
    // elephant packet — a pure FIFO would put it dead last. MQFQ
    // frontends it.
    let mouse_pos = order.iter().position(|&p| p == 200).unwrap();
    assert!(
        mouse_pos < order.len() - 1,
        "mouse must not be starved to the FIFO tail; order = {:?}",
        order
    );
}

#[test]
fn best_effort_elephant_vs_mice_per_flow_fairness() {
    // Headline acceptance proxy: 1 elephant (200 pkts) + 4 mice (1 pkt
    // each) on a shaped best-effort queue. After promotion, assert each
    // mouse is admitted to its own bucket and none is starved — per-flow
    // max/min bucket occupancy is bounded, not elephant-dominated.
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    // Mice first so the elephant arriving second triggers promotion and
    // each mouse gets its own bucket.
    for port in [301u16, 302, 303, 304] {
        cos_queue_push_back(queue, test_flow_cos_item(port, 1500));
    }
    // The 4 mice are 4 distinct flows; the 2nd one already promoted.
    assert!(queue.flow_fair());
    for _ in 0..200 {
        cos_queue_push_back(queue, test_flow_cos_item(999, 1500)); // elephant
    }
    let ff = test_flow_fair_state(queue);
    // Collision-aware (Copilot review): with 4096 buckets the 5 flows
    // MAY (rarely) collide. Derive the distinct-bucket set under the
    // ACTUAL runtime seed and assert against THAT, so the test is
    // deterministic regardless of collision. The fairness property —
    // the first MQFQ round touches every DISTINCT bucket (no flow
    // starved behind the elephant) — holds either way.
    let seed = ff.flow_hash_seed;
    let mut distinct_buckets = std::collections::HashSet::new();
    for port in [301u16, 302, 303, 304, 999] {
        distinct_buckets.insert(cos_flow_bucket_index(seed, Some(&test_session_key(port, 5201))));
    }
    let n_buckets = distinct_buckets.len();
    assert_eq!(
        usize::from(ff.active_flow_buckets),
        n_buckets,
        "active_flow_buckets must equal the distinct-bucket count under the seed"
    );
    // Pop the first `n_buckets` items and assert each touches a distinct
    // bucket — the first MQFQ round visits every active flow's bucket
    // rather than draining the elephant wholesale (no starvation).
    let mut seen_buckets = std::collections::HashSet::new();
    for _ in 0..n_buckets {
        let item = cos_queue_pop_front(queue).expect("item");
        let b = cos_flow_bucket_index(seed, cos_item_flow_key(&item));
        seen_buckets.insert(b);
    }
    assert_eq!(
        seen_buckets.len(),
        n_buckets,
        "first MQFQ round must touch every active bucket (no flow starved); saw {:?}",
        seen_buckets
    );
}

#[test]
fn lazy_demotion_after_hysteresis_on_drained_nonexact_queue() {
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    // Promote via two flows, then fully drain.
    cos_queue_push_back(queue, test_flow_cos_item(100, 1500));
    cos_queue_push_back(queue, test_flow_cos_item(200, 1500));
    assert!(queue.flow_fair());
    while cos_queue_pop_front(queue).is_some() {}
    queue.hot.queued_bytes = 0;
    // Each quiescent settle bumps the counter; demote only at threshold.
    for i in 1..COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS {
        maybe_demote_drained_best_effort(queue);
        assert!(
            queue.flow_fair_state.is_some(),
            "must not demote before hysteresis (settle {i})"
        );
    }
    maybe_demote_drained_best_effort(queue);
    assert!(
        queue.flow_fair_state.is_none(),
        "demotes once hysteresis reached; FlowFairState box dropped"
    );
    assert_eq!(queue.hot.cos_demote_empty_settles, 0);
}

#[test]
fn demotion_hysteresis_resets_on_nonquiescent_settle() {
    // A queue oscillating between drained and busy must NOT demote.
    let mut root = test_nonexact_eligible_root();
    let queue = &mut root.queues[0];
    cos_queue_push_back(queue, test_flow_cos_item(100, 1500));
    cos_queue_push_back(queue, test_flow_cos_item(200, 1500));
    assert!(queue.flow_fair());
    for _ in 0..(COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS as usize + 2) {
        // Drain, observe a couple empty settles...
        while cos_queue_pop_front(queue).is_some() {}
        queue.hot.queued_bytes = 0;
        maybe_demote_drained_best_effort(queue);
        // ...then a new burst arrives BEFORE the threshold (non-quiescent
        // settle resets the counter).
        cos_queue_push_back(queue, test_flow_cos_item(100, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(200, 1500));
        maybe_demote_drained_best_effort(queue); // non-quiescent -> reset
        assert!(
            queue.flow_fair_state.is_some(),
            "oscillating 1<->2 flow queue must not thrash-demote"
        );
    }
}

#[test]
fn exact_queue_never_demotes() {
    // Exact queues promote eagerly and must stay promoted through full
    // drain (V_min / v8-lease coordination assumes stable state).
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-a".into(),
            priority: 4,
            transmit_rate_bytes: 1_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            surplus_weight: 1,
            buffer_bytes: 1024 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    queue.config.flow_fair_eligible = true;
    enable_test_flow_fair(queue);
    assert!(queue.flow_fair());
    for _ in 0..(COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS as usize + 4) {
        queue.hot.queued_bytes = 0;
        maybe_demote_drained_best_effort(queue);
    }
    assert!(
        queue.flow_fair_state.is_some(),
        "exact queue must never demote (stable flow_fair_state)"
    );
}
