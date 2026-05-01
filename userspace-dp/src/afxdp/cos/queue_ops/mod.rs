// CoS queue primitives: accessors, enqueue/dequeue, MQFQ ordering
// bookkeeping, V-min slot lifecycle. Per-byte hot-path fns carry
// `#[inline]` to preserve cross-module inlining at the
// `pub(in crate::afxdp)` boundary.

use std::collections::VecDeque;

use crate::afxdp::types::{
    CoSPendingTxItem, CoSQueuePopSnapshot, CoSQueueRuntime,
};
use crate::afxdp::TX_BATCH_SIZE;
use crate::session::SessionKey;

use super::flow_hash::{cos_flow_bucket_index, cos_item_flow_key};

// #1034 P1: MQFQ V_min coordination split into a sibling submodule.
mod v_min;
pub(in crate::afxdp) use v_min::{
    cos_queue_v_min_consume_suspension, cos_queue_v_min_continue,
    publish_committed_queue_vtime,
};

// #1034 P2: flow accounting + drain orchestration split into siblings.
mod accounting;
mod drain;
use accounting::{account_cos_queue_flow_dequeue, account_cos_queue_flow_enqueue};
pub(in crate::afxdp) use drain::{
    cos_queue_clear_orphan_snapshot_after_drop, cos_queue_drain_all, cos_queue_restore_front,
};

// #1034 P3: push + pop ops split into siblings.
mod pop;
mod push;
pub(in crate::afxdp) use pop::{cos_queue_pop_front, cos_queue_pop_front_no_snapshot};
pub(in crate::afxdp) use push::{cos_queue_push_back, cos_queue_push_front};



#[inline]
pub(in crate::afxdp) fn cos_queue_is_empty(queue: &CoSQueueRuntime) -> bool {
    if !queue.flow_fair {
        return queue.items.is_empty();
    }
    queue.flow_rr_buckets.is_empty()
}

#[inline]
pub(in crate::afxdp) fn cos_queue_len(queue: &CoSQueueRuntime) -> usize {
    if !queue.flow_fair {
        return queue.items.len();
    }
    queue
        .flow_rr_buckets
        .iter()
        .map(|bucket| queue.flow_bucket_items[usize::from(bucket)].len())
        .sum()
}

/// #785 Phase 3 — find the flow bucket whose HEAD packet has the
/// smallest MQFQ virtual-finish-time among the currently active
/// set. The head-packet's finish (not the tail) is the correct
/// selection key: drains pop from the head, so that's the packet
/// whose ordering actually matters.
///
/// Linear scan over the active ring. Size bound: `active_flow_buckets
/// <= COS_FLOW_FAIR_BUCKETS = 1024`, typical workloads 2-16. At 12
/// active buckets this is 12 × (u64 load + compare) ≈ 20 ns — well
/// below NAPI batch pacing.
///
/// If we ever profile this as hot (e.g. with thousands of active
/// flows on a single queue), the replacement is a min-heap keyed by
/// `flow_bucket_head_finish_bytes`. For iperf3-sized workloads the
/// linear scan is cache-friendlier and simpler.
#[inline]
fn cos_queue_min_finish_bucket(queue: &CoSQueueRuntime) -> Option<u16> {
    let mut best: Option<u16> = None;
    let mut best_finish = u64::MAX;
    for bucket in queue.flow_rr_buckets.iter() {
        let finish = queue.flow_bucket_head_finish_bytes[usize::from(bucket)];
        if finish < best_finish {
            best_finish = finish;
            best = Some(bucket);
        }
    }
    best
}

#[inline]
pub(in crate::afxdp) fn cos_queue_front(queue: &CoSQueueRuntime) -> Option<&CoSPendingTxItem> {
    if !queue.flow_fair {
        return queue.items.front();
    }
    // #785 Phase 3 — MQFQ: return the head of the bucket with the
    // smallest virtual-finish-time, not the DRR-rotation head. This
    // is the byte-rate-fair dequeue order (classical SFQ / WFQ).
    let bucket = usize::from(cos_queue_min_finish_bucket(queue)?);
    queue.flow_bucket_items[bucket].front()
}










/// #917 — V_min sync throttle decision. Plan §3.3 v2 cadence:
/// K=8 + mandatory check at drain-batch start (`pop_count == 1`).
const V_MIN_READ_CADENCE: u32 = 8;

/// #917 — per-flow drift budget that V_min sync tolerates before
/// throttling the fast worker. Plan §3.5: `per_worker_rate × 1 ms`.
const V_MIN_LAG_THRESHOLD_NS: u64 = 1_000_000;

/// Floor for the lag budget so the throttle never fires below the
/// minimum forward-progress unit (~16 MTU at 1500 B = 24 KB).
const V_MIN_MIN_LAG_BYTES: u64 = 24_000;


/// #941 Work item D — hard-cap escape hatch constants.
pub(in crate::afxdp) const V_MIN_CONSECUTIVE_SKIP_HARD_CAP: u32 = 8;

/// #941 Work item D — N drain calls of V_min suspension after a
/// hard-cap activation. At ~5 K successful drain invocations/sec
/// under load, N=1000 ≈ 200 ms suspension window — long enough for
/// peers to either catch up or visibly persist as out-of-band, and
/// short enough that mouse-latency budgets (#905) are unaffected.
pub(in crate::afxdp) const V_MIN_SUSPENSION_BATCHES: u32 = 1000;



#[inline]
pub(in crate::afxdp) fn cos_item_len(item: &CoSPendingTxItem) -> u64 {
    match item {
        CoSPendingTxItem::Local(req) => req.bytes.len() as u64,
        CoSPendingTxItem::Prepared(req) => req.len as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::afxdp::tx::test_support::*;
    use crate::afxdp::PROTO_TCP;
    use crate::afxdp::tx_frame_capacity;
    use crate::afxdp::cos::queue_service::ExactCoSScratchBuild;
    use crate::afxdp::types::{COS_FLOW_FAIR_BUCKETS, CoSQueueConfig, FastMap, FlowRrRing, PreparedTxRecycle, PreparedTxRequest, TxRequest};
    use crate::afxdp::umem::MmapArea;
    use crate::afxdp::cos::token_bucket::COS_MIN_BURST_BYTES;
    use crate::afxdp::cos::admission::{apply_cos_queue_flow_fair_promotion, cos_flow_aware_buffer_limit, cos_queue_flow_share_limit};
    use crate::afxdp::cos::queue_service::{drain_exact_local_fifo_items_to_scratch, drain_exact_local_items_to_scratch_flow_fair, drain_exact_prepared_fifo_items_to_scratch, drain_exact_prepared_items_to_scratch_flow_fair, settle_exact_local_fifo_submission, settle_exact_local_scratch_submission_flow_fair, settle_exact_prepared_fifo_submission};
    use crate::afxdp::tx::cos_classify::{cos_queue_accepts_prepared, demote_prepared_cos_queue_to_local};

    #[test]
    fn cos_queue_rejects_prepared_once_local_items_enter_queue() {
        let mut root = test_cos_runtime_with_queues(
            10_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 10_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        // #774: use cos_queue_push_back so local_item_count
        // stays in sync. Previously this test poked queue.items
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
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
            }));
        root.queues[0]
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
            }));
        root.queues[0]
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
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![2]
        ));
        assert!(matches!(
            root.queues[0].items.get(1),
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
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![2]
        ));
        assert!(matches!(
            root.queues[0].items.get(1),
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
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
            u64::MAX,
            u64::MAX,
            None,
        );

        match build {
            ExactCoSScratchBuild::Drop { dropped_bytes, .. } => {
                assert_eq!(dropped_bytes, (tx_frame_capacity() + 1) as u64);
            }
            ExactCoSScratchBuild::Ready => panic!("oversized prepared frame must drop"),
        }
        assert!(scratch_prepared_tx.is_empty());
        assert!(free_tx_frames.is_empty());
        assert_eq!(pending_fill_frames, VecDeque::from([64]));
        assert!(root.queues[0].items.is_empty());
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        root.queues[0]
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
            }));
        root.queues[0]
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
            }));
        root.queues[0]
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
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Prepared(req)) if req.offset == 128
        ));
        assert!(matches!(
            root.queues[0].items.get(1),
            Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![9]
        ));

        let build = drain_exact_prepared_fifo_items_to_scratch(
            &mut root.queues[0],
            &mut scratch_prepared_tx,
            &area,
            &mut free_tx_frames,
            &mut pending_fill_frames,
            7,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(matches!(build, ExactCoSScratchBuild::Ready));
        assert_eq!(scratch_prepared_tx.len(), 1);
        assert_eq!(scratch_prepared_tx[0].offset, 128);
        assert!(matches!(
            root.queues[0].items.front(),
            Some(CoSPendingTxItem::Prepared(req)) if req.offset == 128
        ));
        assert!(matches!(
            root.queues[0].items.get(1),
            Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![9]
        ));
    }

    #[test]
    fn flow_fair_exact_queue_limits_dominant_flow_share() {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;
        let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
        let flow_a = test_session_key(1111, 5201);
        let flow_b = test_session_key(1112, 5201);
        let bucket_a = cos_flow_bucket_index(queue.flow_hash_seed, Some(&flow_a));
        let bucket_b = cos_flow_bucket_index(queue.flow_hash_seed, Some(&flow_b));
        assert_ne!(bucket_a, bucket_b);

        assert_eq!(
            cos_queue_flow_share_limit(queue, buffer_limit, bucket_a),
            buffer_limit
        );
        account_cos_queue_flow_enqueue(queue, Some(&flow_a), 64 * 1024);
        account_cos_queue_flow_enqueue(queue, Some(&flow_a), 32 * 1024);
        assert_eq!(queue.active_flow_buckets, 1);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], 96 * 1024);

        account_cos_queue_flow_enqueue(queue, Some(&flow_b), 16 * 1024);
        assert_eq!(queue.active_flow_buckets, 2);
        assert_eq!(queue.flow_bucket_bytes[bucket_b], 16 * 1024);

        let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, bucket_a);
        assert_eq!(share_cap, buffer_limit / 2);
        assert!(queue.flow_bucket_bytes[bucket_a].saturating_add(16 * 1024) > share_cap);

        account_cos_queue_flow_dequeue(queue, Some(&flow_b), 16 * 1024);
        assert_eq!(queue.active_flow_buckets, 1);
        assert_eq!(queue.flow_bucket_bytes[bucket_b], 0);
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        let req_a = TxRequest {
            bytes: vec![0; 1500],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(test_session_key(1111, 5201)),
            egress_ifindex: 80,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
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
        };
        let bucket_a = cos_flow_bucket_index(queue.flow_hash_seed, req_a.flow_key.as_ref());
        let bucket_b = cos_flow_bucket_index(queue.flow_hash_seed, req_b.flow_key.as_ref());
        assert_ne!(bucket_a, bucket_b);

        cos_queue_push_back(queue, CoSPendingTxItem::Local(req_a));
        cos_queue_push_back(queue, CoSPendingTxItem::Local(req_b));
        assert_eq!(queue.active_flow_buckets, 2);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], 1500);
        assert_eq!(queue.flow_bucket_bytes[bucket_b], 1500);

        let Some(CoSPendingTxItem::Local(req)) = cos_queue_pop_front(queue) else {
            panic!("expected first queued local request");
        };
        assert_eq!(req.flow_key.as_ref().map(|flow| flow.src_port), Some(1111));
        assert_eq!(queue.active_flow_buckets, 1);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_bytes[bucket_b], 1500);
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

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
        assert_eq!(queue.active_flow_buckets, 0);
        assert!(queue.flow_rr_buckets.is_empty());
        // #913 — MQFQ served-finish semantics: vtime tracks the
        // finish time of the last served packet, not the
        // aggregate bytes drained. With pop order
        // [1111, 1112, 1113, 1111] each picking a bucket whose
        // head_finish=1500 (and the last pop seeing head_finish=
        // 3000 after head-advance), `max(0,1500,1500,1500,3000)
        // = 3000`. Pre-#913 (aggregate-bytes) would have given
        // Σbytes = 6000.
        assert_eq!(
            queue.queue_vtime, 3000,
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

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
                    exact: true,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                }],
            );
            let queue = &mut root.queues[0];
            queue.flow_fair = true;
            queue.flow_hash_seed = 0;

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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

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
        assert_eq!(queue.queue_vtime, 4500);

        // Flow B was idle the whole time. It now returns with a
        // 1200-byte packet. It MUST anchor at queue_vtime+bytes =
        // 4500+1200 = 5700, NOT at 0+1200 = 1200.
        cos_queue_push_back(queue, test_flow_cos_item(3302, 1200));
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_b], 5700,
            "#785 Phase 3: idle-returning bucket MUST re-anchor at \
             current queue_vtime, not 0. Anchoring at 0 lets the \
             returning flow sweep past all established flows for \
             several rounds (#785 CoV regression).",
        );
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_b], 5700);
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;
        // Simulate the queue having already drained to vtime=5000.
        queue.queue_vtime = 5000;

        let flow_a = test_session_key(1111, 5201);
        let flow_b = test_session_key(2222, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
        let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
        assert_ne!(bucket_a, bucket_b, "fixture flow keys must not collide");

        // Packet 1 of flow A — bucket was idle (finish=0). Re-anchor
        // to queue.vtime (5000) then + 1500.
        account_cos_queue_flow_enqueue(queue, Some(&flow_a), 1500);
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], 6500,
            "first packet on an idle bucket re-anchors to queue.vtime \
             + bytes (5000 + 1500 = 6500)",
        );

        // Packet 2 of flow A — already-active. finish advances by bytes.
        account_cos_queue_flow_enqueue(queue, Some(&flow_a), 1500);
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], 8000,
            "subsequent packet on the same active bucket advances by \
             exactly bytes (6500 + 1500 = 8000)",
        );

        // Packet 1 of flow B — independent bucket, same re-anchor.
        account_cos_queue_flow_enqueue(queue, Some(&flow_b), 500);
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_b], 5500,
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        let flow = test_session_key(3333, 5201);
        let bucket = cos_flow_bucket_index(0, Some(&flow));

        cos_queue_push_back(queue, test_flow_cos_item(3333, 1500));
        assert!(queue.flow_bucket_head_finish_bytes[bucket] > 0);
        assert!(queue.flow_bucket_tail_finish_bytes[bucket] > 0);

        // Drain the only packet. Bucket is now empty.
        let _ = cos_queue_pop_front(queue);
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket], 0,
            "bucket drain to 0 MUST reset head-finish-time",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket], 0,
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Three packets on one flow. After enqueue, bucket_finish
        // = 4500 (the 3rd packet's finish). But queue.vtime should
        // advance by 1500 per pop, not jump to 4500 on the first.
        cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(1111, 1500));

        assert_eq!(queue.queue_vtime, 0);

        let _ = cos_queue_pop_front(queue);
        assert_eq!(
            queue.queue_vtime, 1500,
            "first pop: vtime tracks served packet's finish_time \
             (1500 = head_finish of the 1st packet)",
        );
        let _ = cos_queue_pop_front(queue);
        assert_eq!(queue.queue_vtime, 3000);
        let _ = cos_queue_pop_front(queue);
        assert_eq!(queue.queue_vtime, 4500);
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Enqueue one 1500-byte packet on each of 10 distinct
        // flows. After enqueue, every bucket has head=tail=1500.
        // Copilot review: select flow IDs dynamically so the test
        // doesn't couple to a specific hash distribution. We
        // sweep candidate IDs and accept the first 10 that land
        // in distinct buckets.
        let mut buckets: std::collections::HashSet<usize> =
            std::collections::HashSet::new();
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
        assert_eq!(queue.queue_vtime, 0);
        assert_eq!(queue.active_flow_buckets, 10);

        // Pop all 10 items via MQFQ (min head_finish first).
        for _ in 0..10 {
            assert!(cos_queue_pop_front(queue).is_some());
        }

        assert_eq!(
            queue.queue_vtime, 1500,
            "#913 MQFQ: vtime tracks served-packet finish, \
             not aggregate bytes drained. Each pop sees the \
             same head_finish=1500 across the 10 distinct \
             flows; max(0,1500,1500,...,1500) = 1500. \
             Pre-#913 aggregate-bytes would have given \
             10 × 1500 = 15000."
        );
        assert_eq!(queue.active_flow_buckets, 0);
    }

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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Distinct buckets X / Y / Z with mixed packet sizes so
        // each has a unique head_finish (avoids the "all-equal"
        // numeric-coincidence case). Copilot review: select flow
        // IDs dynamically so the test doesn't couple to a
        // specific hash distribution.
        let mut seen: std::collections::HashSet<usize> =
            std::collections::HashSet::new();
        let mut picks: Vec<u16> = Vec::with_capacity(3);
        for flow_id in 7001u16..8001u16 {
            let bucket = cos_flow_bucket_index(
                0,
                Some(&test_session_key(flow_id, 5201)),
            );
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

        let pre_batch_head_x = queue.flow_bucket_head_finish_bytes[bucket_x];
        let pre_batch_head_y = queue.flow_bucket_head_finish_bytes[bucket_y];
        let pre_batch_head_z = queue.flow_bucket_head_finish_bytes[bucket_z];
        assert_eq!(pre_batch_head_x, 1500);
        assert_eq!(pre_batch_head_y, 2000);
        assert_eq!(pre_batch_head_z, 3000);

        // Pop X, Y, Z in MQFQ order.
        let popped_x = cos_queue_pop_front(queue).expect("pop X");
        let popped_y = cos_queue_pop_front(queue).expect("pop Y");
        let _popped_z = cos_queue_pop_front(queue).expect("pop Z");
        assert_eq!(
            queue.queue_vtime, 3000,
            "after X→Y→Z pops, vtime tracks served-finish frontier (max=3000)"
        );
        assert_eq!(queue.pop_snapshot_stack.len(), 3);

        // Simulate Z dropped (e.g., frame too big in scratch builder).
        cos_queue_clear_orphan_snapshot_after_drop(queue);
        assert_eq!(queue.pop_snapshot_stack.len(), 2);
        assert_eq!(
            queue.queue_vtime, 3000,
            "Drop preserves the committed vtime advance"
        );

        // Restore Y first (LIFO), then X.
        cos_queue_push_front(queue, popped_y);
        assert!(
            queue.queue_vtime >= 3000,
            "after Y restore, vtime must NOT regress below Z's commit \
             (got {})",
            queue.queue_vtime
        );
        cos_queue_push_front(queue, popped_x);
        assert!(
            queue.queue_vtime >= 3000,
            "after X restore, vtime must NOT regress below Z's commit \
             (got {})",
            queue.queue_vtime
        );
        assert!(
            queue.pop_snapshot_stack.is_empty(),
            "all snapshots consumed by restore"
        );

        // X and Y bucket head_finish restored to pre-pop values.
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_x], pre_batch_head_x);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_y], pre_batch_head_y);

        // Now enqueue a new idle flow W with a small packet. Pick
        // its flow ID dynamically so its bucket is distinct from
        // the restored X and Y buckets.
        let mut flow_w_id: u16 = 0;
        for candidate in 8001u16..9001u16 {
            let bucket = cos_flow_bucket_index(
                0,
                Some(&test_session_key(candidate, 5201)),
            );
            if bucket != bucket_x && bucket != bucket_y && bucket != bucket_z {
                flow_w_id = candidate;
                break;
            }
        }
        assert_ne!(flow_w_id, 0, "test setup: distinct W bucket selectable");
        cos_queue_push_back(queue, test_flow_cos_item(flow_w_id, 100));
        let key_w = test_session_key(flow_w_id, 5201);
        let bucket_w = cos_flow_bucket_index(0, Some(&key_w));
        let w_head = queue.flow_bucket_head_finish_bytes[bucket_w];

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
            w_head, pre_batch_head_x
        );
        assert!(
            w_head >= pre_batch_head_y,
            "Codex regression: new idle flow W (head={}) must NOT \
             jump ahead of restored bucket Y (head={})",
            w_head, pre_batch_head_y
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Single bucket A, 3 packets with mixed sizes.
        cos_queue_push_back(queue, test_flow_cos_item(8001, 1000));
        cos_queue_push_back(queue, test_flow_cos_item(8001, 2000));
        cos_queue_push_back(queue, test_flow_cos_item(8001, 1500));
        let key_a = test_session_key(8001, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&key_a));

        // Pop A1 (1000B). head_finish advances to 3000.
        let popped_a1 = cos_queue_pop_front(queue).expect("pop A1");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 3000);

        // Pop A2 (2000B). head_finish advances to 4500.
        let _popped_a2 = cos_queue_pop_front(queue).expect("pop A2");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 4500);
        assert_eq!(queue.pop_snapshot_stack.len(), 2);

        // Simulate A2 dropped via the scratch-builder Drop helper.
        cos_queue_clear_orphan_snapshot_after_drop(queue);
        assert_eq!(queue.pop_snapshot_stack.len(), 1);

        // Restore A1 via push_front. Active-bucket arithmetic:
        // head=4500 - bytes(A3=1500) = 3000. This is the
        // post-A2-pop value; A2's "virtual service" is preserved.
        cos_queue_push_front(queue, popped_a1);
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], 3000,
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
            queue.flow_bucket_head_finish_bytes[bucket_a], 4500,
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

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
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 1000);
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], 3000);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_c], 2500);

        // Pop A1: head_finish[A] advances to 3000 (A2 finish-time).
        let popped_a1 = cos_queue_pop_front(queue).expect("pop A1");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 3000);

        // Pop C: MQFQ picks min-finish-first; with A.head=3000
        // and C.head=2500, C.head < A.head so C is the next pop.
        // After pop: bucket C empty; C.head_finish reset to 0.
        let popped_c = cos_queue_pop_front(queue).expect("pop C");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_c], 0);

        // Pop A2 (last in A): bucket A drains, A.head_finish reset
        // to 0. queue_vtime reflects all three pops.
        let _popped_a2 = cos_queue_pop_front(queue).expect("pop A2");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 0);
        assert_eq!(queue.pop_snapshot_stack.len(), 3);

        // Simulate A2 dropped (e.g., frame too big to transmit).
        cos_queue_clear_orphan_snapshot_after_drop(queue);
        assert_eq!(queue.pop_snapshot_stack.len(), 2);

        // Restore C via push_front: bucket C is empty so the
        // `was_empty` snapshot path applies. C.head should restore
        // to snap_C.pre_pop_head_finish = 2500.
        cos_queue_push_front(queue, popped_c);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_c], 2500);

        // Restore A1 via push_front: bucket A is empty so the
        // `was_empty` snapshot path applies. WITHOUT #927, A.head
        // would restore to snap_1.pre_pop_head_finish = 1000 —
        // inverting MQFQ order vs C (1000 < 2500). WITH #927, the
        // orphan-cleanup helper bumped snap_1.pre_pop_head_finish
        // up to A2's served_finish = 3000, so the restored A.head
        // = 3000 > C.head = 2500 — MQFQ correctly picks C first.
        cos_queue_push_front(queue, popped_a1);
        assert!(
            queue.flow_bucket_head_finish_bytes[bucket_a]
                > queue.flow_bucket_head_finish_bytes[bucket_c],
            "#927 regression: A.head ({}) must be strictly greater than \
             C.head ({}) so MQFQ picks C first. Without the orphan-cleanup \
             same-bucket frontier bump, A.head would restore to 1000 and \
             A1 would pop before C — inverting their original schedule.",
            queue.flow_bucket_head_finish_bytes[bucket_a],
            queue.flow_bucket_head_finish_bytes[bucket_c],
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.shared_exact = true;
        queue.flow_hash_seed = 0;

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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Enqueue three packets on one flow.
        cos_queue_push_back(queue, test_flow_cos_item(4444, 1000));
        cos_queue_push_back(queue, test_flow_cos_item(4444, 2000));
        cos_queue_push_back(queue, test_flow_cos_item(4444, 1500));

        let flow = test_session_key(4444, 5201);
        let bucket = cos_flow_bucket_index(0, Some(&flow));

        // Bucket state: head=1000, tail=4500.
        let pre_pop_head = queue.flow_bucket_head_finish_bytes[bucket];
        let pre_pop_tail = queue.flow_bucket_tail_finish_bytes[bucket];
        let pre_pop_bytes = queue.flow_bucket_bytes[bucket];
        let pre_pop_vtime = queue.queue_vtime;
        assert_eq!(pre_pop_head, 1000);
        assert_eq!(pre_pop_tail, 4500);
        assert_eq!(pre_pop_bytes, 4500);
        assert_eq!(pre_pop_vtime, 0);

        // Pop head (the 1000-byte packet). Head advances to 3000
        // (= pre_pop_head + bytes(new head = 2000)). vtime += 1000.
        let popped = cos_queue_pop_front(queue).expect("pop");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket], 3000);
        assert_eq!(queue.queue_vtime, 1000);

        // Push the same item back onto the front. Head-finish MUST
        // return to the pre-pop value (1000), AND queue_vtime MUST
        // return to its pre-pop value (0) — Codex round-3 HIGH.
        cos_queue_push_front(queue, popped);
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket], pre_pop_head,
            "#785 Phase 3 Codex HIGH: push_front must be finish-\
             time-neutral on active buckets. Regression re-opens \
             the MQFQ ordering corruption on TX-ring-full retry.",
        );
        // Tail unchanged — we didn't add at tail.
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket], pre_pop_tail);
        assert_eq!(queue.flow_bucket_bytes[bucket], pre_pop_bytes);
        assert_eq!(
            queue.queue_vtime, pre_pop_vtime,
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Simulate a vtime that's already advanced (as it would
        // be mid-stream when other flows have drained), then
        // enqueue a single packet on flow A. The idle-bucket
        // re-anchor writes head=tail=max(tail=0, vtime=5000)+1500
        // = 6500.
        queue.queue_vtime = 5000;
        let flow_a = test_session_key(7777, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
        cos_queue_push_back(queue, test_flow_cos_item(7777, 1500));

        let pre_pop_head = queue.flow_bucket_head_finish_bytes[bucket_a];
        let pre_pop_tail = queue.flow_bucket_tail_finish_bytes[bucket_a];
        let pre_pop_bytes = queue.flow_bucket_bytes[bucket_a];
        let pre_pop_vtime = queue.queue_vtime;
        let pre_pop_active = queue.active_flow_buckets;
        assert_eq!(pre_pop_head, 6500);
        assert_eq!(pre_pop_tail, 6500);
        assert_eq!(pre_pop_bytes, 1500);
        assert_eq!(pre_pop_vtime, 5000);

        // Pop the sole item. Bucket drains: head=tail=0, active
        // count -=1, vtime advances to 6500.
        let popped = cos_queue_pop_front(queue).expect("pop");
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], 0);
        assert_eq!(queue.queue_vtime, pre_pop_vtime + 1500);
        assert!(queue.flow_bucket_items[bucket_a].is_empty());

        // Restore it via push_front. Without the snapshot fix this
        // re-anchors to vtime+bytes = 6500+1500 = 8000 — one packet
        // past the pre-pop head of 6500. With the fix, head/tail
        // restore to 6500 exactly.
        cos_queue_push_front(queue, popped);

        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], pre_pop_head,
            "#785 Phase 3 Codex round-3 HIGH / Rust MEDIUM #1: \
             push_front on a drained bucket must restore pre-pop \
             head exactly, not re-anchor one packet past it.",
        );
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], pre_pop_tail);
        assert_eq!(queue.flow_bucket_bytes[bucket_a], pre_pop_bytes);
        assert_eq!(
            queue.queue_vtime, pre_pop_vtime,
            "#785 Phase 3: queue_vtime must rewind to pre-pop on \
             drained-bucket round-trip too.",
        );
        assert_eq!(queue.active_flow_buckets, pre_pop_active);
        assert_eq!(queue.flow_bucket_items[bucket_a].len(), 1);
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Advance `queue_vtime` so that later flows anchor ahead
        // of zero (stresses the cross-bucket bug — an earlier pop
        // whose bucket drains resets head/tail to 0, then
        // `max(0, queue_vtime) + bytes` on re-enqueue overshoots
        // the pre-pop head).
        queue.queue_vtime = 3000;

        let flow_a = test_session_key(5555, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));

        cos_queue_push_back(queue, test_flow_cos_item(5555, 1000));
        cos_queue_push_back(queue, test_flow_cos_item(5555, 1200));
        cos_queue_push_back(queue, test_flow_cos_item(5555, 800));
        cos_queue_push_back(queue, test_flow_cos_item(5555, 1400));

        let pre_batch_head = queue.flow_bucket_head_finish_bytes[bucket_a];
        let pre_batch_tail = queue.flow_bucket_tail_finish_bytes[bucket_a];
        let pre_batch_bytes = queue.flow_bucket_bytes[bucket_a];
        let pre_batch_vtime = queue.queue_vtime;
        let pre_batch_active = queue.active_flow_buckets;
        let pre_batch_peak = queue.active_flow_buckets_peak;
        let pre_batch_items = queue.flow_bucket_items[bucket_a].len();
        assert_eq!(pre_batch_items, 4);

        // Drain all 4 into scratch. Stack grows to 4 snapshots.
        let mut scratch: Vec<CoSPendingTxItem> = Vec::with_capacity(4);
        while let Some(item) = cos_queue_pop_front(queue) {
            scratch.push(item);
        }
        assert_eq!(scratch.len(), 4);
        assert_eq!(
            queue.pop_snapshot_stack.len(),
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
            queue.pop_snapshot_stack.is_empty(),
            "NEW-1: snapshot stack must be fully consumed after a \
             complete rollback",
        );
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], pre_batch_head,
            "#785 Phase 3 NEW-1: batched rollback must restore \
             bucket HEAD finish exactly (single-bucket case)",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], pre_batch_tail,
            "#785 Phase 3 NEW-1: batched rollback must restore \
             bucket TAIL finish exactly (single-bucket case)",
        );
        assert_eq!(
            queue.flow_bucket_bytes[bucket_a], pre_batch_bytes,
            "#785 Phase 3 NEW-1: batched rollback must restore \
             bucket byte count exactly",
        );
        assert_eq!(
            queue.queue_vtime, pre_batch_vtime,
            "#785 Phase 3 NEW-1: batched rollback must restore \
             queue_vtime exactly — symmetric per-item rewind",
        );
        assert_eq!(
            queue.active_flow_buckets, pre_batch_active,
            "#785 Phase 3 NEW-1: batched rollback must leave \
             active_flow_buckets unchanged",
        );
        assert_eq!(
            queue.active_flow_buckets_peak, pre_batch_peak,
            "#785 Phase 3 NEW-1: peak counter is monotonic — \
             rollback must not bump it (no fresh high-water mark)",
        );
        assert_eq!(queue.flow_bucket_items[bucket_a].len(), pre_batch_items);
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Step 1: low vtime so A and B anchor near 0.
        queue.queue_vtime = 100;

        let flow_a = test_session_key(6001, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
        let flow_b = test_session_key(6002, 5201);
        let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
        assert_ne!(bucket_a, bucket_b, "test hash collision");

        cos_queue_push_back(queue, test_flow_cos_item(6001, 1500));
        cos_queue_push_back(queue, test_flow_cos_item(6002, 900));
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 1600);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_b], 1000);

        // Step 2: simulate other-flow drain activity. vtime
        // advances past both buckets' head finish times. This is
        // the condition that makes the old single-Option rollback
        // overshoot on the earlier-popped bucket.
        queue.queue_vtime = 5000;

        let pre_batch_head_a = queue.flow_bucket_head_finish_bytes[bucket_a];
        let pre_batch_tail_a = queue.flow_bucket_tail_finish_bytes[bucket_a];
        let pre_batch_bytes_a = queue.flow_bucket_bytes[bucket_a];
        let pre_batch_head_b = queue.flow_bucket_head_finish_bytes[bucket_b];
        let pre_batch_tail_b = queue.flow_bucket_tail_finish_bytes[bucket_b];
        let pre_batch_bytes_b = queue.flow_bucket_bytes[bucket_b];
        let pre_batch_vtime = queue.queue_vtime;
        let pre_batch_active = queue.active_flow_buckets;
        let pre_batch_peak = queue.active_flow_buckets_peak;
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
        assert_eq!(queue.pop_snapshot_stack.len(), 2);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_b], 0);
        assert_eq!(queue.active_flow_buckets, 0);

        // Roll back LIFO. scratch.pop() returns A (popped second)
        // first, then B. Each push_front consumes its own
        // snapshot off the stack.
        while let Some(item) = scratch.pop() {
            cos_queue_push_front(queue, item);
        }

        assert!(
            queue.pop_snapshot_stack.is_empty(),
            "NEW-1: snapshot stack must be fully consumed after a \
             complete cross-bucket rollback",
        );
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], pre_batch_head_a,
            "#785 Phase 3 NEW-1: cross-bucket rollback — A's HEAD \
             must restore from A's OWN per-pop snapshot, not re- \
             anchor off the rewound vtime (that overshoots).",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], pre_batch_tail_a,
            "#785 Phase 3 NEW-1: cross-bucket rollback — A's TAIL \
             must restore exactly.",
        );
        assert_eq!(queue.flow_bucket_bytes[bucket_a], pre_batch_bytes_a);
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_b], pre_batch_head_b,
            "#785 Phase 3 NEW-1: cross-bucket rollback — B's HEAD \
             must restore exactly (this is the 'most recent pop' \
             case that worked with the single-snapshot impl too).",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_b], pre_batch_tail_b,
        );
        assert_eq!(queue.flow_bucket_bytes[bucket_b], pre_batch_bytes_b);
        assert_eq!(
            queue.queue_vtime, pre_batch_vtime,
            "#785 Phase 3 NEW-1: vtime must rewind symmetrically \
             across a cross-bucket batch rollback.",
        );
        assert_eq!(
            queue.active_flow_buckets, pre_batch_active,
            "#785 Phase 3 NEW-1: cross-bucket rollback must re- \
             activate both buckets.",
        );
        assert_eq!(queue.active_flow_buckets_peak, pre_batch_peak);
    }

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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 8 * 1024 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        let pre_cap = queue.pop_snapshot_stack.capacity();
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
                queue.pop_snapshot_stack.len() <= TX_BATCH_SIZE,
                "NEW-2: pop_snapshot_stack must never exceed \
                 TX_BATCH_SIZE during a single drain batch",
            );
        }
        assert_eq!(
            queue.pop_snapshot_stack.len(),
            TX_BATCH_SIZE,
            "full-batch commit should leave exactly TX_BATCH_SIZE \
             snapshots (no push_front rollback consumed any)",
        );

        // Simulate what `drain_exact_*_flow_fair` does at batch
        // start: clear the stack before the next batch drains.
        // This is the fix point.
        queue.pop_snapshot_stack.clear();

        // Batch 2: drain the remaining 64 items. Stack must stay
        // bounded; without the batch-start clear this would grow
        // from TX_BATCH_SIZE → TX_BATCH_SIZE + 64 and realloc.
        for _ in 0..64 {
            let popped = cos_queue_pop_front(queue);
            assert!(popped.is_some());
            assert!(
                queue.pop_snapshot_stack.len() <= TX_BATCH_SIZE,
                "NEW-2: cross-batch drain must stay bounded after \
                 the drain-start clear",
            );
        }

        // No realloc: capacity must equal the preallocated
        // TX_BATCH_SIZE exactly. A realloc would prove the bound
        // was violated at some point.
        assert_eq!(
            queue.pop_snapshot_stack.capacity(),
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 8 * 1024 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        let pre_cap = queue.pop_snapshot_stack.capacity();
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
        assert!(queue.pop_snapshot_stack.is_empty());

        // Drain via the teardown helper. Must NOT grow the stack
        // and must NOT trip the pop_front debug_assert on overflow.
        let drained = cos_queue_drain_all(queue);
        assert_eq!(
            drained.len(),
            total,
            "drain_all must yield every enqueued item",
        );
        assert!(
            queue.pop_snapshot_stack.is_empty(),
            "NEW-2: teardown drain path must leave the snapshot \
             stack empty — no stale snapshots resident",
        );
        assert_eq!(
            queue.pop_snapshot_stack.capacity(),
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        let flow_a = test_session_key(1001, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));
        let flow_b = test_session_key(1002, 5201);
        let bucket_b = cos_flow_bucket_index(0, Some(&flow_b));
        assert_ne!(bucket_a, bucket_b, "test hash collision");

        // Flow A: single packet. Enqueue + drain fully. Bucket A
        // goes idle with head/tail=0.
        cos_queue_push_back(queue, test_flow_cos_item(1001, 1500));
        let _ = cos_queue_pop_front(queue);
        assert_eq!(queue.flow_bucket_head_finish_bytes[bucket_a], 0);
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], 0);
        assert_eq!(queue.queue_vtime, 1500);

        // Flow B: one packet, drain it. Advances queue_vtime to
        // 1500 + 800 = 2300 (small amount vs. flow A's lifetime).
        cos_queue_push_back(queue, test_flow_cos_item(1002, 800));
        let _ = cos_queue_pop_front(queue);
        assert_eq!(queue.queue_vtime, 2300);
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_b], 0);

        // Flow A returns with a 1200-byte packet. tail_finish[A]=0,
        // queue_vtime=2300 → max picks vtime → head = tail = 2300
        // + 1200 = 3500. This is the "brief-idle" re-anchor.
        cos_queue_push_back(queue, test_flow_cos_item(1001, 1200));
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], 3500,
            "#785 Phase 3 brief-idle re-entry: first arm of max \
             (tail_finish=0 < queue_vtime=2300) must anchor at \
             queue_vtime + bytes",
        );
        assert_eq!(queue.flow_bucket_tail_finish_bytes[bucket_a], 3500);

        // Flow A appends a second 900-byte packet on its now-
        // active bucket. tail_finish=3500 > queue_vtime=2300 →
        // max picks tail_finish → tail = 3500 + 900 = 4400. Head
        // unchanged (head packet is still the first one, 3500).
        cos_queue_push_back(queue, test_flow_cos_item(1001, 900));
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], 3500,
            "#785 Phase 3 brief-idle re-entry: active-bucket \
             enqueue must NOT alter head (head packet didn't \
             change)",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], 4400,
            "#785 Phase 3 brief-idle re-entry: second arm of max \
             (tail_finish=3500 > queue_vtime=2300) must anchor at \
             tail_finish + bytes",
        );
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
    ///   1. Drives `queue.queue_vtime` to `u64::MAX - 10_000`.
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        queue.flow_hash_seed = 0;

        // Largest plausible single enqueue: MTU 9000 at weight 1.
        const MAX_SINGLE_DELTA: usize = 9_000;
        const SLACK: u64 = 10_000;
        let near_wrap = u64::MAX - SLACK;

        // Drive the runtime field near wrap by setting queue_vtime
        // (the re-anchor source for idle-bucket enqueue). The first
        // enqueue re-anchors head=tail=max(0, near_wrap)+9000 =
        // near_wrap + 9000 — well within u64 and exactly one delta
        // past queue_vtime.
        queue.queue_vtime = near_wrap;

        let flow_a = test_session_key(9999, 5201);
        let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));

        cos_queue_push_back(queue, test_flow_cos_item(9999, MAX_SINGLE_DELTA));
        let expected_first = near_wrap + MAX_SINGLE_DELTA as u64;
        assert_eq!(
            queue.flow_bucket_head_finish_bytes[bucket_a], expected_first,
            "first enqueue near u64 wrap must anchor at queue_vtime \
             + bytes; regression to u32 or non-saturating add would \
             fail here with a wrapped or truncated value",
        );
        assert_eq!(
            queue.flow_bucket_tail_finish_bytes[bucket_a], expected_first,
        );
        assert!(
            queue.flow_bucket_head_finish_bytes[bucket_a] > near_wrap,
            "finish time did not advance past pre-enqueue vtime — \
             type narrowed or wrap occurred",
        );

        // Second enqueue onto the ACTIVE bucket: tail advances by
        // MAX_SINGLE_DELTA, but saturating_add caps at u64::MAX.
        // With near_wrap + 2*9000 = u64::MAX - 10_000 + 18_000 =
        // u64::MAX + 8_000 — this SHOULD saturate to u64::MAX.
        cos_queue_push_back(queue, test_flow_cos_item(9999, MAX_SINGLE_DELTA));
        let new_tail = queue.flow_bucket_tail_finish_bytes[bucket_a];
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
            queue.flow_bucket_head_finish_bytes[bucket_a], expected_first,
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        assert!(!runtime.queues[0].flow_fair);
        assert!(!runtime.queues[0].shared_exact);

        // Drive the full ensure_cos_interface_runtime promotion loop.
        let fast_path = vec![test_queue_fast_path_for_promotion(true)];
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path, 0);

        assert!(
            runtime.queues[0].flow_fair,
            "#785 Phase 3: shared_exact queue MUST be promoted onto \
             the flow-fair path so MQFQ virtual-finish-time ordering \
             runs in the dequeue path. Regression here re-opens the \
             CoV gap we just measured closed.",
        );
        assert!(
            runtime.queues[0].shared_exact,
            "#785 Phase 3: shared_exact shadow MUST be cached onto \
             the runtime so the admission gates in \
             cos_queue_flow_share_limit and \
             apply_cos_admission_ecn_policy downgrade to \
             aggregate-only. Per-flow admission gates are rate-\
             unaware (24 KB floor) and would tail-drop TCP at \
             multi-Gbps per-flow rates.",
        );
        assert_ne!(
            runtime.queues[0].flow_hash_seed, 0,
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );
        let fast_path = vec![test_queue_fast_path_for_promotion(false)];
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path, 0);

        assert!(
            runtime.queues[0].flow_fair,
            "owner-local-exact queue MUST be promoted onto the SFQ \
             path — #784 fairness fix depends on it",
        );
        assert!(
            !runtime.queues[0].shared_exact,
            "owner-local-exact queue MUST keep shared_exact=false so \
             the per-flow share cap and per-flow ECN arm continue to \
             run — #784 depends on the per-flow cap firing at 1 Gbps",
        );
        assert_ne!(
            runtime.queues[0].flow_hash_seed, 0,
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
                exact: false,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            }],
        );

        // Drive the production loop with shared_exact=false first,
        // then again with shared_exact=true — both MUST leave a
        // non-exact queue off the flow-fair path, because the gate's
        // LHS (`queue.exact`) fails regardless of the fast-path bit.
        let fast_path_owner_local = vec![test_queue_fast_path_for_promotion(false)];
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path_owner_local, 0);
        assert!(
            !runtime.queues[0].flow_fair,
            "non-exact queues must stay off the flow-fair path: SFQ \
             has no rate contract to enforce there, and draws an OS \
             random seed per queue",
        );

        let fast_path_shared = vec![test_queue_fast_path_for_promotion(true)];
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path_shared, 0);
        assert!(
            !runtime.queues[0].flow_fair,
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
    //       queue.items.pop_front per sent packet, scratch Vec pop.
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 4 * 1024 * 1024,
                dscp_rewrite: None,
            }],
        );
        root.tokens = u64::MAX;
        root.queues[0].tokens = u64::MAX;
        root.queues[0].runnable = true;

        let packet_bytes = vec![0xABu8; PACKET_LEN];
        let mut scratch = Vec::with_capacity(ITEMS_PER_BATCH);
        let mut free_frames: VecDeque<u64> =
            (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();

        // Prime: one full batch of items. Each iteration below drains
        // them all and then re-primes both the items and the free frames
        // to the same initial state.
        let prime_queue = |queue: &mut CoSQueueRuntime, packet: &[u8]| {
            queue.items.clear();
            queue.queued_bytes = 0;
            for _ in 0..ITEMS_PER_BATCH {
                queue.items.push_back(CoSPendingTxItem::Local(TxRequest {
                    bytes: packet.to_vec(),
                    expected_ports: None,
                    expected_addr_family: libc::AF_INET as u8,
                    expected_protocol: PROTO_TCP,
                    flow_key: None,
                    egress_ifindex: 80,
                    cos_queue_id: Some(5),
                    dscp_rewrite: None,
                }));
                queue.queued_bytes += packet.len() as u64;
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
                exact: true,
                surplus_weight: 1,
                buffer_bytes: 4 * 1024 * 1024,
                dscp_rewrite: None,
            }],
        );
        root.tokens = u64::MAX;
        // Promote to flow_fair + shared_exact + attach floor to
        // exercise the V_min publish path.
        let queue = &mut root.queues[0];
        queue.tokens = u64::MAX;
        queue.flow_fair = true;
        queue.exact = true;
        queue.shared_exact = true;
        let _floor = attach_test_vtime_floor(queue, 4, 0);
        queue.runnable = true;

        let area = MmapArea::new(2 * 1024 * 1024).expect("mmap umem");
        let packet_bytes = vec![0xABu8; PACKET_LEN];
        let mut scratch: Vec<(u64, TxRequest)> = Vec::with_capacity(ITEMS_PER_BATCH);
        let mut free_frames: VecDeque<u64> =
            (0..ITEMS_PER_BATCH as u64).map(|i| i * 4096).collect();

        let prime_queue = |queue: &mut CoSQueueRuntime, packet: &[u8]| {
            queue.items.clear();
            queue.queued_bytes = 0;
            queue.queue_vtime = 0;
            queue.flow_bucket_bytes = [0; COS_FLOW_FAIR_BUCKETS];
            queue.flow_bucket_head_finish_bytes = [0; COS_FLOW_FAIR_BUCKETS];
            queue.flow_bucket_tail_finish_bytes = [0; COS_FLOW_FAIR_BUCKETS];
            queue.flow_rr_buckets = FlowRrRing::default();
            queue.flow_bucket_items = std::array::from_fn(|_| VecDeque::new());
            queue.active_flow_buckets = 0;
            queue.local_item_count = 0;
            queue.pop_snapshot_stack.clear();
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

}
