// Tests for afxdp/tx/cos_classify.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep cos_classify.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "cos_classify_tests.rs"]` from cos_classify.rs.

use super::*;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::SharedCoSExactBacklog;
use crate::filter::TermMatchExtra;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSForwardingClassSnapshot, CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
    FirewallFilterSnapshot, FirewallTermSnapshot, ThreeColorPolicerSnapshot,
};

#[test]
fn resolve_cos_queue_idx_rejects_explicit_queue_miss() {
    let root = test_cos_runtime_with_queues(
        10_000_000,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );

    assert_eq!(resolve_cos_queue_idx(&root, Some(4)), None);
    assert_eq!(resolve_cos_queue_idx(&root, None), Some(0));
}

#[test]
fn enqueue_exact_queue_publishes_shared_backlog_slot() {
    let root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 125_000_000,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 4_000_000,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let mut fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        4,
        vec![(4, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let shared_exact_backlog = Arc::new(SharedCoSExactBacklog::new(1));
    fast_interfaces
        .get_mut(&42)
        .expect("test fast path")
        .shared_exact_backlog = Some(shared_exact_backlog.clone());
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    assert!(
        enqueue_cos_item(
            &mut binding,
            42,
            Some(4),
            512,
            test_flow_cos_item(5201, 512),
            0,
            None,
        )
        .is_ok()
    );

    assert!(
        shared_exact_backlog.has_peer_backlog(1),
        "exact enqueue must publish immediately so peer workers do not undercount exact backlog",
    );
}

#[test]
fn clone_prepared_request_for_cos_returns_local_copy_with_metadata() {
    let mut area = MmapArea::new(4096).expect("mmap");
    let payload = [0xde, 0xad, 0xbe, 0xef];
    area.slice_mut(128, payload.len())
        .expect("slice")
        .copy_from_slice(&payload);
    let req = PreparedTxRequest {
        offset: 128,
        len: payload.len() as u32,
        recycle: PreparedTxRecycle::FreeTxFrame,
        expected_ports: Some((1111, 2222)),
        expected_addr_family: libc::AF_INET6 as u8,
        expected_protocol: PROTO_TCP,
        flow_key: Some(SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            src_port: 1111,
            dst_port: 2222,
        }),
        egress_ifindex: 80,
        cos_queue_id: Some(4),
        dscp_rewrite: Some(46),
        mirror_clone: true,
        enqueue_ns: 0,
    };

    let local = clone_prepared_request_for_cos(&area, &req).expect("local copy");

    assert_eq!(local.bytes, payload);
    assert_eq!(local.expected_ports, Some((1111, 2222)));
    assert_eq!(local.expected_addr_family, libc::AF_INET6 as u8);
    assert_eq!(local.expected_protocol, PROTO_TCP);
    assert_eq!(local.egress_ifindex, 80);
    assert_eq!(local.cos_queue_id, Some(4));
    assert_eq!(local.dscp_rewrite, Some(46));
    assert!(local.mirror_clone);
    assert_eq!(
        local
            .flow_key
            .as_ref()
            .map(|key| (key.src_port, key.dst_port)),
        Some((1111, 2222))
    );
}

#[test]
fn clone_prepared_request_for_cos_rejects_out_of_range_offset() {
    let area = MmapArea::new(256).expect("mmap");
    let req = PreparedTxRequest {
        offset: 1024,
        len: 64,
        recycle: PreparedTxRecycle::FreeTxFrame,
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 80,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
        mirror_clone: false,
        enqueue_ns: 0,
    };

    assert!(clone_prepared_request_for_cos(&area, &req).is_none());
}

#[test]
fn prepare_local_request_for_cos_preserves_mirror_tx_frame_reserve() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut free_tx_frames = (0..MIRROR_TX_FRAME_RESERVE as u64)
        .map(|idx| idx << UMEM_FRAME_SHIFT)
        .collect::<VecDeque<_>>();
    let original_free = free_tx_frames.clone();
    let req = TxRequest {
        bytes: vec![1, 2, 3, 4],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 80,
        cos_queue_id: Some(5),
        dscp_rewrite: None,
        mirror_clone: true,
        enqueue_ns: 0,
    };

    let req = match prepare_local_request_for_cos(&area, &mut free_tx_frames, req) {
        Ok(_) => panic!("mirror clones must not consume the last reserved TX frames"),
        Err(req) => req,
    };

    assert!(req.mirror_clone);
    assert_eq!(free_tx_frames, original_free);
}

#[test]
fn prepare_local_request_for_cos_materializes_prepared_frame() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut free_tx_frames = VecDeque::from([128]);
    let req = TxRequest {
        bytes: vec![0xde, 0xad, 0xbe, 0xef],
        expected_ports: Some((1111, 2222)),
        expected_addr_family: libc::AF_INET6 as u8,
        expected_protocol: PROTO_TCP,
        flow_key: Some(SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            src_port: 1111,
            dst_port: 2222,
        }),
        egress_ifindex: 80,
        cos_queue_id: Some(5),
        dscp_rewrite: Some(46),
        mirror_clone: false,
        enqueue_ns: 0,
    };

    let prepared =
        prepare_local_request_for_cos(&area, &mut free_tx_frames, req).expect("prepared");

    assert_eq!(prepared.offset, 128);
    assert_eq!(prepared.len, 4);
    assert_eq!(prepared.recycle, PreparedTxRecycle::FreeTxFrame);
    assert_eq!(prepared.expected_ports, Some((1111, 2222)));
    assert_eq!(prepared.egress_ifindex, 80);
    assert_eq!(prepared.cos_queue_id, Some(5));
    assert_eq!(prepared.dscp_rewrite, Some(46));
    assert!(free_tx_frames.is_empty());
    assert_eq!(area.slice(128, 4).expect("slice"), [0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn prepare_local_request_for_cos_falls_back_when_no_free_tx_frame_exists() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut free_tx_frames = VecDeque::new();
    let req = TxRequest {
        bytes: vec![1, 2, 3, 4],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 80,
        cos_queue_id: Some(5),
        dscp_rewrite: None,
        mirror_clone: false,
        enqueue_ns: 0,
    };

    let req = match prepare_local_request_for_cos(&area, &mut free_tx_frames, req) {
        Ok(_) => panic!("must fall back to local"),
        Err(req) => req,
    };

    assert_eq!(req.bytes, [1, 2, 3, 4]);
    assert!(free_tx_frames.is_empty());
}

#[test]
fn cos_queue_accepts_prepared_when_queue_is_prepared_only() {
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
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
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
        }));

    assert!(cos_queue_accepts_prepared(&root, Some(5)));
}

#[test]
fn demote_prepared_cos_queue_to_local_recycles_frames_and_blocks_prepared_appends() {
    let area = MmapArea::new(4096).expect("mmap");
    unsafe { area.slice_mut_unchecked(64, 4) }
        .expect("frame")
        .copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    unsafe { area.slice_mut_unchecked(128, 4) }
        .expect("frame")
        .copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);

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
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
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
            len: 4,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: Some((1111, 5202)),
            expected_addr_family: libc::AF_INET6 as u8,
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
            len: 4,
            recycle: PreparedTxRecycle::FillOnSlot(7),
            expected_ports: Some((1112, 5202)),
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));

    let mut free_tx_frames = VecDeque::from([512]);
    let mut pending_fill_frames = VecDeque::new();
    assert!(demote_prepared_cos_queue_to_local(
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut root,
        Some(5),
        None,
    ));

    let items = root.queues[0]
        .hot
        .items
        .iter()
        .map(|item| match item {
            CoSPendingTxItem::Local(req) => req.bytes.clone(),
            CoSPendingTxItem::Prepared(_) => panic!("prepared item should be demoted"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        items,
        vec![vec![0xde, 0xad, 0xbe, 0xef], vec![0xca, 0xfe, 0xba, 0xbe]]
    );
    assert_eq!(free_tx_frames, VecDeque::from([512, 64]));
    assert_eq!(pending_fill_frames, VecDeque::from([128]));
    assert!(!cos_queue_accepts_prepared(&root, Some(5)));
}

/// #926: regression test for the success-path
/// queue_vtime / head-finish preservation. Prepared items
/// across multiple flows are queued, demoted to Local, and
/// the MQFQ frontier (queue_vtime + per-bucket head/tail
/// finish-times) MUST be unchanged. A new flow Y enqueued
/// immediately after demotion MUST anchor at a finish-time
/// that respects the demoted backlog's frontier — i.e. Y
/// cannot jump ahead of the demoted backlog.
#[test]
fn demote_prepared_cos_queue_to_local_preserves_mqfq_frontier() {
    let area = MmapArea::new(4096).expect("mmap");
    unsafe { area.slice_mut_unchecked(64, 4) }
        .expect("frame")
        .copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    unsafe { area.slice_mut_unchecked(128, 4) }
        .expect("frame")
        .copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);

    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
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

    // Two distinct flows, each one Prepared item. Bucket
    // indices computed under flow_hash_seed=0 for use in
    // post-demote frontier assertions.
    let key_a = test_session_key(8001, 5201);
    let key_b = test_session_key(8002, 5201);
    let bucket_a = cos_flow_bucket_index(0, Some(&key_a));
    let bucket_b = cos_flow_bucket_index(0, Some(&key_b));
    assert_ne!(
        bucket_a, bucket_b,
        "test setup: ports 8001/8002 must hash to distinct buckets"
    );

    cos_queue_push_back(
        queue,
        CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 64,
            len: 1500,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(key_a.clone()),
            egress_ifindex: 42,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }),
    );
    cos_queue_push_back(
        queue,
        CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 128,
            len: 1500,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(key_b.clone()),
            egress_ifindex: 42,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }),
    );

    // Snapshot pre-demote MQFQ frontier.
    let pre_vtime = test_flow_fair_state(queue).queue_vtime;
    let pre_head_a = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a];
    let pre_head_b = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_b];
    let pre_tail_a = test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a];
    let pre_tail_b = test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_b];
    assert!(pre_head_a > 0);
    assert!(pre_head_b > 0);

    // Demote (success path).
    let mut free_tx_frames = VecDeque::from([512]);
    let mut pending_fill_frames = VecDeque::new();
    assert!(demote_prepared_cos_queue_to_local(
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut root,
        Some(4),
        None,
    ));

    let queue = &mut root.queues[0];

    // Frontier MUST be unchanged across the success path.
    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        pre_vtime,
        "#926 regression: queue_vtime must be preserved across \
         demote success path. Pre={pre_vtime} post={}",
        test_flow_fair_state(queue).queue_vtime
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        pre_head_a,
        "#926: head_finish[A] must be preserved (pre={pre_head_a})"
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_b],
        pre_head_b,
        "#926: head_finish[B] must be preserved (pre={pre_head_b})"
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        pre_tail_a,
        "#926: tail_finish[A] must be preserved"
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_b],
        pre_tail_b,
        "#926: tail_finish[B] must be preserved"
    );

    // Items now Local. flow_fair=true stores items in
    // per-bucket VecDeques at `flow_bucket_items[bucket]`,
    // not in `queue.hot.items`.
    let mut total_items = 0;
    for bucket in [bucket_a, bucket_b] {
        for item in test_flow_fair_state(queue).flow_bucket_items[bucket].iter() {
            assert!(
                matches!(item, CoSPendingTxItem::Local(_)),
                "demote should convert Prepared → Local"
            );
            total_items += 1;
        }
    }
    assert_eq!(total_items, 2);

    // The frontier-preservation assertions above are the
    // load-bearing test (Codex code review caught that an
    // earlier "Y does not jump ahead" assertion was
    // logically muddled — without the fix, the four
    // assert_eq calls already FAIL at the queue_vtime / head /
    // tail checks; demote_prepared without snapshot/restore
    // leaves queue_vtime=3000 and head_a=head_b=4500, all
    // mismatching the captured pre-state). The Y-anchor
    // behavior at this scenario is identical with-or-without
    // the fix (Y is small enough to anchor below A/B in
    // both cases) so it's not a useful gate.
}

#[test]
fn demote_prepared_cos_queue_to_local_skips_non_exact_queue() {
    let area = MmapArea::new(4096).expect("mmap");
    unsafe { area.slice_mut_unchecked(64, 4) }
        .expect("frame")
        .copy_from_slice(&[1, 2, 3, 4]);

    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
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
            len: 4,
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
        }));

    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();
    assert!(!demote_prepared_cos_queue_to_local(
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut root,
        Some(5),
        None,
    ));
    assert!(matches!(
        root.queues[0].hot.items.front(),
        Some(CoSPendingTxItem::Prepared(_))
    ));
    assert!(free_tx_frames.is_empty());
    assert!(pending_fill_frames.is_empty());
}

#[test]
fn resolve_cos_queue_id_prefers_egress_output_filter_forwarding_class() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "cos-classify".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                filter_output_v4: "wan-classify".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![
            FirewallFilterSnapshot {
                name: "cos-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    forwarding_class: "best-effort".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "wan-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    forwarding_class: "expedited-forwarding".into(),
                    ..Default::default()
                }],
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
    );

    assert_eq!(queue_id, Some(1));
}

#[test]
fn resolve_cos_queue_id_uses_reverse_output_source_port_filter() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0-0-1.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:61:01".into(),
            filter_output_v4: "bandwidth-output-reverse".into(),
            cos_shaping_rate_bytes_per_sec: 25_000_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "bandwidth-limit".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "bandwidth-output-reverse".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "iperf-a-reverse".into(),
                protocols: vec!["tcp".into()],
                source_ports: vec!["5201".into()],
                action: "accept".into(),
                count: "iperf-a-reverse".into(),
                forwarding_class: "iperf-a".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "iperf-a".into(),
                    queue: 4,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "scheduler-be".into(),
                    transmit_rate_bytes: 100_000_000,
                    transmit_rate_exact: true,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "scheduler-iperf-a".into(),
                    transmit_rate_bytes: 1_000_000_000,
                    transmit_rate_exact: true,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "bandwidth-limit".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "scheduler-be".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "iperf-a".into(),
                        scheduler: "scheduler-iperf-a".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let reverse_data = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 80,
            ingress_vlan_id: 80,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            src_port: 5201,
            dst_port: 49152,
        }),
    );
    let forward_shape_on_reverse_egress = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 80,
            ingress_vlan_id: 80,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            src_port: 49152,
            dst_port: 5201,
        }),
    );

    assert_eq!(reverse_data, Some(4));
    assert_eq!(forward_shape_on_reverse_egress, Some(0));
}

#[test]
fn resolve_cached_cos_tx_selection_prefers_egress_output_filter_and_keeps_counter() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "cos-classify".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                filter_output_v4: "wan-classify".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![
            FirewallFilterSnapshot {
                name: "cos-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    forwarding_class: "best-effort".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "wan-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    count: "wan-hits".into(),
                    forwarding_class: "expedited-forwarding".into(),
                    ..Default::default()
                }],
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let cached = resolve_cached_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
    );

    assert_eq!(cached.queue_id, Some(1));
    assert_eq!(cached.dscp_rewrite, None);
    assert!(!cached.filter_counters.is_empty());
}

#[test]
fn resolve_cos_queue_id_uses_ingress_input_filter_when_no_output_filter_exists() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "cos-classify".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "cos-classify".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "voice".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                forwarding_class: "expedited-forwarding".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
    );

    assert_eq!(queue_id, Some(1));
}

#[test]
fn resolve_cached_cos_tx_selection_uses_ingress_input_filter_when_no_output_exists() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "cos-classify".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "cos-classify".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "voice".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                count: "lan-hits".into(),
                forwarding_class: "expedited-forwarding".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let cached = resolve_cached_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
    );

    assert_eq!(cached.queue_id, Some(1));
    assert_eq!(cached.dscp_rewrite, None);
    assert!(!cached.filter_counters.is_empty());
}

#[test]
fn resolve_cached_cos_tx_selection_keeps_counter_only_output_filter_hits() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-count".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-count".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "count-only".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                count: "wan-hits".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 4_000_000,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let cached = resolve_cached_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
    );

    assert_eq!(cached.queue_id, Some(0));
    assert_eq!(cached.dscp_rewrite, None);
    assert!(!cached.filter_counters.is_empty());
}

#[test]
fn resolve_cos_tx_selection_counts_counter_only_output_filter_hits() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-count".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-count".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "count-only".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                count: "wan-hits".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 4_000_000,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            pkt_len: 1514,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
        TermMatchExtra::default(),
    );

    assert_eq!(selection.queue_id, Some(0));
    assert_eq!(selection.dscp_rewrite, None);

    let filter = forwarding
        .filter_state
        .filters
        .get("inet:wan-count")
        .expect("inet output filter");
    let term = filter.terms.first().expect("first term");
    assert_eq!(term.counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 1514);
}

#[test]
fn resolve_cos_tx_selection_drops_terminal_output_filter_without_log() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-drop".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-drop".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            dscp: 0,
            pkt_len: 1514,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
        TermMatchExtra::default(),
    );

    assert!(selection.drop);
    assert_eq!(selection.queue_id, None);
    assert_eq!(selection.filter_log, None);
}

#[test]
fn resolve_cos_tx_selection_drops_reject_output_filter_without_log() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-reject".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-reject".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "reject-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "reject".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            dscp: 0,
            pkt_len: 1514,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
        TermMatchExtra::default(),
    );

    assert!(selection.drop);
    assert_eq!(selection.queue_id, None);
    assert_eq!(selection.filter_log, None);
}

#[test]
fn resolve_cos_tx_selection_uses_ingress_filter_dscp_rewrite_when_no_output_filter_exists() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "cos-classify".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "cos-classify".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "voice".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                forwarding_class: "expedited-forwarding".into(),
                dscp_rewrite: Some(0),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 46,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
        TermMatchExtra::default(),
    );

    assert_eq!(selection.queue_id, Some(1));
    assert_eq!(selection.dscp_rewrite, Some(0));
}

#[test]
fn resolve_cos_tx_selection_skips_ingress_filter_without_tx_selection_effects() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "sfmix-pbr".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "sfmix-pbr".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "sfmix-route".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                count: "tx-duplicate".into(),
                routing_instance: "sfmix".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 7,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 10_000_000,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            pkt_len: 1500,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
        TermMatchExtra::default(),
    );

    assert_eq!(selection.queue_id, Some(7));
    assert_eq!(selection.dscp_rewrite, None);
    let filter = forwarding
        .filter_state
        .filters
        .get("inet:sfmix-pbr")
        .expect("filter");
    assert_eq!(
        filter.terms[0]
            .counter
            .packets
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn resolve_cos_tx_selection_returns_none_when_no_cos_or_tx_selection_filters_exist() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth1.0".into(),
            ifindex: 101,
            parent_ifindex: 5,
            vlan_id: 0,
            hardware_addr: "02:bf:72:00:61:01".into(),
            filter_input_v4: "sfmix-pbr".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "sfmix-pbr".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "sfmix-route".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                count: "tx-duplicate".into(),
                routing_instance: "sfmix".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            pkt_len: 1500,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
        TermMatchExtra::default(),
    );

    assert_eq!(selection.queue_id, None);
    assert_eq!(selection.dscp_rewrite, None);
    let filter = forwarding
        .filter_state
        .filters
        .get("inet:sfmix-pbr")
        .expect("filter");
    assert_eq!(
        filter.terms[0]
            .counter
            .packets
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn resolve_cos_queue_id_falls_back_to_default_queue_without_filter_match() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 7,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 10_000_000,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 999,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            ..Default::default()
        },
        None,
    );

    assert_eq!(queue_id, Some(7));
}

#[test]
fn resolve_cos_queue_id_uses_dscp_classifier_when_filters_do_not_set_class() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            cos_dscp_classifier: "wan-classifier".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "voice".into(),
                    queue: 5,
                },
            ],
            dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                name: "wan-classifier".into(),
                entries: vec![CoSDSCPClassifierEntrySnapshot {
                    forwarding_class: "voice".into(),
                    loss_priority: "low".into(),
                    dscp_values: vec![46],
                }],
            }],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "voice".into(),
                        scheduler: "voice-sched".into(),
                    },
                ],
            }],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "voice-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
            ],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 999,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 46,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
    );

    assert_eq!(queue_id, Some(5));
}

#[test]
fn resolve_cos_queue_id_uses_ieee8021_classifier_when_filters_do_not_set_class() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            cos_ieee8021_classifier: "wan-pcp".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "voice".into(),
                    queue: 5,
                },
            ],
            ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                name: "wan-pcp".into(),
                entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                    forwarding_class: "voice".into(),
                    loss_priority: "low".into(),
                    code_points: vec![5],
                }],
            }],
            dscp_rewrite_rules: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "voice".into(),
                        scheduler: "voice-sched".into(),
                    },
                ],
            }],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "voice-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 999,
            ingress_vlan_id: 100,
            ingress_pcp: 5,
            ingress_vlan_present: 1,
            addr_family: libc::AF_INET as u8,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
    );

    assert_eq!(queue_id, Some(5));
}

#[test]
fn resolve_cos_queue_id_does_not_use_ieee8021_classifier_for_untagged_packets() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            cos_ieee8021_classifier: "wan-pcp".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "bulk".into(),
                    queue: 3,
                },
            ],
            ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                name: "wan-pcp".into(),
                entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    loss_priority: "low".into(),
                    code_points: vec![0],
                }],
            }],
            dscp_rewrite_rules: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "bulk".into(),
                        scheduler: "bulk-sched".into(),
                    },
                ],
            }],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "bulk-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 999,
            ingress_pcp: 0,
            ingress_vlan_present: 0,
            addr_family: libc::AF_INET as u8,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
    );

    assert_eq!(queue_id, Some(0));
}

// Note on invariant change (replaces the pre-a15a6120 "defaults to iface default" behavior):
// The original shape of this test asserted that an output filter with NO tx-side effect (no
// forwarding_class, no counter) would still shadow the ingress input filter's classification
// and leave egress at the interface default queue.  Commit a15a6120 changed the gating so the
// output filter is skipped entirely when it has neither forwarding_class, dscp_rewrite, nor
// counter terms — matching Junos semantics, where a classify-only output filter that does not
// classify does not clobber upstream classification.  The new invariant asserted below: when
// the output filter has no tx-side effect, ingress input-filter classification is preserved.
#[test]
fn resolve_cos_queue_id_preserves_ingress_classification_when_output_filter_has_no_forwarding_class()
 {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "cos-classify".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                filter_output_v4: "wan-classify".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![
            FirewallFilterSnapshot {
                name: "cos-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    forwarding_class: "expedited-forwarding".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "wan-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "allow".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    ..Default::default()
                }],
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 7,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 10_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 10_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
    );

    // cos-classify on reth1.0 maps expedited-forwarding -> queue 1.  The output filter
    // wan-classify on reth0.0 has no tx-side effect (no forwarding_class, no dscp_rewrite,
    // no counter), so post-a15a6120 it is bypassed and the ingress classification is
    // preserved.  Pre-a15a6120 this was expected to fall through to the iface default queue
    // (best-effort = 7); that contract no longer holds and is captured by this test.
    assert_eq!(queue_id, Some(1));
}

#[test]
fn resolve_cos_tx_selection_preserves_output_filter_dscp_rewrite_without_forwarding_class() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-rewrite".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-rewrite".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "rewrite".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                dscp_rewrite: Some(46),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 7,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 10_000_000,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
        TermMatchExtra::default(),
    );

    assert_eq!(selection.queue_id, Some(7));
    assert_eq!(selection.dscp_rewrite, Some(46));
}

// #1829 Phase 1: `enqueue_cos_item` is the single CoS admission choke
// point and must stamp `enqueue_ns` from the threaded pass `now_ns` on
// every admitted item — the dequeue-side sojourn recorder depends on
// it (an unstamped item is silently skipped, see plan invariant 10).
#[test]
fn enqueue_cos_item_stamps_enqueue_ns_at_admission() {
    let root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 125_000_000,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 4_000_000,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        4,
        vec![(4, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    let now_ns = 777_000_000u64;
    assert!(
        enqueue_cos_item(
            &mut binding,
            42,
            Some(4),
            512,
            test_flow_cos_item(5201, 512),
            now_ns,
            None,
        )
        .is_ok()
    );

    let queue = &binding
        .cos
        .cos_interfaces
        .get(&42)
        .expect("cos interface")
        .queues[0];
    match crate::afxdp::cos::queue_ops::cos_queue_front(queue) {
        Some(CoSPendingTxItem::Local(req)) => assert_eq!(req.enqueue_ns, now_ns),
        Some(CoSPendingTxItem::Prepared(req)) => assert_eq!(req.enqueue_ns, now_ns),
        None => panic!("admitted item must be at the queue front"),
    }
}

// ---------------------------------------------------------------------------
// #2238: classify_generated_reply — output classification of a host-generated
// reply by its OWN egress tuple, fail-CLOSED on a parse failure (§6.2).
// ---------------------------------------------------------------------------

/// Build a minimal untagged IPv4 frame on egress ifindex 202's address pair
/// for the given protocol, with TCP/UDP ports (ignored for ICMP). DSCP via
/// the ToS byte.
fn generated_v4_frame(protocol: u8, tos: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]); // dst mac
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // src mac
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    let l3 = frame.len();
    let l4: Vec<u8> = match protocol {
        PROTO_TCP => {
            let mut v = Vec::new();
            v.extend_from_slice(&src_port.to_be_bytes());
            v.extend_from_slice(&dst_port.to_be_bytes());
            v.extend_from_slice(&[0; 12]); // seq/ack/off-flags/win/csum/urg
            v
        }
        PROTO_UDP => {
            let mut v = Vec::new();
            v.extend_from_slice(&src_port.to_be_bytes());
            v.extend_from_slice(&dst_port.to_be_bytes());
            v.extend_from_slice(&[0; 4]);
            v
        }
        _ => vec![11, 0, 0, 0, 0, 0, 0, 0], // ICMP Time Exceeded
    };
    let total_len = (20 + l4.len()) as u16;
    frame.push(0x45);
    frame.push(tos);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, protocol, 0x00, 0x00]);
    frame.extend_from_slice(&Ipv4Addr::new(172, 16, 80, 8).octets());
    frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets());
    let csum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&csum.to_be_bytes());
    frame.extend_from_slice(&l4);
    frame
}

fn forwarding_with_v4_output_filter(
    filter_name: &str,
    term: FirewallTermSnapshot,
) -> ForwardingState {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: filter_name.into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: filter_name.into(),
            family: "inet".into(),
            terms: vec![term],
        }],
        ..Default::default()
    };
    build_forwarding_state(&snapshot)
}

#[test]
fn classify_generated_reply_drops_icmp_on_terminal_discard() {
    // Output filter `then discard` for `protocol icmp` drops a generated
    // ICMP Time Exceeded reply.
    let forwarding = forwarding_with_v4_output_filter(
        "drop-icmp",
        FirewallTermSnapshot {
            name: "drop-icmp".into(),
            action: "discard".into(),
            protocols: vec!["icmp".into()],
            ..Default::default()
        },
    );
    let frame = generated_v4_frame(PROTO_ICMP, 0x00, 0, 0);
    let verdict = classify_generated_reply(&forwarding, 202, &frame, 0);
    assert!(
        verdict.drop,
        "generated ICMP reply must be dropped by `then discard`"
    );
    assert!(!verdict.parse_error);
}

#[test]
fn classify_generated_reply_ignores_trigger_protocol_filter() {
    // The discriminating test: a filter discarding TCP does NOT drop a
    // generated ICMP reply (proves classify-by-generated-tuple, not trigger).
    let forwarding = forwarding_with_v4_output_filter(
        "drop-tcp",
        FirewallTermSnapshot {
            name: "drop-tcp".into(),
            action: "discard".into(),
            protocols: vec!["tcp".into()],
            ..Default::default()
        },
    );
    let frame = generated_v4_frame(PROTO_ICMP, 0x00, 0, 0);
    let verdict = classify_generated_reply(&forwarding, 202, &frame, 0);
    assert!(
        !verdict.drop,
        "a TCP-matching filter must not drop the generated ICMP reply"
    );
    assert!(!verdict.parse_error);
}

#[test]
fn classify_generated_reply_assigns_forwarding_class_queue() {
    // `then forwarding-class iperf-a` on the egress output filter routes the
    // generated RST to the queue mapped from that forwarding class.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "fc-tcp".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "fc-tcp".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "fc-rst".into(),
                action: "accept".into(),
                protocols: vec!["tcp".into()],
                forwarding_class: "iperf-a".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "iperf-a".into(),
                    queue: 4,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "a".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "iperf-a".into(),
                        scheduler: "a".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);
    let frame = generated_v4_frame(PROTO_TCP, 0x00, 80, 49152);
    let verdict = classify_generated_reply(&forwarding, 202, &frame, 0);
    assert!(!verdict.drop);
    assert_eq!(
        verdict.cos_queue_id,
        Some(4),
        "generated RST routes to the iperf-a queue"
    );
}

#[test]
fn classify_generated_reply_fails_closed_on_parse_failure() {
    // §6.2: a truncated "generated" frame cannot be parsed → fail CLOSED
    // (drop + parse_error), never leak past an output discard.
    let forwarding = forwarding_with_v4_output_filter(
        "drop-icmp",
        FirewallTermSnapshot {
            name: "drop-icmp".into(),
            action: "discard".into(),
            protocols: vec!["icmp".into()],
            ..Default::default()
        },
    );
    // L2 + EtherType only — no L3.
    let frame = vec![
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x00,
    ];
    let verdict = classify_generated_reply(&forwarding, 202, &frame, 0);
    assert!(verdict.drop, "parse failure must fail CLOSED (drop)");
    assert!(
        verdict.parse_error,
        "parse failure must set parse_error so the caller counts it"
    );
    assert_eq!(verdict.cos_queue_id, None);
}

#[test]
fn classify_generated_reply_counterfactual_trigger_keying_would_misverdict() {
    // Counter-factual pin (engineering-style "Test strength"): reconstruct
    // the PRE-#2238 call — classify on the TRIGGER tuple (UDP, the inbound
    // flow) — and show it produces the WRONG verdict for the same fixtures.
    // The egress output filter discards ICMP; the generated reply is ICMP.
    let forwarding = forwarding_with_v4_output_filter(
        "drop-icmp",
        FirewallTermSnapshot {
            name: "drop-icmp".into(),
            action: "discard".into(),
            protocols: vec!["icmp".into()],
            ..Default::default()
        },
    );
    let frame = generated_v4_frame(PROTO_ICMP, 0x00, 0, 0);

    // Correct (#2238): classify the GENERATED ICMP bytes → drop.
    let correct = classify_generated_reply(&forwarding, 202, &frame, 0);
    assert!(correct.drop, "the generated ICMP reply must be dropped");

    // Pre-fix: classify on the TRIGGER tuple (a UDP flow) → NOT dropped,
    // because the `protocol icmp` discard term never matches UDP. This is
    // the exact bug (#2238): the reply leaks past the operator's ICMP
    // discard filter.
    let trigger_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        src_port: 49152,
        dst_port: 53,
    };
    let pre_fix = resolve_cos_tx_selection_at(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_UDP,
            pkt_len: 60,
            ..Default::default()
        },
        Some(&trigger_key),
        TermMatchExtra::default(),
        0,
    );
    assert!(
        !pre_fix.drop,
        "trigger-keyed classification would WRONGLY admit the reply (the #2238 bug)"
    );
}

// ---------------------------------------------------------------------------
// #2330: the POST-TRANSFORM inner-source PTB (NAT64/GRE/WG) must route
// through the SAME classify_generated_reply contract as the #2301/#2328
// egress-MTU PTB — i.e. an output `then discard protocol icmp` drops it, and
// a malformed PTB fails closed. This proves the inner-MTU PTB built by
// build_frag_needed_v4 / build_packet_too_big_v6 from the #2330 site is a
// well-formed, classifiable reply (the finalizer enqueue is shared verbatim
// with #2301, so classification behavior is identical).
// ---------------------------------------------------------------------------

/// Build a real inner-source Frag-Needed PTB (carrying an INNER MTU, the
/// #2330 GRE/WG/NAT64 case) on egress ifindex 202's address pair, using the
/// production builder. The trigger is a 1500-byte inner v4 DF UDP datagram.
fn post_transform_inner_frag_needed_ptb(inner_mtu: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]); // fw mac (becomes PTB src side)
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // sender mac (becomes PTB dst)
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    let l3 = frame.len();
    let total_len = (20 + 8 + 1500) as u16;
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, 17, 0x00, 0x00]); // DF set, UDP
    frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets()); // inner src
    frame.extend_from_slice(&Ipv4Addr::new(172, 16, 80, 200).octets()); // inner dst
    let ip_csum = crate::afxdp::checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&5201u16.to_be_bytes());
    frame.extend_from_slice(&((8 + 1500) as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend(std::iter::repeat(0xABu8).take(1500));

    let meta = UserspaceDpMeta {
        ingress_ifindex: 202,
        l3_offset: l3 as u16,
        l4_offset: (l3 + 20) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: 17,
        ..Default::default()
    };

    let mut fwd = ForwardingState::default();
    fwd.egress.insert(
        202,
        EgressInterface {
            bind_ifindex: 0,
            vlan_id: 0,
            mtu: 1400,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );
    crate::afxdp::build_frag_needed_v4(&frame, meta, 202, &fwd, inner_mtu)
        .expect("inner-source frag-needed must build")
}

#[test]
fn classify_post_transform_inner_ptb_drops_on_terminal_discard() {
    // The #2330 inner-source PTB (advertising a GRE/WG/NAT64 inner MTU)
    // routes through classify_generated_reply exactly like #2328's PTB: an
    // output `then discard protocol icmp` drops it.
    let forwarding = forwarding_with_v4_output_filter(
        "drop-icmp",
        FirewallTermSnapshot {
            name: "drop-icmp".into(),
            action: "discard".into(),
            protocols: vec!["icmp".into()],
            ..Default::default()
        },
    );
    let ptb = post_transform_inner_frag_needed_ptb(1376); // GRE inner MTU
    // Sanity: the built PTB carries the INNER MTU, not the transport MTU.
    let icmp = 14 + 20;
    assert_eq!(ptb[icmp], 3, "ICMP Frag-Needed");
    assert_eq!(
        u16::from_be_bytes([ptb[icmp + 6], ptb[icmp + 7]]),
        1376,
        "PTB advertises the inner MTU"
    );
    let verdict = classify_generated_reply(&forwarding, 202, &ptb, 0);
    assert!(
        verdict.drop,
        "post-transform PTB must honor the output discard filter"
    );
    assert!(
        !verdict.parse_error,
        "a well-formed PTB must NOT fail as a parse error"
    );
}

#[test]
fn classify_post_transform_inner_ptb_admitted_without_filter() {
    // No matching output filter -> the inner PTB is admitted (drop=false),
    // proving classification is keyed on the PTB's own ICMP tuple and the
    // built bytes parse cleanly (so the only drop is an intentional filter).
    let forwarding = forwarding_with_v4_output_filter(
        "drop-tcp",
        FirewallTermSnapshot {
            name: "drop-tcp".into(),
            action: "discard".into(),
            protocols: vec!["tcp".into()],
            ..Default::default()
        },
    );
    let ptb = post_transform_inner_frag_needed_ptb(1325); // WG inner MTU
    let verdict = classify_generated_reply(&forwarding, 202, &ptb, 0);
    assert!(
        !verdict.drop,
        "a TCP-only discard must not drop the ICMP PTB"
    );
    assert!(!verdict.parse_error);
}

// #2362 fold B: the TX-selection / CoS leg must honor a per-packet L4 match
// condition. A `from { tcp-flags syn } then forwarding-class ef` output filter
// selects the EF queue ONLY for a packet whose tcp_flags carry SYN; a non-SYN
// packet of the same 5-tuple falls through to the interface default queue. This
// fails if the TX-selection path reverts to TermMatchExtra::default() (the SYN
// term would never match → no EF selection on any packet → silent under-match).
#[test]
fn resolve_cos_tx_selection_honors_tcp_flags_per_packet_match() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-syn-ef".into(),
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-syn-ef".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "syn-ef".into(),
                protocols: vec!["tcp".into()],
                action: "accept".into(),
                forwarding_class: "expedited-forwarding".into(),
                tcp_flags: Some(0x02), // SYN
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port: 443,
    };
    let meta = || UserspaceDpMeta {
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        pkt_len: 1514,
        protocol: PROTO_TCP,
        ..Default::default()
    };

    // SYN packet -> tcp-flags term matches -> EF (queue 1).
    let syn = resolve_cos_tx_selection(
        &forwarding,
        202,
        meta(),
        Some(&key),
        TermMatchExtra {
            tcp_flags: 0x02,
            l4_present: true,
            ..Default::default()
        },
    );
    assert_eq!(
        syn.queue_id,
        Some(1),
        "SYN must select the EF forwarding-class queue"
    );

    // Pure-ACK packet -> tcp-flags term does NOT match -> interface default queue
    // (queue 0), NOT EF.
    let ack = resolve_cos_tx_selection(
        &forwarding,
        202,
        meta(),
        Some(&key),
        TermMatchExtra {
            tcp_flags: 0x10,
            l4_present: true,
            ..Default::default()
        },
    );
    assert_ne!(
        ack.queue_id,
        Some(1),
        "a non-SYN packet must NOT be classified into the SYN-gated EF queue (#2362 fold B)"
    );
}


// #2621 regression guard: an accepted input firewall-filter whose fall-through
// `then { forwarding-class; dscp; policer; next term; }` classify term precedes
// a terminating `then routing-instance` (PBR) term must still apply the
// forwarding-class queue, DSCP rewrite, AND three-color policer at egress.
//
// codex review-040 finding 040-07 hypothesized the split PBR/non-PBR session-
// miss evaluators (eval.rs `evaluate_filter_ref_non_routing_counted_v4` returns
// `FilterResult::default()` on a matched routing-instance term) DROP these
// modifiers. That FilterResult feeds ONLY the verdict + log on the miss path
// (`NonPbrInputFilterEval` reads action/log_match only — filter.rs:78-154);
// the modifiers are enforced at TX time, where `resolve_cos_tx_selection` and
// `resolve_cached_cos_tx_selection` re-walk the FULL ingress filter via the
// TX-selection evaluators (`tx_selection.rs` / `cache_sensitive.rs`), which
// ACCUMULATE fc/dscp/three-color-policer across every matched fall-through term
// and only return at the terminating routing-instance term (the LAST relevant
// term). So the classify term's modifiers ARE recovered — #2621 is a false
// positive. This test pins that recovery on BOTH the per-packet live path and
// the cached descriptor path; it goes RED if a future change reintroduces the
// split (e.g. the TX-selection evaluator early-returning at the routing-instance
// term before folding the earlier classify term's modifiers).
fn pbr_classify_then_route_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "classify-then-pbr".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "classify-then-pbr".into(),
            family: "inet".into(),
            terms: vec![
                // Fall-through (`next term`) classify term ahead of the PBR
                // term: forwarding-class + dscp rewrite + a single-rate
                // (three-color) policer whose tiny committed rate/burst meters
                // any real packet RED -> drop.
                FirewallTermSnapshot {
                    name: "classify-before-pbr".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    next_term: true,
                    forwarding_class: "expedited-forwarding".into(),
                    dscp_rewrite: Some(46),
                    policer: "trickle".into(),
                    ..Default::default()
                },
                // Terminating PBR term — routing-instance only, no modifiers.
                FirewallTermSnapshot {
                    name: "steer-blue".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    routing_instance: "blue".into(),
                    ..Default::default()
                },
            ],
        }],
        three_color_policers: vec![ThreeColorPolicerSnapshot {
            name: "trickle".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 1,
            peak_or_excess_rate_bytes_per_sec: 0,
            peak_or_excess_burst_bytes: 1,
            then_action: "discard".into(),
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
        }),
        ..Default::default()
    }
}

fn pbr_classify_flow_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port: 443,
    }
}

fn pbr_classify_meta() -> UserspaceDpMeta {
    UserspaceDpMeta {
        ingress_ifindex: 5,
        ingress_vlan_id: 0,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        dscp: 0,
        pkt_len: 1500,
        ..Default::default()
    }
}

#[test]
fn pbr_recovers_classify_modifiers_on_live_tx_selection() {
    // #2621: live (per-packet) TX selection at the PBR-overridden egress must
    // recover the classify term's forwarding-class queue + DSCP rewrite + the
    // three-color policer drop that ride ahead of the routing-instance term.
    let forwarding = build_forwarding_state(&pbr_classify_then_route_snapshot());
    let key = pbr_classify_flow_key();

    // The runtime-counted path actually meters the three-color policer (now_ns
    // present), so its tiny committed burst forces a RED -> drop on a 1500-byte
    // packet — proving the policer modifier is recovered through PBR.
    let metered = resolve_cos_tx_selection_at(
        &forwarding,
        202,
        pbr_classify_meta(),
        Some(&key),
        TermMatchExtra::default(),
        1_000_000_000,
    );
    assert_eq!(
        metered.queue_id,
        Some(1),
        "#2621: forwarding-class -> EF queue must survive the PBR term"
    );
    assert_eq!(
        metered.dscp_rewrite,
        Some(46),
        "#2621: dscp rewrite must survive the PBR term"
    );
    assert!(
        metered.drop,
        "#2621: three-color policer drop must survive the PBR term"
    );
}

#[test]
fn pbr_recovers_classify_modifiers_on_cached_tx_selection() {
    // #2621: the cached descriptor TX selection (flow-cache hit replay) must
    // also recover the classify term's forwarding-class queue + DSCP rewrite
    // ahead of the routing-instance term. (The cached path carries the policer
    // runtimes for cache-hit metering but does not meter at build time, so this
    // arm pins the queue + DSCP recovery; the live arm above pins the drop.)
    let forwarding = build_forwarding_state(&pbr_classify_then_route_snapshot());
    let key = pbr_classify_flow_key();

    let cached = resolve_cached_cos_tx_selection(&forwarding, 202, pbr_classify_meta(), Some(&key));
    assert_eq!(
        cached.queue_id,
        Some(1),
        "#2621: cached forwarding-class -> EF queue must survive the PBR term"
    );
    assert_eq!(
        cached.dscp_rewrite,
        Some(46),
        "#2621: cached dscp rewrite must survive the PBR term"
    );
}
