//! queue_service submit tests: submit_local/submit_prepared owner
//! tx-counter bumps and flow-fair local-scratch offset recycling.

use super::*;

// #hb166 T-7: the flow-fair local scratch None arms (queue torn down
// mid-drain) must recycle the popped `free_tx_frames` UMEM offsets, not
// leak them. Pre-fix they bare-`.clear()`ed the scratch, unlike the FIFO
// sibling `settle_exact_local_fifo_submission`. RED-on-revert: the
// recycled offsets stay absent from `free_tx_frames`.
fn t7_local_scratch_entry(offset: u64, len: usize) -> (u64, TxRequest) {
    (
        offset,
        TxRequest {
            bytes: vec![0u8; len],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        },
    )
}

#[test]
fn settle_local_scratch_flow_fair_recycles_offsets_when_queue_gone() {
    let mut free_tx_frames: VecDeque<u64> = VecDeque::new();
    let mut scratch_local_tx: Vec<(u64, TxRequest)> =
        vec![t7_local_scratch_entry(64, 4), t7_local_scratch_entry(128, 4)];
    let (packets, bytes) = settle_exact_local_scratch_submission_flow_fair(
        None,
        &mut free_tx_frames,
        &mut scratch_local_tx,
        0,
        0,
    );
    assert_eq!((packets, bytes), (0, 0));
    assert!(scratch_local_tx.is_empty(), "scratch must be drained");
    let mut recycled: Vec<u64> = free_tx_frames.into_iter().collect();
    recycled.sort_unstable();
    assert_eq!(
        recycled,
        vec![64, 128],
        "both UMEM offsets must be recycled to free_tx_frames, not leaked"
    );
}

#[test]
fn restore_local_scratch_flow_fair_recycles_offsets_when_queue_gone() {
    let mut free_tx_frames: VecDeque<u64> = VecDeque::new();
    let mut scratch_local_tx: Vec<(u64, TxRequest)> =
        vec![t7_local_scratch_entry(64, 4), t7_local_scratch_entry(128, 4)];
    restore_exact_local_scratch_to_queue_head_flow_fair(
        None,
        &mut free_tx_frames,
        &mut scratch_local_tx,
    );
    assert!(scratch_local_tx.is_empty(), "scratch must be drained");
    let mut recycled: Vec<u64> = free_tx_frames.into_iter().collect();
    recycled.sort_unstable();
    assert_eq!(
        recycled,
        vec![64, 128],
        "both UMEM offsets must be recycled to free_tx_frames, not leaked"
    );
}

// #4282 part (a): owner-lifecycle TX accounting lock on the CoS submit
// paths. A CoS-forwarded packet MUST bump the owner binding's
// `live.tx_packets` / `live.tx_bytes` exactly like the non-CoS backup
// drain path (`tx/drain/phase_backup.rs`), or `show interfaces` and the
// Prometheus TX gauges undercount every shaped byte.
//
// Verification at HEAD found the accounting already present on all CoS
// ship paths — this is a regression LOCK, not a fix. Every CoS-submit
// settle boundary funnels through exactly one of three `fetch_add`
// sites:
//   1. `submit_local`  — the non-exact CoSBatch::Local batched submit.
//   2. `submit_prepared` — the non-exact CoSBatch::Prepared submit.
//   3. `apply_direct_exact_send_result` — the single funnel for the
//      four exact direct-service settle sites in `service.rs`
//      (local|prepared × FIFO|flow-fair).
// The three tests below pin the (tx_packets, tx_bytes) pair on each,
// so a future refactor that drops the counter goes RED on revert.

/// FAIL-ON-REVERT: neutering either `binding.live.tx_packets` /
/// `tx_bytes` `fetch_add` in `submit_local`'s Ok arm leaves the counter
/// at 0 and the matching assert fails.
#[test]
fn submit_local_bumps_owner_tx_packets_and_bytes() {
    let now_ns = 1_000_000_000u64;
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: true,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    root.tokens = 10_000;
    root.queues[0].hot.tokens = 10_000;
    root.queues[0].hot.queued_bytes = 300;

    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    // Three 100-byte items, all fully shipped through the test TX ring
    // in a single transmit_batch call (TX_BATCH_SIZE == 64).
    let items: VecDeque<TxRequest> = (0..3)
        .map(|_| TxRequest {
            bytes: vec![0u8; 100],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: now_ns,
        })
        .collect();
    let mut shared_recycles = Vec::new();

    let progress = submit_local(
        &mut binding,
        42,
        0,
        CoSServicePhase::Surplus,
        300,
        items,
        now_ns,
        &mut shared_recycles,
    );
    assert!(
        progress,
        "submit_local must report progress on a full commit"
    );

    assert_eq!(
        binding
            .live
            .tx_packets
            .load(std::sync::atomic::Ordering::Relaxed),
        3,
        "submit_local must bump owner tx_packets by the committed packet count",
    );
    assert_eq!(
        binding
            .live
            .tx_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        300,
        "submit_local must bump owner tx_bytes by the committed byte count",
    );
}

/// FAIL-ON-REVERT: neutering either `binding.live.tx_packets` /
/// `tx_bytes` `fetch_add` in `submit_prepared`'s Ok arm leaves the
/// counter at 0 and the matching assert fails.
#[test]
fn submit_prepared_bumps_owner_tx_packets_and_bytes() {
    let now_ns = 1_000_000_000u64;
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: true,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    root.tokens = 10_000;
    root.queues[0].hot.tokens = 10_000;
    root.queues[0].hot.queued_bytes = 250;

    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    // Two prepared items whose frames live in the binding's own UMEM.
    // Production allocates a prepared frame OUT of the free pool, so
    // remove those two offsets from free_tx_frames to mirror that and
    // avoid double-ownership of the frame.
    let specs = [
        (40u64 << UMEM_FRAME_SHIFT, 100u32),
        (41u64 << UMEM_FRAME_SHIFT, 150u32),
    ];
    for (offset, len) in specs {
        let frame = unsafe {
            binding
                .umem
                .area()
                .slice_mut_unchecked(offset as usize, len as usize)
        }
        .expect("umem frame slice");
        frame.fill(0);
    }
    binding
        .tx_pipeline
        .free_tx_frames
        .retain(|&off| off != specs[0].0 && off != specs[1].0);

    let items: VecDeque<PreparedTxRequest> = specs
        .iter()
        .map(|&(offset, len)| PreparedTxRequest {
            offset,
            len,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: now_ns,
        })
        .collect();
    let mut shared_recycles = Vec::new();

    let progress = submit_prepared(
        &mut binding,
        42,
        0,
        CoSServicePhase::Surplus,
        250,
        items,
        now_ns,
        &mut shared_recycles,
    );
    assert!(
        progress,
        "submit_prepared must report progress on a full commit"
    );

    assert_eq!(
        binding
            .live
            .tx_packets
            .load(std::sync::atomic::Ordering::Relaxed),
        2,
        "submit_prepared must bump owner tx_packets by the committed packet count",
    );
    assert_eq!(
        binding
            .live
            .tx_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        250,
        "submit_prepared must bump owner tx_bytes by the committed byte count",
    );
}

/// FAIL-ON-REVERT: removing either `binding.live.tx_packets` /
/// `tx_bytes` `fetch_add` in `apply_direct_exact_send_result` leaves the
/// counter at 0. This is the single owner-TX accounting funnel for all
/// four exact direct-service settle sites in `service.rs`.
#[test]
fn apply_direct_exact_send_result_bumps_owner_tx_packets_and_bytes() {
    let root = test_cos_interface_runtime(0);
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    crate::afxdp::cos::tx_completion::apply_direct_exact_send_result(&mut binding, 42, 0, 4, 6_000);

    assert_eq!(
        binding
            .live
            .tx_packets
            .load(std::sync::atomic::Ordering::Relaxed),
        4,
        "direct-exact settle funnel must bump owner tx_packets",
    );
    assert_eq!(
        binding
            .live
            .tx_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        6_000,
        "direct-exact settle funnel must bump owner tx_bytes",
    );
}

