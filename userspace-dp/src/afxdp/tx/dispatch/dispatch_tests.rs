// Tests for afxdp/tx/dispatch.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep dispatch.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "dispatch_tests.rs"]` from dispatch.rs.

use super::*;
use crate::afxdp::tx::test_support::{build_ipv4_test_packet, test_session_key};
use crate::test_zone_ids::*;
use arc_swap::ArcSwap;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};

fn test_forwarding_with_egress_mtu(mtu: usize) -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );
    forwarding
}
fn test_decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 80,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    }
}

fn test_forwarding_decision_to_bound_ifindex(tx_ifindex: i32) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 80,
            tx_ifindex,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    }
}

fn test_pending_forward_request(
    addr_family: u8,
    cos_tx_selection_resolved: bool,
) -> PendingForwardRequest {
    PendingForwardRequest {
        target_ifindex: 11,
        target_binding_index: None,
        ingress_queue_id: 0,
        desc: XdpDesc {
            addr: 0,
            len: 64,
            options: 0,
        },
        frame: PendingForwardFrame::Live,
        meta: ForwardPacketMeta {
            addr_family,
            ..ForwardPacketMeta::default()
        },
        decision: test_decision(),
        apply_nat_on_fabric: false,
        expected_ports: None,
        flow_key: None,
        nat64_reverse: None,
        cos_queue_id: None,
        dscp_rewrite: None,
        cos_tx_selection_resolved,
        filter_match_extra: crate::filter::TermMatchExtra::default(),
    }
}

fn test_live_forward_request_for_frame(
    frame_len: usize,
    decision: SessionDecision,
) -> PendingForwardRequest {
    PendingForwardRequest {
        target_ifindex: decision.resolution.tx_ifindex,
        target_binding_index: None,
        ingress_queue_id: 0,
        desc: XdpDesc {
            addr: 0,
            len: frame_len as u32,
            options: 0,
        },
        frame: PendingForwardFrame::Live,
        meta: ForwardPacketMeta {
            ingress_ifindex: 11,
            l3_offset: 14,
            l4_offset: 34,
            pkt_len: frame_len as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..ForwardPacketMeta::default()
        },
        decision,
        apply_nat_on_fabric: false,
        expected_ports: None,
        flow_key: Some(test_session_key(12345, 443)),
        nat64_reverse: None,
        cos_queue_id: None,
        dscp_rewrite: None,
        cos_tx_selection_resolved: true,
        filter_match_extra: crate::filter::TermMatchExtra::default(),
    }
}

fn test_cos_fast_interfaces(
    egress_ifindex: i32,
    default_queue: u8,
    shared_exact_queues: &[(u8, bool)],
) -> FastMap<i32, WorkerCoSInterfaceFastPath> {
    // Legacy fixture: shared_exact AND shared_queue_lease set together.
    // For the post-#1598 decoupled case where a queue can be
    // shared_exact=true with NO lease (non-exact uncapped class), use
    // `test_cos_fast_interfaces_decoupled` below.
    let decoupled: Vec<(u8, bool, bool)> = shared_exact_queues
        .iter()
        .copied()
        .map(|(queue_id, shared_exact)| (queue_id, shared_exact, shared_exact))
        .collect();
    test_cos_fast_interfaces_decoupled(egress_ifindex, default_queue, &decoupled)
}

fn test_cos_fast_interfaces_decoupled(
    egress_ifindex: i32,
    default_queue: u8,
    queues: &[(u8, bool, bool)],
) -> FastMap<i32, WorkerCoSInterfaceFastPath> {
    // Each tuple: (queue_id, shared_exact, has_lease).
    // The pair (true, false) models the #1598 non-exact uncapped case:
    // the routing-level shared_exact flag is set, but the
    // exact-only `shared_queue_lease` is absent.
    let mut queue_index_by_id = [COS_FAST_QUEUE_INDEX_MISS; 256];
    let mut queue_fast_path = Vec::new();
    for (idx, (queue_id, shared_exact, has_lease)) in queues.iter().copied().enumerate() {
        queue_index_by_id[usize::from(queue_id)] = idx as u16;
        queue_fast_path.push(WorkerCoSQueueFastPath {
            shared_exact,
            owner_worker_id: 0,
            owner_live: None,
            shared_queue_lease: has_lease
                .then(|| Arc::new(SharedCoSQueueLease::new(1_250_000_000, 256 * 1024, 2))),
            vtime_floor: None,
        });
    }
    let mut interfaces = FastMap::default();
    interfaces.insert(
        egress_ifindex,
        WorkerCoSInterfaceFastPath {
            tx_ifindex: 11,
            default_queue_index: queue_index_by_id[usize::from(default_queue)] as usize,
            queue_index_by_id,
            tx_owner_live: None,
            shared_root_lease: None,
            shared_exact_backlog: None,
            queue_fast_path,
        },
    );
    interfaces
}

#[test]
fn pending_forward_cos_resolution_uses_resolved_bit_not_empty_outputs() {
    let resolved = test_pending_forward_request(libc::AF_INET as u8, true);
    assert!(
        !pending_forward_needs_cos_tx_selection(&resolved, true, false),
        "a resolved None/None selection must not be metered again"
    );

    let unresolved_v4 = test_pending_forward_request(libc::AF_INET as u8, false);
    assert!(pending_forward_needs_cos_tx_selection(
        &unresolved_v4,
        true,
        false
    ));

    let unresolved_v6 = test_pending_forward_request(libc::AF_INET6 as u8, false);
    assert!(pending_forward_needs_cos_tx_selection(
        &unresolved_v6,
        false,
        true
    ));
}

#[test]
fn forwarded_tcp_may_need_segmentation_skips_mtu_sized_frame() {
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        ..UserspaceDpMeta::default()
    };
    let frame = vec![0u8; 14 + 1500];
    assert!(!forwarded_tcp_may_need_segmentation(
        &frame,
        meta,
        &test_decision(),
        &forwarding,
    ));
}

#[test]
fn forwarded_tcp_may_need_segmentation_uses_frame_vlan_offset_over_stale_meta() {
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        // Stale metadata shape observed in #1282: the live frame is VLAN
        // tagged, but metadata still points at a 14-byte Ethernet header.
        l3_offset: 14,
        ..UserspaceDpMeta::default()
    };
    let mut frame = vec![0u8; 18 + 1500];
    frame[12] = 0x81;
    frame[13] = 0x00;
    frame[16] = 0x08;
    frame[17] = 0x00;

    assert!(!forwarded_tcp_may_need_segmentation(
        &frame,
        meta,
        &test_decision(),
        &forwarding,
    ));
}

#[test]
fn segmentation_miss_counter_skips_mtu_sized_vlan_frame_with_stale_meta() {
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        ..UserspaceDpMeta::default()
    };
    let mut frame = vec![0u8; 18 + 1500];
    frame[12] = 0x81;
    frame[13] = 0x00;
    frame[16] = 0x08;
    frame[17] = 0x00;
    let tcp_segmentation_needed =
        forwarded_tcp_may_need_segmentation(&frame, meta, &test_decision(), &forwarding);
    let mut dbg = DebugPollCounters::default();

    assert!(!count_forwarded_tcp_segmentation_miss_if_needed(
        &mut dbg,
        false,
        tcp_segmentation_needed,
    ));
    assert_eq!(dbg.seg_needed_but_none, 0);
}

fn test_binding_identity() -> BindingIdentity {
    BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("reth1.0"),
        ifindex: 11,
    }
}

// #1282: a genuine segmentation miss must surface to operators in
// release builds. Before the fix the only signal was the
// `pub(in crate::afxdp)` counter `seg_needed_but_none` (never exported to
// Go/CLI) plus an ungated `DBG SEG_MISS` eprintln. The eprintln is now
// `debug-log`-only, so the durable signal must be the recorded exception.
// This test recreates the failure mode: it drives the seg-miss recorder
// and proves a `tcp_segmentation_miss` exception lands in the
// operator-visible `recent_exceptions` buffer.
#[test]
fn segmentation_miss_records_operator_visible_exception() {
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let request =
        test_live_forward_request_for_frame(1518, test_forwarding_decision_to_bound_ifindex(11));
    let ingress_ident = test_binding_identity();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let source_frame = vec![0u8; 1518];
    let cap = std::cell::Cell::new(0u32);

    record_forwarded_tcp_segmentation_miss(
        &cap,
        &recent_exceptions,
        &ingress_ident,
        &source_frame,
        &request,
        &forwarding,
    );

    let recent = recent_exceptions.lock().expect("lock");
    assert_eq!(recent.len(), 1, "exactly one exception recorded");
    let exc = recent.front().expect("recorded exception");
    assert_eq!(exc.reason, "tcp_segmentation_miss");
    assert_eq!(exc.packet_length, 1518);
    assert_eq!(cap.get(), 1, "rate-cap counter advanced");
}

// #1282: the recorder must be rate-capped so a pathological per-packet
// seg-miss cannot spin the `recent_exceptions` mutex on the hot path.
// After 20 records the recorder is a no-op; the recent buffer also has
// its own retention cap, so we assert the recorder stops incrementing the
// cap counter and stops pushing new entries past the threshold.
#[test]
fn segmentation_miss_recorder_is_rate_capped() {
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let request =
        test_live_forward_request_for_frame(1518, test_forwarding_decision_to_bound_ifindex(11));
    let ingress_ident = test_binding_identity();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let source_frame = vec![0u8; 1518];
    let cap = std::cell::Cell::new(0u32);

    // 25 calls; only the first 20 may record.
    for _ in 0..25 {
        record_forwarded_tcp_segmentation_miss(
            &cap,
            &recent_exceptions,
            &ingress_ident,
            &source_frame,
            &request,
            &forwarding,
        );
    }

    assert_eq!(cap.get(), 20, "cap counter saturates at 20");
    // The cap must also stop *exception generation*, not just the
    // counter: prove only 20 exceptions were recorded across 25 calls,
    // so the 5 over-cap calls never reached `record_exception` (and thus
    // never locked the `recent_exceptions` mutex on the hot path).
    assert_eq!(
        recent_exceptions.lock().expect("lock").len(),
        20,
        "no exceptions recorded past the cap — the 5 over-cap calls never \
         locked the recent_exceptions mutex",
    );
}

#[test]
fn segmentation_miss_counter_truth_table() {
    let cases = [
        (false, true, true, 1),
        (true, true, false, 0),
        (true, false, false, 0),
        (false, false, false, 0),
    ];

    for (copied_source_frame, tcp_segmentation_needed, expected_counted, expected_counter) in cases
    {
        let mut dbg = DebugPollCounters::default();

        assert_eq!(
            count_forwarded_tcp_segmentation_miss_if_needed(
                &mut dbg,
                copied_source_frame,
                tcp_segmentation_needed,
            ),
            expected_counted,
        );
        assert_eq!(dbg.seg_needed_but_none, expected_counter);
    }
}

#[test]
fn forwarded_tcp_may_need_segmentation_flags_oversized_frame() {
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        ..UserspaceDpMeta::default()
    };
    let frame = vec![0u8; 14 + 1600];
    assert!(forwarded_tcp_may_need_segmentation(
        &frame,
        meta,
        &test_decision(),
        &forwarding,
    ));
}

#[test]
fn shared_recycle_target_uses_lookup_when_slot_matches() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 1);
    let slots = [10, 20, 30];

    assert_eq!(
        shared_recycle_target_index(slots.len(), &lookup, 20, |idx| slots.get(idx).copied()),
        Some(1)
    );
}

#[test]
fn shared_recycle_target_scans_when_lookup_is_stale_or_wrong_slot() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 1);
    let slots = [10, 99, 20];

    assert_eq!(
        shared_recycle_target_index(slots.len(), &lookup, 20, |idx| slots.get(idx).copied()),
        Some(2)
    );
}

#[test]
fn shared_recycle_target_drops_unknown_or_out_of_range_slot() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 99);
    let slots = [10, 30];

    assert_eq!(
        shared_recycle_target_index(slots.len(), &lookup, 20, |idx| slots.get(idx).copied()),
        None
    );
}

fn test_split_slot_at(
    left: &[u32],
    current_index: usize,
    current_slot: u32,
    right: &[u32],
    target_index: usize,
) -> Option<u32> {
    if target_index == current_index {
        return Some(current_slot);
    }
    if target_index < current_index {
        return left.get(target_index).copied();
    }
    right
        .get(target_index.saturating_sub(current_index + 1))
        .copied()
}

#[test]
fn shared_recycle_split_target_scans_when_lookup_is_stale() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 1);
    let left = [10, 99];
    let current_index = 2;
    let current_slot = 30;
    let right = [20, 40];

    assert_eq!(
        shared_recycle_target_index_for_split(left.len(), right.len(), &lookup, 20, |idx| {
            test_split_slot_at(&left, current_index, current_slot, &right, idx)
        }),
        Some(3)
    );
}

#[test]
fn shared_recycle_split_target_drops_unknown_slot() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 9);
    let left = [10, 30];
    let current_index = 2;
    let current_slot = 40;
    let right = [50, 60];

    assert_eq!(
        shared_recycle_target_index_for_split(left.len(), right.len(), &lookup, 20, |idx| {
            test_split_slot_at(&left, current_index, current_slot, &right, idx)
        }),
        None
    );
}

#[test]
fn shared_recycle_unknown_slot_drop_increments_tx_errors() {
    let live = BindingLiveState::new();

    record_shared_recycle_unknown_slot_drops(Some(&live), 2);
    record_shared_recycle_unknown_slot_drops(Some(&live), 0);
    record_shared_recycle_unknown_slot_drops(None, 5);

    assert_eq!(live.tx_errors.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(
        live.tx_shared_recycle_unknown_slot_drops
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
}

#[test]
fn enqueue_pending_forwards_mirrors_live_frame_and_records_counter() {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        BindingWorker::new_for_mirror_test(2, 0, 33, 0),
    ];
    let original_frame = build_ipv4_test_packet(0);
    unsafe {
        bindings[0]
            .umem
            .area()
            .slice_mut_unchecked(0, original_frame.len())
    }
    .expect("ingress frame")
    .copy_from_slice(&original_frame);

    let mut forwarding = test_forwarding_with_egress_mtu(1500);
    forwarding.mirror_configs.insert(
        11,
        MirrorRuntimeConfig {
            output_ifindex: 33,
            rate: 0,
        },
    );
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut pending = vec![test_live_forward_request_for_frame(
        original_frame.len(),
        test_forwarding_decision_to_bound_ifindex(22),
    )];
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();
    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");

    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut BatchCounters::default(),
        0,
        &worker_commands_by_id,
    );

    assert_eq!(bindings[0].live.mirrored_packets.load(Ordering::Relaxed), 1);
    assert_eq!(
        bindings[0].live.mirrored_bytes.load(Ordering::Relaxed),
        original_frame.len() as u64
    );
    let mirror_req = bindings[2]
        .tx_pipeline
        .pending_tx_prepared
        .front()
        .expect("mirror prepared request");
    assert!(mirror_req.mirror_clone);
    assert_eq!(mirror_req.egress_ifindex, 33);
    assert_eq!(
        bindings[2]
            .umem
            .area()
            .slice(mirror_req.offset as usize, mirror_req.len as usize)
            .expect("mirrored frame"),
        original_frame.as_slice(),
    );
    let forwarded_req = bindings[1]
        .tx_pipeline
        .pending_tx_prepared
        .front()
        .expect("forwarded prepared request");
    assert!(!forwarded_req.mirror_clone);
}

/// #1946: a Prebuilt FabricRedirect frame (e.g. an embedded-ICMP
/// NAT-reversed error whose resolution turned into a fabric redirect)
/// that is unsendable to the peer because the fabric parent has no XSK
/// binding must be dropped fail-closed AND counted on
/// `fabric_redirect_unsendable_drops` — not silently recycled. Drives the
/// Prebuilt no-binding arm of `enqueue_pending_forwards`.
#[test]
fn enqueue_pending_forwards_counts_prebuilt_fabric_redirect_no_binding() {
    let mut bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 11, 0)];
    let mut forwarding = test_forwarding_with_egress_mtu(1500);
    forwarding.fabrics.clear();
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();

    // Target ifindex 4242 has no binding in `lookup`, so
    // resolve_pending_forward_target_binding returns None.
    let mut decision = test_forwarding_decision_to_bound_ifindex(4242);
    decision.resolution.disposition = ForwardingDisposition::FabricRedirect;
    let mut request = test_live_forward_request_for_frame(64, decision);
    request.frame = PendingForwardFrame::Prebuilt(vec![0u8; 64]);
    let mut pending = vec![request];

    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();
    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");

    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut BatchCounters::default(),
        0,
        &worker_commands_by_id,
    );

    assert_eq!(
        bindings[0]
            .live
            .fabric_redirect_unsendable_drops
            .load(Ordering::Relaxed),
        1
    );
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|entry| entry.reason.clone())
        .collect();
    assert_eq!(reasons, vec!["fabric_redirect_no_binding"]);
}

// ---------------------------------------------------------------------------
// #2208: the dispatch copy paths must recycle the ingress UMEM descriptor on
// EVERY exit. Four bare `continue;` statements (cp1/cp2 oversized + cp1/cp2
// enqueue-failure) jumped to the next loop iteration before the finalizer,
// permanently leaking the ingress descriptor (it never reached the fill ring)
// and — for the enqueue-failure sites — also skipping the slow-path reinject
// the `build_failed=true; fallback_to_slow_path=true` flags requested.
//
// These tests drive `enqueue_pending_forwards` through the cp2 copy fallback
// (target on a separate UMEM with an empty free_tx_frames pool forces the
// NoFreeTxFrame → Vec-copy branch) and assert:
//   (a) the ingress descriptor IS returned to circulation exactly once
//       (fill-ring pending + pending_fill_frames == 1, never 0 or 2);
//   (b) the enqueue-failure path runs handle_forward_build_failure
//       (dbg.build_fail bumped) AND its slow-path reinject
//       (slow_path_drops bumped, since the test passes slow_path=None so the
//        reinject lands on `slow_path_unavailable`);
//   (c) the oversized path recycles but does NOT reinject (the frame is
//       undeliverable) — build_fail bumped, slow_path_drops untouched.
//
// Against the pre-fix bare `continue;` (a) is 0 (leak) and (b)/(c) never fire.

/// Count ingress descriptors returned to circulation: those submitted to the
/// fill ring plus any still queued in `pending_fill_frames`. Each forwarded
/// request must contribute exactly one — 0 is a leak, 2 is a double-recycle.
fn ingress_recycled_count(ingress: &BindingWorker) -> usize {
    ingress.xsk.device.pending() as usize + ingress.tx_pipeline.pending_fill_frames.len()
}

/// RAII guard that resets the #2208 fault-injection thread-locals so a
/// panicking assertion cannot leak state into the next test on the same
/// thread.
struct ForceFaultGuard;
impl Drop for ForceFaultGuard {
    fn drop(&mut self) {
        super::cos::FORCE_ENQUEUE_ERR.with(|c| c.set(false));
        super::FORCE_OVERSIZED.with(|c| c.set(false));
    }
}

/// Build a two-binding harness (ingress slot 0 / ifindex 11, egress slot 1 /
/// ifindex 22) with a valid IPv4 frame in the ingress UMEM at offset 0 and the
/// egress binding's `free_tx_frames` drained so dispatch is forced down the
/// cp2 Vec-copy fallback. Returns everything `enqueue_pending_forwards` needs.
fn cp2_copy_fallback_harness() -> (Vec<BindingWorker>, Vec<u8>) {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    let original_frame = build_ipv4_test_packet(0);
    unsafe {
        bindings[0]
            .umem
            .area()
            .slice_mut_unchecked(0, original_frame.len())
    }
    .expect("ingress frame")
    .copy_from_slice(&original_frame);
    // Drain the egress free-TX pool: with no direct-TX frame available the
    // dispatcher falls back to the Vec copy path (cp2), which is where the
    // enqueue/oversized #2208 sites live.
    bindings[1].tx_pipeline.free_tx_frames.clear();
    (bindings, original_frame)
}

#[test]
fn enqueue_failure_recycles_ingress_descriptor_and_reinjects_slow_path() {
    let _guard = ForceFaultGuard;
    let (mut bindings, original_frame) = cp2_copy_fallback_harness();
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut pending = vec![test_live_forward_request_for_frame(
        original_frame.len(),
        test_forwarding_decision_to_bound_ifindex(22),
    )];
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();

    // Force the cp2 enqueue to fail (owner queue full / TX congestion).
    super::cos::FORCE_ENQUEUE_ERR.with(|c| c.set(true));

    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");
    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None, // slow_path: None → reinject lands on slow_path_unavailable
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut BatchCounters::default(),
        0,
        &worker_commands_by_id,
    );

    // (a) ingress descriptor recycled exactly once — the pre-fix `continue;`
    // leaked it (would be 0).
    assert_eq!(
        ingress_recycled_count(&bindings[0]),
        1,
        "ingress descriptor must be recycled exactly once on enqueue failure"
    );
    // (b) handle_forward_build_failure ran (build_fail) AND it reinjected to
    // the slow path (slow_path_drops, since slow_path=None). The pre-fix
    // `continue;` skipped both even though it set the build-failure flags.
    assert_eq!(dbg.build_fail, 1, "build-failure handler must run");
    assert_eq!(
        bindings[0].live.slow_path_drops.load(Ordering::Relaxed),
        1,
        "fallback_to_slow_path must reach the slow-path reinject"
    );
    // No successful TX was counted.
    assert_eq!(dbg.enqueue_ok, 0, "no TX enqueue succeeded");
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|e| e.reason.clone())
        .collect();
    assert!(
        reasons.iter().any(|r| r == "forward_build_failed"),
        "build-failure exception recorded: {reasons:?}"
    );
    assert!(
        reasons.iter().any(|r| r == "slow_path_unavailable"),
        "slow-path reinject attempted (unavailable here): {reasons:?}"
    );
}

#[test]
fn oversized_forward_frame_recycles_ingress_descriptor_without_reinject() {
    let _guard = ForceFaultGuard;
    let (mut bindings, original_frame) = cp2_copy_fallback_harness();
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut pending = vec![test_live_forward_request_for_frame(
        original_frame.len(),
        test_forwarding_decision_to_bound_ifindex(22),
    )];
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();

    // Force the built cp2 frame to be treated as oversized (undeliverable).
    super::FORCE_OVERSIZED.with(|c| c.set(true));

    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");
    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut BatchCounters::default(),
        0,
        &worker_commands_by_id,
    );

    // (a) recycled exactly once — the pre-fix `continue;` leaked it.
    assert_eq!(
        ingress_recycled_count(&bindings[0]),
        1,
        "ingress descriptor must be recycled exactly once on oversized frame"
    );
    // (c) build-failure handler ran but did NOT reinject — an oversized frame
    // is undeliverable, so slow_path_drops stays 0.
    assert_eq!(dbg.build_fail, 1, "build-failure handler must run");
    assert_eq!(
        bindings[0].live.slow_path_drops.load(Ordering::Relaxed),
        0,
        "oversized frame must NOT be reinjected to the slow path"
    );
    assert_eq!(dbg.enqueue_ok, 0, "no TX enqueue succeeded");
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|e| e.reason.clone())
        .collect();
    assert!(
        reasons.iter().any(|r| r == "oversized_forward_frame"),
        "oversized exception recorded: {reasons:?}"
    );
    assert!(
        !reasons.iter().any(|r| r == "slow_path_unavailable"),
        "no slow-path reinject for an oversized frame: {reasons:?}"
    );
}

#[test]
fn enqueue_failure_conserves_free_frames_across_many_forwards() {
    // Descriptor-conservation check: under sustained enqueue failure (TX
    // congestion) every ingress descriptor must return to circulation. The
    // pre-fix `continue;` leaked one per failed forward → pool exhaustion.
    let _guard = ForceFaultGuard;
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    let original_frame = build_ipv4_test_packet(0);
    // Lay the same frame down at N distinct ingress UMEM offsets and drive N
    // requests, each referencing its own descriptor.
    const N: usize = 16;
    let mut pending = Vec::with_capacity(N);
    for i in 0..N {
        let offset = (i as u64) << super::UMEM_FRAME_SHIFT;
        unsafe {
            bindings[0]
                .umem
                .area()
                .slice_mut_unchecked(offset as usize, original_frame.len())
        }
        .expect("ingress frame")
        .copy_from_slice(&original_frame);
        let mut req = test_live_forward_request_for_frame(
            original_frame.len(),
            test_forwarding_decision_to_bound_ifindex(22),
        );
        req.desc.addr = offset;
        pending.push(req);
    }
    bindings[1].tx_pipeline.free_tx_frames.clear();

    let forwarding = test_forwarding_with_egress_mtu(1500);
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();

    super::cos::FORCE_ENQUEUE_ERR.with(|c| c.set(true));

    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");
    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut BatchCounters::default(),
        0,
        &worker_commands_by_id,
    );

    assert_eq!(
        ingress_recycled_count(&bindings[0]),
        N,
        "every ingress descriptor must be recycled exactly once — no leak, \
         no double-recycle"
    );
    assert_eq!(
        dbg.build_fail as usize, N,
        "every forward hit build failure"
    );
    assert_eq!(
        bindings[0].live.slow_path_drops.load(Ordering::Relaxed) as usize,
        N,
        "every failed forward reinjected to the slow path"
    );
}

// #2301: end-to-end egress-MTU PTB through `enqueue_pending_forwards`.
//
// Build a large UDP IPv4 (DF) frame in the ingress UMEM, point the forward
// at egress ifindex 80 with a SMALL MTU, and add an egress entry for the
// INGRESS interface (ifindex 11) so the reflected reply can be sourced.
// The dispatcher must:
//   - enqueue an ICMP Frag-Needed (type 3 code 4, next-hop MTU) back out
//     the ingress binding,
//   - NOT forward the oversized original to the egress binding,
//   - recycle the ingress descriptor exactly once,
//   - record the `egress_mtu_exceeded` exception.
// The counter-factual (large MTU) proves the gate fires only on a real MTU
// violation: the frame forwards normally and no PTB lands on the ingress.

/// Build a large IPv4 UDP frame (Ethernet + IP + UDP + payload) with the
/// DF bit set. `l3_payload` is the total L3 length excluding the 14-byte
/// Ethernet header.
fn large_udp_v4_df_frame(l3_payload: usize) -> Vec<u8> {
    assert!(l3_payload >= 28, "need room for IP+UDP headers");
    let mut frame = Vec::with_capacity(14 + l3_payload);
    // L2: dst = firewall NIC, src = sender. EtherType IPv4.
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    frame.extend_from_slice(&[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    let l3 = frame.len();
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&(l3_payload as u16).to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01]); // ID
    frame.extend_from_slice(&0x4000u16.to_be_bytes()); // DF=1
    frame.extend_from_slice(&[64, 17, 0x00, 0x00]); // TTL, proto UDP, csum
    frame.extend_from_slice(&[198, 51, 100, 20]); // src
    frame.extend_from_slice(&[203, 0, 113, 9]); // dst
    let csum = crate::afxdp::tx::test_support::compute_ipv4_header_checksum(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&csum.to_be_bytes());
    // UDP header + payload to fill out to l3_payload.
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&5201u16.to_be_bytes());
    frame.extend_from_slice(&((l3_payload - 20) as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.resize(14 + l3_payload, 0xAB);
    frame
}

/// Forwarding state for the PTB e2e test: egress 80 with `mtu`, plus an
/// egress entry for the ingress interface (ifindex 11) carrying a primary
/// v4 so the reflected error can be built.
fn forwarding_for_ptb(mtu: usize) -> ForwardingState {
    let mut forwarding = test_forwarding_with_egress_mtu(mtu);
    forwarding.egress.insert(
        11,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x16, 0x00, 0x01],
            zone_id: TEST_TRUST_ZONE_ID,
            redundancy_group: 0,
            primary_v4: Some(std::net::Ipv4Addr::new(10, 0, 1, 1)),
            primary_v6: None,
        },
    );
    forwarding
}

fn run_ptb_dispatch(egress_mtu: usize) -> (Vec<BindingWorker>, DebugPollCounters, Vec<String>) {
    let (bindings, dbg, _counters, reasons) =
        run_ptb_dispatch_with_forwarding(forwarding_for_ptb(egress_mtu));
    (bindings, dbg, reasons)
}

/// #2328: PTB e2e harness parameterized on the full `ForwardingState` so a
/// test can install an output firewall filter / CoS classifier on the egress
/// (ingress-reflected) interface (ifindex 11) and observe the generated PTB
/// being classified by its OWN egress tuple. Returns the `BatchCounters` so
/// the fail-on-revert tests can assert the generated-reply drop counters.
fn run_ptb_dispatch_with_forwarding(
    forwarding: ForwardingState,
) -> (
    Vec<BindingWorker>,
    DebugPollCounters,
    BatchCounters,
    Vec<String>,
) {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    // 1600-byte L3 payload -> 1614-byte frame. Fits a 4096 UMEM frame but
    // exceeds a 1400 egress MTU.
    let frame = large_udp_v4_df_frame(1600);
    unsafe { bindings[0].umem.area().slice_mut_unchecked(0, frame.len()) }
        .expect("ingress frame")
        .copy_from_slice(&frame);

    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    // UDP (not TCP) so the TCP-segmentation path is skipped and the
    // egress-MTU decision is the only oversized handler.
    let mut req = test_live_forward_request_for_frame(
        frame.len(),
        test_forwarding_decision_to_bound_ifindex(22),
    );
    req.meta.protocol = PROTO_UDP;
    req.meta.l3_offset = 14;
    req.meta.l4_offset = 34;
    req.meta.pkt_len = (frame.len() - 14) as u16;
    let mut pending = vec![req];
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();
    let mut counters = BatchCounters::default();

    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");
    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut counters,
        0,
        &worker_commands_by_id,
    );
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|e| e.reason.clone())
        .collect();
    (bindings, dbg, counters, reasons)
}

#[test]
fn oversized_forward_emits_ptb_and_drops_original() {
    let (bindings, _dbg, reasons) = run_ptb_dispatch(1400);

    // PTB enqueued back out the INGRESS binding (slot 0).
    let ingress_tx = &bindings[0].tx_pipeline.pending_tx_local;
    assert_eq!(
        ingress_tx.len(),
        1,
        "exactly one ICMP Frag-Needed must be enqueued on the ingress binding"
    );
    let reply = &ingress_tx[0];
    assert_eq!(
        reply.egress_ifindex, 11,
        "PTB leaves via the ingress interface"
    );
    let b = &reply.bytes;
    assert_eq!(
        &b[0..6],
        &[0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        "reflected to the sender"
    );
    assert_eq!(&b[12..14], &[0x08, 0x00], "IPv4 reply");
    assert_eq!(b[14], 0x45);
    assert_eq!(b[23], PROTO_ICMP, "outer ICMP");
    let icmp = 14 + 20;
    assert_eq!(b[icmp], 3, "ICMP type 3");
    assert_eq!(b[icmp + 1], 4, "code 4 (Frag Needed)");
    assert_eq!(
        u16::from_be_bytes([b[icmp + 6], b[icmp + 7]]),
        1400,
        "advertised next-hop MTU"
    );

    // The oversized original was NOT forwarded to the egress binding.
    assert_eq!(
        bindings[1].tx_pipeline.pending_tx_local.len(),
        0,
        "oversized original must not be forwarded"
    );
    assert_eq!(
        bindings[1].tx_pipeline.pending_tx_prepared.len(),
        0,
        "oversized original must not be prepared for the egress TX ring"
    );
    // Ingress descriptor recycled exactly once (no leak, no double).
    assert_eq!(ingress_recycled_count(&bindings[0]), 1);
    assert!(
        reasons.iter().any(|r| r == "egress_mtu_exceeded"),
        "egress-MTU exception recorded: {reasons:?}"
    );
    // The original was NOT silently dropped without a signal: no
    // oversized_forward_frame / slow-path drop was recorded.
    assert!(
        !reasons.iter().any(|r| r == "oversized_forward_frame"),
        "MTU drop must not be miscounted as a descriptor-capacity overflow: {reasons:?}"
    );
}

#[test]
fn in_mtu_forward_emits_no_ptb_counterfactual() {
    // Same 1614-byte frame, but a 9000 (jumbo) egress MTU. The frame now
    // fits, so it forwards normally and NO PTB lands on the ingress. This
    // is the fail-on-revert pin: if the decision wrongly fired on an
    // in-MTU frame, the ingress would carry a spurious ICMP error.
    let (bindings, _dbg, reasons) = run_ptb_dispatch(9000);
    assert_eq!(
        bindings[0].tx_pipeline.pending_tx_local.len(),
        0,
        "no PTB may be generated for an in-MTU frame"
    );
    assert!(
        !reasons.iter().any(|r| r == "egress_mtu_exceeded"),
        "no egress-MTU exception for an in-MTU frame: {reasons:?}"
    );
    // The frame was actually forwarded to the egress binding (slot 1),
    // proving the in-MTU fast path is untouched.
    let egress_tx = bindings[1].tx_pipeline.pending_tx_local.len()
        + bindings[1].tx_pipeline.pending_tx_prepared.len();
    assert_eq!(
        egress_tx, 1,
        "in-MTU frame must forward to the egress binding"
    );
}

/// #2328: build a v4 output firewall filter on the PTB egress interface
/// (ifindex 11 — the ingress interface the PTB is reflected back out of)
/// carrying a single term, and splice it onto `forwarding_for_ptb`. The
/// trigger frame is UDP, so a term keyed on `protocol icmp` fires ONLY for
/// the GENERATED ICMP Frag-Needed reply — proving classify-by-the-PTB's-own
/// egress tuple, not the UDP trigger tuple.
fn forwarding_for_ptb_with_output_term(
    mtu: usize,
    term: crate::FirewallTermSnapshot,
) -> ForwardingState {
    let mut forwarding = forwarding_for_ptb(mtu);
    forwarding.filter_state = crate::filter::parse_filter_state(
        &[crate::FirewallFilterSnapshot {
            name: "ptb-out".into(),
            family: "inet".into(),
            terms: vec![term],
        }],
        &[],
        &[crate::InterfaceSnapshot {
            name: "ge-0/0/0.0".into(),
            ifindex: 11,
            filter_output_v4: "ptb-out".into(),
            ..Default::default()
        }],
        "",
        "",
    );
    forwarding.tx_selection_enabled_v4 = true;
    forwarding
}

/// #2328: an OUTPUT firewall filter `then discard` matching `protocol icmp`
/// on the PTB egress interface drops the GENERATED Frag-Needed reply — the
/// PTB is now classified by its own egress tuple (#2238 contract parity with
/// Time Exceeded / policy-reject / SYN-cookie). The drop lands on the
/// dedicated `ptb_output_filter_drops` counter. Fail-on-revert: if the PTB
/// enqueue reverts to the pre-#2328 unclassified `cos_queue_id: None,
/// dscp_rewrite: None` (no `classify_generated_reply` call), the PTB would be
/// enqueued and this assertion fails.
#[test]
fn ptb_dropped_by_egress_output_filter_discard() {
    let (bindings, _dbg, counters, reasons) =
        run_ptb_dispatch_with_forwarding(forwarding_for_ptb_with_output_term(
            1400,
            crate::FirewallTermSnapshot {
                name: "drop-icmp".into(),
                action: "discard".into(),
                protocols: vec!["icmp".into()],
                ..Default::default()
            },
        ));
    // The generated PTB was DROPPED (not enqueued) by the output `discard`.
    assert_eq!(
        bindings[0].tx_pipeline.pending_tx_local.len(),
        0,
        "an output `then discard` (protocol icmp) on the egress interface must drop the generated PTB"
    );
    // Drop attributed to the dedicated PTB counter, not the parse-error one.
    assert!(
        counters.ptb_output_filter_drops >= 1,
        "output-filter drop of the PTB must land on ptb_output_filter_drops"
    );
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
    // The oversized original is still dropped (PMTUD), and the descriptor is
    // recycled exactly once — no leak past the fail-closed drop.
    assert_eq!(bindings[1].tx_pipeline.pending_tx_local.len(), 0);
    assert_eq!(bindings[1].tx_pipeline.pending_tx_prepared.len(), 0);
    assert_eq!(ingress_recycled_count(&bindings[0]), 1);
    assert!(reasons.iter().any(|r| r == "egress_mtu_exceeded"));
}

/// #2328: an output filter matching the UDP TRIGGER tuple does NOT drop the
/// generated ICMP PTB — discriminating proof the PTB is classified by its
/// OWN (ICMP) egress tuple, not the trigger's (UDP). Sibling of the Time
/// Exceeded `ignores_trigger_matching_output_filter` test.
#[test]
fn ptb_ignores_trigger_matching_output_filter() {
    let (bindings, _dbg, counters, _reasons) =
        run_ptb_dispatch_with_forwarding(forwarding_for_ptb_with_output_term(
            1400,
            crate::FirewallTermSnapshot {
                name: "drop-udp".into(),
                action: "discard".into(),
                protocols: vec!["udp".into()],
                ..Default::default()
            },
        ));
    assert_eq!(
        bindings[0].tx_pipeline.pending_tx_local.len(),
        1,
        "an output filter matching the UDP trigger must NOT drop the generated ICMP PTB"
    );
    assert_eq!(counters.ptb_output_filter_drops, 0);
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
}

/// #2328: a forwarding-class / DSCP-rewrite output filter matching the
/// generated PTB's ICMP tuple sets the enqueued PTB TxRequest's
/// `dscp_rewrite` from the classifier verdict — NOT the pre-#2328
/// hard-coded `None`. Fail-on-revert: reverting the PTB enqueue to
/// `dscp_rewrite: None` makes the asserted rewrite disappear.
#[test]
fn ptb_dscp_rewrite_comes_from_classifier_not_none() {
    let (bindings, _dbg, counters, _reasons) =
        run_ptb_dispatch_with_forwarding(forwarding_for_ptb_with_output_term(
            1400,
            crate::FirewallTermSnapshot {
                name: "mark-icmp".into(),
                action: "accept".into(),
                protocols: vec!["icmp".into()],
                dscp_rewrite: Some(46),
                ..Default::default()
            },
        ));
    let ptb = &bindings[0].tx_pipeline.pending_tx_local;
    assert_eq!(ptb.len(), 1, "PTB accepted (then accept) and enqueued");
    assert_eq!(
        ptb[0].dscp_rewrite,
        Some(46),
        "the PTB TxRequest dscp_rewrite must come from classify_generated_reply, not None"
    );
    assert_eq!(counters.ptb_output_filter_drops, 0);
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
}

/// #2328 §6.2 fail-CLOSED canary: the PTB path routes a generated-reply parse
/// failure through `classify_generated_reply`, which returns
/// `drop: true, parse_error: true` for bytes it cannot re-parse. The
/// dispatch wiring maps that verdict onto
/// `generated_reply_classify_parse_errors` and drops the PTB (never leaking
/// it past an output `discard`). This pins the shared mechanism the PTB
/// enqueue depends on: truncated/malformed reply bytes fail closed.
#[test]
fn ptb_parse_failure_fails_closed_with_parse_error_verdict() {
    let forwarding = forwarding_for_ptb(1400);
    // Bytes too short for an L3 header — frame_l3_offset / the v4 parser
    // reject them, exactly the canary a malformed PTB builder would hit.
    let malformed: Vec<u8> = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let verdict = classify_generated_reply(&forwarding, 11, &malformed, 1);
    assert!(
        verdict.drop,
        "unparseable generated bytes must fail CLOSED (drop)"
    );
    assert!(
        verdict.parse_error,
        "the drop must be attributed as a parse error so the PTB path bumps generated_reply_classify_parse_errors"
    );
    assert_eq!(verdict.cos_queue_id, None);
    assert_eq!(verdict.dscp_rewrite, None);
}

#[test]
fn shared_exact_policy_uses_requested_queue_id() {
    let cos_fast_interfaces = test_cos_fast_interfaces(80, 5, &[(5, true)]);

    assert!(request_runs_under_shared_exact_policy(
        &cos_fast_interfaces,
        80,
        Some(5),
    ));
    assert!(!request_runs_under_shared_exact_policy(
        &cos_fast_interfaces,
        80,
        Some(4),
    ));
}

#[test]
fn shared_exact_policy_uses_interface_default_queue() {
    let cos_fast_interfaces = test_cos_fast_interfaces(80, 5, &[(5, true)]);

    assert!(request_runs_under_shared_exact_policy(
        &cos_fast_interfaces,
        80,
        None,
    ));
}

#[test]
fn shared_exact_policy_admits_non_exact_uncapped_queue_without_lease() {
    // #1598 secondary fix: non-exact uncapped queues run under
    // `shared_exact = true` (from worker/cos/mod.rs:126-131) but have
    // NO `shared_queue_lease` (filtered out at coordinator/mod.rs:1058
    // because `!queue.exact`). The TX-dispatch path must keep these
    // requests local rather than funneling them to a single
    // owner_worker_id; that is precisely the failure mode that the
    // smoke run caught (port 5211 push P=12 capped at ~9 Gbps even
    // after the primary fix).
    let cos_fast_interfaces = test_cos_fast_interfaces_decoupled(
        80,
        11,
        // queue 11: shared_exact = true, has_lease = false (uncapped class)
        &[(11, true, false)],
    );

    assert!(
        request_runs_under_shared_exact_policy(&cos_fast_interfaces, 80, Some(11)),
        "#1598: non-exact uncapped queue with shared_exact=true must \
         signal 'stay local' to the TX dispatch, even with no lease"
    );
    // Verify the state divergence at the source — `shared_exact=true`
    // AND `shared_queue_lease=None` is the post-#1598 production shape
    // that the previous lease-as-proxy gate mis-classified. This pin
    // ensures the test fixture actually models the failure mode (not
    // a coincidental shape that happens to pass the new helper).
    let iface_fast = cos_fast_interfaces.get(&80).expect("iface fixture");
    let queue_fast = iface_fast
        .queue_fast_path(Some(11))
        .expect("queue 11 fixture");
    assert!(
        queue_fast.shared_exact,
        "#1598 fixture invariant: queue 11 must have shared_exact=true"
    );
    assert!(
        queue_fast.shared_queue_lease.is_none(),
        "#1598 fixture invariant: queue 11 must have shared_queue_lease=None \
         to model the non-exact uncapped class"
    );
}

#[test]
fn shared_exact_policy_rejects_single_owner_queue() {
    // Single-owner queue (low-rate exact or non-exact below threshold)
    // has shared_exact = false. The policy helper must return false so
    // the dispatch path routes to owner_worker_id (the intended
    // single-FIFO arbitration domain for low-rate classes — #680/#690).
    let cos_fast_interfaces = test_cos_fast_interfaces_decoupled(
        80,
        1,
        // queue 1: shared_exact = false, has_lease = true (this would be
        // a hypothetical legacy state — verify the helper still says no)
        &[(1, false, true)],
    );
    assert!(
        !request_runs_under_shared_exact_policy(&cos_fast_interfaces, 80, Some(1)),
        "#1598: shared_exact=false must keep the request funnel-routed \
         to the queue owner regardless of lease presence"
    );
}

#[test]
fn shared_exact_policy_handles_unknown_queue() {
    // Defensive: a request whose `cos_queue_id` does not resolve in
    // the fast-path table must return false (the dispatch path falls
    // back to single-owner / local TX). This mirrors the existing
    // is_some_and shape on the lease-only helper.
    let cos_fast_interfaces = test_cos_fast_interfaces_decoupled(80, 5, &[(5, true, true)]);
    assert!(
        !request_runs_under_shared_exact_policy(&cos_fast_interfaces, 80, Some(42)),
        "an unknown queue_id must not be reported as shared_exact policy"
    );
    assert!(
        !request_runs_under_shared_exact_policy(&cos_fast_interfaces, 999, Some(5)),
        "an unknown egress_ifindex must not be reported as shared_exact policy"
    );
}
