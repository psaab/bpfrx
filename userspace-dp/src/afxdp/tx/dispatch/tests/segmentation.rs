// #1282 TCP-segmentation / segmentation-miss tests for the dispatch path:
// `forwarded_tcp_may_need_segmentation`, the seg-miss counter
// (`count_forwarded_tcp_segmentation_miss_if_needed`), and the
// operator-visible seg-miss recorder (`record_forwarded_tcp_segmentation_miss`,
// rate-capped). Local fixtures `test_decision` / `test_binding_identity`.

use super::*;

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

fn test_binding_identity() -> BindingIdentity {
    BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("reth1.0"),
        ifindex: 11,
    }
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
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
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
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
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
    // The #1282 cap stops *exception generation* at 20 (the 5 over-cap
    // calls return before `record_exception`, so `cap` never exceeds 20).
    // #5289 adds a second bound: the per-(reason,5-tuple) sampler collapses
    // this identical seg-miss flood to a SINGLE ring entry, so the operator
    // sees one representative `tcp_segmentation_miss` rather than 20 copies.
    // Both bounds ensure a pathological per-packet seg-miss cannot thrash
    // the ring on the hot path.
    let ring = recent_exceptions.lock().expect("lock");
    assert_eq!(
        ring.len(),
        1,
        "the #5289 sampler collapses the identical seg-miss flood to one entry",
    );
    assert_eq!(
        ring.back().expect("entry").reason(),
        "tcp_segmentation_miss",
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
    // #5141: the gate now admits on the IP-DECLARED datagram length, not the
    // raw backing length, so the frame needs a valid IPv4 header whose
    // `total_len` declares an oversized (>MTU) datagram. total_len = 1600 with
    // ihl=20; backing = 14 + 1600 matches the declaration (no slack).
    let mut frame = vec![0u8; 14 + 1600];
    frame[14] = 0x45; // IPv4, ihl=5 (20 bytes)
    let total_len: u16 = 1600;
    frame[16] = (total_len >> 8) as u8;
    frame[17] = total_len as u8;
    frame[23] = PROTO_TCP; // protocol (cosmetic; gate uses meta.protocol)
    assert!(forwarded_tcp_may_need_segmentation(
        &frame,
        meta,
        &test_decision(),
        &forwarding,
    ));
}

#[test]
fn forwarded_tcp_may_need_segmentation_uses_declared_len_not_backing() {
    // #5141 admission-clamp sentinel: a frame whose BACKING (14 + 1600) exceeds
    // the 1500 MTU but whose IPv4 `total_len` declares only a 1400-byte
    // datagram (200 trailing slack bytes) must NOT be admitted for
    // segmentation — the declared datagram fits within the MTU. The pre-#5141
    // gate compared `frame.len() - l3 > mtu` on the backing length and would
    // (wrongly) flag it, then the builder would clamp and refuse: a spurious
    // `tcp_segmentation_miss`. RED-on-revert: restoring the backing-length
    // compare makes this assertion fail (returns true).
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        ..UserspaceDpMeta::default()
    };
    let mut frame = vec![0u8; 14 + 1600];
    frame[14] = 0x45; // IPv4, ihl=5 (20 bytes)
    let declared_total_len: u16 = 1400; // < MTU: the true datagram fits
    frame[16] = (declared_total_len >> 8) as u8;
    frame[17] = declared_total_len as u8;
    frame[23] = PROTO_TCP;
    assert!(
        !forwarded_tcp_may_need_segmentation(&frame, meta, &test_decision(), &forwarding),
        "admission must read the IP-declared length, not the backing slack"
    );
}

// #5148 RED-on-revert: a FIRST IPv4 fragment (MF=1, offset 0) carries a real
// TCP header at the post-IP offset, so the pre-#5148 non-first-only gate
// (`is_non_first_fragment`, mask 0x1FFF over the offset bits only) treated it
// as "not a fragment" and ADMITTED it into the segmentation builders — which
// then cloned the fragment-bearing IP header (Identification / MF / offset)
// into every output while rewriting seq/checksum, emitting overlapping
// offset-0 pseudo-fragments. The fix uses `is_any_fragment` (mask 0x3FFF =
// MF+offset), so an over-MTU FIRST fragment is now rejected from segmentation.
// Reverting the gate to `is_non_first_fragment` makes this assertion fail
// (the gate returns true and admits the fragment).
#[test]
fn forwarded_tcp_may_need_segmentation_rejects_first_ipv4_fragment() {
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        ..UserspaceDpMeta::default()
    };
    // Same oversized IPv4 datagram as `..._flags_oversized_frame` (total_len
    // 1600 > MTU 1500), but MF=1 marks it the FIRST fragment of a larger
    // datagram. The gate must NOT admit it for TCP segmentation.
    let mut frame = vec![0u8; 14 + 1600];
    frame[14] = 0x45; // IPv4, ihl=5 (20 bytes)
    let total_len: u16 = 1600;
    frame[16] = (total_len >> 8) as u8;
    frame[17] = total_len as u8;
    frame[20] = 0x20; // flags: MF=1, fragment offset 0 → a FIRST fragment
    frame[23] = PROTO_TCP;
    assert!(
        !forwarded_tcp_may_need_segmentation(&frame, meta, &test_decision(), &forwarding),
        "a first IPv4 fragment (MF=1) must never be admitted for TCP segmentation"
    );
}

// #5148 RED-on-revert: an IPv6 packet carrying a Fragment extension header
// (next-header 44) — even the FIRST fragment (offset 0, M=1) — must never be
// TCP-segmented. The pre-#5148 gate (`ipv6_is_non_first_fragment`, which
// requires the offset bits to be non-zero) treated a first fragment as "not a
// fragment" and admitted it. `is_any_fragment` triggers on the Fragment header
// itself regardless of offset. Reverting the gate makes this assertion fail.
#[test]
fn forwarded_tcp_may_need_segmentation_rejects_ipv6_fragment_header() {
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        ..UserspaceDpMeta::default()
    };
    // IPv6 base header declaring an oversized datagram (payload_len 1600 →
    // 40 + 1600 = 1640 > MTU 1500), next-header = 44 (Fragment). The 8-byte
    // fragment header that follows is a FIRST fragment (offset 0, M=1),
    // next-header TCP.
    let mut frame = vec![0u8; 14 + 40 + 1600];
    frame[12] = 0x86;
    frame[13] = 0xdd; // IPv6 ethertype
    frame[14] = 0x60; // version 6
    let payload_len: u16 = 1600;
    frame[18] = (payload_len >> 8) as u8;
    frame[19] = payload_len as u8;
    frame[20] = 44; // next-header: Fragment extension header
    frame[21] = 64; // hop limit
    // Fragment header at frame[54..62]: next-header TCP, offset 0, M=1.
    frame[54] = PROTO_TCP;
    frame[57] = 0x01; // M (more-fragments) bit; fragment offset 0
    assert!(
        !forwarded_tcp_may_need_segmentation(&frame, meta, &test_decision(), &forwarding),
        "an IPv6 packet with a Fragment header must never be admitted for TCP segmentation"
    );
}
