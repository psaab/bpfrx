//! S4 — TCP segmentation properties (#1824 plan §5.3-S4).
//!
//! `segment_forwarded_tcp_frames_from_frame` is pure
//! (`&[u8] → Option<Vec<Vec<u8>>>`) modulo a fixture `ForwardingState`
//! for the MTU lookup and a `SessionDecision`.
//!
//! P-T1 no-panic, P-T2 reassembly identity, P-T3 per-segment
//! wellformedness (bounds, seq arithmetic incl. u32 wrap, PSH
//! handling, IP length fields, P-N2 oracle checksums, segment count),
//! P-T4 NAT composition. v6 inputs include ext-header chains
//! (re-admitted when #1838 was fixed): each segment copies the full
//! IP header incl. the ext chain, the payload-length field counts the
//! ext bytes, and `apply_nat_ipv6` / `recompute_l4_checksum_ipv6`
//! receive the threaded ext-aware offset.
//!
//! The UMEM-coupled twin (`tx/tcp_segmentation.rs::…_into_prepared`)
//! is out of scope (needs a BindingWorker/tx_pipeline harness) — plan
//! §10 follow-up.

use super::oracle::oracle_packet_valid;
use super::strategies::{
    arb_garbage_frame, arb_meta, arb_nat, arb_seg_packet, arb_vlan, ValidPacket, AF4,
};
use super::*;

const TCP_PSH: u8 = 0x08;

fn seg_fixture(mtu: usize, tx_vlan: u16) -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: tx_vlan,
            mtu,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );
    forwarding
}

fn seg_decision(next_hop: IpAddr, tx_vlan: u16, nat: NatDecision) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(next_hop),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: tx_vlan,
        },
        nat,
    }
}

/// The wire tuple a segment must carry after the NAT decision.
struct ExpectedTuple {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
}

fn expected_tuple(pkt: &ValidPacket, nat: NatDecision) -> ExpectedTuple {
    ExpectedTuple {
        src_ip: nat.rewrite_src.unwrap_or(pkt.src_ip),
        dst_ip: nat.rewrite_dst.unwrap_or(pkt.dst_ip),
        src_port: nat.rewrite_src_port.unwrap_or(pkt.src_port),
        dst_port: nat.rewrite_dst_port.unwrap_or(pkt.dst_port),
    }
}

/// P-T2 + P-T3 (+ tuple checks for P-T4): every wellformedness
/// invariant over a segment list.
fn check_segments(
    segs: &[Vec<u8>],
    pkt: &ValidPacket,
    mtu: usize,
    tx_vlan: u16,
    want: &ExpectedTuple,
) -> Result<(), TestCaseError> {
    let eth_out = if tx_vlan > 0 { 18usize } else { 14usize };
    let ip_hdr = pkt.rel_l4; // v4: IHL preserved; v6: 40 + ext chain
    let tcp_hdr = pkt.l4_header_len;
    let seg_max = mtu - ip_hdr - tcp_hdr;
    let data_len = pkt.payload_len;
    prop_assert_eq!(segs.len(), data_len.div_ceil(seg_max), "segment count");

    let orig = &pkt.frame;
    let orig_seq = u32::from_be_bytes([
        orig[pkt.l4() + 4],
        orig[pkt.l4() + 5],
        orig[pkt.l4() + 6],
        orig[pkt.l4() + 7],
    ]);
    let orig_flags = orig[pkt.l4() + 13];
    let orig_ttl = orig[pkt.l3 + if pkt.addr_family == AF4 { 8 } else { 7 }];
    let orig_payload = &orig[pkt.l4() + tcp_hdr..];

    let mut reassembled = Vec::with_capacity(data_len);
    let mut cumulative = 0usize;
    for (idx, seg) in segs.iter().enumerate() {
        let is_last = idx + 1 == segs.len();
        let chunk = (data_len - cumulative).min(seg_max);
        prop_assert_eq!(seg.len(), eth_out + ip_hdr + tcp_hdr + chunk, "segment length");
        prop_assert!(seg.len() <= eth_out + mtu, "segment exceeds MTU");

        let packet = &seg[eth_out..];
        // IP length fields consistent with the segment.
        if pkt.addr_family == AF4 {
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            prop_assert_eq!(total, ip_hdr + tcp_hdr + chunk, "v4 total_len");
            prop_assert_eq!(packet[8], orig_ttl - 1, "v4 TTL decremented once");
            prop_assert_eq!(
                (
                    Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
                    Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
                ),
                (
                    match want.src_ip { IpAddr::V4(v) => v, _ => unreachable!() },
                    match want.dst_ip { IpAddr::V4(v) => v, _ => unreachable!() },
                ),
                "v4 tuple"
            );
        } else {
            let plen = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            // #1838 §5.3: the payload-length field counts the copied
            // ext-chain bytes (ip_hdr - 40) plus TCP header + chunk.
            prop_assert_eq!(plen, (ip_hdr - 40) + tcp_hdr + chunk, "v6 payload_len");
            prop_assert_eq!(packet[7], orig_ttl - 1, "v6 hop limit decremented once");
            prop_assert_eq!(
                (
                    Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()),
                    Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()),
                ),
                (
                    match want.src_ip { IpAddr::V6(v) => v, _ => unreachable!() },
                    match want.dst_ip { IpAddr::V6(v) => v, _ => unreachable!() },
                ),
                "v6 tuple"
            );
        }

        let tcp = &packet[ip_hdr..];
        prop_assert_eq!(
            u16::from_be_bytes([tcp[0], tcp[1]]),
            want.src_port,
            "src port"
        );
        prop_assert_eq!(
            u16::from_be_bytes([tcp[2], tcp[3]]),
            want.dst_port,
            "dst port"
        );
        // seq_i == orig_seq + cumulative offset (mod 2^32).
        prop_assert_eq!(
            u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
            orig_seq.wrapping_add(cumulative as u32),
            "sequence number"
        );
        // PSH cleared on all but the last segment; other flags kept.
        let want_flags = if is_last {
            orig_flags
        } else {
            orig_flags & !TCP_PSH
        };
        prop_assert_eq!(tcp[13], want_flags, "TCP flags");

        // Full checksum oracle per segment (P-N2 — NOT the v4-TCP-only
        // verify_built_frame_checksums).
        let verdict = oracle_packet_valid(packet, pkt.addr_family, PROTO_TCP, ip_hdr, false);
        prop_assert!(verdict.is_ok(), "segment {} checksums: {:?}", idx, verdict);

        reassembled.extend_from_slice(&tcp[tcp_hdr..]);
        cumulative += chunk;
    }
    // P-T2: reassembly identity.
    prop_assert_eq!(reassembled.len(), orig_payload.len(), "reassembled length");
    prop_assert!(reassembled == orig_payload, "reassembled payload differs");
    Ok(())
}

proptest! {
    #![proptest_config(super::cfg(256))]

    /// P-T1: the splitter never panics on garbage frames × arbitrary
    /// metadata × fixture forwarding state.
    #[test]
    fn segmentation_no_panic_on_garbage(
        frame in arb_garbage_frame(),
        meta in arb_meta(),
        mtu in 1280usize..=9216,
        tx_vlan in arb_vlan(),
        expected in proptest::option::of((any::<u16>(), any::<u16>())),
    ) {
        let forwarding = seg_fixture(mtu, tx_vlan);
        let decision = seg_decision(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            tx_vlan,
            NatDecision::default(),
        );
        let _ = segment_forwarded_tcp_frames_from_frame(
            &frame, meta, &decision, &forwarding, false, expected,
        );
    }

    /// P-T2 + P-T3: no NAT — split, then verify reassembly identity
    /// and every per-segment invariant.
    #[test]
    fn segmentation_reassembles_identically(
        (pkt, mtu) in arb_seg_packet(),
        tx_vlan in arb_vlan(),
    ) {
        let forwarding = seg_fixture(mtu, tx_vlan);
        let decision = seg_decision(pkt.dst_ip, tx_vlan, NatDecision::default());
        let segs = segment_forwarded_tcp_frames_from_frame(
            &pkt.frame, pkt.meta, &decision, &forwarding, false, None,
        ).expect("oversized valid TCP frame must segment");
        let want = expected_tuple(&pkt, NatDecision::default());
        check_segments(&segs, &pkt, mtu, tx_vlan, &want)?;
    }

    /// P-T4: NAT composition — every segment carries the rewritten
    /// tuple and valid checksums (composes the S2 oracle).
    /// `expected_ports` is the post-NAT wire tuple, matching how the
    /// enforce step runs after `apply_nat_*` in the splitter.
    #[test]
    fn segmentation_composes_with_nat(
        ((pkt, mtu), nat) in arb_seg_packet().prop_flat_map(|(pkt, mtu)| {
            let v6 = pkt.addr_family != AF4;
            (Just((pkt, mtu)), arb_nat(v6))
        }),
        tx_vlan in arb_vlan(),
    ) {
        let forwarding = seg_fixture(mtu, tx_vlan);
        let decision = seg_decision(pkt.dst_ip, tx_vlan, nat);
        let want = expected_tuple(&pkt, nat);
        let segs = segment_forwarded_tcp_frames_from_frame(
            &pkt.frame,
            pkt.meta,
            &decision,
            &forwarding,
            false,
            Some((want.src_port, want.dst_port)),
        ).expect("oversized valid TCP frame must segment under NAT");
        check_segments(&segs, &pkt, mtu, tx_vlan, &want)?;
    }

    /// P-T3 precondition gate: SYN/FIN/RST oversized frames are
    /// declined (`None`), never split (tcp_segmentation.rs:79).
    #[test]
    fn segmentation_declines_syn_fin_rst(
        (mut pkt, mtu) in arb_seg_packet(),
        flag in prop_oneof![
            Just(TCP_FLAG_SYN),
            Just(TCP_FLAG_FIN),
            Just(TCP_FLAG_RST),
        ],
        tx_vlan in arb_vlan(),
    ) {
        let flags_off = pkt.l4() + 13;
        pkt.frame[flags_off] |= flag;
        let forwarding = seg_fixture(mtu, tx_vlan);
        let decision = seg_decision(pkt.dst_ip, tx_vlan, NatDecision::default());
        prop_assert_eq!(
            segment_forwarded_tcp_frames_from_frame(
                &pkt.frame, pkt.meta, &decision, &forwarding, false, None,
            ),
            None
        );
    }
}

/// #1838 §5.3 deterministic pin: an ext-headered oversized v6 TCP
/// frame segments into oracle-valid segments whose payload-length
/// fields count the copied ext-chain bytes, under a dst-port NAT.
#[test]
fn pin_segmentation_v6_ext_chain_segments_valid() {
    use super::strategies::{build_valid_frame, ExtHdr, PacketSpec};
    let mtu = 1280usize;
    let spec = PacketSpec {
        v6: true,
        src4: 0,
        dst4: 0,
        src6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66],
        dst6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc8],
        protocol: PROTO_TCP,
        src_port: 0x1111,
        dst_port: 0x2222,
        vlan_id: 0,
        vlan_present: false,
        pcp: 0,
        ttl: 64,
        ihl: 20,
        ext: vec![ExtHdr::HopByHop(0), ExtHdr::DestOpts(0)],
        payload_len: 3000,
        payload_seed: 7,
        udp_zero_csum: false,
        tcp_flags: 0x18,
        tcp_opt_len: 0,
        seq: 1000,
    };
    let pkt = build_valid_frame(&spec);
    assert_eq!(pkt.rel_l4, 56, "two 8-byte ext headers → L4 at 56");

    let nat = NatDecision {
        rewrite_dst_port: Some(0x3333),
        ..NatDecision::default()
    };
    let forwarding = seg_fixture(mtu, 0);
    let decision = seg_decision(pkt.dst_ip, 0, nat);
    let want = expected_tuple(&pkt, nat);
    let segs = segment_forwarded_tcp_frames_from_frame(
        &pkt.frame,
        pkt.meta,
        &decision,
        &forwarding,
        false,
        Some((want.src_port, want.dst_port)),
    )
    .expect("ext-headered oversized v6 TCP must segment");
    assert!(segs.len() > 1, "splitter engaged");
    check_segments(&segs, &pkt, mtu, 0, &want).expect("per-segment invariants hold");
    // Spot-check the ext chain is carried verbatim in every segment.
    for seg in &segs {
        assert_eq!(
            &seg[14 + 40..14 + 56],
            &pkt.frame[14 + 40..14 + 56],
            "segment carries the original ext chain"
        );
    }
}
