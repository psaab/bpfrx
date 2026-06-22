// #2301 egress-MTU PTB tests. Exercise the decision + the ICMP
// Frag-Needed / Packet-Too-Big builders directly:
//   - oversized forwarded non-TCP IPv4 DF -> Frag-Needed (type 3 code 4)
//     with the correct next-hop MTU and the quoted original packet,
//   - oversized forwarded IPv6 -> Packet Too Big (type 2 code 0) with MTU,
//   - in-MTU frames -> Forward (no PTB),
//   - non-DF oversized IPv4 -> Forward (pre-#2301 behaviour preserved),
//   - RFC suppression: non-first fragment + inbound ICMP error -> no PTB.

use super::*;

const PTB_IFINDEX: i32 = 24;
const EGRESS_SRC_MAC: [u8; 6] = [0x02, 0xbf, 0x72, 0x00, 0x00, 0x01];
const SENDER_MAC: [u8; 6] = [0x00, 0x25, 0x90, 0x12, 0x34, 0x56];
const FW_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

fn forwarding_with_egress(mtu: usize) -> ForwardingState {
    let mut state = ForwardingState::default();
    state.egress.insert(
        PTB_IFINDEX,
        EgressInterface {
            bind_ifindex: 0,
            vlan_id: 0,
            mtu,
            src_mac: EGRESS_SRC_MAC,
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: Some("2001:559:8585:80::8".parse().expect("v6")),
        },
    );
    state
}

/// Build an inbound IPv4 UDP packet with `payload_len` UDP payload bytes
/// (total L3 = 20 + 8 + payload). `df` sets the Don't-Fragment bit.
fn inbound_v4_udp(payload_len: usize, df: bool) -> (Vec<u8>, UserspaceDpMeta) {
    let mut frame = Vec::new();
    frame.extend_from_slice(&FW_MAC);
    frame.extend_from_slice(&SENDER_MAC);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    let l3 = frame.len();
    let total_len = (20 + 8 + payload_len) as u16;
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01]); // ID
    let flags_frag = if df { 0x4000u16 } else { 0x0000u16 };
    frame.extend_from_slice(&flags_frag.to_be_bytes());
    frame.extend_from_slice(&[64, 17, 0x00, 0x00]); // TTL, proto UDP, csum
    frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets()); // src
    frame.extend_from_slice(&Ipv4Addr::new(172, 16, 80, 200).octets()); // dst
    let ip_csum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
    // UDP header.
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&5201u16.to_be_bytes());
    frame.extend_from_slice(&((8 + payload_len) as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend(std::iter::repeat(0xABu8).take(payload_len));

    let meta = UserspaceDpMeta {
        ingress_ifindex: PTB_IFINDEX as u32,
        l3_offset: l3 as u16,
        l4_offset: (l3 + 20) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: 17,
        ..UserspaceDpMeta::default()
    };
    (frame, meta)
}

/// Build an inbound IPv6 UDP packet with `payload_len` UDP payload bytes.
fn inbound_v6_udp(payload_len: usize) -> (Vec<u8>, UserspaceDpMeta) {
    let mut frame = Vec::new();
    frame.extend_from_slice(&FW_MAC);
    frame.extend_from_slice(&SENDER_MAC);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    let l3 = frame.len();
    let payload = (8 + payload_len) as u16; // UDP header + data
    frame.push(0x60); // version 6
    frame.extend_from_slice(&[0x00, 0x00, 0x00]); // TC/flow
    frame.extend_from_slice(&payload.to_be_bytes());
    frame.push(17); // next header UDP
    frame.push(64); // hop limit
    frame.extend_from_slice(&"2001:559:8585:bf01::20".parse::<Ipv6Addr>().unwrap().octets()); // src
    frame.extend_from_slice(&"2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap().octets()); // dst
    // UDP header.
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&5201u16.to_be_bytes());
    frame.extend_from_slice(&((8 + payload_len) as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend(std::iter::repeat(0xCDu8).take(payload_len));

    let meta = UserspaceDpMeta {
        ingress_ifindex: PTB_IFINDEX as u32,
        l3_offset: l3 as u16,
        l4_offset: (l3 + 40) as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: 17,
        ..UserspaceDpMeta::default()
    };
    (frame, meta)
}

#[test]
fn oversized_v4_df_udp_emits_frag_needed() {
    // L3 = 20 + 8 + 1500 = 1528 > 1400 MTU, DF set.
    let (frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    let mtu = 1400usize;
    let decision = forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, mtu);
    let next_hop_mtu = match decision {
        EgressMtuDecision::EmitPacketTooBig { next_hop_mtu } => next_hop_mtu,
        other => panic!("expected EmitPacketTooBig, got {other:?}"),
    };
    assert_eq!(next_hop_mtu, 1400, "advertised MTU must equal the egress MTU");

    assert!(
        !ptb_reply_suppressed(&frame, meta, l3),
        "a plain UDP frame must not be suppressed"
    );

    let fwd = forwarding_with_egress(mtu);
    let out = build_frag_needed_v4(&frame, meta, PTB_IFINDEX, &fwd, next_hop_mtu)
        .expect("frag-needed must build");

    // L2: reflected (dst = inbound src), src = egress MAC, EtherType IPv4.
    assert_eq!(&out[0..6], &SENDER_MAC, "reflected dst MAC = inbound src");
    assert_eq!(&out[6..12], &EGRESS_SRC_MAC, "src MAC = egress");
    assert_eq!(&out[12..14], &[0x08, 0x00]);
    // Outer IPv4: src = ingress primary, dst = original src, proto ICMP.
    assert_eq!(out[14], 0x45);
    assert_eq!(out[23], PROTO_ICMP, "outer protocol must be ICMP");
    assert_eq!(&out[26..30], &Ipv4Addr::new(172, 16, 80, 8).octets(), "src = ingress primary");
    assert_eq!(&out[30..34], &Ipv4Addr::new(198, 51, 100, 20).octets(), "dst = original sender");
    // ICMP: type 3 code 4, next-hop MTU in bytes 6..8 of the ICMP message.
    let icmp = 14 + 20;
    assert_eq!(out[icmp], 3, "ICMP type 3 (Dest Unreachable)");
    assert_eq!(out[icmp + 1], 4, "ICMP code 4 (Frag Needed and DF Set)");
    assert_eq!(
        u16::from_be_bytes([out[icmp + 6], out[icmp + 7]]),
        1400,
        "next-hop MTU in the ICMP unused word"
    );
    // ICMP checksum is valid (computed over the whole ICMP message -> 0).
    assert_eq!(checksum16(&out[icmp..]), 0, "ICMP checksum must verify");
    // Quoted packet: the original IPv4 header (first byte 0x45) follows the
    // 8-byte ICMP header.
    assert_eq!(out[icmp + 8], 0x45, "quoted original IPv4 header present");
}

#[test]
fn oversized_v6_udp_emits_packet_too_big() {
    // L3 = 40 + 8 + 1300 = 1348 > 1280 MTU.
    let (frame, meta) = inbound_v6_udp(1300);
    let l3 = meta.l3_offset as usize;
    let mtu = 1280usize;
    let decision = forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, mtu);
    let next_hop_mtu = match decision {
        EgressMtuDecision::EmitPacketTooBig { next_hop_mtu } => next_hop_mtu,
        other => panic!("expected EmitPacketTooBig, got {other:?}"),
    };
    assert_eq!(next_hop_mtu, 1280);

    let fwd = forwarding_with_egress(mtu);
    let out = build_packet_too_big_v6(&frame, meta, PTB_IFINDEX, &fwd, next_hop_mtu as u32)
        .expect("packet-too-big must build");

    assert_eq!(&out[0..6], &SENDER_MAC);
    assert_eq!(&out[6..12], &EGRESS_SRC_MAC);
    assert_eq!(&out[12..14], &[0x86, 0xdd]);
    // Outer IPv6: version 6, next header ICMPv6.
    assert_eq!(out[14] & 0xf0, 0x60);
    assert_eq!(out[14 + 6], PROTO_ICMPV6, "outer next header ICMPv6");
    let icmp = 14 + 40;
    assert_eq!(out[icmp], 2, "ICMPv6 type 2 (Packet Too Big)");
    assert_eq!(out[icmp + 1], 0, "ICMPv6 code 0");
    assert_eq!(
        u32::from_be_bytes([out[icmp + 4], out[icmp + 5], out[icmp + 6], out[icmp + 7]]),
        1280,
        "MTU in the 32-bit ICMPv6 PTB field"
    );
    // Quoted original IPv6 header (version 6) follows the 8-byte header.
    assert_eq!(out[icmp + 8] & 0xf0, 0x60, "quoted original IPv6 header present");
    // The reply must not exceed the IPv6 minimum MTU (RFC 4443 §3.2).
    assert!(out.len() - 14 <= 1280, "reply L3 size <= 1280");
}

#[test]
fn in_mtu_v4_forwards_unchanged() {
    // L3 = 20 + 8 + 1000 = 1028 <= 1500 MTU. No PTB.
    let (frame, meta) = inbound_v4_udp(1000, true);
    let l3 = meta.l3_offset as usize;
    assert_eq!(
        forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, 1500),
        EgressMtuDecision::Forward,
        "in-MTU frame must forward unchanged"
    );
}

#[test]
fn in_mtu_v6_forwards_unchanged() {
    let (frame, meta) = inbound_v6_udp(600);
    let l3 = meta.l3_offset as usize;
    assert_eq!(
        forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, 1500),
        EgressMtuDecision::Forward
    );
}

#[test]
fn oversized_v4_without_df_forwards() {
    // Oversized but DF clear: the downstream may fragment. Preserve the
    // pre-#2301 forward behaviour rather than PTB-storming the flow.
    let (frame, meta) = inbound_v4_udp(1500, false);
    let l3 = meta.l3_offset as usize;
    assert_eq!(
        forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, 1400),
        EgressMtuDecision::Forward,
        "non-DF oversized IPv4 must forward (downstream fragments)"
    );
}

#[test]
fn no_egress_mtu_known_forwards() {
    // mtu == 0 means no egress entry known -> never invent a smaller MTU.
    let (frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    assert_eq!(
        forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, 0),
        EgressMtuDecision::Forward
    );
}

#[test]
fn next_hop_mtu_floored_at_protocol_minimum() {
    // A pathologically tiny egress MTU must never advertise below the
    // IPv6 minimum (1280) / IPv4 floor (68).
    let (v6_frame, v6_meta) = inbound_v6_udp(1300);
    let l3 = v6_meta.l3_offset as usize;
    match forwarded_egress_mtu_decision(&v6_frame, l3, v6_meta.addr_family, 100) {
        EgressMtuDecision::EmitPacketTooBig { next_hop_mtu } => {
            assert_eq!(next_hop_mtu, 1280, "v6 advertised MTU floored at 1280");
        }
        other => panic!("expected PTB, got {other:?}"),
    }
}

#[test]
fn non_first_fragment_v4_is_suppressed() {
    // A non-first fragment has no transport header to quote/key.
    let (mut frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    // Set fragment offset != 0, DF clear, MF set: a non-first fragment.
    // flags+frag word at l3+6..l3+8: MF (0x2000) | frag offset 185.
    let frag_word: u16 = 0x2000 | 185;
    frame[l3 + 6..l3 + 8].copy_from_slice(&frag_word.to_be_bytes());
    let ip_csum = {
        frame[l3 + 10..l3 + 12].copy_from_slice(&[0, 0]);
        checksum16(&frame[l3..l3 + 20])
    };
    frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
    assert!(
        ptb_reply_suppressed(&frame, meta, l3),
        "non-first fragment must be suppressed"
    );
}

#[test]
fn inbound_icmp_error_is_suppressed() {
    // An oversized inbound ICMPv4 *error* (type 3) must not generate a
    // fresh PTB -> avoid error loops / amplification (RFC 792).
    let mut frame = Vec::new();
    frame.extend_from_slice(&FW_MAC);
    frame.extend_from_slice(&SENDER_MAC);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    let l3 = frame.len();
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&28u16.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, PROTO_ICMP, 0x00, 0x00]);
    frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets());
    frame.extend_from_slice(&Ipv4Addr::new(172, 16, 80, 200).octets());
    let ip_csum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
    let l4 = frame.len();
    // ICMP type 3 (Destination Unreachable) — an error message.
    frame.extend_from_slice(&[3, 1, 0, 0, 0, 0, 0, 0]);
    let meta = UserspaceDpMeta {
        ingress_ifindex: PTB_IFINDEX as u32,
        l3_offset: l3 as u16,
        l4_offset: l4 as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    assert!(
        ptb_reply_suppressed(&frame, meta, l3),
        "inbound ICMP error must be suppressed"
    );
    // Counter-factual: an inbound ICMP *echo request* (query, type 8) is
    // NOT suppressed — proving the gate is type-specific, not all-ICMP.
    let mut echo = frame.clone();
    echo[l4] = 8; // echo request
    let echo_meta = UserspaceDpMeta {
        l4_offset: l4 as u16,
        ..meta
    };
    assert!(
        !ptb_reply_suppressed(&echo, echo_meta, l3),
        "an inbound ICMP echo request is a query, not suppressed"
    );
}

#[test]
fn no_primary_address_fails_closed() {
    // Egress has no primary v4 -> the builder returns None (caller silently
    // drops). The decision still fires, so the oversized original is dropped
    // either way; this proves the builder does not panic / forge a source.
    let (frame, meta) = inbound_v4_udp(1500, true);
    let mut fwd = forwarding_with_egress(1400);
    fwd.egress.get_mut(&PTB_IFINDEX).unwrap().primary_v4 = None;
    assert!(
        build_frag_needed_v4(&frame, meta, PTB_IFINDEX, &fwd, 1400).is_none(),
        "no ingress primary v4 -> fail-closed None"
    );
}
