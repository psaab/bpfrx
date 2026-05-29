// Tests for nat64.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep nat64.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "nat64_tests.rs"]` from nat64.rs.

use super::*;

fn well_known_prefix() -> NAT64RuleSnapshot {
    NAT64RuleSnapshot {
        name: "nat64-wkp".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["198.51.100.1".to_string(), "198.51.100.2".to_string()],
    }
}

#[test]
fn parse_well_known_prefix() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    assert!(state.is_active());
    assert_eq!(state.prefixes.len(), 1);
    assert_eq!(
        state.prefixes[0].prefix_bytes,
        [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    assert_eq!(state.prefixes[0].pool_v4.len(), 2);
}

#[test]
fn match_ipv6_dest_extracts_v4() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    // 64:ff9b::198.51.100.50 = 64:ff9b::c633:6432
    let dst: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let (idx, v4) = state.match_ipv6_dest(dst).expect("should match");
    assert_eq!(idx, 0);
    assert_eq!(v4, Ipv4Addr::new(198, 51, 100, 50));
}

#[test]
fn match_ipv6_dest_no_match() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert!(state.match_ipv6_dest(dst).is_none());
}

#[test]
fn pool_allocation_round_robin() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let a1 = state.allocate_v4_source(0).expect("alloc1");
    let a2 = state.allocate_v4_source(0).expect("alloc2");
    let a3 = state.allocate_v4_source(0).expect("alloc3");
    assert_eq!(a1, Ipv4Addr::new(198, 51, 100, 1));
    assert_eq!(a2, Ipv4Addr::new(198, 51, 100, 2));
    assert_eq!(a3, Ipv4Addr::new(198, 51, 100, 1)); // wraps
}

#[test]
fn empty_pool_returns_none() {
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "no-pool".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![],
    }]);
    assert!(state.allocate_v4_source(0).is_none());
}

#[test]
fn invalid_prefix_length_ignored() {
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "bad".to_string(),
        prefix: "64:ff9b::/64".to_string(),
        pool_addresses: vec!["1.2.3.4".to_string()],
    }]);
    assert!(!state.is_active());
}

// --- Packet translation tests ---

fn make_ipv6_tcp_packet(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let mut pkt = vec![0u8; 40 + tcp_len];
    // IPv6 header
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    pkt[6] = PROTO_TCP;
    pkt[7] = 64; // hop limit
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    // TCP header (minimal)
    pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
    pkt[52] = 0x50; // data offset = 5 (20 bytes)
    pkt[53] = 0x02; // SYN
    pkt[54..56].copy_from_slice(&1024u16.to_be_bytes()); // window
                                                         // Copy payload
    pkt[60..60 + payload.len()].copy_from_slice(payload);
    // Compute TCP checksum
    pkt[56..58].copy_from_slice(&[0, 0]);
    let sum = checksum16_ipv6_pseudo(src, dst, PROTO_TCP, &pkt[40..]);
    pkt[56..58].copy_from_slice(&sum.to_be_bytes());
    pkt
}

fn make_ipv4_tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let total_len = 20 + tcp_len;
    let mut pkt = vec![0u8; total_len];
    // IPv4 header
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64; // TTL
    pkt[9] = PROTO_TCP;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    // TCP header
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[32] = 0x50; // data offset = 5
    pkt[33] = 0x12; // SYN+ACK
    pkt[34..36].copy_from_slice(&1024u16.to_be_bytes());
    pkt[40..40 + payload.len()].copy_from_slice(payload);
    // Compute checksums
    pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    pkt[36..38].copy_from_slice(&[0, 0]);
    let tcp_sum = checksum16_ipv4_pseudo(src, dst, PROTO_TCP, &pkt[20..]);
    pkt[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
    pkt
}

#[test]
fn translate_v6_to_v4_tcp() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"hello");
    let ipv4_pkt = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4).expect("translate");

    // Verify IPv4 header.
    assert_eq!(ipv4_pkt[0], 0x45);
    assert_eq!(ipv4_pkt[8], 63); // TTL = 64-1
    assert_eq!(ipv4_pkt[9], PROTO_TCP);
    assert_eq!(&ipv4_pkt[12..16], &snat_v4.octets());
    assert_eq!(&ipv4_pkt[16..20], &dst_v4.octets());

    // Verify size: IPv6 was 40+25=65, IPv4 should be 20+25=45.
    assert_eq!(ipv4_pkt.len(), 45);

    // Verify TCP ports preserved.
    assert_eq!(u16::from_be_bytes([ipv4_pkt[20], ipv4_pkt[21]]), 12345);
    assert_eq!(u16::from_be_bytes([ipv4_pkt[22], ipv4_pkt[23]]), 80);

    // Verify IPv4 header checksum.
    assert_eq!(checksum16(&ipv4_pkt[..20]), 0);

    // Verify TCP checksum.
    let tcp_payload = &ipv4_pkt[20..];
    let src = Ipv4Addr::new(ipv4_pkt[12], ipv4_pkt[13], ipv4_pkt[14], ipv4_pkt[15]);
    let dst = Ipv4Addr::new(ipv4_pkt[16], ipv4_pkt[17], ipv4_pkt[18], ipv4_pkt[19]);
    assert_eq!(checksum16_ipv4_pseudo(src, dst, PROTO_TCP, tcp_payload), 0);
}

#[test]
fn translate_v4_to_v6_tcp() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap(); // server→client reply
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let ipv4_pkt = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"world");
    let ipv6_pkt = translate_v4_to_v6(&ipv4_pkt, src_v6, dst_v6).expect("translate");

    // Verify IPv6 header.
    assert_eq!(ipv6_pkt[0] >> 4, 6);
    assert_eq!(ipv6_pkt[6], PROTO_TCP);
    assert_eq!(ipv6_pkt[7], 63); // hop limit = 64-1
    assert_eq!(&ipv6_pkt[8..24], &src_v6.octets());
    assert_eq!(&ipv6_pkt[24..40], &dst_v6.octets());

    // Verify size: IPv4 was 20+25=45, IPv6 should be 40+25=65.
    assert_eq!(ipv6_pkt.len(), 65);

    // Verify TCP ports preserved.
    assert_eq!(u16::from_be_bytes([ipv6_pkt[40], ipv6_pkt[41]]), 80);
    assert_eq!(u16::from_be_bytes([ipv6_pkt[42], ipv6_pkt[43]]), 12345);

    // Verify TCP checksum.
    let src6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[8..24]).unwrap());
    let dst6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(src6, dst6, PROTO_TCP, &ipv6_pkt[40..]),
        0
    );
}

#[test]
fn translate_v6_to_v4_udp() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Build IPv6 + UDP.
    let dns_query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
    let udp_len = 8 + dns_query.len();
    let mut pkt = vec![0u8; 40 + udp_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = PROTO_UDP;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_v6.octets());
    pkt[24..40].copy_from_slice(&dst_v6.octets());
    pkt[40..42].copy_from_slice(&12345u16.to_be_bytes());
    pkt[42..44].copy_from_slice(&53u16.to_be_bytes());
    pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[48..48 + dns_query.len()].copy_from_slice(dns_query);
    // UDP checksum
    pkt[46..48].copy_from_slice(&[0, 0]);
    let sum = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_UDP, &pkt[40..]);
    pkt[46..48].copy_from_slice(&sum.to_be_bytes());

    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4).expect("translate");
    assert_eq!(v4[9], PROTO_UDP);
    assert_eq!(checksum16(&v4[..20]), 0);
}

#[test]
fn translate_v6_to_v4_icmp_echo() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Build ICMPv6 Echo Request.
    let icmp_len = 8; // type(1) + code(1) + checksum(2) + id(2) + seq(2)
    let mut pkt = vec![0u8; 40 + icmp_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    pkt[6] = PROTO_ICMPV6;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_v6.octets());
    pkt[24..40].copy_from_slice(&dst_v6.octets());
    pkt[40] = ICMPV6_ECHO_REQUEST;
    pkt[41] = 0; // code
    pkt[44..46].copy_from_slice(&0x1234u16.to_be_bytes()); // id
    pkt[46..48].copy_from_slice(&0x0001u16.to_be_bytes()); // seq
                                                           // ICMPv6 checksum
    pkt[42..44].copy_from_slice(&[0, 0]);
    let sum = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_ICMPV6, &pkt[40..]);
    pkt[42..44].copy_from_slice(&sum.to_be_bytes());

    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4).expect("translate");
    assert_eq!(v4[9], PROTO_ICMP);
    assert_eq!(v4[20], ICMP_ECHO_REQUEST); // type mapped
    assert_eq!(checksum16(&v4[..20]), 0);
    // ICMPv4 checksum: no pseudo-header.
    assert_eq!(checksum16(&v4[20..]), 0);
}

#[test]
fn translate_v4_to_v6_icmp_echo_reply() {
    let src_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    // Build ICMPv4 Echo Reply.
    let icmp_len = 8;
    let total = 20 + icmp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = PROTO_ICMP;
    pkt[12..16].copy_from_slice(&src_v4.octets());
    pkt[16..20].copy_from_slice(&dst_v4.octets());
    pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    pkt[20] = ICMP_ECHO_REPLY;
    pkt[21] = 0;
    pkt[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
    pkt[26..28].copy_from_slice(&0x0001u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&[0, 0]);
    let icmp_sum = checksum16(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_sum.to_be_bytes());

    let v6 = translate_v4_to_v6(&pkt, src_v6, dst_v6).expect("translate");
    assert_eq!(v6[6], PROTO_ICMPV6);
    assert_eq!(v6[40], ICMPV6_ECHO_REPLY); // type mapped
                                           // ICMPv6 checksum verification.
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(checksum16_ipv6_pseudo(s6, d6, PROTO_ICMPV6, &v6[40..]), 0);
}

#[test]
fn packet_size_delta() {
    // IPv6 packet: 40 header + 20 TCP header + 5 payload = 65 bytes
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 1025, 80, b"hello");
    assert_eq!(pkt.len(), 65); // 40 + 20 + 5

    let v4 = translate_v6_to_v4(
        &pkt,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
    )
    .expect("translate");
    assert_eq!(v4.len(), 45); // 20 + 20 + 5
    assert_eq!(pkt.len() - v4.len(), 20); // IPv6→IPv4 shrinks by 20 bytes
}

#[test]
fn forward_decision_sets_nat64_flag() {
    let d = Nat64State::forward_decision(Ipv4Addr::new(198, 51, 100, 1), Ipv4Addr::new(8, 8, 8, 8));
    assert!(d.nat64);
    assert_eq!(
        d.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))
    );
    assert_eq!(d.rewrite_dst, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[test]
fn frame_building_v6_to_v4() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();

    // Build Ethernet + IPv6 frame.
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"test");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]); // dst mac
    frame.extend_from_slice(&[0xbb; 6]); // src mac
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    let result = build_nat64_v6_to_v4_frame(
        &frame,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        [0x11; 6],
        [0x22; 6],
        0,
    )
    .expect("build");

    // Should be 14 (eth) + 44 (20 ipv4 + 20 tcp + 4 payload)
    assert_eq!(result.len(), 14 + 44);
    // Check Ethernet type is IPv4.
    assert_eq!(u16::from_be_bytes([result[12], result[13]]), 0x0800);
}

#[test]
fn frame_building_v4_to_v6() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);

    let pkt = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"resp");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]);
    frame.extend_from_slice(&[0xbb; 6]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let result =
        build_nat64_v4_to_v6_frame(&frame, src_v6, dst_v6, [0x11; 6], [0x22; 6], 0).expect("build");

    // Should be 14 (eth) + 64 (40 ipv6 + 20 tcp + 4 payload)
    assert_eq!(result.len(), 14 + 64);
    // Check Ethernet type is IPv6.
    assert_eq!(u16::from_be_bytes([result[12], result[13]]), 0x86dd);
}

#[test]
fn ttl_expired_returns_none() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let mut pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 1025, 80, b"x");
    pkt[7] = 1; // hop limit = 1
                // Need to recompute TCP checksum after modifying hop limit
                // (hop limit isn't in pseudo-header so checksum is still valid).
    assert!(
        translate_v6_to_v4(&pkt, Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8),).is_none()
    );
}

#[test]
fn frame_building_v6_to_v4_with_vlan() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();

    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"vlan");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]);
    frame.extend_from_slice(&[0xbb; 6]);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    let result = build_nat64_v6_to_v4_frame(
        &frame,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        [0x11; 6],
        [0x22; 6],
        100, // VLAN 100
    )
    .expect("build");

    // 18 (eth+vlan) + 44 (20 ipv4 + 20 tcp + 4 payload)
    assert_eq!(result.len(), 18 + 44);
    // VLAN tag
    assert_eq!(u16::from_be_bytes([result[12], result[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([result[16], result[17]]), 0x0800);
}

// ---------------------------------------------------------------------------
// Regression tests for #1641: translate_v4_to_v6 must trim the L4 payload to
// the IPv4 Total Length field, not the end of the input slice. The caller
// passes the whole L3-onward frame, which can carry Ethernet padding when the
// reply is shorter than the 60/64-byte minimum frame size. Before the fix the
// padding was copied into the IPv6 packet, inflating payload_len and poisoning
// the L4 checksum so the receiver dropped the reply.
// ---------------------------------------------------------------------------

#[test]
fn translate_v4_to_v6_trims_ethernet_padding_tcp() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    // A bare TCP ACK: 20B IP + 20B TCP, no L4 payload = 40B on the wire. The
    // NIC/driver pads the frame to the 60-byte L2 minimum, so the L3-onward
    // slice the caller hands us is 46 bytes (40B real + 6B zero padding).
    let mut packet = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"");
    assert_eq!(packet.len(), 40, "unpadded ACK should be 40 bytes");
    let real_len = packet.len();
    packet.extend_from_slice(&[0u8; 6]); // simulate trailing Ethernet padding
    assert_eq!(packet.len(), 46);

    let ipv6_pkt = translate_v4_to_v6(&packet, src_v6, dst_v6).expect("translate");

    // payload_len must reflect the real L4 length (20B TCP), NOT the padded
    // slice length. Before the fix this was 26 (20 + 6 padding bytes).
    let payload_len = u16::from_be_bytes([ipv6_pkt[4], ipv6_pkt[5]]) as usize;
    assert_eq!(payload_len, 20, "payload_len must exclude Ethernet padding");
    // Total translated length = 40B IPv6 header + 20B TCP, with no padding.
    assert_eq!(ipv6_pkt.len(), 40 + (real_len - 20));
    assert_eq!(ipv6_pkt.len(), 60);

    // The L4 checksum must verify over the trimmed payload. A padding-poisoned
    // checksum (the pre-fix bug) leaves a non-zero residual here.
    let src6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[8..24]).unwrap());
    let dst6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(src6, dst6, PROTO_TCP, &ipv6_pkt[40..]),
        0,
        "TCP checksum must verify over the unpadded payload"
    );
}

#[test]
fn translate_v4_to_v6_trims_ethernet_padding_udp_dns() {
    // Short UDP/DNS reply (the canonical Ethernet-padded case). Build a 12B
    // DNS-ish payload: 20B IP + 8B UDP + 12B = 40B real, padded to 46B.
    let src_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let dns = b"\x00\x01\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00";
    let udp_len = 8 + dns.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = PROTO_UDP;
    packet[12..16].copy_from_slice(&src_v4.octets());
    packet[16..20].copy_from_slice(&dst_v4.octets());
    packet[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    packet[20..22].copy_from_slice(&53u16.to_be_bytes()); // src port
    packet[22..24].copy_from_slice(&12345u16.to_be_bytes()); // dst port
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..28 + dns.len()].copy_from_slice(dns);
    packet[26..28].copy_from_slice(&[0, 0]);
    let udp_sum = checksum16_ipv4_pseudo(src_v4, dst_v4, PROTO_UDP, &packet[20..]);
    packet[26..28].copy_from_slice(&udp_sum.to_be_bytes());

    assert_eq!(packet.len(), 40);
    packet.extend_from_slice(&[0u8; 6]); // Ethernet padding to 46B L3 slice

    let v6 = translate_v4_to_v6(&packet, src_v6, dst_v6).expect("translate");
    let payload_len = u16::from_be_bytes([v6[4], v6[5]]) as usize;
    assert_eq!(payload_len, udp_len, "payload_len must exclude padding");
    assert_eq!(v6.len(), 40 + udp_len);

    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(s6, d6, PROTO_UDP, &v6[40..]),
        0,
        "UDP checksum must verify over the unpadded payload"
    );
}

#[test]
fn translate_v4_to_v6_total_len_larger_than_slice_returns_none() {
    // Malformed Total Length advertising more bytes than we received: must be
    // rejected safely (no panic, no out-of-bounds), not trusted.
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut packet = make_ipv4_tcp_packet(
        Ipv4Addr::new(198, 51, 100, 50),
        Ipv4Addr::new(198, 51, 100, 1),
        80,
        12345,
        b"hi",
    );
    // Advertise a Total Length 100 bytes beyond the actual slice.
    let bogus = (packet.len() + 100) as u16;
    packet[2..4].copy_from_slice(&bogus.to_be_bytes());
    assert!(
        translate_v4_to_v6(&packet, src_v6, dst_v6).is_none(),
        "oversized total_len must be rejected"
    );
}

#[test]
fn translate_v4_to_v6_total_len_below_ihl_returns_none() {
    // Total Length shorter than the IPv4 header is nonsensical: reject it.
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut packet = make_ipv4_tcp_packet(
        Ipv4Addr::new(198, 51, 100, 50),
        Ipv4Addr::new(198, 51, 100, 1),
        80,
        12345,
        b"hi",
    );
    packet[2..4].copy_from_slice(&10u16.to_be_bytes()); // < 20B IHL
    assert!(
        translate_v4_to_v6(&packet, src_v6, dst_v6).is_none(),
        "total_len below the IPv4 header length must be rejected"
    );
}
