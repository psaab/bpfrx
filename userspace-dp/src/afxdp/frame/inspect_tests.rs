// Tests for afxdp/frame/inspect.rs (#2361) — the live ingress frame parser
// must bound the L4 port read by the IP-DECLARED packet length
// (IPv4 total_len / IPv6 40+payload_len), not merely the backing slice.
//
// These pin the fail-closed invariant that out-of-datagram trailing slack
// (NIC zero-pad on a sub-60-byte frame, or attacker-supplied bytes) can NOT
// be read as L4 ports — mirroring the sibling generated-reply parser's
// `generated_l4_ports` bound (`generated.rs`, #2321/#2238). Loaded as a
// sibling submodule via `#[path = "inspect_tests.rs"]`.

use super::*;

const ETH_DST: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const ETH_SRC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

/// Build an untagged IPv4 frame: eth(14) + IPv4 header(20) + `l4` bytes.
/// `declared_total_len` is written into the IPv4 total_len field (bytes
/// [2..4]) INDEPENDENTLY of how many L4 bytes are actually appended, so a
/// caller can declare a short datagram but still carry trailing slack.
fn v4_frame(protocol: u8, declared_total_len: u16, l4: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&ETH_DST);
    frame.extend_from_slice(&ETH_SRC);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4 header (IHL=5 => 20 bytes).
    frame.push(0x45);
    frame.push(0x00); // ToS
    frame.extend_from_slice(&declared_total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]); // id
    frame.extend_from_slice(&[0x40, 0x00]); // flags/frag-off (DF, offset 0)
    frame.extend_from_slice(&[64, protocol]); // ttl, proto
    frame.extend_from_slice(&[0x00, 0x00]); // checksum (unused by parser)
    frame.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());
    frame.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 2).octets());
    frame.extend_from_slice(l4);
    frame
}

/// Build an untagged IPv6 frame: eth(14) + IPv6 header(40) + `l4` bytes.
/// `declared_payload_len` is written into the payload_len field (bytes
/// [4..6]) INDEPENDENTLY of the appended L4, so a short datagram can carry
/// trailing slack.
fn v6_frame(next_header: u8, declared_payload_len: u16, l4: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&ETH_DST);
    frame.extend_from_slice(&ETH_SRC);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.push(0x60); // version 6
    frame.extend_from_slice(&[0x00, 0x00, 0x00]); // tc + flow label
    frame.extend_from_slice(&declared_payload_len.to_be_bytes());
    frame.push(next_header);
    frame.push(64); // hop limit
    frame.extend_from_slice(&[0x20; 16]); // src
    frame.extend_from_slice(&[0x30; 16]); // dst
    frame.extend_from_slice(l4);
    frame
}

/// 4 TCP/UDP port bytes (src=0x1122, dst=0x3344) the parser must NOT read
/// when they fall outside the IP-declared packet end.
const FAKE_PORTS: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

fn v4_meta(protocol: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol,
        ..UserspaceDpMeta::default()
    }
}

fn v6_meta(protocol: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        addr_family: libc::AF_INET6 as u8,
        protocol,
        ..UserspaceDpMeta::default()
    }
}

// ---- IPv4 frame-led parser: out-of-declared-length ports -> None ----

#[test]
fn v4_total_len_ihl_only_with_fake_tcp_ports_returns_none() {
    // total_len = 20 (IHL only, no L4 in the IP-declared datagram) but the
    // buffer carries 4 trailing slack bytes that spell tcp/ports. The port
    // read at l4=l3+20 would land entirely OUTSIDE the IP-declared end
    // (l3+20) -> must fail closed (None / flowless).
    let frame = v4_frame(PROTO_TCP, 20, &FAKE_PORTS);
    assert_eq!(
        parse_ipv4_session_flow_from_frame(&frame, v4_meta(PROTO_TCP)),
        None,
        "ports past the IPv4 total_len must NOT be read as L4"
    );
    // The bytes ARE present in the slice — proving the old slice-only bound
    // would have returned them.
    assert_eq!(&frame[14 + 20..14 + 24], &FAKE_PORTS);
}

#[test]
fn v4_total_len_ihl_plus_two_with_fake_udp_ports_returns_none() {
    // total_len = 22 => declared end at l3+22, but the 4 UDP port bytes end
    // at l3+24 > l3+22 -> straddles the IP-declared boundary -> None.
    let frame = v4_frame(PROTO_UDP, 22, &FAKE_PORTS);
    assert_eq!(
        parse_ipv4_session_flow_from_frame(&frame, v4_meta(PROTO_UDP)),
        None,
        "ports straddling the IPv4 total_len boundary must fail closed"
    );
}

#[test]
fn v4_well_formed_tcp_parses_ports_normally() {
    // total_len == actual (20 + 4) so the ports lie INSIDE the declared
    // datagram. Anti-over-gate: a legitimate packet still classifies.
    let frame = v4_frame(PROTO_TCP, 24, &[0xab, 0xcd, 0x12, 0x34]);
    let flow = parse_ipv4_session_flow_from_frame(&frame, v4_meta(PROTO_TCP))
        .expect("well-formed v4 TCP must parse");
    assert_eq!(flow.forward_key.src_port, 0xabcd);
    assert_eq!(flow.forward_key.dst_port, 0x1234);
}

// ---- IPv6 frame-led parser ----

#[test]
fn v6_payload_len_zero_with_fake_tcp_ports_returns_none() {
    // payload_len = 0 => declared end at l3+40, but the slice carries 4
    // trailing fake port bytes at l3+40. Must fail closed.
    let frame = v6_frame(PROTO_TCP, 0, &FAKE_PORTS);
    assert_eq!(
        parse_session_flow_from_frame(&frame, v6_meta(PROTO_TCP)),
        None,
        "ports past the IPv6 payload_len must NOT be read as L4"
    );
    assert_eq!(&frame[14 + 40..14 + 44], &FAKE_PORTS);
}

#[test]
fn v6_well_formed_udp_parses_ports_normally() {
    // payload_len == 4 (the 4 UDP port bytes are inside the datagram).
    let frame = v6_frame(PROTO_UDP, 4, &[0x55, 0x66, 0x77, 0x88]);
    let flow = parse_session_flow_from_frame(&frame, v6_meta(PROTO_UDP))
        .expect("well-formed v6 UDP must parse");
    assert_eq!(flow.forward_key.src_port, 0x5566);
    assert_eq!(flow.forward_key.dst_port, 0x7788);
}

// ---- meta-offset fallback (parse_session_flow_from_bytes) ----

#[test]
fn meta_fallback_v4_short_total_len_returns_none() {
    // Drive the meta-offset fallback arm: stamp matching IPs (so the meta
    // fast path's metadata_tuple_complete is satisfied by addresses) but a
    // protocol that needs ports, with l4 pointing past the declared end.
    // total_len = 20 (no L4 declared) + trailing fake ports.
    let frame = v4_frame(PROTO_TCP, 20, &FAKE_PORTS);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 14 + 20,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_session_flow_from_bytes(&frame, meta),
        None,
        "meta-offset fallback must also honor the IPv4 total_len bound"
    );
}

#[test]
fn meta_fallback_v6_short_payload_len_returns_none() {
    let frame = v6_frame(PROTO_TCP, 0, &FAKE_PORTS);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 14 + 40,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_session_flow_from_bytes(&frame, meta),
        None,
        "meta-offset fallback must also honor the IPv6 payload_len bound"
    );
}

// ---- meta fast path (live_frame_ports_from_meta_bytes / _bytes) ----

#[test]
fn meta_fast_path_v4_out_of_declared_ports_returns_none() {
    // #2357-style chokepoint: a meta-stamped l4_offset that points past the
    // IP-declared end must not yield ports. total_len = 20, fake trailing
    // ports, l4_offset = l3+20.
    let frame = v4_frame(PROTO_TCP, 20, &FAKE_PORTS);
    let meta = ForwardPacketMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 14 + 20,
        ..ForwardPacketMeta::default()
    };
    assert_eq!(
        live_frame_ports_from_meta_bytes(&frame, meta),
        None,
        "meta fast path must bound the port read by the IPv4 total_len"
    );
}

#[test]
fn meta_fast_path_v4_well_formed_returns_ports() {
    // Anti-over-gate for the meta fast path.
    let frame = v4_frame(PROTO_TCP, 24, &[0xab, 0xcd, 0x12, 0x34]);
    let meta = ForwardPacketMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 14 + 20,
        ..ForwardPacketMeta::default()
    };
    assert_eq!(
        live_frame_ports_from_meta_bytes(&frame, meta),
        Some((0xabcd, 0x1234)),
        "well-formed meta fast path still returns ports"
    );
}

#[test]
fn live_frame_ports_bytes_v6_out_of_declared_returns_none() {
    // Byte-led variant (no usable meta l4): re-derives l3 + declared end
    // from the frame and must still fail closed.
    let frame = v6_frame(PROTO_TCP, 0, &FAKE_PORTS);
    assert_eq!(
        live_frame_ports_bytes(&frame, libc::AF_INET6 as u8, PROTO_TCP),
        None,
        "byte-led meta path must bound by the IPv6 payload_len"
    );
}

// ---- declared-end helper unit truth ----

#[test]
fn declared_end_helpers_clamp_to_slice_and_floor() {
    // v4: total_len declares MORE than the slice -> clamp to slice len.
    let frame = v4_frame(PROTO_TCP, 1500, &FAKE_PORTS); // slice = 14+20+4=38
    assert_eq!(ipv4_declared_l3_end(&frame, 14), Some(frame.len()));
    // v4: total_len below ihl floors at l3+ihl (l3+20).
    let frame2 = v4_frame(PROTO_TCP, 10, &FAKE_PORTS);
    assert_eq!(ipv4_declared_l3_end(&frame2, 14), Some(14 + 20));
    // v6: payload_len declares more than the slice -> clamp to slice.
    let frame3 = v6_frame(PROTO_TCP, 1000, &FAKE_PORTS);
    assert_eq!(ipv6_declared_l3_end(&frame3, 14), Some(frame3.len()));
}

// ---- clamp-panic safety (Copilot fold): ihl declares more than the slice ----

#[test]
fn ipv4_declared_end_oversized_ihl_truncated_buffer_returns_none_no_panic() {
    // IHL nibble = 15 => declared IPv4 header = 60 bytes, but the buffer
    // holds only l3 + 20 (eth + minimal IPv4 header, no options present).
    // Without the `frame.len() < l3 + ihl` guard, `clamp(min = l3+60,
    // max = l3+20)` has min > max and PANICS. Must fail closed (None).
    let mut frame = v4_frame(PROTO_TCP, 20, &[]); // eth(14) + IPv4(20), no L4
    assert_eq!(frame.len(), 14 + 20);
    frame[14] = 0x4f; // version 4, IHL = 15 (60-byte header claimed)
    // A panic here (clamp min > max) is a test FAILURE.
    assert_eq!(
        ipv4_declared_l3_end(&frame, 14),
        None,
        "oversized IHL on a truncated buffer must fail closed, not panic"
    );
}

#[test]
fn meta_fast_path_oversized_ihl_truncated_buffer_no_panic() {
    // Reachable from the meta-driven caller, which does NOT validate ihl
    // against the slice. Same crafted frame; must not panic and must yield
    // no ports (None).
    let mut frame = v4_frame(PROTO_TCP, 20, &[]);
    frame[14] = 0x4f; // IHL = 15
    let meta = ForwardPacketMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 14 + 20,
        ..ForwardPacketMeta::default()
    };
    assert_eq!(
        live_frame_ports_from_meta_bytes(&frame, meta),
        None,
        "meta fast path must not panic on an oversized IHL truncated frame"
    );
}

// ---- #3067: ICMP identifier is a pseudo-port ONLY for query types ----
//
// `parse_flow_ports` reads bytes [l4+4, l4+6) of the ICMP/ICMPv6 header as a
// pseudo source port. Those two bytes are the Identifier ONLY for the query
// types (Echo, and for ICMPv4 the Timestamp/Information pairs). For error and
// control types (Dest-Unreachable, Packet-Too-Big, Time-Exceeded,
// Parameter-Problem, Redirect, ND/MLD) they are part of a gateway address /
// next-hop MTU / pointer / unused field — NOT a port — so treating them as one
// installed bogus identifier-keyed sessions for transit ICMP control traffic.
// These tests pin the type discrimination. Reverting it (back to an
// unconditional `Some((ident, 0))`) turns the non-query assertions RED.

/// Build an 8-byte ICMP/ICMPv6 header L4 payload: type, code, 2-byte checksum,
/// then a 2-byte "identifier" word (bytes [4..6]) and a 2-byte sequence word.
fn icmp_l4(icmp_type: u8, ident: u16) -> [u8; 8] {
    let id = ident.to_be_bytes();
    [icmp_type, 0x00, 0x00, 0x00, id[0], id[1], 0x00, 0x01]
}

const ICMP_IDENT: u16 = 0xABCD;
// Reachable l4/declared_end for the helper-built frames: eth(14) + IP header.
const V4_ICMP_L4: usize = 14 + 20;
const V6_ICMP_L4: usize = 14 + 40;

#[test]
fn icmpv4_echo_request_reply_still_yields_identifier_pseudo_port() {
    for icmp_type in [8u8, 0u8] {
        let frame = v4_frame(PROTO_ICMP, 28, &icmp_l4(icmp_type, ICMP_IDENT));
        let declared_end = ipv4_declared_l3_end(&frame, 14).expect("v4 declared end");
        assert_eq!(
            parse_flow_ports(&frame, V4_ICMP_L4, PROTO_ICMP, declared_end),
            Some((ICMP_IDENT, 0)),
            "ICMPv4 echo type {icmp_type} must still carry the identifier as the pseudo-port"
        );
    }
}

#[test]
fn icmpv4_timestamp_information_query_types_yield_identifier() {
    // RFC 792 query types whose Identifier sits at the same [4..6] offset.
    for icmp_type in [13u8, 14u8, 15u8, 16u8] {
        let frame = v4_frame(PROTO_ICMP, 28, &icmp_l4(icmp_type, ICMP_IDENT));
        let declared_end = ipv4_declared_l3_end(&frame, 14).unwrap();
        assert_eq!(
            parse_flow_ports(&frame, V4_ICMP_L4, PROTO_ICMP, declared_end),
            Some((ICMP_IDENT, 0)),
            "ICMPv4 query type {icmp_type} carries an identifier at [4..6]"
        );
    }
}

#[test]
fn icmpv4_error_control_types_yield_no_pseudo_port() {
    // Dest-Unreachable (3), Time-Exceeded (11), Parameter-Problem (12),
    // Redirect (5). Bytes [4..6] here are NOT an identifier — they are part of
    // the unused word / gateway address / pointer. Must be flowless (None) so
    // no bogus identifier-keyed session is installed.
    for icmp_type in [3u8, 5u8, 11u8, 12u8] {
        // The "identifier" bytes are present in the slice (proving the old
        // unconditional read would have returned them as a fake port).
        let frame = v4_frame(PROTO_ICMP, 28, &icmp_l4(icmp_type, ICMP_IDENT));
        let declared_end = ipv4_declared_l3_end(&frame, 14).unwrap();
        assert_eq!(
            parse_flow_ports(&frame, V4_ICMP_L4, PROTO_ICMP, declared_end),
            None,
            "ICMPv4 error/control type {icmp_type} must NOT install a pseudo-port"
        );
    }
}

#[test]
fn icmpv6_echo_request_reply_still_yields_identifier_pseudo_port() {
    for icmp_type in [128u8, 129u8] {
        let frame = v6_frame(PROTO_ICMPV6, 8, &icmp_l4(icmp_type, ICMP_IDENT));
        let declared_end = ipv6_declared_l3_end(&frame, 14).expect("v6 declared end");
        assert_eq!(
            parse_flow_ports(&frame, V6_ICMP_L4, PROTO_ICMPV6, declared_end),
            Some((ICMP_IDENT, 0)),
            "ICMPv6 echo type {icmp_type} must still carry the identifier as the pseudo-port"
        );
    }
}

#[test]
fn icmpv6_packet_too_big_redirect_nd_yield_no_pseudo_port() {
    // Packet-Too-Big (2) — bytes [4..6] are the high half of the next-hop MTU.
    // Dest-Unreachable (1), Time-Exceeded (3), Parameter-Problem (4),
    // Redirect (137), Router/Neighbor Solicit/Advert (133..136). None is an
    // identifier-bearing query type -> flowless.
    for icmp_type in [1u8, 2u8, 3u8, 4u8, 133u8, 134u8, 135u8, 136u8, 137u8] {
        let frame = v6_frame(PROTO_ICMPV6, 8, &icmp_l4(icmp_type, ICMP_IDENT));
        let declared_end = ipv6_declared_l3_end(&frame, 14).unwrap();
        assert_eq!(
            parse_flow_ports(&frame, V6_ICMP_L4, PROTO_ICMPV6, declared_end),
            None,
            "ICMPv6 error/control/ND type {icmp_type} must NOT install a pseudo-port"
        );
    }
}

// ---- #3290: the metadata fallback must honor the SAME ICMP query-type gate ----
//
// The XDP shim stamps `flow_src_port = bytes[l4+4..l4+6]` for EVERY ICMP type
// (no query gate), so a non-query ICMP error/control packet arrives with a
// hostile pseudo-port in metadata. `parse_session_flow_from_bytes` must NOT
// reconstruct a stateful SessionFlow from that metadata word — otherwise the
// #3067 frame-parser invariant is bypassed via the metadata path and the
// session table is polluted with a fake ICMP-control "flow". Reverting the
// gate (so the meta fallback is reached for these types) turns the None
// assertions RED.

/// Hostile pseudo-port the shim would stamp into `flow_src_port` from the
/// control bytes of a non-query ICMP packet.
const ICMP_HOSTILE_PORT: u16 = 0xBEEF;

#[test]
fn meta_fallback_icmpv4_error_control_installs_no_session() {
    // Dest-Unreachable (3), Redirect (5), Time-Exceeded (11),
    // Parameter-Problem (12). Frame is well-formed (the frame parser already
    // returns None for it), and metadata carries matching IPs plus the hostile
    // pseudo-port — exactly the #3290 attack shape.
    for icmp_type in [3u8, 5u8, 11u8, 12u8] {
        let frame = v4_frame(PROTO_ICMP, 28, &icmp_l4(icmp_type, ICMP_HOSTILE_PORT));
        let meta = UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            l3_offset: 14,
            l4_offset: V4_ICMP_L4 as u16,
            flow_src_port: ICMP_HOSTILE_PORT,
            flow_dst_port: 0,
            flow_src_addr: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            flow_dst_addr: [192, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ..UserspaceDpMeta::default()
        };
        assert_eq!(
            parse_session_flow_from_bytes(&frame, meta),
            None,
            "ICMPv4 error/control type {icmp_type} must not install a metadata-keyed session"
        );
    }
}

#[test]
fn meta_fallback_icmpv6_error_control_nd_installs_no_session() {
    // Dest-Unreachable (1), Packet-Too-Big (2), Time-Exceeded (3),
    // Parameter-Problem (4), the MLD types (130 Query / 131 Report / 132 Done
    // / 143 MLDv2 Report), and the ND types (133..137 Router/Neighbor
    // Solicit/Advert + Redirect).
    for icmp_type in [
        1u8, 2u8, 3u8, 4u8, 130u8, 131u8, 132u8, 133u8, 134u8, 135u8, 136u8, 137u8, 143u8,
    ] {
        let frame = v6_frame(PROTO_ICMPV6, 8, &icmp_l4(icmp_type, ICMP_HOSTILE_PORT));
        let meta = UserspaceDpMeta {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            l3_offset: 14,
            l4_offset: V6_ICMP_L4 as u16,
            flow_src_port: ICMP_HOSTILE_PORT,
            flow_dst_port: 0,
            flow_src_addr: [0x20; 16],
            flow_dst_addr: [0x30; 16],
            ..UserspaceDpMeta::default()
        };
        assert_eq!(
            parse_session_flow_from_bytes(&frame, meta),
            None,
            "ICMPv6 error/control/ND type {icmp_type} must not install a metadata-keyed session"
        );
    }
}

#[test]
fn meta_fallback_icmpv4_echo_still_keys_on_identifier() {
    // Identifier-bearing query types (Echo Request 8 / Reply 0) are
    // unaffected: the metadata identifier matches the frame-derived one, so a
    // stateful flow keyed on the identifier pseudo-port is still produced.
    for icmp_type in [8u8, 0u8] {
        let frame = v4_frame(PROTO_ICMP, 28, &icmp_l4(icmp_type, ICMP_IDENT));
        let meta = UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            l3_offset: 14,
            l4_offset: V4_ICMP_L4 as u16,
            flow_src_port: ICMP_IDENT,
            flow_dst_port: 0,
            flow_src_addr: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            flow_dst_addr: [192, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ..UserspaceDpMeta::default()
        };
        let flow = parse_session_flow_from_bytes(&frame, meta)
            .expect("ICMPv4 echo query must still build an identifier-keyed flow");
        assert_eq!(flow.forward_key.src_port, ICMP_IDENT);
        assert_eq!(flow.forward_key.dst_port, 0);
    }
}

#[test]
fn meta_fallback_icmpv4_truncated_echo_installs_no_session() {
    // #3290 (frame-equivalence): an Echo (query) packet truncated between the
    // type byte and its 2-byte Identifier. `parse_flow_ports` returns None
    // here because the identifier END lies past the IP-declared datagram, so
    // the metadata gate must ALSO reject it — otherwise the shim's pseudo-port
    // (read from bytes outside the declared identifier) would still install a
    // metadata-keyed session. declared total_len = 24 -> declared end at frame
    // offset 38: the type byte (offset 34) is inside, the identifier
    // [38..40) is NOT. Checking only the type byte (the pre-fold behavior)
    // would wrongly admit the meta fallback -> RED on revert.
    let frame = v4_frame(PROTO_ICMP, 24, &icmp_l4(8, ICMP_IDENT));
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        l3_offset: 14,
        l4_offset: V4_ICMP_L4 as u16,
        flow_src_port: ICMP_HOSTILE_PORT,
        flow_dst_port: 0,
        flow_src_addr: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [192, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_session_flow_from_bytes(&frame, meta),
        None,
        "a query packet truncated before its identifier must not install a metadata-keyed session"
    );
}
