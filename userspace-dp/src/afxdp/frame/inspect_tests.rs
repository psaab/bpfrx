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
