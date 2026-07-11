// fragment predicates, firewall term-extra match extraction (incl. flex-bytes clamping), and non-first-fragment NAT/clamp handling.
//
// Split out of afxdp/frame/tests.rs (#4840) as a sibling `#[path]` test
// module loaded from afxdp/frame/mod.rs. Pure code motion: every #[test]
// fn is moved verbatim; shared test-support helpers live in
// afxdp/frame/tests_support.rs.
#![allow(unused_imports)]

use super::super::test_fixtures::*;
use super::*;
use crate::event_stream::DataplaneEventRateLimitConfig;
use crate::event_stream::codec::DataplaneEventKind;
use crate::test_zone_ids::*;
use crate::{FirewallFilterSnapshot, FirewallTermSnapshot, ThreeColorPolicerSnapshot};
use super::tests_support::*;

#[test]
fn ipv4_non_first_fragment_predicate_truth_table() {
    // offset 0, MF=0 (atomic) and MF=1 (first) -> first/atomic, false.
    assert!(!ipv4_is_non_first_fragment(&frag_v4_packet(
        PROTO_TCP, 0x0000, &[0; 8]
    )));
    assert!(!ipv4_is_non_first_fragment(&frag_v4_packet(
        PROTO_TCP, 0x2000, &[0; 8]
    )));
    // offset != 0 -> non-first (with and without MF).
    assert!(ipv4_is_non_first_fragment(&frag_v4_packet(
        PROTO_TCP, 0x0001, &[0; 8]
    )));
    assert!(ipv4_is_non_first_fragment(&frag_v4_packet(
        PROTO_TCP, 0x2001, &[0; 8]
    )));
    // too-short slice -> false (length guards reject separately).
    assert!(!ipv4_is_non_first_fragment(&[0x45, 0x00, 0x00]));
}


#[test]
fn ipv6_non_first_fragment_predicate_truth_table() {
    // No fragment header -> false.
    assert!(!ipv6_is_non_first_fragment(&frag_v6_packet(
        PROTO_TCP, None, &[0; 8]
    )));
    // Fragment header, offset 0 (first/atomic) with MF=0 and MF=1 -> false.
    assert!(!ipv6_is_non_first_fragment(&frag_v6_packet(
        PROTO_TCP,
        Some(0x0000),
        &[0; 8]
    )));
    assert!(!ipv6_is_non_first_fragment(&frag_v6_packet(
        PROTO_TCP,
        Some(0x0001),
        &[0; 8]
    )));
    // Fragment header, offset bits set -> non-first.
    assert!(ipv6_is_non_first_fragment(&frag_v6_packet(
        PROTO_TCP,
        Some(0x0008),
        &[0; 8]
    )));
    assert!(ipv6_is_non_first_fragment(&frag_v6_packet(
        PROTO_TCP,
        Some(0xABC8),
        &[0; 8]
    )));
}


// #2362: Junos `is-fragment` matches ANY fragment (first OR non-first), unlike
// the non-first predicate above. The MF bit (0x2000) alone (offset 0) means a
// FIRST fragment, which must match.
#[test]
fn ipv4_any_fragment_predicate_truth_table() {
    // Unfragmented datagram (MF=0, offset=0) -> not a fragment.
    assert!(!ipv4_is_any_fragment(&frag_v4_packet(
        PROTO_TCP, 0x0000, &[0; 8]
    )));
    // DF set only (0x4000) -> still not a fragment.
    assert!(!ipv4_is_any_fragment(&frag_v4_packet(
        PROTO_TCP, 0x4000, &[0; 8]
    )));
    // First fragment (MF=1, offset=0) -> IS a fragment.
    assert!(ipv4_is_any_fragment(&frag_v4_packet(
        PROTO_TCP, 0x2000, &[0; 8]
    )));
    // Middle/last fragment (offset != 0) -> IS a fragment, MF set or not.
    assert!(ipv4_is_any_fragment(&frag_v4_packet(
        PROTO_TCP, 0x0001, &[0; 8]
    )));
    assert!(ipv4_is_any_fragment(&frag_v4_packet(
        PROTO_TCP, 0x2001, &[0; 8]
    )));
    // Too-short slice -> false.
    assert!(!ipv4_is_any_fragment(&[0x45, 0x00, 0x00]));
}


#[test]
fn ipv6_any_fragment_predicate_truth_table() {
    // No fragment header -> not a fragment.
    assert!(!ipv6_is_any_fragment(&frag_v6_packet(
        PROTO_TCP, None, &[0; 8]
    )));
    // Fragment header present, first fragment (offset 0, M=1) -> IS a fragment.
    assert!(ipv6_is_any_fragment(&frag_v6_packet(
        PROTO_TCP,
        Some(0x0001),
        &[0; 8]
    )));
    // Fragment header present, offset 0, M=0 (atomic-ish) -> still a fragment
    // header is present, so Junos is-fragment matches.
    assert!(ipv6_is_any_fragment(&frag_v6_packet(
        PROTO_TCP,
        Some(0x0000),
        &[0; 8]
    )));
    // Middle/last fragment -> IS a fragment.
    assert!(ipv6_is_any_fragment(&frag_v6_packet(
        PROTO_TCP,
        Some(0x0008),
        &[0; 8]
    )));
}


// #2362 fold A (the #2344 non-first-fragment class): term_match_extra_from_frame
// must NOT read L4-derived match inputs from a non-first fragment — its bytes
// at l4_offset are payload, not a real L4 header. is_fragment (L3-only) MUST
// still be set. These fail if the non-first-fragment gate is removed.
#[test]
fn term_extra_non_first_icmp_fragment_suppresses_icmp_type_keeps_is_fragment() {
    // Non-first ICMP fragment (offset != 0) whose payload byte at l4_offset == 8
    // (would spuriously match `icmp-type 8` without the gate).
    let frag = frag_v4_packet(PROTO_ICMP, 0x0001, &[8, 0, 0, 0, 0, 0, 0, 0]);
    let mut frame = vec![0u8; 14];
    frame.extend_from_slice(&frag);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let extra = term_match_extra_from_frame(&frame, meta);
    assert_eq!(
        extra.icmp_type, 0,
        "non-first fragment payload byte must NOT leak as icmp_type"
    );
    assert_eq!(extra.icmp_code, 0);
    assert_eq!(extra.tcp_flags, 0);
    assert!(
        !extra.l4_present,
        "non-first fragment has no L4 header → l4_present must be false (the matcher gates on this, not the byte value)"
    );
    assert!(
        extra.is_fragment,
        "a non-first fragment IS a fragment (is-fragment must match)"
    );
}


#[test]
fn term_extra_non_first_tcp_fragment_suppresses_tcp_flags() {
    // Non-first TCP fragment with meta.tcp_flags carrying SYN (payload-derived).
    let frag = frag_v4_packet(PROTO_TCP, 0x0001, &[0; 8]);
    let mut frame = vec![0u8; 14];
    frame.extend_from_slice(&frag);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0x02, // SYN — would spuriously match `tcp-flags syn`
        ..UserspaceDpMeta::default()
    };
    let extra = term_match_extra_from_frame(&frame, meta);
    assert_eq!(
        extra.tcp_flags, 0,
        "non-first fragment must NOT expose payload-derived tcp_flags"
    );
    assert!(!extra.l4_present, "non-first fragment → l4_present false");
    assert!(extra.is_fragment);
}


#[test]
fn term_extra_first_fragment_keeps_l4_fields() {
    // A FIRST fragment (offset 0, MF=1) carries the real L4 header — keep the
    // L4 fields AND mark is_fragment.
    let frag = frag_v4_packet(PROTO_ICMP, 0x2000, &[8, 0, 0, 0, 0, 0, 0, 0]);
    let mut frame = vec![0u8; 14];
    frame.extend_from_slice(&frag);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let extra = term_match_extra_from_frame(&frame, meta);
    assert_eq!(
        extra.icmp_type, 8,
        "first fragment carries the real ICMP type"
    );
    assert!(
        extra.l4_present,
        "first fragment carries the real L4 header → l4_present true"
    );
    assert!(extra.is_fragment, "first fragment IS a fragment");
}


// #2449 (the truncation class): a NON-FRAGMENTED ICMP frame that is shorter
// than `l4_offset + 2` carries NO type/code bytes. The pre-fix code read them
// with `.unwrap_or(0)` while keeping `l4_present = true`, so the frame
// spuriously matched `icmp-type 0 / icmp-code 0` (Echo Reply). The guard must
// force (0, 0, 0) AND drop l4_present. Reverting the guard makes the truncated
// frame expose `l4_present == true` again — this test then fails.
#[test]
fn term_extra_truncated_icmp_v4_fails_closed_no_icmp_type_match() {
    // Non-fragmented ICMP packet (frag_off 0) but truncated: the frame ends at
    // l4_offset, so neither type nor code byte is present.
    let frag = frag_v4_packet(PROTO_ICMP, 0x0000, &[]);
    let mut frame = vec![0u8; 14];
    frame.extend_from_slice(&frag);
    // frame ends exactly at l4_offset (14 ethernet + 20 IPv4 = 34); no L4 bytes.
    let l4_offset = (14 + 20) as u16;
    assert_eq!(frame.len(), l4_offset as usize);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let extra = term_match_extra_from_frame(&frame, meta);
    assert_eq!(
        extra.icmp_type, 0,
        "truncated ICMP must not surface a real icmp_type"
    );
    assert_eq!(extra.icmp_code, 0);
    assert!(
        !extra.l4_present,
        "truncated ICMP frame has no type/code bytes → l4_present MUST be false \
         so an `icmp-type 0` term fails closed (reverting the #2449 guard makes \
         this true and the term spuriously matches)"
    );
    // is_fragment is L3-only and this is not a fragment.
    assert!(!extra.is_fragment, "non-fragmented packet is not a fragment");
}


#[test]
fn term_extra_truncated_icmp_v4_one_byte_short_fails_closed() {
    // One byte present (type) but code byte missing — still truncated, still
    // fail-closed (we require BOTH type and code bytes).
    let frag = frag_v4_packet(PROTO_ICMP, 0x0000, &[8]);
    let mut frame = vec![0u8; 14];
    frame.extend_from_slice(&frag);
    let l4_offset = (14 + 20) as u16;
    assert_eq!(frame.len(), l4_offset as usize + 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let extra = term_match_extra_from_frame(&frame, meta);
    assert_eq!(extra.icmp_type, 0, "type byte must not leak when code absent");
    assert_eq!(extra.icmp_code, 0);
    assert!(
        !extra.l4_present,
        "ICMP frame one byte short of type+code → fail closed"
    );
}


#[test]
fn term_extra_full_icmp_v4_still_matches() {
    // A FULL non-fragmented ICMP packet (type 8 echo-request, code 0) keeps the
    // real type/code and l4_present true — proves the guard does not over-reject
    // legitimate packets.
    let frag = frag_v4_packet(PROTO_ICMP, 0x0000, &[8, 0, 0, 0, 0, 0, 0, 0]);
    let mut frame = vec![0u8; 14];
    frame.extend_from_slice(&frag);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let extra = term_match_extra_from_frame(&frame, meta);
    assert_eq!(extra.icmp_type, 8, "full ICMP carries the real type");
    assert_eq!(extra.icmp_code, 0);
    assert!(extra.l4_present, "full ICMP frame → l4_present true");
}


// #2449 IPv6 sibling: a truncated ICMPv6 frame (no type/code bytes past the
// fixed IPv6 header) must also fail closed.
#[test]
fn term_extra_truncated_icmpv6_fails_closed() {
    use crate::ip_proto::PROTO_ICMPV6;
    // Non-fragmented IPv6 (no fragment header), truncated at l4_offset.
    let pkt = frag_v6_packet(PROTO_ICMPV6, None, &[]);
    let mut frame = vec![0u8; 14];
    frame.extend_from_slice(&pkt);
    let l4_offset = (14 + 40) as u16;
    assert_eq!(frame.len(), l4_offset as usize, "frame ends at l4_offset");
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };
    let extra = term_match_extra_from_frame(&frame, meta);
    assert_eq!(extra.icmp_type, 0);
    assert_eq!(extra.icmp_code, 0);
    assert!(
        !extra.l4_present,
        "truncated ICMPv6 frame must fail closed (l4_present false)"
    );
}


#[test]
fn term_extra_flex_l3_l4_clamped_to_ipv4_declared_end_excludes_ethernet_slack() {
    // Real 8-byte L4 payload; frag_v4_packet sets IPv4 total-length correctly to
    // 20 (IP header) + payload.len().
    let payload = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let datagram = frag_v4_packet(PROTO_UDP, 0x0000, &payload);
    let total_length = datagram.len(); // == the IPv4 total-length field
    let mut frame = vec![0u8; 14]; // ethernet header
    frame.extend_from_slice(&datagram);
    frame.extend_from_slice(&FLEX_SLACK_MARKER); // attacker bytes in Ethernet slack
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 14 + 20, // ethernet + IPv4 header
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    let extra = term_match_extra_from_frame(&frame, meta);

    let flex_l3 = extra.flex_l3.expect("l3 slice present");
    assert_eq!(
        flex_l3.len(),
        total_length,
        "flex_l3 must end at the IP-declared datagram end (l3_offset + total-length), \
         excluding the 4 Ethernet-slack bytes — reverting the clamp to ..frame.len() \
         makes this total_length + 4 and fails here"
    );
    assert!(
        !flex_l3.ends_with(&FLEX_SLACK_MARKER),
        "the attacker slack marker must NOT be visible to a layer-3 flex byte-match"
    );

    let flex_l4 = extra.flex_l4.expect("l4 slice present");
    assert_eq!(
        flex_l4.len(),
        payload.len(),
        "flex_l4 (from l4_offset) must end at the declared datagram end — the real \
         L4 payload only, no Ethernet slack"
    );
    assert!(
        !flex_l4.ends_with(&FLEX_SLACK_MARKER),
        "the attacker slack marker must NOT be visible to a layer-4 flex byte-match"
    );
}


#[test]
fn term_extra_flex_no_slack_exposes_full_ipv4_datagram() {
    // No Ethernet slack: frame.len() == 14 + total-length, so declared_end ==
    // frame.len() and both slices are byte-identical to pre-#5150 behavior.
    let payload = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02];
    let datagram = frag_v4_packet(PROTO_UDP, 0x0000, &payload);
    let mut frame = vec![0u8; 14];
    frame.extend_from_slice(&datagram);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 14 + 20,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    let extra = term_match_extra_from_frame(&frame, meta);
    assert_eq!(
        extra.flex_l3,
        Some(&frame[14..]),
        "a well-formed packet with no slack must expose the full L3 datagram (no regression)"
    );
    assert_eq!(
        extra.flex_l4,
        Some(&frame[14 + 20..]),
        "flex_l4 must expose the full L4 payload when there is no slack"
    );
}


#[test]
fn term_extra_flex_lying_oversized_ipv4_length_clamped_to_frame() {
    // A LYING (too-large) IPv4 total-length must clamp to frame.len(): the slice
    // is bounded by the physical frame, never over-reading (no panic).
    let payload = [0x11u8, 0x22, 0x33, 0x44];
    let mut datagram = frag_v4_packet(PROTO_UDP, 0x0000, &payload);
    datagram[2..4].copy_from_slice(&0xFFFFu16.to_be_bytes()); // total-length = 65535
    let mut frame = vec![0u8; 14];
    frame.extend_from_slice(&datagram);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 14 + 20,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    let extra = term_match_extra_from_frame(&frame, meta);
    assert_eq!(
        extra.flex_l3,
        Some(&frame[14..]),
        "a lying oversized IP total-length must clamp to frame.len(), not over-read"
    );
    assert_eq!(extra.flex_l4, Some(&frame[14 + 20..]));
}


#[test]
fn term_extra_flex_tiny_ipv4_length_l4_offset_past_declared_end_fails_closed() {
    // A TINY declared total-length (10) puts the declared datagram end (l3+10=24)
    // BEFORE l4_offset (34). The L4 slice range is invalid → None (fail closed,
    // no panic, no negative range). flex_l3 is a bounded 10-byte window.
    let payload = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let mut datagram = frag_v4_packet(PROTO_UDP, 0x0000, &payload);
    datagram[2..4].copy_from_slice(&10u16.to_be_bytes());
    let mut frame = vec![0u8; 14];
    frame.extend_from_slice(&datagram);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 14 + 20, // 34, past the declared end (24)
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    let extra = term_match_extra_from_frame(&frame, meta);
    assert!(
        extra.flex_l4.is_none(),
        "l4_offset at/past the declared datagram end must yield no L4 slice (fail closed)"
    );
    assert_eq!(
        extra.flex_l3.map(<[u8]>::len),
        Some(10),
        "flex_l3 is clamped to the tiny declared length (l3_offset..l3_offset+10)"
    );
}


#[test]
fn term_extra_flex_clamped_to_ipv6_declared_end_excludes_ethernet_slack() {
    // IPv6 sibling: payload-length == payload.len() (no ext headers), so the
    // declared datagram end is l3 + 40 + payload-length == datagram.len().
    let payload = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let datagram = frag_v6_packet(PROTO_UDP, None, &payload);
    let declared_len = datagram.len();
    let mut frame = vec![0u8; 14];
    frame.extend_from_slice(&datagram);
    frame.extend_from_slice(&FLEX_SLACK_MARKER);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 14 + 40,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    let extra = term_match_extra_from_frame(&frame, meta);
    let flex_l3 = extra.flex_l3.expect("l3 slice present");
    assert_eq!(
        flex_l3.len(),
        declared_len,
        "IPv6 flex_l3 must end at l3 + 40 + payload-length, excluding Ethernet slack"
    );
    assert!(!flex_l3.ends_with(&FLEX_SLACK_MARKER));
    let flex_l4 = extra.flex_l4.expect("l4 slice present");
    assert_eq!(flex_l4.len(), payload.len());
    assert!(!flex_l4.ends_with(&FLEX_SLACK_MARKER));
}


#[test]
fn term_extra_fwd_flex_clamped_to_ipv4_declared_end_excludes_slack() {
    // The ForwardPacketMeta (CoS / TX-selection) builder is the twin fold and
    // MUST apply the identical clamp — otherwise a CoS-action byte-match on that
    // path reads Ethernet slack.
    let payload = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let datagram = frag_v4_packet(PROTO_UDP, 0x0000, &payload);
    let total_length = datagram.len();
    let mut frame = vec![0u8; 14];
    frame.extend_from_slice(&datagram);
    frame.extend_from_slice(&FLEX_SLACK_MARKER);
    let meta = ForwardPacketMeta {
        l3_offset: 14,
        l4_offset: 14 + 20,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..ForwardPacketMeta::default()
    };
    let extra = term_match_extra_from_frame_fwd(&frame, meta);
    let flex_l3 = extra.flex_l3.expect("l3 slice present");
    assert_eq!(
        flex_l3.len(),
        total_length,
        "the fwd builder must clamp flex_l3 to the IP-declared end too"
    );
    assert!(!flex_l3.ends_with(&FLEX_SLACK_MARKER));
    assert!(!extra.flex_l4.expect("l4 slice present").ends_with(&FLEX_SLACK_MARKER));
}


// #3008 (meta sibling of #2449): `term_match_extra_from_meta` builds match
// inputs from metadata ALONE — there is no frame to read the real ICMP type/code
// from. The pre-fix code stamped `icmp_type = icmp_code = 0` while keeping
// `l4_present = true`, so any term keyed on `icmp-type 0` (echo-reply) or
// `icmp-code 0` (a valid, common value) FALSE-MATCHED every ICMP-family packet
// whose type/code was never parsed. The fix drops `l4_present` for ICMP/ICMPv6
// on this path so the matcher fails the icmp-type/code terms closed. These tests
// FAIL if `l4_present` reverts to an unconditional `true`.
#[test]
fn term_extra_from_meta_icmpv4_fails_closed_no_icmp_type_match() {
    use crate::ip_proto::PROTO_ICMP;
    let meta: ForwardPacketMeta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    }
    .into();
    let extra = term_match_extra_from_meta(meta);
    assert_eq!(extra.icmp_type, 0);
    assert_eq!(extra.icmp_code, 0);
    assert!(
        !extra.l4_present,
        "meta-only ICMP packet has no parsed type/code → l4_present MUST be false \
         so an `icmp-type 0` / `icmp-code 0` term fails closed (reverting to \
         unconditional l4_present=true makes this true and the term spuriously \
         matches every ICMP-family packet)"
    );
    assert!(!extra.is_fragment);
}


#[test]
fn term_extra_from_meta_icmpv6_fails_closed_no_icmp_type_match() {
    use crate::ip_proto::PROTO_ICMPV6;
    let meta: ForwardPacketMeta = UserspaceDpMeta {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    }
    .into();
    let extra = term_match_extra_from_meta(meta);
    assert_eq!(extra.icmp_type, 0);
    assert_eq!(extra.icmp_code, 0);
    assert!(
        !extra.l4_present,
        "meta-only ICMPv6 packet must fail closed (l4_present false)"
    );
}


// Anti-over-gate: a meta-only TCP packet must KEEP l4_present true so the
// authoritative shim-stamped tcp_flags still drives `tcp-flags` matching. The
// #3008 fix only drops l4_present for the ICMP family.
#[test]
fn term_extra_from_meta_tcp_keeps_l4_present_and_tcp_flags() {
    use crate::ip_proto::PROTO_TCP;
    let meta: ForwardPacketMeta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0x02, // SYN
        ..UserspaceDpMeta::default()
    }
    .into();
    let extra = term_match_extra_from_meta(meta);
    assert_eq!(
        extra.tcp_flags, 0x02,
        "meta-only TCP must surface the authoritative shim-stamped tcp_flags"
    );
    assert!(
        extra.l4_present,
        "meta-only TCP carries a real L4 header (tcp_flags authoritative) → \
         l4_present stays true so tcp-flags terms keep matching"
    );
}


#[test]
fn apply_nat_ipv4_non_first_fragment_rewrites_ip_only() {
    // Payload bytes occupy the post-IP offset where the buggy code would
    // write the dst port + adjust an L4 checksum.
    let payload = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
    let mut frag = frag_v4_packet(PROTO_TCP, 0x0001, &payload);
    let nat = NatDecision {
        rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
        rewrite_dst_port: Some(8080),
        ..NatDecision::default()
    };
    assert_eq!(apply_nat_ipv4(&mut frag, PROTO_TCP, nat, true), Some(()));
    // dst IP rewritten on the fragment ...
    assert_eq!(&frag[16..20], &[192, 0, 2, 9]);
    // ... but the payload (the fictitious L4 header) is byte-identical.
    assert_eq!(&frag[20..], &payload);
}


#[test]
fn apply_nat_ipv6_non_first_fragment_rewrites_ip_only() {
    let payload = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
    let mut frag = frag_v6_packet(PROTO_TCP, Some(0x0008), &payload);
    let new_dst = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x99);
    let nat = NatDecision {
        rewrite_dst: Some(IpAddr::V6(new_dst)),
        rewrite_dst_port: Some(8080),
        ..NatDecision::default()
    };
    // rel_l4 = 48 (40 base + 8 fragment header).
    assert_eq!(
        apply_nat_ipv6(&mut frag, 48, PROTO_TCP, nat, true),
        Some(())
    );
    assert_eq!(&frag[24..40], &new_dst.octets());
    assert_eq!(&frag[48..], &payload);
}


#[test]
fn enforce_expected_ports_skips_non_first_fragment() {
    // A non-first fragment's "ports" are payload; enforcement must no-op.
    let payload = [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0];
    let mut frame = frag_v4_packet(PROTO_TCP, 0x0001, &payload);
    let before = frame.clone();
    let repaired = enforce_expected_ports(
        &mut frame,
        libc::AF_INET as u8,
        PROTO_TCP,
        Some((54688, 5201)),
        true,
    )
    .expect("enforce");
    assert!(!repaired);
    assert_eq!(
        frame, before,
        "non-first fragment payload must be untouched"
    );
}


#[test]
fn clamp_tcp_mss_clamps_ext_headered_v6_syn() {
    // hop-by-hop ext header (8 bytes, next=TCP) then a SYN with an MSS
    // option of 1460. Before #1852 the fixed (40, packet[6]) read saw
    // packet[6] == 0 (hop-by-hop) and bailed; now the clamp walks the
    // chain and clamps to 1400.
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[6] = 0; // next header = hop-by-hop
    p[7] = 64;
    // hop-by-hop: next=TCP(6), hdr ext len 0 (8 bytes total).
    p.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
    // TCP header at offset 48: ports, seq, ack, data-offset=6 (24 bytes,
    // 20 + 4 MSS option), SYN flag, window, csum, urg, MSS option.
    let mut tcp = vec![0u8; 24];
    tcp[12] = 6 << 4; // data offset 6 words = 24 bytes
    tcp[13] = 0x02; // SYN
    tcp[20] = 2; // MSS kind
    tcp[21] = 4; // MSS len
    tcp[22..24].copy_from_slice(&1460u16.to_be_bytes());
    p.extend_from_slice(&tcp);
    let plen = (p.len() - 40) as u16;
    p[4..6].copy_from_slice(&plen.to_be_bytes());

    assert!(
        super::tcp::clamp_tcp_mss(&mut p, 1400),
        "ext-headered v6 SYN must clamp"
    );
    let mss = u16::from_be_bytes([p[48 + 22], p[48 + 23]]);
    assert_eq!(mss, 1400);
}


#[test]
fn clamp_tcp_mss_skips_non_first_fragment() {
    // A non-first v4 fragment whose payload happens to look like a SYN
    // with an MSS option must NOT be clamped (the bytes are payload).
    let mut tcp_like = vec![0u8; 24];
    tcp_like[12] = 6 << 4;
    tcp_like[13] = 0x02; // looks like SYN
    tcp_like[20] = 2;
    tcp_like[21] = 4;
    tcp_like[22..24].copy_from_slice(&1460u16.to_be_bytes());
    let before = tcp_like.clone();
    let mut frag = frag_v4_packet(PROTO_TCP, 0x0001, &tcp_like);
    assert!(!super::tcp::clamp_tcp_mss(&mut frag, 1400));
    assert_eq!(&frag[20..], &before[..], "fragment payload untouched");
}


#[test]
fn build_tunnel_egress_non_first_fragment_skips_forced_l4_recompute() {
    // #1852 (Codex impl review): the copy builder's forced tunnel L4
    // recompute (tunnel_endpoint_id != 0 -> force_tunnel_l4_recompute)
    // must NOT run on a non-first fragment — it would write a checksum at
    // ihl+16, which is payload, re-corrupting what the NAT/port gates
    // protected. Build an eth + non-first IPv4 fragment + TCP-like
    // payload and assert the payload is byte-identical after the build.
    let mut out = Vec::new();
    write_eth_header(
        &mut out,
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        0,
        0x0800,
    );
    let ip_start = out.len(); // 14
    // IPv4 header: non-first fragment (offset 1), ttl 64, proto TCP.
    let payload = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    let total = (20 + payload.len()) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip[6..8].copy_from_slice(&0x0001u16.to_be_bytes()); // non-first
    ip[8] = 64;
    ip[9] = PROTO_TCP;
    ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
    ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
    out.extend_from_slice(&ip);
    out.extend_from_slice(&payload);
    let before_payload = payload.to_vec();
    let ingress = out.clone();

    let meta: ForwardPacketMeta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: ip_start as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    }
    .into();
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 7, // tunnel egress -> force_tunnel_l4_recompute
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };

    let mut egress = vec![0u8; ingress.len()];
    let written = build_forwarded_frame_into_from_frame(
        &mut egress,
        &ingress,
        meta,
        &decision,
        &ForwardingState::default(),
        false,
        None,
    )
    .expect("build");
    let out_payload_start = 14 + 20; // eth + ihl
    assert_eq!(
        &egress[out_payload_start..written],
        &before_payload[..],
        "forced tunnel L4 recompute must not touch non-first fragment payload"
    );
}

