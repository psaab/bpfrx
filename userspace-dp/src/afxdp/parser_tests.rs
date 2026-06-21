// Tests for afxdp/parser.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep parser.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "parser_tests.rs"]` from parser.rs.

use super::*;

fn build_eth_arp_reply(vlan: bool) -> Vec<u8> {
    let mut f = Vec::new();
    // dst mac
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    // src mac
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    if vlan {
        // 802.1Q + VID 100
        f.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]);
    }
    // ethertype = ARP
    f.extend_from_slice(&[0x08, 0x06]);
    // ARP body: htype=1, ptype=0x0800, hlen=6, plen=4, op=2 (reply)
    f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
    // sender mac
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    // sender ip 10.0.0.42
    f.extend_from_slice(&[10, 0, 0, 42]);
    // target mac (filled to 28-byte body)
    f.extend_from_slice(&[0x00; 6]);
    // target ip
    f.extend_from_slice(&[10, 0, 0, 1]);
    f
}

#[test]
fn classify_arp_reply_untagged() {
    let f = build_eth_arp_reply(false);
    match classify_arp(&f) {
        ArpClassification::Reply(r) => {
            assert_eq!(r.sender_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
            assert_eq!(r.sender_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)));
        }
        other => panic!("expected Reply, got {:?}", other),
    }
}

#[test]
fn classify_arp_reply_vlan_tagged() {
    let f = build_eth_arp_reply(true);
    match classify_arp(&f) {
        ArpClassification::Reply(r) => {
            assert_eq!(r.sender_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        }
        other => panic!("expected Reply, got {:?}", other),
    }
}

#[test]
fn classify_arp_request_is_other_arp() {
    let mut f = build_eth_arp_reply(false);
    // flip op from 2 (reply) to 1 (request)
    f[14 + 6] = 0x00;
    f[14 + 7] = 0x01;
    assert_eq!(classify_arp(&f), ArpClassification::OtherArp);
}

#[test]
fn classify_arp_rejects_non_arp_ethertype() {
    let mut f = build_eth_arp_reply(false);
    // change ethertype to IPv4
    f[12] = 0x08;
    f[13] = 0x00;
    assert_eq!(classify_arp(&f), ArpClassification::NotArp);
}

#[test]
fn classify_arp_rejects_short_frame() {
    let f = vec![0u8; 30];
    assert_eq!(classify_arp(&f), ArpClassification::NotArp);
}

fn build_eth_ndp_na(vlan: bool, with_tlla: bool) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    if vlan {
        f.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]);
    }
    // ethertype IPv6
    f.extend_from_slice(&[0x86, 0xdd]);
    // IPv6 header (40 bytes): version=6, payload-len=24+8 if TLLA else 24,
    // next-header=58 ICMPv6, hop-limit=255
    let payload_len = if with_tlla { 32u16 } else { 24u16 };
    f.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // ver+tc+flow
    f.extend_from_slice(&payload_len.to_be_bytes());
    f.push(NEXT_HEADER_ICMPV6); // next header
    f.push(255); // hop limit
                 // src ip
    f.extend_from_slice(&[
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x01,
    ]);
    // dst ip
    f.extend_from_slice(&[0xff; 16]);
    // ICMPv6 NA: type=136, code=0, checksum=0xffff, flags=0, target=fe80::abcd:ef01:0:42
    f.push(ICMPV6_TYPE_NA);
    f.push(0); // code
    f.extend_from_slice(&[0xff, 0xff]); // checksum
    f.extend_from_slice(&[0; 4]); // flags
                                  // target address
    f.extend_from_slice(&[
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x42,
    ]);
    if with_tlla {
        // option type=2 (TLLA), len=1 (×8 = 8 bytes), MAC
        f.push(NDP_OPT_TARGET_LL);
        f.push(1);
        f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }
    f
}

#[test]
fn parse_ndp_na_with_tlla_untagged() {
    let f = build_eth_ndp_na(false, true);
    let r = parse_ndp_neighbor_advert(&f).expect("NA parses");
    assert_eq!(
        r.target_ip,
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xabcd, 0xef01, 0, 0x42)),
    );
    assert_eq!(r.target_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
}

#[test]
fn parse_ndp_na_with_tlla_vlan() {
    let f = build_eth_ndp_na(true, true);
    let r = parse_ndp_neighbor_advert(&f).expect("VLAN NA parses");
    assert_eq!(r.target_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
}

#[test]
fn parse_ndp_na_without_tlla() {
    let f = build_eth_ndp_na(false, false);
    let r = parse_ndp_neighbor_advert(&f).expect("NA without TLLA still parses");
    assert!(r.target_mac.is_none());
}

#[test]
fn parse_ndp_na_rejects_non_icmpv6_next_header() {
    let mut f = build_eth_ndp_na(false, true);
    // flip next-header from ICMPv6 (58) to UDP (17)
    f[14 + 6] = 17;
    assert!(parse_ndp_neighbor_advert(&f).is_none());
}

#[test]
fn parse_ndp_na_rejects_non_na_type() {
    let mut f = build_eth_ndp_na(false, true);
    // flip ICMPv6 type from 136 (NA) to 135 (NS)
    f[14 + 40] = 135;
    assert!(parse_ndp_neighbor_advert(&f).is_none());
}

#[test]
fn parse_eth_offsets_handles_short_frame() {
    let f = vec![0u8; 12];
    assert!(parse_eth_offsets(&f).is_none());
}

// ---------------------------------------------------------------------------
// #2150 sub-fix tests + drift-guard canaries.
//
// The L2 canary pins the four userspace L2 offset parsers (parse_eth_offsets
// [learning], frame/inspect::frame_l3_offset [forwarding], cos/ecn::ethernet_l3
// [CoS ECN], nat64::frame_l3_offset [NAT64]) to AGREE on the L3 offset for
// every L2 shape the shim can steer to userspace, so a future drift on a
// single 0x88a8 tag (or any new tag handling) is caught at `cargo test`.
//
// The IPv6 canary pins the learning NDP walker to AGREE with the shared #2148
// forwarding walker on the L4 offset for every IPv6 extension-header chain.
//
// Both canaries FAIL on pre-fix code: pre-fix parse_eth_offsets returns l3=14
// on a 0x88a8 tag (the others return 18), and pre-fix parse_ndp_neighbor_advert
// returns None for an NA behind a hop-by-hop header (the forwarding walker
// finds the ICMPv6). PR-2 (full parser unification) is gated on these staying
// green.
// ---------------------------------------------------------------------------

use crate::afxdp::cos::ecn::{EthernetL3, ethernet_l3};
use crate::afxdp::frame::frame_l3_offset;

/// Build an L2 frame: dst+src MAC, an optional VLAN tag with the given
/// outer TPID, the given inner ethertype, then `body_len` zero body bytes.
fn build_l2_frame(outer_tpid: Option<u16>, inner_ethertype: u16, body_len: usize) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // src
    if let Some(tpid) = outer_tpid {
        f.extend_from_slice(&tpid.to_be_bytes());
        f.extend_from_slice(&0x0064u16.to_be_bytes()); // TCI: VID 100
    }
    f.extend_from_slice(&inner_ethertype.to_be_bytes());
    f.extend_from_slice(&vec![0u8; body_len]);
    f
}

/// The L2-offset parser that `nat64::frame_l3_offset` re-implements. We
/// can't reach the private `nat64::frame_l3_offset` from this module, so
/// `nat64_tests.rs::nat64_l2_offset_canary` proves NAT64 agrees; this
/// mirror documents the contract the four parsers share.
fn expected_l3_for_shape(outer_tpid: Option<u16>) -> usize {
    match outer_tpid {
        // single 0x8100 OR 0x88a8 tag → one tag → l3 at 18
        Some(0x8100) | Some(0x88a8) => 18,
        // untagged → l3 at 14
        None => 14,
        // any other outer ethertype is "untagged" from the L2 parser's
        // point of view (the ethertype IS the L3 discriminator)
        Some(_) => 14,
    }
}

#[test]
fn l2_offset_canary_all_parsers_agree() {
    // Every L2 shape the shim steers to userspace, × IPv4 / IPv6.
    let inner_families = [0x0800u16, 0x86DDu16];
    let outer_shapes = [None, Some(0x8100u16), Some(0x88a8u16)];

    for &outer in &outer_shapes {
        for &inner in &inner_families {
            let f = build_l2_frame(outer, inner, 64);
            let want = expected_l3_for_shape(outer);

            // L2-a learning parser.
            let (a_l3, a_ethertype) =
                parse_eth_offsets(&f).expect("parse_eth_offsets parses a valid L2 frame");
            assert_eq!(
                a_l3, want,
                "parse_eth_offsets l3 mismatch for outer={outer:?} inner={inner:#06x}"
            );
            assert_eq!(
                a_ethertype, inner,
                "parse_eth_offsets must return the inner ethertype for outer={outer:?}"
            );

            // L2-b forwarding parser.
            let b_l3 = frame_l3_offset(&f).expect("frame_l3_offset parses a valid L2 frame");
            assert_eq!(
                b_l3, want,
                "frame_l3_offset l3 mismatch for outer={outer:?} inner={inner:#06x}"
            );

            // L2-c CoS ECN parser (returns family + offset).
            let c = ethernet_l3(&f).expect("ethernet_l3 parses an IP L2 frame");
            let c_l3 = match c {
                EthernetL3::Ipv4(off) | EthernetL3::Ipv6(off) => off,
            };
            assert_eq!(
                c_l3, want,
                "ethernet_l3 l3 mismatch for outer={outer:?} inner={inner:#06x}"
            );
            // ethernet_l3 must also classify the family from the wire
            // bytes, not the sideband.
            match (inner, c) {
                (0x0800, EthernetL3::Ipv4(_)) | (0x86DD, EthernetL3::Ipv6(_)) => {}
                other => panic!("ethernet_l3 family mismatch: {other:?}"),
            }

            // All three reachable parsers must agree with each other and
            // with the documented contract.
            assert_eq!(a_l3, b_l3, "parse_eth_offsets vs frame_l3_offset disagree");
            assert_eq!(b_l3, c_l3, "frame_l3_offset vs ethernet_l3 disagree");
        }
    }
}

#[test]
fn classify_arp_reply_8021ad_tagged() {
    // A single 0x88a8 (802.1ad) tagged ARP reply must be classified as a
    // Reply, not NotArp. Pre-#2150 parse_eth_offsets returned l3=14 with
    // ethertype 0x88a8, so classify_arp saw a non-ARP ethertype.
    let mut f = build_eth_arp_reply(true);
    // Rewrite the outer TPID from 0x8100 to 0x88a8.
    f[12] = 0x88;
    f[13] = 0xa8;
    match classify_arp(&f) {
        ArpClassification::Reply(r) => {
            assert_eq!(r.sender_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
            assert_eq!(r.sender_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)));
        }
        other => panic!("expected Reply for 0x88a8-tagged ARP, got {:?}", other),
    }
}

/// Build an NDP NA frame with an arbitrary IPv6 extension-header chain
/// between the base IPv6 header and the ICMPv6 NA. Each `(next_header,
/// payload_len_units)` entry emits one ext header whose `next_header`
/// byte points at the following header (or 58 for the final, pointing at
/// ICMPv6).
fn build_ndp_na_with_ext_chain(ext_chain: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst mac
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // src mac
    f.extend_from_slice(&0x86ddu16.to_be_bytes()); // IPv6 ethertype

    // Build the ext-header block first so we know payload_len.
    let mut ext_block = Vec::new();
    for (i, &ext_type) in ext_chain.iter().enumerate() {
        // Each ext header is the minimal 8 bytes: next_header, hdr_ext_len=0,
        // then 6 bytes of padding/options.
        let next = if i + 1 < ext_chain.len() {
            ext_chain[i + 1]
        } else {
            NEXT_HEADER_ICMPV6
        };
        ext_block.push(next); // next header
        ext_block.push(0); // hdr ext len = 0 → header is 8 bytes
        ext_block.extend_from_slice(&[0u8; 6]); // pad to 8 bytes
        let _ = ext_type; // ext_type is informational; layout is uniform
    }

    // ICMPv6 NA: type, code, csum, flags(4), target(16), TLLA option(8) = 32.
    let mut na = Vec::new();
    na.push(ICMPV6_TYPE_NA);
    na.push(0); // code
    na.extend_from_slice(&[0xff, 0xff]); // checksum
    na.extend_from_slice(&[0u8; 4]); // flags
    na.extend_from_slice(&[
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x42,
    ]); // target
    na.push(NDP_OPT_TARGET_LL);
    na.push(1); // len ×8 = 8
    na.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // MAC

    let payload_len = (ext_block.len() + na.len()) as u16;

    // base IPv6 header
    f.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // ver+tc+flow
    f.extend_from_slice(&payload_len.to_be_bytes());
    // next-header = first ext header type, or ICMPv6 if no ext headers
    f.push(*ext_chain.first().unwrap_or(&NEXT_HEADER_ICMPV6));
    f.push(255); // hop limit
    f.extend_from_slice(&[
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x01,
    ]); // src
    f.extend_from_slice(&[0xff; 16]); // dst

    f.extend_from_slice(&ext_block);
    f.extend_from_slice(&na);
    f
}

#[test]
fn parse_ndp_na_behind_hop_by_hop() {
    // NDP NA behind a single hop-by-hop (next_header 0) extension header.
    // Pre-#2150 this returned None (fixed l3+40 read the HBH bytes, not
    // ICMPv6). The fix walks the chain and finds the NA at l3+48.
    let f = build_ndp_na_with_ext_chain(&[0]); // 0 = hop-by-hop
    let r = parse_ndp_neighbor_advert(&f).expect("NA behind HBH must parse");
    assert_eq!(
        r.target_ip,
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xabcd, 0xef01, 0, 0x42)),
    );
    assert_eq!(r.target_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
}

#[test]
fn parse_ndp_na_behind_dest_options() {
    // Destination-options (60) ext header.
    let f = build_ndp_na_with_ext_chain(&[60]);
    let r = parse_ndp_neighbor_advert(&f).expect("NA behind dest-opts must parse");
    assert_eq!(r.target_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
}

#[test]
fn ipv6_walk_canary_learning_agrees_with_forwarding() {
    // For every ext-header chain, the learning NDP walk must land on the
    // same L4 offset as the shared #2148 forwarding walker.
    let chains: &[&[u8]] = &[
        &[],       // no ext headers
        &[0],      // hop-by-hop
        &[60],     // dest-options
        &[0, 60],  // HBH + dest-opts
        &[43],     // routing
        &[0, 60, 43], // 3-deep, within the 6-iteration bound
    ];
    for chain in chains {
        let f = build_ndp_na_with_ext_chain(chain);
        let (l3, _) = parse_eth_offsets(&f).expect("L2 parses");
        // Forwarding walker authority (L3-relative).
        let l3_slice = &f[l3..];
        let (rel_l4, proto) = crate::afxdp::frame::packet_rel_l4_offset_and_protocol(
            l3_slice,
            libc::AF_INET6 as u8,
        )
        .expect("forwarding walker finds L4");
        assert_eq!(proto, NEXT_HEADER_ICMPV6, "terminal proto must be ICMPv6");
        // The learning parser must accept the same frame (proving it walks
        // to the same ICMPv6 the forwarding path found).
        let r = parse_ndp_neighbor_advert(&f)
            .unwrap_or_else(|| panic!("learning parser missed NA for chain {chain:?}"));
        assert_eq!(r.target_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        // Sanity: the forwarding L4 offset points at the ICMPv6 type byte.
        assert_eq!(f[l3 + rel_l4], ICMPV6_TYPE_NA);
    }
}

#[test]
fn parse_ndp_na_truncated_ext_chain_no_panic() {
    // An NA whose ext chain is truncated before the ICMPv6 header must
    // return None, never panic / read OOB.
    let mut f = build_ndp_na_with_ext_chain(&[0]);
    // Truncate inside the ICMPv6 NA body (keep base + HBH + a few bytes).
    f.truncate(14 + 40 + 8 + 4);
    assert!(parse_ndp_neighbor_advert(&f).is_none());
}
