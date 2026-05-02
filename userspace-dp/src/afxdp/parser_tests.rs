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
