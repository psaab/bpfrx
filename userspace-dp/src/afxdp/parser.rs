//! #947: pure parsers for ARP and IPv6 NDP packets, extracted from
//! `poll_binding_process_descriptor` to make them testable in
//! isolation and to declutter the main poll loop.
//!
//! These functions intentionally do NOT use trait objects (`dyn
//! ProtocolParser`) — they are `#[inline]`-able free functions so the
//! compiler can fold them into the caller. The original issue
//! proposed a Strategy trait pattern, but trait-object dispatch on a
//! per-packet path would regress IPC; generics with monomorphization
//! (or, as here, simple `#[inline]` functions) are the correct shape.
//!
//! IPv4/IPv6/TCP/GRE parsing already lives in `frame.rs` and
//! `gre.rs`; this module covers the two control-plane shapes (ARP
//! reply and IPv6 neighbor advertisement) that were still inline in
//! `afxdp.rs`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::ethernet::{ETH_HDR_LEN, ETHERTYPE_ARP, ETHERTYPE_IPV6, ETHERTYPE_VLAN, VLAN_TAG_LEN};

const ARP_BODY_LEN: usize = 28;
const IPV6_HDR_LEN: usize = 40;
const ICMPV6_NA_HDR_LEN: usize = 24;
const NEXT_HEADER_ICMPV6: u8 = 58;
const ICMPV6_TYPE_NA: u8 = 136;
const ARP_OP_REPLY: u16 = 2;
const NDP_OPT_TARGET_LL: u8 = 2;

/// Resolve the L3-header offset and the EtherType. Handles both
/// untagged and 802.1Q VLAN-tagged frames.
///
/// Returns `(l3_start, ethertype)` if the frame is large enough to
/// contain the L2 header, otherwise `None`.
#[inline(always)]
pub(super) fn parse_eth_offsets(raw_frame: &[u8]) -> Option<(usize, u16)> {
    if raw_frame.len() < ETH_HDR_LEN {
        return None;
    }
    let outer_ethertype = u16::from_be_bytes([raw_frame[12], raw_frame[13]]);
    if outer_ethertype == ETHERTYPE_VLAN {
        if raw_frame.len() < ETH_HDR_LEN + VLAN_TAG_LEN {
            return None;
        }
        let inner = u16::from_be_bytes([raw_frame[16], raw_frame[17]]);
        Some((ETH_HDR_LEN + VLAN_TAG_LEN, inner))
    } else {
        Some((ETH_HDR_LEN, outer_ethertype))
    }
}

/// Parsed ARP reply (sender MAC + sender IP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ArpReply {
    pub sender_mac: [u8; 6],
    pub sender_ip: IpAddr,
}

/// Classification of an Ethernet frame as ARP-or-not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ArpClassification {
    /// Frame is not ARP (or is too short to classify).
    NotArp,
    /// Frame is ARP but not a reply (e.g. request, RARP, gratuitous
    /// announcement). Caller should recycle the frame — ARP does not
    /// transit the firewall — but skip neighbor learning.
    OtherArp,
    /// Frame is an ARP reply with a parsed `(sender_mac, sender_ip)`.
    Reply(ArpReply),
}

/// Classify an Ethernet frame as ARP / non-ARP / ARP reply. Handles
/// untagged and VLAN-tagged frames.
///
/// Replaces the inline parser at `afxdp.rs:893-947` (pre-#947). The
/// caller's contract was: if it's any kind of ARP, recycle the frame
/// (ARP does not transit); if it's specifically an ARP reply, also
/// learn the neighbor entry. The enum captures both branches without
/// re-parsing.
#[inline(always)]
pub(super) fn classify_arp(raw_frame: &[u8]) -> ArpClassification {
    let Some((l3_start, ethertype)) = parse_eth_offsets(raw_frame) else {
        return ArpClassification::NotArp;
    };
    if ethertype != ETHERTYPE_ARP {
        return ArpClassification::NotArp;
    }
    if raw_frame.len() < l3_start + ARP_BODY_LEN {
        return ArpClassification::NotArp;
    }
    let opcode = u16::from_be_bytes([raw_frame[l3_start + 6], raw_frame[l3_start + 7]]);
    if opcode != ARP_OP_REPLY {
        return ArpClassification::OtherArp;
    }
    let sender_mac = [
        raw_frame[l3_start + 8],
        raw_frame[l3_start + 9],
        raw_frame[l3_start + 10],
        raw_frame[l3_start + 11],
        raw_frame[l3_start + 12],
        raw_frame[l3_start + 13],
    ];
    let sender_ip = IpAddr::V4(Ipv4Addr::new(
        raw_frame[l3_start + 14],
        raw_frame[l3_start + 15],
        raw_frame[l3_start + 16],
        raw_frame[l3_start + 17],
    ));
    ArpClassification::Reply(ArpReply {
        sender_mac,
        sender_ip,
    })
}

/// Parsed ICMPv6 Neighbor Advertisement (type 136).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NdpNeighborAdvert {
    pub target_ip: IpAddr,
    /// Some(mac) iff the NA carries a Target Link-Layer Address option
    /// (option type 2). NA without TLLA is valid (e.g. unsolicited NA
    /// from a host whose router knows the LLA already), but we can't
    /// learn a MAC from those.
    pub target_mac: Option<[u8; 6]>,
}

/// Parse an IPv6 Neighbor Advertisement. Returns `None` if the frame
/// is not an NA or is too short. Handles VLAN-tagged frames.
///
/// Replaces the inline parser at `afxdp.rs:948-1014` (pre-#947).
#[inline(always)]
pub(super) fn parse_ndp_neighbor_advert(raw_frame: &[u8]) -> Option<NdpNeighborAdvert> {
    let (l3_start, ethertype) = parse_eth_offsets(raw_frame)?;
    if ethertype != ETHERTYPE_IPV6 {
        return None;
    }
    if raw_frame.len() < l3_start + IPV6_HDR_LEN {
        return None;
    }
    let next_header = raw_frame[l3_start + 6];
    let l4_start = l3_start + IPV6_HDR_LEN;
    if next_header != NEXT_HEADER_ICMPV6
        || raw_frame.len() < l4_start + ICMPV6_NA_HDR_LEN
        || raw_frame[l4_start] != ICMPV6_TYPE_NA
    {
        return None;
    }
    let target_bytes: [u8; 16] =
        <[u8; 16]>::try_from(&raw_frame[l4_start + 8..l4_start + 24]).ok()?;
    let target_ip = IpAddr::V6(Ipv6Addr::from(target_bytes));
    // Walk the NDP options for a Target Link-Layer Address (type 2).
    let mut target_mac: Option<[u8; 6]> = None;
    let mut opt_off = l4_start + ICMPV6_NA_HDR_LEN;
    while opt_off + 2 <= raw_frame.len() {
        let opt_type = raw_frame[opt_off];
        let opt_len = raw_frame[opt_off + 1] as usize * 8;
        if opt_len == 0 {
            break;
        }
        if opt_type == NDP_OPT_TARGET_LL && opt_len >= 8 && opt_off + 8 <= raw_frame.len() {
            target_mac = Some([
                raw_frame[opt_off + 2],
                raw_frame[opt_off + 3],
                raw_frame[opt_off + 4],
                raw_frame[opt_off + 5],
                raw_frame[opt_off + 6],
                raw_frame[opt_off + 7],
            ]);
            break;
        }
        opt_off += opt_len;
    }
    Some(NdpNeighborAdvert {
        target_ip,
        target_mac,
    })
}

#[cfg(test)]
mod tests {
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
}
