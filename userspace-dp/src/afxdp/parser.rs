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

use super::ethernet::{
    ETH_HDR_LEN, ETHERTYPE_ARP, ETHERTYPE_IPV6, ETHERTYPE_VLAN, ETHERTYPE_VLAN_8021AD, VLAN_TAG_LEN,
};

const ARP_BODY_LEN: usize = 28;
const IPV6_HDR_LEN: usize = 40;
const ICMPV6_NA_HDR_LEN: usize = 24;
const NEXT_HEADER_ICMPV6: u8 = 58;
const ICMPV6_TYPE_NA: u8 = 136;
const ARP_OP_REPLY: u16 = 2;
const NDP_OPT_TARGET_LL: u8 = 2;

/// Resolve the L3-header offset and the EtherType. Handles untagged
/// and single-tagged frames carrying either an 802.1Q (0x8100) or an
/// 802.1ad (0x88a8) VLAN tag.
///
/// Returns `(l3_start, ethertype)` if the frame is large enough to
/// contain the L2 header, otherwise `None`.
///
/// #2150: 0x88a8 was previously treated as the inner ethertype (l3=14),
/// which made a single-0x88a8-tagged ARP/NDP frame parse as a non-IP /
/// non-ARP frame and silently skip neighbor learning. Both forwarding
/// L2 parsers (`frame/inspect.rs::frame_l3_offset`,
/// `cos/ecn.rs::ethernet_l3`) already treat 0x88a8 as a single tag with
/// l3 at 18; this learning parser must agree. A QinQ DOUBLE tag (a tag
/// whose inner ethertype is itself a VLAN TPID) is NOT unwound here —
/// the upstream XDP shim drops double-tagged frames before they reach
/// userspace, so the canonical contract is "single tag → l3=18; the
/// inner (possibly still-VLAN) ethertype is returned as-is". The
/// canary in parser_tests.rs pins this agreement across all L2 parsers.
#[inline(always)]
pub(super) fn parse_eth_offsets(raw_frame: &[u8]) -> Option<(usize, u16)> {
    if raw_frame.len() < ETH_HDR_LEN {
        return None;
    }
    let outer_ethertype = u16::from_be_bytes([raw_frame[12], raw_frame[13]]);
    if matches!(outer_ethertype, ETHERTYPE_VLAN | ETHERTYPE_VLAN_8021AD) {
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
///
/// #2150: previously this assumed ICMPv6 sat at a fixed `l3 + 40` and
/// read the base `next_header` (`raw[l3 + 6]`) directly, so an NA that
/// arrived behind an IPv6 extension header (hop-by-hop, dest-options,
/// routing, fragment) was missed — the exact asymmetry the
/// forwarding/screen walkers (#2148/#2189) were written to avoid. It now
/// reuses the shared #2148 walker `packet_rel_l4_offset_and_protocol`
/// over the L3-relative slice to locate the real L4 offset and confirm
/// the terminal protocol is ICMPv6 (58). The walker keeps its existing
/// 6-iteration bound, so behavior is byte-identical for the no-ext-header
/// case (offset == l3 + 40, protocol == 58). The parser-agreement canary
/// in parser_tests.rs pins this against the forwarding walker.
#[inline(always)]
pub(super) fn parse_ndp_neighbor_advert(raw_frame: &[u8]) -> Option<NdpNeighborAdvert> {
    let (l3_start, ethertype) = parse_eth_offsets(raw_frame)?;
    if ethertype != ETHERTYPE_IPV6 {
        return None;
    }
    if raw_frame.len() < l3_start + IPV6_HDR_LEN {
        return None;
    }
    // Walk the IPv6 extension-header chain (shared #2148 engine) to find
    // the real L4 offset + terminal protocol. The walker operates on the
    // L3-relative slice; translate its relative offset back to a
    // frame-absolute offset.
    let l3_slice = raw_frame.get(l3_start..)?;
    let (rel_l4, protocol) =
        super::frame::packet_rel_l4_offset_and_protocol(l3_slice, libc::AF_INET6 as u8)?;
    let l4_start = l3_start.checked_add(rel_l4)?;
    if protocol != NEXT_HEADER_ICMPV6
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
#[path = "parser_tests.rs"]
mod tests;

