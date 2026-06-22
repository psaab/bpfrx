// #2301: locally-generated Path-MTU-Discovery ICMP errors for the generic
// forwarder.
//
// The TX dispatcher only had a TCP-specific segmentation decision
// (`forwarded_tcp_may_need_segmentation`). Every other oversized forwarded
// L3 packet — UDP, ICMP, ESP, GRE, a TCP segmentation MISS, a tunnelled
// inner that grew past the egress MTU — was enqueued for TX into an MTU
// violation and silently dropped by the NIC / switch / peer, with no MTU
// signal to the sender. PMTUD therefore never converged on a mixed-MTU /
// tunnel-underlay path (PPPoE 1492, cloud ~1450, VLAN stacks). For a
// routing/security appliance that is a forwarding-correctness gap, not a
// perf nicety.
//
// This module adds the egress-MTU decision and the matching ICMP error
// generators:
//   - ICMPv4 Destination Unreachable, type 3 code 4 (Fragmentation Needed
//     and DF Set) carrying the next-hop MTU in the low 16 bits of the
//     "unused" word (RFC 1191).
//   - ICMPv6 Packet Too Big, type 2 code 0, carrying the MTU in the 32-bit
//     field that replaces the "unused" word (RFC 4443 §3.2).
//
// The builders deliberately mirror `icmp::build_local_icmp_error_v4/v6`
// (L2 reflect + ingress-sourced outer IP + quoted inbound packet) rather
// than calling them, because those two functions hardcode the post-checksum
// word to zero and have no MTU parameter. icmp.rs is being edited in
// parallel (#2237/#2242), so keeping the PTB builders in their own module
// keeps the diff additive and conflict-free; the shared header/checksum
// helpers (`write_eth_header_tagged`, `write_ipv4_header`,
// `write_ipv6_header`, `checksum16`, `checksum16_ipv6`, `TxVlanTag`) and the
// RFC suppression gate (`icmp::reject_icmp_reply_suppressed`,
// `is_non_first_fragment`) are reused verbatim.

use super::*;

use super::icmp::reject_icmp_reply_suppressed;

/// Outcome of the per-forward egress-MTU decision. The fast path (the
/// forwarded L3 size fits the egress MTU) is `Forward` and adds a single
/// `usize` comparison to the dispatcher; everything else is a cold arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum EgressMtuDecision {
    /// The frame fits the egress MTU (or no egress MTU is known) — forward
    /// it unchanged. Also the answer when the original packet does NOT have
    /// DF set (IPv4) so the downstream may still fragment, preserving the
    /// pre-#2301 forward-and-let-the-path-fragment behaviour.
    Forward,
    /// The frame exceeds the egress MTU and the sender asked us not to
    /// fragment (IPv4 DF=1) or cannot be fragmented in transit (IPv6) —
    /// generate an ICMP Frag-Needed / Packet-Too-Big advertising
    /// `next_hop_mtu` and drop the original.
    EmitPacketTooBig { next_hop_mtu: u16 },
}

/// Compute the egress-MTU decision for a forwarded L3 frame that the TCP
/// segmentation path did NOT handle.
///
/// `forwarded_len` is the on-the-wire length of the frame as it will leave
/// the egress interface (post-NAT / post-header-rewrite). `l3_offset` is
/// where the L3 header starts in that frame. The decision compares the L3
/// payload (`forwarded_len - l3_offset`) against the resolved egress MTU.
///
/// Returns `Forward` whenever:
///   - no egress MTU is known for the resolution (fail-open: never invent
///     an MTU smaller than the link),
///   - the L3 payload fits the MTU,
///   - the packet is IPv4 without the DF bit (the downstream is allowed to
///     fragment — keep the pre-#2301 behaviour rather than PTB-storm a
///     fragmentable flow), or
///   - the frame is otherwise unparseable for the MTU check.
#[inline]
pub(in crate::afxdp) fn forwarded_egress_mtu_decision(
    frame: &[u8],
    l3_offset: usize,
    addr_family: u8,
    mtu: usize,
) -> EgressMtuDecision {
    if mtu == 0 || l3_offset >= frame.len() {
        return EgressMtuDecision::Forward;
    }
    let l3_len = frame.len().saturating_sub(l3_offset);
    if l3_len <= mtu {
        return EgressMtuDecision::Forward;
    }
    // The next-hop MTU we advertise. Floor at the protocol minimum so a
    // misconfigured tiny MTU never tells the sender to use an illegal MSS.
    let floor = match addr_family as i32 {
        libc::AF_INET6 => 1280usize,
        _ => 68usize, // RFC 791 minimum IPv4 reassembly buffer / link MTU floor
    };
    let next_hop_mtu = mtu.max(floor).min(u16::MAX as usize) as u16;
    match addr_family as i32 {
        libc::AF_INET => {
            // Only signal PTB when the sender forbade fragmentation
            // (DF=1). A non-DF oversized datagram is the downstream's to
            // fragment; PTB-storming it would regress the prior behaviour.
            if ipv4_df_set(&frame[l3_offset..]) {
                EgressMtuDecision::EmitPacketTooBig { next_hop_mtu }
            } else {
                EgressMtuDecision::Forward
            }
        }
        // IPv6 routers never fragment in transit (RFC 8200 §4.5) — always
        // signal Packet-Too-Big.
        libc::AF_INET6 => EgressMtuDecision::EmitPacketTooBig { next_hop_mtu },
        _ => EgressMtuDecision::Forward,
    }
}

/// Read the IPv4 Don't-Fragment bit from an L3 (IP-header-first) slice.
#[inline]
fn ipv4_df_set(packet: &[u8]) -> bool {
    // Bytes 6..8 are flags+fragment-offset; DF is bit 14 (0x4000).
    packet
        .get(6)
        .map(|&b| (b & 0x40) != 0)
        .unwrap_or(false)
}

/// RFC error-suppression gate shared by the PTB path. Mirrors the reject
/// path: never reply to a non-first fragment (no transport header to quote
/// / key), to a trigger frame whose link-layer (L2) destination was
/// group/broadcast (RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e), #2325 — a
/// datagram delivered as an L2 broadcast/multicast must not generate an
/// error), to a trigger packet whose IP (L3) destination was
/// multicast/broadcast (#2314 — a multicast flood must not be amplified
/// into an ICMP-error backscatter storm), or to an inbound ICMP/ICMPv6
/// *error* message (avoid error loops and amplification). Returns true
/// when a PTB MUST be suppressed.
#[inline]
pub(in crate::afxdp) fn ptb_reply_suppressed(
    frame: &[u8],
    meta: UserspaceDpMeta,
    l3_offset: usize,
) -> bool {
    // #2325: never generate a PTB in reply to a datagram delivered as an
    // L2 broadcast/multicast frame. This gives the PTB path the same L2
    // suppression that the reject / Time-Exceeded path
    // (`can_generate_icmp_error_reply`) has. `frame` is the full trigger
    // ethernet frame (the same slice the PTB builders read the reflected
    // destination MAC from), so the L2 dst is the first 6 bytes.
    if let Some(eth_dst) = frame.get(0..6)
        && let Ok(eth_dst) = <&[u8; 6]>::try_from(eth_dst)
        && l2_dst_is_group_or_broadcast(eth_dst)
    {
        return true;
    }
    let Some(packet) = frame.get(l3_offset..) else {
        return true;
    };
    if is_non_first_fragment(packet, meta.addr_family) {
        return true;
    }
    // #2314: never generate a PTB in reply to a datagram whose IP
    // destination was multicast or broadcast.
    if dest_is_multicast_or_broadcast(meta.addr_family, packet) {
        return true;
    }
    if matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        let Some(&icmp_type) = frame.get(meta.l4_offset as usize) else {
            return true;
        };
        if reject_icmp_reply_suppressed(meta.protocol, icmp_type) {
            return true;
        }
    }
    false
}

/// Build a local-origin ICMPv4 Destination Unreachable (type 3, code 4 —
/// Fragmentation Needed and DF Set), reflecting L2 back to the sender and
/// sourcing the outer IP from the ingress interface primary v4. The
/// next-hop MTU is written into the low 16 bits of the otherwise-unused
/// word per RFC 1191. Quotes the inbound IP header plus the first 8 L4
/// bytes (RFC 792).
pub(in crate::afxdp) fn build_frag_needed_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
    next_hop_mtu: u16,
) -> Option<Vec<u8>> {
    let egress = forwarding.egress.get(&ingress_ifindex)?;
    let (dst_mac, fallback_src_mac, ingress_tag) = ingress_reply_l2(frame)?;
    let src_ip = egress.primary_v4?;
    let src_mac = egress.src_mac;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    let packet = frame.get(l3..)?;
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let dst_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let packet_len = total_len.min(packet.len());
    let quoted_len = packet_len.min(ihl.saturating_add(8));
    let tag = if ingress_tag.emits() {
        ingress_tag
    } else {
        TxVlanTag::from(egress.vlan_id)
    };
    let eth_len = tag.header_len();
    let total_len = 20usize.checked_add(8)?.checked_add(quoted_len)?;
    let mut out = Vec::with_capacity(eth_len + total_len);
    write_eth_header_tagged(
        &mut out,
        dst_mac,
        if src_mac == [0; 6] {
            fallback_src_mac
        } else {
            src_mac
        },
        tag,
        0x0800,
    );
    let ip_start = out.len();
    out.resize(ip_start + 20, 0);
    write_ipv4_header(
        &mut out[ip_start..ip_start + 20],
        src_ip,
        dst_ip,
        PROTO_ICMP,
        /* tos */ 0,
        /* ttl */ 64,
        total_len as u16,
    )?;
    let icmp_start = out.len();
    // type=3 code=4; bytes 4..6 unused (0); bytes 6..8 = next-hop MTU.
    out.extend_from_slice(&[3, 4, 0, 0, 0, 0]);
    out.extend_from_slice(&next_hop_mtu.to_be_bytes());
    out.extend_from_slice(packet.get(..quoted_len)?);
    let icmp_sum = checksum16(&out[icmp_start..]);
    out[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(out)
}

/// Build a local-origin ICMPv6 Packet Too Big (type 2, code 0), reflecting
/// L2 back to the sender and sourcing the outer IP from the ingress
/// interface primary v6. The MTU is written into the 32-bit field that
/// follows the checksum (RFC 4443 §3.2). Quotes as much of the inbound
/// packet as fits under the IPv6 minimum MTU (1280) so the reply itself is
/// never oversized.
pub(in crate::afxdp) fn build_packet_too_big_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
    mtu: u32,
) -> Option<Vec<u8>> {
    let egress = forwarding.egress.get(&ingress_ifindex)?;
    let (dst_mac, fallback_src_mac, ingress_tag) = ingress_reply_l2(frame)?;
    let src_ip = egress.primary_v6?;
    let src_mac = egress.src_mac;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    let packet = frame.get(l3..)?;
    if packet.len() < 40 {
        return None;
    }
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let packet_len = (40 + payload_len).min(packet.len());
    // RFC 4443 §3.2: the error must not exceed the IPv6 minimum MTU. Cap
    // the quote so eth + 40 (outer IP) + 8 (ICMPv6 header) + quote <= 1280.
    let tag = if ingress_tag.emits() {
        ingress_tag
    } else {
        TxVlanTag::from(egress.vlan_id)
    };
    let eth_len = tag.header_len();
    let max_quote = 1280usize.saturating_sub(40 + 8);
    let quoted_len = packet_len.min(max_quote);
    let outer_payload_len = 8usize.checked_add(quoted_len)?;
    let mut out = Vec::with_capacity(eth_len + 40 + outer_payload_len);
    write_eth_header_tagged(
        &mut out,
        dst_mac,
        if src_mac == [0; 6] {
            fallback_src_mac
        } else {
            src_mac
        },
        tag,
        0x86dd,
    );
    let ip_start = out.len();
    out.resize(ip_start + 40, 0);
    write_ipv6_header(
        &mut out[ip_start..ip_start + 40],
        src_ip,
        dst_ip,
        PROTO_ICMPV6,
        /* traffic_class */ 0,
        /* flow_label */ 0,
        /* hop_limit */ 64,
        outer_payload_len as u16,
    )?;
    let icmp_start = out.len();
    // type=2 code=0; bytes 4..8 = MTU (replaces the "unused" word).
    out.extend_from_slice(&[2, 0, 0, 0]);
    out.extend_from_slice(&mtu.to_be_bytes());
    out.extend_from_slice(packet.get(..quoted_len)?);
    let icmp_sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &out[icmp_start..]);
    out[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(out)
}

/// Parse the inbound L2 header for a reflected local-origin reply: swapped
/// MACs plus the full ingress 802.1Q/802.1ad tag. Local copy of the
/// icmp.rs helper so this module does not depend on a `pub` widening of a
/// private icmp.rs function (icmp.rs is edited in parallel by #2237/#2242).
fn ingress_reply_l2(frame: &[u8]) -> Option<([u8; 6], [u8; 6], TxVlanTag)> {
    if frame.len() < 14 {
        return None;
    }
    let dst_mac = <[u8; 6]>::try_from(frame.get(0..6)?).ok()?;
    let src_mac = <[u8; 6]>::try_from(frame.get(6..12)?).ok()?;
    let eth_proto = u16::from_be_bytes([frame[12], frame[13]]);
    let ingress_tag = if matches!(eth_proto, TPID_8021Q | TPID_8021AD) {
        let tci = u16::from_be_bytes([*frame.get(14)?, *frame.get(15)?]);
        TxVlanTag {
            tpid: eth_proto,
            tci,
            present: true,
        }
    } else {
        TxVlanTag::NONE
    };
    Some((src_mac, dst_mac, ingress_tag))
}

#[cfg(test)]
#[path = "icmp_ptb_tests.rs"]
mod tests;
