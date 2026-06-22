//! WireGuard transit-egress encap for the AF_XDP copy path (#1432 S2a).
//!
//! This is the SECOND of the two S2a egress encap sites; the primary is
//! the WG control thread's TUN-read loop (coordinator/wg_control.rs).
//! This site fires only when an AF_XDP forwarding decision targets a
//! `mode == "wireguard"` tunnel endpoint id directly (a route/connected
//! entry carrying the WG endpoint id). In the canonical wgN-TUN topology
//! the kernel routes inner traffic to the wgN device and the control
//! thread owns egress, so this path is rarely hit; it exists so a
//! forwarding decision that does target the WG endpoint produces a valid
//! frame (and is correctly MTU-gated) rather than falling through to the
//! GRE builder.
//!
//! The non-WG fast path NEVER reaches here: `build_forwarded_frame_*`
//! only calls into the tunnel-encap branch when
//! `tunnel_endpoint_id != 0`, and a plain forward short-circuits long
//! before (tx/dispatch/mod.rs). The mode `match` in frame/mod.rs reads a
//! `&str` already loaded for the GRE lookup — no new branch on the
//! plain-forward path.

use super::super::wg::{EncapError, POLY1305_TAG_LEN, WG_DATA_HEADER_LEN};
use super::super::*;
use super::headers::{write_eth_header_slice, write_ipv4_header, write_ipv6_header, write_udp_header};
use std::net::IpAddr;

/// Round `n` up to the nearest multiple of 16 (WG §5.4.6 pad).
#[inline]
const fn pad_to_16(n: usize) -> usize {
    (n + 15) & !15
}

/// The exact pad-aware encapped wire size for an `inner_len`-byte inner
/// packet plus the outer L3/L4 (IP + UDP). Used by the MTU guard so a
/// frame that would exceed the egress MTU is dropped rather than forcing
/// outer IP fragmentation (plan §7, Codex r3). Pulled out of
/// `wg_encap_frame` so the arithmetic is unit-testable in isolation.
#[inline]
fn wg_encapped_size(inner_len: usize, outer_v6: bool) -> usize {
    let outer_ip_len = if outer_v6 { 40 } else { 20 };
    let wg_record_len = WG_DATA_HEADER_LEN + pad_to_16(inner_len) + POLY1305_TAG_LEN;
    wg_record_len + outer_ip_len + 8
}

pub(super) fn wg_encap_frame(
    inner_frame: &[u8],
    inner_meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    let inner_meta = inner_meta.into();
    let id = decision.resolution.tunnel_endpoint_id;
    let endpoint = forwarding.tunnel_endpoints.get(&id)?;
    // #1873 (Codex code r2): refuse to encapsulate when the id's
    // owning netdev differs from the one recorded in the session's
    // stored resolution (egress_ifindex = logical_ifindex at resolve
    // time) — a re-owned id must fail the build (R-C gate drops the
    // frame), never encapsulate into the new owner.
    if decision.resolution.egress_ifindex > 0
        && endpoint.logical_ifindex != decision.resolution.egress_ifindex
    {
        return None;
    }
    let engine = forwarding.wg_engines.get(&id)?;
    let dst_mac = decision.resolution.neighbor_mac?;
    let src_mac = decision.resolution.src_mac?;
    let vlan_id = decision.resolution.tx_vlan_id;
    let outer_eth_len = if vlan_id > 0 { 18 } else { 14 };

    // Extract the inner IP packet (strip L2).
    let inner_l3 = match frame_l3_offset(inner_frame) {
        Some(offset) => offset,
        None => inner_meta.l3_offset as usize,
    };
    let inner_packet = inner_frame.get(inner_l3..)?;
    let inner_len = crate::afxdp::gre::packet_trimmed_len(inner_packet, inner_meta.addr_family)?;
    let inner_packet = &inner_packet[..inner_len];

    // #1434 B1b cryptokey routing: select the egress peer by the inner
    // destination's longest-prefix match in the AllowedIPs trie (NOT a
    // single scalar peer). A packet with no covering peer is dropped —
    // there is no peer to encrypt it to.
    let inner_dst = crate::afxdp::gre::inner_dst_ip(inner_packet, inner_meta.addr_family)?;
    let (peer_pubkey, peer_endpoint) = engine.peer_for_dest(inner_dst)?;
    // A responder-only peer with no learned endpoint cannot be an encap
    // TARGET on this transit path (the control thread learns the
    // endpoint from inbound traffic; this AF_XDP transit site has no
    // such state). Drop rather than encap to a phantom destination.
    let peer_endpoint = peer_endpoint?;
    // #2303: copy the inner DSCP+ECN onto the outer header (uniform
    // DSCP model + RFC 6040 ECN ingress copy) instead of hardcoding 0.
    let outer_tos = crate::afxdp::gre::inner_tos_byte(inner_packet, inner_meta.addr_family);

    // Outer family follows the peer endpoint address.
    let outer_v6 = peer_endpoint.is_ipv6();
    let outer_ip_len = if outer_v6 { 40 } else { 20 };

    // Exact pad-aware MTU guard (plan §7, Codex r3). The WG record is
    // WG_DATA_HEADER_LEN + pad_to_16(inner) + POLY1305_TAG_LEN; the full
    // outer frame adds eth + outer IP + UDP(8). Drop oversize rather than
    // letting the kernel fragment the outer datagram. The egress MTU is
    // the egress interface MTU (default 1500 if unknown).
    let outer_mtu = forwarding
        .egress
        .get(&decision.resolution.egress_ifindex)
        .map(|e| e.mtu)
        .filter(|m| *m > 0)
        .unwrap_or(1500);
    let wg_record_len = WG_DATA_HEADER_LEN + pad_to_16(inner_packet.len()) + POLY1305_TAG_LEN;
    if wg_encapped_size(inner_packet.len(), outer_v6) > outer_mtu {
        // #1865: the promised "follow-up" counter store — same
        // `encap_mtu_drops` counter as the control thread's symmetric
        // guard (the plan's both-guards requirement).
        //
        // #2330: when a PTB is OWED (inner IPv4 DF or IPv6), the TX
        // dispatcher's pre-build `post_transform_inner_mtu` decision fires
        // BEFORE this builder is called (advertising the WG inner MTU =
        // `wg::mss::wg_inner_mtu`, the inverse of `wg_encapped_size`),
        // `mtu_signalled` skips the encap build, and this site is never
        // reached for that case — so the PTB and this drop counter never
        // both fire. This guard remains the backstop for a non-DF IPv4
        // inner (kept `Forward` to preserve fragmentable behaviour) whose
        // encapped outer still exceeds the MTU.
        crate::afxdp::wg::counters::WgCounters::bump(&engine.counters().encap_mtu_drops);
        return None;
    }

    // Encap the inner packet into a stack/heap scratch via the engine.
    // No per-packet alloc on the steady path would require a worker
    // RefCell scratch; this rarely-hit transit site uses a local buffer
    // sized once to the record length.
    let mut wg_record = vec![0u8; wg_record_len];
    let outcome = match engine.try_encap(&peer_pubkey, inner_packet, &mut wg_record) {
        Ok(o) => o,
        Err(EncapError::NoSession) => {
            // Request a handshake (rate-limited relaxed atomic) and drop.
            engine.request_handshake(monotonic_nanos());
            return None;
        }
        Err(_) => return None,
    };
    let wg_record = &wg_record[..outcome.len];

    let udp_len = 8 + wg_record.len();
    let frame_len = outer_eth_len + outer_ip_len + udp_len;
    let mut out = vec![0u8; frame_len];

    write_eth_header_slice(
        out.get_mut(..outer_eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        if outer_v6 { 0x86dd } else { 0x0800 },
    )?;

    let outer_ip_start = outer_eth_len;
    let udp_start = outer_ip_start + outer_ip_len;
    let payload_start = udp_start + 8;
    out.get_mut(payload_start..)?
        .get_mut(..wg_record.len())?
        .copy_from_slice(wg_record);

    // Source IP/port: the firewall egress primary address + WG listen
    // port; destination: the peer endpoint.
    let egress = forwarding.egress.get(&decision.resolution.egress_ifindex);
    let src_port = endpoint.wg_listen_port;
    let dst_port = peer_endpoint.port();

    match (outer_v6, peer_endpoint.ip()) {
        (false, IpAddr::V4(dst)) => {
            let src = egress.and_then(|e| e.primary_v4)?;
            let total_len = u16::try_from(outer_ip_len + udp_len).ok()?;
            write_ipv4_header(
                out.get_mut(outer_ip_start..outer_ip_start + 20)?,
                src,
                dst,
                PROTO_UDP,
                outer_tos,
                endpoint.ttl,
                total_len,
            )?;
            // UDP checksum is optional over IPv4; leave 0 (disabled).
            write_udp_header(
                out.get_mut(udp_start..udp_start + 8)?,
                src_port,
                dst_port,
                u16::try_from(udp_len).ok()?,
                0,
            )?;
        }
        (true, IpAddr::V6(dst)) => {
            let src = egress.and_then(|e| e.primary_v6)?;
            let payload_len = u16::try_from(udp_len).ok()?;
            write_ipv6_header(
                out.get_mut(outer_ip_start..outer_ip_start + 40)?,
                src,
                dst,
                PROTO_UDP,
                outer_tos,
                /* flow_label */ 0,
                endpoint.ttl,
                payload_len,
            )?;
            // IPv6 mandates a non-zero UDP checksum. Compute over the
            // pseudo-header + UDP header + payload.
            write_udp_header(
                out.get_mut(udp_start..udp_start + 8)?,
                src_port,
                dst_port,
                payload_len,
                0,
            )?;
            let csum = udp6_checksum(src, dst, &out[udp_start..udp_start + udp_len]);
            out[udp_start + 6..udp_start + 8].copy_from_slice(&csum.to_be_bytes());
        }
        _ => return None,
    }

    Some(out)
}

/// RFC 768 / RFC 8200 IPv6 UDP checksum over the pseudo-header + UDP
/// datagram. `udp` is the full UDP header+payload (checksum field 0).
fn udp6_checksum(src: std::net::Ipv6Addr, dst: std::net::Ipv6Addr, udp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let len = udp.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    sum += PROTO_UDP as u32; // next-header
    let mut i = 0;
    while i + 1 < udp.len() {
        sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
        i += 2;
    }
    if i < udp.len() {
        sum += (udp[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    if csum == 0 { 0xffff } else { csum }
}

#[cfg(test)]
mod wg_frame_tests {
    use super::*;

    #[test]
    fn pad_to_16_rounds_up() {
        assert_eq!(pad_to_16(0), 0);
        assert_eq!(pad_to_16(1), 16);
        assert_eq!(pad_to_16(16), 16);
        assert_eq!(pad_to_16(17), 32);
    }

    #[test]
    fn wg_encapped_size_is_pad_aware() {
        // inner 1 byte: pads to 16; record = 16 (hdr) + 16 (pad) + 16
        // (tag) = 48; + outer v4 IP(20) + UDP(8) = 76.
        assert_eq!(wg_encapped_size(1, false), 16 + 16 + 16 + 20 + 8);
        // v6 adds 20 more for the bigger outer IP header.
        assert_eq!(
            wg_encapped_size(1, true),
            wg_encapped_size(1, false) + 20
        );
        // An inner already a 16-multiple does not over-pad.
        assert_eq!(
            wg_encapped_size(32, false),
            WG_DATA_HEADER_LEN + 32 + POLY1305_TAG_LEN + 20 + 8
        );
    }

    #[test]
    fn wg_mtu_guard_drops_oversize_inner() {
        // At a 1500-byte v4 outer MTU the largest inner that fits is
        // 1500 - 20 - 8 - 16 - 16 = 1440, padded to a 16-multiple. A
        // 1441-byte inner pads to 1456 and overflows.
        let mtu = 1500usize;
        assert!(
            wg_encapped_size(1440, false) <= mtu,
            "1440-byte inner must fit a 1500 v4 outer MTU"
        );
        assert!(
            wg_encapped_size(1441, false) > mtu,
            "1441-byte inner (pads to 1456) must overflow and be dropped"
        );
    }
}
