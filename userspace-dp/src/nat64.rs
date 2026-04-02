use crate::NAT64RuleSnapshot;
use crate::nat::NatDecision;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};

/// NAT64 prefix configuration — one per `security nat nat64` rule.
#[derive(Debug)]
pub(crate) struct Nat64Prefix {
    /// First 96 bits of the NAT64 prefix (e.g. 64:ff9b::).
    pub(crate) prefix_bytes: [u8; 12],
    /// IPv4 source pool addresses for SNAT.
    pub(crate) pool_v4: Vec<Ipv4Addr>,
    /// Round-robin index for pool allocation (atomic for thread safety).
    pool_index: AtomicUsize,
}

impl Clone for Nat64Prefix {
    fn clone(&self) -> Self {
        Self {
            prefix_bytes: self.prefix_bytes,
            pool_v4: self.pool_v4.clone(),
            pool_index: AtomicUsize::new(self.pool_index.load(Ordering::Relaxed)),
        }
    }
}

/// Aggregated NAT64 state built from config snapshots.
#[derive(Clone, Debug, Default)]
pub(crate) struct Nat64State {
    pub(crate) prefixes: Vec<Nat64Prefix>,
}

/// Reverse-direction state stored with NAT64 sessions so IPv4 replies can be
/// translated back to IPv6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Nat64ReverseInfo {
    pub(crate) orig_src_v6: Ipv6Addr,
    pub(crate) orig_dst_v6: Ipv6Addr,
}

impl Nat64State {
    /// Build from config snapshot NAT64 rules.
    pub(crate) fn from_snapshots(snaps: &[NAT64RuleSnapshot]) -> Self {
        let mut prefixes = Vec::with_capacity(snaps.len());
        for snap in snaps {
            if snap.prefix.is_empty() {
                continue;
            }
            // Parse "64:ff9b::/96" — extract the prefix address and verify /96.
            let parts: Vec<&str> = snap.prefix.split('/').collect();
            let prefix_len: u8 = match parts.get(1).and_then(|s| s.parse().ok()) {
                Some(96) => 96,
                _ => continue, // Only /96 is supported.
            };
            let _ = prefix_len; // suppress warning; validated above
            let addr: Ipv6Addr = match parts[0].parse() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let octets = addr.octets();
            let mut prefix_bytes = [0u8; 12];
            prefix_bytes.copy_from_slice(&octets[..12]);
            let pool_v4: Vec<Ipv4Addr> = snap
                .pool_addresses
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            prefixes.push(Nat64Prefix {
                prefix_bytes,
                pool_v4,
                pool_index: AtomicUsize::new(0),
            });
        }
        Self { prefixes }
    }

    /// Returns true if any NAT64 prefixes are configured.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_active(&self) -> bool {
        !self.prefixes.is_empty()
    }

    /// Check if an IPv6 destination matches any NAT64 prefix.
    /// Returns (prefix_index, extracted_ipv4_dest) on match.
    pub(crate) fn match_ipv6_dest(&self, dst: Ipv6Addr) -> Option<(usize, Ipv4Addr)> {
        let octets = dst.octets();
        for (idx, prefix) in self.prefixes.iter().enumerate() {
            if octets[..12] == prefix.prefix_bytes {
                let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return Some((idx, v4));
            }
        }
        None
    }

    /// Round-robin allocation of an IPv4 source address from the pool.
    pub(crate) fn allocate_v4_source(&self, prefix_idx: usize) -> Option<Ipv4Addr> {
        let prefix = self.prefixes.get(prefix_idx)?;
        if prefix.pool_v4.is_empty() {
            return None;
        }
        let idx = prefix.pool_index.fetch_add(1, Ordering::Relaxed);
        let addr = prefix.pool_v4[idx % prefix.pool_v4.len()];
        Some(addr)
    }

    /// Create a NAT64 forward decision: IPv6 packet → IPv4 translated.
    /// `snat_v4` is the SNAT pool address, `dst_v4` is extracted from the prefix.
    pub(crate) fn forward_decision(snat_v4: Ipv4Addr, dst_v4: Ipv4Addr) -> NatDecision {
        NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_v4)),
            rewrite_dst: Some(IpAddr::V4(dst_v4)),
            rewrite_src_port: None,
            rewrite_dst_port: None,
            nat64: true,
            nptv6: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Packet translation functions
// ---------------------------------------------------------------------------

const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;

/// Translate an IPv6 packet to IPv4 (forward direction: client→server).
///
/// Input: `packet` starts at L3 (IPv6 header), not Ethernet.
/// `snat_v4` = pool IPv4 source, `dst_v4` = extracted destination.
///
/// Returns the translated IPv4 packet (L3 only, no Ethernet header).
pub(crate) fn translate_v6_to_v4(
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
) -> Option<Vec<u8>> {
    if packet.len() < 40 {
        return None;
    }
    // IPv6 header fields.
    let _traffic_class = ((packet[0] & 0x0f) << 4) | (packet[1] >> 4);
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let next_header = packet[6];
    let hop_limit = packet[7];

    if hop_limit <= 1 {
        return None; // TTL expired
    }

    // Map protocol.
    let ipv4_protocol = match next_header {
        PROTO_ICMPV6 => PROTO_ICMP,
        PROTO_TCP | PROTO_UDP => next_header,
        _ => return None, // Unsupported protocol
    };

    let l4_payload = packet.get(40..40 + payload_len)?;
    let new_ttl = hop_limit - 1;

    // Total IPv4 packet length: 20 (header) + L4 payload.
    let ipv4_total_len = 20u16 + l4_payload.len() as u16;
    let mut out = vec![0u8; ipv4_total_len as usize];

    // Build IPv4 header.
    out[0] = 0x45; // version=4, IHL=5
    out[1] = 0; // DSCP/ECN (TODO: copy from traffic class)
    out[2..4].copy_from_slice(&ipv4_total_len.to_be_bytes());
    // ID = 0, flags = DF (0x4000)
    out[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags + frag offset: DF
    out[8] = new_ttl;
    out[9] = ipv4_protocol;
    // Checksum = 0 (computed below)
    out[12..16].copy_from_slice(&snat_v4.octets());
    out[16..20].copy_from_slice(&dst_v4.octets());

    // Copy L4 payload.
    out[20..].copy_from_slice(l4_payload);

    // ICMP type/code translation.
    if next_header == PROTO_ICMPV6 {
        translate_icmpv6_to_icmpv4(&mut out[20..])?;
    }

    // Recompute L4 checksum (pseudo-header changes from IPv6 to IPv4).
    recompute_l4_checksum_after_nat64_v6_to_v4(&mut out, ipv4_protocol)?;

    // Compute IPv4 header checksum.
    out[10..12].copy_from_slice(&[0, 0]);
    let hdr_sum = checksum16(&out[..20]);
    out[10..12].copy_from_slice(&hdr_sum.to_be_bytes());

    Some(out)
}

/// Translate an IPv4 packet to IPv6 (reverse direction: server→client reply).
///
/// Input: `packet` starts at L3 (IPv4 header), not Ethernet.
/// `dst_v6` is the original IPv6 client source, `src_v6` is the NAT64 prefix
/// + original IPv4 server address (i.e. orig_dst_v6 for the reply src).
///
/// Returns the translated IPv6 packet (L3 only, no Ethernet header).
pub(crate) fn translate_v4_to_v6(
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
) -> Option<Vec<u8>> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let ttl = packet[8];
    if ttl <= 1 {
        return None; // TTL expired
    }
    let protocol = packet[9];
    let l4_payload = packet.get(ihl..)?;

    // Map protocol.
    let next_header = match protocol {
        PROTO_ICMP => PROTO_ICMPV6,
        PROTO_TCP | PROTO_UDP => protocol,
        _ => return None,
    };

    let new_hop_limit = ttl - 1;
    let ipv6_payload_len = l4_payload.len() as u16;
    let total_len = 40 + l4_payload.len();
    let mut out = vec![0u8; total_len];

    // Build IPv6 header.
    out[0] = 0x60; // version=6
    // flow label and traffic class = 0 for now
    out[4..6].copy_from_slice(&ipv6_payload_len.to_be_bytes());
    out[6] = next_header;
    out[7] = new_hop_limit;
    out[8..24].copy_from_slice(&src_v6.octets());
    out[24..40].copy_from_slice(&dst_v6.octets());

    // Copy L4 payload.
    out[40..].copy_from_slice(l4_payload);

    // ICMP type/code translation.
    if protocol == PROTO_ICMP {
        translate_icmpv4_to_icmpv6(&mut out[40..])?;
    }

    // Recompute L4 checksum (pseudo-header changes from IPv4 to IPv6).
    recompute_l4_checksum_after_nat64_v4_to_v6(&mut out, next_header)?;

    Some(out)
}

/// Translate ICMPv6 type/code to ICMPv4.
fn translate_icmpv6_to_icmpv4(icmp: &mut [u8]) -> Option<()> {
    if icmp.len() < 4 {
        return None;
    }
    let icmpv6_type = icmp[0];
    let (icmpv4_type, icmpv4_code) = match icmpv6_type {
        ICMPV6_ECHO_REQUEST => (ICMP_ECHO_REQUEST, 0u8),
        ICMPV6_ECHO_REPLY => (ICMP_ECHO_REPLY, 0u8),
        _ => return None, // Unsupported ICMPv6 type
    };
    icmp[0] = icmpv4_type;
    icmp[1] = icmpv4_code;
    // Checksum will be recomputed below.
    Some(())
}

/// Translate ICMPv4 type/code to ICMPv6.
fn translate_icmpv4_to_icmpv6(icmp: &mut [u8]) -> Option<()> {
    if icmp.len() < 4 {
        return None;
    }
    let icmpv4_type = icmp[0];
    let (icmpv6_type, icmpv6_code) = match icmpv4_type {
        ICMP_ECHO_REQUEST => (ICMPV6_ECHO_REQUEST, 0u8),
        ICMP_ECHO_REPLY => (ICMPV6_ECHO_REPLY, 0u8),
        _ => return None,
    };
    icmp[0] = icmpv6_type;
    icmp[1] = icmpv6_code;
    Some(())
}

/// Recompute L4 checksum after IPv6→IPv4 translation.
fn recompute_l4_checksum_after_nat64_v6_to_v4(packet: &mut [u8], protocol: u8) -> Option<()> {
    if packet.len() < 20 {
        return None;
    }
    // Read IP addresses before taking mutable borrow of L4 portion.
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let l4 = &mut packet[20..];
    match protocol {
        PROTO_TCP => {
            if l4.len() < 20 {
                return None;
            }
            l4[16..18].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv4_pseudo(src, dst, protocol, l4);
            l4[16..18].copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            l4[6..8].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv4_pseudo(src, dst, protocol, l4);
            l4[6..8].copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_ICMP => {
            if l4.len() < 4 {
                return None;
            }
            // ICMPv4 does NOT use pseudo-header — checksum over ICMP message only.
            l4[2..4].copy_from_slice(&[0, 0]);
            let sum = checksum16(l4);
            l4[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

/// Recompute L4 checksum after IPv4→IPv6 translation.
fn recompute_l4_checksum_after_nat64_v4_to_v6(packet: &mut [u8], next_header: u8) -> Option<()> {
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
    let l4 = &mut packet[40..];
    match next_header {
        PROTO_TCP => {
            if l4.len() < 20 {
                return None;
            }
            l4[16..18].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            l4[16..18].copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            l4[6..8].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            // UDP over IPv6: zero checksum is illegal, but if it computes to 0
            // the standard says use 0xFFFF.
            let final_sum = if sum == 0 { 0xFFFF } else { sum };
            l4[6..8].copy_from_slice(&final_sum.to_be_bytes());
        }
        PROTO_ICMPV6 => {
            if l4.len() < 4 {
                return None;
            }
            // ICMPv6 DOES use pseudo-header.
            l4[2..4].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            l4[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Checksum helpers
// ---------------------------------------------------------------------------

fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum16_ipv4_pseudo(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(protocol);
    pseudo.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(payload);
    checksum16(&pseudo)
}

fn checksum16_ipv6_pseudo(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, next_header]);
    pseudo.extend_from_slice(payload);
    checksum16(&pseudo)
}

// ---------------------------------------------------------------------------
// Frame building helpers for NAT64
// ---------------------------------------------------------------------------

/// Build a complete Ethernet + IPv4 frame from an Ethernet + IPv6 frame.
/// Used for forward NAT64 (IPv6→IPv4): frame shrinks by 20 bytes.
///
/// `eth_dst`, `eth_src` are the new L2 addresses for the forwarded frame.
/// `vlan_id` is inserted if > 0.
pub(crate) fn build_nat64_v6_to_v4_frame(
    frame: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
) -> Option<Vec<u8>> {
    // Find L3 offset.
    let l3 = frame_l3_offset(frame)?;
    let ipv6_packet = frame.get(l3..)?;
    let ipv4_packet = translate_v6_to_v4(ipv6_packet, snat_v4, dst_v4)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let total = eth_len + ipv4_packet.len();
    let mut out = vec![0u8; total];
    write_eth_header(&mut out, eth_dst, eth_src, vlan_id, 0x0800)?;
    out[eth_len..].copy_from_slice(&ipv4_packet);
    Some(out)
}

/// Build a complete Ethernet + IPv6 frame from an Ethernet + IPv4 frame.
/// Used for reverse NAT64 (IPv4→IPv6): frame grows by 20 bytes.
///
/// `src_v6` and `dst_v6` are the restored IPv6 addresses.
pub(crate) fn build_nat64_v4_to_v6_frame(
    frame: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
) -> Option<Vec<u8>> {
    let l3 = frame_l3_offset(frame)?;
    let ipv4_packet = frame.get(l3..)?;
    let ipv6_packet = translate_v4_to_v6(ipv4_packet, src_v6, dst_v6)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let total = eth_len + ipv6_packet.len();
    let mut out = vec![0u8; total];
    write_eth_header(&mut out, eth_dst, eth_src, vlan_id, 0x86dd)?;
    out[eth_len..].copy_from_slice(&ipv6_packet);
    Some(out)
}

/// Find the L3 offset by checking Ethernet type/VLAN.
fn frame_l3_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype == 0x8100 {
        if frame.len() < 18 {
            return None;
        }
        Some(18)
    } else {
        Some(14)
    }
}

/// Write Ethernet header (with optional VLAN tag) into the beginning of `buf`.
fn write_eth_header(
    buf: &mut [u8],
    dst: [u8; 6],
    src: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
) -> Option<()> {
    if vlan_id > 0 {
        if buf.len() < 18 {
            return None;
        }
        buf[..6].copy_from_slice(&dst);
        buf[6..12].copy_from_slice(&src);
        buf[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        buf[14..16].copy_from_slice(&vlan_id.to_be_bytes());
        buf[16..18].copy_from_slice(&ether_type.to_be_bytes());
    } else {
        if buf.len() < 14 {
            return None;
        }
        buf[..6].copy_from_slice(&dst);
        buf[6..12].copy_from_slice(&src);
        buf[12..14].copy_from_slice(&ether_type.to_be_bytes());
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
        let d =
            Nat64State::forward_decision(Ipv4Addr::new(198, 51, 100, 1), Ipv4Addr::new(8, 8, 8, 8));
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

        let result = build_nat64_v4_to_v6_frame(&frame, src_v6, dst_v6, [0x11; 6], [0x22; 6], 0)
            .expect("build");

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
            translate_v6_to_v4(&pkt, Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8),)
                .is_none()
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
}
