//! Outer L2 + IPv4 + UDP header construction for WG encap.
//!
//! Scope: IPv4 outer only in this PR. The framing module is
//! family-agnostic but the outer-header builder is not — adding
//! v6 outer is a follow-up.
//!
//! All builders write into a caller-provided slice. No allocations.

use std::net::Ipv4Addr;

/// Length of an outer L2 header with optional 802.1Q tag.
#[inline]
pub(crate) fn outer_l2_len(vlan_id: u16) -> usize {
    if vlan_id != 0 { 18 } else { 14 }
}

/// Write the outer Ethernet header (with optional 802.1Q tag) into
/// `out`. `ethertype` should be 0x0800 for IPv4 (this PR's only
/// supported outer).
///
/// Returns the number of bytes written. Returns `None` if the slice
/// is too short.
pub(crate) fn write_outer_eth(
    out: &mut [u8],
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    vlan_id: u16,
    ethertype: u16,
) -> Option<usize> {
    let len = outer_l2_len(vlan_id);
    let hdr = out.get_mut(..len)?;
    hdr[0..6].copy_from_slice(&dst_mac);
    hdr[6..12].copy_from_slice(&src_mac);
    if vlan_id != 0 {
        // 802.1Q TPID 0x8100, then PCP=0 DEI=0 VID=vlan_id, then
        // inner ethertype.
        hdr[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        let tci = vlan_id & 0x0FFF;
        hdr[14..16].copy_from_slice(&tci.to_be_bytes());
        hdr[16..18].copy_from_slice(&ethertype.to_be_bytes());
    } else {
        hdr[12..14].copy_from_slice(&ethertype.to_be_bytes());
    }
    Some(len)
}

/// Write the outer IPv4 + UDP header for a WG-encapsulated payload.
///
/// `payload_len` is the length of the WG transport record
/// (header + ciphertext + tag) that follows the UDP header.
///
/// The IPv4 checksum is computed over the IPv4 header only;
/// per RFC 768 the UDP checksum on IPv4 is optional. We set it to
/// zero (skip) for now — UDP checksum offload semantics differ
/// across NICs and we want a known-baseline behavior. A future
/// PR can wire it through if needed.
pub(crate) fn write_outer_ipv4_udp(
    out: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    tos: u8,
    ttl: u8,
    payload_len: usize,
) -> Option<usize> {
    const IP_HDR_LEN: usize = 20;
    const UDP_HDR_LEN: usize = 8;
    let total = IP_HDR_LEN + UDP_HDR_LEN + payload_len;
    let total_len = u16::try_from(total).ok()?;
    let udp_len = u16::try_from(UDP_HDR_LEN + payload_len).ok()?;
    let hdr = out.get_mut(..IP_HDR_LEN + UDP_HDR_LEN)?;
    // IPv4 header.
    hdr[0] = 0x45;
    hdr[1] = tos;
    hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
    hdr[4..6].copy_from_slice(&0u16.to_be_bytes()); // ID = 0
    hdr[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags / frag
    hdr[8] = if ttl == 0 { 64 } else { ttl };
    hdr[9] = 17; // UDP
    hdr[10..12].copy_from_slice(&[0, 0]); // checksum placeholder
    hdr[12..16].copy_from_slice(&src.octets());
    hdr[16..20].copy_from_slice(&dst.octets());
    let ip_csum = checksum_be(&hdr[..IP_HDR_LEN]);
    hdr[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    // UDP header.
    hdr[20..22].copy_from_slice(&src_port.to_be_bytes());
    hdr[22..24].copy_from_slice(&dst_port.to_be_bytes());
    hdr[24..26].copy_from_slice(&udp_len.to_be_bytes());
    hdr[26..28].copy_from_slice(&0u16.to_be_bytes()); // checksum = 0
    Some(IP_HDR_LEN + UDP_HDR_LEN)
}

/// 16-bit ones-complement Internet checksum, returned in host-byte
/// order ready to splat into a network-byte-order field. Same shape
/// as `gre.rs::checksum16` but local — keeping the WG module free
/// of dependencies on the rest of `afxdp/`.
fn checksum_be(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum = sum.wrapping_add(u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32);
        i += 2;
    }
    if i < bytes.len() {
        sum = sum.wrapping_add((bytes[i] as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod outer_tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn outer_eth_no_vlan() {
        let mut out = [0u8; 32];
        let n = write_outer_eth(
            &mut out,
            [1, 2, 3, 4, 5, 6],
            [7, 8, 9, 10, 11, 12],
            0,
            0x0800,
        )
        .unwrap();
        assert_eq!(n, 14);
        assert_eq!(&out[0..6], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(&out[6..12], &[7, 8, 9, 10, 11, 12]);
        assert_eq!(&out[12..14], &[0x08, 0x00]);
    }

    #[test]
    fn outer_eth_with_vlan() {
        // VLAN-safe encap was one of the #1492 misses. Verify the
        // 802.1Q layout is correct: TPID, then PCP/VID, then the
        // inner ethertype.
        let mut out = [0u8; 32];
        let n = write_outer_eth(
            &mut out,
            [0; 6],
            [0; 6],
            0x123, // VID 0x123
            0x0800,
        )
        .unwrap();
        assert_eq!(n, 18);
        assert_eq!(&out[12..14], &[0x81, 0x00]);
        assert_eq!(&out[14..16], &[0x01, 0x23]);
        assert_eq!(&out[16..18], &[0x08, 0x00]);
    }

    #[test]
    fn ipv4_udp_header_layout() {
        let mut out = [0u8; 40];
        let n = write_outer_ipv4_udp(
            &mut out,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            51820,
            51820,
            0,
            64,
            100,
        )
        .unwrap();
        assert_eq!(n, 28);
        assert_eq!(out[0], 0x45);
        // Total length = 20 + 8 + 100 = 128.
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 128);
        assert_eq!(out[8], 64); // TTL
        assert_eq!(out[9], 17); // UDP
        // UDP length = 8 + 100 = 108
        assert_eq!(u16::from_be_bytes([out[24], out[25]]), 108);
    }

    #[test]
    fn ipv4_checksum_is_correct() {
        // Round-trip: the checksum field is set such that a fresh
        // checksum over the full header (with the checksum present)
        // is zero. This is the standard self-check for an IPv4
        // header's correctness.
        let mut out = [0u8; 28];
        write_outer_ipv4_udp(
            &mut out,
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 1),
            12345,
            51820,
            0xb8, // EF
            64,
            500,
        )
        .unwrap();
        let cs = checksum_be(&out[..20]);
        assert_eq!(cs, 0, "header self-check failed (cs={:#06x})", cs);
    }

    #[test]
    fn tos_is_threaded_through() {
        let mut out = [0u8; 28];
        write_outer_ipv4_udp(
            &mut out,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(0, 0, 0, 0),
            0,
            0,
            0xb8, // EF (DSCP=46 << 2)
            64,
            0,
        )
        .unwrap();
        assert_eq!(out[1], 0xb8);
    }
}
