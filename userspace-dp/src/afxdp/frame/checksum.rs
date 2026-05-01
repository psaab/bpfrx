// Pure 16-bit one's-complement checksum arithmetic for IPv4/IPv6
// header + L4 (TCP/UDP/ICMP) updates.

use crate::afxdp::{PROTO_TCP, PROTO_UDP, PROTO_ICMPV6};
use std::net::{Ipv4Addr, Ipv6Addr};

pub(in crate::afxdp) fn checksum16(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(last) = chunks.remainder().first() {
        sum += (*last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(in crate::afxdp) fn checksum16_add_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(last) = chunks.remainder().first() {
        sum += (*last as u32) << 8;
    }
    sum
}

pub(in crate::afxdp) fn checksum16_finish(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(in crate::afxdp) fn checksum16_adjust(checksum: u16, old_words: &[u16], new_words: &[u16]) -> u16 {
    let mut sum = (!checksum as u32) & 0xffff;
    for word in old_words {
        sum += (!u32::from(*word)) & 0xffff;
    }
    for word in new_words {
        sum += u32::from(*word);
    }
    checksum16_finish(sum)
}

#[inline(always)]
fn checksum16_adjust_ipv6_addr_bytes(
    checksum: u16,
    old_addr: &[u8; 16],
    new_addr: &[u8; 16],
) -> u16 {
    let mut sum = (!checksum as u32) & 0xffff;
    let mut idx = 0usize;
    while idx < 16 {
        let old_word = u16::from_be_bytes([old_addr[idx], old_addr[idx + 1]]);
        let new_word = u16::from_be_bytes([new_addr[idx], new_addr[idx + 1]]);
        sum += (!u32::from(old_word)) & 0xffff;
        sum += u32::from(new_word);
        idx += 2;
    }
    checksum16_finish(sum)
}

pub(in crate::afxdp) fn ipv4_words(ip: Ipv4Addr) -> [u16; 2] {
    let octets = ip.octets();
    [
        u16::from_be_bytes([octets[0], octets[1]]),
        u16::from_be_bytes([octets[2], octets[3]]),
    ]
}

#[allow(dead_code)]
pub(in crate::afxdp) fn ipv6_words(ip: Ipv6Addr) -> [u16; 8] {
    ipv6_words_from_octets(ip.octets())
}

pub(in crate::afxdp) fn ipv6_words_from_octets(octets: [u8; 16]) -> [u16; 8] {
    [
        u16::from_be_bytes([octets[0], octets[1]]),
        u16::from_be_bytes([octets[2], octets[3]]),
        u16::from_be_bytes([octets[4], octets[5]]),
        u16::from_be_bytes([octets[6], octets[7]]),
        u16::from_be_bytes([octets[8], octets[9]]),
        u16::from_be_bytes([octets[10], octets[11]]),
        u16::from_be_bytes([octets[12], octets[13]]),
        u16::from_be_bytes([octets[14], octets[15]]),
    ]
}

pub(in crate::afxdp) fn ipv6_words_from_slice(bytes: &[u8]) -> Option<[u16; 8]> {
    let octets: [u8; 16] = bytes.get(..16)?.try_into().ok()?;
    Some(ipv6_words_from_octets(octets))
}

pub(in crate::afxdp) fn adjust_ipv4_header_checksum(
    packet: &mut [u8],
    old_src: Ipv4Addr,
    old_dst: Ipv4Addr,
    old_ttl: u8,
) -> Option<()> {
    if packet.len() < 20 {
        return None;
    }
    let current = u16::from_be_bytes([packet[10], packet[11]]);
    let new_src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let new_dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let old_ttl_word = u16::from_be_bytes([old_ttl, packet[9]]);
    let new_ttl_word = u16::from_be_bytes([packet[8], packet[9]]);
    let mut updated = checksum16_adjust(current, &ipv4_words(old_src), &ipv4_words(new_src));
    updated = checksum16_adjust(updated, &ipv4_words(old_dst), &ipv4_words(new_dst));
    updated = checksum16_adjust(updated, &[old_ttl_word], &[new_ttl_word]);
    packet
        .get_mut(10..12)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

pub(in crate::afxdp) fn checksum16_ipv6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    payload: &[u8],
) -> u16 {
    let mut sum = 0u32;
    sum = checksum16_add_bytes(sum, &src.octets());
    sum = checksum16_add_bytes(sum, &dst.octets());
    sum = checksum16_add_bytes(sum, &(payload.len() as u32).to_be_bytes());
    sum = checksum16_add_bytes(sum, &[0, 0, 0, next_header]);
    sum = checksum16_add_bytes(sum, payload);
    checksum16_finish(sum)
}

pub(in crate::afxdp) fn checksum16_ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = checksum16_add_bytes(sum, &src.octets());
    sum = checksum16_add_bytes(sum, &dst.octets());
    sum = checksum16_add_bytes(sum, &[0, protocol]);
    sum = checksum16_add_bytes(sum, &(payload.len() as u16).to_be_bytes());
    sum = checksum16_add_bytes(sum, payload);
    checksum16_finish(sum)
}

pub(in crate::afxdp) fn adjust_l4_checksum_ipv4(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_src: Ipv4Addr,
    new_src: Ipv4Addr,
    old_dst: Ipv4Addr,
    new_dst: Ipv4Addr,
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => ihl.checked_add(16)?,
        PROTO_UDP => ihl.checked_add(6)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust(current, &ipv4_words(old_src), &ipv4_words(new_src));
    updated = checksum16_adjust(updated, &ipv4_words(old_dst), &ipv4_words(new_dst));
    if matches!(protocol, PROTO_UDP) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

#[allow(dead_code)]
pub(in crate::afxdp) fn adjust_l4_checksum_ipv6(
    packet: &mut [u8],
    protocol: u8,
    old_src: Ipv6Addr,
    new_src: Ipv6Addr,
    old_dst: Ipv6Addr,
    new_dst: Ipv6Addr,
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => 40usize.checked_add(16)?,
        PROTO_UDP => 40usize.checked_add(6)?,
        PROTO_ICMPV6 => 40usize.checked_add(2)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust(current, &ipv6_words(old_src), &ipv6_words(new_src));
    updated = checksum16_adjust(updated, &ipv6_words(old_dst), &ipv6_words(new_dst));
    if matches!(protocol, PROTO_UDP | PROTO_ICMPV6) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

pub(in crate::afxdp) fn adjust_l4_checksum_ipv4_src(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_src: Ipv4Addr,
    new_src: Ipv4Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv4_words(
        packet,
        ihl,
        protocol,
        &ipv4_words(old_src),
        &ipv4_words(new_src),
    )
}

pub(in crate::afxdp) fn adjust_l4_checksum_ipv4_dst(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_dst: Ipv4Addr,
    new_dst: Ipv4Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv4_words(
        packet,
        ihl,
        protocol,
        &ipv4_words(old_dst),
        &ipv4_words(new_dst),
    )
}

pub(in crate::afxdp) fn adjust_l4_checksum_ipv4_words(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_words: &[u16],
    new_words: &[u16],
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => ihl.checked_add(16)?,
        PROTO_UDP => ihl.checked_add(6)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    if matches!(protocol, PROTO_UDP) && current == 0 {
        return Some(());
    }
    let updated = checksum16_adjust(current, old_words, new_words);
    let updated = if matches!(protocol, PROTO_UDP) && updated == 0 {
        0xffff
    } else {
        updated
    };
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

#[allow(dead_code)]
pub(in crate::afxdp) fn adjust_l4_checksum_ipv6_src(
    packet: &mut [u8],
    protocol: u8,
    old_src: Ipv6Addr,
    new_src: Ipv6Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv6_words(packet, protocol, &ipv6_words(old_src), &ipv6_words(new_src))
}

#[allow(dead_code)]
pub(in crate::afxdp) fn adjust_l4_checksum_ipv6_dst(
    packet: &mut [u8],
    protocol: u8,
    old_dst: Ipv6Addr,
    new_dst: Ipv6Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv6_words(packet, protocol, &ipv6_words(old_dst), &ipv6_words(new_dst))
}

pub(in crate::afxdp) fn adjust_l4_checksum_ipv6_words(
    packet: &mut [u8],
    protocol: u8,
    old_words: &[u16],
    new_words: &[u16],
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => 40usize.checked_add(16)?,
        PROTO_UDP => 40usize.checked_add(6)?,
        PROTO_ICMPV6 => 40usize.checked_add(2)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust(current, old_words, new_words);
    if matches!(protocol, PROTO_UDP | PROTO_ICMPV6) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

#[inline(always)]
pub(super) fn adjust_l4_checksum_ipv6_addr_bytes(
    packet: &mut [u8],
    protocol: u8,
    old_addr: &[u8; 16],
    new_addr: &[u8; 16],
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => 56usize,
        PROTO_UDP => 46usize,
        PROTO_ICMPV6 => 42usize,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust_ipv6_addr_bytes(current, old_addr, new_addr);
    if matches!(protocol, PROTO_UDP | PROTO_ICMPV6) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

pub(in crate::afxdp) fn recompute_l4_checksum_ipv4(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    zero_offset: bool,
) -> Option<()> {
    let segment = packet.get(ihl..)?;
    match protocol {
        PROTO_TCP => {
            if segment.len() < 20 {
                return None;
            }
            packet.get_mut(ihl + 16..ihl + 18)?.copy_from_slice(&[0, 0]);
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let sum = checksum16_ipv4(src, dst, protocol, packet.get(ihl..)?);
            packet
                .get_mut(ihl + 16..ihl + 18)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if segment.len() < 8 {
                return None;
            }
            packet.get_mut(ihl + 6..ihl + 8)?.copy_from_slice(&[0, 0]);
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let sum = checksum16_ipv4(src, dst, protocol, packet.get(ihl..)?);
            let sum = if zero_offset && sum == 0 { 0xffff } else { sum };
            packet
                .get_mut(ihl + 6..ihl + 8)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

pub(in crate::afxdp) fn recompute_l4_checksum_ipv6(packet: &mut [u8], protocol: u8) -> Option<()> {
    let payload = packet.get(40..)?;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
    match protocol {
        PROTO_TCP => {
            if payload.len() < 20 {
                return None;
            }
            packet.get_mut(40 + 16..40 + 18)?.copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_TCP, packet.get(40..)?);
            packet
                .get_mut(40 + 16..40 + 18)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if payload.len() < 8 {
                return None;
            }
            packet.get_mut(40 + 6..40 + 8)?.copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_UDP, packet.get(40..)?);
            let sum = if sum == 0 { 0xffff } else { sum };
            packet
                .get_mut(40 + 6..40 + 8)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_ICMPV6 => {
            if payload.len() < 4 {
                return None;
            }
            packet.get_mut(40 + 2..40 + 4)?.copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_ICMPV6, packet.get(40..)?);
            packet
                .get_mut(40 + 2..40 + 4)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}
