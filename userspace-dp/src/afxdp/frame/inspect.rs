//! Header inspection / parsing helpers — pure read-only fns over
//! Ethernet/IPv4/IPv6/TCP/UDP/ICMP byte buffers. No mutation.
//!
//! Phase 2 split out of `frame.rs` per #988. Larger inspect fns
//! (parse_session_flow_*, authoritative_forward_ports,
//! try_parse_metadata) remain in mod.rs for now and will land in a
//! follow-on phase to keep this diff reviewable.

use super::*;

/// Check if a frame contains a TCP RST flag.
pub(in crate::afxdp) fn frame_has_tcp_rst(frame: &[u8]) -> bool {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return false,
    };
    let ip = match frame.get(l3..) {
        Some(ip) if ip.len() >= 20 => ip,
        _ => return false,
    };
    let (protocol, l4_offset) = match ip[0] >> 4 {
        4 => {
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        6 if ip.len() >= 40 => (ip[6], 40usize),
        _ => return false,
    };
    if protocol != PROTO_TCP {
        return false;
    }
    let tcp = match ip.get(l4_offset..) {
        Some(t) if t.len() >= 14 => t,
        _ => return false,
    };
    // TCP flags at offset 13: RST = 0x04
    (tcp[13] & 0x04) != 0
}

/// Extract TCP flags and window from raw frame, auto-detecting L3 from Ethernet header.
/// Returns (tcp_flags, tcp_window) or None.
pub(in crate::afxdp) fn extract_tcp_flags_and_window(frame: &[u8]) -> Option<(u8, u16)> {
    let l3 = frame_l3_offset(frame)?;
    let ip = frame.get(l3..)?;
    let (protocol, l4_offset) = match ip.first()? >> 4 {
        4 => {
            if ip.len() < 20 {
                return None;
            }
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        6 => {
            if ip.len() < 40 {
                return None;
            }
            (ip[6], 40usize)
        }
        _ => return None,
    };
    if protocol != PROTO_TCP {
        return None;
    }
    let tcp = ip.get(l4_offset..)?;
    if tcp.len() < 16 {
        return None;
    }
    let flags = tcp[13];
    let window = u16::from_be_bytes([tcp[14], tcp[15]]);
    Some((flags, window))
}

/// Extract TCP window size from raw frame data.
/// Returns None if not a TCP frame or if frame is too short.
#[allow(dead_code)]
pub(in crate::afxdp) fn extract_tcp_window(frame: &[u8], addr_family: u8) -> Option<u16> {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return None,
    };
    let ip = frame.get(l3..)?;
    let (protocol, l4_offset) = match addr_family as i32 {
        libc::AF_INET => {
            if ip.len() < 20 {
                return None;
            }
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        libc::AF_INET6 => {
            if ip.len() < 40 {
                return None;
            }
            (ip[6], 40usize)
        }
        _ => return None,
    };
    if protocol != PROTO_TCP {
        return None;
    }
    let tcp = ip.get(l4_offset..)?;
    if tcp.len() < 16 {
        return None;
    }
    // TCP window is at offset 14-15 (big-endian)
    Some(u16::from_be_bytes([tcp[14], tcp[15]]))
}

pub(in crate::afxdp) fn frame_l3_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < 14 {
        return None;
    }
    let eth_proto = u16::from_be_bytes([frame[12], frame[13]]);
    if matches!(eth_proto, 0x8100 | 0x88a8) {
        if frame.len() < 18 {
            return None;
        }
        return Some(18);
    }
    Some(14)
}

pub(in crate::afxdp) fn tcp_flags_str(flags: u8) -> String {
    let mut s = String::with_capacity(12);
    if flags & 0x02 != 0 {
        s.push_str("SYN ");
    }
    if flags & 0x10 != 0 {
        s.push_str("ACK ");
    }
    if flags & 0x01 != 0 {
        s.push_str("FIN ");
    }
    if flags & 0x04 != 0 {
        s.push_str("RST ");
    }
    if flags & 0x08 != 0 {
        s.push_str("PSH ");
    }
    if flags & 0x20 != 0 {
        s.push_str("URG ");
    }
    if s.ends_with(' ') {
        s.truncate(s.len() - 1);
    }
    if s.is_empty() {
        s.push_str("none");
    }
    s
}

pub(in crate::afxdp) fn frame_l4_offset(frame: &[u8], addr_family: u8) -> Option<usize> {
    let l3 = frame_l3_offset(frame)?;
    match addr_family as i32 {
        libc::AF_INET => {
            if frame.len() < l3 + 20 {
                return None;
            }
            let ihl = usize::from(frame[l3] & 0x0f) * 4;
            if ihl < 20 || frame.len() < l3 + ihl {
                return None;
            }
            Some(l3 + ihl)
        }
        libc::AF_INET6 => {
            if frame.len() < l3 + 40 {
                return None;
            }
            let mut protocol = *frame.get(l3 + 6)?;
            let mut offset = l3 + 40;
            for _ in 0..6 {
                match protocol {
                    0 | 43 | 60 => {
                        let opt = frame.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
                        if frame.len() < offset {
                            return None;
                        }
                    }
                    51 => {
                        let opt = frame.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 2) * 4)?;
                        if frame.len() < offset {
                            return None;
                        }
                    }
                    44 => {
                        let frag = frame.get(offset..offset + 8)?;
                        protocol = frag[0];
                        offset = offset.checked_add(8)?;
                        if frame.len() < offset {
                            return None;
                        }
                    }
                    59 => return None,
                    _ => return Some(offset),
                }
            }
            Some(offset)
        }
        _ => None,
    }
}

pub(in crate::afxdp) fn packet_rel_l4_offset(packet: &[u8], addr_family: u8) -> Option<usize> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            Some(ihl)
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut protocol = *packet.get(6)?;
            let mut offset = 40usize;
            for _ in 0..6 {
                match protocol {
                    0 | 43 | 60 => {
                        let opt = packet.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    51 => {
                        let opt = packet.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 2) * 4)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    44 => {
                        let frag = packet.get(offset..offset + 8)?;
                        protocol = frag[0];
                        offset = offset.checked_add(8)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    59 => return None,
                    _ => return Some(offset),
                }
            }
            Some(offset)
        }
        _ => None,
    }
}

/// Like `packet_rel_l4_offset` but also returns the final L4 protocol
/// after walking IPv6 extension headers. For IPv4, returns the protocol
/// byte from the IP header. Needed for GRE inner packet parsing where
/// the initial next-header (packet[6]) may be an extension header, not
/// the actual L4 protocol.
pub(in crate::afxdp) fn packet_rel_l4_offset_and_protocol(
    packet: &[u8],
    addr_family: u8,
) -> Option<(usize, u8)> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            Some((ihl, packet[9]))
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut protocol = *packet.get(6)?;
            let mut offset = 40usize;
            for _ in 0..6 {
                match protocol {
                    0 | 43 | 60 => {
                        let opt = packet.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    51 => {
                        let opt = packet.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 2) * 4)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    44 => {
                        let frag = packet.get(offset..offset + 8)?;
                        protocol = frag[0];
                        offset = offset.checked_add(8)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    59 => return None,
                    _ => return Some((offset, protocol)),
                }
            }
            Some((offset, protocol))
        }
        _ => None,
    }
}

pub(in crate::afxdp) fn metadata_tuple_complete(meta: UserspaceDpMeta, flow: &SessionFlow) -> bool {
    if flow.src_ip.is_unspecified() || flow.dst_ip.is_unspecified() {
        return false;
    }
    match meta.protocol {
        PROTO_TCP | PROTO_UDP => flow.forward_key.src_port != 0 && flow.forward_key.dst_port != 0,
        _ => true,
    }
}

pub(in crate::afxdp) fn parse_flow_ports(frame: &[u8], l4: usize, protocol: u8) -> Option<(u16, u16)> {
    match protocol {
        PROTO_TCP | PROTO_UDP => {
            let bytes = frame.get(l4..l4 + 4)?;
            Some((
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
            ))
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            let bytes = frame.get(l4 + 4..l4 + 6)?;
            let ident = u16::from_be_bytes([bytes[0], bytes[1]]);
            Some((ident, 0))
        }
        _ => None,
    }
}
