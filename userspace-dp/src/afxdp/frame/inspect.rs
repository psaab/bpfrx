//! Header inspection / parsing helpers — read-only fns over
//! Ethernet/IPv4/IPv6/TCP/UDP/ICMP byte buffers. No mutation.
//!
//! Phase 2 split out of `frame.rs` per #988. The inspect cluster
//! covers raw header parsing (frame_l3_offset, parse_session_flow_*,
//! decode_frame_summary, etc.) plus session-key / fabric-tag readers
//! that operate on a frame slice without mutating it.

use super::*;

// #989: TCP-specific inspection helpers (frame_has_tcp_rst,
// extract_tcp_flags_and_window, extract_tcp_window) and tcp_flags_str
// were relocated to `frame/tcp.rs`.

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

// #989: tcp_flags_str moved to `frame/tcp.rs`.

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

pub(in crate::afxdp) fn parse_flow_ports(
    frame: &[u8],
    l4: usize,
    protocol: u8,
) -> Option<(u16, u16)> {
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

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn authoritative_forward_ports(
    frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
) -> Option<(u16, u16)> {
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    if let Some(flow_ports) = flow.and_then(|flow| {
        if flow.forward_key.src_port != 0 && flow.forward_key.dst_port != 0 {
            Some((flow.forward_key.src_port, flow.forward_key.dst_port))
        } else {
            None
        }
    }) {
        return Some(flow_ports);
    }
    let meta_ports = if meta.flow_src_port != 0 && meta.flow_dst_port != 0 {
        Some((meta.flow_src_port, meta.flow_dst_port))
    } else {
        None
    };
    let frame_ports = live_frame_ports_from_meta_bytes(frame, meta);
    frame_ports.or(meta_ports)
}

#[allow(dead_code)]
pub(in crate::afxdp) fn live_frame_ports(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<(u16, u16)> {
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    live_frame_ports_from_meta_bytes(frame, meta)
}

#[inline(always)]
pub(in crate::afxdp) fn live_frame_ports_from_meta_bytes(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
) -> Option<(u16, u16)> {
    let meta = meta.into();
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let l4 = meta.l4_offset as usize;
    if l4 != 0
        && let Some(ports) = parse_flow_ports(frame, l4, meta.protocol)
    {
        return Some(ports);
    }
    live_frame_ports_bytes(frame, meta.addr_family, meta.protocol)
}

pub(in crate::afxdp) fn live_frame_ports_bytes(
    frame: &[u8],
    addr_family: u8,
    protocol: u8,
) -> Option<(u16, u16)> {
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let l4 = frame_l4_offset(frame, addr_family)?;
    parse_flow_ports(frame, l4, protocol)
}

pub(in crate::afxdp) fn forward_tuple_mismatch_reason(
    source_ports: Option<(u16, u16)>,
    expected_ports: Option<(u16, u16)>,
    built_ports: Option<(u16, u16)>,
) -> Option<String> {
    let expected = expected_ports.or(source_ports)?;
    let built = built_ports?;
    if built == expected {
        return None;
    }
    let source = source_ports.unwrap_or((0, 0));
    Some(format!(
        "forward_tuple_mismatch:src={}:{} expected={}:{} built={}:{}",
        source.0, source.1, expected.0, expected.1, built.0, built.1
    ))
}

pub(in crate::afxdp) fn parse_session_flow_from_bytes(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    let meta_flow = parse_session_flow_from_meta(meta);
    // Fast path: for TCP/UDP with complete metadata tuple, use meta directly
    // without parsing the frame. This avoids extra L3/L4 parsing for the
    // common established-flow case.
    if matches!(meta.protocol, PROTO_TCP | PROTO_UDP)
        && let Some(meta_flow) = meta_flow.as_ref()
        && metadata_tuple_complete(meta, meta_flow)
    {
        return Some(meta_flow.clone());
    }

    let frame_flow = if matches!(meta.addr_family as i32, libc::AF_INET) {
        parse_ipv4_session_flow_from_frame(frame, meta)
    } else {
        parse_session_flow_from_frame(frame, meta)
    };

    if let Some(meta_flow) = meta_flow
        && metadata_tuple_complete(meta, &meta_flow)
    {
        if let Some(ref frame_flow) = frame_flow {
            if frame_flow.src_ip == meta_flow.src_ip && frame_flow.dst_ip == meta_flow.dst_ip {
                return Some(meta_flow);
            }
            return Some(frame_flow.clone());
        }
        return Some(meta_flow);
    }

    if let Some(flow) = frame_flow {
        return Some(flow);
    }

    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            if frame.len() < l3 + 20 || frame.len() < l4 {
                return None;
            }
            let src_ip = IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 12],
                frame[l3 + 13],
                frame[l3 + 14],
                frame[l3 + 15],
            ));
            let dst_ip = IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 16],
                frame[l3 + 17],
                frame[l3 + 18],
                frame[l3 + 19],
            ));
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                },
            })
        }
        libc::AF_INET6 => {
            if frame.len() < l3 + 40 || frame.len() < l4 {
                return None;
            }
            let src_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 8..l3 + 24]).ok()?,
            ));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            ));
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                },
            })
        }
        _ => None,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn parse_session_flow(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    parse_session_flow_from_bytes(frame, meta)
}

/// Decode an Ethernet frame into a human-readable summary showing IP src/dst,
/// TCP/UDP ports, TCP flags, and checksums. For debugging packet forwarding.
pub(in crate::afxdp) fn decode_frame_summary(frame: &[u8]) -> String {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return String::new(),
    };
    let ip = &frame[l3..];
    if ip.len() < 20 {
        return String::new();
    }
    let version = ip[0] >> 4;
    if version == 4 {
        let ihl = ((ip[0] & 0x0f) as usize) * 4;
        let total_len = u16::from_be_bytes([ip[2], ip[3]]);
        let protocol = ip[9];
        let ip_csum = u16::from_be_bytes([ip[10], ip[11]]);
        let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
        let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
        let ttl = ip[8];
        if matches!(protocol, PROTO_TCP | PROTO_UDP) && ip.len() >= ihl + 8 {
            let l4 = &ip[ihl..];
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            if protocol == PROTO_TCP && ip.len() >= ihl + 20 {
                let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
                let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
                let flags = l4[13];
                let tcp_csum = u16::from_be_bytes([l4[16], l4[17]]);
                let flag_str = tcp_flags_str(flags);
                format!(
                    "IPv4 {}:{} -> {}:{} TCP [{flag_str}] seq={seq} ack={ack} ttl={ttl} ip_csum={ip_csum:#06x} tcp_csum={tcp_csum:#06x} ip_len={total_len}",
                    src, sport, dst, dport,
                )
            } else if protocol == PROTO_UDP {
                let udp_csum = u16::from_be_bytes([l4[6], l4[7]]);
                format!(
                    "IPv4 {}:{} -> {}:{} UDP ttl={ttl} ip_csum={ip_csum:#06x} udp_csum={udp_csum:#06x} ip_len={total_len}",
                    src, sport, dst, dport,
                )
            } else {
                format!(
                    "IPv4 {} -> {} proto={protocol} ttl={ttl} ip_len={total_len}",
                    src, dst
                )
            }
        } else {
            format!(
                "IPv4 {} -> {} proto={protocol} ttl={ttl} ip_len={total_len}",
                src, dst
            )
        }
    } else if version == 6 && ip.len() >= 40 {
        let payload_len = u16::from_be_bytes([ip[4], ip[5]]);
        let next_header = ip[6];
        let hop_limit = ip[7];
        let src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap_or([0; 16]));
        let dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap_or([0; 16]));
        if matches!(next_header, PROTO_TCP | PROTO_UDP) && ip.len() >= 48 {
            let l4 = &ip[40..];
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            if next_header == PROTO_TCP && ip.len() >= 60 {
                let flags = l4[13];
                let flag_str = tcp_flags_str(flags);
                format!(
                    "IPv6 [{src}]:{sport} -> [{dst}]:{dport} TCP [{flag_str}] hop={hop_limit} pl={payload_len}"
                )
            } else {
                format!(
                    "IPv6 [{src}]:{sport} -> [{dst}]:{dport} proto={next_header} hop={hop_limit} pl={payload_len}"
                )
            }
        } else {
            format!("IPv6 [{src}] -> [{dst}] proto={next_header} hop={hop_limit} pl={payload_len}")
        }
    } else {
        String::new()
    }
}

pub(in crate::afxdp) fn parse_session_flow_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    match meta.addr_family as i32 {
        libc::AF_INET => parse_ipv4_session_flow_from_frame(frame, meta),
        libc::AF_INET6 => {
            let l3 = match meta.l3_offset {
                14 | 18
                    if frame
                        .get(meta.l3_offset as usize)
                        .is_some_and(|byte| (byte >> 4) == 6) =>
                {
                    meta.l3_offset as usize
                }
                _ => frame_l3_offset(frame)?,
            };
            let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
            let l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
                l3.checked_add(meta_rel)?
            } else {
                frame_l4_offset(frame, meta.addr_family)?
            };
            if frame.len() < l3 + 40 || frame.len() < l4 {
                return None;
            }
            let src_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 8..l3 + 24]).ok()?,
            ));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            ));
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                },
            })
        }
        _ => None,
    }
}

pub(in crate::afxdp) fn parse_session_flow_from_meta(meta: UserspaceDpMeta) -> Option<SessionFlow> {
    let (src_ip, dst_ip) = match meta.addr_family as i32 {
        libc::AF_INET => {
            let src = meta.flow_src_addr.get(..4)?;
            let dst = meta.flow_dst_addr.get(..4)?;
            (
                IpAddr::V4(Ipv4Addr::new(src[0], src[1], src[2], src[3])),
                IpAddr::V4(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3])),
            )
        }
        libc::AF_INET6 => (
            IpAddr::V6(Ipv6Addr::from(meta.flow_src_addr)),
            IpAddr::V6(Ipv6Addr::from(meta.flow_dst_addr)),
        ),
        _ => return None,
    };
    if src_ip.is_unspecified() || dst_ip.is_unspecified() {
        return None;
    }
    Some(SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            src_ip,
            dst_ip,
            src_port: meta.flow_src_port,
            dst_port: meta.flow_dst_port,
        },
    })
}

pub(in crate::afxdp) fn parse_ipv4_session_flow_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    let l3 = match meta.l3_offset {
        14 | 18
            if frame
                .get(meta.l3_offset as usize)
                .is_some_and(|byte| (byte >> 4) == 4) =>
        {
            meta.l3_offset as usize
        }
        _ => frame_l3_offset(frame)?,
    };
    if frame.len() < l3 + 20 {
        return None;
    }
    let ihl = usize::from(frame[l3] & 0x0f) * 4;
    if ihl < 20 || frame.len() < l3 + ihl {
        return None;
    }
    let protocol = frame[l3 + 9];
    let parsed_l4 = l3 + ihl;
    let l4 = if meta.l4_offset > meta.l3_offset && meta.l4_offset as usize == parsed_l4 {
        meta.l4_offset as usize
    } else {
        parsed_l4
    };
    if frame.len() < l4 {
        return None;
    }
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        frame[l3 + 12],
        frame[l3 + 13],
        frame[l3 + 14],
        frame[l3 + 15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        frame[l3 + 16],
        frame[l3 + 17],
        frame[l3 + 18],
        frame[l3 + 19],
    ));
    let (src_port, dst_port) = parse_flow_ports(frame, l4, protocol)?;
    Some(SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: meta.addr_family,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        },
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn parse_zone_encoded_fabric_ingress(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> Option<u16> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    parse_zone_encoded_fabric_ingress_from_frame(frame, meta, forwarding)
}

/// #919/#922: returns the encoded zone ID (u8 → u16) directly, no
/// `zone_id_to_name` lookup or `String` clone. Callers that need a
/// name resolve via `forwarding.zone_id_to_name` on the slow path.
pub(in crate::afxdp) fn parse_zone_encoded_fabric_ingress_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> Option<u16> {
    if !ingress_is_fabric(forwarding, meta.ingress_ifindex as i32) {
        return None;
    }
    if frame.len() < 12 {
        return None;
    }
    if frame[6] != 0x02
        || frame[7] != 0xbf
        || frame[8] != 0x72
        || frame[9] != FABRIC_ZONE_MAC_MAGIC
        || frame[10] != 0x00
    {
        return None;
    }
    let id = frame[11] as u16;
    if id == 0 {
        return None;
    }
    // Validate the encoded ID exists in the configured zone map; an
    // unknown id is a stale or hostile frame. Single hash lookup —
    // the value isn't needed, just presence.
    forwarding.zone_id_to_name.get(&id).map(|_| id)
}

pub(in crate::afxdp) fn parse_packet_destination_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<IpAddr> {
    let l3 = meta.l3_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            let end = l3.checked_add(20)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 16],
                frame[l3 + 17],
                frame[l3 + 18],
                frame[l3 + 19],
            )))
        }
        libc::AF_INET6 => {
            let end = l3.checked_add(40)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            )))
        }
        _ => None,
    }
}

pub(in crate::afxdp) fn try_parse_metadata(area: &MmapArea, desc: XdpDesc) -> Option<UserspaceDpMeta> {
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    if (desc.addr as usize) < meta_len {
        return None;
    }
    let meta_offset = (desc.addr as usize).checked_sub(meta_len)?;
    let bytes = area.slice(meta_offset, meta_len)?;
    // ptr::read_unaligned: bytes is &[u8] with no alignment guarantee;
    // dereferencing as *const UserspaceDpMeta directly would be UB on
    // architectures that fault on misaligned loads (the x86 host happens
    // to tolerate it but it's still UB and a portability footgun).
    let meta = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const UserspaceDpMeta) };
    if meta.magic != USERSPACE_META_MAGIC || meta.version != USERSPACE_META_VERSION {
        return None;
    }
    if meta.length as usize != meta_len {
        return None;
    }
    Some(meta)
}
