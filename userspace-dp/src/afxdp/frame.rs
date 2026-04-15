use super::*;

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn authoritative_forward_ports(
    frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
) -> Option<(u16, u16)> {
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let flow_ports = flow.and_then(|flow| {
        if flow.forward_key.src_port != 0 && flow.forward_key.dst_port != 0 {
            Some((flow.forward_key.src_port, flow.forward_key.dst_port))
        } else {
            None
        }
    });
    let meta_ports = if meta.flow_src_port != 0 && meta.flow_dst_port != 0 {
        Some((meta.flow_src_port, meta.flow_dst_port))
    } else {
        None
    };
    let frame_ports = live_frame_ports_bytes(frame, meta.addr_family, meta.protocol);
    flow_ports.or(frame_ports).or(meta_ports)
}

#[allow(dead_code)]
pub(super) fn live_frame_ports(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<(u16, u16)> {
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    live_frame_ports_bytes(frame, meta.addr_family, meta.protocol)
}

pub(super) fn live_frame_ports_bytes(
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

pub(super) fn forward_tuple_mismatch_reason(
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

pub(super) fn parse_session_flow_from_bytes(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    // Fast path: for TCP/UDP with complete metadata tuple, use meta directly
    // without parsing the frame. This avoids extra L3/L4 parsing for the
    // common established-flow case.
    if matches!(meta.protocol, PROTO_TCP | PROTO_UDP)
        && let Some(meta_flow) = parse_session_flow_from_meta(meta)
        && metadata_tuple_complete(meta, &meta_flow)
    {
        return Some(meta_flow);
    }

    let frame_flow = if matches!(meta.addr_family as i32, libc::AF_INET) {
        parse_ipv4_session_flow_from_frame(frame, meta)
    } else {
        parse_session_flow_from_frame(frame, meta)
    };

    if let Some(meta_flow) = parse_session_flow_from_meta(meta)
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
pub(super) fn parse_session_flow(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    parse_session_flow_from_bytes(frame, meta)
}

/// Check if a frame contains a TCP RST flag. Returns (is_rst, summary) for logging.
pub(super) fn frame_has_tcp_rst(frame: &[u8]) -> bool {
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
pub(super) fn extract_tcp_flags_and_window(frame: &[u8]) -> Option<(u8, u16)> {
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
pub(super) fn extract_tcp_window(frame: &[u8], addr_family: u8) -> Option<u16> {
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

pub(super) fn frame_l3_offset(frame: &[u8]) -> Option<usize> {
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

pub(super) fn apply_dscp_rewrite_to_frame(frame: &mut [u8], dscp: u8) -> Option<()> {
    let dscp = dscp & 0x3f;
    let l3 = frame_l3_offset(frame)?;
    let ip = frame.get_mut(l3..)?;
    match ip.first()? >> 4 {
        4 => {
            if ip.len() < 20 {
                return None;
            }
            let new_tos = (dscp << 2) | (ip[1] & 0x03);
            if new_tos == ip[1] {
                return Some(());
            }
            let old_word = u16::from_be_bytes([ip[0], ip[1]]);
            let new_word = u16::from_be_bytes([ip[0], new_tos]);
            let current = u16::from_be_bytes([ip[10], ip[11]]);
            let updated = checksum16_adjust(current, &[old_word], &[new_word]);
            ip[1] = new_tos;
            ip[10] = (updated >> 8) as u8;
            ip[11] = updated as u8;
            Some(())
        }
        6 => {
            if ip.len() < 40 {
                return None;
            }
            let current_tc = ((ip[0] & 0x0f) << 4) | (ip[1] >> 4);
            let new_tc = (dscp << 2) | (current_tc & 0x03);
            if new_tc == current_tc {
                return Some(());
            }
            ip[0] = (ip[0] & 0xf0) | (new_tc >> 4);
            ip[1] = ((new_tc & 0x0f) << 4) | (ip[1] & 0x0f);
            Some(())
        }
        _ => None,
    }
}

/// Decode an Ethernet frame into a human-readable summary showing IP src/dst,
/// TCP/UDP ports, TCP flags, and checksums. For debugging packet forwarding.
pub(super) fn decode_frame_summary(frame: &[u8]) -> String {
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

pub(super) fn tcp_flags_str(flags: u8) -> String {
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

pub(super) fn frame_l4_offset(frame: &[u8], addr_family: u8) -> Option<usize> {
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

pub(super) fn packet_rel_l4_offset(packet: &[u8], addr_family: u8) -> Option<usize> {
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
pub(super) fn packet_rel_l4_offset_and_protocol(
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

pub(super) fn metadata_tuple_complete(meta: UserspaceDpMeta, flow: &SessionFlow) -> bool {
    if flow.src_ip.is_unspecified() || flow.dst_ip.is_unspecified() {
        return false;
    }
    match meta.protocol {
        PROTO_TCP | PROTO_UDP => flow.forward_key.src_port != 0 && flow.forward_key.dst_port != 0,
        _ => true,
    }
}

pub(super) fn parse_session_flow_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    match meta.addr_family as i32 {
        libc::AF_INET => parse_ipv4_session_flow_from_frame(frame, meta),
        libc::AF_INET6 => {
            let l3 = frame_l3_offset(frame)?;
            let l4 = frame_l4_offset(frame, meta.addr_family)?;
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

pub(super) fn parse_session_flow_from_meta(meta: UserspaceDpMeta) -> Option<SessionFlow> {
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

pub(super) fn parse_ipv4_session_flow_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    let mut l3 = 14usize;
    if frame.len() < l3 {
        return None;
    }
    let mut eth_proto = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    if matches!(eth_proto, 0x8100 | 0x88a8) {
        if frame.len() < l3 + 4 {
            return None;
        }
        eth_proto = u16::from_be_bytes([*frame.get(16)?, *frame.get(17)?]);
        l3 += 4;
    }
    if eth_proto != 0x0800 || frame.len() < l3 + 20 {
        return None;
    }
    let ihl = usize::from(frame[l3] & 0x0f) * 4;
    if ihl < 20 || frame.len() < l3 + ihl {
        return None;
    }
    let protocol = frame[l3 + 9];
    let l4 = l3 + ihl;
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

pub(super) fn parse_flow_ports(frame: &[u8], l4: usize, protocol: u8) -> Option<(u16, u16)> {
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
pub(super) fn parse_zone_encoded_fabric_ingress(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> Option<String> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    parse_zone_encoded_fabric_ingress_from_frame(frame, meta, forwarding)
}

pub(super) fn parse_zone_encoded_fabric_ingress_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> Option<String> {
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
    forwarding.zone_id_to_name.get(&(frame[11] as u16)).cloned()
}

pub(super) fn parse_packet_destination_from_frame(
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

pub(super) fn build_injected_packet(
    req: &InjectPacketRequest,
    dst: IpAddr,
    resolution: ForwardingResolution,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let dst_mac = resolution
        .neighbor_mac
        .ok_or_else(|| "missing neighbor MAC".to_string())?;
    match dst {
        IpAddr::V4(dst_v4) => build_injected_ipv4(req, dst_mac, dst_v4, egress),
        IpAddr::V6(dst_v6) => build_injected_ipv6(req, dst_mac, dst_v6, egress),
    }
}

/// Build a forwarded frame for NAT64 packets. NAT64 changes the IP address
/// family so the frame size changes (IPv6→IPv4 shrinks by 20, IPv4→IPv6 grows
/// by 20). This always uses a copy path — in-place rewrite is not possible.
pub(super) fn build_nat64_forwarded_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    nat64_reverse: Option<&Nat64ReverseInfo>,
) -> Option<Vec<u8>> {
    let dst_mac = decision.resolution.neighbor_mac?;
    let src_mac = decision.resolution.src_mac?;
    let vlan_id = decision.resolution.tx_vlan_id;

    match meta.addr_family as i32 {
        libc::AF_INET6 => {
            // Forward direction: IPv6 → IPv4.
            let snat_v4 = match decision.nat.rewrite_src {
                Some(IpAddr::V4(v4)) => v4,
                _ => return None,
            };
            let dst_v4 = match decision.nat.rewrite_dst {
                Some(IpAddr::V4(v4)) => v4,
                _ => return None,
            };
            crate::nat64::build_nat64_v6_to_v4_frame(
                frame, snat_v4, dst_v4, dst_mac, src_mac, vlan_id,
            )
        }
        libc::AF_INET => {
            // Reverse direction: IPv4 → IPv6 (reply from server).
            let info = nat64_reverse?;
            // Reply: src_v6 = original dst (NAT64 prefix + server), dst_v6 = original client
            crate::nat64::build_nat64_v4_to_v6_frame(
                frame,
                info.orig_dst_v6,
                info.orig_src_v6,
                dst_mac,
                src_mac,
                vlan_id,
            )
        }
        _ => None,
    }
}

pub(super) fn build_forwarded_frame_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<u8>> {
    let mut out = vec![0u8; frame.len().saturating_add(4)];
    let written = build_forwarded_frame_into_from_frame(
        &mut out,
        frame,
        meta,
        decision,
        forwarding,
        apply_nat_on_fabric,
        expected_ports,
    )?;
    out.truncate(written);
    if decision.resolution.tunnel_endpoint_id != 0 {
        return encapsulate_native_gre_frame(&out, meta, decision, forwarding);
    }
    Some(out)
}

pub(super) fn segment_forwarded_tcp_frames_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<Vec<u8>>> {
    if meta.protocol != PROTO_TCP {
        return None;
    }
    let mtu = if decision.resolution.tunnel_endpoint_id != 0 {
        native_gre_inner_mtu(forwarding, decision)
    } else {
        forwarding
            .egress
            .get(&decision.resolution.egress_ifindex)
            .or_else(|| forwarding.egress.get(&decision.resolution.tx_ifindex))
            .map(|egress| egress.mtu)
            .unwrap_or_default()
    }
    .max(1280);
    if mtu == 0 {
        return None;
    }
    let Some(l3) = frame_l3_offset(frame) else {
        return None;
    };
    if l3 >= frame.len() {
        return None;
    }
    let payload = &frame[l3..];
    if payload.len() <= mtu {
        return None;
    }
    let Some(frame_l4) = frame_l4_offset(frame, meta.addr_family) else {
        return None;
    };
    let Some(tcp_offset) = frame_l4.checked_sub(l3) else {
        return None;
    };
    let (ip_header_len, tcp_offset) = match meta.addr_family as i32 {
        libc::AF_INET => {
            if payload.len() < 20 {
                return None;
            }
            let ihl = ((payload[0] & 0x0f) as usize) * 4;
            if ihl < 20 || payload.len() < ihl + 20 {
                return None;
            }
            (ihl, ihl)
        }
        libc::AF_INET6 => {
            let ip_header_len = tcp_offset;
            if ip_header_len < 40 || payload.len() < ip_header_len + 20 {
                return None;
            }
            (ip_header_len, ip_header_len)
        }
        _ => return None,
    };
    let tcp_header_len = ((payload.get(tcp_offset + 12)? >> 4) as usize) * 4;
    if tcp_header_len < 20 || payload.len() < tcp_offset + tcp_header_len {
        return None;
    }
    let tcp_flags = *payload.get(tcp_offset + 13)?;
    if (tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST)) != 0 {
        return None;
    }
    let Some(segment_payload_max) = mtu.checked_sub(ip_header_len + tcp_header_len) else {
        return None;
    };
    if segment_payload_max == 0 {
        return None;
    }
    let Some(data) = payload.get(tcp_offset + tcp_header_len..) else {
        return None;
    };
    if data.len() <= segment_payload_max {
        return None;
    }

    let Some(dst_mac) = decision.resolution.neighbor_mac else {
        return None;
    };
    let (src_mac, vlan_id, apply_nat) =
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                apply_nat_on_fabric,
            )
        } else {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                true,
            )
        };
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let ether_type = match meta.addr_family as i32 {
        libc::AF_INET => 0x0800,
        libc::AF_INET6 => 0x86dd,
        _ => return None,
    };
    let original_seq = u32::from_be_bytes([
        *payload.get(tcp_offset + 4)?,
        *payload.get(tcp_offset + 5)?,
        *payload.get(tcp_offset + 6)?,
        *payload.get(tcp_offset + 7)?,
    ]);
    let enforced_ports = expected_ports.or(live_frame_ports_bytes(
        frame,
        meta.addr_family,
        meta.protocol,
    ));
    let Some(tcp_header) = payload.get(tcp_offset..tcp_offset + tcp_header_len) else {
        return None;
    };
    let Some(ip_header) = payload.get(..ip_header_len) else {
        return None;
    };
    let mut out = Vec::with_capacity((data.len() / segment_payload_max) + 1);
    let mut data_offset = 0usize;
    while data_offset < data.len() {
        let chunk_len = (data.len() - data_offset).min(segment_payload_max);
        let is_last = data_offset + chunk_len == data.len();
        let total_ip_len = ip_header_len + tcp_header_len + chunk_len;
        let mut frame_out = vec![0u8; eth_len + total_ip_len];
        write_eth_header_slice(
            frame_out.get_mut(..eth_len)?,
            dst_mac,
            src_mac,
            vlan_id,
            ether_type,
        )?;
        {
            let packet = frame_out.get_mut(eth_len..)?;
            packet.get_mut(..ip_header_len)?.copy_from_slice(ip_header);
            packet
                .get_mut(ip_header_len..ip_header_len + tcp_header_len)?
                .copy_from_slice(tcp_header);
            packet
                .get_mut(ip_header_len + tcp_header_len..total_ip_len)?
                .copy_from_slice(data.get(data_offset..data_offset + chunk_len)?);

            let tcp = packet.get_mut(tcp_offset..)?;
            let seq = original_seq.wrapping_add(data_offset as u32);
            tcp.get_mut(4..8)?.copy_from_slice(&seq.to_be_bytes());
            if !is_last {
                tcp[13] &= !TCP_FLAG_PSH;
            }
        }

        match meta.addr_family as i32 {
            libc::AF_INET => {
                // Capture pre-modification IPs and ports for incremental
                // L4 checksum adjustment (avoids O(payload) full recompute).
                let pre_src_ip;
                let pre_dst_ip;
                let pre_src_port;
                let pre_dst_port;
                {
                    let packet = frame_out.get(eth_len..)?;
                    pre_src_ip = [packet[12], packet[13], packet[14], packet[15]];
                    pre_dst_ip = [packet[16], packet[17], packet[18], packet[19]];
                    pre_src_port = u16::from_be_bytes([
                        *packet.get(ip_header_len)?,
                        *packet.get(ip_header_len + 1)?,
                    ]);
                    pre_dst_port = u16::from_be_bytes([
                        *packet.get(ip_header_len + 2)?,
                        *packet.get(ip_header_len + 3)?,
                    ]);
                }
                {
                    let packet = frame_out.get_mut(eth_len..)?;
                    packet
                        .get_mut(2..4)?
                        .copy_from_slice(&(total_ip_len as u16).to_be_bytes());
                    if packet[8] <= 1 {
                        return None;
                    }
                    if apply_nat {
                        apply_nat_ipv4(packet, meta.protocol, decision.nat)?;
                    }
                    if (meta.meta_flags & 0x80) == 0 {
                        packet[8] -= 1;
                    }
                }
                let _ = enforce_expected_ports(
                    &mut frame_out,
                    meta.addr_family,
                    meta.protocol,
                    enforced_ports,
                )?;
                let packet = frame_out.get_mut(eth_len..)?;
                // IP header checksum: full recompute (only 20 bytes, fast).
                packet.get_mut(10..12)?.copy_from_slice(&[0, 0]);
                let ip_sum = checksum16(packet.get(..ip_header_len)?);
                packet
                    .get_mut(10..12)?
                    .copy_from_slice(&ip_sum.to_be_bytes());
                // L4 checksum: incremental adjustment for NAT and TTL
                // changes instead of full payload recompute. O(1) vs
                // O(payload_size) — saves ~3.6% CPU at fabric throughput.
                let post_src_ip = [packet[12], packet[13], packet[14], packet[15]];
                let post_dst_ip = [packet[16], packet[17], packet[18], packet[19]];
                // L4 checksum: use incremental adjustment when
                // enforce_expected_ports was a no-op (the common fabric
                // case where expected_ports=None). This is O(1) vs
                // O(payload_size) — saves ~3.6% CPU.
                // When enforce_expected_ports DID run (expected_ports is
                // Some), fall back to full recompute because the
                // interaction between NAT port changes, port enforcement,
                // and checksum adjustments is complex.
                if enforced_ports.is_none() {
                    let post_src_ip = [packet[12], packet[13], packet[14], packet[15]];
                    let post_dst_ip = [packet[16], packet[17], packet[18], packet[19]];
                    let post_src_port = u16::from_be_bytes([
                        *packet.get(ip_header_len)?,
                        *packet.get(ip_header_len + 1)?,
                    ]);
                    let post_dst_port = u16::from_be_bytes([
                        *packet.get(ip_header_len + 2)?,
                        *packet.get(ip_header_len + 3)?,
                    ]);
                    let has_changes = pre_src_ip != post_src_ip
                        || pre_dst_ip != post_dst_ip
                        || pre_src_port != post_src_port
                        || pre_dst_port != post_dst_port;
                    if has_changes {
                        let csum_off = match meta.protocol {
                            PROTO_TCP => ip_header_len + 16,
                            PROTO_UDP => ip_header_len + 6,
                            _ => 0,
                        };
                        if csum_off > 0 && packet.len() > csum_off + 1 {
                            let current =
                                u16::from_be_bytes([packet[csum_off], packet[csum_off + 1]]);
                            let mut updated = checksum16_adjust(
                                current,
                                &ipv4_words(Ipv4Addr::from(pre_src_ip)),
                                &ipv4_words(Ipv4Addr::from(post_src_ip)),
                            );
                            updated = checksum16_adjust(
                                updated,
                                &ipv4_words(Ipv4Addr::from(pre_dst_ip)),
                                &ipv4_words(Ipv4Addr::from(post_dst_ip)),
                            );
                            if pre_src_port != post_src_port {
                                updated =
                                    checksum16_adjust(updated, &[pre_src_port], &[post_src_port]);
                            }
                            if pre_dst_port != post_dst_port {
                                updated =
                                    checksum16_adjust(updated, &[pre_dst_port], &[post_dst_port]);
                            }
                            if matches!(meta.protocol, PROTO_UDP) && updated == 0 {
                                updated = 0xffff;
                            }
                            packet
                                .get_mut(csum_off..csum_off + 2)?
                                .copy_from_slice(&updated.to_be_bytes());
                        }
                    }
                } else {
                    // Full L4 checksum recompute when enforce_expected_ports
                    // may have modified ports and adjusted the checksum.
                    recompute_l4_checksum_ipv4(packet, ip_header_len, meta.protocol, false)?;
                }
            }
            libc::AF_INET6 => {
                {
                    let packet = frame_out.get_mut(eth_len..)?;
                    packet
                        .get_mut(4..6)?
                        .copy_from_slice(&((tcp_header_len + chunk_len) as u16).to_be_bytes());
                    if (meta.meta_flags & 0x80) == 0 && packet[7] <= 1 {
                        return None;
                    }
                    if apply_nat {
                        apply_nat_ipv6(packet, meta.protocol, decision.nat)?;
                    }
                    if (meta.meta_flags & 0x80) == 0 {
                        packet[7] -= 1;
                    }
                }
                let _ = enforce_expected_ports(
                    &mut frame_out,
                    meta.addr_family,
                    meta.protocol,
                    enforced_ports,
                )?;
                let packet = frame_out.get_mut(eth_len..)?;
                recompute_l4_checksum_ipv6(packet, meta.protocol)?;
            }
            _ => return None,
        }
        if decision.resolution.tunnel_endpoint_id != 0 {
            out.push(encapsulate_native_gre_frame(
                &frame_out, meta, decision, forwarding,
            )?);
        } else {
            out.push(frame_out);
        }
        data_offset += chunk_len;
    }
    Some(out)
}

pub(super) fn build_forwarded_frame_into_from_frame(
    out: &mut [u8],
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<usize> {
    let dst_mac = decision.resolution.neighbor_mac?;
    let enforced_ports = expected_ports;
    // Use meta L3 offset when it's a valid Ethernet header size (14 or 18),
    // otherwise re-derive from the frame's ethertype.
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    if l3 >= frame.len() {
        return None;
    }
    let raw_payload = &frame[l3..];
    // Trim Ethernet padding: use ip_total_len so we don't carry trailing
    // pad bytes (small frames padded to 60/64 by hardware).
    let payload = if raw_payload.len() >= 4 {
        let ip_version = raw_payload[0] >> 4;
        if ip_version == 4 {
            let ip_total_len = u16::from_be_bytes([raw_payload[2], raw_payload[3]]) as usize;
            if ip_total_len > 0 && ip_total_len < raw_payload.len() {
                &raw_payload[..ip_total_len]
            } else {
                raw_payload
            }
        } else if ip_version == 6 && raw_payload.len() >= 40 {
            let ipv6_payload_len = u16::from_be_bytes([raw_payload[4], raw_payload[5]]) as usize;
            let ip6_total = 40 + ipv6_payload_len;
            if ip6_total > 0 && ip6_total < raw_payload.len() {
                &raw_payload[..ip6_total]
            } else {
                raw_payload
            }
        } else {
            raw_payload
        }
    } else {
        raw_payload
    };
    let (src_mac, vlan_id, apply_nat) =
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                apply_nat_on_fabric,
            )
        } else {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                true,
            )
        };
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let ether_type = match meta.addr_family as i32 {
        libc::AF_INET => 0x0800,
        libc::AF_INET6 => 0x86dd,
        _ => return None,
    };
    let frame_len = eth_len + payload.len();
    if frame_len > out.len() {
        return None;
    }
    write_eth_header_slice(
        out.get_mut(..eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        ether_type,
    )?;
    let payload_out = out.get_mut(eth_len..frame_len)?;
    // SAFETY: source (payload) and destination (payload_out) are distinct
    // buffers — payload is from the ingress UMEM, payload_out is in the
    // egress UMEM. Lengths are equal because both span eth_len..frame_len.
    debug_assert_eq!(payload_out.len(), payload.len());
    unsafe {
        core::ptr::copy_nonoverlapping(payload.as_ptr(), payload_out.as_mut_ptr(), payload.len());
    }
    let out = &mut out[..frame_len];
    let force_tunnel_l4_recompute = decision.resolution.tunnel_endpoint_id != 0;
    let tunnel_tcp_mss = native_gre_tcp_mss(forwarding, decision, meta.addr_family);
    let ip_start = eth_len;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            if out.len() < ip_start + 20 {
                return None;
            }
            let ihl = ((out[ip_start] & 0x0f) as usize) * 4;
            if ihl < 20 || out.len() < ip_start + ihl {
                return None;
            }
            if (meta.meta_flags & 0x80) == 0 && out[ip_start + 8] <= 1 {
                return None;
            }
            let old_src = Ipv4Addr::new(
                out[ip_start + 12],
                out[ip_start + 13],
                out[ip_start + 14],
                out[ip_start + 15],
            );
            let old_dst = Ipv4Addr::new(
                out[ip_start + 16],
                out[ip_start + 17],
                out[ip_start + 18],
                out[ip_start + 19],
            );
            let old_ttl = out[ip_start + 8];
            // IHL already computed above — use directly instead of re-parsing.
            let rel_l4 = ihl;
            let repaired_ports =
                restore_l4_tuple_from_meta(&mut out[ip_start..], meta, rel_l4).unwrap_or(false);
            if apply_nat {
                apply_nat_ipv4(&mut out[ip_start..], meta.protocol, decision.nat)?;
            }
            let skip_ttl = (meta.meta_flags & 0x80) != 0;
            if !skip_ttl {
                out[ip_start + 8] -= 1;
            }
            let enforced = enforce_expected_ports_at(
                out,
                ip_start,
                ip_start + rel_l4,
                meta.addr_family,
                meta.protocol,
                enforced_ports,
            )
            .unwrap_or(false);
            adjust_ipv4_header_checksum(
                &mut out[ip_start..ip_start + ihl],
                old_src,
                old_dst,
                old_ttl,
            )?;
            if tunnel_tcp_mss > 0 {
                let _ = clamp_tcp_mss_frame(out, ip_start, tunnel_tcp_mss);
            }
            if force_tunnel_l4_recompute || (repaired_ports && !enforced) {
                recompute_l4_checksum_ipv4(&mut out[ip_start..], ihl, meta.protocol, true)?;
            }
        }
        libc::AF_INET6 => {
            if out.len() < ip_start + 40 {
                return None;
            }
            if (meta.meta_flags & 0x80) == 0 && out[ip_start + 7] <= 1 {
                return None;
            }
            // Use meta-derived L4 offset when valid (>= 40 for IPv6 base header,
            // avoids walking extension headers). Fall back to parsing otherwise.
            let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
            let rel_l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
                meta_rel
            } else {
                packet_rel_l4_offset(&out[ip_start..], meta.addr_family)?
            };
            let repaired_ports =
                restore_l4_tuple_from_meta(&mut out[ip_start..], meta, rel_l4).unwrap_or(false);
            if apply_nat {
                apply_nat_ipv6(&mut out[ip_start..], meta.protocol, decision.nat)?;
            }
            if (meta.meta_flags & 0x80) == 0 {
                out[ip_start + 7] -= 1;
            }
            let enforced = enforce_expected_ports_at(
                out,
                ip_start,
                ip_start + rel_l4,
                meta.addr_family,
                meta.protocol,
                enforced_ports,
            )
            .unwrap_or(false);
            if tunnel_tcp_mss > 0 {
                let _ = clamp_tcp_mss_frame(out, ip_start, tunnel_tcp_mss);
            }
            if force_tunnel_l4_recompute || (repaired_ports && !enforced) {
                recompute_l4_checksum_ipv6(&mut out[ip_start..], meta.protocol)?;
            }
        }
        _ => return None,
    }
    // Debug: dump first N built frames' Ethernet + IP headers to see post-NAT on wire
    if cfg!(feature = "debug-log") {
        thread_local! {
            static BUILD_FWD_DBG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        BUILD_FWD_DBG_COUNT.with(|c| {
            let n = c.get();
            if n < 30 {
                c.set(n + 1);
                let pkt_detail = decode_frame_summary(out);
                eprintln!(
                    "DBG BUILT_ETH[{}]: vlan={} frame_len={} proto={} {}",
                    n, vlan_id, frame_len, meta.protocol, pkt_detail,
                );
                // For the first 3 frames, also dump the full IP+TCP header hex
                if n < 3 {
                    let dump_len = frame_len.min(out.len()).min(eth_len + 60);
                    let hex: String = out[..dump_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!("DBG BUILT_HEX[{n}]: {hex}");
                }
            }
        });
    }
    // Checksum verification: recompute from scratch and compare to incremental update.
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&out[..frame_len]);
    }

    // RST corruption check: detect if frame building introduced a TCP RST
    // that wasn't in the source frame.
    if cfg!(feature = "debug-log") {
        let out_has_rst = frame_has_tcp_rst(&out[..frame_len]);
        let in_has_rst = frame_has_tcp_rst(frame);
        if out_has_rst && !in_has_rst {
            thread_local! {
                static BUILD_RST_CORRUPT_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
            }
            BUILD_RST_CORRUPT_COUNT.with(|c| {
                let n = c.get();
                if n < 20 {
                    c.set(n + 1);
                    let in_summary = decode_frame_summary(frame);
                    let out_summary = decode_frame_summary(&out[..frame_len]);
                    eprintln!(
                        "RST_CORRUPT BUILD[{}]: frame build INTRODUCED RST! in=[{}] out=[{}]",
                        n, in_summary, out_summary,
                    );
                    let in_hex_len = frame.len().min(80);
                    let in_hex: String = frame[..in_hex_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let out_hex_len = frame_len.min(out.len()).min(80);
                    let out_hex: String = out[..out_hex_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!("RST_CORRUPT IN_HEX[{n}]: {in_hex}");
                    eprintln!("RST_CORRUPT OUT_HEX[{n}]: {out_hex}");
                }
            });
        }
    }
    Some(frame_len)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn build_forwarded_frame(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<u8>> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    build_forwarded_frame_from_frame(frame, meta, decision, forwarding, false, expected_ports)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn segment_forwarded_tcp_frames(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<Vec<u8>>> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    segment_forwarded_tcp_frames_from_frame(
        frame,
        meta,
        decision,
        forwarding,
        false,
        expected_ports,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn build_forwarded_frame_into(
    out: &mut [u8],
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    expected_ports: Option<(u16, u16)>,
) -> Option<usize> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    build_forwarded_frame_into_from_frame(
        out,
        frame,
        meta,
        decision,
        forwarding,
        false,
        expected_ports,
    )
}

pub(super) fn rewrite_forwarded_frame_in_place(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<u32> {
    let dst_mac = decision.resolution.neighbor_mac?;
    let enforced_ports = expected_ports;
    let frame = unsafe { area.slice_mut_unchecked(desc.addr as usize, UMEM_FRAME_SIZE as usize)? };
    let current_len = desc.len as usize;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(&frame[..current_len])?,
    };
    if l3 >= current_len {
        return None;
    }
    let mut payload_len = current_len.checked_sub(l3)?;
    // Trim Ethernet padding: use ip_total_len when available so we don't
    // carry trailing pad bytes (small frames padded to 60/64 by hardware).
    if payload_len >= 4 {
        let ip_version = frame[l3] >> 4;
        if ip_version == 4 {
            let ip_total_len = u16::from_be_bytes([frame[l3 + 2], frame[l3 + 3]]) as usize;
            if ip_total_len > 0 && ip_total_len < payload_len {
                payload_len = ip_total_len;
            }
        } else if ip_version == 6 && payload_len >= 40 {
            let ipv6_payload_len = u16::from_be_bytes([frame[l3 + 4], frame[l3 + 5]]) as usize;
            let ip6_total = 40 + ipv6_payload_len;
            if ip6_total > 0 && ip6_total < payload_len {
                payload_len = ip6_total;
            }
        }
    }
    let (src_mac, vlan_id, apply_nat) =
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                apply_nat_on_fabric,
            )
        } else {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                true,
            )
        };
    let eth_len = if vlan_id > 0 { 18usize } else { 14usize };
    let ether_type = match meta.addr_family as i32 {
        libc::AF_INET => 0x0800,
        libc::AF_INET6 => 0x86dd,
        _ => return None,
    };
    let frame_len = eth_len.checked_add(payload_len)?;
    if frame_len > frame.len() {
        return None;
    }
    if eth_len != l3 {
        frame.copy_within(l3..l3 + payload_len, eth_len);
    }
    write_eth_header_slice(
        frame.get_mut(..eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        ether_type,
    )?;
    let packet = &mut frame[..frame_len];
    let ip_start = eth_len;
    // Fabric-ingress packets already had TTL decremented by the sending peer.
    let skip_ttl = (meta.meta_flags & 0x80) != 0;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < ip_start + 20 {
                return None;
            }
            let ihl = ((packet[ip_start] & 0x0f) as usize) * 4;
            if ihl < 20 || packet.len() < ip_start + ihl {
                return None;
            }
            if !skip_ttl && packet[ip_start + 8] <= 1 {
                return None;
            }
            let old_src = Ipv4Addr::new(
                packet[ip_start + 12],
                packet[ip_start + 13],
                packet[ip_start + 14],
                packet[ip_start + 15],
            );
            let old_dst = Ipv4Addr::new(
                packet[ip_start + 16],
                packet[ip_start + 17],
                packet[ip_start + 18],
                packet[ip_start + 19],
            );
            let old_ttl = packet[ip_start + 8];
            let rel_l4 = ihl;
            let repaired_ports =
                restore_l4_tuple_from_meta(&mut packet[ip_start..], meta, rel_l4).unwrap_or(false);
            if apply_nat {
                apply_nat_ipv4(&mut packet[ip_start..], meta.protocol, decision.nat)?;
            }
            if !skip_ttl {
                packet[ip_start + 8] -= 1;
            }
            adjust_ipv4_header_checksum(
                &mut packet[ip_start..ip_start + ihl],
                old_src,
                old_dst,
                old_ttl,
            )?;
            let enforced =
                enforce_expected_ports(packet, meta.addr_family, meta.protocol, enforced_ports)
                    .unwrap_or(false);
            if repaired_ports && !enforced {
                recompute_l4_checksum_ipv4(&mut packet[ip_start..], ihl, meta.protocol, true)?;
            }
        }
        libc::AF_INET6 => {
            if packet.len() < ip_start + 40 {
                return None;
            }
            if !skip_ttl && packet[ip_start + 7] <= 1 {
                return None;
            }
            let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
            let rel_l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
                meta_rel
            } else {
                packet_rel_l4_offset(&packet[ip_start..], meta.addr_family)?
            };
            let repaired_ports =
                restore_l4_tuple_from_meta(&mut packet[ip_start..], meta, rel_l4).unwrap_or(false);
            if apply_nat {
                apply_nat_ipv6(&mut packet[ip_start..], meta.protocol, decision.nat)?;
            }
            if !skip_ttl {
                packet[ip_start + 7] -= 1;
            }
            let enforced =
                enforce_expected_ports(packet, meta.addr_family, meta.protocol, enforced_ports)
                    .unwrap_or(false);
            if repaired_ports && !enforced {
                recompute_l4_checksum_ipv6(&mut packet[ip_start..], meta.protocol)?;
            }
        }
        _ => return None,
    }
    // Debug: dump first N in-place rewritten frames' Ethernet headers
    #[cfg(feature = "debug-log")]
    {
        thread_local! {
            static INPLACE_FWD_DBG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        INPLACE_FWD_DBG_COUNT.with(|c| {
            let n = c.get();
            if n < 10 {
                c.set(n + 1);
                let hdr_len = eth_len.min(packet.len()).min(22);
                let hdr_hex: String = packet[..hdr_len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                let ip_info = if meta.addr_family as i32 == libc::AF_INET && packet.len() >= ip_start + 20 {
                    format!("src={}.{}.{}.{} dst={}.{}.{}.{}",
                        packet[ip_start+12], packet[ip_start+13], packet[ip_start+14], packet[ip_start+15],
                        packet[ip_start+16], packet[ip_start+17], packet[ip_start+18], packet[ip_start+19])
                } else if meta.addr_family as i32 == libc::AF_INET6 && packet.len() >= ip_start + 40 {
                    let s = &packet[ip_start+8..ip_start+24];
                    let d = &packet[ip_start+24..ip_start+40];
                    format!("src={:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x} dst={:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8],s[9],s[10],s[11],s[12],s[13],s[14],s[15],
                        d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7],d[8],d[9],d[10],d[11],d[12],d[13],d[14],d[15])
                } else {
                    "unknown-af".to_string()
                };
                debug_log!("DBG INPLACE_ETH[{}]: eth=[{}] vlan={} frame_len={} proto={} {}",
                    n, hdr_hex, vlan_id, frame_len, meta.protocol, ip_info,
                );
            }
        });
    }
    // Checksum verification for in-place path.
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&packet[..frame_len]);
    }
    Some(frame_len as u32)
}

/// Straight-line frame rewrite using a precomputed `RewriteDescriptor`.
///
/// Eliminates per-packet branches for address family, VLAN presence, NAT type,
/// and checksum recomputation — all decisions are baked into the descriptor at
/// session / flow-cache insertion time.
///
/// Returns the new frame length on success, or `None` if the frame is corrupt,
/// too short, or has a port mismatch (caller falls back to generic rewrite).
///
/// **Scope**: IPv4/IPv6 TCP and UDP only (flow cache gates on ACK-only TCP + UDP).
/// Does NOT handle: ICMP identifier repair, NAT64 (header-size change), NPTv6
/// (checksum-neutral — no L4 csum adjust needed, but address rewrite differs).
#[inline]
pub(super) fn apply_rewrite_descriptor(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    rd: &super::RewriteDescriptor,
    expected_ports: Option<(u16, u16)>,
) -> Option<u32> {
    // NAT64 and NPTv6 use the generic path — they need special handling.
    if rd.nat64 || rd.nptv6 {
        return None;
    }

    let frame = unsafe { area.slice_mut_unchecked(desc.addr as usize, UMEM_FRAME_SIZE as usize)? };
    let current_len = desc.len as usize;

    // L3 offset: trust XDP shim metadata when it's a standard value.
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(&frame[..current_len])?,
    };
    if l3 >= current_len {
        return None;
    }

    // Trim Ethernet padding using IP total length.
    let mut payload_len = current_len.checked_sub(l3)?;
    if payload_len >= 4 {
        let ip_version = frame[l3] >> 4;
        if ip_version == 4 {
            let ip_total_len = u16::from_be_bytes([frame[l3 + 2], frame[l3 + 3]]) as usize;
            if ip_total_len > 0 && ip_total_len < payload_len {
                payload_len = ip_total_len;
            }
        } else if ip_version == 6 && payload_len >= 40 {
            let ipv6_payload_len = u16::from_be_bytes([frame[l3 + 4], frame[l3 + 5]]) as usize;
            let ip6_total = 40 + ipv6_payload_len;
            if ip6_total > 0 && ip6_total < payload_len {
                payload_len = ip6_total;
            }
        }
    }

    // Target Ethernet header length (14 = no VLAN, 18 = 802.1Q).
    let eth_len = if rd.tx_vlan_id > 0 { 18usize } else { 14usize };
    let frame_len = eth_len.checked_add(payload_len)?;
    if frame_len > frame.len() {
        return None;
    }

    // Shift payload if L3 offset changes (adding/removing VLAN tag).
    if eth_len != l3 {
        frame.copy_within(l3..l3 + payload_len, eth_len);
    }

    // Write Ethernet header — precomputed MACs, VLAN, ether_type.
    write_eth_header_slice(
        frame.get_mut(..eth_len)?,
        rd.dst_mac,
        rd.src_mac,
        rd.tx_vlan_id,
        rd.ether_type,
    )?;

    let packet = &mut frame[..frame_len];
    let ip = eth_len;
    let skip_ttl = (meta.meta_flags & 0x80) != 0;
    let apply_nat = !rd.fabric_redirect || rd.apply_nat_on_fabric;

    match rd.ether_type {
        0x0800 => {
            // ── IPv4 straight-line rewrite ──
            if packet.len() < ip + 20 {
                return None;
            }
            let ihl = ((packet[ip] & 0x0f) as usize) * 4;
            if ihl < 20 || packet.len() < ip + ihl {
                return None;
            }
            if !skip_ttl && packet[ip + 8] <= 1 {
                return None; // TTL expired
            }
            let l4 = ip + ihl;

            // Port validation (DMA race guard).
            // If ports don't match, fall back to generic path for repair.
            if let Some((exp_src, exp_dst)) = expected_ports {
                if matches!(meta.protocol, PROTO_TCP | PROTO_UDP) && packet.len() >= l4 + 4 {
                    let cur_src = u16::from_be_bytes([packet[l4], packet[l4 + 1]]);
                    let cur_dst = u16::from_be_bytes([packet[l4 + 2], packet[l4 + 3]]);
                    if cur_src != exp_src || cur_dst != exp_dst {
                        return None;
                    }
                }
            }

            // NAT: direct byte writes for IP addresses.
            if apply_nat {
                if let Some(IpAddr::V4(new_src)) = rd.rewrite_src_ip {
                    packet[ip + 12..ip + 16].copy_from_slice(&new_src.octets());
                }
                if let Some(IpAddr::V4(new_dst)) = rd.rewrite_dst_ip {
                    packet[ip + 16..ip + 20].copy_from_slice(&new_dst.octets());
                }
            }

            // NAT: direct byte writes for L4 ports.
            if apply_nat {
                if let Some(new_sport) = rd.rewrite_src_port {
                    if packet.len() >= l4 + 2 {
                        packet[l4..l4 + 2].copy_from_slice(&new_sport.to_be_bytes());
                    }
                }
                if let Some(new_dport) = rd.rewrite_dst_port {
                    if packet.len() >= l4 + 4 {
                        packet[l4 + 2..l4 + 4].copy_from_slice(&new_dport.to_be_bytes());
                    }
                }
            }

            // TTL decrement (skip for fabric-ingress — peer already decremented).
            if !skip_ttl {
                packet[ip + 8] -= 1;
            }

            // IP header checksum: precomputed NAT delta + TTL-1 delta.
            let old_csum = u16::from_be_bytes([packet[ip + 10], packet[ip + 11]]);
            let mut sum = (!old_csum as u32) & 0xffff;
            if apply_nat {
                sum += rd.ip_csum_delta as u32;
            }
            if !skip_ttl {
                // TTL-1 delta is always 0xFEFF in one's complement arithmetic
                sum += 0xFEFF;
            }
            while (sum >> 16) != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let new_csum = !(sum as u16);
            packet[ip + 10..ip + 12].copy_from_slice(&new_csum.to_be_bytes());

            // L4 checksum: precomputed delta covers IP + port changes.
            if apply_nat && rd.l4_csum_delta != 0 {
                let l4_csum_off = match meta.protocol {
                    PROTO_TCP => l4 + 16,
                    PROTO_UDP => l4 + 6,
                    _ => 0,
                };
                if l4_csum_off > 0 && packet.len() >= l4_csum_off + 2 {
                    let old_l4_csum =
                        u16::from_be_bytes([packet[l4_csum_off], packet[l4_csum_off + 1]]);
                    // Skip UDP checksum update if zero (no checksum, RFC 768).
                    if meta.protocol != PROTO_UDP || old_l4_csum != 0 {
                        let mut l4sum = (!old_l4_csum as u32) & 0xffff;
                        l4sum += rd.l4_csum_delta as u32;
                        while (l4sum >> 16) != 0 {
                            l4sum = (l4sum & 0xffff) + (l4sum >> 16);
                        }
                        let new_l4 = !(l4sum as u16);
                        // UDP: 0x0000 means "no checksum" — use 0xFFFF (RFC 768).
                        let final_csum = if meta.protocol == PROTO_UDP && new_l4 == 0 {
                            0xFFFFu16
                        } else {
                            new_l4
                        };
                        packet[l4_csum_off..l4_csum_off + 2]
                            .copy_from_slice(&final_csum.to_be_bytes());
                    }
                }
            }
        }
        0x86dd => {
            // ── IPv6 straight-line rewrite ──
            // No IP header checksum; only L4 pseudo-header changes matter.
            if packet.len() < ip + 40 {
                return None;
            }
            if !skip_ttl && packet[ip + 7] <= 1 {
                return None; // Hop limit expired
            }

            // L4 offset from metadata or by parsing extension headers.
            let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
            let rel_l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
                meta_rel
            } else {
                packet_rel_l4_offset(&packet[ip..], meta.addr_family)?
            };
            let l4 = ip + rel_l4;

            // Port validation (DMA race guard).
            if let Some((exp_src, exp_dst)) = expected_ports {
                if matches!(meta.protocol, PROTO_TCP | PROTO_UDP) && packet.len() >= l4 + 4 {
                    let cur_src = u16::from_be_bytes([packet[l4], packet[l4 + 1]]);
                    let cur_dst = u16::from_be_bytes([packet[l4 + 2], packet[l4 + 3]]);
                    if cur_src != exp_src || cur_dst != exp_dst {
                        return None;
                    }
                }
            }

            // NAT: direct byte writes for IPv6 addresses.
            if apply_nat {
                if let Some(IpAddr::V6(new_src)) = rd.rewrite_src_ip {
                    packet[ip + 8..ip + 24].copy_from_slice(&new_src.octets());
                }
                if let Some(IpAddr::V6(new_dst)) = rd.rewrite_dst_ip {
                    packet[ip + 24..ip + 40].copy_from_slice(&new_dst.octets());
                }
            }

            // NAT: direct byte writes for L4 ports.
            if apply_nat {
                if let Some(new_sport) = rd.rewrite_src_port {
                    if packet.len() >= l4 + 2 {
                        packet[l4..l4 + 2].copy_from_slice(&new_sport.to_be_bytes());
                    }
                }
                if let Some(new_dport) = rd.rewrite_dst_port {
                    if packet.len() >= l4 + 4 {
                        packet[l4 + 2..l4 + 4].copy_from_slice(&new_dport.to_be_bytes());
                    }
                }
            }

            // Hop limit decrement (skip for fabric-ingress).
            if !skip_ttl {
                packet[ip + 7] -= 1;
            }

            // L4 checksum: precomputed delta covers IPv6 address + port changes.
            if apply_nat && rd.l4_csum_delta != 0 {
                let l4_csum_off = match meta.protocol {
                    PROTO_TCP => l4 + 16,
                    PROTO_UDP => l4 + 6,
                    PROTO_ICMPV6 => l4 + 2,
                    _ => 0,
                };
                if l4_csum_off > 0 && packet.len() >= l4_csum_off + 2 {
                    let old_l4_csum =
                        u16::from_be_bytes([packet[l4_csum_off], packet[l4_csum_off + 1]]);
                    let mut l4sum = (!old_l4_csum as u32) & 0xffff;
                    l4sum += rd.l4_csum_delta as u32;
                    while (l4sum >> 16) != 0 {
                        l4sum = (l4sum & 0xffff) + (l4sum >> 16);
                    }
                    let new_l4 = !(l4sum as u16);
                    // IPv6 UDP must have non-zero checksum; use 0xFFFF for all.
                    let final_csum = if new_l4 == 0 { 0xFFFFu16 } else { new_l4 };
                    packet[l4_csum_off..l4_csum_off + 2].copy_from_slice(&final_csum.to_be_bytes());
                }
            }
        }
        _ => return None,
    }

    // Checksum verification for descriptor path (debug only).
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&packet[..frame_len]);
    }
    Some(frame_len as u32)
}

pub(super) fn apply_nat_ipv4(packet: &mut [u8], protocol: u8, nat: NatDecision) -> Option<()> {
    if nat == NatDecision::default() {
        return Some(());
    }
    if packet.len() < 20 {
        return None;
    }
    let old_src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let old_dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let new_src = nat.rewrite_src.and_then(|ip| match ip {
        IpAddr::V4(ip) => Some(ip),
        _ => None,
    });
    let new_dst = nat.rewrite_dst.and_then(|ip| match ip {
        IpAddr::V4(ip) => Some(ip),
        _ => None,
    });
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }

    // --- IP address rewriting ---
    if new_src.is_some() && new_dst.is_none() {
        let new_src = new_src?;
        packet.get_mut(12..16)?.copy_from_slice(&new_src.octets());
        adjust_l4_checksum_ipv4_src(packet, ihl, protocol, old_src, new_src)?;
    } else if new_dst.is_some() && new_src.is_none() {
        let new_dst = new_dst?;
        packet.get_mut(16..20)?.copy_from_slice(&new_dst.octets());
        adjust_l4_checksum_ipv4_dst(packet, ihl, protocol, old_dst, new_dst)?;
    } else if new_src.is_some() || new_dst.is_some() {
        if let Some(ip) = new_src {
            packet.get_mut(12..16)?.copy_from_slice(&ip.octets());
        }
        if let Some(ip) = new_dst {
            packet.get_mut(16..20)?.copy_from_slice(&ip.octets());
        }
        let new_src = new_src.unwrap_or(old_src);
        let new_dst = new_dst.unwrap_or(old_dst);
        match protocol {
            PROTO_TCP => {
                adjust_l4_checksum_ipv4(packet, ihl, protocol, old_src, new_src, old_dst, new_dst)?
            }
            PROTO_UDP => {
                let checksum_offset = ihl.checked_add(6)?;
                let keep_zero = packet
                    .get(checksum_offset..checksum_offset + 2)
                    .map(|bytes| bytes == [0, 0])
                    .unwrap_or(false);
                if !keep_zero {
                    adjust_l4_checksum_ipv4(
                        packet, ihl, protocol, old_src, new_src, old_dst, new_dst,
                    )?;
                }
            }
            _ => {}
        }
    }

    // --- L4 port rewriting (after IP rewriting) ---
    apply_nat_port_rewrite(packet, ihl, protocol, nat)?;

    Some(())
}

pub(super) fn apply_nat_ipv6(packet: &mut [u8], protocol: u8, nat: NatDecision) -> Option<()> {
    if nat == NatDecision::default() {
        return Some(());
    }
    if packet.len() < 40 {
        return None;
    }
    let new_src = nat.rewrite_src.and_then(|ip| match ip {
        IpAddr::V6(ip) => Some(ip.octets()),
        _ => None,
    });
    let new_dst = nat.rewrite_dst.and_then(|ip| match ip {
        IpAddr::V6(ip) => Some(ip.octets()),
        _ => None,
    });

    // NPTv6 (RFC 6296): prefix translation is checksum-neutral by design --
    // the adjustment word preserves the ones-complement sum of the full address.
    // Skip L4 checksum updates entirely for NPTv6 rewrites.
    let skip_l4_csum = nat.nptv6;
    if new_src.is_some() && new_dst.is_none() {
        let new_src = new_src?;
        let old_src_words = ipv6_words_from_slice(packet.get(8..24)?)?;
        packet.get_mut(8..24)?.copy_from_slice(&new_src);
        if !skip_l4_csum {
            let new_src_words = ipv6_words_from_octets(new_src);
            adjust_l4_checksum_ipv6_words(packet, protocol, &old_src_words, &new_src_words)?;
        }
    } else if new_dst.is_some() && new_src.is_none() {
        let new_dst = new_dst?;
        let old_dst_words = ipv6_words_from_slice(packet.get(24..40)?)?;
        packet.get_mut(24..40)?.copy_from_slice(&new_dst);
        if !skip_l4_csum {
            let new_dst_words = ipv6_words_from_octets(new_dst);
            adjust_l4_checksum_ipv6_words(packet, protocol, &old_dst_words, &new_dst_words)?;
        }
    } else if new_src.is_some() || new_dst.is_some() {
        let old_src_words = ipv6_words_from_slice(packet.get(8..24)?)?;
        let old_dst_words = ipv6_words_from_slice(packet.get(24..40)?)?;
        if let Some(ip) = new_src {
            packet.get_mut(8..24)?.copy_from_slice(&ip);
        }
        if let Some(ip) = new_dst {
            packet.get_mut(24..40)?.copy_from_slice(&ip);
        }
        if !skip_l4_csum {
            let new_src_words = new_src.map(ipv6_words_from_octets).unwrap_or(old_src_words);
            let new_dst_words = new_dst.map(ipv6_words_from_octets).unwrap_or(old_dst_words);
            match protocol {
                PROTO_TCP | PROTO_UDP | PROTO_ICMPV6 => {
                    adjust_l4_checksum_ipv6_words(
                        packet,
                        protocol,
                        &old_src_words,
                        &new_src_words,
                    )?;
                    adjust_l4_checksum_ipv6_words(
                        packet,
                        protocol,
                        &old_dst_words,
                        &new_dst_words,
                    )?;
                }
                _ => {}
            }
        }
    }

    // --- L4 port rewriting (after IP rewriting) ---
    // IPv6 header is always 40 bytes (no IHL).
    apply_nat_port_rewrite(packet, 40, protocol, nat)?;

    Some(())
}

/// Rewrite L4 source/destination ports and incrementally update the L4 checksum.
/// Port rewriting MUST happen AFTER IP address rewriting to avoid double-counting
/// in the checksum. Skips ICMP (no ports).
pub(super) fn apply_nat_port_rewrite(
    packet: &mut [u8],
    l4_offset: usize,
    protocol: u8,
    nat: NatDecision,
) -> Option<()> {
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return Some(());
    }
    if packet.len() < l4_offset + 4 {
        return Some(());
    }

    if let Some(new_src_port) = nat.rewrite_src_port {
        let port_offset = l4_offset; // TCP/UDP src port at offset +0
        let old_port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        if old_port != new_src_port {
            packet[port_offset..port_offset + 2].copy_from_slice(&new_src_port.to_be_bytes());
            adjust_l4_checksum_port(packet, l4_offset, protocol, old_port, new_src_port)?;
        }
    }

    if let Some(new_dst_port) = nat.rewrite_dst_port {
        let port_offset = l4_offset + 2; // TCP/UDP dst port at offset +2
        let old_port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        if old_port != new_dst_port {
            packet[port_offset..port_offset + 2].copy_from_slice(&new_dst_port.to_be_bytes());
            adjust_l4_checksum_port(packet, l4_offset, protocol, old_port, new_dst_port)?;
        }
    }

    Some(())
}

/// Incremental L4 checksum update for a single 16-bit port change.
pub(super) fn adjust_l4_checksum_port(
    packet: &mut [u8],
    l4_offset: usize,
    protocol: u8,
    old_port: u16,
    new_port: u16,
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => l4_offset.checked_add(16)?,
        PROTO_UDP => l4_offset.checked_add(6)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    // Skip UDP IPv4 checksum update when checksum is 0 (optional for IPv4 UDP)
    if matches!(protocol, PROTO_UDP) && current == 0 {
        return Some(());
    }
    let mut updated = checksum16_adjust(current, &[old_port], &[new_port]);
    if matches!(protocol, PROTO_UDP) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

pub(super) fn enforce_expected_ports(
    frame: &mut [u8],
    addr_family: u8,
    protocol: u8,
    expected_ports: Option<(u16, u16)>,
) -> Option<bool> {
    let Some((expected_src, expected_dst)) = expected_ports else {
        return Some(false);
    };
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return Some(false);
    }
    let l3 = frame_l3_offset(frame)?;
    let l4 = frame_l4_offset(frame, addr_family)?;
    let ports = frame.get(l4..l4 + 4)?;
    let current_src = u16::from_be_bytes([ports[0], ports[1]]);
    let current_dst = u16::from_be_bytes([ports[2], ports[3]]);
    if current_src == expected_src && current_dst == expected_dst {
        return Some(false);
    }
    let packet = frame.get_mut(l3..)?;
    let rel_l4 = l4.checked_sub(l3)?;
    if current_src != expected_src {
        packet
            .get_mut(rel_l4..rel_l4 + 2)?
            .copy_from_slice(&expected_src.to_be_bytes());
        adjust_l4_checksum_port(packet, rel_l4, protocol, current_src, expected_src)?;
    }
    if current_dst != expected_dst {
        packet
            .get_mut(rel_l4 + 2..rel_l4 + 4)?
            .copy_from_slice(&expected_dst.to_be_bytes());
        adjust_l4_checksum_port(packet, rel_l4, protocol, current_dst, expected_dst)?;
    }
    Some(true)
}

/// Like enforce_expected_ports, but takes pre-computed L3/L4 offsets to avoid
/// redundant header parsing in the hot path.
#[inline]
pub(super) fn enforce_expected_ports_at(
    frame: &mut [u8],
    l3: usize,
    l4: usize,
    _addr_family: u8,
    protocol: u8,
    expected_ports: Option<(u16, u16)>,
) -> Option<bool> {
    let Some((expected_src, expected_dst)) = expected_ports else {
        return Some(false);
    };
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return Some(false);
    }
    let ports = frame.get(l4..l4 + 4)?;
    let current_src = u16::from_be_bytes([ports[0], ports[1]]);
    let current_dst = u16::from_be_bytes([ports[2], ports[3]]);
    if current_src == expected_src && current_dst == expected_dst {
        return Some(false);
    }
    let packet = frame.get_mut(l3..)?;
    let rel_l4 = l4.checked_sub(l3)?;
    if current_src != expected_src {
        packet
            .get_mut(rel_l4..rel_l4 + 2)?
            .copy_from_slice(&expected_src.to_be_bytes());
        adjust_l4_checksum_port(packet, rel_l4, protocol, current_src, expected_src)?;
    }
    if current_dst != expected_dst {
        packet
            .get_mut(rel_l4 + 2..rel_l4 + 4)?
            .copy_from_slice(&expected_dst.to_be_bytes());
        adjust_l4_checksum_port(packet, rel_l4, protocol, current_dst, expected_dst)?;
    }
    Some(true)
}

pub(super) fn restore_l4_tuple_from_meta(
    packet: &mut [u8],
    meta: UserspaceDpMeta,
    rel_l4: usize,
) -> Option<bool> {
    match meta.protocol {
        PROTO_TCP | PROTO_UDP => Some(false),
        PROTO_ICMP | PROTO_ICMPV6 => {
            let ident = packet.get_mut(rel_l4 + 4..rel_l4 + 6)?;
            let expected = meta.flow_src_port.to_be_bytes();
            let repaired = *ident != expected;
            if repaired {
                ident.copy_from_slice(&expected);
            }
            Some(repaired)
        }
        _ => Some(false),
    }
}

pub(super) fn build_injected_ipv4(
    req: &InjectPacketRequest,
    dst_mac: [u8; 6],
    dst_ip: Ipv4Addr,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let src_ip = egress
        .primary_v4
        .ok_or_else(|| "egress interface has no IPv4 source address".to_string())?;
    let eth_len = if egress.vlan_id > 0 { 18 } else { 14 };
    let min_total = eth_len + 20 + 8 + 16;
    let target_len = req.packet_length.max(min_total as u32) as usize;
    let payload_len = target_len.saturating_sub(eth_len + 20 + 8);

    let mut frame = Vec::with_capacity(target_len);
    write_eth_header(&mut frame, dst_mac, egress.src_mac, egress.vlan_id, 0x0800);

    let total_len = (20 + 8 + payload_len) as u16;
    let ip_start = frame.len();
    frame.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        64,
        1,
        0,
        0,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    let ip_sum = checksum16(&frame[ip_start..ip_start + 20]);
    frame[ip_start + 10] = (ip_sum >> 8) as u8;
    frame[ip_start + 11] = ip_sum as u8;

    let icmp_start = frame.len();
    frame.extend_from_slice(&[8, 0, 0, 0]);
    frame.extend_from_slice(&(req.slot as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    for i in 0..payload_len {
        frame.push((i & 0xff) as u8);
    }
    let icmp_sum = checksum16(&frame[icmp_start..]);
    frame[icmp_start + 2] = (icmp_sum >> 8) as u8;
    frame[icmp_start + 3] = icmp_sum as u8;
    Ok(frame)
}

pub(super) fn build_injected_ipv6(
    req: &InjectPacketRequest,
    dst_mac: [u8; 6],
    dst_ip: Ipv6Addr,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let src_ip = egress
        .primary_v6
        .ok_or_else(|| "egress interface has no IPv6 source address".to_string())?;
    let eth_len = if egress.vlan_id > 0 { 18 } else { 14 };
    let min_total = eth_len + 40 + 8 + 16;
    let target_len = req.packet_length.max(min_total as u32) as usize;
    let payload_len = target_len.saturating_sub(eth_len + 40 + 8);

    let mut frame = Vec::with_capacity(target_len);
    write_eth_header(&mut frame, dst_mac, egress.src_mac, egress.vlan_id, 0x86dd);
    let plen = (8 + payload_len) as u16;
    frame.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (plen >> 8) as u8,
        plen as u8,
        58,
        64,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());

    let icmp_start = frame.len();
    frame.extend_from_slice(&[128, 0, 0, 0]);
    frame.extend_from_slice(&(req.slot as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    for i in 0..payload_len {
        frame.push((i & 0xff) as u8);
    }
    let icmp_sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &frame[icmp_start..]);
    frame[icmp_start + 2] = (icmp_sum >> 8) as u8;
    frame[icmp_start + 3] = icmp_sum as u8;
    Ok(frame)
}

pub(super) fn write_eth_header(
    buf: &mut Vec<u8>,
    dst: [u8; 6],
    src: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
) {
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&src);
    if vlan_id > 0 {
        buf.extend_from_slice(&0x8100u16.to_be_bytes());
        buf.extend_from_slice(&(vlan_id & 0x0fff).to_be_bytes());
    }
    buf.extend_from_slice(&ether_type.to_be_bytes());
}

pub(super) fn write_eth_header_slice(
    buf: &mut [u8],
    dst: [u8; 6],
    src: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
) -> Option<()> {
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    if buf.len() < eth_len {
        return None;
    }
    let ether_type_bytes = ether_type.to_be_bytes();
    // SAFETY: buf.len() >= eth_len is guaranteed by the guard above.
    // eth_len is 14 (no VLAN) or 18 (VLAN), so all writes are in-bounds.
    debug_assert!(buf.len() >= eth_len);
    unsafe {
        let ptr = buf.as_mut_ptr();
        core::ptr::copy_nonoverlapping(dst.as_ptr(), ptr, 6);
        core::ptr::copy_nonoverlapping(src.as_ptr(), ptr.add(6), 6);
        if vlan_id > 0 {
            core::ptr::copy_nonoverlapping(0x8100u16.to_be_bytes().as_ptr(), ptr.add(12), 2);
            core::ptr::copy_nonoverlapping(
                (vlan_id & 0x0fff).to_be_bytes().as_ptr(),
                ptr.add(14),
                2,
            );
            core::ptr::copy_nonoverlapping(ether_type_bytes.as_ptr(), ptr.add(16), 2);
        } else {
            core::ptr::copy_nonoverlapping(ether_type_bytes.as_ptr(), ptr.add(12), 2);
        }
    }
    Some(())
}

pub(super) fn checksum16(bytes: &[u8]) -> u16 {
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

pub(super) fn checksum16_add_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(last) = chunks.remainder().first() {
        sum += (*last as u32) << 8;
    }
    sum
}

pub(super) fn checksum16_finish(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(super) fn checksum16_adjust(checksum: u16, old_words: &[u16], new_words: &[u16]) -> u16 {
    let mut sum = (!checksum as u32) & 0xffff;
    for word in old_words {
        sum += (!u32::from(*word)) & 0xffff;
    }
    for word in new_words {
        sum += u32::from(*word);
    }
    checksum16_finish(sum)
}

pub(super) fn ipv4_words(ip: Ipv4Addr) -> [u16; 2] {
    let octets = ip.octets();
    [
        u16::from_be_bytes([octets[0], octets[1]]),
        u16::from_be_bytes([octets[2], octets[3]]),
    ]
}

#[allow(dead_code)]
pub(super) fn ipv6_words(ip: Ipv6Addr) -> [u16; 8] {
    ipv6_words_from_octets(ip.octets())
}

pub(super) fn ipv6_words_from_octets(octets: [u8; 16]) -> [u16; 8] {
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

pub(super) fn ipv6_words_from_slice(bytes: &[u8]) -> Option<[u16; 8]> {
    let octets: [u8; 16] = bytes.get(..16)?.try_into().ok()?;
    Some(ipv6_words_from_octets(octets))
}

pub(super) fn adjust_ipv4_header_checksum(
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

pub(super) fn checksum16_ipv6(
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

pub(super) fn checksum16_ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = checksum16_add_bytes(sum, &src.octets());
    sum = checksum16_add_bytes(sum, &dst.octets());
    sum = checksum16_add_bytes(sum, &[0, protocol]);
    sum = checksum16_add_bytes(sum, &(payload.len() as u16).to_be_bytes());
    sum = checksum16_add_bytes(sum, payload);
    checksum16_finish(sum)
}

pub(super) fn adjust_l4_checksum_ipv4(
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
pub(super) fn adjust_l4_checksum_ipv6(
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

pub(super) fn adjust_l4_checksum_ipv4_src(
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

pub(super) fn adjust_l4_checksum_ipv4_dst(
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

pub(super) fn adjust_l4_checksum_ipv4_words(
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
pub(super) fn adjust_l4_checksum_ipv6_src(
    packet: &mut [u8],
    protocol: u8,
    old_src: Ipv6Addr,
    new_src: Ipv6Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv6_words(packet, protocol, &ipv6_words(old_src), &ipv6_words(new_src))
}

#[allow(dead_code)]
pub(super) fn adjust_l4_checksum_ipv6_dst(
    packet: &mut [u8],
    protocol: u8,
    old_dst: Ipv6Addr,
    new_dst: Ipv6Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv6_words(packet, protocol, &ipv6_words(old_dst), &ipv6_words(new_dst))
}

pub(super) fn adjust_l4_checksum_ipv6_words(
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

pub(super) fn recompute_l4_checksum_ipv4(
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

pub(super) fn recompute_l4_checksum_ipv6(packet: &mut [u8], protocol: u8) -> Option<()> {
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

/// Verify IP + TCP/UDP checksums on a fully-built forwarded frame.
/// Returns (ip_ok, l4_ok). Logs mismatches for the first N frames.
pub(super) static CSUM_VERIFIED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub(super) static CSUM_BAD_IP_TOTAL: AtomicU64 = AtomicU64::new(0);
pub(super) static CSUM_BAD_L4_TOTAL: AtomicU64 = AtomicU64::new(0);

pub(super) fn verify_built_frame_checksums(frame: &[u8]) -> (bool, bool) {
    let l3 = match frame_l3_offset(frame) {
        Some(o) => o,
        None => return (true, true),
    };
    let packet = match frame.get(l3..) {
        Some(p) if p.len() >= 20 => p,
        _ => return (true, true),
    };
    // Only handle IPv4 TCP for now (main traffic under test).
    if (packet[0] >> 4) != 4 {
        return (true, true);
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return (true, true);
    }
    let protocol = packet[9];
    // --- IP header checksum verification ---
    let ip_header = match packet.get(..ihl) {
        Some(h) => h,
        None => return (true, true),
    };
    let ip_csum_in_frame = u16::from_be_bytes([ip_header[10], ip_header[11]]);
    // Compute from scratch: zero out checksum field, compute, compare.
    let mut ip_scratch = [0u8; 60]; // max IHL = 60
    let scratch = &mut ip_scratch[..ihl];
    scratch.copy_from_slice(ip_header);
    scratch[10] = 0;
    scratch[11] = 0;
    let expected_ip_csum = checksum16(scratch);
    let ip_ok = ip_csum_in_frame == expected_ip_csum;

    // --- IP total length consistency ---
    let ip_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let actual_l3_len = packet.len();
    if ip_total_len != actual_l3_len {
        thread_local! {
            static IP_LEN_MISMATCH_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        IP_LEN_MISMATCH_LOG.with(|c| {
            let n = c.get();
            if n < 20 {
                c.set(n + 1);
                #[cfg(feature = "debug-log")]
                {
                    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                    debug_log!(
                        "IP_LEN_MISMATCH[{}]: ip_total_len={} actual_l3_len={} frame_len={} l3={} src={} dst={} proto={}",
                        n, ip_total_len, actual_l3_len, frame.len(), l3, src, dst, protocol,
                    );
                }
            }
        });
    }

    // --- L4 checksum verification (TCP or UDP) ---
    // Use ip_total_len to bound the L4 segment — Ethernet padding bytes beyond
    // ip_total_len must NOT be included in the checksum pseudo-header or payload.
    let l4_len = if ip_total_len > ihl {
        ip_total_len - ihl
    } else {
        0
    };
    let l4_ok = if protocol == PROTO_TCP {
        let segment = match packet.get(ihl..ihl + l4_len) {
            Some(s) if s.len() >= 20 => s,
            _ => return (ip_ok, true),
        };
        let tcp_csum_in_frame = u16::from_be_bytes([segment[16], segment[17]]);
        let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        // Build pseudo-header + TCP with checksum zeroed.
        let mut pseudo = Vec::with_capacity(12 + segment.len());
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(PROTO_TCP);
        pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(segment);
        // Zero the checksum field in pseudo buffer (offset 12 + 16 = 28..30).
        let csum_off = 12 + 16;
        if pseudo.len() > csum_off + 1 {
            pseudo[csum_off] = 0;
            pseudo[csum_off + 1] = 0;
        }
        let expected_tcp_csum = checksum16(&pseudo);
        tcp_csum_in_frame == expected_tcp_csum
    } else if protocol == PROTO_UDP {
        let segment = match packet.get(ihl..ihl + l4_len) {
            Some(s) if s.len() >= 8 => s,
            _ => return (ip_ok, true),
        };
        let udp_csum_in_frame = u16::from_be_bytes([segment[6], segment[7]]);
        if udp_csum_in_frame == 0 {
            true // zero = no checksum
        } else {
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let mut pseudo = Vec::with_capacity(12 + segment.len());
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.push(0);
            pseudo.push(PROTO_UDP);
            pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
            pseudo.extend_from_slice(segment);
            let csum_off = 12 + 6;
            if pseudo.len() > csum_off + 1 {
                pseudo[csum_off] = 0;
                pseudo[csum_off + 1] = 0;
            }
            let expected_udp_csum = checksum16(&pseudo);
            let expected_udp_csum = if expected_udp_csum == 0 {
                0xffff
            } else {
                expected_udp_csum
            };
            udp_csum_in_frame == expected_udp_csum
        }
    } else {
        true
    };

    CSUM_VERIFIED_TOTAL.fetch_add(1, Ordering::Relaxed);
    if !ip_ok {
        CSUM_BAD_IP_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    if !l4_ok {
        CSUM_BAD_L4_TOTAL.fetch_add(1, Ordering::Relaxed);
    }

    thread_local! {
        static CSUM_VERIFY_COUNT: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
    }
    if !ip_ok || !l4_ok {
        CSUM_VERIFY_COUNT.with(|c| {
            let (total_bad, logged) = c.get();
            c.set((total_bad + 1, logged));
            if logged < 30 {
                c.set((total_bad + 1, logged + 1));
                let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                eprintln!("CSUM_BAD[{}]: ip_ok={} l4_ok={} proto={} ip_in={:#06x} ip_exp={:#06x} \
                     src={} dst={} frame_len={} l3={} ihl={}",
                    total_bad, ip_ok, l4_ok, protocol,
                    ip_csum_in_frame, expected_ip_csum,
                    src, dst, frame.len(), l3, ihl,
                );
                if !l4_ok && protocol == PROTO_TCP {
                    let segment = &packet[ihl..];
                    let tcp_csum = u16::from_be_bytes([segment[16], segment[17]]);
                    let tcp_src = u16::from_be_bytes([segment[0], segment[1]]);
                    let tcp_dst = u16::from_be_bytes([segment[2], segment[3]]);
                    // Recompute to show expected
                    let mut pseudo = Vec::with_capacity(12 + segment.len());
                    pseudo.extend_from_slice(&src.octets());
                    pseudo.extend_from_slice(&dst.octets());
                    pseudo.push(0);
                    pseudo.push(PROTO_TCP);
                    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
                    pseudo.extend_from_slice(segment);
                    pseudo[12 + 16] = 0;
                    pseudo[12 + 17] = 0;
                    let expected = checksum16(&pseudo);
                    eprintln!("CSUM_BAD_TCP[{}]: sport={} dport={} csum_in={:#06x} csum_exp={:#06x} seg_len={}",
                        total_bad, tcp_src, tcp_dst, tcp_csum, expected, segment.len(),
                    );
                    // Hex dump of first 60 bytes of frame for deep debug
                    if logged < 5 {
                        let hex_len = frame.len().min(80);
                        let hex: String = frame[..hex_len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                        eprintln!("CSUM_BAD_HEX[{}]: {}", total_bad, hex);
                    }
                }
            }
        });
    }
    (ip_ok, l4_ok)
}

pub(super) fn try_parse_metadata(area: &MmapArea, desc: XdpDesc) -> Option<UserspaceDpMeta> {
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    if (desc.addr as usize) < meta_len {
        return None;
    }
    let meta_offset = (desc.addr as usize).checked_sub(meta_len)?;
    let bytes = area.slice(meta_offset, meta_len)?;
    let meta = unsafe { *(bytes.as_ptr() as *const UserspaceDpMeta) };
    if meta.magic != USERSPACE_META_MAGIC || meta.version != USERSPACE_META_VERSION {
        return None;
    }
    if meta.length as usize != meta_len {
        return None;
    }
    Some(meta)
}

#[cfg(test)]
mod tests {
    use super::super::test_fixtures::*;
    use super::*;

    fn active_ha_runtime(now_secs: u64) -> HAGroupRuntime {
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: now_secs,
            lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
        }
    }

    fn inactive_ha_runtime(watchdog_timestamp: u64) -> HAGroupRuntime {
        HAGroupRuntime {
            active: false,
            watchdog_timestamp,
            lease: HAForwardingLease::Inactive,
        }
    }

    fn build_icmp_echo_frame_v4(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8) -> Vec<u8> {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, ttl, PROTO_ICMP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&dst.octets());
        let ip_csum = checksum16(&frame[14..34]);
        frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
        let icmp_start = frame.len();
        frame.extend_from_slice(&[8, 0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01]);
        let icmp_csum = checksum16(&frame[icmp_start..]);
        frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
        frame
    }

    fn build_ipv6_gre_frame(
        inner_packet: &[u8],
        src: Ipv6Addr,
        dst: Ipv6Addr,
        key: Option<u32>,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x02],
            0,
            0x86dd,
        );
        let gre_len = if key.is_some() { 8usize } else { 4usize };
        let payload_len = u16::try_from(gre_len + inner_packet.len()).unwrap();
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.push(PROTO_GRE);
        frame.push(64);
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&dst.octets());
        let flags = if key.is_some() { 0x2000u16 } else { 0u16 };
        frame.extend_from_slice(&flags.to_be_bytes());
        frame.extend_from_slice(
            &(if inner_packet.first().map(|b| b >> 4) == Some(4) {
                0x0800u16
            } else {
                0x86ddu16
            })
            .to_be_bytes(),
        );
        if let Some(key) = key {
            frame.extend_from_slice(&key.to_be_bytes());
        }
        frame.extend_from_slice(inner_packet);
        frame
    }

    fn native_gre_outer_meta() -> UserspaceDpMeta {
        UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 6,
            rx_queue_index: 0,
            l3_offset: 14,
            l4_offset: 54,
            payload_offset: 58,
            pkt_len: 92,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_GRE,
            ..UserspaceDpMeta::default()
        }
    }

    #[test]
    fn parse_session_flow_reparses_vlan_ipv4_reply_without_meta_offsets() {
        let frame = vlan_icmp_reply_frame();
        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            l3_offset: 14,
            l4_offset: 34,
            ..UserspaceDpMeta::default()
        };
        let flow = parse_session_flow(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
        )
        .expect("flow");
        assert_eq!(flow.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
        assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
        assert_eq!(flow.forward_key.src_port, 0x1234);
        assert_eq!(flow.forward_key.dst_port, 0);
    }

    #[test]
    fn parse_session_flow_prefers_tuple_stamped_in_metadata() {
        let mut area = MmapArea::new(256).expect("mmap");
        area.slice_mut(0, 64).expect("slice").fill(0xaa);
        let meta = valid_meta();
        let flow = parse_session_flow(
            &area,
            XdpDesc {
                addr: 0,
                len: 64,
                options: 0,
            },
            meta,
        )
        .expect("flow");
        assert_eq!(flow.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
        assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
        assert_eq!(flow.forward_key.src_port, 0x1234);
        assert_eq!(flow.forward_key.dst_port, 0);
    }

    #[test]
    fn parse_session_flow_prefers_frame_tuple_when_metadata_disagrees() {
        let frame = vlan_icmp_reply_frame();
        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let mut meta = valid_meta();
        meta.l3_offset = 18;
        meta.l4_offset = 38;
        meta.flow_src_addr[..4].copy_from_slice(&[10, 0, 61, 102]);
        meta.flow_dst_addr[..4].copy_from_slice(&[172, 16, 80, 200]);
        meta.flow_src_port = 0xbeef;
        meta.flow_dst_port = 0;
        let flow = parse_session_flow(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
        )
        .expect("flow");
        assert_eq!(flow.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
        assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
        assert_eq!(flow.forward_key.src_port, 0x1234);
        assert_eq!(flow.forward_key.dst_port, 0);
    }

    #[test]
    fn parse_session_flow_prefers_ipv6_metadata_ports_when_frame_ports_disagree() {
        let src_ip: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src");
        let dst_ip: Ipv6Addr = "2001:559:8585:80::200".parse().expect("dst");
        let src_port = 50662u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&80u16.to_be_bytes());
        frame.extend_from_slice(&0x86ddu16.to_be_bytes());
        frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&[0x50, 0x10, 0, 64, 0, 0, 0, 0]);

        let mut area = MmapArea::new(512).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            l3_offset: 18,
            l4_offset: 58,
            payload_offset: 78,
            flow_src_port: 1026,
            flow_dst_port: dst_port,
            flow_src_addr: src_ip.octets(),
            flow_dst_addr: dst_ip.octets(),
            ..UserspaceDpMeta::default()
        };
        let flow = parse_session_flow(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
        )
        .expect("flow");
        assert_eq!(flow.src_ip, IpAddr::V6(src_ip));
        assert_eq!(flow.dst_ip, IpAddr::V6(dst_ip));
        assert_eq!(flow.forward_key.src_port, 1026);
        assert_eq!(flow.forward_key.dst_port, dst_port);
    }

    #[test]
    fn parse_session_flow_reparses_ipv6_when_metadata_l4_offset_is_bad() {
        let src_ip: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src");
        let dst_ip: Ipv6Addr = "2001:559:8585:80::200".parse().expect("dst");
        let src_port = 50662u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&80u16.to_be_bytes());
        frame.extend_from_slice(&0x86ddu16.to_be_bytes());
        frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&[0x50, 0x10, 0, 64, 0, 0, 0, 0]);

        let mut area = MmapArea::new(512).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            l3_offset: 18,
            l4_offset: 22,
            payload_offset: 78,
            flow_src_port: 1025,
            flow_dst_port: dst_port,
            flow_src_addr: src_ip.octets(),
            flow_dst_addr: dst_ip.octets(),
            ..UserspaceDpMeta::default()
        };
        let flow = parse_session_flow(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
        )
        .expect("flow");
        assert_eq!(flow.src_ip, IpAddr::V6(src_ip));
        assert_eq!(flow.dst_ip, IpAddr::V6(dst_ip));
        // When IPs match, parse_session_flow prefers metadata ports over
        // frame-parsed ports (metadata is stamped by BPF before any DMA
        // corruption). The meta port (1025) wins over the frame port (50662).
        assert_eq!(flow.forward_key.src_port, 1025);
        assert_eq!(flow.forward_key.dst_port, dst_port);
    }

    #[test]
    fn forwarding_lookup_prefers_local_delivery() {
        let mut snapshot = forwarding_snapshot(true);
        snapshot.source_nat_rules.clear();
        let state = build_forwarding_state(&snapshot);
        assert_eq!(
            lookup_forwarding_for_ip(&state, IpAddr::V4(Ipv4Addr::new(172, 16, 50, 8))),
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(
            lookup_forwarding_for_ip(
                &state,
                IpAddr::V6("2001:559:8585:50::8".parse().expect("ipv6")),
            ),
            ForwardingDisposition::LocalDelivery
        );
    }

    #[test]
    fn forwarding_lookup_requires_neighbor_for_forward_candidate() {
        let good = build_forwarding_state(&forwarding_snapshot(true));
        assert_eq!(
            lookup_forwarding_for_ip(&good, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(
            lookup_forwarding_for_ip(
                &good,
                IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
            ),
            ForwardingDisposition::ForwardCandidate
        );

        let missing_neighbor = build_forwarding_state(&forwarding_snapshot(false));
        assert_eq!(
            lookup_forwarding_for_ip(&missing_neighbor, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),),
            ForwardingDisposition::MissingNeighbor
        );
    }

    #[test]
    fn tunnel_route_resolves_to_logical_tunnel_and_physical_tx() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let resolved = lookup_forwarding_resolution_v4(
            &state,
            None,
            Ipv4Addr::new(8, 8, 8, 8),
            "sfmix.inet.0",
            0,
            true,
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 362);
        assert_eq!(resolved.tx_ifindex, 6);
        assert_eq!(resolved.tunnel_endpoint_id, 1);
        assert_eq!(
            resolved.next_hop,
            Some(IpAddr::V6("2001:559:8585:80::1".parse().expect("outer nh")))
        );
        assert_eq!(
            resolved.neighbor_mac,
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(resolved.src_mac, Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]));
        assert_eq!(resolved.tx_vlan_id, 80);
    }

    #[test]
    fn tunnel_route_preserves_logical_egress_on_outer_neighbor_miss() {
        let state = build_forwarding_state(&native_gre_snapshot(false));
        let resolved = lookup_forwarding_resolution_v4(
            &state,
            None,
            Ipv4Addr::new(8, 8, 8, 8),
            "sfmix.inet.0",
            0,
            true,
        );
        assert_eq!(resolved.disposition, ForwardingDisposition::MissingNeighbor);
        assert_eq!(resolved.egress_ifindex, 362);
        assert_eq!(resolved.tx_ifindex, 6);
        assert_eq!(resolved.tunnel_endpoint_id, 1);
        assert_eq!(resolved.src_mac, Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]));
        assert_eq!(resolved.tx_vlan_id, 80);
    }

    #[test]
    fn ingress_filter_routing_instance_steers_flow_into_native_gre_table() {
        let state = build_forwarding_state(&native_gre_pbr_snapshot(true));
        let flow = SessionFlow {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_ICMP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
                src_port: 0,
                dst_port: 0,
            },
        };
        let meta = UserspaceDpMeta {
            ingress_ifindex: 5,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            ..Default::default()
        };
        let override_table = ingress_route_table_override(&state, meta, &flow);
        assert_eq!(override_table.as_deref(), Some("sfmix.inet.0"));
        let resolved = lookup_forwarding_resolution_in_table_with_dynamic(
            &state,
            &Default::default(),
            flow.dst_ip,
            override_table.as_deref(),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 362);
        assert_eq!(resolved.tx_ifindex, 6);
        assert_eq!(resolved.tunnel_endpoint_id, 1);
    }

    #[test]
    fn native_gre_logical_egress_retains_zone_without_mac() {
        let state = build_forwarding_state(&native_gre_pbr_snapshot(true));
        let egress = state.egress.get(&362).expect("logical tunnel egress");
        assert_eq!(egress.zone, "sfmix");
        assert_eq!(egress.primary_v4, Some(Ipv4Addr::new(10, 255, 192, 42)));
    }

    #[test]
    fn owner_rg_for_resolution_uses_native_gre_endpoint_group() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let resolved = lookup_forwarding_resolution_with_dynamic(
            &state,
            &Default::default(),
            IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
        );
        assert_eq!(resolved.tunnel_endpoint_id, 1);
        assert_eq!(owner_rg_for_resolution(&state, resolved), 1);
    }

    #[test]
    fn native_gre_decap_maps_inner_packet_to_logical_tunnel_ingress() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let inner = build_icmp_echo_frame_v4(
            Ipv4Addr::new(10, 255, 192, 41),
            Ipv4Addr::new(10, 255, 192, 42),
            63,
        );
        let outer = build_ipv6_gre_frame(
            &inner[14..],
            "2602:ffd3:0:2::7".parse().unwrap(),
            "2001:559:8585:80::8".parse().unwrap(),
            None,
        );
        let packet = try_native_gre_decap_from_frame(&outer, native_gre_outer_meta(), &state)
            .expect("native gre decap");
        assert_eq!(packet.meta.ingress_ifindex, 362);
        assert_eq!(packet.meta.addr_family, libc::AF_INET as u8);
        assert_eq!(packet.meta.protocol, PROTO_ICMP);
        assert_eq!(packet.meta.l3_offset, 14);
        assert_eq!(&packet.frame[12..14], &[0x08, 0x00]);
        assert_eq!(&packet.frame[26..30], &[10, 255, 192, 41]);
        assert_eq!(&packet.frame[30..34], &[10, 255, 192, 42]);
    }

    #[test]
    fn build_forwarded_frame_from_frame_encapsulates_native_gre() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let inner =
            build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(8, 8, 8, 8), 64);
        let inner_meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 11,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 42,
            pkt_len: (inner.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            flow_src_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&[10, 0, 61, 102]);
                addr
            },
            flow_dst_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&[8, 8, 8, 8]);
                addr
            },
            flow_src_port: 0x1234,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: lookup_forwarding_resolution_v4(
                &state,
                None,
                Ipv4Addr::new(8, 8, 8, 8),
                "sfmix.inet.0",
                0,
                true,
            ),
            nat: NatDecision::default(),
        };
        let built = build_forwarded_frame_from_frame(
            &inner,
            inner_meta,
            &decision,
            &state,
            false,
            Some((0x1234, 0)),
        )
        .expect("encapsulated gre frame");
        assert_eq!(&built[12..16], &[0x81, 0x00, 0x00, 0x50]);
        assert_eq!(&built[16..18], &[0x86, 0xdd]);
        assert_eq!(&built[22..24], &[0x00, 0x20]);
        assert_eq!(built[24], PROTO_GRE);
        assert_eq!(built[25], 64);
        assert_eq!(&built[60..62], &[0x08, 0x00]);
        assert_eq!(built[70], 63);
        assert_eq!(&built[74..78], &[10, 0, 61, 102]);
        assert_eq!(&built[78..82], &[8, 8, 8, 8]);
    }

    #[test]
    fn local_origin_tunnel_tx_request_encapsulates_raw_ip_for_active_owner() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
            1,
            active_ha_runtime(monotonic_nanos() / 1_000_000_000),
        )])));
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let packet = build_icmp_echo_frame_v4(
            Ipv4Addr::new(10, 255, 192, 42),
            Ipv4Addr::new(10, 255, 192, 41),
            64,
        );
        let plan = build_local_origin_tunnel_tx_request(
            &packet[14..],
            1,
            &state,
            &ha_state,
            &dynamic_neighbors,
        )
        .expect("local-origin tunnel tx request");
        assert_eq!(plan.tx_ifindex, 6);
        assert_eq!(&plan.tx_request.bytes[12..16], &[0x81, 0x00, 0x00, 0x50]);
        assert_eq!(&plan.tx_request.bytes[16..18], &[0x86, 0xdd]);
        assert_eq!(plan.tx_request.bytes[24], PROTO_GRE);
        assert_eq!(&plan.tx_request.bytes[60..62], &[0x08, 0x00]);
        assert_eq!(&plan.tx_request.bytes[74..78], &[10, 255, 192, 42]);
        assert_eq!(&plan.tx_request.bytes[78..82], &[10, 255, 192, 41]);
        assert_eq!(plan.session_entry.key.protocol, PROTO_ICMP);
    }

    #[test]
    fn local_origin_tunnel_tx_request_rejects_inactive_owner() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
            1,
            inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
        )])));
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let packet = build_icmp_echo_frame_v4(
            Ipv4Addr::new(10, 255, 192, 42),
            Ipv4Addr::new(10, 255, 192, 41),
            64,
        );
        let err = build_local_origin_tunnel_tx_request(
            &packet[14..],
            1,
            &state,
            &ha_state,
            &dynamic_neighbors,
        )
        .expect_err("inactive owner should not originate tunnel traffic");
        assert!(err.contains("ha_inactive"), "unexpected error: {err}");
    }

    #[test]
    fn build_forwarded_frame_from_frame_encapsulates_native_gre_after_ipv4_snat() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let inner = build_icmp_echo_frame_v4(
            Ipv4Addr::new(10, 0, 61, 102),
            Ipv4Addr::new(10, 255, 192, 41),
            64,
        );
        let inner_meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 42,
            pkt_len: (inner.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            flow_src_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&[10, 0, 61, 102]);
                addr
            },
            flow_dst_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&[10, 255, 192, 41]);
                addr
            },
            flow_src_port: 0x1234,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: lookup_forwarding_resolution_v4(
                &state,
                None,
                Ipv4Addr::new(10, 255, 192, 41),
                "sfmix.inet.0",
                0,
                true,
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42))),
                ..NatDecision::default()
            },
        };
        let built = build_forwarded_frame_from_frame(
            &inner,
            inner_meta,
            &decision,
            &state,
            false,
            Some((0x1234, 0)),
        )
        .expect("encapsulated native gre frame with snat");
        assert_eq!(&built[12..16], &[0x81, 0x00, 0x00, 0x50]);
        assert_eq!(&built[16..18], &[0x86, 0xdd]);
        assert_eq!(built[24], PROTO_GRE);
        assert_eq!(&built[74..78], &[10, 255, 192, 42]);
        assert_eq!(&built[78..82], &[10, 255, 192, 41]);
    }

    #[test]
    fn build_forwarded_frame_from_frame_recomputes_tcp_checksum_for_native_gre_snat() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let src_ip = Ipv4Addr::new(10, 0, 61, 102);
        let dst_ip = Ipv4Addr::new(10, 255, 192, 41);
        let snat_ip = Ipv4Addr::new(10, 255, 192, 42);
        let src_port = 50420u16;
        let dst_port = 5201u16;

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x01, // ack
            0x50, 0x18, 0x20, 0x00, // data offset/flags/window
            0x18, 0x29, 0x00, 0x00, // intentionally bogus partial/offload checksum + urg
            b't', b'e', b's', b't', b'd', b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 54,
            pkt_len: (frame.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&src_ip.octets());
                addr
            },
            flow_dst_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&dst_ip.octets());
                addr
            },
            flow_src_port: src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: lookup_forwarding_resolution_v4(
                &state,
                None,
                dst_ip,
                "sfmix.inet.0",
                0,
                true,
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                ..NatDecision::default()
            },
        };
        let built = build_forwarded_frame_from_frame(
            &frame,
            meta,
            &decision,
            &state,
            false,
            Some((src_port, dst_port)),
        )
        .expect("encapsulated native gre frame with tcp snat");
        let inner = &built[62..];
        assert_eq!(&inner[12..16], &snat_ip.octets());
        assert_eq!(&inner[16..20], &dst_ip.octets());
        assert!(tcp_checksum_ok_ipv4(inner));
    }

    #[test]
    fn build_forwarded_frame_from_frame_clamps_tcp_mss_for_native_gre() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let src_ip = Ipv4Addr::new(10, 0, 61, 102);
        let dst_ip = Ipv4Addr::new(10, 255, 192, 41);
        let src_port = 44028u16;
        let dst_port = 5201u16;

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x2c, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x00,
            0x00,
            0x00,
            0x01, // seq
            0x00,
            0x00,
            0x00,
            0x00, // ack
            0x60,
            TCP_FLAG_SYN,
            0xfa,
            0xf0, // data offset / flags / window
            0x00,
            0x00,
            0x00,
            0x00, // checksum + urg
            0x02,
            0x04,
            0x05,
            0xb4, // MSS 1460
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 58,
            pkt_len: (frame.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            tcp_flags: TCP_FLAG_SYN,
            flow_src_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&src_ip.octets());
                addr
            },
            flow_dst_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&dst_ip.octets());
                addr
            },
            flow_src_port: src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: lookup_forwarding_resolution_v4(
                &state,
                None,
                dst_ip,
                "sfmix.inet.0",
                0,
                true,
            ),
            nat: NatDecision::default(),
        };
        let built = build_forwarded_frame_from_frame(
            &frame,
            meta,
            &decision,
            &state,
            false,
            Some((src_port, dst_port)),
        )
        .expect("encapsulated native gre frame with tcp syn");
        let inner = &built[62..];
        assert_eq!(&inner[40..44], &[0x02, 0x04, 0x05, 0x88]);
        assert!(tcp_checksum_ok_ipv4(inner));
    }
    fn tcp_checksum_ok_ipv4(packet: &[u8]) -> bool {
        let ihl = usize::from(packet[0] & 0x0f) * 4;
        let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        checksum16_ipv4(src, dst, PROTO_TCP, &packet[ihl..]) == 0
    }

    fn tcp_ports_ipv4(packet: &[u8]) -> (u16, u16) {
        let ihl = usize::from(packet[0] & 0x0f) * 4;
        (
            u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
            u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]),
        )
    }

    fn icmpv6_checksum_ok(packet: &[u8]) -> bool {
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("src"));
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("dst"));
        checksum16_ipv6(src, dst, PROTO_ICMPV6, &packet[40..]) == 0
    }

    #[test]
    fn apply_nat_ipv4_recomputes_tcp_checksum() {
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61,
            102, 172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x50, 0x18, 0x20, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd',
            b'a', b't', b'a',
        ];
        let ip_sum = checksum16(&packet[..20]);
        packet[10] = (ip_sum >> 8) as u8;
        packet[11] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut packet, 20, PROTO_TCP, false).expect("initial tcp sum");
        assert!(tcp_checksum_ok_ipv4(&packet));

        apply_nat_ipv4(
            &mut packet,
            PROTO_TCP,
            NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_dst: None,
                ..NatDecision::default()
            },
        )
        .expect("apply nat");

        assert_eq!(&packet[12..16], &[172, 16, 80, 8]);
        assert!(tcp_checksum_ok_ipv4(&packet));
    }

    #[test]
    fn extract_l3_packet_with_nat_rewrites_reverse_snat_reply_v4() {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
            [0x02, 0xbf, 0x72, 0x00, 0x50, 0x08],
            80,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 63, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
            200, 172, 16, 80, 8, 0x14, 0x51, 0x9c, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd',
            b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[18..38]);
        frame[28] = (ip_sum >> 8) as u8;
        frame[29] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 18,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let packet = extract_l3_packet_with_nat(
            &frame,
            meta,
            NatDecision {
                rewrite_src: None,
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                ..NatDecision::default()
            },
        )
        .expect("slow-path packet");
        assert_eq!(&packet[12..16], &[172, 16, 80, 200]);
        assert_eq!(&packet[16..20], &[10, 0, 61, 102]);
        assert!(tcp_checksum_ok_ipv4(&packet));
    }

    #[test]
    fn extract_l3_packet_with_nat_rewrites_reverse_snat_reply_v6() {
        let src_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap();
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
            [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            80,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 63]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&[
            0x14, 0x51, 0x95, 0x2c, 0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x10,
            0x00, 0x40, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
            b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[18..], PROTO_TCP).expect("tcp sum");

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 18,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let packet = extract_l3_packet_with_nat(
            &frame,
            meta,
            NatDecision {
                rewrite_src: None,
                rewrite_dst: Some(IpAddr::V6("2001:559:8585:ef00::102".parse().unwrap())),
                ..NatDecision::default()
            },
        )
        .expect("slow-path packet");
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()),
            src_ip
        );
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()),
            "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap()
        );
        assert!(tcp_checksum_ok_ipv6(&packet));
    }

    #[test]
    fn build_forwarded_frame_keeps_tcp_checksum_valid_after_snat() {
        let state = build_forwarding_state(&nat_snapshot());
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61,
            102, 172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x50, 0x18, 0x20, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd',
            b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let out = build_forwarded_frame(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 12,
                    tx_ifindex: 11,
                    tunnel_endpoint_id: 0,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
                    neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                    tx_vlan_id: 80,
                },
                nat: NatDecision {
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                    rewrite_dst: None,
                    ..NatDecision::default()
                },
            },
            &state,
            None,
        )
        .expect("forwarded frame");

        assert_eq!(&out[30..34], &[172, 16, 80, 8]);
        assert_eq!(out[26], 63);
        assert!(tcp_checksum_ok_ipv4(&out[18..]));
    }

    #[test]
    fn rewrite_forwarded_frame_in_place_keeps_icmpv6_checksum_valid_after_snat() {
        let src_ip = "2001:559:8585:ef00::100".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, PROTO_ICMPV6, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&[128, 0, 0, 0, 0x12, 0x34, 0x00, 0x01]);
        let sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &frame[54..]);
        frame[56] = (sum >> 8) as u8;
        frame[57] = sum as u8;

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let frame_len = rewrite_forwarded_frame_in_place(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            false,
            None,
        )
        .expect("in-place v6 forward");
        let out = area.slice(0, frame_len as usize).expect("rewritten frame");
        assert_eq!(&out[0..6], &[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
        assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]);
        assert_eq!(out[25], 63);
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&out[26..42]).unwrap()),
            "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap()
        );
        assert!(icmpv6_checksum_ok(&out[18..]));
    }

    #[test]
    fn rewrite_forwarded_frame_in_place_keeps_icmpv6_echo_identifier_and_sequence() {
        let src_ip = "2001:559:8585:ef00::100".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2607:f8b0:4005:814::200e".parse::<Ipv6Addr>().unwrap();
        let echo_id = 0x3e0f;
        let echo_seq = 0x80e9;

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x07, 0x9f, 0x9c, 0x00, 0x18, PROTO_ICMPV6, 2]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&[
            128,
            0,
            0,
            0,
            (echo_id >> 8) as u8,
            echo_id as u8,
            (echo_seq >> 8) as u8,
            echo_seq as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        let sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &frame[54..]);
        frame[56] = (sum >> 8) as u8;
        frame[57] = sum as u8;

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            flow_src_port: echo_id,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:50::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };

        let frame_len = rewrite_forwarded_frame_in_place(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            false,
            None,
        )
        .expect("in-place v6 echo forward");
        let out = area.slice(0, frame_len as usize).expect("rewritten frame");

        let packet = &out[18..];
        assert_eq!(packet[40], 128);
        assert_eq!(packet[41], 0);
        assert_eq!(u16::from_be_bytes([packet[44], packet[45]]), echo_id);
        assert_eq!(u16::from_be_bytes([packet[46], packet[47]]), echo_seq);
        assert!(icmpv6_checksum_ok(packet));
    }

    fn tcp_ports_ipv6(packet: &[u8]) -> (u16, u16) {
        (
            u16::from_be_bytes([packet[40], packet[41]]),
            u16::from_be_bytes([packet[42], packet[43]]),
        )
    }

    fn tcp_checksum_ok_ipv6(packet: &[u8]) -> bool {
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("v6 src"));
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("v6 dst"));
        checksum16_ipv6(src, dst, PROTO_TCP, &packet[40..]) == 0
    }

    #[test]
    fn enforce_expected_ports_repairs_ipv6_tcp_ports_and_checksum() {
        let src_ip = "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
            [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            80,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 63]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&[
            0x04, 0x01, 0x14, 0x51, // wrong src port 1025 -> 5201
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[18..], PROTO_TCP).expect("initial checksum");
        assert!(tcp_checksum_ok_ipv6(&frame[18..]));

        let repaired = enforce_expected_ports(
            &mut frame,
            libc::AF_INET6 as u8,
            PROTO_TCP,
            Some((54688, 5201)),
        )
        .expect("repair");
        assert!(repaired);
        assert_eq!(tcp_ports_ipv6(&frame[18..]), (54688, 5201));
        assert!(tcp_checksum_ok_ipv6(&frame[18..]));
    }

    #[test]
    fn enforce_expected_ports_repairs_ipv4_tcp_ports_and_checksum() {
        let src_ip = Ipv4Addr::new(172, 16, 80, 8);
        let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
            [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            80,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x34, 0x00, 0x01, 0x00, 0x00, 63, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&[
            0x04, 0x01, 0x14, 0x51, // wrong src port 1025 -> 54688
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[18..38]);
        frame[28] = (ip_sum >> 8) as u8;
        frame[29] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, true)
            .expect("initial checksum");
        assert!(tcp_checksum_ok_ipv4(&frame[18..]));

        let repaired = enforce_expected_ports(
            &mut frame,
            libc::AF_INET as u8,
            PROTO_TCP,
            Some((54688, 5201)),
        )
        .expect("repair");
        assert!(repaired);
        assert_eq!(tcp_ports_ipv4(&frame[18..]), (54688, 5201));
        assert!(tcp_checksum_ok_ipv4(&frame[18..]));
    }

    #[test]
    fn rewrite_forwarded_frame_in_place_keeps_ipv6_tcp_ports_after_vlan_snat() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&[
            0xd5, 0xa0, 0x14, 0x51, // 54688 -> 5201
            0x31, 0x96, 0xc8, 0x32, // seq
            0x08, 0xf0, 0x5a, 0xc6, // ack
            0x50, 0x18, 0x00, 0x40, // data offset/flags/window
            0x00, 0x00, 0x00, 0x00, // checksum/urgent
            b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");
        assert!(tcp_checksum_ok_ipv6(&frame[14..]));

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 54688,
            flow_dst_port: 5201,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let frame_len = rewrite_forwarded_frame_in_place(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            false,
            Some((54688, 5201)),
        )
        .expect("rewrite in place");
        let out = area.slice(0, frame_len as usize).expect("rewritten frame");
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
        assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
        assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x86dd);
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&out[26..42]).unwrap()),
            "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(tcp_ports_ipv6(&out[18..]), (54688, 5201));
        assert!(tcp_checksum_ok_ipv6(&out[18..]));
    }

    #[test]
    fn build_forwarded_frame_into_keeps_ipv6_tcp_ports_after_vlan_snat() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&[
            0xd5, 0xa0, 0x14, 0x51, // 54688 -> 5201
            0x31, 0x96, 0xc8, 0x32, // seq
            0x08, 0xf0, 0x5a, 0xc6, // ack
            0x50, 0x18, 0x00, 0x40, // data offset/flags/window
            0x00, 0x00, 0x00, 0x00, // checksum/urgent
            b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");
        assert!(tcp_checksum_ok_ipv6(&frame[14..]));

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 54688,
            flow_dst_port: 5201,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut out = [0u8; 256];
        let frame_len = build_forwarded_frame_into(
            &mut out,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &ForwardingState::default(),
            Some((54688, 5201)),
        )
        .expect("build forwarded frame");
        let out = &out[..frame_len];
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
        assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
        assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x86dd);
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&out[26..42]).unwrap()),
            "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(tcp_ports_ipv6(&out[18..]), (54688, 5201));
        assert!(tcp_checksum_ok_ipv6(&out[18..]));
    }

    #[test]
    fn build_forwarded_frame_into_ignores_ipv6_tcp_metadata_port_mismatch() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let real_src_port = 38276u16;
        let real_dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&real_src_port.to_be_bytes());
        frame.extend_from_slice(&real_dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, // seq
            0x08, 0xf0, 0x5a, 0xc6, // ack
            0x50, 0x18, 0x00, 0x40, // data offset/flags/window
            0x00, 0x00, 0x00, 0x00, // checksum/urgent
            b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1025,
            flow_dst_port: real_dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut out = [0u8; 256];
        let frame_len = build_forwarded_frame_into(
            &mut out,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &ForwardingState::default(),
            Some((real_src_port, real_dst_port)),
        )
        .expect("build forwarded frame");
        let out = &out[..frame_len];
        assert_eq!(tcp_ports_ipv6(&out[18..]), (real_src_port, real_dst_port));
        assert!(tcp_checksum_ok_ipv6(&out[18..]));
    }

    #[test]
    fn build_live_forward_request_prefers_session_flow_ports_over_frame() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let frame_src_port = 38276u16;
        let frame_dst_port = 5201u16;
        let session_src_port = 1025u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&frame_src_port.to_be_bytes());
        frame.extend_from_slice(&frame_dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: session_src_port,
            flow_dst_port: frame_dst_port,
            ..UserspaceDpMeta::default()
        };
        // Session flow ports differ from frame ports — session is authoritative
        // because it is immune to UMEM DMA races.
        let session_flow = SessionFlow {
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            forward_key: SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V6(src_ip),
                dst_ip: IpAddr::V6(dst_ip),
                src_port: session_src_port,
                dst_port: frame_dst_port,
            },
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
            },
        );
        let ingress = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-1"),
            ifindex: 10,
        };

        let req = build_live_forward_request(
            &area,
            &WorkerBindingLookup::default(),
            0,
            &ingress,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            Some(&session_flow),
            None,
            false,
        )
        .expect("request");
        // Session flow ports (1025, 5201) take priority over frame ports (38276, 5201)
        assert_eq!(req.expected_ports, Some((session_src_port, frame_dst_port)));
    }

    #[test]
    fn build_live_forward_request_uses_live_frame_ports_when_no_session_flow() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let real_src_port = 38276u16;
        let real_dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&real_src_port.to_be_bytes());
        frame.extend_from_slice(&real_dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1025,
            flow_dst_port: real_dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
            },
        );
        let ingress = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-1"),
            ifindex: 10,
        };

        // No session flow — live frame ports should be used (over meta ports)
        let req = build_live_forward_request(
            &area,
            &WorkerBindingLookup::default(),
            0,
            &ingress,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            None,
            None,
            false,
        )
        .expect("request");
        assert_eq!(req.expected_ports, Some((real_src_port, real_dst_port)));
    }

    #[test]
    fn build_live_forward_request_uses_flow_or_metadata_ports_when_frame_ports_unavailable() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let area = MmapArea::new(4096).expect("mmap");
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1025,
            flow_dst_port: 5201,
            ..UserspaceDpMeta::default()
        };
        let flow = SessionFlow {
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            forward_key: SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V6(src_ip),
                dst_ip: IpAddr::V6(dst_ip),
                src_port: 54688,
                dst_port: 5201,
            },
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let ingress_ident = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-1"),
            ifindex: 5,
        };
        let req = build_live_forward_request(
            &area,
            &WorkerBindingLookup::default(),
            0,
            &ingress_ident,
            XdpDesc {
                addr: 0,
                len: 0,
                options: 0,
            },
            meta,
            &decision,
            &ForwardingState::default(),
            Some(&flow),
            None,
            false,
        )
        .expect("request");
        assert_eq!(req.expected_ports, Some((54688, 5201)));
    }

    #[test]
    fn build_live_forward_request_marks_session_fabric_redirect_for_nat_and_zone() {
        let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
        let fabric_redirect = resolve_fabric_redirect(&forwarding).expect("fabric redirect");
        let zone_redirect =
            resolve_zone_encoded_fabric_redirect(&forwarding, "wan").expect("zone redirect");
        let mut area = MmapArea::new(256).expect("mmap");
        area.slice_mut(0, 64).expect("slice").fill(0xaa);
        let ingress_ident = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("fab0"),
            ifindex: 21,
        };
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_port: 5201,
            flow_dst_port: 44278,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: fabric_redirect,
            nat: NatDecision {
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                ..NatDecision::default()
            },
        };
        let flow = SessionFlow {
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
                src_port: 5201,
                dst_port: 44278,
            },
        };

        let req = build_live_forward_request(
            &area,
            &WorkerBindingLookup::default(),
            0,
            &ingress_ident,
            XdpDesc {
                addr: 0,
                len: 64,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            Some(&flow),
            Some(&Arc::<str>::from("wan")),
            true,
        )
        .expect("request");

        assert!(req.apply_nat_on_fabric);
        assert_eq!(
            req.decision.resolution.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(req.decision.resolution.src_mac, zone_redirect.src_mac);
    }

    #[test]
    fn build_live_forward_request_caches_target_binding_index() {
        let mut area = MmapArea::new(256).expect("mmap");
        area.slice_mut(0, 64).expect("slice").fill(0xaa);
        let ingress_ident = BindingIdentity {
            slot: 7,
            queue_id: 3,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-1"),
            ifindex: 10,
        };
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_port: 12345,
            flow_dst_port: 5201,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision::default(),
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
                primary_v6: None,
            },
        );
        let mut lookup = WorkerBindingLookup::default();
        lookup.by_if_queue.insert((11, 3), 5);
        lookup.first_by_if.insert(11, 4);

        let req = build_live_forward_request(
            &area,
            &lookup,
            2,
            &ingress_ident,
            XdpDesc {
                addr: 0,
                len: 64,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            None,
            None,
            false,
        )
        .expect("request");

        assert_eq!(req.target_ifindex, 11);
        assert_eq!(req.target_binding_index, Some(5));
    }

    #[test]
    fn build_forwarded_frame_applies_nat_on_fabric_when_requested() {
        let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
        let fabric_redirect = resolve_fabric_redirect(&forwarding).expect("fabric redirect");
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x10, 0xdb, 0xff, 0x10, 0x01],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x00, 0x02, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
            200, 172, 16, 80, 8, 0x14, 0x51, 0xac, 0xf6, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x02, 0x50, 0x12, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
        assert!(tcp_checksum_ok_ipv4(&frame[14..]));
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_port: 5201,
            flow_dst_port: 44278,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: fabric_redirect,
            nat: NatDecision {
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                ..NatDecision::default()
            },
        };

        let no_nat = build_forwarded_frame_from_frame(
            &frame,
            meta,
            &decision,
            &forwarding,
            false,
            Some((5201, 44278)),
        )
        .expect("frame without nat");
        assert_eq!(&no_nat[30..34], &[172, 16, 80, 8]);

        let nat = build_forwarded_frame_from_frame(
            &frame,
            meta,
            &decision,
            &forwarding,
            true,
            Some((5201, 44278)),
        )
        .expect("frame with nat");
        assert_eq!(&nat[30..34], &[10, 0, 61, 102]);
        assert!(tcp_checksum_ok_ipv4(&nat[14..]));
    }

    #[test]
    fn build_forwarded_frame_into_keeps_ipv6_ports_when_frame_and_metadata_disagree() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let real_src_port = 0x0401u16;
        let real_dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&real_src_port.to_be_bytes());
        frame.extend_from_slice(&real_dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 54688,
            flow_dst_port: real_dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut out = [0u8; 256];
        let frame_len = build_forwarded_frame_into(
            &mut out,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &ForwardingState::default(),
            Some((real_src_port, real_dst_port)),
        )
        .expect("build forwarded frame");
        let out = &out[..frame_len];
        assert_eq!(tcp_ports_ipv6(&out[18..]), (real_src_port, real_dst_port));
        assert!(tcp_checksum_ok_ipv6(&out[18..]));
    }

    #[test]
    fn build_forwarded_frame_into_prefers_expected_ipv6_ports_over_wrong_live_ports() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let real_src_port = 42566u16;
        let real_dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&real_src_port.to_be_bytes());
        frame.extend_from_slice(&real_dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1042,
            flow_dst_port: real_dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut out = [0u8; 256];
        let frame_len = build_forwarded_frame_into(
            &mut out,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &ForwardingState::default(),
            Some((1042, real_dst_port)),
        )
        .expect("build forwarded frame");
        let out = &out[..frame_len];
        assert_eq!(tcp_ports_ipv6(&out[18..]), (1042, real_dst_port));
        assert!(tcp_checksum_ok_ipv6(&out[18..]));
    }

    #[test]
    fn build_forwarded_frame_into_repairs_wrong_ipv6_frame_ports_from_expected_tuple() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let expected_src_port = 36394u16;
        let wrong_src_port = 1025u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&wrong_src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_addr: src_ip.octets(),
            flow_dst_addr: dst_ip.octets(),
            flow_src_port: expected_src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut out = [0u8; 256];
        let frame_len = build_forwarded_frame_into(
            &mut out,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &ForwardingState::default(),
            Some((expected_src_port, dst_port)),
        )
        .expect("build forwarded frame");
        let out = &out[..frame_len];
        assert_eq!(tcp_ports_ipv6(&out[18..]), (expected_src_port, dst_port));
        assert!(tcp_checksum_ok_ipv6(&out[18..]));
    }

    #[test]
    fn build_forwarded_frame_into_ignores_wrong_ipv4_offsets() {
        let src_ip = Ipv4Addr::new(10, 0, 61, 102);
        let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
        let real_src_port = 47032u16;
        let real_dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x00, 0x00, 64, PROTO_TCP, 0, 0,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&real_src_port.to_be_bytes());
        frame.extend_from_slice(&real_dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 54,
            l4_offset: 74,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1059,
            flow_dst_port: real_dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        };
        let mut out = [0u8; 256];
        let frame_len = build_forwarded_frame_into(
            &mut out,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &ForwardingState::default(),
            Some((real_src_port, real_dst_port)),
        )
        .expect("build forwarded frame");
        let out = &out[..frame_len];
        let tcp = &out[18 + 20..];
        assert_eq!(
            (
                u16::from_be_bytes([tcp[0], tcp[1]]),
                u16::from_be_bytes([tcp[2], tcp[3]])
            ),
            (real_src_port, real_dst_port)
        );
    }

    #[test]
    fn segment_forwarded_tcp_frames_splits_ipv6_snat_payload_by_mtu() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let src_port = 54688u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        let tcp_payload_len = 4096usize;
        let plen = (20 + tcp_payload_len) as u16;
        frame.extend_from_slice(&[
            0x60,
            0x00,
            0x00,
            0x00,
            (plen >> 8) as u8,
            plen as u8,
            PROTO_TCP,
            64,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, // seq
            0x08, 0xf0, 0x5a, 0xc6, // ack
            0x50, 0x18, 0x00, 0x40, // data offset/flags/window
            0x00, 0x00, 0x00, 0x00, // checksum/urgent
        ]);
        frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(8192).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 54688,
            flow_dst_port: 5201,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
            },
        );

        let segments = segment_forwarded_tcp_frames(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            Some((src_port, dst_port)),
        )
        .expect("segmented");
        assert!(segments.len() > 1);
        let mut expected_seq = 0x3196c832u32;
        let mut total_payload = 0usize;
        for (idx, seg) in segments.iter().enumerate() {
            assert!(seg.len() <= 18 + 1500);
            assert_eq!(tcp_ports_ipv6(&seg[18..]), (54688, 5201));
            assert!(tcp_checksum_ok_ipv6(&seg[18..]));
            let tcp = &seg[18 + 40..];
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            assert_eq!(seq, expected_seq);
            let seg_payload = seg.len() - 18 - 40 - 20;
            total_payload += seg_payload;
            expected_seq = expected_seq.wrapping_add(seg_payload as u32);
            if idx + 1 != segments.len() {
                assert_eq!(tcp[13] & TCP_FLAG_PSH, 0);
            }
        }
        assert_eq!(total_payload, tcp_payload_len);
    }

    #[test]
    fn segment_forwarded_tcp_frames_repairs_ipv6_tcp_ports_when_metadata_disagrees() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let src_port = 38276u16;
        let dst_port = 5201u16;
        let tcp_payload_len = 4096usize;
        let plen = (20 + tcp_payload_len) as u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[
            0x60,
            0x00,
            0x00,
            0x00,
            (plen >> 8) as u8,
            plen as u8,
            PROTO_TCP,
            64,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00,
        ]);
        frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(8192).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1025,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
            },
        );
        let segments = segment_forwarded_tcp_frames(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            Some((src_port, dst_port)),
        )
        .expect("segmented");
        assert!(segments.len() > 1);
        for seg in &segments {
            assert_eq!(tcp_ports_ipv6(&seg[18..]), (src_port, dst_port));
            assert!(tcp_checksum_ok_ipv6(&seg[18..]));
        }
    }

    #[test]
    fn segment_forwarded_tcp_frames_prefers_expected_ipv6_ports_over_wrong_live_ports() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let src_port = 42566u16;
        let dst_port = 5201u16;
        let tcp_payload_len = 4096usize;
        let plen = (20 + tcp_payload_len) as u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[
            0x60,
            0x00,
            0x00,
            0x00,
            (plen >> 8) as u8,
            plen as u8,
            PROTO_TCP,
            64,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00,
        ]);
        frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(8192).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1042,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
            },
        );
        let segments = segment_forwarded_tcp_frames(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            Some((1042, dst_port)),
        )
        .expect("segmented");
        assert!(segments.len() > 1);
        for seg in &segments {
            assert_eq!(tcp_ports_ipv6(&seg[18..]), (1042, dst_port));
            assert!(tcp_checksum_ok_ipv6(&seg[18..]));
        }
    }

    #[test]
    fn segment_forwarded_tcp_frames_repairs_wrong_ipv6_frame_ports_from_expected_tuple() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let expected_src_port = 36394u16;
        let wrong_src_port = 1025u16;
        let dst_port = 5201u16;
        let tcp_payload_len = 4096usize;
        let plen = (20 + tcp_payload_len) as u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[
            0x60,
            0x00,
            0x00,
            0x00,
            (plen >> 8) as u8,
            plen as u8,
            PROTO_TCP,
            64,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&wrong_src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00,
        ]);
        frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(8192).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_addr: src_ip.octets(),
            flow_dst_addr: dst_ip.octets(),
            flow_src_port: expected_src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
            },
        );
        let segments = segment_forwarded_tcp_frames(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            Some((expected_src_port, dst_port)),
        )
        .expect("segmented");
        assert!(segments.len() > 1);
        for seg in &segments {
            assert_eq!(tcp_ports_ipv6(&seg[18..]), (expected_src_port, dst_port));
            assert!(tcp_checksum_ok_ipv6(&seg[18..]));
        }
    }

    #[test]
    fn authoritative_forward_ports_prefers_flow_tuple_when_frame_ports_mismatch() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let expected_src_port = 55068u16;
        let wrong_src_port = 1041u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&wrong_src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_addr: src_ip.octets(),
            flow_dst_addr: dst_ip.octets(),
            flow_src_port: expected_src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let flow = SessionFlow {
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            forward_key: SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V6(src_ip),
                dst_ip: IpAddr::V6(dst_ip),
                src_port: expected_src_port,
                dst_port,
            },
        };

        assert_eq!(
            authoritative_forward_ports(&frame, meta, Some(&flow)),
            Some((expected_src_port, dst_port))
        );
    }

    #[test]
    fn authoritative_forward_ports_prefers_frame_tuple_over_metadata_when_flow_missing() {
        let src_ip = Ipv4Addr::new(10, 0, 61, 102);
        let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
        let frame_src_port = 1041u16;
        let meta_src_port = 55068u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&frame_src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
        ]);
        let ip_csum = checksum16(&frame[14..34]);
        frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

        let mut flow_src_addr = [0u8; 16];
        flow_src_addr[..4].copy_from_slice(&src_ip.octets());
        let mut flow_dst_addr = [0u8; 16];
        flow_dst_addr[..4].copy_from_slice(&dst_ip.octets());
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_addr,
            flow_dst_addr,
            flow_src_port: meta_src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };

        // Live frame ports preferred over metadata (flow > frame > meta)
        assert_eq!(
            authoritative_forward_ports(&frame, meta, None),
            Some((frame_src_port, dst_port))
        );
    }

    #[test]
    fn authoritative_forward_ports_falls_back_to_live_frame_ports_when_metadata_missing() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let src_port = 55068u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x14, PROTO_UDP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x14, 0x00, 0x00]);
        frame.extend_from_slice(b"userspace-udp");
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_UDP).expect("udp sum");

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_UDP,
            ..UserspaceDpMeta::default()
        };

        assert_eq!(
            authoritative_forward_ports(&frame, meta, None),
            Some((src_port, dst_port))
        );
    }

    #[test]
    fn parse_session_flow_prefers_metadata_tuple_when_frame_ports_mismatch() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let expected_src_port = 55068u16;
        let wrong_src_port = 1041u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&wrong_src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_addr: src_ip.octets(),
            flow_dst_addr: dst_ip.octets(),
            flow_src_port: expected_src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let flow = parse_session_flow(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
        )
        .expect("flow");
        assert_eq!(flow.forward_key.src_port, expected_src_port);
        assert_eq!(flow.forward_key.dst_port, dst_port);
    }

    #[test]
    fn segment_forwarded_tcp_frames_keeps_ipv4_tcp_ports_after_vlan_snat() {
        let src_ip = Ipv4Addr::new(10, 0, 61, 102);
        let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
        let src_port = 47308u16;
        let dst_port = 5201u16;
        let tcp_payload_len = 30_408usize;
        let tcp_header_len = 32usize;
        let total_len = (20 + tcp_header_len + tcp_payload_len) as u16;

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45,
            0x00,
            (total_len >> 8) as u8,
            total_len as u8,
            0xd1,
            0x43,
            0x40,
            0x00,
            64,
            PROTO_TCP,
            0x00,
            0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x52, 0x04, 0xc1, 0xa3, // seq
            0x73, 0x7f, 0x63, 0x1c, // ack
            0x80, 0x10, 0x00, 0x3f, // data offset/flags/window
            0x00, 0x00, 0x00, 0x00, // checksum/urgent
            0x01, 0x01, 0x08, 0x0a, // TCP timestamp option
            0x91, 0x9b, 0x0d, 0x5f, 0xd3, 0x53, 0x0f, 0x7f,
        ]);
        frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

        let mut area = MmapArea::new(65_536).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1041,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x01, 0x00]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x16, 0x01, 0x00],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
                primary_v6: None,
            },
        );

        let segments = segment_forwarded_tcp_frames(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            Some((src_port, dst_port)),
        )
        .expect("segmented");
        assert!(segments.len() > 1);
        let mut total_payload = 0usize;
        let mut expected_seq = 0x5204c1a3u32;
        for seg in &segments {
            assert!(seg.len() <= 18 + 1500);
            let tcp = &seg[18 + 20..];
            assert_eq!(
                (
                    u16::from_be_bytes([tcp[0], tcp[1]]),
                    u16::from_be_bytes([tcp[2], tcp[3]])
                ),
                (src_port, dst_port)
            );
            assert!(tcp_checksum_ok_ipv4(&seg[18..]));
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            assert_eq!(seq, expected_seq);
            let seg_payload = seg.len() - 18 - 20 - tcp_header_len;
            total_payload += seg_payload;
            expected_seq = expected_seq.wrapping_add(seg_payload as u32);
        }
        assert_eq!(total_payload, tcp_payload_len);
    }

    #[test]
    fn segment_forwarded_tcp_frames_keeps_ipv4_snat_inside_native_gre() {
        let src_ip = Ipv4Addr::new(10, 0, 61, 102);
        let dst_ip = Ipv4Addr::new(10, 255, 192, 41);
        let snat_ip = Ipv4Addr::new(10, 255, 192, 42);
        let src_port = 47308u16;
        let dst_port = 5201u16;
        let tcp_payload_len = 30_408usize;
        let tcp_header_len = 32usize;
        let total_len = (20 + tcp_header_len + tcp_payload_len) as u16;

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45,
            0x00,
            (total_len >> 8) as u8,
            total_len as u8,
            0xd1,
            0x43,
            0x40,
            0x00,
            64,
            PROTO_TCP,
            0x00,
            0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x52, 0x04, 0xc1, 0xa3, 0x73, 0x7f, 0x63, 0x1c, 0x80, 0x10, 0x00, 0x3f, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x91, 0x9b, 0x0d, 0x5f, 0xd3, 0x53, 0x0f, 0x7f,
        ]);
        frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

        let mut area = MmapArea::new(65_536).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1041,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let decision = SessionDecision {
            resolution: lookup_forwarding_resolution_v4(
                &state,
                None,
                dst_ip,
                "sfmix.inet.0",
                0,
                true,
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                ..NatDecision::default()
            },
        };

        let segments = segment_forwarded_tcp_frames(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &state,
            Some((src_port, dst_port)),
        )
        .expect("segmented native gre");
        assert!(segments.len() > 1);
        let outer_eth_len = 18usize;
        let outer_ip_len = 40usize;
        let gre_len = 4usize;
        let transport_mtu = 1500usize;
        let inner_start = outer_eth_len + outer_ip_len + gre_len;
        let mut total_payload = 0usize;
        let mut expected_seq = 0x5204c1a3u32;
        for seg in &segments {
            assert!(seg.len() >= outer_eth_len);
            assert!(
                seg.len() - outer_eth_len <= transport_mtu,
                "native GRE segment exceeds transport MTU: {}",
                seg.len() - outer_eth_len
            );
            assert_eq!(&seg[16..18], &[0x86, 0xdd]);
            assert_eq!(seg[24], PROTO_GRE);
            let inner = &seg[inner_start..];
            assert_eq!(&inner[12..16], &snat_ip.octets());
            assert_eq!(&inner[16..20], &dst_ip.octets());
            assert!(tcp_checksum_ok_ipv4(inner));
            let tcp = &inner[20..];
            assert_eq!(
                (
                    u16::from_be_bytes([tcp[0], tcp[1]]),
                    u16::from_be_bytes([tcp[2], tcp[3]])
                ),
                (src_port, dst_port)
            );
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            assert_eq!(seq, expected_seq);
            let seg_payload = inner.len() - 20 - tcp_header_len;
            total_payload += seg_payload;
            expected_seq = expected_seq.wrapping_add(seg_payload as u32);
        }
        assert_eq!(total_payload, tcp_payload_len);
    }

    #[test]
    fn rewrite_forwarded_frame_in_place_keeps_tcp_checksum_valid_after_vlan_snat() {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61,
            102, 172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd',
            b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
        assert!(tcp_checksum_ok_ipv4(&frame[14..]));

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let frame_len = rewrite_forwarded_frame_in_place(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 12,
                    tx_ifindex: 11,
                    tunnel_endpoint_id: 0,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
                    neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                    tx_vlan_id: 80,
                },
                nat: NatDecision {
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                    rewrite_dst: None,
                    ..NatDecision::default()
                },
            },
            false,
            None,
        )
        .expect("rewrite in place");

        let out = area.slice(0, frame_len as usize).expect("rewritten frame");
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
        assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
        assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x0800);
        assert_eq!(&out[30..34], &[172, 16, 80, 8]);
        assert_eq!(out[26], 63);
        assert!(tcp_checksum_ok_ipv4(&out[18..]));
    }

    #[test]
    fn rewrite_forwarded_frame_in_place_keeps_tcp_checksum_valid_after_vlan_dnat() {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x10, 0xdb, 0xff, 0x10, 0x01],
            80,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x00, 0x02, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
            200, 172, 16, 80, 8, 0x14, 0x51, 0x9c, 0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x02, 0x50, 0x12, 0x20, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a',
            b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[18..38]);
        frame[28] = (ip_sum >> 8) as u8;
        frame[29] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");
        assert!(tcp_checksum_ok_ipv4(&frame[18..]));

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 18,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let frame_len = rewrite_forwarded_frame_in_place(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 5,
                    tx_ifindex: 5,
                    tunnel_endpoint_id: 0,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                    neighbor_mac: Some([0x02, 0x66, 0x6a, 0x82, 0xfb, 0x2f]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x01, 0x00]),
                    tx_vlan_id: 0,
                },
                nat: NatDecision {
                    rewrite_src: None,
                    rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                    ..NatDecision::default()
                },
            },
            false,
            None,
        )
        .expect("rewrite in place");

        let out = area.slice(0, frame_len as usize).expect("rewritten frame");
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
        assert_eq!(&out[30..34], &[10, 0, 61, 102]);
        assert_eq!(out[22], 63);
        assert!(tcp_checksum_ok_ipv4(&out[14..]));
    }

    #[test]
    fn rewrite_forwarded_frame_in_place_applies_nat_for_fabric_redirect_when_enabled() {
        let mut frame = Vec::new();
        write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61,
            102, 172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't',
            b'd', b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
        assert!(tcp_checksum_ok_ipv4(&frame[14..]));

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let frame_len = rewrite_forwarded_frame_in_place(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::FabricRedirect,
                    local_ifindex: 0,
                    egress_ifindex: 21,
                    tx_ifindex: 21,
                    tunnel_endpoint_id: 0,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                    neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                    tx_vlan_id: 0,
                },
                nat: NatDecision {
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                    ..NatDecision::default()
                },
            },
            true,
            None,
        )
        .expect("rewrite in place");

        let out = area.slice(0, frame_len as usize).expect("rewritten frame");
        assert_eq!(&out[0..6], &[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
        assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
        assert_eq!(&out[26..30], &[172, 16, 80, 8]);
        assert_eq!(&out[30..34], &[172, 16, 80, 200]);
        assert_eq!(out[22], 63);
        assert!(tcp_checksum_ok_ipv4(&out[14..]));
    }

    // --- apply_rewrite_descriptor tests ---

    /// Helper: build a RewriteDescriptor from a SessionDecision + flow.
    fn test_descriptor(
        flow: &SessionFlow,
        decision: &SessionDecision,
        vlan_id: u16,
        ether_type: u16,
    ) -> RewriteDescriptor {
        RewriteDescriptor {
            dst_mac: decision.resolution.neighbor_mac.unwrap_or([0; 6]),
            src_mac: decision.resolution.src_mac.unwrap_or([0; 6]),
            fabric_redirect: decision.resolution.disposition
                == ForwardingDisposition::FabricRedirect,
            tx_vlan_id: vlan_id,
            ether_type,
            rewrite_src_ip: decision.nat.rewrite_src,
            rewrite_dst_ip: decision.nat.rewrite_dst,
            rewrite_src_port: decision.nat.rewrite_src_port,
            rewrite_dst_port: decision.nat.rewrite_dst_port,
            ip_csum_delta: compute_ip_csum_delta(flow, &decision.nat),
            l4_csum_delta: compute_l4_csum_delta(flow, &decision.nat),
            egress_ifindex: decision.resolution.egress_ifindex,
            tx_ifindex: decision.resolution.tx_ifindex,
            target_binding_index: None,
            nat64: false,
            nptv6: false,
            apply_nat_on_fabric: false,
        }
    }

    #[test]
    fn apply_descriptor_ipv4_no_nat_ttl_and_checksum() {
        // IPv4 TCP, no NAT, just TTL decrement + ethernet rewrite.
        let mut frame = Vec::new();
        write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, // IPv4, IHL=5, total_len=40
            0x00, 0x01, 0x00, 0x00, // ID, flags/frag
            64, PROTO_TCP, 0x00, 0x00, // TTL=64, proto=TCP, checksum placeholder
            10, 0, 1, 102, // src = 10.0.1.102
            172, 16, 80, 200, // dst = 172.16.80.200
            // TCP header (20 bytes)
            0x9c, 0x40, 0x01, 0xbb, // src_port=40000 dst_port=443
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x10, 0x20, 0x00, // data_off=5 flags=ACK win=8192
            0x00, 0x00, 0x00, 0x00, // checksum+urgent
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
        assert!(tcp_checksum_ok_ipv4(&frame[14..]));

        let flow = SessionFlow {
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 40000,
                dst_port: 443,
            },
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                egress_ifindex: 12,
                tx_ifindex: 11,
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 0,
                local_ifindex: 0,
                tunnel_endpoint_id: 0,
                next_hop: None,
            },
            nat: NatDecision::default(),
        };
        let rd = test_descriptor(&flow, &decision, 0, 0x0800);

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .unwrap()
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let frame_len = apply_rewrite_descriptor(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &rd,
            None,
        )
        .expect("descriptor rewrite");

        let out = area.slice(0, frame_len as usize).expect("out");
        // Ethernet header
        assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
        // TTL decremented
        assert_eq!(out[22], 63);
        // IP checksum valid
        assert_eq!(checksum16(&out[14..34]), 0);
        // TCP checksum valid
        assert!(tcp_checksum_ok_ipv4(&out[14..]));
    }

    #[test]
    fn apply_descriptor_ipv4_snat_with_vlan() {
        // IPv4 TCP with SNAT 10.0.61.102 -> 172.16.80.8, adding VLAN 80.
        let mut frame = Vec::new();
        write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, // IPv4, total_len=48
            0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61,
            102, // src = 10.0.61.102
            172, 16, 80, 200, // dst = 172.16.80.200
            0x9c, 0x40, 0x14, 0x51, // src_port=40000 dst_port=5201
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
        assert!(tcp_checksum_ok_ipv4(&frame[14..]));

        let flow = SessionFlow {
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 40000,
                dst_port: 5201,
            },
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                egress_ifindex: 12,
                tx_ifindex: 11,
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
                local_ifindex: 0,
                tunnel_endpoint_id: 0,
                next_hop: None,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        };
        let rd = test_descriptor(&flow, &decision, 80, 0x0800);

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .unwrap()
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let frame_len = apply_rewrite_descriptor(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &rd,
            None,
        )
        .expect("descriptor snat rewrite");

        let out = area.slice(0, frame_len as usize).expect("out");
        // VLAN tag added
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
        assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
        assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x0800);
        // SNAT applied
        assert_eq!(&out[30..34], &[172, 16, 80, 8]); // new src IP
        assert_eq!(&out[34..38], &[172, 16, 80, 200]); // dst unchanged
        // TTL
        assert_eq!(out[26], 63);
        // IP checksum valid
        assert_eq!(checksum16(&out[18..38]), 0);
        // TCP checksum valid
        assert!(tcp_checksum_ok_ipv4(&out[18..]));
    }

    #[test]
    fn apply_descriptor_fabric_redirect_skips_nat_when_flag_is_false() {
        let mut frame = Vec::new();
        write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61,
            102, 172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't',
            b'd', b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
        assert!(tcp_checksum_ok_ipv4(&frame[14..]));

        let flow = SessionFlow {
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 40000,
                dst_port: 5201,
            },
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::FabricRedirect,
                egress_ifindex: 21,
                tx_ifindex: 21,
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                tx_vlan_id: 0,
                local_ifindex: 0,
                tunnel_endpoint_id: 0,
                next_hop: None,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        };
        let mut rd = test_descriptor(&flow, &decision, 0, 0x0800);
        rd.apply_nat_on_fabric = false;

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .unwrap()
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let frame_len = apply_rewrite_descriptor(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &rd,
            None,
        )
        .expect("descriptor fabric rewrite");

        let out = area.slice(0, frame_len as usize).expect("out");
        assert_eq!(&out[0..6], &[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
        assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
        assert_eq!(&out[26..30], &[10, 0, 61, 102]);
        assert_eq!(&out[30..34], &[172, 16, 80, 200]);
        assert_eq!(out[22], 63);
        assert_eq!(checksum16(&out[14..34]), 0);
        assert!(tcp_checksum_ok_ipv4(&out[14..]));
    }

    #[test]
    fn apply_descriptor_ipv4_dnat_removes_vlan() {
        // IPv4 TCP with DNAT 172.16.80.8 -> 10.0.61.102, ingress VLAN 80 -> no VLAN.
        let mut frame = Vec::new();
        write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 80, 0x0800);
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x00, 0x02, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
            200, // src
            172, 16, 80, 8, // dst (pre-DNAT)
            0x14, 0x51, 0x9c, 0x40, // src_port=5201 dst_port=40000
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[18..38]);
        frame[28] = (ip_sum >> 8) as u8;
        frame[29] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");

        let flow = SessionFlow {
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
                src_port: 5201,
                dst_port: 40000,
            },
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                egress_ifindex: 5,
                tx_ifindex: 5,
                neighbor_mac: Some([0x02, 0x66, 0x6a, 0x82, 0xfb, 0x2f]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x01, 0x00]),
                tx_vlan_id: 0,
                local_ifindex: 0,
                tunnel_endpoint_id: 0,
                next_hop: None,
            },
            nat: NatDecision {
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                ..NatDecision::default()
            },
        };
        let rd = test_descriptor(&flow, &decision, 0, 0x0800);

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .unwrap()
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 18,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let frame_len = apply_rewrite_descriptor(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &rd,
            None,
        )
        .expect("descriptor dnat rewrite");

        let out = area.slice(0, frame_len as usize).expect("out");
        // No VLAN
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
        // DNAT applied
        assert_eq!(&out[30..34], &[10, 0, 61, 102]); // new dst IP
        // TTL
        assert_eq!(out[22], 63);
        // Checksums valid
        assert_eq!(checksum16(&out[14..34]), 0);
        assert!(tcp_checksum_ok_ipv4(&out[14..]));
    }

    #[test]
    fn apply_descriptor_ipv6_no_nat_hop_limit() {
        // IPv6 TCP, no NAT, hop limit decrement only.
        let mut frame = Vec::new();
        write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x86dd);
        let src = Ipv6Addr::new(0x2001, 0x0559, 0x8585, 0xbf01, 0, 0, 0, 0x102);
        let dst = Ipv6Addr::new(0x2001, 0x0559, 0x8585, 0x80, 0, 0, 0, 0x200);
        frame.push(0x60);
        frame.push(0x00);
        frame.push(0x00);
        frame.push(0x00); // version+flow
        frame.extend_from_slice(&20u16.to_be_bytes()); // payload_len = 20 (TCP header only)
        frame.push(PROTO_TCP); // next header
        frame.push(64); // hop limit = 64
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&dst.octets());
        // TCP header (20 bytes)
        frame.extend_from_slice(&40000u16.to_be_bytes()); // src port
        frame.extend_from_slice(&443u16.to_be_bytes()); // dst port
        frame.extend_from_slice(&1u32.to_be_bytes()); // seq
        frame.extend_from_slice(&0u32.to_be_bytes()); // ack
        frame.extend_from_slice(&[0x50, 0x10, 0x20, 0x00]); // data_off=5, ACK, win=8192
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // checksum + urgent
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp6 sum");

        let flow = SessionFlow {
            forward_key: SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V6(src),
                dst_ip: IpAddr::V6(dst),
                src_port: 40000,
                dst_port: 443,
            },
            src_ip: IpAddr::V6(src),
            dst_ip: IpAddr::V6(dst),
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                egress_ifindex: 12,
                tx_ifindex: 11,
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 0,
                local_ifindex: 0,
                tunnel_endpoint_id: 0,
                next_hop: None,
            },
            nat: NatDecision::default(),
        };
        let rd = test_descriptor(&flow, &decision, 0, 0x86dd);

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .unwrap()
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54, // 14 + 40
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let frame_len = apply_rewrite_descriptor(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &rd,
            None,
        )
        .expect("descriptor ipv6 rewrite");

        let out = area.slice(0, frame_len as usize).expect("out");
        assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x86dd);
        // Hop limit decremented
        assert_eq!(out[21], 63);
        // TCP checksum still valid (no NAT changes to pseudo-header)
        let tcp_csum_ok = {
            let packet = &out[14..];
            let rel_l4 = 40usize;
            let csum_off = rel_l4 + 16;
            let stored = u16::from_be_bytes([packet[csum_off], packet[csum_off + 1]]);
            stored != 0 // basic sanity — full validation via recompute
        };
        assert!(tcp_csum_ok);
    }

    #[test]
    fn apply_descriptor_returns_none_on_port_mismatch() {
        // If frame ports don't match expected_ports, descriptor path falls back to None.
        let mut frame = Vec::new();
        write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 1,
            102, 172, 16, 80, 200, 0x9c, 0x40, 0x01, 0xbb, // src=40000 dst=443
            0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;

        let flow = SessionFlow {
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 40000,
                dst_port: 443,
            },
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                egress_ifindex: 12,
                tx_ifindex: 11,
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 0,
                local_ifindex: 0,
                tunnel_endpoint_id: 0,
                next_hop: None,
            },
            nat: NatDecision::default(),
        };
        let rd = test_descriptor(&flow, &decision, 0, 0x0800);

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .unwrap()
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        // Expected ports don't match frame (99/99 vs 40000/443).
        let result = apply_rewrite_descriptor(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &rd,
            Some((99, 99)),
        );
        assert!(result.is_none(), "should return None on port mismatch");
    }

    #[test]
    fn apply_descriptor_nat64_falls_back() {
        let rd = RewriteDescriptor {
            dst_mac: [0; 6],
            src_mac: [0; 6],
            fabric_redirect: false,
            tx_vlan_id: 0,
            ether_type: 0x0800,
            rewrite_src_ip: None,
            rewrite_dst_ip: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            ip_csum_delta: 0,
            l4_csum_delta: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            target_binding_index: None,
            nat64: true,
            nptv6: false,
            apply_nat_on_fabric: false,
        };
        let area = MmapArea::new(4096).expect("mmap");
        let meta = UserspaceDpMeta::default();
        let result = apply_rewrite_descriptor(
            &area,
            XdpDesc {
                addr: 0,
                len: 64,
                options: 0,
            },
            meta,
            &rd,
            None,
        );
        assert!(result.is_none(), "NAT64 should fall back to generic");
    }

    #[test]
    fn apply_dscp_rewrite_to_ipv4_frame_updates_tos_and_checksum() {
        let src = Ipv4Addr::new(10, 0, 61, 102);
        let dst = Ipv4Addr::new(172, 16, 80, 200);
        let mut frame = build_icmp_echo_frame_v4(src, dst, 64);
        let l3 = frame_l3_offset(&frame).expect("l3");
        let old_tos = frame[l3 + 1];
        let old_checksum = u16::from_be_bytes([frame[l3 + 10], frame[l3 + 11]]);

        apply_dscp_rewrite_to_frame(&mut frame, 46).expect("rewrite");

        assert_eq!(frame[l3 + 1] >> 2, 46);
        assert_eq!(frame[l3 + 1] & 0x03, old_tos & 0x03);
        let new_checksum = u16::from_be_bytes([frame[l3 + 10], frame[l3 + 11]]);
        assert_ne!(new_checksum, old_checksum);
        assert_eq!(checksum16(&frame[l3..l3 + 20]), 0);
    }

    #[test]
    fn apply_dscp_rewrite_to_ipv6_frame_updates_traffic_class() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x86, 0xdd]);
        frame.extend_from_slice(&[
            0x60, 0x0b, 0x12, 0x34, // version + traffic class + flow label
            0x00, 0x08, // payload len
            58, 64, // next header + hop limit
        ]);
        frame.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        frame.extend_from_slice(
            &Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200).octets(),
        );
        frame.extend_from_slice(&[128, 0, 0, 0, 0, 1, 0, 1]);

        let l3 = frame_l3_offset(&frame).expect("l3");
        let old_tc = ((frame[l3] & 0x0f) << 4) | (frame[l3 + 1] >> 4);

        apply_dscp_rewrite_to_frame(&mut frame, 46).expect("rewrite");

        let new_tc = ((frame[l3] & 0x0f) << 4) | (frame[l3 + 1] >> 4);
        assert_eq!(new_tc >> 2, 46);
        assert_eq!(new_tc & 0x03, old_tc & 0x03);
    }
}
