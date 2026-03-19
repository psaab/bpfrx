use super::*;

const GRE_FLAG_CHECKSUM: u16 = 0x8000;
const GRE_FLAG_ROUTING: u16 = 0x4000;
const GRE_FLAG_KEY: u16 = 0x2000;
const GRE_FLAG_SEQUENCE: u16 = 0x1000;
const GRE_VERSION_MASK: u16 = 0x0007;
const GRE_PROTO_IPV4: u16 = 0x0800;
const GRE_PROTO_IPV6: u16 = 0x86dd;

#[derive(Clone, Debug)]
pub(super) struct NativeGrePacket {
    pub(super) frame: Vec<u8>,
    pub(super) meta: UserspaceDpMeta,
}

fn parse_outer_addresses(frame: &[u8], meta: UserspaceDpMeta) -> Option<(IpAddr, IpAddr)> {
    let l3 = meta.l3_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            let end = l3.checked_add(20)?;
            if end > frame.len() {
                return None;
            }
            Some((
                IpAddr::V4(Ipv4Addr::new(
                    frame[l3 + 12],
                    frame[l3 + 13],
                    frame[l3 + 14],
                    frame[l3 + 15],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    frame[l3 + 16],
                    frame[l3 + 17],
                    frame[l3 + 18],
                    frame[l3 + 19],
                )),
            ))
        }
        libc::AF_INET6 => {
            let end = l3.checked_add(40)?;
            if end > frame.len() {
                return None;
            }
            Some((
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&frame[l3 + 8..l3 + 24]).ok()?,
                )),
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
                )),
            ))
        }
        _ => None,
    }
}

fn packet_trimmed_len(packet: &[u8], addr_family: u8) -> Option<usize> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if total_len == 0 || total_len > packet.len() {
                return None;
            }
            Some(total_len)
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            let total_len = 40usize.checked_add(payload_len)?;
            if total_len > packet.len() {
                return None;
            }
            Some(total_len)
        }
        _ => None,
    }
}

fn gre_inner_family_and_proto(proto: u16) -> Option<(u8, u16)> {
    match proto {
        GRE_PROTO_IPV4 => Some((libc::AF_INET as u8, 0x0800)),
        GRE_PROTO_IPV6 => Some((libc::AF_INET6 as u8, 0x86dd)),
        _ => None,
    }
}

fn match_tunnel_endpoint(
    forwarding: &ForwardingState,
    outer_family: i32,
    outer_src: IpAddr,
    outer_dst: IpAddr,
    key: u32,
    key_present: bool,
) -> Option<&TunnelEndpoint> {
    forwarding.tunnel_endpoints.values().find(|endpoint| {
        endpoint.outer_family == outer_family
            && endpoint.source == outer_dst
            && endpoint.destination == outer_src
            && if endpoint.key == 0 {
                !key_present || key == 0
            } else {
                key_present && endpoint.key == key
            }
    })
}

fn parse_inner_protocol_and_offsets(packet: &[u8], addr_family: u8) -> Option<(u8, u16, u16)> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            let protocol = packet[9];
            let l4_offset = ihl as u16;
            let payload_offset = match protocol {
                PROTO_TCP => {
                    if packet.len() < ihl + 20 {
                        return None;
                    }
                    let tcp_len = usize::from(packet[ihl + 12] >> 4) * 4;
                    if tcp_len < 20 || packet.len() < ihl + tcp_len {
                        return None;
                    }
                    l4_offset + tcp_len as u16
                }
                PROTO_UDP => l4_offset + 8,
                PROTO_ICMP => l4_offset + 8,
                _ => l4_offset,
            };
            Some((protocol, l4_offset, payload_offset))
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            // Use the extension-header-aware helper to get both the final L4
            // protocol and the correct offset. packet[6] may be an extension
            // header type, not the actual L4 protocol.
            let (l4_off, protocol) = packet_rel_l4_offset_and_protocol(packet, addr_family)?;
            let rel_l4 = l4_off as u16;
            let payload_offset = match protocol {
                PROTO_TCP => {
                    let l4 = rel_l4 as usize;
                    if packet.len() < l4 + 20 {
                        return None;
                    }
                    let tcp_len = usize::from(packet[l4 + 12] >> 4) * 4;
                    if tcp_len < 20 || packet.len() < l4 + tcp_len {
                        return None;
                    }
                    rel_l4 + tcp_len as u16
                }
                PROTO_UDP => rel_l4 + 8,
                PROTO_ICMPV6 => rel_l4 + 8,
                _ => rel_l4,
            };
            Some((protocol, rel_l4, payload_offset))
        }
        _ => None,
    }
}

fn packet_tcp_flags(packet: &[u8], _addr_family: u8, protocol: u8, rel_l4: u16) -> u8 {
    if protocol != PROTO_TCP {
        return 0;
    }
    let l4 = rel_l4 as usize;
    packet.get(l4 + 13).copied().unwrap_or_default()
}

pub(super) fn try_native_gre_decap_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> Option<NativeGrePacket> {
    if meta.protocol != PROTO_GRE {
        return None;
    }
    let gre_offset = meta.l4_offset as usize;
    let base = frame.get(gre_offset..gre_offset + 4)?;
    let flags_version = u16::from_be_bytes([base[0], base[1]]);
    if (flags_version & GRE_VERSION_MASK) != 0 {
        return None;
    }
    if (flags_version & (GRE_FLAG_CHECKSUM | GRE_FLAG_ROUTING)) != 0 {
        return None;
    }
    let key_present = (flags_version & GRE_FLAG_KEY) != 0;
    let sequence_present = (flags_version & GRE_FLAG_SEQUENCE) != 0;
    let gre_proto = u16::from_be_bytes([base[2], base[3]]);
    let (inner_family, inner_eth_proto) = gre_inner_family_and_proto(gre_proto)?;

    let mut inner_offset = gre_offset + 4;
    let mut key = 0u32;
    if key_present {
        key = u32::from_be_bytes(
            <[u8; 4]>::try_from(frame.get(inner_offset..inner_offset + 4)?).ok()?,
        );
        inner_offset += 4;
    }
    if sequence_present {
        frame.get(inner_offset..inner_offset + 4)?;
        inner_offset += 4;
    }
    let inner_packet = frame.get(inner_offset..)?;
    let inner_len = packet_trimmed_len(inner_packet, inner_family)?;
    let inner_packet = &inner_packet[..inner_len];

    let (outer_src, outer_dst) = parse_outer_addresses(frame, meta)?;
    let endpoint = match_tunnel_endpoint(
        forwarding,
        meta.addr_family as i32,
        outer_src,
        outer_dst,
        key,
        key_present,
    )?;
    let (protocol, rel_l4_offset, payload_offset) =
        parse_inner_protocol_and_offsets(inner_packet, inner_family)?;

    let mut synthetic = vec![0u8; 14 + inner_packet.len()];
    synthetic[12..14].copy_from_slice(&inner_eth_proto.to_be_bytes());
    synthetic[14..].copy_from_slice(inner_packet);

    let flow = parse_session_flow_from_frame(
        &synthetic,
        UserspaceDpMeta {
            addr_family: inner_family,
            protocol,
            ..UserspaceDpMeta::default()
        },
    );
    let mut flow_src_addr = [0u8; 16];
    let mut flow_dst_addr = [0u8; 16];
    let (src_port, dst_port) = flow
        .as_ref()
        .map(|flow| (flow.forward_key.src_port, flow.forward_key.dst_port))
        .unwrap_or_default();
    if let Some(flow) = flow.as_ref() {
        match flow.src_ip {
            IpAddr::V4(ip) => flow_src_addr[..4].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => flow_src_addr.copy_from_slice(&ip.octets()),
        }
        match flow.dst_ip {
            IpAddr::V4(ip) => flow_dst_addr[..4].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => flow_dst_addr.copy_from_slice(&ip.octets()),
        }
    }

    let ingress_zone = forwarding
        .ifindex_to_zone
        .get(&endpoint.logical_ifindex)
        .and_then(|zone| forwarding.zone_name_to_id.get(zone))
        .copied()
        .unwrap_or_default();
    let pkt_len = u16::try_from(inner_packet.len()).ok()?;
    let inner_meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: endpoint.logical_ifindex as u32,
        rx_queue_index: meta.rx_queue_index,
        ingress_vlan_id: 0,
        ingress_zone,
        l3_offset: 14,
        l4_offset: 14 + rel_l4_offset,
        payload_offset: 14 + payload_offset,
        pkt_len,
        addr_family: inner_family,
        protocol,
        tcp_flags: packet_tcp_flags(inner_packet, inner_family, protocol, rel_l4_offset),
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        flow_src_addr,
        flow_dst_addr,
        config_generation: meta.config_generation,
        fib_generation: meta.fib_generation,
        ..UserspaceDpMeta::default()
    };

    Some(NativeGrePacket {
        frame: synthetic,
        meta: inner_meta,
    })
}

pub(super) fn encapsulate_native_gre_frame(
    inner_frame: &[u8],
    inner_meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    let endpoint = forwarding
        .tunnel_endpoints
        .get(&decision.resolution.tunnel_endpoint_id)?;
    let dst_mac = decision.resolution.neighbor_mac?;
    let src_mac = decision.resolution.src_mac?;
    let vlan_id = decision.resolution.tx_vlan_id;
    let outer_eth_len = if vlan_id > 0 { 18 } else { 14 };
    let inner_l3 = match frame_l3_offset(inner_frame) {
        Some(offset) => offset,
        None => inner_meta.l3_offset as usize,
    };
    let inner_packet = inner_frame.get(inner_l3..)?.to_vec();
    let inner_len = packet_trimmed_len(&inner_packet, inner_meta.addr_family)?;
    let inner_packet = &inner_packet[..inner_len];

    let key_words = if endpoint.key != 0 { 1 } else { 0 };
    let gre_len = 4 + key_words * 4;
    let outer_ip_len = match endpoint.outer_family {
        libc::AF_INET => 20,
        libc::AF_INET6 => 40,
        _ => return None,
    };
    let frame_len = outer_eth_len + outer_ip_len + gre_len + inner_packet.len();
    let mut out = vec![0u8; frame_len];
    write_eth_header_slice(
        out.get_mut(..outer_eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        if endpoint.outer_family == libc::AF_INET {
            0x0800
        } else {
            0x86dd
        },
    )?;

    let outer_ip_start = outer_eth_len;
    let gre_start = outer_ip_start + outer_ip_len;
    let inner_start = gre_start + gre_len;
    out.get_mut(inner_start..)?
        .get_mut(..inner_packet.len())?
        .copy_from_slice(inner_packet);

    let gre_flags = if endpoint.key != 0 { GRE_FLAG_KEY } else { 0 };
    out[gre_start..gre_start + 2].copy_from_slice(&gre_flags.to_be_bytes());
    out[gre_start + 2..gre_start + 4].copy_from_slice(
        &(if inner_meta.addr_family as i32 == libc::AF_INET {
            GRE_PROTO_IPV4
        } else {
            GRE_PROTO_IPV6
        })
        .to_be_bytes(),
    );
    if endpoint.key != 0 {
        out[gre_start + 4..gre_start + 8].copy_from_slice(&endpoint.key.to_be_bytes());
    }

    match endpoint.outer_family {
        libc::AF_INET => {
            let src = match endpoint.source {
                IpAddr::V4(ip) => ip,
                _ => return None,
            };
            let dst = match endpoint.destination {
                IpAddr::V4(ip) => ip,
                _ => return None,
            };
            let total_len = u16::try_from(outer_ip_len + gre_len + inner_packet.len()).ok()?;
            let ip = out.get_mut(outer_ip_start..outer_ip_start + 20)?;
            ip[0] = 0x45;
            ip[1] = 0;
            ip[2..4].copy_from_slice(&total_len.to_be_bytes());
            ip[4..6].copy_from_slice(&0u16.to_be_bytes());
            ip[6..8].copy_from_slice(&0u16.to_be_bytes());
            ip[8] = if endpoint.ttl == 0 { 64 } else { endpoint.ttl };
            ip[9] = PROTO_GRE;
            ip[10..12].copy_from_slice(&[0, 0]);
            ip[12..16].copy_from_slice(&src.octets());
            ip[16..20].copy_from_slice(&dst.octets());
            let checksum = checksum16(ip);
            ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        libc::AF_INET6 => {
            let src = match endpoint.source {
                IpAddr::V6(ip) => ip,
                _ => return None,
            };
            let dst = match endpoint.destination {
                IpAddr::V6(ip) => ip,
                _ => return None,
            };
            let payload_len = u16::try_from(gre_len + inner_packet.len()).ok()?;
            let ip = out.get_mut(outer_ip_start..outer_ip_start + 40)?;
            ip[0] = 0x60;
            ip[1] = 0;
            ip[2] = 0;
            ip[3] = 0;
            ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
            ip[6] = PROTO_GRE;
            ip[7] = if endpoint.ttl == 0 { 64 } else { endpoint.ttl };
            ip[8..24].copy_from_slice(&src.octets());
            ip[24..40].copy_from_slice(&dst.octets());
        }
        _ => return None,
    }

    Some(out)
}
