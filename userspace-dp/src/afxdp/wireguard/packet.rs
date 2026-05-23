use crate::afxdp::frame::{checksum16, checksum16_add_bytes, checksum16_finish, checksum16_ipv4, checksum16_ipv6};
use crate::afxdp::{UserspaceDpMeta, USERSPACE_META_MAGIC, USERSPACE_META_VERSION};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) const PROTO_UDP: u8 = 17;
pub(crate) const WG_HEADER_LEN: usize = 32;

pub(crate) fn build_outer_headers(
    out: &mut [u8],
    ip_start: usize,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
    inner_tos_tc: u8,
    payload: &[u8],
) -> Option<UserspaceDpMeta> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let udp_start = ip_start + 20;
            if udp_start + 8 > out.len() {
                return None;
            }
            let total_len_u16 = u16::try_from(20 + 8 + payload_len).ok()?;
            let ip_hdr = out.get_mut(ip_start..ip_start + 20)?;
            ip_hdr[0] = 0x45;
            ip_hdr[1] = inner_tos_tc << 2;
            ip_hdr[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
            ip_hdr[4..8].copy_from_slice(&[0, 0, 0x40, 0]);
            ip_hdr[8] = 64;
            ip_hdr[9] = PROTO_UDP;
            ip_hdr[10..12].copy_from_slice(&[0, 0]);
            ip_hdr[12..16].copy_from_slice(&src.octets());
            ip_hdr[16..20].copy_from_slice(&dst.octets());
            let csum = checksum16(ip_hdr);
            ip_hdr[10..12].copy_from_slice(&csum.to_be_bytes());

            let udp = out.get_mut(udp_start..udp_start + 8)?;
            udp[0..2].copy_from_slice(&src_port.to_be_bytes());
            udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
            let udp_len = u16::try_from(8 + payload_len).ok()?;
            udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
            udp[6..8].copy_from_slice(&[0, 0]);

            let mut csum = checksum16_add_bytes(0, &src.octets());
            csum = checksum16_add_bytes(csum, &dst.octets());
            csum = checksum16_add_bytes(csum, &[0, PROTO_UDP]);
            csum = checksum16_add_bytes(csum, &udp_len.to_be_bytes());
            csum = checksum16_add_bytes(csum, udp);
            csum = checksum16_add_bytes(csum, payload);
            let udp_csum = {
                let c = checksum16_finish(csum);
                // RFC 768: transmitted checksum 0 means "no checksum"; use 0xFFFF.
                if c == 0 { 0xffff } else { c }
            };
            udp[6..8].copy_from_slice(&udp_csum.to_be_bytes());

            let mut meta = meta_for_outer(ip_start as u16, udp_start as u16, libc::AF_INET as u8, PROTO_UDP);
            meta.flow_src_port = src_port;
            meta.flow_dst_port = dst_port;
            meta.flow_src_addr[..4].copy_from_slice(&src.octets());
            meta.flow_dst_addr[..4].copy_from_slice(&dst.octets());
            Some(meta)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let udp_start = ip_start + 40;
            if udp_start + 8 > out.len() {
                return None;
            }
            let payload_len_u16 = u16::try_from(8 + payload_len).ok()?;
            let ip_hdr = out.get_mut(ip_start..ip_start + 40)?;
            // inner_tos_tc is the 6-bit DSCP value (right-justified,
            // per meta.dscp in xpf_helpers.h).  Shift left by 2 to
            // restore the full TOS/TC byte (ECN bits = 00), then
            // split across the IPv6 TC nibbles.  Set flow-label to
            // zero (bytes 1-3) rather than preserving garbage.
            let tc_byte = inner_tos_tc << 2;
            ip_hdr[0] = 0x60 | ((tc_byte >> 4) & 0x0f);
            ip_hdr[1] = (tc_byte & 0x0f) << 4;
            ip_hdr[2..4].copy_from_slice(&[0, 0]);
            ip_hdr[4..6].copy_from_slice(&payload_len_u16.to_be_bytes());
            ip_hdr[6] = PROTO_UDP;
            ip_hdr[7] = 64;
            ip_hdr[8..24].copy_from_slice(&src.octets());
            ip_hdr[24..40].copy_from_slice(&dst.octets());

            let udp = out.get_mut(udp_start..udp_start + 8)?;
            udp[0..2].copy_from_slice(&src_port.to_be_bytes());
            udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
            let udp_len = u16::try_from(8 + payload_len).ok()?;
            udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
            udp[6..8].copy_from_slice(&[0, 0]);

            let mut csum = checksum16_add_bytes(0, &src.octets());
            csum = checksum16_add_bytes(csum, &dst.octets());
            csum = checksum16_add_bytes(csum, &(u32::from(udp_len)).to_be_bytes());
            csum = checksum16_add_bytes(csum, &[0, 0, 0, PROTO_UDP]);
            csum = checksum16_add_bytes(csum, udp);
            csum = checksum16_add_bytes(csum, payload);
            let udp_csum = {
                let c = checksum16_finish(csum);
                // RFC 768: transmitted checksum 0 means "no checksum"; use 0xFFFF.
                // IPv6 UDP checksum is mandatory and zero is invalid (RFC 2460 §8.1).
                if c == 0 { 0xffff } else { c }
            };
            udp[6..8].copy_from_slice(&udp_csum.to_be_bytes());

            let mut meta = meta_for_outer(ip_start as u16, udp_start as u16, libc::AF_INET6 as u8, PROTO_UDP);
            meta.flow_src_port = src_port;
            meta.flow_dst_port = dst_port;
            meta.flow_src_addr.copy_from_slice(&src.octets());
            meta.flow_dst_addr.copy_from_slice(&dst.octets());
            Some(meta)
        }
        _ => None,
    }
}

pub(crate) fn meta_for_outer(l3_offset: u16, l4_offset: u16, addr_family: u8, protocol: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset,
        l4_offset,
        payload_offset: l4_offset + 8,
        addr_family,
        protocol,
        ..UserspaceDpMeta::default()
    }
}

pub(crate) fn dst_ip_from_meta(meta: &UserspaceDpMeta) -> IpAddr {
    match meta.addr_family as i32 {
        libc::AF_INET => {
            IpAddr::V4(Ipv4Addr::new(
                meta.flow_dst_addr[0],
                meta.flow_dst_addr[1],
                meta.flow_dst_addr[2],
                meta.flow_dst_addr[3],
            ))
        }
        _ => {
            IpAddr::V6(Ipv6Addr::from(meta.flow_dst_addr))
        }
    }
}

pub(crate) fn src_ip_from_meta(meta: &UserspaceDpMeta) -> IpAddr {
    match meta.addr_family as i32 {
        libc::AF_INET => {
            IpAddr::V4(Ipv4Addr::new(
                meta.flow_src_addr[0],
                meta.flow_src_addr[1],
                meta.flow_src_addr[2],
                meta.flow_src_addr[3],
            ))
        }
        _ => {
            IpAddr::V6(Ipv6Addr::from(meta.flow_src_addr))
        }
    }
}

pub(crate) fn packet_trimmed_len(packet: &[u8], addr_family: u8) -> Option<usize> {
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

pub(crate) fn parse_inner_protocol_and_offsets(packet: &[u8], addr_family: u8) -> Option<(u8, u16, u16)> {
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
                6 => {
                    if packet.len() < ihl + 20 {
                        return None;
                    }
                    let tcp_len = usize::from(packet[ihl + 12] >> 4) * 4;
                    if tcp_len < 20 || packet.len() < ihl + tcp_len {
                        return None;
                    }
                    l4_offset + tcp_len as u16
                }
                17 => l4_offset + 8,
                1 => l4_offset + 8,
                _ => l4_offset,
            };
            Some((protocol, l4_offset, payload_offset))
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let next_hdr = packet[6];
            if next_hdr == 0 || next_hdr == 60 || next_hdr == 43 || next_hdr == 44 || next_hdr == 51 || next_hdr == 50 || next_hdr == 135 {
                let mut offset = 40usize;
                let mut proto = next_hdr;
                loop {
                    if offset + 2 > packet.len() {
                        return None;
                    }
                    let ext_hdr_len = match proto {
                        0 | 60 => {
                            if offset + 1 > packet.len() {
                                return None;
                            }
                            (packet[offset + 1] as usize + 1) * 8
                        }
                        43 | 44 => {
                            if offset + 1 > packet.len() {
                                return None;
                            }
                            (packet[offset + 1] as usize) * 8 + 8
                        }
                        51 => {
                            if offset + 3 > packet.len() {
                                return None;
                            }
                            // RFC 4302 §2: Hdr Ext Len is count of 32-bit
                            // words minus 2.  Total = (payload_len + 2) * 4.
                            (packet[offset + 1] as usize + 2) * 4
                        }
                        135 => {
                            if offset + 1 > packet.len() {
                                return None;
                            }
                            (packet[offset + 1] as usize + 1) * 8
                        }
                        _ => break,
                    };
                    if offset + ext_hdr_len > packet.len() {
                        return None;
                    }
                    proto = packet[offset];
                    offset += ext_hdr_len;
                    if proto != 0 && proto != 60 && proto != 43 && proto != 44 && proto != 51 && proto != 135 {
                        let l4_off = offset as u16;
                        let payload_offset = match proto {
                            6 => {
                                if packet.len() < offset + 20 {
                                    return None;
                                }
                                let tcp_len = usize::from(packet[offset + 12] >> 4) * 4;
                                if tcp_len < 20 || packet.len() < offset + tcp_len {
                                    return None;
                                }
                                l4_off + tcp_len as u16
                            }
                            17 => l4_off + 8,
                            58 => l4_off + 8,
                            _ => l4_off,
                        };
                        return Some((proto, l4_off, payload_offset));
                    }
                }
            }
            let l4_offset = 40u16;
            let payload_offset = match next_hdr {
                6 => {
                    if packet.len() < 60 {
                        return None;
                    }
                    let tcp_len = usize::from(packet[52] >> 4) * 4;
                    if tcp_len < 20 || packet.len() < 40 + tcp_len {
                        return None;
                    }
                    l4_offset + tcp_len as u16
                }
                17 => l4_offset + 8,
                58 => l4_offset + 8,
                _ => l4_offset,
            };
            Some((next_hdr, l4_offset, payload_offset))
        }
        _ => None,
    }
}

pub(crate) fn packet_tcp_flags(packet: &[u8], _addr_family: u8, protocol: u8, rel_l4: u16) -> u8 {
    if protocol != 6 {
        return 0;
    }
    let l4 = rel_l4 as usize;
    packet.get(l4 + 13).copied().unwrap_or_default()
}

pub(crate) fn parse_endpoint(s: &str) -> Option<(IpAddr, u16)> {
    if s.is_empty() {
        return None;
    }
    if s.starts_with('[') {
        let close_bracket = s.find(']')?;
        let ip_str = &s[1..close_bracket];
        let port_str = s.get(close_bracket + 1..)?.strip_prefix(':')?;
        let ip: IpAddr = ip_str.parse().ok()?;
        let port: u16 = port_str.parse().ok()?;
        Some((ip, port))
    } else if let Some((host, port_str)) = s.rsplit_once(':') {
        let port: u16 = port_str.parse().ok()?;
        let ip: IpAddr = host.parse().ok()?;
        Some((ip, port))
    } else {
        None
    }
}
