// TCP segmentation builders extracted from frame/mod.rs (#1046).
// `segment_forwarded_tcp_frames_from_frame` does the heavy lifting;
// `segment_forwarded_tcp_frames` is the XdpDesc adapter wrapper.
// Pure relocation — bodies are byte-for-byte identical; only the
// enclosing module is new and the visibility is rewritten from
// `pub(super)` (visible to afxdp via frame::*) to
// `pub(in crate::afxdp::frame)` so frame/mod.rs can `pub(in crate::afxdp) use` them.

use super::*;

pub(in crate::afxdp) fn segment_forwarded_tcp_frames_from_frame(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<Vec<u8>>> {
    let meta = meta.into();
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
    let enforced_ports = expected_ports.or(live_frame_ports_from_meta_bytes(frame, meta));
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
                let _post_src_ip = [packet[12], packet[13], packet[14], packet[15]];
                let _post_dst_ip = [packet[16], packet[17], packet[18], packet[19]];
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

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn segment_forwarded_tcp_frames(
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
