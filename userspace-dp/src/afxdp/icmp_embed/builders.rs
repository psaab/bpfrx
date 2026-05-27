use super::*;

/// Rewrite an IPv4 ICMP error packet so it appears to originate from
/// (and be addressed to) the original pre-NAT client. Mirrors
/// `icmp_embed.rs:531-643` literally.
pub(in crate::afxdp::icmp_embed) fn build_nat_reversed_icmp_error_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    if l3 >= frame.len() || l4 >= frame.len() || l3 >= l4 {
        return None;
    }
    let packet = frame.get(l3..)?;
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 8 {
        return None;
    }

    let original_client = match icmp_match.original_src {
        IpAddr::V4(v4) => v4,
        _ => return None,
    };

    #[cfg(feature = "debug-log")]
    let _eth_len = l3;
    let dst_mac = icmp_match.resolution.neighbor_mac?;
    let src_mac = icmp_match.resolution.src_mac?;
    let vlan_id = icmp_match.resolution.tx_vlan_id;

    let ip_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let payload = if ip_total_len > 0 && ip_total_len < packet.len() {
        &packet[..ip_total_len]
    } else {
        packet
    };

    let out_eth_len = if vlan_id > 0 { 18 } else { 14 };
    let mut out = vec![0u8; out_eth_len + payload.len()];
    write_eth_header_slice(
        out.get_mut(..out_eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        0x0800,
    )?;
    out.get_mut(out_eth_len..)?.copy_from_slice(payload);

    let pkt = &mut out[out_eth_len..];

    pkt.get_mut(16..20)?
        .copy_from_slice(&original_client.octets());

    let icmp_offset = ihl;
    let emb_ip_offset = icmp_offset + 8;
    if pkt.len() < emb_ip_offset + 20 {
        return None;
    }
    let emb_ihl = ((pkt[emb_ip_offset] & 0x0f) as usize) * 4;
    if emb_ihl < 20 || pkt.len() < emb_ip_offset + emb_ihl {
        return None;
    }

    pkt.get_mut(emb_ip_offset + 12..emb_ip_offset + 16)?
        .copy_from_slice(&original_client.octets());

    {
        pkt.get_mut(emb_ip_offset + 10..emb_ip_offset + 12)?
            .copy_from_slice(&[0, 0]);
        let emb_ip_header = pkt.get(emb_ip_offset..emb_ip_offset + emb_ihl)?;
        let csum = checksum16(emb_ip_header);
        pkt.get_mut(emb_ip_offset + 10..emb_ip_offset + 12)?
            .copy_from_slice(&csum.to_be_bytes());
    }

    let emb_l4_offset = emb_ip_offset + emb_ihl;
    if icmp_match.nat.rewrite_src_port.is_some() || icmp_match.nat.rewrite_src.is_some() {
        let emb_proto = icmp_match.embedded_proto;
        if matches!(emb_proto, PROTO_TCP | PROTO_UDP) && pkt.len() >= emb_l4_offset + 2 {
            pkt.get_mut(emb_l4_offset..emb_l4_offset + 2)?
                .copy_from_slice(&icmp_match.original_src_port.to_be_bytes());
        } else if emb_proto == PROTO_ICMP && pkt.len() >= emb_l4_offset + 6 {
            let old_id_bytes = pkt.get(emb_l4_offset + 4..emb_l4_offset + 6)?;
            let old_id = u16::from_be_bytes([old_id_bytes[0], old_id_bytes[1]]);
            if old_id != icmp_match.original_src_port {
                pkt.get_mut(emb_l4_offset + 4..emb_l4_offset + 6)?
                    .copy_from_slice(&icmp_match.original_src_port.to_be_bytes());
                if pkt.len() >= emb_l4_offset + 4 {
                    let old_csum =
                        u16::from_be_bytes([pkt[emb_l4_offset + 2], pkt[emb_l4_offset + 3]]);
                    let new_csum =
                        checksum16_adjust(old_csum, &[old_id], &[icmp_match.original_src_port]);
                    pkt.get_mut(emb_l4_offset + 2..emb_l4_offset + 4)?
                        .copy_from_slice(&new_csum.to_be_bytes());
                }
            }
        }
    }

    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&[0, 0]);
    let icmp_data = pkt.get(icmp_offset..)?;
    let icmp_csum = checksum16(icmp_data);
    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&icmp_csum.to_be_bytes());

    pkt.get_mut(10..12)?.copy_from_slice(&[0, 0]);
    let ip_header = pkt.get(..ihl)?;
    let ip_csum = checksum16(ip_header);
    pkt.get_mut(10..12)?.copy_from_slice(&ip_csum.to_be_bytes());

    Some(out)
}

/// Rewrite an IPv6 ICMPv6 error packet so it appears to originate
/// from (and be addressed to) the original pre-NAT client. Mirrors
/// `icmp_embed.rs:645-734` literally.
pub(in crate::afxdp::icmp_embed) fn build_nat_reversed_icmp_error_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    if l3 >= frame.len() || l4 >= frame.len() || l3 >= l4 {
        return None;
    }
    let packet = frame.get(l3..)?;
    if packet.len() < 40 {
        return None;
    }

    let original_client_bytes = match icmp_match.original_src {
        IpAddr::V6(v6) => v6.octets(),
        _ => return None,
    };

    let dst_mac = icmp_match.resolution.neighbor_mac?;
    let src_mac = icmp_match.resolution.src_mac?;
    let vlan_id = icmp_match.resolution.tx_vlan_id;

    let ipv6_payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ip6_total = 40 + ipv6_payload_len;
    let payload = if ip6_total > 0 && ip6_total < packet.len() {
        &packet[..ip6_total]
    } else {
        packet
    };

    let out_eth_len = if vlan_id > 0 { 18 } else { 14 };
    let mut out = vec![0u8; out_eth_len + payload.len()];
    write_eth_header_slice(
        out.get_mut(..out_eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        0x86dd,
    )?;
    out.get_mut(out_eth_len..)?.copy_from_slice(payload);

    let pkt = &mut out[out_eth_len..];

    pkt.get_mut(24..40)?.copy_from_slice(&original_client_bytes);

    let icmp_offset = 40;
    let emb_ip_offset = icmp_offset + 8;
    if pkt.len() < emb_ip_offset + 40 {
        return None;
    }
    pkt.get_mut(emb_ip_offset + 8..emb_ip_offset + 24)?
        .copy_from_slice(&original_client_bytes);

    let emb_l4_offset = emb_ip_offset + 40;
    if icmp_match.nat.rewrite_src_port.is_some() || icmp_match.nat.rewrite_src.is_some() {
        let emb_proto = icmp_match.embedded_proto;
        if matches!(emb_proto, PROTO_TCP | PROTO_UDP) && pkt.len() >= emb_l4_offset + 2 {
            pkt.get_mut(emb_l4_offset..emb_l4_offset + 2)?
                .copy_from_slice(&icmp_match.original_src_port.to_be_bytes());
        } else if emb_proto == PROTO_ICMPV6 && pkt.len() >= emb_l4_offset + 6 {
            let old_id_bytes = pkt.get(emb_l4_offset + 4..emb_l4_offset + 6)?;
            let old_id = u16::from_be_bytes([old_id_bytes[0], old_id_bytes[1]]);
            if old_id != icmp_match.original_src_port {
                pkt.get_mut(emb_l4_offset + 4..emb_l4_offset + 6)?
                    .copy_from_slice(&icmp_match.original_src_port.to_be_bytes());
                if pkt.len() >= emb_l4_offset + 4 {
                    let old_csum =
                        u16::from_be_bytes([pkt[emb_l4_offset + 2], pkt[emb_l4_offset + 3]]);
                    let new_csum =
                        checksum16_adjust(old_csum, &[old_id], &[icmp_match.original_src_port]);
                    pkt.get_mut(emb_l4_offset + 2..emb_l4_offset + 4)?
                        .copy_from_slice(&new_csum.to_be_bytes());
                }
            }
        }
    }

    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&[0, 0]);
    let src_v6 = Ipv6Addr::from(<[u8; 16]>::try_from(pkt.get(8..24)?).ok()?);
    let dst_v6 = Ipv6Addr::from(<[u8; 16]>::try_from(pkt.get(24..40)?).ok()?);
    let icmp6_data = pkt.get(icmp_offset..)?;
    let icmp6_csum = checksum16_ipv6(src_v6, dst_v6, PROTO_ICMPV6, icmp6_data);
    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&icmp6_csum.to_be_bytes());

    Some(out)
}

/// Finalize the forwarding resolution attached to an embedded ICMP
/// match — enforce HA disposition, then re-redirect via fabric if the
/// local resolution turned into HAInactive/NoRoute/DiscardRoute.
/// Mirrors `icmp_embed.rs:736-761` literally.
pub(in crate::afxdp::icmp_embed) fn finalize_embedded_icmp_resolution(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    ingress_ifindex: i32,
    icmp_match: &EmbeddedIcmpMatch,
) -> ForwardingResolution {
    let enforced =
        enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, icmp_match.resolution);
    if !ingress_is_fabric(forwarding, ingress_ifindex)
        && matches!(
            enforced.disposition,
            ForwardingDisposition::HAInactive
                | ForwardingDisposition::NoRoute
                | ForwardingDisposition::DiscardRoute
        )
    {
        if let Some(redirect) = resolve_zone_encoded_fabric_redirect_by_id(
            forwarding,
            icmp_match.metadata.ingress_zone,
        ) {
            return redirect;
        }
    }
    redirect_via_fabric_if_needed(forwarding, enforced, ingress_ifindex)
}
