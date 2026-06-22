// TCP segmentation builders extracted from frame/mod.rs (#1046).
// `segment_forwarded_tcp_frames_from_frame` does the heavy lifting;
// `segment_forwarded_tcp_frames` is the XdpDesc adapter wrapper.
// Pure relocation — bodies are byte-for-byte identical; only the
// enclosing module is new and the visibility is rewritten from
// `pub(super)` (visible to afxdp via frame::*) to `pub(in crate::afxdp)`
// so frame/mod.rs can re-export them at the same effective surface
// for tx/dispatch.rs's existing call sites.

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
    // #2329: mode-aware inner-L3 MTU. The pre-#2329 code used the GRE
    // inner-MTU formula for EVERY tunnel endpoint, so a WireGuard tunnel
    // got the GRE budget (~36-60 bytes too large) and the oversized
    // segments were built then dropped at the WG encap MTU guard
    // (`encap_mtu_drops`) — a blackhole. Dispatch on the endpoint's
    // `TunnelKind` (the #2327 classifier) and reuse the pad-aware WG SSOT
    // `wg::mss::wg_inner_mtu` (#2330) for WireGuard — do NOT re-derive WG
    // overhead here. An unknown/missing tunnel mode yields a 0 budget,
    // which short-circuits to `None` below (fail-closed) and matches the
    // encap dispatch's Unknown-drop arm.
    let mtu = if decision.resolution.tunnel_endpoint_id != 0 {
        // For a tunnel the inner-L3 budget is the encap-mode's exact inner
        // MTU; an Unknown/missing mode yields 0 → fail closed. Do NOT
        // floor a tunnel budget to 1280: a tunnel with a small outer MTU
        // has a genuinely smaller inner budget, and flooring it would
        // re-introduce the oversized-then-dropped blackhole this fix
        // exists to prevent. The 1280 floor stays on the plain-forward
        // path only (its historical semantics).
        let kind = forwarding
            .tunnel_endpoints
            .get(&decision.resolution.tunnel_endpoint_id)
            .map(|e| tunnel_mode_kind(&e.mode));
        match kind {
            Some(TunnelKind::Gre) => native_gre_inner_mtu(forwarding, decision),
            Some(TunnelKind::WireGuard) => {
                let endpoint = forwarding
                    .tunnel_endpoints
                    .get(&decision.resolution.tunnel_endpoint_id)?;
                let outer_mtu = tunnel_outer_mtu(forwarding, decision, endpoint);
                crate::afxdp::wg::mss::wg_inner_mtu(endpoint.outer_family, outer_mtu)
            }
            // Unknown mode or missing endpoint row: 0 budget → None below.
            Some(TunnelKind::Unknown) | None => 0,
        }
    } else {
        forwarding
            .egress
            .get(&decision.resolution.egress_ifindex)
            .or_else(|| forwarding.egress.get(&decision.resolution.tx_ifindex))
            .map(|egress| egress.mtu)
            .unwrap_or_default()
            .max(1280)
    };
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
                    // #2077: gate the TTL==1 drop on NOT-fabric-ingress,
                    // matching the IPv6 hop-limit gate below and the
                    // canonical build/rewrite paths (build/ipv4.rs,
                    // frame/mod.rs, rewrite/ipv4.rs). A fabric-ingress
                    // segment (FABRIC_INGRESS_FLAG = 0x80) was already
                    // decremented by the peer chassis at its real
                    // ingress; the fabric crossing is an internal
                    // cross-chassis redirect, not an IP hop, so the
                    // decrement below is suppressed and the drop must be
                    // too — otherwise a legitimately-low-TTL fabric
                    // segment is wrongly dropped here (v4 was the lone
                    // asymmetric site).
                    if (meta.meta_flags & 0x80) == 0 && packet[8] <= 1 {
                        return None;
                    }
                    if apply_nat {
                        // #1852: non_first_fragment=false — the segmentation
                        // admission gate (forwarded_tcp_may_need_segmentation)
                        // never admits a non-first fragment.
                        apply_nat_ipv4(packet, meta.protocol, decision.nat, false)?;
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
                    false,
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
                    // v6 payload length = ext-header bytes + TCP header
                    // + chunk. Each segment carries the FULL copied IP
                    // header including the extension chain
                    // (`ip_header_len` is the parsed ext-aware L4
                    // offset), so omitting `ip_header_len - 40` here
                    // under-stated the length for every ext-headered
                    // segment (#1838). Bit-identical for the no-ext
                    // case (ip_header_len == 40).
                    let v6_payload_len = (ip_header_len - 40) + tcp_header_len + chunk_len;
                    packet
                        .get_mut(4..6)?
                        .copy_from_slice(&(v6_payload_len as u16).to_be_bytes());
                    if (meta.meta_flags & 0x80) == 0 && packet[7] <= 1 {
                        return None;
                    }
                    if apply_nat {
                        // `ip_header_len` IS the ext-aware rel_l4: it is
                        // `frame_l4_offset - l3` and the segment copies
                        // the full IP header incl. the ext chain.
                        // #1852: non_first_fragment=false (admission gate).
                        apply_nat_ipv6(packet, ip_header_len, meta.protocol, decision.nat, false)?;
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
                    false,
                )?;
                let packet = frame_out.get_mut(eth_len..)?;
                recompute_l4_checksum_ipv6(packet, ip_header_len, meta.protocol)?;
            }
            _ => return None,
        }
        if decision.resolution.tunnel_endpoint_id != 0 {
            // #2329: mode-aware encap dispatch. The pre-#2329 code
            // unconditionally GRE-encapsulated EVERY tunnel's segmented
            // TCP, so a WireGuard endpoint's segments went out as GRE on
            // the wire (wrong protocol; for an inet WG endpoint it even
            // built a degenerate 0.0.0.0→0.0.0.0 outer). Mirror the #2327
            // build-egress dispatch in frame/mod.rs exactly: GRE→GRE,
            // WireGuard→the WG encap path (same `wg::wg_encap_frame` the
            // normal WG egress uses; it pulls the live noise session from
            // `forwarding.wg_engines` itself, so the seg site needs no
            // extra keystate), Unknown/missing→drop (fail closed, never
            // GRE-encap an unrecognized mode).
            let kind = forwarding
                .tunnel_endpoints
                .get(&decision.resolution.tunnel_endpoint_id)
                .map(|e| tunnel_mode_kind(&e.mode));
            let encapped = match kind {
                Some(TunnelKind::Gre) => {
                    encapsulate_native_gre_frame(&frame_out, meta, decision, forwarding)?
                }
                Some(TunnelKind::WireGuard) => {
                    wg::wg_encap_frame(&frame_out, meta, decision, forwarding)?
                }
                // Unknown mode or missing endpoint row: fail closed.
                Some(TunnelKind::Unknown) | None => return None,
            };
            out.push(encapped);
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

#[cfg(test)]
mod mode_aware_segmentation_tests {
    //! #2329 fail-on-revert tests for the mode-aware TCP-segmentation
    //! egress path. They lock in BOTH mode gates:
    //!
    //!   (a) inner-L3 MTU math — a WireGuard endpoint must size segments
    //!       to `wg::mss::wg_inner_mtu` (the pad-aware SSOT), NOT the
    //!       larger GRE inner-MTU. A GRE endpoint is unchanged.
    //!   (b) encap dispatch — a WireGuard endpoint's segments must be
    //!       WG/UDP-encapsulated (the same `wg::wg_encap_frame` the normal
    //!       egress uses), NEVER a GRE outer (proto-47). A GRE endpoint
    //!       still GRE-encaps; an unknown/missing mode drops (fail closed).
    //!
    //! If either gate is reverted to the pre-#2329 unconditional-GRE
    //! behavior these tests fail: the WG inner segments would exceed the
    //! WG budget (a) and/or carry a GRE outer (b).

    use super::*;
    use crate::afxdp::wg::session::{SessionRole, WgSession};
    use crate::afxdp::wg::{WgEngine, WgEngineConfig, WgPeerConfig};
    use crate::ip_proto::{PROTO_GRE, PROTO_UDP};
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    const TUN_ID: u16 = 1;
    const EGRESS_IFINDEX: i32 = 362;

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let kp = snow::Builder::new(crate::afxdp::wg::WG_NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let mut priv_k = [0u8; 32];
        let mut pub_k = [0u8; 32];
        priv_k.copy_from_slice(&kp.private);
        pub_k.copy_from_slice(&kp.public);
        (priv_k, pub_k)
    }

    /// Build an ESTABLISHED initiator/responder `WgEngine` pair. The
    /// initiator's peer endpoint is pre-configured so `peer_for_dest`
    /// resolves a concrete destination (no learned-endpoint dependency)
    /// and `try_encap` succeeds inside `wg_encap_frame`; the responder is
    /// returned so the test can decrypt the encapped segments and verify
    /// the inner sizing/protocol. Mirrors `wg::tests::established_pair`.
    fn established_engine_pair(peer_cidr: &str) -> (WgEngine, WgEngine) {
        let (init_priv, init_pub) = keypair();
        let (resp_priv, resp_pub) = keypair();
        let peer_ep: std::net::SocketAddr = "203.0.113.9:51820".parse().unwrap();

        let init_engine = WgEngine::new(WgEngineConfig {
            local_private_key: init_priv,
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: resp_pub,
                endpoint: Some(peer_ep),
                persistent_keepalive: 0,
                allowed_ips: vec![peer_cidr.parse().unwrap()],
                preshared_key: [0u8; 32],
            }],
        });
        let resp_engine = WgEngine::new(WgEngineConfig {
            local_private_key: resp_priv,
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: init_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                preshared_key: [0u8; 32],
            }],
        });

        // Drive a real Noise IKpsk2 handshake so the transport keys match,
        // then install both sessions with matching receiver indices.
        let mut init_hs = init_engine.build_initiator_handshake(&resp_pub).unwrap();
        let mut resp_hs = resp_engine.build_responder_handshake().unwrap();
        let mut buf = [0u8; 1024];
        let mut sink = [0u8; 1024];
        let n1 = init_hs.write_message(&[], &mut buf).unwrap();
        resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
        let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
        init_hs.read_message(&buf[..n2], &mut sink).unwrap();
        let init_xport = init_hs.into_stateless_transport_mode().unwrap();
        let resp_xport = resp_hs.into_stateless_transport_mode().unwrap();
        let now = crate::afxdp::wg::counters::monotonic_now_ns();
        let init_local = 0xaaaa_0001u32;
        let resp_local = 0xbbbb_0001u32;
        init_engine
            .install_session(
                &resp_pub,
                Arc::new(WgSession::new_with_role(
                    init_xport,
                    init_local,
                    resp_local,
                    resp_pub,
                    SessionRole::Initiator,
                    now,
                )),
            )
            .unwrap();
        let resp_session = Arc::new(WgSession::new_with_role(
            resp_xport,
            resp_local,
            init_local,
            init_pub,
            SessionRole::Responder,
            now,
        ));
        resp_session.mark_confirmed();
        resp_engine
            .install_session(&init_pub, resp_session)
            .unwrap();
        (init_engine, resp_engine)
    }

    fn wg_endpoint(outer_family: i32) -> TunnelEndpoint {
        TunnelEndpoint {
            id: TUN_ID,
            logical_ifindex: EGRESS_IFINDEX,
            interface_label: "wg0.0".to_string(),
            interface: "wg0.0".to_string(),
            redundancy_group: 0,
            mode: "wireguard".to_string(),
            outer_family,
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            key: 0,
            ttl: 64,
            transport_table: "inet.0".to_string(),
            wg_listen_port: 51820,
            wg_local_privkey: zeroize::Zeroizing::new([0u8; 32]),
            wg_peers: Vec::new(),
        }
    }

    fn gre_endpoint(outer_family: i32) -> TunnelEndpoint {
        TunnelEndpoint {
            mode: "gre".to_string(),
            ..wg_endpoint(outer_family)
        }
    }

    fn egress_iface(mtu: usize) -> EgressInterface {
        EgressInterface {
            bind_ifindex: EGRESS_IFINDEX,
            vlan_id: 0,
            mtu,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x50, 0x08],
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            primary_v6: None,
        }
    }

    /// Resolution that points the test endpoint at itself with both MACs
    /// resolved and `egress_ifindex == endpoint.logical_ifindex` (so the
    /// WG encap `#1873` R-C owner gate passes and the GRE builder builds).
    fn tunnel_resolution() -> ForwardingResolution {
        ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 12,
            egress_ifindex: EGRESS_IFINDEX,
            tx_ifindex: 12,
            tunnel_endpoint_id: TUN_ID,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        }
    }

    /// Build an L2 IPv4/TCP frame carrying `payload_len` bytes of data,
    /// inner src/dst chosen to land inside the WG peer's AllowedIPs.
    fn ipv4_tcp_frame(payload_len: usize) -> Vec<u8> {
        let src_ip = Ipv4Addr::new(10, 0, 0, 5);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 9);
        let src_port = 40000u16;
        let dst_port = 5201u16;
        let tcp_header_len = 20usize;
        let total_len = (20 + tcp_header_len + payload_len) as u16;

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0x02, 0xbf, 0x72, 0x00, 0x50, 0x08],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45,
            0x00,
            (total_len >> 8) as u8,
            total_len as u8,
            0x00,
            0x01,
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
        // seq, ack, data-offset (5<<4), flags (ACK), window, csum, urg.
        frame.extend_from_slice(&[
            0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0x00, 0x3f, 0x00, 0x00,
            0x00, 0x00,
        ]);
        frame.extend((0..payload_len).map(|i| (i & 0xff) as u8));
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
        frame
    }

    fn meta_v4() -> ForwardPacketMeta {
        ForwardPacketMeta {
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..ForwardPacketMeta::default()
        }
    }

    // ------- (a) MTU math -------------------------------------------

    #[test]
    fn wireguard_segmentation_uses_wg_inner_mtu_not_gre() {
        // At a 1500 v4 outer MTU the WG inner-L3 budget is 1425 (pad-aware:
        // 1500 - 20 IP - 8 UDP - 16 WG hdr - 16 tag, floored to a 16
        // multiple). The GRE inner budget would be 1476 (only IP+GRE). A
        // 2000-byte inner payload must therefore split with each inner IP
        // total length <= 1425, NOT <= 1476. A revert to GRE math sizes the
        // first segment to ~1476 and this assertion fails.
        let mtu = 1500usize;
        let wg_budget = crate::afxdp::wg::mss::wg_inner_mtu(libc::AF_INET, mtu);
        let gre_budget = 1476usize; // 1500 - 20 (IP) - 4 (GRE no-key)
        assert!(
            wg_budget < gre_budget,
            "test premise: WG inner budget ({wg_budget}) must be < GRE ({gre_budget})"
        );

        let (init_engine, resp_engine) = established_engine_pair("10.0.0.0/24");
        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(mtu));
        state
            .tunnel_endpoints
            .insert(TUN_ID, wg_endpoint(libc::AF_INET));
        state.wg_engines.insert(TUN_ID, Arc::new(init_engine));
        state.has_wg_tunnels = true;

        let decision = SessionDecision {
            resolution: tunnel_resolution(),
            nat: NatDecision::default(),
        };
        let frame = ipv4_tcp_frame(2000);
        let segments = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v4(),
            &decision,
            &state,
            false,
            None,
        )
        .expect("WG segmentation must produce frames");
        assert!(segments.len() > 1, "2000 inner must split at the WG budget");

        // Decrypt each segment back out of the WG outer ONCE (the WG engine
        // enforces anti-replay, so a segment may be decapped only once) and
        // collect the inner IPv4 total length. Confirm the UDP outer
        // (gate (b)) before measuring the inner size.
        let inner_lens: Vec<usize> = segments
            .iter()
            .map(|seg| {
                assert_eq!(seg[23], PROTO_UDP, "WG outer must be UDP, not GRE");
                wg_decap_inner_ipv4_total_len(seg, &resp_engine)
            })
            .collect();
        for inner_len in &inner_lens {
            assert!(
                *inner_len <= wg_budget,
                "WG segment inner IP total {inner_len} exceeds WG budget {wg_budget}"
            );
        }
        // The full (largest) segment must be sized exactly to the WG inner
        // budget (1425), NOT the larger GRE budget (1476). This is the
        // direct revert sentinel for the mode-aware MTU gate: a GRE-blind
        // revert would size the full segment to 1476.
        let max_inner = *inner_lens.iter().max().unwrap();
        assert_eq!(
            max_inner, wg_budget,
            "the full segment must be sized exactly to the WG inner budget, not GRE's {gre_budget}"
        );
    }

    #[test]
    fn gre_segmentation_inner_size_unchanged() {
        // The counterfactual GRE endpoint keeps the GRE inner budget: at a
        // 1500 outer MTU the largest inner IP total is 1476 (1500 - 20 - 4).
        let mtu = 1500usize;
        // IPv4-outer GRE, no key: inner budget = 1500 - 20 (outer IP) - 4
        // (GRE) = 1476.
        let gre_budget = native_gre_inner_mtu_for_test(mtu);
        assert_eq!(gre_budget, 1476, "GRE inner budget at 1500 MTU (v4 outer)");

        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(mtu));
        state
            .tunnel_endpoints
            .insert(TUN_ID, gre_endpoint(libc::AF_INET));
        let decision = SessionDecision {
            resolution: tunnel_resolution(),
            nat: NatDecision::default(),
        };
        let frame = ipv4_tcp_frame(2000);
        let segments = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v4(),
            &decision,
            &state,
            false,
            None,
        )
        .expect("GRE segmentation must produce frames");
        assert!(segments.len() > 1);
        // GRE outer is IPv4 (fixture outer_family inet): eth(14) + IPv4(20)
        // + GRE(4) + inner. Inner IP total length must reach the GRE budget,
        // proving the GRE math is untouched (still 1476, NOT the smaller WG
        // 1425 budget).
        let outer_eth = 14usize;
        let gre_inner_start = outer_eth + 20 + 4;
        let max_inner = segments
            .iter()
            .map(|s| {
                let inner = &s[gre_inner_start..];
                u16::from_be_bytes([inner[2], inner[3]]) as usize
            })
            .max()
            .unwrap();
        assert_eq!(
            max_inner, gre_budget,
            "GRE segment inner size must equal the (unchanged) GRE budget"
        );
        // Outer protocol is GRE, never UDP.
        for seg in &segments {
            assert_eq!(&seg[12..14], &[0x08, 0x00], "GRE v4 outer ethertype");
            // IPv4 protocol field is at offset 9 within the outer IP header.
            assert_eq!(seg[outer_eth + 9], PROTO_GRE, "GRE outer proto-47");
        }
    }

    // ------- (b) encap dispatch -------------------------------------

    #[test]
    fn wireguard_segmentation_emits_wg_outer_never_gre() {
        // Already covered by the MTU test's per-segment proto check, but
        // pinned independently so a future MTU-only refactor cannot drop
        // the encap-dispatch gate. Every emitted segment must be a WG/UDP
        // outer and decap cleanly; none may be GRE.
        let (init_engine, resp_engine) = established_engine_pair("10.0.0.0/24");
        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(1500));
        state
            .tunnel_endpoints
            .insert(TUN_ID, wg_endpoint(libc::AF_INET));
        state.wg_engines.insert(TUN_ID, Arc::new(init_engine));
        state.has_wg_tunnels = true;
        let decision = SessionDecision {
            resolution: tunnel_resolution(),
            nat: NatDecision::default(),
        };
        let frame = ipv4_tcp_frame(2000);
        let segments = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v4(),
            &decision,
            &state,
            false,
            None,
        )
        .expect("WG segmentation must produce frames");
        for seg in &segments {
            assert_eq!(&seg[12..14], &[0x08, 0x00], "WG v4 outer ethertype");
            assert_eq!(seg[23], PROTO_UDP, "WG outer proto must be UDP(17)");
            assert_ne!(seg[23], PROTO_GRE, "WG segment must never be GRE-encapped");
            // It must decap back to a valid inner IPv4 packet (a GRE-encapped
            // revert would NOT decrypt under the responder engine).
            let _ = wg_decap_inner_ipv4_total_len(seg, &resp_engine);
        }
    }

    #[test]
    fn unknown_tunnel_mode_segmentation_drops_fail_closed() {
        // An endpoint whose mode is neither GRE nor WireGuard must DROP
        // (return None) — never silently GRE-encap (the pre-#2327/#2329
        // fail-open default).
        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(1500));
        let mut ep = wg_endpoint(libc::AF_INET);
        ep.mode = "l2tp".to_string();
        state.tunnel_endpoints.insert(TUN_ID, ep);
        let decision = SessionDecision {
            resolution: tunnel_resolution(),
            nat: NatDecision::default(),
        };
        let frame = ipv4_tcp_frame(2000);
        let out = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v4(),
            &decision,
            &state,
            false,
            None,
        );
        assert!(
            out.is_none(),
            "unknown tunnel mode must fail closed (drop), not GRE-encap"
        );
    }

    #[test]
    fn missing_tunnel_endpoint_segmentation_drops_fail_closed() {
        // A non-zero tunnel_endpoint_id that resolves to no row must drop.
        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(1500));
        // Intentionally do NOT insert tunnel_endpoints[TUN_ID].
        let decision = SessionDecision {
            resolution: tunnel_resolution(),
            nat: NatDecision::default(),
        };
        let frame = ipv4_tcp_frame(2000);
        let out = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v4(),
            &decision,
            &state,
            false,
            None,
        );
        assert!(
            out.is_none(),
            "missing tunnel endpoint row must fail closed (drop)"
        );
    }

    // ------- decap helper -------------------------------------------

    /// Decrypt one WG/UDP outer segment with the responder `engine` and
    /// return the inner IPv4 total-length field. Panics on any decode
    /// failure (the test wants a hard failure if the outer is malformed or
    /// — the revert case — a GRE frame that this WG decap cannot read).
    fn wg_decap_inner_ipv4_total_len(seg: &[u8], engine: &WgEngine) -> usize {
        // outer eth(14) + IPv4(20) + UDP(8) = 42 → WG data record.
        let wg_record = &seg[42..];
        let mut plain = [0u8; 4096];
        let dec = engine
            .try_decap(wg_record, &mut plain)
            .expect("WG outer must decrypt (a GRE revert would not)");
        let inner = &plain[..dec.len];
        assert_eq!(inner[0] >> 4, 4, "decapped inner must be IPv4");
        u16::from_be_bytes([inner[2], inner[3]]) as usize
    }

    /// Mirror of the GRE inner-MTU arithmetic for the no-key v6-outer
    /// fixture (40-byte outer IP + 4-byte GRE), so the GRE-unchanged test
    /// asserts against an explicit constant rather than re-calling the
    /// private helper indirectly.
    fn native_gre_inner_mtu_for_test(outer_mtu: usize) -> usize {
        outer_mtu - 20 - 4
    }
}
