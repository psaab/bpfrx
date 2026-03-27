use super::*;

/// Information returned from an embedded ICMP error session match that includes
/// NAT reversal data needed to rewrite the ICMP error packet back to the
/// original pre-NAT client.
#[derive(Clone, Debug)]
pub(super) struct EmbeddedIcmpMatch {
    /// The forward session's NAT decision (has rewrite_src for SNAT).
    pub(super) nat: NatDecision,
    /// The original (pre-NAT) source IP of the client.
    pub(super) original_src: IpAddr,
    /// The original source port (if port SNAT was applied).
    pub(super) original_src_port: u16,
    /// The embedded packet's L4 protocol.
    pub(super) embedded_proto: u8,
    /// Forwarding resolution toward the original client.
    pub(super) resolution: ForwardingResolution,
    /// Session metadata (zones, RG).
    pub(super) metadata: SessionMetadata,
}

/// Parse the embedded IP+L4 headers from an ICMP error payload and look up the
/// corresponding session. Returns the session lookup if found.
///
/// ICMP error format (after outer IP header):
///   [type(1)][code(1)][checksum(2)][unused(4)][ embedded IP header ... ]
///
/// The embedded IP header contains the original packet's src/dst and the first
/// 8 bytes of the original L4 header (enough for ports).
#[allow(dead_code)]
pub(super) fn try_embedded_icmp_session_match(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    now_ns: u64,
) -> Option<SessionLookup> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    try_embedded_icmp_session_match_from_frame(frame, meta, sessions, now_ns)
}

/// Core embedded ICMP session match logic operating on a frame slice.
pub(super) fn try_embedded_icmp_session_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    now_ns: u64,
) -> Option<SessionLookup> {
    let l4 = meta.l4_offset as usize;

    let icmp_type = *frame.get(l4)?;
    if !is_icmp_error(meta.protocol, icmp_type) {
        return None;
    }

    let embedded_ip_start = l4 + 8;

    match meta.protocol {
        PROTO_ICMP => {
            if frame.len() < embedded_ip_start + 28 {
                return None;
            }
            let ihl = ((frame[embedded_ip_start] & 0x0F) as usize) * 4;
            if ihl < 20 || frame.len() < embedded_ip_start + ihl + 4 {
                return None;
            }
            let emb_protocol = frame[embedded_ip_start + 9];
            let emb_src = IpAddr::V4(Ipv4Addr::new(
                frame[embedded_ip_start + 12],
                frame[embedded_ip_start + 13],
                frame[embedded_ip_start + 14],
                frame[embedded_ip_start + 15],
            ));
            let emb_dst = IpAddr::V4(Ipv4Addr::new(
                frame[embedded_ip_start + 16],
                frame[embedded_ip_start + 17],
                frame[embedded_ip_start + 18],
                frame[embedded_ip_start + 19],
            ));
            let emb_l4 = embedded_ip_start + ihl;
            let (emb_src_port, emb_dst_port) = if matches!(emb_protocol, PROTO_TCP | PROTO_UDP) {
                let bytes = frame.get(emb_l4..emb_l4 + 4)?;
                (
                    u16::from_be_bytes([bytes[0], bytes[1]]),
                    u16::from_be_bytes([bytes[2], bytes[3]]),
                )
            } else if matches!(emb_protocol, PROTO_ICMP) {
                let bytes = frame.get(emb_l4 + 4..emb_l4 + 6)?;
                (u16::from_be_bytes([bytes[0], bytes[1]]), 0)
            } else {
                (0, 0)
            };
            let embedded_key = SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: emb_protocol,
                src_ip: emb_src,
                dst_ip: emb_dst,
                src_port: emb_src_port,
                dst_port: emb_dst_port,
            };
            let reverse_key = embedded_reply_key(
                libc::AF_INET as u8,
                emb_protocol,
                emb_src,
                emb_dst,
                emb_src_port,
                emb_dst_port,
            );
            lookup_embedded_session(sessions, &embedded_key, &reverse_key, now_ns)
        }
        PROTO_ICMPV6 => {
            if frame.len() < embedded_ip_start + 48 {
                return None;
            }
            let emb_protocol = frame[embedded_ip_start + 6];
            let emb_src = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[embedded_ip_start + 8..embedded_ip_start + 24]).ok()?,
            ));
            let emb_dst = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[embedded_ip_start + 24..embedded_ip_start + 40])
                    .ok()?,
            ));
            let emb_l4 = embedded_ip_start + 40;
            let (emb_src_port, emb_dst_port) = if matches!(emb_protocol, PROTO_TCP | PROTO_UDP) {
                let bytes = frame.get(emb_l4..emb_l4 + 4)?;
                (
                    u16::from_be_bytes([bytes[0], bytes[1]]),
                    u16::from_be_bytes([bytes[2], bytes[3]]),
                )
            } else if matches!(emb_protocol, PROTO_ICMPV6) {
                let bytes = frame.get(emb_l4 + 4..emb_l4 + 6)?;
                (u16::from_be_bytes([bytes[0], bytes[1]]), 0)
            } else {
                (0, 0)
            };
            let embedded_key = SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: emb_protocol,
                src_ip: emb_src,
                dst_ip: emb_dst,
                src_port: emb_src_port,
                dst_port: emb_dst_port,
            };
            let reverse_key = embedded_reply_key(
                libc::AF_INET6 as u8,
                emb_protocol,
                emb_src,
                emb_dst,
                emb_src_port,
                emb_dst_port,
            );
            lookup_embedded_session(sessions, &embedded_key, &reverse_key, now_ns)
        }
        _ => None,
    }
}

/// Extended embedded ICMP session match that returns full NAT reversal info.
///
/// Unlike `try_embedded_icmp_session_match` which only confirms a match exists,
/// this function extracts the original (pre-NAT) source IP and port from the
/// matched session, and resolves forwarding toward the original client.
pub(super) fn try_embedded_icmp_nat_match(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
) -> Option<EmbeddedIcmpMatch> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    try_embedded_icmp_nat_match_from_frame(
        frame,
        meta,
        sessions,
        forwarding,
        dynamic_neighbors,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        now_ns,
    )
}

/// Core implementation of embedded ICMP NAT match operating on a frame slice.
pub(super) fn try_embedded_icmp_nat_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
) -> Option<EmbeddedIcmpMatch> {
    let l4 = meta.l4_offset as usize;
    let icmp_type = *frame.get(l4)?;
    if !is_icmp_error(meta.protocol, icmp_type) {
        return None;
    }

    let embedded_ip_start = l4 + 8;

    match meta.protocol {
        PROTO_ICMP => {
            if frame.len() < embedded_ip_start + 28 {
                return None;
            }
            let ihl = ((frame[embedded_ip_start] & 0x0F) as usize) * 4;
            if ihl < 20 || frame.len() < embedded_ip_start + ihl + 4 {
                return None;
            }
            let emb_protocol = frame[embedded_ip_start + 9];
            let emb_src_v4 = Ipv4Addr::new(
                frame[embedded_ip_start + 12],
                frame[embedded_ip_start + 13],
                frame[embedded_ip_start + 14],
                frame[embedded_ip_start + 15],
            );
            let emb_dst_v4 = Ipv4Addr::new(
                frame[embedded_ip_start + 16],
                frame[embedded_ip_start + 17],
                frame[embedded_ip_start + 18],
                frame[embedded_ip_start + 19],
            );
            let emb_src = IpAddr::V4(emb_src_v4);
            let emb_dst = IpAddr::V4(emb_dst_v4);
            let emb_l4 = embedded_ip_start + ihl;
            let (emb_src_port, emb_dst_port) = if matches!(emb_protocol, PROTO_TCP | PROTO_UDP) {
                let bytes = frame.get(emb_l4..emb_l4 + 4)?;
                (
                    u16::from_be_bytes([bytes[0], bytes[1]]),
                    u16::from_be_bytes([bytes[2], bytes[3]]),
                )
            } else if matches!(emb_protocol, PROTO_ICMP) {
                let bytes = frame.get(emb_l4 + 4..emb_l4 + 6)?;
                (u16::from_be_bytes([bytes[0], bytes[1]]), 0)
            } else {
                (0, 0)
            };
            let embedded_key = SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: emb_protocol,
                src_ip: emb_src,
                dst_ip: emb_dst,
                src_port: emb_src_port,
                dst_port: emb_dst_port,
            };
            let reverse_key = embedded_reply_key(
                libc::AF_INET as u8,
                emb_protocol,
                emb_src,
                emb_dst,
                emb_src_port,
                emb_dst_port,
            );
            if let Some(fwd) =
                lookup_forward_nat_across_scopes(sessions, shared_nat_sessions, &reverse_key)
            {
                let nat = fwd.decision.nat;
                let original_src = fwd.key.src_ip;
                let original_src_port = fwd.key.src_port;
                let resolution = embedded_icmp_return_resolution(
                    sessions,
                    shared_sessions,
                    shared_forward_wire_sessions,
                    forwarding,
                    dynamic_neighbors,
                    &fwd.key,
                    fwd.decision,
                    original_src,
                    now_ns,
                );
                return Some(EmbeddedIcmpMatch {
                    nat,
                    original_src,
                    original_src_port,
                    embedded_proto: emb_protocol,
                    resolution,
                    metadata: fwd.metadata,
                });
            }
            lookup_session_across_scopes(
                sessions,
                shared_sessions,
                shared_forward_wire_sessions,
                &embedded_key,
                now_ns,
                0,
            )
            .or_else(|| {
                lookup_session_across_scopes(
                    sessions,
                    shared_sessions,
                    shared_forward_wire_sessions,
                    &reverse_key,
                    now_ns,
                    0,
                )
            })
            .map(|resolved| {
                let sl = resolved.lookup;
                let resolution = if sl.metadata.is_reverse {
                    sl.decision.resolution
                } else {
                    embedded_icmp_return_resolution(
                        sessions,
                        shared_sessions,
                        shared_forward_wire_sessions,
                        forwarding,
                        dynamic_neighbors,
                        &embedded_key,
                        sl.decision,
                        emb_src,
                        now_ns,
                    )
                };
                EmbeddedIcmpMatch {
                    nat: sl.decision.nat,
                    original_src: emb_src,
                    original_src_port: emb_src_port,
                    embedded_proto: emb_protocol,
                    resolution,
                    metadata: sl.metadata,
                }
            })
        }
        PROTO_ICMPV6 => {
            if frame.len() < embedded_ip_start + 48 {
                return None;
            }
            let emb_protocol = frame[embedded_ip_start + 6];
            let emb_src_wire = Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[embedded_ip_start + 8..embedded_ip_start + 24]).ok()?,
            );
            let emb_dst = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[embedded_ip_start + 24..embedded_ip_start + 40])
                    .ok()?,
            ));
            let emb_l4 = embedded_ip_start + 40;
            let (emb_src_port, emb_dst_port) = if matches!(emb_protocol, PROTO_TCP | PROTO_UDP) {
                let bytes = frame.get(emb_l4..emb_l4 + 4)?;
                (
                    u16::from_be_bytes([bytes[0], bytes[1]]),
                    u16::from_be_bytes([bytes[2], bytes[3]]),
                )
            } else if matches!(emb_protocol, PROTO_ICMPV6) {
                let bytes = frame.get(emb_l4 + 4..emb_l4 + 6)?;
                (u16::from_be_bytes([bytes[0], bytes[1]]), 0)
            } else {
                (0, 0)
            };
            let mut emb_src_lookup_v6 = emb_src_wire;
            let _nptv6_reverse = forwarding.nptv6.translate_inbound(&mut emb_src_lookup_v6);
            let emb_src_lookup = IpAddr::V6(emb_src_lookup_v6);
            let embedded_key = SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: emb_protocol,
                src_ip: emb_src_lookup,
                dst_ip: emb_dst,
                src_port: emb_src_port,
                dst_port: emb_dst_port,
            };
            let reverse_key = embedded_reply_key(
                libc::AF_INET6 as u8,
                emb_protocol,
                emb_src_wire.into(),
                emb_dst,
                emb_src_port,
                emb_dst_port,
            );
            if let Some(fwd) =
                lookup_forward_nat_across_scopes(sessions, shared_nat_sessions, &reverse_key)
            {
                let nat = fwd.decision.nat;
                let original_src = fwd.key.src_ip;
                let original_src_port = fwd.key.src_port;
                let resolution = embedded_icmp_return_resolution(
                    sessions,
                    shared_sessions,
                    shared_forward_wire_sessions,
                    forwarding,
                    dynamic_neighbors,
                    &fwd.key,
                    fwd.decision,
                    original_src,
                    now_ns,
                );
                return Some(EmbeddedIcmpMatch {
                    nat,
                    original_src,
                    original_src_port,
                    embedded_proto: emb_protocol,
                    resolution,
                    metadata: fwd.metadata,
                });
            }
            lookup_session_across_scopes(
                sessions,
                shared_sessions,
                shared_forward_wire_sessions,
                &embedded_key,
                now_ns,
                0,
            )
            .or_else(|| {
                let shared_reverse_key = embedded_reply_key(
                    libc::AF_INET6 as u8,
                    emb_protocol,
                    emb_src_lookup,
                    emb_dst,
                    emb_src_port,
                    emb_dst_port,
                );
                lookup_session_across_scopes(
                    sessions,
                    shared_sessions,
                    shared_forward_wire_sessions,
                    &shared_reverse_key,
                    now_ns,
                    0,
                )
            })
            .map(|resolved| {
                let sl = resolved.lookup;
                let resolution = if sl.metadata.is_reverse {
                    sl.decision.resolution
                } else {
                    embedded_icmp_return_resolution(
                        sessions,
                        shared_sessions,
                        shared_forward_wire_sessions,
                        forwarding,
                        dynamic_neighbors,
                        &embedded_key,
                        sl.decision,
                        emb_src_lookup,
                        now_ns,
                    )
                };
                EmbeddedIcmpMatch {
                    nat: sl.decision.nat,
                    original_src: emb_src_lookup,
                    original_src_port: emb_src_port,
                    embedded_proto: emb_protocol,
                    resolution,
                    metadata: sl.metadata,
                }
            })
        }
        _ => None,
    }
}

fn embedded_icmp_return_resolution(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    forward_key: &SessionKey,
    forward_decision: SessionDecision,
    original_src: IpAddr,
    now_ns: u64,
) -> ForwardingResolution {
    let reverse_key = reverse_session_key(forward_key, forward_decision.nat);
    if let Some(reverse) = lookup_session_across_scopes(
        sessions,
        shared_sessions,
        shared_forward_wire_sessions,
        &reverse_key,
        now_ns,
        0,
    ) {
        return reverse.lookup.decision.resolution;
    }
    lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, original_src)
}

fn lookup_embedded_session(
    sessions: &mut SessionTable,
    embedded_key: &SessionKey,
    reverse_key: &SessionKey,
    now_ns: u64,
) -> Option<SessionLookup> {
    sessions
        .lookup(embedded_key, now_ns, 0)
        .or_else(|| sessions.lookup(reverse_key, now_ns, 0))
        .or_else(|| {
            sessions
                .find_forward_nat_match(reverse_key)
                .map(|m| SessionLookup {
                    decision: m.decision,
                    metadata: m.metadata,
                })
        })
}

fn embedded_reply_key(
    addr_family: u8,
    protocol: u8,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
) -> SessionKey {
    let (reply_src_port, reply_dst_port) = embedded_reply_ports(protocol, src_port, dst_port);
    SessionKey {
        addr_family,
        protocol,
        src_ip: dst_ip,
        dst_ip: src_ip,
        src_port: reply_src_port,
        dst_port: reply_dst_port,
    }
}

fn embedded_reply_ports(protocol: u8, src_port: u16, dst_port: u16) -> (u16, u16) {
    if matches!(protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (src_port, dst_port)
    } else {
        (dst_port, src_port)
    }
}

pub(super) fn build_nat_reversed_icmp_error_v4(
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

pub(super) fn build_nat_reversed_icmp_error_v6(
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

pub(super) fn finalize_embedded_icmp_resolution(
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
        if let Some(redirect) = resolve_zone_encoded_fabric_redirect(
            forwarding,
            icmp_match.metadata.ingress_zone.as_ref(),
        ) {
            return redirect;
        }
    }
    redirect_via_fabric_if_needed(forwarding, enforced, ingress_ifindex)
}
