use super::*;

pub(super) const FABRIC_INGRESS_FLAG: u8 = 0x80;

pub(super) fn packet_ttl_would_expire(frame: &[u8], meta: UserspaceDpMeta) -> Option<bool> {
    if (meta.meta_flags & FABRIC_INGRESS_FLAG) != 0 {
        return Some(false);
    }
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    match meta.addr_family as i32 {
        libc::AF_INET => Some(*frame.get(l3 + 8)? <= 1),
        libc::AF_INET6 => Some(*frame.get(l3 + 7)? <= 1),
        _ => None,
    }
}

pub(super) fn build_local_time_exceeded_request(
    frame: &[u8],
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    ingress_ident: &BindingIdentity,
    flow: &SessionFlow,
    forwarding: &ForwardingState,
    _dynamic_neighbors: &Arc<ShardedNeighborMap>,
    _ha_state: &BTreeMap<i32, HAGroupRuntime>,
    _now_secs: u64,
) -> Option<PendingForwardRequest> {
    if !matches!(packet_ttl_would_expire(frame, meta), Some(true)) {
        return None;
    }

    let egress = forwarding.egress.get(&ingress_ident.ifindex)?;
    let target_ifindex = if egress.bind_ifindex > 0 {
        egress.bind_ifindex
    } else {
        ingress_ident.ifindex
    };
    let prebuilt_frame = match meta.addr_family as i32 {
        libc::AF_INET => {
            build_local_time_exceeded_v4(frame, meta, ingress_ident.ifindex, forwarding)
        }
        libc::AF_INET6 => {
            build_local_time_exceeded_v6(frame, meta, ingress_ident.ifindex, forwarding)
        }
        _ => return None,
    }?;

    let now_ns = monotonic_nanos();
    let cos = resolve_cos_tx_selection_at(
        forwarding,
        ingress_ident.ifindex,
        meta,
        Some(&flow.forward_key),
        now_ns,
    );
    if cos.drop {
        return None;
    }
    Some(PendingForwardRequest {
        target_ifindex,
        target_binding_index: None,
        ingress_queue_id: ingress_ident.queue_id,
        desc,
        frame: PendingForwardFrame::Prebuilt(prebuilt_frame),
        meta: meta.into(),
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: ingress_ident.ifindex,
                tx_ifindex: target_ifindex,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: Some(egress.src_mac),
                tx_vlan_id: egress.vlan_id,
            },
            nat: NatDecision::default(),
        },
        apply_nat_on_fabric: false,
        expected_ports: None,
        flow_key: Some(flow.forward_key.clone()),
        nat64_reverse: None,
        cos_queue_id: cos.queue_id,
        dscp_rewrite: cos.dscp_rewrite,
        cos_tx_selection_resolved: true,
    })
}

/// Parse the inbound L2 header for a reflected local-origin reply:
/// swapped MACs plus the full ingress 802.1Q/802.1ad tag (TPID + TCI:
/// PCP, DEI, VID). #2149: this previously returned only `vlan_id: u16`,
/// collapsing VID 0 to untagged and dropping PCP/DEI/TPID — so a
/// priority-tagged VLAN-0 frame (a real tag with VID 0 and PCP != 0,
/// used for 802.1p priority-only QoS) was reflected untagged with its
/// priority lost, and an 802.1ad (0x88a8) tag was lost entirely.
/// Returning a `TxVlanTag` preserves the full tag so the reflected
/// error carries the original priority and TPID.
fn ingress_reply_l2(frame: &[u8]) -> Option<([u8; 6], [u8; 6], TxVlanTag)> {
    if frame.len() < 14 {
        return None;
    }
    let dst_mac = <[u8; 6]>::try_from(frame.get(0..6)?).ok()?;
    let src_mac = <[u8; 6]>::try_from(frame.get(6..12)?).ok()?;
    let eth_proto = u16::from_be_bytes([frame[12], frame[13]]);
    let ingress_tag = if matches!(eth_proto, TPID_8021Q | TPID_8021AD) {
        let tci = u16::from_be_bytes([*frame.get(14)?, *frame.get(15)?]);
        // Preserve the full TCI (PCP | DEI | VID) and the original TPID.
        // `present: true` makes a priority-tagged VID-0 frame reflect
        // its tag; an all-zero TCI degrades to untagged via `emits()`.
        TxVlanTag {
            tpid: eth_proto,
            tci,
            present: true,
        }
    } else {
        TxVlanTag::NONE
    };
    Some((src_mac, dst_mac, ingress_tag))
}

pub(super) fn build_local_time_exceeded_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    // ICMPv4 Time Exceeded: type 11, code 0.
    build_local_icmp_error_v4(frame, meta, ingress_ifindex, forwarding, 11, 0)
}

/// Build a local-origin ICMPv4 error message of the given type/code,
/// reflecting L2 (MAC swap + ingress VLAN), sourcing the outer IP from
/// the ingress interface primary v4, and quoting the inbound IP header
/// plus the first 8 L4 bytes (RFC 792). Shared by the Time Exceeded
/// builder (type 11) and the #2089 reject Destination Unreachable
/// builder (type 3, code 13).
pub(super) fn build_local_icmp_error_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
    icmp_type: u8,
    icmp_code: u8,
) -> Option<Vec<u8>> {
    let egress = forwarding.egress.get(&ingress_ifindex)?;
    let (dst_mac, fallback_src_mac, ingress_tag) = ingress_reply_l2(frame)?;
    let src_ip = egress.primary_v4?;
    let src_mac = egress.src_mac;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    let packet = frame.get(l3..)?;
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let dst_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let packet_len = total_len.min(packet.len());
    let quoted_len = packet_len.min(ihl.saturating_add(8));
    // #2149: reflect the inbound tag verbatim (TPID + PCP + DEI + VID)
    // when one was present, so a priority-tagged VLAN-0 inbound error
    // is reflected with its priority intact. Fall back to the egress
    // interface's configured VID (bare 802.1Q, PCP 0) when ingress was
    // untagged.
    let tag = if ingress_tag.emits() {
        ingress_tag
    } else {
        TxVlanTag::from(egress.vlan_id)
    };
    let eth_len = tag.header_len();
    let total_len = 20usize.checked_add(8)?.checked_add(quoted_len)?;
    let mut out = Vec::with_capacity(eth_len + total_len);
    write_eth_header_tagged(
        &mut out,
        dst_mac,
        if src_mac == [0; 6] {
            fallback_src_mac
        } else {
            src_mac
        },
        tag,
        0x0800,
    );
    // #1440: consolidated IPv4 outer builder. Sets DF=1 + computes
    // header checksum. Wire-byte change vs previous open-code:
    // ip[6..8] = 0x4000 (was 0x0000).
    let ip_start = out.len();
    out.resize(ip_start + 20, 0);
    write_ipv4_header(
        &mut out[ip_start..ip_start + 20],
        src_ip,
        dst_ip,
        PROTO_ICMP,
        /* tos */ 0,
        /* ttl */ 64,
        total_len as u16,
    )?;
    let icmp_start = out.len();
    out.extend_from_slice(&[icmp_type, icmp_code, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(packet.get(..quoted_len)?);
    let icmp_sum = checksum16(&out[icmp_start..]);
    out[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(out)
}

pub(super) fn build_local_time_exceeded_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    // ICMPv6 Time Exceeded: type 3, code 0.
    build_local_icmp_error_v6(frame, meta, ingress_ifindex, forwarding, 3, 0)
}

/// Build a local-origin ICMPv6 error message of the given type/code,
/// reflecting L2 (MAC swap + ingress VLAN), sourcing the outer IP from
/// the ingress interface primary v6, and quoting the inbound packet up
/// to 48 bytes (well under the RFC 4443 minimum-MTU cap). The ICMPv6
/// checksum (`checksum16_ipv6`) is computed over the pseudo-header and
/// is type-agnostic, so this is shared by the Time Exceeded builder
/// (type 3) and the #2089 reject Destination Unreachable builder
/// (type 1, code 1).
pub(super) fn build_local_icmp_error_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
    icmp_type: u8,
    icmp_code: u8,
) -> Option<Vec<u8>> {
    let egress = forwarding.egress.get(&ingress_ifindex)?;
    let (dst_mac, fallback_src_mac, ingress_tag) = ingress_reply_l2(frame)?;
    let src_ip = egress.primary_v6?;
    let src_mac = egress.src_mac;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    let packet = frame.get(l3..)?;
    if packet.len() < 40 {
        return None;
    }
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let packet_len = (40 + payload_len).min(packet.len());
    let quoted_len = packet_len.min(48);
    // #2149: preserve the inbound tag (TPID + PCP + DEI + VID) on the
    // reflected error; fall back to the egress configured VID when
    // ingress was untagged. See the v4 builder for the rationale.
    let tag = if ingress_tag.emits() {
        ingress_tag
    } else {
        TxVlanTag::from(egress.vlan_id)
    };
    let eth_len = tag.header_len();
    let outer_payload_len = 8usize.checked_add(quoted_len)?;
    let mut out = Vec::with_capacity(eth_len + 40 + outer_payload_len);
    write_eth_header_tagged(
        &mut out,
        dst_mac,
        if src_mac == [0; 6] {
            fallback_src_mac
        } else {
            src_mac
        },
        tag,
        0x86dd,
    );
    // #1440: consolidated IPv6 outer builder.
    let ip_start = out.len();
    out.resize(ip_start + 40, 0);
    write_ipv6_header(
        &mut out[ip_start..ip_start + 40],
        src_ip,
        dst_ip,
        PROTO_ICMPV6,
        /* traffic_class */ 0,
        /* flow_label */ 0,
        /* hop_limit */ 64,
        outer_payload_len as u16,
    )?;
    let icmp_start = out.len();
    out.extend_from_slice(&[icmp_type, icmp_code, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(packet.get(..quoted_len)?);
    let icmp_sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &out[icmp_start..]);
    out[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(out)
}

/// #2089 reject-action ICMP-error suppression guard, matching the
/// retired eBPF `send_icmp_unreach_*` dispatch verbatim: never generate
/// a Destination Unreachable in reply to an inbound ICMP/ICMPv6 *error*
/// message (RFC 792 / RFC 4443). This is intentionally a different (and
/// broader) set than [`is_icmp_error`], which the embedded-ICMP-NAT path
/// uses — the reject guard suppresses ICMPv4 types {3,4,5,11,12} and ALL
/// ICMPv6 types < 128 (the ICMPv6 error range). ICMP *query* types (echo
/// request/reply, etc.) are NOT suppressed: a rejected echo gets an
/// unreachable, matching Junos.
///
/// Returns true when a reject reply MUST be suppressed for this inbound
/// ICMP/ICMPv6 message.
pub(super) fn reject_icmp_reply_suppressed(protocol: u8, icmp_type: u8) -> bool {
    match protocol {
        PROTO_ICMP => matches!(icmp_type, 3 | 4 | 5 | 11 | 12),
        PROTO_ICMPV6 => icmp_type < 128,
        _ => false,
    }
}

/// Build the #2089 policy-`reject` ICMP/ICMPv6 Destination Unreachable
/// (administratively prohibited) reply for a rejected non-TCP flow:
/// ICMPv4 type 3 code 13, or ICMPv6 type 1 code 1 — the codes the
/// retired eBPF reject path used ("matching Junos reject behavior").
///
/// Returns `None` (caller fail-closes to a silent drop) when:
///   - the inbound is an ICMP/ICMPv6 *error* message
///     ([`reject_icmp_reply_suppressed`]),
///   - the inbound is a non-first fragment (no transport header to key),
///   - the ingress interface has no primary address of the inbound
///     family, or the frame is otherwise unparseable.
pub(super) fn build_reject_icmp_unreachable(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    let packet = frame.get(l3..)?;
    // Never reply to a non-first fragment (no L4 header to quote/key).
    if is_non_first_fragment(packet, meta.addr_family) {
        return None;
    }
    // Suppress replies to inbound ICMP/ICMPv6 error messages.
    if matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        let icmp_type = *frame.get(meta.l4_offset as usize)?;
        if reject_icmp_reply_suppressed(meta.protocol, icmp_type) {
            return None;
        }
    }
    match meta.addr_family as i32 {
        // ICMPv4 Destination Unreachable, code 13 (communication
        // administratively prohibited).
        libc::AF_INET => {
            build_local_icmp_error_v4(frame, meta, ingress_ifindex, forwarding, 3, 13)
        }
        // ICMPv6 Destination Unreachable, code 1 (communication with
        // destination administratively prohibited).
        libc::AF_INET6 => {
            build_local_icmp_error_v6(frame, meta, ingress_ifindex, forwarding, 1, 1)
        }
        _ => None,
    }
}

/// Returns true if the protocol and ICMP type indicate an ICMP error message
/// (Destination Unreachable, Time Exceeded, Parameter Problem, Packet Too Big).
pub(super) fn is_icmp_error(protocol: u8, icmp_type: u8) -> bool {
    match protocol {
        PROTO_ICMP => matches!(icmp_type, 3 | 11 | 12),
        PROTO_ICMPV6 => matches!(icmp_type, 1 | 2 | 3 | 4),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ICMP_IFINDEX: i32 = 24;
    const EGRESS_SRC_MAC: [u8; 6] = [0x02, 0xbf, 0x72, 0x00, 0x00, 0x01];

    /// A ForwardingState with one egress interface (the ingress index
    /// the reflected-error builders look up). `egress.vlan_id` is the
    /// fallback used when the inbound frame is untagged.
    fn forwarding_with_egress(vlan_id: u16) -> ForwardingState {
        let mut state = ForwardingState::default();
        state.egress.insert(
            ICMP_IFINDEX,
            EgressInterface {
                bind_ifindex: 0,
                vlan_id,
                mtu: 1500,
                src_mac: EGRESS_SRC_MAC,
                zone_id: 0,
                redundancy_group: 0,
                primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
                primary_v6: Some("2001:559:8585:80::8".parse().expect("v6")),
            },
        );
        state
    }

    #[derive(Clone, Copy)]
    enum InL2 {
        Untagged,
        /// 802.1p priority-tagged VLAN-0: TPID 0x8100, PCP 5, VID 0.
        PriorityTaggedVlan0,
        /// Normal 802.1Q tag, PCP 0, VID 100.
        Vlan100,
    }

    /// Build an inbound IPv4 UDP packet (so the reflected reply is a
    /// real error, not suppressed) with the chosen L2 header. The TTL
    /// is 1 so `build_local_time_exceeded_v4` fires; the builders read
    /// the inbound tag straight from the frame bytes.
    fn inbound_v4(l2: InL2) -> (Vec<u8>, UserspaceDpMeta) {
        let mut frame = Vec::new();
        let dst_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]; // firewall NIC
        let src_mac = [0x00, 0x25, 0x90, 0x12, 0x34, 0x56]; // sender
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);
        let l3_off: u16 = match l2 {
            InL2::Untagged => {
                frame.extend_from_slice(&0x0800u16.to_be_bytes());
                14
            }
            InL2::PriorityTaggedVlan0 => {
                frame.extend_from_slice(&0x8100u16.to_be_bytes());
                // TCI = PCP 5 << 13 | DEI 0 | VID 0 = 0xA000.
                frame.extend_from_slice(&0xA000u16.to_be_bytes());
                frame.extend_from_slice(&0x0800u16.to_be_bytes());
                18
            }
            InL2::Vlan100 => {
                frame.extend_from_slice(&0x8100u16.to_be_bytes());
                frame.extend_from_slice(&100u16.to_be_bytes());
                frame.extend_from_slice(&0x0800u16.to_be_bytes());
                18
            }
        };
        let l3 = frame.len();
        // IPv4 header, IHL 5, TTL 1, proto UDP, total_len = 20 + 8.
        frame.push(0x45);
        frame.push(0x00);
        frame.extend_from_slice(&28u16.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 1, 17, 0x00, 0x00]);
        frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets()); // src
        frame.extend_from_slice(&Ipv4Addr::new(172, 16, 80, 200).octets()); // dst
        let ip_csum = checksum16(&frame[l3..l3 + 20]);
        frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
        // 8-byte UDP header.
        frame.extend_from_slice(&49152u16.to_be_bytes());
        frame.extend_from_slice(&5201u16.to_be_bytes());
        frame.extend_from_slice(&8u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());

        let meta = UserspaceDpMeta {
            ingress_ifindex: ICMP_IFINDEX as u32,
            l3_offset: l3_off,
            addr_family: libc::AF_INET as u8,
            protocol: 17,
            ..UserspaceDpMeta::default()
        };
        (frame, meta)
    }

    /// #2149 regression: a priority-tagged VLAN-0 inbound frame
    /// (TPID 0x8100, PCP 5, VID 0) must have its tag — including PCP —
    /// reflected on the local-origin ICMP error. Pre-fix the builder
    /// gated tag emission on `vlan_id > 0`, so VID 0 collapsed to
    /// untagged (14-byte L2) and PCP was lost.
    #[test]
    fn reflected_v4_error_preserves_priority_tagged_vlan0() {
        let (frame, meta) = inbound_v4(InL2::PriorityTaggedVlan0);
        // Egress config VID is 0 (no membership) — the ONLY tag source
        // is the inbound priority tag, proving preservation rather than
        // an egress-config fallback.
        let fwd = forwarding_with_egress(0);
        let out =
            build_local_icmp_error_v4(&frame, meta, ICMP_IFINDEX, &fwd, 11, 0).expect("v4 error");

        assert_eq!(&out[12..14], &[0x81, 0x00], "reflected frame must carry an 802.1Q TPID");
        assert_eq!(
            &out[14..16],
            &[0xA0, 0x00],
            "reflected TCI must preserve PCP=5, VID=0 (the priority tag)"
        );
        // EtherType IPv4 follows the tag → L3 starts at byte 18.
        assert_eq!(&out[16..18], &[0x08, 0x00]);
        assert_eq!(out[18], 0x45, "IPv4 outer header starts at offset 18");
        // MACs swapped: reflected dst = inbound src.
        assert_eq!(&out[0..6], &[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
        assert_eq!(&out[6..12], &EGRESS_SRC_MAC);
    }

    /// A normal VID > 0 inbound tag is reflected unchanged (regression
    /// guard for the common path).
    #[test]
    fn reflected_v4_error_preserves_normal_vlan() {
        let (frame, meta) = inbound_v4(InL2::Vlan100);
        let fwd = forwarding_with_egress(0);
        let out =
            build_local_icmp_error_v4(&frame, meta, ICMP_IFINDEX, &fwd, 11, 0).expect("v4 error");
        assert_eq!(&out[12..14], &[0x81, 0x00]);
        assert_eq!(&out[14..16], &100u16.to_be_bytes(), "VID 100 preserved, PCP 0");
        assert_eq!(out[18], 0x45);
    }

    /// An untagged inbound frame stays untagged on the reflected error
    /// when the egress interface has no configured VID.
    #[test]
    fn reflected_v4_error_untagged_stays_untagged() {
        let (frame, meta) = inbound_v4(InL2::Untagged);
        let fwd = forwarding_with_egress(0);
        let out =
            build_local_icmp_error_v4(&frame, meta, ICMP_IFINDEX, &fwd, 11, 0).expect("v4 error");
        assert_eq!(&out[12..14], &[0x08, 0x00], "EtherType IPv4 at byte 12 (untagged)");
        assert_eq!(out[14], 0x45, "IPv4 outer header starts at offset 14");
    }

    /// An untagged inbound frame on an egress interface WITH a
    /// configured VID falls back to that VID (legacy egress behavior).
    #[test]
    fn reflected_v4_error_untagged_falls_back_to_egress_vid() {
        let (frame, meta) = inbound_v4(InL2::Untagged);
        let fwd = forwarding_with_egress(50);
        let out =
            build_local_icmp_error_v4(&frame, meta, ICMP_IFINDEX, &fwd, 11, 0).expect("v4 error");
        assert_eq!(&out[12..14], &[0x81, 0x00]);
        assert_eq!(&out[14..16], &50u16.to_be_bytes(), "egress VID 50 fallback");
    }
}
