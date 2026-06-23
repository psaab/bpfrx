use super::*;

pub(super) const FABRIC_INGRESS_FLAG: u8 = 0x80;

/// RFC 1812 §4.3.2.7 / RFC 792 / RFC 4443 §2.4 error-suppression gate
/// for LOCALLY GENERATED ICMP/ICMPv6 error messages (Time Exceeded,
/// Destination Unreachable). A router MUST NOT originate an ICMP error
/// in response to:
///
///   (a) an ICMP/ICMPv6 *error* message (prevents error loops /
///       amplification) — ICMPv4 types {3,4,5,11,12}, all ICMPv6 < 128
///       (the ICMPv6 error range). ICMP *query* types (echo, etc.) are
///       NOT suppressed.
///   (b) a non-first IP fragment (no transport context to quote/key —
///       RFC 1812 §4.3.2.7 "a fragment other than the first").
///   (c) a packet whose IP destination is multicast/broadcast (L3), or
///       whose L2 destination is broadcast/multicast — never reply to a
///       group/broadcast solicitation.
///   (d) a packet whose IP source is the unspecified address, loopback,
///       multicast, or (v4) broadcast — there is no legitimate unicast
///       host to send the error to.
///
/// Returns `true` when an ICMP error reply MAY be generated, `false`
/// when it MUST be suppressed (the caller fail-closes to a silent drop).
/// Hot-path: cheap field reads only, no allocation; the fragment walk is
/// the same bounded extension-header loop already used on every packet.
///
/// `protocol`/`icmp_type`/fragment status are read from the inbound
/// frame; the L4/ICMP-type read uses `meta.l4_offset`, which the shim
/// fills for ICMP, matching [`build_reject_icmp_unreachable`].
///
/// `forwarding` supplies the connected-route table for the #2411
/// directed-broadcast check (RFC 1812 §4.3.2.7): an IPv4 destination
/// that is the all-ones host address of a configured connected subnet
/// (e.g. `10.0.1.255` for `10.0.1.0/24`) is a subnet-directed broadcast
/// and must also suppress the error. This is a cold-path lookup only —
/// the gate runs solely when an error is about to be generated.
pub(super) fn can_generate_icmp_error_reply(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> bool {
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => match frame_l3_offset(frame) {
            Some(off) => off,
            None => return false,
        },
    };
    let Some(packet) = frame.get(l3..) else {
        return false;
    };

    // (c) L2 destination: never reply to a broadcast/multicast frame.
    // The destination MAC is the first 6 frame bytes (present because
    // frame_l3_offset / the 14|18 match imply >= 14 bytes). Routes
    // through the shared #2325 predicate so the PTB and reject/TE paths
    // agree on the L2 group/broadcast test.
    if let Some(eth_dst) = frame.get(0..6)
        && let Ok(eth_dst) = <&[u8; 6]>::try_from(eth_dst)
        && l2_dst_is_group_or_broadcast(eth_dst)
    {
        return false;
    }

    // (b) non-first fragment: no transport header to quote/key.
    if is_non_first_fragment(packet, meta.addr_family) {
        return false;
    }

    match meta.addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return false;
            }
            // (d) bad source / (c) group or broadcast destination. Both
            // tests route through the shared predicates (#2367 source,
            // #2314 destination) so the PTB, reject, and Time Exceeded
            // paths agree on the disallowed source/destination sets.
            // #2411: also suppress for an IPv4 subnet-directed broadcast
            // (all-ones host of a connected prefix) — invisible to the
            // limited-broadcast test, needs the connected subnet mask.
            if source_is_invalid_for_icmp_error(meta.addr_family, packet)
                || dest_is_multicast_or_broadcast(meta.addr_family, packet)
                || dest_is_directed_broadcast(forwarding, packet)
            {
                return false;
            }
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return false;
            }
            // (d) bad source / (c) multicast destination. IPv6 has no
            // broadcast; multicast (ff00::/8) covers the group case. Both
            // tests route through the shared predicates (#2367 source,
            // #2314 destination).
            if source_is_invalid_for_icmp_error(meta.addr_family, packet)
                || dest_is_multicast_or_broadcast(meta.addr_family, packet)
            {
                return false;
            }
        }
        _ => return false,
    }

    // (a) never reply to an inbound ICMP/ICMPv6 error message.
    if matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        let l4 = meta.l4_offset as usize;
        // A zero/invalid l4_offset means we could not locate the ICMP
        // header — fail closed rather than reading a stale type byte.
        if l4 <= l3 {
            return false;
        }
        let Some(&icmp_type) = frame.get(l4) else {
            return false;
        };
        if reject_icmp_reply_suppressed(meta.protocol, icmp_type) {
            return false;
        }
    }

    true
}

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
    counters: &mut BatchCounters,
) -> Option<PendingForwardRequest> {
    if !matches!(packet_ttl_would_expire(frame, meta), Some(true)) {
        return None;
    }
    // #2237: RFC 1812 §4.3.2.7 / RFC 4443 §2.4 suppression — do not
    // originate a Time Exceeded in reply to an ICMP error, a non-first
    // fragment, a group/broadcast destination, or a bogus source. The
    // sibling reject path enforces the same contract via this gate.
    if !can_generate_icmp_error_reply(frame, meta, forwarding) {
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
    // #2238: classify the GENERATED ICMP/ICMPv6 error by its OWN egress
    // 5-tuple + the resolved egress interface (`target_ifindex`, which
    // accounts for `bind_ifindex`), NOT the triggering inbound packet's
    // tuple/ingress. Pre-#2238 this called
    // `resolve_cos_tx_selection_at(.., meta, flow.forward_key, ..)` — the
    // trigger — on `ingress_ident.ifindex`, so an output filter matching the
    // generated ICMP tuple never fired, and an output filter matching the
    // original TCP/UDP flow could wrongly drop the ICMP error. A parse
    // failure of our own built bytes fails CLOSED (drop + dedicated
    // counter, §6.2).
    let verdict = classify_generated_reply(forwarding, target_ifindex, &prebuilt_frame, now_ns);
    if verdict.drop {
        counters.touched = true;
        if verdict.parse_error {
            counters.generated_reply_classify_parse_errors += 1;
        } else {
            counters.time_exceeded_output_filter_drops += 1;
        }
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
        cos_queue_id: verdict.cos_queue_id,
        dscp_rewrite: verdict.dscp_rewrite,
        cos_tx_selection_resolved: true,
        // #2362 fold B: TX-selection already resolved above via
        // classify_generated_reply (which read the prebuilt frame), so the
        // deferred recompute path is never taken for this request — Default is
        // unused. The prebuilt frame was moved into `frame`, so it cannot be
        // re-read here regardless.
        filter_match_extra: crate::filter::TermMatchExtra::default(),
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
/// to the RFC 4443 minimum-MTU cap (1280 - 40 outer IPv6 - 8 ICMPv6 =
/// 1232 bytes, #2242), bounded by the invoking-packet length — so the
/// quote reaches the transport header even behind IPv6 extension
/// headers. The ICMPv6 checksum (`checksum16_ipv6`) is computed over
/// the pseudo-header and
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
    // #2242: RFC 4443 §2.4(c)/§3.1 — include as much of the invoking
    // packet as possible without the ICMPv6 error exceeding the IPv6
    // minimum MTU (1280). The total error datagram is
    //   40 (outer IPv6) + 8 (ICMPv6 header) + quoted_len <= 1280,
    // so quote up to 1280 - 40 - 8 = 1232 bytes. The previous fixed
    // 48-byte cap stopped just past the IPv6 base header and omitted the
    // transport header whenever extension headers pushed it past byte 48,
    // breaking PMTUD/traceroute diagnostics and receiver-side
    // error<->socket demux. Bounded by the actual invoking-packet length.
    const ICMP6_MIN_MTU: usize = 1280;
    const OUTER_V6_LEN: usize = 40;
    const ICMP6_HDR_LEN: usize = 8;
    const MAX_V6_QUOTE: usize = ICMP6_MIN_MTU - OUTER_V6_LEN - ICMP6_HDR_LEN; // 1232
    let quoted_len = packet_len.min(MAX_V6_QUOTE);
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
/// message (RFC 792 / RFC 4443). The reject guard suppresses ICMPv4 types
/// {3,4,5,11,12} and ALL ICMPv6 types < 128 (the ICMPv6 error range). ICMP
/// *query* types (echo request/reply, etc.) are NOT suppressed: a rejected
/// echo gets an unreachable, matching Junos.
///
/// #2393: the ICMPv4 set here now matches [`is_icmp_error`]
/// ({3,4,5,11,12}) — both follow the full RFC 792 quoted-datagram error
/// set. The two predicates remain separate because their ICMPv6 arms still
/// differ: this guard suppresses the entire ICMPv6 error range (`< 128`,
/// which includes types beyond the embedded-NAT set), while
/// [`is_icmp_error`] enumerates only the ICMPv6 errors that quote a
/// translatable inner packet (1/2/3/4).
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
/// Returns `None` (caller fail-closes to a silent drop) when the shared
/// [`can_generate_icmp_error_reply`] gate (#2237) suppresses the reply:
///   - the inbound is an ICMP/ICMPv6 *error* message
///     ([`reject_icmp_reply_suppressed`]),
///   - the inbound is a non-first fragment (no transport header to key),
///   - the inbound L2/L3 destination is broadcast/multicast, or its IP
///     source is unspecified/loopback/multicast/broadcast,
/// or when the ingress interface has no primary address of the inbound
/// family, or the frame is otherwise unparseable.
pub(super) fn build_reject_icmp_unreachable(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    // #2237: shared RFC 1812 §4.3.2.7 / RFC 4443 §2.4 suppression gate.
    // Subsumes the prior inline non-first-fragment and inbound-ICMP-error
    // checks and additionally suppresses group/broadcast destinations and
    // bogus sources — the same contract the Time Exceeded path now uses.
    if !can_generate_icmp_error_reply(frame, meta, forwarding) {
        return None;
    }
    match meta.addr_family as i32 {
        // ICMPv4 Destination Unreachable, code 13 (communication
        // administratively prohibited).
        libc::AF_INET => build_local_icmp_error_v4(frame, meta, ingress_ifindex, forwarding, 3, 13),
        // ICMPv6 Destination Unreachable, code 1 (communication with
        // destination administratively prohibited).
        libc::AF_INET6 => build_local_icmp_error_v6(frame, meta, ingress_ifindex, forwarding, 1, 1),
        _ => None,
    }
}

/// Returns true if the protocol and ICMP type indicate an ICMP error message
/// that quotes the offending datagram (an inner IP header + at least the
/// first 8 bytes of its transport header), which the embedded-ICMP-NAT
/// reversal path must translate back to the pre-NAT tuple.
///
/// #2393: the ICMPv4 arm matches the full RFC 792 error set that carries a
/// quoted datagram — Destination Unreachable (3), Source Quench (4),
/// Redirect (5), Time Exceeded (11), Parameter Problem (12) — so that a
/// NAT44 transit Redirect / Source Quench has its embedded inner addresses
/// rewritten just like types 3/11/12. All five share the same 8-byte ICMP
/// header layout (the type-specific word — Redirect's gateway address,
/// Source Quench / Dest-Unreachable's unused word — occupies bytes 4..8),
/// so the quoted IP header begins at `l4 + 8` for every one of them and the
/// type-agnostic embedded parser/builders need no per-type handling. This
/// now matches the broader [`reject_icmp_reply_suppressed`] set and Linux
/// netfilter conntrack's related-ICMP `icmp_error` (3/4/5/11/12).
///
/// Type 4 (Source Quench) is deprecated (RFC 6633) and type 5 (Redirect)
/// is normally link-scoped, so in practice a NATed transit instance is
/// rare; including them is a correctness/parity completion, not a hot path.
/// Note these two are still dropped (not mistranslated) on the NAT64
/// cross-family path — they have no IPv6 analogue (RFC 7915, see
/// `nat64.rs`); this set governs only same-family embedded-NAT reversal.
///
/// The ICMPv6 arm is the full ICMPv6 error range that carries a quoted
/// packet: Destination Unreachable (1), Packet Too Big (2), Time Exceeded
/// (3), Parameter Problem (4).
pub(super) fn is_icmp_error(protocol: u8, icmp_type: u8) -> bool {
    match protocol {
        PROTO_ICMP => matches!(icmp_type, 3 | 4 | 5 | 11 | 12),
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

        assert_eq!(
            &out[12..14],
            &[0x81, 0x00],
            "reflected frame must carry an 802.1Q TPID"
        );
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
        assert_eq!(
            &out[14..16],
            &100u16.to_be_bytes(),
            "VID 100 preserved, PCP 0"
        );
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
        assert_eq!(
            &out[12..14],
            &[0x08, 0x00],
            "EtherType IPv4 at byte 12 (untagged)"
        );
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

    /// #2314: rewrite the IPv4 destination of an `inbound_v4` frame
    /// (offset depends on the L2 tag) and fix the IP-header checksum.
    fn set_inbound_v4_dst(frame: &mut [u8], meta: UserspaceDpMeta, dst: Ipv4Addr) {
        let l3 = meta.l3_offset as usize;
        frame[l3 + 16..l3 + 20].copy_from_slice(&dst.octets());
        frame[l3 + 10..l3 + 12].copy_from_slice(&[0, 0]);
        let csum = checksum16(&frame[l3..l3 + 20]);
        frame[l3 + 10..l3 + 12].copy_from_slice(&csum.to_be_bytes());
    }

    /// Build an inbound IPv6 UDP frame (untagged) destined to `dst`, with
    /// `l4_offset` set so `can_generate_icmp_error_reply` can locate the
    /// transport header.
    fn inbound_v6_to(dst: Ipv6Addr) -> (Vec<u8>, UserspaceDpMeta) {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // firewall NIC
        frame.extend_from_slice(&[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]); // sender
        frame.extend_from_slice(&0x86ddu16.to_be_bytes());
        let l3 = frame.len();
        frame.push(0x60); // version 6
        frame.extend_from_slice(&[0x00, 0x00, 0x00]); // TC/flow
        frame.extend_from_slice(&8u16.to_be_bytes()); // payload = 8 (UDP hdr)
        frame.push(17); // next header UDP
        frame.push(64); // hop limit
        frame.extend_from_slice(
            &"2001:559:8585:bf01::20"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        frame.extend_from_slice(&dst.octets());
        let l4 = frame.len();
        frame.extend_from_slice(&49152u16.to_be_bytes());
        frame.extend_from_slice(&5201u16.to_be_bytes());
        frame.extend_from_slice(&8u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        let meta = UserspaceDpMeta {
            ingress_ifindex: ICMP_IFINDEX as u32,
            l3_offset: l3 as u16,
            l4_offset: l4 as u16,
            addr_family: libc::AF_INET6 as u8,
            protocol: 17,
            ..UserspaceDpMeta::default()
        };
        (frame, meta)
    }

    /// #2314 reject/time-exceeded path: a trigger packet whose IPv4
    /// destination is multicast (224.0.0.0/4) must suppress the locally
    /// generated ICMP error (`can_generate_icmp_error_reply` returns false,
    /// so `build_reject_icmp_unreachable` returns None). RFC 1812 §4.3.2.7.
    #[test]
    fn reject_suppressed_for_v4_multicast_dst() {
        let (mut frame, meta) = inbound_v4(InL2::Untagged);
        set_inbound_v4_dst(&mut frame, meta, Ipv4Addr::new(239, 1, 2, 3));
        assert!(
            !can_generate_icmp_error_reply(&frame, meta, &forwarding_with_egress(0)),
            "IPv4 multicast destination must suppress the reply"
        );
        let fwd = forwarding_with_egress(0);
        assert!(
            build_reject_icmp_unreachable(&frame, meta, ICMP_IFINDEX, &fwd).is_none(),
            "reject unreachable must not build for a multicast destination"
        );
    }

    /// #2314: an IPv4 trigger destined to the limited broadcast
    /// 255.255.255.255 must suppress the reply.
    #[test]
    fn reject_suppressed_for_v4_limited_broadcast_dst() {
        let (mut frame, meta) = inbound_v4(InL2::Untagged);
        set_inbound_v4_dst(&mut frame, meta, Ipv4Addr::new(255, 255, 255, 255));
        assert!(
            !can_generate_icmp_error_reply(&frame, meta, &forwarding_with_egress(0)),
            "IPv4 limited broadcast destination must suppress the reply"
        );
    }

    /// #2411: a `ForwardingState` whose connected v4 table holds a single
    /// connected prefix, so the directed-broadcast gate has a subnet mask
    /// to test the trigger destination against.
    fn forwarding_with_connected_v4(cidr: &str) -> ForwardingState {
        let mut state = forwarding_with_egress(0);
        state.connected_v4.push(ConnectedRouteV4 {
            prefix: crate::prefix::PrefixV4::from_net(cidr.parse().expect("cidr")),
            ifindex: ICMP_IFINDEX,
            tunnel_endpoint_id: 0,
        });
        state
    }

    /// #2411: an IPv4 trigger destined to a SUBNET-DIRECTED broadcast
    /// (the all-ones host of a configured connected prefix, e.g.
    /// 10.0.1.255 for 10.0.1.0/24) must suppress the locally generated
    /// ICMP error (RFC 1812 §4.3.2.7) even though it is a plain unicast
    /// address to the limited-broadcast / multicast tests. Fails (error
    /// generated) if the `dest_is_directed_broadcast` check is removed.
    #[test]
    fn reject_suppressed_for_v4_directed_broadcast_dst() {
        let (mut frame, meta) = inbound_v4(InL2::Untagged);
        set_inbound_v4_dst(&mut frame, meta, Ipv4Addr::new(10, 0, 1, 255));
        let fwd = forwarding_with_connected_v4("10.0.1.0/24");
        assert!(
            !can_generate_icmp_error_reply(&frame, meta, &fwd),
            "IPv4 subnet-directed broadcast must suppress the reply"
        );
        assert!(
            build_reject_icmp_unreachable(&frame, meta, ICMP_IFINDEX, &fwd).is_none(),
            "reject unreachable must not build for a directed broadcast"
        );
    }

    /// #2411 anti-over-suppress: a normal unicast HOST inside the same
    /// connected subnet (10.0.1.42 in 10.0.1.0/24) must STILL generate
    /// the error — only the all-ones host is the directed broadcast.
    #[test]
    fn reject_still_allowed_for_unicast_in_connected_subnet() {
        let (mut frame, meta) = inbound_v4(InL2::Untagged);
        set_inbound_v4_dst(&mut frame, meta, Ipv4Addr::new(10, 0, 1, 42));
        let fwd = forwarding_with_connected_v4("10.0.1.0/24");
        assert!(
            can_generate_icmp_error_reply(&frame, meta, &fwd),
            "a unicast host inside a connected subnet must allow the reply"
        );
    }

    /// #2411 fail-on-revert guard for the prefix-length skip: the .255
    /// host of a /32 connected prefix is the host itself, NOT a directed
    /// broadcast, so a normal unicast to a /32 host must NOT be
    /// suppressed (the `prefix_len() < 31` guard keeps it allowed).
    #[test]
    fn reject_still_allowed_for_v4_host_route_all_ones_octet() {
        let (mut frame, meta) = inbound_v4(InL2::Untagged);
        set_inbound_v4_dst(&mut frame, meta, Ipv4Addr::new(10, 0, 1, 255));
        let fwd = forwarding_with_connected_v4("10.0.1.255/32");
        assert!(
            can_generate_icmp_error_reply(&frame, meta, &fwd),
            "a /32 connected host must not be treated as a directed broadcast"
        );
    }

    /// #2314: an IPv6 trigger destined to ff00::/8 multicast must suppress
    /// the reply (RFC 4443 §2.4(e)).
    #[test]
    fn reject_suppressed_for_v6_multicast_dst() {
        let (frame, meta) = inbound_v6_to("ff02::1".parse().expect("v6 mcast"));
        assert!(
            !can_generate_icmp_error_reply(&frame, meta, &forwarding_with_egress(0)),
            "IPv6 multicast destination must suppress the reply"
        );
        let fwd = forwarding_with_egress(0);
        assert!(
            build_reject_icmp_unreachable(&frame, meta, ICMP_IFINDEX, &fwd).is_none(),
            "reject unreachable must not build for an IPv6 multicast destination"
        );
    }

    /// #2314 fail-on-revert: a NORMAL unicast destination must STILL allow
    /// the reply. Pairs with the suppression tests so reverting the gate
    /// turns those red while this one stays green.
    #[test]
    fn reject_still_allowed_for_unicast_dst() {
        // IPv4 default destination 172.16.80.200 is plain unicast.
        let (frame4, meta4) = inbound_v4(InL2::Untagged);
        assert!(
            can_generate_icmp_error_reply(&frame4, meta4, &forwarding_with_egress(0)),
            "a unicast IPv4 destination must allow the reply"
        );
        let fwd = forwarding_with_egress(0);
        assert!(
            build_reject_icmp_unreachable(&frame4, meta4, ICMP_IFINDEX, &fwd).is_some(),
            "reject unreachable must build for a unicast destination"
        );
        // IPv6 global unicast destination.
        let (frame6, meta6) = inbound_v6_to("2001:559:8585:80::200".parse().expect("v6 ucast"));
        assert!(
            can_generate_icmp_error_reply(&frame6, meta6, &forwarding_with_egress(0)),
            "a unicast IPv6 destination must allow the reply"
        );
    }
}
