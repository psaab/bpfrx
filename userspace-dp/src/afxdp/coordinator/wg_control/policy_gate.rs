//! #5618: xpf forward zone-policy authority over decapped WireGuard
//! plaintext.
//!
//! ## The defect
//!
//! `dispatch.rs` authenticated a type-4 transport record, decrypted the
//! inner IP packet, and wrote it straight to the `wgN` TUN, where the
//! Linux kernel routed and firewalled it. That was the deliberate #1432
//! S2a boundary ("xpf does not re-implement inner routing or policy"),
//! but it made the tunnel an inter-zone policy BYPASS: a flow the
//! operator's `from-zone <wg-zone> to-zone <x>` policy DENIES still
//! transited, because it re-entered via the kernel FIB instead of the
//! xpf forward path. The AllowedIPs check inside `try_decap` is a
//! cryptographic peer/source-ownership gate, NOT the SRX zone-pair
//! authority, and cannot substitute for it.
//!
//! The direction was ASYMMETRIC on master: transit egress (LAN → `wgN`)
//! runs the full AF_XDP forward pipeline and IS policy-adjudicated
//! (`frame/wg.rs` encap happens after `evaluate_policy`); only the
//! inbound decap direction escaped.
//!
//! ## What this gate does
//!
//! The FORWARD ZONE-POLICY authority, evaluated synchronously on the
//! control thread against the live forwarding snapshot, before the TUN
//! write:
//!
//!   1. from-zone := the zone bound to the tunnel's LOGICAL interface
//!      (`TunnelEndpoint.logical_ifindex`), never the outer UDP
//!      interface. This is the same logical-interface authority model
//!      native GRE decap uses (`gre.rs`).
//!   2. to-zone := the zone of the egress interface the xpf FIB
//!      resolves for the inner destination, looked up in the tunnel
//!      interface's routing instance.
//!   3. `evaluate_policy_result_l3_aware` on the inner tuple. A
//!      non-permit verdict DROPS the plaintext — it is never written to
//!      the TUN, so the kernel never sees it and cannot forward it.
//!
//! It does NOT create a session, run NAT/PBR/filters/screen, emit an
//! RT_FLOW policy-deny record, or apply host-inbound admission. Those
//! need the bounded control-thread→worker logical-ingress handoff that
//! #5618 tracks as the full fix.
//!
//! ## Packets with no 5-tuple are ADJUDICATED, not delegated (r2 MAJOR 1)
//!
//! The first cut of this gate bailed to `Unadjudicated` whenever
//! `parse_session_flow_from_frame` returned `None`. That was a
//! **fail-open an authenticated peer selects with one byte**:
//! `parse_flow_ports` yields `None` for every IP protocol except TCP,
//! UDP, and identifier-bearing ICMP/ICMPv6 — so inner proto 132 (SCTP),
//! 47 (GRE), 4/41 (IPIP), 50/51 (ESP/AH), every ICMP error and ND/MLD
//! type, and every non-first fragment walked straight past a DENY.
//! AllowedIPs constrains the inner SOURCE; nothing constrains the inner
//! PROTOCOL NUMBER, and the peer is exactly the entity the deny exists
//! to constrain.
//!
//! **The correct verdict for a packet with no 5-tuple is to adjudicate
//! on the L3 identity it DOES carry** — (src, dst, protocol) — via
//! `evaluate_policy_result_l3_aware(.., l4_present = false)`, the SAME
//! shared entry point the AF_XDP transit path already uses for this
//! class (#3291 / #4569). That is not "adjudicating on fabricated
//! ports": `l4_present = false` is DEFINED as "ports are 0 and MUST NOT
//! be trusted" — port-bearing application terms fail closed, while
//! address/protocol/`any` terms still evaluate on the L3 identity the
//! packet does carry. Dropping the whole class outright instead would
//! break legitimate flowless traffic; delegating it leaves the deny
//! bypassable. Adjudicating on L3 is the answer the transit direction
//! already settled on, so the two directions agree by construction —
//! this gate calls the very same `evaluate_policy_result_l3_aware` with
//! the same `(ports = 0, l4_present = false)` the mainline flowless
//! transit arm passes.
//!
//! ### Inherited limitation: a port-bearing PERMIT and a non-first fragment
//!
//! Because port-bearing terms fail closed under `l4_present = false`, a
//! `permit ... application junos-http` matches the FIRST fragment (real
//! ports) but not the non-first fragments, which fall through to the
//! default policy and drop. That is the mainline transit behaviour, not
//! something this gate invents — `poll_descriptor/mod.rs` states it
//! outright: "L4-specific-PERMITTED fragmented flows are the deferred
//! fragment-association-cache stage of the #3291 plan; until then their
//! non-first fragments fall to the default policy, the documented
//! fail-closed limitation."
//!
//! An earlier revision of this comment claimed #4569's
//! fragment-association override covered the case. **It does not** —
//! #4569 remembers only a skipped port-bearing *DENY* and turns a later
//! permit into a drop; it never recovers a skipped port-bearing
//! *PERMIT* (`policy.rs`). The honest statement is that WireGuard inner
//! ingress now inherits the same documented #3291 limitation as every
//! other interface, and the same deferred fix (a fragment-association
//! cache keyed on `(src, dst, frag-id)`) closes it in both directions at
//! once. The alternative — permitting a fragment on the L3 match alone —
//! would make a port-bearing permit port-AGNOSTIC for fragments and
//! would re-create the very asymmetry this gate exists to remove (the
//! same flow dropped LAN→WAN, permitted WG→LAN).
//!
//! ## Fail-CLOSED cases (`ForwardDrop`)
//!
//! Deliberately NARROW — round 2 over-corrected here and killed valid
//! traffic. Only three things drop:
//!
//!   - `DiscardRoute` — the xpf FIB matched a discard/reject route
//!     "whose entire purpose is to drop the traffic", and it is
//!     explicitly NOT slow-path eligible. `NextTableUnsupported` is a
//!     different animal and DELEGATES (see below).
//!   - an OVER-LIMIT IPv6 extension chain (#4743's IDS-evasion shape).
//!     A `NoNextHeader` terminal or an unfinished chain does NOT drop —
//!     the L3 identity is intact, so it is adjudicated flowlessly, which
//!     is what mainline does.
//!   - a non-IPv4/IPv6 inner payload, or one too short to carry an L3
//!     header. WireGuard is an IP tunnel; the inner version nibble is 4
//!     or 6 by construction (a zero-length keepalive never reaches here —
//!     it exits decap through the `MalformedInner` arm), so there is no
//!     identity to adjudicate.
//!
//! ## Where the kernel delegation genuinely REMAINS (`Unadjudicated`)
//!
//! Three cases, and their steerability differs — which matters, because
//! a delegation a peer can select on demand is a bypass while one fixed
//! by operator config is not:
//!
//!   - `endpoint_absent` / `ingress_unzoned` — NOT peer-steerable. Both
//!     derive from the tunnel row's `logical_ifindex`, fixed when the
//!     control thread spawns. No packet content reaches them.
//!   - `next_table_unsupported` / `no_egress_ifindex` (`NoRoute`) — the
//!     peer DOES select these via the inner destination, but both are
//!     slow-path ELIGIBLE dispositions that the mainline transit path
//!     also hands to the kernel FIB without evaluating the transit
//!     policy (that gate runs only for `ForwardCandidate`). Dropping
//!     them here alone would diverge from
//!     `ForwardingDisposition::is_slow_path_eligible` AND re-create the
//!     WG-vs-transit asymmetry. Delegated for parity, recorded as a
//!     residual — not claimed closed.
//!   - `local_delivery` — peer-selectable on demand (AllowedIPs
//!     validates only the inner SOURCE, so the destination is entirely
//!     the peer's choice) and NOT covered by this gate. A host-bound
//!     inner packet belongs to the host-inbound plane
//!     (`host-inbound-traffic` admission, then the `to-zone junos-host`
//!     policy), which this control-thread gate does not implement.
//!     Applying a TRANSIT zone-pair policy to it would be the wrong
//!     authority; dropping it would break every legitimate host-bound
//!     flow through the tunnel (ping/SSH to the firewall over WG).
//!     **This is an open residual of #5618, not a closed case** — see
//!     `docs/wireguard-interop.md`.
//!
//! Every un-adjudicated packet bumps `inner_policy_unadjudicated`, so
//! the residual delegation is operator-visible rather than silent.
//! Note that a cold ARP/ND entry is NOT in this set: a `MissingNeighbor`
//! resolution still carries `egress_ifindex`, so the zone pair is known
//! and the policy is enforced normally. Neither is an unzoned EGRESS
//! interface: the peer selects it, so it is adjudicated with
//! `to_zone = 0` and resolved by #3110's default-action fall-through.

use super::super::*;
use crate::afxdp::forwarding::{
    lookup_forwarding_resolution_inner, zone_pair_ids_for_flow_with_override,
};
use crate::afxdp::frame::{
    ExtChainOutcome, parse_session_flow_from_frame, term_match_extra_from_frame,
    walk_ipv6_ext_chain,
};

/// Ethernet header length of the synthetic frame the inner IP packet is
/// copied behind so the shared L3/L4 parsers (which are Ethernet-framed
/// by contract) can read it. Mirrors the `14` native GRE decap uses for
/// its synthetic inner frame.
pub(super) const WG_GATE_ETH_LEN: usize = 14;

/// The xpf forward-policy verdict for one decapped inner packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InnerVerdict {
    /// xpf computed a real from-zone → to-zone verdict and it PERMITS.
    /// Deliver to the TUN.
    Permit,
    /// xpf computed a real from-zone → to-zone verdict and it DENIES (or
    /// REJECTS). DROP: the plaintext must not reach the kernel.
    Deny { from_zone: u16, to_zone: u16 },
    /// xpf has a definite NON-policy verdict of its own — a discard
    /// route, or an inner packet it cannot safely inspect. DROP. The
    /// `&'static str` is the reason, for the debug log.
    ForwardDrop(&'static str),
    /// xpf has no forward authority over this packet (unzoned tunnel or
    /// egress, host-bound destination, no FIB egress). Preserve the S2a
    /// kernel delegation and count it.
    Unadjudicated(&'static str),
}

/// Evaluate the xpf forward zone policy for one decapped WireGuard inner
/// IP packet.
///
/// `gate_buf` is the caller's reusable scratch (`>= WG_GATE_ETH_LEN +
/// inner.len()`); the inner packet is copied behind a synthetic Ethernet
/// header because every shared L3/L4 parser in this tree is
/// Ethernet-framed by contract. No allocation on this path.
pub(super) fn evaluate_wg_inner_ingress(
    forwarding: &ForwardingState,
    tunnel_endpoint_id: u16,
    inner: &[u8],
    gate_buf: &mut [u8],
) -> InnerVerdict {
    // The tunnel's LOGICAL interface is the ingress identity — read live
    // from the snapshot (not baked in at spawn) so a config change that
    // re-attaches or re-zones the tunnel takes effect on the next
    // published forwarding state.
    let Some(endpoint) = forwarding.tunnel_endpoints.get(&tunnel_endpoint_id) else {
        // The endpoint left the snapshot (teardown in flight). The
        // supervision layer stops this thread; until it does we have no
        // ingress identity to adjudicate against.
        return InnerVerdict::Unadjudicated("endpoint_absent");
    };
    let logical_ifindex = endpoint.logical_ifindex;
    // #3110: zone id 0 is the reserved "unknown / no zone" sentinel. An
    // unzoned tunnel interface has no from-zone, so there is no zone pair
    // to evaluate at all — the gate's whole premise fails. This is
    // operator config ("wgN is not in a security zone"), NOT peer-
    // selectable: `logical_ifindex` is fixed by the tunnel row, so a peer
    // cannot steer a packet into this branch. Delegate + count.
    //
    // Contrast the EGRESS zone below, which the peer DOES select via the
    // inner destination: that one is adjudicated with `to_zone = 0` and
    // resolved by #3110's fall-through to the default action, exactly as
    // the mainline transit path does.
    let from_zone = forwarding
        .ifindex_to_zone_id
        .get(&logical_ifindex)
        .copied()
        .unwrap_or_default();
    if from_zone == 0 {
        return InnerVerdict::Unadjudicated("ingress_unzoned");
    }

    // Family off the version nibble — the TUN carries a bare inner IP
    // packet with no L2, exactly like the egress direction's sniff.
    let addr_family = match inner.first().map(|b| b >> 4) {
        Some(4) => libc::AF_INET as u8,
        Some(6) => libc::AF_INET6 as u8,
        // WireGuard is an IP tunnel: the inner version nibble is 4 or 6
        // by construction. Anything else is malformed — fail closed.
        _ => return InnerVerdict::ForwardDrop("inner_not_ip"),
    };
    let (frame_len, meta) = match synthetic_frame_and_meta(inner, addr_family, gate_buf) {
        Ok(pair) => pair,
        Err(reason) => return InnerVerdict::ForwardDrop(reason),
    };
    let frame = &gate_buf[..frame_len];
    let protocol = meta.protocol;
    // The frame-derived match inputs (ICMP type/code + the `l4_present`
    // gate). Built from the DECLARED datagram end, so trailing slack
    // cannot manufacture a type/code (#5568), and zeroed on a non-first
    // fragment so an ICMP-constrained term fails closed there.
    let extra = term_match_extra_from_frame(frame, meta);

    // r2 MAJOR 1: a packet with no 5-tuple is ADJUDICATED on its L3
    // identity, never delegated. `l4_present` mirrors the flow-parse
    // outcome exactly — the same predicate the mainline transit path
    // derives it from — so an SCTP/GRE/fragment inner packet gets the
    // same treatment in both directions.
    let (src_ip, dst_ip, src_port, dst_port, l4_present) =
        match parse_session_flow_from_frame(frame, meta) {
            Some(flow) => (
                flow.src_ip,
                flow.dst_ip,
                flow.forward_key.src_port,
                flow.forward_key.dst_port,
                true,
            ),
            None => {
                // The L3 tuple must come off the FRAME: the gate's
                // synthetic meta leaves `flow_src_addr`/`flow_dst_addr`
                // zeroed, so the meta-based L3 helpers cannot be reused.
                let Some((src_ip, dst_ip)) = inner_l3_addrs(frame, addr_family) else {
                    return InnerVerdict::ForwardDrop("inner_uninspectable");
                };
                (src_ip, dst_ip, 0, 0, false)
            }
        };

    // Route the inner destination in the TUNNEL's routing instance — a
    // wgN bound into a VRF must not resolve its to-zone out of inet.0.
    let table = forwarding
        .ifindex_to_routing_instance
        .get(&logical_ifindex)
        .map(String::as_str)
        .filter(|instance| !instance.is_empty());
    // `dynamic_neighbors = None`: this gate needs the egress INTERFACE,
    // not a MAC. A cold ARP/ND entry yields `MissingNeighbor`, which
    // still carries `egress_ifindex`, so the zone pair is known and the
    // verdict is enforced — a cold neighbor must never read as "no
    // authority" and fail open.
    let resolution = lookup_forwarding_resolution_inner(forwarding, None, dst_ip, table);
    match resolution.disposition {
        ForwardingDisposition::LocalDelivery => {
            // Host-bound inner traffic is a host-inbound-admission
            // question (`security zones ... host-inbound-traffic` +
            // `to-zone junos-host`), not a forward zone-pair question.
            // Applying a transit policy to it would be the wrong
            // authority. Still the kernel's call today; counted as
            // residual. Attacker-reachable on demand (AllowedIPs gates
            // the inner SOURCE, not the destination) — see the module
            // header.
            return InnerVerdict::Unadjudicated("local_delivery");
        }
        // xpf's own FIB said discard. That is a definite verdict, not an
        // absence of authority — and `DiscardRoute` is explicitly NOT
        // slow-path eligible (`ForwardingDisposition::is_slow_path_eligible`:
        // "matched a discard/reject route whose entire purpose is to drop
        // the traffic"). Drop.
        ForwardingDisposition::DiscardRoute => {
            return InnerVerdict::ForwardDrop("discard_route");
        }
        // r3 MAJOR 4: `NextTableUnsupported` is slow-path ELIGIBLE —
        // "inter-VRF next-table the helper does not implement; defer to
        // the kernel FIB". It is also produced for an acyclic chain past
        // the eight-table limit, not only for discard-equivalent config,
        // so dropping it blackholed kernel-routable inter-VRF traffic.
        // Round 2 lumped it in with `DiscardRoute`; that was wrong.
        ForwardingDisposition::NextTableUnsupported => {
            return InnerVerdict::Unadjudicated("next_table_unsupported");
        }
        // r3 MAJOR 1 / `NoRoute`: no egress interface. Mainline treats
        // `NoRoute` as slow-path ELIGIBLE ("userspace has no route, but
        // the kernel FIB may (e.g. a route the helper has not yet
        // learned); let the kernel try, rate-limited") and does NOT
        // evaluate the transit policy for it — the flowless/session-miss
        // policy gate runs only for `ForwardCandidate`. Delegating here
        // is therefore exactly what the transit direction does for the
        // same destination, so closing it in the WG direction alone would
        // RE-CREATE the asymmetry this gate exists to remove. Peer-
        // selectable via the inner destination, so it is recorded as a
        // residual, not claimed closed.
        _ if resolution.egress_ifindex <= 0 => {
            return InnerVerdict::Unadjudicated("no_egress_ifindex");
        }
        _ => {}
    }
    // r3 MAJOR 1: the EGRESS zone is peer-selected (the inner destination
    // is entirely the peer's choice — AllowedIPs validates only the inner
    // SOURCE), so an unzoned egress must NOT bail out of adjudication. It
    // is passed through as `to_zone = 0` and resolved by #3110's
    // fall-through to the default action — byte-identical to what the
    // mainline transit path does, which derives both ids with this same
    // helper and hands a 0 straight to `evaluate_policy_result_l3_aware`.
    // Round 2's `egress_unzoned` bail let a peer pick a destination
    // routed out an unzoned interface and skip the policy entirely.
    let (_from_zone_via_helper, to_zone) = zone_pair_ids_for_flow_with_override(
        forwarding,
        logical_ifindex,
        None,
        resolution.egress_ifindex,
    );
    debug_assert_eq!(
        _from_zone_via_helper, from_zone,
        "the gate's from-zone must agree with the shared zone-pair helper"
    );

    // #3020: carry the REAL ICMP type/code so an icmp-type-constrained
    // application term (junos-ping = echo-request) matches. `extra` fails
    // it closed (`l4_present == false`) on a non-first fragment or a
    // truncated/padded ICMP, exactly as the mainline flowless path does —
    // mirroring `policy_packet_icmp` + `flowless_local_delivery_verdict`.
    let packet_icmp = if matches!(protocol, PROTO_ICMP | PROTO_ICMPV6) && extra.l4_present {
        Some((extra.icmp_type, extra.icmp_code))
    } else {
        None
    };
    let action = crate::policy::evaluate_policy_result_l3_aware(
        &forwarding.policy,
        from_zone,
        to_zone,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        packet_icmp,
        inner.len() as u64,
        l4_present,
    )
    .action;
    match action {
        PolicyAction::Permit => InnerVerdict::Permit,
        PolicyAction::Deny | PolicyAction::Reject => InnerVerdict::Deny {
            from_zone,
            to_zone,
        },
    }
}

/// Build the synthetic Ethernet-framed copy of `inner` in `gate_buf` and
/// the `UserspaceDpMeta` describing it. Returns `(frame_len, meta)`, or
/// `Err(reason)` when the packet must be dropped outright.
///
/// **`l4_offset` is load-bearing and must be stamped** (r2 MAJOR 2).
/// `term_match_extra_from_frame` trusts the field VERBATIM; leaving it at
/// its `Default` 0 made it read the ICMP type/code out of the ZEROED
/// synthetic Ethernet header, so every inner ICMP packet was evaluated as
/// type 0 code 0 — which broke `permit .. application junos-ping`
/// (echo-request is type 8, so the term never matched and ping died
/// through every tunnel) AND failed `deny .. application junos-ping`
/// OPEN.
///
/// **Only an OVER-LIMIT IPv6 extension chain is a drop** (r3 MAJOR 3).
/// Round 2 folded every "no resolvable L4" outcome into one
/// `inner_uninspectable` drop, which newly killed valid traffic — most
/// visibly a well-formed IPv6 packet with Next Header 59 (No Next
/// Header), a legal terminal that simply has no L4. The mainline gate is
/// narrower and says so explicitly (#4743, `poll_descriptor/mod.rs`):
/// drop "ONLY the genuine over-limit chain; a non-first fragment /
/// ICMPv6 / truncated packet is not over-limit and keeps its existing
/// flowless handling." This mirrors that exactly:
///
///   - `L4(off, proto)` — normal: stamp the resolved offset + terminal
///     protocol.
///   - `OverLimit` — DROP (#4743 parity; the ext-header IDS-evasion
///     shape).
///   - `NoNextHeader` / `Truncated` — no L4 to point at, but the L3
///     identity is intact and adjudicable: stamp the post-base-header
///     offset and the base header's own Next Header byte, and let the
///     flowless `l4_present = false` arm evaluate it.
///
/// An IPv4 packet whose IHL is degenerate is treated the same way: the
/// L3 identity is still readable, so it is adjudicated rather than
/// dropped. Only a packet too short to carry an L3 header at all is a
/// drop — there is nothing to adjudicate.
fn synthetic_frame_and_meta(
    inner: &[u8],
    addr_family: u8,
    gate_buf: &mut [u8],
) -> Result<(usize, UserspaceDpMeta), &'static str> {
    let frame_len = build_synthetic_frame(inner, addr_family, gate_buf)
        // Unreachable in production: `gate_buf` is WG_GATE_ETH_LEN +
        // 65535 while `decap_buf` is 65535.
        .ok_or("gate_buf_too_small")?;
    let l3 = WG_GATE_ETH_LEN;
    let (l4_offset, protocol) = if addr_family == libc::AF_INET as u8 {
        if inner.len() < 20 {
            return Err("inner_truncated_l3");
        }
        let protocol = inner[9];
        let ihl = usize::from(inner[0] & 0x0f) * 4;
        // A degenerate IHL still leaves the L3 identity readable, so
        // adjudicate on it; point `l4_offset` past the fixed header.
        let rel_l4 = if ihl >= 20 && inner.len() >= ihl { ihl } else { 20 };
        (l3 + rel_l4, protocol)
    } else {
        if inner.len() < 40 {
            return Err("inner_truncated_l3");
        }
        match walk_ipv6_ext_chain(&gate_buf[..frame_len], l3).outcome {
            ExtChainOutcome::L4(offset, protocol) => (offset, protocol),
            // #4743 parity: the ONE fail-closed inspection drop.
            ExtChainOutcome::OverLimit => return Err("ipv6_ext_chain_over_limit"),
            // A legal terminal with no L4 (59 = No Next Header), or a
            // chain the walk could not finish. Either way the L3 identity
            // is intact — adjudicate it flowlessly, as mainline does.
            ExtChainOutcome::NoNextHeader | ExtChainOutcome::Truncated => {
                (l3 + 40, inner[6])
            }
        }
    };
    Ok((
        frame_len,
        UserspaceDpMeta {
            addr_family,
            protocol,
            l3_offset: WG_GATE_ETH_LEN as u16,
            l4_offset: u16::try_from(l4_offset).unwrap_or(u16::MAX),
            pkt_len: u16::try_from(inner.len()).unwrap_or(u16::MAX),
            ..UserspaceDpMeta::default()
        },
    ))
}

/// Test seam over [`synthetic_frame_and_meta`] — the PRODUCTION builder,
/// not a reimplementation, so a test asserting the ICMP type/code the
/// gate hands policy binds the real `l4_offset` stamping.
#[cfg(test)]
pub(super) fn synthetic_frame_and_meta_for_test(
    inner: &[u8],
    addr_family: u8,
    gate_buf: &mut [u8],
) -> Option<(usize, UserspaceDpMeta)> {
    synthetic_frame_and_meta(inner, addr_family, gate_buf).ok()
}

/// Copy `inner` behind a synthetic Ethernet header in `gate_buf` and
/// return the framed length. MAC addresses stay zero — nothing on this
/// path reads them; only the ethertype and the L3 payload matter.
fn build_synthetic_frame(inner: &[u8], addr_family: u8, gate_buf: &mut [u8]) -> Option<usize> {
    let frame_len = WG_GATE_ETH_LEN.checked_add(inner.len())?;
    if gate_buf.len() < frame_len {
        return None;
    }
    gate_buf[..WG_GATE_ETH_LEN].fill(0);
    let ethertype: u16 = if addr_family == libc::AF_INET as u8 {
        0x0800
    } else {
        0x86dd
    };
    gate_buf[12..14].copy_from_slice(&ethertype.to_be_bytes());
    gate_buf[WG_GATE_ETH_LEN..frame_len].copy_from_slice(inner);
    Some(frame_len)
}

/// The inner packet's (source, destination) L3 addresses, read off the
/// SYNTHETIC frame at fixed IP-header offsets. Used only on the flowless
/// arm, where `parse_session_flow_from_frame` declined to build a
/// 5-tuple but the L3 identity is still authoritative and still
/// adjudicable.
fn inner_l3_addrs(frame: &[u8], addr_family: u8) -> Option<(IpAddr, IpAddr)> {
    let l3 = WG_GATE_ETH_LEN;
    if addr_family == libc::AF_INET as u8 {
        let src: [u8; 4] = frame.get(l3 + 12..l3 + 16)?.try_into().ok()?;
        let dst: [u8; 4] = frame.get(l3 + 16..l3 + 20)?.try_into().ok()?;
        return Some((
            IpAddr::V4(std::net::Ipv4Addr::from(src)),
            IpAddr::V4(std::net::Ipv4Addr::from(dst)),
        ));
    }
    let src: [u8; 16] = frame.get(l3 + 8..l3 + 24)?.try_into().ok()?;
    let dst: [u8; 16] = frame.get(l3 + 24..l3 + 40)?.try_into().ok()?;
    Some((
        IpAddr::V6(std::net::Ipv6Addr::from(src)),
        IpAddr::V6(std::net::Ipv6Addr::from(dst)),
    ))
}
