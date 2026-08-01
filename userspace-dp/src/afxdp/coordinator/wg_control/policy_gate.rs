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
//! packet does carry, and #4569's fragment-association override turns a
//! later permit into a drop when an overlapping port-bearing DENY was
//! skipped. Dropping outright instead would break legitimate fragmented
//! traffic and legitimate ICMP errors under a permit policy; delegating
//! leaves the deny bypassable. Adjudicating on L3 is the answer the
//! transit direction already settled on, so the two directions now agree
//! by construction.
//!
//! ## Fail-CLOSED cases (`ForwardDrop`)
//!
//! Three dispositions are xpf verdicts in their own right, not an
//! absence of authority, so they DROP rather than delegate:
//!
//!   - `DiscardRoute` / `NextTableUnsupported` — the xpf FIB said
//!     *discard*. Handing the plaintext to the kernel after that is
//!     incoherent, even though FRR usually installs the same blackhole.
//!   - an UNINSPECTABLE inner packet: a truncated IP header, a declared
//!     length overrunning the buffer, or an IPv6 extension chain still
//!     unresolved at `MAX_IPV6_EXT_HEADERS`. The mainline forward path
//!     fails these closed too (#2292 / #4743 `ipv6_ext_header_dropped`),
//!     and an over-limit chain is a known IDS-evasion shape.
//!   - a non-IPv4/IPv6 inner payload. WireGuard is an IP tunnel; the
//!     inner version nibble is 4 or 6 by construction (a zero-length
//!     keepalive never reaches here — it exits decap through the
//!     `MalformedInner` arm), so anything else is malformed.
//!
//! ## Where the kernel delegation genuinely REMAINS (`Unadjudicated`)
//!
//! Only where xpf cannot compute a zone pair at all: the tunnel
//! interface is not in a security zone, the routed egress interface is
//! not in a security zone, the FIB resolves no egress interface, or the
//! inner destination is host-bound (`LocalDelivery` — a
//! `host-inbound-traffic` / `to-zone junos-host` question, a DIFFERENT
//! policy plane, not a transit zone pair). Enforcing a DENY in those
//! cases would drop traffic on the basis of a zone pair xpf could not
//! actually compute, which is a worse failure than the bug.
//!
//! The `LocalDelivery` residual is **attacker-reachable on demand** —
//! AllowedIPs constrains the inner source, not the inner destination, so
//! a peer may freely address any firewall-local IP. That is unchanged
//! from master and belongs to the host-inbound plane (#5618's full-fix
//! scope), but it is not an incidental corner and the docs say so.
//!
//! Every un-adjudicated packet bumps `inner_policy_unadjudicated`, so
//! the residual delegation is operator-visible rather than silent.
//! Note that a cold ARP/ND entry is NOT in this set: a `MissingNeighbor`
//! resolution still carries `egress_ifindex`, so the zone pair is known
//! and the policy is enforced normally.

use super::super::*;
use crate::afxdp::forwarding::lookup_forwarding_resolution_inner;
use crate::afxdp::frame::{
    packet_rel_l4_offset_and_protocol, parse_session_flow_from_frame, term_match_extra_from_frame,
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
    // to evaluate — this is the pre-existing "operator did not put wgN in
    // a security zone" state, not a bypass we can close here.
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
    let Some((frame_len, meta)) = synthetic_frame_and_meta(inner, addr_family, gate_buf) else {
        // Either the scratch is too small — unreachable in production
        // (`gate_buf` is WG_GATE_ETH_LEN + 65535 while `decap_buf` is
        // 65535) — or the inner packet is uninspectable. Fail closed
        // rather than hand an unadjudicated packet to the kernel.
        return InnerVerdict::ForwardDrop("inner_uninspectable");
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
        // absence of authority — do not hand the plaintext to the kernel.
        ForwardingDisposition::DiscardRoute => {
            return InnerVerdict::ForwardDrop("discard_route");
        }
        ForwardingDisposition::NextTableUnsupported => {
            return InnerVerdict::ForwardDrop("next_table_unsupported");
        }
        _ => {}
    }
    if resolution.egress_ifindex <= 0 {
        return InnerVerdict::Unadjudicated("no_egress_ifindex");
    }
    let to_zone = forwarding
        .ifindex_to_zone_id
        .get(&resolution.egress_ifindex)
        .copied()
        .unwrap_or_default();
    if to_zone == 0 {
        return InnerVerdict::Unadjudicated("egress_unzoned");
    }

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
/// `None` when the scratch is too small or the inner packet is
/// UNINSPECTABLE (truncated IP header, declared length overrunning the
/// buffer, or an IPv6 extension chain still unresolved at
/// `MAX_IPV6_EXT_HEADERS`).
///
/// **`l4_offset` is load-bearing and must be stamped** (r2 MAJOR 2).
/// `term_match_extra_from_frame` trusts the field VERBATIM; leaving it at
/// its `Default` 0 made it read the ICMP type/code out of the ZEROED
/// synthetic Ethernet header, so every inner ICMP packet was evaluated as
/// type 0 code 0 — which broke `permit .. application junos-ping`
/// (echo-request is type 8, so the term never matched and ping died
/// through every tunnel) AND failed `deny .. application junos-ping`
/// OPEN. `packet_rel_l4_offset_and_protocol` resolves the L4 offset and
/// the TERMINAL protocol together over the L3-relative inner slice — the
/// same SSOT the GRE inner-parse and tunnel local-origin metadata use,
/// fail-closed on the uninspectable shapes above (#2292 / #4743).
fn synthetic_frame_and_meta(
    inner: &[u8],
    addr_family: u8,
    gate_buf: &mut [u8],
) -> Option<(usize, UserspaceDpMeta)> {
    let frame_len = build_synthetic_frame(inner, addr_family, gate_buf)?;
    let (rel_l4_offset, protocol) = packet_rel_l4_offset_and_protocol(inner, addr_family)?;
    Some((
        frame_len,
        UserspaceDpMeta {
            addr_family,
            protocol,
            l3_offset: WG_GATE_ETH_LEN as u16,
            l4_offset: (WG_GATE_ETH_LEN + rel_l4_offset) as u16,
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
    synthetic_frame_and_meta(inner, addr_family, gate_buf)
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
