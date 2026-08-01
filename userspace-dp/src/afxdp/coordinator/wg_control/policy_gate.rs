//! #5618: xpf forward zone-policy authority over decapped WireGuard
//! plaintext.
//!
//! ## The defect
//!
//! `dispatch.rs` authenticates a type-4 transport record, decrypts the
//! inner IP packet, and writes it straight to the `wgN` TUN, where the
//! Linux kernel routes and firewalls it. That was the deliberate #1432
//! S2a boundary ("xpf does not re-implement inner routing or policy"),
//! but it makes the tunnel an inter-zone policy BYPASS: a flow the
//! operator's `from-zone <wg-zone> to-zone <x>` policy DENIES still
//! transits, because it re-enters via the kernel FIB instead of the xpf
//! forward path. The AllowedIPs check inside `try_decap` is a
//! cryptographic peer/source-ownership gate, NOT the SRX zone-pair
//! authority, and cannot substitute for it.
//!
//! The direction is ASYMMETRIC on master: transit egress (LAN → `wgN`)
//! runs the full AF_XDP forward pipeline and IS policy-adjudicated
//! (`frame/wg.rs` encap happens after `evaluate_policy`); only the
//! inbound decap direction escapes.
//!
//! ## What this gate does (and does not) do
//!
//! This is the FORWARD ZONE-POLICY half of the fix, evaluated
//! synchronously on the control thread against the live forwarding
//! snapshot, before the TUN write:
//!
//!   1. from-zone := the zone bound to the tunnel's LOGICAL interface
//!      (`TunnelEndpoint.logical_ifindex`), never the outer UDP
//!      interface. This is the same logical-interface authority model
//!      native GRE decap already uses (`gre.rs`).
//!   2. to-zone := the zone of the egress interface the xpf FIB
//!      resolves for the inner destination, looked up in the tunnel
//!      interface's routing instance.
//!   3. `evaluate_policy` on the inner 5-tuple. A non-permit verdict
//!      DROPS the plaintext — it is never written to the TUN, so the
//!      kernel never sees it and cannot forward it.
//!
//! It does NOT create a session, run NAT/PBR/filters/screen, emit an
//! RT_FLOW policy-deny record, or apply host-inbound admission. Those
//! need the bounded control-thread→worker logical-ingress handoff that
//! #5618 tracks as the full fix; this gate closes the inter-zone
//! authority hole without that redesign.
//!
//! ## Why unadjudicated packets still pass (fail-open, but COUNTED)
//!
//! The gate enforces only where xpf actually HAS authority. It returns
//! [`InnerVerdict::Unadjudicated`] — preserving today's kernel
//! delegation — when the tunnel interface is not in a security zone,
//! when the inner destination is host-bound (`LocalDelivery`, a
//! host-inbound question, not a forward-policy one), when the xpf FIB
//! resolves no egress interface, when that egress interface is unzoned,
//! or when the inner packet is unparseable.
//!
//! Enforcing a DENY in those cases would drop traffic on the basis of a
//! zone pair xpf could not actually compute, which is a worse failure
//! than the bug. Every such packet bumps `inner_policy_unadjudicated`,
//! so the residual delegation is operator-visible rather than silent —
//! the "make the boundary explicit and detectable" half of the fix.
//! Note that a cold ARP/ND entry is NOT unadjudicated: a
//! `MissingNeighbor` resolution still carries `egress_ifindex`, so the
//! zone pair is known and the policy is enforced normally.

use super::super::*;
use crate::afxdp::forwarding::lookup_forwarding_resolution_inner;
use crate::afxdp::frame::parse_session_flow_from_frame;

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
    /// xpf has no forward authority over this packet. Preserve the S2a
    /// kernel delegation and count it. The `&'static str` is the reason,
    /// for the debug log only (a single counter carries the class).
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
        _ => return InnerVerdict::Unadjudicated("inner_not_ip"),
    };
    let Some(frame_len) = build_synthetic_frame(inner, addr_family, gate_buf) else {
        return InnerVerdict::Unadjudicated("gate_buf_too_small");
    };
    let frame = &gate_buf[..frame_len];
    let protocol = match inner_protocol(frame, addr_family) {
        Some(protocol) => protocol,
        None => return InnerVerdict::Unadjudicated("inner_truncated"),
    };
    let meta = UserspaceDpMeta {
        addr_family,
        protocol,
        l3_offset: WG_GATE_ETH_LEN as u16,
        pkt_len: u16::try_from(inner.len()).unwrap_or(u16::MAX),
        ..UserspaceDpMeta::default()
    };
    // A flowless inner packet (non-first fragment) yields no 5-tuple. The
    // flowless zone-policy path (`evaluate_policy_result_l3_aware` with
    // `l4_present = false`) belongs to the full worker re-entry; here it
    // would mean adjudicating a fragment on fabricated ports, so leave it
    // to the kernel and count it.
    let Some(flow) = parse_session_flow_from_frame(frame, meta) else {
        return InnerVerdict::Unadjudicated("inner_flowless");
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
    let resolution = lookup_forwarding_resolution_inner(forwarding, None, flow.dst_ip, table);
    if matches!(resolution.disposition, ForwardingDisposition::LocalDelivery) {
        // Host-bound inner traffic is a host-inbound-admission question
        // (`security zones ... host-inbound-traffic` + `to-zone
        // junos-host`), not a forward zone-pair question. Applying a
        // transit policy to it would be the wrong authority. Still the
        // kernel's call today; counted as residual.
        return InnerVerdict::Unadjudicated("local_delivery");
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

    // #3020: carry the real ICMP type/code so an icmp-type-constrained
    // application term (junos-ping = echo-request) MATCHES. Passing None
    // would fail those terms closed and drop legitimate pings the
    // operator explicitly permitted.
    let packet_icmp = if matches!(protocol, PROTO_ICMP | PROTO_ICMPV6) {
        let extra = crate::afxdp::frame::term_match_extra_from_frame(frame, meta);
        if extra.l4_present {
            Some((extra.icmp_type, extra.icmp_code))
        } else {
            None
        }
    } else {
        None
    };
    let action = crate::policy::evaluate_policy_result_with_icmp(
        &forwarding.policy,
        from_zone,
        to_zone,
        flow.src_ip,
        flow.dst_ip,
        protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        packet_icmp,
        inner.len() as u64,
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

/// The inner packet's terminal L4 protocol number, read off the
/// SYNTHETIC frame (so `l3` is `WG_GATE_ETH_LEN`). IPv4 reads the fixed
/// protocol octet; IPv6 walks the extension-header chain via the SHARED
/// `walk_ipv6_ext_chain` so a chained inner packet resolves its terminal
/// L4, and every non-`L4` verdict (truncated / over-limit / non-first
/// fragment) fails CLOSED to `None` → unadjudicated, never a fabricated
/// protocol 0 evaluated against a real policy.
fn inner_protocol(frame: &[u8], addr_family: u8) -> Option<u8> {
    if addr_family == libc::AF_INET as u8 {
        return frame.get(WG_GATE_ETH_LEN + 9).copied();
    }
    match crate::afxdp::frame::walk_ipv6_ext_chain(frame, WG_GATE_ETH_LEN).outcome {
        crate::afxdp::frame::ExtChainOutcome::L4(_, protocol) => Some(protocol),
        _ => None,
    }
}
