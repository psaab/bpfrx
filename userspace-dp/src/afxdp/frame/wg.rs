//! WireGuard transit-egress encap for the AF_XDP copy path (#1432 S2a).
//!
//! This is the SECOND of the two S2a egress encap sites; the primary is
//! the WG control thread's TUN-read loop (coordinator/wg_control.rs).
//! This site fires only when an AF_XDP forwarding decision targets a
//! `mode == "wireguard"` tunnel endpoint id directly (a route/connected
//! entry carrying the WG endpoint id). In the canonical wgN-TUN topology
//! the kernel routes inner traffic to the wgN device and the control
//! thread owns egress, so this path is rarely hit; it exists so a
//! forwarding decision that does target the WG endpoint produces a valid
//! frame (and is correctly MTU-gated) rather than falling through to the
//! GRE builder.
//!
//! The non-WG fast path NEVER reaches here: `build_forwarded_frame_*`
//! only calls into the tunnel-encap branch when
//! `tunnel_endpoint_id != 0`, and a plain forward short-circuits long
//! before (tx/dispatch/mod.rs). The mode `match` in frame/mod.rs reads a
//! `&str` already loaded for the GRE lookup — no new branch on the
//! plain-forward path.

use super::super::wg::{EncapError, POLY1305_TAG_LEN, WG_DATA_HEADER_LEN};
use super::super::*;
use super::headers::{write_eth_header_slice, write_ipv4_header, write_ipv6_header, write_udp_header};
use std::net::IpAddr;

/// Round `n` up to the nearest multiple of 16 (WG §5.4.6 pad).
#[inline]
const fn pad_to_16(n: usize) -> usize {
    (n + 15) & !15
}

/// The exact pad-aware encapped wire size for an `inner_len`-byte inner
/// packet plus the outer L3/L4 (IP + UDP). Used by the MTU guard so a
/// frame that would exceed the egress MTU is dropped rather than forcing
/// outer IP fragmentation (plan §7, Codex r3). Pulled out of
/// `wg_encap_frame` so the arithmetic is unit-testable in isolation.
#[inline]
fn wg_encapped_size(inner_len: usize, outer_v6: bool) -> usize {
    let outer_ip_len = if outer_v6 { 40 } else { 20 };
    let wg_record_len = WG_DATA_HEADER_LEN + pad_to_16(inner_len) + POLY1305_TAG_LEN;
    wg_record_len + outer_ip_len + 8
}

/// Resolve the PHYSICAL underlay egress ifindex the OUTER (WG/UDP) datagram
/// actually leaves on, for a tunnel-resolved encap decision (#2680/#2701).
///
/// The interface that matters here is the PHYSICAL underlay egress — the one
/// the outer WG/UDP datagram leaves on — NOT
/// `decision.resolution.egress_ifindex`, which for a tunnel-resolved flow is
/// the tunnel LOGICAL ifindex (the WG interface, MTU ~1420, address a tunnel
/// address, used for zone/policy/CoS). BOTH the outer-MTU guard AND the outer
/// IP SOURCE address must follow this SAME physical egress:
///   - #2680: gating the outer size against the LOGICAL MTU is
///     apples-to-oranges and silently drops inner packets whose outer datagram
///     fits the 1500-byte underlay (broken PMTUD / tunnel transit).
///   - #2701: sourcing the outer IP from the LOGICAL ifindex reads a tunnel
///     address (or, when the logical WG iface carries no primary, `None` →
///     drop). The outer UDP must be sourced from the physical WAN primary.
///
/// For WireGuard the outer destination is the SELECTED peer endpoint
/// (`engine.peer_for_dest` LPM), NOT the endpoint-level `destination` (which
/// the build path zeroes to `0.0.0.0` for WG — the peer carries the real
/// outer hop). So the physical egress is the route to `outer_dst` in the
/// endpoint's transport table — exactly the interface the encapped datagram
/// egresses. `dynamic_neighbors` is `None`: the egress ifindex comes from
/// the ROUTE lookup, not from neighbor resolution, so the static forwarding
/// state suffices. (This is why `resolve_tunnel_outer`, which reads the
/// zeroed endpoint destination, cannot be reused here — it always NoRoutes
/// for WG.)
///
/// Fallback (conservative): if the outer route cannot be resolved (no FIB
/// entry / non-positive egress / the resolved egress is itself a tunnel
/// interface) fall back to the resolution's own `egress_ifindex` (the LOGICAL
/// ifindex). For the MTU guard this never makes it tighter than the pre-#2680
/// logical-MTU behaviour; for the source it preserves the pre-#2701 lookup,
/// so an unresolvable outer is no worse than before.
#[inline]
fn outer_physical_egress_ifindex(
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    endpoint: &TunnelEndpoint,
    outer_dst: IpAddr,
) -> i32 {
    // #2734: WG outer underlay resolution is per-tunnel-endpoint, not
    // per-inner-flow — pass None (per-destination ECMP spread).
    let outer = match outer_dst {
        IpAddr::V4(ip) => lookup_forwarding_resolution_v4(
            forwarding,
            None,
            ip,
            &endpoint.transport_table,
            1,
            false,
            None,
        ),
        IpAddr::V6(ip) => lookup_forwarding_resolution_v6(
            forwarding,
            None,
            ip,
            &endpoint.transport_table,
            1,
            false,
            None,
        ),
    };
    if outer.egress_ifindex > 0
        && outer.disposition != ForwardingDisposition::NoRoute
        && !forwarding.tunnel_interfaces.contains(&outer.egress_ifindex)
    {
        outer.egress_ifindex
    } else {
        decision.resolution.egress_ifindex
    }
}

/// The PHYSICAL underlay egress MTU the OUTER (WG/UDP) datagram must fit
/// (#2680). Thin wrapper over `outer_physical_egress_ifindex` so the MTU
/// guard and the outer-source lookup resolve the SAME physical egress.
///
/// The inner packet's own logical/PMTUD MTU is a SEPARATE concern handled
/// by the WG inner-MTU clamp / post-transform PMTUD on the TX dispatcher
/// (#2299/#2330/#2457); this helper is strictly outer-size-vs-physical-MTU.
/// Final fallback (egress row missing / MTU 0) is 1500.
#[inline]
fn outer_physical_egress_mtu(
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    endpoint: &TunnelEndpoint,
    outer_dst: IpAddr,
) -> usize {
    let physical_ifindex =
        outer_physical_egress_ifindex(decision, forwarding, endpoint, outer_dst);
    forwarding
        .egress
        .get(&physical_ifindex)
        .map(|e| e.mtu)
        .filter(|m| *m > 0)
        .unwrap_or(1500)
}

/// The PHYSICAL underlay egress MTU for a WireGuard endpoint, for the
/// post-transform PTB inner-MTU derivation (#2684).
///
/// This is the SAME physical-underlay SSOT (`outer_physical_egress_mtu`,
/// #2680) the encap drop guard uses, exposed so the TX dispatcher's
/// `post_transform_inner_mtu` advertises an inner MTU consistent with what
/// the encap guard actually admits. The PTB path runs BEFORE the per-packet
/// peer LPM (it has no inner frame to select a peer), but the WG outer
/// underlay is per-tunnel-endpoint, not per-inner-flow (#2734): every peer of
/// an endpoint egresses the same physical underlay. So we resolve the
/// physical egress via the FIRST peer endpoint that yields a route; the
/// fallback inside `outer_physical_egress_mtu` (route unresolvable → the
/// resolution's own `egress_ifindex` MTU = the tunnel LOGICAL MTU) preserves
/// the conservative pre-#2684 behaviour, never tighter.
///
/// Returns the logical-ifindex MTU fallback when the endpoint has no peer
/// with a learned/configured endpoint address (no outer hop to route to) —
/// the same value `tunnel_outer_mtu` would have produced, so the PTB is no
/// worse than before in that degenerate case.
///
/// # Why not `tunnel_outer_mtu`
/// For a WG transit flow `endpoint.destination` is `0.0.0.0`/`::`
/// (`forwarding_build::tunnels` zeroes it — the peer carries the real outer
/// hop), so `tunnel_outer_mtu`'s `tx_ifindex` resolution NoRoutes and the
/// chain falls through to the LOGICAL `egress_ifindex` MTU (~1420). Feeding
/// that to `wg_inner_mtu` subtracts the WG encap overhead a SECOND time
/// (the logical MTU is already underlay − encap), under-advertising the
/// inner PMTU by ~one encap (~75-95B). GRE is unaffected: its
/// `endpoint.destination` is the real outer hop, so `tunnel_outer_mtu`
/// resolves to the physical underlay correctly.
#[inline]
pub(in crate::afxdp) fn wg_endpoint_physical_outer_mtu(
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    endpoint: &TunnelEndpoint,
) -> usize {
    // The WG underlay is per-endpoint (#2734): the first peer with a known
    // endpoint address resolves the same physical egress as any other.
    let outer_dst = endpoint
        .wg_peers
        .iter()
        .find_map(|peer| peer.endpoint.map(|ep| ep.ip()));
    match outer_dst {
        Some(dst) => outer_physical_egress_mtu(decision, forwarding, endpoint, dst),
        // No peer endpoint to route to: fall back to the resolution's own
        // egress (the logical ifindex), exactly what `tunnel_outer_mtu`
        // would have yielded — no regression in the degenerate case.
        None => forwarding
            .egress
            .get(&decision.resolution.egress_ifindex)
            .map(|e| e.mtu)
            .filter(|m| *m > 0)
            .unwrap_or(1500),
    }
}

pub(super) fn wg_encap_frame(
    inner_frame: &[u8],
    inner_meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    let inner_meta = inner_meta.into();
    let id = decision.resolution.tunnel_endpoint_id;
    let endpoint = forwarding.tunnel_endpoints.get(&id)?;
    // #1873 (Codex code r2): refuse to encapsulate when the id's
    // owning netdev differs from the one recorded in the session's
    // stored resolution (egress_ifindex = logical_ifindex at resolve
    // time) — a re-owned id must fail the build (R-C gate drops the
    // frame), never encapsulate into the new owner.
    if decision.resolution.egress_ifindex > 0
        && endpoint.logical_ifindex != decision.resolution.egress_ifindex
    {
        return None;
    }
    let engine = forwarding.wg_engines.get(&id)?;
    let dst_mac = decision.resolution.neighbor_mac?;
    let src_mac = decision.resolution.src_mac?;
    let vlan_id = decision.resolution.tx_vlan_id;
    let outer_eth_len = if vlan_id > 0 { 18 } else { 14 };

    // Extract the inner IP packet (strip L2).
    let inner_l3 = match frame_l3_offset(inner_frame) {
        Some(offset) => offset,
        None => inner_meta.l3_offset as usize,
    };
    let inner_packet = inner_frame.get(inner_l3..)?;
    let inner_len = crate::afxdp::gre::packet_trimmed_len(inner_packet, inner_meta.addr_family)?;
    let inner_packet = &inner_packet[..inner_len];

    // #1434 B1b cryptokey routing: select the egress peer by the inner
    // destination's longest-prefix match in the AllowedIPs trie (NOT a
    // single scalar peer). A packet with no covering peer is dropped —
    // there is no peer to encrypt it to.
    let inner_dst = crate::afxdp::gre::inner_dst_ip(inner_packet, inner_meta.addr_family)?;
    let (peer_pubkey, peer_endpoint) = engine.peer_for_dest(inner_dst)?;
    // A responder-only peer with no learned endpoint cannot be an encap
    // TARGET on this transit path (the control thread learns the
    // endpoint from inbound traffic; this AF_XDP transit site has no
    // such state). Drop rather than encap to a phantom destination.
    let peer_endpoint = peer_endpoint?;
    // #2303: copy the inner DSCP+ECN onto the outer header (uniform
    // DSCP model + RFC 6040 ECN ingress copy) instead of hardcoding 0.
    let outer_tos = crate::afxdp::gre::inner_tos_byte(inner_packet, inner_meta.addr_family);

    // Outer family follows the peer endpoint address.
    let outer_v6 = peer_endpoint.is_ipv6();
    let outer_ip_len = if outer_v6 { 40 } else { 20 };

    // Exact pad-aware MTU guard (plan §7, Codex r3). The WG record is
    // WG_DATA_HEADER_LEN + pad_to_16(inner) + POLY1305_TAG_LEN; the full
    // outer frame adds eth + outer IP + UDP(8). Drop oversize rather than
    // letting the kernel fragment the outer datagram.
    //
    // #2680: the OUTER datagram must fit the PHYSICAL underlay egress MTU,
    // NOT `decision.resolution.egress_ifindex` (the tunnel LOGICAL ifindex,
    // MTU ~1420). Re-resolve the underlay egress via the route to the SELECTED
    // peer endpoint (the real outer hop for WG) and use its MTU; the
    // logical/inner MTU is a separate concern handled by the inner-MTU clamp.
    let outer_mtu = outer_physical_egress_mtu(decision, forwarding, endpoint, peer_endpoint.ip());
    let wg_record_len = WG_DATA_HEADER_LEN + pad_to_16(inner_packet.len()) + POLY1305_TAG_LEN;
    if wg_encapped_size(inner_packet.len(), outer_v6) > outer_mtu {
        // #1865: the promised "follow-up" counter store — same
        // `encap_mtu_drops` counter as the control thread's symmetric
        // guard (the plan's both-guards requirement).
        //
        // #2330: when a PTB is OWED (inner IPv4 DF or IPv6), the TX
        // dispatcher's pre-build `post_transform_inner_mtu` decision fires
        // BEFORE this builder is called (advertising the WG inner MTU =
        // `wg::mss::wg_inner_mtu`, the inverse of `wg_encapped_size`),
        // `mtu_signalled` skips the encap build, and this site is never
        // reached for that case — so the PTB and this drop counter never
        // both fire. This guard remains the backstop for a non-DF IPv4
        // inner (kept `Forward` to preserve fragmentable behaviour) whose
        // encapped outer still exceeds the MTU.
        crate::afxdp::wg::counters::WgCounters::bump(&engine.counters().encap_mtu_drops);
        return None;
    }

    // #2792 (agy-review-048 finding 048-11): eliminate the per-packet
    // heap churn. The pre-#2792 code allocated TWO Vecs per packet here —
    // an intermediate `wg_record` scratch for `try_encap`, then copied
    // that scratch into a second `out` frame Vec. Both are gone:
    //
    //   1. `wg_record` (removed): `try_encap` writes the WG transport
    //      record (data header + ciphertext + Poly1305 tag) starting at
    //      `out[0]` of whatever `&mut [u8]` it is handed. We hand it the
    //      UDP payload slot of `out` directly, so the encrypt lands in
    //      its final position — no intermediate buffer and no follow-up
    //      copy. The plaintext is staged on the stack inside `try_encap`
    //      (MaybeUninit), so the in-place encrypt is sound: snow's
    //      non-overlapping plaintext/ciphertext requirement is satisfied
    //      by that stack staging, not by a separate output buffer.
    //
    //   2. `out` is now sized ONCE to the pad-aware maximum record length
    //      (`wg_record_len`, the same arithmetic the MTU guard already
    //      validated above) and truncated to the actual encapped length
    //      after `try_encap` reports it. The single remaining `out`
    //      allocation is the function's owned return value (the
    //      `Vec<Vec<u8>>` TCP-segmentation caller needs an owned frame per
    //      segment) and is byte-for-byte identical to the GRE sibling's
    //      `encapsulate_native_gre_frame` output Vec — no WG-specific
    //      extra alloc remains.
    //
    // Wire output is unchanged: same header bytes, same ciphertext+tag,
    // same outer framing (proved byte-identical by
    // `wg_encap_in_place_matches_separate_buffer`).
    let outer_ip_start = outer_eth_len;
    let udp_start = outer_ip_start + outer_ip_len;
    let payload_start = udp_start + 8;
    // Size to the pad-aware maximum WG record; truncate to the real
    // length once `try_encap` reports `outcome.len`.
    let max_frame_len = payload_start + wg_record_len;
    let mut out = vec![0u8; max_frame_len];

    let outcome = match engine.try_encap(
        &peer_pubkey,
        inner_packet,
        out.get_mut(payload_start..payload_start + wg_record_len)?,
    ) {
        Ok(o) => o,
        Err(EncapError::NoSession) => {
            // Request a handshake (rate-limited relaxed atomic) and drop.
            engine.request_handshake(monotonic_nanos());
            return None;
        }
        Err(_) => return None,
    };
    let wg_record_actual = outcome.len;
    let udp_len = 8 + wg_record_actual;
    let frame_len = outer_eth_len + outer_ip_len + udp_len;
    out.truncate(frame_len);

    write_eth_header_slice(
        out.get_mut(..outer_eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        if outer_v6 { 0x86dd } else { 0x0800 },
    )?;

    // Source IP/port: the firewall egress primary address + WG listen
    // port; destination: the peer endpoint.
    //
    // #2701: the outer IP SOURCE must be the PHYSICAL underlay egress
    // primary, resolved via the route to the SELECTED peer endpoint — the
    // SAME egress the #2680 MTU guard uses — NOT
    // `decision.resolution.egress_ifindex` (the tunnel LOGICAL ifindex,
    // whose primary is a tunnel address or absent → wrong source / None
    // drop). Both follow `outer_physical_egress_ifindex`.
    let physical_egress_ifindex =
        outer_physical_egress_ifindex(decision, forwarding, endpoint, peer_endpoint.ip());
    let egress = forwarding.egress.get(&physical_egress_ifindex);
    let src_port = endpoint.wg_listen_port;
    let dst_port = peer_endpoint.port();

    match (outer_v6, peer_endpoint.ip()) {
        (false, IpAddr::V4(dst)) => {
            let src = egress.and_then(|e| e.primary_v4)?;
            let total_len = u16::try_from(outer_ip_len + udp_len).ok()?;
            write_ipv4_header(
                out.get_mut(outer_ip_start..outer_ip_start + 20)?,
                src,
                dst,
                PROTO_UDP,
                outer_tos,
                endpoint.ttl,
                total_len,
            )?;
            // UDP checksum is optional over IPv4; leave 0 (disabled).
            write_udp_header(
                out.get_mut(udp_start..udp_start + 8)?,
                src_port,
                dst_port,
                u16::try_from(udp_len).ok()?,
                0,
            )?;
        }
        (true, IpAddr::V6(dst)) => {
            let src = egress.and_then(|e| e.primary_v6)?;
            let payload_len = u16::try_from(udp_len).ok()?;
            write_ipv6_header(
                out.get_mut(outer_ip_start..outer_ip_start + 40)?,
                src,
                dst,
                PROTO_UDP,
                outer_tos,
                /* flow_label */ 0,
                endpoint.ttl,
                payload_len,
            )?;
            // IPv6 mandates a non-zero UDP checksum. Compute over the
            // pseudo-header + UDP header + payload.
            write_udp_header(
                out.get_mut(udp_start..udp_start + 8)?,
                src_port,
                dst_port,
                payload_len,
                0,
            )?;
            let csum = udp6_checksum(src, dst, &out[udp_start..udp_start + udp_len]);
            out[udp_start + 6..udp_start + 8].copy_from_slice(&csum.to_be_bytes());
        }
        _ => return None,
    }

    Some(out)
}

/// RFC 768 / RFC 8200 IPv6 UDP checksum over the pseudo-header + UDP
/// datagram. `udp` is the full UDP header+payload (checksum field 0).
fn udp6_checksum(src: std::net::Ipv6Addr, dst: std::net::Ipv6Addr, udp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let len = udp.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    sum += PROTO_UDP as u32; // next-header
    let mut i = 0;
    while i + 1 < udp.len() {
        sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
        i += 2;
    }
    if i < udp.len() {
        sum += (udp[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    if csum == 0 { 0xffff } else { csum }
}

#[cfg(test)]
mod wg_frame_tests {
    use super::super::super::test_fixtures::*;
    use super::*;

    #[test]
    fn pad_to_16_rounds_up() {
        assert_eq!(pad_to_16(0), 0);
        assert_eq!(pad_to_16(1), 16);
        assert_eq!(pad_to_16(16), 16);
        assert_eq!(pad_to_16(17), 32);
    }

    #[test]
    fn wg_encapped_size_is_pad_aware() {
        // inner 1 byte: pads to 16; record = 16 (hdr) + 16 (pad) + 16
        // (tag) = 48; + outer v4 IP(20) + UDP(8) = 76.
        assert_eq!(wg_encapped_size(1, false), 16 + 16 + 16 + 20 + 8);
        // v6 adds 20 more for the bigger outer IP header.
        assert_eq!(
            wg_encapped_size(1, true),
            wg_encapped_size(1, false) + 20
        );
        // An inner already a 16-multiple does not over-pad.
        assert_eq!(
            wg_encapped_size(32, false),
            WG_DATA_HEADER_LEN + 32 + POLY1305_TAG_LEN + 20 + 8
        );
    }

    // === #2680: the OUTER MTU guard gates against the PHYSICAL underlay
    // egress MTU, not the tunnel LOGICAL ifindex MTU. ===

    /// A tunnel-resolved `SessionDecision` whose resolution carries
    /// `egress_ifindex` = the tunnel LOGICAL ifindex (what the resolver
    /// stores) and `tunnel_endpoint_id` = the WG endpoint id.
    fn wg_tunnel_decision(logical_ifindex: i32, tunnel_endpoint_id: u16) -> SessionDecision {
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::MissingNeighbor,
                local_ifindex: 0,
                egress_ifindex: logical_ifindex,
                tx_ifindex: 0,
                tunnel_endpoint_id,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: crate::nat::NatDecision::default(),
        }
    }

    // The peer endpoint the WG fixture's single peer learns / is configured
    // with — the REAL outer hop (the endpoint-level destination is zeroed for
    // WG). The route to this IP egresses on the physical underlay (reth0.80).
    const WG_PEER_OUTER_DST: IpAddr =
        IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));

    #[test]
    fn outer_mtu_uses_physical_egress_not_tunnel_logical() {
        // The WG endpoint's logical interface (wg0.0, ifindex 400) has MTU
        // 1420; the outer transport egresses on reth0.80 (ifindex 12, MTU
        // 1500) via the route to the peer endpoint. The guard must use the
        // PHYSICAL 1500, NOT the logical 1420.
        let state = build_forwarding_state(&wg_outer_mtu_snapshot());
        // Sanity: both interfaces really do carry the distinct MTUs the
        // fixture claims, so the assertion below is meaningful.
        assert_eq!(state.egress.get(&400).map(|e| e.mtu), Some(1420));
        assert_eq!(state.egress.get(&12).map(|e| e.mtu), Some(1500));

        let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");
        let decision = wg_tunnel_decision(400, 1);
        // The fix: the guard MTU is the physical underlay (1500). Reverting
        // to the logical-ifindex lookup would return 1420 → this fails red.
        assert_eq!(
            outer_physical_egress_mtu(&decision, &state, endpoint, WG_PEER_OUTER_DST),
            1500,
            "outer guard must use the PHYSICAL underlay MTU (reth0.80=1500), \
             not the tunnel LOGICAL ifindex MTU (wg0.0=1420)"
        );
    }

    #[test]
    fn fits_physical_but_exceeds_logical_inner_is_not_dropped() {
        // An inner packet whose OUTER encapped size fits the PHYSICAL egress
        // (1500) but exceeds the tunnel LOGICAL MTU (1420) must NOT be
        // dropped. Pick an inner length whose encapped size is in (1420,
        // 1500].
        let state = build_forwarding_state(&wg_outer_mtu_snapshot());
        let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");
        let decision = wg_tunnel_decision(400, 1);
        let physical_mtu =
            outer_physical_egress_mtu(&decision, &state, endpoint, WG_PEER_OUTER_DST);
        let logical_mtu = 1420usize;

        // 1400-byte inner → ~1460-ish outer (v4): fits 1500, exceeds 1420.
        let inner = 1400usize;
        let encapped = wg_encapped_size(inner, false);
        assert!(
            encapped > logical_mtu,
            "the test inner must exceed the logical MTU (else it proves nothing): \
             {encapped} <= {logical_mtu}"
        );
        // With the fix the guard compares against physical_mtu → NOT dropped.
        // Reverting to the logical MTU would make physical_mtu == 1420 and
        // this assertion would fail red (the silent drop the bug caused).
        assert!(
            encapped <= physical_mtu,
            "fits-physical-exceeds-logical inner must be forwarded, not dropped \
             ({encapped} > {physical_mtu})"
        );
    }

    #[test]
    fn genuinely_oversized_outer_still_drops_against_physical() {
        // An inner whose OUTER encapped size exceeds even the PHYSICAL MTU
        // (1500) is still correctly dropped — the fix widens the guard to the
        // underlay, it does not disable it.
        let state = build_forwarding_state(&wg_outer_mtu_snapshot());
        let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");
        let decision = wg_tunnel_decision(400, 1);
        let physical_mtu =
            outer_physical_egress_mtu(&decision, &state, endpoint, WG_PEER_OUTER_DST);
        assert_eq!(physical_mtu, 1500);
        // 1480-byte inner pads to 1488; record 1488+16+16=1520; +20+8 = 1548
        // > 1500 → drop.
        assert!(
            wg_encapped_size(1480, false) > physical_mtu,
            "a genuinely oversized outer must still exceed the physical MTU"
        );
    }

    #[test]
    fn outer_mtu_falls_back_to_logical_when_outer_unresolvable() {
        // Conservative fallback: if the outer destination has no FIB entry the
        // route lookup NoRoutes → fall back to the resolution's own
        // egress_ifindex MTU (the pre-#2680 behaviour), never tighter.
        let state = build_forwarding_state(&wg_outer_mtu_snapshot());
        let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");
        let decision = wg_tunnel_decision(400, 1);
        // 198.51.100.9 has no route → NoRoute → fall back to egress_ifindex
        // (400, the logical, MTU 1420).
        let unrouted = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 9));
        assert_eq!(
            outer_physical_egress_mtu(&decision, &state, endpoint, unrouted),
            1420
        );
    }

    // === #2701: the OUTER IP SOURCE follows the PHYSICAL underlay egress,
    // not the tunnel LOGICAL ifindex. ===

    #[test]
    fn outer_source_uses_physical_egress_not_tunnel_logical() {
        // The WG endpoint's logical interface (wg0.0, ifindex 400) carries a
        // TUNNEL address (10.123.0.1) and no WAN primary; the outer transport
        // egresses on reth0.80 (ifindex 12, primary 172.16.80.8) via the route
        // to the peer endpoint. The outer source must be the PHYSICAL WAN
        // primary, NOT the logical tunnel address (or None).
        let state = build_forwarding_state(&wg_outer_mtu_snapshot());
        let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");
        let decision = wg_tunnel_decision(400, 1);

        // Sanity: the logical iface's primary really is the tunnel address —
        // sourcing from it (the bug) would leak a tunnel source / fail policy.
        assert_eq!(
            state.egress.get(&400).and_then(|e| e.primary_v4),
            Some(std::net::Ipv4Addr::new(10, 123, 0, 1)),
            "logical wg0.0 primary is the tunnel address (the wrong source)"
        );

        // The fix: resolve the physical egress (reth0.80, ifindex 12) and read
        // its WAN primary. Reverting to `decision.resolution.egress_ifindex`
        // (400) would read the tunnel address → this fails red.
        let physical =
            outer_physical_egress_ifindex(&decision, &state, endpoint, WG_PEER_OUTER_DST);
        assert_eq!(physical, 12, "outer source must follow the PHYSICAL egress");
        assert_eq!(
            state.egress.get(&physical).and_then(|e| e.primary_v4),
            Some(std::net::Ipv4Addr::new(172, 16, 80, 8)),
            "outer source must be the PHYSICAL WAN primary (172.16.80.8), \
             not the tunnel-logical address"
        );
    }

    #[test]
    fn outer_source_falls_back_to_logical_when_outer_unresolvable() {
        // Conservative fallback parity with the MTU helper: an unresolvable
        // outer destination falls back to the resolution's own egress_ifindex
        // (the logical), so the source is no worse than the pre-#2701 lookup.
        let state = build_forwarding_state(&wg_outer_mtu_snapshot());
        let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");
        let decision = wg_tunnel_decision(400, 1);
        let unrouted = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 9));
        assert_eq!(
            outer_physical_egress_ifindex(&decision, &state, endpoint, unrouted),
            400,
            "unresolvable outer falls back to the logical egress_ifindex"
        );
    }

    // === #2701 END-TO-END: `wg_encap_frame` writes the PHYSICAL WAN primary
    // into the BUILT outer IP header — the call-site guard, not just the
    // helper. ===
    //
    // The helper tests above prove `outer_physical_egress_ifindex` resolves
    // the physical egress, but they do NOT call `wg_encap_frame`: reverting
    // ONLY the call-site source lookup (back to
    // `forwarding.egress.get(&decision.resolution.egress_ifindex)`) leaves
    // them green. These tests close that gap by asserting on the emitted
    // outer-IP source bytes of a real built frame, for BOTH outer families.

    use crate::afxdp::wg::session::{SessionRole, WgSession};
    use crate::afxdp::wg::{WgEngine, WgEngineConfig, WgPeerConfig};
    use std::sync::Arc;

    fn wg_keypair() -> ([u8; 32], [u8; 32]) {
        let kp = snow::Builder::new(crate::afxdp::wg::WG_NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let mut priv_k = [0u8; 32];
        let mut pub_k = [0u8; 32];
        priv_k.copy_from_slice(&kp.private);
        pub_k.copy_from_slice(&kp.public);
        (priv_k, pub_k)
    }

    /// Build an ESTABLISHED initiator engine whose single peer's endpoint is
    /// `peer_ep` (the real outer hop, so `peer_for_dest` returns a concrete
    /// destination that the FIB route resolves to the physical egress) and
    /// whose AllowedIPs cover `peer_cidr` (so the inner dst LPM-selects it).
    /// `try_encap` succeeds because a real Noise IKpsk2 handshake is driven.
    fn established_initiator_engine(
        peer_ep: std::net::SocketAddr,
        peer_cidr: &str,
    ) -> WgEngine {
        let (init_priv, init_pub) = wg_keypair();
        let (resp_priv, resp_pub) = wg_keypair();

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

        let mut init_hs = init_engine.build_initiator_handshake(&resp_pub).unwrap();
        let mut resp_hs = resp_engine.build_responder_handshake().unwrap();
        let mut buf = [0u8; 1024];
        let mut sink = [0u8; 1024];
        let n1 = init_hs.write_message(&[], &mut buf).unwrap();
        resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
        let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
        init_hs.read_message(&buf[..n2], &mut sink).unwrap();
        let init_xport = init_hs.into_stateless_transport_mode().unwrap();
        let now = crate::afxdp::wg::counters::monotonic_now_ns();
        init_engine
            .install_session(
                &resp_pub,
                Arc::new(WgSession::new_with_role(
                    init_xport,
                    0xaaaa_0001u32,
                    0xbbbb_0001u32,
                    resp_pub,
                    SessionRole::Initiator,
                    now,
                )),
            )
            .unwrap();
        init_engine
    }

    /// Build an ESTABLISHED initiator/responder PAIR sharing one real Noise
    /// handshake. The initiator (returned `.0`) encaps via `wg_encap_frame`;
    /// the responder (returned `.1`) can `try_decap` the resulting WG record,
    /// recovering the original inner IP packet. Used by the #2792 in-place
    /// encrypt byte-identity / round-trip proof: if the in-place encrypt wrote
    /// to the wrong slice offset (or the truncation/length math drifted), the
    /// decap would fail to authenticate or recover the wrong plaintext.
    fn established_pair(
        peer_ep: std::net::SocketAddr,
        peer_cidr: &str,
    ) -> (WgEngine, WgEngine) {
        let (init_priv, init_pub) = wg_keypair();
        let (resp_priv, resp_pub) = wg_keypair();

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
        // Initiator: local index 0xaaaa_0001, sends to responder index
        // 0xbbbb_0001 (the value snow stamps into the WG data header as the
        // RECEIVER index). The responder must therefore be reachable in its
        // sessions_by_local_index under 0xbbbb_0001.
        init_engine
            .install_session(
                &resp_pub,
                Arc::new(WgSession::new_with_role(
                    init_xport,
                    0xaaaa_0001u32,
                    0xbbbb_0001u32,
                    resp_pub,
                    SessionRole::Initiator,
                    now,
                )),
            )
            .unwrap();
        resp_engine
            .install_session(
                &init_pub,
                Arc::new(WgSession::new_with_role(
                    resp_xport,
                    0xbbbb_0001u32,
                    0xaaaa_0001u32,
                    init_pub,
                    SessionRole::Responder,
                    now,
                )),
            )
            .unwrap();
        (init_engine, resp_engine)
    }

    /// A tunnel-resolved decision with the LOGICAL egress_ifindex (400, the
    /// `wg0.0` tunnel iface — its primary is the tunnel address 10.123.0.1)
    /// and both MACs resolved so `wg_encap_frame` builds rather than dropping
    /// on a missing neighbor.
    fn wg_encap_decision() -> SessionDecision {
        let mut d = wg_tunnel_decision(400, 1);
        d.resolution.disposition = ForwardingDisposition::ForwardCandidate;
        d.resolution.neighbor_mac = Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        d.resolution.src_mac = Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
        d
    }

    /// Minimal L2/IPv4/UDP inner frame with dst in the WG peer's AllowedIPs
    /// (10.123.0.0/24) so `peer_for_dest` selects the established peer.
    fn inner_v4_frame() -> Vec<u8> {
        let src_ip = std::net::Ipv4Addr::new(10, 0, 61, 50);
        let dst_ip = std::net::Ipv4Addr::new(10, 123, 0, 9);
        let payload = [0xabu8; 32];
        let total_len = (20 + 8 + payload.len()) as u16;
        let mut frame = Vec::new();
        // eth
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame.extend_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
        frame.extend_from_slice(&[0x08, 0x00]);
        // ipv4
        frame.extend_from_slice(&[
            0x45, 0x00,
            (total_len >> 8) as u8, total_len as u8,
            0x00, 0x01, 0x00, 0x00,
            64, PROTO_UDP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        // udp
        frame.extend_from_slice(&4000u16.to_be_bytes());
        frame.extend_from_slice(&5000u16.to_be_bytes());
        frame.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&payload);
        let ip_sum = crate::afxdp::frame::checksum::checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        frame
    }

    fn inner_v4_meta() -> ForwardPacketMeta {
        ForwardPacketMeta {
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_UDP,
            ..ForwardPacketMeta::default()
        }
    }

    #[test]
    fn wg_encap_frame_sources_outer_from_physical_wan_primary_v4() {
        // Build the real forwarding state from the shared #2680 fixture:
        // reth0.80 (ifindex 12, primary 172.16.80.8) is the physical egress
        // via the route to the peer endpoint (203.0.113.7); wg0.0
        // (ifindex 400, primary 10.123.0.1) is the LOGICAL tunnel iface.
        let mut state = build_forwarding_state(&wg_outer_mtu_snapshot());
        // Swap in an ESTABLISHED engine (the snapshot one has no session, so
        // try_encap would NoSession) whose peer endpoint == the fixture route
        // target so the FIB resolves to the physical egress (ifindex 12).
        let peer_ep: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
        state
            .wg_engines
            .insert(1, Arc::new(established_initiator_engine(peer_ep, "10.123.0.0/24")));

        let decision = wg_encap_decision();
        let frame = inner_v4_frame();
        let out = wg_encap_frame(&frame, inner_v4_meta(), &decision, &state)
            .expect("wg_encap_frame must build (established session, routed peer)");

        // Outer layout: eth(14) + IPv4(20). The IPv4 source is at bytes
        // 14+12 ..= 14+15. The fix sources it from the PHYSICAL WAN primary
        // (172.16.80.8). Reverting the call-site source lookup to the LOGICAL
        // egress_ifindex (400) would write the tunnel address 10.123.0.1 → red.
        let outer_src = &out[26..30];
        assert_eq!(
            outer_src,
            &[172, 16, 80, 8],
            "outer IPv4 source must be the PHYSICAL WAN primary (172.16.80.8), \
             not the tunnel-logical address (10.123.0.1) — call-site #2701 guard"
        );
        // Sanity: it is NOT the logical tunnel address.
        assert_ne!(outer_src, &[10, 123, 0, 1], "outer source must not be the tunnel addr");
        // And the destination is the peer endpoint (203.0.113.7).
        assert_eq!(&out[30..34], &[203, 0, 113, 7], "outer dst is the peer endpoint");
    }

    /// Minimal L2/IPv6/UDP inner frame with dst in `fd00:123::/64` so
    /// `peer_for_dest` selects the v6-endpoint peer.
    fn inner_v6_frame() -> Vec<u8> {
        let src_ip: std::net::Ipv6Addr = "fd00:61::50".parse().unwrap();
        let dst_ip: std::net::Ipv6Addr = "fd00:123::9".parse().unwrap();
        let payload = [0xabu8; 32];
        let payload_len = (8 + payload.len()) as u16; // UDP header + data
        let mut frame = Vec::new();
        // eth
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame.extend_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
        frame.extend_from_slice(&[0x86, 0xdd]);
        // ipv6: version/tc/flow, payload len, next header (UDP), hop limit
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.push(PROTO_UDP);
        frame.push(64);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        // udp
        frame.extend_from_slice(&4000u16.to_be_bytes());
        frame.extend_from_slice(&5000u16.to_be_bytes());
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    fn inner_v6_meta() -> ForwardPacketMeta {
        ForwardPacketMeta {
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_UDP,
            ..ForwardPacketMeta::default()
        }
    }

    #[test]
    fn wg_encap_frame_sources_outer_from_physical_wan_primary_v6() {
        // Clone the shared fixture and extend it with an IPv6 WAN primary on
        // reth0.80 + a v6 route to a v6 peer endpoint, so the outer family is
        // IPv6 and the physical egress (ifindex 12) carries a v6 primary
        // (2001:559:8585:80::8) distinct from the logical wg0.0 v6 address.
        let mut snap = wg_outer_mtu_snapshot();
        // reth0.80 gets the WAN v6 primary; wg0.0 gets a tunnel v6 address.
        snap.interfaces[0].addresses.push(crate::InterfaceAddressSnapshot {
            family: "inet6".to_string(),
            address: "2001:559:8585:80::8/64".to_string(),
            scope: 0,
        });
        snap.interfaces[1].addresses.push(crate::InterfaceAddressSnapshot {
            family: "inet6".to_string(),
            address: "fd00:dead::1/64".to_string(),
            scope: 0,
        });
        // v6 route to the peer endpoint prefix, egressing reth0.80.
        snap.routes.push(crate::RouteSnapshot {
            table: "inet6.0".to_string(),
            family: "inet6".to_string(),
            destination: "2001:db8:113::/48".to_string(),
            next_hops: vec!["2001:559:8585:80::1@reth0.80".to_string()],
            discard: false,
            next_table: String::new(),
            preference: 0,
        });
        // The WG endpoint's transport table follows the v6 outer family.
        snap.tunnel_endpoints[0].outer_family = "inet6".to_string();
        snap.tunnel_endpoints[0].transport_table = "inet6.0".to_string();
        snap.tunnel_endpoints[0].source = "2001:559:8585:80::8".to_string();
        snap.tunnel_endpoints[0].destination = "2001:db8:113::7".to_string();
        snap.tunnel_endpoints[0].wg_peers[0].wg_allowed_ips = vec!["fd00:123::/64".to_string()];
        snap.tunnel_endpoints[0].wg_peers[0].wg_endpoint = "[2001:db8:113::7]:51820".to_string();

        let mut state = build_forwarding_state(&snap);
        let peer_ep: std::net::SocketAddr = "[2001:db8:113::7]:51820".parse().unwrap();
        state
            .wg_engines
            .insert(1, Arc::new(established_initiator_engine(peer_ep, "fd00:123::/64")));

        let decision = wg_encap_decision();
        let frame = inner_v6_frame();
        let out = wg_encap_frame(&frame, inner_v6_meta(), &decision, &state)
            .expect("wg_encap_frame must build a v6 outer (established session, routed peer)");

        // Outer layout: eth(14) + IPv6(40). The IPv6 source is at bytes
        // 14+8 ..= 14+23, i.e. out[22..38]. It must be the PHYSICAL WAN v6
        // primary. Reverting the call-site lookup to the LOGICAL ifindex (400)
        // would write the tunnel v6 address (fd00:dead::1) → red.
        let expected: std::net::Ipv6Addr = "2001:559:8585:80::8".parse().unwrap();
        let tunnel_addr: std::net::Ipv6Addr = "fd00:dead::1".parse().unwrap();
        assert_eq!(
            &out[22..38],
            &expected.octets(),
            "outer IPv6 source must be the PHYSICAL WAN v6 primary, not the tunnel-logical address"
        );
        assert_ne!(&out[22..38], &tunnel_addr.octets());
        // Destination is the v6 peer endpoint.
        let dst: std::net::Ipv6Addr = "2001:db8:113::7".parse().unwrap();
        assert_eq!(&out[38..54], &dst.octets(), "outer v6 dst is the peer endpoint");
    }

    #[test]
    fn wg_encap_in_place_matches_separate_buffer() {
        // #2792 correctness lock: the in-place encrypt (the WG record is
        // written DIRECTLY into the output frame's UDP payload slot, removing
        // the pre-#2792 intermediate `wg_record` Vec + copy) must produce a
        // frame whose WG record (a) sits at the exact UDP payload offset, (b)
        // is the exact pad-aware record length, and (c) decrypts back to the
        // ORIGINAL inner IP packet under the paired peer's transport. A revert
        // that wrote the encrypt to the wrong offset, mis-sized the buffer, or
        // truncated incorrectly fails the decap (auth/length) → red.
        let mut state = build_forwarding_state(&wg_outer_mtu_snapshot());
        let peer_ep: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let (init_engine, resp_engine) = established_pair(peer_ep, "10.123.0.0/24");
        state.wg_engines.insert(1, Arc::new(init_engine));

        let decision = wg_encap_decision();
        let frame = inner_v4_frame();
        // The inner IP packet the encap path actually encrypts: strip L2,
        // trim to the IP total-length (mirrors wg_encap_frame's own slicing).
        let inner_l3 = 14usize;
        let inner_packet = &frame[inner_l3..];
        let inner_len =
            crate::afxdp::gre::packet_trimmed_len(inner_packet, libc::AF_INET as u8).unwrap();
        let expected_inner = inner_packet[..inner_len].to_vec();

        let out = wg_encap_frame(&frame, inner_v4_meta(), &decision, &state)
            .expect("wg_encap_frame must build (established session, routed peer)");

        // Outer framing: eth(14) + IPv4(20) + UDP(8) = 42-byte payload offset.
        let payload_start = 14 + 20 + 8;
        // The WG record is the remainder of the frame. Its length must be the
        // exact pad-aware record size (header + pad_to_16(inner) + tag).
        let expected_record_len =
            WG_DATA_HEADER_LEN + pad_to_16(expected_inner.len()) + POLY1305_TAG_LEN;
        let wg_record = &out[payload_start..];
        assert_eq!(
            wg_record.len(),
            expected_record_len,
            "in-place encrypt must leave exactly the pad-aware WG record at the UDP payload offset"
        );

        // Round-trip: the paired responder must decrypt the in-place-written
        // record back to the ORIGINAL inner IP packet. This proves the
        // ciphertext+tag landed at the correct offset and the framing is
        // byte-faithful to the pre-#2792 separate-buffer path.
        let mut recovered = vec![0u8; expected_record_len];
        let dec = resp_engine
            .try_decap(wg_record, &mut recovered)
            .expect("paired responder must authenticate the in-place WG record");
        assert_eq!(
            &recovered[..dec.len],
            &expected_inner[..],
            "decapped plaintext must equal the original inner IP packet (in-place encrypt is byte-faithful)"
        );

        // Outer total-length fields must agree with the truncated frame size
        // (the truncation math, not the max-sized scratch, drives the wire).
        let ip_total = u16::from_be_bytes([out[16], out[17]]) as usize;
        assert_eq!(ip_total, 20 + 8 + expected_record_len, "IPv4 total length tracks the real record");
        let udp_len = u16::from_be_bytes([out[38], out[39]]) as usize;
        assert_eq!(udp_len, 8 + expected_record_len, "UDP length tracks the real record");
        assert_eq!(out.len(), payload_start + expected_record_len, "frame truncated to the real size");
    }

    #[test]
    fn wg_mtu_guard_drops_oversize_inner() {
        // At a 1500-byte v4 outer MTU the largest inner that fits is
        // 1500 - 20 - 8 - 16 - 16 = 1440, padded to a 16-multiple. A
        // 1441-byte inner pads to 1456 and overflows.
        let mtu = 1500usize;
        assert!(
            wg_encapped_size(1440, false) <= mtu,
            "1440-byte inner must fit a 1500 v4 outer MTU"
        );
        assert!(
            wg_encapped_size(1441, false) > mtu,
            "1441-byte inner (pads to 1456) must overflow and be dropped"
        );
    }
}
