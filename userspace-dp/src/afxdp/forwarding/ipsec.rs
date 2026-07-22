//! #5650: IPsec traffic classification and inbound admission decision. Pure
//! code-motion split out of `forwarding/mod.rs` (behavior-identical).

use super::*;

/// Returns true if the packet is IPsec traffic (ESP protocol 50, AH protocol
/// 51, or IKE UDP ports 500/4500) that should be passed to the kernel for
/// XFRM processing.
///
/// AH (Authentication Header, proto 51) is a configurable host-terminated
/// IPsec protocol (`set security ipsec proposal ... protocol ah`,
/// pkg/config/schema_security.go). Like ESP it carries no transport port, so
/// only the protocol-number arm applies.
///
/// The predicate is family-symmetric — it keys solely on `meta.protocol` —
/// but in practice `meta.protocol == PROTO_AH` only ever occurs for **IPv4
/// AH**. The XDP shim's IPv6 parser treats AH as an extension header and
/// walks THROUGH it (`NEXTHDR_AUTH` arm in `userspace-xdp/src/lib.rs`),
/// setting `meta.protocol` to AH's inner next-header rather than 51. So the
/// `PROTO_AH` arm is a v4-only backstop; it never fires for IPv6 AH.
///
/// This is not a functional gap. IPv6 host-terminated AH-to-self still
/// reaches the kernel XFRM stack via the shim's `is_local_destination`
/// shunt, which fires for any local-destination packet *before* the
/// userspace dataplane runs this predicate; transit AH (v4 or v6) takes
/// ordinary forwarding. ESP (proto 50) is parsed as a terminal protocol on
/// both families, so ESP is recognized here for v4 and v6 alike. Giving this
/// predicate true IPv6 AH coverage would require the shim to surface an
/// "AH present" signal instead of walking past the header — out of scope
/// here, and unnecessary given the local-dest shunt.
#[inline]
pub(in crate::afxdp) fn is_ipsec_traffic(protocol: u8, dst_port: u16) -> bool {
    protocol == PROTO_ESP
        || protocol == PROTO_AH
        || (protocol == PROTO_UDP && (dst_port == 500 || dst_port == 4500))
}

/// #4323: the Stage-11 admission class of an IPsec packet that `is_ipsec_traffic`
/// already matched. Only a NEW inbound IKE initiation is subject to the per-zone
/// host-inbound `ike`/`ipsec` gate; every other IPsec class is unconditionally
/// exempt (the negotiated SA is the authorization).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum IpsecAdmissionClass {
    /// ESP/AH raw data plane, ESP-in-UDP, a NAT-T keepalive, OR a NON-initial
    /// IKE packet (the exchange already carries a responder SPI). Always
    /// passthrough — mirrors the kernel host-inbound chain's global
    /// `meta l4proto { 50, 51 } accept` (ESP/AH) and `ct established,related
    /// accept` (later IKE), so the IPsec data plane and every return/reply IKE
    /// packet transit even on a zone that omits `ike`.
    Exempt,
    /// The FIRST packet of a NEW inbound IKE exchange (we would be the
    /// responder): an ISAKMP header whose Responder SPI/cookie is all-zero
    /// (IKEv2 IKE_SA_INIT request / IKEv1 Main- or Aggressive-mode first
    /// message). This is the packet the Junos `system-services ike` knob is
    /// meant to gate, so it is subject to the per-zone host-inbound admit check.
    NewInboundIke,
}

/// #4323: classify an IPsec packet (one `is_ipsec_traffic` matched) into its
/// Stage-11 admission class. Only a NEW inbound IKE initiation
/// ([`IpsecAdmissionClass::NewInboundIke`]) is gated on host-inbound; every
/// other class is [`IpsecAdmissionClass::Exempt`] (unconditional passthrough).
///
/// New-vs-established is derived STATELESSLY from the ISAKMP header rather than
/// from conntrack state (the userspace-dp secondary path installs no session for
/// a passthrough flow, so a session lookup would be dead here): the first packet
/// of a new exchange has an all-zero Responder SPI, and every later packet
/// carries the responder's SPI. This admits all return/reply IKE (the AGY-M2
/// established-first requirement) without a session table.
///
/// `l4_offset` is the UDP header offset within `packet_frame`; the ISAKMP header
/// follows the 8-byte UDP header (and, on NAT-T UDP 4500, the 4-byte non-ESP
/// marker). A missing / too-short ISAKMP header fails CLOSED (`NewInboundIke`) so
/// a truncated IKE to an unpermitted source is gated, never silently admitted.
pub(in crate::afxdp) fn classify_ipsec_admission(
    packet_frame: &[u8],
    l4_offset: usize,
    protocol: u8,
    dst_port: u16,
) -> IpsecAdmissionClass {
    // ESP (50) / AH (51): raw IPsec data plane — the SA is the authorization.
    if protocol != PROTO_UDP {
        return IpsecAdmissionClass::Exempt;
    }
    // UDP payload (ISAKMP or, on 4500, the NAT-T non-ESP marker) starts after
    // the fixed 8-byte UDP header.
    let Some(payload) = packet_frame.get(l4_offset + 8..) else {
        return IpsecAdmissionClass::NewInboundIke;
    };
    let isakmp = if dst_port == 4500 {
        // RFC 3948 NAT-T demux: a 4-byte all-zero non-ESP marker precedes IKE on
        // UDP 4500. Anything else on 4500 is ESP-in-UDP (its non-zero ESP SPI is
        // the first word) or a 1-byte NAT-T keepalive — both exempt like raw ESP.
        match payload.get(0..4) {
            Some([0, 0, 0, 0]) => &payload[4..],
            _ => return IpsecAdmissionClass::Exempt,
        }
    } else {
        // UDP 500 — ISAKMP directly, no non-ESP marker.
        payload
    };
    // ISAKMP header: Initiator SPI [0..8], Responder SPI [8..16]. A new exchange's
    // first packet carries an all-zero Responder SPI; a set Responder SPI means
    // the exchange is under way (established/related) — exempt.
    match isakmp.get(8..16) {
        Some(responder_spi) if responder_spi.iter().all(|&b| b == 0) => {
            IpsecAdmissionClass::NewInboundIke
        }
        Some(_) => IpsecAdmissionClass::Exempt,
        None => IpsecAdmissionClass::NewInboundIke,
    }
}
