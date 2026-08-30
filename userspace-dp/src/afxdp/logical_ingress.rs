//! #7167: the shared logical-tunnel-ingress primitive.
//!
//! Turning decapsulated tunnel plaintext into a packet the normal AF_XDP
//! worker pipeline can adjudicate is four steps: synthesize Ethernet framing
//! around the raw inner L3 bytes, apply the RFC 6040 decap-side ECN combine,
//! reparse the inner flow, and build an inner `UserspaceDpMeta` bound to the
//! tunnel's LOGICAL ifindex and the zone that ifindex maps to.
//!
//! Native GRE decap has done exactly this since #921, but inline inside
//! `gre::try_native_gre_decap_from_frame` and welded to GRE: its endpoint
//! lookup filters `TunnelKind::Gre` and indexes `forwarding.gre_decap_index`.
//! Extracting the protocol-agnostic half here is a prerequisite for giving
//! WireGuard and IPsec plaintext the same treatment (#7167) WITHOUT a second
//! copy of this logic -- a divergence between two copies of a
//! synthesize/rebind/reparse path is precisely the #7176 C179-001 defect.
//!
//! This extraction is behaviour-neutral: GRE is the only caller, and it passes
//! exactly the values it previously used inline.

use super::*;
use super::gre::{apply_decap_ecn_combine, packet_tcp_flags};
use std::sync::atomic::AtomicU64;

/// Everything the shared body cannot derive for itself.
///
/// Deliberately has **no** `Default` and **no** `Option` on the generation
/// fields. A struct literal must therefore name every field, so a new caller
/// cannot acquire a generation by omission.
///
/// That matters because `config_generation` / `fib_generation` are what
/// attachment fencing rests on (#7167 invariant 5: "a packet decrypted under
/// an old attachment must never be evaluated under a replacement's zone/VRF
/// identity"). GRE inherits both from the triggering RX meta because it runs
/// inside a worker on a received packet. A caller that has no ingress meta --
/// the WireGuard control thread, for instance -- has no such value to inherit,
/// and fabricating one (`0`, or a freshly-read current value) would compile,
/// adjudicate, and violate the fencing invariant SILENTLY, because a
/// fabricated generation always looks current. Supply the generation captured
/// when the attachment the packet was decrypted under was resolved, or do not
/// call this.
pub(in crate::afxdp) struct LogicalIngressParams<'a> {
    /// Raw inner L3 bytes, with no Ethernet header.
    pub(in crate::afxdp) inner_packet: &'a [u8],
    /// `libc::AF_INET` / `AF_INET6` of the inner packet.
    pub(in crate::afxdp) inner_family: u8,
    /// Ethertype to write into the synthesized Ethernet header.
    pub(in crate::afxdp) inner_eth_proto: u16,
    /// Inner L4 protocol, and offsets RELATIVE to the start of the inner L3
    /// header (the shared body adds the 14-byte synthetic Ethernet header).
    pub(in crate::afxdp) protocol: u8,
    pub(in crate::afxdp) rel_l4_offset: u16,
    pub(in crate::afxdp) payload_offset: u16,
    /// The tunnel's LOGICAL ifindex -- never the outer/physical one. The
    /// ingress zone is derived from it via `ifindex_to_zone_id`, so passing a
    /// physical ifindex here would adjudicate inner traffic under the
    /// underlay's zone (#7167 invariant 2).
    pub(in crate::afxdp) logical_ifindex: i32,
    /// Outer ECN bits for the RFC 6040 §4.2 combine, or `None` when the outer
    /// header is unavailable/truncated. GRE reads these from the still-present
    /// outer IP header; a protocol whose outer header is already gone by this
    /// point must capture them earlier rather than skip the combine.
    pub(in crate::afxdp) outer_ecn: Option<u8>,
    /// Counter bumped when the combine rejects an illegal outer-CE /
    /// inner-Not-ECT pair. Per-protocol so the drop is attributable.
    pub(in crate::afxdp) ecn_illegal_drops: &'static AtomicU64,
    /// Per-protocol meta flags. GRE passes `GRE_DECAP_INGRESS_FLAG` (#2486);
    /// "whatever GRE passes" is not an answer for another protocol.
    pub(in crate::afxdp) meta_flags: u8,
    pub(in crate::afxdp) rx_queue_index: u32,
    /// See the struct-level note: required, no default, no fallback.
    pub(in crate::afxdp) config_generation: u64,
    pub(in crate::afxdp) fib_generation: u32,
}

/// Build the Ethernet-framed inner packet and its logical-ingress meta.
///
/// Returns `None` when the inner packet cannot be parsed or the RFC 6040
/// combine rejects the packet (the relevant counter is bumped first).
pub(in crate::afxdp) fn build_logical_ingress_packet(
    forwarding: &ForwardingState,
    params: &LogicalIngressParams<'_>,
) -> Option<(Vec<u8>, UserspaceDpMeta)> {
    let mut synthetic = vec![0u8; 14 + params.inner_packet.len()];
    synthetic[12..14].copy_from_slice(&params.inner_eth_proto.to_be_bytes());
    synthetic[14..].copy_from_slice(params.inner_packet);

    // #2315: RFC 6040 §4.2 decap-side ECN combine. The outer ECN arrives as
    // `params.outer_ecn` -- this body has no outer header and must NOT try to
    // derive it, which is the whole reason it is a parameter (#7167). GRE
    // reads it from its still-present outer IP header at `meta.l3_offset`
    // before calling; a protocol whose outer header is already gone by this
    // point must have captured it earlier rather than skip the combine.
    //
    // An outer CE upgrades an ECN-capable inner to CE, so a congestion mark
    // applied on the OUTER path reaches the inner endpoints; the illegal
    // outer-CE / inner-Not-ECT combination is dropped. Mutates the synthetic
    // inner in place (octet `14 + 1` for the inner TOS) and recomputes the
    // inner IPv4 header checksum when CE is set. `None` skips the combine --
    // for GRE that means a truncated outer header.
    if let Some(outer_ecn) = params.outer_ecn
        && !apply_decap_ecn_combine(
            &mut synthetic[14..],
            params.inner_family,
            outer_ecn,
            params.ecn_illegal_drops,
        )
    {
        // Illegal RFC 6040 §4.2 combination — drop (counter bumped in
        // apply_decap_ecn_combine).
        return None;
    }

    let flow = parse_session_flow_from_frame(
        &synthetic,
        UserspaceDpMeta {
            addr_family: params.inner_family,
            protocol: params.protocol,
            ..UserspaceDpMeta::default()
        },
    );
    let mut flow_src_addr = [0u8; 16];
    let mut flow_dst_addr = [0u8; 16];
    let (src_port, dst_port) = flow
        .as_ref()
        .map(|flow| (flow.forward_key.src_port, flow.forward_key.dst_port))
        .unwrap_or_default();
    if let Some(flow) = flow.as_ref() {
        match flow.src_ip {
            IpAddr::V4(ip) => flow_src_addr[..4].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => flow_src_addr.copy_from_slice(&ip.octets()),
        }
        match flow.dst_ip {
            IpAddr::V4(ip) => flow_dst_addr[..4].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => flow_dst_addr.copy_from_slice(&ip.octets()),
        }
    }

    // Derive the ingress zone from the tunnel's LOGICAL ifindex, never the
    // underlay's (#7167 invariant 2).
    //
    // #921: a direct ID lookup rather than a two-hop name round-trip, because
    // GRE's caller runs pre-flow-cache on the per-packet path for GRE-tunnel
    // workloads. Other callers may be colder, but none of them want the
    // round-trip either.
    let ingress_zone = forwarding
        .ifindex_to_zone_id
        .get(&params.logical_ifindex)
        .copied()
        .unwrap_or_default();
    let pkt_len = u16::try_from(params.inner_packet.len()).ok()?;
    let inner_meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: params.logical_ifindex as u32,
        rx_queue_index: params.rx_queue_index,
        ingress_vlan_id: 0,
        ingress_zone,
        l3_offset: 14,
        l4_offset: 14 + params.rel_l4_offset,
        payload_offset: 14 + params.payload_offset,
        pkt_len,
        addr_family: params.inner_family,
        protocol: params.protocol,
        tcp_flags: packet_tcp_flags(params.inner_packet, params.inner_family, params.protocol, params.rel_l4_offset),
        // Caller-supplied: GRE passes GRE_DECAP_INGRESS_FLAG (#2486) so the
        // forward builder selects the `tcp-mss gre-in` clamp. Every protocol
        // owes its own answer here -- see the struct docs.
        meta_flags: params.meta_flags,
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        flow_src_addr,
        flow_dst_addr,
        config_generation: params.config_generation,
        fib_generation: params.fib_generation,
        ..UserspaceDpMeta::default()
    };

    Some((synthetic, inner_meta))
}
