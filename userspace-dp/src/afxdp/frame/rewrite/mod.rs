//! Orchestrator for `apply_rewrite_descriptor`.
//!
//! Validates the rewrite descriptor's L2 parameters via
//! `rewrite_prepare_eth_from_parts` (NAT64/NPTv6 early-return; eth
//! header write + apply_nat / skip_ttl / ip_start computation), then
//! dispatches to the address-family helper.
//!
//! Codegen contract (see docs/pr/1352-frame-build-rewrite-split/plan.md):
//!   - This orchestrator is `#[inline]` (standard hint). It has
//!     exactly ONE caller (`poll_descriptor.rs:746` inside the
//!     per-packet SIMD descriptor loop). Transitive duplication is
//!     impossible with one caller; LLVM may inline fully or keep
//!     ONE standalone definition. Both are acceptable.
//!   - Per-family helpers (`rewrite/ipv4.rs`, `rewrite/ipv6.rs`) are
//!     `#[inline(always)]` to fold into this orchestrator's body.

mod ipv4;
mod ipv6;

use ipv4::apply_rewrite_descriptor_ipv4;
use ipv6::apply_rewrite_descriptor_ipv6;

use super::{
    rewrite_prepare_eth_from_parts, verify_built_frame_checksums, InPlaceRewriteResult,
    RewriteEthParams,
};
use crate::afxdp::{MmapArea, RewriteDescriptor, UserspaceDpMeta, XdpDesc};

/// Apply a precomputed `RewriteDescriptor` to a frame in-place inside
/// a UMEM-resident packet. Mirrors the byte-level rewrite semantics of
/// the generic in-place rewrite (`rewrite_forwarded_frame_in_place`)
/// but uses the descriptor's precomputed checksum deltas instead of
/// recomputing the L4 checksum from scratch.
///
/// **Returns** `Some(InPlaceRewriteResult)` on success, `None` when the
/// frame fails any validation (TTL expired, header too short, port
/// mismatch — caller falls back to generic rewrite).
///
/// **Scope**: IPv4/IPv6 TCP and UDP only (flow cache gates on
/// ACK-only TCP + UDP). Does NOT handle: ICMP identifier repair,
/// NAT64 (header-size change), NPTv6 (checksum-neutral — address
/// rewrite differs).
#[inline]
pub(in crate::afxdp) fn apply_rewrite_descriptor(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    rd: &RewriteDescriptor,
    expected_ports: Option<(u16, u16)>,
) -> Option<InPlaceRewriteResult> {
    // NAT64 and NPTv6 use the generic path — they need special handling.
    if rd.nat64 || rd.nptv6 {
        return None;
    }

    let prep = rewrite_prepare_eth_from_parts(
        area,
        desc,
        meta.into(),
        RewriteEthParams {
            dst_mac: rd.dst_mac,
            src_mac: rd.src_mac,
            vlan_id: rd.tx_vlan_id,
            ether_type: rd.ether_type,
            apply_nat: !rd.fabric_redirect || rd.apply_nat_on_fabric,
        },
    )?;
    let packet = unsafe { area.slice_mut_unchecked(prep.tx_offset as usize, prep.frame_len)? };
    let frame_len = prep.frame_len;
    let ip = prep.ip_start;
    let skip_ttl = prep.skip_ttl;
    let apply_nat = prep.apply_nat;

    match rd.ether_type {
        0x0800 => apply_rewrite_descriptor_ipv4(
            packet,
            ip,
            skip_ttl,
            apply_nat,
            meta,
            rd,
            expected_ports,
        )?,
        0x86dd => apply_rewrite_descriptor_ipv6(
            packet,
            ip,
            skip_ttl,
            apply_nat,
            meta,
            rd,
            expected_ports,
        )?,
        _ => return None,
    }

    // Checksum verification for descriptor path (debug only).
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&packet[..frame_len]);
    }
    Some(InPlaceRewriteResult {
        offset: prep.tx_offset,
        len: frame_len as u32,
        l2_rewrite: prep.l2_rewrite,
    })
}
