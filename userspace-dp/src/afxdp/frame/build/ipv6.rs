//! IPv6 arm of `build_forwarded_frame_into_from_frame`.
//!
//! Body is byte-identical to the AF_INET6 match arm at
//! `frame/mod.rs:342..380` before this split. The orchestrator at
//! `frame/build/mod.rs` computes the L2 prelude (eth header, payload
//! memcpy, ip_start, tunnel_tcp_mss, apply_nat) and dispatches here.

use super::super::tcp::clamp_tcp_mss_frame;
use super::super::{
    apply_nat_ipv6, enforce_expected_ports_at, packet_rel_l4_offset,
    recompute_l4_checksum_ipv6, restore_l4_tuple_from_meta,
};
use crate::afxdp::{ForwardPacketMeta, SessionDecision};

#[inline(always)]
pub(in crate::afxdp::frame) fn build_forwarded_frame_into_ipv6(
    out: &mut [u8],
    ip_start: usize,
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    apply_nat: bool,
    expected_ports: Option<(u16, u16)>,
    tunnel_tcp_mss: u16,
    force_tunnel_l4_recompute: bool,
) -> Option<()> {
    let enforced_ports = expected_ports;
    if out.len() < ip_start + 40 {
        return None;
    }
    if (meta.meta_flags & 0x80) == 0 && out[ip_start + 7] <= 1 {
        return None;
    }
    // Use meta-derived L4 offset when valid (>= 40 for IPv6 base header,
    // avoids walking extension headers). Fall back to parsing otherwise.
    let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
    let rel_l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
        meta_rel
    } else {
        packet_rel_l4_offset(&out[ip_start..], meta.addr_family)?
    };
    let repaired_ports =
        restore_l4_tuple_from_meta(&mut out[ip_start..], meta, rel_l4).unwrap_or(false);
    if apply_nat {
        apply_nat_ipv6(&mut out[ip_start..], meta.protocol, decision.nat)?;
    }
    if (meta.meta_flags & 0x80) == 0 {
        out[ip_start + 7] -= 1;
    }
    let enforced = enforce_expected_ports_at(
        out,
        ip_start,
        ip_start + rel_l4,
        meta.addr_family,
        meta.protocol,
        enforced_ports,
    )
    .unwrap_or(false);
    if tunnel_tcp_mss > 0 {
        let _ = clamp_tcp_mss_frame(out, ip_start, tunnel_tcp_mss);
    }
    if force_tunnel_l4_recompute || (repaired_ports && !enforced) {
        recompute_l4_checksum_ipv6(&mut out[ip_start..], meta.protocol)?;
    }
    Some(())
}
