//! IPv4 arm of `build_forwarded_frame_into_from_frame`.
//!
//! Body is byte-identical to the AF_INET match arm at
//! `frame/mod.rs:285..341` before this split. The orchestrator at
//! `frame/build/mod.rs` computes the L2 prelude (eth header, payload
//! memcpy, ip_start, tunnel_tcp_mss, apply_nat) and dispatches here.

use super::super::tcp::clamp_tcp_mss_frame;
use super::super::{
    adjust_ipv4_header_checksum, apply_nat_ipv4, enforce_expected_ports_at,
    recompute_l4_checksum_ipv4, restore_l4_tuple_from_meta,
};
use crate::afxdp::{ForwardPacketMeta, SessionDecision};
use std::net::Ipv4Addr;

#[inline(always)]
pub(in crate::afxdp::frame) fn build_forwarded_frame_into_ipv4(
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
    if out.len() < ip_start + 20 {
        return None;
    }
    let ihl = ((out[ip_start] & 0x0f) as usize) * 4;
    if ihl < 20 || out.len() < ip_start + ihl {
        return None;
    }
    if (meta.meta_flags & 0x80) == 0 && out[ip_start + 8] <= 1 {
        return None;
    }
    let old_src = Ipv4Addr::new(
        out[ip_start + 12],
        out[ip_start + 13],
        out[ip_start + 14],
        out[ip_start + 15],
    );
    let old_dst = Ipv4Addr::new(
        out[ip_start + 16],
        out[ip_start + 17],
        out[ip_start + 18],
        out[ip_start + 19],
    );
    let old_ttl = out[ip_start + 8];
    // IHL already computed above — use directly instead of re-parsing.
    let rel_l4 = ihl;
    let repaired_ports =
        restore_l4_tuple_from_meta(&mut out[ip_start..], meta, rel_l4).unwrap_or(false);
    if apply_nat {
        apply_nat_ipv4(&mut out[ip_start..], meta.protocol, decision.nat)?;
    }
    let skip_ttl = (meta.meta_flags & 0x80) != 0;
    if !skip_ttl {
        out[ip_start + 8] -= 1;
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
    adjust_ipv4_header_checksum(
        &mut out[ip_start..ip_start + ihl],
        old_src,
        old_dst,
        old_ttl,
    )?;
    if tunnel_tcp_mss > 0 {
        let _ = clamp_tcp_mss_frame(out, ip_start, tunnel_tcp_mss);
    }
    if force_tunnel_l4_recompute || (repaired_ports && !enforced) {
        recompute_l4_checksum_ipv4(&mut out[ip_start..], ihl, meta.protocol, true)?;
    }
    Some(())
}
