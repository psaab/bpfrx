//! IPv6 arm of `apply_rewrite_descriptor`.
//!
//! Body is byte-identical to the `0x86dd` match arm at
//! `frame/mod.rs:1038..1115` before this split. The orchestrator at
//! `frame/rewrite/mod.rs` validates `RewriteEthParams` via
//! `rewrite_prepare_eth_from_parts`, then dispatches here.

use super::super::byte_writes::{
    write_ipv6_dst, write_ipv6_src, write_l4_dst_port, write_l4_src_port,
};
use super::super::packet_rel_l4_offset;
use crate::afxdp::{
    RewriteDescriptor, UserspaceDpMeta, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP,
};
use std::net::IpAddr;

#[inline(always)]
pub(in crate::afxdp::frame) fn apply_rewrite_descriptor_ipv6(
    packet: &mut [u8],
    ip: usize,
    skip_ttl: bool,
    apply_nat: bool,
    meta: UserspaceDpMeta,
    rd: &RewriteDescriptor,
    expected_ports: Option<(u16, u16)>,
) -> Option<()> {
    // No IP header checksum; only L4 pseudo-header changes matter.
    if packet.len() < ip + 40 {
        return None;
    }
    if !skip_ttl && packet[ip + 7] <= 1 {
        return None; // Hop limit expired
    }

    // L4 offset from metadata or by parsing extension headers.
    let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
    let rel_l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
        meta_rel
    } else {
        packet_rel_l4_offset(&packet[ip..], meta.addr_family)?
    };
    let l4 = ip + rel_l4;

    // Port validation (DMA race guard).
    if let Some((exp_src, exp_dst)) = expected_ports {
        if matches!(meta.protocol, PROTO_TCP | PROTO_UDP) && packet.len() >= l4 + 4 {
            let cur_src = u16::from_be_bytes([packet[l4], packet[l4 + 1]]);
            let cur_dst = u16::from_be_bytes([packet[l4 + 2], packet[l4 + 3]]);
            if cur_src != exp_src || cur_dst != exp_dst {
                return None;
            }
        }
    }

    // NAT: direct byte writes for IPv6 addresses (#963 PR-B).
    if apply_nat {
        if let Some(IpAddr::V6(new_src)) = rd.rewrite_src_ip {
            write_ipv6_src(packet, ip, new_src);
        }
        if let Some(IpAddr::V6(new_dst)) = rd.rewrite_dst_ip {
            write_ipv6_dst(packet, ip, new_dst);
        }
    }

    // NAT: direct byte writes for L4 ports (#963 PR-B).
    if apply_nat {
        if let Some(new_sport) = rd.rewrite_src_port {
            write_l4_src_port(packet, l4, new_sport);
        }
        if let Some(new_dport) = rd.rewrite_dst_port {
            write_l4_dst_port(packet, l4, new_dport);
        }
    }

    // Hop limit decrement (skip for fabric-ingress).
    if !skip_ttl {
        packet[ip + 7] -= 1;
    }

    // L4 checksum: precomputed delta covers IPv6 address + port changes.
    if apply_nat && rd.l4_csum_delta != 0 {
        let l4_csum_off = match meta.protocol {
            PROTO_TCP => l4 + 16,
            PROTO_UDP => l4 + 6,
            PROTO_ICMPV6 => l4 + 2,
            _ => 0,
        };
        if l4_csum_off > 0 && packet.len() >= l4_csum_off + 2 {
            let old_l4_csum =
                u16::from_be_bytes([packet[l4_csum_off], packet[l4_csum_off + 1]]);
            let mut l4sum = (!old_l4_csum as u32) & 0xffff;
            l4sum += rd.l4_csum_delta as u32;
            while (l4sum >> 16) != 0 {
                l4sum = (l4sum & 0xffff) + (l4sum >> 16);
            }
            let new_l4 = !(l4sum as u16);
            // IPv6 UDP must have non-zero checksum; use 0xFFFF for all.
            let final_csum = if new_l4 == 0 { 0xFFFFu16 } else { new_l4 };
            packet[l4_csum_off..l4_csum_off + 2].copy_from_slice(&final_csum.to_be_bytes());
        }
    }
    Some(())
}
