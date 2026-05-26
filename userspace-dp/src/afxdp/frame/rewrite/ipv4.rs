//! IPv4 arm of `apply_rewrite_descriptor`.
//!
//! Body is byte-identical to the `0x0800` match arm at
//! `frame/mod.rs:937..1037` before this split. The orchestrator at
//! `frame/rewrite/mod.rs` validates `RewriteEthParams` via
//! `rewrite_prepare_eth_from_parts`, then dispatches here.

use super::super::byte_writes::{
    write_ipv4_dst, write_ipv4_src, write_l4_dst_port, write_l4_src_port,
};
use crate::afxdp::{RewriteDescriptor, UserspaceDpMeta, PROTO_TCP, PROTO_UDP};
use std::net::IpAddr;

#[inline(always)]
pub(in crate::afxdp::frame) fn apply_rewrite_descriptor_ipv4(
    packet: &mut [u8],
    ip: usize,
    skip_ttl: bool,
    apply_nat: bool,
    meta: UserspaceDpMeta,
    rd: &RewriteDescriptor,
    expected_ports: Option<(u16, u16)>,
) -> Option<()> {
    if packet.len() < ip + 20 {
        return None;
    }
    let ihl = ((packet[ip] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ip + ihl {
        return None;
    }
    if !skip_ttl && packet[ip + 8] <= 1 {
        return None; // TTL expired
    }
    let l4 = ip + ihl;

    // Port validation (DMA race guard).
    // If ports don't match, fall back to generic path for repair.
    if let Some((exp_src, exp_dst)) = expected_ports {
        if matches!(meta.protocol, PROTO_TCP | PROTO_UDP) && packet.len() >= l4 + 4 {
            let cur_src = u16::from_be_bytes([packet[l4], packet[l4 + 1]]);
            let cur_dst = u16::from_be_bytes([packet[l4 + 2], packet[l4 + 3]]);
            if cur_src != exp_src || cur_dst != exp_dst {
                return None;
            }
        }
    }

    // NAT: direct byte writes for IP addresses (#963 PR-B
    // helpers). Caller-side `if let Some(IpAddr::V4(_))`
    // matching keeps conditional logic visible at the call
    // site and lets the `#[inline(always)]` helpers fold
    // into a single MOV/MOVB instruction.
    if apply_nat {
        if let Some(IpAddr::V4(new_src)) = rd.rewrite_src_ip {
            write_ipv4_src(packet, ip, new_src);
        }
        if let Some(IpAddr::V4(new_dst)) = rd.rewrite_dst_ip {
            write_ipv4_dst(packet, ip, new_dst);
        }
    }

    // NAT: direct byte writes for L4 ports.
    if apply_nat {
        if let Some(new_sport) = rd.rewrite_src_port {
            write_l4_src_port(packet, l4, new_sport);
        }
        if let Some(new_dport) = rd.rewrite_dst_port {
            write_l4_dst_port(packet, l4, new_dport);
        }
    }

    // TTL decrement (skip for fabric-ingress — peer already decremented).
    if !skip_ttl {
        packet[ip + 8] -= 1;
    }

    // IP header checksum: precomputed NAT delta + TTL-1 delta.
    let old_csum = u16::from_be_bytes([packet[ip + 10], packet[ip + 11]]);
    let mut sum = (!old_csum as u32) & 0xffff;
    if apply_nat {
        sum += rd.ip_csum_delta as u32;
    }
    if !skip_ttl {
        // TTL-1 delta is always 0xFEFF in one's complement arithmetic
        sum += 0xFEFF;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let new_csum = !(sum as u16);
    packet[ip + 10..ip + 12].copy_from_slice(&new_csum.to_be_bytes());

    // L4 checksum: precomputed delta covers IP + port changes.
    if apply_nat && rd.l4_csum_delta != 0 {
        let l4_csum_off = match meta.protocol {
            PROTO_TCP => l4 + 16,
            PROTO_UDP => l4 + 6,
            _ => 0,
        };
        if l4_csum_off > 0 && packet.len() >= l4_csum_off + 2 {
            let old_l4_csum =
                u16::from_be_bytes([packet[l4_csum_off], packet[l4_csum_off + 1]]);
            // Skip UDP checksum update if zero (no checksum, RFC 768).
            if meta.protocol != PROTO_UDP || old_l4_csum != 0 {
                let mut l4sum = (!old_l4_csum as u32) & 0xffff;
                l4sum += rd.l4_csum_delta as u32;
                while (l4sum >> 16) != 0 {
                    l4sum = (l4sum & 0xffff) + (l4sum >> 16);
                }
                let new_l4 = !(l4sum as u16);
                // UDP: 0x0000 means "no checksum" — use 0xFFFF (RFC 768).
                let final_csum = if meta.protocol == PROTO_UDP && new_l4 == 0 {
                    0xFFFFu16
                } else {
                    new_l4
                };
                packet[l4_csum_off..l4_csum_off + 2]
                    .copy_from_slice(&final_csum.to_be_bytes());
            }
        }
    }
    Some(())
}
