// #963 PR-B: unconditional byte-write kernels for L3/L4 packet
// mutation. Extracted from inline call sites in
// `apply_rewrite_descriptor` (frame/mod.rs, both v4 and v6 arms)
// and from `apply_nat_ipv4`, `apply_nat_ipv6`, `apply_nat_port_rewrite`,
// `enforce_expected_ports`, and `enforce_expected_ports_at` so a
// single source of truth defines "byte 12-15 is the IPv4 source
// address" etc.
//
// Design discipline (Codex + Gemini design review, rev 4):
//
//  - Helpers are *maximally stupid*. No `Option` matching, no
//    family branches, no fallback paths. Caller does the
//    `if let Some(IpAddr::V4(_))` match and calls the bare-bones
//    helper. This keeps the optimizer's job simple — it sees a
//    constant-offset memcpy with no phase-ordering surprise from
//    pushing conditionals into a generic body.
//
//  - All helpers are `#[inline(always)]`. The hot path in
//    `apply_rewrite_descriptor` calls each helper exactly once per
//    packet; forcing inline guarantees zero call overhead. Because
//    the helpers themselves are 1-2 instructions wide each, there
//    is no L1-i bloat concern (unlike the larger
//    `record_rx_descriptor_telemetry` from #1128 where `#[inline]`
//    was the deliberate choice).
//
//  - IP-write helpers have NO length guards. Callers MUST have
//    already validated `packet.len() >= ip + 20` (IPv4) or
//    `packet.len() >= ip + 40` (IPv6). The fast path validates this
//    near the top of the v4/v6 arms; the generic-path NAT helpers
//    are only called after their own bounds-checks fire.
//
//  - L4 port-write helpers DO have length guards. The fast path
//    today already gates port writes on `packet.len() >= l4 + 2`
//    or `+ 4`; preserving that guard keeps behavior identical to
//    pre-extraction.

use std::net::{Ipv4Addr, Ipv6Addr};

#[inline(always)]
pub(super) fn write_ipv4_src(packet: &mut [u8], ip: usize, addr: Ipv4Addr) {
    packet[ip + 12..ip + 16].copy_from_slice(&addr.octets());
}

#[inline(always)]
pub(super) fn write_ipv4_dst(packet: &mut [u8], ip: usize, addr: Ipv4Addr) {
    packet[ip + 16..ip + 20].copy_from_slice(&addr.octets());
}

#[inline(always)]
pub(super) fn write_ipv6_src(packet: &mut [u8], ip: usize, addr: Ipv6Addr) {
    packet[ip + 8..ip + 24].copy_from_slice(&addr.octets());
}

#[inline(always)]
pub(super) fn write_ipv6_dst(packet: &mut [u8], ip: usize, addr: Ipv6Addr) {
    packet[ip + 24..ip + 40].copy_from_slice(&addr.octets());
}

/// L4 source-port write at offset `l4` (TCP+UDP share this layout
/// for the source-port field at bytes 0-1). Bounds-checked: a
/// truncated frame at the L4 boundary skips the write rather than
/// panicking. Mirrors the inline pattern at the previous call sites.
#[inline(always)]
pub(super) fn write_l4_src_port(packet: &mut [u8], l4: usize, port: u16) {
    if packet.len() >= l4 + 2 {
        packet[l4..l4 + 2].copy_from_slice(&port.to_be_bytes());
    }
}

/// L4 destination-port write at offset `l4 + 2`. Same bounds-check
/// discipline as `write_l4_src_port`.
#[inline(always)]
pub(super) fn write_l4_dst_port(packet: &mut [u8], l4: usize, port: u16) {
    if packet.len() >= l4 + 4 {
        packet[l4 + 2..l4 + 4].copy_from_slice(&port.to_be_bytes());
    }
}

#[cfg(test)]
#[path = "byte_writes_tests.rs"]
mod tests;
