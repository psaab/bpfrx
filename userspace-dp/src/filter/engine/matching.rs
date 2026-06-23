// Per-term match predicates extracted from engine.rs by #1546. The hot
// per-packet path keeps #[inline(always)] so it folds through
// `cargo build --release`.
//
// #2362 added the per-packet L4 match conditions (tcp-flags, is-fragment,
// icmp-type, icmp-code). They are carried in `TermMatchExtra`, computed once
// per packet at the evaluate call site, and applied via `per_packet_l4_matches`
// after the 5-tuple checks. They are family-agnostic, so the v4/v6 leaves share
// the same helper.

use super::super::*;
use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP};

/// Apply the #2362 per-packet L4 match conditions. Returns `false` (no match)
/// if any configured condition fails. A condition that constrains a protocol
/// the packet is not (e.g. a tcp-flags term against a UDP packet, or an
/// icmp-type term against a TCP packet) fails closed — the term must NOT match,
/// matching Junos semantics where `from tcp-flags ...` implies the TCP
/// protocol family. Empty (`None` / false) conditions are no-ops.
///
/// #2362 fold A (Copilot): every L4-header-derived constraint (tcp-flags,
/// icmp-type, icmp-code) additionally requires `extra.l4_present`. A NON-FIRST
/// fragment carries no L4 header at `l4_offset` (its bytes are payload), so
/// `l4_present` is false for it and those terms MUST NOT match. Keying off the
/// byte VALUE alone is insufficient: 0 is a valid icmp-type (echo-reply) and a
/// valid icmp-code, so a zeroed byte on a non-first fragment would still
/// spuriously match `from { icmp-type 0 }` / `from { icmp-code 0 }`. The
/// `is-fragment` constraint is L3-derived (every fragment carries the IP
/// header) and is therefore NOT gated by `l4_present` — a non-first fragment
/// still matches `from { is-fragment }`.
#[inline(always)]
fn per_packet_l4_matches(term: &FilterTerm, protocol: u8, extra: TermMatchExtra) -> bool {
    if let Some(mask) = term.tcp_flags_mask {
        // A tcp-flags constraint only matches a TCP segment that actually has
        // an L4 header. A non-TCP packet, or a non-first fragment (no L4
        // header), never matches.
        if !extra.l4_present || protocol != PROTO_TCP || (extra.tcp_flags & mask) != mask {
            return false;
        }
    }
    if term.is_fragment && !extra.is_fragment {
        return false;
    }
    let is_icmp = protocol == PROTO_ICMP || protocol == PROTO_ICMPV6;
    if let Some(want_type) = term.icmp_type {
        // Gate on l4_present, NOT just the value: icmp-type 0 (echo-reply) is a
        // real term, so a non-first fragment with a forced-0 type byte must NOT
        // match it.
        if !extra.l4_present || !is_icmp || extra.icmp_type != want_type {
            return false;
        }
    }
    if let Some(want_code) = term.icmp_code {
        // icmp-code 0 is the most common code — same l4_present gate.
        if !extra.l4_present || !is_icmp || extra.icmp_code != want_code {
            return false;
        }
    }
    true
}

/// Check whether a single filter term matches the given packet fields.
/// All specified criteria must match (AND logic). Empty criteria = match any.
#[inline(always)]
pub(super) fn term_matches(
    term: &FilterTerm,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra,
) -> bool {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            term_matches_v4(term, src, dst, protocol, src_port, dst_port, dscp, extra)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            term_matches_v6(term, src, dst, protocol, src_port, dst_port, dscp, extra)
        }
        _ => false,
    }
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(super) fn term_matches_v4(
    term: &FilterTerm,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra,
) -> bool {
    if term.protocol_match_enabled
        && (term.protocol_bitmap[(protocol / 64) as usize] & (1u64 << (protocol % 64))) == 0
    {
        return false;
    }
    if !term.source_v4.is_empty() && !term.source_v4.iter().any(|net| net.contains(src_ip)) {
        return false;
    }
    if !term.dest_v4.is_empty() && !term.dest_v4.iter().any(|net| net.contains(dst_ip)) {
        return false;
    }
    if !term.source_ports.matches(src_port) {
        return false;
    }
    if !term.dest_ports.matches(dst_port) {
        return false;
    }
    if term.dscp_match_enabled && (term.dscp_bitmap & (1u64 << dscp)) == 0 {
        return false;
    }
    if !per_packet_l4_matches(term, protocol, extra) {
        return false;
    }
    true
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(super) fn term_matches_v6(
    term: &FilterTerm,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    extra: TermMatchExtra,
) -> bool {
    if term.protocol_match_enabled
        && (term.protocol_bitmap[(protocol / 64) as usize] & (1u64 << (protocol % 64))) == 0
    {
        return false;
    }
    if !term.source_v6.is_empty() && !term.source_v6.iter().any(|net| net.contains(src_ip)) {
        return false;
    }
    if !term.dest_v6.is_empty() && !term.dest_v6.iter().any(|net| net.contains(dst_ip)) {
        return false;
    }
    if !term.source_ports.matches(src_port) {
        return false;
    }
    if !term.dest_ports.matches(dst_port) {
        return false;
    }
    if term.dscp_match_enabled && (term.dscp_bitmap & (1u64 << dscp)) == 0 {
        return false;
    }
    if !per_packet_l4_matches(term, protocol, extra) {
        return false;
    }
    true
}
