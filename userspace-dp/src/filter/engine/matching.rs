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
    if term.icmp_type_match_enabled {
        // #2545: SET membership (match-ANY). Gate on l4_present, NOT just the
        // value: icmp-type 0 (echo-reply) is a real term, so a non-first
        // fragment with a forced-0 type byte must NOT match it. A non-ICMP
        // packet never matches a term constraining icmp-type.
        let t = extra.icmp_type;
        let in_set = (term.icmp_type_bitmap[(t / 64) as usize] & (1u64 << (t % 64))) != 0;
        if !extra.l4_present || !is_icmp || !in_set {
            return false;
        }
    }
    if term.icmp_code_match_enabled {
        // icmp-code 0 is the most common code — same l4_present gate.
        let c = extra.icmp_code;
        let in_set = (term.icmp_code_bitmap[(c / 64) as usize] & (1u64 << (c % 64))) != 0;
        if !extra.l4_present || !is_icmp || !in_set {
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
    if !nets_match_v4(
        term.source_addr_constrained,
        term.source_except,
        &term.source_v4,
        src_ip,
    ) {
        return false;
    }
    if !nets_match_v4(
        term.dest_addr_constrained,
        term.dest_except,
        &term.dest_v4,
        dst_ip,
    ) {
        return false;
    }
    if !port_match(
        term.source_port_constrained,
        term.source_port_except,
        &term.source_ports,
        src_port,
    ) {
        return false;
    }
    if !port_match(
        term.dest_port_constrained,
        term.dest_port_except,
        &term.dest_ports,
        dst_port,
    ) {
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

/// #2400 (032-18) + #2506: match a v4 IP against a filter term's address set.
///
/// - `constrained == false` (the term wrote no source/dest scope — no literal
///   address and no prefix-list ref): match any IP — unchanged unscoped
///   behavior. `except` is irrelevant: there is no scope to invert.
/// - `constrained == true` but `nets` empty for THIS family: the operator wrote
///   a scope that yielded no prefixes for this family. Return `except` — the
///   Junos empty-set semantic:
///     * positive (`except == false`): "match addresses in {}" = match NOTHING
///       (fail closed). This is the #2400 all-malformed / #2506 empty-positive
///       (defined-empty or lenient-unresolved prefix-list) case — never the
///       pre-#2400 collapse to match-any.
///     * `except == true`: "match addresses NOT in {}" = match ALL. This also
///       gives the correct CROSS-FAMILY answer: a v4-only `... except` list has
///       an empty v6 vec, and a v6 source is trivially "not in" a v4 list, so a
///       v6 packet matches the except term (the v4 list does not constrain v6).
///   The `constrained` input is derived in the compiler from the EXPLICIT
///   `source_constrained` / `destination_constrained` snapshot flag (OR'd with
///   the address-length test), so an empty-resolving prefix-list still counts as
///   constrained and does not fall through to the `!constrained` match-any arm.
/// - otherwise: membership XOR `except`. `except == false` is the plain
///   `addr ∈ prefixes`; `except == true` is "match every address NOT in the
///   set".
///
/// Mirrors `nat::source::nets_match_v4` (#2398).
#[inline(always)]
fn nets_match_v4(constrained: bool, except: bool, nets: &[PrefixV4], ip: Ipv4Addr) -> bool {
    if !constrained {
        return true;
    }
    if nets.is_empty() {
        return except;
    }
    nets.iter().any(|net| net.contains(ip)) ^ except
}

/// #2400 (032-18) + #2506: v6 sibling of `nets_match_v4` (same empty-set and
/// `except` inversion semantics).
#[inline(always)]
fn nets_match_v6(constrained: bool, except: bool, nets: &[PrefixV6], ip: Ipv6Addr) -> bool {
    if !constrained {
        return true;
    }
    if nets.is_empty() {
        return except;
    }
    nets.iter().any(|net| net.contains(ip)) ^ except
}

/// #2400 (032-19) + #2622: match a port against a filter term's port matcher
/// with fail-closed semantics for an all-malformed list, and optional `except`
/// inversion for the negated `source-port-except` / `destination-port-except`
/// match.
///
/// - `constrained == false` (the term carried no real port spec): the matcher
///   is `PortMatcher::Any` and matches any port — unchanged unscoped behavior.
///   `except` is irrelevant: there is no port scope to invert.
/// - `constrained == true` but the matcher is `PortMatcher::Any` (every
///   configured port spec failed to parse, leaving zero ranges):
///     * positive (`except == false`): match NOTHING — fail closed (#2400).
///     * `except == true`: "match all ports EXCEPT {}" = match ALL — the Junos
///       empty-except-set semantic (mirrors `nets_match_v4`).
/// - otherwise: `matcher.matches(port) XOR except`. `except == false` is the
///   plain positive membership; `except == true` matches every port NOT in the
///   set.
#[inline(always)]
fn port_match(constrained: bool, except: bool, matcher: &PortMatcher, port: u16) -> bool {
    if constrained && matches!(matcher, PortMatcher::Any) {
        // Constrained but no range survived parsing. Positive -> match nothing
        // (fail closed). Except -> "all ports but none" = match all.
        return except;
    }
    matcher.matches(port) ^ except
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
    if !nets_match_v6(
        term.source_addr_constrained,
        term.source_except,
        &term.source_v6,
        src_ip,
    ) {
        return false;
    }
    if !nets_match_v6(
        term.dest_addr_constrained,
        term.dest_except,
        &term.dest_v6,
        dst_ip,
    ) {
        return false;
    }
    if !port_match(
        term.source_port_constrained,
        term.source_port_except,
        &term.source_ports,
        src_port,
    ) {
        return false;
    }
    if !port_match(
        term.dest_port_constrained,
        term.dest_port_except,
        &term.dest_ports,
        dst_port,
    ) {
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
