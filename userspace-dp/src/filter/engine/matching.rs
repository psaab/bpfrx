// Per-term match predicates extracted from engine.rs by #1546. Bodies
// byte-identical with the pre-split versions; #[inline(always)] preserved
// so the hot per-packet path keeps folding through `cargo build --release`.

use super::super::*;

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
) -> bool {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            term_matches_v4(term, src, dst, protocol, src_port, dst_port, dscp)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            term_matches_v6(term, src, dst, protocol, src_port, dst_port, dscp)
        }
        _ => false,
    }
}

#[inline(always)]
pub(super) fn term_matches_v4(
    term: &FilterTerm,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
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
    true
}

#[inline(always)]
pub(super) fn term_matches_v6(
    term: &FilterTerm,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
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
    true
}
