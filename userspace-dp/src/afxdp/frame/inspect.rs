//! Header inspection / parsing helpers — read-only fns over
//! Ethernet/IPv4/IPv6/TCP/UDP/ICMP byte buffers. No mutation.
//!
//! Phase 2 split out of `frame.rs` per #988. The inspect cluster
//! covers raw header parsing (frame_l3_offset, parse_session_flow_*,
//! decode_frame_summary, etc.) plus session-key / fabric-tag readers
//! that operate on a frame slice without mutating it.

use super::*;

// #989: TCP-specific inspection helpers (frame_has_tcp_rst,
// extract_tcp_flags_and_window, extract_tcp_window) and tcp_flags_str
// were relocated to `frame/tcp.rs`.

/// #2292: maximum IPv6 extension headers the forwarding walkers will
/// chase before giving up. Kept equal to the screen path's bound in
/// `screen/extract.rs` (`for _ in 0..8`) so screen and forwarding agree
/// on what "valid enough IPv6" means — a chain that is still on an
/// extension header at the bound is treated identically (fail-closed)
/// by both paths. Before #2292 the forwarding walkers used 6 and
/// surrendered open at the bound (returned `Some(offset)` with the
/// unconsumed ext-header type as a bogus "L4 protocol"), so a 7th ext
/// header was classified one way by screen and another by forwarding.
pub(in crate::afxdp) const MAX_IPV6_EXT_HEADERS: usize = 8;

pub(in crate::afxdp) fn frame_l3_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < 14 {
        return None;
    }
    let eth_proto = u16::from_be_bytes([frame[12], frame[13]]);
    if matches!(eth_proto, 0x8100 | 0x88a8) {
        if frame.len() < 18 {
            return None;
        }
        return Some(18);
    }
    Some(14)
}

// #989: tcp_flags_str moved to `frame/tcp.rs`.

pub(in crate::afxdp) fn frame_l4_offset(frame: &[u8], addr_family: u8) -> Option<usize> {
    let l3 = frame_l3_offset(frame)?;
    match addr_family as i32 {
        libc::AF_INET => {
            if frame.len() < l3 + 20 {
                return None;
            }
            let ihl = usize::from(frame[l3] & 0x0f) * 4;
            if ihl < 20 || frame.len() < l3 + ihl {
                return None;
            }
            Some(l3 + ihl)
        }
        libc::AF_INET6 => {
            if frame.len() < l3 + 40 {
                return None;
            }
            let mut protocol = *frame.get(l3 + 6)?;
            let mut offset = l3 + 40;
            for _ in 0..MAX_IPV6_EXT_HEADERS {
                match protocol {
                    0 | 43 | 60 => {
                        let opt = frame.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
                        if frame.len() < offset {
                            return None;
                        }
                    }
                    51 => {
                        let opt = frame.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 2) * 4)?;
                        if frame.len() < offset {
                            return None;
                        }
                    }
                    44 => {
                        let frag = frame.get(offset..offset + 8)?;
                        protocol = frag[0];
                        offset = offset.checked_add(8)?;
                        if frame.len() < offset {
                            return None;
                        }
                    }
                    59 => return None,
                    _ => return Some(offset),
                }
            }
            // #2292: still on an extension header at the bound — fail
            // CLOSED (None → caller drops) instead of surrendering the
            // ext-header offset as a fake L4 offset. Matches the screen
            // path (`screen/extract.rs`), which returns
            // `Err(TruncatedIpv6ExtChain)` on the same over-bound chain.
            None
        }
        _ => None,
    }
}

pub(in crate::afxdp) fn packet_rel_l4_offset(packet: &[u8], addr_family: u8) -> Option<usize> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            Some(ihl)
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut protocol = *packet.get(6)?;
            let mut offset = 40usize;
            for _ in 0..MAX_IPV6_EXT_HEADERS {
                match protocol {
                    0 | 43 | 60 => {
                        let opt = packet.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    51 => {
                        let opt = packet.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 2) * 4)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    44 => {
                        let frag = packet.get(offset..offset + 8)?;
                        protocol = frag[0];
                        offset = offset.checked_add(8)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    59 => return None,
                    _ => return Some(offset),
                }
            }
            // #2292: fail-CLOSED at the bound (see frame_l4_offset).
            None
        }
        _ => None,
    }
}

/// Like `packet_rel_l4_offset` but also returns the final L4 protocol
/// after walking IPv6 extension headers. For IPv4, returns the protocol
/// byte from the IP header. Needed for GRE inner packet parsing where
/// the initial next-header (packet[6]) may be an extension header, not
/// the actual L4 protocol.
pub(in crate::afxdp) fn packet_rel_l4_offset_and_protocol(
    packet: &[u8],
    addr_family: u8,
) -> Option<(usize, u8)> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            Some((ihl, packet[9]))
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut protocol = *packet.get(6)?;
            let mut offset = 40usize;
            for _ in 0..MAX_IPV6_EXT_HEADERS {
                match protocol {
                    0 | 43 | 60 => {
                        let opt = packet.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    51 => {
                        let opt = packet.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 2) * 4)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    44 => {
                        let frag = packet.get(offset..offset + 8)?;
                        protocol = frag[0];
                        offset = offset.checked_add(8)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    59 => return None,
                    _ => return Some((offset, protocol)),
                }
            }
            // #2292: fail-CLOSED at the bound. Previously this returned
            // `Some((offset, protocol))` where `protocol` was the
            // unconsumed extension-header type (0/43/51/60), which
            // callers (GRE inner-parse, tunnel local-origin metadata,
            // NDP/TCP-flag helpers) then trusted as a real L4 protocol.
            None
        }
        _ => None,
    }
}

/// #1852: is this L3-relative IPv4 packet a NON-first fragment?
///
/// A non-first fragment has a non-zero fragment offset (the low 13 bits
/// of the `frag_off` field at IPv4 header bytes 6-7) and therefore has NO
/// L4 header at the post-IP-header offset — its "L4" bytes are payload.
/// First and atomic fragments (offset 0, MF=0 or 1) carry the real L4
/// header and return `false`. A too-short slice returns `false` (the
/// length guards in the rewrite leaves reject it separately).
#[inline]
pub(in crate::afxdp) fn ipv4_is_non_first_fragment(packet: &[u8]) -> bool {
    packet.len() >= 8 && (u16::from_be_bytes([packet[6], packet[7]]) & 0x1FFF) != 0
}

/// #1852: is this L3-relative IPv6 packet a NON-first fragment?
///
/// Walks the extension-header chain (bounded, same iteration limit as
/// `packet_rel_l4_offset` — `MAX_IPV6_EXT_HEADERS`) looking for a
/// fragment header (44). Returns
/// `true` iff a fragment header is present AND its fragment-offset bits
/// (upper 13 bits of bytes 2-3, mask `0xFFF8`, RFC 8200 §4.5) are
/// non-zero. First/atomic fragments (offset 0) and packets without a
/// fragment header return `false`. Mirrors `screen/extract.rs` /
/// `parse_embedded_v6_l4` fragment semantics. Read-only, no mutation;
/// unlike the defect-2 fix this is a separate predicate so the shared
/// `packet_rel_l4_offset_and_protocol` (read by GRE decap / tunnel
/// local-origin to FORWARD fragments) stays unchanged.
#[inline]
pub(in crate::afxdp) fn ipv6_is_non_first_fragment(packet: &[u8]) -> bool {
    if packet.len() < 40 {
        return false;
    }
    let mut protocol = packet[6];
    let mut offset = 40usize;
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        match protocol {
            0 | 43 | 60 => {
                let Some(opt) = packet.get(offset..offset + 2) else {
                    return false;
                };
                protocol = opt[0];
                let Some(next) = offset.checked_add((usize::from(opt[1]) + 1) * 8) else {
                    return false;
                };
                offset = next;
                if packet.len() < offset {
                    return false;
                }
            }
            51 => {
                let Some(opt) = packet.get(offset..offset + 2) else {
                    return false;
                };
                protocol = opt[0];
                let Some(next) = offset.checked_add((usize::from(opt[1]) + 2) * 4) else {
                    return false;
                };
                offset = next;
                if packet.len() < offset {
                    return false;
                }
            }
            44 => {
                let Some(frag) = packet.get(offset..offset + 8) else {
                    return false;
                };
                return (u16::from_be_bytes([frag[2], frag[3]]) & 0xFFF8) != 0;
            }
            _ => return false,
        }
    }
    false
}

/// #1852: family-dispatched non-first-fragment predicate over the
/// L3-relative packet slice. Computed ONCE per packet by the rewrite
/// orchestrators and threaded into the NAT leaves so the L4 byte
/// operations (port rewrite, L4-checksum adjust, port enforcement, ICMP
/// ident restore) are skipped on non-first fragments while the IP
/// address rewrite still runs (the IP header is present on every
/// fragment; the L4 checksum lives only in the first fragment).
#[inline]
pub(in crate::afxdp) fn is_non_first_fragment(packet: &[u8], addr_family: u8) -> bool {
    match addr_family as i32 {
        libc::AF_INET => ipv4_is_non_first_fragment(packet),
        libc::AF_INET6 => ipv6_is_non_first_fragment(packet),
        _ => false,
    }
}

/// #2362: is this L3-relative IPv4 packet ANY fragment? Junos `is-fragment`
/// matches a datagram that is part of a fragmented packet — the FIRST fragment
/// (MF=1, offset=0), a MIDDLE/LAST fragment (offset != 0), but NOT an
/// unfragmented datagram (MF=0, offset=0). The MF bit is 0x2000 and the
/// fragment-offset field is the low 13 bits, so the combined test on the
/// `frag_off` field (IPv4 header bytes 6-7) is `(value & 0x3FFF) != 0`. The DF
/// bit (0x4000) and the reserved bit (0x8000) are intentionally excluded. A
/// too-short slice returns `false`.
#[inline]
pub(in crate::afxdp) fn ipv4_is_any_fragment(packet: &[u8]) -> bool {
    packet.len() >= 8 && (u16::from_be_bytes([packet[6], packet[7]]) & 0x3FFF) != 0
}

/// #2362: is this L3-relative IPv6 packet ANY fragment? IPv6 carries
/// fragmentation in a Fragment extension header (next-header 44). Junos
/// `is-fragment` matches any datagram that carries a fragment header, including
/// the first fragment (offset 0, M=1). Walks the extension-header chain
/// (bounded by `MAX_IPV6_EXT_HEADERS`) and returns `true` as soon as a fragment
/// header is found. Packets with no fragment header return `false`.
#[inline]
pub(in crate::afxdp) fn ipv6_is_any_fragment(packet: &[u8]) -> bool {
    if packet.len() < 40 {
        return false;
    }
    let mut protocol = packet[6];
    let mut offset = 40usize;
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        match protocol {
            0 | 43 | 60 => {
                let Some(opt) = packet.get(offset..offset + 2) else {
                    return false;
                };
                protocol = opt[0];
                let Some(next) = offset.checked_add((usize::from(opt[1]) + 1) * 8) else {
                    return false;
                };
                offset = next;
                if packet.len() < offset {
                    return false;
                }
            }
            51 => {
                let Some(opt) = packet.get(offset..offset + 2) else {
                    return false;
                };
                protocol = opt[0];
                let Some(next) = offset.checked_add((usize::from(opt[1]) + 2) * 4) else {
                    return false;
                };
                offset = next;
                if packet.len() < offset {
                    return false;
                }
            }
            44 => return true,
            _ => return false,
        }
    }
    false
}

/// #2362: family-dispatched ANY-fragment predicate over the L3-relative packet
/// slice. Used by the firewall-filter `is-fragment` match condition.
#[inline]
pub(in crate::afxdp) fn is_any_fragment(packet: &[u8], addr_family: u8) -> bool {
    match addr_family as i32 {
        libc::AF_INET => ipv4_is_any_fragment(packet),
        libc::AF_INET6 => ipv6_is_any_fragment(packet),
        _ => false,
    }
}

/// #2362: build the per-packet L4 match inputs (tcp-flags / is-fragment /
/// icmp-type / icmp-code) consumed by the firewall-filter term predicate, from
/// the live frame + metadata. The fragment bit is read from the L3-relative
/// packet slice (`meta.l3_offset`); `tcp_flags` comes from `meta`, and the
/// ICMP/ICMPv6 type/code bytes from `meta.l4_offset`. Only the cold
/// filter-evaluation path calls this, and only when an interface carries a
/// per-packet-L4 (or DSCP) match filter, so the parse cost stays off the hot
/// path. A non-ICMP protocol yields (0, 0) for type/code — the matcher already
/// guards those against the protocol, so the values are never consulted.
///
/// #2362 fold A (the #2344 non-first-fragment class): a NON-FIRST fragment
/// carries NO L4 header at `l4_offset` — those bytes are payload, and
/// `meta.protocol` / `meta.tcp_flags` are derived from the IP header / shim
/// stamping, not a real L4 header. Reading them would let a crafted fragment
/// whose payload byte equals a filter's `icmp-type` (or whose payload-derived
/// `tcp_flags` carries the masked bits) spuriously match. So when the packet is
/// a non-first fragment, force `tcp_flags = icmp_type = icmp_code = 0` — those
/// L4 terms must NOT match (matching the `per_packet_l4_matches` doc contract).
/// `is_fragment` is KEPT true (a non-first fragment IS a fragment; the
/// `is-fragment` term reads only the L3 header, which is present on every
/// fragment). Reuses the existing `is_non_first_fragment` predicate (#2344).
///
/// #2449 (the truncation class): a NON-FRAGMENTED ICMP/ICMPv6 frame may still
/// be shorter than `l4_offset + 2`, so the type/code bytes are absent. Reading
/// them with `unwrap_or(0)` would yield `icmp_type = icmp_code = 0` while
/// `l4_present` stayed true — a crafted short ICMP packet would spuriously
/// match `icmp-type 0 / icmp-code 0` (Echo Reply). So when the type/code bytes
/// are not present in the frame, force `(0, 0, 0)` AND drop `l4_present`, so the
/// L4 matcher fails closed (treats it as no-match). The #2344/#2362 gate only
/// covered the non-first-fragment case, not pure truncation.
#[inline]
pub(in crate::afxdp) fn term_match_extra_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> crate::filter::TermMatchExtra<'_> {
    use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6};
    let l3_packet = frame.get(meta.l3_offset as usize..);
    let is_fragment = l3_packet.is_some_and(|packet| is_any_fragment(packet, meta.addr_family));
    // A non-first fragment has no L4 header at `l4_offset` (its bytes are
    // payload) — suppress every L4-derived match input so those terms fail
    // closed. The is-fragment bit above stays as-is (L3-only).
    let non_first_fragment =
        l3_packet.is_some_and(|packet| is_non_first_fragment(packet, meta.addr_family));
    // #2449: a TRUNCATED (non-fragmented) ICMP/ICMPv6 frame may be shorter than
    // `l4_offset + 2`, so the type/code bytes are absent. Reading them with
    // `.unwrap_or(0)` would yield (0, 0) while `l4_present` stayed true — a
    // crafted short ICMP packet would then spuriously match `icmp-type 0 /
    // icmp-code 0` (Echo Reply). Detect the truncation and fail closed: force
    // (0, 0, 0) AND drop `l4_present` so the L4 matcher rejects the term.
    // `icmp_type_code_truncated` is false for non-ICMP protocols (those never
    // read the bytes) and for non-first fragments (handled above).
    let icmp_type_code_present = matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
        && !non_first_fragment
        && (frame.len() >= (meta.l4_offset as usize).saturating_add(2));
    let l4_truncated = matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
        && !non_first_fragment
        && !icmp_type_code_present;
    let (tcp_flags, icmp_type, icmp_code) = if non_first_fragment {
        (0, 0, 0)
    } else if icmp_type_code_present {
        let l4 = meta.l4_offset as usize;
        (
            meta.tcp_flags,
            frame.get(l4).copied().unwrap_or(0),
            frame.get(l4.wrapping_add(1)).copied().unwrap_or(0),
        )
    } else if l4_truncated {
        // Truncated ICMP — no real type/code bytes. Fail closed.
        (0, 0, 0)
    } else {
        (meta.tcp_flags, 0, 0)
    };
    crate::filter::TermMatchExtra {
        tcp_flags,
        is_fragment,
        icmp_type,
        icmp_code,
        // The L4 header is absent on a non-first fragment OR a truncated ICMP
        // frame (#2449). The matcher gates tcp-flags / icmp-type / icmp-code on
        // this (a zeroed icmp byte is otherwise a valid icmp-type 0 / icmp-code
        // 0 match).
        l4_present: !non_first_fragment && !l4_truncated,
        // #3077: the L3 header slice (match-start layer-3) backs the
        // flexible-match-range byte-offset match. The byte offset is relative to
        // the start of the IP header. `l3_packet` is None if the frame is
        // shorter than l3_offset, in which case the matcher's bounds check fails
        // the flex term closed.
        flex_l3: l3_packet,
        // #3232: the L4 header slice (match-start layer-4) backs a layer-4
        // flexible-match-range. The byte offset is relative to the start of the
        // transport header (`meta.l4_offset`). A NON-FIRST fragment carries no
        // L4 header there (its post-IP bytes are payload), so it gets None and a
        // layer-4 flex term fails closed. `frame.get` is None if the frame is
        // shorter than l4_offset, in which case the matcher's bounds check fails
        // closed too.
        flex_l4: if non_first_fragment {
            None
        } else {
            frame.get(meta.l4_offset as usize..)
        },
    }
}

/// #2362 fold B: the `ForwardPacketMeta` flavor of `term_match_extra_from_frame`,
/// for the TX-selection / CoS classification path (`tx/cos_classify.rs`), which
/// carries a `ForwardPacketMeta` rather than the full `UserspaceDpMeta`. Same
/// fragment-safe contract: a non-first fragment forces the L4-derived fields to
/// 0 (its bytes are payload) while keeping the L3-only `is_fragment` bit. The
/// CoS path already routes a non-first fragment to the default queue with no
/// flow_key (#2357), so in practice this builder is invoked on first/atomic
/// packets — the gate is defense-in-depth and keeps the two builders identical.
#[inline]
pub(in crate::afxdp) fn term_match_extra_from_frame_fwd(
    frame: &[u8],
    meta: ForwardPacketMeta,
) -> crate::filter::TermMatchExtra<'_> {
    use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6};
    let l3_packet = frame.get(meta.l3_offset as usize..);
    let is_fragment = l3_packet.is_some_and(|packet| is_any_fragment(packet, meta.addr_family));
    let non_first_fragment =
        l3_packet.is_some_and(|packet| is_non_first_fragment(packet, meta.addr_family));
    // #2449: see `term_match_extra_from_frame` — same truncated-ICMP fail-closed
    // guard. A frame shorter than `l4_offset + 2` has no real type/code bytes.
    let icmp_type_code_present = matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
        && !non_first_fragment
        && (frame.len() >= (meta.l4_offset as usize).saturating_add(2));
    let l4_truncated = matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
        && !non_first_fragment
        && !icmp_type_code_present;
    let (tcp_flags, icmp_type, icmp_code) = if non_first_fragment {
        (0, 0, 0)
    } else if icmp_type_code_present {
        let l4 = meta.l4_offset as usize;
        (
            meta.tcp_flags,
            frame.get(l4).copied().unwrap_or(0),
            frame.get(l4.wrapping_add(1)).copied().unwrap_or(0),
        )
    } else if l4_truncated {
        (0, 0, 0)
    } else {
        (meta.tcp_flags, 0, 0)
    };
    crate::filter::TermMatchExtra {
        tcp_flags,
        is_fragment,
        icmp_type,
        icmp_code,
        l4_present: !non_first_fragment && !l4_truncated,
        // #3077: L3 header slice for flexible-match-range (see the input-filter
        // builder above). Same fail-closed-on-too-short bounds check applies.
        flex_l3: l3_packet,
        // #3232: L4 header slice for a layer-4 flexible-match-range (see the
        // input-filter builder above). None on a non-first fragment so a
        // layer-4 flex term fails closed.
        flex_l4: if non_first_fragment {
            None
        } else {
            frame.get(meta.l4_offset as usize..)
        },
    }
}

/// #2362 fold B: build the per-packet match inputs from metadata ALONE, for the
/// rare TX-selection callers that have no contiguous ingress frame slice
/// (locally-generated replies whose tuple is re-derived, ARP/NDP-deferred
/// forwards, control-plane injects). `tcp_flags` is taken from the
/// shim-stamped `meta` (authoritative on the forwarding path); `is_fragment`
/// and `icmp_type`/`icmp_code` cannot be read without the frame, so they are
/// 0/false — a CoS-action filter term keyed on is-fragment or icmp-type on one
/// of these non-transit paths under-matches rather than mis-matches. The common
/// `tcp-flags` CoS term is fully covered.
///
/// #3008 (meta sibling of #2449): the real ICMP type/code bytes are NOT
/// available on this meta-only path — there is no frame to read them from. The
/// pre-#3008 code stamped `icmp_type = icmp_code = 0` while leaving
/// `l4_present = true`, so any term keyed on `icmp-type 0` (echo-reply) or
/// `icmp-code 0` (a *valid*, common value) FALSE-MATCHED every ICMP-family
/// packet whose type/code was never parsed. The matcher gates the
/// icmp-type / icmp-code terms on `l4_present`, so for an ICMP/ICMPv6 packet on
/// this path we MUST drop `l4_present` to make those terms fail closed — the
/// type/code is genuinely unknown, so an `icmp-type N` / `icmp-code N` term must
/// NOT match. For non-ICMP protocols `l4_present` stays true so the
/// authoritative shim-stamped `tcp_flags` keeps matching (tcp-flags terms only
/// apply to TCP anyway). `icmp_type` / `icmp_code` are left 0 but are now inert
/// on the ICMP path because the `l4_present` gate rejects the term first.
#[inline]
pub(in crate::afxdp) fn term_match_extra_from_meta(
    meta: ForwardPacketMeta,
) -> crate::filter::TermMatchExtra<'static> {
    use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6};
    // #3008: the ICMP type/code bytes are unknown on the meta-only path (no
    // frame). A 0 byte is a real `icmp-type 0` / `icmp-code 0` value, so we must
    // signal "L4 type/code not parsed" to fail those terms closed. The matcher
    // shares one `l4_present` bit across tcp-flags and icmp-type/code; for an
    // ICMP-family packet there are no tcp-flags terms to preserve, so dropping
    // `l4_present` is safe and fails the icmp-type/code terms closed. For TCP/
    // UDP it stays true so authoritative `tcp_flags` matching is preserved.
    let is_icmp = matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6);
    crate::filter::TermMatchExtra {
        tcp_flags: meta.tcp_flags,
        is_fragment: false,
        icmp_type: 0,
        icmp_code: 0,
        // FALSE for ICMP/ICMPv6 (type/code genuinely unknown — fail
        // icmp-type/code terms closed); TRUE otherwise so the shim-stamped
        // tcp_flags still drives tcp-flags matching on synthetic/local TX.
        l4_present: !is_icmp,
        // #3077: no contiguous frame on this meta-only path, so there are no L3
        // bytes to read. A flex-constrained term fails closed here (the
        // flow-cache declines for such filters, so this path never carries one).
        flex_l3: None,
        // #3232: likewise no L4 bytes on the meta-only path — a layer-4 flex
        // term fails closed.
        flex_l4: None,
    }
}

/// #2314: RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e) — a router MUST NOT
/// originate an ICMP/ICMPv6 *error* in reply to a datagram whose IP
/// destination was a broadcast or multicast address. Reading the
/// destination straight off the L3-relative packet slice keeps this
/// cheap on the (cold-ish) error-generation arms: a single octet test
/// for the common cases.
///
///   - IPv4: multicast 224.0.0.0/4 (first octet 224..=239) OR the
///     limited broadcast 255.255.255.255. Subnet/directed broadcasts
///     require per-interface mask knowledge that is not available at the
///     generation site, so they are not detectable here — the limited
///     broadcast and the multicast block are the cases this gate covers.
///   - IPv6: multicast ff00::/8 (first byte 0xff). IPv6 has no broadcast.
///
/// Returns `true` when an ICMP error MUST be suppressed for this trigger
/// destination. Fails closed (`true`) on a too-short packet slice and on
/// an unknown/unexpected `addr_family`: a destination we cannot classify
/// must suppress the error rather than risk emitting backscatter for a
/// packet whose family (and therefore whose group/broadcast bits) we did
/// not parse.
#[inline]
pub(in crate::afxdp) fn dest_is_multicast_or_broadcast(addr_family: u8, packet: &[u8]) -> bool {
    match addr_family as i32 {
        libc::AF_INET => {
            let Some(dst) = packet.get(16..20) else {
                return true;
            };
            let dst = Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3]);
            dst.is_multicast() || dst.is_broadcast()
        }
        libc::AF_INET6 => {
            let Some(dst) = packet.get(24..40) else {
                return true;
            };
            // ff00::/8 — the leading byte alone identifies all IPv6
            // multicast (link-local-all-nodes, solicited-node, etc.).
            dst[0] == 0xff
        }
        // Unknown family — fail closed (suppress). The error generators
        // never call this for a non-IP family in practice (their own
        // family dispatch rejects first), but the predicate's contract is
        // "suppress on anything we could not classify."
        _ => true,
    }
}

/// #2411: RFC 1812 §4.3.2.7 — a router MUST NOT originate an ICMP error
/// in reply to a datagram whose IP destination is a *directed* (subnet)
/// broadcast, e.g. `10.0.1.255` for a connected `10.0.1.0/24`. Unlike
/// the limited broadcast (`255.255.255.255`, caught by
/// [`dest_is_multicast_or_broadcast`]'s `is_broadcast()`), a directed
/// broadcast is a normal unicast address to the L3 destination test —
/// recognizing it requires the configured subnet MASK, which only the
/// forwarding state's connected-route table carries. This is the
/// per-interface-prefix sibling of [`dest_is_multicast_or_broadcast`]
/// (L3 group/limited-broadcast), [`l2_dst_is_group_or_broadcast`] (L2),
/// and [`source_is_invalid_for_icmp_error`] (L3 source); it is shared by
/// the reject / Time-Exceeded path (`can_generate_icmp_error_reply`) and
/// the PTB path (`ptb_reply_suppressed`) so every locally generated ICMP
/// error applies the SAME directed-broadcast gate.
///
/// IPv4-only: IPv6 has no broadcast (the v6 caller never invokes this).
/// `packet` is the L3 (IP-header-first) slice. Returns `true` when the
/// destination is the all-ones host address of a connected prefix and
/// the ICMP error MUST be suppressed. A too-short slice fails closed
/// (suppress). The connected table is reused from the forwarding path
/// (no new infrastructure); the scan is the same `connected_v4.iter()`
/// the FIB lookup already does, on a cold (error-generation) path only.
///
/// Prefixes shorter than /31 are the only ones with a meaningful
/// directed broadcast: a /31 (RFC 3021) has no broadcast and a /32's
/// host-all-ones value equals the host itself, so both are skipped to
/// avoid mis-suppressing a legitimate unicast to a /32 connected host.
#[inline]
pub(in crate::afxdp) fn dest_is_directed_broadcast(
    forwarding: &ForwardingState,
    packet: &[u8],
) -> bool {
    let Some(dst) = packet.get(16..20) else {
        // Fail closed: a destination we cannot read must suppress the
        // error rather than risk directed-broadcast backscatter.
        return true;
    };
    let dst = Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3]);
    v4_addr_is_directed_broadcast(forwarding, dst)
}

/// Shared connected-table directed-broadcast test for a single IPv4
/// address, used by both the L3-DESTINATION gate
/// ([`dest_is_directed_broadcast`]) and the L3-SOURCE gate
/// ([`src_is_directed_broadcast`]). Returns `true` when `addr` is the
/// all-ones host (subnet-directed broadcast) of any connected prefix.
///
/// `directed_broadcast() == addr` already implies the prefix contains
/// `addr`: a directed broadcast is `network | !mask`, so `addr & mask ==
/// network` (the host bits are all-ones and masked off) — i.e.
/// `contains(addr)` is necessarily true. The explicit `contains` check
/// would be redundant, so only the broadcast-equality and the
/// prefix-length guard remain.
///
/// Prefixes shorter than /31 are the only ones with a meaningful
/// directed broadcast: a /31 (RFC 3021) has no broadcast and a /32's
/// host-all-ones value equals the host itself, so both are skipped to
/// avoid mis-classifying a legitimate unicast to a /32 connected host.
#[inline]
fn v4_addr_is_directed_broadcast(forwarding: &ForwardingState, addr: Ipv4Addr) -> bool {
    forwarding
        .connected_v4
        .iter()
        .any(|entry| entry.prefix.prefix_len() < 31 && entry.prefix.directed_broadcast() == addr)
}

/// #2487: RFC 1812 §4.3.2.7 — a router MUST NOT originate an ICMP error
/// in reply to a datagram whose IP SOURCE is a *directed* (subnet)
/// broadcast, e.g. `10.0.1.255` for a connected `10.0.1.0/24`. A locally
/// generated error is addressed TO the trigger's source, so a directed-
/// broadcast source produces an error sent to that directed broadcast —
/// delivered to every host on the segment (Smurf-style amplification /
/// backscatter). This is the L3-SOURCE sibling of the merged #2411
/// [`dest_is_directed_broadcast`] (L3 destination): the
/// [`source_is_invalid_for_icmp_error`] limited-broadcast test
/// (`is_broadcast()`) only catches `255.255.255.255`; a subnet-directed
/// broadcast is a plain unicast address to that test and needs the
/// configured subnet MASK from the connected-route table to recognize.
///
/// IPv4-only: IPv6 has no broadcast (the v6 caller never invokes this).
/// `packet` is the L3 (IP-header-first) slice. Returns `true` when the
/// source is the all-ones host address of a connected prefix and the
/// ICMP error MUST be suppressed. A too-short slice fails closed
/// (suppress). The connected table is reused from the forwarding path
/// (no new infrastructure), scanned only on the cold error-generation
/// path. The /31 and /32 prefix-length guards match
/// [`dest_is_directed_broadcast`].
#[inline]
pub(in crate::afxdp) fn src_is_directed_broadcast(
    forwarding: &ForwardingState,
    packet: &[u8],
) -> bool {
    let Some(src) = packet.get(12..16) else {
        // Fail closed: a source we cannot read must suppress the error
        // rather than risk directed-broadcast backscatter.
        return true;
    };
    let src = Ipv4Addr::new(src[0], src[1], src[2], src[3]);
    v4_addr_is_directed_broadcast(forwarding, src)
}

/// #2367: RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e) — a router MUST NOT
/// originate an ICMP/ICMPv6 *error* in response to a datagram whose IP
/// SOURCE address does not uniquely identify a single host. A locally
/// generated error is addressed to the trigger packet's source, so a
/// forbidden source (unspecified, loopback, multicast, or — for IPv4 —
/// broadcast) would produce spoofable ICMP backscatter aimed at an
/// address that is not a legitimate unicast host. This is the L3-SOURCE
/// sibling of [`dest_is_multicast_or_broadcast`] (the L3-destination
/// test) and [`l2_dst_is_group_or_broadcast`] (the L2 test); it is shared
/// by the reject / Time-Exceeded path (`can_generate_icmp_error_reply`)
/// and the PTB path (`ptb_reply_suppressed`) so every locally generated
/// ICMP error applies the SAME bad-source gate.
///
/// `packet` is the L3 (IP-header-first) slice of the trigger frame.
/// Returns `true` when the source is forbidden and the ICMP error MUST be
/// suppressed. A too-short or unknown-family slice fails closed
/// (suppress).
#[inline]
pub(in crate::afxdp) fn source_is_invalid_for_icmp_error(addr_family: u8, packet: &[u8]) -> bool {
    match addr_family as i32 {
        libc::AF_INET => {
            // IPv4 source is header bytes 12..16.
            let Some(src) = packet.get(12..16) else {
                return true;
            };
            let src = Ipv4Addr::new(src[0], src[1], src[2], src[3]);
            src.is_unspecified() || src.is_loopback() || src.is_multicast() || src.is_broadcast()
        }
        libc::AF_INET6 => {
            // IPv6 source is header bytes 8..24. IPv6 has no broadcast;
            // multicast (ff00::/8) covers the group case.
            let Some(src) = packet.get(8..24) else {
                return true;
            };
            let src = Ipv6Addr::from(match <[u8; 16]>::try_from(src) {
                Ok(addr) => addr,
                Err(_) => return true,
            });
            src.is_unspecified() || src.is_loopback() || src.is_multicast()
        }
        // Unknown family — fail closed (suppress). Mirrors the
        // destination predicate's "suppress on anything we could not
        // classify" contract.
        _ => true,
    }
}

/// #2325: RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e) — a router MUST NOT
/// originate an ICMP/ICMPv6 *error* in reply to a datagram that was
/// delivered as a link-layer (L2) broadcast or multicast. The IEEE 802
/// group (I/G) bit is the low bit of the first MAC octet; the all-ones
/// MAC (broadcast) is a special case of group, so a single bit test on
/// the first destination-MAC octet covers both. This is the L2 sibling
/// of [`dest_is_multicast_or_broadcast`] (the L3 destination test) and
/// is shared by the reject / Time-Exceeded path
/// (`can_generate_icmp_error_reply`) and the PTB path
/// (`ptb_reply_suppressed`) so both apply the same L2+L3 suppression.
///
/// Takes the trigger frame's 6-byte destination MAC. Returns `true` when
/// the L2 destination is group/broadcast and the ICMP error MUST be
/// suppressed.
#[inline]
pub(in crate::afxdp) fn l2_dst_is_group_or_broadcast(eth_dst: &[u8; 6]) -> bool {
    // The low bit of the first MAC octet is the I/G (group) bit; the
    // all-ones MAC is broadcast (a group address). A single bit test
    // catches both.
    (eth_dst[0] & 0x01) != 0
}

/// #2790: RFC 826 — a learned neighbor (ARP reply sender, NDP NA target)
/// MUST uniquely identify a single host before it is cached and
/// programmed into the kernel neighbor table. An ARP/NDP reply whose
/// advertised protocol address is unspecified (`0.0.0.0` / `::`),
/// loopback (`127/8` / `::1`), multicast (`224/4` / `ff00::/8`), or — for
/// IPv4 — the limited broadcast (`255.255.255.255`) does not name a
/// legitimate unicast peer; caching it pollutes both the userspace
/// `dynamic_neighbors` map and the kernel ARP/NDP table, enabling a
/// spoofed-reply DoS (routing disruption). Fail closed: such a reply is
/// not learnable and the caller drops/recycles it without caching.
///
/// This is the neighbor-learning sibling of
/// [`source_is_invalid_for_icmp_error`] (the ICMP-error L3-SOURCE gate);
/// it applies the SAME unicast-only posture the #2367 / #2487 ICMP-source
/// checks and the cold-neighbor warmer (`coordinator::warm_neighbors`)
/// already enforce, so every neighbor write — learned or warmed — rejects
/// the same illegitimate address classes.
///
/// Returns `true` when `ip` is a legitimate unicast address that MAY be
/// learned. IPv4 broadcast is rejected; IPv6 has no broadcast (multicast
/// covers the group case). Directed (subnet) broadcasts are NOT rejected
/// here: recognizing them needs the per-interface mask, the learned key
/// is already scoped to the ingress logical ifindex, and a directed
/// broadcast is a normal unicast address to this test — matching the
/// warmer's posture, which also only tests the limited broadcast.
#[inline]
pub(in crate::afxdp) fn neighbor_ip_is_learnable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified() && !v4.is_loopback() && !v4.is_multicast() && !v4.is_broadcast()
        }
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_loopback() && !v6.is_multicast(),
    }
}

pub(in crate::afxdp) fn metadata_tuple_complete(meta: UserspaceDpMeta, flow: &SessionFlow) -> bool {
    if flow.src_ip.is_unspecified() || flow.dst_ip.is_unspecified() {
        return false;
    }
    match meta.protocol {
        PROTO_TCP | PROTO_UDP => flow.forward_key.src_port != 0 && flow.forward_key.dst_port != 0,
        _ => true,
    }
}

/// The frame-relative byte offset at which the IPv4 datagram ENDS, as
/// declared by the IP header `total_len` (bytes [l3+2..l3+4]), clamped to
/// `[l3 + ihl, frame.len()]`.
///
/// #2361 fail-CLOSED: the L4 port read MUST be bounded by the IP-DECLARED
/// packet end, not merely the backing slice. A frame whose `total_len`
/// declares a short datagram but carries trailing slack (NIC zero-pad on a
/// sub-60-byte frame, or attacker-supplied bytes) would otherwise have its
/// "ports" read from out-of-datagram bytes. We clamp to the slice so a
/// truncated capture (slice shorter than `total_len`) also fails closed
/// (the read still cannot exceed what is present). Mirrors the
/// `total_len.clamp(ihl, packet.len())` bound the sibling generated-reply
/// parser enforces (`generated.rs::parse_generated_v4`).
///
/// Returns `None` when the IPv4 header itself is truncated/malformed
/// (caller already validated `frame.len() >= l3 + 20` and `ihl >= 20`, so
/// this is belt-and-suspenders for stray callers).
pub(in crate::afxdp) fn ipv4_declared_l3_end(frame: &[u8], l3: usize) -> Option<usize> {
    if frame.len() < l3 + 20 {
        return None;
    }
    let ihl = usize::from(frame[l3] & 0x0f) * 4;
    // Fail closed when the buffer does not even hold the declared IHL
    // header (ihl can be 21..=60 with IPv4 options, but the meta-driven
    // callers do NOT validate ihl against the slice). This guard is also a
    // PANIC SAFETY invariant: the `clamp` below requires `min <= max`, i.e.
    // `l3 + ihl <= frame.len()`. Without this guard a crafted frame with
    // IHL nibble = 15 (60 bytes) in a buffer truncated to l3+20 would give
    // `clamp(min = l3+60, max = l3+20)` -> `min > max` -> panic (DoS).
    if ihl < 20 || frame.len() < l3 + ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([frame[l3 + 2], frame[l3 + 3]]) as usize;
    Some(l3.saturating_add(total_len).clamp(l3 + ihl, frame.len()))
}

/// The frame-relative byte offset at which the IPv6 datagram ENDS, as
/// declared by the fixed-header `payload_len` (bytes [l3+4..l3+6]), clamped
/// to `[l3 + 40, frame.len()]`.
///
/// #2361 fail-CLOSED counterpart of [`ipv4_declared_l3_end`]: the IPv6
/// packet end is `l3 + 40 + payload_len`. Mirrors the
/// `(40 + payload_len).clamp(40, packet.len())` bound in
/// `generated.rs::parse_generated_v6`.
pub(in crate::afxdp) fn ipv6_declared_l3_end(frame: &[u8], l3: usize) -> Option<usize> {
    if frame.len() < l3 + 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([frame[l3 + 4], frame[l3 + 5]]) as usize;
    Some(
        l3.saturating_add(40)
            .saturating_add(payload_len)
            .clamp(l3 + 40, frame.len()),
    )
}

/// IP-declared datagram end for either family, given the L3 offset and the
/// address family. `None` for an unknown family or a truncated L3 header.
pub(in crate::afxdp) fn declared_l3_end(frame: &[u8], l3: usize, addr_family: u8) -> Option<usize> {
    match addr_family as i32 {
        libc::AF_INET => ipv4_declared_l3_end(frame, l3),
        libc::AF_INET6 => ipv6_declared_l3_end(frame, l3),
        _ => None,
    }
}

/// Read the L4 ports at `l4`, bounded by BOTH the backing slice AND the
/// IP-DECLARED packet end (`declared_end`, the slice-clamped
/// `ipv4_declared_l3_end` / `ipv6_declared_l3_end`).
///
/// #2361 fail-CLOSED: TCP/UDP need 4 port bytes at `[l4, l4+4)`; ICMP/ICMPv6
/// read the 2 identifier bytes at `[l4+4, l4+6)`. The read MUST lie entirely
/// within `declared_end`. When the IP header declares a datagram that ends
/// BEFORE the L4 ports — even though the backing buffer still holds trailing
/// slack/padding bytes — this returns `None` rather than synthesizing ports
/// from out-of-datagram bytes. The caller treats `None` as flowless (the
/// packet follows the route-based, session-less forward path, consistent with
/// the #2344 non-first-fragment handling), so out-of-packet bytes never drive
/// policy / firewall-filter / CoS / session installation. This is the same
/// invariant the sibling generated-reply parser enforces via
/// `generated.rs::generated_l4_ports`.
/// #3067/#3290: the ICMP/ICMPv6 types whose 3rd/4th header bytes
/// (`[l4+4..l4+6]`) are a genuine Identifier usable as a stateful
/// pseudo source port. Echo Request/Reply carry one in both families;
/// ICMPv4 additionally has the Timestamp and Information query+reply
/// pairs (same offset per RFC 792). For every error/control type
/// (Dest-Unreachable, Packet-Too-Big, Time-Exceeded, Parameter-Problem,
/// Redirect, ND/MLD, ...) those bytes are part of a gateway address /
/// next-hop MTU / pointer / unused word — NOT a port.
///
/// This is the single predicate shared by the frame port parser
/// (`parse_flow_ports`) and the metadata-fallback gate in
/// `parse_session_flow_from_bytes` (#3290), so both arms honor the SAME
/// query-type rule and the shim's ungated pseudo-port can never install a
/// fake session for a non-query ICMP packet.
#[inline]
pub(in crate::afxdp) fn icmp_identifier_bearing(protocol: u8, icmp_type: u8) -> bool {
    match protocol {
        // Echo Reply (0) / Echo Request (8), Timestamp Request (13) /
        // Reply (14), Information Request (15) / Reply (16).
        PROTO_ICMP => matches!(icmp_type, 0 | 8 | 13 | 14 | 15 | 16),
        // Echo Request (128) / Echo Reply (129).
        PROTO_ICMPV6 => matches!(icmp_type, 128 | 129),
        _ => false,
    }
}

/// #3290: report whether the metadata-stamped ICMP/ICMPv6 pseudo-port may be
/// trusted as a stateful identifier — frame-EQUIVALENT to the
/// `parse_flow_ports` gate. Two conditions must hold, both bounded by the
/// IP-declared datagram end (the #2361 fail-closed invariant, since trailing
/// slack is not authoritative):
///
/// 1. the ICMP type byte at `l4` lies inside the declared datagram AND is an
///    identifier-bearing query type, and
/// 2. the full 2-byte Identifier at `[l4+4..l4+6)` ALSO lies inside the
///    declared datagram.
///
/// Condition 2 is what `parse_flow_ports` enforces with its `ident_end >
/// declared_end` check: a query packet truncated between the type byte and the
/// identifier yields `None` there, so the meta gate must agree or the shim's
/// pseudo-port (read from bytes outside the declared datagram) would still
/// install a metadata-keyed session. Returns `false` (fail closed -> suppress
/// the metadata pseudo-port fallback) on any malformed/truncated input. Only
/// gates the metadata fallback; the frame parsers re-derive the type
/// independently.
pub(in crate::afxdp) fn meta_icmp_identifier_bearing(frame: &[u8], meta: UserspaceDpMeta) -> bool {
    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    let declared_end = match meta.addr_family as i32 {
        libc::AF_INET => ipv4_declared_l3_end(frame, l3),
        libc::AF_INET6 => ipv6_declared_l3_end(frame, l3),
        _ => None,
    };
    let Some(declared_end) = declared_end else {
        return false;
    };
    if l4 >= declared_end {
        return false;
    }
    // Frame-equivalent to parse_flow_ports: the identifier bytes [l4+4..l4+6)
    // must lie within the IP-declared datagram, not merely the type byte.
    match l4.checked_add(6) {
        Some(ident_end) if ident_end <= declared_end => {}
        _ => return false,
    }
    match frame.get(l4) {
        Some(&icmp_type) => icmp_identifier_bearing(meta.protocol, icmp_type),
        None => false,
    }
}

pub(in crate::afxdp) fn parse_flow_ports(
    frame: &[u8],
    l4: usize,
    protocol: u8,
    declared_end: usize,
) -> Option<(u16, u16)> {
    match protocol {
        PROTO_TCP | PROTO_UDP => {
            let end = l4.checked_add(4)?;
            if end > declared_end {
                return None;
            }
            let bytes = frame.get(l4..end)?;
            Some((
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
            ))
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            // #3067: bytes [l4+4, l4+6) are the ICMP/ICMPv6 Identifier ONLY for
            // the identifier-bearing query types. For ICMPv4 those are Echo
            // Request/Reply and the Timestamp/Information query+reply pairs (the
            // Identifier sits at the same offset for all of them, per RFC 792);
            // for ICMPv6 only Echo Request/Reply (RFC 4443). For error and
            // control messages — Dest-Unreachable, Packet-Too-Big,
            // Time-Exceeded, Parameter-Problem, Redirect, and the ND/MLD types —
            // those two bytes are NOT a port: they are part of a gateway
            // address, the next-hop MTU, a pointer, or an unused/reserved field.
            // Treating them as a pseudo source port installed bogus
            // identifier-keyed stateful sessions for transit ICMP control
            // traffic, polluting the session table and risking spurious
            // collisions. Return `None` (the caller's "flowless" sentinel) for
            // every non-query type so the packet takes the session-less,
            // route-based forward path instead of installing a fake session.
            //
            // The type byte at `l4` must itself lie within the IP-declared
            // datagram (the #2361 fail-closed invariant); a type byte read from
            // trailing slack past `declared_end` is not authoritative.
            if l4 >= declared_end {
                return None;
            }
            let icmp_type = *frame.get(l4)?;
            if !icmp_identifier_bearing(protocol, icmp_type) {
                return None;
            }
            let ident_start = l4.checked_add(4)?;
            let ident_end = l4.checked_add(6)?;
            if ident_end > declared_end {
                return None;
            }
            let bytes = frame.get(ident_start..ident_end)?;
            let ident = u16::from_be_bytes([bytes[0], bytes[1]]);
            Some((ident, 0))
        }
        _ => None,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn authoritative_forward_ports(
    frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
) -> Option<(u16, u16)> {
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    if let Some(flow_ports) = flow.and_then(|flow| {
        if flow.forward_key.src_port != 0 && flow.forward_key.dst_port != 0 {
            Some((flow.forward_key.src_port, flow.forward_key.dst_port))
        } else {
            None
        }
    }) {
        return Some(flow_ports);
    }
    let meta_ports = if meta.flow_src_port != 0 && meta.flow_dst_port != 0 {
        Some((meta.flow_src_port, meta.flow_dst_port))
    } else {
        None
    };
    let frame_ports = live_frame_ports_from_meta_bytes(frame, meta);
    frame_ports.or(meta_ports)
}

#[allow(dead_code)]
pub(in crate::afxdp) fn live_frame_ports(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<(u16, u16)> {
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    live_frame_ports_from_meta_bytes(frame, meta)
}

#[inline(always)]
pub(in crate::afxdp) fn live_frame_ports_from_meta_bytes(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
) -> Option<(u16, u16)> {
    let meta = meta.into();
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let l4 = meta.l4_offset as usize;
    // #2361: bound the meta-stamped L4 read by the IP-declared packet end,
    // not just the slice. The XDP shim stamps `meta.l4_offset` but does NOT
    // enforce that the L4 header lies inside the IP-declared datagram, so a
    // frame with a short total_len/payload_len + trailing slack could have
    // its ports read past the datagram. We re-derive the declared end from
    // the L3 header in the frame (using `meta.l3_offset`). If the meta
    // offsets are unusable, fall through to the byte-led parser, which
    // re-derives both L3 and the declared end from the frame.
    if l4 != 0
        && let Some(declared_end) =
            declared_l3_end(frame, meta.l3_offset as usize, meta.addr_family)
        && let Some(ports) = parse_flow_ports(frame, l4, meta.protocol, declared_end)
    {
        return Some(ports);
    }
    live_frame_ports_bytes(frame, meta.addr_family, meta.protocol)
}

pub(in crate::afxdp) fn live_frame_ports_bytes(
    frame: &[u8],
    addr_family: u8,
    protocol: u8,
) -> Option<(u16, u16)> {
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let l3 = frame_l3_offset(frame)?;
    let l4 = frame_l4_offset(frame, addr_family)?;
    // #2361: bound by the IP-declared packet end (re-derived from the frame),
    // not just the backing slice.
    let declared_end = declared_l3_end(frame, l3, addr_family)?;
    parse_flow_ports(frame, l4, protocol, declared_end)
}

pub(in crate::afxdp) fn forward_tuple_mismatch_reason(
    source_ports: Option<(u16, u16)>,
    expected_ports: Option<(u16, u16)>,
    built_ports: Option<(u16, u16)>,
) -> Option<String> {
    let expected = expected_ports.or(source_ports)?;
    let built = built_ports?;
    if built == expected {
        return None;
    }
    let source = source_ports.unwrap_or((0, 0));
    Some(format!(
        "forward_tuple_mismatch:src={}:{} expected={}:{} built={}:{}",
        source.0, source.1, expected.0, expected.1, built.0, built.1
    ))
}

/// #2344: resolve the L3-relative slice the way the SessionFlow frame
/// parsers do (prefer `meta.l3_offset` when it points at a frame byte
/// whose IP-version nibble matches `addr_family`, else fall back to
/// `frame_l3_offset`) and run the family-aware non-first-fragment
/// predicate over it. Returns `true` only when the packet is positively
/// identified as a non-first fragment; an unresolvable/too-short frame
/// returns `false` (the downstream parser length guards reject it).
pub(in crate::afxdp) fn frame_is_non_first_fragment(frame: &[u8], meta: UserspaceDpMeta) -> bool {
    let expected_version = match meta.addr_family as i32 {
        libc::AF_INET => 4u8,
        libc::AF_INET6 => 6u8,
        _ => return false,
    };
    let l3 = match meta.l3_offset {
        14 | 18
            if frame
                .get(meta.l3_offset as usize)
                .is_some_and(|byte| (byte >> 4) == expected_version) =>
        {
            meta.l3_offset as usize
        }
        _ => match frame_l3_offset(frame) {
            Some(off) => off,
            None => return false,
        },
    };
    // Only flag a fragment when the byte at the resolved L3 offset is a
    // real IP header whose version matches the metadata family. Without
    // this the predicate would read the fragment-offset bytes out of a
    // garbage/non-IP frame whose flow tuple is carried entirely in
    // metadata (e.g. the meta-led ICMP fixtures), spuriously suppressing
    // a legitimate flow. The downstream parsers already re-derive L3,
    // so this only guards the early-exit decision.
    if frame
        .get(l3)
        .is_none_or(|byte| (byte >> 4) != expected_version)
    {
        return false;
    }
    match frame.get(l3..) {
        Some(slice) => is_non_first_fragment(slice, meta.addr_family),
        None => false,
    }
}

pub(in crate::afxdp) fn parse_session_flow_from_bytes(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    // #2344: a non-first IP fragment carries no L4 header. Refuse to build
    // any ported SessionFlow for it — this is the single chokepoint that
    // also defeats the meta fast path below (the XDP shim does NOT gate
    // non-first fragments, so `meta.flow_*_port` may hold payload bytes
    // read at the post-IP-header offset). Returning `None` makes the
    // fragment flowless: it follows the route-based, session-less forward
    // path instead of polluting policy / flow-cache / session indexes.
    // Composes with #1852 (NAT leaves gated on the same predicate) and
    // #2293-era screen fragment classification.
    if frame_is_non_first_fragment(frame, meta) {
        return None;
    }
    let meta_flow = parse_session_flow_from_meta(meta);
    // #3290: the metadata fallback below copies `meta.flow_src_port` verbatim
    // into the SessionKey, but the XDP shim stamps bytes [l4+4..l4+6] as
    // `flow_src_port` for EVERY ICMP/ICMPv6 type with NO query-type gate. An
    // ICMP error/control packet (Dest-Unreachable, Packet-Too-Big,
    // Time-Exceeded, Parameter-Problem, Redirect, ND/MLD, ...) would otherwise
    // install a stateful session keyed on a non-port control word, bypassing
    // the #3067 invariant the frame parser (`parse_flow_ports`) enforces.
    // Discard the metadata flow for a non-query ICMP type so the packet stays
    // flowless: `frame_flow` is already `None` for it (the frame parser gates),
    // and the offset fallback re-runs the same `parse_flow_ports` gate, so the
    // packet follows the session-less, route-based forward path. Only
    // identifier-bearing query types keep their metadata tuple (where it equals
    // the frame-derived identifier anyway).
    let meta_flow = match meta.protocol {
        PROTO_ICMP | PROTO_ICMPV6 if !meta_icmp_identifier_bearing(frame, meta) => None,
        _ => meta_flow,
    };
    // Fast path: for TCP/UDP with complete metadata tuple, use meta directly
    // without parsing the frame. This avoids extra L3/L4 parsing for the
    // common established-flow case.
    if matches!(meta.protocol, PROTO_TCP | PROTO_UDP)
        && let Some(meta_flow) = meta_flow.as_ref()
        && metadata_tuple_complete(meta, meta_flow)
    {
        return Some(meta_flow.clone());
    }

    let frame_flow = if matches!(meta.addr_family as i32, libc::AF_INET) {
        parse_ipv4_session_flow_from_frame(frame, meta)
    } else {
        parse_session_flow_from_frame(frame, meta)
    };

    if let Some(meta_flow) = meta_flow
        && metadata_tuple_complete(meta, &meta_flow)
    {
        if let Some(ref frame_flow) = frame_flow {
            if frame_flow.src_ip == meta_flow.src_ip && frame_flow.dst_ip == meta_flow.dst_ip {
                return Some(meta_flow);
            }
            return Some(frame_flow.clone());
        }
        return Some(meta_flow);
    }

    if let Some(flow) = frame_flow {
        return Some(flow);
    }

    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            if frame.len() < l3 + 20 || frame.len() < l4 {
                return None;
            }
            // #2344: same non-first-fragment gate as the frame parsers —
            // this meta-offset fallback must not fabricate ports either.
            if ipv4_is_non_first_fragment(&frame[l3..]) {
                return None;
            }
            let src_ip = IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 12],
                frame[l3 + 13],
                frame[l3 + 14],
                frame[l3 + 15],
            ));
            let dst_ip = IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 16],
                frame[l3 + 17],
                frame[l3 + 18],
                frame[l3 + 19],
            ));
            // #2361: bound by the IP-declared packet end, not just the slice.
            let declared_end = ipv4_declared_l3_end(frame, l3)?;
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol, declared_end)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                },
            })
        }
        libc::AF_INET6 => {
            if frame.len() < l3 + 40 || frame.len() < l4 {
                return None;
            }
            // #2344: same non-first-fragment gate as the frame parsers.
            if ipv6_is_non_first_fragment(&frame[l3..]) {
                return None;
            }
            let src_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 8..l3 + 24]).ok()?,
            ));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            ));
            // #2361: bound by the IP-declared packet end, not just the slice.
            let declared_end = ipv6_declared_l3_end(frame, l3)?;
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol, declared_end)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                },
            })
        }
        _ => None,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn parse_session_flow(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    parse_session_flow_from_bytes(frame, meta)
}

/// Decode an Ethernet frame into a human-readable summary showing IP src/dst,
/// TCP/UDP ports, TCP flags, and checksums. For debugging packet forwarding.
pub(in crate::afxdp) fn decode_frame_summary(frame: &[u8]) -> String {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return String::new(),
    };
    let ip = &frame[l3..];
    if ip.len() < 20 {
        return String::new();
    }
    let version = ip[0] >> 4;
    if version == 4 {
        let ihl = ((ip[0] & 0x0f) as usize) * 4;
        let total_len = u16::from_be_bytes([ip[2], ip[3]]);
        let protocol = ip[9];
        let ip_csum = u16::from_be_bytes([ip[10], ip[11]]);
        let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
        let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
        let ttl = ip[8];
        if matches!(protocol, PROTO_TCP | PROTO_UDP) && ip.len() >= ihl + 8 {
            let l4 = &ip[ihl..];
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            if protocol == PROTO_TCP && ip.len() >= ihl + 20 {
                let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
                let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
                let flags = l4[13];
                let tcp_csum = u16::from_be_bytes([l4[16], l4[17]]);
                let flag_str = tcp_flags_str(flags);
                format!(
                    "IPv4 {}:{} -> {}:{} TCP [{flag_str}] seq={seq} ack={ack} ttl={ttl} ip_csum={ip_csum:#06x} tcp_csum={tcp_csum:#06x} ip_len={total_len}",
                    src, sport, dst, dport,
                )
            } else if protocol == PROTO_UDP {
                let udp_csum = u16::from_be_bytes([l4[6], l4[7]]);
                format!(
                    "IPv4 {}:{} -> {}:{} UDP ttl={ttl} ip_csum={ip_csum:#06x} udp_csum={udp_csum:#06x} ip_len={total_len}",
                    src, sport, dst, dport,
                )
            } else {
                format!(
                    "IPv4 {} -> {} proto={protocol} ttl={ttl} ip_len={total_len}",
                    src, dst
                )
            }
        } else {
            format!(
                "IPv4 {} -> {} proto={protocol} ttl={ttl} ip_len={total_len}",
                src, dst
            )
        }
    } else if version == 6 && ip.len() >= 40 {
        let payload_len = u16::from_be_bytes([ip[4], ip[5]]);
        let next_header = ip[6];
        let hop_limit = ip[7];
        let src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap_or([0; 16]));
        let dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap_or([0; 16]));
        if matches!(next_header, PROTO_TCP | PROTO_UDP) && ip.len() >= 48 {
            let l4 = &ip[40..];
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            if next_header == PROTO_TCP && ip.len() >= 60 {
                let flags = l4[13];
                let flag_str = tcp_flags_str(flags);
                format!(
                    "IPv6 [{src}]:{sport} -> [{dst}]:{dport} TCP [{flag_str}] hop={hop_limit} pl={payload_len}"
                )
            } else {
                format!(
                    "IPv6 [{src}]:{sport} -> [{dst}]:{dport} proto={next_header} hop={hop_limit} pl={payload_len}"
                )
            }
        } else {
            format!("IPv6 [{src}] -> [{dst}] proto={next_header} hop={hop_limit} pl={payload_len}")
        }
    } else {
        String::new()
    }
}

pub(in crate::afxdp) fn parse_session_flow_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    match meta.addr_family as i32 {
        libc::AF_INET => parse_ipv4_session_flow_from_frame(frame, meta),
        libc::AF_INET6 => {
            let l3 = match meta.l3_offset {
                14 | 18
                    if frame
                        .get(meta.l3_offset as usize)
                        .is_some_and(|byte| (byte >> 4) == 6) =>
                {
                    meta.l3_offset as usize
                }
                _ => frame_l3_offset(frame)?,
            };
            let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
            let l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
                l3.checked_add(meta_rel)?
            } else {
                frame_l4_offset(frame, meta.addr_family)?
            };
            if frame.len() < l3 + 40 || frame.len() < l4 {
                return None;
            }
            // #2344: a non-first IPv6 fragment (Fragment Header type 44
            // with a non-zero offset) carries NO L4 header. Refuse to
            // synthesize a ported SessionFlow for it; return `None` so the
            // fragment is flowless and follows the route-based forward
            // path. Same predicate #1852 uses for the NAT leaves, walked
            // over the L3-relative slice.
            if ipv6_is_non_first_fragment(&frame[l3..]) {
                return None;
            }
            let src_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 8..l3 + 24]).ok()?,
            ));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            ));
            // #2361: bound the L4 port read by the IP-declared packet end
            // (l3 + 40 + payload_len, slice-clamped), not just the slice.
            let declared_end = ipv6_declared_l3_end(frame, l3)?;
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol, declared_end)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                },
            })
        }
        _ => None,
    }
}

pub(in crate::afxdp) fn parse_session_flow_from_meta(meta: UserspaceDpMeta) -> Option<SessionFlow> {
    let (src_ip, dst_ip) = match meta.addr_family as i32 {
        libc::AF_INET => {
            let src = meta.flow_src_addr.get(..4)?;
            let dst = meta.flow_dst_addr.get(..4)?;
            (
                IpAddr::V4(Ipv4Addr::new(src[0], src[1], src[2], src[3])),
                IpAddr::V4(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3])),
            )
        }
        libc::AF_INET6 => (
            IpAddr::V6(Ipv6Addr::from(meta.flow_src_addr)),
            IpAddr::V6(Ipv6Addr::from(meta.flow_dst_addr)),
        ),
        _ => return None,
    };
    if src_ip.is_unspecified() || dst_ip.is_unspecified() {
        return None;
    }
    Some(SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            src_ip,
            dst_ip,
            src_port: meta.flow_src_port,
            dst_port: meta.flow_dst_port,
        },
    })
}

pub(in crate::afxdp) fn parse_ipv4_session_flow_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    let l3 = match meta.l3_offset {
        14 | 18
            if frame
                .get(meta.l3_offset as usize)
                .is_some_and(|byte| (byte >> 4) == 4) =>
        {
            meta.l3_offset as usize
        }
        _ => frame_l3_offset(frame)?,
    };
    if frame.len() < l3 + 20 {
        return None;
    }
    let ihl = usize::from(frame[l3] & 0x0f) * 4;
    if ihl < 20 || frame.len() < l3 + ihl {
        return None;
    }
    let protocol = frame[l3 + 9];
    // #2344: a non-first IPv4 fragment carries NO L4 header — its
    // post-IP-header bytes are payload, not TCP/UDP ports. Refuse to
    // synthesize a ported SessionFlow for it. Returning `None` makes the
    // fragment flowless: it follows the route-based, session-less forward
    // path (the existing pre-#1913 "no flow tuple" behavior) instead of
    // polluting policy / flow-cache / session indexes with fake ports.
    // Mirrors #1852, which gates the NAT rewrite leaves on the same
    // `ipv4_is_non_first_fragment` predicate over the L3-relative slice.
    if ipv4_is_non_first_fragment(&frame[l3..]) {
        return None;
    }
    let parsed_l4 = l3 + ihl;
    let l4 = if meta.l4_offset > meta.l3_offset && meta.l4_offset as usize == parsed_l4 {
        meta.l4_offset as usize
    } else {
        parsed_l4
    };
    if frame.len() < l4 {
        return None;
    }
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        frame[l3 + 12],
        frame[l3 + 13],
        frame[l3 + 14],
        frame[l3 + 15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        frame[l3 + 16],
        frame[l3 + 17],
        frame[l3 + 18],
        frame[l3 + 19],
    ));
    // #2361: bound the L4 port read by the IP-declared packet end
    // (l3 + total_len, slice-clamped), not just the slice. A short total_len
    // with trailing slack/padding must NOT yield ports from out-of-datagram
    // bytes.
    let declared_end = ipv4_declared_l3_end(frame, l3)?;
    let (src_port, dst_port) = parse_flow_ports(frame, l4, protocol, declared_end)?;
    Some(SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: meta.addr_family,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        },
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn parse_zone_encoded_fabric_ingress(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> Option<u16> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    parse_zone_encoded_fabric_ingress_from_frame(frame, meta, forwarding)
}

/// #919/#922: returns the encoded zone ID (u8 → u16) directly, no
/// `zone_id_to_name` lookup or `String` clone. Callers that need a
/// name resolve via `forwarding.zone_id_to_name` on the slow path.
pub(in crate::afxdp) fn parse_zone_encoded_fabric_ingress_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> Option<u16> {
    if !ingress_is_fabric(forwarding, meta.ingress_ifindex as i32) {
        return None;
    }
    if frame.len() < 12 {
        return None;
    }
    if frame[6] != 0x02
        || frame[7] != 0xbf
        || frame[8] != 0x72
        || frame[9] != FABRIC_ZONE_MAC_MAGIC
        || frame[10] != 0x00
    {
        return None;
    }
    let id = frame[11] as u16;
    if id == 0 {
        return None;
    }
    // Validate the encoded ID exists in the configured zone map; an
    // unknown id is a stale or hostile frame. Single hash lookup —
    // the value isn't needed, just presence.
    forwarding.zone_id_to_name.get(&id).map(|_| id)
}

pub(in crate::afxdp) fn parse_packet_destination_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<IpAddr> {
    let l3 = meta.l3_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            let end = l3.checked_add(20)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 16],
                frame[l3 + 17],
                frame[l3 + 18],
                frame[l3 + 19],
            )))
        }
        libc::AF_INET6 => {
            let end = l3.checked_add(40)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            )))
        }
        _ => None,
    }
}

pub(in crate::afxdp) fn try_parse_metadata(
    area: &MmapArea,
    desc: XdpDesc,
) -> Option<UserspaceDpMeta> {
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    if (desc.addr as usize) < meta_len {
        return None;
    }
    let meta_offset = (desc.addr as usize).checked_sub(meta_len)?;
    let bytes = area.slice(meta_offset, meta_len)?;
    // ptr::read_unaligned: bytes is &[u8] with no alignment guarantee;
    // dereferencing as *const UserspaceDpMeta directly would be UB on
    // architectures that fault on misaligned loads (the x86 host happens
    // to tolerate it but it's still UB and a portability footgun).
    let meta = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const UserspaceDpMeta) };
    if meta.magic != USERSPACE_META_MAGIC || meta.version != USERSPACE_META_VERSION {
        return None;
    }
    if meta.length as usize != meta_len {
        return None;
    }
    Some(meta)
}

#[cfg(test)]
#[path = "inspect_tests.rs"]
mod inspect_iplen_tests;
