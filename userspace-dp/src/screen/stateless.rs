//! Side-effect-free stateless screen checks. Each helper takes
//! immutable borrows of the per-zone `ScreenProfile` and the parsed
//! `ScreenPacketInfo` and returns `Some(reason)` if the packet
//! should be dropped. The orchestrator in `mod.rs` calls these in
//! the same order the monolithic implementation did so drop
//! precedence is preserved byte-for-byte.
//!
//! Hot-path discipline: every helper is `#[inline]` so LLVM inlines
//! the bodies back into the caller. No allocations.

use super::packet::{
    PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, ScreenPacketInfo, ScreenProfile, TCP_ACK, TCP_FIN,
    TCP_SYN, TCP_URG,
};

/// LAND attack: `src_ip == dst_ip`.
///
/// Mirrors the authoritative BPF screen (#2215, see
/// `git show 13fa1009e^:bpf/xdp/xdp_screen.c` ~lines 715-723), which
/// dropped on `src_ip == dst_ip` ALONE for both IPv4 and IPv6, with NO
/// port comparison. The classic named LAND attack does use equal ports,
/// but the source==destination IP match is the LAND signature and an
/// unconditional anti-spoofing invariant — a spoofed frame whose source
/// equals its destination is illegal regardless of L4 ports (and need
/// not even be TCP/UDP). The pre-#2215 userspace port added a
/// `src_port == dst_port` requirement that silently admitted such frames
/// when the ports differed; that narrowing is removed here for BPF
/// parity.
#[inline]
pub(super) fn check_land(profile: &ScreenProfile, pkt: &ScreenPacketInfo) -> Option<&'static str> {
    if profile.land && pkt.src_ip == pkt.dst_ip {
        return Some("land-attack");
    }
    None
}

/// TCP flag-bit screens (SYN+FIN, no-flag, FIN-no-ACK, WinNuke,
/// syn_frag). Outer guard `!is_fragment || is_first_fragment`
/// mirrors the BPF #853 defense (#1137): subsequent fragments
/// don't carry the L4 header so `tcp_flags` is unreliable for them.
#[inline]
pub(super) fn check_tcp_flag_screens(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if pkt.protocol != PROTO_TCP {
        return None;
    }
    if pkt.is_fragment && !pkt.is_first_fragment {
        return None;
    }
    let tf = pkt.tcp_flags;

    if profile.syn_fin && (tf & TCP_SYN) != 0 && (tf & TCP_FIN) != 0 {
        return Some("tcp-syn-fin");
    }

    if profile.no_flag && tf == 0 {
        return Some("tcp-no-flag");
    }

    if profile.fin_no_ack && (tf & TCP_FIN) != 0 && (tf & TCP_ACK) == 0 {
        return Some("tcp-fin-no-ack");
    }

    if profile.winnuke && (tf & TCP_URG) != 0 && pkt.dst_port == 139 {
        return Some("winnuke");
    }

    // #1137: SYN-fragment — TCP SYN on a first-fragment is the
    // fragmentation-based attack pattern.
    if profile.syn_frag && (tf & TCP_SYN) != 0 && pkt.is_first_fragment {
        return Some("syn-frag");
    }

    None
}

/// Ping of Death: an IPv4 fragment whose contribution to the
/// reassembled datagram would exceed the 65535-byte IP length limit.
///
/// Ports the authoritative BPF screen `SCREEN_PING_OF_DEATH` formula
/// (#2215, restored from #893 / `git show
/// 13fa1009e^:bpf/xdp/xdp_screen.c`). The dataplane does not reassemble
/// fragments, so the classic ping-of-death (many small fragments that
/// reassemble to >65535 bytes) is detected per-fragment from the
/// fragment offset plus this fragment's total length:
///
/// ```text
///   offset_bytes = (frag_off & 0x1FFF) << 3   // 8-byte fragment units
///   if offset_bytes + ip_total_len > 65535 -> drop
/// ```
///
/// Applies to ANY IPv4 protocol (not just ICMP) and only to fragmented
/// packets, exactly matching the BPF reference. The pre-#2215 userspace
/// port reverted to the original pre-#893 dead-code shape (an
/// ICMP-only `pkt.pkt_len as u32 > 65535` predicate that is structurally
/// unsatisfiable because `pkt_len` is a u16), so fragment-based
/// ping-of-death went entirely undetected.
///
/// Limitation (inherited from #893): a first fragment carrying IP
/// options combined with non-first fragments without them can craft
/// `offset_bytes + ip_total_len <= 65535` while the reassembled total
/// overflows by up to 40 bytes. (Note: the `ip-source-route` screen now
/// only drops actual LSRR/SSRR options after #2973, so it no longer
/// blanket-drops every IHL>5 packet as a side defense here.)
///
/// #2293: the IPv6 path applies the same per-fragment oversize formula.
/// The dataplane does not reassemble, so for an IPv6 fragment we size
/// the reassembled end-byte this fragment implies:
///
/// ```text
///   offset_bytes = (frag_off & 0xFFF8) >> 3 << 3 == frag_off & 0xFFF8
///   frag_data    = ip_payload_len - frag_data_off   // L4/data bytes
///   if offset_bytes + frag_data > 65535 -> drop
/// ```
///
/// `frag_off & 0xFFF8` is already the byte offset (the IPv6 fragment
/// offset field is the upper 13 bits and counts 8-byte units, so masking
/// the low 3 bits yields the offset directly in bytes). `frag_data_off`
/// is the payload-region bytes consumed by extension headers up to and
/// including the fragment header (captured in `extract.rs`), so
/// `ip_payload_len - frag_data_off` is this fragment's data contribution.
/// A maximal-offset last fragment that pushes the reassembled datagram
/// past the 65535 IPv6-payload ceiling is dropped — the IPv6 analogue of
/// the classic ping-of-death. Like the IPv4 path this fires on ANY IPv6
/// protocol, only for fragments, and inherits the same per-fragment
/// (non-reassembling) approximation limit.
#[inline]
pub(super) fn check_ping_of_death(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if !profile.ping_death || !pkt.is_fragment {
        return None;
    }
    if pkt.addr_family == libc::AF_INET as u8 {
        let offset_bytes = ((pkt.ip_frag_off & 0x1FFF) as u32) << 3;
        if offset_bytes + pkt.ip_total_len as u32 > 65535 {
            return Some("ping-of-death");
        }
    } else if pkt.addr_family == libc::AF_INET6 as u8 {
        // IPv6 fragment offset is the upper 13 bits (8-byte units) of the
        // fragment header's frag_off field; `& 0xFFF8` is the byte offset.
        let offset_bytes = (pkt.ip_frag_off & 0xFFF8) as u32;
        // This fragment's data bytes = payload_len minus the ext-header
        // bytes preceding the fragment data. saturating_sub guards a
        // hostile payload_len shorter than the headers actually walked.
        let frag_data = pkt.ip_payload_len.saturating_sub(pkt.frag_data_off) as u32;
        if offset_bytes + frag_data > 65535 {
            return Some("ping-of-death");
        }
    }
    None
}

/// Teardrop: a non-first fragment with tiny / zero / under-length payload
/// (< 8 bytes of data) — the classic overlapping-fragment signature that
/// confuses downstream reassemblers.
///
/// #3027: a non-first fragment whose `ip_total_len <= hdr_len` carries
/// zero (or, by the field's claimed length, "negative") payload. That is
/// even more clearly malformed than the classic tiny-but-positive
/// teardrop signature — exactly the kind of crafted fragment that
/// confuses downstream reassembly — yet the pre-#3027 code only entered
/// the payload-size branch when `ip_total_len > hdr_len`, so the
/// zero/under-length case slipped through as a PASS. Treat it as a
/// teardrop drop.
///
/// #3119: this check was IPv4-only while the sibling `check_ping_of_death`
/// already screened both families. An IPv6 teardrop (a non-first Fragment
/// extension-header fragment with a tiny data contribution) therefore
/// bypassed the screen entirely. The IPv6 arm mirrors the
/// `check_ping_of_death` IPv6 sizing: the Fragment header's offset field
/// is the upper 13 bits (8-byte units), so `ip_frag_off & 0xFFF8` is the
/// byte offset, and this fragment's data bytes are
/// `ip_payload_len - frag_data_off` (the L4/data region after the
/// extension headers up to and including the 8-byte fragment header).
/// `saturating_sub` collapses a hostile under-length (`frag_data_off`
/// larger than the declared `ip_payload_len`) to 0, which is `< 8` and so
/// is treated as the malformed zero/under-length teardrop case — the IPv6
/// analogue of the #3027 IPv4 fix. Junos vSRX applies teardrop screening
/// to both families.
#[inline]
pub(super) fn check_teardrop(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if !profile.teardrop || !pkt.is_fragment {
        return None;
    }
    if pkt.addr_family == libc::AF_INET as u8 {
        let frag_offset = pkt.ip_frag_off & 0x1FFF;
        if frag_offset > 0 {
            let hdr_len = (pkt.ip_ihl as u16) * 4;
            if pkt.ip_total_len <= hdr_len {
                // No / negative payload on a non-first fragment — malformed.
                return Some("teardrop");
            }
            let payload = pkt.ip_total_len - hdr_len;
            if payload < 8 {
                return Some("teardrop");
            }
        }
    } else if pkt.addr_family == libc::AF_INET6 as u8 {
        // IPv6 Fragment header: offset is the upper 13 bits (8-byte
        // units); `& 0xFFF8` is the byte offset. A non-first fragment has
        // a non-zero byte offset.
        let offset_bytes = pkt.ip_frag_off & 0xFFF8;
        if offset_bytes > 0 {
            // This fragment's data bytes = payload_len minus the
            // ext-header bytes preceding the fragment data. saturating_sub
            // collapses a hostile under-length to 0 (< 8 → teardrop), the
            // IPv6 analogue of the #3027 zero/negative-payload case.
            let frag_data = pkt.ip_payload_len.saturating_sub(pkt.frag_data_off);
            if frag_data < 8 {
                return Some("teardrop");
            }
        }
    }
    None
}

/// ICMP fragment: any fragmented ICMP/ICMPv6 packet.
#[inline]
pub(super) fn check_icmp_fragment(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if profile.icmp_fragment
        && pkt.is_fragment
        && (pkt.protocol == PROTO_ICMP || pkt.protocol == PROTO_ICMPV6)
    {
        return Some("icmp-fragment");
    }
    None
}

/// IP source-route screen.
///
/// #2973: drop ONLY when an actual source-route option/header is present
/// — IPv4 LSRR (option 131) / SSRR (option 137), or an IPv6 Routing
/// Header (next-header 43) carrying a source-route routing type (RH0 /
/// type 1). The extractor (`extract.rs`) decodes the IPv4 options TLVs
/// and the IPv6 extension-header chain to set `saw_ipv4_source_route` /
/// `saw_ipv6_routing_header`.
///
/// The pre-#2973 implementation dropped on ANY IPv4 IHL>5 (any options
/// present), which false-dropped benign router-alert / record-route /
/// timestamp / security packets, and it ignored IPv6 Routing Headers
/// entirely — a vSRX/SRX feature-parity gap (the screen is expected to
/// catch the source-route security intent on both families).
#[inline]
pub(super) fn check_source_route(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if profile.source_route && (pkt.saw_ipv4_source_route || pkt.saw_ipv6_routing_header) {
        return Some("ip-source-route");
    }
    None
}
