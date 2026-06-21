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
/// overflows by up to 40 bytes. Operators concerned about this should
/// also enable the `ip-source-route` screen, which drops any IPv4
/// packet with `ihl > 5`. IPv4 only — IPv6 ping-of-death would need
/// reassembled-length tracking across NEXTHDR_FRAGMENT and is not
/// covered by the BPF reference either.
#[inline]
pub(super) fn check_ping_of_death(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if profile.ping_death && pkt.addr_family == libc::AF_INET as u8 && pkt.is_fragment {
        let offset_bytes = ((pkt.ip_frag_off & 0x1FFF) as u32) << 3;
        if offset_bytes + pkt.ip_total_len as u32 > 65535 {
            return Some("ping-of-death");
        }
    }
    None
}

/// Teardrop: IPv4 non-first fragment with tiny payload (< 8 bytes).
#[inline]
pub(super) fn check_teardrop(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if profile.teardrop && pkt.addr_family == libc::AF_INET as u8 && pkt.is_fragment {
        let frag_offset = pkt.ip_frag_off & 0x1FFF;
        if frag_offset > 0 {
            let hdr_len = (pkt.ip_ihl as u16) * 4;
            if pkt.ip_total_len > hdr_len {
                let payload = pkt.ip_total_len - hdr_len;
                if payload < 8 {
                    return Some("teardrop");
                }
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

/// IP source-route option: IPv4 with IHL > 5 (options present).
#[inline]
pub(super) fn check_source_route(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if profile.source_route && pkt.addr_family == libc::AF_INET as u8 && pkt.ip_ihl > 5 {
        return Some("ip-source-route");
    }
    None
}
