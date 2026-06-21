// Tests for screen.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep screen.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "screen_tests.rs"]` from screen.rs.

use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn default_profile() -> ScreenProfile {
    ScreenProfile {
        land: true,
        syn_fin: true,
        no_flag: true,
        fin_no_ack: true,
        winnuke: true,
        ping_death: true,
        teardrop: true,
        icmp_fragment: true,
        syn_frag: true,
        source_route: true,
        icmp_flood_threshold: 0,
        udp_flood_threshold: 0,
        syn_flood_threshold: 0,
        syn_cookie: false,
        session_limit_src: 0,
        session_limit_dst: 0,
        port_scan_threshold: 0,
        ip_sweep_threshold: 0,
    }
}

fn tcp_pkt(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16, flags: u8) -> ScreenPacketInfo {
    ScreenPacketInfo {
        addr_family: match src {
            IpAddr::V4(_) => libc::AF_INET as u8,
            IpAddr::V6(_) => libc::AF_INET6 as u8,
        },
        protocol: PROTO_TCP,
        tcp_flags: flags,
        src_ip: src,
        dst_ip: dst,
        src_port,
        dst_port,
        tcp_seq: 1,
        tcp_ack: 0,
        tcp_mss: 1460,
        pkt_len: 60,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 60,
    }
}

fn icmp_pkt(src: IpAddr, dst: IpAddr, pkt_len: u16) -> ScreenPacketInfo {
    let proto = match src {
        IpAddr::V4(_) => PROTO_ICMP,
        IpAddr::V6(_) => PROTO_ICMPV6,
    };
    ScreenPacketInfo {
        addr_family: match src {
            IpAddr::V4(_) => libc::AF_INET as u8,
            IpAddr::V6(_) => libc::AF_INET6 as u8,
        },
        protocol: proto,
        tcp_flags: 0,
        src_ip: src,
        dst_ip: dst,
        src_port: 0,
        dst_port: 0,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: pkt_len,
    }
}

fn udp_pkt(src: IpAddr, dst: IpAddr) -> ScreenPacketInfo {
    ScreenPacketInfo {
        addr_family: match src {
            IpAddr::V4(_) => libc::AF_INET as u8,
            IpAddr::V6(_) => libc::AF_INET6 as u8,
        },
        protocol: PROTO_UDP,
        tcp_flags: 0,
        src_ip: src,
        dst_ip: dst,
        src_port: 5000,
        dst_port: 5001,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len: 100,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 100,
    }
}

fn make_state(zone: &str, profile: ScreenProfile) -> ScreenState {
    let mut state = ScreenState::new();
    let mut profiles = FxHashMap::default();
    profiles.insert(zone.to_string(), profile);
    state.update_profiles(profiles);
    state
}

// ================================================================
// Land attack
// ================================================================

#[test]
fn land_attack_v4() {
    let mut state = make_state("trust", default_profile());
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let pkt = tcp_pkt(src, src, 80, 80, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("land-attack")
    );
}

#[test]
fn land_attack_v6() {
    let mut state = make_state("trust", default_profile());
    let src = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap());
    let pkt = tcp_pkt(src, src, 443, 443, TCP_SYN);
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("land-attack")
    );
}

#[test]
fn land_attack_different_ports_passes() {
    let mut state = make_state("trust", default_profile());
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    // Same IP but different ports should pass
    let pkt = tcp_pkt(src, src, 80, 443, TCP_SYN);
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn land_attack_disabled() {
    let mut profile = default_profile();
    profile.land = false;
    let mut state = make_state("trust", profile);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let pkt = tcp_pkt(src, src, 80, 80, TCP_SYN);
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// TCP SYN+FIN
// ================================================================

#[test]
fn syn_fin_drops() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN | TCP_FIN,
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("tcp-syn-fin")
    );
}

#[test]
fn syn_fin_disabled_passes() {
    let mut profile = default_profile();
    profile.syn_fin = false;
    // SYN+FIN also has FIN set without ACK, so disable fin_no_ack too
    profile.fin_no_ack = false;
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN | TCP_FIN,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// TCP no-flag (null scan)
// ================================================================

#[test]
fn no_flag_drops() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        0, // no flags
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("tcp-no-flag")
    );
}

#[test]
fn no_flag_disabled_passes() {
    let mut profile = default_profile();
    profile.no_flag = false;
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        0,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// TCP FIN without ACK
// ================================================================

#[test]
fn fin_no_ack_drops() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_FIN, // FIN without ACK
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("tcp-fin-no-ack")
    );
}

#[test]
fn fin_with_ack_passes() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_FIN | TCP_ACK, // FIN+ACK is normal
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// WinNuke
// ================================================================

#[test]
fn winnuke_drops() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        139, // NetBIOS
        TCP_URG | TCP_ACK,
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("winnuke")
    );
}

#[test]
fn winnuke_wrong_port_passes() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80, // not 139
        TCP_URG | TCP_ACK,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn winnuke_disabled_passes() {
    let mut profile = default_profile();
    profile.winnuke = false;
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        139,
        TCP_URG | TCP_ACK,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// Ping of Death
// ================================================================

/// Build an IPv4 fragment with the given fragment-offset (in 8-byte
/// units, i.e. the raw 13-bit offset field) and IP total length.
/// `more_fragments` controls the MF bit. Used by the #2215
/// ping-of-death and teardrop regression tests.
fn ipv4_fragment(
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    frag_units: u16,
    more_fragments: bool,
    ip_total_len: u16,
) -> ScreenPacketInfo {
    let mut frag_off = frag_units & 0x1FFF;
    if more_fragments {
        frag_off |= 0x2000;
    }
    let is_first = more_fragments && (frag_units & 0x1FFF) == 0;
    ScreenPacketInfo {
        addr_family: libc::AF_INET as u8,
        protocol,
        tcp_flags: 0,
        src_ip: src,
        dst_ip: dst,
        src_port: 0,
        dst_port: 0,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len: ip_total_len,
        is_fragment: (frag_off & 0x3FFF) != 0,
        is_first_fragment: is_first,
        ip_ihl: 5,
        ip_frag_off: frag_off,
        ip_total_len,
    }
}

#[test]
fn ping_of_death_oversized_fragment_drops() {
    // #2215 fail-on-revert (sub-bug A): the classic ping-of-death is a
    // fragment whose reassembled contribution exceeds the 65535-byte IP
    // length limit. The dataplane does not reassemble, so it is detected
    // per-fragment: offset_bytes = (frag_off & 0x1FFF) << 3; if
    // offset_bytes + ip_total_len > 65535 -> drop (BPF #893 formula).
    //
    // Last fragment at offset 8191 units = 65528 bytes carrying a 60-byte
    // IP datagram: 65528 + 60 = 65588 > 65535 -> ping-of-death. Pre-#2215
    // the check was ICMP-only dead code (`pkt_len as u32 > 65535`,
    // unsatisfiable for a u16) so this PASSED.
    let mut state = make_state("trust", default_profile());
    let pkt = ipv4_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_ICMP,
        8191, // 8191 * 8 = 65528 bytes
        false,
        60,
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("ping-of-death")
    );
}

#[test]
fn ping_of_death_oversized_fragment_any_proto_drops() {
    // #2215 (sub-bug A): the BPF reference fires for ANY IPv4 protocol,
    // not just ICMP. A UDP fragment that overflows the reassembly limit
    // must DROP. (Disable the UDP-flood screen so only ping-of-death can
    // fire.)
    let mut profile = default_profile();
    profile.udp_flood_threshold = 0;
    let mut state = make_state("trust", profile);
    let pkt = ipv4_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_UDP,
        8190, // 8190 * 8 = 65520 bytes
        false,
        100, // 65520 + 100 = 65620 > 65535
    );
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("ping-of-death")
    );
}

#[test]
fn ping_of_death_in_bounds_fragment_passes() {
    // Control: a fragment whose offset + total length stays within the
    // 65535-byte limit must NOT be flagged as ping-of-death. Use a UDP
    // fragment (with the udp-flood screen disabled) so neither the
    // icmp-fragment nor teardrop screens can mask the ping-of-death
    // outcome; payload (1500-20=1480) is well above the 8-byte teardrop
    // floor regardless.
    let mut profile = default_profile();
    profile.udp_flood_threshold = 0;
    let mut state = make_state("trust", profile);
    let pkt = ipv4_fragment(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        PROTO_UDP,
        100,   // 100 * 8 = 800 bytes
        false, // not the last fragment is irrelevant; a mid-chain fragment
        1500,  // 800 + 1500 = 2300 <= 65535
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn ping_of_death_non_fragment_passes() {
    // Control: a normal (unfragmented) ICMP echo must NOT be flagged —
    // the check only applies to fragments.
    let mut state = make_state("trust", default_profile());
    let pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn normal_ping_passes() {
    let mut state = make_state("trust", default_profile());
    let pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// Teardrop
// ================================================================

#[test]
fn teardrop_drops() {
    let mut state = make_state("trust", default_profile());
    let pkt = ScreenPacketInfo {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_ACK, // use ACK to avoid no-flag check
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        src_port: 1234,
        dst_port: 80,
        tcp_seq: 1,
        tcp_ack: 0,
        tcp_mss: 1460,
        pkt_len: 28,
        is_fragment: true,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0x0001 | 0x2000, // offset=1 (non-first frag), MF=1
        ip_total_len: 24,             // 20 byte header + 4 byte payload (< 8)
    };
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("teardrop")
    );
}

#[test]
fn teardrop_first_fragment_passes() {
    let _state = make_state("trust", default_profile());
    let pkt = ScreenPacketInfo {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        src_port: 1234,
        dst_port: 80,
        tcp_seq: 1,
        tcp_ack: 0,
        tcp_mss: 1460,
        pkt_len: 24,
        is_fragment: true,
        // #1137 Copilot review: ip_frag_off=0x2000 means MF=1 &&
        // offset==0, which IS a first-fragment. Keep the fields
        // consistent with each other so future regressions don't
        // hide behind misleading metadata.
        is_first_fragment: true,
        ip_ihl: 5,
        ip_frag_off: 0x2000, // offset=0 (first frag), MF=1
        ip_total_len: 24,
    };
    // First fragment (offset=0) — teardrop only triggers on non-first
    // However no_flag check will trigger first since tcp_flags=0
    // Use a profile with only teardrop enabled
    let mut profile = ScreenProfile::default();
    profile.teardrop = true;
    let mut st = make_state("trust", profile);
    assert_eq!(st.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// ICMP fragment
// ================================================================

#[test]
fn icmp_fragment_drops() {
    let mut state = make_state("trust", default_profile());
    let mut pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    pkt.is_fragment = true;
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("icmp-fragment")
    );
}

#[test]
fn icmpv6_fragment_drops() {
    let mut state = make_state("trust", default_profile());
    let mut pkt = icmp_pkt(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        84,
    );
    pkt.is_fragment = true;
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("icmp-fragment")
    );
}

// ================================================================
// #1137 SCREEN_SYN_FRAG — TCP SYN on a first-fragment is the
// fragmentation-based attack pattern. Mirrors BPF SCREEN_SYN_FRAG
// (see #866 / docs/pr/bug-batch-866-867-916-925/design.md §1).
// ================================================================

#[test]
fn syn_frag_drops_on_first_fragment_with_syn() {
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        12345,
        80,
        TCP_SYN,
    );
    pkt.is_fragment = true;
    pkt.is_first_fragment = true;
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("syn-frag")
    );
}

#[test]
fn syn_frag_passes_when_first_fragment_without_syn() {
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        12345,
        80,
        TCP_ACK, // ACK without SYN — not a SYN-fragment
    );
    pkt.is_fragment = true;
    pkt.is_first_fragment = true;
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn syn_frag_passes_on_subsequent_fragment() {
    // Subsequent fragments don't carry the L4 header, so tcp_flags is
    // unreliable. is_first_fragment=0 keeps the check from firing on
    // them — even if SYN bit is somehow set in the meta (e.g. a
    // crafted attacker frame), is_first_fragment guards us.
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        12345,
        80,
        TCP_SYN,
    );
    pkt.is_fragment = true;
    pkt.is_first_fragment = false;
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn syn_frag_passes_on_non_fragmented_syn() {
    // Non-fragmented TCP SYN is normal connection setup, not the
    // syn-frag attack. Should pass regardless of profile.syn_frag.
    let mut profile = ScreenProfile::default();
    profile.syn_frag = true;
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        12345,
        80,
        TCP_SYN,
    );
    // Defaults: is_fragment=false, is_first_fragment=false
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn syn_frag_disabled_when_profile_off() {
    // Even a SYN-bearing first-fragment passes when the profile
    // doesn't enable syn_frag.
    let profile = ScreenProfile::default(); // all checks off
    let mut state = make_state("trust", profile);
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        12345,
        80,
        TCP_SYN,
    );
    pkt.is_fragment = true;
    pkt.is_first_fragment = true;
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn extract_screen_info_ipv4_first_fragment() {
    // Build a synthetic IPv4 header at offset 14 (Ethernet) with
    // MF=1 and offset=0. version=4, ihl=5, tot_len=40 (20 IP + 20 TCP),
    // protocol=TCP, src=1.2.3.4 dst=5.6.7.8.
    let mut frame = vec![0u8; 14 + 40];
    // Ethernet: zeroed (we don't parse it here)
    let ip = 14;
    frame[ip] = 0x45; // version=4, ihl=5
    frame[ip + 2..ip + 4].copy_from_slice(&40u16.to_be_bytes());
    // frag_off: MF (0x2000) | offset 0 = 0x2000 BE
    frame[ip + 6..ip + 8].copy_from_slice(&0x2000u16.to_be_bytes());
    frame[ip + 9] = 6; // protocol = TCP
    frame[ip + 12..ip + 16].copy_from_slice(&[1, 2, 3, 4]);
    frame[ip + 16..ip + 20].copy_from_slice(&[5, 6, 7, 8]);

    let info = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        6,    // TCP
        0x02, // SYN
        40,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        12345,
        80,
        14,
    )
    .expect("valid IPv4 first fragment parses");
    assert!(info.is_fragment, "MF=1 → is_fragment");
    assert!(
        info.is_first_fragment,
        "MF=1 && offset==0 → is_first_fragment"
    );
}

#[test]
fn extract_screen_info_ipv4_subsequent_fragment() {
    // offset=8 octets (encoded as 0x0001 since offset is in 8-byte units),
    // MF=0 (last fragment).
    let mut frame = vec![0u8; 14 + 40];
    let ip = 14;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&40u16.to_be_bytes());
    frame[ip + 6..ip + 8].copy_from_slice(&0x0001u16.to_be_bytes());
    frame[ip + 9] = 6;

    let info = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        6,
        0,
        40,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        0,
        0,
        14,
    )
    .expect("valid IPv4 subsequent fragment parses");
    assert!(info.is_fragment, "offset>0 → is_fragment");
    assert!(
        !info.is_first_fragment,
        "offset>0 → is_first_fragment must be 0"
    );
}

#[test]
fn extract_screen_info_ipv6_first_fragment() {
    // IPv6 base header (40 bytes) at offset 14, with NextHdr=44 (FRAGMENT),
    // followed by an 8-byte fragment ext header. MF=1, offset=0.
    let mut frame = vec![0u8; 14 + 40 + 8];
    // IPv6 first byte: version=6 in top nibble
    frame[14] = 0x60;
    // NextHdr = FRAGMENT
    frame[14 + 6] = 44;
    // Fragment header at offset 14+40 = 54: nexthdr=6 (TCP), reserved=0,
    // frag_off (MF=1, offset=0) = 0x0001 in big-endian.
    let frag_off_pos = 14 + 40 + 2;
    frame[14 + 40] = 6; // inner nexthdr = TCP
    frame[frag_off_pos..frag_off_pos + 2].copy_from_slice(&0x0001u16.to_be_bytes());

    let info = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0x02,
        48,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    )
    .expect("valid IPv6 first fragment parses");
    assert!(info.is_fragment, "IPv6 MF=1 → is_fragment");
    assert!(
        info.is_first_fragment,
        "IPv6 MF=1 && offset==0 → is_first_fragment"
    );
}

#[test]
fn extract_screen_info_ipv6_subsequent_fragment() {
    // IPv6 fragment with offset>0 (e.g. offset=1 in 8-byte units → 0x0008).
    let mut frame = vec![0u8; 14 + 40 + 8];
    frame[14] = 0x60;
    frame[14 + 6] = 44;
    let frag_off_pos = 14 + 40 + 2;
    frame[14 + 40] = 6;
    frame[frag_off_pos..frag_off_pos + 2].copy_from_slice(&0x0008u16.to_be_bytes());

    let info = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0,
        48,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        0,
        0,
        14,
    )
    .expect("valid IPv6 subsequent fragment parses");
    assert!(info.is_fragment, "IPv6 offset>0 → is_fragment");
    assert!(
        !info.is_first_fragment,
        "IPv6 offset>0 → is_first_fragment must be 0"
    );
}

#[test]
fn extract_screen_info_ipv6_truncated_fragment_fails_closed() {
    // #2146 IDS-evasion: an IPv6 frame whose base header advertises
    // NextHdr=FRAGMENT (44) but whose captured bytes are TOO SHORT to
    // contain the 8-byte fragment header. The pre-fix extractor
    // `break`d out of the walk and returned defaults with
    // `is_first_fragment=false`, so a SYN-bearing truncated fragment
    // silently bypassed the `syn-frag` screen. The fix returns
    // `Err(TruncatedIpv6ExtChain)` so the caller drops it FAIL-CLOSED.
    //
    // Frame: 14 Ethernet + 40 IPv6 base + only 4 of the 8 fragment
    // bytes present (offset+8 > frame.len()).
    let mut frame = vec![0u8; 14 + 40 + 4];
    frame[14] = 0x60; // version=6
    frame[14 + 6] = 44; // NextHdr = FRAGMENT
    frame[14 + 40] = 6; // inner nexthdr = TCP (would have set syn-frag)

    let res = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,    // TCP
        0x02, // SYN — the attack-relevant flag
        48,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    );
    let err = res.expect_err("truncated IPv6 FRAGMENT header must FAIL CLOSED, not pass syn-frag");
    assert_eq!(err, ScreenParseError::TruncatedIpv6ExtChain);
    assert_eq!(err.screen_reason(), "ip-malformed", "fail-closed drop reason");
}

#[test]
fn extract_screen_info_ipv6_truncated_base_header_fails_closed() {
    // AF_INET6 metadata but the captured frame is shorter than the
    // mandatory 40-byte IPv6 base header. Pre-fix this fell through the
    // `l3_offset + 40 <= frame.len()` guard to silent defaults; now it
    // is FAIL-CLOSED.
    let frame = vec![0u8; 14 + 30]; // 10 bytes short of the base header
    let res = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0x02,
        44,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    );
    assert_eq!(
        res.expect_err("short IPv6 base header must fail closed"),
        ScreenParseError::TruncatedIpv6ExtChain
    );
}

#[test]
fn extract_screen_info_ipv6_truncated_hopbyhop_fails_closed() {
    // NextHdr=HOP-BY-HOP (0) at the base header, but the chain is cut
    // off before the hop-by-hop header's own 2 length bytes — the walk
    // runs out of bytes before reaching the FRAGMENT/upper header.
    let mut frame = vec![0u8; 14 + 40]; // exactly the base header, no ext bytes
    frame[14] = 0x60;
    frame[14 + 6] = 0; // NextHdr = HOP-BY-HOP, but offset(54)+2 > len(54)
    let res = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0x02,
        40,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    );
    assert_eq!(
        res.expect_err("truncated hop-by-hop chain must fail closed"),
        ScreenParseError::TruncatedIpv6ExtChain
    );
}

#[test]
fn extract_screen_info_ipv6_exact_fragment_bytes_parses_ok() {
    // Boundary: the frame is EXACTLY long enough to hold the 8-byte
    // fragment header (offset + 8 == frame.len()). This must parse OK
    // (no off-by-one over-rejection) and yield is_first_fragment for a
    // MF=1, offset=0 first fragment carrying TCP.
    let mut frame = vec![0u8; 14 + 40 + 8];
    frame[14] = 0x60;
    frame[14 + 6] = 44; // FRAGMENT
    frame[14 + 40] = 6; // inner nexthdr = TCP
    let frag_off_pos = 14 + 40 + 2;
    frame[frag_off_pos..frag_off_pos + 2].copy_from_slice(&0x0001u16.to_be_bytes());
    assert_eq!(frame.len(), 14 + 40 + 8, "frame is exactly base + frag hdr");

    let info = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0x02,
        48,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    )
    .expect("exactly-enough fragment bytes must parse OK, not over-reject");
    assert!(info.is_fragment, "MF=1 → is_fragment");
    assert!(
        info.is_first_fragment,
        "MF=1 && offset==0 → is_first_fragment"
    );
}

#[test]
fn extract_screen_info_ipv6_hopbyhop_overshoot_inner_tcp_fails_closed() {
    // #2189 MAJOR fail-open: the base NextHdr=HOP-BY-HOP (0) header's own
    // length bytes ARE present, but its DECLARED length (HdrExtLen=200)
    // advances `offset` far past the captured frame. The inner NextHdr is
    // TCP (6). Pre-fix, the walk advanced `offset` without re-validating
    // it, then the next iteration hit the `PROTO_TCP` arm, set
    // `tcp_offset=Some(offset)` and returned `Ok{is_first_fragment:false}`
    // — a SYN with NO captured FRAGMENT header bypassed `syn-frag`. The
    // fix re-validates `offset > frame.len()` at the top of the loop, so
    // this now FAILS CLOSED before the terminal arm runs.
    //
    // Frame: 14 Ethernet + 40 IPv6 base + 8 bytes of hop-by-hop header
    // (only the first 2 — NextHdr + HdrExtLen — are read).
    let mut frame = vec![0u8; 14 + 40 + 8];
    frame[14] = 0x60; // version=6
    frame[14 + 6] = 0; // base NextHdr = HOP-BY-HOP
    frame[14 + 40] = 6; // hop-by-hop NextHdr = TCP (the inner upper-layer)
    frame[14 + 40 + 1] = 200; // HdrExtLen=200 → offset jumps far past frame

    let res = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,    // TCP
        0x02, // SYN — the attack-relevant flag
        48,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    );
    assert_eq!(
        res.expect_err("hop-by-hop overshoot to inner TCP must FAIL CLOSED, not pass syn-frag"),
        ScreenParseError::TruncatedIpv6ExtChain
    );
}

#[test]
fn extract_screen_info_ipv6_routing_overshoot_unknown_inner_fails_closed() {
    // #2189 sibling: a ROUTING (43) header whose DECLARED length
    // overshoots the frame, with an UNKNOWN inner NextHdr that would hit
    // the `_` terminal arm and `break` with `Ok` pre-fix. The fix's
    // top-of-loop `offset > frame.len()` guard covers the `_` arm too.
    let mut frame = vec![0u8; 14 + 40 + 8];
    frame[14] = 0x60;
    frame[14 + 6] = 43; // base NextHdr = ROUTING
    frame[14 + 40] = 253; // routing NextHdr = unknown/experimental → `_` arm
    frame[14 + 40 + 1] = 200; // HdrExtLen=200 → offset overshoots

    let res = extract_screen_info(
        &frame,
        libc::AF_INET6 as u8,
        6,
        0x02,
        48,
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        14,
    );
    assert_eq!(
        res.expect_err("routing overshoot to unknown inner must FAIL CLOSED"),
        ScreenParseError::TruncatedIpv6ExtChain
    );
}

#[test]
fn syn_frag_drops_truncated_ipv6_first_fragment_at_screen() {
    // End-to-end at the screen layer: a properly-parsed IPv6 SYN first
    // fragment is dropped by `syn-frag`. This pins the defense the
    // truncated-fragment evasion was bypassing: pre-#2146 the extractor
    // returned `is_first_fragment=false` for a truncated frame, so this
    // check never fired. With the extractor now FAIL-CLOSED, a truncated
    // frame is dropped before this check; a complete one is dropped HERE.
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        12345,
        80,
        TCP_SYN,
    );
    pkt.is_fragment = true;
    pkt.is_first_fragment = true;
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("syn-frag"),
        "IPv6 SYN first-fragment must hit the syn-frag screen"
    );
}

#[test]
fn tcp_no_flag_passes_on_subsequent_fragment_with_zero_flags() {
    // #1137 Copilot review regression: subsequent fragments don't
    // carry the L4 header, so tcp_flags is meaningless. Without the
    // outer `!is_fragment || is_first_fragment` guard, a subsequent
    // fragment with tcp_flags=0 (because the meta wasn't filled)
    // would falsely trip SCREEN_TCP_NO_FLAG. Mirrors the BPF #853
    // defense.
    let mut profile = ScreenProfile::default();
    profile.no_flag = true;
    let mut state = make_state("trust", profile);
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        12345,
        80,
        0, // tcp_flags=0 on a subsequent fragment is normal — meta wasn't filled
    );
    pkt.is_fragment = true;
    pkt.is_first_fragment = false;
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Pass,
        "subsequent fragment must not trip TCP_NO_FLAG even with tf=0"
    );
}

#[test]
fn tcp_syn_fin_passes_on_subsequent_fragment_with_syn_fin_bytes() {
    // Adversarial: subsequent fragment whose payload bytes happen to
    // look like SYN+FIN. The outer guard must keep this from tripping
    // syn_fin (the bytes aren't real TCP flags).
    let mut profile = ScreenProfile::default();
    profile.syn_fin = true;
    let mut state = make_state("trust", profile);
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        12345,
        80,
        TCP_SYN | TCP_FIN,
    );
    pkt.is_fragment = true;
    pkt.is_first_fragment = false;
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// IP source route
// ================================================================

#[test]
fn source_route_drops() {
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    pkt.ip_ihl = 6; // Options present (IHL > 5)
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("ip-source-route")
    );
}

#[test]
fn source_route_ipv6_ignored() {
    let mut state = make_state("trust", default_profile());
    let mut pkt = tcp_pkt(
        IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        1234,
        80,
        TCP_SYN,
    );
    pkt.ip_ihl = 6; // IPv6 doesn't use IHL, should be ignored
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// Normal packets pass all checks
// ================================================================

#[test]
fn normal_tcp_syn_passes() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn normal_tcp_established_passes() {
    let mut state = make_state("trust", default_profile());
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_ACK, // normal established traffic
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn normal_udp_passes() {
    let mut state = make_state("trust", default_profile());
    let pkt = udp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

#[test]
fn no_profile_passes() {
    let mut state = ScreenState::new();
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        80,
        80,
        TCP_SYN | TCP_FIN, // malicious but no profile
    );
    assert_eq!(state.check_packet("trust", &pkt, 1), ScreenVerdict::Pass);
}

// ================================================================
// Rate limiting: ICMP flood
// ================================================================

#[test]
fn icmp_flood_triggers() {
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = 3;
    let mut state = make_state("trust", profile);
    let pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    // First 3 pass
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    // 4th exceeds threshold
    assert_eq!(
        state.check_packet("trust", &pkt, 100),
        ScreenVerdict::Drop("icmp-flood")
    );
}

#[test]
fn icmp_flood_resets_on_new_window() {
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    // Exceeds in window 100
    assert_eq!(
        state.check_packet("trust", &pkt, 100),
        ScreenVerdict::Drop("icmp-flood")
    );
    // New window (101) resets
    assert_eq!(state.check_packet("trust", &pkt, 101), ScreenVerdict::Pass);
}

// ================================================================
// Rate limiting: UDP flood
// ================================================================

#[test]
fn udp_flood_triggers() {
    let mut profile = ScreenProfile::default();
    profile.udp_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let pkt = udp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
    );
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(
        state.check_packet("trust", &pkt, 100),
        ScreenVerdict::Drop("udp-flood")
    );
}

// ================================================================
// Rate limiting: SYN flood
// ================================================================

#[test]
fn syn_flood_triggers() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(
        state.check_packet("trust", &pkt, 100),
        ScreenVerdict::Drop("syn-flood")
    );
}

#[test]
fn syn_flood_ignores_syn_ack() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    let mut state = make_state("trust", profile);
    // SYN+ACK should not count toward SYN flood
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN | TCP_ACK,
    );
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
}

#[test]
fn syn_flood_disabled_passes() {
    let profile = ScreenProfile::default(); // threshold=0 means disabled
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        TCP_SYN,
    );
    for _ in 0..1000 {
        assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    }
}

// ================================================================
// SYN cookie core (#1374)
// ================================================================

fn syn_cookie_codec() -> SynCookieCodec {
    SynCookieCodec::new(syn_cookie_key())
}

fn syn_cookie_key() -> [u8; 16] {
    [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f,
    ]
}

fn syn_cookie_tuple() -> SynCookieTuple {
    SynCookieTuple {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        src_port: 49152,
        dst_port: 443,
    }
}

#[test]
fn siphash24_matches_reference_vectors() {
    // SipHash-2-4 reference vectors for key bytes 00..0f and message bytes
    // 00..len. These pin the private implementation used by the cookie MAC.
    let k0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
    let k1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);
    let vectors = [
        (0usize, 0x726f_db47_dd0e_0e31u64),
        (1, 0x74f8_39c5_93dc_67fdu64),
        (8, 0x93f5_f579_9a93_2462u64),
        (15, 0xa129_ca61_49be_45e5u64),
    ];

    for (len, expected) in vectors {
        let mut sip = SipHash24::new(k0, k1);
        let bytes: Vec<u8> = (0..len as u8).collect();
        sip.write_bytes(&bytes);
        assert_eq!(sip.finish(), expected, "SipHash-2-4 vector length {len}");
    }
}

#[test]
fn syn_cookie_layout_fills_tcp_isn() {
    assert_eq!(SYN_COOKIE_LAYOUT_BITS, SYN_COOKIE_ISN_BITS);
    assert_eq!(SYN_COOKIE_EPOCH_SHIFT, 27);
    assert_eq!(SYN_COOKIE_MSS_SHIFT, 24);
}

#[test]
fn syn_cookie_tuple_from_packet_matches_packet_flow() {
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(SynCookieTuple::from_packet(&pkt), syn_cookie_tuple());
}

#[test]
fn syn_cookie_mint_validate_roundtrip() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();
    let cookie = codec.mint_isn(tuple, 7, 42, 1460);
    let validation = codec
        .validate_isn(tuple, 7, 42, cookie)
        .expect("fresh cookie should validate");

    assert_eq!(validation.full_epoch, 42);
    assert_eq!(validation.mss_index, 6);
    assert_eq!(validation.mss, 1460);
    assert_eq!(
        (cookie >> SYN_COOKIE_EPOCH_SHIFT) & SYN_COOKIE_EPOCH_MASK,
        10
    );
}

#[test]
fn syn_cookie_validate_rejects_modified_tuple() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();
    let cookie = codec.mint_isn(tuple, 7, 42, 1460);

    let mut mutated = tuple;
    mutated.src_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    assert!(codec.validate_isn(mutated, 7, 42, cookie).is_none());

    mutated = tuple;
    mutated.dst_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 21));
    assert!(codec.validate_isn(mutated, 7, 42, cookie).is_none());

    mutated = tuple;
    mutated.src_port += 1;
    assert!(codec.validate_isn(mutated, 7, 42, cookie).is_none());

    mutated = tuple;
    mutated.dst_port += 1;
    assert!(codec.validate_isn(mutated, 7, 42, cookie).is_none());

    assert!(codec.validate_isn(tuple, 8, 42, cookie).is_none());
}

#[test]
fn syn_cookie_validate_rejects_stale_secret() {
    let codec = syn_cookie_codec();
    let stale_codec = SynCookieCodec::new([
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ]);
    let tuple = syn_cookie_tuple();
    let cookie = codec.mint_isn(tuple, 7, 42, 1460);

    assert!(stale_codec.validate_isn(tuple, 7, 42, cookie).is_none());
}

#[test]
fn syn_cookie_mss_index_encoding_parity() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();

    for (idx, mss) in SYN_COOKIE_MSS_VALUES.iter().copied().enumerate() {
        assert_eq!(SynCookieCodec::mss_index(mss), idx as u8);
        let cookie = codec.mint_isn(tuple, 7, 42, mss);
        assert_eq!(
            (cookie >> SYN_COOKIE_MSS_SHIFT) & SYN_COOKIE_MSS_MASK,
            idx as u32
        );
        assert_eq!(codec.validate_isn(tuple, 7, 42, cookie).unwrap().mss, mss);
    }

    assert_eq!(SynCookieCodec::mss_index(535), 0);
    assert_eq!(SynCookieCodec::mss_index(1459), 5);
    assert_eq!(SynCookieCodec::mss_index(9000), 7);

    let cookie = codec.mint_isn(tuple, 7, 42, 1460);
    let tampered_mss =
        (cookie & !(SYN_COOKIE_MSS_MASK << SYN_COOKIE_MSS_SHIFT)) | (5 << SYN_COOKIE_MSS_SHIFT);
    assert!(codec.validate_isn(tuple, 7, 42, tampered_mss).is_none());
}

#[test]
fn syn_cookie_epoch_uses_unix_wall_clock_units() {
    assert_eq!(SynCookieCodec::full_epoch_from_unix_secs(0), 0);
    assert_eq!(SynCookieCodec::full_epoch_from_unix_secs(63), 0);
    assert_eq!(SynCookieCodec::full_epoch_from_unix_secs(64), 1);
    assert_eq!(SynCookieCodec::full_epoch_from_unix_secs(64 * 33 + 9), 33);
}

#[test]
fn syn_cookie_wall_clock_epoch_survives_peer_uptime_skew() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();
    let shared_wall_epoch = SynCookieCodec::full_epoch_from_unix_secs(1_800_000_000);
    let peer_monotonic_epoch = 0;
    let cookie = codec.mint_isn(tuple, 7, shared_wall_epoch, 1460);

    assert_ne!(
        shared_wall_epoch, peer_monotonic_epoch,
        "test must model peers with unrelated monotonic uptimes"
    );
    assert!(
        codec
            .validate_isn(tuple, 7, shared_wall_epoch, cookie)
            .is_some(),
        "HA peers validate with the shared Unix wall-clock epoch"
    );
    assert!(
        codec
            .validate_isn(tuple, 7, peer_monotonic_epoch, cookie)
            .is_none(),
        "local monotonic uptime would reject the peer-minted cookie"
    );
}

#[test]
fn syn_cookie_epoch_low_bits_wrap_rejects_32_epoch_old_cookie() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();
    let old_epoch = 10;
    let current_epoch = old_epoch + 32;
    let cookie = codec.mint_isn(tuple, 7, old_epoch, 1460);

    assert_eq!(old_epoch & 0x1f, current_epoch & 0x1f);
    assert!(
        codec
            .validate_isn(tuple, 7, current_epoch, cookie)
            .is_none()
    );
}

#[test]
fn syn_cookie_validation_tries_next_current_and_previous_full_epoch() {
    let codec = syn_cookie_codec();
    let tuple = syn_cookie_tuple();
    let next_cookie = codec.mint_isn(tuple, 7, 43, 1460);
    let current_cookie = codec.mint_isn(tuple, 7, 42, 1460);
    let previous_cookie = codec.mint_isn(tuple, 7, 41, 1460);
    let older_cookie = codec.mint_isn(tuple, 7, 40, 1460);

    assert_eq!(
        codec
            .validate_isn(tuple, 7, 42, next_cookie)
            .expect("next epoch")
            .full_epoch,
        43
    );
    assert_eq!(
        codec
            .validate_isn(tuple, 7, 42, current_cookie)
            .expect("current epoch")
            .full_epoch,
        42
    );
    assert_eq!(
        codec
            .validate_isn(tuple, 7, 42, previous_cookie)
            .expect("previous epoch")
            .full_epoch,
        41
    );
    assert!(codec.validate_isn(tuple, 7, 42, older_cookie).is_none());
}

#[test]
fn syn_cookie_chosen_when_threshold_exceeded() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 2;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.set_syn_cookie_full_epoch_for_test(2);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &pkt, 128),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &pkt, 128),
        ScreenVerdict::Pass
    );
    let expected_isn =
        syn_cookie_codec().mint_isn(SynCookieTuple::from_packet(&pkt), 7, 2, pkt.tcp_mss);
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &pkt, 128),
        ScreenVerdict::SynCookieChallenge(SynCookieChallenge {
            cookie_isn: expected_isn,
            peer_mss: 1460,
        })
    );
}

#[test]
fn syn_cookie_without_published_secret_fails_closed() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    let pkt = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &pkt, 128),
        ScreenVerdict::Pass
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &pkt, 128),
        ScreenVerdict::Drop("syn-cookie-unavailable")
    );
}

#[test]
fn syn_cookie_ack_validation_marks_next_syn_bypass_without_session_creation() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.set_syn_cookie_full_epoch_for_test(1);
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    let challenge = match state.check_packet_with_zone_id("trust", 7, &syn, 128) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };

    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128),
        SynCookieAckVerdict::Validated
    );
    assert_eq!(state.syn_cookie_validated_len(), 1);

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::SynCookieBypass
    );
    assert_eq!(
        state.syn_cookie_validated_len(),
        0,
        "validated tuple is single-use"
    );
}

#[test]
fn syn_cookie_validated_syn_bypasses_flood_gate_and_passes() {
    // #2134: this test used to prove "a SYN-cookie-validated SYN still
    // runs the LATER screen checks" by asserting the session-limit drop
    // fires on the validated tuple. That check moved out of the screen
    // stage (it now enforces at the new-flow decision in
    // poll_descriptor), and the only remaining later stateful checks
    // (port-scan / ip-sweep) key on tuple-uniqueness — which conflicts
    // with the validated cache, that only bypasses the flood gate for the
    // EXACT validated tuple. So we prove the load-bearing property
    // directly: a cookie-validated SYN bypasses the SYN-flood gate and
    // traverses the rest of `check_packet_with_zone_id` to a clean Pass,
    // whereas the identical un-validated SYN is challenged at the gate.
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    // First SYN passes (under the SYN-flood threshold of 1).
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    // Second SYN crosses the SYN-flood threshold -> cookie challenge.
    let challenge = match state.check_packet_with_zone_id("trust", 7, &syn, 128) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };

    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128),
        SynCookieAckVerdict::Validated
    );

    // The client's next SYN (identical tuple), now cookie-validated,
    // bypasses the SYN-flood gate and runs to completion: SynCookieBypass
    // (a Pass-equivalent that records the bypass), NOT another challenge
    // or drop. The validated tuple is single-use, so the cache is empty
    // again afterwards.
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::SynCookieBypass
    );
    assert_eq!(state.syn_cookie_validated_len(), 0);
}

#[test]
fn syn_cookie_invalid_ack_does_not_validate_client() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.set_syn_cookie_full_epoch_for_test(1);
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    assert!(matches!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::SynCookieChallenge(_)
    ));

    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = 0xdead_beefu32;
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128),
        SynCookieAckVerdict::Invalid
    );
    assert_eq!(state.syn_cookie_validated_len(), 0);
}

#[test]
fn syn_cookie_ack_validates_on_peer_without_local_active_window() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;

    let mut peer = make_state("trust", profile);
    peer.update_syn_cookie_master_key(Some(syn_cookie_key()));
    peer.set_syn_cookie_full_epoch_for_test(41);

    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    let cookie_isn =
        syn_cookie_codec().mint_isn(SynCookieTuple::from_packet(&syn), 7, 41, syn.tcp_mss);

    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = cookie_isn.wrapping_add(1);

    assert_eq!(
        peer.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128),
        SynCookieAckVerdict::Validated,
        "HA backup must accept a peer-minted cookie without a local flood window"
    );
    assert_eq!(peer.syn_cookie_validated_len(), 1);
}

#[test]
fn syn_cookie_ack_validates_on_peer_one_epoch_behind_active() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;

    let mut standby = make_state("trust", profile);
    standby.update_syn_cookie_master_key(Some(syn_cookie_key()));
    standby.set_syn_cookie_full_epoch_for_test(40);

    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    let active_cookie =
        syn_cookie_codec().mint_isn(SynCookieTuple::from_packet(&syn), 7, 41, syn.tcp_mss);

    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_seq = 2;
    ack.tcp_ack = active_cookie.wrapping_add(1);

    assert_eq!(
        standby.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128),
        SynCookieAckVerdict::Validated,
        "standby one epoch behind must accept cookies minted by the former active"
    );
    assert_eq!(standby.syn_cookie_validated_len(), 1);
}

#[test]
fn syn_cookie_invalid_ack_without_active_window_remains_not_applicable() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;

    let mut peer = make_state("trust", profile);
    peer.update_syn_cookie_master_key(Some(syn_cookie_key()));
    peer.set_syn_cookie_full_epoch_for_test(41);

    let mut ack = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_ACK,
    );
    ack.tcp_seq = 2;
    ack.tcp_ack = 0xdead_beefu32;

    assert_eq!(
        peer.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128),
        SynCookieAckVerdict::NotApplicable,
        "inactive peers only consume ACKs that validate against the shared key"
    );
    assert_eq!(peer.syn_cookie_validated_len(), 0);
}

#[test]
fn syn_cookie_standby_ack_prefilter_skips_implausible_epoch_bits() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;

    let mut peer = make_state("trust", profile);
    peer.update_syn_cookie_master_key(Some(syn_cookie_key()));
    peer.set_syn_cookie_full_epoch_for_test(40);

    let mut ack = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_ACK,
    );
    let implausible_cookie =
        ((45u32 & SYN_COOKIE_EPOCH_MASK) << SYN_COOKIE_EPOCH_SHIFT) | 0x00ff_eeaa;
    ack.tcp_ack = implausible_cookie.wrapping_add(1);

    assert_eq!(
        peer.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128),
        SynCookieAckVerdict::NotApplicable,
        "inactive peers should reject ACKs outside the epoch window before MAC work"
    );
    assert_eq!(
        peer.syn_cookie_standby_ack_count("trust"),
        0,
        "wire-epoch prefilter must not spend standby validation budget"
    );
}

#[test]
fn syn_cookie_standby_ack_validation_is_rate_limited() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;

    let mut peer = make_state("trust", profile);
    peer.update_syn_cookie_master_key(Some(syn_cookie_key()));
    peer.set_syn_cookie_full_epoch_for_test(41);

    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );
    let mut bad_ack = syn.clone();
    bad_ack.tcp_flags = TCP_ACK;
    bad_ack.tcp_seq = 2;
    bad_ack.tcp_ack =
        (((41u32 & SYN_COOKIE_EPOCH_MASK) << SYN_COOKIE_EPOCH_SHIFT) | 0x1234).wrapping_add(1);

    for _ in 0..SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC {
        assert_eq!(
            peer.validate_syn_cookie_ack_on_session_miss("trust", 7, &bad_ack, 128),
            SynCookieAckVerdict::NotApplicable
        );
    }
    assert_eq!(
        peer.syn_cookie_standby_ack_count("trust"),
        SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC
    );

    let valid_cookie =
        syn_cookie_codec().mint_isn(SynCookieTuple::from_packet(&syn), 7, 41, syn.tcp_mss);
    let mut valid_ack = syn.clone();
    valid_ack.tcp_flags = TCP_ACK;
    valid_ack.tcp_seq = 3;
    valid_ack.tcp_ack = valid_cookie.wrapping_add(1);

    assert_eq!(
        peer.validate_syn_cookie_ack_on_session_miss("trust", 7, &valid_ack, 128),
        SynCookieAckVerdict::NotApplicable,
        "standby validation budget should cap SipHash work for the current second"
    );
    assert_eq!(peer.syn_cookie_validated_len(), 0);

    assert_eq!(
        peer.validate_syn_cookie_ack_on_session_miss("trust", 7, &valid_ack, 129),
        SynCookieAckVerdict::Validated,
        "the standby guard is per-second and recovers on the next window"
    );
    assert_eq!(peer.syn_cookie_validated_len(), 1);
}

#[test]
fn syn_cookie_ack_fin_is_invalid_while_cookie_mode_is_active() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    let challenge = match state.check_packet_with_zone_id("trust", 7, &syn, 128) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };

    let mut ack_fin = syn.clone();
    ack_fin.tcp_flags = TCP_ACK | TCP_FIN;
    ack_fin.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack_fin, 128),
        SynCookieAckVerdict::Invalid
    );
    assert_eq!(state.syn_cookie_validated_len(), 0);
}

#[test]
fn syn_cookie_validated_cache_is_bounded() {
    let mut cache = SynCookieValidatedCache::new(4, 64);
    assert_eq!(cache.capacity(), 4);

    let mut tuple = syn_cookie_tuple();
    for port in 40000..40032 {
        tuple.src_port = port;
        cache.insert(7, tuple, 100);
    }

    assert_eq!(cache.len(), 4);
    let mut evicted = syn_cookie_tuple();
    evicted.src_port = 40000;
    assert!(!cache.take_valid(7, evicted, 100));
    evicted.src_port = 40027;
    assert!(!cache.take_valid(7, evicted, 100));

    let mut retained = syn_cookie_tuple();
    retained.src_port = 40028;
    assert!(cache.take_valid(7, retained, 100));
    retained.src_port = 40031;
    assert!(cache.take_valid(7, retained, 100));
}

#[test]
fn syn_cookie_validated_cache_index_is_keyed() {
    let mut left = SynCookieValidatedCache::new(64, 64);
    left.set_hash_keys([0x1111_2222_3333_4444, 0x5555_6666_7777_8888]);
    let mut right = SynCookieValidatedCache::new(64, 64);
    right.set_hash_keys([0x9999_aaaa_bbbb_cccc, 0xdddd_eeee_ffff_0000]);

    let mut tuple = syn_cookie_tuple();
    let differs = (0..1024).any(|offset| {
        tuple.src_port = 30000 + offset;
        left.debug_set_index(7, tuple) != right.debug_set_index(7, tuple)
    });

    assert!(
        differs,
        "cache slot selection must be keyed rather than attacker-predictable"
    );
}

#[test]
fn syn_cookie_invalid_ack_flood_does_not_grow_validated_cache() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    assert!(matches!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::SynCookieChallenge(_)
    ));

    for offset in 0..1024 {
        let mut ack = syn.clone();
        ack.tcp_flags = TCP_ACK;
        ack.src_port = 30000 + offset;
        ack.tcp_ack = 0xdead_0000u32.wrapping_add(offset as u32);
        assert_eq!(
            state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128),
            SynCookieAckVerdict::Invalid
        );
    }

    assert_eq!(state.syn_cookie_validated_len(), 0);
}

#[test]
fn syn_cookie_master_key_rotation_clears_validated_cache() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::Pass
    );
    let challenge = match state.check_packet_with_zone_id("trust", 7, &syn, 128) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };
    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128),
        SynCookieAckVerdict::Validated
    );
    assert_eq!(state.syn_cookie_validated_len(), 1);

    state.update_syn_cookie_master_key(None);

    assert_eq!(state.syn_cookie_validated_len(), 0);
}

#[test]
fn update_profiles_prepopulates_syn_cookie_active_state() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile.clone());
    assert_eq!(state.syn_cookie_active_zone_count(), 1);

    let mut profiles = FxHashMap::default();
    profiles.insert("trust".to_string(), profile.clone());
    profiles.insert("untrust".to_string(), profile);
    state.update_profiles(profiles);
    assert_eq!(state.syn_cookie_active_zone_count(), 2);

    state.update_profiles(FxHashMap::default());
    assert_eq!(state.syn_cookie_active_zone_count(), 0);
}

#[test]
fn syn_cookie_validated_cache_refresh_extends_ttl() {
    let mut cache = SynCookieValidatedCache::new(4, 10);
    let tuple_refreshed = syn_cookie_tuple();
    let mut tuple_old = syn_cookie_tuple();
    tuple_old.src_port += 1;
    cache.insert(7, tuple_refreshed, 100);
    cache.insert(7, tuple_old, 100);
    cache.insert(7, tuple_refreshed, 109);
    assert!(!cache.take_valid(7, tuple_old, 110));
    assert!(cache.take_valid(7, tuple_refreshed, 110));
}

#[test]
fn syn_cookie_validated_cache_expires_on_ttl_boundary() {
    let mut cache = SynCookieValidatedCache::new(4, SynCookieCodec::EPOCH_SECS);
    let tuple = syn_cookie_tuple();

    cache.insert(7, tuple, 128);
    assert!(
        cache.take_valid(7, tuple, 191),
        "entry should remain valid until just before the 64s TTL boundary"
    );

    cache.insert(7, tuple, 128);
    assert!(
        !cache.take_valid(7, tuple, 192),
        "entry expires at insertion time + one cookie epoch"
    );
}

#[test]
fn syn_cookie_ack_validation_accepts_previous_epoch_after_rotation() {
    let mut profile = ScreenProfile::default();
    profile.syn_flood_threshold = 1;
    profile.syn_cookie = true;
    let mut state = make_state("trust", profile);
    state.update_syn_cookie_master_key(Some(syn_cookie_key()));
    state.set_syn_cookie_full_epoch_for_test(1);
    let syn = tcp_pkt(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        49152,
        443,
        TCP_SYN,
    );

    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 127),
        ScreenVerdict::Pass
    );
    let challenge = match state.check_packet_with_zone_id("trust", 7, &syn, 127) {
        ScreenVerdict::SynCookieChallenge(challenge) => challenge,
        other => panic!("expected SYN-cookie challenge, got {other:?}"),
    };

    let mut ack = syn.clone();
    ack.tcp_flags = TCP_ACK;
    ack.tcp_ack = challenge.cookie_isn.wrapping_add(1);
    state.set_syn_cookie_full_epoch_for_test(2);
    assert_eq!(
        state.validate_syn_cookie_ack_on_session_miss("trust", 7, &ack, 128),
        SynCookieAckVerdict::Validated,
        "ACK after the epoch tick must validate against the previous full epoch"
    );
    assert_eq!(
        state.check_packet_with_zone_id("trust", 7, &syn, 128),
        ScreenVerdict::SynCookieBypass
    );
}

// ================================================================
// Profile update
// ================================================================

#[test]
fn update_profiles_clears_stale_counters() {
    let mut profile = ScreenProfile::default();
    profile.icmp_flood_threshold = 2;
    let mut state = make_state("trust", profile);
    let pkt = icmp_pkt(
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        84,
    );
    // Fill up counter
    state.check_packet("trust", &pkt, 100);
    state.check_packet("trust", &pkt, 100);

    // Update profiles for a different zone — trust counter should be removed
    let mut new_profiles = FxHashMap::default();
    let mut new_profile = ScreenProfile::default();
    new_profile.icmp_flood_threshold = 2;
    new_profiles.insert("untrust".to_string(), new_profile);
    state.update_profiles(new_profiles);

    // trust zone no longer has a profile — all packets pass
    assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
}

// ================================================================
// extract_screen_info
// ================================================================

#[test]
fn extract_info_from_ipv4_frame() {
    // Build a minimal IPv4 frame: 14 bytes Ethernet + 20 bytes IP header
    let mut frame = vec![0u8; 34];
    // IP header at offset 14
    frame[14] = 0x45; // version=4, ihl=5
    frame[16] = 0x00; // total_len high
    frame[17] = 20; // total_len low = 20
    frame[20] = 0x20; // flags=MF, offset=0
    frame[21] = 0x00;

    let info = extract_screen_info(
        &frame,
        libc::AF_INET as u8,
        PROTO_TCP,
        TCP_SYN,
        34,
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
        1234,
        80,
        14,
    )
    .expect("valid IPv4 frame parses");

    assert_eq!(info.ip_ihl, 5);
    assert_eq!(info.ip_total_len, 20);
    assert!(info.is_fragment); // MF bit set
    assert_eq!(info.protocol, PROTO_TCP);
}

// ================================================================
// Per-IP session limits — #2134: enforcement + lifecycle now live in
// `session::SessionTable` (count maintained at the install/remove sinks,
// checked at the new-flow decision in poll_descriptor). The screen stage
// no longer evaluates the per-IP count. End-to-end enforcement, the
// established-flow no-self-drop regression, evict-on-zero (#2128), the
// HA promote/demote count sites, the differential invariant, and
// clear-on-disable are covered by `session/tests.rs`
// (`session_limit_*`). The obsolete ScreenState-resident tests that
// drove the now-retired `session_created`/`session_expired` mutators
// were removed here.
// ================================================================

// ================================================================
// Port scan detection
// ================================================================

// NOTE (#2210): scan/sweep detection moved OFF the per-packet
// `check_packet` pre-session stage and onto the NEW-FLOW / session-MISS
// hook `scan_sweep_drop_on_new_flow`. These tests drive that hook (the
// caller in `poll_descriptor` only reaches it on a session miss, which is
// what gives established flows their immunity). `ZID` is an arbitrary but
// fixed zone id; the per-zone keying is exercised in
// `screen::scan::scan_tests` and `scan_sweep_per_zone_no_cross_count`.
const ZID: u16 = 7;

#[test]
fn port_scan_detected() {
    let mut profile = ScreenProfile::default();
    profile.port_scan_threshold = 3;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));

    // First 3 unique ports pass
    for port in [80, 443, 8080] {
        let pkt = tcp_pkt(src, dst, 1234, port, TCP_SYN);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, 100),
            None,
            "port {} should pass",
            port,
        );
    }

    // 4th unique port triggers port scan
    let pkt = tcp_pkt(src, dst, 1234, 22, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, 100),
        Some("port-scan")
    );
}

#[test]
fn port_scan_resets_on_window_expiry() {
    let mut profile = ScreenProfile::default();
    profile.port_scan_threshold = 2;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));

    // Fill up in window at time=100
    let pkt1 = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
    let pkt2 = tcp_pkt(src, dst, 1234, 443, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt1, 100),
        None
    );
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt2, 100),
        None
    );

    // 3rd port triggers at time=100
    let pkt3 = tcp_pkt(src, dst, 1234, 22, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt3, 100),
        Some("port-scan")
    );

    // After window expires (default 10s), should pass again
    let pkt4 = tcp_pkt(src, dst, 1234, 8080, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt4, 111),
        None
    );
}

#[test]
fn port_scan_only_on_syn() {
    let mut profile = ScreenProfile::default();
    profile.port_scan_threshold = 1;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));

    // ACK packets (a session-miss ACK still reaches the hook, but
    // port-scan is SYN-only) should not trigger port scan. (IP-sweep on a
    // miss ACK is a separate, intended count — threshold is 0 here so it
    // never fires.)
    for port in [80, 443, 8080, 22] {
        let pkt = tcp_pkt(src, dst, 1234, port, TCP_ACK);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, 100),
            None
        );
    }
}

// ================================================================
// IP sweep detection
// ================================================================

#[test]
fn ip_sweep_detected() {
    let mut profile = ScreenProfile::default();
    profile.ip_sweep_threshold = 3;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));

    // First 3 unique destinations pass
    for i in 1..=3u8 {
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, i));
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, 100),
            None
        );
    }

    // 4th unique destination triggers IP sweep
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 4));
    let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, 100),
        Some("ip-sweep")
    );
}

#[test]
fn ip_sweep_resets_on_window_expiry() {
    let mut profile = ScreenProfile::default();
    profile.ip_sweep_threshold = 2;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));

    // Fill up window at time=100
    for i in 1..=2u8 {
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, i));
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, 100),
            None
        );
    }

    // 3rd triggers
    let dst3 = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 3));
    let pkt3 = tcp_pkt(src, dst3, 1234, 80, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt3, 100),
        Some("ip-sweep")
    );

    // After window expires (default 10s), passes again
    let dst4 = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 4));
    let pkt4 = tcp_pkt(src, dst4, 1234, 80, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt4, 111),
        None
    );
}

#[test]
fn ip_sweep_works_with_udp() {
    let mut profile = ScreenProfile::default();
    profile.ip_sweep_threshold = 2;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));

    for i in 1..=2u8 {
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, i));
        let mut pkt = udp_pkt(src, dst);
        pkt.dst_ip = dst;
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, 100),
            None
        );
    }

    // 3rd triggers
    let dst3 = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 3));
    let mut pkt3 = udp_pkt(src, dst3);
    pkt3.dst_ip = dst3;
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt3, 100),
        Some("ip-sweep")
    );
}

// ================================================================
// #2210: established (session-hit) traffic must NOT count toward sweep.
// #2209: per-zone keying + bounded state + no per-packet profile clone.
// ================================================================

/// #2210 fail-on-revert: the per-packet `check_packet` pre-session stage
/// must NOT touch the sweep/scan trackers. If the scan/sweep mutation were
/// (re)added back to `check_packet` (the pre-#2210 bug), this would drop on
/// the 3rd packet. Established flows are session HITS in production and
/// never reach the miss hook, so the only way they could inflate the sweep
/// counter is via `check_packet` — which this asserts they do not.
#[test]
fn established_traffic_does_not_count_toward_sweep_via_check_packet() {
    let mut profile = ScreenProfile::default();
    profile.ip_sweep_threshold = 2;
    profile.port_scan_threshold = 2;
    let mut state = make_state("trust", profile);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    // A high-fan-out established client: ACKs to many destinations on many
    // ports. None of these are SYNs; in production they would be session
    // hits. `check_packet` must pass every one — sweep is NOT evaluated
    // here anymore.
    for i in 1..=10u8 {
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, i));
        let pkt = tcp_pkt(src, dst, 1234, 1000 + i as u16, TCP_ACK);
        assert_eq!(
            state.check_packet("trust", &pkt, 100),
            ScreenVerdict::Pass,
            "established ACK to dst .{} must not count toward sweep on the pre-session stage",
            i
        );
    }
    // And a genuine new-flow sweep still fires on the miss hook.
    for i in 1..=2u8 {
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 3, i));
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, 100),
            None
        );
    }
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 3, 3));
    let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, 100),
        Some("ip-sweep")
    );
}

/// #2209 fail-on-revert: scan/sweep state is per-zone. The SAME source
/// sweeping zone A must not push zone B over its threshold. A global
/// tracker (the pre-#2209 bug) would have zone B already at zone A's count.
#[test]
fn scan_sweep_per_zone_no_cross_count() {
    let mut state = ScreenState::new();
    let mut profiles = FxHashMap::default();
    let mut a = ScreenProfile::default();
    a.ip_sweep_threshold = 2;
    let mut b = ScreenProfile::default();
    b.ip_sweep_threshold = 2;
    profiles.insert("zoneA".to_string(), a);
    profiles.insert("zoneB".to_string(), b);
    state.update_profiles(profiles);

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    // Source sweeps zoneA: two unique dsts (no drop yet).
    for i in 1..=2u8 {
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, i));
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("zoneA", 1, &pkt, 100),
            None
        );
    }
    // Same source in zoneB starts fresh — two unique dsts still pass.
    for i in 1..=2u8 {
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 9, i));
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("zoneB", 2, &pkt, 100),
            None,
            "zoneB must not inherit zoneA's sweep history for the same source",
        );
    }
    // zoneB's 3rd unique dst crosses zoneB's own threshold.
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 9, 3));
    let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
    assert_eq!(
        state.scan_sweep_drop_on_new_flow("zoneB", 2, &pkt, 100),
        Some("ip-sweep")
    );
}

/// #2209 fail-on-revert: a per-packet profile CLONE on the screen hot path
/// would defeat the perf fix. `ScreenProfile` is not `Copy` and the
/// production `check_packet_with_zone_id` borrows it. We assert the type is
/// NOT `Copy` (so an accidental `Clone`-by-value reintroduction is a visible
/// `.clone()` in review) and exercise the borrow-only path heavily to prove
/// it compiles and runs without a per-call clone. (A `Copy` profile would
/// silently hide a per-packet copy; keeping it non-Copy keeps the cost
/// auditable.)
#[test]
fn screen_profile_is_not_copy_so_per_packet_copies_stay_auditable() {
    // REAL negative-Copy guard (#2227 MINOR-3): autoref specialization.
    // `IsCopy::is_copy` (the inherent method on the `Witness<T>` wrapper) is
    // selected ONLY when `T: Copy`; otherwise method resolution autorefs to
    // the `NotCopy` trait's `is_copy(&self)`. So the returned flag is `true`
    // iff `ScreenProfile: Copy`. A test (not just a compile gate) lets this
    // FAIL-ON-REVERT loudly if someone makes `ScreenProfile` `Copy` — which
    // would silently hide a per-packet copy on the screen hot path.
    struct Witness<T>(core::marker::PhantomData<T>);
    trait NotCopy {
        fn is_copy(&self) -> bool {
            false
        }
    }
    impl<T> NotCopy for Witness<T> {}
    impl<T: Copy> Witness<T> {
        fn is_copy(&self) -> bool {
            true
        }
    }
    assert!(
        !Witness::<ScreenProfile>(core::marker::PhantomData).is_copy(),
        "ScreenProfile must NOT be Copy — a Copy profile silently hides a \
         per-packet copy on the screen hot path (#2209 perf invariant)"
    );
    // Sanity: the witness reports `true` for a genuinely-Copy type, proving
    // the negative assertion above is discriminating (not vacuously false).
    assert!(
        Witness::<u32>(core::marker::PhantomData).is_copy(),
        "witness must detect a Copy type"
    );

    // Drive the borrow-only hot path many times; this would not compile if
    // the body still required a `self.profiles.get(zone).clone()` and we had
    // removed Clone — and it documents the no-clone invariant.
    let mut profile = ScreenProfile::default();
    profile.land = true;
    let mut state = make_state("trust", profile);
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    for _ in 0..1000 {
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        assert_eq!(state.check_packet("trust", &pkt, 100), ScreenVerdict::Pass);
    }
}

/// #2209 fail-on-revert (bounded + not-fail-open at the `ScreenState`
/// level): a spoofed-source flood through the new-flow hook cannot grow the
/// tracker without bound and never fail-opens the drop.
#[test]
fn scan_sweep_state_bounded_and_records_pressure() {
    let mut profile = ScreenProfile::default();
    profile.ip_sweep_threshold = 1_000_000; // never trips by detection
    let mut state = make_state("trust", profile);

    assert_eq!(state.scan_sweep_skipped_pressure(), 0);
    // Far more distinct sources than the per-zone cap.
    for i in 0..(super::scan::max_sources_per_zone_for_test() + 200) {
        let src = IpAddr::V4(Ipv4Addr::from(0x0a00_0000u32 + i as u32));
        let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        // Must never return a drop reason from overflow (no fail-open).
        assert_eq!(
            state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, 100),
            None
        );
    }
    assert!(
        state.scan_sweep_skipped_pressure() >= 200,
        "over-cap sources must record pressure, got {}",
        state.scan_sweep_skipped_pressure()
    );
}

/// #2227 MAJOR-1 fail-on-revert (at the production `ScreenState` hook): an
/// IP-sweep configured with a threshold ABOVE the per-source unique cap
/// (3000 — a value `pkg/config` parses and stores unchanged) must STILL fire
/// detection. Pre-fix the dataplane compared `set.len() > threshold` and
/// `len()` could never exceed `MAX_UNIQUE_PER_SOURCE` (1024 < 3000), so the
/// scanner was NEVER dropped (silent fail-OPEN). The fail-closed clamp makes a
/// saturated set always cross the effective threshold, and the clamp is
/// recorded for observability.
#[test]
fn ip_sweep_above_unique_cap_still_fires_at_screen_state() {
    let mut profile = ScreenProfile::default();
    // 3000 mirrors parser_security_test.go's TestScreenCompilation and exceeds
    // MAX_UNIQUE_PER_SOURCE — the exact case the reviewer reproduced.
    profile.ip_sweep_threshold = 3000;
    let mut state = make_state("trust", profile);
    let cap = super::scan::max_unique_per_source_for_test();
    assert!(
        3000 > cap,
        "test premise: configured threshold (3000) must exceed the cap ({cap})"
    );

    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let mut fired = false;
    // Sweep more distinct destinations than the cap from the same source.
    for i in 0..(cap + 50) {
        let dst = IpAddr::V4(Ipv4Addr::from(0xac10_0000u32 + i as u32)); // 172.16.x.x
        let pkt = tcp_pkt(src, dst, 1234, 80, TCP_SYN);
        if state.scan_sweep_drop_on_new_flow("trust", ZID, &pkt, 100) == Some("ip-sweep") {
            fired = true;
            break;
        }
    }
    assert!(
        fired,
        "ip-sweep threshold 3000 (> cap {cap}) must fire — pre-fix it NEVER fired (fail-open)"
    );
    assert!(
        state.scan_sweep_threshold_clamped() >= 1,
        "an over-cap threshold must be recorded as clamped, got {}",
        state.scan_sweep_threshold_clamped()
    );
}
