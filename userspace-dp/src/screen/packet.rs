//! Shared per-packet types and protocol/flag constants used by the
//! screen submodules. Hosting these in a dedicated sibling avoids
//! cross-module re-export hops between `stateless.rs`, `extract.rs`,
//! `syncookie.rs`, and `mod.rs`.
//!
//! No runtime behavior lives here — only data definitions.

use std::net::IpAddr;

use super::syncookie::SynCookieChallenge;

pub(super) const PROTO_TCP: u8 = 6;
pub(super) const PROTO_UDP: u8 = 17;
pub(super) const PROTO_ICMP: u8 = 1;
pub(super) const PROTO_ICMPV6: u8 = 58;

// TCP flag bits (matching BPF layout: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20)
pub(super) const TCP_FIN: u8 = 0x01;
pub(super) const TCP_SYN: u8 = 0x02;
pub(super) const TCP_RST: u8 = 0x04;
pub(super) const TCP_ACK: u8 = 0x10;
pub(super) const TCP_URG: u8 = 0x20;

/// Parsed packet fields needed for screen checks.
/// Extracted from raw packet bytes for speed — no allocations.
#[derive(Debug, Clone)]
pub(crate) struct ScreenPacketInfo {
    pub addr_family: u8, // AF_INET=2, AF_INET6=10
    pub protocol: u8,    // IPPROTO_*
    pub tcp_flags: u8,   // TCP flags byte
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16, // host byte order
    pub dst_port: u16, // host byte order
    pub tcp_seq: u32,
    pub tcp_ack: u32,
    pub tcp_mss: u16,
    pub pkt_len: u16, // total packet length from meta
    pub is_fragment: bool,
    /// #1137: 1 = first fragment of a fragmented datagram (IPv4: MF=1
    /// && offset==0; IPv6: MF=1 && offset==0). Mirrors the BPF
    /// `is_first_fragment` flag in pkt_meta. `is_fragment=1 &&
    /// is_first_fragment=0` indicates a subsequent fragment.
    pub is_first_fragment: bool,
    pub ip_ihl: u8,        // IPv4 IHL field (header length in 32-bit words)
    pub ip_frag_off: u16,  // raw frag_off field (network byte order already parsed)
    pub ip_total_len: u16, // IPv4 total length
}

/// Screen profile configuration for a zone. Mirrors the BPF `screen_config`.
#[derive(Clone, Debug, Default)]
pub(crate) struct ScreenProfile {
    pub land: bool,
    pub syn_fin: bool,
    pub no_flag: bool,
    pub fin_no_ack: bool,
    pub winnuke: bool,
    pub ping_death: bool,
    pub teardrop: bool,
    pub icmp_fragment: bool,
    /// #1137: TCP SYN on a first-fragment is the fragmentation-based
    /// attack pattern. Mirrors the BPF SCREEN_SYN_FRAG (#866) on the
    /// userspace dataplane path.
    pub syn_frag: bool,
    pub source_route: bool,
    pub icmp_flood_threshold: u32, // packets per second, 0 = disabled
    pub udp_flood_threshold: u32,  // packets per second, 0 = disabled
    pub syn_flood_threshold: u32,  // SYN packets per second per zone, 0 = disabled
    /// Enable SYN-cookie challenge/validation behavior for SYN flood threshold
    /// crossings. Defaults false so rate-based SYN flood behavior remains a
    /// plain drop until the control plane explicitly enables cookie mode.
    pub syn_cookie: bool,
    pub session_limit_src: u32, // max sessions per source IP, 0 = disabled
    pub session_limit_dst: u32, // max sessions per destination IP, 0 = disabled
    pub port_scan_threshold: u32, // unique dst ports per src IP within window, 0 = disabled
    pub ip_sweep_threshold: u32, // unique dst IPs per src IP within window, 0 = disabled
}

/// Result of a screen check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScreenVerdict {
    Pass,
    SynCookieBypass,
    Drop(&'static str),
    SynCookieChallenge(SynCookieChallenge),
}
