//! Shared per-packet types and protocol/flag constants used by the
//! screen submodules. Hosting these in a dedicated sibling avoids
//! cross-module re-export hops between `stateless.rs`, `extract.rs`,
//! `syncookie.rs`, and `mod.rs`.
//!
//! No runtime behavior lives here — only data definitions.

use std::net::IpAddr;

use super::syncookie::SynCookieChallenge;

pub(super) use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};

// TCP flag bits (#2151: re-exported from the shared crate::tcp_flags SSOT;
// values match the wire layout FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08
// ACK=0x10 URG=0x20). Re-exported at `pub(super)` so the screen
// submodules keep importing them via `packet::TCP_*`.
pub(super) use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, TCP_URG};

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
    /// #2293: IPv6 payload-length field (bytes 4-5 of the base header),
    /// i.e. the length of everything after the 40-byte fixed header
    /// (extension headers + L4 + data). 0 for IPv4 / when not parsed.
    /// Used by the IPv6 ping-of-death check together with `frag_data_off`.
    pub ip_payload_len: u16,
    /// #2293: for an IPv6 fragment, the number of payload-region bytes
    /// (after the 40-byte base header) that precede THIS fragment's data
    /// — i.e. the extension headers up to and including the 8-byte
    /// fragment header. `ip_payload_len - frag_data_off` is therefore the
    /// L4/data bytes this fragment contributes to the reassembled
    /// datagram. 0 when there is no fragment header.
    pub frag_data_off: u16,
    /// #2973: an actual IPv4 source-route option (LSRR=131 or SSRR=137)
    /// was found in the IPv4 options region. The `source-route` screen
    /// drops ONLY when this is set, not on every IHL>5 packet — benign
    /// options (router-alert, record-route, timestamp, security) no
    /// longer trigger a false `ip-source-route` drop.
    pub saw_ipv4_source_route: bool,
    /// #2973: an IPv6 Routing Header (next-header 43) carrying a
    /// source-route routing type was found in the extension-header
    /// chain. The `source-route` screen drops on this for IPv6 parity
    /// with the IPv4 LSRR/SSRR detection. Type-0 (RH0, the deprecated
    /// source-route routing type) and the legacy/experimental type-1
    /// are treated as source routing; type-2 (Mobile IPv6) and other
    /// non-source-route types do not set this.
    pub saw_ipv6_routing_header: bool,
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
    /// #3315: SYN-flood sub-thresholds (SYN/s; 0 = disabled). `syn_flood_alarm`
    /// is the log-only rate (below attack-threshold) that raises an out-of-band
    /// alarm event without dropping. `syn_flood_dst`/`syn_flood_src` are the
    /// per-destination-IP / per-source-IP caps enforced by the per-zone
    /// `SynRateSketch` count-min sketch (per-dest primary/spoof-resistant,
    /// per-source secondary and gated to the non-cookie-active regime).
    pub syn_flood_alarm_threshold: u32,
    pub syn_flood_dst_threshold: u32,
    pub syn_flood_src_threshold: u32,
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

/// Reason an L3 header could not be parsed far enough to evaluate the
/// screen checks. Any variant means the extractor could NOT prove the
/// packet is benign for the fragment/TCP screens, so the caller MUST
/// fail CLOSED (drop) rather than admit a frame whose fragmentation or
/// L4 flags it was unable to read (#2146).
///
/// The legacy BPF `parse_ipv6hdr` returned `-1` on the same condition,
/// which dropped the frame earlier in the (now-retired #1373/#1476)
/// pipeline. With no upstream BPF screen path left, the extractor is
/// the only place that can enforce the defense.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScreenParseError {
    /// The IPv6 extension-header chain was truncated before the walk
    /// could reach the upper-layer (or FRAGMENT) header — the frame is
    /// too short to contain the headers its own chaining claims. A
    /// SYN-bearing frame with a truncated FRAGMENT header would
    /// otherwise leave `is_first_fragment=false` and silently bypass
    /// the `syn-frag` screen.
    TruncatedIpv6ExtChain,
}

impl ScreenParseError {
    /// Stable screen-drop reason string for the fail-closed verdict.
    /// Mapped to `SCREEN_IP_MALFORMED` (1<<18) in the event-emit reason
    /// table (`screen_reason_id`). The Go ring-buffer decoder has no
    /// dedicated name for this flag, so it decodes via the generic
    /// `screen(0x%x)` fallback in `pkg/logging/ringbuf.go` — same as the
    /// unmapped `icmp-fragment` (1<<17) flag.
    #[inline]
    pub(crate) fn screen_reason(self) -> &'static str {
        match self {
            ScreenParseError::TruncatedIpv6ExtChain => "ip-malformed",
        }
    }
}
