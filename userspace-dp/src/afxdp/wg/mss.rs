//! WireGuard MSS-clamp arithmetic.
//!
//! Lives separately from `forwarding/mod.rs::native_gre_tcp_mss`
//! because the byte overhead differs from GRE and because reusing
//! the GRE function (as PR #1492 did) was a 48-byte error.
//!
//! Per-packet overhead, end-to-end, from inner-TCP payload back
//! out to the wire:
//!
//! ```text
//!   inner TCP header      20
//!   inner IPv4 header     20    (or 40 for v6)
//!   ----------------
//!   inner IP packet       40 (v4) / 60 (v6)
//!
//!   WG data record:
//!     type+reserved        4
//!     receiver_index       4
//!     counter              8
//!     Poly1305 tag        16
//!   ----------------
//!   WG transport         32
//!
//!   outer UDP             8
//!   outer IP             20 (v4) / 40 (v6)
//!   ----------------
//!   outer encap          28 (v4) / 48 (v6)
//! ```
//!
//! Maximum permitted inner-TCP MSS at MTU `M` for an IPv4 outer
//! tunnel carrying an IPv4 inner TCP segment:
//!
//! ```text
//!   max_inner_tcp_payload = M - outer_encap_v4 - wg_transport
//!                             - inner_ip_v4 - inner_tcp_header
//!                         = M - 28 - 32 - 20 - 20
//!                         = M - 100
//! ```
//!
//! For a 1500-byte outer link MTU, this gives MSS = 1400. (Compare
//! to vanilla TCP-over-Ethernet at MSS = 1460 — the 60-byte delta
//! is the WG + outer-IP+UDP overhead.)

use super::{WG_OVERHEAD_V4, WG_OVERHEAD_V6};

/// Inner-TCP MSS for the given outer-link MTU and inner+outer IP
/// families. Returns 0 if `mtu` is too small to accommodate any
/// inner TCP payload (in which case the caller MUST NOT advertise
/// the MSS — leave the TCP option as-is).
///
/// `outer_family` is one of `libc::AF_INET` or `libc::AF_INET6`;
/// `inner_family` ditto. The cross-family combos (v4-inner in
/// v6-outer, etc.) are valid: the WG inner payload is an IP packet
/// of whichever family the originator chose.
pub(crate) fn wg_tcp_mss(outer_family: i32, inner_family: i32, mtu: usize) -> u16 {
    let outer_overhead = match outer_family {
        x if x == libc::AF_INET => WG_OVERHEAD_V4,
        x if x == libc::AF_INET6 => WG_OVERHEAD_V6,
        _ => return 0,
    };
    let inner_ip_header = match inner_family {
        x if x == libc::AF_INET => 20usize,
        x if x == libc::AF_INET6 => 40usize,
        _ => return 0,
    };
    let inner_tcp_header = 20usize;
    mtu.checked_sub(outer_overhead + inner_ip_header + inner_tcp_header)
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod mss_tests {
    use super::*;

    // The numbers below come from the table at the top of this file.
    // If they change, the table is the source of truth — update it
    // first.

    #[test]
    fn v4_outer_v4_inner_1500_mtu() {
        // 1500 - 60 (outer encap+WG) - 20 (inner IPv4) - 20 (TCP) = 1400.
        assert_eq!(wg_tcp_mss(libc::AF_INET, libc::AF_INET, 1500), 1400);
    }

    #[test]
    fn v6_outer_v4_inner_1500_mtu() {
        // 1500 - 80 (outer encap+WG) - 20 (inner IPv4) - 20 (TCP) = 1380.
        assert_eq!(wg_tcp_mss(libc::AF_INET6, libc::AF_INET, 1500), 1380);
    }

    #[test]
    fn v4_outer_v6_inner_1500_mtu() {
        // 1500 - 60 - 40 (inner IPv6) - 20 (TCP) = 1380.
        assert_eq!(wg_tcp_mss(libc::AF_INET, libc::AF_INET6, 1500), 1380);
    }

    #[test]
    fn under_minimum_mtu_returns_zero() {
        // 60-byte outer + 40-byte inner IP+TCP = 100 bytes minimum.
        // An MTU of 50 cannot carry any inner TCP payload.
        assert_eq!(wg_tcp_mss(libc::AF_INET, libc::AF_INET, 50), 0);
    }

    #[test]
    fn unknown_family_returns_zero() {
        assert_eq!(wg_tcp_mss(99, libc::AF_INET, 1500), 0);
        assert_eq!(wg_tcp_mss(libc::AF_INET, 99, 1500), 0);
    }

    #[test]
    fn matches_byte_breakdown_constant() {
        // Cross-check: the IPv4-outer overhead must equal the
        // constants used by the framing code.
        assert_eq!(WG_OVERHEAD_V4, 60);
        assert_eq!(WG_OVERHEAD_V6, 80);
    }
}
