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
//!     §5.4.6 padding       0..15  (round inner up to 16-byte multiple)
//!     Poly1305 tag        16
//!   ----------------
//!   WG transport         32..47
//!
//!   outer UDP             8
//!   outer IP             20 (v4) / 40 (v6)
//!   ----------------
//!   outer encap          28 (v4) / 48 (v6)
//! ```
//!
//! Maximum permitted inner-TCP MSS at MTU `M` for an IPv4 outer
//! tunnel carrying an IPv4 inner TCP segment, accounting for the
//! worst-case 15 bytes of WG §5.4.6 padding that the encap side
//! will add to a non-16-aligned inner length:
//!
//! ```text
//!   max_inner_tcp_payload = M - outer_encap_v4 - wg_transport
//!                             - max_padding
//!                             - inner_ip_v4 - inner_tcp_header
//!                         = M - 28 - 32 - 15 - 20 - 20
//!                         = M - 115
//! ```
//!
//! For a 1500-byte outer link MTU, this gives MSS = 1385. (Compare
//! to vanilla TCP-over-Ethernet at MSS = 1460 — the 75-byte delta
//! is the WG + padding + outer-IP+UDP overhead.)
//!
//! The 15-byte subtraction is conservative: a real inner segment
//! of MSS bytes will need padding only if the resulting inner IP
//! packet length is not a multiple of 16. Subtracting the worst
//! case keeps the outer frame at or under MTU regardless of how
//! the inner payload length lands, which is the property a sender
//! MUST be able to advertise. Carrying tight per-packet math here
//! would require knowing the exact inner-IP+TCP+payload length at
//! TCP-option-rewrite time, which we don't.

use super::{WG_OVERHEAD_V4, WG_OVERHEAD_V6};

/// Worst-case bytes of WG §5.4.6 padding (round inner-IP packet up
/// to a 16-byte multiple before AEAD).
const WG_MAX_PADDING: usize = 15;

/// Inner-TCP MSS for the given outer-link MTU and inner+outer IP
/// families. Returns 0 if `mtu` is too small to accommodate any
/// inner TCP payload (in which case the caller MUST NOT advertise
/// the MSS — leave the TCP option as-is).
///
/// `outer_family` is one of `libc::AF_INET` or `libc::AF_INET6`;
/// `inner_family` ditto. The cross-family combos (v4-inner in
/// v6-outer, etc.) are valid: the WG inner payload is an IP packet
/// of whichever family the originator chose.
///
/// The returned MSS accounts for the worst-case 15 bytes of WG
/// §5.4.6 transport-padding that the encap side may add to align
/// the inner-IP packet length to a 16-byte multiple — see the
/// module-level doc for the byte-by-byte derivation. The sender
/// advertising this MSS will never produce an outer frame that
/// exceeds `mtu`, regardless of how the inner segment's total
/// length aligns modulo 16.
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
    mtu.checked_sub(outer_overhead + WG_MAX_PADDING + inner_ip_header + inner_tcp_header)
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
        // 1500 - 60 (outer encap+WG) - 15 (worst-case padding)
        //      - 20 (inner IPv4) - 20 (TCP) = 1385.
        assert_eq!(wg_tcp_mss(libc::AF_INET, libc::AF_INET, 1500), 1385);
    }

    #[test]
    fn v6_outer_v4_inner_1500_mtu() {
        // 1500 - 80 (outer encap+WG) - 15 (worst-case padding)
        //      - 20 (inner IPv4) - 20 (TCP) = 1365.
        assert_eq!(wg_tcp_mss(libc::AF_INET6, libc::AF_INET, 1500), 1365);
    }

    #[test]
    fn v4_outer_v6_inner_1500_mtu() {
        // 1500 - 60 - 15 (worst-case padding) - 40 (inner IPv6) - 20 (TCP) = 1365.
        assert_eq!(wg_tcp_mss(libc::AF_INET, libc::AF_INET6, 1500), 1365);
    }

    #[test]
    fn padded_inner_never_exceeds_mtu() {
        // Property check: at MSS, the worst-case padded inner IP
        // packet plus WG transport plus outer encap must fit in
        // the MTU. This is the contract that justifies the
        // WG_MAX_PADDING subtraction in the MSS formula.
        for mtu in [576usize, 1280, 1500, 9000] {
            for (outer, inner, outer_enc, inner_ip) in [
                (libc::AF_INET, libc::AF_INET, WG_OVERHEAD_V4, 20),
                (libc::AF_INET, libc::AF_INET6, WG_OVERHEAD_V4, 40),
                (libc::AF_INET6, libc::AF_INET, WG_OVERHEAD_V6, 20),
                (libc::AF_INET6, libc::AF_INET6, WG_OVERHEAD_V6, 40),
            ] {
                let mss = wg_tcp_mss(outer, inner, mtu) as usize;
                if mss == 0 {
                    continue;
                }
                // Worst-case inner IP packet at MSS, with the padding
                // rounded up to a 16-byte multiple.
                let inner_total = inner_ip + 20 + mss;
                let padded = (inner_total + 15) & !15;
                // padded inner + WG transport overhead (data header
                // 16 + tag 16 = 32 already inside outer_enc - outer IP
                // and UDP, so we add 0) — outer_enc already includes
                // WG_DATA_HEADER_LEN + POLY1305_TAG_LEN per mod.rs.
                let outer_total = outer_enc + (padded - inner_total) + inner_total;
                // The above simplifies to outer_enc + padded; assert
                // it directly to be unambiguous.
                assert_eq!(outer_total, outer_enc + padded);
                assert!(
                    outer_enc + padded <= mtu,
                    "MTU {mtu} outer={outer} inner={inner}: outer_enc {outer_enc} + padded {padded} = {} > MTU",
                    outer_enc + padded
                );
            }
        }
    }

    #[test]
    fn under_minimum_mtu_returns_zero() {
        // 60-byte outer + 15-byte padding + 40-byte inner IP+TCP =
        // 115 bytes minimum. An MTU of 50 cannot carry any inner
        // TCP payload.
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
