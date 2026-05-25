//! DSCP and ECN handling for the WG outer header.
//!
//! `UserspaceDpMeta::dscp` is 6-bit right-justified in xpf (matches
//! the existing dataplane convention — see `forwarding/mod.rs` for
//! the same placement on the GRE encap). The outer IP TOS byte
//! holds DSCP in the high 6 bits and ECN in the low 2 bits.
//!
//! Conversion is `dscp << 2`. ECN is **cleared** by this PR; RFC
//! 6040 (ECN propagation across tunnels) is a tracked follow-up.

/// Build the outer IPv4 TOS / IPv6 Traffic Class byte from a
/// 6-bit DSCP value. ECN bits are cleared.
#[inline]
pub(crate) fn tos_from_dscp(dscp: u8) -> u8 {
    // Defensive mask: callers should pass 6-bit values, but a
    // stray high bit would corrupt the ECN field, which is the
    // sort of bug that's invisible in unit tests and shows up as
    // mysterious congestion behavior on the wire.
    (dscp & 0x3F) << 2
}

#[cfg(test)]
mod dscp_tests {
    use super::*;

    #[test]
    fn dscp_shifted_two_left() {
        // CS0 / EF / AF41 sanity checks.
        assert_eq!(tos_from_dscp(0), 0); // CS0
        assert_eq!(tos_from_dscp(46), 46 << 2); // EF = 0xB8 = 184
        assert_eq!(tos_from_dscp(34), 34 << 2); // AF41 = 0x88 = 136
    }

    #[test]
    fn ecn_bits_always_clear() {
        // Even with a max-valued DSCP, the low 2 bits (ECN) must
        // be zero. This is the property the RFC 6040 follow-up
        // will lift.
        for d in 0u8..=63u8 {
            assert_eq!(tos_from_dscp(d) & 0x03, 0);
        }
    }

    #[test]
    fn rejects_overflow_into_ecn() {
        // If a caller mistakenly passes an 8-bit value with bits
        // in positions 6-7, those must NOT bleed into the TOS
        // byte. (Equivalent: ECN is preserved at zero.)
        assert_eq!(tos_from_dscp(0xFF), 0x3F << 2);
        assert_eq!(tos_from_dscp(0xC0), 0); // upper bits only
    }
}
