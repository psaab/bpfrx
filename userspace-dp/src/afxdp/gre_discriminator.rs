//! RFC 2890 GRE tunnel-discriminator extraction for TRANSIT GRE (#7188).
//!
//! GRE is IP protocol 47 and has no L4 ports, so two tunnels between the same
//! pair of outer endpoints are indistinguishable by 5-tuple. Since #6837 the
//! dataplane declines to invent a tuple for them — `metadata_tuple_complete`
//! returns false for protocol 47, so transit GRE is FLOWLESS rather than sharing
//! one zero-ported `SessionKey`. What that gives up is stateful return admission
//! and session visibility, and the RFC 2890 Key is the discriminator that can
//! restore both: it is carried identically in BOTH directions of a tunnel, which
//! is what a session key requires.
//!
//! DISTINCT FROM THE DECAP WALK in `gre.rs`. That one parses GRE this box
//! TERMINATES: it validates the checksum, refuses on mismatch, and resolves an
//! inner packet. This one only classifies a packet PASSING THROUGH, so it
//! deliberately does not validate the checksum — a transit frame with a bad GRE
//! checksum is not ours to drop, and dropping it here would be a behaviour
//! change smuggled in under an identity change. It skips the field and reads on.
//!
//! The refusal discipline is shared, and deliberately: version and routing are
//! both hard refusals in `gre.rs` for reasons that apply identically here.
//!
//! NOTHING IN PRODUCTION CALLS THIS YET, hence the `#![allow(dead_code)]` below.
//! This cut lands the extractor and its classification rules ALONE, so the
//! packet path is observably unchanged — transit GRE stays flowless, exactly as
//! #6837 left it. The next cut threads `TunnelDiscriminator` onto `SessionKey`
//! and reads it here. That is the same seam convention
//! `ForwardingState.gre_acceleration` already documents for this feature.
#![allow(dead_code)]

use super::gre::{GRE_FLAG_CHECKSUM, GRE_FLAG_KEY};

/// RFC 1701 Routing Present. RFC 2890 declares the bit reserved-zero; a frame
/// that sets it carries a variable-length Source Route Entry list with no fixed
/// offset, so nothing after it can be located.
const GRE_FLAG_ROUTING: u16 = 0x4000;
/// Version lives in the low 3 bits. RFC 2784/2890 GRE is version 0; RFC 2637
/// PPTP enhanced GRE is version 1 and re-purposes the same 32 bits.
const GRE_VERSION_MASK: u16 = 0x0007;

/// The session-identity discriminator for a tunnelled protocol.
///
/// The four classes are DISJOINT ON PURPOSE (#7188 decision 6), and the two
/// pairs that look mergeable are the two that must not merge:
///
/// * `Unkeyed` is not `Keyed(0)`. A tunnel that carries no Key and a tunnel
///   whose Key is literally zero are different tunnels, and RFC 2890 permits
///   both. Collapsing them would let an unkeyed tunnel join a keyed-zero
///   session.
/// * `Unparseable` is not `Unkeyed`. A truncated, version-1 or source-routed
///   header is one we could not read — not one we read and found no key in.
///   Falling back to `Unkeyed` would let a malformed header merge into a
///   legitimate unkeyed session, which is the failure a fail-closed class
///   exists to prevent.
///
/// `None` is the everything-else case: a protocol with no discriminator concept
/// at all. It is what every non-GRE session carries, so adding this field to a
/// session key leaves every existing protocol's identity unchanged.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq)]
pub(in crate::afxdp) enum TunnelDiscriminator {
    /// No discriminator concept for this protocol (everything but GRE today).
    #[default]
    None,
    /// GRE with the K bit clear — a real, distinct identity.
    Unkeyed,
    /// RFC 2890 Key, including the legal value 0.
    Keyed(u32),
    /// The header could not be read. Fails closed: never merges with anything.
    Unparseable,
}

impl TunnelDiscriminator {
    /// True when this discriminator would split sessions that the 5-tuple alone
    /// would merge. Used to keep the acceleration-off path bit-identical.
    pub(in crate::afxdp) fn is_none(self) -> bool {
        matches!(self, TunnelDiscriminator::None)
    }
}

/// Classify a transit GRE packet's RFC 2890 discriminator.
///
/// `gre_offset` is the frame offset of the GRE header; `outer_end` is the offset
/// at which the OUTER IP datagram ends, as declared by the IP header rather than
/// by the backing slice. Bounding on the declared end rather than `frame.len()`
/// is the #2361 rule: a frame carrying trailing L2 pad or attacker-supplied
/// slack must not have an option field read out of that slack.
///
/// Every failure path returns `Unparseable`, never `Unkeyed`.
pub(in crate::afxdp) fn gre_transit_discriminator(
    frame: &[u8],
    gre_offset: usize,
    outer_end: usize,
) -> TunnelDiscriminator {
    // Bound reads by the DECLARED datagram end, and only then by the slice.
    let Some(outer) = frame.get(..outer_end.min(frame.len())) else {
        return TunnelDiscriminator::Unparseable;
    };
    let Some(base) = outer.get(gre_offset..gre_offset + 4) else {
        return TunnelDiscriminator::Unparseable;
    };
    let flags_version = u16::from_be_bytes([base[0], base[1]]);

    // Version 1 is PPTP enhanced GRE, whose 32 bits after the flags word are
    // `Payload Length | Call ID` — NOT a Key. Reading them with RFC 2890 field
    // order would promote a per-packet-varying length as if it were a stable
    // tunnel identity. PPTP call-ID pairing is directional and lands separately.
    if (flags_version & GRE_VERSION_MASK) != 0 {
        return TunnelDiscriminator::Unparseable;
    }
    // Source Route Entries have no fixed offset, so nothing behind them can be
    // located — including the Key.
    if (flags_version & GRE_FLAG_ROUTING) != 0 {
        return TunnelDiscriminator::Unparseable;
    }
    if (flags_version & GRE_FLAG_KEY) == 0 {
        return TunnelDiscriminator::Unkeyed;
    }

    // RFC 2890 field order is Checksum+Reserved1, then Key, then Sequence. The
    // checksum field is SKIPPED, not validated — see the module note.
    let mut off = gre_offset + 4;
    if (flags_version & GRE_FLAG_CHECKSUM) != 0 {
        if outer.get(off..off + 4).is_none() {
            return TunnelDiscriminator::Unparseable;
        }
        off += 4;
    }
    match outer.get(off..off + 4) {
        Some(key) => {
            let Ok(bytes) = <[u8; 4]>::try_from(key) else {
                return TunnelDiscriminator::Unparseable;
            };
            TunnelDiscriminator::Keyed(u32::from_be_bytes(bytes))
        }
        None => TunnelDiscriminator::Unparseable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a frame whose GRE header starts at `GRE_OFF`, with `flags` and the
    /// given option words appended in RFC 2890 order. `slack` bytes of trailing
    /// garbage are appended BEYOND the declared datagram end, so a test can
    /// prove a read is bounded by the declaration and not by the slice.
    const GRE_OFF: usize = 20; // a plain 20-byte IPv4 header

    fn frame(flags: u16, options: &[u32], slack: usize) -> (Vec<u8>, usize) {
        let mut f = vec![0u8; GRE_OFF];
        f.extend_from_slice(&flags.to_be_bytes());
        f.extend_from_slice(&0x0800u16.to_be_bytes()); // inner proto: IPv4
        for w in options {
            f.extend_from_slice(&w.to_be_bytes());
        }
        let outer_end = f.len();
        f.extend(std::iter::repeat(0xAA).take(slack));
        (f, outer_end)
    }

    const K: u16 = GRE_FLAG_KEY;
    const C: u16 = GRE_FLAG_CHECKSUM;
    const S: u16 = 0x1000;
    const R: u16 = GRE_FLAG_ROUTING;

    #[test]
    fn unkeyed_is_not_keyed_zero_7188() {
        let (unkeyed, end) = frame(0, &[], 0);
        let (keyed_zero, end0) = frame(K, &[0], 0);
        let a = gre_transit_discriminator(&unkeyed, GRE_OFF, end);
        let b = gre_transit_discriminator(&keyed_zero, GRE_OFF, end0);
        assert_eq!(a, TunnelDiscriminator::Unkeyed);
        assert_eq!(b, TunnelDiscriminator::Keyed(0));
        assert_ne!(
            a, b,
            "an UNKEYED tunnel and a tunnel whose RFC 2890 Key is literally 0 are \
             different tunnels and both are legal. Collapsing them lets an \
             unkeyed tunnel join a keyed-zero session (#7188 decision 6)"
        );
    }

    #[test]
    fn distinct_keys_are_distinct_discriminators_7188() {
        let (a, ea) = frame(K, &[0x0000_002a], 0);
        let (b, eb) = frame(K, &[0x0000_002b], 0);
        assert_eq!(
            gre_transit_discriminator(&a, GRE_OFF, ea),
            TunnelDiscriminator::Keyed(0x2a)
        );
        assert_ne!(
            gre_transit_discriminator(&a, GRE_OFF, ea),
            gre_transit_discriminator(&b, GRE_OFF, eb),
            "two RFC 2890 keys between the same endpoints must not share an identity \
             — that is the whole feature (#7188)"
        );
    }

    #[test]
    fn checksum_present_shifts_the_key_by_four_7188() {
        // Checksum+Reserved1 comes FIRST, then Key. Reading the key without
        // skipping it returns the checksum word — a value that VARIES per
        // packet, so it would split one tunnel into a new session per packet.
        let (f, end) = frame(C | K, &[0xdead_beef, 0x0000_0099], 0);
        assert_eq!(
            gre_transit_discriminator(&f, GRE_OFF, end),
            TunnelDiscriminator::Keyed(0x99),
            "the Key must be read AFTER the 4-byte Checksum+Reserved1 field"
        );
    }

    #[test]
    fn sequence_present_does_not_move_the_key_7188() {
        // Sequence comes AFTER Key, so its presence must not shift the read.
        let (f, end) = frame(K | S, &[0x0000_0077, 0x0000_0001], 0);
        assert_eq!(
            gre_transit_discriminator(&f, GRE_OFF, end),
            TunnelDiscriminator::Keyed(0x77)
        );
    }

    #[test]
    fn unsupported_version_is_unparseable_not_unkeyed_7188() {
        // PPTP enhanced GRE (version 1) re-purposes the same 32 bits as
        // `Payload Length | Call ID`. Reading them as a Key would promote a
        // per-packet length as a stable identity.
        let (f, end) = frame(K | 1, &[0x0000_0055], 0);
        assert_eq!(
            gre_transit_discriminator(&f, GRE_OFF, end),
            TunnelDiscriminator::Unparseable,
            "a version-1 header must fail CLOSED, not fall back to Unkeyed"
        );
    }

    #[test]
    fn routing_present_is_unparseable_7188() {
        let (f, end) = frame(K | R, &[0x0000_0055], 0);
        assert_eq!(
            gre_transit_discriminator(&f, GRE_OFF, end),
            TunnelDiscriminator::Unparseable,
            "a Source Route Entry list has no fixed offset, so the Key behind it \
             cannot be located and must not be guessed"
        );
    }

    #[test]
    fn truncated_key_is_unparseable_7188() {
        // K set but the key word is absent.
        let (f, end) = frame(K, &[], 0);
        assert_eq!(
            gre_transit_discriminator(&f, GRE_OFF, end),
            TunnelDiscriminator::Unparseable
        );
        // K set, checksum set, only the checksum word present.
        let (g, endg) = frame(C | K, &[0xdead_beef], 0);
        assert_eq!(
            gre_transit_discriminator(&g, GRE_OFF, endg),
            TunnelDiscriminator::Unparseable
        );
        // Not even the 4-byte base header.
        let short = vec![0u8; GRE_OFF + 2];
        assert_eq!(
            gre_transit_discriminator(&short, GRE_OFF, short.len()),
            TunnelDiscriminator::Unparseable
        );
    }

    /// #2361: the read is bounded by the DECLARED datagram end, not the slice.
    /// The key bytes exist in the backing buffer here — as trailing slack — and
    /// must still not be read.
    #[test]
    fn key_in_trailing_slack_is_not_read_7188() {
        let (f, declared_end) = frame(K, &[], 8);
        assert!(
            f.len() > declared_end,
            "fixture must actually carry slack past the declared end, or this \
             cell cannot distinguish a bounded read from an unbounded one"
        );
        assert_eq!(
            gre_transit_discriminator(&f, GRE_OFF, declared_end),
            TunnelDiscriminator::Unparseable,
            "the Key must not be read out of bytes beyond the IP-declared end"
        );
        // Control: with the declaration extended to cover them, the same bytes
        // ARE read — proving the refusal above came from the bound and not from
        // the bytes being absent.
        assert_eq!(
            gre_transit_discriminator(&f, GRE_OFF, f.len()),
            TunnelDiscriminator::Keyed(0xAAAA_AAAA)
        );
    }

    #[test]
    fn offset_past_end_is_unparseable_not_a_panic_7188() {
        let (f, end) = frame(K, &[0x1234_5678], 0);
        assert_eq!(
            gre_transit_discriminator(&f, end + 64, end),
            TunnelDiscriminator::Unparseable
        );
        assert_eq!(
            gre_transit_discriminator(&[], 0, 0),
            TunnelDiscriminator::Unparseable
        );
    }

    #[test]
    fn default_is_none_so_existing_protocols_are_unchanged_7188() {
        assert_eq!(TunnelDiscriminator::default(), TunnelDiscriminator::None);
        assert!(TunnelDiscriminator::None.is_none());
        assert!(!TunnelDiscriminator::Unkeyed.is_none());
        assert!(!TunnelDiscriminator::Keyed(0).is_none());
        assert!(!TunnelDiscriminator::Unparseable.is_none());
    }
}
