//! The session-identity discriminator (#7188).
//!
//! Lives beside `SessionKey` rather than in `afxdp` because it is PART of the
//! key: the type must be visible everywhere the key is, which is crate-wide.
//! The GRE *extractor* stays in `afxdp/gre_discriminator.rs`, because parsing a
//! frame is a packet-path concern and this is an identity concern.

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
pub(crate) enum TunnelDiscriminator {
    /// No discriminator concept for this protocol (everything but GRE today).
    #[default]
    None,
    /// GRE with the K bit clear — a real, distinct identity.
    Unkeyed,
    /// RFC 2890 Key, including the legal value 0.
    Keyed(u32),
    /// The header could not be read.
    ///
    /// Fail-closed ACROSS classes, NOT splitting WITHIN this one (#8380). The
    /// distinction decides what a caller may rely on:
    ///
    /// - it is distinct from `None`, `Unkeyed` and every `Keyed(_)`, so an
    ///   unreadable header can never be taken for a legitimate unkeyed tunnel
    ///   — the failure this class exists to prevent, and what the paragraph
    ///   above is about;
    /// - it is EQUAL to itself, and hashes equal, so two sessions sharing an
    ///   outer 5-tuple whose headers BOTH failed to parse resolve to the same
    ///   `SessionKey` and merge into one session.
    ///
    /// This said "never merges with anything", which is the second half
    /// inverted. Anyone reasoning about aliasing from that sentence reasoned
    /// wrongly — including about #7699's criterion 4, where two PPTP calls
    /// between one endpoint pair are both `Unparseable` and therefore alias.
    /// If a caller needs two unreadable headers kept apart, it needs its own
    /// discriminating class; this one cannot do it.
    Unparseable,
}

impl TunnelDiscriminator {
    /// True when this discriminator would split sessions that the 5-tuple alone
    /// would merge. Used to keep the acceleration-off path bit-identical.
    pub(crate) fn is_none(self) -> bool {
        matches!(self, TunnelDiscriminator::None)
    }
}


/// The result of decoding a `TunnelDiscriminator` off the HA session-sync wire
/// (#7188 decision 2).
///
/// THREE states, not two, and the third is the whole point. A peer that
/// predates the wire field sends nothing, which decodes to the reserved tag
/// `0` — and `0` must NOT mean [`TunnelDiscriminator::None`], because `None`
/// is a real class a NEW peer sends deliberately (a non-GRE session, or GRE
/// with `gre-performance-acceleration` off). Collapsing "the peer could not
/// express it" into "the peer said None" is exactly the aliasing this codec
/// exists to prevent: two RFC 2890 tunnels between one pair of outer endpoints
/// both land on the same 5-tuple key, and the second install evicts the first
/// (`session/install.rs` opens with an unconditional `remove_entry`).
///
/// See `docs/session-sync-architecture.md` and
/// `userspace-dp/src/afxdp/forwarding/README.md` for how the caller acts on
/// each state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WireDiscriminator {
    /// Tag `0`: the field was not carried. A peer that predates it.
    Absent,
    /// A tag this build understands, decoded to its class.
    Present(TunnelDiscriminator),
    /// A tag this build does NOT understand — a peer from the future that
    /// classifies an identity axis we cannot reproduce. Fails closed exactly
    /// like `Absent`: importing an identity we cannot express is how two
    /// distinct sessions become one.
    Unrecognized,
}

/// Reserved: the field was not carried on the wire.
///
/// It is deliberately NOT `None`'s tag. `serde(default)` and a short
/// length-gated binary record both yield `0`, so `0` is the one value a peer
/// can produce WITHOUT meaning to, and it must therefore be the one value that
/// means "no statement made".
const WIRE_ABSENT: u64 = 0;
const WIRE_NONE: u64 = 1;
const WIRE_UNKEYED: u64 = 2;
const WIRE_UNPARSEABLE: u64 = 3;
/// `Keyed(k)` rides as `KEYED_TAG | k`, so the full 32-bit RFC 2890 key space
/// — INCLUDING the legal key `0` — is representable without colliding with the
/// scalar tags above. Key 0 encodes as `0x1_0000_0000`, never as `0`, which is
/// what keeps decision 6's `Keyed(0) != Unkeyed != Absent` true on the wire.
const WIRE_KEYED_TAG: u64 = 1 << 32;

impl TunnelDiscriminator {
    /// Encode for the HA session-sync wire. Never returns [`WIRE_ABSENT`]: a
    /// build that has this function always makes a statement, which is what
    /// lets the receiver read `0` as "the peer could not".
    pub(crate) fn to_wire(self) -> u64 {
        match self {
            TunnelDiscriminator::None => WIRE_NONE,
            TunnelDiscriminator::Unkeyed => WIRE_UNKEYED,
            TunnelDiscriminator::Keyed(key) => WIRE_KEYED_TAG | u64::from(key),
            TunnelDiscriminator::Unparseable => WIRE_UNPARSEABLE,
        }
    }

    /// Decode a wire tag. See [`WireDiscriminator`] for why absence is a state
    /// of its own rather than a default.
    pub(crate) fn from_wire(wire: u64) -> WireDiscriminator {
        match wire {
            WIRE_ABSENT => WireDiscriminator::Absent,
            WIRE_NONE => WireDiscriminator::Present(TunnelDiscriminator::None),
            WIRE_UNKEYED => WireDiscriminator::Present(TunnelDiscriminator::Unkeyed),
            WIRE_UNPARSEABLE => WireDiscriminator::Present(TunnelDiscriminator::Unparseable),
            _ if wire & WIRE_KEYED_TAG != 0 && wire >> 33 == 0 => WireDiscriminator::Present(
                TunnelDiscriminator::Keyed((wire & 0xFFFF_FFFF) as u32),
            ),
            _ => WireDiscriminator::Unrecognized,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four classes are disjoint locally (decision 6); the wire encoding
    /// must not merge any pair of them. Asserted as a SET property over every
    /// class rather than tag-by-tag, so a future class cannot be added with a
    /// colliding tag and still pass.
    #[test]
    fn every_class_encodes_to_a_distinct_nonzero_tag_7188() {
        let classes = [
            TunnelDiscriminator::None,
            TunnelDiscriminator::Unkeyed,
            TunnelDiscriminator::Unparseable,
            TunnelDiscriminator::Keyed(0),
            TunnelDiscriminator::Keyed(1),
            TunnelDiscriminator::Keyed(100),
            TunnelDiscriminator::Keyed(200),
            TunnelDiscriminator::Keyed(u32::MAX),
        ];
        let mut seen = std::collections::HashSet::new();
        for class in classes {
            let wire = class.to_wire();
            assert_ne!(
                wire, WIRE_ABSENT,
                "{class:?} encoded to the reserved absent tag, so a peer that \
                 DID express it is indistinguishable from one that could not"
            );
            assert!(
                seen.insert(wire),
                "{class:?} shares a wire tag with another class; the four \
                 classes are disjoint on purpose (#7188 decision 6)"
            );
            assert_eq!(
                TunnelDiscriminator::from_wire(wire),
                WireDiscriminator::Present(class),
                "{class:?} must round-trip through the wire encoding"
            );
        }
    }

    /// What `Unparseable` actually guarantees (#8380).
    ///
    /// Its doc said "Fails closed: never merges with anything." That is true
    /// ACROSS classes and false WITHIN one, and the difference is the whole
    /// question a caller asks of it. Both halves are pinned here because a
    /// corrected comment with no cell is one edit from regressing to the
    /// comfortable version.
    ///
    /// The intra-class half asserts the HASH as well as equality: a session
    /// map keys on `Hash`, so equality alone would not pin what callers
    /// actually depend on.
    #[test]
    fn unparseable_fails_closed_across_classes_but_does_not_split_within_8380() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn hash_of(d: TunnelDiscriminator) -> u64 {
            let mut h = DefaultHasher::new();
            d.hash(&mut h);
            h.finish()
        }

        // ACROSS: never aliases onto a legitimate class. This is the property
        // the class exists for.
        for other in [
            TunnelDiscriminator::None,
            TunnelDiscriminator::Unkeyed,
            TunnelDiscriminator::Keyed(0),
            TunnelDiscriminator::Keyed(1),
            TunnelDiscriminator::Keyed(u32::MAX),
        ] {
            assert_ne!(
                TunnelDiscriminator::Unparseable,
                other,
                "an unreadable header must never be taken for {other:?}; that \
                 aliasing is what this class exists to prevent"
            );
        }

        // WITHIN: two unreadable headers are the SAME discriminator. This is
        // the half the old comment denied — and the reason #7699's criterion 4
        // is NOT satisfied by this class alone.
        assert_eq!(
            TunnelDiscriminator::Unparseable,
            TunnelDiscriminator::Unparseable,
            "two Unparseable discriminators must compare equal; if this ever \
             fails, the class started splitting and every caller relying on it \
             to MERGE unreadable headers changed behaviour"
        );
        assert_eq!(
            hash_of(TunnelDiscriminator::Unparseable),
            hash_of(TunnelDiscriminator::Unparseable),
            "hashes must agree too — a session map keys on Hash, so equality \
             alone does not pin what callers depend on"
        );
    }

    /// The pair decision 6 singles out: an unkeyed tunnel and a tunnel whose
    /// RFC 2890 Key is literally zero are DIFFERENT tunnels. A naive
    /// "key or zero" encoding merges them, which is why this is asserted
    /// separately from the set property above.
    #[test]
    fn keyed_zero_is_not_unkeyed_on_the_wire_7188() {
        assert_ne!(
            TunnelDiscriminator::Keyed(0).to_wire(),
            TunnelDiscriminator::Unkeyed.to_wire()
        );
        assert_ne!(
            TunnelDiscriminator::Keyed(0).to_wire(),
            TunnelDiscriminator::None.to_wire()
        );
    }

    /// `0` is the value a peer produces by NOT having the field:
    /// `#[serde(default)]` on the JSON leg, a short record on the
    /// length-gated binary leg. It must decode to `Absent`, never to a class.
    #[test]
    fn zero_decodes_to_absent_not_to_none_7188() {
        assert_eq!(TunnelDiscriminator::from_wire(0), WireDiscriminator::Absent);
        assert_ne!(
            TunnelDiscriminator::from_wire(0),
            WireDiscriminator::Present(TunnelDiscriminator::None),
            "absence and an explicit `None` are different statements: the first \
             is a peer that cannot express the identity (withhold), the second \
             is a peer that says this protocol has no discriminator (import)"
        );
    }

    /// A tag from a future build classifies an identity axis this one cannot
    /// reproduce, so it fails closed rather than defaulting into a class.
    #[test]
    fn an_unknown_tag_is_unrecognized_not_coerced_7188() {
        for wire in [4u64, 5, 0xFFFF, 2 << 32, u64::MAX] {
            assert_eq!(
                TunnelDiscriminator::from_wire(wire),
                WireDiscriminator::Unrecognized,
                "wire tag {wire:#x} is not one this build defines; coercing it \
                 into a known class would import an identity we cannot express"
            );
        }
    }
}
