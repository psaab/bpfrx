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
    /// The header could not be read. Fails closed: never merges with anything.
    Unparseable,
}

impl TunnelDiscriminator {
    /// True when this discriminator would split sessions that the 5-tuple alone
    /// would merge. Used to keep the acceleration-off path bit-identical.
    pub(crate) fn is_none(self) -> bool {
        matches!(self, TunnelDiscriminator::None)
    }
}

