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
//! THE SEAM IS CLOSED. This module's landing cut said "nothing in production
//! calls this yet"; that has not been true since `stage_parse_flow_and_learn`
//! grew `None if worker_ctx.forwarding.gre_acceleration =>
//! gre_keyed_session_flow(..)` (`afxdp/poll_stages.rs`), which is the read this
//! module was staged for. The `#![allow(dead_code)]` stays because the module
//! still carries classification helpers the single call site does not reach.
//!
//! What this classification now feeds, beyond the local key: the discriminator
//! rides the HA session-sync wire (#7188, `session/discriminator.rs`
//! `to_wire`/`from_wire`), so a misclassification here is not merely a local
//! identity error — it is the identity a peer imports after a failover. See
//! `docs/session-sync-architecture.md`, "Tunnel Session-Identity
//! Discriminator".
#![allow(dead_code)]

use super::gre::{GRE_FLAG_CHECKSUM, GRE_FLAG_KEY};
use super::types::{SessionFlow, UserspaceDpMeta};
use crate::session::TunnelDiscriminator;

/// RFC 1701 Routing Present. RFC 2890 declares the bit reserved-zero; a frame
/// that sets it carries a variable-length Source Route Entry list with no fixed
/// offset, so nothing after it can be located.
const GRE_FLAG_ROUTING: u16 = 0x4000;
/// Version lives in the low 3 bits. RFC 2784/2890 GRE is version 0; RFC 2637
/// PPTP enhanced GRE is version 1 and re-purposes the same 32 bits.
const GRE_VERSION_MASK: u16 = 0x0007;

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

    /// A GRE frame with a full IPv4 header, so `outer_datagram_end` and the
    /// metadata flow builder both have real material to work from.
    fn gre_v4_frame(flags: u16, options: &[u32]) -> (Vec<u8>, UserspaceDpMeta) {
        let mut f = vec![0u8; 20];
        f[0] = 0x45; // IPv4, IHL 5
        f[9] = crate::ip_proto::PROTO_GRE;
        f[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
        f[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
        f.extend_from_slice(&flags.to_be_bytes());
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        for w in options {
            f.extend_from_slice(&w.to_be_bytes());
        }
        let total = f.len() as u16;
        f[2..4].copy_from_slice(&total.to_be_bytes()); // IP total_len
        let mut meta = UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_GRE,
            l3_offset: 0,
            l4_offset: 20,
            ..Default::default()
        };
        meta.flow_src_addr[..4].copy_from_slice(&[10, 0, 0, 1]);
        meta.flow_dst_addr[..4].copy_from_slice(&[10, 0, 0, 2]);
        (f, meta)
    }

    /// The feature: two RFC 2890 keys between the SAME outer endpoints must not
    /// share an identity. Everything else in the tuple is identical here, so the
    /// discriminator is the only thing that can separate them.
    #[test]
    fn two_keys_same_endpoints_are_distinct_flows_7188() {
        let (a, ma) = gre_v4_frame(K, &[0x0000_002a]);
        let (b, mb) = gre_v4_frame(K, &[0x0000_002b]);
        let fa = gre_keyed_session_flow(&a, ma).expect("keyed GRE must produce a flow");
        let fb = gre_keyed_session_flow(&b, mb).expect("keyed GRE must produce a flow");
        assert_eq!(fa.forward_key.src_ip, fb.forward_key.src_ip);
        assert_eq!(fa.forward_key.dst_ip, fb.forward_key.dst_ip);
        assert_ne!(
            fa.forward_key, fb.forward_key,
            "two tunnels between one endpoint pair must not share a SessionKey — \
             that is the whole feature (#7188)"
        );
    }

    /// Decision 5: the discriminator is NOT a port. Ports stay honestly zero, so
    /// every port consumer (show, RT_FLOW, clear filters, NAT alias matching)
    /// keeps reporting the truth rather than a fabricated transport port.
    #[test]
    fn keyed_gre_reports_no_fake_ports_7188() {
        let (f, m) = gre_v4_frame(K, &[0xdead_beef]);
        let flow = gre_keyed_session_flow(&f, m).expect("flow");
        assert_eq!(flow.forward_key.src_port, 0);
        assert_eq!(flow.forward_key.dst_port, 0);
        assert_eq!(
            flow.forward_key.discriminator,
            TunnelDiscriminator::Keyed(0xdead_beef)
        );
    }

    /// Unkeyed GRE still gets an identity, and it is NOT the keyed-zero one.
    #[test]
    fn unkeyed_and_keyed_zero_are_distinct_flows_7188() {
        let (u, mu) = gre_v4_frame(0, &[]);
        let (z, mz) = gre_v4_frame(K, &[0]);
        let fu = gre_keyed_session_flow(&u, mu).expect("unkeyed flow");
        let fz = gre_keyed_session_flow(&z, mz).expect("keyed-zero flow");
        assert_ne!(fu.forward_key, fz.forward_key);
    }

    /// Fail closed: a header we could not read gets NO session, so it cannot
    /// alias a legitimate one. It is also what such a packet does today.
    #[test]
    fn unparseable_stays_flowless_7188() {
        let (v1, mv1) = gre_v4_frame(K | 1, &[0x0000_0055]); // version 1
        assert!(gre_keyed_session_flow(&v1, mv1).is_none());
        let (rt, mrt) = gre_v4_frame(K | R, &[0x0000_0055]); // routing present
        assert!(gre_keyed_session_flow(&rt, mrt).is_none());
        let (tr, mtr) = gre_v4_frame(K, &[]); // truncated key
        assert!(gre_keyed_session_flow(&tr, mtr).is_none());
    }

    /// Non-GRE never reaches this arm even if called: the caller gates on the
    /// knob, and this gates on the protocol.
    #[test]
    fn non_gre_is_never_keyed_7188() {
        let (f, mut m) = gre_v4_frame(K, &[0x0000_0001]);
        m.protocol = crate::ip_proto::PROTO_TCP;
        assert!(gre_keyed_session_flow(&f, m).is_none());
    }

    /// INERTNESS with acceleration OFF, demonstrated rather than asserted.
    ///
    /// With the knob off, `stage_parse_flow_and_learn` returns exactly what
    /// `parse_session_flow_from_bytes` returned — the keyed arm is behind
    /// `None if worker_ctx.forwarding.gre_acceleration`. So the acceleration-off
    /// behaviour IS this function's behaviour, and this cell pins that #6837's
    /// flowless treatment of transit GRE is untouched by #7188.
    ///
    /// If this ever returns `Some`, the knob has stopped being a switch: GRE
    /// would be getting a session on the default path, which is the zero-ported
    /// aliasing #6837 removed.
    #[test]
    fn acceleration_off_leaves_transit_gre_flowless_7188() {
        for (label, flags, opts) in [
            ("keyed", K, &[0x0000_002a][..]),
            ("unkeyed", 0, &[][..]),
            ("keyed-zero", K, &[0][..]),
        ] {
            let (f, m) = gre_v4_frame(flags, opts);
            assert!(
                crate::afxdp::frame::parse_session_flow_from_bytes(&f, m).is_none(),
                "{label} transit GRE must stay FLOWLESS on the acceleration-off path \
                 (#6837); a Some here means the knob is not a switch and GRE is \
                 getting a session by default"
            );
            // Control: the same frame DOES yield a flow through the keyed arm,
            // so the None above is the knob's doing and not an inert fixture.
            assert!(
                gre_keyed_session_flow(&f, m).is_some(),
                "{label} fixture must be capable of producing a keyed flow, or the \
                 assertion above passes for the wrong reason"
            );
        }
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

/// Build the keyed-GRE session flow for a transit packet, or `None` to leave it
/// flowless (#7188 cut 1c).
///
/// This is an ADDITIVE arm, deliberately. It does not touch
/// `metadata_tuple_complete`, which #6837 set to refuse protocol 47 and whose
/// comment warns the discriminator "must not come back as a metadata-side
/// default". The shim does not parse GRE, so the metadata side has no
/// discriminator to offer and must keep refusing; this arm supplies the identity
/// from the FRAME, which is the only side that can have read it.
///
/// With `gre-performance-acceleration` off the caller never reaches here, so the
/// packet path is bit-identical to #6837's flowless behaviour.
///
/// `Unparseable` returns `None` — flowless. A header we could not read gets no
/// session at all, which is a stronger form of decision 6's "must not merge into
/// a legitimate session" than giving it an identity of its own would be: a
/// packet with no session cannot alias anything, and this is also exactly what
/// such a packet does today.
pub(in crate::afxdp) fn gre_keyed_session_flow(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    if meta.protocol != crate::ip_proto::PROTO_GRE {
        return None;
    }
    let outer_end = super::gre::outer_datagram_end(frame, meta)?;
    let discriminator = gre_transit_discriminator(frame, meta.l4_offset as usize, outer_end);
    match discriminator {
        TunnelDiscriminator::Unparseable | TunnelDiscriminator::None => return None,
        TunnelDiscriminator::Unkeyed | TunnelDiscriminator::Keyed(_) => {}
    }
    let mut flow = super::frame::parse_session_flow_from_meta(meta)?;
    // GRE has no ports and never gains fake ones (#7188 decision 5): identity
    // comes from the discriminator alone, and every port consumer keeps seeing
    // the honest zero.
    flow.forward_key.src_port = 0;
    flow.forward_key.dst_port = 0;
    flow.forward_key.discriminator = discriminator;
    Some(flow)
}
