//! RFC 2637 PPTP control-channel parsing (#7699 stage 2).
//!
//! # What this is for
//!
//! A PPTP GRE data packet carries only ONE of a call's two Call IDs — the one
//! belonging to the peer it is sent to — so the pair that identifies a call can
//! only be learned from the control channel on TCP/1723. This module turns a
//! control-channel segment into that pair; [`crate::session::pptp`] turns the
//! pair into the direction-neutral handle the dataplane keys on.
//!
//! # What this is NOT
//!
//! **Not a TCP reassembler.** There is no reassembly machinery in this tree and
//! stage 2 is not the place to invent one, so this parses only a control
//! message wholly contained in the segment it is given and reports
//! [`ControlParse::Truncated`] otherwise. That is a designed degradation, not a
//! defaulted one: a truncated message means *no association learned*, which
//! routes into the unassociated path stage 1 already built — the packet
//! forwards and is counted. PPTP control messages are small (an
//! Outgoing-Call-Reply is 32 bytes) and a stack that splits one across segments
//! is pathological, but it must land somewhere defined rather than nowhere.
//!
//! Also not: call-ID rewriting for NAT, a general ALG framework, or IPv6.

/// RFC 2637 §2.1 control-message header, before any message-specific body.
///
/// `Length(2) | PPTP Message Type(2) | Magic Cookie(4) | Control Message
/// Type(2) | Reserved0(2)`.
const CONTROL_HEADER_LEN: usize = 12;
/// RFC 2637 §2.1: distinguishes a control message and lets a receiver confirm
/// it is still synchronised with the stream. Required, because it is the only
/// cheap check that these bytes are PPTP at all.
const MAGIC_COOKIE: u32 = 0x1A2B_3C4D;
/// RFC 2637 §2.1 PPTP Message Type 1 — Control Message.
const MSG_TYPE_CONTROL: u16 = 1;
/// RFC 2637 §2.8 Control Message Type 8 — Outgoing-Call-Reply.
///
/// The reply is the ONLY message carrying both halves of the pair: its `Call
/// ID` is the sender's own, and `Peer's Call ID` echoes the requester's. An
/// Outgoing-Call-Request alone names one side and cannot pair a call.
const CTRL_OUTGOING_CALL_REPLY: u16 = 8;
/// Total length of an Outgoing-Call-Reply, header included (RFC 2637 §2.8).
const OUTGOING_CALL_REPLY_LEN: usize = 32;
/// RFC 2637 §2.8 Result Code 1 — Connected. Any other value is a call that did
/// NOT come up, and learning an association for it would install state for a
/// call that does not exist.
const RESULT_CONNECTED: u8 = 1;

/// What a control-channel segment yielded.
///
/// Four outcomes rather than `Option`, because the reasons are operationally
/// different and two of them are not errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlParse {
    /// A complete, successful Outgoing-Call-Reply naming both call ids.
    ///
    /// `call_id` belongs to the SENDER of this segment; `peer_call_id` to its
    /// destination. That asymmetry is the whole reason the pair must be learned
    /// here rather than derived from a data packet.
    CallReply { call_id: u16, peer_call_id: u16 },
    /// A well-formed control message this stage does not learn from — a
    /// different message type, or a reply whose Result Code says the call did
    /// not connect.
    Ignored,
    /// The message did not fit in this segment.
    ///
    /// Deliberately distinct from [`Self::Ignored`]: nothing is wrong with the
    /// stream, this parser simply does not reassemble. It routes to the
    /// unassociated path, and it is counted separately so "we are not
    /// reassembling" never looks like "there was no call".
    Truncated,
    /// Not a PPTP control message: too short for a header, wrong magic cookie,
    /// or not PPTP Message Type 1.
    NotControl,
}

/// Parse one TCP/1723 segment payload.
///
/// Takes the segment's bytes as given. Every read is bounds-checked against the
/// slice rather than against the declared `Length`, because the declared length
/// is attacker-controlled — a hostile peer that claims 32 bytes and sends 8
/// must yield `Truncated`, not an out-of-bounds read.
pub(crate) fn parse_control_segment(payload: &[u8]) -> ControlParse {
    if payload.len() < CONTROL_HEADER_LEN {
        return ControlParse::NotControl;
    }
    let declared_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    let msg_type = u16::from_be_bytes([payload[2], payload[3]]);
    let cookie = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if cookie != MAGIC_COOKIE || msg_type != MSG_TYPE_CONTROL {
        return ControlParse::NotControl;
    }
    let ctrl_type = u16::from_be_bytes([payload[8], payload[9]]);
    if ctrl_type != CTRL_OUTGOING_CALL_REPLY {
        return ControlParse::Ignored;
    }
    // A reply that claims a length other than the RFC's is not one we will read
    // fields out of by offset.
    if declared_len != OUTGOING_CALL_REPLY_LEN {
        return ControlParse::Ignored;
    }
    // The single-segment bound. Checked against what we ACTUALLY have.
    if payload.len() < OUTGOING_CALL_REPLY_LEN {
        return ControlParse::Truncated;
    }
    let call_id = u16::from_be_bytes([payload[12], payload[13]]);
    let peer_call_id = u16::from_be_bytes([payload[14], payload[15]]);
    if payload[16] != RESULT_CONNECTED {
        return ControlParse::Ignored;
    }
    ControlParse::CallReply {
        call_id,
        peer_call_id,
    }
}

/// Turn a control segment into the association it announces.
///
/// `src`/`dst` are the segment's own addresses. The mapping is the load-bearing
/// part: an Outgoing-Call-Reply's `Call ID` is the SENDER's, and `Peer's Call
/// ID` is the destination's. Getting it backwards would build an association
/// that resolves both directions to a handle no data packet can produce, which
/// is indistinguishable from not learning at all until a reply goes unmatched.
pub(crate) fn learn_from_control_segment(
    src: std::net::IpAddr,
    dst: std::net::IpAddr,
    payload: &[u8],
) -> Option<crate::session::pptp::PptpCall> {
    match parse_control_segment(payload) {
        ControlParse::CallReply {
            call_id,
            peer_call_id,
        } => Some(crate::session::pptp::PptpCall::new(
            src,
            call_id,
            dst,
            peer_call_id,
        )),
        ControlParse::Ignored | ControlParse::Truncated | ControlParse::NotControl => None,
    }
}

#[cfg(test)]
pub(crate) mod fixtures_7699 {
    use super::*;

    /// Build an Outgoing-Call-Reply exactly as RFC 2637 §2.8 lays it out.
    ///
    /// Written from the field layout rather than captured, so the offsets this
    /// parser reads are asserted against the RFC's structure and not against
    /// whatever the parser happens to do.
    pub(crate) fn outgoing_call_reply(call_id: u16, peer_call_id: u16, result: u8) -> Vec<u8> {
        let mut m = Vec::with_capacity(OUTGOING_CALL_REPLY_LEN);
        m.extend_from_slice(&(OUTGOING_CALL_REPLY_LEN as u16).to_be_bytes()); // Length
        m.extend_from_slice(&MSG_TYPE_CONTROL.to_be_bytes()); // PPTP Message Type
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes()); // Magic Cookie
        m.extend_from_slice(&CTRL_OUTGOING_CALL_REPLY.to_be_bytes()); // Control Message Type
        m.extend_from_slice(&0u16.to_be_bytes()); // Reserved0
        m.extend_from_slice(&call_id.to_be_bytes()); // Call ID (sender's)
        m.extend_from_slice(&peer_call_id.to_be_bytes()); // Peer's Call ID
        m.push(result); // Result Code
        m.push(0); // Error Code
        m.extend_from_slice(&0u16.to_be_bytes()); // Cause Code
        m.extend_from_slice(&0u32.to_be_bytes()); // Connect Speed
        m.extend_from_slice(&0u16.to_be_bytes()); // Recv Window Size
        m.extend_from_slice(&0u16.to_be_bytes()); // Processing Delay
        m.extend_from_slice(&0u32.to_be_bytes()); // Physical Channel ID
        assert_eq!(m.len(), OUTGOING_CALL_REPLY_LEN, "fixture must match the RFC length");
        m
    }
}

#[cfg(test)]
mod tests_7699 {
    use super::fixtures_7699::outgoing_call_reply;
    use super::*;

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    /// The pair comes out, and each call id is attributed to the RIGHT peer.
    ///
    /// The attribution is asserted through `resolve`, not by reading the struct:
    /// a data packet is keyed on its DESTINATION, so this is the property the
    /// dataplane actually depends on. Reading the fields back would pass with
    /// the two ids swapped.
    #[test]
    fn a_call_reply_yields_the_pair_attributed_to_the_right_peers_7699() {
        let (s, d) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let msg = outgoing_call_reply(0xAAAA, 0xBBBB, RESULT_CONNECTED);
        let call = learn_from_control_segment(s, d, &msg).expect("a connected reply must learn");

        let mut table = crate::session::pptp::PptpAssociations::default();
        let handle = table.install(call).expect("install");
        assert_eq!(
            table.resolve(s, 0xAAAA),
            Some(handle),
            "the reply's own Call ID belongs to its SENDER, so a packet sent TO \\
             the sender carries it"
        );
        assert_eq!(
            table.resolve(d, 0xBBBB),
            Some(handle),
            "Peer's Call ID belongs to the DESTINATION"
        );
        assert_eq!(
            table.resolve(s, 0xBBBB),
            None,
            "the ids must not both resolve under one peer; that is the swapped \\
             attribution, which looks identical until a reply goes unmatched"
        );
    }

    /// A call that did NOT connect must not be learned.
    ///
    /// Installing an association for a failed call puts state in the table for
    /// a call that does not exist, and its 16-bit ids are then reserved against
    /// a future call that reuses them.
    #[test]
    fn a_failed_call_reply_is_not_learned_7699() {
        let (s, d) = (ip("198.51.100.7"), ip("203.0.113.9"));
        for result in [0u8, 2, 3, 7] {
            let msg = outgoing_call_reply(0xAAAA, 0xBBBB, result);
            assert_eq!(parse_control_segment(&msg), ControlParse::Ignored);
            assert!(learn_from_control_segment(s, d, &msg).is_none());
        }
        // CONTROL: the same message with Result Code 1 IS learned, so the
        // assertion above is about the result code and not about a fixture that
        // never parses.
        let ok = outgoing_call_reply(0xAAAA, 0xBBBB, RESULT_CONNECTED);
        assert!(learn_from_control_segment(s, d, &ok).is_some());
    }

    /// The single-segment bound, and its DESIGNED degradation.
    ///
    /// A split message is `Truncated`, distinct from `Ignored`: nothing is
    /// wrong with the stream, this parser simply does not reassemble. It learns
    /// nothing, so the call's data packets take the unassociated path — forward
    /// and count — rather than anything undefined.
    #[test]
    fn a_message_split_across_segments_is_truncated_not_misparsed_7699() {
        let full = outgoing_call_reply(0xAAAA, 0xBBBB, RESULT_CONNECTED);
        for cut in [12usize, 13, 16, 20, OUTGOING_CALL_REPLY_LEN - 1] {
            let partial = &full[..cut];
            assert_eq!(
                parse_control_segment(partial),
                ControlParse::Truncated,
                "a {cut}-byte prefix must report Truncated"
            );
            assert!(
                learn_from_control_segment(
                    ip("198.51.100.7"),
                    ip("203.0.113.9"),
                    partial
                )
                .is_none(),
                "a truncated message must learn nothing"
            );
        }
    }

    /// A DECLARED length longer than the bytes present must not read past the
    /// slice.
    ///
    /// The declared length is attacker-controlled. This is the case a parser
    /// that trusts it panics on — and a panic here is a dead AF_XDP worker.
    #[test]
    fn a_lying_declared_length_does_not_read_past_the_segment_7699() {
        let mut m = outgoing_call_reply(0xAAAA, 0xBBBB, RESULT_CONNECTED);
        m.truncate(CONTROL_HEADER_LEN + 2); // claims 32, carries 14
        assert_eq!(parse_control_segment(&m), ControlParse::Truncated);
    }

    /// Not-PPTP is rejected before any field is read by offset.
    #[test]
    fn non_pptp_bytes_are_not_control_7699() {
        assert_eq!(parse_control_segment(&[]), ControlParse::NotControl);
        assert_eq!(parse_control_segment(&[0u8; 8]), ControlParse::NotControl);

        let mut bad_cookie = outgoing_call_reply(1, 2, RESULT_CONNECTED);
        bad_cookie[4] ^= 0xFF;
        assert_eq!(parse_control_segment(&bad_cookie), ControlParse::NotControl);

        let mut bad_msg_type = outgoing_call_reply(1, 2, RESULT_CONNECTED);
        bad_msg_type[3] = 9;
        assert_eq!(parse_control_segment(&bad_msg_type), ControlParse::NotControl);
    }

    /// A control message of another type is Ignored, not misread.
    #[test]
    fn another_control_message_type_is_ignored_7699() {
        let mut other = outgoing_call_reply(1, 2, RESULT_CONNECTED);
        other[8..10].copy_from_slice(&7u16.to_be_bytes()); // Outgoing-Call-Request
        assert_eq!(parse_control_segment(&other), ControlParse::Ignored);
    }
}
