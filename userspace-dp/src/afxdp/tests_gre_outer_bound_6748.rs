//! #6748: native GRE decap must not promote bytes outside the OUTER IP
//! datagram.
//!
//! THE TITLE MISDESCRIBES THE MECHANISM, and implementing from it would fix
//! nothing. Decap does not use the frame length as the inner end:
//! `packet_trimmed_len` reads the INNER header's own declared length and fails
//! closed when it exceeds the slice, so Ethernet min-frame padding was already
//! trimmed and was never promoted. What was missing is a bound against the
//! OUTER datagram: the inner extent was capped at `frame.len() - inner_offset`,
//! and nothing cross-checked it against the outer IPv4 Total Length / IPv6
//! Payload Length.
//!
//! So the attack needs BOTH halves: a trailer appended past the outer datagram
//! AND an inner header inflated to cover it. Either alone is already refused.
//!
//! The asymmetry is what makes this an oversight rather than a design choice:
//! `gre_checksum_region` in the same file DID bound by the outer length, and
//! said so in its docstring — "so trailing Ethernet min-frame padding is
//! excluded" — while payload promotion did not. Checksummed GRE got an
//! incidental sanity check that non-checksummed GRE did not.

use super::tests_support::*;
use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::gre::try_native_gre_decap_from_frame;

/// Marker byte for the out-of-datagram trailer. Distinctive so a promotion
/// shows up as this byte appearing in a decapped payload, rather than as a
/// length mismatch that could have several causes.
const TRAILER_BYTE: u8 = 0xAA;
const TRAILER_LEN: usize = 16;

/// Rewrite an IPv4 packet's Total Length and fix its header checksum.
fn set_inner_total_len(packet: &mut [u8], total: u16) {
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[10] = 0;
    packet[11] = 0;
    let sum = checksum16(&packet[0..20]);
    packet[10] = (sum >> 8) as u8;
    packet[11] = sum as u8;
}

/// #6748 PRIMARY. A peer appends a trailer past the outer datagram and inflates
/// the inner Total Length to cover it. Those bytes must never reach the
/// decapped packet.
#[test]
fn gre_decap_refuses_an_inner_that_reaches_past_the_outer_datagram_6748() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());

    let honest = build_gre_inner_icmp_packet_v4();
    let mut lying = honest.clone();
    set_inner_total_len(&mut lying, (honest.len() + TRAILER_LEN) as u16);

    // The outer Total Length written here covers 20 + 4 + lying.len() — i.e.
    // the REAL inner extent. The trailer is appended AFTER that, so it is
    // outside the outer datagram by construction.
    let mut frame = build_gre_to_self_outer_frame_v4(0, &lying);
    let outer_end = frame.len();
    frame.extend(std::iter::repeat_n(TRAILER_BYTE, TRAILER_LEN));

    // Premise checks: without these, a decap refused for some unrelated reason
    // would read as the fix working.
    assert_eq!(
        u16::from_be_bytes([frame[14 + 2], frame[14 + 3]]) as usize,
        outer_end - 14,
        "fixture: the outer Total Length must describe the datagram WITHOUT the trailer",
    );
    assert!(
        frame.len() > outer_end,
        "fixture: the trailer must actually sit past the outer datagram",
    );

    let meta = gre_to_self_outer_meta(0, frame.len());
    let decapped = try_native_gre_decap_from_frame(&frame, meta, &forwarding);

    if let Some(d) = decapped {
        assert!(
            !d.frame.contains(&TRAILER_BYTE),
            "decap PROMOTED bytes from outside the outer IP datagram. A peer that \
             appends a trailer and inflates the inner Total Length to cover it gets \
             attacker-chosen bytes into the packet the firewall then adjudicates and \
             forwards (#6748).",
        );
        panic!(
            "decap accepted a frame whose inner header declares {} bytes while the outer \
             datagram carries only {}. The inner extent must be bounded by the OUTER \
             datagram, and an inner header that lies about it is refused, not clamped.",
            honest.len() + TRAILER_LEN,
            honest.len(),
        );
    }
}

/// #6748 NEGATIVE CONTROL, and the cell that stops the fix from being a
/// blanket rejection of trailers.
///
/// An HONEST inner with the same trailer must still decap, byte-identically.
/// Trailers are ordinary: Ethernet min-frame padding puts one on every small
/// frame, and refusing them would blackhole legitimate GRE. Without this cell,
/// "bound the inner by the outer datagram" and "reject anything with bytes
/// after the outer datagram" are indistinguishable, and the second is an
/// outage.
#[test]
fn gre_decap_still_accepts_an_honest_inner_under_a_trailer_6748() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let honest = build_gre_inner_icmp_packet_v4();

    let mut frame = build_gre_to_self_outer_frame_v4(0, &honest);
    frame.extend(std::iter::repeat_n(TRAILER_BYTE, TRAILER_LEN));

    let meta = gre_to_self_outer_meta(0, frame.len());
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
        .expect("an honest inner under trailing padding must still decap — padding is ordinary");
    assert_eq!(
        &decap.frame[decap.meta.l3_offset as usize..],
        &honest[..],
        "the decapped inner must be byte-identical to the authored one",
    );
    assert!(
        !decap.frame.contains(&TRAILER_BYTE),
        "the trailer must be trimmed, not carried",
    );
}

/// #6748 on the CHECKSUM-PRESENT path. The option-field skips move inside the
/// outer bound too, so a checksummed frame is subject to the same rule — and
/// must still accept an honest one, since `gre_checksum_region` already
/// excluded the trailer from the sum.
#[test]
fn gre_decap_checksum_present_honours_the_outer_bound_6748() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let honest = build_gre_inner_icmp_packet_v4();
    let mut lying = honest.clone();
    set_inner_total_len(&mut lying, (honest.len() + TRAILER_LEN) as u16);

    // Honest: still decaps.
    let mut ok_frame = build_gre_checksum_present_outer_frame_v4(
        0,
        crate::afxdp::gre::GRE_FLAG_CHECKSUM,
        0,
        0,
        &honest,
        false,
    );
    ok_frame.extend(std::iter::repeat_n(TRAILER_BYTE, TRAILER_LEN));
    let ok_meta = gre_to_self_outer_meta(0, ok_frame.len());
    let decap = try_native_gre_decap_from_frame(&ok_frame, ok_meta, &forwarding)
        .expect("a checksummed frame with padding must still decap");
    assert_eq!(&decap.frame[decap.meta.l3_offset as usize..], &honest[..]);

    // Lying: refused, and in particular the trailer is never promoted.
    let mut bad_frame = build_gre_checksum_present_outer_frame_v4(
        0,
        crate::afxdp::gre::GRE_FLAG_CHECKSUM,
        0,
        0,
        &lying,
        false,
    );
    bad_frame.extend(std::iter::repeat_n(TRAILER_BYTE, TRAILER_LEN));
    let bad_meta = gre_to_self_outer_meta(0, bad_frame.len());
    if let Some(d) = try_native_gre_decap_from_frame(&bad_frame, bad_meta, &forwarding) {
        assert!(
            !d.frame.contains(&TRAILER_BYTE),
            "checksum-present decap promoted out-of-datagram bytes (#6748)",
        );
        panic!("checksum-present decap accepted an inner that reaches past the outer datagram");
    }
}

/// #6748: the outer-end computation itself, for BOTH families.
///
/// The decap cells above are IPv4-only because the frame builders are; this
/// covers the v6 arm directly rather than leaving it unasserted. It also pins
/// the refuse-don't-clamp choice: a declaration longer than the capture is
/// `None`, because clamping would silently accept a header lying about its own
/// datagram — the same trust this function exists to remove.
#[test]
fn outer_datagram_end_reads_both_families_and_refuses_overdeclaration_6748() {
    // IPv4: l3 at 14, Total Length 60 -> end 74.
    let mut v4 = vec![0u8; 14];
    v4.extend_from_slice(&[0x45, 0x00]);
    v4.extend_from_slice(&60u16.to_be_bytes());
    v4.extend(std::iter::repeat_n(0u8, 60 - 4));
    v4.extend(std::iter::repeat_n(TRAILER_BYTE, 8));
    let v4_meta = gre_to_self_outer_meta(0, v4.len());
    assert_eq!(
        crate::afxdp::gre::outer_datagram_end(&v4, v4_meta),
        Some(74),
        "IPv4 outer end is l3 + Total Length, excluding the trailer",
    );

    // IPv6: l3 at 14, Payload Length 20 -> end 14 + 40 + 20 = 74.
    let mut v6 = vec![0u8; 14];
    v6.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    v6.extend_from_slice(&20u16.to_be_bytes());
    v6.extend(std::iter::repeat_n(0u8, 40 - 6 + 20));
    v6.extend(std::iter::repeat_n(TRAILER_BYTE, 8));
    let mut v6_meta = gre_to_self_outer_meta(0, v6.len());
    v6_meta.addr_family = libc::AF_INET6 as u8;
    assert_eq!(
        crate::afxdp::gre::outer_datagram_end(&v6, v6_meta),
        Some(74),
        "IPv6 outer end is l3 + 40 + Payload Length, excluding the trailer",
    );

    // Over-declaration is refused, not clamped, in both families.
    let mut short_v4 = v4[..40].to_vec();
    short_v4[14 + 2..14 + 4].copy_from_slice(&600u16.to_be_bytes());
    let short_meta = gre_to_self_outer_meta(0, short_v4.len());
    assert_eq!(
        crate::afxdp::gre::outer_datagram_end(&short_v4, short_meta),
        None,
        "an outer header declaring more than was captured must be refused",
    );
}
