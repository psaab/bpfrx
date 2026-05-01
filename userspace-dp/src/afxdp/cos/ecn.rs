// #956 Phase 1: ECN marking + Ethernet L3 parser, extracted from
// tx.rs. The threshold constants `COS_ECN_MARK_THRESHOLD_NUM/_DEN`
// and the admission policy `apply_cos_admission_ecn_policy` moved
// with admission to `cos/admission.rs` in Phase 3 (Phase 2 was
// flow_hash; correct dependency direction — a byte-mutation
// module should not own admission tuning).
//
// ECN-marker unit tests now live in this file (`mod tests` at
// the bottom). Pre-#984 P3 phase 2c they lived in `tx::tests` via
// the `cos/mod.rs` re-exports; that pattern is now retired for
// helpers in this module. Admission-path tests still live in
// `tx::tests` because they share larger fixtures.

use crate::afxdp::ethernet::{ETH_HDR_LEN, VLAN_TAG_LEN};
use crate::afxdp::types::{PreparedTxRequest, TxRequest};
use crate::afxdp::umem::MmapArea;

/// ECN codepoint masks (low 2 bits of IPv4 TOS / IPv6 tclass).
///
/// `pub(in crate::afxdp)` because admission tests in
/// `cos/admission.rs::tests` reference these masks directly.
pub(in crate::afxdp) const ECN_MASK: u8 = 0b0000_0011;
pub(in crate::afxdp) const ECN_NOT_ECT: u8 = 0b0000_0000;
pub(in crate::afxdp) const ECN_ECT_0: u8 = 0b0000_0010;
pub(in crate::afxdp) const ECN_ECT_1: u8 = 0b0000_0001;
pub(in crate::afxdp) const ECN_CE: u8 = 0b0000_0011;

/// Parsed L3 discriminator + offset from a forwarded Ethernet frame.
/// Carries both pieces together so the ECN mark path dispatches off the
/// bytes it actually parsed, not the `expected_addr_family` sideband —
/// a malformed frame whose sideband says AF_INET but whose ethertype
/// says something else must not get its "TOS byte" stamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::afxdp) enum EthernetL3 {
    Ipv4(usize),
    Ipv6(usize),
}

/// Parse the outer Ethernet header, transparently walk a single 802.1Q
/// / 802.1ad VLAN tag, and report the L3 family + header offset. The
/// CoS admission path sees frames post-forward-build, so VLAN tags
/// from tagged subinterfaces (e.g. `reth0 unit 80`) are already
/// present. Callers use the returned family to dispatch to the
/// matching ECN marker and the offset to locate the TOS / tclass byte.
///
/// Returns `None` for:
/// - buffers shorter than the parse requires (no slice-out-of-bounds
///   panic on the hot path),
/// - non-IP ethertypes (including ARP, MPLS, and the tail of a QinQ
///   stack) — we refuse to guess rather than stamp a byte that is not
///   a TOS / tclass byte,
/// - nested VLAN tags (QinQ / 802.1ad-over-Q) — not implemented yet;
///   adding support means one more 4-byte hop plus recursive inner-
///   ethertype inspection. The single-tag path covers the only lab
///   fixture we currently exercise.
///
/// Historically this helper just returned an offset, and dispatch was
/// based on `expected_addr_family`. The gap that exposed was: if the
/// sideband said AF_INET but the frame was ARP-inside-VLAN, we would
/// still compute offset = 18 and stamp byte 19 inside the ARP body.
/// Returning the parsed family here closes that drift permanently —
/// the marker cannot disagree with the wire bytes it is mutating.
#[inline]
pub(in crate::afxdp) fn ethernet_l3(bytes: &[u8]) -> Option<EthernetL3> {
    if bytes.len() < ETH_HDR_LEN {
        return None;
    }
    let outer = u16::from_be_bytes([bytes[12], bytes[13]]);
    match outer {
        0x0800 => Some(EthernetL3::Ipv4(ETH_HDR_LEN)),
        0x86DD => Some(EthernetL3::Ipv6(ETH_HDR_LEN)),
        // 802.1Q / 802.1ad single VLAN tag. The inner ethertype lives
        // 4 bytes after the outer one; if that inner ethertype is
        // *itself* a VLAN TPID we have a QinQ stack that we do not
        // support yet — reject it rather than stamping into an inner
        // tag.
        0x8100 | 0x88A8 => {
            let inner_off = ETH_HDR_LEN + VLAN_TAG_LEN;
            // Inner ethertype lives at bytes[inner_off-2..inner_off],
            // so we only need `bytes.len() >= inner_off`. The downstream
            // markers (`mark_ecn_ce_ipv4` / `_ipv6`) have their own
            // bounds checks for the IP header itself; the parser must
            // not over-reject frames that ARE long enough to identify
            // the L3 family (Copilot review on PR #976).
            if bytes.len() < inner_off {
                return None;
            }
            let inner = u16::from_be_bytes([bytes[inner_off - 2], bytes[inner_off - 1]]);
            match inner {
                0x0800 => Some(EthernetL3::Ipv4(inner_off)),
                0x86DD => Some(EthernetL3::Ipv6(inner_off)),
                // QinQ or unknown inner — refuse to guess.
                _ => None,
            }
        }
        _ => None,
    }
}

/// Mark the IPv4 packet at `l3_offset` within `bytes` as ECN CE if it
/// is already ECT(0) or ECT(1). Updates the IP header checksum
/// incrementally (RFC 1624). Returns true iff the packet was marked.
/// Never modifies a NOT-ECT packet (protects non-ECN flows per RFC
/// 3168 section 6.1.1.1).
#[inline]
pub(in crate::afxdp) fn mark_ecn_ce_ipv4(bytes: &mut [u8], l3_offset: usize) -> bool {
    // Need the full 20-byte base IPv4 header (through the checksum field).
    // Short buffers are returned false rather than panicking — this path
    // runs per admission on the hot path and cannot trust upstream
    // length validation to have covered every corner.
    let end = l3_offset.saturating_add(20);
    if bytes.len() < end {
        return false;
    }
    let tos_idx = l3_offset + 1;
    let old_tos = bytes[tos_idx];
    let ecn = old_tos & ECN_MASK;
    // Branchless: only ECT(0) and ECT(1) cross to CE; NOT-ECT and CE
    // are left unchanged. A non-ECT packet returning false routes into
    // the existing admission drop path unchanged.
    if ecn != ECN_ECT_0 && ecn != ECN_ECT_1 {
        return false;
    }
    let new_tos = (old_tos & !ECN_MASK) | ECN_CE;
    bytes[tos_idx] = new_tos;

    // RFC 1624 incremental checksum update for a single byte change to
    // the TOS field (16-bit word = [version/IHL, TOS]). The header
    // checksum sits at l3_offset+10..l3_offset+12 in network byte order.
    //
    //   HC' = ~(~HC + ~m + m')
    //
    // where m and m' are the 16-bit words at the mutated position. The
    // version/IHL byte is unchanged so it cancels inside `old_word` /
    // `new_word` — but keeping it in the word avoids a conditional on
    // which half of the 16-bit word we touched.
    let ihl = bytes[l3_offset];
    let old_word = ((ihl as u32) << 8) | old_tos as u32;
    let new_word = ((ihl as u32) << 8) | new_tos as u32;
    let csum_idx = l3_offset + 10;
    let old_csum = ((bytes[csum_idx] as u32) << 8) | bytes[csum_idx + 1] as u32;
    // ~HC + ~m + m' in 32-bit arithmetic, then fold carries.
    let mut sum = (!old_csum & 0xffff) + (!old_word & 0xffff) + new_word;
    // Fold any carries out of the low 16 bits. Two folds are sufficient
    // for the three 16-bit addends above (max ~3 * 0xffff fits in 18
    // bits, one fold collapses to 17 bits, second to 16 bits).
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let new_csum = (!sum) & 0xffff;
    bytes[csum_idx] = (new_csum >> 8) as u8;
    bytes[csum_idx + 1] = (new_csum & 0xff) as u8;
    true
}

/// Mark the IPv6 packet at `l3_offset` within `bytes` as ECN CE if it
/// is already ECT(0) or ECT(1). IPv6 has no header checksum so no
/// incremental update is needed. Returns true iff the packet was marked.
#[inline]
pub(in crate::afxdp) fn mark_ecn_ce_ipv6(bytes: &mut [u8], l3_offset: usize) -> bool {
    // tclass spans the low nibble of byte[l3_offset] and the high
    // nibble of byte[l3_offset+1]. We need both bytes in range.
    let end = l3_offset.saturating_add(2);
    if bytes.len() < end {
        return false;
    }
    // Version/tclass-high byte: [vvvv tttt]. ECN bits are the low 2
    // bits of tclass, which sit in the high nibble of byte[l3_offset+1]
    // as bits 5..4. Extract with a simple shift-mask.
    let b1 = bytes[l3_offset + 1];
    let ecn = (b1 >> 4) & ECN_MASK;
    if ecn != ECN_ECT_0 && ecn != ECN_ECT_1 {
        return false;
    }
    // Clear the old ECN bits (bits 5..4 of byte[l3_offset+1]) and OR in
    // CE shifted into place.
    let cleared = b1 & !(ECN_MASK << 4);
    bytes[l3_offset + 1] = cleared | (ECN_CE << 4);
    true
}

/// Dispatch ECN marking based on the L3 protocol family parsed
/// from the TxRequest's bytes (NOT the `expected_addr_family`
/// sideband — see the dispatch body for the rationale). Returns
/// true iff the packet was marked.
#[inline]
pub(in crate::afxdp) fn maybe_mark_ecn_ce(req: &mut TxRequest) -> bool {
    // Dispatch off the parsed Ethernet header, not the sideband
    // `expected_addr_family`. The sideband is populated at RX time and
    // can drift for injected or re-queued frames whose wire bytes got
    // rewritten (e.g. NAT64, tunnel transit). Trusting the parse keeps
    // the marker from stamping the wrong protocol body on any frame
    // where the two disagree.
    match ethernet_l3(&req.bytes) {
        Some(EthernetL3::Ipv4(l3_offset)) => mark_ecn_ce_ipv4(&mut req.bytes, l3_offset),
        Some(EthernetL3::Ipv6(l3_offset)) => mark_ecn_ce_ipv6(&mut req.bytes, l3_offset),
        None => false,
    }
}

/// Mark a prepared (zero-copy) TX frame as ECN CE in place inside the
/// UMEM. Only fires on ECT(0)/ECT(1) per RFC 3168 §6.1.1.1. Returns
/// true iff the packet was marked. Out-of-range offset/len pairs
/// (e.g. a PreparedTxRequest that somehow escaped bounds checks)
/// return false without panicking — the caller falls through into
/// the existing admission path unchanged.
///
/// This is the Prepared-variant counterpart to `maybe_mark_ecn_ce`;
/// #718 / #722 originally only handled the Local variant, leaving
/// the XSK-RX→XSK-TX zero-copy hot path (iperf3, NAT'd flows) with
/// the marker dormant. See `docs/cos-validation-notes.md` for the
/// counter-reading methodology.
///
/// # Safety
///
/// The caller must hold exclusive access to the frame at
/// `[req.offset, req.offset + req.len)` within `umem`. On the CoS
/// admission path this is guaranteed: admission runs *before* the
/// frame is enqueued into the CoS queue, let alone submitted to the
/// XSK TX ring, so the worker that built the frame is still the sole
/// owner. Callers that invoke this outside of the admission gate
/// must provide the same guarantee.
#[inline]
pub(in crate::afxdp) fn maybe_mark_ecn_ce_prepared(
    req: &PreparedTxRequest,
    umem: &MmapArea,
) -> bool {
    let offset = req.offset as usize;
    let len = req.len as usize;
    // SAFETY: see function-level doc. The admission path owns the
    // frame until `cos_queue_push_back` takes it, which is strictly
    // after this call. Out-of-range slices return None (handled
    // below) rather than producing a dangling reference.
    let Some(bytes) = (unsafe { umem.slice_mut_unchecked(offset, len) }) else {
        return false;
    };
    // Same rationale as `maybe_mark_ecn_ce`: dispatch off the parsed
    // wire bytes, not `expected_addr_family`. See that helper's
    // comment for the drift scenarios this protects against.
    match ethernet_l3(bytes) {
        Some(EthernetL3::Ipv4(l3_offset)) => mark_ecn_ce_ipv4(bytes, l3_offset),
        Some(EthernetL3::Ipv6(l3_offset)) => mark_ecn_ce_ipv6(bytes, l3_offset),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::afxdp::tx::test_support::*;
    use crate::afxdp::PROTO_TCP;

    #[test]
    fn mark_ecn_ce_ipv4_converts_ect0_to_ce_and_updates_checksum() {
        // ECT(0) = 0b10 in the low 2 bits of the TOS byte. Pick a
        // non-zero DSCP (0x28 = CS5 = expedited forwarding) to verify
        // the upper 6 bits survive the mark. TOS before = 0xa2.
        let tos = (0x28u8 << 2) | ECN_ECT_0;
        let mut pkt = build_ipv4_test_packet(tos);
        assert_eq!(ipv4_tos(&pkt), 0xa2);
        let csum_before = ipv4_checksum(&pkt);

        assert!(mark_ecn_ce_ipv4(&mut pkt, 14));

        // Low 2 bits now CE, upper 6 bits (DSCP) unchanged.
        assert_eq!(ipv4_tos(&pkt) & ECN_MASK, ECN_CE);
        assert_eq!(ipv4_tos(&pkt) >> 2, 0x28);
        // Checksum must differ from the before-state (ECN flipped one
        // bit in the low byte) AND be valid from scratch.
        assert_ne!(
            ipv4_checksum(&pkt),
            csum_before,
            "ECN bit flip must change the IP checksum",
        );
        assert_eq!(
            ipv4_checksum(&pkt),
            compute_ipv4_header_checksum(&pkt[14..34]),
            "incremental checksum must match a from-scratch recompute",
        );
    }

    #[test]
    fn mark_ecn_ce_ipv4_converts_ect1_to_ce_and_updates_checksum() {
        // ECT(1) = 0b01. DSCP = 0, so TOS starts at 0x01 — stresses
        // the case where the high nibble is zero and only the low
        // bits mutate.
        let tos = ECN_ECT_1;
        let mut pkt = build_ipv4_test_packet(tos);

        assert!(mark_ecn_ce_ipv4(&mut pkt, 14));
        assert_eq!(ipv4_tos(&pkt), ECN_CE);
        assert_eq!(
            ipv4_checksum(&pkt),
            compute_ipv4_header_checksum(&pkt[14..34]),
        );
    }

    #[test]
    fn mark_ecn_ce_ipv4_leaves_not_ect_untouched() {
        // NOT-ECT packet must be left entirely alone — RFC 3168 6.1.1.1
        // forbids forcing ECN on flows that did not negotiate it.
        let tos = 0xb8; // DSCP 46 (EF), ECN = 00
        let mut pkt = build_ipv4_test_packet(tos);
        let before = pkt.clone();

        assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));
        assert_eq!(pkt, before, "NOT-ECT packet must be byte-identical");
    }

    #[test]
    fn mark_ecn_ce_ipv4_leaves_ce_untouched() {
        // CE already — idempotent: function reports "not marked" but
        // also doesn't re-write the checksum, so bytes stay identical.
        let tos = 0xb8 | ECN_CE;
        let mut pkt = build_ipv4_test_packet(tos);
        let before = pkt.clone();

        assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));
        assert_eq!(pkt, before, "CE packet must be byte-identical");
    }

    #[test]
    fn mark_ecn_ce_ipv4_rejects_short_buffer() {
        // Buffer too short to hold a full 20-byte IPv4 header starting
        // at l3_offset=14 (only 33 bytes — one short). Must return
        // false and not panic.
        let mut pkt = vec![0u8; 33];
        assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));

        // Also exercise the case where `l3_offset` itself pushes past
        // the buffer end.
        let mut pkt = vec![0u8; 16];
        assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));
    }

    #[test]
    fn mark_ecn_ce_ipv6_converts_ect0_to_ce() {
        // DSCP 46 (EF) + ECT(0) → full tclass 0xba.
        let tclass = (0x2eu8 << 2) | ECN_ECT_0;
        let mut pkt = build_ipv6_test_packet(tclass);
        assert_eq!(ipv6_tclass(&pkt), 0xba);
        // Preserve flow label / version bits for the round-trip check.
        let version_nibble_before = pkt[14] & 0xf0;
        let flow_label_low_before = pkt[15] & 0x0f;

        assert!(mark_ecn_ce_ipv6(&mut pkt, 14));
        assert_eq!(ipv6_tclass(&pkt) & ECN_MASK, ECN_CE);
        assert_eq!(ipv6_tclass(&pkt) >> 2, 0x2e);
        // Version + flow-label bits must not drift.
        assert_eq!(pkt[14] & 0xf0, version_nibble_before);
        assert_eq!(pkt[15] & 0x0f, flow_label_low_before);
    }

    #[test]
    fn mark_ecn_ce_ipv6_converts_ect1_to_ce() {
        let tclass = ECN_ECT_1;
        let mut pkt = build_ipv6_test_packet(tclass);
        assert!(mark_ecn_ce_ipv6(&mut pkt, 14));
        assert_eq!(ipv6_tclass(&pkt), ECN_CE);
    }

    #[test]
    fn mark_ecn_ce_ipv6_leaves_not_ect_untouched() {
        let tclass = 0xb8; // DSCP 46, ECN 00
        let mut pkt = build_ipv6_test_packet(tclass);
        let before = pkt.clone();
        assert!(!mark_ecn_ce_ipv6(&mut pkt, 14));
        assert_eq!(pkt, before);
    }

    #[test]
    fn mark_ecn_ce_ipv6_leaves_ce_untouched() {
        let tclass = 0xb8 | ECN_CE;
        let mut pkt = build_ipv6_test_packet(tclass);
        let before = pkt.clone();
        assert!(!mark_ecn_ce_ipv6(&mut pkt, 14));
        assert_eq!(pkt, before);
    }

    #[test]
    fn mark_ecn_ce_ipv6_rejects_short_buffer() {
        let mut pkt = vec![0u8; 15];
        assert!(!mark_ecn_ce_ipv6(&mut pkt, 14));
    }

    #[test]
    fn maybe_mark_ecn_ce_dispatches_by_ethertype() {
        // IPv4 dispatch: ECT(0) → CE.
        let tos = ECN_ECT_0;
        let bytes = build_ipv4_test_packet(tos);
        let mut req = TxRequest {
            bytes,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        };
        assert!(maybe_mark_ecn_ce(&mut req));
        assert_eq!(req.bytes[15] & ECN_MASK, ECN_CE);

        // IPv6 dispatch: ECT(1) → CE.
        let tclass = ECN_ECT_1;
        let bytes = build_ipv6_test_packet(tclass);
        let mut req = TxRequest {
            bytes,
            expected_ports: None,
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        };
        assert!(maybe_mark_ecn_ce(&mut req));
        assert_eq!(ipv6_tclass(&req.bytes), ECN_CE);

        // Unknown ethertype: no-op (and no panic). The all-zeros
        // packet has zero in the ethertype slot, so `ethernet_l3`
        // returns None and the marker bails. Note: dispatch is
        // driven by the parsed L2 ethertype, not by
        // `expected_addr_family` — that field is metadata only.
        let mut req = TxRequest {
            bytes: vec![0u8; 64],
            expected_ports: None,
            expected_addr_family: 0,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        };
        assert!(!maybe_mark_ecn_ce(&mut req));
    }

    /// Regression pin for the VLAN-tagged admission path discovered in
    /// the #727 live validation: a single 802.1Q tag (ethertype 0x8100)
    /// pushes L3 four bytes deeper. `maybe_mark_ecn_ce` must detect
    /// that via `ethernet_l3` and still mark the ECN bits at
    /// the correct offset rather than stamping into the VLAN TCI.
    #[test]
    fn maybe_mark_ecn_ce_handles_single_vlan_tagged_frame() {
        // Build a standard IPv4 test packet, then splice a 4-byte VLAN
        // tag between the MAC addresses and the ethertype. The result
        // is: 6 dst + 6 src + TPID(0x8100) + TCI(VID=80, prio=5) +
        //     EthType(0x0800) + <20-byte IPv4 header>.
        let tos = ECN_ECT_0;
        let base = build_ipv4_test_packet(tos);
        let mut tagged = Vec::with_capacity(base.len() + 4);
        tagged.extend_from_slice(&base[..12]); // dst + src MAC
        tagged.extend_from_slice(&[0x81, 0x00]); // TPID
        // TCI: priority 5 << 13 | DEI 0 | VID 80.
        let tci: u16 = (5 << 13) | 80;
        tagged.extend_from_slice(&tci.to_be_bytes());
        tagged.extend_from_slice(&[0x08, 0x00]); // inner ethertype (IPv4)
        tagged.extend_from_slice(&base[14..]); // IPv4 header + payload

        // Confirm `ethernet_l3` parses IPv4 at offset 18 for this frame.
        assert_eq!(ethernet_l3(&tagged), Some(EthernetL3::Ipv4(18)));

        let mut req = TxRequest {
            bytes: tagged,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };
        assert!(
            maybe_mark_ecn_ce(&mut req),
            "VLAN-tagged ECT(0) frame must be marked at the VLAN-shifted L3 offset"
        );
        // TOS byte sits at l3_offset + 1 = 19 in the tagged frame.
        assert_eq!(req.bytes[19] & ECN_MASK, ECN_CE);
        // And critically: the VLAN TCI bytes must NOT have been
        // mutated — if the old hardcoded offset 14 had hit, the "ECN
        // bits" we'd have touched are inside the VLAN priority nibble
        // at byte 15, which we assert stayed intact.
        let tci_after = u16::from_be_bytes([req.bytes[14], req.bytes[15]]);
        assert_eq!(
            tci_after, tci,
            "VLAN TCI must be untouched by ECN marking"
        );
    }

    /// Counter-factual: ethertype 0 (or anything we don't understand)
    /// returns `None` from `ethernet_l3`, so marking is a no-op.
    /// Guards against a regression that defaults to offset 14 on
    /// unknown frames.
    #[test]
    fn maybe_mark_ecn_ce_rejects_unknown_ethertype() {
        let mut req = TxRequest {
            bytes: {
                let mut b = build_ipv4_test_packet(ECN_ECT_0);
                b[12] = 0x12;
                b[13] = 0x34;
                b
            },
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        };
        assert_eq!(ethernet_l3(&req.bytes), None);
        assert!(!maybe_mark_ecn_ce(&mut req));
        // ECT(0) bits at the would-have-been-wrong-offset untouched.
        assert_eq!(req.bytes[15] & ECN_MASK, ECN_ECT_0);
    }

    /// QinQ (0x88A8 outer + 0x8100 inner) must be rejected rather than
    /// guessed at, because L3 actually lives at offset 22 on those
    /// frames and a default to 18 would stamp into the inner VLAN TCI.
    /// #728 review pin: once we've paid to parse the outer ethertype,
    /// the parse must be the source of truth.
    #[test]
    fn ethernet_l3_rejects_qinq_until_explicitly_supported() {
        let base = build_ipv4_test_packet(ECN_ECT_0);
        let mut qinq = Vec::with_capacity(base.len() + 8);
        qinq.extend_from_slice(&base[..12]); // MACs
        // Outer 802.1ad: TPID 0x88A8, TCI with an outer VID 100.
        qinq.extend_from_slice(&[0x88, 0xA8]);
        let outer_tci: u16 = 100;
        qinq.extend_from_slice(&outer_tci.to_be_bytes());
        // Inner 802.1Q: TPID 0x8100 at the "inner ethertype" position.
        qinq.extend_from_slice(&[0x81, 0x00]);
        let inner_tci: u16 = 80;
        qinq.extend_from_slice(&inner_tci.to_be_bytes());
        qinq.extend_from_slice(&[0x08, 0x00]); // IPv4 (well beyond where we care)
        qinq.extend_from_slice(&base[14..]);

        assert_eq!(
            ethernet_l3(&qinq),
            None,
            "QinQ (0x88A8 → 0x8100) must be rejected — inner VLAN tag not yet supported"
        );

        // And the marker refuses such a frame — no ECN bits are flipped.
        let mut req = TxRequest {
            bytes: qinq,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 1,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
        };
        assert!(!maybe_mark_ecn_ce(&mut req));
    }

    /// A VLAN-tagged frame whose inner ethertype is ARP / MPLS / etc.
    /// must be rejected too, matching the `refuse to guess` contract.
    /// Without this check we'd treat offset 18 as an IPv4 TOS byte and
    /// stamp the low 2 bits of whatever is there (ARP's hardware type
    /// in this case), corrupting the frame.
    #[test]
    fn ethernet_l3_rejects_vlan_tagged_non_ip_payload() {
        let base = build_ipv4_test_packet(ECN_ECT_0);
        let mut tagged = Vec::with_capacity(base.len() + 4);
        tagged.extend_from_slice(&base[..12]);
        tagged.extend_from_slice(&[0x81, 0x00]); // outer 802.1Q
        let tci: u16 = 80;
        tagged.extend_from_slice(&tci.to_be_bytes());
        tagged.extend_from_slice(&[0x08, 0x06]); // inner = ARP (0x0806)
        tagged.extend_from_slice(&base[14..]);
        assert_eq!(
            ethernet_l3(&tagged),
            None,
            "VLAN-tagged non-IP payload must not dispatch to an IP marker",
        );
    }

}
