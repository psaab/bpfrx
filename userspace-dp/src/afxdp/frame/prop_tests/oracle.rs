//! P-N2 — test-local full-recompute checksum validity oracle + the
//! shared masked byte-equality helper (#1824 plan §5.3-S2).
//!
//! NOT `verify_built_frame_checksums`: that helper early-returns
//! `(true, true)` for everything except IPv4 TCP (frame/mod.rs:1129
//! "Only handle IPv4 TCP for now") and would make the v6/UDP arms
//! vacuous.
//!
//! Validity is checked the receiver's way: the one's-complement sum of
//! the protected words INCLUDING the stored checksum field must fold
//! to 0xFFFF (`checksum16(..) == 0`). That acceptance test is
//! naturally insensitive to the 0x0000/0xFFFF zero-encoding ambiguity
//! (#1839 / RFC 1624) — both encodings of one's-complement zero
//! verify — which is exactly the contract the two rewrite paths
//! actually promise.

use super::*;

/// Validate the L3 packet (no Ethernet header) at a *known* L4 offset.
/// `rel_l4` comes from generator ground truth, never from the parsers
/// under test. `v4_udp_zero_ok` permits the RFC 768 "no checksum"
/// encoding (only ever true for v4 UDP inputs built that way).
pub(super) fn oracle_packet_valid(
    packet: &[u8],
    addr_family: u8,
    protocol: u8,
    rel_l4: usize,
    v4_udp_zero_ok: bool,
) -> Result<(), String> {
    if addr_family == strategies::AF4 {
        if packet.len() < 20 {
            return Err("v4 packet shorter than 20".into());
        }
        let ihl = usize::from(packet[0] & 0x0f) * 4;
        if ihl != rel_l4 {
            return Err(format!("ihl {ihl} != expected rel_l4 {rel_l4}"));
        }
        if packet.len() < ihl {
            return Err("v4 packet shorter than IHL".into());
        }
        // IP header: stored checksum included, must fold to zero.
        if checksum16(&packet[..ihl]) != 0 {
            return Err(format!(
                "v4 IP header checksum invalid (stored {:#06x})",
                u16::from_be_bytes([packet[10], packet[11]])
            ));
        }
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if total_len < ihl || total_len > packet.len() {
            return Err(format!(
                "v4 total_len {total_len} out of range (ihl {ihl}, len {})",
                packet.len()
            ));
        }
        let seg = &packet[ihl..total_len];
        let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        match protocol {
            PROTO_TCP => {
                if seg.len() < 20 {
                    return Err("v4 TCP segment shorter than 20".into());
                }
                if checksum16_ipv4(src, dst, PROTO_TCP, seg) != 0 {
                    return Err("v4 TCP checksum invalid".into());
                }
            }
            PROTO_UDP => {
                if seg.len() < 8 {
                    return Err("v4 UDP segment shorter than 8".into());
                }
                let stored = u16::from_be_bytes([seg[6], seg[7]]);
                if stored == 0 {
                    if !v4_udp_zero_ok {
                        return Err("v4 UDP checksum became 0 unexpectedly".into());
                    }
                } else if checksum16_ipv4(src, dst, PROTO_UDP, seg) != 0 {
                    return Err("v4 UDP checksum invalid".into());
                }
            }
            PROTO_ICMP => {
                if seg.len() < 8 {
                    return Err("v4 ICMP segment shorter than 8".into());
                }
                if checksum16(seg) != 0 {
                    return Err("v4 ICMP checksum invalid".into());
                }
            }
            _ => {}
        }
        Ok(())
    } else if addr_family == strategies::AF6 {
        if packet.len() < 40 {
            return Err("v6 packet shorter than 40".into());
        }
        let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
        let end = 40 + payload_len;
        if rel_l4 < 40 || rel_l4 > end || end > packet.len() {
            return Err(format!(
                "v6 lengths out of range (rel_l4 {rel_l4}, payload_len {payload_len}, len {})",
                packet.len()
            ));
        }
        // L4 segment excludes any extension headers; the pseudo-header
        // upper-layer length is the L4 segment length (RFC 8200 §8.1).
        let seg = &packet[rel_l4..end];
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
        match protocol {
            PROTO_TCP => {
                if seg.len() < 20 {
                    return Err("v6 TCP segment shorter than 20".into());
                }
                if checksum16_ipv6(src, dst, PROTO_TCP, seg) != 0 {
                    return Err("v6 TCP checksum invalid".into());
                }
            }
            PROTO_UDP => {
                if seg.len() < 8 {
                    return Err("v6 UDP segment shorter than 8".into());
                }
                let stored = u16::from_be_bytes([seg[6], seg[7]]);
                if stored == 0 {
                    return Err("v6 UDP stored checksum is 0x0000 (RFC 8200 violation)".into());
                }
                if checksum16_ipv6(src, dst, PROTO_UDP, seg) != 0 {
                    return Err("v6 UDP checksum invalid".into());
                }
            }
            PROTO_ICMPV6 => {
                if seg.len() < 8 {
                    return Err("v6 ICMPv6 segment shorter than 8".into());
                }
                if checksum16_ipv6(src, dst, PROTO_ICMPV6, seg) != 0 {
                    return Err("v6 ICMPv6 checksum invalid".into());
                }
            }
            _ => {}
        }
        Ok(())
    } else {
        Err(format!("oracle: unsupported address family {addr_family}"))
    }
}

/// Byte ranges (relative to the L3 start) where a rewrite may
/// legitimately change the encoding without changing the value — the
/// checksum fields. Used by P-N1's apply+undo round trip, which
/// restores the checksum VALUE class but is not
/// representation-stable for one's-complement zero.
///
/// - v4: IP header checksum (10..12) + L4 checksum.
/// - v6: L4 checksum only (no IP header checksum).
///
/// NOT used by P-N3 anymore: since the #1838/#1839/#1840 trio fix the
/// descriptor and generic paths agree byte-for-byte (the computed-zero
/// canonicalization is predicate-scoped on both, the RFC 768 skip is
/// family-gated on both, and the §5.5 no-op-port rule closes the
/// stored-zero identity corner), so the differential runs with an
/// EMPTY mask.
pub(super) fn checksum_byte_ranges(
    addr_family: u8,
    protocol: u8,
    rel_l4: usize,
) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    if addr_family == strategies::AF4 {
        out.push(10..12);
    }
    let l4_csum = match protocol {
        PROTO_TCP => Some(rel_l4 + 16),
        PROTO_UDP => Some(rel_l4 + 6),
        PROTO_ICMP | PROTO_ICMPV6 => Some(rel_l4 + 2),
        _ => None,
    };
    if let Some(off) = l4_csum {
        out.push(off..off + 2);
    }
    out
}

/// Assert two equal-length byte slices are identical outside the
/// excluded ranges. Returns the first differing offset for shrink
/// readability instead of panicking, so property bodies can
/// `prop_assert!` on it.
pub(super) fn first_diff_outside(
    a: &[u8],
    b: &[u8],
    excluded: &[std::ops::Range<usize>],
) -> Option<usize> {
    debug_assert_eq!(a.len(), b.len());
    'bytes: for i in 0..a.len().min(b.len()) {
        if a[i] == b[i] {
            continue;
        }
        for range in excluded {
            if range.contains(&i) {
                continue 'bytes;
            }
        }
        return Some(i);
    }
    None
}
