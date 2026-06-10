use super::*;

/// Parsed embedded inner IPv4 header + first 8 bytes of L4 (enough to
/// recover ports / icmp echo id). IP address octets are recovered
/// directly from the frame; L4 port fields are decoded from
/// big-endian wire bytes into host-order `u16` for convenient
/// comparison and key construction.
pub(in crate::afxdp::icmp_embed) struct EmbeddedV4Header {
    pub proto: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub l4_off: usize,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Parsed embedded inner IPv6 header + first 8 bytes of L4.
///
/// `src_wire` is the on-the-wire (untranslated) source address —
/// NPTv6 inbound translation, if any, MUST be applied at the call
/// site (see `nat_match_v6.rs`, mirroring `icmp_embed.rs:358-360`).
/// The parser does not translate. L4 port fields are decoded from
/// big-endian wire bytes into host-order `u16` like
/// `EmbeddedV4Header`.
pub(in crate::afxdp::icmp_embed) struct EmbeddedV6Header {
    pub proto: u8,
    pub src_wire: Ipv6Addr,
    pub dst: IpAddr,
    pub l4_off: usize,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Parse the embedded IPv4 header starting at `embedded_ip_start`.
/// Returns None on truncated frame or malformed IHL.
pub(in crate::afxdp::icmp_embed) fn parse_embedded_v4(
    frame: &[u8],
    embedded_ip_start: usize,
) -> Option<EmbeddedV4Header> {
    if frame.len() < embedded_ip_start + 28 {
        return None;
    }
    let ihl = ((frame[embedded_ip_start] & 0x0F) as usize) * 4;
    if ihl < 20 || frame.len() < embedded_ip_start + ihl + 4 {
        return None;
    }
    let proto = frame[embedded_ip_start + 9];
    let src = Ipv4Addr::new(
        frame[embedded_ip_start + 12],
        frame[embedded_ip_start + 13],
        frame[embedded_ip_start + 14],
        frame[embedded_ip_start + 15],
    );
    let dst = Ipv4Addr::new(
        frame[embedded_ip_start + 16],
        frame[embedded_ip_start + 17],
        frame[embedded_ip_start + 18],
        frame[embedded_ip_start + 19],
    );
    let l4_off = embedded_ip_start + ihl;
    let (src_port, dst_port) = if matches!(proto, PROTO_TCP | PROTO_UDP) {
        let bytes = frame.get(l4_off..l4_off + 4)?;
        (
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
        )
    } else if matches!(proto, PROTO_ICMP) {
        let bytes = frame.get(l4_off + 4..l4_off + 6)?;
        (u16::from_be_bytes([bytes[0], bytes[1]]), 0)
    } else {
        (0, 0)
    };
    Some(EmbeddedV4Header {
        proto,
        src,
        dst,
        l4_off,
        src_port,
        dst_port,
    })
}

/// Fragment-aware IPv6 extension-chain walk for QUOTED (embedded)
/// packets inside ICMPv6 errors (#1838 / plan §5.7). Walks the chain
/// like `packet_rel_l4_offset_and_protocol(.., AF_INET6)` but, on the
/// fragment header (44), reads the fragment-offset bits and returns
/// `None` unless they are zero: a quoted NON-FIRST fragment has no L4
/// header, and reading "ports" from its payload bytes would enable
/// false NAT/session matches (the bug class the old fixed-40 read
/// accidentally avoided by leaving proto = 44). First and atomic
/// fragments (offset 0) are allowed. Returns the L4 offset relative
/// to the embedded IPv6 header plus the final L4 protocol.
pub(in crate::afxdp::icmp_embed) fn parse_embedded_v6_l4(packet: &[u8]) -> Option<(usize, u8)> {
    if packet.len() < 40 {
        return None;
    }
    let mut protocol = *packet.get(6)?;
    let mut offset = 40usize;
    for _ in 0..6 {
        match protocol {
            0 | 43 | 60 => {
                let opt = packet.get(offset..offset + 2)?;
                protocol = opt[0];
                offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
                if packet.len() < offset {
                    return None;
                }
            }
            51 => {
                let opt = packet.get(offset..offset + 2)?;
                protocol = opt[0];
                offset = offset.checked_add((usize::from(opt[1]) + 2) * 4)?;
                if packet.len() < offset {
                    return None;
                }
            }
            44 => {
                let frag = packet.get(offset..offset + 8)?;
                // Fragment Offset = upper 13 bits of bytes 2..4
                // (RFC 8200 §4.5). Non-zero => non-first fragment =>
                // no L4 header in the quoted bytes.
                if (u16::from_be_bytes([frag[2], frag[3]]) & 0xFFF8) != 0 {
                    return None;
                }
                protocol = frag[0];
                offset = offset.checked_add(8)?;
                if packet.len() < offset {
                    return None;
                }
            }
            59 => return None,
            _ => return Some((offset, protocol)),
        }
    }
    Some((offset, protocol))
}

/// Parse the embedded IPv6 header starting at `embedded_ip_start`.
/// Returns None on truncated frame or when the quoted packet is a
/// non-first fragment (no L4 header — see `parse_embedded_v6_l4`).
/// The L4 offset and final protocol come from the fragment-aware
/// extension-chain walk (#1838 — previously a fixed
/// `embedded_ip_start + 40` with the raw next-header byte, which made
/// embedded-ext quoted packets parse as proto = ext-type and silently
/// never match their session). NPTv6 translation is NOT applied
/// here — the caller must do that on `src_wire` if needed.
pub(in crate::afxdp::icmp_embed) fn parse_embedded_v6(
    frame: &[u8],
    embedded_ip_start: usize,
) -> Option<EmbeddedV6Header> {
    if frame.len() < embedded_ip_start + 48 {
        return None;
    }
    let (rel_l4, proto) = parse_embedded_v6_l4(frame.get(embedded_ip_start..)?)?;
    let src_wire = Ipv6Addr::from(
        <[u8; 16]>::try_from(&frame[embedded_ip_start + 8..embedded_ip_start + 24]).ok()?,
    );
    let dst = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&frame[embedded_ip_start + 24..embedded_ip_start + 40]).ok()?,
    ));
    let l4_off = embedded_ip_start + rel_l4;
    let (src_port, dst_port) = if matches!(proto, PROTO_TCP | PROTO_UDP) {
        let bytes = frame.get(l4_off..l4_off + 4)?;
        (
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
        )
    } else if matches!(proto, PROTO_ICMPV6) {
        let bytes = frame.get(l4_off + 4..l4_off + 6)?;
        (u16::from_be_bytes([bytes[0], bytes[1]]), 0)
    } else {
        (0, 0)
    };
    Some(EmbeddedV6Header {
        proto,
        src_wire,
        dst,
        l4_off,
        src_port,
        dst_port,
    })
}

/// Build the embedded reply key — the session-table key for the
/// "reverse direction" of the embedded packet. For TCP/UDP this swaps
/// src/dst ports; for ICMP/ICMPv6 the echo id stays in place.
pub(in crate::afxdp::icmp_embed) fn embedded_reply_key(
    addr_family: u8,
    protocol: u8,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
) -> SessionKey {
    let (reply_src_port, reply_dst_port) = embedded_reply_ports(protocol, src_port, dst_port);
    SessionKey {
        addr_family,
        protocol,
        src_ip: dst_ip,
        dst_ip: src_ip,
        src_port: reply_src_port,
        dst_port: reply_dst_port,
    }
}

pub(in crate::afxdp::icmp_embed) fn embedded_reply_ports(
    protocol: u8,
    src_port: u16,
    dst_port: u16,
) -> (u16, u16) {
    if matches!(protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (src_port, dst_port)
    } else {
        (dst_port, src_port)
    }
}

#[cfg(test)]
mod embedded_v6_parse_tests {
    use super::*;

    /// Build a minimal embedded IPv6 packet: base header + optional
    /// extension headers + 8 bytes of TCP (ports + seq).
    fn embedded_v6(ext: &[(u8, Vec<u8>)], final_proto: u8) -> Vec<u8> {
        // ext: list of (type_byte, full encoded header bytes); each
        // header's byte 0 (next header) is patched below.
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        let mut chain_types: Vec<u8> = ext.iter().map(|(t, _)| *t).collect();
        chain_types.push(final_proto);
        p[6] = chain_types[0];
        p[7] = 64; // hop limit
        p[8..24].copy_from_slice(&[0x20; 16]); // src
        p[24..40].copy_from_slice(&[0x30; 16]); // dst
        for (i, (_, bytes)) in ext.iter().enumerate() {
            let mut b = bytes.clone();
            b[0] = chain_types[i + 1];
            p.extend_from_slice(&b);
        }
        // 8 bytes of L4: TCP ports 0x1111 / 0x2222 + 4 seq bytes.
        p.extend_from_slice(&[0x11, 0x11, 0x22, 0x22, 0, 0, 0, 1]);
        let plen = (p.len() - 40) as u16;
        p[4..6].copy_from_slice(&plen.to_be_bytes());
        p
    }

    #[test]
    fn embedded_ext_chain_recovers_true_proto_and_ports() {
        // hop-by-hop (8 bytes) before TCP: the old fixed-40 read saw
        // proto = 0 and garbage ports; the walk recovers TCP at 48.
        let hbh = (0u8, vec![0u8, 0, 0, 0, 0, 0, 0, 0]);
        let p = embedded_v6(&[hbh], PROTO_TCP);
        let (rel, proto) = parse_embedded_v6_l4(&p).expect("walk succeeds");
        assert_eq!((rel, proto), (48, PROTO_TCP));

        let hdr = parse_embedded_v6(&p, 0).expect("parse succeeds");
        assert_eq!(hdr.proto, PROTO_TCP);
        assert_eq!(hdr.l4_off, 48);
        assert_eq!((hdr.src_port, hdr.dst_port), (0x1111, 0x2222));
    }

    #[test]
    fn embedded_first_or_atomic_fragment_allowed() {
        // Fragment header with offset 0 (atomic / first fragment):
        // the L4 header IS present in the quoted bytes — match allowed.
        for m_flag in [0u8, 1u8] {
            let frag = (44u8, vec![0u8, 0, 0x00, m_flag, 0, 0, 0, 1]);
            let p = embedded_v6(&[frag], PROTO_TCP);
            let (rel, proto) =
                parse_embedded_v6_l4(&p).expect("first/atomic fragment walks to L4");
            assert_eq!((rel, proto), (48, PROTO_TCP));
            let hdr = parse_embedded_v6(&p, 0).expect("parse succeeds");
            assert_eq!((hdr.src_port, hdr.dst_port), (0x1111, 0x2222));
        }
    }

    #[test]
    fn embedded_non_first_fragment_never_matches() {
        // Non-first fragment (offset bits nonzero): the "L4 bytes" are
        // payload — parse must return None so no NAT/session match can
        // form (plan §5.7 / Codex r2 medium 1). Offset 1 (0x0008) and
        // a large offset both refuse.
        for off_be in [0x0008u16, 0xABC8] {
            let mut frag_bytes = vec![0u8, 0, 0, 0, 0, 0, 0, 1];
            frag_bytes[2..4].copy_from_slice(&off_be.to_be_bytes());
            let frag = (44u8, frag_bytes);
            let p = embedded_v6(&[frag], PROTO_TCP);
            assert_eq!(
                parse_embedded_v6_l4(&p),
                None,
                "non-first fragment (offset {off_be:#06x}) must not expose payload as ports"
            );
            assert!(
                parse_embedded_v6(&p, 0).is_none(),
                "parse_embedded_v6 must refuse a quoted non-first fragment"
            );
        }
    }

    #[test]
    fn embedded_no_ext_unchanged() {
        // Ext-free quoted packet: identical result to the old fixed-40
        // read (regression guard for the common case).
        let p = embedded_v6(&[], PROTO_TCP);
        let hdr = parse_embedded_v6(&p, 0).expect("parse succeeds");
        assert_eq!(hdr.proto, PROTO_TCP);
        assert_eq!(hdr.l4_off, 40);
        assert_eq!((hdr.src_port, hdr.dst_port), (0x1111, 0x2222));
    }
}
