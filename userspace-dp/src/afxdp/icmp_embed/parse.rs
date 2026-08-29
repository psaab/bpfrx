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
/// Returns None on truncated frame, malformed IHL, or when the QUOTED
/// packet is a non-first fragment.
///
/// #1852: a quoted non-first fragment (IPv4 fragment-offset field, low
/// 13 bits of bytes 6-7, non-zero) has no L4 header — reading "ports" at
/// `ihl` would interpret payload bytes as ports and could enable a false
/// embedded-session match. This is the IPv4 twin of the #1853
/// fragment-aware `parse_embedded_v6_l4` guard (it was deferred to this
/// follow-up). First/atomic fragments (offset 0) carry the real L4
/// header and parse normally.
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
    // #1852: refuse a quoted non-first fragment (no L4 header to read).
    let frag_off =
        u16::from_be_bytes([frame[embedded_ip_start + 6], frame[embedded_ip_start + 7]]);
    if (frag_off & 0x1FFF) != 0 {
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
    // #5568: bound the quoted-inner L4 read by the QUOTED IPv4 datagram's
    // declared total-length, not merely the outer backing frame. An ICMP error
    // whose outer frame carries slack/padding beyond the quoted datagram's
    // declared length would otherwise have those bytes read as inner ports — a
    // manufactured embedded-session tuple that could touch an existing session.
    // The quoted datagram ends at `embedded_ip_start + total_len`; the port read
    // must lie within it. A quote whose declared length legitimately EXCEEDS the
    // available bytes (an RFC-792 minimum, intentionally truncated quote) is NOT
    // rejected: `total_len` is large, so the window check passes and `frame.get`
    // then bounds the read to what is actually present.
    let inner_total =
        u16::from_be_bytes([frame[embedded_ip_start + 2], frame[embedded_ip_start + 3]]) as usize;
    let inner_declared_end = embedded_ip_start.saturating_add(inner_total);
    let (src_port, dst_port) = if matches!(proto, PROTO_TCP | PROTO_UDP) {
        if l4_off.saturating_add(4) > inner_declared_end {
            return None;
        }
        let bytes = frame.get(l4_off..l4_off + 4)?;
        (
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
        )
    } else if matches!(proto, PROTO_ICMP) {
        if l4_off.saturating_add(6) > inner_declared_end {
            return None;
        }
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
/// packets inside ICMPv6 errors (#1838 / plan §5.7). #6435: folds the ONE
/// canonical walker (`walk_ipv6_ext_chain`, shared with the forwarding
/// path's `packet_rel_l4_offset_and_protocol(.., AF_INET6)`); #6513-review:
/// judges EVERY sighted Fragment header (not just the recorded first) via
/// `ExtChainWalk::non_first_fragment_offset_seen`, restoring the pre-#6435
/// every-header verdict — a quoted NON-FIRST fragment has no L4 header, and
/// reading "ports" from its payload bytes would enable false NAT/session
/// matches (the bug class the old fixed-40 read accidentally avoided by
/// leaving proto = 44). First and atomic fragments (offset 0) are allowed.
/// Returns the L4 offset relative to the embedded IPv6 header plus the
/// final L4 protocol.
pub(in crate::afxdp::icmp_embed) fn parse_embedded_v6_l4(packet: &[u8]) -> Option<(usize, u8)> {
    let walk = walk_ipv6_ext_chain(packet, 0);
    // #1838: a quoted NON-FIRST fragment has no L4 header in the quoted
    // bytes — judged across EVERY Fragment header sighted, so a hostile
    // [Frag(off=0)][Frag(off!=0)][TCP] chain cannot smuggle the second
    // header's payload bytes past this resolver as "ports" (the first-
    // sighting-only check let exactly that through). A declared-but-
    // truncated Fragment header (offset bits unreadable) is NOT rejected
    // here — it fails closed on the `Truncated` outcome below instead,
    // exactly like the pre-#6435 walker's `packet.get(offset..offset + 8)?`
    // (both yield `None`).
    if walk.non_first_fragment_offset_seen {
        return None;
    }
    // #4533: every non-L4 verdict fails CLOSED (None) — an over-bound
    // chain (`OverLimit`, still on an extension header at the
    // MAX_IPV6_EXT_HEADERS bound) never surrenders the unconsumed
    // ext-header offset/type as a fake embedded L4, aligning this walker
    // with the #2292 forwarding walker and the #4435 NAT64 walkers by
    // construction (#6435: they now share the loop, not just the bound).
    match walk.outcome {
        ExtChainOutcome::L4(offset, protocol) => Some((offset, protocol)),
        _ => None,
    }
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
    // #5568: bound BOTH the quoted-inner extension-header walk AND the L4 read by
    // the QUOTED IPv6 datagram's declared length (`embedded_ip_start + 40 +
    // payload_len`), clamped to the available quote bytes — not the raw outer
    // frame. Otherwise outer-frame slack/padding beyond the quoted datagram could
    // be walked as ext headers and read as inner ports (a manufactured
    // embedded-session tuple). A truncated RFC-minimum quote whose declared
    // `payload_len` exceeds the available bytes is NOT rejected: the clamp keeps
    // the slice at `frame.len()` there, identical to the pre-#5568 read.
    let inner_payload_len =
        u16::from_be_bytes([frame[embedded_ip_start + 4], frame[embedded_ip_start + 5]]) as usize;
    let inner_declared_end = embedded_ip_start
        .saturating_add(40)
        .saturating_add(inner_payload_len)
        .min(frame.len());
    let (rel_l4, proto) = parse_embedded_v6_l4(frame.get(embedded_ip_start..inner_declared_end)?)?;
    let src_wire = Ipv6Addr::from(
        <[u8; 16]>::try_from(&frame[embedded_ip_start + 8..embedded_ip_start + 24]).ok()?,
    );
    let dst = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&frame[embedded_ip_start + 24..embedded_ip_start + 40]).ok()?,
    ));
    let l4_off = embedded_ip_start + rel_l4;
    let (src_port, dst_port) = if matches!(proto, PROTO_TCP | PROTO_UDP) {
        if l4_off.saturating_add(4) > inner_declared_end {
            return None;
        }
        let bytes = frame.get(l4_off..l4_off + 4)?;
        (
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
        )
    } else if matches!(proto, PROTO_ICMPV6) {
        if l4_off.saturating_add(6) > inner_declared_end {
            return None;
        }
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
            discriminator: Default::default(),
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
    fn embedded_mobility_hip_shim6_headers_recover_true_proto() {
        // #4517: an ICMPv6 error that quotes an inner packet whose chain
        // hides the L4 behind a Mobility (135) / HIP (139) / Shim6 (140)
        // extension header must still resolve the embedded TCP so the
        // return-path session/NAT match can form. Before #4517 the walk
        // stopped at type 135/139/140 and reported proto=135 with garbage
        // ports (parity gap vs the canonical afxdp walker).
        for exotic in [135u8, 139u8, 140u8] {
            let eh = (exotic, vec![0u8, 0, 0, 0, 0, 0, 0, 0]); // 8-byte generic EH
            let p = embedded_v6(&[eh], PROTO_TCP);
            let (rel, proto) = parse_embedded_v6_l4(&p)
                .unwrap_or_else(|| panic!("walk past EH type {exotic} must succeed"));
            assert_eq!((rel, proto), (48, PROTO_TCP));
            let hdr = parse_embedded_v6(&p, 0).expect("parse succeeds");
            assert_eq!(hdr.proto, PROTO_TCP);
            assert_eq!((hdr.src_port, hdr.dst_port), (0x1111, 0x2222));
        }
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
    fn embedded_double_fragment_chain_never_matches() {
        // #6513 hostile-review pin: a (RFC 8200-non-conformant) chain with
        // a SECOND Fragment header carrying non-zero offset bits must fail
        // closed — the pre-#6435 walker judged EVERY sighted Fragment
        // header; judging only the recorded first sighting let
        // [Frag(off=0)][Frag(off!=0)][TCP] smuggle the second header's
        // payload past this resolver as "ports" (fail-open on the #1838
        // gate). Every-header judgement is restored via
        // ExtChainWalk::non_first_fragment_offset_seen.
        let frag_first = (44u8, vec![44u8, 0, 0, 0, 0, 0, 0, 1]); // next=44, offset 0
        let mut second_bytes = vec![PROTO_TCP, 0, 0, 0, 0, 0, 0, 1];
        second_bytes[2..4].copy_from_slice(&0x0008u16.to_be_bytes()); // offset != 0
        let frag_second = (44u8, second_bytes);
        let p = embedded_v6(&[frag_first.clone(), frag_second], PROTO_TCP);
        assert_eq!(
            parse_embedded_v6_l4(&p),
            None,
            "a second Fragment header with non-zero offset must refuse the chain"
        );
        assert!(
            parse_embedded_v6(&p, 0).is_none(),
            "parse_embedded_v6 must refuse the double-fragment chain"
        );
        // Control: the same two-header chain with offset 0 in BOTH
        // Fragment headers walks to L4 at 40 + 8 + 8 = 56.
        let frag_second_ok = (44u8, vec![PROTO_TCP, 0, 0, 0, 0, 0, 0, 1]);
        let p_ok = embedded_v6(&[frag_first, frag_second_ok], PROTO_TCP);
        let (rel, proto) =
            parse_embedded_v6_l4(&p_ok).expect("all-atomic fragments walk to L4");
        assert_eq!((rel, proto), (56, PROTO_TCP));
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

    #[test]
    fn embedded_seven_ext_headers_still_resolve() {
        // #4533: the bound was bumped from a stale 6 to the shared
        // MAX_IPV6_EXT_HEADERS (8), so a quoted inner packet with up to
        // 7 extension headers (incl the #4517 Mobility/HIP/Shim6/exp
        // exotics) still walks to its terminal L4 — parity with the
        // forwarding/screen/nat64 siblings. The old 6-bound stopped at
        // the 7th header and reported it as a bogus proto.
        let ehs: Vec<(u8, Vec<u8>)> = [0u8, 43, 60, 135, 139, 140, 253]
            .iter()
            .map(|&t| (t, vec![0u8, 0, 0, 0, 0, 0, 0, 0]))
            .collect();
        assert_eq!(ehs.len(), MAX_IPV6_EXT_HEADERS - 1);
        let p = embedded_v6(&ehs, PROTO_TCP);
        let (rel, proto) = parse_embedded_v6_l4(&p).expect("7 ext headers within bound resolve");
        assert_eq!((rel, proto), (40 + 7 * 8, PROTO_TCP));
        let hdr = parse_embedded_v6(&p, 0).expect("parse succeeds");
        assert_eq!(hdr.proto, PROTO_TCP);
        assert_eq!(hdr.l4_off, 40 + 7 * 8);
        assert_eq!((hdr.src_port, hdr.dst_port), (0x1111, 0x2222));
    }

    #[test]
    fn embedded_ext_chain_overflow_fails_closed() {
        // #4533: a quoted inner packet with MORE extension headers than
        // MAX_IPV6_EXT_HEADERS must FAIL CLOSED (None) rather than
        // surrendering the ext-header offset/type as a fake embedded L4.
        // Before #4533 the walk stopped at the 6-iteration bound and fell
        // through to `Some((offset, ext_type))`, returning a bogus proto
        // that could not match a real session (fail-SAFE) but diverged
        // from the #2292/#4435 fail-closed doctrine the siblings enforce.
        let ehs: Vec<(u8, Vec<u8>)> = [0u8, 43, 60, 135, 139, 140, 253, 254]
            .iter()
            .map(|&t| (t, vec![0u8, 0, 0, 0, 0, 0, 0, 0]))
            .collect();
        assert_eq!(ehs.len(), MAX_IPV6_EXT_HEADERS);
        let p = embedded_v6(&ehs, PROTO_TCP);
        assert_eq!(
            parse_embedded_v6_l4(&p),
            None,
            "a chain longer than MAX_IPV6_EXT_HEADERS must fail closed"
        );
        assert!(
            parse_embedded_v6(&p, 0).is_none(),
            "parse_embedded_v6 must refuse an over-bound quoted chain"
        );
    }

    #[test]
    fn embedded_esp_stops_walk() {
        // ESP (50) is deliberately NOT walked (encrypted payload,
        // unreadable inner next-header): the walk STOPS at it and reports
        // proto=ESP rather than descending. Preserved across the #4533
        // bound/fail-closed change — ESP hits the terminal `_` arm and
        // returns early, before the loop bound or the post-loop None.
        let esp = crate::ip_proto::PROTO_ESP;
        // ESP directly after the base header.
        let (rel, proto) =
            parse_embedded_v6_l4(&embedded_v6(&[], esp)).expect("ESP resolves at base L4 offset");
        assert_eq!((rel, proto), (40, esp));
        // ESP behind one hop-by-hop header — the walk advances through the
        // EH then STOPS at ESP (offset 48), never reading the payload.
        let hbh = (0u8, vec![0u8, 0, 0, 0, 0, 0, 0, 0]);
        let (rel, proto) =
            parse_embedded_v6_l4(&embedded_v6(&[hbh], esp)).expect("ESP after one EH resolves");
        assert_eq!((rel, proto), (48, esp));
    }

    // #5568 IPv6 sibling (embedded-session tuple from slack): a quoted inner
    // IPv6 datagram declaring payload_len 0 (declared datagram = 40 bytes, NO L4)
    // whose next-header is TCP. Outer-frame slack past byte 40 forges ports. The
    // parser MUST bound BOTH the ext-header walk AND the L4 read by the quoted
    // datagram's declared length and refuse. Reverting to the outer-frame bound
    // returns Some(_) with the forged ports → RED.
    #[test]
    fn embedded_v6_ports_from_slack_beyond_declared_end_not_manufactured() {
        let mut inner = vec![0u8; 40];
        inner[0] = 0x60;
        inner[6] = PROTO_TCP; // next header = TCP directly
        // payload_len (bytes 4..6) stays 0 → declared datagram end = 40.
        inner[8..24].copy_from_slice(&[0x20; 16]);
        inner[24..40].copy_from_slice(&[0x30; 16]);
        // Forged ports in the outer slack beyond the declared datagram.
        inner.extend_from_slice(&[0x30, 0x39, 0x14, 0x51, 0, 0, 0, 0]);
        assert!(
            parse_embedded_v6(&inner, 0).is_none(),
            "ports in slack beyond the quoted IPv6 payload_len (0) must not be read"
        );
    }

    // #5568 anti-over-gate (IPv6): a truncated RFC-minimum quote whose declared
    // payload_len (1280) legitimately EXCEEDS the quoted bytes must STILL parse
    // its quoted ports — the declared-length bound clamps to the available quote,
    // it does not reject a legitimately-truncated quote.
    #[test]
    fn embedded_v6_truncated_quote_still_parses() {
        let mut inner = vec![0u8; 40];
        inner[0] = 0x60;
        inner[6] = PROTO_TCP;
        inner[4..6].copy_from_slice(&1280u16.to_be_bytes()); // original datagram was large
        inner[8..24].copy_from_slice(&[0x20; 16]);
        inner[24..40].copy_from_slice(&[0x30; 16]);
        inner.extend_from_slice(&[0x11, 0x11, 0x22, 0x22, 0, 0, 0, 1]); // 8 quoted L4 bytes
        let hdr =
            parse_embedded_v6(&inner, 0).expect("truncated RFC-minimum v6 quote must still parse");
        assert_eq!((hdr.src_port, hdr.dst_port), (0x1111, 0x2222));
    }
}

#[cfg(test)]
mod embedded_v4_fragment_tests {
    use super::*;

    /// Build a minimal embedded IPv4 header (20-byte) + 8 L4 bytes.
    /// `frag_off` is the raw IPv4 fragment-offset field.
    fn embedded_v4(frag_off: u16, proto: u8) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[6..8].copy_from_slice(&frag_off.to_be_bytes());
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // 8 L4 bytes: TCP ports 0x1111 / 0x2222 + seq.
        p.extend_from_slice(&[0x11, 0x11, 0x22, 0x22, 0, 0, 0, 1]);
        p
    }

    #[test]
    fn embedded_v4_first_or_atomic_fragment_parses() {
        // offset 0 (atomic) and offset 0 + MF (first) both carry the L4
        // header in the quoted bytes — parse succeeds.
        for frag_off in [0x0000u16, 0x2000] {
            let p = embedded_v4(frag_off, PROTO_TCP);
            let hdr = parse_embedded_v4(&p, 0).expect("first/atomic fragment parses");
            assert_eq!(hdr.proto, PROTO_TCP);
            assert_eq!((hdr.src_port, hdr.dst_port), (0x1111, 0x2222));
        }
    }

    #[test]
    fn embedded_v4_non_first_fragment_refused() {
        // offset bits set: the quoted "ports" are payload — #1852 guard
        // (the IPv4 twin of #1853's parse_embedded_v6_l4) returns None.
        for frag_off in [0x0001u16, 0x2001, 0x1FFF] {
            let p = embedded_v4(frag_off, PROTO_TCP);
            assert!(
                parse_embedded_v4(&p, 0).is_none(),
                "quoted non-first fragment (frag_off {frag_off:#06x}) must not parse"
            );
        }
    }

    // #5568 (security — embedded-session tuple from slack): an ICMP error quotes
    // an inner IPv4 datagram declaring total-length 20 (a bare IP header, NO L4).
    // Outer-frame slack/padding beyond the quoted datagram forges TCP ports of an
    // existing session. The parser MUST bound the L4 read by the quoted IP's
    // declared total-length and refuse — else the forged ports drive a bogus
    // embedded-session/NAT match. Reverting to the outer-frame-only bound returns
    // Some(_) with the forged ports → RED (embedded axis, target-count 1).
    #[test]
    fn embedded_v4_ports_from_slack_beyond_declared_end_not_manufactured() {
        let mut inner = vec![0u8; 20];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&20u16.to_be_bytes()); // total-length 20 — no L4
        inner[9] = PROTO_TCP;
        inner[12..16].copy_from_slice(&[10, 0, 0, 1]);
        inner[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // Outer slack past the declared inner datagram: forged src/dst ports
        // (12345 / 5201) that would look like an existing session tuple.
        inner.extend_from_slice(&[0x30, 0x39, 0x14, 0x51, 0, 0, 0, 0]);
        assert!(
            parse_embedded_v4(&inner, 0).is_none(),
            "ports lie in slack beyond the quoted IP's declared total-length (20) — \
             the parser must not manufacture an embedded-session tuple from them"
        );
    }

    // #5568 anti-over-gate: a legitimate ICMP error quotes only the inner IP
    // header + first 8 bytes (RFC 792 minimum). The inner ORIGINAL total-length
    // (1500) legitimately EXCEEDS the quoted bytes — the parser must still read
    // the 8 quoted L4 bytes (ports), NOT reject the quote.
    #[test]
    fn embedded_v4_truncated_rfc_minimum_quote_still_parses() {
        let mut inner = vec![0u8; 20];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&1500u16.to_be_bytes()); // original datagram was large
        inner[9] = PROTO_TCP;
        inner[12..16].copy_from_slice(&[10, 0, 0, 1]);
        inner[16..20].copy_from_slice(&[10, 0, 0, 2]);
        inner.extend_from_slice(&[0x11, 0x11, 0x22, 0x22, 0, 0, 0, 1]); // the 8 quoted bytes
        let hdr =
            parse_embedded_v4(&inner, 0).expect("truncated RFC-minimum quote must still parse");
        assert_eq!(
            (hdr.src_port, hdr.dst_port),
            (0x1111, 0x2222),
            "the quoted ports are within the (large) declared length → read them"
        );
    }
}
