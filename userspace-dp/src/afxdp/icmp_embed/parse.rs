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

/// Parse the embedded IPv6 header starting at `embedded_ip_start`.
/// Returns None on truncated frame. NPTv6 translation is NOT applied
/// here — the caller must do that on `src_wire` if needed.
pub(in crate::afxdp::icmp_embed) fn parse_embedded_v6(
    frame: &[u8],
    embedded_ip_start: usize,
) -> Option<EmbeddedV6Header> {
    if frame.len() < embedded_ip_start + 48 {
        return None;
    }
    let proto = frame[embedded_ip_start + 6];
    let src_wire = Ipv6Addr::from(
        <[u8; 16]>::try_from(&frame[embedded_ip_start + 8..embedded_ip_start + 24]).ok()?,
    );
    let dst = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&frame[embedded_ip_start + 24..embedded_ip_start + 40]).ok()?,
    ));
    let l4_off = embedded_ip_start + 40;
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
