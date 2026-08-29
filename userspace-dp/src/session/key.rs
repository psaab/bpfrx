// SessionKey + key-transform helpers extracted from session.rs (#1047 P2).
// Pure relocation — bodies are byte-for-byte identical except
// `reverse_wire_key` widened from `fn` (file-private) to
// `pub(super) fn` so session/mod.rs's SessionTable impl can still
// call it across the new module boundary.

use super::*;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct SessionKey {
    pub addr_family: u8,
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// #7188: the tunnel discriminator that participates in session identity
    /// for protocols with no L4 ports. `None` for every protocol that has no
    /// discriminator concept, which is everything but GRE — so this field
    /// leaves every existing protocol's identity byte-for-byte unchanged, and
    /// the `Hash`/`Eq` derives above keep doing the right thing for free.
    ///
    /// It is NOT a port: it is never matchable, never rendered in a port field,
    /// and never encoded onto a wire that carries ports (#7188 decision 5).
    pub discriminator: TunnelDiscriminator,
}

pub(crate) fn reply_matches_forward_session(
    forward_key: &SessionKey,
    nat: NatDecision,
    reply_key: &SessionKey,
) -> bool {
    reverse_wire_key(forward_key, nat) == *reply_key
        || reverse_canonical_key(forward_key, nat) == *reply_key
}

pub(crate) fn forward_wire_key(forward_key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(forward_key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        // #4074: the ICMP Query Identifier lives in `src_port` (`dst_port` is
        // always 0) and is a single symmetric field carried at the same offset
        // in both directions. Pool SNAT translates it (RFC 5508 §3.1), so the
        // forward wire key carries the translated id when the decision set one;
        // absent a translation this is `forward_key.src_port` — unchanged.
        (
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
            forward_key.dst_port,
        )
    } else {
        (
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
            nat.rewrite_dst_port.unwrap_or(forward_key.dst_port),
        )
    };
    let wire_src = nat.rewrite_src.unwrap_or(forward_key.src_ip);
    let wire_dst = nat.rewrite_dst.unwrap_or(forward_key.dst_ip);
    let (addr_family, protocol) = if nat.nat64 {
        let af = match wire_src {
            std::net::IpAddr::V4(_) => libc::AF_INET as u8,
            std::net::IpAddr::V6(_) => libc::AF_INET6 as u8,
        };
        let proto = if af == libc::AF_INET as u8 && forward_key.protocol == PROTO_ICMPV6 {
            PROTO_ICMP
        } else if af == libc::AF_INET6 as u8 && forward_key.protocol == PROTO_ICMP {
            PROTO_ICMPV6
        } else {
            forward_key.protocol
        };
        (af, proto)
    } else {
        (forward_key.addr_family, forward_key.protocol)
    };
    SessionKey {
        addr_family,
        protocol,
        src_ip: wire_src,
        dst_ip: wire_dst,
        src_port,
        dst_port,
            discriminator: Default::default(),
    }
}

pub(crate) fn translated_session_key(key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        // #4074: translate the ICMP Query Identifier (in `src_port`) like a
        // port; `dst_port` stays 0. No translation => `key.src_port` unchanged.
        (nat.rewrite_src_port.unwrap_or(key.src_port), key.dst_port)
    } else {
        (
            nat.rewrite_src_port.unwrap_or(key.src_port),
            nat.rewrite_dst_port.unwrap_or(key.dst_port),
        )
    };
    SessionKey {
        addr_family: key.addr_family,
        protocol: key.protocol,
        src_ip: nat.rewrite_src.unwrap_or(key.src_ip),
        dst_ip: nat.rewrite_dst.unwrap_or(key.dst_ip),
        src_port,
        dst_port,
            discriminator: Default::default(),
    }
}

pub(super) fn reverse_wire_key(forward_key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(forward_key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        // #4074: the reply carries the SAME (translated) ICMP identifier at the
        // same offset, which the parser lifts into the reply's `src_port`. So
        // the reverse wire key's `src_port` is the translated id (not swapped
        // with `dst_port` the way a TCP/UDP port pair is), and `dst_port` stays
        // 0. This is what makes two hosts sharing a pool address + original id
        // demux — their translated ids differ, so their reverse keys differ.
        (
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
            forward_key.dst_port,
        )
    } else {
        (
            nat.rewrite_dst_port.unwrap_or(forward_key.dst_port),
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
        )
    };
    let wire_src = nat.rewrite_dst.unwrap_or(forward_key.dst_ip);
    let wire_dst = nat.rewrite_src.unwrap_or(forward_key.src_ip);
    // NAT64: the reverse (reply) packet is a different address family.
    // Determine the AF from the NAT-rewritten addresses.
    let (addr_family, protocol) = if nat.nat64 {
        let af = match wire_src {
            std::net::IpAddr::V4(_) => libc::AF_INET as u8,
            std::net::IpAddr::V6(_) => libc::AF_INET6 as u8,
        };
        // ICMPv6 ↔ ICMP protocol mapping.
        let proto = if af == libc::AF_INET as u8 && forward_key.protocol == PROTO_ICMPV6 {
            PROTO_ICMP
        } else if af == libc::AF_INET6 as u8 && forward_key.protocol == PROTO_ICMP {
            PROTO_ICMPV6
        } else {
            forward_key.protocol
        };
        (af, proto)
    } else {
        (forward_key.addr_family, forward_key.protocol)
    };
    SessionKey {
        addr_family,
        protocol,
        src_ip: wire_src,
        dst_ip: wire_dst,
        src_port,
        dst_port,
            discriminator: Default::default(),
    }
}

pub(crate) fn reverse_canonical_key(forward_key: &SessionKey, _nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(forward_key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (forward_key.src_port, forward_key.dst_port)
    } else {
        (forward_key.dst_port, forward_key.src_port)
    };
    SessionKey {
        addr_family: forward_key.addr_family,
        protocol: forward_key.protocol,
        src_ip: forward_key.dst_ip,
        dst_ip: forward_key.src_ip,
        src_port,
        dst_port,
            discriminator: Default::default(),
    }
}

// Issue 70 / #994: `reverse_session_key` extracted from
// afxdp/session_glue (the audit's "abstraction-leak" junk drawer).
// Pure SessionKey + NatDecision → SessionKey transformation, fits
// alongside forward_wire_key / translated_session_key /
// reverse_canonical_key already in this file. Visibility widened
// from `pub(super)` (afxdp-internal) to `pub(crate)` so existing
// callers in afxdp/{ha,session_delta,session_glue}.rs continue to
// resolve through the session::* re-export.
//
// Note: the audit also called out resolution_target_for_session as
// a candidate to move here, but it takes &SessionFlow and SessionFlow
// lives in afxdp/types (46 references inside afxdp/ — moving it
// would be a much larger refactor). Left in session_glue for now.

pub(crate) fn reverse_session_key(key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        // #4074: the ICMP Query Identifier is a symmetric field, and this
        // function is called in BOTH directions:
        //   - forward→reverse (build the reverse companion key from the FORWARD
        //     entry + its FORWARD decision): the translated id lives in
        //     `rewrite_src_port` (= Y), so the companion is keyed on Y and the
        //     reply (which carries Y) demuxes to it.
        //   - reverse→forward (`account_packet` recovers the FORWARD entry key
        //     from the REVERSE entry + its REVERSE decision, session/mod.rs):
        //     `NatDecision::reverse` moved the ORIGINAL id into
        //     `rewrite_dst_port` (= X) and left `rewrite_src_port` None, so we
        //     must read `rewrite_dst_port` to recover X and hit the forward
        //     entry — reading only `rewrite_src_port` (=None → falls back to the
        //     reverse key's Y) misses it and mis-accounts the reply volume onto
        //     the reverse entry.
        // At most one of the two port fields is ever set for an ICMP flow (SNAT
        // sets only `rewrite_src_port` forward; its `.reverse()` sets only
        // `rewrite_dst_port`; ICMP DNAT is gated to no L4 port), so `.or()`
        // picks the right id in each direction. No translation => `key.src_port`
        // unchanged; `dst_port` stays 0.
        (
            nat.rewrite_src_port
                .or(nat.rewrite_dst_port)
                .unwrap_or(key.src_port),
            key.dst_port,
        )
    } else {
        (
            nat.rewrite_dst_port.unwrap_or(key.dst_port),
            nat.rewrite_src_port.unwrap_or(key.src_port),
        )
    };
    let wire_src = nat.rewrite_dst.unwrap_or(key.dst_ip);
    let wire_dst = nat.rewrite_src.unwrap_or(key.src_ip);
    let (addr_family, protocol) = if nat.nat64 {
        let af = match wire_src {
            IpAddr::V4(_) => libc::AF_INET as u8,
            IpAddr::V6(_) => libc::AF_INET6 as u8,
        };
        let proto = if af == libc::AF_INET as u8 && key.protocol == PROTO_ICMPV6 {
            PROTO_ICMP
        } else if af == libc::AF_INET6 as u8 && key.protocol == PROTO_ICMP {
            PROTO_ICMPV6
        } else {
            key.protocol
        };
        (af, proto)
    } else {
        (key.addr_family, key.protocol)
    };
    SessionKey {
        addr_family,
        protocol,
        src_ip: wire_src,
        dst_ip: wire_dst,
        src_port,
        dst_port,
            discriminator: Default::default(),
    }
}
