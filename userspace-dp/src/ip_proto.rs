//! Canonical IANA IP protocol numbers shared across the dataplane.
//!
//! #1826: consolidates the per-module `const PROTO_*` duplicates (eight
//! files each carried their own `PROTO_TCP = 6` copy) into one crate-wide
//! home. These are load-bearing wire constants — the values must match
//! the IANA "Assigned Internet Protocol Numbers" registry and are used in
//! packet parsing, session keys, NAT/NAT64 translation, policy and filter
//! matching, and screen checks.

pub(crate) const PROTO_ICMP: u8 = 1;
pub(crate) const PROTO_IGMP: u8 = 2;
pub(crate) const PROTO_IPIP: u8 = 4;
pub(crate) const PROTO_TCP: u8 = 6;
pub(crate) const PROTO_EGP: u8 = 8;
pub(crate) const PROTO_UDP: u8 = 17;
pub(crate) const PROTO_GRE: u8 = 47;
pub(crate) const PROTO_ESP: u8 = 50;
pub(crate) const PROTO_AH: u8 = 51;
pub(crate) const PROTO_ICMPV6: u8 = 58;
pub(crate) const PROTO_OSPF: u8 = 89;
pub(crate) const PROTO_PIM: u8 = 103;
pub(crate) const PROTO_VRRP: u8 = 112;
pub(crate) const PROTO_SCTP: u8 = 132;

/// Resolve a config-level protocol token to its IANA number.
///
/// #2396: the DNAT snapshot carries `protocol` as the Junos config string
/// (`"tcp"`, `"udp"`, `"icmp"`, `"icmp6"`/`"icmpv6"`, `"gre"`, ..., or a bare
/// 0-255 number). The Rust DNAT table used to recognize only `"tcp"`/`"udp"`
/// and silently DROP everything else (`_ => continue`), so a GRE/ICMP DNAT
/// rule compiled, committed, and never reached the dataplane. This resolver
/// mirrors the Go SSOT `appid.ProtocolNumber` (the table the commit-time gate
/// validates against) so the two views agree on the accepted set.
///
/// `junos-*` aliases are NOT handled here: the Go compiler resolves an
/// `application junos-foo` to its numeric protocol before building the
/// snapshot, so the wire `protocol` is already a bare name or number. Returns
/// `None` for an unrecognized token; the DNAT commit gate
/// (validateDestinationNATProtocolStrict, #2396) rejects an unresolvable DNAT
/// protocol so an inert rule never reaches the wire, and the dataplane drops
/// any that slip through a tolerant load.
///
/// #2396 (Copilot fold): the token is trimmed and lower-cased before matching.
/// DNAT `match protocol` and an `application`'s `protocol` reach the wire
/// VERBATIM from the parser (`nodeVal`) — neither the parser nor the snapshot
/// builder normalizes — so a config `protocol GRE` or `protocol " icmp "`
/// would otherwise resolve to nothing here and be silently dropped. The Go
/// commit gate normalizes the same way (strings.TrimSpace + ToLower) before
/// validating, so the two views agree on the accepted set after normalization.
pub(crate) fn proto_number(name: &str) -> Option<u8> {
    match name.trim().to_ascii_lowercase().as_str() {
        "tcp" => Some(PROTO_TCP),
        "udp" => Some(PROTO_UDP),
        "icmp" => Some(PROTO_ICMP),
        "icmp6" | "icmpv6" => Some(PROTO_ICMPV6),
        "gre" => Some(PROTO_GRE),
        "ospf" => Some(PROTO_OSPF),
        "ipip" => Some(PROTO_IPIP),
        "egp" => Some(PROTO_EGP),
        "igmp" => Some(PROTO_IGMP),
        "pim" => Some(PROTO_PIM),
        "ah" => Some(PROTO_AH),
        "esp" => Some(PROTO_ESP),
        "sctp" => Some(PROTO_SCTP),
        "vrrp" => Some(PROTO_VRRP),
        other => other.parse::<u8>().ok(),
    }
}
