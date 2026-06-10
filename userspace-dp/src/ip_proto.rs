//! Canonical IANA IP protocol numbers shared across the dataplane.
//!
//! #1826: consolidates the per-module `const PROTO_*` duplicates (eight
//! files each carried their own `PROTO_TCP = 6` copy) into one crate-wide
//! home. These are load-bearing wire constants — the values must match
//! the IANA "Assigned Internet Protocol Numbers" registry and are used in
//! packet parsing, session keys, NAT/NAT64 translation, policy and filter
//! matching, and screen checks.

pub(crate) const PROTO_ICMP: u8 = 1;
pub(crate) const PROTO_IPIP: u8 = 4;
pub(crate) const PROTO_TCP: u8 = 6;
pub(crate) const PROTO_UDP: u8 = 17;
pub(crate) const PROTO_GRE: u8 = 47;
pub(crate) const PROTO_ESP: u8 = 50;
pub(crate) const PROTO_ICMPV6: u8 = 58;
pub(crate) const PROTO_OSPF: u8 = 89;
