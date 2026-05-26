// NAT runtime module — split per #1542.
//
// The previous single-file `userspace-dp/src/nat.rs` (~1605 LOC)
// mixed six independent concerns: NatDecision (the cross-cutting
// output type), source NAT rule parsing/matching, pool-mode port
// allocator + persistent lease state machine, destination NAT
// table, static 1:1 NAT, and pool status aggregation. The split
// localizes the allocator's rollback/release/expiration invariants
// to `allocator.rs`, keeps DNAT and static NAT tables in their own
// files, and aggregates pool status alongside the cross-cutting
// type at the module root.
//
// Submodules are intentionally private; `mod.rs` is the curated
// public namespace and re-exports the `pub(crate)` symbols that
// external callers reach as `crate::nat::*`. Cross-submodule
// internal items use `pub(super)` and are NOT re-exported here.

use std::net::IpAddr;

mod allocator;
mod destination;
mod source;
mod static_nat;
mod status;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub(crate) use allocator::{PortAllocator, PortAllocatorSnapshot};
pub(crate) use destination::{DnatKey, DnatTable, DnatValue};
pub(crate) use source::{
    match_source_nat, match_source_nat_result, match_source_nat_result_for_tuple,
    parse_source_nat_rules, parse_source_nat_rules_with_previous,
    release_source_nat_allocation, rollback_source_nat_allocation, SourceNatFailure,
    SourceNatFailureReason, SourceNatFlowKey, SourceNatLookup, SourceNatRule,
};
pub(crate) use static_nat::{StaticNatEntry, StaticNatTable};
pub(crate) use status::source_nat_pool_statuses;

/// NatDecision is the cross-cutting output type for every NAT
/// concern (DNAT, SNAT, static, NAT64, NPTv6). It lives at the
/// `nat` module root because it is the only type all submodules
/// produce or consume. Wire-serialized over the HA fabric via
/// `SessionDecision`/`SessionDelta`; field shape and derive set
/// must be preserved bit-for-bit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NatDecision {
    pub(crate) rewrite_src: Option<IpAddr>,
    pub(crate) rewrite_dst: Option<IpAddr>,
    pub(crate) rewrite_src_port: Option<u16>,
    pub(crate) rewrite_dst_port: Option<u16>,
    /// When true, this is a NAT64 cross-address-family translation.
    /// The forward session key is IPv6 and the reverse session key is IPv4
    /// (or vice versa for the return direction).
    pub(crate) nat64: bool,
    /// When true, this is an NPTv6 (RFC 6296) stateless prefix translation.
    /// No L4 checksum update is needed -- the prefix rewrite is checksum-neutral.
    pub(crate) nptv6: bool,
}

impl NatDecision {
    pub(crate) fn reverse(
        self,
        original_src: IpAddr,
        original_dst: IpAddr,
        original_src_port: u16,
        original_dst_port: u16,
    ) -> Self {
        Self {
            rewrite_src: self.rewrite_dst.map(|_| original_dst),
            rewrite_dst: self.rewrite_src.map(|_| original_src),
            rewrite_src_port: self.rewrite_dst_port.map(|_| original_dst_port),
            rewrite_dst_port: self.rewrite_src_port.map(|_| original_src_port),
            nat64: self.nat64,
            nptv6: self.nptv6,
        }
    }

    /// Merge two NAT decisions, preferring fields already set in `self`.
    /// Used to combine a pre-routing DNAT decision with a post-policy SNAT decision.
    pub(crate) fn merge(self, other: NatDecision) -> Self {
        Self {
            rewrite_src: self.rewrite_src.or(other.rewrite_src),
            rewrite_dst: self.rewrite_dst.or(other.rewrite_dst),
            rewrite_src_port: self.rewrite_src_port.or(other.rewrite_src_port),
            rewrite_dst_port: self.rewrite_dst_port.or(other.rewrite_dst_port),
            nat64: self.nat64 || other.nat64,
            nptv6: self.nptv6 || other.nptv6,
        }
    }
}
