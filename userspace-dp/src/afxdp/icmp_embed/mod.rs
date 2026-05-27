//! Embedded ICMP error path: reverse-NAT and forwarding-resolution
//! for ICMP / ICMPv6 error packets (Time-Exceeded, Destination
//! Unreachable, etc.) whose embedded inner header matches an existing
//! session. The 8 `pub(super)` items below are the public surface
//! consumed by `afxdp/mod.rs` and `afxdp/poll_descriptor/mod.rs`.
//!
//! The 269-LOC `try_embedded_icmp_nat_match_from_frame` body has been
//! split by outer address family into private `nat_match_v4` /
//! `nat_match_v6` submodules. The 10-param
//! `embedded_icmp_return_resolution` collapses behind `NatMatchCtx`,
//! a borrow bundle threaded through all four embedded-ICMP NAT
//! match arms.
//!
//! Wrapper functions in this file delegate directly to children via
//! qualified-path calls (NOT `pub(super) use ...`) — that pattern
//! would trigger E0364 on `pub(super)` child items, as documented
//! in `afxdp/tx/mod.rs:38-42`.

use super::*;

mod builders;
mod nat_match_v4;
mod nat_match_v6;
mod parse;
mod return_resolution;
mod session_match;

/// Information returned from an embedded ICMP error session match
/// that includes NAT reversal data needed to rewrite the ICMP error
/// packet back to the original pre-NAT client.
#[derive(Clone, Debug)]
pub(super) struct EmbeddedIcmpMatch {
    /// The forward session's NAT decision (has rewrite_src for SNAT).
    pub(super) nat: NatDecision,
    /// The original (pre-NAT) source IP of the client.
    pub(super) original_src: IpAddr,
    /// The original source port (if port SNAT was applied).
    pub(super) original_src_port: u16,
    /// The embedded packet's L4 protocol.
    pub(super) embedded_proto: u8,
    /// Forwarding resolution toward the original client.
    pub(super) resolution: ForwardingResolution,
    /// Session metadata (zones, RG).
    pub(super) metadata: SessionMetadata,
}

/// Borrow bundle threaded through both v4/v6 NAT-match paths and the
/// embedded-ICMP return-resolution helper. ONE struct only — both
/// the NAT lookup path (which needs `shared_nat_sessions`) and the
/// return-resolution path (which doesn't) share the same `&mut`
/// borrow on `SessionTable`, so two structs holding `&mut sessions`
/// concurrently would be a borrow-checker error.
pub(in crate::afxdp::icmp_embed) struct NatMatchCtx<'a> {
    pub sessions: &'a mut SessionTable,
    pub forwarding: &'a ForwardingState,
    pub dynamic_neighbors: &'a Arc<ShardedNeighborMap>,
    pub shared_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub shared_nat_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub shared_forward_wire_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
}

// ---------------------------------------------------------------
// Public surface — `pub(super)` wrappers delegating to children.
// ---------------------------------------------------------------

/// Parse the embedded IP+L4 headers from an ICMP error payload and
/// look up the corresponding session. Returns the session lookup if
/// found.
#[allow(dead_code)]
pub(super) fn try_embedded_icmp_session_match(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    now_ns: u64,
) -> Option<SessionLookup> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    session_match::try_embedded_icmp_session_match_from_frame(frame, meta, sessions, now_ns)
}

/// Core embedded ICMP session match logic operating on a frame slice.
pub(super) fn try_embedded_icmp_session_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    now_ns: u64,
) -> Option<SessionLookup> {
    session_match::try_embedded_icmp_session_match_from_frame(frame, meta, sessions, now_ns)
}

/// Extended embedded ICMP session match that returns full NAT
/// reversal info. Unlike `try_embedded_icmp_session_match`, this also
/// extracts the original (pre-NAT) source IP and port and resolves
/// forwarding toward the original client.
pub(super) fn try_embedded_icmp_nat_match(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
) -> Option<EmbeddedIcmpMatch> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    try_embedded_icmp_nat_match_from_frame(
        frame,
        meta,
        sessions,
        forwarding,
        dynamic_neighbors,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        now_ns,
    )
}

/// Core implementation of embedded ICMP NAT match operating on a
/// frame slice. Dispatches to the v4 / v6 outer family branch.
#[inline]
pub(super) fn try_embedded_icmp_nat_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
) -> Option<EmbeddedIcmpMatch> {
    let l4 = meta.l4_offset as usize;
    let icmp_type = *frame.get(l4)?;
    if !is_icmp_error(meta.protocol, icmp_type) {
        return None;
    }
    let mut ctx = NatMatchCtx {
        sessions,
        forwarding,
        dynamic_neighbors,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
    };
    match meta.protocol {
        PROTO_ICMP => nat_match_v4::match_outer_v4(frame, meta, &mut ctx, now_ns),
        PROTO_ICMPV6 => nat_match_v6::match_outer_v6(frame, meta, &mut ctx, now_ns),
        _ => None,
    }
}

pub(super) fn build_nat_reversed_icmp_error_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    builders::build_nat_reversed_icmp_error_v4(frame, meta, icmp_match)
}

pub(super) fn build_nat_reversed_icmp_error_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    builders::build_nat_reversed_icmp_error_v6(frame, meta, icmp_match)
}

pub(super) fn finalize_embedded_icmp_resolution(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    ingress_ifindex: i32,
    icmp_match: &EmbeddedIcmpMatch,
) -> ForwardingResolution {
    builders::finalize_embedded_icmp_resolution(
        forwarding,
        ha_state,
        now_secs,
        ingress_ifindex,
        icmp_match,
    )
}
