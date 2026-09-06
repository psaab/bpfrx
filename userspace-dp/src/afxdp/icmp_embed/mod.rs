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
mod nat64_match;
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
    /// The original (pre-DNAT/static) destination IP the client used —
    /// i.e. the public address before destination NAT. For a flow with
    /// NO destination NAT this equals the embedded packet's destination,
    /// so the destination rewrite in the builders is a no-op and
    /// SNAT-only / no-NAT behaviour stays byte-identical (#3112).
    pub(super) original_dst: IpAddr,
    /// The original (pre-DNAT) destination port. Equals the embedded
    /// destination port when no port DNAT was applied (no-op rewrite).
    pub(super) original_dst_port: u16,
    /// The embedded packet's L4 protocol.
    pub(super) embedded_proto: u8,
    /// Forwarding resolution toward the original client.
    pub(super) resolution: ForwardingResolution,
    /// Session metadata (zones, RG).
    pub(super) metadata: SessionMetadata,
    /// #6474: this match is an OUTBOUND ICMP error through source NAT — the
    /// internal host emitted the error about the session's REPLY packet, so
    /// the quote carries the PRE-NAT tuple and the session-fallback matched
    /// the FORWARD session via the quote's reply key (`is_reverse == false`,
    /// `rewrite_src` set, no destination NAT). The caller must re-NAT the
    /// outer source and the embedded quote to the session's external
    /// identity (RFC 5508 §4) with the `build_snat_outbound_icmp_error_*`
    /// builders — NOT the #5690 reversal, which would consume the
    /// descriptor with the internal (pre-NAT) source on the wire and an
    /// unassociable quote. `false` on every inbound match.
    pub(super) outbound_snat: bool,
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
    // #9162: the arriving interface's routing domain — see the child's doc.
    routing_domain: u32,
) -> Option<SessionLookup> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    session_match::try_embedded_icmp_session_match_from_frame(
        frame,
        meta,
        sessions,
        now_ns,
        routing_domain,
    )
}

/// Core embedded ICMP session match logic operating on a frame slice.
pub(super) fn try_embedded_icmp_session_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    now_ns: u64,
    // #9162: the arriving interface's routing domain — see the child's doc.
    routing_domain: u32,
) -> Option<SessionLookup> {
    session_match::try_embedded_icmp_session_match_from_frame(
        frame,
        meta,
        sessions,
        now_ns,
        routing_domain,
    )
}

// #8271: `try_embedded_icmp_nat_match` -- the `(area, desc)` wrapper that
// sliced the UMEM frame at `desc.addr`/`desc.len` and called the `_from_frame`
// twin below -- was DELETED rather than left unused.
//
// It had exactly one behaviour: pair whatever frame `desc` points at with
// whatever `meta` it was handed. On a native-GRE-decapped packet those are
// different packets -- `stage_native_gre_decap` rebinds `meta` to the inner
// frame while `desc` still references the un-decapped outer one -- and its last
// caller (`try_reverse_embedded_icmp_error`) was doing precisely that, parsing
// outer bytes at inner offsets. Two sibling arms of
// `poll_binding_process_descriptor` had already been fixed for the same pairing
// (#1885, #1902); these two had not.
//
// Removing the wrapper removes the ability to make that mistake, which is worth
// more than removing this instance of it: every caller must now name the frame
// it means. Callers that genuinely hold only a descriptor slice it themselves
// and pass the bytes.

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

pub(super) use nat64_match::Nat64IcmpErrorMatch;

/// #6472: NAT64 flowless ICMP-error session match, operating on a frame
/// slice. Builds the `NatMatchCtx` borrow bundle exactly like
/// [`try_embedded_icmp_nat_match_from_frame`] and dispatches to the
/// cross-family matcher; the poll-side caller translates + forwards per
/// the returned direction. `None` = not a NAT64 session error (the
/// same-family reversal and normal flowless enforcement run unchanged).
#[allow(clippy::too_many_arguments)]
pub(super) fn try_nat64_icmp_error_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
) -> Option<Nat64IcmpErrorMatch> {
    let mut ctx = NatMatchCtx {
        sessions,
        forwarding,
        dynamic_neighbors,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
    };
    nat64_match::try_nat64_icmp_error_match(frame, meta, &mut ctx, now_ns)
}

pub(super) fn build_nat_reversed_icmp_error_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    builders::build_nat_reversed_icmp_error_v4(frame, meta, icmp_match)
}

/// #6474: OUTBOUND ICMP error through source NAT — rewrite the outer
/// source and the embedded quote to the session's external identity
/// (RFC 5508 §4). See [`builders::build_snat_outbound_icmp_error_v4`].
pub(super) fn build_snat_outbound_icmp_error_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    builders::build_snat_outbound_icmp_error_v4(frame, meta, icmp_match)
}

/// #6474: IPv6 twin of [`build_snat_outbound_icmp_error_v4`].
pub(super) fn build_snat_outbound_icmp_error_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    builders::build_snat_outbound_icmp_error_v6(frame, meta, icmp_match)
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

/// #6472: (resolution, ingress-zone) form of the embedded-ICMP resolution
/// finalizer for the NAT64 flowless arm (its match is not an
/// [`EmbeddedIcmpMatch`]). See
/// [`builders::finalize_embedded_icmp_resolution_parts`].
pub(super) fn finalize_embedded_icmp_resolution_parts(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    ingress_ifindex: i32,
    resolution: ForwardingResolution,
    ingress_zone: u16,
) -> ForwardingResolution {
    builders::finalize_embedded_icmp_resolution_parts(
        forwarding,
        ha_state,
        now_secs,
        ingress_ifindex,
        resolution,
        ingress_zone,
    )
}
