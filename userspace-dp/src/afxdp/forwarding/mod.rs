use super::*;
use std::borrow::Cow;

mod host_inbound;
mod ipsec;
pub(in crate::afxdp) use ipsec::*;
mod mss;
pub(in crate::afxdp) use mss::*;
mod ha;
pub(in crate::afxdp) use ha::*;
mod nat;
pub(in crate::afxdp) use nat::*;
mod fabric;
pub(in crate::afxdp) use fabric::*;
// #3070: re-export into the afxdp scope so the local-delivery admit path
// (poll_descriptor, via `use self::forwarding::*`) and the forwarding-state
// builder (forwarding_build::zones) can reach them.
pub(in crate::afxdp) use host_inbound::{
    host_inbound_admits, host_inbound_admits_iface, zone_host_inbound_from_snapshot,
    zone_host_inbound_from_tokens,
};

const DEFAULT_V4_TABLE: &str = "inet.0";
const DEFAULT_V6_TABLE: &str = "inet6.0";
const MAX_NEXT_TABLE_DEPTH: usize = 8;

/// #3769: count of `LocalDelivery` resolutions returned with `local_ifindex ==
/// 0` — i.e. a NAT/DNAT-only local target (no interface owns the address, so
/// the table-scoped connected scan cannot attribute an ifindex). This is
/// legitimate for a NAT/DNAT external IP owned in the resolving table (the NAT
/// subsystem owns it, there is no interface), but downstream zone / security-
/// policy / HA-RG-owner selection then operate on ifindex 0, so the count is
/// exposed as a diagnostic. A steadily climbing value on a router with per-VRF
/// NAT is expected; a climbing value that correlates with mis-attributed
/// sessions is the signal to inspect. `LocalDelivery` for a genuine interface
/// address always carries the real ifindex and does NOT bump this.
pub(in crate::afxdp) static LOCAL_DELIVERY_IFINDEX0: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(super) fn classify_metadata(
    meta: UserspaceDpMeta,
    validation: ValidationState,
) -> PacketDisposition {
    if !validation.snapshot_installed {
        return PacketDisposition::NoSnapshot;
    }
    if meta.config_generation != validation.config_generation {
        return PacketDisposition::ConfigGenerationMismatch;
    }
    if meta.fib_generation != validation.fib_generation {
        return PacketDisposition::FibGenerationMismatch;
    }
    match meta.addr_family as i32 {
        libc::AF_INET | libc::AF_INET6 => PacketDisposition::Valid,
        _ => PacketDisposition::UnsupportedPacket,
    }
}

/// #4674: returns `Cow<'static, str>` rather than an owned `String`. The
/// common cases — the default-table remaps (`inet.0`↔`inet6.0`) — borrow the
/// `'static` `DEFAULT_V4_TABLE`/`DEFAULT_V6_TABLE` constants and never
/// allocate. Only the rare per-VRF suffix rewrite (`<inst>.inet.0`↔
/// `<inst>.inet6.0`) or a non-canonical passthrough owns a heap string. This
/// removes the per-new-flow FIB-resolution alloc that `.to_string()` forced at
/// every lookup-path caller (see `lookup_forwarding_resolution_inner_ecmp`,
/// which now defaults to `Cow::Borrowed(DEFAULT_V*_TABLE)`).
pub(super) fn canonical_route_table(table: &str, is_ipv6: bool) -> Cow<'static, str> {
    if is_ipv6 {
        if table == DEFAULT_V4_TABLE {
            return Cow::Borrowed(DEFAULT_V6_TABLE);
        }
        if let Some(prefix) = table.strip_suffix(".inet.0") {
            return Cow::Owned(format!("{prefix}.inet6.0"));
        }
        return Cow::Owned(table.to_string());
    }
    if table == DEFAULT_V6_TABLE {
        return Cow::Borrowed(DEFAULT_V4_TABLE);
    }
    if let Some(prefix) = table.strip_suffix(".inet6.0") {
        return Cow::Owned(format!("{prefix}.inet.0"));
    }
    Cow::Owned(table.to_string())
}

pub(super) fn parse_packet_destination(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<IpAddr> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    let l3 = meta.l3_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            let end = l3.checked_add(20)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 16],
                frame[l3 + 17],
                frame[l3 + 18],
                frame[l3 + 19],
            )))
        }
        libc::AF_INET6 => {
            let end = l3.checked_add(40)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            )))
        }
        _ => None,
    }
}

pub(super) fn resolve_forwarding(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> ForwardingResolution {
    let Some(dst) = parse_packet_destination(area, desc, meta) else {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        };
    };
    lookup_forwarding_resolution_with_dynamic(state, dynamic_neighbors, dst)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn zone_pair_for_flow(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    egress_ifindex: i32,
) -> (String, String) {
    zone_pair_for_flow_with_override(forwarding, ingress_ifindex, None, egress_ifindex)
}

pub(super) fn zone_pair_for_flow_with_override(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_zone_override: Option<&str>,
    egress_ifindex: i32,
) -> (String, String) {
    // #921: this helper is `#[cfg_attr(not(test), allow(dead_code))]`
    // (see zone_pair_for_flow above) and is only called from tests.
    // After #921, `ifindex_to_zone_id` and `EgressInterface.zone_id`
    // are u16. Resolve back to the name via `zone_id_to_name` for
    // the test-only String API. Slow path; allocations are fine.
    let from_zone = ingress_zone_override
        .map(|zone| zone.to_string())
        .or_else(|| {
            forwarding
                .ifindex_to_zone_id
                .get(&ingress_ifindex)
                .and_then(|id| forwarding.zone_id_to_name.get(id).cloned())
        })
        .unwrap_or_default();
    let to_zone = forwarding
        .egress
        .get(&egress_ifindex)
        .and_then(|iface| forwarding.zone_id_to_name.get(&iface.zone_id).cloned())
        .unwrap_or_default();
    (from_zone, to_zone)
}

/// #919/#922: zero-allocation production zone-pair resolver. Returns
/// `(from_id, to_id)` u16 pair directly without `String` materialisation.
/// `ingress_zone_override` is `Option<u16>` (parsed from fabric MAC),
/// not `Option<&str>` — callers no longer round-trip through names.
/// Returns `(0, 0)` segments for ifindexes not in the zone maps; the
/// caller treats `0` as "unknown" and falls back to default policy.
#[inline]
pub(super) fn zone_pair_ids_for_flow_with_override(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_zone_override: Option<u16>,
    egress_ifindex: i32,
) -> (u16, u16) {
    // #921: single-hop direct lookup. Was two HashMap lookups
    // (ifindex → String → u16) and one String hash; now one
    // (ifindex → u16) for ingress and a struct field load for egress.
    let from_id = ingress_zone_override
        .or_else(|| forwarding.ifindex_to_zone_id.get(&ingress_ifindex).copied())
        .unwrap_or(0);
    let to_id = forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.zone_id)
        .unwrap_or(0);
    (from_id, to_id)
}

/// #919/#922 test convenience: ID-pair without override.
#[cfg(test)]
pub(super) fn zone_pair_ids_for_flow(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    egress_ifindex: i32,
) -> (u16, u16) {
    zone_pair_ids_for_flow_with_override(forwarding, ingress_ifindex, None, egress_ifindex)
}

pub(super) fn allow_unsolicited_dns_reply(
    forwarding: &ForwardingState,
    flow: &SessionFlow,
) -> bool {
    forwarding.allow_dns_reply
        && flow.forward_key.protocol == PROTO_UDP
        && flow.forward_key.src_port == 53
}

pub(super) fn is_icmp_echo_request(packet_frame: &[u8], meta: UserspaceDpMeta) -> bool {
    if !matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        return false;
    }
    packet_frame
        .get(meta.l4_offset as usize)
        .copied()
        .map(|icmp_type| {
            matches!(
                (meta.protocol, icmp_type),
                (PROTO_ICMP, 8) | (PROTO_ICMPV6, 128)
            )
        })
        .unwrap_or(false)
}

pub(super) fn resolve_ingress_logical_ifindex(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
) -> Option<i32> {
    forwarding
        .ingress_logical_ifindex
        .get(&(ingress_ifindex, ingress_vlan_id))
        .copied()
}

// #989: clamp_tcp_mss / clamp_tcp_mss_frame relocated to `frame/tcp.rs`.

#[cfg(test)]
pub(super) fn lookup_forwarding_for_ip(
    state: &ForwardingState,
    dst: IpAddr,
) -> ForwardingDisposition {
    lookup_forwarding_resolution(state, dst).disposition
}

pub(super) fn lookup_forwarding_resolution(
    state: &ForwardingState,
    dst: IpAddr,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, None, dst, None)
}

pub(super) fn lookup_forwarding_resolution_with_dynamic(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    dst: IpAddr,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst, None)
}

/// #2734: like `lookup_forwarding_resolution_with_dynamic`, but selects an
/// equal-cost next-hop by the per-FLOW 5-tuple hash (from the session
/// forward key) so distinct flows to the same destination spread across
/// ECMP members. Used by the session forwarding-resolution path.
pub(super) fn lookup_forwarding_resolution_with_dynamic_for_flow(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    dst: IpAddr,
    flow_key: &crate::session::SessionKey,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner_ecmp(
        state,
        Some(dynamic_neighbors),
        dst,
        None,
        Some(ecmp_hash_flow(flow_key)),
    )
}

pub(super) fn lookup_forwarding_resolution_in_table_with_dynamic(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    dst: IpAddr,
    table: Option<&str>,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst, table)
}

pub(super) fn lookup_forwarding_resolution_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    dst: IpAddr,
    table: Option<&str>,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner_ecmp(state, dynamic_neighbors, dst, table, None)
}

/// #2734: as `lookup_forwarding_resolution_inner`, plus an optional
/// per-flow ECMP spread key. `ecmp_flow_hash = Some(h)` selects the
/// equal-cost member by the 5-tuple flow hash (per-flow spread); `None`
/// falls back to the per-destination hash (#2389 behavior) for callers
/// without a flow context.
pub(super) fn lookup_forwarding_resolution_inner_ecmp(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    dst: IpAddr,
    table: Option<&str>,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingResolution {
    match dst {
        IpAddr::V4(ip) => {
            let table = table
                .map(|table| canonical_route_table(table, false))
                .unwrap_or(Cow::Borrowed(DEFAULT_V4_TABLE));
            if state.local_v4.contains(&ip) {
                // #3151: local-delivery (to-self) attribution is table-scoped,
                // exactly like the route-path connected scan (#2388). When the
                // same local IP exists in more than one routing-instance, a
                // to-self packet in VRF A must NOT resolve its
                // local/egress/tx ifindex to VRF B's connected entry — that
                // would mis-attribute zone/security-policy and HA RG ownership
                // (owner_rg_for_flow(egress_ifindex)) across VRFs. Filter the
                // connected scan by the canonical ingress table; the default
                // routing-instance (inet.0) case still matches default-table
                // connected routes.
                // #3769: the local-delivery DECISION is now table-scoped too,
                // not just the #3151 ifindex attribution. `local_v4` is a
                // GLOBAL membership set, so a NAT/DNAT external IP owned in
                // VRF B (or an interface IP owned only in another
                // routing-instance) would otherwise short-circuit a VRF-A
                // packet to LocalDelivery, bypassing the VRF-A FIB +
                // zone/policy + HA-RG owner check. `local_tables_v4` records,
                // per local address, the tables that own it (paired with every
                // `local_v4` insert); deliver locally only when the RESOLVING
                // table is one of them. NOTE: the membership DECISION cannot
                // use the connected scan — `ConnectedRouteV4` stores the MASKED
                // network address, so `prefix.addr() == host` matches only a
                // /32 (and never a NAT-only IP, which has no connected route).
                // #3769: an UNSCOPED NAT/DNAT external (`local_nat_any_table_v4`)
                // is table-agnostic (mirrors `scope_ok`'s empty-instance
                // wildcard); a named-VRF / interface address must match the
                // resolving table exactly.
                let owned_here = state.local_nat_any_table_v4.contains(&ip)
                    || state
                        .local_tables_v4
                        .get(&ip)
                        .is_some_and(|tables| tables.contains(table.as_ref()));
                if !owned_here {
                    // Owned in a DIFFERENT table only (cross-VRF) — fall
                    // through to the VRF-A route lookup instead of leaking to
                    // LocalDelivery.
                } else {
                    // #3151: ifindex attribution stays via the table-scoped
                    // connected scan (the /32-HA case). A NAT-only external IP
                    // or a non-/32 interface host IP has no exact connected
                    // match → ifindex 0 (unchanged pre-#3769 behaviour), now
                    // reached only when the table genuinely owns the address.
                    let local_ifindex = state
                        .connected_v4
                        .iter()
                        .find(|entry| entry.table == table && entry.prefix.addr() == ip)
                        .map(|entry| entry.ifindex)
                        .unwrap_or(0);
                    if local_ifindex == 0 {
                        // #3769 L5: table-owned local target with no interface
                        // ifindex (NAT-only, or a non-/32 interface IP whose
                        // ingress-interface path was bypassed). Gated on table
                        // ownership; counted for diagnostics.
                        LOCAL_DELIVERY_IFINDEX0
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    return ForwardingResolution {
                        disposition: ForwardingDisposition::LocalDelivery,
                        local_ifindex,
                        egress_ifindex: local_ifindex,
                        tx_ifindex: local_ifindex,
                        tunnel_endpoint_id: 0,
                        next_hop: None,
                        neighbor_mac: None,
                        src_mac: None,
                        tx_vlan_id: 0,
                    };
                }
            }
            lookup_forwarding_resolution_v4(
                state,
                dynamic_neighbors,
                ip,
                &table,
                0,
                true,
                ecmp_flow_hash,
            )
        }
        IpAddr::V6(ip) => {
            let table = table
                .map(|table| canonical_route_table(table, true))
                .unwrap_or(Cow::Borrowed(DEFAULT_V6_TABLE));
            if state.local_v6.contains(&ip) {
                // #3151: table-scoped local-delivery attribution (see the v4
                // branch above and the #2388 route-path connected scan).
                // #3769: table-scoped local-delivery DECISION (see the v4
                // branch). A NAT/DNAT external IP owned in another VRF, or an
                // interface IP owned only in another routing-instance, must not
                // short-circuit a VRF-A packet to LocalDelivery. `local_v6`
                // membership alone is global; gate on `local_tables_v6` (plus
                // the unscoped-wildcard `local_nat_any_table_v6`, see the v4
                // branch).
                let owned_here = state.local_nat_any_table_v6.contains(&ip)
                    || state
                        .local_tables_v6
                        .get(&ip)
                        .is_some_and(|tables| tables.contains(table.as_ref()));
                if !owned_here {
                    // Owned in a DIFFERENT table only (cross-VRF) — fall
                    // through to the route lookup.
                } else {
                    // #3151: ifindex attribution via the table-scoped connected
                    // scan (matches a /128 host; a NAT-only or non-/128 IP →
                    // ifindex 0, now reached only when this table owns the IP).
                    let local_ifindex = state
                        .connected_v6
                        .iter()
                        .find(|entry| entry.table == table && entry.prefix.addr() == ip)
                        .map(|entry| entry.ifindex)
                        .unwrap_or(0);
                    if local_ifindex == 0 {
                        // #3769 L5: table-owned local target, no interface
                        // ifindex; gated on table ownership, counted.
                        LOCAL_DELIVERY_IFINDEX0
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    return ForwardingResolution {
                        disposition: ForwardingDisposition::LocalDelivery,
                        local_ifindex,
                        egress_ifindex: local_ifindex,
                        tx_ifindex: local_ifindex,
                        tunnel_endpoint_id: 0,
                        next_hop: None,
                        neighbor_mac: None,
                        src_mac: None,
                        tx_vlan_id: 0,
                    };
                }
            }
            lookup_forwarding_resolution_v6(
                state,
                dynamic_neighbors,
                ip,
                &table,
                0,
                true,
                ecmp_flow_hash,
            )
        }
    }
}

/// #4392: a reject-reply sink for the flow-backed PBR drop path. Present on the
/// flow-backed session-miss path, which carries a full L4 header and can
/// synthesize a TCP RST / ICMP-unreachable exactly like a non-PBR `then reject`.
/// `None` on the flowless path (a non-first fragment / L3-only packet has no L4
/// header to reflect), where a PBR `reject`/`discard` degrades to a silent drop
/// — identical to the flowless non-PBR input-filter deny.
pub(super) struct PbrRejectSink<'a> {
    pub(super) tx_pipeline: &'a mut crate::afxdp::worker::WorkerTxPipeline,
    pub(super) ingress_ifindex: i32,
    pub(super) counters: &'a mut crate::afxdp::BatchCounters,
}

/// #4392: the route-lookup decision returned by `ingress_route_table_override`.
///
/// A PBR term `from { ... } then { routing-instance X; reject | discard; }`
/// carries BOTH a routing-instance override AND a drop action. Before this fix
/// the override was applied unconditionally and the packet was FORWARDED into
/// VRF X — a VRF leak plus a false audit (the filter log recorded a deny while
/// the data plane forwarded). The drop action now gates the override.
pub(super) enum RouteOverride {
    /// No interface input filter affects route lookup here, or no PBR
    /// routing-instance term matched. Use the default route table.
    None,
    /// A PBR routing-instance term matched with a non-drop (accept) action.
    /// Steer the route lookup to this override table (`<ri>.inet[6].0`) and
    /// forward — normal policy-based routing, unchanged.
    Table(String),
    /// A PBR routing-instance term matched with a `reject`/`discard` action.
    /// The caller MUST DROP: do NOT apply the override, do NOT route-lookup or
    /// forward. Any reject reply (TCP RST / ICMP unreachable) has already been
    /// synthesized inside `ingress_route_table_override` when a `PbrRejectSink`
    /// was supplied and the action is `reject`; `discard`, and the flowless
    /// (sink-less) path, drop silently.
    Drop,
}

pub(super) fn ingress_route_table_override(
    forwarding: &ForwardingState,
    frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    ingress_zone_override: Option<u16>,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    now_ns: u64,
    reject_sink: Option<PbrRejectSink<'_>>,
) -> RouteOverride {
    let ingress_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    if !crate::filter::interface_filter_affects_route_lookup(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
    ) {
        return RouteOverride::None;
    }
    // #2362: PBR terms may carry per-packet L4 match conditions (tcp-flags /
    // is-fragment / icmp-type / icmp-code); build the extra inputs so a
    // `from { tcp-flags ...; } then routing-instance ...` term matches exactly
    // the authored packets.
    let extra = crate::afxdp::frame::term_match_extra_from_frame(frame, meta);
    let routing_result =
        match crate::filter::evaluate_interface_filter_routing_instance_event_counted(
            &forwarding.filter_state,
            ingress_ifindex,
            is_v6,
            flow.src_ip,
            flow.dst_ip,
            meta.protocol,
            flow.forward_key.src_port,
            flow.forward_key.dst_port,
            meta.dscp,
            extra,
            meta.pkt_len as u64,
        ) {
            Some(result) => result,
            None => return RouteOverride::None,
        };
    // #4392: a matched PBR routing-instance term may ALSO carry a drop action
    // (`then { routing-instance X; reject | discard; }`). Such a term is a DENY,
    // NOT a forward: the routing-instance override must NOT be applied. On the
    // flow-backed session-miss path a `PbrRejectSink` is supplied, so a `reject`
    // synthesizes the TCP RST / ICMP-unreachable reply here — byte-identical to
    // a non-PBR `then reject` — and its ACTUAL outcome is threaded into the
    // filter log (#3615) below. A `discard`, and the flowless (sink-less) path,
    // drop silently.
    let is_drop = matches!(
        routing_result.action,
        crate::filter::FilterAction::Reject | crate::filter::FilterAction::Discard
    );
    let reject_reply_enqueued = match (routing_result.action, reject_sink) {
        (crate::filter::FilterAction::Reject, Some(sink)) => {
            crate::afxdp::poll_descriptor::reject_reply::enqueue_filter_reject_reply(
                sink.tx_pipeline,
                forwarding,
                sink.ingress_ifindex,
                frame,
                meta,
                flow,
                sink.counters,
            )
        }
        _ => false,
    };
    // #2619: emit the accumulated log_match — it captures fall-through
    // `then { log; next term; }` terms ahead of the routing-instance term that
    // the PBR path previously dropped, AND the routing-instance term's own log
    // (latest matched wins). Its action is already normalized to the verdict the
    // packet receives (#2616). Falls back to nothing when no matched term logged.
    if let Some(log_match) = routing_result.log_match {
        let ingress_zone_id = ingress_zone_override
            .filter(|id| forwarding.zone_id_to_name.contains_key(id))
            .or_else(|| forwarding.ifindex_to_zone_id.get(&ingress_ifindex).copied())
            .or_else(|| {
                forwarding
                    .ifindex_to_zone_id
                    .get(&(meta.ingress_ifindex as i32))
                    .copied()
            })
            .unwrap_or(0);
        emit_filter_log_event(
            event_stream,
            flow,
            meta,
            ingress_zone_id,
            0,
            log_match.filter_id,
            log_match.term_id,
            log_match.action,
            FilterLogSource::Pbr,
            // #2520: AppID via the hot-path app_catalog.lookup.
            resolve_flow_app_id(&forwarding.app_catalog, flow),
            // #3615/#4392: report the TRUTHFUL reject outcome. A forward
            // (non-drop) PBR term never rejects (false). A `then reject` on the
            // flow-backed session-miss path synthesizes an RST/ICMP reply above
            // and logs REJECT; a `discard`, or the flowless (sink-less) path,
            // logs the truthful DENY (silent drop).
            reject_reply_enqueued,
            now_ns,
        );
    }
    if is_drop {
        // #4392: reject/discard PBR term — the caller must drop; do NOT apply
        // the routing-instance override or route-lookup/forward.
        return RouteOverride::Drop;
    }
    let routing_instance = routing_result.routing_instance;
    RouteOverride::Table(if is_v6 {
        format!("{routing_instance}.inet6.0")
    } else {
        format!("{routing_instance}.inet.0")
    })
}

pub(super) fn should_cache_local_delivery_session_on_miss(
    state: &ForwardingState,
    resolution_target: IpAddr,
    resolution: ForwardingResolution,
    protocol: u8,
    tcp_flags: u8,
) -> bool {
    if resolution.disposition != ForwardingDisposition::LocalDelivery {
        return false;
    }
    // Non-TCP (ICMP / UDP) LocalDelivery always caches — the handshake gate
    // below is TCP-only and MUST NOT change non-TCP behavior.
    if !matches!(protocol, PROTO_TCP) {
        return true;
    }
    let _ = state;
    let _ = resolution_target;
    // #4539 (gate-consistency hardening; subsumes #2151 + #4487): cache a
    // host-inbound TCP session ONLY off the handshake — a first packet that
    // carries SYN (an initial SYN, or a SYN|ACK for the inbound leg of a
    // firewall-originated flow). Decline every other non-SYN TCP first packet.
    //
    // A SINGLE POSITIVE `has_syn` predicate replaces the two prior NARROW
    // decline-gates that this subsumes:
    //   - #2151 declined a bare/established ACK (`has_ack && !has_syn`) — the
    //     prior inline `(tcp_flags & ACK) != 0 && (tcp_flags & SYN) == 0`.
    //   - #4487 (residual of P6 / #4400) declined a bare RST / FIN closing
    //     segment (`is_closing && !has_syn`) — a session-table DoS surface (a
    //     RST/FIN flood to a firewall IP churns the per-worker table) plus a
    //     policy-evaluation skip (a stray teardown seeding an immediately
    //     `closing` host-local session).
    // Both are `!has_syn` cases, so a single `has_syn` gate subsumes them. It
    // ADDITIONALLY closes the residual the two decline-gates left open: a
    // non-handshake anomalous / crafted first packet that is neither ACK-set
    // nor closing — pure PSH (0x08), a null segment (0x00), pure URG (0x20),
    // or an ECE/CWR-only segment — which previously fell through to the
    // default `true` and seeded a 300s host-local LocalDelivery session
    // (`is_initial_syn` false at install → `established = true`). Aligning on
    // `has_syn` matches the gate to its stated "only off the handshake" intent.
    //
    // The packet is NOT dropped: a declined non-SYN first packet still reaches
    // the host via the LocalDelivery reinject chokepoint (the #4400
    // drop-exemption for host-inbound — the ACTION differs BY DISPOSITION, as
    // #4400 deliberately chose: the TRANSIT dispositions DROP a bare teardown,
    // host-inbound LocalDelivery must NOT). A peer RST/FIN tearing down a
    // firewall-ORIGINATED TCP flow (BGP-active, syslog-TCP/TLS, feed/RPM
    // fetches, DNS-over-TCP), or a connection-refused RST for the firewall's
    // own outbound SYN, therefore still reaches the local stack so the kernel
    // socket tears down promptly — this gate only declines to CACHE. A later
    // real SYN hitting a firewall IP is re-evaluated by the `to-zone
    // junos-host` mandatory-teardown gate that runs on EVERY LocalDelivery
    // session hit (poll_descriptor), so declining to cache never skips policy.
    crate::tcp_flags::has_syn(tcp_flags)
}

pub(super) fn install_helper_local_session_on_miss(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
    origin: SessionOrigin,
    now_ns: u64,
    protocol: u8,
    tcp_flags: u8,
) -> bool {
    if let Some(previous) = sessions.take_synced_local(key) {
        remove_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            key,
        );
        delete_session_map_entry_for_removed_session(
            session_map_fd,
            key,
            previous.decision,
            &previous.metadata,
        );
    }
    if !sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata.clone(),
        origin,
        now_ns,
        protocol,
        tcp_flags,
    ) {
        return false;
    }
    let local_entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata,
        origin,
        protocol,
        tcp_flags,
        // Local forwarding-learn entry: no peer install generation (#2170).
        generation: 0,
        // #5212: a local-origin shared-map publish. The stable id is carried on
        // the wire straight off the live entry by the incremental Open delta
        // (`install_with_protocol_with_origin`) / the owner-RG cold-sync export
        // (`emit_open_delta_with_origin`), not via this shared replica — so 0
        // here (a cross-worker materialize of this entry re-allocs a local id).
        session_id: 0,
    };
    // #1789: count a failed helper-local session publish (same
    // shim-missing-key consequence as every other publish site).
    if publish_session_map_entry_for_session(session_map_fd, key, decision, &local_entry.metadata)
        .is_err()
    {
        crate::afxdp::bpf_map::SESSION_PUBLISH_ERRORS_SHARED
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    true
}

pub(super) fn ingress_interface_local_resolution(
    state: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    dst: IpAddr,
) -> Option<ForwardingResolution> {
    let logical_ifindex = resolve_ingress_logical_ifindex(state, ingress_ifindex, ingress_vlan_id)
        .or_else(|| {
            state.egress.iter().find_map(|(ifindex, iface)| {
                ((iface.bind_ifindex == ingress_ifindex || *ifindex == ingress_ifindex)
                    && iface.vlan_id == ingress_vlan_id)
                    .then_some(*ifindex)
            })
        })
        .filter(|ifindex| *ifindex > 0)
        .unwrap_or(ingress_ifindex);
    let iface = state.egress.get(&logical_ifindex)?;
    let matches_local = match dst {
        IpAddr::V4(ip) => iface.primary_v4 == Some(ip),
        IpAddr::V6(ip) => iface.primary_v6 == Some(ip),
    };
    if !matches_local {
        return None;
    }
    Some(ForwardingResolution {
        disposition: ForwardingDisposition::LocalDelivery,
        local_ifindex: logical_ifindex,
        egress_ifindex: logical_ifindex,
        tx_ifindex: logical_ifindex,
        tunnel_endpoint_id: state
            .tunnel_endpoint_by_ifindex
            .get(&logical_ifindex)
            .copied()
            .unwrap_or_default(),
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    })
}

pub(super) fn ingress_interface_local_resolution_on_session_miss(
    state: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    dst: IpAddr,
    _protocol: u8,
) -> Option<ForwardingResolution> {
    ingress_interface_local_resolution(state, ingress_ifindex, ingress_vlan_id, dst)
}

pub(super) fn lookup_forwarding_resolution_v4(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv4Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingResolution {
    // #3768 (M6): each top-level resolution starts a fresh visited-table
    // chain for A->B->A next-table cycle detection. The tunnel-underlay
    // sub-resolution (resolve_tunnel_outer) also enters through this public
    // wrapper, so it correctly starts its own independent chain.
    let mut visited: Vec<String> = Vec::new();
    lookup_forwarding_resolution_v4_inner(
        state,
        dynamic_neighbors,
        ip,
        table,
        depth,
        allow_tunnels,
        ecmp_flow_hash,
        &mut visited,
    )
}

fn lookup_forwarding_resolution_v4_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv4Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
    visited: &mut Vec<String>,
) -> ForwardingResolution {
    if depth >= MAX_NEXT_TABLE_DEPTH {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NextTableUnsupported,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(ip)),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        };
    }
    let static_match = state
        .routes_v4
        .get(table)
        .and_then(|routes| routes.iter().find(|entry| entry.prefix.contains(ip)));
    // #2388: connected routes are table-scoped — only consider a connected
    // prefix that belongs to the table being resolved, so a per-VRF /
    // next-table lookup never matches another routing-instance's connected
    // prefix. The vec is sorted longest-prefix-first, so the first matching
    // in-table entry is the most specific.
    let connected_match = state
        .connected_v4
        .iter()
        .find(|entry| entry.table == table && entry.prefix.contains(ip));
    match choose_v4_route(static_match, connected_match) {
        Some(ResolvedRouteV4::Connected {
            ifindex,
            tunnel_endpoint_id,
        }) => {
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(Some(IpAddr::V4(ip)))
                };
            }
            let neighbor = lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V4(ip));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(ip)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        Some(ResolvedRouteV4::Static(route)) => {
            if route.discard {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::DiscardRoute,
                    local_ifindex: 0,
                    egress_ifindex: 0,
                    tx_ifindex: 0,
                    tunnel_endpoint_id: 0,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            if !route.next_table.is_empty() {
                // #3768 (M5): canonicalize the recursive next-table name for
                // THIS address family before loop detection and recursion.
                // routes_v4 is keyed by canonical_route_table(table, false),
                // so a v4 next-table string is already canonical here; the
                // canonicalization is defense-in-depth (a stale/mis-derived
                // "<inst>.inet6.0" on the v4 side would otherwise miss). The
                // symmetric v6 site is where this actually rewrites (see the
                // Go #3768 H6 fix + the v6 lookup below).
                let next_table_name = canonical_route_table(&route.next_table, false);
                // #3768 (M6): reject a next-table that revisits the current
                // table (direct self-loop) OR any table already on this
                // resolution's chain (A->B->A cross-table cycle). Without the
                // visited set an A->B->A cycle burned to MAX_NEXT_TABLE_DEPTH
                // on every packet and masked the config defect.
                if next_table_name == table || visited.iter().any(|t| t == &next_table_name) {
                    return ForwardingResolution {
                        disposition: ForwardingDisposition::NextTableUnsupported,
                        local_ifindex: 0,
                        egress_ifindex: 0,
                        tx_ifindex: 0,
                        tunnel_endpoint_id: 0,
                        next_hop: Some(IpAddr::V4(ip)),
                        neighbor_mac: None,
                        src_mac: None,
                        tx_vlan_id: 0,
                    };
                }
                visited.push(table.to_string());
                return lookup_forwarding_resolution_v4_inner(
                    state,
                    dynamic_neighbors,
                    ip,
                    &next_table_name,
                    depth + 1,
                    allow_tunnels,
                    ecmp_flow_hash,
                    visited,
                );
            }
            // #2389/#2734: select one equal-cost next-hop, skipping a dead
            // one. Spread by the per-flow 5-tuple hash when supplied,
            // else fall back to the per-destination hash.
            let spread_hash = ecmp_flow_hash.unwrap_or_else(|| ecmp_hash_v4(ip));
            let selected = select_route_next_hop(&route.next_hops, spread_hash, |nh| {
                // #2923: tunnel candidates use TUNNEL liveness (endpoint +
                // resolvable underlay), NOT the direct-neighbor gate they can
                // never satisfy. Without this branch a live direct member in a
                // mixed ECMP group starves the tunnel path.
                if nh.tunnel_endpoint_id != 0 {
                    return tunnel_next_hop_live(
                        state,
                        dynamic_neighbors,
                        nh.tunnel_endpoint_id,
                        depth,
                    );
                }
                // #5161: an interface-only member (`next_hop == None` — a
                // directly-connected / point-to-point "via <if>" candidate)
                // resolves its neighbor from the PER-FLOW destination `ip`, not
                // a stable gateway. The coordinator warmer cannot pre-resolve
                // that address (the on-link destination is a whole prefix,
                // unknown at route-sweep time), so gating liveness on an
                // already-present destination neighbor drops the member out of
                // the live set the moment any explicit-next_hop member resolves
                // — ECMP collapses to width-1. Treat an up interface-only
                // member as LIVE and let the MissingNeighbor cold path resolve
                // the destination lazily per flow, mirroring the single-member
                // resolution path (which forwards a missing-neighbor direct hop
                // as MissingNeighbor, never a drop).
                if nh.next_hop.is_none() {
                    return nh.ifindex > 0;
                }
                let target = nh.next_hop.unwrap_or(ip);
                nh.ifindex > 0
                    && lookup_neighbor_entry(state, dynamic_neighbors, nh.ifindex, IpAddr::V4(target))
                        .is_some()
            });
            let (next_hop, ifindex, tunnel_endpoint_id) = match selected {
                Some(nh) => (nh.next_hop, nh.ifindex, nh.tunnel_endpoint_id),
                None => (None, 0, 0),
            };
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(next_hop.map(IpAddr::V4).or(Some(IpAddr::V4(ip))))
                };
            }
            if ifindex <= 0 {
                return no_route_resolution(next_hop.map(IpAddr::V4));
            }
            let target = next_hop.unwrap_or(ip);
            let neighbor =
                lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V4(target));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(target)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        None => no_route_resolution(None),
    }
}

pub(super) fn lookup_forwarding_resolution_v6(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingResolution {
    // #3768 (M6): fresh visited-table chain per top-level resolution (see
    // the v4 wrapper).
    let mut visited: Vec<String> = Vec::new();
    lookup_forwarding_resolution_v6_inner(
        state,
        dynamic_neighbors,
        ip,
        table,
        depth,
        allow_tunnels,
        ecmp_flow_hash,
        &mut visited,
    )
}

fn lookup_forwarding_resolution_v6_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
    visited: &mut Vec<String>,
) -> ForwardingResolution {
    if depth >= MAX_NEXT_TABLE_DEPTH {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NextTableUnsupported,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(ip)),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        };
    }
    let static_match = state
        .routes_v6
        .get(table)
        .and_then(|routes| routes.iter().find(|entry| entry.prefix.contains(ip)));
    // #2388: connected routes are table-scoped (see the v4 lookup).
    let connected_match = state
        .connected_v6
        .iter()
        .find(|entry| entry.table == table && entry.prefix.contains(ip));
    match choose_v6_route(static_match, connected_match) {
        Some(ResolvedRouteV6::Connected {
            ifindex,
            tunnel_endpoint_id,
        }) => {
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(Some(IpAddr::V6(ip)))
                };
            }
            let neighbor = lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V6(ip));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(ip)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        Some(ResolvedRouteV6::Static(route)) => {
            if route.discard {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::DiscardRoute,
                    local_ifindex: 0,
                    egress_ifindex: 0,
                    tx_ifindex: 0,
                    tunnel_endpoint_id: 0,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            if !route.next_table.is_empty() {
                // #3768 (M5): canonicalize the recursive next-table name for
                // the v6 family before loop detection + recursion. routes_v6
                // is keyed by canonical_route_table(table, true) =
                // "<inst>.inet6.0"; canonicalizing here rewrites a
                // "<inst>.inet.0" next-table string (e.g. a pre-#3768-H6 Go
                // snapshot, or a next_table authored in v4 form) onto the v6
                // table so the lookup hits instead of blackholing.
                let next_table_name = canonical_route_table(&route.next_table, true);
                // #3768 (M6): self-loop + A->B->A cross-table cycle guard
                // (see the v4 site).
                if next_table_name == table || visited.iter().any(|t| t == &next_table_name) {
                    return ForwardingResolution {
                        disposition: ForwardingDisposition::NextTableUnsupported,
                        local_ifindex: 0,
                        egress_ifindex: 0,
                        tx_ifindex: 0,
                        tunnel_endpoint_id: 0,
                        next_hop: Some(IpAddr::V6(ip)),
                        neighbor_mac: None,
                        src_mac: None,
                        tx_vlan_id: 0,
                    };
                }
                visited.push(table.to_string());
                return lookup_forwarding_resolution_v6_inner(
                    state,
                    dynamic_neighbors,
                    ip,
                    &next_table_name,
                    depth + 1,
                    allow_tunnels,
                    ecmp_flow_hash,
                    visited,
                );
            }
            // #2389/#2734: select one equal-cost next-hop, skipping a dead
            // one. Spread by the per-flow 5-tuple hash when supplied,
            // else fall back to the per-destination hash.
            let spread_hash = ecmp_flow_hash.unwrap_or_else(|| ecmp_hash_v6(ip));
            let selected = select_route_next_hop(&route.next_hops, spread_hash, |nh| {
                // #2923: tunnel candidates use TUNNEL liveness (endpoint +
                // resolvable underlay), NOT the direct-neighbor gate they can
                // never satisfy. Without this branch a live direct member in a
                // mixed ECMP group starves the tunnel path.
                if nh.tunnel_endpoint_id != 0 {
                    return tunnel_next_hop_live(
                        state,
                        dynamic_neighbors,
                        nh.tunnel_endpoint_id,
                        depth,
                    );
                }
                // #5161: an interface-only member (`next_hop == None`) resolves
                // its neighbor from the PER-FLOW destination `ip`, which the
                // warmer cannot pre-resolve (a whole prefix, unknown at
                // route-sweep time). Gating on an already-present destination
                // neighbor starves it out of the live set once any
                // explicit-next_hop member resolves — ECMP collapses to
                // width-1. Treat an up interface-only member as LIVE; the
                // MissingNeighbor cold path resolves the destination lazily per
                // flow. See the v4 twin for the full rationale.
                if nh.next_hop.is_none() {
                    return nh.ifindex > 0;
                }
                let target = nh.next_hop.unwrap_or(ip);
                nh.ifindex > 0
                    && lookup_neighbor_entry(state, dynamic_neighbors, nh.ifindex, IpAddr::V6(target))
                        .is_some()
            });
            let (next_hop, ifindex, tunnel_endpoint_id) = match selected {
                Some(nh) => (nh.next_hop, nh.ifindex, nh.tunnel_endpoint_id),
                None => (None, 0, 0),
            };
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(next_hop.map(IpAddr::V6).or(Some(IpAddr::V6(ip))))
                };
            }
            if ifindex <= 0 {
                return no_route_resolution(next_hop.map(IpAddr::V6));
            }
            let target = next_hop.unwrap_or(ip);
            let neighbor =
                lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V6(target));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(target)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        None => no_route_resolution(None),
    }
}

pub(super) fn no_route_resolution(next_hop: Option<IpAddr>) -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::NoRoute,
        local_ifindex: 0,
        egress_ifindex: 0,
        tx_ifindex: 0,
        tunnel_endpoint_id: 0,
        next_hop,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    }
}

/// Resolve a tunnel endpoint's OUTER transport destination.
///
/// Shared SSOT for the outer-hop lookup: returns the OUTER
/// `ForwardingResolution` (whose `egress_ifindex` is the OUTER L3 egress
/// interface where the outer next-hop neighbor is keyed, NOT the tunnel
/// logical ifindex), or `None` when the endpoint id is unknown OR the
/// outer destination resolves to local delivery / a tunnel interface (the
/// recursion guard). `resolve_tunnel_forwarding_resolution` re-maps the
/// returned resolution onto the tunnel logical ifindex; the cold-path
/// `outer_neighbor_ifindex` helper reads `egress_ifindex` straight off it
/// to key the outer-hop ARP/NDP probe + neighbor map + neg-cache.
pub(super) fn resolve_tunnel_outer(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    tunnel_endpoint_id: u16,
    depth: usize,
) -> Option<ForwardingResolution> {
    let endpoint = state.tunnel_endpoints.get(&tunnel_endpoint_id)?;
    let outer = match endpoint.destination {
        // #2734: tunnel OUTER resolution is per-tunnel-endpoint, not
        // per-inner-flow — no 5-tuple flow hash applies here, so pass
        // None (per-destination spread across outer-transport ECMP).
        IpAddr::V4(ip) => lookup_forwarding_resolution_v4(
            state,
            dynamic_neighbors,
            ip,
            &endpoint.transport_table,
            depth + 1,
            false,
            None,
        ),
        IpAddr::V6(ip) => lookup_forwarding_resolution_v6(
            state,
            dynamic_neighbors,
            ip,
            &endpoint.transport_table,
            depth + 1,
            false,
            None,
        ),
    };
    if outer.disposition == ForwardingDisposition::LocalDelivery
        || state.tunnel_interfaces.contains(&outer.egress_ifindex)
    {
        return None;
    }
    Some(outer)
}

pub(super) fn resolve_tunnel_forwarding_resolution(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    tunnel_endpoint_id: u16,
    depth: usize,
) -> ForwardingResolution {
    let Some(endpoint) = state.tunnel_endpoints.get(&tunnel_endpoint_id) else {
        return no_route_resolution(None);
    };
    let logical_ifindex = endpoint.logical_ifindex;
    let destination = endpoint.destination;
    let Some(outer) = resolve_tunnel_outer(state, dynamic_neighbors, tunnel_endpoint_id, depth)
    else {
        return no_route_resolution(Some(destination));
    };
    ForwardingResolution {
        disposition: outer.disposition,
        local_ifindex: outer.local_ifindex,
        egress_ifindex: logical_ifindex,
        tx_ifindex: outer.tx_ifindex,
        tunnel_endpoint_id,
        next_hop: outer.next_hop,
        neighbor_mac: outer.neighbor_mac,
        src_mac: outer.src_mac,
        tx_vlan_id: outer.tx_vlan_id,
    }
}

/// The ifindex on which `resolution.next_hop` must be neighbor-resolved
/// (ARP/NDP probe + neighbor-map key + negative-cache key) on the cold
/// path. For a normal (non-tunnel) resolution this is `egress_ifindex`.
/// For a tunnel-marked resolution it is the OUTER transport's L3 egress
/// ifindex — where the outer next-hop neighbor (e.g. the GRE outer hop)
/// actually lives — which differs from `resolution.egress_ifindex` (the
/// tunnel LOGICAL ifindex, used for zone/policy/CoS) and from
/// `resolution.tx_ifindex` (the VLAN PARENT for a VLAN outer transport;
/// neighbors are keyed by the L3 subif, so `tx_ifindex` would be the wrong
/// key).
///
/// Computed from LIVE forwarding state at use time, so it is inherently
/// peer-local and needs no wire field / HA-sync trust — synced sessions
/// re-resolve on upsert. The outer re-resolution reuses the shared
/// `resolve_tunnel_outer` SSOT (the same lookup the original resolution
/// ran), so there is no logic duplication. Cold-path only (MissingNeighbor
/// arm), never the fast path.
///
/// The `> 0` guard (vs `== 0`) is the conservative fallback: if the
/// endpoint vanished or the re-resolved outer egress is non-positive, fall
/// back to `resolution.egress_ifindex` rather than emit a probe on ifindex
/// 0.
pub(super) fn outer_neighbor_ifindex(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    resolution: &ForwardingResolution,
) -> i32 {
    if resolution.tunnel_endpoint_id == 0 {
        return resolution.egress_ifindex;
    }
    match resolve_tunnel_outer(state, dynamic_neighbors, resolution.tunnel_endpoint_id, 0) {
        Some(outer) if outer.egress_ifindex > 0 => outer.egress_ifindex,
        _ => resolution.egress_ifindex,
    }
}

pub(super) fn lookup_neighbor_entry(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ifindex: i32,
    target: IpAddr,
) -> Option<NeighborEntry> {
    if let Some(entry) = state.neighbors.get(&(ifindex, target)).copied() {
        return Some(entry);
    }
    let Some(dynamic_neighbors) = dynamic_neighbors else {
        return None;
    };
    if let Some(entry) = dynamic_neighbors.get(&(ifindex, target)) {
        return Some(entry);
    }
    // The worker hot path must not block on shelling out to `ip neigh` or
    // active probes. Runtime neighbor discovery is maintained asynchronously
    // by the helper's own netlink dump+subscribe path.
    None
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn parse_neighbor_entries(output: &str) -> Vec<(IpAddr, NeighborEntry)> {
    let mut out = Vec::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        // #3771 (M12): the NUD state is the FINAL token of an `ip neigh` row
        // (REACHABLE / STALE / FAILED / ...). Classify ONLY that token with the
        // allowlist. The pre-#3771 denylist was applied to EVERY field, which
        // only worked because an IP / MAC / `lladdr` never contained the
        // "failed" / "incomplete" substrings; the allowlist would reject those
        // non-state fields and drop every row, so we must scope it to the state.
        match fields.last() {
            Some(state) if neighbor_state_usable(state) => {}
            _ => continue,
        }
        let Ok(ip) = fields[0].parse::<IpAddr>() else {
            continue;
        };
        let Some(lladdr) = fields.iter().position(|field| *field == "lladdr") else {
            continue;
        };
        let Some(candidate) = fields.get(lladdr + 1) else {
            continue;
        };
        let Some(mac) = parse_mac(candidate).or_else(|| parse_mac(candidate.trim())) else {
            continue;
        };
        out.push((ip, NeighborEntry { mac }));
    }
    out
}

enum ResolvedRouteV4<'a> {
    Connected {
        ifindex: i32,
        tunnel_endpoint_id: u16,
    },
    Static(&'a RouteEntryV4),
}

enum ResolvedRouteV6<'a> {
    Connected {
        ifindex: i32,
        tunnel_endpoint_id: u16,
    },
    Static(&'a RouteEntryV6),
}

fn choose_v4_route<'a>(
    static_match: Option<&'a RouteEntryV4>,
    connected_match: Option<&'a ConnectedRouteV4>,
) -> Option<ResolvedRouteV4<'a>> {
    match (static_match, connected_match) {
        (Some(route), Some(conn)) if conn.prefix.prefix_len() >= route.prefix.prefix_len() => {
            Some(ResolvedRouteV4::Connected {
                ifindex: conn.ifindex,
                tunnel_endpoint_id: conn.tunnel_endpoint_id,
            })
        }
        (Some(route), _) => Some(ResolvedRouteV4::Static(route)),
        (None, Some(conn)) => Some(ResolvedRouteV4::Connected {
            ifindex: conn.ifindex,
            tunnel_endpoint_id: conn.tunnel_endpoint_id,
        }),
        (None, None) => None,
    }
}

fn choose_v6_route<'a>(
    static_match: Option<&'a RouteEntryV6>,
    connected_match: Option<&'a ConnectedRouteV6>,
) -> Option<ResolvedRouteV6<'a>> {
    match (static_match, connected_match) {
        (Some(route), Some(conn)) if conn.prefix.prefix_len() >= route.prefix.prefix_len() => {
            Some(ResolvedRouteV6::Connected {
                ifindex: conn.ifindex,
                tunnel_endpoint_id: conn.tunnel_endpoint_id,
            })
        }
        (Some(route), _) => Some(ResolvedRouteV6::Static(route)),
        (None, Some(conn)) => Some(ResolvedRouteV6::Connected {
            ifindex: conn.ifindex,
            tunnel_endpoint_id: conn.tunnel_endpoint_id,
        }),
        (None, None) => None,
    }
}

/// #2389/#2734: select one equal-cost next-hop candidate for a forwarding
/// static route. Prefers a candidate whose neighbor is resolved (skips a
/// dead/unresolved first next-hop — the load-bearing correctness fix); if
/// several resolve, distributes deterministically by the supplied
/// `flow_hash`; if none resolve, falls back to the same hashed pick so the
/// kernel slow-path can drive ARP/NDP.
///
/// #2734: the spread key is now per-FLOW. The session resolution path
/// threads the 5-tuple flow hash (`ecmp_hash_flow`, the same seeded
/// FxHasher the flow cache already feeds the session 5-tuple — see
/// `ecmp_hash_flow`) into `select_route_next_hop`, so distinct flows to
/// the SAME destination spread across equal-cost members while every
/// packet of a single flow pins to one member (flow-consistent — no
/// intra-flow reordering). Callers without a flow context (tunnel outer
/// resolution, `inject`, bare-dst lookups) pass `None`, which falls back
/// to the per-DESTINATION hash (`ecmp_hash_v4`/`ecmp_hash_v6`) — the
/// #2389 behavior. The retained candidate vector (Vec<RouteNextHop>) is
/// what makes per-flow selection a localized runtime change.
/// Deterministic ECMP spread mixer. A fixed-seed splitmix64 finalizer over
/// the input word — used for the per-destination fallback. Stable across
/// reloads and workers so every worker maps the same input to the same
/// equal-cost path (a flow's packets never split across paths). Not a
/// security hash.
fn ecmp_hash_bytes(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn ecmp_hash_v4(ip: Ipv4Addr) -> u64 {
    ecmp_hash_bytes(u32::from(ip) as u64)
}

fn ecmp_hash_v6(ip: Ipv6Addr) -> u64 {
    let bits = u128::from(ip);
    ecmp_hash_bytes((bits as u64) ^ ((bits >> 64) as u64))
}

/// #2734: per-FLOW ECMP spread key over the full 5-tuple.
///
/// Hashes the session forward 5-tuple (`addr_family`/`protocol`/`src_ip`/
/// `dst_ip`/`src_port`/`dst_port`) with the SAME per-boot, per-process
/// seeded `FxHasher` the flow cache uses (`hot_hash_seed::hot_path_hash_seed`
/// — #2364), so the cost is one already-vetted hash and the per-flow
/// mapping reshuffles each restart (defeats offline collision construction)
/// while staying stable for a flow's lifetime within a boot. The seed is
/// node-local: ECMP selection picks among THIS node's equal-cost members
/// and is not part of any wire/HA-synced structure, so a per-node seed is
/// correct (HA peers re-derive their own pick under their own seed, exactly
/// as the flow cache and fabric-queue hash do). Determinism within a boot
/// guarantees flow consistency — every packet of one flow hashes to the
/// same member, no intra-flow reordering. `select_route_next_hop` reduces
/// this modulo the live-member count, so the spread tracks the live pool.
fn ecmp_hash_flow(key: &crate::session::SessionKey) -> u64 {
    ecmp_hash_flow_seeded(crate::hot_hash_seed::hot_path_hash_seed(), key)
}

/// Seed-parameterized core of `ecmp_hash_flow`. Split out so tests can pin
/// the seed and assert (a) intra-seed stability (flow consistency) and
/// (b) that distinct 5-tuples spread. Production calls through
/// `ecmp_hash_flow`, which supplies the per-boot process seed.
fn ecmp_hash_flow_seeded(seed: u64, key: &crate::session::SessionKey) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = rustc_hash::FxHasher::with_seed(seed as usize);
    key.hash(&mut hasher);
    hasher.finish()
}

/// #2922: select one equal-cost next-hop in a SINGLE liveness pass.
///
/// The liveness predicate (`is_live`) is NOT pure — the IPv4/IPv6 callers
/// probe the shared dynamic-neighbor map, which the monitor thread mutates
/// concurrently. The previous two-pass form (`count()` then `nth()`)
/// evaluated `is_live` twice per candidate, so (a) a neighbor removed
/// between the two passes made `live > 0` true at count time but
/// `nth(pick)` yield `None` → spurious no-route even though a live
/// candidate existed at count time, and (b) every session-miss ECMP
/// lookup ran two full sets of neighbor hash probes on the hot path.
///
/// Fix: materialize the live candidates into a stack `SmallVec` of
/// references in one pass, so the count and the selection observe the
/// SAME liveness snapshot. ECMP fanout is small (a handful of equal-cost
/// members), so the inline capacity (8) covers the common case without a
/// heap allocation. Selection semantics are unchanged: when any member is
/// live, the pick is `ip_hash % live_count` over the live set in original
/// candidate order (so the same flow pins to the same member given the
/// same liveness); when none are live, fall back to the same hashed pick
/// over the full candidate vector so the kernel slow-path can drive
/// ARP/NDP.
/// #2923: ECMP candidate liveness for a TUNNEL next-hop.
///
/// A tunnel candidate (`tunnel_endpoint_id != 0`) is NOT a neighbor-resolved
/// L2 next-hop on the logical tunnel ifindex, so the direct-neighbor liveness
/// gate (`ifindex > 0 && lookup_neighbor_entry(...)`) always marks it dead.
/// In a MIXED direct+tunnel ECMP group a live direct member makes `live > 0`,
/// which restricts selection to direct candidates and starves the tunnel path
/// even when its underlay is fully up.
///
/// A tunnel next-hop is live iff its endpoint exists AND the OUTER transport
/// resolves to a FORWARDABLE disposition. `resolve_tunnel_outer` already
/// rejects the structurally-broken cases (unknown endpoint, local-delivery
/// outer, tunnel-interface recursion loop) by returning `None`, but a tunnel
/// whose underlay ROUTE is withdrawn still returns
/// `Some(ForwardingResolution { disposition: NoRoute, egress_ifindex: 0, .. })`
/// — a bare `.is_some()` would mark that DEAD tunnel live, and in a mixed
/// group ~half the flows would hash to it and DROP (NoRoute) despite a fully
/// live direct member (#2923 review finding). So gate on the OUTER
/// disposition:
///
/// * `ForwardCandidate` — outer next-hop neighbor resolved, fully usable.
/// * `MissingNeighbor` — outer route present, ARP/NDP pending; the cold path
///   drives resolution, so this is LIVE, matching the direct-hop branch which
///   keeps an `ifindex > 0` next-hop selectable while its neighbor resolves
///   (a tunnel marked MissingNeighbor egresses the logical tunnel ifindex and
///   the cold path probes the OUTER hop via `outer_neighbor_ifindex`).
///
/// Every other disposition (`NoRoute`, `DiscardRoute`, `NextTableUnsupported`,
/// etc.) means the underlay cannot forward → DEAD, so selection skips it and a
/// live alternate (direct or another tunnel) carries the flow. Reusing
/// `resolve_tunnel_outer` keeps liveness identical to what selection later
/// resolves via `resolve_tunnel_forwarding_resolution`. `depth` is forwarded
/// so the outer re-resolution honors the same next-table recursion budget as
/// the caller.
fn tunnel_next_hop_live(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    tunnel_endpoint_id: u16,
    depth: usize,
) -> bool {
    matches!(
        resolve_tunnel_outer(state, dynamic_neighbors, tunnel_endpoint_id, depth)
            .map(|outer| outer.disposition),
        Some(ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor)
    )
}

fn select_route_next_hop<'a, T: Copy>(
    candidates: &'a [T],
    ip_hash: u64,
    is_live: impl Fn(&T) -> bool,
) -> Option<&'a T> {
    if candidates.is_empty() {
        return None;
    }
    // Single liveness evaluation: collect live candidate references once.
    // `is_live` is called exactly `candidates.len()` times total.
    let live: smallvec::SmallVec<[&'a T; 8]> =
        candidates.iter().filter(|c| is_live(c)).collect();
    if !live.is_empty() {
        let pick = (ip_hash % live.len() as u64) as usize;
        // `pick < live.len()` by construction, so this never yields None.
        live.get(pick).copied()
    } else {
        let pick = (ip_hash % candidates.len() as u64) as usize;
        candidates.get(pick)
    }
}

#[cfg(test)]
mod tests;
