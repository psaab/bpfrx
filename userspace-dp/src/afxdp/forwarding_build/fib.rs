//! FIB / neighbor / fabric population for `build_forwarding_state`.
//!
//! Owns:
//!
//! - [`sort_connected`] — sort `state.connected_v[46]` by prefix length.
//! - [`populate_routes`] — walk `snapshot.routes`, push into
//!   `state.routes_v[46]` keyed by canonical table name.
//! - [`sort_routes`] — sort each route table by prefix length.
//! - [`populate_neighbors`] — copy usable neighbors into
//!   `state.neighbors`.
//! - [`populate_fabrics`] — append `FabricLink` entries to
//!   `state.fabrics`, resolving local + peer MACs through
//!   [`IfaceIndex`] and the populated `state.neighbors` map.
//!
//! Also hosts the route-target resolution helpers
//! ([`resolve_route_next_hops_v4`] etc.) re-exported by
//! `forwarding_build/mod.rs` as `pub(in crate::afxdp)` for the
//! other afxdp siblings that consume them via `use
//! self::forwarding_build::*;` in `afxdp/mod.rs`.

use super::super::*;
use super::interfaces::IfaceIndex;
use crate::RouteSnapshot;
use ipnet::{Ipv4Net, Ipv6Net};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(super) fn sort_connected(state: &mut ForwardingState) {
    state
        .connected_v4
        .sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
    state
        .connected_v6
        .sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
}

pub(super) fn populate_routes(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
    iface_ctx: &IfaceIndex,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    use crate::policy::SnapshotIntegrityError;
    for route in &snapshot.routes {
        // #3771 (L1): reject a NEGATIVE route preference. The FIB tie-breaks
        // same-prefix routes by ascending preference (`sort_routes`); a negative
        // value (e.g. i32::MIN) would sort ahead of every route and silently
        // hijack the selection for that prefix. Checked before the family/prefix
        // parse so it applies to every route shape.
        if route.preference < 0 {
            return Err(SnapshotIntegrityError::RoutePreferenceOutOfRange {
                table: route.table.clone(),
                destination: route.destination.clone(),
                preference: route.preference,
            });
        }
        if let Ok(prefix) = route.destination.parse::<Ipv4Net>() {
            // #3771 (M4): the destination parses as IPv4 — a NON-EMPTY declared
            // family must agree ("inet"), else the route's family metadata
            // contradicts the FIB it would install into. Fail CLOSED rather than
            // install into routes_v4 while `family` claims v6.
            if route_family_mismatch(&route.family, false) {
                return Err(SnapshotIntegrityError::RouteFamilyMismatch {
                    table: route.table.clone(),
                    destination: route.destination.clone(),
                    family: route.family.clone(),
                });
            }
            let next_hops = resolve_route_next_hops_v4(
                route,
                &iface_ctx.name_to_ifindex,
                &iface_ctx.linux_to_ifindex,
                state,
            );
            let table = canonical_route_table(&route.table, false);
            state
                .routes_v4
                .entry(table)
                .or_default()
                .push(RouteEntryV4 {
                    prefix: PrefixV4::from_net(prefix),
                    next_hops,
                    discard: route.discard,
                    next_table: route.next_table.clone(),
                    preference: route.preference,
                });
            continue;
        }
        if let Ok(prefix) = route.destination.parse::<Ipv6Net>() {
            // #3771 (M4): the destination parses as IPv6 — a NON-EMPTY declared
            // family must agree ("inet6").
            if route_family_mismatch(&route.family, true) {
                return Err(SnapshotIntegrityError::RouteFamilyMismatch {
                    table: route.table.clone(),
                    destination: route.destination.clone(),
                    family: route.family.clone(),
                });
            }
            let next_hops = resolve_route_next_hops_v6(
                route,
                &iface_ctx.name_to_ifindex,
                &iface_ctx.linux_to_ifindex,
                state,
            );
            let table = canonical_route_table(&route.table, true);
            state
                .routes_v6
                .entry(table)
                .or_default()
                .push(RouteEntryV6 {
                    prefix: PrefixV6::from_net(prefix),
                    next_hops,
                    discard: route.discard,
                    next_table: route.next_table.clone(),
                    preference: route.preference,
                });
        }
    }
    Ok(())
}

/// #3771 (M4): true iff `family` is a NON-EMPTY declared address family that
/// does not match the actual family (`is_ipv6`). An empty family (older /
/// omitted producer) is unconstrained — the pre-fix parse-only behaviour — and
/// is never a mismatch. Any non-empty string other than the matching canonical
/// token ("inet" for v4, "inet6" for v6) is a mismatch, so a corrupt / unknown
/// family also fails closed.
fn route_family_mismatch(family: &str, is_ipv6: bool) -> bool {
    let fam = family.trim();
    if fam.is_empty() {
        return false;
    }
    if is_ipv6 {
        !fam.eq_ignore_ascii_case("inet6")
    } else {
        !fam.eq_ignore_ascii_case("inet")
    }
}

pub(super) fn sort_routes(state: &mut ForwardingState) {
    // #2390: order each table by descending prefix length (longest-match
    // first), then ASCENDING preference (lower = more preferred per Junos),
    // so `routes.iter().find(prefix.contains)` returns the most-specific
    // and, among same-prefix routes, the operator-preferred one — NOT the
    // insertion-order first. `sort_by` is stable, so same-prefix /
    // same-preference routes keep their relative (insertion) order.
    for routes in state.routes_v4.values_mut() {
        routes.sort_by(|a, b| {
            b.prefix
                .prefix_len()
                .cmp(&a.prefix.prefix_len())
                .then(a.preference.cmp(&b.preference))
        });
    }
    for routes in state.routes_v6.values_mut() {
        routes.sort_by(|a, b| {
            b.prefix
                .prefix_len()
                .cmp(&a.prefix.prefix_len())
                .then(a.preference.cmp(&b.preference))
        });
    }
}

pub(super) fn populate_neighbors(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    for neigh in &snapshot.neighbors {
        if neigh.ifindex <= 0 {
            continue;
        }
        let Ok(ip) = neigh.ip.parse::<IpAddr>() else {
            continue;
        };
        // #3771 (M11): fail CLOSED on a neighbor whose NON-EMPTY declared family
        // contradicts its parsed IP, rather than installing it under the wrong
        // family. Checked before the state / MAC skips so a family-metadata
        // corruption is surfaced regardless of whether the entry is installable.
        if neighbor_family_mismatch(&neigh.family, &ip) {
            return Err(crate::policy::SnapshotIntegrityError::NeighborFamilyMismatch {
                interface: neigh.interface.clone(),
                ip: neigh.ip.clone(),
                family: neigh.family.clone(),
            });
        }
        // #3771 (M12): allowlist neighbor states — skip a known-unusable state
        // (failed/incomplete) silently and COUNT an unknown/future state
        // (none/empty/corrupt), instead of the pre-fix denylist that installed
        // every unrecognized state that happened to carry a parseable IP+MAC.
        match classify_neighbor_state(&neigh.state) {
            NeighborStateClass::Usable => {}
            NeighborStateClass::KnownUnusable => continue,
            NeighborStateClass::Unknown => {
                NEIGHBOR_UNKNOWN_STATE_SKIPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                continue;
            }
        }
        let Some(mac) = parse_mac(&neigh.mac) else {
            continue;
        };
        state
            .neighbors
            .insert((neigh.ifindex, ip), NeighborEntry { mac });
    }
    Ok(())
}

/// #3771 (M11): true iff `family` is a NON-EMPTY declared address family that
/// does not match the actual family of `ip`. An empty family (older / omitted
/// producer) is unconstrained and never a mismatch; any non-empty non-matching
/// value (including a corrupt/unknown token) fails closed.
fn neighbor_family_mismatch(family: &str, ip: &IpAddr) -> bool {
    let fam = family.trim();
    if fam.is_empty() {
        return false;
    }
    match ip {
        IpAddr::V4(_) => !fam.eq_ignore_ascii_case("inet"),
        IpAddr::V6(_) => !fam.eq_ignore_ascii_case("inet6"),
    }
}

pub(super) fn populate_fabrics(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
    iface_ctx: &IfaceIndex,
) {
    for fabric in &snapshot.fabrics {
        if fabric.parent_ifindex <= 0 {
            continue;
        }
        let Ok(peer_addr) = fabric.peer_address.parse::<IpAddr>() else {
            continue;
        };
        let local_mac = parse_mac(&fabric.local_mac)
            .or_else(|| iface_ctx.mac_by_ifindex.get(&fabric.parent_ifindex).copied());
        let Some(local_mac) = local_mac else {
            continue;
        };
        let peer_mac = parse_mac(&fabric.peer_mac).or_else(|| {
            state
                .neighbors
                .get(&(fabric.overlay_ifindex, peer_addr))
                .or_else(|| state.neighbors.get(&(fabric.parent_ifindex, peer_addr)))
                .map(|entry| entry.mac)
        });
        let Some(peer_mac) = peer_mac else {
            continue;
        };
        state.fabrics.push(FabricLink {
            parent_ifindex: fabric.parent_ifindex,
            overlay_ifindex: fabric.overlay_ifindex,
            peer_addr,
            peer_mac,
            local_mac,
        });
    }
}

/// #2389: resolve EVERY configured next-hop of a static route into a
/// `RouteNextHopV4` candidate. A discard / next-table route has no
/// forwarding next-hop (returns empty). Each candidate resolves its egress
/// ifindex from an explicit `@interface` spec, else by inferring the
/// connected interface that contains the gateway IP — scoped to the
/// route's own table (#2388) so a gateway is never resolved against
/// another routing-instance's connected prefix. Candidates whose interface
/// fails to resolve are still retained with ifindex 0 (matching the
/// pre-#2389 single-next-hop fallback, which kept next_hop with ifindex 0).
pub(in crate::afxdp) fn resolve_route_next_hops_v4(
    route: &RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
) -> Vec<RouteNextHopV4> {
    if route.discard || !route.next_table.is_empty() {
        return Vec::new();
    }
    route
        .next_hops
        .iter()
        .map(|nh| {
            let (next_hop, interface) = parse_route_next_hop(nh.as_str());
            let (ifindex, tunnel_endpoint_id) = resolve_next_hop_target_v4(
                next_hop,
                interface.as_deref(),
                names,
                linux_names,
                state,
            );
            RouteNextHopV4 {
                next_hop,
                ifindex,
                tunnel_endpoint_id,
            }
        })
        .collect()
}

pub(in crate::afxdp) fn resolve_route_next_hops_v6(
    route: &RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
) -> Vec<RouteNextHopV6> {
    if route.discard || !route.next_table.is_empty() {
        return Vec::new();
    }
    route
        .next_hops
        .iter()
        .map(|nh| {
            let (next_hop, interface) = parse_route_next_hop_v6(nh.as_str());
            let (ifindex, tunnel_endpoint_id) = resolve_next_hop_target_v6(
                next_hop,
                interface.as_deref(),
                names,
                linux_names,
                state,
            );
            RouteNextHopV6 {
                next_hop,
                ifindex,
                tunnel_endpoint_id,
            }
        })
        .collect()
}

fn resolve_next_hop_target_v4(
    next_hop: Option<Ipv4Addr>,
    interface: Option<&str>,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
) -> (i32, u16) {
    interface
        .and_then(|name| resolve_ifindex(name, names, linux_names))
        .map(|ifindex| {
            (
                ifindex,
                state
                    .tunnel_endpoint_by_ifindex
                    .get(&ifindex)
                    .copied()
                    .unwrap_or(0),
            )
        })
        .or_else(|| next_hop.and_then(|ip| infer_connected_route_target_v4(state, ip)))
        .unwrap_or((0, 0))
}

fn resolve_next_hop_target_v6(
    next_hop: Option<Ipv6Addr>,
    interface: Option<&str>,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
) -> (i32, u16) {
    interface
        .and_then(|name| resolve_ifindex(name, names, linux_names))
        .map(|ifindex| {
            (
                ifindex,
                state
                    .tunnel_endpoint_by_ifindex
                    .get(&ifindex)
                    .copied()
                    .unwrap_or(0),
            )
        })
        .or_else(|| next_hop.and_then(|ip| infer_connected_route_target_v6(state, ip)))
        .unwrap_or((0, 0))
}

pub(in crate::afxdp) fn parse_route_next_hop(spec: &str) -> (Option<Ipv4Addr>, Option<String>) {
    let (ip_part, if_part) = if let Some((lhs, rhs)) = spec.split_once('@') {
        (lhs, rhs)
    } else {
        (spec, "")
    };
    let ip = if ip_part.is_empty() {
        None
    } else {
        ip_part.parse::<Ipv4Addr>().ok()
    };
    let iface = if if_part.is_empty() {
        None
    } else {
        Some(if_part.to_string())
    };
    (ip, iface)
}

pub(in crate::afxdp) fn parse_route_next_hop_v6(spec: &str) -> (Option<Ipv6Addr>, Option<String>) {
    let (ip_part, if_part) = if let Some((lhs, rhs)) = spec.split_once('@') {
        (lhs, rhs)
    } else {
        (spec, "")
    };
    let ip = if ip_part.is_empty() {
        None
    } else {
        ip_part.parse::<Ipv6Addr>().ok()
    };
    let iface = if if_part.is_empty() {
        None
    } else {
        Some(if_part.to_string())
    };
    (ip, iface)
}

pub(in crate::afxdp) fn resolve_ifindex(
    name: &str,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
) -> Option<i32> {
    names
        .get(name)
        .copied()
        .or_else(|| linux_names.get(name).copied())
}

pub(in crate::afxdp) fn infer_connected_route_target_v4(
    state: &ForwardingState,
    ip: Ipv4Addr,
) -> Option<(i32, u16)> {
    // Gateway -> egress-interface inference at FIB-build time: "which
    // interface can reach this next-hop gateway IP". This is a global
    // connected-prefix match and is intentionally NOT table-scoped — a
    // route's configured gateway resolves to whatever connected interface
    // contains it. The #2388 cross-VRF leak is a LOOKUP-time concern
    // (which connected prefix a destination egresses on) and is fixed at
    // the lookup site by filtering connected_v4 on the resolving table.
    state
        .connected_v4
        .iter()
        .find(|entry| entry.prefix.contains(ip))
        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
}

pub(in crate::afxdp) fn infer_connected_route_target_v6(
    state: &ForwardingState,
    ip: Ipv6Addr,
) -> Option<(i32, u16)> {
    state
        .connected_v6
        .iter()
        .find(|entry| entry.prefix.contains(ip))
        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
}
