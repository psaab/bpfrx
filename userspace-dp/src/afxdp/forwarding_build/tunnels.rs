//! Tunnel-endpoint population for `build_forwarding_state`.
//!
//! Populates `state.tunnel_endpoints` and
//! `state.tunnel_endpoint_by_ifindex`. Must run before the
//! interfaces addresses pass, which reads
//! `tunnel_endpoint_by_ifindex` when building
//! `ConnectedRouteV4/V6.tunnel_endpoint_id`.

use super::super::*;
use std::net::IpAddr;

pub(super) fn populate_tunnel_endpoints(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
) {
    for endpoint in &snapshot.tunnel_endpoints {
        if endpoint.id == 0 || endpoint.ifindex <= 0 {
            continue;
        }
        let Ok(source) = endpoint.source.parse::<IpAddr>() else {
            continue;
        };
        let Ok(destination) = endpoint.destination.parse::<IpAddr>() else {
            continue;
        };
        let outer_family = match (endpoint.outer_family.as_str(), destination) {
            ("inet6", _) => libc::AF_INET6,
            ("inet", _) => libc::AF_INET,
            (_, IpAddr::V6(_)) => libc::AF_INET6,
            _ => libc::AF_INET,
        };
        let transport_table =
            canonical_route_table(&endpoint.transport_table, outer_family == libc::AF_INET6);
        state.tunnel_endpoints.insert(
            endpoint.id,
            TunnelEndpoint {
                id: endpoint.id,
                logical_ifindex: endpoint.ifindex,
                redundancy_group: endpoint.redundancy_group,
                mode: endpoint.mode.clone(),
                outer_family,
                source,
                destination,
                key: endpoint.key,
                ttl: endpoint.ttl.max(0) as u8,
                transport_table,
            },
        );
        state
            .tunnel_endpoint_by_ifindex
            .insert(endpoint.ifindex, endpoint.id);
    }
}
