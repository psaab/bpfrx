//! Interface-state population for `build_forwarding_state`.
//!
//! Two passes:
//!
//! 1. [`populate_interfaces`] — walks `snapshot.interfaces`,
//!    populates `state.ifindex_to_*`, `state.ifindex_to_zone_id`,
//!    `state.tunnel_interfaces`, `state.local_v[46]`,
//!    `state.interface_nat_v[46]`, `state.connected_v[46]`. Returns
//!    an [`IfaceIndex`] context with `name_to_ifindex` /
//!    `linux_to_ifindex` / `mac_by_ifindex` carried across the
//!    later egress, route, and fabric passes.
//! 2. [`populate_egress`] — walks `snapshot.interfaces` a second
//!    time to build per-interface `EgressInterface` entries with
//!    the resolved `bind_ifindex`, MAC, and zone_id.

use super::super::*;
use ipnet::IpNet;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Carry context built by [`populate_interfaces`] for downstream
/// passes (egress / fib / fabrics). Owned by the orchestrator;
/// passed by `&` to consumers.
pub(super) struct IfaceIndex {
    pub name_to_ifindex: BTreeMap<String, i32>,
    pub linux_to_ifindex: BTreeMap<String, i32>,
    pub mac_by_ifindex: BTreeMap<i32, [u8; 6]>,
}

pub(super) fn populate_interfaces(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
    excluded_local_v4: &FastSet<Ipv4Addr>,
    excluded_local_v6: &FastSet<Ipv6Addr>,
) -> Result<IfaceIndex, crate::policy::SnapshotIntegrityError> {
    let mut name_to_ifindex = BTreeMap::new();
    let mut linux_to_ifindex = BTreeMap::new();
    let mut mac_by_ifindex = BTreeMap::new();

    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let label = if iface.linux_name.is_empty() {
            iface.name.clone()
        } else {
            iface.linux_name.clone()
        };
        state.ifindex_to_name.insert(iface.ifindex, label);
        state
            .ifindex_to_config_name
            .insert(iface.ifindex, iface.name.clone());
        // #3096: record the interface's routing instance for NAT rule-set
        // `from`/`to routing-instance` scope matching ("" = default VRF).
        state
            .ifindex_to_routing_instance
            .insert(iface.ifindex, iface.routing_instance.clone());
        name_to_ifindex.insert(iface.name.clone(), iface.ifindex);
        if !iface.linux_name.is_empty() {
            linux_to_ifindex.insert(iface.linux_name.clone(), iface.ifindex);
        }
        if !iface.zone.is_empty() {
            // #921: resolve zone NAME → u16 once at config build, so
            // every read on the hot path is one HashMap lookup
            // (ifindex → u16).
            // #2391: a non-empty zone NAME that is not in the zone table
            // (dropped at populate_zones for a u8-overflow id, or a
            // version-drifted/hostile snapshot) must FAIL CLOSED instead of
            // collapsing to zone 0 — collapsing bypasses every zone-pair policy
            // (fail-open under a permit default). The Go commit-time cap is the
            // primary gate; this is the helper-boundary backstop.
            let zone_id = match state.zone_name_to_id.get(&iface.zone).copied() {
                Some(id) => id,
                None => {
                    return Err(crate::policy::SnapshotIntegrityError::InterfaceUnknownZone {
                        interface: iface.name.clone(),
                        zone: iface.zone.clone(),
                    });
                }
            };
            state.ifindex_to_zone_id.insert(iface.ifindex, zone_id);
            if iface.parent_ifindex > 0 {
                match state.ifindex_to_zone_id.get(&iface.parent_ifindex) {
                    Some(existing) if *existing != zone_id => {}
                    _ => {
                        state
                            .ifindex_to_zone_id
                            .insert(iface.parent_ifindex, zone_id);
                    }
                }
            }
        }
        // #3362: per-interface host-inbound OVERRIDE. When the control plane
        // marked this interface host-inbound-configured, classify its EFFECTIVE
        // (zone ∪ interface) token set and key it by ifindex so the
        // local-delivery admit path prefers it over the from-zone's set. A
        // present-but-empty override classifies to an empty ZoneHostInbound =
        // fail-closed deny-all (matching the zone-level semantics and the nft
        // primary path's per-interface drop).
        if iface.host_inbound_configured {
            state.ifindex_host_inbound.insert(
                iface.ifindex,
                crate::afxdp::forwarding::zone_host_inbound_from_tokens(
                    &iface.host_inbound_system_services,
                    &iface.host_inbound_protocols,
                ),
            );
        }
        if iface.tunnel {
            state.tunnel_interfaces.insert(iface.ifindex);
        }
        if let Some(mac) = parse_mac(&iface.hardware_addr) {
            mac_by_ifindex.insert(iface.ifindex, mac);
        }
        let tunnel_endpoint_id = state
            .tunnel_endpoint_by_ifindex
            .get(&iface.ifindex)
            .copied()
            .unwrap_or(0);
        // #2388: canonical connected-route table names for this interface's
        // routing-instance. "" (default instance) → inet.0 / inet6.0; a
        // named instance → "<ri>.inet.0" / "<ri>.inet6.0". The lookup
        // filters connected routes by the canonical table it is resolving
        // in, so a per-VRF / next-table lookup never matches a connected
        // prefix owned by a different routing-instance.
        let (connected_table_v4, connected_table_v6) =
            connected_route_tables(&iface.routing_instance);
        for addr in &iface.addresses {
            // #2409: fail CLOSED on an unparseable interface address rather
            // than silently `continue`-ing past it. The pre-fix skip lost the
            // connected route / local-address / interface-NAT material for
            // that address while the apply still succeeded — silent
            // connectivity loss in a retired-eBPF world. The Go commit-time
            // validation is the primary gate; this is the helper-boundary
            // backstop (the preflight keeps the previous good state).
            let net = addr.address.parse::<IpNet>().map_err(|_| {
                crate::policy::SnapshotIntegrityError::InterfaceAddressUnparseable {
                    interface: iface.name.clone(),
                    address: addr.address.clone(),
                }
            })?;
            match net {
                IpNet::V4(v4) => {
                    // #3182: record EVERY configured interface IP in the
                    // NAT-decoupled set BEFORE the NAT-exclusion branch, so the
                    // anti-poison `owns_configured_ip` gate protects the
                    // SNAT/WAN interface IP that the exclusion routes into
                    // `interface_nat_v4` (out of `local_v4`).
                    state.configured_iface_v4.insert(v4.addr());
                    if excluded_local_v4.contains(&v4.addr()) {
                        state.interface_nat_v4.insert(v4.addr(), iface.ifindex);
                    } else {
                        state.local_v4.insert(v4.addr());
                    }
                    state.connected_v4.push(ConnectedRouteV4 {
                        prefix: PrefixV4::from_net(v4),
                        ifindex: iface.ifindex,
                        tunnel_endpoint_id,
                        table: connected_table_v4.clone(),
                    });
                }
                IpNet::V6(v6) => {
                    // #3182: NAT-decoupled full interface-IP set (see the V4
                    // arm above) — protects the SNAT/WAN IPv6 interface IP too.
                    state.configured_iface_v6.insert(v6.addr());
                    if excluded_local_v6.contains(&v6.addr()) {
                        state.interface_nat_v6.insert(v6.addr(), iface.ifindex);
                    } else {
                        state.local_v6.insert(v6.addr());
                    }
                    state.connected_v6.push(ConnectedRouteV6 {
                        prefix: PrefixV6::from_net(v6),
                        ifindex: iface.ifindex,
                        tunnel_endpoint_id,
                        table: connected_table_v6.clone(),
                    });
                }
            }
        }
    }

    Ok(IfaceIndex {
        name_to_ifindex,
        linux_to_ifindex,
        mac_by_ifindex,
    })
}

pub(super) fn populate_egress(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
    iface_ctx: &IfaceIndex,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let bind_ifindex = if iface.parent_ifindex > 0 {
            iface.parent_ifindex
        } else {
            iface.ifindex
        };
        // #2410: validate the VLAN id ONCE here instead of narrowing it with
        // an unchecked `iface.vlan_id.max(0) as u16` at both the ingress-key
        // and the EgressInterface.vlan_id site. An out-of-range value
        // (> 65535) fails the snapshot closed rather than wrapping to a
        // different VLAN (a different L2 domain).
        let vlan_id = super::validated::VlanId::try_from_snapshot(iface.vlan_id, &iface.name)?.get();
        // #2706: validate the MTU ONCE here instead of narrowing it with an
        // unchecked `iface.mtu.max(0) as usize`. A NEGATIVE value fails the
        // snapshot closed rather than collapsing to 0 — which the egress MTU
        // guard treats as "unknown; forward", silently disabling PTB/drop
        // enforcement. 0 (the legitimate "unknown MTU" sentinel) stays
        // permissive.
        let mtu = super::validated::InterfaceMtu::try_from_snapshot(iface.mtu, &iface.name)?.get();
        let ingress_key = (bind_ifindex, vlan_id);
        if iface.parent_ifindex > 0 {
            state
                .ingress_logical_ifindex
                .insert(ingress_key, iface.ifindex);
        } else {
            state
                .ingress_logical_ifindex
                .entry(ingress_key)
                .or_insert(iface.ifindex);
        }
        let src_mac = match parse_mac(&iface.hardware_addr)
            .or_else(|| iface_ctx.mac_by_ifindex.get(&bind_ifindex).copied())
            .or_else(|| iface.tunnel.then_some([0; 6]))
        {
            Some(mac) => mac,
            None => continue,
        };
        // #921: resolve zone name → u16 at build time.
        // #2391: a non-empty zone name absent from the zone table fails CLOSED
        // (consistent with populate_interfaces); an empty zone (unzoned
        // interface) maps to 0, the legitimate "no zone" case.
        let zone_id = if iface.zone.is_empty() {
            0
        } else {
            match state.zone_name_to_id.get(&iface.zone).copied() {
                Some(id) => id,
                None => {
                    return Err(crate::policy::SnapshotIntegrityError::InterfaceUnknownZone {
                        interface: iface.name.clone(),
                        zone: iface.zone.clone(),
                    });
                }
            }
        };
        state.egress.insert(
            iface.ifindex,
            EgressInterface {
                bind_ifindex,
                vlan_id,
                mtu,
                src_mac,
                zone_id,
                redundancy_group: iface.redundancy_group,
                primary_v4: pick_interface_v4(iface),
                primary_v6: pick_interface_v6(iface),
            },
        );
    }
    Ok(())
}

/// #2388: canonical (v4, v6) connected-route table names for a routing
/// instance. The empty instance name is the default instance
/// (inet.0 / inet6.0); a named instance maps to "<ri>.inet.0" /
/// "<ri>.inet6.0". These match the names the lookup canonicalizes the
/// queried table to (`canonical_route_table`), so a connected entry is
/// only matched when the lookup is resolving in the owning table.
pub(in crate::afxdp) fn connected_route_tables(routing_instance: &str) -> (String, String) {
    if routing_instance.is_empty() {
        ("inet.0".to_string(), "inet6.0".to_string())
    } else {
        (
            format!("{routing_instance}.inet.0"),
            format!("{routing_instance}.inet6.0"),
        )
    }
}

pub(in crate::afxdp) fn pick_interface_v4(iface: &InterfaceSnapshot) -> Option<Ipv4Addr> {
    let mut fallback = None;
    for addr in &iface.addresses {
        if addr.family != "inet" {
            continue;
        }
        let Ok(net) = addr.address.parse::<ipnet::Ipv4Net>() else {
            continue;
        };
        let ip = net.addr();
        if fallback.is_none() {
            fallback = Some(ip);
        }
        if !ip.is_link_local() {
            return Some(ip);
        }
    }
    fallback
}

pub(in crate::afxdp) fn pick_interface_v6(iface: &InterfaceSnapshot) -> Option<Ipv6Addr> {
    let mut fallback = None;
    for addr in &iface.addresses {
        if addr.family != "inet6" {
            continue;
        }
        let Ok(net) = addr.address.parse::<ipnet::Ipv6Net>() else {
            continue;
        };
        let ip = net.addr();
        if fallback.is_none() {
            fallback = Some(ip);
        }
        if !ip.is_unicast_link_local() {
            return Some(ip);
        }
    }
    fallback
}
