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
) -> IfaceIndex {
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
        name_to_ifindex.insert(iface.name.clone(), iface.ifindex);
        if !iface.linux_name.is_empty() {
            linux_to_ifindex.insert(iface.linux_name.clone(), iface.ifindex);
        }
        if !iface.zone.is_empty() {
            // #921: resolve zone NAME → u16 once at config build, so
            // every read on the hot path is one HashMap lookup
            // (ifindex → u16). Unknown / dropped zones map to 0 (the
            // canonical "unknown" sentinel).
            let zone_id = state.zone_name_to_id.get(&iface.zone).copied().unwrap_or(0);
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
        for addr in &iface.addresses {
            let Ok(net) = addr.address.parse::<IpNet>() else {
                continue;
            };
            match net {
                IpNet::V4(v4) => {
                    if excluded_local_v4.contains(&v4.addr()) {
                        state.interface_nat_v4.insert(v4.addr(), iface.ifindex);
                    } else {
                        state.local_v4.insert(v4.addr());
                    }
                    state.connected_v4.push(ConnectedRouteV4 {
                        prefix: PrefixV4::from_net(v4),
                        ifindex: iface.ifindex,
                        tunnel_endpoint_id,
                    });
                }
                IpNet::V6(v6) => {
                    if excluded_local_v6.contains(&v6.addr()) {
                        state.interface_nat_v6.insert(v6.addr(), iface.ifindex);
                    } else {
                        state.local_v6.insert(v6.addr());
                    }
                    state.connected_v6.push(ConnectedRouteV6 {
                        prefix: PrefixV6::from_net(v6),
                        ifindex: iface.ifindex,
                        tunnel_endpoint_id,
                    });
                }
            }
        }
    }

    IfaceIndex {
        name_to_ifindex,
        linux_to_ifindex,
        mac_by_ifindex,
    }
}

pub(super) fn populate_egress(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
    iface_ctx: &IfaceIndex,
) {
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let bind_ifindex = if iface.parent_ifindex > 0 {
            iface.parent_ifindex
        } else {
            iface.ifindex
        };
        let ingress_key = (bind_ifindex, iface.vlan_id.max(0) as u16);
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
        // #921: resolve zone name → u16 at build time. 0 for
        // unknown / dropped zones (consistent with ifindex_to_zone_id).
        let zone_id = state.zone_name_to_id.get(&iface.zone).copied().unwrap_or(0);
        state.egress.insert(
            iface.ifindex,
            EgressInterface {
                bind_ifindex,
                vlan_id: iface.vlan_id.max(0) as u16,
                mtu: iface.mtu.max(0) as usize,
                src_mac,
                zone_id,
                redundancy_group: iface.redundancy_group,
                primary_v4: pick_interface_v4(iface),
                primary_v6: pick_interface_v6(iface),
            },
        );
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
