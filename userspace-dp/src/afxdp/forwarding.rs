use super::*;
use crate::RouteSnapshot;

const DEFAULT_V4_TABLE: &str = "inet.0";
const DEFAULT_V6_TABLE: &str = "inet6.0";
const MAX_NEXT_TABLE_DEPTH: usize = 8;

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

pub(super) fn build_screen_profiles(snapshot: &ConfigSnapshot) -> FxHashMap<String, ScreenProfile> {
    let mut profiles = FxHashMap::default();
    for sp in &snapshot.screens {
        if sp.zone.is_empty() {
            continue;
        }
        profiles.insert(
            sp.zone.clone(),
            ScreenProfile {
                land: sp.land,
                syn_fin: sp.syn_fin,
                no_flag: sp.tcp_no_flag,
                fin_no_ack: sp.fin_no_ack,
                winnuke: sp.winnuke,
                ping_death: sp.ping_death,
                teardrop: sp.teardrop,
                icmp_fragment: sp.icmp_fragment,
                source_route: sp.source_route,
                icmp_flood_threshold: sp.icmp_flood_threshold,
                udp_flood_threshold: sp.udp_flood_threshold,
                syn_flood_threshold: sp.syn_flood_threshold,
                session_limit_src: sp.session_limit_src,
                session_limit_dst: sp.session_limit_dst,
                port_scan_threshold: sp.port_scan_threshold,
                ip_sweep_threshold: sp.ip_sweep_threshold,
            },
        );
    }
    profiles
}

pub(super) fn build_forwarding_state(snapshot: &ConfigSnapshot) -> ForwardingState {
    let mut state = ForwardingState::default();
    let mut name_to_ifindex = BTreeMap::new();
    let mut linux_to_ifindex = BTreeMap::new();
    let mut mac_by_ifindex = BTreeMap::new();
    let (excluded_local_v4, excluded_local_v6) = nat_translated_local_exclusions(snapshot);

    for zone in &snapshot.zones {
        if zone.id == 0 || zone.name.is_empty() {
            continue;
        }
        state.zone_name_to_id.insert(zone.name.clone(), zone.id);
        state.zone_id_to_name.insert(zone.id, zone.name.clone());
    }

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
        name_to_ifindex.insert(iface.name.clone(), iface.ifindex);
        if !iface.linux_name.is_empty() {
            linux_to_ifindex.insert(iface.linux_name.clone(), iface.ifindex);
        }
        if !iface.zone.is_empty() {
            state
                .ifindex_to_zone
                .insert(iface.ifindex, iface.zone.clone());
            if iface.parent_ifindex > 0 {
                match state.ifindex_to_zone.get(&iface.parent_ifindex) {
                    Some(existing) if existing != &iface.zone => {}
                    _ => {
                        state
                            .ifindex_to_zone
                            .insert(iface.parent_ifindex, iface.zone.clone());
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

    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let bind_ifindex = if iface.parent_ifindex > 0 {
            iface.parent_ifindex
        } else {
            iface.ifindex
        };
        let src_mac = match parse_mac(&iface.hardware_addr)
            .or_else(|| mac_by_ifindex.get(&bind_ifindex).copied())
            .or_else(|| iface.tunnel.then_some([0; 6]))
        {
            Some(mac) => mac,
            None => continue,
        };
        state.egress.insert(
            iface.ifindex,
            EgressInterface {
                bind_ifindex,
                vlan_id: iface.vlan_id.max(0) as u16,
                mtu: iface.mtu.max(0) as usize,
                src_mac,
                zone: iface.zone.clone(),
                redundancy_group: iface.redundancy_group,
                primary_v4: pick_interface_v4(iface),
                primary_v6: pick_interface_v6(iface),
            },
        );
    }

    state
        .connected_v4
        .sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
    state
        .connected_v6
        .sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));

    for route in &snapshot.routes {
        if let Ok(prefix) = route.destination.parse::<Ipv4Net>() {
            let (next_hop, ifindex, tunnel_endpoint_id) =
                resolve_route_target_v4(route, &name_to_ifindex, &linux_to_ifindex, &state);
            let table = canonical_route_table(&route.table, false);
            state
                .routes_v4
                .entry(table)
                .or_default()
                .push(RouteEntryV4 {
                    prefix: PrefixV4::from_net(prefix),
                    ifindex,
                    tunnel_endpoint_id,
                    next_hop,
                    discard: route.discard,
                    next_table: route.next_table.clone(),
                });
            continue;
        }
        if let Ok(prefix) = route.destination.parse::<Ipv6Net>() {
            let (next_hop, ifindex, tunnel_endpoint_id) =
                resolve_route_target_v6(route, &name_to_ifindex, &linux_to_ifindex, &state);
            let table = canonical_route_table(&route.table, true);
            state
                .routes_v6
                .entry(table)
                .or_default()
                .push(RouteEntryV6 {
                    prefix: PrefixV6::from_net(prefix),
                    ifindex,
                    tunnel_endpoint_id,
                    next_hop,
                    discard: route.discard,
                    next_table: route.next_table.clone(),
                });
        }
    }
    for routes in state.routes_v4.values_mut() {
        routes.sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
    }
    for routes in state.routes_v6.values_mut() {
        routes.sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
    }

    for neigh in &snapshot.neighbors {
        if neigh.ifindex <= 0 || !neighbor_state_usable(&neigh.state) {
            continue;
        }
        let Ok(ip) = neigh.ip.parse::<IpAddr>() else {
            continue;
        };
        let Some(mac) = parse_mac(&neigh.mac) else {
            continue;
        };
        state
            .neighbors
            .insert((neigh.ifindex, ip), NeighborEntry { mac });
    }
    for fabric in &snapshot.fabrics {
        if fabric.parent_ifindex <= 0 {
            continue;
        }
        let Ok(peer_addr) = fabric.peer_address.parse::<IpAddr>() else {
            continue;
        };
        let local_mac = parse_mac(&fabric.local_mac)
            .or_else(|| mac_by_ifindex.get(&fabric.parent_ifindex).copied());
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
    state.policy = parse_policy_state(&snapshot.default_policy, &snapshot.policies);
    state.allow_dns_reply = snapshot.flow.allow_dns_reply;
    state.allow_embedded_icmp = snapshot.flow.allow_embedded_icmp;
    state.session_timeouts = crate::session::SessionTimeouts::from_seconds(
        snapshot.flow.tcp_session_timeout,
        snapshot.flow.udp_session_timeout,
        snapshot.flow.icmp_session_timeout,
    );
    state.source_nat_rules = parse_source_nat_rules(&snapshot.source_nat_rules);
    state.static_nat = StaticNatTable::from_snapshots(&snapshot.static_nat_rules);
    state.dnat_table = DnatTable::from_snapshots(&snapshot.destination_nat_rules);
    state.nat64 = Nat64State::from_snapshots(&snapshot.nat64_rules);
    state.nptv6 = Nptv6State::from_snapshots(&snapshot.nptv6_rules);
    state.screen_profiles = build_screen_profiles(snapshot);
    state.tcp_mss_all_tcp = snapshot.flow.tcp_mss_all_tcp;
    state.tcp_mss_ipsec_vpn = snapshot.flow.tcp_mss_ipsec_vpn;
    state.tcp_mss_gre_in = snapshot.flow.tcp_mss_gre_in;
    state.tcp_mss_gre_out = snapshot.flow.tcp_mss_gre_out;
    // Build filter state from snapshot
    state.filter_state = crate::filter::parse_filter_state(
        &snapshot.filters,
        &snapshot.policers,
        &snapshot.interfaces,
        &snapshot.flow.lo0_filter_input_v4,
        &snapshot.flow.lo0_filter_input_v6,
    );
    // Build flow export config from snapshot
    state.flow_export_config = snapshot.flow_export.as_ref().and_then(|fe| {
        let addr = format!("{}:{}", fe.collector_address, fe.collector_port);
        addr.parse::<std::net::SocketAddr>().ok().map(|collector| {
            crate::flowexport::FlowExportConfig {
                collector,
                sampling_rate: fe.sampling_rate,
                active_timeout_secs: fe.active_timeout as u64,
                inactive_timeout_secs: fe.inactive_timeout as u64,
            }
        })
    });

    // Add static NAT external IPs as local delivery targets so inbound
    // traffic destined to external IPs is recognized by the firewall.
    for ext_ip in state.static_nat.external_ips() {
        match ext_ip {
            IpAddr::V4(v4) => {
                state.local_v4.insert(*v4);
            }
            IpAddr::V6(v6) => {
                state.local_v6.insert(*v6);
            }
        }
    }

    // Add DNAT destination IPs as local delivery targets so traffic
    // to those IPs is recognized as locally-destined and processed.
    for dst_ip in state.dnat_table.destination_ips() {
        match dst_ip {
            IpAddr::V4(v4) => {
                state.local_v4.insert(v4);
            }
            IpAddr::V6(v6) => {
                state.local_v6.insert(v6);
            }
        }
    }

    // Debug: dump zone mappings and policy rules
    #[cfg(feature = "debug-log")]
    {
        debug_log!("FWD_STATE: ifindex_to_zone={:?}", state.ifindex_to_zone);
        debug_log!(
            "FWD_STATE: egress keys={:?}",
            state.egress.keys().collect::<Vec<_>>()
        );
        for (ifidx, eg) in &state.egress {
            debug_log!(
                "FWD_STATE: egress[{}] bind={} zone={} vlan={} mtu={}",
                ifidx,
                eg.bind_ifindex,
                eg.zone,
                eg.vlan_id,
                eg.mtu,
            );
        }
        debug_log!(
            "FWD_STATE: policy default={:?} rules={}",
            state.policy.default_action,
            state.policy.rules.len(),
        );
        for (i, rule) in state.policy.rules.iter().enumerate() {
            debug_log!(
                "FWD_STATE: policy[{}] {}->{}  action={:?} src_v4={} dst_v4={} apps={}",
                i,
                rule.from_zone,
                rule.to_zone,
                rule.action,
                rule.source_v4.len(),
                rule.destination_v4.len(),
                rule.applications.len(),
            );
        }
        debug_log!(
            "FWD_STATE: local_v4={:?} interface_nat_v4={:?}",
            state.local_v4,
            state.interface_nat_v4,
        );
        debug_log!(
            "FWD_STATE: snat_rules={} static_nat={} dnat_table={} nptv6={} connected_v4={} routes_v4={}",
            state.source_nat_rules.len(),
            if state.static_nat.is_empty() {
                0
            } else {
                state.static_nat.external_ips().count()
            },
            if state.dnat_table.is_empty() {
                0
            } else {
                state.dnat_table.destination_ips().count()
            },
            if state.nptv6.is_empty() {
                0
            } else {
                state.nptv6.external_prefixes().len()
            },
            state.connected_v4.len(),
            state.routes_v4.values().map(|v| v.len()).sum::<usize>(),
        );
    }

    // Install nftables rules to suppress kernel TCP RSTs from SNAT IPs.
    //
    // When the AF_XDP fill ring momentarily runs dry under high load,
    // the mlx5 driver falls back to the regular RX path. Those leaked
    // packets reach the kernel TCP stack which — having no matching
    // socket — sends RSTs to the server, killing the connection.
    // Blocking outgoing RSTs for SNAT-managed IPs is a targeted fix:
    // the DP handles all TCP state for those addresses.
    install_kernel_rst_suppression(&state);

    state
}

/// Install nftables rules to DROP outgoing TCP RSTs from interface-NAT
/// (SNAT) addresses.  These addresses are owned by the userspace
/// dataplane; the kernel has no sockets for them and should never emit
/// RSTs.
pub(super) fn canonical_route_table(table: &str, is_ipv6: bool) -> String {
    if is_ipv6 {
        if table == "inet.0" {
            return "inet6.0".to_string();
        }
        if let Some(prefix) = table.strip_suffix(".inet.0") {
            return format!("{prefix}.inet6.0");
        }
        return table.to_string();
    }
    if table == "inet6.0" {
        return "inet.0".to_string();
    }
    if let Some(prefix) = table.strip_suffix(".inet6.0") {
        return format!("{prefix}.inet.0");
    }
    table.to_string()
}

pub(super) fn pick_interface_v4(iface: &InterfaceSnapshot) -> Option<Ipv4Addr> {
    let mut fallback = None;
    for addr in &iface.addresses {
        if addr.family != "inet" {
            continue;
        }
        let Ok(net) = addr.address.parse::<Ipv4Net>() else {
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

pub(super) fn pick_interface_v6(iface: &InterfaceSnapshot) -> Option<Ipv6Addr> {
    let mut fallback = None;
    for addr in &iface.addresses {
        if addr.family != "inet6" {
            continue;
        }
        let Ok(net) = addr.address.parse::<Ipv6Net>() else {
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

pub(super) fn resolve_route_target_v4(
    route: &RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
) -> (Option<Ipv4Addr>, i32, u16) {
    if route.discard || !route.next_table.is_empty() {
        return (None, 0, 0);
    }
    let Some((next_hop, interface)) = route
        .next_hops
        .first()
        .map(|nh| parse_route_next_hop(nh.as_str()))
    else {
        return (None, 0, 0);
    };
    let target = interface
        .as_deref()
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
        .or_else(|| next_hop.and_then(|ip| infer_connected_route_target_v4(state, ip)));
    let (ifindex, tunnel_endpoint_id) = target.unwrap_or((0, 0));
    (next_hop, ifindex, tunnel_endpoint_id)
}

pub(super) fn resolve_route_target_v6(
    route: &RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
) -> (Option<Ipv6Addr>, i32, u16) {
    if route.discard || !route.next_table.is_empty() {
        return (None, 0, 0);
    }
    let Some((next_hop, interface)) = route
        .next_hops
        .first()
        .map(|nh| parse_route_next_hop_v6(nh.as_str()))
    else {
        return (None, 0, 0);
    };
    let target = interface
        .as_deref()
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
        .or_else(|| next_hop.and_then(|ip| infer_connected_route_target_v6(state, ip)));
    let (ifindex, tunnel_endpoint_id) = target.unwrap_or((0, 0));
    (next_hop, ifindex, tunnel_endpoint_id)
}

pub(super) fn parse_route_next_hop(spec: &str) -> (Option<Ipv4Addr>, Option<String>) {
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

pub(super) fn parse_route_next_hop_v6(spec: &str) -> (Option<Ipv6Addr>, Option<String>) {
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

pub(super) fn resolve_ifindex(
    name: &str,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
) -> Option<i32> {
    names
        .get(name)
        .copied()
        .or_else(|| linux_names.get(name).copied())
}

pub(super) fn infer_connected_route_target_v4(
    state: &ForwardingState,
    ip: Ipv4Addr,
) -> Option<(i32, u16)> {
    state
        .connected_v4
        .iter()
        .find(|entry| entry.prefix.contains(ip))
        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
}

pub(super) fn infer_connected_route_target_v6(
    state: &ForwardingState,
    ip: Ipv6Addr,
) -> Option<(i32, u16)> {
    state
        .connected_v6
        .iter()
        .find(|entry| entry.prefix.contains(ip))
        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
}

pub(super) fn neighbor_state_usable(state: &str) -> bool {
    let normalized = state.to_ascii_lowercase();
    !(normalized.contains("failed") || normalized.contains("incomplete"))
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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
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

pub(super) fn match_source_nat_for_flow(
    forwarding: &ForwardingState,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    flow: &SessionFlow,
) -> Option<NatDecision> {
    let egress = forwarding.egress.get(&egress_ifindex)?;
    match_source_nat(
        &forwarding.source_nat_rules,
        from_zone,
        to_zone,
        flow.src_ip,
        flow.dst_ip,
        egress.primary_v4,
        egress.primary_v6,
    )
}

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
    let from_zone = ingress_zone_override
        .map(|zone| zone.to_string())
        .or_else(|| forwarding.ifindex_to_zone.get(&ingress_ifindex).cloned())
        .unwrap_or_default();
    let to_zone = forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.zone.clone())
        .unwrap_or_default();
    (from_zone, to_zone)
}

pub(super) fn allow_unsolicited_dns_reply(
    forwarding: &ForwardingState,
    flow: &SessionFlow,
) -> bool {
    forwarding.allow_dns_reply
        && flow.forward_key.protocol == PROTO_UDP
        && flow.forward_key.src_port == 53
}

pub(super) fn owner_rg_for_flow(forwarding: &ForwardingState, egress_ifindex: i32) -> i32 {
    forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.redundancy_group.max(0))
        .unwrap_or_default()
}

pub(super) fn owner_rg_for_resolution(
    forwarding: &ForwardingState,
    resolution: ForwardingResolution,
) -> i32 {
    if resolution.tunnel_endpoint_id != 0 {
        return forwarding
            .tunnel_endpoints
            .get(&resolution.tunnel_endpoint_id)
            .map(|endpoint| endpoint.redundancy_group.max(0))
            .unwrap_or_default();
    }
    owner_rg_for_flow(forwarding, resolution.egress_ifindex)
}

pub(super) fn ingress_is_fabric(forwarding: &ForwardingState, ingress_ifindex: i32) -> bool {
    forwarding.fabrics.iter().any(|fabric| {
        fabric.parent_ifindex == ingress_ifindex || fabric.overlay_ifindex == ingress_ifindex
    })
}

pub(super) fn resolve_fabric_links_from_snapshots(
    snapshots: &[crate::FabricSnapshot],
    egress: &FastMap<i32, EgressInterface>,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
) -> Vec<FabricLink> {
    let mut out = Vec::with_capacity(snapshots.len());
    for fabric in snapshots {
        if fabric.parent_ifindex <= 0 {
            continue;
        }
        let Ok(peer_addr) = fabric.peer_address.parse::<IpAddr>() else {
            continue;
        };
        let local_mac = parse_mac(&fabric.local_mac)
            .or_else(|| egress.get(&fabric.parent_ifindex).map(|e| e.src_mac));
        let Some(local_mac) = local_mac else { continue };
        let peer_mac = parse_mac(&fabric.peer_mac).or_else(|| {
            dynamic_neighbors.lock().ok().and_then(|n| {
                n.get(&(fabric.overlay_ifindex, peer_addr))
                    .or_else(|| n.get(&(fabric.parent_ifindex, peer_addr)))
                    .map(|e| e.mac)
            })
        });
        let Some(peer_mac) = peer_mac else { continue };
        out.push(FabricLink {
            parent_ifindex: fabric.parent_ifindex,
            overlay_ifindex: fabric.overlay_ifindex,
            peer_addr,
            peer_mac,
            local_mac,
        });
    }
    out
}

pub(super) fn resolve_fabric_redirect(
    forwarding: &ForwardingState,
) -> Option<ForwardingResolution> {
    resolve_fabric_redirect_from_list(&forwarding.fabrics)
}

pub(super) fn resolve_fabric_redirect_from_shared(
    forwarding: &ForwardingState,
    shared_fabrics: &ArcSwap<Vec<FabricLink>>,
) -> Option<ForwardingResolution> {
    // Try static forwarding state first, then shared (dynamically updated) fabrics.
    resolve_fabric_redirect_from_list(&forwarding.fabrics)
        .or_else(|| resolve_fabric_redirect_from_list(&shared_fabrics.load()))
}

pub(super) fn resolve_fabric_redirect_from_list(
    fabrics: &[FabricLink],
) -> Option<ForwardingResolution> {
    let fabric = fabrics
        .iter()
        .find(|fabric| fabric.parent_ifindex > 0)
        .copied()?;
    Some(ForwardingResolution {
        disposition: ForwardingDisposition::FabricRedirect,
        local_ifindex: 0,
        egress_ifindex: fabric.parent_ifindex,
        tx_ifindex: fabric.parent_ifindex,
        tunnel_endpoint_id: 0,
        next_hop: Some(fabric.peer_addr),
        neighbor_mac: Some(fabric.peer_mac),
        src_mac: Some(fabric.local_mac),
        tx_vlan_id: 0,
    })
}

pub(super) fn resolve_zone_encoded_fabric_redirect(
    forwarding: &ForwardingState,
    ingress_zone: &str,
) -> Option<ForwardingResolution> {
    let mut resolution = resolve_fabric_redirect(forwarding)?;
    let zone_id = forwarding.zone_name_to_id.get(ingress_zone).copied()?;
    if zone_id == 0 || zone_id > u8::MAX as u16 {
        return None;
    }
    resolution.src_mac = Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, zone_id as u8]);
    Some(resolution)
}

pub(super) fn redirect_via_fabric_if_needed(
    forwarding: &ForwardingState,
    resolution: ForwardingResolution,
    ingress_ifindex: i32,
) -> ForwardingResolution {
    if resolution.disposition != ForwardingDisposition::HAInactive {
        return resolution;
    }
    if ingress_is_fabric(forwarding, ingress_ifindex) {
        return resolution;
    }
    resolve_fabric_redirect(forwarding).unwrap_or(resolution)
}

pub(super) fn prefer_local_forward_candidate_for_fabric_ingress(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    now_secs: u64,
    fabric_ingress: bool,
    target_ip: IpAddr,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    if !fabric_ingress || matches!(resolution.disposition, ForwardingDisposition::LocalDelivery) {
        return resolution;
    }

    let current_owner_rg = owner_rg_for_resolution(forwarding, resolution);
    let current_egress_is_fabric =
        resolution.egress_ifindex > 0 && ingress_is_fabric(forwarding, resolution.egress_ifindex);
    if !current_egress_is_fabric
        && current_owner_rg > 0
        && resolution.disposition != ForwardingDisposition::FabricRedirect
    {
        return resolution;
    }

    let local_resolution = enforce_ha_resolution_snapshot(
        forwarding,
        ha_state,
        now_secs,
        lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, target_ip),
    );
    let local_owner_rg = owner_rg_for_resolution(forwarding, local_resolution);
    let local_egress_is_fabric = local_resolution.egress_ifindex > 0
        && ingress_is_fabric(forwarding, local_resolution.egress_ifindex);
    if matches!(
        local_resolution.disposition,
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
    ) && local_owner_rg > 0
        && !local_egress_is_fabric
    {
        return local_resolution;
    }

    resolution
}

pub(super) fn cluster_peer_return_fast_path(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<&str>,
    resolution_target: IpAddr,
) -> Option<(SessionDecision, SessionMetadata)> {
    if !ingress_is_fabric(forwarding, meta.ingress_ifindex as i32) {
        return None;
    }
    let ingress_zone = ingress_zone_override?;
    if is_icmp_echo_request(packet_frame, meta) {
        return None;
    }
    if meta.protocol == PROTO_TCP
        && (meta.tcp_flags & TCP_FLAG_SYN) != 0
        && (meta.tcp_flags & 0x10) == 0
    {
        return None;
    }

    let fabric_return_resolution =
        lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, resolution_target);
    if fabric_return_resolution.disposition != ForwardingDisposition::ForwardCandidate {
        return None;
    }
    let egress_zone = forwarding
        .ifindex_to_zone
        .get(&fabric_return_resolution.egress_ifindex)?
        .clone();
    let metadata = SessionMetadata {
        ingress_zone: Arc::<str>::from(ingress_zone),
        egress_zone: Arc::<str>::from(egress_zone),
        owner_rg_id: owner_rg_for_resolution(forwarding, fabric_return_resolution),
        fabric_ingress: true,
        is_reverse: true,
        synced: false,
        nat64_reverse: None,
    };
    Some((
        SessionDecision {
            resolution: fabric_return_resolution,
            nat: NatDecision::default(),
        },
        metadata,
    ))
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
    forwarding.egress.iter().find_map(|(ifindex, iface)| {
        if iface.bind_ifindex == ingress_ifindex && iface.vlan_id == ingress_vlan_id {
            Some(*ifindex)
        } else {
            None
        }
    })
}

pub(super) fn enforce_ha_resolution(
    forwarding: &ForwardingState,
    ha_state: &Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    enforce_ha_resolution_at(
        forwarding,
        ha_state,
        monotonic_nanos() / 1_000_000_000,
        resolution,
    )
}

pub(super) fn enforce_ha_resolution_at(
    forwarding: &ForwardingState,
    ha_state: &Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    now_secs: u64,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    let state = ha_state.load();
    enforce_ha_resolution_snapshot(forwarding, state.as_ref(), now_secs, resolution)
}

pub(super) fn enforce_ha_resolution_snapshot(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    if !matches!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
    ) {
        return resolution;
    }
    let owner_rg_id = owner_rg_for_resolution(forwarding, resolution);
    if owner_rg_id <= 0 {
        return resolution;
    }
    let Some(group) = ha_state.get(&owner_rg_id) else {
        return ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            ..resolution
        };
    };
    if !group.active || group.demoting {
        return ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            ..resolution
        };
    }
    if group.watchdog_timestamp == 0
        || now_secs < group.watchdog_timestamp
        || now_secs.saturating_sub(group.watchdog_timestamp) > HA_WATCHDOG_STALE_AFTER_SECS
    {
        return ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            ..resolution
        };
    }
    resolution
}

pub(super) fn cached_flow_decision_valid(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: ForwardingResolution,
) -> bool {
    enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, resolution) == resolution
}

pub(super) fn demoted_owner_rgs(
    previous: &BTreeMap<i32, HAGroupRuntime>,
    current: &BTreeMap<i32, HAGroupRuntime>,
) -> Vec<i32> {
    previous
        .iter()
        .filter_map(|(rg_id, old)| {
            let became_inactive = match current.get(rg_id) {
                Some(new) => old.active && !new.active,
                None => old.active,
            };
            became_inactive.then_some(*rg_id)
        })
        .collect()
}

pub(super) fn activated_owner_rgs(
    previous: &BTreeMap<i32, HAGroupRuntime>,
    current: &BTreeMap<i32, HAGroupRuntime>,
) -> Vec<i32> {
    current
        .iter()
        .filter_map(|(rg_id, new)| {
            let became_active = match previous.get(rg_id) {
                Some(old) => !old.active && new.active,
                None => new.active,
            };
            became_active.then_some(*rg_id)
        })
        .collect()
}

/// Return the effective TCP MSS clamp value for the current config.
/// Returns 0 if MSS clamping is disabled.
#[allow(dead_code)]
pub(super) fn effective_tcp_mss(forwarding: &ForwardingState) -> u16 {
    if forwarding.tcp_mss_all_tcp > 0 {
        return forwarding.tcp_mss_all_tcp;
    }
    // IPsec VPN and GRE MSS values are returned when configured;
    // the caller is responsible for checking the tunnel context.
    if forwarding.tcp_mss_ipsec_vpn > 0 {
        return forwarding.tcp_mss_ipsec_vpn;
    }
    0
}

pub(super) fn native_gre_inner_mtu(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
) -> usize {
    if decision.resolution.tunnel_endpoint_id == 0 {
        return 0;
    }
    let Some(endpoint) = forwarding
        .tunnel_endpoints
        .get(&decision.resolution.tunnel_endpoint_id)
        .cloned()
    else {
        return 0;
    };
    let transport_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        decision.resolution.tx_ifindex,
        decision.resolution.tx_vlan_id,
    )
    .unwrap_or(decision.resolution.tx_ifindex);
    let transport_mtu = forwarding
        .egress
        .get(&transport_ifindex)
        .or_else(|| forwarding.egress.get(&decision.resolution.egress_ifindex))
        .or_else(|| forwarding.egress.get(&endpoint.logical_ifindex))
        .map(|egress| egress.mtu)
        .unwrap_or_default();
    if transport_mtu == 0 {
        return 0;
    }
    let outer_ip_header_len = match endpoint.outer_family {
        libc::AF_INET => 20usize,
        libc::AF_INET6 => 40usize,
        _ => return 0,
    };
    let gre_header_len = 4usize + if endpoint.key != 0 { 4 } else { 0 };
    transport_mtu
        .checked_sub(outer_ip_header_len + gre_header_len)
        .unwrap_or_default()
}

pub(super) fn native_gre_tcp_mss(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
    addr_family: u8,
) -> u16 {
    if decision.resolution.tunnel_endpoint_id == 0 {
        return 0;
    }
    if forwarding.tcp_mss_gre_out > 0 {
        return forwarding.tcp_mss_gre_out;
    }
    let mtu = native_gre_inner_mtu(forwarding, decision);
    if mtu == 0 {
        return 0;
    }
    let ip_header_len = match addr_family as i32 {
        libc::AF_INET => 20usize,
        libc::AF_INET6 => 40usize,
        _ => return 0,
    };
    let Some(max_mss) = mtu.checked_sub(ip_header_len + 20) else {
        return 0;
    };
    u16::try_from(max_mss).unwrap_or_default()
}

/// Clamp TCP MSS option in-place in an L3 packet (starting at IP header).
/// `max_mss` is the maximum allowed MSS value.
/// Returns true if the MSS was clamped.
#[allow(dead_code)]
pub(super) fn clamp_tcp_mss(packet: &mut [u8], max_mss: u16) -> bool {
    if max_mss == 0 {
        return false;
    }
    // Determine L3 header length and protocol.
    if packet.is_empty() {
        return false;
    }
    let version = packet[0] >> 4;
    let (l4_offset, protocol) = match version {
        4 => {
            if packet.len() < 20 {
                return false;
            }
            let ihl = (packet[0] & 0x0F) as usize * 4;
            (ihl, packet[9])
        }
        6 => {
            if packet.len() < 40 {
                return false;
            }
            (40, packet[6])
        }
        _ => return false,
    };
    if protocol != PROTO_TCP {
        return false;
    }
    let tcp = match packet.get_mut(l4_offset..) {
        Some(s) if s.len() >= 20 => s,
        _ => return false,
    };
    let flags = tcp[13];
    // Only clamp on SYN or SYN+ACK
    if (flags & 0x02) == 0 {
        return false;
    }
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return false;
    }
    // Walk TCP options looking for MSS (kind=2, len=4)
    let mut pos = 20;
    while pos + 4 <= data_offset {
        let kind = tcp[pos];
        if kind == 0 {
            break; // end of options
        }
        if kind == 1 {
            pos += 1; // NOP
            continue;
        }
        let opt_len = tcp[pos + 1] as usize;
        if opt_len < 2 || pos + opt_len > data_offset {
            break;
        }
        if kind == 2 && opt_len == 4 {
            let current_mss = u16::from_be_bytes([tcp[pos + 2], tcp[pos + 3]]);
            if current_mss > max_mss {
                // Clamp MSS and adjust TCP checksum
                let old_bytes = [tcp[pos + 2], tcp[pos + 3]];
                tcp[pos + 2..pos + 4].copy_from_slice(&max_mss.to_be_bytes());
                // Incremental checksum update
                let old_val = u16::from_be_bytes(old_bytes) as u32;
                let new_val = max_mss as u32;
                let old_csum = u16::from_be_bytes([tcp[16], tcp[17]]) as u32;
                let mut sum = (!old_csum & 0xFFFF) + old_val + (!new_val & 0xFFFF);
                sum = (sum & 0xFFFF) + (sum >> 16);
                sum = (sum & 0xFFFF) + (sum >> 16);
                tcp[16..18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
                return true;
            }
            return false;
        }
        pos += opt_len;
    }
    false
}

/// Clamp TCP MSS in a full Ethernet frame starting at `l3_offset`.
#[allow(dead_code)]
pub(super) fn clamp_tcp_mss_frame(frame: &mut [u8], l3_offset: usize, max_mss: u16) -> bool {
    if max_mss == 0 || l3_offset >= frame.len() {
        return false;
    }
    clamp_tcp_mss(&mut frame[l3_offset..], max_mss)
}

#[allow(dead_code)]
const ICMP_TE_MAX_PER_SEC: u32 = 100;

/// Rate limiter for ICMP Time Exceeded messages.
#[allow(dead_code)]
struct IcmpTeRateLimiter {
    max_per_sec: u32,
    count: u32,
    window_start_ns: u64,
}

#[allow(dead_code)]
impl IcmpTeRateLimiter {
    fn new(max_per_sec: u32) -> Self {
        Self {
            max_per_sec,
            count: 0,
            window_start_ns: 0,
        }
    }

    fn allow(&mut self, now_ns: u64) -> bool {
        let window = now_ns / 1_000_000_000;
        let prev_window = self.window_start_ns / 1_000_000_000;
        if window != prev_window {
            self.count = 0;
            self.window_start_ns = now_ns;
        }
        if self.count >= self.max_per_sec {
            return false;
        }
        self.count += 1;
        true
    }
}

/// Returns true if the packet is IPsec traffic (ESP protocol 50 or IKE UDP
/// ports 500/4500) that should be passed to the kernel for XFRM processing.
#[inline]
pub(super) fn is_ipsec_traffic(protocol: u8, dst_port: u16) -> bool {
    protocol == PROTO_ESP || (protocol == PROTO_UDP && (dst_port == 500 || dst_port == 4500))
}

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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    dst: IpAddr,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst, None)
}

pub(super) fn lookup_forwarding_resolution_in_table_with_dynamic(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    dst: IpAddr,
    table: Option<&str>,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst, table)
}

pub(super) fn lookup_forwarding_resolution_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    dst: IpAddr,
    table: Option<&str>,
) -> ForwardingResolution {
    match dst {
        IpAddr::V4(ip) => {
            if state.local_v4.contains(&ip) {
                let local_ifindex = state
                    .connected_v4
                    .iter()
                    .find(|entry| entry.prefix.addr() == ip)
                    .map(|entry| entry.ifindex)
                    .unwrap_or(0);
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
            let table = table
                .map(|table| canonical_route_table(table, false))
                .unwrap_or_else(|| DEFAULT_V4_TABLE.to_string());
            lookup_forwarding_resolution_v4(state, dynamic_neighbors, ip, &table, 0, true)
        }
        IpAddr::V6(ip) => {
            if state.local_v6.contains(&ip) {
                let local_ifindex = state
                    .connected_v6
                    .iter()
                    .find(|entry| entry.prefix.addr() == ip)
                    .map(|entry| entry.ifindex)
                    .unwrap_or(0);
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
            let table = table
                .map(|table| canonical_route_table(table, true))
                .unwrap_or_else(|| DEFAULT_V6_TABLE.to_string());
            lookup_forwarding_resolution_v6(state, dynamic_neighbors, ip, &table, 0, true)
        }
    }
}

pub(super) fn ingress_route_table_override(
    forwarding: &ForwardingState,
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
) -> Option<String> {
    let ingress_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    let result = crate::filter::evaluate_interface_filter(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
        flow.src_ip,
        flow.dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        meta.dscp,
    );
    if result.routing_instance.is_empty() {
        return None;
    }
    Some(if is_v6 {
        format!("{}.inet6.0", result.routing_instance)
    } else {
        format!("{}.inet.0", result.routing_instance)
    })
}

pub(super) fn interface_nat_local_resolution(
    state: &ForwardingState,
    dst: IpAddr,
) -> Option<ForwardingResolution> {
    match dst {
        IpAddr::V4(ip) => state
            .interface_nat_v4
            .get(&ip)
            .copied()
            .map(|local_ifindex| ForwardingResolution {
                disposition: ForwardingDisposition::LocalDelivery,
                local_ifindex,
                egress_ifindex: local_ifindex,
                tx_ifindex: local_ifindex,
                tunnel_endpoint_id: state
                    .tunnel_endpoint_by_ifindex
                    .get(&local_ifindex)
                    .copied()
                    .unwrap_or_default(),
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            }),
        IpAddr::V6(ip) => state
            .interface_nat_v6
            .get(&ip)
            .copied()
            .map(|local_ifindex| ForwardingResolution {
                disposition: ForwardingDisposition::LocalDelivery,
                local_ifindex,
                egress_ifindex: local_ifindex,
                tx_ifindex: local_ifindex,
                tunnel_endpoint_id: state
                    .tunnel_endpoint_by_ifindex
                    .get(&local_ifindex)
                    .copied()
                    .unwrap_or_default(),
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            }),
    }
}

pub(super) fn interface_nat_local_resolution_on_session_miss(
    state: &ForwardingState,
    dst: IpAddr,
    _protocol: u8,
) -> Option<ForwardingResolution> {
    interface_nat_local_resolution(state, dst)
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
    if !matches!(protocol, PROTO_TCP) {
        return true;
    }
    const TCP_SYN_FLAG: u8 = 0x02;
    const TCP_ACK_FLAG: u8 = 0x10;
    if (tcp_flags & TCP_ACK_FLAG) != 0 && (tcp_flags & TCP_SYN_FLAG) == 0 {
        return false;
    }
    let _ = state;
    let _ = resolution_target;
    true
}

pub(super) fn install_helper_local_session_on_miss(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
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
    };
    let _ =
        publish_session_map_entry_for_session(session_map_fd, key, decision, &local_entry.metadata);
    true
}

pub(super) fn should_block_tunnel_interface_nat_session_miss(
    state: &ForwardingState,
    dst: IpAddr,
    protocol: u8,
) -> bool {
    matches!(protocol, PROTO_TCP | PROTO_UDP | PROTO_ICMP | PROTO_ICMPV6)
        && matches!(
            interface_nat_local_resolution(state, dst),
            Some(local) if local.tunnel_endpoint_id != 0
        )
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
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    ip: Ipv4Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
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
    let connected_match = state
        .connected_v4
        .iter()
        .find(|entry| entry.prefix.contains(ip));
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
        Some(ResolvedRouteV4::Static {
            ifindex,
            tunnel_endpoint_id,
            next_hop,
            discard,
            next_table,
        }) => {
            if discard {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::DiscardRoute,
                    local_ifindex: 0,
                    egress_ifindex: ifindex,
                    tx_ifindex: ifindex,
                    tunnel_endpoint_id,
                    next_hop: next_hop.map(IpAddr::V4),
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            if let Some(next_table_name) = next_table {
                if next_table_name == table {
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
                return lookup_forwarding_resolution_v4(
                    state,
                    dynamic_neighbors,
                    ip,
                    &next_table_name,
                    depth + 1,
                    allow_tunnels,
                );
            }
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
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
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
    let connected_match = state
        .connected_v6
        .iter()
        .find(|entry| entry.prefix.contains(ip));
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
        Some(ResolvedRouteV6::Static {
            ifindex,
            tunnel_endpoint_id,
            next_hop,
            discard,
            next_table,
        }) => {
            if discard {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::DiscardRoute,
                    local_ifindex: 0,
                    egress_ifindex: ifindex,
                    tx_ifindex: ifindex,
                    tunnel_endpoint_id,
                    next_hop: next_hop.map(IpAddr::V6),
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            if let Some(next_table_name) = next_table {
                if next_table_name == table {
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
                return lookup_forwarding_resolution_v6(
                    state,
                    dynamic_neighbors,
                    ip,
                    &next_table_name,
                    depth + 1,
                    allow_tunnels,
                );
            }
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

pub(super) fn resolve_tunnel_forwarding_resolution(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    tunnel_endpoint_id: u16,
    depth: usize,
) -> ForwardingResolution {
    let Some(endpoint) = state.tunnel_endpoints.get(&tunnel_endpoint_id) else {
        return no_route_resolution(None);
    };
    let outer = match endpoint.destination {
        IpAddr::V4(ip) => lookup_forwarding_resolution_v4(
            state,
            dynamic_neighbors,
            ip,
            &endpoint.transport_table,
            depth + 1,
            false,
        ),
        IpAddr::V6(ip) => lookup_forwarding_resolution_v6(
            state,
            dynamic_neighbors,
            ip,
            &endpoint.transport_table,
            depth + 1,
            false,
        ),
    };
    if outer.disposition == ForwardingDisposition::LocalDelivery
        || state.tunnel_interfaces.contains(&outer.egress_ifindex)
    {
        return no_route_resolution(Some(endpoint.destination));
    }
    ForwardingResolution {
        disposition: outer.disposition,
        local_ifindex: outer.local_ifindex,
        egress_ifindex: endpoint.logical_ifindex,
        tx_ifindex: outer.tx_ifindex,
        tunnel_endpoint_id,
        next_hop: outer.next_hop,
        neighbor_mac: outer.neighbor_mac,
        src_mac: outer.src_mac,
        tx_vlan_id: outer.tx_vlan_id,
    }
}

pub(super) fn lookup_neighbor_entry(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    ifindex: i32,
    target: IpAddr,
) -> Option<NeighborEntry> {
    if let Some(entry) = state.neighbors.get(&(ifindex, target)).copied() {
        return Some(entry);
    }
    let Some(dynamic_neighbors) = dynamic_neighbors else {
        return None;
    };
    if let Ok(cache) = dynamic_neighbors.lock() {
        if let Some(entry) = cache.get(&(ifindex, target)).copied() {
            return Some(entry);
        }
    }
    // The worker hot path must not block on shelling out to `ip neigh` or
    // active probes. Runtime neighbor discovery is maintained asynchronously
    // by the helper's own netlink dump+subscribe path.
    None
}

pub(super) fn parse_neighbor_entries(output: &str) -> Vec<(IpAddr, NeighborEntry)> {
    let mut out = Vec::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        if fields.iter().any(|field| !neighbor_state_usable(field)) {
            continue;
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

enum ResolvedRouteV4 {
    Connected {
        ifindex: i32,
        tunnel_endpoint_id: u16,
    },
    Static {
        ifindex: i32,
        tunnel_endpoint_id: u16,
        next_hop: Option<Ipv4Addr>,
        discard: bool,
        next_table: Option<String>,
    },
}

enum ResolvedRouteV6 {
    Connected {
        ifindex: i32,
        tunnel_endpoint_id: u16,
    },
    Static {
        ifindex: i32,
        tunnel_endpoint_id: u16,
        next_hop: Option<Ipv6Addr>,
        discard: bool,
        next_table: Option<String>,
    },
}

fn choose_v4_route(
    static_match: Option<&RouteEntryV4>,
    connected_match: Option<&ConnectedRouteV4>,
) -> Option<ResolvedRouteV4> {
    match (static_match, connected_match) {
        (Some(route), Some(conn)) if conn.prefix.prefix_len() >= route.prefix.prefix_len() => {
            Some(ResolvedRouteV4::Connected {
                ifindex: conn.ifindex,
                tunnel_endpoint_id: conn.tunnel_endpoint_id,
            })
        }
        (Some(route), _) => Some(ResolvedRouteV4::Static {
            ifindex: route.ifindex,
            tunnel_endpoint_id: route.tunnel_endpoint_id,
            next_hop: route.next_hop,
            discard: route.discard,
            next_table: if route.next_table.is_empty() {
                None
            } else {
                Some(route.next_table.clone())
            },
        }),
        (None, Some(conn)) => Some(ResolvedRouteV4::Connected {
            ifindex: conn.ifindex,
            tunnel_endpoint_id: conn.tunnel_endpoint_id,
        }),
        (None, None) => None,
    }
}

fn choose_v6_route(
    static_match: Option<&RouteEntryV6>,
    connected_match: Option<&ConnectedRouteV6>,
) -> Option<ResolvedRouteV6> {
    match (static_match, connected_match) {
        (Some(route), Some(conn)) if conn.prefix.prefix_len() >= route.prefix.prefix_len() => {
            Some(ResolvedRouteV6::Connected {
                ifindex: conn.ifindex,
                tunnel_endpoint_id: conn.tunnel_endpoint_id,
            })
        }
        (Some(route), _) => Some(ResolvedRouteV6::Static {
            ifindex: route.ifindex,
            tunnel_endpoint_id: route.tunnel_endpoint_id,
            next_hop: route.next_hop,
            discard: route.discard,
            next_table: if route.next_table.is_empty() {
                None
            } else {
                Some(route.next_table.clone())
            },
        }),
        (None, Some(conn)) => Some(ResolvedRouteV6::Connected {
            ifindex: conn.ifindex,
            tunnel_endpoint_id: conn.tunnel_endpoint_id,
        }),
        (None, None) => None,
    }
}
