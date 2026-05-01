// Snapshot/AST → typed Filter compiler extracted from filter.rs (#1049 P2 structural split).
// Pure relocation — bodies are byte-for-byte identical; only the
// enclosing module and visibility paths change.

use super::*;


/// Build the complete FilterState from snapshot data.
pub(crate) fn parse_filter_state(
    filters: &[FirewallFilterSnapshot],
    policers: &[PolicerSnapshot],
    interfaces: &[crate::InterfaceSnapshot],
    lo0_filter_v4: &str,
    lo0_filter_v6: &str,
) -> FilterState {
    let mut state = FilterState::default();

    // Parse filters
    for snap in filters {
        let key = qualify_filter_key(&snap.family, &snap.name);
        let filter = Filter {
            name: snap.name.clone(),
            family: snap.family.clone(),
            terms: snap.terms.iter().map(|t| parse_term(t)).collect(),
            affects_tx_selection: snap
                .terms
                .iter()
                .any(|term| !term.forwarding_class.is_empty() || term.dscp_rewrite.is_some()),
            affects_route_lookup: snap
                .terms
                .iter()
                .any(|term| !term.routing_instance.is_empty()),
            has_counter_terms: snap.terms.iter().any(|term| !term.count.is_empty()),
        };
        state.filters.insert(key, Arc::new(filter));
    }

    // Parse policers
    for snap in policers {
        state.policers.insert(
            snap.name.clone(),
            PolicerState::new(
                snap.name.clone(),
                snap.bandwidth_bps,
                snap.burst_bytes,
                snap.discard_excess,
            ),
        );
    }

    // Build per-interface filter assignments
    for iface in interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        if !iface.filter_input_v4.is_empty() {
            let key = qualify_filter_key("inet", &iface.filter_input_v4);
            if let Some(filter) = state.filters.get(&key) {
                if filter.affects_tx_selection {
                    state
                        .iface_filter_v4_affects_tx_selection
                        .insert(iface.ifindex);
                    state.has_input_tx_selection_v4 = true;
                }
                if filter.affects_route_lookup {
                    state
                        .iface_filter_v4_affects_route_lookup
                        .insert(iface.ifindex);
                }
                state
                    .iface_filter_v4_fast
                    .insert(iface.ifindex, filter.clone());
            }
            state.iface_filter_v4.insert(iface.ifindex, key);
        }
        if !iface.filter_output_v4.is_empty() {
            let key = qualify_filter_key("inet", &iface.filter_output_v4);
            if let Some(filter) = state.filters.get(&key) {
                if filter.affects_tx_selection || filter.has_counter_terms {
                    state
                        .iface_filter_out_v4_needs_tx_eval
                        .insert(iface.ifindex);
                }
                if filter.affects_tx_selection {
                    state.has_output_tx_selection_v4 = true;
                }
                state
                    .iface_filter_out_v4_fast
                    .insert(iface.ifindex, filter.clone());
            }
            state.iface_filter_out_v4.insert(iface.ifindex, key);
        }
        if !iface.filter_input_v6.is_empty() {
            let key = qualify_filter_key("inet6", &iface.filter_input_v6);
            if let Some(filter) = state.filters.get(&key) {
                if filter.affects_tx_selection {
                    state
                        .iface_filter_v6_affects_tx_selection
                        .insert(iface.ifindex);
                    state.has_input_tx_selection_v6 = true;
                }
                if filter.affects_route_lookup {
                    state
                        .iface_filter_v6_affects_route_lookup
                        .insert(iface.ifindex);
                }
                state
                    .iface_filter_v6_fast
                    .insert(iface.ifindex, filter.clone());
            }
            state.iface_filter_v6.insert(iface.ifindex, key);
        }
        if !iface.filter_output_v6.is_empty() {
            let key = qualify_filter_key("inet6", &iface.filter_output_v6);
            if let Some(filter) = state.filters.get(&key) {
                if filter.affects_tx_selection || filter.has_counter_terms {
                    state
                        .iface_filter_out_v6_needs_tx_eval
                        .insert(iface.ifindex);
                }
                if filter.affects_tx_selection {
                    state.has_output_tx_selection_v6 = true;
                }
                state
                    .iface_filter_out_v6_fast
                    .insert(iface.ifindex, filter.clone());
            }
            state.iface_filter_out_v6.insert(iface.ifindex, key);
        }
    }

    state.lo0_filter_v4 = if lo0_filter_v4.is_empty() {
        String::new()
    } else {
        qualify_filter_key("inet", lo0_filter_v4)
    };
    state.lo0_filter_v4_fast = state.filters.get(&state.lo0_filter_v4).cloned();
    state.lo0_filter_v6 = if lo0_filter_v6.is_empty() {
        String::new()
    } else {
        qualify_filter_key("inet6", lo0_filter_v6)
    };
    state.lo0_filter_v6_fast = state.filters.get(&state.lo0_filter_v6).cloned();

    state
}

fn qualify_filter_key(family: &str, filter_name: &str) -> String {
    format!("{family}:{filter_name}")
}

fn parse_term(snap: &FirewallTermSnapshot) -> FilterTerm {
    let mut source_v4 = Vec::new();
    let mut source_v6 = Vec::new();
    for addr in &snap.source_addresses {
        parse_address(addr, &mut source_v4, &mut source_v6);
    }
    let mut dest_v4 = Vec::new();
    let mut dest_v6 = Vec::new();
    for addr in &snap.destination_addresses {
        parse_address(addr, &mut dest_v4, &mut dest_v6);
    }
    let protocols: Vec<u8> = snap
        .protocols
        .iter()
        .filter_map(|p| parse_protocol(p))
        .collect();
    let source_ports: Vec<PortRange> = snap
        .source_ports
        .iter()
        .filter_map(|p| parse_port_spec(p))
        .flatten()
        .collect();
    let dest_ports: Vec<PortRange> = snap
        .destination_ports
        .iter()
        .filter_map(|p| parse_port_spec(p))
        .flatten()
        .collect();
    let action = match snap.action.as_str() {
        "accept" => FilterAction::Accept,
        "reject" => FilterAction::Reject,
        "discard" => FilterAction::Discard,
        _ => FilterAction::Accept,
    };
    let dscp_rewrite = snap.dscp_rewrite.map(|value| value & 0x3f);

    FilterTerm {
        name: snap.name.clone(),
        source_v4,
        source_v6,
        dest_v4,
        dest_v6,
        protocol_bitmap: build_u8_match_bitmap(&protocols),
        protocol_match_enabled: !protocols.is_empty(),
        source_ports: build_port_matcher(source_ports),
        dest_ports: build_port_matcher(dest_ports),
        dscp_bitmap: build_u6_match_bitmap(&snap.dscp_values),
        dscp_match_enabled: !snap.dscp_values.is_empty(),
        action,
        count: snap.count.clone(),
        has_count: !snap.count.is_empty(),
        log: snap.log,
        policer_name: snap.policer.clone(),
        routing_instance: snap.routing_instance.clone(),
        forwarding_class: Arc::<str>::from(snap.forwarding_class.as_str()),
        dscp_rewrite,
        counter: Arc::new(FilterTermCounter::default()),
    }
}

fn parse_address(prefix: &str, out_v4: &mut Vec<PrefixV4>, out_v6: &mut Vec<PrefixV6>) {
    if prefix.is_empty() || prefix == "any" {
        return;
    }
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => out_v4.push(PrefixV4::from_net(net)),
        Ok(IpNet::V6(net)) => out_v6.push(PrefixV6::from_net(net)),
        Err(_) => {
            if let Ok(ip) = prefix.parse::<Ipv4Addr>() {
                out_v4.push(PrefixV4::from_net(
                    ipnet::Ipv4Net::new(ip, 32).expect("v4 /32"),
                ));
            } else if let Ok(ip) = prefix.parse::<Ipv6Addr>() {
                out_v6.push(PrefixV6::from_net(
                    ipnet::Ipv6Net::new(ip, 128).expect("v6 /128"),
                ));
            }
        }
    }
}

fn parse_protocol(protocol: &str) -> Option<u8> {
    match protocol {
        "" => None,
        "tcp" => Some(PROTO_TCP),
        "udp" => Some(PROTO_UDP),
        "icmp" => Some(PROTO_ICMP),
        "icmpv6" => Some(PROTO_ICMPV6),
        "gre" => Some(PROTO_GRE),
        "89" | "ospf" => Some(PROTO_OSPF),
        "4" | "ipip" => Some(PROTO_IPIP),
        _ => protocol.parse::<u8>().ok(),
    }
}

fn parse_port_spec(spec: &str) -> Option<Vec<PortRange>> {
    if spec.is_empty() {
        return Some(Vec::new());
    }
    let normalized = match spec {
        "http" => "80",
        "https" => "443",
        "ssh" => "22",
        "telnet" => "23",
        "ftp" => "21",
        "ftp-data" => "20",
        "smtp" => "25",
        "dns" => "53",
        "pop3" => "110",
        "imap" => "143",
        "snmp" => "161",
        "ntp" => "123",
        "bgp" => "179",
        "ldap" => "389",
        "syslog" => "514",
        other => other,
    };
    if let Some((low, high)) = normalized.split_once('-') {
        let low = low.parse::<u16>().ok()?;
        let high = high.parse::<u16>().ok()?;
        if low == 0 || low > high {
            return None;
        }
        return Some(vec![PortRange { low, high }]);
    }
    let port = normalized.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    Some(vec![PortRange {
        low: port,
        high: port,
    }])
}

fn build_port_matcher(mut ranges: Vec<PortRange>) -> PortMatcher {
    match ranges.len() {
        0 => PortMatcher::Any,
        1 => {
            let range = ranges.pop().expect("single range");
            if range.low == range.high {
                PortMatcher::Single(range.low)
            } else {
                PortMatcher::Range(range)
            }
        }
        _ => PortMatcher::Set(ranges.into_boxed_slice()),
    }
}

fn build_u8_match_bitmap(values: &[u8]) -> [u64; 4] {
    let mut bitmap = [0u64; 4];
    for value in values {
        bitmap[(value / 64) as usize] |= 1u64 << (value % 64);
    }
    bitmap
}

fn build_u6_match_bitmap(values: &[u8]) -> u64 {
    let mut bitmap = 0u64;
    for value in values {
        if *value < 64 {
            bitmap |= 1u64 << value;
        }
    }
    bitmap
}

