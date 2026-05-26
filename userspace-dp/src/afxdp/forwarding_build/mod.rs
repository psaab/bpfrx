//! `ConfigSnapshot → ForwardingState` translation.
//!
//! Decomposed (#1342) from the original 1162-LOC
//! `forwarding_build.rs` into per-entity sibling files. This mod
//! file is the orchestrator — a linear, easy-to-audit sequence of
//! sub-builder calls — plus small helpers
//! ([`build_screen_profiles`], [`parse_syn_cookie_master_key`])
//! and the late-stage static-NAT / DNAT local-delivery passes that
//! MUST stay after every other writer of `state.local_v[46]`.
//!
//! Sibling modules:
//!
//! - [`zones`] — `populate_zones`
//! - [`tunnels`] — `populate_tunnel_endpoints`
//! - [`interfaces`] — `populate_interfaces` (returns `IfaceIndex`),
//!   `populate_egress`, `pick_interface_v[46]`
//! - [`fib`] — `sort_connected`, `populate_routes`, `sort_routes`,
//!   `populate_neighbors`, `populate_fabrics`,
//!   `resolve_route_target_v[46]`, `parse_route_next_hop[_v6]`,
//!   `resolve_ifindex`, `infer_connected_route_target_v[46]`
//! - [`cos`] — `build_cos_state` (split into
//!   `build_cos_classifier_tables` + `build_cos_iface_config` +
//!   orchestrator).

use super::*;

mod cos;
mod fib;
mod interfaces;
mod tunnels;
mod zones;

#[cfg(test)]
mod tests;

// Re-exports for cross-afxdp-sibling consumers reached via
// `use self::forwarding_build::*;` in `afxdp/mod.rs`.
pub(in crate::afxdp) use fib::{
    infer_connected_route_target_v4, infer_connected_route_target_v6, parse_route_next_hop,
    parse_route_next_hop_v6, resolve_ifindex, resolve_route_target_v4, resolve_route_target_v6,
};
pub(in crate::afxdp) use interfaces::{pick_interface_v4, pick_interface_v6};

// Plain (private) `use` for orchestrator-local symbols. NOT a
// `pub(super) use` of a `pub(super)` item — that triggers E0364
// (see `tx/mod.rs:38` for the documented precedent).
//
// `default_cos_burst_bytes` is brought in so that the test module
// (`forwarding_build/tests.rs`, loaded as a child via `mod tests;`)
// can resolve it via `super::*`.
use cos::{build_cos_classifier_tables, build_cos_iface_config, build_cos_state, default_cos_burst_bytes};
use interfaces::IfaceIndex;

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
                syn_frag: sp.syn_frag,
                source_route: sp.source_route,
                icmp_flood_threshold: sp.icmp_flood_threshold,
                udp_flood_threshold: sp.udp_flood_threshold,
                syn_flood_threshold: sp.syn_flood_threshold,
                syn_cookie: sp.syn_cookie,
                session_limit_src: sp.session_limit_src,
                session_limit_dst: sp.session_limit_dst,
                port_scan_threshold: sp.port_scan_threshold,
                ip_sweep_threshold: sp.ip_sweep_threshold,
            },
        );
    }
    profiles
}

fn parse_syn_cookie_master_key(key: &str) -> Option<[u8; 16]> {
    if key.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (idx, byte) in out.iter_mut().enumerate() {
        let start = idx * 2;
        let part = key.get(start..start + 2)?;
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    Some(out)
}

pub(super) fn build_forwarding_state(snapshot: &ConfigSnapshot) -> ForwardingState {
    build_forwarding_state_with_policy_counters(snapshot, &PolicyCounterStore::default())
}

pub(super) fn build_forwarding_state_with_policy_counters(
    snapshot: &ConfigSnapshot,
    policy_counters: &PolicyCounterStore,
) -> ForwardingState {
    build_forwarding_state_with_policy_counters_and_previous(snapshot, policy_counters, None)
}

pub(super) fn build_forwarding_state_with_policy_counters_and_previous(
    snapshot: &ConfigSnapshot,
    policy_counters: &PolicyCounterStore,
    previous: Option<&ForwardingState>,
) -> ForwardingState {
    let mut state = ForwardingState::default();
    let (excluded_local_v4, excluded_local_v6) = nat_translated_local_exclusions(snapshot);

    zones::populate_zones(snapshot, &mut state);
    tunnels::populate_tunnel_endpoints(snapshot, &mut state);

    let iface_ctx = interfaces::populate_interfaces(
        snapshot,
        &mut state,
        &excluded_local_v4,
        &excluded_local_v6,
    );
    interfaces::populate_egress(snapshot, &mut state, &iface_ctx);

    fib::sort_connected(&mut state);
    fib::populate_routes(snapshot, &mut state, &iface_ctx);
    fib::sort_routes(&mut state);
    fib::populate_neighbors(snapshot, &mut state);
    fib::populate_fabrics(snapshot, &mut state, &iface_ctx);

    state.policy = parse_policy_state_with_counters(
        &snapshot.default_policy,
        &snapshot.policies,
        &state.zone_name_to_id,
        policy_counters,
    );
    state.allow_dns_reply = snapshot.flow.allow_dns_reply;
    state.allow_embedded_icmp = snapshot.flow.allow_embedded_icmp;
    state.session_timeouts = crate::session::SessionTimeouts::from_seconds(
        snapshot.flow.tcp_session_timeout,
        snapshot.flow.udp_session_timeout,
        snapshot.flow.icmp_session_timeout,
    );
    state.source_nat_rules = parse_source_nat_rules_with_previous(
        &snapshot.source_nat_rules,
        previous.map(|state| state.source_nat_rules.as_slice()),
    );
    state.static_nat = StaticNatTable::from_snapshots(&snapshot.static_nat_rules);
    state.dnat_table = DnatTable::from_snapshots(&snapshot.destination_nat_rules);
    state.nat64 = Nat64State::from_snapshots(&snapshot.nat64_rules);
    state.nptv6 = Nptv6State::from_snapshots(&snapshot.nptv6_rules);
    state.screen_profiles = build_screen_profiles(snapshot);
    state.syn_cookie_master_key = parse_syn_cookie_master_key(&snapshot.syn_cookie_master_key);
    state.tcp_mss_all_tcp = snapshot.flow.tcp_mss_all_tcp;
    state.tcp_mss_ipsec_vpn = snapshot.flow.tcp_mss_ipsec_vpn;
    state.tcp_mss_gre_in = snapshot.flow.tcp_mss_gre_in;
    state.tcp_mss_gre_out = snapshot.flow.tcp_mss_gre_out;
    // Build filter state from snapshot
    state.filter_state = crate::filter::parse_filter_state_with_three_color_preserving(
        &snapshot.filters,
        &snapshot.policers,
        &snapshot.three_color_policers,
        &snapshot.interfaces,
        &snapshot.flow.lo0_filter_input_v4,
        &snapshot.flow.lo0_filter_input_v6,
        previous.map(|state| &state.filter_state),
    );
    state.cos = build_cos_state(snapshot);
    let has_cos_interfaces = !state.cos.interfaces.is_empty();
    state.tx_selection_enabled_v4 = has_cos_interfaces
        || state.filter_state.has_input_tx_selection_v4
        || state.filter_state.has_output_tx_selection_v4
        || state.filter_state.has_input_three_color_policer_v4
        || !state
            .filter_state
            .iface_filter_out_v4_needs_tx_eval
            .is_empty();
    state.tx_selection_enabled_v6 = has_cos_interfaces
        || state.filter_state.has_input_tx_selection_v6
        || state.filter_state.has_output_tx_selection_v6
        || state.filter_state.has_input_three_color_policer_v6
        || !state
            .filter_state
            .iface_filter_out_v6_needs_tx_eval
            .is_empty();
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
    for mirror in &snapshot.mirror_configs {
        if mirror.ingress_ifindex <= 0 || mirror.output_ifindex <= 0 {
            continue;
        }
        state.mirror_configs.insert(
            mirror.ingress_ifindex,
            MirrorRuntimeConfig {
                output_ifindex: mirror.output_ifindex,
                rate: mirror.rate,
            },
        );
    }

    // === Late-stage local-delivery additions ===========================
    // These two loops APPEND to `state.local_v[46]` AFTER every other
    // writer. They MUST stay here in `forwarding_build/mod.rs` and MUST
    // NOT be moved into `interfaces.rs` — moving them earlier would
    // execute before `state.static_nat` and `state.dnat_table` are
    // populated, silently emptying the NAT local-delivery set and
    // breaking inbound firewall delivery for all NAT traffic. (#1342
    // AGY r1 finding #2.)

    // Add static NAT external IPs as local delivery targets so inbound
    // traffic destined to external IPs is recognized by the firewall.
    for ext_ip in state.static_nat.external_ips() {
        match ext_ip {
            std::net::IpAddr::V4(v4) => {
                state.local_v4.insert(*v4);
            }
            std::net::IpAddr::V6(v6) => {
                state.local_v6.insert(*v6);
            }
        }
    }

    // Add DNAT destination IPs as local delivery targets so traffic
    // to those IPs is recognized as locally-destined and processed.
    for dst_ip in state.dnat_table.destination_ips() {
        match dst_ip {
            std::net::IpAddr::V4(v4) => {
                state.local_v4.insert(v4);
            }
            std::net::IpAddr::V6(v6) => {
                state.local_v6.insert(v6);
            }
        }
    }

    // Debug: dump zone mappings and policy rules
    #[cfg(feature = "debug-log")]
    {
        // #921: ifindex_to_zone_id is u16 — render with names via
        // zone_id_to_name for log readability.
        let ifindex_to_zone_named: Vec<(i32, &str)> = state
            .ifindex_to_zone_id
            .iter()
            .map(|(&ifidx, id)| {
                let name = state
                    .zone_id_to_name
                    .get(id)
                    .map(|s| s.as_str())
                    .unwrap_or("");
                (ifidx, name)
            })
            .collect();
        debug_log!("FWD_STATE: ifindex_to_zone={:?}", ifindex_to_zone_named);
        debug_log!(
            "FWD_STATE: egress keys={:?}",
            state.egress.keys().collect::<Vec<_>>()
        );
        for (ifidx, eg) in &state.egress {
            // #921: render eg.zone_id back to name for debug.
            let zone_name = state
                .zone_id_to_name
                .get(&eg.zone_id)
                .map(|s| s.as_str())
                .unwrap_or("");
            debug_log!(
                "FWD_STATE: egress[{}] bind={} zone={} vlan={} mtu={}",
                ifidx,
                eg.bind_ifindex,
                zone_name,
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
                rule.source_v4.prefix_count(),
                rule.destination_v4.prefix_count(),
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
