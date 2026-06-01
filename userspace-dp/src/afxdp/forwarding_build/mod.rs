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
mod wg;
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
use cos::build_cos_state;

// Test-only imports. `default_cos_burst_bytes` is reached by
// `forwarding_build/tests.rs` (loaded as `mod tests;` below) via
// `use super::*;`. `build_cos_classifier_tables`,
// `build_cos_iface_config`, and `IfaceIndex` are not referenced
// outside their defining sub-modules in production but are
// surfaced for test assertions and future intra-module use.
#[cfg(test)]
#[allow(unused_imports)]
use cos::{build_cos_classifier_tables, build_cos_iface_config, default_cos_burst_bytes};
#[cfg(test)]
#[allow(unused_imports)]
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

/// Test/legacy entry point — infallible; panics on snapshot
/// integrity error (which test snapshots never hit). Production
/// code uses `try_build_forwarding_state_*` instead.
pub(super) fn build_forwarding_state(snapshot: &ConfigSnapshot) -> ForwardingState {
    try_build_forwarding_state_with_policy_counters(snapshot, &PolicyCounterStore::default())
        .expect("test snapshot must not produce policy integrity error")
}

pub(super) fn build_forwarding_state_with_policy_counters(
    snapshot: &ConfigSnapshot,
    policy_counters: &PolicyCounterStore,
) -> ForwardingState {
    try_build_forwarding_state_with_policy_counters(snapshot, policy_counters)
        .expect("test snapshot must not produce policy integrity error")
}

pub(super) fn try_build_forwarding_state_with_policy_counters(
    snapshot: &ConfigSnapshot,
    policy_counters: &PolicyCounterStore,
) -> Result<ForwardingState, crate::policy::SnapshotIntegrityError> {
    build_forwarding_state_with_policy_counters_and_previous(snapshot, policy_counters, None)
}

pub(super) fn build_forwarding_state_with_policy_counters_and_previous(
    snapshot: &ConfigSnapshot,
    policy_counters: &PolicyCounterStore,
    previous: Option<&ForwardingState>,
) -> Result<ForwardingState, crate::policy::SnapshotIntegrityError> {
    let mut state = ForwardingState::default();
    let (excluded_local_v4, excluded_local_v6) = nat_translated_local_exclusions(snapshot);

    zones::populate_zones(snapshot, &mut state);
    tunnels::populate_tunnel_endpoints(snapshot, &mut state);
    // #1432 S2a: instantiate one WgEngine per mode=="wireguard" endpoint,
    // reusing the previous state's engine Arc when the endpoint config is
    // unchanged (TAI64N + live sessions survive the commit) and seeding a
    // fresh engine's TAI64N high-water from the prior engine otherwise.
    wg::populate_wg_engines(&mut state, previous);

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
        &snapshot.address_books,
        policy_counters,
    )?;
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
    // #1620: cold-path latency histogram sample mask. Default to 0xff
    // (1-in-256) when the field is absent on the wire (Option::None ⇒
    // older Go daemon or daemon launched without --cold-path-sample-mask).
    // The Go side validates the mask (powers-of-two minus one, plus
    // explicit --enable-cold-path-1-in-1-sampling for mask=0).
    state.cold_path_sample_mask = snapshot.cold_path_sample_mask.unwrap_or(0xff);
    // #1635: build the direct cold-path histogram slot map from the
    // configured policy zone-pairs, reusing the previous map's slot
    // assignments so retained pairs keep their accumulated histogram.
    // The worker derives its own slot zero-out set by diffing the old
    // and new map inverses at the ArcSwap point (Copilot code-r2:
    // generation-independent, unlike a coordinator-computed list), so
    // the build's `slots_to_zero` return is unused here — only the map
    // is stored.
    {
        use crate::afxdp::cold_path_hist::ColdPathSlotMap;
        let pairs = state.policy.configured_zone_pairs();
        let prev_map = previous.map(|p| p.cold_path_slot_map.as_ref());
        let (slot_map, _slots_to_zero) = ColdPathSlotMap::build(prev_map, &pairs);
        state.cold_path_slot_map = std::sync::Arc::new(slot_map);
    }
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
            // #1606: aggregate prefix count across the rule's
            // literal set + every cited book's dense entry.
            let src_v4_count = rule.source_literal_v4.prefix_count()
                + rule
                    .source_book_idxs
                    .iter()
                    .map(|&idx| state.policy.books[idx as usize].v4.prefix_count())
                    .sum::<usize>();
            let dst_v4_count = rule.destination_literal_v4.prefix_count()
                + rule
                    .destination_book_idxs
                    .iter()
                    .map(|&idx| state.policy.books[idx as usize].v4.prefix_count())
                    .sum::<usize>();
            debug_log!(
                "FWD_STATE: policy[{}] {}->{}  action={:?} src_v4={} dst_v4={} apps={}",
                i,
                rule.from_zone,
                rule.to_zone,
                rule.action,
                src_v4_count,
                dst_v4_count,
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

    // #1636 option D: compute the pending-neighbor drop timeout from the
    // live kernel retrans_time_ms sysctls. Re-evaluated every snapshot so
    // a runtime sysctl change (e.g. an admin reverting PR-1) is picked up
    // on the next apply and propagated atomically via ha.forwarding.
    state.pending_neigh_timeout_ns =
        compute_pending_neigh_timeout_ns(&state.ifindex_to_name, &RealSysctlReader);

    Ok(state)
}

/// #1636 option D: PENDING_NEIGH_TIMEOUT value (ns) when the kernel
/// `retrans_time_ms` is confirmed <= 250 on every dataplane interface
/// (v4 AND v6) plus the `default` template. Dropping a queued SYN at
/// 800ms re-drives it (via the client's first TCP RTO at ~1000ms)
/// against a kernel that has already resolved or is one fast retransmit
/// from resolving, instead of stalling to the 2000ms default.
pub(in crate::afxdp) const PENDING_NEIGH_TIMEOUT_FAST_NS: u64 = 800_000_000;

/// Threshold (ms) at/below which the kernel retrans timer is fast enough
/// to admit the 800ms timeout. The daemon writes 250ms
/// (neighRetransTargetMs in pkg/daemon/host_tunables.go) but the kernel
/// rounds retrans_time_ms to its internal jiffy resolution — a write of
/// 250 reads back as 252 on HZ=100 hosts. The threshold is therefore set
/// above the rounded value while staying far below the 1000ms default,
/// so the jiffy-rounded fast value is still admitted but a host left at
/// the default fails closed.
const NEIGH_RETRANS_FAST_THRESHOLD_MS: u32 = 300;

/// Reads a u32 from a sysctl-style file path. Abstracted so the
/// timeout-compute logic is unit-testable without touching real /proc.
pub(in crate::afxdp) trait SysctlReader {
    fn read_u32(&self, path: &str) -> Option<u32>;
}

struct RealSysctlReader;

impl SysctlReader for RealSysctlReader {
    fn read_u32(&self, path: &str) -> Option<u32> {
        std::fs::read_to_string(path)
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()
    }
}

/// Fail-closed computation of the pending-neighbor drop timeout.
///
/// Returns `PENDING_NEIGH_TIMEOUT_FAST_NS` (800ms) only if EVERY checked
/// `retrans_time_ms` sysctl reads <= `NEIGH_RETRANS_FAST_THRESHOLD_MS`
/// (300ms — the daemon writes 250 but the kernel jiffy-rounds it to 252
/// on HZ=100; v4 AND v6, every dataplane interface plus the `default`
/// template). Any read failure or any value above the threshold falls
/// back to `super::PENDING_NEIGH_TIMEOUT_NS` (2000ms) and emits a
/// transition-gated operator warning — if the sysctl never applied
/// (restricted container, sysctl namespace, admin override), dropping at
/// 800ms before the kernel's first 1000ms wire solicit would REGRESS the
/// baseline, so we keep the safe default.
pub(in crate::afxdp) fn compute_pending_neigh_timeout_ns<R: SysctlReader>(
    ifindex_to_name: &FastMap<i32, String>,
    reader: &R,
) -> u64 {
    // AGY r1 #4: this runs on EVERY snapshot build, so an un-gated
    // eprintln in the fallback path would flood stderr on every route
    // churn when option B is unapplied. Log only on the false->true
    // transition into the fallback state (and re-arm on recovery so a
    // revert→fix→revert cycle re-warns once). Process-global because the
    // sysctl state is process-global.
    static IN_FALLBACK: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    let fallback = || -> u64 {
        if !IN_FALLBACK.swap(true, Ordering::Relaxed) {
            eprintln!(
                "xpf-userspace-dp: WARNING: kernel retrans_time_ms not <= {}ms on all dataplane \
                 interfaces (v4 AND v6) — using PENDING_NEIGH_TIMEOUT_NS={}ms (option D inactive). \
                 Apply the #1636 sysctl drop-in to enable.",
                NEIGH_RETRANS_FAST_THRESHOLD_MS,
                super::PENDING_NEIGH_TIMEOUT_NS / 1_000_000,
            );
        }
        super::PENDING_NEIGH_TIMEOUT_NS
    };
    // Per-interface tables first (an interface created from a stale
    // template before PR-1 applied could still carry the old 1000ms).
    for name in ifindex_to_name.values() {
        for family in ["ipv4", "ipv6"] {
            let path = format!("/proc/sys/net/{family}/neigh/{name}/retrans_time_ms");
            match reader.read_u32(&path) {
                Some(v) if v <= NEIGH_RETRANS_FAST_THRESHOLD_MS => {}
                _ => return fallback(),
            }
        }
    }
    // The `default` template covers interfaces created post-snapshot.
    for family in ["ipv4", "ipv6"] {
        let path = format!("/proc/sys/net/{family}/neigh/default/retrans_time_ms");
        match reader.read_u32(&path) {
            Some(v) if v <= NEIGH_RETRANS_FAST_THRESHOLD_MS => {}
            _ => return fallback(),
        }
    }
    // Recovered (or always-fast): re-arm the warning so a later revert
    // logs again exactly once.
    IN_FALLBACK.store(false, Ordering::Relaxed);
    PENDING_NEIGH_TIMEOUT_FAST_NS
}
