// Snapshot/AST → typed Filter compiler extracted from filter.rs (#1049 P2 structural split).
// Pure relocation — bodies are byte-for-byte identical; only the
// enclosing module and visibility paths change.

use super::*;

/// Build the complete FilterState from snapshot data.
///
/// #2505: returns `Err(SnapshotIntegrityError)` when a filter term carries a
/// NON-EMPTY `from protocol` list with a token `ip_proto::proto_number` cannot
/// resolve. Silently dropping it (the pre-fix `filter_map`) was a fail-WIDE
/// security bug — an all-dropped list disabled the protocol match so the term
/// matched every protocol.
pub(crate) fn parse_filter_state(
    filters: &[FirewallFilterSnapshot],
    policers: &[PolicerSnapshot],
    interfaces: &[crate::InterfaceSnapshot],
    lo0_filter_v4: &str,
    lo0_filter_v6: &str,
) -> Result<FilterState, SnapshotIntegrityError> {
    parse_filter_state_with_three_color(
        filters,
        policers,
        &[],
        interfaces,
        lo0_filter_v4,
        lo0_filter_v6,
    )
}

/// Build the complete FilterState from snapshot data, including stable
/// three-color policer runtimes.
pub(crate) fn parse_filter_state_with_three_color(
    filters: &[FirewallFilterSnapshot],
    policers: &[PolicerSnapshot],
    three_color_policers: &[ThreeColorPolicerSnapshot],
    interfaces: &[crate::InterfaceSnapshot],
    lo0_filter_v4: &str,
    lo0_filter_v6: &str,
) -> Result<FilterState, SnapshotIntegrityError> {
    parse_filter_state_with_three_color_preserving(
        filters,
        policers,
        three_color_policers,
        interfaces,
        lo0_filter_v4,
        lo0_filter_v6,
        None,
    )
}

/// Build the complete FilterState while preserving compatible three-color
/// policer token/counter state across snapshot refreshes.
pub(crate) fn parse_filter_state_with_three_color_preserving(
    filters: &[FirewallFilterSnapshot],
    policers: &[PolicerSnapshot],
    three_color_policers: &[ThreeColorPolicerSnapshot],
    interfaces: &[crate::InterfaceSnapshot],
    lo0_filter_v4: &str,
    lo0_filter_v6: &str,
    previous: Option<&FilterState>,
) -> Result<FilterState, SnapshotIntegrityError> {
    let mut state = FilterState::default();

    // Parse legacy token-bucket policers.
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

    // Parse three-color policers by stable name order. Runtime IDs are
    // name-derived so inserting a lower-sorted policer does not reset
    // unchanged existing runtimes.
    let mut three_color = three_color_policers.iter().collect::<Vec<_>>();
    three_color.sort_by(|a, b| a.name.cmp(&b.name));
    let mut used_three_color_ids = rustc_hash::FxHashSet::default();
    for snap in three_color {
        let id = unique_three_color_policer_runtime_id(&snap.name, &mut used_three_color_ids);
        let Some(runtime) = parse_three_color_policer(snap, id, previous) else {
            continue;
        };
        state
            .three_color_policer_by_name
            .insert(runtime.name.to_string(), runtime.clone());
        state.three_color_policers.push(runtime);
    }

    // Parse filters
    for (filter_idx, snap) in filters.iter().enumerate() {
        let key = qualify_filter_key(&snap.family, &snap.name);
        let terms = snap
            .terms
            .iter()
            .enumerate()
            .map(|(term_idx, t)| {
                parse_term(
                    t,
                    term_idx as u32,
                    &snap.family,
                    &snap.name,
                    &state.three_color_policer_by_name,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let filter = Filter {
            id: filter_idx as u32,
            name: snap.name.clone(),
            family: snap.family.clone(),
            affects_tx_selection: terms
                .iter()
                .any(|term| !term.forwarding_class.is_empty() || term.dscp_rewrite.is_some()),
            affects_route_lookup: terms.iter().any(|term| !term.routing_instance.is_empty()),
            has_counter_terms: terms.iter().any(|term| term.has_count),
            has_log_terms: terms.iter().any(|term| term.log),
            has_terminal_action_terms: terms.iter().any(|term| term.action != FilterAction::Accept),
            has_dscp_match_terms: terms.iter().any(|term| term.dscp_match_enabled),
            has_per_packet_l4_match_terms: terms.iter().any(|term| term.has_per_packet_l4_match()),
            has_three_color_policer_terms: terms
                .iter()
                .any(|term| term.three_color_policer.is_some()),
            terms,
        };
        state.filters.insert(key, Arc::new(filter));
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
                if filter.has_three_color_policer_terms {
                    state.has_input_three_color_policer_v4 = true;
                }
                if filter.affects_route_lookup {
                    state
                        .iface_filter_v4_affects_route_lookup
                        .insert(iface.ifindex);
                }
                if filter.has_dscp_match_terms {
                    state.iface_filter_v4_has_dscp_match.insert(iface.ifindex);
                }
                if filter.has_per_packet_l4_match_terms {
                    state
                        .iface_filter_v4_has_per_packet_l4_match
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
                if filter.affects_tx_selection
                    || filter.has_counter_terms
                    || filter.has_log_terms
                    || filter.has_terminal_action_terms
                    || filter.has_three_color_policer_terms
                {
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
                if filter.has_three_color_policer_terms {
                    state.has_input_three_color_policer_v6 = true;
                }
                if filter.affects_route_lookup {
                    state
                        .iface_filter_v6_affects_route_lookup
                        .insert(iface.ifindex);
                }
                if filter.has_dscp_match_terms {
                    state.iface_filter_v6_has_dscp_match.insert(iface.ifindex);
                }
                if filter.has_per_packet_l4_match_terms {
                    state
                        .iface_filter_v6_has_per_packet_l4_match
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
                if filter.affects_tx_selection
                    || filter.has_counter_terms
                    || filter.has_log_terms
                    || filter.has_terminal_action_terms
                    || filter.has_three_color_policer_terms
                {
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

    Ok(state)
}

fn parse_three_color_policer(
    snap: &ThreeColorPolicerSnapshot,
    id: u32,
    previous: Option<&FilterState>,
) -> Option<Arc<ThreeColorPolicerRuntime>> {
    let state = build_three_color_policer_state(snap)
        .unwrap_or_else(|| ThreeColorPolicerState::fail_closed(snap.color_blind));
    if let Some(previous_runtime) =
        previous.and_then(|prev| prev.three_color_policer_by_name.get(&snap.name))
    {
        if previous_runtime.reusable_for(id, &state) {
            return Some(Arc::clone(previous_runtime));
        }
    }
    Some(Arc::new(ThreeColorPolicerRuntime::new(
        id,
        snap.name.clone(),
        state,
    )))
}

fn unique_three_color_policer_runtime_id(
    name: &str,
    used_ids: &mut rustc_hash::FxHashSet<u32>,
) -> u32 {
    let mut id = three_color_policer_runtime_id(name);
    while !used_ids.insert(id) {
        id = id.wrapping_add(1);
        if id == 0 {
            id = 1;
        }
    }
    id
}

pub(crate) fn three_color_policer_runtime_id(name: &str) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811c_9dc5;
    const FNV_PRIME: u32 = 0x0100_0193;
    const NAMESPACE: &[u8] = b"xpf-three-color-policer-v1:";

    let mut hash = FNV_OFFSET_BASIS;
    for byte in NAMESPACE.iter().chain(name.as_bytes()) {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    if hash == 0 { 1 } else { hash }
}

fn build_three_color_policer_state(
    snap: &ThreeColorPolicerSnapshot,
) -> Option<ThreeColorPolicerState> {
    if !snapshot_three_color_shape_supported(snap) {
        return None;
    }

    let treatments = treatments_from_then_action(&snap.then_action);
    match snap.mode.as_str() {
        "single-rate" => ThreeColorPolicerState::sr_tcm_with_treatments(
            snap.committed_rate_bytes_per_sec,
            snap.committed_burst_bytes,
            snap.peak_or_excess_burst_bytes,
            snap.color_blind,
            treatments,
        )
        .ok(),
        "two-rate" => ThreeColorPolicerState::tr_tcm_with_treatments(
            snap.committed_rate_bytes_per_sec,
            snap.committed_burst_bytes,
            snap.peak_or_excess_rate_bytes_per_sec,
            snap.peak_or_excess_burst_bytes,
            snap.color_blind,
            treatments,
        )
        .ok(),
        _ => None,
    }
}

fn snapshot_three_color_shape_supported(snap: &ThreeColorPolicerSnapshot) -> bool {
    snap.color_blind && (snap.then_action.is_empty() || snap.then_action == "discard")
}

fn treatments_from_then_action(action: &str) -> ThreeColorTreatments {
    if action.is_empty() || action == "discard" {
        return ThreeColorTreatments {
            red: ColorTreatment::drop(),
            ..ThreeColorTreatments::default()
        };
    }
    ThreeColorTreatments::default()
}

fn qualify_filter_key(family: &str, filter_name: &str) -> String {
    format!("{family}:{filter_name}")
}

fn parse_term(
    snap: &FirewallTermSnapshot,
    id: u32,
    filter_family: &str,
    filter_name: &str,
    three_color_policers: &rustc_hash::FxHashMap<String, Arc<ThreeColorPolicerRuntime>>,
) -> Result<FilterTerm, SnapshotIntegrityError> {
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
    // #2400 (032-18): a term is ADDRESS-CONSTRAINED when it has at least one
    // REAL `from { source-address / destination-address }` entry — `addr_is_real`
    // EXCLUDES the empty string and the literal `any` (the placeholders
    // `parse_address` already drops), so an explicit `from { source-address
    // any; }` stays UNCONSTRAINED (match-any) rather than degrading to
    // fail-closed. When the term is constrained but every real entry failed to
    // parse, the per-family vecs are empty and the matcher fails closed (see
    // engine/matching.rs).
    //
    // #2506 (Copilot): OR in the EXPLICIT `source_constrained` /
    // `destination_constrained` snapshot signal. The address-length derivation
    // alone is insufficient for prefix-list scopes that resolve EMPTY: a `from
    // source-prefix-list X` whose X is defined-but-empty or lenient-unresolved
    // produces an empty `source_addresses` list, so the length test yields
    // `false` and the direction would wrongly collapse to match-any. The Go side
    // sets the explicit flag whenever the term wrote ANY scope (literal address
    // OR prefix-list ref), so the OR makes the matcher fail closed (positive) /
    // match-all (except) per the Junos empty-set semantics. An older Go control
    // plane that omits the flag (false) falls back to the length derivation —
    // unchanged for the non-prefix-list cases that have no empty-resolution gap.
    let source_addr_constrained =
        snap.source_constrained || snap.source_addresses.iter().any(|a| addr_is_real(a));
    let dest_addr_constrained =
        snap.destination_constrained || snap.destination_addresses.iter().any(|a| addr_is_real(a));
    // #2505: resolve every `from protocol` token via the SHARED, normalizing
    // resolver `ip_proto::proto_number` (trim + lowercase + the full
    // appid.ProtocolNumber acceptance set: esp/ah/sctp/vrrp/igmp/pim/egp +
    // the junos-* aliases), NOT the stale local parser this function used to
    // carry (tcp/udp/icmp/icmpv6/gre/ospf/ipip + bare numeric, no
    // normalization). An EMPTY input list is the legitimate "no protocol
    // constraint" case -> empty `protocols` -> `protocol_match_enabled` false
    // (match-any, preserved below). A NON-EMPTY list with any UNRESOLVABLE
    // token is a snapshot-integrity error: silently dropping it (the pre-fix
    // `filter_map`) collapses the list to empty and disables the protocol
    // match, so a `from protocol esp; then discard` term would match EVERY
    // protocol (fail-WIDE). Fail closed by rejecting the whole snapshot — the
    // reconcile preflight keeps the previous good filter state.
    let mut protocols: Vec<u8> = Vec::with_capacity(snap.protocols.len());
    for token in &snap.protocols {
        // An empty / whitespace-only entry is a placeholder, never a real
        // constraint (the Go side only emits `protocols` when `term.Protocol
        // != ""`); treat it as "no protocol" rather than an integrity error,
        // mirroring the pre-fix `parse_protocol("")` -> None drop.
        if token.trim().is_empty() {
            continue;
        }
        match proto_number(token) {
            Some(n) => protocols.push(n),
            None => {
                return Err(SnapshotIntegrityError::UnrepresentableFilterProtocol {
                    family: filter_family.to_string(),
                    filter: filter_name.to_string(),
                    term: snap.name.clone(),
                    token: token.clone(),
                });
            }
        }
    }
    // #2622: a direction's port scope is either the positive `source-port` /
    // `destination-port` list OR the negated `source-port-except` /
    // `destination-port-except` list (Junos treats them as mutually exclusive).
    // Build ONE PortMatcher per direction from whichever list carries entries,
    // and set `*_port_except` when the except list is the source. If both are
    // somehow present, the positive list builds the matcher and the except list
    // is ignored (positive wins) — the except flag stays false so the positive
    // set is honored verbatim.
    let source_port_except = snap.source_ports.iter().all(|p| !port_is_real(p))
        && snap.source_ports_except.iter().any(|p| port_is_real(p));
    let dest_port_except = snap.destination_ports.iter().all(|p| !port_is_real(p))
        && snap.destination_ports_except.iter().any(|p| port_is_real(p));
    let source_port_specs: &[String] = if source_port_except {
        &snap.source_ports_except
    } else {
        &snap.source_ports
    };
    let dest_port_specs: &[String] = if dest_port_except {
        &snap.destination_ports_except
    } else {
        &snap.destination_ports
    };
    let source_ports: Vec<PortRange> = source_port_specs
        .iter()
        .filter_map(|p| parse_port_spec(p))
        .flatten()
        .collect();
    let dest_ports: Vec<PortRange> = dest_port_specs
        .iter()
        .filter_map(|p| parse_port_spec(p))
        .flatten()
        .collect();
    // #2400 (032-19): mirror of the address constraint for the port match sets.
    // `port_is_real` ignores the empty-string placeholder (which `parse_port_spec`
    // treats as "no port range") so an empty entry never trips fail-closed. A
    // constrained port set whose entries ALL failed to parse yields zero ranges
    // -> `PortMatcher::Any`; the `*_port_constrained` flag lets the matcher tell
    // that apart from a genuinely unscoped term and fail closed. The constraint
    // is derived from the SELECTED spec list (positive or except), so an
    // except-only term is correctly constrained (#2622).
    let source_port_constrained = source_port_specs.iter().any(|p| port_is_real(p));
    let dest_port_constrained = dest_port_specs.iter().any(|p| port_is_real(p));
    let action = match snap.action.as_str() {
        "accept" => FilterAction::Accept,
        "reject" => FilterAction::Reject,
        "discard" => FilterAction::Discard,
        // #2399 (032-16) / #2544: an EMPTY action is the legitimate "no
        // terminating action" case — the term carries only modifiers
        // (count/log/forwarding-class/policer/dscp) and falls through to the
        // next term. Map it to Accept as a PLACEHOLDER (the action field is
        // never returned for a matched fall-through term — see continue_term
        // below), but the real semantic is carried by FilterTerm.continue_term:
        // the evaluator applies the modifiers and CONTINUES rather than
        // short-circuiting to a terminating decision. A NON-EMPTY but
        // unrecognized action string can only arrive from a mixed-version
        // snapshot (the Go commit gate validateFilterActionsStrict rejects an
        // unknown `then` token before it is persisted). For a FIREWALL FILTER an
        // unknown terminating action must fail CLOSED, never silently permit —
        // map it to Discard rather than Accept.
        "" => FilterAction::Accept,
        other => {
            eprintln!(
                "xpf-filter: term {:?} carries an unknown action {:?}; \
                 failing closed (discard) — snapshot/version drift",
                snap.name, other
            );
            FilterAction::Discard
        }
    };
    let dscp_rewrite = snap.dscp_rewrite.map(|value| value & 0x3f);

    Ok(FilterTerm {
        id,
        name: snap.name.clone(),
        source_v4,
        source_v6,
        dest_v4,
        dest_v6,
        source_addr_constrained,
        dest_addr_constrained,
        // #2506: carry the per-direction `except` inversion flag from the
        // snapshot. The Go control plane only sets it when the address set is an
        // `except` prefix-list (the inversion is meaningful only against a
        // non-empty constrained set; see resolvePrefixListAddrs).
        source_except: snap.source_except,
        dest_except: snap.destination_except,
        protocol_bitmap: build_u8_match_bitmap(&protocols),
        protocol_match_enabled: !protocols.is_empty(),
        source_ports: build_port_matcher(source_ports),
        dest_ports: build_port_matcher(dest_ports),
        source_port_constrained,
        dest_port_constrained,
        // #2622: carry the negated-port inversion flag (Junos `*-port-except`).
        source_port_except,
        dest_port_except,
        dscp_bitmap: build_u6_match_bitmap(&snap.dscp_values),
        dscp_match_enabled: !snap.dscp_values.is_empty(),
        // #2362 per-packet L4 match conditions. A zero tcp_flags mask means
        // "no constraint" (would match every packet), so fold it to None — the
        // Go side already omits a 0 mask; this is a guard against a
        // hand-crafted snapshot.
        tcp_flags_mask: snap.tcp_flags.filter(|&m| m != 0),
        // #3076 forbidden-bits mask (negated tcp-flags operands). Same 0->None
        // fold as the required mask: a 0 forbidden mask is "no constraint", and
        // the Go side already omits a 0; this guards a hand-crafted snapshot.
        tcp_flags_forbidden: snap.tcp_flags_forbidden.filter(|&m| m != 0),
        is_fragment: snap.is_fragment,
        // #2545: icmp-type / icmp-code are SET membership (match-ANY). An empty
        // list = no constraint (`*_match_enabled` false → match any), preserving
        // the prior scalar-None behavior.
        icmp_type_bitmap: build_u8_match_bitmap(&snap.icmp_types),
        icmp_type_match_enabled: !snap.icmp_types.is_empty(),
        icmp_code_bitmap: build_u8_match_bitmap(&snap.icmp_codes),
        icmp_code_match_enabled: !snap.icmp_codes.is_empty(),
        action,
        // #2544: this term falls through (applies modifiers, continues to the
        // next term) when it carries no terminating action. The Go control
        // plane sets next_term for both the explicit `then next term` and the
        // modifier-only case. We OR in `snap.action.is_empty()` as a belt-and-
        // suspenders guard so an older Go control plane that omits next_term but
        // sends an empty-action modifier-only term still falls through instead
        // of terminating as Accept. A routing-instance (PBR) term takes its own
        // routing decision and is NOT a fall-through even with an empty action.
        continue_term: (snap.next_term || snap.action.is_empty())
            && snap.routing_instance.is_empty(),
        count: snap.count.clone(),
        has_count: !snap.count.is_empty(),
        log: snap.log,
        policer_name: snap.policer.clone(),
        three_color_policer: three_color_policers.get(&snap.policer).cloned(),
        routing_instance: snap.routing_instance.clone(),
        forwarding_class: Arc::<str>::from(snap.forwarding_class.as_str()),
        dscp_rewrite,
        counter: Arc::new(FilterTermCounter::default()),
    })
}

/// #2400: whether an address entry imposes a real scope. `parse_address` drops
/// the empty string and the literal `any` as "no constraint" placeholders, so
/// they must NOT make a term address-constrained (otherwise `from {
/// source-address any; }` would fail closed). Every other entry — valid OR
/// malformed — is a real scope; an all-malformed list is exactly the fail-open
/// case #2400 closes.
fn addr_is_real(entry: &str) -> bool {
    !entry.is_empty() && entry != "any"
}

/// #2400: whether a port entry imposes a real scope. `parse_port_spec` treats
/// the empty string as "no port range", so an empty placeholder must NOT make a
/// term port-constrained. Every other entry — valid OR malformed — is a real
/// scope.
fn port_is_real(entry: &str) -> bool {
    !entry.is_empty()
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
