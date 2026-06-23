// Tests for the filter module (#1049). Originally inline in filter.rs,
// relocated as filter_tests.rs in P1 (PR #1052), then renamed to
// filter/tests.rs alongside the structural split into compiler/engine/policer.
// Loaded as a sibling submodule via `#[path = "tests.rs"]` from filter/mod.rs.

use super::*;

fn make_filter_state(
    filters: &[FirewallFilterSnapshot],
    policers: &[PolicerSnapshot],
) -> FilterState {
    parse_filter_state(filters, policers, &[], "", "")
}

fn make_filter_state_with_three_color(
    filters: &[FirewallFilterSnapshot],
    three_color_policers: &[ThreeColorPolicerSnapshot],
) -> FilterState {
    parse_filter_state_with_three_color(filters, &[], three_color_policers, &[], "", "")
}

fn make_filter_state_with_interfaces(
    filters: &[FirewallFilterSnapshot],
    interfaces: &[crate::InterfaceSnapshot],
) -> FilterState {
    parse_filter_state(filters, &[], interfaces, "", "")
}

#[test]
fn basic_accept_discard() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "test-filter".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "deny-ssh".into(),
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec!["tcp".into()],
                    source_ports: vec![],
                    destination_ports: vec!["22".into()],
                    dscp_values: vec![],
                    action: "discard".into(),
                    count: String::new(),
                    log: false,
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
                    tcp_flags: None,
                    is_fragment: false,
                    icmp_type: None,
                    icmp_code: None,
                },
                FirewallTermSnapshot {
                    name: "allow-all".into(),
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec![],
                    source_ports: vec![],
                    destination_ports: vec![],
                    dscp_values: vec![],
                    action: "accept".into(),
                    count: String::new(),
                    log: false,
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
                    tcp_flags: None,
                    is_fragment: false,
                    icmp_type: None,
                    icmp_code: None,
                },
            ],
        }],
        &[],
    );
    // SSH traffic should be discarded
    let result = evaluate_filter(
        &state,
        "inet:test-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),
        PROTO_TCP,
        12345,
        22,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);

    // HTTP traffic should be accepted
    let result = evaluate_filter(
        &state,
        "inet:test-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),
        PROTO_TCP,
        12345,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);
}

#[test]
fn interface_filter_log_match_returns_filter_and_term_identity() {
    let state = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "edge-in".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "log-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                log: true,
                ..Default::default()
            }],
        }],
        &[crate::InterfaceSnapshot {
            ifindex: 7,
            filter_input_v4: "edge-in".into(),
            ..Default::default()
        }],
    );

    let log_match = evaluate_interface_filter_log_match(
        &state,
        7,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        PROTO_TCP,
        49152,
        443,
        0,
        TermMatchExtra::default(),
        true,
    )
    .expect("logged input filter hit");

    assert_eq!(log_match.filter_id, 0);
    assert_eq!(log_match.term_id, 0);
    assert_eq!(log_match.action, FilterAction::Accept);
}

#[test]
fn interface_filter_log_match_skips_pbr_terms_without_double_emit() {
    let state = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "pbr-in".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "route-and-log".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                log: true,
                routing_instance: "blue".into(),
                ..Default::default()
            }],
        }],
        &[crate::InterfaceSnapshot {
            ifindex: 7,
            filter_input_v4: "pbr-in".into(),
            ..Default::default()
        }],
    );

    let log_match = evaluate_interface_filter_log_match(
        &state,
        7,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        PROTO_TCP,
        49152,
        443,
        0,
        TermMatchExtra::default(),
        true,
    );

    assert_eq!(log_match, None);
}

#[test]
fn port_range_matching() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "port-range".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "high-ports".into(),
                destination_addresses: vec![],
                source_addresses: vec![],
                protocols: vec!["tcp".into()],
                source_ports: vec![],
                destination_ports: vec!["1024-65535".into()],
                dscp_values: vec![],
                action: "discard".into(),
                count: String::new(),
                log: false,
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: None,
                tcp_flags: None,
                is_fragment: false,
                icmp_type: None,
                icmp_code: None,
            }],
        }],
        &[],
    );
    // Port 2000 is in range
    let result = evaluate_filter(
        &state,
        "inet:port-range",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        54321,
        2000,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);

    // Port 80 is not in range — no match, implicit accept
    let result = evaluate_filter(
        &state,
        "inet:port-range",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        54321,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);
}

#[test]
fn protocol_matching() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "proto-filter".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny-icmp".into(),
                destination_addresses: vec![],
                source_addresses: vec![],
                protocols: vec!["icmp".into()],
                source_ports: vec![],
                destination_ports: vec![],
                dscp_values: vec![],
                action: "discard".into(),
                count: String::new(),
                log: false,
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: None,
                tcp_flags: None,
                is_fragment: false,
                icmp_type: None,
                icmp_code: None,
            }],
        }],
        &[],
    );
    // ICMP should be discarded
    let result = evaluate_filter(
        &state,
        "inet:proto-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_ICMP,
        0,
        0,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);

    // TCP should pass (no match)
    let result = evaluate_filter(
        &state,
        "inet:proto-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);
}

#[test]
fn dscp_rewrite_action() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "dscp-rewrite".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "mark-ef".into(),
                destination_addresses: vec![],
                source_addresses: vec![],
                protocols: vec!["udp".into()],
                source_ports: vec![],
                destination_ports: vec!["5060".into()],
                dscp_values: vec![],
                action: "accept".into(),
                count: String::new(),
                log: false,
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: Some(46), // EF
                tcp_flags: None,
                is_fragment: false,
                icmp_type: None,
                icmp_code: None,
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:dscp-rewrite",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        54321,
        5060,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);
    assert_eq!(result.dscp_rewrite, Some(46));
}

#[test]
fn dscp_rewrite_action_allows_default_zero() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "dscp-default".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "mark-default".into(),
                destination_addresses: vec![],
                source_addresses: vec![],
                protocols: vec!["udp".into()],
                source_ports: vec![],
                destination_ports: vec!["5060".into()],
                dscp_values: vec![],
                action: "accept".into(),
                count: String::new(),
                log: false,
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: Some(0),
                tcp_flags: None,
                is_fragment: false,
                icmp_type: None,
                icmp_code: None,
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:dscp-default",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        54321,
        5060,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);
    assert_eq!(result.dscp_rewrite, Some(0));
}

#[test]
fn token_bucket_policer() {
    let mut policer = PolicerState::new(
        "1mbps".into(),
        1_000_000, // 1 Mbps = 125,000 bytes/sec
        125_000,   // burst = 125KB
        true,
    );

    // First packet at t=0 — should be within burst
    let conforming = policer.consume(0, 1000);
    assert!(conforming, "first packet within burst should conform");

    // Consume most of the burst
    let conforming = policer.consume(0, 120_000);
    assert!(conforming, "second packet within burst should conform");

    // This should exceed burst (only ~4000 tokens left)
    let conforming = policer.consume(0, 10_000);
    assert!(
        !conforming,
        "packet exceeding burst should be non-conforming"
    );

    // After 1 second, tokens should have refilled
    let conforming = policer.consume(1_000_000_000, 1000);
    assert!(conforming, "packet after refill should conform");
}

#[test]
fn three_color_runtime_ids_and_miss_path_counters_are_stable() {
    let state = make_filter_state_with_three_color(
        &[FirewallFilterSnapshot {
            name: "policed".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "meter".into(),
                action: "accept".into(),
                policer: "alpha".into(),
                ..Default::default()
            }],
        }],
        &[
            ThreeColorPolicerSnapshot {
                name: "zeta".into(),
                mode: "single-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1,
                committed_burst_bytes: 100,
                peak_or_excess_burst_bytes: 50,
                then_action: "discard".into(),
                ..Default::default()
            },
            ThreeColorPolicerSnapshot {
                name: "alpha".into(),
                mode: "single-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1,
                committed_burst_bytes: 100,
                peak_or_excess_burst_bytes: 50,
                then_action: "discard".into(),
                ..Default::default()
            },
        ],
    );

    let ids = state
        .three_color_policers
        .iter()
        .map(|runtime| (runtime.id, runtime.name.as_ref().to_string()))
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        vec![
            (three_color_policer_runtime_id("alpha"), "alpha".into()),
            (three_color_policer_runtime_id("zeta"), "zeta".into()),
        ]
    );

    let filter = state.filters.get("inet:policed").unwrap();
    assert!(filter.has_three_color_policer_terms);
    let first = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        100,
        0,
    );
    assert!(!first.policer_drop);

    let second = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        51,
        0,
    );
    assert!(second.policer_drop);

    let status = state.three_color_policer_statuses();
    let alpha = status.iter().find(|item| item.name == "alpha").unwrap();
    assert_eq!(alpha.mode, "single-rate");
    assert!(alpha.color_blind);
    assert_eq!(alpha.green_packets, 1);
    assert_eq!(alpha.green_bytes, 100);
    assert_eq!(alpha.red_packets, 1);
    assert_eq!(alpha.red_bytes, 51);
    assert_eq!(alpha.drop_packets, 1);
    assert_eq!(alpha.drop_bytes, 51);
}

#[test]
fn flow_cache_hits_run_three_color_policer() {
    let state = make_filter_state_with_three_color(
        &[FirewallFilterSnapshot {
            name: "policed".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "meter".into(),
                action: "accept".into(),
                policer: "cache-pol".into(),
                ..Default::default()
            }],
        }],
        &[ThreeColorPolicerSnapshot {
            name: "cache-pol".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 100,
            peak_or_excess_burst_bytes: 50,
            then_action: "discard".into(),
            ..Default::default()
        }],
    );

    let filter = state.filters.get("inet:policed").unwrap();
    let cached = evaluate_filter_ref_tx_selection_cached(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
    );
    assert_eq!(cached.three_color_policers.len(), 1);

    let first = apply_cached_three_color_policers(&cached.three_color_policers, 0, 100);
    assert!(!first.drop);
    let second = apply_cached_three_color_policers(&cached.three_color_policers, 0, 51);
    assert!(second.drop);

    let status = state.three_color_policer_statuses();
    assert_eq!(status[0].green_packets, 1);
    assert_eq!(status[0].red_packets, 1);
    assert_eq!(status[0].drop_packets, 1);
}

#[test]
fn equivalent_snapshot_refresh_preserves_three_color_state_and_counters() {
    let filters = [FirewallFilterSnapshot {
        name: "policed".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "meter".into(),
            action: "accept".into(),
            policer: "stable-pol".into(),
            ..Default::default()
        }],
    }];
    let policers = [ThreeColorPolicerSnapshot {
        name: "stable-pol".into(),
        mode: "single-rate".into(),
        color_blind: true,
        committed_rate_bytes_per_sec: 1,
        committed_burst_bytes: 100,
        peak_or_excess_burst_bytes: 50,
        then_action: "discard".into(),
        ..Default::default()
    }];

    let state = make_filter_state_with_three_color(&filters, &policers);
    let filter = state.filters.get("inet:policed").unwrap();
    let green = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        100,
        0,
    );
    assert!(!green.policer_drop);

    let refreshed = parse_filter_state_with_three_color_preserving(
        &filters,
        &[],
        &policers,
        &[],
        "",
        "",
        Some(&state),
    );
    assert!(
        std::sync::Arc::ptr_eq(
            &state.three_color_policers[0],
            &refreshed.three_color_policers[0]
        ),
        "compatible refresh must reuse the live runtime, not clone state"
    );
    let refreshed_filter = refreshed.filters.get("inet:policed").unwrap();
    let red = evaluate_filter_ref_tx_selection_runtime_counted(
        refreshed_filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        51,
        0,
    );

    assert!(
        red.policer_drop,
        "equivalent snapshot refresh must preserve consumed token state"
    );
    let status = refreshed.three_color_policer_statuses();
    assert_eq!(status[0].green_packets, 1);
    assert_eq!(status[0].green_bytes, 100);
    assert_eq!(status[0].red_packets, 1);
    assert_eq!(status[0].red_bytes, 51);
    assert_eq!(status[0].drop_packets, 1);
    assert_eq!(status[0].drop_bytes, 51);
}

#[test]
fn three_color_adding_lower_sorted_policer_does_not_reset_existing_runtime() {
    let filters = [FirewallFilterSnapshot {
        name: "policed".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "meter".into(),
            action: "accept".into(),
            policer: "stable-pol".into(),
            ..Default::default()
        }],
    }];
    let stable = ThreeColorPolicerSnapshot {
        name: "stable-pol".into(),
        mode: "single-rate".into(),
        color_blind: true,
        committed_rate_bytes_per_sec: 1,
        committed_burst_bytes: 100,
        peak_or_excess_burst_bytes: 50,
        then_action: "discard".into(),
        ..Default::default()
    };
    let inserted = ThreeColorPolicerSnapshot {
        name: "aaa-new-pol".into(),
        ..stable.clone()
    };

    let state = make_filter_state_with_three_color(&filters, &[stable.clone()]);
    let filter = state.filters.get("inet:policed").unwrap();
    let first = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        100,
        0,
    );
    assert!(!first.policer_drop);

    let refreshed = parse_filter_state_with_three_color_preserving(
        &filters,
        &[],
        &[inserted, stable],
        &[],
        "",
        "",
        Some(&state),
    );
    let previous_runtime = state
        .three_color_policer_by_name
        .get("stable-pol")
        .expect("previous runtime");
    let refreshed_runtime = refreshed
        .three_color_policer_by_name
        .get("stable-pol")
        .expect("refreshed runtime");
    assert!(
        std::sync::Arc::ptr_eq(previous_runtime, refreshed_runtime),
        "adding an alphabetically earlier policer must not reset stable-pol"
    );
    assert_eq!(
        refreshed_runtime.id,
        three_color_policer_runtime_id("stable-pol")
    );

    let refreshed_filter = refreshed.filters.get("inet:policed").unwrap();
    let second = evaluate_filter_ref_tx_selection_runtime_counted(
        refreshed_filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        51,
        0,
    );
    assert!(
        second.policer_drop,
        "refreshed stable-pol must retain tokens consumed before insertion"
    );
}

#[test]
fn three_color_compatible_refresh_observes_old_runtime_mutations_after_rebuild() {
    let filters = [FirewallFilterSnapshot {
        name: "policed".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "meter".into(),
            action: "accept".into(),
            policer: "stable-pol".into(),
            ..Default::default()
        }],
    }];
    let policers = [ThreeColorPolicerSnapshot {
        name: "stable-pol".into(),
        mode: "single-rate".into(),
        color_blind: true,
        committed_rate_bytes_per_sec: 1,
        committed_burst_bytes: 100,
        peak_or_excess_burst_bytes: 50,
        then_action: "discard".into(),
        ..Default::default()
    }];

    let state = make_filter_state_with_three_color(&filters, &policers);
    let refreshed = parse_filter_state_with_three_color_preserving(
        &filters,
        &[],
        &policers,
        &[],
        "",
        "",
        Some(&state),
    );
    assert!(std::sync::Arc::ptr_eq(
        &state.three_color_policers[0],
        &refreshed.three_color_policers[0]
    ));

    let old_filter = state.filters.get("inet:policed").unwrap();
    let old_green = evaluate_filter_ref_tx_selection_runtime_counted(
        old_filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        100,
        0,
    );
    assert!(!old_green.policer_drop);

    let refreshed_filter = refreshed.filters.get("inet:policed").unwrap();
    let refreshed_red = evaluate_filter_ref_tx_selection_runtime_counted(
        refreshed_filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        51,
        0,
    );

    assert!(
        refreshed_red.policer_drop,
        "post-rebuild mutations through the old handle must be visible"
    );
    let status = refreshed.three_color_policer_statuses();
    assert_eq!(status[0].green_packets, 1);
    assert_eq!(status[0].red_packets, 1);
    assert_eq!(status[0].drop_packets, 1);
}

#[test]
fn changed_snapshot_shape_resets_three_color_runtime_state() {
    let filters = [FirewallFilterSnapshot {
        name: "policed".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "meter".into(),
            action: "accept".into(),
            policer: "stable-pol".into(),
            ..Default::default()
        }],
    }];
    let original = [ThreeColorPolicerSnapshot {
        name: "stable-pol".into(),
        mode: "single-rate".into(),
        color_blind: true,
        committed_rate_bytes_per_sec: 1,
        committed_burst_bytes: 100,
        peak_or_excess_burst_bytes: 50,
        then_action: "discard".into(),
        ..Default::default()
    }];
    let changed = [ThreeColorPolicerSnapshot {
        committed_burst_bytes: 200,
        ..original[0].clone()
    }];

    let state = make_filter_state_with_three_color(&filters, &original);
    let filter = state.filters.get("inet:policed").unwrap();
    let first = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        100,
        0,
    );
    assert!(!first.policer_drop);

    let refreshed = parse_filter_state_with_three_color_preserving(
        &filters,
        &[],
        &changed,
        &[],
        "",
        "",
        Some(&state),
    );
    let refreshed_filter = refreshed.filters.get("inet:policed").unwrap();
    let second = evaluate_filter_ref_tx_selection_runtime_counted(
        refreshed_filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        200,
        0,
    );

    assert!(
        !second.policer_drop,
        "changed token shape should create a fresh runtime with new burst"
    );
    let status = refreshed.three_color_policer_statuses();
    assert_eq!(status[0].green_packets, 1);
    assert_eq!(status[0].green_bytes, 200);
}

#[test]
fn unsupported_three_color_snapshots_fail_closed_in_rust_compiler() {
    let cases = vec![
        (
            "color-aware",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "single-rate".into(),
                color_blind: false,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_burst_bytes: 50,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "non-discard-action",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "single-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_burst_bytes: 50,
                then_action: "loss-priority high".into(),
                ..Default::default()
            },
        ),
        (
            "invalid-token-shape",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "single-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 0,
                committed_burst_bytes: 100,
                peak_or_excess_burst_bytes: 50,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "mode-drift",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "single_rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_burst_bytes: 50,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "pir-below-cir",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "two-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_rate_bytes_per_sec: 999,
                peak_or_excess_burst_bytes: 100,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "zero-pir-two-rate",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "two-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_rate_bytes_per_sec: 0,
                peak_or_excess_burst_bytes: 100,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "zero-committed-burst-two-rate",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "two-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 0,
                peak_or_excess_rate_bytes_per_sec: 2_000,
                peak_or_excess_burst_bytes: 100,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "peak-burst-below-committed-burst",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "two-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_rate_bytes_per_sec: 2_000,
                peak_or_excess_burst_bytes: 99,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "zero-peak-burst-two-rate",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "two-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_rate_bytes_per_sec: 2_000,
                peak_or_excess_burst_bytes: 0,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "zero-excess-burst",
            ThreeColorPolicerSnapshot {
                name: "bad-pol".into(),
                mode: "single-rate".into(),
                color_blind: true,
                committed_rate_bytes_per_sec: 1_000,
                committed_burst_bytes: 100,
                peak_or_excess_burst_bytes: 0,
                then_action: "discard".into(),
                ..Default::default()
            },
        ),
        (
            "serde-defaulted-malformed",
            serde_json::from_value(serde_json::json!({
                "name": "bad-pol",
                "color_blind": true,
                "then_action": "discard"
            }))
            .expect("defaulted malformed snapshot decodes"),
        ),
    ];

    for (name, snapshot) in cases {
        let state = make_filter_state_with_three_color(
            &[FirewallFilterSnapshot {
                name: format!("policed-{name}"),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "meter".into(),
                    action: "accept".into(),
                    policer: "bad-pol".into(),
                    ..Default::default()
                }],
            }],
            &[snapshot],
        );

        let filter = state
            .filters
            .get(&format!("inet:policed-{name}"))
            .expect("compiled filter");
        assert!(
            filter.has_three_color_policer_terms,
            "{name}: unsupported snapshot must still link a fail-closed runtime"
        );

        let result = evaluate_filter_ref_tx_selection_runtime_counted(
            filter,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_UDP,
            12345,
            5000,
            0,
            TermMatchExtra::default(),
            1,
            0,
        );

        assert!(
            result.policer_drop,
            "{name}: unsupported snapshot must drop matching traffic"
        );
        let status = state.three_color_policer_statuses();
        assert_eq!(status.len(), 1, "{name}: status should expose runtime");
        assert_eq!(status[0].mode, "unsupported", "{name}: mode");
        assert_eq!(status[0].red_packets, 1, "{name}: red packets");
        assert_eq!(status[0].drop_packets, 1, "{name}: drop packets");
    }
}

#[test]
fn three_color_empty_then_action_uses_default_discard() {
    let state = make_filter_state_with_three_color(
        &[FirewallFilterSnapshot {
            name: "policed".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "meter".into(),
                action: "accept".into(),
                policer: "default-action-pol".into(),
                ..Default::default()
            }],
        }],
        &[ThreeColorPolicerSnapshot {
            name: "default-action-pol".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 100,
            peak_or_excess_burst_bytes: 50,
            then_action: String::new(),
            ..Default::default()
        }],
    );

    let filter = state.filters.get("inet:policed").unwrap();
    let green = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        100,
        0,
    );
    let red = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        51,
        0,
    );

    assert!(!green.policer_drop);
    assert!(red.policer_drop);
    let status = state.three_color_policer_statuses();
    assert_eq!(status[0].mode, "single-rate");
    assert_eq!(status[0].green_packets, 1);
    assert_eq!(status[0].red_packets, 1);
    assert_eq!(status[0].drop_packets, 1);
}

#[test]
fn cached_three_color_descriptor_dedupes_without_vec_allocation() {
    let state = make_filter_state_with_three_color(
        &[
            FirewallFilterSnapshot {
                name: "in".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "meter-in".into(),
                    action: "accept".into(),
                    policer: "same-pol".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "out".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "meter-out".into(),
                    action: "accept".into(),
                    policer: "same-pol".into(),
                    ..Default::default()
                }],
            },
        ],
        &[ThreeColorPolicerSnapshot {
            name: "same-pol".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 100,
            peak_or_excess_burst_bytes: 50,
            then_action: "discard".into(),
            ..Default::default()
        }],
    );

    let mut combined = evaluate_filter_ref_tx_selection_cached(
        state.filters.get("inet:out").unwrap(),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
    )
    .three_color_policers;
    combined.extend(
        evaluate_filter_ref_tx_selection_cached(
            state.filters.get("inet:in").unwrap(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            PROTO_UDP,
            12345,
            5000,
            0,
        )
        .three_color_policers,
    );

    assert_eq!(combined.len(), 1);
    assert!(!apply_cached_three_color_policers(&combined, 0, 100).drop);
    assert!(apply_cached_three_color_policers(&combined, 0, 51).drop);
}

#[test]
fn multiple_terms_first_match_wins() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "multi".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "allow-dns".into(),
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec!["udp".into()],
                    source_ports: vec![],
                    destination_ports: vec!["53".into()],
                    dscp_values: vec![],
                    action: "accept".into(),
                    count: String::new(),
                    log: false,
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
                    tcp_flags: None,
                    is_fragment: false,
                    icmp_type: None,
                    icmp_code: None,
                },
                FirewallTermSnapshot {
                    name: "deny-all-udp".into(),
                    destination_addresses: vec![],
                    source_addresses: vec![],
                    protocols: vec!["udp".into()],
                    source_ports: vec![],
                    destination_ports: vec![],
                    dscp_values: vec![],
                    action: "discard".into(),
                    count: String::new(),
                    log: false,
                    policer: String::new(),
                    routing_instance: String::new(),
                    forwarding_class: String::new(),
                    dscp_rewrite: None,
                    tcp_flags: None,
                    is_fragment: false,
                    icmp_type: None,
                    icmp_code: None,
                },
            ],
        }],
        &[],
    );
    // DNS should be accepted (first term wins)
    let result = evaluate_filter(
        &state,
        "inet:multi",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        53,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);

    // Other UDP should be discarded (second term)
    let result = evaluate_filter(
        &state,
        "inet:multi",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        1234,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);
}

#[test]
fn source_dest_address_matching() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "addr-filter".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny-from-subnet".into(),
                source_addresses: vec!["192.168.1.0/24".into()],
                destination_addresses: vec!["10.0.0.0/8".into()],
                protocols: vec![],
                source_ports: vec![],
                destination_ports: vec![],
                dscp_values: vec![],
                action: "discard".into(),
                count: String::new(),
                log: false,
                policer: String::new(),
                routing_instance: String::new(),
                forwarding_class: String::new(),
                dscp_rewrite: None,
                tcp_flags: None,
                is_fragment: false,
                icmp_type: None,
                icmp_code: None,
            }],
        }],
        &[],
    );
    // Matching src+dst
    let result = evaluate_filter(
        &state,
        "inet:addr-filter",
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);

    // Non-matching source
    let result = evaluate_filter(
        &state,
        "inet:addr-filter",
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);
}

#[test]
fn interface_filter_assignment() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "ge-0/0/0.0".into(),
        ifindex: 5,
        filter_input_v4: "protect-RE".into(),
        filter_input_v6: "protect-RE-v6".into(),
        filter_output_v4: "egress-v4".into(),
        filter_output_v6: "egress-v6".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[
            FirewallFilterSnapshot {
                name: "protect-RE".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "deny-all".into(),
                    action: "discard".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "protect-RE-v6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "deny-all".into(),
                    action: "discard".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "egress-v4".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "classify".into(),
                    action: "accept".into(),
                    forwarding_class: "bandwidth-10mb".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "egress-v6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "classify".into(),
                    action: "accept".into(),
                    forwarding_class: "bandwidth-10mb".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    ..Default::default()
                }],
            },
        ],
        &[],
        &ifaces,
        "",
        "",
    );
    // v4 filter on ifindex 5
    let result = evaluate_interface_filter(
        &state,
        5,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);

    // No filter on ifindex 6
    let result = evaluate_interface_filter(
        &state,
        6,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);

    let result = evaluate_interface_output_filter(
        &state,
        5,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        1234,
        5201,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.forwarding_class.as_ref(), "bandwidth-10mb");
}

#[test]
fn parse_filter_state_prequalifies_interface_and_lo0_filter_keys() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 7,
        filter_input_v4: "ingress-v4".into(),
        filter_output_v6: "egress-v6".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[
            FirewallFilterSnapshot {
                name: "ingress-v4".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "tx-select".into(),
                    forwarding_class: "best-effort".into(),
                    routing_instance: "sfmix".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "egress-v6".into(),
                family: "inet6".into(),
                terms: vec![],
            },
            FirewallFilterSnapshot {
                name: "protect-re".into(),
                family: "inet".into(),
                terms: vec![],
            },
            FirewallFilterSnapshot {
                name: "protect-re-v6".into(),
                family: "inet6".into(),
                terms: vec![],
            },
        ],
        &[],
        &ifaces,
        "protect-re",
        "protect-re-v6",
    );
    assert_eq!(
        state.iface_filter_v4.get(&7).map(String::as_str),
        Some("inet:ingress-v4")
    );
    assert!(state.iface_filter_v4_affects_tx_selection.contains(&7));
    assert!(state.has_input_tx_selection_v4);
    assert!(state.iface_filter_v4_affects_route_lookup.contains(&7));
    assert!(!state.iface_filter_out_v4_needs_tx_eval.contains(&7));
    assert!(!state.iface_filter_out_v6_needs_tx_eval.contains(&7));
    assert!(!state.has_output_tx_selection_v4);
    assert!(!state.has_output_tx_selection_v6);
    assert_eq!(
        state.iface_filter_out_v6.get(&7).map(String::as_str),
        Some("inet6:egress-v6")
    );
    assert_eq!(state.lo0_filter_v4, "inet:protect-re");
    assert_eq!(state.lo0_filter_v6, "inet6:protect-re-v6");
}

#[test]
fn accept_only_output_filter_does_not_need_tx_eval() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 7,
        filter_output_v4: "wan-allow".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "wan-allow".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "allow".into(),
                action: "accept".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["5201".into()],
                ..Default::default()
            }],
        }],
        &[],
        &ifaces,
        "",
        "",
    );

    assert!(!interface_output_filter_needs_tx_eval(&state, 7, false));
    assert!(!filter_state_has_output_tx_selection(&state, false));
}

#[test]
fn interface_filter_routing_instance_counted_returns_matching_override() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 11,
        filter_input_v6: "sfmix-pbr".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "sfmix-pbr".into(),
            family: "inet6".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "match-iperf".into(),
                    action: "accept".into(),
                    count: "iperf-v6".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    routing_instance: "sfmix".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "default".into(),
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
        &ifaces,
        "",
        "",
    );

    assert!(interface_filter_affects_route_lookup(&state, 11, true));
    let routing_instance = evaluate_interface_filter_routing_instance_counted(
        &state,
        11,
        true,
        IpAddr::V6("2001:db8::10".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        12345,
        5201,
        0,
        TermMatchExtra::default(),
        1500,
    );
    assert_eq!(routing_instance, Some("sfmix"));
    let filter = state.iface_filter_v6_fast.get(&11).expect("input filter");
    assert_eq!(filter.terms[0].counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(filter.terms[0].counter.bytes.load(Ordering::Relaxed), 1500);
}

#[test]
fn interface_output_filter_counted_records_term_hits() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 7,
        filter_output_v6: "bandwidth-output".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "bandwidth-output".into(),
            family: "inet6".into(),
            terms: vec![FirewallTermSnapshot {
                name: "iperf-a".into(),
                action: "accept".into(),
                forwarding_class: "iperf-a".into(),
                count: "iperf-a-v6".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["5201".into()],
                ..Default::default()
            }],
        }],
        &[],
        &ifaces,
        "",
        "",
    );
    let result = evaluate_interface_output_filter_counted(
        &state,
        7,
        true,
        IpAddr::V6("2001:db8::10".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1514,
    );
    assert_eq!(result.forwarding_class.as_ref(), "iperf-a");
    let filter = state
        .filters
        .get("inet6:bandwidth-output")
        .expect("inet6 output filter");
    let term = filter.terms.first().expect("first term");
    assert_eq!(term.counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 1514);
}

#[test]
fn interface_output_filter_without_count_does_not_record_term_hits() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 7,
        filter_output_v6: "bandwidth-output".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "bandwidth-output".into(),
            family: "inet6".into(),
            terms: vec![FirewallTermSnapshot {
                name: "iperf-a".into(),
                action: "accept".into(),
                forwarding_class: "iperf-a".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["5201".into()],
                ..Default::default()
            }],
        }],
        &[],
        &ifaces,
        "",
        "",
    );
    let result = evaluate_interface_output_filter_counted(
        &state,
        7,
        true,
        IpAddr::V6("2001:db8::10".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1514,
    );
    assert_eq!(result.forwarding_class.as_ref(), "iperf-a");
    let filter = state
        .filters
        .get("inet6:bandwidth-output")
        .expect("inet6 output filter");
    let term = filter.terms.first().expect("first term");
    assert_eq!(term.counter.packets.load(Ordering::Relaxed), 0);
    assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 0);
}

#[test]
fn lo0_filter_evaluation() {
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "protect-RE".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "allow-ssh".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["22".into()],
                    action: "accept".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "deny-rest".into(),
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
        &[],
        "protect-RE",
        "",
    );
    // SSH should pass lo0 filter
    let result = evaluate_lo0_filter(
        &state,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        12345,
        22,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);

    // HTTP should be denied by lo0 filter
    let result = evaluate_lo0_filter(
        &state,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        12345,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);
}

#[test]
fn dscp_match_in_term() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "dscp-filter".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "match-ef".into(),
                    dscp_values: vec![46],
                    action: "accept".into(),
                    dscp_rewrite: None,
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "deny-rest".into(),
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    // DSCP 46 (EF) matches
    let result = evaluate_filter(
        &state,
        "inet:dscp-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        1234,
        5060,
        46,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);

    // DSCP 0 doesn't match first term, falls through to deny
    let result = evaluate_filter(
        &state,
        "inet:dscp-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        1234,
        5060,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);
}

#[test]
fn input_dscp_filter_families_changed_detects_same_ifindex_content_change() {
    let iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        filter_input_v4: "dscp-filter".into(),
        ..Default::default()
    };
    let old = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "dscp-filter".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "dscp-term".into(),
                dscp_values: vec![0],
                action: "accept".into(),
                ..Default::default()
            }],
        }],
        std::slice::from_ref(&iface),
    );
    let new = make_filter_state_with_interfaces(
        &[FirewallFilterSnapshot {
            name: "dscp-filter".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "dscp-term".into(),
                dscp_values: vec![46],
                action: "discard".into(),
                log: true,
                ..Default::default()
            }],
        }],
        &[iface],
    );

    assert_eq!(
        input_dscp_filter_families_changed(&old, &new),
        (true, false)
    );
}

#[test]
fn input_dscp_filter_families_changed_ignores_unchanged_filter() {
    let iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        filter_input_v4: "dscp-filter".into(),
        ..Default::default()
    };
    let filter = FirewallFilterSnapshot {
        name: "dscp-filter".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "dscp-term".into(),
            dscp_values: vec![46],
            action: "discard".into(),
            log: true,
            ..Default::default()
        }],
    };
    let old = make_filter_state_with_interfaces(
        std::slice::from_ref(&filter),
        std::slice::from_ref(&iface),
    );
    let new = make_filter_state_with_interfaces(&[filter], &[iface]);

    assert_eq!(
        input_dscp_filter_families_changed(&old, &new),
        (false, false)
    );
}

#[test]
fn input_dscp_filter_families_changed_ignores_positional_filter_id_change() {
    let iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        filter_input_v4: "dscp-filter".into(),
        ..Default::default()
    };
    let unrelated = FirewallFilterSnapshot {
        name: "unrelated".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "accept".into(),
            action: "accept".into(),
            ..Default::default()
        }],
    };
    let dscp_filter = FirewallFilterSnapshot {
        name: "dscp-filter".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "dscp-term".into(),
            dscp_values: vec![46],
            action: "discard".into(),
            log: true,
            ..Default::default()
        }],
    };
    let old = make_filter_state_with_interfaces(
        &[unrelated.clone(), dscp_filter.clone()],
        std::slice::from_ref(&iface),
    );
    let new = make_filter_state_with_interfaces(&[dscp_filter, unrelated], &[iface]);

    assert_ne!(
        old.iface_filter_v4_fast.get(&10).unwrap().id,
        new.iface_filter_v4_fast.get(&10).unwrap().id,
        "test setup must shift the compiler-positional filter id"
    );
    assert_eq!(
        input_dscp_filter_families_changed(&old, &new),
        (false, false)
    );
}

#[test]
fn input_dscp_filter_families_changed_detects_three_color_shape_change() {
    let iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        filter_input_v4: "dscp-filter".into(),
        ..Default::default()
    };
    let filters = [FirewallFilterSnapshot {
        name: "dscp-filter".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "dscp-term".into(),
            dscp_values: vec![46],
            action: "accept".into(),
            policer: "stable-pol".into(),
            ..Default::default()
        }],
    }];
    let original = [ThreeColorPolicerSnapshot {
        name: "stable-pol".into(),
        mode: "single-rate".into(),
        color_blind: true,
        committed_rate_bytes_per_sec: 1,
        committed_burst_bytes: 100,
        peak_or_excess_burst_bytes: 50,
        then_action: "discard".into(),
        ..Default::default()
    }];
    let changed = [ThreeColorPolicerSnapshot {
        committed_burst_bytes: 200,
        ..original[0].clone()
    }];

    let old = parse_filter_state_with_three_color(
        &filters,
        &[],
        &original,
        std::slice::from_ref(&iface),
        "",
        "",
    );
    let new = parse_filter_state_with_three_color_preserving(
        &filters,
        &[],
        &changed,
        &[iface],
        "",
        "",
        Some(&old),
    );

    assert!(
        !std::sync::Arc::ptr_eq(
            old.iface_filter_v4_fast.get(&10).unwrap().terms[0]
                .three_color_policer
                .as_ref()
                .unwrap(),
            new.iface_filter_v4_fast.get(&10).unwrap().terms[0]
                .three_color_policer
                .as_ref()
                .unwrap(),
        ),
        "test setup must create a new runtime for the changed policer shape"
    );
    assert_eq!(
        input_dscp_filter_families_changed(&old, &new),
        (true, false)
    );
}

// AC2 coverage for #1546: add/remove of a DSCP-sensitive interface filter
// must invalidate the affected family. The same_ifindex/positional/three-color
// tests above cover the other three AC2 scenarios; these two close the gap.

#[test]
fn input_dscp_filter_families_changed_detects_filter_added_to_interface() {
    let iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        filter_input_v4: "dscp-filter".into(),
        ..Default::default()
    };
    let filter = FirewallFilterSnapshot {
        name: "dscp-filter".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "dscp-term".into(),
            dscp_values: vec![46],
            action: "discard".into(),
            log: true,
            ..Default::default()
        }],
    };

    // `old` has no DSCP-sensitive filter bound to ifindex 10.
    let bare_iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        ..Default::default()
    };
    let old = make_filter_state_with_interfaces(&[], std::slice::from_ref(&bare_iface));
    // `new` adds the DSCP-sensitive filter on the same interface — must trigger v4 family change.
    let new = make_filter_state_with_interfaces(&[filter], &[iface]);

    assert_eq!(
        input_dscp_filter_families_changed(&old, &new),
        (true, false)
    );
}

#[test]
fn input_dscp_filter_families_changed_detects_filter_removed_from_interface() {
    let iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        filter_input_v4: "dscp-filter".into(),
        ..Default::default()
    };
    let filter = FirewallFilterSnapshot {
        name: "dscp-filter".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "dscp-term".into(),
            dscp_values: vec![46],
            action: "discard".into(),
            log: true,
            ..Default::default()
        }],
    };

    // `old` has the DSCP-sensitive filter bound to ifindex 10.
    let old = make_filter_state_with_interfaces(
        std::slice::from_ref(&filter),
        std::slice::from_ref(&iface),
    );
    // `new` removes the filter binding — must trigger v4 family change.
    let bare_iface = crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 10,
        ..Default::default()
    };
    let new = make_filter_state_with_interfaces(&[], &[bare_iface]);

    assert_eq!(
        input_dscp_filter_families_changed(&old, &new),
        (true, false)
    );
}

// ============================================================
// #1725 — engine evaluation coverage gaps
//
// filter/tests.rs already covers most of eval.rs / tx_selection.rs /
// cache_sensitive.rs. The tests below fill the nine genuinely-uncovered
// behaviors identified in docs/pr/1725-filter-engine-tests/plan.md:
// Reject via the plain evaluate_filter path; missing-filter / empty-filter
// default; address-family mismatch default; IPv6 baseline evaluate / lo0 /
// interface-input paths; baseline counter increment; the non-routing
// (PBR-reject) variant; the FilterState-keyed tx_selection wrappers; the
// thin accessor predicates; and cached-vs-runtime baseline parity.
// ============================================================

// --- Gap 1: FilterAction::Reject through the plain evaluate_filter path ---
#[test]
fn evaluate_filter_returns_reject_action() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "reject-filter".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "reject-telnet".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["23".into()],
                action: "reject".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:reject-filter",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        23,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Reject);
}

// --- Gap 2: missing filter key + empty filter both fall through to Accept ---
#[test]
fn evaluate_filter_missing_key_returns_default_accept() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "present".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny-all".into(),
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    // A key that was never compiled must return the implicit Accept default,
    // never panic and never reach into an unrelated filter.
    let result = evaluate_filter(
        &state,
        "inet:does-not-exist",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Accept);
    assert_eq!(result, FilterResult::default());
}

#[test]
fn evaluate_filter_empty_filter_returns_default_accept() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "empty".into(),
            family: "inet".into(),
            terms: vec![],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:empty",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    // A compiled-but-empty filter must fall through to the full default,
    // distinguishable from the missing-key path: the filter exists with zero
    // terms, so a compiler bug that dropped empty filters would also surface
    // here.
    assert_eq!(result, FilterResult::default());
    let filter = state
        .filters
        .get("inet:empty")
        .expect("empty filter compiled");
    assert!(filter.terms.is_empty());
}

// --- Gap 3: address-family mismatch (V4 src + V6 dst) takes the default arm ---
#[test]
fn evaluate_filter_mixed_address_family_returns_default_accept() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "deny-all".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny".into(),
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    // A V4 source with a V6 destination hits the `_ => default` arm in
    // evaluate_filter_ref_counted rather than matching the discard term.
    let result = evaluate_filter(
        &state,
        "inet:deny-all",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V6("2001:db8::2".parse().unwrap()),
        PROTO_TCP,
        1234,
        80,
        0,
        TermMatchExtra::default(),
    );
    // The default arm must produce the full default result, not just an Accept
    // action with leftover rewrite/routing/forwarding-class fields.
    assert_eq!(result, FilterResult::default());
}

// --- Gap 4: IPv6 baseline evaluate_filter / lo0 / interface-input paths ---
#[test]
fn evaluate_filter_ipv6_matches_term() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "v6-filter".into(),
            family: "inet6".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "deny-from-doc".into(),
                    source_addresses: vec!["2001:db8::/32".into()],
                    action: "discard".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "allow-rest".into(),
                    action: "accept".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
    );
    // In-prefix source matches the discard term.
    let denied = evaluate_filter(
        &state,
        "inet6:v6-filter",
        IpAddr::V6("2001:db8::100".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        40000,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(denied.action, FilterAction::Discard);
    // Out-of-prefix source falls through to the accept term.
    let allowed = evaluate_filter(
        &state,
        "inet6:v6-filter",
        IpAddr::V6("2001:db9::1".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        40000,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(allowed.action, FilterAction::Accept);
}

#[test]
fn evaluate_lo0_filter_ipv6_path() {
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "protect-RE-v6".into(),
            family: "inet6".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "allow-ssh".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["22".into()],
                    action: "accept".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "deny-rest".into(),
                    action: "discard".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
        &[],
        "",
        "protect-RE-v6",
    );
    let accepted = evaluate_lo0_filter(
        &state,
        true,
        IpAddr::V6("2001:db8::1".parse().unwrap()),
        IpAddr::V6("2001:db8::2".parse().unwrap()),
        PROTO_TCP,
        40000,
        22,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(accepted.action, FilterAction::Accept);
    let discarded = evaluate_lo0_filter(
        &state,
        true,
        IpAddr::V6("2001:db8::1".parse().unwrap()),
        IpAddr::V6("2001:db8::2".parse().unwrap()),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(discarded.action, FilterAction::Discard);
}

#[test]
fn evaluate_interface_filter_ipv6_input_path() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 9,
        filter_input_v6: "edge-in-v6".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "edge-in-v6".into(),
            family: "inet6".into(),
            terms: vec![FirewallTermSnapshot {
                name: "deny-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
        &ifaces,
        "",
        "",
    );
    let result = evaluate_interface_filter(
        &state,
        9,
        true,
        IpAddr::V6("2001:db8::10".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        49152,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(result.action, FilterAction::Discard);
}

// --- Gap 5: baseline evaluate_filter_counted hit-counter increment (v4 + v6) ---
#[test]
fn evaluate_filter_counted_increments_term_counter() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "counted".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "count-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["80".into()],
                action: "accept".into(),
                count: "web-hits".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter_counted(
        &state,
        "inet:counted",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
        1400,
    );
    assert_eq!(result.action, FilterAction::Accept);
    let filter = state.filters.get("inet:counted").expect("counted filter");
    let term = filter.terms.first().expect("first term");
    assert_eq!(term.counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 1400);

    // A non-matching packet (wrong port) must not bump the counter.
    let miss = evaluate_filter_counted(
        &state,
        "inet:counted",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        443,
        0,
        TermMatchExtra::default(),
        1400,
    );
    assert_eq!(miss.action, FilterAction::Accept);
    assert_eq!(term.counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 1400);
}

#[test]
fn evaluate_filter_counted_increments_term_counter_ipv6() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "counted6".into(),
            family: "inet6".into(),
            terms: vec![FirewallTermSnapshot {
                name: "count-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["80".into()],
                action: "accept".into(),
                count: "web-hits-v6".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter_counted(
        &state,
        "inet6:counted6",
        IpAddr::V6("2001:db8::1".parse().unwrap()),
        IpAddr::V6("2001:db8::2".parse().unwrap()),
        PROTO_TCP,
        40000,
        80,
        0,
        TermMatchExtra::default(),
        1500,
    );
    assert_eq!(result.action, FilterAction::Accept);
    let filter = state.filters.get("inet6:counted6").expect("counted filter");
    let term = filter.terms.first().expect("first term");
    assert_eq!(term.counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 1500);
}

// --- Gap 6: evaluate_interface_filter_non_routing_counted PBR-reject behavior ---
#[test]
fn interface_filter_non_routing_counted_defers_pbr_term() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 12,
        filter_input_v4: "mixed-pbr".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "mixed-pbr".into(),
            family: "inet".into(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "route-to-blue".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    action: "accept".into(),
                    count: "pbr-hits".into(),
                    routing_instance: "blue".into(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "plain-deny".into(),
                    protocols: vec!["udp".into()],
                    destination_ports: vec!["53".into()],
                    action: "discard".into(),
                    count: "dns-hits".into(),
                    ..Default::default()
                },
            ],
        }],
        &[],
        &ifaces,
        "",
        "",
    );

    // A packet that matches the routing-instance term must short-circuit to
    // the default (route-lookup wins) and must NOT increment that term's
    // counter — the non-routing evaluator returns before recording.
    let pbr = evaluate_interface_filter_non_routing_counted(
        &state,
        12,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1400,
    );
    assert_eq!(pbr.action, FilterAction::Accept);
    assert!(pbr.routing_instance.is_empty());
    let filter = state.iface_filter_v4_fast.get(&12).expect("input filter");
    assert_eq!(filter.terms[0].counter.packets.load(Ordering::Relaxed), 0);

    // A packet matching the plain (non-routing) term gets its action and a
    // counter bump as normal.
    let plain = evaluate_interface_filter_non_routing_counted(
        &state,
        12,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        40000,
        53,
        0,
        TermMatchExtra::default(),
        500,
    );
    assert_eq!(plain.action, FilterAction::Discard);
    assert_eq!(filter.terms[1].counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(filter.terms[1].counter.bytes.load(Ordering::Relaxed), 500);
}

// --- Gap 7: FilterState-keyed tx_selection dispatch wrappers ---
#[test]
fn interface_filter_tx_selection_wrappers_dispatch_and_default() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 7,
        filter_input_v4: "tx-in".into(),
        filter_output_v4: "tx-out".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[
            FirewallFilterSnapshot {
                name: "tx-in".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "classify-in".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5201".into()],
                    action: "accept".into(),
                    forwarding_class: "iperf-a".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "tx-out".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "classify-out".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["5202".into()],
                    action: "accept".into(),
                    forwarding_class: "iperf-b".into(),
                    ..Default::default()
                }],
            },
        ],
        &[],
        &ifaces,
        "",
        "",
    );

    let input = evaluate_interface_filter_tx_selection_counted(
        &state,
        7,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1400,
    );
    assert_eq!(input.action, FilterAction::Accept);
    assert_eq!(input.forwarding_class, Some("iperf-a"));

    let output = evaluate_interface_output_filter_tx_selection_counted(
        &state,
        7,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        5202,
        0,
        TermMatchExtra::default(),
        1400,
    );
    assert_eq!(output.action, FilterAction::Accept);
    assert_eq!(output.forwarding_class, Some("iperf-b"));

    // No filter bound to an unrelated ifindex returns the default.
    let none_in = evaluate_interface_filter_tx_selection_counted(
        &state,
        99,
        false,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        1400,
    );
    assert_eq!(none_in.action, FilterAction::Accept);
    assert_eq!(none_in.forwarding_class, None);
}

// --- Gap 8: thin accessor predicates (grouped, table-driven) ---
#[test]
fn thin_accessor_predicates() {
    // Two separate input ifindices so the TX-selection and DSCP-match
    // accessors are cross-checked: ifindex 21 is TX-selection-only (a
    // forwarding-class term, no DSCP match), ifindex 22 is DSCP-only (a DSCP
    // match, no forwarding class). An accessor that consulted the wrong set
    // (aliasing bug) would flip on one of the cross-negative assertions
    // below. ifindex 23 carries a DSCP-match output filter.
    let ifaces = vec![
        crate::InterfaceSnapshot {
            name: "reth1.0".into(),
            ifindex: 21,
            filter_input_v4: "tx-only-in".into(),
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "reth1.1".into(),
            ifindex: 22,
            filter_input_v4: "dscp-only-in".into(),
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "reth1.2".into(),
            ifindex: 23,
            filter_output_v4: "dscp-out".into(),
            ..Default::default()
        },
    ];
    let state = parse_filter_state(
        &[
            FirewallFilterSnapshot {
                name: "tx-only-in".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "classify".into(),
                    protocols: vec!["tcp".into()],
                    action: "accept".into(),
                    forwarding_class: "iperf-a".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "dscp-only-in".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "match-ef".into(),
                    dscp_values: vec![46],
                    action: "accept".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "dscp-out".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "match-ef".into(),
                    dscp_values: vec![46],
                    action: "accept".into(),
                    ..Default::default()
                }],
            },
        ],
        &[],
        &ifaces,
        "",
        "",
    );

    // TX-selection accessor reads the TX-selection set, NOT the DSCP set:
    // true on the TX-only ifindex, false on the DSCP-only ifindex.
    assert!(interface_filter_affects_tx_selection(&state, 21, false));
    assert!(!interface_filter_affects_tx_selection(&state, 22, false));
    assert!(!interface_filter_affects_tx_selection(&state, 21, true));
    assert!(filter_state_has_input_tx_selection(&state, false));
    assert!(!filter_state_has_input_tx_selection(&state, true));

    // DSCP-match accessor reads the DSCP set, NOT the TX-selection set:
    // true on the DSCP-only ifindex, false on the TX-only ifindex.
    assert!(interface_input_filter_has_dscp_match(&state, 22, false));
    assert!(!interface_input_filter_has_dscp_match(&state, 21, false));
    assert!(!interface_input_filter_has_dscp_match(&state, 22, true));
    assert!(interface_output_filter_has_dscp_match(&state, 23, false));
    assert!(!interface_output_filter_has_dscp_match(&state, 23, true));
    // No filter bound to an unrelated ifindex.
    assert!(!interface_input_filter_has_dscp_match(&state, 99, false));
    assert!(!interface_filter_affects_tx_selection(&state, 99, false));
}

// --- Gap 9: cached-vs-runtime baseline parity for a plain (no-policer) term ---
#[test]
fn cached_and_runtime_tx_selection_agree_on_plain_term() {
    let ifaces = vec![crate::InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 30,
        filter_input_v4: "parity".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "parity".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "classify".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["5201".into()],
                action: "accept".into(),
                forwarding_class: "iperf-a".into(),
                dscp_rewrite: Some(46),
                log: true,
                ..Default::default()
            }],
        }],
        &[],
        &ifaces,
        "",
        "",
    );
    let filter = state.iface_filter_v4_fast.get(&30).expect("input filter");
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let runtime = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        src,
        dst,
        PROTO_TCP,
        40000,
        5201,
        0,
        TermMatchExtra::default(),
        0,
        1,
    );
    let cached =
        evaluate_filter_ref_tx_selection_cached(filter, src, dst, PROTO_TCP, 40000, 5201, 0);

    // A term with no three-color policer must yield identical action,
    // forwarding-class, DSCP rewrite, and log-match identity on both paths.
    assert_eq!(runtime.action, cached.action);
    assert_eq!(runtime.action, FilterAction::Accept);
    assert_eq!(runtime.forwarding_class, cached.forwarding_class.as_deref());
    assert_eq!(runtime.forwarding_class, Some("iperf-a"));
    assert_eq!(runtime.dscp_rewrite, cached.dscp_rewrite);
    assert_eq!(runtime.dscp_rewrite, Some(46));
    assert_eq!(runtime.log_match, cached.log_match);
    assert!(runtime.log_match.is_some());
    assert!(!runtime.policer_drop);
}

// ===========================================================================
// #2362 per-packet L4 match conditions (tcp-flags / is-fragment / icmp-type /
// icmp-code). These were parsed by the Go compiler but dropped on the wire and
// absent from the Rust matcher, so a term matched broader than authored. The
// tests below exercise the runtime match predicate directly: a packet matching
// the condition triggers the term action; one that does not (wrong flags / not
// a fragment / wrong icmp-type / wrong protocol) falls through to the default.
// ===========================================================================

// Build a one-term filter carrying explicit per-packet conditions, then a
// trailing accept-all term so a non-match is observably Accept.
fn per_packet_filter(
    family: &str,
    proto: &str,
    tcp_flags: Option<u8>,
    is_fragment: bool,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
) -> Vec<FirewallFilterSnapshot> {
    vec![FirewallFilterSnapshot {
        name: "pp".into(),
        family: family.into(),
        terms: vec![
            FirewallTermSnapshot {
                name: "match".into(),
                protocols: if proto.is_empty() {
                    vec![]
                } else {
                    vec![proto.into()]
                },
                action: "discard".into(),
                tcp_flags,
                is_fragment,
                icmp_type,
                icmp_code,
                ..Default::default()
            },
            FirewallTermSnapshot {
                name: "rest".into(),
                action: "accept".into(),
                ..Default::default()
            },
        ],
    }]
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn extra_tcp(flags: u8) -> TermMatchExtra {
    TermMatchExtra {
        tcp_flags: flags,
        // A real (first/atomic) TCP segment has an L4 header — the matcher
        // gates tcp-flags on l4_present (#2362 fold A).
        l4_present: true,
        ..Default::default()
    }
}

#[test]
fn tcp_flags_term_matches_syn_only() {
    // tcp-flags syn then discard: SYN(0x02) is dropped, a pure ACK forwards.
    let state = make_filter_state(
        &per_packet_filter("inet", "tcp", Some(0x02), false, None, None),
        &[],
    );
    let syn = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        22,
        0,
        extra_tcp(0x02),
    );
    assert_eq!(
        syn.action,
        FilterAction::Discard,
        "SYN must match tcp-flags syn"
    );
    let ack = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        22,
        0,
        extra_tcp(0x10),
    );
    assert_eq!(
        ack.action,
        FilterAction::Accept,
        "pure ACK must NOT match tcp-flags syn"
    );
    // SYN+ACK has SYN set -> still matches (Junos `tcp-flags syn` semantics).
    let synack = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        22,
        0,
        extra_tcp(0x12),
    );
    assert_eq!(
        synack.action,
        FilterAction::Discard,
        "SYN+ACK has SYN set -> matches"
    );
}

#[test]
fn tcp_flags_term_requires_all_listed_flags() {
    // tcp-flags (syn & ack) folded to mask 0x12: only a segment with BOTH set matches.
    let state = make_filter_state(
        &per_packet_filter("inet", "tcp", Some(0x12), false, None, None),
        &[],
    );
    let synack = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        extra_tcp(0x12),
    );
    assert_eq!(synack.action, FilterAction::Discard);
    let syn = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        extra_tcp(0x02),
    );
    assert_eq!(
        syn.action,
        FilterAction::Accept,
        "SYN alone lacks ACK -> no match"
    );
}

#[test]
fn tcp_flags_term_does_not_match_non_tcp() {
    // A tcp-flags term must never match a UDP packet even if the (meaningless)
    // tcp_flags byte happens to carry the bits.
    let state = make_filter_state(
        &per_packet_filter("inet", "", Some(0x02), false, None, None),
        &[],
    );
    let udp = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_UDP,
        1000,
        53,
        0,
        extra_tcp(0x02),
    );
    assert_eq!(
        udp.action,
        FilterAction::Accept,
        "UDP must not match a tcp-flags term"
    );
}

#[test]
fn is_fragment_term_spares_non_fragments() {
    let state = make_filter_state(&per_packet_filter("inet", "", None, true, None, None), &[]);
    let frag = TermMatchExtra {
        is_fragment: true,
        ..Default::default()
    };
    let dropped = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_UDP,
        1000,
        53,
        0,
        frag,
    );
    assert_eq!(
        dropped.action,
        FilterAction::Discard,
        "a fragment must match is-fragment"
    );
    let whole = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_UDP,
        1000,
        53,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        whole.action,
        FilterAction::Accept,
        "a non-fragment must NOT match is-fragment"
    );
}

#[test]
fn icmp_type_term_matches_only_that_type_v4() {
    // icmp-type 8 (echo-request) then discard must NOT collapse to drop-all-ICMP.
    let state = make_filter_state(
        &per_packet_filter("inet", "icmp", None, false, Some(8), None),
        &[],
    );
    let echo = TermMatchExtra {
        icmp_type: 8,
        l4_present: true,
        ..Default::default()
    };
    let drop = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        echo,
    );
    assert_eq!(
        drop.action,
        FilterAction::Discard,
        "echo-request must match icmp-type 8"
    );
    let reply = TermMatchExtra {
        icmp_type: 0,
        l4_present: true,
        ..Default::default()
    };
    let pass = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        reply,
    );
    assert_eq!(
        pass.action,
        FilterAction::Accept,
        "echo-reply (type 0) must NOT match icmp-type 8"
    );
}

#[test]
fn icmp_type_term_matches_icmpv6() {
    // icmp-type 128 (ICMPv6 echo-request) on an inet6 filter.
    let state = make_filter_state(
        &per_packet_filter("inet6", "icmpv6", None, false, Some(128), None),
        &[],
    );
    let v6 = |s: &str| IpAddr::V6(s.parse::<Ipv6Addr>().unwrap());
    let echo = TermMatchExtra {
        icmp_type: 128,
        l4_present: true,
        ..Default::default()
    };
    let drop = evaluate_filter(
        &state,
        "inet6:pp",
        v6("2001:db8::1"),
        v6("2001:db8::2"),
        PROTO_ICMPV6,
        0,
        0,
        0,
        echo,
    );
    assert_eq!(drop.action, FilterAction::Discard);
    let na = TermMatchExtra {
        icmp_type: 136,
        l4_present: true,
        ..Default::default()
    };
    let pass = evaluate_filter(
        &state,
        "inet6:pp",
        v6("2001:db8::1"),
        v6("2001:db8::2"),
        PROTO_ICMPV6,
        0,
        0,
        0,
        na,
    );
    assert_eq!(
        pass.action,
        FilterAction::Accept,
        "neighbor-advert (136) must NOT match icmp-type 128"
    );
}

#[test]
fn icmp_code_term_narrows_within_type() {
    // icmp-type 3 code 4 (frag-needed) — code 0 must not match.
    let state = make_filter_state(
        &per_packet_filter("inet", "icmp", None, false, Some(3), Some(4)),
        &[],
    );
    let frag_needed = TermMatchExtra {
        icmp_type: 3,
        icmp_code: 4,
        l4_present: true,
        ..Default::default()
    };
    let drop = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        frag_needed,
    );
    assert_eq!(drop.action, FilterAction::Discard);
    let net_unreach = TermMatchExtra {
        icmp_type: 3,
        icmp_code: 0,
        l4_present: true,
        ..Default::default()
    };
    let pass = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        net_unreach,
    );
    assert_eq!(
        pass.action,
        FilterAction::Accept,
        "code 0 must NOT match icmp-code 4"
    );
}

#[test]
fn icmp_term_does_not_match_non_icmp() {
    let state = make_filter_state(
        &per_packet_filter("inet", "", None, false, Some(8), None),
        &[],
    );
    // A TCP packet whose byte happens to equal 8 must not match an icmp-type term.
    // l4_present: true so this proves the PROTOCOL gate, not the l4-absence gate.
    let tcp = TermMatchExtra {
        tcp_flags: 0x02,
        icmp_type: 8,
        l4_present: true,
        ..Default::default()
    };
    let pass = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        80,
        0,
        tcp,
    );
    assert_eq!(
        pass.action,
        FilterAction::Accept,
        "TCP must not match an icmp-type term"
    );
}

#[test]
fn per_packet_match_action_applies_with_count() {
    // The term action AND its count side-effect apply on a per-packet match.
    let filters = vec![FirewallFilterSnapshot {
        name: "c".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "syn".into(),
            protocols: vec!["tcp".into()],
            action: "discard".into(),
            count: "syns".into(),
            tcp_flags: Some(0x02),
            ..Default::default()
        }],
    }];
    let state = make_filter_state(&filters, &[]);
    let r = evaluate_filter_counted(
        &state,
        "inet:c",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        22,
        0,
        extra_tcp(0x02),
        1500,
    );
    assert_eq!(r.action, FilterAction::Discard);
    let filter = state.filters.get("inet:c").expect("filter");
    assert_eq!(filter.terms[0].counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(filter.terms[0].counter.bytes.load(Ordering::Relaxed), 1500);
    // A non-matching ACK must NOT bump the counter.
    let _ = evaluate_filter_counted(
        &state,
        "inet:c",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        1000,
        22,
        0,
        extra_tcp(0x10),
        1500,
    );
    assert_eq!(filter.terms[0].counter.packets.load(Ordering::Relaxed), 1);
}

#[test]
fn per_packet_match_marks_filter_cache_sensitive() {
    // A filter carrying any per-packet L4 match term must be flagged so the
    // flow-cache declines (path (b), #1431/#2362) and the on-session re-eval
    // gate fires.
    let filters = per_packet_filter("inet", "tcp", Some(0x02), false, None, None);
    let interfaces = [crate::InterfaceSnapshot {
        ifindex: 7,
        filter_input_v4: "pp".into(),
        ..Default::default()
    }];
    let state = parse_filter_state(&filters, &[], &interfaces, "", "");
    assert!(
        state.iface_filter_v4_has_per_packet_l4_match.contains(&7),
        "interface input filter with a tcp-flags term must be marked per-packet-L4 cache-sensitive"
    );
    assert!(interface_input_filter_has_per_packet_l4_match(
        &state, 7, false
    ));
    let filter = state.iface_filter_v4_fast.get(&7).expect("filter");
    assert!(filter.has_per_packet_l4_match_terms);
}

// #2362 / #1961-class wire round-trip: a Go-encoded FirewallTermSnapshot with
// the new fields must decode into the Rust DTO with the same values. Guards the
// one-sided-field decode-failure (whole-snapshot abort -> no transit) class.
#[test]
fn firewall_term_snapshot_per_packet_fields_round_trip() {
    let json = r#"{
        "name": "syn-only",
        "protocols": ["tcp"],
        "action": "discard",
        "tcp_flags": 2,
        "is_fragment": true,
        "icmp_type": 8,
        "icmp_code": 0
    }"#;
    let term: FirewallTermSnapshot = serde_json::from_str(json).expect("decode");
    assert_eq!(term.tcp_flags, Some(2));
    assert!(term.is_fragment);
    assert_eq!(term.icmp_type, Some(8));
    assert_eq!(term.icmp_code, Some(0));
    // Absent fields default to None/false (forward/backward compatibility).
    let minimal: FirewallTermSnapshot =
        serde_json::from_str(r#"{"name":"x","action":"accept"}"#).expect("decode minimal");
    assert_eq!(minimal.tcp_flags, None);
    assert!(!minimal.is_fragment);
    assert_eq!(minimal.icmp_type, None);
    assert_eq!(minimal.icmp_code, None);
}

// #2362 fold A (Copilot): the L4-present gate. Forcing the icmp byte to 0 for a
// non-first fragment is NOT sufficient, because 0 is a valid icmp-type
// (echo-reply) and a valid icmp-code — a value-only check would still match
// `from { icmp-type 0 }` / `from { icmp-code 0 }`. The matcher MUST key off
// extra.l4_present (false for a non-first fragment) so those terms fail closed,
// while is-fragment (L3-derived) STILL matches. These fail if the gate reverts
// to the value-0 sentinel.
#[test]
fn non_first_fragment_does_not_match_icmp_type_zero() {
    let state = make_filter_state(
        &per_packet_filter("inet", "icmp", None, false, Some(0), None),
        &[],
    );
    // What term_match_extra_from_frame produces for a non-first ICMP fragment:
    // l4_present false, icmp bytes forced 0, is_fragment true.
    let frag = TermMatchExtra {
        l4_present: false,
        icmp_type: 0,
        is_fragment: true,
        ..Default::default()
    };
    let r = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        frag,
    );
    assert_eq!(
        r.action,
        FilterAction::Accept,
        "a non-first fragment (no L4 header) must NOT match `icmp-type 0` (#2362 fold A)"
    );
    // Anti-over-gate: a real echo-reply (type 0, l4_present) DOES match.
    let echo_reply = TermMatchExtra {
        l4_present: true,
        icmp_type: 0,
        ..Default::default()
    };
    let r2 = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        echo_reply,
    );
    assert_eq!(
        r2.action,
        FilterAction::Discard,
        "a real echo-reply (icmp-type 0, L4 present) MUST match `icmp-type 0`"
    );
}

#[test]
fn non_first_fragment_does_not_match_icmp_code_zero() {
    let state = make_filter_state(
        &per_packet_filter("inet", "icmp", None, false, None, Some(0)),
        &[],
    );
    let frag = TermMatchExtra {
        l4_present: false,
        icmp_code: 0,
        is_fragment: true,
        ..Default::default()
    };
    let r = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        frag,
    );
    assert_eq!(
        r.action,
        FilterAction::Accept,
        "a non-first fragment must NOT match `icmp-code 0` (#2362 fold A)"
    );
    let real = TermMatchExtra {
        l4_present: true,
        icmp_code: 0,
        ..Default::default()
    };
    let r2 = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        real,
    );
    assert_eq!(
        r2.action,
        FilterAction::Discard,
        "a real ICMP packet with code 0 (L4 present) MUST match `icmp-code 0`"
    );
}

#[test]
fn non_first_fragment_still_matches_is_fragment() {
    // The is-fragment term is L3-derived and NOT gated by l4_present.
    let state = make_filter_state(&per_packet_filter("inet", "", None, true, None, None), &[]);
    let frag = TermMatchExtra {
        l4_present: false,
        is_fragment: true,
        ..Default::default()
    };
    let r = evaluate_filter(
        &state,
        "inet:pp",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_ICMP,
        0,
        0,
        0,
        frag,
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "a non-first fragment IS a fragment — is-fragment must still match (#2362 fold A)"
    );
}

// #2399 (032-16): a snapshot/version-drift term carrying a NON-EMPTY but
// unrecognized action string must fail CLOSED (discard), never silently permit.
// The Go commit gate (validateFilterActionsStrict) rejects an unknown `then`
// token before it can be persisted, so a non-empty unknown action can only
// reach the dataplane via a mixed-version snapshot — and for a firewall filter
// that must deny, not accept. MUST FAIL if parse_term's non-empty arm reverts
// to FilterAction::Accept.
#[test]
fn unknown_nonempty_action_fails_closed_discard() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "drift".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "future-action".into(),
                protocols: vec!["tcp".into()],
                // An action a future/peer version understands but this one does
                // not. Today's code silently treated this as Accept.
                action: "future-permit".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let r = evaluate_filter(
        &state,
        "inet:drift",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        12345,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Discard,
        "an unknown non-empty filter action must fail closed (discard), not accept"
    );
}

// An EMPTY action is the legitimate "no terminating action" case: the term
// carries only modifiers and falls through to the next term. It must remain
// Accept (today's fall-through semantics) so a valid `then count`-only term is
// not turned into a deny. MUST FAIL if the empty-string arm is folded into the
// fail-closed default.
#[test]
fn empty_action_falls_through_to_accept() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "fallthrough".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "count-only".into(),
                protocols: vec!["tcp".into()],
                count: "c1".into(),
                // No terminating action — empty string.
                action: String::new(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let r = evaluate_filter(
        &state,
        "inet:fallthrough",
        v4(10, 0, 0, 1),
        v4(10, 0, 0, 2),
        PROTO_TCP,
        12345,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        r.action,
        FilterAction::Accept,
        "an empty (no terminating) action must keep fall-through accept semantics"
    );
}

// ============================================================
// #2400 (codex 032-18 / 032-19): all-malformed firewall-filter
// addresses/ports must FAIL CLOSED (match nothing), never degrade to
// match-any (fail-open filter broadening). A `discard` term scoped to
// an all-malformed address/port set must NOT become discard-all.
//
// The fail-on-revert pivot: the filter's implicit (no-term-match) action
// is Accept (see evaluate_filter docstring). So a single `discard` term
// scoped to bad addresses/ports yields Accept when the term correctly
// matches NOTHING, and Discard if it wrongly broadens to match-any.
// ============================================================

/// One `discard` term scoped to an all-malformed source-address list. The fix
/// makes the term match nothing -> the packet falls through to implicit Accept.
/// REVERT (empty parsed list -> match-any) makes the term match every packet ->
/// Discard, failing this assert.
#[test]
fn term_2400_all_malformed_source_address_fails_closed_v4() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped-discard".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-bad-src".into(),
                // Every entry is unparseable as an IP/CIDR.
                source_addresses: vec!["not-an-ip".into(), "10.0.0.0/99".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:scoped-discard",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Accept,
        "all-malformed source-address must fail CLOSED (term matches nothing -> \
         implicit accept); a match-any regression would Discard"
    );
}

/// Same for destination-address.
#[test]
fn term_2400_all_malformed_destination_address_fails_closed_v4() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped-discard".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-bad-dst".into(),
                destination_addresses: vec!["garbage".into(), "999.1.2.3".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:scoped-discard",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Accept,
        "all-malformed destination-address must fail CLOSED"
    );
}

/// v6 sibling: all-malformed source-address in an inet6 filter.
#[test]
fn term_2400_all_malformed_source_address_fails_closed_v6() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped-discard6".into(),
            family: "inet6".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-bad-src6".into(),
                source_addresses: vec!["xyzzy".into(), "2001:db8::/200".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet6:scoped-discard6",
        IpAddr::V6("2001:db8::10".parse().unwrap()),
        IpAddr::V6("2001:db8::200".parse().unwrap()),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Accept,
        "all-malformed inet6 source-address must fail CLOSED"
    );
}

/// All-malformed source-port set -> fail closed.
#[test]
fn term_2400_all_malformed_source_port_fails_closed() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped-discard".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-bad-sport".into(),
                // Unparseable port specs: a name not in the table, an out-of-range
                // number, and an inverted range.
                source_ports: vec!["nonsense".into(), "70000".into(), "100-50".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:scoped-discard",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        40000,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Accept,
        "all-malformed source-port must fail CLOSED (term matches nothing); a \
         PortMatcher::Any regression would Discard"
    );
}

/// All-malformed destination-port set -> fail closed.
#[test]
fn term_2400_all_malformed_destination_port_fails_closed() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped-discard".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-bad-dport".into(),
                destination_ports: vec!["bogus".into(), "0".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:scoped-discard",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        40000,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Accept,
        "all-malformed destination-port must fail CLOSED"
    );
}

/// A bare-host match address (no /prefix) scopes correctly: the matching host
/// hits the term, a different host does not (anti-over-restrict + anti-fail-open
/// at once). IpNet::parse rejects a bare IP, so this exercises the bare-IP
/// fallback to /32.
#[test]
fn term_2400_bare_host_source_address_scopes_correctly() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped-discard".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-one-host".into(),
                source_addresses: vec!["203.0.113.7".into()], // bare host, no /32
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    // The configured host is dropped.
    let hit = evaluate_filter(
        &state,
        "inet:scoped-discard",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        hit.action,
        FilterAction::Discard,
        "bare-host source-address must match the configured host (bare-IP /32 fallback)"
    );
    // A different host is NOT dropped (falls through to implicit accept).
    let miss = evaluate_filter(
        &state,
        "inet:scoped-discard",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        miss.action,
        FilterAction::Accept,
        "a non-configured host must NOT match the bare-host-scoped term"
    );
}

/// Anti-over-restrict: a VALID UNSCOPED discard term (no address/port) still
/// matches everything. The constrained flags must not narrow a genuinely
/// unscoped term.
#[test]
fn term_2400_valid_unscoped_term_still_matches_all() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "unscoped".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-all".into(),
                // no source/destination addresses, no ports.
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let result = evaluate_filter(
        &state,
        "inet:unscoped",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        result.action,
        FilterAction::Discard,
        "a valid unscoped term must still match all traffic (no over-restriction)"
    );
}

/// Anti-over-restrict: a VALID SCOPED term matches only its address and port,
/// and falls through (accept) for everything else.
#[test]
fn term_2400_valid_scoped_term_matches_only_its_scope() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "scoped".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-net-port".into(),
                source_addresses: vec!["203.0.113.0/24".into()],
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    // In-scope: matches -> discard.
    let in_scope = evaluate_filter(
        &state,
        "inet:scoped",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(in_scope.action, FilterAction::Discard, "in-scope must match");
    // Wrong port: out of scope -> accept.
    let wrong_port = evaluate_filter(
        &state,
        "inet:scoped",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        80,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        wrong_port.action,
        FilterAction::Accept,
        "a valid scoped term must NOT match a packet outside its port scope"
    );
    // Wrong source: out of scope -> accept.
    let wrong_src = evaluate_filter(
        &state,
        "inet:scoped",
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        wrong_src.action,
        FilterAction::Accept,
        "a valid scoped term must NOT match a packet outside its address scope"
    );
}

/// Composition with #2362 (tcp-flags) and #2399 (action) intact: a term that
/// mixes a VALID scope with a tcp-flags constraint matches only the in-scope
/// SYN packet, and an all-malformed address with the same tcp-flags still fails
/// closed (does not broaden to match-any-SYN).
#[test]
fn term_2400_composes_with_2362_tcp_flags() {
    // Valid scope + tcp-flags syn -> matches the in-scope SYN.
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "syn-scoped".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-syn-from-net".into(),
                source_addresses: vec!["203.0.113.0/24".into()],
                tcp_flags: Some(0x02), // SYN
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let syn_extra = TermMatchExtra {
        tcp_flags: 0x02,
        l4_present: true,
        ..Default::default()
    };
    let in_scope_syn = evaluate_filter(
        &state,
        "inet:syn-scoped",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        syn_extra,
    );
    assert_eq!(
        in_scope_syn.action,
        FilterAction::Discard,
        "valid scope + tcp-flags must still match the in-scope SYN (#2362 intact)"
    );

    // All-malformed address + the same tcp-flags -> fail closed even for a SYN.
    let bad_state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "syn-bad".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-syn-bad-src".into(),
                source_addresses: vec!["not-an-ip".into()],
                tcp_flags: Some(0x02),
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let bad_syn = evaluate_filter(
        &bad_state,
        "inet:syn-bad",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        syn_extra,
    );
    assert_eq!(
        bad_syn.action,
        FilterAction::Accept,
        "all-malformed address + tcp-flags must fail CLOSED, not broaden to match-any-SYN"
    );
}

/// A term mixing one VALID and one malformed address keeps the valid scope
/// (the malformed entry is dropped, the term stays constrained and matches the
/// valid prefix only). This guards against an over-correction that would fail
/// the whole term closed when ANY entry is bad.
#[test]
fn term_2400_partial_malformed_address_keeps_valid_scope() {
    let state = make_filter_state(
        &[FirewallFilterSnapshot {
            name: "partial".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-mixed".into(),
                source_addresses: vec!["203.0.113.0/24".into(), "garbage".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
    );
    let in_valid = evaluate_filter(
        &state,
        "inet:partial",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        PROTO_TCP,
        12345,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        in_valid.action,
        FilterAction::Discard,
        "the surviving valid prefix must still match (partial-malformed != all-malformed)"
    );
}
