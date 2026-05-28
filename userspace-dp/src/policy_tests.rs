// Tests for policy.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep policy.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "policy_tests.rs"]` from policy.rs.

use super::*;
use crate::test_zone_ids::*;

fn test_zone_name_to_id() -> FxHashMap<String, u16> {
    let mut m = FxHashMap::default();
    m.insert("lan".to_string(), TEST_LAN_ZONE_ID);
    m.insert("wan".to_string(), TEST_WAN_ZONE_ID);
    m.insert("trust".to_string(), TEST_TRUST_ZONE_ID);
    m.insert("untrust".to_string(), TEST_UNTRUST_ZONE_ID);
    m.insert("sfmix".to_string(), TEST_SFMIX_ZONE_ID);
    m
}

fn scheduled_allow_snapshot(rule_id: &str, inactive: bool) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        rule_id: rule_id.to_string(),
        name: "scheduled-allow".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        scheduler_name: "workhours".to_string(),
        inactive,
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        action: "permit".to_string(),
        ..Default::default()
    }
}

fn policy_counter(state: &PolicyState, rule_id: &str) -> PolicyRuleCounterStatus {
    state
        .counter_snapshots()
        .into_iter()
        .find(|counter| counter.rule_id == rule_id)
        .unwrap_or_else(|| panic!("missing policy counter for {rule_id}"))
}

#[test]
fn allow_all_matches_zone_pair() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "allow-all".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit
    );
}

#[test]
fn evaluate_policy_result_reports_snapshot_policy_id() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            policy_id: 257,
            name: "deny-web".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            action: "deny".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );

    let result = evaluate_policy_result_with_len(
        &state,
        TEST_LAN_ZONE_ID,
        TEST_WAN_ZONE_ID,
        "10.0.61.100".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        PROTO_TCP,
        12345,
        443,
        64,
    );

    assert_eq!(result.action, PolicyAction::Deny);
    assert_eq!(result.policy_id, 257);
}

#[test]
fn default_deny_applies_without_match() {
    let state = parse_policy_state("deny", &[], &test_zone_name_to_id());
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny
    );
}

#[test]
fn evaluate_policy_skips_inactive_rules() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            rule_id: "security-policy:lan:wan:inactive-allow".to_string(),
            name: "inactive-allow".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            scheduler_name: "workhours".to_string(),
            inactive: true,
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );

    assert_eq!(
        state.rules[0].rule_id,
        "security-policy:lan:wan:inactive-allow"
    );
    assert_eq!(state.rules[0].scheduler_name, "workhours");
    assert!(state.rules[0].inactive);
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny
    );
    assert_eq!(
        policy_counter(&state, "security-policy:lan:wan:inactive-allow").packets,
        0
    );
}

#[test]
fn inactive_rule_falls_through_to_next_match() {
    let state = parse_policy_state(
        "deny",
        &[
            PolicyRuleSnapshot {
                name: "inactive-deny".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                scheduler_name: "offhours".to_string(),
                inactive: true,
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                action: "deny".to_string(),
                ..Default::default()
            },
            PolicyRuleSnapshot {
                rule_id: "security-policy:lan:wan:active-allow".to_string(),
                name: "active-allow".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                action: "permit".to_string(),
                ..Default::default()
            },
        ],
        &test_zone_name_to_id(),
    );

    assert_eq!(state.rules[0].rule_id, "lan->wan/inactive-deny");
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit
    );
    assert_eq!(policy_counter(&state, "lan->wan/inactive-deny").packets, 0);
    assert_eq!(
        policy_counter(&state, "security-policy:lan:wan:active-allow").packets,
        1
    );
}

#[test]
fn hit_counters_survive_scheduler_snapshot_rebuild() {
    let rule_id = format!("security-policy:lan:wan:counter-survival-{}", line!());
    let counter_store = PolicyCounterStore::default();
    counter_store.reconcile_rules(&[scheduled_allow_snapshot(&rule_id, false)]);
    let active = parse_policy_state_with_counters(
        "deny",
        &[scheduled_allow_snapshot(&rule_id, false)],
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    ).expect("test snapshot must not produce integrity error");

    for _ in 0..2 {
        assert_eq!(
            evaluate_policy_with_len(
                &active,
                TEST_LAN_ZONE_ID,
                TEST_WAN_ZONE_ID,
                "10.0.61.100".parse().expect("src"),
                "172.16.80.200".parse().expect("dst"),
                PROTO_TCP,
                12345,
                5201,
                64,
            ),
            PolicyAction::Permit
        );
    }
    let active_counter = policy_counter(&active, &rule_id);
    assert_eq!(active_counter.packets, 2);
    assert_eq!(active_counter.bytes, 128);

    counter_store.reconcile_rules(&[scheduled_allow_snapshot(&rule_id, true)]);
    let inactive = parse_policy_state_with_counters(
        "deny",
        &[scheduled_allow_snapshot(&rule_id, true)],
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    ).expect("test snapshot must not produce integrity error");
    assert!(inactive.rules[0].inactive);
    assert_eq!(policy_counter(&inactive, &rule_id).packets, 2);
    assert_eq!(
        evaluate_policy(
            &inactive,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny
    );
    assert_eq!(policy_counter(&inactive, &rule_id).packets, 2);

    drop(active);
    drop(inactive);
    counter_store.reconcile_rules(&[scheduled_allow_snapshot(&rule_id, false)]);
    let active_again = parse_policy_state_with_counters(
        "deny",
        &[scheduled_allow_snapshot(&rule_id, false)],
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    ).expect("test snapshot must not produce integrity error");
    assert_eq!(policy_counter(&active_again, &rule_id).packets, 2);
    assert_eq!(
        evaluate_policy(
            &active_again,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit
    );
    assert_eq!(policy_counter(&active_again, &rule_id).packets, 3);
}

#[test]
fn hit_counters_reset_after_rule_absent_then_readded() {
    let rule_id = format!("security-policy:lan:wan:counter-reset-{}", line!());
    let counter_store = PolicyCounterStore::default();
    counter_store.reconcile_rules(&[scheduled_allow_snapshot(&rule_id, false)]);
    let active = parse_policy_state_with_counters(
        "deny",
        &[scheduled_allow_snapshot(&rule_id, false)],
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    ).expect("test snapshot must not produce integrity error");
    assert_eq!(
        evaluate_policy_with_len(
            &active,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
            96,
        ),
        PolicyAction::Permit
    );
    let active_counter = policy_counter(&active, &rule_id);
    assert_eq!(active_counter.packets, 1);
    assert_eq!(active_counter.bytes, 96);

    counter_store.reconcile_rules(&[]);
    let deleted =
        parse_policy_state_with_counters(
        "deny",
        &[],
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    ).expect("test snapshot must not produce integrity error");
    assert!(deleted.counter_snapshots().is_empty());

    counter_store.reconcile_rules(&[scheduled_allow_snapshot(&rule_id, false)]);
    let active_again = parse_policy_state_with_counters(
        "deny",
        &[scheduled_allow_snapshot(&rule_id, false)],
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    ).expect("test snapshot must not produce integrity error");
    let reset_counter = policy_counter(&active_again, &rule_id);
    assert_eq!(reset_counter.packets, 0);
    assert_eq!(reset_counter.bytes, 0);
}

#[test]
fn cidr_matches_ipv6() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "allow-v6".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["2001:559:8585:ef00::/64".to_string()],
            destination_addresses: vec!["2001:559:8585:80::/64".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "2001:559:8585:ef00::100".parse().expect("src"),
            "2001:559:8585:80::200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit
    );
}

#[test]
fn named_application_matches_protocol_and_port() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "allow-http".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["junos-http".to_string()],
            application_terms: vec![PolicyApplicationSnapshot {
                name: "junos-http".to_string(),
                protocol: "tcp".to_string(),
                source_port: String::new(),
                destination_port: "80".to_string(),
            }],
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            40000,
            80,
        ),
        PolicyAction::Permit
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            40000,
            443,
        ),
        PolicyAction::Deny
    );
}

#[test]
fn application_set_matches_any_expanded_term() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "allow-web".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["web".to_string()],
            application_terms: vec![
                PolicyApplicationSnapshot {
                    name: "junos-http".to_string(),
                    protocol: "tcp".to_string(),
                    source_port: String::new(),
                    destination_port: "80".to_string(),
                },
                PolicyApplicationSnapshot {
                    name: "junos-https".to_string(),
                    protocol: "tcp".to_string(),
                    source_port: String::new(),
                    destination_port: "443".to_string(),
                },
            ],
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            40000,
            443,
        ),
        PolicyAction::Permit
    );
}

#[test]
fn global_policy_matches_any_zone_pair() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "global-allow".to_string(),
            from_zone: "junos-global".to_string(),
            to_zone: "junos-global".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );
    // Should match any zone pair
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_TRUST_ZONE_ID,
            TEST_UNTRUST_ZONE_ID,
            "10.0.0.1".parse().expect("src"),
            "8.8.8.8".parse().expect("dst"),
            PROTO_TCP,
            12345,
            443,
        ),
        PolicyAction::Permit
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_DMZ_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "192.168.1.1".parse().expect("src"),
            "1.1.1.1".parse().expect("dst"),
            PROTO_UDP,
            5555,
            53,
        ),
        PolicyAction::Permit
    );
}

#[test]
fn global_policy_evaluated_after_zone_specific() {
    let state = parse_policy_state(
        "deny",
        &[
            PolicyRuleSnapshot {
                name: "deny-trust-to-untrust".to_string(),
                from_zone: "trust".to_string(),
                to_zone: "untrust".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                application_terms: Vec::new(),
                action: "deny".to_string(),
                ..Default::default()
            },
            PolicyRuleSnapshot {
                name: "global-allow".to_string(),
                from_zone: "junos-global".to_string(),
                to_zone: "junos-global".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                application_terms: Vec::new(),
                action: "permit".to_string(),
                ..Default::default()
            },
        ],
        &test_zone_name_to_id(),
    );
    // Zone-specific deny should take precedence (evaluated first)
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_TRUST_ZONE_ID,
            TEST_UNTRUST_ZONE_ID,
            "10.0.0.1".parse().expect("src"),
            "8.8.8.8".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Deny
    );
    // Different zone pair should hit the global permit
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_SFMIX_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.0.1".parse().expect("src"),
            "8.8.8.8".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Permit
    );
}

/// #919/#922: snapshot rules whose zone names are absent from
/// `zone_name_to_id` are dropped by `parse_policy_state` (logged
/// and not indexed). A real `LAN→WAN` lookup therefore finds
/// nothing and falls through to the default action.
#[test]
fn evaluate_policy_unknown_zone_pair_returns_default_action() {
    let zones = test_zone_name_to_id();
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "rule".into(),
            from_zone: "ghost-from".into(),
            to_zone: "ghost-to".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: "permit".into(),
            ..Default::default()
        }],
        &zones,
    );
    // Unknown-zone rule was not indexed; LAN→WAN lookup finds nothing → default deny.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.0.1".parse().expect("src"),
            "8.8.8.8".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Deny
    );
}

/// #923: legacy permissive parse — addresses that fail to parse
/// are silently dropped by `parse_address`. If ALL configured
/// addresses are malformed the resulting Vec is empty, which
/// `PrefixSet::from_prefixes(Vec::new())` collapses to
/// `MatchAny` — preserving the legacy `Vec::is_empty()` =
/// match-all behavior. This is intentional; a strict-parse
/// follow-up issue tracks fixing the silent-drop.
#[test]
fn malformed_only_input_yields_match_all_via_evaluate_policy() {
    let zones = test_zone_name_to_id();
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "permit-with-typo".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec![
                "totally-bogus".into(),
                "192.18.1/24".into(), // invalid (missing octet)
            ],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: "permit".into(),
            ..Default::default()
        }],
        &zones,
    );
    // The malformed source becomes MatchAny; an arbitrary src
    // hits the rule and returns Permit.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "8.8.8.8".parse().expect("src"),
            "1.1.1.1".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Permit
    );
}

// #1606 — address-book wire-protocol tests.

fn book(id: u32, name: &str, v4: &[&str], v6: &[&str]) -> AddressBookSnapshot {
    AddressBookSnapshot {
        id,
        name: name.to_string(),
        prefixes_v4: v4.iter().map(|s| s.to_string()).collect(),
        prefixes_v6: v6.iter().map(|s| s.to_string()).collect(),
    }
}

fn v3_rule(name: &str, src_books: &[u32], src_lits: &[&str]) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_book_ids: src_books.to_vec(),
        source_literals: src_lits.iter().map(|s| s.to_string()).collect(),
        destination_literals: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        action: "permit".to_string(),
        ..Default::default()
    }
}

#[test]
fn test_book_table_dedup_by_index() {
    // Two rules cite the same book ID. After parsing, both rules
    // resolve to the same dense index → identical match path.
    let books = [book(42, "corp-net", &["10.0.0.0/8"], &[])];
    let rules = [
        v3_rule("rule-a", &[42], &[]),
        v3_rule("rule-b", &[42], &[]),
    ];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    assert_eq!(state.books.len(), 1);
    assert_eq!(state.rules[0].source_book_idxs[..], state.rules[1].source_book_idxs[..]);
}

#[test]
fn test_book_only_rule_does_not_fail_open() {
    // A rule citing only a book (empty source_literals) must
    // match ONLY IPs covered by the book — NOT all v4 traffic.
    // Without the MatchNone fix this rule would have
    // source_literal_v4 = MatchAny (legacy from_prefixes(empty)
    // semantics) and match-all.
    let books = [book(7, "internal", &["10.0.0.0/8"], &[])];
    let rules = [v3_rule("internal-only", &[7], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    // Inside the book → match (Permit).
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.5.5.5".parse().expect("src"),
            "1.1.1.1".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Permit
    );
    // Outside the book → default Deny. If MatchNone is broken,
    // this would be Permit (match-all).
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "8.8.8.8".parse().expect("src"),
            "1.1.1.1".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Deny
    );
}

#[test]
fn test_v3_shaped_any_token_matches_all_v4_and_v6() {
    // Codex r5 F-r5-1 regression test: a v3-shaped rule with
    // source_literals=["any"] must match all v4 AND v6, NOT
    // fail closed via MatchNone.
    let rules = [PolicyRuleSnapshot {
        name: "any-perm".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_literals: vec!["any".to_string()],
        destination_literals: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        action: "permit".to_string(),
        ..Default::default()
    }];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    )
    .expect("parse");
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "8.8.8.8".parse().expect("src"),
            "1.1.1.1".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Permit
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "2001:db8::1".parse().expect("src"),
            "2001:db8::2".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Permit
    );
}

#[test]
fn test_v4_only_book_does_not_match_v6_traffic() {
    // Codex r4 family-incomplete-book test. A v4-only book has
    // entry.v6 = MatchNone, so a v6 packet hitting a rule citing
    // only this book MUST NOT match.
    let books = [book(11, "v4-only", &["10.0.0.0/8"], &[])];
    let rules = [v3_rule("v4-only-rule", &[11], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    // v6 packet → no match → default deny.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "2001:db8::1".parse().expect("src"),
            "2001:db8::2".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Deny
    );
}

#[test]
fn test_v6_only_book_does_not_match_v4_traffic() {
    let books = [book(12, "v6-only", &[], &["2001:db8::/32"])];
    let rules = [v3_rule("v6-only-rule", &[12], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "8.8.8.8".parse().expect("src"),
            "1.1.1.1".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Deny
    );
}

#[test]
fn test_unknown_book_id_hard_fails_snapshot() {
    // Rule cites book ID 99 but address_books is empty → hard fail.
    let rules = [v3_rule("missing-book", &[99], &[])];
    let counter_store = PolicyCounterStore::default();
    let result = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    );
    match result {
        Err(SnapshotIntegrityError::UnknownAddressBookId { book_id, .. }) => {
            assert_eq!(book_id, 99);
        }
        other => panic!("expected UnknownAddressBookId(99), got {:?}", other),
    }
}

#[test]
fn test_duplicate_address_book_id_hard_fails_snapshot() {
    let books = [book(5, "a", &["10.0.0.0/24"], &[]), book(5, "b", &["10.1.0.0/24"], &[])];
    let counter_store = PolicyCounterStore::default();
    let result = parse_policy_state_with_counters(
        "deny",
        &[],
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    );
    match result {
        Err(SnapshotIntegrityError::DuplicateAddressBookId(id)) => assert_eq!(id, 5),
        other => panic!("expected DuplicateAddressBookId(5), got {:?}", other),
    }
}

#[test]
fn test_book_id_zero_hard_fails_snapshot() {
    let books = [book(0, "reserved", &["10.0.0.0/24"], &[])];
    let counter_store = PolicyCounterStore::default();
    let result = parse_policy_state_with_counters(
        "deny",
        &[],
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    );
    assert!(
        matches!(result, Err(SnapshotIntegrityError::AddressBookIdZero)),
        "expected AddressBookIdZero, got {:?}",
        result
    );
}

#[test]
fn test_per_rule_duplicate_book_ids_are_deduped() {
    let books = [book(8, "x", &["10.0.0.0/8"], &[])];
    let rules = [v3_rule("dup-ids", &[8, 8, 8], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    // After sort+dedup, only one index is stored.
    assert_eq!(state.rules[0].source_book_idxs.len(), 1);
}

#[test]
fn test_non_v3_shaped_falls_through_to_legacy_field() {
    // Rule has source_addresses populated (legacy emission) but
    // NO source_book_ids or source_literals → non-v3-shaped → use
    // legacy field via from_prefixes (empty → MatchAny). With a
    // concrete CIDR in the legacy field, matching is correct.
    let rules = [PolicyRuleSnapshot {
        name: "legacy".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.0.0/8".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        action: "permit".to_string(),
        ..Default::default()
    }];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    )
    .expect("parse");
    // In the 10/8 range → match.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.5.5.5".parse().expect("src"),
            "1.1.1.1".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Permit
    );
    // Outside 10/8 → no match.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "8.8.8.8".parse().expect("src"),
            "1.1.1.1".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Deny
    );
}

// -----------------------------------------------------------------
// #1609 v3.1 Step 1 (STAGED narrow scope) — BookEntry parallel
// prefix-list scaffolding.
//
// These tests verify that the `prefixes_v4` / `prefixes_v6` Arc
// fields on `BookEntry` agree with the contents of the matching
// PrefixSetV{4,6} on representative inputs. The future Multi-Book
// LPM (deferred to a follow-up issue per the v3.1 r2
// PLAN-NEEDS-MAJOR convergence) reads these parallel fields
// directly rather than walking the trie-compressed PrefixSet.
// -----------------------------------------------------------------

#[test]
fn test_book_entry_carries_canonical_prefix_lists_v4() {
    let books = [book(
        100,
        "mixed-v4",
        &["10.0.0.0/8", "192.168.1.0/24", "203.0.113.5/32"],
        &[],
    )];
    let rules = [v3_rule("r", &[100], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    assert_eq!(state.books.len(), 1);
    let entry = &state.books[0];
    // Every parallel-array entry must be contained in the PrefixSet.
    for p in entry.prefixes_v4.iter() {
        // Use the IP at the network base to sample membership.
        assert!(
            entry.v4.contains(p.addr()),
            "PrefixSet does not contain prefix from parallel array: {p:?}"
        );
    }
    assert_eq!(entry.prefixes_v4.len(), 3);
    assert!(entry.prefixes_v6.is_empty());
}

#[test]
fn test_book_entry_canonical_prefix_lists_v6() {
    let books = [book(
        101,
        "mixed-v6",
        &[],
        &["2001:db8::/32", "fe80::/10", "::1/128"],
    )];
    let rules = [v3_rule("r", &[101], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    assert_eq!(state.books.len(), 1);
    let entry = &state.books[0];
    for p in entry.prefixes_v6.iter() {
        assert!(
            entry.v6.contains(p.addr()),
            "PrefixSet does not contain prefix from parallel array: {p:?}"
        );
    }
    assert!(entry.prefixes_v4.is_empty());
    assert_eq!(entry.prefixes_v6.len(), 3);
}

#[test]
fn test_book_entry_empty_book_has_empty_parallel_arrays() {
    // Book with no v4 + no v6 prefixes: PrefixSet collapses to
    // MatchNone (v3 factory semantics); parallel arrays are empty.
    let books = [book(102, "empty", &[], &[])];
    let rules = [v3_rule("r", &[102], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let entry = &state.books[0];
    assert!(entry.prefixes_v4.is_empty());
    assert!(entry.prefixes_v6.is_empty());
    assert!(entry.v4.is_match_none());
    assert!(entry.v6.is_match_none());
}

#[test]
fn test_book_entry_parallel_array_preserves_zero_prefix() {
    // A book containing 0.0.0.0/0 collapses its PrefixSet to
    // MatchAny — but the parallel prefix array MUST still carry
    // the /0 entry so a future LPM builder can route it through
    // the §2.6 short-circuit (books_covering_all_v4) rather than
    // populate every level-0 entry.
    let books = [book(103, "any-v4", &["0.0.0.0/0"], &[])];
    let rules = [v3_rule("r", &[103], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let entry = &state.books[0];
    // PrefixSet has collapsed to MatchAny per the /0 semantics.
    assert!(entry.v4.is_match_any());
    // But the parallel array preserves the /0 so a future LPM
    // build can short-circuit per plan §2.6.
    assert_eq!(entry.prefixes_v4.len(), 1);
    assert_eq!(entry.prefixes_v4[0].prefix_len(), 0);
}

#[test]
fn test_book_entry_canonical_prefix_lists_dual_family() {
    // AGY r1 nit Patch A: a single book with BOTH v4 and v6
    // prefixes — verifies parallel arrays are populated for each
    // family independently.
    let books = [book(
        104,
        "dual-family",
        &["10.0.0.0/8", "192.168.1.0/24"],
        &["2001:db8::/32", "fe80::/10"],
    )];
    let rules = [v3_rule("r", &[104], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let entry = &state.books[0];
    assert_eq!(entry.prefixes_v4.len(), 2);
    assert_eq!(entry.prefixes_v6.len(), 2);
    for p in entry.prefixes_v4.iter() {
        assert!(entry.v4.contains(p.addr()));
    }
    for p in entry.prefixes_v6.iter() {
        assert!(entry.v6.contains(p.addr()));
    }
}

#[test]
fn test_book_entry_canonical_prefix_lists_trie_variant() {
    // AGY r1 nit Patch B: 17 prefixes triggers the Trie variant
    // (PREFIX_SET_LINEAR_MAX = 16). Verifies the parallel array
    // is variant-independent — it's captured BEFORE PrefixSet
    // chooses Linear vs Trie.
    let prefix_strs: Vec<String> = (0..17).map(|i| format!("10.0.{i}.0/24")).collect();
    let prefix_refs: Vec<&str> = prefix_strs.iter().map(|s| s.as_str()).collect();
    let books = [book(105, "large-v4", &prefix_refs, &[])];
    let rules = [v3_rule("r", &[105], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let entry = &state.books[0];
    assert!(matches!(entry.v4, crate::prefix_set::PrefixSetV4::Trie(_)));
    assert_eq!(entry.prefixes_v4.len(), 17);
    for p in entry.prefixes_v4.iter() {
        assert!(entry.v4.contains(p.addr()));
    }
}

#[test]
fn test_book_entry_zero_plus_non_zero_prefixes_preserved() {
    // Copilot r3 nit: a book containing 0.0.0.0/0 AND 10.0.0.0/8
    // (or analogous v6) — PrefixSet collapses to MatchAny (which
    // drops the non-/0 entries from its internal Linear/Trie
    // representation), but the parallel `prefixes_v{4,6}` array
    // MUST retain BOTH entries so the future Multi-Book LPM build
    // can route /0 through the §2.6 short-circuit while still
    // inserting the /8 (and analogous) prefixes into the LPM
    // proper. This is the load-bearing motivation for the parallel
    // array.
    let books = [book(
        106,
        "any-plus-net",
        &["0.0.0.0/0", "10.0.0.0/8"],
        &["::/0", "2001:db8::/32"],
    )];
    let rules = [v3_rule("r", &[106], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let entry = &state.books[0];
    // PrefixSet collapses to MatchAny on both families due to /0.
    assert!(entry.v4.is_match_any());
    assert!(entry.v6.is_match_any());
    // But the parallel arrays preserve BOTH the /0 and the non-/0
    // entries — this is exactly what the future LPM builder needs.
    assert_eq!(entry.prefixes_v4.len(), 2);
    assert_eq!(entry.prefixes_v6.len(), 2);
    // /0 and the non-/0 entry must both be present.
    let v4_lens: Vec<u8> = entry.prefixes_v4.iter().map(|p| p.prefix_len()).collect();
    assert!(v4_lens.contains(&0), "v4 parallel array must keep /0: got {v4_lens:?}");
    assert!(v4_lens.contains(&8), "v4 parallel array must keep /8: got {v4_lens:?}");
    let v6_lens: Vec<u8> = entry.prefixes_v6.iter().map(|p| p.prefix_len()).collect();
    assert!(v6_lens.contains(&0), "v6 parallel array must keep ::/0: got {v6_lens:?}");
    assert!(v6_lens.contains(&32), "v6 parallel array must keep /32: got {v6_lens:?}");
}

// -----------------------------------------------------------------
// #1623 Path B narrow (STAGED scaffolding) — PolicyRule parallel
// prefix arrays.
//
// These tests verify that the `source_prefixes_v{4,6}` /
// `destination_prefixes_v{4,6}` Option<Arc<[T]>> fields on
// `PolicyRule` are populated correctly at parse-time as the union
// of (a) the rule's own literal CIDRs and (b) every cited address
// book's prefixes_v{4,6}. `None` represents "no operator-stated
// input prefixes for this side+family" — paired with the existing
// `..._match_any` flag for semantic match shape (see the
// dominance rule in plan §4.2).
//
// Mirrors the BookEntry parallel-prefix test pattern from #1624
// (lines ~1015-1239 above) with the Option wrapper differences.
// -----------------------------------------------------------------

// Helper: build a v3-shaped rule with explicit destination side.
fn v3_rule_full(
    name: &str,
    src_books: &[u32],
    src_lits: &[&str],
    dst_books: &[u32],
    dst_lits: &[&str],
) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_book_ids: src_books.to_vec(),
        source_literals: src_lits.iter().map(|s| s.to_string()).collect(),
        destination_book_ids: dst_books.to_vec(),
        destination_literals: dst_lits.iter().map(|s| s.to_string()).collect(),
        applications: vec!["any".to_string()],
        action: "permit".to_string(),
        ..Default::default()
    }
}

#[test]
fn test_policy_rule_v3_carries_canonical_prefix_lists_v4() {
    // Test 1: rule with three v4 literal CIDRs + one cited v4-only
    // book (one v4 prefix). Assert source_prefixes_v4 = Some(4
    // entries), source_prefixes_v6 = None, destination_*_v{4,6}
    // = None (destination is "any").
    let books = [book(200, "corp-v4", &["172.16.0.0/12"], &[])];
    let rules = [v3_rule(
        "r-v4",
        &[200],
        &["10.0.0.0/8", "192.168.0.0/16", "203.0.113.5/32"],
    )];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    let arr = rule
        .source_prefixes_v4
        .as_deref()
        .expect("source_prefixes_v4 must be Some");
    assert_eq!(arr.len(), 4, "3 literals + 1 book prefix = 4");
    assert!(rule.source_prefixes_v6.is_none());
    // Destination side is "any" -> None.
    assert!(rule.destination_prefixes_v4.is_none());
    assert!(rule.destination_prefixes_v6.is_none());
}

#[test]
fn test_policy_rule_v3_carries_canonical_prefix_lists_v6() {
    // Test 2: same shape as v4, but v6 only.
    let books = [book(201, "corp-v6", &[], &["2001:db8::/32"])];
    let rules = [PolicyRuleSnapshot {
        name: "r-v6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_book_ids: vec![201],
        source_literals: vec![
            "fe80::/10".to_string(),
            "::1/128".to_string(),
        ],
        destination_literals: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        action: "permit".to_string(),
        ..Default::default()
    }];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    let arr = rule
        .source_prefixes_v6
        .as_deref()
        .expect("source_prefixes_v6 must be Some");
    assert_eq!(arr.len(), 3, "2 literals + 1 book prefix = 3");
    assert!(rule.source_prefixes_v4.is_none());
}

#[test]
fn test_policy_rule_v3_dual_family() {
    // Test 3: rule with v4 + v6 literals + a dual-family book.
    let books = [book(
        202,
        "dual",
        &["10.0.0.0/8"],
        &["2001:db8::/32"],
    )];
    let rules = [v3_rule(
        "r-dual",
        &[202],
        &["172.16.0.0/12", "fe80::/10"],
    )];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    let v4 = rule.source_prefixes_v4.as_deref().expect("v4 Some");
    let v6 = rule.source_prefixes_v6.as_deref().expect("v6 Some");
    assert_eq!(v4.len(), 2, "v4: 1 literal + 1 book = 2");
    assert_eq!(v6.len(), 2, "v6: 1 literal + 1 book = 2");
}

#[test]
fn test_policy_rule_v3_any_source_yields_none() {
    // Test 4: rule with source_literals=["any"], no books.
    // Assert source_prefixes_v4 = None AND source_prefixes_v6 =
    // None AND source_v{4,6}_match_any = true. Demonstrates the
    // "any -> None + flag" contract and zero allocation for the
    // common case.
    let rules = [v3_rule("r-any", &[], &["any"])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    assert!(rule.source_prefixes_v4.is_none());
    assert!(rule.source_prefixes_v6.is_none());
    assert!(rule.source_v4_match_any);
    assert!(rule.source_v6_match_any);
}

#[test]
fn test_policy_rule_v3_book_only_inherits_book_prefixes() {
    // Test 5: rule with source_book_ids=[N], empty literals.
    // Assert rule's source_prefixes_v4 matches the book's
    // prefixes_v4 exactly in length AND content.
    let books = [book(
        203,
        "book-only",
        &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        &[],
    )];
    let rules = [v3_rule("r-book", &[203], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    let arr = rule.source_prefixes_v4.as_deref().expect("Some");
    assert_eq!(arr.len(), 3);
    // Rule's parallel array content matches book's: every entry
    // round-trips through the book's PrefixSet.
    let book_entry = &state.books[0];
    for p in arr.iter() {
        assert!(book_entry.v4.contains(p.addr()));
    }
}

#[test]
fn test_policy_rule_v3_multiple_books_dense_index_order() {
    // Test 6: rule with source_book_ids=[3, 1, 2] (declared
    // out-of-order). resolve_book_idxs sort_unstable + dedup
    // sorts to ascending dense indices. The parallel array
    // walks the cited books in ascending dense-index order.
    let books = [
        book(301, "a", &["10.1.0.0/16"], &[]),
        book(302, "b", &["10.2.0.0/16"], &[]),
        book(303, "c", &["10.3.0.0/16"], &[]),
    ];
    let mut rule_snap = v3_rule("r-multi", &[], &[]);
    rule_snap.source_book_ids = vec![303, 301, 302];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &[rule_snap],
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    let arr = rule.source_prefixes_v4.as_deref().expect("Some");
    assert_eq!(arr.len(), 3, "3 books × 1 prefix each");
    // Books were inserted in declared order [301, 302, 303] so
    // dense indices are 0, 1, 2 respectively. After
    // sort_unstable on source_book_ids: [301, 302, 303] -> dense
    // [0, 1, 2]. Array walk visits each book once in ascending
    // dense index, giving prefixes in order a, b, c.
    assert_eq!(arr[0].prefix_len(), 16);
    // Spot-check the first octet of the addresses (10.1, 10.2,
    // 10.3): each address is in its respective book.
    let book_a = &state.books[0];
    let book_b = &state.books[1];
    let book_c = &state.books[2];
    assert!(book_a.v4.contains(arr[0].addr()));
    assert!(book_b.v4.contains(arr[1].addr()));
    assert!(book_c.v4.contains(arr[2].addr()));
}

#[test]
fn test_policy_rule_legacy_source_addresses_path() {
    // Test 7: non-v3-shaped rule using source_addresses (legacy).
    // No source_literals, no books, no destination_literals nor
    // destination_book_ids. Assert source_prefixes_v4 = Some([
    // 10.0.0.0/8]).
    let rule_snap = PolicyRuleSnapshot {
        name: "r-legacy".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.0.0/8".to_string()],
        destination_addresses: vec![],
        applications: vec!["any".to_string()],
        action: "permit".to_string(),
        ..Default::default()
    };
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &[rule_snap],
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    let arr = rule.source_prefixes_v4.as_deref().expect("Some");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0].prefix_len(), 8);
}

#[test]
fn test_policy_rule_v3_any4_any6_tokens() {
    // Test 8: rule with source_literals=["any4"] — sets
    // source_v4_match_any=true, parallel array still None
    // (any token contributes no literal prefix). Then symmetric
    // for ["any6"].
    let rules = [
        v3_rule("r-any4", &[], &["any4"]),
        v3_rule("r-any6", &[], &["any6"]),
    ];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    )
    .expect("parse");
    let r_any4 = &state.rules[0];
    assert!(r_any4.source_v4_match_any, "any4 -> v4 match_any true");
    assert!(!r_any4.source_v6_match_any, "any4 -> v6 match_any false");
    assert!(r_any4.source_prefixes_v4.is_none());
    assert!(r_any4.source_prefixes_v6.is_none());
    let r_any6 = &state.rules[1];
    assert!(!r_any6.source_v4_match_any);
    assert!(r_any6.source_v6_match_any);
    assert!(r_any6.source_prefixes_v4.is_none());
    assert!(r_any6.source_prefixes_v6.is_none());
}

#[test]
fn test_policy_rule_v3_literal_zero_prefix_preserved() {
    // Test 9: rule with literal "0.0.0.0/0" (NOT "any" token).
    // PrefixSet collapses to MatchAny because /0 is present, but
    // parallel array preserves the /0 entry as
    // Some([0.0.0.0/0]). Demonstrates the operator-input
    // fidelity contract: Some([/0]) and None mean different
    // things (operator literal /0 vs operator any).
    let rules = [v3_rule("r-zero", &[], &["0.0.0.0/0"])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    assert!(rule.source_v4_match_any, "/0 collapses to MatchAny");
    let arr = rule
        .source_prefixes_v4
        .as_deref()
        .expect("literal /0 must be Some([/0]), NOT None");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0].prefix_len(), 0);
}

#[test]
fn test_policy_rule_v3_destination_side_independent() {
    // Test 10: rule with source="any", destination=[two literal
    // CIDRs]. Assert source side is None for both families;
    // destination_v4 has 2 entries, destination_v6 is None.
    let rule_snap = v3_rule_full(
        "r-dst",
        &[],
        &["any"],
        &[],
        &["10.0.0.0/8", "192.168.0.0/16"],
    );
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &[rule_snap],
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    assert!(rule.source_prefixes_v4.is_none());
    assert!(rule.source_prefixes_v6.is_none());
    let arr = rule.destination_prefixes_v4.as_deref().expect("Some");
    assert_eq!(arr.len(), 2);
    assert!(rule.destination_prefixes_v6.is_none());
}

#[test]
fn test_policy_rule_v3_trie_variant_preserves_array() {
    // Test 11: rule with 17 literal CIDRs (triggers Trie variant
    // since PREFIX_SET_LINEAR_MAX = 16). Parallel array preserves
    // all 17 — variant-independent because it's captured before
    // PrefixSet chooses Linear vs Trie.
    let lits: Vec<String> = (0..17).map(|i| format!("10.0.{i}.0/24")).collect();
    let lit_refs: Vec<&str> = lits.iter().map(|s| s.as_str()).collect();
    let rules = [v3_rule("r-trie", &[], &lit_refs)];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    assert!(matches!(
        rule.source_literal_v4,
        crate::prefix_set::PrefixSetV4::Trie(_)
    ));
    let arr = rule.source_prefixes_v4.as_deref().expect("Some");
    assert_eq!(arr.len(), 17);
}

#[test]
fn test_policy_rule_clone_preserves_arrays() {
    // Test 12: build a rule with Some(arr) AND None fields, clone
    // it, assert ptr-equality for Some (Arc ref-count bump) and
    // None preserved.
    let books = [book(204, "for-clone", &["10.0.0.0/8"], &[])];
    let rules = [v3_rule("r-clone", &[204], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    let cloned = rule.clone();
    // Some side: same Arc data pointer (ref-count bump).
    let orig = rule.source_prefixes_v4.as_ref().expect("Some");
    let dup = cloned.source_prefixes_v4.as_ref().expect("Some");
    assert!(
        Arc::ptr_eq(orig, dup),
        "Arc::ptr_eq must hold across clone"
    );
    // None side: still None.
    assert!(cloned.source_prefixes_v6.is_none());
    assert!(cloned.destination_prefixes_v4.is_none());
    assert!(cloned.destination_prefixes_v6.is_none());
}

// Compile-time size_of guards (test 13). These const blocks fail
// compilation if NPO is ever broken (which would tank the memory
// accounting in plan §2.1). The const _ pattern avoids the
// static_assertions crate dependency (per AGY r3 + Codex r3
// alignment).
const _: [(); 16] = [(); std::mem::size_of::<Option<Arc<[PrefixV4]>>>()];
const _: [(); 16] = [(); std::mem::size_of::<Option<Arc<[PrefixV6]>>>()];
const _: [(); 16] = [(); std::mem::size_of::<Arc<[PrefixV4]>>()];
const _: [(); 16] = [(); std::mem::size_of::<Arc<[PrefixV6]>>()];

#[test]
fn test_policy_rule_size_of_option_arc() {
    // Runtime mirror of the const _ guards above so the test
    // appears in `cargo test` output. The const blocks are the
    // load-bearing compile-time enforcement; the runtime
    // assertions reaffirm for visibility.
    assert_eq!(std::mem::size_of::<Option<Arc<[PrefixV4]>>>(), 16);
    assert_eq!(std::mem::size_of::<Option<Arc<[PrefixV6]>>>(), 16);
    assert_eq!(std::mem::size_of::<Arc<[PrefixV4]>>(), 16);
    assert_eq!(std::mem::size_of::<Arc<[PrefixV6]>>(), 16);
}

#[test]
fn test_policy_rule_v3_any_plus_book_match_any_with_some_arr() {
    // Test 14: rule with source_literals=["any"] AND a cited
    // book with v4 prefixes. source_v4_match_any becomes true
    // via the "any" token. The parallel array still gets the
    // book's prefixes (the "any" token contributes no literal,
    // but the cited book contributes its prefixes_v4).
    // Demonstrates dominance: match_any=true means the array is
    // diagnostic only, never narrows the rule.
    let books = [book(205, "any-plus", &["10.0.0.0/8"], &[])];
    let rules = [v3_rule("r-any-plus", &[205], &["any"])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    assert!(rule.source_v4_match_any, "any token dominates");
    assert!(rule.source_v6_match_any);
    let arr = rule.source_prefixes_v4.as_deref().expect("Some");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0].prefix_len(), 8);
    // v6: book has no v6 prefixes -> None per §4.3 invariant.
    assert!(rule.source_prefixes_v6.is_none());
}

#[test]
fn test_policy_rule_v3_book_v6_only_yields_v4_none() {
    // Test 15: rule cites a v6-only book and has no v4 literals.
    // Assert source_prefixes_v4 = None (not Some([])), since the
    // empty union short-circuits to None in build_rule_side_arc.
    let books = [book(206, "v6-only", &[], &["2001:db8::/32"])];
    let rules = [v3_rule("r-v6-book", &[206], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    assert!(
        rule.source_prefixes_v4.is_none(),
        "v6-only book contributes no v4 -> None, not Some([])"
    );
    let v6 = rule.source_prefixes_v6.as_deref().expect("Some");
    assert_eq!(v6.len(), 1);
}

#[test]
fn test_policy_rule_v3_destination_book_path() {
    // Test 16: rule with destination_book_ids=[N], empty
    // destination_literals. Mirrors test 5 but on the destination
    // side — asserts symmetric handling.
    let books = [book(207, "dst-book", &["10.0.0.0/8", "172.16.0.0/12"], &[])];
    let rule_snap = v3_rule_full(
        "r-dst-book",
        &[],
        &["any"],
        &[207],
        &[],
    );
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &[rule_snap],
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    let arr = rule.destination_prefixes_v4.as_deref().expect("Some");
    assert_eq!(arr.len(), 2);
    assert!(rule.destination_prefixes_v6.is_none());
}

#[test]
fn test_policy_rule_v3_book_zero_plus_non_zero() {
    // Test 17: rule cites a book containing both 0.0.0.0/0 AND
    // 10.0.0.0/8 (book's prefixes_v4 carries both per #1624
    // BookEntry contract). Rule's parallel array inherits BOTH;
    // source_v4_match_any becomes true via the book's /0
    // contribution (book.v4.is_match_any()).
    let books = [book(
        208,
        "book-zero-plus",
        &["0.0.0.0/0", "10.0.0.0/8"],
        &[],
    )];
    let rules = [v3_rule("r-bzp", &[208], &[])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    assert!(
        rule.source_v4_match_any,
        "book containing /0 propagates match_any"
    );
    let arr = rule.source_prefixes_v4.as_deref().expect("Some");
    assert_eq!(arr.len(), 2, "preserve both /0 and /8 entries");
    let lens: Vec<u8> = arr.iter().map(|p| p.prefix_len()).collect();
    assert!(lens.contains(&0), "must include /0");
    assert!(lens.contains(&8), "must include /8");
}

#[test]
fn test_policy_rule_v3_literal_zero_plus_non_zero() {
    // Test 18: rule with literal source_literals=["0.0.0.0/0",
    // "10.0.0.0/8"]. Rule-level mirror of book test 17.
    // Parallel array preserves both entries; match_any becomes
    // true via the literal /0 (PrefixSet collapses to MatchAny).
    let rules = [v3_rule(
        "r-lit-zp",
        &[],
        &["0.0.0.0/0", "10.0.0.0/8"],
    )];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    assert!(rule.source_v4_match_any);
    let arr = rule.source_prefixes_v4.as_deref().expect("Some");
    assert_eq!(arr.len(), 2);
    let lens: Vec<u8> = arr.iter().map(|p| p.prefix_len()).collect();
    assert!(lens.contains(&0));
    assert!(lens.contains(&8));
}

#[test]
fn test_policy_rule_v3_duplicate_preservation() {
    // Test 19: rule with literal "10.0.0.0/8" AND citing a book
    // that ALSO contains "10.0.0.0/8". Parallel array contains
    // the prefix TWICE (literal + book). Confirms the "no dedup
    // at this layer; future LPM owns it" invariant from §4.3.
    let books = [book(209, "dup-book", &["10.0.0.0/8"], &[])];
    let rules = [v3_rule("r-dup", &[209], &["10.0.0.0/8"])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &books,
        &counter_store,
    )
    .expect("parse");
    let rule = &state.rules[0];
    let arr = rule.source_prefixes_v4.as_deref().expect("Some");
    assert_eq!(
        arr.len(),
        2,
        "duplicate must be preserved (literal + book = 2)"
    );
    // Both entries are 10.0.0.0/8.
    for p in arr.iter() {
        assert_eq!(p.prefix_len(), 8);
    }
}
