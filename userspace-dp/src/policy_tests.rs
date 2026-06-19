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

// #1606: `any4` / `any6` literal tokens force MatchAny on the named
// family only, leaving the other family MatchNone. This is the sole
// coverage of the per-family any-token parse semantics (preserved
// from the removed #1623 scaffolding test block in #1638).
#[test]
fn test_policy_rule_v3_any4_any6_tokens() {
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
    let r_any6 = &state.rules[1];
    assert!(!r_any6.source_v4_match_any, "any6 -> v4 match_any false");
    assert!(r_any6.source_v6_match_any, "any6 -> v6 match_any true");
}

// #2008 H11: the Junos `any-ipv4` / `any-ipv6` policy-match keywords
// must expand to the all-addresses prefix of their own family — and
// ONLY that family. Before the fix the tokens reached the dataplane
// verbatim, failed CIDR parsing, and were silently dropped (the rule
// then matched no v4/v6 traffic, or fell through to default-deny).
#[test]
fn test_policy_any_ipv4_token_matches_v4_only() {
    let rules = [v3_rule("r-any-ipv4", &[], &["any-ipv4"])];
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &rules,
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    )
    .expect("parse");
    // v4 source matches (any-ipv4 covers 0.0.0.0/0).
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("v4 src"),
            "172.16.80.200".parse().expect("v4 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit,
        "any-ipv4 must permit v4 traffic"
    );
    // v6 source must NOT be swept in by any-ipv4 (family-scoped).
    // destination_literals is "any" (both families), so the only
    // thing gating the v6 packet is the v6 source set, which must be
    // empty → default-deny.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "2001:db8::1".parse().expect("v6 src"),
            "2001:db8::2".parse().expect("v6 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny,
        "any-ipv4 must NOT match v6 traffic"
    );
}

#[test]
fn test_policy_any_ipv6_token_matches_v6_only() {
    let rules = [v3_rule("r-any-ipv6", &[], &["any-ipv6"])];
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
            "2001:db8::1".parse().expect("v6 src"),
            "2001:db8::2".parse().expect("v6 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit,
        "any-ipv6 must permit v6 traffic"
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("v4 src"),
            "172.16.80.200".parse().expect("v4 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny,
        "any-ipv6 must NOT match v4 traffic"
    );
}

// #2008 H2: `source-address-excluded` inverts the source match —
// the rule matches every source EXCEPT those in source_literals.
// Before the fix the snapshot flag did not exist, so the rule matched
// the literal set instead of its complement.
#[test]
fn test_policy_source_address_excluded_inverts_match() {
    let mut snap = v3_rule("r-excl-src", &[], &["10.0.0.0/8"]);
    snap.source_address_excluded = true;
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        std::slice::from_ref(&snap),
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    )
    .expect("parse");
    // Source INSIDE the excluded set → must NOT match → default-deny.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.5.5.5".parse().expect("excluded src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny,
        "a source inside the excluded set must NOT match"
    );
    // Source OUTSIDE the excluded set → matches → permit.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "192.168.1.5".parse().expect("non-excluded src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit,
        "a source outside the excluded set must match"
    );
}

// #2008 H2: without the excluded flag the SAME rule must match the
// literal set itself (proves the flag is what flips the sense, not a
// constant). Mutation-sentinel: passes only because the inversion is
// gated on source_address_excluded.
#[test]
fn test_policy_source_address_not_excluded_matches_set() {
    let snap = v3_rule("r-incl-src", &[], &["10.0.0.0/8"]);
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        std::slice::from_ref(&snap),
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
            "10.5.5.5".parse().expect("in-set src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit,
        "a source inside the (non-excluded) set must match"
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "192.168.1.5".parse().expect("out-of-set src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny,
        "a source outside the (non-excluded) set must NOT match"
    );
}

// #2008 H2: destination-address-excluded inverts the destination
// match independently of the source side.
#[test]
fn test_policy_destination_address_excluded_inverts_match() {
    let mut snap = v3_rule("r-excl-dst", &[], &["any"]);
    snap.destination_literals = vec!["172.16.0.0/16".to_string()];
    snap.destination_address_excluded = true;
    let counter_store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        std::slice::from_ref(&snap),
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    )
    .expect("parse");
    // Destination INSIDE the excluded set → must NOT match.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("excluded dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny,
        "a destination inside the excluded set must NOT match"
    );
    // Destination OUTSIDE the excluded set → matches.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "8.8.8.8".parse().expect("non-excluded dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit,
        "a destination outside the excluded set must match"
    );
}
