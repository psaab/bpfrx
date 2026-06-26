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

// #2508 fail-on-revert: the per-policy `then log session-init`/`session-close`
// flags must flow snapshot -> PolicyRule -> PolicyEvaluationResult so the
// session-install path can stamp them onto the session metadata. If any leg of
// that wiring is dropped, the matched result reports false and this fails. The
// implicit default-policy path (no rule match) reports false for both.
#[test]
fn evaluate_policy_result_carries_per_policy_log_flags() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            policy_id: 991,
            name: "permit-logged".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            action: "permit".to_string(),
            log_session_init: true,
            log_session_close: true,
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );

    let matched = evaluate_policy_result_with_len(
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
    assert_eq!(matched.action, PolicyAction::Permit);
    assert!(
        matched.log_session_init,
        "log_session_init must propagate snapshot -> rule -> eval result"
    );
    assert!(
        matched.log_session_close,
        "log_session_close must propagate snapshot -> rule -> eval result"
    );

    // A flow that matches NO explicit rule rides the implicit default policy,
    // which has no `then log` selection.
    let default_hit = evaluate_policy_result_with_len(
        &state,
        TEST_WAN_ZONE_ID,
        TEST_LAN_ZONE_ID,
        "172.16.80.200".parse().expect("src"),
        "10.0.61.100".parse().expect("dst"),
        PROTO_TCP,
        443,
        12345,
        64,
    );
    assert_eq!(default_hit.action, PolicyAction::Deny);
    assert!(!default_hit.log_session_init);
    assert!(!default_hit.log_session_close);
}

// #2508 fail-on-revert: a policy WITHOUT `then log` must report both flags
// false (the common case — most rules do not request session logging).
#[test]
fn evaluate_policy_result_unlogged_policy_reports_no_log_flags() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            policy_id: 992,
            name: "permit-quiet".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );

    let matched = evaluate_policy_result_with_len(
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
    assert_eq!(matched.action, PolicyAction::Permit);
    assert!(!matched.log_session_init);
    assert!(!matched.log_session_close);
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

// #2118: explicit permit AND explicit deny rules both attribute their
// hit to the matched rule's per-rule counter (visible in
// counter_snapshots), while a flow that matches NO explicit rule and
// rides the implicit default-deny increments NO per-rule counter. The
// last assertion is the load-bearing one for #2118: it proves that the
// "deny rows read 0" observed in the loss-cluster smoke is CORRECT when
// the config has only explicit permit rules plus default-policy
// deny-all — the blocked traffic rode the default-deny, which bumps the
// aggregate counter but no per-rule counter, so there is no bug to fix
// on the deny rows.
#[test]
fn hit_counter_attributes_permit_and_deny_but_not_default_deny() {
    let permit_id = "security-policy:lan:wan:permit-web".to_string();
    let deny_id = "security-policy:lan:wan:deny-ssh".to_string();
    let state = parse_policy_state(
        "deny",
        &[
            PolicyRuleSnapshot {
                rule_id: permit_id.clone(),
                name: "permit-web".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["10.0.0.0/8".to_string()],
                applications: vec!["any".to_string()],
                action: "permit".to_string(),
                ..Default::default()
            },
            PolicyRuleSnapshot {
                rule_id: deny_id.clone(),
                name: "deny-ssh".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["192.168.0.0/16".to_string()],
                applications: vec!["any".to_string()],
                action: "deny".to_string(),
                ..Default::default()
            },
        ],
        &test_zone_name_to_id(),
    );

    // Flow matching the explicit PERMIT rule (dst in 10.0.0.0/8).
    assert_eq!(
        evaluate_policy_with_len(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "10.0.2.5".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
            100,
        ),
        PolicyAction::Permit
    );
    // Flow matching the explicit DENY rule (dst in 192.168.0.0/16).
    assert_eq!(
        evaluate_policy_with_len(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "192.168.1.7".parse().expect("dst"),
            PROTO_TCP,
            12345,
            22,
            200,
        ),
        PolicyAction::Deny
    );
    // Flow matching NEITHER explicit rule (dst 172.16.x) -> implicit
    // default-deny.
    assert_eq!(
        evaluate_policy_with_len(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            443,
            300,
        ),
        PolicyAction::Deny
    );

    let permit_counter = policy_counter(&state, &permit_id);
    assert_eq!(permit_counter.packets, 1, "permit rule must record 1 hit");
    assert_eq!(permit_counter.bytes, 100);

    let deny_counter = policy_counter(&state, &deny_id);
    assert_eq!(deny_counter.packets, 1, "explicit deny rule must record 1 hit");
    assert_eq!(deny_counter.bytes, 200);

    // The default-deny flow must NOT have inflated either per-rule
    // counter — there is no rule_id for the default action, so no
    // per-rule counter exists for it (the aggregate policy_deny counter,
    // owned by the forwarding path, accounts for it instead).
    let total_per_rule_packets: u64 = state
        .counter_snapshots()
        .into_iter()
        .map(|c| c.packets)
        .sum();
    assert_eq!(
        total_per_rule_packets, 2,
        "default-deny must not increment any per-rule counter (only the \
         permit + explicit-deny hits should be attributed)"
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
                icmp_type: None,
                icmp_code: None,
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

// #2124 — a policy application term whose named protocol the Rust matcher
// previously could not parse (sctp/esp/ah/vrrp/igmp/pim/egp) silently failed
// OPEN to match-any: parse_protocol returned None, the term was dropped, and a
// rule whose only term dropped collapsed to match_any, permitting ALL traffic.
// These tests assert the named set now matches correctly AND that an
// all-unparseable term list fails CLOSED (whole-snapshot integrity error)
// rather than match-any.

fn proto_only_app_rule(rule_id: &str, protocol: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        rule_id: rule_id.to_string(),
        name: rule_id.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec![rule_id.to_string()],
        application_terms: vec![PolicyApplicationSnapshot {
            name: rule_id.to_string(),
            protocol: protocol.to_string(),
            source_port: String::new(),
            destination_port: String::new(),
            icmp_type: None,
            icmp_code: None,
        }],
        action: "permit".to_string(),
        ..Default::default()
    }
}

#[test]
fn named_protocol_sctp_matches_only_sctp_not_tcp() {
    // PROVES #2124(R-a): a permit rule for an sctp-only application permits
    // SCTP and DENIES TCP. Pre-fix the sctp term dropped -> match_any ->
    // TCP would be (wrongly) Permit, so this is non-tautological.
    let state = parse_policy_state(
        "deny",
        &[proto_only_app_rule("esp-or-sctp", "sctp")],
        &test_zone_name_to_id(),
    );
    let src = "10.0.61.100".parse().expect("src");
    let dst = "172.16.80.200".parse().expect("dst");
    assert_eq!(
        evaluate_policy(
            &state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, src, dst, PROTO_SCTP, 0, 0,
        ),
        PolicyAction::Permit,
        "sctp must match an sctp-only rule"
    );
    assert_eq!(
        evaluate_policy(
            &state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, src, dst, PROTO_TCP, 40000, 443,
        ),
        PolicyAction::Deny,
        "TCP must NOT match an sctp-only rule (no fail-open to match-any)"
    );
}

#[test]
fn named_protocol_esp_matches_only_esp_not_tcp() {
    let state = parse_policy_state(
        "deny",
        &[proto_only_app_rule("esp-only", "esp")],
        &test_zone_name_to_id(),
    );
    let src = "10.0.61.100".parse().expect("src");
    let dst = "172.16.80.200".parse().expect("dst");
    assert_eq!(
        evaluate_policy(
            &state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, src, dst, PROTO_ESP, 0, 0,
        ),
        PolicyAction::Permit
    );
    assert_eq!(
        evaluate_policy(
            &state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, src, dst, PROTO_TCP, 40000, 443,
        ),
        PolicyAction::Deny
    );
}

#[test]
fn named_protocol_parse_covers_full_iana_set() {
    // Every named protocol the Go validateProtocol/capability gate accepts must
    // resolve to its IANA number here, or the gate-and-matcher contract breaks.
    assert_eq!(parse_protocol("sctp"), Some(PROTO_SCTP));
    assert_eq!(parse_protocol("esp"), Some(PROTO_ESP));
    assert_eq!(parse_protocol("ah"), Some(PROTO_AH));
    assert_eq!(parse_protocol("vrrp"), Some(PROTO_VRRP));
    assert_eq!(parse_protocol("igmp"), Some(PROTO_IGMP));
    assert_eq!(parse_protocol("pim"), Some(PROTO_PIM));
    assert_eq!(parse_protocol("egp"), Some(PROTO_EGP));
    assert_eq!(parse_protocol("icmp6"), Some(PROTO_ICMPV6));
    // Numeric forms (including the canonicalized wire form the Go gate emits).
    assert_eq!(parse_protocol("132"), Some(PROTO_SCTP));
    assert_eq!(parse_protocol("50"), Some(PROTO_ESP));
    assert_eq!(parse_protocol("0"), Some(0));
    // Unparseable tokens stay None (so parse_applications drops + fails closed).
    assert_eq!(parse_protocol(""), None);
    assert_eq!(parse_protocol("definitely-not-a-proto"), None);
    assert_eq!(parse_protocol("__unsupported__"), None);
    assert_eq!(parse_protocol("256"), None);
}

#[test]
fn numeric_protocol_still_matches() {
    // Regression guard for the numeric parse arm.
    let state = parse_policy_state(
        "deny",
        &[proto_only_app_rule("num-132", "132")],
        &test_zone_name_to_id(),
    );
    let src = "10.0.61.100".parse().expect("src");
    let dst = "172.16.80.200".parse().expect("dst");
    assert_eq!(
        evaluate_policy(
            &state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, src, dst, PROTO_SCTP, 0, 0,
        ),
        PolicyAction::Permit
    );
    assert_eq!(
        evaluate_policy(
            &state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, src, dst, PROTO_TCP, 40000, 443,
        ),
        PolicyAction::Deny
    );
}

#[test]
fn all_unparseable_terms_fail_closed_with_integrity_error() {
    // PROVES #2124(R-b/Layer S): a rule whose application_terms are NON-empty
    // but ALL unparseable raises SnapshotIntegrityError instead of collapsing
    // to match-any. Pre-fix this returned Ok with a match_any rule (the
    // fail-open), so this is non-tautological.
    let store = PolicyCounterStore::default();
    let result = parse_policy_state_with_counters(
        "deny",
        &[proto_only_app_rule("bogus", "definitely-not-a-proto")],
        &test_zone_name_to_id(),
        &[],
        &store,
    );
    match result {
        Err(SnapshotIntegrityError::UnrepresentableApplicationProtocol { rule_id }) => {
            assert_eq!(rule_id, "bogus");
        }
        other => panic!("expected UnrepresentableApplicationProtocol, got {other:?}"),
    }
}

#[test]
fn go_unsupported_sentinel_fails_closed() {
    // Cross-language contract: the Go capability gate emits a "__unsupported__"
    // sentinel term for an unrepresentable application; Rust must drop it and
    // reject the whole snapshot (fail closed), NOT decode it as match-any.
    let store = PolicyCounterStore::default();
    let result = parse_policy_state_with_counters(
        "deny",
        &[proto_only_app_rule("sentinel-rule", "__unsupported__")],
        &test_zone_name_to_id(),
        &[],
        &store,
    );
    assert!(
        matches!(
            result,
            Err(SnapshotIntegrityError::UnrepresentableApplicationProtocol { .. })
        ),
        "the Go __unsupported__ sentinel must fail closed, got {result:?}"
    );
}

#[test]
fn empty_application_terms_stay_match_any() {
    // Regression guard: genuinely-empty application_terms (Junos
    // `application any` / no match application) must remain match-any and parse
    // Ok — the new integrity check must NOT fire here.
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            rule_id: "allow-any-app".to_string(),
            name: "allow-any-app".to_string(),
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
    let src = "10.0.61.100".parse().expect("src");
    let dst = "172.16.80.200".parse().expect("dst");
    // Both an arbitrary TCP flow and an SCTP flow must be permitted (match-any).
    assert_eq!(
        evaluate_policy(
            &state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, src, dst, PROTO_TCP, 40000, 443,
        ),
        PolicyAction::Permit
    );
    assert_eq!(
        evaluate_policy(
            &state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, src, dst, PROTO_SCTP, 0, 0,
        ),
        PolicyAction::Permit
    );
}

#[test]
fn mixed_parseable_and_unparseable_fails_closed() {
    // A rule with one parseable (esp) and one unparseable term has dropped_any
    // set, so it fails CLOSED (whole-snapshot integrity error) rather than
    // silently NARROWING the match by dropping the bad term. Narrowing matters
    // for a deny rule: a dropped term would let traffic the deny meant to block
    // fall through to a later permit / default. Normal Go snapshots never reach
    // this (the capability gate rejects any unrepresentable term before
    // publish); this is the corrupt/non-Go-snapshot backstop (Codex code-review
    // finding 2). Pre-fix this returned Ok with the bad term silently dropped.
    let store = PolicyCounterStore::default();
    let result = parse_policy_state_with_counters(
        "deny",
        &[PolicyRuleSnapshot {
            rule_id: "esp-plus-bogus".to_string(),
            name: "esp-plus-bogus".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["esp-plus-bogus".to_string()],
            application_terms: vec![
                PolicyApplicationSnapshot {
                    name: "esp".to_string(),
                    protocol: "esp".to_string(),
                    source_port: String::new(),
                    destination_port: String::new(),
                    icmp_type: None,
                    icmp_code: None,
                },
                PolicyApplicationSnapshot {
                    name: "bogus".to_string(),
                    protocol: "definitely-not-a-proto".to_string(),
                    source_port: String::new(),
                    destination_port: String::new(),
                    icmp_type: None,
                    icmp_code: None,
                },
            ],
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
        &[],
        &store,
    );
    assert!(
        matches!(
            result,
            Err(SnapshotIntegrityError::UnrepresentableApplicationProtocol { .. })
        ),
        "a partially-unparseable term list must fail closed, got {result:?}"
    );
}

#[test]
fn all_parseable_terms_match_each_protocol() {
    // Sanity: a rule with two fully-parseable terms (esp + tcp/443) parses Ok
    // and matches BOTH, without tripping the dropped_any backstop.
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            rule_id: "esp-and-https".to_string(),
            name: "esp-and-https".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["esp-and-https".to_string()],
            application_terms: vec![
                PolicyApplicationSnapshot {
                    name: "esp".to_string(),
                    protocol: "esp".to_string(),
                    source_port: String::new(),
                    destination_port: String::new(),
                    icmp_type: None,
                    icmp_code: None,
                },
                PolicyApplicationSnapshot {
                    name: "https".to_string(),
                    protocol: "tcp".to_string(),
                    source_port: String::new(),
                    destination_port: "443".to_string(),
                    icmp_type: None,
                    icmp_code: None,
                },
            ],
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );
    let src = "10.0.61.100".parse().expect("src");
    let dst = "172.16.80.200".parse().expect("dst");
    assert_eq!(
        evaluate_policy(
            &state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, src, dst, PROTO_ESP, 0, 0,
        ),
        PolicyAction::Permit,
        "esp term must match"
    );
    assert_eq!(
        evaluate_policy(
            &state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, src, dst, PROTO_TCP, 40000, 443,
        ),
        PolicyAction::Permit,
        "tcp/443 term must match"
    );
    assert_eq!(
        evaluate_policy(
            &state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, src, dst, PROTO_TCP, 40000, 80,
        ),
        PolicyAction::Deny,
        "tcp/80 must NOT match (not match-any)"
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
                    icmp_type: None,
                    icmp_code: None,
                },
                PolicyApplicationSnapshot {
                    name: "junos-https".to_string(),
                    protocol: "tcp".to_string(),
                    source_port: String::new(),
                    destination_port: "443".to_string(),
                    icmp_type: None,
                    icmp_code: None,
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

/// #3110: a flow whose ingress OR egress zone is the reserved
/// "unknown / no zone" sentinel (id 0 — an interface not bound to any
/// security zone, or the over-cap-zone collapse-to-0 path) must NOT be
/// eligible for `junos-global` policies. A configured permit-global
/// otherwise leaks transit on an unzoned ingress/egress interface. The
/// unknown-zone flow must fall through to the default action (deny).
/// Reverting the `from_id != 0 && to_id != 0` guard makes these RED.
#[test]
fn unknown_ingress_zone_does_not_match_permit_global() {
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
    // Unknown (0) ingress zone, valid egress zone -> default deny.
    assert_eq!(
        evaluate_policy(
            &state,
            0,
            TEST_WAN_ZONE_ID,
            "10.0.0.1".parse().expect("src"),
            "8.8.8.8".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Deny
    );
    // Valid ingress zone, unknown (0) egress zone -> default deny.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_TRUST_ZONE_ID,
            0,
            "10.0.0.1".parse().expect("src"),
            "8.8.8.8".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Deny
    );
    // Both unknown (0) -> default deny.
    assert_eq!(
        evaluate_policy(
            &state,
            0,
            0,
            "10.0.0.1".parse().expect("src"),
            "8.8.8.8".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Deny
    );
    // Sanity: both zones valid still hits the permit-global as before.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_TRUST_ZONE_ID,
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

/// #3057: a flow that matches NO configured policy rides the implicit
/// default-policy, whose evaluation result MUST carry the reserved
/// DEFAULT_POLICY_SENTINEL_ID — NOT 0, which aliased the first configured
/// policy (also ID 0) and caused the Go log/display planes to mis-attribute the
/// default deny to the first rule. The first configured rule here is a PERMIT
/// with policy_id 0; the no-match default deny must NOT borrow that identity.
#[test]
fn default_policy_no_match_emits_sentinel_policy_id() {
    let zones = test_zone_name_to_id();
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            // The first configured policy explicitly takes runtime ID 0 — the
            // value the old default-policy path collided with.
            policy_id: 0,
            name: "allow-web".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["10.0.61.0/24".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: "permit".into(),
            ..Default::default()
        }],
        &zones,
    );

    // A LAN→WAN flow whose source is OUTSIDE allow-web's 10.0.61.0/24 matches
    // no rule and rides the implicit default deny.
    let default_hit = evaluate_policy_result_with_len(
        &state,
        TEST_LAN_ZONE_ID,
        TEST_WAN_ZONE_ID,
        "203.0.113.7".parse().expect("src"),
        "8.8.8.8".parse().expect("dst"),
        PROTO_TCP,
        12345,
        80,
        64,
    );
    assert_eq!(default_hit.action, PolicyAction::Deny);
    assert_eq!(
        default_hit.policy_id,
        DEFAULT_POLICY_SENTINEL_ID,
        "the implicit default-policy must emit the reserved sentinel ID, not 0"
    );
    assert_ne!(
        default_hit.policy_id, 0,
        "policy_id 0 aliases the first configured policy (the #3057 bug)"
    );

    // Sanity: a flow that DOES match the first rule still carries its real
    // ID 0 — the sentinel only moves the implicit default, never a real policy.
    let matched = evaluate_policy_result_with_len(
        &state,
        TEST_LAN_ZONE_ID,
        TEST_WAN_ZONE_ID,
        "10.0.61.100".parse().expect("src"),
        "8.8.8.8".parse().expect("dst"),
        PROTO_TCP,
        12345,
        80,
        64,
    );
    assert_eq!(matched.action, PolicyAction::Permit);
    assert_eq!(matched.policy_id, 0, "the real first policy keeps ID 0");
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

// #2008 H11 (legacy path): the non-v3-shaped fallback that reads
// `source_addresses` / `destination_addresses` must family-scope
// `any-ipv4` / `any-ipv6` exactly like the v3 path. Before the fix the
// opposite family was built with `from_prefixes(empty)` == MatchAny, so
// a legacy rule keyed on `any-ipv4` STILL matched IPv6 (and the reverse
// for `any-ipv6`) — a cross-family leak.
//
// These tests drive the LEGACY field (no source_book_ids /
// source_literals → source_is_v3_shaped == false), which the v3-path
// tests above do not exercise.

fn legacy_addr_rule(name: &str, src: &[&str], dst: &[&str]) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: src.iter().map(|s| s.to_string()).collect(),
        destination_addresses: dst.iter().map(|s| s.to_string()).collect(),
        applications: vec!["any".to_string()],
        action: "permit".to_string(),
        ..Default::default()
    }
}

fn eval_legacy(rule: PolicyRuleSnapshot, src: &str, dst: &str) -> PolicyAction {
    let state = parse_policy_state("deny", std::slice::from_ref(&rule), &test_zone_name_to_id());
    evaluate_policy(
        &state,
        TEST_LAN_ZONE_ID,
        TEST_WAN_ZONE_ID,
        src.parse().expect("src"),
        dst.parse().expect("dst"),
        PROTO_TCP,
        12345,
        5201,
    )
}

#[test]
fn test_legacy_source_any_ipv4_denies_ipv6() {
    // source_addresses=["any-ipv4"], destination_addresses=["any"].
    // v4 src must permit; v6 src must NOT match (opposite family is
    // MatchNone, not MatchAny). Mutation sentinel: if the v6 set were
    // left MatchAny, the v6 case below would return Permit.
    let rule = legacy_addr_rule("legacy-any4-src", &["any-ipv4"], &["any"]);
    assert_eq!(
        eval_legacy(rule.clone(), "10.0.61.100", "172.16.80.200"),
        PolicyAction::Permit,
        "legacy any-ipv4 source must permit v4"
    );
    assert_eq!(
        eval_legacy(rule, "2001:db8::1", "2001:db8::2"),
        PolicyAction::Deny,
        "legacy any-ipv4 source must NOT match v6 (cross-family leak)"
    );
}

#[test]
fn test_legacy_source_any_ipv6_denies_ipv4() {
    let rule = legacy_addr_rule("legacy-any6-src", &["any-ipv6"], &["any"]);
    assert_eq!(
        eval_legacy(rule.clone(), "2001:db8::1", "2001:db8::2"),
        PolicyAction::Permit,
        "legacy any-ipv6 source must permit v6"
    );
    assert_eq!(
        eval_legacy(rule, "10.0.61.100", "172.16.80.200"),
        PolicyAction::Deny,
        "legacy any-ipv6 source must NOT match v4 (cross-family leak)"
    );
}

#[test]
fn test_legacy_destination_any_ipv4_denies_ipv6() {
    // Same leak on the destination side. source is "any" (both
    // families); only the family scoping of the destination set gates.
    let rule = legacy_addr_rule("legacy-any4-dst", &["any"], &["any-ipv4"]);
    assert_eq!(
        eval_legacy(rule.clone(), "10.0.61.100", "172.16.80.200"),
        PolicyAction::Permit,
        "legacy any-ipv4 destination must permit v4"
    );
    assert_eq!(
        eval_legacy(rule, "2001:db8::1", "2001:db8::2"),
        PolicyAction::Deny,
        "legacy any-ipv4 destination must NOT match v6 (cross-family leak)"
    );
}

#[test]
fn test_legacy_destination_any_ipv6_denies_ipv4() {
    let rule = legacy_addr_rule("legacy-any6-dst", &["any"], &["any-ipv6"]);
    assert_eq!(
        eval_legacy(rule.clone(), "2001:db8::1", "2001:db8::2"),
        PolicyAction::Permit,
        "legacy any-ipv6 destination must permit v6"
    );
    assert_eq!(
        eval_legacy(rule, "10.0.61.100", "172.16.80.200"),
        PolicyAction::Deny,
        "legacy any-ipv6 destination must NOT match v4 (cross-family leak)"
    );
}

#[test]
fn test_legacy_empty_source_still_match_any_both_families() {
    // Regression guard: with NO family-scoped wildcard, the legacy
    // empty→MatchAny convention must hold for BOTH families (the fix
    // must not over-tighten the unconstrained case to MatchNone).
    let rule = legacy_addr_rule("legacy-empty-src", &[], &["any"]);
    assert_eq!(
        eval_legacy(rule.clone(), "10.0.61.100", "172.16.80.200"),
        PolicyAction::Permit,
        "empty legacy source must match v4 (legacy MatchAny)"
    );
    assert_eq!(
        eval_legacy(rule, "2001:db8::1", "2001:db8::2"),
        PolicyAction::Permit,
        "empty legacy source must match v6 (legacy MatchAny)"
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

// #2008 fail-open hardening: an `*-excluded` side whose configured
// address set is unexpectedly EMPTY (e.g. a typo'd address that was
// silently dropped during parse) must fail CLOSED — it must NOT
// invert into match-ALL. The Go compiler now rejects such typos at
// commit, but the dataplane is hardened as defense-in-depth.
#[test]
fn test_empty_excluded_source_fails_closed_v4() {
    // source_literals=["totally-bogus"] drops to nothing → MatchNone →
    // source_v4_empty == true. With source_address_excluded, the side
    // must NOT match any v4 source (fail-closed), not match-all.
    let mut snap = v3_rule("r-empty-excl-src", &[], &["totally-bogus"]);
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
    // The dropped-typo set leaves the side empty; confirm the
    // precomputed flag agrees so the fail-closed branch is exercised.
    assert!(
        state.rules[0].source_v4_empty,
        "an all-dropped excluded source set must be flagged empty"
    );
    // Any v4 source → fail-closed → default-deny (NOT match-all).
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "8.8.8.8".parse().expect("src"),
            "1.1.1.1".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny,
        "an empty excluded source set must fail-closed, not match-all"
    );
}

#[test]
fn test_empty_excluded_destination_fails_closed_v6() {
    let mut snap = v3_rule("r-empty-excl-dst", &[], &["any"]);
    snap.destination_literals = vec!["not-an-address".to_string()];
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
    assert!(
        state.rules[0].destination_v6_empty,
        "an all-dropped excluded destination set must be flagged empty (v6)"
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
            5201,
        ),
        PolicyAction::Deny,
        "an empty excluded destination set must fail-closed, not match-all"
    );
}

// #3023: a `*-excluded` set that legitimately lists only ONE address
// family must NOT fail-closed for the OTHER family. A v6-only excluded
// source has an empty v4 family but a populated v6 family — a v4 source
// is trivially not in the (v6-only) excluded set, so it must MATCH. The
// #2008 per-family empty guard wrongly dropped all v4 traffic here; the
// fix gates fail-closed on emptiness across BOTH families.
#[test]
fn test_excluded_source_v6_only_permits_v4_3023() {
    let mut snap = v3_rule("r-excl-src-v6only", &[], &["2001:db8::/32"]);
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
    // One-family signal: v4 empty, v6 populated.
    assert!(
        state.rules[0].source_v4_empty,
        "a v6-only excluded source must have an empty v4 family"
    );
    assert!(
        !state.rules[0].source_v6_empty,
        "a v6-only excluded source must have a populated v6 family"
    );
    // A v4 source is not in the v6-only excluded set → permit (the bug).
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "8.8.8.8".parse().expect("v4 src"),
            "1.1.1.1".parse().expect("v4 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit,
        "#3023: a v4 source must match when only v6 is excluded"
    );
    // A v6 source INSIDE the excluded set is still excluded → deny.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "2001:db8::5".parse().expect("excluded v6 src"),
            "2001:db8:1::2".parse().expect("v6 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny,
        "a v6 source inside the excluded set must still be excluded"
    );
    // A v6 source OUTSIDE the excluded set → permit (inversion intact).
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "2001:dead::5".parse().expect("non-excluded v6 src"),
            "2001:db8:1::2".parse().expect("v6 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit,
        "a v6 source outside the excluded set must match"
    );
}

// #3023 mirror: a destination-address-excluded set listing only v4 must
// permit v6 destinations (v6 family empty, v4 populated → a v6 dst is
// trivially not-excluded). Symmetric to the source case above.
#[test]
fn test_excluded_destination_v4_only_permits_v6_3023() {
    let mut snap = v3_rule("r-excl-dst-v4only", &[], &["any"]);
    snap.destination_literals = vec!["10.0.0.0/8".to_string()];
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
    assert!(
        state.rules[0].destination_v6_empty,
        "a v4-only excluded destination must have an empty v6 family"
    );
    assert!(
        !state.rules[0].destination_v4_empty,
        "a v4-only excluded destination must have a populated v4 family"
    );
    // A v6 destination is not in the v4-only excluded set → permit.
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
        "#3023: a v6 destination must match when only v4 is excluded"
    );
    // A v4 destination INSIDE the excluded set is still excluded → deny.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "192.168.1.5".parse().expect("v4 src"),
            "10.5.5.5".parse().expect("excluded v4 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny,
        "a v4 destination inside the excluded set must still be excluded"
    );
    // A v4 destination OUTSIDE the excluded set → permit.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "192.168.1.5".parse().expect("v4 src"),
            "8.8.8.8".parse().expect("non-excluded v4 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit,
        "a v4 destination outside the excluded set must match"
    );
}

// #2008 contract preserved by #3023: when the excluded set is empty
// across BOTH families (genuine typo/parse-drop), it must STILL
// fail-closed for v4 AND v6. The one-family relief must not relax the
// true empty-set case — this stays GREEN before and after the #3023 fix.
#[test]
fn test_fully_empty_excluded_source_fails_closed_both_families_3023() {
    let mut snap = v3_rule("r-fully-empty-excl-src", &[], &["totally-bogus"]);
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
    assert!(
        state.rules[0].source_v4_empty && state.rules[0].source_v6_empty,
        "a fully-dropped excluded source set is empty across both families"
    );
    // v4 packet → fail-closed.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "8.8.8.8".parse().expect("v4 src"),
            "1.1.1.1".parse().expect("v4 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny,
        "a fully-empty excluded source must fail-closed for v4 (#2008)"
    );
    // v6 packet → fail-closed.
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
        "a fully-empty excluded source must fail-closed for v6 (#2008)"
    );
}

// Mutation sentinel for the fail-closed change: a NON-empty excluded
// set must STILL invert (this passes only because the fail-closed
// guard is gated on the empty flag, not applied unconditionally — if
// the guard were `false &&` the non-excluded-address case below would
// wrongly become Deny).
#[test]
fn test_nonempty_excluded_still_inverts_after_fail_closed_guard() {
    let mut snap = v3_rule("r-nonempty-excl", &[], &["10.0.0.0/8"]);
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
    assert!(
        !state.rules[0].source_v4_empty,
        "a non-empty excluded set must NOT be flagged empty"
    );
    // Outside the excluded set → still matches (inversion intact).
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
        "a non-empty excluded set must still invert (outside set matches)"
    );
    // Inside the excluded set → no match.
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
        "a source inside the (non-empty) excluded set must NOT match"
    );
}

// #2008 — Copilot match_any-under-exclusion finding (PR #2013).
// `source-address any; source-address-excluded;` is the degenerate but
// valid idiom "match if the source is NOT in `any`" — which is NOTHING.
// The `any` literal compiles to MatchAny, so source_v4_match_any is set,
// yet the excluded branch deliberately DROPS the match_any short-circuit
// and instead asks `!(MatchAny.contains(src))`, which is `!true` = false
// for every source → fail-closed deny. This pins that an excluded-`any`
// rule denies ALL v4 traffic (NOT match-all, the bug Copilot worried
// about). Mutation: if the excluded branch reused
// `source_v4_match_any || ...` as the in-set predicate it would still be
// correct here (MatchAny contains everything); the real regression guard
// is that the excluded branch never short-circuits to src_ok=true on
// match_any — verified by the Permit assertion in case 4 below.
#[test]
fn test_policy_source_any_excluded_denies_all_v4() {
    let mut snap = v3_rule("r-any-excl-src-v4", &[], &["any"]);
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
    // `any` → MatchAny on both families, so match_any is set but NOT
    // empty (MatchAny is not MatchNone). The deny comes from the inner
    // `!contains`, not from the empty fail-closed guard.
    assert!(
        state.rules[0].source_v4_match_any,
        "an excluded `any` source must still flag v4 match_any"
    );
    assert!(
        !state.rules[0].source_v4_empty,
        "an excluded `any` source is NOT the empty set (MatchAny != MatchNone)"
    );
    for src in ["8.8.8.8", "10.5.5.5", "192.168.1.5"] {
        assert_eq!(
            evaluate_policy(
                &state,
                TEST_LAN_ZONE_ID,
                TEST_WAN_ZONE_ID,
                src.parse().expect("src"),
                "172.16.80.200".parse().expect("dst"),
                PROTO_TCP,
                12345,
                5201,
            ),
            PolicyAction::Deny,
            "`source-address any; excluded;` must deny ALL v4 sources, not match-all"
        );
    }
}

// #2008 — v6 mirror of the excluded-`any` case. `any` covers both
// families, so an excluded `any` source must also deny ALL v6 traffic.
#[test]
fn test_policy_source_any_excluded_denies_all_v6() {
    let mut snap = v3_rule("r-any-excl-src-v6", &[], &["any"]);
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
    assert!(
        state.rules[0].source_v6_match_any,
        "an excluded `any` source must still flag v6 match_any"
    );
    assert!(
        !state.rules[0].source_v6_empty,
        "an excluded `any` source is NOT the empty set on v6 either"
    );
    for src in ["2001:db8::1", "fe80::1", "::1"] {
        assert_eq!(
            evaluate_policy(
                &state,
                TEST_LAN_ZONE_ID,
                TEST_WAN_ZONE_ID,
                src.parse().expect("src"),
                "2001:db8::2".parse().expect("dst"),
                PROTO_TCP,
                12345,
                5201,
            ),
            PolicyAction::Deny,
            "`source-address any; excluded;` must deny ALL v6 sources, not match-all"
        );
    }
}

// #2008 — destination mirror of the excluded-`any` case.
#[test]
fn test_policy_destination_any_excluded_denies_all_v4() {
    let mut snap = v3_rule("r-any-excl-dst-v4", &[], &["any"]);
    // destination defaults to `any` in v3_rule; mark it excluded.
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
    assert!(
        state.rules[0].destination_v4_match_any,
        "an excluded `any` destination must still flag v4 match_any"
    );
    assert!(
        !state.rules[0].destination_v4_empty,
        "an excluded `any` destination is NOT the empty set"
    );
    for dst in ["8.8.8.8", "172.16.80.200", "1.1.1.1"] {
        assert_eq!(
            evaluate_policy(
                &state,
                TEST_LAN_ZONE_ID,
                TEST_WAN_ZONE_ID,
                "10.0.61.100".parse().expect("src"),
                dst.parse().expect("dst"),
                PROTO_TCP,
                12345,
                5201,
            ),
            PolicyAction::Deny,
            "`destination-address any; excluded;` must deny ALL v4 destinations"
        );
    }
}

// #2008 — regression sentinel for Copilot's concern: `source-address
// any;` WITHOUT exclusion MUST still match every source (the match_any
// short-circuit is preserved on the non-excluded path). This is the
// case that would break if a fix naively dropped match_any handling
// outright; the excluded-`any` deny tests above MUST coexist with this
// match-all behavior. v4 and v6.
#[test]
fn test_policy_source_any_not_excluded_matches_all() {
    let snap = v3_rule("r-any-incl-src", &[], &["any"]);
    let counter_store = PolicyCounterStore::default();
    // Default action is `deny` so a Permit can ONLY come from the rule
    // matching (match-all), never from the default fallback — without
    // this a non-matching rule would also return Permit and the test
    // would not detect a broken match path.
    let state = parse_policy_state_with_counters(
        "deny",
        std::slice::from_ref(&snap),
        &test_zone_name_to_id(),
        &[],
        &counter_store,
    )
    .expect("parse");
    assert!(
        !state.rules[0].source_excluded,
        "non-excluded `any` source must not set the excluded flag"
    );
    // v4: every source matches via match_any.
    for (src, dst) in [
        ("8.8.8.8", "1.1.1.1"),
        ("10.5.5.5", "172.16.80.200"),
        ("192.168.1.5", "203.0.113.7"),
    ] {
        assert_eq!(
            evaluate_policy(
                &state,
                TEST_LAN_ZONE_ID,
                TEST_WAN_ZONE_ID,
                src.parse().expect("src"),
                dst.parse().expect("dst"),
                PROTO_TCP,
                12345,
                5201,
            ),
            PolicyAction::Permit,
            "`source-address any;` (no exclusion) must match every v4 source"
        );
    }
    // v6: every source matches via match_any (both-family `any`).
    for (src, dst) in [("2001:db8::1", "2001:db8::2"), ("fe80::1", "2001:db8::9")] {
        assert_eq!(
            evaluate_policy(
                &state,
                TEST_LAN_ZONE_ID,
                TEST_WAN_ZONE_ID,
                src.parse().expect("src"),
                dst.parse().expect("dst"),
                PROTO_TCP,
                12345,
                5201,
            ),
            PolicyAction::Permit,
            "`source-address any;` (no exclusion) must match every v6 source"
        );
    }
}

// #2008 — v6 mirror of the source-excluded inversion (case 1): a v6
// literal set with `source-address-excluded` matches every v6 source
// EXCEPT those in the set. The existing inversion test covers v4 only.
#[test]
fn test_policy_source_address_excluded_inverts_match_v6() {
    let mut snap = v3_rule("r-excl-src-v6", &[], &["2001:db8:dead::/48"]);
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
    // Source INSIDE the excluded v6 set → must NOT match → default-deny.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "2001:db8:dead::5".parse().expect("excluded v6 src"),
            "2001:db8::2".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny,
        "a v6 source inside the excluded set must NOT match"
    );
    // Source OUTSIDE the excluded v6 set → matches → permit.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "2001:db8:beef::5".parse().expect("non-excluded v6 src"),
            "2001:db8::2".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit,
        "a v6 source outside the excluded set must match"
    );
}

// ── #2008 M5: application-identification catalog matcher ──

fn cat_entry(app_id: u16, proto: u8, dlo: u16, dhi: u16) -> crate::AppCatalogEntry {
    crate::AppCatalogEntry {
        app_id,
        protocol: proto,
        dst_port_low: dlo,
        dst_port_high: dhi,
        src_port_low: 0,
        src_port_high: 0,
    }
}

// The core stamp behaviour: a session on a catalog application's service port
// resolves to that app_id. This is the assertion that regresses to 0 if the
// session-create path stops calling AppCatalog::lookup (mutation-verify of the
// #2008 M5 stamp).
#[test]
fn app_catalog_exact_dst_port_resolves_id() {
    let cat = AppCatalog::from_snapshot(&[cat_entry(7, 6, 443, 443)]);
    // forward session: client ephemeral src -> server dst 443.
    assert_eq!(cat.lookup(6, 51000, 443), 7);
    // reverse-keyed session carries the service port in the src slot.
    assert_eq!(cat.lookup(6, 443, 51000), 7);
    // wrong protocol on the same port is not the app.
    assert_eq!(cat.lookup(17, 51000, 443), 0);
    // unrelated port resolves to unknown (0).
    assert_eq!(cat.lookup(6, 51000, 80), 0);
}

#[test]
fn app_catalog_port_range_resolves_id() {
    let cat = AppCatalog::from_snapshot(&[cat_entry(9, 6, 9000, 9100)]);
    assert_eq!(cat.lookup(6, 40000, 9000), 9); // low edge
    assert_eq!(cat.lookup(6, 40000, 9100), 9); // high edge
    assert_eq!(cat.lookup(6, 40000, 9050), 9); // interior
    assert_eq!(cat.lookup(6, 40000, 8999), 0); // below
    assert_eq!(cat.lookup(6, 40000, 9101), 0); // above
    // reverse-keyed: service-port range in the src slot still resolves.
    assert_eq!(cat.lookup(6, 9050, 40000), 9);
}

// A (0,0) dst-port pair means "protocol-only" (e.g. ICMP) — match on protocol
// regardless of ports.
#[test]
fn app_catalog_protocol_only_entry() {
    let cat = AppCatalog::from_snapshot(&[cat_entry(3, 1, 0, 0)]); // ICMP
    assert_eq!(cat.lookup(1, 0, 0), 3);
    assert_eq!(cat.lookup(1, 1234, 5678), 3);
    assert_eq!(cat.lookup(6, 1234, 5678), 0); // different protocol
}

// app_id 0 is the reserved unknown sentinel and must never be indexed even if a
// malformed snapshot carries it.
#[test]
fn app_catalog_skips_zero_app_id() {
    let cat = AppCatalog::from_snapshot(&[cat_entry(0, 6, 443, 443)]);
    assert!(cat.is_empty());
    assert_eq!(cat.lookup(6, 51000, 443), 0);
}

// Overlapping entries: first/lowest app_id wins, deterministically (the Go
// builder emits ascending ids in sorted-name order).
#[test]
fn app_catalog_overlap_lowest_id_wins() {
    // Two apps both claiming tcp/80 — exact-port path.
    let cat = AppCatalog::from_snapshot(&[cat_entry(5, 6, 80, 80), cat_entry(11, 6, 80, 80)]);
    assert_eq!(cat.lookup(6, 40000, 80), 5);

    // Range vs exact overlap — lowest id still wins.
    let cat = AppCatalog::from_snapshot(&[cat_entry(2, 6, 8000, 8100), cat_entry(20, 6, 8050, 8050)]);
    assert_eq!(cat.lookup(6, 40000, 8050), 2);
}

#[test]
fn app_catalog_empty_resolves_unknown() {
    let cat = AppCatalog::default();
    assert!(cat.is_empty());
    assert_eq!(cat.lookup(6, 51000, 443), 0);
}

// ---------------------------------------------------------------------------
// #3020 — junos-ping / junos-pingv6 are echo-request ONLY (ICMP type 8 /
// ICMPv6 type 128), not every ICMP type. The all-ICMP aliases stay
// unconstrained. The matcher gates an icmp-type-constrained term on the
// packet's ICMP type/code, which is threaded into
// `evaluate_policy_result_with_len` as `packet_icmp`.
// ---------------------------------------------------------------------------

fn icmp_app_rule(name: &str, protocol: &str, icmp_type: Option<u8>) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec![name.to_string()],
        application_terms: vec![PolicyApplicationSnapshot {
            name: name.to_string(),
            protocol: protocol.to_string(),
            source_port: String::new(),
            destination_port: String::new(),
            icmp_type,
            icmp_code: None,
        }],
        action: "permit".to_string(),
        ..Default::default()
    }
}

fn eval_icmp(state: &PolicyState, protocol: u8, icmp_type: u8, icmp_code: u8) -> PolicyAction {
    evaluate_policy_result_with_icmp(
        state,
        TEST_LAN_ZONE_ID,
        TEST_WAN_ZONE_ID,
        "10.0.61.100".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        protocol,
        0,
        0,
        Some((icmp_type, icmp_code)),
        0,
    )
    .action
}

#[test]
fn junos_ping_matches_echo_request_only() {
    let state = parse_policy_state(
        "deny",
        &[icmp_app_rule("junos-ping", "icmp", Some(8))],
        &test_zone_name_to_id(),
    );
    // Echo-request (type 8) is permitted.
    assert_eq!(eval_icmp(&state, PROTO_ICMP, 8, 0), PolicyAction::Permit);
    // Echo-reply (type 0) must NOT match — falls through to default deny.
    assert_eq!(eval_icmp(&state, PROTO_ICMP, 0, 0), PolicyAction::Deny);
    // Destination-unreachable (type 3) must NOT match.
    assert_eq!(eval_icmp(&state, PROTO_ICMP, 3, 1), PolicyAction::Deny);
}

#[test]
fn junos_pingv6_matches_echo_request_only() {
    let state = parse_policy_state(
        "deny",
        &[icmp_app_rule("junos-pingv6", "icmpv6", Some(128))],
        &test_zone_name_to_id(),
    );
    // ICMPv6 echo-request is type 128.
    assert_eq!(eval_icmp(&state, PROTO_ICMPV6, 128, 0), PolicyAction::Permit);
    // Echo-reply is 129 — must NOT match.
    assert_eq!(eval_icmp(&state, PROTO_ICMPV6, 129, 0), PolicyAction::Deny);
    // Neighbor solicitation (135) — must NOT match.
    assert_eq!(eval_icmp(&state, PROTO_ICMPV6, 135, 0), PolicyAction::Deny);
}

#[test]
fn junos_icmp_all_matches_every_type() {
    // Regression: an UNCONSTRAINED ICMP term (junos-icmp-all) still matches
    // every ICMP type/code, regardless of the packet's type.
    let state = parse_policy_state(
        "deny",
        &[icmp_app_rule("junos-icmp-all", "icmp", None)],
        &test_zone_name_to_id(),
    );
    for t in [0u8, 3, 8, 11, 13] {
        assert_eq!(
            eval_icmp(&state, PROTO_ICMP, t, 0),
            PolicyAction::Permit,
            "junos-icmp-all must match ICMP type {t}"
        );
    }
}

#[test]
fn junos_ping_with_icmp_all_matches_every_type() {
    // A rule citing BOTH junos-ping AND junos-icmp-all matches all ICMP: the
    // unconstrained term short-circuits the type constraint.
    let mut rule = icmp_app_rule("ping-and-all", "icmp", Some(8));
    rule.application_terms.push(PolicyApplicationSnapshot {
        name: "junos-icmp-all".to_string(),
        protocol: "icmp".to_string(),
        source_port: String::new(),
        destination_port: String::new(),
        icmp_type: None,
        icmp_code: None,
    });
    let state = parse_policy_state("deny", &[rule], &test_zone_name_to_id());
    assert_eq!(eval_icmp(&state, PROTO_ICMP, 8, 0), PolicyAction::Permit);
    assert_eq!(eval_icmp(&state, PROTO_ICMP, 3, 0), PolicyAction::Permit);
}

#[test]
fn icmp_constraint_does_not_affect_tcp_app() {
    // A TCP application is completely unaffected by the icmp constraint path.
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
                icmp_type: None,
                icmp_code: None,
            }],
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );
    // TCP/80 permitted; a None packet_icmp (non-ICMP) is irrelevant.
    assert_eq!(
        evaluate_policy_result_with_icmp(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            40000,
            80,
            None,
            0,
        )
        .action,
        PolicyAction::Permit
    );
}

#[test]
fn junos_ping_unknown_icmp_type_fails_closed() {
    // When the packet's ICMP type/code is unknown (truncated frame / non-first
    // fragment → packet_icmp == None), an icmp-type-constrained term must NOT
    // match (fail closed) rather than matching a fabricated type 0.
    let state = parse_policy_state(
        "deny",
        &[icmp_app_rule("junos-ping", "icmp", Some(8))],
        &test_zone_name_to_id(),
    );
    let action = evaluate_policy_result_with_icmp(
        &state,
        TEST_LAN_ZONE_ID,
        TEST_WAN_ZONE_ID,
        "10.0.61.100".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        PROTO_ICMP,
        0,
        0,
        None, // type/code unknown
        0,
    )
    .action;
    assert_eq!(action, PolicyAction::Deny);
}

#[test]
fn icmp_skew_old_snapshot_without_type_matches_all() {
    // Version skew: a snapshot whose application term OMITS the icmp_type field
    // (old Go control plane) decodes to icmp_type=None → the term is
    // unconstrained and matches every ICMP type — today's pre-#3020 behavior,
    // so skew degrades safely to match-all rather than failing to decode.
    let json = r#"{
        "name": "legacy-ping",
        "from_zone": "lan",
        "to_zone": "wan",
        "source_addresses": ["any"],
        "destination_addresses": ["any"],
        "applications": ["junos-ping"],
        "application_terms": [{"name": "junos-ping", "protocol": "icmp"}],
        "action": "permit"
    }"#;
    let snap: PolicyRuleSnapshot =
        serde_json::from_str(json).expect("legacy snapshot without icmp_type decodes");
    assert!(
        snap.application_terms[0].icmp_type.is_none(),
        "omitted icmp_type must decode to None"
    );
    let state = parse_policy_state("deny", &[snap], &test_zone_name_to_id());
    assert_eq!(eval_icmp(&state, PROTO_ICMP, 8, 0), PolicyAction::Permit);
    assert_eq!(eval_icmp(&state, PROTO_ICMP, 3, 0), PolicyAction::Permit);
}
