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

/// #3395: a minimal lan->wan permit rule carrying an explicit positional
/// `policy_id`. The stable rule_id derives from from/to/name
/// (`lan->wan/<name>`), independent of `policy_id`, so the same logical rule
/// keeps its identity across a renumbering edit.
fn permit_snapshot(name: &str, policy_id: u32) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: name.to_string(),
        policy_id,
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
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

// #3534 fail-on-revert: the IMPLICIT default-policy verdict must carry the
// operator's `security policies default-policy-log session-init/session-close`
// selection so a default-PERMIT session emits RT_FLOW_SESSION_CREATE/CLOSE like
// a named policy's `then log`. PolicyState.default_log_session_* is set from the
// snapshot at build time (build_forwarding_state_*); here we set it directly on
// a parsed state. Reverting policy.rs to hardcode `log_session_init: false` on
// the default verdict makes the "selected" assertions RED.
#[test]
fn default_verdict_carries_default_policy_log_flags() {
    // permit default so the no-match flow rides a default-PERMIT verdict.
    let mut state = parse_policy_state("permit", &[], &test_zone_name_to_id());
    state.default_log_session_init = true;
    state.default_log_session_close = true;

    let default_hit = evaluate_policy_result_with_len(
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
    assert_eq!(default_hit.action, PolicyAction::Permit);
    assert!(
        default_hit.log_session_init,
        "default verdict must carry default-policy-log session-init"
    );
    assert!(
        default_hit.log_session_close,
        "default verdict must carry default-policy-log session-close"
    );

    // Gating: a default state WITHOUT the selection reports both flags false
    // (the historical behaviour — proves the flags are not spuriously set).
    let quiet = parse_policy_state("permit", &[], &test_zone_name_to_id());
    let quiet_hit = evaluate_policy_result_with_len(
        &quiet,
        TEST_LAN_ZONE_ID,
        TEST_WAN_ZONE_ID,
        "10.0.61.100".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        PROTO_TCP,
        12345,
        443,
        64,
    );
    assert!(!quiet_hit.log_session_init);
    assert!(!quiet_hit.log_session_close);
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

// #2118 / #3363: explicit permit AND explicit deny rules both attribute
// their hit to the matched rule's per-rule counter (visible in
// counter_snapshots). A flow that matches NO explicit rule and rides the
// implicit default-deny attributes its hit to the RESERVED default-policy
// counter (#3363) — NOT to any named per-rule counter. Before #3363 the
// default verdict incremented nothing; this asserts the named counters
// stay clean of default-deny traffic AND that the default counter now
// captures it under its reserved rule id.
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

    // #3363: the default-deny flow must NOT have inflated either NAMED
    // per-rule counter — only the explicit permit + deny hits attribute to
    // those. The sum across the named rules is therefore exactly 2.
    let named_per_rule_packets: u64 = state
        .counter_snapshots()
        .into_iter()
        .filter(|c| c.rule_id != "default-policy")
        .map(|c| c.packets)
        .sum();
    assert_eq!(
        named_per_rule_packets, 2,
        "default-deny must not increment any NAMED per-rule counter (only \
         the permit + explicit-deny hits should be attributed)"
    );

    // #3363: the default-deny flow IS captured by the reserved default-policy
    // counter (1 packet, 300 bytes) — the implicit catch-all is now visible.
    let default_counter = policy_counter(&state, "default-policy");
    assert_eq!(
        default_counter.packets, 1,
        "the implicit default-deny flow must increment the reserved \
         default-policy counter"
    );
    assert_eq!(default_counter.bytes, 300);
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
    // #3363: counter_snapshots always carries the reserved default-policy
    // row, so the only surviving counter after deleting every named rule is
    // that reserved one — no NAMED rule counter remains.
    let deleted_named: Vec<_> = deleted
        .counter_snapshots()
        .into_iter()
        .filter(|c| c.rule_id != "default-policy")
        .collect();
    assert!(deleted_named.is_empty());

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

// ── #3395: positional policy_id re-resolution at the local publish surfaces ──
//
// `policy_id` (#3056) is span-accumulated in config order, frozen onto a session
// at install. A live mid-list policy insert/delete renumbers every later rule,
// so the frozen id resolves to the WRONG policy's name afterwards (the
// display/forensic sibling of the #3322 hit-counter bug). The fix re-resolves
// the CURRENT positional id from the session's BOUND rule handle
// (`PolicyState::reresolve_session_policy_id`) at the live-row refresh and the
// RT_FLOW SESSION_CLOSE emit — the exact SSOT both call sites use. These tests
// pin that SSOT; the close-path wiring is pinned end-to-end by
// `flush_session_deltas_session_close_reresolves_policy_id_after_reorder`
// (afxdp/session_glue/tests.rs).

#[test]
fn policy_id_reresolves_to_current_index_after_mid_list_insert() {
    // RED-on-revert: an established session admitted by rule "bee" at positional
    // id 5 must report bee's NEW positional id after a live insert shifts it —
    // NOT the frozen install-time id 5. Reverting reresolve_session_policy_id to
    // return the frozen `stamped` argument makes this read 5 → RED.
    let store = PolicyCounterStore::default();
    // Snapshot 1: bee is the only rule, positional id 5. The session binds bee's
    // hit-counter Arc at install (the #3322 handle), which now also carries bee's
    // stable rule_id.
    let s1 = parse_policy_state_with_counters(
        "deny",
        &[permit_snapshot("bee", 5)],
        &test_zone_name_to_id(),
        &[],
        &store,
    )
    .expect("s1");
    let bound_bee = s1.hit_counter_by_idx(1).cloned().expect("bee bound handle");
    assert_eq!(bound_bee.rule_id(), "lan->wan/bee");

    // Snapshot 2: rule "aaa" is inserted ABOVE bee, so bee renumbers 5 -> 6.
    let s2 = parse_policy_state_with_counters(
        "deny",
        &[permit_snapshot("aaa", 5), permit_snapshot("bee", 6)],
        &test_zone_name_to_id(),
        &[],
        &store,
    )
    .expect("s2");

    assert_eq!(
        s2.reresolve_session_policy_id(Some(&bound_bee), 5),
        6,
        "established session must re-resolve to bee's CURRENT positional id (6), \
         not the frozen install-time id (5)"
    );
}

#[test]
fn deleted_rule_resolves_to_unattributed_sentinel_not_reassigned_index() {
    // #3395 / AGY catch RED-on-revert: when the admitting rule is DELETED a
    // session must resolve to the unattributed default-policy sentinel — NOT the
    // frozen positional id, which a later reorder can reassign to a DIFFERENT
    // extant rule (a confident mis-attribution). Reverting the deleted-rule
    // fallback from `unwrap_or(DEFAULT_POLICY_SENTINEL_ID)` to
    // `unwrap_or(stamped)` resolves to 5 (now cee) → RED.
    let store = PolicyCounterStore::default();
    let s1 = parse_policy_state_with_counters(
        "deny",
        &[permit_snapshot("bee", 5)],
        &test_zone_name_to_id(),
        &[],
        &store,
    )
    .expect("s1");
    let bound_bee = s1.hit_counter_by_idx(1).cloned().expect("bee bound handle");

    // Snapshot 3: bee is DELETED; a DIFFERENT rule "cee" now occupies the freed
    // positional id 5. bee's rule_id is absent from s3.
    store.reconcile_rules(&[permit_snapshot("cee", 5)]);
    let s3 = parse_policy_state_with_counters(
        "deny",
        &[permit_snapshot("cee", 5)],
        &test_zone_name_to_id(),
        &[],
        &store,
    )
    .expect("s3");

    let resolved = s3.reresolve_session_policy_id(Some(&bound_bee), 5);
    assert_eq!(
        resolved, DEFAULT_POLICY_SENTINEL_ID,
        "deleted admitting rule must resolve to the unattributed default-policy \
         sentinel"
    );
    assert_ne!(
        resolved, 5,
        "must NOT resolve to the frozen id 5 — cee now occupies that index"
    );
}

#[test]
fn unbound_session_keeps_frozen_policy_id() {
    // #3395: an unbound session (idx-0 non-policy: host-local / neighbor-seed /
    // fabric / tunnel; or a peer-synced session carrying only the wire scalar)
    // has no local stable identity to re-resolve from, so it keeps its frozen id.
    // A no-policy session must stay 0 (NOT promoted to the default-policy
    // sentinel — that would regress the "no policy" rendering).
    let store = PolicyCounterStore::default();
    let s = parse_policy_state_with_counters(
        "deny",
        &[permit_snapshot("bee", 5)],
        &test_zone_name_to_id(),
        &[],
        &store,
    )
    .expect("s");
    assert_eq!(s.reresolve_session_policy_id(None, 7), 7);
    assert_eq!(s.reresolve_session_policy_id(None, 0), 0);
}

#[test]
fn default_policy_session_reresolves_to_sentinel() {
    // #3395: a default-PERMIT session (#3363) binds the reserved default_counter
    // (rule_id "default-policy") and is stamped with DEFAULT_POLICY_SENTINEL_ID.
    // After a reorder it must re-resolve STABLY to the sentinel — NOT fall into
    // the deleted-rule arm — because the default policy maps to the sentinel in
    // the per-snapshot map.
    let store = PolicyCounterStore::default();
    let s = parse_policy_state_with_counters(
        "deny",
        &[permit_snapshot("aaa", 5), permit_snapshot("bee", 6)],
        &test_zone_name_to_id(),
        &[],
        &store,
    )
    .expect("s");
    let bound_default = s
        .hit_counter_by_idx(DEFAULT_POLICY_COUNTER_IDX)
        .cloned()
        .expect("default-policy bound handle");
    assert_eq!(bound_default.rule_id(), DEFAULT_POLICY_COUNTER_RULE_ID);
    assert_eq!(
        s.reresolve_session_policy_id(Some(&bound_default), DEFAULT_POLICY_SENTINEL_ID),
        DEFAULT_POLICY_SENTINEL_ID,
    );
}

#[test]
fn fresh_flow_policy_id_reresolution_is_noop() {
    // #3395: a flow freshly admitted under the CURRENT snapshot re-resolves to
    // exactly its rule's current positional id — re-resolution introduces no
    // #3063 Index↔RT_FLOW drift for fresh flows.
    let store = PolicyCounterStore::default();
    let s = parse_policy_state_with_counters(
        "deny",
        &[permit_snapshot("aaa", 5), permit_snapshot("bee", 6)],
        &test_zone_name_to_id(),
        &[],
        &store,
    )
    .expect("s");
    let bee = s.hit_counter_by_idx(2).cloned().expect("bee");
    assert_eq!(s.rules[1].policy_id, 6);
    assert_eq!(s.reresolve_session_policy_id(Some(&bee), 6), 6);
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
                inactivity_timeout: None,
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
            inactivity_timeout: None,
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
fn malformed_legacy_source_address_fails_closed_with_integrity_error() {
    // #3367 RED-on-revert: a rule whose LEGACY `source_addresses` field carries a
    // token that is non-empty, non-`any`, non-family-wildcard, and unparseable as
    // an IP/CIDR must reject the WHOLE snapshot. Pre-fix `parse_address` silently
    // dropped the bad token; with no family-scoped wildcard present the side then
    // collapsed to the empty->MatchAny legacy convention, so a `deny` rule scoped
    // to one (mistyped) address WIDENED to match every source (fail-OPEN).
    // Reverting the fix returns Ok(state) with a match-any source, so this is
    // non-tautological.
    let store = PolicyCounterStore::default();
    let bad = PolicyRuleSnapshot {
        rule_id: "bad-src".to_string(),
        name: "deny-host".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        // Legacy path: no source_literals / source_book_ids, so this is parsed by
        // parse_legacy_address_set. "10.0.0.999" is not a valid IPv4.
        source_addresses: vec!["10.0.0.999".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "deny".to_string(),
        ..Default::default()
    };
    let result =
        parse_policy_state_with_counters("deny", &[bad], &test_zone_name_to_id(), &[], &store);
    match result {
        Err(SnapshotIntegrityError::UnrepresentableLegacyAddress { rule_id, address }) => {
            assert_eq!(rule_id, "bad-src");
            assert_eq!(address, "10.0.0.999");
        }
        other => panic!("expected UnrepresentableLegacyAddress, got {other:?}"),
    }
}

#[test]
fn malformed_legacy_destination_address_fails_closed() {
    // #3367: the destination side of the legacy field is guarded identically.
    let store = PolicyCounterStore::default();
    let bad = PolicyRuleSnapshot {
        rule_id: "bad-dst".to_string(),
        name: "deny-host".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["not-an-address".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "deny".to_string(),
        ..Default::default()
    };
    let result =
        parse_policy_state_with_counters("deny", &[bad], &test_zone_name_to_id(), &[], &store);
    match result {
        Err(SnapshotIntegrityError::UnrepresentableLegacyAddress { rule_id, address }) => {
            assert_eq!(rule_id, "bad-dst");
            assert_eq!(address, "not-an-address");
        }
        other => panic!("expected UnrepresentableLegacyAddress, got {other:?}"),
    }
}

#[test]
fn legacy_address_valid_literals_and_wildcards_still_parse() {
    // #3367 guard: the reject is keyed on UNPARSEABLE tokens only. Valid CIDRs,
    // bare IPs, `any`, and family-scoped wildcards must still compile cleanly.
    let store = PolicyCounterStore::default();
    let good = PolicyRuleSnapshot {
        rule_id: "good".to_string(),
        name: "permit-host".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.61.0/24".to_string(), "192.168.1.5".to_string()],
        destination_addresses: vec!["any-ipv4".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    };
    parse_policy_state_with_counters("deny", &[good], &test_zone_name_to_id(), &[], &store)
        .expect("valid legacy literals / wildcards must compile");
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
fn unknown_rule_action_rejects_whole_snapshot() {
    // #3365 RED-on-revert: a per-rule action string that is not
    // permit/reject/deny must reject the WHOLE snapshot. Pre-fix `parse_action`
    // mapped any unknown token to PolicyAction::Deny via a catch-all match arm,
    // so a future `reject-*` variant or a corrupt token silently downgraded to
    // a plain Deny (a `reject` losing its RST/ICMP-unreachable semantics) with
    // NO integrity error. Reverting the fix returns Ok(state) here, so this is
    // non-tautological.
    let store = PolicyCounterStore::default();
    let bad = PolicyRuleSnapshot {
        rule_id: "bad-action".to_string(),
        name: "bad-action".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "reject-tcp".to_string(),
        ..Default::default()
    };
    let result =
        parse_policy_state_with_counters("deny", &[bad], &test_zone_name_to_id(), &[], &store);
    match result {
        Err(SnapshotIntegrityError::UnknownPolicyAction { context, action }) => {
            assert!(context.contains("bad-action"), "context names the rule: {context}");
            assert_eq!(action, "reject-tcp");
        }
        other => panic!("expected UnknownPolicyAction, got {other:?}"),
    }
}

#[test]
fn empty_rule_action_rejects_whole_snapshot() {
    // #3365: every configured rule carries a concrete action; an EMPTY action
    // (which pre-fix also collapsed silently to Deny) is rejected fail-closed.
    let store = PolicyCounterStore::default();
    let bad = PolicyRuleSnapshot {
        rule_id: "empty-action".to_string(),
        name: "empty-action".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: String::new(),
        ..Default::default()
    };
    let result =
        parse_policy_state_with_counters("deny", &[bad], &test_zone_name_to_id(), &[], &store);
    assert!(
        matches!(result, Err(SnapshotIntegrityError::UnknownPolicyAction { .. })),
        "an empty per-rule action must fail closed, got {result:?}"
    );
}

#[test]
fn unknown_default_policy_action_rejects_whole_snapshot() {
    // #3365: the snapshot `default_policy` is the other side of the same
    // string boundary. A non-empty unknown default action must reject the whole
    // snapshot rather than silently collapse to Deny.
    let store = PolicyCounterStore::default();
    let result =
        parse_policy_state_with_counters("permit-all", &[], &test_zone_name_to_id(), &[], &store);
    match result {
        Err(SnapshotIntegrityError::UnknownPolicyAction { context, action }) => {
            assert_eq!(context, "default-policy");
            assert_eq!(action, "permit-all");
        }
        other => panic!("expected UnknownPolicyAction for default-policy, got {other:?}"),
    }
}

#[test]
fn empty_default_policy_is_accepted_as_deny() {
    // #3365 guard against over-rejection: an EMPTY default_policy is the
    // legitimate `omitempty`/unspecified wire state and must decode to the
    // default-deny posture WITHOUT an integrity error. The Rust snapshot field
    // is `#[serde(default)]`, so a snapshot that omits default_policy delivers
    // "" — this must NOT be rejected.
    let store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters("", &[], &test_zone_name_to_id(), &[], &store)
        .expect("empty default_policy must be accepted");
    assert_eq!(state.default_action, PolicyAction::Deny);
}

#[test]
fn known_actions_still_parse() {
    // #3365 sanity: the three known tokens still decode to their actions on both
    // the default-policy and per-rule boundaries.
    let store = PolicyCounterStore::default();
    for (tok, want) in [
        ("permit", PolicyAction::Permit),
        ("reject", PolicyAction::Reject),
        ("deny", PolicyAction::Deny),
    ] {
        let rule = PolicyRuleSnapshot {
            rule_id: format!("r-{tok}"),
            name: format!("r-{tok}"),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: tok.to_string(),
            ..Default::default()
        };
        let state =
            parse_policy_state_with_counters(tok, &[rule], &test_zone_name_to_id(), &[], &store)
                .unwrap_or_else(|e| panic!("token {tok} must parse: {e:?}"));
        assert_eq!(state.default_action, want, "default-policy {tok}");
        assert_eq!(state.rules[0].action, want, "rule action {tok}");
    }
}

#[test]
fn deny_rule_with_unrepresentable_app_rejects_whole_snapshot_no_fall_through() {
    // #3261 doctrine guard (plan test #4): a `deny` rule naming an
    // unrepresentable application AHEAD of a later `permit application any` in
    // the same zone-pair must reject the WHOLE snapshot — the bad traffic must
    // NOT fall through to the permit. This is exactly the deny-rule fail-open
    // Option B would have reintroduced; Option A keeps it fail-CLOSED via the
    // whole-snapshot integrity reject (previous-good retained; fresh boot =
    // default-deny). A per-rule drop of the deny term would let the blocked
    // traffic reach the permit — the regression this pins.
    let store = PolicyCounterStore::default();
    let deny_bad = PolicyRuleSnapshot {
        rule_id: "deny-bad".to_string(),
        name: "deny-bad".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["__unsupported__".to_string()],
        application_terms: vec![PolicyApplicationSnapshot {
            name: "__unsupported__".to_string(),
            protocol: "__unsupported__".to_string(),
            source_port: String::new(),
            destination_port: String::new(),
            icmp_type: None,
            icmp_code: None,
            inactivity_timeout: None,
        }],
        action: "deny".to_string(),
        ..Default::default()
    };
    let permit_any = PolicyRuleSnapshot {
        rule_id: "permit-any".to_string(),
        name: "permit-any".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    };
    let result = parse_policy_state_with_counters(
        "deny",
        &[deny_bad, permit_any],
        &test_zone_name_to_id(),
        &[],
        &store,
    );
    assert!(
        matches!(
            result,
            Err(SnapshotIntegrityError::UnrepresentableApplicationProtocol { .. })
        ),
        "deny+unrepresentable ahead of permit-any must reject the whole snapshot \
         (no fall-through), got {result:?}"
    );
}

#[test]
fn deny_rule_with_unrepresentable_address_rejects_whole_snapshot_no_fall_through() {
    // #3261 address half (the deny-rule doctrine guard, symmetric to the
    // application case): a `deny` rule whose source/destination address the Go
    // gate could not represent carries the __unsupported_address__ sentinel.
    // Ahead of a later `permit application any`, the whole snapshot MUST be
    // rejected — the bad-address deny must NOT silently collapse to MatchNone
    // and let the blocked traffic fall through to the permit. Pre-fix the
    // address side had no sentinel/reject backstop and DID fall through (deny
    // fail-open); removing the sentinel reject flips this RED.
    let store = PolicyCounterStore::default();
    let deny_bad_addr = PolicyRuleSnapshot {
        rule_id: "deny-bad-addr".to_string(),
        name: "deny-bad-addr".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        // Both shapes carry the sentinel for the failed side, exactly as the Go
        // builder stamps them.
        source_addresses: vec![UNREPRESENTABLE_ADDRESS_SENTINEL.to_string()],
        source_literals: vec![UNREPRESENTABLE_ADDRESS_SENTINEL.to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "deny".to_string(),
        ..Default::default()
    };
    let permit_any = PolicyRuleSnapshot {
        rule_id: "permit-any".to_string(),
        name: "permit-any".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    };
    let result = parse_policy_state_with_counters(
        "deny",
        &[deny_bad_addr, permit_any],
        &test_zone_name_to_id(),
        &[],
        &store,
    );
    assert!(
        matches!(
            result,
            Err(SnapshotIntegrityError::UnrepresentableAddress { .. })
        ),
        "deny+unrepresentable-address ahead of permit-any must reject the whole \
         snapshot (no fall-through), got {result:?}"
    );
}

#[test]
fn unrepresentable_address_sentinel_in_legacy_shape_also_rejects() {
    // The sentinel must be caught in the legacy (source_addresses) shape too —
    // an old-reader rule that is not v3-shaped (no book ids / literals) still
    // fails closed.
    let store = PolicyCounterStore::default();
    let rule = PolicyRuleSnapshot {
        rule_id: "legacy-bad-addr".to_string(),
        name: "legacy-bad-addr".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        destination_addresses: vec![UNREPRESENTABLE_ADDRESS_SENTINEL.to_string()],
        source_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    };
    let result =
        parse_policy_state_with_counters("deny", &[rule], &test_zone_name_to_id(), &[], &store);
    assert!(
        matches!(
            result,
            Err(SnapshotIntegrityError::UnrepresentableAddress { .. })
        ),
        "legacy-shape unrepresentable-address sentinel must fail closed, got {result:?}"
    );
}

#[test]
fn fresh_boot_default_policy_state_denies_all_transit() {
    // #3261 (plan test #3, fresh-boot half): when the FIRST-ever snapshot is
    // rejected by the integrity preflight, the helper stays armed with the
    // default PolicyState — whose default_action is Deny. So a fresh boot with
    // only a bad config DENIES all transit (NOT kernel fail-open). This pins
    // the safe-side outcome of Option A's one degraded-vs-ideal scenario.
    let state = PolicyState::default();
    assert_eq!(state.default_action, PolicyAction::Deny);
    let src = "10.0.61.100".parse().expect("src");
    let dst = "172.16.80.200".parse().expect("dst");
    assert_eq!(
        evaluate_policy(
            &state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, src, dst, PROTO_TCP, 40000, 443,
        ),
        PolicyAction::Deny,
        "fresh-boot default PolicyState must deny all transit"
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
                    inactivity_timeout: None,
                },
                PolicyApplicationSnapshot {
                    name: "bogus".to_string(),
                    protocol: "definitely-not-a-proto".to_string(),
                    source_port: String::new(),
                    destination_port: String::new(),
                    icmp_type: None,
                    icmp_code: None,
                    inactivity_timeout: None,
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
                    inactivity_timeout: None,
                },
                PolicyApplicationSnapshot {
                    name: "https".to_string(),
                    protocol: "tcp".to_string(),
                    source_port: String::new(),
                    destination_port: "443".to_string(),
                    icmp_type: None,
                    icmp_code: None,
                    inactivity_timeout: None,
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
                    inactivity_timeout: None,
                },
                PolicyApplicationSnapshot {
                    name: "junos-https".to_string(),
                    protocol: "tcp".to_string(),
                    source_port: String::new(),
                    destination_port: "443".to_string(),
                    icmp_type: None,
                    icmp_code: None,
                    inactivity_timeout: None,
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

/// #3402 (was #919/#922): a snapshot zone-pair rule whose from/to zone is
/// absent from `zone_name_to_id` now fails the WHOLE snapshot closed
/// (`SnapshotIntegrityError::UnresolvableZoneReference`) instead of being kept
/// stderr-only and not indexed. The pre-fix behavior silently dropped the rule
/// so a real `LAN→WAN` lookup found nothing and fell through to default-policy:
/// under `default-policy permit-all` a stale `deny` became an ALLOW (fail-OPEN)
/// and under `deny-all` a stale `permit` BLACKHOLED — both invisible to the
/// control plane. Rejecting the snapshot keeps the previous good state (a fresh
/// boot keeps the default-deny PolicyState).
///
/// Fail-on-revert: restoring the stderr-only "rule kept, but not indexed" drop
/// makes `parse_policy_state_with_counters` return `Ok`, so the `Err` match arm
/// below panics → RED. Covers BOTH default postures via the two assertions.
#[test]
fn unknown_zone_pair_fails_closed() {
    let zones = test_zone_name_to_id();
    let make = |default_policy: &str, action: &str| {
        let store = PolicyCounterStore::default();
        parse_policy_state_with_counters(
            default_policy,
            &[PolicyRuleSnapshot {
                rule_id: "ghost".into(),
                name: "rule".into(),
                from_zone: "ghost-from".into(),
                to_zone: "ghost-to".into(),
                source_addresses: vec!["any".into()],
                destination_addresses: vec!["any".into()],
                applications: vec!["any".into()],
                application_terms: Vec::new(),
                action: action.into(),
                ..Default::default()
            }],
            &zones,
            &[],
            &store,
        )
    };
    // default-policy permit-all: a stale `deny` against an undefined zone must
    // NOT silently widen to a fall-through permit.
    match make("permit", "deny") {
        Err(SnapshotIntegrityError::UnresolvableZoneReference { rule_id, zone }) => {
            assert_eq!(rule_id, "ghost");
            // from-zone is reported first (matches the Go strict-gate order).
            assert_eq!(zone, "ghost-from");
        }
        other => panic!("expected UnresolvableZoneReference (permit default), got {other:?}"),
    }
    // default-policy deny-all: a stale `permit` must NOT silently blackhole.
    match make("deny", "permit") {
        Err(SnapshotIntegrityError::UnresolvableZoneReference { rule_id, zone }) => {
            assert_eq!(rule_id, "ghost");
            assert_eq!(zone, "ghost-from");
        }
        other => panic!("expected UnresolvableZoneReference (deny default), got {other:?}"),
    }
}

/// #3402: a single-wildcard rule (`from-zone any to-zone <undefined>`, or
/// `from-zone <undefined> to-zone any`) is guarded on the concrete side too —
/// the concrete zone must resolve or the snapshot fails closed.
#[test]
fn unknown_single_wildcard_zone_fails_closed() {
    let zones = test_zone_name_to_id();
    let store = PolicyCounterStore::default();
    // from-zone any to-zone <ghost>: the concrete to-zone is unresolvable.
    let r = parse_policy_state_with_counters(
        "deny",
        &[PolicyRuleSnapshot {
            rule_id: "wild-to".into(),
            name: "rule".into(),
            from_zone: "any".into(),
            to_zone: "ghost-to".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: "permit".into(),
            ..Default::default()
        }],
        &zones,
        &[],
        &store,
    );
    match r {
        Err(SnapshotIntegrityError::UnresolvableZoneReference { rule_id, zone }) => {
            assert_eq!(rule_id, "wild-to");
            assert_eq!(zone, "ghost-to");
        }
        other => panic!("expected UnresolvableZoneReference (from-any), got {other:?}"),
    }
    // from-zone <ghost> to-zone any: the concrete from-zone is unresolvable.
    let store2 = PolicyCounterStore::default();
    let r2 = parse_policy_state_with_counters(
        "deny",
        &[PolicyRuleSnapshot {
            rule_id: "wild-from".into(),
            name: "rule".into(),
            from_zone: "ghost-from".into(),
            to_zone: "any".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: "deny".into(),
            ..Default::default()
        }],
        &zones,
        &[],
        &store2,
    );
    match r2 {
        Err(SnapshotIntegrityError::UnresolvableZoneReference { rule_id, zone }) => {
            assert_eq!(rule_id, "wild-from");
            assert_eq!(zone, "ghost-from");
        }
        other => panic!("expected UnresolvableZoneReference (to-any), got {other:?}"),
    }
}

/// #3402 over-reject guard: a zone-pair rule whose zones DO resolve still
/// compiles and is enforced. A resolvable `trust->untrust permit` must match.
#[test]
fn resolvable_zone_pair_still_compiles() {
    let zones = test_zone_name_to_id();
    let store = PolicyCounterStore::default();
    let state = parse_policy_state_with_counters(
        "deny",
        &[PolicyRuleSnapshot {
            rule_id: "ok".into(),
            name: "rule".into(),
            from_zone: "trust".into(),
            to_zone: "untrust".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: "permit".into(),
            ..Default::default()
        }],
        &zones,
        &[],
        &store,
    )
    .expect("resolvable zone-pair rule must compile");
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
        PolicyAction::Permit
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

/// #923 / #3367: legacy permissive parse — addresses that fail to parse used to
/// be silently dropped by `parse_address`, so an all-malformed list collapsed to
/// MatchAny (the historical `Vec::is_empty()` = match-all behavior). #3367 makes
/// that a snapshot-integrity error: a malformed token can no longer silently
/// widen a rule. This test now PROVES the fail-closed reject (it asserted the
/// old match-all behavior before #3367, so a revert flips it back to Ok+Permit).
#[test]
fn malformed_only_input_fails_closed_not_match_all() {
    let zones = test_zone_name_to_id();
    let store = PolicyCounterStore::default();
    let result = parse_policy_state_with_counters(
        "deny",
        &[PolicyRuleSnapshot {
            rule_id: "permit-with-typo".into(),
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
        &[],
        &store,
    );
    // Pre-#3367 this parsed Ok and the malformed source collapsed to MatchAny
    // (match-all). Now the whole snapshot is rejected — the first malformed
    // token is surfaced.
    match result {
        Err(SnapshotIntegrityError::UnrepresentableLegacyAddress { rule_id, address }) => {
            assert_eq!(rule_id, "permit-with-typo");
            assert_eq!(address, "totally-bogus");
        }
        other => panic!("expected UnrepresentableLegacyAddress, got {other:?}"),
    }
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
    assert_eq!(cat.lookup_forward(6, 51000, 443), 7);
    // reverse-keyed session carries the service port in the src slot; only the
    // reverse-aware lookup probes that slot (#3321).
    assert_eq!(cat.lookup_directional(6, 443, 51000, true), 7);
    // #3321 fail-on-revert: a FORWARD flow whose SOURCE port coincides with the
    // service port (src=443, dst=ephemeral) must NOT be mislabeled. The old
    // directionless probe returned 7 here.
    assert_eq!(cat.lookup_forward(6, 443, 51000), 0);
    // wrong protocol on the same port is not the app.
    assert_eq!(cat.lookup_forward(17, 51000, 443), 0);
    // unrelated port resolves to unknown (0).
    assert_eq!(cat.lookup_forward(6, 51000, 80), 0);
}

#[test]
fn app_catalog_port_range_resolves_id() {
    let cat = AppCatalog::from_snapshot(&[cat_entry(9, 6, 9000, 9100)]);
    assert_eq!(cat.lookup_forward(6, 40000, 9000), 9); // low edge
    assert_eq!(cat.lookup_forward(6, 40000, 9100), 9); // high edge
    assert_eq!(cat.lookup_forward(6, 40000, 9050), 9); // interior
    assert_eq!(cat.lookup_forward(6, 40000, 8999), 0); // below
    assert_eq!(cat.lookup_forward(6, 40000, 9101), 0); // above
    // reverse-keyed: service-port range in the src slot still resolves via the
    // reverse-aware lookup.
    assert_eq!(cat.lookup_directional(6, 9050, 40000, true), 9);
    // #3321: a forward flow with the service-port range in the SOURCE slot is
    // not mislabeled.
    assert_eq!(cat.lookup_forward(6, 9050, 40000), 0);
}

// #3321: the AppID lookup must be DIRECTION-AWARE. A forward flow whose source
// port coincides with a well-known service port must resolve to UNKNOWN, while
// the SAME tuple presented as a reverse-keyed session (service in the src slot)
// resolves to the service. The pre-#3321 directionless probe matched the
// service on EITHER slot, so the forward false-positive below returned the
// service id — polluting session display / RT_FLOW / policy-deny / filter-log.
#[test]
fn app_catalog_directional_forward_not_mislabeled_by_source_port() {
    // junos-https stand-in: TCP dst/443 (exact-port path).
    let https = AppCatalog::from_snapshot(&[cat_entry(7, 6, 443, 443)]);
    // Forward: src=443 (server-like source), dst=ephemeral client port.
    assert_eq!(
        https.lookup_forward(6, 443, 51000),
        0,
        "forward flow with a service-valued SOURCE port must be UNKNOWN"
    );
    // Reverse-keyed: the service port legitimately rides the src slot.
    assert_eq!(
        https.lookup_directional(6, 443, 51000, true),
        7,
        "reverse-keyed session with the service port in the src slot resolves"
    );
    // The genuine forward direction still resolves on the destination.
    assert_eq!(https.lookup_forward(6, 51000, 443), 7);

    // Same property on the scan (range) path, with a source-constrained app:
    // dst range 9000-9100 AND src range 1000-2000.
    let ranged = AppCatalog::from_snapshot(&[crate::AppCatalogEntry {
        app_id: 9,
        protocol: 6,
        dst_port_low: 9000,
        dst_port_high: 9100,
        src_port_low: 1000,
        src_port_high: 2000,
    }]);
    // Forward: client src in 1000-2000, server dst in 9000-9100 -> match.
    assert_eq!(ranged.lookup_forward(6, 1500, 9050), 9);
    // Forward false-positive: service-range value in the SOURCE slot, client
    // value in the dst slot -> must NOT match.
    assert_eq!(ranged.lookup_forward(6, 9050, 1500), 0);
    // Reverse-keyed: service range in src, client range in dst -> match.
    assert_eq!(ranged.lookup_directional(6, 9050, 1500, true), 9);
}

// #3385: a dual-constrained custom app whose SOURCE and DESTINATION port ranges
// OVERLAP must still match only when a CONSISTENT directional pairing holds —
// NOT whenever a single port happens to fall in the overlap. The pre-#3321
// OR-decomposition (`dst in dstR || src in dstR` AND `src in srcR || dst in
// srcR`) admitted a packet whose DESTINATION port landed in the overlap
// regardless of the source port: srcR=80..80, dstR=80..1000, forward
// src=55555,dst=80 satisfied `dst_ok` (80 in dstR) AND `src_ok` (dst=80 in
// srcR) and was mislabeled, even though neither the forward nor the reverse
// pairing actually holds. This is the distinct over-match #3385 calls out; the
// direction-aware lookup (#3321) eliminates the cross-slot probing entirely.
#[test]
fn app_catalog_overlapping_dual_range_no_cross_slot_overmatch() {
    // Custom app: srcR = 80..80, dstR = 80..1000 (overlapping at 80).
    let cat = AppCatalog::from_snapshot(&[crate::AppCatalogEntry {
        app_id: 11,
        protocol: 6,
        dst_port_low: 80,
        dst_port_high: 1000,
        src_port_low: 80,
        src_port_high: 80,
    }]);

    // RED-on-revert: the #3385 over-match. Forward src=55555 (NOT in srcR),
    // dst=80 (in dstR AND, via the overlap, in srcR). The OR-decomposition
    // returned 11 here; the directional lookup yields UNKNOWN because the
    // source constraint is checked ONLY against the client slot (src=55555).
    assert_eq!(
        cat.lookup_forward(6, 55555, 80),
        0,
        "forward flow whose dst falls in the src/dst overlap but whose src \
         violates srcR must NOT match (the #3385 cross-slot over-match)"
    );

    // The genuine forward pairing still resolves: client src=80 (in srcR),
    // server dst=500 (in dstR).
    assert_eq!(cat.lookup_forward(6, 80, 500), 11);

    // Reverse-keyed: service slot rides the source port. service=src=500 (in
    // dstR), client=dst=80 (in srcR) -> match.
    assert_eq!(cat.lookup_directional(6, 500, 80, true), 11);

    // Reverse-keyed over-match guard: service=src=55555 (NOT in dstR) ->
    // UNKNOWN regardless of the client (dst) slot landing in the overlap.
    assert_eq!(cat.lookup_directional(6, 55555, 80, true), 0);
}

// #3416: the permit-side audit AppID must resolve from the POST-translation
// destination port a DNAT'd session was admitted under, mirroring the deny side
// (#3058/#3185). A public-port -> private-port forward (e.g. :2222 -> :22 for
// junos-ssh) must render the admitting application, not UNKNOWN/the public port.
#[test]
fn app_catalog_lookup_admitted_uses_post_nat_dst_port() {
    // junos-ssh stand-in: TCP dst/22 (exact-port path).
    let ssh = AppCatalog::from_snapshot(&[cat_entry(22, 6, 22, 22)]);

    // Forward DNAT: client src=51000 -> public dst=2222, DNAT-rewritten to :22.
    // RED-on-revert: passing the pre-NAT forward-key dst (2222) to the plain
    // directional lookup mislabels the session UNKNOWN — exactly the #3416 bug.
    assert_eq!(
        ssh.lookup_directional(6, 51000, 2222, false),
        0,
        "pre-NAT public dst port resolves UNKNOWN — the #3416 mislabel"
    );
    // The fix: lookup_admitted substitutes the post-NAT (rewritten) dst port and
    // resolves the admitting application.
    assert_eq!(
        ssh.lookup_admitted(6, 51000, 2222, false, Some(22)),
        22,
        "forward DNAT session resolves on the post-NAT (rewritten) dst port"
    );

    // Negative control: public == private port (no rewrite). rewrite_dst_port is
    // None, so the result is byte-identical to the plain directional lookup.
    assert_eq!(
        ssh.lookup_admitted(6, 51000, 22, false, None),
        22,
        "non-translated flow falls back to the forward-key dst port"
    );
    // A DNAT that does NOT change the port (rewrite_dst_port None even though the
    // dst address changed) also falls back to the received service port.
    assert_eq!(
        ssh.lookup_admitted(6, 51000, 22, false, None),
        22,
        "address-only DNAT (no port rewrite) still resolves on the dst port"
    );

    // Reverse-keyed entry: the service rides the SRC slot and the key already
    // carries the real internal port. The forward-only rewrite must NOT touch
    // the reverse service slot, so a (bogus, for this direction) rewrite_dst_port
    // is ignored and the src slot still resolves.
    assert_eq!(
        ssh.lookup_admitted(6, 22, 51000, true, Some(2222)),
        22,
        "reverse-keyed session resolves on its received src service slot"
    );

    // Wrong post-NAT port still resolves to UNKNOWN (no false positive).
    assert_eq!(
        ssh.lookup_admitted(6, 51000, 2222, false, Some(8080)),
        0,
        "post-NAT port with no catalog entry resolves UNKNOWN"
    );
}

// A (0,0) dst-port pair means "protocol-only" (e.g. ICMP) — match on protocol
// regardless of ports.
#[test]
fn app_catalog_protocol_only_entry() {
    let cat = AppCatalog::from_snapshot(&[cat_entry(3, 1, 0, 0)]); // ICMP
    assert_eq!(cat.lookup_forward(1, 0, 0), 3);
    assert_eq!(cat.lookup_forward(1, 1234, 5678), 3);
    assert_eq!(cat.lookup_forward(6, 1234, 5678), 0); // different protocol
}

// app_id 0 is the reserved unknown sentinel and must never be indexed even if a
// malformed snapshot carries it.
#[test]
fn app_catalog_skips_zero_app_id() {
    let cat = AppCatalog::from_snapshot(&[cat_entry(0, 6, 443, 443)]);
    assert!(cat.is_empty());
    assert_eq!(cat.lookup_forward(6, 51000, 443), 0);
}

// Overlapping entries: first/lowest app_id wins, deterministically (the Go
// builder emits ascending ids in sorted-name order).
#[test]
fn app_catalog_overlap_lowest_id_wins() {
    // Two apps both claiming tcp/80 — exact-port path.
    let cat = AppCatalog::from_snapshot(&[cat_entry(5, 6, 80, 80), cat_entry(11, 6, 80, 80)]);
    assert_eq!(cat.lookup_forward(6, 40000, 80), 5);

    // Range vs exact overlap — lowest id still wins.
    let cat = AppCatalog::from_snapshot(&[cat_entry(2, 6, 8000, 8100), cat_entry(20, 6, 8050, 8050)]);
    assert_eq!(cat.lookup_forward(6, 40000, 8050), 2);
}

#[test]
fn app_catalog_empty_resolves_unknown() {
    let cat = AppCatalog::default();
    assert!(cat.is_empty());
    assert_eq!(cat.lookup_forward(6, 51000, 443), 0);
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
            inactivity_timeout: None,
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
        inactivity_timeout: None,
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
                inactivity_timeout: None,
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

// ---------------------------------------------------------------------------
// #3019: `to-zone junos-host` / `from-zone junos-host` self-traffic policy.
// ---------------------------------------------------------------------------

fn junos_host_deny_snapshot(action: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: "host-ssh".to_string(),
        from_zone: "trust".to_string(),
        to_zone: JUNOS_HOST_ZONE_NAME.to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: action.to_string(),
        ..Default::default()
    }
}

/// #3019: a `to-zone junos-host` rule is INDEXED under the reserved synthetic
/// zone id (mirroring a normal zone-pair) and arms `has_junos_host_rules`.
/// Pre-fix the rule was kept-but-not-indexed (like the wildcard-`any` case),
/// so the LocalDelivery gate could never reach it.
#[test]
fn junos_host_rule_is_indexed_under_reserved_zone_id() {
    let state = parse_policy_state("permit", &[junos_host_deny_snapshot("deny")], &test_zone_name_to_id());
    assert!(state.has_junos_host_rules, "junos-host rule must arm the gate");
    let key = zone_pair_key(TEST_TRUST_ZONE_ID, JUNOS_HOST_ZONE_ID);
    assert!(
        state.zone_pair_index.contains_key(&key),
        "trust->junos-host rule must be indexed under (trust_id, JUNOS_HOST_ZONE_ID)"
    );
}

/// #3019: a configured `from-zone trust to-zone junos-host then deny` DENIES a
/// host-bound flow from trust (the deny test). The eval consults the
/// junos-host zone-pair and returns the matched Deny action.
#[test]
fn junos_host_policy_denies_matching_host_bound_flow() {
    let state = parse_policy_state("permit", &[junos_host_deny_snapshot("deny")], &test_zone_name_to_id());
    let result = evaluate_junos_host_policy(
        &state,
        TEST_TRUST_ZONE_ID,
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 102)),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 1)),
        PROTO_TCP,
        12345,
        22,
        None,
        64,
    );
    assert_eq!(
        result.map(|r| r.action),
        Some(PolicyAction::Deny),
        "trust->junos-host deny must match and deny"
    );
}

/// #3019: `then permit` admits the host-bound flow (returns Permit). Ordering:
/// host-inbound admission runs FIRST in the caller, so this permit cannot
/// re-admit what host-inbound rejected — that is enforced by the poll-path
/// call order, not here.
#[test]
fn junos_host_policy_permits_matching_host_bound_flow() {
    let state = parse_policy_state("deny", &[junos_host_deny_snapshot("permit")], &test_zone_name_to_id());
    let result = evaluate_junos_host_policy(
        &state,
        TEST_TRUST_ZONE_ID,
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 102)),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 1)),
        PROTO_TCP,
        12345,
        22,
        None,
        64,
    );
    assert_eq!(result.map(|r| r.action), Some(PolicyAction::Permit));
}

/// #3019 lifeline fail-safe: with NO junos-host policy configured at all, the
/// gate is a NO-OP (`None`) regardless of the (deny) default policy — host-
/// bound traffic keeps pre-#3019 behavior and can never be newly denied.
#[test]
fn junos_host_policy_no_op_without_configured_rule() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "transit".to_string(),
            from_zone: "trust".to_string(),
            to_zone: "untrust".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );
    assert!(!state.has_junos_host_rules);
    assert!(
        evaluate_junos_host_policy(
            &state,
            TEST_TRUST_ZONE_ID,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 102)),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 1)),
            PROTO_TCP,
            12345,
            22,
            None,
            64,
        )
        .is_none(),
        "no junos-host policy configured: gate must be a no-op"
    );
}

/// #3019 fail-safe: a junos-host policy is configured for trust, but a flow
/// from a DIFFERENT ingress zone (untrust) matches no junos-host rule for that
/// pair → `None` (no implicit default-deny — host-bound traffic from untrust
/// is unaffected). Also covers the unzoned (id 0) ingress short-circuit.
#[test]
fn junos_host_policy_no_match_falls_through_to_today_behavior() {
    let state = parse_policy_state("permit", &[junos_host_deny_snapshot("deny")], &test_zone_name_to_id());
    // Different ingress zone, no junos-host rule for (untrust, junos-host).
    assert!(
        evaluate_junos_host_policy(
            &state,
            TEST_UNTRUST_ZONE_ID,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 2, 102)),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 2, 1)),
            PROTO_TCP,
            12345,
            22,
            None,
            64,
        )
        .is_none(),
        "no junos-host rule for this ingress zone: no implicit default-deny"
    );
    // Unzoned (id 0) ingress is never eligible (mirror #3110).
    assert!(
        evaluate_junos_host_policy(
            &state,
            0,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 2, 102)),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 2, 1)),
            PROTO_TCP,
            12345,
            22,
            None,
            64,
        )
        .is_none(),
        "unzoned ingress must not be eligible for junos-host policy"
    );
}

// #3292: a `to-zone junos-host` rule with a PORT-BEARING application
// (`destination-port 22`). The two assertions below hold the 5-tuple IDENTICAL
// (dst_port = 22) and flip ONLY `l4_present`, so the difference in verdict is
// attributable solely to the L4-presence gate: a flowless host-bound packet
// (l4_present = false) MUST fail the port-bearing term closed even when a port
// byte happens to be supplied, because a non-first fragment's post-IP bytes are
// payload, never an authoritative L4 header. Reverting
// `evaluate_junos_host_policy_l3_aware` to ignore `l4_present` (force true) makes
// the flowless call spuriously MATCH → the flowless assertion flips RED.
fn junos_host_port_app_snapshot() -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: "host-ssh-port".to_string(),
        from_zone: "trust".to_string(),
        to_zone: JUNOS_HOST_ZONE_NAME.to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["host-ssh".to_string()],
        application_terms: vec![PolicyApplicationSnapshot {
            name: "host-ssh".to_string(),
            protocol: "tcp".to_string(),
            source_port: String::new(),
            destination_port: "22".to_string(),
            icmp_type: None,
            icmp_code: None,
            inactivity_timeout: None,
        }],
        action: "deny".to_string(),
        ..Default::default()
    }
}

#[test]
fn junos_host_l3_aware_fails_port_bearing_term_closed_for_flowless() {
    let state = parse_policy_state("permit", &[junos_host_port_app_snapshot()], &test_zone_name_to_id());
    let src = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 102));
    let dst = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 1));

    // Flow-backed (l4_present = true, dst_port = 22): the destination-port 22 app
    // term matches → deny. (Anchors that the port itself matches, so the flowless
    // non-match below is attributable ONLY to l4_present being false.)
    assert_eq!(
        evaluate_junos_host_policy_l3_aware(
            &state, TEST_TRUST_ZONE_ID, src, dst, PROTO_TCP, 12345, 22, None, 64, true,
        )
        .map(|r| r.action),
        Some(PolicyAction::Deny),
        "flow-backed call must match the destination-port 22 junos-host app term",
    );

    // Flowless (l4_present = false) — SAME tuple, only l4_present flipped: the
    // port-bearing term fails CLOSED → no match → None → local delivery proceeds
    // (a fragment's port is not authoritative, so it must not be denied by a
    // port-specific rule it cannot be classified into).
    assert!(
        evaluate_junos_host_policy_l3_aware(
            &state, TEST_TRUST_ZONE_ID, src, dst, PROTO_TCP, 12345, 22, None, 64, false,
        )
        .is_none(),
        "flowless call must NOT match a port-bearing junos-host app term (l4_present=false)",
    );
}

#[test]
fn junos_host_l3_aware_any_app_matches_regardless_of_l4_presence() {
    // An `application any` junos-host deny matches a flowless host-bound packet
    // (no port required) — the L3-identity rule still enforces.
    let state = parse_policy_state("permit", &[junos_host_deny_snapshot("deny")], &test_zone_name_to_id());
    let src = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 102));
    let dst = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 1));
    assert_eq!(
        evaluate_junos_host_policy_l3_aware(
            &state, TEST_TRUST_ZONE_ID, src, dst, PROTO_TCP, 0, 0, None, 64, false,
        )
        .map(|r| r.action),
        Some(PolicyAction::Deny),
        "an `any` junos-host rule denies a flowless host-bound packet too",
    );
}

// ── #3073: established-session policy hit-count (per-packet) ──────────
//
// Before #3073 the per-rule packet/byte hit counter was incremented
// exactly once per flow — on the cold (session-miss) path inside
// `try_match_rule`. The established fast path
// (`poll_descriptor`/`flow_cache_hit`) now resolves the admitting rule's
// counter via `PolicyState::hit_counter_by_idx` (using the 1-based handle
// carried on the session metadata) and calls `record_policy_hit_counter`
// for EVERY packet. These tests exercise that resolution + counting
// sequence at the mechanism level (driving the real poll loop would
// require a full BindingWorker/WorkerContext).

#[test]
fn policy_hit_count_evaluation_emits_one_based_counter_handle() {
    let rule_id = "security-policy:lan:wan:permit-web".to_string();
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            rule_id: rule_id.clone(),
            name: "permit-web".to_string(),
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

    let res = evaluate_policy_result_with_len(
        &state,
        TEST_LAN_ZONE_ID,
        TEST_WAN_ZONE_ID,
        "10.0.61.100".parse().expect("src"),
        "10.0.2.5".parse().expect("dst"),
        PROTO_TCP,
        12345,
        80,
        100,
    );
    assert_eq!(res.action, PolicyAction::Permit);
    // The sole configured rule sits at rules[0] -> 1-based handle 1.
    assert_eq!(
        res.policy_counter_idx, 1,
        "the admitting rule must surface a non-zero (1-based) counter handle"
    );
    // The handle resolves back to that rule's counter.
    assert!(
        state.hit_counter_by_idx(res.policy_counter_idx).is_some(),
        "the handle must resolve to the admitting rule's counter"
    );
    // #3363: the implicit default-deny (an unconfigured zone pair: wan->lan
    // has no rule) now carries the RESERVED default-policy handle, and that
    // handle resolves to the reserved default counter so a default-PERMIT
    // session would re-count on the fast path.
    let defaulted = evaluate_policy_result_with_len(
        &state,
        TEST_WAN_ZONE_ID,
        TEST_LAN_ZONE_ID,
        "10.0.2.5".parse().expect("src"),
        "10.0.61.100".parse().expect("dst"),
        PROTO_TCP,
        80,
        12345,
        100,
    );
    assert_eq!(defaulted.action, PolicyAction::Deny);
    assert_eq!(
        defaulted.policy_counter_idx,
        crate::policy::DEFAULT_POLICY_COUNTER_IDX,
        "the implicit default-policy must carry the reserved default-policy handle"
    );
    assert!(
        state
            .hit_counter_by_idx(defaulted.policy_counter_idx)
            .is_some(),
        "the reserved handle must resolve to the default-policy counter"
    );
    // The reserved handle resolves to a DIFFERENT counter than the named rule.
    assert!(
        !std::sync::Arc::ptr_eq(
            state.hit_counter_by_idx(res.policy_counter_idx).unwrap(),
            state.hit_counter_by_idx(defaulted.policy_counter_idx).unwrap(),
        ),
        "the default-policy counter must be distinct from any named-rule counter"
    );
}

#[test]
fn hit_counter_by_idx_guards_sentinel_and_stale() {
    let rule_id = "security-policy:lan:wan:permit-web".to_string();
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            rule_id,
            name: "permit-web".to_string(),
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
    // 0 = "no per-rule counter" sentinel.
    assert!(state.hit_counter_by_idx(0).is_none());
    // 1-based handle for the single rule resolves.
    assert!(state.hit_counter_by_idx(1).is_some());
    // A stale handle past the (now smaller) rule table resolves to None —
    // never a panic, never a wrong-rule increment off the table end.
    assert!(state.hit_counter_by_idx(2).is_none());
    // A near-max stale handle (NOT the reserved sentinel) also resolves None.
    assert!(state.hit_counter_by_idx(u32::MAX - 1).is_none());
    // #3363: u32::MAX is the RESERVED default-policy handle and resolves to the
    // reserved default counter (distinct from any named rule's counter).
    assert!(state.hit_counter_by_idx(u32::MAX).is_some());
    assert!(std::sync::Arc::ptr_eq(
        state.hit_counter_by_idx(u32::MAX).unwrap(),
        &state.default_counter,
    ));
}

#[test]
fn policy_hit_count_counts_every_established_packet_not_just_first() {
    let rule_id = "security-policy:lan:wan:permit-web".to_string();
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            rule_id: rule_id.clone(),
            name: "permit-web".to_string(),
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

    // Packet 1: the cold (session-miss) path runs policy evaluation, which
    // increments the counter once inside `try_match_rule` and hands back the
    // counter handle to stamp on the new session.
    const FIRST_LEN: u64 = 100;
    let res = evaluate_policy_result_with_len(
        &state,
        TEST_LAN_ZONE_ID,
        TEST_WAN_ZONE_ID,
        "10.0.61.100".parse().expect("src"),
        "10.0.2.5".parse().expect("dst"),
        PROTO_TCP,
        12345,
        80,
        FIRST_LEN,
    );
    assert_eq!(res.action, PolicyAction::Permit);
    assert_ne!(res.policy_counter_idx, 0);

    // Packets 2..=N+1: the established fast path resolves the stamped handle
    // and records each packet (this is the per-packet increment #3073 adds;
    // reverting it makes this assertion read packets == 1 -> RED).
    const N: u64 = 999;
    const PKT_LEN: u64 = 1500;
    for _ in 0..N {
        let counter = state
            .hit_counter_by_idx(res.policy_counter_idx)
            .expect("stamped handle must resolve to the admitting rule");
        record_policy_hit_counter(counter, PKT_LEN);
    }

    let snap = policy_counter(&state, &rule_id);
    assert_eq!(
        snap.packets,
        N + 1,
        "a long-lived flow must count the cold-path first packet PLUS every \
         established fast-path packet (pre-#3073 this read 1)"
    );
    assert_eq!(
        snap.bytes,
        FIRST_LEN + N * PKT_LEN,
        "byte counter must accumulate every packet's length, not just the \
         first frame"
    );
}

// ── #3322: bound hit-counter handle survives a live policy reorder ──────
//
// The per-session counter handle is a 1-based POSITIONAL index into the rule
// table. #3073 made it stable within one snapshot; it is NOT stable across a
// live policy insert/reorder. If an operator inserts a rule above an
// already-counted rule, the same index points at whatever rule now occupies
// that slot — so established-session packets used to increment the inserted
// rule's counter (and the real admitting rule stopped counting). #3322 binds
// the admitting rule's SHARED counter Arc onto the session at install (when the
// index is still correct) and the established fast path prefers that bound
// handle over the positional index via `resolve_session_hit_counter`. The Arc
// is the same instance the persistent `PolicyCounterStore` re-hands for a
// surviving `rule_id` across snapshot rebuilds, so it follows the admitting
// rule through reorders.
fn reorder_rule_snapshot(rule_id: &str, name: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        rule_id: rule_id.to_string(),
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        action: "permit".to_string(),
        ..Default::default()
    }
}

#[test]
fn bound_hit_counter_survives_live_policy_reorder() {
    let id_b = "security-policy:lan:wan:permit-b".to_string();
    let id_a = "security-policy:lan:wan:permit-a".to_string();
    let zones = test_zone_name_to_id();
    // Persistent counter store, exactly as the coordinator keeps it across
    // snapshot rebuilds.
    let store = PolicyCounterStore::default();

    // Snapshot 1: a single rule B. B sits at rules[0] -> 1-based handle 1.
    let rule_b = reorder_rule_snapshot(&id_b, "permit-b");
    let state1 =
        parse_policy_state_with_counters("deny", std::slice::from_ref(&rule_b), &zones, &[], &store)
            .expect("state1");
    // Bind B's counter the way session install does (idx still valid here).
    let bound = state1.hit_counter_by_idx(1).cloned();
    assert!(bound.is_some(), "rule B must surface a bound counter at install");

    // Operator inserts rule A ABOVE B (a live reorder) — same persistent store.
    let rule_a = reorder_rule_snapshot(&id_a, "permit-a");
    let state2 = parse_policy_state_with_counters(
        "deny",
        &[rule_a, rule_b.clone()],
        &zones,
        &[],
        &store,
    )
    .expect("state2");
    // The positional handle 1 now points at the INSERTED rule A — the stale
    // index. Resolving it positionally would mis-attribute B's traffic to A.
    assert_eq!(state2.rules[0].rule_id, id_a, "A must occupy the old slot 1");
    assert_eq!(state2.rules[1].rule_id, id_b, "B shifted to slot 2");

    // Established fast path: resolve via the BOUND handle, passing the now-stale
    // idx=1. The bound Arc must win, so the packet counts against B, not A.
    let counter = state2
        .resolve_session_hit_counter(bound.as_ref(), 1)
        .expect("bound handle must resolve");
    record_policy_hit_counter(counter, 1500);
    flush_recorded_policy_hit_counters();

    let after = policy_counter(&state2, &id_b);
    let inserted = policy_counter(&state2, &id_a);
    assert_eq!(
        after.packets, 1,
        "established packet must keep counting against the ADMITTING rule B \
         after a live reorder (reverting #3322 to positional resolution reads 0 \
         here and 1 on A -> RED)"
    );
    assert_eq!(after.bytes, 1500, "B's byte counter must accumulate");
    assert_eq!(
        inserted.packets, 0,
        "the INSERTED rule A must NOT inherit B's established traffic"
    );

    // Document the bug the bound handle defeats: resolving the SAME stale idx
    // positionally (bound = None -> idx fallback) lands on the inserted rule A.
    let positional = state2
        .resolve_session_hit_counter(None, 1)
        .expect("positional idx 1 resolves");
    record_policy_hit_counter(positional, 1500);
    flush_recorded_policy_hit_counters();
    assert_eq!(
        policy_counter(&state2, &id_a).packets,
        1,
        "positional resolution of the stale idx mis-attributes to A (the #3322 bug)"
    );
    assert_eq!(
        policy_counter(&state2, &id_b).packets,
        1,
        "B is untouched by the positional mis-attribution"
    );
}

#[test]
fn policy_hit_count_single_packet_flow_reads_one() {
    // Back-compat: a flow whose only packet rides the cold path (no
    // established follow-on packets) still reports exactly 1 packet and the
    // first frame's bytes — identical to pre-#3073 behavior.
    let rule_id = "security-policy:lan:wan:permit-web".to_string();
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            rule_id: rule_id.clone(),
            name: "permit-web".to_string(),
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
    let res = evaluate_policy_result_with_len(
        &state,
        TEST_LAN_ZONE_ID,
        TEST_WAN_ZONE_ID,
        "10.0.61.100".parse().expect("src"),
        "10.0.2.5".parse().expect("dst"),
        PROTO_TCP,
        12345,
        80,
        64,
    );
    assert_eq!(res.action, PolicyAction::Permit);
    let snap = policy_counter(&state, &rule_id);
    assert_eq!(snap.packets, 1, "single-packet flow must read exactly 1");
    assert_eq!(snap.bytes, 64);
}

// ─────────────────────────────────────────────────────────────────────────
// #3090 wildcard from-zone/to-zone `any` policy indexing.
//
// These exercise PolicyState's new wildcard tiers (from-any / to-any /
// both-any) and their Junos most-specific-first precedence vs exact zone-pair
// rules, global rules, and the default policy. The fail-on-revert guard is
// `from_zone_any_matches_across_ingress_zones` / `to_zone_any_matches_across_
// egress_zones`: deleting the wildcard lookup block in
// evaluate_policy_result_with_icmp makes those RED (the wildcard rule stops
// matching the non-config-ordered zone and the flow falls to the default
// action).
// ─────────────────────────────────────────────────────────────────────────

fn wildcard_rule(name: &str, from_zone: &str, to_zone: &str, action: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: name.to_string(),
        from_zone: from_zone.to_string(),
        to_zone: to_zone.to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: action.to_string(),
        ..Default::default()
    }
}

fn eval(state: &PolicyState, from_id: u16, to_id: u16) -> PolicyAction {
    evaluate_policy(
        state,
        from_id,
        to_id,
        "10.0.0.1".parse().expect("src"),
        "10.0.0.2".parse().expect("dst"),
        PROTO_TCP,
        12345,
        443,
    )
}

#[test]
fn from_zone_any_matches_across_ingress_zones() {
    // `from-zone any to-zone wan deny` must block traffic into wan from EVERY
    // ingress zone (lan, trust, untrust), default permit otherwise.
    let state = parse_policy_state(
        "permit",
        &[wildcard_rule("block-to-wan", "any", "wan", "deny")],
        &test_zone_name_to_id(),
    );
    assert_eq!(eval(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Deny);
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Deny);
    assert_eq!(eval(&state, TEST_UNTRUST_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Deny);
    // A flow into a DIFFERENT to-zone is NOT matched by the from-any-to-wan
    // rule and falls through to the default permit.
    assert_eq!(eval(&state, TEST_LAN_ZONE_ID, TEST_TRUST_ZONE_ID), PolicyAction::Permit);
}

#[test]
fn to_zone_any_matches_across_egress_zones() {
    // `from-zone trust to-zone any permit`, default deny: trust may reach EVERY
    // egress zone; other ingress zones stay denied.
    let state = parse_policy_state(
        "deny",
        &[wildcard_rule("trust-out", "trust", "any", "permit")],
        &test_zone_name_to_id(),
    );
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_LAN_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID), PolicyAction::Permit);
    // A different ingress zone is not matched → default deny.
    assert_eq!(eval(&state, TEST_UNTRUST_ZONE_ID, TEST_LAN_ZONE_ID), PolicyAction::Deny);
}

#[test]
fn both_any_matches_every_pair() {
    // `from-zone any to-zone any permit`, default deny: matches every defined
    // zone pair.
    let state = parse_policy_state(
        "deny",
        &[wildcard_rule("all", "any", "any", "permit")],
        &test_zone_name_to_id(),
    );
    assert_eq!(eval(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval(&state, TEST_UNTRUST_ZONE_ID, TEST_TRUST_ZONE_ID), PolicyAction::Permit);
    // An unzoned flow (id 0) still falls through to default (the #3110 guard);
    // wildcard tiers live inside the from_id!=0 && to_id!=0 gate.
    assert_eq!(eval(&state, 0, TEST_WAN_ZONE_ID), PolicyAction::Deny);
}

#[test]
fn exact_zone_pair_takes_precedence_over_wildcard() {
    // Even when the wildcard rule is configured FIRST, the exact zone-pair
    // tier is evaluated before it, so for lan->wan the exact deny wins; for a
    // non-exact pair (trust->wan) only the from-any rule applies.
    let state = parse_policy_state(
        "deny",
        &[
            wildcard_rule("wild-permit", "any", "wan", "permit"),
            wildcard_rule("exact-deny", "lan", "wan", "deny"),
        ],
        &test_zone_name_to_id(),
    );
    assert_eq!(
        eval(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID),
        PolicyAction::Deny,
        "exact lan->wan deny must win over the earlier from-any permit"
    );
    assert_eq!(
        eval(&state, TEST_TRUST_ZONE_ID, TEST_WAN_ZONE_ID),
        PolicyAction::Permit,
        "trust->wan has no exact rule, so the from-any permit applies"
    );
}

#[test]
fn single_wildcard_tier_honors_config_order() {
    // from-any (deny) configured BEFORE to-any (permit): for an untrust->trust
    // flow both wildcards match, and the earlier-configured from-any deny wins.
    let deny_first = parse_policy_state(
        "permit",
        &[
            wildcard_rule("from-any-deny", "any", "trust", "deny"),
            wildcard_rule("to-any-permit", "untrust", "any", "permit"),
        ],
        &test_zone_name_to_id(),
    );
    assert_eq!(eval(&deny_first, TEST_UNTRUST_ZONE_ID, TEST_TRUST_ZONE_ID), PolicyAction::Deny);
    // Reversed config order: the to-any permit is now first and wins.
    let permit_first = parse_policy_state(
        "deny",
        &[
            wildcard_rule("to-any-permit", "untrust", "any", "permit"),
            wildcard_rule("from-any-deny", "any", "trust", "deny"),
        ],
        &test_zone_name_to_id(),
    );
    assert_eq!(eval(&permit_first, TEST_UNTRUST_ZONE_ID, TEST_TRUST_ZONE_ID), PolicyAction::Permit);
}

#[test]
fn single_wildcard_beats_both_any() {
    // A single-wildcard rule (from-any-to-wan deny) is more specific than a
    // both-any permit and wins regardless of config order.
    let state = parse_policy_state(
        "permit",
        &[
            wildcard_rule("both-any-permit", "any", "any", "permit"),
            wildcard_rule("from-any-deny", "any", "wan", "deny"),
        ],
        &test_zone_name_to_id(),
    );
    assert_eq!(eval(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Deny);
    // A pair the single-wildcard does not cover falls to both-any permit.
    assert_eq!(eval(&state, TEST_LAN_ZONE_ID, TEST_TRUST_ZONE_ID), PolicyAction::Permit);
}

#[test]
fn wildcard_takes_precedence_over_global() {
    // A both-any deny must be evaluated BEFORE a global permit (global is the
    // device-wide fallback tier, consulted only after all wildcard tiers).
    // Global rules carry the junos-global sentinel on both zones.
    let state = parse_policy_state(
        "deny",
        &[
            wildcard_rule("global-permit", "junos-global", "junos-global", "permit"),
            wildcard_rule("both-any-deny", "any", "any", "deny"),
        ],
        &test_zone_name_to_id(),
    );
    assert_eq!(
        eval(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID),
        PolicyAction::Deny,
        "both-any deny must win over the global permit"
    );
}

#[test]
fn wildcard_falls_through_to_default() {
    // A from-any-to-wan rule does not match a flow to a different to-zone, so
    // the default action applies.
    let state = parse_policy_state(
        "deny",
        &[wildcard_rule("from-any-wan", "any", "wan", "permit")],
        &test_zone_name_to_id(),
    );
    assert_eq!(eval(&state, TEST_LAN_ZONE_ID, TEST_TRUST_ZONE_ID), PolicyAction::Deny);
}

#[test]
fn from_zone_any_to_junos_host_blocks_host_inbound_from_any_zone() {
    // `from-zone any to-zone junos-host deny` must be enforced on the host
    // (LocalDelivery) path for every ingress zone — proving the wildcard is not
    // re-introducing the #3018 silent fail-open now that the commit reject is
    // lifted.
    let state = parse_policy_state(
        "permit",
        &[wildcard_rule("host-block", "any", "junos-host", "deny")],
        &test_zone_name_to_id(),
    );
    for from in [TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, TEST_UNTRUST_ZONE_ID] {
        let res = evaluate_junos_host_policy(
            &state,
            from,
            "10.0.0.1".parse().expect("src"),
            "10.0.0.2".parse().expect("dst"),
            PROTO_TCP,
            12345,
            22,
            None,
            64,
        );
        assert_eq!(
            res.map(|r| r.action),
            Some(PolicyAction::Deny),
            "from-zone any to-zone junos-host must block host-inbound from zone {from}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// #3148 global policy from-zone/to-zone match context.
//
// A Junos global policy may carry optional `match from-zone`/`match to-zone`
// so one global policy applies to a chosen zone pair (or one wildcard side)
// instead of every zone pair, while still being evaluated in the GLOBAL tier
// ordering (after exact zone-pair and the #3090 wildcard tiers). The
// fail-on-revert guard is `global_policy_zone_context_scopes_to_pair`:
// deleting the `global_*_zone.matches(...)` skip in the global-tier loop of
// `evaluate_policy_result_with_icmp` makes the scoped global rule match EVERY
// zone pair again, so the "other pair falls through to default" assertions go
// RED.
// ─────────────────────────────────────────────────────────────────────────

fn global_zone_rule(name: &str, match_from: &str, match_to: &str, action: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: name.to_string(),
        // A global policy keeps the junos-global sentinel on both structural
        // zone fields (so it is classified into the global tier); the optional
        // zone context rides in match_from_zone / match_to_zone (#3148).
        from_zone: "junos-global".to_string(),
        to_zone: "junos-global".to_string(),
        match_from_zone: match_from.to_string(),
        match_to_zone: match_to.to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: action.to_string(),
        ..Default::default()
    }
}

#[test]
fn global_policy_zone_context_scopes_to_pair() {
    // `global policy match from-zone trust to-zone untrust permit`, default
    // deny: ONLY trust->untrust is permitted; every other pair falls through
    // to the default deny. (Fail-on-revert: drop the scope skip and the global
    // rule matches every pair, so the Deny assertions turn into Permit.)
    let state = parse_policy_state(
        "deny",
        &[global_zone_rule("scoped", "trust", "untrust", "permit")],
        &test_zone_name_to_id(),
    );
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Deny);
    assert_eq!(eval(&state, TEST_UNTRUST_ZONE_ID, TEST_TRUST_ZONE_ID), PolicyAction::Deny);
    assert_eq!(eval(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Deny);
}

#[test]
fn global_policy_no_zone_context_matches_all_pairs() {
    // No #3148 regression: a global policy with NO from/to zone context keeps
    // the historical all-zones semantics.
    let state = parse_policy_state(
        "deny",
        &[global_zone_rule("all", "", "", "permit")],
        &test_zone_name_to_id(),
    );
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval(&state, TEST_UNTRUST_ZONE_ID, TEST_TRUST_ZONE_ID), PolicyAction::Permit);
}

#[test]
fn global_policy_single_side_zone_context() {
    // from-zone-only scope: matches every egress zone but only the named
    // ingress zone.
    let state = parse_policy_state(
        "deny",
        &[global_zone_rule("from-trust", "trust", "", "permit")],
        &test_zone_name_to_id(),
    );
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Deny);

    // to-zone-only scope (symmetric).
    let state = parse_policy_state(
        "deny",
        &[global_zone_rule("to-wan", "", "wan", "permit")],
        &test_zone_name_to_id(),
    );
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID), PolicyAction::Deny);
}

#[test]
fn global_policy_evaluated_after_wildcard_tiers() {
    // Precedence vs #3090: a `from-zone any to-zone untrust permit` wildcard
    // (zone-pair tier 1) is consulted BEFORE the zone-scoped global tier, so it
    // wins a trust->untrust flow over a conflicting `global match from-zone
    // trust to-zone untrust deny`. Default deny.
    let state = parse_policy_state(
        "deny",
        &[
            wildcard_rule("wild-permit", "any", "untrust", "permit"),
            global_zone_rule("global-deny", "trust", "untrust", "deny"),
        ],
        &test_zone_name_to_id(),
    );
    // Tier 1 wildcard permit wins over the tier 4 scoped global deny.
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID), PolicyAction::Permit);
    // The wildcard also covers a different ingress into untrust.
    assert_eq!(eval(&state, TEST_LAN_ZONE_ID, TEST_UNTRUST_ZONE_ID), PolicyAction::Permit);
    // Neither rule covers trust->wan (wildcard is to-untrust, global is
    // to-untrust) → default deny.
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Deny);
}

#[test]
fn global_policy_unknown_zone_context_fails_closed() {
    // #3402: a scoped-global policy whose match-from/to zone does not resolve to
    // a defined zone now fails the WHOLE snapshot closed
    // (SnapshotIntegrityError::UnresolvableZoneReference), never silently
    // producing a matches-nothing scope (which removed the operator's broad
    // safety net with no surfaced failure). The preflight keeps the previous
    // good state.
    //
    // Fail-on-revert: restoring `GlobalZoneScope::Unresolved` (the pre-#3402
    // matches-nothing scope) makes `parse_policy_state_with_counters` return
    // `Ok`, so the `Err` match below panics → RED. Both match-zone sides are
    // covered.
    let zones = test_zone_name_to_id();
    let store = PolicyCounterStore::default();
    // Unresolvable match from-zone.
    match parse_policy_state_with_counters(
        "deny",
        &[global_zone_rule("typo-from", "nonexistent", "untrust", "permit")],
        &zones,
        &[],
        &store,
    ) {
        Err(SnapshotIntegrityError::UnresolvableZoneReference { rule_id, zone }) => {
            // global_zone_rule sets no explicit rule_id, so stable_policy_rule_id
            // synthesizes "<from>-><to>/<name>".
            assert!(rule_id.ends_with("/typo-from"), "rule_id={rule_id}");
            assert_eq!(zone, "nonexistent");
        }
        other => panic!("expected UnresolvableZoneReference (match from-zone), got {other:?}"),
    }
    // Unresolvable match to-zone (with a default-permit, where a stale scoped
    // `deny` silently un-nets the safety net under the old behavior).
    let store2 = PolicyCounterStore::default();
    match parse_policy_state_with_counters(
        "permit",
        &[global_zone_rule("typo-to", "trust", "ghostzone", "deny")],
        &zones,
        &[],
        &store2,
    ) {
        Err(SnapshotIntegrityError::UnresolvableZoneReference { rule_id, zone }) => {
            assert!(rule_id.ends_with("/typo-to"), "rule_id={rule_id}");
            assert_eq!(zone, "ghostzone");
        }
        other => panic!("expected UnresolvableZoneReference (match to-zone), got {other:?}"),
    }
}

#[test]
fn global_policy_explicit_any_matches_all_zones() {
    // #3148 fold: an EXPLICIT `match from-zone any` is the Junos all-zones
    // default — identical to omitting the leaf. It must resolve to
    // GlobalZoneScope::Any (matches every from-zone), NOT route through
    // resolve_policy_zone_id("any") -> None, which since #3402 fails the whole
    // snapshot closed (UnresolvableZoneReference). Fail-on-revert: drop the
    // `name == "any"` short-circuit in build_global_zone_scope and parse now
    // ERRORS on the explicit `any`, so parse_policy_state panics here.
    let state = parse_policy_state(
        "deny",
        &[global_zone_rule("any-to-untrust", "any", "untrust", "permit")],
        &test_zone_name_to_id(),
    );
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval(&state, TEST_LAN_ZONE_ID, TEST_UNTRUST_ZONE_ID), PolicyAction::Permit);
    // Not into untrust → default deny (the to-zone scope still applies).
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Deny);

    // Symmetric: explicit `to-zone any`.
    let state = parse_policy_state(
        "deny",
        &[global_zone_rule("trust-to-any", "trust", "any", "permit")],
        &test_zone_name_to_id(),
    );
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval(&state, TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Deny);

    // Explicit `any` on BOTH sides == no zone context == all zones.
    let state = parse_policy_state(
        "deny",
        &[global_zone_rule("any-any", "any", "any", "permit")],
        &test_zone_name_to_id(),
    );
    assert_eq!(eval(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval(&state, TEST_UNTRUST_ZONE_ID, TEST_TRUST_ZONE_ID), PolicyAction::Permit);
}
// === #2358: NAT64 inbound cross-family (V6 src, V4 dst) policy matching ===
//
// For an inbound NAT64 flow the source remains the IPv6 client while the
// destination is translated to the real internal IPv4 host BEFORE the
// security-policy lookup (Junos/SRX order of operations). The forwarding
// path therefore evaluates the policy on a mixed (V6 src, V4 dst) tuple.
// These tests pin that a policy authored against the real IPv4 destination
// permits the flow, and that a policy authored only against the synthetic
// IPv6 NAT64 prefix no longer spuriously matches the translated tuple.

#[test]
fn nat64_inbound_policy_matches_real_v4_destination() {
    // from-zone wan (v6 ingress) -> to-zone lan (v4 server zone). The
    // operator writes the policy against the REAL internal v4 host.
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "permit-nat64-to-v4-host".to_string(),
            from_zone: "wan".to_string(),
            to_zone: "lan".to_string(),
            source_addresses: vec!["2001:559:8585:ef00::/64".to_string()],
            destination_addresses: vec!["172.16.80.200/32".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );
    // (V6 src, V4 dst): the post-translation tuple the dataplane feeds for
    // a NAT64 flow. FAIL-ON-REVERT: drop the policy.rs (V6 src, V4 dst)
    // arm and this returns Deny (mixed tuple matches no rule).
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_WAN_ZONE_ID,
            TEST_LAN_ZONE_ID,
            "2001:559:8585:ef00::100".parse().expect("v6 src"),
            "172.16.80.200".parse().expect("translated v4 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit,
        "NAT64 inbound must match the real translated IPv4 destination"
    );
}

#[test]
fn nat64_inbound_policy_v6_source_any_dest_v4_host() {
    // `source-address any` (family-unscoped) must still admit the v6
    // source against the v4-destination rule.
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "permit-any-to-v4-host".to_string(),
            from_zone: "wan".to_string(),
            to_zone: "lan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["172.16.80.200/32".to_string()],
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
            TEST_WAN_ZONE_ID,
            TEST_LAN_ZONE_ID,
            "2001:559:8585:ef00::100".parse().expect("v6 src"),
            "172.16.80.200".parse().expect("translated v4 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit,
        "source-address any must admit a v6 NAT64 source to the v4 host"
    );
}

#[test]
fn nat64_inbound_policy_specific_to_wrong_v4_host_denies() {
    // A policy scoped to a DIFFERENT real IPv4 host must NOT match the
    // translated destination — proving the v4 destination is actually
    // matched (not blanket match-any). With a concrete v4 prefix the
    // destination v4 set is non-empty, so the legacy "empty family =
    // match-any" convention does not apply and the wrong host falls to the
    // default deny.
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "permit-other-v4-host".to_string(),
            from_zone: "wan".to_string(),
            to_zone: "lan".to_string(),
            source_addresses: vec!["2001:559:8585:ef00::/64".to_string()],
            destination_addresses: vec!["172.16.80.201/32".to_string()],
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
            TEST_WAN_ZONE_ID,
            TEST_LAN_ZONE_ID,
            "2001:559:8585:ef00::100".parse().expect("v6 src"),
            "172.16.80.200".parse().expect("translated v4 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny,
        "a policy scoped to a different v4 host must not match the translated dst"
    );
}

#[test]
fn nat64_inbound_wrong_v6_source_denies() {
    // The v6 source side is still matched against the rule's IPv6 source
    // set: a v6 client outside the configured source prefix must be denied
    // even when the v4 destination matches.
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "permit-scoped-v6-src".to_string(),
            from_zone: "wan".to_string(),
            to_zone: "lan".to_string(),
            source_addresses: vec!["2001:559:8585:ef00::/64".to_string()],
            destination_addresses: vec!["172.16.80.200/32".to_string()],
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
            TEST_WAN_ZONE_ID,
            TEST_LAN_ZONE_ID,
            "2001:dead::1".parse().expect("off-prefix v6 src"),
            "172.16.80.200".parse().expect("translated v4 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny,
        "a v6 source outside the configured prefix must be denied"
    );
}

#[test]
fn nat46_v4_src_v6_dst_tuple_never_matches() {
    // The reverse cross-family tuple (V4 src, V6 dst) has no inbound
    // translation that produces it (NAT46 unsupported) and must fail
    // closed regardless of how permissive the rule is.
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "permit-all".to_string(),
            from_zone: "wan".to_string(),
            to_zone: "lan".to_string(),
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
            TEST_WAN_ZONE_ID,
            TEST_LAN_ZONE_ID,
            "10.0.61.100".parse().expect("v4 src"),
            "2001:559:8585:80::200".parse().expect("v6 dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny,
        "(V4 src, V6 dst) must never match — NAT46 is unsupported"
    );
}

// ===========================================================================
// #3346: application-term precedence is CONFIG ORDER (Junos first-term-wins),
// not the old class heuristic (exact-port always beats range beats
// icmp-constrained). These tests pin the per-application inactivity-timeout
// selected by CompiledApplications::matches to the FIRST listed matching term.
// ===========================================================================

fn exact_app(port: u16, timeout: Option<u32>) -> ApplicationMatch {
    ApplicationMatch {
        protocol: PROTO_TCP,
        source_ports: Vec::new(),
        destination_ports: vec![PortRange {
            low: port,
            high: port,
        }],
        icmp_type: None,
        icmp_code: None,
        inactivity_timeout: timeout,
    }
}

fn range_app(low: u16, high: u16, timeout: Option<u32>) -> ApplicationMatch {
    ApplicationMatch {
        protocol: PROTO_TCP,
        source_ports: Vec::new(),
        destination_ports: vec![PortRange { low, high }],
        icmp_type: None,
        icmp_code: None,
        inactivity_timeout: timeout,
    }
}

#[test]
fn app_term_range_listed_before_exact_wins() {
    // Range 80-90 listed FIRST, exact 80 listed SECOND. For dst port 80 (in
    // BOTH), Junos first-term-wins → the range term's timeout (200) must win.
    // RED-on-revert: the pre-#3346 class heuristic always probed exact_dst_ports
    // before range_terms, so the exact term's timeout (100) wrongly won.
    let apps = vec![range_app(80, 90, Some(200)), exact_app(80, Some(100))];
    let compiled = CompiledApplications::from_matches(&apps);
    assert_eq!(
        compiled.matches(PROTO_TCP, 12345, 80, None, true),
        Some(Some(200)),
        "range term listed first must win the timeout for a port both match"
    );
    // Port 85: only the range matches → 200 regardless of order.
    assert_eq!(
        compiled.matches(PROTO_TCP, 12345, 85, None, true),
        Some(Some(200))
    );
}

#[test]
fn app_term_exact_listed_before_range_wins() {
    // Reverse order: exact 80 listed FIRST, range 80-90 SECOND. For port 80 the
    // exact term is first → its timeout (100) wins. Confirms the fix is true
    // config-order, not "range always wins".
    let apps = vec![exact_app(80, Some(100)), range_app(80, 90, Some(200))];
    let compiled = CompiledApplications::from_matches(&apps);
    assert_eq!(
        compiled.matches(PROTO_TCP, 12345, 80, None, true),
        Some(Some(100)),
        "exact term listed first must win the timeout for a port both match"
    );
    // Port 85: only the range matches → 200.
    assert_eq!(
        compiled.matches(PROTO_TCP, 12345, 85, None, true),
        Some(Some(200))
    );
}

#[test]
fn app_term_icmp_constrained_before_all_icmp_wins() {
    // junos-ping (icmp type 8 → icmp_constraints) listed FIRST, junos-icmp-all
    // (unconstrained → range_terms empty-range match-all) SECOND. For an echo
    // (type 8) packet both match; first-term-wins → the constrained term's
    // timeout (11). RED-on-revert: the old order checked range_terms (icmp-all)
    // before icmp_constraints, so the all-ICMP timeout (22) wrongly won.
    let ping = ApplicationMatch {
        protocol: PROTO_ICMP,
        source_ports: Vec::new(),
        destination_ports: Vec::new(),
        icmp_type: Some(8),
        icmp_code: None,
        inactivity_timeout: Some(11),
    };
    let icmp_all = ApplicationMatch {
        protocol: PROTO_ICMP,
        source_ports: Vec::new(),
        destination_ports: Vec::new(),
        icmp_type: None,
        icmp_code: None,
        inactivity_timeout: Some(22),
    };
    let compiled = CompiledApplications::from_matches(&vec![ping.clone(), icmp_all.clone()]);
    assert_eq!(
        compiled.matches(PROTO_ICMP, 0, 0, Some((8, 0)), true),
        Some(Some(11)),
        "icmp-type-constrained term listed first must win for an echo packet"
    );
    // Reverse order: junos-icmp-all first → its timeout (22) wins.
    let compiled_rev = CompiledApplications::from_matches(&vec![icmp_all, ping]);
    assert_eq!(
        compiled_rev.matches(PROTO_ICMP, 0, 0, Some((8, 0)), true),
        Some(Some(22)),
        "all-icmp term listed first must win for an echo packet"
    );
}

// ── #3448: `clear security policies hit-count` must not replay pre-clear
// hits buffered in the per-worker pending coalescer ────────────────────────
//
// The #3073 coalescer (`record_policy_hit_counter`) buffers up to
// POLICY_HIT_FLUSH_PACKETS established-flow hits in a thread-local
// `PendingPolicyHitRecord` before folding them into the shared
// `PolicyRuleCounter` atomics. `clear()` only zeroes the shared atomics, so
// before #3448 a pending batch captured before the clear would `add_batch`
// its stale pre-clear counts onto the freshly-zeroed counter at the next
// flush — the clear appeared to fail or to invent traffic.
//
// These tests drive the load-bearing flush helper directly because the
// thread-local coalescer is compiled out under `#[cfg(test)]`.

#[test]
fn clear_discards_pre_clear_pending_policy_hits_3448() {
    let counter = Arc::new(PolicyRuleCounter::default());

    // A worker buffered 30 established-flow hits for an admitting policy that
    // have NOT yet been folded into the shared atomics.
    let mut pending = PendingPolicyHitRecord {
        counter: Some(counter.clone()),
        generation: counter.generation(),
        packets: 30,
        bytes: 30 * 100,
    };

    // Operator runs `clear security policies hit-count`: shared atomics zeroed,
    // clear epoch bumped.
    counter.reset();
    let after_clear = counter.snapshot("allow-web");
    assert_eq!(after_clear.packets, 0, "clear must zero the shared atomics");
    assert_eq!(after_clear.bytes, 0);

    // The worker's next RX-batch flush must DISCARD the stale pre-clear batch,
    // not replay it onto the freshly-zeroed counter.
    flush_pending_policy_hit_record(&mut pending);
    let after_flush = counter.snapshot("allow-web");
    assert_eq!(
        after_flush.packets, 0,
        "pre-clear pending hits replayed after clear (snap-back) — #3448"
    );
    assert_eq!(
        after_flush.bytes, 0,
        "pre-clear pending bytes replayed after clear (snap-back) — #3448"
    );
    // The discarded batch is drained so it cannot be re-applied.
    assert!(pending.counter.is_none());
    assert_eq!(pending.packets, 0);
    assert_eq!(pending.bytes, 0);
}

#[test]
fn post_clear_pending_policy_hits_flush_normally_3448() {
    let counter = Arc::new(PolicyRuleCounter::default());
    // Clear first so the live epoch is non-zero.
    counter.reset();

    // A batch captured AFTER the clear (current epoch) must flush normally —
    // the generation guard must not over-discard legitimate post-clear hits.
    let mut pending = PendingPolicyHitRecord {
        counter: Some(counter.clone()),
        generation: counter.generation(),
        packets: 7,
        bytes: 7 * 100,
    };
    flush_pending_policy_hit_record(&mut pending);
    let snap = counter.snapshot("allow-web");
    assert_eq!(
        snap.packets, 7,
        "post-clear hits captured under the current epoch must be counted"
    );
    assert_eq!(snap.bytes, 700);
}

#[test]
fn clear_bumps_policy_counter_generation_3448() {
    let counter = Arc::new(PolicyRuleCounter::default());
    let g0 = counter.generation();
    counter.reset();
    let g1 = counter.generation();
    counter.reset();
    let g2 = counter.generation();
    assert!(g1 > g0, "clear must advance the counter generation");
    assert!(g2 > g1, "each clear must advance the counter generation");
}

#[test]
fn store_clear_bumps_generation_for_all_counters_3448() {
    // PolicyCounterStore::clear (the control-plane `clear_policy_counters`
    // entry point) must bump every registered counter's epoch so buffered
    // pre-clear batches against any rule are discarded.
    let store = PolicyCounterStore::default();
    let c_allow = store.rule_hit_counter("security-policy:trust:untrust:allow-web");
    let c_deny = store.rule_hit_counter(DEFAULT_POLICY_COUNTER_RULE_ID);
    let g_allow0 = c_allow.generation();
    let g_deny0 = c_deny.generation();

    // Buffer a pre-clear batch against allow-web.
    let mut pending = PendingPolicyHitRecord {
        counter: Some(c_allow.clone()),
        generation: c_allow.generation(),
        packets: 50,
        bytes: 50 * 64,
    };

    store.clear();
    assert!(c_allow.generation() > g_allow0);
    assert!(c_deny.generation() > g_deny0);

    flush_pending_policy_hit_record(&mut pending);
    assert_eq!(
        c_allow.snapshot("allow-web").packets,
        0,
        "store clear must invalidate pre-clear pending batches — #3448"
    );
}

// #3451: lock the per-rule counter VALUE contract that the snapshot path
// exposes to `show security policies hit-count` / REST / Prometheus: `add` and
// `add_batch` accumulate into the right field, `snapshot` reports packets as
// packets and bytes as bytes (NO swap), and `reset` zeroes BOTH fields. These
// totals are exact regardless of the relaxed-pair semantics documented on
// `PolicyRuleCounter` (the pair can straddle one in-flight update, but each
// field's total never tears or double-counts). Reverting the field mapping —
// e.g. a packets/bytes swap in `snapshot`/`add_batch`, dropping an `add`, or a
// half-`reset` — makes one of these assertions RED.
#[test]
fn policy_rule_counter_snapshot_pairs_totals() {
    let counter = PolicyRuleCounter::default();

    // Single-packet adds (cold path): packet count +1 each, bytes += len.
    counter.add(100);
    counter.add(40);
    // Coalesced batch (established fast path, #3073): distinct packet and byte
    // magnitudes so a swap would be caught.
    counter.add_batch(3, 450);

    let snap = counter.snapshot("trust->untrust/allow-web");
    assert_eq!(snap.rule_id, "trust->untrust/allow-web");
    assert_eq!(
        snap.packets, 5,
        "packets must accumulate add + add_batch (2 + 3), not bytes"
    );
    assert_eq!(
        snap.bytes, 590,
        "bytes must accumulate add + add_batch (100 + 40 + 450), not packets"
    );

    // A zero-length add still counts the packet but adds no bytes.
    counter.add(0);
    let snap = counter.snapshot("trust->untrust/allow-web");
    assert_eq!(snap.packets, 6, "a zero-length packet still increments packets");
    assert_eq!(snap.bytes, 590, "a zero-length packet adds no bytes");

    // reset must zero BOTH fields (a half-reset leaving one field stale would
    // make `clear security policies hit-count` lie).
    counter.reset();
    let snap = counter.snapshot("trust->untrust/allow-web");
    assert_eq!(snap.packets, 0, "reset must zero packets");
    assert_eq!(snap.bytes, 0, "reset must zero bytes");
}
