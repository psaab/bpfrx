// Tests for the nat/ module. Moved into nat/tests.rs as part of the
// #1542 split. White-box tests reach into allocator internals via the
// `debug_live()` accessor and the `pub(super)` items promoted in
// allocator.rs / destination.rs.

use super::allocator::{
    ALLOCATION_GC_BUDGET, NS_PER_SEC, PersistentLease, PersistentSourceKey, PoolAddressFamily,
    sticky_pool_index,
};
use super::source::{PersistentNatPermit, SOURCE_NAT_PROTO_ANY, SourceNatFlowKey};
use super::destination::{PROTO_ANY, PROTO_TCP, PROTO_UDP};
use super::*;
use crate::ip_proto::{PROTO_ESP, PROTO_GRE, PROTO_ICMP, PROTO_ICMPV6};
use crate::{
    DestinationNATRuleSnapshot, NatAppTermWire, NatPortRangeWire, SourceNATRuleSnapshot,
    StaticNATRuleSnapshot,
};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn interface_source_nat_matches_v4_rule() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn interface_source_nat_matches_v6_rule() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["::/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn off_rule_short_circuits_translation() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "no-nat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.61.0/24".to_string()],
        off: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert_eq!(
        match_source_nat(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            "10.0.61.102".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            Some("172.16.80.8".parse().expect("egress")),
            None,
        ),
        Some(NatDecision::default())
    );
}

// === #2398: SNAT all-malformed match prefixes must fail CLOSED, not match-any ===

/// #2398 fail-on-revert: a SNAT rule whose configured source match set is
/// non-empty but whose entries ALL fail to parse must match NOTHING. Before
/// #2398 the empty parsed list collapsed to "match any source", so the SNAT
/// silently translated all traffic in the zone pair (fail-open broadening).
/// This test FAILS (SNAT fires) if the constrained flag / fail-closed path is
/// reverted to `nets.is_empty() || ...`.
#[test]
fn snat_all_malformed_source_match_fails_closed_v4() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-typo".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        // Every prefix is garbage / unparseable — operator typo.
        source_addresses: vec!["not-an-ip".to_string(), "10.0.0.0/99".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        decision, None,
        "all-malformed SNAT source match must NOT translate (fail closed) — \
         got a translation, which is the #2398 match-any fail-open"
    );
}

/// #2398 fail-on-revert (v6): same as above for an IPv6 SNAT rule.
#[test]
fn snat_all_malformed_source_match_fails_closed_v6() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat6-typo".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["::/999".to_string(), "garbage".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(
        decision, None,
        "all-malformed SNAT v6 source match must fail closed (#2398)"
    );
}

/// #2398: a malformed DESTINATION match set (non-empty, all-garbage) must also
/// fail closed — the destination side gets the same constrained-flag treatment.
#[test]
fn snat_all_malformed_destination_match_fails_closed_v4() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-dst-typo".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        // Source is valid (match any in zone), destination is all garbage.
        source_addresses: vec!["0.0.0.0/0".to_string()],
        destination_addresses: vec!["bogus".to_string(), "1.2.3.4/40".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        decision, None,
        "all-malformed SNAT destination match must fail closed (#2398)"
    );
}

/// #2398 (v6 destination): a SNAT rule with a non-empty but ALL-malformed v6
/// destination match set must match NOTHING. The fail-closed logic
/// (`destination_constrained` + `nets_match_v6`) is identical to the v4
/// destination path, so without this test a v6-destination-only regression
/// (e.g. `nets_match_v6` reverted to empty=match-any) would slip through. This
/// test FAILS (SNAT fires) if the v6 destination fail-closed path reverts.
#[test]
fn snat_all_malformed_destination_match_fails_closed_v6() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-dst-typo6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        // Source is valid (match any in zone), v6 destination is all garbage.
        source_addresses: vec!["::/0".to_string()],
        destination_addresses: vec!["bogus6".to_string(), "2001:db8::/999".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(
        decision, None,
        "all-malformed SNAT v6 destination match must fail closed (#2398)"
    );
}

/// #2398: a bare host v4 destination match IP (no `/prefix`) correctly scopes
/// the SNAT on the DESTINATION path — symmetric with the source bare-IP
/// fallback. Only traffic to the configured destination host is translated.
#[test]
fn snat_bare_host_destination_match_scopes_v4() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-bare-dst".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        destination_addresses: vec!["172.16.80.200".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    // Traffic to the configured destination host is translated.
    let hit = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        hit,
        Some(NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        }),
        "bare-host SNAT destination must translate traffic to the configured host (#2398)"
    );
    // Traffic to a different destination is NOT translated (scope held).
    let miss = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.201".parse().expect("other dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        miss, None,
        "bare-host SNAT destination must NOT translate traffic to a different host"
    );
}

/// #2398 (v6): bare host v6 destination match scopes the SNAT on the
/// destination path.
#[test]
fn snat_bare_host_destination_match_scopes_v6() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-bare-dst6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        destination_addresses: vec!["2001:559:8585:80::200".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let hit = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(
        hit,
        Some(NatDecision {
            rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        }),
        "bare-host v6 SNAT destination must translate traffic to the configured host (#2398)"
    );
    let miss = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::201".parse().expect("other dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(
        miss, None,
        "bare-host v6 SNAT destination must NOT translate traffic to a different host"
    );
}

/// #2398: a bare host match IP (no `/prefix`) correctly scopes the SNAT. Junos
/// carries `match source-address 10.0.61.102` verbatim; `IpNet::from_str`
/// rejects a bare IP, so without the bare-IP /32 fallback this rule would have
/// an empty parsed list and (after the fail-closed fix) match NOTHING. With the
/// fallback it matches exactly the host and only the host.
#[test]
fn snat_bare_host_source_match_scopes_v4() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-bare".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.61.102".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    // Configured host is translated.
    let hit = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        hit,
        Some(NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        }),
        "bare-host SNAT source must translate the configured host (#2398 fallback)"
    );
    // A different host is NOT translated (scope held, not match-any).
    let miss = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.200".parse().expect("other src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        miss, None,
        "bare-host SNAT must NOT translate a different source (no over-broadening)"
    );
}

/// #2398 (v6): bare host IPv6 match scopes the SNAT.
#[test]
fn snat_bare_host_source_match_scopes_v6() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-bare6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["2001:559:8585:ef00::100".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let hit = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(
        hit,
        Some(NatDecision {
            rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        }),
        "bare-host v6 SNAT source must translate the configured host (#2398)"
    );
    let miss = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::200".parse().expect("other src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(miss, None, "bare-host v6 SNAT must not translate a different source");
}

/// #2398 anti-over-restrict: a valid UNSCOPED SNAT (empty match set) still
/// translates all sources. This is the behavior we must NOT break while making
/// the all-malformed case fail closed.
#[test]
fn snat_unscoped_still_translates_all_sources() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-any".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        // No source/destination match prefixes — unconstrained.
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    for src in ["10.0.61.5", "192.0.2.7", "10.0.99.250"] {
        let decision = match_source_nat(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src.parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            Some("172.16.80.8".parse().expect("egress")),
            None,
        );
        assert_eq!(
            decision,
            Some(NatDecision {
                rewrite_src: Some("172.16.80.8".parse().expect("snat")),
                rewrite_dst: None,
                ..NatDecision::default()
            }),
            "unscoped SNAT must translate every source (anti-over-restrict, #2398) — {src}"
        );
    }
}

/// #2398 anti-over-restrict: a valid SCOPED SNAT translates only matching
/// traffic — the configured subnet is translated, an out-of-subnet source is
/// not.
#[test]
fn snat_valid_scoped_translates_only_matching() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-scoped".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.61.0/24".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let hit = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.50".parse().expect("in-subnet"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert!(hit.is_some(), "in-subnet source must be translated");
    let miss = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.62.50".parse().expect("out-of-subnet"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(miss, None, "out-of-subnet source must NOT be translated");
}

/// #2398: a MIXED valid+malformed source match set keeps the valid entries and
/// drops only the garbage — the match narrows to the valid prefix rather than
/// failing closed entirely or broadening to match-any.
#[test]
fn snat_mixed_valid_and_malformed_keeps_valid() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-mixed".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec![
            "garbage".to_string(),
            "10.0.61.0/24".to_string(),
            "10.0.0.0/99".to_string(),
        ],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    // Valid prefix still matches.
    let hit = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.7".parse().expect("in valid subnet"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert!(
        hit.is_some(),
        "mixed match set must keep the valid prefix and translate it (#2398)"
    );
    // Out-of-prefix source is not translated (no match-any leak from the garbage).
    let miss = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.62.7".parse().expect("out of valid subnet"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        miss, None,
        "mixed match set must NOT broaden to match-any from the dropped garbage (#2398)"
    );
}

#[test]
fn reverse_decision_turns_snat_into_reply_dnat() {
    let decision = NatDecision {
        rewrite_src: Some("172.16.80.8".parse().expect("snat")),
        rewrite_dst: None,
        ..NatDecision::default()
    };
    assert_eq!(
        decision.reverse(
            "10.0.61.102".parse().expect("orig src"),
            "172.16.80.200".parse().expect("orig dst"),
            12345,
            443,
        ),
        NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("10.0.61.102".parse().expect("orig src")),
            ..NatDecision::default()
        }
    );
}

#[test]
fn static_nat_dnat_matches_external_ip_v4() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.match_dnat("203.0.113.10".parse().expect("ext"), "untrust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("192.168.1.10".parse().expect("int")),
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_snat_matches_internal_ip_v4() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "trust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.match_snat("192.168.1.10".parse().expect("int"), "trust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("203.0.113.10".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_dnat_matches_external_ip_v6() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-v6".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "2001:db8::1".to_string(),
            internal_ip: "fd00::1".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.match_dnat("2001:db8::1".parse().expect("ext"), "untrust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("fd00::1".parse().expect("int")),
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_snat_matches_internal_ip_v6() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-v6".to_string(),
            from_zone: "trust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "2001:db8::1".to_string(),
            internal_ip: "fd00::1".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.match_snat("fd00::1".parse().expect("int"), "trust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("2001:db8::1".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

// #3031: block-to-block (subnet) static NAT — 1:1 by offset. A source
// host maps to the same offset in the destination block (network bits
// replaced, host bits preserved), both directions.

fn block_snapshot(ext: &str, int: &str, from_zone: &str) -> StaticNATRuleSnapshot {
    StaticNATRuleSnapshot {
        source_addresses: Vec::new(),
        counter_id: 0,
        name: "block-1".to_string(),
        from_zone: from_zone.to_string(),
        from_interface: String::new(),
        from_routing_instance: String::new(),
        external_ip: ext.to_string(),
        internal_ip: int.to_string(),
        match_destination_port: 0,
        mapped_port: 0,
    }
}

#[test]
fn static_nat_block_dnat_v4_preserves_offset() {
    // 198.51.100.0/24 (external) -> 192.168.1.0/24 (internal). An inbound
    // packet to 198.51.100.7 DNATs to 192.168.1.7 (offset .7 preserved).
    let table = StaticNatTable::from_snapshots(
        &[block_snapshot("198.51.100.0/24", "192.168.1.0/24", "untrust")],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.match_dnat("198.51.100.7".parse().expect("ext host"), "untrust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("192.168.1.7".parse().expect("int host")),
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_block_snat_v4_reverses_offset() {
    // Reverse: an outbound packet from 192.168.1.7 SNATs back to
    // 198.51.100.7 (the inverse offset map), so return traffic matches.
    let table = StaticNatTable::from_snapshots(
        &[block_snapshot("198.51.100.0/24", "192.168.1.0/24", "untrust")],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.match_snat("192.168.1.7".parse().expect("int host"), "untrust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("198.51.100.7".parse().expect("ext host")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_block_v6_preserves_offset_both_directions() {
    // /120 -> /120 v6 block map. Offset ::7 preserved both directions.
    let table = StaticNatTable::from_snapshots(
        &[block_snapshot("2001:db8:a::/120", "fd00:1::/120", "untrust")],
        &crate::nat::NatCounterStore::default(),
    );
    let dnat = table.match_dnat("2001:db8:a::7".parse().expect("ext v6"), "untrust");
    assert_eq!(
        dnat,
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("fd00:1::7".parse().expect("int v6")),
            ..NatDecision::default()
        })
    );
    let snat = table.match_snat("fd00:1::7".parse().expect("int v6"), "untrust");
    assert_eq!(
        snat,
        Some(NatDecision {
            rewrite_src: Some("2001:db8:a::7".parse().expect("ext v6")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_block_does_not_translate_outside_source_block() {
    // An address OUTSIDE the external block is not DNAT'd, and an address
    // outside the internal block is not SNAT'd.
    let table = StaticNatTable::from_snapshots(
        &[block_snapshot("198.51.100.0/24", "192.168.1.0/24", "untrust")],
        &crate::nat::NatCounterStore::default(),
    );
    assert_eq!(
        table.match_dnat("198.51.101.7".parse().expect("outside ext"), "untrust"),
        None
    );
    assert_eq!(
        table.match_snat("192.168.2.7".parse().expect("outside int"), "untrust"),
        None
    );
}

#[test]
fn static_nat_block_mismatched_length_is_skipped() {
    // A /24 -> /25 pair is not a 1:1 block map; the rule is skipped (no
    // table entry, no translation), preserving the #2122 skip rationale.
    let table = StaticNatTable::from_snapshots(
        &[block_snapshot("198.51.100.0/24", "192.168.1.0/25", "untrust")],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(table.is_empty());
    assert_eq!(
        table.match_dnat("198.51.100.7".parse().expect("ext host"), "untrust"),
        None
    );
}

#[test]
fn static_nat_block_with_port_is_dropped() {
    // #3202: a block (subnet) pair that ALSO carries a port match / mapped-port
    // is NOT representable by StaticNatBlock (address-only, all-port offset
    // remap). Installing it would silently widen "port 80 of this /24 -> 8080"
    // into "every port of the /24". The lenient-load backstop drops the rule
    // (fail closed) instead of mis-installing it. The Go strict commit-check
    // rejects this; this test pins the dataplane backstop.
    //
    // Fail-on-revert: removing the `snap.match_destination_port != 0 ||
    // snap.mapped_port != 0` skip in from_snapshots installs an all-port block
    // → table is non-empty and 198.51.100.7 DNATs to 192.168.1.7 → RED.
    let mut snap = block_snapshot("198.51.100.0/24", "192.168.1.0/24", "untrust");
    snap.match_destination_port = 80;
    snap.mapped_port = 8080;
    let table = StaticNatTable::from_snapshots(&[snap], &crate::nat::NatCounterStore::default());
    assert!(
        table.is_empty(),
        "a block pair with a port mapping must be dropped, not installed as an all-port block"
    );
    assert_eq!(
        table.match_dnat("198.51.100.7".parse().expect("ext host"), "untrust"),
        None
    );
}

#[test]
fn static_nat_block_with_match_port_only_is_dropped() {
    // A block pair with only a match destination-port (no mapped-port) is
    // equally not representable — also dropped by the #3202 backstop.
    let mut snap = block_snapshot("198.51.100.0/24", "192.168.1.0/24", "untrust");
    snap.match_destination_port = 80;
    let table = StaticNatTable::from_snapshots(&[snap], &crate::nat::NatCounterStore::default());
    assert!(table.is_empty());
}

#[test]
fn static_nat_host_v4_unchanged_with_block_support() {
    // #3031 regression: a /32 host rule still behaves byte-identical to
    // pre-#3031 (exact 1:1, no offset math). Both directions.
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10/32".to_string(),
            internal_ip: "192.168.1.10/32".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert_eq!(
        table.match_dnat("203.0.113.10".parse().expect("ext"), "untrust"),
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("192.168.1.10".parse().expect("int")),
            ..NatDecision::default()
        })
    );
    assert_eq!(
        table.match_snat("192.168.1.10".parse().expect("int"), "untrust"),
        Some(NatDecision {
            rewrite_src: Some("203.0.113.10".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
    // A non-mapped host (not the /32) is not translated.
    assert_eq!(
        table.match_dnat("203.0.113.11".parse().expect("other"), "untrust"),
        None
    );
}

#[test]
fn static_nat_zone_mismatch_returns_none_for_dnat() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    // DNAT from wrong zone should fail
    assert!(
        table
            .match_dnat("203.0.113.10".parse().expect("ext"), "trust")
            .is_none()
    );
    // #2871: SNAT (reverse) now honors the EGRESS zone symmetrically with
    // DNAT's ingress-zone gate. A packet egressing toward a zone OTHER than
    // the rule's external `from zone` ("untrust") must NOT be source-NAT'd.
    assert!(
        table
            .match_snat("192.168.1.10".parse().expect("int"), "dmz")
            .is_none()
    );
}

/// #2871 FAIL-ON-REVERT: static-NAT reverse (SNAT) must honor the EGRESS zone,
/// mirroring the #2864 DNAT ingress-zone gate. An outbound packet sourced from
/// a static-NAT internal IP but egressing toward a DIFFERENT internal zone
/// (east-west) must NOT be source-translated to the public external IP — that
/// was the cross-zone leak. It MUST still translate when egressing toward the
/// rule's external `from zone`.
///
/// Drop the `egress_zone` gate from `match_snat_with_counter` (the pre-#2871
/// "internal IP match is sufficient" behaviour) and the wrong-zone assertion
/// below flips to Some(..) — this test goes RED.
#[test]
fn static_nat_snat_honors_egress_zone() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "web-server".to_string(),
            // External zone of the rule: reverse SNAT applies only when the
            // packet egresses toward THIS zone.
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let internal: IpAddr = "192.168.1.10".parse().expect("int");

    // RIGHT zone: egressing toward the external zone "untrust" -> SNAT applies.
    assert_eq!(
        table.match_snat(internal, "untrust"),
        Some(NatDecision {
            rewrite_src: Some("203.0.113.10".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        }),
        "SNAT must apply when egressing toward the rule's external zone"
    );

    // WRONG zone: egressing toward another internal zone -> no source NAT.
    // This is the assertion that fails without the #2871 egress-zone gate.
    assert!(
        table.match_snat(internal, "trust").is_none(),
        "SNAT must NOT apply for an east-west packet egressing toward a \
         non-external zone (cross-zone leak #2871)"
    );
    assert!(
        table.match_snat(internal, "dmz").is_none(),
        "SNAT must NOT apply when egressing toward an unrelated internal zone"
    );
}

/// #2871: an empty external `from zone` ("any zone") still source-NATs on any
/// egress zone — the egress-zone gate must not regress wildcard rules.
#[test]
fn static_nat_snat_empty_zone_matches_any_egress() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "wildcard".to_string(),
            from_zone: String::new(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let internal: IpAddr = "192.168.1.10".parse().expect("int");
    for egress in ["untrust", "trust", "dmz"] {
        assert!(
            table.match_snat(internal, egress).is_some(),
            "wildcard (empty from_zone) SNAT must match any egress zone"
        );
    }
}

#[test]
fn static_nat_empty_zone_matches_any() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-any".to_string(),
            from_zone: String::new(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(
        table
            .match_dnat("203.0.113.10".parse().expect("ext"), "untrust")
            .is_some()
    );
    assert!(
        table
            .match_dnat("203.0.113.10".parse().expect("ext"), "trust")
            .is_some()
    );
    assert!(
        table
            .match_snat("192.168.1.10".parse().expect("int"), "trust")
            .is_some()
    );
}

#[test]
fn static_nat_bidirectional_reverse() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    // Inbound DNAT: external -> internal
    let dnat = table
        .match_dnat("203.0.113.10".parse().expect("ext"), "untrust")
        .expect("dnat");
    assert_eq!(
        dnat,
        NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("192.168.1.10".parse().expect("int")),
            ..NatDecision::default()
        }
    );
    // The reverse of DNAT should produce SNAT: on reply packets from
    // the internal host, rewrite src back to the external IP.
    // reverse().rewrite_src = self.rewrite_dst.map(|_| original_dst) = Some(external)
    // reverse().rewrite_dst = self.rewrite_src.map(|_| original_src) = None
    let original_src: IpAddr = "198.51.100.1".parse().expect("peer");
    let original_dst: IpAddr = "203.0.113.10".parse().expect("ext");
    let reverse = dnat.reverse(original_src, original_dst, 54321, 80);
    assert_eq!(
        reverse,
        NatDecision {
            rewrite_src: Some(original_dst),
            rewrite_dst: None,
            ..NatDecision::default()
        }
    );
}

#[test]
fn static_nat_no_match_returns_none() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(
        table
            .match_dnat("203.0.113.99".parse().expect("unknown"), "untrust")
            .is_none()
    );
    assert!(
        table
            .match_snat("192.168.1.99".parse().expect("unknown"), "trust")
            .is_none()
    );
}

#[test]
fn static_nat_invalid_ip_skipped() {
    let table = StaticNatTable::from_snapshots(
        &[
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "bad".to_string(),
                from_zone: String::new(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "not-an-ip".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "good".to_string(),
                from_zone: String::new(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    // The bad entry should be skipped, the good one should work
    assert!(
        table
            .match_dnat("203.0.113.10".parse().expect("ext"), "any")
            .is_some()
    );
}

#[test]
fn static_nat_external_ips_iterator() {
    let table = StaticNatTable::from_snapshots(
        &[
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "s1".to_string(),
                from_zone: String::new(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "s2".to_string(),
                from_zone: String::new(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.20".to_string(),
                internal_ip: "192.168.1.20".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let mut ips: Vec<IpAddr> = table.external_ips().copied().collect();
    ips.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
    assert_eq!(ips.len(), 2);
    assert!(ips.contains(&"203.0.113.10".parse::<IpAddr>().unwrap()));
    assert!(ips.contains(&"203.0.113.20".parse::<IpAddr>().unwrap()));
}

#[test]
fn static_nat_canonical_cidr_mask_v4_installs_entry() {
    // #2122: Junos emits static-NAT match/then in canonical prefix form
    // ("203.0.113.5/32" / "10.0.0.5/32") and the Go compiler copies the mask
    // verbatim into the snapshot. IpAddr::from_str rejects CIDR, so pre-fix
    // every rule hit the Err/skip arm and was silently dropped — no
    // translation occurred and the external IP was never registered as a
    // local address. The parse must strip the /32 mask. This test FAILS on
    // the unfixed code (table is empty, every assertion is None).
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-cidr".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.5/32".to_string(),
            internal_ip: "10.0.0.5/32".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    // Inbound DNAT on the bare external IP -> bare internal IP.
    assert_eq!(
        table.match_dnat("203.0.113.5".parse().expect("ext"), "untrust"),
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("10.0.0.5".parse().expect("int")),
            ..NatDecision::default()
        })
    );
    // Outbound SNAT on the bare internal IP -> bare external IP.
    assert_eq!(
        table.match_snat("10.0.0.5".parse().expect("int"), "untrust"),
        Some(NatDecision {
            rewrite_src: Some("203.0.113.5".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
    // The external IP must be registered (bare, no mask) for local delivery
    // recognition (forwarding_build iterates external_ips()).
    let ips: Vec<IpAddr> = table.external_ips().copied().collect();
    assert_eq!(ips, vec!["203.0.113.5".parse::<IpAddr>().unwrap()]);
}

#[test]
fn static_nat_canonical_cidr_mask_v6_installs_entry() {
    // IPv6 canonical host form carries /128; same root cause as the v4 case.
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-cidr-v6".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "2001:db8::1/128".to_string(),
            internal_ip: "fd00::1/128".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert_eq!(
        table.match_dnat("2001:db8::1".parse().expect("ext"), "untrust"),
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("fd00::1".parse().expect("int")),
            ..NatDecision::default()
        })
    );
    assert_eq!(
        table.match_snat("fd00::1".parse().expect("int"), "untrust"),
        Some(NatDecision {
            rewrite_src: Some("2001:db8::1".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
    let ips: Vec<IpAddr> = table.external_ips().copied().collect();
    assert_eq!(ips, vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
}

#[test]
fn static_nat_cidr_and_bare_coexist() {
    // A masked rule and a bare-IP rule must both install — stripping the mask
    // on one must not regress the other.
    let table = StaticNatTable::from_snapshots(
        &[
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "masked".to_string(),
                from_zone: String::new(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.5/32".to_string(),
                internal_ip: "10.0.0.5".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "bare".to_string(),
                from_zone: String::new(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.6".to_string(),
                internal_ip: "10.0.0.6/32".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(
        table
            .match_dnat("203.0.113.5".parse().expect("ext"), "any")
            .is_some()
    );
    assert!(
        table
            .match_dnat("203.0.113.6".parse().expect("ext"), "any")
            .is_some()
    );
    assert!(
        table
            .match_snat("10.0.0.5".parse().expect("int"), "any")
            .is_some()
    );
    assert!(
        table
            .match_snat("10.0.0.6".parse().expect("int"), "any")
            .is_some()
    );
}

#[test]
fn static_nat_non_host_mask_rejected() {
    // A non-host mask (or garbage suffix) is NOT a canonical host form and
    // must be rejected (skipped), not silently coerced to a host route — it
    // would otherwise translate the wrong scope. Pre-#2122 ALL of these were
    // rejected too (the bare parser errored on any mask), so this is not a
    // regression; it keeps the hardened parse strict about misconfiguration.
    for bad in [
        "203.0.113.5/24",      // non-host v4 prefix
        "203.0.113.5/notanum", // non-numeric mask
        "203.0.113.5/",        // empty mask
        "203.0.113.5//32",     // double slash
        "203.0.113.5/128",     // v6 host length applied to a v4 address
        "2001:db8::1/64",      // non-host v6 prefix
        "2001:db8::1/32",      // v4 host length applied to a v6 address
    ] {
        let table = StaticNatTable::from_snapshots(
            &[StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "bad-mask".to_string(),
                from_zone: String::new(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: bad.to_string(),
                internal_ip: "10.0.0.5".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            }],
            &crate::nat::NatCounterStore::default(),
        );
        assert_eq!(
            table.external_ips().count(),
            0,
            "non-host/garbage mask {bad:?} must be rejected, not installed"
        );
    }
}

// --- #2491 static-NAT port / mapped-port forwarding ---

fn mapped_port_snapshot() -> StaticNATRuleSnapshot {
    StaticNATRuleSnapshot {
        source_addresses: Vec::new(),
        counter_id: 0,
        name: "port-map".to_string(),
        from_zone: "untrust".to_string(),
        from_interface: String::new(),
        from_routing_instance: String::new(),
        external_ip: "203.0.113.1/32".to_string(),
        internal_ip: "10.0.0.5/32".to_string(),
        match_destination_port: 8080,
        mapped_port: 80,
    }
}

// Forward (inbound DNAT): a packet to the external IP on the matched external
// port is translated to the internal IP AND the destination port is rewritten
// to the mapped-port. A packet to the same IP on a DIFFERENT port misses (no
// port-less fallback entry, so no translation).
//
// Fail-on-revert: dropping `rewrite_dst_port: entry.mapped_port` in
// match_dnat_with_counter turns the rewrite_dst_port assertion RED.
#[test]
fn static_nat_mapped_port_dnat_rewrites_dst_port() {
    let table =
        StaticNatTable::from_snapshots(&[mapped_port_snapshot()], &crate::nat::NatCounterStore::default());
    let ext: IpAddr = "203.0.113.1".parse().unwrap();
    let int: IpAddr = "10.0.0.5".parse().unwrap();

    let (decision, _) = table
        .match_dnat_with_counter(ext, 8080, "untrust")
        .expect("matched external port");
    assert_eq!(decision.rewrite_dst, Some(int), "dst IP must be the internal host");
    assert_eq!(decision.rewrite_dst_port, Some(80), "dst port must be the mapped-port");

    // A non-matching external port must NOT translate (no whole-address
    // fallback present).
    assert!(
        table.match_dnat_with_counter(ext, 9999, "untrust").is_none(),
        "non-matching external port must miss"
    );
}

// Reverse (outbound return SNAT): the return packet from the internal host's
// mapped-port has its source IP rewritten back to the external IP AND its
// source port un-translated back to the external (match) port.
//
// Fail-on-revert: dropping `rewrite_src_port` in match_snat_with_counter (or
// keying snat on the internal IP without the mapped-port) turns the
// rewrite_src_port assertion RED / the lookup miss.
#[test]
fn static_nat_mapped_port_snat_untranslates_src_port() {
    let table =
        StaticNatTable::from_snapshots(&[mapped_port_snapshot()], &crate::nat::NatCounterStore::default());
    let ext: IpAddr = "203.0.113.1".parse().unwrap();
    let int: IpAddr = "10.0.0.5".parse().unwrap();

    let (decision, _) = table
        .match_snat_with_counter(int, 80, "untrust")
        .expect("matched internal mapped-port");
    assert_eq!(decision.rewrite_src, Some(ext), "src IP must be the external IP");
    assert_eq!(
        decision.rewrite_src_port,
        Some(8080),
        "src port must be un-translated to the external match port"
    );
}

// A whole-address rule and a port-mapped rule can coexist on the SAME external
// IP: the port-mapped entry wins on its exact port; everything else falls back
// to the whole-address mapping (no port rewrite).
#[test]
fn static_nat_port_mapped_and_whole_address_coexist() {
    let table = StaticNatTable::from_snapshots(
        &[
            mapped_port_snapshot(), // 203.0.113.1:8080 -> 10.0.0.5:80
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "whole".to_string(),
                from_zone: "untrust".to_string(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.1/32".to_string(),
                internal_ip: "10.0.0.9/32".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let ext: IpAddr = "203.0.113.1".parse().unwrap();

    // Port-mapped entry wins on 8080.
    let (port_dec, _) = table.match_dnat_with_counter(ext, 8080, "untrust").expect("port match");
    assert_eq!(port_dec.rewrite_dst, Some("10.0.0.5".parse().unwrap()));
    assert_eq!(port_dec.rewrite_dst_port, Some(80));

    // Any other port falls back to the whole-address mapping (no port rewrite).
    let (whole_dec, _) = table.match_dnat_with_counter(ext, 443, "untrust").expect("fallback match");
    assert_eq!(whole_dec.rewrite_dst, Some("10.0.0.9".parse().unwrap()));
    assert_eq!(whole_dec.rewrite_dst_port, None);
}

// Fail-closed: a mapped_port without a match_destination_port (which the Go
// strict commit-check rejects, but can slip through the lenient load path) is
// demoted to a whole-address 1:1 — no port rewrite, no orphaned port key.
#[test]
fn static_nat_mapped_port_without_match_port_demotes_to_whole_address() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "orphan".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.1/32".to_string(),
            internal_ip: "10.0.0.5/32".to_string(),
            match_destination_port: 0,
            mapped_port: 80,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let ext: IpAddr = "203.0.113.1".parse().unwrap();
    // Matches as a whole-address entry on any port, with NO port rewrite.
    let (decision, _) = table.match_dnat_with_counter(ext, 12345, "untrust").expect("whole-address match");
    assert_eq!(decision.rewrite_dst, Some("10.0.0.5".parse().unwrap()));
    assert_eq!(decision.rewrite_dst_port, None, "orphaned mapped-port must not rewrite");
}

// #2769: a `match destination-port` WITHOUT a `mapped-port` is a port-scoped
// 1:1 (no port translation). The reverse SNAT MUST stay scoped to the matched
// port — the internal service runs on, and its return packets leave from, the
// matched port (no translation happened). A return packet from ANY OTHER
// source port on the internal host MUST NOT be source-translated.
//
// Before #2769 the SNAT entry was keyed on `(internal_ip, None)`, so the
// reverse SNAT matched every source port → it source-translated every service
// on the internal host, not just the one port-scoped inbound. This is the
// whole-host NAT broadening the issue reports.
//
// Fail-on-revert: reverting the `let snat_port = mapped_port.or(match_dst_port)`
// scoping in from_snapshots back to `let snat_port = mapped_port` re-keys the
// SNAT entry on `None`; the off-port lookup then matches the fallback entry and
// the `is_none()` assertion goes RED.
#[test]
fn static_nat_match_port_without_mapped_port_scopes_reverse_snat() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "port-scoped-1to1".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.1/32".to_string(),
            internal_ip: "10.0.0.5/32".to_string(),
            match_destination_port: 8080,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let ext: IpAddr = "203.0.113.1".parse().unwrap();
    let int: IpAddr = "10.0.0.5".parse().unwrap();

    // Inbound DNAT is scoped to the matched port (no port-less fallback).
    let (dnat, _) = table
        .match_dnat_with_counter(ext, 8080, "untrust")
        .expect("matched external port");
    assert_eq!(dnat.rewrite_dst, Some(int), "dst IP must be the internal host");
    assert_eq!(
        dnat.rewrite_dst_port, None,
        "no mapped-port: destination port is not rewritten"
    );
    assert!(
        table.match_dnat_with_counter(ext, 9999, "untrust").is_none(),
        "off-port inbound must miss (port-scoped, no whole-address fallback)"
    );

    // Reverse SNAT: a return packet leaving the internal host on the matched
    // port (8080 — no translation happened) IS source-translated to the
    // external IP, with NO source-port rewrite.
    let (snat, _) = table
        .match_snat_with_counter(int, 8080, "untrust")
        .expect("return from the port-scoped service");
    assert_eq!(snat.rewrite_src, Some(ext), "src IP must be the external IP");
    assert_eq!(
        snat.rewrite_src_port, None,
        "no port translation: source port is not rewritten"
    );

    // The bug: a packet from ANY OTHER source port on the internal host MUST
    // NOT be source-translated. This is the whole-host broadening #2769 fixes.
    assert!(
        table.match_snat_with_counter(int, 1234, "untrust").is_none(),
        "off-port outbound must NOT be source-translated (reverse SNAT must \
         stay scoped to the matched port)"
    );
}

// #2864: a port-specific static-NAT DNAT entry whose `from_zone` does NOT match
// the packet's ingress zone MUST NOT short-circuit the lookup to `None`. It must
// fall through to the whole-address `(dst_ip, None)` entry, which carries its own
// (matching/empty) zone constraint. Before #2864 the zone check ran ONCE after
// the `or_else()` precedence resolved, so a zone-mismatched port-specific entry
// returned `None` and the whole-address rule was silently bypassed.
//
// Fail-on-revert: removing the per-candidate `.filter(zone_ok)` fall-through in
// match_dnat_with_counter (so a port-specific zone-fail short-circuits to None)
// turns the `fallback match` expect RED.
#[test]
fn static_nat_dnat_port_zone_mismatch_falls_back_to_whole_address() {
    let ext: IpAddr = "203.0.113.1".parse().unwrap();
    let table = StaticNatTable::from_snapshots(
        &[
            // Port-specific entry constrained to a DIFFERENT zone than the
            // packet will arrive on. (203.0.113.1:8080 from "dmz" -> 10.0.0.5:80)
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "port-dmz".to_string(),
                from_zone: "dmz".to_string(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.1/32".to_string(),
                internal_ip: "10.0.0.5/32".to_string(),
                match_destination_port: 8080,
                mapped_port: 80,
            },
            // Whole-address entry valid for the packet's actual ingress zone.
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "whole-untrust".to_string(),
                from_zone: "untrust".to_string(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.1/32".to_string(),
                internal_ip: "10.0.0.9/32".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );

    // A packet to the port-specific port (8080) but from the WRONG zone for the
    // port entry ("untrust", not "dmz") must NOT short-circuit: it falls back to
    // the whole-address entry, whose zone ("untrust") matches.
    let (whole_dec, _) = table
        .match_dnat_with_counter(ext, 8080, "untrust")
        .expect("fallback match — port-specific zone-fail must fall through to whole-address");
    assert_eq!(
        whole_dec.rewrite_dst,
        Some("10.0.0.9".parse().unwrap()),
        "must translate via the whole-address entry, not the zone-mismatched port entry"
    );
    assert_eq!(
        whole_dec.rewrite_dst_port, None,
        "whole-address entry has no mapped-port"
    );

    // Port-specific precedence is preserved when its zone DOES match: a packet
    // to 8080 from "dmz" hits the port entry (mapped-port rewrite), NOT the
    // whole-address entry.
    let (port_dec, _) = table
        .match_dnat_with_counter(ext, 8080, "dmz")
        .expect("port-specific entry wins when its zone matches");
    assert_eq!(port_dec.rewrite_dst, Some("10.0.0.5".parse().unwrap()));
    assert_eq!(port_dec.rewrite_dst_port, Some(80));

    // A non-port packet from "dmz" — the port entry does not key, and the
    // whole-address entry's zone ("untrust") does not match "dmz" → no DNAT.
    assert!(
        table.match_dnat_with_counter(ext, 443, "dmz").is_none(),
        "no candidate matches the ingress zone → no DNAT"
    );

    // A non-port packet from "untrust" hits the whole-address entry.
    let (any_dec, _) = table
        .match_dnat_with_counter(ext, 443, "untrust")
        .expect("whole-address entry matches its own zone on any port");
    assert_eq!(any_dec.rewrite_dst, Some("10.0.0.9".parse().unwrap()));

    // No entry for an unknown IP → no DNAT.
    assert!(
        table
            .match_dnat_with_counter("203.0.113.250".parse().unwrap(), 8080, "untrust")
            .is_none(),
        "unknown destination IP → no DNAT"
    );
}

// --- DNAT table tests ---

#[test]
fn dnat_basic_lookup_tcp() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            counter_id: 0,
            name: "web".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.lookup(
        PROTO_TCP,
        "198.51.100.1".parse().unwrap(),
        "203.0.113.10".parse().unwrap(),
        80,
        "",
    );
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        })
    );
}

#[test]
fn dnat_wildcard_port_fallback() {
    // port=0 entry matches any destination port
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            counter_id: 0,
            name: "any-port".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 0,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 0,
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    // Any port should match via wildcard
    let decision = table.lookup(
        PROTO_TCP,
        "198.51.100.1".parse().unwrap(),
        "203.0.113.10".parse().unwrap(),
        12345,
        "",
    );
    assert!(decision.is_some());
    let d = decision.unwrap();
    assert_eq!(d.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
    // port=0 wildcard: no port rewrite
    assert_eq!(d.rewrite_dst_port, None);
}

#[test]
fn dnat_protocol_specificity() {
    // TCP entry should not match UDP lookups
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            counter_id: 0,
            name: "tcp-only".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "198.51.100.1".parse().unwrap(),
                "203.0.113.10".parse().unwrap(),
                80,
                ""
            )
            .is_some()
    );
    assert!(
        table
            .lookup(
                PROTO_UDP,
                "198.51.100.1".parse().unwrap(),
                "203.0.113.10".parse().unwrap(),
                80,
                ""
            )
            .is_none()
    );
}

#[test]
fn dnat_ipv6_lookup() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            counter_id: 0,
            name: "web-v6".to_string(),
            destination_address: "2001:db8::1".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "fd00::1".to_string(),
            pool_port: 8443,
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.lookup(
        PROTO_TCP,
        "2001:db8:ffff::1".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        443,
        "",
    );
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_dst: Some("fd00::1".parse().unwrap()),
            rewrite_dst_port: Some(8443),
            ..NatDecision::default()
        })
    );
}

#[test]
fn dnat_multiple_entries() {
    let table = DnatTable::from_snapshots(
        &[
            DestinationNATRuleSnapshot {
                counter_id: 0,
                name: "http".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 80,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8080,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                counter_id: 0,
                name: "https".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8443,
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let http = table.lookup(
        PROTO_TCP,
        "198.51.100.1".parse().unwrap(),
        "203.0.113.10".parse().unwrap(),
        80,
        "",
    );
    assert_eq!(http.unwrap().rewrite_dst_port, Some(8080));
    let https = table.lookup(
        PROTO_TCP,
        "198.51.100.1".parse().unwrap(),
        "203.0.113.10".parse().unwrap(),
        443,
        "",
    );
    assert_eq!(https.unwrap().rewrite_dst_port, Some(8443));
}

#[test]
fn dnat_no_match_returns_none() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            counter_id: 0,
            name: "web".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    // Different IP
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "198.51.100.1".parse().unwrap(),
                "203.0.113.99".parse().unwrap(),
                80,
                ""
            )
            .is_none()
    );
    // Different port (no wildcard entry)
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "198.51.100.1".parse().unwrap(),
                "203.0.113.10".parse().unwrap(),
                443,
                ""
            )
            .is_none()
    );
}

// --- #2394: DNAT source-address constraint ---
//
// A DNAT rule scoped to `match source-address <X>` MUST fire only for packets
// whose source IP falls in X. Before #2394 the source constraint was dropped at
// the Go->Rust snapshot boundary, so the DNAT became destination-only and fired
// for ANY source — a fail-open that published the internal service to sources
// the operator scoped out. These tests fail (DNAT fires for the wrong source)
// if the source constraint is ever dropped again.

#[test]
fn dnat_source_scoped_matches_only_configured_source_v4() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "scoped-web".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            // Only sources in 198.51.100.0/24 may be DNAT'd.
            source_addresses: vec!["198.51.100.0/24".to_string()],
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    // Matching source -> DNAT fires.
    let hit = table.lookup(
        PROTO_TCP,
        "198.51.100.42".parse().unwrap(),
        "203.0.113.10".parse().unwrap(),
        80,
        "",
    );
    assert_eq!(
        hit,
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        }),
        "DNAT must fire for a source inside the configured source-address prefix"
    );
    // FAIL-ON-REVERT: a source OUTSIDE the configured prefix must NOT be DNAT'd.
    // If the source constraint is dropped this returns Some -> fail-open.
    let miss = table.lookup(
        PROTO_TCP,
        "203.0.113.200".parse().unwrap(),
        "203.0.113.10".parse().unwrap(),
        80,
        "",
    );
    assert_eq!(
        miss, None,
        "DNAT must NOT fire for a source outside the configured source-address (fail-open)"
    );
}

#[test]
fn dnat_source_scoped_matches_only_configured_source_v6() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "scoped-web-v6".to_string(),
            destination_address: "2001:db8::1".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "fd00::1".to_string(),
            pool_port: 8443,
            source_addresses: vec!["2001:db8:aaaa::/48".to_string()],
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    // Matching v6 source -> DNAT fires.
    let hit = table.lookup(
        PROTO_TCP,
        "2001:db8:aaaa::99".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        443,
        "",
    );
    assert!(
        hit.is_some(),
        "v6 DNAT must fire for a source inside the configured prefix"
    );
    // FAIL-ON-REVERT: non-matching v6 source must NOT be DNAT'd.
    let miss = table.lookup(
        PROTO_TCP,
        "2001:db8:bbbb::99".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        443,
        "",
    );
    assert_eq!(
        miss, None,
        "v6 DNAT must NOT fire for a source outside the configured prefix (fail-open)"
    );
}

#[test]
fn dnat_unscoped_matches_any_source() {
    // ANTI-OVER-RESTRICT: a DNAT rule with no source-address still DNATs every
    // source (the empty-source = match-any behavior must be preserved).
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "open-web".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            source_addresses: vec![],
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    for src in ["198.51.100.1", "203.0.113.250", "10.9.9.9"] {
        let d = table.lookup(
            PROTO_TCP,
            src.parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        );
        assert!(
            d.is_some(),
            "unscoped DNAT must fire for every source (src={src})"
        );
    }
}

#[test]
fn dnat_two_source_scoped_rules_same_dest_each_fire_for_own_source() {
    // Two source-scoped rules on the same (proto, dst, port) but different
    // source prefixes and pools. Each must fire only for its own source — the
    // dedup must not collapse them onto one entry.
    let table = DnatTable::from_snapshots(
        &[
            DestinationNATRuleSnapshot {
                name: "from-a".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 80,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8080,
                source_addresses: vec!["10.1.0.0/16".to_string()],
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                name: "from-b".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 80,
                protocol: "tcp".to_string(),
                pool_address: "192.168.2.20".to_string(),
                pool_port: 9090,
                source_addresses: vec!["10.2.0.0/16".to_string()],
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let a = table
        .lookup(
            PROTO_TCP,
            "10.1.5.5".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        )
        .expect("source A must match rule from-a");
    assert_eq!(a.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
    let b = table
        .lookup(
            PROTO_TCP,
            "10.2.5.5".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        )
        .expect("source B must match rule from-b");
    assert_eq!(b.rewrite_dst, Some("192.168.2.20".parse().unwrap()));
    // A third source matches neither -> no DNAT.
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "10.3.5.5".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        ),
        None,
        "a source outside both scoped prefixes must not be DNAT'd"
    );
}

// --- #2394 Copilot fold: bare-host source + all-malformed fail-closed ---

#[test]
fn dnat_source_scoped_bare_host_ip_v4_matches_only_that_host() {
    // The Go compiler carries `match source-address 198.51.100.42` (NO /prefix)
    // verbatim. `IpNet::from_str` rejects a bare IP, so without the bare-host
    // fallback this entry is skipped, the source list is empty, and the DNAT
    // matches ANY source — the #2394 fail-open. FAIL-ON-REVERT: removing the
    // bare-IP fallback makes the wrong-source lookup return Some.
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "bare-host".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            source_addresses: vec!["198.51.100.42".to_string()],
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    // The exact configured host -> DNAT fires.
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "198.51.100.42".parse().unwrap(),
                "203.0.113.10".parse().unwrap(),
                80,
                "",
            )
            .is_some(),
        "bare-host source-scoped DNAT must fire for the configured host"
    );
    // A different host -> must NOT be DNAT'd.
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "198.51.100.43".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        ),
        None,
        "bare-host source-scoped DNAT must NOT fire for a different host (fail-open)"
    );
}

#[test]
fn dnat_source_scoped_bare_host_ip_v6_matches_only_that_host() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "bare-host-v6".to_string(),
            destination_address: "2001:db8::1".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "fd00::1".to_string(),
            pool_port: 8443,
            source_addresses: vec!["2001:db8:aaaa::99".to_string()],
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "2001:db8:aaaa::99".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
                443,
                "",
            )
            .is_some(),
        "bare-host v6 source-scoped DNAT must fire for the configured host"
    );
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "2001:db8:aaaa::98".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            443,
            "",
        ),
        None,
        "bare-host v6 source-scoped DNAT must NOT fire for a different host (fail-open)"
    );
}

#[test]
fn dnat_source_scoped_all_malformed_fails_closed() {
    // A rule that WAS scoped (source_addresses non-empty) but every entry is
    // unparseable must match NOTHING — never silently revert to match-any.
    // FAIL-ON-REVERT: reverting `source_matches` to the old empty-list=match-any
    // form makes this lookup return Some (the all-malformed fail-open).
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "all-malformed".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            source_addresses: vec!["not-an-ip".to_string(), "999.999.0.0/16".to_string()],
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    for src in ["198.51.100.1", "203.0.113.250", "10.9.9.9"] {
        assert_eq!(
            table.lookup(
                PROTO_TCP,
                src.parse().unwrap(),
                "203.0.113.10".parse().unwrap(),
                80,
                "",
            ),
            None,
            "scoped DNAT with all-unparseable sources must match NOTHING (src={src})"
        );
    }
    // v6 source too -> still no match.
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "2001:db8::1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        ),
        None,
        "scoped DNAT with all-unparseable sources must match NOTHING for v6 too"
    );
}

#[test]
fn dnat_source_scoped_mixed_valid_and_malformed_keeps_valid() {
    // A scoped rule with one valid prefix and one garbage entry must still
    // enforce the valid prefix (garbage is dropped, not fail-open to any).
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "mixed".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            source_addresses: vec!["10.1.0.0/16".to_string(), "garbage".to_string()],
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "10.1.5.5".parse().unwrap(),
                "203.0.113.10".parse().unwrap(),
                80,
                "",
            )
            .is_some(),
        "the valid prefix must still match"
    );
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "10.2.5.5".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        ),
        None,
        "a source outside the valid prefix must not be DNAT'd despite the garbage entry"
    );
}

#[test]
fn dnat_multiple_destinations_each_fire() {
    // #2395: a DNAT rule with `match destination-address [ A B C ]` is emitted
    // by the Go builder as ONE snapshot per destination sharing the rule's
    // pool/port/counter. The dataplane keys DNAT by exact dst_ip, so each
    // destination must install its own table entry and translate. Before #2395
    // only the FIRST destination got a snapshot, so traffic to B and C was
    // forwarded untranslated. FAIL-ON-REVERT: with the collapse bug only the
    // first lookup returns Some — the B and C lookups assert Some here.
    let dests = ["203.0.113.20", "203.0.113.21", "203.0.113.22"];
    let snaps: Vec<DestinationNATRuleSnapshot> = dests
        .iter()
        .map(|d| DestinationNATRuleSnapshot {
            name: "multi-dnat".to_string(),
            destination_address: d.to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "10.0.0.5".to_string(),
            pool_port: 8443,
            ..DestinationNATRuleSnapshot::default()
        })
        .collect();
    let table = DnatTable::from_snapshots(&snaps, &crate::nat::NatCounterStore::default());
    for d in dests {
        let got = table.lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            d.parse().unwrap(),
            443,
            "",
        );
        assert_eq!(
            got.and_then(|dec| dec.rewrite_dst),
            Some("10.0.0.5".parse().unwrap()),
            "destination {d} of a multi-dest DNAT must be translated (collapse bug drops B/C)"
        );
        assert_eq!(
            got.unwrap().rewrite_dst_port,
            Some(8443),
            "destination {d} must rewrite the port to the shared pool port"
        );
    }
}

#[test]
fn dnat_multiple_destinations_v6_each_fire() {
    // #2395 IPv6 sibling: every v6 destination in the bracket list translates.
    let dests = ["2001:db8:beef::10", "2001:db8:beef::11"];
    let snaps: Vec<DestinationNATRuleSnapshot> = dests
        .iter()
        .map(|d| DestinationNATRuleSnapshot {
            name: "multi-dnat-v6".to_string(),
            destination_address: d.to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "2001:db8:dead::5".to_string(),
            pool_port: 0,
            ..DestinationNATRuleSnapshot::default()
        })
        .collect();
    let table = DnatTable::from_snapshots(&snaps, &crate::nat::NatCounterStore::default());
    for d in dests {
        let got = table.lookup(
            PROTO_TCP,
            "2001:db8:aaaa::1".parse().unwrap(),
            d.parse().unwrap(),
            443,
            "",
        );
        assert_eq!(
            got.and_then(|dec| dec.rewrite_dst),
            Some("2001:db8:dead::5".parse().unwrap()),
            "v6 destination {d} of a multi-dest DNAT must be translated"
        );
    }
}

#[test]
fn dnat_multiple_destinations_compose_with_source_scope() {
    // #2395 + #2394: a multi-destination DNAT that is ALSO source-scoped must
    // fire for each destination ONLY when the source matches. Each per-dest
    // snapshot carries the same source constraint (the Go builder shares
    // sourceAddrs across the destination loop). FAIL-ON-REVERT for both: a
    // dropped destination (collapse) loses B; a dropped source constraint
    // (#2394) fires for the wrong source.
    let dests = ["203.0.113.30", "203.0.113.31"];
    let snaps: Vec<DestinationNATRuleSnapshot> = dests
        .iter()
        .map(|d| DestinationNATRuleSnapshot {
            name: "multi-scoped".to_string(),
            destination_address: d.to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "10.0.0.5".to_string(),
            pool_port: 8080,
            source_addresses: vec!["198.51.100.0/24".to_string()],
            ..DestinationNATRuleSnapshot::default()
        })
        .collect();
    let table = DnatTable::from_snapshots(&snaps, &crate::nat::NatCounterStore::default());
    for d in dests {
        // In-scope source -> both destinations translate.
        assert!(
            table
                .lookup(
                    PROTO_TCP,
                    "198.51.100.7".parse().unwrap(),
                    d.parse().unwrap(),
                    80,
                    "",
                )
                .is_some(),
            "in-scope source must DNAT destination {d}"
        );
        // Out-of-scope source -> no translation for any destination.
        assert_eq!(
            table.lookup(
                PROTO_TCP,
                "203.0.113.250".parse().unwrap(),
                d.parse().unwrap(),
                80,
                "",
            ),
            None,
            "out-of-scope source must NOT DNAT destination {d} (#2394 not regressed)"
        );
    }
}

// #3164 helper: build a DNAT snapshot row as the Go builder emits it.
// `prefix` is the canonical masked CIDR for a non-host block (empty for a host).
fn dnat_row(
    name: &str,
    dst_addr: &str,
    dst_prefix: &str,
    pool: &str,
    port: u16,
) -> DestinationNATRuleSnapshot {
    DestinationNATRuleSnapshot {
        name: name.to_string(),
        destination_address: dst_addr.to_string(),
        destination_prefix: dst_prefix.to_string(),
        destination_port: port,
        protocol: "tcp".to_string(),
        pool_address: pool.to_string(),
        pool_port: 0,
        ..DestinationNATRuleSnapshot::default()
    }
}

#[test]
fn dnat_prefix_destination_matches_any_host_in_block() {
    // #3164 PRIMARY: `match destination-address [ A/32 B/32 C/24 ]` translates a
    // packet to A, B, or ANY host in C/24, and leaves a destination outside all
    // three untranslated. The Go builder emits A and B as exact-host rows
    // (destination_prefix empty) and C/24 as a prefix row (network base in
    // destination_address, canonical CIDR in destination_prefix).
    //
    // FAIL-ON-REVERT: revert to single-prefix exact-host-only matching and the
    // C/24 host probes (the "matches the third prefix" assertions) return None.
    let snaps = vec![
        dnat_row("multi", "203.0.113.5", "", "10.0.0.5", 443),
        dnat_row("multi", "203.0.113.6", "", "10.0.0.5", 443),
        dnat_row("multi", "192.0.2.0", "192.0.2.0/24", "10.0.0.5", 443),
    ];
    let table = DnatTable::from_snapshots(&snaps, &crate::nat::NatCounterStore::default());
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let pool: IpAddr = "10.0.0.5".parse().unwrap();

    for dst in [
        "203.0.113.5",   // A/32
        "203.0.113.6",   // B/32
        "192.0.2.1",     // first host in C/24
        "192.0.2.77",    // arbitrary host in C/24
        "192.0.2.254",   // last host in C/24
    ] {
        let got = table.lookup(PROTO_TCP, src, dst.parse().unwrap(), 443, "");
        assert_eq!(
            got.and_then(|d| d.rewrite_dst),
            Some(pool),
            "destination {dst} must match (A, B, or any host in C/24) and translate to the pool"
        );
    }

    for dst in [
        "198.51.100.99", // outside all three
        "203.0.113.7",   // adjacent to A/B but not listed
        "192.0.3.1",     // adjacent block, not in C/24
    ] {
        assert_eq!(
            table.lookup(PROTO_TCP, src, dst.parse().unwrap(), 443, ""),
            None,
            "destination {dst} is outside every configured prefix and must NOT translate"
        );
    }
}

#[test]
fn dnat_prefix_longest_match_wins() {
    // #3164 LPM: two overlapping prefixes must resolve by longest match. A more
    // specific /28 (pool P2) nested inside a /24 (pool P1): a host in the /28
    // translates to P2, a host in the /24 but outside the /28 to P1. An exact
    // host (/32, pool P3) inside the /28 wins over both (host = longest prefix,
    // exact-map fast path). FAIL-ON-REVERT: drop the longest-prefix tie-break
    // (e.g. return the first match) and the /28 host resolves to P1.
    let snaps = vec![
        dnat_row("wide", "192.0.2.0", "192.0.2.0/24", "10.0.0.1", 80),
        dnat_row("narrow", "192.0.2.16", "192.0.2.16/28", "10.0.0.2", 80),
        dnat_row("host", "192.0.2.20", "", "10.0.0.3", 80),
    ];
    let table = DnatTable::from_snapshots(&snaps, &crate::nat::NatCounterStore::default());
    let src: IpAddr = "198.51.100.1".parse().unwrap();

    // Host inside the /28 but not the exact host -> narrow /28 pool (P2).
    assert_eq!(
        table
            .lookup(PROTO_TCP, src, "192.0.2.18".parse().unwrap(), 80, "")
            .and_then(|d| d.rewrite_dst),
        Some("10.0.0.2".parse().unwrap()),
        "a host in the more-specific /28 must use the /28 pool (longest-prefix-match)"
    );
    // Host in the /24 but outside the /28 -> wide /24 pool (P1).
    assert_eq!(
        table
            .lookup(PROTO_TCP, src, "192.0.2.200".parse().unwrap(), 80, "")
            .and_then(|d| d.rewrite_dst),
        Some("10.0.0.1".parse().unwrap()),
        "a host in the /24 outside the /28 must use the /24 pool"
    );
    // Exact host inside the /28 -> exact-host pool (P3), beats both prefixes.
    assert_eq!(
        table
            .lookup(PROTO_TCP, src, "192.0.2.20".parse().unwrap(), 80, "")
            .and_then(|d| d.rewrite_dst),
        Some("10.0.0.3".parse().unwrap()),
        "an exact-host entry must win over any covering prefix (host = longest match)"
    );
}

#[test]
fn dnat_prefix_v6_matches_block() {
    // #3164 IPv6: a /64 destination prefix translates every host in the block.
    let snaps = vec![dnat_row(
        "v6-block",
        "2001:db8:beef::",
        "2001:db8:beef::/64",
        "2001:db8:dead::5",
        443,
    )];
    let table = DnatTable::from_snapshots(&snaps, &crate::nat::NatCounterStore::default());
    let src: IpAddr = "2001:db8:aaaa::1".parse().unwrap();
    let pool: IpAddr = "2001:db8:dead::5".parse().unwrap();
    for dst in ["2001:db8:beef::1", "2001:db8:beef::dead:beef", "2001:db8:beef:0:ffff::9"] {
        assert_eq!(
            table
                .lookup(PROTO_TCP, src, dst.parse().unwrap(), 443, "")
                .and_then(|d| d.rewrite_dst),
            Some(pool),
            "v6 host {dst} in the /64 block must translate"
        );
    }
    assert_eq!(
        table.lookup(PROTO_TCP, src, "2001:db8:cafe::1".parse().unwrap(), 443, ""),
        None,
        "a v6 host outside the /64 block must NOT translate"
    );
}

#[test]
fn dnat_prefix_destination_compose_with_source_scope() {
    // #3164 + #2394: a prefix DNAT that is ALSO source-scoped fires for a host
    // in the block ONLY when the source matches.
    let mut row = dnat_row("scoped-block", "192.0.2.0", "192.0.2.0/24", "10.0.0.5", 80);
    row.source_addresses = vec!["198.51.100.0/24".to_string()];
    let table = DnatTable::from_snapshots(&[row], &crate::nat::NatCounterStore::default());
    let dst: IpAddr = "192.0.2.42".parse().unwrap();
    assert!(
        table
            .lookup(PROTO_TCP, "198.51.100.7".parse().unwrap(), dst, 80, "")
            .is_some(),
        "in-scope source must DNAT a host in the destination prefix"
    );
    assert_eq!(
        table.lookup(PROTO_TCP, "203.0.113.9".parse().unwrap(), dst, 80, ""),
        None,
        "out-of-scope source must NOT DNAT a host in the destination prefix (#2394 holds)"
    );
}

#[test]
fn dnat_prefix_host_mask_collapses_to_exact() {
    // #3164 defensive: a /32 or /128 carried in destination_prefix is a host and
    // must collapse onto the exact map (no spurious prefix entry).
    let snaps = vec![
        dnat_row("h4", "203.0.113.10", "203.0.113.10/32", "10.0.0.5", 80),
        dnat_row("h6", "2001:db8::1", "2001:db8::1/128", "2001:db8:dead::5", 80),
    ];
    let table = DnatTable::from_snapshots(&snaps, &crate::nat::NatCounterStore::default());
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "198.51.100.1".parse().unwrap(),
                "203.0.113.10".parse().unwrap(),
                80,
                ""
            )
            .is_some(),
        "a /32 in destination_prefix must match as an exact host"
    );
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "2001:db8:aaaa::1".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
                80,
                ""
            )
            .is_some(),
        "a /128 in destination_prefix must match as an exact host"
    );
}

#[test]
fn dnat_prefix_destination_ips_registers_small_block_base_only_for_large() {
    // #3164 local-address registration: a small block (<= MAX_LOCAL_PREFIX_HOSTS)
    // expands host-by-host so the firewall answers proxy-ARP for the whole block;
    // a large block registers only its network base (the block must be routed to
    // the firewall). The DNAT MATCH is independent of this set in both cases.
    let small = dnat_row("small", "192.0.2.0", "192.0.2.0/24", "10.0.0.5", 0);
    let table = DnatTable::from_snapshots(&[small], &crate::nat::NatCounterStore::default());
    let ips: std::collections::HashSet<IpAddr> = table.destination_ips().collect();
    assert!(
        ips.contains(&"192.0.2.1".parse().unwrap())
            && ips.contains(&"192.0.2.254".parse().unwrap()),
        "a /24 block must register its usable hosts for proxy-ARP, got {} ips",
        ips.len()
    );

    let large = dnat_row("large", "10.0.0.0", "10.0.0.0/8", "10.9.9.9", 0);
    let table = DnatTable::from_snapshots(&[large], &crate::nat::NatCounterStore::default());
    let ips: std::collections::HashSet<IpAddr> = table.destination_ips().collect();
    assert!(
        ips.contains(&"10.0.0.0".parse().unwrap()),
        "a large block must still register its network base"
    );
    assert!(
        ips.len() <= 2,
        "a /8 block must NOT explode the local set (base only), got {} ips",
        ips.len()
    );
}

#[test]
fn dnat_port_aware_reverse() {
    // DNAT: rewrite dst to internal, rewrite dst_port from 80 to 8080
    let decision = NatDecision {
        rewrite_src: None,
        rewrite_dst: Some("192.168.1.10".parse().unwrap()),
        rewrite_src_port: None,
        rewrite_dst_port: Some(8080),
        nat64: false,
        nptv6: false,
    };
    // Reverse should turn rewrite_dst -> rewrite_src and port mapping too
    let reversed = decision.reverse(
        "198.51.100.1".parse().unwrap(), // original src
        "203.0.113.10".parse().unwrap(), // original dst
        54321,                           // original src_port
        80,                              // original dst_port
    );
    assert_eq!(reversed.rewrite_src, Some("203.0.113.10".parse().unwrap()));
    assert_eq!(reversed.rewrite_dst, None);
    assert_eq!(reversed.rewrite_src_port, Some(80));
    assert_eq!(reversed.rewrite_dst_port, None);
}

#[test]
fn dnat_snat_merge_preserves_both() {
    let dnat = NatDecision {
        rewrite_dst: Some("192.168.1.10".parse().unwrap()),
        rewrite_dst_port: Some(8080),
        ..NatDecision::default()
    };
    let snat = NatDecision {
        rewrite_src: Some("10.0.0.1".parse().unwrap()),
        ..NatDecision::default()
    };
    let merged = dnat.merge(snat);
    assert_eq!(merged.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
    assert_eq!(merged.rewrite_dst_port, Some(8080));
    assert_eq!(merged.rewrite_src, Some("10.0.0.1".parse().unwrap()));
    assert_eq!(merged.rewrite_src_port, None);
}

#[test]
fn default_nat_decision_unchanged() {
    let d = NatDecision::default();
    assert_eq!(d.rewrite_src, None);
    assert_eq!(d.rewrite_dst, None);
    assert_eq!(d.rewrite_src_port, None);
    assert_eq!(d.rewrite_dst_port, None);
    assert!(!d.nat64);
}

#[test]
fn dnat_empty_protocol_expands_to_both() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            counter_id: 0,
            name: "both".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 0,
            protocol: String::new(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 0,
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    // Both TCP and UDP should match
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "198.51.100.1".parse().unwrap(),
                "203.0.113.10".parse().unwrap(),
                53,
                ""
            )
            .is_some()
    );
    assert!(
        table
            .lookup(
                PROTO_UDP,
                "198.51.100.1".parse().unwrap(),
                "203.0.113.10".parse().unwrap(),
                53,
                ""
            )
            .is_some()
    );
}

#[test]
fn dnat_same_port_no_port_rewrite() {
    // When pool_port == destination_port, no port rewrite needed
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            counter_id: 0,
            name: "same-port".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 80,
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table
        .lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        )
        .unwrap();
    assert_eq!(decision.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
    // Same port: no rewrite needed
    assert_eq!(decision.rewrite_dst_port, None);
}

#[test]
fn dnat_destination_ips_iterator() {
    let table = DnatTable::from_snapshots(
        &[
            DestinationNATRuleSnapshot {
                counter_id: 0,
                name: "web".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 80,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8080,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                counter_id: 0,
                name: "ssh".to_string(),
                destination_address: "203.0.113.20".to_string(),
                destination_port: 22,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.20".to_string(),
                pool_port: 22,
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let mut ips: Vec<IpAddr> = table.destination_ips().collect();
    ips.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
    assert_eq!(ips.len(), 2);
    assert!(ips.contains(&"203.0.113.10".parse::<IpAddr>().unwrap()));
    assert!(ips.contains(&"203.0.113.20".parse::<IpAddr>().unwrap()));
}

#[test]
fn dnat_exact_port_beats_wildcard() {
    let table = DnatTable::from_snapshots(
        &[
            DestinationNATRuleSnapshot {
                counter_id: 0,
                name: "wildcard".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 0,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.100".to_string(),
                pool_port: 0,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                counter_id: 0,
                name: "exact".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 80,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8080,
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    // Exact match should win over wildcard
    let decision = table
        .lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        )
        .unwrap();
    assert_eq!(decision.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
    assert_eq!(decision.rewrite_dst_port, Some(8080));
    // Non-matching port should fall through to wildcard
    let decision = table
        .lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            443,
            "",
        )
        .unwrap();
    assert_eq!(decision.rewrite_dst, Some("192.168.1.100".parse().unwrap()));
    assert_eq!(decision.rewrite_dst_port, None);
}

#[test]
fn dnat_prefers_exact_from_zone_over_any_zone() {
    let table = DnatTable::from_snapshots(
        &[
            DestinationNATRuleSnapshot {
                counter_id: 0,
                name: "any-zone".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.200".to_string(),
                pool_port: 9443,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                counter_id: 0,
                name: "wan-only".to_string(),
                from_zone: "wan".to_string(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8443,
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table
        .lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            443,
            "wan",
        )
        .unwrap();
    assert_eq!(decision.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
    assert_eq!(decision.rewrite_dst_port, Some(8443));
}

#[test]
fn dnat_zone_mismatch_falls_back_to_any_zone_rule() {
    let table = DnatTable::from_snapshots(
        &[
            DestinationNATRuleSnapshot {
                counter_id: 0,
                name: "wan-only".to_string(),
                from_zone: "wan".to_string(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8443,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                counter_id: 0,
                name: "any-zone".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.200".to_string(),
                pool_port: 9443,
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table
        .lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            443,
            "dmz",
        )
        .unwrap();
    assert_eq!(decision.rewrite_dst, Some("192.168.1.200".parse().unwrap()));
    assert_eq!(decision.rewrite_dst_port, Some(9443));
}

#[test]
fn dnat_zone_mismatch_without_wildcard_returns_none() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            counter_id: 0,
            name: "wan-only".to_string(),
            from_zone: "wan".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8443,
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "198.51.100.1".parse().unwrap(),
                "203.0.113.10".parse().unwrap(),
                443,
                "dmz"
            )
            .is_none()
    );
}

#[test]
fn dnat_duplicate_same_zone_last_rule_wins() {
    let table = DnatTable::from_snapshots(
        &[
            DestinationNATRuleSnapshot {
                counter_id: 0,
                name: "first".to_string(),
                from_zone: "wan".to_string(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.101".to_string(),
                pool_port: 8443,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                counter_id: 0,
                name: "second".to_string(),
                from_zone: "wan".to_string(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.102".to_string(),
                pool_port: 9443,
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table
        .lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            443,
            "wan",
        )
        .unwrap();
    assert_eq!(decision.rewrite_dst, Some("192.168.1.102".parse().unwrap()));
    assert_eq!(decision.rewrite_dst_port, Some(9443));
}

#[test]
fn dnat_duplicate_any_zone_last_rule_wins() {
    let table = DnatTable::from_snapshots(
        &[
            DestinationNATRuleSnapshot {
                counter_id: 0,
                name: "first".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.101".to_string(),
                pool_port: 8443,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                counter_id: 0,
                name: "second".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.102".to_string(),
                pool_port: 9443,
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table
        .lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            443,
            "wan",
        )
        .unwrap();
    assert_eq!(decision.rewrite_dst, Some("192.168.1.102".parse().unwrap()));
    assert_eq!(decision.rewrite_dst_port, Some(9443));
}

// --- Pool-mode SNAT tests ---

// #3111: a single-address pool rule applied to a TCP flow allocates a port
// and rewrites BOTH the source IP and source port. This is the port-bearing
// positive case that must stay byte-identical after the port-less gate. The
// lookup uses the protocol-aware entry with TCP so the assertion exercises
// the real `allocate_translation` path (the proto-0 `match_source_nat`
// wrapper is now address-only — see the GRE/ESP test below).
#[test]
fn pool_snat_single_address_rewrites_src_and_port() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);
    let mut counter = None;
    let d = expect_snat_decision(match_source_nat_result_for_tuple(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().expect("src"),
        "8.8.8.8".parse().expect("dst"),
        PROTO_TCP,
        12345,
        443,
        None,
        None,
        0,
        false,
        &mut counter,
    ));
    assert_eq!(d.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert!(d.rewrite_src_port.is_some(), "TCP must allocate a port");
    let port = d.rewrite_src_port.unwrap();
    assert!(port >= 1024, "port {} out of range", port);
    assert_eq!(d.rewrite_dst, None);
    assert_eq!(d.rewrite_dst_port, None);
}

// #3111 FAIL-ON-REVERT: pool-mode source-NAT applied to a port-less protocol
// (GRE/ESP/AH/OSPF/...) must translate ONLY the source IP — it must NOT
// allocate a pool port and must leave `rewrite_src_port` unset. Before the
// fix the gate only special-cased `protocol == 0`, so GRE (47) / ESP (50)
// fell through to `allocate_translation`, which returned a pseudo-port that
// the descriptor fast-path rewriter then wrote over the first two L4 bytes —
// corrupting the GRE flags / ESP SPI and breaking the tunnel, plus leaking a
// pool port per flow.
//
// Reverting the source.rs gate (allocate a port for all protocols) makes
// `rewrite_src_port` `Some(_)` and consumes a pool port, turning both
// assertions RED.
#[test]
fn pool_snat_portless_protocols_translate_ip_only_no_port() {
    for proto in [PROTO_GRE, PROTO_ESP] {
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "pool-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "my-pool".to_string(),
            pool_addresses: vec!["203.0.113.1/32".to_string()],
            port_low: 1024,
            port_high: 65535,
            ..SourceNATRuleSnapshot::default()
        }]);
        let mut counter = None;
        let d = expect_snat_decision(match_source_nat_result_for_tuple(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            "10.0.1.100".parse().expect("src"),
            "8.8.8.8".parse().expect("dst"),
            proto,
            0,
            0,
            None,
            None,
            0,
            false,
            &mut counter,
        ));
        assert_eq!(
            d.rewrite_src,
            Some("203.0.113.1".parse().unwrap()),
            "proto {proto}: source IP must be translated to the pool address",
        );
        assert_eq!(
            d.rewrite_src_port, None,
            "proto {proto}: a port-less protocol must NOT allocate/rewrite an L4 port",
        );
        assert_eq!(d.rewrite_dst, None, "proto {proto}: dst must be untouched");
        assert_eq!(d.rewrite_dst_port, None, "proto {proto}: no dst port");

        // No pool port may be consumed for a port-less flow.
        let status = source_nat_pool_statuses(&rules);
        assert_eq!(
            status[0].used_ports, 0,
            "proto {proto}: no pool port may be allocated for a port-less protocol",
        );
    }
}

#[test]
fn pool_snat_multiple_addresses_round_robin() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-multi".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "multi-pool".to_string(),
        pool_addresses: vec![
            "203.0.113.1".to_string(),
            "203.0.113.2".to_string(),
            "203.0.113.3".to_string(),
        ],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);
    let mut seen_addrs = std::collections::HashSet::new();
    for _ in 0..6 {
        let d = match_source_nat(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            "10.0.1.100".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            None,
            None,
        )
        .expect("should match");
        if let Some(IpAddr::V4(addr)) = d.rewrite_src {
            seen_addrs.insert(addr);
        }
    }
    // After 6 allocations across 3 addresses, all should have been used.
    assert_eq!(
        seen_addrs.len(),
        3,
        "expected round-robin across all 3 addresses, got {:?}",
        seen_addrs
    );
}

// #3049: a subnet-style source-NAT pool address must enumerate the FULL
// prefix range, not collapse to the single network host. This is the
// fail-on-revert guard: pre-#3049 the parser stripped the `/28` mask and kept
// only `203.0.113.0`, so the pool had ONE address. With the fix a `/28` pool
// expands to all 16 host addresses and round-robin spreads across them.
#[test]
fn pool_snat_subnet_expands_full_cidr_range() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-subnet".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "subnet-pool".to_string(),
        // A /28 is 16 addresses: 203.0.113.0 .. 203.0.113.15.
        pool_addresses: vec!["203.0.113.0/28".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);
    // FAIL-ON-REVERT: the whole /28 must be enumerated. Pre-#3049 this was 1.
    assert_eq!(
        rules[0].pool_addresses_v4.len(),
        16,
        "a /28 source-NAT pool must expand to all 16 host addresses, not be \
         truncated to a single host"
    );
    assert_eq!(
        rules[0].pool_addresses_v4[0],
        "203.0.113.0".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert_eq!(
        rules[0].pool_addresses_v4[15],
        "203.0.113.15".parse::<std::net::Ipv4Addr>().unwrap()
    );

    // The allocator must actually hand out more than one address from the
    // expanded range — a single-host truncation would only ever return one.
    let mut seen = std::collections::HashSet::new();
    for i in 0..64u8 {
        let src = format!("10.0.1.{}", i);
        let d = match_source_nat(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src.parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            None,
            None,
        )
        .expect("should match subnet pool rule");
        if let Some(IpAddr::V4(addr)) = d.rewrite_src {
            seen.insert(addr);
        }
    }
    assert!(
        seen.len() > 1,
        "expected SNAT to spread across multiple pool addresses, saw {:?}",
        seen
    );
}

// #3049: a single-host pool prefix (/32, /128) must still yield exactly one
// address — the expansion must not over-broaden a host route.
#[test]
fn pool_snat_host_cidr_yields_single_address() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-host".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "host-pool".to_string(),
        pool_addresses: vec!["203.0.113.7/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert_eq!(rules[0].pool_addresses_v4.len(), 1);
    assert_eq!(
        rules[0].pool_addresses_v4[0],
        "203.0.113.7".parse::<std::net::Ipv4Addr>().unwrap()
    );

    // A v6 /120 expands to 256 addresses; a /128 stays a single host.
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-v6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["::/0".to_string()],
        pool_name: "v6-pool".to_string(),
        pool_addresses: vec!["2001:db8::/120".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert_eq!(rules[0].pool_addresses_v6.len(), 256);
}

// #3049: an over-broad pool prefix (host count beyond MAX_POOL_PREFIX_HOSTS)
// is rejected as an invalid pool rather than silently clamped or OOM-expanded.
#[test]
fn pool_snat_overbroad_prefix_marks_invalid() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-huge".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "huge-pool".to_string(),
        // /8 = ~16M hosts, far beyond the cap.
        pool_addresses: vec!["10.0.0.0/8".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert!(rules[0].pool_addresses_v4.is_empty());
    let d = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    // An invalid pool yields no usable translation (fail-closed, not a single
    // truncated host).
    assert!(d.is_none());
}

// --- #1827 PR-3: per-uplink SNAT pool selection by to-zone ---
//
// Multi-WAN per-uplink pools need NO new matcher: the to-zone fed to
// match_source_nat is derived from the RESOLVED egress interface of
// each new flow (zone_pair_ids_for_flow_with_override in
// poll_descriptor), so when ip-monitoring flips the preferred route
// (or an FBF term steers into an uplink's routing-instance), the
// to-zone follows the new egress interface and the other rule-set's
// pool is chosen. These tests pin the matcher half of that contract:
// two rules identical except to_zone select their own pools.

fn per_uplink_pool_rules() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "snat-isp-a".to_string(),
            from_zone: "trust".to_string(),
            to_zone: "untrust-a".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "isp-a-pool".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 1024,
            port_high: 65535,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "snat-isp-b".to_string(),
            from_zone: "trust".to_string(),
            to_zone: "untrust-b".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "isp-b-pool".to_string(),
            pool_addresses: vec!["198.51.100.10/32".to_string()],
            port_low: 1024,
            port_high: 65535,
            ..SourceNATRuleSnapshot::default()
        },
    ])
}

#[test]
fn per_uplink_pool_selected_by_to_zone() {
    let rules = per_uplink_pool_rules();
    // Same flow, resolved egress in uplink A's zone -> pool A.
    let d = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "trust",
        "untrust-a",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    )
    .expect("uplink A rule should match");
    assert_eq!(d.rewrite_src, Some("203.0.113.10".parse().unwrap()));

    // Identical flow after a route flip: resolved egress now sits in
    // uplink B's zone -> pool B, with no rule-set change.
    let d = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "trust",
        "untrust-b",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    )
    .expect("uplink B rule should match");
    assert_eq!(d.rewrite_src, Some("198.51.100.10".parse().unwrap()));
}

#[test]
fn per_uplink_pool_no_match_outside_uplink_zones() {
    let rules = per_uplink_pool_rules();
    // Egress resolving into a zone neither rule-set names must not
    // borrow either uplink's pool.
    assert_eq!(
        match_source_nat(
            &rules,
            &NatScopeCtx::default(),
            "trust",
            "dmz",
            "10.0.1.100".parse().unwrap(),
            "10.0.30.101".parse().unwrap(),
            None,
            None,
        ),
        None
    );
}

fn persistent_pool_rules(timeout_secs: i64, port_low: u16, port_high: u16) -> Vec<SourceNatRule> {
    persistent_pool_rules_with_options(
        timeout_secs,
        port_low,
        port_high,
        vec!["203.0.113.10"],
        false,
    )
}

fn persistent_pool_rules_with_options(
    timeout_secs: i64,
    port_low: u16,
    port_high: u16,
    pool_addresses: Vec<&str>,
    address_persistent: bool,
) -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[persistent_pool_snapshot(
        timeout_secs,
        port_low,
        port_high,
        pool_addresses,
        address_persistent,
    )])
}

fn persistent_pool_snapshot(
    timeout_secs: i64,
    port_low: u16,
    port_high: u16,
    pool_addresses: Vec<&str>,
    address_persistent: bool,
) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: "persistent-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "persistent-pool".to_string(),
        pool_addresses: pool_addresses
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>(),
        port_low,
        port_high,
        address_persistent,
        persistent_nat: true,
        persistent_nat_permit_any_remote_host: true,
        persistent_nat_inactivity_timeout: timeout_secs,
        ..SourceNATRuleSnapshot::default()
    }
}

/// #2397: build a persistent-NAT pool rule whose `permit-any-remote-host`
/// flag is set explicitly. The default `persistent_pool_snapshot` hardcodes
/// `true`; this lets the remote-host-scoping regression exercise both modes.
fn persistent_pool_rules_remote_scope(
    timeout_secs: i64,
    port_low: u16,
    port_high: u16,
    permit_any_remote_host: bool,
) -> Vec<SourceNatRule> {
    let mut snapshot =
        persistent_pool_snapshot(timeout_secs, port_low, port_high, vec!["203.0.113.10"], false);
    snapshot.persistent_nat_permit_any_remote_host = permit_any_remote_host;
    parse_source_nat_rules(&[snapshot])
}

fn tuple_snat_lookup(
    rules: &[SourceNatRule],
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    now_ns: u64,
) -> SourceNatLookup {
    tuple_snat_lookup_from_src(rules, "10.0.1.100", src_port, dst_ip, dst_port, now_ns)
}

fn tuple_snat_lookup_from_src(
    rules: &[SourceNatRule],
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    now_ns: u64,
) -> SourceNatLookup {
    let mut counter = None;
    match_source_nat_result_for_tuple(
        rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src_ip.parse().unwrap(),
        dst_ip.parse().unwrap(),
        6,
        src_port,
        dst_port,
        None,
        None,
        now_ns,
        false,
        &mut counter,
    )
}

fn expect_snat_decision(lookup: SourceNatLookup) -> NatDecision {
    match lookup {
        SourceNatLookup::Matched(decision) => decision,
        other => panic!("expected matched SNAT decision, got {other:?}"),
    }
}

fn session_key(src_port: u16, dst_ip: &str, dst_port: u16) -> crate::session::SessionKey {
    session_key_from_src("10.0.1.100", src_port, dst_ip, dst_port)
}

fn lease_key(src_port: u16) -> PersistentSourceKey {
    // #2397: the surrounding tests build rules with
    // `permit_any_remote_host: true`, so the lease is keyed by the local
    // source tuple only (`remote: None`) and reused across remote hosts.
    PersistentSourceKey {
        protocol: 6,
        src_ip: "10.0.1.100".parse().unwrap(),
        src_port,
        remote: None,
    }
}

fn session_key_from_src(
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: src_ip.parse().unwrap(),
        dst_ip: dst_ip.parse().unwrap(),
        src_port,
        dst_port,
    }
}

fn assert_persistent_expiry_indexes_consistent(rule: &SourceNatRule) {
    let live = rule.pool_allocator.debug_live();
    let mut expected_global = BTreeSet::new();
    let mut expected_by_addr = vec![BTreeSet::new(); live.lease_expirations_by_addr.len()];

    for (key, lease) in &live.persistent_by_source {
        let entry = (lease.expires_at_ns, *key);
        assert!(
            lease.addr_index < expected_by_addr.len(),
            "persistent lease addr index {} out of range {}",
            lease.addr_index,
            expected_by_addr.len()
        );
        assert_eq!(
            live.addr_index_by_translated
                .get(&lease.translated)
                .copied(),
            Some(lease.addr_index),
            "persistent lease addr index mismatch"
        );
        assert_eq!(
            pool_ip_for_addr_index(rule, lease.addr_index),
            Some(lease.translated.ip),
            "persistent lease translated address mismatch"
        );
        if lease.active_flows == 0 {
            expected_global.insert(entry);
            expected_by_addr[lease.addr_index].insert(entry);
        }
    }

    assert_eq!(
        live.lease_expirations, expected_global,
        "global persistent expiry index mismatch"
    );
    assert_eq!(
        live.lease_expirations_by_addr, expected_by_addr,
        "per-address persistent expiry index mismatch"
    );
}

fn pool_ip_for_addr_index(rule: &SourceNatRule, addr_index: usize) -> Option<IpAddr> {
    if addr_index < rule.pool_addresses_v4.len() {
        return Some(IpAddr::V4(rule.pool_addresses_v4[addr_index]));
    }
    let v6_index = addr_index.checked_sub(rule.pool_addresses_v4.len())?;
    rule.pool_addresses_v6
        .get(v6_index)
        .copied()
        .map(IpAddr::V6)
}

#[test]
fn pool_snat_persistent_reuses_same_source_tuple() {
    let rules = persistent_pool_rules(300, 40000, 40010);
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 53, 1));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "1.1.1.1", 443, 2));

    assert_eq!(first.rewrite_src, second.rewrite_src);
    assert_eq!(first.rewrite_src_port, second.rewrite_src_port);

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].allocations_total, 1);
    assert_eq!(status[0].reuses_total, 1);
    assert_eq!(status[0].persistent_leases, 1);
    assert_eq!(status[0].live_flows, 2);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

/// #2397 FAIL-ON-REVERT: with `permit-any-remote-host` DISABLED, the
/// persistent mapping must be bound to the original remote endpoint. A second
/// flow from the same local source to a DIFFERENT remote 5-tuple must NOT
/// reuse the first translated mapping — it gets a distinct lease and a
/// distinct port. The enabled-flag mode (asserted in the sibling test below
/// and in `pool_snat_persistent_reuses_same_source_tuple`) keeps the historical
/// any-remote reuse. Reverting the remote-scoping key change makes the
/// disabled-flag branch reuse the mapping again and this assertion goes RED.
#[test]
fn pool_snat_persistent_no_permit_any_remote_scopes_to_remote_host() {
    let rules = persistent_pool_rules_remote_scope(300, 40000, 40010, false);

    // First flow: same local source (10.0.1.100:12345) to remote 8.8.8.8:53.
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 53, 1));
    // Second flow: SAME local source, DIFFERENT remote (1.1.1.1:443).
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "1.1.1.1", 443, 2));

    // permit-any-remote-host=false => the second remote must NOT inherit the
    // first remote's persistent mapping.
    assert_ne!(
        (first.rewrite_src, first.rewrite_src_port),
        (second.rewrite_src, second.rewrite_src_port),
        "permit-any-remote-host=false must scope the persistent lease to the \
         original remote host: a different remote 5-tuple must get a distinct \
         translated mapping (issue #2397)"
    );

    // A THIRD flow back to the original remote 8.8.8.8:53 must reuse the first
    // mapping (the lease is scoped TO that remote, not destroyed).
    let third = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 53, 3));
    assert_eq!(
        (third.rewrite_src, third.rewrite_src_port),
        (first.rewrite_src, first.rewrite_src_port),
        "the same local source returning to the ORIGINAL remote must reuse its \
         own remote-scoped persistent mapping"
    );

    // Two distinct remotes => two distinct leases, both live.
    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].persistent_leases, 2);
    assert_eq!(status[0].allocations_total, 2);
    assert_eq!(status[0].reuses_total, 1);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

/// #2397 control: with `permit-any-remote-host` ENABLED, the historical
/// any-remote reuse is preserved — a second flow from the same local source to
/// a different remote reuses the first translated mapping (one lease).
#[test]
fn pool_snat_persistent_permit_any_remote_reuses_across_remotes() {
    let rules = persistent_pool_rules_remote_scope(300, 40000, 40010, true);

    let first = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 53, 1));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "1.1.1.1", 443, 2));

    assert_eq!(
        (first.rewrite_src, first.rewrite_src_port),
        (second.rewrite_src, second.rewrite_src_port),
        "permit-any-remote-host=true must reuse the persistent mapping across \
         remote hosts (unchanged behavior)"
    );

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].persistent_leases, 1);
    assert_eq!(status[0].allocations_total, 1);
    assert_eq!(status[0].reuses_total, 1);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

/// #2823: build a persistent-NAT pool rule with an explicit three-way
/// `permit` mode string ("any-remote-host" | "target-host" |
/// "target-host-port"), exercising the full enum wire path through
/// `PersistentNatPermit::from_wire`.
fn persistent_pool_rules_permit(
    timeout_secs: i64,
    port_low: u16,
    port_high: u16,
    permit: &str,
) -> Vec<SourceNatRule> {
    let mut snapshot =
        persistent_pool_snapshot(timeout_secs, port_low, port_high, vec!["203.0.113.10"], false);
    // Clear the legacy bool so the string is the sole source of truth.
    snapshot.persistent_nat_permit_any_remote_host = false;
    snapshot.persistent_nat_permit = permit.to_string();
    parse_source_nat_rules(&[snapshot])
}

/// #2823 FAIL-ON-REVERT: `permit target-host` scopes the persistent lease
/// to the remote HOST only (dst_ip), dropping the remote PORT from the key.
/// A second flow from the same local source to a NEW remote PORT on the
/// SAME remote host MUST reuse the first translated mapping. Reverting the
/// target-host branch to (dst_ip, dst_port) keying makes the new-port flow
/// allocate a distinct mapping and turns the reuse assertion RED — while the
/// sibling `target-host-port` test (which expects no-reuse) stays GREEN.
#[test]
fn pool_snat_persistent_target_host_reuses_across_remote_ports() {
    let rules = persistent_pool_rules_permit(300, 40000, 40010, "target-host");

    // First flow: same local source to remote 8.8.8.8:53.
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 53, 1));
    // Second flow: SAME local source, SAME remote HOST, DIFFERENT remote PORT.
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 443, 2));

    assert_eq!(
        (first.rewrite_src, first.rewrite_src_port),
        (second.rewrite_src, second.rewrite_src_port),
        "permit target-host must reuse the persistent mapping for a NEW remote \
         port on the SAME remote host (issue #2823)"
    );

    // A DIFFERENT remote HOST must get a distinct lease (the scope is the
    // remote host, not global).
    let other_host = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "1.1.1.1", 53, 3));
    assert_ne!(
        (first.rewrite_src, first.rewrite_src_port),
        (other_host.rewrite_src, other_host.rewrite_src_port),
        "permit target-host must scope the lease to the remote host: a \
         different remote host must get a distinct mapping"
    );

    let status = source_nat_pool_statuses(&rules);
    // Two distinct remote HOSTS => two leases; the new-port reuse adds a reuse.
    assert_eq!(status[0].persistent_leases, 2);
    assert_eq!(status[0].allocations_total, 2);
    assert_eq!(status[0].reuses_total, 1);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

/// #2823: `permit target-host-port` keys the lease by the full remote
/// endpoint (dst_ip + dst_port). A second flow from the same local source to
/// the SAME remote host but a DIFFERENT remote PORT must NOT reuse the first
/// mapping — it gets a distinct lease and port. This is the pre-#2823
/// behavior and the back-compat default.
#[test]
fn pool_snat_persistent_target_host_port_distinct_per_remote_port() {
    let rules = persistent_pool_rules_permit(300, 40000, 40010, "target-host-port");

    let first = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 53, 1));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 443, 2));

    assert_ne!(
        (first.rewrite_src, first.rewrite_src_port),
        (second.rewrite_src, second.rewrite_src_port),
        "permit target-host-port must scope the lease to the remote host:PORT: \
         a different remote port must get a distinct mapping (issue #2823)"
    );

    // Returning to the ORIGINAL remote host:port reuses its own lease.
    let third = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 53, 3));
    assert_eq!(
        (third.rewrite_src, third.rewrite_src_port),
        (first.rewrite_src, first.rewrite_src_port),
        "returning to the original remote host:port must reuse its lease"
    );

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].persistent_leases, 2);
    assert_eq!(status[0].allocations_total, 2);
    assert_eq!(status[0].reuses_total, 1);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

/// #2823: `permit any-remote-host` keys the lease by the local source tuple
/// only — ANY remote (different host AND/OR port) reuses the mapping. Driven
/// through the enum string wire path.
#[test]
fn pool_snat_persistent_any_remote_host_reuses_everywhere() {
    let rules = persistent_pool_rules_permit(300, 40000, 40010, "any-remote-host");

    let first = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 53, 1));
    // Different host AND different port.
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "1.1.1.1", 443, 2));

    assert_eq!(
        (first.rewrite_src, first.rewrite_src_port),
        (second.rewrite_src, second.rewrite_src_port),
        "permit any-remote-host must reuse the persistent mapping across any \
         remote host:port (issue #2823)"
    );

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].persistent_leases, 1);
    assert_eq!(status[0].allocations_total, 1);
    assert_eq!(status[0].reuses_total, 1);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

/// #3193 FAIL-ON-REVERT: the source-NAT pool STATUS surface must carry the
/// full three-way `persistent_nat_permit` mode so the operator SHOW path can
/// distinguish target-host from target-host-port. Before #3193 the status
/// exposed only the binary `persistent_nat_permit_any_remote_host` flag, which
/// is identical (false) for BOTH target-host and target-host-port. Reverting
/// `status.rs` to emit only that bool turns the target-host != target-host-port
/// assertion below RED.
#[test]
fn pool_status_reports_three_way_persistent_permit_mode() {
    let any = source_nat_pool_statuses(&persistent_pool_rules_permit(
        300,
        40000,
        40010,
        "any-remote-host",
    ));
    let host = source_nat_pool_statuses(&persistent_pool_rules_permit(
        300,
        40000,
        40010,
        "target-host",
    ));
    let host_port = source_nat_pool_statuses(&persistent_pool_rules_permit(
        300,
        40000,
        40010,
        "target-host-port",
    ));

    assert_eq!(any[0].persistent_nat_permit, "any-remote-host");
    assert_eq!(host[0].persistent_nat_permit, "target-host");
    assert_eq!(host_port[0].persistent_nat_permit, "target-host-port");

    // The legacy binary flag CANNOT tell the two target modes apart.
    assert_eq!(
        host[0].persistent_nat_permit_any_remote_host,
        host_port[0].persistent_nat_permit_any_remote_host,
        "the legacy bool is identical for target-host and target-host-port"
    );
    // The three-way mode MUST.
    assert_ne!(
        host[0].persistent_nat_permit, host_port[0].persistent_nat_permit,
        "target-host and target-host-port must be distinguishable in status (#3193)"
    );
}

/// #2823: an EMPTY wire `persistent_nat_permit` string (old control plane)
/// falls back to the legacy bool. bool=false must mean target-host-port (the
/// pre-#2823 (dst_ip, dst_port) keying), so a new remote port does NOT reuse.
#[test]
fn pool_snat_persistent_permit_empty_string_falls_back_to_legacy_bool() {
    // Empty string + bool=false => TargetHostPort.
    let mut snapshot = persistent_pool_snapshot(300, 40000, 40010, vec!["203.0.113.10"], false);
    snapshot.persistent_nat_permit_any_remote_host = false;
    snapshot.persistent_nat_permit = String::new();
    let rules = parse_source_nat_rules(&[snapshot]);

    let first = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 53, 1));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 443, 2));
    assert_ne!(
        (first.rewrite_src, first.rewrite_src_port),
        (second.rewrite_src, second.rewrite_src_port),
        "empty permit string + legacy bool=false must behave as target-host-port"
    );
}

#[test]
fn pool_snat_persistent_reassigns_after_timeout() {
    let rules = persistent_pool_rules(2, 40000, 40001);
    let first = expect_snat_decision(tuple_snat_lookup(
        &rules,
        12345,
        "8.8.8.8",
        53,
        1_000_000_000,
    ));
    release_source_nat_allocation(
        &rules,
        &session_key(12345, "8.8.8.8", 53),
        first,
        false,
        2_000_000_000,
    );

    let reused = expect_snat_decision(tuple_snat_lookup(
        &rules,
        12345,
        "1.1.1.1",
        443,
        3_000_000_000,
    ));
    assert_eq!(first.rewrite_src_port, reused.rewrite_src_port);
    release_source_nat_allocation(
        &rules,
        &session_key(12345, "1.1.1.1", 443),
        reused,
        false,
        3_500_000_000,
    );

    let reassigned = expect_snat_decision(tuple_snat_lookup(
        &rules,
        12345,
        "9.9.9.9",
        853,
        6_000_000_000,
    ));
    assert_eq!(reassigned.rewrite_src, first.rewrite_src);
    assert_ne!(reassigned.rewrite_src_port, first.rewrite_src_port);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
fn pool_snat_persistent_compatible_refresh_preserves_lease_state() {
    let snapshot = persistent_pool_snapshot(300, 40000, 40001, vec!["203.0.113.10"], false);
    let rules = parse_source_nat_rules(&[snapshot.clone()]);
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 53, 1));
    release_source_nat_allocation(&rules, &session_key(12345, "8.8.8.8", 53), first, false, 2);

    let before = source_nat_pool_statuses(&rules);
    assert_eq!(before[0].live_flows, 0);
    assert_eq!(before[0].used_ports, 1);
    assert_eq!(before[0].persistent_leases, 1);
    assert_eq!(before[0].allocations_total, 1);
    assert_eq!(before[0].reuses_total, 0);

    let refreshed = parse_source_nat_rules_with_previous(
        &[snapshot],
        Some(&rules),
        &crate::nat::NatCounterStore::default(),
    );
    let after_refresh = source_nat_pool_statuses(&refreshed);
    assert_eq!(after_refresh[0].live_flows, 0);
    assert_eq!(after_refresh[0].used_ports, 1);
    assert_eq!(after_refresh[0].persistent_leases, 1);
    assert_eq!(after_refresh[0].allocations_total, 1);
    assert_eq!(after_refresh[0].reuses_total, 0);

    let reused = expect_snat_decision(tuple_snat_lookup(&refreshed, 12345, "1.1.1.1", 443, 3));
    assert_eq!(reused.rewrite_src, first.rewrite_src);
    assert_eq!(reused.rewrite_src_port, first.rewrite_src_port);

    let after_reuse = source_nat_pool_statuses(&refreshed);
    assert_eq!(after_reuse[0].live_flows, 1);
    assert_eq!(after_reuse[0].used_ports, 1);
    assert_eq!(after_reuse[0].persistent_leases, 1);
    assert_eq!(after_reuse[0].allocations_total, 1);
    assert_eq!(after_reuse[0].reuses_total, 1);
    assert_persistent_expiry_indexes_consistent(&refreshed[0]);
}

#[test]
fn pool_snat_persistent_helper_restart_resets_lease_state() {
    let snapshot = persistent_pool_snapshot(300, 40000, 40001, vec!["203.0.113.10"], false);
    let rules = parse_source_nat_rules(&[snapshot.clone()]);
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 12345, "8.8.8.8", 53, 1));
    release_source_nat_allocation(&rules, &session_key(12345, "8.8.8.8", 53), first, false, 2);

    let before = source_nat_pool_statuses(&rules);
    assert_eq!(before[0].live_flows, 0);
    assert_eq!(before[0].used_ports, 1);
    assert_eq!(before[0].persistent_leases, 1);
    assert_eq!(before[0].allocations_total, 1);

    // A helper restart has no previous in-process allocator to reuse. The
    // lease table and allocator counters reset even when the snapshot is
    // byte-identical.
    let restarted = parse_source_nat_rules(&[snapshot]);
    let reset = source_nat_pool_statuses(&restarted);
    assert_eq!(reset[0].live_flows, 0);
    assert_eq!(reset[0].used_ports, 0);
    assert_eq!(reset[0].persistent_leases, 0);
    assert_eq!(reset[0].allocations_total, 0);
    assert_eq!(reset[0].reuses_total, 0);
    assert_eq!(reset[0].exhaustion_total, 0);

    let fresh = expect_snat_decision(tuple_snat_lookup(&restarted, 12345, "1.1.1.1", 443, 3));
    assert_eq!(fresh.rewrite_src, Some("203.0.113.10".parse().unwrap()));
    assert!(fresh.rewrite_src_port.is_some());

    let after_fresh = source_nat_pool_statuses(&restarted);
    assert_eq!(after_fresh[0].live_flows, 1);
    assert_eq!(after_fresh[0].used_ports, 1);
    assert_eq!(after_fresh[0].persistent_leases, 1);
    assert_eq!(after_fresh[0].allocations_total, 1);
    assert_eq!(after_fresh[0].reuses_total, 0);
    assert_persistent_expiry_indexes_consistent(&restarted[0]);
}

#[test]
fn pool_snat_allocator_exhausted_counter_increments() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "tiny-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "tiny-pool".to_string(),
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: 40000,
        port_high: 40000,
        ..SourceNATRuleSnapshot::default()
    }]);

    let first = tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1);
    assert!(matches!(first, SourceNatLookup::Matched(_)));
    let second = tuple_snat_lookup(&rules, 10001, "1.1.1.1", 53, 2);
    assert_eq!(
        second,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "tiny-snat".to_string(),
            pool_name: "tiny-pool".to_string(),
            reason: SourceNatFailureReason::AllocatorExhausted,
        })
    );

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].used_ports, 1);
    assert_eq!(status[0].live_flows, 1);
    assert_eq!(status[0].exhaustion_total, 1);
}

#[test]
fn pool_snat_shared_pool_exhaustion_crosses_rules() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "rule-a".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.1.0/24".to_string()],
            pool_name: "shared-pool".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: 40000,
            port_high: 40000,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "rule-b".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.2.0/24".to_string()],
            pool_name: "shared-pool".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: 40000,
            port_high: 40000,
            ..SourceNATRuleSnapshot::default()
        },
    ]);

    let first = match_source_nat_result_for_tuple(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        6,
        10000,
        53,
        None,
        None,
        1,
        false,
        &mut None,
    );
    assert!(matches!(first, SourceNatLookup::Matched(_)));

    let second = match_source_nat_result_for_tuple(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.2.100".parse().unwrap(),
        "1.1.1.1".parse().unwrap(),
        6,
        10001,
        53,
        None,
        None,
        2,
        false,
        &mut None,
    );
    assert_eq!(
        second,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "rule-b".to_string(),
            pool_name: "shared-pool".to_string(),
            reason: SourceNatFailureReason::AllocatorExhausted,
        })
    );

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].used_ports, 1);
    assert_eq!(status[1].used_ports, 1);
    assert_eq!(status[0].exhaustion_total, 1);
    assert_eq!(status[1].exhaustion_total, 1);
}

#[test]
fn pool_snat_shared_pool_exhaustion_crosses_persistence_modes() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "persistent-rule".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.1.0/24".to_string()],
            pool_name: "shared-pool".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: 40000,
            port_high: 40000,
            persistent_nat: true,
            persistent_nat_permit_any_remote_host: true,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "plain-rule".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.2.0/24".to_string()],
            pool_name: "shared-pool".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: 40000,
            port_high: 40000,
            ..SourceNATRuleSnapshot::default()
        },
    ]);

    let first = match_source_nat_result_for_tuple(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        6,
        10000,
        53,
        None,
        None,
        1,
        false,
        &mut None,
    );
    assert!(matches!(first, SourceNatLookup::Matched(_)));

    let second = match_source_nat_result_for_tuple(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.2.100".parse().unwrap(),
        "1.1.1.1".parse().unwrap(),
        6,
        10001,
        53,
        None,
        None,
        2,
        false,
        &mut None,
    );
    assert_eq!(
        second,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "plain-rule".to_string(),
            pool_name: "shared-pool".to_string(),
            reason: SourceNatFailureReason::AllocatorExhausted,
        })
    );
}

#[test]
fn pool_snat_release_after_failed_session_install_frees_tuple() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "tiny-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "tiny-pool".to_string(),
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: 40000,
        port_high: 40000,
        ..SourceNATRuleSnapshot::default()
    }]);

    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));
    release_source_nat_allocation(&rules, &session_key(10000, "8.8.8.8", 53), first, false, 2);

    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10001, "1.1.1.1", 53, 3));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);
}

#[test]
fn pool_snat_persistent_rollback_removes_fresh_lease() {
    let rules = persistent_pool_rules(300, 40000, 40000);
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));

    rollback_source_nat_allocation(&rules, &session_key(10000, "8.8.8.8", 53), first, false, 2);

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].live_flows, 0);
    assert_eq!(status[0].used_ports, 0);
    assert_eq!(status[0].persistent_leases, 0);
    assert_persistent_expiry_indexes_consistent(&rules[0]);

    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10001, "1.1.1.1", 53, 3));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);
}

#[test]
fn pool_snat_persistent_rollback_keeps_lease_reused_by_another_flow() {
    let rules = persistent_pool_rules(300, 40000, 40001);
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "1.1.1.1", 53, 2));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);

    rollback_source_nat_allocation(&rules, &session_key(10000, "8.8.8.8", 53), first, false, 3);

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].live_flows, 1);
    assert_eq!(status[0].used_ports, 1);
    assert_eq!(status[0].persistent_leases, 1);
    {
        let live = rules[0].pool_allocator.debug_live();
        let lease = live.persistent_by_source.values().next().unwrap();
        assert_eq!(lease.active_flows, 1);
        assert!(live.lease_expirations.is_empty());
        assert!(live.lease_expirations_by_addr[0].is_empty());
    }

    let third = expect_snat_decision(tuple_snat_lookup(&rules, 10001, "9.9.9.9", 53, 4));
    assert_ne!(third.rewrite_src_port, first.rewrite_src_port);
}

#[test]
fn pool_snat_persistent_rollback_preserves_lease_after_reuser_release() {
    let rules = persistent_pool_rules(300, 40000, 40001);
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "1.1.1.1", 53, 2));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);

    release_source_nat_allocation(&rules, &session_key(10000, "1.1.1.1", 53), second, false, 3);
    rollback_source_nat_allocation(&rules, &session_key(10000, "8.8.8.8", 53), first, false, 4);

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].live_flows, 0);
    assert_eq!(status[0].used_ports, 1);
    assert_eq!(status[0].persistent_leases, 1);
    {
        let live = rules[0].pool_allocator.debug_live();
        let lease = live.persistent_by_source.values().next().unwrap();
        assert_eq!(lease.active_flows, 0);
        assert_eq!(lease.completed_flows, 1);
        assert_eq!(live.lease_expirations.len(), 1);
        assert_eq!(live.lease_expirations_by_addr[0].len(), 1);
    }

    let third = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "9.9.9.9", 53, 5));
    assert_eq!(third.rewrite_src, first.rewrite_src);
    assert_eq!(third.rewrite_src_port, first.rewrite_src_port);
}

#[test]
fn pool_snat_persistent_double_rollback_removes_unused_lease() {
    let rules = persistent_pool_rules(300, 40000, 40001);
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "1.1.1.1", 53, 2));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);

    rollback_source_nat_allocation(&rules, &session_key(10000, "8.8.8.8", 53), first, false, 3);
    rollback_source_nat_allocation(&rules, &session_key(10000, "1.1.1.1", 53), second, false, 4);

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].live_flows, 0);
    assert_eq!(status[0].used_ports, 0);
    assert_eq!(status[0].persistent_leases, 0);
    {
        let live = rules[0].pool_allocator.debug_live();
        assert!(live.persistent_by_source.is_empty());
        assert!(live.lease_expirations.is_empty());
        assert!(live.lease_expirations_by_addr[0].is_empty());
        assert_eq!(
            live.recycled_ports_by_addr[0].iter().copied().collect::<Vec<_>>(),
            vec![40000]
        );
    }
}

#[test]
fn pool_snat_persistent_reactivation_uses_fresh_expiry_after_success() {
    let rules = persistent_pool_rules(300, 40000, 40001);
    let timeout_ns = 300 * NS_PER_SEC;
    let original = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));
    release_source_nat_allocation(
        &rules,
        &session_key(10000, "8.8.8.8", 53),
        original,
        false,
        2,
    );

    let old_expiry = 2 + timeout_ns;
    {
        let live = rules[0].pool_allocator.debug_live();
        let lease = live.persistent_by_source.values().next().unwrap();
        assert_eq!(lease.expires_at_ns, old_expiry);
        assert!(
            live.lease_expirations
                .contains(&(old_expiry, lease_key(10000)))
        );
    }

    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "1.1.1.1", 53, 3));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "9.9.9.9", 53, 4));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);

    release_source_nat_allocation(&rules, &session_key(10000, "9.9.9.9", 53), second, false, 5);
    rollback_source_nat_allocation(&rules, &session_key(10000, "1.1.1.1", 53), first, false, 6);

    let fresh_expiry = 6 + timeout_ns;
    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].live_flows, 0);
    assert_eq!(status[0].used_ports, 1);
    assert_eq!(status[0].persistent_leases, 1);
    {
        let live = rules[0].pool_allocator.debug_live();
        let lease = live.persistent_by_source.values().next().unwrap();
        assert_eq!(lease.active_flows, 0);
        assert_eq!(lease.completed_flows, 2);
        assert_eq!(lease.expires_at_ns, fresh_expiry);
        assert_eq!(live.lease_expirations.len(), 1);
        assert!(
            live.lease_expirations
                .contains(&(fresh_expiry, lease_key(10000)))
        );
        assert!(
            !live
                .lease_expirations
                .contains(&(old_expiry, lease_key(10000)))
        );
    }
}

#[test]
fn pool_snat_persistent_reactivation_completion_survives_saturated_counter() {
    let rules = persistent_pool_rules(300, 40000, 40001);
    let timeout_ns = 300 * NS_PER_SEC;
    let original = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));
    release_source_nat_allocation(
        &rules,
        &session_key(10000, "8.8.8.8", 53),
        original,
        false,
        2,
    );

    let old_expiry = 2 + timeout_ns;
    {
        let mut live = rules[0].pool_allocator.debug_live();
        let lease = live.persistent_by_source.values_mut().next().unwrap();
        lease.completed_flows = u64::MAX;
        assert_eq!(lease.expires_at_ns, old_expiry);
    }

    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "1.1.1.1", 53, 3));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "9.9.9.9", 53, 4));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);

    release_source_nat_allocation(&rules, &session_key(10000, "9.9.9.9", 53), second, false, 5);
    rollback_source_nat_allocation(&rules, &session_key(10000, "1.1.1.1", 53), first, false, 6);

    let fresh_expiry = 6 + timeout_ns;
    {
        let live = rules[0].pool_allocator.debug_live();
        let lease = live.persistent_by_source.values().next().unwrap();
        assert_eq!(lease.active_flows, 0);
        assert_eq!(lease.completed_flows, u64::MAX);
        assert_eq!(lease.expires_at_ns, fresh_expiry);
        assert!(
            live.lease_expirations
                .contains(&(fresh_expiry, lease_key(10000)))
        );
        assert!(
            !live
                .lease_expirations
                .contains(&(old_expiry, lease_key(10000)))
        );
    }
}

#[test]
fn pool_snat_persistent_reactivation_double_rollback_restores_old_expiry() {
    let rules = persistent_pool_rules(300, 40000, 40001);
    let timeout_ns = 300 * NS_PER_SEC;
    let original = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1));
    release_source_nat_allocation(
        &rules,
        &session_key(10000, "8.8.8.8", 53),
        original,
        false,
        2,
    );

    let old_expiry = 2 + timeout_ns;
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "1.1.1.1", 53, 3));
    let second = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "9.9.9.9", 53, 4));
    assert_eq!(second.rewrite_src, first.rewrite_src);
    assert_eq!(second.rewrite_src_port, first.rewrite_src_port);

    rollback_source_nat_allocation(&rules, &session_key(10000, "1.1.1.1", 53), first, false, 5);
    rollback_source_nat_allocation(&rules, &session_key(10000, "9.9.9.9", 53), second, false, 6);

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].live_flows, 0);
    assert_eq!(status[0].used_ports, 1);
    assert_eq!(status[0].persistent_leases, 1);
    {
        let live = rules[0].pool_allocator.debug_live();
        let lease = live.persistent_by_source.values().next().unwrap();
        assert_eq!(lease.active_flows, 0);
        assert_eq!(lease.completed_flows, 1);
        assert_eq!(lease.expires_at_ns, old_expiry);
        assert_eq!(live.lease_expirations.len(), 1);
        assert!(
            live.lease_expirations
                .contains(&(old_expiry, lease_key(10000)))
        );
    }
}

#[test]
fn pool_snat_release_uses_rewritten_dnat_destination_key() {
    let rules = persistent_pool_rules(300, 40000, 40000);
    let translated_dst: IpAddr = "10.0.0.5".parse().unwrap();
    let first = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "10.0.0.5", 443, 1));
    let mut nat = first;
    nat.rewrite_dst = Some(translated_dst);

    release_source_nat_allocation(
        &rules,
        &session_key(10000, "198.51.100.5", 443),
        nat,
        false,
        2,
    );

    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].live_flows, 0);
    assert_eq!(status[0].used_ports, 1);
    assert_eq!(status[0].persistent_leases, 1);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
fn pool_snat_persistent_expiry_index_is_bounded_by_leases() {
    let rules = persistent_pool_rules(300, 40000, 40000);
    for i in 0..10 {
        let now_ns = 1_000_000_000 + i * 10_000_000;
        let decision =
            expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, now_ns));
        release_source_nat_allocation(
            &rules,
            &session_key(10000, "8.8.8.8", 53),
            decision,
            false,
            now_ns + 1,
        );
    }

    let live = rules[0].pool_allocator.debug_live();
    assert_eq!(live.persistent_by_source.len(), 1);
    assert_eq!(live.lease_expirations.len(), 1);
    assert_eq!(live.lease_expirations_by_addr[0].len(), 1);
    drop(live);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
#[should_panic(expected = "global persistent expiry index mismatch")]
fn pool_snat_expiry_invariant_rejects_stale_global_entry() {
    let rules = persistent_pool_rules(300, 40000, 40000);
    let decision = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1_000));
    release_source_nat_allocation(
        &rules,
        &session_key(10000, "8.8.8.8", 53),
        decision,
        false,
        2_000,
    );
    {
        let mut live = rules[0].pool_allocator.debug_live();
        let (key, lease) = live
            .persistent_by_source
            .iter()
            .next()
            .map(|(key, lease)| (*key, *lease))
            .unwrap();
        live.lease_expirations
            .insert((lease.expires_at_ns + 1, key));
    }

    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
#[should_panic(expected = "per-address persistent expiry index mismatch")]
fn pool_snat_expiry_invariant_rejects_stale_per_address_entry() {
    let rules = persistent_pool_rules(300, 40000, 40000);
    let decision = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1_000));
    release_source_nat_allocation(
        &rules,
        &session_key(10000, "8.8.8.8", 53),
        decision,
        false,
        2_000,
    );
    {
        let mut live = rules[0].pool_allocator.debug_live();
        let (key, lease) = live
            .persistent_by_source
            .iter()
            .next()
            .map(|(key, lease)| (*key, *lease))
            .unwrap();
        live.lease_expirations_by_addr[lease.addr_index].insert((lease.expires_at_ns + 1, key));
    }

    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
#[should_panic(expected = "persistent lease addr index mismatch")]
fn pool_snat_expiry_invariant_rejects_wrong_addr_index() {
    let rules = persistent_pool_rules_with_options(
        300,
        40000,
        40000,
        vec!["203.0.113.10", "203.0.113.11"],
        false,
    );
    let decision = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1_000));
    release_source_nat_allocation(
        &rules,
        &session_key(10000, "8.8.8.8", 53),
        decision,
        false,
        2_000,
    );
    {
        let mut live = rules[0].pool_allocator.debug_live();
        let (key, lease) = live
            .persistent_by_source
            .iter()
            .next()
            .map(|(key, lease)| (*key, *lease))
            .unwrap();
        let wrong_addr_index = if lease.addr_index == 0 { 1 } else { 0 };
        let entry = (lease.expires_at_ns, key);
        live.lease_expirations_by_addr[lease.addr_index].remove(&entry);
        live.lease_expirations_by_addr[wrong_addr_index].insert(entry);
        live.persistent_by_source.insert(
            key,
            PersistentLease {
                addr_index: wrong_addr_index,
                ..lease
            },
        );
    }

    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
fn pool_snat_persistent_release_replaces_stale_expiry_tuple() {
    let rules = persistent_pool_rules(300, 40000, 40000);
    let decision = expect_snat_decision(tuple_snat_lookup(&rules, 10000, "8.8.8.8", 53, 1_000));
    let stale_expires_at_ns = {
        let mut live = rules[0].pool_allocator.debug_live();
        let (key, lease) = live
            .persistent_by_source
            .iter()
            .next()
            .map(|(key, lease)| (*key, *lease))
            .unwrap();
        assert_eq!(lease.active_flows, 1);
        live.lease_expirations.insert((lease.expires_at_ns, key));
        live.lease_expirations_by_addr[lease.addr_index].insert((lease.expires_at_ns, key));
        lease.expires_at_ns
    };

    release_source_nat_allocation(
        &rules,
        &session_key(10000, "8.8.8.8", 53),
        decision,
        false,
        2_000,
    );

    let live = rules[0].pool_allocator.debug_live();
    let (key, lease) = live
        .persistent_by_source
        .iter()
        .next()
        .map(|(key, lease)| (*key, *lease))
        .unwrap();
    assert_ne!(lease.expires_at_ns, stale_expires_at_ns);
    assert_eq!(live.lease_expirations.len(), 1);
    assert!(live.lease_expirations.contains(&(lease.expires_at_ns, key)));
    assert!(!live.lease_expirations.contains(&(stale_expires_at_ns, key)));
    assert_eq!(live.lease_expirations_by_addr[lease.addr_index].len(), 1);
    assert!(live.lease_expirations_by_addr[lease.addr_index].contains(&(lease.expires_at_ns, key)));
    assert!(
        !live.lease_expirations_by_addr[lease.addr_index].contains(&(stale_expires_at_ns, key))
    );
}

#[test]
fn pool_snat_allocation_gc_is_bounded_when_not_under_pressure() {
    let rules = persistent_pool_rules(1, 40000, 40099);
    let expired_lease_count = ALLOCATION_GC_BUDGET + 12;
    for i in 0..expired_lease_count {
        let src_port = 10000 + i as u16;
        let now_ns = 1_000_000_000 + i as u64;
        let decision =
            expect_snat_decision(tuple_snat_lookup(&rules, src_port, "8.8.8.8", 53, now_ns));
        release_source_nat_allocation(
            &rules,
            &session_key(src_port, "8.8.8.8", 53),
            decision,
            false,
            now_ns + 1,
        );
    }

    let before = source_nat_pool_statuses(&rules);
    assert_eq!(before[0].persistent_leases, expired_lease_count as u64);

    let decision = expect_snat_decision(tuple_snat_lookup(
        &rules,
        20000,
        "1.1.1.1",
        53,
        5_000_000_000,
    ));
    assert_eq!(
        decision.rewrite_src_port,
        Some(40000 + expired_lease_count as u16)
    );

    let after = source_nat_pool_statuses(&rules);
    assert_eq!(
        after[0].persistent_leases,
        (expired_lease_count - ALLOCATION_GC_BUDGET + 1) as u64
    );
    let live = rules[0].pool_allocator.debug_live();
    assert_eq!(
        live.lease_expirations.len(),
        expired_lease_count - ALLOCATION_GC_BUDGET
    );
    assert_eq!(
        live.lease_expirations_by_addr[0].len(),
        expired_lease_count - ALLOCATION_GC_BUDGET
    );
    drop(live);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

#[test]
fn pool_snat_pressure_gc_reclaims_expired_lease_for_selected_address() {
    let rules = persistent_pool_rules_with_options(
        1,
        40000,
        40007,
        vec!["203.0.113.10", "203.0.113.11"],
        true,
    );
    let src_addr_0 = source_for_sticky_pool_index(0, 2);
    let src_addr_1 = source_for_sticky_pool_index(1, 2);

    for i in 0..ALLOCATION_GC_BUDGET {
        let src_port = 10000 + i as u16;
        let now_ns = 1_000_000_000 + i as u64;
        let decision = expect_snat_decision(tuple_snat_lookup_from_src(
            &rules,
            &src_addr_0,
            src_port,
            "8.8.8.8",
            53,
            now_ns,
        ));
        release_source_nat_allocation(
            &rules,
            &session_key_from_src(&src_addr_0, src_port, "8.8.8.8", 53),
            decision,
            false,
            now_ns + 1,
        );
    }
    for i in 0..ALLOCATION_GC_BUDGET {
        let src_port = 11000 + i as u16;
        let now_ns = 1_100_000_000 + i as u64;
        let decision = expect_snat_decision(tuple_snat_lookup_from_src(
            &rules,
            &src_addr_1,
            src_port,
            "8.8.4.4",
            53,
            now_ns,
        ));
        release_source_nat_allocation(
            &rules,
            &session_key_from_src(&src_addr_1, src_port, "8.8.4.4", 53),
            decision,
            false,
            now_ns + 1,
        );
    }

    {
        let live = rules[0].pool_allocator.debug_live();
        assert_eq!(
            live.lease_expirations_by_addr[0].len(),
            ALLOCATION_GC_BUDGET
        );
        assert_eq!(
            live.lease_expirations_by_addr[1].len(),
            ALLOCATION_GC_BUDGET
        );
    }
    assert_persistent_expiry_indexes_consistent(&rules[0]);

    let decision = expect_snat_decision(tuple_snat_lookup_from_src(
        &rules,
        &src_addr_1,
        12000,
        "1.1.1.1",
        53,
        5_000_000_000,
    ));

    assert_eq!(decision.rewrite_src, Some("203.0.113.11".parse().unwrap()));
    assert!(matches!(decision.rewrite_src_port, Some(40000..=40007)));
    let live = rules[0].pool_allocator.debug_live();
    assert_eq!(live.lease_expirations_by_addr[0].len(), 0);
    assert!(live.lease_expirations_by_addr[1].len() < ALLOCATION_GC_BUDGET);
    drop(live);
    assert_persistent_expiry_indexes_consistent(&rules[0]);
}

fn source_for_sticky_pool_index(want: usize, pool_len: usize) -> String {
    for octet in 1..=254 {
        let candidate = format!("10.0.1.{octet}");
        let ip = candidate.parse().unwrap();
        if sticky_pool_index(ip, pool_len) == want {
            return candidate;
        }
    }
    panic!("no source address found for sticky index {want}");
}

#[test]
fn pool_snat_wrong_family_pool_fails_closed_before_later_rule() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "wrong-family".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "v6-only".to_string(),
            pool_addresses: vec!["2001:db8::10".to_string()],
            port_low: 1024,
            port_high: 65535,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "usable-v4".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "v4-pool".to_string(),
            pool_addresses: vec!["203.0.113.20".to_string()],
            port_low: 40000,
            port_high: 40000,
            ..SourceNATRuleSnapshot::default()
        },
    ]);

    let lookup = match_source_nat_result(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "wrong-family".to_string(),
            pool_name: "v6-only".to_string(),
            reason: SourceNatFailureReason::WrongAddressFamily,
        })
    );
}

#[test]
fn pool_snat_wrong_family_pool_fails_closed_when_no_later_rule_matches() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "wrong-family".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "v6-only".to_string(),
        pool_addresses: vec!["2001:db8::10".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);

    let lookup = match_source_nat_result(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "wrong-family".to_string(),
            pool_name: "v6-only".to_string(),
            reason: SourceNatFailureReason::WrongAddressFamily,
        })
    );
}

#[test]
fn pool_snat_missing_pool_snapshot_fails_closed() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "missing".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "missing-pool".to_string(),
        pool_unusable: true,
        pool_unusable_reason: "missing_pool".to_string(),
        ..SourceNATRuleSnapshot::default()
    }]);

    let lookup = match_source_nat_result(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "missing".to_string(),
            pool_name: "missing-pool".to_string(),
            reason: SourceNatFailureReason::MissingPool,
        })
    );
}

#[test]
fn pool_snat_empty_pool_fails_closed_instead_of_no_match() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "empty".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "empty-pool".to_string(),
        ..SourceNATRuleSnapshot::default()
    }]);

    let lookup = match_source_nat_result(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "empty".to_string(),
            pool_name: "empty-pool".to_string(),
            reason: SourceNatFailureReason::EmptyPool,
        })
    );
}

#[test]
fn pool_snat_invalid_port_range_fails_closed() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "bad-ports".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "bad-port-pool".to_string(),
        pool_addresses: vec!["203.0.113.1".to_string()],
        port_low: 40000,
        port_high: 39999,
        ..SourceNATRuleSnapshot::default()
    }]);

    let lookup = match_source_nat_result(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "bad-ports".to_string(),
            pool_name: "bad-port-pool".to_string(),
            reason: SourceNatFailureReason::InvalidPortRange,
        })
    );
}

#[test]
fn pool_snat_invalid_pool_address_fails_closed() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "bad-address".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "bad-address-pool".to_string(),
        pool_addresses: vec!["not-an-ip".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);

    let lookup = match_source_nat_result(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "bad-address".to_string(),
            pool_name: "bad-address-pool".to_string(),
            reason: SourceNatFailureReason::InvalidPool,
        })
    );
}

#[test]
fn pool_snat_partially_invalid_pool_address_fails_closed() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "mixed-addresses".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "mixed-address-pool".to_string(),
        pool_addresses: vec!["203.0.113.1".to_string(), "not-an-ip".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);

    let lookup = match_source_nat_result(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "mixed-addresses".to_string(),
            pool_name: "mixed-address-pool".to_string(),
            reason: SourceNatFailureReason::InvalidPool,
        })
    );
}

#[test]
fn pool_snat_address_persistent_sticks_source_to_pool_address() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-sticky".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "sticky-pool".to_string(),
        pool_addresses: vec![
            "203.0.113.1".to_string(),
            "203.0.113.2".to_string(),
            "203.0.113.3".to_string(),
        ],
        port_low: 40000,
        port_high: 40010,
        address_persistent: true,
        ..SourceNATRuleSnapshot::default()
    }]);

    let src = "10.0.1.101".parse().unwrap();
    let expected_idx = sticky_pool_index(src, 3);
    assert_eq!(expected_idx, 1);

    for want_port in 40000..40004 {
        let d = match_source_nat(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src,
            "8.8.8.8".parse().unwrap(),
            None,
            None,
        )
        .expect("should match");
        assert_eq!(d.rewrite_src, Some("203.0.113.2".parse().unwrap()));
        assert_eq!(d.rewrite_src_port, Some(want_port));
    }
}

#[test]
fn pool_snat_address_persistent_sticks_each_source_independently() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-sticky-many".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "sticky-pool".to_string(),
        pool_addresses: vec![
            "203.0.113.1".to_string(),
            "203.0.113.2".to_string(),
            "203.0.113.3".to_string(),
            "203.0.113.4".to_string(),
            "203.0.113.5".to_string(),
        ],
        port_low: 40000,
        port_high: 40100,
        address_persistent: true,
        ..SourceNATRuleSnapshot::default()
    }]);

    let sources: [IpAddr; 8] = [
        "10.0.1.100".parse().unwrap(),
        "10.0.1.101".parse().unwrap(),
        "10.0.1.102".parse().unwrap(),
        "10.0.1.103".parse().unwrap(),
        "10.0.1.104".parse().unwrap(),
        "10.0.1.105".parse().unwrap(),
        "10.0.1.106".parse().unwrap(),
        "10.0.1.107".parse().unwrap(),
    ];
    let mut pool_addresses_used = std::collections::HashSet::new();

    for src in sources {
        let mut addresses_for_src = std::collections::HashSet::new();
        for dst_host in 1..=20 {
            let dst = IpAddr::V4(Ipv4Addr::new(8, 8, 8, dst_host));
            let d = match_source_nat(&rules, &NatScopeCtx::default(), "lan", "wan", src, dst, None, None)
                .expect("sticky source should match");
            addresses_for_src.insert(d.rewrite_src.expect("pool address"));
        }
        assert_eq!(
            addresses_for_src.len(),
            1,
            "source {src} mapped to multiple pool addresses: {addresses_for_src:?}"
        );
        pool_addresses_used.extend(addresses_for_src);
    }

    assert!(
        pool_addresses_used.len() >= 4,
        "sticky hash collapsed source spread: {pool_addresses_used:?}"
    );
}

#[test]
fn pool_snat_address_persistent_spreads_distinct_sources_across_pool() {
    let pool_len = 64usize;
    let mut seen = vec![false; pool_len];

    for host in 0..1000u32 {
        let src = IpAddr::V4(Ipv4Addr::new(
            10,
            ((host >> 16) & 0xff) as u8,
            ((host >> 8) & 0xff) as u8,
            (host & 0xff) as u8,
        ));
        seen[sticky_pool_index(src, pool_len)] = true;
    }

    let used = seen.iter().filter(|used| **used).count();
    assert!(
        used >= pool_len * 80 / 100,
        "sticky hash used {used}/{pool_len} pool slots"
    );
}

#[test]
fn pool_snat_address_persistent_userspace_v2_contract_fixtures() {
    // Golden vectors pinning the FxHash-seeded mapping (#2349). These guard
    // against an accidental change to the sticky-index hash; a deliberate hash
    // change must re-pin them and bump the seed version.
    assert_eq!(sticky_pool_index("10.0.1.100".parse().unwrap(), 4), 3);
    assert_eq!(sticky_pool_index("10.0.1.101".parse().unwrap(), 4), 2);
    assert_eq!(sticky_pool_index("192.0.2.1".parse().unwrap(), 5), 3);
    assert_eq!(sticky_pool_index("198.51.100.25".parse().unwrap(), 5), 2);
    assert_eq!(sticky_pool_index("2001:db8::1".parse().unwrap(), 257), 109);
    assert_eq!(sticky_pool_index("2001:db8::2".parse().unwrap(), 257), 240);
}

#[test]
fn pool_snat_address_persistent_userspace_v2_selects_pool_addresses() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "userspace-v1-selection".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
        pool_name: "userspace-v1-pool".to_string(),
        pool_addresses: vec![
            "203.0.113.10".to_string(),
            "203.0.113.11".to_string(),
            "203.0.113.12".to_string(),
            "203.0.113.13".to_string(),
            "2001:db8:ffff::10".to_string(),
            "2001:db8:ffff::11".to_string(),
            "2001:db8:ffff::12".to_string(),
            "2001:db8:ffff::13".to_string(),
        ],
        port_low: 40000,
        port_high: 40010,
        address_persistent: true,
        ..SourceNATRuleSnapshot::default()
    }]);

    let cases = [
        ("10.0.1.100", "8.8.8.8", 50000, "203.0.113.13"),
        ("10.0.1.101", "8.8.4.4", 50001, "203.0.113.12"),
        (
            "2001:db8::1",
            "2001:4860:4860::8888",
            50002,
            "2001:db8:ffff::11",
        ),
        (
            "fd00::3",
            "2001:4860:4860::8844",
            50003,
            "2001:db8:ffff::13",
        ),
    ];

    for (src, dst, src_port, want_src) in cases {
        let decision = expect_snat_decision(match_source_nat_result_for_tuple(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src.parse().unwrap(),
            dst.parse().unwrap(),
            6,
            src_port,
            443,
            None,
            None,
            0,
            false,
            &mut None,
        ));

        assert_eq!(decision.rewrite_src, Some(want_src.parse().unwrap()));
        assert_eq!(decision.rewrite_src_port, Some(40000));
    }
}

#[test]
fn pool_snat_address_persistent_differs_from_legacy_backend_algorithms() {
    let v4: Ipv4Addr = "10.0.1.100".parse().unwrap();
    assert_eq!(sticky_pool_index(IpAddr::V4(v4), 4), 3);
    assert_eq!(legacy_backend_v4_index(v4, 4), 2);

    let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert_eq!(sticky_pool_index(IpAddr::V6(v6), 257), 109);
    assert_eq!(legacy_backend_v6_index(v6, 257), 116);
}

fn legacy_backend_v4_index(src_ip: Ipv4Addr, pool_len: usize) -> usize {
    if pool_len <= 1 {
        return 0;
    }
    (u32::from_le_bytes(src_ip.octets()) as usize) % pool_len
}

fn legacy_backend_v6_index(src_ip: Ipv6Addr, pool_len: usize) -> usize {
    if pool_len <= 1 {
        return 0;
    }
    let mut hash = 0u32;
    for chunk in src_ip.octets().chunks_exact(4) {
        let mut word = [0u8; 4];
        word.copy_from_slice(chunk);
        hash ^= u32::from_le_bytes(word);
    }
    (hash as usize) % pool_len
}

#[test]
fn pool_snat_address_persistent_hashes_full_ipv6_address() {
    let a: IpAddr = "2001:db8::1".parse().unwrap();
    let b: IpAddr = "2001:db8::2".parse().unwrap();

    assert_eq!(sticky_pool_index(a, 257), 109);
    assert_eq!(sticky_pool_index(b, 257), 240);
}

#[test]
fn pool_snat_address_persistent_sticky_index_is_deterministic_and_stable() {
    // Determinism + persistence contract (#2349): the same source IP must map
    // to the same pool slot on every call, regardless of how many other
    // sources have been hashed in between (the FxHasher is constructed fresh
    // per call, so there is no shared mutable state — but assert it anyway so
    // a future change that introduces state fails here).
    let sources: &[&str] = &[
        "10.0.1.100",
        "10.0.1.101",
        "192.0.2.1",
        "198.51.100.25",
        "2001:db8::1",
        "2001:db8::2",
        "fd00::1234",
    ];
    let pool_lens = [2usize, 3, 4, 5, 64, 257];

    for pool_len in pool_lens {
        for src in sources {
            let ip: IpAddr = src.parse().unwrap();
            let first = sticky_pool_index(ip, pool_len);

            // Repeated calls return the same slot.
            for _ in 0..16 {
                assert_eq!(
                    sticky_pool_index(ip, pool_len),
                    first,
                    "sticky index for {src} (pool_len={pool_len}) changed across calls"
                );
            }

            // Interleaving other sources does not perturb this one's slot —
            // proves the SELECTOR (sticky_pool_index) is a pure deterministic
            // function with no shared/mutable hasher state, so the same source
            // always hashes to the same slot. This is distinct from the
            // separate lease cache (persistent_by_source), which memoizes the
            // chosen address; the hash itself caches nothing.
            for other in sources {
                let _ = sticky_pool_index(other.parse().unwrap(), pool_len);
            }
            assert_eq!(
                sticky_pool_index(ip, pool_len),
                first,
                "sticky index for {src} (pool_len={pool_len}) drifted after hashing other sources"
            );

            // Result is always a valid slot.
            assert!(
                first < pool_len,
                "sticky index {first} out of range for pool_len={pool_len}"
            );
        }
    }
}

#[test]
fn pool_snat_port_range_wrapping() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "small-range".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "small".to_string(),
        pool_addresses: vec!["203.0.113.1".to_string()],
        port_low: 10000,
        port_high: 10002,
        ..SourceNATRuleSnapshot::default()
    }]);
    let mut ports = Vec::new();
    for _ in 0..6 {
        let d = match_source_nat(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            "10.0.1.100".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            None,
            None,
        )
        .expect("should match");
        ports.push(d.rewrite_src_port.unwrap());
    }
    // With range [10000, 10002] (3 ports), allocations should wrap.
    assert_eq!(ports[0], 10000);
    assert_eq!(ports[1], 10001);
    assert_eq!(ports[2], 10002);
    assert_eq!(ports[3], 10000);
    assert_eq!(ports[4], 10001);
    assert_eq!(ports[5], 10002);
}

#[test]
fn pool_snat_combined_with_dnat() {
    // Pre-routing DNAT decision
    let dnat = NatDecision {
        rewrite_dst: Some("192.168.1.10".parse().unwrap()),
        rewrite_dst_port: Some(8080),
        ..NatDecision::default()
    };
    // Post-policy pool SNAT decision
    let snat = NatDecision {
        rewrite_src: Some("203.0.113.1".parse().unwrap()),
        rewrite_src_port: Some(40000),
        ..NatDecision::default()
    };
    let merged = dnat.merge(snat);
    assert_eq!(merged.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
    assert_eq!(merged.rewrite_dst_port, Some(8080));
    assert_eq!(merged.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert_eq!(merged.rewrite_src_port, Some(40000));
}

#[test]
fn pool_snat_reverse_session_key() {
    let decision = NatDecision {
        rewrite_src: Some("203.0.113.1".parse().unwrap()),
        rewrite_src_port: Some(40000),
        ..NatDecision::default()
    };
    let reversed = decision.reverse(
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        12345,
        443,
    );
    assert_eq!(reversed.rewrite_src, None);
    assert_eq!(reversed.rewrite_dst, Some("10.0.1.100".parse().unwrap()));
    assert_eq!(reversed.rewrite_src_port, None);
    assert_eq!(reversed.rewrite_dst_port, Some(12345));
}

#[test]
fn pool_snat_v6_single_address() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-v6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["::/0".to_string()],
        pool_name: "v6-pool".to_string(),
        pool_addresses: vec!["2001:db8::1".to_string()],
        port_low: 2000,
        port_high: 3000,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "fd00::100".parse().expect("src"),
        "2001:db8:1::1".parse().expect("dst"),
        None,
        None,
    );
    let d = decision.expect("should match pool v6 rule");
    assert_eq!(d.rewrite_src, Some("2001:db8::1".parse().unwrap()));
    assert!(d.rewrite_src_port.is_some());
    let port = d.rewrite_src_port.unwrap();
    assert!(port >= 2000 && port <= 3000, "port {} out of range", port);
}

#[test]
fn pool_snat_default_port_range() {
    // When port_low and port_high are 0, defaults to 1024..65535
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "default-range".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "default".to_string(),
        pool_addresses: vec!["203.0.113.1".to_string()],
        port_low: 0,
        port_high: 0,
        ..SourceNATRuleSnapshot::default()
    }]);
    let d = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    )
    .expect("should match");
    let port = d.rewrite_src_port.unwrap();
    assert!(port >= 1024, "port {} out of default range", port);
}

#[test]
fn pool_snat_zone_mismatch_returns_none() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-zone".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "p".to_string(),
        pool_addresses: vec!["203.0.113.1".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert!(
        match_source_nat(
            &rules,
            &NatScopeCtx::default(),
            "dmz", // wrong from_zone
            "wan",
            "10.0.1.100".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            None,
            None,
        )
        .is_none()
    );
}

#[test]
fn port_allocator_basic() {
    let alloc = PortAllocator::new(2, 5000, 5002);
    // Address selection round-robin
    let src = "10.0.1.100".parse().unwrap();
    assert_eq!(alloc.address_index(src, 0, 2, false), 0);
    assert_eq!(alloc.address_index(src, 0, 2, false), 1);
    assert_eq!(alloc.address_index(src, 0, 2, false), 0);
    // Port allocation for address 0
    assert_eq!(alloc.try_next_port(0), Ok(5000));
    assert_eq!(alloc.try_next_port(0), Ok(5001));
    assert_eq!(alloc.try_next_port(0), Ok(5002));
    assert_eq!(alloc.try_next_port(0), Ok(5000)); // wraps

    let mixed = PortAllocator::new(4, 5000, 5002);
    let src_v4 = "10.0.1.100".parse().unwrap();
    let src_v6 = "2001:db8::100".parse().unwrap();
    assert_eq!(mixed.address_index(src_v4, 0, 2, false), 0);
    assert_eq!(mixed.address_index(src_v6, 2, 2, false), 2);
    assert_eq!(mixed.address_index(src_v4, 0, 2, false), 1);
    assert_eq!(mixed.address_index(src_v6, 2, 2, false), 3);
}

/// #3047 (062-05) fail-on-revert: a single collision on the sequential
/// candidate port must NOT spuriously exhaust the allocator. With the next two
/// sequential ports occupied out-of-band (a persistent lease / HA-synced
/// install sitting inside the range), the allocator must probe forward and
/// hand out the next free port. Before the fix `claim_free_port_locked` tried
/// only one port per call; `allocate_translation`'s two-shot retry then both
/// hit an occupied port and the flow was wrongly refused as exhausted.
#[test]
fn pool_snat_sequential_collision_probes_next_free_port() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    // Range 1024..=1027 (4 ports). Occupy the first two sequential candidates.
    let alloc = PortAllocator::new(1, 1024, 1027);
    alloc.debug_seed_owner(0, IpAddr::V4(pool_ip), 1024);
    alloc.debug_seed_owner(0, IpAddr::V4(pool_ip), 1025);

    let flow = SourceNatFlowKey {
        protocol: 6,
        src_ip: "10.0.61.50".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 40000,
        dst_port: 443,
    };
    let result = alloc.allocate_translation(
        flow,
        PoolAddressFamily::V4(&addrs),
        0,
        false,
        false,
        PersistentNatPermit::TargetHostPort,
        0,
        1_000,
    );
    let translated = result.expect("collision must not exhaust an otherwise-free range");
    assert_eq!(translated.ip, IpAddr::V4(pool_ip));
    assert_eq!(
        translated.port, 1026,
        "must probe past the two occupied ports to the next free one"
    );
}

/// #3047 (062-10) fail-on-revert: a recycled port that collides with an
/// out-of-band owner must be RETAINED on the recycled stack, not discarded.
/// Before the fix the colliding port was popped and dropped, permanently
/// shrinking the reusable pool. Here the sequential cursor is exhausted so the
/// recycled stack is the only source; the top entry collides and the second is
/// free. The allocation must succeed with the free port AND leave the collided
/// port still recyclable.
#[test]
fn pool_snat_recycled_collision_retains_port() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    // Range 1024..=1025 (2 ports).
    let alloc = PortAllocator::new(1, 1024, 1025);
    {
        let mut live = alloc.debug_live();
        // Force the sequential cursor past the range so only the recycled
        // stack is consulted.
        live.next_port_offset_by_addr[0] = 2;
        // FIFO queue: pop_front() yields 1025 (collides) first, then 1024
        // (free). Front-first ordering keeps this exercising the #3047
        // collision-retain path after the #3011 LIFO->FIFO change.
        live.recycled_ports_by_addr[0] = std::collections::VecDeque::from(vec![1025, 1024]);
    }
    // 1025 is occupied out-of-band, so the recycled pop of 1025 collides.
    alloc.debug_seed_owner(0, IpAddr::V4(pool_ip), 1025);

    let flow = SourceNatFlowKey {
        protocol: 6,
        src_ip: "10.0.61.51".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 40001,
        dst_port: 443,
    };
    let result = alloc.allocate_translation(
        flow,
        PoolAddressFamily::V4(&addrs),
        0,
        false,
        false,
        PersistentNatPermit::TargetHostPort,
        0,
        1_000,
    );
    let translated = result.expect("free recycled port must be allocated");
    assert_eq!(translated.port, 1024, "must hand out the free recycled port");

    // The collided recycled port must NOT have been leaked: it is still on the
    // recycled stack, so once its out-of-band owner clears it is reusable.
    {
        let live = alloc.debug_live();
        assert!(
            live.recycled_ports_by_addr[0].contains(&1025),
            "collided recycled port must be retained, not discarded (leak)"
        );
    }

    // Prove reusability: clear the out-of-band owner and allocate again — the
    // retained port 1025 must be handed out instead of a spurious exhaustion.
    alloc.debug_clear_owner(IpAddr::V4(pool_ip), 1025);
    let flow2 = SourceNatFlowKey {
        protocol: 6,
        src_ip: "10.0.61.52".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 40002,
        dst_port: 443,
    };
    let result2 = alloc.allocate_translation(
        flow2,
        PoolAddressFamily::V4(&addrs),
        0,
        false,
        false,
        PersistentNatPermit::TargetHostPort,
        0,
        1_000,
    );
    let translated2 = result2.expect("retained recycled port must be reusable after owner clears");
    assert_eq!(
        translated2.port, 1025,
        "the retained recycled port must be reused, proving no leak"
    );
}

/// #3011 fail-on-revert: freed SNAT ports must be recycled FIFO (oldest-freed
/// reused first), NOT LIFO (most-recently-freed reused first). LIFO immediately
/// hands a just-freed port back, maximizing the chance of colliding with the
/// upstream's lingering TIME_WAIT/2MSL state for the prior 4-tuple. FIFO spreads
/// reuse across the whole 2MSL window. Here we exhaust the sequential range,
/// free three ports in a known order, and require the next three allocations to
/// reuse them in that SAME (FIFO) order. Reverting to a back-popping LIFO queue
/// flips the order and turns this test RED.
#[test]
fn pool_snat_recycle_order_is_fifo_not_lifo() {
    let pool_ip: Ipv4Addr = "203.0.113.7".parse().unwrap();
    let addrs = [pool_ip];
    // 5-port range so we can fully spend the sequential phase and then force
    // all subsequent allocations through the recycle queue.
    let alloc = PortAllocator::new(1, 1024, 1028);

    let mk_flow = |src_port: u16| SourceNatFlowKey {
        protocol: 6,
        src_ip: "10.0.61.70".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port,
        dst_port: 443,
    };
    let allocate = |flow: SourceNatFlowKey| {
        alloc
            .allocate_translation(
                flow,
                PoolAddressFamily::V4(&addrs),
                0,
                false,
                false,
                PersistentNatPermit::TargetHostPort,
                0,
                1_000,
            )
            .expect("sequential allocation must succeed within range")
    };

    // Spend the entire sequential range: ports 1024..=1028 go to flows in
    // allocation order.
    let mut seq = Vec::new();
    for i in 0..5u16 {
        let flow = mk_flow(5000 + i);
        let t = allocate(flow);
        seq.push((flow, t));
    }
    assert_eq!(
        seq.iter().map(|(_, t)| t.port).collect::<Vec<_>>(),
        vec![1024, 1025, 1026, 1027, 1028],
        "sequential phase hands out ports in ascending order"
    );

    // Free three flows in a deliberately non-monotonic order: 1026, then 1024,
    // then 1028. Recycle queue (FIFO) must end up [1026, 1024, 1028].
    let free_order = [2usize, 0usize, 4usize]; // ports 1026, 1024, 1028
    for &idx in &free_order {
        let (flow, t) = seq[idx];
        assert!(
            alloc.release_flow(flow, t, 2_000),
            "release of a live flow must succeed"
        );
    }
    {
        let live = alloc.debug_live();
        assert_eq!(
            live.recycled_ports_by_addr[0]
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![1026, 1024, 1028],
            "freed ports queue in release order (push_back)"
        );
    }

    // The next three allocations must reuse the freed ports FIFO: oldest-freed
    // (1026) first, then 1024, then 1028 — NOT the LIFO reverse (1028,1024,1026).
    let reused: Vec<u16> = (0..3u16)
        .map(|i| allocate(mk_flow(6000 + i)).port)
        .collect();
    assert_eq!(
        reused,
        vec![1026, 1024, 1028],
        "recycled ports must be reused FIFO (oldest freed first), not LIFO"
    );

    // Explicit just-freed-not-immediately-reused check: while other recycled
    // ports remain, the most-recently-freed port (1028) is the LAST handed out.
    assert_eq!(
        reused.last().copied(),
        Some(1028),
        "the most-recently-freed port must be reused LAST while others remain"
    );
}

#[test]
fn pool_snat_non_first_fragment_refused_no_allocation() {
    // #1852: a non-first fragment that would match a pool-mode SNAT rule
    // must be refused (Unavailable::NonFirstFragment) so no pool port is
    // allocated and no port is written into payload. The matching
    // first-fragment case (non_first_fragment=false) still allocates.
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);

    // Non-first fragment: refused without allocating.
    let frag = match_source_nat_result_for_tuple(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        6,
        10000,
        53,
        None,
        None,
        1,
        true,
        &mut None,
    );
    match frag {
        SourceNatLookup::Unavailable(failure) => {
            assert_eq!(failure.exception_reason(), "source_nat_non_first_fragment");
        }
        other => panic!("expected NonFirstFragment refusal, got {other:?}"),
    }

    // First/atomic fragment (non_first_fragment=false): still allocates.
    let first = match_source_nat_result_for_tuple(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        6,
        10000,
        53,
        None,
        None,
        1,
        false,
        &mut None,
    );
    assert!(
        matches!(first, SourceNatLookup::Matched(d) if d.rewrite_src_port.is_some()),
        "first fragment must still allocate a pool mapping"
    );
}

// === #2218: per-rule NAT translation hit counters ===

// FAIL-ON-REVERT: this test fails if NatRuleCounter::add stops counting or
// snapshots() drops a stored id. It exercises the store contract directly
// (get-or-insert, add packets+bytes, snapshot, the counter_id==0 skip, and
// reconcile/clear) independent of the worker path.
#[test]
fn nat_counter_store_counts_and_skips_id_zero() {
    let store = NatCounterStore::default();

    // counter_id 0 is the "no per-rule counter" sentinel — never allocated.
    assert!(
        store.rule_counter(0).is_none(),
        "counter_id 0 must not allocate a counter"
    );

    // get-or-insert returns the SAME Arc for the same id.
    let c1 = store.rule_counter(1).expect("id 1 counter");
    let c1_again = store.rule_counter(1).expect("id 1 counter again");
    assert!(
        std::sync::Arc::ptr_eq(&c1, &c1_again),
        "rule_counter must share one Arc per id"
    );

    // N adds of 100 bytes each -> packets=N, bytes=100*N.
    const N: u64 = 7;
    for _ in 0..N {
        c1.add(100);
    }
    let snaps = store.snapshots();
    assert_eq!(snaps.len(), 1, "exactly one stored counter");
    assert_eq!(snaps[0].counter_id, 1);
    assert_eq!(snaps[0].packets, N, "one packet counted per add");
    assert_eq!(snaps[0].bytes, 100 * N, "bytes accumulate per add");

    // A second id is independent.
    let c2 = store.rule_counter(2).expect("id 2 counter");
    c2.add(40);
    let mut snaps = store.snapshots();
    snaps.sort_by_key(|s| s.counter_id);
    assert_eq!(snaps.len(), 2);
    assert_eq!(
        (snaps[1].counter_id, snaps[1].packets, snaps[1].bytes),
        (2, 1, 40)
    );

    // reconcile_ids drops counters whose id is no longer active.
    store.reconcile_ids(&[1]);
    let snaps = store.snapshots();
    assert_eq!(snaps.len(), 1, "id 2 dropped by reconcile");
    assert_eq!(snaps[0].counter_id, 1);
    assert_eq!(snaps[0].packets, N, "surviving counter keeps its count");

    // clear zeroes the survivors but keeps them registered.
    store.clear();
    let snaps = store.snapshots();
    assert_eq!(snaps.len(), 1, "clear keeps the registration");
    assert_eq!((snaps[0].packets, snaps[0].bytes), (0, 0), "clear zeroes");
}

// === #2255: counter_id stability across config reorder/removal ===

// FAIL-ON-REVERT for #2255 at the store layer. The cumulative numeric-keyed
// store stays correctly attributed ONLY because the compiler now derives a
// STABLE, identity-bound counter_id (a wide u32 hash) for each rule. This test
// proves the store's two safety properties that the stable id relies on:
//
//   1. A retained id keeps its cumulative count across reconcile (a rule that
//      survives a config reorder reads its OWN prior count).
//   2. A removed id is dropped, so a later rule that gets a DIFFERENT stable id
//      can never read the removed rule's leftover count.
//
// With the pre-#2255 sequential id assignment, a reorder reused a small id (1)
// for a different rule, and reconcile_ids([1]) would RETAIN the old slot 1 — so
// the new rule inherited the old rule's count. The wide, identity-derived ids
// here are the values the compiler produces (no two distinct rules share one),
// so reconcile retains the right rule and drops the rest.
#[test]
fn nat_counter_store_stable_ids_survive_reorder_and_removal() {
    let store = NatCounterStore::default();

    // Two rules with stable, identity-derived u32 ids (as the compiler emits).
    const ID_A: u32 = 0x9E37_79B1; // "rule-a"-shaped wide id
    const ID_B: u32 = 0x1234_5678; // "rule-b"-shaped wide id

    let a = store.rule_counter(ID_A).expect("id A");
    let b = store.rule_counter(ID_B).expect("id B");
    for _ in 0..5 {
        a.add(10);
    }
    for _ in 0..3 {
        b.add(10);
    }

    // Reorder: the snapshot now lists the SAME ids (identity-bound), just in a
    // different order. reconcile retains both; each rule reads its OWN count.
    store.reconcile_ids(&[ID_B, ID_A]);
    let snaps = store.snapshots();
    let a_pkts = snaps
        .iter()
        .find(|s| s.counter_id == ID_A)
        .map(|s| s.packets);
    let b_pkts = snaps
        .iter()
        .find(|s| s.counter_id == ID_B)
        .map(|s| s.packets);
    assert_eq!(a_pkts, Some(5), "rule A keeps its count across reorder");
    assert_eq!(b_pkts, Some(3), "rule B keeps its count across reorder");

    // Removal: rule A is removed. Its id is dropped from the store entirely.
    store.reconcile_ids(&[ID_B]);
    let snaps = store.snapshots();
    assert_eq!(snaps.len(), 1, "removed rule A's counter is dropped");
    assert_eq!(snaps[0].counter_id, ID_B);
    assert_eq!(snaps[0].packets, 3, "surviving rule B is untouched");

    // Re-add a NEW rule C with a different stable id. It starts at zero — it can
    // never inherit removed rule A's count, because A's id is gone and C's id
    // (a function of C's identity) differs from A's.
    const ID_C: u32 = 0xCAFE_BABE;
    let c = store.rule_counter(ID_C).expect("id C");
    c.add(10);
    store.reconcile_ids(&[ID_B, ID_C]);
    let snaps = store.snapshots();
    let c_pkts = snaps
        .iter()
        .find(|s| s.counter_id == ID_C)
        .map(|s| s.packets);
    assert_eq!(
        c_pkts,
        Some(1),
        "re-added rule C starts from its own count, not A's"
    );
    assert!(
        snaps.iter().all(|s| s.counter_id != ID_A),
        "removed rule A's id never reappears"
    );
}

// FAIL-ON-REVERT: a parsed SourceNatRule / DnatEntry / StaticNatEntry must
// SHARE the store's Arc for its counter_id, and carry None for counter_id 0.
// If the build wiring drops the store, the Arcs would not be ptr-eq (or the
// rule would carry None), and this fails.
#[test]
fn parsed_nat_rules_share_store_counters() {
    let store = NatCounterStore::default();

    // SNAT rule with a counter and one without.
    let snat = parse_source_nat_rules_with_previous(
        &[
            SourceNATRuleSnapshot {
                name: "snat-counted".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["0.0.0.0/0".to_string()],
                interface_mode: true,
                counter_id: 11,
                ..SourceNATRuleSnapshot::default()
            },
            SourceNATRuleSnapshot {
                name: "snat-uncounted".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["0.0.0.0/0".to_string()],
                interface_mode: true,
                counter_id: 0,
                ..SourceNATRuleSnapshot::default()
            },
        ],
        None,
        &store,
    );
    let snat_counter = snat[0]
        .hit_counter
        .clone()
        .expect("counted snat has counter");
    assert!(
        std::sync::Arc::ptr_eq(&snat_counter, &store.rule_counter(11).expect("store id 11")),
        "SNAT rule shares the store Arc for counter_id 11"
    );
    assert!(
        snat[1].hit_counter.is_none(),
        "counter_id 0 SNAT rule carries no counter"
    );

    // Static NAT entry with a counter.
    let static_tbl = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            name: "static-counted".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
            counter_id: 22,
        }],
        &store,
    );
    let (_d, static_counter) = static_tbl
        .match_dnat_with_counter("203.0.113.10".parse().unwrap(), 0, "untrust")
        .expect("static dnat match");
    assert!(
        std::sync::Arc::ptr_eq(
            &static_counter.expect("static has counter"),
            &store.rule_counter(22).expect("store id 22")
        ),
        "static NAT entry shares the store Arc for counter_id 22"
    );

    // DNAT entry with a counter.
    let dnat_tbl = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "dnat-counted".to_string(),
            counter_id: 33,
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            source_addresses: vec![],
            destination_address: "203.0.113.20".to_string(),
            destination_prefix: String::new(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "10.0.0.20".to_string(),
            pool_port: 8443,
            match_source_ports: vec![],
            match_destination_ports: vec![],
            match_icmp_type: None,
            match_icmp_code: None,
        }],
        &store,
    );
    let (_d, dnat_counter) = dnat_tbl
        .lookup_with_counter(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.20".parse().unwrap(),
            0,
            443,
            "untrust",
            None,
        )
        .expect("dnat match");
    assert!(
        std::sync::Arc::ptr_eq(
            &dnat_counter.expect("dnat has counter"),
            &store.rule_counter(33).expect("store id 33")
        ),
        "DNAT entry shares the store Arc for counter_id 33"
    );
}

// ---------------------------------------------------------------------------
// #2396: DNAT must not silently drop non-TCP/UDP protocols or IP-only rules.
// ---------------------------------------------------------------------------

/// #2396(a): a GRE DNAT rule (protocol "gre") must install a table entry and
/// translate GRE traffic. Before #2396 the `_ => continue` arm SILENTLY
/// dropped any protocol other than tcp/udp, so this rule never reached the
/// dataplane. Fails (decision None) if the protocol is dropped again.
#[test]
fn dnat_protocol_gre_translates() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "gre-dnat".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 0,
            protocol: "gre".to_string(),
            pool_address: "192.168.1.10".to_string(),
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.lookup(
        PROTO_GRE,
        "198.51.100.1".parse().unwrap(),
        "203.0.113.10".parse().unwrap(),
        0,
        "",
    );
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            ..NatDecision::default()
        }),
        "GRE DNAT rule must translate GRE traffic, not be silently dropped"
    );
    // And it must NOT bleed into a different protocol (no PROTO_ANY wildcard
    // was created — this is a protocol-scoped rule).
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "198.51.100.1".parse().unwrap(),
                "203.0.113.10".parse().unwrap(),
                0,
                ""
            )
            .is_none(),
        "GRE-scoped DNAT must not match TCP"
    );
}

/// #2396(a): an ICMPv6 DNAT rule (protocol "icmp6") must install and translate.
#[test]
fn dnat_protocol_icmp6_translates() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "icmp6-dnat".to_string(),
            destination_address: "2001:db8::1".to_string(),
            destination_port: 0,
            protocol: "icmp6".to_string(),
            pool_address: "fd00::1".to_string(),
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.lookup(
        PROTO_ICMPV6,
        "2001:db8::100".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        0,
        "",
    );
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_dst: Some("fd00::1".parse().unwrap()),
            ..NatDecision::default()
        }),
        "ICMPv6 DNAT rule must translate, not be silently dropped"
    );
}

/// #2396(b): an IP-only DNAT rule (no protocol, no port) must cover ALL L4
/// protocols including ICMP via the protocol wildcard (PROTO_ANY). Before
/// #2396 the `""` + port-0 arm expanded to TCP+UDP ONLY, so ICMP traffic to
/// the destination was NOT translated — contradicting the closeout doc. Fails
/// (ICMP decision None) if the rule reverts to TCP/UDP-only expansion.
#[test]
fn dnat_ip_only_covers_all_protocols_incl_icmp() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "ip-only".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 0,
            protocol: "".to_string(),
            pool_address: "192.168.1.10".to_string(),
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let expected = Some(NatDecision {
        rewrite_dst: Some("192.168.1.10".parse().unwrap()),
        ..NatDecision::default()
    });
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    // ICMP — the case the old TCP/UDP-only expansion missed.
    assert_eq!(
        table.lookup(PROTO_ICMP, src, dst, 0, ""),
        expected,
        "IP-only DNAT must cover ICMP"
    );
    // GRE — another non-TCP/UDP protocol.
    assert_eq!(
        table.lookup(PROTO_GRE, src, dst, 47, ""),
        expected,
        "IP-only DNAT must cover GRE"
    );
    // TCP/UDP at arbitrary ports still match (regression).
    assert_eq!(
        table.lookup(PROTO_TCP, src, dst, 443, ""),
        expected,
        "IP-only DNAT must still cover TCP"
    );
    assert_eq!(
        table.lookup(PROTO_UDP, src, dst, 53, ""),
        expected,
        "IP-only DNAT must still cover UDP"
    );
}

/// #2396(b): a CONCRETE protocol/port DNAT rule must win over a co-resident
/// IP-only (PROTO_ANY) rule on the same destination — the wildcard is only a
/// last-resort fallback, never an override.
#[test]
fn dnat_concrete_rule_wins_over_ip_only_wildcard() {
    let table = DnatTable::from_snapshots(
        &[
            // IP-only catch-all -> pool A
            DestinationNATRuleSnapshot {
                name: "catch-all".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 0,
                protocol: "".to_string(),
                pool_address: "192.168.1.10".to_string(),
                ..DestinationNATRuleSnapshot::default()
            },
            // Specific TCP/443 -> pool B
            DestinationNATRuleSnapshot {
                name: "https".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.20".to_string(),
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    // TCP/443 -> the specific rule (pool B).
    assert_eq!(
        table.lookup(PROTO_TCP, src, dst, 443, ""),
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.20".parse().unwrap()),
            ..NatDecision::default()
        }),
        "specific TCP/443 rule must win over the IP-only wildcard"
    );
    // ICMP -> falls through to the catch-all (pool A).
    assert_eq!(
        table.lookup(PROTO_ICMP, src, dst, 0, ""),
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            ..NatDecision::default()
        }),
        "ICMP must fall through to the IP-only catch-all"
    );
}

/// #2396(c) runtime sibling: a DNAT snapshot whose destination_address fails
/// to parse emits NO entry (fail-closed), and the table is empty — the commit
/// gate (validateDestinationNATAddressesStrict) is what gives the operator
/// feedback, but the dataplane must not install a bogus entry either.
#[test]
fn dnat_invalid_destination_address_yields_no_entry() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "typo".to_string(),
            destination_address: "not-an-ip".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(
        table.is_empty(),
        "a DNAT rule with an unparseable destination must install no entry"
    );
}

/// #2396: the protocol token resolver mirrors the Go SSOT acceptance set.
#[test]
fn proto_number_resolver_matches_known_tokens() {
    use crate::ip_proto::proto_number;
    assert_eq!(proto_number("tcp"), Some(PROTO_TCP));
    assert_eq!(proto_number("udp"), Some(PROTO_UDP));
    assert_eq!(proto_number("icmp"), Some(PROTO_ICMP));
    assert_eq!(proto_number("icmp6"), Some(PROTO_ICMPV6));
    assert_eq!(proto_number("icmpv6"), Some(PROTO_ICMPV6));
    assert_eq!(proto_number("gre"), Some(PROTO_GRE));
    // Bare numeric protocol number.
    assert_eq!(proto_number("47"), Some(PROTO_GRE));
    // #2396 (Copilot fold): "0" is HOPOPT — a REAL, exact protocol number, NOT
    // the wildcard. The wildcard sentinel (PROTO_ANY = 256) is u16 and outside
    // proto_number's u8 range, so it can never be returned here.
    assert_eq!(proto_number("0"), Some(0u8));
    assert_eq!(u16::from(0u8) != PROTO_ANY, true, "HOPOPT must differ from PROTO_ANY");
    // Unresolvable token.
    assert_eq!(proto_number("bogus"), None);
    assert_eq!(proto_number("256"), None);
}

/// #2505: the shared resolver must cover the FULL appid.ProtocolNumber
/// acceptance set — the named protocols and the specific junos-* aliases the
/// Go filter commit gate (filterProtocolResolvable) accepts. A firewall
/// filter `from protocol <token>` reaches the snapshot VERBATIM, so any token
/// the gate passes must resolve here or the filter loses its protocol
/// constraint (the #2505 fail-wide bug).
#[test]
fn proto_number_resolves_full_gate_acceptance_set() {
    use crate::ip_proto::proto_number;
    // Named protocols the stale local filter parser dropped.
    assert_eq!(proto_number("esp"), Some(50));
    assert_eq!(proto_number("ah"), Some(51));
    assert_eq!(proto_number("sctp"), Some(132));
    assert_eq!(proto_number("vrrp"), Some(112));
    assert_eq!(proto_number("igmp"), Some(2));
    assert_eq!(proto_number("pim"), Some(103));
    assert_eq!(proto_number("egp"), Some(8));
    assert_eq!(proto_number("ipip"), Some(4));
    assert_eq!(proto_number("ospf"), Some(89));
    // junos-* aliases (mirror appid.ProtocolNumber / catalog.go).
    assert_eq!(proto_number("junos-tcp-any"), Some(PROTO_TCP));
    assert_eq!(proto_number("junos-udp-any"), Some(PROTO_UDP));
    assert_eq!(proto_number("junos-icmp-all"), Some(PROTO_ICMP));
    assert_eq!(proto_number("junos-ping"), Some(PROTO_ICMP));
    assert_eq!(proto_number("junos-icmp6-all"), Some(PROTO_ICMPV6));
    assert_eq!(proto_number("junos-pingv6"), Some(PROTO_ICMPV6));
    assert_eq!(proto_number("junos-gre"), Some(PROTO_GRE));
    assert_eq!(proto_number("junos-ospf"), Some(89));
    assert_eq!(proto_number("junos-ip-in-ip"), Some(4));
    assert_eq!(proto_number("junos-ipip"), Some(4));
    // An UNKNOWN junos-* alias is NOT accepted (consistent with the gate).
    assert_eq!(proto_number("junos-foobar"), None);
}

/// #2396 (Copilot fold, item 1): the resolver normalizes (trim + lower-case)
/// so a mixed-case or whitespace-padded protocol token from the verbatim
/// parser path resolves to the SAME number as the canonical lower-case token —
/// rather than failing and being silently dropped while the Go side accepts it.
#[test]
fn proto_number_normalizes_case_and_whitespace() {
    use crate::ip_proto::proto_number;
    assert_eq!(proto_number(" GRE "), proto_number("gre"));
    assert_eq!(proto_number("GRE"), Some(PROTO_GRE));
    assert_eq!(proto_number("Icmp"), Some(PROTO_ICMP));
    assert_eq!(proto_number("  TCP"), Some(PROTO_TCP));
    assert_eq!(proto_number("ICMP6"), Some(PROTO_ICMPV6));
    assert_eq!(proto_number(" 47 "), Some(PROTO_GRE));
}

/// #2396 (Copilot fold, item 2): a DNAT rule with `protocol "0"` (HOPOPT) is a
/// DISTINCT exact match — it must NOT alias the IP-only wildcard. A separate
/// IP-only ("") rule on the SAME destination still matches every OTHER
/// protocol via the wildcard, but the HOPOPT rule owns protocol 0 exactly.
#[test]
fn dnat_protocol_zero_hopopt_is_distinct_from_wildcard() {
    use crate::ip_proto::PROTO_TCP as P_TCP;
    let table = DnatTable::from_snapshots(
        &[
            // IP-only catch-all -> pool A (every protocol EXCEPT an exact match)
            DestinationNATRuleSnapshot {
                name: "catch-all".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 0,
                protocol: "".to_string(),
                pool_address: "192.168.1.10".to_string(),
                ..DestinationNATRuleSnapshot::default()
            },
            // Exact HOPOPT (protocol 0) -> pool B
            DestinationNATRuleSnapshot {
                name: "hopopt".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 0,
                protocol: "0".to_string(),
                pool_address: "192.168.1.20".to_string(),
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    // Protocol 0 (HOPOPT) -> the exact HOPOPT rule (pool B), NOT the wildcard.
    assert_eq!(
        table.lookup(0u8, src, dst, 0, ""),
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.20".parse().unwrap()),
            ..NatDecision::default()
        }),
        "protocol 0 (HOPOPT) must hit its exact rule, not the IP-only wildcard"
    );
    // Any OTHER protocol (TCP) -> the IP-only wildcard catch-all (pool A).
    assert_eq!(
        table.lookup(P_TCP, src, dst, 80, ""),
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            ..NatDecision::default()
        }),
        "a non-HOPOPT protocol must still fall through to the IP-only wildcard"
    );
}

// === #3096: interface- / routing-instance-scoped NAT rule-set matching ===

// Source NAT scoped by `from interface`: matches a flow ingressing the named
// interface, NOT another. Fail-on-revert: dropping the `scope_matches` gate in
// SourceNatRule::matches makes the second assertion (wrong-interface) match and
// so RED.
#[test]
fn source_nat_from_interface_scope_matches_only_named_iface() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_interface: "ge-0/0/1.0".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let src: IpAddr = "10.0.61.102".parse().unwrap();
    let dst: IpAddr = "172.16.80.200".parse().unwrap();
    let egress_v4 = Some("172.16.80.8".parse().unwrap());

    // Ingress on the named interface -> matches.
    let on_iface = NatScopeCtx {
        ingress_ifname: "ge-0/0/1.0",
        ..NatScopeCtx::default()
    };
    assert!(
        match_source_nat(&rules, &on_iface, "", "", src, dst, egress_v4, None).is_some(),
        "from-interface-scoped SNAT must match traffic ingressing the named interface"
    );

    // Ingress on a DIFFERENT interface -> no match.
    let other_iface = NatScopeCtx {
        ingress_ifname: "ge-0/0/2.0",
        ..NatScopeCtx::default()
    };
    assert!(
        match_source_nat(&rules, &other_iface, "", "", src, dst, egress_v4, None).is_none(),
        "from-interface-scoped SNAT must NOT match traffic ingressing another interface"
    );
}

// Source NAT scoped by `from routing-instance`: matches only the named VRF.
#[test]
fn source_nat_from_routing_instance_scope_matches_only_named_vrf() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_routing_instance: "VR1".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let src: IpAddr = "10.0.61.102".parse().unwrap();
    let dst: IpAddr = "172.16.80.200".parse().unwrap();
    let egress_v4 = Some("172.16.80.8".parse().unwrap());

    let in_vr1 = NatScopeCtx {
        ingress_routing_instance: "VR1",
        ..NatScopeCtx::default()
    };
    assert!(
        match_source_nat(&rules, &in_vr1, "", "", src, dst, egress_v4, None).is_some(),
        "from-routing-instance-scoped SNAT must match traffic in the named VRF"
    );

    let in_vr2 = NatScopeCtx {
        ingress_routing_instance: "VR2",
        ..NatScopeCtx::default()
    };
    assert!(
        match_source_nat(&rules, &in_vr2, "", "", src, dst, egress_v4, None).is_none(),
        "from-routing-instance-scoped SNAT must NOT match traffic in another VRF"
    );
}

// Source NAT scoped by `to interface`: matches only the named egress interface.
#[test]
fn source_nat_to_interface_scope_matches_only_named_egress() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        to_interface: "ge-0/0/2.0".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let src: IpAddr = "10.0.61.102".parse().unwrap();
    let dst: IpAddr = "172.16.80.200".parse().unwrap();
    let egress_v4 = Some("172.16.80.8".parse().unwrap());

    let to_named = NatScopeCtx {
        egress_ifname: "ge-0/0/2.0",
        ..NatScopeCtx::default()
    };
    assert!(
        match_source_nat(&rules, &to_named, "", "", src, dst, egress_v4, None).is_some(),
        "to-interface-scoped SNAT must match traffic egressing the named interface"
    );
    let to_other = NatScopeCtx {
        egress_ifname: "ge-0/0/9.0",
        ..NatScopeCtx::default()
    };
    assert!(
        match_source_nat(&rules, &to_other, "", "", src, dst, egress_v4, None).is_none(),
        "to-interface-scoped SNAT must NOT match traffic egressing another interface"
    );
}

// A zone-scoped source NAT rule is unaffected by the #3096 scope plumbing
// (no-regression): empty interface/RI scope = wildcard, so any interface/VRF
// in the matching zone pair still matches.
#[test]
fn source_nat_zone_scope_unaffected_by_interface_plumbing() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let src: IpAddr = "10.0.61.102".parse().unwrap();
    let dst: IpAddr = "172.16.80.200".parse().unwrap();
    let egress_v4 = Some("172.16.80.8".parse().unwrap());
    // Arbitrary interface names in the scope ctx must not affect a zone rule.
    let scope = NatScopeCtx {
        ingress_ifname: "ge-0/0/7.0",
        egress_ifname: "ge-0/0/8.0",
        ingress_routing_instance: "whatever",
        egress_routing_instance: "whatever",
    };
    assert!(
        match_source_nat(&rules, &scope, "lan", "wan", src, dst, egress_v4, None).is_some(),
        "zone-scoped SNAT must still match regardless of interface/RI ctx"
    );
}

// Static NAT (DNAT direction) scoped by `from interface`: the inbound
// translation fires only when the packet ingresses the named interface.
// Fail-on-revert: dropping the interface gate in match_dnat_with_counter_scoped
// makes the wrong-interface assertion fire and so RED.
#[test]
fn static_nat_dnat_from_interface_scope_matches_only_named_iface() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            name: "stat".to_string(),
            from_interface: "ge-0/0/1.0".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    let ext: IpAddr = "203.0.113.10".parse().unwrap();
    // On the named interface -> DNAT applies.
    assert!(
        table
            .match_dnat_with_counter_scoped(ext, 0, None, "", "ge-0/0/1.0", "")
            .is_some(),
        "interface-scoped static DNAT must match on the named ingress interface"
    );
    // On a different interface -> no DNAT.
    assert!(
        table
            .match_dnat_with_counter_scoped(ext, 0, None, "", "ge-0/0/2.0", "")
            .is_none(),
        "interface-scoped static DNAT must NOT match on another ingress interface"
    );
}

// Static NAT (SNAT/reverse direction) scoped by `from interface`: the reverse
// source translation fires only when the packet egresses the named interface.
#[test]
fn static_nat_snat_from_interface_scope_matches_only_named_egress() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            name: "stat".to_string(),
            from_interface: "ge-0/0/1.0".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    let int: IpAddr = "192.168.1.10".parse().unwrap();
    assert!(
        table
            .match_snat_with_counter_scoped(int, 0, None, "", "ge-0/0/1.0", "")
            .is_some(),
        "interface-scoped static SNAT must match on the named egress interface"
    );
    assert!(
        table
            .match_snat_with_counter_scoped(int, 0, None, "", "ge-0/0/2.0", "")
            .is_none(),
        "interface-scoped static SNAT must NOT match on another egress interface"
    );
}

// #3435 (H01): static-NAT `match source-address` must gate the inbound DNAT
// translation on the packet SOURCE. Before #3435 the constraint was dropped at
// the snapshot boundary, installing an all-source mapping that exposed the
// internal host to ANY source. Fail-on-revert: dropping the `source_ok` gate
// makes the out-of-scope-source assertion (which expects None) match and so RED.
#[test]
fn static_nat_dnat_source_address_gates_inbound() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            name: "stat".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            source_addresses: vec!["198.51.100.0/24".to_string()],
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    let ext: IpAddr = "203.0.113.10".parse().unwrap();
    let in_scope: IpAddr = "198.51.100.7".parse().unwrap();
    let out_scope: IpAddr = "203.0.113.99".parse().unwrap();
    assert!(
        table
            .match_dnat_with_counter_scoped(ext, 0, Some(in_scope), "", "", "")
            .is_some(),
        "static DNAT must fire for a source inside `match source-address`"
    );
    assert!(
        table
            .match_dnat_with_counter_scoped(ext, 0, Some(out_scope), "", "", "")
            .is_none(),
        "static DNAT must NOT fire for a source outside `match source-address` (the #3435 fail-open)"
    );
}

// #3435 (M02): a bracket / repeated source-address list must honor EVERY prefix
// (the multi-value scalar loss). Fail-on-revert: if the compiler/snapshot drops
// every entry after the first, the second-prefix source goes unmatched and the
// loop assertion RED.
#[test]
fn static_nat_dnat_source_address_bracket_list() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            name: "stat".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            source_addresses: vec![
                "198.51.100.0/24".to_string(),
                "203.0.113.200".to_string(),
            ],
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    let ext: IpAddr = "203.0.113.10".parse().unwrap();
    for src in ["198.51.100.7", "203.0.113.200"] {
        let s: IpAddr = src.parse().unwrap();
        assert!(
            table
                .match_dnat_with_counter_scoped(ext, 0, Some(s), "", "", "")
                .is_some(),
            "static DNAT must fire for source {src} in the bracket list"
        );
    }
    let out: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(
        table
            .match_dnat_with_counter_scoped(ext, 0, Some(out), "", "", "")
            .is_none(),
        "static DNAT must NOT fire for a source outside the bracket list"
    );
}

// #3435: the reverse (SNAT) direction gates on the packet DESTINATION (the
// original client), symmetric with the inbound source gate. Fail-on-revert:
// dropping the source gate lets an out-of-scope destination match.
#[test]
fn static_nat_snat_source_address_gates_reverse() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            name: "stat".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            source_addresses: vec!["198.51.100.0/24".to_string()],
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    let int: IpAddr = "192.168.1.10".parse().unwrap();
    let in_scope: IpAddr = "198.51.100.7".parse().unwrap();
    let out_scope: IpAddr = "203.0.113.99".parse().unwrap();
    assert!(
        table
            .match_snat_with_counter_scoped(int, 0, Some(in_scope), "", "", "")
            .is_some(),
        "reverse static SNAT must fire toward a client inside `match source-address`"
    );
    assert!(
        table
            .match_snat_with_counter_scoped(int, 0, Some(out_scope), "", "", "")
            .is_none(),
        "reverse static SNAT must NOT fire toward a client outside `match source-address`"
    );
}

// #3435: a source-constrained rule whose source list parses to NOTHING (every
// entry malformed) must match NO source — fail CLOSED, never revert to
// match-any (the #2394/#3435 fail-open guard). Fail-on-revert: collapsing the
// unparseable list to "unconstrained" makes the assertion (expecting None) RED.
#[test]
fn static_nat_dnat_source_address_unparseable_fails_closed() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            name: "stat".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            source_addresses: vec!["not-an-ip".to_string()],
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    let ext: IpAddr = "203.0.113.10".parse().unwrap();
    let any: IpAddr = "198.51.100.7".parse().unwrap();
    assert!(
        table
            .match_dnat_with_counter_scoped(ext, 0, Some(any), "", "", "")
            .is_none(),
        "a source-scoped rule with no parseable prefix must match nothing (fail closed)"
    );
}

// #3435: guard against over-gating — an UNscoped static-NAT rule (no `match
// source-address`) must still translate every source.
#[test]
fn static_nat_dnat_no_source_constraint_matches_any() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            name: "stat".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    let ext: IpAddr = "203.0.113.10".parse().unwrap();
    let any: IpAddr = "10.9.8.7".parse().unwrap();
    assert!(
        table
            .match_dnat_with_counter_scoped(ext, 0, Some(any), "", "", "")
            .is_some(),
        "an unscoped static DNAT must match any source"
    );
}

// === #3605: zone/scope-differentiated static-NAT rules must COEXIST ===

// Split-horizon static DNAT: two rules share the same `(external_ip,
// match-port)` key but differ by `from zone`, translating the same public
// address to a DIFFERENT internal host per ingress zone. Both must be
// installed and matched by scope.
//
// Fail-on-revert: with the pre-#3605 single-entry map the second rule
// OVERWRITES the first (last-write-wins), so the untrust packet — whose only
// surviving entry is the dmz-scoped rule — fails `zone_ok` and returns None
// (a silent UNtranslated leak). The untrust assertion below then RED.
#[test]
fn static_nat_dnat_scope_differentiated_rules_coexist_3605() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[
            StaticNATRuleSnapshot {
                name: "from-untrust".to_string(),
                from_zone: "untrust".to_string(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
            StaticNATRuleSnapshot {
                name: "from-dmz".to_string(),
                from_zone: "dmz".to_string(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "10.0.0.10".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
        ],
        &counters,
    );
    let ext: IpAddr = "203.0.113.10".parse().unwrap();
    // Packet ingressing untrust -> the untrust rule (192.168.1.10). This is the
    // rule OVERWRITTEN pre-#3605, so this assertion is the fail-on-revert.
    let via_untrust = table
        .match_dnat_with_counter_scoped(ext, 0, None, "untrust", "", "")
        .map(|(d, _)| d.rewrite_dst);
    assert_eq!(
        via_untrust,
        Some(Some("192.168.1.10".parse().unwrap())),
        "untrust-scoped static DNAT must survive alongside the dmz-scoped rule (#3605 overwrite)"
    );
    // Packet ingressing dmz -> the dmz rule (10.0.0.10).
    let via_dmz = table
        .match_dnat_with_counter_scoped(ext, 0, None, "dmz", "", "")
        .map(|(d, _)| d.rewrite_dst);
    assert_eq!(
        via_dmz,
        Some(Some("10.0.0.10".parse().unwrap())),
        "dmz-scoped static DNAT must translate to its own internal host"
    );
}

// Reverse (SNAT) direction of the same #3605 overwrite: two rules map DIFFERENT
// external addresses to the SAME internal host, scoped by different egress
// zones. The SNAT map keys on `(internal_ip, snat_port)`, so both rules collide
// on one key and the pre-#3605 map kept only the last -> the trust-egress
// return packet un-NATs to the wrong (or no) external address.
//
// Fail-on-revert: the trust assertion RED because its rule was overwritten by
// the wan-scoped rule.
#[test]
fn static_nat_snat_scope_differentiated_rules_coexist_3605() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[
            StaticNATRuleSnapshot {
                name: "egress-trust".to_string(),
                from_zone: "trust".to_string(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
            StaticNATRuleSnapshot {
                name: "egress-wan".to_string(),
                from_zone: "wan".to_string(),
                external_ip: "203.0.113.20".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
        ],
        &counters,
    );
    let int: IpAddr = "192.168.1.10".parse().unwrap();
    // Return packet egressing trust -> un-NAT to 203.0.113.10 (overwritten rule).
    let via_trust = table
        .match_snat_with_counter_scoped(int, 0, None, "trust", "", "")
        .map(|(d, _)| d.rewrite_src);
    assert_eq!(
        via_trust,
        Some(Some("203.0.113.10".parse().unwrap())),
        "trust-egress static SNAT must survive alongside the wan-scoped rule (#3605 overwrite)"
    );
    // Return packet egressing wan -> un-NAT to 203.0.113.20.
    let via_wan = table
        .match_snat_with_counter_scoped(int, 0, None, "wan", "", "")
        .map(|(d, _)| d.rewrite_src);
    assert_eq!(
        via_wan,
        Some(Some("203.0.113.20".parse().unwrap())),
        "wan-egress static SNAT must un-NAT to its own external address"
    );
}

// #3605 specificity tiering: a zone-SCOPED rule and a zone-WILDCARD rule share
// the same `(external_ip, match-port)` key. A packet matching the scoped zone
// must hit the SPECIFIC rule, not the wildcard — regardless of config order
// (the wildcard is authored FIRST here, the adversarial order). Traffic in any
// other zone falls through to the wildcard.
//
// Fail-on-revert: with the single-entry map the scoped rule (authored second)
// overwrites the wildcard, so the "other zone" packet — whose only entry is now
// the trust-scoped rule — returns None instead of the wildcard translation, so
// the other-zone assertion RED.
#[test]
fn static_nat_dnat_scoped_rule_wins_over_coexisting_wildcard_3605() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[
            StaticNATRuleSnapshot {
                name: "wildcard".to_string(),
                from_zone: String::new(), // any zone
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "10.0.0.99".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
            StaticNATRuleSnapshot {
                name: "trust-specific".to_string(),
                from_zone: "trust".to_string(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
        ],
        &counters,
    );
    let ext: IpAddr = "203.0.113.10".parse().unwrap();
    // trust ingress -> the SPECIFIC rule wins over the wildcard.
    let via_trust = table
        .match_dnat_with_counter_scoped(ext, 0, None, "trust", "", "")
        .map(|(d, _)| d.rewrite_dst);
    assert_eq!(
        via_trust,
        Some(Some("192.168.1.10".parse().unwrap())),
        "the zone-specific rule must win over a coexisting wildcard regardless of order (#3605)"
    );
    // any other zone -> the wildcard catch-all (fail-on-revert: overwritten).
    let via_other = table
        .match_dnat_with_counter_scoped(ext, 0, None, "untrust", "", "")
        .map(|(d, _)| d.rewrite_dst);
    assert_eq!(
        via_other,
        Some(Some("10.0.0.99".parse().unwrap())),
        "an unmatched zone must fall through to the coexisting wildcard rule (#3605 overwrite)"
    );
}

// Destination NAT scoped by `from interface`: the DNAT entry fires only for the
// named ingress interface. Fail-on-revert: dropping the scope_ok gate in
// match_entries makes the wrong-interface assertion fire and so RED.
#[test]
fn destination_nat_from_interface_scope_matches_only_named_iface() {
    let counters = NatCounterStore::default();
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "dnat".to_string(),
            from_interface: "ge-0/0/1.0".to_string(),
            destination_address: "203.0.113.10".to_string(),
            pool_address: "10.0.0.5".to_string(),
            ..DestinationNATRuleSnapshot::default()
        }],
        &counters,
    );
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    assert!(
        table
            .lookup_with_counter_scoped(PROTO_TCP, src, dst, 0, 443, "", "ge-0/0/1.0", "", None)
            .is_some(),
        "interface-scoped DNAT must match on the named ingress interface"
    );
    assert!(
        table
            .lookup_with_counter_scoped(PROTO_TCP, src, dst, 0, 443, "", "ge-0/0/2.0", "", None)
            .is_none(),
        "interface-scoped DNAT must NOT match on another ingress interface"
    );
}

// Destination NAT scoped by `from routing-instance`.
#[test]
fn destination_nat_from_routing_instance_scope_matches_only_named_vrf() {
    let counters = NatCounterStore::default();
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "dnat".to_string(),
            from_routing_instance: "VR1".to_string(),
            destination_address: "203.0.113.10".to_string(),
            pool_address: "10.0.0.5".to_string(),
            ..DestinationNATRuleSnapshot::default()
        }],
        &counters,
    );
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    assert!(
        table
            .lookup_with_counter_scoped(PROTO_TCP, src, dst, 0, 443, "", "", "VR1", None)
            .is_some(),
        "RI-scoped DNAT must match in the named VRF"
    );
    assert!(
        table
            .lookup_with_counter_scoped(PROTO_TCP, src, dst, 0, 443, "", "", "VR2", None)
            .is_none(),
        "RI-scoped DNAT must NOT match in another VRF"
    );
}

// === #3429: source-NAT `match destination-port` / `match application`
// enforcement. Before the fix these match fields were parsed and compiled but
// never carried to the dataplane, so a port/app-scoped source-NAT rule
// (including a `then source-nat off` exemption) silently widened to every
// port/protocol. Reverting the l4_matches gate makes the wrong-port / wrong-app
// lookups translate, turning the NoMatch assertions RED. ===

#[test]
fn source_nat_match_destination_port_constrains_flow_3429() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        // `match destination-port 20000 to 20003`.
        match_destination_ports: vec![NatPortRangeWire {
            low: 20000,
            high: 20003,
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let src: IpAddr = "10.0.1.100".parse().unwrap();
    let dst: IpAddr = "8.8.8.8".parse().unwrap();
    let mut counter = None;
    // In-range destination port -> translated.
    let hit = match_source_nat_result_for_tuple(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src,
        dst,
        PROTO_TCP,
        12345,
        20001,
        egress_v4,
        None,
        0,
        false,
        &mut counter,
    );
    assert!(
        matches!(hit, SourceNatLookup::Matched(_)),
        "in-range dst port must match: {:?}",
        hit
    );
    // Out-of-range destination port -> NO match (pre-fix this over-matched).
    let miss = match_source_nat_result_for_tuple(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src,
        dst,
        PROTO_TCP,
        12345,
        80,
        egress_v4,
        None,
        0,
        false,
        &mut counter,
    );
    assert_eq!(
        miss,
        SourceNatLookup::NoMatch,
        "out-of-range dst port must NOT match"
    );
}

#[test]
fn source_nat_match_destination_port_constrains_off_exemption_3429() {
    // `then source-nat off` scoped to a destination port must exempt ONLY that
    // port. Pre-fix the exemption widened to every port, so a flow on a
    // different port was wrongly left untranslated (Matched(default)).
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "no-nat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        off: true,
        match_destination_ports: vec![NatPortRangeWire { low: 53, high: 53 }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let src: IpAddr = "10.0.1.100".parse().unwrap();
    let dst: IpAddr = "8.8.8.8".parse().unwrap();
    let mut counter = None;
    // Exempt port -> matched as a no-op (off) rule.
    let on_port = match_source_nat_result_for_tuple(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src,
        dst,
        PROTO_UDP,
        40000,
        53,
        egress_v4,
        None,
        0,
        false,
        &mut counter,
    );
    assert!(
        matches!(on_port, SourceNatLookup::Matched(_)),
        "exempt port must match the off rule: {:?}",
        on_port
    );
    // Different port -> the off rule must NOT swallow it.
    let other_port = match_source_nat_result_for_tuple(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src,
        dst,
        PROTO_UDP,
        40000,
        443,
        egress_v4,
        None,
        0,
        false,
        &mut counter,
    );
    assert_eq!(
        other_port,
        SourceNatLookup::NoMatch,
        "a port-scoped `source-nat off` must NOT exempt other ports"
    );
}

#[test]
fn source_nat_match_application_constrains_protocol_and_port_3429() {
    // `match application` pre-expanded to (proto=TCP, ports=[443]).
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        match_applications: vec![NatAppTermWire {
            protocol: PROTO_TCP as u16,
            ports: vec![NatPortRangeWire {
                low: 443,
                high: 443,
            }],
            src_ports: vec![],
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let src: IpAddr = "10.0.1.100".parse().unwrap();
    let dst: IpAddr = "8.8.8.8".parse().unwrap();
    let lookup = |proto: u8, dport: u16| {
        let mut counter = None;
        match_source_nat_result_for_tuple(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src,
            dst,
            proto,
            12345,
            dport,
            egress_v4,
            None,
            0,
            false,
            &mut counter,
        )
    };
    // Right proto + right port -> match.
    assert!(
        matches!(lookup(PROTO_TCP, 443), SourceNatLookup::Matched(_)),
        "tcp/443 must match the app-scoped rule"
    );
    // Right proto, wrong port -> no match.
    assert_eq!(
        lookup(PROTO_TCP, 80),
        SourceNatLookup::NoMatch,
        "tcp/80 must NOT match an app scoped to tcp/443"
    );
    // Wrong proto (UDP) on the same port -> no match.
    assert_eq!(
        lookup(PROTO_UDP, 443),
        SourceNatLookup::NoMatch,
        "udp/443 must NOT match an app scoped to tcp/443"
    );
}

#[test]
fn source_nat_match_application_constrains_source_port_3491() {
    // #3491: `match application` pre-expanded to (proto=TCP, dst=443, src=12345).
    // The application carried a source-port constraint; before #3491 it was
    // dropped and the rule matched any source port (fail-open). Reverting the
    // l4_matches src_port gate (or the SrcPorts wire) makes the wrong-source-port
    // assertion below match -> RED.
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        match_applications: vec![NatAppTermWire {
            protocol: PROTO_TCP as u16,
            ports: vec![NatPortRangeWire {
                low: 443,
                high: 443,
            }],
            src_ports: vec![NatPortRangeWire {
                low: 12345,
                high: 12345,
            }],
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let src: IpAddr = "10.0.1.100".parse().unwrap();
    let dst: IpAddr = "8.8.8.8".parse().unwrap();
    let lookup = |sport: u16, dport: u16| {
        let mut counter = None;
        match_source_nat_result_for_tuple(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src,
            dst,
            PROTO_TCP,
            sport,
            dport,
            egress_v4,
            None,
            0,
            false,
            &mut counter,
        )
    };
    // Right source port + right dest port -> match.
    assert!(
        matches!(lookup(12345, 443), SourceNatLookup::Matched(_)),
        "tcp src=12345 dst=443 must match the app-scoped rule"
    );
    // Right dest port, WRONG source port -> no match (the #3491 fail-open).
    assert_eq!(
        lookup(55555, 443),
        SourceNatLookup::NoMatch,
        "tcp src=55555 dst=443 must NOT match an app scoped to source-port 12345"
    );
}

#[test]
fn source_nat_app_source_port_never_match_sentinel_3491() {
    // #3491: the Go builder emits a low>high never-match range when an
    // application's source-port spec coalesces to nothing. The Rust matcher must
    // preserve it (port_in_ranges can never satisfy low>high) so the term matches
    // NO source port rather than widening to any source port.
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        match_applications: vec![NatAppTermWire {
            protocol: PROTO_TCP as u16,
            ports: vec![],
            src_ports: vec![NatPortRangeWire { low: 1, high: 0 }],
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let mut counter = None;
    let lookup = match_source_nat_result_for_tuple(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        PROTO_TCP,
        12345,
        443,
        egress_v4,
        None,
        0,
        false,
        &mut counter,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::NoMatch,
        "a never-match source-port sentinel must match NO source port"
    );
}

#[test]
fn source_nat_unconstrained_rule_still_matches_any_l4_3429() {
    // A rule with NO L4 match fields keeps the pre-#3429 match-any behavior,
    // including for the address-only (proto=0) tuple-unknown caller.
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let d = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        egress_v4,
        None,
    );
    assert!(
        d.is_some(),
        "an unconstrained SNAT rule must still match (proto-unknown caller)"
    );
}

#[test]
fn source_nat_l4_constrained_rule_fails_closed_on_unknown_tuple_3429() {
    // The address-only (proto=0) caller cannot supply a port/protocol, so an
    // L4-constrained rule fails closed (does not fire) rather than over-match.
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        match_destination_ports: vec![NatPortRangeWire {
            low: 443,
            high: 443,
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let d = match_source_nat(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        egress_v4,
        None,
    );
    assert!(
        d.is_none(),
        "an L4-scoped SNAT rule must NOT fire for an unknown (proto=0) tuple"
    );
}

// #3471 fold: a destination-port constraint that is purely an impossible
// (low > high) range — the natNeverMatchPortRange fail-closed sentinel the Go
// builder emits when every configured port is out of range — must match
// NOTHING, NOT collapse to "unconstrained". The Rust parser keeps a low > high
// range verbatim; dropping it (the pre-fold revert) empties match_dst_ports and
// l4_matches then treats the rule as port-unconstrained = match-all (fail-open).
#[test]
fn source_nat_never_match_port_sentinel_matches_nothing_3429() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        // natNeverMatchPortRange = {low:1, high:0} — impossible, never matches.
        match_destination_ports: vec![NatPortRangeWire { low: 1, high: 0 }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let src: IpAddr = "10.0.1.100".parse().unwrap();
    let dst: IpAddr = "8.8.8.8".parse().unwrap();
    for dport in [1u16, 80, 443, 20001, 65535] {
        let mut counter = None;
        let r = match_source_nat_result_for_tuple(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src,
            dst,
            PROTO_TCP,
            12345,
            dport,
            egress_v4,
            None,
            0,
            false,
            &mut counter,
        );
        assert_eq!(
            r,
            SourceNatLookup::NoMatch,
            "never-match port sentinel must reject dst port {}",
            dport
        );
    }
}

// #3471 fold: an app term whose protocol is the never-match sentinel (0xFFFF,
// what the Go builder emits for an empty/unresolvable app protocol) must match
// NOTHING, while a genuinely-any term (SOURCE_NAT_PROTO_ANY = 256) still matches
// every protocol. This locks the distinction the Codex finding turned on:
// returning natProtoAny for an unresolvable protocol (the revert) would make the
// never term behave like the any term — fail-open.
#[test]
fn source_nat_app_protocol_never_vs_any_3429() {
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let src: IpAddr = "10.0.1.100".parse().unwrap();
    let dst: IpAddr = "8.8.8.8".parse().unwrap();
    let lookup = |rules: &[_], proto: u8| {
        let mut counter = None;
        match_source_nat_result_for_tuple(
            rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src,
            dst,
            proto,
            12345,
            443,
            egress_v4,
            None,
            0,
            false,
            &mut counter,
        )
    };

    // Never-match protocol sentinel (0xFFFF): no protocol satisfies the term.
    let never = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        match_applications: vec![NatAppTermWire {
            protocol: 0xFFFF,
            ports: vec![],
            src_ports: vec![],
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    for proto in [PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_GRE] {
        assert_eq!(
            lookup(&never, proto),
            SourceNatLookup::NoMatch,
            "never-match app protocol must reject protocol {}",
            proto
        );
    }

    // Genuinely-any protocol (256): every protocol matches the term.
    let any = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        match_applications: vec![NatAppTermWire {
            protocol: SOURCE_NAT_PROTO_ANY,
            ports: vec![],
            src_ports: vec![],
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    for proto in [PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_GRE] {
        assert!(
            matches!(lookup(&any, proto), SourceNatLookup::Matched(_)),
            "any-protocol app term must match protocol {}",
            proto
        );
    }
}

// ===========================================================================
// #3437: DNAT `match application` source-port (H10) + ICMP type/code (H11)
// enforcement. Before #3437 the DNAT builder reduced an application to
// protocol + destination-port only, so the published VIP matched any source
// port and every ICMP type — a fail-open NAT widening. These tests pin the
// dataplane gate and are RED when the `l4_extra_matches` source-port / ICMP
// checks are reverted.
// ===========================================================================

/// Helper: a single-rule DNAT table whose entry carries the given L4 match
/// constraints. Destination 203.0.113.10, pool 192.168.1.10, unscoped zone.
fn dnat_table_with_l4(
    protocol: &str,
    destination_port: u16,
    match_source_ports: Vec<NatPortRangeWire>,
    match_icmp_type: Option<u8>,
    match_icmp_code: Option<u8>,
) -> DnatTable {
    DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "app-scoped".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port,
            protocol: protocol.to_string(),
            pool_address: "192.168.1.10".to_string(),
            match_source_ports,
            match_icmp_type,
            match_icmp_code,
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    )
}

#[test]
fn dnat_match_application_constrains_source_port_3437() {
    // `match application <app>` with source-port 12345 -> only a flow whose
    // SOURCE port is 12345 (hitting dest port 80) is DNAT'd.
    let table = dnat_table_with_l4(
        "tcp",
        80,
        vec![NatPortRangeWire {
            low: 12345,
            high: 12345,
        }],
        None,
        None,
    );
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();

    // In-range source port: translated.
    let hit = table
        .lookup_with_counter(PROTO_TCP, src, dst, 12345, 80, "", None)
        .map(|(d, _)| d);
    assert_eq!(
        hit,
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            ..NatDecision::default()
        }),
        "DNAT must fire for the application's source port"
    );

    // Out-of-range source port: NOT translated (RED on revert of the
    // source-port gate in l4_extra_matches — without it this is Some).
    let miss = table
        .lookup_with_counter(PROTO_TCP, src, dst, 55555, 80, "", None)
        .map(|(d, _)| d);
    assert_eq!(
        miss, None,
        "DNAT must NOT fire for a source port outside the application's range"
    );
}

#[test]
fn dnat_match_application_source_port_never_match_sentinel_3437() {
    // A configured source-port that coalesced to nothing -> never-match
    // sentinel ({low:1, high:0}). The entry must match NO source port (fail
    // closed), not widen to any.
    let table = dnat_table_with_l4(
        "tcp",
        80,
        vec![NatPortRangeWire { low: 1, high: 0 }],
        None,
        None,
    );
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    for sp in [0u16, 1, 80, 12345, 65535] {
        assert!(
            table
                .lookup_with_counter(PROTO_TCP, src, dst, sp, 80, "", None)
                .is_none(),
            "never-match source-port sentinel must reject source port {sp}"
        );
    }
}

#[test]
fn dnat_match_application_constrains_icmp_type_3437() {
    // `match application junos-ping` = ICMP echo-request (type 8). Only ICMP
    // type 8 to the VIP is DNAT'd; an echo-reply (type 0), a destination-
    // unreachable (type 3), and a non-ICMP flow must NOT be translated.
    let table = dnat_table_with_l4("icmp", 0, vec![], Some(8), None);
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();

    // Echo-request: translated.
    let hit = table
        .lookup_with_counter(PROTO_ICMP, src, dst, 0, 0, "", Some((8, 0)))
        .map(|(d, _)| d);
    assert_eq!(
        hit,
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            ..NatDecision::default()
        }),
        "DNAT must fire for the application's ICMP type (echo-request)"
    );

    // Echo-reply (type 0): NOT translated (RED on revert of the ICMP gate —
    // without it this is Some).
    assert!(
        table
            .lookup_with_counter(PROTO_ICMP, src, dst, 0, 0, "", Some((0, 0)))
            .is_none(),
        "DNAT must NOT fire for a different ICMP type (echo-reply)"
    );

    // Destination-unreachable (type 3): NOT translated.
    assert!(
        table
            .lookup_with_counter(PROTO_ICMP, src, dst, 0, 0, "", Some((3, 1)))
            .is_none(),
        "DNAT must NOT fire for an ICMP error type"
    );

    // Non-ICMP flow (no packet_icmp supplied): fail closed.
    assert!(
        table
            .lookup_with_counter(PROTO_ICMP, src, dst, 0, 0, "", None)
            .is_none(),
        "an ICMP-type-constrained entry must fail closed when the packet has no ICMP (type, code)"
    );
}

#[test]
fn dnat_match_application_constrains_icmp_type_and_code_3437() {
    // type 3 + code 1 (host-unreachable). Right type, wrong code must NOT match.
    let table = dnat_table_with_l4("icmp", 0, vec![], Some(3), Some(1));
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    assert!(
        table
            .lookup_with_counter(PROTO_ICMP, src, dst, 0, 0, "", Some((3, 1)))
            .is_some(),
        "DNAT must fire for the exact (type, code)"
    );
    assert!(
        table
            .lookup_with_counter(PROTO_ICMP, src, dst, 0, 0, "", Some((3, 0)))
            .is_none(),
        "DNAT must NOT fire for the right type but wrong code"
    );
}

#[test]
fn dnat_unconstrained_application_still_matches_any_l4_3437() {
    // Regression guard: an entry with NO source-port and NO ICMP constraint
    // (the common case) still matches any source port / any ICMP type — the
    // fix must not narrow the unconstrained path.
    let table = dnat_table_with_l4("tcp", 80, vec![], None, None);
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    for sp in [0u16, 1, 1024, 65535] {
        assert!(
            table
                .lookup_with_counter(PROTO_TCP, src, dst, sp, 80, "", None)
                .is_some(),
            "unconstrained DNAT must match any source port (got miss at {sp})"
        );
    }

    let icmp_any = dnat_table_with_l4("icmp", 0, vec![], None, None);
    for t in [0u8, 3, 8, 11] {
        assert!(
            icmp_any
                .lookup_with_counter(PROTO_ICMP, src, dst, 0, 0, "", Some((t, 0)))
                .is_some(),
            "unconstrained ICMP DNAT must match any ICMP type (got miss at type {t})"
        );
    }
}

// #3434 (Codex audit 095 H07/H08): a DNAT rule whose `match application` names
// an UNDEFINED application or a defined-but-EMPTY application-set resolves to
// zero application terms. Before the fix the Go builder fell through to its
// explicit-match fallback and emitted protocol="" + destination_port=0 — a
// PROTO_ANY wildcard entry that translated EVERY flow to the destination (a
// fail-open wildcard VIP). The fix instead emits that same wildcard shape but
// with the #3437 source-port never-match sentinel ({low:1, high:0}), so the
// installed entry can never satisfy l4_extra_matches and translates NOTHING.
//
// This test pins the exact snapshot shape the Go builder now emits for an
// undefined/empty NAT app reference and proves it fails CLOSED across every L4
// protocol and port. The first table is the pre-fix fail-open (no sentinel) —
// it translates everything — and is the contrast that proves the sentinel is
// what closes the hole.
#[test]
fn dnat_undefined_application_never_match_sentinel_fails_closed_3434() {
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();

    // Pre-fix shape: an IP-only wildcard entry (protocol="" + dst_port=0 =>
    // PROTO_ANY) with NO L4 constraint translates ANY protocol/port — the
    // H07/H08 fail-open the explicit-match fallback produced.
    let fail_open = dnat_table_with_l4("", 0, vec![], None, None);
    assert!(
        fail_open
            .lookup_with_counter(PROTO_TCP, src, dst, 40000, 443, "", None)
            .is_some(),
        "control: an unconstrained PROTO_ANY DNAT entry translates any flow (the pre-fix fail-open)"
    );

    // Post-fix shape: the same wildcard entry carrying the never-match
    // source-port sentinel matches NOTHING, for every protocol and port.
    let fail_closed = dnat_table_with_l4("", 0, vec![NatPortRangeWire { low: 1, high: 0 }], None, None);
    for &(proto, sp, dp) in &[
        (PROTO_TCP, 0u16, 0u16),
        (PROTO_TCP, 40000, 443),
        (PROTO_UDP, 1, 53),
        (PROTO_ICMP, 0, 0),
        (PROTO_TCP, 65535, 65535),
    ] {
        let icmp = if proto == PROTO_ICMP {
            Some((8u8, 0u8))
        } else {
            None
        };
        assert!(
            fail_closed
                .lookup_with_counter(proto, src, dst, sp, dp, "", icmp)
                .is_none(),
            "undefined-app never-match sentinel must reject proto={proto} sport={sp} dport={dp}"
        );
    }
}

// #3449: a DNAT `match destination-port low to high` range rides ONE
// wildcard-port entry (destination_port=0) carrying a match_destination_ports
// range, instead of one exact-port entry per port. The lookup must translate a
// flow whose destination port falls in the range and miss one outside it. A
// pool_port of 0 preserves the destination port (the range maps each port to
// itself). RED-on-revert: drop the match_dst_ports check in l4_extra_matches
// and the out-of-range port is wrongly translated (the wildcard entry widens to
// match-any-port).
#[test]
fn dnat_destination_port_range_3449() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "range".to_string(),
            from_zone: "untrust".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 0,
            match_destination_ports: vec![NatPortRangeWire {
                low: 20000,
                high: 30000,
            }],
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 0,
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let src: std::net::IpAddr = "198.51.100.1".parse().unwrap();
    let dst: std::net::IpAddr = "203.0.113.10".parse().unwrap();

    // In-range ports translate the destination (port preserved, pool_port=0).
    for port in [20000u16, 25000, 30000] {
        let decision = table.lookup(PROTO_TCP, src, dst, port, "untrust");
        assert_eq!(
            decision,
            Some(NatDecision {
                rewrite_dst: Some("192.168.1.10".parse().unwrap()),
                ..NatDecision::default()
            }),
            "in-range dport {port} must DNAT to the pool"
        );
    }

    // Out-of-range ports must NOT match (the range entry is not a match-any
    // wildcard).
    for port in [19999u16, 30001, 80] {
        assert!(
            table.lookup(PROTO_TCP, src, dst, port, "untrust").is_none(),
            "out-of-range dport {port} must NOT match the [20000,30000] range entry"
        );
    }
}
