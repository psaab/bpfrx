// Tests for the nat/ module. Moved into nat/tests.rs as part of the
// #1542 split. White-box tests reach into allocator internals via the
// `debug_live()` accessor and the `pub(super)` items promoted in
// allocator.rs / destination.rs.

use super::allocator::{
    ALLOCATION_GC_BUDGET, NS_PER_SEC, PersistentLease, PersistentSourceKey, sticky_pool_index,
};
use super::destination::{PROTO_ANY, PROTO_TCP, PROTO_UDP};
use super::*;
use crate::ip_proto::{PROTO_GRE, PROTO_ICMP, PROTO_ICMPV6};
use crate::{DestinationNATRuleSnapshot, SourceNATRuleSnapshot, StaticNATRuleSnapshot};
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
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
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
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "trust".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
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
            counter_id: 0,
            name: "static-v6".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "2001:db8::1".to_string(),
            internal_ip: "fd00::1".to_string(),
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
            counter_id: 0,
            name: "static-v6".to_string(),
            from_zone: "trust".to_string(),
            external_ip: "2001:db8::1".to_string(),
            internal_ip: "fd00::1".to_string(),
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

#[test]
fn static_nat_zone_mismatch_returns_none_for_dnat() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
        }],
        &crate::nat::NatCounterStore::default(),
    );
    // DNAT from wrong zone should fail
    assert!(
        table
            .match_dnat("203.0.113.10".parse().expect("ext"), "trust")
            .is_none()
    );
    // SNAT does not check from_zone -- internal IP match is sufficient.
    // Traffic from internal host gets SNAT regardless of ingress zone.
    assert!(
        table
            .match_snat("192.168.1.10".parse().expect("int"), "dmz")
            .is_some()
    );
}

#[test]
fn static_nat_empty_zone_matches_any() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            counter_id: 0,
            name: "static-any".to_string(),
            from_zone: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
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
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
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
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
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
                counter_id: 0,
                name: "bad".to_string(),
                from_zone: String::new(),
                external_ip: "not-an-ip".to_string(),
                internal_ip: "192.168.1.10".to_string(),
            },
            StaticNATRuleSnapshot {
                counter_id: 0,
                name: "good".to_string(),
                from_zone: String::new(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
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
                counter_id: 0,
                name: "s1".to_string(),
                from_zone: String::new(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
            },
            StaticNATRuleSnapshot {
                counter_id: 0,
                name: "s2".to_string(),
                from_zone: String::new(),
                external_ip: "203.0.113.20".to_string(),
                internal_ip: "192.168.1.20".to_string(),
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
            counter_id: 0,
            name: "static-cidr".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "203.0.113.5/32".to_string(),
            internal_ip: "10.0.0.5/32".to_string(),
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
        table.match_snat("10.0.0.5".parse().expect("int"), "trust"),
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
            counter_id: 0,
            name: "static-cidr-v6".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "2001:db8::1/128".to_string(),
            internal_ip: "fd00::1/128".to_string(),
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
        table.match_snat("fd00::1".parse().expect("int"), "trust"),
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
                counter_id: 0,
                name: "masked".to_string(),
                from_zone: String::new(),
                external_ip: "203.0.113.5/32".to_string(),
                internal_ip: "10.0.0.5".to_string(),
            },
            StaticNATRuleSnapshot {
                counter_id: 0,
                name: "bare".to_string(),
                from_zone: String::new(),
                external_ip: "203.0.113.6".to_string(),
                internal_ip: "10.0.0.6/32".to_string(),
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
                counter_id: 0,
                name: "bad-mask".to_string(),
                from_zone: String::new(),
                external_ip: bad.to_string(),
                internal_ip: "10.0.0.5".to_string(),
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
    let decision = match_source_nat(
        &rules,
        "lan",
        "wan",
        "10.0.1.100".parse().expect("src"),
        "8.8.8.8".parse().expect("dst"),
        None,
        None,
    );
    let d = decision.expect("should match pool rule");
    assert_eq!(d.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert!(d.rewrite_src_port.is_some());
    let port = d.rewrite_src_port.unwrap();
    assert!(port >= 1024, "port {} out of range", port);
    assert_eq!(d.rewrite_dst, None);
    assert_eq!(d.rewrite_dst_port, None);
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
    PersistentSourceKey {
        protocol: 6,
        src_ip: "10.0.1.100".parse().unwrap(),
        src_port,
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
        assert_eq!(live.recycled_ports_by_addr[0], vec![40000]);
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
            let d = match_source_nat(&rules, "lan", "wan", src, dst, None, None)
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
            name: "static-counted".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            counter_id: 22,
        }],
        &store,
    );
    let (_d, static_counter) = static_tbl
        .match_dnat_with_counter("203.0.113.10".parse().unwrap(), "untrust")
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
            source_addresses: vec![],
            destination_address: "203.0.113.20".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "10.0.0.20".to_string(),
            pool_port: 8443,
        }],
        &store,
    );
    let (_d, dnat_counter) = dnat_tbl
        .lookup_with_counter(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.20".parse().unwrap(),
            443,
            "untrust",
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
