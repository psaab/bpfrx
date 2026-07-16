// Source (interface/address-match) NAT tests for the nat/ module.
//
// Split out of nat/tests.rs (#4409) as a sibling `#[path]` test module
// loaded from nat/mod.rs. Pure code motion: every #[test] fn and
// test-local helper is moved verbatim.
#![allow(unused_imports)]

use super::allocator::{
    ALLOCATION_GC_BUDGET, NS_PER_SEC, PersistentLease, PersistentSourceKey, PoolAddressFamily,
    TranslatedTuple, sticky_pool_index,
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

// === #5688: interface SNAT with no same-family egress address must fail CLOSED ===

/// #5688 fail-on-revert: interface-mode SNAT translates the source to the egress
/// interface's OWN address of the PACKET's family. When a v4 packet's egress
/// interface has NO v4 address (only a v6 address here), there is nothing to
/// translate to. Before the fix this returned `Matched` with a `None` rewrite,
/// so the packet was forwarded with its private/internal source UNTRANSLATED —
/// the leak. The fix fails CLOSED: `Unavailable(InterfaceNoEgressAddress)`, which
/// funnels through the same drop / `nat_alloc_fail` disposition a pool-mode
/// allocation failure takes. Reverting to `Matched`-with-`None` makes this panic
/// (the returned lookup is no longer `Unavailable`). Passing a v6 egress address
/// that must NOT be used also proves the RIGHT family is resolved.
#[test]
fn interface_source_nat_no_v4_egress_addr_fails_closed() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let lookup = match_source_nat_result(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        None, // egress interface has NO v4 address
        // a v6 address is present but must NOT be used to translate a v4 packet
        Some("2001:559:8585:80::8".parse().expect("egress v6")),
    );
    match lookup {
        SourceNatLookup::Unavailable(f) => {
            assert_eq!(f.reason, SourceNatFailureReason::InterfaceNoEgressAddress);
        }
        other => panic!(
            "expected Unavailable (fail-closed drop), got {other:?} — a \
             Matched-with-None-rewrite forwards the private source UNTRANSLATED (#5688 leak)"
        ),
    }
}

/// #5688 symmetric v6: a v6 packet whose egress interface has NO v6 address
/// (only a v4 address present, which must NOT be used) fails closed the same
/// way. Independent of the v4 branch — the dual-stack family check is per-packet.
#[test]
fn interface_source_nat_no_v6_egress_addr_fails_closed() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["::/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let lookup = match_source_nat_result(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        // a v4 address is present but must NOT be used to translate a v6 packet
        Some("172.16.80.8".parse().expect("egress v4")),
        None, // egress interface has NO v6 address
    );
    match lookup {
        SourceNatLookup::Unavailable(f) => {
            assert_eq!(f.reason, SourceNatFailureReason::InterfaceNoEgressAddress);
        }
        other => panic!(
            "expected Unavailable (fail-closed drop), got {other:?} — a \
             Matched-with-None-rewrite forwards the private source UNTRANSLATED (#5688 leak)"
        ),
    }
}

/// #5688 no-regression / dual-stack independence: the SAME lookup that fails
/// closed for a family with no egress address still TRANSLATES when the egress
/// interface HAS the packet's family address. A v6 packet is translated to the
/// egress v6 address even though there is ALSO a v4 address present (which is
/// irrelevant to a v6 packet), and vice versa — proving the working case is
/// preserved and the families are resolved independently.
#[test]
fn interface_source_nat_translates_when_same_family_egress_addr_present() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "snat4".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "snat6".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["::/0".to_string()],
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        },
    ]);
    // v4 packet -> egress v4 address (v6 also present but unused).
    let v4 = match_source_nat_result(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress v4")),
        Some("2001:559:8585:80::8".parse().expect("egress v6")),
    );
    assert_eq!(
        v4,
        SourceNatLookup::Matched(NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat v4")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
    // v6 packet -> egress v6 address (v4 also present but unused).
    let v6 = match_source_nat_result(
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress v4")),
        Some("2001:559:8585:80::8".parse().expect("egress v6")),
    );
    assert_eq!(
        v6,
        SourceNatLookup::Matched(NatDecision {
            rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat v6")),
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

// #4718 FAIL-ON-REVERT: a source-NAT rule whose match set contains an
// UNPARSEABLE prefix must (1) still translate via its VALID prefixes and (2)
// SURFACE the dropped prefix via the NatCounterStore parse-error counter,
// instead of the pre-#4718 silent `Err(_) => {}`. Reverting
// `record_parse_error` back to the empty arm leaves `parse_errors() == 0` →
// surfacing assertion RED, while the translation still succeeds (the fix does
// not change the fail-closed match-set behaviour, only makes the drop
// observable).
#[test]
fn source_nat_unparseable_match_prefix_surfaces_and_keeps_valid() {
    let counters = crate::nat::NatCounterStore::default();
    let rules = parse_source_nat_rules_with_previous(
        &[SourceNATRuleSnapshot {
            name: "snat-mixed".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec![
                "garbage".to_string(),      // unparseable — surfaced drop
                "10.0.61.0/24".to_string(), // valid — must still translate
            ],
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        }],
        None,
        &counters,
    );
    // (1) The valid prefix still translates its source.
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
        "valid source-NAT prefix must translate despite a malformed sibling"
    );
    // (2) The malformed prefix was surfaced — RED on the silent-skip revert.
    assert_eq!(
        counters.parse_errors(),
        1,
        "an unparseable source-NAT match prefix must bump the parse-error counter"
    );
}

// #4718 guard: an all-valid source-NAT match set reports ZERO parse errors —
// no false positive from the surfacing path.
#[test]
fn source_nat_all_valid_reports_no_parse_errors() {
    let counters = crate::nat::NatCounterStore::default();
    let _rules = parse_source_nat_rules_with_previous(
        &[SourceNATRuleSnapshot {
            name: "snat-clean".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.61.0/24".to_string(), "10.0.62.5".to_string()],
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        }],
        None,
        &counters,
    );
    assert_eq!(
        counters.parse_errors(),
        0,
        "an all-valid match set must report zero parse errors"
    );
}

