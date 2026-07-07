// Tests for the nat/ module. Moved into nat/tests.rs as part of the
// #1542 split. White-box tests reach into allocator internals via the
// `debug_live()` accessor and the `pub(super)` items promoted in
// allocator.rs / destination.rs.

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

