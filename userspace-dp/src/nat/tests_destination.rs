// Destination NAT (DNAT) lookup / scoping / prefix tests for the nat/ module.
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

// #4074 FAIL-ON-REVERT: an UNSCOPED pool DNAT rule (no `match destination-port`)
// whose pool carries a `port` must NOT attach that port to a port-less ICMP
// flow. `validateDNATPoolStrict` does not require a destination-port, so such a
// rule commits; the snapshot builder emits protocol="" (ANY) + destination_port
// 0 (wildcard) + pool_port=8080, and the ICMP DNAT lookup runs with dst_port 0.
// Pre-gate, `rewrite_dst_port` became `Some(8080)` and the SNAT ICMP-identifier
// rewriter (`apply_nat_icmp_identifier_rewrite`) then corrupted the ICMP Query
// Identifier to 8080, breaking ping through the DNAT rule. The `has_l4_ports`
// gate keeps ICMP DNAT address-only (pre-#4074 behaviour).
//
// Reverting the gate in destination.rs makes `rewrite_dst_port` `Some(8080)` for
// the ICMP lookup, turning the `None` assertion RED. The TCP control (which DOES
// carry an L4 port) still receives the port translation.
#[test]
fn dnat_pooled_port_does_not_translate_icmp_identifier() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            counter_id: 0,
            name: "web".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 0,     // unscoped by destination-port
            protocol: String::new(), // any protocol (matches ICMP)
            pool_address: "10.0.0.5".to_string(),
            pool_port: 8080,
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    // ICMP echo (dst_port 0): the destination address is translated, but the
    // pool port must NOT be attached — ICMP has no L4 port.
    let icmp = table.lookup(
        PROTO_ICMP,
        "198.51.100.1".parse().unwrap(),
        "203.0.113.10".parse().unwrap(),
        0,
        "",
    );
    assert_eq!(
        icmp,
        Some(NatDecision {
            rewrite_dst: Some("10.0.0.5".parse().unwrap()),
            rewrite_dst_port: None,
            ..NatDecision::default()
        }),
        "ICMP DNAT must be address-only — no pooled L4 port on a port-less flow",
    );
    // TCP control: a port-carrying protocol still gets the pool port.
    let tcp = table.lookup(
        PROTO_TCP,
        "198.51.100.1".parse().unwrap(),
        "203.0.113.10".parse().unwrap(),
        80,
        "",
    );
    assert_eq!(
        tcp,
        Some(NatDecision {
            rewrite_dst: Some("10.0.0.5".parse().unwrap()),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        }),
        "TCP DNAT still translates the destination port",
    );
}

// #3844: `then destination-nat off` is a no-translate EXEMPTION. An off entry
// that matches must return NO DNAT decision AND short-circuit later DNAT rules
// for the same destination — a translate rule keyed identically must NOT
// re-translate the exempted flow. Before #3844 the off rule compiled to an
// empty Then and was dropped, so the "exempted" traffic fell through and was
// DNAT'd by the later rule (fail-open).
#[test]
fn dnat_off_exemption_short_circuits_identical_translate_rule() {
    let table = DnatTable::from_snapshots(
        &[
            // The off (exemption) rule is configured FIRST — like the Junos
            // rule order that makes it win. It carries the same destination /
            // protocol / port as the translate rule and NO pool address.
            DestinationNATRuleSnapshot {
                name: "exempt".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 80,
                protocol: "tcp".to_string(),
                off: true,
                ..DestinationNATRuleSnapshot::default()
            },
            // A later translate rule that, without the exemption, WOULD DNAT
            // the same traffic. It must not fire for the exempted flow.
            DestinationNATRuleSnapshot {
                name: "web".to_string(),
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
    // The exemption wins: no DNAT (RED before #3844 — the off rule was dropped
    // as pool-less and only the translate rule survived, returning a rewrite).
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        ),
        None,
        "matched `then destination-nat off` must yield no DNAT"
    );
}

// #3844: an off-only destination must NOT be registered as a firewall-local
// address — it is a real routed host, not a VIP the firewall should proxy-ARP/ND
// for. (A translate rule for the same destination WOULD register it; here the
// only rule is the exemption.)
#[test]
fn dnat_off_exemption_not_local_address() {
    let table = DnatTable::from_snapshots(
        &[
            DestinationNATRuleSnapshot {
                name: "exempt".to_string(),
                destination_address: "203.0.113.10".to_string(),
                protocol: "tcp".to_string(),
                destination_port: 80,
                off: true,
                ..DestinationNATRuleSnapshot::default()
            },
            // A translate rule for a DIFFERENT destination — it must still be a
            // local address, proving the exclusion is off-specific.
            DestinationNATRuleSnapshot {
                name: "web".to_string(),
                destination_address: "203.0.113.20".to_string(),
                protocol: "tcp".to_string(),
                destination_port: 80,
                pool_address: "192.168.1.20".to_string(),
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let locals: Vec<IpAddr> = table.destination_ips().collect();
    assert!(
        !locals.contains(&"203.0.113.10".parse::<IpAddr>().unwrap()),
        "an off-exempted destination must not be a local address; locals={locals:?}"
    );
    assert!(
        locals.contains(&"203.0.113.20".parse::<IpAddr>().unwrap()),
        "a translate destination must still be a local address; locals={locals:?}"
    );
}

// #6025 FAIL-ON-REVERT: a specific `/32 destination-nat off` exemption that
// shadows a BROADER translate prefix must NOT leave the exempt host registered
// as a firewall-local address. The broad translate prefix (`203.0.113.0/24`)
// expands host-by-host into the local set (the #3164 on-segment proxy-ARP
// mechanism); before #6025 that expansion re-registered the exempt `/32`
// (203.0.113.50) even though the exact-host `off` entry correctly WINS the DNAT
// match (exact-host entries are probed before any prefix — see
// `lookup_with_counter_scoped`). The result was a silent blackhole: the exempt
// host wins the match (no translation) but its inbound packets are still
// consumed via LocalDelivery instead of being routed to the real host.
//
// The fix (`destination_ips_scoped`) withdraws a prefix-expanded address when an
// exact-host `off` exemption whose scope is a superset of the registering
// translate slot shadows it. The assertion below proves both halves:
//   - the exempt /32 is NOT local (routed/forwarded, not LocalDelivered) — RED
//     before the fix, because the /24 expansion registered it;
//   - a NON-exempt host under the same /24 is STILL local (the fix is surgical
//     and does not break the common DNAT-to-firewall-VIP delivery).
#[test]
fn dnat_off_exemption_shadowing_broad_translate_prefix_not_local() {
    let table = DnatTable::from_snapshots(
        &[
            // Specific /32 exemption — configured in the same rule-set (same
            // `from zone`) as the broad translate below, the common operator
            // idiom. An exact-host entry always beats the prefix in the lookup.
            DestinationNATRuleSnapshot {
                name: "exempt-host".to_string(),
                destination_address: "203.0.113.50".to_string(),
                protocol: "tcp".to_string(),
                destination_port: 80,
                from_zone: "untrust".to_string(),
                off: true,
                ..DestinationNATRuleSnapshot::default()
            },
            // Broad translate over the whole /24 -> a pool. Its bounded prefix
            // expansion registers every usable host (incl. the exempt .50) as a
            // firewall-local proxy-ARP target.
            DestinationNATRuleSnapshot {
                name: "web-pool".to_string(),
                destination_prefix: "203.0.113.0/24".to_string(),
                protocol: "tcp".to_string(),
                destination_port: 80,
                from_zone: "untrust".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8080,
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );

    // The exempt host wins the DNAT match: no translation (exact-host `off`
    // short-circuits before the /24 prefix). This is the disposition the local
    // set must agree with — routed, not owned.
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.50".parse().unwrap(),
            80,
            "untrust",
        ),
        None,
        "exempt /32 must not be DNAT-translated (the off rule wins the match)"
    );
    // A non-exempt host under the same /24 is still translated.
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "198.51.100.1".parse().unwrap(),
                "203.0.113.51".parse().unwrap(),
                80,
                "untrust",
            )
            .is_some(),
        "a non-exempt host under the /24 must still be DNAT-translated"
    );

    let locals: std::collections::HashSet<IpAddr> = table.destination_ips().collect();
    // The bug: exempt /32 must NOT be a firewall-local address (else it is
    // LocalDelivered instead of routed to the real host).
    assert!(
        !locals.contains(&"203.0.113.50".parse::<IpAddr>().unwrap()),
        "exempt /32 (won by `destination-nat off`) must be routed, not \
         LocalDelivered — it must not be a firewall-local address; locals={locals:?}"
    );
    // Surgical: a non-exempt host in the same /24 IS still local so its DNAT
    // traffic is delivered/translated by the firewall as before.
    assert!(
        locals.contains(&"203.0.113.51".parse::<IpAddr>().unwrap()),
        "a non-exempt host under the translate /24 must remain a firewall-local \
         address; locals={locals:?}"
    );
}

// #6025 FAIL-ON-REVERT (negative-scope): a `/32 destination-nat off` that
// shadows the same broad `/24` translate BY DESTINATION IDENTITY but is NOT a
// match-scope superset of it must NOT withdraw the host from the firewall-local
// set. Here the exemption is SOURCE-SCOPED (`match source-address
// 198.51.100.0/24`), so it wins only for that source — every OTHER source is
// still DNAT-translated by the `/24` rule, which means the host genuinely still
// receives translated traffic and MUST stay firewall-local (else the translated
// portion is blackholed by the reverse of #6025). `off_scope_superset` returns
// false for a source-constrained off, so the withdrawal correctly does NOT fire.
//
// This exercises the SCOPE axis that the positive test's `.51`-stays-local
// assertion cannot: `.51` stays local purely because its dst_ip does not equal
// the off's (`off_key.dst_ip == addr` is false), never touching
// `off_scope_superset`. Here the destination identity MATCHES (.50 == .50) and
// only the scope check keeps the host registered.
//
// RED-on-revert: loosen `off_scope_superset` (e.g. change
// `!off.source_constrained` at destination.rs to an always-true term) — the
// source-scoped off is then treated as a superset, `.50` is wrongly withdrawn,
// and the "remains firewall-local" assertion below goes RED. Restore -> GREEN.
#[test]
fn dnat_off_exemption_non_superset_source_scope_stays_local() {
    let table = DnatTable::from_snapshots(
        &[
            // Source-scoped /32 exemption: only exempts sources in
            // 198.51.100.0/24. NOT a scope superset of the unconstrained /24
            // translate below.
            DestinationNATRuleSnapshot {
                name: "exempt-one-source".to_string(),
                destination_address: "203.0.113.50".to_string(),
                protocol: "tcp".to_string(),
                destination_port: 80,
                from_zone: "untrust".to_string(),
                source_addresses: vec!["198.51.100.0/24".to_string()],
                off: true,
                ..DestinationNATRuleSnapshot::default()
            },
            // Broad, source-UNCONSTRAINED translate over the whole /24.
            DestinationNATRuleSnapshot {
                name: "web-pool".to_string(),
                destination_prefix: "203.0.113.0/24".to_string(),
                protocol: "tcp".to_string(),
                destination_port: 80,
                from_zone: "untrust".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8080,
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );

    // For a source INSIDE the exemption's scope, the off wins -> no translation.
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "198.51.100.10".parse().unwrap(),
            "203.0.113.50".parse().unwrap(),
            80,
            "untrust",
        ),
        None,
        "the source-scoped off wins for a source within its scope"
    );
    // For a source OUTSIDE the exemption's scope, `.50` is STILL translated by
    // the broad /24 -> the host genuinely receives translated traffic.
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "192.0.2.1".parse().unwrap(),
                "203.0.113.50".parse().unwrap(),
                80,
                "untrust",
            )
            .is_some(),
        "an out-of-scope source is still DNAT-translated for the same host"
    );

    let locals: std::collections::HashSet<IpAddr> = table.destination_ips().collect();
    // The crux: a NON-superset (source-scoped) off must NOT withdraw the VIP —
    // `.50` still has translated traffic and must remain firewall-local.
    assert!(
        locals.contains(&"203.0.113.50".parse::<IpAddr>().unwrap()),
        "a host shadowed only by a NON-superset (source-scoped) off must remain \
         firewall-local — some traffic to it is still translated; locals={locals:?}"
    );
}

// #6025: v6 analog of the positive withdrawal test — the v6 prefix-expansion
// path applies the same `shadowed` filter. A broad `2001:db8::/120` translate
// with a `2001:db8::50/128 destination-nat off` exemption must withdraw the
// exempt /128 from the firewall-local set while a non-exempt sibling stays.
#[test]
fn dnat_off_exemption_shadowing_broad_translate_prefix_not_local_v6() {
    let table = DnatTable::from_snapshots(
        &[
            DestinationNATRuleSnapshot {
                name: "exempt-host6".to_string(),
                destination_address: "2001:db8::50".to_string(),
                protocol: "tcp".to_string(),
                destination_port: 80,
                from_zone: "untrust".to_string(),
                off: true,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                name: "web-pool6".to_string(),
                destination_prefix: "2001:db8::/120".to_string(),
                protocol: "tcp".to_string(),
                destination_port: 80,
                from_zone: "untrust".to_string(),
                pool_address: "fd00::10".to_string(),
                pool_port: 8080,
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );

    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "2001:db8:1::1".parse().unwrap(),
            "2001:db8::50".parse().unwrap(),
            80,
            "untrust",
        ),
        None,
        "exempt /128 must not be DNAT-translated (the off rule wins the match)"
    );

    let locals: std::collections::HashSet<IpAddr> = table.destination_ips().collect();
    assert!(
        !locals.contains(&"2001:db8::50".parse::<IpAddr>().unwrap()),
        "exempt /128 (won by `destination-nat off`) must be routed, not \
         LocalDelivered; locals={locals:?}"
    );
    assert!(
        locals.contains(&"2001:db8::51".parse::<IpAddr>().unwrap()),
        "a non-exempt /128 under the translate /120 must remain firewall-local; \
         locals={locals:?}"
    );
}

// #3844: a source-scoped exemption — exempt one source subnet from DNAT while
// every other source is still translated by a later (unconstrained) rule. This
// exercises both outcomes and the tier short-circuit across the source axis.
#[test]
fn dnat_off_exemption_source_scoped() {
    let table = DnatTable::from_snapshots(
        &[
            DestinationNATRuleSnapshot {
                name: "exempt-internal".to_string(),
                source_addresses: vec!["198.51.100.0/24".to_string()],
                destination_address: "203.0.113.10".to_string(),
                destination_port: 80,
                protocol: "tcp".to_string(),
                off: true,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                name: "web".to_string(),
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
    // A source in the exempted subnet is NOT translated.
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "198.51.100.5".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        ),
        None,
        "exempted source subnet must not be DNAT'd"
    );
    // A source outside the exempted subnet still gets the translate rule.
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "203.0.113.99".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        ),
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        }),
        "non-exempted source must still be DNAT'd by the later rule"
    );
}

// #3844: an off exemption at the MORE-SPECIFIC (exact-port) tier short-circuits
// a broader wildcard-port translate entry — the tier `.or_else` chain must stop
// at Exempt and never probe the wildcard tier.
#[test]
fn dnat_off_exemption_short_circuits_broader_tier() {
    let table = DnatTable::from_snapshots(
        &[
            // Exact-port off exemption for port 80.
            DestinationNATRuleSnapshot {
                name: "exempt-80".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 80,
                protocol: "tcp".to_string(),
                off: true,
                ..DestinationNATRuleSnapshot::default()
            },
            // Wildcard-port translate for the same destination (any tcp port).
            DestinationNATRuleSnapshot {
                name: "any-port".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 0,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    // Port 80 hits the exact-port off entry first → exempt, no fall-through to
    // the wildcard translate.
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        ),
        None,
        "exact-port exemption must short-circuit the wildcard-port translate"
    );
    // A different port (443) misses the exact-port off entry and is translated
    // by the wildcard-port rule.
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            443,
            "",
        ),
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            ..NatDecision::default()
        }),
        "a non-exempted port must still hit the wildcard-port translate"
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
fn dnat_prefix_zero_length_does_not_register_unspecified_local_v4() {
    // #5658: a `/0` DNAT match prefix is a legitimate "all routed destinations"
    // rule — it must still MATCH routed traffic (the packet-path lookup keys on
    // the destination directly and is independent of the local set). But its
    // canonical network base is the UNSPECIFIED address 0.0.0.0, which is not an
    // owned unicast VIP and must NOT enter the firewall-local / proxy-ARP set.
    //
    // FAIL-ON-REVERT: dropping the `!net.is_unspecified()` guard in
    // destination_ips_scoped re-registers 0.0.0.0 as local → the contains()
    // assertion below RED.
    let row = dnat_row("all", "0.0.0.0", "0.0.0.0/0", "10.0.0.5", 0);
    let table = DnatTable::from_snapshots(&[row], &crate::nat::NatCounterStore::default());
    let ips: std::collections::HashSet<IpAddr> = table.destination_ips().collect();
    assert!(
        !ips.contains(&"0.0.0.0".parse::<IpAddr>().unwrap()),
        "a /0 DNAT prefix must NOT register the unspecified 0.0.0.0 as a local address; ips={ips:?}"
    );
    // The /0 match still translates a routed destination (match is independent
    // of the local set): an arbitrary internet host is DNAT'd to the pool.
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            443,
            "",
        ),
        Some(NatDecision {
            rewrite_dst: Some("10.0.0.5".parse().unwrap()),
            ..NatDecision::default()
        }),
        "a /0 DNAT match must still translate routed traffic"
    );
}

#[test]
fn dnat_prefix_zero_length_does_not_register_unspecified_local_v6() {
    // #5658 IPv6 equivalent: a `::/0` DNAT prefix must not register the
    // unspecified `::` as a local address, but must still match routed v6.
    let row = dnat_row("all6", "::", "::/0", "2001:db8::5", 0);
    let table = DnatTable::from_snapshots(&[row], &crate::nat::NatCounterStore::default());
    let ips: std::collections::HashSet<IpAddr> = table.destination_ips().collect();
    assert!(
        !ips.contains(&"::".parse::<IpAddr>().unwrap()),
        "a ::/0 DNAT prefix must NOT register the unspecified :: as a local address; ips={ips:?}"
    );
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "2001:db8:1::1".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
            443,
            "",
        ),
        Some(NatDecision {
            rewrite_dst: Some("2001:db8::5".parse().unwrap()),
            ..NatDecision::default()
        }),
        "a ::/0 DNAT match must still translate routed v6 traffic"
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

// #4718 FAIL-ON-REVERT: a DNAT batch carrying rules with an UNPARSEABLE
// destination address / pool address must (1) still install the VALID rules
// and (2) SURFACE each drop via the NatCounterStore parse-error counter,
// instead of the pre-#4718 silent `continue`. Reverting `record_parse_error`
// back to a bare `continue` leaves `parse_errors() == 0` → surfacing
// assertion RED.
#[test]
fn dnat_unparseable_field_surfaces_and_keeps_valid_rules() {
    let counters = crate::nat::NatCounterStore::default();
    let table = DnatTable::from_snapshots(
        &[
            // Bad: destination address unparseable (empty-prefix host path).
            DestinationNATRuleSnapshot {
                name: "bad-dest".to_string(),
                destination_address: "not-an-ip".to_string(),
                destination_port: 80,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.99".to_string(),
                pool_port: 8080,
                ..DestinationNATRuleSnapshot::default()
            },
            // Bad: pool address unparseable on a translate (non-off) rule.
            DestinationNATRuleSnapshot {
                name: "bad-pool".to_string(),
                destination_address: "203.0.113.20".to_string(),
                destination_port: 80,
                protocol: "tcp".to_string(),
                pool_address: "garbage".to_string(),
                pool_port: 8080,
                ..DestinationNATRuleSnapshot::default()
            },
            // Valid: must still install despite the malformed siblings.
            DestinationNATRuleSnapshot {
                name: "good".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 80,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8080,
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &counters,
    );
    // (1) The valid rule installed.
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        ),
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        }),
        "valid DNAT rule must install despite sibling parse failures"
    );
    // The bad pool rule (valid destination) must NOT have installed.
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.20".parse().unwrap(),
            80,
            "",
        ),
        None,
        "a DNAT rule with an unparseable pool address must be dropped"
    );
    // (2) Both drops surfaced — RED on the silent-skip revert.
    assert_eq!(
        counters.parse_errors(),
        2,
        "each unparseable DNAT field must bump the parse-error counter"
    );
}

// #4718 guard: an all-valid DNAT batch installs its rule with ZERO parse
// errors — no false positive from the surfacing path.
#[test]
fn dnat_all_valid_reports_no_parse_errors() {
    let counters = crate::nat::NatCounterStore::default();
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "good".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            ..DestinationNATRuleSnapshot::default()
        }],
        &counters,
    );
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "198.51.100.1".parse().unwrap(),
                "203.0.113.10".parse().unwrap(),
                80,
                "",
            )
            .is_some(),
        "the valid rule must install"
    );
    assert_eq!(
        counters.parse_errors(),
        0,
        "an all-valid batch must report zero parse errors"
    );
}

// --- Pool-mode SNAT tests ---


/// #6820: the DNAT `off` exemption is decided by `off` ALONE in Rust — the
/// pool plays no part. The Go builder's `if !isOff` short-circuit
/// (`pkg/dataplane/userspace/nat_destination.go`) CANONICALIZES an exemption
/// entry to an empty pool; it does not decide the precedence, and an earlier
/// revision of the #5628/#5717 gate comments said it did.
///
/// Every other `off: true` fixture in this file also leaves `pool_address`
/// empty — exactly the shape Go emits — so the suite could not tell "Rust
/// ignores the pool" from "Go removed the pool". This one carries BOTH `off`
/// and a usable pool, i.e. the snapshot Go never produces — a hand-built one, or
/// a mixed-version xpfd/helper pair, since `DestinationNATRuleSnapshot` is the
/// xpfd->helper wire form. NOT a "mixed-version peer" (#6820 round 3): HA config
/// sync ships configuration TEXT and the receiver recompiles locally, so a peer
/// never transports a snapshot at all.
///
/// Two arms, because a bare `None` is also what a DROPPED entry returns:
///   - control: the SAME rule with `off: false` must TRANSLATE, proving the
///     match criteria and pool are live;
///   - measurement: with `off: true` and a later broader translate rule
///     present, the lookup must still be `None` — an entry that was dropped
///     rather than installed would let the later rule translate.
///
/// Measured under the killing edit `to_outcome`'s `if self.off` -> `if false`:
/// the measurement arm goes RED with
/// `Some(rewrite_dst: 0.0.0.0, rewrite_dst_port: 8080)`. The `0.0.0.0` is the
/// second half of the answer — `from_snapshots` also refuses to parse an `off`
/// entry's pool ADDRESS, substituting the placeholder. So Rust drops the pool
/// at two independent points, both keyed on `off` and neither on anything Go
/// did; the pool PORT survives into the entry and is simply never read. Note
/// this is why the narrower edit "exempt only when the pool is also empty"
/// would NOT discriminate: the address is already the placeholder by then.
#[test]
fn dnat_off_exemption_is_decided_by_off_not_by_an_empty_pool_6820() {
    let exempt_rule_with_pool = |off: bool| DestinationNATRuleSnapshot {
        name: "exempt-with-pool".to_string(),
        destination_address: "203.0.113.10".to_string(),
        destination_port: 80,
        protocol: "tcp".to_string(),
        off,
        // The Go canonicalization is bypassed by construction: an `off` rule
        // that nevertheless carries a fully usable pool.
        pool_address: "192.168.1.10".to_string(),
        pool_port: 8080,
        ..DestinationNATRuleSnapshot::default()
    };
    // A later, broader rule that WOULD translate this flow to a DIFFERENT pool
    // if the exemption entry were dropped instead of installed.
    let later_broader = DestinationNATRuleSnapshot {
        name: "catch-all".to_string(),
        destination_address: "203.0.113.10".to_string(),
        destination_port: 80,
        protocol: "tcp".to_string(),
        pool_address: "192.168.99.99".to_string(),
        pool_port: 9999,
        ..DestinationNATRuleSnapshot::default()
    };
    let lookup = |rules: &[DestinationNATRuleSnapshot]| {
        DnatTable::from_snapshots(rules, &crate::nat::NatCounterStore::default()).lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            "",
        )
    };

    // CONTROL: same rule, `off` cleared. The pool must be honoured — this is
    // what proves the fixture's match criteria are live and its pool usable,
    // so the measurement arm's `None` cannot be a silently dropped entry.
    assert_eq!(
        lookup(&[exempt_rule_with_pool(false)]),
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        }),
        "control: with `off` cleared the SAME rule must translate to its pool — \
         if it does not, the measurement arm below proves nothing"
    );

    // MEASUREMENT: `off` set, pool still populated, later broader rule present.
    // Exemption, and NOT the later rule's 192.168.99.99 — so the entry was
    // installed, matched, and short-circuited while ignoring its own pool.
    assert_eq!(
        lookup(&[exempt_rule_with_pool(true), later_broader]),
        None,
        "a DNAT `off` rule carrying a pool must still EXEMPT: Rust keys the \
         exemption on `off` alone. ANY rewrite here means it no longer does — \
         192.168.99.99 specifically would mean the off entry was dropped \
         rather than installed and the later broader rule won"
    );
}
