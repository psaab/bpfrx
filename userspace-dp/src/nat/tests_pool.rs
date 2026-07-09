// Pool source-NAT, persistent-NAT, allocator, and synced-session
// pool-reservation tests for the nat/ module.
//
// Split out of nat/tests.rs (#4409) as a sibling `#[path]` test module
// loaded from nat/mod.rs. Pure code motion: every #[test] fn and
// test-local helper is moved verbatim.
#![allow(unused_imports)]

use super::allocator::{
    ALLOCATION_GC_BUDGET, DeterministicV4, DeterministicV6, NS_PER_SEC, PersistentLease,
    PersistentSourceKey, PoolAddressFamily, TranslatedTuple, deterministic_indices_v6,
    reverse_deterministic_v4, reverse_deterministic_v6, sticky_pool_index,
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

// #4074 FAIL-ON-REVERT (RFC 5508 §3.1): pool-mode source-NAT applied to an
// ICMP echo/query flow must translate the ICMP Query Identifier — the flow
// parser lifts that id into `src_port` (with `dst_port == 0`), and it is the
// ICMP demux key exactly like a TCP/UDP port. Two internal hosts pinging the
// same target with the SAME id, both hidden behind ONE pool address, must get
// DISTINCT translated ids so their return replies demux (the reverse tuple
// `(pool_addr, id)` no longer collides).
//
// Reverting the source.rs `icmp_query` gate makes ICMP fall through to the
// port-less address-only path (`rewrite_src_port: None`), so BOTH decisions
// carry the untranslated id, the two `is_some()`/distinctness assertions go
// RED, and (in production) the reverse keys collide.
#[test]
fn pool_snat_translates_icmp_query_id_distinct_per_host() {
    for proto in [PROTO_ICMP, PROTO_ICMPV6] {
        let (src_a, src_b, dst): (IpAddr, IpAddr, IpAddr) = if proto == PROTO_ICMP {
            (
                "10.0.1.100".parse().unwrap(),
                "10.0.1.101".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
            )
        } else {
            (
                "2001:db8::100".parse().unwrap(),
                "2001:db8::101".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap(),
            )
        };
        let pool_addr = if proto == PROTO_ICMP {
            "203.0.113.1/32".to_string()
        } else {
            "2001:db8:cafe::1/128".to_string()
        };
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "pool-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec![if proto == PROTO_ICMP {
                "0.0.0.0/0".to_string()
            } else {
                "::/0".to_string()
            }],
            pool_name: "my-pool".to_string(),
            pool_addresses: vec![pool_addr],
            port_low: 1024,
            port_high: 65535,
            ..SourceNATRuleSnapshot::default()
        }]);
        // Both hosts use the SAME ICMP query-id 0x1234 to the SAME target.
        let query_id = 0x1234u16;
        let mut counter = None;
        let da = expect_snat_decision(match_source_nat_result_for_tuple(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src_a,
            dst,
            proto,
            query_id,
            0,
            None,
            None,
            0,
            false,
            // #4088: an identifier-bearing ICMP echo query.
            true,
            &mut counter,
        ));
        let db = expect_snat_decision(match_source_nat_result_for_tuple(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src_b,
            dst,
            proto,
            query_id,
            0,
            None,
            None,
            0,
            false,
            // #4088: an identifier-bearing ICMP echo query.
            true,
            &mut counter,
        ));
        // Both hosts land on the single pool address (overload) ...
        let expected_pool: IpAddr = if proto == PROTO_ICMP {
            "203.0.113.1".parse().unwrap()
        } else {
            "2001:db8:cafe::1".parse().unwrap()
        };
        assert_eq!(da.rewrite_src, Some(expected_pool), "proto {proto}");
        assert_eq!(db.rewrite_src, Some(expected_pool), "proto {proto}");
        // ... and each MUST get a translated query-id from the pool id space.
        let id_a = da
            .rewrite_src_port
            .unwrap_or_else(|| panic!("proto {proto}: host A must get a translated ICMP id"));
        let id_b = db
            .rewrite_src_port
            .unwrap_or_else(|| panic!("proto {proto}: host B must get a translated ICMP id"));
        assert!(id_a >= 1024, "proto {proto}: id {id_a} out of pool range");
        assert!(id_b >= 1024, "proto {proto}: id {id_b} out of pool range");
        // The demux invariant: same pool address + same original id => the
        // translated ids MUST differ (RFC 5508 §3.1 uniqueness).
        assert_ne!(
            id_a, id_b,
            "proto {proto}: two hosts sharing a pool address + query-id must get DISTINCT translated ids",
        );
        assert_eq!(da.rewrite_dst, None, "proto {proto}");
        assert_eq!(da.rewrite_dst_port, None, "proto {proto}");

        // Two pool ids consumed, one per flow.
        let status = source_nat_pool_statuses(&rules);
        assert_eq!(
            status[0].used_ports, 2,
            "proto {proto}: one pool id per ICMP query flow",
        );
    }
}

// #4088 FAIL-ON-REVERT (RFC 5508 §3.1): an ICMP echo whose Query Identifier is
// 0 is a valid, keyable query (the id space is 0..=65535). Pool-mode source-NAT
// must translate it exactly like any other id — two hosts pinging the same
// target with id==0 behind one pool address must get DISTINCT translated ids so
// their replies demux on the reverse tuple (pool_addr, translated_id).
//
// Before #4088 the query gate was `src_port != 0`, so an id==0 query flattened
// to the same `src_port == 0` sentinel a non-query ICMP uses, took the
// address-only path, and both id==0 flows collided on the reverse tuple
// (pool_addr, 0) — the #4074 bug, residual for id==0. Reverting the source.rs
// gate to `src_port != 0` makes `icmp_query` false for id==0, both decisions
// carry `rewrite_src_port: None`, and the `is_some()` / distinctness assertions
// go RED.
//
// The authoritative signal is `icmp_identifier_present` (the last positional
// bool arg), set true here because the frame parser only builds a SessionFlow
// for an identifier-bearing ICMP query — so id==0 is a real id, not "no id".
#[test]
fn pool_snat_translates_icmp_query_id_zero_distinct_per_host() {
    for proto in [PROTO_ICMP, PROTO_ICMPV6] {
        let (src_a, src_b, dst): (IpAddr, IpAddr, IpAddr) = if proto == PROTO_ICMP {
            (
                "10.0.1.100".parse().unwrap(),
                "10.0.1.101".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
            )
        } else {
            (
                "2001:db8::100".parse().unwrap(),
                "2001:db8::101".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap(),
            )
        };
        let pool_addr = if proto == PROTO_ICMP {
            "203.0.113.1/32".to_string()
        } else {
            "2001:db8:cafe::1/128".to_string()
        };
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "pool-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec![if proto == PROTO_ICMP {
                "0.0.0.0/0".to_string()
            } else {
                "::/0".to_string()
            }],
            pool_name: "my-pool".to_string(),
            pool_addresses: vec![pool_addr],
            port_low: 1024,
            port_high: 65535,
            ..SourceNATRuleSnapshot::default()
        }]);
        // Both hosts use the identifier 0 (a valid on-wire ICMP Query id).
        let query_id = 0u16;
        let mut counter = None;
        let da = expect_snat_decision(match_source_nat_result_for_tuple(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src_a,
            dst,
            proto,
            query_id,
            0,
            None,
            None,
            0,
            false,
            // #4088: identifier-bearing echo query — even though id==0.
            true,
            &mut counter,
        ));
        let db = expect_snat_decision(match_source_nat_result_for_tuple(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src_b,
            dst,
            proto,
            query_id,
            0,
            None,
            None,
            0,
            false,
            true,
            &mut counter,
        ));
        let expected_pool: IpAddr = if proto == PROTO_ICMP {
            "203.0.113.1".parse().unwrap()
        } else {
            "2001:db8:cafe::1".parse().unwrap()
        };
        assert_eq!(da.rewrite_src, Some(expected_pool), "proto {proto}");
        assert_eq!(db.rewrite_src, Some(expected_pool), "proto {proto}");
        let id_a = da.rewrite_src_port.unwrap_or_else(|| {
            panic!("proto {proto}: host A id==0 query must get a translated ICMP id")
        });
        let id_b = db.rewrite_src_port.unwrap_or_else(|| {
            panic!("proto {proto}: host B id==0 query must get a translated ICMP id")
        });
        assert!(id_a >= 1024, "proto {proto}: id {id_a} out of pool range");
        assert!(id_b >= 1024, "proto {proto}: id {id_b} out of pool range");
        assert_ne!(
            id_a, id_b,
            "proto {proto}: two id==0 flows sharing a pool address must get DISTINCT translated ids",
        );
        let status = source_nat_pool_statuses(&rules);
        assert_eq!(
            status[0].used_ports, 2,
            "proto {proto}: one pool id per id==0 ICMP query flow",
        );

        // Contrast: WITHOUT the identifier-present signal (a non-query ICMP that
        // also flattens to src_port==0) the same id==0 tuple stays address-only.
        // This pins that the gate is `icmp_identifier_present`, not the id value.
        let mut counter2 = None;
        let non_query = expect_snat_decision(match_source_nat_result_for_tuple(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src_a,
            dst,
            proto,
            query_id,
            0,
            None,
            None,
            0,
            false,
            false,
            &mut counter2,
        ));
        assert_eq!(
            non_query.rewrite_src,
            Some(expected_pool),
            "proto {proto}: address still translated",
        );
        assert_eq!(
            non_query.rewrite_src_port, None,
            "proto {proto}: no identifier present => address-only, no id allocated",
        );
    }
}

// #4074/#4088: a NON-identifier ICMP message (an error / control type, or any
// flow the parser could not lift an id from — no `SessionFlow`, so
// `icmp_identifier_present` is false) keeps the address-only path: the source
// IP is translated but NO id is allocated. This pins that the `icmp_query`
// gate is the identifier-present signal, not "all ICMP" (and, post-#4088, not
// `src_port != 0` either).
#[test]
fn pool_snat_icmp_without_query_id_is_address_only() {
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
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        PROTO_ICMP,
        0, // flowless / non-identifier ICMP
        0,
        None,
        None,
        0,
        false,
        // #4088: no identifier-bearing query → address-only.
        false,
        &mut counter,
    ));
    assert_eq!(d.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert_eq!(
        d.rewrite_src_port, None,
        "a flowless / non-identifier ICMP must NOT allocate a pool id",
    );
    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].used_ports, 0, "no pool id for a flowless ICMP");
}

// #3906 FAIL-ON-REVERT: pool-mode source-NAT with `port no-translation` must
// translate the source ADDRESS but PRESERVE the original source port — for a
// port-carrying protocol (TCP/UDP) it takes the address-only path (pick a pool
// address, leave `rewrite_src_port` unset so the packet rewriter keeps the
// packet's own source port) and consumes NO pool port. Before #3906 the
// `no-translation` token was dropped and the pool PAT-translated the port,
// returning `rewrite_src_port: Some(_)`.
//
// Reverting the source.rs `address_only` inclusion of `rule.no_translation`
// makes the TCP flow fall through to `allocate_translation`, so
// `rewrite_src_port` becomes `Some(_)` and a pool port is consumed — turning
// both the None assertion and the used_ports==0 assertion RED.
#[test]
fn pool_snat_no_translation_preserves_source_port() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-notrans".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        pool_no_translation: true,
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
        false,
        &mut counter,
    ));
    assert_eq!(
        d.rewrite_src,
        Some("203.0.113.1".parse().unwrap()),
        "no-translation must still translate the source ADDRESS to the pool address",
    );
    assert_eq!(
        d.rewrite_src_port, None,
        "no-translation must PRESERVE the source port (leave rewrite_src_port unset) \
         — Some(_) here is the pre-#3906 PAT-anyway bug",
    );
    assert_eq!(d.rewrite_dst, None);
    assert_eq!(d.rewrite_dst_port, None);
    // No pool port may be consumed when the source port is preserved.
    let status = source_nat_pool_statuses(&rules);
    assert_eq!(
        status[0].used_ports, 0,
        "no-translation must NOT allocate a pool port (source port preserved)",
    );
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
        assert!(
            rule.pool_allocator
                .debug_is_port_occupied(lease.addr_index, lease.translated.port),
            "persistent lease port must be occupied on its addr index"
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
    }
    assert_eq!(rules[0].pool_allocator.debug_recycled_ports(0), vec![40000]);
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
#[should_panic(expected = "persistent lease port must be occupied on its addr index")]
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
    // Force the sequential cursor past the range so only the recycle ring is
    // consulted. FIFO queue: pop_front() yields 1025 (collides) first, then
    // 1024 (free). Front-first ordering keeps this exercising the #3047
    // collision-retain path after the #3011 LIFO->FIFO change.
    alloc.debug_set_cursor(0, 2);
    alloc.debug_set_recycled(0, vec![1025, 1024]);
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
    // recycle ring, so once its out-of-band owner clears it is reusable.
    assert!(
        alloc.debug_recycled_ports(0).contains(&1025),
        "collided recycled port must be retained, not discarded (leak)"
    );

    // Prove reusability: clear the out-of-band owner and allocate again — the
    // retained port 1025 must be handed out instead of a spurious exhaustion.
    alloc.debug_clear_owner(0, IpAddr::V4(pool_ip), 1025);
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
    assert_eq!(
        alloc.debug_recycled_ports(0),
        vec![1026, 1024, 1028],
        "freed ports queue in release order (push_back)"
    );

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
        false,
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
        false,
        &mut None,
    );
    assert!(
        matches!(first, SourceNatLookup::Matched(d) if d.rewrite_src_port.is_some()),
        "first fragment must still allocate a pool mapping"
    );
}

// === #2218: per-rule NAT translation hit counters ===

// #4388 FAIL-ON-REVERT: a peer-synced session's translated NAT pool port must
// be RESERVED in the standby's LOCAL source-NAT allocator, so a post-failover
// local allocation cannot hand the SAME (pool_addr, port) to a new flow — two
// sessions colliding on one NAT source tuple (reply mis-delivery / session
// hijack surface).
//
// The standby imports the active node's pre-computed NAT decision but never
// calls `allocate_translation`, so before the fix its allocator had no record
// that (pool_addr, port) was in use and a fresh local flow reused it. Reverting
// `reserve_synced_source_nat_allocation` (or its call site at
// `handle_upsert_synced`) makes the "new flow must NOT get the synced port"
// assertion RED.
#[test]
fn synced_session_reserves_nat_pool_port_4388() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    // 2-port pool [10000, 10001] so a single sequential allocation spends the
    // range and forces the post-release reuse through the recycled queue.
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 10000,
        port_high: 10001,
        ..SourceNATRuleSnapshot::default()
    }]);

    // A peer-synced session the active node translated to (203.0.113.1, 10000).
    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let synced_nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(pool_ip)),
        rewrite_src_port: Some(10000),
        ..NatDecision::default()
    };

    reserve_synced_source_nat_allocation(&rules, &synced_key, synced_nat, false);

    // The reservation is visible as an occupied translated tuple.
    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, 10000),
        "synced NAT pool port must be reserved in the local allocator"
    );

    // A NEW local flow allocates from the same pool: it MUST skip the reserved
    // 10000 and hand out 10001. On revert (no reservation) it returns 10000 —
    // a collision with the still-active synced session.
    let addrs = rules[0].pool_addresses_v4.clone();
    let new_flow = SourceNatFlowKey {
        protocol: 6,
        src_ip: "10.0.61.51".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 40001,
        dst_port: 443,
    };
    let translated = rules[0]
        .pool_allocator
        .allocate_translation(
            new_flow,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            false,
            PersistentNatPermit::TargetHostPort,
            0,
            1_000,
        )
        .expect("the second pool port must be available");
    assert_eq!(
        translated.port, 10001,
        "a post-failover local flow must NOT reuse the synced session's \
         reserved port 10000 (#4388 collision)"
    );

    // Deleting the synced session releases the reservation (mirror of the
    // standby teardown: `handle_delete_synced` / reap call
    // `release_source_nat_allocation`).
    release_source_nat_allocation(&rules, &synced_key, synced_nat, false, 2_000);
    assert!(
        !rules[0].pool_allocator.debug_is_port_occupied(0, 10000),
        "releasing the synced session must free its reserved pool port"
    );

    // Prove reusability: with the sequential range spent (10001 taken above),
    // the next allocation drains the recycled queue and reuses the freed 10000.
    let reuse_flow = SourceNatFlowKey {
        protocol: 6,
        src_ip: "10.0.61.52".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 40002,
        dst_port: 443,
    };
    let reused = rules[0]
        .pool_allocator
        .allocate_translation(
            reuse_flow,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            false,
            PersistentNatPermit::TargetHostPort,
            0,
            3_000,
        )
        .expect("the freed port must be reusable after release");
    assert_eq!(
        reused.port, 10000,
        "the released synced port must be reusable by a later local flow"
    );
}

// #4388: a peer-synced session WITHOUT a source-NAT translation (no
// rewrite_src / rewrite_src_port — plain forwarding, address-only, or `port
// no-translation`) reserves nothing. The allocator stays empty and a new flow
// gets the first pool port.
#[test]
fn synced_session_without_nat_reserves_nothing_4388() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 10000,
        port_high: 10005,
        ..SourceNATRuleSnapshot::default()
    }]);

    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    // No translation carried on the synced decision.
    reserve_synced_source_nat_allocation(&rules, &synced_key, NatDecision::default(), false);

    assert_eq!(
        rules[0].pool_allocator.debug_occupied_count(),
        0,
        "a synced session with no NAT translation must reserve nothing"
    );
}

// #4388: if the synced pool address is not a member of ANY local pool (config
// drift between HA nodes), the reserve is skipped gracefully — no panic,
// nothing reserved on the wrong pool.
#[test]
fn synced_session_foreign_pool_addr_skips_reserve_4388() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 10000,
        port_high: 10005,
        ..SourceNATRuleSnapshot::default()
    }]);

    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    // 198.51.100.9 is NOT in the local pool (config drift).
    let foreign_nat = NatDecision {
        rewrite_src: Some("198.51.100.9".parse().unwrap()),
        rewrite_src_port: Some(10000),
        ..NatDecision::default()
    };
    reserve_synced_source_nat_allocation(&rules, &synced_key, foreign_nat, false);

    assert_eq!(
        rules[0].pool_allocator.debug_occupied_count(),
        0,
        "a synced pool address not in any local pool must not reserve anything"
    );
}

// #4388: a peer-synced REVERSE entry carries the destination rewrite, not the
// pool source port, and must reserve nothing (mirrors the is_reverse guard on
// the release path). The forward entry alone owns the pool-port reservation.
#[test]
fn synced_reverse_entry_reserves_nothing_4388() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 10000,
        port_high: 10005,
        ..SourceNATRuleSnapshot::default()
    }]);

    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let synced_nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(pool_ip)),
        rewrite_src_port: Some(10000),
        ..NatDecision::default()
    };
    // is_reverse = true: the reserve is a no-op.
    reserve_synced_source_nat_allocation(&rules, &synced_key, synced_nat, true);

    assert_eq!(
        rules[0].pool_allocator.debug_occupied_count(),
        0,
        "a reverse synced entry must not reserve a pool source port"
    );
}

// #4559 deterministic CGNAT (mode 1, IPv4 subscriber) block allocation.
//
// A deterministic-NAT pool maps each in-range subscriber IPv4 to a FIXED
// external pool address + port block, computed purely from the subscriber's
// internal address (no per-flow state). The mapping is reversible: from the
// translated (external IP, port) alone the CGN operator recovers the subscriber
// IP for lawful-intercept / audit WITHOUT per-connection logs — the whole point
// of deterministic NAT.
//
// RED-ON-REVERT: revert the source.rs deterministic branch (so a deterministic
// pool falls through to `allocate_translation` round-robin) and:
//   - the first allocation lands at the round-robin cursor start (port_low =
//     1024), NOT in subscriber A's computed block [3584, 4095] -> the
//     "port in block" assertions turn RED;
//   - `rules[0].deterministic_v4` becomes `None` (revert the source.rs parse
//     wiring) -> the gating assertion turns RED;
//   - the two subscribers no longer land on their deterministic external
//     addresses / blocks -> the reverse-mapping assertions turn RED.
#[test]
fn deterministic_cgnat_v4_fixed_block_per_subscriber_reversible() {
    // Pool of 4 external addresses, port range 1024..=65535 (64512 ports).
    // block_size 512 -> blocks_per_ip = 126. Host CIDR 100.64.0.0/22 ->
    // host_count 1024 (a /22).
    let pool = [
        Ipv4Addr::new(203, 0, 113, 1),
        Ipv4Addr::new(203, 0, 113, 2),
        Ipv4Addr::new(203, 0, 113, 3),
        Ipv4Addr::new(203, 0, 113, 4),
    ];
    let host_base = u32::from(Ipv4Addr::new(100, 64, 0, 0));
    let det = DeterministicV4 {
        block_size: 512,
        blocks_per_ip: 126,
        host_base,
        host_count: 1024,
    };
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "cgnat".to_string(),
        from_zone: "subs".to_string(),
        to_zone: "inet".to_string(),
        source_addresses: vec!["100.64.0.0/22".to_string()],
        pool_name: "cgn-pool".to_string(),
        pool_addresses: pool.iter().map(|a| format!("{a}/32")).collect(),
        port_low: 1024,
        port_high: 65535,
        deterministic_mode: 1,
        deterministic_block_size: 512,
        deterministic_blocks_per_ip: 126,
        deterministic_host_base: host_base,
        deterministic_host_count: 1024,
        ..SourceNATRuleSnapshot::default()
    }]);
    // Gating: a mode-1 IPv4 deterministic snapshot builds a deterministic rule.
    assert!(
        rules[0].deterministic_v4.is_some(),
        "mode-1 IPv4 deterministic snapshot must build a deterministic rule"
    );

    let alloc = |src: &str, dst: &str, sport: u16| -> (Ipv4Addr, u16) {
        let mut counter = None;
        let d = expect_snat_decision(match_source_nat_result_for_tuple(
            &rules,
            &NatScopeCtx::default(),
            "subs",
            "inet",
            src.parse().expect("src"),
            dst.parse().expect("dst"),
            PROTO_TCP,
            sport,
            443,
            None,
            None,
            0,
            false,
            false,
            &mut counter,
        ));
        let ip = match d.rewrite_src.expect("rewrite_src") {
            IpAddr::V4(v4) => v4,
            other => panic!("expected v4 pool address, got {other}"),
        };
        (ip, d.rewrite_src_port.expect("deterministic PAT must allocate a port"))
    };

    // Subscriber A = 100.64.0.5 -> sub_idx 5, ip_idx 0, block_idx 5,
    // block [1024 + 5*512, ..+511] = [3584, 4095], external pool[0].
    let (a_ip, a_port) = alloc("100.64.0.5", "8.8.8.8", 10001);
    assert_eq!(a_ip, pool[0], "subscriber A must map to its deterministic pool IP");
    assert!(
        (3584..=4095).contains(&a_port),
        "subscriber A port {a_port} must fall in its deterministic block [3584,4095]"
    );

    // Same subscriber, a DIFFERENT flow (new remote) -> SAME external IP and the
    // SAME block; a distinct free port inside the block (collision-free).
    let (a2_ip, a2_port) = alloc("100.64.0.5", "9.9.9.9", 10002);
    assert_eq!(a2_ip, pool[0], "same subscriber must keep the same deterministic IP");
    assert!(
        (3584..=4095).contains(&a2_port),
        "same subscriber's second flow port {a2_port} must stay in block [3584,4095]"
    );
    assert_ne!(a_port, a2_port, "two live flows in one block must get distinct ports");

    // Reverse: (external IP, port) -> subscriber, no per-flow state.
    assert_eq!(
        reverse_deterministic_v4(&det, &pool, 1024, a_ip, a_port),
        Some(Ipv4Addr::new(100, 64, 0, 5)),
        "reverse must recover subscriber A from (external IP, port) alone"
    );
    assert_eq!(
        reverse_deterministic_v4(&det, &pool, 1024, a2_ip, a2_port),
        Some(Ipv4Addr::new(100, 64, 0, 5)),
        "the second flow reverses to the same subscriber A"
    );

    // Subscriber B = 100.64.1.0 -> sub_idx 256, ip_idx 2, block_idx 4,
    // block [1024 + 4*512, ..+511] = [3072, 3583], external pool[2].
    let (b_ip, b_port) = alloc("100.64.1.0", "8.8.8.8", 20001);
    assert_eq!(b_ip, pool[2], "subscriber B must map to a DIFFERENT deterministic pool IP");
    assert!(
        (3072..=3583).contains(&b_port),
        "subscriber B port {b_port} must fall in its deterministic block [3072,3583]"
    );
    assert_eq!(
        reverse_deterministic_v4(&det, &pool, 1024, b_ip, b_port),
        Some(Ipv4Addr::new(100, 64, 1, 0)),
        "reverse must recover subscriber B"
    );
}

// #4559 companion: a pool WITHOUT the deterministic mode is unchanged — it
// builds a non-deterministic rule (`deterministic_v4 == None`) and round-robins
// as before. Guards the gate so the deterministic path never engages for a
// plain source-NAT pool.
#[test]
fn deterministic_cgnat_absent_leaves_round_robin_pool_unchanged() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "plain".to_string(),
        from_zone: "subs".to_string(),
        to_zone: "inet".to_string(),
        source_addresses: vec!["100.64.0.0/22".to_string()],
        pool_name: "plain-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string(), "203.0.113.2/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        // No deterministic_* fields.
        ..SourceNATRuleSnapshot::default()
    }]);
    assert!(
        rules[0].deterministic_v4.is_none(),
        "a pool without `port deterministic` must not build a deterministic rule"
    );
    let mut counter = None;
    let d = expect_snat_decision(match_source_nat_result_for_tuple(
        &rules,
        &NatScopeCtx::default(),
        "subs",
        "inet",
        "100.64.0.5".parse().expect("src"),
        "8.8.8.8".parse().expect("dst"),
        PROTO_TCP,
        10001,
        443,
        None,
        None,
        0,
        false,
        false,
        &mut counter,
    ));
    // Round-robin allocator hands out the cursor-start port (port_low), which is
    // NOT subscriber A's deterministic block — confirming the deterministic path
    // did not engage.
    assert_eq!(
        d.rewrite_src_port,
        Some(1024),
        "a non-deterministic pool allocates from the round-robin cursor (port_low)"
    );
}

// #4559 mode-2 (NAPT64) RED-on-revert: an IPv6 subscriber deterministically maps
// to a FIXED external IPv4 + port block computed from the 32-bit word after the
// configured prefix, reversible from (external IPv4, port) with no per-flow
// state. Neutralizing `allocate_deterministic_v6` / `deterministic_indices_v6`
// (e.g. reverting to the round-robin `allocate_nat64_pool_port`) turns this RED:
// the external IP / port would no longer be the subscriber's computed block and
// the reverse would not recover the subscriber. Mirrors the mode-1 IPv4 test's
// block math (sub_idx 5 and 256) so the two paths cross-check.
#[test]
fn deterministic_napt64_v6_fixed_block_per_subscriber_reversible() {
    let pool = [
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 2),
        Ipv4Addr::new(198, 51, 100, 3),
        Ipv4Addr::new(198, 51, 100, 4),
    ];
    // NAT64 fixed translated-port range 1024..=65535 => 64512 ports.
    // block_size 512 => blocks_per_ip 126. host_count = pool.len() * bpi = 504.
    let base: Ipv6Addr = "2001:db8::".parse().unwrap();
    let det = DeterministicV6 {
        block_size: 512,
        blocks_per_ip: 126,
        host_prefix_len: 32,
        host_base: base.octets(),
        host_count: 4 * 126,
    };
    // One shared allocator sized like the NAT64 per-prefix allocator.
    let alloc = PortAllocator::new(pool.len(), 1024, 65535);

    let alloc_for = |src: &str, sport: u16| -> (Ipv4Addr, u16) {
        let flow = SourceNatFlowKey {
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(src.parse().expect("src")),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: sport,
            dst_port: 443,
        };
        let t = alloc
            .allocate_deterministic_v6(flow, &pool, det, src.parse().expect("src"))
            .expect("deterministic v6 allocation");
        match t.ip {
            IpAddr::V4(v4) => (v4, t.port),
            other => panic!("NAT64 pool is always v4, got {other}"),
        }
    };

    // Subscriber A = 2001:db8:0:5:: -> word after /32 = 5 -> sub_idx 5,
    // ip_idx 0, block_idx 5, block [1024+5*512, ..+511] = [3584,4095], pool[0].
    let (a_ip, a_port) = alloc_for("2001:db8:0:5::", 10001);
    assert_eq!(a_ip, pool[0], "subscriber A maps to its deterministic pool IP");
    assert!(
        (3584..=4095).contains(&a_port),
        "subscriber A port {a_port} must fall in its deterministic block [3584,4095]"
    );

    // Same subscriber, a DIFFERENT flow -> SAME external IP + block, distinct port.
    let (a2_ip, a2_port) = alloc_for("2001:db8:0:5::", 10002);
    assert_eq!(a2_ip, pool[0], "same subscriber keeps the same deterministic IP");
    assert!(
        (3584..=4095).contains(&a2_port),
        "same subscriber's second flow port {a2_port} stays in block [3584,4095]"
    );
    assert_ne!(a_port, a2_port, "two live flows in one block get distinct ports");

    // Reverse: (external IPv4, port) -> subscriber prefix, no per-flow state.
    assert_eq!(
        reverse_deterministic_v6(&det, &pool, 1024, a_ip, a_port),
        Some("2001:db8:0:5::".parse().unwrap()),
        "reverse must recover subscriber A from (external IPv4, port) alone"
    );
    assert_eq!(
        reverse_deterministic_v6(&det, &pool, 1024, a2_ip, a2_port),
        Some("2001:db8:0:5::".parse().unwrap()),
        "the second flow reverses to the same subscriber A"
    );

    // Subscriber B = 2001:db8:0:100:: -> word 256 -> sub_idx 256, ip_idx 2,
    // block_idx 4, block [1024+4*512, ..+511] = [3072,3583], pool[2].
    let (b_ip, b_port) = alloc_for("2001:db8:0:100::", 20001);
    assert_eq!(b_ip, pool[2], "subscriber B maps to a DIFFERENT deterministic pool IP");
    assert!(
        (3072..=3583).contains(&b_port),
        "subscriber B port {b_port} must fall in its deterministic block [3072,3583]"
    );
    assert_eq!(
        reverse_deterministic_v6(&det, &pool, 1024, b_ip, b_port),
        Some("2001:db8:0:100::".parse().unwrap()),
        "reverse must recover subscriber B"
    );

    // A subscriber beyond the pool-bounded host_count fails CLOSED (never
    // round-robins). host_count = 504, so sub_idx 504 (word 0x1f8) is one past.
    let over = SourceNatFlowKey {
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6("2001:db8:0:1f8::".parse().unwrap()),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port: 30001,
        dst_port: 443,
    };
    assert!(
        alloc
            .allocate_deterministic_v6(over, &pool, det, "2001:db8:0:1f8::".parse().unwrap())
            .is_err(),
        "a subscriber beyond host_count must fail closed, not round-robin"
    );

    // /64 prefix reads the subscriber word at octet offset 8 (word[2]), not 4.
    let det64 = DeterministicV6 {
        host_prefix_len: 64,
        ..det
    };
    // 2001:db8:0:0:0:7:: -> octets[8..12] = 0x00000007 -> sub_idx 7.
    assert_eq!(
        deterministic_indices_v6(&det64, "2001:db8::7:0:0".parse().unwrap()),
        Some((0, 7)),
        "/64 subscriber index derives from the word after the /64 prefix"
    );
}

// #4863 RED-on-revert: deterministic NAPT64 must reject an IPv6 source that is
// OUTSIDE the configured subscriber prefix even when it shares the same 32-bit
// subscriber word as an in-prefix subscriber. Before the fix, the subscriber
// index was derived from the word alone (no prefix membership check), so an
// out-of-prefix source was accepted, mapped into the in-prefix subscriber's
// fixed block, and reverse-mapped to the WRONG (configured-base) subscriber —
// cross-tenant block assignment + a lying stateless reverse map. Reverting the
// `src_octets[..off] != host_base[..off]` check in `deterministic_indices_v6`
// turns the out-of-prefix asserts below RED (the source wrongly maps to
// Some((0, 5)) / the allocation wrongly succeeds).
#[test]
fn deterministic_napt64_v6_rejects_out_of_prefix_shared_word() {
    let pool = [
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 2),
        Ipv4Addr::new(198, 51, 100, 3),
        Ipv4Addr::new(198, 51, 100, 4),
    ];
    let base: Ipv6Addr = "2001:db8::".parse().unwrap();
    let det = DeterministicV6 {
        block_size: 512,
        blocks_per_ip: 126,
        host_prefix_len: 32,
        host_base: base.octets(),
        host_count: 4 * 126,
    };

    // (a) /32: the in-prefix subscriber 2001:db8:0:5:: -> word 5 -> Some((0, 5)).
    assert_eq!(
        deterministic_indices_v6(&det, "2001:db8:0:5::".parse().unwrap()),
        Some((0, 5)),
        "an in-prefix source keeps mapping to its subscriber block (no regression)"
    );
    // The bug case: 2001:db9:0:5:: shares the subscriber word (octets[4..8] = 5)
    // but the /32 prefix differs (0db9 != 0db8) -> MUST be rejected, not mapped.
    assert_eq!(
        deterministic_indices_v6(&det, "2001:db9:0:5::".parse().unwrap()),
        None,
        "an out-of-prefix source sharing the subscriber word must be rejected"
    );

    // (b) /64: prefix is octets[0..8]. In-prefix 2001:db8::7:0:0 -> word 7.
    let det64 = DeterministicV6 {
        host_prefix_len: 64,
        ..det
    };
    assert_eq!(
        deterministic_indices_v6(&det64, "2001:db8::7:0:0".parse().unwrap()),
        Some((0, 7)),
        "an in-prefix /64 source maps to its subscriber block"
    );
    // 2001:db8:0:1:0:7:: shares octets[8..12] = 7 but the /64 prefix differs
    // (octets[6..8] = 0001 != 0000) -> rejected.
    assert_eq!(
        deterministic_indices_v6(&det64, "2001:db8:0:1:0:7::".parse().unwrap()),
        None,
        "an out-of-prefix /64 source sharing the subscriber word must be rejected"
    );

    // End to end through the allocator: an out-of-prefix source must fail the
    // allocation CLOSED (no external tuple handed out, so no lying reverse
    // map), while the in-prefix source still allocates and reverses correctly.
    let alloc = PortAllocator::new(pool.len(), 1024, 65535);
    let flow_for = |src: &str| SourceNatFlowKey {
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6(src.parse().expect("src")),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port: 40001,
        dst_port: 443,
    };
    assert!(
        alloc
            .allocate_deterministic_v6(
                flow_for("2001:db9:0:5::"),
                &pool,
                det,
                "2001:db9:0:5::".parse().unwrap()
            )
            .is_err(),
        "the out-of-prefix source must not be translated into subscriber 5's block"
    );
    let ok = alloc
        .allocate_deterministic_v6(
            flow_for("2001:db8:0:5::"),
            &pool,
            det,
            "2001:db8:0:5::".parse().unwrap(),
        )
        .expect("the in-prefix source still allocates");
    let ext_ip = match ok.ip {
        IpAddr::V4(v4) => v4,
        other => panic!("NAT64 pool is always v4, got {other}"),
    };
    assert_eq!(ext_ip, pool[0], "in-prefix subscriber 5 maps to pool[0]");
    assert_eq!(
        reverse_deterministic_v6(&det, &pool, 1024, ext_ip, ok.port),
        Some("2001:db8:0:5::".parse().unwrap()),
        "the reverse map recovers the true in-prefix subscriber"
    );
}

// === #2852 Phase 1: lock-free port-claim correctness =====================

// #2852 FAIL-ON-REVERT: with the port claim lock-free (per-address atomic
// occupancy bitmap, CAS is the sole ownership arbiter), M worker threads
// hammering ONE full-capacity pool must hand out each (ip, port) EXACTLY once:
//   - no double-allocation  (distinct == successes: the bit CAS never lets two
//     flows win the same offset), AND
//   - no false exhaustion / no over-cap (successes == capacity: every port is
//     handed out, and never more than capacity — the exact `live_by_flow.len()`
//     cap under the tiny insert mutex, F4, has no M-in-flight overshoot).
// Reverting the CAS-claim to a non-atomic set, or the exact cap to a racy
// pre-claim reserve, turns this RED (duplicates appear, or fewer than capacity
// succeed on a tiny pool near capacity).
#[test]
fn pool_snat_lockfree_concurrent_fill_is_exact_and_collision_free() {
    use std::collections::HashSet;
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    // 1 address, 64 ports => capacity 64, max_tracked_flows 64.
    let alloc = PortAllocator::new(1, 30000, 30063);
    let capacity = 64usize;
    let m = 8usize;
    let attempts_per_thread = 200usize; // 1600 attempts >> 64 capacity

    let results = Arc::new(Mutex::new(Vec::<(IpAddr, u16)>::new()));
    let barrier = Arc::new(Barrier::new(m));
    let mut handles = Vec::new();
    for tid in 0..m {
        let alloc = alloc.clone();
        let results = results.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            let addrs = [pool_ip];
            let mut local = Vec::new();
            barrier.wait();
            for n in 0..attempts_per_thread {
                // Globally-unique 5-tuple per (tid, n).
                let flow = SourceNatFlowKey {
                    protocol: 6,
                    src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, tid as u8, (n & 0xff) as u8)),
                    dst_ip: "8.8.8.8".parse().unwrap(),
                    src_port: 1024 + n as u16,
                    dst_port: 443,
                };
                if let Ok(t) = alloc.allocate_translation(
                    flow,
                    PoolAddressFamily::V4(&addrs),
                    0,
                    false,
                    false,
                    PersistentNatPermit::TargetHostPort,
                    0,
                    1_000,
                ) {
                    local.push((t.ip, t.port));
                }
            }
            results.lock().unwrap().extend(local);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let all = results.lock().unwrap().clone();
    assert_eq!(
        all.len(),
        capacity,
        "exactly capacity allocations must succeed (no false exhaustion, no over-cap)"
    );
    let distinct: HashSet<_> = all.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        capacity,
        "no (ip, port) may be handed to two flows (no double-allocation)"
    );
    for (ip, port) in &all {
        assert_eq!(*ip, IpAddr::V4(pool_ip));
        assert!((30000..=30063).contains(port), "port {port} out of pool range");
    }
    assert_eq!(alloc.debug_occupied_count(), capacity, "every port bit is set");
}

// #2852 FAIL-ON-REVERT: concurrent allocate+release churn must (a) never leak a
// bit, and (b) never hand the SAME (ip, port) to two simultaneously-live flows.
// M threads each allocate a unique flow then immediately release it, on a pool
// with ample headroom (never genuinely exhausted) but small enough that the
// fresh cursor is spent quickly and reuse flows through the recycle ring under
// contention — the exact path where the CAS-arbiter (a set bit cannot be
// re-claimed) matters. A shared live-set records every translated tuple while
// it is live: insert-on-allocate MUST be new (no double-allocation), and the
// tuple is removed BEFORE `release_flow` clears the bit so a legitimate reuse
// by a peer is never a false collision. Reverting the CAS-claim (double-alloc)
// or the bit-clear-on-release (leak / exhaustion) turns this RED.
#[test]
fn pool_snat_lockfree_concurrent_churn_no_double_alloc_no_leak() {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    let pool_ip: Ipv4Addr = "203.0.113.2".parse().unwrap();
    // 2 addresses x 32 ports = 64 capacity; <= 8 concurrent outstanding, so the
    // fresh range is spent almost immediately and reuse hammers the recycle ring.
    let alloc = PortAllocator::new(2, 20000, 20031);
    let addrs2 = [pool_ip, "203.0.113.3".parse().unwrap()];
    let m = 8usize;
    let iters = 6000usize;
    let exhausted = Arc::new(AtomicU64::new(0));
    let live_set = Arc::new(Mutex::new(HashSet::<(IpAddr, u16)>::new()));
    let barrier = Arc::new(Barrier::new(m));
    let mut handles = Vec::new();
    for tid in 0..m {
        let alloc = alloc.clone();
        let exhausted = exhausted.clone();
        let live_set = live_set.clone();
        let barrier = barrier.clone();
        let addrs2 = addrs2;
        handles.push(thread::spawn(move || {
            barrier.wait();
            for it in 0..iters {
                // Unique 5-tuple per (tid, it): tid in bits 20-22, it in low 20.
                let host = 0x0a00_0000u32 | ((tid as u32) << 20) | (it as u32);
                let flow = SourceNatFlowKey {
                    protocol: 6,
                    src_ip: IpAddr::V4(Ipv4Addr::from(host)),
                    dst_ip: "8.8.8.8".parse().unwrap(),
                    src_port: 1024,
                    dst_port: 443,
                };
                match alloc.allocate_translation(
                    flow,
                    PoolAddressFamily::V4(&addrs2),
                    0,
                    false,
                    false,
                    PersistentNatPermit::TargetHostPort,
                    0,
                    1_000,
                ) {
                    Ok(t) => {
                        // No two live flows may hold the same translated tuple:
                        // the occupancy bit was exclusively ours, so the insert
                        // must be new.
                        assert!(
                            live_set.lock().unwrap().insert((t.ip, t.port)),
                            "double-allocation: (ip, port) already held by a live flow"
                        );
                        // Remove from the live-set BEFORE freeing the bit, so a
                        // peer's legitimate reuse of the freed port is not a
                        // false collision.
                        live_set.lock().unwrap().remove(&(t.ip, t.port));
                        assert!(alloc.release_flow(flow, t, 2_000), "release of a live flow");
                    }
                    Err(_) => {
                        exhausted.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        exhausted.load(Ordering::Relaxed),
        0,
        "a pool with 8x headroom must never exhaust under allocate+release churn"
    );
    assert_eq!(
        alloc.debug_occupied_count(),
        0,
        "every allocated port must be freed (no leaked occupancy bit)"
    );
}

// #2852 FAIL-ON-REVERT: releasing a flow clears its occupancy bit so the port
// is reusable. Fill a 2-port pool, confirm the 3rd flow is exhausted, release
// one, and require the next flow to reuse the freed port. Reverting the
// bit-clear (or leaving the port unrecycled) turns the reuse assertion RED.
#[test]
fn pool_snat_release_frees_bit_and_port_is_reusable() {
    let pool_ip: Ipv4Addr = "203.0.113.9".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = PortAllocator::new(1, 50000, 50001); // 2 ports
    let mk = |src_port: u16| SourceNatFlowKey {
        protocol: 6,
        src_ip: "10.0.0.7".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port,
        dst_port: 443,
    };
    let alloc_one = |flow: SourceNatFlowKey| {
        alloc.allocate_translation(
            flow,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            false,
            PersistentNatPermit::TargetHostPort,
            0,
            1_000,
        )
    };

    let t1 = alloc_one(mk(5001)).expect("first port");
    let _t2 = alloc_one(mk(5002)).expect("second port");
    assert_eq!(alloc.debug_occupied_count(), 2);
    assert!(
        alloc_one(mk(5003)).is_err(),
        "a full 2-port pool must exhaust"
    );

    assert!(
        alloc.release_flow(mk(5001), t1, 2_000),
        "release the first flow"
    );
    assert_eq!(
        alloc.debug_occupied_count(),
        1,
        "release must clear the bit"
    );

    let t4 = alloc_one(mk(5004)).expect("freed port must be reusable");
    assert_eq!(
        t4.port, t1.port,
        "the released port must be handed back out"
    );
    assert_eq!(alloc.debug_occupied_count(), 2);
}

// #2852 FAIL-ON-REVERT (F4 exact cap): a tiny pool fills to EXACTLY its capacity
// with no false exhaustion near the boundary, then the next flow exhausts. The
// cap is `live_by_flow.len()` re-checked under the tiny insert mutex, so there
// is no M-in-flight overshoot that would spuriously reject a near-full pool.
#[test]
fn pool_snat_fills_to_exact_capacity_then_exhausts() {
    let pool_ip: Ipv4Addr = "203.0.113.8".parse().unwrap();
    let addrs = [pool_ip];
    let cap: u16 = 16;
    let alloc = PortAllocator::new(1, 40000, 40000 + cap - 1);
    let mut ports = std::collections::HashSet::new();
    for i in 0..cap {
        let flow = SourceNatFlowKey {
            protocol: 6,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8)),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 1024 + i,
            dst_port: 443,
        };
        let t = alloc
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
            .expect("must allocate up to exact capacity without false exhaustion");
        assert!(
            ports.insert(t.port),
            "each allocation up to capacity is a distinct port"
        );
    }
    assert_eq!(ports.len(), cap as usize);
    assert_eq!(alloc.debug_occupied_count(), cap as usize);

    let overflow = SourceNatFlowKey {
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 2048,
        dst_port: 443,
    };
    assert!(
        alloc
            .allocate_translation(
                overflow,
                PoolAddressFamily::V4(&addrs),
                0,
                false,
                false,
                PersistentNatPermit::TargetHostPort,
                0,
                1_000,
            )
            .is_err(),
        "one flow beyond exact capacity must exhaust"
    );
}

// ---------------------------------------------------------------------------
// #4676: chunked opportunistic GC releases the alloc mutex between batches.
//
// Phase-1 (#2852) made the port CLAIM lock-free, but the expiry GC still ran
// under the shared `live` mutex for its whole sweep, lengthening the "tiny"
// insert critical section on the hot allocation path. The chunked sweep now
// collects a bounded batch of expired leases under a SHORT `live` critical
// section, drops the guard, frees the reclaimed ports on the lock-free
// occupancy bitmap, then re-takes `live` for the next batch. These tests pin
// (1) the seam — the sweep acquires `live` more than once, i.e. it releases it
// between batches (RED on revert to a single critical section), (2) reclaim
// correctness — every expired idle lease is reclaimed and its port freed, and
// (3) that active / not-yet-expired leases are spared, plus a concurrency
// stress that a chunked GC racing live allocations never corrupts state.
// ---------------------------------------------------------------------------

/// Install `count` idle, already-expired persistent leases on pool address
/// `addr_index` (one per port starting at `port_low`), with their occupancy
/// bits set and their expiry indexed — exactly the residue the live
/// alloc+release path leaves behind for an idle-but-not-yet-GC'd lease. Lets
/// the chunked GC be driven in isolation.
fn install_expired_idle_leases(
    alloc: &PortAllocator,
    addr_index: usize,
    ip: Ipv4Addr,
    port_low: u16,
    count: u16,
    expires_at_ns: u64,
) {
    {
        let mut live = alloc.debug_live();
        for i in 0..count {
            let port = port_low + i;
            let key = PersistentSourceKey {
                protocol: 6,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, (i & 0xff) as u8)),
                src_port: 40000 + i,
                remote: None,
            };
            live.persistent_by_source.insert(
                key,
                PersistentLease {
                    translated: TranslatedTuple {
                        ip: IpAddr::V4(ip),
                        port,
                    },
                    addr_index,
                    expires_at_ns,
                    timeout_ns: NS_PER_SEC,
                    active_flows: 0,
                    completed_flows: 1,
                    activation_saw_completion: true,
                    activation_previous_expires_at_ns: 0,
                    activation_had_previous_lease: false,
                },
            );
            live.lease_expirations.insert((expires_at_ns, key));
            live.lease_expirations_by_addr[addr_index].insert((expires_at_ns, key));
        }
    }
    for i in 0..count {
        alloc.debug_seed_owner(addr_index, IpAddr::V4(ip), port_low + i);
    }
}

/// (1) The seam: a multi-batch chunked sweep acquires `live` more than once,
/// which (a std `Mutex` being non-reentrant) is direct proof it RELEASED the
/// mutex between batches so a concurrent allocation's insert can slip in.
/// Reverting the chunking to a single critical section collapses the
/// acquisition count to 1 and fails this test.
#[test]
fn pool_snat_gc_chunked_releases_lock_between_batches() {
    let ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let count: u16 = 20; // > GC_CHUNK (8): a budget-20 sweep needs >= 3 batches.
    let alloc = PortAllocator::new(1, 1024, 1024 + count);
    install_expired_idle_leases(&alloc, 0, ip, 1024, count, 500);

    assert_eq!(alloc.debug_occupied_count(), count as usize);
    {
        let live = alloc.debug_live();
        assert_eq!(live.persistent_by_source.len(), count as usize);
        assert_eq!(live.lease_expirations.len(), count as usize);
        assert_eq!(live.lease_expirations_by_addr[0].len(), count as usize);
    }

    // now_ns = 1000 is past every lease's expiry (500).
    let reclaimed = alloc.debug_gc_expired_chunked(1_000, count as usize);

    assert_eq!(
        reclaimed, count as usize,
        "every expired idle lease must be reclaimed"
    );
    assert!(
        alloc.debug_gc_lock_acquisitions() >= 2,
        "chunked GC must acquire `live` more than once (released between batches); got {}",
        alloc.debug_gc_lock_acquisitions()
    );
    // No port left occupied after its lease was removed (no lost-reclaim leak).
    assert_eq!(
        alloc.debug_occupied_count(),
        0,
        "every reclaimed port must be freed on the occupancy bitmap"
    );
    let live = alloc.debug_live();
    assert!(live.persistent_by_source.is_empty());
    assert!(live.lease_expirations.is_empty());
    assert!(live.lease_expirations_by_addr[0].is_empty());
}

/// (2) Correctness: the chunked sweep reclaims ONLY expired idle leases. An
/// active lease (active_flows > 0, absent from the expiry index) and an idle
/// but not-yet-expired lease are both spared — their ports stay occupied and
/// their map entries survive.
#[test]
fn pool_snat_gc_chunked_spares_active_and_unexpired_leases() {
    let ip: Ipv4Addr = "203.0.113.2".parse().unwrap();
    let alloc = PortAllocator::new(1, 1024, 4096);
    // 5 expired idle leases (ports 1024..1029, expiry 500).
    install_expired_idle_leases(&alloc, 0, ip, 1024, 5, 500);

    let active_key = PersistentSourceKey {
        protocol: 6,
        src_ip: "10.1.1.1".parse().unwrap(),
        src_port: 1,
        remote: None,
    };
    let future_key = PersistentSourceKey {
        protocol: 6,
        src_ip: "10.1.1.2".parse().unwrap(),
        src_port: 2,
        remote: None,
    };
    {
        let mut live = alloc.debug_live();
        // Active lease: active_flows = 1, deliberately NOT indexed (active
        // leases never sit in the expiry index — GC must not touch it).
        live.persistent_by_source.insert(
            active_key,
            PersistentLease {
                translated: TranslatedTuple {
                    ip: IpAddr::V4(ip),
                    port: 2000,
                },
                addr_index: 0,
                expires_at_ns: 500,
                timeout_ns: NS_PER_SEC,
                active_flows: 1,
                completed_flows: 0,
                activation_saw_completion: false,
                activation_previous_expires_at_ns: 0,
                activation_had_previous_lease: false,
            },
        );
        // Idle but not-yet-expired lease (expiry 10_000, past now=1000).
        live.persistent_by_source.insert(
            future_key,
            PersistentLease {
                translated: TranslatedTuple {
                    ip: IpAddr::V4(ip),
                    port: 2001,
                },
                addr_index: 0,
                expires_at_ns: 10_000,
                timeout_ns: NS_PER_SEC,
                active_flows: 0,
                completed_flows: 1,
                activation_saw_completion: true,
                activation_previous_expires_at_ns: 0,
                activation_had_previous_lease: false,
            },
        );
        live.lease_expirations.insert((10_000, future_key));
        live.lease_expirations_by_addr[0].insert((10_000, future_key));
    }
    alloc.debug_seed_owner(0, IpAddr::V4(ip), 2000);
    alloc.debug_seed_owner(0, IpAddr::V4(ip), 2001);

    // now_ns = 1000: past the 5 expired leases (500) but before the future
    // lease (10_000). The active lease is never reached (not indexed).
    let reclaimed = alloc.debug_gc_expired_chunked(1_000, 64);

    assert_eq!(reclaimed, 5, "only the 5 expired idle leases are reclaimed");
    for p in 1024..1029 {
        assert!(
            !alloc.debug_is_port_occupied(0, p),
            "expired lease port {p} must be freed"
        );
    }
    assert!(
        alloc.debug_is_port_occupied(0, 2000),
        "active lease port must stay occupied (never early-freed)"
    );
    assert!(
        alloc.debug_is_port_occupied(0, 2001),
        "not-yet-expired lease port must stay occupied"
    );
    let live = alloc.debug_live();
    assert!(live.persistent_by_source.contains_key(&active_key));
    assert!(live.persistent_by_source.contains_key(&future_key));
    assert_eq!(live.persistent_by_source.len(), 2);
    assert_eq!(live.lease_expirations.len(), 1);
    assert!(live.lease_expirations.contains(&(10_000, future_key)));
    assert_eq!(live.lease_expirations_by_addr[0].len(), 1);
}

/// (3) Concurrency: many threads drive real persistent + non-persistent
/// allocate/release cycles (so both chunked-GC entry points — the hot alloc
/// path and the periodic release path — race live allocations) on a shared
/// allocator. now_ns advances faster than the lease timeout so GC actively
/// reclaims expired leases DURING the run. Afterwards a single full GC must
/// leave the allocator perfectly consistent: no lease, no occupied port, no
/// stale index entry, no leaked flow — proving a chunked GC racing allocations
/// neither double-frees, misses, nor strands a port.
#[test]
fn pool_snat_gc_chunked_concurrent_alloc_release_stays_consistent() {
    use std::thread;
    let ip: Ipv4Addr = "203.0.113.3".parse().unwrap();
    let alloc = PortAllocator::new(1, 1024, 64000);
    let threads = 4u32;
    let per_thread = 1500u32;

    thread::scope(|s| {
        for t in 0..threads {
            let alloc = alloc.clone();
            s.spawn(move || {
                let addrs = [ip];
                for i in 0..per_thread {
                    // Advance now_ns by 2s/iter (> the 1s min lease timeout) so
                    // leases from earlier iterations are expired and reclaimed
                    // by the concurrent chunked GC as the run proceeds.
                    let now_ns = 1_000_000_000u64 + (i as u64) * 2 * NS_PER_SEC;
                    // Unique source per (t, i) => a distinct flow AND lease key.
                    let src_ip = IpAddr::V4(Ipv4Addr::new(
                        10,
                        t as u8,
                        (i >> 8) as u8,
                        (i & 0xff) as u8,
                    ));
                    let persistent = i % 2 == 0;
                    let flow = SourceNatFlowKey {
                        protocol: 6,
                        src_ip,
                        dst_ip: "8.8.8.8".parse().unwrap(),
                        src_port: 1024 + (i % 60000) as u16,
                        dst_port: 443,
                    };
                    if let Ok(translated) = alloc.allocate_translation(
                        flow,
                        PoolAddressFamily::V4(&addrs),
                        0,
                        false,
                        persistent,
                        PersistentNatPermit::AnyRemoteHost,
                        NS_PER_SEC,
                        now_ns,
                    ) {
                        assert!(
                            alloc.release_flow(flow, translated, now_ns + 1),
                            "release of a just-allocated unique flow must succeed"
                        );
                    }
                }
            });
        }
    });

    // Single-threaded full GC well past every lease's expiry: every idle lease
    // is now reclaimable, and every flow has been released.
    alloc.debug_gc_expired_chunked(u64::MAX / 2, usize::MAX);

    let snap = alloc.snapshot();
    assert_eq!(
        snap.live_flows, 0,
        "all flows released; no live flow may remain"
    );
    assert_eq!(
        snap.persistent_leases, 0,
        "all idle expired leases must be reclaimed by the final GC"
    );
    assert_eq!(
        snap.used_ports, 0,
        "no port may stay occupied once every lease is reclaimed"
    );
    assert_eq!(alloc.debug_occupied_count(), 0);
    let live = alloc.debug_live();
    assert!(live.lease_expirations.is_empty());
    assert!(live.lease_expirations_by_addr[0].is_empty());
}
