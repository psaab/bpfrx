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
            off: false,
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

// #3830: `clear` of the per-rule NAT hit counters (`NatCounterStore::clear` ->
// `NatRuleCounter::reset`) must not WIPE a per-flow increment recorded in the
// same instant as the clear. `reset` observes the pre-clear total, then
// `fetch_sub`s exactly that amount instead of `store(0)`, so a concurrent
// post-clear cold-path `add` survives — both are atomic RMWs on the same
// location and serialize in the modification order (no lost update). Mirrors
// the #3782 `PolicyRuleCounter` fix; narrower here (per-flow cold-path
// increment, no coalescer/generation to fence).
//
// Drives the reset/increment interleaving deterministically through the real
// subtraction seam (`subtract_observed`): a live two-thread race would be
// non-deterministic. RED-on-revert: restoring `packets.store(0)` /
// `bytes.store(0)` in `subtract_observed` (or collapsing `reset` back to
// `store(0)`) wipes the concurrent post-clear increment (1 -> 0) and fails
// the packet/byte assertions.
#[test]
fn nat_counter_clear_preserves_concurrent_post_clear_hit_3830() {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    let counter = Arc::new(NatRuleCounter::default());

    // Pre-clear traffic already folded into the shared atomics: 100 translated
    // flows, 64 bytes on each trigger packet (the per-flow semantic).
    for _ in 0..100 {
        counter.add(64);
    }

    // === reset() stage 1: OBSERVE the pre-clear totals — exactly what reset()
    // reads before its subtraction. ===
    let observed_packets = counter.packets.load(Ordering::Relaxed);
    let observed_bytes = counter.bytes.load(Ordering::Relaxed);
    assert_eq!(observed_packets, 100, "observed pre-clear packet total");
    assert_eq!(observed_bytes, 100 * 64, "observed pre-clear byte total");

    // === Concurrent cold-path worker: a LEGITIMATE post-clear translated flow
    // is counted in the window between reset's observation and its
    // subtraction. ===
    counter.add(64);

    // === reset() stage 2: subtract the observed pre-clear amount. fetch_sub
    // removes only the pre-clear 100 pkts / 6400 B; a store(0) here would wipe
    // the counter INCLUDING the concurrent post-clear 1 pkt / 64 B. ===
    counter.subtract_observed(observed_packets, observed_bytes);

    let snap = counter.snapshot(7);
    assert_eq!(
        snap.packets, 1,
        "post-clear NAT hit wiped by clear — a store(0) clobbered the \
         concurrent post-clear increment (#3830)"
    );
    assert_eq!(
        snap.bytes, 64,
        "post-clear NAT bytes wiped by clear (#3830)"
    );
    assert_eq!(snap.counter_id, 7, "snapshot echoes the counter id");
}

// #3830: with NO concurrent increment, a `clear` still zeroes both fields
// exactly (the fetch_sub path is not a regression of the normal clear).
// Exercises the full operator path: `NatCounterStore::clear` -> reset.
#[test]
fn nat_counter_clear_zeroes_when_uncontended_3830() {
    let store = NatCounterStore::default();
    let counter = store.rule_counter(42).expect("non-zero id yields a counter");
    counter.add(64);
    counter.add(1500);
    let before = counter.snapshot(42);
    assert_eq!(before.packets, 2, "two flows counted");
    assert_eq!(before.bytes, 64 + 1500, "byte total accumulated");

    store.clear();

    let after = counter.snapshot(42);
    assert_eq!(after.packets, 0, "clear zeroes packets when uncontended");
    assert_eq!(after.bytes, 0, "clear zeroes bytes when uncontended");
}

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

    // The reservation is visible as an owned translated tuple.
    {
        let live = rules[0].pool_allocator.debug_live();
        assert!(
            live.addr_index_by_translated
                .contains_key(&TranslatedTuple {
                    ip: IpAddr::V4(pool_ip),
                    port: 10000,
                }),
            "synced NAT pool port must be reserved in the local allocator"
        );
    }

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
    {
        let live = rules[0].pool_allocator.debug_live();
        assert!(
            !live
                .addr_index_by_translated
                .contains_key(&TranslatedTuple {
                    ip: IpAddr::V4(pool_ip),
                    port: 10000,
                }),
            "releasing the synced session must free its reserved pool port"
        );
    }

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

    let live = rules[0].pool_allocator.debug_live();
    assert!(
        live.addr_index_by_translated.is_empty(),
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

    let live = rules[0].pool_allocator.debug_live();
    assert!(
        live.addr_index_by_translated.is_empty(),
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

    let live = rules[0].pool_allocator.debug_live();
    assert!(
        live.addr_index_by_translated.is_empty(),
        "a reverse synced entry must not reserve a pool source port"
    );
}
