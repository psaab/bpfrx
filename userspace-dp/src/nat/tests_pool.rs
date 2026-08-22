// Pool source-NAT, persistent-NAT, allocator, and synced-session
// pool-reservation tests for the nat/ module.
//
// Split out of nat/tests.rs (#4409) as a sibling `#[path]` test module
// loaded from nat/mod.rs. Pure code motion: every #[test] fn and
// test-local helper is moved verbatim.
#![allow(unused_imports)]

use super::allocator::{
    ALLOCATION_GC_BUDGET, DeterministicV4, DeterministicV6, NS_PER_SEC, PersistentLease,
    PersistentSourceKey, PoolAddressFamily, TranslatedTuple, build_pool_reverse_index,
    deterministic_indices_v4, deterministic_indices_v6, reverse_deterministic_v4,
    reverse_deterministic_v6, sticky_pool_index,
};
use super::source::{
    PersistentNatPermit, SOURCE_NAT_PROTO_ANY, SourceNatFailureReason, SourceNatFlowKey,
};
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
        Some(PROTO_TCP),
        12345,
        443,
        None,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
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
            Some(proto),
            0,
            0,
            None,
            None,
            0,
            false,
            false,
            NatHolder::Untracked,
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
            Some(proto),
            query_id,
            0,
            None,
            None,
            0,
            false,
            // #4088: an identifier-bearing ICMP echo query.
            true,
            NatHolder::Untracked,
            &mut counter,
        ));
        let db = expect_snat_decision(match_source_nat_result_for_tuple(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src_b,
            dst,
            Some(proto),
            query_id,
            0,
            None,
            None,
            0,
            false,
            // #4088: an identifier-bearing ICMP echo query.
            true,
            NatHolder::Untracked,
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
            Some(proto),
            query_id,
            0,
            None,
            None,
            0,
            false,
            // #4088: identifier-bearing echo query — even though id==0.
            true,
            NatHolder::Untracked,
            &mut counter,
        ));
        let db = expect_snat_decision(match_source_nat_result_for_tuple(
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src_b,
            dst,
            Some(proto),
            query_id,
            0,
            None,
            None,
            0,
            false,
            true,
            NatHolder::Untracked,
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
            Some(proto),
            query_id,
            0,
            None,
            None,
            0,
            false,
            false,
            NatHolder::Untracked,
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
        Some(PROTO_ICMP),
        0, // flowless / non-identifier ICMP
        0,
        None,
        None,
        0,
        false,
        // #4088: no identifier-bearing query → address-only.
        false,
        NatHolder::Untracked,
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
        Some(PROTO_TCP),
        12345,
        443,
        None,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
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

// ---------------------------------------------------------------------------
// #5269: address-only occupancy tokens (port no-translation / port-less).
//
// The address-only branch selects a pool address but must ALSO mint an
// occupancy token keyed on the translated REVERSE identity (protocol, pool
// address, PRESERVED source port, remote endpoint), so two internal flows behind
// a one-address pool cannot both receive the SAME public tuple. Before the fix
// the branch minted nothing: a second colliding flow got an identical translated
// tuple the reverse (1:N) index could not disambiguate, stranding / mis-
// delivering the later flow's replies under the first session. A genuinely-
// colliding second flow is now DENIED as exhaustion (mirroring how a full port-
// translating pool behaves and the vSRX address-only capacity limit); a non-
// colliding flow mints its own token and succeeds.
// ---------------------------------------------------------------------------

fn addr_only_lookup(
    rules: &[SourceNatRule],
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    protocol: u8,
) -> SourceNatLookup {
    let mut counter = None;
    match_source_nat_result_for_tuple(
        rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src_ip.parse().expect("src"),
        dst_ip.parse().expect("dst"),
        Some(protocol),
        src_port,
        dst_port,
        None,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    )
}

fn one_address_notrans_rule() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[SourceNATRuleSnapshot {
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
    }])
}

// #5269 FAIL-ON-REVERT: `port no-translation`, ONE rule / ONE pool / ONE
// address. Flow A gets the public tuple AND an occupancy token; the reverse
// index resolves the public tuple to exactly A. Flow B (a different internal
// host, SAME preserved port + SAME remote) would collide on the identical public
// tuple and MUST be denied as exhaustion — not handed the duplicate. Reverting
// the fix (drop the `reserve_address_only` mint) makes B return `Matched` with
// A's rewrite_src and `rewrite_src_port: None` — an unowned duplicate — turning
// the `Unavailable` assertion RED.
#[test]
fn pool_snat_no_translation_collision_denies_second_flow_5269() {
    let rules = one_address_notrans_rule();

    let a = expect_snat_decision(addr_only_lookup(
        &rules,
        "10.0.1.100",
        12345,
        "8.8.8.8",
        443,
        PROTO_TCP,
    ));
    assert_eq!(a.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    // Wire contract (unchanged): the source port is PRESERVED, never rewritten.
    assert_eq!(a.rewrite_src_port, None);

    // The reverse index resolves the public tuple to EXACTLY flow A.
    let flow_a = SourceNatFlowKey {
        protocol: PROTO_TCP,
        src_ip: "10.0.1.100".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 12345,
        dst_port: 443,
    };
    let owners = rules[0].pool_allocator.debug_address_only_owners();
    assert_eq!(owners.len(), 1, "flow A must mint exactly one occupancy token");
    assert_eq!(owners[0].1, flow_a, "reverse index must resolve to flow A");
    assert_eq!(
        owners[0].0.translated_ip,
        "203.0.113.1".parse::<IpAddr>().unwrap()
    );
    assert_eq!(owners[0].0.translated_port, 12345);

    // Flow B: DIFFERENT internal host, SAME preserved port + SAME remote -> SAME
    // public tuple (203.0.113.1:12345 -> 8.8.8.8:443). It must fail closed.
    match addr_only_lookup(&rules, "10.0.1.101", 12345, "8.8.8.8", 443, PROTO_TCP) {
        SourceNatLookup::Unavailable(f) => assert_eq!(
            f.reason,
            SourceNatFailureReason::AllocatorExhausted,
            "colliding address-only flow must fail closed as exhaustion",
        ),
        other => panic!("flow B must be denied (exhaustion), got {other:?}"),
    }

    // The reverse index STILL resolves uniquely to flow A — B minted nothing.
    let owners_after = rules[0].pool_allocator.debug_address_only_owners();
    assert_eq!(owners_after.len(), 1, "denied flow B must not add a token");
    assert_eq!(owners_after[0].1, flow_a);

    // No pool PORT is consumed (address-only tokens are off the port bitmap).
    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].used_ports, 0);
    assert_eq!(status[0].live_flows, 1, "only flow A is tracked");
}

// #5269: the address-only token is freed by the SAME teardown path used for PAT
// ports (`release_source_nat_allocation`), so a colliding identity becomes
// reusable after the first flow tears down — no leak.
#[test]
fn pool_snat_no_translation_token_released_on_teardown_5269() {
    let rules = one_address_notrans_rule();

    let a = expect_snat_decision(addr_only_lookup(
        &rules,
        "10.0.1.100",
        12345,
        "8.8.8.8",
        443,
        PROTO_TCP,
    ));
    assert_eq!(rules[0].pool_allocator.debug_address_only_owners().len(), 1);

    // Tear down flow A. `release_source_nat_allocation` now derives the preserved
    // port from the flow key (the decision left `rewrite_src_port` unset) and
    // clears the reverse-identity token.
    let key_a = session_key_from_src("10.0.1.100", 12345, "8.8.8.8", 443);
    release_source_nat_allocation(&rules, &key_a, a, false, 1);
    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        0,
        "token must be freed on teardown (no leak)",
    );
    assert_eq!(source_nat_pool_statuses(&rules)[0].live_flows, 0);

    // The previously-colliding flow B now succeeds (identity is free again).
    let b = expect_snat_decision(addr_only_lookup(
        &rules,
        "10.0.1.101",
        12345,
        "8.8.8.8",
        443,
        PROTO_TCP,
    ));
    assert_eq!(b.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert_eq!(rules[0].pool_allocator.debug_address_only_owners().len(), 1);
}

// #5269 FAIL-ON-REVERT: two port-less (GRE) flows to a one-address pool. Same
// remote -> indistinguishable reverse identity -> the second is denied as
// exhaustion. Different remote -> distinct reverse identity -> disambiguated and
// admitted. Either way the reverse index is unambiguous. Reverting the mint lets
// the same-remote second flow return `Matched` with the duplicate `(pool_addr)`
// tuple (`rewrite_src_port: None`), turning the `Unavailable` assertion RED.
#[test]
fn pool_snat_portless_gre_collision_and_disambiguation_5269() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-gre".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);

    // Flow A: GRE 10.0.1.100 -> 8.8.8.8 (port-less; src/dst port 0).
    let a = expect_snat_decision(addr_only_lookup(
        &rules,
        "10.0.1.100",
        0,
        "8.8.8.8",
        0,
        PROTO_GRE,
    ));
    assert_eq!(a.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert_eq!(a.rewrite_src_port, None, "port-less flow must not carry a port");
    assert_eq!(rules[0].pool_allocator.debug_address_only_owners().len(), 1);

    // Flow B: GRE from a DIFFERENT host to the SAME remote — indistinguishable on
    // the reverse path -> denied as exhaustion (address-only capacity limit).
    match addr_only_lookup(&rules, "10.0.1.101", 0, "8.8.8.8", 0, PROTO_GRE) {
        SourceNatLookup::Unavailable(f) => {
            assert_eq!(f.reason, SourceNatFailureReason::AllocatorExhausted)
        }
        other => panic!("colliding GRE flow must be denied, got {other:?}"),
    }
    assert_eq!(rules[0].pool_allocator.debug_address_only_owners().len(), 1);

    // Flow C: GRE from a third host to a DIFFERENT remote — reverse identity
    // differs by remote IP -> disambiguated and admitted.
    let c = expect_snat_decision(addr_only_lookup(
        &rules,
        "10.0.1.102",
        0,
        "9.9.9.9",
        0,
        PROTO_GRE,
    ));
    assert_eq!(c.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert_eq!(c.rewrite_src_port, None);

    // Two owners, each keyed by a DISTINCT remote — no two flows share a public
    // reverse tuple, and each identity resolves to exactly one owning flow.
    let owners = rules[0].pool_allocator.debug_address_only_owners();
    assert_eq!(owners.len(), 2, "A (8.8.8.8) and C (9.9.9.9) own distinct identities");
    let mut remotes: Vec<IpAddr> = owners.iter().map(|(k, _)| k.dst_ip).collect();
    remotes.sort();
    assert_eq!(
        remotes,
        vec![
            "8.8.8.8".parse::<IpAddr>().unwrap(),
            "9.9.9.9".parse::<IpAddr>().unwrap()
        ],
    );
    let mut owning_srcs: Vec<IpAddr> = owners.iter().map(|(_, f)| f.src_ip).collect();
    owning_srcs.sort();
    assert_eq!(
        owning_srcs,
        vec![
            "10.0.1.100".parse::<IpAddr>().unwrap(),
            "10.0.1.102".parse::<IpAddr>().unwrap()
        ],
    );
    assert_eq!(source_nat_pool_statuses(&rules)[0].used_ports, 0);
}

// #5687 FAIL-ON-REVERT: a genuine IPv4 protocol 0 (HOPOPT) SNAT flow must be
// treated as a REAL port-less protocol (like GRE/ESP), NOT confused with the
// synthetic "L4 tuple unknown" sentinel that historically also used the value
// 0. It takes the real address-only path and mints a reverse-identity occupancy
// token (`rewrite_src_port: None`, ONE owner keyed on protocol 0), so a second
// HOPOPT flow that would collide on the same public reverse tuple (same pool
// addr + same remote) is DENIED as exhaustion — its reverse translation is
// unambiguous. A HOPOPT flow to a DIFFERENT remote mints a DISTINCT identity and
// is admitted.
//
// Reverting the #5687 sentinel (classify `Some(0)` as tuple_unknown again, e.g.
// `let tuple_unknown = protocol.map_or(true, |p| p == 0)`) sends a real HOPOPT
// down the synthetic round-robin path: it returns `rewrite_src_port: Some(_)`
// and mints NO token, so the colliding second flow wrongly returns `Matched`
// with a duplicate `(pool_addr)` tuple the reverse index cannot disambiguate —
// turning every assertion below RED. The reverse translation for protocol 0 is
// the concrete symptom the issue reports.
#[test]
fn pool_snat_protocol0_hopopt_is_real_address_only_not_unknown_5687() {
    const PROTO_HOPOPT: u8 = 0;
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-hopopt".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);

    // Flow A: HOPOPT 10.0.1.100 -> 8.8.8.8 (port-less; src/dst port 0).
    let a = expect_snat_decision(addr_only_lookup(
        &rules,
        "10.0.1.100",
        0,
        "8.8.8.8",
        0,
        PROTO_HOPOPT,
    ));
    assert_eq!(a.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert_eq!(
        a.rewrite_src_port, None,
        "a real HOPOPT flow is port-less: it must preserve the wire source port \
         (None), NOT take the synthetic tuple-unknown round-robin port path"
    );
    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        1,
        "a real HOPOPT flow must mint a reverse-identity token (the #5687 fix)"
    );

    // Flow B: HOPOPT from a DIFFERENT host to the SAME remote — indistinguishable
    // on the reverse path -> denied as exhaustion. Under the reverted sentinel
    // this wrongly returns Matched (no token was minted).
    match addr_only_lookup(&rules, "10.0.1.101", 0, "8.8.8.8", 0, PROTO_HOPOPT) {
        SourceNatLookup::Unavailable(f) => {
            assert_eq!(f.reason, SourceNatFailureReason::AllocatorExhausted)
        }
        other => panic!("colliding HOPOPT flow must be denied, got {other:?}"),
    }
    assert_eq!(rules[0].pool_allocator.debug_address_only_owners().len(), 1);

    // Flow C: HOPOPT to a DIFFERENT remote — distinct reverse identity -> admitted.
    let c = expect_snat_decision(addr_only_lookup(
        &rules,
        "10.0.1.102",
        0,
        "9.9.9.9",
        0,
        PROTO_HOPOPT,
    ));
    assert_eq!(c.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert_eq!(c.rewrite_src_port, None);

    let owners = rules[0].pool_allocator.debug_address_only_owners();
    assert_eq!(
        owners.len(),
        2,
        "A (8.8.8.8) and C (9.9.9.9) own distinct HOPOPT reverse identities"
    );
    // The reverse index keys on the REAL protocol number 0 — the in-map tuple
    // layout is byte-identical to any other protocol; only the "is unknown?"
    // test changed.
    for (k, _) in owners.iter() {
        assert_eq!(k.protocol, PROTO_HOPOPT, "owner keyed on real protocol 0");
    }
    assert_eq!(source_nat_pool_statuses(&rules)[0].used_ports, 0);
}

// #5687: the disambiguation must cut BOTH ways. The synthetic "tuple unknown"
// caller (the address-only `match_source_nat` wrapper, `protocol == None`) keeps
// its historical synthetic behavior — round-robin port, NO reverse-identity
// token — while a real HOPOPT (`Some(0)`) takes the real address-only path, and
// a normal TCP flow (`Some(6)`) still PATs. This proves a genuinely-unknown
// tuple is still treated as unknown (not confused with protocol 0) and that
// normal-protocol translation is unregressed.
#[test]
fn pool_snat_unknown_tuple_distinct_from_real_hopopt_5687() {
    let make_rules = || {
        parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "pool-mixed".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "my-pool".to_string(),
            pool_addresses: vec!["203.0.113.1/32".to_string()],
            port_low: 1024,
            port_high: 65535,
            ..SourceNATRuleSnapshot::default()
        }])
    };

    // (a) The synthetic address-only wrapper (protocol UNKNOWN / None) keeps its
    // historical behavior: it selects a pool address, hands out a round-robin
    // port, and mints NO reverse-identity token (there is no real reverse flow).
    let ru = make_rules();
    let unknown = match_source_nat(
        &ru,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        None,
        None,
    )
    .expect("an unconstrained pool rule matches the tuple-unknown wrapper");
    assert_eq!(unknown.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert!(
        unknown.rewrite_src_port.is_some(),
        "the tuple-unknown wrapper keeps its historical round-robin port"
    );
    assert_eq!(
        ru[0].pool_allocator.debug_address_only_owners().len(),
        0,
        "the synthetic unknown wrapper must NOT mint a reverse-identity token"
    );

    // (b) A REAL HOPOPT (Some(0)) on the same rule shape takes the real
    // address-only path: it preserves the wire port and DOES mint a token.
    let rh = make_rules();
    let hopopt = expect_snat_decision(addr_only_lookup(&rh, "10.0.1.100", 0, "8.8.8.8", 0, 0));
    assert_eq!(
        hopopt.rewrite_src_port, None,
        "real HOPOPT preserves the wire source port"
    );
    assert_eq!(
        rh[0].pool_allocator.debug_address_only_owners().len(),
        1,
        "real HOPOPT mints a reverse-identity token, unlike the unknown wrapper"
    );

    // (c) No regression for a normal TCP flow: it still PATs — a pool port is
    // allocated and rewritten, and its reverse mapping is flow-keyed (address-
    // only owners stay empty because TCP is not address-only).
    let rt = make_rules();
    let tcp = expect_snat_decision(addr_only_lookup(&rt, "10.0.1.100", 12345, "8.8.8.8", 443, 6));
    assert_eq!(tcp.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert!(
        tcp.rewrite_src_port.is_some(),
        "a normal TCP flow must still allocate a translated port (no regression)"
    );
    assert_eq!(
        rt[0].pool_allocator.debug_address_only_owners().len(),
        0,
        "TCP PAT does not use the address-only owner map"
    );
}

// #5269 (no false exhaustion): distinct preserved ports on a ONE-address pool
// mint distinct reverse identities, so both address-only flows succeed.
#[test]
fn pool_snat_no_translation_distinct_ports_both_succeed_5269() {
    let rules = one_address_notrans_rule();

    let a = expect_snat_decision(addr_only_lookup(
        &rules,
        "10.0.1.100",
        12345,
        "8.8.8.8",
        443,
        PROTO_TCP,
    ));
    let b = expect_snat_decision(addr_only_lookup(
        &rules,
        "10.0.1.100",
        12346,
        "8.8.8.8",
        443,
        PROTO_TCP,
    ));
    assert_eq!(a.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert_eq!(b.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert_eq!(a.rewrite_src_port, None);
    assert_eq!(b.rewrite_src_port, None);

    let owners = rules[0].pool_allocator.debug_address_only_owners();
    assert_eq!(owners.len(), 2, "distinct preserved ports mint distinct tokens");
    let mut ports: Vec<u16> = owners.iter().map(|(k, _)| k.translated_port).collect();
    ports.sort();
    assert_eq!(ports, vec![12345, 12346]);
    assert_eq!(source_nat_pool_statuses(&rules)[0].used_ports, 0);
}

// #5269 (no false exhaustion): a TWO-address pool round-robins two colliding-port
// flows onto DIFFERENT pool addresses, so both address-only flows succeed with
// distinct reverse identities.
#[test]
fn pool_snat_no_translation_two_address_pool_both_succeed_5269() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-notrans2".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string(), "203.0.113.2/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        pool_no_translation: true,
        ..SourceNATRuleSnapshot::default()
    }]);

    // Same preserved port + remote, but round-robin places the two flows on
    // different pool addresses -> distinct identities -> both admitted.
    let a = expect_snat_decision(addr_only_lookup(
        &rules,
        "10.0.1.100",
        12345,
        "8.8.8.8",
        443,
        PROTO_TCP,
    ));
    let b = expect_snat_decision(addr_only_lookup(
        &rules,
        "10.0.1.101",
        12345,
        "8.8.8.8",
        443,
        PROTO_TCP,
    ));
    assert_ne!(
        a.rewrite_src, b.rewrite_src,
        "round-robin must place the two flows on different pool addresses",
    );

    let owners = rules[0].pool_allocator.debug_address_only_owners();
    assert_eq!(owners.len(), 2, "two-address pool mints two distinct tokens");
    let mut ips: Vec<IpAddr> = owners.iter().map(|(k, _)| k.translated_ip).collect();
    ips.sort();
    assert_eq!(
        ips,
        vec![
            "203.0.113.1".parse::<IpAddr>().unwrap(),
            "203.0.113.2".parse::<IpAddr>().unwrap()
        ],
    );
}

// #6226 FAIL-ON-REVERT: the round-robin (non-deterministic, non-persistent)
// address-only branch must probe the WHOLE pool, not single-probe one
// round-robin-chosen address. A 2-address pool [A1,A2], port-less GRE
// (address-only), non-persistent. F1 (S1->R) takes A1 and owns the reverse
// identity (GRE,A1,-,R). F2 (S2->R2, a DIFFERENT remote) advances the SHARED
// round-robin counter so F3 rolls back onto A1. F3 (S3->R, the SAME remote as
// F1) would COLLIDE on A1's reverse identity — but A2 is FREE for remote R, so
// the round-robin loop must place F3 on the free sibling A2 rather than dropping
// it. The shared counter is oblivious to per-remote occupancy, so an unrelated
// flow (F2) advancing it trivially lands F3 on an already-owned address — the
// #6226 false-exhaustion.
//
// Reverting to the single-probe `reserve_address_only(flow, pool_addr)` makes F3
// return `Unavailable(AllocatorExhausted)` -> `expect_snat_decision` panics ->
// RED. This is adjacent to but distinct from the deterministic-CGNAT (#5341) and
// address-only persistent-NAT (#6041) branches, which correctly single-probe.
#[test]
fn address_only_roundrobin_probes_free_sibling_5341adjacent_6226() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-rr".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string(), "203.0.113.2/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);

    let a1: IpAddr = "203.0.113.1".parse().unwrap();
    let a2: IpAddr = "203.0.113.2".parse().unwrap();

    // F1: GRE S1 (10.0.1.100) -> R (8.8.8.8). Round-robin counter 0 -> A1; owns
    // the reverse identity (GRE, A1, port-less, 8.8.8.8).
    let d1 = expect_snat_decision(addr_only_lookup(
        &rules, "10.0.1.100", 0, "8.8.8.8", 0, PROTO_GRE,
    ));
    assert_eq!(d1.rewrite_src, Some(a1), "F1 takes the first pool address A1");
    assert_eq!(d1.rewrite_src_port, None, "port-less GRE preserves the wire port");

    // F2: GRE S2 (10.0.1.101) -> R2 (9.9.9.9), a DIFFERENT remote. Its sole job is
    // to advance the SHARED round-robin counter (1 -> 2) so F3 rolls back onto A1.
    // Distinct remote -> distinct identity -> admitted on A2 without colliding.
    let d2 = expect_snat_decision(addr_only_lookup(
        &rules, "10.0.1.101", 0, "9.9.9.9", 0, PROTO_GRE,
    ));
    assert_eq!(d2.rewrite_src, Some(a2), "F2 advances the counter onto A2");

    // F3: GRE S3 (10.0.1.102) -> R (8.8.8.8), the SAME remote + port-less identity
    // as F1. The round-robin counter (now 2, 2 % 2 == 0) points back at A1, whose
    // reverse identity F1 already owns. The pre-#6226 single probe returns
    // AllocatorExhausted here even though A2 is FREE for remote R; the fix probes
    // the whole pool and maps F3 to the free sibling A2.
    let d3 = expect_snat_decision(addr_only_lookup(
        &rules, "10.0.1.102", 0, "8.8.8.8", 0, PROTO_GRE,
    ));
    assert_eq!(
        d3.rewrite_src,
        Some(a2),
        "F3 must map to the FREE sibling A2, not exhaust on the owned A1",
    );
    assert_ne!(
        d3.rewrite_src, d1.rewrite_src,
        "F3 must not collide onto F1's address A1",
    );
    assert_eq!(d3.rewrite_src_port, None, "port-less GRE preserves the wire port");

    // Three distinct live reverse identities, no false exhaustion, no pool port
    // consumed (address-only tokens are off the port bitmap).
    let owners = rules[0].pool_allocator.debug_address_only_owners();
    assert_eq!(owners.len(), 3, "F1, F2, F3 each own a distinct reverse identity");
    assert_eq!(source_nat_pool_statuses(&rules)[0].used_ports, 0);
    assert_eq!(source_nat_pool_statuses(&rules)[0].live_flows, 3);
}

// ---------------------------------------------------------------------------
// #6041: address-only ("port no-translation") PERSISTENT-NAT leases.
//
// A pool configuring BOTH `persistent-nat` and `port no-translation` now pins a
// public pool ADDRESS across the configured permit scope WITHOUT consuming a
// translated pool port (`reserve_address_only_persistent`). This replaces the
// #5819 fail-closed reject. The per-flow #5269 reverse-identity collision guard
// still applies.
// ---------------------------------------------------------------------------

/// Build a `persistent-nat` + `port no-translation` pool rule. Source scope
/// matches both families so the same helper drives the v4 and v6 tests.
fn notrans_persistent_rules(
    pool_addresses: Vec<&str>,
    permit: &str,
    timeout_secs: i64,
    address_persistent: bool,
) -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "notrans-persist".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
        pool_name: "np-pool".to_string(),
        pool_addresses: pool_addresses.into_iter().map(str::to_string).collect(),
        port_low: 1024,
        port_high: 65535,
        pool_no_translation: true,
        persistent_nat: true,
        persistent_nat_permit: permit.to_string(),
        persistent_nat_inactivity_timeout: timeout_secs,
        address_persistent,
        ..SourceNATRuleSnapshot::default()
    }])
}

fn notrans_persistent_lookup(
    rules: &[SourceNatRule],
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    proto: u8,
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
        Some(proto),
        src_port,
        dst_port,
        None,
        None,
        now_ns,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    )
}

// #6041 FAIL-ON-REVERT: two flows keyed to the SAME address-only persistent
// source (any-remote-host, DIFFERENT remotes) reuse ONE public address even on
// a TWO-address pool with global `address-persistent` OFF. The lease pins the
// address; reverting `reserve_address_only_persistent` to the round-robin
// `reserve_address_only` sends the second flow to the OTHER pool address,
// turning the equality assertion RED.
#[test]
fn notrans_persistent_two_flows_reuse_one_address_6041() {
    let rules = notrans_persistent_rules(
        vec!["203.0.113.1/32", "203.0.113.2/32"],
        "any-remote-host",
        300,
        false, // address-persistent OFF: round-robin would split the addresses
    );
    let now = NS_PER_SEC;
    let a = expect_snat_decision(notrans_persistent_lookup(
        &rules, "10.0.1.100", 40000, "8.8.8.8", 443, PROTO_TCP, now,
    ));
    assert!(a.rewrite_src.is_some());
    assert_eq!(
        a.rewrite_src_port, None,
        "no-translation preserves the source port"
    );

    // SAME local source tuple, DIFFERENT remote endpoint. any-remote-host keys
    // the lease by the local source only -> reuse A's public address.
    let b = expect_snat_decision(notrans_persistent_lookup(
        &rules, "10.0.1.100", 40000, "9.9.9.9", 8080, PROTO_TCP, now,
    ));
    assert_eq!(
        a.rewrite_src, b.rewrite_src,
        "address-only persistent lease must pin ONE public address across the permit scope",
    );
    assert_eq!(b.rewrite_src_port, None);

    {
        let live = rules[0].pool_allocator.debug_live();
        assert_eq!(live.persistent_by_source.len(), 1, "one address-only lease");
        let lease = live.persistent_by_source.values().next().unwrap();
        assert!(lease.address_only, "lease must be flagged address_only");
        assert_eq!(lease.active_flows, 2, "two live flows share the lease");
    }
    assert_eq!(
        source_nat_pool_statuses(&rules)[0].used_ports,
        0,
        "address-only lease consumes no pool port",
    );
    // Two distinct reverse-identity tokens (distinct remotes), same address.
    assert_eq!(rules[0].pool_allocator.debug_address_only_owners().len(), 2);
}

// #6041: releasing the flows decrements the lease refcount; at refcount 0 the
// lease enters the idle expiry window and is reclaimed once the inactivity
// timeout elapses. A NEW flow after reclamation mints a fresh lease — proving
// the address is freed at refcount 0 + timeout, not leaked.
#[test]
fn notrans_persistent_refcount_release_and_expiry_6041() {
    let timeout_secs = 300i64;
    let rules =
        notrans_persistent_rules(vec!["203.0.113.1/32"], "any-remote-host", timeout_secs, false);
    let now = NS_PER_SEC;

    let a = expect_snat_decision(notrans_persistent_lookup(
        &rules, "10.0.1.100", 40000, "8.8.8.8", 443, PROTO_TCP, now,
    ));
    let b = expect_snat_decision(notrans_persistent_lookup(
        &rules, "10.0.1.100", 40000, "9.9.9.9", 80, PROTO_TCP, now,
    ));
    assert_eq!(a.rewrite_src, b.rewrite_src);
    {
        let live = rules[0].pool_allocator.debug_live();
        assert_eq!(
            live.persistent_by_source.values().next().unwrap().active_flows,
            2
        );
    }

    // Release flow A: refcount 2 -> 1, lease stays (address still pinned), its
    // token cleared; an active lease is NOT in the expiry index.
    release_source_nat_allocation(
        &rules,
        &session_key_from_src("10.0.1.100", 40000, "8.8.8.8", 443),
        a,
        false,
        now,
    );
    {
        let live = rules[0].pool_allocator.debug_live();
        let lease = live.persistent_by_source.values().next().unwrap();
        assert_eq!(lease.active_flows, 1, "one flow still live");
        assert_eq!(
            live.lease_expirations.len(),
            0,
            "an active lease is not indexed for expiry"
        );
    }
    assert_eq!(rules[0].pool_allocator.debug_address_only_owners().len(), 1);

    // Release flow B: refcount 1 -> 0, lease goes idle and is indexed for expiry.
    release_source_nat_allocation(
        &rules,
        &session_key_from_src("10.0.1.100", 40000, "9.9.9.9", 80),
        b,
        false,
        now,
    );
    {
        let live = rules[0].pool_allocator.debug_live();
        assert_eq!(
            live.persistent_by_source.len(),
            1,
            "idle lease survives until the inactivity timeout"
        );
        assert_eq!(
            live.persistent_by_source.values().next().unwrap().active_flows,
            0
        );
        assert_eq!(
            live.lease_expirations.len(),
            1,
            "idle lease is indexed for expiry"
        );
    }
    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        0,
        "all reverse-identity tokens freed at refcount 0",
    );
    assert_eq!(source_nat_pool_statuses(&rules)[0].used_ports, 0);

    // After the inactivity window a fresh lookup reclaims the idle lease (GC) and
    // mints a new one for the new source.
    let past = now + (timeout_secs as u64 + 1) * NS_PER_SEC;
    let c = expect_snat_decision(notrans_persistent_lookup(
        &rules, "10.0.2.50", 50000, "8.8.8.8", 443, PROTO_TCP, past,
    ));
    assert!(c.rewrite_src.is_some());
    {
        let live = rules[0].pool_allocator.debug_live();
        assert_eq!(
            live.persistent_by_source.len(),
            1,
            "old idle lease reclaimed; only the fresh lease remains"
        );
        assert_eq!(
            live.persistent_by_source.values().next().unwrap().active_flows,
            1
        );
    }
}

// #6041: the #5269 reverse-identity collision guard still fires under persistent
// leases. Two DIFFERENT internal hosts (distinct lease keys) landing on the SAME
// pool address with the SAME preserved source port + SAME remote produce an
// indistinguishable public reverse tuple -> the second is DENIED as exhaustion.
// Reverting the guard lets host B create a second lease + duplicate token and
// return Matched, turning the Unavailable assertion RED.
#[test]
fn notrans_persistent_collision_guard_denies_conflicting_owner_6041() {
    // One-address pool so both hosts' leases pin the SAME public address.
    let rules = notrans_persistent_rules(vec!["203.0.113.1/32"], "any-remote-host", 300, false);
    let now = NS_PER_SEC;

    let a = expect_snat_decision(notrans_persistent_lookup(
        &rules, "10.0.1.100", 40000, "8.8.8.8", 443, PROTO_TCP, now,
    ));
    assert_eq!(a.rewrite_src, Some("203.0.113.1".parse().unwrap()));

    match notrans_persistent_lookup(&rules, "10.0.1.101", 40000, "8.8.8.8", 443, PROTO_TCP, now) {
        SourceNatLookup::Unavailable(f) => assert_eq!(
            f.reason,
            SourceNatFailureReason::AllocatorExhausted,
            "colliding owner must fail closed as exhaustion",
        ),
        other => panic!("colliding owner must be denied, got {other:?}"),
    }
    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        1,
        "denied host B minted no token",
    );
    {
        let live = rules[0].pool_allocator.debug_live();
        assert_eq!(
            live.persistent_by_source.len(),
            1,
            "denied host B created no lease",
        );
    }
}

// #6041: a second packet of the SAME flow (racing session install) returns the
// same decision and does NOT double-count the lease refcount.
#[test]
fn notrans_persistent_idempotent_reentry_6041() {
    let rules = notrans_persistent_rules(vec!["203.0.113.1/32"], "any-remote-host", 300, false);
    let now = NS_PER_SEC;
    let a1 = expect_snat_decision(notrans_persistent_lookup(
        &rules, "10.0.1.100", 40000, "8.8.8.8", 443, PROTO_TCP, now,
    ));
    let a2 = expect_snat_decision(notrans_persistent_lookup(
        &rules, "10.0.1.100", 40000, "8.8.8.8", 443, PROTO_TCP, now,
    ));
    assert_eq!(a1.rewrite_src, a2.rewrite_src);
    {
        let live = rules[0].pool_allocator.debug_live();
        assert_eq!(
            live.persistent_by_source.values().next().unwrap().active_flows,
            1,
            "re-entry of the same flow must not double-count the refcount",
        );
    }
    assert_eq!(rules[0].pool_allocator.debug_address_only_owners().len(), 1);
}

// #6041: the configured permit scope drives lease keying independent of the
// global address-persistent flag. any-remote-host shares ONE lease across
// remotes; target-host-port keys a DISTINCT lease per remote endpoint.
#[test]
fn notrans_persistent_permit_scope_keying_6041() {
    let now = NS_PER_SEC;
    let any = notrans_persistent_rules(
        vec!["203.0.113.1/32", "203.0.113.2/32"],
        "any-remote-host",
        300,
        false,
    );
    let _ = notrans_persistent_lookup(&any, "10.0.1.100", 40000, "8.8.8.8", 443, PROTO_TCP, now);
    let _ = notrans_persistent_lookup(&any, "10.0.1.100", 40000, "9.9.9.9", 80, PROTO_TCP, now);
    assert_eq!(
        any[0].pool_allocator.debug_live().persistent_by_source.len(),
        1,
        "any-remote-host: one lease shared across remotes",
    );

    let thp = notrans_persistent_rules(
        vec!["203.0.113.1/32", "203.0.113.2/32"],
        "target-host-port",
        300,
        false,
    );
    let _ = notrans_persistent_lookup(&thp, "10.0.1.100", 40000, "8.8.8.8", 443, PROTO_TCP, now);
    let _ = notrans_persistent_lookup(&thp, "10.0.1.100", 40000, "9.9.9.9", 80, PROTO_TCP, now);
    assert_eq!(
        thp[0].pool_allocator.debug_live().persistent_by_source.len(),
        2,
        "target-host-port: distinct lease per remote endpoint",
    );
}

// #6041: IPv6 twin of the core reuse test — an address-only persistent lease
// pins one public v6 address across the permit scope, no port consumed.
#[test]
fn notrans_persistent_ipv6_reuse_one_address_6041() {
    let rules = notrans_persistent_rules(
        vec!["2001:db8::1/128", "2001:db8::2/128"],
        "any-remote-host",
        300,
        false,
    );
    let now = NS_PER_SEC;
    let a = expect_snat_decision(notrans_persistent_lookup(
        &rules,
        "2001:db8:1::100",
        40000,
        "2001:4860::8888",
        443,
        PROTO_TCP,
        now,
    ));
    let b = expect_snat_decision(notrans_persistent_lookup(
        &rules,
        "2001:db8:1::100",
        40000,
        "2001:4860::9999",
        80,
        PROTO_TCP,
        now,
    ));
    assert!(a.rewrite_src.unwrap().is_ipv6());
    assert_eq!(
        a.rewrite_src, b.rewrite_src,
        "v6 address-only persistent lease must pin one public address",
    );
    assert_eq!(a.rewrite_src_port, None);
    {
        let live = rules[0].pool_allocator.debug_live();
        assert_eq!(live.persistent_by_source.len(), 1);
        assert!(live.persistent_by_source.values().next().unwrap().address_only);
    }
    assert_eq!(source_nat_pool_statuses(&rules)[0].used_ports, 0);
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
        Some(6),
        src_port,
        dst_port,
        None,
        None,
        now_ns,
        false,
        false,
        NatHolder::Untracked,
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
        Some(6),
        10000,
        53,
        None,
        None,
        1,
        false,
        false,
        NatHolder::Untracked,
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
        Some(6),
        10001,
        53,
        None,
        None,
        2,
        false,
        false,
        NatHolder::Untracked,
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
        Some(6),
        10000,
        53,
        None,
        None,
        1,
        false,
        false,
        NatHolder::Untracked,
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
        Some(6),
        10001,
        53,
        None,
        None,
        2,
        false,
        false,
        NatHolder::Untracked,
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
            Some(6),
            src_port,
            443,
            None,
            None,
            0,
            false,
            false,
            NatHolder::Untracked,
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
        NatHolder::Untracked,
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
        NatHolder::Untracked,
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
        NatHolder::Untracked,
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
                NatHolder::Untracked,
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
            alloc.release_flow(flow, t, 2_000, NatHolder::Untracked),
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
        Some(6),
        10000,
        53,
        None,
        None,
        1,
        true,
        false,
        NatHolder::Untracked,
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
        Some(6),
        10000,
        53,
        None,
        None,
        1,
        false,
        false,
        NatHolder::Untracked,
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

    reserve_synced_source_nat_allocation(&rules, &synced_key, synced_nat, false, None, 0);

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
            NatHolder::Untracked,
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
            NatHolder::Untracked,
        )
        .expect("the freed port must be reusable after release");
    assert_eq!(
        reused.port, 10000,
        "the released synced port must be reusable by a later local flow"
    );
}

// #5178 FAIL-ON-REVERT: a peer-synced session reserved on a DETERMINISTIC
// CGNAT (mode 1) pool must be tagged deterministic in the standby's local
// allocator, so its RELEASE takes the `free_no_recycle` path (the occupancy bit
// is the only reuse gate) instead of pushing the freed port onto the per-address
// recycle `VecDeque`. The deterministic allocation path never drains that queue
// (#4559), so a mis-tagged reservation leaks one recycle entry per released
// synced flow → unbounded standby memory under synced-session churn.
//
// Before the fix `reserve_flow` hardcoded `deterministic: false`, so the standby
// stored every synced reservation as non-deterministic and recycled it on
// release. Reverting the threaded `deterministic` parameter (hardcoding it back
// to `false`) makes the "deterministic reservation must NOT recycle" assertion
// RED. The non-deterministic control below proves round-robin pools still
// recycle (the fix is not an over-correction that suppresses ALL recycling).
#[test]
fn synced_deterministic_reservation_not_recycled_5178() {
    // --- Deterministic (mode 1) pool: released reservation must NOT recycle. ---
    let det_pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let host_base = u32::from(Ipv4Addr::new(100, 64, 0, 0));
    let det_rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "cgn-pool".to_string(),
        from_zone: "subs".to_string(),
        to_zone: "inet".to_string(),
        source_addresses: vec!["100.64.0.0/22".to_string()],
        pool_name: "cgn-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        deterministic_mode: 1,
        deterministic_block_size: 512,
        deterministic_blocks_per_ip: 126,
        deterministic_host_base: host_base,
        deterministic_host_count: 1024,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert!(
        det_rules[0].deterministic_v4.is_some(),
        "mode-1 snapshot must build a deterministic rule (test precondition)"
    );

    // A peer-synced session the active node translated deterministically:
    // subscriber 100.64.0.5 -> external 203.0.113.1, block [3584, 4095].
    let det_key = session_key_from_src("100.64.0.5", 40000, "8.8.8.8", 443);
    let det_nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(det_pool_ip)),
        rewrite_src_port: Some(3584),
        ..NatDecision::default()
    };
    reserve_synced_source_nat_allocation(&det_rules, &det_key, det_nat, false, None, 0);
    assert!(
        det_rules[0].pool_allocator.debug_is_port_occupied(0, 3584),
        "synced deterministic reservation must occupy its pool port"
    );

    // Standard teardown (reap / delete-sync) releases the reservation.
    release_source_nat_allocation(&det_rules, &det_key, det_nat, false, 2_000);
    assert!(
        !det_rules[0].pool_allocator.debug_is_port_occupied(0, 3584),
        "release must free the deterministic reservation's bit"
    );
    // THE FAIL-ON-REVERT ASSERTION: a deterministic reservation must NOT land in
    // the recycle queue. On revert (hardcoded `deterministic: false`) release
    // recycles the port and this queue is non-empty.
    assert!(
        det_rules[0].pool_allocator.debug_recycled_ports(0).is_empty(),
        "a released deterministic synced reservation must NOT be recycled \
         (free_no_recycle); a non-empty recycle queue is the #5178 leak"
    );

    // --- Non-deterministic (round-robin) pool: release STILL recycles. ---
    let rr_pool_ip: Ipv4Addr = "203.0.113.9".parse().unwrap();
    let rr_rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "rr-pool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "rr-pool".to_string(),
        pool_addresses: vec!["203.0.113.9/32".to_string()],
        port_low: 10000,
        port_high: 10001,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert!(
        rr_rules[0].deterministic_v4.is_none(),
        "a plain pool must NOT be deterministic (test precondition)"
    );
    let rr_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let rr_nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(rr_pool_ip)),
        rewrite_src_port: Some(10000),
        ..NatDecision::default()
    };
    reserve_synced_source_nat_allocation(&rr_rules, &rr_key, rr_nat, false, None, 0);
    release_source_nat_allocation(&rr_rules, &rr_key, rr_nat, false, 2_000);
    // Unchanged by the fix: a round-robin reservation recycles on release so the
    // freed port is reused oldest-first (#3011). This must stay GREEN both before
    // and after #5178 — the fix must not suppress recycling for round-robin pools.
    assert!(
        rr_rules[0]
            .pool_allocator
            .debug_recycled_ports(0)
            .contains(&10000),
        "a non-deterministic synced reservation must STILL recycle on release"
    );
}

// #4388: a peer-synced session WITHOUT any source-NAT translation (no
// `rewrite_src` at all — plain forwarding) reserves nothing. The allocator stays
// empty and a new flow gets the first pool port. (An ADDRESS-ONLY decision —
// `rewrite_src` set, `rewrite_src_port` None — now DOES mint a reverse-identity
// token per #5338; that case is exercised by
// `synced_address_only_session_reserves_reverse_identity_token_5338`.)
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
    reserve_synced_source_nat_allocation(
        &rules,
        &synced_key,
        NatDecision::default(),
        false,
        None,
        0,
    );

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
    reserve_synced_source_nat_allocation(&rules, &synced_key, foreign_nat, false, None, 0);

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
    reserve_synced_source_nat_allocation(&rules, &synced_key, synced_nat, true, None, 0);

    assert_eq!(
        rules[0].pool_allocator.debug_occupied_count(),
        0,
        "a reverse synced entry must not reserve a pool source port"
    );
}

// #5338 FAIL-ON-REVERT: a peer-synced ADDRESS-ONLY source-NAT session (`port
// no-translation` — a pool ADDRESS is chosen but the source port is PRESERVED on
// the wire, so the decision carries `rewrite_src = Some(pool_addr)` but NO
// `rewrite_src_port`) must mint the SAME reverse-identity occupancy token on the
// STANDBY that the active node minted (#5336 round-robin / #5341 deterministic),
// so the reverse (1:N) index can disambiguate the promoted session after
// failover.
//
// Before the fix `reserve_synced_source_nat_allocation` early-returned when
// `rewrite_src_port` was None, so the standby minted NO token: its
// `address_only_owners` map stayed empty and a fresh local address-only flow to
// the SAME public identity was admitted as an UNOWNED duplicate the reverse
// index could not tell apart from the synced session — the exact #5269
// collision class the active node closes. Reverting the address-only arm
// (restoring the `let Some(rewrite_src_port) = nat.rewrite_src_port else {
// return; };` skip) makes the "token minted" + "colliding local flow denied"
// assertions RED.
#[test]
fn synced_address_only_session_reserves_reverse_identity_token_5338() {
    // One-address `port no-translation` pool: address-only, source port preserved.
    let rules = one_address_notrans_rule();

    // A peer-synced ADDRESS-ONLY session: the active node chose pool address
    // 203.0.113.1 and PRESERVED the source port (`rewrite_src_port` None).
    let synced_key = session_key_from_src("10.0.1.100", 12345, "8.8.8.8", 443);
    let synced_nat = NatDecision {
        rewrite_src: Some("203.0.113.1".parse().unwrap()),
        rewrite_src_port: None,
        ..NatDecision::default()
    };

    reserve_synced_source_nat_allocation(&rules, &synced_key, synced_nat, false, None, 0);

    // THE FAIL-ON-REVERT ASSERTION (mint): the standby minted the reverse-
    // identity token for the synced flow. On revert the map is empty.
    let synced_flow = SourceNatFlowKey {
        protocol: PROTO_TCP,
        src_ip: "10.0.1.100".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 12345,
        dst_port: 443,
    };
    let owners = rules[0].pool_allocator.debug_address_only_owners();
    assert_eq!(
        owners.len(),
        1,
        "standby must mint one address-only occupancy token for the synced session"
    );
    assert_eq!(
        owners[0].1, synced_flow,
        "reverse index must resolve to the synced flow"
    );
    assert_eq!(
        owners[0].0.translated_ip,
        "203.0.113.1".parse::<IpAddr>().unwrap()
    );
    // The PRESERVED source port keys the reverse identity.
    assert_eq!(owners[0].0.translated_port, 12345);

    // No pool PORT bit is consumed (address-only tokens are off the port bitmap).
    assert_eq!(
        rules[0].pool_allocator.debug_occupied_count(),
        0,
        "an address-only reservation must not claim a pool-port bit"
    );

    // THE FAIL-ON-REVERT ASSERTION (disambiguation): a fresh LOCAL address-only
    // flow to the SAME public identity (one-address pool forces 203.0.113.1;
    // SAME preserved port + remote) must now be DENIED as exhaustion — the
    // standby already owns that reverse identity from the synced session. On
    // revert it is `Matched` with `rewrite_src_port: None`, an unowned duplicate
    // the reverse index cannot disambiguate from the synced session.
    match addr_only_lookup(&rules, "10.0.1.200", 12345, "8.8.8.8", 443, PROTO_TCP) {
        SourceNatLookup::Unavailable(f) => assert_eq!(
            f.reason,
            SourceNatFailureReason::AllocatorExhausted,
            "a local flow colliding with the synced reverse identity must fail closed",
        ),
        other => panic!("colliding local flow must be denied (exhaustion), got {other:?}"),
    }
    // The synced session STILL owns the identity uniquely — the denied local flow
    // minted nothing.
    let owners_after = rules[0].pool_allocator.debug_address_only_owners();
    assert_eq!(
        owners_after.len(),
        1,
        "denied local flow must not add a token"
    );
    assert_eq!(owners_after[0].1, synced_flow);

    // Teardown of the synced session (standby reap / delete-sync) frees the token
    // via the SAME `release_source_nat_allocation` path — no new delete site.
    release_source_nat_allocation(&rules, &synced_key, synced_nat, false, 1_000);
    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        0,
        "releasing the synced session must free its address-only token (no leak)"
    );
}

// === #6211: synced source-NAT rule identity under OVERLAPPING pool addresses ===

/// #6211 fixture: two pool-mode source-NAT rules that carry the SAME public
/// pool address in SEPARATE allocators.
///
/// The allocator is shared per `allocator_key` (pool name + addresses + port
/// range — see `SourceNatRule::allocator_key`), so DISTINCT `pool_name`s with
/// the same member address give two rules one address across two independent
/// `PortAllocator`s. That is the pathological shape #6211 is about: the
/// pre-fix "first rule whose pool CONTAINS `rewrite_src`" selection cannot
/// tell them apart, while the ACTIVE node picked between them by zone.
///
/// Rule order is deliberate: the `dmz->wan` rule is FIRST, so a session the
/// active translated under the `lan->wan` rule hits the wrong allocator first
/// on the pre-fix path.
fn overlapping_pool_rules_6211() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "snat-dmz".to_string(),
            from_zone: "dmz".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-dmz".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "snat-lan".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-lan".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..SourceNATRuleSnapshot::default()
        },
    ])
}

// #6211 FAIL-ON-REVERT (port-bearing / PAT arm): with two source-NAT rules
// carrying OVERLAPPING pool addresses in SEPARATE allocators, a peer-synced
// reservation must land in the allocator belonging to the rule the ACTIVE node
// matched by ZONE — not in the first rule whose pool merely CONTAINS the
// translated address.
//
// Before the fix `reserve_synced_source_nat_allocation` scanned rules in
// snapshot order and reserved on the first pool-owner, which here is the
// `dmz->wan` rule; the active had translated a `lan->wan` flow under the
// `lan->wan` rule. The standby's collision guard therefore sat in the WRONG
// allocator, so after a failover a fresh local `lan->wan` flow allocated the
// SAME (pool address, port) the still-live synced session owns — two sessions
// on one public source tuple, the reverse-path ambiguity the reservation
// exists to prevent.
//
// Reverting the #6211 pass-1 block in `reserve_synced_source_nat_allocation`
// (leaving only the pre-#6211 first-pool-match) makes the "lan rule holds the
// reservation" and "post-failover local flow must not get 20000" assertions
// RED.
#[test]
fn synced_reservation_follows_active_zone_match_6211() {
    let rules = overlapping_pool_rules_6211();
    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let synced_nat = NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        rewrite_src_port: Some(20000),
        ..NatDecision::default()
    };

    // The active matched its rule by zone: this session came in on `lan` and
    // left via `wan`, so it was translated under rules[1] (`snat-lan`).
    reserve_synced_source_nat_allocation(
        &rules,
        &synced_key,
        synced_nat,
        false,
        Some(("lan", "wan")),
        0,
    );

    assert!(
        rules[1].pool_allocator.debug_is_port_occupied(0, 20000),
        "the lan->wan rule's allocator (the one the ACTIVE used) must hold the reservation"
    );
    assert!(
        !rules[0].pool_allocator.debug_is_port_occupied(0, 20000),
        "the dmz->wan rule's allocator must NOT hold the reservation (#6211: it is \
         merely the first pool that contains the address)"
    );

    // The consequence the reservation exists to prevent: a post-failover local
    // `lan->wan` flow allocates from the SAME allocator the active used. It
    // must skip the reserved 20000. On revert it gets 20000 and collides with
    // the still-live synced session.
    let addrs = rules[1].pool_addresses_v4.clone();
    let new_flow = SourceNatFlowKey {
        protocol: PROTO_TCP,
        src_ip: "10.0.61.51".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 40001,
        dst_port: 443,
    };
    let translated = rules[1]
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
            NatHolder::Untracked,
        )
        .expect("the lan pool must have a free port");
    assert_eq!(
        translated.port, 20001,
        "a post-failover local flow under the SAME rule the active used must not \
         reuse the synced session's reserved port 20000"
    );

    // The standard teardown still frees it — the reservation went in through
    // the shared `reserve_synced_on_first_pool_owner` body, so
    // `release_source_nat_allocation`'s own first-pool-owner scan finds it.
    release_source_nat_allocation(&rules, &synced_key, synced_nat, false, 2_000);
    assert!(
        !rules[1].pool_allocator.debug_is_port_occupied(0, 20000),
        "releasing the synced session must free the reservation it took"
    );
}

// #6211 FAIL-ON-REVERT (address-only arm, #5338/#6210): the same divergence
// applies to a `port no-translation` synced session, whose reverse-identity
// token must be minted in the allocator the ACTIVE used. A token in the wrong
// allocator is exactly the "reverse index cannot disambiguate the promoted
// session" hazard #5338 closes — the #6210 mirror inherited it.
//
// Reverting the #6211 pass-1 block mints the token on the `dmz->wan` rule and
// turns both assertions RED.
#[test]
fn synced_address_only_token_follows_active_zone_match_6211() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "snat-dmz".to_string(),
            from_zone: "dmz".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-dmz".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            pool_no_translation: true,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "snat-lan".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-lan".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            pool_no_translation: true,
            ..SourceNATRuleSnapshot::default()
        },
    ]);
    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    // Address-only: a pool address but NO translated port (the wire keeps the
    // packet's own source port).
    let synced_nat = NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        rewrite_src_port: None,
        ..NatDecision::default()
    };

    reserve_synced_source_nat_allocation(
        &rules,
        &synced_key,
        synced_nat,
        false,
        Some(("lan", "wan")),
        0,
    );

    assert_eq!(
        rules[1].pool_allocator.debug_address_only_owners().len(),
        1,
        "the lan->wan rule's allocator (the one the ACTIVE used) must own the \
         address-only reverse-identity token"
    );
    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        0,
        "the dmz->wan rule's allocator must mint no token (#6211)"
    );
}

// #6211 FAIL-ON-REVERT (leak): a session re-upserted under a DIFFERENT
// `synced_zones` outcome lands in a SECOND allocator, and the teardown must
// free BOTH.
//
// The two-pass selection is not a pure function of `rules`: pass 1 and pass 2
// can pick different rules for the same session at different times. A zone
// delete/renumber flips `synced_source_nat_zone_pair` to `None`; a rule-set
// `from zone` / `match` edit moves pass 1's candidate set. Every live session
// re-upserts on HA session-sync reconnect (and on a post-delete-journal-overflow
// resync), and `upsert_synced_with_origin` removes + re-inserts, so
// `handle_upsert_synced` re-runs the reserve. The two rules' allocators are
// independent, so the second reserve SUCCEEDS rather than short-circuiting on
// `reserve_flow`'s idempotence.
//
// With the pre-fix first-hit `break` in `release_source_nat_allocation` the
// teardown freed `pool-dmz` and stopped, leaving `pool-lan` holding port 20000
// forever — a permanent standby pool leak that also counts against
// `max_tracked_flows`. Restoring that `break` makes the "both freed" assertion
// RED.
#[test]
fn synced_reservation_double_upsert_across_zone_outcomes_frees_both_6211() {
    let rules = overlapping_pool_rules_6211();
    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let synced_nat = NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        rewrite_src_port: Some(20000),
        ..NatDecision::default()
    };

    // Upsert #1: the zone pair resolves -> pass 1 -> the `lan->wan` rule.
    reserve_synced_source_nat_allocation(
        &rules,
        &synced_key,
        synced_nat,
        false,
        Some(("lan", "wan")),
        0,
    );
    // Upsert #2 (same live session re-synced) AFTER a zone delete/renumber, so
    // the pair no longer resolves -> pass 2 -> the `dmz->wan` rule.
    reserve_synced_source_nat_allocation(&rules, &synced_key, synced_nat, false, None, 0);

    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, 20000)
            && rules[1].pool_allocator.debug_is_port_occupied(0, 20000),
        "precondition: the re-upsert reserved the SAME session in a SECOND \
         allocator (they are independent, so idempotence does not apply)"
    );

    release_source_nat_allocation(&rules, &synced_key, synced_nat, false, 2_000);

    assert!(
        !rules[0].pool_allocator.debug_is_port_occupied(0, 20000),
        "teardown must free the dmz-rule reservation"
    );
    assert!(
        !rules[1].pool_allocator.debug_is_port_occupied(0, 20000),
        "#6211 LEAK: teardown must ALSO free the lan-rule reservation — a \
         first-hit `break` in release_source_nat_allocation strands it forever"
    );
}

// #6211 CONTROL for the release sweep: dropping the first-hit `break` must not
// over-free. A DIFFERENT flow holding a reservation in another rule's allocator
// is untouched by this flow's teardown — `release_flow` returns false unless
// the stored translated tuple matches.
#[test]
fn synced_release_sweep_does_not_free_an_unrelated_flow_6211() {
    let rules = overlapping_pool_rules_6211();
    let mine = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let mine_nat = NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        rewrite_src_port: Some(20000),
        ..NatDecision::default()
    };
    let other = session_key_from_src("10.0.61.99", 40099, "8.8.8.8", 443);
    let other_nat = NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        rewrite_src_port: Some(20050),
        ..NatDecision::default()
    };

    reserve_synced_source_nat_allocation(&rules, &mine, mine_nat, false, Some(("lan", "wan")), 0);
    reserve_synced_source_nat_allocation(&rules, &other, other_nat, false, None, 0);
    assert!(rules[1].pool_allocator.debug_is_port_occupied(0, 20000));
    assert!(rules[0].pool_allocator.debug_is_port_occupied(0, 20050));

    release_source_nat_allocation(&rules, &mine, mine_nat, false, 2_000);

    assert!(
        !rules[1].pool_allocator.debug_is_port_occupied(0, 20000),
        "this flow's own reservation is freed"
    );
    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, 20050),
        "the sweep must NOT free an UNRELATED flow's reservation in another \
         rule's allocator"
    );
}

// #6211 NEGATIVE CONTROL (mixed-version / unresolvable zone): with NO zone pair
// available — an old peer that carried neither a zone id nor a resolvable zone
// name, or config drift — the reservation falls back to the pre-#6211
// first-pool-match. It must NOT be dropped: a missing reservation is strictly
// worse than one in a debatable allocator, and this is byte-identical to what
// shipped.
//
// This is the direction stated in the `reserve_synced_source_nat_allocation`
// doc comment; deleting the pass-2 fallback leaves both allocators empty and
// turns this RED.
#[test]
fn synced_reservation_without_zone_pair_falls_back_to_first_pool_match_6211() {
    let rules = overlapping_pool_rules_6211();
    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let synced_nat = NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        rewrite_src_port: Some(20000),
        ..NatDecision::default()
    };

    reserve_synced_source_nat_allocation(&rules, &synced_key, synced_nat, false, None, 0);

    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, 20000),
        "with no zone pair the reservation must still be taken, on the pre-#6211 \
         first pool that contains the address"
    );
    assert!(
        !rules[1].pool_allocator.debug_is_port_occupied(0, 20000),
        "the fallback must not reserve on both rules"
    );
}

// #6211 NEGATIVE CONTROL (zone pair matches NO rule): the active translated
// under a rule this node cannot confirm — e.g. NAT config drift between the HA
// nodes, so no local rule matches the synced zone pair. The reservation must
// still be taken via the pass-2 fallback rather than silently skipped.
#[test]
fn synced_reservation_unmatched_zone_pair_still_reserves_6211() {
    let rules = overlapping_pool_rules_6211();
    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let synced_nat = NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        rewrite_src_port: Some(20000),
        ..NatDecision::default()
    };

    // No local rule is scoped `mgmt -> wan`.
    reserve_synced_source_nat_allocation(
        &rules,
        &synced_key,
        synced_nat,
        false,
        Some(("mgmt", "wan")),
        0,
    );

    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, 20000),
        "an unmatched zone pair must fall back to the pre-#6211 first-pool-match, \
         never drop the reservation"
    );
}

// #6211 NEGATIVE CONTROL (single rule): the one-rule config — the overwhelming
// majority — must be byte-identical with and without a zone pair. There is
// nothing to disambiguate, so pass 1 and pass 2 land on the same allocator.
#[test]
fn synced_reservation_single_rule_is_zone_pair_invariant_6211() {
    let snapshot = [SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 10000,
        port_high: 10005,
        ..SourceNATRuleSnapshot::default()
    }];
    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let synced_nat = NatDecision {
        rewrite_src: Some("203.0.113.1".parse().unwrap()),
        rewrite_src_port: Some(10000),
        ..NatDecision::default()
    };

    for zones in [None, Some(("lan", "wan"))] {
        let rules = parse_source_nat_rules(&snapshot);
        reserve_synced_source_nat_allocation(&rules, &synced_key, synced_nat, false, zones, 0);
        assert!(
            rules[0].pool_allocator.debug_is_port_occupied(0, 10000),
            "single-rule reservation must be identical for zones = {zones:?}"
        );
        assert_eq!(
            rules[0].pool_allocator.debug_occupied_count(),
            1,
            "exactly one port reserved for zones = {zones:?}"
        );
    }
}

// #6211 NEGATIVE CONTROL (non-overlapping pools): when only ONE rule's pool
// owns the translated address there is nothing to disambiguate, so the
// selection must be identical with and without a zone pair — including when
// the owning rule is NOT first in snapshot order.
#[test]
fn synced_reservation_non_overlapping_pools_is_zone_pair_invariant_6211() {
    let snapshot = [
        SourceNATRuleSnapshot {
            name: "snat-dmz".to_string(),
            from_zone: "dmz".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-dmz".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "snat-lan".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-lan".to_string(),
            // DISJOINT from the dmz pool.
            pool_addresses: vec!["203.0.113.20/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..SourceNATRuleSnapshot::default()
        },
    ];
    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let synced_nat = NatDecision {
        rewrite_src: Some("203.0.113.20".parse().unwrap()),
        rewrite_src_port: Some(20000),
        ..NatDecision::default()
    };

    for zones in [None, Some(("lan", "wan"))] {
        let rules = parse_source_nat_rules(&snapshot);
        reserve_synced_source_nat_allocation(&rules, &synced_key, synced_nat, false, zones, 0);
        assert!(
            rules[1].pool_allocator.debug_is_port_occupied(0, 20000),
            "the only pool owning 203.0.113.20 must hold it for zones = {zones:?}"
        );
        assert_eq!(
            rules[0].pool_allocator.debug_occupied_count(),
            0,
            "the disjoint pool must stay untouched for zones = {zones:?}"
        );
    }
}

// #6211 GUARD on the scope decision: the standby matcher deliberately IGNORES
// the #3096 interface / routing-instance scope axis, because that axis is
// derived from node-local ifindex maps the standby cannot reproduce for the
// ACTIVE node's ingress/egress.
//
// Here the rule the active used carries `from interface ge-0/0/1` and comes
// FIRST; a second, unscoped rule with an overlapping pool follows. Matching
// with the full `matches` predicate under an empty scope context would REJECT
// the scoped rule (its `from_interface` cannot equal "") and push the
// reservation onto the later rule — worse than the pre-#6211 first-pool-match,
// which at least landed on the right one. Swapping `matches_ignoring_scope`
// for `matches` in `reserve_synced_source_nat_allocation` turns this RED.
#[test]
fn synced_reservation_ignores_unconfirmable_interface_scope_6211() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "snat-lan-if".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            // #3096 scope: node-local, and NOT carried on the sync wire.
            from_interface: "ge-0/0/1.0".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-if".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "snat-lan".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-lan".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..SourceNATRuleSnapshot::default()
        },
    ]);
    assert_eq!(
        rules[0].from_interface, "ge-0/0/1.0",
        "precondition: the first rule carries an interface scope"
    );
    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let synced_nat = NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        rewrite_src_port: Some(20000),
        ..NatDecision::default()
    };

    reserve_synced_source_nat_allocation(
        &rules,
        &synced_key,
        synced_nat,
        false,
        Some(("lan", "wan")),
        0,
    );

    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, 20000),
        "an interface-scoped rule must stay a CANDIDATE — the standby cannot \
         confirm or refute the #3096 scope, so it must not narrow on it"
    );
    assert!(
        !rules[1].pool_allocator.debug_is_port_occupied(0, 20000),
        "the reservation must not skip past the scoped rule onto a later one"
    );
}

// #6211 GUARD on the L4 axis: the zone pair alone does not disambiguate. Two
// rules with the SAME zone pair and overlapping pools, separated only by
// `match destination-port`, must still resolve to the rule the active matched
// — the standby feeds the synced 5-tuple through the same `l4_matches` the
// active used.
//
// Dropping `l4_matches` from `matches_ignoring_scope` makes both rules
// candidates, the first wins, and this turns RED.
#[test]
fn synced_reservation_narrows_on_l4_match_6211() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "snat-web".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            match_destination_ports: vec![NatPortRangeWire { low: 80, high: 80 }],
            pool_name: "pool-web".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "snat-tls".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            match_destination_ports: vec![NatPortRangeWire {
                low: 443,
                high: 443,
            }],
            pool_name: "pool-tls".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..SourceNATRuleSnapshot::default()
        },
    ]);
    // The synced session is to port 443 — the active matched `snat-tls`.
    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let synced_nat = NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        rewrite_src_port: Some(20000),
        ..NatDecision::default()
    };

    reserve_synced_source_nat_allocation(
        &rules,
        &synced_key,
        synced_nat,
        false,
        Some(("lan", "wan")),
        0,
    );

    assert!(
        rules[1].pool_allocator.debug_is_port_occupied(0, 20000),
        "the dst-port 443 rule (the one the ACTIVE matched) must hold the reservation"
    );
    assert!(
        !rules[0].pool_allocator.debug_is_port_occupied(0, 20000),
        "the dst-port 80 rule must not hold it"
    );
}

// #6211 GUARD on the destination axis being POST-DNAT: the active matches
// source NAT against the post-DNAT destination (`nat_match_flow =
// flow.with_destination(effective_resolution_target)` in `poll_descriptor`),
// and `reserve_synced_source_nat_allocation` builds its flow key the same way
// (`nat.rewrite_dst.unwrap_or(key.dst_ip)`). So a synced session that also
// carries a DNAT must be narrowed on the TRANSLATED destination, not the
// original one.
//
// Feeding `key.dst_ip` instead of `flow.dst_ip` into the pass-1 predicate picks
// the wrong rule and turns this RED.
//
// NB the key here carries the PRE-DNAT destination with `rewrite_dst` set. In
// production the installed forward key IS `nat_match_flow.forward_key`, whose
// destination is ALREADY post-DNAT, so `nat.rewrite_dst.unwrap_or(key.dst_ip)`
// is idempotent and both shapes yield the same `flow.dst_ip`. This shape is
// used deliberately because it is the one that DISTINGUISHES the two: with a
// production-shaped key the mutation would be invisible.
#[test]
fn synced_reservation_narrows_on_post_dnat_destination_6211() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "snat-orig-dst".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            // Matches the ORIGINAL (pre-DNAT) destination.
            destination_addresses: vec!["198.51.100.7/32".to_string()],
            pool_name: "pool-orig".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "snat-xlated-dst".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            // Matches the POST-DNAT destination — what the active matched on.
            destination_addresses: vec!["10.10.10.7/32".to_string()],
            pool_name: "pool-xlated".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..SourceNATRuleSnapshot::default()
        },
    ]);
    let synced_key = session_key_from_src("10.0.61.50", 40000, "198.51.100.7", 443);
    let synced_nat = NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        rewrite_src_port: Some(20000),
        // Pre-routing DNAT rewrote the destination before the SNAT match ran.
        rewrite_dst: Some("10.10.10.7".parse().unwrap()),
        ..NatDecision::default()
    };

    reserve_synced_source_nat_allocation(
        &rules,
        &synced_key,
        synced_nat,
        false,
        Some(("lan", "wan")),
        0,
    );

    assert!(
        rules[1].pool_allocator.debug_is_port_occupied(0, 20000),
        "the rule matching the POST-DNAT destination must hold the reservation"
    );
    assert!(
        !rules[0].pool_allocator.debug_is_port_occupied(0, 20000),
        "the rule matching the pre-DNAT destination must not hold it"
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

    // #5660: the reverse path indexes the pool via the O(1) reverse map built
    // once from the ordered pool, not a per-lookup linear scan.
    let pool_index = build_pool_reverse_index(&pool);

    let alloc = |src: &str, dst: &str, sport: u16| -> (Ipv4Addr, u16) {
        let mut counter = None;
        let d = expect_snat_decision(match_source_nat_result_for_tuple(
            &rules,
            &NatScopeCtx::default(),
            "subs",
            "inet",
            src.parse().expect("src"),
            dst.parse().expect("dst"),
            Some(PROTO_TCP),
            sport,
            443,
            None,
            None,
            0,
            false,
            false,
            NatHolder::Untracked,
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
        reverse_deterministic_v4(&det, &pool_index, 1024, a_ip, a_port),
        Some(Ipv4Addr::new(100, 64, 0, 5)),
        "reverse must recover subscriber A from (external IP, port) alone"
    );
    assert_eq!(
        reverse_deterministic_v4(&det, &pool_index, 1024, a2_ip, a2_port),
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
        reverse_deterministic_v4(&det, &pool_index, 1024, b_ip, b_port),
        Some(Ipv4Addr::new(100, 64, 1, 0)),
        "reverse must recover subscriber B"
    );
}

// ---------------------------------------------------------------------------
// #5341: address-only occupancy tokens on the DETERMINISTIC-CGNAT (mode 1)
// address-only sub-branch.
//
// Follow-up to #5336, which minted the #5269 reverse-identity occupancy token
// on the ROUND-ROBIN/persistent address-only branch. The deterministic-CGNAT
// (mode 1) `port no-translation` / port-less sub-branch was left UN-tokened: it
// selected the deterministic external address and returned without claiming the
// translated reverse identity, so two subscribers sharing one deterministic
// pool address (same preserved source port + remote) both received the SAME
// public tuple the reverse (1:N) index cannot disambiguate — the same #5269
// collision class. The deterministic branch now mints the SAME token (same
// `reserve_address_only` allocator API, same reservation semantics, freed by
// the SAME teardown path), closing the gap.
//
// blocks_per_ip = 126 (from the #4559 test): sub_idx / 126 = ip_idx, so
// subscribers 100.64.0.5 (sub_idx 5) and 100.64.0.6 (sub_idx 6) BOTH map to
// ip_idx 0 -> pool[0] = 203.0.113.1, and collide when they share a preserved
// source port + remote. 100.64.1.0 (sub_idx 256) maps to ip_idx 2 -> pool[2].
// ---------------------------------------------------------------------------

fn deterministic_notrans_rule() -> Vec<SourceNatRule> {
    let host_base = u32::from(Ipv4Addr::new(100, 64, 0, 0));
    parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "cgnat-notrans".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["100.64.0.0/22".to_string()],
        pool_name: "cgn-pool".to_string(),
        pool_addresses: vec![
            "203.0.113.1/32".to_string(),
            "203.0.113.2/32".to_string(),
            "203.0.113.3/32".to_string(),
            "203.0.113.4/32".to_string(),
        ],
        port_low: 1024,
        port_high: 65535,
        // `port no-translation` — the source port is PRESERVED, so this is a
        // REAL address-only flow, not the PAT case.
        pool_no_translation: true,
        deterministic_mode: 1,
        deterministic_block_size: 512,
        deterministic_blocks_per_ip: 126,
        deterministic_host_base: host_base,
        deterministic_host_count: 1024,
        ..SourceNATRuleSnapshot::default()
    }])
}

// #5341 FAIL-ON-REVERT: deterministic-CGNAT pool with `port no-translation`.
// Subscriber A (100.64.0.5) and subscriber B (100.64.0.6) BOTH map to the same
// deterministic external address (203.0.113.1). With the same preserved source
// port + remote they collide on the identical public reverse tuple. A gets the
// tuple AND an occupancy token; B MUST be denied as exhaustion. Reverting the
// `reserve_address_only` mint makes B return `Matched` with A's rewrite_src and
// `rewrite_src_port: None` — an unowned duplicate — turning the `Unavailable`
// assertion RED. The deterministic rule must be built (gating assertion) so the
// tested sub-branch is actually the deterministic one.
#[test]
fn deterministic_cgnat_no_translation_collision_denies_second_flow_5341() {
    let rules = deterministic_notrans_rule();
    assert!(
        rules[0].deterministic_v4.is_some(),
        "mode-1 deterministic no-translation snapshot must build a deterministic rule"
    );

    let a = expect_snat_decision(addr_only_lookup(
        &rules,
        "100.64.0.5",
        12345,
        "8.8.8.8",
        443,
        PROTO_TCP,
    ));
    assert_eq!(
        a.rewrite_src,
        Some("203.0.113.1".parse().unwrap()),
        "subscriber A must translate to its deterministic external address"
    );
    // Wire contract (unchanged): `no-translation` PRESERVES the source port.
    assert_eq!(a.rewrite_src_port, None);

    // The deterministic branch minted exactly one reverse-identity token,
    // resolving the public tuple to EXACTLY flow A.
    let flow_a = SourceNatFlowKey {
        protocol: PROTO_TCP,
        src_ip: "100.64.0.5".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 12345,
        dst_port: 443,
    };
    let owners = rules[0].pool_allocator.debug_address_only_owners();
    assert_eq!(
        owners.len(),
        1,
        "deterministic address-only flow A must mint exactly one occupancy token"
    );
    assert_eq!(owners[0].1, flow_a, "reverse index must resolve to flow A");
    assert_eq!(
        owners[0].0.translated_ip,
        "203.0.113.1".parse::<IpAddr>().unwrap()
    );
    assert_eq!(owners[0].0.translated_port, 12345);

    // Flow B: DIFFERENT subscriber that maps to the SAME deterministic address,
    // SAME preserved port + SAME remote -> SAME public tuple. Fail closed.
    match addr_only_lookup(&rules, "100.64.0.6", 12345, "8.8.8.8", 443, PROTO_TCP) {
        SourceNatLookup::Unavailable(f) => assert_eq!(
            f.reason,
            SourceNatFailureReason::AllocatorExhausted,
            "colliding deterministic address-only flow must fail closed as exhaustion",
        ),
        other => panic!("flow B must be denied (exhaustion), got {other:?}"),
    }

    // The reverse index STILL resolves uniquely to flow A — B minted nothing.
    let owners_after = rules[0].pool_allocator.debug_address_only_owners();
    assert_eq!(owners_after.len(), 1, "denied flow B must not add a token");
    assert_eq!(owners_after[0].1, flow_a);

    // No pool PORT is consumed (address-only tokens are off the port bitmap).
    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].used_ports, 0);
    assert_eq!(status[0].live_flows, 1, "only flow A is tracked");
}

// #5341: the deterministic address-only token is freed by the SAME teardown
// path used for PAT ports (`release_source_nat_allocation`), so the colliding
// identity becomes reusable after the first flow tears down — no leak, no
// double-free, matching the round-robin branch's token lifecycle.
#[test]
fn deterministic_cgnat_no_translation_token_released_on_teardown_5341() {
    let rules = deterministic_notrans_rule();

    let a = expect_snat_decision(addr_only_lookup(
        &rules,
        "100.64.0.5",
        12345,
        "8.8.8.8",
        443,
        PROTO_TCP,
    ));
    assert_eq!(rules[0].pool_allocator.debug_address_only_owners().len(), 1);

    // Tear down flow A. `release_source_nat_allocation` derives the preserved
    // port from the flow key (the decision left `rewrite_src_port` unset) and
    // clears the reverse-identity token.
    let key_a = session_key_from_src("100.64.0.5", 12345, "8.8.8.8", 443);
    release_source_nat_allocation(&rules, &key_a, a, false, 1);
    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        0,
        "deterministic address-only token must be freed on teardown (no leak)",
    );
    assert_eq!(source_nat_pool_statuses(&rules)[0].live_flows, 0);

    // The previously-colliding subscriber B now succeeds (identity is free).
    let b = expect_snat_decision(addr_only_lookup(
        &rules,
        "100.64.0.6",
        12345,
        "8.8.8.8",
        443,
        PROTO_TCP,
    ));
    assert_eq!(b.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert_eq!(rules[0].pool_allocator.debug_address_only_owners().len(), 1);
}

// #5341: two subscribers sharing the SAME deterministic external address but
// talking to DIFFERENT remotes have DISTINCT reverse identities, so both mint
// their own token and succeed — the token denies only a genuine collision, it
// does not over-block. Guards against a fix that keys the token on the pool
// address alone rather than the full reverse tuple.
#[test]
fn deterministic_cgnat_no_translation_distinct_remote_both_succeed_5341() {
    let rules = deterministic_notrans_rule();

    // A: 100.64.0.5 -> 8.8.8.8 (ip_idx 0 -> 203.0.113.1).
    let a = expect_snat_decision(addr_only_lookup(
        &rules,
        "100.64.0.5",
        12345,
        "8.8.8.8",
        443,
        PROTO_TCP,
    ));
    // B: 100.64.0.6 -> 9.9.9.9 (SAME deterministic address, DIFFERENT remote).
    let b = expect_snat_decision(addr_only_lookup(
        &rules,
        "100.64.0.6",
        12345,
        "9.9.9.9",
        443,
        PROTO_TCP,
    ));
    assert_eq!(a.rewrite_src, Some("203.0.113.1".parse().unwrap()));
    assert_eq!(
        b.rewrite_src,
        Some("203.0.113.1".parse().unwrap()),
        "both subscribers share the deterministic address; distinct remotes keep \
         their reverse identities distinct"
    );
    assert_eq!(a.rewrite_src_port, None);
    assert_eq!(b.rewrite_src_port, None);

    // Two distinct reverse-identity tokens coexist on the one pool address.
    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        2,
        "non-colliding deterministic address-only flows each mint their own token"
    );
    let status = source_nat_pool_statuses(&rules);
    assert_eq!(status[0].used_ports, 0, "address-only tokens claim no pool port");
    assert_eq!(status[0].live_flows, 2);
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
        Some(PROTO_TCP),
        10001,
        443,
        None,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
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
    // #5660: O(1) reverse index over the ordered pool (built once, reused).
    let pool_index = build_pool_reverse_index(&pool);

    let alloc_for = |src: &str, sport: u16| -> (Ipv4Addr, u16) {
        let flow = SourceNatFlowKey {
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(src.parse().expect("src")),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port: sport,
            dst_port: 443,
        };
        let t = alloc
            .allocate_deterministic_v6(
                flow,
                &pool,
                det,
                src.parse().expect("src"),
                NatHolder::Untracked,
            )
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
        reverse_deterministic_v6(&det, &pool_index, 1024, a_ip, a_port),
        Some("2001:db8:0:5::".parse().unwrap()),
        "reverse must recover subscriber A from (external IPv4, port) alone"
    );
    assert_eq!(
        reverse_deterministic_v6(&det, &pool_index, 1024, a2_ip, a2_port),
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
        reverse_deterministic_v6(&det, &pool_index, 1024, b_ip, b_port),
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
            .allocate_deterministic_v6(
                over,
                &pool,
                det,
                "2001:db8:0:1f8::".parse().unwrap(),
                NatHolder::Untracked,
            )
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
    // #5660: O(1) reverse index over the ordered pool (built once, reused).
    let pool_index = build_pool_reverse_index(&pool);
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
                "2001:db9:0:5::".parse().unwrap(),
                NatHolder::Untracked,
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
            NatHolder::Untracked,
        )
        .expect("the in-prefix source still allocates");
    let ext_ip = match ok.ip {
        IpAddr::V4(v4) => v4,
        other => panic!("NAT64 pool is always v4, got {other}"),
    };
    assert_eq!(ext_ip, pool[0], "in-prefix subscriber 5 maps to pool[0]");
    assert_eq!(
        reverse_deterministic_v6(&det, &pool_index, 1024, ext_ip, ok.port),
        Some("2001:db8:0:5::".parse().unwrap()),
        "the reverse map recovers the true in-prefix subscriber"
    );
}

// #5660: the O(1) reverse index must be the EXACT inverse of the forward
// deterministic mapping across EVERY subscriber and pool-address position — idx
// 0 (first), the middle addresses, and the LAST address. The pool here is
// deliberately NON-CONTIGUOUS (gaps between 10.0.0.1/.9/.100/.200), which is the
// realistic shape (NAT64 parses arbitrary pool strings; source-NAT pools span
// disjoint ranges). This is the guard against the tempting-but-WRONG "O(1)"
// shortcut of `translated_ip - pool_base`: a contiguous-subtraction reverse
// would attribute .9/.100/.200 to the wrong index and turn this RED. Both the
// old `position()` scan and the new hash index satisfy this round-trip, so it is
// a correctness guard for the refactor (the perf change itself is unobservable).
#[test]
fn deterministic_reverse_v4_o1_index_is_exact_inverse_across_pool_boundaries() {
    // Non-contiguous 4-address pool. block_size 4, blocks_per_ip 3 -> each pool
    // address serves 3 subscriber blocks; host_count = 4 * 3 = 12 subscribers.
    let pool = [
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 9),
        Ipv4Addr::new(10, 0, 0, 100),
        Ipv4Addr::new(10, 0, 0, 200),
    ];
    let port_low = 1024u16;
    let host_base = u32::from(Ipv4Addr::new(100, 64, 0, 0));
    let det = DeterministicV4 {
        block_size: 4,
        blocks_per_ip: 3,
        host_base,
        host_count: 12,
    };
    let pool_index = build_pool_reverse_index(&pool);

    // Every subscriber (sub_idx 0..host_count) round-trips forward -> reverse.
    // sub_idx spans ip_idx 0 (first), 1, 2 (middle), and 3 (last).
    for sub_idx in 0..det.host_count {
        let src = Ipv4Addr::from(host_base + sub_idx);
        let (ip_idx, block_idx) =
            deterministic_indices_v4(&det, src).expect("in-range subscriber maps forward");
        assert_eq!(ip_idx, (sub_idx / 3) as usize, "forward ip_idx");
        let external = pool[ip_idx];
        // Confirm the reverse index recovers the SAME position the forward used.
        assert_eq!(
            pool_index.get(&external).copied(),
            Some(ip_idx as u32),
            "reverse index must return the forward pool position for {external}"
        );
        // The whole port block reverses to the same subscriber.
        let block_start = port_low as u32 + block_idx * det.block_size as u32;
        for p in block_start..block_start + det.block_size as u32 {
            let port = p as u16;
            assert_eq!(
                reverse_deterministic_v4(&det, &pool_index, port_low, external, port),
                Some(src),
                "reverse of (external {external}, port {port}) must recover subscriber {src}"
            );
        }
    }

    // Idx 0 / middle / last explicitly, as the ticket calls out.
    for &ip_idx in &[0usize, 1, 2, 3] {
        let external = pool[ip_idx];
        let expected_sub = (ip_idx as u32) * det.blocks_per_ip as u32; // block_idx 0
        let expected_src = Ipv4Addr::from(host_base + expected_sub);
        assert_eq!(
            reverse_deterministic_v4(&det, &pool_index, port_low, external, port_low),
            Some(expected_src),
            "pool boundary idx {ip_idx} ({external}) reverses to {expected_src}"
        );
    }

    // An external IP NOT in the pool is rejected (the reverse index misses).
    assert_eq!(
        reverse_deterministic_v4(
            &det,
            &pool_index,
            port_low,
            Ipv4Addr::new(10, 0, 0, 2),
            port_low,
        ),
        None,
        "an address absent from the pool must not reverse to any subscriber"
    );
}

// #5660 RED-on-revert (item 2): `AddressOccupancy::port_of` must REJECT an
// offset outside the port range instead of silently truncating it through the
// `u32 -> u16` cast into a valid-looking but WRONG port. Removing the range
// guard (keeping the `Option` shape, e.g. `if false && offset >= self.range`)
// makes the out-of-range asserts below return `Some(<forged port>)` and turns
// this RED — a bare `offset as u16` wraps `65536 + k` back to `k`, forging the
// port `port_low + k` inside the pool.
#[test]
fn port_of_rejects_out_of_range_offset_no_silent_truncation() {
    // port_low 1024, port_high 2047 -> range 1024 (offsets 0..=1023 valid).
    let alloc = PortAllocator::new(1, 1024, 2047);

    // In-range offsets map to the exact wire port (no truncation).
    assert_eq!(alloc.debug_port_of(0, 0), Some(1024), "offset 0 -> port_low");
    assert_eq!(
        alloc.debug_port_of(0, 1023),
        Some(2047),
        "last valid offset -> port_high"
    );

    // offset == range is one past the end: rejected, not wrapped to port_low.
    assert_eq!(
        alloc.debug_port_of(0, 1024),
        None,
        "offset == range must be rejected"
    );

    // The truncation forgery: offset 65536+5 casts (as u16) to 5, which would
    // forge the VALID in-range port 1029. The range check rejects it instead.
    assert_eq!(
        alloc.debug_port_of(0, 65536 + 5),
        None,
        "an offset whose u16 truncation forges a valid port must be rejected"
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
                    NatHolder::Untracked,
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
                    NatHolder::Untracked,
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
                        assert!(alloc.release_flow(flow, t, 2_000, NatHolder::Untracked), "release of a live flow");
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
            NatHolder::Untracked,
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
        alloc.release_flow(mk(5001), t1, 2_000, NatHolder::Untracked),
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
                NatHolder::Untracked,
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
                NatHolder::Untracked,
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
                    address_only: false,
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
                address_only: false,
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
                address_only: false,
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
                        NatHolder::Untracked,
                    ) {
                        assert!(
                            alloc.release_flow(flow, translated, now_ns + 1, NatHolder::Untracked),
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

// ---------------------------------------------------------------------------
// #6211 F2 — per-worker holder set on a synced reservation
// ---------------------------------------------------------------------------
//
// An HA-synced session is pushed to EVERY worker's session table
// (`afxdp/ha/session_import.rs` fans `UpsertSynced` out to each worker's command
// queue) while the source-NAT allocator is ONE shared `Arc`. So N workers reserve
// the same `(flow, translated)` and each releases it independently — the reap,
// the replicated `DeleteSynced`, and the alias purge all run per worker.
//
// Before the holder mask, `reserve_flow`'s idempotent early return collapsed the
// N reserves into ONE record and `release_flow` removed it unconditionally, so
// the FIRST worker to let go freed a `(pool_addr, port)` the other N-1 were still
// forwarding through. That is not a narrow race: post-failover the active's
// periodic `UpsertSynced` refresh stops and RSS lands traffic on exactly one
// worker, so the other replicas idle out with nothing refreshing them and
// whichever expires first frees the port the live worker is using.
//
// A single-worker fixture cannot express this property — it passes both before
// and after the fix — so every cell below reserves on at least TWO workers.

/// One single-address pool rule with a 2-port range, the fixture shape the
/// #4388 synced-reservation tests already use.
fn holder_pool_rules_6211_f2() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 10000,
        port_high: 10001,
        ..SourceNATRuleSnapshot::default()
    }])
}

fn holder_synced_nat_6211_f2() -> NatDecision {
    NatDecision {
        rewrite_src: Some("203.0.113.1".parse().unwrap()),
        rewrite_src_port: Some(10000),
        ..NatDecision::default()
    }
}

// #6211 F2 FAIL-ON-REVERT (the binder). Two workers hold the same synced
// reservation; retiring the FIRST must leave the port reserved for the second.
//
// Reverting the holder mask — restoring `release_flow` to remove
// unconditionally, or dropping the `holders |= holder.bit()` from
// `reserve_flow`'s idempotent early return (which is where worker 1 lands, since
// worker 0 already inserted the record) — makes this assertion RED.
//
// Deliberately kept in its OWN body: pairing it with the "frees on the last
// retire" guard below would mean the guard never executes once this assertion
// fires.
#[test]
fn synced_reservation_survives_first_worker_retire_6211_f2() {
    let rules = holder_pool_rules_6211_f2();
    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let synced_nat = holder_synced_nat_6211_f2();

    // The same synced entry installed on two workers — what the fan-out does.
    reserve_synced_source_nat_allocation_for_worker(
        &rules,
        &synced_key,
        synced_nat,
        false,
        None,
        0,
        0,
    );
    reserve_synced_source_nat_allocation_for_worker(
        &rules,
        &synced_key,
        synced_nat,
        false,
        None,
        0,
        1,
    );
    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, 10000),
        "precondition: both workers reserved the synced port"
    );

    // Worker 0 reaps its replica (post-failover: RSS moved the traffic to
    // worker 1, so worker 0's copy idles out first).
    release_source_nat_allocation_for_worker(&rules, &synced_key, synced_nat, false, 2_000, 0);

    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, 10000),
        "#6211 F2: worker 1 still holds this synced session, so worker 0's \
         retire must NOT free (203.0.113.1, 10000) — freeing it hands a live \
         worker's NAT source tuple to the next local flow"
    );
}

// #6211 F2 companion to the binder, in its OWN body: once the LAST worker
// retires, the port really is freed. Without this a "never free" implementation
// would satisfy the binder above while leaking every synced port.
//
// Stays GREEN under the revert (the pre-fix code frees on the first release, so
// it is also free after the second) — this is a leak guard, not a restatement of
// the fix.
#[test]
fn synced_reservation_frees_on_last_worker_retire_6211_f2() {
    let rules = holder_pool_rules_6211_f2();
    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let synced_nat = holder_synced_nat_6211_f2();

    reserve_synced_source_nat_allocation_for_worker(
        &rules,
        &synced_key,
        synced_nat,
        false,
        None,
        0,
        0,
    );
    reserve_synced_source_nat_allocation_for_worker(
        &rules,
        &synced_key,
        synced_nat,
        false,
        None,
        0,
        1,
    );

    release_source_nat_allocation_for_worker(&rules, &synced_key, synced_nat, false, 2_000, 0);
    release_source_nat_allocation_for_worker(&rules, &synced_key, synced_nat, false, 2_001, 1);

    assert!(
        !rules[0].pool_allocator.debug_is_port_occupied(0, 10000),
        "#6211 F2: the LAST holder's retire must free the pool port — holding \
         it past the final release is a permanent standby leak that counts \
         against max_tracked_flows"
    );
}

// #6211 F2 REFRESH CELL — the cell a bare COUNTER fails.
//
// `reserve_flow`'s idempotent early return is not only where workers 2..N land;
// it is the path an ALREADY-holding worker takes on every refresh (each HA
// session-sync reconnect, each periodic re-`UpsertSynced`). A counter
// incremented there would climb without bound and never drain to zero, so this
// worker's single retire would leave the port reserved forever. OR is idempotent
// where increment is not, which is why the holder set is a bitmask.
//
// GREEN both before and after the fix: it constrains the SHAPE of the fix.
#[test]
fn synced_reservation_refresh_by_one_worker_does_not_accumulate_holders_6211_f2() {
    let rules = holder_pool_rules_6211_f2();
    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    let synced_nat = holder_synced_nat_6211_f2();

    // One worker, refreshed repeatedly — every re-sync of a live session.
    for _ in 0..8 {
        reserve_synced_source_nat_allocation_for_worker(
            &rules,
            &synced_key,
            synced_nat,
            false,
            None,
            0,
            3,
        );
    }
    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, 10000),
        "precondition: the refreshed reservation is held"
    );

    // ONE retire, because there is exactly ONE holder however many times it
    // refreshed.
    release_source_nat_allocation_for_worker(&rules, &synced_key, synced_nat, false, 2_000, 3);

    assert!(
        !rules[0].pool_allocator.debug_is_port_occupied(0, 10000),
        "#6211 F2: a refresh must not add a holder — 8 re-reserves by worker 3 \
         are still ONE holder, so worker 3's single retire frees the port. A \
         refcount incremented on the idempotent path would sit at 8 and leak"
    );
}

// #6211 F2 for the ADDRESS-ONLY (#5338) synced arm: `reserve_address_only` has
// its own idempotent early return, so it needs the same holder treatment. The
// observable is the reverse-identity token in `address_only_owners` (an
// address-only flow claims no port bit on the occupancy bitmap).
//
// RED on revert for the same reason as the port-bearing binder.
#[test]
fn synced_address_only_token_survives_first_worker_retire_6211_f2() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-snat-addr-only".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 10000,
        port_high: 10001,
        ..SourceNATRuleSnapshot::default()
    }]);
    let synced_key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    // Address-only: a pool source address with NO translated port — the wire
    // keeps the packet's own source port.
    let synced_nat = NatDecision {
        rewrite_src: Some("203.0.113.1".parse().unwrap()),
        rewrite_src_port: None,
        ..NatDecision::default()
    };

    reserve_synced_source_nat_allocation_for_worker(
        &rules,
        &synced_key,
        synced_nat,
        false,
        None,
        0,
        0,
    );
    reserve_synced_source_nat_allocation_for_worker(
        &rules,
        &synced_key,
        synced_nat,
        false,
        None,
        0,
        1,
    );
    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        1,
        "precondition: both workers hold ONE address-only reverse-identity token"
    );

    release_source_nat_allocation_for_worker(&rules, &synced_key, synced_nat, false, 2_000, 0);

    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        1,
        "#6211 F2: worker 1 still holds this synced address-only session, so \
         worker 0's retire must NOT drop the reverse-identity token"
    );
}

// #6211 F2 OVER-REACH GUARD, re-scoped by #6522: an UNTRACKED allocation is
// untouched by the holder set.
//
// `NatHolder::Untracked` records no bit, so such a record carries
// `holders == 0` and the FIRST release frees it — the pre-#6211-F2 contract —
// no matter which worker id the release carries. A fix that made EVERY release
// refcounted would leak every port allocated through an untracked entry point;
// this cell is what separates the two.
//
// #6522 narrowed WHO passes `Untracked`: the production packet path now names
// its own worker (`NatHolder::Worker(worker_id)`, see the #6522 cells below),
// so the remaining untracked callers are the test entry points and the
// read-only non-first-fragment probe (which mints nothing). This cell pins the
// `Untracked` contract those callers depend on, not a claim about local flows.
//
// Stays GREEN under both reverts.
#[test]
fn untracked_allocation_still_frees_on_first_release_6211_f2() {
    let rules = holder_pool_rules_6211_f2();
    let addrs = rules[0].pool_addresses_v4.clone();
    let local_flow = SourceNatFlowKey {
        protocol: 6,
        src_ip: "10.0.61.51".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 40001,
        dst_port: 443,
    };
    let translated = rules[0]
        .pool_allocator
        .allocate_translation(
            local_flow,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            false,
            PersistentNatPermit::TargetHostPort,
            0,
            1_000,
            NatHolder::Untracked,
        )
        .expect("a fresh pool port must be available");
    assert!(
        rules[0]
            .pool_allocator
            .debug_is_port_occupied(0, translated.port),
        "precondition: the local allocation holds its port"
    );

    // The owning worker retires it exactly once.
    assert!(
        rules[0]
            .pool_allocator
            .release_flow(local_flow, translated, 2_000, NatHolder::Worker(5)),
        "a local allocation is freed by its first release"
    );
    assert!(
        !rules[0]
            .pool_allocator
            .debug_is_port_occupied(0, translated.port),
        "#6211 F2 must not make UNTRACKED allocations refcounted — a record \
         minted through `NatHolder::Untracked` carries no holder bits and \
         frees on the first release"
    );
}


// ---------------------------------------------------------------------------
// #6522 — the ALLOCATING worker is a holder of its own allocation
// ---------------------------------------------------------------------------
//
// #6211 F2 gave an HA-SYNCED reservation a holder bit per worker, because
// `handle_upsert_synced` runs on every worker against one shared allocator. It
// left the LOCAL allocation path untracked on the stated ground that "RSS
// steers a 5-tuple to exactly one worker, so a local allocation has a single
// holder by construction".
//
// That ground does not hold. A locally-born forward session is REPLICATED to
// every sibling worker: `poll_descriptor` calls `replicate_session_upsert`,
// which fans a `WorkerLocalImport`-origin `UpsertSynced` to
// `peer_worker_commands` — the queue list built in
// `coordinator/reconcile/bringup.rs` by `.filter(|(id, _)| **id != worker_id)`,
// i.e. every worker EXCEPT the allocating one. `SessionOrigin::is_peer_synced()`
// returns TRUE for `WorkerLocalImport`, so each sibling's `handle_upsert_synced`
// calls `reserve_synced_source_nat_allocation_for_worker` and takes a holder
// bit on the record the allocating worker created.
//
// So with an untracked local allocation the holder mask ends up naming every
// worker EXCEPT the one actually forwarding. The sibling replicas see no
// traffic (flow-hash steering pins the flow's packets to one worker) and are
// never refreshed, so they all age out; when the LAST of them reaps,
// `drop_holder_locked` empties the mask and frees a `(pool_addr, port)` the
// owning worker is still forwarding through — mid-flow pool-port reuse.
//
// The second reaching path needs no reserve at all:
// `session_glue::materialize_shared_session_hit` installs a `WorkerLocalImport`
// replica on a worker off the SHARED map WITHOUT reserving, and
// `reap_expired_sessions` then releases for it unconditionally — a worker that
// never held the allocation freeing it outright.
//
// A single-worker fixture cannot express any of this: it is green before and
// after. Every cell below has the allocation made by one worker and released or
// reserved by another.

/// Allocate through the REAL packet-path SNAT decision function, as
/// `source_nat_decision_for_flow` does, recording `worker` as the holder.
fn local_pool_allocation_6522(
    rules: &[SourceNatRule],
    src_ip: &str,
    src_port: u16,
    holder: NatHolder,
) -> NatDecision {
    let mut counter = None;
    expect_snat_decision(match_source_nat_result_for_tuple(
        rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src_ip.parse().expect("src"),
        "8.8.8.8".parse().expect("dst"),
        Some(PROTO_TCP),
        src_port,
        443,
        None,
        None,
        1_000,
        false,
        false,
        holder,
        &mut counter,
    ))
}

// #6522 FAIL-ON-REVERT (the binder). Worker 0 allocates locally and keeps
// forwarding; its five sibling replicas each reserve and then age-reap. The
// port must still be held.
//
// Reverting the fix — restoring `holders: 0` at `allocate_translation`'s
// `live_by_flow.insert` — makes this assertion RED: the mask becomes
// {1,2,3,4,5}, worker 5's reap empties it, and the port is freed under worker 0.
//
// Kept in its own body so the leak guard below still runs when this fires.
#[test]
fn local_allocation_survives_sibling_replica_reaps_6522() {
    let rules = holder_pool_rules_6211_f2();
    let decision = local_pool_allocation_6522(&rules, "10.0.61.50", 40000, NatHolder::Worker(0));
    let port = decision
        .rewrite_src_port
        .expect("a pool-mode TCP flow allocates a translated port");
    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, port),
        "precondition: worker 0's local allocation holds its pool port"
    );

    let key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    // What `replicate_session_upsert` -> `handle_upsert_synced` does on each
    // SIBLING worker (never worker 0 — `peer_worker_commands` excludes self).
    for sibling in 1..6u32 {
        reserve_synced_source_nat_allocation_for_worker(
            &rules, &key, decision, false, None, 1_000, sibling,
        );
    }

    // Every replica ages out with nothing refreshing it and reaps.
    for sibling in 1..6u32 {
        release_source_nat_allocation_for_worker(&rules, &key, decision, false, 2_000, sibling);
    }

    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, port),
        "#6522: worker 0 is still forwarding this flow, so the sibling \
         replicas' age-reap must NOT free its (203.0.113.1, {port}) — freeing \
         it hands a live flow's NAT source tuple to the next local flow"
    );
}

// #6522 LEAK GUARD, in its own body: once the OWNING worker releases, the port
// really is freed. Without this a "never free a local allocation" implementation
// would satisfy the binder above while leaking every pool port.
//
// Stays GREEN under the revert (pre-fix the first sibling reap already freed it),
// so it constrains the fix rather than restating it.
#[test]
fn local_allocation_frees_when_the_owning_worker_reaps_6522() {
    let rules = holder_pool_rules_6211_f2();
    let decision = local_pool_allocation_6522(&rules, "10.0.61.50", 40000, NatHolder::Worker(0));
    let port = decision.rewrite_src_port.expect("translated port");
    let key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);

    for sibling in 1..6u32 {
        reserve_synced_source_nat_allocation_for_worker(
            &rules, &key, decision, false, None, 1_000, sibling,
        );
        release_source_nat_allocation_for_worker(&rules, &key, decision, false, 2_000, sibling);
    }
    release_source_nat_allocation_for_worker(&rules, &key, decision, false, 2_001, 0);

    assert!(
        !rules[0].pool_allocator.debug_is_port_occupied(0, port),
        "#6522: the owning worker's release is the LAST holder's release — \
         holding the port past it is a permanent pool leak that counts against \
         max_tracked_flows"
    );
}

// #6522 the tight property, and the `materialize_shared_session_hit` path: a
// worker that NEVER reserved must not free another worker's allocation. That
// path installs a `WorkerLocalImport` replica off the shared map without
// reserving, and `reap_expired_sessions` releases for every expired entry with
// no origin or holder filter — so the release below is exactly what production
// issues, with no reserve preceding it.
//
// RED on revert: with `holders == 0` the release frees on first call regardless
// of which worker id it carries.
#[test]
fn foreign_worker_release_does_not_free_a_local_allocation_6522() {
    let rules = holder_pool_rules_6211_f2();
    let decision = local_pool_allocation_6522(&rules, "10.0.61.50", 40000, NatHolder::Worker(0));
    let port = decision.rewrite_src_port.expect("translated port");
    let key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);

    release_source_nat_allocation_for_worker(&rules, &key, decision, false, 2_000, 3);

    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, port),
        "#6522: worker 3 never held this allocation — reaping its \
         materialized replica must not free worker 0's live pool port"
    );
}

// #6522 for the ADDRESS-ONLY (#5269/#6226) local arm. It mints no port bit, so
// the observable is the reverse-identity token in `address_only_owners`, and it
// reaches a DIFFERENT allocator entry point
// (`reserve_address_only_roundrobin`) than the PAT cells above — its own
// `holders:` literal, its own revert.
//
// RED on revert for the same reason as the PAT binder.
#[test]
fn local_address_only_token_survives_sibling_replica_reaps_6522() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-snat-addr-only".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "my-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 10000,
        port_high: 10001,
        // `port no-translation`: the wire keeps the packet's own source port and
        // the flow claims a reverse-identity token instead of a pool port bit.
        pool_no_translation: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = local_pool_allocation_6522(&rules, "10.0.61.50", 40000, NatHolder::Worker(0));
    assert_eq!(
        decision.rewrite_src_port, None,
        "precondition: `port no-translation` preserves the source port"
    );
    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        1,
        "precondition: worker 0's local flow minted one reverse-identity token"
    );

    let key = session_key_from_src("10.0.61.50", 40000, "8.8.8.8", 443);
    for sibling in 1..6u32 {
        reserve_synced_source_nat_allocation_for_worker(
            &rules, &key, decision, false, None, 1_000, sibling,
        );
    }
    for sibling in 1..6u32 {
        release_source_nat_allocation_for_worker(&rules, &key, decision, false, 2_000, sibling);
    }

    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        1,
        "#6522: worker 0 still owns this address-only flow, so its sibling \
         replicas' age-reap must NOT drop the reverse-identity token"
    );
}


// ---------------------------------------------------------------------------
// #6528 — `reserve_flow`'s stale-tuple eviction must use a MODE-CORRECT teardown
// ---------------------------------------------------------------------------
//
// When a synced upsert re-decides a live flow onto a DIFFERENT translated tuple,
// `reserve_flow` evicts the incumbent `live_by_flow` record. That eviction used
// to be an unconditional `free_translated_port(existing.addr_index,
// existing.translated.port, !existing.deterministic)` — correct for exactly ONE
// of the three allocation modes, and for the other two it mutates state that
// belongs to an UNRELATED flow:
//
//   - ADDRESS-ONLY (#5269/#6041): owns no occupancy bit. `addr_index` is a
//     hardcoded 0 and `translated.port` is the PRESERVED internal source port,
//     so the call cleared whatever bit pool address 0 held at that offset. A
//     `port no-translation` rule and a PAT rule SHARE an allocator when their
//     pool name, addresses and port range agree (`allocator_key()` does not
//     include `no_translation`), so that bit is a live PAT flow's — and
//     `free_recycle` then queues the port for reuse. Meanwhile the incumbent's
//     `address_only_owners` token was never cleared, denying that public
//     reverse identity forever.
//   - PERSISTENT: the port belongs to the LEASE, not the flow, so the call freed
//     a port the lease still claimed AND left the lease's `active_flows`
//     refcount incremented. A leaked refcount is never idle, so the lease never
//     enters `lease_expirations` and no GC path can reclaim it.
//
// `release_flow` (`:1585`) and `rollback_flow` had both modes right; only this
// fourth teardown diverged. The eviction now shares `release_flow`'s
// `unlink_live_allocation_locked` + `complete_persistent_lease_locked`, so a
// fifth cannot diverge either.
//
// Reachability: `reserve_synced_source_nat_allocation_for_worker` runs on every
// peer-synced forward upsert. Every cell below drives that real entry point.

/// Two rules over ONE pool name / addresses / port range — rule 0 `port
/// no-translation` (mints ADDRESS-ONLY reservations), rule 1 ordinary PAT.
/// `allocator_key()` matches, so they share one `PortAllocator`.
fn shared_notrans_pat_rules_6528(port_low: u16, port_high: u16) -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "notrans".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "shared-pool".to_string(),
            pool_addresses: vec!["203.0.113.1/32".to_string()],
            port_low,
            port_high,
            pool_no_translation: true,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "pat".to_string(),
            from_zone: "lan2".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "shared-pool".to_string(),
            pool_addresses: vec!["203.0.113.1/32".to_string()],
            port_low,
            port_high,
            ..SourceNATRuleSnapshot::default()
        },
    ])
}

fn snat_lookup_6528(
    rules: &[SourceNatRule],
    from_zone: &str,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
) -> SourceNatLookup {
    let mut counter = None;
    match_source_nat_result_for_tuple(
        rules,
        &NatScopeCtx::default(),
        from_zone,
        "wan",
        src_ip.parse().unwrap(),
        dst_ip.parse().unwrap(),
        Some(PROTO_TCP),
        src_port,
        dst_port,
        None,
        None,
        NS_PER_SEC,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    )
}

fn synced_pat_decision_6528(port: u16) -> NatDecision {
    NatDecision {
        rewrite_src: Some("203.0.113.1".parse().unwrap()),
        rewrite_src_port: Some(port),
        ..NatDecision::default()
    }
}

// FIXTURE GUARD, not a property: the two rules really do share one allocator, so
// the cross-flow cell below is testing the collision it claims to. If
// `allocator_key()` ever starts discriminating on `no_translation` this cell
// fails first and says why, instead of the collision cell silently going vacuous.
#[test]
fn notrans_and_pat_rules_share_one_allocator_6528() {
    let rules = shared_notrans_pat_rules_6528(40000, 40009);
    assert_eq!(
        rules[0].pool_allocator.debug_shared_identity(),
        rules[1].pool_allocator.debug_shared_identity(),
        "#6528 fixture: `port no-translation` and PAT rules over the same pool \
         name / addresses / port range must share ONE allocator — that sharing \
         is what makes the address-only eviction reach a PAT flow's bit"
    );
}

// #6528 FAIL-ON-REVERT (the headline). An address-only incumbent's eviction must
// not clear — or recycle — a LIVE PAT flow's occupancy bit.
//
// The pool is deliberately 2 ports wide so the consequence is observable end to
// end: `claim()` spends the fresh cursor first and only then drains the FIFO
// recycle queue, so once the cursor is spent the wrongly-recycled port is handed
// straight to the next flow while its real owner is still forwarding.
#[test]
fn synced_eviction_of_address_only_keeps_unrelated_pat_port_6528() {
    let rules = shared_notrans_pat_rules_6528(40000, 40001);
    // A PAT flow through rule 1 claims a real occupancy bit.
    let pat = expect_snat_decision(snat_lookup_6528(
        &rules, "lan2", "10.0.2.50", 55555, "8.8.8.8", 443,
    ));
    let pat_port = pat.rewrite_src_port.expect("PAT allocates a port");
    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, pat_port),
        "precondition: the PAT flow owns its bit"
    );

    // An ADDRESS-ONLY flow through rule 0 whose PRESERVED source port equals the
    // PAT flow's translated port. It claims NO occupancy bit.
    let ao = expect_snat_decision(snat_lookup_6528(
        &rules, "lan", "10.0.1.50", pat_port, "9.9.9.9", 443,
    ));
    assert_eq!(
        ao.rewrite_src_port, None,
        "precondition: `port no-translation` preserves the source port"
    );

    // The active re-decides that flow as PAT and syncs it: same flow key,
    // different translated tuple -> `reserve_flow` evicts the incumbent.
    let key = session_key_from_src("10.0.1.50", pat_port, "9.9.9.9", 443);
    let other_port = if pat_port == 40000 { 40001 } else { 40000 };
    reserve_synced_source_nat_allocation_for_worker(
        &rules,
        &key,
        synced_pat_decision_6528(other_port),
        false,
        None,
        NS_PER_SEC,
        0,
    );

    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, pat_port),
        "#6528: the evicted entry was ADDRESS-ONLY and owned no port bit, so \
         freeing (203.0.113.1, {pat_port}) clears a LIVE PAT flow's occupancy bit"
    );
    // ...and the damage that follows from clearing it.
    let fresh = snat_lookup_6528(&rules, "lan2", "10.0.2.51", 55556, "8.8.8.8", 443);
    let fresh_port = match fresh {
        SourceNatLookup::Matched(d) => d.rewrite_src_port,
        // The pool really is full — the correct outcome here.
        SourceNatLookup::Unavailable(_) | SourceNatLookup::NoMatch => None,
    };
    assert_ne!(
        fresh_port,
        Some(pat_port),
        "#6528: the wrongly-freed port is recycled, so the next flow is handed \
         a translated tuple another flow is still forwarding on"
    );
}

// #6528: an address-only incumbent's reverse-identity token must be cleared by
// the eviction. `release_flow` clears it and `rollback_flow` clears it;
// `reserve_flow` cleared it nowhere, so the token outlived the record that owned
// it and permanently denied that public identity.
#[test]
fn synced_eviction_of_address_only_clears_its_token_6528() {
    let rules = shared_notrans_pat_rules_6528(40000, 40009);
    let ao = expect_snat_decision(snat_lookup_6528(
        &rules, "lan", "10.0.1.50", 40005, "9.9.9.9", 443,
    ));
    assert_eq!(ao.rewrite_src_port, None);
    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        1,
        "precondition: the address-only flow minted one reverse-identity token"
    );

    let key = session_key_from_src("10.0.1.50", 40005, "9.9.9.9", 443);
    reserve_synced_source_nat_allocation_for_worker(
        &rules,
        &key,
        synced_pat_decision_6528(40009),
        false,
        None,
        NS_PER_SEC,
        0,
    );

    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        0,
        "#6528: the evicted address-only record no longer exists, so its \
         `address_only_owners` token must go with it — a leaked token denies \
         that public reverse identity for the life of the allocator"
    );
}

// #6528: a PERSISTENT incumbent's eviction must drop the lease refcount. This is
// the piece with NO reclamation path: `gc_expired_chunked` sweeps leases that are
// IDLE, and a lease whose `active_flows` never returns to zero is never idle, so
// it never enters `lease_expirations` at all.
#[test]
fn synced_eviction_drops_the_persistent_lease_refcount_6528() {
    let rules = notrans_persistent_rules(vec!["203.0.113.1/32"], "any-remote-host", 300, false);
    let now = NS_PER_SEC;
    let a = expect_snat_decision(notrans_persistent_lookup(
        &rules, "10.0.1.100", 40000, "8.8.8.8", 443, PROTO_TCP, now,
    ));
    assert_eq!(a.rewrite_src_port, None);
    {
        let live = rules[0].pool_allocator.debug_live();
        assert_eq!(
            live.persistent_by_source
                .values()
                .next()
                .expect("precondition: one lease")
                .active_flows,
            1,
            "precondition: the lease has one active flow"
        );
    }

    let key = session_key_from_src("10.0.1.100", 40000, "8.8.8.8", 443);
    reserve_synced_source_nat_allocation_for_worker(
        &rules,
        &key,
        synced_pat_decision_6528(40009),
        false,
        None,
        now,
        0,
    );

    let live = rules[0].pool_allocator.debug_live();
    assert_eq!(
        live.persistent_by_source
            .values()
            .next()
            .map(|l| l.active_flows),
        Some(0),
        "#6528: the evicted flow must drop its lease refcount — a leaked \
         refcount is never idle, so the lease never enters `lease_expirations` \
         and NO GC path can reclaim it"
    );
}

// #6528: a PERSISTENT PAT incumbent's port belongs to the LEASE. `release_flow`
// deliberately does not free it (the lease keeps the port/address until the
// lease itself is torn down) — and neither may the eviction, or the lease's port
// is handed out while the lease still claims it.
#[test]
fn synced_eviction_keeps_a_persistent_pat_lease_port_6528() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pat-persist".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "pp-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 40000,
        port_high: 40009,
        persistent_nat: true,
        persistent_nat_permit: "any-remote-host".to_string(),
        persistent_nat_inactivity_timeout: 300,
        ..SourceNATRuleSnapshot::default()
    }]);
    let d = expect_snat_decision(snat_lookup_6528(
        &rules, "lan", "10.0.1.100", 40000, "8.8.8.8", 443,
    ));
    let port = d.rewrite_src_port.expect("persistent PAT allocates a port");
    assert!(rules[0].pool_allocator.debug_is_port_occupied(0, port));

    let key = session_key_from_src("10.0.1.100", 40000, "8.8.8.8", 443);
    let synced_port = if port == 40009 { 40008 } else { 40009 };
    reserve_synced_source_nat_allocation_for_worker(
        &rules,
        &key,
        synced_pat_decision_6528(synced_port),
        false,
        None,
        NS_PER_SEC,
        0,
    );

    assert!(
        rules[0].pool_allocator.debug_is_port_occupied(0, port),
        "#6528: a persistent flow's port belongs to the lease, so the eviction \
         must not free it while the lease still holds the address"
    );
}

// #6528 ANTI-OVER-REACH GUARD: the ONE mode the pre-fix eviction got right must
// keep working. A plain non-persistent PAT incumbent DOES own its port outright,
// so the eviction must still free and recycle it. A "fix" that simply deleted
// the `free_translated_port` call would satisfy every cell above while leaking a
// pool port on every re-decided PAT flow.
//
// GREEN both before and after the fix: it constrains the SHAPE of the fix.
#[test]
fn synced_eviction_still_frees_a_plain_pat_port_6528() {
    let rules = shared_notrans_pat_rules_6528(40000, 40009);
    let pat = expect_snat_decision(snat_lookup_6528(
        &rules, "lan2", "10.0.2.50", 55555, "8.8.8.8", 443,
    ));
    let port = pat.rewrite_src_port.expect("PAT allocates a port");
    assert!(rules[0].pool_allocator.debug_is_port_occupied(0, port));

    let key = session_key_from_src("10.0.2.50", 55555, "8.8.8.8", 443);
    let synced_port = if port == 40009 { 40008 } else { 40009 };
    reserve_synced_source_nat_allocation_for_worker(
        &rules,
        &key,
        synced_pat_decision_6528(synced_port),
        false,
        None,
        NS_PER_SEC,
        0,
    );

    assert!(
        !rules[0].pool_allocator.debug_is_port_occupied(0, port),
        "#6528 must not stop freeing a PLAIN PAT port on eviction — that flow \
         owns its bit outright and nothing else will ever release it"
    );
    assert!(
        rules[0].pool_allocator.debug_recycled_ports(0).contains(&port),
        "#6528: and it is still RECYCLED (non-deterministic), so the pool does \
         not shrink by one port per re-decided flow"
    );
}
