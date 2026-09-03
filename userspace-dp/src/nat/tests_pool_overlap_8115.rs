// #8115 R1 — the ADDRESS-ONLY route to the pool-vs-pool duplicate identity.
//
// #6979 F6 (PR #8111) closed one route: a LOCAL, port-translating (PAT) mint
// may not publish a `(pool address, port)` a PEER pool's occupancy bitmap
// already holds. That check asks the bitmap, and the bitmap is only ONE of the
// two ownership tokens this allocator issues.
//
// A `port no-translation` flow, or a port-less protocol, takes the ADDRESS-ONLY
// path: it claims NO occupancy bit and instead owns an entry in
// `address_only_owners`, keyed by the full reverse identity
// `(protocol, translated ip, translated port, dst ip, dst port)`. The two
// spaces never met, so BOTH directions were open:
//
//   - a peer pool preserving `X:P` toward `R` did not stop a PAT mint of `X:P`
//     toward `R`;
//   - two address-only flows in DIFFERENT pools over one address collided
//     whenever protocol and remote matched.
//
// # Population
//
// Same as F6's, and verified rather than assumed: the Go #5144 gate
// (`validateNATPoolExternalTupleOverlapStrict`) rejects overlapping pools at
// commit on address overlap alone, so an overlapping config arrives only from
// the tolerant load / peer-sync path (`lenientCompileOpts`, wired at
// `configstore.Store` load and SyncApply). That path is real, and its own
// compiler doc records the part that makes this worth fixing: unlike
// `lenientNPTv6` / `lenientNAT64Prefix`, "the dataplane does NOT reject the
// overlapping snapshot — the overlap installs with a LATENT collision".
//
// # The two sub-questions are not equally precise
//
// The bitmap question is REMOTE-AGNOSTIC and the address-only question is
// REMOTE-SPECIFIC. The controls below are what hold that line: a peer
// address-only identity toward a DIFFERENT remote is not a wire collision and
// must still translate. Overlapping pools are a shape this dataplane
// deliberately supports, so nothing may stop translating that is not an actual
// duplicate.

use super::allocator::NatHolder;
use super::destination::PROTO_TCP;
use super::source::SourceNatRule;
use super::*;
use crate::SourceNATRuleSnapshot;
use std::net::IpAddr;

const SHARED: &str = "203.0.113.1";
const REMOTE: &str = "8.8.8.8";
const OTHER_REMOTE: &str = "9.9.9.9";

/// A PAT pool-mode rule. The ONE-port range makes "did the second flow get the
/// identity the first one holds" a yes/no question rather than a probability.
fn pat_rule(name: &str, pool: &str, source: &str) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec![source.to_string()],
        pool_name: pool.to_string(),
        pool_addresses: vec![format!("{SHARED}/32")],
        port_low: 20000,
        port_high: 20000,
        ..SourceNATRuleSnapshot::default()
    }
}

/// The address-only twin: `port no-translation` preserves the source port, so a
/// flow whose source port is 20000 puts the SAME wire identity on the link that
/// the PAT rule above mints.
fn notrans_rule(name: &str, pool: &str, source: &str) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        pool_no_translation: true,
        ..pat_rule(name, pool, source)
    }
}

fn mint_to(rules: &[SourceNatRule], src: &str, src_port: u16, dst: &str) -> SourceNatLookup {
    let mut counter = None;
    match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src.parse().expect("src"),
        dst.parse().expect("dst"),
        Some(PROTO_TCP),
        src_port,
        443,
        None,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    )
}

fn identity(lookup: &SourceNatLookup) -> Option<(IpAddr, Option<u16>)> {
    match lookup {
        SourceNatLookup::Matched(d) => d.rewrite_src.map(|ip| (ip, d.rewrite_src_port)),
        _ => None,
    }
}

fn failure_reason(lookup: &SourceNatLookup) -> Option<SourceNatFailureReason> {
    match lookup {
        SourceNatLookup::Unavailable(f) => Some(f.reason),
        _ => None,
    }
}

fn shared_ip() -> IpAddr {
    SHARED.parse().expect("shared")
}

/// DIRECTION A: a peer's preserved `X:P` must block a PAT mint of `X:P`.
///
/// Fires on: deleting the `peer_holds_address_only_identity` term from
/// `peer_owns_wire_identity`. The bitmap term alone answers `false` here —
/// pool `a` holds no occupancy bit at all — so the PAT mint publishes the
/// identity pool `a` is already preserving on the wire.
#[test]
fn an_address_only_peer_identity_blocks_a_pat_mint_8115() {
    let rules = parse_source_nat_rules(&[
        notrans_rule("r1", "a", "10.0.0.0/24"),
        pat_rule("r2", "b", "10.1.0.0/24"),
    ]);

    // Pool `a` preserves source port 20000 -> wire identity 203.0.113.1:20000.
    let first = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), None)),
        "fixture: the address-only rule must translate the ADDRESS and preserve \
         the port (rewrite_src_port None). If this minted a port, the rule is \
         not on the address-only path and the cell is measuring the PAT arm"
    );

    // Pool `b`'s PAT mint lands on the same address:port toward the same remote.
    let second = mint_to(&rules, "10.1.0.7", 33333, REMOTE);
    assert_eq!(
        failure_reason(&second),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "pool `b` published 203.0.113.1:20000 while pool `a` preserves that exact \
         wire identity toward the same remote. An address-only flow owns no \
         occupancy bit, so #6979 F6's bitmap query cannot see it and reports the \
         identity free (#8115 R1)"
    );
    assert_eq!(
        identity(&second),
        None,
        "and it must not translate at all — a refusal that still handed back a \
         decision would be the duplicate wearing a failure's shape"
    );
}

/// CONTROL for direction A, and the reason the address-only term is keyed on the
/// remote rather than on `(address, port)`.
///
/// The same two pools, the same preserved identity, a DIFFERENT remote. The
/// reverse conntrack index keys on the full tuple, so `X:P -> R` and
/// `X:P -> R'` are distinguishable and both must translate.
///
/// Fires on: widening the address-only term to ignore `dst_ip`/`dst_port` —
/// which is the obvious "make it match the bitmap's shape" simplification.
#[test]
fn an_address_only_peer_toward_another_remote_does_not_block_a_pat_mint_8115() {
    let rules = parse_source_nat_rules(&[
        notrans_rule("r1", "a", "10.0.0.0/24"),
        pat_rule("r2", "b", "10.1.0.0/24"),
    ]);

    let first = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), None)),
        "fixture: pool `a` preserves 203.0.113.1:20000 toward 8.8.8.8"
    );

    let second = mint_to(&rules, "10.1.0.7", 33333, OTHER_REMOTE);
    assert_eq!(
        identity(&second),
        Some((shared_ip(), Some(20000))),
        "a PAT mint toward a DIFFERENT remote is not a duplicate and must still \
         translate. Overlapping pools are a supported shape; a check that \
         refuses here stops translating traffic that never collided"
    );
}

/// DIRECTION B: two address-only pools over one address must not both mint one
/// identity.
///
/// Neither flow claims an occupancy bit, so this route is invisible to the
/// bitmap query in BOTH directions — it is the pure address-only collision.
///
/// Fires on: deleting the `peer_holds_address_only_identity` term. Each pool's
/// own `address_only_owners` map is empty of the other's tokens, so both mint.
#[test]
fn two_address_only_pools_do_not_both_mint_one_identity_8115() {
    let rules = parse_source_nat_rules(&[
        notrans_rule("r1", "a", "10.0.0.0/24"),
        notrans_rule("r2", "b", "10.1.0.0/24"),
    ]);

    let first = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), None)),
        "fixture: pool `a` takes the identity first"
    );

    let second = mint_to(&rules, "10.1.0.7", 20000, REMOTE);
    assert_eq!(
        failure_reason(&second),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "two address-only flows in different pools, same protocol, same preserved \
         port, same remote — one wire identity, two sessions, and replies the \
         reverse (1:N) index cannot attribute (#8115 R1)"
    );
}

/// CONTROL for direction B.
///
/// Same two address-only pools, different remotes. Both identities are distinct
/// on the wire and both must translate.
#[test]
fn two_address_only_pools_toward_different_remotes_both_mint_8115() {
    let rules = parse_source_nat_rules(&[
        notrans_rule("r1", "a", "10.0.0.0/24"),
        notrans_rule("r2", "b", "10.1.0.0/24"),
    ]);

    let first = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    assert_eq!(identity(&first), Some((shared_ip(), None)), "fixture");

    let second = mint_to(&rules, "10.1.0.7", 20000, OTHER_REMOTE);
    assert_eq!(
        identity(&second),
        Some((shared_ip(), None)),
        "a different remote is a different wire identity and must still translate"
    );
}

/// The common case: NO overlapping pools, so no index is built and the new term
/// is never consulted.
///
/// This is the cell that fails if the check is ever wired to something other
/// than `overlap_owners` — an unconditional query would refuse here too, since
/// the two pools' addresses differ and nothing shares an identity.
#[test]
fn non_overlapping_address_only_pools_are_untouched_8115() {
    let mut r2 = notrans_rule("r2", "b", "10.1.0.0/24");
    r2.pool_addresses = vec!["203.0.113.9/32".to_string()];
    let rules = parse_source_nat_rules(&[notrans_rule("r1", "a", "10.0.0.0/24"), r2]);

    let first = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    let second = mint_to(&rules, "10.1.0.7", 20000, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), None)),
        "pool `a` translates to its own address"
    );
    assert_eq!(
        identity(&second),
        Some(("203.0.113.9".parse::<IpAddr>().expect("other"), None)),
        "pool `b` translates to ITS own address — disjoint pools share no \
         identity and the peer query must not be reached at all"
    );
}

// ---------------------------------------------------------------------------
// Per-ARM coverage.
//
// The address-only mint has THREE arms — v4 round-robin/persistent, v6
// round-robin/persistent, and deterministic-v4 — each with its own reserve call
// and its own copy of the peer check. #6979 F6's own test file records the
// lesson: "removing the v6 call alone escapes all seven of them."
//
// Measured here rather than assumed. With only the v4 cells above, disabling
// the v6 arm's check and disabling the deterministic arm's check BOTH escaped
// the full 5143-test suite. These two cells are what closes that.

const SHARED_V6: &str = "2001:db8:ff::1";
const REMOTE_V6: &str = "2001:4860:4860::8888";

fn notrans_rule_v6(name: &str, pool: &str, source: &str) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec![source.to_string()],
        pool_name: pool.to_string(),
        pool_addresses: vec![format!("{SHARED_V6}/128")],
        port_low: 20000,
        port_high: 20000,
        pool_no_translation: true,
        ..SourceNATRuleSnapshot::default()
    }
}

/// ARM: the IPv6 address-only mint.
///
/// A separate arm of `match_source_nat_result_for_tuple` with its own reserve
/// call, so a check wired only into the v4 arm passes every cell above.
///
/// Fires on: removing the peer check from the v6 arm alone.
#[test]
fn two_address_only_v6_pools_do_not_both_mint_one_identity_8115() {
    let rules = parse_source_nat_rules(&[
        notrans_rule_v6("r1", "a", "2001:db8:1::/64"),
        notrans_rule_v6("r2", "b", "2001:db8:2::/64"),
    ]);

    let first = mint_to(&rules, "2001:db8:1::7", 20000, REMOTE_V6);
    assert_eq!(
        identity(&first),
        Some((SHARED_V6.parse::<IpAddr>().expect("v6"), None)),
        "fixture: the v6 address-only rule must translate the ADDRESS and \
         preserve the port"
    );

    let second = mint_to(&rules, "2001:db8:2::7", 20000, REMOTE_V6);
    assert_eq!(
        failure_reason(&second),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "the v6 address-only arm owes the same peer check as the v4 one — \
         without it two v6 pools over one address both preserve the identical \
         wire identity (#8115 R1)"
    );
}

/// ARM: the deterministic-v4 (CGNAT mode 1) address-only mint.
///
/// `port no-translation` on a deterministic pool takes a THIRD reserve call
/// (`reserve_address_only` on the deterministically chosen external address),
/// which the two arms above do not touch.
///
/// Fires on: removing the peer check from the deterministic arm alone.
#[test]
fn two_deterministic_address_only_pools_do_not_both_mint_one_identity_8115() {
    // 100.64.0.0 as a u32 — the deterministic subscriber host base.
    const HOST_BASE: u32 = (100 << 24) | (64 << 16);
    let det = |name: &str, pool: &str, source: &str| SourceNATRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec![source.to_string()],
        pool_name: pool.to_string(),
        pool_addresses: vec![format!("{SHARED}/32")],
        port_low: 1024,
        port_high: 65535,
        pool_no_translation: true,
        deterministic_mode: 1,
        deterministic_block_size: 512,
        deterministic_blocks_per_ip: 126,
        deterministic_host_base: HOST_BASE,
        deterministic_host_count: 1024,
        ..SourceNATRuleSnapshot::default()
    };
    // Both subscribers must fall inside `blocks_per_ip` (126) of the host base,
    // or the deterministic map has no block for them and the mint fails
    // `AllocatorExhausted` — a refusal that looks like a pass for the wrong
    // reason. Measured: `100.64.1.5` is subscriber index 261 and did exactly
    // that.
    let rules = parse_source_nat_rules(&[
        det("r1", "a", "100.64.0.5/32"),
        det("r2", "b", "100.64.0.6/32"),
    ]);
    assert!(
        rules[0].deterministic_v4.is_some() && rules[1].deterministic_v4.is_some(),
        "precondition: both mode-1 snapshots must build deterministic rules, or \
         this cell silently measures the round-robin arm it is not about"
    );

    let first = mint_to(&rules, "100.64.0.5", 20000, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), None)),
        "fixture: a deterministic pool with `port no-translation` translates the \
         ADDRESS and preserves the port"
    );

    let second = mint_to(&rules, "100.64.0.6", 20000, REMOTE);
    assert_eq!(
        failure_reason(&second),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "the deterministic address-only arm owes the same peer check — two \
         deterministic pools over one external address otherwise both preserve \
         the identical wire identity (#8115 R1)"
    );
}
