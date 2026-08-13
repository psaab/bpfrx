// #6812: source-NAT AGGREGATE allocator budget at the apply boundary
// (opus-review-001 R73).
//
// The #5877 Go strict commit gate rejects an over-budget source-NAT config,
// but the TOLERANT load / peer-sync path only warns (#1960 no-brick) — and
// before this fix the Rust apply boundary then built every pool's
// per-address occupancy bitmap EAGERLY: `PortAllocator::new` ran for every
// pool-mode rule with `total_pool > 0` BEFORE the reuse maps were consulted
// and even when `pool_failure` was already set, with no aggregate cap at the
// final allocation boundary. Three full-range /16 pools materialise
// 12,683,575,296 bitmap bits (~1.48 GiB) — enough to stall or OOM the
// dataplane on an upgrade boot / HA convergence while processing the legacy
// config the tolerant path exists to recover.
//
// The fix defers allocator construction to `resolve_pool_allocators`:
// reuse-before-build, nothing for a failed pool, and the aggregate budget
// (pool count / total addresses / total port slots — mirroring the Go #5877
// constants) charged across the distinct keys an apply will hold live.
//
// The production budget (2^33 port slots) cannot be driven end-to-end in a
// unit test without allocating ~1 GiB of real bitmaps, so the WIRING tests
// inject a scaled-down budget via `parse_source_nat_rules_with_budget`
// (identical resolve path); the budget VALUES and the review's exact
// 12,683,575,296-slot scenario are pinned arithmetically with zero
// allocation in `real_budget_matches_go_5877_constants`.
//
// FAIL-ON-REVERT map (what goes RED if the fix is reverted):
// - gate removed: over_budget_pool_fails_closed_without_bitmap,
//   first_fit_continuation_admits_later_smaller_pool,
//   pool_count_budget_refused (refused rule comes back accepted, with a
//   real bitmap).
// - reuse-before-build reverted (build then maybe discard):
//   reuse_consumes_budget_and_preserves_last_good (allocator identity
//   changes on a same-config re-apply).
// - charge-new-only "simplification" (reuse free):
//   reuse_consumes_budget_and_preserves_last_good (the third pool is
//   admitted -> no OverBudget).
// - failed-pool skip reverted: failed_pool_builds_no_bitmap (occupancy
//   words come back non-zero).

#![allow(unused_imports)]

use super::allocator::TranslatedTuple;
use super::source::{
    SOURCE_NAT_AGGREGATE_BUDGET, SourceNatAggregateBudget, SourceNatAggregateUse,
    SourceNatFailureReason, parse_source_nat_rules_with_budget,
    parse_source_nat_rules_with_previous,
};
use super::*;
use crate::SourceNATRuleSnapshot;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Pool-mode snapshot fixture: one rule referencing `pool_name` with the
/// given members and an EXPLICIT port range (so the charge arithmetic is
/// exact and independent of the 1024-65535 default).
fn pool_snap(
    rule: &str,
    pool_name: &str,
    members: &[&str],
    port_low: u16,
    port_high: u16,
) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: rule.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: pool_name.to_string(),
        pool_addresses: members.iter().map(|m| m.to_string()).collect(),
        port_low,
        port_high,
        ..SourceNATRuleSnapshot::default()
    }
}

/// The scaled test budget: 200 port slots fits two 8-address x 10-port pools
/// (80 slots each) but not three.
const TEST_BUDGET: SourceNatAggregateBudget = SourceNatAggregateBudget {
    max_pools: 1024,
    max_addresses: 1_048_576,
    max_port_capacity: 200,
};

/// One 8-address (/29) pool member with a 10-port range => 80 port slots,
/// 8 occupancy words (div_ceil(10, 64) = 1 word per address).
const SMALL_POOL: &[&str] = &["203.0.113.0/29"];
const SMALL_LOW: u16 = 10000;
const SMALL_HIGH: u16 = 10009;

fn parse_with_test_budget(
    snaps: &[SourceNATRuleSnapshot],
    previous: Option<&[SourceNatRule]>,
) -> Vec<SourceNatRule> {
    parse_source_nat_rules_with_budget(snaps, previous, &NatCounterStore::default(), &TEST_BUDGET)
}

#[test]
fn over_budget_pool_fails_closed_without_bitmap() {
    let snaps = vec![
        pool_snap("r0", "p0", SMALL_POOL, SMALL_LOW, SMALL_HIGH),
        pool_snap("r1", "p1", SMALL_POOL, SMALL_LOW, SMALL_HIGH),
        pool_snap("r2", "p2", SMALL_POOL, SMALL_LOW, SMALL_HIGH),
    ];
    let rules = parse_with_test_budget(&snaps, None);
    assert_eq!(rules.len(), 3);

    // The two pools that fit install REAL allocators (8 addresses x 1 word).
    for (i, rule) in rules.iter().take(2).enumerate() {
        assert_eq!(
            rule.pool_failure, None,
            "rule {i} within budget must stay usable (no over-reject)"
        );
        assert_eq!(
            rule.pool_allocator.debug_occupancy_words(),
            8,
            "rule {i} within budget must materialise its bitmap"
        );
    }

    // The pool that crosses the budget fails CLOSED with a diagnostic and
    // materialised NO bitmap.
    assert_eq!(
        rules[2].pool_failure,
        Some(SourceNatFailureReason::OverBudget),
        "the pool crossing the aggregate budget must fail closed (revert: accepted)"
    );
    assert_eq!(
        rules[2].pool_allocator.debug_occupancy_words(),
        0,
        "a refused pool must NOT materialise an occupancy bitmap (the #6812 eager allocation)"
    );

    // The failure carries the dataplane diagnostic through the existing
    // exception plumbing: a flow hitting only this rule gets Unavailable,
    // never an untranslated forward.
    let lookup = match_source_nat_result(
        &rules[2..],
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().expect("src"),
        "8.8.8.8".parse().expect("dst"),
        None,
        None,
    );
    match lookup {
        SourceNatLookup::Unavailable(f) => {
            assert_eq!(f.reason, SourceNatFailureReason::OverBudget);
            assert_eq!(f.exception_reason(), "source_nat_pool_over_budget");
            assert_eq!(f.pool_name, "p2");
        }
        other => panic!("over-budget pool must fail closed at match, got {other:?}"),
    }

    // Counter-factual arithmetic pin: the pre-fix code charged NOTHING, so
    // the three pools would have summed 240 slots; the fix's admission
    // function refuses exactly the candidate that crosses 200.
    let charge = SourceNatAggregateUse {
        pools: 1,
        addresses: 8,
        port_capacity: 80,
    };
    let used_two = SourceNatAggregateUse {
        pools: 2,
        addresses: 16,
        port_capacity: 160,
    };
    assert_eq!(used_two.admitted_with(charge, &TEST_BUDGET), None);
    assert!(
        3 * 80 > TEST_BUDGET.max_port_capacity,
        "pre-fix sum 240 slots exceeds the budget the code now enforces"
    );
}

#[test]
fn reuse_consumes_budget_and_preserves_last_good() {
    // Apply 1: two pools fit (160 of 200 slots).
    let snaps_ab = vec![
        pool_snap("r0", "p0", SMALL_POOL, SMALL_LOW, SMALL_HIGH),
        pool_snap("r1", "p1", SMALL_POOL, SMALL_LOW, SMALL_HIGH),
    ];
    let apply1 = parse_with_test_budget(&snaps_ab, None);
    assert!(apply1.iter().all(|r| r.pool_failure.is_none()));
    let id0 = apply1[0].pool_allocator.debug_shared_identity();
    let id1 = apply1[1].pool_allocator.debug_shared_identity();

    // Apply 2: the SAME two pools plus a third. The reused keys consume
    // budget, so the third does not fit; last-good state is preserved
    // byte-identical (same Arc, no rebuild).
    let snaps_abc = vec![
        pool_snap("r0", "p0", SMALL_POOL, SMALL_LOW, SMALL_HIGH),
        pool_snap("r1", "p1", SMALL_POOL, SMALL_LOW, SMALL_HIGH),
        pool_snap("r2", "p2", SMALL_POOL, SMALL_LOW, SMALL_HIGH),
    ];
    let apply2 = parse_with_test_budget(&snaps_abc, Some(&apply1));

    assert_eq!(
        apply2[0].pool_allocator.debug_shared_identity(),
        id0,
        "a same-config re-apply must REUSE the previous allocator, not build a fresh bitmap"
    );
    assert_eq!(
        apply2[1].pool_allocator.debug_shared_identity(),
        id1,
        "a same-config re-apply must REUSE the previous allocator, not build a fresh bitmap"
    );
    assert_eq!(apply2[0].pool_failure, None);
    assert_eq!(apply2[1].pool_failure, None);
    assert_eq!(
        apply2[2].pool_failure,
        Some(SourceNatFailureReason::OverBudget),
        "reused keys CONSUME budget: 160 live + 80 new crosses 200 (a charge-new-only \
         variant would admit the third pool -> creep past the cap one apply at a time)"
    );
    assert_eq!(apply2[2].pool_allocator.debug_occupancy_words(), 0);
}

#[test]
fn failed_pool_builds_no_bitmap() {
    // A pool the control plane already poisoned (or that fails its own
    // grammar) must keep the EMPTY default allocator: no consumer can reach
    // it (the match path short-circuits on pool_failure), so building its
    // bitmap was pure waste — and on the tolerant path the poisoned pool is
    // exactly the oversized one.
    let snaps = vec![SourceNATRuleSnapshot {
        pool_unusable: true,
        pool_unusable_reason: "invalid_pool".to_string(),
        ..pool_snap("r0", "p0", SMALL_POOL, SMALL_LOW, SMALL_HIGH)
    }];
    let rules = parse_with_test_budget(&snaps, None);
    assert_eq!(
        rules[0].pool_failure,
        Some(SourceNatFailureReason::InvalidPool)
    );
    assert_eq!(
        rules[0].pool_allocator.debug_occupancy_words(),
        0,
        "a failed pool must not build an occupancy bitmap (revert: 8 words come back)"
    );

    // Wire-mapping pin: the Go tolerant poison reason maps to the dedicated
    // OverBudget variant (an old helper's catch-all maps it to InvalidPool —
    // still fail-closed — but THIS helper must give the precise diagnostic).
    let snaps = vec![SourceNATRuleSnapshot {
        pool_unusable: true,
        pool_unusable_reason: "aggregate_over_budget".to_string(),
        ..pool_snap("r0", "p0", SMALL_POOL, SMALL_LOW, SMALL_HIGH)
    }];
    let rules = parse_with_test_budget(&snaps, None);
    assert_eq!(
        rules[0].pool_failure,
        Some(SourceNatFailureReason::OverBudget),
        "the Go aggregate_over_budget poison must map to OverBudget"
    );
    assert_eq!(rules[0].pool_allocator.debug_occupancy_words(), 0);
}

#[test]
fn first_fit_continuation_admits_later_smaller_pool() {
    // p1 alone (8 addresses x 40 ports = 320 slots) exceeds the whole 200
    // budget; it is refused WITHOUT consuming budget, so the later small p2
    // still installs. Deterministic first-fit, maximal service preserved.
    let big_pool: &[&str] = &["203.0.113.0/29"];
    let snaps = vec![
        pool_snap("r0", "p0", SMALL_POOL, SMALL_LOW, SMALL_HIGH),
        pool_snap("r1", "p1-oversize", big_pool, 10000, 10039),
        pool_snap("r2", "p2", SMALL_POOL, SMALL_LOW, SMALL_HIGH),
    ];
    let rules = parse_with_test_budget(&snaps, None);
    assert_eq!(rules[0].pool_failure, None);
    assert_eq!(rules[0].pool_allocator.debug_occupancy_words(), 8);
    assert_eq!(
        rules[1].pool_failure,
        Some(SourceNatFailureReason::OverBudget),
        "a pool that alone exceeds the budget must be refused"
    );
    assert_eq!(rules[1].pool_allocator.debug_occupancy_words(), 0);
    assert_eq!(
        rules[2].pool_failure, None,
        "first-fit: a later pool that fits the remaining budget must still install"
    );
    assert_eq!(rules[2].pool_allocator.debug_occupancy_words(), 8);
}

#[test]
fn pool_count_budget_refused() {
    // The distinct-allocator COUNT budget trips independently of slots: 3
    // pools of 1 address x 1 port each against a max_pools of 2.
    let budget = SourceNatAggregateBudget {
        max_pools: 2,
        max_addresses: 1_048_576,
        max_port_capacity: 1 << 33,
    };
    let snaps = vec![
        pool_snap("r0", "p0", &["203.0.113.1/32"], 10000, 10000),
        pool_snap("r1", "p1", &["203.0.113.2/32"], 10000, 10000),
        pool_snap("r2", "p2", &["203.0.113.3/32"], 10000, 10000),
    ];
    let rules = parse_source_nat_rules_with_budget(
        &snaps,
        None,
        &NatCounterStore::default(),
        &budget,
    );
    assert_eq!(rules[0].pool_failure, None);
    assert_eq!(rules[1].pool_failure, None);
    assert_eq!(
        rules[2].pool_failure,
        Some(SourceNatFailureReason::OverBudget),
        "the third distinct allocator must trip the pool-count budget"
    );
    assert_eq!(rules[2].pool_allocator.debug_occupancy_words(), 0);
}

#[test]
fn failed_pool_status_reports_configured_port_range() {
    // #6812 status contract: a FAILED pool builds no allocator (empty
    // default), but the pool status view must still report the CONFIGURED
    // port range (carried on the rule), not the default allocator's
    // 1024-65535 — exactly the pools an operator is debugging must not lie
    // about their config. Pre-#6812 the eager (wasteful) build made this
    // true by accident; the rule-carried range keeps it true on purpose.
    let snaps = vec![SourceNATRuleSnapshot {
        pool_unusable: true,
        pool_unusable_reason: "aggregate_over_budget".to_string(),
        ..pool_snap("r0", "p0", SMALL_POOL, SMALL_LOW, SMALL_HIGH)
    }];
    let rules = parse_with_test_budget(&snaps, None);
    let statuses = source_nat_pool_statuses(&rules);
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].port_low, SMALL_LOW);
    assert_eq!(statuses[0].port_high, SMALL_HIGH);
    assert_eq!(statuses[0].address_count, 8);
    assert_eq!(
        statuses[0].max_tracked_flows, 0,
        "a failed pool has no allocator state behind the status view"
    );

    // A HEALTHY pool's status is unchanged: configured range plus real
    // allocator capacity.
    let snaps = vec![pool_snap("r0", "p0", SMALL_POOL, SMALL_LOW, SMALL_HIGH)];
    let rules = parse_with_test_budget(&snaps, None);
    let statuses = source_nat_pool_statuses(&rules);
    assert_eq!(statuses[0].port_low, SMALL_LOW);
    assert_eq!(statuses[0].port_high, SMALL_HIGH);
    assert!(
        statuses[0].max_tracked_flows > 0,
        "a healthy pool reports real allocator capacity"
    );
}

#[test]
fn real_budget_matches_go_5877_constants() {
    // Parity with pkg/config/compiler_validate_strict_nat.go — if either side
    // moves, this test and the Go gate must move together.
    assert_eq!(SOURCE_NAT_AGGREGATE_BUDGET.max_pools, 1024);
    assert_eq!(SOURCE_NAT_AGGREGATE_BUDGET.max_addresses, 1_048_576);
    assert_eq!(SOURCE_NAT_AGGREGATE_BUDGET.max_port_capacity, 1 << 33);

    // The review's exact scenario (opus-review-001 R73), arithmetically, with
    // ZERO allocation: three full-range /16 pools at the default 1024-65535
    // PAT range (65,536 addresses x 64,512 ports = 4,227,858,432 slots each).
    // Two fit under 2^33; the third crosses it — the pre-fix boundary built
    // all three bitmaps (12,683,575,296 bits, ~1.48 GiB).
    let per_pool = SourceNatAggregateUse {
        pools: 1,
        addresses: 65_536,
        port_capacity: 65_536 * 64_512,
    };
    assert_eq!(per_pool.port_capacity, 4_227_858_432);
    let used = SourceNatAggregateUse::default()
        .admitted_with(per_pool, &SOURCE_NAT_AGGREGATE_BUDGET)
        .expect("first full-range /16 pool fits");
    let used = used
        .admitted_with(per_pool, &SOURCE_NAT_AGGREGATE_BUDGET)
        .expect("second full-range /16 pool fits");
    assert_eq!(used.port_capacity, 8_455_716_864);
    assert!(
        used.admitted_with(per_pool, &SOURCE_NAT_AGGREGATE_BUDGET)
            .is_none(),
        "the third full-range /16 pool (12,683,575,296 slots cumulative) must be refused"
    );
    assert_eq!(
        3 * 4_227_858_432u64,
        12_683_575_296,
        "the review's 12,683,575,296-bit (~1.48 GiB) figure is the pre-fix sum this gate now refuses"
    );
}

// ---------------------------------------------------------------------------
// #6812 F-Q3: bind the PRODUCTION budget WIRING, not just the budget logic.
//
// Every test above drives `parse_source_nat_rules_with_budget` with
// `TEST_BUDGET` — an injected, scaled-down budget. Production calls
// `parse_source_nat_rules_with_previous`, which passes
// `&SOURCE_NAT_AGGREGATE_BUDGET`. Nothing bound THAT. Measured before these
// tests existed: leaving the constant untouched (so
// `real_budget_matches_go_5877_constants` still passes) and replacing only the
// budget the production entry forwards with
// `SourceNatAggregateBudget { max_pools: u64::MAX, max_addresses: u64::MAX,
// max_port_capacity: u64::MAX }` left `cargo test --release --bins nat::` at
// 273 passed, 0 failed — ZERO failures. The real budget could be swapped for an
// infinite one and the suite did not notice, because the parity test asserts
// the constant's VALUES and the `admitted_with` tests call the arithmetic
// directly; neither observes that production USES it.
//
// WHY THE POOL-COUNT AXIS. These two cross the real budget by DISTINCT POOL
// COUNT (`max_pools` = 1024), not by port capacity. Crossing
// `max_port_capacity` (2^33) honestly would mean materialising ~8.6 billion
// occupancy slots in a unit test — a test that is eventually deleted for being
// slow, and a guard nobody runs is not a guard. Pool count crosses a REAL
// budget exactly and costs almost nothing: 1024 single-address pools over a
// 10-port range is ~10,240 occupancy bits total. Do not "improve" these into
// the port-capacity form. `max_addresses` (1,048,576) and `max_port_capacity`
// stay far below their limits here, so the ONLY budget these fixtures cross is
// the pool count — the refusal cannot be attributed to another axis.

/// One pool-mode rule per distinct pool, each a single /32 with a 10-port
/// range: 1 pool + 1 address + 10 port slots of charge apiece.
fn one_address_pool_snaps_6812(count: usize) -> Vec<SourceNATRuleSnapshot> {
    (0..count)
        .map(|i| {
            let addr = format!("10.{}.{}.1/32", (i / 256) & 0xff, i % 256);
            pool_snap(
                &format!("r{i}"),
                &format!("p{i}"),
                &[addr.as_str()],
                10_000,
                10_009,
            )
        })
        .collect()
}

/// #6812 FAIL-ON-REVERT for the WIRING: the production entry must enforce the
/// REAL `SOURCE_NAT_AGGREGATE_BUDGET`, not merely be capable of enforcing some
/// budget handed to it.
///
/// RED when the budget the production entry forwards is widened (the severed-
/// wiring mutation above): the 1025th pool is admitted and its rule comes back
/// healthy instead of `OverBudget`.
#[test]
fn production_entry_enforces_the_real_pool_count_budget_6812() {
    let over = SOURCE_NAT_AGGREGATE_BUDGET.max_pools as usize + 1; // 1025
    let snaps = one_address_pool_snaps_6812(over);

    // The PRODUCTION entry — no injectable budget. This is the whole point.
    let rules =
        parse_source_nat_rules_with_previous(&snaps, None, &NatCounterStore::default());

    // --- PRECONDITION 1: the production path was actually entered and
    // returned a rule per snapshot. A fixture that never reached
    // parse_source_nat_rules_with_previous would otherwise pass silently —
    // the same class as the defect being closed here.
    assert_eq!(
        rules.len(),
        over,
        "the production entry did not return one rule per snapshot, so the fixture \
         never drove the path under test"
    );

    // --- PRECONDITION 2: pools BELOW the cap are healthy. This proves the
    // refusal below is a BUDGET refusal and not a wholesale parse failure
    // (a malformed fixture would fail every rule, and the reason assertion
    // would then be reporting something else entirely).
    assert!(
        rules[0].pool_failure.is_none(),
        "the first pool — far below every budget — failed with {:?}; the fixture is \
         malformed, so a refusal further down would prove nothing about the budget",
        rules[0].pool_failure
    );

    // --- THE DISCRIMINATOR: the pool that crosses max_pools is refused, and
    // refused for the BUDGET reason specifically.
    assert_eq!(
        rules[over - 1].pool_failure,
        Some(SourceNatFailureReason::OverBudget),
        "the {over}th distinct pool was admitted past the real \
         SOURCE_NAT_AGGREGATE_BUDGET.max_pools ({}); the production entry is not \
         forwarding the real budget, so the cap is enforced only in tests that \
         inject their own",
        SOURCE_NAT_AGGREGATE_BUDGET.max_pools
    );
}

/// #6812 OVER-REACH CONTROL, deliberately its own test body — a control that
/// shares a body with its binder never runs once the binder fails, so it can
/// never be observed to hold independently.
///
/// A config sitting exactly AT the pool-count budget must install completely.
/// This fails for its own reason: an off-by-one in the first-fit accounting, or
/// a production entry forwarding a budget SMALLER than the real one, refuses
/// the 1024th pool and reds here while leaving the binder above green. It stays
/// GREEN under the severed-wiring mutation (which only ever admits more), which
/// is what makes it a control rather than a restatement of the binder.
#[test]
fn production_entry_admits_a_config_at_the_real_pool_count_budget_6812() {
    let at = SOURCE_NAT_AGGREGATE_BUDGET.max_pools as usize; // 1024
    let snaps = one_address_pool_snaps_6812(at);

    let rules =
        parse_source_nat_rules_with_previous(&snaps, None, &NatCounterStore::default());

    assert_eq!(
        rules.len(),
        at,
        "the production entry did not return one rule per snapshot, so this control \
         is not controlling for anything"
    );
    let refused: Vec<&str> = rules
        .iter()
        .filter(|r| r.pool_failure == Some(SourceNatFailureReason::OverBudget))
        .map(|r| r.pool_name.as_str())
        .collect();
    assert!(
        refused.is_empty(),
        "a config sitting exactly AT the pool-count budget had {} pool(s) refused \
         ({:?}...): the cap is rejecting configs it must admit",
        refused.len(),
        &refused[..refused.len().min(3)]
    );
}
