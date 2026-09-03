//! #8447: the source-NAT rule-match outcome counters.
//!
//! These exist to close the reading the admission pair left open. "Never
//! reached `allocate_translation`" is true whether the packet was refused
//! before allocation or never arrived at source-NAT at all, and the cluster
//! comparison could not separate those because both arms lose ICMP under a
//! pool. `consulted` is the quantity that separates them.
//!
//! Every cell asserts a DELTA across one call rather than an absolute. The
//! production counters are process-global, so an absolute assertion would fail
//! the moment any other test in this binary touched the match path — and it
//! would fail for a reason that has nothing to do with the property under test.

use super::allocator::NatHolder;
use super::*;
use crate::SourceNATRuleSnapshot;

const TCP: u8 = 6;
const EGRESS: &str = "172.16.80.8";
const SRV: &str = "172.16.80.200";

fn iface_rule() -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.61.0/24".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }
}

fn admit(rules: &[SourceNatRule], src: &str) -> SourceNatLookup {
    let reg = InterfaceNatAllocators::default();
    let mut counter = None;
    match_source_nat_result_for_tuple(
        &reg,
        rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src.parse().expect("src"),
        SRV.parse().expect("dst"),
        Some(TCP),
        40000,
        80,
        Some(EGRESS.parse().expect("egress")),
        None,
        1_000,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    )
}

fn delta(before: SourceNatMatchSnapshot, after: SourceNatMatchSnapshot) -> SourceNatMatchSnapshot {
    SourceNatMatchSnapshot {
        consulted: after.consulted - before.consulted,
        matched: after.matched - before.matched,
        unavailable: after.unavailable - before.unavailable,
        no_match: after.no_match - before.no_match,
    }
}

/// A packet that MATCHES a rule bumps `consulted` and `matched`, and nothing
/// else. The `consulted` half is the point: it is what makes a zero in the
/// other counters mean "nothing matched" rather than "nothing arrived".
#[test]
fn a_matching_packet_counts_consulted_and_matched_8447() {
    let rules = parse_source_nat_rules(&[iface_rule()]);
    let c = process_source_nat_match_counters();
    let before = c.snapshot();
    let out = admit(&rules, "10.0.61.50");
    assert!(
        matches!(out, SourceNatLookup::Matched(_)),
        "control: this fixture must actually match, got {out:?}"
    );
    let d = delta(before, c.snapshot());
    assert_eq!(d.consulted, 1, "the match path ran exactly once");
    assert_eq!(d.matched, 1);
    assert_eq!((d.unavailable, d.no_match), (0, 0));
}

/// A packet that matches NO rule still bumps `consulted`. Without that this
/// counter set could not distinguish "packets arrived and matched nothing"
/// from "no packets arrived" — the exact ambiguity #8447's cluster read left
/// open one layer down.
#[test]
fn a_non_matching_packet_still_counts_consulted_8447() {
    let rules = parse_source_nat_rules(&[iface_rule()]);
    let c = process_source_nat_match_counters();
    let before = c.snapshot();
    // Outside the rule's 10.0.61.0/24 source range.
    let out = admit(&rules, "192.0.2.7");
    assert!(
        matches!(out, SourceNatLookup::NoMatch),
        "control: this fixture must NOT match, got {out:?}"
    );
    let d = delta(before, c.snapshot());
    assert_eq!(
        d.consulted, 1,
        "#8447: a packet that matched nothing still REACHED source-NAT, and \
         that is the distinction these counters exist to make"
    );
    assert_eq!(d.no_match, 1);
    assert_eq!((d.matched, d.unavailable), (0, 0));
}

/// `consulted` must equal the sum of the three arms. A divergence means a
/// return path escaped the wrapper — which is a defect in the instrument, and
/// the instrument is the thing this issue now rests on.
#[test]
fn consulted_equals_the_sum_of_the_arms_8447() {
    let rules = parse_source_nat_rules(&[iface_rule()]);
    let c = process_source_nat_match_counters();
    let before = c.snapshot();
    let _ = admit(&rules, "10.0.61.51");
    let _ = admit(&rules, "192.0.2.8");
    let _ = admit(&rules, "10.0.61.52");
    let d = delta(before, c.snapshot());
    assert_eq!(d.consulted, 3, "three calls");
    assert_eq!(
        d.matched + d.unavailable + d.no_match,
        d.consulted,
        "every call must land in exactly one arm: {d:?}"
    );
}
