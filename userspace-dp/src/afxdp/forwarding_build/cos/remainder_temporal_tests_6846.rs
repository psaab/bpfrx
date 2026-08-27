//! #6846 remainder / temporal resolver cells for `forwarding_build::cos`.
//!
//! Split out of `cos.rs` because the inline module pushed that file past the
//! 1500 LOC modularity WATCH floor (`TestTouchedFileCrossedModularityThreshold`).
//! Loaded as a child module of `cos`, so `use super::*` still reaches the
//! private resolver functions these cells exist to pin — the split moves the
//! code, not its access.
//!
//! The BUILDER-level cells for the same issue deliberately live elsewhere, in
//! `forwarding_build/tests.rs`, next to the other `build_cos_state` cells: they
//! assert what a queue ends up with, which is a different layer from what the
//! resolver returns, and that separation is the whole point of #6846's F5.

use super::*;
use crate::CoSSchedulerMapEntrySnapshot;

/// A scheduler-map entry naming `sched` for `fc`.
fn entry(fc: &str, sched: &str) -> CoSSchedulerMapEntrySnapshot {
    CoSSchedulerMapEntrySnapshot {
        forwarding_class: fc.to_string(),
        scheduler: sched.to_string(),
        ..Default::default()
    }
}

fn absolute(name: &str, bytes: u64) -> CoSSchedulerSnapshot {
    CoSSchedulerSnapshot {
        name: name.to_string(),
        transmit_rate_bytes: bytes,
        ..Default::default()
    }
}

fn percent(name: &str, pct: f64) -> CoSSchedulerSnapshot {
    CoSSchedulerSnapshot {
        name: name.to_string(),
        transmit_rate_percent: pct,
        ..Default::default()
    }
}

fn remainder(name: &str) -> CoSSchedulerSnapshot {
    CoSSchedulerSnapshot {
        name: name.to_string(),
        transmit_rate_remainder: true,
        ..Default::default()
    }
}

fn resolve(
    scheds: &[CoSSchedulerSnapshot],
    entries: Vec<CoSSchedulerMapEntrySnapshot>,
    shaping: u64,
) -> Option<u64> {
    let map = CoSSchedulerMapSnapshot {
        name: "m".to_string(),
        entries,
    };
    let table: FastMap<String, &CoSSchedulerSnapshot> =
        scheds.iter().map(|s| (s.name.clone(), s)).collect();
    cos_remainder_rate_bytes(&map, &table, shaping)
}

/// The leftover is what the shaping rate has after RESOLVED siblings, and
/// a percent sibling must be counted at its resolved value rather than
/// skipped — a fixture with only absolute siblings cannot tell the two
/// apart, because both "resolve percent" and "ignore percent" leave an
/// absolute-only sum identical.
#[test]
fn remainder_subtracts_resolved_percent_siblings() {
    let scheds = [absolute("a", 200), percent("p", 10.0), remainder("r")];
    // shaping 1000, absolute 200, percent 10% = 100 -> leftover 700.
    let got = resolve(
        &scheds,
        vec![entry("fa", "a"), entry("fp", "p"), entry("fr", "r")],
        1000,
    );
    assert_eq!(
        got,
        Some(700),
        "a `percent` sibling must be subtracted at its RESOLVED value (10% of \
         1000 = 100), not skipped"
    );
}

/// THE SPLIT FLOORS, pinned with an INDIVISIBLE leftover.
///
/// An evenly-divisible fixture cannot distinguish floor, ceil, or
/// distribute-the-slack — all three agree there. 1000 - 1 = 999 across two
/// queues is 499 under floor and 500 under ceil, so this fixture separates
/// them; and a `leftover`-not-`leftover/n` implementation returns 999.
#[test]
fn cos_remainder_split_floors() {
    let scheds = [absolute("a", 1), remainder("r1"), remainder("r2")];
    let got = resolve(
        &scheds,
        vec![entry("fa", "a"), entry("f1", "r1"), entry("f2", "r2")],
        1000,
    );
    assert_eq!(
        got,
        Some(499),
        "999 across two remainder queues must FLOOR to 499 each. 500 means \
         ceiling (the two jointly over-claim the leftover they came from); \
         999 means the leftover was handed to each queue whole instead of split"
    );
}

/// Order-independence. A rate that depends on scheduler-map iteration
/// order passes a hundred runs before it does not, so it is asserted
/// rather than hoped for.
#[test]
fn remainder_is_order_independent() {
    let scheds = [absolute("a", 250), percent("p", 25.0), remainder("r")];
    let forward = resolve(
        &scheds,
        vec![entry("fa", "a"), entry("fp", "p"), entry("fr", "r")],
        1000,
    );
    let reversed = resolve(
        &scheds,
        vec![entry("fr", "r"), entry("fp", "p"), entry("fa", "a")],
        1000,
    );
    assert_eq!(
        forward, reversed,
        "the same config must resolve identically regardless of entry order"
    );
    assert_eq!(forward, Some(500), "1000 - 250 - 250 = 500");
}

/// A sibling that is ITSELF `remainder` claims the leftover rather than a
/// share of it, so it must contribute ZERO to the claimed sum. If it
/// contributed its own resolved value the computation would be circular.
#[test]
fn a_remainder_sibling_contributes_zero_to_the_claim() {
    let scheds = [remainder("r1"), remainder("r2")];
    let got = resolve(&scheds, vec![entry("f1", "r1"), entry("f2", "r2")], 1000);
    assert_eq!(
        got,
        Some(500),
        "with no absolute/percent siblings the whole shaping rate is the \
         leftover, split across the two remainder queues"
    );
}

/// A malformed scheduler carrying BOTH an absolute rate and `remainder`
/// must NOT be counted as a remainder queue.
///
/// The main path prefers absolute, so such a queue never uses the leftover
/// — counting it here would inflate the divisor and silently shrink every
/// real remainder queue's share. The two passes must agree about which
/// queues are remainder queues.
///
/// Reachable only on the lenient load / peer-sync path (#1960): the strict
/// commit gate rejects the combination. That is precisely where a
/// disagreement between two passes goes unnoticed.
#[test]
fn a_scheduler_with_both_forms_is_not_a_remainder_queue() {
    let mut both = remainder("both");
    both.transmit_rate_bytes = 400;
    let scheds = [both, remainder("r")];
    let got = resolve(&scheds, vec![entry("fb", "both"), entry("fr", "r")], 1000);
    assert_eq!(
        got,
        Some(600),
        "the both-forms queue resolves via its ABSOLUTE 400 and is not a \
         remainder queue, so the single real remainder queue takes the whole \
         600 leftover. 300 means it was counted as a remainder queue too, \
         halving every real remainder queue's share"
    );
}

/// Over-subscription leaves no leftover, so it does NOT resolve.
///
/// This asserted `Some(0)` in an earlier revision, on the reasoning that
/// "resolved to zero" and "could not resolve" are different facts an
/// operator needs told apart. The reasoning was right and the ENCODING was
/// wrong: zero is the dataplane's sentinel for "unshaped", so `Some(0)`
/// promoted the queue into guarantee service uncapped. The distinction now
/// lives in the ADVISORY WORDING, which is where it belonged.
#[test]
fn over_subscription_is_unresolvable() {
    let scheds = [absolute("a", 900), absolute("b", 400), remainder("r")];
    let got = resolve(
        &scheds,
        vec![entry("fa", "a"), entry("fb", "b"), entry("fr", "r")],
        1000,
    );
    assert_eq!(
        got, None,
        "siblings claiming MORE than the shaping rate leave no remainder, and \
         a share of nothing is not a rate: Some(0) reaches the token bucket as \
         the `unshaped/full bucket` sentinel, so the over-subscribed queue \
         would come out UNCAPPED rather than starved"
    );
}

/// No shaping rate is genuinely unresolvable: there is no base to take a
/// remainder of, and no port speed is available here to substitute.
#[test]
fn no_shaping_rate_is_unresolvable() {
    let scheds = [remainder("r")];
    assert_eq!(
        resolve(&scheds, vec![entry("fr", "r")], 0),
        None,
        "with no shaping rate the form must stay INERT (None), not resolve to \
         a fabricated zero"
    );
}

/// No remainder-marked queue means nothing to compute — and in particular
/// must not divide by zero.
#[test]
fn no_remainder_queue_yields_none() {
    let scheds = [absolute("a", 100)];
    assert_eq!(resolve(&scheds, vec![entry("fa", "a")], 1000), None);
}

/// `temporal` converts against the queue's RESOLVED rate.
#[test]
fn temporal_converts_against_the_resolved_rate() {
    // 1_000_000 bytes/sec for 1500us = 1500 bytes.
    assert_eq!(cos_temporal_buffer_bytes(1_000_000, 1_500), Some(1_500));
    // Ceiling, matching cos_percent_buffer_bytes.
    assert_eq!(cos_temporal_buffer_bytes(1_000_000, 1), Some(1));
    assert_eq!(cos_temporal_buffer_bytes(3, 1), Some(1), "floor of 1");
}

/// A queue with no resolved rate has no drain speed, so a microsecond
/// target has no byte value. Returning 0 would size the queue to nothing.
#[test]
fn temporal_without_a_rate_is_unresolvable() {
    assert_eq!(cos_temporal_buffer_bytes(0, 1_500), None);
    assert_eq!(cos_temporal_buffer_bytes(1_000_000, 0), None);
}

/// EXACT subscription leaves a ZERO leftover, and zero is a SENTINEL.
///
/// `types/cos.rs` states it: "transparent zero-rate queues use that value
/// to mean unshaped/full bucket". A `Some(0)` from the resolver therefore
/// arrives at the call site as `guarantee_enabled = true` with
/// `transmit_rate_bytes = 0` — promoting the queue into guarantee service
/// while the token bucket reads it as unshaped. That is the INVERSE of the
/// starved queue the design intended, and it needs no over-subscription:
/// `percent 60` + `percent 40` + `remainder` is an ordinary Junos idiom.
#[test]
fn zero_leftover_must_not_resolve() {
    let scheds = [percent("a", 60.0), percent("b", 40.0), remainder("r")];
    let got = resolve(
        &scheds,
        vec![entry("fa", "a"), entry("fb", "b"), entry("fr", "r")],
        1000,
    );
    assert_eq!(
        got, None,
        "an exactly-subscribed shape leaves NO leftover, so `remainder` has \
         nothing to resolve to. Some(0) would set guarantee_enabled while \
         transmit_rate_bytes=0 means `unshaped` to the token bucket — the \
         queue would be promoted into guarantee service AND uncapped"
    );
}

/// The CALL SITE must hand temporal the queue's transmit rate, not the
/// interface burst.
///
/// Every other temporal cell calls `cos_temporal_buffer_bytes` directly, so
/// none of them exercises `cos_scheduler_buffer_bytes` — and a converter
/// that is correct but wired to the wrong argument produces a plausible
/// number rather than a failure. Found by the mutation matrix: swapping
/// `transmit_rate_bytes` for `interface_burst_bytes` at the call site
/// escaped GREEN against the whole crate.
#[test]
fn temporal_call_site_uses_the_queue_rate_not_the_interface_burst() {
    let mut sched = CoSSchedulerSnapshot::default();
    sched.name = "s".to_string();
    sched.buffer_size_temporal_us = 1_000_000; // one second of drain
                                               // Distinct values so the two arguments cannot be confused: converting
                                               // against the RATE gives 700, against the BURST gives 90_000.
    let got = cos_scheduler_buffer_bytes(Some(&sched), 90_000, 700);
    assert_eq!(
        got, 700,
        "one second of drain must be computed from the queue's transmit rate \
         (700), not the interface burst (90_000) — the converter being right \
         does not make the call site right"
    );
}

/// `remainder` + `temporal` on ONE queue is LEGAL, and the ORDERING is the
/// property: temporal must convert against the rate remainder produced,
/// not against zero or the interface rate.
#[test]
fn remainder_then_temporal_on_one_queue() {
    let mut r = remainder("r");
    r.buffer_size_temporal_us = 1_000_000; // one second of drain
    let scheds = [absolute("a", 400), r.clone()];
    let rate = resolve(&scheds, vec![entry("fa", "a"), entry("fr", "r")], 1000)
        .expect("remainder must resolve");
    assert_eq!(rate, 600, "1000 - 400");
    assert_eq!(
        cos_temporal_buffer_bytes(rate, r.buffer_size_temporal_us),
        Some(600),
        "one second at the RESOLVED remainder rate is 600 bytes — using the \
         interface rate would give 1000, and using an unresolved zero would \
         give None"
    );
}
