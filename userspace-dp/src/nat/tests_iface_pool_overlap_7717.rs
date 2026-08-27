// #7717 DEFECT PIN — this file asserts a BUG, not a guarantee.
//
// Read the test name before the assertions: `defect_pin_*`. It asserts that a
// NAT pool and the interface-SNAT registry MINT THE SAME IDENTITY on one
// address. That is the wrong behaviour. It is pinned because #7717 has already
// been argued from prose twice — a dead lane's doc comment and a distilled plan
// brief — and both were wrong in different directions. A demonstrated defect
// cannot be re-litigated from prose.
//
// # CORRECTION: THIS TEST WILL *NOT* INVERT WHEN #7717 IS FIXED
//
// This block previously read "when #7717 is fixed, this test inverts... that
// failure is the SIGNAL THE FIX LANDED". **That is wrong for the mechanism
// §5.7 actually specifies, and a wrong done-signal is more expensive than no
// done-signal.**
//
// §5.7 forecloses the overlap at the SNAPSHOT BUILDER: an interface-mode
// egress address overlapping a pool marks that POOL unusable
// (`pool_failure`/`PoolUnusable`), and the dataplane drains the quarantined
// allocator. That prevents the colliding state from being reachable FROM
// CONFIG. It does not — and cannot — stop this file constructing it directly:
// the fixture below builds its rules with `parse_source_nat_rules` and a
// HEALTHY pool, never passing through the builder that would quarantine it.
// The assertion at the bottom of this file therefore keeps holding after a
// correct §5.7 lands.
//
// MEASURED, not predicted. The rescued PR-3b drain
// (`origin/rescue/6751-pr3b-drain-unvalidated`, 331 lines) applies cleanly to
// current master; applied whole, **this test still passes** — the collision
// still occurs. Its drain engages only when `rule.pool_failure.is_some()`, and
// nothing in the shipped tree sets that, because the Go snapshot-builder half
// is not written. So the Rust half is INERT ALONE, and adopting it as "the
// fix" would ship 331 lines of dataplane change that alter nothing observable.
//
// # The done-signal that IS correct
//
// The pair's acceptance control must drive the **snapshot builder**, not this
// unit-level pin: configure an interface-mode rule whose runtime-resolved
// egress address overlaps a pool, and assert the builder quarantines the pool
// AND that live sessions on it drain rather than strand. This file keeps its
// job — it pins that the two occupancy domains are independent *at the
// admission layer*, which stays true and stays worth guarding.
//
// # What bounds the design space (verified by symbol, for whoever builds it)
//
//   1. The substrates are NOT unifiable without an apply-path refactor.
//      `resolve_pool_allocators` (source.rs) takes only snapshot inputs and has
//      no access to the node-lifetime registry; pool allocators are owned BY
//      VALUE per `SourceNatPoolAllocatorKey`, interface allocators are
//      `Arc<PortAllocator>` per `IpAddr` (iface_registry.rs:115-116). Different
//      owner, different granularity, different lifetime.
//   2. Option (a)'s interface-side core ALREADY SHIPPED — the interface branch
//      calls `allocator_for`, fails closed on `InterfaceRegistryCap`, and PATs
//      later colliders via `allocate_interface_identity` (source.rs:2539-2588).
//      The remaining gap is purely CROSS-DOMAIN.
//   3. Neither half is a fix alone. The Rust drain is inert without the Go
//      quarantine (measured, above); the Go quarantine cannot ship enforcing
//      without the drain, because the merged config gate says so in its own
//      words — "marking a pool unusable with nothing draining would strand
//      live sessions" (pkg/config/compiler_nat_iface_egress.go).
//
// # The mechanism
//
// Pool mode and interface mode are SEPARATE occupancy structures keyed
// differently for the same address:
//
//   pool mode      -> `rule.pool_allocator`, keyed by `SourceNatPoolAllocatorKey`
//   interface mode -> `InterfaceNatAllocators`, keyed by `IpAddr`
//
// Neither consults the other, so the interface registry reports "uncontended"
// for a port the pool is actively using and preserves it.
//
// The config gate that forecloses this overlap
// (`pkg/config/compiler_nat_iface_egress.go`) states its own scope:
//
//   "This is CONFIG-time derivation only. Runtime-resolved addresses (DHCP,
//    netlink) are deliberately out of scope here — foreclosing those is the
//    snapshot-builder half of §5.7 and needs the DRAIN discipline behind it."
//
// So a runtime-learned egress address that overlaps a pool reaches this state.
#![allow(unused_imports)]

use super::allocator::NatHolder;
use super::source::SourceNatFlowKey;
use super::*;
use crate::SourceNATRuleSnapshot;
use std::net::IpAddr;

const E: &str = "172.16.80.8";
const SRV: &str = "172.16.80.200";
const TCP: u8 = 6;

fn admit(reg: &InterfaceNatAllocators, rules: &[SourceNatRule], src: &str, src_port: u16) -> SourceNatLookup {
    let mut counter = None;
    match_source_nat_result_for_tuple(
        reg,
        rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src.parse().expect("src"),
        SRV.parse().expect("dst"),
        Some(TCP),
        src_port,
        80,
        Some(E.parse().expect("egress")),
        None,
        1_000,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    )
}

fn wire(l: &SourceNatLookup, sent_port: u16) -> (Option<IpAddr>, u16) {
    match l {
        // checksum.rs uses `rewrite_src_port.unwrap_or(key.src_port)`, so an
        // unset port means the packet keeps its own — that is the wire tuple.
        SourceNatLookup::Matched(d) => (d.rewrite_src, d.rewrite_src_port.unwrap_or(sent_port)),
        other => panic!("admission did not match: {other:?}"),
    }
}

#[test]
fn defect_pin_pool_and_interface_snat_mint_one_identity_7717() {
    let pool_rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "P".to_string(),
        // The pool's ONLY address is also the interface-SNAT egress address.
        pool_addresses: vec![E.to_string()],
        ..SourceNATRuleSnapshot::default()
    }]);
    let iface_rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "iface-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    // The pool is HEALTHY, and that is load-bearing for the correction in this
    // file's header: §5.7 forecloses by QUARANTINING a pool
    // (`pool_failure`/`PoolUnusable`), so a fixture whose pool is quarantined
    // would be testing the post-fix state rather than the defect. Asserting it
    // here makes the property explicit instead of incidental — and it reds if
    // someone "fixes" this pin by quarantining the fixture, which is exactly
    // the shape of chasing a done-signal that was never going to arrive.
    assert!(
        pool_rules[0].pool_failure.is_none(),
        "#7717: the fixture's pool must be HEALTHY. A quarantined pool does not \
         demonstrate the cross-domain collision — it demonstrates the foreclosure \
         that §5.7 adds, which this unit-level pin cannot reach"
    );
    let reg = InterfaceNatAllocators::default();

    // Flow A, POOL mode. Stays live for the rest of the test.
    let (a_ip, a_port) = wire(&admit(&reg, &pool_rules, "10.0.0.1", 5555), 5555);

    // CONTROL — KNOWN ANSWER, and it is load-bearing.
    //
    // A second POOL flow must NOT reuse A's identity. This is what makes the
    // collision below a CROSS-DOMAIN finding rather than "the pool allocator is
    // broken". Without it, a future refactor that broke the pool allocator
    // would keep the collision assertion passing for a reason nobody intended,
    // and the pin would be satisfiable by a second, unrelated defect.
    let (_, a2_port) = wire(&admit(&reg, &pool_rules, "10.0.0.3", 5555), 5555);
    assert_ne!(
        a2_port, a_port,
        "CONTROL FAILED: two pool-mode flows were handed the same port ({a_port}). \
         The pool allocator is not correct within its own domain, so the collision \
         asserted below would not be evidence of a CROSS-DOMAIN defect. Fix this \
         before reading the assertion that follows."
    );

    // Flow B, INTERFACE mode, from a DIFFERENT internal host, sourcing exactly
    // the port the pool handed A.
    let (b_ip, b_port) = wire(&admit(&reg, &iface_rules, "10.0.0.2", a_port), a_port);

    assert_eq!(
        (b_ip, b_port),
        (a_ip, a_port),
        "#7717 appears FIXED — the interface mint no longer collides with the \
         live pool identity. That is the desired behaviour and this defect pin \
         has done its job: flip this file to assert NON-collision and rename it \
         off `defect_pin_`."
    );
}
