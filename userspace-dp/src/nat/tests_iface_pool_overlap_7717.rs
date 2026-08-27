// #7717 DEFECT PIN — this file asserts a BUG, not a guarantee.
//
// Read the test name before the assertions: `defect_pin_*`. It asserts that a
// NAT pool and the interface-SNAT registry MINT THE SAME IDENTITY on one
// address. That is the wrong behaviour. It is pinned because #7717 has already
// been argued from prose twice — a dead lane's doc comment and a distilled plan
// brief — and both were wrong in different directions. A demonstrated defect
// cannot be re-litigated from prose.
//
// # WHEN #7717 IS FIXED, THIS TEST INVERTS
//
// The collision assertion below will start failing. That failure is the SIGNAL
// THE FIX LANDED, not a regression. Whoever lands the fix should flip this file
// to assert non-collision and rename it off `defect_pin_`.
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
