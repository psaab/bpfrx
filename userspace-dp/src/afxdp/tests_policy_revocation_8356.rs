// #8356: fail-on-revert coverage for ZONE-POLICY re-derivation on the
// established-session hit path, driven through the REAL
// `poll_binding_process_descriptor` via `txn_run_descriptor`.
//
// Sibling of `tests_filter_revocation_7212.rs`, which does the same for the
// input FILTER. Read them together: this file exists because #7323 closed on
// accepting the ZONE-POLICY half as a residual, and the asymmetry — the tree
// tears down a live flow when a commit narrows a FILTER but not when it narrows
// POLICY — is what #8356 removes.
//
// WHY THESE DRIVE A REAL DESCRIPTOR. A direct call to
// `revalidate_zone_policy_on_session_hit` cannot see the stage deleted from the
// poll loop, and a packet-path change that is never called leaves every cell
// green and the box unchanged. That has cost this board an issue's worth of
// rework twice, most recently #8274.
//
// THE CELL THAT MATTERS MOST is `..._leaves_the_reverse_companion_alone_8356`,
// and it is the one place this feature deliberately does NOT mirror #7212.
// #7212's stamp is per-DIRECTION, correctly: an input filter is a per-interface
// object and each direction is judged against the interface its packet actually
// arrived on. Copying that here is catastrophic. The reverse companion is built
// with SWAPPED zones (`afxdp/shared_ops.rs`, `afxdp/poll_descriptor/mod.rs`),
// and this is a STATEFUL firewall: a reply is permitted because the session
// exists, not because a policy admits (to_zone -> from_zone). Re-derived
// per-direction it evaluates the reversed pair, matches nothing, hits
// `default_policy: deny`, and revokes — so EVERY established session in the box
// dies on the first packet after ANY commit.
//
// That cell only has power because the fixture's policy is ASYMMETRIC.
// `policy_deny_snapshot` permits dmz -> wan and denies by default, so the
// reversed pair genuinely has no rule. A symmetric or allow-all policy set
// would make the cell pass whether the gate exists or not — the "fixture that
// varies an axis but samples only the passing point" failure.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::session::{SessionDecision, SessionMetadata, SessionOrigin};
use crate::test_zone_ids::*;
use crate::{
    FirewallFilterSnapshot, FirewallTermSnapshot, InterfaceSnapshot, PolicyRuleSnapshot,
    RouteSnapshot,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::tcp_flags::TCP_ACK;

const LAN_IFINDEX: i32 = 24;
const WAN_IFINDEX: i32 = 12;
/// A MAC-less egress: routable, but absent from the unambiguous zone ledger.
const MACLESS_IFINDEX: i32 = 77;
const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const DST: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 200);
const SPORT: u16 = 12345;
const DPORT: u16 = 443;

/// `policy_deny_snapshot` permits `dmz -> wan` only, with `default_policy:
/// deny`. Adding a `lan -> wan` permit is the "policy admits this flow" state;
/// leaving it out is the "a commit narrowed policy" state. The ASYMMETRY is
/// load-bearing — see the header.
///
/// #9381: the rule's ACTION is a parameter, not a bool. `None` = no `lan -> wan`
/// rule at all (the narrowed-to-nothing state); `Some(action)` = the rule is
/// present carrying exactly that action. The bool form sampled the
/// TERMINAL-ACTION axis at two points — *present as `permit`* and *absent* — and
/// both agree with a revoke arm spelled `!matches!(.., Deny)`. `reject` is the
/// third point, and it is the one the collapsed arm got wrong: a non-forwarding
/// verdict that was re-stamped as revalidated and kept forwarding.
fn forwarding_with_lan_rule(lan_action: Option<&str>) -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    // #6722: `egress_zone_id` reads `ifindex_unambiguous_zone_id`, which
    // `populate_egress` fills only for interfaces with a resolvable link-layer
    // address. A MAC-less interface (the canonical case is an IPsec xfrmi
    // secure tunnel) is therefore ABSENT from it and its to-zone resolves to the
    // unknown sentinel 0 — the reachable form of "the egress does not resolve to
    // a zone".
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "st0.0".into(),
        zone: "wan".into(),
        linux_name: "st0".into(),
        ifindex: MACLESS_IFINDEX,
        mtu: 1400,
        tunnel: true,
        ..Default::default()
    });
    snapshot.routes.push(RouteSnapshot {
        table: "inet.0".into(),
        family: "inet".into(),
        destination: "198.51.100.0/24".into(),
        next_hops: vec!["st0.0".into()],
        discard: false,
        next_table: String::new(),
        preference: 0,
    });
    if let Some(action) = lan_action {
        snapshot.policies.push(PolicyRuleSnapshot {
            name: "lan-out".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: action.into(),
            ..Default::default()
        });
    }
    build_forwarding_state(&snapshot)
}

fn flow_key_to(dst: Ipv4Addr) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(SRC),
        dst_ip: IpAddr::V4(dst),
        src_port: SPORT,
        dst_port: DPORT,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// `egress_ifindex` is what the re-derivation resolves the TO-zone from. `0`
/// models the unresolvable case (a peer-synced import for an inactive RG keeps
/// `NoRoute`/0).
fn decision(egress_ifindex: i32) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex,
            tx_ifindex: egress_ifindex,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(DST)),
            neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    }
}

/// `is_reverse` and the zone pair are the two axes these cells vary. A REVERSE
/// companion carries the zones SWAPPED, which is the whole point of the trap
/// cell.
fn metadata(is_reverse: bool) -> SessionMetadata {
    let (ingress_zone, egress_zone) = if is_reverse {
        (TEST_WAN_ZONE_ID, TEST_LAN_ZONE_ID)
    } else {
        (TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID)
    };
    SessionMetadata {
        ingress_zone,
        egress_zone,
        ingress_ifindex: LAN_IFINDEX as u32,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

struct Outcome {
    sessions: SessionTable,
    revoked: u64,
}

/// Pre-install ONE established session — stamped UNVALIDATED, exactly what an
/// operator's commit leaves behind — then drive one packet of it through the
/// real poll body.
fn drive_one_packet(permit_lan: bool, is_reverse: bool, egress_ifindex: i32) -> Outcome {
    drive_one_packet_to(permit_lan, is_reverse, egress_ifindex, DST)
}

fn drive_one_packet_to(
    permit_lan: bool,
    is_reverse: bool,
    egress_ifindex: i32,
    dst: Ipv4Addr,
) -> Outcome {
    drive_one_packet_with_action(permit_lan.then_some("permit"), is_reverse, egress_ifindex, dst)
}

/// #9381: the same driver, taking the `lan -> wan` rule's ACTION rather than a
/// present/absent bool, so the three terminal actions are reachable from one
/// path through the REAL poll body.
fn drive_one_packet_with_action(
    lan_action: Option<&str>,
    is_reverse: bool,
    egress_ifindex: i32,
    dst: Ipv4Addr,
) -> Outcome {
    let forwarding = forwarding_with_lan_rule(lan_action);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();

    let mut sessions = SessionTable::new();
    assert!(
        sessions.install_with_protocol_with_origin(
            flow_key_to(dst),
            decision(egress_ifindex),
            metadata(is_reverse),
            SessionOrigin::ForwardFlow,
            122_000_000_000,
            PROTO_TCP,
            0,
        ),
        "the fixture must install the session, or every assertion below is vacuous"
    );

    let frame = build_txn_tcp_syn_frame_v4(SRC, dst, SPORT, DPORT, TCP_ACK);
    let meta = txn_meta_v4(LAN_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    Outcome {
        sessions,
        revoked: dbg.policy_revoked_sessions,
    }
}

fn session_count(sessions: &SessionTable) -> usize {
    let mut n = 0;
    sessions.iter_with_origin(|_k, _d, _m, _o| n += 1);
    n
}

/// THE FEATURE, AND THE WIRING. A session established under an older policy must
/// be revoked on its next packet once policy no longer permits the flow.
///
/// Dies if the re-derivation is built but never called from the poll loop.
#[test]
fn a_narrowed_zone_policy_revokes_the_established_session_8356() {
    let out = drive_one_packet(false, false, WAN_IFINDEX);
    assert_eq!(
        out.revoked, 1,
        "an established lan -> wan session must be revoked once policy stops \
         permitting it. 0 means the poll loop never called the re-derivation — \
         the state in which every direct-call cell is still green (#8356)"
    );
    assert_eq!(
        session_count(&out.sessions),
        0,
        "revocation must actually remove the session, not merely count itself"
    );
}

/// THE CONTROL that gives the cell above its aim. The SAME packet, the SAME
/// path, policy PERMITTING: nothing may be revoked.
///
/// Without this, a re-derivation that revoked unconditionally would satisfy the
/// deny cell perfectly.
#[test]
fn a_still_permitted_flow_survives_the_re_derivation_8356() {
    let out = drive_one_packet(true, false, WAN_IFINDEX);
    assert_eq!(
        out.revoked, 0,
        "policy still permits lan -> wan, so nothing may be revoked. A \
         re-derivation that denied unconditionally would pass the deny cell and \
         fail here (#8356)"
    );
    assert_eq!(
        session_count(&out.sessions),
        1,
        "the permitted session — and its NAT translation, since a \
         purged-and-recreated permitted SNAT flow reinstalls on a DIFFERENT \
         translated port and breaks — must be untouched"
    );
}

/// THE TRAP. A REVERSE companion carries SWAPPED zones, so re-deriving policy on
/// it evaluates (wan -> lan), which this asymmetric fixture does not permit and
/// `default_policy: deny` therefore denies.
///
/// Policy here PERMITS the flow's real direction. Nothing may be revoked.
/// Deleting the `is_reverse` gate reds this and nothing else — and on a real box
/// that deletion kills every established session on the first packet after any
/// commit.
#[test]
fn a_re_derivation_leaves_the_reverse_companion_alone_8356() {
    let out = drive_one_packet(true, true, WAN_IFINDEX);
    assert_eq!(
        out.revoked, 0,
        "the reverse companion must NEVER be independently policy-adjudicated. \
         Its zones are SWAPPED, so evaluating it asks whether policy permits \
         (wan -> lan) — which no ordinary one-way policy set does. This is a \
         STATEFUL firewall: the reply is permitted because the session exists. \
         A non-zero count here means every established session in the box dies \
         on the first packet after any commit (#8356)"
    );
    assert_eq!(
        session_count(&out.sessions),
        1,
        "the reverse companion must survive"
    );
}

/// #9381: THE THIRD TERMINAL ACTION. `PolicyAction` is `Permit`/`Deny`/`Reject`,
/// and the revoke arm used to be spelled `!matches!(result.action, Deny)` — so a
/// `Reject` verdict took the PERMIT exit, re-stamped the session as revalidated,
/// and every established session admitted by the rule the operator just narrowed
/// to `reject` kept forwarding in both directions until idle timeout.
///
/// Its control is the cell BELOW, not the `permit` cell above: `permit` and
/// *absent* are the two points the old bool fixture already sampled, and both
/// agree with the collapsed arm. The pair that binds the DIRECTION is
/// `reject` -> revoked and `permit` -> survives, driven through the SAME
/// `drive_one_packet_with_action` path so the only thing that differs between
/// them is the rule's action string.
///
/// Reverting to `!matches!(.., Deny)` reds this cell and nothing else.
#[test]
fn a_narrowed_to_reject_zone_policy_revokes_the_established_session_9381() {
    let out = drive_one_packet_with_action(Some("reject"), false, WAN_IFINDEX, DST);
    assert_eq!(
        out.revoked, 1,
        "a `reject` verdict is TERMINAL NON-FORWARDING, exactly as admission \
         treats it (`reject_reply.rs` drops the first packet). 0 here means the \
         revoke arm collapsed `Reject` into the permit exit and RE-STAMPED the \
         session, so every flow admitted by a rule the operator just narrowed \
         `permit` -> `reject` keeps forwarding until idle timeout and no later \
         packet of the generation re-asks (#9381)"
    );
    assert_eq!(
        session_count(&out.sessions),
        0,
        "a reject-narrowed session must actually be torn down, not merely counted"
    );
}

/// THE CONTROL for the cell above, and the one that has to stay green: the SAME
/// driver, the SAME packet, the rule present as `permit`.
///
/// Without it, widening the arm to "revoke on anything that is not Deny" — or to
/// "revoke unconditionally" — would satisfy the `reject` cell perfectly while
/// tearing down every permitted session in the box on the first packet after any
/// commit. That is a strictly worse bug than the one #9381 fixes, so the pair is
/// what makes the fix falsifiable rather than the reject cell alone.
#[test]
fn a_permit_rule_still_survives_the_widened_revoke_predicate_9381() {
    let out = drive_one_packet_with_action(Some("permit"), false, WAN_IFINDEX, DST);
    assert_eq!(
        out.revoked, 0,
        "the rule is `permit`; widening the revoke predicate must not touch it. \
         A non-zero count means the predicate now revokes on a PERMIT, i.e. every \
         established session dies on the first packet after any commit (#9381)"
    );
    assert_eq!(
        session_count(&out.sessions),
        1,
        "the permitted session and its NAT translation must be untouched"
    );
}

/// The `deny` point of the same three-way axis, driven through the action-taking
/// path rather than the bool one.
///
/// It is not redundant with `a_narrowed_zone_policy_revokes_the_established_
/// session_8356`: that cell narrows the rule to ABSENT and revokes via the
/// implicit `default_policy: deny`, which is a different code path through
/// `evaluate_policy_result_with_icmp` (the default-counter exit, not
/// `try_match_rule`). This one revokes on an EXPLICIT matched `deny` rule, so the
/// three actions are all sampled on the matched-rule path.
#[test]
fn an_explicit_deny_rule_revokes_the_established_session_9381() {
    let out = drive_one_packet_with_action(Some("deny"), false, WAN_IFINDEX, DST);
    assert_eq!(
        out.revoked, 1,
        "an explicitly matched `deny` rule must revoke, the same as the \
         implicit default-deny does"
    );
    assert_eq!(session_count(&out.sessions), 0);
}

/// An egress that does not resolve to a zone yields the sentinel 0, against
/// which policy matches no rule and the flow falls to `default_policy: deny`.
/// That is a LOOKUP FAILURE, not a verdict.
///
/// It is a REACHABLE state, not a hypothetical: a peer-synced import for an
/// INACTIVE redundancy group keeps its incoming `NoRoute` / `egress_ifindex ==
/// 0` resolution, because `session_glue/commands/upsert_synced.rs` overwrites
/// the resolution only when the re-resolved disposition is not `HAInactive`.
/// Treating it as a deny would revoke exactly the standby population this
/// feature protects, at the moment of promotion — a mass teardown at failover,
/// which is the outcome #7323 chose option B to avoid.
#[test]
fn an_unresolvable_egress_declines_rather_than_denying_8356() {
    // 198.51.100.77 is outside every connected subnet in the fixture and has
    // no route, so the egress genuinely does not resolve — the poll path
    // RE-RESOLVES a session's decision on a hit, so an entry merely INSTALLED
    // with `egress_ifindex: 0` is not enough to reach this state.
    let out = drive_one_packet_to(false, false, MACLESS_IFINDEX, Ipv4Addr::new(198, 51, 100, 77));
    assert_eq!(
        out.revoked, 0,
        "an egress that resolves to no zone must DECLINE, not deny. Note this \
         fixture does NOT permit the flow — so a re-derivation that treated the \
         unknown-zone sentinel as a verdict would revoke here, and that is \
         exactly the mass-teardown-at-failover this asserts against (#8356)"
    );
    assert_eq!(
        session_count(&out.sessions),
        1,
        "the session must survive an egress the node cannot yet resolve"
    );
}

// ---------------------------------------------------------------------------
// #8618: the ICMP half of the #7323 residual.
//
// #8356 declined ICMP outright: a zone policy can match icmp type/code via a
// junos-ping-style application term (#3020), so where such a term exists the
// verdict is a property of the PACKET and a frame-independent derivation has no
// type to offer. #8618 narrows that decline to the case the reasoning describes
// — `packet_icmp` is read in exactly ONE arm of `CompiledApplications::matches`
// (`icmp_constraints`), so with no type-constrained PERMIT in the snapshot a
// type-blind evaluation is not a guess, it is the same answer.
//
// THE PAIR THAT MATTERS is `..._revokes_an_established_icmp_session_8618` and
// `..._a_type_constrained_permit_declines_8618`. Their fixtures are IDENTICAL
// but for one junos-ping permit, so together they bind the gate's DIRECTION.
// Either alone is satisfied by a constant: "always revoke" passes the first,
// "always decline" (i.e. #8356 unchanged, the revert) passes the second.
//
// The first is also the POSITIVE CONTROL for the whole group: if the ICMP
// session key or meta were wrong the packet would never find the session, and
// every "declines" assertion below would pass vacuously on a session that was
// never a candidate.

use crate::PolicyApplicationSnapshot;

const ICMP_ID: u16 = 0x1234;

/// `parse_flow_ports` keys an identifier-bearing ICMP query as (identifier, 0);
/// `build_icmp_echo_frame_v4` stamps identifier 0x1234.
fn icmp_flow_key() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        src_ip: IpAddr::V4(SRC),
        dst_ip: IpAddr::V4(DST),
        src_port: ICMP_ID,
        dst_port: 0,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// A junos-ping-shaped PERMIT: an ICMP application term carrying an echo-request
/// TYPE constraint, which is what `icmp_constraints` (#3020) is populated from.
///
/// Deliberately on a DIFFERENT zone pair (`dmz -> wan`) than the flow under
/// test. The #8618 predicate is whole-snapshot, so this documents the
/// coarseness as a property rather than leaving it to be discovered: one
/// type-constrained permit anywhere declines ICMP box-wide. That is #8356's
/// behaviour, i.e. the conservative direction.
fn junos_ping_permit() -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: "ping-elsewhere".into(),
        from_zone: "dmz".into(),
        to_zone: "wan".into(),
        source_addresses: vec!["any".into()],
        destination_addresses: vec!["any".into()],
        applications: vec!["junos-ping".into()],
        application_terms: vec![PolicyApplicationSnapshot {
            name: "junos-ping".into(),
            protocol: "icmp".into(),
            source_port: String::new(),
            destination_port: String::new(),
            icmp_type: Some(8),
            icmp_code: None,
            inactivity_timeout: None,
        }],
        action: "permit".into(),
        ..Default::default()
    }
}

fn drive_one_icmp_packet(permit_lan: bool, with_type_constrained_permit: bool) -> Outcome {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    if permit_lan {
        snapshot.policies.push(PolicyRuleSnapshot {
            name: "lan-out".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            // `application any` matches every ICMP message regardless of type,
            // so a verdict resting on it is a FLOW property.
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: "permit".into(),
            ..Default::default()
        });
    }
    if with_type_constrained_permit {
        snapshot.policies.push(junos_ping_permit());
    }
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();

    let mut sessions = SessionTable::new();
    assert!(
        sessions.install_with_protocol_with_origin(
            icmp_flow_key(),
            decision(WAN_IFINDEX),
            metadata(false),
            SessionOrigin::ForwardFlow,
            122_000_000_000,
            PROTO_ICMP,
            0,
        ),
        "the fixture must install the ICMP session, or every assertion is vacuous"
    );

    let frame = build_icmp_echo_frame_v4(SRC, DST, 64);
    let mut meta = txn_meta_v4(LAN_IFINDEX as u32, 0, frame.len() as u16);
    meta.protocol = PROTO_ICMP;
    meta.payload_offset = 42;
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    Outcome {
        sessions,
        revoked: dbg.policy_revoked_sessions,
    }
}

/// THE FEATURE. An established ICMP session whose flow the live policy no longer
/// permits is revoked — the half of #7323's residual #8356 left open.
///
/// Also the POSITIVE CONTROL for this group: a wrong ICMP key or meta shows up
/// here as revoked == 0, rather than silently making the "declines" cells pass
/// on a session the packet never reached.
#[test]
fn a_narrowed_zone_policy_revokes_an_established_icmp_session_8618() {
    let out = drive_one_icmp_packet(false, false);
    assert_eq!(
        out.revoked, 1,
        "an ICMP session the live policy denies must be revoked once no \
         type-constrained permit makes the verdict packet-dependent"
    );
    assert_eq!(
        session_count(&out.sessions),
        0,
        "the revoked ICMP session must be torn down, not merely counted"
    );
}

/// THE HONESTY GATE, and the direction that must never regress. Same fixture as
/// above plus ONE junos-ping permit: the type-blind derivation could now be
/// wrong, so it must decline rather than revoke.
///
/// If this ever fails, the box is tearing down live ICMP flows on a verdict it
/// could not derive — strictly worse than the residual #8618 set out to close.
#[test]
fn a_type_constrained_permit_declines_the_icmp_re_derivation_8618() {
    let out = drive_one_icmp_packet(false, true);
    assert_eq!(
        out.revoked, 0,
        "with a junos-ping permit in the snapshot the verdict may depend on the \
         icmp type, which this derivation does not have — it must decline"
    );
    assert_eq!(
        session_count(&out.sessions),
        1,
        "the declined ICMP session must survive, exactly as under #8356"
    );
}

/// A still-permitted ICMP flow is not revoked. Guards the blanket-revocation
/// failure the reverse-companion cell guards for TCP.
#[test]
fn a_still_permitted_icmp_flow_survives_the_re_derivation_8618() {
    let out = drive_one_icmp_packet(true, false);
    assert_eq!(
        out.revoked, 0,
        "policy still permits this ICMP flow; re-deriving must not revoke it"
    );
    assert_eq!(session_count(&out.sessions), 1);
}

/// The predicate is PER PROTOCOL, and this is the only cell that can see it.
/// The three above all run over ICMPv4, so swapping the two slots — or collapsing
/// them to one bool — leaves every one of them green while an ICMPv6 flow starts
/// declining (or, worse, stops declining) for a v4-only junos-ping permit.
#[test]
fn the_type_constrained_predicate_is_per_protocol_8618() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.policies.push(junos_ping_permit()); // protocol "icmp" = v4 only
    let forwarding = build_forwarding_state(&snapshot);
    assert!(
        forwarding
            .policy
            .icmp_verdict_may_depend_on_type(PROTO_ICMP),
        "a v4 junos-ping permit must make the ICMPv4 verdict type-dependent"
    );
    assert!(
        !forwarding
            .policy
            .icmp_verdict_may_depend_on_type(PROTO_ICMPV6),
        "an ICMPv4-only constraint must NOT decline ICMPv6 — the slots are \
         independent"
    );
    assert!(
        !forwarding.policy.icmp_verdict_may_depend_on_type(PROTO_TCP),
        "a non-ICMP protocol can never be type-dependent"
    );
}

/// Binds the `PolicyAction::Permit` filter on the #8618 arming, which an
/// escaped mutation showed nothing else could see.
///
/// Only a PERMIT can overturn a type-blind DENY. A type-constrained DENY that
/// `packet_icmp = None` gates OFF can only make the walk fall through to a
/// later permit — i.e. more permissive, "do not revoke", which is the residual
/// staying open exactly as it does today. It can never manufacture the false
/// DENY the gate exists to prevent, so arming on it would decline for no reason
/// and leave #7323's residual open on configs that never needed it.
///
/// Dropping `&& matches!(.., Permit)` from the arming loop leaves every other
/// #8618 cell green; this one goes red.
#[test]
fn a_type_constrained_deny_does_not_suppress_the_icmp_re_derivation_8618() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    // A junos-ping-shaped DENY, and NO type-constrained permit anywhere.
    let mut ping_deny = junos_ping_permit();
    ping_deny.name = "ping-deny".into();
    ping_deny.action = "deny".into();
    snapshot.policies.push(ping_deny);
    let forwarding = build_forwarding_state(&snapshot);

    assert!(
        !forwarding
            .policy
            .icmp_verdict_may_depend_on_type(PROTO_ICMP),
        "a type-constrained DENY cannot manufacture a false DENY, so it must \
         NOT make the verdict type-dependent"
    );

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        icmp_flow_key(),
        decision(WAN_IFINDEX),
        metadata(false),
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_ICMP,
        0,
    ));
    let frame = build_icmp_echo_frame_v4(SRC, DST, 64);
    let mut meta = txn_meta_v4(LAN_IFINDEX as u32, 0, frame.len() as u16);
    meta.protocol = PROTO_ICMP;
    meta.payload_offset = 42;
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(
        dbg.policy_revoked_sessions, 1,
        "a type-constrained DENY must not suppress the re-derivation — the \
         residual would stay open on configs that never needed it"
    );
}

// ---------------------------------------------------------------------------
// #9382: the re-derivation must judge the POST-TRANSLATION destination, the
// same tuple admission judges (#2345/#2358).
//
// Admission evaluates zone policy on `policy_dst_ip` / `policy_dst_port` —
// `effective_resolution_target` plus the pre-routing DNAT's rewritten port —
// whose own comment states it "carries the correct post-translation tuple for
// all inbound destination translations (DNAT/static-DNAT/NPTv6/NAT64)". The
// re-derivation evaluated `flow.dst_ip` / `flow.forward_key.dst_port`, i.e. the
// WIRE tuple, because the forward session is installed on the WIRE key. For any
// session with an inbound destination translation the two sites therefore asked
// DIFFERENT QUESTIONS about the same session.
//
// The dominant consequence is FAIL-CLOSED and needs no crafted config: a
// published service whose permit names the real server is revoked and its packet
// dropped on the first flow-cache miss, with the policy completely unchanged.
// Flow-cache misses are not rare — `PublishRouteOverlaySnapshot` bumps the
// config generation for a ROUTE-ONLY publish, and the rtnetlink route listener
// calls it on kernel route changes, so ordinary BGP/OSPF churn is enough. A
// session also installs with `policy_revalidated_gen: 0`, so an eviction alone
// suffices with no generation change at all.
//
// WHY THESE ARE TWO-PHASE. The pre/post-translation distinction only exists for
// a session that HAS a translation, and the only honest way to get one is to let
// the production path admit it: phase 1 drives the real SYN through
// `txn_run_descriptor` (session MISS -> policy -> NAT -> forward+reverse
// install), phase 2 drives one more packet of that same flow on a FRESH binding.
// A fresh binding is an EMPTY FLOW CACHE, which is exactly what a generation
// bump leaves behind, and it is what makes phase 2 reach the session-hit path at
// all rather than replaying a cached descriptor.
//
// WHY THE SHIPPED #8356 CELLS COULD NOT SEE IT: every one of them installs
// `NatDecision::default()` and writes `destination_addresses: vec!["any"]`, so
// the pre/post-translation destination is unobservable twice over. The survival
// cell even asserts it is "preserving NAT" in a fixture with no translation to
// preserve.

struct TranslatedOutcome {
    revoked: u64,
    sessions: usize,
    session_hit_phase2: u64,
    tx_phase2: u64,
}

/// Phase 1 admits the translated flow through the production path. Phase 2
/// drives one more packet of the SAME flow, under `snapshot_phase2`, on a FRESH
/// binding.
///
/// `snapshot_phase2` is the whole point of the shape: passing the SAME snapshot
/// models "nothing about the policy changed", which is the state in which this
/// derivation must do NOTHING, and passing a different one models a real commit.
fn admit_then_one_more_packet(
    snapshot_phase1: crate::ConfigSnapshot,
    snapshot_phase2: crate::ConfigSnapshot,
    ifindex: i32,
    iface: &str,
    frame_admit: &[u8],
    meta_admit: UserspaceDpMeta,
    frame_established: &[u8],
    meta_established: UserspaceDpMeta,
) -> TranslatedOutcome {
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();

    let forwarding1 = build_forwarding_state(&snapshot_phase1);
    let mut binding1 = BindingWorker::new_for_mirror_test(0, 0, ifindex, 0);
    binding1.interface = Arc::<str>::from(iface);
    let (_b1, dbg1) = txn_run_descriptor(
        &mut binding1,
        &mut sessions,
        &forwarding1,
        &ha_state,
        frame_admit,
        meta_admit,
    );
    assert_eq!(
        dbg1.tx, 1,
        "PHASE 1 must ADMIT and forward the translated flow, or every phase-2 \
         assertion is vacuous — nothing would be installed to re-derive (#9382)"
    );
    assert_eq!(
        session_count(&sessions),
        2,
        "PHASE 1 must install the forward + reverse pair (#9382)"
    );

    // A FRESH binding: an empty flow cache, which is what a generation bump
    // leaves behind and what makes phase 2 take the session-hit path.
    let forwarding2 = build_forwarding_state(&snapshot_phase2);
    let mut binding2 = BindingWorker::new_for_mirror_test(0, 0, ifindex, 0);
    binding2.interface = Arc::<str>::from(iface);
    let (_b2, dbg2) = txn_run_descriptor(
        &mut binding2,
        &mut sessions,
        &forwarding2,
        &ha_state,
        frame_established,
        meta_established,
    );
    TranslatedOutcome {
        revoked: dbg2.policy_revoked_sessions,
        sessions: session_count(&sessions),
        session_hit_phase2: dbg2.session_hit,
        tx_phase2: dbg2.tx,
    }
}

const DNAT_CLIENT: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const DNAT_VIP: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 8);
/// The DNAT fixture translates `172.16.80.8:443` -> `10.0.61.102:8443`, so BOTH
/// the address and the PORT differ pre/post translation. That matters: a fix
/// that carried the translated ADDRESS but left the wire PORT would pass an
/// address-only cell.
const DNAT_REAL: &str = "10.0.61.102/32";
const DNAT_VIP_CIDR: &str = "172.16.80.8/32";
const WAN_INGRESS_IFINDEX: i32 = 12;

fn dnat_frames() -> (Vec<u8>, UserspaceDpMeta, Vec<u8>, UserspaceDpMeta) {
    let syn = build_txn_tcp_syn_frame_v4(DNAT_CLIENT, DNAT_VIP, 54321, 443, TCP_FLAG_SYN);
    let meta_syn = txn_meta_v4(WAN_INGRESS_IFINDEX as u32, TCP_FLAG_SYN, syn.len() as u16);
    let ack = build_txn_tcp_syn_frame_v4(DNAT_CLIENT, DNAT_VIP, 54321, 443, TCP_ACK);
    let meta_ack = txn_meta_v4(WAN_INGRESS_IFINDEX as u32, TCP_ACK, ack.len() as u16);
    (syn, meta_syn, ack, meta_ack)
}

/// THE DOMINANT, ORDINARY-OPERATIONS CASE, and it is FAIL-CLOSED. The policy is
/// byte-identical across the generation bump — the SAME permit that admitted the
/// flow, naming the real server — so nothing may be revoked.
///
/// Before the fix this revoked and dropped the packet: the re-derivation asked
/// whether policy permits traffic to the VIP `172.16.80.8:443`, which is
/// precisely the rule admission REFUSES to match
/// (`policy_inbound_dnat_denies_when_only_original_dst_permitted`), found
/// nothing, and fell to `default_policy: deny`. Every published DNAT service on
/// the box lost its live sessions on the next route event.
#[test]
fn an_unchanged_dnat_policy_does_not_revoke_the_established_session_9382() {
    let (syn, meta_syn, ack, meta_ack) = dnat_frames();
    let out = admit_then_one_more_packet(
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal")),
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal")),
        WAN_INGRESS_IFINDEX,
        "reth0.80",
        &syn,
        meta_syn,
        &ack,
        meta_ack,
    );
    assert_eq!(
        out.session_hit_phase2, 1,
        "phase 2 must HIT the installed session, or the revoke assertion below \
         is vacuous (#9382)"
    );
    assert_eq!(
        out.revoked, 0,
        "the policy is UNCHANGED and names the real server 10.0.61.102 — the \
         same rule that admitted this flow. A non-zero count means the \
         re-derivation judged the PRE-translation VIP 172.16.80.8, which is the \
         rule admission refuses, so it found nothing and fell to default-deny: \
         every published DNAT/NPTv6 service loses its live sessions on the next \
         route event, with the policy untouched (#9382)"
    );
    assert_eq!(
        out.sessions, 2,
        "the forward + reverse pair must survive an unchanged policy"
    );
    assert_eq!(out.tx_phase2, 1, "and the packet must still be forwarded");
}

/// THE LOAD-BEARING CONTROL. Same phase 1, but phase 2's policy genuinely no
/// longer covers the flow — the permit now names an unrelated internal host.
///
/// Without this cell, "never revoke a session that has a destination
/// translation" passes the cell above perfectly while silently exempting every
/// DNAT'd service from zone-policy re-derivation altogether. That is a worse bug
/// than the one #9382 fixes, and this is the only cell that can see it.
#[test]
fn a_genuinely_narrowed_dnat_policy_still_revokes_9382() {
    let (syn, meta_syn, ack, meta_ack) = dnat_frames();
    let out = admit_then_one_more_packet(
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal")),
        inbound_dnat_snapshot(wan_to_lan_permit("10.0.61.200/32", "permit-someone-else")),
        WAN_INGRESS_IFINDEX,
        "reth0.80",
        &syn,
        meta_syn,
        &ack,
        meta_ack,
    );
    assert_eq!(out.session_hit_phase2, 1, "phase 2 must hit the session");
    assert_eq!(
        out.revoked, 1,
        "the live policy no longer covers 10.0.61.102, so the session MUST be \
         revoked. 0 here means the translated-destination fix degenerated into \
         'translated sessions are never re-derived' (#9382)"
    );
    assert_eq!(out.sessions, 0, "the revoked pair must be torn down");
}

/// THE FAIL-OPEN DIRECTION, closed. A DENY naming the REAL server, ahead of a
/// permit-any, must revoke.
///
/// Before the fix this was missed: the re-derivation compared the VIP against a
/// deny written for `10.0.61.102`, did not match, fell through to the permit-any
/// and kept the session — so an operator's deny against a published service's
/// real address did not take effect on live traffic.
#[test]
fn a_deny_naming_the_translated_destination_revokes_9382() {
    let (syn, meta_syn, ack, meta_ack) = dnat_frames();
    let mut deny_real = wan_to_lan_permit(DNAT_REAL, "deny-internal");
    deny_real.action = "deny".to_string();
    let mut phase2 = inbound_dnat_snapshot(deny_real);
    // A trailing permit-any so the ONLY thing that can revoke is the deny
    // matching the POST-translation destination — not the default policy.
    phase2.policies.push(wan_to_lan_permit("any", "permit-rest"));
    let out = admit_then_one_more_packet(
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal")),
        phase2,
        WAN_INGRESS_IFINDEX,
        "reth0.80",
        &syn,
        meta_syn,
        &ack,
        meta_ack,
    );
    assert_eq!(out.session_hit_phase2, 1, "phase 2 must hit the session");
    assert_eq!(
        out.revoked, 1,
        "a deny naming the REAL server 10.0.61.102, ahead of a permit-any, must \
         revoke. 0 means the derivation compared the VIP, missed the deny and \
         fell through to the permit — the fail-OPEN half of #9382"
    );
    assert_eq!(out.sessions, 0, "the denied pair must be torn down");
}

/// THE CELL THAT PINS THE EVALUATED TUPLE EXACTLY, and it is the inverse of the
/// one above. A DENY naming ONLY the PRE-translation VIP must NOT revoke,
/// because the VIP is not the address policy judges — admission refuses a rule
/// written against it, so a deny written against it must be equally inert.
///
/// This is the sharpest cell in the group: it fails in OPPOSITE directions
/// before and after the fix (before: revoked 1, because the wire dst IS the VIP;
/// after: revoked 0), so it cannot be satisfied by any constant.
#[test]
fn a_deny_naming_only_the_pre_translation_vip_does_not_revoke_9382() {
    let (syn, meta_syn, ack, meta_ack) = dnat_frames();
    let mut deny_vip = wan_to_lan_permit(DNAT_VIP_CIDR, "deny-public-vip");
    deny_vip.action = "deny".to_string();
    let mut phase2 = inbound_dnat_snapshot(deny_vip);
    phase2
        .policies
        .push(wan_to_lan_permit(DNAT_REAL, "permit-internal"));
    let out = admit_then_one_more_packet(
        inbound_dnat_snapshot(wan_to_lan_permit(DNAT_REAL, "permit-internal")),
        phase2,
        WAN_INGRESS_IFINDEX,
        "reth0.80",
        &syn,
        meta_syn,
        &ack,
        meta_ack,
    );
    assert_eq!(out.session_hit_phase2, 1, "phase 2 must hit the session");
    assert_eq!(
        out.revoked, 0,
        "a deny naming only the PRE-translation VIP must be inert, exactly as \
         admission treats a permit written against it. A non-zero count means \
         the evaluated destination is still the wire tuple (#9382)"
    );
    assert_eq!(out.sessions, 2, "the session must survive an inert deny");
}

/// A SECOND TRANSLATION KIND and a second address family: NPTv6 maps the
/// external prefix `2602:fd41:70::/48` to the internal `fd35:1940:27::/48`. The
/// policy is unchanged and names the INTERNAL prefix — the one admission
/// matches — so nothing may be revoked.
///
/// Not redundant with the DNAT cells: NPTv6 arrives at `decision.nat` by a
/// different route (`nptv6_nat`, a prefix rewrite with NO port rewrite), so a fix
/// that read only the DNAT decision would pass the DNAT cells and fail here.
#[test]
fn an_unchanged_nptv6_policy_does_not_revoke_the_established_session_9382() {
    let src: Ipv6Addr = "2001:559:8585:80::200".parse().expect("ext client");
    let dst: Ipv6Addr = "2602:fd41:70:100::102".parse().expect("external prefix dst");
    let syn = build_txn_tcp_frame_v6(src, dst, 54321, 443, TCP_FLAG_SYN);
    let mut meta_syn = txn_meta_v6(WAN_INGRESS_IFINDEX as u32, syn.len());
    meta_syn.tcp_flags = TCP_FLAG_SYN;
    let ack = build_txn_tcp_frame_v6(src, dst, 54321, 443, TCP_ACK);
    let mut meta_ack = txn_meta_v6(WAN_INGRESS_IFINDEX as u32, ack.len());
    meta_ack.tcp_flags = TCP_ACK;

    let out = admit_then_one_more_packet(
        inbound_nptv6_snapshot(wan_to_lan_permit("fd35:1940:27::/48", "permit-internal-prefix")),
        inbound_nptv6_snapshot(wan_to_lan_permit("fd35:1940:27::/48", "permit-internal-prefix")),
        WAN_INGRESS_IFINDEX,
        "reth0.80",
        &syn,
        meta_syn,
        &ack,
        meta_ack,
    );
    assert_eq!(out.session_hit_phase2, 1, "phase 2 must hit the session");
    assert_eq!(
        out.revoked, 0,
        "the policy is unchanged and names the INTERNAL prefix admission \
         matches. A non-zero count means the re-derivation judged the EXTERNAL \
         prefix the packet carried on the wire (#9382)"
    );
    assert_eq!(out.sessions, 2, "the NPTv6 pair must survive");
}

/// NAT64, AND IT MUST BE THE MIXED-FAMILY DESTINATION SET. This is the cell the
/// issue insists on, because the v4-only shape passes TODAY FOR THE WRONG
/// REASON: a destination set with no IPv6 member compiles to IPv6-match-any (the
/// legacy address-set convention), so the synthetic v6 wire destination matches
/// on the match-any path and the broken derivation looks correct.
///
/// Giving the rule a v6 member that does NOT cover `64:ff9b::/96` removes that
/// accident. The rule then names the REAL IPv4 server `8.8.8.8` — which is
/// exactly what #2358 tells operators to write — so admission matches it on the
/// cross-family (V6 src, V4 dst) arm, and the re-derivation must reach the same
/// verdict through `decision.nat.rewrite_dst`, the extracted IPv4 target.
#[test]
fn an_unchanged_nat64_policy_with_a_mixed_family_destination_set_does_not_revoke_9382() {
    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("v6 client");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 synthetic dst");
    let syn = build_txn_tcp_frame_v6(src, dst, 12345, 443, TCP_FLAG_SYN);
    let mut meta_syn = txn_meta_v6(LAN_IFINDEX as u32, syn.len());
    meta_syn.tcp_flags = TCP_FLAG_SYN;
    let ack = build_txn_tcp_frame_v6(src, dst, 12345, 443, TCP_ACK);
    let mut meta_ack = txn_meta_v6(LAN_IFINDEX as u32, ack.len());
    meta_ack.tcp_flags = TCP_ACK;

    let mixed = || {
        let mut rule = lan_to_wan_permit("8.8.8.8/32", "permit-real-v4-server");
        // The v6 member is what defeats the IPv6-match-any accident. It must
        // NOT cover 64:ff9b::/96 — if it did, the synthetic wire destination
        // would match it and the cell would pass whether the fix exists or not.
        rule.destination_addresses
            .push("2001:db8::/32".to_string());
        nat64_snapshot(rule)
    };
    let out = admit_then_one_more_packet(
        mixed(),
        mixed(),
        LAN_IFINDEX,
        "reth1.0",
        &syn,
        meta_syn,
        &ack,
        meta_ack,
    );
    assert_eq!(out.session_hit_phase2, 1, "phase 2 must hit the session");
    assert_eq!(
        out.revoked, 0,
        "the rule names the REAL IPv4 server 8.8.8.8 — the tuple #2358 has \
         admission match — and carries a v6 member so the destination set is no \
         longer IPv6-match-any. A non-zero count means the re-derivation judged \
         the SYNTHETIC v6 destination, which matches nothing here (#9382)"
    );
    assert_eq!(out.sessions, 2, "the NAT64 pair must survive");
}
