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
use std::net::{IpAddr, Ipv4Addr};
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
