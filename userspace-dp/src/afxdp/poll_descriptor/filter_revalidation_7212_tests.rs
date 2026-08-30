// #7212: the established-session-hit input-filter re-evaluation gate
// (`evaluate_input_filter_on_session_hit`).
//
// These cells drive the helper directly, so they can vary one axis at a time —
// family, logical VLAN unit, filter shape, stamp freshness. The END-TO-END
// revocation (teardown + the pinned permitted-SNAT case) is driven through the
// real poll loop in `afxdp/tests_filter_revocation_7212.rs`.

use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::test_fixtures::policy_deny_snapshot;
use crate::ip_proto::PROTO_TCP;
use crate::session::{SessionKey, SessionMetadata, SessionOrigin};
use crate::test_zone_ids::*;
use crate::{FirewallFilterSnapshot, FirewallTermSnapshot, InterfaceSnapshot};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The LAN-side interface every cell attaches its input filter to. It is the
/// ingress of the `policy_deny_snapshot` topology's `reth1.0`.
const LAN_IFINDEX: i32 = 24;
/// A VLAN sub-interface added on a DIFFERENT physical parent, so a
/// physical-keyed lookup would resolve no filter at all and a logical-keyed one
/// resolves this unit's own.
const VLAN_PARENT_IFINDEX: i32 = 11;
const VLAN_UNIT_IFINDEX: i32 = 13;
const VLAN_ID: i32 = 50;

fn deny_term(name: &str, dport: &str) -> FirewallTermSnapshot {
    FirewallTermSnapshot {
        name: name.into(),
        protocols: vec!["tcp".into()],
        destination_ports: vec![dport.into()],
        action: "discard".into(),
        syslog: false,
        reject_message_type: String::new(),
        ..Default::default()
    }
}

fn accept_term(name: &str, dport: &str) -> FirewallTermSnapshot {
    FirewallTermSnapshot {
        action: "accept".into(),
        ..deny_term(name, dport)
    }
}

/// Build a forwarding state from the shared LAN/WAN topology with `terms`
/// attached as the inet (or inet6) INPUT filter of `ifindex`.
fn forwarding_with_input_filter(
    ifindex: i32,
    v6: bool,
    terms: Vec<FirewallTermSnapshot>,
) -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "edge-in".into(),
        family: if v6 { "inet6".into() } else { "inet".into() },
        terms,
    }];
    // A second VLAN unit on a different physical parent, used only by the VLAN
    // cell. Harmless elsewhere: nothing attaches a filter to it there.
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth0.50".into(),
        zone: "lan".into(),
        linux_name: "ge-0-0-0.50".into(),
        ifindex: VLAN_UNIT_IFINDEX,
        parent_ifindex: VLAN_PARENT_IFINDEX,
        vlan_id: VLAN_ID,
        ..Default::default()
    });
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == ifindex {
            if v6 {
                iface.filter_input_v6 = "edge-in".into();
            } else {
                iface.filter_input_v4 = "edge-in".into();
            }
        }
    }
    build_forwarding_state(&snapshot)
}

fn v4_flow(dst_port: u16) -> SessionFlow {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
    let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    SessionFlow {
        src_ip: src,
        dst_ip: dst,
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: src,
            dst_ip: dst,
            src_port: 12345,
            dst_port,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    }
}

fn v6_flow(dst_port: u16) -> SessionFlow {
    let src = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0x61, 0, 0, 0, 0x102));
    let dst = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0x80, 0, 0, 0, 0x200));
    SessionFlow {
        src_ip: src,
        dst_ip: dst,
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: src,
            dst_ip: dst,
            src_port: 12345,
            dst_port,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    }
}

fn meta(ingress_ifindex: u32, vlan: u16, v6: bool) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex,
        ingress_vlan_id: vlan,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: 54,
        addr_family: if v6 {
            libc::AF_INET6 as u8
        } else {
            libc::AF_INET as u8
        },
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    }
}

fn metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

fn decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    }
}

/// Install `flow` as an established session stamped under generation
/// `stamped_gen`, with the table now publishing `live_gen`.
fn table_with_session(flow: &SessionFlow, stamped_gen: u64, live_gen: u64) -> SessionTable {
    let mut sessions = SessionTable::new();
    sessions.set_filter_revalidation_gen(stamped_gen);
    assert!(sessions.install_with_protocol_with_origin(
        flow.forward_key.clone(),
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        1_000,
        PROTO_TCP,
        0,
    ));
    sessions.set_filter_revalidation_gen(live_gen);
    sessions
}

/// The shared LAN->WAN TCP SYN frame: 10.0.61.102:12345 -> 172.16.80.200:5201,
/// the exact tuple `v4_flow(5201)` names.
///
/// A zero-filled buffer would be enough for the STATIC cells — no static term
/// reads a packet byte — but it is NOT enough for the per-packet cell: a
/// `tcp-flags` term requires `TermMatchExtra::l4_present`, which
/// `term_match_extra_from_frame` derives from the frame, so a synthetic buffer
/// makes that term fail closed and the cell would assert Accept for a reason
/// that has nothing to do with the code under test. Using one real frame
/// everywhere removes that class of fixture lie.
fn frame() -> Vec<u8> {
    crate::afxdp::tests_support::build_policy_deny_tcp_syn_frame()
}

/// A static `then discard` attached after the session was established revokes
/// it on the next packet: the helper reports a non-Accept action AND flags the
/// verdict as a REVOCATION, which is what makes the caller tear the pair down
/// rather than merely drop the packet.
#[test]
fn static_discard_revokes_a_stale_stamped_session_7212() {
    let forwarding = forwarding_with_input_filter(LAN_IFINDEX, false, vec![deny_term("no-5201", "5201")]);
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 6, 7);

    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(LAN_IFINDEX as u32, 0, false),
        Some(TEST_LAN_ZONE_ID),
    )
    .expect("a newly-denied stale session must produce a verdict");
    assert_eq!(hit.eval.action, crate::filter::FilterAction::Discard);
    assert!(
        hit.revoked,
        "a static-filter verdict must revoke the SESSION, not just drop the packet"
    );
}

/// THE pinned acceptance case, at the helper level: a session the same
/// interface's filter still PERMITS is not touched — no verdict is returned at
/// all — and its SNAT translated port is unchanged. This is the whole reason
/// #5858's interface-keyed family purge was rejected: a purged permitted SNAT
/// flow reinstalls on a DIFFERENT translated port and breaks.
///
/// The deny term is present and matches a SIBLING port on the SAME interface,
/// so the filter is genuinely one that can deny; an all-accept filter would
/// make this pass for the wrong reason.
#[test]
fn a_still_permitted_session_keeps_its_snat_translation_7212() {
    let forwarding = forwarding_with_input_filter(
        LAN_IFINDEX,
        false,
        vec![deny_term("no-ssh", "22"), accept_term("web", "5201")],
    );
    let flow = v4_flow(5201);

    let mut sessions = SessionTable::new();
    sessions.set_filter_revalidation_gen(6);
    let mut snat = decision();
    snat.nat.rewrite_src = Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    snat.nat.rewrite_src_port = Some(40001);
    assert!(sessions.install_with_protocol_with_origin(
        flow.forward_key.clone(),
        snat,
        metadata(),
        SessionOrigin::ForwardFlow,
        1_000,
        PROTO_TCP,
        0,
    ));
    sessions.set_filter_revalidation_gen(7);

    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(LAN_IFINDEX as u32, 0, false),
        Some(TEST_LAN_ZONE_ID),
    );
    assert!(
        hit.is_none(),
        "a still-permitted session must produce no verdict, no counter and no log"
    );
    let lookup = sessions
        .lookup(&flow.forward_key, 2_000, 0)
        .expect("the permitted session must survive the revalidation");
    assert_eq!(
        lookup.decision.nat.rewrite_src_port,
        Some(40001),
        "the translated port must be unchanged — a purge-and-recreate hands out \
         a different one and breaks the flow"
    );
    assert_eq!(
        lookup.decision.nat.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)))
    );
    assert!(
        !sessions.filter_revalidation_stale(&flow.forward_key),
        "an Accept verdict must re-stamp, or every later packet re-derives it"
    );
}

/// The STAMP is the gate, not the filter. A session whose verdict was already
/// computed under the live generation is not re-derived, so no work is done and
/// nothing is revoked.
///
/// This state is unreachable in production for a DENIED flow — the install-time
/// verdict and the install-time stamp come from the same generation, so a
/// session stamped at the live generation was admitted by this very filter —
/// but it is exactly the state that distinguishes "re-derive when stale" from
/// "re-derive on every packet", and only a fresh-stamp row can show that.
#[test]
fn a_fresh_stamp_skips_the_revalidation_entirely_7212() {
    let forwarding = forwarding_with_input_filter(LAN_IFINDEX, false, vec![deny_term("no-5201", "5201")]);
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 7, 7);

    assert!(
        evaluate_input_filter_on_session_hit(
            &forwarding,
            &mut sessions,
            &flow.forward_key,
            &frame(),
            Some(&flow),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
        )
        .is_none(),
        "a session already revalidated under the live generation must not be \
         re-derived"
    );
}

/// inet6 parity. The family selects a different fast map, and a v4-only
/// implementation would leave every IPv6 session unrevoked.
#[test]
fn static_discard_revokes_an_ipv6_session_7212() {
    let forwarding = forwarding_with_input_filter(LAN_IFINDEX, true, vec![deny_term("no-5201", "5201")]);
    let flow = v6_flow(5201);
    let mut sessions = table_with_session(&flow, 6, 7);

    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(LAN_IFINDEX as u32, 0, true),
        Some(TEST_LAN_ZONE_ID),
    )
    .expect("v6 verdict");
    assert_eq!(hit.eval.action, crate::filter::FilterAction::Discard);
    assert!(hit.revoked);
}

/// The filter is resolved through the LOGICAL VLAN unit, not the physical
/// parent. The filter is attached to unit ifindex 13 and the packet arrives on
/// physical ifindex 11 with VID 50; a physical-keyed lookup finds NO filter and
/// revokes nothing.
#[test]
fn static_discard_resolves_through_the_vlan_logical_unit_7212() {
    let forwarding =
        forwarding_with_input_filter(VLAN_UNIT_IFINDEX, false, vec![deny_term("no-5201", "5201")]);
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 6, 7);

    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(VLAN_PARENT_IFINDEX as u32, VLAN_ID as u16, false),
        Some(TEST_LAN_ZONE_ID),
    )
    .expect("the VLAN unit's own filter must be found");
    assert_eq!(hit.eval.action, crate::filter::FilterAction::Discard);
    assert!(hit.revoked);
}

/// Term ORDER decides. The same two terms with the accept first must permit;
/// reversing them must revoke. A single-order fixture would pass for an
/// implementation that ignored ordering entirely.
#[test]
fn term_order_decides_the_static_verdict_7212() {
    for (accept_first, want_revoked) in [(true, false), (false, true)] {
        let terms = if accept_first {
            vec![accept_term("web", "5201"), deny_term("no-5201", "5201")]
        } else {
            vec![deny_term("no-5201", "5201"), accept_term("web", "5201")]
        };
        let forwarding = forwarding_with_input_filter(LAN_IFINDEX, false, terms);
        let flow = v4_flow(5201);
        let mut sessions = table_with_session(&flow, 6, 7);
        let hit = evaluate_input_filter_on_session_hit(
            &forwarding,
            &mut sessions,
            &flow.forward_key,
            &frame(),
            Some(&flow),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
        );
        assert_eq!(
            hit.is_some_and(|h| h.revoked),
            want_revoked,
            "accept_first={accept_first}: first match wins"
        );
    }
}

/// `from source-address ... except` inverts the address match, so the same deny
/// term revokes or does not depending only on the `except` bit.
#[test]
fn source_address_except_inverts_the_static_verdict_7212() {
    for (except, want_revoked) in [(false, true), (true, false)] {
        let mut term = deny_term("no-5201", "5201");
        term.source_addresses = vec!["10.0.61.102/32".into()];
        term.source_except = except;
        let forwarding = forwarding_with_input_filter(LAN_IFINDEX, false, vec![term]);
        let flow = v4_flow(5201);
        let mut sessions = table_with_session(&flow, 6, 7);
        let hit = evaluate_input_filter_on_session_hit(
            &forwarding,
            &mut sessions,
            &flow.forward_key,
            &frame(),
            Some(&flow),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
        );
        assert_eq!(
            hit.is_some_and(|h| h.revoked),
            want_revoked,
            "except={except}: the deny applies only when the address matches"
        );
    }
}

/// DETACH is strictly loosening: with no filter attached, a stale stamp
/// produces no verdict and nothing is revoked.
#[test]
fn detaching_the_filter_revokes_nothing_7212() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.filters = Vec::new();
    let forwarding = build_forwarding_state(&snapshot);
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 6, 7);

    assert!(
        evaluate_input_filter_on_session_hit(
            &forwarding,
            &mut sessions,
            &flow.forward_key,
            &frame(),
            Some(&flow),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
        )
        .is_none()
    );
}

/// A filter whose verdict VARIES per packet (#1430 DSCP / #2362 per-packet L4)
/// keeps its per-packet re-evaluation and must NEVER be flagged as a
/// revocation: its verdict is about THIS packet and says nothing about the
/// flow. A tcp-flags term denying a packet with no SYN set would otherwise tear
/// down the whole session on one mid-stream segment.
#[test]
fn a_per_packet_filter_drops_the_packet_without_revoking_the_session_7212() {
    let mut term = deny_term("no-syn-5201", "5201");
    term.tcp_flags = Some(crate::tcp_flags::TCP_SYN);
    let forwarding = forwarding_with_input_filter(LAN_IFINDEX, false, vec![term]);
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 6, 7);

    let mut m = meta(LAN_IFINDEX as u32, 0, false);
    m.tcp_flags = crate::tcp_flags::TCP_SYN;
    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        m,
        Some(TEST_LAN_ZONE_ID),
    )
    .expect("a per-packet filter is re-evaluated on every hit");
    assert_eq!(hit.eval.action, crate::filter::FilterAction::Discard);
    assert!(
        !hit.revoked,
        "a per-packet verdict must drop the packet, never revoke the session"
    );
    assert!(
        sessions.filter_revalidation_stale(&flow.forward_key),
        "the per-packet arm must not consume the static revalidation stamp"
    );
}
