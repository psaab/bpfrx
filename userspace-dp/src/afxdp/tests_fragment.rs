// IPv4/IPv6 fragment handling, output-filter fragment semantics, and fabric queue-hash.
//
// Split out of afxdp/tests.rs (#4840) as a sibling `#[path]` test module
// loaded from afxdp/mod.rs. Pure code motion: every #[test] fn is moved
// verbatim; shared test-support helpers live in afxdp/tests_support.rs.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::worker::WorkerTxPipeline;
use super::*;
use crate::test_zone_ids::*;
use crate::xsk_ffi::IfInfo;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSForwardingClassSnapshot, CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
    DestinationNATRuleSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot,
    InterfaceAddressSnapshot, NeighborSnapshot, PolicyRuleSnapshot, RouteSnapshot,
    SourceNATRuleSnapshot, StaticNATRuleSnapshot, ThreeColorPolicerSnapshot, ZoneSnapshot,
};
use super::tests_support::*;

#[test]
fn non_first_fragment_v4_not_dropped_by_port_matching_output_filter() {
    // payload at the post-IP offset spells src=33333 dst=443 — exactly what
    // the buggy meta fallback would parse as the discarded web port.
    let payload = [0x82, 0x35, 0x01, 0xbb, 0, 0, 0, 0];
    let frame = eth_ipv4_frag_frame(0x0001, &payload); // non-first (offset != 0)
    let forwarding = wan_drop_443_forwarding();
    let ingress_ident = frag_test_ingress_ident();
    let decision = frag_test_decision();
    let meta = frag_test_meta(14);
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        &frame,
        meta,
        &decision,
        &forwarding,
        None, // flowless — the #2344 fragment case
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    );

    let req = req.expect(
        "a non-first fragment must NOT be dropped by a port-matching output filter \
         (gate routes it to the None flow_key default-queue path)",
    );
    assert_eq!(
        req.flow_key, None,
        "fragment TX selection must use no flow_key (no payload-derived ports)"
    );
    assert_eq!(
        req.expected_ports, None,
        "fragment must not carry payload-derived expected ports"
    );
}


#[test]
fn control_icmp_v4_installs_no_synthesized_tx_flow_key() {
    // #3290 (TX/CoS side): a permitted ICMPv4 control packet (Time-Exceeded)
    // whose shim metadata carries a hostile pseudo-port (0xBEEF) must NOT
    // propagate a synthesized flow key into TX selection / CoS output-filter
    // evaluation. The forward_request meta-fallback gate mirrors the
    // conntrack-side parse_session_flow_from_bytes verdict (the primary flow is
    // None for these packets). Reverting the gate makes the fallback synthesize
    // a meta-keyed flow with src_port=0xBEEF -> req.flow_key becomes Some -> RED.
    let frame = eth_ipv4_icmp_frame(11); // Time-Exceeded
    let forwarding = wan_drop_443_forwarding();
    let ingress_ident = frag_test_ingress_ident();
    let decision = frag_test_decision();
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 10,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        pkt_len: frame.len() as u16,
        l3_offset: 14,
        l4_offset: 34,
        flow_src_port: 0xBEEF,
        flow_dst_port: 0,
        flow_src_addr: [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..UserspaceDpMeta::default()
    };
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        &frame,
        meta,
        &decision,
        &forwarding,
        None, // primary flow is None (conntrack-side #3290 gate)
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    )
    .expect("control ICMP must still forward (TCP-only output filter does not match)");

    assert_eq!(
        req.flow_key, None,
        "#3290: a control ICMP packet must not synthesize a metadata-derived TX flow key"
    );
}


#[test]
fn flowless_non_fragmented_tcp_still_hits_port_matching_output_filter() {
    // Same meta (dst port 443) but a FIRST/atomic fragment (offset 0) — a
    // real L4 header, so the gate must NOT fire and the meta fallback's
    // ports must drive the discard. Proves we did not over-gate every None
    // flow to the default queue.
    let payload = [0x82, 0x35, 0x01, 0xbb, 0, 0, 0, 0];
    let frame = eth_ipv4_frag_frame(0x0000, &payload); // atomic (offset 0)
    let forwarding = wan_drop_443_forwarding();
    let ingress_ident = frag_test_ingress_ident();
    let decision = frag_test_decision();
    let meta = frag_test_meta(14);
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        &frame,
        meta,
        &decision,
        &forwarding,
        None, // flowless, but a real L4 header (not a fragment)
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    );

    assert!(
        req.is_none(),
        "a flowless NON-fragmented TCP packet to dst 443 must still be dropped \
         by the port-matching terminal output filter (gate must not over-suppress)"
    );
}


#[test]
fn fabric_queue_hash_non_first_fragment_is_port_independent_3tuple() {
    // Two non-first fragments of one datagram differ only in payload bytes
    // (the fictitious "ports"); the fabric hash must be identical so they
    // bind the same fabric target (no cross-chassis reordering).
    let mut meta_a = frag_test_meta(14);
    meta_a.flow_src_port = 1111;
    meta_a.flow_dst_port = 2222;
    let mut meta_b = meta_a;
    meta_b.flow_src_port = 40000; // different payload bytes
    meta_b.flow_dst_port = 50000;

    let h_a = fabric_queue_hash(None, Some((1111, 2222)), meta_a, true);
    let h_b = fabric_queue_hash(None, Some((40000, 50000)), meta_b, true);
    assert_eq!(
        h_a, h_b,
        "fragment fabric hash must be port-independent (3-tuple: src/dst/proto)"
    );

    // The 3-tuple still distinguishes different src/dst/proto.
    let mut meta_c = meta_a;
    meta_c.flow_dst_addr[3] = 201; // different dst IP
    let h_c = fabric_queue_hash(None, Some((1111, 2222)), meta_c, true);
    assert_ne!(h_a, h_c, "fragment fabric hash must depend on dst address");

    let mut meta_d = meta_a;
    meta_d.protocol = PROTO_UDP;
    let h_d = fabric_queue_hash(None, Some((1111, 2222)), meta_d, true);
    assert_ne!(h_a, h_d, "fragment fabric hash must depend on protocol");

    // And the non-fragment (ported) path is still port-sensitive — proves
    // the gate flag, not a blanket change, drives the new behavior.
    let h_ported_a = fabric_queue_hash(None, Some((1111, 2222)), meta_a, false);
    let h_ported_b = fabric_queue_hash(None, Some((40000, 50000)), meta_b, false);
    assert_ne!(
        h_ported_a, h_ported_b,
        "non-fragment fabric hash must remain port-sensitive"
    );
}

// ---- #3291: flowless / non-first-fragment transit ENFORCEMENT ------------
//
// A non-first IPv4 fragment is flowless (#2344: its post-IP bytes are payload,
// never L4 ports). Before #3291 the flowless transit arm ran only
// resolve_forwarding (+ HA + fabric) and forwarded the fragment whenever a route
// existed — so a `deny-all` zone pair, an interface input filter, and PBR
// (`then routing-instance`) all silently no-op'd on fragments (fail-open). These
// tests push a real non-first fragment through poll_binding_process_descriptor
// and pin the gate that now applies zone policy + input filter + PBR. Reverting
// the gate flips the deny / input-filter / PBR cases from drop back to forward,
// turning the asserts RED.


#[test]
fn flowless_non_first_fragment_transit_dropped_by_deny_all_3291() {
    // lan->wan is denied (default-deny; only dmz->wan permitted). A non-first
    // fragment from lan toward a routed wan dst must be DROPPED by zone policy.
    // RED-on-revert: the flowless arm used to forward it (dbg.forward == 1,
    // dbg.policy_deny == 0).
    let mut snapshot = policy_deny_snapshot();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame();
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta(),
    );

    assert_eq!(
        dbg.policy_deny, 1,
        "#3291: a deny-all zone pair must DROP a flowless non-first fragment"
    );
    assert_eq!(
        dbg.forward, 0,
        "#3291: the fragment must NOT forward under deny-all (RED on revert)"
    );
}


#[test]
fn flowless_non_first_fragment_transit_permitted_by_any_policy_3291() {
    // An address/`application any` permit for lan->wan must still FORWARD a
    // non-first fragment — the gate must not over-block legitimate flowless
    // forwarding.
    let mut snapshot = policy_deny_snapshot();
    snapshot.policies = vec![PolicyRuleSnapshot {
        name: "permit-lan-wan".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    }];
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame();
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta(),
    );

    assert_eq!(
        dbg.policy_deny, 0,
        "#3291: an `application any` permit must not deny the fragment"
    );
    assert_eq!(
        dbg.forward, 1,
        "#3291: a permitted non-first fragment must still forward (no over-gating)"
    );
}


/// eth(14) + IPv4(20, proto=UDP) + UDP(8). `frag_off` carries the IPv4
/// flags+offset word (0x2000 => MF, offset 0 == first fragment; 0x0001 =>
/// offset 1 == non-first). `id` is the 16-bit IPv4 Identification shared by
/// every fragment of one datagram. src 10.0.61.100 (lan) -> dst 172.16.80.200
/// (wan), matching `frag_transit_wan_neighbor`.
fn udp_frag_frame_5689(frag_off: u16, id: u16) -> Vec<u8> {
    let mut f = vec![
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x08, 0x00,
    ];
    // For a first fragment the 8 bytes at l4 are a real UDP header (sport
    // 33333, dport 443); for a non-first fragment they are payload (never read
    // as ports — the fragment is flowless per #2344).
    let udp = [0x82, 0x35, 0x01, 0xbb, 0x00, 0x08, 0x00, 0x00];
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    let total = (20 + udp.len()) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip[4..6].copy_from_slice(&id.to_be_bytes());
    ip[6..8].copy_from_slice(&frag_off.to_be_bytes());
    ip[8] = 64; // ttl
    ip[9] = PROTO_UDP;
    ip[12..16].copy_from_slice(&[10, 0, 61, 100]); // src (lan)
    ip[16..20].copy_from_slice(&[172, 16, 80, 200]); // dst (wan)
    f.extend_from_slice(&ip);
    f.extend_from_slice(&udp);
    f
}

fn udp_frag_meta_5689() -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24, // reth1.0 (lan)
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        pkt_len: 42,
        l3_offset: 14,
        l4_offset: 34,
        flow_src_port: 33333,
        flow_dst_port: 443,
        flow_src_addr: [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}


#[test]
fn flowless_non_first_fragment_inherits_ordinary_snat_translation_5689() {
    // #5689: a non-first fragment of an ORDINARY-NAT (interface SNAT lan->wan)
    // flow must inherit the first fragment's translation on the flowless arm
    // (address-only L3 rewrite) instead of being forwarded UNTRANSLATED. Before
    // this fix only NAT64 had a fragment association; an ordinary-NAT/NPT
    // non-first fragment resolved `NatDecision::default()` and leaked out with
    // the untranslated internal source.
    //
    // The FIRST fragment (offset 0, MF=1) runs the full cold path: it is
    // permitted, interface-SNAT'd to the wan interface IP (172.16.80.8), a
    // session is installed, AND the ordinary-NAT fragment association is
    // installed. The NON-first fragment (offset 1, same IPv4 id) is flowless;
    // the flowless arm consults the association and inherits the SNAT decision.
    //
    // RED-on-revert: reverting the install (cold-path) OR the flowless consult
    // makes the non-first fragment resolve `NatDecision::default()` ->
    // `nat_applied_none == 1`, `nat_applied_snat == 0` (forwarded untranslated).
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "snat-lan-wan".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();

    // (1) FIRST fragment: MF=1, offset 0, id 0xbeef. Seeds the session, applies
    //     interface SNAT, and installs the ordinary-NAT fragment association.
    let first = udp_frag_frame_5689(0x2000, 0xbeef);
    let (_b1, dbg1) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &first,
        udp_frag_meta_5689(),
    );
    assert_eq!(
        dbg1.nat_applied_snat, 1,
        "#5689: the SNAT'd first fragment must translate (source -> wan IP)"
    );
    assert_eq!(
        forwarding.nat64.frag_assoc.len(),
        1,
        "#5689: the first fragment must install exactly one ordinary-NAT association"
    );

    // (2) NON-first fragment: offset 1, SAME id 0xbeef -> flowless -> consult
    //     the association installed above and inherit the SNAT translation.
    let non_first = udp_frag_frame_5689(0x0001, 0xbeef);
    let (_b2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        udp_frag_meta_5689(),
    );
    assert_eq!(
        dbg2.forward, 1,
        "#5689: the non-first fragment must forward"
    );
    assert_eq!(
        dbg2.nat_applied_snat, 1,
        "#5689: the non-first fragment must INHERIT the SNAT translation (RED on revert)"
    );
    assert_eq!(
        dbg2.nat_applied_none, 0,
        "#5689: the non-first fragment must NOT be forwarded untranslated"
    );
}


#[test]
fn nat_nonfirst_fragment_assoc_miss_fails_closed_6122() {
    // #6122: a NON-first fragment of an ORDINARY-NAT (interface SNAT lan->wan)
    // flow that MISSES the fragment-association cache must be DROPPED
    // fail-closed, NOT forwarded UNTRANSLATED. The miss is exercised the way it
    // happens in production on the reorder / eviction / TTL-straddle /
    // config-generation-bump / never-forwarded-first edges: the non-first
    // fragment reaches the flowless arm with an EMPTY association cache (no
    // first fragment installed one). Before #6122 the flowless default forwarded
    // it with `NatDecision::default()`, leaking the internal source
    // (10.0.61.100) onto the wan wire. #6122 fails closed: the discriminator
    // sees the SNAT rule WOULD translate this flow's L3 identity, so the
    // permitted-but-untranslatable fragment is dropped (the sender retransmits).
    //
    // RED-on-revert: reverting the fail-closed drop makes the fragment forward
    // untranslated -> `dbg.forward == 1`, `dbg.nat_applied_none == 1`,
    // `batch.nat_frag_untranslated_dropped == 0`, tripping all three asserts.
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "snat-lan-wan".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();

    // Precondition: the association cache is EMPTY (no first fragment seen), so
    // the flowless consult below is a genuine MISS.
    assert_eq!(
        forwarding.nat64.frag_assoc.len(),
        0,
        "#6122 precondition: no fragment association installed (a pure miss)"
    );

    // NON-first fragment (offset 1, id 0xbeef) arriving WITHOUT its first
    // fragment -> flowless -> association MISS -> #6122 fail-closed drop.
    let non_first = udp_frag_frame_5689(0x0001, 0xbeef);
    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        udp_frag_meta_5689(),
    );
    assert_eq!(
        dbg.forward, 0,
        "#6122: a NAT'd non-first fragment that misses the association must NOT forward"
    );
    assert_eq!(
        dbg.nat_applied_none, 0,
        "#6122: the fragment must NOT be forwarded untranslated (no internal-source leak)"
    );
    assert_eq!(
        batch.nat_frag_untranslated_dropped, 1,
        "#6122: the fail-closed drop must be counted (RED on revert)"
    );
}


#[test]
fn nonnat_nonfirst_fragment_assoc_miss_still_forwards_6122() {
    // #6122 no-regression: a NON-NAT'd (plain-forwarded) non-first fragment that
    // misses the association must STILL forward normally. The #6122 fail-closed
    // drop is scoped to fragments whose flow WOULD be NAT-translated; a plain
    // fragmented flow needs no translation, so dropping it would break ordinary
    // fragmented forwarding. Same topology as the SNAT test above but with NO
    // NAT rule of any kind, so the discriminator finds no matching rule and the
    // fragment forwards untranslated (the correct disposition for a no-NAT flow).
    //
    // Guards against an over-broad fix: reverting the discriminator's NAT-scope
    // gate (dropping EVERY same-family fragment miss) makes `dbg.forward == 0`
    // and `batch.nat_frag_untranslated_dropped == 1`, tripping these asserts.
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    // No source_nat_rules / DNAT / static-NAT / NPTv6 -> a plain (no-NAT) flow.
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();

    let non_first = udp_frag_frame_5689(0x0001, 0xbeef);
    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        udp_frag_meta_5689(),
    );
    assert_eq!(
        dbg.forward, 1,
        "#6122: a plain (no-NAT) non-first fragment must still forward"
    );
    assert_eq!(
        dbg.nat_applied_none, 1,
        "#6122: a plain fragment forwards untranslated (correct — no NAT applies)"
    );
    assert_eq!(
        batch.nat_frag_untranslated_dropped, 0,
        "#6122: a plain fragment must NOT be counted as a NAT'd-fragment drop"
    );
}


#[test]
fn flowless_non_first_fragment_dropped_by_is_fragment_input_filter_3291() {
    // Interface input filter `from is-fragment then discard` on the ingress
    // interface must DROP a non-first fragment. Default-permit policy ensures
    // the drop is the filter's doing, not zone policy. RED-on-revert: the
    // flowless arm never ran the input filter (dbg.forward == 1).
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.interfaces[0].filter_input_v4 = "drop-frags".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "drop-frags".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "frag".to_string(),
            is_fragment: true,
            action: "discard".to_string(),
            ..Default::default()
        }],
    }];
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame();
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta(),
    );

    assert_eq!(
        dbg.forward, 0,
        "#3291: `from is-fragment then discard` must drop a non-first fragment (RED on revert)"
    );
}


#[test]
fn flowless_non_first_fragment_steered_by_pbr_routing_instance_3291() {
    // Firewall-filter PBR `from is-fragment then routing-instance scrub` must
    // steer the fragment's route lookup to the (empty) `scrub` table -> NoRoute
    // -> drop. Default-permit policy + a base connected route to 172.16.80.0/24
    // mean that WITHOUT the gate the fragment forwards via the base table.
    // RED-on-revert: the flowless arm ignored PBR -> base route -> forward.
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.interfaces[0].filter_input_v4 = "frag-to-scrub".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "frag-to-scrub".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "frag".to_string(),
            is_fragment: true,
            action: "accept".to_string(),
            routing_instance: "scrub".to_string(),
            ..Default::default()
        }],
    }];
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame();
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta(),
    );

    assert_eq!(
        dbg.forward, 0,
        "#3291: PBR `then routing-instance scrub` must steer the fragment to the \
         empty scrub table -> NoRoute -> drop (RED on revert: base-table forward)"
    );
    assert_eq!(
        dbg.no_route, 1,
        "#3291: the PBR-steered fragment resolves NoRoute in the empty scrub table"
    );
}

// ---- #4024: flowless / non-first-fragment MISSING-NEIGHBOR ENFORCEMENT ----
//
// #3291 enforced zone policy on the flowless ForwardCandidate arm but deferred
// MissingNeighbor to "its own cold-path arm" — whose #1913 policy gate is
// `if let Some(flow)` and so never fired for a flowless (flow == None) packet.
// So a flowless fragment whose next-hop neighbor was unresolved fell through to
// the FIB reinject, and a `deny-all` zone pair FAILED OPEN for it (kernel
// forwarded the transit). #4024 adds the flowless (flow == None) policy gate to
// the MissingNeighbor arm. Reverting the gate flips the deny case from a
// policy-deny drop back to a buffered-and-reinjected forward, turning the
// asserts RED.


#[test]
fn flowless_non_first_fragment_missing_neighbor_dropped_by_deny_all_4024() {
    // lan->wan is default-deny (policy_deny_snapshot only permits dmz->wan).
    // With NO neighbor for 172.16.80.200 the connected WAN route resolves but
    // ARP is unresolved -> MissingNeighbor. A flowless (non-first fragment) that
    // hits that cold path MUST be DROPPED by zone policy, not FIB-reinjected.
    // RED-on-revert: the flowless MissingNeighbor arm used to skip the policy
    // gate (dbg.policy_deny == 0) and buffer the frame for retry
    // (pending_neigh not empty) while the trailing chokepoint reinjected it.
    let mut snapshot = policy_deny_snapshot();
    // Empty neighbors => the WAN connected route resolves egress but no MAC =>
    // MissingNeighbor (the cold path under test), not ForwardCandidate.
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame();
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta(),
    );

    assert_eq!(
        dbg.missing_neigh, 1,
        "#4024: no neighbor for the connected WAN dst must resolve MissingNeighbor \
         (the flowless cold path under test)"
    );
    assert_eq!(
        dbg.policy_deny, 1,
        "#4024: a deny-all zone pair must DROP a flowless MissingNeighbor fragment \
         via the policy gate (RED on revert: 0 — flowless skipped the gate)"
    );
    assert!(
        binding.pending_neigh.is_empty(),
        "#4024: a denied flowless MissingNeighbor fragment must NOT be buffered \
         for neighbor retry (RED on revert: buffered before the reinject leak)"
    );
}


#[test]
fn flowless_non_first_fragment_missing_neighbor_permitted_forwards_4024() {
    // An `application any` permit for lan->wan must NOT deny a flowless
    // MissingNeighbor fragment — the gate must not over-block legitimate
    // flowless forwarding. The permitted fragment stays on the cold path
    // (buffered for in-place retry once the neighbor resolves).
    let mut snapshot = policy_deny_snapshot();
    snapshot.policies = vec![PolicyRuleSnapshot {
        name: "permit-lan-wan".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    }];
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame();
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta(),
    );

    assert_eq!(
        dbg.missing_neigh, 1,
        "#4024: the permitted fragment still resolves MissingNeighbor"
    );
    assert_eq!(
        dbg.policy_deny, 0,
        "#4024: an `application any` permit must not deny the flowless fragment"
    );
    assert!(
        !binding.pending_neigh.is_empty(),
        "#4024: a PERMITTED flowless MissingNeighbor fragment must still take the \
         forward/retry path (buffered for neighbor resolution) — no over-gating"
    );
}

// ---- #2364: seeded fabric queue hash ------------------------------------


#[test]
fn fabric_queue_hash_is_stable_within_one_seed() {
    // Intra-process invariant: every fragment/packet of one datagram must
    // pick the same fabric binding, so the hash must be stable for a fixed
    // seed. Pin a seed and demand identical output across repeats.
    let metas = fabric_adversarial_metas(32);
    let seed = 0x0123_4567_89AB_CDEFu64;
    let first: Vec<u64> = metas
        .iter()
        .map(|(m, ports)| fabric_queue_hash_seeded(seed, None, Some(*ports), *m, false))
        .collect();
    for _ in 0..128 {
        let again: Vec<u64> = metas
            .iter()
            .map(|(m, ports)| fabric_queue_hash_seeded(seed, None, Some(*ports), *m, false))
            .collect();
        assert_eq!(
            first, again,
            "fabric_queue_hash must be stable for a fixed seed (no fragment reorder)"
        );
    }
}


#[test]
fn fabric_queue_hash_distribution_depends_on_seed() {
    // Hardening invariant: the fabric queue selection is not an externally
    // probeable pure function of the tuple. Two seeds must produce a
    // different hash distribution for the SAME attacker tuple set, so a
    // flow generator cannot precompute a single-worker pin. With the prior
    // unseeded `seed = meta.protocol` the distribution is seed-independent
    // and this fails — fail-on-revert.
    let metas = fabric_adversarial_metas(64);
    let ref_seed = 0xA5A5_0000_C3C3_FFFFu64;
    let reference: Vec<u64> = metas
        .iter()
        .map(|(m, ports)| fabric_queue_hash_seeded(ref_seed, None, Some(*ports), *m, false))
        .collect();
    let mut diverged = false;
    for seed in 1u64..4096u64 {
        if seed == ref_seed {
            continue;
        }
        let dist: Vec<u64> = metas
            .iter()
            .map(|(m, ports)| fabric_queue_hash_seeded(seed, None, Some(*ports), *m, false))
            .collect();
        if dist != reference {
            diverged = true;
            break;
        }
    }
    assert!(
        diverged,
        "fabric_queue_hash distribution did not change across seeds — \
         hash is seed-independent (unseeded regression, #2364)"
    );
}


#[test]
fn fabric_queue_hash_seed_reshuffles_modular_target_buckets() {
    // The production consumer is `flow_hash % local_fabric_binding_count`.
    // Model that with a small modulus and show the per-flow target bucket
    // assignment changes across seeds — i.e. an attacker who biased all
    // flows onto one fabric worker under a known mapping loses that pin on
    // the next boot's reseed.
    const FABRIC_QUEUES: u64 = 6; // mlx5 VF: 6 combined RX queues → 6 workers
    let metas = fabric_adversarial_metas(96);
    let buckets = |seed: u64| -> Vec<u64> {
        metas
            .iter()
            .map(|(m, ports)| {
                fabric_queue_hash_seeded(seed, None, Some(*ports), *m, false) % FABRIC_QUEUES
            })
            .collect()
    };
    let a = buckets(0xDEAD_BEEF_CAFE_BABE);
    let b = buckets(0xDEAD_BEEF_CAFE_BABE ^ 0xFFFF_FFFF_FFFF_FFFF);
    assert_ne!(
        a, b,
        "modular fabric target assignment is identical across seeds — \
         reseed does not break a precomputed single-worker pin (#2364)"
    );
}


#[test]
fn non_first_fragment_v6_not_dropped_by_port_matching_output_filter() {
    let payload = [0x82, 0x35, 0x01, 0xbb, 0, 0, 0, 0];
    let frame = eth_ipv6_frag_frame(0x0008, &payload); // non-first (offset != 0)
    let forwarding = build_forwarding_state(&ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 12,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v6: "wan-drop6".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-drop6".into(),
            family: "inet6".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "discard".into(),
                log: true,
                ..Default::default()
            }],
        }],
        ..Default::default()
    });
    let ingress_ident = frag_test_ingress_ident();
    let decision = frag_test_decision();
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 10,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        pkt_len: 80,
        l3_offset: 14,
        flow_src_port: 33333,
        flow_dst_port: 443,
        flow_src_addr: [
            0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0x00,
        ],
        flow_dst_addr: [
            0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00,
        ],
        ..UserspaceDpMeta::default()
    };
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        &frame,
        meta,
        &decision,
        &forwarding,
        None,
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    );

    let req = req.expect("a non-first IPv6 fragment must NOT be dropped by a port filter");
    assert_eq!(req.flow_key, None, "v6 fragment TX selection must use no flow_key");
    assert_eq!(req.expected_ports, None, "v6 fragment must not carry payload ports");
}


#[test]
fn pending_neigh_fragment_buffers_no_flow_key() {
    // Mirrors the poll_descriptor pending-neigh buffer-admission expression
    // (#2357): a buffered packet's stored flow_key later drives
    // resolve_cos_tx_selection_at on flush, so a non-first fragment must
    // store `None` rather than a payload-derived ported tuple. A legitimate
    // flowless TCP packet (real L4 header) keeps its meta-derived flow_key.
    let flow: Option<&SessionFlow> = None;

    // Non-first fragment frame; meta claims a ported tuple (the shim stamps
    // payload bytes). The gate must suppress the meta fallback.
    let frag_frame = eth_ipv4_frag_frame(0x0001, &[0x82, 0x35, 0x01, 0xbb, 0, 0, 0, 0]);
    let frag_meta = frag_test_meta(14);
    let frag_key = flow
        .as_ref()
        .map(|flow| flow.forward_key.clone())
        .or_else(|| {
            if frame_is_non_first_fragment(&frag_frame, frag_meta) {
                None
            } else {
                parse_session_flow_from_meta(frag_meta).map(|flow| flow.forward_key)
            }
        });
    assert_eq!(
        frag_key, None,
        "a buffered non-first fragment must store no flow_key"
    );

    // First/atomic fragment (real L4 header) — same meta — keeps its ports.
    let ok_frame = eth_ipv4_frag_frame(0x0000, &[0x82, 0x35, 0x01, 0xbb, 0, 0, 0, 0]);
    let ok_meta = frag_test_meta(14);
    let ok_key = flow
        .as_ref()
        .map(|flow| flow.forward_key.clone())
        .or_else(|| {
            if frame_is_non_first_fragment(&ok_frame, ok_meta) {
                None
            } else {
                parse_session_flow_from_meta(ok_meta).map(|flow| flow.forward_key)
            }
        });
    let ok_key = ok_key.expect("a flowless non-fragmented TCP packet keeps its meta flow_key");
    assert_eq!(ok_key.dst_port, 443, "legit flowless packet keeps its dst port");
}


// #3534 fail-on-revert: build_forwarding_state must thread the snapshot's
// implicit-default-policy RT_FLOW log selection
// (ConfigSnapshot.default_log_session_init/close) onto PolicyState so the
// default-verdict result can stamp a default-PERMIT session. Reverting the
// forwarding_build/mod.rs assignment leaves the PolicyState flags false and the
// "true" assertions go RED. Additive: an omitted field decodes to false.
#[test]
fn build_forwarding_state_threads_default_policy_log_flags() {
    let state = build_forwarding_state(&ConfigSnapshot {
        default_policy: "permit".into(),
        default_log_session_init: true,
        default_log_session_close: true,
        ..Default::default()
    });
    assert!(
        state.policy.default_log_session_init,
        "default_log_session_init must reach PolicyState from the snapshot"
    );
    assert!(
        state.policy.default_log_session_close,
        "default_log_session_close must reach PolicyState from the snapshot"
    );

    // Omitting the selection leaves both false (the default behaviour).
    let quiet = build_forwarding_state(&ConfigSnapshot {
        default_policy: "permit".into(),
        ..Default::default()
    });
    assert!(!quiet.policy.default_log_session_init);
    assert!(!quiet.policy.default_log_session_close);
}

// #5798 FAIL-ON-REVERT, NON-NAT64 arm: an ORDINARY same-family NAT association
// HIT must also be subject to the per-packet interface INPUT FILTER.
//
// The hit-arm filter block lives on the shared `{ hit }` arm, which serves BOTH
// consults — the NAT64 (cross-family) one and the #5689 same-family SNAT / DNAT
// / static-NAT / NPTv6 one. `nat64_association_hit_still_runs_interface_input_filter_5798`
// (tests_nat64_tunnel.rs) exercises only the NAT64 consult, so it would stay
// green if the filter were gated to NAT64 associations, leaving every ordinary
// NAT association hit unfiltered. This test closes that: an interface-SNAT
// lan->wan datagram, whose non-first fragment inherits via
// `nat_consult_forward_fragment_assoc`.
//
// Why the filter can install AND still catch the non-first fragment (no cache
// seeding needed here): term 1 matches `destination-port 443`, which only the
// FIRST fragment carries — a non-first fragment is flowless, so the hit arm
// evaluates it with `l3_session_flow_from_meta`'s zero ports and `l4_present`
// false. So the first fragment terminates on the accept term and installs the
// association; the non-first fragment falls through to term 2's
// `from is-fragment then discard`.
//
// The `nat_frag_untranslated_dropped == 0` assertion is what stops this passing
// for the wrong reason: it proves the fragment was dropped by the FILTER on the
// hit path, not by the #6122 fail-closed drop that a consult MISS would take.
//
// RED on revert: delete the input-filter block from the `{ hit }` arm in
// poll_descriptor (or gate it on `decision.nat.nat64`) and the discarded case
// forwards + SNATs.
#[test]
fn nat_ordinary_association_hit_still_runs_interface_input_filter_5798() {
    // Returns (forward, nat_applied_snat, nat_frag_untranslated_dropped) for the
    // NON-first fragment.
    let run = |second_term_action: &str| -> (u64, u64, u64) {
        let mut snapshot = policy_deny_snapshot();
        snapshot.default_policy = "permit".to_string();
        snapshot.policies.clear();
        snapshot.neighbors = vec![frag_transit_wan_neighbor()];
        snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
            name: "snat-lan-wan".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            interface_mode: true,
            ..Default::default()
        }];
        snapshot.interfaces[0].filter_input_v4 = "frag-gate".to_string();
        snapshot.filters = vec![FirewallFilterSnapshot {
            name: "frag-gate".to_string(),
            family: "inet".to_string(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "allow-first".to_string(),
                    destination_ports: vec!["443".to_string()],
                    action: "accept".to_string(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "fragments".to_string(),
                    is_fragment: true,
                    action: second_term_action.to_string(),
                    ..Default::default()
                },
            ],
        }];
        let forwarding = build_forwarding_state(&snapshot);

        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
        binding.interface = Arc::<str>::from("reth1.0");
        let mut sessions = SessionTable::new();
        let ha_state = BTreeMap::new();

        // FIRST fragment: terminates on the `destination-port 443` accept term,
        // is interface-SNAT'd, and installs the ordinary-NAT association.
        let first = udp_frag_frame_5689(0x2000, 0xf00d);
        let (_b1, dbg1) = txn_run_descriptor(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &first,
            udp_frag_meta_5689(),
        );
        assert_eq!(
            dbg1.nat_applied_snat, 1,
            "the SNAT'd first fragment must translate and install the association"
        );
        assert_eq!(
            forwarding.nat64.frag_assoc.len(),
            1,
            "the first fragment must install exactly one ordinary-NAT association"
        );

        // NON-first fragment: association HIT, then the per-packet filter.
        let non_first = udp_frag_frame_5689(0x0001, 0xf00d);
        let (batch, dbg2) = txn_run_descriptor(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &non_first,
            udp_frag_meta_5689(),
        );
        (
            dbg2.forward,
            dbg2.nat_applied_snat,
            batch.nat_frag_untranslated_dropped,
        )
    };

    // Control: with the fragment term set to `accept`, the ordinary-NAT
    // association hit forwards and inherits the SNAT translation. This proves
    // the seeded hit is real, so the discard case below cannot pass for an
    // unrelated reason.
    let (fwd_open, snat_open, miss_drop_open) = run("accept");
    assert_eq!(
        fwd_open, 1,
        "#5798 control: with an accepting fragment term the ordinary-NAT hit must forward"
    );
    assert_eq!(
        snat_open, 1,
        "#5798 control: the inherited fragment must be SNAT-translated"
    );
    assert_eq!(
        miss_drop_open, 0,
        "#5798 control: it was an association HIT, not a #6122 fail-closed miss"
    );

    // The guard.
    let (fwd_filtered, snat_filtered, miss_drop_filtered) = run("discard");
    assert_eq!(
        fwd_filtered, 0,
        "#5798: a NON-NAT64 (ordinary SNAT) association HIT must still be subject to the \
         per-packet interface input filter — `from is-fragment then discard` must drop it"
    );
    assert_eq!(
        snat_filtered, 0,
        "#5798: the filtered fragment must not be SNAT-translated and forwarded"
    );
    assert_eq!(
        miss_drop_filtered, 0,
        "#5798: the drop must come from the INPUT FILTER on the hit path, not from the #6122 \
         fail-closed association-miss drop (which would mean the association never hit and \
         this test proved nothing about the hit arm)"
    );
}
