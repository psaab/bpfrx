// NAT64 translation/exhaustion accounting and tunnel-gate delivery.
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

// I14: a NAT64 flow refused at cap is dropped like any other refused
// flow — one translated packet must NOT leak out, nothing installs,
// nothing caches (the NAT64 v4-source pick is a stateless round-robin
// with no reservation, so there is nothing to roll back — plan §4 I14).
#[test]
fn txn_nat64_refusal_at_cap_drops_translated_packet() {
    let mut snapshot = nat_snapshot();
    snapshot.nat64_rules = vec![crate::protocol::NAT64RuleSnapshot {
        name: "nat64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["172.16.80.50".to_string()],
        no_v6_frag_header: false,
            ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(0);

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 12345, 443);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 74,
        pkt_len: (frame.len() - 14) as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(
        dbg.tx, 0,
        "a refused NAT64 flow must not forward its translated trigger packet"
    );
    assert_eq!(sessions.len(), 0);
    assert_eq!(sessions.admission_refused(), 1);
    assert_eq!(txn_flow_cache_entries(&binding), 0);
    assert_eq!(batch.session_creates, 0);

    // Below cap the same flow is admitted — sanity that the fixture
    // actually exercises the NAT64 install path (forward + reverse).
    sessions.set_max_sessions_for_test(16);
    let meta2 = UserspaceDpMeta { ..meta };
    let (batch2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta2,
    );
    assert_eq!(
        sessions.len(),
        2,
        "NAT64 forward + reverse install below cap"
    );
    assert_eq!(batch2.session_creates, 2);
    assert_eq!(dbg2.tx, 1);
}


// #2161: a successful NAT64 forward translation (v6 client SYN -> v4) must
// bump the per-binding nat64_translations counter, and the matching v4
// reply (v4 server -> v6 client, reverse session hit) must bump it again.
// The counter previously stayed 0 even though the translated packets flowed
// on the wire (observability gap caught in the #2132 NAT smoke). A refused
// flow (table at cap, packet dropped) must NOT bump it.
#[test]
fn txn_nat64_translation_bumps_counter_both_directions() {
    let mut snapshot = nat_snapshot();
    snapshot.nat64_rules = vec![crate::protocol::NAT64RuleSnapshot {
        name: "nat64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["172.16.80.50".to_string()],
        no_v6_frag_header: false,
            ..Default::default()
    }];
    // The reverse v4->v6 reply forwards back to the v6 client on reth1.0;
    // seed its neighbor so the reverse resolution is a usable ForwardCandidate
    // (otherwise the reply would stall on MissingNeighbor and never reach the
    // forward-candidate counting site — a fixture gap, not a code gap).
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "reth1.0".to_string(),
        ifindex: 24,
        family: "inet6".to_string(),
        ip: "2001:559:8585:ef00::102".to_string(),
        mac: "02:aa:bb:cc:dd:ee".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    });
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    // Refused-at-cap case first: the translated trigger is dropped, so the
    // counter must stay 0 (counting happens only on the admitted forward).
    sessions.set_max_sessions_for_test(0);
    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let fwd_frame = build_txn_tcp_syn_frame_v6(src, dst, 12345, 443);
    let fwd_meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 74,
        pkt_len: (fwd_frame.len() - 14) as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let (refused_batch, refused_dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &fwd_frame,
        fwd_meta,
    );
    assert_eq!(refused_dbg.tx, 0, "refused NAT64 flow must not forward");
    assert_eq!(
        refused_batch.nat64_translations, 0,
        "a dropped NAT64 trigger must not increment the translations counter"
    );

    // Below cap: the forward v6->v4 translation is admitted and counted once.
    sessions.set_max_sessions_for_test(16);
    let (fwd_batch, fwd_dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &fwd_frame,
        UserspaceDpMeta { ..fwd_meta },
    );
    assert_eq!(
        fwd_dbg.tx, 1,
        "admitted NAT64 forward must translate + forward"
    );
    assert_eq!(sessions.len(), 2, "NAT64 forward + reverse install");
    assert_eq!(
        fwd_batch.nat64_translations, 1,
        "the admitted v6->v4 translation must bump the counter exactly once"
    );

    // Reverse: the v4 server reply hits the reverse session and translates
    // v4->v6, bumping the counter again.
    //
    // #4381: the forward flow's source port is now TRANSLATED to a UNIQUE pool
    // port (RFC 6146 BIB) instead of being preserved, so the server replies to
    // the TRANSLATED port and the reverse session keys on it. Discover the
    // translated port from the installed reverse (v4) session rather than
    // assuming the original 12345 is preserved.
    let pool_v4: Ipv4Addr = "172.16.80.50".parse().expect("pool v4");
    let dst_v4: Ipv4Addr = "8.8.8.8".parse().expect("dst v4");
    let mut translated_port = 0u16;
    sessions.iter_with_origin(|key, _decision, _metadata, _origin| {
        if key.addr_family == libc::AF_INET as u8 {
            translated_port = key.dst_port;
        }
    });
    assert_ne!(
        translated_port, 0,
        "the reverse NAT64 (v4) session must key on a translated port"
    );
    assert_ne!(
        translated_port, 12345,
        "#4381: the source port must be translated, not preserved"
    );
    // SYN-ACK = SYN (0x02) | ACK (0x10). TCP_FLAG_ACK is not exported at the
    // afxdp module level, so spell the ACK bit inline.
    const ACK: u8 = 0x10;
    let reply_frame =
        build_txn_tcp_syn_frame_v4(dst_v4, pool_v4, 443, translated_port, TCP_FLAG_SYN | ACK);
    let reply_meta = txn_meta_v4(24, TCP_FLAG_SYN | ACK, (reply_frame.len() - 14) as u16);
    let (rev_batch, _rev_dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &reply_frame,
        reply_meta,
    );
    assert_eq!(
        rev_batch.nat64_translations, 1,
        "the v4->v6 reverse translation must bump the counter exactly once"
    );
}


// #2218: a translated forward flow through the worker poll path must bump the
// matched SNAT rule's per-rule hit counter exactly once on the committed
// install, and NOT bump it for a refused-at-cap flow (the trigger is dropped,
// no session is created). FAIL-ON-REVERT: with the cold-path increment line
// removed, the admitted-flow assertion (count == 1) fails.
#[test]
fn txn_source_nat_translation_bumps_rule_counter_once() {
    let mut snapshot = nat_snapshot();
    // Stamp a per-rule counter id on the interface-mode SNAT rule that the
    // 10.0.61.x -> 8.8.8.8 lan->wan flow matches.
    snapshot.source_nat_rules[0].counter_id = 5;

    let policy_counters = crate::policy::PolicyCounterStore::default();
    let nat_counters = crate::nat::NatCounterStore::default();
    let forwarding =
        build_forwarding_state_with_counters(&snapshot, &policy_counters, &nat_counters);
    let counter = nat_counters
        .rule_counter(5)
        .expect("store must hold the parsed rule's counter");

    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    // Phase 1 — refused at cap 0: the trigger is dropped, nothing installs, so
    // the counter MUST stay 0.
    sessions.set_max_sessions_for_test(0);
    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, (frame.len() - 14) as u16);
    let (_b0, d0) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(d0.tx, 0, "refused SNAT flow must not forward");
    assert_eq!(
        nat_counters.snapshots()[0].packets,
        0,
        "a refused (rolled-back) SNAT translation must not be counted"
    );

    // Phase 2 — admitted below cap: the forward translation commits and the
    // counter bumps exactly once (per committed flow, with the trigger len).
    sessions.set_max_sessions_for_test(16);
    let (_b1, d1) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(d1.tx, 1, "admitted SNAT flow must forward its trigger");
    let snaps = nat_counters.snapshots();
    assert_eq!(snaps.len(), 1, "exactly one NAT rule counter");
    assert_eq!(snaps[0].counter_id, 5);
    assert_eq!(
        snaps[0].packets, 1,
        "the committed SNAT translation must bump the counter exactly once"
    );
    assert_eq!(
        snaps[0].bytes,
        frame.len() as u64,
        "the per-flow byte count is the trigger descriptor length (full frame, matching the policy counter's desc.len semantic)"
    );
    // The shared Arc reflects the same count.
    assert_eq!(
        counter.snapshot(5).packets,
        1,
        "the rule's shared Arc carries the committed count"
    );

    // Phase 3 — a NON-translated flow (different SNAT rule with no counter):
    // build a fresh forwarding with the rule's counter_id back to 0 and verify
    // the store stays empty after a flow.
    let mut snapshot2 = nat_snapshot();
    snapshot2.source_nat_rules[0].counter_id = 0;
    let nat_counters2 = crate::nat::NatCounterStore::default();
    let forwarding2 = build_forwarding_state_with_counters(
        &snapshot2,
        &crate::policy::PolicyCounterStore::default(),
        &nat_counters2,
    );
    let mut binding2 = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding2.interface = Arc::<str>::from("reth1.0");
    let mut sessions2 = SessionTable::new();
    sessions2.set_max_sessions_for_test(16);
    let (_b2, d2) = txn_run_descriptor(
        &mut binding2,
        &mut sessions2,
        &forwarding2,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(d2.tx, 1, "the uncounted SNAT flow still forwards");
    assert!(
        nat_counters2.snapshots().is_empty(),
        "a counter_id-0 SNAT rule allocates no counter, so the store stays empty"
    );
}


// #2161: BatchCounters.nat64_translations must flush into BindingLiveState
// and survive into the snapshot the coordinator reads to build the wire
// BindingStatus.nat64_translations the Go control plane sums. This guards
// the deepest plumbing layer end to end (counter -> live atomic ->
// snapshot) so a dropped flush line or a missed snapshot field is caught.
#[test]
fn nat64_translations_flushes_to_live_and_snapshot() {
    let live = BindingLiveState::new();
    let mut batch = BatchCounters::default();
    // rx_telemetry sets `touched` for every RX packet before the
    // forward-candidate counting site; mirror that so flush runs.
    batch.touched = true;
    batch.nat64_translations = 3;
    batch.flush(&live);
    assert_eq!(
        batch.nat64_translations, 0,
        "flush must zero the batched count"
    );
    let snap = live.snapshot();
    assert_eq!(
        snap.nat64_translations, 3,
        "the live atomic + snapshot must carry the flushed NAT64 count"
    );
}


// #2291: the fail-closed NAT64 drop counter (prefix matched, no source pool)
// must flush BatchCounters -> BindingLiveState -> snapshot the same way as
// nat64_translations, so an operator can see the drops and a dropped flush
// line is caught at build/test time.
#[test]
fn nat64_no_source_pool_flushes_to_live_and_snapshot() {
    let live = BindingLiveState::new();
    let mut batch = BatchCounters::default();
    batch.touched = true;
    batch.nat64_no_source_pool = 5;
    batch.flush(&live);
    assert_eq!(
        batch.nat64_no_source_pool, 0,
        "flush must zero the batched no-source-pool drop count"
    );
    let snap = live.snapshot();
    assert_eq!(
        snap.nat64_no_source_pool, 5,
        "the live atomic + snapshot must carry the flushed no-source-pool count"
    );
}


// #4520: the transient NAT64 pool-exhaustion drop counter must flush
// BatchCounters -> BindingLiveState -> snapshot the same way as its
// config/empty sibling nat64_no_source_pool, so an operator can see the
// transient drops and a dropped flush/snapshot line is caught at build/test
// time.
#[test]
fn nat64_pool_exhausted_flushes_to_live_and_snapshot() {
    let live = BindingLiveState::new();
    let mut batch = BatchCounters::default();
    batch.touched = true;
    batch.nat64_pool_exhausted = 7;
    batch.flush(&live);
    assert_eq!(
        batch.nat64_pool_exhausted, 0,
        "flush must zero the batched pool-exhausted drop count"
    );
    let snap = live.snapshot();
    assert_eq!(
        snap.nat64_pool_exhausted, 7,
        "the live atomic + snapshot must carry the flushed pool-exhausted count"
    );
    assert_eq!(
        snap.nat64_no_source_pool, 0,
        "the config/empty sibling must NOT be touched by a pool-exhaustion drop"
    );
}


// #4520: the NAT64 source-allocation failure reason must be attributed to the
// RIGHT counter — transient port exhaustion (add capacity) split from a
// config/empty pool (fix config), mirroring source-NAT. FAIL-ON-REVERT:
// collapsing both arms back onto nat64_no_source_pool (the pre-#4520
// `Err(_) => nat64_no_source_pool += 1`) makes the AllocatorExhausted
// assertion below fail RED.
#[test]
fn record_nat64_source_failure_splits_exhaustion_from_config() {
    use crate::nat::SourceNatFailureReason;

    // Transient exhaustion -> nat64_pool_exhausted, NOT nat64_no_source_pool.
    let mut batch = BatchCounters::default();
    batch.record_nat64_source_failure(SourceNatFailureReason::AllocatorExhausted);
    assert_eq!(
        batch.nat64_pool_exhausted, 1,
        "AllocatorExhausted must bump nat64_pool_exhausted (transient)"
    );
    assert_eq!(
        batch.nat64_no_source_pool, 0,
        "AllocatorExhausted must NOT bump nat64_no_source_pool (config/empty)"
    );
    assert!(batch.touched, "recording a drop must mark the batch touched");

    // Every non-exhaustion reason -> nat64_no_source_pool (config/empty).
    for reason in [
        SourceNatFailureReason::MissingPool,
        SourceNatFailureReason::EmptyPool,
        SourceNatFailureReason::InvalidPool,
        SourceNatFailureReason::WrongAddressFamily,
    ] {
        let mut b = BatchCounters::default();
        b.record_nat64_source_failure(reason);
        assert_eq!(
            b.nat64_no_source_pool, 1,
            "{reason:?} must bump nat64_no_source_pool (config/empty)"
        );
        assert_eq!(
            b.nat64_pool_exhausted, 0,
            "{reason:?} must NOT bump nat64_pool_exhausted (transient)"
        );
    }
}


// #2562: the fail-closed NAT64 fragment-drop counter must flush
// BatchCounters -> BindingLiveState -> snapshot the same way as the sibling
// nat64 drop counters, so an operator can see fragmented-NAT64 drops and a
// dropped flush/snapshot line is caught at build/test time.
#[test]
fn nat64_frag_dropped_flushes_to_live_and_snapshot() {
    let live = BindingLiveState::new();
    let mut batch = BatchCounters::default();
    batch.touched = true;
    batch.nat64_frag_dropped = 4;
    batch.flush(&live);
    assert_eq!(
        batch.nat64_frag_dropped, 0,
        "flush must zero the batched fragment-drop count"
    );
    let snap = live.snapshot();
    assert_eq!(
        snap.nat64_frag_dropped, 4,
        "the live atomic + snapshot must carry the flushed fragment-drop count"
    );
    // The fragment drop is a distinct bucket from the pool counters.
    assert_eq!(snap.nat64_no_source_pool, 0);
    assert_eq!(snap.nat64_pool_exhausted, 0);
}


// #2562: `record_nat64_frag_dropped` bumps the fragment-drop counter and marks
// the batch touched (so the value survives to the next flush).
#[test]
fn record_nat64_frag_dropped_bumps_counter() {
    let mut batch = BatchCounters::default();
    assert!(!batch.touched);
    batch.record_nat64_frag_dropped();
    batch.record_nat64_frag_dropped();
    assert_eq!(
        batch.nat64_frag_dropped, 2,
        "each record must bump the fragment-drop counter"
    );
    assert!(batch.touched, "recording a drop must mark the batch touched");
    // Sibling nat64 drop counters are untouched.
    assert_eq!(batch.nat64_no_source_pool, 0);
    assert_eq!(batch.nat64_pool_exhausted, 0);
}

// === #1873 R-C: blanket tunnel gate at the slow-path chokepoint ===


/// #1873 R-C: a tunnel-marked inner packet must NEVER be enqueued to
/// the kernel slow-path TUN — through ANY door (build-failure
/// fallback, NoRoute, MissingNeighbor non-forward dispositions). It is
/// dropped with the dedicated counter + exception, and the generic
/// slow_path_drops counter stays untouched (proving the gate fires
/// BEFORE the enqueue/unavailable handling, not as a side effect of
/// slow_path being absent).
#[test]
fn tunnel_marked_frame_never_reaches_slow_path() {
    for (i, disposition) in [
        ForwardingDisposition::ForwardCandidate, // build-failure door
        ForwardingDisposition::NoRoute,
        ForwardingDisposition::MissingNeighbor,
    ]
    .into_iter()
    .enumerate()
    {
        let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
        let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
        maybe_reinject_slow_path_from_frame(
            &binding,
            &live,
            None,
            &local_tunnel_deliveries,
            &frame,
            meta,
            tunnel_marked_decision(disposition),
            &recent_exceptions,
            "forward_build_slow_path",
            &ForwardingState::default(),
        );
        assert_eq!(
            live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed),
            1,
            "case {i}: tunnel gate did not fire"
        );
        assert_eq!(
            live.slow_path_drops.load(Ordering::Relaxed),
            0,
            "case {i}: generic slow-path drop counted — gate fired too late"
        );
        assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
        let exceptions = recent_exceptions.lock().expect("exceptions");
        assert_eq!(
            exceptions.back().expect("exception").reason,
            "tunnel_encap_unresolved",
            "case {i}"
        );
    }
}


/// #1873 R-C: the build-failure entry point (`handle_forward_build_failure`
/// with fallback_to_slow_path = true) funnels through the same gate.
#[test]
fn tunnel_marked_build_failure_drops_instead_of_slow_path() {
    let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let mut dbg = DebugPollCounters::default();
    handle_forward_build_failure(
        &binding,
        &live,
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        6,
        frame.len() as u32,
        &frame,
        meta,
        tunnel_marked_decision(ForwardingDisposition::ForwardCandidate),
        true,
        &ForwardingState::default(),
    );
    assert_eq!(
        live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed),
        1
    );
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
}


/// #1873 R-C: the local_tunnel_deliveries branch (GRE local-origin
/// INBOUND delivery, keyed by local_ifindex) must stay OPEN — the gate
/// sits after it.
#[test]
fn tunnel_gate_keeps_local_tunnel_delivery_open() {
    let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
    let (tx, rx) = mpsc::sync_channel(4);
    // #2412: the delivery map now carries the eventfd wake alongside the
    // sender; the worker slow path signals it via LocalTunnelDelivery.
    let wake = Arc::new(TunnelWake::new().expect("eventfd"));
    let mut deliveries = BTreeMap::new();
    deliveries.insert(9, LocalTunnelDelivery { tx, wake });
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));
    let mut decision = tunnel_marked_decision(ForwardingDisposition::LocalDelivery);
    decision.resolution.local_ifindex = 9;
    maybe_reinject_slow_path_from_frame(
        &binding,
        &live,
        None,
        &local_tunnel_deliveries,
        &frame,
        meta,
        decision,
        &recent_exceptions,
        "forward_build_slow_path",
        &ForwardingState::default(),
    );
    assert_eq!(
        live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed),
        0
    );
    let delivered = rx.try_recv().expect("local tunnel delivery still open");
    assert!(!delivered.is_empty());
}


/// #1873 R-E: a tunnel-marked decision whose OUTER next-hop is
/// unresolved must NOT be buffered in pending_neigh — the retry path's
/// in-place rewrite cannot encapsulate, so a buffered tunnel inner
/// packet would later TX PLAINTEXT. The frame is dropped instead.
///
/// In this fixture the tunnel endpoint carries no redundancy_group and
/// the egress RG is unowned, so the HA gate resolves the tunnel-marked
/// decision to a residual `HAInactive` (rg=0) — the §2.3 corner. Before
/// #1913 the trailing reinject chokepoint ran UNFILTERED, so this
/// HAInactive frame fell into `maybe_reinject_slow_path_from_frame` and
/// was dropped+counted at the R-C tunnel gate
/// (`tunnel_encap_unresolved_drops`). After #1913 the chokepoint gates
/// on `is_slow_path_eligible`, so the HAInactive frame is dropped
/// EARLIER, at the disposition gate (counted as an `ha_inactive`
/// exception and recycled) and never reaches `_from_frame`. Either way
/// the frame is DROPPED, NOT buffered, and NOT reinjected to the kernel
/// FIB — which is the R-E invariant under test.
#[test]
fn txn_tunnel_marked_missing_neighbor_not_buffered() {
    let mut snapshot = nat_snapshot();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "gr-0/0/0.0".to_string(),
        zone: "wan".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 77,
        ..Default::default()
    });
    snapshot.tunnel_endpoints = vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
        id: 824,
        interface: "gr-0/0/0.0".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 77,
        zone: "wan".to_string(),
        mode: "gre".to_string(),
        outer_family: "inet".to_string(),
        source: "172.16.80.8".to_string(),
        destination: "203.0.113.9".to_string(),
        transport_table: "inet.0".to_string(),
        ttl: 64,
        ..Default::default()
    }];
    snapshot.routes.push(RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "8.8.8.8/32".to_string(),
        next_hops: vec!["@gr-0/0/0.0".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
    });
    // No neighbors: the tunnel's OUTER destination (203.0.113.9 via the
    // 172.16.80.1 default gateway) is unresolved -> MissingNeighbor
    // with tunnel_endpoint_id preserved.
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, (frame.len() - 14) as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    // First packet: residual HAInactive (rg=0) tunnel-marked frame.
    // R-E invariant: never buffered for in-place retry.
    assert!(
        binding.pending_neigh.is_empty(),
        "tunnel-marked frame must never be admitted to pending_neigh (#1873 R-E)"
    );
    // #1913: the HAInactive frame is dropped at the disposition gate
    // (not eligible for slow-path reinjection) and never reaches
    // `_from_frame`, so it is NOT handed to the kernel FIB. It is
    // counted as an `ha_inactive` exception by record_forwarding_
    // disposition and recycled.
    assert_eq!(
        binding.live.slow_path_packets.load(Ordering::Relaxed),
        0,
        "HAInactive tunnel frame must NOT be reinjected to the kernel slow path (#1913)"
    );
    assert_eq!(
        binding
            .live
            .tunnel_encap_unresolved_drops
            .load(Ordering::Relaxed),
        0,
        "HAInactive frame is gated before the R-C tunnel gate post-#1913"
    );
    let _ = dbg;

    // Second packet: the HAInactive arm never seeds a session, so this
    // run re-executes the session-miss path (the `sessions` table is
    // still empty). It re-resolves to the same residual HAInactive
    // tunnel decision and must again be dropped — never buffered for
    // in-place retry and never reinjected.
    assert_eq!(
        sessions.len(),
        0,
        "HAInactive frame must NOT seed a session (second run stays on the miss path)"
    );
    let meta2 = txn_meta_v4(24, TCP_FLAG_SYN, (frame.len() - 14) as u16);
    let (_batch2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta2,
    );
    let _ = dbg2;
    assert!(
        binding.pending_neigh.is_empty(),
        "tunnel-marked frame must skip pending_neigh admission on the re-run too (#1873 R-E)"
    );
    assert_eq!(
        binding.live.slow_path_packets.load(Ordering::Relaxed),
        0,
        "second packet must also NOT be reinjected to the kernel slow path (#1913)"
    );
}


/// #1913 (Codex r1): a packet DENIED by zone policy whose forwarding
/// resolution is `MissingNeighbor` (connected destination, no neighbor
/// learned yet) must NOT be reinjected to the kernel slow path. The
/// MissingNeighbor arm has its own policy evaluation that historically
/// only gated SNAT — a DENY fell through to session install + pending-
/// neighbor buffer + the trailing reinject chokepoint with the
/// disposition still `MissingNeighbor` (slow-path-eligible), so a denied
/// unresolved-neighbor cold-path packet leaked to the kernel FIB. The
/// fix converts the deny to `PolicyDenied` and drops+recycles it inside
/// the arm. Asserts: zero reinjects, no session created, not buffered.
#[test]
fn txn_policy_denied_missing_neighbor_is_dropped_not_reinjected() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        },
        // #3457: policy_deny_snapshot() carries a dmz->wan permit policy;
        // the dmz zone must stay in the table or the #3402 fail-closed
        // gate raises UnresolvableZoneReference and build_forwarding_state
        // panics. The flow under test is lan->wan, so dmz is inert here.
        ZoneSnapshot {
            name: "dmz".to_string(),
            id: TEST_DMZ_ZONE_ID,
            ..Default::default()
        },
    ];
    // No neighbor for 172.16.80.200: the connected WAN route resolves
    // but ARP is unresolved -> MissingNeighbor (the cold path under test).
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = BTreeMap::new();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    // src 10.0.61.102 (lan, ingress ifindex 24) -> dst 172.16.80.200
    // (connected wan). lan->wan is default-deny.
    let frame = build_policy_deny_tcp_syn_frame();
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, (frame.len() - 14) as u16);
    let sessions_before = sessions.len();
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert!(
        dbg.policy_deny >= 1,
        "denied MissingNeighbor flow must be counted as a policy deny (#1913)"
    );
    assert_eq!(
        binding.live.slow_path_packets.load(Ordering::Relaxed),
        0,
        "denied MissingNeighbor flow must NOT be reinjected to the kernel slow path (#1913)"
    );
    assert!(
        binding.pending_neigh.is_empty(),
        "denied flow must NOT be buffered for in-place neighbor retry (#1913)"
    );
    assert_eq!(
        sessions.len(),
        sessions_before,
        "denied flow must NOT seed a MissingNeighbor session (#1913)"
    );
}


/// #1913 (Codex r3): the deny gate must run BEFORE the negative-cache
/// fast-fail / resolver enqueue at the top of the MissingNeighbor arm.
/// With the dst's neg-cache key pre-seeded, a denied flow must STILL be
/// converted to PolicyDenied and counted — not silently recycled by the
/// neg_neigh_gate fast-fail path (which would skip the deny event/count
/// and could enqueue a resolver probe for a flow policy says to drop).
#[test]
fn txn_policy_denied_missing_neighbor_skips_neg_cache_fast_fail() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        },
        // #3457: keep the dmz zone so policy_deny_snapshot()'s dmz->wan
        // permit policy resolves under the #3402 fail-closed gate. The
        // flow under test is lan->wan; dmz is inert.
        ZoneSnapshot {
            name: "dmz".to_string(),
            id: TEST_DMZ_ZONE_ID,
            ..Default::default()
        },
    ];
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = BTreeMap::new();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    // Pre-seed the negative cache for the connected WAN dst's neg-cache
    // key (egress reth0.80 ifindex 12, next_hop = the connected dst). If
    // the deny gate ran AFTER neg_neigh_gate, this packet would fast-fail
    // and recycle as a dead-host miss with NO policy deny counted.
    let now_ns = 123_000_000_000u64;
    binding
        .neg_neigh_cache
        .insert((12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))), now_ns);
    let mut sessions = SessionTable::new();

    let frame = build_policy_deny_tcp_syn_frame();
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, (frame.len() - 14) as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert!(
        dbg.policy_deny >= 1,
        "denied flow must be counted as a policy deny even with the neg-cache key seeded (#1913 Codex r3)"
    );
    assert_eq!(
        dbg.neg_neigh_fast_fail, 0,
        "deny gate must run BEFORE the neg-cache fast-fail — a denied flow must not take the dead-host recycle path (#1913 Codex r3)"
    );
    assert_eq!(
        binding.live.slow_path_packets.load(Ordering::Relaxed),
        0,
        "denied flow must NOT be reinjected (#1913)"
    );
    assert!(
        binding.pending_neigh.is_empty(),
        "denied flow must NOT be buffered (#1913)"
    );
}


// =====================================================================
// #5174: NAT64 MissingNeighbor cold-path fail-closed. NAT64 classification +
// source allocation are gated inside the ForwardCandidate session-miss branch,
// so a NAT64 flow whose extracted-IPv4 next-hop is UNRESOLVED reaches the
// MissingNeighbor arm with a non-NAT64 `decision.nat` — the arm previously
// evaluated policy on the SYNTHETIC IPv6 dst and seeded/buffered an untranslated
// forward (an HA-synced broken session that replays the IPv6 frame to the IPv4
// gateway). The bounded fix: re-classify NAT64 in the arm (policy on the
// extracted V4 dst), and for a permitted NAT64 flow fire the neighbor probe then
// DROP (no seed, no untranslated buffer) — the flow recovers via ForwardCandidate
// once the neighbor resolves. Full buffer-and-translate parity is a follow-up.
// =====================================================================

fn nat64_v6_syn_meta(frame_len: usize) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 74,
        pkt_len: (frame_len - 14) as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

/// #5174 FAIL-ON-REVERT: a PERMITTED NAT64 flow whose extracted-IPv4 next-hop is
/// UNRESOLVED must be handled fail-closed — (a) policy is evaluated on the
/// extracted IPv4 dst (8.8.8.8), NOT the synthetic IPv6 dst (64:ff9b::808:808),
/// and (b) NO MissingNeighborSeed is installed and NO untranslated frame is
/// buffered (the arm probes then drops). The permit rule's destination is the
/// IPv4 host `8.8.8.8/32` under a default-deny, so the flow is permitted ONLY if
/// policy matched the extracted IPv4 dst (proves (a)). Reverting the fix:
///   - drop the policy-tuple fix → policy denies on the synthetic IPv6 →
///     `nat64_missing_neigh_drop == 0` → RED;
///   - drop the fail-closed divert → the permitted flow seeds + buffers the
///     untranslated frame → `sessions.len() >= 1` / `pending_neigh` non-empty /
///     counter 0 → RED.
#[test]
fn nat64_missing_neighbor_fail_closed_drop_5174() {
    let mut snapshot = nat64_snapshot(lan_to_wan_permit("8.8.8.8/32", "permit-nat64-v4"));
    // The extracted IPv4 dst 8.8.8.8 routes via the default gw 172.16.80.1;
    // clear neighbors so that gateway is unresolved -> MissingNeighbor.
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst (extracts 8.8.8.8)");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 12345, 443);
    let meta = nat64_v6_syn_meta(frame.len());
    let (_batch, dbg) =
        txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);

    assert_eq!(
        dbg.nat64_missing_neigh_drop, 1,
        "a permitted NAT64 flow with an unresolved extracted-IPv4 next-hop must \
         fail-closed drop (policy matched the V4 dst AND the arm recycled after the probe)"
    );
    assert_eq!(
        sessions.len(),
        0,
        "NAT64 MissingNeighbor must NOT seed a (non-NAT64) MissingNeighborSeed session"
    );
    assert!(
        binding.pending_neigh.is_empty(),
        "NAT64 MissingNeighbor must NOT buffer the untranslated IPv6 frame for in-place replay"
    );
}

/// #5174 control: a PERMITTED NON-NAT64 flow (plain IPv4) whose next-hop is
/// unresolved is UNCHANGED — it still seeds/buffers the normal MissingNeighbor
/// cold path (the #5174 divert fires ONLY for a NAT64 flow). Counter stays 0.
#[test]
fn non_nat64_missing_neighbor_still_buffers_5174() {
    let mut snapshot = nat64_snapshot(lan_to_wan_permit("9.9.9.9/32", "permit-v4"));
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(9, 9, 9, 9),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, (frame.len() - 14) as u16);
    let (_batch, dbg) =
        txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);

    assert_eq!(
        dbg.nat64_missing_neigh_drop, 0,
        "the NAT64 fail-closed divert must NOT fire for a non-NAT64 flow"
    );
    assert!(
        sessions.len() >= 1 || !binding.pending_neigh.is_empty(),
        "a permitted non-NAT64 MissingNeighbor flow must still seed/buffer (unregressed cold path)"
    );
}

/// #5174 FAIL-ON-REVERT (Harm A — policy tuple): a NAT64 flow to the extracted
/// IPv4 dst 8.8.8.8 under a permit rule for a DIFFERENT v4 host (9.9.9.9) must be
/// DENIED — policy is evaluated on the correct extracted V4 dst (8.8.8.8 ∉
/// 9.9.9.9/32 → default-deny), so it exits via the normal PolicyDenied path, NOT
/// the NAT64 fail-closed divert. Reverting the policy-tuple fix evaluates policy
/// on the SYNTHETIC IPv6 dst (64:ff9b::808:808): a v4-destination rule matches a
/// v6 destination as match-any (the cross-family legacy convention), so the flow
/// is WRONGLY PERMITTED → it hits the divert (`nat64_missing_neigh_drop == 1`,
/// `policy_deny == 0`) → RED. This is the policy-divergence security bug the arm
/// classification fixes.
#[test]
fn nat64_missing_neighbor_denied_no_fail_closed_drop_5174() {
    let mut snapshot = nat64_snapshot(lan_to_wan_permit("9.9.9.9/32", "permit-other-v4"));
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst (extracts 8.8.8.8)");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 12345, 443);
    let meta = nat64_v6_syn_meta(frame.len());
    let (_batch, dbg) =
        txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);

    assert_eq!(
        dbg.nat64_missing_neigh_drop, 0,
        "a DENIED NAT64 flow must exit at the policy deny, NOT the fail-closed divert"
    );
    assert!(dbg.policy_deny >= 1, "the NAT64 flow to a non-permitted v4 dst must be policy-denied");
    assert_eq!(sessions.len(), 0);
    assert!(binding.pending_neigh.is_empty());
}
