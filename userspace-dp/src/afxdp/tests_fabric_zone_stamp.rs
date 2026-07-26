// #6458: end-to-end fail-on-revert coverage for the fabric zone-encoded
// src-MAC validation, driven through the REAL
// `poll_binding_process_descriptor` control flow (not the decode helper).
//
// The exploit: an L2-adjacent host on the HA fabric segment stamps a
// synthetic source MAC `02:bf:72:fe:<hi>:<lo>` encoding
// `StableZoneID("lan")` onto a frame and picks the ingress ZONE the
// receiving node evaluates new-flow policy / screens / host-inbound under.
// Before the fix the decode checked only fabric-ingress + magic +
// zone-exists, so the stamped `lan -> wan` permit admitted the flow and
// installed a session. The fix honors the stamp only when it validates
// against the fabric link identity (unicast dst == our fabric MAC) and the
// live RG ownership (V1b claimed-zone RG not locally active at stage 9;
// V2 resolution-owner RG locally active at the session-miss zone pair).
//
// Sibling `#[path]` test module loaded from afxdp/mod.rs, mirroring the
// #4840 split; helpers come from afxdp/tests_support.rs.
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

/// Control-zone id for the restrictive-fabric fixture (arbitrary test id,
/// distinct from the `test_zone_ids` constants — lan=1, wan=2).
const TEST_CONTROL_ZONE_ID: u16 = 9;

/// The fabric link in `nat_snapshot_with_fabric` (parent ifindex 21) has
/// local MAC 02:bf:72:ff:00:01; the legitimate peer unicasts the redirect
/// to it. Build a LAN→WAN TCP SYN frame carrying the zone-encoded stamp
/// for `zone_id` in the source MAC, addressed to the fabric link's MAC —
/// byte-identical to what the legitimate sender emits, except the RG
/// placement decides whether it is legitimate. The destination (8.8.8.8)
/// resolves via the default route to the fixture's REACHABLE gateway
/// neighbor (172.16.80.1), so an admitted flow installs a session AND
/// queues a forward — the two observables the forged-frame pins assert
/// against (a connected-subnet dst would strand in MissingNeighbor and
/// make the deny assertions vacuous).
fn stamped_fabric_frame(zone_id: u16) -> Vec<u8> {
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let [hi, lo] = zone_id.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    frame
}

fn fabric_binding() -> BindingWorker {
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 21, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    binding
}

fn active_rg(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

/// #6458 fail-on-revert, single-primary node: a forged stamp claiming
/// `lan` arrives on the fabric while lan's RG (2) is forwarding-active
/// LOCALLY. The stage-9 RG-binding check rejects the stamp, so the new
/// flow evaluates under the fabric interface's own (unzoned) zone and the
/// default-deny drops it: NO session, NO forward. Before the fix the
/// stamped `lan -> wan` permit admitted the flow and installed a session
/// with a queued forward — both assertions go RED.
#[test]
fn forged_fabric_stamp_denied_when_claimed_zone_rg_is_local_6458() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Single-primary placement: BOTH RGs forwarding-active locally.
    let ha_state = BTreeMap::from([(1, active_rg(now_secs)), (2, active_rg(now_secs))]);
    let frame = stamped_fabric_frame(TEST_LAN_ZONE_ID);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, (frame.len() - 14) as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        sessions.len(),
        0,
        "forged zone-encoded stamp must not install a session (RED on revert: \
         the stamped lan -> wan permit installs one)"
    );
    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "forged zone-encoded stamp must not queue a forward (RED on revert: \
         the admitted flow forwards toward the WAN gateway)"
    );
}

/// #6458 fail-on-revert (V2 owner binding), host-inbound variant: the
/// fabric parent sits in a RESTRICTIVE `control` zone (ping-only), so an
/// UNSTAMPED fabric-ingress packet to the firewall's own reth address is
/// denied host-inbound SSH. The attacker stamps `lan` (host-inbound `all`
/// in this fixture) to escalate. The stage-9 RG-binding check honors the
/// stamp (lan's RG 2 is not locally active — the WAN RG 1 primary is us),
/// but the session-miss V2 owner binding strips it: the local-delivery
/// target lives on reth1.0 (RG 2), which is NOT forwarding-active locally
/// either — the peer never punts host-bound traffic for an RG it owns to
/// us. The packet therefore evaluates under the restrictive control zone
/// and is denied: NO host-bound session. Before the fix the stamped `lan`
/// admit set opened SSH — the session caches and this test goes RED.
#[test]
fn forged_fabric_stamp_denied_for_host_inbound_when_owner_rg_remote_6458() {
    let mut snapshot = nat_snapshot_with_fabric();
    // A restrictive fabric zone: ping only, no SSH. Mirrors the reference
    // cluster's `control` zone containing fab0/fab1, but locked down so the
    // stamp's zone escalation is observable.
    snapshot.zones.push(ZoneSnapshot {
        name: "control".to_string(),
        id: TEST_CONTROL_ZONE_ID,
        host_inbound_configured: true,
        host_inbound_system_services: vec!["ping".to_string()],
        ..Default::default()
    });
    snapshot.interfaces[2].zone = "control".to_string(); // ge-0/0/0 (fabric parent)
    let forwarding = build_forwarding_state(&snapshot);
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Split placement: WAN RG (1) is local; LAN RG (2) is the peer's.
    let ha_state = BTreeMap::from([(1, active_rg(now_secs))]);
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 0, 61, 1),
        12345,
        22,
        TCP_FLAG_SYN,
    );
    let [hi, lo] = TEST_LAN_ZONE_ID.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, (frame.len() - 14) as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        sessions.len(),
        0,
        "a stamped host-inbound escalation must not cache a host-bound session \
         (RED on revert: the forged lan admit set opens SSH)"
    );
    assert!(
        binding.scratch.scratch_recycle.contains(&128),
        "the denied host-inbound packet must be dropped"
    );
}

/// #6458 preservation pin, host-inbound split-RG variant: the LAN RG (2)
/// primary is US, the WAN RG (1) primary is the PEER. A remote host's SSH
/// to our reth1.0 address ingressed the peer (WAN side) and is
/// legitimately punted across the fabric stamped `wan`. The stamp
/// validates (unicast dst; claimed-zone RG 1 not local; local-delivery
/// target's RG 2 IS local), so host-inbound evaluates under `wan` (admits
/// `all` here) and the host-bound session caches — identical before and
/// after the fix.
#[test]
fn legitimate_fabric_punted_host_inbound_still_admitted_6458() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Split placement: LAN RG (2) is local; WAN RG (1) is the peer's.
    let ha_state = BTreeMap::from([(2, active_rg(now_secs))]);
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(172, 16, 80, 200),
        Ipv4Addr::new(10, 0, 61, 1),
        43210,
        22,
        TCP_FLAG_SYN,
    );
    let [hi, lo] = TEST_WAN_ZONE_ID.to_be_bytes();
    frame[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, (frame.len() - 14) as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert!(
        sessions.len() >= 1,
        "the legitimate split-RG host-inbound punt must keep caching its session"
    );
}

/// #6458 preservation pin, split-RG active/active: the LAN RG (2) primary
/// is the PEER, the WAN RG (1) primary is US. The peer legitimately punts
/// a LAN→WAN new flow across the fabric stamped `lan`; the stamp
/// validates (unicast dst, claimed-zone RG not local, resolution-owner RG
/// local), the `lan -> wan` permit admits the flow, and the session
/// installs with a queued forward — identical before and after the fix.
#[test]
fn legitimate_fabric_punted_flow_still_admitted_6458() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Split placement: WAN RG (1) is local; LAN RG (2) is the peer's.
    let ha_state = BTreeMap::from([(1, active_rg(now_secs))]);
    let frame = stamped_fabric_frame(TEST_LAN_ZONE_ID);
    let meta = txn_meta_v4(21, TCP_FLAG_SYN, (frame.len() - 14) as u16);

    let mut binding = fabric_binding();
    let mut sessions = SessionTable::new();
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        sessions.len(),
        2,
        "the legitimate split-RG fabric punt must keep installing its session \
         (forward + reverse companion for the NAT'd lan -> wan flow)"
    );
    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "the legitimate split-RG fabric punt must keep forwarding"
    );
}
