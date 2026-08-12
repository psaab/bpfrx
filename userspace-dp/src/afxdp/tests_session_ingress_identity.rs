// #4983 PRODUCER binding: end-to-end fail-on-revert coverage for the
// session ingress-interface STAMP, driven through the REAL
// `poll_binding_process_descriptor` control flow.
//
// The feature is a chain of three links and the other two were already
// pinned: `bpf_map_tests.rs` binds the MIRROR (build_conntrack_value_v4/v6
// copy `metadata.ingress_*` onto the on-map row) with a hand-set
// `SessionMetadata`, and `pkg/cli/session_filter_ingress_identity_4983_test.go`
// binds the CONSUMER with a hand-built `dataplane.SessionValue`. Neither can
// see the PRODUCER — the handful of lines inside the 5000-line poll body that
// are the only place a REAL packet's binding ever reaches `SessionMetadata`.
// Replacing those with `0` left the whole Rust suite green, and the
// observable effect would be silent: every session would carry
// `ingress_ifindex 0`, the Go filter would fall back to the zone for all of
// them, and `show/clear security flow session interface X` would revert to
// exact pre-#4983 behaviour with CI green and no counter or log to notice.
//
// The fixture puts the ingress on a VLAN unit of a TRUNK NIC whose PARENT
// carries a DIFFERENT zone, and whose SIBLING unit on that same parent is the
// egress. That is the project's own loss-cluster wiring (reth0.50 / reth0.80
// share the physical WAN NIC) and it is the case the two halves of the stamp
// have to separate: the ifindex alone names the parent — shared by both units
// — so only the {ifindex, VLAN} PAIR names the unit the flow arrived on.
//
// Sibling `#[path]` test module loaded from afxdp/mod.rs, mirroring the #4840
// split; helpers come from afxdp/tests_support.rs.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::test_zone_ids::*;
use crate::{InterfaceAddressSnapshot, NeighborSnapshot, PolicyRuleSnapshot, ZoneSnapshot};

/// The ingress unit under test: `reth0.50`, VLAN 50 on the physical trunk
/// `ge-0-0-0` (parent ifindex 11), in zone `lan`. Its SIBLING unit on the
/// same parent is `nat_snapshot`'s `reth0.80` (VLAN 80, ifindex 12, zone
/// `wan`) — the egress of the flow driven below.
const INGRESS_PARENT_IFINDEX: i32 = 11;
const INGRESS_VLAN_ID: u16 = 50;
const INGRESS_LOGICAL_IFINDEX: i32 = 13;

/// `nat_snapshot()` (lan -> wan permit, interface-mode SNAT, default route via
/// a REACHABLE 172.16.80.1 gateway on reth0.80) plus a second LAN interface:
/// `reth0.50`, a VLAN unit riding the SAME physical parent as the WAN egress
/// unit reth0.80.
///
/// Two properties make this fixture bind rather than pass for free:
///   - zone `lan` now holds TWO interfaces (reth1.0 ifindex 24 and reth0.50),
///     so "the session's ingress zone" no longer identifies an interface —
///     which is the entire premise of #4983;
///   - the ingress parent ifindex 11 is SHARED with the egress unit and
///     resolves to `wan` on its own (reth0.80 is its first sub-interface), so
///     an implementation that stamped only the parent, or re-derived from the
///     zone, produces a visibly different answer.
fn ingress_identity_snapshot() -> crate::ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.interfaces.push(crate::InterfaceSnapshot {
        name: "reth0.50".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-0.50".to_string(),
        ifindex: INGRESS_LOGICAL_IFINDEX,
        parent_ifindex: INGRESS_PARENT_IFINDEX,
        vlan_id: INGRESS_VLAN_ID as i32,
        // Same redundancy group as the fixture's other LAN interface so the
        // shared `txn_ha_state()` placement (RG 1 + RG 2 forwarding-active)
        // owns this ingress too — an RG the local node does not own resolves
        // HAInactive and installs nothing.
        redundancy_group: 2,
        hardware_addr: "02:bf:72:00:50:08".to_string(),
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.0.62.1/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot
}

/// Push ONE LAN -> WAN TCP SYN through the real poll body, ingressing on
/// `reth0.50` ({parent 11, VLAN 50}) and egressing on its sibling reth0.80
/// toward the reachable default gateway. Returns the session table the poll
/// installed into.
///
/// Asserts the fixture is live before returning: the ingress must resolve to
/// the LAN logical unit (not the parent's wan zone) and the poll must have
/// installed BOTH halves of the flow. Without those, a fixture that quietly
/// stopped admitting the flow would make every metadata assertion below
/// vacuous instead of RED.
fn run_ingress_identity_flow() -> SessionTable {
    let forwarding = build_forwarding_state(&ingress_identity_snapshot());
    assert_eq!(
        crate::afxdp::forwarding::resolve_ingress_logical_ifindex(
            &forwarding,
            INGRESS_PARENT_IFINDEX,
            INGRESS_VLAN_ID
        ),
        Some(INGRESS_LOGICAL_IFINDEX),
        "fixture must map parent 11 / VLAN 50 -> the reth0.50 logical unit"
    );
    assert_eq!(
        forwarding
            .ifindex_to_zone_id
            .get(&INGRESS_LOGICAL_IFINDEX)
            .copied(),
        Some(TEST_LAN_ZONE_ID),
        "reth0.50 is in zone lan"
    );
    assert_eq!(
        forwarding
            .ifindex_to_zone_id
            .get(&INGRESS_PARENT_IFINDEX)
            .copied(),
        Some(TEST_WAN_ZONE_ID),
        "the SHARED physical parent resolves to wan on its own, so stamping \
         the parent's zone instead of the packet's binding is observable"
    );

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 62, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    // The shim strips the 802.1Q tag and conveys the VID out of band in
    // `meta.ingress_vlan_id`, so the frame stays untagged and l3 is at 14 —
    // the same shape the #3021/#3022 VLAN pins use.
    let mut meta = txn_meta_v4(
        INGRESS_PARENT_IFINDEX as u32,
        TCP_FLAG_SYN,
        (frame.len() - 14) as u16,
    );
    meta.ingress_vlan_id = INGRESS_VLAN_ID;

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, INGRESS_PARENT_IFINDEX, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    let ha_state = txn_ha_state();
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
        "the permitted lan -> wan SYN must install the forward session and its \
         reverse companion; without both, the metadata assertions are vacuous"
    );
    sessions
}

/// Every session-table entry's metadata, split into (forward, reverse) by the
/// `is_reverse` flag. Reading through `iter_with_origin` avoids reconstructing
/// the SNAT-translated reverse key by hand — a hand-built key that missed
/// would silently return an EMPTY set and make an assertion pass for free.
fn split_forward_reverse(sessions: &SessionTable) -> (Vec<SessionMetadata>, Vec<SessionMetadata>) {
    let mut forward = Vec::new();
    let mut reverse = Vec::new();
    sessions.iter_with_origin(|_key, _decision, metadata, _origin| {
        if metadata.is_reverse {
            reverse.push(metadata.clone());
        } else {
            forward.push(metadata.clone());
        }
    });
    (forward, reverse)
}

/// #4983 PRODUCER fail-on-revert (transit forward install). The FORWARD
/// session the poll installs must carry the {ifindex, VLAN} of the binding
/// the SYN actually arrived on — parent 11, VLAN 50 — not 0, not the parent
/// alone, and not anything re-derived from a zone.
///
/// RED on reverting `poll_descriptor/mod.rs` transit install to
/// `ingress_ifindex: 0` / `ingress_vlan_id: 0`.
#[test]
fn poll_descriptor_transit_install_stamps_ingress_binding_4983() {
    let sessions = run_ingress_identity_flow();
    let (forward, _reverse) = split_forward_reverse(&sessions);
    assert_eq!(
        forward.len(),
        1,
        "exactly one forward session for the driven flow"
    );
    let metadata = &forward[0];
    assert_eq!(
        metadata.ingress_ifindex, INGRESS_PARENT_IFINDEX as u32,
        "the forward session must record the ifindex of the binding its first \
         packet arrived on (RED on revert: the transit install stamps 0 and the \
         Go filter falls back to the zone for every session)"
    );
    assert_eq!(
        metadata.ingress_vlan_id, INGRESS_VLAN_ID,
        "the forward session must record the ingress 802.1Q VID (RED on revert: \
         stamping 0 aliases reth0.50 onto its trunk-sibling reth0.80, which is \
         the cross-interface match #4983 removes)"
    );
    // The ingress ZONE is unchanged by this PR. Pinned here so a future change
    // that "fixed" the ifindex by rewriting the zone stamp is not mistaken for
    // this one.
    assert_eq!(
        metadata.ingress_zone, TEST_LAN_ZONE_ID,
        "the ingress zone still resolves from the LOGICAL unit (#3021)"
    );
}

/// #4983 OVER-REACH guard, forward/reverse arm separation. The REVERSE
/// companion installed by the SAME poll call must keep carrying NO ingress
/// identity: its true ingress is the forward flow's EGRESS interface, which is
/// not resolved at install time, so stamping the forward frame's binding onto
/// it would name the wrong side of the flow.
///
/// This is what makes the pair a distinguishing fixture rather than a
/// restatement: 11/50 on one entry and 0/0 on the other cannot both be
/// satisfied by any single constant. It stays GREEN under the revert that
/// turns the sibling test RED, and goes RED if the reverse install starts
/// copying `meta.ingress_*`.
#[test]
fn poll_descriptor_reverse_companion_carries_no_ingress_identity_4983() {
    let sessions = run_ingress_identity_flow();
    let (_forward, reverse) = split_forward_reverse(&sessions);
    assert_eq!(
        reverse.len(),
        1,
        "exactly one reverse companion for the driven flow"
    );
    let metadata = &reverse[0];
    assert_eq!(
        metadata.ingress_ifindex, 0,
        "the reverse companion must carry NO ingress ifindex — stamping the \
         forward frame's binding here would name the flow's client side as the \
         reverse entry's ingress"
    );
    assert_eq!(
        metadata.ingress_vlan_id, 0,
        "the reverse companion must carry NO ingress VLAN for the same reason"
    );
    // The reverse companion's zone pair IS inverted (that is pre-existing and
    // deliberate); pinning it here keeps "carries no identity" from being read
    // as "carries nothing".
    assert_eq!(
        metadata.ingress_zone, TEST_WAN_ZONE_ID,
        "the reverse companion's ingress zone is the forward flow's egress zone"
    );
}

/// The same LAN -> WAN flow, but with the gateway neighbor UNRESOLVED, so the
/// poll takes the missing-neighbor branch and installs a
/// `MissingNeighborSeed` forward session instead.
fn run_missing_neighbor_seed_flow() -> SessionTable {
    let mut snapshot = ingress_identity_snapshot();
    // Drop the reachable 172.16.80.1 entry: the default route's next hop no
    // longer resolves, which is the ordinary cold-start case (first packet of
    // a flow racing ARP/NDP on a busy LAN).
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 62, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let mut meta = txn_meta_v4(
        INGRESS_PARENT_IFINDEX as u32,
        TCP_FLAG_SYN,
        (frame.len() - 14) as u16,
    );
    meta.ingress_vlan_id = INGRESS_VLAN_ID;

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, INGRESS_PARENT_IFINDEX, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    sessions
}

/// #4983 PRODUCER fail-on-revert (missing-neighbor seed install). A flow whose
/// FIRST packet arrives while the next-hop ARP/NDP is still unresolved installs
/// a seed session so the reply finds the forward NAT match. That seed is a
/// forward session with an ordinary lifetime — the pending-neighbor retry
/// sweep replays the buffered FRAME but never re-installs the SESSION (it
/// takes no `&mut SessionTable`), and the seed is published to the BPF
/// conntrack map at install. So whatever it is stamped with is what the flow
/// carries for its whole life.
///
/// RED on reverting `build_missing_neighbor_session_metadata`'s stamp to 0
/// while the two policy-admitted install sites stay stamped.
#[test]
fn poll_descriptor_missing_neighbor_seed_stamps_ingress_binding_4983() {
    let sessions = run_missing_neighbor_seed_flow();
    let mut seeds = Vec::new();
    sessions.iter_with_origin(|_key, _decision, metadata, origin| {
        if origin == SessionOrigin::MissingNeighborSeed {
            seeds.push(metadata.clone());
        }
    });
    assert_eq!(
        seeds.len(),
        1,
        "an unresolved next hop must install exactly one missing-neighbor seed \
         (if it installs none, this test proves nothing)"
    );
    let metadata = &seeds[0];
    assert!(
        !metadata.is_reverse,
        "the missing-neighbor seed is a FORWARD session"
    );
    assert_eq!(
        metadata.ingress_ifindex, INGRESS_PARENT_IFINDEX as u32,
        "the missing-neighbor seed must record the ingress binding of the frame \
         that created it (RED on revert: every flow whose first packet raced an \
         unresolved neighbor keeps the zone approximation for its whole life)"
    );
    assert_eq!(
        metadata.ingress_vlan_id, INGRESS_VLAN_ID,
        "the missing-neighbor seed must record the ingress 802.1Q VID too"
    );
}
