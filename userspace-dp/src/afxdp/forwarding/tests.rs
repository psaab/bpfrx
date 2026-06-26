use super::super::forwarding_build::*;
use super::super::test_fixtures::*;
use super::*;
use crate::event_stream::DataplaneEventRateLimitConfig;
use crate::event_stream::codec::DataplaneEventKind;
use crate::nat::SourceNatFailureReason;
use crate::test_zone_ids::*;
use crate::{FabricSnapshot, NeighborSnapshot, SourceNATRuleSnapshot, ZoneSnapshot};

fn active_ha_runtime(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

fn inactive_ha_runtime(watchdog_timestamp: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: false,
        watchdog_timestamp,
        lease: HAForwardingLease::Inactive,
    }
}

#[test]
fn metadata_classification_accepts_matching_generations() {
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 11,
        fib_generation: 7,
    };
    assert_eq!(
        classify_metadata(valid_meta(), validation),
        PacketDisposition::Valid
    );
}

#[test]
fn metadata_classification_rejects_generation_mismatch() {
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 22,
        fib_generation: 9,
    };
    assert_eq!(
        classify_metadata(valid_meta(), validation),
        PacketDisposition::ConfigGenerationMismatch
    );
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 11,
        fib_generation: 9,
    };
    assert_eq!(
        classify_metadata(valid_meta(), validation),
        PacketDisposition::FibGenerationMismatch
    );
}

#[test]
fn metadata_classification_rejects_unknown_address_family() {
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 11,
        fib_generation: 7,
    };
    let mut meta = valid_meta();
    meta.addr_family = 0;
    assert_eq!(
        classify_metadata(meta, validation),
        PacketDisposition::UnsupportedPacket
    );
}
#[test]
fn ha_resolution_blocks_inactive_owner_rg() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let resolved = enforce_ha_resolution(
        &state,
        &ha_state,
        lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
}

#[test]
fn ha_resolution_allows_fresh_active_owner_rg() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        active_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let resolved = enforce_ha_resolution(
        &state,
        &ha_state,
        lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
}

#[test]
fn cached_flow_decision_invalidates_when_owner_rg_is_demoted() {
    let state = build_forwarding_state(&nat_snapshot());
    let active = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let demoted = BTreeMap::from([(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let resolution = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    assert!(cached_flow_decision_valid(
        &state,
        &active,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
    assert!(!cached_flow_decision_valid(
        &state,
        &demoted,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_flow_decision_invalidates_fabric_redirect_on_fabric_ingress_when_local_owner_active() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

    assert!(!cached_flow_decision_valid(
        &state,
        &ha_state,
        &dynamic_neighbors,
        now_secs,
        1,
        true,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_flow_decision_invalidates_fabric_redirect_on_non_fabric_ingress_when_local_owner_active()
{
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

    assert!(!cached_flow_decision_valid(
        &state,
        &ha_state,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_flow_decision_keeps_fabric_redirect_on_fabric_ingress_when_local_owner_inactive() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

    assert!(cached_flow_decision_valid(
        &state,
        &ha_state,
        &dynamic_neighbors,
        now_secs,
        1,
        true,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_flow_decision_keeps_fabric_redirect_on_non_fabric_ingress_when_local_owner_inactive() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

    assert!(cached_flow_decision_valid(
        &state,
        &ha_state,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_local_delivery_decision_invalidates_when_owner_rg_is_demoted() {
    let state = build_forwarding_state(&nat_snapshot());
    let active = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let demoted = BTreeMap::from([(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = interface_nat_local_resolution(&state, "172.16.80.8".parse().expect("v4"))
        .expect("interface nat local delivery");
    let now_secs = monotonic_nanos() / 1_000_000_000;

    assert!(cached_flow_decision_valid(
        &state,
        &active,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        resolution
    ));
    assert!(!cached_flow_decision_valid(
        &state,
        &demoted,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        resolution
    ));
}

#[test]
fn inactive_owner_rg_redirects_established_session_to_fabric() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let blocked = enforce_ha_resolution(
        &state,
        &ha_state,
        lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    );
    assert_eq!(blocked.disposition, ForwardingDisposition::HAInactive);
    let redirected = redirect_via_fabric_if_needed(&state, blocked, 24);
    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(redirected.egress_ifindex, 21);
    assert_eq!(redirected.tx_ifindex, 21);
    assert_eq!(
        redirected.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)))
    );
    assert_eq!(
        redirected.neighbor_mac,
        Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
    );
    assert_eq!(
        redirected.src_mac,
        Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01])
    );
}

#[test]
fn inactive_owner_missing_neighbor_redirects_to_fabric() {
    let mut snapshot = nat_snapshot_with_fabric();
    snapshot
        .neighbors
        .retain(|neighbor| neighbor.ip != "172.16.80.1");
    let state = build_forwarding_state(&snapshot);
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let blocked = enforce_ha_resolution(
        &state,
        &ha_state,
        lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    );
    assert_eq!(blocked.disposition, ForwardingDisposition::HAInactive);
    let redirected = redirect_via_fabric_if_needed(&state, blocked, 24);
    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(redirected.egress_ifindex, 21);
    assert_eq!(redirected.tx_ifindex, 21);
    assert_eq!(
        redirected.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)))
    );
}

#[test]
fn fabric_ingress_prefers_local_active_owner_resolution_over_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
    let redirected = resolve_fabric_redirect(&state).expect("fabric redirect");
    let preferred = prefer_local_forward_candidate_for_fabric_ingress(
        &state,
        &ha_state,
        &Default::default(),
        now_secs,
        true,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        redirected,
    );
    assert_eq!(
        preferred.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(preferred.egress_ifindex, 12);
    assert_eq!(owner_rg_for_resolution(&state, preferred), 1);
}

#[test]
fn build_forwarding_state_uses_fabric_snapshot_macs_without_parent_interface() {
    let mut snapshot = nat_snapshot();
    snapshot.fabrics = vec![FabricSnapshot {
        name: "fab0".to_string(),
        parent_interface: "ge-0/0/0".to_string(),
        parent_linux_name: "ge-0-0-0".to_string(),
        parent_ifindex: 21,
        overlay_linux_name: "fab0".to_string(),
        overlay_ifindex: 101,
        rx_queues: 2,
        peer_address: "10.99.13.2".to_string(),
        local_mac: "02:bf:72:ff:00:01".to_string(),
        peer_mac: "00:aa:bb:cc:dd:ee".to_string(),
    }];
    let state = build_forwarding_state(&snapshot);
    let redirect = resolve_fabric_redirect(&state).expect("fabric redirect");
    assert_eq!(redirect.egress_ifindex, 21);
    assert_eq!(redirect.tx_ifindex, 21);
    assert_eq!(
        redirect.neighbor_mac,
        Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
    );
    assert_eq!(redirect.src_mac, Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]));
}

#[test]
fn zone_encoded_fabric_redirect_preserves_ingress_zone() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let redirected =
        resolve_zone_encoded_fabric_redirect(&state, "lan").expect("zone-encoded redirect");
    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(redirected.egress_ifindex, 21);
    assert_eq!(redirected.tx_ifindex, 21);
    assert_eq!(
        redirected.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
    );
}

#[test]
fn parse_zone_encoded_fabric_ingress_uses_zone_override() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let mut frame = vec![0u8; 64];
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 21,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_zone_encoded_fabric_ingress(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &state,
        ),
        Some(TEST_LAN_ZONE_ID)
    );
}

#[test]
fn zone_encoded_fabric_ingress_skips_dynamic_neighbor_learning() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let mut frame = vec![0u8; 64];
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let mut last_learned = None;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 21,
        ..UserspaceDpMeta::default()
    };
    learn_dynamic_neighbor_from_packet(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        &mut last_learned,
        &state,
        &neighbors,
    );
    assert!(neighbors.is_empty());
}

#[test]
fn manager_neighbor_replace_preserves_packet_learned_entries() {
    let mut coordinator = Coordinator::new();
    coordinator.dynamic_neighbors_ref().insert(
        (
            5,
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x559, 0x8585, 0xef00, 0x1266, 0x6aff, 0xfe0b, 0xd017,
            )),
        ),
        NeighborEntry {
            mac: [0x10, 0x66, 0x6a, 0x0b, 0xd0, 0x17],
        },
    );

    coordinator.apply_manager_neighbors(
        true,
        &[(
            13,
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            NeighborEntry {
                mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
            },
        )],
    );

    let neighbors = coordinator.dynamic_neighbors_ref();
    assert_eq!(neighbors.len(), 2);
    assert!(neighbors.contains_key(&(
        5,
        IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x559, 0x8585, 0xef00, 0x1266, 0x6aff, 0xfe0b, 0xd017,
        ))
    )));
    assert!(neighbors.contains_key(&(13, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)))));
}

#[test]
fn manager_neighbor_replace_overrides_snapshot_neighbor_entry() {
    let mut coordinator = Coordinator::new();
    let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    coordinator.refresh_runtime_snapshot(&ConfigSnapshot {
        neighbors: vec![NeighborSnapshot {
            ifindex: 13,
            family: "inet".to_string(),
            ip: target.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            state: "reachable".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    });

    let before = lookup_neighbor_entry(
        &coordinator.forwarding,
        Some(coordinator.dynamic_neighbors_ref()),
        13,
        target,
    )
    .expect("snapshot neighbor");
    assert_eq!(before.mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    coordinator.apply_manager_neighbors(
        true,
        &[(
            13,
            target,
            NeighborEntry {
                mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
            },
        )],
    );

    let after = lookup_neighbor_entry(
        &coordinator.forwarding,
        Some(coordinator.dynamic_neighbors_ref()),
        13,
        target,
    )
    .expect("updated manager neighbor");
    assert_eq!(after.mac, [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32]);
}

#[test]
fn manager_neighbor_replace_removes_snapshot_seeded_neighbor_entry() {
    let mut coordinator = Coordinator::new();
    let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    coordinator.refresh_runtime_snapshot(&ConfigSnapshot {
        neighbors: vec![NeighborSnapshot {
            ifindex: 13,
            family: "inet".to_string(),
            ip: target.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            state: "reachable".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    });

    coordinator.apply_manager_neighbors(true, &[]);

    assert!(
        lookup_neighbor_entry(
            &coordinator.forwarding,
            Some(coordinator.dynamic_neighbors_ref()),
            13,
            target,
        )
        .is_none()
    );
}

#[test]
fn refresh_runtime_snapshot_clears_old_manager_neighbor_cache_entries() {
    let mut coordinator = Coordinator::new();
    let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    coordinator.apply_manager_neighbors(
        true,
        &[(
            13,
            target,
            NeighborEntry {
                mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
            },
        )],
    );
    assert!(
        coordinator
            .dynamic_neighbors_ref()
            .contains_key(&(13, target))
    );

    coordinator.refresh_runtime_snapshot(&ConfigSnapshot::default());

    assert!(
        !coordinator
            .dynamic_neighbors_ref()
            .contains_key(&(13, target))
    );
    assert!(
        lookup_neighbor_entry(
            &coordinator.forwarding,
            Some(coordinator.dynamic_neighbors_ref()),
            13,
            target,
        )
        .is_none()
    );
}

#[test]
fn new_flow_to_inactive_owner_rg_uses_zone_encoded_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
    let routed = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let (from_zone, _) = zone_pair_for_flow(&state, 24, routed.egress_ifindex);
    let redirected = finalize_new_flow_ha_resolution(
        &state,
        &ha_state,
        now_secs,
        routed,
        false,
        24,
        state.zone_name_to_id.get(&from_zone).copied().unwrap_or(0),
        0,
    );
    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(
        redirected.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
    );
}

#[test]
fn new_flow_from_fabric_keeps_forward_candidate_when_owner_rg_inactive() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
    let routed = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let resolved =
        finalize_new_flow_ha_resolution(&state, &ha_state, now_secs, routed, true, 21, 1, 0);
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, routed.egress_ifindex);
}

#[test]
fn fabric_originated_reverse_session_prefers_local_client_delivery_when_rg_active() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::from([(2, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    dynamic_neighbors.insert(
        (24, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        },
    );

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        1,
        true,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 24);
    assert_eq!(resolved.tx_ifindex, 24);
}

#[test]
fn fabric_originated_reverse_session_uses_zone_encoded_fabric_redirect_when_client_rg_inactive() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        1,
        true,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
    assert_eq!(resolved.egress_ifindex, 21);
    assert_eq!(resolved.tx_ifindex, 21);
    assert_eq!(
        resolved.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
    );
}

#[test]
fn cluster_peer_return_fast_path_allows_sfmix_to_lan_reply() {
    let mut state = build_forwarding_state(&native_gre_pbr_snapshot(true));
    state.fabrics.push(FabricLink {
        parent_ifindex: 4,
        overlay_ifindex: 104,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
    });
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    dynamic_neighbors.insert(
        (5, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        },
    );
    let meta = UserspaceDpMeta {
        ingress_ifindex: 4,
        protocol: PROTO_ICMP,
        l4_offset: 0,
        ..UserspaceDpMeta::default()
    };
    let packet_frame = [0u8];

    let (decision, metadata) = cluster_peer_return_fast_path(
        &state,
        &dynamic_neighbors,
        &packet_frame,
        meta,
        Some(TEST_SFMIX_ZONE_ID),
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
    )
    .expect("fabric return fast path");

    assert_eq!(
        decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(decision.resolution.egress_ifindex, 5);
    assert_eq!(metadata.ingress_zone, 5);
    assert_eq!(metadata.egress_zone, 1);
    assert!(metadata.fabric_ingress);
    assert!(metadata.is_reverse);
}

#[test]
fn cluster_peer_return_fast_path_skips_pure_tcp_syn() {
    let mut state = build_forwarding_state(&native_gre_pbr_snapshot(true));
    state.fabrics.push(FabricLink {
        parent_ifindex: 4,
        overlay_ifindex: 104,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
    });
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let meta = UserspaceDpMeta {
        ingress_ifindex: 4,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        ..UserspaceDpMeta::default()
    };

    assert!(
        cluster_peer_return_fast_path(
            &state,
            &dynamic_neighbors,
            &[],
            meta,
            Some(TEST_SFMIX_ZONE_ID),
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        )
        .is_none()
    );
}

#[test]
fn cluster_peer_return_fast_path_skips_icmp_echo_request() {
    let mut state = build_forwarding_state(&native_gre_pbr_snapshot(true));
    state.fabrics.push(FabricLink {
        parent_ifindex: 4,
        overlay_ifindex: 104,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
    });
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let meta = UserspaceDpMeta {
        ingress_ifindex: 4,
        protocol: PROTO_ICMP,
        l4_offset: 0,
        ..UserspaceDpMeta::default()
    };
    let packet_frame = [8u8];

    assert!(
        cluster_peer_return_fast_path(
            &state,
            &dynamic_neighbors,
            &packet_frame,
            meta,
            Some(TEST_LAN_ZONE_ID),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        )
        .is_none()
    );
}

#[test]
fn cluster_peer_return_fast_path_skips_icmpv6_echo_request() {
    let mut state = build_forwarding_state(&native_gre_pbr_snapshot(true));
    state.fabrics.push(FabricLink {
        parent_ifindex: 4,
        overlay_ifindex: 104,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
    });
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let meta = UserspaceDpMeta {
        ingress_ifindex: 4,
        protocol: PROTO_ICMPV6,
        l4_offset: 0,
        ..UserspaceDpMeta::default()
    };
    let packet_frame = [128u8];

    assert!(
        cluster_peer_return_fast_path(
            &state,
            &dynamic_neighbors,
            &packet_frame,
            meta,
            Some(TEST_LAN_ZONE_ID),
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
        )
        .is_none()
    );
}

#[test]
fn missing_neighbor_session_metadata_preserves_fabric_ingress() {
    let mut state = build_forwarding_state(&native_gre_pbr_snapshot(false));
    state.fabrics.push(FabricLink {
        parent_ifindex: 4,
        overlay_ifindex: 104,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
    });
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::MissingNeighbor,
            local_ifindex: 0,
            egress_ifindex: 13,
            tx_ifindex: 13,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x559, 0x8585, 0x50, 0, 0, 0, 0x1,
            ))),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };

    let metadata = build_missing_neighbor_session_metadata(
        &state,
        TEST_LAN_ZONE_ID,
        TEST_WAN_ZONE_ID,
        true,
        decision,
    );

    assert_eq!(metadata.ingress_zone, 1);
    assert_eq!(metadata.egress_zone, 2);
    assert!(metadata.fabric_ingress);
    assert!(!metadata.is_reverse);
}

#[test]
fn reverse_session_prefers_interface_snat_ipv4_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        2,
        false,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(resolved.tx_ifindex, 12);
}

#[test]
fn reverse_session_blocks_inactive_interface_snat_ipv4_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        2,
        false,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
    assert_eq!(resolved.local_ifindex, 12);
    assert_eq!(resolved.egress_ifindex, 12);
}

#[test]
fn reverse_session_prefers_interface_snat_ipv6_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        "2001:559:8585:80::8".parse().expect("dst"),
        2,
        false,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(resolved.tx_ifindex, 12);
}

#[test]
fn session_hit_keeps_interface_snat_ipv4_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 5201,
            dst_port: 43600,
        },
    };
    let decision = SessionDecision {
        resolution: interface_nat_local_resolution(&state, flow.dst_ip)
            .expect("interface nat local delivery"),
        nat: NatDecision::default(),
    };

    let resolved =
        lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, &flow, decision);

    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
}

#[test]
fn inactive_interface_snat_session_hit_redirects_to_fabric() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 5201,
            dst_port: 43600,
        },
    };
    let decision = SessionDecision {
        resolution: interface_nat_local_resolution(&state, flow.dst_ip)
            .expect("interface nat local delivery"),
        nat: NatDecision::default(),
    };

    let looked_up =
        lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, &flow, decision);
    let blocked = enforce_ha_resolution(&state, &ha_state, looked_up);
    let redirected = redirect_via_fabric_if_needed(&state, blocked, 12);

    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(redirected.egress_ifindex, 21);
    assert_eq!(redirected.tx_ifindex, 21);
}

#[test]
fn session_hit_keeps_interface_snat_ipv6_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let flow = SessionFlow {
        src_ip: "2001:559:8585:80::200".parse().expect("src"),
        dst_ip: "2001:559:8585:80::8".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: "2001:559:8585:80::200".parse().expect("src"),
            dst_ip: "2001:559:8585:80::8".parse().expect("dst"),
            src_port: 5201,
            dst_port: 43600,
        },
    };
    let decision = SessionDecision {
        resolution: interface_nat_local_resolution(&state, flow.dst_ip)
            .expect("interface nat local delivery"),
        nat: NatDecision::default(),
    };

    let resolved =
        lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, &flow, decision);

    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
}

#[test]
fn embedded_icmp_to_inactive_owner_rg_uses_zone_encoded_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        original_src_port: 33434,
        original_dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        original_dst_port: 33434,
        embedded_proto: PROTO_UDP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_WAN_ZONE_ID,
            egress_zone: TEST_LAN_ZONE_ID,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
        },
    };

    let resolved = finalize_embedded_icmp_resolution(
        &state,
        &ha_state,
        monotonic_nanos() / 1_000_000_000,
        12,
        &icmp_match,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
    assert_eq!(resolved.egress_ifindex, 21);
    assert_eq!(resolved.tx_ifindex, 21);
    assert_eq!(
        resolved.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02])
    );
}

#[test]
fn embedded_icmp_no_route_uses_zone_encoded_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::new();
    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        original_src_port: 33434,
        original_dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        original_dst_port: 33434,
        embedded_proto: PROTO_UDP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_WAN_ZONE_ID,
            egress_zone: TEST_LAN_ZONE_ID,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
        },
    };

    let resolved = finalize_embedded_icmp_resolution(
        &state,
        &ha_state,
        monotonic_nanos() / 1_000_000_000,
        12,
        &icmp_match,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
    assert_eq!(resolved.egress_ifindex, 21);
    assert_eq!(resolved.tx_ifindex, 21);
    assert_eq!(
        resolved.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02])
    );
}

#[test]
fn embedded_icmp_discard_route_uses_zone_encoded_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::new();
    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        original_src_port: 33434,
        original_dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        original_dst_port: 33434,
        embedded_proto: PROTO_UDP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::DiscardRoute,
            local_ifindex: 0,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_WAN_ZONE_ID,
            egress_zone: TEST_LAN_ZONE_ID,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
        },
    };

    let resolved = finalize_embedded_icmp_resolution(
        &state,
        &ha_state,
        monotonic_nanos() / 1_000_000_000,
        12,
        &icmp_match,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
    assert_eq!(resolved.egress_ifindex, 21);
    assert_eq!(resolved.tx_ifindex, 21);
}

#[test]
fn embedded_icmp_from_fabric_does_not_redirect_back_to_fabric() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        original_src_port: 33434,
        original_dst: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        original_dst_port: 33434,
        embedded_proto: PROTO_UDP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_WAN_ZONE_ID,
            egress_zone: TEST_LAN_ZONE_ID,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
        },
    };

    let resolved = finalize_embedded_icmp_resolution(
        &state,
        &ha_state,
        monotonic_nanos() / 1_000_000_000,
        21,
        &icmp_match,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
}

#[test]
fn fabric_ingress_does_not_redirect_back_to_fabric() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let blocked = ForwardingResolution {
        disposition: ForwardingDisposition::HAInactive,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        src_mac: None,
        tx_vlan_id: 80,
    };
    assert_eq!(
        redirect_via_fabric_if_needed(&state, blocked, 21).disposition,
        ForwardingDisposition::HAInactive
    );
}

#[test]
fn source_nat_selection_uses_interface_addresses() {
    let state = build_forwarding_state(&nat_snapshot());
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);
    assert_eq!(
        match_source_nat_for_flow(&state, &from_zone, &to_zone, 12, &flow),
        Some(NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn source_nat_selection_uses_interface_addresses_v6() {
    let state = build_forwarding_state(&nat_snapshot());
    let flow = SessionFlow {
        src_ip: "2001:559:8585:ef00::100".parse().expect("src"),
        dst_ip: "2001:559:8585:80::200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: "2001:559:8585:ef00::100".parse().expect("src"),
            dst_ip: "2001:559:8585:80::200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);
    assert_eq!(
        match_source_nat_for_flow(&state, &from_zone, &to_zone, 12, &flow),
        Some(NatDecision {
            rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn source_nat_pool_unavailable_reports_rule_and_pool_identity() {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "wrong-family".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "v6-only".to_string(),
        pool_addresses: vec!["2001:db8::10".to_string()],
        port_low: 10_000,
        port_high: 10_010,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);

    assert_eq!(
        match_source_nat_for_flow_result(&state, &from_zone, &to_zone, 12, &flow),
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "wrong-family".to_string(),
            pool_name: "v6-only".to_string(),
            reason: SourceNatFailureReason::WrongAddressFamily,
        })
    );
}

#[test]
fn source_nat_allocator_exhausted_reports_rule_and_pool_identity() {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "exhausted".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "tiny-pool".to_string(),
        pool_unusable: true,
        pool_unusable_reason: "allocator_exhausted".to_string(),
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);

    assert_eq!(
        match_source_nat_for_flow_result(&state, &from_zone, &to_zone, 12, &flow),
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "exhausted".to_string(),
            pool_name: "tiny-pool".to_string(),
            reason: SourceNatFailureReason::AllocatorExhausted,
        })
    );
}

#[test]
fn interface_snat_addresses_are_not_treated_as_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved_v4 = lookup_forwarding_resolution(&state, "172.16.80.8".parse().expect("v4"));
    assert_ne!(
        resolved_v4.disposition,
        ForwardingDisposition::LocalDelivery
    );
    let resolved_v6 =
        lookup_forwarding_resolution(&state, "2001:559:8585:80::8".parse().expect("v6"));
    assert_ne!(
        resolved_v6.disposition,
        ForwardingDisposition::LocalDelivery
    );
}

#[test]
fn interface_snat_addresses_are_local_delivered_on_session_miss() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved_v4 = interface_nat_local_resolution(&state, "172.16.80.8".parse().expect("v4"))
        .expect("v4 nat local delivery");
    assert_eq!(
        resolved_v4.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v4.local_ifindex, 12);

    let resolved_v6 =
        interface_nat_local_resolution(&state, "2001:559:8585:80::8".parse().expect("v6"))
            .expect("v6 nat local delivery");
    assert_eq!(
        resolved_v6.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v6.local_ifindex, 12);
}

#[test]
fn icmp_session_miss_resolution_prefers_frame_destination_for_interface_nat_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let frame = vlan_icmp_reply_frame();
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let mut meta = valid_meta();
    meta.l3_offset = 18;
    meta.l4_offset = 38;
    meta.flow_src_addr[..4].copy_from_slice(&[172, 16, 80, 201]);
    // Deliberately poison the metadata tuple to model a stamped-dst mismatch.
    meta.flow_dst_addr[..4].copy_from_slice(&[10, 0, 61, 1]);

    let flow = parse_session_flow(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
    )
    .expect("flow");
    assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));

    let resolution_target = parse_packet_destination(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
    )
    .expect("frame destination");
    assert_eq!(resolution_target, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));

    let resolved =
        interface_nat_local_resolution_on_session_miss(&state, resolution_target, PROTO_ICMP)
            .expect("nat local delivery");
    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
}

#[test]
fn tcp_session_miss_local_delivers_interface_nat_address() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved_v4 = interface_nat_local_resolution_on_session_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        PROTO_TCP,
    )
    .expect("tcp v4 nat local delivery");
    assert_eq!(
        resolved_v4.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v4.local_ifindex, 12);

    let resolved_v6 = interface_nat_local_resolution_on_session_miss(
        &state,
        "2001:559:8585:80::8".parse().expect("v6"),
        PROTO_UDP,
    )
    .expect("udp v6 nat local delivery");
    assert_eq!(
        resolved_v6.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v6.local_ifindex, 12);
}

#[test]
fn tcp_ack_session_miss_does_not_cache_interface_nat_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolution = interface_nat_local_resolution_on_session_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        PROTO_TCP,
    )
    .expect("tcp nat local delivery");
    assert!(!should_cache_local_delivery_session_on_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        resolution,
        PROTO_TCP,
        0x10,
    ));
}

#[test]
fn tcp_syn_session_miss_still_caches_interface_nat_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolution = interface_nat_local_resolution_on_session_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        PROTO_TCP,
    )
    .expect("tcp nat local delivery");
    assert!(should_cache_local_delivery_session_on_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        resolution,
        PROTO_TCP,
        0x02,
    ));
}

#[test]
fn tunnel_session_miss_blocks_interface_nat_local_delivery() {
    let mut snapshot = native_gre_snapshot(true);
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "lan-to-sfmix".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "sfmix".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    let tunnel_snat_ip = "10.255.192.42".parse().expect("tunnel snat");
    assert!(should_block_tunnel_interface_nat_session_miss(
        &state,
        tunnel_snat_ip,
        PROTO_TCP,
    ));
    assert!(should_block_tunnel_interface_nat_session_miss(
        &state,
        tunnel_snat_ip,
        PROTO_UDP,
    ));
    assert!(should_block_tunnel_interface_nat_session_miss(
        &state,
        tunnel_snat_ip,
        PROTO_ICMP,
    ));
}

#[test]
fn ingress_interface_local_resolution_matches_vlan_local_address() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved =
        ingress_interface_local_resolution(&state, 11, 80, "172.16.80.8".parse().expect("dst"))
            .expect("ingress local delivery");
    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
}

#[test]
fn tcp_session_miss_local_delivers_ingress_vlan_address() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved_v4 = ingress_interface_local_resolution_on_session_miss(
        &state,
        11,
        80,
        "172.16.80.8".parse().expect("dst"),
        PROTO_TCP,
    )
    .expect("tcp ingress local delivery");
    assert_eq!(
        resolved_v4.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v4.local_ifindex, 12);

    let resolved_v6 = ingress_interface_local_resolution_on_session_miss(
        &state,
        11,
        80,
        "2001:559:8585:80::8".parse().expect("dst"),
        PROTO_UDP,
    )
    .expect("udp ingress local delivery");
    assert_eq!(
        resolved_v6.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v6.local_ifindex, 12);
}

#[test]
fn tcp_ack_session_miss_does_not_cache_ingress_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolution = ingress_interface_local_resolution_on_session_miss(
        &state,
        11,
        80,
        "172.16.80.8".parse().expect("dst"),
        PROTO_TCP,
    )
    .expect("tcp ingress local delivery");
    assert!(!should_cache_local_delivery_session_on_miss(
        &state,
        "172.16.80.8".parse().expect("dst"),
        resolution,
        PROTO_TCP,
        0x10,
    ));
}

#[test]
fn tcp_syn_session_miss_still_caches_ingress_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolution = ingress_interface_local_resolution_on_session_miss(
        &state,
        11,
        80,
        "172.16.80.8".parse().expect("dst"),
        PROTO_TCP,
    )
    .expect("tcp ingress local delivery");
    assert!(should_cache_local_delivery_session_on_miss(
        &state,
        "172.16.80.8".parse().expect("dst"),
        resolution,
        PROTO_TCP,
        0x02,
    ));
}

#[test]
fn helper_local_session_on_miss_stays_out_of_shared_alias_maps() {
    let mut sessions = SessionTable::new();
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let state = build_forwarding_state(&nat_snapshot());
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: "172.16.80.8".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        src_port: 40278,
        dst_port: 5201,
    };
    let decision = SessionDecision {
        resolution: ingress_interface_local_resolution_on_session_miss(
            &state, 11, 80, key.src_ip, PROTO_TCP,
        )
        .expect("tcp ingress local delivery"),
        nat: NatDecision::default(),
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
    };

    assert!(install_helper_local_session_on_miss(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &key,
        decision,
        metadata,
        SessionOrigin::LocalMiss,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert!(sessions.lookup(&key, 1_000_000, 0x10).is_some());
    assert!(
        shared_sessions
            .lock()
            .expect("shared lock")
            .get(&key)
            .is_none()
    );
    assert!(shared_nat_sessions.lock().expect("nat lock").is_empty());
    assert!(
        shared_forward_wire_sessions
            .lock()
            .expect("forward wire lock")
            .is_empty()
    );
}

#[test]
fn helper_local_session_on_miss_clears_stale_shared_aliases() {
    let mut sessions = SessionTable::new();
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let state = build_forwarding_state(&nat_snapshot());
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: "172.16.80.8".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        src_port: 40278,
        dst_port: 5201,
    };
    let decision = SessionDecision {
        resolution: ingress_interface_local_resolution_on_session_miss(
            &state, 11, 80, key.src_ip, PROTO_TCP,
        )
        .expect("tcp ingress local delivery"),
        nat: NatDecision::default(),
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: metadata.clone(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };

    // Install with SyncImport origin so take_synced_local recognizes
    // this as a peer-synced session.
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata,
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    assert!(install_helper_local_session_on_miss(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &key,
        decision,
        entry.metadata.clone(),
        SessionOrigin::LocalMiss,
        2_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert!(
        shared_sessions
            .lock()
            .expect("shared lock")
            .get(&key)
            .is_none()
    );
    assert!(shared_nat_sessions.lock().expect("nat lock").is_empty());
    assert!(
        shared_forward_wire_sessions
            .lock()
            .expect("forward wire lock")
            .is_empty()
    );
}

#[test]
fn unsolicited_dns_reply_respects_flow_knob() {
    let mut state = build_forwarding_state(&nat_snapshot());
    let flow = SessionFlow {
        src_ip: "172.16.80.53".parse().expect("src"),
        dst_ip: "10.0.61.102".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_UDP,
            src_ip: "172.16.80.53".parse().expect("src"),
            dst_ip: "10.0.61.102".parse().expect("dst"),
            src_port: 53,
            dst_port: 5353,
        },
    };
    state.allow_dns_reply = true;
    assert!(allow_unsolicited_dns_reply(&state, &flow));
    state.allow_dns_reply = false;
    assert!(!allow_unsolicited_dns_reply(&state, &flow));
}

#[test]
fn policy_selection_permits_matching_zone_pair() {
    let state = build_forwarding_state(&nat_snapshot());
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let (from_id, to_id) = zone_pair_ids_for_flow(&state, 24, 12);
    assert_eq!(
        evaluate_policy(
            &state.policy,
            from_id,
            to_id,
            flow.src_ip,
            flow.dst_ip,
            flow.forward_key.protocol,
            flow.forward_key.src_port,
            flow.forward_key.dst_port,
        ),
        PolicyAction::Permit
    );
}

#[test]
fn policy_selection_denies_on_default_policy() {
    let state = build_forwarding_state(&policy_deny_snapshot());
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let (from_id, to_id) = zone_pair_ids_for_flow(&state, 24, 12);
    assert_eq!(
        evaluate_policy(
            &state.policy,
            from_id,
            to_id,
            flow.src_ip,
            flow.dst_ip,
            flow.forward_key.protocol,
            flow.forward_key.src_port,
            flow.forward_key.dst_port,
        ),
        PolicyAction::Deny
    );
}

#[test]
fn policy_selection_deny_emits_rt_flow_event() {
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
        ZoneSnapshot {
            name: "dmz".to_string(),
            id: TEST_DMZ_ZONE_ID,
            ..Default::default()
        },
    ];
    let state = build_forwarding_state(&snapshot);
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let (from_id, to_id) = zone_pair_ids_for_flow(&state, 24, 12);
    let action = evaluate_policy(
        &state.policy,
        from_id,
        to_id,
        flow.src_ip,
        flow.dst_ip,
        flow.forward_key.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
    );
    assert_eq!(action, PolicyAction::Deny);

    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let meta = UserspaceDpMeta {
        ingress_ifindex: 24,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 60,
        ..Default::default()
    };

    super::super::emit_policy_deny_event(
        Some(&event_handle),
        &flow,
        &crate::nat::NatDecision::default(),
        meta,
        from_id,
        to_id,
        1,
        42,
        action,
        0,
        123,
    );

    let event = event_rx
        .try_recv()
        .expect("policy-deny event")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(event.kind, DataplaneEventKind::PolicyDeny);
    assert_eq!(event.action, 0);
    assert_eq!(event.reason, 5);
    assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(event.egress_zone_id, TEST_WAN_ZONE_ID);
    assert_eq!(event.ingress_ifindex, 24);
    assert_eq!(event.policy_id, 42);
    assert_eq!(event.rule_id, 42);
    assert_eq!(event.src_port, 12345);
    assert_eq!(event.dst_port, 5201);
    assert_eq!(event_handle.dataplane_event_stats().policy_deny.sent, 1);
}

#[test]
fn forwarding_resolution_reports_egress_and_neighbor() {
    let state = build_forwarding_state(&forwarding_snapshot(true));
    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(
        resolved.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1)))
    );
    assert_eq!(
        resolved.neighbor_mac,
        Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
}

#[test]
fn forwarding_resolution_supports_next_table_recursion() {
    let state = build_forwarding_state(&forwarding_snapshot_with_next_table(true));
    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(
        resolved.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1)))
    );

    let resolved_v6 = lookup_forwarding_resolution(
        &state,
        IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
    );
    assert_eq!(
        resolved_v6.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved_v6.egress_ifindex, 12);
    assert_eq!(
        resolved_v6.next_hop,
        Some(IpAddr::V6("2001:559:8585:50::1".parse().expect("v6 nh")))
    );
}

#[test]
fn forwarding_state_normalizes_ipv6_routes_emitted_in_inet_table() {
    let mut snapshot = forwarding_snapshot(true);
    snapshot.routes[1].table = "inet.0".to_string();
    snapshot.routes[1].family = "inet".to_string();
    let state = build_forwarding_state(&snapshot);
    let resolved = lookup_forwarding_resolution(
        &state,
        IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(
        resolved.next_hop,
        Some(IpAddr::V6("2001:559:8585:50::1".parse().expect("v6 nh")))
    );
}

#[test]
fn dynamic_neighbor_cache_enables_forward_candidate() {
    let state = build_forwarding_state(&forwarding_snapshot(false));
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    dynamic_neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
        NeighborEntry {
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        },
    );
    let resolved = lookup_forwarding_resolution_with_dynamic(
        &state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        resolved.neighbor_mac,
        Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
}

#[test]
fn parse_neighbor_entries_accepts_stale_ipv4_and_ipv6_rows() {
    let parsed = parse_neighbor_entries(
        "172.16.80.200 lladdr ba:86:e9:f6:4b:d5 STALE\n2001:559:8585:80::200 lladdr ba:86:e9:f6:4b:d5 STALE\n",
    );
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].0, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    assert_eq!(
        parsed[1].0,
        IpAddr::V6("2001:559:8585:80::200".parse().expect("ipv6"))
    );
    assert_eq!(parsed[0].1.mac, [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    assert_eq!(parsed[1].1.mac, [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
}

#[test]
fn learned_ingress_neighbor_enables_reverse_lan_resolution() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    learn_dynamic_neighbor(
        &state,
        &dynamic_neighbors,
        24,
        0,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let resolved = lookup_forwarding_resolution_with_dynamic(
        &state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 24);
    assert_eq!(
        resolved.neighbor_mac,
        Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    );
}

#[test]
fn learned_vlan_ingress_neighbor_maps_to_logical_ifindex() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    learn_dynamic_neighbor(
        &state,
        &dynamic_neighbors,
        11,
        80,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
    );
    let resolved = lookup_forwarding_resolution_with_dynamic(
        &state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(
        resolved.neighbor_mac,
        Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])
    );
}

// #1787: end-state assertions for the cheap-first learn rework. The
// elision decision itself is covered by the pure-helper matrix in
// neighbor_dispatch::learn_precheck_tests (map contents cannot
// distinguish an elided write from an idempotent overwrite).

const LEARN_MAC_A: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const LEARN_MAC_B: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

#[test]
fn learn_dynamic_neighbor_first_learn_inserts_single_key_without_vlan() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100));
    // reth1.0 has no parent: (24, 0) resolves to logical 24 ==
    // ingress, so exactly one key is written.
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 24, 0, ip, LEARN_MAC_A);
    assert_eq!(
        dynamic_neighbors.get(&(24, ip)).map(|e| e.mac),
        Some(LEARN_MAC_A)
    );
    // The unused stack-array placeholder key (0, ip) must never leak
    // into the map.
    assert!(dynamic_neighbors.get(&(0, ip)).is_none());
    assert_eq!(dynamic_neighbors.len(), 1);
}

#[test]
fn learn_dynamic_neighbor_vlan_first_learn_inserts_both_keys() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    // (11, vlan 80) resolves to logical sub-interface 12: the #949
    // pair — physical 11 AND logical 12 — is written together.
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 11, 80, ip, LEARN_MAC_A);
    assert_eq!(
        dynamic_neighbors.get(&(11, ip)).map(|e| e.mac),
        Some(LEARN_MAC_A)
    );
    assert_eq!(
        dynamic_neighbors.get(&(12, ip)).map(|e| e.mac),
        Some(LEARN_MAC_A)
    );
    assert_eq!(dynamic_neighbors.len(), 2);
}

#[test]
fn learn_dynamic_neighbor_same_mac_relearn_is_noop_precheck() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 11, 80, ip, LEARN_MAC_A);
    // After the first learn, the pre-check decision for the same MAC
    // must be "no write needed" — this is the steady-state elision.
    let current = [
        dynamic_neighbors.get(&(11, ip)).map(|e| e.mac),
        dynamic_neighbors.get(&(12, ip)).map(|e| e.mac),
    ];
    assert!(!pair_write_needed(&current, LEARN_MAC_A));
    // A second identical learn leaves contents unchanged.
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 11, 80, ip, LEARN_MAC_A);
    assert_eq!(
        dynamic_neighbors.get(&(11, ip)).map(|e| e.mac),
        Some(LEARN_MAC_A)
    );
    assert_eq!(
        dynamic_neighbors.get(&(12, ip)).map(|e| e.mac),
        Some(LEARN_MAC_A)
    );
    assert_eq!(dynamic_neighbors.len(), 2);
}

#[test]
fn learn_dynamic_neighbor_mac_flip_updates_both_keys() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 11, 80, ip, LEARN_MAC_A);
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 11, 80, ip, LEARN_MAC_B);
    assert_eq!(
        dynamic_neighbors.get(&(11, ip)).map(|e| e.mac),
        Some(LEARN_MAC_B)
    );
    assert_eq!(
        dynamic_neighbors.get(&(12, ip)).map(|e| e.mac),
        Some(LEARN_MAC_B)
    );
    assert_eq!(dynamic_neighbors.len(), 2);
}

#[test]
fn learn_dynamic_neighbor_relearns_removed_key() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 11, 80, ip, LEARN_MAC_A);
    // A remove (netlink delete / resolver revoke / manager replace)
    // takes one half of the pair out. The next learn that reaches
    // this function pre-check-misses and restores BOTH keys via the
    // bulk path.
    dynamic_neighbors.remove(&(12, ip));
    assert!(dynamic_neighbors.get(&(12, ip)).is_none());
    learn_dynamic_neighbor(&state, &dynamic_neighbors, 11, 80, ip, LEARN_MAC_A);
    assert_eq!(
        dynamic_neighbors.get(&(11, ip)).map(|e| e.mac),
        Some(LEARN_MAC_A)
    );
    assert_eq!(
        dynamic_neighbors.get(&(12, ip)).map(|e| e.mac),
        Some(LEARN_MAC_A)
    );
}

#[test]
fn forwarding_resolution_rejects_next_table_loop() {
    let state = build_forwarding_state(&forwarding_snapshot_with_next_table_loop());
    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::NextTableUnsupported
    );
}

#[test]
fn tx_binding_resolution_prefers_bind_ifindex_for_vlan_units() {
    let state = build_forwarding_state(&nat_snapshot());
    assert_eq!(resolve_tx_binding_ifindex(&state, 12), 11);
}

#[test]
fn tx_binding_resolution_uses_fabric_parent_ifindex() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    assert_eq!(resolve_tx_binding_ifindex(&state, 21), 21);
}

// === #1912: cold ENCAP outer next-hop neighbor keying ===

#[test]
fn outer_neighbor_ifindex_non_tunnel_returns_egress_ifindex() {
    // For a non-tunnel resolution the helper must be byte-identical to
    // egress_ifindex (the off-tunnel path is unchanged).
    let state = build_forwarding_state(&nat_snapshot());
    let resolution = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(172, 16, 80, 200),
        "inet.0",
        0,
        true,
        None,
    );
    assert_eq!(resolution.tunnel_endpoint_id, 0);
    assert_eq!(
        outer_neighbor_ifindex(&state, None, &resolution),
        resolution.egress_ifindex
    );
}

#[test]
fn resolve_tunnel_outer_returns_outer_l3_egress() {
    // The factored SSOT returns the OUTER transport resolution whose
    // egress_ifindex is the outer L3 egress (reth0.80, ifindex 12 — a VLAN
    // subif), NOT the tunnel logical ifindex (gr-0-0-0, 362).
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let outer = resolve_tunnel_outer(&state, None, 1, 0).expect("outer resolves");
    assert_eq!(outer.egress_ifindex, 12);
    // VLAN outer transport: tx_ifindex is the PARENT (bind_ifindex 6), so
    // the neighbor key (the subif) differs from tx_ifindex — keying by
    // tx_ifindex would be wrong.
    assert_eq!(outer.tx_ifindex, 6);
}

#[test]
fn outer_neighbor_ifindex_tunnel_returns_outer_vlan_subif_not_logical_or_parent() {
    // A tunnel-marked resolution carries egress_ifindex = tunnel logical
    // (362) but next_hop = outer hop. The helper must return the outer L3
    // egress (12, the VLAN subif), not the tunnel logical (362) and not the
    // VLAN parent / tx_ifindex (6).
    let state = build_forwarding_state(&native_gre_snapshot(false));
    let resolution = resolve_tunnel_forwarding_resolution(&state, None, 1, 0);
    assert_ne!(resolution.tunnel_endpoint_id, 0);
    assert_eq!(resolution.egress_ifindex, 362);
    assert_eq!(resolution.disposition, ForwardingDisposition::MissingNeighbor);
    let neigh_if = outer_neighbor_ifindex(&state, None, &resolution);
    assert_eq!(neigh_if, 12, "outer L3 subif, not tunnel logical");
    assert_ne!(neigh_if, resolution.egress_ifindex, "not the tunnel logical");
    assert_ne!(neigh_if, resolution.tx_ifindex, "not the VLAN parent");
}

#[test]
fn outer_neighbor_ifindex_missing_endpoint_falls_back_to_egress_ifindex() {
    // The `> 0` fallback: a tunnel-marked resolution whose endpoint id is
    // unknown to live state must fall back to egress_ifindex rather than
    // probe ifindex 0.
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let mut resolution = no_route_resolution(None);
    resolution.tunnel_endpoint_id = 9999; // not present in state
    resolution.egress_ifindex = 777;
    assert_eq!(outer_neighbor_ifindex(&state, None, &resolution), 777);
}

// --- is_ipsec_traffic recognition (#2385) ---------------------------------
//
// Host-terminated IPsec must be steered to the kernel XFRM slow path. The
// recognition predicate must cover ESP (proto 50), AH (proto 51), and IKE /
// NAT-T (UDP 500/4500). AH (#2385) is the regression guard: it was omitted,
// so AH-protected SAs fell through to ordinary transit forwarding and were
// dropped. The dst_port argument is ignored for the protocol-number arms, so
// these cases hold for both IPv4 and IPv6 (the protocol number is the only
// input, taken from meta.protocol regardless of L3 family).

#[test]
fn is_ipsec_traffic_recognizes_ah_proto_51() {
    // FAIL-ON-REVERT: AH (proto 51) must be recognized as IPsec passthrough,
    // exactly like ESP. If PROTO_AH is removed from is_ipsec_traffic this
    // assertion fails. AH carries no transport port, so dst_port is
    // irrelevant — assert across a representative spread of ports.
    assert_eq!(PROTO_AH, 51, "AH protocol number");
    for port in [0u16, 80, 443, 500, 4500, 65535] {
        assert!(
            is_ipsec_traffic(PROTO_AH, port),
            "AH (proto 51) must be IPsec-passthrough regardless of port \
             (port={port})"
        );
    }
}

#[test]
fn is_ipsec_traffic_recognizes_esp_and_ike() {
    // No-regression: ESP (proto 50) and IKE/NAT-T (UDP 500/4500) must still
    // be recognized.
    assert_eq!(PROTO_ESP, 50, "ESP protocol number");
    for port in [0u16, 443, 500, 4500, 65535] {
        assert!(
            is_ipsec_traffic(PROTO_ESP, port),
            "ESP (proto 50) must be IPsec-passthrough regardless of port \
             (port={port})"
        );
    }
    assert!(
        is_ipsec_traffic(PROTO_UDP, 500),
        "IKE on UDP/500 must be IPsec-passthrough"
    );
    assert!(
        is_ipsec_traffic(PROTO_UDP, 4500),
        "NAT-T on UDP/4500 must be IPsec-passthrough"
    );
}

#[test]
fn is_ipsec_traffic_rejects_non_ipsec() {
    // No over-match: ordinary transit protocols must NOT be classified as
    // IPsec passthrough.
    assert!(
        !is_ipsec_traffic(PROTO_TCP, 443),
        "TCP/443 is not IPsec passthrough"
    );
    assert!(
        !is_ipsec_traffic(PROTO_UDP, 53),
        "UDP/53 (DNS) is not IPsec passthrough"
    );
    assert!(
        !is_ipsec_traffic(PROTO_UDP, 4499),
        "UDP near-miss port is not IPsec passthrough"
    );
    // GRE (proto 47) sits between UDP(17) and ESP(50)/AH(51) — guard the
    // protocol boundary so the predicate does not widen to a range check.
    assert!(
        !is_ipsec_traffic(PROTO_GRE, 0),
        "GRE (proto 47) is not IPsec passthrough"
    );
}

// ---------------------------------------------------------------------------
// #2388 / #2389 / #2390 — Rust FIB route-snapshot correctness regressions.
// Each test FAILS if the corresponding fix is reverted.
// ---------------------------------------------------------------------------

/// #2388: connected routes must be table-scoped. Two routing-instances own
/// the SAME connected prefix (10.0.0.0/24) on different interfaces. A
/// lookup in tenant-b's table must resolve to tenant-b's interface, never
/// leak to tenant-a's connected route. Revert (drop the `entry.table ==
/// table` filter in the connected scan) → the global scan returns
/// tenant-a's interface (pushed first) → egress mismatch → RED.
#[test]
fn connected_routes_are_table_scoped_no_cross_vrf_leak() {
    let snapshot = crate::ConfigSnapshot {
        zones: vec![
            crate::ZoneSnapshot {
                name: "za".to_string(),
                id: TEST_TRUST_ZONE_ID,
                ..Default::default()
            },
            crate::ZoneSnapshot {
                name: "zb".to_string(),
                id: TEST_UNTRUST_ZONE_ID,
                ..Default::default()
            },
        ],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/1.80".to_string(),
                zone: "za".to_string(),
                routing_instance: "tenant-a".to_string(),
                linux_name: "ge-0-0-1.80".to_string(),
                ifindex: 101,
                hardware_addr: "02:00:00:00:00:a1".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.0.0.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/1.90".to_string(),
                zone: "zb".to_string(),
                routing_instance: "tenant-b".to_string(),
                linux_name: "ge-0-0-1.90".to_string(),
                ifindex: 202,
                hardware_addr: "02:00:00:00:00:b2".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.0.0.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);

    // A lookup directed into tenant-b's table for a host in the overlapping
    // prefix must egress tenant-b's interface (202), never tenant-a's (101).
    let resolved = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(10, 0, 0, 42),
        "tenant-b.inet.0",
        0,
        true,
        None,
    );
    assert_eq!(
        resolved.egress_ifindex, 202,
        "tenant-b lookup must resolve tenant-b's connected interface, not tenant-a's (cross-VRF leak)",
    );

    // And the mirror: tenant-a's table resolves tenant-a's interface.
    let resolved_a = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(10, 0, 0, 42),
        "tenant-a.inet.0",
        0,
        true,
        None,
    );
    assert_eq!(resolved_a.egress_ifindex, 101);
}

/// #3151: local-delivery (to-self) resolution must be table-scoped, mirroring
/// the #2388 route-path fix. Two routing-instances own the SAME local address
/// (10.0.0.1) on different interfaces. A to-self packet resolved in tenant-b's
/// table must attribute local/egress/tx ifindex to tenant-b's interface (202),
/// never leak to tenant-a's (101, pushed first). Revert (drop the
/// `entry.table == table` filter in the local-delivery connected scan) → the
/// global scan returns tenant-a's interface → wrong VRF/zone/RG attribution →
/// RED.
#[test]
fn local_delivery_is_table_scoped_no_cross_vrf_leak() {
    let snapshot = crate::ConfigSnapshot {
        zones: vec![
            crate::ZoneSnapshot {
                name: "za".to_string(),
                id: TEST_TRUST_ZONE_ID,
                tcp_rst: false,
                ..Default::default()
            },
            crate::ZoneSnapshot {
                name: "zb".to_string(),
                id: TEST_UNTRUST_ZONE_ID,
                tcp_rst: false,
                ..Default::default()
            },
        ],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/1.80".to_string(),
                zone: "za".to_string(),
                routing_instance: "tenant-a".to_string(),
                linux_name: "ge-0-0-1.80".to_string(),
                ifindex: 101,
                hardware_addr: "02:00:00:00:00:a1".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.0.0.1/32".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/1.90".to_string(),
                zone: "zb".to_string(),
                routing_instance: "tenant-b".to_string(),
                linux_name: "ge-0-0-1.90".to_string(),
                ifindex: 202,
                hardware_addr: "02:00:00:00:00:b2".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.0.0.1/32".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());

    // The destination is one of our own local addresses (to-self): it is in
    // both VRFs' connected lists. Resolved in tenant-b's table → tenant-b's
    // interface (202).
    let resolved_b = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        Some("tenant-b.inet.0"),
    );
    assert_eq!(
        resolved_b.disposition,
        ForwardingDisposition::LocalDelivery,
        "to-self traffic must be local-delivery",
    );
    assert_eq!(
        resolved_b.local_ifindex, 202,
        "tenant-b to-self must attribute tenant-b's interface, not tenant-a's (cross-VRF leak)",
    );
    assert_eq!(resolved_b.egress_ifindex, 202);

    // Mirror: tenant-a's table resolves tenant-a's interface (101).
    let resolved_a = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        Some("tenant-a.inet.0"),
    );
    assert_eq!(resolved_a.local_ifindex, 101);
}

/// #3151 (v6): identical table-scoped local-delivery guarantee for the IPv6
/// branch (connected_v6). Revert the `entry.table == table` filter → tenant-a
/// leak → RED.
#[test]
fn local_delivery_v6_is_table_scoped_no_cross_vrf_leak() {
    let snapshot = crate::ConfigSnapshot {
        zones: vec![
            crate::ZoneSnapshot {
                name: "za".to_string(),
                id: TEST_TRUST_ZONE_ID,
                tcp_rst: false,
                ..Default::default()
            },
            crate::ZoneSnapshot {
                name: "zb".to_string(),
                id: TEST_UNTRUST_ZONE_ID,
                tcp_rst: false,
                ..Default::default()
            },
        ],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/1.80".to_string(),
                zone: "za".to_string(),
                routing_instance: "tenant-a".to_string(),
                linux_name: "ge-0-0-1.80".to_string(),
                ifindex: 301,
                hardware_addr: "02:00:00:00:00:a1".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet6".to_string(),
                    address: "2001:db8::1/128".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/1.90".to_string(),
                zone: "zb".to_string(),
                routing_instance: "tenant-b".to_string(),
                linux_name: "ge-0-0-1.90".to_string(),
                ifindex: 402,
                hardware_addr: "02:00:00:00:00:b2".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet6".to_string(),
                    address: "2001:db8::1/128".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());

    let resolved_b = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V6("2001:db8::1".parse().unwrap()),
        Some("tenant-b.inet6.0"),
    );
    assert_eq!(
        resolved_b.disposition,
        ForwardingDisposition::LocalDelivery,
    );
    assert_eq!(
        resolved_b.local_ifindex, 402,
        "tenant-b to-self (v6) must attribute tenant-b's interface, not tenant-a's",
    );

    let resolved_a = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V6("2001:db8::1".parse().unwrap()),
        Some("tenant-a.inet6.0"),
    );
    assert_eq!(resolved_a.local_ifindex, 301);
}

/// #2389: a static route with two next-hops must retain BOTH in the FIB
/// (equal-cost), and a dead first next-hop must fall back to a live
/// alternate. Revert the build to `next_hops.first()` → only one candidate
/// retained → len 1 → RED; revert the selection → a dead NH[0] blackholes.
#[test]
fn ecmp_static_route_retains_all_next_hops_and_skips_dead() {
    let snapshot = crate::ConfigSnapshot {
        zones: vec![crate::ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        }],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 11,
                hardware_addr: "02:00:00:00:00:11".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.2.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                ifindex: 22,
                hardware_addr: "02:00:00:00:00:22".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.3.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        routes: vec![crate::RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "203.0.113.0/24".to_string(),
            // Two equal-cost next-hops, each via a distinct interface.
            next_hops: vec![
                "192.0.2.2@ge-0/0/1".to_string(),
                "192.0.3.2@ge-0/0/2".to_string(),
            ],
            discard: false,
            next_table: String::new(),
            preference: 5,
        }],
        // Only the SECOND next-hop's neighbor is resolved; the first is dead.
        neighbors: vec![crate::NeighborSnapshot {
            interface: "ge-0-0-2".to_string(),
            ifindex: 22,
            family: "inet".to_string(),
            ip: "192.0.3.2".to_string(),
            mac: "00:11:22:33:44:66".to_string(),
            state: "reachable".to_string(),
            router: true,
            link_local: false,
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);

    // Build retains BOTH next-hops (not just the first).
    let route = &state.routes_v4.get("inet.0").expect("table")[0];
    assert_eq!(
        route.next_hops.len(),
        2,
        "ECMP route must retain all next-hops, not collapse to the first",
    );

    // Selection skips the dead first next-hop and forwards via the live
    // second (egress ge-0/0/2 = ifindex 22), producing a ForwardCandidate
    // rather than a MissingNeighbor blackhole on NH[0].
    let resolved = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(203, 0, 113, 5),
        "inet.0",
        0,
        true,
        None,
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate,
        "live alternate next-hop must forward despite a dead first next-hop",
    );
    assert_eq!(
        resolved.egress_ifindex, 22,
        "must egress the live next-hop's interface",
    );
}

/// #2923: a MIXED direct+tunnel ECMP group must select BOTH paths. The
/// pre-fix liveness closure gated EVERY candidate on `ifindex > 0 &&
/// neighbor-resolved-on-that-ifindex`. A tunnel next-hop is the logical
/// tunnel ifindex with no neighbor for the inner destination, so it always
/// failed that gate. With a live DIRECT member also present, `live > 0`
/// restricted selection to the direct member and the tunnel path was
/// starved — every flow pinned to the direct hop, the tunnel endpoint never
/// selected even though its underlay was fully up.
///
/// The fix makes liveness type-aware: a tunnel candidate is live when its
/// endpoint resolves a usable underlay (`resolve_tunnel_outer`). This test
/// builds a direct hop (egress ifindex 11) plus a GRE tunnel hop (endpoint
/// id 1, logical ifindex 362, IPv6 outer that resolves via reth0.80 with a
/// live neighbor) on ONE inet.0 ECMP prefix, and asserts that sweeping the
/// per-flow hash selects BOTH the direct egress (11) and the tunnel egress
/// (362, carrying tunnel_endpoint_id 1).
///
/// FAIL-ON-REVERT: revert the tunnel-liveness branch in the v4 selection
/// closure and the tunnel candidate is marked dead again; with the direct
/// member live, selection collapses to ifindex 11 only and the tunnel egress
/// assertion goes RED (tunnel starved).
#[test]
fn ecmp_mixed_direct_and_tunnel_selects_both_paths() {
    // Base GRE fixture: tunnel endpoint id 1 on gr-0/0/0.0 (logical ifindex
    // 362), IPv6 outer destination resolving via reth0.80 (ifindex 12) with
    // a live outer neighbor (include_neighbor = true).
    let mut snapshot = native_gre_snapshot(true);
    // Add a DIRECT next-hop interface in a routable zone with a live neighbor.
    snapshot.interfaces.push(crate::InterfaceSnapshot {
        name: "ge-0/0/1".to_string(),
        zone: "wan".to_string(),
        linux_name: "ge-0-0-1".to_string(),
        ifindex: 11,
        hardware_addr: "02:00:00:00:00:11".to_string(),
        addresses: vec![crate::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "192.0.2.1/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.neighbors.push(crate::NeighborSnapshot {
        interface: "ge-0-0-1".to_string(),
        ifindex: 11,
        family: "inet".to_string(),
        ip: "192.0.2.2".to_string(),
        mac: "00:11:22:33:44:77".to_string(),
        state: "reachable".to_string(),
        router: true,
        link_local: false,
    });
    // One inet.0 ECMP prefix with a mixed direct + tunnel next-hop set.
    snapshot.routes.push(crate::RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "203.0.113.0/24".to_string(),
        next_hops: vec![
            "192.0.2.2@ge-0/0/1".to_string(), // direct
            "@gr-0/0/0.0".to_string(),        // tunnel (endpoint id 1)
        ],
        discard: false,
        next_table: String::new(),
        preference: 5,
    });
    let state = build_forwarding_state(&snapshot);

    // The FIB retains BOTH next-hops, and exactly one carries a tunnel id.
    let route = &state.routes_v4.get("inet.0").expect("table")[0];
    assert_eq!(route.next_hops.len(), 2, "ECMP route must retain both hops");
    assert!(
        route.next_hops.iter().any(|nh| nh.tunnel_endpoint_id == 1),
        "the tunnel next-hop must carry tunnel_endpoint_id 1",
    );
    assert!(
        route.next_hops.iter().any(|nh| nh.tunnel_endpoint_id == 0),
        "the direct next-hop must carry no tunnel id",
    );

    // Sweep the per-flow hash; both the direct egress (11) and the tunnel
    // egress (logical ifindex 362) must be selected. Pre-fix, the tunnel
    // candidate is dead and selection collapses to 11 only.
    let mut egresses = std::collections::BTreeSet::new();
    let mut saw_tunnel_id = false;
    for h in 0u64..64 {
        let resolved = lookup_forwarding_resolution_v4(
            &state,
            None,
            Ipv4Addr::new(203, 0, 113, 5),
            "inet.0",
            0,
            true,
            Some(h),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate,
            "both the direct and tunnel members must forward (live)",
        );
        egresses.insert(resolved.egress_ifindex);
        if resolved.tunnel_endpoint_id == 1 {
            saw_tunnel_id = true;
            assert_eq!(
                resolved.egress_ifindex, 362,
                "a tunnel selection must egress the logical tunnel ifindex",
            );
        }
    }
    assert!(
        egresses.contains(&11),
        "the direct ECMP member (ifindex 11) must be selected",
    );
    assert!(
        egresses.contains(&362),
        "the tunnel ECMP member (logical ifindex 362) must be selected \
         — RED pre-fix: the direct-neighbor gate starves the tunnel path",
    );
    assert!(
        saw_tunnel_id,
        "a tunnel selection must carry tunnel_endpoint_id 1",
    );
}

/// #2923 (review finding #1): a tunnel candidate whose OUTER underlay route is
/// WITHDRAWN must be DEAD, not live. `resolve_tunnel_outer` still returns
/// `Some(NoRoute)` for an endpoint with no usable underlay route (it only
/// returns `None` for unknown-endpoint / local-delivery / recursion), so a
/// bare `.is_some()` liveness test would mark the dead tunnel live and ~half
/// the flows in a mixed group would hash to it and DROP (NoRoute) despite a
/// fully live direct member. The fix gates tunnel liveness on a FORWARDABLE
/// disposition (ForwardCandidate | MissingNeighbor).
///
/// FAIL-ON-REVERT: revert `tunnel_next_hop_live` to bare `.is_some()` and the
/// NoRoute tunnel is selected for ~half the hashes → a NoRoute disposition
/// appears and the "all flows forward via the live direct hop" assertion goes
/// RED (partial blackhole).
#[test]
fn ecmp_mixed_with_noroute_underlay_tunnel_uses_only_live_direct_hop() {
    // Same base as the mixed test, but the GRE tunnel's OUTER route
    // (2602:ffd3:0:2::/64 in inet6.0) is WITHDRAWN — its underlay is down, so
    // the outer resolves to NoRoute and the tunnel must be DEAD.
    let mut snapshot = native_gre_snapshot(true);
    snapshot
        .routes
        .retain(|r| r.destination != "2602:ffd3:0:2::/64");
    snapshot.interfaces.push(crate::InterfaceSnapshot {
        name: "ge-0/0/1".to_string(),
        zone: "wan".to_string(),
        linux_name: "ge-0-0-1".to_string(),
        ifindex: 11,
        hardware_addr: "02:00:00:00:00:11".to_string(),
        addresses: vec![crate::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "192.0.2.1/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.neighbors.push(crate::NeighborSnapshot {
        interface: "ge-0-0-1".to_string(),
        ifindex: 11,
        family: "inet".to_string(),
        ip: "192.0.2.2".to_string(),
        mac: "00:11:22:33:44:77".to_string(),
        state: "reachable".to_string(),
        router: true,
        link_local: false,
    });
    snapshot.routes.push(crate::RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "203.0.113.0/24".to_string(),
        next_hops: vec![
            "192.0.2.2@ge-0/0/1".to_string(), // direct, live
            "@gr-0/0/0.0".to_string(),        // tunnel, underlay WITHDRAWN
        ],
        discard: false,
        next_table: String::new(),
        preference: 5,
    });
    let state = build_forwarding_state(&snapshot);

    // Sweep the per-flow hash: EVERY flow must forward via the live direct hop
    // (ifindex 11). The dead tunnel must never be selected — no NoRoute, no
    // tunnel egress (362).
    let mut egresses = std::collections::BTreeSet::new();
    for h in 0u64..64 {
        let resolved = lookup_forwarding_resolution_v4(
            &state,
            None,
            Ipv4Addr::new(203, 0, 113, 5),
            "inet.0",
            0,
            true,
            Some(h),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate,
            "no flow may blackhole (NoRoute) on the dead tunnel — every flow \
             must forward via the live direct hop",
        );
        assert_eq!(
            resolved.tunnel_endpoint_id, 0,
            "the dead (NoRoute-underlay) tunnel must never be selected",
        );
        egresses.insert(resolved.egress_ifindex);
    }
    assert_eq!(
        egresses,
        std::collections::BTreeSet::from([11]),
        "every flow must forward via the live direct hop (ifindex 11) — a \
         NoRoute-underlay tunnel must NOT be selected (RED if liveness stays \
         bare .is_some(): the dead tunnel is picked for ~half the hashes)",
    );
}

/// #2923 (review finding #2): the v6 selection path must apply the same
/// type-aware tunnel liveness. Mirrors `ecmp_mixed_direct_and_tunnel_*` but
/// drives `lookup_forwarding_resolution_v6` with an INNER v6 prefix whose ECMP
/// set mixes a direct v6 hop (ifindex 11) and the GRE tunnel hop (endpoint 1,
/// logical ifindex 362, IPv6 outer resolving via reth0.80).
///
/// FAIL-ON-REVERT: revert the v6 tunnel-liveness branch and the tunnel
/// candidate is dead again; with the direct v6 member live, selection
/// collapses to ifindex 11 only and the tunnel-egress assertion goes RED.
#[test]
fn ecmp_mixed_direct_and_tunnel_selects_both_paths_v6() {
    let mut snapshot = native_gre_snapshot(true);
    // Direct v6 next-hop interface in a routable zone with a live v6 neighbor.
    snapshot.interfaces.push(crate::InterfaceSnapshot {
        name: "ge-0/0/1".to_string(),
        zone: "wan".to_string(),
        linux_name: "ge-0-0-1".to_string(),
        ifindex: 11,
        hardware_addr: "02:00:00:00:00:11".to_string(),
        addresses: vec![crate::InterfaceAddressSnapshot {
            family: "inet6".to_string(),
            address: "2001:db8:ec::1/64".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.neighbors.push(crate::NeighborSnapshot {
        interface: "ge-0-0-1".to_string(),
        ifindex: 11,
        family: "inet6".to_string(),
        ip: "2001:db8:ec::2".to_string(),
        mac: "00:11:22:33:44:88".to_string(),
        state: "reachable".to_string(),
        router: true,
        link_local: false,
    });
    // One inet6.0 INNER ECMP prefix mixing a direct v6 hop + the tunnel hop.
    // (Disjoint from the GRE outer prefix 2602:ffd3:0:2::/64.)
    snapshot.routes.push(crate::RouteSnapshot {
        table: "inet6.0".to_string(),
        family: "inet6".to_string(),
        destination: "2001:db8:dead::/48".to_string(),
        next_hops: vec![
            "2001:db8:ec::2@ge-0/0/1".to_string(), // direct
            "@gr-0/0/0.0".to_string(),             // tunnel (endpoint id 1)
        ],
        discard: false,
        next_table: String::new(),
        preference: 5,
    });
    let state = build_forwarding_state(&snapshot);

    // The inet6.0 table also holds the GRE outer prefix; find OUR mixed prefix.
    let dead_net: Ipv6Addr = "2001:db8:dead::".parse().unwrap();
    let route = state
        .routes_v6
        .get("inet6.0")
        .expect("table")
        .iter()
        .find(|r| r.prefix.contains(dead_net))
        .expect("mixed inet6.0 ECMP route present");
    assert_eq!(route.next_hops.len(), 2, "ECMP route must retain both hops");
    assert!(
        route.next_hops.iter().any(|nh| nh.tunnel_endpoint_id == 1),
        "the tunnel next-hop must carry tunnel_endpoint_id 1",
    );

    let mut egresses = std::collections::BTreeSet::new();
    let mut saw_tunnel_id = false;
    for h in 0u64..64 {
        let resolved = lookup_forwarding_resolution_v6(
            &state,
            None,
            "2001:db8:dead::5".parse::<Ipv6Addr>().unwrap(),
            "inet6.0",
            0,
            true,
            Some(h),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate,
            "both the direct and tunnel v6 members must forward (live)",
        );
        egresses.insert(resolved.egress_ifindex);
        if resolved.tunnel_endpoint_id == 1 {
            saw_tunnel_id = true;
            assert_eq!(
                resolved.egress_ifindex, 362,
                "a v6 tunnel selection must egress the logical tunnel ifindex",
            );
        }
    }
    assert!(
        egresses.contains(&11),
        "the direct v6 ECMP member (ifindex 11) must be selected",
    );
    assert!(
        egresses.contains(&362),
        "the v6 tunnel ECMP member (logical ifindex 362) must be selected \
         — RED if the v6 tunnel-liveness branch is reverted",
    );
    assert!(
        saw_tunnel_id,
        "a v6 tunnel selection must carry tunnel_endpoint_id 1",
    );
}

/// #2734: ECMP must spread by the per-FLOW 5-tuple, not per-destination.
///
/// Two equal-cost next-hops to the same prefix, BOTH neighbors live.
/// Distinct flows to the SAME destination IP must spread across both
/// members (per-flow), while every probe of ONE flow pins to a single
/// member (flow consistency — no intra-flow reordering). The
/// per-destination fallback (`None`) collapses every flow onto ONE member
/// — that is the pre-#2734 behavior and the fail-on-revert guard: if the
/// production path is reverted to per-dst selection, the spread assertion
/// goes RED.
#[test]
fn ecmp_static_route_spreads_per_flow_not_per_destination() {
    let snapshot = crate::ConfigSnapshot {
        zones: vec![crate::ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        }],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 11,
                hardware_addr: "02:00:00:00:00:11".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.2.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                ifindex: 22,
                hardware_addr: "02:00:00:00:00:22".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.3.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        routes: vec![crate::RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "203.0.113.0/24".to_string(),
            next_hops: vec![
                "192.0.2.2@ge-0/0/1".to_string(),
                "192.0.3.2@ge-0/0/2".to_string(),
            ],
            discard: false,
            next_table: String::new(),
            preference: 5,
        }],
        // BOTH next-hop neighbors are resolved/live, so the live pool is
        // the full set of equal-cost members.
        neighbors: vec![
            crate::NeighborSnapshot {
                interface: "ge-0-0-1".to_string(),
                ifindex: 11,
                family: "inet".to_string(),
                ip: "192.0.2.2".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                state: "reachable".to_string(),
                router: true,
                link_local: false,
            },
            crate::NeighborSnapshot {
                interface: "ge-0-0-2".to_string(),
                ifindex: 22,
                family: "inet".to_string(),
                ip: "192.0.3.2".to_string(),
                mac: "00:11:22:33:44:66".to_string(),
                state: "reachable".to_string(),
                router: true,
                link_local: false,
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    let make_flow = |src_port: u16| SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
        dst_ip: dst,
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            dst_ip: dst,
            src_port,
            dst_port: 443,
        },
    };
    // A non-LocalDelivery, non-tunnel, non-cacheable decision resolution so
    // the production session path RE-RESOLVES via the flow hash (rather than
    // returning a cached ForwardCandidate). This exercises the real wiring
    // (`lookup_forwarding_resolution_for_session`), not just the helper.
    let resolve_for_flow = |flow: &SessionFlow| {
        let decision = SessionDecision {
            resolution: no_route_resolution(None),
            nat: NatDecision::default(),
        };
        lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, flow, decision)
    };

    // (a) Per-FLOW spread: distinct 5-tuples (varying source port) to the
    // SAME destination must hit BOTH equal-cost members through the real
    // session resolution path.
    let mut egresses = std::collections::BTreeSet::new();
    for src_port in 1024u16..1124 {
        let resolved = resolve_for_flow(&make_flow(src_port));
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate,
            "every live flow must forward",
        );
        egresses.insert(resolved.egress_ifindex);
    }
    assert_eq!(
        egresses,
        std::collections::BTreeSet::from([11, 22]),
        "distinct flows to one dst must spread across BOTH ECMP members \
         (per-flow), not pin to one — RED if reverted to per-destination",
    );

    // (b) Flow consistency: repeated probes of ONE flow pin to ONE member.
    let one_flow = make_flow(1042);
    let pinned = resolve_for_flow(&one_flow).egress_ifindex;
    for _ in 0..50 {
        let again = resolve_for_flow(&one_flow).egress_ifindex;
        assert_eq!(
            again, pinned,
            "a single flow's packets must pin to one member (no reorder)",
        );
    }

    // (c) Fail-on-revert: the per-DESTINATION path (None flow hash, the
    // pre-#2734 behavior) collapses EVERY flow onto a SINGLE member —
    // exactly the spread the per-flow path fixes.
    let mut dst_egresses = std::collections::BTreeSet::new();
    for src_port in 1024u16..1124 {
        // The 5-tuple differs, but the per-dst path ignores it.
        let _ = src_port;
        let resolved = lookup_forwarding_resolution_v4(
            &state,
            Some(&dynamic_neighbors),
            Ipv4Addr::new(203, 0, 113, 5),
            "inet.0",
            0,
            true,
            None,
        );
        dst_egresses.insert(resolved.egress_ifindex);
    }
    assert_eq!(
        dst_egresses.len(),
        1,
        "per-destination ECMP must collapse all flows to one member \
         (the bug #2734 fixes)",
    );
}

/// #2734: the seeded per-flow ECMP hash is deterministic within a boot
/// (flow consistency) and spreads distinct 5-tuples across the index
/// space. Pin the seed so the assertions are stable across the parallel
/// runner; production folds in the per-boot process seed.
#[test]
fn ecmp_flow_hash_is_stable_and_spreads() {
    let key_a = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        src_port: 1024,
        dst_port: 443,
    };
    let mut key_b = key_a.clone();
    key_b.src_port = 1025;

    let seed = 0x1234_5678_9abc_def0u64;
    // Intra-seed stability: same key, same hash (a flow never splits).
    assert_eq!(
        ecmp_hash_flow_seeded(seed, &key_a),
        ecmp_hash_flow_seeded(seed, &key_a),
    );
    // Distinct 5-tuples map to distinct hashes under one seed (spread).
    assert_ne!(
        ecmp_hash_flow_seeded(seed, &key_a),
        ecmp_hash_flow_seeded(seed, &key_b),
    );
    // Cross-seed reshuffle: a different per-boot seed remaps the flow.
    assert_ne!(
        ecmp_hash_flow_seeded(seed, &key_a),
        ecmp_hash_flow_seeded(seed ^ 0xffff_ffff_ffff_ffff, &key_a),
    );
}

/// #2390: two same-prefix static routes with different preference must
/// select the lower-preference one regardless of insertion order. The
/// worse route is inserted FIRST. Revert (sort by prefix length only) →
/// insertion order wins → the worse next-hop is selected → RED.
#[test]
fn same_prefix_routes_tie_break_by_preference_not_insertion_order() {
    let snapshot = crate::ConfigSnapshot {
        zones: vec![crate::ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        }],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 11,
                hardware_addr: "02:00:00:00:00:11".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.2.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                ifindex: 22,
                hardware_addr: "02:00:00:00:00:22".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.3.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        routes: vec![
            // WORSE route first (higher preference = less preferred).
            crate::RouteSnapshot {
                table: "inet.0".to_string(),
                family: "inet".to_string(),
                destination: "203.0.113.0/24".to_string(),
                next_hops: vec!["192.0.2.2@ge-0/0/1".to_string()],
                discard: false,
                next_table: String::new(),
                preference: 50,
            },
            // BETTER route second (lower preference).
            crate::RouteSnapshot {
                table: "inet.0".to_string(),
                family: "inet".to_string(),
                destination: "203.0.113.0/24".to_string(),
                next_hops: vec!["192.0.3.2@ge-0/0/2".to_string()],
                discard: false,
                next_table: String::new(),
                preference: 5,
            },
        ],
        neighbors: vec![
            crate::NeighborSnapshot {
                interface: "ge-0-0-1".to_string(),
                ifindex: 11,
                family: "inet".to_string(),
                ip: "192.0.2.2".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                state: "reachable".to_string(),
                router: true,
                link_local: false,
            },
            crate::NeighborSnapshot {
                interface: "ge-0-0-2".to_string(),
                ifindex: 22,
                family: "inet".to_string(),
                ip: "192.0.3.2".to_string(),
                mac: "00:11:22:33:44:66".to_string(),
                state: "reachable".to_string(),
                router: true,
                link_local: false,
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);

    let resolved = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(203, 0, 113, 5),
        "inet.0",
        0,
        true,
        None,
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        resolved.egress_ifindex, 22,
        "lower-preference route (pref 5, ge-0/0/2) must win over the higher-preference route (pref 50, ge-0/0/1) inserted first",
    );
}

/// #2922: `select_route_next_hop` must evaluate the (impure) liveness
/// predicate exactly ONCE per candidate — not twice (count + nth).
///
/// FAIL-ON-REVERT: the pre-#2922 two-pass form called `is_live` for the
/// `count()` pass AND again for the `nth()` pass — `2 * candidates.len()`
/// calls. This test pins the call count to exactly `candidates.len()`, so
/// reverting to the double-eval form makes the assertion RED.
#[test]
fn select_route_next_hop_evaluates_liveness_once_per_candidate() {
    use std::cell::Cell;
    let candidates = [10u32, 20, 30, 40];
    let calls = Cell::new(0usize);
    let selected = select_route_next_hop(&candidates, 1, |_c| {
        calls.set(calls.get() + 1);
        true // all live
    });
    assert_eq!(
        calls.get(),
        candidates.len(),
        "liveness predicate must be evaluated exactly once per candidate (single snapshot); \
         the reverted double-eval form calls it 2x",
    );
    // Selection still works over the live set: ip_hash 1 % 4 live = index 1.
    assert_eq!(selected, Some(&20));
}

/// #2922: a candidate that flips from live→dead between the count pass and
/// the selection pass must not cause a wrong/dead pick (or a spurious
/// no-route). With a single snapshot this is structurally impossible.
///
/// FAIL-ON-REVERT: the closure here returns `true` on the FIRST observation
/// of a given candidate and `false` on every later observation — modeling a
/// neighbor the monitor thread removes between passes. Under the old
/// two-pass form the `count()` pass saw all 4 live (`live == 4`,
/// `pool_len == 4`, `pick == 4 % 4 == 0`), then the `nth(0)` pass re-ran the
/// closure and EVERY candidate now reported dead → the filtered iterator was
/// empty → `nth(0)` returned `None` → spurious no-route despite live members
/// at count time. The single-pass form snapshots liveness once, so the pick
/// resolves to a real, live candidate.
#[test]
fn select_route_next_hop_consistent_under_liveness_flip_between_passes() {
    use std::cell::RefCell;
    use std::collections::HashSet;
    let candidates = [10u32, 20, 30, 40];
    // Each candidate is "live" only the first time it is observed; any
    // subsequent observation (a second pass) reports it dead.
    let seen: RefCell<HashSet<u32>> = RefCell::new(HashSet::new());
    let selected = select_route_next_hop(&candidates, 0, |c| {
        let mut s = seen.borrow_mut();
        s.insert(*c) // true on first insert, false if already present
    });
    assert!(
        selected.is_some(),
        "single liveness snapshot must not yield a spurious no-route when \
         live candidates existed at evaluation time (the reverted double-eval \
         form returns None here)",
    );
    let pick = selected.unwrap();
    assert!(
        candidates.contains(pick),
        "selected next-hop must be a real candidate from the snapshot",
    );
}
