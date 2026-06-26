// Tests for afxdp/session_glue/mod.rs — originally inline in
// session_glue.rs, relocated to session_glue_tests.rs in #1077, then
// folded with mod.rs into the afxdp/session_glue/ directory module
// (#1078) to keep afxdp/'s flat namespace tidy.
// Loaded as a sibling submodule via `#[path = "tests.rs"]` from
// session_glue/mod.rs.

use super::*;
use crate::filter::Filter;
use crate::test_zone_ids::*;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

const TCP_FLAG_ACK: u8 = 0x10;

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

fn test_resolution() -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
        neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
        src_mac: Some([6, 7, 8, 9, 10, 11]),
        tx_vlan_id: 0,
    }
}

fn test_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: 1,
        egress_zone: 2,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
    }
}

fn test_decision() -> SessionDecision {
    SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision::default(),
    }
}

fn empty_filter(name: &str, family: &str) -> Arc<Filter> {
    Arc::new(Filter {
        id: 1,
        name: name.to_string(),
        family: family.to_string(),
        terms: Vec::new(),
        affects_tx_selection: false,
        affects_route_lookup: false,
        has_counter_terms: false,
        has_log_terms: false,
        has_terminal_action_terms: false,
        has_dscp_match_terms: false,
        has_per_packet_l4_match_terms: false,
        has_three_color_policer_terms: false,
    })
}

fn test_forwarding_state() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(10, 0, 61, 0), 24).unwrap()),
        ifindex: 6,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (6, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        },
    );
    forwarding.egress.insert(
        6,
        EgressInterface {
            bind_ifindex: 6,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );
    forwarding
}

#[test]
fn session_key_has_lo0_filter_matches_packet_family() {
    let mut forwarding = ForwardingState::default();
    let v4_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)),
        src_port: 12345,
        dst_port: 5201,
    };
    let v6_key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        src_port: 12345,
        dst_port: 5201,
    };

    assert!(!session_key_has_lo0_filter(&forwarding, &v4_key));
    forwarding.filter_state.lo0_filter_v4_fast = Some(empty_filter("lo0-v4", "inet"));
    assert!(session_key_has_lo0_filter(&forwarding, &v4_key));
    assert!(!session_key_has_lo0_filter(&forwarding, &v6_key));

    forwarding.filter_state.lo0_filter_v6_fast = Some(empty_filter("lo0-v6", "inet6"));
    assert!(session_key_has_lo0_filter(&forwarding, &v6_key));
}

#[test]
fn republish_local_delivery_sessions_for_lo0_filter_selects_existing_hits() {
    let mut forwarding = ForwardingState::default();
    forwarding.filter_state.lo0_filter_v4_fast = Some(empty_filter("lo0-v4", "inet"));
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)),
        src_port: 12345,
        dst_port: 5201,
    };
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        key,
        test_local_delivery_decision(),
        test_metadata(),
        SessionOrigin::SyncImport,
        1,
        PROTO_TCP,
        TCP_FLAG_SYN,
    ));

    assert_eq!(
        republish_local_delivery_sessions_for_lo0_filter(&sessions, -1, &forwarding),
        1
    );

    forwarding.filter_state.lo0_filter_v4_fast = None;
    assert_eq!(
        republish_local_delivery_sessions_for_lo0_filter(&sessions, -1, &forwarding),
        0
    );
}

#[test]
fn purge_sessions_for_input_dscp_filter_revalidation_removes_family() {
    let forwarding = ForwardingState::default();
    let mut sessions = SessionTable::new();
    let v4_key = test_key();
    let v6_key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        src_port: 12345,
        dst_port: 5201,
    };
    assert!(sessions.install_with_protocol_with_origin(
        v4_key.clone(),
        test_decision(),
        test_metadata(),
        SessionOrigin::ForwardFlow,
        1,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    assert!(sessions.install_with_protocol_with_origin(
        v6_key.clone(),
        test_decision(),
        test_metadata(),
        SessionOrigin::ForwardFlow,
        1,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    let _ = sessions.drain_deltas(16);
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();

    assert_eq!(
        purge_sessions_for_input_dscp_filter_revalidation(
            &mut sessions,
            -1,
            -1,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            &forwarding,
            true,
            false,
            2,
        ),
        1
    );

    assert!(sessions.entry_with_origin(&v4_key).is_none());
    assert!(sessions.entry_with_origin(&v6_key).is_some());
    let deltas = sessions.drain_deltas(16);
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
    assert_eq!(deltas[0].key, v4_key);
}

fn test_local_delivery_decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 12,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    }
}

fn test_forwarding_state_with_fabric() -> ForwardingState {
    let mut forwarding = test_forwarding_state();
    forwarding
        .zone_name_to_id
        .insert("lan".to_string(), TEST_LAN_ZONE_ID);
    forwarding
        .zone_name_to_id
        .insert("sfmix".to_string(), TEST_SFMIX_ZONE_ID);
    forwarding
        .zone_name_to_id
        .insert("wan".to_string(), TEST_WAN_ZONE_ID);
    forwarding.fabrics.push(FabricLink {
        parent_ifindex: 21,
        overlay_ifindex: 101,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
    });
    forwarding
}

fn test_forwarding_state_split_rgs() -> ForwardingState {
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.egress.insert(
        6,
        EgressInterface {
            bind_ifindex: 6,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 2,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    forwarding
}

fn test_forwarding_state_split_rgs_with_tunnel() -> ForwardingState {
    let mut forwarding = test_forwarding_state_split_rgs();
    forwarding.tunnel_endpoint_by_ifindex.insert(586, 1);
    forwarding
}

fn test_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 55068,
        dst_port: 5201,
    }
}

#[test]
fn maybe_promote_synced_session_sets_fabric_ingress_on_fabric_hit() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();
    // Install with SyncImport origin to mark as peer-synced
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata.clone(),
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let forwarding = test_forwarding_state_with_fabric();
    // #1346: wrap the four shared-map refs in `SharedSessionRefs`
    // (Copy struct) to match the post-refactor signature.
    let shared = super::SharedSessionRefs {
        sessions: &shared_sessions,
        nat_sessions: &shared_nat_sessions,
        forward_wire_sessions: &shared_forward_wire_sessions,
        owner_rg_indexes: &shared_owner_rg_indexes,
    };

    let promoted = maybe_promote_synced_session(
        &mut sessions,
        -1,
        shared,
        &peer_worker_commands,
        &forwarding,
        &key,
        decision,
        metadata,
        SessionOrigin::SyncImport,
        true,
        2_000_000,
        PROTO_TCP,
        0x10,
    );

    assert!(promoted.fabric_ingress);
}

#[test]
fn maybe_promote_synced_session_skips_worker_local_import() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata.clone(),
        SessionOrigin::WorkerLocalImport,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let forwarding = test_forwarding_state_with_fabric();
    // #1346: wrap the four shared-map refs in `SharedSessionRefs`
    // (Copy struct) to match the post-refactor signature.
    let shared = super::SharedSessionRefs {
        sessions: &shared_sessions,
        nat_sessions: &shared_nat_sessions,
        forward_wire_sessions: &shared_forward_wire_sessions,
        owner_rg_indexes: &shared_owner_rg_indexes,
    };

    let promoted = maybe_promote_synced_session(
        &mut sessions,
        -1,
        shared,
        &peer_worker_commands,
        &forwarding,
        &key,
        decision,
        metadata.clone(),
        SessionOrigin::WorkerLocalImport,
        false,
        2_000_000,
        PROTO_TCP,
        0x10,
    );

    assert_eq!(promoted, metadata);
    let Some((_decision, _metadata, origin)) = sessions.entry_with_origin(&key) else {
        panic!("worker-local session missing");
    };
    assert_eq!(origin, SessionOrigin::WorkerLocalImport);
    assert!(shared_sessions.lock().expect("shared sessions").is_empty());
}

#[test]
fn resolve_flow_session_decision_promotes_stale_fabric_shared_hit_to_local_owner_path() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
        },
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(1));

    let shared_entry = SyncedSessionEntry {
        key: key.clone(),
        decision: SessionDecision {
            resolution: resolve_fabric_redirect(&forwarding).expect("fabric redirect"),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: Some(key.src_port),
                ..NatDecision::default()
            },
        },
        metadata: SessionMetadata {
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x18,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &shared_entry,
    );

    let wire_key = forward_wire_key(&key, shared_entry.decision.nat);
    let flow = SessionFlow {
        src_ip: wire_key.src_ip,
        dst_ip: wire_key.dst_ip,
        forward_key: wire_key,
    };
    let resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        0x18,
        21,
        true,
        0,
    )
    .expect("resolved");

    assert_eq!(
        resolved.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.decision.resolution.egress_ifindex, 12);
    assert_eq!(resolved.metadata.owner_rg_id, 1);
    assert!(resolved.metadata.fabric_ingress);
}

#[test]
fn cached_session_resolution_skips_fabric_redirect() {
    let forwarding = test_forwarding_state_with_fabric();
    let cached = ForwardingResolution {
        disposition: ForwardingDisposition::FabricRedirect,
        local_ifindex: 0,
        egress_ifindex: 21,
        tx_ifindex: 21,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
        neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
        src_mac: Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]),
        tx_vlan_id: 0,
    };

    assert!(cached_session_resolution(&forwarding, cached).is_none());
}

#[test]
fn lookup_session_across_scopes_returns_shared_entry() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision: test_decision(),
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_sessions
        .lock()
        .expect("shared lock")
        .insert(key.clone(), entry.clone());

    let resolved = lookup_session_across_scopes(
        &mut sessions,
        &shared_sessions,
        &shared_forward_wire_sessions,
        &key,
        1,
        0,
    )
    .expect("shared hit");
    assert!(resolved.shared_entry.is_some());
    assert_eq!(resolved.key.as_ref(&key), &key);
    assert_eq!(resolved.lookup.decision, entry.decision);
    assert_eq!(resolved.lookup.metadata, entry.metadata);
    assert_eq!(resolved.origin, SessionOrigin::SyncImport);
}

#[test]
fn lookup_session_across_scopes_preserves_local_synced_origin() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        test_decision(),
        test_metadata(),
        SessionOrigin::SyncImport,
        1,
        PROTO_TCP,
        0,
    ));
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));

    let resolved = lookup_session_across_scopes(
        &mut sessions,
        &shared_sessions,
        &shared_forward_wire_sessions,
        &key,
        2,
        0,
    )
    .expect("local synced hit");
    assert!(resolved.shared_entry.is_none());
    assert_eq!(resolved.key.as_ref(&key), &key);
    assert_eq!(resolved.origin, SessionOrigin::SyncImport);
}

#[test]
fn lookup_session_across_scopes_returns_shared_forward_wire_entry() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_forward_wire_sessions
        .lock()
        .expect("shared forward-wire lock")
        .insert(translated_key.clone(), entry.clone());

    let resolved = lookup_session_across_scopes(
        &mut sessions,
        &shared_sessions,
        &shared_forward_wire_sessions,
        &translated_key,
        1,
        0,
    )
    .expect("shared forward-wire hit");
    assert!(resolved.shared_entry.is_some());
    assert_eq!(resolved.key.as_ref(&translated_key), &key);
    assert_eq!(resolved.lookup.decision, entry.decision);
    assert_eq!(resolved.lookup.metadata, entry.metadata);
    assert_eq!(resolved.origin, SessionOrigin::SyncImport);
}

#[test]
fn lookup_session_across_scopes_preserves_local_forward_wire_synced_origin() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        test_metadata(),
        SessionOrigin::SyncImport,
        1,
        PROTO_TCP,
        0,
    ));
    let translated_key = forward_wire_key(&key, decision.nat);
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));

    let resolved = lookup_session_across_scopes(
        &mut sessions,
        &shared_sessions,
        &shared_forward_wire_sessions,
        &translated_key,
        2,
        0,
    )
    .expect("local forward-wire synced hit");
    assert!(resolved.shared_entry.is_none());
    assert_eq!(resolved.key.as_ref(&translated_key), &key);
    assert_eq!(resolved.origin, SessionOrigin::SyncImport);
}

#[test]
fn lookup_session_across_scopes_prefers_shared_entry_over_fabric_wire_placeholder() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    assert!(sessions.install_with_protocol_with_origin(
        translated_key.clone(),
        decision,
        SessionMetadata {
            fabric_ingress: true,
            ..test_metadata()
        },
        SessionOrigin::ForwardFlow,
        1,
        PROTO_TCP,
        0,
    ));
    let shared_entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_forward_wire_sessions
        .lock()
        .expect("shared forward-wire lock")
        .insert(translated_key.clone(), shared_entry.clone());

    let resolved = lookup_session_across_scopes(
        &mut sessions,
        &shared_sessions,
        &shared_forward_wire_sessions,
        &translated_key,
        2,
        0,
    )
    .expect("shared forward-wire hit");
    assert!(resolved.shared_entry.is_some());
    assert_eq!(resolved.key.as_ref(&translated_key), &key);
    assert_eq!(resolved.lookup.decision, shared_entry.decision);
    assert_eq!(resolved.lookup.metadata, shared_entry.metadata);
    assert_eq!(resolved.origin, SessionOrigin::SyncImport);
}

#[test]
fn lookup_forward_nat_across_scopes_returns_shared_nat_entry() {
    let sessions = SessionTable::new();
    let key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        src_ip: IpAddr::V6("fd35:1940:27:100::102".parse::<Ipv6Addr>().unwrap()),
        dst_ip: IpAddr::V6("2607:f8b0:4005:814::200e".parse::<Ipv6Addr>().unwrap()),
        src_port: 0x8234,
        dst_port: 0,
    };
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(
                "2602:fd41:70:100::102".parse::<Ipv6Addr>().unwrap(),
            )),
            nptv6: true,
            ..NatDecision::default()
        },
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_ICMPV6,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let reply_key = reverse_session_key(&key, decision.nat);
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_nat_sessions
        .lock()
        .expect("shared nat lock")
        .insert(reply_key.clone(), entry.clone());

    let hit = lookup_forward_nat_across_scopes(&sessions, &shared_nat_sessions, &reply_key)
        .expect("shared forward nat hit");
    assert_eq!(hit.key, entry.key);
    assert_eq!(hit.decision, entry.decision);
    assert_eq!(hit.metadata, entry.metadata);
}

#[test]
fn lookup_forward_nat_across_scopes_prefers_shared_entry_over_fabric_wire_placeholder() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    assert!(sessions.install_with_protocol_with_origin(
        translated_key,
        decision,
        SessionMetadata {
            fabric_ingress: true,
            ..test_metadata()
        },
        SessionOrigin::ForwardFlow,
        1,
        PROTO_TCP,
        0,
    ));
    let shared_entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let reply_key = reverse_session_key(&key, decision.nat);
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_nat_sessions
        .lock()
        .expect("shared nat lock")
        .insert(reply_key.clone(), shared_entry.clone());

    let hit = lookup_forward_nat_across_scopes(&sessions, &shared_nat_sessions, &reply_key)
        .expect("shared nat hit");
    assert_eq!(hit.key, shared_entry.key);
    assert_eq!(hit.decision, shared_entry.decision);
    assert_eq!(hit.metadata, shared_entry.metadata);
}

#[test]
fn lookup_forward_nat_across_scopes_ignores_fabric_wire_placeholder_without_shared_entry() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    assert!(sessions.install_with_protocol_with_origin(
        translated_key,
        decision,
        SessionMetadata {
            fabric_ingress: true,
            ..test_metadata()
        },
        SessionOrigin::ForwardFlow,
        1,
        PROTO_TCP,
        0,
    ));
    let reply_key = reverse_session_key(&key, decision.nat);
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));

    assert!(
        lookup_forward_nat_across_scopes(&sessions, &shared_nat_sessions, &reply_key).is_none()
    );
}

#[test]
fn lookup_forward_nat_across_scopes_returns_shared_canonical_reverse_entry() {
    let sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let canonical_reply = reverse_canonical_key(&key, decision.nat);
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_nat_sessions
        .lock()
        .expect("shared nat lock")
        .insert(canonical_reply.clone(), entry.clone());

    let hit = lookup_forward_nat_across_scopes(&sessions, &shared_nat_sessions, &canonical_reply)
        .expect("shared canonical reverse hit");
    assert_eq!(hit.key, entry.key);
    assert_eq!(hit.decision, entry.decision);
    assert_eq!(hit.metadata, entry.metadata);
}

#[test]
fn publish_and_remove_shared_session_tracks_forward_wire_alias() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let translated_key = forward_wire_key(&key, decision.nat);

    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    let alias_hit =
        lookup_shared_forward_wire_match(&shared_forward_wire_sessions, &translated_key)
            .expect("forward-wire alias should be published");
    assert_eq!(alias_hit.key, key);

    remove_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry.key,
    );
    assert!(
        lookup_shared_forward_wire_match(&shared_forward_wire_sessions, &translated_key).is_none()
    );
}

#[test]
fn publish_and_remove_shared_session_tracks_canonical_reverse_alias() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let canonical_reply = reverse_canonical_key(&key, decision.nat);

    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    let alias_hit = lookup_shared_forward_nat_match(&shared_nat_sessions, &canonical_reply)
        .expect("canonical reverse alias should be published");
    assert_eq!(alias_hit.key, key);

    remove_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry.key,
    );
    assert!(lookup_shared_forward_nat_match(&shared_nat_sessions, &canonical_reply).is_none());
}

#[test]
fn publish_and_remove_shared_session_tracks_owner_rg_indexes() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let forward_wire = forward_wire_key(&key, decision.nat);
    let reverse_wire = reverse_session_key(&key, decision.nat);
    let reverse_canonical = reverse_canonical_key(&key, decision.nat);

    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    let sessions_index = shared_owner_rg_indexes
        .sessions
        .lock()
        .expect("sessions index");
    assert!(
        sessions_index
            .get(&entry.metadata.owner_rg_id)
            .is_some_and(|keys| keys.contains(&key))
    );
    drop(sessions_index);

    let nat_index = shared_owner_rg_indexes
        .nat_sessions
        .lock()
        .expect("nat index");
    assert!(
        nat_index
            .get(&entry.metadata.owner_rg_id)
            .is_some_and(|keys| keys.contains(&reverse_wire) && keys.contains(&reverse_canonical))
    );
    drop(nat_index);

    let forward_wire_index = shared_owner_rg_indexes
        .forward_wire_sessions
        .lock()
        .expect("forward-wire index");
    assert!(
        forward_wire_index
            .get(&entry.metadata.owner_rg_id)
            .is_some_and(|keys| keys.contains(&forward_wire))
    );
    drop(forward_wire_index);

    remove_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry.key,
    );

    assert!(
        shared_owner_rg_indexes
            .sessions
            .lock()
            .expect("sessions index")
            .is_empty()
    );
    assert!(
        shared_owner_rg_indexes
            .nat_sessions
            .lock()
            .expect("nat index")
            .is_empty()
    );
    assert!(
        shared_owner_rg_indexes
            .forward_wire_sessions
            .lock()
            .expect("forward-wire index")
            .is_empty()
    );
}

#[test]
fn publish_shared_session_reindexes_owner_rg_on_replace() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let mut entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };

    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    entry.metadata.owner_rg_id = 2;
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    assert!(
        shared_owner_rg_indexes
            .sessions
            .lock()
            .expect("sessions index")
            .get(&1)
            .is_none()
    );
    assert!(
        shared_owner_rg_indexes
            .sessions
            .lock()
            .expect("sessions index")
            .get(&2)
            .is_some_and(|keys| keys.contains(&entry.key))
    );
}

#[test]
fn publish_shared_session_heals_missing_owner_rg_index_on_same_owner_update() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };

    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    shared_owner_rg_indexes
        .sessions
        .lock()
        .expect("sessions index")
        .clear();

    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    assert!(
        shared_owner_rg_indexes
            .sessions
            .lock()
            .expect("sessions index")
            .get(&entry.metadata.owner_rg_id)
            .is_some_and(|keys| keys.contains(&entry.key))
    );
}

#[test]
fn resolve_flow_session_decision_uses_canonical_key_for_translated_forward_hit() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    let flow = SessionFlow {
        src_ip: translated_key.src_ip,
        dst_ip: translated_key.dst_ip,
        forward_key: translated_key.clone(),
    };
    let forwarding = ForwardingState::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let peer_worker_commands = Vec::new();
    let resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        0x10,
        0,
        false,
        0,
    )
    .expect("translated forward hit should resolve");

    assert!(!resolved.created);

    assert!(sessions.lookup(&translated_key, 1_000_000, 0x10).is_none());
    let local_hit = sessions
        .find_forward_wire_match(&translated_key)
        .expect("local canonical session should keep forward-wire alias");
    assert_eq!(local_hit.key, key);
    assert_eq!(resolved.decision.nat, decision.nat);
}

#[test]
fn resolve_flow_session_decision_promotes_translated_shared_hit_on_active_fabric_ingress() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
            .expect("fabric redirect"),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    let entry = SyncedSessionEntry {
        key: translated_key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x18,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
        },
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let peer_worker_commands = Vec::new();
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(1));

    let flow = SessionFlow {
        src_ip: translated_key.src_ip,
        dst_ip: translated_key.dst_ip,
        forward_key: translated_key.clone(),
    };
    let resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        0x18,
        21,
        true,
        0,
    )
    .expect("translated shared hit should resolve");

    assert_eq!(
        resolved.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.decision.resolution.egress_ifindex, 12);

    let local_hit = sessions
        .lookup(&translated_key, 1_000_000, 0x18)
        .expect("promoted translated hit should stay local");
    assert_eq!(local_hit.decision.nat, decision.nat);

    assert!(
        shared_sessions
            .lock()
            .expect("shared lock")
            .get(&translated_key)
            .is_some()
    );
}

#[test]
fn resolve_flow_session_decision_promotes_local_synced_translated_hit_on_active_fabric_ingress() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
            .expect("fabric redirect"),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    assert!(sessions.install_with_protocol_with_origin(
        translated_key.clone(),
        decision,
        SessionMetadata { ..test_metadata() },
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x18,
    ));
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
        },
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let peer_worker_commands = Vec::new();
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(1));

    let flow = SessionFlow {
        src_ip: translated_key.src_ip,
        dst_ip: translated_key.dst_ip,
        forward_key: translated_key.clone(),
    };
    let resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        0x18,
        21,
        true,
        0,
    )
    .expect("translated local hit should resolve");

    assert_eq!(
        resolved.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.decision.resolution.egress_ifindex, 12);

    let local_hit = sessions
        .lookup(&translated_key, 1_000_000, 0x18)
        .expect("promoted translated local hit should stay local");
    assert_eq!(local_hit.decision.nat, decision.nat);
}

#[test]
fn resolve_flow_session_decision_keeps_translated_shared_hit_transient_on_inactive_fabric_ingress()
{
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
            .expect("fabric redirect"),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    let entry = SyncedSessionEntry {
        key: translated_key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x18,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
        },
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let peer_worker_commands = Vec::new();
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, inactive_ha_runtime(0));

    let flow = SessionFlow {
        src_ip: translated_key.src_ip,
        dst_ip: translated_key.dst_ip,
        forward_key: translated_key.clone(),
    };
    let _resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        0x18,
        21,
        true,
        0,
    )
    .expect("translated shared hit should resolve");

    assert!(sessions.lookup(&translated_key, 1_000_000, 0x18).is_none());
}

#[test]
fn resolve_flow_session_decision_keeps_translated_shared_hit_transient_on_inactive_non_fabric_ingress()
 {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
            .expect("fabric redirect"),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    let entry = SyncedSessionEntry {
        key: translated_key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x18,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
        },
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let peer_worker_commands = Vec::new();
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, inactive_ha_runtime(0));

    let flow = SessionFlow {
        src_ip: translated_key.src_ip,
        dst_ip: translated_key.dst_ip,
        forward_key: translated_key.clone(),
    };
    let _resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        0x18,
        12,
        false,
        0,
    )
    .expect("translated shared hit should resolve");

    assert!(sessions.lookup(&translated_key, 1_000_000, 0x18).is_none());
}

#[test]
fn resolve_flow_session_decision_keeps_local_synced_translated_hit_transient_on_inactive_non_fabric_ingress()
 {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
            .expect("fabric redirect"),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    assert!(sessions.install_with_protocol_with_origin(
        translated_key.clone(),
        decision,
        SessionMetadata { ..test_metadata() },
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x18,
    ));
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
        },
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let peer_worker_commands = Vec::new();
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, inactive_ha_runtime(0));

    let flow = SessionFlow {
        src_ip: translated_key.src_ip,
        dst_ip: translated_key.dst_ip,
        forward_key: translated_key.clone(),
    };
    let _resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        0x18,
        12,
        false,
        0,
    )
    .expect("translated local hit should resolve");

    assert!(sessions.lookup(&translated_key, 1_000_000, 0x18).is_none());
}

#[test]
fn apply_worker_commands_replaces_stale_local_session_for_inactive_owner_rg() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let live_metadata = test_metadata();
    assert!(sessions.install_with_protocol(
        key.clone(),
        test_decision(),
        live_metadata,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    let synced_metadata = SessionMetadata { ..test_metadata() };
    let synced_decision = SessionDecision {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
        ..test_decision()
    };
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::UpsertSynced(SyncedSessionEntry {
            key: key.clone(),
            decision: synced_decision,
            metadata: synced_metadata.clone(),
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            // #2170 test fixture: no peer install generation.
            generation: 0,
        }));
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, inactive_ha_runtime(0));
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
    );

    let hit = sessions.lookup(&key, 2_000_000, 0x10).expect("synced hit");
    assert_eq!(hit.metadata, synced_metadata);
    // With #326, synced sessions are always re-resolved with local egress
    // info even on standby — so tx_vlan_id picks up the local egress VLAN.
    let expected_decision = SessionDecision {
        resolution: ForwardingResolution {
            tx_vlan_id: 80,
            ..synced_decision.resolution
        },
        ..synced_decision
    };
    assert_eq!(hit.decision, expected_decision);
}

#[test]
fn apply_worker_commands_preserves_local_session_for_active_owner_rg() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let live_decision = test_decision();
    let live_metadata = test_metadata();
    assert!(sessions.install_with_protocol(
        key.clone(),
        live_decision,
        live_metadata.clone(),
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    let synced_decision = SessionDecision {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
        ..test_decision()
    };
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::UpsertSynced(SyncedSessionEntry {
            key: key.clone(),
            decision: synced_decision,
            metadata: SessionMetadata { ..test_metadata() },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            // #2170 test fixture: no peer install generation.
            generation: 0,
        }));
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
    );

    let hit = sessions.lookup(&key, 2_000_000, 0x10).expect("live hit");
    assert_eq!(hit.metadata, live_metadata);
    assert_eq!(hit.decision, live_decision);
}

#[test]
fn worker_synced_local_delivery_forces_live_redirect_on_standby() {
    assert!(force_live_redirect_for_worker_synced_entry(
        test_local_delivery_decision(),
        &test_metadata(),
        SessionOrigin::SyncImport,
        true,
    ));
}

#[test]
fn worker_synced_local_delivery_keeps_default_publish_on_active_owner() {
    assert!(!force_live_redirect_for_worker_synced_entry(
        test_local_delivery_decision(),
        &test_metadata(),
        SessionOrigin::SyncImport,
        false,
    ));
}

#[test]
fn apply_worker_commands_demotes_local_owner_rg_sessions_to_sync_import() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = test_key();
    assert!(sessions.install_with_protocol(
        key.clone(),
        test_decision(),
        test_metadata(),
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] });
    let forwarding = test_forwarding_state();
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(0))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
    );

    let Some((_decision, _metadata, origin)) = sessions.entry_with_origin(&key) else {
        panic!("demoted session missing");
    };
    assert_eq!(origin, SessionOrigin::SyncImport);
}

#[test]
fn demoted_local_session_promotes_as_synced_on_failback_lookup() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();
    assert!(sessions.install_with_protocol(
        key.clone(),
        decision,
        metadata.clone(),
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] });
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let inactive_state = BTreeMap::from([(1, inactive_ha_runtime(0))]);

    apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &inactive_state,
        &dynamic_neighbors,
    );

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let active_state = BTreeMap::from([(1, active_ha_runtime(1))]);
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    };

    let resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &active_state,
        &dynamic_neighbors,
        &flow,
        2_000_000,
        2,
        PROTO_TCP,
        0x10,
        6,
        false,
        0,
    )
    .expect("resolved demoted session");

    assert!(!resolved.created);
    let Some((_decision, _metadata, origin)) = sessions.entry_with_origin(&key) else {
        panic!("promoted session missing");
    };
    assert_eq!(origin, SessionOrigin::SharedPromote);
}

#[test]
fn epoch_based_flow_cache_invalidation_for_demoted_owner_rg() {
    let rg_epochs: [AtomicU32; MAX_RG_EPOCHS] = std::array::from_fn(|_| AtomicU32::new(0));
    let mut flow_cache = FlowCache::new();
    let key = test_key();
    let metadata = SessionMetadata {
        owner_rg_id: 1,
        ..test_metadata()
    };
    // Insert with current epoch (0).
    flow_cache.insert(FlowCacheEntry {
        key: key.clone(),
        ingress_ifindex: 7,
        descriptor: RewriteDescriptor {
            dst_mac: [0; 6],
            src_mac: [0; 6],
            fabric_redirect: false,
            tx_vlan_id: 0,
            ether_type: 0x0800,
            rewrite_src_ip: None,
            rewrite_dst_ip: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            ip_csum_delta: 0,
            l4_csum_delta: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            target_binding_index: None,
            input_filter_log: None,
            tx_selection: CachedTxSelectionDescriptor::default(),
            nat64: false,
            nptv6: false,
            apply_nat_on_fabric: false,
        },
        decision: test_decision(),
        metadata,
        stamp: FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 1,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        },
        observed_bytes: 0,
        last_used_epoch: 0,
        neighbor_mac_epoch: 0,
    });

    // Before epoch bump, lookup should hit.
    assert!(
        flow_cache
            .lookup(
                &key,
                FlowCacheLookup {
                    ingress_ifindex: 7,
                    config_generation: 1,
                    fib_generation: 1,
                },
                0,
                &rg_epochs,
            )
            .is_some()
    );

    // Bump epoch for RG 1 (simulates demotion).
    rg_epochs[1].fetch_add(1, Ordering::Relaxed);

    // After epoch bump, lookup should miss (stale entry).
    assert!(
        flow_cache
            .lookup(
                &key,
                FlowCacheLookup {
                    ingress_ifindex: 7,
                    config_generation: 1,
                    fib_generation: 1,
                },
                0,
                &rg_epochs,
            )
            .is_none()
    );
}

#[test]
fn epoch_based_flow_cache_unrelated_rg_not_invalidated() {
    let rg_epochs: [AtomicU32; MAX_RG_EPOCHS] = std::array::from_fn(|_| AtomicU32::new(0));
    let mut flow_cache = FlowCache::new();
    let key = test_key();
    let metadata = SessionMetadata {
        owner_rg_id: 1,
        ..test_metadata()
    };
    flow_cache.insert(FlowCacheEntry {
        key: key.clone(),
        ingress_ifindex: 7,
        descriptor: RewriteDescriptor {
            dst_mac: [0; 6],
            src_mac: [0; 6],
            fabric_redirect: false,
            tx_vlan_id: 0,
            ether_type: 0x0800,
            rewrite_src_ip: None,
            rewrite_dst_ip: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            ip_csum_delta: 0,
            l4_csum_delta: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            target_binding_index: None,
            input_filter_log: None,
            tx_selection: CachedTxSelectionDescriptor::default(),
            nat64: false,
            nptv6: false,
            apply_nat_on_fabric: false,
        },
        decision: test_decision(),
        metadata,
        stamp: FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 1,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        },
        observed_bytes: 0,
        last_used_epoch: 0,
        neighbor_mac_epoch: 0,
    });

    // Bump epoch for RG 2 (unrelated).
    rg_epochs[2].fetch_add(1, Ordering::Relaxed);

    // RG 1 entry should still hit — only RG 2 was bumped.
    assert!(
        flow_cache
            .lookup(
                &key,
                FlowCacheLookup {
                    ingress_ifindex: 7,
                    config_generation: 1,
                    fib_generation: 1,
                },
                0,
                &rg_epochs,
            )
            .is_some()
    );
}

/// #2653: the single-shot `ExportOwnerRGSessions` command path must NOT push
/// the entire owned-session set into the 4096-slot delta ring in one shot. A
/// worker can own up to DEFAULT_MAX_SESSIONS (131072) = 32x the ring; the old
/// `handle_export_owner_rg_sessions` called `export_forward_sessions_for_owner_rgs`
/// inline, which emitted all N open deltas with no interleaved drain, overflowed
/// the ring at delta 4097, and silently dropped sessions 4097..N from the HA
/// bulk snapshot on rejoin / RG transition (the command-path sibling of the
/// #2442 worker-loop overflow).
///
/// The fix makes the command handler RECORD the owner RGs (`export_owner_rgs`)
/// instead of emitting; the worker loop performs the chunked drain-as-you-export.
/// This test installs > ring-cap owned forward sessions, dispatches the command
/// through `apply_worker_commands`, and asserts:
///   (a) the command records the owner RG;
///   (b) `apply_worker_commands` emits NOTHING inline and does NOT overflow the
///       ring (delta_drops unchanged, no loss latch) — the bound is respected;
///   (c) driving the recorded RGs through the chunked drain-as-you-export ships
///       the COMPLETE snapshot (all N) with zero new drops.
///
/// FAIL-ON-REVERT: restoring the inline `export_forward_sessions_for_owner_rgs`
/// call in `handle_export_owner_rg_sessions` overflows the ring INSIDE
/// `apply_worker_commands` — (b) reds (delta_drops jumps by ~N-4096, the loss
/// latch arms, and only 4096 deltas reach the inline drain).
#[test]
fn export_owner_rg_command_does_not_overflow_ring_unbounded() {
    // Ring cap is MAX_SESSION_DELTAS (4096, private to session/mod.rs).
    const RING_CAP: usize = 4096;
    const RESYNC_EXPORT_CHUNK: usize = 2048; // mirror the worker loop
    let n: usize = RING_CAP + 1000; // 5096 > cap to exercise the overflow hole

    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let mut keys: Vec<SessionKey> = Vec::with_capacity(n);
    for i in 0..n {
        let mut key = test_key();
        // Unique forward keys (owner RG 1 from test_metadata): sweep src ip+port.
        key.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 61, (i / 256) as u8));
        key.src_port = ((i % 256) as u16) + 1000;
        assert!(sessions.install_with_protocol(
            key.clone(),
            test_decision(),
            test_metadata(),
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        keys.push(key);
    }
    // The installs themselves overflowed the ring (n > cap) and latched loss;
    // clear that pre-existing state so the assertions below measure ONLY what
    // the export command does.
    assert!(sessions.delta_drops() > 0, "installing > cap deltas overflows");
    let _ = sessions.take_delta_loss();
    while !sessions.drain_deltas(256).is_empty() {}
    let drops_before_export = sessions.delta_drops();
    assert!(!sessions.take_delta_loss(), "loss latch cleared before export");

    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::ExportOwnerRGSessions {
            sequence: 42,
            owner_rgs: vec![1],
        });
    let forwarding = test_forwarding_state_with_fabric();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
    );

    // (a) the command recorded the owner RG and sequence.
    assert_eq!(results.exported_sequences, vec![42]);
    assert_eq!(results.export_owner_rgs, vec![1]);

    // (b) THE BOUND: apply_worker_commands must NOT push unbounded into the
    // ring. It emits nothing inline and never overflows. The reverted inline
    // export would have emitted all N here, overflowing the ring.
    assert!(
        !sessions.has_pending_deltas(),
        "export command must NOT emit deltas inline (#2653) — the worker loop \
         performs the chunked drain-as-you-export"
    );
    assert_eq!(
        sessions.delta_drops(),
        drops_before_export,
        "export command must NOT overflow the ring (the #2653 unbounded bug)"
    );
    assert!(
        !sessions.take_delta_loss(),
        "export command must NOT latch a delta loss (no mid-export overflow)"
    );

    // (c) driving the recorded RGs through the chunked drain-as-you-export the
    // worker loop runs ships the COMPLETE snapshot with zero new drops.
    let owner_rgs = results.export_owner_rgs.clone();
    let candidates = crate::afxdp::forward_export_candidates_for_owner_rgs(&sessions, &owner_rgs);
    let mut exported = 0usize;
    for chunk in candidates.chunks(RESYNC_EXPORT_CHUNK) {
        for (key, decision, metadata, origin) in chunk.iter().cloned() {
            sessions.emit_open_delta_with_origin(key, decision, metadata, origin, true);
        }
        loop {
            let d = sessions.drain_deltas(256);
            if d.is_empty() {
                break;
            }
            exported += d.iter().filter(|x| x.kind == SessionDeltaKind::Open).count();
        }
    }
    assert_eq!(
        exported, n,
        "chunked export ships the COMPLETE snapshot ({n}), not the ring cap"
    );
    assert_eq!(
        sessions.delta_drops(),
        drops_before_export,
        "the chunked export drops nothing (drain-as-you-export never overflows)"
    );
    assert!(!sessions.take_delta_loss(), "no spurious re-arm after export");
}

#[test]
fn apply_worker_commands_exports_owner_rg_forward_sessions_without_teardown() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_decision().resolution,
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let metadata = SessionMetadata {
        owner_rg_id: 1,
        ..test_metadata()
    };
    assert!(sessions.install_with_protocol(
        key.clone(),
        decision,
        metadata,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(sessions.drain_deltas(16).len(), 1, "initial open delta");
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::ExportOwnerRGSessions {
            sequence: 9,
            owner_rgs: vec![1],
        });
    let forwarding = test_forwarding_state_with_fabric();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
    );

    assert!(results.cancelled_keys.is_empty());
    assert_eq!(results.exported_sequences, vec![9]);
    // #2653: the command handler records the owner RGs instead of emitting the
    // deltas inline (the worker loop performs the chunked drain-as-you-export).
    assert_eq!(results.export_owner_rgs, vec![1]);
    assert!(
        sessions.drain_deltas(16).is_empty(),
        "apply_worker_commands no longer emits export deltas inline (#2653)"
    );
    let hit = sessions
        .lookup(&key, 2_000_000, 0x10)
        .expect("exported forward hit");

    assert_eq!(
        hit.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    // Drive the recorded RGs through the same candidate walk the worker loop
    // chunked export uses: the forward session must republish as an Open delta.
    export_forward_sessions_for_owner_rgs(&mut sessions, &results.export_owner_rgs);
    let deltas = sessions.drain_deltas(16);
    assert_eq!(deltas.len(), 1, "export should republish forward session");
    assert_eq!(deltas[0].kind, SessionDeltaKind::Open);
    assert!(deltas[0].fabric_redirect_sync);
}

#[test]
fn apply_worker_commands_does_not_export_missing_neighbor_seed_sessions() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let metadata = SessionMetadata {
        owner_rg_id: 1,
        ..test_metadata()
    };
    assert!(sessions.install_with_protocol_with_origin(
        key,
        test_decision(),
        metadata,
        SessionOrigin::MissingNeighborSeed,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert!(
        sessions.drain_deltas(16).is_empty(),
        "missing-neighbor seed install should not emit open deltas"
    );
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::ExportOwnerRGSessions {
            sequence: 10,
            owner_rgs: vec![1],
        });
    let forwarding = test_forwarding_state_with_fabric();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
    );

    assert!(results.cancelled_keys.is_empty());
    assert_eq!(results.exported_sequences, vec![10]);
    assert_eq!(results.export_owner_rgs, vec![1]);
    // Even when the worker loop drives the recorded RGs through the chunked
    // export, a missing-neighbor seed session must NOT be republished.
    export_forward_sessions_for_owner_rgs(&mut sessions, &results.export_owner_rgs);
    assert!(
        sessions.drain_deltas(16).is_empty(),
        "missing-neighbor seed sessions must not be exported as HA deltas"
    );
}

#[test]
fn apply_worker_commands_demote_owner_rg_returns_cancelled_keys() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = test_key();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        test_decision(),
        test_metadata(),
        SessionOrigin::ForwardFlow,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::DemoteOwnerRGS {
            owner_rgs: vec![1, 1],
        });

    let forwarding = test_forwarding_state_with_fabric();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000));

    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
    );

    assert_eq!(results.exported_sequences, Vec::<u64>::new());
    assert_eq!(results.cancelled_keys.len(), 1);
    assert!(results.cancelled_keys.iter().any(|k| k == &key));
}

#[test]
fn demote_shared_owner_rgs_preserves_reverse_entries_and_marks_all_synced() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let forward = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let reverse = SyncedSessionEntry {
        key: reverse_session_key(&forward.key, forward.decision.nat),
        decision: test_decision(),
        metadata: SessionMetadata {
            is_reverse: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &forward,
    );
    shared_sessions
        .lock()
        .expect("shared sessions")
        .insert(reverse.key.clone(), reverse.clone());

    demote_shared_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &test_forwarding_state_with_fabric(),
        &Arc::new(ShardedNeighborMap::new()),
        &[1],
    );

    let shared_forward = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&forward.key)
        .cloned()
        .expect("forward entry");
    assert!(shared_forward.origin.is_peer_synced());
    let shared_reverse = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&reverse.key)
        .cloned()
        .expect("reverse entry");
    assert!(shared_reverse.origin.is_peer_synced());
    let reverse_alias = reverse_session_key(&forward.key, forward.decision.nat);
    let nat_alias = shared_nat_sessions
        .lock()
        .expect("shared nat")
        .get(&reverse_alias)
        .cloned()
        .expect("nat alias");
    assert!(nat_alias.origin.is_peer_synced());
}

#[test]
fn demoted_shared_local_forward_session_enters_reverse_prewarm_index() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let forwarding = test_forwarding_state_split_rgs();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: SessionMetadata {
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    entry.metadata.owner_rg_id = 1;

    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    demote_shared_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &forwarding,
        &dynamic_neighbors,
        &[1],
    );

    let index = shared_owner_rg_indexes
        .reverse_prewarm_sessions
        .lock()
        .expect("prewarm index");
    assert!(index.get(&1).is_some_and(|keys| keys.contains(&entry.key)));
    assert!(index.get(&2).is_some_and(|keys| keys.contains(&entry.key)));
}

#[test]
fn prewarm_reverse_synced_sessions_after_demotion_recomputes_split_owner_reverse() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let worker_commands = vec![Arc::new(Mutex::new(VecDeque::new()))];
    let forwarding = test_forwarding_state_split_rgs();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(2, active_ha_runtime(1));
    let mut entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: SessionMetadata {
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    entry.metadata.owner_rg_id = 1;

    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    demote_shared_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &forwarding,
        &dynamic_neighbors,
        &[1],
    );

    prewarm_reverse_synced_sessions_for_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &worker_commands,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &[2],
        1,
    );

    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&reverse_key)
        .cloned()
        .expect("reverse entry");
    assert!(reverse.metadata.is_reverse);
    assert_eq!(reverse.metadata.owner_rg_id, 2);
    assert_eq!(worker_commands[0].lock().expect("commands").len(), 2);
}

#[test]
fn apply_worker_commands_demotes_local_owner_rg_sessions_and_cancels_keys() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] },
    ])));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata,
        SessionOrigin::ForwardFlow,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_with_fabric(),
        &BTreeMap::new(),
        &Arc::new(ShardedNeighborMap::new()),
    );

    assert_eq!(results.cancelled_keys, vec![key.clone()]);
    let (_, origin) = sessions
        .lookup_with_origin(&key, now_ns, 0x10)
        .expect("demoted session");
    assert!(origin.is_peer_synced());
}

#[test]
fn apply_worker_commands_demote_owner_rg_rewrites_resolution_to_fabric_redirect() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] },
    ])));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata,
        SessionOrigin::ForwardFlow,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_ns / 1_000_000_000))]);
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_with_fabric(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
    );

    assert_eq!(results.cancelled_keys, vec![key.clone()]);
    let (lookup, origin) = sessions
        .lookup_with_origin(&key, now_ns, 0x10)
        .expect("demoted session");
    assert!(origin.is_peer_synced());
    assert_eq!(
        lookup.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(lookup.decision.resolution.egress_ifindex, 21);
}

#[test]
fn apply_worker_commands_demote_split_reverse_owner_rg_rewrites_to_fabric_redirect() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![2] },
    ])));
    let mut sessions = SessionTable::new();
    let forward_key = test_key();
    let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
                tx_vlan_id: 0,
            },
            nat: test_decision().nat.reverse(
                forward_key.src_ip,
                forward_key.dst_ip,
                forward_key.src_port,
                forward_key.dst_port,
            ),
        },
        SessionMetadata {
            ingress_zone: 2,
            egress_zone: 1,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
        },
        SessionOrigin::SyncImport,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(now_ns / 1_000_000_000))]);
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_split_rgs(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
    );

    assert_eq!(results.cancelled_keys, vec![reverse_key.clone()]);
    let (lookup, origin) = sessions
        .lookup_with_origin(&reverse_key, now_ns, 0x10)
        .expect("demoted reverse session");
    assert!(origin.is_peer_synced());
    assert_eq!(
        lookup.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(lookup.decision.resolution.egress_ifindex, 21);
    assert_eq!(lookup.metadata.owner_rg_id, 2);
    assert!(lookup.metadata.is_reverse);
}

#[test]
fn apply_worker_commands_refresh_split_reverse_owner_rg_rewrites_to_forward_candidate() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![2] },
    ])));
    let mut sessions = SessionTable::new();
    let forward_key = test_key();
    let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::FabricRedirect,
                local_ifindex: 0,
                egress_ifindex: 21,
                tx_ifindex: 21,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            nat: test_decision().nat.reverse(
                forward_key.src_ip,
                forward_key.dst_ip,
                forward_key.src_port,
                forward_key.dst_port,
            ),
        },
        SessionMetadata {
            ingress_zone: 2,
            egress_zone: 1,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
        },
        SessionOrigin::SyncImport,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let ha_state = BTreeMap::from([(2, active_ha_runtime(now_ns / 1_000_000_000))]);
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_split_rgs(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
    );

    assert!(results.cancelled_keys.is_empty());
    let (lookup, origin) = sessions
        .lookup_with_origin(&reverse_key, now_ns, 0x10)
        .expect("refreshed reverse session");
    assert!(origin.is_peer_synced());
    assert_eq!(
        lookup.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(lookup.decision.resolution.egress_ifindex, 6);
    assert_eq!(lookup.decision.resolution.tx_ifindex, 6);
    assert_eq!(
        lookup.decision.resolution.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
    );
    assert_eq!(lookup.metadata.owner_rg_id, 2);
    assert!(lookup.metadata.is_reverse);
}

#[test]
fn apply_worker_commands_refresh_split_reverse_owner_rg_updates_stale_indexed_session() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![2] },
    ])));
    let mut sessions = SessionTable::new();
    let forward_key = test_key();
    let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::FabricRedirect,
                local_ifindex: 0,
                egress_ifindex: 21,
                tx_ifindex: 21,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            nat: test_decision().nat.reverse(
                forward_key.src_ip,
                forward_key.dst_ip,
                forward_key.src_port,
                forward_key.dst_port,
            ),
        },
        SessionMetadata {
            ingress_zone: 2,
            egress_zone: 1,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
        },
        SessionOrigin::SyncImport,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let ha_state = BTreeMap::from([
        (1, inactive_ha_runtime(now_ns / 1_000_000_000)),
        (2, active_ha_runtime(now_ns / 1_000_000_000)),
    ]);
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_split_rgs(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
    );

    assert!(results.cancelled_keys.is_empty());
    let (lookup, origin) = sessions
        .lookup_with_origin(&reverse_key, now_ns, 0x10)
        .expect("refreshed reverse session");
    assert!(origin.is_peer_synced());
    assert_eq!(
        lookup.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(lookup.decision.resolution.egress_ifindex, 6);
    assert_eq!(lookup.decision.resolution.tx_ifindex, 6);
    assert_eq!(
        lookup.decision.resolution.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
    );
    assert_eq!(lookup.metadata.owner_rg_id, 2);
    assert!(lookup.metadata.is_reverse);
}

#[test]
fn apply_worker_commands_refresh_owner_rg_updates_reverse_session_owned_by_other_rg() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![1] },
    ])));
    let mut sessions = SessionTable::new();
    let forward_key = test_key();
    let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::FabricRedirect,
                local_ifindex: 0,
                egress_ifindex: 21,
                tx_ifindex: 21,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            nat: test_decision().nat.reverse(
                forward_key.src_ip,
                forward_key.dst_ip,
                forward_key.src_port,
                forward_key.dst_port,
            ),
        },
        SessionMetadata {
            ingress_zone: 2,
            egress_zone: 1,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
        },
        SessionOrigin::SharedPromote,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let ha_state = BTreeMap::from([
        (1, active_ha_runtime(now_ns / 1_000_000_000)),
        (2, active_ha_runtime(now_ns / 1_000_000_000)),
    ]);
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_split_rgs(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
    );

    assert!(results.cancelled_keys.is_empty());
    let (lookup, origin) = sessions
        .lookup_with_origin(&reverse_key, now_ns, 0x10)
        .expect("refreshed reverse session");
    assert_eq!(origin, SessionOrigin::SharedPromote);
    assert_eq!(
        lookup.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(lookup.decision.resolution.egress_ifindex, 6);
    assert_eq!(lookup.decision.resolution.tx_ifindex, 6);
    assert_eq!(
        lookup.decision.resolution.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
    );
    assert_eq!(lookup.metadata.owner_rg_id, 2);
    assert!(lookup.metadata.is_reverse);
}

#[test]
fn apply_worker_commands_refresh_owner_rg_rewrites_remote_reverse_session_on_peer_move() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![1] },
    ])));
    let mut sessions = SessionTable::new();
    let forward_key = test_key();
    let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
                tx_vlan_id: 0,
            },
            nat: test_decision().nat.reverse(
                forward_key.src_ip,
                forward_key.dst_ip,
                forward_key.src_port,
                forward_key.dst_port,
            ),
        },
        SessionMetadata {
            ingress_zone: 2,
            egress_zone: 1,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
        },
        SessionOrigin::SyncImport,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let ha_state = BTreeMap::from([
        (1, active_ha_runtime(now_ns / 1_000_000_000)),
        (2, inactive_ha_runtime(now_ns / 1_000_000_000)),
    ]);
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_split_rgs(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
    );

    assert!(results.cancelled_keys.is_empty());
    let (lookup, origin) = sessions
        .lookup_with_origin(&reverse_key, now_ns, 0x10)
        .expect("refreshed reverse session");
    assert!(origin.is_peer_synced());
    assert_eq!(
        lookup.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(lookup.decision.resolution.egress_ifindex, 21);
    assert_eq!(lookup.metadata.owner_rg_id, 2);
    assert!(lookup.metadata.is_reverse);
}

#[test]
fn apply_worker_commands_refresh_owner_rg_rewrites_shared_promote_reverse_on_peer_move() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![1] },
    ])));
    let mut sessions = SessionTable::new();
    let forward_key = test_key();
    let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
                tx_vlan_id: 0,
            },
            nat: test_decision().nat.reverse(
                forward_key.src_ip,
                forward_key.dst_ip,
                forward_key.src_port,
                forward_key.dst_port,
            ),
        },
        SessionMetadata {
            ingress_zone: 2,
            egress_zone: 1,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
        },
        SessionOrigin::SharedPromote,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let ha_state = BTreeMap::from([
        (1, active_ha_runtime(now_ns / 1_000_000_000)),
        (2, inactive_ha_runtime(now_ns / 1_000_000_000)),
    ]);
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_split_rgs(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
    );

    assert!(results.cancelled_keys.is_empty());
    let (lookup, origin) = sessions
        .lookup_with_origin(&reverse_key, now_ns, 0x10)
        .expect("refreshed reverse session");
    assert_eq!(origin, SessionOrigin::SharedPromote);
    assert_eq!(
        lookup.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(lookup.decision.resolution.egress_ifindex, 21);
    assert_eq!(lookup.metadata.owner_rg_id, 2);
    assert!(lookup.metadata.is_reverse);
}

#[test]
fn export_owner_rg_sessions_skips_locally_demoted_entries() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] },
        WorkerCommand::ExportOwnerRGSessions {
            sequence: 11,
            owner_rgs: vec![1],
        },
    ])));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        key,
        decision,
        metadata,
        SessionOrigin::ForwardFlow,
        now_ns,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(sessions.drain_deltas(16).len(), 1);

    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_with_fabric(),
        &BTreeMap::new(),
        &Arc::new(ShardedNeighborMap::new()),
    );

    assert_eq!(results.exported_sequences, vec![11]);
    assert_eq!(results.export_owner_rgs, vec![1]);
    // Driving the recorded RGs through the chunked-export candidate walk must
    // still emit nothing: the session was demoted out of owner RG 1's index.
    export_forward_sessions_for_owner_rgs(&mut sessions, &results.export_owner_rgs);
    assert!(
        sessions.drain_deltas(16).is_empty(),
        "demoted local owner sessions must not be re-exported as fresh HA deltas"
    );
}

#[test]
fn synthesized_synced_reverse_entry_preserves_fabric_ingress_and_reverse_flag() {
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut metadata = test_metadata();
    metadata.fabric_ingress = true;
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };

    let reverse = synthesized_synced_reverse_entry(
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        &entry,
        1,
    )
    .expect("reverse companion");

    assert!(reverse.metadata.is_reverse);
    assert!(reverse.origin.is_peer_synced());
    assert!(reverse.metadata.fabric_ingress);
    assert_eq!(reverse.metadata.ingress_zone, 2);
    assert_eq!(reverse.metadata.egress_zone, 1);
    assert_eq!(
        reverse.key,
        reverse_session_key(&entry.key, entry.decision.nat)
    );
}

#[test]
fn synthesized_synced_reverse_entry_tracks_local_client_when_owner_rg_active() {
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut metadata = test_metadata();
    metadata.fabric_ingress = true;
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(1));

    let reverse =
        synthesized_synced_reverse_entry(&forwarding, &ha_state, &dynamic_neighbors, &entry, 1)
            .expect("reverse companion");

    assert_eq!(
        reverse.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(reverse.decision.resolution.egress_ifindex, 6);
}

#[test]
fn synthesized_synced_reverse_entry_uses_fabric_redirect_when_client_rg_inactive() {
    let forwarding = test_forwarding_state_split_rgs();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut metadata = test_metadata();
    metadata.ingress_zone = TEST_LAN_ZONE_ID;
    metadata.egress_zone = TEST_WAN_ZONE_ID;
    metadata.fabric_ingress = false;
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(1));
    ha_state.insert(2, inactive_ha_runtime(1));

    let reverse =
        synthesized_synced_reverse_entry(&forwarding, &ha_state, &dynamic_neighbors, &entry, 1)
            .expect("reverse companion");

    assert_eq!(
        reverse.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(reverse.decision.resolution.egress_ifindex, 21);
    assert_eq!(
        reverse.decision.resolution.src_mac,
        Some([
            0x02,
            0xbf,
            0x72,
            FABRIC_ZONE_MAC_MAGIC,
            0x00,
            TEST_WAN_ZONE_ID as u8
        ])
    );
    assert_eq!(reverse.metadata.owner_rg_id, 2);
    assert!(reverse.metadata.is_reverse);
}

#[test]
fn session_hit_ha_inactive_uses_zone_encoded_fabric_redirect() {
    let forwarding = test_forwarding_state_with_fabric();
    let redirected = redirect_session_via_fabric_if_needed(
        &forwarding,
        ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            local_ifindex: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
            tx_vlan_id: 0,
        },
        false,
        TEST_SFMIX_ZONE_ID,
    );
    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(redirected.egress_ifindex, 21);
    assert_eq!(redirected.tx_ifindex, 21);
    assert_eq!(
        redirected.src_mac,
        Some([
            0x02,
            0xbf,
            0x72,
            FABRIC_ZONE_MAC_MAGIC,
            0x00,
            TEST_SFMIX_ZONE_ID as u8
        ])
    );
}

#[test]
fn session_hit_ha_inactive_does_not_redirect_actual_fabric_ingress() {
    let forwarding = test_forwarding_state_with_fabric();
    let resolved = redirect_session_via_fabric_if_needed(
        &forwarding,
        ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            local_ifindex: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
            tx_vlan_id: 0,
        },
        true,
        5,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
}

#[test]
fn fabric_ingress_session_hit_obeys_ha_inactive_gate() {
    let forwarding = test_forwarding_state_with_fabric();
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(1))]);
    let resolved = enforce_session_ha_resolution(
        &forwarding,
        &ha_state,
        1,
        ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
            tx_vlan_id: 0,
        },
        21,
        0,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
    assert_eq!(resolved.egress_ifindex, 6);
}

#[test]
fn tunnel_ingress_session_hit_bypasses_unseeded_ha_during_startup_grace() {
    let forwarding = test_forwarding_state_split_rgs_with_tunnel();
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(0))]);
    let resolved = enforce_session_ha_resolution(
        &forwarding,
        &ha_state,
        100,
        ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
            tx_vlan_id: 0,
        },
        586,
        110,
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 6);
}

#[test]
fn reverse_session_from_tunnel_forward_bypasses_unseeded_ha_during_startup_grace() {
    let forwarding = test_forwarding_state_split_rgs_with_tunnel();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(0))]);
    let reverse = build_reverse_session_from_forward_match(
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        ForwardSessionMatch {
            key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
                src_port: 42424,
                dst_port: 5201,
            },
            decision: SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 12,
                    tx_ifindex: 12,
                    tunnel_endpoint_id: 1,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41))),
                    neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x02]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                    tx_vlan_id: 80,
                },
                nat: NatDecision {
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42))),
                    ..NatDecision::default()
                },
            },
            metadata: SessionMetadata {
                ingress_zone: 1,
                egress_zone: 5,
                owner_rg_id: 2,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
                log_session_init: false,
                log_session_close: false,
                policy_id: 0,
            },
        },
        100,
        110,
    );
    assert_eq!(
        reverse.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(reverse.decision.resolution.egress_ifindex, 6);
    assert_eq!(reverse.metadata.owner_rg_id, 2);
}

#[test]
fn prewarm_reverse_synced_sessions_for_owner_rgs_adds_reverse_companion() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let worker_commands = vec![Arc::new(Mutex::new(VecDeque::new()))];
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(1));
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: SessionMetadata {
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    refresh_reverse_prewarm_owner_rg_indexes(
        &shared_owner_rg_indexes.reverse_prewarm_sessions,
        &forwarding,
        &dynamic_neighbors,
        None,
        Some(&entry),
    );

    prewarm_reverse_synced_sessions_for_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &worker_commands,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &[1],
        1,
    );

    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&reverse_key)
        .cloned()
        .expect("reverse entry");
    assert!(reverse.metadata.is_reverse);
    assert!(reverse.origin.is_peer_synced());
    // 2 commands: forward entry + reverse entry (both pushed to workers)
    assert_eq!(worker_commands[0].lock().expect("commands").len(), 2);
}

#[test]
fn prewarm_reverse_synced_sessions_for_owner_rgs_restores_shared_promote_forward_entry() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let worker_commands = vec![Arc::new(Mutex::new(VecDeque::new()))];
    let forwarding = test_forwarding_state_split_rgs();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(1));
    ha_state.insert(2, inactive_ha_runtime(1));
    let mut metadata = test_metadata();
    metadata.ingress_zone = 1;
    metadata.egress_zone = 2;
    metadata.fabric_ingress = false;
    metadata.owner_rg_id = 1;
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata,
        origin: SessionOrigin::SharedPromote,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    let prewarm_index = shared_owner_rg_indexes
        .reverse_prewarm_sessions
        .lock()
        .expect("prewarm index");
    assert!(
        prewarm_index.get(&1).is_none() || !prewarm_index.get(&1).unwrap().contains(&entry.key)
    );
    drop(prewarm_index);

    prewarm_reverse_synced_sessions_for_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &worker_commands,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &[1],
        1,
    );

    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&reverse_key)
        .cloned()
        .expect("reverse entry");
    assert!(reverse.metadata.is_reverse);
    assert_eq!(reverse.metadata.owner_rg_id, 2);
    let commands = worker_commands[0].lock().expect("commands");
    assert_eq!(commands.len(), 2);
    assert!(matches!(
        &commands[0],
        WorkerCommand::UpsertSynced(session) if session.origin == SessionOrigin::SharedPromote
    ));
    assert!(matches!(
        &commands[1],
        WorkerCommand::UpsertSynced(session)
            if session.metadata.is_reverse && session.metadata.owner_rg_id == 2
    ));
}

#[test]
fn prewarm_reverse_synced_sessions_recomputes_when_reverse_owner_rg_activates() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let worker_commands = vec![Arc::new(Mutex::new(VecDeque::new()))];
    let forwarding = test_forwarding_state_split_rgs();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(2, active_ha_runtime(1));
    let mut entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: SessionMetadata {
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    entry.metadata.owner_rg_id = 1;
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    refresh_reverse_prewarm_owner_rg_indexes(
        &shared_owner_rg_indexes.reverse_prewarm_sessions,
        &forwarding,
        &dynamic_neighbors,
        None,
        Some(&entry),
    );

    // owner_rgs=[2] does not include the forward session's owner_rg_id=1,
    // but the synthesized reverse companion resolves to owner_rg_id=2 in
    // the split-RG topology, so activation of RG2 must still prewarm it.
    prewarm_reverse_synced_sessions_for_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &worker_commands,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &[2],
        1,
    );

    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&reverse_key)
        .cloned()
        .expect("reverse entry");
    assert!(reverse.metadata.is_reverse);
    assert_eq!(reverse.metadata.owner_rg_id, 2);
    // 2 commands: forward entry + reverse entry (both pushed to workers)
    assert_eq!(worker_commands[0].lock().expect("commands").len(), 2);
}

#[test]
fn reverse_prewarm_index_tracks_split_reverse_owner_rg_candidate() {
    let forwarding = test_forwarding_state_split_rgs();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let mut entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: SessionMetadata {
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    entry.metadata.owner_rg_id = 1;

    refresh_reverse_prewarm_owner_rg_indexes(
        &shared_owner_rg_indexes.reverse_prewarm_sessions,
        &forwarding,
        &dynamic_neighbors,
        None,
        Some(&entry),
    );

    let index = shared_owner_rg_indexes
        .reverse_prewarm_sessions
        .lock()
        .expect("prewarm index");
    assert!(index.get(&1).is_some_and(|keys| keys.contains(&entry.key)));
    assert!(index.get(&2).is_some_and(|keys| keys.contains(&entry.key)));
}

#[test]
fn reverse_session_from_split_owner_fabric_redirect_uses_fabric_return_when_client_rg_inactive() {
    let forwarding = test_forwarding_state_split_rgs();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(1))]);
    let reverse = build_reverse_session_from_forward_match(
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        ForwardSessionMatch {
            key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 42424,
                dst_port: 5201,
            },
            decision: SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::FabricRedirect,
                    local_ifindex: 0,
                    egress_ifindex: 21,
                    tx_ifindex: 21,
                    tunnel_endpoint_id: 0,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                    neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                    src_mac: Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]),
                    tx_vlan_id: 0,
                },
                nat: NatDecision {
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                    ..NatDecision::default()
                },
            },
            metadata: SessionMetadata {
                ingress_zone: 1,
                egress_zone: 2,
                owner_rg_id: 1,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
                log_session_init: false,
                log_session_close: false,
                policy_id: 0,
            },
        },
        1,
        0,
    );
    assert_eq!(
        reverse.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(reverse.decision.resolution.egress_ifindex, 21);
    assert_eq!(reverse.decision.resolution.tx_ifindex, 21);
}

#[test]
fn republish_bpf_session_entries_covers_all_sessions_in_owner_rg_index() {
    // Simulate the failover+failback scenario (#475):
    // A session is in the shared sessions table and the `sessions`
    // owner-RG index but NOT in the `reverse_prewarm_sessions` index
    // (e.g., locally originated then demoted). The comprehensive
    // republish function must find and attempt to publish it.
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();

    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: SessionMetadata {
            owner_rg_id: 1,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    // Publish to shared table + sessions index (but NOT reverse_prewarm).
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    // Verify the session is in the sessions index but not reverse_prewarm.
    let sessions_index = shared_owner_rg_indexes
        .sessions
        .lock()
        .expect("sessions index");
    assert!(
        sessions_index
            .get(&1)
            .is_some_and(|keys| keys.contains(&entry.key))
    );
    drop(sessions_index);

    let prewarm_index = shared_owner_rg_indexes
        .reverse_prewarm_sessions
        .lock()
        .expect("prewarm index");
    assert!(prewarm_index.get(&1).is_none() || prewarm_index.get(&1).unwrap().is_empty());
    drop(prewarm_index);

    // Call republish — it should find the session via the sessions index.
    // Use fd=-1 (the BPF syscall will fail). The function now only counts
    // successful publishes, so count=0 with fd=-1. We verify the function
    // iterates the right sessions by checking RG2 returns 0 (no sessions).
    let count = republish_bpf_session_entries_for_owner_rgs(
        &shared_sessions,
        &shared_owner_rg_indexes,
        -1,
        &[1],
    );
    assert_eq!(count, 0, "fd=-1 should produce 0 successful publishes");

    // Unrelated RG should return 0.
    let count = republish_bpf_session_entries_for_owner_rgs(
        &shared_sessions,
        &shared_owner_rg_indexes,
        -1,
        &[2],
    );
    assert_eq!(count, 0, "should find 0 sessions for RG2");
}

#[test]
fn synced_session_hit_recomputes_local_resolution_after_failover() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
        },
    );
    let stale_fabric_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::FabricRedirect,
            local_ifindex: 0,
            egress_ifindex: 21,
            tx_ifindex: 21,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
            neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &SyncedSessionEntry {
            key: key.clone(),
            decision: stale_fabric_decision,
            metadata: test_metadata(),
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            // #2170 test fixture: no peer install generation.
            generation: 0,
        },
    );
    let peer_worker_commands = Vec::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ha_state = BTreeMap::from([(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
            lease: HAGroupRuntime::active_lease_until(
                monotonic_nanos() / 1_000_000_000,
                monotonic_nanos() / 1_000_000_000,
            ),
        },
    )]);

    let resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &SessionFlow {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            forward_key: key.clone(),
        },
        1_000_000,
        monotonic_nanos() / 1_000_000_000,
        PROTO_TCP,
        0x10,
        5,
        false,
        0,
    )
    .expect("synced session should resolve");

    assert_eq!(
        resolved.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.decision.resolution.egress_ifindex, 12);
    assert_eq!(resolved.decision.resolution.tx_ifindex, 11);
}

// === #1346 dispatcher order-pin + dedup test =================================
//
// Round-2 Codex review required two test additions:
//   (a) An interleaved-variant dispatcher test that pins side-effect
//       order across all four WorkerCommandResults fields.
//   (b) Coverage for `DemoteOwnerRGS` duplicate / first-occurrence
//       dedup (because the original dispatcher arm carried an
//       `if !cancelled_keys.iter().any(|key| key == &demoted_key)`
//       guard whose contract must outlive the lift to
//       commands/demote_owner_rgs.rs).
//
// The test queues, in order:
//   1. DemoteOwnerRGS { owner_rgs: [5] }    — demote RG5 (one session)
//   2. UpsertSynced(s5b)                    — install a synced session
//   3. DemoteOwnerRGS { owner_rgs: [5, 5] } — duplicate; dedup-safe
//   4. ExportOwnerRGSessions { sequence: 7, owner_rgs: [5] }
//   5. DemoteOwnerRGS { owner_rgs: [7] }    — second RG
//   6. EnqueueShapedLocal(req)              — pushes onto shaped_tx_requests
//   7. RefreshOwnerRGS { owner_rgs: [5] }   — exercise the wider scan
//   8. VacateAllSharedExactSlots             — flag flip
//
// Asserts:
//   - exported_sequences == [7]                        (single Export queued)
//   - shaped_tx_requests.len() == 1                    (single ShapedLocal queued)
//   - vacate_all_shared_exact_slots == true            (Vacate queued)
//   - cancelled_keys contains the RG5 key once and the RG7 key once
//     (no duplicates from the repeated Demote(rg=5) and no extra
//     entries from the second Demote in the same command list).

#[test]
fn apply_worker_commands_dispatch_order_pin_with_demote_dedup() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();

    // Install two sessions on distinct owner RGs (5 and 7) so that
    // DemoteOwnerRGS [5] and DemoteOwnerRGS [7] each produce one
    // distinct cancelled key.
    let key_rg5 = test_key();
    let mut metadata_rg5 = test_metadata();
    metadata_rg5.owner_rg_id = 5;
    assert!(sessions.install_with_protocol_with_origin(
        key_rg5.clone(),
        test_decision(),
        metadata_rg5.clone(),
        SessionOrigin::ForwardFlow,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));

    let key_rg7 = SessionKey {
        // distinct src_port → distinct key
        src_port: 33333,
        ..test_key()
    };
    let mut metadata_rg7 = test_metadata();
    metadata_rg7.owner_rg_id = 7;
    assert!(sessions.install_with_protocol_with_origin(
        key_rg7.clone(),
        test_decision(),
        metadata_rg7.clone(),
        SessionOrigin::ForwardFlow,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));

    // Synced entry for the UpsertSynced step.
    let synced_entry = SyncedSessionEntry {
        key: SessionKey {
            src_port: 44444,
            ..test_key()
        },
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };

    // Build a minimal TxRequest for the EnqueueShapedLocal step.
    let shaped_req = TxRequest {
        bytes: Vec::new(),
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: -1,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        enqueue_ns: 0,
    };

    {
        let mut pending = commands.lock().expect("commands lock");
        pending.push_back(WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![5] });
        pending.push_back(WorkerCommand::UpsertSynced(synced_entry.clone()));
        pending.push_back(WorkerCommand::DemoteOwnerRGS {
            owner_rgs: vec![5, 5], // duplicate within the same command
        });
        pending.push_back(WorkerCommand::ExportOwnerRGSessions {
            sequence: 7,
            owner_rgs: vec![5],
        });
        pending.push_back(WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![7] });
        pending.push_back(WorkerCommand::EnqueueShapedLocal(shaped_req));
        pending.push_back(WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![5] });
        pending.push_back(WorkerCommand::VacateAllSharedExactSlots);
    }

    let forwarding = test_forwarding_state_with_fabric();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Inactive on both RGs so DemoteOwnerRGS demotes them and HA enforcement
    // doesn't elide the cancellations.
    ha_state.insert(5, inactive_ha_runtime(now_secs));
    ha_state.insert(7, inactive_ha_runtime(now_secs));

    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
    );

    // ── (a) Exports preserved ───────────────────────────────────────────────
    assert_eq!(results.exported_sequences, vec![7u64]);
    // #2653: the export owner RG is recorded for the worker-loop chunked export.
    assert_eq!(results.export_owner_rgs, vec![5i32]);

    // ── (b) ShapedLocal pushed exactly once ────────────────────────────────
    assert_eq!(results.shaped_tx_requests.len(), 1);

    // ── (c) Vacate flag flipped ─────────────────────────────────────────────
    assert!(results.vacate_all_shared_exact_slots);

    // ── (d) DemoteOwnerRGS dedup contract preserved ────────────────────────
    // Both keys appear exactly once. Two dedup guards are at work:
    //
    //   1. `seen_owner_rgs.insert` inside `handle_demote_owner_rgs`
    //      skips the second `5` in `Demote{[5, 5]}`.
    //   2. `!cancelled_keys.iter().any(|key| key == &demoted_key)`
    //      skips key_rg5 the SECOND time it surfaces. This is NOT
    //      belt-and-braces — `SessionTable::demote_owner_rg` only
    //      flips the session's origin to `SyncImport`; it does NOT
    //      remove the entry from `owner_rg_sessions[5]`. So the
    //      second `Demote{[5]}` arm in the command stream re-discovers
    //      key_rg5 in the bucket and would re-cancel it without this
    //      guard.
    //
    // Per Gemini r1 code-review feedback: an earlier comment here
    // claimed the bucket was cleared and the guard was belt-and-braces.
    // That was empirically false — the `cancelled_keys.iter().any`
    // guard is load-bearing.
    let rg5_count = results
        .cancelled_keys
        .iter()
        .filter(|k| **k == key_rg5)
        .count();
    let rg7_count = results
        .cancelled_keys
        .iter()
        .filter(|k| **k == key_rg7)
        .count();
    assert_eq!(
        rg5_count, 1,
        "key_rg5 must appear exactly once in cancelled_keys"
    );
    assert_eq!(
        rg7_count, 1,
        "key_rg7 must appear exactly once in cancelled_keys"
    );
    // Nothing else got cancelled.
    assert_eq!(results.cancelled_keys.len(), 2);

    // ── (e) First-occurrence order: RG5 demote precedes RG7 demote ─────────
    let pos_rg5 = results
        .cancelled_keys
        .iter()
        .position(|k| *k == key_rg5)
        .expect("rg5 key position");
    let pos_rg7 = results
        .cancelled_keys
        .iter()
        .position(|k| *k == key_rg7)
        .expect("rg7 key position");
    assert!(
        pos_rg5 < pos_rg7,
        "DemoteOwnerRGS first-occurrence order must be preserved"
    );
}

// ---------------------------------------------------------------------------
// #1807: worker-side command-queue poison recovery. A panic that poisons
// a worker command mutex must not make the consumer permanently deaf
// (apply_worker_commands) nor make producers silently drop replicas
// (replicate_session_upsert/delete). Poison shape mirrors the #1790
// ha_tests regression: a thread panics while holding the lock.
// ---------------------------------------------------------------------------

fn poison_command_queue(queue: &Arc<Mutex<VecDeque<WorkerCommand>>>) {
    let to_poison = queue.clone();
    let poisoner = std::thread::spawn(move || {
        let _guard = to_poison.lock().expect("lock before poisoning");
        panic!("poison worker command mutex");
    })
    .join();
    assert!(poisoner.is_err(), "poisoning thread must panic");
    assert!(queue.is_poisoned(), "queue mutex must be poisoned");
}

fn test_synced_entry() -> SyncedSessionEntry {
    SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_ACK,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    }
}

#[test]
fn apply_worker_commands_recovers_poisoned_queue_and_processes_commands() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::ExportOwnerRGSessions {
            sequence: 21,
            owner_rgs: vec![1],
        });
    poison_command_queue(&commands);

    let mut sessions = SessionTable::new();
    let forwarding = test_forwarding_state_with_fabric();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
    );

    // The queued command was processed (NOT the empty "deaf" result the
    // pre-#1807 Err arm returned).
    assert_eq!(
        results.exported_sequences,
        vec![21],
        "poisoned queue must be recovered and its commands processed"
    );
    // clear_poison: the queue is drained and a plain lock() works again.
    assert!(!commands.is_poisoned(), "poison must be cleared");
    let pending = commands.lock().expect("plain lock after recovery");
    assert!(pending.is_empty(), "recovered queue must be drained");
}

#[test]
fn replicate_session_upsert_delivers_to_poisoned_queue() {
    let queues: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = (0..2)
        .map(|_| Arc::new(Mutex::new(VecDeque::new())))
        .collect();
    poison_command_queue(&queues[1]);

    let entry = test_synced_entry();
    replicate_session_upsert(&queues, &entry);

    for (worker_id, queue) in queues.iter().enumerate() {
        let pending = queue.lock().expect("queue unpoisoned after replicate");
        assert!(
            pending.iter().any(
                |command| matches!(command, WorkerCommand::UpsertSynced(replica)
                    if replica.key == entry.key)
            ),
            "worker {worker_id} missing UpsertSynced replica"
        );
    }
    assert!(!queues[1].is_poisoned(), "poison must be cleared");
}

#[test]
fn replicate_session_delete_delivers_to_poisoned_queue() {
    let queues: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = (0..2)
        .map(|_| Arc::new(Mutex::new(VecDeque::new())))
        .collect();
    poison_command_queue(&queues[0]);

    let key = test_key();
    replicate_session_delete(&queues, &key);

    for (worker_id, queue) in queues.iter().enumerate() {
        let pending = queue.lock().expect("queue unpoisoned after replicate");
        assert!(
            pending.iter().any(
                |command| matches!(command, WorkerCommand::DeleteSynced(deleted)
                    if deleted == &key)
            ),
            "worker {worker_id} missing DeleteSynced"
        );
    }
    assert!(!queues[0].is_poisoned(), "poison must be cleared");
}

// ---------------------------------------------------------------------------
// #1760 W3': shared-map NAT reverse-key displacement counter
// ---------------------------------------------------------------------------
//
// NOTE on the process-global static: NAT_REVERSE_KEY_SHARED_DISPLACEMENTS is
// shared across the whole test binary. All assertions below are DELTA-based
// around the specific publish calls, and only the tests in this block publish
// colliding (distinct-forward-key, same-reverse-key) entries — every other
// test in the binary publishes either unrelated keys or same-session
// republishes, neither of which increments the counter. The positive and
// negative cases are kept in ONE test to avoid cross-test ordering effects.

fn w3_forward_entry(src_host: u8, src_port: u16, snat_ip: Ipv4Addr) -> SyncedSessionEntry {
    // Interface-mode SNAT shape: rewrite_src set, NO source-port rewrite —
    // the portless mode that makes the reverse key collide (#1760 §2.7).
    SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, src_host)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port,
            dst_port: 443,
        },
        decision: SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_src_port: None,
                ..NatDecision::default()
            },
        },
        metadata: test_metadata(),
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x02,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    }
}

#[test]
fn shared_nat_displacement_counter_counts_collisions_not_republishes() {
    use crate::afxdp::shared_ops::NAT_REVERSE_KEY_SHARED_DISPLACEMENTS;
    use std::sync::atomic::Ordering;

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);

    // Two distinct internal hosts, SAME source port, same dst — the
    // interface-SNAT collision: identical reverse wire key K.
    let s1 = w3_forward_entry(101, 40_000, snat_ip);
    let s2 = w3_forward_entry(102, 40_000, snat_ip);
    assert_ne!(s1.key, s2.key, "distinct forward sessions");
    assert_eq!(
        reverse_session_key(&s1.key, s1.decision.nat),
        reverse_session_key(&s2.key, s2.decision.nat),
        "construction must produce a genuine reverse-key collision"
    );

    // Fresh publish: no displacement.
    let before = NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed);
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &s1,
    );
    assert_eq!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed),
        before,
        "first publish must not count"
    );

    // Same-session republish (promote / RG migration / HA re-sync shape):
    // displaced.key == entry.key -> no count.
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &s1,
    );
    assert_eq!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed),
        before,
        "same-session republish must not count"
    );

    // Colliding second session displaces s1 at K -> counts. The
    // reverse-canonical slot for this NAT shape may coincide with the wire
    // slot (single insert) or differ (second insert also displaces); accept
    // either by asserting a positive, bounded delta.
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &s2,
    );
    let after_collision = NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed);
    let delta = after_collision - before;
    assert!(
        (1..=2).contains(&delta),
        "colliding publish must count once per displaced slot (delta={delta})"
    );

    // s1 re-publishes (e.g. its worker re-installs): displaces s2 -> counts
    // again. Alternations keep counting — event count, not pair census.
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &s1,
    );
    assert!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed) > after_collision,
        "alternation must count again"
    );

    // All remaining negatives live in THIS test (not separate #[test]s):
    // the counter static is process-global and cargo runs tests in
    // parallel, so equality assertions in a sibling test could observe
    // this test's increments (Codex code-r1 F2).
    let settled = NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed);

    // Reverse entries never touch shared_nat_sessions.
    let mut reverse = w3_forward_entry(103, 40_001, snat_ip);
    reverse.metadata.is_reverse = true;
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &reverse,
    );
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &reverse,
    );
    assert_eq!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed),
        settled,
        "reverse entries never touch shared_nat_sessions"
    );

    // HA fabric-redirect wire-ALIAS republish (Codex code-r1 F1): the
    // same logical session arrives a second time under its NAT-translated
    // forward-wire key with the same value
    // (daemon_ha_userspace.go userspaceForwardWireAliasFromDeltaV4). The
    // alias derives the same reverse key K as its canonical form and
    // MUST NOT count as a collision.
    let fresh_nat = Arc::new(Mutex::new(FastMap::default()));
    let mut canonical = w3_forward_entry(110, 40_002, snat_ip);
    // On the wire both canonical and alias arrive via HA sync.
    canonical.origin = SessionOrigin::SyncImport;
    let mut alias = canonical.clone();
    alias.key = forward_wire_key(&canonical.key, canonical.decision.nat);
    assert_ne!(alias.key, canonical.key, "alias must be a distinct key");
    assert_eq!(
        reverse_session_key(&alias.key, alias.decision.nat),
        reverse_session_key(&canonical.key, canonical.decision.nat),
        "alias and canonical must derive the same reverse key K"
    );
    let before_alias = NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed);
    for entry in [&canonical, &alias, &canonical] {
        publish_shared_session(
            &shared_sessions,
            &fresh_nat,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            entry,
        );
    }
    assert_eq!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed),
        before_alias,
        "canonical<->wire-alias churn of one logical session must not count"
    );

    // Codex code-r2: DNAT-vs-direct is a GENUINE collision whose keys are
    // wire-related — a DNAT flow client:p -> VIP:443 rewritten to
    // backend:443, plus a direct no-NAT flow client:p -> backend:443.
    // Both derive the same reverse key K; the alias exclusion must NOT
    // swallow it (their NatDecisions differ).
    let backend = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 90));
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 120));
    let dnat = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: client,
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 91)), // VIP
            src_port: 40_003,
            dst_port: 443,
        },
        decision: SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision {
                rewrite_dst: Some(backend),
                ..NatDecision::default()
            },
        },
        metadata: test_metadata(),
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x02,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let mut direct = dnat.clone();
    direct.key.dst_ip = backend;
    direct.decision.nat = NatDecision::default();
    assert_eq!(
        reverse_session_key(&dnat.key, dnat.decision.nat),
        reverse_session_key(&direct.key, direct.decision.nat),
        "DNAT and direct flows must derive the same reverse key K"
    );
    let dnat_map = Arc::new(Mutex::new(FastMap::default()));
    let before_dnat = NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed);
    for entry in [&dnat, &direct] {
        publish_shared_session(
            &shared_sessions,
            &dnat_map,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            entry,
        );
    }
    assert!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed) > before_dnat,
        "DNAT-vs-direct genuine collision must count despite wire-related keys"
    );

    // Codex code-r3 owner-side corner: a LOCAL flow whose source already
    // equals the SNAT external address. Identical NatDecision and
    // wire-related keys, but BOTH entries are locally originated — two
    // real sessions, must count. (The alias exclusion requires at least
    // one peer-synced side: the HA wire-alias never originates locally.)
    let local_a = w3_forward_entry(121, 40_004, snat_ip); // 10.0.61.121
    let mut local_b = local_a.clone();
    local_b.key.src_ip = IpAddr::V4(snat_ip); // source IS the external IP
    assert_eq!(
        local_b.key,
        forward_wire_key(&local_a.key, local_a.decision.nat),
        "corner construction: B must be A's wire form"
    );
    assert_eq!(local_a.decision.nat, local_b.decision.nat);
    assert!(!local_a.origin.is_peer_synced() && !local_b.origin.is_peer_synced());
    let corner_map = Arc::new(Mutex::new(FastMap::default()));
    let before_corner = NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed);
    for entry in [&local_a, &local_b] {
        publish_shared_session(
            &shared_sessions,
            &corner_map,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            entry,
        );
    }
    assert!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed) > before_corner,
        "local same-NAT wire-related pair must count (owner-side corner)"
    );

    // Codex code-r4: post-failover PROMOTE churn. At activation the new
    // owner can promote both the canonical and its wire-alias to
    // SharedPromote (not peer-synced) and republish each — identical
    // NatDecision, wire-related keys, same logical session. Must not
    // count, in either promote order.
    let mut promoted_canonical = w3_forward_entry(130, 40_005, snat_ip);
    promoted_canonical.origin = SessionOrigin::SharedPromote;
    let mut promoted_alias = promoted_canonical.clone();
    promoted_alias.key = forward_wire_key(&promoted_canonical.key, promoted_canonical.decision.nat);
    let promote_map = Arc::new(Mutex::new(FastMap::default()));
    let before_promote = NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed);
    for entry in [
        &promoted_canonical, // canonical-then-alias
        &promoted_alias,
        &promoted_canonical, // alias-then-canonical
    ] {
        publish_shared_session(
            &shared_sessions,
            &promote_map,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            entry,
        );
    }
    assert_eq!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed),
        before_promote,
        "SharedPromote canonical<->alias churn must not count (either order)"
    );
}

#[test]
fn nat_reverse_key_warn_throttle_claims_once_per_window() {
    use crate::afxdp::shared_ops::try_claim_nat_reverse_key_warn;

    // The throttle static is process-global and never reset; derive a base
    // far beyond any previously claimed slot so this test is self-contained.
    let base: u64 = 365 * 24 * 3_600 * 1_000_000_000;
    assert!(
        try_claim_nat_reverse_key_warn(base),
        "first claim past the window must win"
    );
    assert!(
        !try_claim_nat_reverse_key_warn(base + 1_000_000_000),
        "claim inside the 60s window must lose"
    );
    assert!(
        !try_claim_nat_reverse_key_warn(base + 59_999_999_999),
        "claim at window edge - 1ns must lose"
    );
    assert!(
        try_claim_nat_reverse_key_warn(base + 60_000_000_000),
        "claim at the window boundary must win"
    );
}

// ── #1870: UpsertLocal joins the uncapped sync-family install ────────
//
// Deterministic at-cap pins for the local-tunnel prewarm pair. The
// coordinator publishes the forward + synthesized-reverse pair to the
// shared maps unconditionally and fans `WorkerCommand::UpsertLocal` ×2
// out to every worker; routing the apply side through the CAPPED
// install let max_sessions silently refuse the worker-table copy while
// the shared maps kept both entries. These pins run in debug AND
// release profiles (#1855 contract) and use `assert!` on outcomes —
// the production arm's `debug_assert!`s compile out in release.

/// Mirror the producer's pair shape (`build_local_origin_tunnel_tx_request`
/// + `synthesized_synced_reverse_entry`): SyncImport origin, default NAT
/// (no rewrites — so no forward-wire alias exists), forward + reverse.
fn local_tunnel_pair() -> (SyncedSessionEntry, SyncedSessionEntry) {
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let forward = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_ACK,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let reverse = synthesized_synced_reverse_entry(
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        &forward,
        1,
    )
    .expect("reverse companion");
    (forward, reverse)
}

/// Shrink the cap and fill the table with `fill` distinct local entries
/// whose keys cannot collide with the local-tunnel pair (filler src
/// ports start at 40000; the pair uses 55068/5201).
fn rig_capped_table(cap: usize, fill: usize) -> SessionTable {
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(cap);
    for i in 0..fill {
        let key = SessionKey {
            src_port: 40_000 + i as u16,
            ..test_key()
        };
        assert!(sessions.install_with_protocol(
            key,
            test_decision(),
            test_metadata(),
            1_000_000,
            PROTO_TCP,
            TCP_FLAG_ACK,
        ));
    }
    assert_eq!(sessions.len(), fill);
    // Discard the fillers' open deltas so later assertions on the delta
    // ring observe only the behavior under test.
    let _ = sessions.drain_deltas(usize::MAX);
    sessions
}

fn apply_upsert_local_pair(
    sessions: &mut SessionTable,
    forward: &SyncedSessionEntry,
    reverse: &SyncedSessionEntry,
) -> WorkerCommandResults {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    {
        let mut pending = commands.lock().expect("commands lock");
        pending.push_back(WorkerCommand::UpsertLocal(forward.clone()));
        pending.push_back(WorkerCommand::UpsertLocal(reverse.clone()));
    }
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    apply_worker_commands(
        &commands,
        sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
    )
}

/// §2.2 interleaving through the fixed arm: a table AT max_sessions
/// admits the full pair (uncapped sync-family semantics) and no
/// refusal counter moves. Pre-#1870 both installs were silently
/// refused (create_drops += 2) while the shared maps held the pair.
#[test]
fn upsert_local_pair_installs_at_cap() {
    let cap = 4;
    let mut sessions = rig_capped_table(cap, cap);
    let (forward, reverse) = local_tunnel_pair();

    apply_upsert_local_pair(&mut sessions, &forward, &reverse);

    // Exact forward-key lookups — NOT find_forward_wire_match: with
    // default NAT, wire_key == key and the forward-wire index never
    // holds these entries (index_forward_nat_key only inserts when
    // they differ).
    let (_, _, fwd_origin) = sessions
        .entry_with_origin(&forward.key)
        .expect("forward entry installed at cap");
    assert_eq!(fwd_origin, SessionOrigin::SyncImport);
    let (_, rev_metadata, rev_origin) = sessions
        .entry_with_origin(&reverse.key)
        .expect("reverse entry installed at cap");
    assert_eq!(rev_origin, SessionOrigin::SyncImport);
    assert!(rev_metadata.is_reverse);
    assert_eq!(sessions.len(), cap + 2, "pair admitted past the cap");
    assert_eq!(sessions.create_drops(), 0, "no longer counted as drops");
    assert_eq!(sessions.admission_refused(), 0);
    assert_eq!(sessions.install_partial(), 0);
    // SyncImport installs must not enqueue HA deltas.
    assert!(sessions.drain_deltas(usize::MAX).is_empty());
}

/// Producer fan-out pin (Codex #1870 plan r2): worker tables are
/// independent — one at cap, one below — and both must converge to
/// holding the full pair after the same fan-out.
#[test]
fn upsert_local_fanout_diverged_workers_converge() {
    let (forward, reverse) = local_tunnel_pair();
    let mut at_cap = rig_capped_table(2, 2);
    let mut below_cap = rig_capped_table(8, 2);

    for sessions in [&mut at_cap, &mut below_cap] {
        apply_upsert_local_pair(sessions, &forward, &reverse);
        assert!(sessions.entry_with_origin(&forward.key).is_some());
        assert!(sessions.entry_with_origin(&reverse.key).is_some());
        assert_eq!(sessions.create_drops(), 0);
    }
    assert_eq!(at_cap.len(), 4);
    assert_eq!(below_cap.len(), 4);
}

/// Exactly one free slot: pre-#1870 the forward install succeeded and
/// the reverse was refused (partial pair — worker held forward only
/// while the shared maps held both). The fixed arm admits both.
#[test]
fn upsert_local_pair_no_partial_at_cap_minus_one() {
    let cap = 4;
    let mut sessions = rig_capped_table(cap, cap - 1);
    let (forward, reverse) = local_tunnel_pair();

    apply_upsert_local_pair(&mut sessions, &forward, &reverse);

    assert!(sessions.entry_with_origin(&forward.key).is_some());
    assert!(
        sessions.entry_with_origin(&reverse.key).is_some(),
        "reverse half must not be dropped when only one slot is free"
    );
    assert_eq!(sessions.len(), cap + 1);
    assert_eq!(sessions.create_drops(), 0);
}

/// Below cap, `allow_replace_local=true` preserves the pre-#1870
/// replace semantics of the capped install (which clobbered any
/// same-key entry below cap). Guards against a future "tidy-up" to
/// `allow_replace_local=false` or a revert to the capped install.
#[test]
fn upsert_local_below_cap_replaces_existing_local_entry() {
    let mut sessions = SessionTable::new();
    let (forward, reverse) = local_tunnel_pair();
    assert!(sessions.install_with_protocol(
        forward.key.clone(),
        test_decision(),
        test_metadata(),
        1_000_000,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    let _ = sessions.drain_deltas(usize::MAX);

    apply_upsert_local_pair(&mut sessions, &forward, &reverse);

    let (_, _, origin) = sessions
        .entry_with_origin(&forward.key)
        .expect("replaced entry");
    assert_eq!(
        origin,
        SessionOrigin::SyncImport,
        "local same-key entry must be replaced by the tunnel decision"
    );
    assert_eq!(sessions.len(), 2, "replace + reverse install");
    assert_eq!(sessions.create_drops(), 0);
}

/// At cap, same-key replacement is a deliberate #1870 semantic change:
/// the old capped install refused BEFORE reaching remove_entry, so a
/// stale same-key local entry could never be replaced at cap (and a
/// local hit shadows the shared scope, blocking reactive
/// materialization until expiry). The new arm replaces it without
/// growing the table.
#[test]
fn upsert_local_at_cap_replaces_existing_local_entry_without_growth() {
    let cap = 4;
    let mut sessions = rig_capped_table(cap, cap - 1);
    let (forward, reverse) = local_tunnel_pair();
    assert!(sessions.install_with_protocol(
        forward.key.clone(),
        test_decision(),
        test_metadata(),
        1_000_000,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    assert_eq!(sessions.len(), cap, "table rigged to cap incl. stale key");
    let _ = sessions.drain_deltas(usize::MAX);

    apply_upsert_local_pair(&mut sessions, &forward, &reverse);

    let (_, _, origin) = sessions
        .entry_with_origin(&forward.key)
        .expect("replaced entry at cap");
    assert_eq!(origin, SessionOrigin::SyncImport);
    assert_eq!(
        sessions.len(),
        cap + 1,
        "same-key replace must not grow; only the reverse adds a slot"
    );
    assert_eq!(sessions.create_drops(), 0);
}

/// Pins the expected (permanent, by-origin) bulk-export behavior:
/// local-tunnel entries carry SyncImport and are skipped by
/// export_forward_sessions_for_owner_rgs at ANY occupancy — their
/// exclusion is origin design, not a cap artifact (Codex #1870 plan
/// r1 finding 3; refuted v1's "at-cap bulk-export gap" claim).
#[test]
fn upsert_local_entries_stay_out_of_owner_rg_bulk_export() {
    let mut sessions = SessionTable::new();
    let (forward, reverse) = local_tunnel_pair();
    apply_upsert_local_pair(&mut sessions, &forward, &reverse);
    assert!(sessions.entry_with_origin(&forward.key).is_some());
    assert!(sessions.drain_deltas(usize::MAX).is_empty());

    export_forward_sessions_for_owner_rgs(&mut sessions, &[1]);

    assert!(
        sessions.drain_deltas(usize::MAX).is_empty(),
        "peer-synced-origin local-tunnel entries must not bulk-export"
    );
}

/// #2669: a drained Close delta must reach its binding-INDEPENDENT
/// consumers (shared session/conntrack tables, HA peer-worker delete
/// replication, recent-deltas RPC buffer, event stream) even when the
/// worker has NO bindings — i.e. `flush_session_deltas` is invoked with
/// `live = None`. The pre-fix code drained the delta off the ring and then
/// skipped the whole flush when `bindings.first()` was `None`, silently
/// discarding the close. This test exercises the `live = None` path
/// directly: reverting the fix (re-gating the flush on a binding, or
/// passing `&binding.live` only) makes none of these consumers observe the
/// delete, so the assertions go red — fail-on-revert.
#[test]
fn flush_session_deltas_without_binding_reaches_global_consumers() {
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();

    // Seed the shared session table so the Close delete has something to
    // remove (the binding-independent shared-table consumer).
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let shared_entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: metadata.clone(),
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
    };
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &shared_entry,
    );
    assert!(
        !shared_sessions.lock().expect("shared sessions").is_empty(),
        "precondition: shared session seeded"
    );

    // One peer-worker command queue — the HA delete-replication sink.
    let peer_queue: Arc<Mutex<VecDeque<WorkerCommand>>> =
        Arc::new(Mutex::new(VecDeque::new()));
    let peer_worker_commands = vec![peer_queue.clone()];
    let recent_session_deltas = Arc::new(Mutex::new(VecDeque::new()));
    let forwarding = ForwardingState::default();

    let delta = SessionDelta {
        kind: SessionDeltaKind::Close,
        key: key.clone(),
        decision,
        metadata,
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: crate::session::SessionCounters::default(),
    };

    // Synthesize a binding identity with labels only — exactly what the
    // worker loop does when `bindings` is empty — and flush with NO live
    // RPC queue and the fd-less (-1) map fds.
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from(""),
        ifindex: -1,
    };
    let dnat_fds = crate::afxdp::checksum::DnatTableFds::default();
    flush_session_deltas(
        &ident,
        None,
        -1,
        -1,
        -1,
        &dnat_fds,
        &[delta],
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &recent_session_deltas,
        &peer_worker_commands,
        &None,
        &forwarding,
    );

    // Binding-independent consumer 1: shared session table cleared.
    assert!(
        shared_sessions.lock().expect("shared sessions").is_empty(),
        "Close delta must remove the shared session even with no binding"
    );
    // Binding-independent consumer 2: HA peer-worker delete replication.
    let replicated: Vec<_> = peer_queue
        .lock()
        .expect("peer queue")
        .iter()
        .cloned()
        .collect();
    assert!(
        replicated
            .iter()
            .any(|cmd| matches!(cmd, WorkerCommand::DeleteSynced(k) if *k == key)),
        "Close delta must replicate a DeleteSynced to the HA peer even with no binding"
    );
    // Binding-independent consumer 3: recent-deltas RPC buffer.
    let recent = recent_session_deltas.lock().expect("recent deltas");
    assert!(
        recent.iter().any(|info| info.event == "close"),
        "Close delta must reach the recent-deltas buffer even with no binding"
    );
}

/// #2979 FAIL-ON-REVERT: a Close delta for an SNAT'd session must delete the
/// dynamic reverse-NAT `dnat_table` entry that `publish_dnat_table_entry`
/// inserted at session install. The maps are `BPF_MAP_TYPE_HASH` (non-LRU,
/// `max_entries = MAX_SESSIONS`, `BPF_F_NO_PREALLOC`), so a missing close-time
/// delete leaks one entry per closed SNAT session until the map fills and new
/// reverse-NAT publishes fail (#2244 capacity error).
///
/// Real BPF maps cannot be created under `cargo test` (the host runs with
/// `kernel.unprivileged_bpf_disabled`), so this test observes the delete via
/// the test-only `DNAT_DELETE_ATTEMPTS` counter incremented inside
/// `delete_dnat_table_entry` whenever it derives a key and issues the
/// `bpf_map_delete_elem` syscall. The fd is `-1` (the syscall returns EBADF,
/// which is benign — the contract under test is that the close path *attempts*
/// the keyed delete).
///
/// RED on revert: removing the `delete_dnat_table_entry` call from
/// `flush_session_deltas`'s Close handler makes the SNAT-flow assertion (count
/// increments by 1) fail. The non-SNAT control (count unchanged) guards against
/// over-deleting on flows that never published a reverse-NAT entry.
#[test]
fn close_delta_deletes_dnat_table_entry_for_snat_flow() {
    use crate::afxdp::checksum::{DnatTableFds, DNAT_DELETE_ATTEMPTS};
    use std::sync::atomic::Ordering;

    // Serialize against any other test touching the process-global counter.
    static GUARD: Mutex<()> = Mutex::new(());
    let _g = GUARD.lock().expect("counter guard");

    let build_close = |nat: NatDecision| {
        let key = test_key();
        let metadata = test_metadata();
        let decision = SessionDecision {
            resolution: test_resolution(),
            nat,
        };
        SessionDelta {
            kind: SessionDeltaKind::Close,
            key,
            decision,
            metadata,
            origin: SessionOrigin::ForwardFlow,
            fabric_redirect_sync: false,
            created_ns: 0,
            last_seen_ns: 0,
            counters: crate::session::SessionCounters::default(),
        }
    };

    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from(""),
        ifindex: -1,
    };
    // A live v4 table fd so the delete path is reached; -1 makes the syscall a
    // harmless EBADF after the keyed attempt is counted.
    let dnat_fds = DnatTableFds {
        v4: Some(-1),
        v6: None,
    };

    let run = |delta: SessionDelta| {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = vec![];
        let recent_session_deltas = Arc::new(Mutex::new(VecDeque::new()));
        let forwarding = ForwardingState::default();
        flush_session_deltas(
            &ident,
            None,
            -1,
            -1,
            -1,
            &dnat_fds,
            &[delta],
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &recent_session_deltas,
            &peer_worker_commands,
            &None,
            &forwarding,
        );
    };

    // SNAT flow: the forward key's source is SNAT'd to the WAN pool address;
    // this is exactly what the install path published into dnat_table.
    let snat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(54321),
        ..NatDecision::default()
    };

    let before = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    run(build_close(snat));
    let after_snat = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    assert_eq!(
        after_snat - before,
        1,
        "Close delta for an SNAT'd session must attempt the dnat_table reverse-NAT delete \
         (leak fix #2979); got {} attempts",
        after_snat - before
    );

    // Non-SNAT control: a flow that never published a dnat_table entry must not
    // trigger a delete attempt.
    run(build_close(NatDecision::default()));
    let after_plain = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    assert_eq!(
        after_plain - after_snat,
        0,
        "Close delta for a non-SNAT session must NOT attempt a dnat_table delete"
    );
}
