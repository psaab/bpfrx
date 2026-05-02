// Tests for afxdp/ha.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep ha.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "ha_tests.rs"]` from ha.rs.

use super::*;
use crate::test_zone_ids::*;

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
fn demoted_owner_rgs_detects_active_to_inactive_transitions() {
    let previous = BTreeMap::from([(1, active_ha_runtime(11)), (2, active_ha_runtime(12))]);
    let current = BTreeMap::from([(1, inactive_ha_runtime(21)), (2, active_ha_runtime(22))]);

    assert_eq!(demoted_owner_rgs(&previous, &current), vec![1]);
}

#[test]
fn activated_owner_rgs_detects_inactive_to_active_transitions() {
    let previous = BTreeMap::from([(1, inactive_ha_runtime(11)), (2, active_ha_runtime(12))]);
    let current = BTreeMap::from([(1, active_ha_runtime(21)), (2, active_ha_runtime(22))]);

    assert_eq!(activated_owner_rgs(&previous, &current), vec![1]);
}

#[test]
fn update_ha_state_seeds_lease_for_active_group_without_watchdog() {
    let coordinator = Coordinator::new();
    let before = monotonic_nanos() / 1_000_000_000;

    coordinator
        .update_ha_state(&[HAGroupStatus {
            rg_id: 1,
            active: true,
            watchdog_timestamp: 0,
            ..HAGroupStatus::default()
        }])
        .expect("update ha state");

    let after = monotonic_nanos() / 1_000_000_000;
    let state = coordinator.ha.rg_runtime.load();
    let group = state.get(&1).expect("ha group");
    assert!(group.active);
    assert_eq!(group.watchdog_timestamp, 0);
    assert!(matches!(group.lease, HAForwardingLease::ActiveUntil(until)
            if until >= before + HA_WATCHDOG_STALE_AFTER_SECS
                && until <= after + HA_WATCHDOG_STALE_AFTER_SECS));
    assert!(group.is_forwarding_active(after));
}

#[test]
fn ha_groups_reports_forwarding_lease_status() {
    let coordinator = Coordinator::new();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    coordinator.ha.rg_runtime.store(Arc::new(BTreeMap::from([
        (1, active_ha_runtime(now_secs)),
        (2, inactive_ha_runtime(0)),
    ])));

    let groups = coordinator.ha_groups();

    assert!(groups.iter().any(|group| {
        group.rg_id == 1
            && group.active
            && group.forwarding_active
            && group.lease_state == "active"
            && group.lease_until >= now_secs
    }));
    assert!(groups.iter().any(|group| {
        group.rg_id == 2
            && !group.active
            && !group.forwarding_active
            && group.lease_state == "inactive"
            && group.lease_until == 0
    }));
}

#[test]
fn immediate_synced_bpf_programming_skips_locally_active_owner_rg() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);

    assert!(!synced_entry_allows_local_replace(&state, 1, now_secs));
}

#[test]
fn immediate_synced_bpf_programming_skips_unknown_owner_when_any_rg_is_active() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);

    assert!(!synced_entry_allows_local_replace(&state, 0, now_secs));
}

#[test]
fn immediate_synced_bpf_programming_allows_inactive_owner_rg() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);

    assert!(synced_entry_allows_local_replace(&state, 1, now_secs));
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

fn test_decision() -> SessionDecision {
    SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision::default(),
    }
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

fn test_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        owner_rg_id: 1,
        fabric_ingress: true,
        is_reverse: false,
        nat64_reverse: None,
    }
}

fn test_forwarding_state_with_fabric() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(10, 0, 61, 0), 24).unwrap()),
        ifindex: 6,
        tunnel_endpoint_id: 0,
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
    forwarding.zone_name_to_id.insert("lan".to_string(), 1);
    forwarding.zone_name_to_id.insert("sfmix".to_string(), 2);
    forwarding.zone_name_to_id.insert("wan".to_string(), 3);
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

#[test]
fn update_ha_state_prewarms_split_rg_reverse_sessions_on_activation() {
    let mut coordinator = Coordinator::new();
    coordinator.forwarding = test_forwarding_state_split_rgs();
    let worker_commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.handles.insert(
        0,
        WorkerHandle {
            stop: Arc::new(AtomicBool::new(false)),
            heartbeat: Arc::new(AtomicU64::new(0)),
            commands: worker_commands.clone(),
            session_export_ack: Arc::new(AtomicU64::new(0)),
            cos_status: Arc::new(ArcSwap::from_pointee(Vec::new())),
            runtime_atomics: Arc::new(super::worker_runtime::WorkerRuntimeAtomics::new()),
            join: None,
        },
    );

    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
    };
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry,
    );
    refresh_reverse_prewarm_owner_rg_indexes(
        &coordinator
            .sessions
            .owner_rg_indexes
            .reverse_prewarm_sessions,
        &coordinator.forwarding,
        coordinator.dynamic_neighbors_ref(),
        None,
        Some(&entry),
    );

    coordinator
        .update_ha_state(&[
            HAGroupStatus {
                rg_id: 1,
                active: false,
                ..HAGroupStatus::default()
            },
            HAGroupStatus {
                rg_id: 2,
                active: true,
                ..HAGroupStatus::default()
            },
        ])
        .expect("seed initial HA state");
    worker_commands.lock().expect("commands").clear();

    coordinator
        .update_ha_state(&[
            HAGroupStatus {
                rg_id: 1,
                active: true,
                ..HAGroupStatus::default()
            },
            HAGroupStatus {
                rg_id: 2,
                active: true,
                ..HAGroupStatus::default()
            },
        ])
        .expect("activate rg1");

    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = coordinator
        .sessions
        .synced
        .lock()
        .expect("shared sessions")
        .get(&reverse_key)
        .cloned()
        .expect("reverse entry");
    assert!(reverse.metadata.is_reverse);
    assert_eq!(reverse.metadata.owner_rg_id, 2);
    let commands = worker_commands.lock().expect("commands");
    assert_eq!(commands.len(), 3);
    assert!(matches!(
        commands.front(),
        Some(WorkerCommand::RefreshOwnerRGS { owner_rgs }) if owner_rgs == &vec![1]
    ));
    assert!(commands.iter().any(|command| matches!(
        command,
        WorkerCommand::UpsertSynced(session)
            if session.metadata.is_reverse && session.metadata.owner_rg_id == 2
    )));
}
