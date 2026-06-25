// Tests for afxdp/coordinator/mod.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep mod.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tests.rs"]` from coordinator/mod.rs.

use super::*;
use crate::INJECT_PACKET_TUPLE_PROTOCOL_VERSION;
use crate::test_zone_ids::*;
use crate::{
    ClassOfServiceSnapshot, CoSForwardingClassSnapshot, CoSSchedulerMapEntrySnapshot,
    CoSSchedulerMapSnapshot,
};

#[test]
fn stamp_injected_packet_tuple_builds_ipv4_icmp_flow_key() {
    let mut meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: 0,
        ..UserspaceDpMeta::default()
    };
    let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    let req = InjectPacketRequest {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        destination_ip: "172.16.80.200".into(),
        tuple_metadata_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
        source_ip: "172.16.80.8".into(),
        source_port: Some(0x1234),
        destination_port: Some(0),
        ..Default::default()
    };
    let tuple = inject::validate_injected_packet_tuple(&req, dst).expect("validate tuple");
    let egress = EgressInterface {
        bind_ifindex: 12,
        vlan_id: 0,
        mtu: 1500,
        src_mac: [0; 6],
        zone_id: TEST_WAN_ZONE_ID,
        redundancy_group: 0,
        primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
        primary_v6: None,
    };

    inject::stamp_injected_packet_tuple(&mut meta, 98, tuple, &egress).expect("stamp tuple");

    let flow = parse_session_flow_from_meta(meta).expect("metadata flow");
    assert_eq!(meta.protocol, PROTO_ICMP);
    assert_eq!(meta.l3_offset, 14);
    assert_eq!(meta.l4_offset, 34);
    assert_eq!(meta.payload_offset, 42);
    assert_eq!(
        flow.forward_key.src_ip,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))
    );
    assert_eq!(
        flow.forward_key.dst_ip,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))
    );
    assert_eq!(flow.forward_key.src_port, 0x1234);
    assert_eq!(flow.forward_key.dst_port, 0);
}

#[test]
fn stamp_injected_packet_tuple_builds_ipv6_icmp_flow_key() {
    let mut meta = UserspaceDpMeta {
        addr_family: libc::AF_INET6 as u8,
        protocol: 0,
        ..UserspaceDpMeta::default()
    };
    let src = "2001:db8:80::8".parse::<Ipv6Addr>().unwrap();
    let dst = "2001:db8:80::200".parse::<Ipv6Addr>().unwrap();
    let req = InjectPacketRequest {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        destination_ip: "2001:db8:80::200".into(),
        tuple_metadata_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
        source_ip: "2001:db8:80::8".into(),
        source_port: Some(0x4321),
        destination_port: Some(0),
        ..Default::default()
    };
    let tuple =
        inject::validate_injected_packet_tuple(&req, IpAddr::V6(dst)).expect("validate tuple");
    let egress = EgressInterface {
        bind_ifindex: 12,
        vlan_id: 80,
        mtu: 1500,
        src_mac: [0; 6],
        zone_id: TEST_WAN_ZONE_ID,
        redundancy_group: 0,
        primary_v4: None,
        primary_v6: Some(src),
    };

    inject::stamp_injected_packet_tuple(&mut meta, 118, tuple, &egress).expect("stamp tuple");

    let flow = parse_session_flow_from_meta(meta).expect("metadata flow");
    assert_eq!(meta.protocol, PROTO_ICMPV6);
    assert_eq!(meta.l3_offset, 18);
    assert_eq!(meta.l4_offset, 58);
    assert_eq!(meta.payload_offset, 66);
    assert_eq!(flow.forward_key.src_ip, IpAddr::V6(src));
    assert_eq!(flow.forward_key.dst_ip, IpAddr::V6(dst));
    assert_eq!(flow.forward_key.src_port, 0x4321);
    assert_eq!(flow.forward_key.dst_port, 0);
}

#[test]
fn validate_injected_packet_tuple_rejects_legacy_wire_request() {
    let req = InjectPacketRequest {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        destination_ip: "172.16.80.200".into(),
        source_ip: "172.16.80.8".into(),
        source_port: Some(0x1234),
        destination_port: Some(0),
        ..Default::default()
    };

    let err =
        inject::validate_injected_packet_tuple(&req, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)))
            .expect_err("legacy request must fail closed");
    assert!(err.contains("tuple metadata version"), "{err}");
}

#[test]
fn validate_injected_packet_tuple_rejects_protocol_mismatch() {
    let req = InjectPacketRequest {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        destination_ip: "172.16.80.200".into(),
        tuple_metadata_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
        source_ip: "172.16.80.8".into(),
        source_port: Some(0x1234),
        destination_port: Some(0),
        ..Default::default()
    };

    let err =
        inject::validate_injected_packet_tuple(&req, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)))
            .expect_err("non-ICMP tuple must fail closed");
    assert!(err.contains("supports only protocol"), "{err}");
}

#[test]
fn build_injected_packet_uses_wire_tuple_source_ipv4() {
    let req = InjectPacketRequest {
        packet_length: 98,
        ..Default::default()
    };
    let src = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8));
    let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    let egress = EgressInterface {
        bind_ifindex: 12,
        vlan_id: 0,
        mtu: 1500,
        src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
        zone_id: TEST_WAN_ZONE_ID,
        redundancy_group: 0,
        primary_v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
        primary_v6: None,
    };
    let resolution = ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 80,
        tx_ifindex: 80,
        tunnel_endpoint_id: 0,
        next_hop: Some(dst),
        neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
        src_mac: Some(egress.src_mac),
        tx_vlan_id: 0,
    };

    let frame = build_injected_packet(&req, src, dst, 0x3456, resolution, &egress)
        .expect("build injected packet");

    assert_eq!(&frame[26..30], &[172, 16, 80, 8]);
    assert_eq!(&frame[30..34], &[172, 16, 80, 200]);
    assert_eq!(&frame[38..40], &0x3456u16.to_be_bytes());
}

#[test]
fn build_cos_owner_worker_by_queue_prefers_lowest_worker_with_tx_binding() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 1_000_000,
            burst_bytes: 64 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );
    let worker_binding_ifindexes = BTreeMap::from([
        (2, std::collections::BTreeSet::from([12])),
        (7, std::collections::BTreeSet::from([12, 13])),
    ]);

    let owner_by_queue = build_cos_owner_worker_by_queue_from_binding_ifindexes(
        &forwarding,
        &worker_binding_ifindexes,
    );

    assert_eq!(owner_by_queue.get(&(80, 0)), Some(&2));
}

#[test]
fn build_cos_owner_worker_by_queue_spreads_queues_across_eligible_workers() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 1_000_000,
            burst_bytes: 64 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
                CoSQueueConfig {
                    queue_id: 1,
                    forwarding_class: "af11".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
                CoSQueueConfig {
                    queue_id: 2,
                    forwarding_class: "af12".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
            ],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );
    let worker_binding_ifindexes = BTreeMap::from([
        (2, std::collections::BTreeSet::from([12])),
        (7, std::collections::BTreeSet::from([12])),
    ]);

    let owner_by_queue = build_cos_owner_worker_by_queue_from_binding_ifindexes(
        &forwarding,
        &worker_binding_ifindexes,
    );

    assert_eq!(owner_by_queue.get(&(80, 0)), Some(&2));
    assert_eq!(owner_by_queue.get(&(80, 1)), Some(&7));
    assert_eq!(owner_by_queue.get(&(80, 2)), Some(&2));
}

#[test]
fn build_cos_owner_worker_by_queue_prefers_ready_workers_when_available() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 1_000_000,
            burst_bytes: 64 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
                CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    guarantee_enabled: true,
                    exact: true,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
            ],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );

    let owner_by_queue = build_cos_owner_worker_by_queue_with_fallback_ifindexes(
        &forwarding,
        &BTreeMap::from([(7, std::collections::BTreeSet::from([12]))]),
        &BTreeMap::from([
            (2, std::collections::BTreeSet::from([12])),
            (7, std::collections::BTreeSet::from([12])),
        ]),
    );

    assert_eq!(owner_by_queue.get(&(80, 0)), Some(&7));
    assert_eq!(owner_by_queue.get(&(80, 4)), Some(&7));
}

#[test]
fn build_cos_owner_worker_by_queue_falls_back_when_no_ready_workers_exist() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 1_000_000,
            burst_bytes: 64 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );

    let owner_by_queue = build_cos_owner_worker_by_queue_with_fallback_ifindexes(
        &forwarding,
        &BTreeMap::new(),
        &BTreeMap::from([(2, std::collections::BTreeSet::from([12]))]),
    );

    assert_eq!(owner_by_queue.get(&(80, 0)), Some(&2));
}

#[test]
fn build_worker_binding_ifindexes_from_identities_groups_by_worker() {
    let identities = BTreeMap::from([
        (
            10,
            BindingIdentity {
                slot: 10,
                queue_id: 0,
                worker_id: 2,
                interface: "ge-0-0-2".into(),
                ifindex: 12,
            },
        ),
        (
            11,
            BindingIdentity {
                slot: 11,
                queue_id: 1,
                worker_id: 2,
                interface: "ge-0-0-2".into(),
                ifindex: 12,
            },
        ),
        (
            20,
            BindingIdentity {
                slot: 20,
                queue_id: 0,
                worker_id: 7,
                interface: "ge-0-0-3".into(),
                ifindex: 13,
            },
        ),
    ]);

    let worker_binding_ifindexes = build_worker_binding_ifindexes_from_identities(&identities);

    assert_eq!(
        worker_binding_ifindexes.get(&2),
        Some(&std::collections::BTreeSet::from([12]))
    );
    assert_eq!(
        worker_binding_ifindexes.get(&7),
        Some(&std::collections::BTreeSet::from([13]))
    );
}

#[test]
fn refresh_runtime_snapshot_rebuilds_cos_owner_worker_map_from_identities() {
    let mut coordinator = Coordinator::new();
    coordinator.workers.identities.insert(
        1,
        BindingIdentity {
            slot: 1,
            queue_id: 0,
            worker_id: 2,
            interface: "ge-0-0-2".into(),
            ifindex: 12,
        },
    );
    coordinator.workers.identities.insert(
        2,
        BindingIdentity {
            slot: 2,
            queue_id: 0,
            worker_id: 7,
            interface: "ge-0-0-3".into(),
            ifindex: 13,
        },
    );

    let mut snapshot = ConfigSnapshot::default();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 80,
        parent_ifindex: 12,
        hardware_addr: "02:00:00:00:00:80".into(),
        cos_shaping_rate_bytes_per_sec: 1_000_000,
        cos_scheduler_map: "wan-map".into(),
        ..Default::default()
    });
    snapshot.class_of_service = Some(ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".into(),
            queue: 0,
        }],
        schedulers: vec![],
        scheduler_maps: vec![CoSSchedulerMapSnapshot {
            name: "wan-map".into(),
            entries: vec![CoSSchedulerMapEntrySnapshot {
                forwarding_class: "best-effort".into(),
                scheduler: String::new(),
            }],
        }],
        dscp_classifiers: vec![],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![],
    });

    coordinator.refresh_runtime_snapshot(&snapshot);

    assert_eq!(
        coordinator.cos_owner_worker_by_queue.get(&(80, 0)),
        Some(&2)
    );
    let shared = coordinator.cos.owner_worker_by_queue.load();
    assert_eq!(shared.get(&(80, 0)), Some(&2));
}

#[test]
fn build_shared_cos_root_leases_uses_active_workers_per_interface() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 100_000_000,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 50_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
                CoSQueueConfig {
                    queue_id: 1,
                    forwarding_class: "af11".into(),
                    priority: 5,
                    transmit_rate_bytes: 50_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
            ],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    let active_shards_by_egress_ifindex = BTreeMap::from([(80, 2usize)]);

    let leases = build_shared_cos_root_leases(&forwarding, &active_shards_by_egress_ifindex);
    let lease = leases.get(&80).expect("shared root lease");

    // The root lease budget must scale with active_shards: total
    // grantable = lease_bytes * active_shards. That is the actual
    // invariant this test pins. Drive it by reading active_shards
    // from the fixture (so the assertion does not silently decouple
    // from the setup) and drain the budget with fixed-size requests
    // plus a tail remainder for whatever the budget does not cleanly
    // divide by — lease_bytes is a function of shaping rate and
    // COS_ROOT_LEASE_TARGET_US, both of which are tuning knobs, so
    // an exact-divisibility assertion would make this test brittle
    // against legitimate scheduler tuning.
    let active_shards = *active_shards_by_egress_ifindex
        .get(&80)
        .expect("active shards configured for egress ifindex 80") as u64;
    let lease_bytes = lease.lease_bytes();
    let expected_total = lease_bytes * active_shards;
    let per_request = 2500u64;

    let mut remaining = expected_total;
    let mut total = 0u64;
    while remaining > 0 {
        let req = remaining.min(per_request);
        let granted = lease.acquire(1, req);
        assert_eq!(
            granted, req,
            "root lease must grant the full request while budget remains",
        );
        total += granted;
        remaining -= granted;
    }
    assert_eq!(total, expected_total);
    // Budget fully drained — any further acquire must return 0.
    assert_eq!(lease.acquire(1, 1), 0);
}

#[test]
fn build_shared_cos_root_leases_reuses_existing_matching_lease_arc() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 100_000_000,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 100_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    let active_shards_by_egress_ifindex = BTreeMap::from([(80, 1usize)]);

    let existing = build_shared_cos_root_leases(&forwarding, &active_shards_by_egress_ifindex);
    let reused = build_shared_cos_root_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        &existing,
    );

    assert!(Arc::ptr_eq(
        existing.get(&80).expect("existing lease"),
        reused.get(&80).expect("reused lease")
    ));
}

#[test]
fn build_shared_cos_queue_leases_reuses_existing_matching_lease_arc() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 100_000_000,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 50_000_000,
                guarantee_enabled: true,
                exact: true,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    let active_shards_by_egress_ifindex = BTreeMap::from([(80, 2usize)]);

    let existing = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        2,
        &BTreeMap::new(),
    );
    let reused = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        2,
        &existing,
    );

    assert!(Arc::ptr_eq(
        existing.get(&(80, 4)).expect("existing queue lease"),
        reused.get(&(80, 4)).expect("reused queue lease")
    ));
}

#[test]
fn build_shared_cos_queue_leases_rebuilds_when_equal_flow_mode_toggles() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 100_000_000,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 50_000_000,
                guarantee_enabled: true,
                exact: true,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    let active_shards_by_egress_ifindex = BTreeMap::from([(80, 2usize)]);

    let existing = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        2,
        &BTreeMap::new(),
    );
    forwarding
        .cos
        .interfaces
        .get_mut(&80)
        .expect("iface")
        .queues[0]
        .equal_flow_enforcement = true;
    let rebuilt = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        2,
        &existing,
    );

    let old = existing.get(&(80, 4)).expect("existing queue lease");
    let new = rebuilt.get(&(80, 4)).expect("rebuilt queue lease");
    assert!(
        !Arc::ptr_eq(old, new),
        "equal-flow mode toggle must rebuild the lease Arc"
    );
    assert!(new.v8_equal_flow_active());
}

/// #1746 F3: a live `equal-flow-target-policy` edit (slowest -> mean)
/// must rebuild the lease Arc — `matches_config_v8` includes the
/// policy, so a stale lease cannot keep publishing with the old
/// target math. Same-policy rebuild input must still reuse.
#[test]
fn build_shared_cos_queue_leases_rebuilds_when_equal_flow_target_policy_changes() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 100_000_000,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 50_000_000,
                guarantee_enabled: true,
                exact: true,
                surplus_sharing: false,
                equal_flow_enforcement: true,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
                codel_target_ns: 0,
            }],
            oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
            oversubscription_guarantee_fraction: 0.0,
            priority_low_min_share_bytes: 0,
        },
    );
    let active_shards_by_egress_ifindex = BTreeMap::from([(80, 2usize)]);

    let existing = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        2,
        &BTreeMap::new(),
    );

    // Same config -> reuse (no policy change).
    let reused = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        2,
        &existing,
    );
    assert!(Arc::ptr_eq(
        existing.get(&(80, 4)).expect("existing queue lease"),
        reused.get(&(80, 4)).expect("reused queue lease")
    ));

    // Policy edit -> rebuild.
    forwarding
        .cos
        .interfaces
        .get_mut(&80)
        .expect("iface")
        .queues[0]
        .equal_flow_target_policy = EqualFlowTargetPolicy::Mean;
    let rebuilt = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        2,
        &existing,
    );
    let old = existing.get(&(80, 4)).expect("existing queue lease");
    let new = rebuilt.get(&(80, 4)).expect("rebuilt queue lease");
    assert!(
        !Arc::ptr_eq(old, new),
        "equal-flow target-policy change must rebuild the lease Arc"
    );
    assert!(new.v8_equal_flow_active());
    assert_eq!(new.v8_equal_flow_target_policy_label(), "mean");
}

/// #1830 follow-up (Codex review on PR #1841): shared fixture for the
/// sparse-worker-id sizing pins below — one exact 50 MB/s queue on
/// ifindex 80 / queue 4, mirroring the fixtures of the reuse/rebuild
/// tests above.
fn exact_queue_forwarding_fixture() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 100_000_000,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 50_000_000,
                guarantee_enabled: true,
                exact: true,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
                codel_target_ns: 0,
            }],
            oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
            oversubscription_guarantee_fraction: 0.0,
            priority_low_min_share_bytes: 0,
        },
    );
    forwarding
}

/// #1830 follow-up (Codex review on PR #1841): `planned_worker_slots`
/// must derive the per-worker-id array length from the MAX planned
/// worker id, not the worker COUNT — ids are sparse when the bindings
/// carrying the low ids were unregistered.
#[test]
fn planned_worker_slots_uses_max_id_not_count() {
    let empty: BTreeMap<u32, ()> = BTreeMap::new();
    assert_eq!(reconcile::bringup::planned_worker_slots(&empty), 0);

    let dense = BTreeMap::from([(0u32, ()), (1, ()), (2, ())]);
    assert_eq!(reconcile::bringup::planned_worker_slots(&dense), 3);

    // Sparse: two workers survive, but the highest id is 40 — the
    // sizing value must be 41, NOT the count (2).
    let sparse = BTreeMap::from([(3u32, ()), (40, ())]);
    assert_eq!(reconcile::bringup::planned_worker_slots(&sparse), 41);
}

/// #1830 follow-up (Codex review on PR #1841): a lease built for a
/// sparse topology whose only high worker id is 40 must size its
/// per-worker arrays to 41 slots — acquire_v8(40) is in range and
/// granted, and matches_config_v8 keys on the true max id.
#[test]
fn build_shared_cos_queue_leases_sizes_for_sparse_high_worker_id() {
    let forwarding = exact_queue_forwarding_fixture();
    let active_shards_by_egress_ifindex = BTreeMap::from([(80, 2usize)]);

    // worker_slots = 41 as planned_worker_slots derives for a sparse
    // workers map whose highest id is 40 (count would be far lower).
    let leases = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        41,
        &BTreeMap::new(),
    );
    let lease = leases.get(&(80, 4)).expect("queue lease");

    let burst_bytes = (128 * 1024u64).max(64 * 1500);
    assert!(
        lease.matches_config_v8(50_000_000, burst_bytes, 2, 40, V8RateMode::CstructDefault, EqualFlowTargetPolicy::Slowest),
        "lease must be sized for max_worker_id 40 (41 per-worker slots)"
    );
    assert!(
        !lease.matches_config_v8(50_000_000, burst_bytes, 2, 1, V8RateMode::CstructDefault, EqualFlowTargetPolicy::Slowest),
        "a 41-slot lease must not match a 2-slot topology"
    );

    // Worker id 40 (above the pre-fix count-derived sizing) acquires
    // through the lease end to end: in range, nonzero grant, rotation
    // publishes its fair share.
    lease.rehydrate_worker_active_count(40, 1);
    let granted = lease.acquire_v8(40, 1_000_000, 4096);
    assert_eq!(
        granted, 4096,
        "worker id 40 must be in range of the lease arrays and granted"
    );
}

/// #1830 follow-up (Codex review on PR #1841): a worker-slot change
/// with an otherwise identical queue topology must REBUILD the lease
/// (no false reuse) — matches_config_v8 keys on max_worker_id, so a
/// topology whose max id changed never reuses the old sizing even
/// when the worker COUNT is unchanged.
#[test]
fn build_shared_cos_queue_leases_rebuilds_when_worker_slots_change() {
    let forwarding = exact_queue_forwarding_fixture();
    let active_shards_by_egress_ifindex = BTreeMap::from([(80, 2usize)]);

    let existing = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        2,
        &BTreeMap::new(),
    );
    let rebuilt = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        41,
        &existing,
    );

    let old = existing.get(&(80, 4)).expect("existing queue lease");
    let new = rebuilt.get(&(80, 4)).expect("rebuilt queue lease");
    assert!(
        !Arc::ptr_eq(old, new),
        "worker-slot change must rebuild the lease Arc, not reuse the old sizing"
    );

    // And the V_min floors honor the same sizing source. The floor
    // builder additionally gates on COS_SHARED_EXACT_MIN_RATE_BYTES
    // (2.5 Gbps), so raise the queue rate above that gate first.
    let mut high_rate_forwarding = exact_queue_forwarding_fixture();
    high_rate_forwarding
        .cos
        .interfaces
        .get_mut(&80)
        .expect("iface")
        .queues[0]
        .transmit_rate_bytes = 500_000_000;
    let floors = build_shared_cos_queue_vtime_floors_reusing_existing(
        &high_rate_forwarding,
        41,
        &BTreeMap::new(),
    );
    assert_eq!(
        floors.get(&(80, 4)).expect("vtime floor").slots.len(),
        41,
        "V_min floor slots must cover the highest planned worker id"
    );
}

#[test]
fn refresh_cos_owner_worker_map_from_binding_statuses_keeps_shared_arcs_when_unchanged() {
    let mut coordinator = Coordinator::new();
    coordinator.forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 100_000_000,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 50_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
                CoSQueueConfig {
                    queue_id: 1,
                    forwarding_class: "af11".into(),
                    priority: 5,
                    transmit_rate_bytes: 50_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
            ],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    coordinator.forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );
    let bindings = vec![BindingStatus {
        worker_id: 7,
        ifindex: 12,
        ready: true,
        ..Default::default()
    }];

    coordinator.refresh_cos_owner_worker_map_from_binding_statuses(&bindings);
    let owners_before = coordinator.cos.owner_worker_by_queue.load_full();
    let leases_before = coordinator.cos.root_leases.load_full();
    let lease_before = leases_before.get(&80).expect("shared root lease").clone();
    assert_eq!(lease_before.acquire(1, 2500), 2500);

    coordinator.refresh_cos_owner_worker_map_from_binding_statuses(&bindings);
    let owners_after = coordinator.cos.owner_worker_by_queue.load_full();
    let leases_after = coordinator.cos.root_leases.load_full();

    assert!(Arc::ptr_eq(&owners_before, &owners_after));
    assert!(Arc::ptr_eq(
        &lease_before,
        leases_after.get(&80).expect("shared root lease")
    ));
}

#[test]
fn unique_interface_owner_worker_id_returns_none_when_queues_split() {
    let owner = 7u32;
    let queues = vec![
        crate::protocol::CoSQueueStatus {
            queue_id: 0,
            owner_worker_id: Some(2),
            ..Default::default()
        },
        crate::protocol::CoSQueueStatus {
            queue_id: 1,
            owner_worker_id: Some(owner),
            ..Default::default()
        },
    ];

    assert_eq!(unique_interface_owner_worker_id(&queues), None);
}

#[test]
fn aggregate_cos_statuses_sums_drop_counters_across_worker_snapshots() {
    // #710 regression pin. This is the EXACT code path where the
    // live bug landed: `Coordinator::cos_statuses` re-aggregates
    // per-worker snapshots, and before this PR that re-aggregation
    // silently dropped every new drop-counter field. The unit test
    // gate must be at this layer, not just the worker layer.
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    let worker_a = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        shaping_rate_bytes: 1_250_000_000,
        burst_bytes: 256 * 1024,
        worker_instances: 1,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            buffer_bytes: 64 * 1024,
            queued_bytes: 48 * 1024,
            admission_flow_share_drops: 3,
            admission_buffer_drops: 5,
            admission_ecn_marked: 37,
            root_token_starvation_parks: 7,
            queue_token_starvation_parks: 11,
            tx_ring_full_submit_stalls: 13,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let worker_b = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        shaping_rate_bytes: 1_250_000_000,
        burst_bytes: 256 * 1024,
        worker_instances: 1,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            buffer_bytes: 64 * 1024,
            queued_bytes: 16 * 1024,
            admission_flow_share_drops: 17,
            admission_buffer_drops: 19,
            admission_ecn_marked: 41,
            root_token_starvation_parks: 23,
            queue_token_starvation_parks: 29,
            tx_ring_full_submit_stalls: 31,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let owner_by_queue = BTreeMap::from([((80, 4u8), 3u32)]);
    let aggregated = aggregate_cos_statuses_across_workers(&[worker_a, worker_b], &owner_by_queue);

    assert_eq!(aggregated.len(), 1);
    let iface = &aggregated[0];
    assert_eq!(iface.ifindex, 80);
    assert_eq!(iface.queues.len(), 1);
    let q = &iface.queues[0];
    assert_eq!(q.queue_id, 4);
    assert_eq!(q.owner_worker_id, Some(3));
    assert_eq!(q.buffer_bytes, 128 * 1024);
    assert_eq!(q.queued_bytes, 64 * 1024);
    // Each counter is non-coprime-prime on both sides to catch
    // accidental re-attribution between counters.
    assert_eq!(q.admission_flow_share_drops, 3 + 17);
    assert_eq!(q.admission_buffer_drops, 5 + 19);
    assert_eq!(q.admission_ecn_marked, 37 + 41);
    assert_eq!(q.root_token_starvation_parks, 7 + 23);
    assert_eq!(q.queue_token_starvation_parks, 11 + 29);
    assert_eq!(q.tx_ring_full_submit_stalls, 13 + 31);
}

#[test]
fn aggregate_cos_statuses_sums_owner_profile_across_workers_coherently() {
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    let worker_a = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            exact: true,
            drain_latency_hist: {
                let mut v = vec![0; super::super::umem::DRAIN_HIST_BUCKETS];
                v[0] = 5;
                v
            },
            redirect_acquire_hist: {
                let mut v = vec![0; super::super::umem::DRAIN_HIST_BUCKETS];
                v[1] = 3;
                v
            },
            drain_invocations: 5,
            drain_noop_invocations: 1,
            owner_pps: 100,
            peer_pps: 40,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let worker_b = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            exact: true,
            drain_latency_hist: {
                let mut v = vec![0; super::super::umem::DRAIN_HIST_BUCKETS];
                v[7] = 11;
                v
            },
            redirect_acquire_hist: {
                let mut v = vec![0; super::super::umem::DRAIN_HIST_BUCKETS];
                v[2] = 13;
                v
            },
            drain_invocations: 11,
            drain_noop_invocations: 2,
            owner_pps: 200,
            peer_pps: 50,
            ..Default::default()
        }],
        ..Default::default()
    }];

    let owner_by_queue = BTreeMap::from([((80, 4u8), 3u32)]);
    let aggregated = aggregate_cos_statuses_across_workers(&[worker_a, worker_b], &owner_by_queue);

    let q = &aggregated[0].queues[0];
    assert_eq!(q.drain_latency_hist[0], 5);
    assert_eq!(q.drain_latency_hist[7], 11);
    assert_eq!(q.redirect_acquire_hist[1], 3);
    assert_eq!(q.redirect_acquire_hist[2], 13);
    assert_eq!(q.drain_invocations, 16);
    assert_eq!(q.drain_noop_invocations, 3);
    assert_eq!(q.owner_pps, 300);
    assert_eq!(q.peer_pps, 90);
    assert_eq!(
        q.drain_latency_hist.iter().copied().sum::<u64>(),
        q.drain_invocations,
        "cross-worker aggregation must preserve hist == invocation invariant",
    );
}

#[test]
fn cos_no_owner_binding_drops_total_sums_across_every_live_state() {
    // #710: the per-binding `no_owner_binding_drops` atomic is the
    // mechanical accumulator; the operator-facing surface is
    // `Coordinator::cos_no_owner_binding_drops_total`, which must
    // sum across every `BindingLiveState`. Without this test, a
    // refactor that reads only `bindings.first()` or only one
    // worker's bindings could silently undercount.
    let a = std::sync::Arc::new(BindingLiveState::new());
    let b = std::sync::Arc::new(BindingLiveState::new());
    let c = std::sync::Arc::new(BindingLiveState::new());
    a.no_owner_binding_drops
        .store(3, std::sync::atomic::Ordering::Relaxed);
    b.no_owner_binding_drops
        .store(5, std::sync::atomic::Ordering::Relaxed);
    c.no_owner_binding_drops
        .store(7, std::sync::atomic::Ordering::Relaxed);

    let total: u64 = [a, b, c]
        .iter()
        .map(|live| {
            live.no_owner_binding_drops
                .load(std::sync::atomic::Ordering::Relaxed)
        })
        .sum();
    assert_eq!(total, 15);
}

#[test]
fn ring_pressure_counters_round_trip_through_snapshot() {
    // #802: verify that the new ring-pressure atomics on
    // BindingLiveState are surfaced via `snapshot()`. Without this
    // pin, a refactor that drops the new fields from `snapshot()`
    // would silently zero the operator-facing counters.
    use std::sync::atomic::Ordering;
    let live = BindingLiveState::new();
    live.dbg_tx_ring_full.store(11, Ordering::Relaxed);
    live.dbg_sendto_enobufs.store(13, Ordering::Relaxed);
    // #804: two distinct counters — bound-pending FIFO overflow
    // (17) and CoS queue admission overflow (41). Non-coprime-prime
    // per field so an accidental swap across the two is caught.
    live.dbg_bound_pending_overflow.store(17, Ordering::Relaxed);
    live.dbg_cos_queue_overflow.store(41, Ordering::Relaxed);
    live.rx_fill_ring_empty_descs.store(19, Ordering::Relaxed);
    live.debug_outstanding_tx.store(23, Ordering::Relaxed);
    let snap = live.snapshot();
    assert_eq!(snap.dbg_tx_ring_full, 11);
    assert_eq!(snap.dbg_sendto_enobufs, 13);
    assert_eq!(snap.dbg_bound_pending_overflow, 17);
    assert_eq!(snap.dbg_cos_queue_overflow, 41);
    assert_eq!(snap.rx_fill_ring_empty_descs, 19);
    assert_eq!(snap.debug_outstanding_tx, 23);
}

// -------------------------------------------------------------
// #925 Phase 1: worker supervisor catch_unwind tests.
// -------------------------------------------------------------

/// Helper: extract the message from a caught panic payload using
/// the same renderer the supervisor uses.
fn caught_message<F: FnOnce() + std::panic::UnwindSafe>(f: F) -> String {
    let r = std::panic::catch_unwind(f);
    let payload = r.unwrap_err();
    super::supervisor::panic_payload_message(&payload)
}

#[test]
fn panic_payload_message_renders_str_panic() {
    assert_eq!(caught_message(|| panic!("hello world")), "hello world");
}

#[test]
fn panic_payload_message_renders_string_panic() {
    let s = String::from("owned message");
    assert_eq!(caught_message(move || panic!("{}", s)), "owned message");
}

#[test]
fn panic_payload_message_falls_back_for_non_string() {
    // panic_any unwinds with a non-string payload (i32 here).
    let msg = caught_message(|| std::panic::panic_any(42_i32));
    assert_eq!(msg, "non-string panic payload");
}

/// Integration test against the same `spawn_supervised_worker`
/// production uses (the spawn-closure body is the only thing we
/// substitute — the supervisor wrapper is the real one).
#[test]
fn spawn_supervised_worker_catches_string_panic_and_marks_dead() {
    use std::sync::atomic::Ordering;
    let atomics = Arc::new(super::super::worker_runtime::WorkerRuntimeAtomics::new());
    let slot = Arc::new(Mutex::new(None::<String>));
    let join = super::supervisor::spawn_supervised_worker(7, atomics.clone(), slot.clone(), || {
        panic!("intentional test panic")
    })
    .expect("spawn_supervised_worker");
    // The supervisor must NOT propagate the panic to the joiner.
    join.join().expect("supervisor must catch worker panic");
    assert!(atomics.dead.load(Ordering::Relaxed));
    let msg = slot
        .lock()
        .expect("panic slot lock")
        .clone()
        .expect("panic message published");
    assert_eq!(msg, "intentional test panic");
}

/// #925-A: same as the worker test above but for the auxiliary-thread
/// helper. No `runtime_atomics` / `panic_slot` — aux threads only get
/// catch_unwind + journald log + clean exit.
#[test]
fn spawn_supervised_aux_catches_string_panic_and_returns_cleanly() {
    let join = super::supervisor::spawn_supervised_aux("test-aux", || {
        panic!("intentional aux test panic")
    })
    .expect("spawn_supervised_aux");
    // Joiner must observe a clean Ok(()) — supervisor swallowed the panic.
    join.join()
        .expect("supervisor must catch aux thread panic and return Ok(())");
}

#[test]
fn spawn_supervised_aux_runs_body_to_completion_when_no_panic() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let ran = Arc::new(AtomicBool::new(false));
    let ran_clone = ran.clone();
    let join = super::supervisor::spawn_supervised_aux("test-aux-noop", move || {
        ran_clone.store(true, Ordering::Relaxed);
    })
    .expect("spawn_supervised_aux");
    join.join().expect("aux thread join");
    assert!(
        ran.load(Ordering::Relaxed),
        "aux body must execute when no panic occurs"
    );
}

#[test]
fn spawn_supervised_aux_catches_non_string_panic_payload() {
    // Non-string payload exercises the panic_payload_message fallback
    // path, mirroring the worker_loop integration test above.
    let join =
        super::supervisor::spawn_supervised_aux("test-aux-i32", || std::panic::panic_any(99_i32))
            .expect("spawn_supervised_aux");
    join.join().expect("supervisor must catch non-string panic");
}

// -------------------------------------------------------------
// #943 Copilot round-2 finding #6: refresh_bindings hop test.
//
// The wire pipeline is:
//   BindingLiveState::v_min_throttles (AtomicU64)
//     -> snapshot()  (umem/mod.rs)
//     -> refresh_bindings (coordinator/mod.rs)  <-- THIS HOP
//     -> BindingStatus.v_min_throttles
//     -> BindingCountersSnapshot.v_min_throttles (wire JSON)
//
// Codex round-1 caught the BLOCKER where this exact hop was
// missing — refresh_bindings did not bridge the V_min fields, so
// the wire surface projected zeros despite the worker incrementing
// the atomic correctly. That fix lives at coordinator/mod.rs:1149.
//
// This test exercises the production refresh_bindings call against
// a real Coordinator + real BindingLiveState, so a future drop of
// either bridge line surfaces here rather than silently re-zeroing
// the wire field. Non-coprime-prime values per field catch a swap.
// -------------------------------------------------------------
#[test]
fn refresh_bindings_bridges_v_min_counters_into_binding_status() {
    use std::sync::atomic::Ordering;
    let mut coordinator = Coordinator::new();
    let live = std::sync::Arc::new(BindingLiveState::new());
    live.v_min_throttle_hard_cap_overrides
        .store(83, Ordering::Relaxed);
    live.v_min_throttles.store(89, Ordering::Relaxed);
    // Set an unrelated bridged field so the test also pins the
    // surrounding bridge layout (a refactor that re-orders the
    // assignments and drops one in the middle would surface here).
    live.flow_cache_collision_evictions
        .store(79, Ordering::Relaxed);
    live.syn_cookie_challenges.store(97, Ordering::Relaxed);
    live.syn_cookie_secret_unavailable
        .store(101, Ordering::Relaxed);
    live.syn_cookie_syn_ack_sent.store(103, Ordering::Relaxed);
    live.syn_cookie_ack_rst_sent.store(107, Ordering::Relaxed);
    live.syn_cookie_reply_budget_drops
        .store(109, Ordering::Relaxed);
    live.syn_cookie_ack_valid.store(113, Ordering::Relaxed);
    live.syn_cookie_ack_invalid.store(127, Ordering::Relaxed);
    live.syn_cookie_bypass.store(131, Ordering::Relaxed);
    coordinator.workers.live.insert(0, live);

    let mut bindings = vec![BindingStatus {
        slot: 0,
        worker_id: 1,
        ifindex: 12,
        // Pre-populate with junk values so the test also catches a
        // refresh_bindings that fails to overwrite the field (a
        // bridge that branches on `if x != 0` and skips, etc.).
        v_min_throttle_hard_cap_overrides: 0xdead_beef,
        v_min_throttles: 0xcafe_f00d,
        flow_cache_collision_evictions: 0xbad_c0de,
        syn_cookie_challenges: 1,
        syn_cookie_secret_unavailable: 1,
        syn_cookie_syn_ack_sent: 1,
        syn_cookie_ack_rst_sent: 1,
        syn_cookie_reply_budget_drops: 1,
        syn_cookie_ack_valid: 1,
        syn_cookie_ack_invalid: 1,
        syn_cookie_bypass: 1,
        ..Default::default()
    }];

    coordinator.refresh_bindings(&mut bindings);

    assert_eq!(
        bindings[0].v_min_throttle_hard_cap_overrides, 83,
        "refresh_bindings must bridge v_min_throttle_hard_cap_overrides \
         from BindingLiveState into BindingStatus"
    );
    assert_eq!(
        bindings[0].v_min_throttles, 89,
        "refresh_bindings must bridge v_min_throttles from \
         BindingLiveState into BindingStatus"
    );
    assert_eq!(
        bindings[0].flow_cache_collision_evictions, 79,
        "refresh_bindings must bridge flow_cache_collision_evictions \
         (companion bridge line — pinning the surrounding layout)"
    );
    assert_eq!(bindings[0].syn_cookie_challenges, 97);
    assert_eq!(bindings[0].syn_cookie_secret_unavailable, 101);
    assert_eq!(bindings[0].syn_cookie_syn_ack_sent, 103);
    assert_eq!(bindings[0].syn_cookie_ack_rst_sent, 107);
    assert_eq!(bindings[0].syn_cookie_reply_budget_drops, 109);
    assert_eq!(bindings[0].syn_cookie_ack_valid, 113);
    assert_eq!(bindings[0].syn_cookie_ack_invalid, 127);
    assert_eq!(bindings[0].syn_cookie_bypass, 131);
}

#[test]
fn refresh_bindings_zeroes_v_min_counters_when_worker_absent() {
    // Codex BLOCKER fix at coordinator/mod.rs:~1294: when the
    // BindingLiveState is missing for a slot, refresh_bindings
    // resets the V_min fields to 0 rather than leaving stale
    // counter values from a previous live snapshot. Without this,
    // a worker death + slot reassignment would project ghost
    // counters onto the new binding.
    let mut coordinator = Coordinator::new();
    // No insert into coordinator.workers.live for slot 7 — that's
    // the precondition for the reset path.

    let mut bindings = vec![BindingStatus {
        slot: 7,
        worker_id: 9,
        v_min_throttle_hard_cap_overrides: 999,
        v_min_throttles: 888,
        screen_drops: 777,
        syn_cookie_challenges: 666,
        syn_cookie_secret_unavailable: 555,
        syn_cookie_syn_ack_sent: 444,
        syn_cookie_ack_rst_sent: 333,
        syn_cookie_reply_budget_drops: 222,
        syn_cookie_ack_valid: 111,
        syn_cookie_ack_invalid: 99,
        syn_cookie_bypass: 88,
        ..Default::default()
    }];

    coordinator.refresh_bindings(&mut bindings);

    assert_eq!(bindings[0].v_min_throttle_hard_cap_overrides, 0);
    assert_eq!(bindings[0].v_min_throttles, 0);
    assert_eq!(bindings[0].screen_drops, 0);
    assert_eq!(bindings[0].syn_cookie_challenges, 0);
    assert_eq!(bindings[0].syn_cookie_secret_unavailable, 0);
    assert_eq!(bindings[0].syn_cookie_syn_ack_sent, 0);
    assert_eq!(bindings[0].syn_cookie_ack_rst_sent, 0);
    assert_eq!(bindings[0].syn_cookie_reply_budget_drops, 0);
    assert_eq!(bindings[0].syn_cookie_ack_valid, 0);
    assert_eq!(bindings[0].syn_cookie_ack_invalid, 0);
    assert_eq!(bindings[0].syn_cookie_bypass, 0);
}

/// #1328 — verify `reconcile(None, ...)` reaches the
/// `"no_snapshot"` early-exit cleanly, runs the teardown phase
/// (resetting `slow_path` to None), zeros `workers.live`, and
/// increments `reconcile_calls`.
///
/// `last_reconcile_stage` is a single field with no history, so
/// the test asserts the final write only. The per-stage write
/// ORDERING (start -> stopped -> no_snapshot) is verified by
/// reading the diff against the inventory documented in
/// `docs/pr/1328-coordinator-reconcile-split/plan.md`
/// §"Hidden invariants" #2.
#[test]
fn reconcile_with_none_snapshot_reaches_no_snapshot_early_exit() {
    let mut coordinator = Coordinator::new();
    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        worker_id: 0,
        queue_id: 0,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        bound: true,
        xsk_registered: true,
        ready: true,
        rx_packets: 42,
        ..BindingStatus::default()
    }];
    coordinator.reconcile(None, &mut bindings, 64);
    assert_eq!(coordinator.last_reconcile_stage, "no_snapshot");
    assert_eq!(coordinator.reconcile_calls, 1);
    assert!(
        coordinator.workers.live.is_empty(),
        "no live workers expected on None snapshot"
    );
    assert!(
        coordinator.slow_path.is_none(),
        "slow_path should be None after teardown of an unbound coordinator"
    );
    // Reset phase zeroed counter / ready / bound flags.
    assert!(!bindings[0].ready);
    assert!(!bindings[0].bound);
    assert!(!bindings[0].xsk_registered);
    assert_eq!(bindings[0].rx_packets, 0);
}

// ---------------------------------------------------------------------------
// #1636 option C: proactive neighbor warm tests.
// ---------------------------------------------------------------------------

fn warm_active_ha_runtime(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

/// Build a coordinator with an installed warm queue (returning the
/// receiver), one egress interface on RG `rg_id`, that RG marked
/// forwarding-active, and a single static route whose next-hop is
/// UNRESOLVED. The caller drains the receiver after queue_warm_pass.
fn warm_test_coordinator(rg_id: i32) -> (Coordinator, Receiver<WarmItem>) {
    let mut coord = Coordinator::new();
    let (tx, rx) = mpsc::sync_channel::<WarmItem>(WARM_QUEUE_DEPTH);
    coord.neighbors.warm_queue = Some(tx);

    let now_secs = monotonic_nanos() / 1_000_000_000;
    coord
        .ha
        .rg_runtime
        .store(Arc::new(BTreeMap::from([(rg_id, warm_active_ha_runtime(now_secs))])));

    let egress_ifindex = 80i32;
    coord.forwarding.ifindex_to_name.insert(egress_ifindex, "ge-0-0-2".to_string());
    coord.forwarding.egress.insert(
        egress_ifindex,
        EgressInterface {
            bind_ifindex: egress_ifindex,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: 0,
            redundancy_group: rg_id,
            primary_v4: None,
            primary_v6: None,
        },
    );
    coord.forwarding.routes_v4.insert(
        "inet.0".to_string(),
        vec![RouteEntryV4::single(
            PrefixV4::from_net("0.0.0.0/0".parse().unwrap()),
            egress_ifindex,
            0,
            Some(Ipv4Addr::new(172, 16, 80, 1)),
            false,
            String::new(),
            5,
        )],
    );
    (coord, rx)
}

#[test]
fn queue_warm_pass_fires_for_unresolved_next_hop() {
    let (coord, rx) = warm_test_coordinator(0);
    coord.queue_warm_pass(false);
    let item = rx.try_recv().expect("one warm item for the unresolved next-hop");
    assert_eq!(item.ifindex, 80);
    assert_eq!(item.hop, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1)));
    assert_eq!(item.iface_name, "ge-0-0-2");
    assert_eq!(item.rg_id, 0);
    assert!(rx.try_recv().is_err(), "exactly one item expected");
}

#[test]
fn queue_warm_pass_skips_already_resolved_next_hop() {
    let (mut coord, rx) = warm_test_coordinator(0);
    // Resolve the next-hop in the forwarding neighbor map.
    coord.forwarding.neighbors.insert(
        (80, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
        NeighborEntry { mac: [0xaa; 6] },
    );
    coord.queue_warm_pass(false);
    assert!(rx.try_recv().is_err(), "resolved next-hop must not be warmed");
}

#[test]
fn queue_warm_pass_skips_when_owning_rg_inactive() {
    // Route is on RG 1 but RG 1 is NOT forwarding-active.
    let (coord, rx) = warm_test_coordinator(1);
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Replace runtime: RG 1 inactive.
    coord.ha.rg_runtime.store(Arc::new(BTreeMap::from([(
        1i32,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: now_secs,
            lease: HAForwardingLease::Inactive,
        },
    )])));
    coord.queue_warm_pass(false);
    assert!(
        rx.try_recv().is_err(),
        "standby RG next-hop must not be warmed",
    );
}

#[test]
fn queue_warm_pass_skips_tunnel_routes() {
    // Codex r1 High #1: a route with tunnel_endpoint_id != 0 is HA-owned
    // by the tunnel endpoint's RG, not the underlay egress RG, and is out
    // of warm scope. The warmer must skip it rather than gate it on the
    // wrong RG.
    let (mut coord, rx) = warm_test_coordinator(0);
    coord.forwarding.routes_v4.get_mut("inet.0").unwrap()[0].next_hops[0].tunnel_endpoint_id = 7;
    coord.queue_warm_pass(false);
    assert!(rx.try_recv().is_err(), "tunnel route must not be warmed");
}

#[test]
fn queue_warm_pass_skips_invalid_addresses() {
    let (mut coord, rx) = warm_test_coordinator(0);
    // Replace the route's next-hop with a multicast address.
    coord.forwarding.routes_v4.get_mut("inet.0").unwrap()[0].next_hops[0].next_hop =
        Some(Ipv4Addr::new(224, 0, 0, 1));
    coord.queue_warm_pass(false);
    assert!(rx.try_recv().is_err(), "multicast next-hop must be filtered");
}

#[test]
fn queue_warm_pass_dedups_within_one_call() {
    let (mut coord, rx) = warm_test_coordinator(0);
    // Two routes with the SAME (ifindex, next-hop) in different tables.
    coord.forwarding.routes_v4.insert(
        "vrf-a.inet.0".to_string(),
        vec![RouteEntryV4::single(
            PrefixV4::from_net("0.0.0.0/0".parse().unwrap()),
            80,
            0,
            Some(Ipv4Addr::new(172, 16, 80, 1)),
            false,
            String::new(),
            5,
        )],
    );
    coord.queue_warm_pass(false);
    assert!(rx.try_recv().is_ok(), "first item expected");
    assert!(rx.try_recv().is_err(), "duplicate (ifindex, hop) must coalesce");
}

#[test]
fn queue_warm_pass_respects_snapshot_rate_limit() {
    let (coord, rx) = warm_test_coordinator(0);
    coord.queue_warm_pass(false);
    assert!(rx.try_recv().is_ok());
    // Second non-forced sweep within 1s must be skipped wholesale.
    coord.queue_warm_pass(false);
    assert!(
        rx.try_recv().is_err(),
        "second sweep within 1s rate-limit must not enqueue",
    );
    // Forced sweep (RG-promote path) bypasses the snapshot rate-limit.
    coord.queue_warm_pass(true);
    assert!(rx.try_recv().is_ok(), "forced sweep must bypass snapshot rate-limit");
}

#[test]
fn queue_warm_pass_warms_fabric_peer_over_parent_ifindex() {
    let (mut coord, rx) = warm_test_coordinator(0);
    // Drop the route so only the fabric is a candidate.
    coord.forwarding.routes_v4.clear();
    let parent = 80i32;
    coord.forwarding.ifindex_to_name.insert(parent, "ge-0-0-0".to_string());
    coord.forwarding.fabrics.push(FabricLink {
        parent_ifindex: parent,
        overlay_ifindex: 90,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2)),
        peer_mac: [0; 6],
        local_mac: [0; 6],
    });
    coord.queue_warm_pass(false);
    let item = rx.try_recv().expect("fabric peer warm item");
    assert_eq!(item.ifindex, parent, "fabric warms over parent_ifindex (AGY r7 #3)");
    assert_eq!(item.hop, IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2)));
}

#[test]
fn queue_warm_pass_noop_without_worker_queue() {
    // No warm_queue installed (worker not yet spawned) → no panic, no-op.
    let mut coord = Coordinator::new();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    coord
        .ha
        .rg_runtime
        .store(Arc::new(BTreeMap::from([(0i32, warm_active_ha_runtime(now_secs))])));
    coord.forwarding.routes_v4.insert(
        "inet.0".to_string(),
        vec![RouteEntryV4::single(
            PrefixV4::from_net("0.0.0.0/0".parse().unwrap()),
            80,
            0,
            Some(Ipv4Addr::new(172, 16, 80, 1)),
            false,
            String::new(),
            5,
        )],
    );
    coord.queue_warm_pass(false); // must not panic
}

#[test]
fn on_rg_promote_active_clears_rate_limit_and_forces_warm() {
    let (coord, rx) = warm_test_coordinator(0);
    // Pre-load a recent probe for the key so the per-key 5s rate-limit
    // would normally suppress it.
    {
        let mut probed = coord.neighbors.last_probed_at.lock().unwrap();
        probed.insert((80, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))), monotonic_nanos());
    }
    // First non-forced sweep enqueues (queue_warm_pass does not consult
    // last_probed_at — that is the worker's job — so the item IS sent).
    coord.queue_warm_pass(false);
    assert!(rx.try_recv().is_ok());
    // on_rg_promote_active clears last_probed_at AND forces a sweep that
    // bypasses the snapshot rate-limit.
    coord.on_rg_promote_active();
    assert!(
        coord.neighbors.last_probed_at.lock().unwrap().is_empty(),
        "RG-promote must clear the per-key rate-limit map",
    );
    assert!(rx.try_recv().is_ok(), "forced warm pass on RG-promote must enqueue");
}

// #1628: waterfill counter cross-worker aggregation.

#[test]
fn aggregate_cos_waterfill_epochs_sum_and_min_over_active_workers() {
    // Two workers, both with active exact-guarantee backlog. The
    // coordinator MIN-combines the PER-WORKER min_epochs_per_worker each
    // worker already computed over its own bindings (interface_row.rs).
    // Worker A healthy (epochs 1000), worker B frozen in Phase-2 lock-in
    // (epochs 3). The summed epochs climb, but the MIN reflects the
    // frozen worker (F2 regression guard).
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    let active_exact_queue = || CoSQueueStatus {
        queue_id: 4,
        worker_instances: 1,
        exact: true,
        guarantee_enabled: true,
        queued_bytes: 32 * 1024,
        ..Default::default()
    };
    let worker_healthy = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        waterfill_epochs: 1000,
        waterfill_phase1_budget_breaks: 4,
        // worker-side per-binding MIN (one active binding here = its own
        // epochs).
        waterfill_min_epochs_per_worker: 1000,
        queues: vec![active_exact_queue()],
        ..Default::default()
    }];
    let worker_frozen = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        waterfill_epochs: 3, // locked in Phase 2 — barely advanced
        waterfill_phase1_budget_breaks: 900,
        waterfill_min_epochs_per_worker: 3,
        queues: vec![active_exact_queue()],
        ..Default::default()
    }];
    let owner_by_queue = BTreeMap::from([((80, 4u8), 3u32)]);
    let aggregated =
        aggregate_cos_statuses_across_workers(&[worker_healthy, worker_frozen], &owner_by_queue);
    assert_eq!(aggregated.len(), 1);
    let iface = &aggregated[0];
    assert_eq!(iface.waterfill_epochs, 1000 + 3, "epochs SUM across workers");
    assert_eq!(
        iface.waterfill_phase1_budget_breaks,
        4 + 900,
        "budget breaks SUM across workers"
    );
    assert_eq!(
        iface.waterfill_min_epochs_per_worker, 3,
        "MIN must reflect the frozen worker, not be drowned by the healthy SUM"
    );
}

#[test]
fn aggregate_cos_waterfill_min_excludes_idle_workers() {
    // The idle-worker conflation guard: an idle worker reports the
    // u64::MAX "no active-backlog binding" sentinel; the coordinator
    // skips it so it cannot pin the MIN. The MIN reflects only the
    // worker WITH a candidate.
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    let busy = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        waterfill_epochs: 500,
        waterfill_min_epochs_per_worker: 500,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            exact: true,
            guarantee_enabled: true,
            queued_bytes: 64 * 1024,
            ..Default::default()
        }],
        ..Default::default()
    }];
    // Idle worker: reports MAX (no active-backlog binding) per the
    // worker-side sentinel.
    let idle = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        waterfill_epochs: 0,
        waterfill_min_epochs_per_worker: u64::MAX,
        queues: vec![CoSQueueStatus {
            queue_id: 5,
            worker_instances: 1,
            exact: true,
            guarantee_enabled: true,
            queued_bytes: 0,
            queued_packets: 0,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let owner_by_queue = BTreeMap::from([((80, 4u8), 3u32), ((80, 5u8), 4u32)]);
    let aggregated = aggregate_cos_statuses_across_workers(&[busy, idle], &owner_by_queue);
    let iface = &aggregated[0];
    assert_eq!(
        iface.waterfill_min_epochs_per_worker, 500,
        "idle worker (MAX sentinel) must be EXCLUDED from the MIN"
    );
}

#[test]
fn aggregate_cos_waterfill_min_captures_zero_epoch_lockin() {
    // A backlogged binding that completed ZERO epochs is the STRONGEST
    // lock-in signal — the worker reports 0 (NOT the MAX sentinel), and
    // the coordinator MUST capture it as the MIN even alongside a healthy
    // worker. This is the sentinel-collision case the code review flagged.
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    let active_exact_queue = || CoSQueueStatus {
        queue_id: 4,
        worker_instances: 1,
        exact: true,
        guarantee_enabled: true,
        queued_bytes: 16 * 1024,
        ..Default::default()
    };
    let healthy = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        waterfill_epochs: 900,
        waterfill_min_epochs_per_worker: 900,
        queues: vec![active_exact_queue()],
        ..Default::default()
    }];
    let locked_zero = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        waterfill_epochs: 0, // never completed an epoch — hard lock-in
        waterfill_min_epochs_per_worker: 0,
        queues: vec![active_exact_queue()],
        ..Default::default()
    }];
    let owner_by_queue = BTreeMap::from([((80, 4u8), 3u32)]);
    let aggregated =
        aggregate_cos_statuses_across_workers(&[healthy, locked_zero], &owner_by_queue);
    assert_eq!(
        aggregated[0].waterfill_min_epochs_per_worker, 0,
        "a backlogged 0-epoch worker (lock-in) MUST be captured, not treated as 'no candidate'"
    );
}

#[test]
fn aggregate_cos_waterfill_min_max_sentinel_when_no_candidate() {
    // No worker reports a candidate (all u64::MAX) → the AGGREGATED MIN
    // stays u64::MAX (NOT 0), so an idle interface is distinguishable
    // from a hard 0-epoch lock-in. Prometheus suppresses the MAX gauge
    // and the CLI renders it as "none"; only a genuine 0-epoch lock-in
    // emits 0 (code-review r2, both reviewers).
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    let worker = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        waterfill_epochs: 777,
        waterfill_min_epochs_per_worker: u64::MAX,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            exact: true,
            guarantee_enabled: true,
            queued_bytes: 0,
            queued_packets: 0,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let owner_by_queue = BTreeMap::from([((80, 4u8), 3u32)]);
    let aggregated = aggregate_cos_statuses_across_workers(&[worker], &owner_by_queue);
    assert_eq!(
        aggregated[0].waterfill_min_epochs_per_worker,
        u64::MAX,
        "no candidate (all MAX) → aggregated MIN stays the MAX sentinel, NOT 0"
    );
    assert_eq!(aggregated[0].waterfill_epochs, 777);
}

// #1829 Phase 1: cross-worker sojourn aggregation pin. The sojourn
// trio MAX-merges across workers (worst instance) — summing delays
// would be meaningless and a `..Default::default()` fall-through
// would silently zero the gate metric at exactly this layer (the
// same failure shape as the #710 drop-counter regression above).
#[test]
fn aggregate_cos_statuses_max_merges_sojourn_across_worker_snapshots() {
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    let worker_a = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            sojourn_ewma_ns: 2_000_000,
            sojourn_peak_ns: 9_000_000,
            sojourn_windowed_min_ns: 1_500_000,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let worker_b = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            sojourn_ewma_ns: 4_000_000,
            sojourn_peak_ns: 6_000_000,
            sojourn_windowed_min_ns: 5_500_000,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let owner_by_queue = BTreeMap::new();
    let aggregated = aggregate_cos_statuses_across_workers(&[worker_a, worker_b], &owner_by_queue);

    assert_eq!(aggregated.len(), 1);
    let q = &aggregated[0].queues[0];
    assert_eq!(q.sojourn_ewma_ns, 4_000_000, "EWMA must MAX-merge");
    assert_eq!(q.sojourn_peak_ns, 9_000_000, "peak must MAX-merge");
    assert_eq!(
        q.sojourn_windowed_min_ns, 5_500_000,
        "windowed min (the gate metric) must MAX-merge across workers",
    );
}

// ---------------------------------------------------------------------
// #1866 — WG control-thread teardown / lifecycle regression suite.
//
// These tests drive the REAL spawn path: refresh_runtime_snapshot
// spawns an actual control thread that binds the listen UDP port and
// then fails open_tun (no TUN device in the test environment) and
// exits — which is exactly the early-exit shape the tombstone
// machinery must handle. Each test uses a unique listen port so the
// suite can run in parallel.
// ---------------------------------------------------------------------

const WG1866_PRIVKEY_A: &str =
    "a01010101010101010101010101010101010101010101010101010101010101a";
const WG1866_PRIVKEY_B: &str =
    "c03030303030303030303030303030303030303030303030303030303030303c";
const WG1866_PUBKEY: &str =
    "b02020202020202020202020202020202020202020202020202020202020202b";

fn wg1866_snapshot(id: u16, ifindex: i32, name: &str, port: u16, privkey: &str) -> ConfigSnapshot {
    ConfigSnapshot {
        interfaces: vec![crate::protocol::snapshot::InterfaceSnapshot {
            name: name.to_string(),
            linux_name: name.to_string(),
            ifindex,
            tunnel: true,
            ..Default::default()
        }],
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id,
            interface: name.to_string(),
            linux_name: name.to_string(),
            ifindex,
            mode: "wireguard".to_string(),
            wg_listen_port: port,
            wg_local_privkey_hex: privkey.to_string(),
            wg_peers: vec![crate::protocol::snapshot::TunnelWgPeerSnapshot {
                wg_peer_pubkey_hex: WG1866_PUBKEY.to_string(),
                wg_allowed_ips: vec!["10.77.0.0/24".to_string()],
                wg_endpoint: "127.0.0.1:9".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// Drive the finished sweep until the entry for `id` is a tombstone
/// (its real thread exited) or the timeout elapses.
fn wg1866_wait_tombstone(coordinator: &mut Coordinator, id: u16, timeout_ms: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        // None snapshot: sweep-only (the tombstone-only respawn needs a
        // coherent snapshot, so this can never spawn).
        coordinator.reconcile_wg_control_liveness(None);
        match coordinator.wg_control_threads.get(&id) {
            Some(entry) if entry.handle.is_none() => return true,
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Plan §9 test 1 — removal prune: a snapshot refresh that drops the
/// WG endpoint stops + joins the thread, removes the entry, and
/// releases the listen port.
#[test]
fn wg1866_removal_refresh_prunes_thread_and_releases_port() {
    let mut coordinator = Coordinator::new();
    let port: u16 = 51871;
    coordinator.refresh_runtime_snapshot(&wg1866_snapshot(1, 4242, "wgt1866a", port, WG1866_PRIVKEY_A));
    assert!(
        coordinator.wg_control_threads.contains_key(&1),
        "WG control entry created on snapshot with WG endpoint"
    );
    coordinator.refresh_runtime_snapshot(&ConfigSnapshot::default());
    assert!(
        coordinator.wg_control_threads.is_empty(),
        "removal refresh must prune the entry (stop+join)"
    );
    let bind = std::net::UdpSocket::bind(("0.0.0.0", port));
    assert!(
        bind.is_ok(),
        "listen port must be released after removal: {:?}",
        bind.err()
    );
}

/// Plan §9 tests 2+3 — EADDRINUSE regression (rigged old behavior) +
/// tombstone backoff: a thread that dies on a pre-bound port leaves a
/// tombstone; the sweep does NOT retry within the backoff window and
/// DOES retry past it once the port is free.
#[test]
fn wg1866_eaddrinuse_tombstone_backoff_and_retry() {
    let mut coordinator = Coordinator::new();
    let port: u16 = 51872;
    // Rig the failure: a dual-stack [::]:port blocker occupies the port
    // for BOTH of bind_wg_socket's attempts (v6 preferred, v4 fallback).
    let blocker = std::net::UdpSocket::bind(("::", port)).expect("pre-bind");
    let snap = wg1866_snapshot(1, 4242, "wgt1866b", port, WG1866_PRIVKEY_A);
    coordinator.refresh_runtime_snapshot(&snap);
    assert!(
        coordinator.wg_control_threads.contains_key(&1),
        "spawn attempt recorded even though bind will fail"
    );
    // The thread exits on EADDRINUSE; the sweep must tombstone, not drop.
    assert!(
        wg1866_wait_tombstone(&mut coordinator, 1, 2_000),
        "EADDRINUSE thread must become a tombstone"
    );
    let stamp_after_fail = coordinator
        .wg_control_threads
        .get(&1)
        .expect("tombstone entry retained")
        .last_spawn_attempt_ns;
    // Within the backoff window: no respawn even with a coherent
    // snapshot and the port now free.
    drop(blocker);
    coordinator.reconcile_wg_control_liveness(Some(&snap));
    let entry = coordinator.wg_control_threads.get(&1).expect("entry kept");
    assert!(entry.handle.is_none(), "no respawn within the 3s backoff");
    assert_eq!(
        entry.last_spawn_attempt_ns, stamp_after_fail,
        "backoff stamp unchanged while gated"
    );
    // Force past the backoff (tests own the entry — no 3s sleep).
    coordinator
        .wg_control_threads
        .get_mut(&1)
        .expect("entry")
        .last_spawn_attempt_ns = 0;
    coordinator.reconcile_wg_control_liveness(Some(&snap));
    let entry = coordinator.wg_control_threads.get(&1).expect("entry kept");
    assert!(
        entry.handle.is_some(),
        "tombstone respawned past backoff with a coherent snapshot"
    );
    assert!(entry.last_spawn_attempt_ns > 0, "attempt re-stamped");
}

/// Plan §9 test 4 — the #1866 headline contract: remove then re-add
/// the SAME identity; the re-add must spawn a fresh thread (no dead
/// entry shadowing, no EADDRINUSE from a leaked holder).
#[test]
fn wg1866_remove_then_readd_same_identity_respawns() {
    let mut coordinator = Coordinator::new();
    let port: u16 = 51873;
    let snap = wg1866_snapshot(1, 4242, "wgt1866c", port, WG1866_PRIVKEY_A);
    coordinator.refresh_runtime_snapshot(&snap);
    assert!(coordinator.wg_control_threads.contains_key(&1));
    coordinator.refresh_runtime_snapshot(&ConfigSnapshot::default());
    assert!(coordinator.wg_control_threads.is_empty());
    coordinator.refresh_runtime_snapshot(&snap);
    let entry = coordinator
        .wg_control_threads
        .get(&1)
        .expect("re-add with the same identity must create a fresh entry");
    assert!(entry.handle.is_some(), "fresh thread spawned on re-add");
}

/// Plan §9 test 5 — stop-gate shape: stop() clears all entries and a
/// subsequent sweep (tombstone-only) cannot create any, even with a
/// coherent snapshot in hand.
#[test]
fn wg1866_sweep_cannot_spawn_after_stop() {
    let mut coordinator = Coordinator::new();
    let port: u16 = 51874;
    let snap = wg1866_snapshot(1, 4242, "wgt1866d", port, WG1866_PRIVKEY_A);
    coordinator.refresh_runtime_snapshot(&snap);
    assert!(coordinator.wg_control_threads.contains_key(&1));
    coordinator.stop();
    assert!(coordinator.wg_control_threads.is_empty(), "stop clears entries");
    for _ in 0..3 {
        coordinator.reconcile_wg_control_liveness(Some(&snap));
    }
    assert!(
        coordinator.wg_control_threads.is_empty(),
        "tombstone-only sweep must never create entries after stop"
    );
}

/// Plan §9 tests 6+6b — defer-workers prune (Change 2b / D4) + F7
/// regression: the prune stops the thread WITHOUT touching forwarding,
/// and the sweep must NOT resurrect it from the stale forwarding state.
#[test]
fn wg1866_defer_prune_releases_port_and_sweep_does_not_resurrect() {
    let mut coordinator = Coordinator::new();
    let port: u16 = 51875;
    let snap = wg1866_snapshot(1, 4242, "wgt1866e", port, WG1866_PRIVKEY_A);
    coordinator.refresh_runtime_snapshot(&snap);
    assert!(coordinator.wg_control_threads.contains_key(&1));
    // Defer-branch apply removed the endpoint: narrow prune only.
    let removed = ConfigSnapshot::default();
    coordinator.prune_wg_control_threads_for_snapshot(&removed);
    assert!(
        coordinator.wg_control_threads.is_empty(),
        "defer prune must stop+join+remove the entry"
    );
    assert!(
        coordinator.forwarding.tunnel_endpoints.contains_key(&1),
        "defer prune must NOT touch the (intentionally stale) forwarding state"
    );
    let bind = std::net::UdpSocket::bind(("0.0.0.0", port));
    assert!(bind.is_ok(), "port released by the defer prune: {:?}", bind.err());
    // F7 regression: repeated sweeps against the STORED (endpoint-free)
    // snapshot must not resurrect the thread from stale forwarding.
    for _ in 0..3 {
        coordinator.reconcile_wg_control_liveness(Some(&removed));
    }
    assert!(
        coordinator.wg_control_threads.is_empty(),
        "tombstone-only sweep must not resurrect a defer-pruned endpoint"
    );
}

/// Plan §9 test 6c — Codex r3 regression: a tombstone whose latest
/// STORED snapshot row carries a DIFFERENT crypto identity must not
/// respawn from the stale forwarding state during a defer window.
#[test]
fn wg1866_sweep_suppresses_stale_identity_respawn_under_defer() {
    let mut coordinator = Coordinator::new();
    let port: u16 = 51876;
    let snap_a = wg1866_snapshot(1, 4242, "wgt1866f", port, WG1866_PRIVKEY_A);
    coordinator.refresh_runtime_snapshot(&snap_a);
    assert!(wg1866_wait_tombstone(&mut coordinator, 1, 2_000), "open_tun failure tombstones");
    // Defer window: stored snapshot re-keys id 1 to identity B while
    // forwarding still holds identity A. Force past the backoff.
    let snap_b = wg1866_snapshot(1, 4242, "wgt1866f", port, WG1866_PRIVKEY_B);
    coordinator
        .wg_control_threads
        .get_mut(&1)
        .expect("tombstone")
        .last_spawn_attempt_ns = 0;
    coordinator.reconcile_wg_control_liveness(Some(&snap_b));
    let entry = coordinator.wg_control_threads.get(&1).expect("tombstone kept");
    assert!(
        entry.handle.is_none(),
        "sweep must not respawn identity A when the stored snapshot says identity B"
    );
    // The coherent apply with B then restarts cleanly (engine changed
    // => stale prune => fresh spawn).
    coordinator.refresh_runtime_snapshot(&snap_b);
    let entry = coordinator.wg_control_threads.get(&1).expect("entry after B apply");
    assert!(entry.handle.is_some(), "identity B spawns at the coherent apply");
}

/// Plan §9 test 6d — Codex r4 regression: same id, same crypto
/// identity, RENAMED interface in the stored snapshot — the sweep must
/// not respawn the OLD attachment from stale forwarding.
#[test]
fn wg1866_sweep_suppresses_stale_attachment_respawn_under_defer() {
    let mut coordinator = Coordinator::new();
    let port: u16 = 51877;
    let snap_a = wg1866_snapshot(1, 4242, "wgt1866g", port, WG1866_PRIVKEY_A);
    coordinator.refresh_runtime_snapshot(&snap_a);
    assert!(wg1866_wait_tombstone(&mut coordinator, 1, 2_000), "open_tun failure tombstones");
    // Stored snapshot renames the interface (same id + identity).
    let snap_renamed = wg1866_snapshot(1, 4243, "wgt1866h", port, WG1866_PRIVKEY_A);
    coordinator
        .wg_control_threads
        .get_mut(&1)
        .expect("tombstone")
        .last_spawn_attempt_ns = 0;
    coordinator.reconcile_wg_control_liveness(Some(&snap_renamed));
    let entry = coordinator.wg_control_threads.get(&1).expect("tombstone kept");
    assert!(
        entry.handle.is_none(),
        "sweep must not respawn the old TUN attachment when the stored snapshot renamed it"
    );
}

/// Plan §9 test 6e — D5 regression (pre-existing master gap): an
/// apply-time interface rename with an UNCHANGED crypto identity must
/// restart the thread on the new TUN attachment (the reused engine Arc
/// alone must not keep the old thread).
#[test]
fn wg1866_apply_time_rename_restarts_thread_on_new_attachment() {
    let mut coordinator = Coordinator::new();
    let port: u16 = 51878;
    coordinator.refresh_runtime_snapshot(&wg1866_snapshot(1, 4242, "wgt1866i", port, WG1866_PRIVKEY_A));
    let entry = coordinator.wg_control_threads.get(&1).expect("entry");
    assert_eq!(entry.spawned_tunnel_name, "wgt1866i");
    // Rename (same id, same identity): engine Arc is REUSED, but the
    // attachment-aware stale prune must restart the thread.
    coordinator.refresh_runtime_snapshot(&wg1866_snapshot(1, 4243, "wgt1866j", port, WG1866_PRIVKEY_A));
    let entry = coordinator.wg_control_threads.get(&1).expect("entry after rename");
    assert_eq!(
        entry.spawned_tunnel_name, "wgt1866j",
        "rename must stop the old thread and spawn against the new TUN"
    );
    assert_eq!(entry.spawned_ifindex, 4243);
}

/// PR #1872 Codex code-r1 F2 regression: rows whose `linux_name` is
/// empty resolve their forwarding label from the logical name
/// (forwarding_build/interfaces.rs fallback) — the tombstone-respawn
/// coherence check must apply the SAME fallback or self-heal never
/// fires for such rows.
#[test]
fn wg1866_sweep_respawns_with_empty_linux_name_rows() {
    let mut coordinator = Coordinator::new();
    let port: u16 = 51880;
    let mut snap = wg1866_snapshot(1, 4244, "wgt1866k", port, WG1866_PRIVKEY_A);
    snap.interfaces[0].linux_name = String::new();
    snap.tunnel_endpoints[0].linux_name = String::new();
    coordinator.refresh_runtime_snapshot(&snap);
    assert!(
        wg1866_wait_tombstone(&mut coordinator, 1, 2_000),
        "open_tun failure tombstones"
    );
    coordinator
        .wg_control_threads
        .get_mut(&1)
        .expect("tombstone")
        .last_spawn_attempt_ns = 0;
    coordinator.reconcile_wg_control_liveness(Some(&snap));
    let entry = coordinator.wg_control_threads.get(&1).expect("entry");
    assert!(
        entry.handle.is_some(),
        "coherence check must accept the empty-linux_name fallback label and respawn"
    );
}

// ---------------------------------------------------------------------
// #1881 — GRE local-origin thread lifecycle regression suite.
//
// Same shape as the wg1866 suite above: these drive the REAL spawn
// path; the spawned thread fails open_tun (no TUN privilege in the
// test environment) and exits — exactly the early-exit shape the
// tombstone machinery must handle. On master (pre-#1881) the
// entry-creation pins fail outright: refresh_runtime_snapshot never
// touched tunnel_sources (threads were spawned at bring-up only).
// ---------------------------------------------------------------------

fn gre1881_snapshot(id: u16, ifindex: i32, name: &str, dst: &str) -> ConfigSnapshot {
    ConfigSnapshot {
        interfaces: vec![crate::protocol::snapshot::InterfaceSnapshot {
            name: name.to_string(),
            linux_name: name.to_string(),
            ifindex,
            tunnel: true,
            ..Default::default()
        }],
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id,
            interface: name.to_string(),
            linux_name: name.to_string(),
            ifindex,
            mode: "gre".to_string(),
            outer_family: "inet".to_string(),
            source: "192.0.2.1".to_string(),
            destination: dst.to_string(),
            ttl: 64,
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// #1881 plan SMR-1: the spawn pass is gated on live worker handles —
/// a thread spawned with zero workers would freeze EMPTY
/// live/identities/worker_commands captures for its lifetime. Tests
/// that want spawns install one fake handle.
fn gre1881_fake_worker_handle() -> WorkerHandle {
    WorkerHandle {
        stop: Arc::new(AtomicBool::new(false)),
        heartbeat: Arc::new(AtomicU64::new(0)),
        commands: Arc::new(Mutex::new(VecDeque::new())),
        session_export_ack: Arc::new(AtomicU64::new(0)),
        cos_status: Arc::new(ArcSwap::from_pointee(Vec::new())),
        runtime_atomics: Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new()),
        cold_path_atomics: Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new()),
        join: None,
    }
}

fn gre1881_coordinator_with_worker() -> Coordinator {
    let mut coordinator = Coordinator::new();
    coordinator
        .workers
        .handles
        .insert(0, gre1881_fake_worker_handle());
    coordinator
}

/// Drive the finished sweep until the entry for `id` is a tombstone.
fn gre1881_wait_tombstone(coordinator: &mut Coordinator, id: u16, timeout_ms: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        coordinator.reconcile_local_tunnel_liveness(None);
        match coordinator.tunnel_sources.get(&id) {
            Some(entry) if entry.handle.is_none() => return true,
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// THE bug pin (#1881 F3): a same-plan refresh that adds a GRE tunnel
/// must create the local-origin entry AND publish its delivery sender.
/// Fails on master, where refresh never reconciled tunnel_sources.
#[test]
fn gre1881_refresh_creates_entry_and_publishes_delivery() {
    let mut coordinator = gre1881_coordinator_with_worker();
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36281, "gre1881a", "198.51.100.7"));
    let entry = coordinator
        .tunnel_sources
        .get(&1)
        .expect("GRE local-origin entry created on armed refresh");
    assert_eq!(entry.spawned_ifindex, 36281);
    assert_eq!(entry.spawned_tunnel_name, "gre1881a");
    assert!(entry.handle.is_some(), "live handle right after spawn");
    assert!(
        coordinator
            .local_tunnel_deliveries
            .load()
            .contains_key(&36281),
        "delivery sender published for the spawned ifindex"
    );
}

/// #1881 F4: a refresh that REMOVES the tunnel stops + joins the
/// thread, removes the entry, and unpublishes the delivery sender.
#[test]
fn gre1881_removal_refresh_prunes_entry_and_unpublishes() {
    let mut coordinator = gre1881_coordinator_with_worker();
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36282, "gre1881b", "198.51.100.7"));
    assert!(coordinator.tunnel_sources.contains_key(&1));
    coordinator.refresh_runtime_snapshot(&ConfigSnapshot::default());
    assert!(
        coordinator.tunnel_sources.is_empty(),
        "removed endpoint prunes the entry"
    );
    assert!(
        coordinator.local_tunnel_deliveries.load().is_empty(),
        "removed endpoint unpublishes the delivery sender"
    );
}

/// #1881 plan SMR-1: the deferred same-plan window reaches the armed
/// refresh with ZERO worker handles — the spawn pass must do nothing.
#[test]
fn gre1881_no_workers_spawn_gate() {
    let mut coordinator = Coordinator::new();
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36283, "gre1881c", "198.51.100.7"));
    assert!(
        coordinator.tunnel_sources.is_empty(),
        "no spawn without live worker handles (frozen empty captures)"
    );
    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
}

/// #1881 core property: endpoint CONTENT changes (destination edit,
/// same id + same attachment) must NOT restart the thread — the live
/// loop tracks them through the shared forwarding ArcSwap. No respawn
/// means the spawn-attempt stamp is untouched.
#[test]
fn gre1881_destination_edit_preserves_entry_without_respawn() {
    let mut coordinator = gre1881_coordinator_with_worker();
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36284, "gre1881d", "198.51.100.7"));
    let stamp = coordinator
        .tunnel_sources
        .get(&1)
        .expect("entry")
        .last_spawn_attempt_ns;
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36284, "gre1881d", "203.0.113.9"));
    let entry = coordinator
        .tunnel_sources
        .get(&1)
        .expect("destination edit keeps the entry");
    assert_eq!(
        entry.last_spawn_attempt_ns, stamp,
        "destination-only edit must not respawn (no TUN churn)"
    );
}

/// #1881: attachment drift (same id, new logical ifindex) is the ONLY
/// restart condition — the TUN fd is bound to the old netdev.
#[test]
fn gre1881_attachment_change_restarts_thread() {
    let mut coordinator = gre1881_coordinator_with_worker();
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36285, "gre1881e", "198.51.100.7"));
    let stamp = coordinator
        .tunnel_sources
        .get(&1)
        .expect("entry")
        .last_spawn_attempt_ns;
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36286, "gre1881e", "198.51.100.7"));
    let entry = coordinator
        .tunnel_sources
        .get(&1)
        .expect("reattached endpoint respawned");
    assert_eq!(entry.spawned_ifindex, 36286, "entry re-spawned on the new ifindex");
    assert!(
        entry.last_spawn_attempt_ns > stamp,
        "attachment change respawns (fresh attempt stamp)"
    );
    let deliveries = coordinator.local_tunnel_deliveries.load();
    assert!(deliveries.contains_key(&36286));
    assert!(
        !deliveries.contains_key(&36285),
        "old attachment's sender unpublished"
    );
}

/// #1881 / Codex plan r1 MAJOR 1 companion: a same-id mode flip
/// gre→wireguard (reachable because ids are name-derived) prunes the
/// GRE entry; the WG pass owns the id from then on.
#[test]
fn gre1881_mode_flip_to_wireguard_prunes_gre_entry() {
    let mut coordinator = gre1881_coordinator_with_worker();
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36287, "gre1881f", "198.51.100.7"));
    assert!(coordinator.tunnel_sources.contains_key(&1));
    coordinator
        .refresh_runtime_snapshot(&wg1866_snapshot(1, 36287, "gre1881f", 51899, WG1866_PRIVKEY_A));
    assert!(
        !coordinator.tunnel_sources.contains_key(&1),
        "mode flip prunes the GRE local-origin entry"
    );
    assert!(
        coordinator.wg_control_threads.contains_key(&1),
        "the WG pass owns the id after the flip"
    );
    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
}

/// #1881 (mirrors the #1866 disarmed rule): a disarmed same-plan
/// refresh stops all GRE local-origin threads and empties the
/// delivery map (plan SMR2-2).
#[test]
fn gre1881_disarmed_refresh_stops_threads() {
    let mut coordinator = gre1881_coordinator_with_worker();
    let snap = gre1881_snapshot(1, 36288, "gre1881g", "198.51.100.7");
    coordinator.refresh_runtime_snapshot(&snap);
    assert!(coordinator.tunnel_sources.contains_key(&1));
    coordinator.refresh_runtime_snapshot_disarmed(&snap);
    assert!(
        coordinator.tunnel_sources.is_empty(),
        "disarmed refresh must not hold TUN reader fds"
    );
    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
}

/// #1881 (mirrors #1866 Change 2b): the defer-workers narrow prune
/// removes entries absent from (or no longer gre/ip6gre in) the new
/// snapshot and keeps the rest.
#[test]
fn gre1881_defer_prune_removes_only_stale_entries() {
    let mut coordinator = gre1881_coordinator_with_worker();
    let snap = gre1881_snapshot(1, 36289, "gre1881h", "198.51.100.7");
    coordinator.refresh_runtime_snapshot(&snap);
    assert!(coordinator.tunnel_sources.contains_key(&1));
    // Same snapshot: nothing pruned.
    coordinator.prune_local_tunnel_sources_for_snapshot(&snap);
    assert!(coordinator.tunnel_sources.contains_key(&1));
    // Same id, MOVED attachment (Codex code r1): the defer branch
    // never rotates forwarding, so the prune itself must catch
    // attachment drift against the entry's spawned attachment.
    let moved = gre1881_snapshot(1, 46289, "gre1881h", "198.51.100.7");
    coordinator.prune_local_tunnel_sources_for_snapshot(&moved);
    assert!(
        coordinator.tunnel_sources.is_empty(),
        "same-id attachment drift must prune on the defer path"
    );
    assert!(coordinator.local_tunnel_deliveries.load().is_empty());

    // Re-arm an entry and verify full removal still prunes.
    coordinator.refresh_runtime_snapshot(&snap);
    assert!(coordinator.tunnel_sources.contains_key(&1));
    coordinator.prune_local_tunnel_sources_for_snapshot(&ConfigSnapshot::default());
    assert!(coordinator.tunnel_sources.is_empty());
    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
}

/// #1881 F6: a thread that exits (open_tun failure here) is
/// tombstoned by the periodic liveness sweep — which must ALSO
/// unpublish its delivery sender (Codex plan r1 R3) — and respawns
/// past the backoff only when the stored snapshot is coherent with
/// the forwarding attachment.
#[test]
fn gre1881_exit_tombstones_sweep_unpublishes_and_respawn_is_coherence_gated() {
    let mut coordinator = gre1881_coordinator_with_worker();
    let snap = gre1881_snapshot(1, 36290, "gre1881i", "198.51.100.7");
    coordinator.refresh_runtime_snapshot(&snap);
    assert!(
        gre1881_wait_tombstone(&mut coordinator, 1, 2_000),
        "open_tun failure tombstones the entry"
    );
    assert!(
        coordinator.local_tunnel_deliveries.load().is_empty(),
        "sweep republishes the delivery map without the dead sender"
    );
    // Incoherent snapshot (attachment mismatch): no respawn even past
    // the backoff.
    coordinator
        .tunnel_sources
        .get_mut(&1)
        .expect("tombstone")
        .last_spawn_attempt_ns = 0;
    let mismatched = gre1881_snapshot(1, 99999, "gre1881i", "198.51.100.7");
    coordinator.reconcile_local_tunnel_liveness(Some(&mismatched));
    assert_eq!(
        coordinator
            .tunnel_sources
            .get(&1)
            .expect("tombstone retained")
            .last_spawn_attempt_ns,
        0,
        "incoherent snapshot must not respawn"
    );
    // Coherent snapshot past the backoff: one respawn attempt.
    coordinator.reconcile_local_tunnel_liveness(Some(&snap));
    assert!(
        coordinator
            .tunnel_sources
            .get(&1)
            .expect("entry retained")
            .last_spawn_attempt_ns
            > 0,
        "tombstone respawned past backoff with a coherent snapshot"
    );
}

/// #1881: after stop_inner the entry map and delivery map are empty,
/// and a subsequent liveness sweep cannot create entries (tombstone-
/// only rule), even with a coherent snapshot.
#[test]
fn gre1881_stop_inner_clears_and_sweep_creates_nothing() {
    let mut coordinator = gre1881_coordinator_with_worker();
    let snap = gre1881_snapshot(1, 36291, "gre1881j", "198.51.100.7");
    coordinator.refresh_runtime_snapshot(&snap);
    assert!(coordinator.tunnel_sources.contains_key(&1));
    coordinator.stop_inner(false);
    assert!(coordinator.tunnel_sources.is_empty(), "stop clears entries");
    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
    for _ in 0..3 {
        coordinator.reconcile_local_tunnel_liveness(Some(&snap));
        assert!(
            coordinator.tunnel_sources.is_empty(),
            "liveness sweep never creates entries"
        );
    }
}

// ---------------------------------------------------------------------------
// #2440 — reconcile must NOT publish a newer forwarding generation (or tear
// down the prior workers) when a mandatory BPF map FD fails to open. The
// mandatory map open (xsk/heartbeat/sessions) is the real correctness
// boundary, so it runs in a PREFLIGHT before teardown/publish.
// ---------------------------------------------------------------------------

/// Build a minimal snapshot whose three mandatory map pins are populated
/// with sentinel paths (see `bpf_map::pin`): xsk + heartbeat resolve to
/// dummy fds, while `sessions` is forced to fail its open. This isolates
/// the failure to the third mandatory open without any real bpffs pins.
/// `generation` is the new generation the reconcile would publish if it
/// ran to completion.
fn fail_open_snapshot(generation: u64) -> ConfigSnapshot {
    ConfigSnapshot {
        generation,
        map_pins: crate::protocol::snapshot::MapPins {
            xsk: format!("{TEST_MAP_PIN_OK}xsk"),
            heartbeat: format!("{TEST_MAP_PIN_OK}heartbeat"),
            sessions: format!("{TEST_MAP_PIN_FAIL}sessions"),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// fail-on-revert regression: with `map_pins.sessions` unopenable, the
/// reconcile must abort in the preflight — leaving the previously
/// published generation intact and NOT advancing `snapshot_installed`
/// / `config_generation`. The xsk + heartbeat opens are forced to
/// "succeed" (dummy fds) so the failure is isolated to the session map,
/// exercising the third mandatory open specifically.
///
/// Fail-on-revert proof: if the fix is reverted so publish happens
/// before the open (the pre-#2440 order), the reconcile stamps the new
/// generation into `validation` + `shared_validation` BEFORE the session
/// open fails, and every assertion below that the prior generation
/// survives will fail.
#[test]
fn reconcile_mandatory_map_open_failure_keeps_prior_generation_published() {
    let mut coordinator = Coordinator::new();

    // Seed a prior, successfully-published forwarding generation. This
    // stands in for "stale-but-correct state backed by running workers".
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 7,
        fib_generation: 3,
    };
    coordinator.validation = prior;
    coordinator.shared_validation.store(Arc::new(prior));

    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        worker_id: 0,
        queue_id: 0,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        bound: true,
        ready: true,
        ..BindingStatus::default()
    }];

    // `fail_open_snapshot` wires xsk + heartbeat to "succeed" (dummy
    // fds) and `sessions` to fail its open, so the failure is isolated
    // to the third mandatory open. The optional maps (conntrack/dnat)
    // are empty so they are never opened.
    coordinator.reconcile(Some(&fail_open_snapshot(8)), &mut bindings, 64);

    // The reconcile aborted at the session-map open.
    assert!(
        coordinator
            .last_reconcile_stage
            .starts_with("open_session_map_failed:"),
        "expected abort at session-map open, got {:?}",
        coordinator.last_reconcile_stage
    );

    // FAIL-ON-REVERT CORE: the prior generation is still the published
    // one. A pre-#2440 publish-before-open would have advanced these to
    // generation 8 before the session open failed.
    assert_eq!(
        coordinator.validation.config_generation, 7,
        "config_generation must NOT advance on a mandatory-FD failure"
    );
    assert_eq!(
        coordinator.validation.fib_generation, 3,
        "fib_generation must NOT advance on a mandatory-FD failure"
    );
    assert!(
        coordinator.validation.snapshot_installed,
        "snapshot_installed must stay at its prior value"
    );
    let shared = **coordinator.shared_validation.load();
    assert_eq!(
        shared.config_generation, 7,
        "shared_validation (the worker-visible view) must still hold the prior generation"
    );
    assert_eq!(shared, prior, "shared_validation must equal the prior published state");

    // The registered binding records the open failure for the operator.
    assert!(
        bindings[0].last_error.starts_with("open session map:"),
        "expected per-binding last_error to record the session-map open failure, got {:?}",
        bindings[0].last_error
    );

    // No workers were brought up (the abort precedes bring-up).
    assert!(
        coordinator.workers.live.is_empty(),
        "no workers should be live after an aborted reconcile"
    );
}

/// A missing (empty) mandatory pin string must abort in the preflight
/// the same way an unopenable FD does — before any publish.
#[test]
fn reconcile_missing_session_pin_keeps_prior_generation_published() {
    let mut coordinator = Coordinator::new();
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 11,
        fib_generation: 5,
    };
    coordinator.validation = prior;
    coordinator.shared_validation.store(Arc::new(prior));

    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        ..BindingStatus::default()
    }];

    // Mandatory xsk + heartbeat present, sessions deliberately empty.
    let mut snap = fail_open_snapshot(12);
    snap.map_pins.sessions = String::new();

    coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert_eq!(
        coordinator.last_reconcile_stage, "missing_session_pin",
        "expected abort at the missing-session-pin guard"
    );
    assert_eq!(coordinator.validation.config_generation, 11);
    assert_eq!((**coordinator.shared_validation.load()).config_generation, 11);
    assert_eq!(
        bindings[0].last_error, "missing session map pin path",
        "expected per-binding last_error for the missing session pin"
    );
}

/// Positive control: when all mandatory pins open, the reconcile
/// proceeds past the preflight and DOES advance the published
/// generation (proving the preflight is not over-gating legitimate
/// applies). Bring-up itself is exercised by the broader reconcile
/// fixtures; here we only assert the publish happened.
#[test]
fn reconcile_all_mandatory_maps_open_advances_published_generation() {
    let mut coordinator = Coordinator::new();
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 1,
        fib_generation: 0,
    };
    coordinator.validation = prior;
    coordinator.shared_validation.store(Arc::new(prior));

    let mut bindings: Vec<BindingStatus> = Vec::new();

    // All three mandatory pins resolve to dummy fds (sentinel-OK), so
    // the preflight passes and the reconcile proceeds to publish.
    let mut snap = fail_open_snapshot(2);
    snap.map_pins.sessions = format!("{TEST_MAP_PIN_OK}sessions");
    coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert_eq!(
        coordinator.validation.config_generation, 2,
        "a fully-openable snapshot must advance the published generation"
    );
    assert_eq!((**coordinator.shared_validation.load()).config_generation, 2);
}

/// #2484 (completes the #2440/#2444 fail-open trilogy): a snapshot
/// INTEGRITY fault must abort the reconcile BEFORE `tear_down`, keeping
/// the prior generation published AND the prior workers/state live — not
/// merely record an observable stage post-teardown.
///
/// Seam: a NAT64 rule with an empty prefix trips
/// `Nat64State::try_from_snapshots` (Nat64UnparseableRule). That path is
/// NOT checked by the top-of-reconcile policy preflight (which only parses
/// the policy/address-book state), so before #2484 it reached the
/// `apply_snapshot` integrity Err arm — which ran AFTER `tear_down`
/// (`stop_inner`) had already reset `coord.validation`,
/// `shared_validation`, `snapshot_installed`, and stopped the workers.
/// #2484 hoists the full forwarding build into the pre-teardown preflight
/// (`build_reconcile_forwarding`), so the fault is now detected with the
/// prior state still live. Map pins are sentinel-OK so the map-FD preflight
/// passes and the integrity check is what fires.
///
/// Fail-on-revert: this is the KEY difference from the pre-#2484 test
/// (which asserted only the stage + non-installation, because the check was
/// post-teardown). With the fix reverted — integrity build back inside
/// `apply_snapshot`, after `tear_down` — `stop_inner` resets
/// `coord.validation` (config_generation -> 0, snapshot_installed -> false)
/// and `shared_validation` to default, so EVERY preservation assertion
/// below fails. The stage assertion alone is NOT revert-sensitive (both the
/// old post-teardown leg and the new pre-teardown leg set it); the
/// preservation assertions are.
#[test]
fn reconcile_snapshot_integrity_error_preserves_prior_generation_and_state() {
    let mut coordinator = Coordinator::new();
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 20,
        fib_generation: 7,
    };
    coordinator.validation = prior;
    coordinator.shared_validation.store(Arc::new(prior));

    // Seed a sentinel live worker. `tear_down` -> `stop_inner` ->
    // `workers.stop_and_clear` would empty `workers.live`; if the integrity
    // fault is (correctly) detected before teardown, this entry survives.
    // This is the direct "prior workers are NOT torn down" proof.
    coordinator
        .workers
        .live
        .insert(0, std::sync::Arc::new(BindingLiveState::new()));

    let mut bindings: Vec<BindingStatus> = Vec::new();

    // Sentinel-OK mandatory pins (preflight passes) + a NAT64 rule with
    // an empty prefix (integrity Err in build_forwarding_state).
    let mut snap = fail_open_snapshot(21);
    snap.map_pins.sessions = format!("{TEST_MAP_PIN_OK}sessions");
    snap.nat64_rules = vec![crate::protocol::NAT64RuleSnapshot {
        name: "bad-nat64".to_string(),
        prefix: String::new(),
        ..Default::default()
    }];

    coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert_eq!(
        coordinator.last_reconcile_stage, "snapshot_integrity_error",
        "integrity-error leg must record an observable stage, got {:?}",
        coordinator.last_reconcile_stage
    );

    // FAIL-ON-REVERT CORE: the prior generation is still the published one,
    // proving the integrity fault aborted BEFORE `tear_down`. A pre-#2484
    // post-teardown reject would have run `stop_inner`, defaulting these.
    assert_eq!(
        coordinator.validation.config_generation, 20,
        "integrity reject must PRESERVE the prior generation (not tear down)"
    );
    assert_eq!(
        coordinator.validation.fib_generation, 7,
        "integrity reject must PRESERVE the prior fib generation"
    );
    assert!(
        coordinator.validation.snapshot_installed,
        "integrity reject must keep snapshot_installed (stop_inner would clear it)"
    );
    let shared = **coordinator.shared_validation.load();
    assert_eq!(
        shared, prior,
        "shared_validation (worker-visible view) must still hold the prior published state"
    );
    // The rejected generation is never published anywhere.
    assert_ne!(coordinator.validation.config_generation, 21);
    assert_ne!(shared.config_generation, 21);

    // FAIL-ON-REVERT (worker preservation): the seeded prior worker is
    // still present — `tear_down`/`stop_inner`/`stop_and_clear` was never
    // reached. A pre-#2484 post-teardown reject would have emptied
    // `workers.live` before the integrity fault was detected.
    assert_eq!(
        coordinator.workers.live.len(),
        1,
        "integrity reject must PRESERVE the prior workers (not tear them down)"
    );
    assert!(
        coordinator.workers.live.contains_key(&0),
        "the seeded prior worker (slot 0) must survive an integrity-faulted reconcile"
    );
}

// ---------------------------------------------------------------------------
// #2444 — an OPTIONAL map (conntrack v4/v6, dnat tables) whose pin is
// PRESENT but fails to open must fail closed exactly like a mandatory map:
// abort the reconcile in the preflight BEFORE teardown/publish, keeping the
// prior generation + workers live. An EMPTY pin (feature genuinely absent)
// must still reconcile normally — the anti-over-gate control.
// ---------------------------------------------------------------------------

/// Build a snapshot whose three mandatory pins are sentinel-OK (so the
/// mandatory preflight passes) and `generation` is the new generation the
/// reconcile would publish if it ran to completion. Optional pins are left
/// empty by the caller unless explicitly set.
fn mandatory_ok_snapshot(generation: u64) -> ConfigSnapshot {
    ConfigSnapshot {
        generation,
        map_pins: crate::protocol::snapshot::MapPins {
            xsk: format!("{TEST_MAP_PIN_OK}xsk"),
            heartbeat: format!("{TEST_MAP_PIN_OK}heartbeat"),
            sessions: format!("{TEST_MAP_PIN_OK}sessions"),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// fail-on-revert: a PRESENT conntrack_v4 pin that fails to open must
/// abort the reconcile in the preflight, leaving the prior published
/// generation intact and recording an observable
/// `open_conntrack_v4_map_failed:` stage.
///
/// Fail-on-revert proof: restoring the pre-#2444
/// `open_bpf_map(...).ok()` swallows the open error -> the optional map
/// silently becomes `None`, the reconcile proceeds, and `config_generation`
/// wrongly advances to the new generation. Every assertion below that the
/// prior generation survives then fails.
#[test]
fn reconcile_present_conntrack_pin_open_failure_keeps_prior_generation() {
    let mut coordinator = Coordinator::new();
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 30,
        fib_generation: 9,
    };
    coordinator.validation = prior;
    coordinator.shared_validation.store(Arc::new(prior));

    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        ..BindingStatus::default()
    }];

    // Mandatory pins OK; conntrack_v4 pin PRESENT but forced to fail open.
    let mut snap = mandatory_ok_snapshot(31);
    snap.map_pins.conntrack_v4 = format!("{TEST_MAP_PIN_FAIL}conntrack_v4");

    coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert!(
        coordinator
            .last_reconcile_stage
            .starts_with("open_conntrack_v4_map_failed:"),
        "expected abort at the conntrack_v4 open, got {:?}",
        coordinator.last_reconcile_stage
    );

    // FAIL-ON-REVERT CORE: the prior generation is still published.
    assert_eq!(
        coordinator.validation.config_generation, 30,
        "config_generation must NOT advance on a present-but-unopenable optional map"
    );
    assert_eq!(coordinator.validation.fib_generation, 9);
    assert_eq!(
        (**coordinator.shared_validation.load()).config_generation,
        30,
        "shared_validation must still hold the prior generation"
    );
    assert!(
        bindings[0]
            .last_error
            .starts_with("open conntrack_v4 map:"),
        "expected per-binding last_error for the conntrack_v4 open failure, got {:?}",
        bindings[0].last_error
    );
    assert!(
        coordinator.workers.live.is_empty(),
        "no workers should be live after an aborted reconcile"
    );
}

/// fail-on-revert: same fail-closed behavior for a PRESENT dnat_table pin
/// that fails to open (embedded-ICMP NAT reversal feature configured but
/// unopenable -> must block, not run degraded).
#[test]
fn reconcile_present_dnat_pin_open_failure_keeps_prior_generation() {
    let mut coordinator = Coordinator::new();
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 40,
        fib_generation: 12,
    };
    coordinator.validation = prior;
    coordinator.shared_validation.store(Arc::new(prior));

    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        ..BindingStatus::default()
    }];

    // Mandatory + conntrack pins OK; dnat_table pin PRESENT but fails open.
    let mut snap = mandatory_ok_snapshot(41);
    snap.map_pins.dnat_table = format!("{TEST_MAP_PIN_FAIL}dnat_table");

    coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert!(
        coordinator
            .last_reconcile_stage
            .starts_with("open_dnat_table_map_failed:"),
        "expected abort at the dnat_table open, got {:?}",
        coordinator.last_reconcile_stage
    );
    assert_eq!(
        coordinator.validation.config_generation, 40,
        "config_generation must NOT advance on a present-but-unopenable dnat map"
    );
    assert_eq!(
        (**coordinator.shared_validation.load()).config_generation,
        40
    );
    assert!(
        bindings[0].last_error.starts_with("open dnat_table map:"),
        "expected per-binding last_error for the dnat_table open failure, got {:?}",
        bindings[0].last_error
    );
}

/// ANTI-OVER-GATE control: when the optional conntrack/dnat pins are EMPTY
/// (feature genuinely absent — the common deploy), the reconcile must NOT
/// be gated: the preflight returns `None` silently for each empty pin and
/// the reconcile proceeds to publish the new generation. This guards
/// against the fix being too aggressive (treating "feature absent" as a
/// failure).
#[test]
fn reconcile_empty_optional_pins_advance_published_generation() {
    let mut coordinator = Coordinator::new();
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 50,
        fib_generation: 0,
    };
    coordinator.validation = prior;
    coordinator.shared_validation.store(Arc::new(prior));

    let mut bindings: Vec<BindingStatus> = Vec::new();

    // Mandatory pins OK; ALL optional pins left empty (the default).
    let snap = mandatory_ok_snapshot(51);
    assert!(snap.map_pins.conntrack_v4.is_empty());
    assert!(snap.map_pins.conntrack_v6.is_empty());
    assert!(snap.map_pins.dnat_table.is_empty());
    assert!(snap.map_pins.dnat_table_v6.is_empty());

    coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert_eq!(
        coordinator.validation.config_generation, 51,
        "empty optional pins must NOT gate the reconcile (anti-over-gate)"
    );
    assert_eq!(
        (**coordinator.shared_validation.load()).config_generation,
        51
    );
}

/// Positive control: PRESENT optional pins that OPEN OK must reconcile
/// normally and advance the published generation (the fix accepts a
/// healthy configured map).
#[test]
fn reconcile_present_optional_pins_open_ok_advance_generation() {
    let mut coordinator = Coordinator::new();
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 60,
        fib_generation: 0,
    };
    coordinator.validation = prior;
    coordinator.shared_validation.store(Arc::new(prior));

    let mut bindings: Vec<BindingStatus> = Vec::new();

    // Mandatory + all optional pins sentinel-OK (present + openable).
    let mut snap = mandatory_ok_snapshot(61);
    snap.map_pins.conntrack_v4 = format!("{TEST_MAP_PIN_OK}conntrack_v4");
    snap.map_pins.conntrack_v6 = format!("{TEST_MAP_PIN_OK}conntrack_v6");
    snap.map_pins.dnat_table = format!("{TEST_MAP_PIN_OK}dnat_table");
    snap.map_pins.dnat_table_v6 = format!("{TEST_MAP_PIN_OK}dnat_table_v6");

    coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert_eq!(
        coordinator.validation.config_generation, 61,
        "present + openable optional maps must reconcile normally"
    );
    assert_eq!(
        (**coordinator.shared_validation.load()).config_generation,
        61
    );
}
