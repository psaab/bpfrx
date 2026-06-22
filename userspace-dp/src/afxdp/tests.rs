use super::test_fixtures::*;
use super::*;
use crate::test_zone_ids::*;
use crate::xsk_ffi::IfInfo;
use crate::{
    DestinationNATRuleSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot,
    InterfaceAddressSnapshot, NeighborSnapshot, PolicyRuleSnapshot, RouteSnapshot,
    SourceNATRuleSnapshot, StaticNATRuleSnapshot, ThreeColorPolicerSnapshot, ZoneSnapshot,
};

#[test]
fn mlx5_keeps_umem_owner_bind_strategy() {
    assert_eq!(
        bind_strategy_for_driver(Some("mlx5_core")),
        AfXdpBindStrategy::UmemOwnerSocket
    );
    assert_eq!(
        alternate_bind_strategy(Some("mlx5_core"), AfXdpBindStrategy::UmemOwnerSocket),
        None
    );
}

#[test]
fn virtio_uses_auto_mode_umem_owner_strategy() {
    assert_eq!(
        bind_strategy_for_driver(Some("virtio_net")),
        AfXdpBindStrategy::UmemOwnerSocket
    );
    assert_eq!(
        alternate_bind_strategy(Some("virtio_net"), AfXdpBindStrategy::UmemOwnerSocket,),
        None
    );
    assert_eq!(
        binder_for_strategy(AfXdpBindStrategy::UmemOwnerSocket),
        AfXdpBinder::Umem
    );
    assert_eq!(bind_flag_candidates_for_driver(Some("virtio_net")), &[0]);
    assert_eq!(
        bind_flag_candidates_for_driver(Some("mlx5_core")),
        &[XSK_BIND_FLAGS_ZEROCOPY, XSK_BIND_FLAGS_COPY]
    );
}

#[test]
fn shared_umem_socket_roles_use_kernel_legal_bind_flags() {
    let mut info = IfInfo::invalid();
    info.set_queue(0);

    assert_eq!(
        bind_flag_candidates_for_socket_role(&info, Some("mlx5_core"), XskSocketRole::SharedOwner),
        &[XSK_BIND_FLAGS_ZEROCOPY]
    );

    let secondary = bind_flag_candidates_for_socket_role(
        &info,
        Some("mlx5_core"),
        XskSocketRole::SharedSecondary,
    );
    assert_eq!(secondary, &[SocketConfig::XDP_BIND_SHARED_UMEM]);
    assert_eq!(secondary[0] & SocketConfig::XDP_BIND_COPY, 0);
    assert_eq!(secondary[0] & SocketConfig::XDP_BIND_ZEROCOPY, 0);
    assert_eq!(secondary[0] & SocketConfig::XDP_BIND_NEED_WAKEUP, 0);
    assert_eq!(describe_bind_flags(secondary[0]), "shared-umem");
}

#[test]
fn shared_umem_group_key_is_same_device_mlx5_only() {
    assert_eq!(
        shared_umem_group_key_for_device(
            Some("mlx5_core"),
            Some("/sys/devices/pci0000:00/0000:08:00.0")
        ),
        Some("mlx5:/sys/devices/pci0000:00/0000:08:00.0".to_string())
    );
    assert_eq!(
        shared_umem_group_key_for_device(
            Some("virtio_net"),
            Some("/sys/devices/pci0000:00/0000:00:07.0")
        ),
        None
    );
    assert_eq!(
        shared_umem_group_key_for_device(Some("mlx5_core"), None),
        None
    );
}

#[test]
fn split_owner_fabric_redirect_skips_local_reverse_placeholder() {
    let decision = SessionDecision {
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
    };

    assert!(!should_install_local_reverse_session(decision, true));
    assert!(!should_install_local_reverse_session(decision, false));
}

#[test]
fn fabric_redirect_reply_from_real_fabric_ingress_keeps_local_reverse() {
    let decision = SessionDecision {
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
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            ..NatDecision::default()
        },
    };

    assert!(should_install_local_reverse_session(decision, true));
    assert!(!should_install_local_reverse_session(decision, false));
}

#[test]
fn cloned_worker_umem_shares_allocation_identity() {
    let shared = match WorkerUmem::new(64) {
        Ok(shared) => shared,
        Err(err) => {
            eprintln!("skipping UMEM identity test: {err}");
            return;
        }
    };
    let shared_clone = shared.clone();
    let private = match WorkerUmem::new(64) {
        Ok(private) => private,
        Err(err) => {
            eprintln!("skipping UMEM identity test: {err}");
            return;
        }
    };
    assert!(shared.shares_allocation_with(&shared_clone));
    assert!(!shared.shares_allocation_with(&private));
}

#[test]
fn worker_binding_lookup_prefers_same_queue_binding() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_if_queue.insert((5, 0), 0);
    lookup.by_if_queue.insert((5, 1), 1);
    lookup.first_by_if.insert(5, 0);
    lookup.all_by_if.insert(5, vec![0, 1]);

    assert_eq!(lookup.target_index(2, 7, 1, 5), Some(1));
    assert_eq!(lookup.target_index(2, 7, 3, 5), Some(0));
    assert_eq!(lookup.target_index(2, 5, 1, 5), Some(2));
}

#[test]
fn worker_binding_lookup_hashes_fabric_target_across_queues() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.all_by_if.insert(5, vec![10, 11, 12, 13]);

    let indices = [
        lookup.fabric_target_index(5, 0),
        lookup.fabric_target_index(5, 1),
        lookup.fabric_target_index(5, 2),
        lookup.fabric_target_index(5, 3),
    ];
    assert_eq!(indices, [Some(10), Some(11), Some(12), Some(13)]);
}

#[test]
fn worker_binding_lookup_resolves_slot_index() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(11, 3);
    assert_eq!(lookup.slot_index(11), Some(3));
    assert_eq!(lookup.slot_index(99), None);
}

#[test]
fn build_live_forward_request_from_frame_uses_precomputed_hints() {
    let lookup = WorkerBindingLookup::default();
    let ingress_ident = BindingIdentity {
        slot: 7,
        queue_id: 3,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };
    let desc = XdpDesc {
        addr: 0,
        len: 0,
        options: 0,
    };
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    };
    let hints = PendingForwardHints {
        expected_ports: Some((12345, 5201)),
        target_binding_index: Some(9),
    };

    let req = build_live_forward_request_from_frame(
        &lookup,
        2,
        &ingress_ident,
        desc,
        &[],
        meta,
        &decision,
        &ForwardingState::default(),
        None,
        None,
        false,
        0,
        None,
        Some(hints),
        None,
    )
    .expect("request");

    assert_eq!(req.expected_ports, hints.expected_ports);
    assert_eq!(req.target_binding_index, hints.target_binding_index);
    assert_eq!(req.target_ifindex, 11);
}

#[test]
fn build_live_forward_request_from_frame_drops_logged_output_filter_discard() {
    let lookup = WorkerBindingLookup::default();
    let ingress_ident = BindingIdentity {
        slot: 7,
        queue_id: 3,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 10,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 60,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        },
    };
    let forwarding = build_forwarding_state(&ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 12,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-drop".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-drop".into(),
            family: "inet".into(),
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
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let req = build_live_forward_request_from_frame(
        &lookup,
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: 0,
            options: 0,
        },
        &[],
        meta,
        &decision,
        &forwarding,
        Some(&flow),
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
    );

    assert!(req.is_none(), "terminal output filter must not forward");
    let event = event_rx
        .try_recv()
        .expect("output filter-log frame")
        .decode_dataplane_event()
        .expect("filter-log payload");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::FilterLog
    );
    assert_eq!(event.action, 0, "discard must encode RT_FLOW deny");
    assert_eq!(
        event.reason,
        FilterLogSource::Output.wire_reason(),
        "live output filter source must not be mislabeled",
    );
}

#[test]
fn icmp_reverse_key_keeps_identifier_position() {
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 0x1234,
            dst_port: 0,
        },
    };
    let reverse = flow.reverse_key_with_nat(NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        ..NatDecision::default()
    });
    assert_eq!(reverse.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    assert_eq!(reverse.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    assert_eq!(reverse.src_port, 0x1234);
    assert_eq!(reverse.dst_port, 0);
}

#[test]
fn synced_replica_entry_keeps_peer_synced_entries_promotable() {
    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
        decision: SessionDecision {
            resolution: lookup_forwarding_resolution(
                &build_forwarding_state(&nat_snapshot()),
                IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let replica = synced_replica_entry(&entry);
    assert!(replica.origin.is_peer_synced());
    assert!(replica.origin.is_promotable_synced());
    assert_eq!(replica.key, entry.key);
    assert_eq!(replica.decision, entry.decision);
}

#[test]
fn synced_replica_entry_marks_local_entries_worker_local() {
    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
        decision: SessionDecision {
            resolution: lookup_forwarding_resolution(
                &build_forwarding_state(&nat_snapshot()),
                IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let replica = synced_replica_entry(&entry);
    assert_eq!(replica.origin, SessionOrigin::WorkerLocalImport);
    assert!(replica.origin.is_peer_synced());
    assert!(!replica.origin.is_promotable_synced());
    assert_eq!(replica.key, entry.key);
    assert_eq!(replica.decision, entry.decision);
}

#[test]
fn reconcile_stop_preserves_shared_synced_sessions() {
    let mut coordinator = Coordinator::new();
    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
        decision: SessionDecision {
            resolution: lookup_forwarding_resolution(
                &build_forwarding_state(&nat_snapshot()),
                IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry,
    );

    coordinator.stop_inner(false);

    let preserved = coordinator.snapshot_shared_session_entries();
    assert_eq!(preserved.len(), 1);
    assert_eq!(preserved[0].key, entry.key);
    assert_eq!(preserved[0].decision, entry.decision);

    coordinator.stop();
    assert!(coordinator.snapshot_shared_session_entries().is_empty());
}

#[test]
fn replay_synced_sessions_requeues_preserved_entries_for_new_workers() {
    let coordinator = Coordinator::new();
    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
        decision: SessionDecision {
            resolution: lookup_forwarding_resolution(
                &build_forwarding_state(&nat_snapshot()),
                IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let worker_command_queues = BTreeMap::from([
        (0u32, Arc::new(Mutex::new(VecDeque::new()))),
        (1u32, Arc::new(Mutex::new(VecDeque::new()))),
    ]);

    let replayed = coordinator.replay_synced_sessions(&[entry.clone()], &worker_command_queues, -1);
    assert_eq!(replayed, 1);

    for commands in worker_command_queues.values() {
        let pending = commands.lock().expect("worker command queue");
        assert_eq!(pending.len(), 1);
        match pending.front().expect("queued command") {
            WorkerCommand::UpsertSynced(replayed_entry) => {
                assert_eq!(replayed_entry.key, entry.key);
                assert!(replayed_entry.origin.is_peer_synced());
            }
            other => panic!("unexpected command queued during replay: {other:?}"),
        }
    }
}

#[test]
fn resolution_target_uses_rewritten_destination_for_reverse_dnat() {
    let flow = SessionFlow {
        src_ip: IpAddr::V6("2001:559:8585:80::200".parse().expect("src")),
        dst_ip: IpAddr::V6("2001:559:8585:80::8".parse().expect("dst")),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            src_ip: IpAddr::V6("2001:559:8585:80::200".parse().expect("src")),
            dst_ip: IpAddr::V6("2001:559:8585:80::8".parse().expect("dst")),
            src_port: 0x1234,
            dst_port: 0,
        },
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(
                "2001:559:8585:ef00::100".parse().expect("next hop"),
            )),
            neighbor_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: None,
            rewrite_dst: Some(IpAddr::V6("2001:559:8585:ef00::100".parse().expect("lan"))),
            ..NatDecision::default()
        },
    };
    assert_eq!(
        resolution_target_for_session(&flow, decision),
        IpAddr::V6("2001:559:8585:ef00::100".parse().expect("lan"))
    );
}

#[test]
fn session_resolution_falls_back_to_cached_neighbor_on_miss() {
    let mut state = build_forwarding_state(&nat_snapshot());
    state.neighbors.clear();
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let resolved = lookup_forwarding_resolution_for_session(
        &state,
        &Arc::new(ShardedNeighborMap::new()),
        &flow,
        decision,
    );
    let expected_src = state
        .egress
        .get(&12)
        .map(|egress| egress.src_mac)
        .expect("egress src mac");
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(resolved.tx_ifindex, 11);
    assert_eq!(resolved.neighbor_mac, decision.resolution.neighbor_mac);
    assert_eq!(resolved.src_mac, Some(expected_src));
    assert_eq!(resolved.tx_vlan_id, 80);
}

#[test]
fn build_forwarded_frame_rewrites_l2_and_decrements_ttl() {
    let state = build_forwarding_state(&forwarding_snapshot(true));
    let resolution = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 192, 0, 2, 10, 8, 8, 8, 8, 8,
        0, 0, 0, 0x12, 0x34, 0x00, 0x01,
    ]);
    let sum = checksum16(&frame[14..34]);
    frame[24] = (sum >> 8) as u8;
    frame[25] = sum as u8;

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };
    let out = build_forwarded_frame(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &SessionDecision {
            resolution,
            nat: NatDecision::default(),
        },
        &state,
        None,
    )
    .expect("forwarded frame");
    assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    assert_eq!(out[22], 63);
}

#[test]
fn rewrite_forwarded_frame_in_place_reuses_rx_frame() {
    let state = build_forwarding_state(&forwarding_snapshot(true));
    let resolution = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 192, 0, 2, 10, 8, 8, 8, 8, 8,
        0, 0, 0, 0x12, 0x34, 0x00, 0x01,
    ]);
    let sum = checksum16(&frame[14..34]);
    frame[24] = (sum >> 8) as u8;
    frame[25] = sum as u8;

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };
    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &SessionDecision {
            resolution,
            nat: NatDecision::default(),
        },
        false,
        None,
    )
    .expect("in-place forward");
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
    assert_eq!(out[22], 63);
}

#[test]
fn build_forwarded_frame_uses_fabric_header_without_nat() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 10, 0, 61, 100, 172, 16, 80,
        200, 8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01,
    ]);
    let sum = checksum16(&frame[14..34]);
    frame[24] = (sum >> 8) as u8;
    frame[25] = sum as u8;

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };
    let out = build_forwarded_frame(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &SessionDecision {
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
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        &state,
        None,
    )
    .expect("fabric frame");
    assert_eq!(&out[0..6], &[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    assert_eq!(&out[26..30], &[10, 0, 61, 100]);
    assert_eq!(out[22], 63);
}

// --- Static NAT integration tests ---

#[test]
fn static_nat_external_ip_recognized_as_local() {
    let state = build_forwarding_state(&static_nat_snapshot());
    // The external IP 203.0.113.10 should be in local_v4 so traffic
    // destined to it is recognized by the firewall.
    assert!(
        state
            .local_v4
            .contains(&"203.0.113.10".parse::<Ipv4Addr>().unwrap()),
        "static NAT external IP must be in local_v4"
    );
}

#[test]
fn static_nat_dnat_routes_to_internal_ip() {
    let state = build_forwarding_state(&static_nat_snapshot());
    // Simulate inbound: packet from 198.51.100.1 -> 203.0.113.10
    // The static NAT DNAT should match and the resolution should route
    // to the internal host 192.168.1.10 (on trust interface ifindex=5).
    let dnat = state
        .static_nat
        .match_dnat("203.0.113.10".parse().unwrap(), "untrust");
    assert!(dnat.is_some(), "DNAT must match external IP from untrust");
    let dnat = dnat.unwrap();
    assert_eq!(
        dnat.rewrite_dst,
        Some("192.168.1.10".parse::<IpAddr>().unwrap())
    );

    // After DNAT translation, resolution target is internal IP
    let internal_ip: IpAddr = "192.168.1.10".parse().unwrap();
    let resolution =
        lookup_forwarding_resolution_with_dynamic(&state, &Default::default(), internal_ip);
    // Should resolve to trust interface (ifindex 5) via connected route
    assert_eq!(resolution.egress_ifindex, 5);
}

#[test]
fn static_nat_snat_rewrites_outbound_source() {
    let state = build_forwarding_state(&static_nat_snapshot());
    // Simulate outbound: packet from 192.168.1.10 -> 198.51.100.1
    // coming from trust zone. Static NAT SNAT should rewrite src
    // to external IP 203.0.113.10.
    // SNAT does not check from_zone -- internal IP match is sufficient.
    let snat = state
        .static_nat
        .match_snat("192.168.1.10".parse().unwrap(), "trust");
    assert!(
        snat.is_some(),
        "SNAT should match internal IP regardless of zone"
    );
    assert_eq!(
        snat.unwrap().rewrite_src,
        Some("203.0.113.10".parse::<IpAddr>().unwrap())
    );
}

#[test]
fn static_nat_snat_matches_when_zone_is_empty() {
    // Create a snapshot where from_zone is empty (matches any zone)
    let mut snapshot = static_nat_snapshot();
    snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
        counter_id: 0,
        name: "web-server".to_string(),
        from_zone: String::new(), // matches any zone
        external_ip: "203.0.113.10".to_string(),
        internal_ip: "192.168.1.10".to_string(),
    }];
    let state = build_forwarding_state(&snapshot);

    // Now SNAT should match from any zone
    let snat = state
        .static_nat
        .match_snat("192.168.1.10".parse().unwrap(), "trust");
    assert!(snat.is_some());
    let snat = snat.unwrap();
    assert_eq!(
        snat.rewrite_src,
        Some("203.0.113.10".parse::<IpAddr>().unwrap())
    );
    assert!(snat.rewrite_dst.is_none());
}

#[test]
fn static_nat_takes_priority_over_interface_snat() {
    // Create snapshot with both static NAT and interface SNAT
    let mut snapshot = static_nat_snapshot();
    snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
        counter_id: 0,
        name: "static-web".to_string(),
        from_zone: String::new(),
        external_ip: "203.0.113.10".to_string(),
        internal_ip: "192.168.1.10".to_string(),
    }];
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "interface-snat".to_string(),
        from_zone: "trust".to_string(),
        to_zone: "untrust".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);

    // For src=192.168.1.10, static NAT should match first
    let static_match = state
        .static_nat
        .match_snat("192.168.1.10".parse().unwrap(), "trust");
    assert!(
        static_match.is_some(),
        "static NAT should match internal IP"
    );
    assert_eq!(
        static_match.unwrap().rewrite_src,
        Some("203.0.113.10".parse::<IpAddr>().unwrap())
    );
}

#[test]
fn static_nat_v6_dnat_and_snat() {
    let mut snapshot = static_nat_snapshot();
    snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
        counter_id: 0,
        name: "v6-server".to_string(),
        from_zone: String::new(),
        external_ip: "2001:db8::10".to_string(),
        internal_ip: "fd00::10".to_string(),
    }];
    // Add v6 addresses to interfaces
    snapshot.interfaces[0]
        .addresses
        .push(InterfaceAddressSnapshot {
            family: "inet6".to_string(),
            address: "fd00::1/64".to_string(),
            scope: 0,
        });
    snapshot.interfaces[1]
        .addresses
        .push(InterfaceAddressSnapshot {
            family: "inet6".to_string(),
            address: "2001:db8::1/64".to_string(),
            scope: 0,
        });
    let state = build_forwarding_state(&snapshot);

    // External v6 IP should be in local_v6
    assert!(
        state
            .local_v6
            .contains(&"2001:db8::10".parse::<Ipv6Addr>().unwrap())
    );

    // DNAT match
    let dnat = state
        .static_nat
        .match_dnat("2001:db8::10".parse().unwrap(), "any-zone");
    assert!(dnat.is_some());
    assert_eq!(
        dnat.unwrap().rewrite_dst,
        Some("fd00::10".parse::<IpAddr>().unwrap())
    );

    // SNAT match
    let snat = state
        .static_nat
        .match_snat("fd00::10".parse().unwrap(), "trust");
    assert!(snat.is_some());
    assert_eq!(
        snat.unwrap().rewrite_src,
        Some("2001:db8::10".parse::<IpAddr>().unwrap())
    );
}

#[test]
fn post_dnat_source_nat_matches_translated_destination() {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "twice-snat".to_string(),
        from_zone: "wan".to_string(),
        to_zone: "lan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        destination_addresses: vec!["10.0.61.102/32".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    snapshot.destination_nat_rules = vec![DestinationNATRuleSnapshot {
        counter_id: 0,
        name: "web-dnat".to_string(),
        from_zone: "wan".to_string(),
        destination_address: "172.16.80.8".to_string(),
        destination_port: 443,
        protocol: "tcp".to_string(),
        pool_address: "10.0.61.102".to_string(),
        pool_port: 8443,
    }];
    snapshot.policies.push(PolicyRuleSnapshot {
        name: "allow-inbound".to_string(),
        from_zone: "wan".to_string(),
        to_zone: "lan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    });

    let state = build_forwarding_state(&snapshot);
    assert!(
        state
            .local_v4
            .contains(&"172.16.80.8".parse::<Ipv4Addr>().unwrap())
    );

    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 54321,
            dst_port: 443,
        },
    };
    let dnat = state
        .dnat_table
        .lookup(PROTO_TCP, flow.dst_ip, 443, "wan")
        .expect("dnat");
    assert_eq!(
        dnat.rewrite_dst,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
    );
    assert_eq!(dnat.rewrite_dst_port, Some(8443));

    let translated_flow = flow.with_destination(dnat.rewrite_dst.unwrap());
    let snat = match_source_nat_for_flow(&state, "wan", "lan", 24, &translated_flow)
        .expect("snat after dnat");
    assert_eq!(
        snat.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)))
    );

    let merged = dnat.merge(snat);
    assert_eq!(
        merged.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)))
    );
    assert_eq!(
        merged.rewrite_dst,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
    );
    assert_eq!(merged.rewrite_dst_port, Some(8443));
}

#[test]
fn is_icmp_error_identifies_v4_types() {
    // ICMPv4 error types
    assert!(is_icmp_error(PROTO_ICMP, 3)); // Destination Unreachable
    assert!(is_icmp_error(PROTO_ICMP, 11)); // Time Exceeded
    assert!(is_icmp_error(PROTO_ICMP, 12)); // Parameter Problem
    // Non-error types
    assert!(!is_icmp_error(PROTO_ICMP, 0)); // Echo Reply
    assert!(!is_icmp_error(PROTO_ICMP, 8)); // Echo Request
}

#[test]
fn is_icmp_error_identifies_v6_types() {
    // ICMPv6 error types
    assert!(is_icmp_error(PROTO_ICMPV6, 1)); // Destination Unreachable
    assert!(is_icmp_error(PROTO_ICMPV6, 2)); // Packet Too Big
    assert!(is_icmp_error(PROTO_ICMPV6, 3)); // Time Exceeded
    assert!(is_icmp_error(PROTO_ICMPV6, 4)); // Parameter Problem
    // Non-error types
    assert!(!is_icmp_error(PROTO_ICMPV6, 128)); // Echo Request
    assert!(!is_icmp_error(PROTO_ICMPV6, 129)); // Echo Reply
}

#[test]
fn is_icmp_error_rejects_non_icmp_protocols() {
    assert!(!is_icmp_error(PROTO_TCP, 3));
    assert!(!is_icmp_error(PROTO_UDP, 3));
}

#[test]
fn forwarding_state_includes_session_timeouts() {
    let snapshot = nat_snapshot();
    let state = build_forwarding_state(&snapshot);
    // Default timeouts when snapshot has 0 values
    assert_eq!(state.session_timeouts.tcp_established_ns, 300_000_000_000);
    assert_eq!(state.session_timeouts.udp_ns, 60_000_000_000);
    assert_eq!(state.session_timeouts.icmp_ns, 60_000_000_000);
}

#[test]
fn forwarding_state_custom_session_timeouts() {
    let mut snapshot = nat_snapshot();
    snapshot.flow.tcp_session_timeout = 120;
    snapshot.flow.udp_session_timeout = 30;
    snapshot.flow.icmp_session_timeout = 5;
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.session_timeouts.tcp_established_ns, 120_000_000_000);
    assert_eq!(state.session_timeouts.udp_ns, 30_000_000_000);
    assert_eq!(state.session_timeouts.icmp_ns, 5_000_000_000);
}

#[test]
fn forwarding_state_allow_embedded_icmp_wired() {
    let mut snapshot = nat_snapshot();
    assert!(!build_forwarding_state(&snapshot).allow_embedded_icmp);
    snapshot.flow.allow_embedded_icmp = true;
    assert!(build_forwarding_state(&snapshot).allow_embedded_icmp);
}

fn build_icmp_echo_frame_v4(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, ttl, PROTO_ICMP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    let icmp_start = frame.len();
    frame.extend_from_slice(&[8, 0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01]);
    let icmp_csum = checksum16(&frame[icmp_start..]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    frame
}

fn build_icmp_echo_frame_v6(src: Ipv6Addr, dst: Ipv6Addr, hop_limit: u8) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, PROTO_ICMPV6, hop_limit]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let icmp_start = frame.len();
    frame.extend_from_slice(&[128, 0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01]);
    let icmp_csum = checksum16_ipv6(src, dst, PROTO_ICMPV6, &frame[icmp_start..]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    frame
}

#[test]
fn packet_ttl_would_expire_identifies_v4_and_v6() {
    let frame_v4 =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 1);
    let meta_v4 = UserspaceDpMeta {
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(packet_ttl_would_expire(&frame_v4, meta_v4), Some(true));

    let frame_v6 = build_icmp_echo_frame_v6(
        "2001:559:8585:ef00::102".parse().unwrap(),
        "2606:4700:4700::1111".parse().unwrap(),
        2,
    );
    let meta_v6 = UserspaceDpMeta {
        l3_offset: 14,
        addr_family: libc::AF_INET6 as u8,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(packet_ttl_would_expire(&frame_v6, meta_v6), Some(false));
}

#[test]
fn build_local_time_exceeded_request_returns_prebuilt_forward_for_ttl_expiry() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 7,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(client_ip),
        dst_ip: IpAddr::V4(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port: 0x1234,
            dst_port: 1,
        },
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );

    let request = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &ingress_ident,
        &flow,
        &forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut BatchCounters::default(),
    )
    .expect("ttl-expiring session/flow-cache hit should enqueue local TE");

    assert_eq!(request.target_ifindex, 5);
    assert_eq!(request.ingress_queue_id, ingress_ident.queue_id);
    assert_eq!(request.desc.addr, desc.addr);
    assert_eq!(request.flow_key.as_ref(), Some(&flow.forward_key));
    assert!(request.cos_tx_selection_resolved);
    assert!(matches!(request.frame, PendingForwardFrame::Prebuilt(_)));
}

/// #2238: the generated ICMP Time Exceeded is classified by its OWN egress
/// tuple, so an OUTPUT firewall filter + three-color policer on the egress
/// interface (matching `protocol icmp`) drops it — and the drop lands on the
/// dedicated `time_exceeded_output_filter_drops` counter, not the trigger's
/// ingress input policer. Pre-#2238 the trigger's tuple was used, so an
/// *input* policer on the ingress interface keyed off the TCP/UDP trigger;
/// that is exactly the bug this fixes (the reply's own egress treatment was
/// never consulted).
#[test]
fn build_local_time_exceeded_request_classifies_generated_icmp_on_egress() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    // The TRIGGER is a UDP flow (proto 17) — proving the egress filter keys
    // off the GENERATED ICMP reply, not the UDP trigger.
    let frame = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client_ip, dst_ip, 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        pkt_len: 128,
        ..UserspaceDpMeta::default()
    };
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 7,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let flow = icmp_suppress_flow_v4(client_ip, dst_ip);
    // OUTPUT filter on the egress interface (ifindex 5) with a terminal
    // `discard` for `protocol icmp`. The term only fires for the GENERATED
    // ICMP reply (the trigger is UDP), proving classify-by-generated-tuple.
    let filter_state = build_output_filter_state(
        "drop-icmp-out",
        FirewallTermSnapshot {
            name: "drop-icmp".into(),
            action: "discard".into(),
            protocols: vec!["icmp".into()],
            ..Default::default()
        },
    );
    let mut forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ..ForwardingState::default()
    };
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );

    let mut counters = BatchCounters::default();
    let request = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &ingress_ident,
        &flow,
        &forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut counters,
    );

    assert!(
        request.is_none(),
        "egress output-filter `then discard` (protocol icmp) must reject the generated ICMP reply"
    );
    assert_eq!(
        counters.time_exceeded_output_filter_drops, 1,
        "the output-filter drop must land on the dedicated TE counter"
    );
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
}

/// #2238: an output filter matching the INBOUND UDP trigger tuple does NOT
/// drop the generated ICMP error — the discriminating test proving the reply
/// is classified by its OWN (ICMP) tuple, not the trigger's (UDP).
#[test]
fn build_local_time_exceeded_request_ignores_trigger_matching_output_filter() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client_ip, dst_ip, 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        pkt_len: 128,
        ..UserspaceDpMeta::default()
    };
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 7,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let flow = icmp_suppress_flow_v4(client_ip, dst_ip);
    // Output filter discards UDP — but the generated reply is ICMP, so it
    // must NOT be dropped.
    let filter_state = build_output_filter_state(
        "drop-udp-out",
        FirewallTermSnapshot {
            name: "drop-udp".into(),
            action: "discard".into(),
            protocols: vec!["udp".into()],
            ..Default::default()
        },
    );
    let mut forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ..ForwardingState::default()
    };
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );

    let mut counters = BatchCounters::default();
    let request = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &ingress_ident,
        &flow,
        &forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut counters,
    );

    assert!(
        request.is_some(),
        "an output filter matching the UDP trigger must NOT drop the generated ICMP reply"
    );
    assert_eq!(counters.time_exceeded_output_filter_drops, 0);
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
}

/// Build a `ForwardingState.filter_state` with a single egress (output) v4
/// firewall filter on ifindex 5 carrying one term (#2238 test helper).
fn build_output_filter_state(
    filter_name: &str,
    term: FirewallTermSnapshot,
) -> crate::filter::FilterState {
    crate::filter::parse_filter_state(
        &[FirewallFilterSnapshot {
            name: filter_name.into(),
            family: "inet".into(),
            terms: vec![term],
        }],
        &[],
        &[crate::InterfaceSnapshot {
            name: "ge-0/0/1.0".into(),
            ifindex: 5,
            filter_output_v4: filter_name.into(),
            ..Default::default()
        }],
        "",
        "",
    )
}

#[test]
fn build_local_time_exceeded_request_skips_fabric_ingress_packets() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        meta_flags: FABRIC_INGRESS_FLAG,
        ..UserspaceDpMeta::default()
    };
    let desc = XdpDesc {
        addr: 8192,
        len: frame.len() as u32,
        options: 0,
    };
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 7,
        worker_id: 0,
        interface: Arc::<str>::from("fab0"),
        ifindex: 5,
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(client_ip),
        dst_ip: IpAddr::V4(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port: 0x1234,
            dst_port: 1,
        },
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_FABRIC_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );

    let request = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &ingress_ident,
        &flow,
        &forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut BatchCounters::default(),
    );

    assert!(
        request.is_none(),
        "fabric-ingress packets should not enqueue local Time Exceeded"
    );
}

#[test]
fn build_local_time_exceeded_v4_quotes_original_packet() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    let out =
        build_local_time_exceeded_v4(&frame, meta, 5, &forwarding).expect("build local IPv4 TE");
    assert_eq!(&out[0..6], &[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
    assert_eq!(
        Ipv4Addr::new(out[26], out[27], out[28], out[29]),
        Ipv4Addr::new(10, 0, 61, 1)
    );
    assert_eq!(Ipv4Addr::new(out[30], out[31], out[32], out[33]), client_ip);
    assert_eq!(out[34], 11);
    assert_eq!(out[35], 0);
    let quoted_ip_start = 42;
    assert_eq!(
        Ipv4Addr::new(
            out[quoted_ip_start + 12],
            out[quoted_ip_start + 13],
            out[quoted_ip_start + 14],
            out[quoted_ip_start + 15]
        ),
        client_ip
    );
    assert_eq!(
        Ipv4Addr::new(
            out[quoted_ip_start + 16],
            out[quoted_ip_start + 17],
            out[quoted_ip_start + 18],
            out[quoted_ip_start + 19]
        ),
        dst_ip
    );
    assert_eq!(out[quoted_ip_start + 8], 1);
}

#[test]
fn build_local_time_exceeded_v6_quotes_original_packet() {
    let client_ip: Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
    let dst_ip: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    let frame = build_icmp_echo_frame_v6(client_ip, dst_ip, 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: Some("2001:559:8585:ef00::1".parse().unwrap()),
        },
    );
    let out =
        build_local_time_exceeded_v6(&frame, meta, 5, &forwarding).expect("build local IPv6 TE");
    assert_eq!(&out[0..6], &[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x86dd);
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&out[22..38]).unwrap()),
        "2001:559:8585:ef00::1".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&out[38..54]).unwrap()),
        client_ip
    );
    assert_eq!(out[54], 3);
    assert_eq!(out[55], 0);
    let quoted_ip_start = 62;
    assert_eq!(
        Ipv6Addr::from(
            <[u8; 16]>::try_from(&out[quoted_ip_start + 8..quoted_ip_start + 24]).unwrap()
        ),
        client_ip
    );
    assert_eq!(
        Ipv6Addr::from(
            <[u8; 16]>::try_from(&out[quoted_ip_start + 24..quoted_ip_start + 40]).unwrap()
        ),
        dst_ip
    );
    assert_eq!(out[quoted_ip_start + 7], 1);
}

// --- #2237 ICMP error-generation suppression gate tests ---

/// Shared egress fixture for the suppression tests: ifindex 5 with a
/// primary v4 and v6 so the emission cases can actually build a reply.
fn icmp_suppress_forwarding() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: Some("2001:559:8585:ef00::1".parse().unwrap()),
        },
    );
    forwarding
}

fn ttl_meta_v4() -> UserspaceDpMeta {
    UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    }
}

fn icmp_suppress_ident() -> BindingIdentity {
    BindingIdentity {
        slot: 0,
        queue_id: 7,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    }
}

fn icmp_suppress_flow_v4(src: Ipv4Addr, dst: Ipv4Addr) -> SessionFlow {
    SessionFlow {
        src_ip: IpAddr::V4(src),
        dst_ip: IpAddr::V4(dst),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_UDP,
            src_ip: IpAddr::V4(src),
            dst_ip: IpAddr::V4(dst),
            src_port: 0xc000,
            dst_port: 53,
        },
    }
}

/// Drive `build_local_time_exceeded_request` end-to-end and return
/// whether it produced a request. Used by the suppression tests so each
/// case pins the CALL-SITE wiring, not just the gate predicate: removing
/// the gate from `build_local_time_exceeded_request` makes these return
/// `true` and the assertions fail.
fn te_request_built(frame: &[u8], meta: UserspaceDpMeta) -> bool {
    let fwd = icmp_suppress_forwarding();
    let (src, dst) = match meta.addr_family as i32 {
        libc::AF_INET6 => (
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[meta.l3_offset as usize + 8..meta.l3_offset as usize + 24])
                    .unwrap(),
            )),
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[meta.l3_offset as usize + 24..meta.l3_offset as usize + 40])
                    .unwrap(),
            )),
        ),
        _ => {
            let l3 = meta.l3_offset as usize;
            (
                IpAddr::V4(Ipv4Addr::new(
                    frame[l3 + 12],
                    frame[l3 + 13],
                    frame[l3 + 14],
                    frame[l3 + 15],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    frame[l3 + 16],
                    frame[l3 + 17],
                    frame[l3 + 18],
                    frame[l3 + 19],
                )),
            )
        }
    };
    let flow = SessionFlow {
        src_ip: src,
        dst_ip: dst,
        forward_key: SessionKey {
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            src_ip: src,
            dst_ip: dst,
            src_port: 0xc000,
            dst_port: 53,
        },
    };
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    build_local_time_exceeded_request(
        frame,
        desc,
        meta,
        &icmp_suppress_ident(),
        &flow,
        &fwd,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut BatchCounters::default(),
    )
    .is_some()
}

/// Build an IPv4 UDP frame with a configurable TTL and dst MAC so the
/// suppression tests can drive the multicast/broadcast-L2 case.
fn build_udp_frame_v4_full(
    dst_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ttl: u8,
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
    frame.extend_from_slice(&[0x08, 0x00]);
    let l3 = frame.len();
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, ttl, PROTO_UDP, 0, 0,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let ip_csum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&[0xc0, 0x00, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]); // UDP
    frame
}

/// The emission case: a normal unicast UDP packet with TTL 1 DOES draw a
/// locally generated Time Exceeded (the suppression gate must NOT fire).
#[test]
fn time_exceeded_emitted_for_unicast_udp() {
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client, server, 1);
    let meta = ttl_meta_v4();
    let fwd = icmp_suppress_forwarding();
    assert!(can_generate_icmp_error_reply(&frame, meta));
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    let req = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &icmp_suppress_ident(),
        &icmp_suppress_flow_v4(client, server),
        &fwd,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut BatchCounters::default(),
    );
    assert!(
        req.is_some(),
        "unicast UDP with TTL 1 must draw a Time Exceeded"
    );
}

/// The emission case for TCP — confirms the gate is protocol-agnostic for
/// non-ICMP transports.
#[test]
fn time_exceeded_emitted_for_unicast_tcp() {
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(1, 1, 1, 1);
    let mut frame =
        build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client, server, 1);
    // Flip the IP protocol byte (l3 + 9 = byte 23) to TCP and recompute
    // the IPv4 header checksum.
    frame[23] = PROTO_TCP;
    frame[24..26].copy_from_slice(&[0, 0]);
    let csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&csum.to_be_bytes());
    let mut meta = ttl_meta_v4();
    meta.protocol = PROTO_TCP;
    assert!(
        can_generate_icmp_error_reply(&frame, meta),
        "unicast TCP TTL 1 must be allowed"
    );
}

/// Suppression (a): a low-TTL inbound ICMPv4 *error* (type 11) must NOT
/// draw a fresh Time Exceeded — classic error loop / amplification.
#[test]
fn time_exceeded_suppressed_for_inbound_icmp_error_v4() {
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(1, 1, 1, 1);
    let mut frame = build_icmp_echo_frame_v4(client, server, 1);
    frame[34] = 11; // ICMP type Time Exceeded (an error)
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let fwd = icmp_suppress_forwarding();
    assert!(
        !can_generate_icmp_error_reply(&frame, meta),
        "gate must suppress reply to an inbound ICMP error"
    );
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    let req = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &icmp_suppress_ident(),
        &icmp_suppress_flow_v4(client, server),
        &fwd,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut BatchCounters::default(),
    );
    assert!(req.is_none(), "no Time Exceeded for an inbound ICMP error");
    // An echo *request* (a query, type 8) is NOT suppressed.
    let mut echo = build_icmp_echo_frame_v4(client, server, 1);
    echo[34] = 8;
    assert!(
        can_generate_icmp_error_reply(&echo, meta),
        "inbound ICMP echo request (query) must still draw an error"
    );
}

/// Suppression (a) for ICMPv6: any inbound ICMPv6 error (type < 128).
#[test]
fn time_exceeded_suppressed_for_inbound_icmp_error_v6() {
    let client: Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
    let server: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    let mut frame = build_icmp_echo_frame_v6(client, server, 1);
    frame[54] = 3; // ICMPv6 Time Exceeded (error, < 128)
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 54,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };
    assert!(
        !can_generate_icmp_error_reply(&frame, meta),
        "gate must suppress reply to an inbound ICMPv6 error"
    );
    // ICMPv6 echo request (type 128, a query) is NOT suppressed.
    let echo = build_icmp_echo_frame_v6(client, server, 1); // type 128
    assert!(
        can_generate_icmp_error_reply(&echo, meta),
        "inbound ICMPv6 echo request must still draw an error"
    );
}

/// Suppression (b): a non-first IPv4 fragment (TTL 1) must NOT draw a
/// Time Exceeded — it carries no transport header.
#[test]
fn time_exceeded_suppressed_for_non_first_fragment_v4() {
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(1, 1, 1, 1);
    let mut frame = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client, server, 1);
    // Set a non-zero fragment offset (frag_off field at l3 + 6..8 = bytes
    // 20..22). Offset 0x0001 => non-first fragment.
    frame[20..22].copy_from_slice(&0x0001u16.to_be_bytes());
    frame[24..26].copy_from_slice(&[0, 0]);
    let csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&csum.to_be_bytes());
    let meta = ttl_meta_v4();
    assert!(
        !can_generate_icmp_error_reply(&frame, meta),
        "gate must suppress reply to a non-first IPv4 fragment"
    );
    assert!(
        !te_request_built(&frame, meta),
        "TE call site must suppress a non-first IPv4 fragment"
    );
}

/// Suppression (b) for IPv6: a non-first fragment behind a fragment
/// extension header must NOT draw a Time Exceeded.
#[test]
fn time_exceeded_suppressed_for_non_first_fragment_v6() {
    let client: Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
    let server: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]); // dst mac
    frame.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
    frame.extend_from_slice(&[0x86, 0xdd]);
    // IPv6 base header, next-header = 44 (Fragment), hop_limit 1.
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 44, 1]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    // Fragment header (8 bytes): next-header UDP, reserved, frag-offset
    // 0x0008 (non-first: offset bits non-zero), then id.
    frame.extend_from_slice(&[PROTO_UDP, 0, 0x00, 0x08, 0xDE, 0xAD, 0xBE, 0xEF]);
    // 8 bytes of "payload" where the UDP header would be on the first frag.
    frame.extend_from_slice(&[0; 8]);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 0,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    assert!(
        !can_generate_icmp_error_reply(&frame, meta),
        "gate must suppress reply to a non-first IPv6 fragment"
    );
    assert!(
        !te_request_built(&frame, meta),
        "TE call site must suppress a non-first IPv6 fragment"
    );
}

/// Suppression (c): an IPv4 multicast destination must NOT draw a reply.
#[test]
fn time_exceeded_suppressed_for_multicast_dest_v4() {
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let mcast = Ipv4Addr::new(224, 0, 0, 251); // mDNS group
    let frame = build_udp_frame_v4_full([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb], client, mcast, 1);
    let meta = ttl_meta_v4();
    assert!(
        !can_generate_icmp_error_reply(&frame, meta),
        "gate must suppress reply to a multicast destination"
    );
    assert!(
        !te_request_built(&frame, meta),
        "TE call site must suppress a multicast destination"
    );
}

/// Suppression (c): an L2 broadcast destination MAC must NOT draw a reply
/// even if the L3 destination looks unicast.
#[test]
fn time_exceeded_suppressed_for_l2_broadcast_dest() {
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(10, 0, 61, 1);
    let frame = build_udp_frame_v4_full([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], client, server, 1);
    let meta = ttl_meta_v4();
    assert!(
        !can_generate_icmp_error_reply(&frame, meta),
        "gate must suppress reply to an L2 broadcast frame"
    );
    assert!(
        !te_request_built(&frame, meta),
        "TE call site must suppress an L2 broadcast frame"
    );
}

/// Suppression (d): a bogus IPv4 source (loopback) must NOT draw a reply.
#[test]
fn time_exceeded_suppressed_for_bad_source_v4() {
    let bad_src = Ipv4Addr::new(127, 0, 0, 1);
    let server = Ipv4Addr::new(10, 0, 61, 1);
    let frame = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], bad_src, server, 1);
    let meta = ttl_meta_v4();
    assert!(
        !can_generate_icmp_error_reply(&frame, meta),
        "gate must suppress reply to a loopback source"
    );
    // Unspecified 0.0.0.0 source is also suppressed.
    let zero_src =
        build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], Ipv4Addr::UNSPECIFIED, server, 1);
    assert!(
        !can_generate_icmp_error_reply(&zero_src, meta),
        "gate must suppress reply to a 0.0.0.0 source"
    );
    assert!(
        !te_request_built(&frame, meta),
        "TE call site must suppress a loopback source"
    );
}

/// Suppression (d) for IPv6: a multicast source must NOT draw a reply.
#[test]
fn time_exceeded_suppressed_for_bad_source_v6() {
    let bad_src: Ipv6Addr = "ff02::1".parse().unwrap(); // multicast
    let server: Ipv6Addr = "2001:559:8585:ef00::1".parse().unwrap();
    let frame = build_icmp_echo_frame_v6(bad_src, server, 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 54,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };
    assert!(
        !can_generate_icmp_error_reply(&frame, meta),
        "gate must suppress reply to a multicast IPv6 source"
    );
    assert!(
        !te_request_built(&frame, meta),
        "TE call site must suppress a multicast IPv6 source"
    );
}

/// The reject path now routes through the same gate: an inbound ICMP
/// error still draws no reject reply, and a non-first fragment is
/// suppressed there too (#2237 unifies the two error generators).
#[test]
fn reject_unreachable_routes_through_shared_gate() {
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(1, 1, 1, 1);
    let fwd = reject_egress_forwarding(Some(Ipv4Addr::new(10, 0, 61, 1)), None);
    // Multicast destination — suppressed (was NOT covered by the old
    // inline reject checks, only the new shared gate catches it).
    let mcast = build_udp_frame_v4_full([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb], client, Ipv4Addr::new(224, 0, 0, 251), 64);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    assert!(
        build_reject_icmp_unreachable(&mcast, meta, 5, &fwd).is_none(),
        "reject path must suppress a multicast destination via the shared gate"
    );
    // A plain unicast UDP reject still works.
    let unicast = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client, server, 64);
    assert!(
        build_reject_icmp_unreachable(&unicast, meta, 5, &fwd).is_some(),
        "reject path still replies to a normal unicast packet"
    );
}

/// #2242: the ICMPv6 error builder must quote enough of the invoking
/// packet to reach the transport header even when IPv6 extension headers
/// push it past byte 48, and the total error must stay within the IPv6
/// minimum MTU (1280).
#[test]
fn icmp_error_v6_quote_includes_transport_header_behind_ext_headers() {
    let client: Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
    let server: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    // Build an inbound IPv6 packet: base header (next=Hop-by-Hop 0) +
    // a Hop-by-Hop ext header (8 bytes) + a Destination-Options ext
    // header (8 bytes) + UDP header. The UDP header therefore starts at
    // L3-relative offset 40 + 8 + 8 = 56 (> 48), so the OLD fixed-48
    // quote would have stopped inside the second ext header.
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]); // dst mac
    frame.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
    frame.extend_from_slice(&[0x86, 0xdd]);
    let l3 = frame.len();
    // payload_len = HBH(8) + DstOpt(8) + UDP(8) = 24; next-header 0 (HBH).
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 24, 0, 1]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    // Hop-by-Hop options: next-header = 60 (Dest-Opts), hdr-ext-len 0
    // (=> 8 bytes total), then 6 pad bytes.
    frame.extend_from_slice(&[60, 0, 1, 4, 0, 0, 0, 0]);
    // Destination-Options: next-header = UDP, hdr-ext-len 0, 6 pad bytes.
    frame.extend_from_slice(&[PROTO_UDP, 0, 1, 4, 0, 0, 0, 0]);
    // UDP header: src 0xABCD, dst 0x0035 (53), len 8, csum 0.
    let udp_off = frame.len();
    frame.extend_from_slice(&[0xAB, 0xCD, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]);
    let udp_rel = udp_off - l3; // L3-relative offset of UDP header
    assert!(udp_rel > 48, "fixture must place transport past byte 48");

    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: udp_off as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    let fwd = icmp_suppress_forwarding();
    let out =
        build_local_time_exceeded_v6(&frame, meta, 5, &fwd).expect("build v6 TE with ext headers");
    // Quoted invoking packet starts after [Eth tag?][outer IPv6 40][ICMPv6
    // hdr 8]. Untagged egress => Eth 14 + IPv6 40 + ICMPv6 8 = 62.
    let quote_start = 62;
    // The quote must reach the UDP header (at L3-relative udp_rel) and
    // carry its ports.
    let q_udp = quote_start + udp_rel;
    assert!(
        out.len() >= q_udp + 4,
        "quote must include the transport header (len {} < {})",
        out.len(),
        q_udp + 4
    );
    assert_eq!(
        u16::from_be_bytes([out[q_udp], out[q_udp + 1]]),
        0xABCD,
        "quoted UDP source port must survive (transport header reached)"
    );
    assert_eq!(
        u16::from_be_bytes([out[q_udp + 2], out[q_udp + 3]]),
        0x0035,
        "quoted UDP dest port must survive"
    );
    // Total ICMPv6 error datagram (from outer IPv6 onward) <= 1280.
    let v6_total = out.len() - quote_start + 40 + 8; // outer IPv6 + ICMPv6 hdr + quote
    let _ = v6_total;
    // Equivalent bound: everything after the Ethernet header.
    assert!(
        out.len() - 14 <= 1280,
        "ICMPv6 error must not exceed the IPv6 minimum MTU"
    );
}

/// #2242: a large invoking IPv6 packet is quoted up to the 1232-byte cap
/// (not truncated to 48), keeping the total error within 1280.
#[test]
fn icmp_error_v6_quote_bounded_to_min_mtu() {
    let client: Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
    let server: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
    frame.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x86, 0xdd]);
    let l3 = frame.len();
    // 2000-byte UDP payload after the UDP header => invoking packet is
    // much larger than 1232.
    let udp_payload = 2000usize;
    let payload_len = 8 + udp_payload; // UDP hdr + data
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
    frame.extend_from_slice(&[PROTO_UDP, 64]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    frame.extend_from_slice(&[0xAB, 0xCD, 0x00, 0x35]);
    frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.resize(l3 + 40 + payload_len, 0);

    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: (l3 + 40) as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    let fwd = icmp_suppress_forwarding();
    let out = build_local_time_exceeded_v6(&frame, meta, 5, &fwd).expect("build large v6 TE");
    // Untagged egress: Eth 14 + outer IPv6 40 + ICMPv6 hdr 8 = 62 prefix.
    let quote_start = 62;
    let quote_len = out.len() - quote_start;
    assert_eq!(
        quote_len, 1232,
        "large invoking packet quoted up to the 1232-byte min-MTU cap"
    );
    assert!(
        out.len() - 14 <= 1280,
        "ICMPv6 error must not exceed the IPv6 minimum MTU"
    );
}

// --- #2089 reject ICMP-unreachable builder tests ---

fn reject_egress_forwarding(v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: v4,
            primary_v6: v6,
        },
    );
    forwarding
}

/// Build an IPv4 UDP frame: [Eth][IP src=client dst=server proto=UDP][UDP].
fn build_udp_frame_v4(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[
        0x00, 0x25, 0x90, 0x12, 0x34, 0x56, // dst mac (firewall)
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // src mac (client)
        0x08, 0x00,
    ]);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, PROTO_UDP, 0, 0,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&[0xc0, 0x00, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]); // UDP hdr
    frame
}

#[test]
fn reject_icmp_unreachable_v4_is_type3_code13_admin_prohibited() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_udp_frame_v4(client_ip, dst_ip);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    let forwarding = reject_egress_forwarding(Some(Ipv4Addr::new(10, 0, 61, 1)), None);
    let out = build_reject_icmp_unreachable(&frame, meta, 5, &forwarding)
        .expect("reject ICMP unreachable v4");
    // MAC reflect: reply dst = inbound src (client).
    assert_eq!(&out[0..6], &[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]);
    // IP: src = firewall ingress primary, dst = client.
    assert_eq!(
        Ipv4Addr::new(out[26], out[27], out[28], out[29]),
        Ipv4Addr::new(10, 0, 61, 1)
    );
    assert_eq!(Ipv4Addr::new(out[30], out[31], out[32], out[33]), client_ip);
    // ICMP type 3 (dest unreachable), code 13 (admin prohibited).
    assert_eq!(out[34], 3);
    assert_eq!(out[35], 13);
}

#[test]
fn reject_icmp_unreachable_v6_is_type1_code1_admin_prohibited() {
    let client_ip: Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
    let dst_ip: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    // Reuse the echo-frame helper (ICMPv6 echo request = a query, not an
    // error) so the suppression guard does NOT fire: a rejected query
    // gets an unreachable.
    let frame = build_icmp_echo_frame_v6(client_ip, dst_ip, 64);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };
    let forwarding = reject_egress_forwarding(None, Some("2001:559:8585:ef00::1".parse().unwrap()));
    let out = build_reject_icmp_unreachable(&frame, meta, 5, &forwarding)
        .expect("reject ICMPv6 unreachable v6");
    // ICMPv6 type 1 (dest unreachable), code 1 (admin prohibited).
    assert_eq!(out[54], 1);
    assert_eq!(out[55], 1);
}

#[test]
fn reject_icmp_unreachable_suppressed_for_inbound_icmp_error() {
    // An inbound ICMPv4 error (type 3) must NOT draw a reject reply.
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let mut frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 64);
    // Rewrite the ICMP type byte (at l4_offset = 34) to 3 (dest unreach).
    frame[34] = 3;
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let forwarding = reject_egress_forwarding(Some(Ipv4Addr::new(10, 0, 61, 1)), None);
    assert!(
        build_reject_icmp_unreachable(&frame, meta, 5, &forwarding).is_none(),
        "must not reply to an inbound ICMP error"
    );
    // Direct guard checks.
    assert!(reject_icmp_reply_suppressed(PROTO_ICMP, 3));
    assert!(reject_icmp_reply_suppressed(PROTO_ICMP, 11));
    assert!(!reject_icmp_reply_suppressed(PROTO_ICMP, 8)); // echo request: reply
    assert!(reject_icmp_reply_suppressed(PROTO_ICMPV6, 1));
    assert!(reject_icmp_reply_suppressed(PROTO_ICMPV6, 127));
    assert!(!reject_icmp_reply_suppressed(PROTO_ICMPV6, 128)); // echo request: reply
    assert!(!reject_icmp_reply_suppressed(PROTO_UDP, 0));
}

// --- ICMP error NAT reversal tests ---

/// Build an IPv4 ICMP Time Exceeded frame with an embedded TCP packet.
/// outer: [Eth][IP: src=router_ip, dst=snat_ip][ICMP type=11 code=0]
///        [Embedded: IP src=snat_ip, dst=server_ip, proto=TCP][TCP src=snat_port, dst=server_port]
fn build_icmp_te_frame_v4(
    router_ip: Ipv4Addr,
    snat_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    snat_port: u16,
    server_port: u16,
    embedded_proto: u8,
) -> Vec<u8> {
    let mut frame = Vec::new();
    // Ethernet header
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], // dst MAC
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56], // src MAC
        0,
        0x0800,
    );
    let ip_start = frame.len(); // 14

    // Build embedded IP+L4 first to know sizes
    let mut embedded = Vec::new();
    // Embedded IPv4 header (20 bytes, IHL=5)
    embedded.extend_from_slice(&[
        0x45,
        0x00,
        0x00,
        0x00, // version/IHL, DSCP, total length (fill later)
        0x00,
        0x01,
        0x00,
        0x00, // ID, flags, fragment offset
        64,
        embedded_proto,
        0x00,
        0x00, // TTL, protocol, checksum (fill later)
    ]);
    embedded.extend_from_slice(&snat_ip.octets()); // src
    embedded.extend_from_slice(&server_ip.octets()); // dst
    // Embedded L4: first 8 bytes
    if matches!(embedded_proto, PROTO_TCP | PROTO_UDP) {
        embedded.extend_from_slice(&snat_port.to_be_bytes());
        embedded.extend_from_slice(&server_port.to_be_bytes());
        embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq/other
    } else if embedded_proto == PROTO_ICMP {
        embedded.extend_from_slice(&[8, 0, 0x00, 0x00]); // echo request, checksum
        embedded.extend_from_slice(&snat_port.to_be_bytes()); // echo ID
        embedded.extend_from_slice(&[0x00, 0x01]); // seq
    }
    // Fill embedded IP total length
    let emb_total = embedded.len() as u16;
    embedded[2..4].copy_from_slice(&emb_total.to_be_bytes());
    // Compute embedded IP checksum
    embedded[10..12].copy_from_slice(&[0, 0]);
    let emb_ip_csum = checksum16(&embedded[..20]);
    embedded[10..12].copy_from_slice(&emb_ip_csum.to_be_bytes());

    // Outer ICMP header: type=11 (Time Exceeded), code=0, checksum, unused
    let mut icmp = Vec::new();
    icmp.extend_from_slice(&[11, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // type, code, csum, unused
    icmp.extend_from_slice(&embedded);
    // Compute ICMP checksum
    icmp[2..4].copy_from_slice(&[0, 0]);
    let icmp_csum = checksum16(&icmp);
    icmp[2..4].copy_from_slice(&icmp_csum.to_be_bytes());

    // Outer IPv4 header
    let outer_total_len = (20 + icmp.len()) as u16;
    frame.extend_from_slice(&[
        0x45, 0x00, // version/IHL, DSCP
    ]);
    frame.extend_from_slice(&outer_total_len.to_be_bytes()); // total length
    frame.extend_from_slice(&[
        0x00, 0x02, 0x00, 0x00, // ID, flags
        64, PROTO_ICMP, 0x00, 0x00, // TTL, protocol, checksum
    ]);
    frame.extend_from_slice(&router_ip.octets()); // src
    frame.extend_from_slice(&snat_ip.octets()); // dst

    // Compute outer IP checksum
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&[0, 0]);
    let ip_csum = checksum16(&frame[ip_start..ip_start + 20]);
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_csum.to_be_bytes());

    // Append ICMP payload
    frame.extend_from_slice(&icmp);

    frame
}

#[test]
fn icmp_te_nat_reversal_v4_rewrites_outer_dst_and_embedded_src() {
    // Scenario: client 10.0.61.102 -> server 1.1.1.1, SNAT'd to 172.16.80.8
    // Router 10.0.0.1 sends ICMP Time Exceeded back to 172.16.80.8
    // NAT reversal: outer dst 172.16.80.8 -> 10.0.61.102,
    //               embedded src 172.16.80.8 -> 10.0.61.102
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_ip)),
            rewrite_src_port: Some(snat_port),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(client_ip),
        original_src_port: client_port,
        embedded_proto: PROTO_TCP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(client_ip)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_UNTRUST_ZONE_ID,
            egress_zone: TEST_TRUST_ZONE_ID,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
    };

    let result = build_nat_reversed_icmp_error_v4(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed frame");

    // Verify Ethernet header
    assert_eq!(&result[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
    assert_eq!(&result[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]); // src MAC
    assert_eq!(&result[12..14], &[0x08, 0x00]); // ethertype IPv4

    // Verify outer IP dst is now the original client
    let outer_dst = Ipv4Addr::new(result[30], result[31], result[32], result[33]);
    assert_eq!(
        outer_dst, client_ip,
        "outer IP dst should be original client"
    );

    // Verify outer IP src is still the router
    let outer_src = Ipv4Addr::new(result[26], result[27], result[28], result[29]);
    assert_eq!(outer_src, router_ip, "outer IP src should remain router");

    // Verify embedded IP src is now the original client
    // Embedded IP starts at: eth(14) + outer_ip(20) + icmp_hdr(8) = 42
    let emb_ip_start = 42;
    let emb_src = Ipv4Addr::new(
        result[emb_ip_start + 12],
        result[emb_ip_start + 13],
        result[emb_ip_start + 14],
        result[emb_ip_start + 15],
    );
    assert_eq!(emb_src, client_ip, "embedded src should be original client");

    // Verify embedded dst is still the server
    let emb_dst = Ipv4Addr::new(
        result[emb_ip_start + 16],
        result[emb_ip_start + 17],
        result[emb_ip_start + 18],
        result[emb_ip_start + 19],
    );
    assert_eq!(emb_dst, server_ip, "embedded dst should remain server");

    // Verify embedded TCP src port is now the original client port
    let emb_l4_start = emb_ip_start + 20; // IHL=5, so 20 bytes
    let emb_port = u16::from_be_bytes([result[emb_l4_start], result[emb_l4_start + 1]]);
    assert_eq!(
        emb_port, client_port,
        "embedded src port should be original"
    );

    // Verify outer IP checksum is valid
    let outer_ihl = ((result[14] & 0x0f) as usize) * 4;
    let ip_csum_check = checksum16(&result[14..14 + outer_ihl]);
    assert_eq!(ip_csum_check, 0, "outer IP checksum should be valid (0)");

    // Verify outer ICMP checksum is valid
    let icmp_start = 14 + outer_ihl;
    let icmp_csum_check = checksum16(&result[icmp_start..]);
    assert_eq!(
        icmp_csum_check, 0,
        "outer ICMP checksum should be valid (0)"
    );

    // Verify embedded IP checksum is valid
    let emb_ihl = ((result[emb_ip_start] & 0x0f) as usize) * 4;
    let emb_ip_csum_check = checksum16(&result[emb_ip_start..emb_ip_start + emb_ihl]);
    assert_eq!(
        emb_ip_csum_check, 0,
        "embedded IP checksum should be valid (0)"
    );
}

#[test]
fn icmp_te_nat_reversal_v4_with_port_snat() {
    // Same as above but verifying UDP port reversal specifically
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 50000;
    let client_port: u16 = 5353;

    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 53, PROTO_UDP);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_ip)),
            rewrite_src_port: Some(snat_port),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(client_ip),
        original_src_port: client_port,
        embedded_proto: PROTO_UDP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(client_ip)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_UNTRUST_ZONE_ID,
            egress_zone: TEST_TRUST_ZONE_ID,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
    };

    let result = build_nat_reversed_icmp_error_v4(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed frame");

    // Verify embedded UDP src port is now the original client port
    let emb_ip_start = 42; // eth(14) + outer_ip(20) + icmp_hdr(8)
    let emb_l4_start = emb_ip_start + 20;
    let emb_port = u16::from_be_bytes([result[emb_l4_start], result[emb_l4_start + 1]]);
    assert_eq!(
        emb_port, client_port,
        "embedded UDP src port should be original"
    );

    // Verify all checksums
    let ip_csum_check = checksum16(&result[14..34]);
    assert_eq!(ip_csum_check, 0, "outer IP checksum should be valid");
    let icmp_csum_check = checksum16(&result[34..]);
    assert_eq!(icmp_csum_check, 0, "outer ICMP checksum should be valid");
}

#[test]
fn icmp_dest_unreach_nat_reversal_v4() {
    // ICMP Destination Unreachable (type 3, code 1) with embedded TCP
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);

    // Build ICMP Destination Unreachable frame manually
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    let ip_start = frame.len();

    // Embedded IP+TCP
    let mut embedded = Vec::new();
    embedded.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    embedded.extend_from_slice(&snat_ip.octets());
    embedded.extend_from_slice(&server_ip.octets());
    let emb_total = (20 + 8) as u16;
    embedded[2..4].copy_from_slice(&emb_total.to_be_bytes());
    embedded.extend_from_slice(&40000u16.to_be_bytes()); // src port (SNAT'd)
    embedded.extend_from_slice(&80u16.to_be_bytes()); // dst port
    embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq
    embedded[10..12].copy_from_slice(&[0, 0]);
    let emb_ip_csum = checksum16(&embedded[..20]);
    embedded[10..12].copy_from_slice(&emb_ip_csum.to_be_bytes());

    // ICMP type=3 (Dest Unreach), code=1 (Host Unreachable)
    let mut icmp = Vec::new();
    icmp.extend_from_slice(&[3, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    icmp.extend_from_slice(&embedded);
    icmp[2..4].copy_from_slice(&[0, 0]);
    let icmp_csum = checksum16(&icmp);
    icmp[2..4].copy_from_slice(&icmp_csum.to_be_bytes());

    // Outer IP
    let outer_total = (20 + icmp.len()) as u16;
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&outer_total.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x02, 0x00, 0x00, 64, PROTO_ICMP, 0x00, 0x00]);
    frame.extend_from_slice(&router_ip.octets());
    frame.extend_from_slice(&snat_ip.octets());
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&[0, 0]);
    let ip_csum = checksum16(&frame[ip_start..ip_start + 20]);
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&icmp);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_ip)),
            rewrite_src_port: Some(40000),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(client_ip),
        original_src_port: 12345,
        embedded_proto: PROTO_TCP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(client_ip)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_UNTRUST_ZONE_ID,
            egress_zone: TEST_TRUST_ZONE_ID,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
    };

    let result = build_nat_reversed_icmp_error_v4(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed frame");

    // Verify outer IP dst is client
    let outer_dst = Ipv4Addr::new(result[30], result[31], result[32], result[33]);
    assert_eq!(outer_dst, client_ip);

    // Verify ICMP type/code NOT modified
    assert_eq!(result[34], 3, "ICMP type must remain Dest Unreach");
    assert_eq!(result[35], 1, "ICMP code must remain Host Unreachable");

    // Verify checksums
    let ip_csum_check = checksum16(&result[14..34]);
    assert_eq!(ip_csum_check, 0);
    let icmp_csum_check = checksum16(&result[34..]);
    assert_eq!(icmp_csum_check, 0);
}

/// Build an IPv6 ICMPv6 Time Exceeded frame with an embedded TCP packet.
fn build_icmpv6_te_frame(
    router_ip: Ipv6Addr,
    snat_ip: Ipv6Addr,
    server_ip: Ipv6Addr,
    snat_port: u16,
    server_port: u16,
    embedded_proto: u8,
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );

    // Build embedded IPv6+L4
    let mut embedded = Vec::new();
    // IPv6 header (40 bytes)
    embedded.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version, traffic class, flow label
    let emb_payload_len = 8u16; // 8 bytes of L4
    embedded.extend_from_slice(&emb_payload_len.to_be_bytes());
    embedded.push(embedded_proto); // next header
    embedded.push(64); // hop limit
    embedded.extend_from_slice(&snat_ip.octets()); // src
    embedded.extend_from_slice(&server_ip.octets()); // dst
    // Embedded L4: first 8 bytes
    if matches!(embedded_proto, PROTO_TCP | PROTO_UDP) {
        embedded.extend_from_slice(&snat_port.to_be_bytes());
        embedded.extend_from_slice(&server_port.to_be_bytes());
        embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    } else if embedded_proto == PROTO_ICMPV6 {
        embedded.extend_from_slice(&[128, 0, 0x00, 0x00]); // echo request, checksum
        embedded.extend_from_slice(&snat_port.to_be_bytes()); // echo ID
        embedded.extend_from_slice(&[0x00, 0x01]); // seq
    }

    // ICMPv6 header: type=3 (Time Exceeded), code=0, checksum, unused
    let mut icmp6 = Vec::new();
    icmp6.extend_from_slice(&[3, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    icmp6.extend_from_slice(&embedded);

    // Outer IPv6 header
    let payload_len = icmp6.len() as u16;
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.push(PROTO_ICMPV6); // next header
    frame.push(64); // hop limit
    frame.extend_from_slice(&router_ip.octets()); // src
    frame.extend_from_slice(&snat_ip.octets()); // dst

    // Compute ICMPv6 checksum (covers pseudo-header)
    icmp6[2..4].copy_from_slice(&[0, 0]);
    let csum = checksum16_ipv6(router_ip, snat_ip, PROTO_ICMPV6, &icmp6);
    icmp6[2..4].copy_from_slice(&csum.to_be_bytes());

    frame.extend_from_slice(&icmp6);
    frame
}

#[test]
fn icmpv6_te_nat_reversal_v6_rewrites_outer_dst_and_embedded_src() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let snat_ip: Ipv6Addr = "2001:db8:1::100".parse().unwrap();
    let client_ip: Ipv6Addr = "fd00::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    let frame = build_icmpv6_te_frame(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(snat_ip)),
            rewrite_src_port: Some(snat_port),
            ..NatDecision::default()
        },
        original_src: IpAddr::V6(client_ip),
        original_src_port: client_port,
        embedded_proto: PROTO_TCP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(client_ip)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_UNTRUST_ZONE_ID,
            egress_zone: TEST_TRUST_ZONE_ID,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
    };

    let result = build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed ICMPv6 frame");

    // Verify Ethernet header
    assert_eq!(&result[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
    assert_eq!(&result[12..14], &[0x86, 0xdd]); // ethertype IPv6

    // Verify outer IPv6 dst is now the original client (bytes 24..40 in IPv6)
    let outer_dst_bytes: [u8; 16] = result[38..54].try_into().unwrap();
    let outer_dst = Ipv6Addr::from(outer_dst_bytes);
    assert_eq!(
        outer_dst, client_ip,
        "outer IPv6 dst should be original client"
    );

    // Verify outer IPv6 src is still the router (bytes 8..24 in IPv6)
    let outer_src_bytes: [u8; 16] = result[22..38].try_into().unwrap();
    let outer_src = Ipv6Addr::from(outer_src_bytes);
    assert_eq!(outer_src, router_ip, "outer IPv6 src should remain router");

    // Verify embedded IPv6 src is now the original client
    // Embedded IPv6 starts at: eth(14) + outer_ipv6(40) + icmpv6_hdr(8) = 62
    let emb_ip_start = 62;
    let emb_src_bytes: [u8; 16] = result[emb_ip_start + 8..emb_ip_start + 24]
        .try_into()
        .unwrap();
    let emb_src = Ipv6Addr::from(emb_src_bytes);
    assert_eq!(
        emb_src, client_ip,
        "embedded IPv6 src should be original client"
    );

    // Verify embedded dst is still the server
    let emb_dst_bytes: [u8; 16] = result[emb_ip_start + 24..emb_ip_start + 40]
        .try_into()
        .unwrap();
    let emb_dst = Ipv6Addr::from(emb_dst_bytes);
    assert_eq!(emb_dst, server_ip, "embedded IPv6 dst should remain server");

    // Verify embedded TCP src port
    let emb_l4_start = emb_ip_start + 40;
    let emb_port = u16::from_be_bytes([result[emb_l4_start], result[emb_l4_start + 1]]);
    assert_eq!(
        emb_port, client_port,
        "embedded src port should be original"
    );

    // Verify ICMPv6 checksum is valid
    let icmp6_start = 54; // eth(14) + ipv6(40)
    let src_v6 = Ipv6Addr::from(outer_src_bytes);
    let dst_v6 = Ipv6Addr::from(outer_dst_bytes);
    let icmp6_data = &result[icmp6_start..];
    // Zero checksum and recompute
    let mut icmp6_copy = icmp6_data.to_vec();
    icmp6_copy[2] = 0;
    icmp6_copy[3] = 0;
    let expected_csum = checksum16_ipv6(src_v6, dst_v6, PROTO_ICMPV6, &icmp6_copy);
    let actual_csum = u16::from_be_bytes([icmp6_data[2], icmp6_data[3]]);
    assert_eq!(
        actual_csum, expected_csum,
        "ICMPv6 checksum should be valid"
    );
}

/// Flexible ICMPv6 Time Exceeded fixture for the #1838 §5.7 builder
/// tests: optional outer hop-by-hop ext header (8 bytes between the
/// outer IPv6 header and the ICMPv6 header), optional fragment header
/// in the EMBEDDED quoted packet (with caller-controlled raw
/// offset/flags bytes), and optional trailing bytes inside the ICMPv6
/// checksum coverage (used to force a computed-zero checksum).
#[allow(clippy::too_many_arguments)]
fn build_icmpv6_te_frame_ext(
    router_ip: Ipv6Addr,
    snat_ip: Ipv6Addr,
    server_ip: Ipv6Addr,
    snat_port: u16,
    server_port: u16,
    outer_hbh: bool,
    embedded_frag_off_flags: Option<u16>,
    trailing: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );

    // Embedded IPv6 (+ optional fragment header) + 8 bytes of TCP.
    let mut embedded = Vec::new();
    embedded.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    let frag_len = if embedded_frag_off_flags.is_some() {
        8
    } else {
        0
    };
    let emb_payload_len = (frag_len + 8) as u16;
    embedded.extend_from_slice(&emb_payload_len.to_be_bytes());
    embedded.push(if embedded_frag_off_flags.is_some() {
        44 // fragment header
    } else {
        PROTO_TCP
    });
    embedded.push(64);
    embedded.extend_from_slice(&snat_ip.octets());
    embedded.extend_from_slice(&server_ip.octets());
    if let Some(off_flags) = embedded_frag_off_flags {
        embedded.push(PROTO_TCP); // next header after the fragment hdr
        embedded.push(0); // reserved
        embedded.extend_from_slice(&off_flags.to_be_bytes());
        embedded.extend_from_slice(&[0, 0, 0, 1]); // identification
    }
    embedded.extend_from_slice(&snat_port.to_be_bytes());
    embedded.extend_from_slice(&server_port.to_be_bytes());
    embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // ICMPv6 Time Exceeded + embedded + trailing.
    let mut icmp6 = Vec::new();
    icmp6.extend_from_slice(&[3, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    icmp6.extend_from_slice(&embedded);
    icmp6.extend_from_slice(trailing);

    // Outer IPv6 header (+ optional hop-by-hop).
    let hbh_len = if outer_hbh { 8usize } else { 0 };
    let payload_len = (hbh_len + icmp6.len()) as u16;
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.push(if outer_hbh { 0 } else { PROTO_ICMPV6 });
    frame.push(64);
    frame.extend_from_slice(&router_ip.octets());
    frame.extend_from_slice(&snat_ip.octets());
    if outer_hbh {
        // Hop-by-hop: next = ICMPv6, hdr-ext-len 0 → 8 bytes total.
        frame.extend_from_slice(&[PROTO_ICMPV6, 0, 1, 4, 0, 0, 0, 0]);
    }

    icmp6[2..4].copy_from_slice(&[0, 0]);
    let csum = checksum16_ipv6(router_ip, snat_ip, PROTO_ICMPV6, &icmp6);
    let csum = if csum == 0 { 0xffff } else { csum };
    icmp6[2..4].copy_from_slice(&csum.to_be_bytes());

    frame.extend_from_slice(&icmp6);
    frame
}

fn icmpv6_te_match_fixture(
    snat_ip: Ipv6Addr,
    client_ip: Ipv6Addr,
    snat_port: u16,
    client_port: u16,
) -> EmbeddedIcmpMatch {
    EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(snat_ip)),
            rewrite_src_port: Some(snat_port),
            ..NatDecision::default()
        },
        original_src: IpAddr::V6(client_ip),
        original_src_port: client_port,
        embedded_proto: PROTO_TCP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(client_ip)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_UNTRUST_ZONE_ID,
            egress_zone: TEST_TRUST_ZONE_ID,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
    }
}

fn icmpv6_te_meta(l4_offset: u16) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    }
}

/// #1838 §5.7: an ICMPv6 error whose OUTER packet carries an extension
/// header. The NAT match is ext-aware (reads the ICMP type at
/// meta.l4_offset), so this input matched — and the old fixed-40
/// builder then wrote the embedded un-NAT and the checksum recompute
/// inside the outer hop-by-hop header. With the shared offset helper
/// the un-NAT lands at the real offsets and the output verifies.
#[test]
fn icmpv6_te_nat_reversal_outer_ext_header_lands_at_real_offsets() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let snat_ip: Ipv6Addr = "2001:db8:1::100".parse().unwrap();
    let client_ip: Ipv6Addr = "fd00::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    let frame = build_icmpv6_te_frame_ext(
        router_ip,
        snat_ip,
        server_ip,
        snat_port,
        80,
        true,
        None,
        &[],
    );
    // Outer L4 (ICMPv6) at eth(14) + IPv6(40) + hop-by-hop(8) = 62.
    let meta = icmpv6_te_meta(62);
    let icmp_match = icmpv6_te_match_fixture(snat_ip, client_ip, snat_port, client_port);

    let result = build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed ICMPv6 frame for outer-ext error");

    // Outer dst rewritten to the original client.
    let outer_dst = Ipv6Addr::from(<[u8; 16]>::try_from(&result[38..54]).unwrap());
    assert_eq!(outer_dst, client_ip);
    // Hop-by-hop bytes untouched (the old fixed-40 builder scribbled
    // the embedded src into them).
    assert_eq!(
        &result[54..62],
        &frame[54..62],
        "outer extension header must not be modified"
    );
    // Embedded IPv6 src is the original client at the REAL offset:
    // eth(14) + outer(40) + hbh(8) + icmp6(8) = 70.
    let emb_ip_start = 70;
    let emb_src =
        Ipv6Addr::from(<[u8; 16]>::try_from(&result[emb_ip_start + 8..emb_ip_start + 24]).unwrap());
    assert_eq!(emb_src, client_ip, "embedded src restored at real offset");
    // Embedded TCP src port restored.
    let emb_l4 = emb_ip_start + 40;
    assert_eq!(
        u16::from_be_bytes([result[emb_l4], result[emb_l4 + 1]]),
        client_port,
        "embedded src port restored at real offset"
    );
    // ICMPv6 checksum recomputed with the CORRECT coverage (from the
    // real icmp_offset 48, upper-layer length = len - 48): receiver
    // verification over the stored checksum folds to zero.
    let outer_src = Ipv6Addr::from(<[u8; 16]>::try_from(&result[22..38]).unwrap());
    assert_eq!(
        checksum16_ipv6(outer_src, outer_dst, PROTO_ICMPV6, &result[62..]),
        0,
        "ICMPv6 checksum must verify with ext-aware coverage"
    );
}

/// #1838 §5.7 (Codex r2): a quoted NON-FIRST fragment has no L4
/// header — the builder must not write "ports" into its payload
/// bytes. A quoted FIRST/atomic fragment does carry the L4 header
/// after the fragment header — the restore must land there.
#[test]
fn icmpv6_te_nat_reversal_embedded_fragment_handling() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let snat_ip: Ipv6Addr = "2001:db8:1::100".parse().unwrap();
    let client_ip: Ipv6Addr = "fd00::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;
    let emb_ip_start = 62; // eth(14) + outer(40) + icmp6(8)

    // Non-first fragment (offset bits nonzero): embedded address is
    // still restored (offset-independent), but the fragment header and
    // the quoted payload bytes after it are byte-identical to input —
    // no port write lands in payload.
    let frame = build_icmpv6_te_frame_ext(
        router_ip,
        snat_ip,
        server_ip,
        snat_port,
        80,
        false,
        Some(0x0008), // fragment offset 1, M=0
        &[],
    );
    let meta = icmpv6_te_meta(54);
    let icmp_match = icmpv6_te_match_fixture(snat_ip, client_ip, snat_port, client_port);
    let result = build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match)
        .expect("builder still produces the error frame");
    let emb_src =
        Ipv6Addr::from(<[u8; 16]>::try_from(&result[emb_ip_start + 8..emb_ip_start + 24]).unwrap());
    assert_eq!(emb_src, client_ip, "address restore is offset-independent");
    assert_eq!(
        &result[emb_ip_start + 40..],
        &frame[emb_ip_start + 40..],
        "non-first fragment: fragment header + payload bytes untouched"
    );

    // First/atomic fragment (offset 0): the L4 header follows the
    // fragment header — the port restore lands at emb_ip + 48.
    let frame = build_icmpv6_te_frame_ext(
        router_ip,
        snat_ip,
        server_ip,
        snat_port,
        80,
        false,
        Some(0x0001), // offset 0, M=1 (first fragment)
        &[],
    );
    let result = build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match)
        .expect("builder produces the error frame");
    let emb_l4 = emb_ip_start + 48;
    assert_eq!(
        u16::from_be_bytes([result[emb_l4], result[emb_l4 + 1]]),
        client_port,
        "first/atomic fragment: port restored after the fragment header"
    );
}

/// #1838 §5.7 (Codex r2 medium 2): the builder's final ICMPv6 checksum
/// recompute canonicalizes a computed 0x0000 to 0xFFFF — representation
/// assertion on the STORED field (a verify-style oracle accepts both
/// encodings of one's-complement zero and cannot see this).
#[test]
fn icmpv6_te_nat_reversal_computed_zero_checksum_stored_as_ffff() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let snat_ip: Ipv6Addr = "2001:db8:1::100".parse().unwrap();
    let client_ip: Ipv6Addr = "fd00::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;
    let icmp6_start = 54; // eth(14) + outer IPv6(40)

    // Pass 1: zero balancing word → read the stored checksum C1.
    // stored C1 = !fold(S) where S is the coverage sum with the
    // checksum field zeroed; setting the balancer to C1 makes
    // fold(S + C1) = 0xFFFF, i.e. a raw computed checksum of 0.
    let meta = icmpv6_te_meta(54);
    let icmp_match = icmpv6_te_match_fixture(snat_ip, client_ip, snat_port, client_port);
    let frame = build_icmpv6_te_frame_ext(
        router_ip,
        snat_ip,
        server_ip,
        snat_port,
        80,
        false,
        None,
        &[0, 0],
    );
    let pass1 = build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match).expect("pass 1 builds");
    let c1 = u16::from_be_bytes([pass1[icmp6_start + 2], pass1[icmp6_start + 3]]);

    // Pass 2: balancer = C1 forces the recomputed sum to zero.
    let frame = build_icmpv6_te_frame_ext(
        router_ip,
        snat_ip,
        server_ip,
        snat_port,
        80,
        false,
        None,
        &c1.to_be_bytes(),
    );
    let result =
        build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match).expect("pass 2 builds");

    // Prove the raw recompute over the output is genuinely zero…
    let outer_src = Ipv6Addr::from(<[u8; 16]>::try_from(&result[22..38]).unwrap());
    let outer_dst = Ipv6Addr::from(<[u8; 16]>::try_from(&result[38..54]).unwrap());
    let mut icmp6_zeroed = result[icmp6_start..].to_vec();
    icmp6_zeroed[2] = 0;
    icmp6_zeroed[3] = 0;
    assert_eq!(
        checksum16_ipv6(outer_src, outer_dst, PROTO_ICMPV6, &icmp6_zeroed),
        0,
        "balancing word must force the raw computed checksum to zero"
    );
    // …and the STORED field is the canonical 0xFFFF encoding.
    assert_eq!(
        u16::from_be_bytes([result[icmp6_start + 2], result[icmp6_start + 3]]),
        0xffff,
        "computed-zero ICMPv6 checksum must be stored as 0xFFFF"
    );
}

#[test]
fn icmpv6_te_nptv6_reverse_lookup_restores_internal_client() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let external_client: Ipv6Addr = "2602:fd41:70:100::102".parse().unwrap();
    let internal_client: Ipv6Addr = "fd35:1940:27:100::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2607:f8b0:4005:814::200e".parse().unwrap();
    let echo_id: u16 = 0x8234;

    let frame = build_icmpv6_te_frame(
        router_ip,
        external_client,
        server_ip,
        echo_id,
        0,
        PROTO_ICMPV6,
    );

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };

    let mut forwarding = ForwardingState::default();
    forwarding.nptv6 = Nptv6State::from_snapshots(&[crate::Nptv6RuleSnapshot {
        name: "nptv6-test".to_string(),
        from_zone: "wan".to_string(),
        internal_prefix: "fd35:1940:0027::/48".to_string(),
        external_prefix: "2602:fd41:0070::/48".to_string(),
    }]);

    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(internal_client)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(external_client)),
            rewrite_dst: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            nat64: false,
            nptv6: true,
        },
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
    };
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            src_ip: IpAddr::V6(internal_client),
            dst_ip: IpAddr::V6(server_ip),
            src_port: echo_id,
            dst_port: 0,
        },
        decision,
        metadata,
        1_000_000,
        PROTO_ICMPV6,
        0,
    ));

    let neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let icmp_match = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    )
    .expect("should match embedded ICMPv6 error");

    assert_eq!(icmp_match.original_src, IpAddr::V6(internal_client));
    assert_eq!(icmp_match.original_src_port, echo_id);
    assert!(icmp_match.nat.nptv6);
    assert_eq!(
        icmp_match.nat.rewrite_src,
        Some(IpAddr::V6(external_client))
    );
}

#[test]
fn icmpv6_te_prefers_reverse_session_resolution_for_client_return_path() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let external_client: Ipv6Addr = "2602:fd41:70:100::102".parse().unwrap();
    let internal_client: Ipv6Addr = "fd35:1940:27:100::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2607:f8b0:4005:814::200e".parse().unwrap();
    let echo_id: u16 = 0x8234;

    let frame = build_icmpv6_te_frame(
        router_ip,
        external_client,
        server_ip,
        echo_id,
        0,
        PROTO_ICMPV6,
    );

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };

    let mut forwarding = ForwardingState::default();
    forwarding.nptv6 = Nptv6State::from_snapshots(&[crate::Nptv6RuleSnapshot {
        name: "nptv6-test".to_string(),
        from_zone: "wan".to_string(),
        internal_prefix: "fd35:1940:0027::/48".to_string(),
        external_prefix: "2602:fd41:0070::/48".to_string(),
    }]);

    let forward_key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        src_ip: IpAddr::V6(internal_client),
        dst_ip: IpAddr::V6(server_ip),
        src_port: echo_id,
        dst_port: 0,
    };
    let forward_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(server_ip)),
            neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(external_client)),
            rewrite_dst: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            nat64: false,
            nptv6: true,
        },
    };
    let forward_metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
    };

    let reverse_key = reverse_session_key(&forward_key, forward_decision.nat);
    let reverse_resolution = ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 24,
        tx_ifindex: 24,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V6(internal_client)),
        neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
        tx_vlan_id: 0,
    };
    let reverse_decision = SessionDecision {
        resolution: reverse_resolution,
        nat: forward_decision.nat.reverse(
            forward_key.src_ip,
            forward_key.dst_ip,
            forward_key.src_port,
            forward_key.dst_port,
        ),
    };
    let reverse_metadata = SessionMetadata {
        ingress_zone: TEST_WAN_ZONE_ID,
        egress_zone: TEST_LAN_ZONE_ID,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: true,
        nat64_reverse: None,
    };

    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        forward_key.clone(),
        forward_decision,
        forward_metadata,
        1_000_000,
        PROTO_ICMPV6,
        0,
    ));
    assert!(sessions.install_with_protocol(
        reverse_key,
        reverse_decision,
        reverse_metadata,
        1_000_000,
        PROTO_ICMPV6,
        0,
    ));

    let neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let icmp_match = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    )
    .expect("should match embedded ICMPv6 error");

    assert_eq!(icmp_match.original_src, IpAddr::V6(internal_client));
    assert_eq!(
        icmp_match.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(icmp_match.resolution.egress_ifindex, 24);
    assert_eq!(icmp_match.resolution.tx_ifindex, 24);
    assert_eq!(
        icmp_match.resolution.neighbor_mac,
        Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
}

#[test]
fn no_match_embedded_icmp_returns_none() {
    // An ICMP error with no matching session should return None
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);

    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, 40000, 80, PROTO_TCP);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let mut sessions = SessionTable::new();
    // Don't install any sessions
    let result = try_embedded_icmp_session_match_from_frame(&frame, meta, &mut sessions, 1_000_000);
    assert!(
        result.is_none(),
        "should return None when no session matches"
    );
}

#[test]
fn embedded_icmp_nat_match_uses_shared_nat_session_for_ipv4() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let mut sessions = SessionTable::new();
    let forwarding = build_forwarding_state(&nat_snapshot());
    let neighbors = Arc::new(ShardedNeighborMap::new());
    learn_dynamic_neighbor(
        &forwarding,
        &neighbors,
        24,
        0,
        IpAddr::V4(client_ip),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));

    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(server_ip),
            src_port: client_port,
            dst_port: 80,
        },
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_dst: None,
                rewrite_src_port: Some(snat_port),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
    };
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    let icmp_match = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    )
    .expect("shared NAT session should match embedded ICMP");

    assert_eq!(icmp_match.original_src, IpAddr::V4(client_ip));
    assert_eq!(icmp_match.original_src_port, client_port);
    assert_eq!(icmp_match.nat.rewrite_src, Some(IpAddr::V4(snat_ip)));
    assert_eq!(icmp_match.resolution.egress_ifindex, 24);
    assert_eq!(icmp_match.resolution.tx_ifindex, 24);
    assert_eq!(
        icmp_match.resolution.neighbor_mac,
        Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    );
}

#[test]
fn embedded_icmp_nat_match_ignores_non_error_echo() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 64);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let mut sessions = SessionTable::new();
    let forwarding = ForwardingState::default();
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));

    let result = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    );
    assert!(
        result.is_none(),
        "non-error ICMP echo should not trigger embedded NAT reversal"
    );
}

fn build_policy_deny_tcp_syn_frame() -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200,
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    frame.extend_from_slice(&12345u16.to_be_bytes());
    frame.extend_from_slice(&5201u16.to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, TCP_FLAG_SYN, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00]);
    frame
}

fn set_ipv4_dst(frame: &mut [u8], dst: Ipv4Addr) {
    frame[24] = 0;
    frame[25] = 0;
    frame[30..34].copy_from_slice(&dst.octets());
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
}

#[test]
fn poll_descriptor_policy_deny_path_emits_rt_flow_event() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
        },
        ZoneSnapshot {
            name: "dmz".to_string(),
            id: TEST_DMZ_ZONE_ID,
        },
    ];
    snapshot.neighbors = vec![NeighborSnapshot {
        interface: "ge-0-0-0.80".to_string(),
        ifindex: 12,
        family: "inet".to_string(),
        ip: "172.16.80.200".to_string(),
        mac: "00:aa:bb:cc:dd:ee".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let frame = build_policy_deny_tcp_syn_frame();
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: (frame.len() - 14) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut sessions = SessionTable::new();
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    let event = event_rx
        .try_recv()
        .expect("policy-deny event from poll descriptor")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::PolicyDeny
    );
    assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(event.egress_zone_id, TEST_WAN_ZONE_ID);
    assert_eq!(event.ingress_ifindex, 24);
    assert_eq!(event.src_port, 12345);
    assert_eq!(event.dst_port, 5201);
    assert_eq!(event.timestamp_ns, 0);
    assert_eq!(event_handle.dataplane_event_stats().policy_deny.sent, 1);
    assert!(telemetry.dbg.policy_deny >= 1);
}

#[test]
fn poll_descriptor_input_filter_log_path_emits_rt_flow_event() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
        },
    ];
    snapshot.interfaces[0].filter_input_v4 = "log-input".to_string();
    snapshot.neighbors = vec![NeighborSnapshot {
        interface: "reth0.80".to_string(),
        ifindex: 12,
        family: "inet".to_string(),
        ip: "172.16.80.200".to_string(),
        mac: "00:aa:bb:cc:dd:ee".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    }];
    snapshot.routes = vec![RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "0.0.0.0/0".to_string(),
        next_hops: vec!["172.16.80.200@reth0.80".to_string()],
        discard: false,
        next_table: String::new(),
    }];
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "log-input".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "log-web".to_string(),
            action: "accept".to_string(),
            destination_ports: vec!["5201".to_string()],
            log: true,
            ..Default::default()
        }],
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let frame = build_policy_deny_tcp_syn_frame();
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: (frame.len() - 14) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut sessions = SessionTable::new();
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    let event = event_rx
        .try_recv()
        .expect("input filter-log event from poll descriptor")
        .decode_dataplane_event()
        .expect("filter-log payload");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::FilterLog
    );
    assert_eq!(event.reason, FilterLogSource::Input.wire_reason());
    assert_eq!(event.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)));
    assert_eq!(event.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    assert_eq!(event.dst_port, 5201);
    assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(event.egress_zone_id, 0);
    assert_eq!(event_handle.dataplane_event_stats().filter_log.sent, 1);
}

#[test]
fn poll_descriptor_input_filter_discard_drops_and_logs() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
        },
    ];
    snapshot.interfaces[0].filter_input_v4 = "drop-input".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "drop-input".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "drop-web".to_string(),
            action: "discard".to_string(),
            destination_ports: vec!["5201".to_string()],
            log: true,
            ..Default::default()
        }],
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut frame = build_policy_deny_tcp_syn_frame();
    frame[47] = 0x10;
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: (frame.len() - 14) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut sessions = SessionTable::new();
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    let event = event_rx
        .try_recv()
        .expect("discard input filter-log event from poll descriptor")
        .decode_dataplane_event()
        .expect("discard filter-log payload");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::FilterLog
    );
    assert_eq!(event.reason, FilterLogSource::Input.wire_reason());
    assert_eq!(event.action, 0);
    assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert!(binding.scratch.scratch_forwards.is_empty());
    assert_eq!(sessions.len(), 0);
    assert_eq!(event_handle.dataplane_event_stats().filter_log.sent, 1);
}

#[test]
fn poll_descriptor_session_hit_rechecks_dscp_input_filter() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
        },
    ];
    snapshot.interfaces[0].filter_input_v4 = "drop-ef-input".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "drop-ef-input".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "drop-ef-web".to_string(),
            action: "discard".to_string(),
            destination_ports: vec!["5201".to_string()],
            dscp_values: vec![46],
            log: true,
            ..Default::default()
        }],
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut frame = build_policy_deny_tcp_syn_frame();
    frame[47] = 0x10;
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: (frame.len() - 14) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        dscp: 46,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut sessions = SessionTable::new();
    let flow_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port: 5201,
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: Some([0, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
    };
    assert!(sessions.install_with_protocol_with_origin(
        flow_key.clone(),
        decision,
        metadata,
        SessionOrigin::ForwardFlow,
        123_000_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(sessions.drain_deltas(16).len(), 1, "initial open delta");
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    let event = event_rx
        .try_recv()
        .expect("DSCP input filter-log event from session hit")
        .decode_dataplane_event()
        .expect("DSCP input filter-log payload");
    assert_eq!(event.reason, FilterLogSource::Input.wire_reason());
    assert_eq!(event.action, 0);
    assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert!(binding.scratch.scratch_forwards.is_empty());
    assert_eq!(sessions.len(), 1, "per-packet input drop keeps session");
    assert_eq!(event_handle.dataplane_event_stats().filter_log.sent, 1);
}

#[test]
fn poll_descriptor_lo0_filter_discard_drops_without_reinject() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
        },
    ];
    snapshot.interfaces[0].addresses = vec![InterfaceAddressSnapshot {
        family: "inet".to_string(),
        address: "10.0.61.1/24".to_string(),
        scope: 0,
    }];
    snapshot.flow.lo0_filter_input_v4 = "protect-re".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "protect-re".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "drop-web".to_string(),
            action: "discard".to_string(),
            destination_ports: vec!["5201".to_string()],
            log: true,
            ..Default::default()
        }],
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut frame = build_policy_deny_tcp_syn_frame();
    set_ipv4_dst(&mut frame, Ipv4Addr::new(10, 0, 61, 1));
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: (frame.len() - 14) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut sessions = SessionTable::new();
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    let event = event_rx
        .try_recv()
        .expect("lo0 filter-log event from poll descriptor")
        .decode_dataplane_event()
        .expect("lo0 filter-log payload");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::FilterLog
    );
    assert_eq!(event.reason, FilterLogSource::Lo0.wire_reason());
    assert_eq!(event.action, 0);
    assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert!(binding.scratch.scratch_forwards.is_empty());
    assert_eq!(sessions.len(), 0);
    assert_eq!(binding.live.slow_path_drops.load(Ordering::Relaxed), 0);
    assert!(recent_exceptions.lock().unwrap().is_empty());
    assert_eq!(event_handle.dataplane_event_stats().filter_log.sent, 1);
}

#[test]
fn poll_descriptor_lo0_filter_drops_cached_local_delivery_session_hit() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
        },
    ];
    snapshot.interfaces[0].addresses = vec![InterfaceAddressSnapshot {
        family: "inet".to_string(),
        address: "10.0.61.1/24".to_string(),
        scope: 0,
    }];
    snapshot.flow.lo0_filter_input_v4 = "protect-re".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "protect-re".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "drop-web".to_string(),
            action: "discard".to_string(),
            destination_ports: vec!["5201".to_string()],
            log: true,
            ..Default::default()
        }],
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut frame = build_policy_deny_tcp_syn_frame();
    set_ipv4_dst(&mut frame, Ipv4Addr::new(10, 0, 61, 1));
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: (frame.len() - 14) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut sessions = SessionTable::new();
    let flow_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)),
        src_port: 12345,
        dst_port: 5201,
    };
    let local_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 24,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let local_metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_LAN_ZONE_ID,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
    };
    assert!(sessions.install_with_protocol_with_origin(
        flow_key.clone(),
        local_decision,
        local_metadata.clone(),
        SessionOrigin::LocalMiss,
        123_000_000_000,
        PROTO_TCP,
        TCP_FLAG_SYN,
    ));
    let shared_entry = SyncedSessionEntry {
        key: flow_key.clone(),
        decision: local_decision,
        metadata: local_metadata,
        origin: SessionOrigin::LocalMiss,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
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
    assert_eq!(sessions.drain_deltas(16).len(), 1, "initial open delta");
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    let event = event_rx
        .try_recv()
        .expect("lo0 filter-log event from cached local session hit")
        .decode_dataplane_event()
        .expect("lo0 filter-log payload");
    assert_eq!(event.reason, FilterLogSource::Lo0.wire_reason());
    assert_eq!(event.action, 0);
    assert!(binding.scratch.scratch_forwards.is_empty());
    assert_eq!(sessions.len(), 0);
    assert!(shared_sessions.lock().expect("shared sessions").is_empty());
    assert!(shared_nat_sessions.lock().expect("shared nat").is_empty());
    assert!(
        shared_forward_wire_sessions
            .lock()
            .expect("shared forward wire")
            .is_empty()
    );
    let deltas = sessions.drain_deltas(16);
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
    assert_eq!(deltas[0].key, flow_key);
    assert_eq!(binding.live.slow_path_drops.load(Ordering::Relaxed), 0);
    assert!(recent_exceptions.lock().unwrap().is_empty());
    assert_eq!(event_handle.dataplane_event_stats().filter_log.sent, 1);
}

#[test]
fn maybe_reinject_slow_path_ignores_forward_candidate_disposition() {
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

    let binding = BindingIdentity {
        slot: 3,
        queue_id: 2,
        worker_id: 1,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };

    maybe_reinject_slow_path(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        decision,
        &recent_exceptions,
        &ForwardingState::default(),
    );

    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
    assert!(recent_exceptions.lock().expect("exceptions").is_empty());
}

// #1913: the slow-path eligibility predicate is the single source of
// truth for which dispositions may be reinjected to the kernel slow
// path. PolicyDenied / HAInactive / DiscardRoute (and the
// forward/fabric dispositions) MUST be rejected so a zone-policy DENY is
// not silently bypassed on the cold path.
#[test]
fn slow_path_eligibility_predicate_allow_list() {
    use ForwardingDisposition::*;
    // Eligible: terminate locally or defer to the kernel FIB.
    assert!(LocalDelivery.is_slow_path_eligible());
    assert!(NoRoute.is_slow_path_eligible());
    assert!(MissingNeighbor.is_slow_path_eligible());
    assert!(NextTableUnsupported.is_slow_path_eligible());
    // NOT eligible: must drop, never reinject.
    assert!(!PolicyDenied.is_slow_path_eligible());
    assert!(!HAInactive.is_slow_path_eligible());
    assert!(!DiscardRoute.is_slow_path_eligible());
    // Forward/fabric dispositions never reach the generic slow path.
    assert!(!ForwardCandidate.is_slow_path_eligible());
    assert!(!FabricRedirect.is_slow_path_eligible());
}

// #1913: the filtered wrapper must drop (no enqueue, no exception,
// no drop-counter bump) for every should-drop disposition. Exercises
// the shared predicate via maybe_reinject_slow_path with a valid frame
// so the only thing keeping the packet out of the slow path is the
// disposition filter.
#[test]
fn maybe_reinject_slow_path_drops_ineligible_dispositions() {
    for disposition in [
        ForwardingDisposition::PolicyDenied,
        ForwardingDisposition::HAInactive,
        ForwardingDisposition::DiscardRoute,
    ] {
        let frame =
            build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

        let binding = BindingIdentity {
            slot: 3,
            queue_id: 2,
            worker_id: 1,
            interface: Arc::<str>::from("ge-0-0-1"),
            ifindex: 5,
        };
        let live = BindingLiveState::new();
        let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition,
                local_ifindex: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                src_mac: Some([6, 7, 8, 9, 10, 11]),
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        };

        maybe_reinject_slow_path(
            &binding,
            &live,
            None,
            &local_tunnel_reinjectors,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            decision,
            &recent_exceptions,
            &ForwardingState::default(),
        );

        assert_eq!(
            live.slow_path_packets.load(Ordering::Relaxed),
            0,
            "{disposition:?} must not be enqueued to the slow path",
        );
        assert_eq!(
            live.slow_path_drops.load(Ordering::Relaxed),
            0,
            "{disposition:?} is filtered before any drop accounting",
        );
        assert!(
            recent_exceptions.lock().expect("exceptions").is_empty(),
            "{disposition:?} filtered cleanly with no exception",
        );
    }
}

#[test]
fn maybe_reinject_slow_path_records_extract_failure_for_invalid_desc() {
    let area = MmapArea::new(128).expect("mmap");
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let binding = BindingIdentity {
        slot: 3,
        queue_id: 2,
        worker_id: 1,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
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
        nat: NatDecision::default(),
    };

    // Addr beyond the registered UMEM length forces an extract failure.
    maybe_reinject_slow_path(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &area,
        XdpDesc {
            addr: 512,
            len: 96,
            options: 0,
        },
        meta,
        decision,
        &recent_exceptions,
        &ForwardingState::default(),
    );

    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
    let exceptions = recent_exceptions.lock().expect("exceptions");
    let last = exceptions.back().expect("exception recorded");
    assert_eq!(last.reason, "slow_path_extract_failed");
    assert_eq!(last.packet_length, 96);
}

#[test]
fn maybe_reinject_slow_path_from_frame_records_unavailable() {
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
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
        nat: NatDecision::default(),
    };

    maybe_reinject_slow_path_from_frame(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &frame,
        meta,
        decision,
        &recent_exceptions,
        "forward_build_slow_path",
        &ForwardingState::default(),
    );

    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
    let exceptions = recent_exceptions.lock().expect("exceptions");
    let last = exceptions.back().expect("exception recorded");
    assert_eq!(last.reason, "slow_path_unavailable");
    assert_eq!(last.ifindex, 6);
}

#[test]
fn handle_forward_build_failure_records_build_and_slow_path_failures() {
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
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
        nat: NatDecision::default(),
    };
    let mut dbg = DebugPollCounters::default();
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

    handle_forward_build_failure(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &recent_exceptions,
        &mut dbg,
        6,
        frame.len() as u32,
        &frame,
        meta,
        decision,
        true,
        &ForwardingState::default(),
    );

    assert_eq!(dbg.build_fail, 1);
    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|entry| entry.reason.clone())
        .collect();
    assert_eq!(
        reasons,
        vec!["forward_build_failed", "slow_path_unavailable"]
    );
}

#[test]
fn handle_forward_build_failure_without_fallback_only_records_build_failure() {
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let mut dbg = DebugPollCounters::default();
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

    handle_forward_build_failure(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &recent_exceptions,
        &mut dbg,
        12,
        frame.len() as u32,
        &frame,
        meta,
        decision,
        false,
        &ForwardingState::default(),
    );

    assert_eq!(dbg.build_fail, 1);
    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|entry| entry.reason.clone())
        .collect();
    assert_eq!(reasons, vec!["forward_build_failed"]);
}

/// #1946: a FabricRedirect frame whose forward-frame build/enqueue failed
/// must NOT be raw-reinjected to the local kernel slow path (a
/// cross-chassis L2 redirect is not kernel-FIB routable — wrong-path /
/// conntrack-poison hazard). It is dropped fail-closed and counted on the
/// shared `fabric_redirect_unsendable_drops` counter with a distinct
/// `fabric_redirect_build_failed` exception, even when
/// `fallback_to_slow_path == true`.
#[test]
fn handle_forward_build_failure_drops_fabric_redirect_fail_closed() {
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::FabricRedirect,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let mut dbg = DebugPollCounters::default();
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

    // `slow_path = None` would make even an eligible disposition record a
    // `slow_path_unavailable` drop; pass None so that, if the gate were
    // ever removed, the reasons vector would differ from the expected
    // fail-closed sequence and the test would catch the regression.
    handle_forward_build_failure(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &recent_exceptions,
        &mut dbg,
        12,
        frame.len() as u32,
        &frame,
        meta,
        decision,
        true,
        &ForwardingState::default(),
    );

    assert_eq!(dbg.build_fail, 1);
    assert_eq!(
        live.fabric_redirect_unsendable_drops
            .load(Ordering::Relaxed),
        1
    );
    // Fail-closed: no slow-path reinjection of any kind.
    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|entry| entry.reason.clone())
        .collect();
    assert_eq!(
        reasons,
        vec!["forward_build_failed", "fabric_redirect_build_failed"]
    );
}

/// #1946 regression guard: the FabricRedirect gate in
/// `handle_forward_build_failure` must be disposition-specific.
/// `ForwardCandidate` IS a route the kernel FIB may legitimately serve,
/// so it must STILL reinject (not be caught by the fabric gate). With
/// `slow_path = None` the reinject lands on `slow_path_unavailable`,
/// proving the gate let it through.
#[test]
fn handle_forward_build_failure_still_reinjects_forward_candidate() {
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let mut dbg = DebugPollCounters::default();
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

    handle_forward_build_failure(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &recent_exceptions,
        &mut dbg,
        12,
        frame.len() as u32,
        &frame,
        meta,
        decision,
        true,
        &ForwardingState::default(),
    );

    assert_eq!(dbg.build_fail, 1);
    // The fabric gate must NOT have caught a ForwardCandidate.
    assert_eq!(
        live.fabric_redirect_unsendable_drops
            .load(Ordering::Relaxed),
        0
    );
    // It reinjected (and dropped only because slow_path is None).
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|entry| entry.reason.clone())
        .collect();
    assert_eq!(
        reasons,
        vec!["forward_build_failed", "slow_path_unavailable"]
    );
}

#[test]
fn slow_path_accept_is_categorized_by_reason_and_disposition() {
    let live = BindingLiveState::new();

    live.record_slow_path_accept(ForwardingDisposition::MissingNeighbor, "slow_path", 128);
    live.record_slow_path_accept(
        ForwardingDisposition::NoRoute,
        "forward_build_slow_path",
        64,
    );

    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 2);
    assert_eq!(live.slow_path_bytes.load(Ordering::Relaxed), 192);
    assert_eq!(
        live.slow_path_missing_neighbor_packets
            .load(Ordering::Relaxed),
        1
    );
}

// #1187: regression tests for DispositionCounters hot/cold accounting modes.
// Hot callers must accumulate in BatchCounters and only write to
// BindingLiveState on flush(). Cold callers must write immediately.

#[test]
fn disposition_counters_hot_accumulates_in_batch_not_live() {
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let binding = BindingIdentity {
        slot: 1,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-0"),
        ifindex: 3,
    };
    let mut counters = BatchCounters::default();

    // Before any calls: live counter must be 0, batch must be clean.
    assert_eq!(live.policy_denied_packets.load(Ordering::Relaxed), 0);
    assert!(!counters.touched);

    // Hot call — should land in batch, not in live.
    record_forwarding_disposition(
        &binding,
        DispositionCounters::Hot(&mut counters),
        ForwardingResolution {
            disposition: ForwardingDisposition::PolicyDenied,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        64,
        None,
        None,
        &recent_exceptions,
        &Arc::new(Mutex::new(None)),
        &ForwardingState::default(),
    );

    assert_eq!(
        counters.policy_denied_packets, 1,
        "batch should hold the count"
    );
    assert_eq!(
        live.policy_denied_packets.load(Ordering::Relaxed),
        0,
        "live must not be updated before flush"
    );
    assert!(counters.touched, "touched flag must be set after hot bump");

    // After flush: batch clears, live receives the accumulated count.
    counters.flush(&live);
    assert_eq!(
        counters.policy_denied_packets, 0,
        "batch must be zero after flush"
    );
    assert_eq!(
        live.policy_denied_packets.load(Ordering::Relaxed),
        1,
        "live must receive count after flush"
    );
    assert!(!counters.touched, "touched flag must clear after flush");
}

#[test]
fn disposition_counters_cold_writes_live_immediately() {
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let binding = BindingIdentity {
        slot: 1,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-0"),
        ifindex: 3,
    };

    // Before any calls: live counter must be 0.
    assert_eq!(live.route_miss_packets.load(Ordering::Relaxed), 0);

    // Cold call — should write to live immediately, no batch involved.
    record_forwarding_disposition(
        &binding,
        DispositionCounters::Cold(&live),
        ForwardingResolution {
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
        64,
        None,
        None,
        &recent_exceptions,
        &Arc::new(Mutex::new(None)),
        &ForwardingState::default(),
    );

    assert_eq!(
        live.route_miss_packets.load(Ordering::Relaxed),
        1,
        "cold path must update live immediately"
    );
}

#[test]
fn disposition_counters_hot_screen_drops_accumulate_in_batch() {
    let live = BindingLiveState::new();
    let mut counters = BatchCounters::default();

    // Simulate the screen-check fast path directly (3 drops).
    for _ in 0..3 {
        counters.touched = true;
        counters.screen_drops += 1;
    }

    assert_eq!(counters.screen_drops, 3);
    assert_eq!(
        live.screen_drops.load(Ordering::Relaxed),
        0,
        "live must be 0 before flush"
    );

    counters.flush(&live);
    assert_eq!(counters.screen_drops, 0, "batch must clear after flush");
    assert_eq!(
        live.screen_drops.load(Ordering::Relaxed),
        3,
        "live must receive count after flush"
    );
}

#[test]
fn syn_cookie_counters_hot_path_accumulate_in_batch() {
    let live = BindingLiveState::new();
    let mut counters = BatchCounters::default();

    counters.touched = true;
    counters.syn_cookie_challenges = 2;
    counters.syn_cookie_secret_unavailable = 3;
    counters.syn_cookie_syn_ack_sent = 5;
    counters.syn_cookie_ack_rst_sent = 7;
    counters.syn_cookie_reply_budget_drops = 11;
    counters.syn_cookie_ack_valid = 13;
    counters.syn_cookie_ack_invalid = 17;
    counters.syn_cookie_bypass = 19;

    counters.flush(&live);

    assert_eq!(counters.syn_cookie_challenges, 0);
    assert_eq!(counters.syn_cookie_secret_unavailable, 0);
    assert_eq!(counters.syn_cookie_syn_ack_sent, 0);
    assert_eq!(counters.syn_cookie_ack_rst_sent, 0);
    assert_eq!(counters.syn_cookie_reply_budget_drops, 0);
    assert_eq!(counters.syn_cookie_ack_valid, 0);
    assert_eq!(counters.syn_cookie_ack_invalid, 0);
    assert_eq!(counters.syn_cookie_bypass, 0);
    assert_eq!(live.syn_cookie_challenges.load(Ordering::Relaxed), 2);
    assert_eq!(
        live.syn_cookie_secret_unavailable.load(Ordering::Relaxed),
        3
    );
    assert_eq!(live.syn_cookie_syn_ack_sent.load(Ordering::Relaxed), 5);
    assert_eq!(live.syn_cookie_ack_rst_sent.load(Ordering::Relaxed), 7);
    assert_eq!(
        live.syn_cookie_reply_budget_drops.load(Ordering::Relaxed),
        11
    );
    assert_eq!(live.syn_cookie_ack_valid.load(Ordering::Relaxed), 13);
    assert_eq!(live.syn_cookie_ack_invalid.load(Ordering::Relaxed), 17);
    assert_eq!(live.syn_cookie_bypass.load(Ordering::Relaxed), 19);
}

// ── #1861: transactional forward+reverse install — interleaving pins ──
//
// Deterministic at-cap pins for every interleaving in
// docs/research/1861-install-txn/plan.md §4 that the fix targets:
// I1/I2 (refusal drops the trigger packet, rolls back SNAT, caches
// nothing), I3 (reverse never attempted without forward), I4 boundary
// (pair admitted at cap-2, refused at cap-1), I5 (failed reply repair
// still forwards, is NOT flow-cached, and self-heals below cap), I6
// (refused seed is recycled, not buffered), I14 (NAT64 refusal drops).

fn txn_ha_state() -> BTreeMap<i32, HAGroupRuntime> {
    let mut ha = BTreeMap::new();
    for rg in [1, 2] {
        ha.insert(
            rg,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: 123,
                lease: HAGroupRuntime::active_lease_until(123, 123),
            },
        );
    }
    ha
}

fn build_txn_tcp_syn_frame_v4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0x02, 0xbf, 0x72, 0x01, 0x00, 0x01],
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        0,
        0x0800,
    );
    let s = src.octets();
    let d = dst.octets();
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, s[0], s[1],
        s[2], s[3], d[0], d[1], d[2], d[3],
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, tcp_flags, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00]);
    frame
}

fn txn_meta_v4(ingress_ifindex: u32, tcp_flags: u8, pkt_len: u16) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

/// Push one frame through `poll_binding_process_descriptor` against the
/// given table/forwarding state. Owns the per-call shared-map and
/// telemetry scaffolding; the caller keeps `binding` + `sessions` across
/// calls so multi-phase pins can observe accumulated state.
fn txn_run_descriptor(
    binding: &mut BindingWorker,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> (BatchCounters, DebugPollCounters) {
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    txn_run_descriptor_with_deliveries(
        binding,
        sessions,
        forwarding,
        ha_state,
        frame,
        meta,
        &local_tunnel_deliveries,
    )
}

/// `txn_run_descriptor` with a caller-provided `local_tunnel_deliveries`
/// map, so the GRE local-origin INBOUND delivery pins (#1885) can
/// observe exactly the bytes that would be written to the gr- TUN.
fn txn_run_descriptor_with_deliveries(
    binding: &mut BindingWorker,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    frame: &[u8],
    meta: UserspaceDpMeta,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
) -> (BatchCounters, DebugPollCounters) {
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(binding));
    let mirror_targets = MirrorTargetMap::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding,
        ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        slow_path: None,
        event_stream: None,
        local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;
    poll_binding_process_descriptor(
        binding,
        0,
        area_ptr,
        1,
        sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );
    (batch, dbg)
}

fn txn_flow_cache_entries(binding: &BindingWorker) -> usize {
    binding.flow.flow_cache.entries.iter().flatten().count()
}

// I1/I2/I3: at cap, a NAT'd new flow is REFUSED — trigger packet dropped
// (not forwarded), nothing installed (forward NOR reverse), nothing
// flow-cached, refusal counted.
#[test]
fn txn_admission_refusal_at_cap_drops_and_leaks_nothing() {
    let forwarding = build_forwarding_state(&nat_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(0);

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, (frame.len() - 14) as u16);
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
        "refused flow's trigger packet must NOT be forwarded"
    );
    assert!(
        binding.scratch.scratch_recycle.contains(&128),
        "refused flow's trigger frame must be recycled"
    );
    assert_eq!(sessions.len(), 0, "no forward or reverse entry may leak");
    assert_eq!(sessions.admission_refused(), 1);
    assert_eq!(sessions.install_partial(), 0);
    assert_eq!(
        txn_flow_cache_entries(&binding),
        0,
        "a refused flow's (rolled-back) NAT decision must never be cached"
    );
    assert_eq!(batch.session_creates, 0);
}

// I4 boundary: a forward+reverse pair is admitted while 2 slots remain
// and refused at cap-1 (1 slot remaining). The admitted phase also pins
// that a passing preflight makes both installs succeed.
#[test]
fn txn_pair_admitted_at_cap_minus_two_refused_at_cap_minus_one() {
    let forwarding = build_forwarding_state(&nat_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(2);

    // Phase 1: len 0, cap 2 — exactly the pair fits.
    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, (frame.len() - 14) as u16);
    let (_b1, d1) = txn_run_descriptor(
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
        "forward + reverse must both install when the pair fits"
    );
    assert_eq!(d1.tx, 1, "admitted flow forwards its trigger packet");
    assert_eq!(sessions.admission_refused(), 0);

    // Phase 2: len 2, cap 3 — one free slot, a pair needs two: refuse.
    sessions.set_max_sessions_for_test(3);
    let frame2 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12346,
        443,
        TCP_FLAG_SYN,
    );
    let meta2 = txn_meta_v4(24, TCP_FLAG_SYN, (frame2.len() - 14) as u16);
    let (_b2, d2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame2,
        meta2,
    );
    assert_eq!(
        sessions.len(),
        2,
        "cap-1 must refuse the pair — no one-sided forward install"
    );
    assert_eq!(sessions.admission_refused(), 1);
    assert_eq!(
        d2.tx, 0,
        "refused flow at cap-1 must not forward its trigger packet"
    );
    assert_eq!(sessions.install_partial(), 0);
}

// I2 (pool-mode): the refusal arm releases the pool-SNAT allocation AND
// the flow cache stays empty — the pre-fix behavior cached the
// rolled-back tuple, persisting an unreserved translated (ip,port) on
// the wire (cross-flow aliasing, plan §2).
#[test]
fn txn_pool_snat_refusal_rolls_back_allocation_and_caches_nothing() {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "snat-pool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "pool-a".to_string(),
        pool_addresses: vec!["172.16.80.100".to_string()],
        port_low: 20000,
        port_high: 20999,
        ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(0);

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, (frame.len() - 14) as u16);
    let (_b, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(dbg.tx, 0, "refused pool-SNAT flow must not forward");
    assert_eq!(sessions.len(), 0);
    assert_eq!(sessions.admission_refused(), 1);
    let pools = crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules);
    assert_eq!(pools.len(), 1);
    assert_eq!(
        pools[0].live_flows, 0,
        "refused flow's pool-SNAT allocation must be rolled back"
    );
    assert_eq!(
        txn_flow_cache_entries(&binding),
        0,
        "the rolled-back pool tuple must NOT persist in the flow cache"
    );
}

// I5: a reply whose reverse-session repair install fails at cap is still
// forwarded but NOT flow-cached, so the repair re-fires per packet and
// installs the reverse session on the first reply after capacity frees
// (plan §5.4, Codex r1 C1). Also pins created==install outcome (AGY r1
// F1): a failed repair must not count a session create.
#[test]
fn txn_failed_reply_repair_forwards_uncached_then_self_heals_below_cap() {
    let mut snapshot = nat_snapshot();
    // The repair resolves the reply toward the LAN host; give it a
    // neighbor so the rebuilt reverse decision is a ForwardCandidate.
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "ge-0-0-1".to_string(),
        ifindex: 24,
        family: "inet".to_string(),
        ip: "10.0.61.102".to_string(),
        mac: "0a:0b:0c:0d:0e:0f".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    });
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    // Forward session: 10.0.61.102:12345 -> 8.8.8.8:443, interface SNAT
    // to 172.16.80.8 (no port rewrite). Installed below cap, then the
    // table is pinned at cap so the repair's reverse install must fail.
    let forward_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port: 12345,
        dst_port: 443,
    };
    let forward_decision = SessionDecision {
        resolution: lookup_forwarding_resolution(
            &forwarding,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    assert!(sessions.install_with_protocol_with_origin(
        forward_key,
        forward_decision,
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        TCP_FLAG_SYN,
    ));
    sessions.set_max_sessions_for_test(1);

    // Reply: 8.8.8.8:443 -> 172.16.80.8:12345 (pure ACK) from the WAN.
    let reply = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(172, 16, 80, 8),
        443,
        12345,
        0x10,
    );
    let meta = txn_meta_v4(12, 0x10, (reply.len() - 14) as u16);
    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &reply,
        meta,
    );
    assert_eq!(
        dbg.tx, 1,
        "reply must still forward when the repair install fails at cap"
    );
    assert_eq!(sessions.len(), 1, "repair install refused at cap");
    assert_eq!(
        batch.session_creates, 0,
        "a failed repair install must not count a session create (created flag)"
    );
    assert_eq!(
        txn_flow_cache_entries(&binding),
        0,
        "a failed repair's sessionless decision must NOT be flow-cached"
    );

    // Below cap, the next reply re-fires the repair and installs the
    // reverse session — the self-heal property the cache gate restores.
    sessions.set_max_sessions_for_test(16);
    let meta2 = txn_meta_v4(12, 0x10, (reply.len() - 14) as u16);
    let (batch2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &reply,
        meta2,
    );
    assert_eq!(
        sessions.len(),
        2,
        "below cap the repair must install the reverse session"
    );
    assert_eq!(batch2.session_creates, 1);
    assert_eq!(dbg2.tx, 1, "self-healed reply forwards as well");
}

// I6: a MissingNeighborSeed install refused at cap must NOT buffer the
// frame for neighbor-resolution replay (the replay would forward on the
// rolled-back SNAT tuple with no session). Below cap the seed installs
// and the frame buffers as before.
#[test]
fn txn_refused_seed_recycles_instead_of_buffering() {
    let mut snapshot = nat_snapshot();
    // Remove the gateway neighbor: 8.8.8.8 routes via 172.16.80.1 whose
    // MAC is now unknown -> MissingNeighbor seed path.
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(0);

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, (frame.len() - 14) as u16);
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(sessions.len(), 0, "seed install refused at cap");
    assert!(
        binding.pending_neigh.is_empty(),
        "a refused seed's frame must be recycled, not buffered for replay"
    );

    // Below cap: the seed installs and the representative frame buffers.
    sessions.set_max_sessions_for_test(16);
    let meta2 = txn_meta_v4(24, TCP_FLAG_SYN, (frame.len() - 14) as u16);
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta2,
    );
    assert_eq!(sessions.len(), 1, "seed installs below cap");
    assert_eq!(
        binding.pending_neigh.len(),
        1,
        "below cap the representative frame buffers as before"
    );
}

fn build_txn_tcp_syn_frame_v6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0x02, 0xbf, 0x72, 0x01, 0x00, 0x01],
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        0,
        0x86dd,
    );
    // IPv6 header: version 6, payload len 20 (TCP), next header TCP, hop 64.
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x14, PROTO_TCP, 64]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let tcp_start = frame.len();
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, TCP_FLAG_SYN, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00]);
    let csum = checksum16_ipv6(src, dst, PROTO_TCP, &frame[tcp_start..]);
    frame[tcp_start + 16] = (csum >> 8) as u8;
    frame[tcp_start + 17] = csum as u8;
    frame
}

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

    // Reverse: the v4 server reply (8.8.8.8:443 -> 172.16.80.50:12345 — the
    // SNAT pool address, port preserved because forward_decision keeps the
    // source port) hits the reverse session and translates v4->v6, bumping
    // the counter again.
    let pool_v4: Ipv4Addr = "172.16.80.50".parse().expect("pool v4");
    let dst_v4: Ipv4Addr = "8.8.8.8".parse().expect("dst v4");
    // SYN-ACK = SYN (0x02) | ACK (0x10). TCP_FLAG_ACK is not exported at the
    // afxdp module level, so spell the ACK bit inline.
    const ACK: u8 = 0x10;
    let reply_frame = build_txn_tcp_syn_frame_v4(dst_v4, pool_v4, 443, 12345, TCP_FLAG_SYN | ACK);
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

// === #1873 R-C: blanket tunnel gate at the slow-path chokepoint ===

fn tunnel_gate_test_fixture() -> (
    BindingIdentity,
    BindingLiveState,
    Arc<Mutex<VecDeque<ExceptionStatus>>>,
    UserspaceDpMeta,
    Vec<u8>,
) {
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    (binding, live, recent_exceptions, meta, frame)
}

fn tunnel_marked_decision(disposition: ForwardingDisposition) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition,
            local_ifindex: 0,
            egress_ifindex: 6,
            tx_ifindex: 0,
            tunnel_endpoint_id: 824,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    }
}

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
    let mut deliveries = BTreeMap::new();
    deliveries.insert(9, tx);
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
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
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
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
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

/// #1885 fixture: WAN underlay (reth0.80, VLAN 80) + a gre endpoint
/// whose local outer address is 172.16.80.8 and whose gr- interface
/// (ifindex 77) carries the inner address 10.255.0.1/30, so an inner
/// packet to 10.255.0.1 resolves LocalDelivery with
/// `local_ifindex == 77` — the `local_tunnel_deliveries` key.
/// Default-permit so host-inbound resolution, not policy, decides.
fn gre_to_self_snapshot() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.source_nat_rules.clear();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "gr-0/0/0.0".to_string(),
        zone: "wan".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 77,
        tunnel: true,
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.255.0.1/30".to_string(),
            scope: 0,
        }],
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
    snapshot
}

/// Inner ICMP echo request 10.255.0.2 -> 10.255.0.1 (the gr-local
/// inner address): 20-byte IPv4 header + 8-byte ICMP + 8 payload.
fn build_gre_inner_icmp_packet_v4() -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x24, 0x00, 0x01, 0x00, 0x00, 64, PROTO_ICMP, 0x00, 0x00, 10, 255, 0, 2,
        10, 255, 0, 1,
    ]);
    let ip_sum = checksum16(&packet[0..20]);
    packet[10] = (ip_sum >> 8) as u8;
    packet[11] = ip_sum as u8;
    let mut icmp = vec![8u8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
    icmp.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]);
    let icmp_sum = checksum16(&icmp);
    icmp[2] = (icmp_sum >> 8) as u8;
    icmp[3] = icmp_sum as u8;
    packet.extend_from_slice(&icmp);
    packet
}

/// GRE-to-self OUTER frame: peer 203.0.113.9 -> local 172.16.80.8,
/// proto 47, flagless GRE (proto 0x0800) wrapping `inner`. `vlan_id`
/// 0 = untagged underlay (L3 at 14); nonzero = 802.1Q-tagged underlay
/// (L3 at 18) — the live reth0.80 shape from #1885.
fn build_gre_to_self_outer_frame_v4(vlan_id: u16, inner: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        vlan_id,
        0x0800,
    );
    let l3 = frame.len();
    let total = (20 + 4 + inner.len()) as u16;
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&[
        0x00, 0x01, 0x00, 0x00, 64, PROTO_GRE, 0x00, 0x00, 203, 0, 113, 9, 172, 16, 80, 8,
    ]);
    let ip_sum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10] = (ip_sum >> 8) as u8;
    frame[l3 + 11] = ip_sum as u8;
    frame.extend_from_slice(&[0x00, 0x00, 0x08, 0x00]); // flagless GRE, proto IPv4
    frame.extend_from_slice(inner);
    frame
}

/// Shim-contract meta for the GRE OUTER frame (`parse_l2` in
/// userspace-xdp is VLAN-aware: tagged L3 at 18, untagged at 14).
fn gre_to_self_outer_meta(vlan_id: u16, frame_len: usize) -> UserspaceDpMeta {
    let l3: u16 = if vlan_id > 0 { 18 } else { 14 };
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 11,
        ingress_vlan_id: vlan_id,
        ingress_vlan_present: u8::from(vlan_id > 0),
        l3_offset: l3,
        l4_offset: l3 + 20,
        payload_offset: l3 + 24,
        pkt_len: frame_len as u16 - l3,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_GRE,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

/// #1885 driver: run one GRE-to-self outer frame end-to-end through
/// `poll_binding_process_descriptor` with a registered gr- delivery
/// channel and assert the TUN-bound payload is the decapped INNER
/// packet, byte-identical, delivered EXACTLY once.
fn assert_gre_to_self_delivers_inner_exactly_once(vlan_id: u16) {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    let mut sessions = SessionTable::new();

    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_v4(vlan_id, &inner);
    let meta = gre_to_self_outer_meta(vlan_id, frame.len());

    let (tx, rx) = mpsc::sync_channel(8);
    let mut deliveries = BTreeMap::new();
    deliveries.insert(77, tx);
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));

    txn_run_descriptor_with_deliveries(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        &local_tunnel_deliveries,
    );

    let delivered = rx
        .try_recv()
        .expect("GRE-to-self inner packet must reach the gr- delivery channel");
    assert_eq!(
        delivered[0] >> 4,
        4,
        "TUN-bound payload must start with the IP version nibble \
         (IFF_NO_PI contract — the #1885 EINVAL observable), got {:02x?}",
        &delivered[..delivered.len().min(8)]
    );
    assert_eq!(
        delivered, inner,
        "delivery must be the decapped INNER packet byte-identical — \
         not an outer-frame slice (mis-paired frame/meta, #1885)"
    );
    assert!(
        rx.try_recv().is_err(),
        "exactly ONE delivery per packet — the LocalDelivery arm must \
         not enqueue in addition to the leg's trailing chokepoint"
    );
}

/// #1885 session-HIT pin: the live keepalive/echo-reply stream rides
/// an EXISTING session (the first packet installs it), so the
/// session-hit leg must ALSO deliver the decapped inner packet
/// exactly once. Runs the same tagged GRE-to-self frame twice through
/// one (binding, sessions) pair and asserts both deliveries.
#[test]
fn gre_to_self_session_hit_delivery_is_inner_packet_exactly_once() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    let mut sessions = SessionTable::new();

    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_v4(80, &inner);

    let (tx, rx) = mpsc::sync_channel(8);
    let mut deliveries = BTreeMap::new();
    deliveries.insert(77, tx);
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));

    for pass in ["session-miss", "session-hit"] {
        let meta = gre_to_self_outer_meta(80, frame.len());
        txn_run_descriptor_with_deliveries(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &frame,
            meta,
            &local_tunnel_deliveries,
        );
        let delivered = rx.try_recv().unwrap_or_else(|_| {
            panic!("{pass} pass must deliver the inner packet to the gr- channel")
        });
        assert_eq!(
            delivered, inner,
            "{pass} pass delivery must be the decapped INNER packet byte-identical"
        );
        assert!(
            rx.try_recv().is_err(),
            "{pass} pass must deliver exactly once"
        );
    }
}

/// #1885: VLAN-tagged underlay (the live reth0.80 topology). Pre-fix
/// the LocalDelivery arm sliced the ORIGINAL tagged outer frame at the
/// post-decap inner meta's l3_offset (14) — the payload started with
/// the dot1q TCI tail (`00 50 86 dd ...` in the issue strace) and
/// every TUN write failed EINVAL.
#[test]
fn gre_to_self_vlan_tagged_local_delivery_is_inner_packet_exactly_once() {
    assert_gre_to_self_delivers_inner_exactly_once(80);
}

/// #1885 blast radius: on an UNTAGGED underlay the mis-paired slice
/// started at the outer L3 header — a valid version nibble, so the TUN
/// write SUCCEEDED but delivered the still-encapsulated OUTER packet.
/// Byte-equality (not just the nibble check) pins this case.
#[test]
fn gre_to_self_untagged_local_delivery_is_inner_packet_exactly_once() {
    assert_gre_to_self_delivers_inner_exactly_once(0);
}

/// #1885 blast radius: NON-decapped local delivery was enqueued TWICE
/// (the in-arm desc-based call duplicated the leg's trailing
/// decap-aware chokepoint — both pass the same disposition filter).
/// A host-bound packet whose `local_ifindex` is not a registered
/// tunnel channel funnels to the kernel slow-path TUN; with no
/// reinjector wired the per-attempt `slow_path_drops` counter is the
/// enqueue-attempt observable: pre-#1885 this read 2, fixed it must
/// read exactly 1.
#[test]
fn unencapsulated_local_delivery_reinjects_slow_path_exactly_once() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 0, 1),
        12345,
        179,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, (frame.len() - 14) as u16);

    let (tx, rx) = mpsc::sync_channel(8);
    let mut deliveries = BTreeMap::new();
    deliveries.insert(77, tx);
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));

    let (_batch, dbg) = txn_run_descriptor_with_deliveries(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        &local_tunnel_deliveries,
    );

    assert_eq!(dbg.local, 1, "packet must take the LocalDelivery arm");
    assert!(
        rx.try_recv().is_err(),
        "a non-tunnel-ingress local packet must NOT hit the gr- channel"
    );
    assert_eq!(
        binding.live.slow_path_drops.load(Ordering::Relaxed),
        1,
        "exactly ONE slow-path enqueue attempt per LocalDelivery packet \
         (#1885 duplicate-enqueue pin — the in-arm call would make it 2)"
    );
}

/// #1885 decap-level consistency pin: on VLAN-TAGGED ingress the decap
/// must produce a synthetic frame and an inner meta that describe EACH
/// OTHER — `synthetic[meta.l3_offset..]` IS the inner packet. (The
/// poll-descriptor defect was pairing this inner meta with the
/// original outer frame instead of the synthetic one.)
#[test]
fn native_gre_decap_tagged_ingress_yields_self_consistent_frame_meta() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_v4(80, &inner);
    let meta = gre_to_self_outer_meta(80, frame.len());
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
        .expect("tagged GRE-to-self outer frame must decap");
    assert_eq!(
        &decap.frame[decap.meta.l3_offset as usize..],
        &inner[..],
        "synthetic frame and inner meta must be self-consistent"
    );
    assert_eq!(decap.meta.ingress_ifindex, 77);
    assert_eq!(decap.meta.addr_family, libc::AF_INET as u8);
}

/// #2327 fail-on-revert: a GRE (proto-47) frame whose outer tuple/key
/// match ONLY a non-GRE (here: WireGuard) tunnel row must NOT be
/// decapsulated as GRE. Pre-#2327 `match_tunnel_endpoint` scanned
/// `tunnel_endpoints.values()` ignoring `mode`, so any row whose outer
/// tuple lined up was decapped as GRE. We mutate the built state so the
/// ONLY endpoint that carries the matching outer tuple is mode
/// "wireguard" — the GRE decap must return `None` (no match / drop),
/// never decap the WireGuard endpoint's traffic as GRE. If the
/// kind-segregation in `match_tunnel_endpoint` / the build-side
/// `gre_decap_index` is reverted, this row reappears and the assert
/// fires.
#[test]
fn gre_decap_does_not_match_wireguard_row_with_same_outer_tuple() {
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    // Flip the single (GRE) endpoint to WireGuard while keeping the
    // exact outer tuple/key the inbound frame matches, and drop it from
    // the kind-segregated decap index (as the WG build path would).
    let id = 824u16;
    if let Some(ep) = forwarding.tunnel_endpoints.get_mut(&id) {
        ep.mode = "wireguard".to_string();
    }
    forwarding.gre_decap_index.clear();

    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_v4(80, &inner);
    let meta = gre_to_self_outer_meta(80, frame.len());
    assert!(
        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
        "a GRE frame matching only a WireGuard row must NOT decap as GRE"
    );
}

/// #2327 fail-on-revert (defense-in-depth pin): even if the build-side
/// index were wrong and surfaced a non-GRE endpoint id for the inbound
/// tuple, the per-candidate `tunnel_mode_kind` re-check in
/// `match_tunnel_endpoint` must reject it. Here the decap index DOES
/// point at the endpoint, but the endpoint's mode is non-GRE — the
/// match must still be `None`.
#[test]
fn gre_decap_rejects_non_gre_candidate_even_if_indexed() {
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let id = 824u16;
    if let Some(ep) = forwarding.tunnel_endpoints.get_mut(&id) {
        ep.mode = "wireguard".to_string();
    }
    // Index intentionally left pointing at the now-WireGuard endpoint to
    // exercise the per-candidate kind re-check.
    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_v4(80, &inner);
    let meta = gre_to_self_outer_meta(80, frame.len());
    assert!(
        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
        "the per-candidate kind re-check must reject a non-GRE endpoint \
         even when the decap index lists it"
    );
}

/// #2327 fail-on-revert: a genuine GRE frame matching a GRE-mode row
/// still decaps (the kind-segregation must not break the happy path).
/// Complements the existing
/// `native_gre_decap_tagged_ingress_yields_self_consistent_frame_meta`.
#[test]
fn gre_decap_still_matches_genuine_gre_row() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_v4(80, &inner);
    let meta = gre_to_self_outer_meta(80, frame.len());
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
        .expect("a genuine GRE frame matching a GRE row must still decap");
    assert_eq!(
        &decap.frame[decap.meta.l3_offset as usize..],
        &inner[..],
        "decapped inner packet must be byte-identical"
    );
}

/// #2327 fail-on-revert: the egress encap dispatcher must FAIL CLOSED on
/// an unknown tunnel mode — a row whose mode is neither GRE nor
/// WireGuard must NOT be silently GRE-encapsulated (the pre-#2327
/// `_ => GRE` fail-open default). `tunnel_mode_kind` classifies it as
/// `Unknown`; the dispatcher drops (`None`). Asserted at the kind layer
/// (the dispatch's `match` arms) so the test pins the fail-closed
/// contract without standing up a full forwarded-frame fixture.
#[test]
fn unknown_tunnel_mode_classifies_as_unknown_not_gre() {
    use crate::afxdp::{tunnel_mode_kind, TunnelKind};
    assert_eq!(tunnel_mode_kind("gre"), TunnelKind::Gre);
    assert_eq!(tunnel_mode_kind("ip6gre"), TunnelKind::Gre);
    assert_eq!(tunnel_mode_kind("wireguard"), TunnelKind::WireGuard);
    // Any unrecognized / future / malformed mode must NOT map to GRE.
    for bad in ["", "ipip", "vxlan", "GRE", "wireguard ", "gre6", "geneve"] {
        assert_eq!(
            tunnel_mode_kind(bad),
            TunnelKind::Unknown,
            "mode {bad:?} must classify Unknown (fail closed), never GRE"
        );
    }
}

/// #1902 fixture: inner TCP SYN L3 packet (no Ethernet header — it is
/// the flagless-GRE proto-0x0800 payload) 10.255.0.2 -> `dst`. With
/// `dst` on the reth1.0 connected subnet the decap-INBOUND forward
/// decision egresses a PLAIN interface (`tunnel_endpoint_id == 0`) —
/// not LocalDelivery, not a tunnel-marked encap — so a cold neighbor
/// reaches the MissingNeighbor pending_neigh admission site.
fn build_gre_inner_tcp_syn_packet_v4(dst: Ipv4Addr) -> Vec<u8> {
    let mut packet = Vec::new();
    let d = dst.octets();
    packet.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 255, 0, 2,
        d[0], d[1], d[2], d[3],
    ]);
    let ip_sum = checksum16(&packet[0..20]);
    packet[10] = (ip_sum >> 8) as u8;
    packet[11] = ip_sum as u8;
    packet.extend_from_slice(&12345u16.to_be_bytes());
    packet.extend_from_slice(&443u16.to_be_bytes());
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.extend_from_slice(&0u32.to_be_bytes());
    packet.extend_from_slice(&[0x50, TCP_FLAG_SYN, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00]);
    packet
}

/// #1902 driver: one GRE-to-self outer frame whose INNER packet
/// forwards out reth1.0 toward a COLD neighbor, end-to-end through
/// `poll_binding_process_descriptor`, then neighbor resolution +
/// `retry_pending_neigh`. Pre-#1902 the MissingNeighbor arm buffered
/// `desc` (the un-decapped OUTER UMEM frame, VLAN-tagged on the
/// reth0.80 underlay) paired with the post-decap INNER meta/decision,
/// and the retry swept that entry into a prepared TX — the
/// still-encapsulated outer GRE packet rewritten at inner-meta
/// offsets, transmitted toward the inner next-hop. Fixed: the packet
/// is never admitted (counted, recycled) and the retry TXes nothing;
/// first-packet delivery rides the trailing decap-aware slow-path
/// chokepoint (#1901), which pairs the INNER frame correctly.
fn assert_decapped_missing_neighbor_never_buffered_or_retried(vlan_id: u16) {
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    // bindings[0] = WAN parent ingress (ifindex 11); bindings[1] = the
    // inner-egress LAN binding (ifindex 24) so a defective retry TX has
    // a real target binding and would land in its pending_tx_prepared.
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 24, 0),
    ];
    bindings[0].interface = Arc::<str>::from("ge-0-0-0");
    bindings[1].interface = Arc::<str>::from("ge-0-0-1");
    let mut sessions = SessionTable::new();

    let inner_dst = Ipv4Addr::new(10, 0, 61, 50);
    let inner = build_gre_inner_tcp_syn_packet_v4(inner_dst);
    let frame = build_gre_to_self_outer_frame_v4(vlan_id, &inner);
    let meta = gre_to_self_outer_meta(vlan_id, frame.len());

    let (_batch, dbg) = txn_run_descriptor(
        &mut bindings[0],
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(
        dbg.missing_neigh, 1,
        "inner dst neighbor is cold -> the packet must take the MissingNeighbor arm"
    );
    assert!(
        bindings[0].pending_neigh.is_empty(),
        "#1902: a GRE-decapped packet must NEVER be admitted to pending_neigh — \
         desc references the un-decapped OUTER frame while meta/decision \
         describe the synthetic INNER frame"
    );
    assert_eq!(
        bindings[0]
            .live
            .pending_neigh_decap_drops
            .load(Ordering::Relaxed),
        1,
        "the decap-refusal gate must count the refused candidate"
    );
    assert!(
        bindings[0].scratch.scratch_recycle.contains(&128),
        "the refused frame must be recycled now, not pinned in pending_neigh"
    );

    // Resolve the inner next-hop and run the retry sweep: nothing may be
    // TXed from the (empty) buffer. Pre-#1902 this swept the mis-paired
    // entry into bindings[1].tx_pipeline.pending_tx_prepared.
    forwarding.neighbors.insert(
        (24, IpAddr::V4(inner_dst)),
        NeighborEntry {
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        },
    );
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut shared_recycles = Vec::new();
    let area = bindings[0].umem.area() as *const MmapArea;
    let (left, rest) = bindings.split_at_mut(0);
    let (binding, right) = rest.split_first_mut().expect("ingress binding");
    retry_pending_neigh(
        binding,
        left,
        0,
        right,
        &lookup,
        &mirror_targets,
        &forwarding,
        &dynamic_neighbors,
        None,
        123_000_000_100,
        // SAFETY: `area` was cast from `&MmapArea` borrowed out of
        // bindings[0].umem just above; the allocation lives past this
        // call, the split borrows cover disjoint binding state (not the
        // umem area), and the test is single-threaded.
        unsafe { &*area },
        &mut shared_recycles,
    );
    for (i, b) in bindings.iter().enumerate() {
        assert!(
            b.tx_pipeline.pending_tx_prepared.is_empty(),
            "binding {i}: no retried TX may exist for a decapped packet — \
             pre-#1902 the untagged variant held the OUTER GRE frame \
             (proto 47, outer dst = the firewall itself) truncated to the \
             inner length and MAC-rewritten toward the inner next-hop"
        );
    }
}

/// #1902: VLAN-tagged underlay (the live reth0.80 shape, #1885
/// parity) — the buffered outer frame's L3 sits at 18 while the inner
/// meta says 14, so the pre-fix retry rewrote the dot1q tail.
#[test]
fn txn_decapped_missing_neighbor_not_buffered_tagged() {
    assert_decapped_missing_neighbor_never_buffered_or_retried(80);
}

/// #1902: untagged underlay — `outer_frame[14..]` IS the outer L3
/// header (valid version nibble), so the pre-fix retry TXed the
/// still-encapsulated OUTER GRE packet toward the INNER next-hop.
/// Byte-indistinguishable from a valid frame at retry time, which is
/// why the fix gates ADMISSION rather than detecting at retry.
#[test]
fn txn_decapped_missing_neighbor_not_buffered_untagged() {
    assert_decapped_missing_neighbor_never_buffered_or_retried(0);
}

/// #1902 regression pin for the UNCHANGED path: a NON-decapped packet
/// (desc and meta describe the same UMEM frame) with a cold neighbor
/// must still buffer in pending_neigh, and after resolution the retry
/// must TX the correctly rewritten ORIGINAL packet (resolved dst MAC,
/// egress src MAC, TTL-1, IP/L4 bytes otherwise identical).
#[test]
fn txn_non_decap_missing_neighbor_buffers_and_retries_correctly() {
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    let mut bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 24, 0)];
    bindings[0].interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    // LAN hairpin: 10.0.61.102 -> 10.0.61.50, directly connected on
    // reth1.0 (egress == ingress binding), neighbor cold.
    let dst = Ipv4Addr::new(10, 0, 61, 50);
    let frame =
        build_txn_tcp_syn_frame_v4(Ipv4Addr::new(10, 0, 61, 102), dst, 12345, 443, TCP_FLAG_SYN);
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, (frame.len() - 14) as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut bindings[0],
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(dbg.missing_neigh, 1, "cold neighbor -> MissingNeighbor arm");
    assert_eq!(
        bindings[0].pending_neigh.len(),
        1,
        "a non-decapped cold-neighbor packet must still buffer"
    );
    assert_eq!(
        bindings[0]
            .live
            .pending_neigh_decap_drops
            .load(Ordering::Relaxed),
        0,
        "the decap gate must not touch UMEM-paired packets"
    );

    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    forwarding
        .neighbors
        .insert((24, IpAddr::V4(dst)), NeighborEntry { mac });
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut shared_recycles = Vec::new();
    let area = bindings[0].umem.area() as *const MmapArea;
    let (left, rest) = bindings.split_at_mut(0);
    let (binding, right) = rest.split_first_mut().expect("ingress binding");
    retry_pending_neigh(
        binding,
        left,
        0,
        right,
        &lookup,
        &mirror_targets,
        &forwarding,
        &dynamic_neighbors,
        None,
        123_000_000_100,
        // SAFETY: same single-threaded umem-area contract as above.
        unsafe { &*area },
        &mut shared_recycles,
    );
    assert!(
        bindings[0].pending_neigh.is_empty(),
        "entry consumed by retry"
    );
    let req = bindings[0]
        .tx_pipeline
        .pending_tx_prepared
        .front()
        .expect("resolved retry must produce a prepared TX");
    let rewritten = bindings[0]
        .umem
        .area()
        .slice(req.offset as usize, req.len as usize)
        .expect("rewritten frame")
        .to_vec();
    assert_eq!(
        &rewritten[0..6],
        &mac,
        "dst MAC must be the resolved neighbor"
    );
    assert_eq!(
        &rewritten[6..12],
        &[0x02, 0xbf, 0x72, 0x01, 0x00, 0x01],
        "src MAC must be the reth1.0 egress interface MAC"
    );
    assert_eq!(
        rewritten.len(),
        frame.len(),
        "no length change on a plain forward"
    );
    assert_eq!(rewritten[22], 63, "TTL decremented exactly once (64 -> 63)");
    assert_eq!(
        &rewritten[26..34],
        &frame[26..34],
        "IP src+dst must be byte-identical to the original packet"
    );
    assert_eq!(
        &rewritten[34..],
        &frame[34..],
        "L4 segment must be byte-identical to the original packet"
    );
}

/// #1873 replay-filter companion pin (AGY code r4 HIGH): filtering the
/// preserved synced-session replay list by purged tunnel ids must
/// mirror delete_synced_session's companion semantics — the derived
/// reverse companion (tunnel_endpoint_id == 0) of a dropped forward
/// entry is dropped too, never resurrected as a half-dead pair; a
/// reverse-marked entry drops standalone; unrelated entries survive.
#[test]
fn replay_filter_drops_purged_forward_and_derived_reverse_companion() {
    use crate::afxdp::coordinator::filter_replayed_synced_sessions;

    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        ..NatDecision::default()
    };
    let forward_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port: 5201,
    };
    let reverse_key = crate::session::reverse_session_key(&forward_key, nat);
    let tunnel_resolution = ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 41,
        tx_ifindex: 3,
        tunnel_endpoint_id: 824,
        next_hop: None,
        neighbor_mac: Some([2, 0, 0, 0, 0, 9]),
        src_mac: Some([2, 0, 0, 0, 0, 1]),
        tx_vlan_id: 0,
    };
    let plain_resolution = ForwardingResolution {
        tunnel_endpoint_id: 0,
        ..tunnel_resolution
    };
    let make =
        |key: &SessionKey, resolution: ForwardingResolution, is_reverse: bool| SyncedSessionEntry {
            key: key.clone(),
            decision: SessionDecision { resolution, nat },
            metadata: SessionMetadata {
                ingress_zone: 1,
                egress_zone: 2,
                owner_rg_id: 1,
                fabric_ingress: false,
                is_reverse,
                nat64_reverse: None,
            },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            // #2170 test fixture: no peer install generation.
            generation: 0,
        };
    let unrelated_key = SessionKey {
        src_port: 23456,
        ..forward_key.clone()
    };

    // Case 1: tunnel-marked forward + unmarked derived reverse
    // companion + unrelated unmarked entry.
    let mut entries = vec![
        make(&forward_key, tunnel_resolution, false),
        make(&reverse_key, plain_resolution, true),
        make(&unrelated_key, plain_resolution, false),
    ];
    filter_replayed_synced_sessions(&mut entries, &[824]);
    assert_eq!(entries.len(), 1, "forward + derived reverse both dropped");
    assert_eq!(entries[0].key, unrelated_key);

    // Case 2: reverse-marked tunnel entry drops standalone; its
    // unmarked forward keeps forwarding (matches live purge
    // semantics: delete_synced_session on a reverse key derives no
    // companion).
    let mut entries = vec![
        make(&forward_key, plain_resolution, false),
        make(&reverse_key, tunnel_resolution, true),
    ];
    filter_replayed_synced_sessions(&mut entries, &[824]);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key, forward_key);

    // Case 3: no purged ids — untouched.
    let mut entries = vec![make(&forward_key, tunnel_resolution, false)];
    filter_replayed_synced_sessions(&mut entries, &[7]);
    assert_eq!(entries.len(), 1);
}

// ---------------------------------------------------------------------------
// #2244: publish_dnat_table_entry must surface bpf_map_update_elem failures.
//
// Before #2244 the syscall return was discarded with `unsafe { ... };`, so a
// failed reverse-SNAT dnat_table publish (map at capacity / EINVAL / bad fd)
// was completely silent — no counter, no log. The embedded-ICMP NAT path then
// cannot reverse-NAT an inbound ICMP error (PMTUD / traceroute) back to the
// original source. These tests pin the new contract:
//   * the function returns `true` for the no-op / nothing-to-publish paths,
//   * it returns `false` when the syscall actually fails, and
//   * the worker call-site increment logic bumps `dnat_publish_errors` on
//     `false` and leaves it at 0 otherwise.
//
// FAIL-ON-REVERT: if the syscall return is discarded again (function reverts
// to `-> ()` / ignores `rc`), `publish_dnat_table_entry` can no longer report
// the failure, the `false` assertion and the counter-increment assertion both
// regress, and these tests fail.
// ---------------------------------------------------------------------------

fn dnat_snat_decision() -> NatDecision {
    NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(54321),
        ..NatDecision::default()
    }
}

fn dnat_v4_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port: 443,
    }
}

#[test]
fn publish_dnat_table_entry_noops_return_true() {
    // No SNAT rewrite → nothing to publish, treated as success.
    let no_snat = NatDecision::default();
    assert!(publish_dnat_table_entry(
        &DnatTableFds { v4: Some(-1), v6: None },
        &dnat_v4_key(),
        no_snat,
    ));

    // SNAT present but no v4 table fd → nothing to publish, success.
    assert!(publish_dnat_table_entry(
        &DnatTableFds::default(),
        &dnat_v4_key(),
        dnat_snat_decision(),
    ));

    // SNAT present but the key is not AF_INET → unsupported family, success.
    let mut v6_key = dnat_v4_key();
    v6_key.addr_family = libc::AF_INET6 as u8;
    assert!(publish_dnat_table_entry(
        &DnatTableFds { v4: Some(-1), v6: None },
        &v6_key,
        dnat_snat_decision(),
    ));
}

#[test]
fn publish_dnat_table_entry_reports_syscall_failure() {
    // An invalid map fd forces bpf_map_update_elem to fail (EBADF). The
    // function must now report that failure instead of swallowing it.
    let fds = DnatTableFds { v4: Some(-1), v6: None };
    let ok = publish_dnat_table_entry(&fds, &dnat_v4_key(), dnat_snat_decision());
    assert!(
        !ok,
        "publish_dnat_table_entry must return false when bpf_map_update_elem fails"
    );
}

#[test]
fn publish_dnat_table_entry_failure_increments_counter() {
    // Mirror the worker poll call-site increment logic against a real
    // BindingLiveState. Pre-#2244 the counter did not exist and the syscall
    // result was discarded, so this increment was impossible.
    let live = BindingLiveState::new();
    assert_eq!(live.dnat_publish_errors.load(Ordering::Relaxed), 0);

    // Success / no-op path: no increment.
    if !publish_dnat_table_entry(&DnatTableFds::default(), &dnat_v4_key(), dnat_snat_decision()) {
        live.dnat_publish_errors.fetch_add(1, Ordering::Relaxed);
    }
    assert_eq!(
        live.dnat_publish_errors.load(Ordering::Relaxed),
        0,
        "no-op publish must not bump the error counter"
    );

    // Failing publish (bad fd): increment fires.
    let fds = DnatTableFds { v4: Some(-1), v6: None };
    if !publish_dnat_table_entry(&fds, &dnat_v4_key(), dnat_snat_decision()) {
        live.dnat_publish_errors.fetch_add(1, Ordering::Relaxed);
    }
    assert_eq!(
        live.dnat_publish_errors.load(Ordering::Relaxed),
        1,
        "failed dnat_table publish must increment dnat_publish_errors"
    );

    // A second failure accumulates.
    if !publish_dnat_table_entry(&fds, &dnat_v4_key(), dnat_snat_decision()) {
        live.dnat_publish_errors.fetch_add(1, Ordering::Relaxed);
    }
    assert_eq!(live.dnat_publish_errors.load(Ordering::Relaxed), 2);
}

// =====================================================================
// #2345: inbound destination-translation policy is evaluated on the
// POST-translation destination tuple (Junos parity).
//
// For every inbound destination translation that happens BEFORE the
// route/zone lookup — DNAT, static-DNAT, inbound NPTv6, and NAT64 — the
// security policy must match on the TRANSLATED (real/internal)
// destination address + port, in the zone derived from that translated
// destination. These tests are fail-on-revert: each builds a config
// where the ORIGINAL (public/virtual) destination and the TRANSLATED
// (internal) destination would draw DIFFERENT policy verdicts, so the
// observed forward/deny outcome can only be produced if the match ran on
// the translated tuple. If the policy lookup reverts to the pre-
// translation tuple/zone these tests flip and fail.
// =====================================================================

/// v6 ingress meta for the txn harness (TCP, ingress on `ifindex`).
fn txn_meta_v6(ingress_ifindex: u32, frame_len: usize) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex,
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

/// Build a wan->lan inbound DNAT snapshot: public VIP 172.16.80.8:443 is
/// port-DNAT'd to the internal LAN host 10.0.61.102:8443. The internal
/// host is directly connected on reth1.0 (10.0.61.0/24) and given a
/// neighbor so the translated destination resolves to a ForwardCandidate.
/// The caller supplies the single from=wan/to=lan policy.
fn inbound_dnat_snapshot(policy: PolicyRuleSnapshot) -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.destination_nat_rules = vec![DestinationNATRuleSnapshot {
        counter_id: 0,
        name: "web-dnat".to_string(),
        from_zone: "wan".to_string(),
        destination_address: "172.16.80.8".to_string(),
        destination_port: 443,
        protocol: "tcp".to_string(),
        pool_address: "10.0.61.102".to_string(),
        pool_port: 8443,
    }];
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "reth1.0".to_string(),
        ifindex: 24,
        family: "inet".to_string(),
        ip: "10.0.61.102".to_string(),
        mac: "02:aa:bb:cc:dd:01".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    });
    // Replace the default lan->wan permit with the caller's wan->lan rule
    // so the only policy that can match the inbound flow is the one under
    // test (default-policy stays deny).
    snapshot.policies = vec![policy];
    snapshot
}

fn wan_to_lan_permit(dst: &str, name: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: name.to_string(),
        from_zone: "wan".to_string(),
        to_zone: "lan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec![dst.to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    }
}

/// DNAT: a policy that permits ONLY the translated internal destination
/// (10.0.61.102) MUST permit + forward the inbound packet whose original
/// destination is the public VIP (172.16.80.8). Proves the policy match
/// ran on the post-DNAT address.
#[test]
fn policy_inbound_dnat_matches_translated_destination_permit() {
    let snapshot = inbound_dnat_snapshot(wan_to_lan_permit("10.0.61.102/32", "permit-internal"));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    // Inbound: external client -> public VIP:443 on the wan interface.
    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(172, 16, 80, 8),
        54321,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(12, TCP_FLAG_SYN, (frame.len() - 14) as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.policy_deny, 0,
        "policy on the translated internal dst must NOT deny the DNAT'd flow"
    );
    assert_eq!(
        dbg.tx, 1,
        "DNAT'd flow permitted by a policy on the translated dst must forward"
    );
    // forward + reverse install: session reversal is preserved.
    assert_eq!(
        sessions.len(),
        2,
        "forward + reverse session install (return-path reversal preserved)"
    );
}

/// DNAT fail-on-revert: a policy that permits ONLY the original public VIP
/// (172.16.80.8) — and does NOT cover the internal host — MUST deny the
/// inbound packet, because the match runs on the post-DNAT internal dst.
/// If the lookup reverted to the pre-DNAT tuple this would wrongly permit.
#[test]
fn policy_inbound_dnat_denies_when_only_original_dst_permitted() {
    let snapshot = inbound_dnat_snapshot(wan_to_lan_permit("172.16.80.8/32", "permit-public-vip"));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(172, 16, 80, 8),
        54322,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(12, TCP_FLAG_SYN, (frame.len() - 14) as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.tx, 0,
        "a policy covering only the public VIP must NOT forward the DNAT'd flow"
    );
    assert!(
        dbg.policy_deny >= 1,
        "match on the post-DNAT internal dst (uncovered) must deny"
    );
    assert_eq!(sessions.len(), 0, "denied flow installs no session");
}

/// DNAT port: a policy that permits the translated dst at the translated
/// PORT (8443) but with the wrong port (443) for the same address would
/// not match. Permitting tcp/8443 to 10.0.61.102 forwards; this pins the
/// translated dst PORT (not just the address) into the policy match.
#[test]
fn policy_inbound_dnat_matches_translated_destination_port() {
    let mut permit = wan_to_lan_permit("10.0.61.102/32", "permit-internal-8443");
    // Restrict the application to tcp/8443 (the translated port). The
    // original packet is tcp/443; only a match on the post-DNAT port 8443
    // can permit it.
    permit.applications = vec!["app-8443".to_string()];
    permit.application_terms = vec![crate::protocol::PolicyApplicationSnapshot {
        name: "app-8443".to_string(),
        protocol: "tcp".to_string(),
        source_port: String::new(),
        destination_port: "8443".to_string(),
    }];
    let snapshot = inbound_dnat_snapshot(permit);
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(172, 16, 80, 8),
        54323,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(12, TCP_FLAG_SYN, (frame.len() - 14) as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.policy_deny, 0,
        "policy on tcp/8443 (translated port) must permit the DNAT'd flow"
    );
    assert_eq!(dbg.tx, 1, "match on the translated dst port must forward");
}

/// Build a wan-ingress inbound NPTv6 snapshot. The external prefix
/// 2602:fd41:70::/48 is translated to the internal prefix
/// fd35:1940:27::/48; a route + neighbor for the internal prefix make the
/// translated destination a ForwardCandidate out reth1.0 (lan). The
/// caller supplies the single wan->lan policy under test.
fn inbound_nptv6_snapshot(policy: PolicyRuleSnapshot) -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.nptv6_rules = vec![crate::protocol::Nptv6RuleSnapshot {
        name: "nptv6".to_string(),
        from_zone: "wan".to_string(),
        internal_prefix: "fd35:1940:27::/48".to_string(),
        external_prefix: "2602:fd41:70::/48".to_string(),
    }];
    // Route the internal /48 toward the LAN host (reth1.0) so the
    // translated destination resolves on the inside.
    snapshot.routes.push(RouteSnapshot {
        table: "inet6.0".to_string(),
        family: "inet6".to_string(),
        destination: "fd35:1940:27::/48".to_string(),
        next_hops: vec!["fd35:1940:27:100::102@reth1.0".to_string()],
        discard: false,
        next_table: String::new(),
    });
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "reth1.0".to_string(),
        ifindex: 24,
        family: "inet6".to_string(),
        ip: "fd35:1940:27:100::102".to_string(),
        mac: "02:aa:bb:cc:dd:02".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    });
    snapshot.policies = vec![policy];
    snapshot
}

/// NPTv6: a policy permitting ONLY the INTERNAL prefix must permit + forward
/// an inbound packet addressed to the EXTERNAL prefix. Proves the match
/// runs on the post-NPTv6 (internal) destination.
#[test]
fn policy_inbound_nptv6_matches_translated_destination_permit() {
    let snapshot = inbound_nptv6_snapshot(wan_to_lan_permit(
        "fd35:1940:27::/48",
        "permit-internal-prefix",
    ));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:80::200".parse().expect("ext client");
    // External-prefix destination; NPTv6 maps it to fd35:1940:27:100::102.
    let dst: Ipv6Addr = "2602:fd41:70:100::102".parse().expect("ext dst");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 54321, 443);
    let meta = txn_meta_v6(12, frame.len());
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.policy_deny, 0,
        "policy on the internal prefix must NOT deny the NPTv6-translated flow"
    );
    assert_eq!(
        dbg.tx, 1,
        "NPTv6 flow permitted by a policy on the internal prefix must forward"
    );
    assert_eq!(sessions.len(), 2, "forward + reverse install");
}

/// NPTv6 fail-on-revert: a policy permitting ONLY the EXTERNAL prefix (and
/// NOT the internal one) must DENY the inbound packet, because the match
/// runs on the post-NPTv6 internal destination.
#[test]
fn policy_inbound_nptv6_denies_when_only_external_prefix_permitted() {
    let snapshot = inbound_nptv6_snapshot(wan_to_lan_permit(
        "2602:fd41:70::/48",
        "permit-external-prefix",
    ));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:80::200".parse().expect("ext client");
    let dst: Ipv6Addr = "2602:fd41:70:100::102".parse().expect("ext dst");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 54322, 443);
    let meta = txn_meta_v6(12, frame.len());
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.tx, 0,
        "a policy covering only the external prefix must NOT forward the NPTv6 flow"
    );
    assert!(
        dbg.policy_deny >= 1,
        "match on the post-NPTv6 internal dst (uncovered) must deny"
    );
    assert_eq!(sessions.len(), 0);
}

/// Build a NAT64 snapshot: the synthetic IPv6 destination 64:ff9b::808:808
/// extracts the IPv4 server 8.8.8.8 (routed out wan via the default route).
/// Ingress is on reth1.0 (lan, ifindex 24); egress zone is wan. The caller
/// supplies the lan->wan policy under test.
fn nat64_snapshot(policy: PolicyRuleSnapshot) -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.nat64_rules = vec![crate::protocol::NAT64RuleSnapshot {
        name: "nat64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["172.16.80.50".to_string()],
        no_v6_frag_header: false,
    }];
    snapshot.policies = vec![policy];
    snapshot
}

fn lan_to_wan_permit(dst: &str, name: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec![dst.to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    }
}

/// NAT64: a policy permitting ONLY the EXTRACTED IPv4 server (8.8.8.8/32)
/// NAT64 (DELIBERATELY EXCLUDED from the #2345 post-translation tuple, see
/// the long comment at the policy-tuple binding in poll_descriptor): NAT64
/// is cross-family (V6 src, V4 dst) and xpf's policy matcher requires
/// same-family src+dst, so feeding the extracted IPv4 destination would
/// match no rule and break ALL NAT64 connectivity. NAT64 therefore keeps
/// its historical behavior: policy matches on the SYNTHETIC IPv6 dst (the
/// only same-family tuple available). This test pins that a policy on the
/// synthetic IPv6 prefix permits + forwards the NAT64 flow.
#[test]
fn policy_inbound_nat64_matches_synthetic_v6_destination_permit() {
    let snapshot = nat64_snapshot(lan_to_wan_permit("64:ff9b::/96", "permit-synthetic-v6"));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("v6 client");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 12345, 443);
    let meta = txn_meta_v6(24, frame.len());
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.policy_deny, 0,
        "policy on the synthetic IPv6 prefix must NOT deny the NAT64 flow"
    );
    assert_eq!(
        dbg.tx, 1,
        "NAT64 flow permitted by a policy on the synthetic IPv6 dst must forward"
    );
    assert_eq!(sessions.len(), 2, "NAT64 forward + reverse install");
}

/// NAT64 fail-on-revert: an explicit DENY on the synthetic IPv6 NAT64
/// destination prefix must DROP the flow. This proves the NAT64 policy
/// match runs on the synthetic IPv6 destination (the documented #2345
/// NAT64 behavior): if NAT64 were folded onto the extracted IPv4 tuple,
/// the V6 deny rule would no longer match (cross-family) and the flow would
/// fall to the default policy, changing the verdict.
#[test]
fn policy_inbound_nat64_denies_on_synthetic_v6_deny_rule() {
    let mut deny = lan_to_wan_permit("64:ff9b::/96", "deny-synthetic-v6");
    deny.action = "deny".to_string();
    let mut snapshot = nat64_snapshot(deny);
    // A trailing permit-any so the ONLY thing that can drop this flow is the
    // synthetic-V6 deny rule matching first — not the default policy.
    snapshot
        .policies
        .push(lan_to_wan_permit("any", "permit-rest"));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("v6 client");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 12346, 443);
    let meta = txn_meta_v6(24, frame.len());
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.tx, 0,
        "an explicit deny on the synthetic IPv6 dst must drop the NAT64 flow"
    );
    assert!(
        dbg.policy_deny >= 1,
        "the synthetic-V6 deny rule must match the NAT64 flow"
    );
    assert_eq!(sessions.len(), 0);
}

/// Session reversal is preserved by the #2345 policy-tuple change. The
/// policy-match tuple change touches ONLY the policy lookup, NOT the
/// installed session keys: a DNAT forward still keys the reverse session
/// off the PUBLIC-facing wire tuple (the public VIP as the reply source),
/// so return traffic from the internal host (rewritten back to the VIP on
/// egress) reverses correctly. This pins that the reverse key is built
/// from the public dst, independent of the policy-match address.
#[test]
fn inbound_dnat_reverse_session_key_uses_public_facing_tuple() {
    // Forward: external client 198.51.100.10:54321 -> public VIP
    // 172.16.80.8:443, DNAT'd to internal 10.0.61.102:8443.
    let forward_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        src_port: 54321,
        dst_port: 443,
    };
    let dnat = NatDecision {
        rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        rewrite_dst_port: Some(8443),
        ..NatDecision::default()
    };
    let reverse = reverse_session_key(&forward_key, dnat);
    // The reply from the internal host arrives as 10.0.61.102:8443 ->
    // 198.51.100.10:54321; the reverse session key must match exactly that
    // wire 5-tuple so the return packet reverses (dst rewritten back to the
    // public VIP on egress). This is unchanged by the policy-tuple fix.
    assert_eq!(
        reverse.src_ip,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        "reverse src = internal host (post-DNAT dst), reply wire source"
    );
    assert_eq!(reverse.src_port, 8443, "reverse src port = translated dst port");
    assert_eq!(
        reverse.dst_ip,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
        "reverse dst = original external client"
    );
    assert_eq!(reverse.dst_port, 54321, "reverse dst port = original src port");
}
