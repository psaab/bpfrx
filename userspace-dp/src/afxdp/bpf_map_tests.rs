// Tests for afxdp/bpf_map.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep bpf_map.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "bpf_map_tests.rs"]` from bpf_map.rs.

use super::*;
use crate::test_zone_ids::*;

fn local_delivery_decision(tunnel_endpoint_id: u16) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    }
}

fn synced_forward_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_TRUST_ZONE_ID,
        egress_zone: TEST_TRUST_ZONE_ID,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
    }
}

#[test]
fn kernel_local_session_map_entry_requires_zero_tunnel_endpoint() {
    let metadata = synced_forward_metadata();
    assert!(uses_kernel_local_session_map_entry(
        local_delivery_decision(0),
        &metadata,
        SessionOrigin::SyncImport,
    ));
    assert!(!uses_kernel_local_session_map_entry(
        local_delivery_decision(7),
        &metadata,
        SessionOrigin::SyncImport,
    ));
}

#[test]
fn kernel_local_session_map_entry_rejects_non_kernel_local_cases() {
    let metadata = synced_forward_metadata();
    // Not local delivery → rejected
    assert!(!uses_kernel_local_session_map_entry(
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                ..local_delivery_decision(0).resolution
            },
            nat: NatDecision::default(),
        },
        &metadata,
        SessionOrigin::SyncImport,
    ));

    // Non-peer-synced origin → rejected
    assert!(!uses_kernel_local_session_map_entry(
        local_delivery_decision(0),
        &metadata,
        SessionOrigin::ForwardFlow,
    ));

    // Reverse session → rejected
    let mut reverse_metadata = synced_forward_metadata();
    reverse_metadata.is_reverse = true;
    assert!(!uses_kernel_local_session_map_entry(
        local_delivery_decision(0),
        &reverse_metadata,
        SessionOrigin::SyncImport,
    ));
}

#[test]
fn bpf_conntrack_struct_sizes_match_c() {
    // Must match C struct sizes from xpf_conntrack.h exactly.
    assert_eq!(core::mem::size_of::<BpfSessionKeyV4>(), 16);
    assert_eq!(core::mem::size_of::<BpfSessionValueV4>(), 128);
    assert_eq!(core::mem::size_of::<BpfSessionKeyV6>(), 40);
    assert_eq!(core::mem::size_of::<BpfSessionValueV6>(), 176);
}

#[test]
fn session_map_redirect_keys_for_forward_session_include_nat_aliases() {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 41086,
        dst_port: 5201,
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 14,
            tx_ifindex: 14,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
    };

    let keys = session_map_redirect_keys_for_session(
        &key,
        decision,
        &metadata,
        SessionOrigin::SharedPromote,
    );

    assert!(keys.contains(&key));
    assert!(keys.contains(&forward_wire_key(&key, decision.nat)));
    assert!(keys.contains(&reverse_session_key(&key, decision.nat)));
    assert!(keys.contains(&reverse_canonical_key(&key, decision.nat)));
}

#[test]
fn session_map_redirect_keys_for_kernel_local_synced_session_delete_superset() {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 1,
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        src_port: 0,
        dst_port: 0,
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 14,
            egress_ifindex: 14,
            tx_ifindex: 14,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let metadata = synced_forward_metadata();

    let keys =
        session_map_redirect_keys_for_session(&key, decision, &metadata, SessionOrigin::SyncImport);

    assert_eq!(keys.len(), 4);
    assert!(keys.contains(&key));
    assert!(keys.contains(&forward_wire_key(&key, decision.nat)));
    assert!(keys.contains(&reverse_session_key(&key, decision.nat)));
    assert!(keys.contains(&reverse_canonical_key(&key, decision.nat)));
}

#[test]
fn bpf_conntrack_key_port_byte_order() {
    // BPF session_key uses __be16 ports (network byte order).
    // SessionKey stores ports in host order (u16::from_be_bytes in parsing).
    // publish_bpf_conntrack_entry must apply .to_be() to produce the correct
    // big-endian byte pattern in the packed struct.
    let port: u16 = 80;
    let bpf_key = BpfSessionKeyV4 {
        src_ip: [10, 0, 1, 102],
        dst_ip: [10, 0, 2, 1],
        src_port: port.to_be(),
        dst_port: 443u16.to_be(),
        protocol: 6,
        pad: [0; 3],
    };
    // The packed struct bytes at the port offsets must be big-endian:
    // port 80 = 0x0050 -> bytes [0x00, 0x50]
    // port 443 = 0x01BB -> bytes [0x01, 0xBB]
    let bytes: [u8; 16] = unsafe { core::mem::transmute(bpf_key) };
    assert_eq!(bytes[8], 0x00, "src_port high byte");
    assert_eq!(bytes[9], 0x50, "src_port low byte");
    assert_eq!(bytes[10], 0x01, "dst_port high byte");
    assert_eq!(bytes[11], 0xBB, "dst_port low byte");
}
