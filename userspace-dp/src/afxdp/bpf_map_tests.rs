// Tests for afxdp/bpf_map/ — relocated from inline
// `#[cfg(test)] mod tests` to keep bpf_map under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "../bpf_map_tests.rs"]` from bpf_map/mod.rs (#1356 split the
// flat bpf_map.rs into a directory; this file stays at the parent
// afxdp/ scope and is pulled back into the bpf_map namespace by the
// path attribute).

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
fn degraded_path_reason_names_cover_retained_shim_actions() {
    assert_eq!(DEGRADED_PATH_REASON_NAMES.len(), 16);
    assert_eq!(DEGRADED_PATH_REASON_NAMES[4], "heartbeat_missing");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[5], "heartbeat_stale");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[11], "interface_nat_no_session");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[13], "strict_drop");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[14], "pass_to_kernel");
    assert_eq!(DEGRADED_PATH_REASON_NAMES[15], "transit_drop");
}

// --- #2332: monotonic HA-liveness freshness (Rust sibling of #1792) ---
//
// `heartbeat_fresh_mono` MUST decide worker liveness purely from two
// CLOCK_MONOTONIC nanosecond readings, never the wall clock. These tests
// pin that contract and FAIL if the function is reverted to a wall-clock
// (`Utc::now()` minus a `DateTime<Utc>`) comparison: the simulated
// forward clock step only changes the wall clock, so a wall-clock revert
// would flip `fresh` to false and fail `heartbeat_fresh_survives_*`.

const HB_STALE_NS: u64 = 5_000_000_000; // mirrors HEARTBEAT_STALE_AFTER (5s)

#[test]
fn heartbeat_fresh_mono_recent_is_fresh() {
    // Worker stamped 1s of monotonic time ago, well under the 5s limit.
    let last = 100_000_000_000_u64;
    let now = last + 1_000_000_000; // +1s monotonic
    assert!(heartbeat_fresh_mono(last, now));
}

#[test]
fn heartbeat_fresh_mono_overdue_is_stale() {
    // Genuinely overdue: 6s of monotonic elapsed > 5s threshold → dead.
    let last = 100_000_000_000_u64;
    let now = last + 6_000_000_000; // +6s monotonic
    assert!(!heartbeat_fresh_mono(last, now));
}

#[test]
fn heartbeat_fresh_mono_exactly_at_limit_is_fresh() {
    // age == HEARTBEAT_STALE_AFTER is inclusive-fresh (`<=`).
    let last = 100_000_000_000_u64;
    let now = last + HB_STALE_NS;
    assert!(heartbeat_fresh_mono(last, now));
    // One nanosecond past the limit is stale.
    assert!(!heartbeat_fresh_mono(last, now + 1));
}

#[test]
fn heartbeat_fresh_mono_zero_sentinel_is_never_fresh() {
    // last_heartbeat_ns == 0 means "never stamped" → not fresh.
    assert!(!heartbeat_fresh_mono(0, 1_000_000_000));
    assert!(!heartbeat_fresh_mono(0, 0));
}

#[test]
fn heartbeat_fresh_survives_forward_wall_clock_step() {
    // FAIL-ON-REVERT: the worker's last heartbeat is monotonically recent
    // (1ms ago), but the wall clock has jumped FORWARD by 1 hour (NTP
    // makestep / VM resume) between the heartbeat stamp and this check.
    //
    // The monotonic decision below depends ONLY on the monotonic readings,
    // so the wall-clock step is invisible and the binding stays FRESH. A
    // wall-clock revert (Utc::now() - last_DateTime) would compute a ~1h
    // age, exceed the 5s limit, and return false — failing this test.
    let last_mono = 500_000_000_000_u64;
    let now_mono = last_mono + 1_000_000; // +1ms monotonic — clearly fresh

    // Build the wall-clock view the OLD code would have used: at heartbeat
    // time the wall clock was `t0`; by check time it stepped forward 1h.
    let t0 = chrono::Utc::now();
    let last_wall = t0; // worker-stamped wall instant (back-projected)
    let now_wall_after_step = t0 + chrono::TimeDelta::hours(1);
    let wall_age = now_wall_after_step.signed_duration_since(last_wall);
    // Sanity: the wall-clock age the old code saw really does exceed 5s.
    assert!(wall_age.to_std().unwrap() > std::time::Duration::from_secs(5));

    // The monotonic decision is unaffected by the wall-clock step.
    assert!(
        heartbeat_fresh_mono(last_mono, now_mono),
        "monotonic liveness must ignore a forward wall-clock step (#2332)"
    );
}

#[test]
fn heartbeat_fresh_backward_monotonic_anomaly_clamps_fresh() {
    // A backward CLOCK_MONOTONIC reading cannot happen on a well-behaved
    // kernel, but saturating_sub clamps it to a zero age (fail-safe:
    // treated as fresh, never spuriously dead).
    let last = 100_000_000_000_u64;
    let now = last - 1_000_000; // now < last
    assert!(heartbeat_fresh_mono(last, now));
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
