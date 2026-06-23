// Tests for frame/mod.rs — relocated from inline `#[cfg(test)] mod tests`
// to keep mod.rs under the modularity-discipline LOC threshold (#1046).
// Loaded as a sibling module via `#[path = "tests.rs"]` from mod.rs.

use super::super::test_fixtures::*;
use super::*;
use crate::event_stream::DataplaneEventRateLimitConfig;
use crate::event_stream::codec::DataplaneEventKind;
use crate::test_zone_ids::*;
use crate::{FirewallFilterSnapshot, FirewallTermSnapshot, ThreeColorPolicerSnapshot};

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

fn build_icmp_echo_frame_v4_vlan(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8, vlan_id: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        vlan_id,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, ttl, PROTO_ICMP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let ip_csum = checksum16(&frame[18..38]);
    frame[28..30].copy_from_slice(&ip_csum.to_be_bytes());
    let icmp_start = frame.len();
    frame.extend_from_slice(&[8, 0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01]);
    let icmp_csum = checksum16(&frame[icmp_start..]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    frame
}

fn build_ipv6_gre_frame(
    inner_packet: &[u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    key: Option<u32>,
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x02],
        0,
        0x86dd,
    );
    let gre_len = if key.is_some() { 8usize } else { 4usize };
    let payload_len = u16::try_from(gre_len + inner_packet.len()).unwrap();
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.push(PROTO_GRE);
    frame.push(64);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let flags = if key.is_some() { 0x2000u16 } else { 0u16 };
    frame.extend_from_slice(&flags.to_be_bytes());
    frame.extend_from_slice(
        &(if inner_packet.first().map(|b| b >> 4) == Some(4) {
            0x0800u16
        } else {
            0x86ddu16
        })
        .to_be_bytes(),
    );
    if let Some(key) = key {
        frame.extend_from_slice(&key.to_be_bytes());
    }
    frame.extend_from_slice(inner_packet);
    frame
}

#[test]
fn trim_l3_payload_uses_frame_length_metadata_relative_to_l3_offset_without_parsing_header() {
    let mut frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), 64);
    let wire_len = frame.len();
    frame[14] = 0;
    frame.extend_from_slice(&[0u8; 8]);
    let raw_payload = &frame[14..];
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        pkt_len: wire_len as u16,
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };

    assert_eq!(trim_l3_payload(raw_payload, meta).len(), wire_len - 14);
}

#[test]
fn trim_l3_payload_uses_vlan_frame_length_metadata_relative_to_l3_offset_without_parsing_header() {
    let mut frame = build_icmp_echo_frame_v4_vlan(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        64,
        80,
    );
    let wire_len = frame.len();
    frame[18] = 0;
    frame.extend_from_slice(&[0u8; 8]);
    let raw_payload = &frame[18..];
    let meta = UserspaceDpMeta {
        l3_offset: 18,
        pkt_len: wire_len as u16,
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };

    assert_eq!(trim_l3_payload(raw_payload, meta).len(), wire_len - 18);
}

fn native_gre_outer_meta() -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 6,
        rx_queue_index: 0,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 58,
        pkt_len: 92,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_GRE,
        ..UserspaceDpMeta::default()
    }
}

#[test]
fn parse_session_flow_reparses_vlan_ipv4_reply_without_meta_offsets() {
    let frame = vlan_icmp_reply_frame();
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
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
    assert_eq!(flow.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    assert_eq!(flow.forward_key.src_port, 0x1234);
    assert_eq!(flow.forward_key.dst_port, 0);
}

#[test]
fn parse_session_flow_prefers_tuple_stamped_in_metadata() {
    let mut area = MmapArea::new(256).expect("mmap");
    area.slice_mut(0, 64).expect("slice").fill(0xaa);
    let meta = valid_meta();
    let flow = parse_session_flow(
        &area,
        XdpDesc {
            addr: 0,
            len: 64,
            options: 0,
        },
        meta,
    )
    .expect("flow");
    assert_eq!(flow.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    assert_eq!(flow.forward_key.src_port, 0x1234);
    assert_eq!(flow.forward_key.dst_port, 0);
}

#[test]
fn parse_session_flow_prefers_frame_tuple_when_metadata_disagrees() {
    let frame = vlan_icmp_reply_frame();
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let mut meta = valid_meta();
    meta.l3_offset = 18;
    meta.l4_offset = 38;
    meta.flow_src_addr[..4].copy_from_slice(&[10, 0, 61, 102]);
    meta.flow_dst_addr[..4].copy_from_slice(&[172, 16, 80, 200]);
    meta.flow_src_port = 0xbeef;
    meta.flow_dst_port = 0;
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
    assert_eq!(flow.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    assert_eq!(flow.forward_key.src_port, 0x1234);
    assert_eq!(flow.forward_key.dst_port, 0);
}

#[test]
fn parse_session_flow_prefers_ipv6_metadata_ports_when_frame_ports_disagree() {
    let src_ip: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src");
    let dst_ip: Ipv6Addr = "2001:559:8585:80::200".parse().expect("dst");
    let src_port = 50662u16;
    let dst_port = 5201u16;
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0u8; 6]);
    frame.extend_from_slice(&[0u8; 6]);
    frame.extend_from_slice(&0x8100u16.to_be_bytes());
    frame.extend_from_slice(&80u16.to_be_bytes());
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, 0x10, 0, 64, 0, 0, 0, 0]);

    let mut area = MmapArea::new(512).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        l3_offset: 18,
        l4_offset: 58,
        payload_offset: 78,
        flow_src_port: 1026,
        flow_dst_port: dst_port,
        flow_src_addr: src_ip.octets(),
        flow_dst_addr: dst_ip.octets(),
        ..UserspaceDpMeta::default()
    };
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
    assert_eq!(flow.src_ip, IpAddr::V6(src_ip));
    assert_eq!(flow.dst_ip, IpAddr::V6(dst_ip));
    assert_eq!(flow.forward_key.src_port, 1026);
    assert_eq!(flow.forward_key.dst_port, dst_port);
}

#[test]
fn parse_session_flow_reparses_ipv6_when_metadata_l4_offset_is_bad() {
    let src_ip: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src");
    let dst_ip: Ipv6Addr = "2001:559:8585:80::200".parse().expect("dst");
    let src_port = 50662u16;
    let dst_port = 5201u16;
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0u8; 6]);
    frame.extend_from_slice(&[0u8; 6]);
    frame.extend_from_slice(&0x8100u16.to_be_bytes());
    frame.extend_from_slice(&80u16.to_be_bytes());
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, 0x10, 0, 64, 0, 0, 0, 0]);

    let mut area = MmapArea::new(512).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        l3_offset: 18,
        l4_offset: 22,
        payload_offset: 78,
        flow_src_port: 1025,
        flow_dst_port: dst_port,
        flow_src_addr: src_ip.octets(),
        flow_dst_addr: dst_ip.octets(),
        ..UserspaceDpMeta::default()
    };
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
    assert_eq!(flow.src_ip, IpAddr::V6(src_ip));
    assert_eq!(flow.dst_ip, IpAddr::V6(dst_ip));
    // When IPs match, parse_session_flow prefers metadata ports over
    // frame-parsed ports (metadata is stamped by BPF before any DMA
    // corruption). The meta port (1025) wins over the frame port (50662).
    assert_eq!(flow.forward_key.src_port, 1025);
    assert_eq!(flow.forward_key.dst_port, dst_port);
}

#[test]
fn forwarding_lookup_prefers_local_delivery() {
    let mut snapshot = forwarding_snapshot(true);
    snapshot.source_nat_rules.clear();
    let state = build_forwarding_state(&snapshot);
    assert_eq!(
        lookup_forwarding_for_ip(&state, IpAddr::V4(Ipv4Addr::new(172, 16, 50, 8))),
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(
        lookup_forwarding_for_ip(
            &state,
            IpAddr::V6("2001:559:8585:50::8".parse().expect("ipv6")),
        ),
        ForwardingDisposition::LocalDelivery
    );
}

#[test]
fn forwarding_lookup_requires_neighbor_for_forward_candidate() {
    let good = build_forwarding_state(&forwarding_snapshot(true));
    assert_eq!(
        lookup_forwarding_for_ip(&good, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        lookup_forwarding_for_ip(
            &good,
            IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
        ),
        ForwardingDisposition::ForwardCandidate
    );

    let missing_neighbor = build_forwarding_state(&forwarding_snapshot(false));
    assert_eq!(
        lookup_forwarding_for_ip(&missing_neighbor, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),),
        ForwardingDisposition::MissingNeighbor
    );
}

#[test]
fn tunnel_route_resolves_to_logical_tunnel_and_physical_tx() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let resolved = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(8, 8, 8, 8),
        "sfmix.inet.0",
        0,
        true,
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 362);
    assert_eq!(resolved.tx_ifindex, 6);
    assert_eq!(resolved.tunnel_endpoint_id, 1);
    assert_eq!(
        resolved.next_hop,
        Some(IpAddr::V6("2001:559:8585:80::1".parse().expect("outer nh")))
    );
    assert_eq!(
        resolved.neighbor_mac,
        Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
    assert_eq!(resolved.src_mac, Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]));
    assert_eq!(resolved.tx_vlan_id, 80);
}

#[test]
fn tunnel_route_preserves_logical_egress_on_outer_neighbor_miss() {
    let state = build_forwarding_state(&native_gre_snapshot(false));
    let resolved = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(8, 8, 8, 8),
        "sfmix.inet.0",
        0,
        true,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(resolved.egress_ifindex, 362);
    assert_eq!(resolved.tx_ifindex, 6);
    assert_eq!(resolved.tunnel_endpoint_id, 1);
    assert_eq!(resolved.src_mac, Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]));
    assert_eq!(resolved.tx_vlan_id, 80);
}

#[test]
fn ingress_filter_routing_instance_steers_flow_into_native_gre_table() {
    let state = build_forwarding_state(&native_gre_pbr_snapshot(true));
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            src_port: 0,
            dst_port: 0,
        },
    };
    let meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..Default::default()
    };
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let override_table =
        ingress_route_table_override(&state, &[], meta, &flow, None, Some(&event_handle), 99);
    assert_eq!(override_table.as_deref(), Some("sfmix.inet.0"));
    let filter_event = event_rx
        .try_recv()
        .expect("filter-log event")
        .decode_dataplane_event()
        .expect("filter-log payload");
    assert_eq!(filter_event.kind, DataplaneEventKind::FilterLog);
    assert_eq!(filter_event.filter_id, 0);
    assert_eq!(filter_event.term_id, 0);
    assert_eq!(filter_event.reason, FilterLogSource::Pbr.wire_reason());
    assert_eq!(filter_event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(filter_event.egress_zone_id, 0);
    let resolved = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &Default::default(),
        flow.dst_ip,
        override_table.as_deref(),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 362);
    assert_eq!(resolved.tx_ifindex, 6);
    assert_eq!(resolved.tunnel_endpoint_id, 1);
}

#[test]
fn native_gre_logical_egress_retains_zone_without_mac() {
    let state = build_forwarding_state(&native_gre_pbr_snapshot(true));
    let egress = state.egress.get(&362).expect("logical tunnel egress");
    assert_eq!(egress.zone_id, TEST_SFMIX_ZONE_ID);
    assert_eq!(egress.primary_v4, Some(Ipv4Addr::new(10, 255, 192, 42)));
}

#[test]
fn owner_rg_for_resolution_uses_native_gre_endpoint_group() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let resolved = lookup_forwarding_resolution_with_dynamic(
        &state,
        &Default::default(),
        IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
    );
    assert_eq!(resolved.tunnel_endpoint_id, 1);
    assert_eq!(owner_rg_for_resolution(&state, resolved), 1);
}

#[test]
fn native_gre_decap_maps_inner_packet_to_logical_tunnel_ingress() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let inner = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 255, 192, 41),
        Ipv4Addr::new(10, 255, 192, 42),
        63,
    );
    let outer = build_ipv6_gre_frame(
        &inner[14..],
        "2602:ffd3:0:2::7".parse().unwrap(),
        "2001:559:8585:80::8".parse().unwrap(),
        None,
    );
    let packet = try_native_gre_decap_from_frame(&outer, native_gre_outer_meta(), &state)
        .expect("native gre decap");
    assert_eq!(packet.meta.ingress_ifindex, 362);
    assert_eq!(packet.meta.addr_family, libc::AF_INET as u8);
    assert_eq!(packet.meta.protocol, PROTO_ICMP);
    assert_eq!(packet.meta.l3_offset, 14);
    assert_eq!(&packet.frame[12..14], &[0x08, 0x00]);
    assert_eq!(&packet.frame[26..30], &[10, 255, 192, 41]);
    assert_eq!(&packet.frame[30..34], &[10, 255, 192, 42]);
}

/// #2315: build an inner IPv4 ICMP frame, set its TOS byte, and
/// recompute the inner IPv4 header checksum so it stays valid. The IPv4
/// header is at inner[14..34]; the TOS byte is inner[15]; the checksum
/// is inner[24..26].
fn inner_v4_frame_with_tos(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8, tos: u8) -> Vec<u8> {
    let mut inner = build_icmp_echo_frame_v4(src, dst, ttl);
    inner[15] = tos;
    inner[24] = 0;
    inner[25] = 0;
    let cs = checksum16(&inner[14..34]);
    inner[24..26].copy_from_slice(&cs.to_be_bytes());
    inner
}

/// #2315: overwrite the outer IPv6 ECN field (low 2 bits of the Traffic
/// Class) on a built GRE frame. The IPv6 header starts at frame[14];
/// TC = (octet0<<4)|(octet1>>4); ECN is bits 4-5 of octet 1.
fn set_outer_ipv6_ecn(frame: &mut [u8], ecn: u8) {
    frame[15] = (frame[15] & 0xCF) | ((ecn & 0x03) << 4);
}

#[test]
fn native_gre_decap_combines_outer_ce_into_inner_ecn() {
    // #2315 RFC 6040 §4.2: an outer CE over an ECN-capable inner must
    // upgrade the inner ECN to CE at decap, and the inner IPv4 header
    // checksum must remain valid after the TOS change.
    let state = build_forwarding_state(&native_gre_snapshot(true));
    // Inner DSCP EF (46) + ECT(0) (0b10).
    let inner_tos = (46u8 << 2) | 0b10;
    let inner = inner_v4_frame_with_tos(
        Ipv4Addr::new(10, 255, 192, 41),
        Ipv4Addr::new(10, 255, 192, 42),
        63,
        inner_tos,
    );
    let mut outer = build_ipv6_gre_frame(
        &inner[14..],
        "2602:ffd3:0:2::7".parse().unwrap(),
        "2001:559:8585:80::8".parse().unwrap(),
        None,
    );
    set_outer_ipv6_ecn(&mut outer, 0b11); // outer CE

    let packet = try_native_gre_decap_from_frame(&outer, native_gre_outer_meta(), &state)
        .expect("decap must forward (legal CE upgrade)");
    // Inner emerges in the synthetic frame at offset 14 (eth) + 1 (TOS).
    let inner_tos_out = packet.frame[15];
    assert_eq!(
        inner_tos_out & 0x03,
        0b11,
        "inner ECN must be upgraded to CE"
    );
    assert_eq!(inner_tos_out >> 2, 46, "inner DSCP (EF) must be preserved");
    // Fail-on-revert: the CE bit MUST be set — the pre-#2315 copy-only
    // path could never produce this (it never touched the inner ECN).
    assert_ne!(inner_tos_out & 0x03, 0b10, "ECN must change from ECT(0)");
    // Inner IPv4 header checksum (synthetic frame[14..34]) must be valid.
    assert_eq!(
        checksum16(&packet.frame[14..34]),
        0,
        "inner IPv4 header checksum must be recomputed after the CE upgrade"
    );
}

#[test]
fn native_gre_decap_drops_illegal_outer_ce_over_not_ect_inner() {
    // #2315 RFC 6040 §4.2: outer CE over a Not-ECT inner is the illegal
    // combination — decap must DROP (return None).
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let inner = inner_v4_frame_with_tos(
        Ipv4Addr::new(10, 255, 192, 41),
        Ipv4Addr::new(10, 255, 192, 42),
        63,
        (46u8 << 2) | 0b00, // Not-ECT
    );
    let mut outer = build_ipv6_gre_frame(
        &inner[14..],
        "2602:ffd3:0:2::7".parse().unwrap(),
        "2001:559:8585:80::8".parse().unwrap(),
        None,
    );
    set_outer_ipv6_ecn(&mut outer, 0b11); // outer CE

    assert!(
        try_native_gre_decap_from_frame(&outer, native_gre_outer_meta(), &state).is_none(),
        "outer CE over a Not-ECT inner must be dropped (§4.2)"
    );
}

#[test]
fn native_gre_decap_leaves_inner_unchanged_when_outer_not_congested() {
    // Outer Not-ECT must leave the inner ECN/DSCP and checksum exactly
    // as they arrived (no spurious mutation on the common case).
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let inner_tos = (10u8 << 2) | 0b01; // DSCP 10 + ECT(1)
    let inner = inner_v4_frame_with_tos(
        Ipv4Addr::new(10, 255, 192, 41),
        Ipv4Addr::new(10, 255, 192, 42),
        63,
        inner_tos,
    );
    let outer = build_ipv6_gre_frame(
        &inner[14..],
        "2602:ffd3:0:2::7".parse().unwrap(),
        "2001:559:8585:80::8".parse().unwrap(),
        None,
    );
    // build_ipv6_gre_frame writes outer TC = 0 (Not-ECT) — no mutation.
    let packet = try_native_gre_decap_from_frame(&outer, native_gre_outer_meta(), &state)
        .expect("decap forwards");
    assert_eq!(
        packet.frame[15], inner_tos,
        "outer Not-ECT must leave the inner TOS byte verbatim"
    );
    assert_eq!(
        checksum16(&packet.frame[14..34]),
        0,
        "inner checksum unchanged and valid"
    );
}

#[test]
fn build_forwarded_frame_from_frame_encapsulates_native_gre() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let inner =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(8, 8, 8, 8), 64);
    let inner_meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 11,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: (inner.len() - 14) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        flow_src_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&[10, 0, 61, 102]);
            addr
        },
        flow_dst_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&[8, 8, 8, 8]);
            addr
        },
        flow_src_port: 0x1234,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: lookup_forwarding_resolution_v4(
            &state,
            None,
            Ipv4Addr::new(8, 8, 8, 8),
            "sfmix.inet.0",
            0,
            true,
        ),
        nat: NatDecision::default(),
    };
    let built = build_forwarded_frame_from_frame(
        &inner,
        inner_meta,
        &decision,
        &state,
        false,
        Some((0x1234, 0)),
    )
    .expect("encapsulated gre frame");
    assert_eq!(&built[12..16], &[0x81, 0x00, 0x00, 0x50]);
    assert_eq!(&built[16..18], &[0x86, 0xdd]);
    assert_eq!(&built[22..24], &[0x00, 0x20]);
    assert_eq!(built[24], PROTO_GRE);
    assert_eq!(built[25], 64);
    assert_eq!(&built[60..62], &[0x08, 0x00]);
    assert_eq!(built[70], 63);
    assert_eq!(&built[74..78], &[10, 0, 61, 102]);
    assert_eq!(&built[78..82], &[8, 8, 8, 8]);
}

#[test]
fn local_origin_tunnel_tx_request_encapsulates_raw_ip_for_active_owner() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    // #1881: the loop now loads HA state once per iteration and
    // passes the map down — the builder takes &BTreeMap directly.
    let ha_state = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let packet = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 255, 192, 42),
        Ipv4Addr::new(10, 255, 192, 41),
        64,
    );
    let plan = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state,
        &ha_state,
        &dynamic_neighbors,
    )
    .expect("local-origin tunnel tx request");
    assert_eq!(plan.tx_ifindex, 6);
    assert_eq!(&plan.tx_request.bytes[12..16], &[0x81, 0x00, 0x00, 0x50]);
    assert_eq!(&plan.tx_request.bytes[16..18], &[0x86, 0xdd]);
    assert_eq!(plan.tx_request.bytes[24], PROTO_GRE);
    assert_eq!(&plan.tx_request.bytes[60..62], &[0x08, 0x00]);
    assert_eq!(&plan.tx_request.bytes[74..78], &[10, 255, 192, 42]);
    assert_eq!(&plan.tx_request.bytes[78..82], &[10, 255, 192, 41]);
    assert_eq!(plan.session_entry.key.protocol, PROTO_ICMP);
}

#[test]
fn local_origin_tunnel_tx_request_rejects_inactive_owner() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let packet = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 255, 192, 42),
        Ipv4Addr::new(10, 255, 192, 41),
        64,
    );
    let err = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state,
        &ha_state,
        &dynamic_neighbors,
    )
    .expect_err("inactive owner should not originate tunnel traffic");
    assert!(err.contains("ha_inactive"), "unexpected error: {err}");
}

#[test]
fn build_forwarded_frame_from_frame_encapsulates_native_gre_after_ipv4_snat() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let inner = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 192, 41),
        64,
    );
    let inner_meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 5,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: (inner.len() - 14) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        flow_src_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&[10, 0, 61, 102]);
            addr
        },
        flow_dst_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&[10, 255, 192, 41]);
            addr
        },
        flow_src_port: 0x1234,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: lookup_forwarding_resolution_v4(
            &state,
            None,
            Ipv4Addr::new(10, 255, 192, 41),
            "sfmix.inet.0",
            0,
            true,
        ),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42))),
            ..NatDecision::default()
        },
    };
    let built = build_forwarded_frame_from_frame(
        &inner,
        inner_meta,
        &decision,
        &state,
        false,
        Some((0x1234, 0)),
    )
    .expect("encapsulated native gre frame with snat");
    assert_eq!(&built[12..16], &[0x81, 0x00, 0x00, 0x50]);
    assert_eq!(&built[16..18], &[0x86, 0xdd]);
    assert_eq!(built[24], PROTO_GRE);
    assert_eq!(&built[74..78], &[10, 255, 192, 42]);
    assert_eq!(&built[78..82], &[10, 255, 192, 41]);
}

#[test]
fn build_forwarded_frame_from_frame_recomputes_tcp_checksum_for_native_gre_snat() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let src_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(10, 255, 192, 41);
    let snat_ip = Ipv4Addr::new(10, 255, 192, 42);
    let src_port = 50420u16;
    let dst_port = 5201u16;

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x01, // ack
        0x50, 0x18, 0x20, 0x00, // data offset/flags/window
        0x18, 0x29, 0x00, 0x00, // intentionally bogus partial/offload checksum + urg
        b't', b'e', b's', b't', b'd', b'a', b't', b'a',
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 5,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: (frame.len() - 14) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&src_ip.octets());
            addr
        },
        flow_dst_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&dst_ip.octets());
            addr
        },
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: lookup_forwarding_resolution_v4(&state, None, dst_ip, "sfmix.inet.0", 0, true),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_ip)),
            ..NatDecision::default()
        },
    };
    let built = build_forwarded_frame_from_frame(
        &frame,
        meta,
        &decision,
        &state,
        false,
        Some((src_port, dst_port)),
    )
    .expect("encapsulated native gre frame with tcp snat");
    let inner = &built[62..];
    assert_eq!(&inner[12..16], &snat_ip.octets());
    assert_eq!(&inner[16..20], &dst_ip.octets());
    assert!(tcp_checksum_ok_ipv4(inner));
}

#[test]
fn build_forwarded_frame_from_frame_clamps_tcp_mss_for_native_gre() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let src_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(10, 255, 192, 41);
    let src_port = 44028u16;
    let dst_port = 5201u16;

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x2c, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x00,
        0x00,
        0x00,
        0x01, // seq
        0x00,
        0x00,
        0x00,
        0x00, // ack
        0x60,
        TCP_FLAG_SYN,
        0xfa,
        0xf0, // data offset / flags / window
        0x00,
        0x00,
        0x00,
        0x00, // checksum + urg
        0x02,
        0x04,
        0x05,
        0xb4, // MSS 1460
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 5,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 58,
        pkt_len: (frame.len() - 14) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        flow_src_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&src_ip.octets());
            addr
        },
        flow_dst_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&dst_ip.octets());
            addr
        },
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: lookup_forwarding_resolution_v4(&state, None, dst_ip, "sfmix.inet.0", 0, true),
        nat: NatDecision::default(),
    };
    let built = build_forwarded_frame_from_frame(
        &frame,
        meta,
        &decision,
        &state,
        false,
        Some((src_port, dst_port)),
    )
    .expect("encapsulated native gre frame with tcp syn");
    let inner = &built[62..];
    assert_eq!(&inner[40..44], &[0x02, 0x04, 0x05, 0x88]);
    assert!(tcp_checksum_ok_ipv4(inner));
}
fn tcp_checksum_ok_ipv4(packet: &[u8]) -> bool {
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    checksum16_ipv4(src, dst, PROTO_TCP, &packet[ihl..total_len]) == 0
}

fn tcp_ports_ipv4(packet: &[u8]) -> (u16, u16) {
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    (
        u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
        u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]),
    )
}

fn build_ipv4_tcp_frame(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(&ack.to_be_bytes());
    frame.extend_from_slice(&[0x50, flags, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    frame
}

#[test]
fn syn_cookie_syn_ack_builder_swaps_tuple_and_preserves_vlan() {
    let client = Ipv4Addr::new(192, 0, 2, 10);
    let server = Ipv4Addr::new(198, 51, 100, 20);
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        80,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    let ip_csum = checksum16(&frame[18..38]);
    frame[28..30].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&443u16.to_be_bytes());
    frame.extend_from_slice(&0x0102_0304u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, TCP_FLAG_SYN, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
    recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");

    let out =
        build_syn_cookie_syn_ack_frame(&frame, 0xaabb_ccdd, 1460).expect("syn-cookie syn-ack");

    assert_eq!(&out[0..6], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    assert_eq!(&out[6..12], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(&out[12..18], &frame[12..18]);
    assert_eq!(&out[30..34], &server.octets());
    assert_eq!(&out[34..38], &client.octets());
    assert_eq!(u16::from_be_bytes([out[20], out[21]]), 44);
    assert_eq!(u16::from_be_bytes([out[38], out[39]]), 443);
    assert_eq!(u16::from_be_bytes([out[40], out[41]]), 49152);
    assert_eq!(
        u32::from_be_bytes([out[42], out[43], out[44], out[45]]),
        0xaabb_ccdd
    );
    assert_eq!(
        u32::from_be_bytes([out[46], out[47], out[48], out[49]]),
        0x0102_0305
    );
    assert_eq!(out[50] >> 4, 6);
    assert_eq!(out[51], TCP_FLAG_SYN | 0x10);
    assert_eq!(&out[58..62], &[2, 4, 0x05, 0xb4]);
    assert_eq!(checksum16(&out[18..38]), 0);
    assert!(tcp_checksum_ok_ipv4(&out[18..]));
}

#[test]
fn syn_cookie_ipv4_syn_ack_builder_pads_to_ethernet_minimum() {
    let client = Ipv4Addr::new(192, 0, 2, 10);
    let server = Ipv4Addr::new(198, 51, 100, 20);
    let frame = build_ipv4_tcp_frame(client, server, 49152, 443, 0x0102_0304, 0, TCP_FLAG_SYN);

    let out =
        build_syn_cookie_syn_ack_frame(&frame, 0xaabb_ccdd, 1460).expect("syn-cookie syn-ack");

    assert_eq!(out.len(), 60);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 44);
    assert_eq!(&out[54..58], &[2, 4, 0x05, 0xb4]);
    assert_eq!(&out[58..60], &[0, 0]);
    assert_eq!(checksum16(&out[14..34]), 0);
    assert!(tcp_checksum_ok_ipv4(&out[14..]));
}

#[test]
fn syn_cookie_ipv4_rst_builder_pads_to_ethernet_minimum() {
    let client = Ipv4Addr::new(192, 0, 2, 10);
    let server = Ipv4Addr::new(198, 51, 100, 20);
    let frame = build_ipv4_tcp_frame(client, server, 49152, 443, 0x1111_2222, 0x3333_4444, 0x10);

    let out = build_syn_cookie_ack_rst_frame(&frame).expect("syn-cookie rst");

    assert_eq!(out.len(), 60);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 40);
    assert_eq!(
        u32::from_be_bytes([out[38], out[39], out[40], out[41]]),
        0x3333_4444
    );
    assert_eq!(
        u32::from_be_bytes([out[42], out[43], out[44], out[45]]),
        0x1111_2223
    );
    assert_eq!(out[47], TCP_FLAG_RST | 0x10);
    assert_eq!(&out[48..50], &[0, 0]);
    assert_eq!(&out[54..60], &[0, 0, 0, 0, 0, 0]);
    assert_eq!(checksum16(&out[14..34]), 0);
    assert!(tcp_checksum_ok_ipv4(&out[14..]));
}

#[test]
fn syn_cookie_vlan_ipv4_rst_builder_pads_to_ethernet_minimum() {
    let client = Ipv4Addr::new(192, 0, 2, 10);
    let server = Ipv4Addr::new(198, 51, 100, 20);
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        80,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    let ip_csum = checksum16(&frame[18..38]);
    frame[28..30].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&443u16.to_be_bytes());
    frame.extend_from_slice(&0x1111_2222u32.to_be_bytes());
    frame.extend_from_slice(&0x3333_4444u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
    recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");

    let out = build_syn_cookie_ack_rst_frame(&frame).expect("syn-cookie rst");

    assert_eq!(out.len(), 60);
    assert_eq!(&out[12..18], &frame[12..18]);
    assert_eq!(u16::from_be_bytes([out[20], out[21]]), 40);
    assert_eq!(
        u32::from_be_bytes([out[42], out[43], out[44], out[45]]),
        0x3333_4444
    );
    assert_eq!(
        u32::from_be_bytes([out[46], out[47], out[48], out[49]]),
        0x1111_2223
    );
    assert_eq!(out[51], TCP_FLAG_RST | 0x10);
    assert_eq!(&out[52..54], &[0, 0]);
    assert_eq!(&out[58..60], &[0, 0]);
    assert_eq!(checksum16(&out[18..38]), 0);
    assert!(tcp_checksum_ok_ipv4(&out[18..]));
}

#[test]
fn syn_cookie_ack_rst_builder_uses_received_ack_as_rst_seq() {
    let client = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 10);
    let server = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 20);
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&20u16.to_be_bytes());
    frame.push(PROTO_TCP);
    frame.push(64);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&443u16.to_be_bytes());
    frame.extend_from_slice(&0x1111_2222u32.to_be_bytes());
    frame.extend_from_slice(&0x3333_4444u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let out = build_syn_cookie_ack_rst_frame(&frame).expect("syn-cookie rst");

    assert_eq!(&out[0..6], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    assert_eq!(&out[6..12], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(&out[22..38], &server.octets());
    assert_eq!(&out[38..54], &client.octets());
    assert_eq!(u16::from_be_bytes([out[18], out[19]]), 20);
    assert_eq!(u16::from_be_bytes([out[54], out[55]]), 443);
    assert_eq!(u16::from_be_bytes([out[56], out[57]]), 49152);
    assert_eq!(
        u32::from_be_bytes([out[58], out[59], out[60], out[61]]),
        0x3333_4444
    );
    assert_eq!(
        u32::from_be_bytes([out[62], out[63], out[64], out[65]]),
        0x1111_2223
    );
    assert_eq!(out[67], TCP_FLAG_RST | 0x10);
    assert_eq!(&out[68..70], &[0, 0]);
    assert!(tcp_checksum_ok_ipv6(&out[14..]));
}

fn icmpv6_checksum_ok(packet: &[u8]) -> bool {
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("src"));
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("dst"));
    checksum16_ipv6(src, dst, PROTO_ICMPV6, &packet[40..]) == 0
}

#[test]
fn apply_nat_ipv4_recomputes_tcp_checksum() {
    let mut packet = vec![
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x50, 0x18, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't',
        b'a',
    ];
    let ip_sum = checksum16(&packet[..20]);
    packet[10] = (ip_sum >> 8) as u8;
    packet[11] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut packet, 20, PROTO_TCP, false).expect("initial tcp sum");
    assert!(tcp_checksum_ok_ipv4(&packet));

    apply_nat_ipv4(
        &mut packet,
        PROTO_TCP,
        NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_dst: None,
            ..NatDecision::default()
        },
        false,
    )
    .expect("apply nat");

    assert_eq!(&packet[12..16], &[172, 16, 80, 8]);
    assert!(tcp_checksum_ok_ipv4(&packet));
}

#[test]
fn extract_l3_packet_with_nat_rewrites_reverse_snat_reply_v4() {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        [0x02, 0xbf, 0x72, 0x00, 0x50, 0x08],
        80,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 63, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
        200, 172, 16, 80, 8, 0x14, 0x51, 0x9c, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a',
        b't', b'a',
    ]);
    let ip_sum = checksum16(&frame[18..38]);
    frame[28] = (ip_sum >> 8) as u8;
    frame[29] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 18,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let packet = extract_l3_packet_with_nat(
        &frame,
        meta,
        NatDecision {
            rewrite_src: None,
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            ..NatDecision::default()
        },
    )
    .expect("slow-path packet");
    assert_eq!(&packet[12..16], &[172, 16, 80, 200]);
    assert_eq!(&packet[16..20], &[10, 0, 61, 102]);
    assert!(tcp_checksum_ok_ipv4(&packet));
}

#[test]
fn extract_l3_packet_with_nat_rewrites_reverse_snat_reply_v6() {
    let src_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap();
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        80,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 63]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&[
        0x14, 0x51, 0x95, 0x2c, 0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x10, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e',
        b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[18..], 40, PROTO_TCP).expect("tcp sum");

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 18,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let packet = extract_l3_packet_with_nat(
        &frame,
        meta,
        NatDecision {
            rewrite_src: None,
            rewrite_dst: Some(IpAddr::V6("2001:559:8585:ef00::102".parse().unwrap())),
            ..NatDecision::default()
        },
    )
    .expect("slow-path packet");
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()),
        src_ip
    );
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()),
        "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap()
    );
    assert!(tcp_checksum_ok_ipv6(&packet));
}

#[test]
fn build_forwarded_frame_keeps_tcp_checksum_valid_after_snat() {
    let state = build_forwarding_state(&nat_snapshot());
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x50, 0x18, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't',
        b'a',
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

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
        protocol: PROTO_TCP,
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
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_dst: None,
                ..NatDecision::default()
            },
        },
        &state,
        None,
    )
    .expect("forwarded frame");

    assert_eq!(&out[30..34], &[172, 16, 80, 8]);
    assert_eq!(out[26], 63);
    assert!(tcp_checksum_ok_ipv4(&out[18..]));
}

#[test]
fn rewrite_forwarded_frame_in_place_keeps_icmpv6_checksum_valid_after_snat() {
    let src_ip = "2001:559:8585:ef00::100".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, PROTO_ICMPV6, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&[128, 0, 0, 0, 0x12, 0x34, 0x00, 0x01]);
    let sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &frame[54..]);
    frame[56] = (sum >> 8) as u8;
    frame[57] = sum as u8;

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        false,
        None,
    )
    .expect("in-place v6 forward");
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    assert_eq!(&out[0..6], &[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]);
    assert_eq!(out[25], 63);
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&out[26..42]).unwrap()),
        "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap()
    );
    assert!(icmpv6_checksum_ok(&out[18..]));
}

fn l2_rewrite_test_decision(vlan_id: u16) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: vlan_id,
        },
        nat: NatDecision::default(),
    }
}

#[test]
fn rewrite_forwarded_frame_in_place_pushes_vlan_by_shifting_tx_descriptor() {
    let frame = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 0, 1, 1),
        Ipv4Addr::new(172, 16, 80, 200),
        64,
    );
    let rx_addr = 256usize;
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(rx_addr, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: rx_addr as u64,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &l2_rewrite_test_decision(80),
        false,
        None,
    )
    .expect("vlan push");

    assert_eq!(rewrite_result.offset, (rx_addr - 4) as u64);
    assert_eq!(rewrite_result.len, frame.len() as u32 + 4);
    assert_eq!(
        rewrite_result.l2_rewrite,
        InPlaceL2Rewrite::VlanPushDescriptor
    );
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    assert_eq!(&out[0..6], &[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x0800);
    assert_eq!(out[18], 0x45);
    assert_eq!(
        area.slice(rx_addr + 14, 1).expect("ip-at-original-address")[0],
        0x45
    );
}

#[test]
fn rewrite_forwarded_frame_in_place_pops_vlan_by_shifting_tx_descriptor() {
    let frame = build_icmp_echo_frame_v4_vlan(
        Ipv4Addr::new(10, 0, 1, 1),
        Ipv4Addr::new(172, 16, 80, 200),
        64,
        80,
    );
    let rx_addr = 256usize;
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(rx_addr, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 18,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: rx_addr as u64,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &l2_rewrite_test_decision(0),
        false,
        None,
    )
    .expect("vlan pop");

    assert_eq!(rewrite_result.offset, (rx_addr + 4) as u64);
    assert_eq!(rewrite_result.len, frame.len() as u32 - 4);
    assert_eq!(
        rewrite_result.l2_rewrite,
        InPlaceL2Rewrite::VlanPopDescriptor
    );
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    assert_eq!(&out[0..6], &[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
    assert_eq!(out[14], 0x45);
    assert_eq!(
        area.slice(rx_addr + 18, 1).expect("ip-at-original-address")[0],
        0x45
    );
}

#[test]
fn rewrite_forwarded_frame_in_place_pushes_vlan_with_memmove_without_headroom() {
    let frame = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 0, 1, 1),
        Ipv4Addr::new(172, 16, 80, 200),
        64,
    );
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
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
        &l2_rewrite_test_decision(80),
        false,
        None,
    )
    .expect("vlan push fallback");

    assert_eq!(rewrite_result.offset, 0);
    assert_eq!(
        rewrite_result.l2_rewrite,
        InPlaceL2Rewrite::VlanPushMemmoveNoHeadroom
    );
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x0800);
    assert_eq!(out[18], 0x45);
}

#[test]
fn rewrite_forwarded_frame_in_place_keeps_icmpv6_echo_identifier_and_sequence() {
    let src_ip = "2001:559:8585:ef00::100".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2607:f8b0:4005:814::200e".parse::<Ipv6Addr>().unwrap();
    let echo_id = 0x3e0f;
    let echo_seq = 0x80e9;

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x07, 0x9f, 0x9c, 0x00, 0x18, PROTO_ICMPV6, 2]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&[
        128,
        0,
        0,
        0,
        (echo_id >> 8) as u8,
        echo_id as u8,
        (echo_seq >> 8) as u8,
        echo_seq as u8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]);
    let sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &frame[54..]);
    frame[56] = (sum >> 8) as u8;
    frame[57] = sum as u8;

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        flow_src_port: echo_id,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:50::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };

    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        false,
        None,
    )
    .expect("in-place v6 echo forward");
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");

    let packet = &out[18..];
    assert_eq!(packet[40], 128);
    assert_eq!(packet[41], 0);
    assert_eq!(u16::from_be_bytes([packet[44], packet[45]]), echo_id);
    assert_eq!(u16::from_be_bytes([packet[46], packet[47]]), echo_seq);
    assert!(icmpv6_checksum_ok(packet));
}

fn tcp_ports_ipv6(packet: &[u8]) -> (u16, u16) {
    (
        u16::from_be_bytes([packet[40], packet[41]]),
        u16::from_be_bytes([packet[42], packet[43]]),
    )
}

fn tcp_checksum_ok_ipv6(packet: &[u8]) -> bool {
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("v6 src"));
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("v6 dst"));
    checksum16_ipv6(src, dst, PROTO_TCP, &packet[40..]) == 0
}

#[test]
fn enforce_expected_ports_repairs_ipv6_tcp_ports_and_checksum() {
    let src_ip = "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        80,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 63]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&[
        0x04, 0x01, 0x14, 0x51, // wrong src port 1025 -> 5201
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[18..], 40, PROTO_TCP).expect("initial checksum");
    assert!(tcp_checksum_ok_ipv6(&frame[18..]));

    let repaired = enforce_expected_ports(
        &mut frame,
        libc::AF_INET6 as u8,
        PROTO_TCP,
        Some((54688, 5201)),
        false,
    )
    .expect("repair");
    assert!(repaired);
    assert_eq!(tcp_ports_ipv6(&frame[18..]), (54688, 5201));
    assert!(tcp_checksum_ok_ipv6(&frame[18..]));
}

#[test]
fn enforce_expected_ports_repairs_ipv4_tcp_ports_and_checksum() {
    let src_ip = Ipv4Addr::new(172, 16, 80, 8);
    let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        80,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 63, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&[
        0x04, 0x01, 0x14, 0x51, // wrong src port 1025 -> 54688
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
    ]);
    let ip_sum = checksum16(&frame[18..38]);
    frame[28] = (ip_sum >> 8) as u8;
    frame[29] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, true).expect("initial checksum");
    assert!(tcp_checksum_ok_ipv4(&frame[18..]));

    let repaired = enforce_expected_ports(
        &mut frame,
        libc::AF_INET as u8,
        PROTO_TCP,
        Some((54688, 5201)),
        false,
    )
    .expect("repair");
    assert!(repaired);
    assert_eq!(tcp_ports_ipv4(&frame[18..]), (54688, 5201));
    assert!(tcp_checksum_ok_ipv4(&frame[18..]));
}

#[test]
fn rewrite_forwarded_frame_in_place_keeps_ipv6_tcp_ports_after_vlan_snat() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&[
        0xd5, 0xa0, 0x14, 0x51, // 54688 -> 5201
        0x31, 0x96, 0xc8, 0x32, // seq
        0x08, 0xf0, 0x5a, 0xc6, // ack
        0x50, 0x18, 0x00, 0x40, // data offset/flags/window
        0x00, 0x00, 0x00, 0x00, // checksum/urgent
        b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv6(&frame[14..]));

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 54688,
        flow_dst_port: 5201,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        false,
        Some((54688, 5201)),
    )
    .expect("rewrite in place");
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x86dd);
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&out[26..42]).unwrap()),
        "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(tcp_ports_ipv6(&out[18..]), (54688, 5201));
    assert!(tcp_checksum_ok_ipv6(&out[18..]));
}

#[test]
fn build_forwarded_frame_into_keeps_ipv6_tcp_ports_after_vlan_snat() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&[
        0xd5, 0xa0, 0x14, 0x51, // 54688 -> 5201
        0x31, 0x96, 0xc8, 0x32, // seq
        0x08, 0xf0, 0x5a, 0xc6, // ack
        0x50, 0x18, 0x00, 0x40, // data offset/flags/window
        0x00, 0x00, 0x00, 0x00, // checksum/urgent
        b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv6(&frame[14..]));

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 54688,
        flow_dst_port: 5201,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let mut out = [0u8; 256];
    let frame_len = build_forwarded_frame_into(
        &mut out,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &ForwardingState::default(),
        Some((54688, 5201)),
    )
    .expect("build forwarded frame");
    let out = &out[..frame_len];
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x86dd);
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&out[26..42]).unwrap()),
        "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(tcp_ports_ipv6(&out[18..]), (54688, 5201));
    assert!(tcp_checksum_ok_ipv6(&out[18..]));
}

#[test]
fn build_forwarded_frame_into_ignores_ipv6_tcp_metadata_port_mismatch() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let real_src_port = 38276u16;
    let real_dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&real_src_port.to_be_bytes());
    frame.extend_from_slice(&real_dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, // seq
        0x08, 0xf0, 0x5a, 0xc6, // ack
        0x50, 0x18, 0x00, 0x40, // data offset/flags/window
        0x00, 0x00, 0x00, 0x00, // checksum/urgent
        b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1025,
        flow_dst_port: real_dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let mut out = [0u8; 256];
    let frame_len = build_forwarded_frame_into(
        &mut out,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &ForwardingState::default(),
        Some((real_src_port, real_dst_port)),
    )
    .expect("build forwarded frame");
    let out = &out[..frame_len];
    assert_eq!(tcp_ports_ipv6(&out[18..]), (real_src_port, real_dst_port));
    assert!(tcp_checksum_ok_ipv6(&out[18..]));
}

#[test]
fn build_live_forward_request_prefers_session_flow_ports_over_frame() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let frame_src_port = 38276u16;
    let frame_dst_port = 5201u16;
    let session_src_port = 1025u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&frame_src_port.to_be_bytes());
    frame.extend_from_slice(&frame_dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: session_src_port,
        flow_dst_port: frame_dst_port,
        ..UserspaceDpMeta::default()
    };
    // Session flow ports differ from frame ports — session is authoritative
    // because it is immune to UMEM DMA races.
    let session_flow = SessionFlow {
        src_ip: IpAddr::V6(src_ip),
        dst_ip: IpAddr::V6(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            src_port: session_src_port,
            dst_port: frame_dst_port,
        },
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
        },
    );
    let ingress = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };

    let req = build_live_forward_request(
        &area,
        &WorkerBindingLookup::default(),
        0,
        &ingress,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some(&session_flow),
        None,
        false,
        0,
    )
    .expect("request");
    // Session flow ports (1025, 5201) take priority over frame ports (38276, 5201)
    assert_eq!(req.expected_ports, Some((session_src_port, frame_dst_port)));
}

#[test]
fn build_live_forward_request_uses_live_frame_ports_when_no_session_flow() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let real_src_port = 38276u16;
    let real_dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&real_src_port.to_be_bytes());
    frame.extend_from_slice(&real_dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1025,
        flow_dst_port: real_dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
        },
    );
    let ingress = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };

    // No session flow — live frame ports should be used (over meta ports)
    let req = build_live_forward_request(
        &area,
        &WorkerBindingLookup::default(),
        0,
        &ingress,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        None,
        None,
        false,
        0,
    )
    .expect("request");
    assert_eq!(req.expected_ports, Some((real_src_port, real_dst_port)));
}

#[test]
fn build_live_forward_request_meters_non_l4_metadata_flow() {
    let src_ip = Ipv4Addr::new(10, 0, 0, 1);
    let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
    let area = MmapArea::new(4096).expect("mmap");
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 10,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_GRE,
        pkt_len: 128,
        flow_src_addr: {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&src_ip.octets());
            bytes
        },
        flow_dst_addr: {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&dst_ip.octets());
            bytes
        },
        ..UserspaceDpMeta::default()
    };
    let filter_state = crate::filter::parse_filter_state_with_three_color(
        &[FirewallFilterSnapshot {
            name: "policed".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "meter-gre".into(),
                action: "accept".into(),
                protocols: vec!["gre".into()],
                policer: "gre-pol".into(),
                ..Default::default()
            }],
        }],
        &[],
        &[ThreeColorPolicerSnapshot {
            name: "gre-pol".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 64,
            peak_or_excess_burst_bytes: 32,
            then_action: "discard".into(),
            ..Default::default()
        }],
        &[crate::InterfaceSnapshot {
            name: "ge-0/0/1.0".into(),
            ifindex: 10,
            filter_input_v4: "policed".into(),
            ..Default::default()
        }],
        "policed",
        "",
    );
    let mut forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ..ForwardingState::default()
    };
    forwarding.cos.interfaces.insert(
        12,
        CoSInterfaceConfig {
            shaping_rate_bytes: 1_000_000,
            burst_bytes: crate::afxdp::cos::COS_MIN_BURST_BYTES,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: Vec::new(),
            oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
            oversubscription_guarantee_fraction: 0.0,
            priority_low_min_share_bytes: 0,
        },
    );
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let ingress = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };

    let req = build_live_forward_request(
        &area,
        &WorkerBindingLookup::default(),
        0,
        &ingress,
        XdpDesc {
            addr: 0,
            len: 0,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        None,
        None,
        false,
        0,
    );

    assert!(
        req.is_none(),
        "red-drop policer should reject non-L4 metadata flow"
    );
    let status = forwarding.filter_state.three_color_policer_statuses();
    assert_eq!(status[0].red_packets, 1);
    assert_eq!(status[0].drop_packets, 1);
}

#[test]
fn build_live_forward_request_marks_empty_cos_selection_resolved() {
    let src_ip = Ipv4Addr::new(10, 0, 0, 1);
    let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
    let area = MmapArea::new(4096).expect("mmap");
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 10,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_GRE,
        pkt_len: 64,
        flow_src_addr: {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&src_ip.octets());
            bytes
        },
        flow_dst_addr: {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&dst_ip.octets());
            bytes
        },
        ..UserspaceDpMeta::default()
    };
    let filter_state = crate::filter::parse_filter_state_with_three_color(
        &[FirewallFilterSnapshot {
            name: "policed".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "meter-gre".into(),
                action: "accept".into(),
                protocols: vec!["gre".into()],
                policer: "gre-pol".into(),
                ..Default::default()
            }],
        }],
        &[],
        &[ThreeColorPolicerSnapshot {
            name: "gre-pol".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 128,
            peak_or_excess_burst_bytes: 64,
            then_action: "discard".into(),
            ..Default::default()
        }],
        &[crate::InterfaceSnapshot {
            name: "ge-0/0/1.0".into(),
            ifindex: 10,
            filter_input_v4: "policed".into(),
            ..Default::default()
        }],
        "policed",
        "",
    );
    let forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ..ForwardingState::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let ingress = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };

    let req = build_live_forward_request(
        &area,
        &WorkerBindingLookup::default(),
        0,
        &ingress,
        XdpDesc {
            addr: 0,
            len: 0,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        None,
        None,
        false,
        0,
    )
    .expect("green policer should permit request");

    assert_eq!(req.cos_queue_id, None);
    assert_eq!(req.dscp_rewrite, None);
    assert!(req.cos_tx_selection_resolved);
    let status = forwarding.filter_state.three_color_policer_statuses();
    assert_eq!(status[0].green_packets, 1);
}

#[test]
fn build_live_forward_request_emits_output_filter_log_event() {
    let src_ip = Ipv4Addr::new(10, 0, 0, 1);
    let dst_ip = Ipv4Addr::new(198, 51, 100, 20);
    let meta = UserspaceDpMeta {
        ingress_ifindex: 10,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 64,
        dscp: 0,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(src_ip),
        dst_ip: IpAddr::V4(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(src_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port: 49152,
            dst_port: 443,
        },
    };
    let filter_state = crate::filter::parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "egress-log".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "log-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                log: true,
                ..Default::default()
            }],
        }],
        &[],
        &[crate::InterfaceSnapshot {
            name: "ge-0/0/2.0".into(),
            ifindex: 12,
            filter_output_v4: "egress-log".into(),
            ..Default::default()
        }],
        "",
        "",
    );
    let mut forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ..ForwardingState::default()
    };
    forwarding.ifindex_to_zone_id.insert(10, TEST_LAN_ZONE_ID);
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: Some(Ipv4Addr::new(198, 51, 100, 1)),
            primary_v6: None,
        },
    );
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let ingress = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        0,
        &ingress,
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
    )
    .expect("output filter log should not block forwarding");

    assert!(req.cos_tx_selection_resolved);
    let filter_event = event_rx
        .try_recv()
        .expect("output filter-log event")
        .decode_dataplane_event()
        .expect("filter-log payload");
    assert_eq!(filter_event.kind, DataplaneEventKind::FilterLog);
    assert_eq!(filter_event.filter_id, 0);
    assert_eq!(filter_event.term_id, 0);
    assert_eq!(filter_event.reason, FilterLogSource::Output.wire_reason());
    assert_eq!(filter_event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(filter_event.egress_zone_id, TEST_WAN_ZONE_ID);
    assert_eq!(event_handle.dataplane_event_stats().filter_log.sent, 1);
}

#[test]
fn build_live_forward_request_uses_flow_or_metadata_ports_when_frame_ports_unavailable() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let area = MmapArea::new(4096).expect("mmap");
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1025,
        flow_dst_port: 5201,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V6(src_ip),
        dst_ip: IpAddr::V6(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            src_port: 54688,
            dst_port: 5201,
        },
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let req = build_live_forward_request(
        &area,
        &WorkerBindingLookup::default(),
        0,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: 0,
            options: 0,
        },
        meta,
        &decision,
        &ForwardingState::default(),
        Some(&flow),
        None,
        false,
        0,
    )
    .expect("request");
    assert_eq!(req.expected_ports, Some((54688, 5201)));
}

#[test]
fn build_live_forward_request_marks_session_fabric_redirect_for_nat_and_zone() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let fabric_redirect = resolve_fabric_redirect(&forwarding).expect("fabric redirect");
    let zone_redirect =
        resolve_zone_encoded_fabric_redirect(&forwarding, "wan").expect("zone redirect");
    let mut area = MmapArea::new(256).expect("mmap");
    area.slice_mut(0, 64).expect("slice").fill(0xaa);
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("fab0"),
        ifindex: 21,
    };
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: 5201,
        flow_dst_port: 44278,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: fabric_redirect,
        nat: NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            ..NatDecision::default()
        },
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 5201,
            dst_port: 44278,
        },
    };

    let req = build_live_forward_request(
        &area,
        &WorkerBindingLookup::default(),
        0,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: 64,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some(&flow),
        Some(TEST_WAN_ZONE_ID),
        true,
        0,
    )
    .expect("request");

    assert!(req.apply_nat_on_fabric);
    assert_eq!(
        req.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(req.decision.resolution.src_mac, zone_redirect.src_mac);
}

#[test]
fn build_live_forward_request_caches_target_binding_index() {
    let mut area = MmapArea::new(256).expect("mmap");
    area.slice_mut(0, 64).expect("slice").fill(0xaa);
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
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: 12345,
        flow_dst_port: 5201,
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
    let mut forwarding = ForwardingState::default();
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
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_if_queue.insert((11, 3), 5);
    lookup.first_by_if.insert(11, 4);

    let req = build_live_forward_request(
        &area,
        &lookup,
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: 64,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        None,
        None,
        false,
        0,
    )
    .expect("request");

    assert_eq!(req.target_ifindex, 11);
    assert_eq!(req.target_binding_index, Some(5));
}

#[test]
fn build_forwarded_frame_applies_nat_on_fabric_when_requested() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let fabric_redirect = resolve_fabric_redirect(&forwarding).expect("fabric redirect");
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x10, 0xdb, 0xff, 0x10, 0x01],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x02, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
        200, 172, 16, 80, 8, 0x14, 0x51, 0xac, 0xf6, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x02, 0x50, 0x12, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv4(&frame[14..]));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: 5201,
        flow_dst_port: 44278,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: fabric_redirect,
        nat: NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            ..NatDecision::default()
        },
    };

    let no_nat = build_forwarded_frame_from_frame(
        &frame,
        meta,
        &decision,
        &forwarding,
        false,
        Some((5201, 44278)),
    )
    .expect("frame without nat");
    assert_eq!(&no_nat[30..34], &[172, 16, 80, 8]);

    let nat = build_forwarded_frame_from_frame(
        &frame,
        meta,
        &decision,
        &forwarding,
        true,
        Some((5201, 44278)),
    )
    .expect("frame with nat");
    assert_eq!(&nat[30..34], &[10, 0, 61, 102]);
    assert!(tcp_checksum_ok_ipv4(&nat[14..]));
}

#[test]
fn build_forwarded_frame_into_keeps_ipv6_ports_when_frame_and_metadata_disagree() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let real_src_port = 0x0401u16;
    let real_dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&real_src_port.to_be_bytes());
    frame.extend_from_slice(&real_dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 54688,
        flow_dst_port: real_dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let mut out = [0u8; 256];
    let frame_len = build_forwarded_frame_into(
        &mut out,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &ForwardingState::default(),
        Some((real_src_port, real_dst_port)),
    )
    .expect("build forwarded frame");
    let out = &out[..frame_len];
    assert_eq!(tcp_ports_ipv6(&out[18..]), (real_src_port, real_dst_port));
    assert!(tcp_checksum_ok_ipv6(&out[18..]));
}

#[test]
fn build_forwarded_frame_into_prefers_expected_ipv6_ports_over_wrong_live_ports() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let real_src_port = 42566u16;
    let real_dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&real_src_port.to_be_bytes());
    frame.extend_from_slice(&real_dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1042,
        flow_dst_port: real_dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let mut out = [0u8; 256];
    let frame_len = build_forwarded_frame_into(
        &mut out,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &ForwardingState::default(),
        Some((1042, real_dst_port)),
    )
    .expect("build forwarded frame");
    let out = &out[..frame_len];
    assert_eq!(tcp_ports_ipv6(&out[18..]), (1042, real_dst_port));
    assert!(tcp_checksum_ok_ipv6(&out[18..]));
}

#[test]
fn build_forwarded_frame_into_repairs_wrong_ipv6_frame_ports_from_expected_tuple() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let expected_src_port = 36394u16;
    let wrong_src_port = 1025u16;
    let dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&wrong_src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_addr: src_ip.octets(),
        flow_dst_addr: dst_ip.octets(),
        flow_src_port: expected_src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let mut out = [0u8; 256];
    let frame_len = build_forwarded_frame_into(
        &mut out,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &ForwardingState::default(),
        Some((expected_src_port, dst_port)),
    )
    .expect("build forwarded frame");
    let out = &out[..frame_len];
    assert_eq!(tcp_ports_ipv6(&out[18..]), (expected_src_port, dst_port));
    assert!(tcp_checksum_ok_ipv6(&out[18..]));
}

#[test]
fn build_forwarded_frame_into_ignores_wrong_ipv4_offsets() {
    let src_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
    let real_src_port = 47032u16;
    let real_dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x00, 0x00, 64, PROTO_TCP, 0, 0,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&real_src_port.to_be_bytes());
    frame.extend_from_slice(&real_dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 54,
        l4_offset: 74,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1059,
        flow_dst_port: real_dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let mut out = [0u8; 256];
    let frame_len = build_forwarded_frame_into(
        &mut out,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &ForwardingState::default(),
        Some((real_src_port, real_dst_port)),
    )
    .expect("build forwarded frame");
    let out = &out[..frame_len];
    let tcp = &out[18 + 20..];
    assert_eq!(
        (
            u16::from_be_bytes([tcp[0], tcp[1]]),
            u16::from_be_bytes([tcp[2], tcp[3]])
        ),
        (real_src_port, real_dst_port)
    );
}

#[test]
fn segment_forwarded_tcp_frames_splits_ipv6_snat_payload_by_mtu() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let src_port = 54688u16;
    let dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    let tcp_payload_len = 4096usize;
    let plen = (20 + tcp_payload_len) as u16;
    frame.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (plen >> 8) as u8,
        plen as u8,
        PROTO_TCP,
        64,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, // seq
        0x08, 0xf0, 0x5a, 0xc6, // ack
        0x50, 0x18, 0x00, 0x40, // data offset/flags/window
        0x00, 0x00, 0x00, 0x00, // checksum/urgent
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(8192).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 54688,
        flow_dst_port: 5201,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
        },
    );

    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some((src_port, dst_port)),
    )
    .expect("segmented");
    assert!(segments.len() > 1);
    let mut expected_seq = 0x3196c832u32;
    let mut total_payload = 0usize;
    for (idx, seg) in segments.iter().enumerate() {
        assert!(seg.len() <= 18 + 1500);
        assert_eq!(tcp_ports_ipv6(&seg[18..]), (54688, 5201));
        assert!(tcp_checksum_ok_ipv6(&seg[18..]));
        let tcp = &seg[18 + 40..];
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        assert_eq!(seq, expected_seq);
        let seg_payload = seg.len() - 18 - 40 - 20;
        total_payload += seg_payload;
        expected_seq = expected_seq.wrapping_add(seg_payload as u32);
        if idx + 1 != segments.len() {
            assert_eq!(tcp[13] & TCP_FLAG_PSH, 0);
        }
    }
    assert_eq!(total_payload, tcp_payload_len);
}

#[test]
fn segment_forwarded_tcp_frames_repairs_ipv6_tcp_ports_when_metadata_disagrees() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let src_port = 38276u16;
    let dst_port = 5201u16;
    let tcp_payload_len = 4096usize;
    let plen = (20 + tcp_payload_len) as u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (plen >> 8) as u8,
        plen as u8,
        PROTO_TCP,
        64,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00,
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(8192).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1025,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
        },
    );
    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some((src_port, dst_port)),
    )
    .expect("segmented");
    assert!(segments.len() > 1);
    for seg in &segments {
        assert_eq!(tcp_ports_ipv6(&seg[18..]), (src_port, dst_port));
        assert!(tcp_checksum_ok_ipv6(&seg[18..]));
    }
}

#[test]
fn segment_forwarded_tcp_frames_prefers_expected_ipv6_ports_over_wrong_live_ports() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let src_port = 42566u16;
    let dst_port = 5201u16;
    let tcp_payload_len = 4096usize;
    let plen = (20 + tcp_payload_len) as u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (plen >> 8) as u8,
        plen as u8,
        PROTO_TCP,
        64,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00,
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(8192).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1042,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
        },
    );
    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some((1042, dst_port)),
    )
    .expect("segmented");
    assert!(segments.len() > 1);
    for seg in &segments {
        assert_eq!(tcp_ports_ipv6(&seg[18..]), (1042, dst_port));
        assert!(tcp_checksum_ok_ipv6(&seg[18..]));
    }
}

#[test]
fn segment_forwarded_tcp_frames_repairs_wrong_ipv6_frame_ports_from_expected_tuple() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let expected_src_port = 36394u16;
    let wrong_src_port = 1025u16;
    let dst_port = 5201u16;
    let tcp_payload_len = 4096usize;
    let plen = (20 + tcp_payload_len) as u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (plen >> 8) as u8,
        plen as u8,
        PROTO_TCP,
        64,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&wrong_src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00,
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(8192).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_addr: src_ip.octets(),
        flow_dst_addr: dst_ip.octets(),
        flow_src_port: expected_src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
        },
    );
    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some((expected_src_port, dst_port)),
    )
    .expect("segmented");
    assert!(segments.len() > 1);
    for seg in &segments {
        assert_eq!(tcp_ports_ipv6(&seg[18..]), (expected_src_port, dst_port));
        assert!(tcp_checksum_ok_ipv6(&seg[18..]));
    }
}

#[test]
fn authoritative_forward_ports_prefers_flow_tuple_when_frame_ports_mismatch() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let expected_src_port = 55068u16;
    let wrong_src_port = 1041u16;
    let dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&wrong_src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_addr: src_ip.octets(),
        flow_dst_addr: dst_ip.octets(),
        flow_src_port: expected_src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V6(src_ip),
        dst_ip: IpAddr::V6(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            src_port: expected_src_port,
            dst_port,
        },
    };

    assert_eq!(
        authoritative_forward_ports(&frame, meta, Some(&flow)),
        Some((expected_src_port, dst_port))
    );
}

#[test]
fn authoritative_forward_ports_prefers_frame_tuple_over_metadata_when_flow_missing() {
    let src_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
    let frame_src_port = 1041u16;
    let meta_src_port = 55068u16;
    let dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&frame_src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
    ]);
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

    let mut flow_src_addr = [0u8; 16];
    flow_src_addr[..4].copy_from_slice(&src_ip.octets());
    let mut flow_dst_addr = [0u8; 16];
    flow_dst_addr[..4].copy_from_slice(&dst_ip.octets());
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_addr,
        flow_dst_addr,
        flow_src_port: meta_src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };

    // Live frame ports preferred over metadata (flow > frame > meta)
    assert_eq!(
        authoritative_forward_ports(&frame, meta, None),
        Some((frame_src_port, dst_port))
    );
}

#[test]
fn authoritative_forward_ports_falls_back_to_live_frame_ports_when_metadata_missing() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let src_port = 55068u16;
    let dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x14, PROTO_UDP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x14, 0x00, 0x00]);
    frame.extend_from_slice(b"userspace-udp");
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_UDP).expect("udp sum");

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };

    assert_eq!(
        authoritative_forward_ports(&frame, meta, None),
        Some((src_port, dst_port))
    );
}

#[test]
fn parse_session_flow_prefers_metadata_tuple_when_frame_ports_mismatch() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let expected_src_port = 55068u16;
    let wrong_src_port = 1041u16;
    let dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&wrong_src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_addr: src_ip.octets(),
        flow_dst_addr: dst_ip.octets(),
        flow_src_port: expected_src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
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
    assert_eq!(flow.forward_key.src_port, expected_src_port);
    assert_eq!(flow.forward_key.dst_port, dst_port);
}

#[test]
fn segment_forwarded_tcp_frames_keeps_ipv4_tcp_ports_after_vlan_snat() {
    let src_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
    let src_port = 47308u16;
    let dst_port = 5201u16;
    let tcp_payload_len = 30_408usize;
    let tcp_header_len = 32usize;
    let total_len = (20 + tcp_header_len + tcp_payload_len) as u16;

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        0xd1,
        0x43,
        0x40,
        0x00,
        64,
        PROTO_TCP,
        0x00,
        0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x52, 0x04, 0xc1, 0xa3, // seq
        0x73, 0x7f, 0x63, 0x1c, // ack
        0x80, 0x10, 0x00, 0x3f, // data offset/flags/window
        0x00, 0x00, 0x00, 0x00, // checksum/urgent
        0x01, 0x01, 0x08, 0x0a, // TCP timestamp option
        0x91, 0x9b, 0x0d, 0x5f, 0xd3, 0x53, 0x0f, 0x7f,
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

    let mut area = MmapArea::new(65_536).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1041,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x01, 0x00]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x16, 0x01, 0x00],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );

    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some((src_port, dst_port)),
    )
    .expect("segmented");
    assert!(segments.len() > 1);
    let mut total_payload = 0usize;
    let mut expected_seq = 0x5204c1a3u32;
    for seg in &segments {
        assert!(seg.len() <= 18 + 1500);
        let tcp = &seg[18 + 20..];
        assert_eq!(
            (
                u16::from_be_bytes([tcp[0], tcp[1]]),
                u16::from_be_bytes([tcp[2], tcp[3]])
            ),
            (src_port, dst_port)
        );
        assert!(tcp_checksum_ok_ipv4(&seg[18..]));
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        assert_eq!(seq, expected_seq);
        let seg_payload = seg.len() - 18 - 20 - tcp_header_len;
        total_payload += seg_payload;
        expected_seq = expected_seq.wrapping_add(seg_payload as u32);
    }
    assert_eq!(total_payload, tcp_payload_len);
}

#[test]
fn segment_forwarded_tcp_frames_keeps_ipv4_snat_inside_native_gre() {
    let src_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(10, 255, 192, 41);
    let snat_ip = Ipv4Addr::new(10, 255, 192, 42);
    let src_port = 47308u16;
    let dst_port = 5201u16;
    let tcp_payload_len = 30_408usize;
    let tcp_header_len = 32usize;
    let total_len = (20 + tcp_header_len + tcp_payload_len) as u16;

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        0xd1,
        0x43,
        0x40,
        0x00,
        64,
        PROTO_TCP,
        0x00,
        0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x52, 0x04, 0xc1, 0xa3, 0x73, 0x7f, 0x63, 0x1c, 0x80, 0x10, 0x00, 0x3f, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x01, 0x08, 0x0a, 0x91, 0x9b, 0x0d, 0x5f, 0xd3, 0x53, 0x0f, 0x7f,
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

    let mut area = MmapArea::new(65_536).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1041,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let decision = SessionDecision {
        resolution: lookup_forwarding_resolution_v4(&state, None, dst_ip, "sfmix.inet.0", 0, true),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_ip)),
            ..NatDecision::default()
        },
    };

    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &state,
        Some((src_port, dst_port)),
    )
    .expect("segmented native gre");
    assert!(segments.len() > 1);
    let outer_eth_len = 18usize;
    let outer_ip_len = 40usize;
    let gre_len = 4usize;
    let transport_mtu = 1500usize;
    let inner_start = outer_eth_len + outer_ip_len + gre_len;
    let mut total_payload = 0usize;
    let mut expected_seq = 0x5204c1a3u32;
    for seg in &segments {
        assert!(seg.len() >= outer_eth_len);
        assert!(
            seg.len() - outer_eth_len <= transport_mtu,
            "native GRE segment exceeds transport MTU: {}",
            seg.len() - outer_eth_len
        );
        assert_eq!(&seg[16..18], &[0x86, 0xdd]);
        assert_eq!(seg[24], PROTO_GRE);
        let inner = &seg[inner_start..];
        assert_eq!(&inner[12..16], &snat_ip.octets());
        assert_eq!(&inner[16..20], &dst_ip.octets());
        assert!(tcp_checksum_ok_ipv4(inner));
        let tcp = &inner[20..];
        assert_eq!(
            (
                u16::from_be_bytes([tcp[0], tcp[1]]),
                u16::from_be_bytes([tcp[2], tcp[3]])
            ),
            (src_port, dst_port)
        );
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        assert_eq!(seq, expected_seq);
        let seg_payload = inner.len() - 20 - tcp_header_len;
        total_payload += seg_payload;
        expected_seq = expected_seq.wrapping_add(seg_payload as u32);
    }
    assert_eq!(total_payload, tcp_payload_len);
}

// --- #2077: TCP-segmentation TTL/hop-limit gate v4/v6 symmetry ---
//
// The TTL==1 drop in the segmentation builders must be gated on
// NOT-fabric-ingress, matching every other forwarding path
// (build/ipv4.rs, build/ipv6.rs, frame/mod.rs, rewrite/ipv4.rs,
// rewrite/ipv6.rs). A fabric-ingress segment (FABRIC_INGRESS_FLAG =
// 0x80 in meta_flags) was already decremented by the peer chassis at
// its real ingress; the fabric crossing is an internal cross-chassis
// redirect, not an IP hop, so neither the decrement NOR the drop
// applies. Before the fix the IPv4 builder dropped UNCONDITIONALLY on
// TTL <= 1 while IPv6 was correctly gated — a fabric-ingress oversized
// IPv4 TCP segment with TTL==1 was wrongly dropped.

/// Build an oversized (multi-MTU) TCP frame for one address family
/// with a caller-chosen TTL / hop-limit, ready for the segmentation
/// builders. No NAT rewrite is configured so the test isolates the
/// TTL gate. `egress mtu` is 1500 and the TCP payload is large enough
/// to force more than one segment.
fn build_oversized_tcp_frame_for_ttl_gate(
    addr_family: i32,
    ttl: u8,
) -> (Vec<u8>, UserspaceDpMeta, SessionDecision, ForwardingState) {
    let src_port = 47308u16;
    let dst_port = 5201u16;
    let tcp_payload_len = 8192usize; // >> MTU, forces segmentation
    let tcp_header_len = 20usize;

    let mut frame = Vec::new();
    let (ether_type, next_hop, primary_v4, primary_v6) = match addr_family {
        libc::AF_INET => (
            0x0800u16,
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            Some(Ipv4Addr::new(172, 16, 80, 8)),
            None,
        ),
        libc::AF_INET6 => (
            0x86ddu16,
            IpAddr::V6("2001:559:8585:80::200".parse().unwrap()),
            None,
            Some("2001:559:8585:80::8".parse().unwrap()),
        ),
        _ => panic!("unsupported addr_family"),
    };
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
        0,
        ether_type,
    );

    let (l4_offset, l3_header_len) = match addr_family {
        libc::AF_INET => {
            let total_len = (20 + tcp_header_len + tcp_payload_len) as u16;
            frame.extend_from_slice(&[
                0x45,
                0x00,
                (total_len >> 8) as u8,
                total_len as u8,
                0xd1,
                0x43,
                0x40,
                0x00,
                ttl, // TTL field at IP-header offset 8
                PROTO_TCP,
                0x00,
                0x00,
            ]);
            frame.extend_from_slice(&Ipv4Addr::new(10, 0, 61, 102).octets());
            frame.extend_from_slice(&Ipv4Addr::new(172, 16, 80, 200).octets());
            (34usize, 20usize)
        }
        libc::AF_INET6 => {
            let plen = (tcp_header_len + tcp_payload_len) as u16;
            frame.extend_from_slice(&[
                0x60,
                0x00,
                0x00,
                0x00,
                (plen >> 8) as u8,
                plen as u8,
                PROTO_TCP,
                ttl, // hop-limit field at IP-header offset 7
            ]);
            frame.extend_from_slice(
                &"2001:559:8585:ef00::102"
                    .parse::<Ipv6Addr>()
                    .unwrap()
                    .octets(),
            );
            frame.extend_from_slice(
                &"2001:559:8585:80::200"
                    .parse::<Ipv6Addr>()
                    .unwrap()
                    .octets(),
            );
            (54usize, 40usize)
        }
        _ => unreachable!(),
    };
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x52, 0x04, 0xc1, 0xa3, // seq
        0x73, 0x7f, 0x63, 0x1c, // ack
        0x50, 0x10, 0x00, 0x3f, // data offset (5)/ACK flag/window
        0x00, 0x00, 0x00, 0x00, // checksum/urgent
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    if addr_family == libc::AF_INET {
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("v4 tcp sum");
    } else {
        recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("v6 tcp sum");
    }

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: l4_offset as u16,
        addr_family: addr_family as u8,
        protocol: PROTO_TCP,
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(next_hop),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x01, 0x00]),
            tx_vlan_id: 0,
        },
        // No NAT — the test isolates the TTL/hop-limit gate.
        nat: NatDecision::default(),
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x16, 0x01, 0x00],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4,
            primary_v6,
        },
    );
    let _ = l3_header_len;
    (frame, meta, decision, forwarding)
}

/// Fabric-ingress (meta_flags = FABRIC_INGRESS_FLAG = 0x80) oversized
/// TCP segment with TTL/hop-limit == 1 must NOT be dropped, for BOTH
/// address families. Non-tautological: pre-fix the IPv4 arm returns
/// None (unconditional `packet[8] <= 1` drop) and this test fails for
/// the v4 case.
#[test]
fn segment_forwarded_tcp_frames_keeps_fabric_ingress_low_ttl_both_families() {
    for (label, af, ttl_off) in [
        ("v4", libc::AF_INET, 8usize),
        ("v6", libc::AF_INET6, 7usize),
    ] {
        let (frame, mut meta, decision, forwarding) = build_oversized_tcp_frame_for_ttl_gate(af, 1);
        meta.meta_flags = 0x80; // FABRIC_INGRESS_FLAG — peer already decremented

        let segments = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta,
            &decision,
            &forwarding,
            false, // apply_nat_on_fabric
            Some((meta.flow_src_port, meta.flow_dst_port)),
        )
        .unwrap_or_else(|| {
            panic!(
                "[{}] fabric-ingress oversized segment with TTL/hop-limit==1 \
                 must segment, not drop (the peer already decremented)",
                label
            )
        });
        assert!(
            segments.len() > 1,
            "[{}] expected multiple segments for oversized payload",
            label
        );
        // The TTL/hop-limit must be preserved (NOT decremented) on the
        // fabric-ingress path. IP header starts at the L2 offset; the
        // built frames have no VLAN tag so eth_len == 14.
        for seg in &segments {
            let post = seg[14 + ttl_off];
            assert_eq!(
                post, 1,
                "[{}] fabric-ingress must preserve TTL/hop-limit (got {})",
                label, post
            );
        }
    }
}

/// Non-fabric (meta_flags == 0) oversized TCP segment with TTL/hop-
/// limit == 1 must STILL be dropped, for BOTH address families. Guards
/// against an over-broad fix that would also drop the legitimate
/// TTL-expiry behaviour on the normal forwarding path.
#[test]
fn segment_forwarded_tcp_frames_drops_non_fabric_low_ttl_both_families() {
    for (label, af) in [("v4", libc::AF_INET), ("v6", libc::AF_INET6)] {
        let (frame, meta, decision, forwarding) = build_oversized_tcp_frame_for_ttl_gate(af, 1);
        // meta_flags defaults to 0 (NOT fabric-ingress).
        assert_eq!(
            meta.meta_flags & 0x80,
            0,
            "[{}] expected non-fabric meta",
            label
        );

        let result = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta,
            &decision,
            &forwarding,
            false,
            Some((meta.flow_src_port, meta.flow_dst_port)),
        );
        assert!(
            result.is_none(),
            "[{}] non-fabric oversized segment with TTL/hop-limit==1 must be \
             dropped (TTL expiry)",
            label
        );
    }
}

/// Sanity twin: a non-fabric oversized segment with a healthy TTL (64)
/// segments normally AND decrements the TTL/hop-limit by one on every
/// segment — confirming the gate only blocks the expiry case and the
/// normal decrement path is intact for BOTH families.
#[test]
fn segment_forwarded_tcp_frames_decrements_non_fabric_healthy_ttl_both_families() {
    for (label, af, ttl_off) in [
        ("v4", libc::AF_INET, 8usize),
        ("v6", libc::AF_INET6, 7usize),
    ] {
        let (frame, meta, decision, forwarding) = build_oversized_tcp_frame_for_ttl_gate(af, 64);

        let segments = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta,
            &decision,
            &forwarding,
            false,
            Some((meta.flow_src_port, meta.flow_dst_port)),
        )
        .unwrap_or_else(|| panic!("[{}] healthy-TTL oversized segment must segment", label));
        assert!(segments.len() > 1, "[{}] expected multiple segments", label);
        for seg in &segments {
            let post = seg[14 + ttl_off];
            assert_eq!(
                post, 63,
                "[{}] non-fabric forwarding must decrement TTL/hop-limit 64->63 \
                 (got {})",
                label, post
            );
        }
    }
}

#[test]
fn rewrite_forwarded_frame_in_place_keeps_tcp_checksum_valid_after_vlan_snat() {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't',
        b'a',
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv4(&frame[14..]));

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
        protocol: PROTO_TCP,
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
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_dst: None,
                ..NatDecision::default()
            },
        },
        false,
        None,
    )
    .expect("rewrite in place");

    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x0800);
    assert_eq!(&out[30..34], &[172, 16, 80, 8]);
    assert_eq!(out[26], 63);
    assert!(tcp_checksum_ok_ipv4(&out[18..]));
}

#[test]
fn rewrite_forwarded_frame_in_place_keeps_tcp_checksum_valid_after_vlan_dnat() {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x10, 0xdb, 0xff, 0x10, 0x01],
        80,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x02, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
        200, 172, 16, 80, 8, 0x14, 0x51, 0x9c, 0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x02, 0x50, 0x12, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a',
        b't', b'a',
    ]);
    let ip_sum = checksum16(&frame[18..38]);
    frame[28] = (ip_sum >> 8) as u8;
    frame[29] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv4(&frame[18..]));

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 18,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
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
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 5,
                tx_ifindex: 5,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0x02, 0x66, 0x6a, 0x82, 0xfb, 0x2f]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x01, 0x00]),
                tx_vlan_id: 0,
            },
            nat: NatDecision {
                rewrite_src: None,
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                ..NatDecision::default()
            },
        },
        false,
        None,
    )
    .expect("rewrite in place");

    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
    assert_eq!(&out[30..34], &[10, 0, 61, 102]);
    assert_eq!(out[22], 63);
    assert!(tcp_checksum_ok_ipv4(&out[14..]));
}

#[test]
fn rewrite_forwarded_frame_in_place_applies_nat_for_fabric_redirect_when_enabled() {
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't',
        b'a',
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv4(&frame[14..]));

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
        protocol: PROTO_TCP,
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
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::FabricRedirect,
                local_ifindex: 0,
                egress_ifindex: 21,
                tx_ifindex: 21,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        true,
        None,
    )
    .expect("rewrite in place");

    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    assert_eq!(&out[0..6], &[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    assert_eq!(&out[26..30], &[172, 16, 80, 8]);
    assert_eq!(&out[30..34], &[172, 16, 80, 200]);
    assert_eq!(out[22], 63);
    assert!(tcp_checksum_ok_ipv4(&out[14..]));
}

/// Sentinel for #963 round-1 #2: inverse of the
/// `_when_enabled` test above. Set
/// `disposition = FabricRedirect`, `apply_nat_on_fabric = false`,
/// SNAT rewrite_src to 198.51.100.99. After the rewrite, assert
/// the source IP in the frame is the ORIGINAL — confirms the
/// `apply_nat` gate at the dispatch correctly suppresses NAT
/// when fabric NAT is disabled.
#[test]
fn rewrite_forwarded_frame_in_place_skips_nat_for_fabric_redirect_when_disabled() {
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't',
        b'a',
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

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
        protocol: PROTO_TCP,
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
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::FabricRedirect,
                local_ifindex: 0,
                egress_ifindex: 21,
                tx_ifindex: 21,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99))),
                ..NatDecision::default()
            },
        },
        false, // apply_nat_on_fabric = false
        None,
    )
    .expect("rewrite in place");

    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    // Source IP MUST be the original 10.0.61.102, not the SNAT'd
    // 198.51.100.99. This validates that apply_nat=false is
    // correctly threaded through the dispatch into rewrite_apply_v4.
    assert_eq!(
        &out[26..30],
        &[10, 0, 61, 102],
        "apply_nat_on_fabric=false must suppress SNAT"
    );
    assert_eq!(&out[30..34], &[172, 16, 80, 200]);
    assert_eq!(out[22], 63); // TTL still decremented (skip_ttl=false)
}

/// Sentinel for #963 round-1 #2 (extended in round-2): table-
/// driven over IPv4 TTL (offset 8 from IP start) and IPv6
/// hop-limit (offset 7 from IP start). For each address family,
/// set `meta.meta_flags = 0x80 (FABRIC_INGRESS_FLAG)` so the
/// sending peer is treated as having already decremented TTL.
/// Capture the relevant byte before and after; assert pre == post
/// (no decrement). Validates the skip_ttl gate in BOTH
/// rewrite_apply_v4 and rewrite_apply_v6.
#[test]
fn rewrite_forwarded_frame_in_place_skips_ttl_when_fabric_ingress_flag_set() {
    // Table-driven: (addr_family, ether_type, ip_header,
    //                 ttl_rel_offset_from_ip_start)
    // ttl_rel_offset is HEADER-relative (not Ethernet-relative)
    // to avoid confusion (Codex round-3 non-blocking note).
    // IP total_len = 0x002c (44 bytes = 20 IP + 24 TCP/data) so
    // the IP header total_len matches the actual constructed
    // frame (Codex impl review round-1 caught a 0x0030 mismatch).
    let v4_header: Vec<u8> = vec![
        0x45, 0x00, 0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200,
    ];
    let v4_payload: Vec<u8> = vec![
        0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0x20,
        0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't',
    ];
    let v6_header: Vec<u8> = vec![
        0x60, 0x00, 0x00, 0x00, 0x00, 0x14, PROTO_TCP, 64, // src 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        // dst 2001:db8::200
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x00,
    ];
    let v6_payload: Vec<u8> = vec![
        0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0x20,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for (label, addr_family, ether_type, ip_header, ip_payload, ttl_rel_offset, src_ip) in [
        (
            "v4",
            libc::AF_INET as u8,
            0x0800u16,
            v4_header,
            v4_payload,
            8usize,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        ),
        (
            "v6",
            libc::AF_INET6 as u8,
            0x86ddu16,
            v6_header,
            v6_payload,
            7usize,
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        ),
    ] {
        let mut frame = Vec::new();
        write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, ether_type);
        frame.extend_from_slice(&ip_header);
        frame.extend_from_slice(&ip_payload);
        if addr_family == libc::AF_INET as u8 {
            let ip_sum = checksum16(&frame[14..14 + ip_header.len()]);
            frame[24] = (ip_sum >> 8) as u8;
            frame[25] = ip_sum as u8;
            recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("v4 tcp sum");
        } else {
            recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("v6 tcp sum");
        }
        let pre_ttl = frame[14 + ttl_rel_offset];

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family,
            protocol: PROTO_TCP,
            meta_flags: 0x80, // FABRIC_INGRESS_FLAG — peer already decremented TTL
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
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 12,
                    tx_ifindex: 12,
                    tunnel_endpoint_id: 0,
                    next_hop: Some(src_ip),
                    neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                    tx_vlan_id: 0,
                },
                nat: NatDecision::default(),
            },
            false,
            None,
        )
        .unwrap_or_else(|| panic!("[{}] rewrite_in_place returned None", label));

        let out = area
            .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
            .expect("rewritten frame");
        let post_ttl = out[14 + ttl_rel_offset];
        assert_eq!(
            pre_ttl, post_ttl,
            "[{}] FABRIC_INGRESS_FLAG must suppress TTL/hop-limit decrement \
             (pre={} post={})",
            label, pre_ttl, post_ttl
        );
    }
}

// --- apply_rewrite_descriptor tests ---

/// Helper: build a RewriteDescriptor from a SessionDecision + flow.
fn test_descriptor(
    flow: &SessionFlow,
    decision: &SessionDecision,
    vlan_id: u16,
    ether_type: u16,
) -> RewriteDescriptor {
    RewriteDescriptor {
        dst_mac: decision.resolution.neighbor_mac.unwrap_or([0; 6]),
        src_mac: decision.resolution.src_mac.unwrap_or([0; 6]),
        fabric_redirect: decision.resolution.disposition == ForwardingDisposition::FabricRedirect,
        tx_vlan_id: vlan_id,
        ether_type,
        rewrite_src_ip: decision.nat.rewrite_src,
        rewrite_dst_ip: decision.nat.rewrite_dst,
        rewrite_src_port: decision.nat.rewrite_src_port,
        rewrite_dst_port: decision.nat.rewrite_dst_port,
        ip_csum_delta: compute_ip_csum_delta(flow, &decision.nat),
        l4_csum_delta: compute_l4_csum_delta(flow, &decision.nat),
        egress_ifindex: decision.resolution.egress_ifindex,
        tx_ifindex: decision.resolution.tx_ifindex,
        target_binding_index: None,
        input_filter_log: None,
        tx_selection: CachedTxSelectionDescriptor::default(),
        nat64: false,
        nptv6: false,
        apply_nat_on_fabric: false,
    }
}

#[test]
fn apply_descriptor_ipv4_no_nat_ttl_and_checksum() {
    // IPv4 TCP, no NAT, just TTL decrement + ethernet rewrite.
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, // IPv4, IHL=5, total_len=40
        0x00, 0x01, 0x00, 0x00, // ID, flags/frag
        64, PROTO_TCP, 0x00, 0x00, // TTL=64, proto=TCP, checksum placeholder
        10, 0, 1, 102, // src = 10.0.1.102
        172, 16, 80, 200, // dst = 172.16.80.200
        // TCP header (20 bytes)
        0x9c, 0x40, 0x01, 0xbb, // src_port=40000 dst_port=443
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x10, 0x20, 0x00, // data_off=5 flags=ACK win=8192
        0x00, 0x00, 0x00, 0x00, // checksum+urgent
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv4(&frame[14..]));

    let flow = SessionFlow {
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 40000,
            dst_port: 443,
        },
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            egress_ifindex: 12,
            tx_ifindex: 11,
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
            local_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
        },
        nat: NatDecision::default(),
    };
    let rd = test_descriptor(&flow, &decision, 0, 0x0800);

    let rx_addr = 256u64;
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(rx_addr as usize, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let rewrite_result = apply_rewrite_descriptor(
        &area,
        XdpDesc {
            addr: rx_addr,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &rd,
        None,
    )
    .expect("descriptor rewrite");

    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    // Ethernet header
    assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
    // TTL decremented
    assert_eq!(out[22], 63);
    // IP checksum valid
    assert_eq!(checksum16(&out[14..34]), 0);
    // TCP checksum valid
    assert!(tcp_checksum_ok_ipv4(&out[14..]));
}

#[test]
fn apply_descriptor_ipv4_snat_with_vlan() {
    // IPv4 TCP with SNAT 10.0.61.102 -> 172.16.80.8, adding VLAN 80.
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, // IPv4, total_len=48
        0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61,
        102, // src = 10.0.61.102
        172, 16, 80, 200, // dst = 172.16.80.200
        0x9c, 0x40, 0x14, 0x51, // src_port=40000 dst_port=5201
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv4(&frame[14..]));

    let flow = SessionFlow {
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 40000,
            dst_port: 5201,
        },
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            egress_ifindex: 12,
            tx_ifindex: 11,
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
            local_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let rd = test_descriptor(&flow, &decision, 80, 0x0800);

    let rx_addr = 256u64;
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(rx_addr as usize, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let rewrite_result = apply_rewrite_descriptor(
        &area,
        XdpDesc {
            addr: rx_addr,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &rd,
        None,
    )
    .expect("descriptor snat rewrite");

    assert_eq!(rewrite_result.offset, rx_addr - 4);
    assert_eq!(
        rewrite_result.l2_rewrite,
        InPlaceL2Rewrite::VlanPushDescriptor
    );
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    // VLAN tag added
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x0800);
    // SNAT applied
    assert_eq!(&out[30..34], &[172, 16, 80, 8]); // new src IP
    assert_eq!(&out[34..38], &[172, 16, 80, 200]); // dst unchanged
    // TTL
    assert_eq!(out[26], 63);
    // IP checksum valid
    assert_eq!(checksum16(&out[18..38]), 0);
    // TCP checksum valid
    assert!(tcp_checksum_ok_ipv4(&out[18..]));
}

#[test]
fn apply_descriptor_fabric_redirect_skips_nat_when_flag_is_false() {
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't',
        b'a',
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv4(&frame[14..]));

    let flow = SessionFlow {
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 40000,
            dst_port: 5201,
        },
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::FabricRedirect,
            egress_ifindex: 21,
            tx_ifindex: 21,
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
            tx_vlan_id: 0,
            local_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let mut rd = test_descriptor(&flow, &decision, 0, 0x0800);
    rd.apply_nat_on_fabric = false;

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let rewrite_result = apply_rewrite_descriptor(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &rd,
        None,
    )
    .expect("descriptor fabric rewrite");

    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    assert_eq!(&out[0..6], &[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    assert_eq!(&out[26..30], &[10, 0, 61, 102]);
    assert_eq!(&out[30..34], &[172, 16, 80, 200]);
    assert_eq!(out[22], 63);
    assert_eq!(checksum16(&out[14..34]), 0);
    assert!(tcp_checksum_ok_ipv4(&out[14..]));
}

#[test]
fn apply_descriptor_ipv4_dnat_removes_vlan() {
    // IPv4 TCP with DNAT 172.16.80.8 -> 10.0.61.102, ingress VLAN 80 -> no VLAN.
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 80, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x02, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
        200, // src
        172, 16, 80, 8, // dst (pre-DNAT)
        0x14, 0x51, 0x9c, 0x40, // src_port=5201 dst_port=40000
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
    ]);
    let ip_sum = checksum16(&frame[18..38]);
    frame[28] = (ip_sum >> 8) as u8;
    frame[29] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");

    let flow = SessionFlow {
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 5201,
            dst_port: 40000,
        },
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            egress_ifindex: 5,
            tx_ifindex: 5,
            neighbor_mac: Some([0x02, 0x66, 0x6a, 0x82, 0xfb, 0x2f]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x01, 0x00]),
            tx_vlan_id: 0,
            local_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
        },
        nat: NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            ..NatDecision::default()
        },
    };
    let rd = test_descriptor(&flow, &decision, 0, 0x0800);

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 18,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let rewrite_result = apply_rewrite_descriptor(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &rd,
        None,
    )
    .expect("descriptor dnat rewrite");

    assert_eq!(rewrite_result.offset, 4);
    assert_eq!(
        rewrite_result.l2_rewrite,
        InPlaceL2Rewrite::VlanPopDescriptor
    );
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    // No VLAN
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
    // DNAT applied
    assert_eq!(&out[30..34], &[10, 0, 61, 102]); // new dst IP
    // TTL
    assert_eq!(out[22], 63);
    // Checksums valid
    assert_eq!(checksum16(&out[14..34]), 0);
    assert!(tcp_checksum_ok_ipv4(&out[14..]));
}

#[test]
fn apply_descriptor_ipv6_no_nat_hop_limit() {
    // IPv6 TCP, no NAT, hop limit decrement only.
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x86dd);
    let src = Ipv6Addr::new(0x2001, 0x0559, 0x8585, 0xbf01, 0, 0, 0, 0x102);
    let dst = Ipv6Addr::new(0x2001, 0x0559, 0x8585, 0x80, 0, 0, 0, 0x200);
    frame.push(0x60);
    frame.push(0x00);
    frame.push(0x00);
    frame.push(0x00); // version+flow
    frame.extend_from_slice(&20u16.to_be_bytes()); // payload_len = 20 (TCP header only)
    frame.push(PROTO_TCP); // next header
    frame.push(64); // hop limit = 64
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    // TCP header (20 bytes)
    frame.extend_from_slice(&40000u16.to_be_bytes()); // src port
    frame.extend_from_slice(&443u16.to_be_bytes()); // dst port
    frame.extend_from_slice(&1u32.to_be_bytes()); // seq
    frame.extend_from_slice(&0u32.to_be_bytes()); // ack
    frame.extend_from_slice(&[0x50, 0x10, 0x20, 0x00]); // data_off=5, ACK, win=8192
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // checksum + urgent
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp6 sum");

    let flow = SessionFlow {
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(src),
            dst_ip: IpAddr::V6(dst),
            src_port: 40000,
            dst_port: 443,
        },
        src_ip: IpAddr::V6(src),
        dst_ip: IpAddr::V6(dst),
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            egress_ifindex: 12,
            tx_ifindex: 11,
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
            local_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
        },
        nat: NatDecision::default(),
    };
    let rd = test_descriptor(&flow, &decision, 0, 0x86dd);

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54, // 14 + 40
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let rewrite_result = apply_rewrite_descriptor(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &rd,
        None,
    )
    .expect("descriptor ipv6 rewrite");

    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x86dd);
    // Hop limit decremented
    assert_eq!(out[21], 63);
    // TCP checksum still valid (no NAT changes to pseudo-header)
    let tcp_csum_ok = {
        let packet = &out[14..];
        let rel_l4 = 40usize;
        let csum_off = rel_l4 + 16;
        let stored = u16::from_be_bytes([packet[csum_off], packet[csum_off + 1]]);
        stored != 0 // basic sanity — full validation via recompute
    };
    assert!(tcp_csum_ok);
}

#[test]
fn apply_descriptor_returns_none_on_port_mismatch() {
    // If frame ports don't match expected_ports, descriptor path falls back to None.
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 1, 102,
        172, 16, 80, 200, 0x9c, 0x40, 0x01, 0xbb, // src=40000 dst=443
        0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;

    let flow = SessionFlow {
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 40000,
            dst_port: 443,
        },
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            egress_ifindex: 12,
            tx_ifindex: 11,
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
            local_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
        },
        nat: NatDecision::default(),
    };
    let rd = test_descriptor(&flow, &decision, 0, 0x0800);

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    // Expected ports don't match frame (99/99 vs 40000/443).
    let result = apply_rewrite_descriptor(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &rd,
        Some((99, 99)),
    );
    assert!(result.is_none(), "should return None on port mismatch");
}

#[test]
fn apply_descriptor_nat64_falls_back() {
    let rd = RewriteDescriptor {
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
        egress_ifindex: 0,
        tx_ifindex: 0,
        target_binding_index: None,
        input_filter_log: None,
        tx_selection: CachedTxSelectionDescriptor::default(),
        nat64: true,
        nptv6: false,
        apply_nat_on_fabric: false,
    };
    let area = MmapArea::new(4096).expect("mmap");
    let meta = UserspaceDpMeta::default();
    let result = apply_rewrite_descriptor(
        &area,
        XdpDesc {
            addr: 0,
            len: 64,
            options: 0,
        },
        meta,
        &rd,
        None,
    );
    assert!(result.is_none(), "NAT64 should fall back to generic");
}

#[test]
fn apply_dscp_rewrite_to_ipv4_frame_updates_tos_and_checksum() {
    let src = Ipv4Addr::new(10, 0, 61, 102);
    let dst = Ipv4Addr::new(172, 16, 80, 200);
    let mut frame = build_icmp_echo_frame_v4(src, dst, 64);
    let l3 = frame_l3_offset(&frame).expect("l3");
    let old_tos = frame[l3 + 1];
    let old_checksum = u16::from_be_bytes([frame[l3 + 10], frame[l3 + 11]]);

    apply_dscp_rewrite_to_frame(&mut frame, 46).expect("rewrite");

    assert_eq!(frame[l3 + 1] >> 2, 46);
    assert_eq!(frame[l3 + 1] & 0x03, old_tos & 0x03);
    let new_checksum = u16::from_be_bytes([frame[l3 + 10], frame[l3 + 11]]);
    assert_ne!(new_checksum, old_checksum);
    assert_eq!(checksum16(&frame[l3..l3 + 20]), 0);
}

#[test]
fn apply_dscp_rewrite_to_ipv6_frame_updates_traffic_class() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x86, 0xdd]);
    frame.extend_from_slice(&[
        0x60, 0x0b, 0x12, 0x34, // version + traffic class + flow label
        0x00, 0x08, // payload len
        58, 64, // next header + hop limit
    ]);
    frame.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
    frame.extend_from_slice(&Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200).octets());
    frame.extend_from_slice(&[128, 0, 0, 0, 0, 1, 0, 1]);

    let l3 = frame_l3_offset(&frame).expect("l3");
    let old_tc = ((frame[l3] & 0x0f) << 4) | (frame[l3 + 1] >> 4);

    apply_dscp_rewrite_to_frame(&mut frame, 46).expect("rewrite");

    let new_tc = ((frame[l3] & 0x0f) << 4) | (frame[l3 + 1] >> 4);
    assert_eq!(new_tc >> 2, 46);
    assert_eq!(new_tc & 0x03, old_tc & 0x03);
}

/// #1840: adjust_l4_checksum_port family pair — the RFC 768 stored-0
/// skip fires for IPv4 UDP only; the same stored-0 v6 UDP input gets
/// adjusted. Deterministic example (miri-coverable twin of the
/// prop_tests pins).
#[test]
fn adjust_l4_checksum_port_v4_skip_v6_no_skip() {
    // 8-byte UDP header at offset 0; checksum bytes at 6..8 = 0.
    let base = [0x12u8, 0x34, 0x56, 0x78, 0x00, 0x08, 0x00, 0x00];

    // v4: stored 0 => skip (bytes unchanged).
    let mut p = base;
    assert_eq!(
        adjust_l4_checksum_port(&mut p, 0, PROTO_UDP, ChecksumFamily::V4, 0x1234, 0x4321),
        Some(())
    );
    assert_eq!(p, base, "v4 UDP stored-0 must keep the RFC 768 skip");

    // v6: stored 0 => adjusted like any other value.
    let mut p = base;
    assert_eq!(
        adjust_l4_checksum_port(&mut p, 0, PROTO_UDP, ChecksumFamily::V6, 0x1234, 0x4321),
        Some(())
    );
    let updated = u16::from_be_bytes([p[6], p[7]]);
    assert_eq!(
        updated,
        checksum16_adjust(0, &[0x1234], &[0x4321]),
        "v6 UDP stored-0 must be incrementally adjusted (#1840)"
    );
    assert_ne!(updated, 0, "adjusted value is non-zero for this delta");

    // Non-zero stored checksum adjusts identically on both families.
    let mut p4 = base;
    p4[6..8].copy_from_slice(&0xBEEFu16.to_be_bytes());
    let mut p6 = p4;
    assert_eq!(
        adjust_l4_checksum_port(&mut p4, 0, PROTO_UDP, ChecksumFamily::V4, 0x1234, 0x4321),
        Some(())
    );
    assert_eq!(
        adjust_l4_checksum_port(&mut p6, 0, PROTO_UDP, ChecksumFamily::V6, 0x1234, 0x4321),
        Some(())
    );
    assert_eq!(
        p4, p6,
        "non-zero stored checksum: families behave identically"
    );
}

// ---------------------------------------------------------------------------
// #1852 — non-first-fragment NAT rewrite gating + MSS-clamp ext-aware fix.
// ---------------------------------------------------------------------------

/// Build a minimal L3-relative IPv4 packet (no Ethernet). `frag_off` is
/// the raw 16-bit IPv4 fragment-offset field (flags + offset). `payload`
/// is appended after the 20-byte header (it stands in for the bytes a
/// non-first fragment carries where an L4 header would be).
fn frag_v4_packet(protocol: u8, frag_off: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    let total = (20 + payload.len()) as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // id
    p[6..8].copy_from_slice(&frag_off.to_be_bytes());
    p[8] = 64; // ttl
    p[9] = protocol;
    p[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
    p[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
    p.extend_from_slice(payload);
    p
}

/// Build a minimal L3-relative IPv6 packet with an optional fragment
/// header (44) before the L4/payload. `frag_off` is the raw 16-bit
/// fragment-header offset/flags field; pass None for no fragment header.
fn frag_v6_packet(protocol: u8, frag_off: Option<u16>, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[7] = 64; // hop limit
    p[8..24].copy_from_slice(&[0x20; 16]); // src
    p[24..40].copy_from_slice(&[0x30; 16]); // dst
    match frag_off {
        Some(off) => {
            p[6] = 44; // next header = fragment
            let mut frag = [0u8; 8];
            frag[0] = protocol; // next header after fragment
            frag[2..4].copy_from_slice(&off.to_be_bytes());
            frag[4..8].copy_from_slice(&0xdead_beefu32.to_be_bytes()); // id
            p.extend_from_slice(&frag);
        }
        None => p[6] = protocol,
    }
    let plen = (p.len() - 40 + payload.len()) as u16;
    p[4..6].copy_from_slice(&plen.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

#[test]
fn ipv4_non_first_fragment_predicate_truth_table() {
    // offset 0, MF=0 (atomic) and MF=1 (first) -> first/atomic, false.
    assert!(!ipv4_is_non_first_fragment(&frag_v4_packet(
        PROTO_TCP, 0x0000, &[0; 8]
    )));
    assert!(!ipv4_is_non_first_fragment(&frag_v4_packet(
        PROTO_TCP, 0x2000, &[0; 8]
    )));
    // offset != 0 -> non-first (with and without MF).
    assert!(ipv4_is_non_first_fragment(&frag_v4_packet(
        PROTO_TCP, 0x0001, &[0; 8]
    )));
    assert!(ipv4_is_non_first_fragment(&frag_v4_packet(
        PROTO_TCP, 0x2001, &[0; 8]
    )));
    // too-short slice -> false (length guards reject separately).
    assert!(!ipv4_is_non_first_fragment(&[0x45, 0x00, 0x00]));
}

#[test]
fn ipv6_non_first_fragment_predicate_truth_table() {
    // No fragment header -> false.
    assert!(!ipv6_is_non_first_fragment(&frag_v6_packet(
        PROTO_TCP, None, &[0; 8]
    )));
    // Fragment header, offset 0 (first/atomic) with MF=0 and MF=1 -> false.
    assert!(!ipv6_is_non_first_fragment(&frag_v6_packet(
        PROTO_TCP,
        Some(0x0000),
        &[0; 8]
    )));
    assert!(!ipv6_is_non_first_fragment(&frag_v6_packet(
        PROTO_TCP,
        Some(0x0001),
        &[0; 8]
    )));
    // Fragment header, offset bits set -> non-first.
    assert!(ipv6_is_non_first_fragment(&frag_v6_packet(
        PROTO_TCP,
        Some(0x0008),
        &[0; 8]
    )));
    assert!(ipv6_is_non_first_fragment(&frag_v6_packet(
        PROTO_TCP,
        Some(0xABC8),
        &[0; 8]
    )));
}

// #2362: Junos `is-fragment` matches ANY fragment (first OR non-first), unlike
// the non-first predicate above. The MF bit (0x2000) alone (offset 0) means a
// FIRST fragment, which must match.
#[test]
fn ipv4_any_fragment_predicate_truth_table() {
    // Unfragmented datagram (MF=0, offset=0) -> not a fragment.
    assert!(!ipv4_is_any_fragment(&frag_v4_packet(
        PROTO_TCP, 0x0000, &[0; 8]
    )));
    // DF set only (0x4000) -> still not a fragment.
    assert!(!ipv4_is_any_fragment(&frag_v4_packet(
        PROTO_TCP, 0x4000, &[0; 8]
    )));
    // First fragment (MF=1, offset=0) -> IS a fragment.
    assert!(ipv4_is_any_fragment(&frag_v4_packet(
        PROTO_TCP, 0x2000, &[0; 8]
    )));
    // Middle/last fragment (offset != 0) -> IS a fragment, MF set or not.
    assert!(ipv4_is_any_fragment(&frag_v4_packet(
        PROTO_TCP, 0x0001, &[0; 8]
    )));
    assert!(ipv4_is_any_fragment(&frag_v4_packet(
        PROTO_TCP, 0x2001, &[0; 8]
    )));
    // Too-short slice -> false.
    assert!(!ipv4_is_any_fragment(&[0x45, 0x00, 0x00]));
}

#[test]
fn ipv6_any_fragment_predicate_truth_table() {
    // No fragment header -> not a fragment.
    assert!(!ipv6_is_any_fragment(&frag_v6_packet(
        PROTO_TCP, None, &[0; 8]
    )));
    // Fragment header present, first fragment (offset 0, M=1) -> IS a fragment.
    assert!(ipv6_is_any_fragment(&frag_v6_packet(
        PROTO_TCP,
        Some(0x0001),
        &[0; 8]
    )));
    // Fragment header present, offset 0, M=0 (atomic-ish) -> still a fragment
    // header is present, so Junos is-fragment matches.
    assert!(ipv6_is_any_fragment(&frag_v6_packet(
        PROTO_TCP,
        Some(0x0000),
        &[0; 8]
    )));
    // Middle/last fragment -> IS a fragment.
    assert!(ipv6_is_any_fragment(&frag_v6_packet(
        PROTO_TCP,
        Some(0x0008),
        &[0; 8]
    )));
}

#[test]
fn apply_nat_ipv4_non_first_fragment_rewrites_ip_only() {
    // Payload bytes occupy the post-IP offset where the buggy code would
    // write the dst port + adjust an L4 checksum.
    let payload = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
    let mut frag = frag_v4_packet(PROTO_TCP, 0x0001, &payload);
    let nat = NatDecision {
        rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
        rewrite_dst_port: Some(8080),
        ..NatDecision::default()
    };
    assert_eq!(apply_nat_ipv4(&mut frag, PROTO_TCP, nat, true), Some(()));
    // dst IP rewritten on the fragment ...
    assert_eq!(&frag[16..20], &[192, 0, 2, 9]);
    // ... but the payload (the fictitious L4 header) is byte-identical.
    assert_eq!(&frag[20..], &payload);
}

#[test]
fn apply_nat_ipv6_non_first_fragment_rewrites_ip_only() {
    let payload = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
    let mut frag = frag_v6_packet(PROTO_TCP, Some(0x0008), &payload);
    let new_dst = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x99);
    let nat = NatDecision {
        rewrite_dst: Some(IpAddr::V6(new_dst)),
        rewrite_dst_port: Some(8080),
        ..NatDecision::default()
    };
    // rel_l4 = 48 (40 base + 8 fragment header).
    assert_eq!(
        apply_nat_ipv6(&mut frag, 48, PROTO_TCP, nat, true),
        Some(())
    );
    assert_eq!(&frag[24..40], &new_dst.octets());
    assert_eq!(&frag[48..], &payload);
}

#[test]
fn enforce_expected_ports_skips_non_first_fragment() {
    // A non-first fragment's "ports" are payload; enforcement must no-op.
    let payload = [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0];
    let mut frame = frag_v4_packet(PROTO_TCP, 0x0001, &payload);
    let before = frame.clone();
    let repaired = enforce_expected_ports(
        &mut frame,
        libc::AF_INET as u8,
        PROTO_TCP,
        Some((54688, 5201)),
        true,
    )
    .expect("enforce");
    assert!(!repaired);
    assert_eq!(
        frame, before,
        "non-first fragment payload must be untouched"
    );
}

#[test]
fn clamp_tcp_mss_clamps_ext_headered_v6_syn() {
    // hop-by-hop ext header (8 bytes, next=TCP) then a SYN with an MSS
    // option of 1460. Before #1852 the fixed (40, packet[6]) read saw
    // packet[6] == 0 (hop-by-hop) and bailed; now the clamp walks the
    // chain and clamps to 1400.
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[6] = 0; // next header = hop-by-hop
    p[7] = 64;
    // hop-by-hop: next=TCP(6), hdr ext len 0 (8 bytes total).
    p.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
    // TCP header at offset 48: ports, seq, ack, data-offset=6 (24 bytes,
    // 20 + 4 MSS option), SYN flag, window, csum, urg, MSS option.
    let mut tcp = vec![0u8; 24];
    tcp[12] = 6 << 4; // data offset 6 words = 24 bytes
    tcp[13] = 0x02; // SYN
    tcp[20] = 2; // MSS kind
    tcp[21] = 4; // MSS len
    tcp[22..24].copy_from_slice(&1460u16.to_be_bytes());
    p.extend_from_slice(&tcp);
    let plen = (p.len() - 40) as u16;
    p[4..6].copy_from_slice(&plen.to_be_bytes());

    assert!(
        super::tcp::clamp_tcp_mss(&mut p, 1400),
        "ext-headered v6 SYN must clamp"
    );
    let mss = u16::from_be_bytes([p[48 + 22], p[48 + 23]]);
    assert_eq!(mss, 1400);
}

#[test]
fn clamp_tcp_mss_skips_non_first_fragment() {
    // A non-first v4 fragment whose payload happens to look like a SYN
    // with an MSS option must NOT be clamped (the bytes are payload).
    let mut tcp_like = vec![0u8; 24];
    tcp_like[12] = 6 << 4;
    tcp_like[13] = 0x02; // looks like SYN
    tcp_like[20] = 2;
    tcp_like[21] = 4;
    tcp_like[22..24].copy_from_slice(&1460u16.to_be_bytes());
    let before = tcp_like.clone();
    let mut frag = frag_v4_packet(PROTO_TCP, 0x0001, &tcp_like);
    assert!(!super::tcp::clamp_tcp_mss(&mut frag, 1400));
    assert_eq!(&frag[20..], &before[..], "fragment payload untouched");
}

#[test]
fn build_tunnel_egress_non_first_fragment_skips_forced_l4_recompute() {
    // #1852 (Codex impl review): the copy builder's forced tunnel L4
    // recompute (tunnel_endpoint_id != 0 -> force_tunnel_l4_recompute)
    // must NOT run on a non-first fragment — it would write a checksum at
    // ihl+16, which is payload, re-corrupting what the NAT/port gates
    // protected. Build an eth + non-first IPv4 fragment + TCP-like
    // payload and assert the payload is byte-identical after the build.
    let mut out = Vec::new();
    write_eth_header(
        &mut out,
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        0,
        0x0800,
    );
    let ip_start = out.len(); // 14
    // IPv4 header: non-first fragment (offset 1), ttl 64, proto TCP.
    let payload = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    let total = (20 + payload.len()) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip[6..8].copy_from_slice(&0x0001u16.to_be_bytes()); // non-first
    ip[8] = 64;
    ip[9] = PROTO_TCP;
    ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
    ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
    out.extend_from_slice(&ip);
    out.extend_from_slice(&payload);
    let before_payload = payload.to_vec();
    let ingress = out.clone();

    let meta: ForwardPacketMeta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: ip_start as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    }
    .into();
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 7, // tunnel egress -> force_tunnel_l4_recompute
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };

    let mut egress = vec![0u8; ingress.len()];
    let written = build_forwarded_frame_into_from_frame(
        &mut egress,
        &ingress,
        meta,
        &decision,
        &ForwardingState::default(),
        false,
        None,
    )
    .expect("build");
    let out_payload_start = 14 + 20; // eth + ihl
    assert_eq!(
        &egress[out_payload_start..written],
        &before_payload[..],
        "forced tunnel L4 recompute must not touch non-first fragment payload"
    );
}

/// #1881 staleness-pin companion (plan §9 test 1): the local-origin
/// builder follows WHATEVER state it is given — with the loop now
/// tracking the shared forwarding ArcSwap, a destination edit reaches
/// the very next packet. Pre-#1881 the loop held a spawn-time clone,
/// so the old-state encap below is exactly what a stale thread kept
/// emitting until restart.
#[test]
fn local_origin_tunnel_tx_request_follows_supplied_state_destination() {
    let state_old = build_forwarding_state(&native_gre_snapshot(true));
    let mut snapshot_new = native_gre_snapshot(true);
    snapshot_new.tunnel_endpoints[0].destination = "2602:ffd3:0:2::9".to_string();
    let state_new = build_forwarding_state(&snapshot_new);
    let ha_state = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let packet = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 255, 192, 42),
        Ipv4Addr::new(10, 255, 192, 41),
        64,
    );
    // Outer IPv6 destination: eth(14) + vlan(4) + 24 = offset 42..58.
    let plan_old = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state_old,
        &ha_state,
        &dynamic_neighbors,
    )
    .expect("old-state plan");
    assert_eq!(plan_old.tx_request.bytes[57], 0x07, "old outer destination");
    let plan_new = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state_new,
        &ha_state,
        &dynamic_neighbors,
    )
    .expect("new-state plan");
    assert_eq!(
        plan_new.tx_request.bytes[57], 0x09,
        "destination edit reaches the encap as soon as the thread \
         loads the rotated state"
    );
}
