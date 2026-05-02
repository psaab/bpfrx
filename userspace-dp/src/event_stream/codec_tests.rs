// Tests for event_stream/codec.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep codec.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "codec_tests.rs"]` from codec.rs.

use super::*;
use crate::afxdp::ForwardingResolution;
use crate::nat::NatDecision;
use crate::test_zone_ids::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn test_zone_map() -> FxHashMap<String, u16> {
    let mut m = FxHashMap::default();
    m.insert("trust".to_string(), 1);
    m.insert("untrust".to_string(), 2);
    m.insert("dmz".to_string(), 3);
    m
}

fn test_key_v4() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 200)),
        src_port: 12345,
        dst_port: 80,
    }
}

fn test_key_v6() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: 6,
        src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0xbf01, 0, 0, 0, 0x102)),
        dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0xbf02, 0, 0, 0, 0x200)),
        src_port: 54321,
        dst_port: 443,
    }
}

fn test_decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 2,
            egress_ifindex: 3,
            tx_ifindex: 3,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1))),
            neighbor_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            src_mac: Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 10))),
            rewrite_dst: None,
            rewrite_src_port: Some(40000),
            rewrite_dst_port: None,
            nat64: false,
            nptv6: false,
        },
    }
}

fn test_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_TRUST_ZONE_ID,
        egress_zone: TEST_UNTRUST_ZONE_ID,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
    }
}

#[test]
fn test_encode_session_open_v4() {
    let zones = test_zone_map();
    let frame = EventFrame::encode_session_open(
        42,
        &test_key_v4(),
        &test_decision(),
        &test_metadata(),
        &zones,
        false,
    );

    // Check header
    let payload_len =
        u32::from_le_bytes([frame.data[0], frame.data[1], frame.data[2], frame.data[3]]);
    assert_eq!(frame.data[4], MSG_SESSION_OPEN);
    let seq = u64::from_le_bytes(frame.data[8..16].try_into().unwrap());
    assert_eq!(seq, 42);
    assert_eq!(frame.seq, 42);
    assert!(frame.len as usize > FRAME_HEADER_SIZE);
    assert_eq!(frame.len as usize, FRAME_HEADER_SIZE + payload_len as usize);

    // Check payload fields
    let p = &frame.data[FRAME_HEADER_SIZE..];
    assert_eq!(p[0], 4); // AddrFamily
    assert_eq!(p[1], 6); // Protocol TCP
    assert_eq!(u16::from_le_bytes([p[2], p[3]]), 12345); // SrcPort
    assert_eq!(u16::from_le_bytes([p[4], p[5]]), 80); // DstPort
    assert_eq!(u16::from_le_bytes([p[6], p[7]]), 40000); // NATSrcPort
    assert_eq!(u16::from_le_bytes([p[8], p[9]]), 0); // NATDstPort
    assert_eq!(i16::from_le_bytes([p[10], p[11]]), 0); // OwnerRGID
    assert_eq!(i16::from_le_bytes([p[12], p[13]]), 3); // EgressIfindex
    assert_eq!(i16::from_le_bytes([p[14], p[15]]), 3); // TXIfindex
    assert_eq!(p[20], 0); // Flags (no fabric redirect, no fabric ingress)
    assert_eq!(p[21], TEST_TRUST_ZONE_ID as u8); // IngressZoneID
    assert_eq!(p[22], TEST_UNTRUST_ZONE_ID as u8); // EgressZoneID
    assert_eq!(p[23], DISP_FORWARD_CANDIDATE); // Disposition
}

#[test]
fn test_encode_session_open_v6() {
    let zones = test_zone_map();
    let frame = EventFrame::encode_session_open(
        100,
        &test_key_v6(),
        &test_decision(),
        &test_metadata(),
        &zones,
        false,
    );

    let p = &frame.data[FRAME_HEADER_SIZE..];
    assert_eq!(p[0], 6); // AddrFamily v6
    assert_eq!(p[1], 6); // Protocol TCP
    assert_eq!(u16::from_le_bytes([p[2], p[3]]), 54321); // SrcPort
    assert_eq!(u16::from_le_bytes([p[4], p[5]]), 443); // DstPort

    // v6 frame should be larger than v4 (16-byte addresses instead of 4)
    assert!(frame.len > 100);
}

#[test]
fn test_encode_session_close_v4() {
    let frame = EventFrame::encode_session_close(
        7,
        &test_key_v4(),
        1,
        FLAG_FABRIC_REDIRECT,
        TEST_TRUST_ZONE_ID,
        TEST_UNTRUST_ZONE_ID,
    );

    assert_eq!(frame.data[4], MSG_SESSION_CLOSE);
    assert_eq!(frame.seq, 7);

    let p = &frame.data[FRAME_HEADER_SIZE..];
    assert_eq!(p[0], 4); // AddrFamily
    assert_eq!(p[1], 6); // Protocol
    assert_eq!(u16::from_le_bytes([p[2], p[3]]), 12345); // SrcPort
    assert_eq!(u16::from_le_bytes([p[4], p[5]]), 80); // DstPort
                                                      // p[6..10] SrcIP, p[10..14] DstIP
                                                      // p[14..16] OwnerRGID
    assert_eq!(i16::from_le_bytes([p[14], p[15]]), 1);
    // p[16] Flags
    assert_eq!(p[16], FLAG_FABRIC_REDIRECT);
    // #919/#922: p[17] IngressZoneID, p[18] EgressZoneID
    assert_eq!(p[17], TEST_TRUST_ZONE_ID as u8);
    assert_eq!(p[18], TEST_UNTRUST_ZONE_ID as u8);
}

#[test]
fn test_encode_drain_complete() {
    let frame = EventFrame::encode_drain_complete(999);
    assert_eq!(frame.data[4], MSG_DRAIN_COMPLETE);
    assert_eq!(frame.seq, 999);
    assert_eq!(frame.len, FRAME_HEADER_SIZE as u16);
}

#[test]
fn test_encode_full_resync() {
    let frame = EventFrame::encode_full_resync(500);
    assert_eq!(frame.data[4], MSG_FULL_RESYNC);
    assert_eq!(frame.seq, 500);
    assert_eq!(frame.len, FRAME_HEADER_SIZE as u16);
}

#[test]
fn test_close_flags() {
    let delta = SessionDelta {
        kind: crate::session::SessionDeltaKind::Close,
        key: test_key_v4(),
        decision: test_decision(),
        metadata: SessionMetadata {
            ingress_zone: TEST_TRUST_ZONE_ID,
            egress_zone: TEST_UNTRUST_ZONE_ID,
            owner_rg_id: 0,
            fabric_ingress: true,
            is_reverse: false,
            nat64_reverse: None,
        },
        origin: crate::session::SessionOrigin::ForwardFlow,
        fabric_redirect_sync: true,
    };
    let flags = close_flags(&delta);
    assert_eq!(flags & FLAG_FABRIC_REDIRECT, FLAG_FABRIC_REDIRECT);
    assert_eq!(flags & FLAG_FABRIC_INGRESS, FLAG_FABRIC_INGRESS);
}

#[test]
fn test_disposition_encoding() {
    assert_eq!(
        encode_disposition(ForwardingDisposition::ForwardCandidate),
        0
    );
    assert_eq!(encode_disposition(ForwardingDisposition::LocalDelivery), 1);
    assert_eq!(encode_disposition(ForwardingDisposition::FabricRedirect), 2);
    assert_eq!(encode_disposition(ForwardingDisposition::PolicyDenied), 3);
    assert_eq!(encode_disposition(ForwardingDisposition::NoRoute), 4);
    assert_eq!(
        encode_disposition(ForwardingDisposition::MissingNeighbor),
        5
    );
    assert_eq!(encode_disposition(ForwardingDisposition::HAInactive), 6);
    assert_eq!(encode_disposition(ForwardingDisposition::DiscardRoute), 7);
    assert_eq!(
        encode_disposition(ForwardingDisposition::NextTableUnsupported),
        8
    );
}
