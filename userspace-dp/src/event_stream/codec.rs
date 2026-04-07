//! Wire codec for the event stream binary protocol.
//!
//! Pure encoding/decoding functions with zero I/O — all frame construction
//! happens on a stack-allocated `[u8; 256]` buffer.

use crate::afxdp::ForwardingDisposition;
use crate::session::{SessionDecision, SessionDelta, SessionKey, SessionMetadata};
use rustc_hash::FxHashMap;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Wire format constants
// ---------------------------------------------------------------------------

pub(crate) const FRAME_HEADER_SIZE: usize = 16;

pub(crate) const MSG_SESSION_OPEN: u8 = 1;
pub(crate) const MSG_SESSION_CLOSE: u8 = 2;
#[allow(dead_code)]
pub(crate) const MSG_SESSION_UPDATE: u8 = 3;
pub(crate) const MSG_ACK: u8 = 4;
pub(crate) const MSG_PAUSE: u8 = 5;
pub(crate) const MSG_RESUME: u8 = 6;
pub(crate) const MSG_DRAIN_REQUEST: u8 = 7;
pub(crate) const MSG_DRAIN_COMPLETE: u8 = 8;
pub(crate) const MSG_FULL_RESYNC: u8 = 9;
pub(crate) const MSG_KEEPALIVE: u8 = 10;

/// Disposition encoding for the wire format.
const DISP_FORWARD_CANDIDATE: u8 = 0;
const DISP_LOCAL_DELIVERY: u8 = 1;
const DISP_FABRIC_REDIRECT: u8 = 2;
const DISP_POLICY_DENIED: u8 = 3;
const DISP_NO_ROUTE: u8 = 4;
const DISP_MISSING_NEIGHBOR: u8 = 5;
const DISP_HA_INACTIVE: u8 = 6;
const DISP_DISCARD_ROUTE: u8 = 7;
const DISP_NEXT_TABLE_UNSUPPORTED: u8 = 8;

// Flag bits for SessionOpen/Close
pub(crate) const FLAG_FABRIC_REDIRECT: u8 = 1 << 0;
pub(crate) const FLAG_FABRIC_INGRESS: u8 = 1 << 1;
pub(crate) const FLAG_IS_REVERSE: u8 = 1 << 2;

// ---------------------------------------------------------------------------
// EventFrame -- zero-allocation stack-buffered wire frame
// ---------------------------------------------------------------------------

/// Pre-serialized event frame ready for socket write.
#[derive(Clone)]
pub(crate) struct EventFrame {
    pub(super) data: [u8; 256],
    pub(super) len: u16,
    pub(crate) seq: u64,
}

impl EventFrame {
    /// Encode a SessionOpen (type 1) or SessionUpdate (type 3) frame.
    pub(crate) fn encode_session_open(
        seq: u64,
        key: &SessionKey,
        decision: &SessionDecision,
        metadata: &SessionMetadata,
        zone_name_to_id: &FxHashMap<String, u16>,
        fabric_redirect_sync: bool,
    ) -> Self {
        let mut buf = [0u8; 256];
        let mut pos = FRAME_HEADER_SIZE; // skip header, fill later

        // [0] AddrFamily
        let is_v6 = key.addr_family == libc::AF_INET6 as u8;
        buf[pos] = if is_v6 { 6 } else { 4 };
        pos += 1;

        // [1] Protocol
        buf[pos] = key.protocol;
        pos += 1;

        // [2:4] SrcPort LE
        buf[pos..pos + 2].copy_from_slice(&key.src_port.to_le_bytes());
        pos += 2;

        // [4:6] DstPort LE
        buf[pos..pos + 2].copy_from_slice(&key.dst_port.to_le_bytes());
        pos += 2;

        // [6:8] NATSrcPort LE
        let nat = &decision.nat;
        buf[pos..pos + 2].copy_from_slice(&nat.rewrite_src_port.unwrap_or(0).to_le_bytes());
        pos += 2;

        // [8:10] NATDstPort LE
        buf[pos..pos + 2].copy_from_slice(&nat.rewrite_dst_port.unwrap_or(0).to_le_bytes());
        pos += 2;

        // [10:12] OwnerRGID i16 LE
        buf[pos..pos + 2].copy_from_slice(&(metadata.owner_rg_id as i16).to_le_bytes());
        pos += 2;

        // [12:14] EgressIfindex i16 LE
        buf[pos..pos + 2]
            .copy_from_slice(&(decision.resolution.egress_ifindex as i16).to_le_bytes());
        pos += 2;

        // [14:16] TXIfindex i16 LE
        buf[pos..pos + 2].copy_from_slice(&(decision.resolution.tx_ifindex as i16).to_le_bytes());
        pos += 2;

        // [16:18] TunnelEndpointID u16 LE
        buf[pos..pos + 2].copy_from_slice(&decision.resolution.tunnel_endpoint_id.to_le_bytes());
        pos += 2;

        // [18:20] TXVLANID u16 LE
        buf[pos..pos + 2].copy_from_slice(&decision.resolution.tx_vlan_id.to_le_bytes());
        pos += 2;

        // [20] Flags
        let mut flags: u8 = 0;
        if fabric_redirect_sync
            || decision.resolution.disposition == ForwardingDisposition::FabricRedirect
        {
            flags |= FLAG_FABRIC_REDIRECT;
        }
        if metadata.fabric_ingress {
            flags |= FLAG_FABRIC_INGRESS;
        }
        if metadata.is_reverse {
            flags |= FLAG_IS_REVERSE;
        }
        buf[pos] = flags;
        pos += 1;

        // [21] IngressZoneID u8
        let ingress_id = zone_name_to_id
            .get(metadata.ingress_zone.as_ref())
            .copied()
            .unwrap_or(0) as u8;
        buf[pos] = ingress_id;
        pos += 1;

        // [22] EgressZoneID u8
        let egress_id = zone_name_to_id
            .get(metadata.egress_zone.as_ref())
            .copied()
            .unwrap_or(0) as u8;
        buf[pos] = egress_id;
        pos += 1;

        // [23] Disposition u8
        buf[pos] = encode_disposition(decision.resolution.disposition);
        pos += 1;

        // Addresses: 4 bytes each for v4, 16 bytes each for v6
        pos = write_ip(&mut buf, pos, key.src_ip, is_v6);
        pos = write_ip(&mut buf, pos, key.dst_ip, is_v6);
        pos = write_ip_opt(&mut buf, pos, nat.rewrite_src, is_v6);
        pos = write_ip_opt(&mut buf, pos, nat.rewrite_dst, is_v6);

        // NeighborMAC [6 bytes]
        if let Some(mac) = decision.resolution.neighbor_mac {
            buf[pos..pos + 6].copy_from_slice(&mac);
        }
        pos += 6;

        // SrcMAC [6 bytes]
        if let Some(mac) = decision.resolution.src_mac {
            buf[pos..pos + 6].copy_from_slice(&mac);
        }
        pos += 6;

        // NextHop (4 or 16 bytes)
        pos = write_ip_opt(&mut buf, pos, decision.resolution.next_hop, is_v6);

        // Write header
        let payload_len = (pos - FRAME_HEADER_SIZE) as u32;
        write_header(&mut buf, payload_len, MSG_SESSION_OPEN, seq);

        EventFrame {
            data: buf,
            len: pos as u16,
            seq,
        }
    }

    /// Encode a SessionClose (type 2) frame -- minimal payload.
    pub(crate) fn encode_session_close(
        seq: u64,
        key: &SessionKey,
        owner_rg_id: i32,
        close_flags: u8,
    ) -> Self {
        let mut buf = [0u8; 256];
        let mut pos = FRAME_HEADER_SIZE;

        let is_v6 = key.addr_family == libc::AF_INET6 as u8;

        // [0] AddrFamily
        buf[pos] = if is_v6 { 6 } else { 4 };
        pos += 1;

        // [1] Protocol
        buf[pos] = key.protocol;
        pos += 1;

        // [2:4] SrcPort
        buf[pos..pos + 2].copy_from_slice(&key.src_port.to_le_bytes());
        pos += 2;

        // [4:6] DstPort
        buf[pos..pos + 2].copy_from_slice(&key.dst_port.to_le_bytes());
        pos += 2;

        // SrcIP, DstIP
        pos = write_ip(&mut buf, pos, key.src_ip, is_v6);
        pos = write_ip(&mut buf, pos, key.dst_ip, is_v6);

        // OwnerRGID i16 LE
        buf[pos..pos + 2].copy_from_slice(&(owner_rg_id as i16).to_le_bytes());
        pos += 2;

        // Flags
        buf[pos] = close_flags;
        pos += 1;

        let payload_len = (pos - FRAME_HEADER_SIZE) as u32;
        write_header(&mut buf, payload_len, MSG_SESSION_CLOSE, seq);

        EventFrame {
            data: buf,
            len: pos as u16,
            seq,
        }
    }

    /// Encode a DrainComplete (type 8) frame -- header only, no payload.
    pub(crate) fn encode_drain_complete(seq: u64) -> Self {
        let mut buf = [0u8; 256];
        write_header(&mut buf, 0, MSG_DRAIN_COMPLETE, seq);
        EventFrame {
            data: buf,
            len: FRAME_HEADER_SIZE as u16,
            seq,
        }
    }

    /// Encode a FullResync (type 9) frame -- header only, no payload.
    pub(crate) fn encode_full_resync(seq: u64) -> Self {
        let mut buf = [0u8; 256];
        write_header(&mut buf, 0, MSG_FULL_RESYNC, seq);
        EventFrame {
            data: buf,
            len: FRAME_HEADER_SIZE as u16,
            seq,
        }
    }

    /// The raw bytes of this frame (header + payload).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

// ---------------------------------------------------------------------------
// Header / address helpers
// ---------------------------------------------------------------------------

fn write_header(buf: &mut [u8; 256], payload_len: u32, msg_type: u8, seq: u64) {
    buf[0..4].copy_from_slice(&payload_len.to_le_bytes());
    buf[4] = msg_type;
    // buf[5..8] reserved (already zeroed)
    buf[8..16].copy_from_slice(&seq.to_le_bytes());
}

fn write_ip(buf: &mut [u8; 256], pos: usize, ip: IpAddr, is_v6: bool) -> usize {
    match ip {
        IpAddr::V4(v4) => {
            buf[pos..pos + 4].copy_from_slice(&v4.octets());
            if is_v6 {
                // pad to 16 bytes if frame is v6 but this particular IP is v4
                // (shouldn't normally happen, but be safe)
                pos + 16
            } else {
                pos + 4
            }
        }
        IpAddr::V6(v6) => {
            buf[pos..pos + 16].copy_from_slice(&v6.octets());
            pos + 16
        }
    }
}

fn write_ip_opt(buf: &mut [u8; 256], pos: usize, ip: Option<IpAddr>, is_v6: bool) -> usize {
    match ip {
        Some(addr) => write_ip(buf, pos, addr, is_v6),
        None => {
            let size = if is_v6 { 16 } else { 4 };
            // already zeroed
            pos + size
        }
    }
}

fn encode_disposition(d: ForwardingDisposition) -> u8 {
    match d {
        ForwardingDisposition::ForwardCandidate => DISP_FORWARD_CANDIDATE,
        ForwardingDisposition::LocalDelivery => DISP_LOCAL_DELIVERY,
        ForwardingDisposition::FabricRedirect => DISP_FABRIC_REDIRECT,
        ForwardingDisposition::PolicyDenied => DISP_POLICY_DENIED,
        ForwardingDisposition::NoRoute => DISP_NO_ROUTE,
        ForwardingDisposition::MissingNeighbor => DISP_MISSING_NEIGHBOR,
        ForwardingDisposition::HAInactive => DISP_HA_INACTIVE,
        ForwardingDisposition::DiscardRoute => DISP_DISCARD_ROUTE,
        ForwardingDisposition::NextTableUnsupported => DISP_NEXT_TABLE_UNSUPPORTED,
    }
}

/// Compute the close flags byte from a SessionDelta.
pub(crate) fn close_flags(delta: &SessionDelta) -> u8 {
    let mut flags: u8 = 0;
    if delta.fabric_redirect_sync
        || delta.decision.resolution.disposition == ForwardingDisposition::FabricRedirect
    {
        flags |= FLAG_FABRIC_REDIRECT;
    }
    if delta.metadata.fabric_ingress {
        flags |= FLAG_FABRIC_INGRESS;
    }
    flags
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::afxdp::ForwardingResolution;
    use crate::nat::NatDecision;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

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
            ingress_zone: Arc::from("trust"),
            egress_zone: Arc::from("untrust"),
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
        assert_eq!(p[21], 1); // IngressZoneID (trust=1)
        assert_eq!(p[22], 2); // EgressZoneID (untrust=2)
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
        let frame = EventFrame::encode_session_close(7, &test_key_v4(), 1, FLAG_FABRIC_REDIRECT);

        assert_eq!(frame.data[4], MSG_SESSION_CLOSE);
        assert_eq!(frame.seq, 7);

        let p = &frame.data[FRAME_HEADER_SIZE..];
        assert_eq!(p[0], 4); // AddrFamily
        assert_eq!(p[1], 6); // Protocol
        assert_eq!(u16::from_le_bytes([p[2], p[3]]), 12345); // SrcPort
        assert_eq!(u16::from_le_bytes([p[4], p[5]]), 80); // DstPort
        // After addresses (4+4 = 8 bytes starting at p[6]):
        // p[6..10] SrcIP, p[10..14] DstIP
        // p[14..16] OwnerRGID
        assert_eq!(i16::from_le_bytes([p[14], p[15]]), 1);
        // p[16] Flags
        assert_eq!(p[16], FLAG_FABRIC_REDIRECT);
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
                ingress_zone: Arc::from("trust"),
                egress_zone: Arc::from("untrust"),
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
}
