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
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

fn test_dataplane_event_v4(kind: DataplaneEventKind) -> DataplaneEventPayload {
    DataplaneEventPayload {
        kind,
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        action: if kind == DataplaneEventKind::FilterLog {
            RT_FLOW_ACTION_PERMIT
        } else {
            RT_FLOW_ACTION_DENY
        },
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        src_port: 49152,
        dst_port: 443,
        nat_src_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 30))),
        nat_dst_ip: None,
        nat_src_port: 40000,
        nat_dst_port: 8443,
        ingress_zone_id: 7,
        egress_zone_id: 9,
        ingress_ifindex: 42,
        policy_id: 101,
        rule_id: 202,
        term_id: 505,
        reason: 5,
        owner_rg_id: 2,
        application_id: 303,
        filter_id: 404,
        screen_id: 606,
        timestamp_ns: 123_456_789,
    }
}

fn test_dataplane_event_v6(kind: DataplaneEventKind) -> DataplaneEventPayload {
    DataplaneEventPayload {
        kind,
        addr_family: libc::AF_INET6 as u8,
        protocol: 17,
        action: if kind == DataplaneEventKind::FilterLog {
            RT_FLOW_ACTION_PERMIT
        } else {
            RT_FLOW_ACTION_DENY
        },
        src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)),
        dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 6, 5, 4, 3, 2, 1)),
        src_port: 5353,
        dst_port: 53,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id: 11,
        egress_zone_id: 12,
        ingress_ifindex: 77,
        policy_id: 0,
        rule_id: 0,
        term_id: 3030,
        reason: 4,
        owner_rg_id: 1,
        application_id: 0,
        filter_id: 909,
        screen_id: 1102,
        timestamp_ns: 987_654_321,
    }
}

fn assert_dataplane_event_round_trip(event: DataplaneEventPayload, msg_type: u8) {
    let frame = EventFrame::encode_dataplane_event(321, &event);

    assert_eq!(frame.data[4], msg_type);
    assert_eq!(frame.seq, 321);
    assert_eq!(
        u32::from_le_bytes(frame.data[0..4].try_into().unwrap()),
        SECURITY_EVENT_PAYLOAD_SIZE as u32
    );
    assert_eq!(
        frame.len as usize,
        FRAME_HEADER_SIZE + SECURITY_EVENT_PAYLOAD_SIZE
    );

    let payload = frame
        .dataplane_event_payload()
        .expect("security event payload");
    assert_eq!(payload.len(), SECURITY_EVENT_PAYLOAD_SIZE);
    assert_eq!(
        payload[55],
        if event.addr_family == libc::AF_INET6 as u8 {
            RT_FLOW_AF_INET6
        } else {
            RT_FLOW_AF_INET
        }
    );
    assert_eq!(
        u16::from_be_bytes(payload[40..42].try_into().unwrap()),
        event.src_port
    );
    assert_eq!(
        u16::from_be_bytes(payload[42..44].try_into().unwrap()),
        event.dst_port
    );
    assert_eq!(payload[52], event.kind.rt_flow_event_type());
    assert_eq!(payload[54], event.action);
    assert_eq!(
        u32::from_le_bytes(payload[56..60].try_into().unwrap()),
        event.rule_id
    );
    assert_eq!(
        u32::from_le_bytes(payload[60..64].try_into().unwrap()),
        event.term_id
    );
    assert_eq!(
        i16::from_le_bytes(payload[64..66].try_into().unwrap()),
        event.owner_rg_id
    );
    assert_eq!(payload[134], event.reason);
    let decoded = decode_dataplane_event(msg_type, payload).expect("decoded security event");
    assert_eq!(decoded.kind, event.kind);
    assert_eq!(decoded.addr_family, event.addr_family);
    assert_eq!(decoded.protocol, event.protocol);
    assert_eq!(decoded.action, event.action);
    assert_eq!(decoded.src_ip, event.src_ip);
    assert_eq!(decoded.dst_ip, event.dst_ip);
    assert_eq!(decoded.src_port, event.src_port);
    assert_eq!(decoded.dst_port, event.dst_port);
    assert_eq!(decoded.nat_src_ip, event.nat_src_ip);
    assert_eq!(decoded.nat_dst_ip, event.nat_dst_ip);
    assert_eq!(decoded.nat_src_port, event.nat_src_port);
    assert_eq!(decoded.nat_dst_port, event.nat_dst_port);
    assert_eq!(decoded.ingress_zone_id, event.ingress_zone_id);
    assert_eq!(decoded.egress_zone_id, event.egress_zone_id);
    assert_eq!(decoded.ingress_ifindex, event.ingress_ifindex);
    assert_eq!(decoded.rule_id, event.rule_id);
    assert_eq!(decoded.term_id, event.term_id);
    assert_eq!(decoded.reason, event.reason);
    assert_eq!(decoded.owner_rg_id, event.owner_rg_id);
    assert_eq!(decoded.application_id, event.application_id);
    assert_eq!(decoded.timestamp_ns, event.timestamp_ns);
    match event.kind {
        DataplaneEventKind::PolicyDeny => assert_eq!(decoded.policy_id, event.policy_id),
        DataplaneEventKind::ScreenDrop => assert_eq!(decoded.screen_id, event.screen_id),
        DataplaneEventKind::FilterLog => assert_eq!(decoded.filter_id, event.filter_id),
        // #2512: this helper only exercises the generic deny/screen/filter
        // dataplane-event payload. SESSION_CLOSE / SESSION_CREATE use their
        // own RT_FLOW encoders and never construct a DataplaneEventPayload.
        DataplaneEventKind::SessionClose | DataplaneEventKind::SessionCreate => {
            unreachable!("session-close/create kinds do not use encode_dataplane_event")
        }
    }
    assert_eq!(
        frame
            .decode_dataplane_event()
            .expect("decoded security event frame"),
        decoded
    );
}

#[test]
fn test_event_frame_type_values_are_stable() {
    assert_eq!(MSG_SESSION_OPEN, 1);
    assert_eq!(MSG_SESSION_CLOSE, 2);
    assert_eq!(MSG_SESSION_UPDATE, 3);
    assert_eq!(MSG_ACK, 4);
    assert_eq!(MSG_PAUSE, 5);
    assert_eq!(MSG_RESUME, 6);
    assert_eq!(MSG_DRAIN_REQUEST, 7);
    assert_eq!(MSG_DRAIN_COMPLETE, 8);
    assert_eq!(MSG_FULL_RESYNC, 9);
    assert_eq!(MSG_KEEPALIVE, 10);
    assert_eq!(MSG_POLICY_DENY, 11);
    assert_eq!(MSG_SCREEN_DROP, 12);
    assert_eq!(MSG_FILTER_LOG, 13);
    // #2460: the RT_FLOW SESSION_CLOSE frame type. Must match the Go
    // EventFrameTypeSessionClose (pkg/dataplane/userspace/protocol.go).
    assert_eq!(MSG_SESSION_CLOSE_RT_FLOW, 14);
}

#[test]
fn test_encode_session_close_rt_flow_v4_wire_layout() {
    // #2460 fail-on-revert: the RT_FLOW SESSION_CLOSE frame must carry the
    // canonical 144-byte dataplane.Event payload with the SESSION_CLOSE
    // event-type byte at offset 52 and the real 5-tuple/NAT/zones at the
    // exact byte offsets the Go logging.DecodeRawEventRecord parser reads.
    // If the encoder drops the SESSION_CLOSE event-type byte (or the type-14
    // emit is reverted), the Go side never sees a Type=="SESSION_CLOSE"
    // record and the NetFlow/IPFIX exporters never fire.
    let frame = EventFrame::encode_session_close_rt_flow(
        99,
        libc::AF_INET as u8,
        6, // TCP
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        12345,
        443,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        None,
        40000,
        0,
        TEST_TRUST_ZONE_ID,
        TEST_UNTRUST_ZONE_ID,
        88,              // #3056: admitting policy id (rides [136:140] on a close)
        1,
        false,           // #2508: log_syslog gate
        1_700_000_000,   // #2465: created Unix seconds
        123_456_789,     // #2853: created sub-second nanos (123.456789 ms)
        1_700_000_123_000_000_000, // #2465: close instant Unix ns
        7,               // #2520: application id
        42,              // #2615: ingress ifindex
        111,             // #2501: fwd packets
        222_333,         // #2501: fwd bytes
        44,              // #2501: rev packets
        55_666,          // #2501: rev bytes
        0xB8,            // #2749: src ToS (DSCP EF=46 << 2)
        0x13,            // #2749: TCP control bits (SYN|FIN|ACK)
        9,               // #2749: egress ifindex
    );

    assert_eq!(frame.data[4], MSG_SESSION_CLOSE_RT_FLOW);
    assert_eq!(frame.seq, 99);
    // Payload length in the header must be the canonical payload size.
    assert_eq!(
        u32::from_le_bytes(frame.data[0..4].try_into().unwrap()),
        SECURITY_EVENT_PAYLOAD_SIZE as u32
    );
    assert_eq!(frame.len as usize, FRAME_HEADER_SIZE + SECURITY_EVENT_PAYLOAD_SIZE);

    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];
    // src/dst IP (16-byte slots, v4 left-aligned).
    assert_eq!(&p[8..12], &[10, 0, 1, 102]);
    assert_eq!(&p[24..28], &[172, 16, 80, 200]);
    // ports — BIG-endian.
    assert_eq!(u16::from_be_bytes([p[40], p[41]]), 12345);
    assert_eq!(u16::from_be_bytes([p[42], p[43]]), 443);
    // zones — little-endian.
    assert_eq!(u16::from_le_bytes([p[48], p[49]]), TEST_TRUST_ZONE_ID);
    assert_eq!(u16::from_le_bytes([p[50], p[51]]), TEST_UNTRUST_ZONE_ID);
    // event type = SESSION_CLOSE (2); protocol; address family (RT_FLOW v4).
    assert_eq!(p[52], RT_FLOW_EVENT_SESSION_CLOSE);
    assert_eq!(p[52], 2, "must equal the Go eventTypeSessionClose value");
    assert_eq!(p[53], 6);
    assert_eq!(p[55], RT_FLOW_AF_INET);
    // NAT translated source IP/port.
    assert_eq!(&p[72..76], &[172, 16, 80, 8]);
    assert_eq!(u16::from_be_bytes([p[104], p[105]]), 40000);
    // #2501 fail-on-revert: the per-session forward/reverse byte+packet
    // counters ride the reserved [56:64]/[64:72] (forward) and
    // [112:120]/[120:128] (reverse) slots, LITTLE-endian, exactly where the
    // Go logging.DecodeRawEventRecord reads SessionPackets/SessionBytes/
    // RevPackets/RevBytes. Reverting the encoder to hard-zero these slots
    // (the pre-#2501 behavior) makes the NetFlow/IPFIX close record report 0
    // volume again — these assertions catch that.
    assert_eq!(u64::from_le_bytes(p[56..64].try_into().unwrap()), 111); // fwd pkts
    assert_eq!(u64::from_le_bytes(p[64..72].try_into().unwrap()), 222_333); // fwd bytes
    assert_eq!(u64::from_le_bytes(p[112..120].try_into().unwrap()), 44); // rev pkts
    assert_eq!(u64::from_le_bytes(p[120..128].try_into().unwrap()), 55_666); // rev bytes
    // #2465 fail-on-revert: the created stamp (offset 108, Unix seconds, LE)
    // and the record timestamp (offset 0, Unix ns, LE) must carry the real
    // session timestamps now, NOT 0. If the encoder drops these args the flow
    // exporter falls back to the packet-count heuristic StartTime.
    assert_eq!(
        u32::from_le_bytes(p[108..112].try_into().unwrap()),
        1_700_000_000
    ); // created Unix secs
    // #2853 fail-on-revert: the creation instant's sub-second nanosecond
    // remainder rides the [44:48] policy_id slot (LITTLE-endian u32), which the
    // Go SESSION_CLOSE decoder reads as CreatedNanos to build a
    // millisecond-accurate flow StartTime. Reverting the encoder to leave this
    // slot 0 collapses every same-second flow onto one integer-second start.
    assert_eq!(
        u32::from_le_bytes(p[44..48].try_into().unwrap()),
        123_456_789
    ); // created sub-second nanos
    // #2749 fail-on-revert: the class-of-service / interface-attribution block
    // rides the additive [144:152] slots — [144] src ToS, [145] cumulative TCP
    // control bits, [148:152] egress ifindex (LE). Reverting the encoder to
    // drop these makes the NetFlow/IPFIX close record report 0 for srcTos /
    // tcpControlBits / egressInterface again (the #2613 regression #2749
    // fixes). The payload itself must be 152 bytes.
    assert_eq!(SECURITY_EVENT_PAYLOAD_SIZE, 152);
    assert_eq!(p.len(), 152);
    assert_eq!(p[144], 0xB8); // src ToS
    assert_eq!(p[145], 0x13); // TCP control bits
    assert_eq!(u32::from_le_bytes(p[148..152].try_into().unwrap()), 9); // egress ifindex
    assert_eq!(
        u64::from_le_bytes(p[0..8].try_into().unwrap()),
        1_700_000_123_000_000_000
    ); // close instant Unix ns
    // close reason — none (the delta carries no idle/FIN/RST discriminator).
    assert_eq!(p[134], RT_FLOW_CLOSE_REASON_NONE);
    // #2520 fail-on-revert: the application id rides the [132:134] slot
    // (little-endian), the same slot the deny/screen/filter frames use and the
    // Go DecodeRawEventRecord reads to resolve application=. Reverting the
    // encoder to leave it 0 makes this assertion fail (and the close record
    // logs application="UNKNOWN").
    assert_eq!(u16::from_le_bytes([p[132], p[133]]), 7);
    // #2615 fail-on-revert: the ingress ifindex rides the [128:132] slot
    // (little-endian u32), the slot the Go DecodeRawEventRecord reads to
    // resolve packet-incoming-interface. Reverting the encoder to leave it 0
    // makes this assertion fail (and the close record logs
    // packet-incoming-interface="N/A").
    assert_eq!(u32::from_le_bytes(p[128..132].try_into().unwrap()), 42);
    // #3056 fail-on-revert: the SESSION_CLOSE frame carries the admitting policy
    // ID in the TRAILING [136:140] slot (LE u32), NOT [44:48] (which #2853 took
    // for the created-subsec-nanos on a close). The Go decoder reads [136:140]
    // back as PolicyID only on a close, so the RT_FLOW_SESSION_CLOSE record and
    // the NetFlow/IPFIX close exporters name the admitting policy. Reverting the
    // encoder to leave [136:140] 0 makes the close record log policy 0 (the first
    // configured policy) and this assertion fails. The payload also grew 136->144
    // for this slot; SECURITY_EVENT_PAYLOAD_SIZE pins the length above.
    assert_eq!(u32::from_le_bytes(p[136..140].try_into().unwrap()), 88);
    // [136:140] must NOT collide with the #2853 created-subsec-nanos in [44:48].
    assert_eq!(u32::from_le_bytes(p[44..48].try_into().unwrap()), 123_456_789);
}

#[test]
fn test_encode_session_close_rt_flow_v6() {
    let frame = EventFrame::encode_session_close_rt_flow(
        100,
        libc::AF_INET6 as u8,
        17, // UDP
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0xbf01, 0, 0, 0, 0x102)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200)),
        5353,
        53,
        None,
        None,
        0,
        0,
        TEST_TRUST_ZONE_ID,
        TEST_UNTRUST_ZONE_ID,
        0,     // #3056: admitting policy id
        0,
        false, // #2508: log_syslog gate
        0,     // #2465: created Unix seconds (unknown → fallback)
        0,     // #2853: created sub-second nanos (unknown)
        0,     // #2465: close instant Unix ns
        0,     // #2520: application id (unknown)
        0,     // #2615: ingress ifindex (unknown)
        0,     // #2501: fwd packets
        0,     // #2501: fwd bytes
        0,     // #2501: rev packets
        0,     // #2501: rev bytes
        0,     // #2749: src ToS
        0,     // #2749: TCP control bits
        0,     // #2749: egress ifindex
    );
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];
    assert_eq!(p[52], RT_FLOW_EVENT_SESSION_CLOSE);
    assert_eq!(p[55], RT_FLOW_AF_INET6);
    assert_eq!(p[53], 17);
    // full 16-byte v6 src address occupies [8..24].
    assert_eq!(
        &p[8..24],
        &Ipv6Addr::new(0x2001, 0x559, 0x8585, 0xbf01, 0, 0, 0, 0x102).octets()
    );
}

// #2508 fail-on-revert: the SESSION_CLOSE frame carries the per-policy SYSLOG
// gate in the final payload byte (offset 135). The frame is sent
// unconditionally (flowexport needs every close), so the gate byte is the ONLY
// signal that distinguishes a logged close from an unlogged one. If the
// encoder stops writing the gate byte, or hard-codes it, these assertions fail.
#[test]
fn test_session_close_rt_flow_log_gate_byte() {
    let mk = |log_syslog: bool| {
        EventFrame::encode_session_close_rt_flow(
            7,
            libc::AF_INET as u8,
            6,
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            12345,
            443,
            None,
            None,
            0,
            0,
            TEST_TRUST_ZONE_ID,
            TEST_UNTRUST_ZONE_ID,
            0, // #3056: admitting policy id
            0,
            log_syslog,
            0, // #2465: created Unix seconds
            0, // #2853: created sub-second nanos
            0, // #2465: close instant Unix ns
            0, // #2520: application id
            0, // #2615: ingress ifindex
            0, // #2501: fwd packets
            0, // #2501: fwd bytes
            0, // #2501: rev packets
            0, // #2501: rev bytes
            0, // #2749: src ToS
            0, // #2749: TCP control bits
            0, // #2749: egress ifindex
        )
    };
    let gated_off = mk(false);
    let p_off = &gated_off.data[FRAME_HEADER_SIZE..gated_off.len as usize];
    assert_eq!(p_off[135], 0, "log_syslog=false must clear the gate byte");

    let gated_on = mk(true);
    let p_on = &gated_on.data[FRAME_HEADER_SIZE..gated_on.len as usize];
    assert_eq!(
        p_on[135], RT_FLOW_LOG_SYSLOG,
        "log_syslog=true must set the gate byte"
    );
    // The frame type and event-type byte are unchanged regardless of the gate.
    assert_eq!(gated_on.data[4], MSG_SESSION_CLOSE_RT_FLOW);
    assert_eq!(p_on[52], RT_FLOW_EVENT_SESSION_CLOSE);
}

// #2508 fail-on-revert: the SESSION_CREATE frame is the new per-policy
// session-init producer. It must use frame type 15, event-type byte 1
// (SESSION_OPEN, renders as RT_FLOW_SESSION_CREATE on the Go side), and set
// the SYSLOG gate byte (it is producer-gated, only emitted when logging is
// requested). It must carry the 5-tuple and NAT slots.
#[test]
fn test_session_create_rt_flow_wire_layout() {
    let frame = EventFrame::encode_session_create_rt_flow(
        42,
        libc::AF_INET as u8,
        6, // TCP
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        12345,
        443,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        None,
        40000,
        0,
        TEST_TRUST_ZONE_ID,
        TEST_UNTRUST_ZONE_ID,
        42, // #3056: admitting policy id
        77, // #2615: ingress ifindex
        9,  // #2615: application id
    );
    assert_eq!(frame.data[4], MSG_SESSION_CREATE_RT_FLOW);
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];
    assert_eq!(p.len(), SECURITY_EVENT_PAYLOAD_SIZE);
    // event type = SESSION_OPEN (1) so the Go formatter emits SESSION_CREATE.
    assert_eq!(p[52], RT_FLOW_EVENT_SESSION_OPEN);
    assert_eq!(p[52], 1, "must equal the Go eventTypeSessionOpen value");
    assert_eq!(p[53], 6); // protocol
    assert_eq!(p[55], RT_FLOW_AF_INET);
    // gate byte set — producer only emits the frame when logging is requested.
    assert_eq!(p[135], RT_FLOW_LOG_SYSLOG);
    // 5-tuple: v4 src/dst left-aligned in the 16-byte slots, BE ports.
    assert_eq!(&p[8..12], &Ipv4Addr::new(10, 0, 1, 102).octets());
    assert_eq!(&p[24..28], &Ipv4Addr::new(172, 16, 80, 200).octets());
    assert_eq!(u16::from_be_bytes([p[40], p[41]]), 12345);
    assert_eq!(u16::from_be_bytes([p[42], p[43]]), 443);
    // NAT source slot populated.
    assert_eq!(&p[72..76], &Ipv4Addr::new(172, 16, 80, 8).octets());
    assert_eq!(u16::from_be_bytes([p[104], p[105]]), 40000);
    // #2615 fail-on-revert: the SESSION_CREATE frame now threads the ingress
    // ifindex ([128:132], LE u32) and the resolved application id
    // ([132:134], LE u16) — the same slots the Go DecodeRawEventRecord reads
    // to resolve packet-incoming-interface and application=. Reverting the
    // encoder to leave either slot 0 makes these assertions fail (and the
    // create record logs packet-incoming-interface="N/A" / application=
    // "UNKNOWN").
    assert_eq!(u32::from_le_bytes(p[128..132].try_into().unwrap()), 77);
    assert_eq!(u16::from_le_bytes([p[132], p[133]]), 9);
    // #3056 fail-on-revert: the SESSION_CREATE frame carries the admitting
    // policy ID in the [44:48] policy_id slot (LE u32) — the same slot the Go
    // decoder reads as PolicyID for non-close frames and resolves a policy name
    // from. Reverting the encoder to leave [44:48] 0 makes the create record
    // log policy 0 (the first configured policy) and this assertion fail.
    assert_eq!(u32::from_le_bytes(p[44..48].try_into().unwrap()), 42);
}

#[test]
fn test_policy_deny_dataplane_event_round_trip() {
    assert_dataplane_event_round_trip(
        test_dataplane_event_v4(DataplaneEventKind::PolicyDeny),
        MSG_POLICY_DENY,
    );
}

#[test]
fn test_screen_drop_dataplane_event_round_trip() {
    assert_dataplane_event_round_trip(
        test_dataplane_event_v6(DataplaneEventKind::ScreenDrop),
        MSG_SCREEN_DROP,
    );
}

#[test]
fn test_filter_log_dataplane_event_round_trip() {
    assert_dataplane_event_round_trip(
        test_dataplane_event_v4(DataplaneEventKind::FilterLog),
        MSG_FILTER_LOG,
    );
}

#[test]
fn test_filter_log_can_encode_discard_action() {
    let mut event = test_dataplane_event_v4(DataplaneEventKind::FilterLog);
    event.action = RT_FLOW_ACTION_DENY;
    let frame = EventFrame::encode_dataplane_event(321, &event);
    let payload = frame
        .dataplane_event_payload()
        .expect("security event payload");
    assert_eq!(payload[54], RT_FLOW_ACTION_DENY);
    assert_eq!(
        frame
            .decode_dataplane_event()
            .expect("decoded security event frame")
            .action,
        RT_FLOW_ACTION_DENY
    );
}

#[test]
fn test_policy_event_can_encode_reject_action() {
    let mut event = test_dataplane_event_v4(DataplaneEventKind::PolicyDeny);
    event.action = RT_FLOW_ACTION_REJECT;
    let frame = EventFrame::encode_dataplane_event(322, &event);
    let payload = frame
        .dataplane_event_payload()
        .expect("security event payload");
    assert_eq!(payload[54], RT_FLOW_ACTION_REJECT);
    assert_eq!(
        frame
            .decode_dataplane_event()
            .expect("decoded security event frame")
            .action,
        RT_FLOW_ACTION_REJECT
    );
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
    // #2467: OwnerRGID/EgressIfindex/TXIfindex are i32 LE at [10:14]/[14:18]/[18:22].
    assert_eq!(i32::from_le_bytes([p[10], p[11], p[12], p[13]]), 0); // OwnerRGID
    assert_eq!(i32::from_le_bytes([p[14], p[15], p[16], p[17]]), 3); // EgressIfindex
    assert_eq!(i32::from_le_bytes([p[18], p[19], p[20], p[21]]), 3); // TXIfindex
    assert_eq!(p[26], 0); // Flags (no fabric redirect, no fabric ingress)
    assert_eq!(p[27], TEST_TRUST_ZONE_ID as u8); // IngressZoneID
    assert_eq!(p[28], TEST_UNTRUST_ZONE_ID as u8); // EgressZoneID
    assert_eq!(p[29], DISP_FORWARD_CANDIDATE); // Disposition
}

// #2785: the per-policy `then log` selection must ride the open-frame flags
// byte (bits 1<<3/1<<4) so a synced session logs identically after failover.
// Reverting the codec.rs encode drops the bits and this fails RED.
#[test]
fn test_encode_session_open_carries_log_flags() {
    let zones = test_zone_map();
    let mut md = test_metadata();
    md.log_session_init = true;
    md.log_session_close = true;
    let frame =
        EventFrame::encode_session_open(1, &test_key_v4(), &test_decision(), &md, &zones, false);
    let p = &frame.data[FRAME_HEADER_SIZE..];
    assert_eq!(
        p[26] & FLAG_LOG_SESSION_INIT,
        FLAG_LOG_SESSION_INIT,
        "log_session_init must set flags bit 1<<3"
    );
    assert_eq!(
        p[26] & FLAG_LOG_SESSION_CLOSE,
        FLAG_LOG_SESSION_CLOSE,
        "log_session_close must set flags bit 1<<4"
    );

    // Only close set: init bit must stay clear.
    let mut md_close = test_metadata();
    md_close.log_session_close = true;
    let frame_close = EventFrame::encode_session_open(
        2,
        &test_key_v4(),
        &test_decision(),
        &md_close,
        &zones,
        false,
    );
    let pc = &frame_close.data[FRAME_HEADER_SIZE..];
    assert_eq!(pc[26] & FLAG_LOG_SESSION_INIT, 0);
    assert_eq!(pc[26] & FLAG_LOG_SESSION_CLOSE, FLAG_LOG_SESSION_CLOSE);

    // Default metadata: neither bit set.
    let frame_none = EventFrame::encode_session_open(
        3,
        &test_key_v4(),
        &test_decision(),
        &test_metadata(),
        &zones,
        false,
    );
    let pn = &frame_none.data[FRAME_HEADER_SIZE..];
    assert_eq!(pn[26] & (FLAG_LOG_SESSION_INIT | FLAG_LOG_SESSION_CLOSE), 0);
}

// #3301: the admitting policy's firewall metadata (policy_id,
// policy_counter_idx, inactivity_timeout seconds) rides the open frame as
// trailing fields after NextHop so a peer-promoted session is correctly
// attributed/counted/aged after failover. Reverting the codec.rs encode drops
// these and this fails RED.
#[test]
fn test_encode_session_open_carries_policy_fields_3301() {
    let zones = test_zone_map();
    let mut md = test_metadata();
    md.policy_id = 42;
    md.policy_counter_idx = 7;
    md.inactivity_timeout_ns = Some(30 * 1_000_000_000);
    let frame =
        EventFrame::encode_session_open(1, &test_key_v4(), &test_decision(), &md, &zones, false);
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];
    // v4 trailing block is the last 12 bytes: policy_id, policy_counter_idx,
    // inactivity_timeout (seconds), each u32 LE.
    let n = p.len();
    let policy_id = u32::from_le_bytes(p[n - 12..n - 8].try_into().unwrap());
    let counter_idx = u32::from_le_bytes(p[n - 8..n - 4].try_into().unwrap());
    let inact_secs = u32::from_le_bytes(p[n - 4..n].try_into().unwrap());
    assert_eq!(policy_id, 42, "policy_id must ride the open frame");
    assert_eq!(counter_idx, 7, "policy_counter_idx must ride the open frame");
    assert_eq!(inact_secs, 30, "inactivity_timeout (ns->s) must ride the open frame");

    // Default metadata => zeros (unattributed / no counter / global timeout).
    let frame_none = EventFrame::encode_session_open(
        2,
        &test_key_v4(),
        &test_decision(),
        &test_metadata(),
        &zones,
        false,
    );
    let pn = &frame_none.data[FRAME_HEADER_SIZE..frame_none.len as usize];
    let m = pn.len();
    assert_eq!(u32::from_le_bytes(pn[m - 12..m - 8].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(pn[m - 8..m - 4].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(pn[m - 4..m].try_into().unwrap()), 0);
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
    // #2467: p[14..18] OwnerRGID (i32 LE, was i16 at [14..16]).
    assert_eq!(i32::from_le_bytes([p[14], p[15], p[16], p[17]]), 1);
    // p[18] Flags
    assert_eq!(p[18], FLAG_FABRIC_REDIRECT);
    // #919/#922: p[19] IngressZoneID, p[20] EgressZoneID
    assert_eq!(p[19], TEST_TRUST_ZONE_ID as u8);
    assert_eq!(p[20], TEST_UNTRUST_ZONE_ID as u8);
}

// #2467: high (>32767) ifindexes must survive the wire encode. With the old
// i16 encoding, an ifindex of 70000 truncated to (70000 & 0xFFFF) = 4464 and,
// once reinterpreted as i16 on decode, sign-extended to a negative value. This
// test pins the i32 encode of the session-open identity fields so a revert to
// i16 (which would write only 2 bytes) fails RED. The full cross-language
// round-trip (Rust encode -> Go decode -> value preserved) is exercised by the
// Go TestDecodeSessionEvent*HighIfindex tests in pkg/dataplane/userspace.
#[test]
fn test_encode_session_open_high_ifindex_v4() {
    let zones = test_zone_map();
    let mut decision = test_decision();
    decision.resolution.egress_ifindex = 70000; // > i16::MAX
    decision.resolution.tx_ifindex = 65536; // > u16::MAX (would be 0 as i16)
    let mut metadata = test_metadata();
    metadata.owner_rg_id = 40000; // > i16::MAX

    let frame =
        EventFrame::encode_session_open(1, &test_key_v4(), &decision, &metadata, &zones, false);
    let p = &frame.data[FRAME_HEADER_SIZE..];

    // i32 LE reads recover the exact values; an i16 encode could not.
    assert_eq!(i32::from_le_bytes([p[10], p[11], p[12], p[13]]), 40000); // OwnerRGID
    assert_eq!(i32::from_le_bytes([p[14], p[15], p[16], p[17]]), 70000); // EgressIfindex
    assert_eq!(i32::from_le_bytes([p[18], p[19], p[20], p[21]]), 65536); // TXIfindex
    // Downstream fields must still land at their shifted offsets.
    assert_eq!(p[27], TEST_TRUST_ZONE_ID as u8); // IngressZoneID
    assert_eq!(p[28], TEST_UNTRUST_ZONE_ID as u8); // EgressZoneID
    assert_eq!(p[29], DISP_FORWARD_CANDIDATE); // Disposition
}

// #2467: session-close owner RG must also survive the i32 widen. The encoder
// accepts owner_rg_id as i32; this pins the 4-byte LE wire encoding.
#[test]
fn test_encode_session_close_high_owner_rg_v4() {
    let frame = EventFrame::encode_session_close(
        2,
        &test_key_v4(),
        40000, // owner_rg_id > i16::MAX
        FLAG_FABRIC_REDIRECT,
        TEST_TRUST_ZONE_ID,
        TEST_UNTRUST_ZONE_ID,
    );
    let p = &frame.data[FRAME_HEADER_SIZE..];
    // p[6..10] SrcIP, p[10..14] DstIP, p[14..18] OwnerRGID i32 LE.
    assert_eq!(i32::from_le_bytes([p[14], p[15], p[16], p[17]]), 40000);
    assert_eq!(p[18], FLAG_FABRIC_REDIRECT); // Flags
    assert_eq!(p[19], TEST_TRUST_ZONE_ID as u8); // IngressZoneID
    assert_eq!(p[20], TEST_UNTRUST_ZONE_ID as u8); // EgressZoneID
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
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        origin: crate::session::SessionOrigin::ForwardFlow,
        fabric_redirect_sync: true,
        created_ns: 0,
        last_seen_ns: 0,
        counters: crate::session::SessionCounters::default(),
        observed_tos: 0,
        observed_tcp_flags: 0,
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
