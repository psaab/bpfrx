// #6312: the JSON leg of the session-delta wire must carry the #5212 stable
// RT_FLOW session id, at parity with the binary event-stream open frame.
//
// The JSON `SessionDeltaInfo` is what the `drain_session_deltas` polling
// fallback (used whenever the binary event stream is down) and the owner-RG
// resync export put on the control-plane RPC. Before this it had no session-id
// field at all, so every session recovered through that leg imported id 0 and
// the peer minted a fresh local one — the originating node's SESSION_CREATE and
// the peer's post-failover SESSION_CLOSE no longer shared an id.
//
// Sibling `#[path]` test module loaded from afxdp/mod.rs, mirroring the #4840
// split.
#![allow(unused_imports)]

use super::session_delta::session_delta_info;
use super::*;
use crate::nat::NatDecision;
use crate::session::{
    SessionCounters, SessionDecision, SessionDelta, SessionDeltaKind, SessionKey, SessionMetadata,
    SessionOrigin,
};
use std::net::{IpAddr, Ipv4Addr};

fn delta_with_session_id(session_id: u64) -> SessionDelta {
    SessionDelta {
        kind: SessionDeltaKind::Open,
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 2,
                egress_ifindex: 3,
                tx_ifindex: 3,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        },
        metadata: SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: SessionCounters::default(),
        observed_tos: 0,
        observed_tcp_flags: 0,
        session_id,
    }
}

fn test_binding_identity() -> BindingIdentity {
    BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 7,
        interface: Arc::from("ge-0-0-1"),
        ifindex: 12,
    }
}

fn zone_names() -> FastMap<u16, String> {
    let mut m: FastMap<u16, String> = FastMap::default();
    m.insert(1, "lan".to_string());
    m.insert(2, "wan".to_string());
    m
}

/// Fail-on-revert: drop `rt_flow_session_id: delta.session_id` from
/// `session_delta_info` and the id arrives as 0, so the peer allocates a fresh
/// local id and the cross-node correlation is lost.
#[test]
fn session_delta_info_carries_rt_flow_session_id_6312() {
    let want = 7u64 << 48 | 0x1234_5678;
    let info = session_delta_info(
        &test_binding_identity(),
        &delta_with_session_id(want),
        &zone_names(),
    );
    assert_eq!(
        info.rt_flow_session_id, want,
        "the JSON resync leg must carry the originating node's stable RT_FLOW \
         session id, like the binary open frame does (#6312)"
    );
    // Positive control: this really is the delta -> JSON conversion, so a
    // mismatch above cannot be a wrongly-built fixture.
    assert_eq!(info.src_port, 12345, "conversion produced the delta's tuple");
    assert_eq!(info.ingress_zone, "lan", "conversion resolved zone names");
}

/// The wire KEY is the cross-language contract: the Go consumer decodes this
/// field as `SessionDeltaInfo.RTFlowSessionID` with `json:"rt_flow_session_id"`
/// (pkg/dataplane/userspace/protocol_ha.go). A rename on this side would ship a
/// key the Go decoder ignores — the field would be present and the id still
/// silently lost, which the struct-level assertion above cannot see.
#[test]
fn session_delta_info_rt_flow_session_id_wire_key_6312() {
    let want = 0x0BAD_F00D_u64;
    let info = session_delta_info(
        &test_binding_identity(),
        &delta_with_session_id(want),
        &zone_names(),
    );
    let v: serde_json::Value = serde_json::to_value(&info).expect("serialize SessionDeltaInfo");
    let on_wire = v
        .get("rt_flow_session_id")
        .unwrap_or_else(|| panic!("no `rt_flow_session_id` key on the wire: {v}"));
    assert_eq!(
        on_wire.as_u64(),
        Some(want),
        "`rt_flow_session_id` must carry the id verbatim: {v}"
    );
}

/// A delta with no backing entry (`session_id == 0`) must still emit the key
/// carrying 0 — the pre-existing "no id" sentinel the peer maps to a fresh local
/// allocation. This is the rolling-upgrade fallback, so it must not become an
/// absent key or a synthesized non-zero value.
#[test]
fn session_delta_info_zero_session_id_is_the_no_id_sentinel_6312() {
    let info = session_delta_info(
        &test_binding_identity(),
        &delta_with_session_id(0),
        &zone_names(),
    );
    assert_eq!(info.rt_flow_session_id, 0);
    let v: serde_json::Value = serde_json::to_value(&info).expect("serialize SessionDeltaInfo");
    assert_eq!(
        v.get("rt_flow_session_id").and_then(|x| x.as_u64()),
        Some(0),
        "the zero sentinel must still ride the wire: {v}"
    );
}
