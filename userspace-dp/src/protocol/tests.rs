//! #1325: protocol-module integration test block.
//!
//! Pre-split, all of these tests lived in a single
//! `#[cfg(test)] mod tests { ... }` at the bottom of `protocol.rs`.
//! Post-split, they remain a single cohesive `#[cfg(test)] mod tests`
//! at the `protocol/` parent layer because every test exercises wire
//! contracts that span multiple sub-modules (ProcessStatus aggregates
//! BindingCountersSnapshot, WorkerRuntimeStatus, SourceNatPoolStatus,
//! etc.). The cross-domain placement rule (#1325 plan v3) puts the
//! ProcessStatus-rooted tests next to ProcessStatus; since
//! ProcessStatus lives in `control.rs` and the test types span every
//! sibling, the parent `protocol::tests` location is the simplest
//! correct home.
//!
//! Cross-module type references use `super::*` (re-exported via
//! `mod.rs` glob), which is equivalent to the absolute
//! `crate::protocol::X` form for this purpose.

use super::*;


#[test]
fn process_status_inject_packet_tuple_protocol_version_roundtrip() {
    let status = ProcessStatus {
        inject_packet_tuple_protocol_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(
        value["inject_packet_tuple_protocol_version"],
        INJECT_PACKET_TUPLE_PROTOCOL_VERSION
    );
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(
        back.inject_packet_tuple_protocol_version,
        INJECT_PACKET_TUPLE_PROTOCOL_VERSION
    );
}

#[test]
fn process_status_buffer_capacity_fields_roundtrip() {
    let status = ProcessStatus {
        session_table_entries: 77,
        max_sessions: 100,
        flow_cache_capacity: 4096,
        neighbor_entries: 9,
        neighbor_cache_capacity: 64,
        worker_runtime: vec![WorkerRuntimeStatus {
            worker_id: 2,
            session_table_entries: 77,
            max_sessions: 100,
            ..Default::default()
        }],
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["session_table_entries"], 77);
    assert_eq!(value["max_sessions"], 100);
    assert_eq!(value["flow_cache_capacity"], 4096);
    assert_eq!(value["neighbor_cache_capacity"], 64);
    assert_eq!(value["worker_runtime"][0]["session_table_entries"], 77);
    assert_eq!(value["worker_runtime"][0]["max_sessions"], 100);

    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.session_table_entries, 77);
    assert_eq!(back.max_sessions, 100);
    assert_eq!(back.flow_cache_capacity, 4096);
    assert_eq!(back.neighbor_cache_capacity, 64);
    assert_eq!(back.worker_runtime[0].session_table_entries, 77);
    assert_eq!(back.worker_runtime[0].max_sessions, 100);
}

#[test]
fn source_nat_persistent_fields_roundtrip() {
    let rule = SourceNATRuleSnapshot {
        name: "snat".into(),
        pool_name: "pool1".into(),
        persistent_nat: true,
        persistent_nat_permit_any_remote_host: true,
        persistent_nat_inactivity_timeout: 600,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&rule).expect("serialize SourceNATRuleSnapshot");
    assert_eq!(value["persistent_nat"], true);
    assert_eq!(value["persistent_nat_permit_any_remote_host"], true);
    assert_eq!(value["persistent_nat_inactivity_timeout"], 600);
    let back: SourceNATRuleSnapshot =
        serde_json::from_value(value).expect("deserialize SourceNATRuleSnapshot");
    assert!(back.persistent_nat);
    assert!(back.persistent_nat_permit_any_remote_host);
    assert_eq!(back.persistent_nat_inactivity_timeout, 600);
}

#[test]
fn process_status_source_nat_pool_status_roundtrip() {
    let status = ProcessStatus {
        source_nat_pools: vec![SourceNatPoolStatus {
            rule_name: "snat".into(),
            pool_name: "pool1".into(),
            persistent_nat: true,
            live_flows: 2,
            used_ports: 1,
            persistent_leases: 1,
            allocations_total: 1,
            reuses_total: 3,
            exhaustion_total: 5,
            ..Default::default()
        }],
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus");
    assert_eq!(value["source_nat_pools"][0]["pool_name"], "pool1");
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.source_nat_pools.len(), 1);
    assert_eq!(back.source_nat_pools[0].exhaustion_total, 5);
}

#[test]
fn inject_packet_request_tuple_metadata_wire_roundtrip() {
    let req = InjectPacketRequest {
        slot: 7,
        packet_length: 128,
        addr_family: libc::AF_INET as u8,
        protocol: 1,
        config_generation: 11,
        fib_generation: 12,
        metadata_valid: true,
        destination_ip: "172.16.80.200".into(),
        emit_on_wire: true,
        tuple_metadata_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
        source_ip: "172.16.80.8".into(),
        source_port: Some(4660),
        destination_port: Some(0),
    };
    let value: serde_json::Value =
        serde_json::to_value(&req).expect("serialize InjectPacketRequest to Value");
    let obj = value
        .as_object()
        .expect("InjectPacketRequest serializes as object");
    for key in [
        "tuple_metadata_version",
        "source_ip",
        "source_port",
        "destination_port",
    ] {
        assert!(
            obj.contains_key(key),
            "InjectPacketRequest wire key `{key}` missing: {value}"
        );
    }
    let back: InjectPacketRequest =
        serde_json::from_value(value).expect("deserialize InjectPacketRequest");
    assert_eq!(
        back.tuple_metadata_version,
        INJECT_PACKET_TUPLE_PROTOCOL_VERSION
    );
    assert_eq!(back.source_ip, "172.16.80.8");
    assert_eq!(back.source_port, Some(4660));
    assert_eq!(back.destination_port, Some(0));
}

#[test]
fn inject_packet_request_legacy_tuple_metadata_defaults_absent() {
    let legacy_json = r#"{
        "slot": 7,
        "packet_length": 128,
        "addr_family": 2,
        "protocol": 1,
        "metadata_valid": true,
        "destination_ip": "172.16.80.200",
        "emit_on_wire": true
    }"#;
    let req: InjectPacketRequest =
        serde_json::from_str(legacy_json).expect("legacy InjectPacketRequest decodes");
    assert_eq!(req.tuple_metadata_version, 0);
    assert_eq!(req.source_ip, "");
    assert_eq!(req.source_port, None);
    assert_eq!(req.destination_port, None);
}

// #825 plan §3.9 test #5: wire-format round-trip for
// BindingStatus. Construct with non-zero values on all four
// kick-latency fields, serialize, deserialize, assert equality.
// Companion to the BindingCountersSnapshot round-trip test in
// main.rs::tx_latency_hist_serialization_roundtrip — covers
// the rich BindingStatus wire shape that
// BindingCountersSnapshot projects from.
#[test]
fn tx_kick_latency_binding_status_wire_roundtrip() {
    let status = BindingStatus {
        worker_id: 3,
        slot: 7,
        ifindex: 11,
        queue_id: 2,
        tx_kick_latency_hist: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        tx_kick_latency_count: 136,
        tx_kick_latency_sum_ns: 1_234_567,
        tx_kick_retry_count: 42,
        ..Default::default()
    };

    let json = serde_json::to_string(&status).expect("serialize BindingStatus");
    let back: BindingStatus = serde_json::from_str(&json).expect("deserialize BindingStatus");
    assert_eq!(back.tx_kick_latency_hist, status.tx_kick_latency_hist);
    assert_eq!(back.tx_kick_latency_count, status.tx_kick_latency_count);
    assert_eq!(back.tx_kick_latency_sum_ns, status.tx_kick_latency_sum_ns);
    assert_eq!(back.tx_kick_retry_count, status.tx_kick_retry_count);
}

// #825 plan §3.9 test #5: pre-#825 JSON payload — fields absent
// — must deserialize with the four kick-latency fields defaulted
// to empty Vec / zero u64. This pins the additive-wire contract
// at the rich BindingStatus layer; the projection into
// BindingCountersSnapshot inherits the same defaulting.
#[test]
fn tx_kick_latency_binding_status_backward_compat() {
    // Minimum plausible BindingStatus payload predating #825.
    // All four kick-latency fields absent.
    let legacy_json = r#"{
        "worker_id": 1,
        "slot": 0,
        "ifindex": 0,
        "queue_id": 0
    }"#;
    let status: BindingStatus =
        serde_json::from_str(legacy_json).expect("pre-#825 payload decodes");
    assert!(
        status.tx_kick_latency_hist.is_empty(),
        "pre-#825 payload must default to empty Vec<u64>",
    );
    assert_eq!(status.tx_kick_latency_count, 0);
    assert_eq!(status.tx_kick_latency_sum_ns, 0);
    assert_eq!(status.tx_kick_retry_count, 0);
}

// #825 plan §3.9 test #5 final clause: From<&BindingStatus>
// propagates the four kick-latency fields onto
// BindingCountersSnapshot — pin that the projection doesn't
// silently drop any of them.
#[test]
fn tx_kick_latency_from_binding_status_propagates() {
    let status = BindingStatus {
        worker_id: 5,
        queue_id: 3,
        tx_kick_latency_hist: vec![100, 200, 300],
        tx_kick_latency_count: 600,
        tx_kick_latency_sum_ns: 987_654,
        tx_kick_retry_count: 7,
        ..Default::default()
    };

    let snap: BindingCountersSnapshot = (&status).into();
    assert_eq!(snap.tx_kick_latency_hist, status.tx_kick_latency_hist);
    assert_eq!(snap.tx_kick_latency_count, status.tx_kick_latency_count);
    assert_eq!(snap.tx_kick_latency_sum_ns, status.tx_kick_latency_sum_ns);
    assert_eq!(snap.tx_kick_retry_count, status.tx_kick_retry_count);
}

// #1241: pin the TX completion-ring availability wire keys at the
// rich BindingStatus layer and the lean BindingCountersSnapshot
// projection. Missing keys would decode as zeros on the Go side,
// exactly the failure mode this telemetry is meant to avoid before
// full fairness measurements.
#[test]
fn tx_completion_ring_binding_status_wire_roundtrip() {
    let status = BindingStatus {
        worker_id: 3,
        slot: 7,
        ifindex: 11,
        queue_id: 2,
        tx_completion_ring_available: 17,
        tx_completion_ring_available_max: 29,
        ..Default::default()
    };

    let json = serde_json::to_string(&status).expect("serialize BindingStatus");
    let value: serde_json::Value =
        serde_json::from_str(&json).expect("deserialize BindingStatus JSON");
    assert_eq!(value["tx_completion_ring_available"], 17);
    assert_eq!(value["tx_completion_ring_available_max"], 29);

    let back: BindingStatus = serde_json::from_str(&json).expect("deserialize BindingStatus");
    assert_eq!(back.tx_completion_ring_available, 17);
    assert_eq!(back.tx_completion_ring_available_max, 29);
}

#[test]
fn tx_completion_ring_from_binding_status_propagates() {
    let status = BindingStatus {
        worker_id: 5,
        queue_id: 3,
        tx_completion_ring_available: 31,
        tx_completion_ring_available_max: 47,
        ..Default::default()
    };

    let snap: BindingCountersSnapshot = (&status).into();
    assert_eq!(
        snap.tx_completion_ring_available,
        status.tx_completion_ring_available
    );
    assert_eq!(
        snap.tx_completion_ring_available_max,
        status.tx_completion_ring_available_max
    );
}

#[test]
fn flow_cache_capacity_binding_status_wire_roundtrip_and_projection() {
    let status = BindingStatus {
        worker_id: 3,
        slot: 7,
        ifindex: 11,
        queue_id: 2,
        active_flow_count: 53,
        flow_cache_capacity: 4096,
        ..Default::default()
    };

    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize BindingStatus to Value");
    assert_eq!(value["flow_cache_capacity"], 4096);

    let back: BindingStatus = serde_json::from_value(value).expect("deserialize BindingStatus");
    assert_eq!(back.flow_cache_capacity, status.flow_cache_capacity);

    let snap: BindingCountersSnapshot = (&status).into();
    assert_eq!(snap.active_flow_count, status.active_flow_count);
    assert_eq!(snap.flow_cache_capacity, status.flow_cache_capacity);
}

#[test]
fn mirror_counters_binding_status_wire_roundtrip_and_projection() {
    let status = BindingStatus {
        worker_id: 7,
        slot: 1,
        ifindex: 11,
        queue_id: 2,
        mirrored_packets: 5,
        mirrored_bytes: 640,
        mirror_drops_no_frame: 1,
        mirror_drops_tx_frame_reserve: 2,
        mirror_drops_no_binding: 3,
        mirror_drops_queue_full: 4,
        ..Default::default()
    };

    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize BindingStatus to Value");
    let obj = value
        .as_object()
        .expect("BindingStatus serializes as a JSON object");
    for key in [
        "mirrored_packets",
        "mirrored_bytes",
        "mirror_drops_no_frame",
        "mirror_drops_tx_frame_reserve",
        "mirror_drops_no_binding",
        "mirror_drops_queue_full",
    ] {
        assert!(
            obj.contains_key(key),
            "BindingStatus wire key `{key}` missing: {value}"
        );
    }

    let json = serde_json::to_string(&status).expect("serialize BindingStatus");
    let back: BindingStatus = serde_json::from_str(&json).expect("deserialize BindingStatus");
    assert_eq!(back.mirrored_packets, status.mirrored_packets);
    assert_eq!(back.mirrored_bytes, status.mirrored_bytes);
    assert_eq!(back.mirror_drops_no_frame, status.mirror_drops_no_frame);
    assert_eq!(
        back.mirror_drops_tx_frame_reserve,
        status.mirror_drops_tx_frame_reserve
    );
    assert_eq!(back.mirror_drops_no_binding, status.mirror_drops_no_binding);
    assert_eq!(back.mirror_drops_queue_full, status.mirror_drops_queue_full);

    let snap: BindingCountersSnapshot = (&status).into();
    assert_eq!(snap.mirrored_packets, status.mirrored_packets);
    assert_eq!(snap.mirrored_bytes, status.mirrored_bytes);
    assert_eq!(snap.mirror_drops_no_frame, status.mirror_drops_no_frame);
    assert_eq!(
        snap.mirror_drops_tx_frame_reserve,
        status.mirror_drops_tx_frame_reserve
    );
    assert_eq!(snap.mirror_drops_no_binding, status.mirror_drops_no_binding);
    assert_eq!(snap.mirror_drops_queue_full, status.mirror_drops_queue_full);
}

#[test]
fn syn_cookie_counters_binding_status_wire_roundtrip() {
    let status = BindingStatus {
        worker_id: 7,
        slot: 1,
        ifindex: 11,
        queue_id: 2,
        syn_cookie_challenges: 3,
        syn_cookie_secret_unavailable: 5,
        syn_cookie_syn_ack_sent: 7,
        syn_cookie_ack_rst_sent: 11,
        syn_cookie_reply_budget_drops: 13,
        syn_cookie_ack_valid: 17,
        syn_cookie_ack_invalid: 19,
        syn_cookie_bypass: 23,
        ..Default::default()
    };

    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize BindingStatus to Value");
    let obj = value
        .as_object()
        .expect("BindingStatus serializes as a JSON object");
    for key in [
        "syn_cookie_challenges",
        "syn_cookie_secret_unavailable",
        "syn_cookie_syn_ack_sent",
        "syn_cookie_ack_rst_sent",
        "syn_cookie_reply_budget_drops",
        "syn_cookie_ack_valid",
        "syn_cookie_ack_invalid",
        "syn_cookie_bypass",
    ] {
        assert!(
            obj.contains_key(key),
            "BindingStatus wire key `{key}` missing: {value}"
        );
    }

    let json = serde_json::to_string(&status).expect("serialize BindingStatus");
    let back: BindingStatus = serde_json::from_str(&json).expect("deserialize BindingStatus");
    assert_eq!(back.syn_cookie_challenges, status.syn_cookie_challenges);
    assert_eq!(
        back.syn_cookie_secret_unavailable,
        status.syn_cookie_secret_unavailable
    );
    assert_eq!(back.syn_cookie_syn_ack_sent, status.syn_cookie_syn_ack_sent);
    assert_eq!(back.syn_cookie_ack_rst_sent, status.syn_cookie_ack_rst_sent);
    assert_eq!(
        back.syn_cookie_reply_budget_drops,
        status.syn_cookie_reply_budget_drops
    );
    assert_eq!(back.syn_cookie_ack_valid, status.syn_cookie_ack_valid);
    assert_eq!(back.syn_cookie_ack_invalid, status.syn_cookie_ack_invalid);
    assert_eq!(back.syn_cookie_bypass, status.syn_cookie_bypass);
}

// #943 Copilot round-2 finding #3: the rich BindingStatus wire
// shape carries the two new V_min fields, but nothing pinned
// their wire keys at this layer. A future serde-rename typo
// would silently project as zeros into the Go consumer (which
// tolerates unknown fields). Round-trip + key-presence catches
// both directions of the contract here.
#[test]
fn v_min_throttle_binding_status_wire_roundtrip() {
    let status = BindingStatus {
        worker_id: 9,
        slot: 1,
        ifindex: 4,
        queue_id: 6,
        v_min_throttle_hard_cap_overrides: 71,
        v_min_throttles: 73,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize BindingStatus to Value");
    let obj = value
        .as_object()
        .expect("BindingStatus serializes as a JSON object");
    for key in ["v_min_throttle_hard_cap_overrides", "v_min_throttles"] {
        assert!(
            obj.contains_key(key),
            "BindingStatus wire key `{key}` missing: {value}"
        );
    }
    let json = serde_json::to_string(&status).expect("serialize BindingStatus");
    let back: BindingStatus = serde_json::from_str(&json).expect("deserialize BindingStatus");
    assert_eq!(
        back.v_min_throttle_hard_cap_overrides,
        status.v_min_throttle_hard_cap_overrides
    );
    assert_eq!(back.v_min_throttles, status.v_min_throttles);
}

#[test]
fn policy_rule_snapshot_scheduler_fields_round_trip() {
    let snap = PolicyRuleSnapshot {
        rule_id: "security-policy:trust:untrust:allow-web".into(),
        policy_id: 17,
        name: "allow-web".into(),
        from_zone: "trust".into(),
        to_zone: "untrust".into(),
        scheduler_name: "workhours".into(),
        inactive: true,
        source_addresses: vec!["any".into()],
        destination_addresses: vec!["any".into()],
        applications: vec!["junos-http".into()],
        action: "permit".into(),
        ..Default::default()
    };

    let value: serde_json::Value =
        serde_json::to_value(&snap).expect("serialize PolicyRuleSnapshot to Value");
    assert_eq!(value["rule_id"], "security-policy:trust:untrust:allow-web");
    assert_eq!(value["policy_id"], 17);
    assert_eq!(value["scheduler_name"], "workhours");
    assert_eq!(value["inactive"], true);

    let back: PolicyRuleSnapshot =
        serde_json::from_value(value).expect("deserialize PolicyRuleSnapshot");
    assert_eq!(back.rule_id, snap.rule_id);
    assert_eq!(back.policy_id, snap.policy_id);
    assert_eq!(back.scheduler_name, snap.scheduler_name);
    assert_eq!(back.inactive, snap.inactive);
}

#[test]
fn policy_rule_snapshot_legacy_scheduler_fields_default() {
    let legacy_json = r#"{
        "name": "allow-web",
        "from_zone": "trust",
        "to_zone": "untrust",
        "source_addresses": ["any"],
        "destination_addresses": ["any"],
        "applications": ["junos-http"],
        "action": "permit"
    }"#;

    let snap: PolicyRuleSnapshot =
        serde_json::from_str(legacy_json).expect("pre-#1378 PolicyRuleSnapshot decodes");
    assert_eq!(snap.rule_id, "");
    assert_eq!(snap.policy_id, 0);
    assert_eq!(snap.scheduler_name, "");
    assert_eq!(snap.inactive, false);
}

// #915 forward-compat: a pre-#915 CoSSchedulerSnapshot
// payload (no `surplus_sharing` field) must decode with
// `surplus_sharing == false` so the runtime sees the field
// as absent = opt-out, preserving Junos `transmit-rate
// exact` hard-cap semantics for older snapshot writers.
// Codex round-1 MAJOR 3 + Gemini round-1 #7.
#[test]
fn cos_scheduler_snapshot_surplus_sharing_default_false() {
    let legacy_json = r#"{
        "name": "iperf-a",
        "transmit_rate_bytes": 125000000,
        "transmit_rate_exact": true,
        "priority": "low",
        "buffer_size_bytes": 65536
    }"#;
    let snap: CoSSchedulerSnapshot =
        serde_json::from_str(legacy_json).expect("pre-#915 CoSSchedulerSnapshot decodes");
    assert_eq!(
        snap.surplus_sharing, false,
        "surplus_sharing must default to false for pre-#915 snapshots"
    );
    assert_eq!(
        snap.equal_flow_enforcement, false,
        "equal_flow_enforcement must default to false for older snapshots"
    );
    assert_eq!(
        snap.buffer_size_percent, 0.0,
        "buffer_size_percent must default to 0 for pre-#1336 snapshots"
    );
    assert_eq!(snap.transmit_rate_exact, true);
}

#[test]
fn cos_scheduler_snapshot_surplus_sharing_round_trip_true() {
    let snap = CoSSchedulerSnapshot {
        name: "iperf-a".into(),
        transmit_rate_bytes: 125_000_000,
        transmit_rate_exact: true,
        priority: "low".into(),
        buffer_size_bytes: 65_536,
        buffer_size_percent: 0.0,
        surplus_sharing: true,
        equal_flow_enforcement: false,
    };
    let json = serde_json::to_string(&snap).expect("serialize");
    let back: CoSSchedulerSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.surplus_sharing, true);
}

#[test]
fn cos_scheduler_snapshot_equal_flow_enforcement_round_trip_true() {
    let snap = CoSSchedulerSnapshot {
        name: "iperf-a".into(),
        transmit_rate_bytes: 125_000_000,
        transmit_rate_exact: true,
        priority: "low".into(),
        buffer_size_bytes: 65_536,
        buffer_size_percent: 0.0,
        surplus_sharing: false,
        equal_flow_enforcement: true,
    };
    let json = serde_json::to_string(&snap).expect("serialize");
    let back: CoSSchedulerSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.equal_flow_enforcement, true);
}

#[test]
fn cos_scheduler_snapshot_buffer_size_percent_round_trip() {
    let snap = CoSSchedulerSnapshot {
        name: "percent-sched".into(),
        transmit_rate_bytes: 125_000_000,
        transmit_rate_exact: true,
        priority: "low".into(),
        buffer_size_bytes: 0,
        buffer_size_percent: 10.0,
        surplus_sharing: false,
        equal_flow_enforcement: false,
    };
    let json = serde_json::to_string(&snap).expect("serialize");
    assert!(
        json.contains("buffer_size_percent"),
        "percent field must be present in serialized scheduler JSON: {}",
        json
    );
    let back: CoSSchedulerSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.buffer_size_percent, 10.0);
    assert_eq!(back.buffer_size_bytes, 0);
}

// #943 additive-wire contract: a pre-#943 BindingStatus payload
// with both V_min fields absent must decode with zero defaults,
// matching the same defaulting pattern the kick-latency fields
// use above. Without this, the projection's `..Default::default`
// would compile but the wire side could silently break.
#[test]
fn v_min_throttle_binding_status_backward_compat() {
    let legacy_json = r#"{
        "worker_id": 1,
        "slot": 0,
        "ifindex": 0,
        "queue_id": 0
    }"#;
    let status: BindingStatus =
        serde_json::from_str(legacy_json).expect("pre-#943 payload decodes");
    assert_eq!(status.v_min_throttle_hard_cap_overrides, 0);
    assert_eq!(status.v_min_throttles, 0);
}
