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

// #1771 §2.6: round-trip + backward-compat pin for the resolver
// backoff-retry counter, the §2.5 ENOBUFS/re-dump counters, and the
// pending-keys / negative-keys gauges. The wire keys feed
// pkg/dataplane/userspace/protocol.go and the Prometheus families
// `xpf_userspace_neighbor_resolver_get_backoff_attempts_total`,
// `xpf_userspace_neighbor_netlink_{enobufs,redumps,redump_upserts}_total`,
// `xpf_userspace_neighbor_pending_keys`, `xpf_userspace_neg_neigh_keys`.
#[test]
fn process_status_neighbor_phase3_counters_roundtrip() {
    let status = ProcessStatus {
        neighbor_resolver_get_backoff_attempts_total: 7,
        neighbor_netlink_enobufs_total: 3,
        neighbor_netlink_redumps_total: 2,
        neighbor_netlink_redump_upserts_total: 11,
        neighbor_pending_keys: 4,
        neg_neigh_keys: 5,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    let keys = [
        ("neighbor_resolver_get_backoff_attempts_total", 7u64),
        ("neighbor_netlink_enobufs_total", 3),
        ("neighbor_netlink_redumps_total", 2),
        ("neighbor_netlink_redump_upserts_total", 11),
        ("neighbor_pending_keys", 4),
        ("neg_neigh_keys", 5),
    ];
    for (key, want) in keys {
        assert_eq!(value[key], want, "wire key {key}");
    }
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.neighbor_resolver_get_backoff_attempts_total, 7);
    assert_eq!(back.neighbor_netlink_enobufs_total, 3);
    assert_eq!(back.neighbor_netlink_redumps_total, 2);
    assert_eq!(back.neighbor_netlink_redump_upserts_total, 11);
    assert_eq!(back.neighbor_pending_keys, 4);
    assert_eq!(back.neg_neigh_keys, 5);

    // Pre-Phase-3 payload (keys absent) must decode with zero defaults.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    for (key, _) in keys {
        legacy_value
            .as_object_mut()
            .expect("ProcessStatus serializes to an object")
            .remove(key)
            .unwrap_or_else(|| panic!("new key {key} present before strip"));
    }
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-Phase-3 payload decodes");
    assert_eq!(legacy.neighbor_resolver_get_backoff_attempts_total, 0);
    assert_eq!(legacy.neighbor_netlink_enobufs_total, 0);
    assert_eq!(legacy.neighbor_netlink_redumps_total, 0);
    assert_eq!(legacy.neighbor_netlink_redump_upserts_total, 0);
    assert_eq!(legacy.neighbor_pending_keys, 0);
    assert_eq!(legacy.neg_neigh_keys, 0);
}

// #1807: round-trip + backward-compat pin for the worker-command-queue
// poison-recovery counter. The wire key feeds
// pkg/dataplane/userspace/protocol.go and the Prometheus counter
// `xpf_userspace_worker_command_queue_poison_recoveries_total`.
#[test]
fn process_status_worker_command_queue_poison_recoveries_roundtrip() {
    let status = ProcessStatus {
        worker_command_queue_poison_recoveries: 3,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["worker_command_queue_poison_recoveries"], 3);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.worker_command_queue_poison_recoveries, 3);

    // Pre-#1807 payload (key absent) must decode with a zero default.
    // ProcessStatus has required fields, so build the legacy document by
    // stripping the new key from a serialized Default instance.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object")
        .remove("worker_command_queue_poison_recoveries")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#1807 payload decodes");
    assert_eq!(legacy.worker_command_queue_poison_recoveries, 0);
}

// #1760 W3': round-trip + backward-compat pin for the shared-map NAT
// reverse-key displacement counter. The wire key feeds
// pkg/dataplane/userspace/protocol.go and the Prometheus counter
// `xpf_userspace_session_nat_reverse_key_shared_displacements_total`.
#[test]
fn process_status_nat_reverse_key_shared_displacements_roundtrip() {
    let status = ProcessStatus {
        nat_reverse_key_shared_displacements_total: 7,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["nat_reverse_key_shared_displacements_total"], 7);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.nat_reverse_key_shared_displacements_total, 7);

    // Pre-#1760-W3' payload (key absent) must decode with a zero default.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object")
        .remove("nat_reverse_key_shared_displacements_total")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#1760-W3' payload decodes");
    assert_eq!(legacy.nat_reverse_key_shared_displacements_total, 0);
}

// #1861: round-trip + backward-compat pin for the install-refusal trio
// (transactional session install). The wire keys feed
// pkg/dataplane/userspace/protocol.go and the Prometheus counters
// `xpf_userspace_session_create_drops_total` /
// `xpf_userspace_session_install_admission_refused_total` /
// `xpf_userspace_session_install_partial_total` (+ per-worker copies).
#[test]
fn install_refusal_trio_roundtrip_and_key_absent_defaults() {
    let status = ProcessStatus {
        session_create_drops: 7,
        session_install_admission_refused: 5,
        session_install_partial: 1,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["session_create_drops"], 7);
    assert_eq!(value["session_install_admission_refused"], 5);
    assert_eq!(value["session_install_partial"], 1);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.session_create_drops, 7);
    assert_eq!(back.session_install_admission_refused, 5);
    assert_eq!(back.session_install_partial, 1);

    // Pre-#1861 payload (keys absent) must decode with zero defaults.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    let obj = legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object");
    for key in [
        "session_create_drops",
        "session_install_admission_refused",
        "session_install_partial",
    ] {
        obj.remove(key).expect("new key present before strip");
    }
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#1861 payload decodes");
    assert_eq!(legacy.session_create_drops, 0);
    assert_eq!(legacy.session_install_admission_refused, 0);
    assert_eq!(legacy.session_install_partial, 0);

    // Same contract for the per-worker WorkerRuntimeStatus copies.
    let worker = WorkerRuntimeStatus {
        session_create_drops: 3,
        session_install_admission_refused: 2,
        session_install_partial: 1,
        ..Default::default()
    };
    let value = serde_json::to_value(&worker).expect("serialize WorkerRuntimeStatus to Value");
    assert_eq!(value["session_create_drops"], 3);
    let back: WorkerRuntimeStatus =
        serde_json::from_value(value).expect("deserialize WorkerRuntimeStatus");
    assert_eq!(back.session_create_drops, 3);
    assert_eq!(back.session_install_admission_refused, 2);
    assert_eq!(back.session_install_partial, 1);
    let mut legacy_value = serde_json::to_value(WorkerRuntimeStatus::default())
        .expect("serialize default WorkerRuntimeStatus");
    let obj = legacy_value
        .as_object_mut()
        .expect("WorkerRuntimeStatus serializes to an object");
    for key in [
        "session_create_drops",
        "session_install_admission_refused",
        "session_install_partial",
    ] {
        obj.remove(key).expect("new key present before strip");
    }
    let legacy: WorkerRuntimeStatus =
        serde_json::from_value(legacy_value).expect("pre-#1861 worker payload decodes");
    assert_eq!(legacy.session_create_drops, 0);
    assert_eq!(legacy.session_install_admission_refused, 0);
    assert_eq!(legacy.session_install_partial, 0);
}

// #1621 plan v2 + Copilot code-r1 C4: round-trip the new cold-path
// histogram fields through serde to confirm:
//   1. Default (zero / empty) WorkerRuntimeStatus omits every
//      cold_path_* field from the wire (skip_serializing_if).
//   2. Populated cold_path_* fields survive serialize → deserialize.
//   3. clock_source String preserves "tsc" exactly.
#[test]
fn worker_runtime_status_cold_path_fields_roundtrip_default_omitted() {
    let status = WorkerRuntimeStatus::default();
    let value: serde_json::Value = serde_json::to_value(&status)
        .expect("serialize default WorkerRuntimeStatus");
    // Every cold_path_* field MUST be absent in the JSON for a
    // default (uncalibrated) worker. This pins the wire-invariant
    // contract that pre-#1621 daemons see byte-identical payloads.
    let cold_keys = [
        // #1635 sparse v3 fields.
        "cold_path_layout_version",
        "cold_path_active_slot_ids",
        "cold_path_active_zone_from",
        "cold_path_active_zone_to",
        "cold_path_active_samples",
        "cold_path_active_sum_ns",
        "cold_path_active_buckets",
        "cold_path_active_builder_collision",
        "cold_path_overflow_active",
        "cold_path_sample_phase",
        "cold_path_wrapper_underflow_count",
        "cold_path_ns_per_tsc_q32",
        "cold_path_wrapper_ns_baseline",
        "cold_path_clock_source",
        "cold_path_snapshot_failed",
    ];
    if let Some(obj) = value.as_object() {
        for k in cold_keys {
            assert!(
                !obj.contains_key(k),
                "default WorkerRuntimeStatus must omit {k} on wire; got {value}"
            );
        }
    } else {
        panic!("expected JSON object, got {value:?}");
    }
}

#[test]
fn worker_runtime_status_cold_path_fields_roundtrip_populated() {
    // #1635 sparse v3 encoding: two active zone-pair slots.
    let buckets_a = {
        let mut b = vec![0u64; 48];
        b[5] = 42;
        b[6] = 100;
        b
    };
    let buckets_b = {
        let mut b = vec![0u64; 48];
        b[0] = 7;
        b
    };

    let status = WorkerRuntimeStatus {
        worker_id: 2,
        cold_path_layout_version: 3,
        cold_path_active_slot_ids: vec![0, 5],
        cold_path_active_zone_from: vec![1, 2],
        cold_path_active_zone_to: vec![3, 4],
        cold_path_active_samples: vec![142, 7],
        cold_path_active_sum_ns: vec![12345, 700],
        cold_path_active_buckets: vec![buckets_a.clone(), buckets_b.clone()],
        cold_path_active_builder_collision: vec![false, false],
        cold_path_overflow_active: true,
        cold_path_sample_phase: 50_000,
        cold_path_wrapper_underflow_count: 3,
        cold_path_ns_per_tsc_q32: 1_871_674_289,
        cold_path_wrapper_ns_baseline: 45,
        cold_path_clock_source: "tsc".into(),
        cold_path_snapshot_failed: 2,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize populated");
    // Spot-check a few fields are present + correctly nested.
    assert_eq!(value["cold_path_layout_version"], 3);
    assert_eq!(value["cold_path_sample_phase"], 50_000);
    assert_eq!(value["cold_path_clock_source"], "tsc");
    assert_eq!(value["cold_path_snapshot_failed"], 2);
    assert_eq!(value["cold_path_active_zone_from"][0], 1);
    assert_eq!(value["cold_path_active_zone_to"][1], 4);
    assert_eq!(value["cold_path_active_samples"][0], 142);
    assert_eq!(value["cold_path_active_buckets"][0][5], 42);
    assert_eq!(value["cold_path_active_buckets"][0][6], 100);
    assert_eq!(value["cold_path_overflow_active"], true);

    // Round-trip back.
    let back: WorkerRuntimeStatus =
        serde_json::from_value(value).expect("deserialize");
    assert_eq!(back.cold_path_layout_version, 3);
    assert_eq!(back.cold_path_active_slot_ids, vec![0, 5]);
    assert_eq!(back.cold_path_active_zone_from, vec![1, 2]);
    assert_eq!(back.cold_path_active_zone_to, vec![3, 4]);
    assert_eq!(back.cold_path_active_samples, vec![142, 7]);
    assert_eq!(back.cold_path_active_sum_ns, vec![12345, 700]);
    assert_eq!(back.cold_path_active_buckets, vec![buckets_a, buckets_b]);
    assert_eq!(back.cold_path_active_builder_collision, vec![false, false]);
    assert!(back.cold_path_overflow_active);
    assert_eq!(back.cold_path_sample_phase, 50_000);
    assert_eq!(back.cold_path_wrapper_underflow_count, 3);
    assert_eq!(back.cold_path_ns_per_tsc_q32, 1_871_674_289);
    assert_eq!(back.cold_path_wrapper_ns_baseline, 45);
    assert_eq!(back.cold_path_clock_source, "tsc");
    assert_eq!(back.cold_path_snapshot_failed, 2);
}

// #1782 Step-1: round-trip + backward-compat (key-absent) pin for the
// cold-start CoS instruments on WorkerRuntimeStatus. The wire keys feed
// pkg/dataplane/userspace/protocol.go and the Prometheus families
// xpf_userspace_worker_cos_wheel_ticks_advanced_{total,max} and
// xpf_userspace_worker_cos_queue_lease_undergrant_total{cause}.
#[test]
fn worker_runtime_status_cos_coldstart_counters_roundtrip() {
    let status = WorkerRuntimeStatus {
        cos_wheel_ticks_advanced_total: 1_000_001,
        cos_wheel_ticks_advanced_max: 999_999,
        cos_queue_lease_undergrant_seqlock_give_up: 1,
        cos_queue_lease_undergrant_cap_zero: 2,
        cos_queue_lease_undergrant_epoch_rotated: 3,
        cos_queue_lease_undergrant_share_exhausted: 4,
        cos_queue_lease_undergrant_class_cap: 5,
        cos_queue_lease_undergrant_outstanding_cap: 6,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize WorkerRuntimeStatus to Value");
    let keys = [
        ("cos_wheel_ticks_advanced_total", 1_000_001u64),
        ("cos_wheel_ticks_advanced_max", 999_999),
        ("cos_queue_lease_undergrant_seqlock_give_up", 1),
        ("cos_queue_lease_undergrant_cap_zero", 2),
        ("cos_queue_lease_undergrant_epoch_rotated", 3),
        ("cos_queue_lease_undergrant_share_exhausted", 4),
        ("cos_queue_lease_undergrant_class_cap", 5),
        ("cos_queue_lease_undergrant_outstanding_cap", 6),
    ];
    for (key, want) in keys {
        assert_eq!(value[key], want, "wire key {key}");
    }
    let back: WorkerRuntimeStatus =
        serde_json::from_value(value).expect("deserialize WorkerRuntimeStatus");
    assert_eq!(back.cos_wheel_ticks_advanced_total, 1_000_001);
    assert_eq!(back.cos_wheel_ticks_advanced_max, 999_999);
    assert_eq!(back.cos_queue_lease_undergrant_seqlock_give_up, 1);
    assert_eq!(back.cos_queue_lease_undergrant_cap_zero, 2);
    assert_eq!(back.cos_queue_lease_undergrant_epoch_rotated, 3);
    assert_eq!(back.cos_queue_lease_undergrant_share_exhausted, 4);
    assert_eq!(back.cos_queue_lease_undergrant_class_cap, 5);
    assert_eq!(back.cos_queue_lease_undergrant_outstanding_cap, 6);

    // Pre-#1782-Step-1 payload (keys absent) must decode with zero
    // defaults — the mixed-version back-compat contract.
    let mut legacy_value = serde_json::to_value(WorkerRuntimeStatus::default())
        .expect("serialize default WorkerRuntimeStatus");
    for (key, _) in keys {
        legacy_value
            .as_object_mut()
            .expect("WorkerRuntimeStatus serializes to an object")
            .remove(key)
            .unwrap_or_else(|| panic!("new key {key} present before strip"));
    }
    let legacy: WorkerRuntimeStatus =
        serde_json::from_value(legacy_value).expect("pre-Step-1 payload decodes");
    assert_eq!(legacy.cos_wheel_ticks_advanced_total, 0);
    assert_eq!(legacy.cos_wheel_ticks_advanced_max, 0);
    assert_eq!(legacy.cos_queue_lease_undergrant_seqlock_give_up, 0);
    assert_eq!(legacy.cos_queue_lease_undergrant_cap_zero, 0);
    assert_eq!(legacy.cos_queue_lease_undergrant_epoch_rotated, 0);
    assert_eq!(legacy.cos_queue_lease_undergrant_share_exhausted, 0);
    assert_eq!(legacy.cos_queue_lease_undergrant_class_cap, 0);
    assert_eq!(legacy.cos_queue_lease_undergrant_outstanding_cap, 0);
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
        equal_flow_target_policy: String::new(),
    codel_target_ns: 0,
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
        equal_flow_target_policy: String::new(),
    codel_target_ns: 0,
    };
    let json = serde_json::to_string(&snap).expect("serialize");
    let back: CoSSchedulerSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.equal_flow_enforcement, true);
}

#[test]
fn cos_scheduler_snapshot_equal_flow_target_policy_round_trip() {
    // #1746: policy string survives the wire; absent field (older
    // snapshots / unset configs) decodes to the empty default, and an
    // unset policy serializes WITHOUT the field on the Go side
    // (omitempty) — the Rust serde default keeps decode compatible.
    let snap = CoSSchedulerSnapshot {
        name: "iperf-a".into(),
        transmit_rate_bytes: 125_000_000,
        transmit_rate_exact: true,
        priority: "low".into(),
        buffer_size_bytes: 65_536,
        buffer_size_percent: 0.0,
        surplus_sharing: false,
        equal_flow_enforcement: true,
        equal_flow_target_policy: "mean".into(),
        codel_target_ns: 0,
    };
    let json = serde_json::to_string(&snap).expect("serialize");
    let back: CoSSchedulerSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.equal_flow_target_policy, "mean");

    // Older snapshot without the field decodes to the default "".
    let legacy = r#"{"name":"iperf-a","transmit_rate_bytes":125000000,"transmit_rate_exact":true,"equal_flow_enforcement":true}"#;
    let back: CoSSchedulerSnapshot = serde_json::from_str(legacy).expect("legacy deserialize");
    assert_eq!(back.equal_flow_target_policy, "");
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
        equal_flow_target_policy: String::new(),
    codel_target_ns: 0,
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

// ---------------------------------------------------------------------------
// #1325: differential wire-format invariant.
//
// Builds a fixed-shape JSON document by serializing
// `Default::default()` instances of every top-level wire type, and
// compares against a checked-in fixture at
// `tests/fixtures/protocol_wire_v1.json`. The fixture is committed
// alongside this test; a future wire-evolving PR has to either
// regenerate the fixture (XPF_PROTOCOL_WIRE_REGEN=1) and review the
// diff, or fail the test.
//
// Scope vs #1325 plan v3: the plan called for an exhaustive
// struct-literal-driven specimen tree. That approach hit ~1000
// LOC of boilerplate that proved fragile to incremental field
// changes mid-implementation. The simpler Default-based approach
// here detects:
//   - any #[serde(rename = ...)] field-key change (key set must match)
//   - any field added without `skip_serializing_if` (new key)
//   - any field removed (missing key)
// Residual gap (fields with `skip_serializing_if = "Option::is_none"`
// defaulting to None) is covered by the inline serde round-trip
// tests above (which DO populate the high-risk types) plus the Go
// control-plane consumption gate.
// ---------------------------------------------------------------------------

#[test]
fn wire_invariant_default_specimens() {
    use serde_json::{Map, Value};

    fn dump<T: serde::Serialize>(value: &T) -> Value {
        serde_json::to_value(value).expect("specimen serializes")
    }

    // Build the specimen map explicitly (no json! macro) to dodge
    // serde_json's recursion limit on a 60+ element literal. Order
    // is preserved by serde_json::Map (BTreeMap-backed), so the
    // fixture output is stable across runs.
    let mut s: Map<String, Value> = Map::new();
    s.insert("binding_control_request".into(), dump(&BindingControlRequest::default()));
    s.insert("binding_counters_snapshot".into(), dump(&BindingCountersSnapshot::default()));
    s.insert("binding_status".into(), dump(&BindingStatus::default()));
    s.insert("class_of_service_snapshot".into(), dump(&ClassOfServiceSnapshot::default()));
    s.insert("config_snapshot".into(), dump(&ConfigSnapshot::default()));
    s.insert("control_request".into(), dump(&ControlRequest::default()));
    s.insert("control_response".into(), dump(&ControlResponse::default()));
    s.insert("cos_active_flow_count_status".into(), dump(&CoSActiveFlowCountStatus::default()));
    s.insert("cos_dscp_classifier_entry_snapshot".into(), dump(&CoSDSCPClassifierEntrySnapshot::default()));
    s.insert("cos_dscp_classifier_snapshot".into(), dump(&CoSDSCPClassifierSnapshot::default()));
    s.insert("cos_dscp_rewrite_rule_entry_snapshot".into(), dump(&CoSDSCPRewriteRuleEntrySnapshot::default()));
    s.insert("cos_dscp_rewrite_rule_snapshot".into(), dump(&CoSDSCPRewriteRuleSnapshot::default()));
    s.insert("cos_forwarding_class_snapshot".into(), dump(&CoSForwardingClassSnapshot::default()));
    s.insert("cos_ieee8021_classifier_entry_snapshot".into(), dump(&CoSIEEE8021ClassifierEntrySnapshot::default()));
    s.insert("cos_ieee8021_classifier_snapshot".into(), dump(&CoSIEEE8021ClassifierSnapshot::default()));
    s.insert("cos_interface_status".into(), dump(&CoSInterfaceStatus::default()));
    s.insert("cos_queue_status".into(), dump(&CoSQueueStatus::default()));
    s.insert("cos_scheduler_map_entry_snapshot".into(), dump(&CoSSchedulerMapEntrySnapshot::default()));
    s.insert("cos_scheduler_map_snapshot".into(), dump(&CoSSchedulerMapSnapshot::default()));
    s.insert("cos_scheduler_snapshot".into(), dump(&CoSSchedulerSnapshot::default()));
    s.insert("destination_nat_rule_snapshot".into(), dump(&DestinationNATRuleSnapshot::default()));
    s.insert("exception_status".into(), dump(&ExceptionStatus::default()));
    s.insert("fabric_snapshot".into(), dump(&FabricSnapshot::default()));
    s.insert("firewall_filter_snapshot".into(), dump(&FirewallFilterSnapshot::default()));
    s.insert("firewall_filter_term_counter_status".into(), dump(&FirewallFilterTermCounterStatus::default()));
    s.insert("firewall_term_snapshot".into(), dump(&FirewallTermSnapshot::default()));
    s.insert("flow_export_snapshot".into(), dump(&FlowExportSnapshot::default()));
    s.insert("flow_snapshot".into(), dump(&FlowSnapshot::default()));
    s.insert("flow_tuple_status".into(), dump(&FlowTupleStatus::default()));
    s.insert("flow_worker_status".into(), dump(&FlowWorkerStatus::default()));
    s.insert("forwarding_control_request".into(), dump(&ForwardingControlRequest::default()));
    s.insert("ha_group_status".into(), dump(&HAGroupStatus::default()));
    s.insert("ha_state_update_request".into(), dump(&HAStateUpdateRequest::default()));
    s.insert("inject_packet_request".into(), dump(&InjectPacketRequest::default()));
    s.insert("interface_address_snapshot".into(), dump(&InterfaceAddressSnapshot::default()));
    s.insert("interface_snapshot".into(), dump(&InterfaceSnapshot::default()));
    s.insert("map_pins".into(), dump(&MapPins::default()));
    s.insert("mirror_config_snapshot".into(), dump(&MirrorConfigSnapshot::default()));
    s.insert("nat64_rule_snapshot".into(), dump(&NAT64RuleSnapshot::default()));
    s.insert("neighbor_snapshot".into(), dump(&NeighborSnapshot::default()));
    s.insert("nptv6_rule_snapshot".into(), dump(&Nptv6RuleSnapshot::default()));
    s.insert("packet_resolution".into(), dump(&PacketResolution::default()));
    s.insert("policer_snapshot".into(), dump(&PolicerSnapshot::default()));
    s.insert("policy_application_snapshot".into(), dump(&PolicyApplicationSnapshot::default()));
    s.insert("policy_rule_counter_status".into(), dump(&PolicyRuleCounterStatus::default()));
    s.insert("policy_rule_snapshot".into(), dump(&PolicyRuleSnapshot::default()));
    s.insert("process_status".into(), dump(&ProcessStatus::default()));
    s.insert("queue_control_request".into(), dump(&QueueControlRequest::default()));
    s.insert("queue_status".into(), dump(&QueueStatus::default()));
    s.insert("route_snapshot".into(), dump(&RouteSnapshot::default()));
    s.insert("screen_profile_snapshot".into(), dump(&ScreenProfileSnapshot::default()));
    s.insert("session_delta_drain_request".into(), dump(&SessionDeltaDrainRequest::default()));
    s.insert("session_delta_info".into(), dump(&SessionDeltaInfo::default()));
    s.insert("session_export_request".into(), dump(&SessionExportRequest::default()));
    s.insert("session_sync_request".into(), dump(&SessionSyncRequest::default()));
    s.insert("slow_path_status".into(), dump(&SlowPathStatus::default()));
    s.insert("snapshot_summary".into(), dump(&SnapshotSummary::default()));
    s.insert("source_nat_pool_status".into(), dump(&SourceNatPoolStatus::default()));
    s.insert("source_nat_rule_snapshot".into(), dump(&SourceNATRuleSnapshot::default()));
    s.insert("static_nat_rule_snapshot".into(), dump(&StaticNATRuleSnapshot::default()));
    s.insert("three_color_policer_snapshot".into(), dump(&ThreeColorPolicerSnapshot::default()));
    s.insert("three_color_policer_status".into(), dump(&ThreeColorPolicerStatus::default()));
    s.insert("tunnel_endpoint_snapshot".into(), dump(&TunnelEndpointSnapshot::default()));
    s.insert("userspace_capabilities".into(), dump(&UserspaceCapabilities::default()));
    s.insert("worker_runtime_status".into(), dump(&WorkerRuntimeStatus::default()));
    s.insert("zone_snapshot".into(), dump(&ZoneSnapshot::default()));
    let specimens = Value::Object(s);

    let actual = serde_json::to_string_pretty(&specimens)
        .expect("specimens serialize to pretty JSON");

    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("protocol_wire_v1.json");

    if std::env::var("XPF_PROTOCOL_WIRE_REGEN").is_ok() {
        std::fs::create_dir_all(fixture_path.parent().unwrap())
            .expect("create fixtures dir");
        std::fs::write(&fixture_path, format!("{}\n", actual))
            .expect("write regenerated fixture");
        eprintln!("regenerated fixture at {}", fixture_path.display());
        return;
    }

    let baseline = std::fs::read_to_string(&fixture_path).unwrap_or_else(|e| {
        panic!(
            "wire fixture missing at {}: {}. Regenerate with \
             XPF_PROTOCOL_WIRE_REGEN=1 cargo test --bin xpf-userspace-dp \
             wire_invariant_default_specimens",
            fixture_path.display(),
            e
        )
    });

    if baseline.trim() != actual.trim() {
        let tmp = fixture_path.with_extension("json.actual");
        let _ = std::fs::write(&tmp, format!("{}\n", actual));
        panic!(
            "wire-format drift detected vs {}.\nActual written to {}.\n\
             Inspect: diff -u {} {}\n\
             If intentional, regenerate with \
             XPF_PROTOCOL_WIRE_REGEN=1 cargo test --bin xpf-userspace-dp \
             wire_invariant_default_specimens",
            fixture_path.display(),
            tmp.display(),
            fixture_path.display(),
            tmp.display(),
        );
    }
}

// #1642: Rust→Go status-field parity. These serde tests pin the exact wire
// keys for the four field groups the Go side previously dropped on unmarshal
// (HAGroupStatus lease telemetry, CoSQueueStatus starvation/ring counters,
// BindingStatus post-drain backup drops, ProcessStatus event-stream
// connected/seq/acked). The matching Go decode tests live in
// pkg/dataplane/userspace/protocol_test.go (*Parity1642). A rename on this
// side is caught here; the Go side then fails to decode the renamed key.

#[test]
fn ha_group_status_lease_fields_wire_keys_1642() {
    let status = HAGroupStatus {
        rg_id: 1,
        active: true,
        watchdog_timestamp: 1,
        forwarding_active: true,
        lease_state: "owner".to_string(),
        lease_until: 9876543210,
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize HAGroupStatus");
    assert_eq!(value["forwarding_active"], true);
    assert_eq!(value["lease_state"], "owner");
    assert_eq!(value["lease_until"], 9876543210u64);
    let back: HAGroupStatus = serde_json::from_value(value).expect("deserialize HAGroupStatus");
    assert!(back.forwarding_active);
    assert_eq!(back.lease_state, "owner");
    assert_eq!(back.lease_until, 9876543210);
}

#[test]
fn cos_queue_status_starvation_counters_wire_keys_1642() {
    let status = CoSQueueStatus {
        root_token_starvation_parks: 11,
        queue_token_starvation_parks: 22,
        tx_ring_full_submit_stalls: 33,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize CoSQueueStatus");
    assert_eq!(value["root_token_starvation_parks"], 11u64);
    assert_eq!(value["queue_token_starvation_parks"], 22u64);
    assert_eq!(value["tx_ring_full_submit_stalls"], 33u64);
}

// #1829 Phase 1: round-trip + backward-compat pin for the sojourn
// telemetry trio. The wire keys feed
// pkg/dataplane/userspace/protocol.go and the Prometheus gauges
// `xpf_userspace_cos_sojourn_{ewma,peak,windowed_min}_ns` — a rename
// on either side must fail a test instead of silently decoding zero.
// `sojourn_windowed_min_ns` is the #1829 Phase-2 gate metric.
#[test]
fn cos_queue_status_sojourn_roundtrip_1829() {
    let status = CoSQueueStatus {
        sojourn_ewma_ns: 2_500_000,
        sojourn_peak_ns: 9_000_000,
        sojourn_windowed_min_ns: 1_750_000,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize CoSQueueStatus");
    assert_eq!(value["sojourn_ewma_ns"], 2_500_000u64);
    assert_eq!(value["sojourn_peak_ns"], 9_000_000u64);
    assert_eq!(value["sojourn_windowed_min_ns"], 1_750_000u64);
    let back: CoSQueueStatus = serde_json::from_value(value).expect("deserialize CoSQueueStatus");
    assert_eq!(back.sojourn_ewma_ns, 2_500_000);
    assert_eq!(back.sojourn_peak_ns, 9_000_000);
    assert_eq!(back.sojourn_windowed_min_ns, 1_750_000);

    // Pre-#1829 payload (keys absent) must decode with zero defaults.
    let mut legacy_value = serde_json::to_value(CoSQueueStatus::default())
        .expect("serialize default CoSQueueStatus");
    for key in [
        "sojourn_ewma_ns",
        "sojourn_peak_ns",
        "sojourn_windowed_min_ns",
    ] {
        legacy_value
            .as_object_mut()
            .expect("CoSQueueStatus serializes to an object")
            .remove(key)
            .unwrap_or_else(|| panic!("new key {key} present before strip"));
    }
    let legacy: CoSQueueStatus =
        serde_json::from_value(legacy_value).expect("pre-#1829 payload decodes");
    assert_eq!(legacy.sojourn_ewma_ns, 0);
    assert_eq!(legacy.sojourn_peak_ns, 0);
    assert_eq!(legacy.sojourn_windowed_min_ns, 0);
}

// #1830 (g): round-trip + backward-compat pin for the bucket-vs-flow
// occupancy telemetry. The wire keys feed
// pkg/dataplane/userspace/protocol.go and the Prometheus gauges
// `xpf_userspace_cos_flow_fair_buckets_occupied` /
// `xpf_userspace_cos_flow_fair_flows_active` — a rename on either side
// must fail a test instead of silently decoding zero.
#[test]
fn cos_queue_status_flow_fair_occupancy_roundtrip_1830() {
    let status = CoSQueueStatus {
        flow_fair_buckets_occupied: 9,
        flow_fair_flows_active: 12,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize CoSQueueStatus");
    assert_eq!(value["flow_fair_buckets_occupied"], 9u64);
    assert_eq!(value["flow_fair_flows_active"], 12u64);
    let back: CoSQueueStatus = serde_json::from_value(value).expect("deserialize CoSQueueStatus");
    assert_eq!(back.flow_fair_buckets_occupied, 9);
    assert_eq!(back.flow_fair_flows_active, 12);

    // Pre-#1830 payload (keys absent) must decode with zero defaults.
    let mut legacy_value = serde_json::to_value(CoSQueueStatus::default())
        .expect("serialize default CoSQueueStatus");
    for key in ["flow_fair_buckets_occupied", "flow_fair_flows_active"] {
        legacy_value
            .as_object_mut()
            .expect("CoSQueueStatus serializes to an object")
            .remove(key)
            .unwrap_or_else(|| panic!("new key {key} present before strip"));
    }
    let legacy: CoSQueueStatus =
        serde_json::from_value(legacy_value).expect("pre-#1830 payload decodes");
    assert_eq!(legacy.flow_fair_buckets_occupied, 0);
    assert_eq!(legacy.flow_fair_flows_active, 0);
}

#[test]
fn binding_status_post_drain_backup_cos_drops_wire_keys_1642() {
    let status = BindingStatus {
        post_drain_backup_cos_drops: 7,
        post_drain_backup_cos_drop_bytes: 4096,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize BindingStatus");
    assert_eq!(value["post_drain_backup_cos_drops"], 7u64);
    assert_eq!(value["post_drain_backup_cos_drop_bytes"], 4096u64);
    // These are binding-scoped: CoSQueueStatus must NOT also carry them.
    let cos: serde_json::Value = serde_json::to_value(CoSQueueStatus {
        post_drain_backup_bytes: 1,
        ..Default::default()
    })
    .expect("serialize CoSQueueStatus");
    assert!(cos.get("post_drain_backup_cos_drops").is_none());
    assert!(cos.get("post_drain_backup_cos_drop_bytes").is_none());
    assert_eq!(cos["post_drain_backup_bytes"], 1u64);
}

#[test]
fn process_status_event_stream_fields_wire_keys_1642() {
    let status = ProcessStatus {
        event_stream_connected: true,
        event_stream_seq: 4242,
        event_stream_acked: 4200,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus");
    assert_eq!(value["event_stream_connected"], true);
    assert_eq!(value["event_stream_seq"], 4242u64);
    assert_eq!(value["event_stream_acked"], 4200u64);
}

// #1863 Step-0: round-trip + omitempty pin for the per-worker v8
// lease claim-flow vectors. The wire keys feed
// pkg/dataplane/userspace/protocol.go and the Prometheus counters
// `xpf_userspace_cos_lease_v8_{requested,granted}_bytes_total` — a
// rename or skip-semantics change on either side must fail here
// instead of silently decoding empty.
#[test]
fn cos_queue_status_lease_claim_flow_roundtrip_1863() {
    let status = CoSQueueStatus {
        lease_v8_worker_requested_bytes: vec![100, 0, 250],
        lease_v8_worker_granted_bytes: vec![90, 0, 200],
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize CoSQueueStatus");
    assert_eq!(
        value["lease_v8_worker_requested_bytes"],
        serde_json::json!([100, 0, 250])
    );
    assert_eq!(
        value["lease_v8_worker_granted_bytes"],
        serde_json::json!([90, 0, 200])
    );
    let back: CoSQueueStatus = serde_json::from_value(value).expect("deserialize CoSQueueStatus");
    assert_eq!(back.lease_v8_worker_requested_bytes, vec![100, 0, 250]);
    assert_eq!(back.lease_v8_worker_granted_bytes, vec![90, 0, 200]);

    // Legacy/non-v8 rows: empty vectors must be OMITTED from the wire
    // (byte-identical pre-#1863 encoding) and absent keys must decode
    // to empty defaults.
    let default_value = serde_json::to_value(CoSQueueStatus::default())
        .expect("serialize default CoSQueueStatus");
    let obj = default_value
        .as_object()
        .expect("CoSQueueStatus serializes to an object");
    assert!(!obj.contains_key("lease_v8_worker_requested_bytes"));
    assert!(!obj.contains_key("lease_v8_worker_granted_bytes"));
    let back: CoSQueueStatus =
        serde_json::from_value(default_value).expect("deserialize legacy CoSQueueStatus");
    assert!(back.lease_v8_worker_requested_bytes.is_empty());
    assert!(back.lease_v8_worker_granted_bytes.is_empty());
}
