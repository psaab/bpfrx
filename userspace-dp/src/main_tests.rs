// Tests for main.rs — relocated from inline `#[cfg(test)] mod tests` to
// keep main.rs under the modularity-discipline LOC threshold (#1048).
// Loaded as a sibling module via `#[path = "main_tests.rs"]` from main.rs.

use super::*;
use crate::test_zone_ids::*;
use std::collections::BTreeMap;

fn test_zone_name_to_id() -> rustc_hash::FxHashMap<String, u16> {
    let mut m = rustc_hash::FxHashMap::default();
    m.insert("lan".to_string(), TEST_LAN_ZONE_ID);
    m.insert("wan".to_string(), TEST_WAN_ZONE_ID);
    m.insert("trust".to_string(), TEST_TRUST_ZONE_ID);
    m.insert("untrust".to_string(), TEST_UNTRUST_ZONE_ID);
    m.insert("sfmix".to_string(), TEST_SFMIX_ZONE_ID);
    m
}

#[test]
fn same_binding_plan_ignores_runtime_only_snapshot_changes() {
    let current = ConfigSnapshot {
        userspace: serde_json::json!({
            "binary": "/usr/libexec/xpf-userspace-dp",
            "control_socket": "/run/xpf/control.sock",
            "state_file": "/run/xpf/state.json",
            "workers": 2,
            "ring_entries": 2048,
            "poll_mode": "interrupt",
        }),
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/1.0".to_string(),
                zone: "lan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 11,
                rx_queues: 4,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "fab0".to_string(),
                zone: "control".to_string(),
                linux_name: "fab0".to_string(),
                ifindex: 149,
                rx_queues: 16,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "gr-0/0/0.0".to_string(),
                zone: "sfmix".to_string(),
                linux_name: "gr-0-0-0".to_string(),
                ifindex: 586,
                rx_queues: 1,
                tunnel: true,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "fxp0.0".to_string(),
                zone: "mgmt".to_string(),
                linux_name: "fxp0".to_string(),
                ifindex: 42,
                rx_queues: 1,
                ..Default::default()
            },
        ],
        fabrics: vec![FabricSnapshot {
            name: "fab0".to_string(),
            parent_linux_name: "ge-0-0-0".to_string(),
            parent_ifindex: 21,
            rx_queues: 1,
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut next = current.clone();
    next.userspace = serde_json::json!({
        "binary": "/tmp/other-helper",
        "control_socket": "/tmp/control.sock",
        "state_file": "/tmp/state.json",
        "workers": 2,
        "ring_entries": 2048,
        "poll_mode": "busy-poll",
    });
    next.interfaces.push(InterfaceSnapshot {
        name: "em0.0".to_string(),
        zone: "mgmt".to_string(),
        linux_name: "em0".to_string(),
        ifindex: 99,
        rx_queues: 1,
        ..Default::default()
    });
    next.interfaces[1].ifindex = 154;

    assert!(same_binding_plan(&current, &next));
}

#[test]
fn same_binding_plan_canonicalizes_shared_umem_json_set_order() {
    let current = ConfigSnapshot {
        userspace: serde_json::from_str(
            r#"{
                "workers": 2,
                "ring_entries": 2048,
                "shared_umem": {
                    "mode": "cross-nic",
                    "interfaces": ["ge-0-0-1", "ge-0-0-2"],
                    "phase0_artifact": {
                        "selected_interfaces": ["ge-0-0-1", "ge-0-0-2"],
                        "selected_nic_pci_ids": ["0000:08:00.0", "0000:09:00.0"],
                        "selected_device_pair": ["0000:08:00.0", "0000:09:00.0"],
                        "mtu": {"ge-0-0-1": 1500, "ge-0-0-2": 1500}
                    }
                }
            }"#,
        )
        .unwrap(),
        ..Default::default()
    };
    let next = ConfigSnapshot {
        userspace: serde_json::from_str(
            r#"{
                "shared_umem": {
                    "phase0_artifact": {
                        "mtu": {"ge-0-0-2": 1500, "ge-0-0-1": 1500},
                        "selected_device_pair": ["0000:09:00.0", "0000:08:00.0"],
                        "selected_nic_pci_ids": ["0000:09:00.0", "0000:08:00.0"],
                        "selected_interfaces": ["ge-0-0-2", "ge-0-0-1"]
                    },
                    "interfaces": ["ge-0-0-2", "ge-0-0-1"],
                    "mode": "cross-nic"
                },
                "ring_entries": 2048,
                "workers": 2
            }"#,
        )
        .unwrap(),
        ..Default::default()
    };

    assert!(same_binding_plan(&current, &next));
}

#[test]
fn same_binding_plan_detects_shared_umem_json_set_membership_change() {
    let current = ConfigSnapshot {
        userspace: serde_json::from_str(
            r#"{
                "workers": 2,
                "ring_entries": 2048,
                "shared_umem": {
                    "mode": "cross-nic",
                    "interfaces": ["ge-0-0-1", "ge-0-0-2"],
                    "phase0_artifact": {
                        "selected_interfaces": ["ge-0-0-1", "ge-0-0-2"],
                        "selected_nic_pci_ids": ["0000:08:00.0", "0000:09:00.0"]
                    }
                }
            }"#,
        )
        .unwrap(),
        ..Default::default()
    };
    let next = ConfigSnapshot {
        userspace: serde_json::from_str(
            r#"{
                "workers": 2,
                "ring_entries": 2048,
                "shared_umem": {
                    "mode": "cross-nic",
                    "interfaces": ["ge-0-0-1", "ge-0-0-3"],
                    "phase0_artifact": {
                        "selected_interfaces": ["ge-0-0-1", "ge-0-0-3"],
                        "selected_nic_pci_ids": ["0000:08:00.0", "0000:0a:00.0"]
                    }
                }
            }"#,
        )
        .unwrap(),
        ..Default::default()
    };

    assert!(!same_binding_plan(&current, &next));
}

#[test]
fn binding_plan_key_hashes_large_shared_umem_artifact() {
    let huge_note = "x".repeat(1024 * 1024);
    let snapshot = ConfigSnapshot {
        userspace: serde_json::json!({
            "workers": 2,
            "ring_entries": 2048,
            "shared_umem": {
                "mode": "cross-nic",
                "interfaces": ["ge-0-0-1", "ge-0-0-2"],
                "phase0_artifact": {
                    "selected_interfaces": ["ge-0-0-1", "ge-0-0-2"],
                    "selected_nic_pci_ids": ["0000:08:00.0", "0000:09:00.0"],
                    "diagnostic_note": huge_note
                }
            }
        }),
        ..Default::default()
    };

    let key = crate::server::helpers::snapshot_binding_plan_key(&snapshot);
    assert!(key.starts_with("sha256:"));
    assert_eq!(key.len(), "sha256:".len() + 64);
    assert!(!key.contains("diagnostic_note"));
    assert!(!key.contains('x'));
}

#[test]
fn same_binding_plan_detects_binding_topology_change() {
    let current = ConfigSnapshot {
        userspace: serde_json::json!({
            "workers": 2,
            "ring_entries": 2048,
        }),
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/1.0".to_string(),
            zone: "lan".to_string(),
            linux_name: "ge-0-0-1".to_string(),
            ifindex: 11,
            rx_queues: 4,
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut next = current.clone();
    next.interfaces[0].rx_queues = 8;

    assert!(!same_binding_plan(&current, &next));
}

#[test]
fn queue_planner_filters_non_data_interfaces() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                ifindex: 11,
                rx_queues: 1,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "xe-0/0/0".to_string(),
                linux_name: "xe-0-0-0".to_string(),
                zone: "untrust".to_string(),
                ifindex: 12,
                rx_queues: 1,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "fab0".to_string(),
                linux_name: "fab0".to_string(),
                ifindex: 13,
                rx_queues: 4,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 2, &[]);
    assert_eq!(bindings.len(), 2);
    assert!(bindings.iter().all(|b| {
        b.interface.starts_with("ge-")
            || b.interface.starts_with("xe-")
            || b.interface.starts_with("et-")
    }));
    assert!(bindings.iter().all(|b| b.registered));
}

// #2915 fail-on-revert: the plan-key hash and the queue planner MUST agree
// on the binding interface set. Both must route through
// `include_userspace_binding_interface` (the Rust mirror of the Go
// authoritative allowlist), not the pre-#2915 prefix-only test. This test
// pins three properties; any one of them goes RED if `replan_queues` reverts
// to the divergent `ge-*`/`xe-*`/`et-*` prefix predicate:
//
//   1. A `ge-*` netdev in a mgmt/control zone is EXCLUDED by both the hash
//      and the planner (the prefix-only predicate would plan it).
//   2. Mutating a non-candidate (mgmt-zone) interface does NOT bump the
//      plan key — change detection is scoped to the planned set.
//   3. Mutating a candidate (zoned data) interface DOES bump the plan key
//      AND that interface IS planned.
#[test]
fn queue_planner_and_plan_key_agree_on_binding_set() {
    use crate::server::helpers::snapshot_binding_plan_key;

    // A genuine data interface plus a `ge-*`-named interface that lives in a
    // management zone (e.g. an out-of-band port the operator zoned `mgmt`).
    let mk = |mgmt_ifindex: i32, data_rx: usize| ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/9".to_string(),
                linux_name: "ge-0-0-9".to_string(),
                zone: "mgmt".to_string(),
                ifindex: mgmt_ifindex,
                rx_queues: 1,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                ifindex: 11,
                rx_queues: data_rx,
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let base = mk(99, 1);

    // Property 1: the mgmt-zone `ge-*` is NOT planned; only the data iface is.
    let bindings = replan_queues(Some(&base), 1, &[]);
    assert!(
        bindings.iter().all(|b| b.interface == "ge-0-0-1"),
        "mgmt-zone ge-* must be excluded from the plan, got: {:?}",
        bindings.iter().map(|b| &b.interface).collect::<Vec<_>>()
    );
    assert_eq!(bindings.len(), 1, "only the data interface should be planned");

    // Property 2: mutating the non-candidate (mgmt) interface must NOT bump
    // the plan key — it is outside the planned set, so it is outside the hash.
    let mgmt_changed = mk(123, 1);
    assert_eq!(
        snapshot_binding_plan_key(&base),
        snapshot_binding_plan_key(&mgmt_changed),
        "a change to a non-candidate (mgmt-zone) interface must not bump the \
         plan key — the hash and planner must share the exclusion contract"
    );
    // ...and the planned set is identical regardless of the mgmt change.
    let bindings_changed = replan_queues(Some(&mgmt_changed), 1, &[]);
    assert_eq!(
        bindings.iter().map(|b| b.interface.clone()).collect::<Vec<_>>(),
        bindings_changed
            .iter()
            .map(|b| b.interface.clone())
            .collect::<Vec<_>>(),
        "mgmt-zone change must not alter the planned interface set"
    );

    // Property 3: mutating the candidate (data) interface DOES bump the key.
    let data_changed = mk(99, 4);
    assert_ne!(
        snapshot_binding_plan_key(&base),
        snapshot_binding_plan_key(&data_changed),
        "a change to a candidate (zoned data) interface must bump the plan key"
    );
}

// #2916 fail-on-revert: the same-plan fast path in `apply_snapshot`
// (`handlers/snapshot.rs`) skips `replan_queues` whenever the plan key is
// unchanged. That is only sound if EVERY field `replan_queues` reads to build
// the binding layout is also hashed into `snapshot_binding_plan_key`. If a
// planner-consumed field were dropped from the hash, two snapshots that
// produce DIFFERENT layouts could share a key, the apply path would take the
// same-plan branch, and the live AF_XDP worker layout would stay stale.
//
// #2915 unified the candidate SET (both paths filter through
// `include_userspace_binding_interface`). This test pins the remaining half of
// the #2916 invariant: for a single candidate interface, mutating ANY of the
// three fields `replan_queues` consumes to construct the layout — `linux_name`
// (candidate identity + dedup key), `ifindex` (per-binding ifindex, drives
// registered/armed/ready gating), and `rx_queues` (queue_count) — MUST bump
// the plan key. Each property is paired with a `replan_queues` assertion
// proving the mutated field actually changes the produced layout, so the test
// cannot be satisfied by a field that the planner ignores.
//
// Revert proof: drop any one of `linux_name`, `ifindex`, or `rx_queues` from
// the `iface=...` segment in `update_snapshot_binding_plan_key` and the
// matching property goes RED — a real layout change becomes invisible to the
// same-plan branch.
#[test]
fn plan_key_covers_every_replan_queues_input() {
    use crate::server::helpers::{replan_queues, snapshot_binding_plan_key};

    let mk = |linux_name: &str, ifindex: i32, rx_queues: usize| ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/1".to_string(),
            linux_name: linux_name.to_string(),
            zone: "trust".to_string(),
            ifindex,
            rx_queues,
            ..Default::default()
        }],
        ..Default::default()
    };

    let base = mk("ge-0-0-1", 11, 2);
    let base_key = snapshot_binding_plan_key(&base);
    let base_layout: Vec<(String, i32, u32)> = replan_queues(Some(&base), 2, &[])
        .iter()
        .map(|b| (b.interface.clone(), b.ifindex, b.queue_id))
        .collect();

    // linux_name change -> different bound netdev -> must bump key.
    let name_changed = mk("ge-0-0-2", 11, 2);
    assert_ne!(
        base_key,
        snapshot_binding_plan_key(&name_changed),
        "a candidate linux_name change must bump the plan key (#2916): the \
         same-plan branch would otherwise leave the binding on the old netdev"
    );
    let name_layout: Vec<String> = replan_queues(Some(&name_changed), 2, &[])
        .iter()
        .map(|b| b.interface.clone())
        .collect();
    assert!(
        name_layout.iter().all(|i| i == "ge-0-0-2"),
        "replan_queues must bind the new linux_name; got {name_layout:?}"
    );

    // ifindex change -> different per-binding ifindex -> must bump key.
    let ifindex_changed = mk("ge-0-0-1", 99, 2);
    assert_ne!(
        base_key,
        snapshot_binding_plan_key(&ifindex_changed),
        "a candidate ifindex change must bump the plan key (#2916): the \
         same-plan branch would otherwise leave bindings pointed at the stale \
         ifindex"
    );
    assert!(
        replan_queues(Some(&ifindex_changed), 2, &[])
            .iter()
            .all(|b| b.ifindex == 99),
        "replan_queues must carry the new ifindex onto every binding"
    );

    // rx_queues change -> different queue_count -> must bump key.
    let rx_changed = mk("ge-0-0-1", 11, 4);
    assert_ne!(
        base_key,
        snapshot_binding_plan_key(&rx_changed),
        "a candidate rx_queues change must bump the plan key (#2916): the \
         same-plan branch would otherwise leave a stale queue count"
    );
    assert_ne!(
        base_layout.len(),
        replan_queues(Some(&rx_changed), 2, &[]).len(),
        "replan_queues must emit a different number of bindings when \
         rx_queues changes"
    );
}

// #3007 fail-on-revert: when the snapshot carries the degenerate `rx_queues ==
// 0` fallback, `replan_queues` reads the live channel count from sysfs
// (`rx_queue_count`) and THAT count drives the layout. The plan key MUST hash
// the same resolved count — otherwise two refreshes with the same (rx_queues=0)
// snapshot but a DIFFERENT actual sysfs channel count (operator ran `ethtool -L
// <if> combined N` out of band, no config commit) share a plan key, the
// same-plan-skip is taken, and the queues are never re-planned to the new count.
//
// Revert proof: change the iface hash in `update_snapshot_binding_plan_key` back
// to hashing `iface.rx_queues` (the raw 0) instead of `effective_rx_queues(...)`
// and this test goes RED — both keys collapse to the same 0-derived hash.
#[test]
fn plan_key_folds_sysfs_resolved_rx_queues_when_snapshot_is_zero() {
    use crate::server::helpers::{
        clear_rx_queue_count_override, set_rx_queue_count_override, snapshot_binding_plan_key,
    };

    // Degenerate snapshot: the Go control plane did not populate a count.
    let mk = || ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/1".to_string(),
            linux_name: "ge-0-0-1".to_string(),
            zone: "trust".to_string(),
            ifindex: 11,
            rx_queues: 0,
            ..Default::default()
        }],
        ..Default::default()
    };

    // sysfs reports 4 combined channels.
    set_rx_queue_count_override("ge-0-0-1", 4);
    let key_4 = snapshot_binding_plan_key(&mk());

    // Operator runs `ethtool -L ge-0-0-1 combined 6` out of band; the snapshot
    // is byte-identical (still rx_queues=0) but the live channel count changed.
    set_rx_queue_count_override("ge-0-0-1", 6);
    let key_6 = snapshot_binding_plan_key(&mk());

    clear_rx_queue_count_override();

    assert_ne!(
        key_4, key_6,
        "an out-of-band channel change (sysfs rx-queue count) MUST bump the plan \
         key when the snapshot rx_queues is the degenerate 0 fallback (#3007); \
         otherwise the same-plan-skip leaves a stale single-/under-queued layout"
    );
}

// #3007 no-regression: for a NONZERO snapshot rx_queues the plan key must be
// independent of sysfs — the resolved count equals the raw field, sysfs is never
// read, and the key is byte-identical to the pre-#3007 hash for the normal case.
#[test]
fn plan_key_for_nonzero_rx_queues_ignores_sysfs() {
    use crate::server::helpers::{
        clear_rx_queue_count_override, set_rx_queue_count_override, snapshot_binding_plan_key,
    };

    let snap = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/1".to_string(),
            linux_name: "ge-0-0-1".to_string(),
            zone: "trust".to_string(),
            ifindex: 11,
            rx_queues: 6,
            ..Default::default()
        }],
        ..Default::default()
    };

    // No override: real sysfs returns 0 for the fake netdev, but rx_queues>0 so
    // it is never consulted. This is the pre-#3007 code path (hash iface.rx_queues).
    clear_rx_queue_count_override();
    let baseline = snapshot_binding_plan_key(&snap);

    // Even a wildly different sysfs count must NOT change the key when the
    // snapshot already carries a real count.
    set_rx_queue_count_override("ge-0-0-1", 999);
    let with_override = snapshot_binding_plan_key(&snap);
    clear_rx_queue_count_override();

    assert_eq!(
        baseline, with_override,
        "a nonzero snapshot rx_queues must produce a plan key independent of \
         sysfs (no regression for the normal case, #3007)"
    );
}

// #3091 fail-on-revert: a WAN VLAN unit (`reth0.80` → Linux `ge-0-0-2.80`) is a
// software VLAN device that the kernel exposes with a SINGLE RX queue. Its
// physical parent (`ge-0-0-2`) carries the VLAN-tagged frames on its 6 hardware
// queues. The parent is already a binding candidate, so the VLAN child must be
// deduped onto it and must NOT enter the candidate list as a separate 1-queue
// interface — otherwise `replan_bindings_from_candidates` takes the MIN
// rx_queues across all candidates (`min(6, 1) == 1`), plans a single queue, and
// the dataplane runs with one worker (~6 Gbps, the regression).
//
// Revert proof: delete the `vlan_child_parent_netdev` dedup block in
// `replan_queues` and this test goes RED — the child re-enters the candidate
// list, `queue_count` collapses to 1, and the parent binds on a single queue.
#[test]
fn queue_planner_dedups_wan_vlan_child_onto_physical_parent() {
    use crate::server::helpers::replan_queues;

    let snapshot = ConfigSnapshot {
        interfaces: vec![
            // Physical WAN netdev: 6 hardware RX queues (mlx5 VF).
            InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 12,
                rx_queues: 6,
                ..Default::default()
            },
            // VLAN unit reth0.50: software VLAN netdev, 1 RX queue.
            InterfaceSnapshot {
                name: "ge-0/0/2.50".to_string(),
                linux_name: "ge-0-0-2.50".to_string(),
                parent_linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 50,
                parent_ifindex: 12,
                vlan_id: 50,
                rx_queues: 1,
                ..Default::default()
            },
            // VLAN unit reth0.80: software VLAN netdev, 1 RX queue.
            InterfaceSnapshot {
                name: "ge-0/0/2.80".to_string(),
                linux_name: "ge-0-0-2.80".to_string(),
                parent_linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 80,
                parent_ifindex: 12,
                vlan_id: 80,
                rx_queues: 1,
                ..Default::default()
            },
            // LAN netdev: 6 hardware RX queues (also mlx5 VF).
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                ifindex: 11,
                rx_queues: 6,
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let bindings = replan_queues(Some(&snapshot), 6, &[]);

    // The VLAN-child netdevs must NOT be planned as separate candidates.
    assert!(
        bindings
            .iter()
            .all(|b| b.interface != "ge-0-0-2.50" && b.interface != "ge-0-0-2.80"),
        "VLAN-child netdevs must be deduped onto the parent, not planned as \
         separate 1-queue candidates; got {:?}",
        bindings.iter().map(|b| &b.interface).collect::<Vec<_>>()
    );

    // The plan must span all 6 hardware queues (queue_count = min over the two
    // remaining 6-queue physical candidates), NOT collapse to 1.
    let queue_ids: std::collections::BTreeSet<u32> = bindings.iter().map(|b| b.queue_id).collect();
    assert_eq!(
        queue_ids,
        (0..6).collect::<std::collections::BTreeSet<u32>>(),
        "queue_count must be 6 (parent hardware queues), not collapsed to 1 by \
         the VLAN child's single software queue"
    );

    // Both physical parents bind on all 6 queues.
    for netdev in ["ge-0-0-1", "ge-0-0-2"] {
        let q: std::collections::BTreeSet<u32> = bindings
            .iter()
            .filter(|b| b.interface == netdev)
            .map(|b| b.queue_id)
            .collect();
        assert_eq!(
            q,
            (0..6).collect::<std::collections::BTreeSet<u32>>(),
            "{netdev} must bind on all 6 hardware queues"
        );
    }

    // The plan spans workers 0..5 (one per queue), i.e. multi-worker.
    let workers: std::collections::BTreeSet<u32> = bindings.iter().map(|b| b.worker_id).collect();
    assert_eq!(
        workers.len(),
        6,
        "the plan must spread across 6 workers, not a single worker (#3091)"
    );
}

// #3091: an ORPHAN VLAN child whose physical parent is NOT itself a binding
// candidate must still be re-keyed onto the parent netdev with the parent's
// HARDWARE queue count, never the child's single software queue. (This is the
// defensive fallback path; the common case is the parent-is-candidate dedup
// above.) Here the parent never appears as its own snapshot interface, so the
// child resolves the parent's queue count from sysfs — in the unit-test
// sandbox that yields 1 via `rx_queue_count`'s `.max(1)`, but the binding is
// keyed on the PARENT netdev (`ge-0-0-9`), proving the child's own netdev name
// never reaches the candidate list.
#[test]
fn queue_planner_rekeys_orphan_vlan_child_onto_parent_netdev() {
    use crate::server::helpers::replan_queues;

    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/9.30".to_string(),
            linux_name: "ge-0-0-9.30".to_string(),
            parent_linux_name: "ge-0-0-9".to_string(),
            zone: "untrust".to_string(),
            ifindex: 130,
            parent_ifindex: 19,
            vlan_id: 30,
            rx_queues: 1,
            ..Default::default()
        }],
        ..Default::default()
    };

    let bindings = replan_queues(Some(&snapshot), 2, &[]);
    assert!(
        bindings.iter().all(|b| b.interface == "ge-0-0-9"),
        "orphan VLAN child must bind on the parent netdev, not its own \
         child netdev; got {:?}",
        bindings.iter().map(|b| &b.interface).collect::<Vec<_>>()
    );
    assert!(
        bindings.iter().all(|b| b.ifindex == 19),
        "orphan VLAN child binding must use the parent ifindex"
    );
}

// #2917 SSOT fail-on-revert: the AF_XDP bind target for a VLAN unit MUST be the
// physical PARENT netdev on BOTH planes. The Go control plane resolves the same
// target via `userspaceBindTargetNetdev` (mirrored from `vlan_child_parent_netdev`)
// and emits it from `UserspaceBoundLinuxInterfaces` (the D3/RSS allowlist); the
// Rust planner must bind the identical netdev so the allowlist, RSS steering, and
// shim maps all target one netdev. A non-VLAN unit binds its OWN netdev (its unit
// netdev and physical netdev are the same device).
//
// Revert proof: change `vlan_child_parent_netdev` to return `None` (or change
// `replan_queues` to push `linux_name` for the VLAN child) and this test goes RED
// — the VLAN child `ge-0-0-2.80` re-enters the candidate list, so a binding with
// `interface == "ge-0-0-2.80"` appears and the parent-only assertion fails.
#[test]
fn replan_queues_binds_vlan_unit_on_parent_netdev() {
    use crate::server::helpers::replan_queues;

    let snapshot = ConfigSnapshot {
        interfaces: vec![
            // Physical WAN netdev parent of the VLAN unit: 6 hardware queues.
            InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 12,
                rx_queues: 6,
                ..Default::default()
            },
            // Tagged VLAN unit reth0.80 → software netdev `ge-0-0-2.80`.
            InterfaceSnapshot {
                name: "ge-0/0/2.80".to_string(),
                linux_name: "ge-0-0-2.80".to_string(),
                parent_linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 80,
                parent_ifindex: 12,
                vlan_id: 80,
                rx_queues: 1,
                ..Default::default()
            },
            // Plain non-VLAN LAN netdev: binds its OWN netdev, 6 queues.
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                ifindex: 11,
                rx_queues: 6,
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let bindings = replan_queues(Some(&snapshot), 6, &[]);
    let bound: std::collections::BTreeSet<&str> =
        bindings.iter().map(|b| b.interface.as_str()).collect();

    // The VLAN unit binds the PARENT netdev, never its `.80` unit netdev.
    assert!(
        bound.contains("ge-0-0-2"),
        "VLAN unit must bind its physical parent `ge-0-0-2`; bound: {bound:?}"
    );
    assert!(
        !bound.contains("ge-0-0-2.80"),
        "VLAN unit MUST NOT bind its `.80` software unit netdev (no hw queues); \
         bound: {bound:?}"
    );
    // The non-VLAN interface binds its own netdev.
    assert!(
        bound.contains("ge-0-0-1"),
        "non-VLAN interface must bind its own netdev `ge-0-0-1`; bound: {bound:?}"
    );
}

// #3175 fail-on-revert: an ORPHAN VLAN child (a VLAN unit whose physical parent
// is NOT itself a binding candidate) is re-keyed in the LAYOUT onto its parent
// netdev using the parent's HARDWARE queue count (`rx_queue_count(parent)`). The
// plan key MUST hash the SAME value. Before #3175 the key loop hashed the
// child's own software-queue count (`effective_rx_queues(child.rx_queues, ...)`,
// the lone 1-queue VLAN device), so an out-of-band `ethtool -L <parent> combined
// N` on the parent (no config commit) left the key unchanged → same-plan-skip →
// stale layout while `replan_queues` would actually re-plan to the new count.
//
// Revert proof: change `plan_key_rx_queues` back to returning
// `effective_rx_queues(iface.rx_queues, resolved_linux_name)` for the orphan
// case and this test goes RED — the child's rx_queues=1 is hashed for both
// counts, so key_4 == key_6.
#[test]
fn plan_key_folds_parent_sysfs_queues_for_orphan_vlan_child() {
    use crate::server::helpers::{
        clear_rx_queue_count_override, set_rx_queue_count_override, snapshot_binding_plan_key,
    };

    // Orphan VLAN child only: its physical parent `ge-0-0-9` is NOT present as
    // its own snapshot interface, so it is not a binding candidate. The child is
    // a real software VLAN device with a single RX queue (rx_queues=1, nonzero),
    // proving the key must NOT hash the child's own count.
    let mk = || ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/9.30".to_string(),
            linux_name: "ge-0-0-9.30".to_string(),
            parent_linux_name: "ge-0-0-9".to_string(),
            zone: "untrust".to_string(),
            ifindex: 130,
            parent_ifindex: 19,
            vlan_id: 30,
            rx_queues: 1,
            ..Default::default()
        }],
        ..Default::default()
    };

    // Parent sysfs reports 4 combined channels.
    set_rx_queue_count_override("ge-0-0-9", 4);
    let key_4 = snapshot_binding_plan_key(&mk());

    // Operator runs `ethtool -L ge-0-0-9 combined 6` out of band; the snapshot is
    // byte-identical (child still rx_queues=1) but the parent's live channel
    // count changed.
    set_rx_queue_count_override("ge-0-0-9", 6);
    let key_6 = snapshot_binding_plan_key(&mk());

    clear_rx_queue_count_override();

    assert_ne!(
        key_4, key_6,
        "an out-of-band channel change on the parent of an ORPHAN VLAN child MUST \
         bump the plan key — the key must hash rx_queue_count(parent), the same \
         value the layout uses, not the child's lone software queue (#3175)"
    );
}

// #3175 no-regression: a NORMAL VLAN child (parent IS a binding candidate) keeps
// the pre-#3175 behavior. The layout dedups the child onto the candidate parent
// (which carries its own physical key entry), so the child's key contribution
// stays `effective_rx_queues(child.rx_queues, ...)` and must NOT reach into the
// parent's sysfs channel count. Overriding the parent's sysfs must leave the
// plan key byte-identical.
#[test]
fn plan_key_for_normal_vlan_child_ignores_parent_sysfs() {
    use crate::server::helpers::{
        clear_rx_queue_count_override, set_rx_queue_count_override, snapshot_binding_plan_key,
    };

    let snap = ConfigSnapshot {
        interfaces: vec![
            // Physical parent IS a candidate (nonzero rx_queues).
            InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 12,
                rx_queues: 6,
                ..Default::default()
            },
            // Normal VLAN child (parent present as a candidate above).
            InterfaceSnapshot {
                name: "ge-0/0/2.80".to_string(),
                linux_name: "ge-0-0-2.80".to_string(),
                parent_linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 80,
                parent_ifindex: 12,
                vlan_id: 80,
                rx_queues: 1,
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    clear_rx_queue_count_override();
    let baseline = snapshot_binding_plan_key(&snap);

    // A wildly different parent sysfs count must NOT change the key: the parent's
    // own rx_queues (6) is nonzero so sysfs is never consulted, and the normal
    // VLAN child must NOT take the orphan branch (parent IS a candidate).
    set_rx_queue_count_override("ge-0-0-2", 999);
    let with_override = snapshot_binding_plan_key(&snap);
    clear_rx_queue_count_override();

    assert_eq!(
        baseline, with_override,
        "a normal VLAN child (parent IS a candidate) must keep the #3007 \
         behavior — the plan key stays independent of the parent's sysfs channel \
         count (only the orphan case re-keys onto the parent, #3175)"
    );
}

#[test]
fn queue_planner_excludes_tunnel_and_local_fabric_ge_interfaces() {
    // #2915: `ge-*`-named interfaces in tunnel or local-fabric contexts are
    // excluded by `include_userspace_binding_interface` (and the Go
    // allowlist). The prefix-only predicate would have planned them.
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/5".to_string(),
                linux_name: "ge-0-0-5".to_string(),
                zone: "trust".to_string(),
                ifindex: 30,
                rx_queues: 1,
                tunnel: true,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/6".to_string(),
                linux_name: "ge-0-0-6".to_string(),
                zone: "trust".to_string(),
                ifindex: 31,
                rx_queues: 1,
                local_fabric_member: "fab0".to_string(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/7".to_string(),
                linux_name: "ge-0-0-7".to_string(),
                zone: "untrust".to_string(),
                ifindex: 32,
                rx_queues: 1,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 1, &[]);
    assert_eq!(
        bindings.iter().map(|b| b.interface.clone()).collect::<Vec<_>>(),
        vec!["ge-0-0-7".to_string()],
        "tunnel and local-fabric ge-* interfaces must be excluded from the plan"
    );
}

#[test]
fn queue_planner_includes_fabric_parent_interface() {
    // The fabric parent (ge-0/0/0) is not in snapshot.interfaces but is
    // referenced by snapshot.fabrics.  It needs an XSK binding so the
    // userspace DP can transmit fabric-redirect packets.
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                ifindex: 11,
                rx_queues: 1,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                ifindex: 12,
                rx_queues: 1,
                ..Default::default()
            },
        ],
        fabrics: vec![FabricSnapshot {
            name: "fab0".to_string(),
            parent_interface: "ge-0/0/0".to_string(),
            parent_linux_name: "ge-0-0-0".to_string(),
            parent_ifindex: 21,
            overlay_linux_name: "fab0".to_string(),
            overlay_ifindex: 101,
            rx_queues: 1,
            peer_address: "10.99.13.2".to_string(),
            local_mac: String::new(),
            peer_mac: String::new(),
            up: true,
        }],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 1, &[]);
    // Should have 3 bindings: ge-0-0-1, ge-0-0-2, ge-0-0-0 (fabric parent)
    assert_eq!(bindings.len(), 3);
    let fabric_binding = bindings
        .iter()
        .find(|b| b.interface == "ge-0-0-0")
        .expect("fabric parent binding missing");
    assert_eq!(fabric_binding.ifindex, 21);
    assert!(fabric_binding.registered);
}

#[test]
fn queue_planner_deduplicates_fabric_parent_already_in_interfaces() {
    // When the fabric parent is already in snapshot.interfaces (e.g. as a
    // RETH member), it should not be duplicated.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/0".to_string(),
            linux_name: "ge-0-0-0".to_string(),
            zone: "trust".to_string(),
            ifindex: 21,
            rx_queues: 1,
            ..Default::default()
        }],
        fabrics: vec![FabricSnapshot {
            name: "fab0".to_string(),
            parent_interface: "ge-0/0/0".to_string(),
            parent_linux_name: "ge-0-0-0".to_string(),
            parent_ifindex: 21,
            overlay_linux_name: "fab0".to_string(),
            overlay_ifindex: 101,
            rx_queues: 1,
            peer_address: "10.99.13.2".to_string(),
            local_mac: String::new(),
            peer_mac: String::new(),
            up: true,
        }],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 1, &[]);
    // ge-0-0-0 appears in both interfaces and fabrics but should only
    // produce one binding.
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].interface, "ge-0-0-0");
    assert_eq!(bindings[0].ifindex, 21);
}

#[test]
fn build_synced_session_entry_preserves_fabric_ingress() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "lan".to_string(),
        egress_zone: "wan".to_string(),
        owner_rg_id: 1,
        egress_ifindex: 5,
        tx_ifindex: 5,
        tx_vlan_id: 80,
        fabric_ingress: true,
        ..SessionSyncRequest::default()
    };

    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id()).expect("synced session entry");
    assert!(entry.metadata.fabric_ingress);
    assert!(entry.origin.is_peer_synced());
    assert_eq!(entry.metadata.owner_rg_id, 1);
}

// #2785: a synced session must carry the per-policy `then log` selection so
// it emits the same RT_FLOW SESSION_CREATE/CLOSE records after failover.
// Reverting the helpers.rs mapping hard-codes both false and this fails RED.
#[test]
fn build_synced_session_entry_applies_log_flags() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "lan".to_string(),
        egress_zone: "wan".to_string(),
        egress_ifindex: 5,
        tx_ifindex: 5,
        log_session_init: true,
        log_session_close: true,
        ..SessionSyncRequest::default()
    };
    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id()).expect("synced session entry");
    assert!(entry.metadata.log_session_init, "log_session_init applied");
    assert!(entry.metadata.log_session_close, "log_session_close applied");

    // Close-only: init must NOT leak true.
    let req_close = SessionSyncRequest {
        log_session_init: false,
        log_session_close: true,
        ..req.clone()
    };
    let entry_close = build_synced_session_entry(&req_close, &test_zone_name_to_id())
        .expect("synced session entry");
    assert!(!entry_close.metadata.log_session_init);
    assert!(entry_close.metadata.log_session_close);

    // Old peer omits the fields => serde(default) false => no per-policy log.
    let req_none = SessionSyncRequest {
        log_session_init: false,
        log_session_close: false,
        ..req
    };
    let entry_none = build_synced_session_entry(&req_none, &test_zone_name_to_id())
        .expect("synced session entry");
    assert!(!entry_none.metadata.log_session_init);
    assert!(!entry_none.metadata.log_session_close);
}

// #3301: the admitting policy's firewall metadata (policy_id,
// policy_counter_idx, per-application inactivity-timeout) must ride the
// session-sync wire and be applied to the peer's SyncedSessionEntry so a
// peer-PROMOTED session is correctly attributed, counted, and aged after
// failover. Reverting build_synced_session_entry to the hard 0/None imports
// fails this RED.
#[test]
fn build_synced_session_entry_applies_policy_fields_3301() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "lan".to_string(),
        egress_zone: "wan".to_string(),
        egress_ifindex: 5,
        tx_ifindex: 5,
        policy_id: 42,
        policy_counter_idx: 7,
        inactivity_timeout: 30,
        ..SessionSyncRequest::default()
    };
    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id()).expect("synced session entry");
    assert_eq!(entry.metadata.policy_id, 42, "policy_id must be applied");
    assert_eq!(
        entry.metadata.policy_counter_idx, 7,
        "policy_counter_idx must be applied"
    );
    assert_eq!(
        entry.metadata.inactivity_timeout_ns,
        Some(30u64 * 1_000_000_000),
        "inactivity_timeout (s) must convert to ns and be applied"
    );

    // Mixed-version: an OLD peer omits the new fields (serde default 0). The
    // sync MUST still decode + install with today's defaults (unattributed /
    // no counter / global timeout), NOT be rejected (rolling-upgrade safe).
    let req_legacy: SessionSyncRequest =
        serde_json::from_str(r#"{"operation":"upsert","addr_family":2,"protocol":6,"src_ip":"10.0.61.102","dst_ip":"172.16.80.200","src_port":40000,"dst_port":5201,"ingress_zone":"lan","egress_zone":"wan","egress_ifindex":5,"tx_ifindex":5}"#)
            .expect("legacy SessionSyncRequest without policy fields decodes");
    assert_eq!(req_legacy.policy_id, 0, "missing policy_id defaults to 0");
    assert_eq!(
        req_legacy.policy_counter_idx, 0,
        "missing policy_counter_idx defaults to 0"
    );
    assert_eq!(
        req_legacy.inactivity_timeout, 0,
        "missing inactivity_timeout defaults to 0"
    );
    let entry_legacy = build_synced_session_entry(&req_legacy, &test_zone_name_to_id())
        .expect("legacy synced session still installs (not rejected)");
    assert_eq!(entry_legacy.metadata.policy_id, 0);
    assert_eq!(entry_legacy.metadata.policy_counter_idx, 0);
    assert_eq!(
        entry_legacy.metadata.inactivity_timeout_ns, None,
        "0 inactivity_timeout maps to None (use global per-protocol timeout)"
    );
}

#[test]
fn build_synced_session_entry_preserves_tunnel_endpoint_id() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 1,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "10.255.192.41".to_string(),
        ingress_zone: "lan".to_string(),
        egress_zone: "sfmix".to_string(),
        egress_ifindex: 586,
        tx_ifindex: 0,
        tunnel_endpoint_id: 3,
        ..SessionSyncRequest::default()
    };

    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id()).expect("synced session entry");
    assert_eq!(entry.decision.resolution.tunnel_endpoint_id, 3);
    assert_eq!(entry.decision.resolution.egress_ifindex, 586);
    assert_eq!(
        entry.decision.resolution.disposition,
        afxdp::ForwardingDisposition::ForwardCandidate
    );
}

/// #919/#922: when a peer sends both legacy zone names and the new
/// u16 IDs, the daemon must trust the IDs. Models a new-peer-to-new-
/// daemon flow where the IDs are authoritative even if the names
/// drift (e.g., a name string is misspelled or unresolved).
#[test]
fn build_synced_session_entry_prefers_id_over_legacy_zone_name() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "stale-name".to_string(),
        egress_zone: "stale-name".to_string(),
        ingress_zone_id: 1,
        egress_zone_id: 2,
        owner_rg_id: 1,
        egress_ifindex: 5,
        tx_ifindex: 5,
        ..SessionSyncRequest::default()
    };
    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id()).expect("synced session entry");
    assert_eq!(entry.metadata.ingress_zone, 1);
    assert_eq!(entry.metadata.egress_zone, 2);
}

/// #919/#922: an old peer (legacy strings, no IDs) lands at a new
/// daemon. `ingress_zone_id == 0` triggers the name-lookup
/// fallback; the session is still installed with the resolved ID.
#[test]
fn build_synced_session_entry_falls_back_to_zone_name_when_id_zero() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "lan".to_string(),
        egress_zone: "wan".to_string(),
        owner_rg_id: 1,
        egress_ifindex: 5,
        tx_ifindex: 5,
        ..SessionSyncRequest::default()
    };
    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id()).expect("synced session entry");
    let m = test_zone_name_to_id();
    assert_eq!(entry.metadata.ingress_zone, m["lan"]);
    assert_eq!(entry.metadata.egress_zone, m["wan"]);
}

/// #919/#922: an old peer with strings that the new daemon doesn't
/// know about. Both legacy and ID lookups fail; metadata zone IDs
/// are 0. The session is still installed (we don't drop it) — the
/// caller observes zone-id 0 and treats it as "unknown".
#[test]
fn build_synced_session_entry_unknown_zone_name_does_not_drop_session() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40000,
        dst_port: 5201,
        ingress_zone: "totally-unknown".to_string(),
        egress_zone: "another-unknown".to_string(),
        owner_rg_id: 1,
        egress_ifindex: 5,
        tx_ifindex: 5,
        ..SessionSyncRequest::default()
    };
    let entry =
        build_synced_session_entry(&req, &test_zone_name_to_id()).expect("synced session entry");
    assert_eq!(entry.metadata.ingress_zone, 0);
    assert_eq!(entry.metadata.egress_zone, 0);
}

#[test]
fn queue_planner_preserves_existing_state() {
    let existing = vec![BindingStatus {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: "ge-0-0-1".to_string(),
        ifindex: 11,
        registered: true,
        armed: true,
        ready: true,
        last_change: Some(Utc::now()),
        ..Default::default()
    }];
    let bindings = replan_bindings_from_candidates(
        1,
        &existing,
        vec![("ge-0-0-1".to_string(), 1)],
        BTreeMap::from([("ge-0-0-1".to_string(), 11)]),
    );
    if let Some(b0) = bindings.iter().find(|b| b.slot == 0) {
        assert!(b0.registered);
        assert!(b0.armed);
        assert!(b0.ready);
    } else {
        panic!("binding 0 missing");
    }
}

#[test]
fn queue_planner_ignores_tunnel_netdevices_for_transit() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "gr-0/0/0.0".to_string(),
                linux_name: "gr-0-0-0".to_string(),
                ifindex: 586,
                rx_queues: 1,
                tunnel: true,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/2.80".to_string(),
                linux_name: "ge-0-0-2.80".to_string(),
                zone: "untrust".to_string(),
                ifindex: 24,
                parent_ifindex: 6,
                rx_queues: 1,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 1, &[]);
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].interface, "ge-0-0-2.80");
    assert_eq!(bindings[0].ifindex, 24);
}

#[test]
fn queue_planner_preserves_manual_unregistration() {
    let existing = vec![BindingStatus {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: "ge-0-0-1".to_string(),
        ifindex: 11,
        registered: false,
        armed: false,
        last_change: Some(Utc::now()),
        ..Default::default()
    }];
    let bindings = replan_bindings_from_candidates(
        1,
        &existing,
        vec![("ge-0-0-1".to_string(), 1)],
        BTreeMap::from([("ge-0-0-1".to_string(), 11)]),
    );
    let b0 = bindings.iter().find(|b| b.slot == 0).expect("binding 0");
    assert!(!b0.registered);
    assert!(!b0.armed);
}

#[test]
fn queue_planner_keeps_queue_zero_available_for_userspace() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                ifindex: 11,
                rx_queues: 2,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth1.0".to_string(),
                linux_name: "reth1".to_string(),
                parent_linux_name: "ge-0-0-1".to_string(),
                ifindex: 21,
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.0.61.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 2, &[]);
    let q0 = bindings
        .iter()
        .find(|b| b.interface == "ge-0-0-1" && b.queue_id == 0)
        .expect("queue 0 binding");
    let q1 = bindings
        .iter()
        .find(|b| b.interface == "ge-0-0-1" && b.queue_id == 1)
        .expect("queue 1 binding");
    assert!(q0.registered);
    assert!(q1.registered);
}

#[test]
fn queue_planner_uses_smallest_queue_count() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                zone: "trust".to_string(),
                rx_queues: 4,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/2".to_string(),
                linux_name: "ge-0-0-2".to_string(),
                zone: "untrust".to_string(),
                rx_queues: 2,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 2, &[]);
    assert_eq!(bindings.len(), 4);
    let queues = summarize_queues(&bindings);
    assert_eq!(queues.len(), 2);
    for (idx, q) in queues.iter().enumerate() {
        assert_eq!(q.queue_id, idx as u32);
        assert_eq!(
            q.interfaces,
            vec!["ge-0-0-1".to_string(), "ge-0-0-2".to_string()]
        );
        assert!(!q.registered);
    }
}

#[test]
fn queue_planner_dedups_physical_and_unit_to_same_netdev() {
    // #1921 regression: the snapshot lists BOTH the physical interface and
    // its unit (`ge-0/0/0` + `ge-0/0/0.0`); for a non-VLAN unit both resolve
    // to the SAME Linux netdev. replan_queues must plan ONE binding per
    // (netdev, queue_id), not two — a duplicate is a guaranteed double-bind
    // (the second XSK on an already-bound queue returns EBUSY, the queue
    // never goes READY, and transit is dropped: the virtio multi-queue
    // forwarding outage).
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/0".to_string(),
                linux_name: "ge-0-0-0".to_string(),
                zone: "trust".to_string(),
                rx_queues: 4,
                ..Default::default()
            },
            InterfaceSnapshot {
                // unit 0 of the same physical NIC — same Linux netdev.
                name: "ge-0/0/0.0".to_string(),
                linux_name: "ge-0-0-0".to_string(),
                zone: "trust".to_string(),
                rx_queues: 4,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let bindings = replan_queues(Some(&snapshot), 1, &[]);
    // 4 queues x 1 netdev = 4 bindings, NOT 8.
    assert_eq!(
        bindings.len(),
        4,
        "physical+unit on the same netdev must not double the binding plan"
    );
    // Every (ifindex, queue_id) pair must be unique (no double-bind).
    let mut seen = std::collections::HashSet::new();
    for b in &bindings {
        assert!(
            seen.insert((b.ifindex, b.queue_id)),
            "duplicate binding for (ifindex={}, queue_id={})",
            b.ifindex,
            b.queue_id
        );
    }
    let queues = summarize_queues(&bindings);
    assert_eq!(queues.len(), 4);
    for q in &queues {
        assert_eq!(q.interfaces, vec!["ge-0-0-0".to_string()]);
    }
}

#[test]
fn afxdp_runtime_stays_off_when_forwarding_is_unarmed() {
    let status = ProcessStatus {
        forwarding_armed: false,
        capabilities: UserspaceCapabilities {
            forwarding_supported: true,
            unsupported_reasons: Vec::new(),
        },
        ..Default::default()
    };
    assert!(!should_run_afxdp(&status));
}

#[test]
fn afxdp_runtime_stays_off_when_forwarding_is_unsupported() {
    let status = ProcessStatus {
        forwarding_armed: true,
        capabilities: UserspaceCapabilities {
            forwarding_supported: false,
            unsupported_reasons: vec!["ha".to_string()],
        },
        ..Default::default()
    };
    assert!(!should_run_afxdp(&status));
}

#[test]
fn afxdp_runtime_starts_only_when_armed_and_supported() {
    let status = ProcessStatus {
        forwarding_armed: true,
        capabilities: UserspaceCapabilities {
            forwarding_supported: true,
            unsupported_reasons: Vec::new(),
        },
        ..Default::default()
    };
    assert!(should_run_afxdp(&status));
}

#[test]
fn forwarding_arm_updates_registered_bindings() {
    let mut status = ProcessStatus {
        bindings: vec![
            BindingStatus {
                registered: true,
                ..Default::default()
            },
            BindingStatus {
                registered: false,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    set_bindings_forwarding_armed(&mut status, true);
    assert!(status.bindings[0].armed);
    assert!(!status.bindings[1].armed);
    set_bindings_forwarding_armed(&mut status, false);
    assert!(!status.bindings[0].armed);
    assert!(!status.bindings[1].armed);
}

#[test]
fn binding_counters_snapshot_projects_ring_pressure_fields() {
    // #802/#804: verify projection from BindingStatus into the
    // focused BindingCountersSnapshot carries every ring-pressure
    // field (with the #804 split of bound-pending vs CoS queue
    // overflow), plus the operator-facing TX drop trio re-surfaced
    // for triage. Non-coprime-prime per field so an accidental
    // re-attribution across fields is caught.
    let binding = BindingStatus {
        slot: 0,
        queue_id: 4,
        worker_id: 7,
        ifindex: 12,
        dbg_tx_ring_full: 11,
        dbg_sendto_enobufs: 13,
        dbg_bound_pending_overflow: 17,
        dbg_cos_queue_overflow: 41,
        rx_fill_ring_empty_descs: 19,
        outstanding_tx: 23,
        tx_errors: 29,
        tx_shared_recycle_unknown_slot_drops: 43,
        tx_submit_error_drops: 31,
        pending_tx_local_overflow_drops: 37,
        mirror_drops_queue_full_same_worker: 47,
        mirror_drops_queue_full_cross_worker: 49,
        // #918 / #943: pin per-set LRU collision and V_min telemetry
        // through the projection so a future refactor that drops
        // either assignment surfaces here.
        flow_cache_collision_evictions: 53,
        active_flow_count: 71,
        flow_cache_capacity: 4096,
        v_min_throttle_hard_cap_overrides: 59,
        v_min_throttles: 67,
        ..Default::default()
    };
    // #804: exercise the `impl From<&BindingStatus>` path. The old
    // named `from_binding_status` was renamed to the idiomatic
    // `From` impl so iterator adaptors and `into()` callsites get
    // the conversion for free.
    let snap = BindingCountersSnapshot::from(&binding);
    assert_eq!(snap.worker_id, 7);
    assert_eq!(snap.ifindex, 12);
    assert_eq!(snap.queue_id, 4);
    assert_eq!(snap.dbg_tx_ring_full, 11);
    assert_eq!(snap.dbg_sendto_enobufs, 13);
    assert_eq!(snap.dbg_bound_pending_overflow, 17);
    assert_eq!(snap.dbg_cos_queue_overflow, 41);
    assert_eq!(snap.rx_fill_ring_empty_descs, 19);
    assert_eq!(snap.outstanding_tx, 23);
    assert_eq!(snap.tx_errors, 29);
    assert_eq!(snap.tx_shared_recycle_unknown_slot_drops, 43);
    assert_eq!(snap.tx_submit_error_drops, 31);
    assert_eq!(snap.pending_tx_local_overflow_drops, 37);
    assert_eq!(snap.mirror_drops_queue_full_same_worker, 47);
    assert_eq!(snap.mirror_drops_queue_full_cross_worker, 49);
    assert_eq!(snap.flow_cache_collision_evictions, 53);
    // #1219: pin active_flow_count projection through the From impl.
    assert_eq!(snap.active_flow_count, 71);
    assert_eq!(snap.flow_cache_capacity, 4096);
    assert_eq!(snap.v_min_throttle_hard_cap_overrides, 59);
    assert_eq!(snap.v_min_throttles, 67);
}

#[test]
fn binding_counters_snapshot_serializes_with_expected_wire_keys() {
    // #802/#804: the daemon's poll path parses these JSON keys. Pin
    // the wire names so a rename that breaks the consumer is caught
    // at CI, not in the field. Uses `serde_json::Value` key
    // introspection rather than substring matching so a key that
    // happens to appear inside another field's string value does
    // not accidentally pass the assertion (the original #802 test
    // was flagged in round-1 review as brittle for exactly this
    // reason).
    let snap = BindingCountersSnapshot {
        worker_id: 1,
        ifindex: 2,
        queue_id: 3,
        dbg_tx_ring_full: 4,
        dbg_sendto_enobufs: 5,
        dbg_bound_pending_overflow: 6,
        dbg_cos_queue_overflow: 12,
        rx_fill_ring_empty_descs: 7,
        outstanding_tx: 8,
        tx_completion_ring_available: 30,
        tx_completion_ring_available_max: 32,
        tx_errors: 9,
        tx_shared_recycle_unknown_slot_drops: 14,
        tx_submit_error_drops: 10,
        pending_tx_local_overflow_drops: 11,
        mirrored_packets: 32,
        mirrored_bytes: 33,
        mirror_drops_no_frame: 34,
        mirror_drops_tx_frame_reserve: 35,
        mirror_drops_no_binding: 36,
        mirror_drops_queue_full: 37,
        mirror_drops_queue_full_same_worker: 38,
        mirror_drops_queue_full_cross_worker: 39,
        // #812: populated so wire-key assertions below also cover
        // the new TX submit-latency fields.
        tx_submit_latency_hist: vec![13, 14, 15],
        tx_submit_latency_count: 16,
        tx_submit_latency_sum_ns: 17,
        // #825: populated so wire-key assertions below also cover
        // the new TX kick-latency fields.
        tx_kick_latency_hist: vec![18, 19, 20],
        tx_kick_latency_count: 21,
        tx_kick_latency_sum_ns: 22,
        tx_kick_retry_count: 23,
        // #878: UMEM / TX-ring utilization fields. Plausible
        // values so the wire-key assertions below also cover them.
        umem_total_frames: 24,
        umem_inflight_frames: 25,
        tx_ring_capacity: 26,
        // #918: per-set LRU collision-eviction counter.
        flow_cache_collision_evictions: 27,
        // #1219: non-zero fixture so the wire-key assertion below also covers
        // this field explicitly. Note: active_flow_count has no
        // skip_serializing_if and serializes even when 0; the non-zero
        // value here is chosen to make the test intent obvious.
        active_flow_count: 31,
        flow_cache_capacity: 4096,
        v_min_throttle_hard_cap_overrides: 28,
        v_min_throttles: 29,
        v_min_suspended_batches: 30,
    };
    let value: serde_json::Value =
        serde_json::to_value(&snap).expect("serialize snapshot to Value");
    let obj = value
        .as_object()
        .expect("snapshot serializes as a JSON object");
    for key in [
        "worker_id",
        "ifindex",
        "queue_id",
        "dbg_tx_ring_full",
        "dbg_sendto_enobufs",
        "dbg_bound_pending_overflow",
        "dbg_cos_queue_overflow",
        "rx_fill_ring_empty_descs",
        "outstanding_tx",
        // #1241: TX completion-ring uniformity wire keys. These
        // are required before full flow-fairness measurements so
        // step1/fairness consumers can separate CQ backlog from
        // RSS-placement skew.
        "tx_completion_ring_available",
        "tx_completion_ring_available_max",
        "tx_errors",
        "tx_shared_recycle_unknown_slot_drops",
        "tx_submit_error_drops",
        "pending_tx_local_overflow_drops",
        "mirrored_packets",
        "mirrored_bytes",
        "mirror_drops_no_frame",
        "mirror_drops_tx_frame_reserve",
        "mirror_drops_no_binding",
        "mirror_drops_queue_full",
        "mirror_drops_queue_full_same_worker",
        "mirror_drops_queue_full_cross_worker",
        // #812: new wire keys — absence from BindingCountersSnapshot
        // JSON breaks the Go-side step1-capture consumer.
        "tx_submit_latency_hist",
        "tx_submit_latency_count",
        "tx_submit_latency_sum_ns",
        // #825: new wire keys — absence breaks the P3 / step1
        // kick-latency consumer.
        "tx_kick_latency_hist",
        "tx_kick_latency_count",
        "tx_kick_latency_sum_ns",
        "tx_kick_retry_count",
        // #878: UMEM / TX-ring utilization wire keys (Copilot
        // A.1: must be in the asserted list since the comment
        // above claims wire-key assertions cover them).
        "umem_total_frames",
        "umem_inflight_frames",
        "tx_ring_capacity",
        // #918: per-set LRU collision-eviction counter wire key.
        "flow_cache_collision_evictions",
        // #1219: distinct active flow count wire key — absence breaks
        // the fairness harness's Cstruct computation. The field is
        // always serialized (no skip_serializing_if); the non-zero
        // fixture value makes the assertion intent clear.
        "active_flow_count",
        // #1453/#1454: Rust-owned flow-cache denominator wire key.
        "flow_cache_capacity",
        // #941 Work item D / #943: V_min throttle counter wire keys.
        // Absence breaks the binding-counter snapshot consumer that
        // gates fairness diagnostics on these fields.
        "v_min_throttle_hard_cap_overrides",
        "v_min_throttles",
    ] {
        assert!(
            obj.contains_key(key),
            "wire key `{key}` missing from snapshot JSON object: {value}"
        );
    }
    // #804: the pre-split `dbg_pending_overflow` wire key must not
    // reappear — that was the conflation the split removed.
    assert!(
        !obj.contains_key("dbg_pending_overflow"),
        "pre-split wire key `dbg_pending_overflow` unexpectedly present: {value}"
    );
    // Round-trip: the daemon's JSON → Rust decode path must be
    // symmetric with the Rust encode path.
    let json = serde_json::to_string(&snap).expect("serialize snapshot");
    let round: BindingCountersSnapshot = serde_json::from_str(&json).expect("deserialize snapshot");
    assert_eq!(round, snap);
}

fn run_control_request(
    state: Arc<Mutex<ServerState>>,
    state_file: &str,
    request: ControlRequest,
) -> ControlResponse {
    let (mut client, server) = std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let running = Arc::new(AtomicBool::new(true));
    let state_file = state_file.to_string();
    let handle = std::thread::spawn(move || handle_stream(server, &state_file, state, running));

    serde_json::to_writer(&mut client, &request).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");

    let response: ControlResponse =
        serde_json::from_reader(std::io::BufReader::new(client)).expect("read response");
    handle
        .join()
        .expect("handler thread")
        .expect("handler result");
    response
}

/// #3789: clearing `defer_workers` on a same-plan apply TRIGGERS the
/// deferred-binding reconcile (`debug_reconcile_calls` 0 -> 1). When that
/// reconcile aborts in the pre-teardown preflight — here the gen-2 snapshot
/// clears its mandatory map pins, so it stops at `missing_xsk_pin` — the
/// full-reconcile handler leg now FAILS CLOSED: it reports `ok=false` and
/// keeps the prior deferred (gen-1) snapshot as the boot baseline. Before
/// #3789 `afxdp.reconcile` returned `()`, the handler swallowed the abort,
/// stored the rejected gen-2 (defer_workers=false) snapshot, and acked
/// ok=true — the M1 class #3766 fixed only for the same-plan *refresh* leg.
///
/// #5171: the gen-1 DEFERRED apply now carries valid (test-sentinel) map
/// pins so it passes the new `validate_snapshot_buildable` gate and is
/// still defer-accepted (ok=true). Before #5171 the deferred apply skipped
/// that integrity build entirely, so gen-1 was acked ok=true even with NO
/// map pins — the fail-open this test used to lean on to keep gen-1 valid.
/// The missing-pin abort is now injected at gen-2 (map pins cleared) where
/// the reconcile actually runs.
#[test]
fn apply_snapshot_same_plan_clearing_defer_workers_reconcile_abort_fails_closed_3789() {
    let state = Arc::new(Mutex::new(ServerState {
        status: ProcessStatus {
            workers: 1,
            ring_entries: 64,
            forwarding_armed: true,
            capabilities: UserspaceCapabilities {
                forwarding_supported: true,
                unsupported_reasons: Vec::new(),
            },
            ..ProcessStatus::default()
        },
        snapshot: None,
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }));
    let state_file = format!(
        "{}/xpf-defer-workers-reconcile-{}.json",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let _ = std::fs::remove_file(&state_file);

    let deferred_snapshot = ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 1,
        fib_generation: 1,
        generated_at: Utc::now(),
        capabilities: UserspaceCapabilities {
            forwarding_supported: true,
            unsupported_reasons: Vec::new(),
        },
        userspace: serde_json::json!({
            "workers": 1,
            "ring_entries": 64,
        }),
        // #5171: define the "lan" zone the interface references so the
        // forwarding build in validate_snapshot_buildable resolves it. Before
        // #5171 the deferred apply skipped the build entirely, so this gen-1
        // snapshot was accepted even though its zoned interface referenced an
        // UNDEFINED zone (a non-buildable config) — the fail-open this fix
        // closes.
        zones: vec![ZoneSnapshot {
            name: "lan".to_string(),
            id: 1,
            ..ZoneSnapshot::default()
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/1.0".to_string(),
            zone: "lan".to_string(),
            linux_name: "ge-0-0-1".to_string(),
            ifindex: 11,
            rx_queues: 1,
            ..InterfaceSnapshot::default()
        }],
        // #5171: valid (test-sentinel) map pins so the deferred apply passes
        // validate_snapshot_buildable and is still accepted (ok=true). The
        // missing-pin abort is injected at gen-2 below, not here.
        map_pins: MapPins {
            xsk: "test-map-pin-ok://xsk".to_string(),
            heartbeat: "test-map-pin-ok://heartbeat".to_string(),
            sessions: "test-map-pin-ok://sessions".to_string(),
            ..MapPins::default()
        },
        defer_workers: true,
        ..ConfigSnapshot::default()
    };

    let response = run_control_request(
        state.clone(),
        &state_file,
        ControlRequest {
            request_type: "apply_snapshot".to_string(),
            snapshot: Some(deferred_snapshot.clone()),
            ..ControlRequest::default()
        },
    );
    assert!(response.ok, "unexpected error: {}", response.error);
    let status = response.status.expect("status response");
    assert_eq!(status.debug_reconcile_calls, 0);
    assert_eq!(status.bindings.len(), 1);
    assert!(status.bindings[0].registered);
    assert!(status.bindings[0].last_error.is_empty());

    let mut resumed_snapshot = deferred_snapshot.clone();
    resumed_snapshot.generation = 2;
    resumed_snapshot.fib_generation = 2;
    resumed_snapshot.generated_at = Utc::now();
    resumed_snapshot.defer_workers = false;
    // #5171: clear the mandatory map pins on gen-2 so the deferred-binding
    // reconcile aborts at `missing_xsk_pin` (map pins are NOT part of the
    // binding-plan key, so gen-1 and gen-2 stay same-plan). Pre-#5171 the
    // missing pin lived on gen-1, but a deferred apply with no pins is now
    // rejected by validate_snapshot_buildable before it can be stored.
    resumed_snapshot.map_pins = MapPins::default();
    assert!(same_binding_plan(&deferred_snapshot, &resumed_snapshot));

    let response = run_control_request(
        state.clone(),
        &state_file,
        ControlRequest {
            request_type: "apply_snapshot".to_string(),
            snapshot: Some(resumed_snapshot),
            ..ControlRequest::default()
        },
    );
    // #3789: the aborted deferred-binding reconcile must fail closed.
    assert!(
        !response.ok,
        "an aborted deferred-binding reconcile must fail closed (#3789), got ok=true"
    );
    assert!(
        response.error.contains("missing_xsk_pin"),
        "unexpected error: {}",
        response.error
    );
    let status = response.status.expect("status response");
    // The reconcile WAS triggered (the point of clearing defer_workers) and
    // aborted at the missing mandatory pin.
    assert_eq!(status.debug_reconcile_calls, 1);
    assert_eq!(status.debug_reconcile_stage, "missing_xsk_pin");
    // #3789: the rejected gen-2 snapshot must NOT overwrite the boot
    // baseline — the prior deferred (gen-1, defer_workers=true) snapshot
    // stays stored.
    {
        let guard = state.lock().expect("state poisoned");
        let stored = guard.snapshot.as_ref().expect("snapshot");
        assert_eq!(
            stored.generation, 1,
            "a rejected apply must keep the prior snapshot as the boot baseline"
        );
        assert!(
            stored.defer_workers,
            "a rejected apply must keep the prior deferred snapshot intact"
        );
    }

    let _ = std::fs::remove_file(&state_file);
}

#[test]
fn apply_snapshot_rejects_unsupported_protocol_version() {
    let (mut client, server) = std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let state = Arc::new(Mutex::new(ServerState {
        status: ProcessStatus::default(),
        snapshot: None,
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }));
    let running = Arc::new(AtomicBool::new(true));
    let state_file = format!(
        "{}/xpf-policy-scheduler-version-gate-{}.json",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let handle = {
        let state = state.clone();
        let running = running.clone();
        std::thread::spawn(move || handle_stream(server, &state_file, state, running))
    };

    let request = ControlRequest {
        request_type: "apply_snapshot".to_string(),
        snapshot: Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION - 1,
            generated_at: Utc::now(),
            ..ConfigSnapshot::default()
        }),
        ..ControlRequest::default()
    };
    serde_json::to_writer(&mut client, &request).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");

    let response: ControlResponse =
        serde_json::from_reader(std::io::BufReader::new(client)).expect("read response");
    assert!(!response.ok);
    assert!(
        response
            .error
            .contains("unsupported snapshot protocol version"),
        "unexpected error: {}",
        response.error
    );
    handle
        .join()
        .expect("handler thread")
        .expect("handler result");
}

fn apply_snapshot_for_test(
    state: Arc<Mutex<ServerState>>,
    snapshot: ConfigSnapshot,
) -> ControlResponse {
    let (mut client, server) = std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let running = Arc::new(AtomicBool::new(true));
    let state_file = format!(
        "{}/xpf-apply-snapshot-test-{}-{}.json",
        std::env::temp_dir().display(),
        std::process::id(),
        snapshot.generation
    );
    let handle = {
        let state = state.clone();
        let running = running.clone();
        let state_file = state_file.clone();
        std::thread::spawn(move || handle_stream(server, &state_file, state, running))
    };

    let request = ControlRequest {
        request_type: "apply_snapshot".to_string(),
        snapshot: Some(snapshot),
        ..ControlRequest::default()
    };
    serde_json::to_writer(&mut client, &request).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");

    let response: ControlResponse =
        serde_json::from_reader(std::io::BufReader::new(client)).expect("read response");
    handle
        .join()
        .expect("handler thread")
        .expect("handler result");
    let _ = std::fs::remove_file(state_file);
    response
}

fn persistent_snat_apply_snapshot(generation: u64) -> ConfigSnapshot {
    ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generated_at: Utc::now(),
        generation,
        capabilities: UserspaceCapabilities {
            forwarding_supported: true,
            ..UserspaceCapabilities::default()
        },
        // #2440: the reconcile preflight now opens the mandatory map
        // FDs (xsk/heartbeat/sessions) BEFORE publishing the forwarding
        // state, so a snapshot with empty mandatory pins aborts before
        // the SNAT state this test inspects is published. Wire the
        // mandatory pins to the bpf_map::pin test sentinel (resolves to
        // a dummy fd without bpffs) so the apply proceeds to publish.
        // Sentinel literal mirrors `TEST_MAP_PIN_OK` in
        // userspace-dp/src/afxdp/bpf_map/pin.rs (the const is
        // afxdp-scoped, not reachable from this crate-root test module).
        map_pins: MapPins {
            xsk: "test-map-pin-ok://xsk".to_string(),
            heartbeat: "test-map-pin-ok://heartbeat".to_string(),
            sessions: "test-map-pin-ok://sessions".to_string(),
            ..MapPins::default()
        },
        source_nat_rules: vec![SourceNATRuleSnapshot {
            name: "persistent-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            pool_name: "persistent-pool".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: 40000,
            port_high: 40001,
            persistent_nat: true,
            persistent_nat_permit_any_remote_host: true,
            persistent_nat_inactivity_timeout: 300,
            ..SourceNATRuleSnapshot::default()
        }],
        ..ConfigSnapshot::default()
    }
}

fn apply_path_persistent_snat_key(
    src_port: u16,
    dst_ip: std::net::IpAddr,
    dst_port: u16,
) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: 2,
        protocol: 17,
        src_ip: "192.0.2.10".parse().unwrap(),
        dst_ip,
        src_port,
        dst_port,
    }
}

#[test]
fn apply_snapshot_same_plan_preserves_persistent_snat_lease_state() {
    let state = Arc::new(Mutex::new(ServerState {
        status: ProcessStatus {
            forwarding_armed: true,
            capabilities: UserspaceCapabilities {
                forwarding_supported: true,
                ..UserspaceCapabilities::default()
            },
            ..ProcessStatus::default()
        },
        snapshot: None,
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }));

    let initial = apply_snapshot_for_test(state.clone(), persistent_snat_apply_snapshot(1));
    assert!(initial.ok, "initial apply failed: {}", initial.error);

    let first_dst: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    let first_nat = {
        let guard = state.lock().expect("server state");
        match guard.afxdp.test_match_source_nat_result_for_tuple(
            "lan",
            "wan",
            "192.0.2.10".parse().unwrap(),
            first_dst,
            17,
            12345,
            53,
            None,
            None,
            1,
        ) {
            crate::nat::SourceNatLookup::Matched(decision) => decision,
            other => panic!("unexpected first SNAT lookup result: {other:?}"),
        }
    };
    {
        let guard = state.lock().expect("server state");
        guard.afxdp.test_release_source_nat_allocation(
            &apply_path_persistent_snat_key(12345, first_dst, 53),
            first_nat,
            2,
        );
        let status = guard.afxdp.source_nat_pool_statuses();
        assert_eq!(status[0].live_flows, 0);
        assert_eq!(status[0].used_ports, 1);
        assert_eq!(status[0].persistent_leases, 1);
        assert_eq!(status[0].allocations_total, 1);
        assert_eq!(status[0].reuses_total, 0);
    }

    let refresh = apply_snapshot_for_test(state.clone(), persistent_snat_apply_snapshot(2));
    assert!(refresh.ok, "same-plan apply failed: {}", refresh.error);
    {
        let guard = state.lock().expect("server state");
        let status = guard.afxdp.source_nat_pool_statuses();
        assert_eq!(status[0].live_flows, 0);
        assert_eq!(status[0].used_ports, 1);
        assert_eq!(status[0].persistent_leases, 1);
        assert_eq!(status[0].allocations_total, 1);
        assert_eq!(status[0].reuses_total, 0);
    }

    let second_dst: std::net::IpAddr = "1.1.1.1".parse().unwrap();
    let reused = {
        let guard = state.lock().expect("server state");
        match guard.afxdp.test_match_source_nat_result_for_tuple(
            "lan",
            "wan",
            "192.0.2.10".parse().unwrap(),
            second_dst,
            17,
            12345,
            443,
            None,
            None,
            3,
        ) {
            crate::nat::SourceNatLookup::Matched(decision) => decision,
            other => panic!("unexpected reused SNAT lookup result: {other:?}"),
        }
    };
    assert_eq!(reused.rewrite_src, first_nat.rewrite_src);
    assert_eq!(reused.rewrite_src_port, first_nat.rewrite_src_port);
    {
        let guard = state.lock().expect("server state");
        let status = guard.afxdp.source_nat_pool_statuses();
        assert_eq!(status[0].live_flows, 1);
        assert_eq!(status[0].used_ports, 1);
        assert_eq!(status[0].persistent_leases, 1);
        assert_eq!(status[0].allocations_total, 1);
        assert_eq!(status[0].reuses_total, 1);
    }
}

#[test]
fn binding_counters_snapshot_tolerates_pre_split_wire() {
    // #804: a helper snapshot that pre-dates the
    // dbg_pending_overflow → {dbg_bound_pending_overflow,
    // dbg_cos_queue_overflow} split must still deserialize — the
    // two new fields should default to 0 rather than the decode
    // failing. This is the compat contract the split relies on.
    let legacy_json = r#"{
        "worker_id": 1,
        "ifindex": 2,
        "queue_id": 3,
        "dbg_tx_ring_full": 4,
        "dbg_sendto_enobufs": 5,
        "dbg_pending_overflow": 99,
        "rx_fill_ring_empty_descs": 7,
        "outstanding_tx": 8,
        "tx_errors": 9,
        "tx_submit_error_drops": 10,
        "pending_tx_local_overflow_drops": 11
    }"#;
    let snap: BindingCountersSnapshot =
        serde_json::from_str(legacy_json).expect("legacy snapshot decodes");
    // The unknown legacy field is discarded; the two new fields
    // default to 0 via `serde(default)`. Callers that need a total
    // across either path must sum the two explicitly — there is no
    // silent re-attribution of the legacy number to one bucket.
    assert_eq!(snap.dbg_bound_pending_overflow, 0);
    assert_eq!(snap.dbg_cos_queue_overflow, 0);
    // Everything else round-trips as expected.
    assert_eq!(snap.worker_id, 1);
    assert_eq!(snap.dbg_tx_ring_full, 4);
    assert_eq!(snap.rx_fill_ring_empty_descs, 7);
}

#[test]
fn config_snapshot_three_color_policers_roundtrip() {
    let json = r#"{
        "version": 1,
        "generation": 42,
        "generated_at": "2026-05-17T00:00:00Z",
        "summary": {
            "host_name": "fw",
            "dataplane_type": "userspace",
            "interface_count": 0,
            "zone_count": 0,
            "policy_count": 0,
            "scheduler_count": 0,
            "ha_enabled": false
        },
        "three_color_policers": [
            {
                "name": "tr",
                "mode": "two-rate",
                "color_blind": true,
                "committed_rate_bytes_per_sec": 125000,
                "committed_burst_bytes": 50000,
                "peak_or_excess_rate_bytes_per_sec": 250000,
                "peak_or_excess_burst_bytes": 100000,
                "then_action": "discard"
            }
        ]
    }"#;
    let snap: ConfigSnapshot = serde_json::from_str(json).expect("three-color snapshot decodes");
    assert_eq!(snap.three_color_policers.len(), 1);
    let policer = &snap.three_color_policers[0];
    assert_eq!(policer.name, "tr");
    assert_eq!(policer.mode, "two-rate");
    assert!(policer.color_blind);
    assert_eq!(policer.committed_rate_bytes_per_sec, 125000);
    assert_eq!(policer.committed_burst_bytes, 50000);
    assert_eq!(policer.peak_or_excess_rate_bytes_per_sec, 250000);
    assert_eq!(policer.peak_or_excess_burst_bytes, 100000);

    let encoded = serde_json::to_value(&snap).expect("three-color snapshot serializes");
    assert!(
        encoded.get("three_color_policers").is_some(),
        "three_color_policers wire key missing from Rust serialization: {encoded}"
    );
}

#[test]
fn config_snapshot_mirror_configs_roundtrip() {
    let json = r#"{
        "version": 1,
        "generation": 42,
        "generated_at": "2026-05-17T00:00:00Z",
        "summary": {
            "host_name": "fw",
            "dataplane_type": "userspace",
            "interface_count": 0,
            "zone_count": 0,
            "policy_count": 0,
            "scheduler_count": 0,
            "ha_enabled": false
        },
        "mirror_configs": [
            {"ingress_ifindex": 11, "output_ifindex": 22, "rate": 100},
            {"ingress_ifindex": 12, "output_ifindex": 22, "rate": 0}
        ]
    }"#;
    let snap: ConfigSnapshot = serde_json::from_str(json).expect("mirror snapshot decodes");
    assert_eq!(
        snap.mirror_configs,
        vec![
            MirrorConfigSnapshot {
                ingress_ifindex: 11,
                output_ifindex: 22,
                rate: 100,
            },
            MirrorConfigSnapshot {
                ingress_ifindex: 12,
                output_ifindex: 22,
                rate: 0,
            },
        ],
        "Rust snapshot DTO must round-trip the Go mirror_configs wire shape"
    );

    let encoded = serde_json::to_value(&snap).expect("mirror snapshot serializes");
    assert!(
        encoded.get("mirror_configs").is_some(),
        "mirror_configs wire key missing from Rust serialization: {encoded}"
    );
}

#[test]
fn tx_latency_hist_serialization_roundtrip() {
    // #812 plan §6.1 test #4. Construct a BindingCountersSnapshot
    // with a non-trivial TX submit-latency histogram; JSON-encode,
    // JSON-decode; assert field-equality — including the Vec<u64>
    // contents (no length truncation, no reorder).
    let snap = BindingCountersSnapshot {
        worker_id: 2,
        ifindex: 11,
        queue_id: 5,
        dbg_tx_ring_full: 0,
        dbg_sendto_enobufs: 0,
        dbg_bound_pending_overflow: 0,
        dbg_cos_queue_overflow: 0,
        rx_fill_ring_empty_descs: 0,
        outstanding_tx: 0,
        tx_completion_ring_available: 0,
        tx_completion_ring_available_max: 0,
        tx_errors: 0,
        tx_shared_recycle_unknown_slot_drops: 0,
        tx_submit_error_drops: 0,
        pending_tx_local_overflow_drops: 0,
        mirrored_packets: 0,
        mirrored_bytes: 0,
        mirror_drops_no_frame: 0,
        mirror_drops_tx_frame_reserve: 0,
        mirror_drops_no_binding: 0,
        mirror_drops_queue_full: 0,
        mirror_drops_queue_full_same_worker: 0,
        mirror_drops_queue_full_cross_worker: 0,
        // Hand-built plausible histogram — bucket 0 heavy,
        // tail in buckets 6-7, saturation bucket 15 empty.
        tx_submit_latency_hist: vec![9001, 123, 45, 30, 12, 4, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0],
        tx_submit_latency_count: 9225,
        tx_submit_latency_sum_ns: 12_345_678,
        // #825: unrelated-to-submit values so the round-trip
        // also covers the four new fields.
        tx_kick_latency_hist: vec![4000, 80, 20, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        tx_kick_latency_count: 4105,
        tx_kick_latency_sum_ns: 7_654_321,
        tx_kick_retry_count: 42,
        // #878: UMEM / TX-ring utilization fields.
        umem_total_frames: 12_288,
        umem_inflight_frames: 4_096,
        tx_ring_capacity: 2_048,
        // #918: per-set LRU collision-eviction counter.
        flow_cache_collision_evictions: 17,
        active_flow_count: 0,
        flow_cache_capacity: 0,
        v_min_throttle_hard_cap_overrides: 18,
        v_min_throttles: 19,
        v_min_suspended_batches: 20,
    };
    let json = serde_json::to_string(&snap).expect("serialize snapshot");
    let back: BindingCountersSnapshot = serde_json::from_str(&json).expect("deserialize snapshot");
    assert_eq!(back, snap);
    assert_eq!(back.tx_submit_latency_hist.len(), 16);
    assert_eq!(back.tx_submit_latency_hist[0], 9001);
    assert_eq!(back.tx_submit_latency_hist[7], 2);
}

#[test]
fn tx_latency_hist_backward_compat_old_payload_deserializes() {
    // #812 plan §6.1 test #4 (second half). A pre-#812 JSON
    // payload MUST deserialize without the three new fields
    // — they default to empty Vec / zero u64 via
    // `#[serde(default)]`. This is the wire-compat contract
    // the step1-capture consumer relies on.
    let legacy_json = r#"{
        "worker_id": 5,
        "ifindex": 7,
        "queue_id": 2,
        "dbg_tx_ring_full": 0,
        "dbg_sendto_enobufs": 0,
        "dbg_bound_pending_overflow": 0,
        "dbg_cos_queue_overflow": 0,
        "rx_fill_ring_empty_descs": 0,
        "outstanding_tx": 0,
        "tx_errors": 0,
        "tx_submit_error_drops": 0,
        "pending_tx_local_overflow_drops": 0
    }"#;
    let snap: BindingCountersSnapshot =
        serde_json::from_str(legacy_json).expect("pre-#812 payload decodes");
    assert_eq!(snap.worker_id, 5);
    assert!(
        snap.tx_submit_latency_hist.is_empty(),
        "pre-#812 payload must default to empty Vec<u64>",
    );
    assert_eq!(snap.tx_submit_latency_count, 0);
    assert_eq!(snap.tx_submit_latency_sum_ns, 0);
}

#[test]
fn tx_latency_hist_binding_counters_snapshot_is_static_send() {
    // #812 plan §6.1 test #8 (runtime corollary of the named
    // compile-time const-assert
    // `_ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND`
    // in protocol.rs). Exercise the `'static + Send` bound at
    // test time too so if the const-assert were ever silently
    // removed, this test still fires. A reference-holding
    // future field would fail EITHER the compile (const-
    // assert) OR this runtime helper (which requires
    // `T: 'static + Send`), catching the regression two
    // different ways.
    fn require_static_send<T: 'static + Send>() {}
    require_static_send::<BindingCountersSnapshot>();
}

// ---------------------------------------------------------------------------
// #5173: the shim must not transform a packet's queue coordinate.
// ---------------------------------------------------------------------------
//
// AF_XDP delivery is queue-bound: the kernel's `xsk_rcv_check` drops a redirect
// whose target socket is bound to a different (netdev, queue) than the packet
// arrived on. So between "which queue did this arrive on" and "which XSK do we
// redirect to" the queue coordinate must survive unchanged.
//
// SCOPE, stated plainly, because the three checks below are NOT the same kind
// of check and that difference decides what they can catch.
//
// The shim is `no_std`, built for `bpfel-unknown-none`, so this crate cannot
// execute the shim BINARY. What it can do — and now does — is compile the
// shim's own index module for the host and RUN it: `binding_index.rs` is
// `#[path]`-included below, so `shim_binding_slot_never_leaves_its_interfaces_row`
// is a behavioural test of the exact source the BPF object is built from. The
// mapping and the stride bound are results there, not claims about text.
//
// What execution cannot cover is whether the shim still CALLS that function,
// and with what arguments. That half is unavoidably a source assertion, and a
// source assertion only sees what it is written to look for. Two hostile rounds
// escaped earlier versions of it with every guard green:
//
//   round 1 — transform the raw `rx_queue_index` before the identity call, and
//             add a raw fallback lookup in a DIFFERENT file, which a
//             file-scoped check cannot see by construction.
//   round 2 — the repo-scoped rewrite that fixed round 1 replaced a token-exact
//             index pin with a bare occurrence COUNT of the needle
//             `USERSPACE_BINDINGS.get(` — and a count cannot see an index that
//             has been transformed. Six mutations reintroduced #5173 green,
//             including `.get(idx % 4)`, dropping `binding_slot` from the path
//             entirely, and reinstating the removed unbounded raw-queue
//             fallback with a single NEWLINE before `.get(` — which is exactly
//             the formatting rustfmt emits for a chain of that length.
//
// Coverage had REGRESSED while the claim strengthened. So the source half is
// now TOKEN-based rather than substring-based, and it pins whole STATEMENTS
// rather than counting needles: `shim_token_vec` drops whitespace, so rustfmt
// reflow is invisible to it while any added, removed or altered token is not.
// What is STILL unbound is enumerated on
// `shim_index_path_has_one_construction_and_one_lookup` — that list is not
// empty and cannot be made empty by a source assertion.
//
// The planner half of #5173 was reverted from this PR (see #6702), so the
// executable coverage that used to be cited here no longer exists in this
// branch; `queue_planner_uses_smallest_queue_count` — master's own test,
// restored by that revert — is what exercises the real planner now, and it is
// the negative control for the mutation matrix precisely because it is true in
// both worlds.

/// Collapse a Rust snippet to a formatting-insensitive token VECTOR.
///
/// Identifiers (and numbers) are single tokens; every other non-whitespace
/// character is its own token. Whitespace is dropped entirely.
///
/// This is the whole reason the checks below survive rustfmt AND catch what a
/// substring count cannot. A newline is not a token here, so
/// `USERSPACE_BINDINGS\n.get(` and `USERSPACE_BINDINGS.get(` are the SAME
/// sequence — while as substrings they differ, and that one-character
/// difference was the entire bypass for the reinstated raw-queue fallback in
/// the round-2 review. Conversely `.get(idx)` and `.get(idx % 4)` are the same
/// SUBSTRING prefix but different token sequences, which is the direction a
/// bare needle count is blind in.
fn shim_token_vec(src: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if c.is_alphanumeric() || c == '_' {
            let mut w = String::from(c);
            while let Some(&n) = chars.peek() {
                if n.is_alphanumeric() || n == '_' {
                    w.push(n);
                    chars.next();
                } else {
                    break;
                }
            }
            out.push(w);
        } else {
            out.push(c.to_string());
        }
    }
    out
}

/// Space-joined [`shim_token_vec`], for readable assertion messages.
fn shim_tokens(src: &str) -> String {
    shim_token_vec(src).join(" ")
}

/// Count occurrences of a token SEQUENCE inside a token stream.
///
/// Windows overlap, so a repeat that abuts its predecessor is still counted —
/// undercounting here would be a fail-OPEN, and the whole point of these checks
/// is that a second occurrence must be impossible to hide.
fn shim_token_seq_count(hay: &[String], needle: &[&str]) -> usize {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    hay.windows(needle.len())
        .filter(|w| w.iter().zip(needle).all(|(a, b)| a.as_str() == *b))
        .count()
}

// #5173: the index computation is EXECUTED here, not described.
//
// `binding_index.rs` is the shim's own source, `#[path]`-included and compiled
// for the host. What runs below is the code the BPF object is built from.
#[path = "../../userspace-xdp/src/binding_index.rs"]
mod shim_binding_index;

/// Every `(ifindex, queue)` resolves to its OWN interface's row, or to nothing.
///
/// This replaces four source-spelling checks that a hostile review escaped
/// twice. The mapping, the stride bound, and the property that a slot never
/// leaves its interface's row are now results of running the shim's function.
#[test]
fn shim_binding_slot_never_leaves_its_interfaces_row() {
    use shim_binding_index::{BINDING_QUEUES_PER_IFACE as STRIDE, RawRxQueue, binding_slot};
    for ifindex in [0u32, 1, 2, 7, 63, 1000, 65535] {
        let row_start = ifindex * STRIDE;
        for q in 0u32..64 {
            let got = binding_slot(ifindex, RawRxQueue::from_ctx_field(q));
            if q >= STRIDE {
                assert_eq!(
                    got, None,
                    "#5173: queue {q} is at or above the stride and must resolve to NO binding; \
                     clamping it back into range is the mis-steer in another form, and indexing \
                     with it addresses ifindex {}'s row",
                    ifindex + q / STRIDE
                );
                continue;
            }
            let slot = got.unwrap_or_else(|| panic!("in-stride queue {q} resolved to no binding"));
            assert_eq!(
                slot,
                row_start + q,
                "#5173: the slot must be the packet's OWN queue in its OWN interface's row"
            );
            assert!(
                slot >= row_start && slot < row_start + STRIDE,
                "#5173: slot {slot} escaped ifindex {ifindex}'s row [{row_start}, {})",
                row_start + STRIDE
            );
        }
    }
}

/// The queue coordinate cannot be transformed after it is wrapped.
///
/// `RawRxQueue` has a private field and no arithmetic impls, so `queue % 2`,
/// `queue & 3` and friends do not COMPILE outside its module — enforced by the
/// compiler rather than asserted about source text. Verified by compiling both
/// directions: `rx_queue % 4` is rejected (E0369) and the tuple constructor is
/// unreachable outside the module (E0423), while reducing the raw `u32` BEFORE
/// construction builds clean — the constructor must accept a bare integer,
/// because the value originates in an aya context no `core`-only module can
/// see.
///
/// TWO things this does NOT cover, stated because an earlier revision claimed
/// there was only one:
///
///  - a reduction applied before the wrap;
///  - a value forged out of raw bytes rather than constructed —
///    `transmute::<u32, RawRxQueue>(..)`, `mem::zeroed()`,
///    `MaybeUninit::assume_init()`, a pointer read. A private field stops the
///    CONSTRUCTOR, not a fabrication, and naming `transmute` alone (as an
///    earlier revision did) understates it: the class is open-ended and every
///    member of it compiles.
///
/// Both are bounded by source instead, in
/// `shim_index_path_has_one_construction_and_one_lookup` — not by chasing the
/// symbols, which would always be one symbol behind, but by bounding the one
/// NAME the pinned lookup statement will accept. Neither is bounded by a type,
/// and no type can bound them.
///
/// This test itself is not decorative: `for_trace()` feeds the queue index the
/// shim hands to the helper in `record_trace`, so corrupting it is a runtime
/// defect and reds here.
#[test]
fn shim_raw_rx_queue_exposes_no_arithmetic() {
    use shim_binding_index::RawRxQueue;
    let a = RawRxQueue::from_ctx_field(3);
    let b = RawRxQueue::from_ctx_field(3);
    assert_eq!(a, b, "the wrapper must preserve the coordinate verbatim");
    assert_eq!(a.for_trace(), 3, "telemetry readback must not alter the value");
}

/// REPO-scoped and TOKEN-exact: the whole shim crate wraps the coordinate in
/// exactly one place and reads the binding map in exactly one place, and BOTH
/// of those statements are pinned token-for-token.
///
/// Two rounds of hostile review shaped this, and both lessons are load-bearing:
///
///  1. **File-scoped is not enough.** A reviewer escaped the per-file version by
///     putting a raw fallback lookup in a DIFFERENT file, which a per-file check
///     cannot see by construction. Hence the crate walk.
///  2. **A count is not enough.** The repo-scoped rewrite that fixed (1)
///     replaced the token-exact index pin with a bare `str::matches` count of
///     `USERSPACE_BINDINGS.get(`. A count cannot see an index that has been
///     transformed, so `.get(idx % 4)` — #5173 verbatim — passed, as did
///     dropping `binding_slot` from the packet path and inlining a reduced
///     index, and as did reinstating the deleted unbounded raw-queue fallback
///     with one NEWLINE before `.get(`. Coverage had regressed while the claim
///     strengthened. Hence whole-STATEMENT token pins.
///  3. **A statement pin fixes SPELLING, not VALUE.** Both coordinates reach
///     the pinned lookup by NAME, so pinning that statement says nothing about
///     what the names are worth. Round 3 shadowed each of them one line above
///     the pin — `% 4` on the ifindex, and an unsafe raw-bytes forgery on the
///     queue — and all three tests stayed green. Hence the binding bounds: a
///     value can only reach the pinned statement through a binding of that
///     exact name, so bounding the BINDINGS is what bounds the values. (The
///     first attempt at that bounded one SPELLING of a binding rather than
///     bindings — see (5).)
///  4. **A compile-time claim is only true while the type still says so.**
///     Adding `impl Rem<u32> for RawRxQueue` and a `pub` field reddened
///     nothing, and with one shadow line reintroduced #5173 with no `unsafe`
///     at all. Hence the trait-impl and field-privacy bounds.
///  5. **A binding bound must bound BINDINGS, not one spelling of one.**
///     `["let", name]` matches a bare-identifier `let` pattern and nothing
///     else. Round 4 walked through it four ways, all compiling with all three
///     tests green: `let (rx_queue, _z) = (transmute::<u32, RawRxQueue>(q % 4),
///     0u32);` — which is #5173 in the EMITTED OBJECT, gaining `r1 &= 0x3`
///     before the map lookup and losing the `> 0xf` stride guard —
///     `let Some(<name>) = … else`, a `macro_rules!` body taking an
///     `$n:ident`, and the closure/`fn` parameter that used to be carried
///     below as the declared residual. Hence the mention COUNT, which is
///     class-complete over binding forms in a way no pattern match is: a
///     binding cannot exist without writing the name it binds.
///
/// # What is still unbound — and it cannot be driven to zero here
///
/// These are source assertions about a call site whose coordinate originates in
/// an aya `XdpContext`, which a `core`-only module cannot see. So a residual is
/// structural, not an oversight. The list is SHORTER than it was, because the
/// binding bounds subsume what used to be enumerated symbol by symbol — a
/// forged `RawRxQueue` (`transmute`, `mem::zeroed`, `MaybeUninit::assume_init`,
/// a pointer read: an open-ended class no symbol list could keep up with) can
/// only be USED by binding the name the pinned lookup passes, and every form of
/// binding raises that name's count. What remains:
///
///  - **CONSERVATION — the mention bound counts, it does not classify.** Every
///    binding form has to write the name, so none of them is FREE; but an
///    author who also DELETES an existing mention pays for one and leaves the
///    total where it was. That is what is left of the binding residual, and it
///    is not the same shape as what it replaced: the escape is no longer an
///    added line, it is an added line plus a deletion. Every mention counted is
///    a pinned statement, a compiled use, or one documentation line, so the
///    deletion has to remove real code or real prose from a hash-pinned file.
///    The two counts leave very different amounts of slack, and it is worth
///    saying which. `rx_queue`'s six code sites are the two pinned statements,
///    `for_trace()`'s only caller, and `binding_slot`'s parameter plus its two
///    uses — deleting ANY of them breaks a pin, the build, or the executed
///    stride test, so its one doc line is the only free slot. `ingress_ifindex`
///    is looser: most of its 24 code sites are `record_trace` arguments, and
///    dropping a trace call compiles. Buying a shadow there costs a visibly
///    deleted telemetry call rather than nothing.
///  - **The ifindex half is a bare `u32`.** `binding_slot`'s queue argument is a
///    newtype; its ifindex argument is not, and it cannot be one without a
///    second wrapper whose constructor would take a bare `u32` for the same
///    aya-shaped reason — moving the residual, not closing it. Both of its
///    statements and its binding count are pinned below; none of that is the
///    type system.
///  - **Anything the tokenizer sees as identical text.** Comments and string
///    literals are tokenized like code. That direction is fail-CLOSED (a
///    spurious RED, never a silent pass), which is the correct polarity, but it
///    does mean a prose mention can trip the count bounds below.
#[test]
fn shim_index_path_has_one_construction_and_one_lookup() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("userspace-xdp")
        .join("src");
    let mut sources: Vec<(String, String)> = Vec::new();
    fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
        for e in std::fs::read_dir(dir).expect("read shim src dir") {
            let p = e.expect("dir entry").path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                let body = std::fs::read_to_string(&p).expect("read shim source");
                out.push((p.display().to_string(), body));
            }
        }
    }
    walk(&root, &mut sources);
    assert!(!sources.is_empty(), "found no shim sources under {}", root.display());

    let tokens: Vec<(String, Vec<String>)> = sources
        .iter()
        .map(|(name, body)| (name.clone(), shim_token_vec(body)))
        .collect();

    // Files in which `needle` occurs, one entry per occurrence.
    let seq = |needle: &[&str]| -> Vec<String> {
        tokens
            .iter()
            .flat_map(|(name, toks)| {
                std::iter::repeat(name.clone()).take(shim_token_seq_count(toks, needle))
            })
            .collect()
    };

    // ---- The walk IS the crate only while the crate IS the walk. ----------
    //
    // A `#[path]` module or an `include!` pulls source in from outside
    // `userspace-xdp/src/`, and every bound below would silently stop covering
    // it — a fail-open in the one dimension walking the directory exists to
    // close. Matched on TOKENS so `#[ path` does not slip past, same as
    // everything else here.
    //
    // The first version of this refusal matched only the literal spellings
    // `[ path` and `include !`, and round 3 walked straight through it twice:
    //
    //   - `#[cfg_attr(all(), path = "…/evil.rs")] mod evil;` never emits the
    //     token pair `[ path`, and rustc really does compile the off-tree file
    //     (proven positively: a syntax error in it fails the build pointing at
    //     the off-tree line). A second, reduced binding-map read was placed on
    //     the packet path there with every bound below green.
    //   - `use core::include as inc;` then `inc!("…")` never emits `include !`.
    //
    // So match the two capabilities, not their spellings. Any attribute form
    // that redirects a module — bare, `cfg_attr`-wrapped, or nested to any
    // depth — has to write the token pair `path =`. Any route to the macro,
    // aliased or not, has to NAME `include` to import it. Both are refused
    // outright; prose that trips them is a spurious RED, which is the polarity
    // this whole test is built on.
    let offpath: Vec<String> = seq(&["[", "path"])
        .into_iter()
        .chain(seq(&["path", "="]))
        .chain(seq(&["include"]))
        .collect();
    assert!(
        offpath.is_empty(),
        "#5173: {offpath:?} names a module-path attribute or the `include` macro, so the shim \
         crate is no longer confined to {}. The bounds in this test walk that directory; source \
         pulled in from elsewhere would be invisible to every one of them — the exact fail-open \
         this refusal exists to close. Extend the walk before adding either. (Prose tripping \
         this is a false RED; reword it.)",
        root.display()
    );

    // ---- The binding lookup, pinned as a whole statement. -----------------
    //
    // This single assertion is what closes the round-2 escapes, because the
    // sequence names every part an attacker has to touch: `binding_slot` is on
    // the packet path, BOTH of its arguments are untransformed, and the value
    // handed to the map read is the resolved slot with nothing applied to it.
    #[rustfmt::skip]
    const LOOKUP_STATEMENT: &[&str] = &[
        "let", "binding", "=",
        "binding_slot", "(", "ingress_ifindex", ",", "rx_queue", ")",
        ".", "and_then", "(", "|", "idx", "|",
        "USERSPACE_BINDINGS", ".", "get", "(", "idx", ")", ")", ";",
    ];
    let pinned = seq(LOOKUP_STATEMENT);
    // Show what IS there when the pin fails. "found 0 occurrences" on its own
    // would send the next author hunting for a needle this test already holds.
    let actual: Vec<String> = sources
        .iter()
        .flat_map(|(name, body)| {
            body.lines()
                .filter(|l| l.contains("USERSPACE_BINDINGS"))
                .map(move |l| format!("{name}: {}", shim_tokens(l)))
        })
        .collect();
    assert_eq!(
        pinned.len(),
        1,
        "#5173: the shim's binding lookup must be exactly this statement, once:\n  {}\nfound \
         {} occurrence(s) {pinned:?}.\nLines naming the map, tokenized:\n{actual:#?}\nEvery \
         round-2 escape is a token inside that sequence: `.get(idx % 4)` reduces the resolved \
         slot; `binding_slot(ingress_ifindex % 4, ..)` reduces the interface coordinate; \
         inlining the index drops `binding_slot` off the packet path so the executed stride \
         bound no longer governs anything. A needle COUNT sees none of those — the whole \
         statement must match.",
        LOOKUP_STATEMENT.join(" "),
        pinned.len(),
    );

    // ---- No second lookup, however it is spelled or wrapped. --------------
    let lookups = seq(&["USERSPACE_BINDINGS", ".", "get", "("]);
    assert_eq!(
        lookups.len(),
        1,
        "#5173: the shim crate must contain exactly ONE binding-map read; found {lookups:?}. A \
         second one is how the removed raw-queue fallback returns, and it indexed with an \
         unbounded rx_queue_index. This is TOKEN-matched, not substring-matched, because the \
         predecessor check was defeated by putting a newline before `.get(` — the very \
         formatting rustfmt produces for a chain this long."
    );

    // ---- …and no ALIAS that would dodge the check above. ------------------
    //
    // `use USERSPACE_BINDINGS as BINDS;` (or `let b = &USERSPACE_BINDINGS;`)
    // gives a second lookup a name the sequence above cannot match. Pinning the
    // identifier's total occurrence count is what closes that: any alias, any
    // re-export, any local rebinding has to NAME the static to create itself.
    const BINDINGS_MENTIONS: usize = 2; // the `static` item + the one lookup
    let mentions = seq(&["USERSPACE_BINDINGS"]);
    assert_eq!(
        mentions.len(),
        BINDINGS_MENTIONS,
        "#5173: `USERSPACE_BINDINGS` must be named exactly {BINDINGS_MENTIONS} times in the shim \
         crate — its `static` definition and the single lookup — but was named {} times \
         {mentions:?}. This bound is deliberately tight: an alias, a re-export or a local \
         rebinding is how a second, unbounded lookup gets a name the sequence checks above \
         cannot see, and all of them have to mention the static to exist. A comment that spells \
         the identifier trips this too; that is a spurious RED, never a silent pass. If you are \
         adding a legitimate mention, raise the constant deliberately and say why.",
        mentions.len(),
    );

    // ---- The wrap site, pinned the same way. ------------------------------
    #[rustfmt::skip]
    const CONSTRUCTION_STATEMENT: &[&str] = &[
        "let", "rx_queue", "=",
        "RawRxQueue", ":", ":", "from_ctx_field", "(",
        "unsafe", "{", "(", "*", "ctx", ".", "ctx", ")", ".", "rx_queue_index", "}",
        ")", ";",
    ];
    let ctor_site = seq(CONSTRUCTION_STATEMENT);
    assert_eq!(
        ctor_site.len(),
        1,
        "#5173: the coordinate must be wrapped by exactly this statement, once:\n  {}\nfound {} \
         occurrence(s) {ctor_site:?}. The constructor takes a bare u32, so a reduction applied \
         BEFORE the wrap is one of the two escapes the newtype cannot prevent (`transmute` is \
         the other, and nothing here catches it) — which makes the argument spelling the \
         load-bearing part, not just the call's existence.",
        CONSTRUCTION_STATEMENT.join(" "),
        ctor_site.len(),
    );

    // A second construction re-opens the pre-wrap reduction, so bound the
    // constructor's name the same way the static's is bounded above: aliasing
    // the TYPE (`use RawRxQueue as RQ;`) still has to name the method.
    const CTOR_MENTIONS: usize = 2; // the `fn` item + the one call
    let ctors = seq(&["from_ctx_field"]);
    assert_eq!(
        ctors.len(),
        CTOR_MENTIONS,
        "#5173: `from_ctx_field` must be named exactly {CTOR_MENTIONS} times in the shim crate — \
         its definition and the single call — but was named {} times {ctors:?}. A second \
         construction site is a second chance to reduce the raw integer before it is wrapped, \
         and renaming the type on import does not hide the method name.",
        ctors.len(),
    );

    // ---- The INTERFACE half of the index, pinned the same way. ------------
    //
    // `binding_slot` takes two coordinates and only the queue one is a
    // newtype, so the ifindex is the half a type cannot defend. Round 3 used
    // exactly that: the statement pin above fixes how the argument is SPELLED,
    // not what it is WORTH, and
    //
    //     let ingress_ifindex = ingress_ifindex % 4;
    //
    // one line above the pinned lookup compiles for the real target, is #5173
    // through the interface dimension, and left all three tests green. Pinning
    // where the value comes FROM closes the other half of that: reducing it at
    // the definition instead breaks this sequence.
    #[rustfmt::skip]
    const INGRESS_STATEMENT: &[&str] = &[
        "let", "ingress_ifindex", "=",
        "unsafe", "{", "(", "*", "ctx", ".", "ctx", ")", ".", "ingress_ifindex", "}", ";",
    ];
    let ifx_site = seq(INGRESS_STATEMENT);
    assert_eq!(
        ifx_site.len(),
        1,
        "#5173: the interface coordinate must be read by exactly this statement, once:\n  \
         {}\nfound {} occurrence(s) {ifx_site:?}. It is a bare u32 all the way to `binding_slot`, \
         so unlike the queue coordinate NOTHING rejects a reduction of it by type — pinning both \
         its definition and its use is the whole defence. `let mut`, or any arithmetic applied \
         here, changes this sequence.",
        INGRESS_STATEMENT.join(" "),
        ifx_site.len(),
    );

    // ---- Neither coordinate may be re-bound, in ANY binding form. ---------
    //
    // The two statement pins fix the definition and the use; a SHADOW between
    // them changes neither. Two bounds close that, and they are deliberately
    // different in KIND, because the first one alone was escaped.
    //
    // `let <name>` is the PRECISE bound. It matches the exact shape of the
    // three escapes round 3 demonstrated, so when it reds its message can say
    // what was done:
    //
    //   - `ingress_ifindex` rebound to `ingress_ifindex % 4` — #5173 through
    //     the interface dimension, invisible to both statement pins;
    //   - `rx_queue` shadowed by an unsafe forgery — `core::mem::zeroed()`,
    //     `transmute`, `MaybeUninit::assume_init`, a pointer read. The newtype
    //     stops the CONSTRUCTOR, never a raw-bytes fabrication, and the class
    //     is open-ended, so bounding the class by symbol name would always be
    //     one symbol behind. Bounding the BINDING is not: the lookup statement
    //     is pinned to pass the identifier `rx_queue`, so a forged value is
    //     only reachable by binding that exact name;
    //   - `rx_queue` shadowed by arithmetic once an impl makes it legal (see
    //     the trait bound below) — a complete #5173 reintroduction with no
    //     `unsafe` anywhere.
    //
    // Matching `let <name>` rather than `<name> =` is deliberate: a type
    // annotation (`let rx_queue: RawRxQueue = …`) puts a token between the two
    // and slips a `<name> =` pair, and the unsafe-forgery shadow is spelled
    // exactly that way. Reassignment without `let` needs `mut`, which breaks
    // whichever statement pin above declares the name.
    //
    // The MENTION COUNT is the CLASS-COMPLETE bound, and it ships because
    // `let <name>` on its own was escaped FOUR ways in round 4 — every one of
    // them compiling for `bpfel-unknown-none`, with all three tests green.
    // `["let", name]` matches only a BARE-IDENTIFIER `let` pattern; put any
    // token between the two and it is gone. The four:
    //
    //   - a tuple pattern —
    //         let (rx_queue, _z) = (transmute::<u32, RawRxQueue>(q % 4), 0u32);
    //     which is a COMPILED #5173, not a theoretical one: the emitted program
    //     gains `r1 &= 0x3` before the map lookup and LOSES the `> 0xf` stride
    //     guard, because LLVM can then prove the index in range;
    //   - `let Some(<name>) = … else { … };`, and every other refutable or
    //     destructuring pattern with it;
    //   - a `macro_rules!` body taking an `$n:ident`. An earlier revision of
    //     this comment asserted that such a body "must still write these tokens
    //     to define itself, and macro hygiene stops an out-of-crate one from
    //     shadowing here". That was simply WRONG on the first half: the body
    //     writes `let $n`, and an `ident` metavariable is call-site-hygienic, so
    //     an in-crate macro shadows fine;
    //   - a closure or `fn` PARAMETER — which this test used to carry as its
    //     declared residual, and no longer does.
    //
    // Enumerating binding FORMS would always be one form behind, exactly as
    // enumerating fabrication symbols would. Counting MENTIONS is not, and that
    // is the whole reason it is what ships: a binding of `<name>` — tuple,
    // struct, slice or `Some(..)` pattern, `let … else`, `if let`, `while let`,
    // `for`, a match arm, a macro expansion, a closure or `fn` parameter —
    // cannot exist without WRITING `<name>`, so every one of them raises this
    // count. Same idiom, and the same reasoning, as `BINDINGS_MENTIONS` and
    // `CTOR_MENTIONS` above; the counts are larger here only because these two
    // are ordinary working identifiers rather than one-site symbols.
    //
    // What the count does NOT do is classify — it counts. What that leaves is
    // on this test's doc comment under CONSERVATION.
    const INGRESS_IFINDEX_MENTIONS: usize = 25; // 24 code sites + 1 doc line
    const RX_QUEUE_MENTIONS: usize = 7; //         6 code sites + 1 doc line
    for (name, mention_bound) in [
        ("ingress_ifindex", INGRESS_IFINDEX_MENTIONS),
        ("rx_queue", RX_QUEUE_MENTIONS),
    ] {
        let rebinds = seq(&["let", name]);
        assert_eq!(
            rebinds.len(),
            1,
            "#5173: `{name}` must be bound by exactly ONE `let {name}` statement in the shim \
             crate, but {} match {rebinds:?}. Both statement pins above stay green when the \
             coordinate is SHADOWED between its definition and its use, so this is the bound that \
             sees it — a one-line `%` shadow, or a shadow whose value is forged out of raw bytes \
             by any `unsafe` construction the newtype cannot prevent. Do not add a second binding \
             of this name; if the value genuinely needs deriving, give the derived value a \
             DIFFERENT name and note that the pinned lookup statement will then reject passing \
             it. (This bound sees a bare-identifier `let` and nothing else — a tuple pattern, a \
             `let … else`, a macro expansion or a parameter slips it, which is what the mention \
             bound below is for.)",
            rebinds.len(),
        );

        // Per-file tally rather than one entry per occurrence: at these counts
        // a flat list is a wall of the same path, and which FILE moved is the
        // only part an author needs.
        let tally: Vec<String> = tokens
            .iter()
            .filter_map(|(file, toks)| match shim_token_seq_count(toks, &[name]) {
                0 => None,
                n => Some(format!("{file}: {n}")),
            })
            .collect();
        let mentions = seq(&[name]);
        assert_eq!(
            mentions.len(),
            mention_bound,
            "#5173: `{name}` must be NAMED exactly {mention_bound} times in the shim crate, but \
             was named {} times. Per file: {tally:#?}\nThis is the CLASS-COMPLETE half of the \
             binding bound and the reason it is a count rather than a pattern match: a rebinding \
             of this name in ANY form — a tuple, struct, slice or `Some(..)` pattern, a \
             `let … else`, `if let`, `while let`, `for`, a match arm, a `macro_rules!` expansion, \
             or a closure/`fn` parameter — has to WRITE the name to exist, so all of them land \
             here even though only the bare-identifier `let` lands on the bound above. Four such \
             forms were demonstrated compiling with every other check green, one of them a \
             `transmute` forgery bound through a tuple pattern that reintroduced #5173 in the \
             emitted object. A comment or doc line that spells the identifier trips this too; \
             that is a spurious RED, never a silent pass. If you are adding a legitimate mention, \
             raise the constant deliberately and say why.",
            mentions.len(),
        );
    }

    // ---- The newtype's compile-time half, tested rather than assumed. -----
    //
    // `binding_index.rs` claims the coordinate cannot be reduced because
    // `RawRxQueue` has a private field and implements no arithmetic — "enforced
    // by the compiler rather than asserted about source text". True, but only
    // while both remain so, and nothing tested that. Round 3 added
    // `impl Rem<u32>` plus a `pub` field and NOTHING went red; with one shadow
    // line that is a full #5173 reintroduction with no `unsafe` marker for a
    // reader to catch. These two bounds are what make the compile-time claim a
    // claim about the code that is actually there.
    let trait_impls = seq(&["for", "RawRxQueue"]);
    assert!(
        trait_impls.is_empty(),
        "#5173: `RawRxQueue` must implement NO traits — found {trait_impls:?}. An arithmetic impl \
         (`Rem`, `BitAnd`, `Shr`) makes reducing the coordinate compile, and `Deref`/`Into` hand \
         out the raw integer to be reduced elsewhere; either way the module's compile-time half \
         is gone while every other check here stays green. `#[derive]`d traits are written before \
         the type, not after it, so they do not trip this."
    );
    let decl = seq(&["RawRxQueue", "(", "u32", ")"]);
    assert_eq!(
        decl.len(),
        1,
        "#5173: `RawRxQueue`'s field must stay PRIVATE — expected exactly one declaration with an \
         unqualified `u32` field, found {} {decl:?}. Marking it `pub` re-exposes the coordinate to \
         arithmetic outside the module, which is the same defect as an arithmetic impl by another \
         route.",
        decl.len(),
    );
}

