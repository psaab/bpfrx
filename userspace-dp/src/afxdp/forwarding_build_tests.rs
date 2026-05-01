// Tests for afxdp/forwarding_build.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep forwarding_build.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tests.rs"]` from mod.rs.

use super::*;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSDSCPRewriteRuleEntrySnapshot, CoSDSCPRewriteRuleSnapshot, CoSForwardingClassSnapshot,
    CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
};

#[test]
fn build_cos_state_translates_scheduler_map_entries() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 3_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 7_000_000,
                    transmit_rate_exact: true,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");
    assert_eq!(iface.shaping_rate_bytes, 10_000_000);
    assert_eq!(iface.burst_bytes, 256_000);
    assert_eq!(iface.default_queue, 0);
    assert_eq!(iface.queues.len(), 2);
    assert_eq!(iface.queues[0].queue_id, 0);
    assert_eq!(iface.queues[0].forwarding_class, "best-effort");
    assert_eq!(iface.queues[0].priority, 5);
    assert_eq!(iface.queues[0].transmit_rate_bytes, 3_000_000);
    assert!(!iface.queues[0].exact);
    assert_eq!(iface.queues[0].surplus_weight, 5);
    assert_eq!(iface.queues[0].buffer_bytes, 128_000);
    assert_eq!(iface.queues[1].queue_id, 1);
    assert_eq!(iface.queues[1].forwarding_class, "expedited-forwarding");
    assert_eq!(iface.queues[1].priority, 0);
    assert_eq!(iface.queues[1].transmit_rate_bytes, 7_000_000);
    assert!(iface.queues[1].exact);
    assert_eq!(iface.queues[1].surplus_weight, 12);
    assert_eq!(iface.queues[1].buffer_bytes, 64_000);
}

#[test]
fn build_cos_state_falls_back_to_default_best_effort_queue() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 7,
            cos_shaping_rate_bytes_per_sec: 1_000_000,
            cos_scheduler_map: "missing-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot::default()),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state
        .interfaces
        .get(&7)
        .expect("missing fallback CoS interface");
    assert_eq!(iface.shaping_rate_bytes, 1_000_000);
    assert_eq!(iface.burst_bytes, default_cos_burst_bytes(1_000_000));
    assert_eq!(iface.default_queue, 0);
    assert_eq!(iface.queues.len(), 1);
    assert_eq!(iface.queues[0].queue_id, 0);
    assert_eq!(iface.queues[0].forwarding_class, "best-effort");
    assert_eq!(iface.queues[0].priority, 5);
    assert_eq!(iface.queues[0].transmit_rate_bytes, 1_000_000);
    assert!(!iface.queues[0].exact);
    assert_eq!(iface.queues[0].surplus_weight, 1);
    assert_eq!(
        iface.queues[0].buffer_bytes,
        default_cos_burst_bytes(1_000_000)
    );
}

#[test]
fn build_cos_state_derives_exact_queue_default_burst_from_queue_rate() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 25_000_000_000 / 8,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 100_000_000 / 8,
                transmit_rate_exact: true,
                priority: "low".into(),
                buffer_size_bytes: 0,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");

    assert_eq!(iface.shaping_rate_bytes, 25_000_000_000 / 8);
    assert_eq!(
        iface.burst_bytes,
        default_cos_burst_bytes(25_000_000_000 / 8),
        "interface burst should still derive from the parent shaper"
    );
    assert_eq!(iface.queues.len(), 1);
    assert_eq!(iface.queues[0].transmit_rate_bytes, 100_000_000 / 8);
    assert!(iface.queues[0].exact);
    assert_eq!(
        iface.queues[0].buffer_bytes,
        default_cos_burst_bytes(100_000_000 / 8),
        "exact queue burst must derive from the scheduler rate, not the 25 Gb/s parent shaper"
    );
}

#[test]
fn build_cos_state_uses_effective_transmit_rate_for_surplus_weight() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 9,
            cos_shaping_rate_bytes_per_sec: 1_000_000,
            cos_scheduler_map: "test-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 0,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "test-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&9).expect("missing CoS interface");
    assert_eq!(iface.queues.len(), 1);
    assert_eq!(iface.queues[0].transmit_rate_bytes, 1_000_000);
    assert_eq!(iface.queues[0].surplus_weight, 16);
}

#[test]
fn build_cos_state_binds_dscp_classifier_to_usable_interface_queue_ids() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            cos_dscp_classifier: "wan-classifier".into(),
            cos_ieee8021_classifier: "wan-pcp".into(),
            cos_dscp_rewrite_rule: "wan-rewrite".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "voice".into(),
                    queue: 5,
                },
            ],
            dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                name: "wan-classifier".into(),
                entries: vec![
                    CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "voice".into(),
                        loss_priority: "low".into(),
                        dscp_values: vec![46],
                    },
                    CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        loss_priority: "low".into(),
                        dscp_values: vec![0],
                    },
                ],
            }],
            ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                name: "wan-pcp".into(),
                entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                    forwarding_class: "voice".into(),
                    loss_priority: "low".into(),
                    code_points: vec![5],
                }],
            }],
            dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
                name: "wan-rewrite".into(),
                entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                    forwarding_class: "voice".into(),
                    loss_priority: "low".into(),
                    dscp_value: 46,
                }],
            }],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be".into(),
                    transmit_rate_bytes: 1_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 0,
                },
                CoSSchedulerSnapshot {
                    name: "voice".into(),
                    transmit_rate_bytes: 2_000_000,
                    transmit_rate_exact: false,
                    priority: "high".into(),
                    buffer_size_bytes: 0,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "voice".into(),
                        scheduler: "voice".into(),
                    },
                ],
            }],
            ..Default::default()
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");
    assert_eq!(iface.dscp_classifier, "wan-classifier");
    assert_eq!(iface.ieee8021_classifier, "wan-pcp");
    assert_eq!(
        iface
            .queues
            .iter()
            .find(|queue| queue.queue_id == 5)
            .and_then(|queue| queue.dscp_rewrite),
        Some(46)
    );
    assert!(iface.queues.iter().any(|queue| queue.queue_id == 5));
    let classifier = state
        .dscp_classifiers
        .get("wan-classifier")
        .expect("missing classifier");
    assert_eq!(classifier.queue_by_dscp.get(&46), Some(&5));
    assert_eq!(classifier.queue_by_dscp.get(&0), Some(&0));
    let pcp_classifier = state
        .ieee8021_classifiers
        .get("wan-pcp")
        .expect("missing 802.1p classifier");
    assert_eq!(pcp_classifier.queue_by_pcp.get(&5), Some(&5));
}

#[test]
fn build_forwarding_state_prefers_logical_unit_for_ingress_lookup() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0-0-1".into(),
                ifindex: 10,
                hardware_addr: "02:00:00:00:00:10".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0-0-1.0".into(),
                ifindex: 11,
                parent_ifindex: 10,
                vlan_id: 0,
                hardware_addr: "02:00:00:00:00:10".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.ingress_logical_ifindex.get(&(10, 0)), Some(&11));
}
#[test]
fn build_forwarding_state_disables_tx_selection_when_no_cos_or_filters_exist() {
    let state = build_forwarding_state(&ConfigSnapshot::default());
    assert!(!state.tx_selection_enabled_v4);
    assert!(!state.tx_selection_enabled_v6);
}

#[test]
fn build_forwarding_state_enables_tx_selection_when_cos_interfaces_exist() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 10_000_000,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            ..Default::default()
        }),
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);
    assert!(state.tx_selection_enabled_v4);
    assert!(state.tx_selection_enabled_v6);
}

/// #919/#922: any zone with id ≥ ZONE_ID_RESERVED_MIN must be
/// dropped at config-build time so a hostile/buggy snapshot cannot
/// collide with the JUNOS_GLOBAL_ZONE_ID sentinel (u16::MAX).
#[test]
fn build_forwarding_state_rejects_reserved_zone_ids() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "ok".into(),
                id: 5,
            },
            ZoneSnapshot {
                name: "reserved-edge".into(),
                id: crate::policy::ZONE_ID_RESERVED_MIN,
            },
            ZoneSnapshot {
                name: "global-sentinel".into(),
                id: crate::policy::JUNOS_GLOBAL_ZONE_ID,
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.zone_name_to_id.get("ok").copied(), Some(5));
    assert!(state.zone_name_to_id.get("reserved-edge").is_none());
    assert!(state.zone_name_to_id.get("global-sentinel").is_none());
    assert!(state
        .zone_id_to_name
        .get(&crate::policy::ZONE_ID_RESERVED_MIN)
        .is_none());
    assert!(state
        .zone_id_to_name
        .get(&crate::policy::JUNOS_GLOBAL_ZONE_ID)
        .is_none());
}

/// #921: ifindex_to_zone_id is populated at config build time
/// from the snapshot's per-interface zone NAME via zone_name_to_id.
#[test]
fn ifindex_to_zone_id_populated_from_snapshot_at_build_time() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "trust".into(),
            id: 7,
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/0".into(),
            zone: "trust".into(),
            ifindex: 42,
            hardware_addr: "02:00:00:00:00:42".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.ifindex_to_zone_id.get(&42).copied(), Some(7));
}

/// #921: EgressInterface.zone_id is set from the snapshot at
/// config build time.
#[test]
fn egress_interface_zone_id_set_from_snapshot() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "wan".into(),
            id: 11,
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/1".into(),
            zone: "wan".into(),
            ifindex: 99,
            hardware_addr: "02:00:00:00:00:99".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let eg = state.egress.get(&99).expect("egress");
    assert_eq!(eg.zone_id, 11);
}

/// #921: an interface whose zone snapshot field references a zone
/// that was DROPPED at config build time (reserved id, > u8 max)
/// collapses to zone_id == 0 (the canonical "unknown" sentinel).
#[test]
fn interface_pointing_at_skipped_zone_collapses_to_zone_id_zero() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "reserved".into(),
            id: crate::policy::ZONE_ID_RESERVED_MIN, // dropped at build
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/2".into(),
            zone: "reserved".into(),
            ifindex: 23,
            hardware_addr: "02:00:00:00:00:23".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    // Zone was dropped; the interface still appears in the
    // ifindex_to_zone_id map but with the unknown sentinel 0.
    assert_eq!(state.ifindex_to_zone_id.get(&23).copied(), Some(0));
}

/// #921: an EgressInterface whose snapshot zone string isn't in
/// the zones list collapses to zone_id == 0.
#[test]
fn egress_with_unknown_zone_name_collapses_to_zone_id_zero() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "trust".into(),
            id: 3,
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/3".into(),
            zone: "ghost".into(), // not in zones
            ifindex: 56,
            hardware_addr: "02:00:00:00:00:56".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let eg = state.egress.get(&56).expect("egress");
    assert_eq!(eg.zone_id, 0);
}
