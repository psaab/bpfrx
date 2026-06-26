// Tests for afxdp/forwarding_build/. Moved from
// afxdp/forwarding_build_tests.rs to the directory-module
// colocated path in #1342 (split forwarding_build.rs by entity
// kind). Loaded as a sibling sub-module via `#[cfg(test)] mod
// tests;` in forwarding_build/mod.rs (no `#[path]` attribute).

use super::*;
use crate::filter::TermMatchExtra;
use crate::filter::evaluate_filter_ref_tx_selection_runtime_counted;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSDSCPRewriteRuleEntrySnapshot, CoSDSCPRewriteRuleSnapshot, CoSForwardingClassSnapshot,
    CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
    FirewallFilterSnapshot, FirewallTermSnapshot, ThreeColorPolicerSnapshot,
};
use std::net::{IpAddr, Ipv4Addr};

fn three_color_snapshot(burst: u64) -> ConfigSnapshot {
    ConfigSnapshot {
        filters: vec![FirewallFilterSnapshot {
            name: "policed".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "meter".into(),
                action: "accept".into(),
                policer: "stable-pol".into(),
                ..Default::default()
            }],
        }],
        three_color_policers: vec![ThreeColorPolicerSnapshot {
            name: "stable-pol".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: burst,
            peak_or_excess_burst_bytes: 50,
            then_action: "discard".into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[test]
fn parse_syn_cookie_master_key_accepts_exact_hex_key() {
    assert_eq!(
        parse_syn_cookie_master_key("00112233445566778899aabbccddeeff"),
        Some([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
    );
}

#[test]
fn parse_syn_cookie_master_key_rejects_malformed_keys() {
    for key in [
        "",
        "00112233445566778899aabbccddee",
        "00112233445566778899aabbccddeeff00",
        "00112233445566778899aabbccddeefg",
    ] {
        assert_eq!(
            parse_syn_cookie_master_key(key),
            None,
            "key {key:?} should fail closed"
        );
    }
}

#[test]
fn forwarding_state_refresh_preserves_three_color_runtime_state() {
    let policy_counters = PolicyCounterStore::default();
    let snapshot = three_color_snapshot(100);
    let state = build_forwarding_state_with_policy_counters(&snapshot, &policy_counters);
    let refreshed = build_forwarding_state_with_policy_counters_and_previous(
        &snapshot,
        &policy_counters,
        &crate::nat::NatCounterStore::default(),
        Some(&state),
    )
    .expect("test snapshot must not produce integrity error");
    assert!(std::sync::Arc::ptr_eq(
        &state.filter_state.three_color_policers[0],
        &refreshed.filter_state.three_color_policers[0]
    ));

    let filter = state.filter_state.filters.get("inet:policed").unwrap();
    let first = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        100,
        0,
    );
    assert!(!first.policer_drop);

    let refreshed_filter = refreshed.filter_state.filters.get("inet:policed").unwrap();
    let second = evaluate_filter_ref_tx_selection_runtime_counted(
        refreshed_filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        51,
        0,
    );

    assert!(
        second.policer_drop,
        "production refresh must share runtime state during publication"
    );
    let status = refreshed.filter_state.three_color_policer_statuses();
    assert_eq!(status[0].green_packets, 1);
    assert_eq!(status[0].red_packets, 1);
    assert_eq!(status[0].drop_packets, 1);
}

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
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 7_000_000,
                    transmit_rate_exact: true,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
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
    assert!(iface.queues[0].guarantee_enabled);
    assert!(!iface.queues[0].exact);
    assert_eq!(iface.queues[0].surplus_weight, 5);
    assert_eq!(iface.queues[0].buffer_bytes, 128_000);
    assert_eq!(iface.queues[1].queue_id, 1);
    assert_eq!(iface.queues[1].forwarding_class, "expedited-forwarding");
    assert_eq!(iface.queues[1].priority, 0);
    assert_eq!(iface.queues[1].transmit_rate_bytes, 7_000_000);
    assert!(iface.queues[1].guarantee_enabled);
    assert!(iface.queues[1].exact);
    assert_eq!(iface.queues[1].surplus_weight, 12);
    assert_eq!(iface.queues[1].buffer_bytes, 64_000);
}

#[test]
fn build_cos_state_resolves_percent_buffer_size_from_interface_burst_pool() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
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
                transmit_rate_bytes: 3_000_000,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 0,
                buffer_size_percent: 10.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
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
    assert_eq!(iface.burst_bytes, 256_000);
    assert_eq!(
        iface.queues[0].buffer_bytes, 25_600,
        "10% of the resolved interface CoS burst pool must not compile to zero"
    );

    let runtime = crate::afxdp::cos::builders::build_cos_interface_runtime(iface, 0);
    assert!(
        runtime.queues[0].config.buffer_bytes >= crate::afxdp::cos::COS_MIN_BURST_BYTES,
        "runtime queue buffer must retain a non-zero capacity after the queue floor"
    );
}

#[test]
fn build_cos_state_prefers_legacy_byte_buffer_when_both_fields_present() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
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
                transmit_rate_bytes: 3_000_000,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 10.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
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
    assert_eq!(
        iface.queues[0].buffer_bytes, 128_000,
        "legacy buffer_size_bytes must keep precedence for additive protocol compatibility"
    );
}

// #915 (Copilot code-review #3): regression test that
// `build_cos_state` correctly propagates the snapshot
// `surplus_sharing` flag into the runtime `CoSQueueConfig`.
// The builders test alone is insufficient because it starts from
// a hand-built `CoSQueueConfig`, so a regression that stops
// `build_cos_state` from copying the snapshot field would not
// show up there. This test starts from a `CoSSchedulerSnapshot`
// with `surplus_sharing=true` and verifies the field arrives at
// `CoSQueueConfig.surplus_sharing`.
#[test]
fn build_cos_state_propagates_surplus_sharing_from_snapshot() {
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
                    name: "iperf-a".into(),
                    queue: 4,
                },
                CoSForwardingClassSnapshot {
                    name: "iperf-b".into(),
                    queue: 5,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "iperf-a".into(),
                    transmit_rate_bytes: 1_000_000_000 / 8,
                    transmit_rate_exact: true,
                    priority: "low".into(),
                    buffer_size_bytes: 128 * 1024,
                    buffer_size_percent: 0.0,
                    surplus_sharing: true, // opt-in
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "iperf-b".into(),
                    transmit_rate_bytes: 10_000_000_000 / 8,
                    transmit_rate_exact: true,
                    priority: "low".into(),
                    buffer_size_bytes: 128 * 1024,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false, // explicit hard-cap
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "iperf-a".into(),
                        scheduler: "iperf-a".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "iperf-b".into(),
                        scheduler: "iperf-b".into(),
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
    let q4 = iface.queues.iter().find(|q| q.queue_id == 4).unwrap();
    let q5 = iface.queues.iter().find(|q| q.queue_id == 5).unwrap();
    assert!(
        q4.surplus_sharing,
        "snapshot scheduler iperf-a (surplus_sharing=true) must reach \
         CoSQueueConfig.surplus_sharing on queue 4"
    );
    assert!(
        !q5.surplus_sharing,
        "snapshot scheduler iperf-b (surplus_sharing=false) must reach \
         CoSQueueConfig.surplus_sharing=false on queue 5"
    );
    // Sanity: both still exact (so the strip-on-non-exact rule wouldn't have
    // fired even if it had been at this layer).
    assert!(q4.exact && q5.exact);
}

#[test]
fn build_cos_state_propagates_equal_flow_target_policy_gated_on_enforcement() {
    // #1746: the policy string reaches CoSQueueConfig only when the
    // scheduler is actually equal-flow-enforcing; otherwise the queue
    // carries the byte-unchanged default `Slowest`. #2458: an unknown
    // NON-EMPTY policy on an active equal-flow scheduler now fails the
    // snapshot closed (see the dedicated fail-closed test below); the
    // empty/unset string still decodes to `Slowest`.
    let make_sched = |name: &str, enforcement: bool, policy: &str| CoSSchedulerSnapshot {
        name: name.into(),
        transmit_rate_bytes: 1_000_000_000 / 8,
        transmit_rate_exact: true,
        priority: "low".into(),
        buffer_size_bytes: 128 * 1024,
        buffer_size_percent: 0.0,
        surplus_sharing: false,
        equal_flow_enforcement: enforcement,
        equal_flow_target_policy: policy.into(),
        codel_target_ns: 0,
    };
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
                    name: "fc-mean".into(),
                    queue: 4,
                },
                CoSForwardingClassSnapshot {
                    name: "fc-ungated".into(),
                    queue: 5,
                },
                CoSForwardingClassSnapshot {
                    name: "fc-ideal".into(),
                    queue: 6,
                },
                CoSForwardingClassSnapshot {
                    name: "fc-empty".into(),
                    queue: 7,
                },
            ],
            schedulers: vec![
                make_sched("s-mean", true, "mean"),
                // Policy set but enforcement absent: must stay Slowest.
                make_sched("s-ungated", false, "mean"),
                make_sched("s-ideal", true, "ideal-share"),
                // #2458: empty/unset policy on an active equal-flow
                // scheduler is the legacy default and decodes to Slowest.
                make_sched("s-empty", true, ""),
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "fc-mean".into(),
                        scheduler: "s-mean".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "fc-ungated".into(),
                        scheduler: "s-ungated".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "fc-ideal".into(),
                        scheduler: "s-ideal".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "fc-empty".into(),
                        scheduler: "s-empty".into(),
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
    let policy_of = |queue_id: u8| {
        iface
            .queues
            .iter()
            .find(|q| q.queue_id == queue_id)
            .unwrap_or_else(|| panic!("queue {queue_id} present"))
            .equal_flow_target_policy
    };
    assert_eq!(policy_of(4), EqualFlowTargetPolicy::Mean);
    assert_eq!(
        policy_of(5),
        EqualFlowTargetPolicy::Slowest,
        "policy without equal-flow-enforcement must stay at the default"
    );
    assert_eq!(policy_of(6), EqualFlowTargetPolicy::IdealShare);
    assert_eq!(
        policy_of(7),
        EqualFlowTargetPolicy::Slowest,
        "empty/unset policy string must decode to the byte-unchanged default"
    );
}

#[test]
fn build_cos_state_fails_closed_on_unknown_equal_flow_target_policy() {
    // #2458: an active equal-flow scheduler carrying a NON-EMPTY policy
    // string that is not one of slowest|mean|ideal-share fails the
    // snapshot CLOSED (the helper-boundary backstop for a typo or a
    // version-drifted snapshot) rather than silently mapping it to the
    // `Slowest` default and changing queue fairness with no failure
    // surfaced. The Go commit-time gate (#1746/#2458) is the primary
    // defense; this proves the Rust backstop names the offending value.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "fc-bad".into(),
                queue: 4,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "s-bad".into(),
                transmit_rate_bytes: 1_000_000_000 / 8,
                transmit_rate_exact: true,
                priority: "low".into(),
                buffer_size_bytes: 128 * 1024,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: true,
                equal_flow_target_policy: "bogus-policy".into(),
                codel_target_ns: 0,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "fc-bad".into(),
                    scheduler: "s-bad".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };

    // Call the fallible production orchestrator directly (the `super::*`
    // `build_cos_state` test wrapper `.expect()`s a clean snapshot).
    match super::cos::build_cos_state(&snapshot) {
        Err(crate::policy::SnapshotIntegrityError::CosUnknownEqualFlowTargetPolicy {
            forwarding_class,
            target_policy,
        }) => {
            assert_eq!(forwarding_class, "fc-bad");
            assert_eq!(target_policy, "bogus-policy");
        }
        Err(other) => panic!("wrong integrity error: {other}"),
        Ok(_) => panic!("unknown equal-flow-target-policy must fail the snapshot closed"),
    }
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
    assert!(iface.queues[0].guarantee_enabled);
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
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
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
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
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
    assert!(
        !iface.queues[0].guarantee_enabled,
        "zero scheduler transmit-rate inherits an effective rate for surplus sizing only"
    );
    assert_eq!(iface.queues[0].surplus_weight, 16);
}

#[test]
fn build_cos_state_marks_no_rate_scheduler_map_queue_residual_only() {
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
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
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
    assert!(
        !iface.queues[0].guarantee_enabled,
        "scheduler-map queue without explicit transmit-rate must not become a root-rate guarantee"
    );
    assert!(!iface.queues[0].exact);
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
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                },
                CoSSchedulerSnapshot {
                    name: "voice".into(),
                    transmit_rate_bytes: 2_000_000,
                    transmit_rate_exact: false,
                    priority: "high".into(),
                    buffer_size_bytes: 0,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
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
fn build_forwarding_state_keeps_parent_bound_vlan_units_distinct() {
    use crate::ZoneSnapshot;

    let snapshot = ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "wan".into(),
                id: 11,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "dmz".into(),
                id: 12,
                ..Default::default()
            },
        ],
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth0.80".into(),
                zone: "wan".into(),
                ifindex: 20080,
                parent_ifindex: 6,
                vlan_id: 80,
                hardware_addr: "02:00:00:00:00:06".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.81".into(),
                zone: "dmz".into(),
                ifindex: 20081,
                parent_ifindex: 6,
                vlan_id: 81,
                hardware_addr: "02:00:00:00:00:06".into(),
                cos_shaping_rate_bytes_per_sec: 20_000_000,
                ..Default::default()
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot::default()),
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);

    assert_eq!(state.ingress_logical_ifindex.get(&(6, 80)), Some(&20080));
    assert_eq!(state.ingress_logical_ifindex.get(&(6, 81)), Some(&20081));
    assert_eq!(state.ifindex_to_zone_id.get(&20080).copied(), Some(11));
    assert_eq!(state.ifindex_to_zone_id.get(&20081).copied(), Some(12));
    assert_eq!(
        state.egress.get(&20080).expect("wan egress").bind_ifindex,
        6
    );
    assert_eq!(
        state.egress.get(&20081).expect("dmz egress").bind_ifindex,
        6
    );
    assert!(state.cos.interfaces.contains_key(&20080));
    assert!(state.cos.interfaces.contains_key(&20081));
}

// #3070: host-inbound-traffic enforcement. A configured zone admits only its
// listed system-services / protocols for host-bound (local-delivery) traffic;
// an unconfigured zone admits everything (admit-all default). Reverting the
// enforcement (treating every zone as admit-all) turns the deny assertions RED.
#[test]
fn build_forwarding_state_enforces_host_inbound_traffic() {
    use crate::ZoneSnapshot;
    use crate::afxdp::forwarding::host_inbound_admits;

    let snapshot = ConfigSnapshot {
        zones: vec![
            // wan: ping + gre + router-discovery (mirrors the repo cluster cfg).
            ZoneSnapshot {
                name: "wan".into(),
                id: 11,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["ping".into(), "gre".into()],
                host_inbound_protocols: vec!["router-discovery".into()],
            },
            // lan: ssh + ping only.
            ZoneSnapshot {
                name: "lan".into(),
                id: 12,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["ssh".into(), "ping".into()],
                host_inbound_protocols: vec![],
            },
            // control: all — fully open (heartbeat zone).
            ZoneSnapshot {
                name: "control".into(),
                id: 13,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["all".into()],
                host_inbound_protocols: vec![],
            },
            // legacy: no host-inbound stanza → admit-all preserved.
            ZoneSnapshot {
                name: "legacy".into(),
                id: 14,
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);

    // Only the three configured zones populate the table; the unconfigured one
    // is absent (admit-all path).
    assert!(state.zone_host_inbound.contains_key(&11));
    assert!(state.zone_host_inbound.contains_key(&12));
    assert!(state.zone_host_inbound.contains_key(&13));
    assert!(!state.zone_host_inbound.contains_key(&14));

    // wan (id 11): ping (icmp) admitted, gre (proto 47) admitted, ssh (tcp/22)
    // DENIED, ospf (proto 89) DENIED.
    assert!(host_inbound_admits(&state, 11, 1, 0, false), "wan ping");
    assert!(host_inbound_admits(&state, 11, 47, 0, false), "wan gre");
    assert!(!host_inbound_admits(&state, 11, 6, 22, false), "wan ssh deny");
    assert!(!host_inbound_admits(&state, 11, 89, 0, false), "wan ospf deny");

    // lan (id 12): ssh (tcp/22) admitted, ping admitted, telnet (tcp/23)
    // DENIED, dhcp (udp/67) DENIED (not listed).
    assert!(host_inbound_admits(&state, 12, 6, 22, false), "lan ssh");
    assert!(host_inbound_admits(&state, 12, 1, 0, false), "lan ping");
    assert!(!host_inbound_admits(&state, 12, 6, 23, false), "lan telnet deny");
    assert!(!host_inbound_admits(&state, 12, 17, 67, false), "lan dhcp deny");

    // control (id 13): all → admit everything.
    assert!(
        host_inbound_admits(&state, 13, 6, 12345, false),
        "control all tcp"
    );
    assert!(
        host_inbound_admits(&state, 13, 89, 0, false),
        "control all ospf"
    );

    // legacy (id 14): unconfigured → admit everything (pre-#3070 behaviour).
    assert!(
        host_inbound_admits(&state, 14, 6, 22, false),
        "legacy admit-all"
    );
    assert!(
        host_inbound_admits(&state, 14, 89, 0, false),
        "legacy admit-all proto"
    );
    // A zone id that does not exist at all also admits (no entry).
    assert!(
        host_inbound_admits(&state, 99, 6, 22, false),
        "unknown zone admit"
    );
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
                ..Default::default()
            },
            ZoneSnapshot {
                name: "reserved-edge".into(),
                id: crate::policy::ZONE_ID_RESERVED_MIN,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "global-sentinel".into(),
                id: crate::policy::JUNOS_GLOBAL_ZONE_ID,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.zone_name_to_id.get("ok").copied(), Some(5));
    assert!(state.zone_name_to_id.get("reserved-edge").is_none());
    assert!(state.zone_name_to_id.get("global-sentinel").is_none());
    assert!(
        state
            .zone_id_to_name
            .get(&crate::policy::ZONE_ID_RESERVED_MIN)
            .is_none()
    );
    assert!(
        state
            .zone_id_to_name
            .get(&crate::policy::JUNOS_GLOBAL_ZONE_ID)
            .is_none()
    );
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
            ..Default::default()
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
            ..Default::default()
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

/// #2391: an interface whose zone snapshot field references a zone that was
/// DROPPED at config build time (reserved id, > u8 max) must FAIL CLOSED — the
/// forwarding build returns InterfaceUnknownZone instead of silently collapsing
/// the interface to zone_id == 0 (which would bypass every zone-pair policy).
/// fail-on-revert: restoring the `unwrap_or(0)` collapse makes this red.
#[test]
fn interface_pointing_at_skipped_zone_fails_closed() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "reserved".into(),
            id: crate::policy::ZONE_ID_RESERVED_MIN, // dropped at populate_zones
            ..Default::default()
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
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("interface referencing a dropped zone must fail closed");
    match err {
        crate::policy::SnapshotIntegrityError::InterfaceUnknownZone { interface, zone } => {
            assert_eq!(interface, "ge-0/0/2");
            assert_eq!(zone, "reserved");
        }
        other => panic!("expected InterfaceUnknownZone, got {other:?}"),
    }
}

/// #2391: an interface whose snapshot zone string isn't in the zones list at all
/// (a typo / version-drifted snapshot) fails CLOSED rather than collapsing the
/// EgressInterface to zone_id == 0.
#[test]
fn interface_with_unknown_zone_name_fails_closed() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "trust".into(),
            id: 3,
            ..Default::default()
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
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("interface referencing an unknown zone must fail closed");
    assert!(matches!(
        err,
        crate::policy::SnapshotIntegrityError::InterfaceUnknownZone { .. }
    ));
}

/// #2391 anti-over-reject: an interface with NO zone (empty string) is the
/// legitimate "unzoned" case and must still build, mapping to zone_id == 0.
#[test]
fn interface_with_empty_zone_builds_with_zone_zero() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/4".into(),
            zone: String::new(), // unzoned
            ifindex: 77,
            hardware_addr: "02:00:00:00:00:77".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let eg = state.egress.get(&77).expect("egress");
    assert_eq!(eg.zone_id, 0);
    // unzoned interfaces are not inserted into ifindex_to_zone_id
    assert!(state.ifindex_to_zone_id.get(&77).is_none());
}

// ---------------------------------------------------------------------
// #2410: validated narrowing newtypes — out-of-range VLAN / TTL / queue
// fail the snapshot CLOSED instead of wrapping (VLAN/TTL) or silently
// dropping (queue). #2409: malformed interface address fails closed.
// ---------------------------------------------------------------------

/// #2410: a VLAN id > 65535 fails the snapshot CLOSED via
/// `InterfaceVlanOutOfRange`. fail-on-revert: restoring
/// `iface.vlan_id.max(0) as u16` wraps 65537 → VLAN 1 and the build
/// succeeds, making this `expect_err` red.
#[test]
fn interface_vlan_id_out_of_range_fails_closed() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/2".into(),
            ifindex: 23,
            parent_ifindex: 22,
            vlan_id: 65_537, // wraps to VLAN 1 under the old `as u16` cast
            hardware_addr: "02:00:00:00:00:23".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("an out-of-range VLAN id must fail closed, not wrap to a different VLAN");
    match err {
        crate::policy::SnapshotIntegrityError::InterfaceVlanOutOfRange { interface, vlan_id } => {
            assert_eq!(interface, "ge-0/0/2");
            assert_eq!(vlan_id, 65_537);
        }
        other => panic!("expected InterfaceVlanOutOfRange, got {other:?}"),
    }
}

/// #2410 anti-over-reject: an in-range VLAN (and the negative "no VLAN"
/// sentinel) still build, byte-identical to the old `.max(0) as u16`.
#[test]
fn interface_vlan_id_in_range_builds_exactly() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/3".into(),
                ifindex: 30,
                parent_ifindex: 29,
                vlan_id: 4094, // top of the legal 802.1Q range
                hardware_addr: "02:00:00:00:00:30".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/4".into(),
                ifindex: 31,
                vlan_id: -1, // legitimate "no VLAN" sentinel → 0 (untagged)
                hardware_addr: "02:00:00:00:00:31".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.egress.get(&30).expect("egress 30").vlan_id, 4094);
    assert_eq!(state.egress.get(&31).expect("egress 31").vlan_id, 0);
}

/// #2706: a NEGATIVE interface MTU fails the snapshot CLOSED via
/// `InterfaceMtuInvalid`. fail-on-revert: restoring `iface.mtu.max(0) as
/// usize` silently collapses -1 → 0, the egress MTU guard then treats 0 as
/// "unknown; forward" (PTB/drop enforcement disabled), the build succeeds,
/// and this `expect_err` goes red.
#[test]
fn interface_negative_mtu_fails_closed() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/2".into(),
            ifindex: 40,
            mtu: -1, // collapses to 0 (enforcement off) under the old `.max(0)` cast
            hardware_addr: "02:00:00:00:00:40".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("a negative interface MTU must fail closed, not collapse to 0 (enforcement off)");
    match err {
        crate::policy::SnapshotIntegrityError::InterfaceMtuInvalid { interface, mtu } => {
            assert_eq!(interface, "ge-0/0/2");
            assert_eq!(mtu, -1);
        }
        other => panic!("expected InterfaceMtuInvalid, got {other:?}"),
    }
}

/// #2706 anti-over-reject: a positive MTU builds through unchanged, and the
/// legitimate 0 "unknown MTU" sentinel is preserved as 0 (the permissive
/// "forward; MTU unknown" case the egress guard relies on) — byte-identical
/// to the old `.max(0) as usize`. This guards against the #2696
/// over-rejection dual-risk (rejecting a legit 0 would break deploy-boot of
/// any interface whose link MTU could not be resolved).
#[test]
fn interface_mtu_positive_and_zero_build_exactly() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/3".into(),
                ifindex: 41,
                mtu: 9000, // jumbo — passes through unchanged
                hardware_addr: "02:00:00:00:00:41".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/4".into(),
                ifindex: 42,
                mtu: 0, // legitimate "unknown MTU" sentinel → stays 0 (permissive)
                hardware_addr: "02:00:00:00:00:42".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.egress.get(&41).expect("egress 41").mtu, 9000);
    assert_eq!(state.egress.get(&42).expect("egress 42").mtu, 0);
}

/// #2410: a tunnel TTL > 255 fails the snapshot CLOSED via
/// `TunnelTtlOutOfRange`. fail-on-revert: restoring
/// `endpoint.ttl.max(0) as u8` wraps 256 → 0 (a blackholed tunnel) and
/// the build succeeds, making this `expect_err` red.
#[test]
fn tunnel_ttl_out_of_range_fails_closed() {
    let snapshot = ConfigSnapshot {
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id: 9,
            interface: "gr-0/0/0".into(),
            ifindex: 50,
            mode: "gre".into(),
            source: "203.0.113.1".into(),
            destination: "198.51.100.1".into(),
            ttl: 256, // wraps to 0 under the old `as u8` cast
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("an out-of-range tunnel TTL must fail closed, not wrap to 0");
    match err {
        crate::policy::SnapshotIntegrityError::TunnelTtlOutOfRange { tunnel_id, ttl } => {
            assert_eq!(tunnel_id, 9);
            assert_eq!(ttl, 256);
        }
        other => panic!("expected TunnelTtlOutOfRange, got {other:?}"),
    }
}

/// #2410 anti-over-reject: an in-range TTL still builds exactly.
#[test]
fn tunnel_ttl_in_range_builds_exactly() {
    let snapshot = ConfigSnapshot {
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id: 10,
            interface: "gr-0/0/0".into(),
            ifindex: 51,
            mode: "gre".into(),
            source: "203.0.113.1".into(),
            destination: "198.51.100.1".into(),
            ttl: 255, // top of the legal range
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.tunnel_endpoints.get(&10).expect("endpoint").ttl, 255);
}

/// #2703: a NEGATIVE tunnel TTL (a corrupt / mixed-version snapshot
/// field) maps to the documented default 64, NOT 0. fail-on-revert:
/// restoring `TunnelTtl(0)` for negatives writes outer TTL 0 and
/// blackholes the tunnel — the exact failure the Go-side 0→64 default
/// guards against — making this assertion red.
#[test]
fn tunnel_ttl_negative_maps_to_default_not_zero() {
    let snapshot = ConfigSnapshot {
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id: 11,
            interface: "gr-0/0/0".into(),
            ifindex: 52,
            mode: "gre".into(),
            source: "203.0.113.1".into(),
            destination: "198.51.100.1".into(),
            ttl: -1, // corrupt / mixed-version: must NOT become 0
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(
        state.tunnel_endpoints.get(&11).expect("endpoint").ttl,
        64,
        "a negative snapshot TTL must map to the default 64, not 0 (blackhole)"
    );
}

/// #2410: a CoS forwarding-class queue id outside 0..=255 fails the
/// snapshot CLOSED via `CosQueueIdOutOfRange`. fail-on-revert: restoring
/// the `filter_map` range check silently DROPS the class, the build
/// succeeds, and this `expect_err` is red.
#[test]
fn cos_forwarding_class_queue_out_of_range_fails_closed() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 60,
            cos_shaping_rate_bytes_per_sec: 1,
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "voice".into(),
                queue: 256, // outside u8 range — pre-fix: silently dropped
            }],
            schedulers: vec![],
            scheduler_maps: vec![],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let err = super::cos::build_cos_state(&snapshot)
        .expect_err("an out-of-range CoS queue id must fail closed, not silently drop the class");
    match err {
        crate::policy::SnapshotIntegrityError::CosQueueIdOutOfRange {
            forwarding_class,
            queue,
        } => {
            assert_eq!(forwarding_class, "voice");
            assert_eq!(queue, 256);
        }
        other => panic!("expected CosQueueIdOutOfRange, got {other:?}"),
    }
}

/// #2410 anti-over-reject: an in-range queue id still maps, and an EMPTY
/// class name is still skipped (the legitimate placeholder case) without
/// erroring.
#[test]
fn cos_forwarding_class_in_range_queue_builds_and_empty_name_skipped() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 61,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_scheduler_map: "m".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "voice".into(),
                    queue: 5, // in-range
                },
                CoSForwardingClassSnapshot {
                    name: String::new(), // placeholder — skipped, not an error
                    queue: 999,
                },
            ],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "m".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "voice".into(),
                    scheduler: String::new(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let state = super::cos::build_cos_state(&snapshot).expect("in-range queue id must build");
    let cfg = state.interfaces.get(&61).expect("iface 61 cos");
    assert_eq!(cfg.queue_by_forwarding_class.get("voice").copied(), Some(5));
}

/// #2447: a DSCP classifier code-point outside the 6-bit DSCP domain
/// (0..=63) fails the snapshot CLOSED via `CosDscpCodePointOutOfRange`. The
/// pre-fix builder masked the index `dscp & 0x3f`, so 110 silently built the
/// classifier for DSCP 46 — a DIFFERENT traffic class. fail-on-revert:
/// restore `usize::from(dscp & 0x3f)` and `table[idx] = queue_id` and the
/// build succeeds (installing the aliased entry), making this `expect_err`
/// red.
#[test]
fn cos_dscp_classifier_out_of_range_code_point_fails_closed() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 80,
            cos_shaping_rate_bytes_per_sec: 1,
            cos_dscp_classifier: "wan".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                name: "wan".into(),
                entries: vec![CoSDSCPClassifierEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    loss_priority: "low".into(),
                    dscp_values: vec![110], // > 63 — pre-fix masked to 46
                }],
            }],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![],
            scheduler_maps: vec![],
        }),
        ..Default::default()
    };
    let err = super::cos::build_cos_state(&snapshot)
        .expect_err("an out-of-range DSCP code-point must fail closed, not alias into queue 46");
    match err {
        crate::policy::SnapshotIntegrityError::CosDscpCodePointOutOfRange { classifier, dscp } => {
            assert_eq!(classifier, "wan");
            assert_eq!(dscp, 110);
        }
        other => panic!("expected CosDscpCodePointOutOfRange, got {other:?}"),
    }
}

/// #2447: an 802.1p classifier code-point outside the 3-bit PCP domain
/// (0..=7) fails closed via `CosIeee8021CodePointOutOfRange` (pre-fix
/// `pcp.min(7)` clamped 9 into queue 7).
#[test]
fn cos_ieee8021_classifier_out_of_range_code_point_fails_closed() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 81,
            cos_shaping_rate_bytes_per_sec: 1,
            cos_ieee8021_classifier: "wan-pcp".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                name: "wan-pcp".into(),
                entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    loss_priority: "low".into(),
                    code_points: vec![9], // > 7 — pre-fix clamped to 7
                }],
            }],
            dscp_rewrite_rules: vec![],
            schedulers: vec![],
            scheduler_maps: vec![],
        }),
        ..Default::default()
    };
    let err = super::cos::build_cos_state(&snapshot)
        .expect_err("an out-of-range PCP code-point must fail closed, not clamp into queue 7");
    match err {
        crate::policy::SnapshotIntegrityError::CosIeee8021CodePointOutOfRange { classifier, pcp } => {
            assert_eq!(classifier, "wan-pcp");
            assert_eq!(pcp, 9);
        }
        other => panic!("expected CosIeee8021CodePointOutOfRange, got {other:?}"),
    }
}

/// #2447 anti-over-reject: in-range boundary code-points (DSCP 63, PCP 7)
/// still build the classifier table at the expected indices.
#[test]
fn cos_classifier_in_range_boundary_code_points_build() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 82,
            cos_shaping_rate_bytes_per_sec: 1,
            cos_dscp_classifier: "wan".into(),
            cos_ieee8021_classifier: "wan-pcp".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                name: "wan".into(),
                entries: vec![CoSDSCPClassifierEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    loss_priority: "low".into(),
                    dscp_values: vec![63], // max in-range
                }],
            }],
            ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                name: "wan-pcp".into(),
                entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    loss_priority: "low".into(),
                    code_points: vec![7], // max in-range
                }],
            }],
            dscp_rewrite_rules: vec![],
            schedulers: vec![],
            scheduler_maps: vec![],
        }),
        ..Default::default()
    };
    let state = super::cos::build_cos_state(&snapshot)
        .expect("in-range boundary code-points must build");
    let iface = state.interfaces.get(&82).expect("iface 82 cos");
    assert_eq!(iface.dscp_queue_by_dscp[63], 0, "DSCP 63 must map to queue 0");
    assert_eq!(iface.ieee8021_queue_by_pcp[7], 0, "PCP 7 must map to queue 0");
}

/// #2409: an interface address that does not parse as an `IpNet` fails the
/// snapshot CLOSED via `InterfaceAddressUnparseable`. fail-on-revert:
/// restoring the `else { continue; }` silently drops the address (losing
/// the connected route) and the build succeeds, making this red.
#[test]
fn interface_malformed_address_fails_closed() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/5".into(),
            ifindex: 70,
            hardware_addr: "02:00:00:00:00:70".into(),
            addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
                family: "inet".into(),
                address: "10.0.0.0/33".into(), // not a parseable CIDR
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("a malformed interface address must fail closed, not silently drop the route");
    match err {
        crate::policy::SnapshotIntegrityError::InterfaceAddressUnparseable { interface, address } => {
            assert_eq!(interface, "ge-0/0/5");
            assert_eq!(address, "10.0.0.0/33");
        }
        other => panic!("expected InterfaceAddressUnparseable, got {other:?}"),
    }
}

/// #2409 anti-over-reject: a valid interface address still installs its
/// connected route.
#[test]
fn interface_valid_address_builds_connected_route() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/6".into(),
            ifindex: 71,
            hardware_addr: "02:00:00:00:00:71".into(),
            addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
                family: "inet".into(),
                address: "10.0.61.1/24".into(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.connected_v4.iter().any(|r| r.ifindex == 71),
        "valid address must produce a connected route"
    );
    assert!(state.local_v4.contains(&"10.0.61.1".parse().unwrap()));
}

// ---------------------------------------------------------------------
// #916: zero-shaping-rate (transparent root) tests.
// ---------------------------------------------------------------------

#[test]
fn build_cos_state_includes_zero_shaping_rate_interface() {
    // Pre-#916, an interface with `cos_shaping_rate_bytes_per_sec == 0`
    // was silently dropped by `build_cos_state`'s upstream skip,
    // which masked the runtime deadlock by suppressing the entire
    // CoS runtime. The bug surface for the operator was "CoS
    // classifier doesn't apply on this interface". The fix permits
    // the interface through; the runtime handles transparent-root
    // semantics.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 0, // <- the case under test
            cos_shaping_burst_bytes: 0,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: String::new(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        state.interfaces.contains_key(&42),
        "zero-shaping-rate interface must be included in CoSState (transparent root)"
    );
    let iface = &state.interfaces[&42];
    assert_eq!(iface.shaping_rate_bytes, 0);
    // burst_bytes falls back to default_cos_burst_bytes(0) which floors
    // at COS_MIN_BURST_BYTES (96 KB).
    assert!(iface.burst_bytes >= 64 * 1500);
}

#[test]
fn build_cos_state_zero_shaping_rate_queue_inherits_transparent() {
    // When the scheduler has no transmit-rate AND the interface has
    // no shaping-rate, the queue's effective rate falls through to
    // 0. Verify the queue config carries `transmit_rate_bytes == 0`
    // (the runtime build path will pre-fill tokens to the buffer cap
    // and the queue-service will bypass the cos_refill_ns_until check).
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "iperf-a".into(),
                queue: 4,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "no-rate".into(),
                transmit_rate_bytes: 0, // <- fallback chains to 0
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 0,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "iperf-a".into(),
                    scheduler: "no-rate".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    let iface = state
        .interfaces
        .get(&42)
        .expect("transparent iface present");
    let queue = iface
        .queues
        .iter()
        .find(|q| q.queue_id == 4)
        .expect("iperf-a queue present");
    assert_eq!(
        queue.transmit_rate_bytes, 0,
        "transparent root + no scheduler rate → transparent queue (rate 0)"
    );
    assert!(
        !queue.guarantee_enabled,
        "no scheduler rate means surplus-only even when the effective rate is transparent"
    );
}

#[test]
fn build_cos_state_no_rate_exact_surplus_equal_flow_is_residual_only() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 25_000_000_000 / 8,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "iperf-a".into(),
                queue: 4,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "no-rate-exact".into(),
                transmit_rate_bytes: 0,
                transmit_rate_exact: true,
                priority: "high".into(),
                buffer_size_bytes: 0,
                buffer_size_percent: 0.0,
                surplus_sharing: true,
                equal_flow_enforcement: true,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "iperf-a".into(),
                    scheduler: "no-rate-exact".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let queue = state
        .interfaces
        .get(&42)
        .expect("shaped iface present")
        .queues
        .iter()
        .find(|q| q.queue_id == 4)
        .expect("iperf-a queue present");

    assert_eq!(queue.transmit_rate_bytes, 25_000_000_000 / 8);
    assert!(!queue.guarantee_enabled);
    assert!(!queue.exact);
    assert!(!queue.surplus_sharing);
    assert!(!queue.equal_flow_enforcement);
}

#[test]
fn build_cos_state_mixed_zero_and_nonzero_shaping_rate() {
    // Two interfaces in the same snapshot — one with shaping-rate
    // configured, one without. Both must produce CoSState entries
    // with the correct semantics.
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                ifindex: 42,
                cos_shaping_rate_bytes_per_sec: 25_000_000_000 / 8,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                ifindex: 43,
                cos_shaping_rate_bytes_per_sec: 0,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: String::new(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    let shaped = state.interfaces.get(&42).expect("shaped iface in CoSState");
    let transparent = state
        .interfaces
        .get(&43)
        .expect("transparent iface in CoSState");
    assert_eq!(shaped.shaping_rate_bytes, 25_000_000_000 / 8);
    assert_eq!(transparent.shaping_rate_bytes, 0);
    // Both must have at least one queue.
    assert!(!shaped.queues.is_empty());
    assert!(!transparent.queues.is_empty());
}

#[test]
fn build_cos_state_skips_interface_with_no_cos_config() {
    // An interface that is NOT participating in CoS (no scheduler-map,
    // no classifier, no rewrite-rule, no shaping-rate) must NOT receive
    // a CoSState entry — otherwise the per-interface owner-worker
    // dispatch funnels every TX into one worker, collapsing throughput
    // (regression hunted in iperf3 -P 12 -R: 22 Gbps → 2 Gbps until
    // this gate was reinstated).
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            // Forwarding-only LAN egress with no CoS at all.
            InterfaceSnapshot {
                ifindex: 100,
                cos_shaping_rate_bytes_per_sec: 0,
                cos_shaping_burst_bytes: 0,
                cos_scheduler_map: String::new(),
                cos_dscp_classifier: String::new(),
                cos_ieee8021_classifier: String::new(),
                cos_dscp_rewrite_rule: String::new(),
                ..Default::default()
            },
            // Sibling that DOES participate in CoS — must still appear.
            InterfaceSnapshot {
                ifindex: 101,
                cos_shaping_rate_bytes_per_sec: 0,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: String::new(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&100),
        "interface with no CoS config must NOT be added to CoSState"
    );
    assert!(
        state.interfaces.contains_key(&101),
        "interface with scheduler-map but no shaping-rate must still appear (transparent root)"
    );
}

#[test]
fn build_cos_state_admits_each_cos_field_in_isolation() {
    // The skip predicate is an OR over five arms (rate, scheduler-map,
    // DSCP classifier, 802.1p classifier, DSCP rewrite). Pin every arm so
    // a future refactor can't silently drop one — Codex review on
    // PR #1183 flagged this as coverage debt (Q5). The sixth `InterfaceSnapshot`
    // CoS field, `cos_shaping_burst_bytes`, is intentionally NOT a
    // standalone arm; see the dedicated burst-only-skip test below and
    // the gate comment in `forwarding_build/cos.rs::build_cos_iface_config`
    // for rationale.
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".into(),
            queue: 0,
        }],
        schedulers: vec![],
        scheduler_maps: vec![CoSSchedulerMapSnapshot {
            name: "wan-map".into(),
            entries: vec![CoSSchedulerMapEntrySnapshot {
                forwarding_class: "best-effort".into(),
                scheduler: String::new(),
            }],
        }],
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "dscp-cls".into(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_values: vec![0],
            }],
        }],
        ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
            name: "p8021-cls".into(),
            entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                code_points: vec![0],
            }],
        }],
        dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
            name: "dscp-rw".into(),
            entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_value: 0,
            }],
        }],
    };
    let cases: &[(i32, &str, InterfaceSnapshot)] = &[
        (
            201,
            "shaping-rate only",
            InterfaceSnapshot {
                ifindex: 201,
                cos_shaping_rate_bytes_per_sec: 1_000_000,
                ..Default::default()
            },
        ),
        (
            203,
            "scheduler-map only",
            InterfaceSnapshot {
                ifindex: 203,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ),
        (
            204,
            "DSCP classifier only",
            InterfaceSnapshot {
                ifindex: 204,
                cos_dscp_classifier: "dscp-cls".into(),
                ..Default::default()
            },
        ),
        (
            205,
            "802.1p classifier only",
            InterfaceSnapshot {
                ifindex: 205,
                cos_ieee8021_classifier: "p8021-cls".into(),
                ..Default::default()
            },
        ),
        (
            206,
            "DSCP rewrite-rule only",
            InterfaceSnapshot {
                ifindex: 206,
                cos_dscp_rewrite_rule: "dscp-rw".into(),
                ..Default::default()
            },
        ),
    ];
    for (ifindex, label, iface) in cases {
        let snapshot = ConfigSnapshot {
            interfaces: vec![iface.clone()],
            class_of_service: Some(cos.clone()),
            ..Default::default()
        };
        let state = build_cos_state(&snapshot);
        assert!(
            state.interfaces.contains_key(ifindex),
            "{label}: interface must be admitted to CoSState (ifindex {ifindex})"
        );
    }
}

#[test]
fn build_cos_state_skips_interface_with_burst_only_no_other_cos_knobs() {
    // The Go compiler permits a committed config to carry
    // `BurstSizeBytes > 0` independently of `ShapingRateBytes`
    // (`pkg/config/compiler_class_of_service.go:285-312`), so this
    // snapshot shape IS reachable from real config. We deliberately
    // skip it anyway: pre-f0e364d7 also skipped burst-only (the old
    // `shaping_rate == 0` skip caught it), and admitting it would
    // install the cross-binding owner-worker redirect that PR #1183
    // exists to remove. The buffer-cap admission effect that admission
    // would unlock has never been observable in production.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 250,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: String::new(),
            cos_dscp_classifier: String::new(),
            cos_ieee8021_classifier: String::new(),
            cos_dscp_rewrite_rule: String::new(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot::default()),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&250),
        "interface with burst-only (no rate, no classes, no rewrite) must NOT be in CoSState"
    );
}

#[test]
fn build_cos_state_skips_interface_with_unresolvable_named_references() {
    // A typo'd scheduler-map / classifier / rewrite-rule name is
    // non-empty but does not resolve to any entry in the CoS config.
    // Pre-fix, an is-non-empty gate would admit such an interface and
    // build only a default best-effort queue with rate=0, re-triggering
    // the owner-worker redirect collapse for an interface with no
    // effective CoS policy. The predicate must require named references
    // to actually resolve.
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".into(),
            queue: 0,
        }],
        schedulers: vec![],
        scheduler_maps: vec![CoSSchedulerMapSnapshot {
            name: "wan-map".into(),
            entries: vec![CoSSchedulerMapEntrySnapshot {
                forwarding_class: "best-effort".into(),
                scheduler: String::new(),
            }],
        }],
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "dscp-cls".into(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_values: vec![0],
            }],
        }],
        ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
            name: "p8021-cls".into(),
            entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                code_points: vec![0],
            }],
        }],
        dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
            name: "dscp-rw".into(),
            entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_value: 0,
            }],
        }],
    };
    // Each typo'd reference (one CoS field non-empty but unresolvable)
    // must NOT admit the interface to CoSState.
    let cases: &[(i32, &str, InterfaceSnapshot)] = &[
        (
            301,
            "typo'd scheduler-map",
            InterfaceSnapshot {
                ifindex: 301,
                cos_scheduler_map: "wan-mapp".into(),
                ..Default::default()
            },
        ),
        (
            302,
            "typo'd DSCP classifier",
            InterfaceSnapshot {
                ifindex: 302,
                cos_dscp_classifier: "dscp-cls-typo".into(),
                ..Default::default()
            },
        ),
        (
            303,
            "typo'd 802.1p classifier",
            InterfaceSnapshot {
                ifindex: 303,
                cos_ieee8021_classifier: "p8021-cls-typo".into(),
                ..Default::default()
            },
        ),
        (
            304,
            "typo'd DSCP rewrite-rule",
            InterfaceSnapshot {
                ifindex: 304,
                cos_dscp_rewrite_rule: "dscp-rw-typo".into(),
                ..Default::default()
            },
        ),
    ];
    for (ifindex, label, iface) in cases {
        let snapshot = ConfigSnapshot {
            interfaces: vec![iface.clone()],
            class_of_service: Some(cos.clone()),
            ..Default::default()
        };
        let state = build_cos_state(&snapshot);
        assert!(
            !state.interfaces.contains_key(ifindex),
            "{label}: unresolvable name must NOT admit interface to CoSState (ifindex {ifindex})"
        );
    }
}

#[test]
fn build_cos_state_skips_interface_with_resolvable_but_empty_scheduler_map() {
    // Copilot review on PR #1183 caught this: `compileClassOfService`
    // keeps a named scheduler-map even when it has zero entries, so
    // a `contains_key` admission check would let a config like
    // `set class-of-service interfaces ifd unit X scheduler-map empty-map`
    // (with `empty-map` declared but no entries) pass the gate, then
    // collapse downstream to a synthetic best-effort default queue —
    // re-triggering the owner-worker redirect collapse for an interface
    // with no effective CoS policy.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 401,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_scheduler_map: "empty-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "empty-map".into(),
                entries: vec![], // <- the critical case: declared but empty
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&401),
        "interface attached to a resolvable but empty scheduler-map must NOT enter CoSState"
    );
}

/// #2409: at the RUST helper boundary, a scheduler-map entry referencing a
/// forwarding-class absent from the class-to-queue table fails the snapshot
/// CLOSED. This is a true NEVER-FIRES DRIFT BACKSTOP: an undefined-class
/// scheduler-map entry is a SUPPORTED, committable config shape on the Go
/// side (warning-only at commit, `compiler_validate_warn.go`), so the Go
/// snapshot emitter (`pkg/dataplane/userspace/cos.go`,
/// `buildClassOfServiceSnapshot`) now DEGRADES VISIBLY — it filters the
/// undefined entry with a `slog.Warn` and never puts it on the wire (see
/// `TestBuildClassOfServiceSnapshotSkipsUndefinedSchedulerMapClass`). This
/// hard-error therefore only fires on a version/snapshot-drifted helper that
/// receives an entry the emitter would have filtered — making it consistent
/// with the VLAN/TTL/queue/address sites (corruption a valid config never
/// produces) and with the #2391/#2212/#2240 precedents (all have a Go gate
/// upstream so their Rust backstop never fires on a fresh operator config).
///
/// fail-on-revert: restoring the `continue` at the `class_to_queue.get`
/// lookup makes the build succeed (silently dropping the entry) and this
/// `expect_err` red.
#[test]
fn build_cos_state_fails_closed_on_scheduler_map_undefined_forwarding_class() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 402,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_scheduler_map: "broken-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            // forwarding_classes intentionally does NOT include the
            // class names referenced by `broken-map` below, so the first
            // entry's `class_to_queue.get(&entry.forwarding_class)` misses.
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "broken-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "missing-class-a".into(),
                        scheduler: String::new(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "missing-class-b".into(),
                        scheduler: String::new(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
        }),
        ..Default::default()
    };
    let err = super::cos::build_cos_state(&snapshot)
        .expect_err("scheduler-map referencing an undefined class must fail closed");
    match err {
        crate::policy::SnapshotIntegrityError::SchedulerMapUnknownClass {
            scheduler_map,
            forwarding_class,
        } => {
            assert_eq!(scheduler_map, "broken-map");
            assert_eq!(forwarding_class, "missing-class-a");
        }
        other => panic!("expected SchedulerMapUnknownClass, got {other:?}"),
    }
}

#[test]
fn build_cos_state_skips_classifier_only_mapping_to_unmaterialized_queue() {
    // An interface attaches a DSCP classifier whose entries map to
    // forwarding-class `voice` (queue 5). The interface has NO
    // scheduler-map, so the only queue it would materialize is the
    // synthetic default best-effort (queue 0). The classifier maps to
    // queue 5, which the interface won't have at runtime — packets
    // matching the classifier would land in `resolve_cos_queue_idx`
    // and get dropped, while the interface still installs the
    // owner-worker redirect. Gate must skip such interfaces.
    // (Copilot review on PR #1183 caught this.)
    let cos = ClassOfServiceSnapshot {
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
        schedulers: vec![],
        scheduler_maps: vec![],
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "voice-cls".into(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "voice".into(), // queue 5
                loss_priority: String::new(),
                dscp_values: vec![0x2e],
            }],
        }],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![],
    };
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 501,
            cos_dscp_classifier: "voice-cls".into(),
            ..Default::default()
        }],
        class_of_service: Some(cos),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&501),
        "DSCP classifier mapping to queue the interface won't materialize (no scheduler-map) must NOT admit"
    );
}

#[test]
fn build_cos_state_admits_classifier_mapping_to_materialized_queue() {
    // The opposite of the previous test: a DSCP classifier mapping to
    // queue 0 is OK on an interface with no scheduler-map, because the
    // synthetic default best-effort queue IS queue 0. Packets land
    // there and the classifier IS observable, so the interface
    // legitimately needs to be in CoSState.
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".into(),
            queue: 0,
        }],
        schedulers: vec![],
        scheduler_maps: vec![],
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "be-cls".into(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(), // queue 0
                loss_priority: String::new(),
                dscp_values: vec![0x10],
            }],
        }],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![],
    };
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 502,
            cos_dscp_classifier: "be-cls".into(),
            ..Default::default()
        }],
        class_of_service: Some(cos),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        state.interfaces.contains_key(&502),
        "DSCP classifier mapping to materialized queue must admit interface"
    );
}

#[test]
fn build_cos_state_skips_rewrite_only_mapping_to_unmaterialized_class() {
    // A DSCP rewrite-rule whose ONLY entry is for forwarding-class
    // `voice` is attached to an interface with no scheduler-map. The
    // interface only has the synthetic default best-effort class —
    // the `voice` rewrite has no queue to attach to, so no packet can
    // ever observe it. Gate must skip.
    let cos = ClassOfServiceSnapshot {
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
        schedulers: vec![],
        scheduler_maps: vec![],
        dscp_classifiers: vec![],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
            name: "voice-rw".into(),
            entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "voice".into(),
                loss_priority: String::new(),
                dscp_value: 0x2e,
            }],
        }],
    };
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 503,
            cos_dscp_rewrite_rule: "voice-rw".into(),
            ..Default::default()
        }],
        class_of_service: Some(cos),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&503),
        "DSCP rewrite-rule for class the interface won't materialize must NOT admit"
    );
}

#[test]
fn build_cos_state_admits_rewrite_only_mapping_to_materialized_class() {
    // A DSCP rewrite-rule with a `best-effort` entry is observable on
    // an interface with no scheduler-map, because the synthetic default
    // best-effort queue IS the materialized class. Packets in that
    // queue can carry the rewrite — interface should be admitted.
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".into(),
            queue: 0,
        }],
        schedulers: vec![],
        scheduler_maps: vec![],
        dscp_classifiers: vec![],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
            name: "be-rw".into(),
            entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_value: 0,
            }],
        }],
    };
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 504,
            cos_dscp_rewrite_rule: "be-rw".into(),
            ..Default::default()
        }],
        class_of_service: Some(cos),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        state.interfaces.contains_key(&504),
        "DSCP rewrite-rule for the materialized best-effort class must admit"
    );
}

// ---------------------------------------------------------------------------
// #1636 option D: compute_pending_neigh_timeout_ns tests.
// ---------------------------------------------------------------------------

/// Fake sysctl reader: maps a path to a u32, or None to simulate a read
/// failure (missing file / permission / parse error).
struct FakeSysctl {
    values: std::collections::HashMap<String, Option<u32>>,
    default_value: Option<u32>,
}

impl FakeSysctl {
    fn all(v: u32) -> Self {
        Self {
            values: std::collections::HashMap::new(),
            default_value: Some(v),
        }
    }
    fn set(mut self, path: &str, v: Option<u32>) -> Self {
        self.values.insert(path.to_string(), v);
        self
    }
}

impl SysctlReader for FakeSysctl {
    fn read_u32(&self, path: &str) -> Option<u32> {
        if let Some(v) = self.values.get(path) {
            return *v;
        }
        self.default_value
    }
}

fn one_iface_map() -> FastMap<i32, String> {
    let mut m = FastMap::default();
    m.insert(80, "ge-0-0-2".to_string());
    m
}

#[test]
fn pending_neigh_timeout_fast_when_all_retrans_le_250() {
    let reader = FakeSysctl::all(250);
    let got = compute_pending_neigh_timeout_ns(&one_iface_map(), &reader);
    assert_eq!(got, PENDING_NEIGH_TIMEOUT_FAST_NS);
}

#[test]
fn pending_neigh_timeout_fallback_when_iface_retrans_too_high() {
    // Default is 250 (fast) but the v4 per-iface table is 1000ms.
    let reader = FakeSysctl::all(250).set(
        "/proc/sys/net/ipv4/neigh/ge-0-0-2/retrans_time_ms",
        Some(1000),
    );
    let got = compute_pending_neigh_timeout_ns(&one_iface_map(), &reader);
    assert_eq!(got, super::super::PENDING_NEIGH_TIMEOUT_NS);
}

#[test]
fn pending_neigh_timeout_fallback_when_v6_too_high() {
    let reader = FakeSysctl::all(250).set(
        "/proc/sys/net/ipv6/neigh/ge-0-0-2/retrans_time_ms",
        Some(900),
    );
    let got = compute_pending_neigh_timeout_ns(&one_iface_map(), &reader);
    assert_eq!(got, super::super::PENDING_NEIGH_TIMEOUT_NS);
}

#[test]
fn pending_neigh_timeout_fallback_when_default_template_too_high() {
    // Per-iface tables fast, but the `default` template is still 1000ms
    // (an interface created after the snapshot would inherit it).
    let reader = FakeSysctl::all(250).set(
        "/proc/sys/net/ipv4/neigh/default/retrans_time_ms",
        Some(1000),
    );
    let got = compute_pending_neigh_timeout_ns(&one_iface_map(), &reader);
    assert_eq!(got, super::super::PENDING_NEIGH_TIMEOUT_NS);
}

#[test]
fn pending_neigh_timeout_fails_closed_on_read_error() {
    // A read failure (None) on any checked path must fail closed to the
    // 2000ms default rather than optimistically assuming fast.
    let reader =
        FakeSysctl::all(250).set("/proc/sys/net/ipv4/neigh/ge-0-0-2/retrans_time_ms", None);
    let got = compute_pending_neigh_timeout_ns(&one_iface_map(), &reader);
    assert_eq!(got, super::super::PENDING_NEIGH_TIMEOUT_NS);
}

#[test]
fn pending_neigh_timeout_fast_with_no_dataplane_interfaces() {
    // Empty iface map: only the `default` template is checked. If it is
    // fast, the timeout is fast.
    let reader = FakeSysctl::all(250);
    let got = compute_pending_neigh_timeout_ns(&FastMap::default(), &reader);
    assert_eq!(got, PENDING_NEIGH_TIMEOUT_FAST_NS);
}

#[test]
fn pending_neigh_timeout_fast_with_jiffy_rounded_252() {
    // The daemon writes 250 but the kernel rounds retrans_time_ms to its
    // internal jiffy resolution and reads back 252 on HZ=100 hosts. The
    // 300ms threshold must still admit the fast 800ms timeout.
    let reader = FakeSysctl::all(252);
    let got = compute_pending_neigh_timeout_ns(&one_iface_map(), &reader);
    assert_eq!(got, PENDING_NEIGH_TIMEOUT_FAST_NS);
}

// ---------------------------------------------------------------------
// #1432 S2a — WireGuard endpoint hydration + engine reload stability.
// ---------------------------------------------------------------------

const WG_TEST_PRIVKEY_HEX: &str =
    "a01010101010101010101010101010101010101010101010101010101010101a";
const WG_TEST_PEERKEY_HEX: &str =
    "b02020202020202020202020202020202020202020202020202020202020202b";

fn wg_snapshot(listen_port: u16, allowed: &[&str], endpoint: &str) -> ConfigSnapshot {
    ConfigSnapshot {
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id: 7,
            interface: "wg0".into(),
            linux_name: "wg0".into(),
            ifindex: 42,
            mode: "wireguard".into(),
            wg_listen_port: listen_port,
            wg_local_privkey_hex: WG_TEST_PRIVKEY_HEX.into(),
            wg_peers: vec![crate::protocol::snapshot::TunnelWgPeerSnapshot {
                wg_peer_pubkey_hex: WG_TEST_PEERKEY_HEX.into(),
                wg_allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
                wg_endpoint: endpoint.into(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[test]
fn wg_endpoint_hydrates_runtime_tunnel_endpoint() {
    let snap = wg_snapshot(51820, &["10.0.0.0/24"], "203.0.113.1:51820");
    let state = build_forwarding_state(&snap);
    assert!(state.has_wg_tunnels, "WG endpoint sets has_wg_tunnels");
    let ep = state.tunnel_endpoints.get(&7).expect("WG endpoint present");
    assert_eq!(ep.mode, "wireguard");
    assert_eq!(ep.wg_listen_port, 51820);
    assert_eq!(ep.wg_peers.len(), 1);
    assert_eq!(ep.wg_peers[0].allowed_ips.len(), 1);
    assert_eq!(
        ep.wg_peers[0].endpoint,
        Some("203.0.113.1:51820".parse().unwrap())
    );
    // Engine instantiated and keyed by endpoint id.
    assert!(state.wg_engines.contains_key(&7), "engine instantiated");
    assert_eq!(state.wg_engines.get(&7).unwrap().listen_port(), 51820);
}

#[test]
fn wg_endpoint_with_malformed_key_is_dropped() {
    let mut snap = wg_snapshot(51820, &[], "");
    snap.tunnel_endpoints[0].wg_local_privkey_hex = "deadbeef".into(); // wrong length
    let state = build_forwarding_state(&snap);
    assert!(
        !state.tunnel_endpoints.contains_key(&7),
        "endpoint with malformed key must be dropped, not half-installed"
    );
    assert!(!state.has_wg_tunnels);
}

#[test]
fn wg_reload_reuses_engine_when_identity_unchanged() {
    let snap = wg_snapshot(51820, &["10.0.0.0/24"], "203.0.113.1:51820");
    let prev = build_forwarding_state(&snap);
    let prev_engine = prev.wg_engines.get(&7).unwrap().clone();
    // Rebuild with the SAME config, threading `previous`.
    let next = build_forwarding_state_with_policy_counters_and_previous(
        &snap,
        &PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        Some(&prev),
    )
    .unwrap();
    let next_engine = next.wg_engines.get(&7).unwrap();
    assert!(
        std::sync::Arc::ptr_eq(&prev_engine, next_engine),
        "unchanged WG identity must reuse the same engine Arc (no reconcile)"
    );
}

#[test]
fn wg_reload_seeds_high_water_on_identity_change() {
    let snap = wg_snapshot(51820, &["10.0.0.0/24"], "203.0.113.1:51820");
    let prev = build_forwarding_state(&snap);
    // Advance the prior engine's TAI64N clock via an initiation.
    let prev_engine = prev.wg_engines.get(&7).unwrap();
    let peer_pub = prev_engine.first_peer_pubkey().unwrap();
    let mut out = [0u8; crate::afxdp::wg::WG_MSG_INIT_LEN];
    prev_engine.create_initiation(&peer_pub, &mut out).unwrap();
    let prev_hw = prev_engine.tai64n_high_water().expect("clock advanced");

    // Change the identity (different listen port) so a fresh engine is built.
    let snap2 = wg_snapshot(51821, &["10.0.0.0/24"], "203.0.113.1:51820");
    let next = build_forwarding_state_with_policy_counters_and_previous(
        &snap2,
        &PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        Some(&prev),
    )
    .unwrap();
    let next_engine = next.wg_engines.get(&7).unwrap();
    assert!(
        !std::sync::Arc::ptr_eq(prev_engine, next_engine),
        "changed identity must build a fresh engine"
    );
    assert_eq!(next_engine.listen_port(), 51821);
    let next_hw = next_engine.tai64n_high_water().expect("seeded from prior");
    assert!(
        next_hw >= prev_hw,
        "fresh engine TAI64N high-water must be seeded >= the prior engine's"
    );
}

#[test]
fn wg_endpoint_with_zero_listen_port_is_dropped() {
    // A WG tunnel with no listen port cannot bind a socket and is
    // invisible to the shim gate; it must be dropped, not installed as a
    // half-dead tunnel binding port 0 (Codex MAJOR).
    let snap = wg_snapshot(0, &["10.0.0.0/24"], "203.0.113.1:51820");
    let state = build_forwarding_state(&snap);
    assert!(
        !state.tunnel_endpoints.contains_key(&7),
        "WG endpoint with listen_port 0 must be dropped"
    );
    assert!(!state.has_wg_tunnels);
    assert!(!state.wg_engines.contains_key(&7));
}

// ---------------------------------------------------------------------
// #1873 — stable-id contract: removing one tunnel preserves the OTHER
// tunnels' engines + remap purge-set computation.
// ---------------------------------------------------------------------

fn two_tunnel_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        tunnel_endpoints: vec![
            crate::protocol::snapshot::TunnelEndpointSnapshot {
                id: 824,
                interface: "gr-0/0/0.0".into(),
                linux_name: "gr-0-0-0".into(),
                ifindex: 41,
                mode: "gre".into(),
                source: "172.16.80.8".into(),
                destination: "203.0.113.9".into(),
                transport_table: "inet.0".into(),
                ttl: 64,
                ..Default::default()
            },
            crate::protocol::snapshot::TunnelEndpointSnapshot {
                id: 7,
                interface: "wg0".into(),
                linux_name: "wg0".into(),
                ifindex: 42,
                mode: "wireguard".into(),
                wg_listen_port: 51820,
                wg_local_privkey_hex: WG_TEST_PRIVKEY_HEX.into(),
                wg_peers: vec![crate::protocol::snapshot::TunnelWgPeerSnapshot {
                    wg_peer_pubkey_hex: WG_TEST_PEERKEY_HEX.into(),
                    wg_allowed_ips: vec!["10.0.0.0/24".into()],
                    wg_endpoint: "203.0.113.1:51820".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

/// #1873 contract pin: with stable (Go-side content-derived) ids, a
/// snapshot that removes one tunnel keeps the OTHER tunnel's id, so
/// `populate_wg_engines` reuses the survivor's engine Arc verbatim —
/// no rebuild, no session reset, no TAI64N reseed. Under the retired
/// positional allocator the survivor's id shifted and this test's
/// Arc::ptr_eq assertion is exactly what broke.
#[test]
fn wg_engine_survives_unrelated_tunnel_removal() {
    let snap = two_tunnel_snapshot();
    let prev = build_forwarding_state(&snap);
    let prev_engine = prev.wg_engines.get(&7).unwrap().clone();

    // Remove the GRE tunnel; the WG row is byte-identical (same id —
    // the Go allocator guarantees this since #1873).
    let mut snap2 = two_tunnel_snapshot();
    snap2.tunnel_endpoints.retain(|ep| ep.id == 7);
    let next = build_forwarding_state_with_policy_counters_and_previous(
        &snap2,
        &PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        Some(&prev),
    )
    .unwrap();
    let next_engine = next.wg_engines.get(&7).unwrap();
    assert!(
        std::sync::Arc::ptr_eq(&prev_engine, next_engine),
        "removing an unrelated tunnel must not rebuild the WG engine (#1873)"
    );
}

/// #1873 R-D purge-set pins: (a) vanished id purged, (b) owner-name
/// change purged, (c) cosmetic linux_name change NOT purged,
/// (d) untouched ids NOT purged.
#[test]
fn tunnel_remap_purge_ids_owner_change_semantics() {
    use crate::afxdp::coordinator::tunnel_remap_purge_ids;
    let prev = build_forwarding_state(&two_tunnel_snapshot());

    // (a) vanished: remove the GRE row.
    let mut snap_removed = two_tunnel_snapshot();
    snap_removed.tunnel_endpoints.retain(|ep| ep.id == 7);
    let next = build_forwarding_state(&snap_removed);
    assert_eq!(tunnel_remap_purge_ids(&prev, &next, true), vec![824]);

    // (b) owner change: id 824 now belongs to a DIFFERENT logical name
    // (temporal hash reuse).
    let mut snap_reused = two_tunnel_snapshot();
    snap_reused.tunnel_endpoints[0].interface = "gr-9/9/9.0".into();
    let next = build_forwarding_state(&snap_reused);
    assert_eq!(tunnel_remap_purge_ids(&prev, &next, true), vec![824]);

    // (c) cosmetic linux_name rename, logical name unchanged: NO purge.
    let mut snap_renamed = two_tunnel_snapshot();
    snap_renamed.tunnel_endpoints[0].linux_name = "gre-renamed".into();
    let next = build_forwarding_state(&snap_renamed);
    assert!(tunnel_remap_purge_ids(&prev, &next, true).is_empty());

    // (d) identical set: NO purge.
    let next = build_forwarding_state(&two_tunnel_snapshot());
    assert!(tunnel_remap_purge_ids(&prev, &next, true).is_empty());
}

/// #1873 owner-check pins (Codex code r2 — replaces the unsound r1
/// defer + rotation-barrier design): a re-owned id installs
/// IMMEDIATELY (no defer), the unrelated WG endpoint's engine Arc is
/// reused verbatim, and the purge set plus the per-packet owner check
/// (not apply-time timing) carry the correctness burden.
#[test]
fn reowned_tunnel_id_installs_immediately_with_engine_reuse() {
    let prev = build_forwarding_state(&two_tunnel_snapshot());

    // Same snapshot, id 824 re-owned by a different logical name.
    let mut snap_reused = two_tunnel_snapshot();
    snap_reused.tunnel_endpoints[0].interface = "gr-9/9/9.0".into();
    let next = build_forwarding_state_with_policy_counters_and_previous(
        &snap_reused,
        &PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        Some(&prev),
    )
    .unwrap();
    let ep = next
        .tunnel_endpoints
        .get(&824)
        .expect("new owner installed");
    assert_eq!(ep.interface, "gr-9/9/9.0");
    // The unrelated WG endpoint keeps its engine Arc across the apply.
    assert!(next.tunnel_endpoints.contains_key(&7));
    assert!(std::sync::Arc::ptr_eq(
        prev.wg_engines.get(&7).expect("prev engine"),
        next.wg_engines.get(&7).expect("next engine"),
    ));
}

/// #1873 purge-set pin (Codex code r2): an id NEWLY APPEARING in
/// `next` (absent in `previous`) is purged when
/// `include_new_appearances` is set — any entry still storing it
/// (e.g. a synced copy installed with an unresolvable id during HA
/// config skew) predates `previous` and must die before the new
/// owner's row is reachable. The first-apply arm (flag false) skips
/// it so boot-time synced sessions survive.
#[test]
fn newly_appearing_tunnel_id_is_purged_after_first_apply() {
    use crate::afxdp::coordinator::tunnel_remap_purge_ids;
    // previous has only the WG endpoint; next adds the GRE row (824).
    let mut snap_wg_only = two_tunnel_snapshot();
    snap_wg_only.tunnel_endpoints.retain(|ep| ep.id == 7);
    let prev = build_forwarding_state(&snap_wg_only);
    let next = build_forwarding_state(&two_tunnel_snapshot());
    assert_eq!(tunnel_remap_purge_ids(&prev, &next, true), vec![824]);
    assert!(tunnel_remap_purge_ids(&prev, &next, false).is_empty());
}

/// #1873 owner check (Codex code r2): a stale session whose stored
/// tunnel resolution was created against a DIFFERENT owning netdev of
/// the same id must NEVER adopt the new owner at re-resolution — the
/// stored egress_ifindex (= the owner's logical_ifindex at resolve
/// time) is the discriminator, independent of purge timing, worker
/// rotation, or which forwarding state the worker held at create.
#[test]
fn stale_session_never_adopts_reowned_tunnel_id() {
    use crate::afxdp::ShardedNeighborMap;
    use crate::afxdp::session_glue::lookup_forwarding_resolution_for_session;

    let state = build_forwarding_state(&two_tunnel_snapshot());
    let row_ifindex = state
        .tunnel_endpoints
        .get(&824)
        .expect("gre row")
        .logical_ifindex;
    let flow = crate::afxdp::SessionFlow {
        src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7)),
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7)),
            src_port: 55068,
            dst_port: 5201,
        },
    };
    let stale_decision = crate::session::SessionDecision {
        resolution: crate::afxdp::ForwardingResolution {
            disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            // The OLD owner's netdev ifindex — different from the
            // current row's.
            egress_ifindex: row_ifindex + 1000,
            tx_ifindex: 3,
            tunnel_endpoint_id: 824,
            next_hop: None,
            neighbor_mac: Some([2, 0, 0, 0, 0, 9]),
            src_mac: Some([2, 0, 0, 0, 0, 1]),
            tx_vlan_id: 0,
        },
        nat: crate::nat::NatDecision::default(),
    };
    let resolved = lookup_forwarding_resolution_for_session(
        &state,
        &std::sync::Arc::new(ShardedNeighborMap::new()),
        &flow,
        stale_decision,
    );
    assert_eq!(
        resolved.disposition,
        crate::afxdp::ForwardingDisposition::NoRoute,
        "stale owner must be gated, never re-resolved into the new owner"
    );
    assert_eq!(
        resolved.tunnel_endpoint_id, 824,
        "the gated resolution stays tunnel-marked so the R-C gate drops it"
    );
    assert_eq!(
        resolved.egress_ifindex,
        row_ifindex + 1000,
        "the stale egress_ifindex survives write-back so the gate stays sticky"
    );

    // Control: a session created against the CURRENT owner re-resolves
    // normally (the cached ForwardCandidate fallback applies when the
    // outer route is unresolvable in this fixture).
    let mut fresh_decision = stale_decision;
    fresh_decision.resolution.egress_ifindex = row_ifindex;
    let resolved = lookup_forwarding_resolution_for_session(
        &state,
        &std::sync::Arc::new(ShardedNeighborMap::new()),
        &flow,
        fresh_decision,
    );
    assert_ne!(
        (resolved.disposition, resolved.egress_ifindex),
        (crate::afxdp::ForwardingDisposition::NoRoute, 0),
        "matching owner must not be gated"
    );
}

/// #1873 owner-RG attribution pin (Codex code r3 MAJOR 2): a stale
/// tunnel resolution (stored egress_ifindex != the current row's
/// logical_ifindex) must NOT inherit the NEW owner's redundancy group
/// — owner_rg_for_resolution returns 0 (unknown) so HA metadata and
/// owner-RG indexes keep their existing attribution.
#[test]
fn stale_owner_resolution_does_not_inherit_new_owner_rg() {
    use crate::afxdp::owner_rg_for_resolution;
    let mut snap = two_tunnel_snapshot();
    snap.tunnel_endpoints[0].redundancy_group = 2;
    let state = build_forwarding_state(&snap);
    let row_ifindex = state
        .tunnel_endpoints
        .get(&824)
        .expect("gre row")
        .logical_ifindex;
    let mut resolution = crate::afxdp::ForwardingResolution {
        disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: row_ifindex,
        tx_ifindex: 3,
        tunnel_endpoint_id: 824,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    };
    assert_eq!(owner_rg_for_resolution(&state, resolution), 2);
    // Stale owner: a different netdev owned this id when the session
    // resolved — never attribute the new owner's RG.
    resolution.egress_ifindex = row_ifindex + 1000;
    assert_eq!(owner_rg_for_resolution(&state, resolution), 0);
    // Synced entries installed with an unresolvable id (egress 0)
    // keep the current-row attribution (no discriminator to check).
    resolution.egress_ifindex = 0;
    assert_eq!(owner_rg_for_resolution(&state, resolution), 2);
}

/// #1873 reconcile-boundary purge pin (AGY code r3 / Codex code r3):
/// the reconcile path diffs against the tunnel-owner map captured
/// BEFORE teardown defaults coord.forwarding — the owners-list flavor
/// must implement all three arms, and the new-appearance arm must be
/// skippable for the genuine first apply.
#[test]
fn tunnel_remap_purge_ids_from_owners_semantics() {
    use crate::afxdp::coordinator::tunnel_remap_purge_ids_from_owners;
    let next = build_forwarding_state(&two_tunnel_snapshot());

    // Vanished id.
    let owners = vec![
        (824u16, "gr-0/0/0.0".to_string()),
        (7u16, "wg0".to_string()),
        (901u16, "gr-1/1/1.0".to_string()),
    ];
    assert_eq!(
        tunnel_remap_purge_ids_from_owners(&owners, &next, true),
        vec![901]
    );

    // Owner change at a surviving id.
    let owners = vec![
        (824u16, "gr-old/0/0.0".to_string()),
        (7u16, "wg0".to_string()),
    ];
    assert_eq!(
        tunnel_remap_purge_ids_from_owners(&owners, &next, true),
        vec![824]
    );

    // New appearance: id 824 absent from the prior owners.
    let owners = vec![(7u16, "wg0".to_string())];
    assert_eq!(
        tunnel_remap_purge_ids_from_owners(&owners, &next, true),
        vec![824]
    );
    assert!(tunnel_remap_purge_ids_from_owners(&owners, &next, false).is_empty());

    // Pristine first apply (empty owners + flag false): nothing purged.
    assert!(tunnel_remap_purge_ids_from_owners(&[], &next, false).is_empty());
}

// #2008 H3/H4: pin the snapshot -> runtime read of the ALG-disable
// bitfield in forwarding_build/mod.rs (`state.alg_disable_flags =
// snapshot.flow.alg_disable_flags`). Without this assertion the wire
// plumbing is untested end to end: the Go-packing tests and the pure
// `alg_type_for_session` tests both stay green even if the build step
// is reverted to a hardcoded 0, so the flag would silently never reach
// the conntrack publisher. MUTATION-VERIFY: hardcoding line 175 to 0
// (or dropping the assignment) must fail this test.
#[test]
fn build_forwarding_state_carries_alg_disable_flags() {
    // DNS (0x01) + FTP (0x02) disabled.
    let flags: u8 = 0x01 | 0x02;
    let snapshot = ConfigSnapshot {
        flow: crate::FlowSnapshot {
            alg_disable_flags: flags,
            ..Default::default()
        },
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(
        state.alg_disable_flags, flags,
        "ForwardingState.alg_disable_flags must equal snapshot.flow.alg_disable_flags"
    );
}

// #2008 H14: pin the snapshot -> runtime read of `power_mode_disable` in
// forwarding_build/mod.rs (`state.power_mode_disable =
// snapshot.flow.power_mode_disable`). MUTATION-VERIFY: dropping that
// assignment (leaving the ForwardingState default of false) must fail this
// test.
#[test]
fn build_forwarding_state_carries_power_mode_disable() {
    let snapshot = ConfigSnapshot {
        flow: crate::FlowSnapshot {
            power_mode_disable: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.power_mode_disable,
        "ForwardingState.power_mode_disable must equal snapshot.flow.power_mode_disable"
    );
}
