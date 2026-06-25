//! CoS (class-of-service) state builder.
//!
//! Translates a `ConfigSnapshot::class_of_service` block into a
//! `CoSState`. Decomposed (#1342) into three sub-100-LOC helpers:
//!
//! 1. [`build_cos_classifier_tables`] — class_to_queue map,
//!    DSCP classifiers, 802.1p classifiers, DSCP rewrite-rules,
//!    schedulers/scheduler-maps borrow-only lookup tables.
//! 2. [`build_cos_iface_config`] — per-interface loop body.
//!    Owns the `useful_cos_state` gate from #1183 that prevents
//!    forwarding-only interfaces from being silently admitted to
//!    `CoSState`, which would collapse 6-worker parallelism via
//!    the cross-binding redirect.
//! 3. [`build_cos_state`] — orchestrator.

use super::super::*;
use crate::{ClassOfServiceSnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot};

/// Borrow-only lookup tables built once per CoS snapshot. The
/// orchestrator owns the value; per-interface helper borrows
/// `&tables`. `'a` ties the borrow-only fields to the
/// `&'a ClassOfServiceSnapshot` we built from.
pub(super) struct ClassifierTables<'a> {
    pub class_to_queue: FastMap<String, u8>,
    pub dscp_classifiers: FastMap<String, CoSDSCPClassifierConfig>,
    pub ieee8021_classifiers: FastMap<String, CoSIEEE8021ClassifierConfig>,
    pub dscp_rewrite_rules: FastMap<String, CoSDSCPRewriteRuleConfig>,
    pub schedulers: FastMap<String, &'a CoSSchedulerSnapshot>,
    pub scheduler_maps: FastMap<String, &'a CoSSchedulerMapSnapshot>,
}

fn build_cos_dscp_queue_table(
    classifier_name: &str,
    classifiers: &FastMap<String, CoSDSCPClassifierConfig>,
) -> Result<[u8; 64], crate::policy::SnapshotIntegrityError> {
    let mut table = [u8::MAX; 64];
    if classifier_name.is_empty() {
        return Ok(table);
    }
    if let Some(classifier) = classifiers.get(classifier_name) {
        for (&dscp, &queue_id) in &classifier.queue_by_dscp {
            // #2447: a code-point outside the 6-bit DSCP domain fails the
            // snapshot CLOSED. The pre-fix `dscp & 0x3f` masked an
            // out-of-range value into a valid index, silently installing the
            // classifier for a DIFFERENT traffic class (110 → 46). The Go
            // commit gate rejects these first; this guards version/snapshot
            // drift. An in-range value indexes the table unchanged.
            let idx = usize::from(dscp);
            let Some(slot) = table.get_mut(idx) else {
                return Err(
                    crate::policy::SnapshotIntegrityError::CosDscpCodePointOutOfRange {
                        classifier: classifier_name.to_string(),
                        dscp,
                    },
                );
            };
            *slot = queue_id;
        }
    }
    Ok(table)
}

fn build_cos_ieee8021_queue_table(
    classifier_name: &str,
    classifiers: &FastMap<String, CoSIEEE8021ClassifierConfig>,
) -> Result<[u8; 8], crate::policy::SnapshotIntegrityError> {
    let mut table = [u8::MAX; 8];
    if classifier_name.is_empty() {
        return Ok(table);
    }
    if let Some(classifier) = classifiers.get(classifier_name) {
        for (&pcp, &queue_id) in &classifier.queue_by_pcp {
            // #2447: a code-point outside the 3-bit PCP domain fails the
            // snapshot CLOSED. The pre-fix `pcp.min(7)` clamped an
            // out-of-range value into a valid index, silently installing the
            // classifier for a DIFFERENT traffic class (9 → 7).
            let idx = usize::from(pcp);
            let Some(slot) = table.get_mut(idx) else {
                return Err(
                    crate::policy::SnapshotIntegrityError::CosIeee8021CodePointOutOfRange {
                        classifier: classifier_name.to_string(),
                        pcp,
                    },
                );
            };
            *slot = queue_id;
        }
    }
    Ok(table)
}

/// Default burst size when interface or scheduler did not specify
/// one. 1% of the rate floored at 64×1500 (~96 KB).
///
/// `pub(super)` because the test suite (now at
/// `forwarding_build/tests.rs`) calls it unqualified via
/// `super::*`. `forwarding_build/mod.rs` re-exports it with a
/// plain `use` to put it in scope of the tests module.
pub(super) fn default_cos_burst_bytes(rate_bytes: u64) -> u64 {
    rate_bytes
        .checked_div(100)
        .unwrap_or_default()
        .max(64 * 1500)
}

fn cos_scheduler_buffer_bytes(
    scheduler: Option<&CoSSchedulerSnapshot>,
    interface_burst_bytes: u64,
    transmit_rate_bytes: u64,
) -> u64 {
    let Some(sched) = scheduler else {
        return default_cos_burst_bytes(transmit_rate_bytes);
    };
    if sched.buffer_size_bytes > 0 {
        return sched.buffer_size_bytes;
    }
    let percent_bytes = cos_percent_buffer_bytes(interface_burst_bytes, sched.buffer_size_percent);
    if let Some(bytes) = percent_bytes {
        return bytes;
    }
    default_cos_burst_bytes(transmit_rate_bytes)
}

fn cos_percent_buffer_bytes(pool_bytes: u64, percent: f64) -> Option<u64> {
    if pool_bytes == 0 || !percent.is_finite() || percent <= 0.0 || percent > 100.0 {
        return None;
    }
    let scaled = ((pool_bytes as f64) * percent / 100.0).ceil();
    if scaled < 1.0 {
        Some(1)
    } else if scaled > u64::MAX as f64 {
        Some(u64::MAX)
    } else {
        Some(scaled as u64)
    }
}

fn cos_surplus_weight(rate_bytes: u64, root_rate_bytes: u64) -> u32 {
    if rate_bytes == 0 || root_rate_bytes == 0 {
        return 1;
    }
    ((rate_bytes as u128) * 16)
        .div_ceil(root_rate_bytes as u128)
        .clamp(1, 16) as u32
}

fn cos_priority_rank(priority: &str) -> u8 {
    match priority {
        "strict-high" => 0,
        "high" => 1,
        "medium-high" => 2,
        "medium" => 3,
        "medium-low" => 4,
        _ => 5,
    }
}

/// Build the borrow-only / owned-map lookup tables consumed by
/// every per-interface CoS evaluation.
///
/// Ordering note (#1342 r2): `class_to_queue` MUST build before
/// `dscp_classifiers` / `ieee8021_classifiers` because the latter
/// resolve `forwarding_class → queue_id` against the former.
pub(super) fn build_cos_classifier_tables(
    cos: &ClassOfServiceSnapshot,
) -> Result<ClassifierTables<'_>, crate::policy::SnapshotIntegrityError> {
    // #2410: a forwarding-class queue id outside 0..=255 fails the snapshot
    // CLOSED. The pre-fix `filter_map` SILENTLY DROPPED the class, so every
    // classifier / scheduler-map entry referencing it lost its queue mapping
    // (a silent fail-open at the second trust boundary). An EMPTY class name
    // is the legitimate placeholder case and is still skipped, not an error.
    let mut class_to_queue: FastMap<String, u8> = FastMap::default();
    for class in &cos.forwarding_classes {
        if class.name.is_empty() {
            continue;
        }
        let queue = super::validated::QueueId::try_from_snapshot(class.queue, &class.name)?.get();
        class_to_queue.insert(class.name.clone(), queue);
    }
    let dscp_classifiers = cos
        .dscp_classifiers
        .iter()
        .filter(|classifier| !classifier.name.is_empty())
        .map(|classifier| {
            let mut queue_by_dscp = FastMap::default();
            for entry in &classifier.entries {
                if entry.forwarding_class.is_empty() {
                    continue;
                }
                let Some(queue_id) = class_to_queue.get(&entry.forwarding_class).copied() else {
                    continue;
                };
                for dscp in &entry.dscp_values {
                    queue_by_dscp.insert(*dscp, queue_id);
                }
            }
            (
                classifier.name.clone(),
                CoSDSCPClassifierConfig { queue_by_dscp },
            )
        })
        .collect::<FastMap<_, _>>();
    let ieee8021_classifiers = cos
        .ieee8021_classifiers
        .iter()
        .filter(|classifier| !classifier.name.is_empty())
        .map(|classifier| {
            let mut queue_by_pcp = FastMap::default();
            for entry in &classifier.entries {
                if entry.forwarding_class.is_empty() {
                    continue;
                }
                let Some(queue_id) = class_to_queue.get(&entry.forwarding_class).copied() else {
                    continue;
                };
                for pcp in &entry.code_points {
                    queue_by_pcp.insert(*pcp, queue_id);
                }
            }
            (
                classifier.name.clone(),
                CoSIEEE8021ClassifierConfig { queue_by_pcp },
            )
        })
        .collect::<FastMap<_, _>>();
    let dscp_rewrite_rules = cos
        .dscp_rewrite_rules
        .iter()
        .filter(|rewrite_rule| !rewrite_rule.name.is_empty())
        .map(|rewrite_rule| {
            let mut dscp_by_forwarding_class = FastMap::default();
            for entry in &rewrite_rule.entries {
                if entry.forwarding_class.is_empty() {
                    continue;
                }
                dscp_by_forwarding_class
                    .entry(entry.forwarding_class.clone())
                    .or_insert(entry.dscp_value);
            }
            (
                rewrite_rule.name.clone(),
                CoSDSCPRewriteRuleConfig {
                    dscp_by_forwarding_class,
                },
            )
        })
        .collect::<FastMap<_, _>>();
    let schedulers = cos
        .schedulers
        .iter()
        .filter(|sched| !sched.name.is_empty())
        .map(|sched| (sched.name.clone(), sched))
        .collect::<FastMap<_, _>>();
    let scheduler_maps = cos
        .scheduler_maps
        .iter()
        .filter(|sched_map| !sched_map.name.is_empty())
        .map(|sched_map| (sched_map.name.clone(), sched_map))
        .collect::<FastMap<_, _>>();
    Ok(ClassifierTables {
        class_to_queue,
        dscp_classifiers,
        ieee8021_classifiers,
        dscp_rewrite_rules,
        schedulers,
        scheduler_maps,
    })
}

/// Per-interface CoS config builder. Returns `None` when the
/// `useful_cos_state` gate (#1183 fix) admits the interface for no
/// usable CoS state — semantically equivalent to the original
/// `continue` at forwarding_build.rs:863.
///
/// Ordering invariant: resolve scheduler-map queues → compute
/// `iface_queue_ids` / `iface_classes` → gate → fallback →
/// finalize. The gate runs BEFORE the synthetic best-effort
/// fallback so that admit/skip is decided on the "useful CoS"
/// criterion alone, not on whether the fallback would otherwise
/// add a synthetic queue.
pub(super) fn build_cos_iface_config(
    iface: &InterfaceSnapshot,
    tables: &ClassifierTables<'_>,
) -> Result<Option<CoSInterfaceConfig>, crate::policy::SnapshotIntegrityError> {
    let burst_bytes = if iface.cos_shaping_burst_bytes > 0 {
        iface.cos_shaping_burst_bytes
    } else {
        default_cos_burst_bytes(iface.cos_shaping_rate_bytes_per_sec)
    };
    let mut queues = Vec::new();
    let dscp_rewrite_rule = tables.dscp_rewrite_rules.get(&iface.cos_dscp_rewrite_rule);
    if let Some(sched_map) = tables.scheduler_maps.get(&iface.cos_scheduler_map) {
        for entry in &sched_map.entries {
            // #2409: a scheduler-map entry referencing a forwarding-class that
            // is not in `class_to_queue` (a typo, a version-drifted snapshot,
            // or a class dropped for an out-of-range queue id) fails the
            // snapshot CLOSED. The pre-fix `continue` partially installed the
            // scheduler — some queues silently missing, no apply failure — a
            // very hard-to-troubleshoot fail-silent loss of shaping.
            let Some(queue_id) = tables.class_to_queue.get(&entry.forwarding_class).copied() else {
                return Err(crate::policy::SnapshotIntegrityError::SchedulerMapUnknownClass {
                    scheduler_map: iface.cos_scheduler_map.clone(),
                    forwarding_class: entry.forwarding_class.clone(),
                });
            };
            let scheduler = tables.schedulers.get(&entry.scheduler).copied();
            let explicit_transmit_rate_bytes = scheduler.and_then(|sched| {
                (sched.transmit_rate_bytes > 0).then_some(sched.transmit_rate_bytes)
            });
            let guarantee_enabled = explicit_transmit_rate_bytes.is_some();
            let transmit_rate_bytes =
                explicit_transmit_rate_bytes.unwrap_or(iface.cos_shaping_rate_bytes_per_sec);
            // #2458: parse the equal-flow target policy up front so an
            // unknown NON-EMPTY value fails the snapshot CLOSED instead of
            // silently collapsing to `Slowest` (the pre-fix catch-all arm).
            // Gated identically to `equal_flow_enforcement`: a policy on a
            // scheduler that is not (or cannot be) equal-flow-enforcing stays
            // at the byte-unchanged default `Slowest`, and the empty / unset
            // wire string is the legitimate legacy default. Only an active
            // equal-flow scheduler with a non-empty UNRECOGNIZED policy
            // string is rejected.
            let equal_flow_target_policy = match scheduler.filter(|sched| {
                guarantee_enabled && sched.transmit_rate_exact && sched.equal_flow_enforcement
            }) {
                Some(sched) => EqualFlowTargetPolicy::parse(&sched.equal_flow_target_policy)
                    .map_err(|bad| {
                        crate::policy::SnapshotIntegrityError::CosUnknownEqualFlowTargetPolicy {
                            forwarding_class: entry.forwarding_class.clone(),
                            target_policy: bad.to_string(),
                        }
                    })?,
                None => EqualFlowTargetPolicy::default(),
            };
            queues.push(CoSQueueConfig {
                queue_id,
                forwarding_class: entry.forwarding_class.clone(),
                priority: cos_priority_rank(
                    scheduler
                        .map(|sched| sched.priority.as_str())
                        .unwrap_or("low"),
                ),
                transmit_rate_bytes,
                guarantee_enabled,
                exact: scheduler
                    .map(|sched| guarantee_enabled && sched.transmit_rate_exact)
                    .unwrap_or(false),
                surplus_sharing: scheduler
                    .map(|sched| {
                        guarantee_enabled && sched.transmit_rate_exact && sched.surplus_sharing
                    })
                    .unwrap_or(false),
                equal_flow_enforcement: scheduler
                    .map(|sched| {
                        guarantee_enabled
                            && sched.transmit_rate_exact
                            && sched.equal_flow_enforcement
                    })
                    .unwrap_or(false),
                // #1746/#2458: gated identically to
                // equal_flow_enforcement; parsed above so an unknown
                // non-empty value fails the snapshot closed.
                equal_flow_target_policy,
                surplus_weight: cos_surplus_weight(
                    transmit_rate_bytes.max(1),
                    iface.cos_shaping_rate_bytes_per_sec,
                ),
                buffer_bytes: cos_scheduler_buffer_bytes(
                    scheduler,
                    burst_bytes,
                    transmit_rate_bytes,
                ),
                dscp_rewrite: dscp_rewrite_rule.and_then(|rewrite_rule| {
                    rewrite_rule
                        .dscp_by_forwarding_class
                        .get(&entry.forwarding_class)
                        .copied()
                }),
                // #1614 A3: per-queue CoDel target from scheduler. 0
                // disables CoDel for the queue (current default).
                codel_target_ns: scheduler
                    .map(|sched| sched.codel_target_ns)
                    .unwrap_or(0),
            });
        }
    }
    let scheduler_map_resolved_to_queues = !queues.is_empty();

    // Determine the set of (queue_id, forwarding_class) pairs that this
    // interface will actually materialize at runtime. If the
    // scheduler-map resolved, those are the configured queues. If not,
    // the synthetic default best-effort queue (queue_id=0,
    // class="best-effort") is added later — but ONLY if we admit the
    // interface, so we model it here for the gate's purposes.
    let (iface_queue_ids, iface_classes): (Vec<u8>, Vec<&str>) =
        if scheduler_map_resolved_to_queues {
            (
                queues.iter().map(|q| q.queue_id).collect(),
                queues.iter().map(|q| q.forwarding_class.as_str()).collect(),
            )
        } else {
            (vec![0], vec!["best-effort"])
        };

    // A classifier arm contributes only if it maps at least one
    // DSCP/802.1p code-point to a queue_id the interface actually
    // materializes. A classifier mapping to queue 5 on an interface
    // that only has queue 0 admits the interface for nothing —
    // packets land in `resolve_cos_queue_idx` and get dropped, the
    // owner-worker redirect engages, and no observable classification
    // happens. Same logic for the rewrite-rule: it contributes only
    // if it has an entry for a forwarding-class the interface
    // materializes.
    let dscp_classifier_targets_iface_queue = tables
        .dscp_classifiers
        .get(&iface.cos_dscp_classifier)
        .map(|c| {
            c.queue_by_dscp
                .values()
                .any(|q| iface_queue_ids.contains(q))
        })
        .unwrap_or(false);
    let ieee8021_classifier_targets_iface_queue = tables
        .ieee8021_classifiers
        .get(&iface.cos_ieee8021_classifier)
        .map(|c| c.queue_by_pcp.values().any(|q| iface_queue_ids.contains(q)))
        .unwrap_or(false);
    let dscp_rewrite_targets_iface_class = dscp_rewrite_rule
        .map(|r| {
            r.dscp_by_forwarding_class
                .keys()
                .any(|fc| iface_classes.contains(&fc.as_str()))
        })
        .unwrap_or(false);

    // Post-build gate (#1183 fix at f0e364d7). See `cos.rs` module
    // doc for full rationale. Skips interfaces that produce no
    // usable CoS state, preventing the cross-binding redirect from
    // funneling TX onto one CPU and collapsing 6-worker parallelism.
    let contributes_usable_cos_state = iface.cos_shaping_rate_bytes_per_sec > 0
        || scheduler_map_resolved_to_queues
        || dscp_classifier_targets_iface_queue
        || ieee8021_classifier_targets_iface_queue
        || dscp_rewrite_targets_iface_class;
    if !contributes_usable_cos_state {
        return Ok(None);
    }
    let dscp_queue_by_dscp =
        build_cos_dscp_queue_table(&iface.cos_dscp_classifier, &tables.dscp_classifiers)?;
    let ieee8021_queue_by_pcp = build_cos_ieee8021_queue_table(
        &iface.cos_ieee8021_classifier,
        &tables.ieee8021_classifiers,
    )?;

    if queues.is_empty() {
        queues.push(CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".to_string(),
            priority: cos_priority_rank("low"),
            transmit_rate_bytes: iface.cos_shaping_rate_bytes_per_sec,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::default(),
            surplus_weight: 1,
            buffer_bytes: burst_bytes,
            dscp_rewrite: dscp_rewrite_rule
                .and_then(|rewrite_rule| {
                    rewrite_rule.dscp_by_forwarding_class.get("best-effort")
                })
                .copied(),
            // #1614 A3: synthetic best-effort queue has no scheduler;
            // CoDel disabled by default (0 = off).
            codel_target_ns: 0,
        });
    }
    queues.sort_by(|a, b| a.queue_id.cmp(&b.queue_id));
    let queue_by_forwarding_class = queues
        .iter()
        .map(|queue| (queue.forwarding_class.clone(), queue.queue_id))
        .collect::<FastMap<_, _>>();
    let default_queue = queues
        .iter()
        .find(|queue| queue.forwarding_class == "best-effort")
        .map(|queue| queue.queue_id)
        .unwrap_or_else(|| queues[0].queue_id);
    // #1614 A1: parse the operator-selectable oversubscription
    // policy. "" or "proportional" (default) maps to Proportional
    // (current scheduler unchanged); "guarantee-rate" activates the
    // v5 two-phase waterfill allocator. The Go control plane is
    // responsible for warn-and-clamping the fraction to 0.0..1.0.
    let oversubscription_policy = match iface.cos_oversubscription_policy.as_str() {
        "guarantee-rate" => CoSOversubscriptionPolicy::GuaranteeRate,
        _ => CoSOversubscriptionPolicy::Proportional,
    };
    let oversubscription_guarantee_fraction = iface
        .cos_oversubscription_guarantee_fraction
        .clamp(0.0, 1.0);
    Ok(Some(CoSInterfaceConfig {
        shaping_rate_bytes: iface.cos_shaping_rate_bytes_per_sec,
        burst_bytes,
        default_queue,
        dscp_classifier: iface.cos_dscp_classifier.clone(),
        ieee8021_classifier: iface.cos_ieee8021_classifier.clone(),
        dscp_queue_by_dscp,
        ieee8021_queue_by_pcp,
        queue_by_forwarding_class,
        queues,
        oversubscription_policy,
        oversubscription_guarantee_fraction,
        priority_low_min_share_bytes: iface.cos_priority_low_min_share_bytes,
    }))
}

/// CoS state orchestrator. Pre-#1342 this was a single 312-LOC
/// function; #1342 split it into [`build_cos_classifier_tables`]
/// + [`build_cos_iface_config`] + this slim orchestrator.
///
/// The interface-by-interface gate (#1183 fix) lives inside
/// `build_cos_iface_config`.
///
/// Skip interfaces that do not contribute any usable CoS state.
///
/// f0e364d7 (#916) removed the prior `shaping_rate == 0` skip so
/// that zero-shaping-rate-with-classes interfaces would get a
/// transparent-root CoS runtime instead of being silently dropped.
/// That side-effect added every interface that produced no usable
/// CoS state to `CoSState` too — and any `CoSState` entry triggers
/// the cross-binding redirect that funnels every TX through the
/// per-interface owner worker, collapsing 6-worker parallelism
/// to one CPU and capping reverse throughput at ~2 Gbps instead
/// of ~22 Gbps on the loss userspace cluster.
///
/// The fix is to gate on whether the interface PRODUCES anything
/// useful — not on whether knob *names* are populated. See
/// `build_cos_iface_config` for the five-input gate that closes
/// every shape committed by `pkg/config/compiler_class_of_service.go`
/// (forwarding-only, burst-only without rate, typo'd named
/// references, empty named entities, scheduler-maps with all
/// undefined forwarding-classes).
pub(super) fn build_cos_state(
    snapshot: &ConfigSnapshot,
) -> Result<CoSState, crate::policy::SnapshotIntegrityError> {
    let Some(cos) = snapshot.class_of_service.as_ref() else {
        return Ok(CoSState::default());
    };
    // #2410/#2409: both helpers are now fallible — an out-of-range queue id
    // or a scheduler-map entry referencing a missing class fails the snapshot
    // CLOSED rather than silently dropping the class / partially installing
    // the scheduler.
    let tables = build_cos_classifier_tables(cos)?;
    let mut state = CoSState::default();
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        if let Some(cfg) = build_cos_iface_config(iface, &tables)? {
            state.interfaces.insert(iface.ifindex, cfg);
        }
    }
    state.dscp_classifiers = tables.dscp_classifiers;
    state.ieee8021_classifiers = tables.ieee8021_classifiers;
    state.dscp_rewrite_rules = tables.dscp_rewrite_rules;
    Ok(state)
}
