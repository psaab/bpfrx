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
    pub inet_precedence_classifiers: FastMap<String, CoSINetPrecedenceClassifierConfig>,
    pub dscp_rewrite_rules: FastMap<String, CoSDSCPRewriteRuleConfig>,
    pub schedulers: FastMap<String, &'a CoSSchedulerSnapshot>,
    pub scheduler_maps: FastMap<String, &'a CoSSchedulerMapSnapshot>,
}

/// #hb166 T-4: substitute the interface default queue for a classifier
/// code-point whose forwarding-class resolves to a queue the interface does
/// NOT materialize (no scheduler-map entry / no synthetic queue for it).
///
/// A behavior-aggregate classifier maps a DSCP / PCP code-point to a
/// forwarding-class, which maps to a `queue_id` via the GLOBAL
/// `class_to_queue`. But an interface only materializes the queues named by
/// its scheduler-map (plus the synthetic best-effort). A code-point steering
/// to a queue the interface never built used to be written verbatim into the
/// per-interface table; at runtime `resolve_cos_queue_idx` then found no such
/// queue and the enqueue path DROPPED every packet of that code-point — a
/// 100% silent blackhole that still committed cleanly. Fail SAFE instead:
/// forward on the interface default (best-effort) queue. The dataplane
/// enqueue path carries a matching runtime fallback (#hb166 T-4 in
/// `tx/cos_classify.rs::resolve_cos_queue_idx`).
fn materialized_queue_or_default(
    queue_id: u8,
    materialized_queues: &[u8],
    default_queue: u8,
) -> u8 {
    if materialized_queues.contains(&queue_id) {
        queue_id
    } else {
        default_queue
    }
}

/// Largest valid DSCP code point: the DS field is 6 bits (#2447/#5193). The
/// classifier builders enforce it via the 64-entry table bound; the rewrite
/// ingest has no table to index, so it compares against this constant.
const COS_MAX_DSCP_CODE_POINT: u8 = 63;

fn build_cos_dscp_queue_table(
    classifier_name: &str,
    classifiers: &FastMap<String, CoSDSCPClassifierConfig>,
    materialized_queues: &[u8],
    default_queue: u8,
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
            *slot = materialized_queue_or_default(queue_id, materialized_queues, default_queue);
        }
    }
    Ok(table)
}

fn build_cos_ieee8021_queue_table(
    classifier_name: &str,
    classifiers: &FastMap<String, CoSIEEE8021ClassifierConfig>,
    materialized_queues: &[u8],
    default_queue: u8,
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
            *slot = materialized_queue_or_default(queue_id, materialized_queues, default_queue);
        }
    }
    Ok(table)
}

/// #3995: map a Junos loss-priority string to an internal index
/// (low=0, medium-low=1, medium-high=2, high=3). Returns `None` for an empty
/// or unrecognized value; callers treat that as the default LOW (classifier)
/// or a wildcard applying to every loss-priority (rewrite-rule).
pub(super) fn cos_loss_priority_index(value: &str) -> Option<u8> {
    match value {
        "low" => Some(0),
        "medium-low" => Some(1),
        "medium-high" => Some(2),
        "high" => Some(3),
        _ => None,
    }
}

/// #3995: flatten a DSCP classifier's `lp_by_dscp` into a fixed 64-entry table
/// (index = DSCP code-point). `u8::MAX` marks an unclassified code-point
/// (resolves to the default LOW loss-priority at classification time). Fails
/// the snapshot CLOSED on an out-of-range code-point, mirroring
/// `build_cos_dscp_queue_table` (#2447).
fn build_cos_dscp_lp_table(
    classifier_name: &str,
    classifiers: &FastMap<String, CoSDSCPClassifierConfig>,
) -> Result<[u8; 64], crate::policy::SnapshotIntegrityError> {
    let mut table = [u8::MAX; 64];
    if classifier_name.is_empty() {
        return Ok(table);
    }
    if let Some(classifier) = classifiers.get(classifier_name) {
        for (&dscp, &lp) in &classifier.lp_by_dscp {
            let Some(slot) = table.get_mut(usize::from(dscp)) else {
                return Err(
                    crate::policy::SnapshotIntegrityError::CosDscpCodePointOutOfRange {
                        classifier: classifier_name.to_string(),
                        dscp,
                    },
                );
            };
            *slot = lp;
        }
    }
    Ok(table)
}

/// #6847: build the per-interface IP-precedence code-point → queue table.
/// Mirrors [`build_cos_ieee8021_queue_table`] (same 3-bit code-point domain,
/// same fail-CLOSED on an out-of-range code-point, same #hb166 T-4
/// materialized-queue fallback), but the code-point comes from the DS field
/// rather than the 802.1Q tag.
fn build_cos_inet_precedence_queue_table(
    classifier_name: &str,
    classifiers: &FastMap<String, CoSINetPrecedenceClassifierConfig>,
    materialized_queues: &[u8],
    default_queue: u8,
) -> Result<[u8; 8], crate::policy::SnapshotIntegrityError> {
    let mut table = [u8::MAX; 8];
    if classifier_name.is_empty() {
        return Ok(table);
    }
    if let Some(classifier) = classifiers.get(classifier_name) {
        for (&precedence, &queue_id) in &classifier.queue_by_prec {
            // A code-point outside the 3-bit IP-precedence domain fails the
            // snapshot CLOSED rather than being masked with `& 0x7`, which
            // would install the classifier for a DIFFERENT traffic class.
            let Some(slot) = table.get_mut(usize::from(precedence)) else {
                return Err(
                    crate::policy::SnapshotIntegrityError::CosInetPrecedenceCodePointOutOfRange {
                        classifier: classifier_name.to_string(),
                        precedence,
                    },
                );
            };
            *slot = materialized_queue_or_default(queue_id, materialized_queues, default_queue);
        }
    }
    Ok(table)
}

/// #6847: flatten an IP-precedence classifier's `lp_by_prec` into a fixed
/// 8-entry table. `u8::MAX` marks an unclassified code-point. Without this the
/// entry's `loss-priority` would compile and be silently dropped before the
/// egress rewrite keyed on it.
fn build_cos_inet_precedence_lp_table(
    classifier_name: &str,
    classifiers: &FastMap<String, CoSINetPrecedenceClassifierConfig>,
) -> Result<[u8; 8], crate::policy::SnapshotIntegrityError> {
    let mut table = [u8::MAX; 8];
    if classifier_name.is_empty() {
        return Ok(table);
    }
    if let Some(classifier) = classifiers.get(classifier_name) {
        for (&precedence, &lp) in &classifier.lp_by_prec {
            let Some(slot) = table.get_mut(usize::from(precedence)) else {
                return Err(
                    crate::policy::SnapshotIntegrityError::CosInetPrecedenceCodePointOutOfRange {
                        classifier: classifier_name.to_string(),
                        precedence,
                    },
                );
            };
            *slot = lp;
        }
    }
    Ok(table)
}

/// #3995: flatten an 802.1p classifier's `lp_by_pcp` into a fixed 8-entry
/// table. `u8::MAX` marks an unclassified code-point.
fn build_cos_ieee8021_lp_table(
    classifier_name: &str,
    classifiers: &FastMap<String, CoSIEEE8021ClassifierConfig>,
) -> Result<[u8; 8], crate::policy::SnapshotIntegrityError> {
    let mut table = [u8::MAX; 8];
    if classifier_name.is_empty() {
        return Ok(table);
    }
    if let Some(classifier) = classifiers.get(classifier_name) {
        for (&pcp, &lp) in &classifier.lp_by_pcp {
            let Some(slot) = table.get_mut(usize::from(pcp)) else {
                return Err(
                    crate::policy::SnapshotIntegrityError::CosIeee8021CodePointOutOfRange {
                        classifier: classifier_name.to_string(),
                        pcp,
                    },
                );
            };
            *slot = lp;
        }
    }
    Ok(table)
}

/// #3995: the loss-priority-INDEPENDENT rewrite for a forwarding-class, or
/// `None`. `Some(v)` only when EVERY loss-priority maps to the same code-point
/// `v` (a single-value / wildcard rule), so the per-queue drain fallback can
/// apply it regardless of a packet's loss-priority without misapplying it.
/// Loss-priority-differentiated (or partial) rules return `None` and are
/// resolved per-flow at classification time.
fn uniform_fc_rewrite(rule: &CoSDSCPRewriteRuleConfig, forwarding_class: &str) -> Option<u8> {
    let first = rule
        .dscp_by_fc_lp
        .get(&(forwarding_class.to_string(), 0))
        .copied()?;
    (1..COS_LOSS_PRIORITY_LEVELS)
        .all(|lp| {
            rule.dscp_by_fc_lp
                .get(&(forwarding_class.to_string(), lp))
                .copied()
                == Some(first)
        })
        .then_some(first)
}

/// #3995: build the per-egress-interface loss-priority classification + rewrite
/// tables. Flattens the interface's classifiers into DSCP/PCP → loss-priority
/// tables and builds the `(queue_id, loss_priority)` → code-point matrix from
/// the interface's rewrite-rule over its materialized queues.
fn build_cos_lp_rewrite(
    iface: &InterfaceSnapshot,
    cfg: &CoSInterfaceConfig,
    tables: &ClassifierTables<'_>,
) -> Result<CoSLossPriorityRewrite, crate::policy::SnapshotIntegrityError> {
    let dscp_lp_by_dscp = build_cos_dscp_lp_table(&cfg.dscp_classifier, &tables.dscp_classifiers)?;
    let ieee8021_lp_by_pcp =
        build_cos_ieee8021_lp_table(&cfg.ieee8021_classifier, &tables.ieee8021_classifiers)?;
    let inet_precedence_lp_by_prec = build_cos_inet_precedence_lp_table(
        &cfg.inet_precedence_classifier,
        &tables.inet_precedence_classifiers,
    )?;
    let mut dscp_rewrite_by_queue_lp: FastMap<(u8, u8), u8> = FastMap::default();
    if let Some(rule) = tables.dscp_rewrite_rules.get(&iface.cos_dscp_rewrite_rule) {
        for queue in &cfg.queues {
            for lp in 0..COS_LOSS_PRIORITY_LEVELS {
                if let Some(&dscp) = rule.dscp_by_fc_lp.get(&(queue.forwarding_class.clone(), lp)) {
                    dscp_rewrite_by_queue_lp.insert((queue.queue_id, lp), dscp);
                }
            }
        }
    }
    Ok(CoSLossPriorityRewrite {
        dscp_lp_by_dscp,
        ieee8021_lp_by_pcp,
        inet_precedence_lp_by_prec,
        dscp_rewrite_by_queue_lp,
    })
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

/// #4228 Gap 2: resolve a Junos `transmit-rate percent <n>` share against a
/// base rate in bytes/sec. Mirrors `cos_percent_buffer_bytes` EXACTLY — same
/// (0,100] domain guard, same `ceil` rounding, same clamp to [1, u64::MAX] —
/// so a scheduler's transmit-rate percent and buffer-size percent round
/// identically. Returns `None` when the base is unknown (0, e.g. a transparent
/// root with no interface shaping-rate) or the percent is out of range; the
/// caller then leaves the queue without an explicit transmit-rate (the
/// documented inert fallback, matching the buffer-size None->default path).
fn cos_percent_rate_bytes(base_rate_bytes: u64, percent: f64) -> Option<u64> {
    cos_percent_buffer_bytes(base_rate_bytes, percent)
}

/// #4228 Gap 2: the effective absolute transmit-rate for a scheduler bound to
/// an interface whose root shaping rate is `iface_shaping_rate_bytes`. An
/// explicit absolute `transmit_rate_bytes` wins; otherwise a `transmit_rate
/// percent <n>` resolves against the interface's shaping rate. `None` means no
/// explicit guarantee (transparent / best-effort), preserving the historical
/// behavior for schedulers with neither form set.
fn cos_effective_transmit_rate_bytes(
    scheduler: Option<&CoSSchedulerSnapshot>,
    iface_shaping_rate_bytes: u64,
) -> Option<u64> {
    let sched = scheduler?;
    if sched.transmit_rate_bytes > 0 {
        return Some(sched.transmit_rate_bytes);
    }
    if sched.transmit_rate_percent > 0.0 {
        return cos_percent_rate_bytes(iface_shaping_rate_bytes, sched.transmit_rate_percent);
    }
    None
}

fn cos_surplus_weight(rate_bytes: u64, root_rate_bytes: u64) -> u32 {
    if rate_bytes == 0 || root_rate_bytes == 0 {
        return 1;
    }
    ((rate_bytes as u128) * 16)
        .div_ceil(root_rate_bytes as u128)
        .clamp(1, 16) as u32
}

/// Map a Junos scheduler priority string to an internal strict-priority
/// rank (0 = highest, 5 = lowest). Returns `None` for an unrecognized
/// non-empty string so the caller can fail the snapshot CLOSED (#hb166
/// T-7) — mirroring the #2458 equal-flow-policy parse on the same queue
/// rather than silently ranking an unknown priority lowest ("low").
///
/// # Rank 3 is deliberately vacant (#6849)
///
/// Junos has no bare `medium` scheduler priority. The five levels are
/// `strict-high` / `high` / `medium-high` / `medium-low` / `low`, which is
/// what the Go config schema's `priority` enum accepts and therefore the
/// only set any committed config can produce (`pkg/config/schema_cos.go`,
/// `ValidateEnum`).
///
/// A `"medium" => Some(3)` arm was here until #6849. It was not a
/// deliberate tolerance for version drift: it predates the T-7 fail-closed
/// work, where the original function was a six-level ladder ending in a
/// catch-all `_ => 5`, and T-7 mechanically rewrote each arm to `Some(n)`
/// while converting the signature. Checked before removing it: no version
/// of the Go producer has ever emitted `medium` for this leaf, so the arm
/// was unreachable from every path that can reach this function.
///
/// The remaining ranks KEEP their original numbers rather than closing up
/// to 0..=4. Renumbering would move `low` from 5 to 4, and a large number
/// of CoS tests construct queues with a literal `priority: 5` meaning
/// "low" — they would still compile, still pass (the builder clamps with
/// `.min(COS_PRIORITY_LEVELS - 1)`), and quietly mean something else. A
/// vacant slot costs one unused `Vec` per interface; a silent
/// reinterpretation of every hardcoded rank costs more.
///
/// Consequently `COS_PRIORITY_LEVELS` stays 6 and is CORRECT rather than
/// off by one: it sizes arrays INDEXED BY RANK, and the highest live rank
/// is still `low` = 5.
#[cfg(test)]
pub(in crate::afxdp::forwarding_build) fn cos_priority_rank_for_test(priority: &str) -> Option<u8> {
    cos_priority_rank(priority)
}

fn cos_priority_rank(priority: &str) -> Option<u8> {
    match priority {
        "strict-high" => Some(0),
        "high" => Some(1),
        "medium-high" => Some(2),
        // rank 3 vacant — see the note above.
        "medium-low" => Some(4),
        "low" => Some(5),
        _ => None,
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
            let mut lp_by_dscp = FastMap::default();
            for entry in &classifier.entries {
                if entry.forwarding_class.is_empty() {
                    continue;
                }
                let Some(queue_id) = class_to_queue.get(&entry.forwarding_class).copied() else {
                    continue;
                };
                // #3995: a classifier entry with no explicit loss-priority
                // defaults to LOW (the Junos default drop-precedence).
                let lp = cos_loss_priority_index(&entry.loss_priority).unwrap_or(0);
                for dscp in &entry.dscp_values {
                    queue_by_dscp.insert(*dscp, queue_id);
                    lp_by_dscp.insert(*dscp, lp);
                }
            }
            (
                classifier.name.clone(),
                CoSDSCPClassifierConfig {
                    queue_by_dscp,
                    lp_by_dscp,
                },
            )
        })
        .collect::<FastMap<_, _>>();
    let ieee8021_classifiers = cos
        .ieee8021_classifiers
        .iter()
        .filter(|classifier| !classifier.name.is_empty())
        .map(|classifier| {
            let mut queue_by_pcp = FastMap::default();
            let mut lp_by_pcp = FastMap::default();
            for entry in &classifier.entries {
                if entry.forwarding_class.is_empty() {
                    continue;
                }
                let Some(queue_id) = class_to_queue.get(&entry.forwarding_class).copied() else {
                    continue;
                };
                let lp = cos_loss_priority_index(&entry.loss_priority).unwrap_or(0);
                for pcp in &entry.code_points {
                    queue_by_pcp.insert(*pcp, queue_id);
                    lp_by_pcp.insert(*pcp, lp);
                }
            }
            (
                classifier.name.clone(),
                CoSIEEE8021ClassifierConfig {
                    queue_by_pcp,
                    lp_by_pcp,
                },
            )
        })
        .collect::<FastMap<_, _>>();
    // #6847: the IP-precedence classifier table. Structurally identical to the
    // 802.1p one — same 3-bit code-point domain, same undefined-class skip —
    // but the code-point is read from the DS field at classification time.
    let inet_precedence_classifiers = cos
        .inet_precedence_classifiers
        .iter()
        .filter(|classifier| !classifier.name.is_empty())
        .map(|classifier| {
            let mut queue_by_prec = FastMap::default();
            let mut lp_by_prec = FastMap::default();
            for entry in &classifier.entries {
                if entry.forwarding_class.is_empty() {
                    continue;
                }
                let Some(queue_id) = class_to_queue.get(&entry.forwarding_class).copied() else {
                    continue;
                };
                let lp = cos_loss_priority_index(&entry.loss_priority).unwrap_or(0);
                for precedence in &entry.precedences {
                    queue_by_prec.insert(*precedence, queue_id);
                    lp_by_prec.insert(*precedence, lp);
                }
            }
            (
                classifier.name.clone(),
                CoSINetPrecedenceClassifierConfig {
                    queue_by_prec,
                    lp_by_prec,
                },
            )
        })
        .collect::<FastMap<_, _>>();
    let dscp_rewrite_rules = cos
        .dscp_rewrite_rules
        .iter()
        .filter(|rewrite_rule| !rewrite_rule.name.is_empty())
        .map(|rewrite_rule| {
            // #3995: key the rewrite on (forwarding-class, loss-priority). Two
            // passes so a specific loss-priority entry always wins over a
            // wildcard (no explicit loss-priority) one regardless of config
            // order.
            let mut dscp_by_fc_lp: FastMap<(String, u8), u8> = FastMap::default();
            // #5193 (A1-b7-F7): every stored code-point is bounded to the
            // 6-bit DSCP domain FIRST. The classifier builders above have
            // failed closed on an out-of-range code-point since #2447, but the
            // rewrite ingest stored `entry.dscp_value` unchecked while the
            // transmit path masks it (`dscp & 0x3f`, frame/mod.rs) — so a rule
            // carrying 110 marked egress packets DSCP 46, a different PHB than
            // configured, with no apply failure anywhere. Validating the whole
            // rule up front (rather than per insert) keeps the two passes below
            // unchanged and means a bad entry cannot install a PARTIAL rule.
            for entry in &rewrite_rule.entries {
                if entry.forwarding_class.is_empty() {
                    continue;
                }
                if entry.dscp_value > COS_MAX_DSCP_CODE_POINT {
                    return Err(
                        crate::policy::SnapshotIntegrityError::CosDscpRewriteCodePointOutOfRange {
                            rule: rewrite_rule.name.clone(),
                            forwarding_class: entry.forwarding_class.clone(),
                            dscp: entry.dscp_value,
                        },
                    );
                }
            }
            // Pass 1: entries WITH an explicit loss-priority.
            for entry in &rewrite_rule.entries {
                if entry.forwarding_class.is_empty() {
                    continue;
                }
                if let Some(lp) = cos_loss_priority_index(&entry.loss_priority) {
                    dscp_by_fc_lp
                        .entry((entry.forwarding_class.clone(), lp))
                        .or_insert(entry.dscp_value);
                }
            }
            // Pass 2: an entry with NO explicit loss-priority is a wildcard that
            // applies to ALL loss-priorities (backward-compat) — filling only
            // the slots a specific entry did not already claim.
            for entry in &rewrite_rule.entries {
                if entry.forwarding_class.is_empty() {
                    continue;
                }
                if cos_loss_priority_index(&entry.loss_priority).is_none() {
                    for lp in 0..COS_LOSS_PRIORITY_LEVELS {
                        dscp_by_fc_lp
                            .entry((entry.forwarding_class.clone(), lp))
                            .or_insert(entry.dscp_value);
                    }
                }
            }
            Ok((
                rewrite_rule.name.clone(),
                CoSDSCPRewriteRuleConfig { dscp_by_fc_lp },
            ))
        })
        .collect::<Result<FastMap<_, _>, crate::policy::SnapshotIntegrityError>>()?;
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
        inet_precedence_classifiers,
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
            // A scheduler-map entry naming a scheduler that is NOT defined
            // in `class-of-service schedulers` resolves to `None` here. The
            // strict commit validator
            // (validateClassOfServiceSchedulerMapRefsStrict, pkg/config)
            // now hard-rejects such a reference, but a config persisted by
            // an older binary — or peer-synced — can still carry it on the
            // lenient load path (#1960 no-brick), so the dataplane must fail
            // SAFE, not OPEN. Before this fix `None` fell through to
            // `transmit_rate_bytes = iface.cos_shaping_rate_bytes_per_sec`
            // (the WHOLE interface shaping rate), which drove
            // `surplus_weight` to the MAX (16, cos_surplus_weight at the
            // root rate): the class did not merely lose its guarantee, it
            // silently won the LARGEST best-effort surplus share. Pin the
            // queue to the minimal best-effort surplus weight (1) for an
            // unresolved reference instead. The queue stays materialized
            // under its real queue_id / forwarding_class so a classifier
            // steering traffic to it still forwards (dropping the entry
            // would blackhole that traffic) — it just never gets MORE than
            // a plain best-effort class. `guarantee_enabled` stays false and
            // priority stays "low" below, so no guarantee or priority is
            // fabricated. A DEFINED scheduler that merely omits a
            // transmit-rate keeps its `surplus_weight = 16` (scheduler is
            // Some), unchanged.
            let scheduler_unresolved = scheduler.is_none();
            // #4228 Gap 2: resolve the scheduler's transmit-rate to an absolute
            // byte/sec rate PER INTERFACE. An explicit absolute rate wins; a
            // `percent <n>` form resolves against THIS interface's shaping rate
            // (`cos_shaping_rate_bytes_per_sec`) — the same interface-shaping
            // base family buffer-size percent uses — so the previously
            // accepted-but-inert percent now drives the guarantee, surplus
            // weight, and token bucket. A named scheduler mapped onto interfaces
            // of different shaping rates materializes a different absolute rate
            // on each, which is exactly why the percent is carried (not
            // pre-resolved) on the shared snapshot.
            let explicit_transmit_rate_bytes =
                cos_effective_transmit_rate_bytes(scheduler, iface.cos_shaping_rate_bytes_per_sec);
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
                // #hb166 T-7: fail-closed on an unknown non-empty priority
                // (mirrors the #2458 equal-flow-policy parse above). A
                // missing scheduler, or one with an empty (unset) priority
                // string, keeps the byte-unchanged legacy "low" default.
                priority: match scheduler.map(|sched| sched.priority.as_str()) {
                    Some(p) if !p.is_empty() => cos_priority_rank(p).ok_or_else(|| {
                        crate::policy::SnapshotIntegrityError::CosUnknownSchedulerPriority {
                            forwarding_class: entry.forwarding_class.clone(),
                            priority: p.to_string(),
                        }
                    })?,
                    _ => 5,
                },
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
                surplus_weight: if scheduler_unresolved {
                    // SAFE default for a dangling scheduler reference:
                    // minimal best-effort surplus share, never the fail-open
                    // maximum the whole-interface effective rate would derive.
                    1
                } else {
                    cos_surplus_weight(
                        transmit_rate_bytes.max(1),
                        iface.cos_shaping_rate_bytes_per_sec,
                    )
                },
                buffer_bytes: cos_scheduler_buffer_bytes(
                    scheduler,
                    burst_bytes,
                    transmit_rate_bytes,
                ),
                // #3995: only the loss-priority-UNIFORM rewrite is baked into
                // the per-queue drain fallback; differentiated rewrites are
                // resolved per-flow at classification (see `uniform_fc_rewrite`).
                dscp_rewrite: dscp_rewrite_rule
                    .and_then(|rewrite_rule| uniform_fc_rewrite(rewrite_rule, &entry.forwarding_class)),
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
    // #6847: an inet-precedence classifier admits the interface on exactly the
    // same terms as the other two BA arms. Omitting it here would make the
    // classifier inert on any interface that has no shaping-rate, no
    // scheduler-map and no other classifier — i.e. the plain
    // `set class-of-service interfaces <if> unit 0 classifiers inet-precedence
    // <name>` config this issue exists to make work.
    let inet_precedence_classifier_targets_iface_queue = tables
        .inet_precedence_classifiers
        .get(&iface.cos_inet_precedence_classifier)
        .map(|c| {
            c.queue_by_prec
                .values()
                .any(|q| iface_queue_ids.contains(q))
        })
        .unwrap_or(false);
    let dscp_rewrite_targets_iface_class = dscp_rewrite_rule
        .map(|r| {
            r.dscp_by_fc_lp
                .keys()
                .any(|(fc, _lp)| iface_classes.contains(&fc.as_str()))
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
        || inet_precedence_classifier_targets_iface_queue
        || dscp_rewrite_targets_iface_class;
    if !contributes_usable_cos_state {
        return Ok(None);
    }

    if queues.is_empty() {
        queues.push(CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".to_string(),
            priority: cos_priority_rank("low").expect("\"low\" is a known scheduler priority"),
            transmit_rate_bytes: iface.cos_shaping_rate_bytes_per_sec,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::default(),
            surplus_weight: 1,
            buffer_bytes: burst_bytes,
            // #3995: uniform-only fallback (see the scheduler-map queue above).
            dscp_rewrite: dscp_rewrite_rule
                .and_then(|rewrite_rule| uniform_fc_rewrite(rewrite_rule, "best-effort")),
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
    // #hb166 T-4: the queue ids this interface actually materializes at
    // runtime. Built AFTER the synthetic best-effort fallback + sort so it is
    // the FINAL queue set. The behavior-aggregate classifier tables below use
    // it to fail-SAFE — a code-point whose forwarding-class resolves to a queue
    // outside this set falls back to `default_queue` (forward on best-effort)
    // instead of writing an unmaterialized queue id that blackholes at enqueue.
    let materialized_queues: Vec<u8> = queues.iter().map(|queue| queue.queue_id).collect();
    let dscp_queue_by_dscp = build_cos_dscp_queue_table(
        &iface.cos_dscp_classifier,
        &tables.dscp_classifiers,
        &materialized_queues,
        default_queue,
    )?;
    let ieee8021_queue_by_pcp = build_cos_ieee8021_queue_table(
        &iface.cos_ieee8021_classifier,
        &tables.ieee8021_classifiers,
        &materialized_queues,
        default_queue,
    )?;
    let inet_precedence_queue_by_prec = build_cos_inet_precedence_queue_table(
        &iface.cos_inet_precedence_classifier,
        &tables.inet_precedence_classifiers,
        &materialized_queues,
        default_queue,
    )?;
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
        inet_precedence_classifier: iface.cos_inet_precedence_classifier.clone(),
        dscp_queue_by_dscp,
        ieee8021_queue_by_pcp,
        inet_precedence_queue_by_prec,
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
            // #3995: build the per-interface loss-priority classification +
            // rewrite tables alongside the interface config so the DSCP rewrite
            // resolves on (forwarding-class, loss-priority) at TX time.
            let lp_rewrite = build_cos_lp_rewrite(iface, &cfg, &tables)?;
            state.lp_rewrite.insert(iface.ifindex, lp_rewrite);
            state.interfaces.insert(iface.ifindex, cfg);
        }
    }
    state.dscp_classifiers = tables.dscp_classifiers;
    state.ieee8021_classifiers = tables.ieee8021_classifiers;
    state.dscp_rewrite_rules = tables.dscp_rewrite_rules;
    Ok(state)
}
