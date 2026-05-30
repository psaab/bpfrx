// #1349: per-interface status-row accumulator extracted from
// `build_worker_cos_statuses_from_maps`. Owns the interface-level
// fields of a `CoSInterfaceStatus` row (ifindex, name resolution,
// root shaping rate, burst, worker_instances, timer-wheel sleeper
// counts). Does NOT touch queues — those are accumulated by the
// caller via `super::queue_row::accumulate_queue_row`.

use super::*;

/// Fold one binding's contribution to a single interface's status row.
///
/// Side effects, in order:
/// - `entry.ifindex` is set unconditionally (idempotent on second visit).
/// - `entry.interface_name` is filled on first visit only via the
///   `ifindex_to_config_name -> ifindex_to_name -> "ifindex-N"`
///   fallback chain.
/// - `shaping_rate_bytes` and `burst_bytes` accumulate as MAX across
///   workers (per the original block at cos.rs:570-571 pre-#1349).
/// - `worker_instances` increments by one (saturating).
/// - Timer-wheel sleeper counts accumulate as saturating sums of the
///   per-bucket vector lengths on level0 and level1.
///
/// No queues are touched here. The orchestrator handles the per-queue
/// inner loop separately so that `queue_maps` accumulation can remain
/// indexed by ifindex at the same level as `interfaces`.
#[inline]
pub(super) fn accumulate_interface_root(
    entry: &mut crate::protocol::CoSInterfaceStatus,
    ifindex: i32,
    root: &CoSInterfaceRuntime,
    forwarding: &ForwardingState,
) {
    entry.ifindex = ifindex;
    if entry.interface_name.is_empty() {
        entry.interface_name = forwarding
            .ifindex_to_config_name
            .get(&ifindex)
            .cloned()
            .or_else(|| forwarding.ifindex_to_name.get(&ifindex).cloned())
            .unwrap_or_else(|| format!("ifindex-{ifindex}"));
    }
    entry.shaping_rate_bytes = entry.shaping_rate_bytes.max(root.shaping_rate_bytes);
    entry.burst_bytes = entry.burst_bytes.max(root.burst_bytes);
    // #1628: seed the per-binding MIN sentinel on the FIRST binding folded
    // for this interface (entry came from or_default() = 0). u64::MAX means
    // "no active-backlog binding seen yet"; converted to 0 in
    // finalize_interface_vec. Done before the worker_instances bump so the
    // `== 0` test reliably fires exactly once per interface entry.
    if entry.worker_instances == 0 {
        entry.waterfill_min_epochs_per_worker = u64::MAX;
    }
    entry.worker_instances = entry.worker_instances.saturating_add(1);
    entry.timer_level0_sleepers = entry.timer_level0_sleepers.saturating_add(
        root.timer_wheel
            .level0
            .iter()
            .map(std::vec::Vec::len)
            .sum::<usize>(),
    );
    entry.timer_level1_sleepers = entry.timer_level1_sleepers.saturating_add(
        root.timer_wheel
            .level1
            .iter()
            .map(std::vec::Vec::len)
            .sum::<usize>(),
    );
    // #1628: per-interface waterfill trace counters (this worker's view).
    // Plain `u64`, single-writer (owner worker), read here on the same
    // worker thread. epochs + budget_breaks are SUMMED across this
    // worker's bindings for the interface, like timer_level*_sleepers;
    // the coordinator then sums across workers.
    entry.waterfill_epochs = entry.waterfill_epochs.saturating_add(root.waterfill_epochs);
    entry.waterfill_phase1_budget_breaks = entry
        .waterfill_phase1_budget_breaks
        .saturating_add(root.waterfill_phase1_budget_breaks);
    // #1628 (code-review MAJOR): the MIN-over-active must be PER-BINDING,
    // not over the worker SUM. A worker can hold MULTIPLE bindings for
    // one ifindex; summing their epochs first would let a healthy
    // binding's high epoch count mask a sibling binding locked in
    // Phase 2 (locked epochs=3 + healthy epochs=1000 → SUM 1003, MIN
    // never sees 3). So fold the MIN here, where each binding's OWN
    // `root.waterfill_epochs` and its OWN queue backlog are visible. A
    // backlogged binding with genuine epochs=0 (the lock-in signal) is
    // correctly captured because the unseeded marker is u64::MAX, not 0.
    let binding_has_active_exact_backlog = root.queues.iter().any(|q| {
        q.config.exact
            && q.config.guarantee_enabled
            && (q.hot.queued_bytes > 0 || cos_queue_len(q) > 0)
    });
    if binding_has_active_exact_backlog {
        entry.waterfill_min_epochs_per_worker = entry
            .waterfill_min_epochs_per_worker
            .min(root.waterfill_epochs);
    }
}
