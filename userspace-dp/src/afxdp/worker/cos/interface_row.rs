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
}
