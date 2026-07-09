use std::collections::BTreeMap;

use super::inputs::{BindingFlowsRow, CosFlowsRow};
use super::verdict::{GUARD_ABSOLUTE, GUARD_OVERCOUNT_DIVISOR, GUARD_RELATIVE};

#[cfg_attr(test, derive(Debug))]
pub(crate) struct AggregateResult {
    pub(crate) distribution_a_i: Vec<u32>,
    pub(crate) iface_filter_active: bool,
}

/// Per-worker {a_i} aggregation over the steady-state window.
///
/// - filter rows by `iface_arg` when iface labels are present;
/// - sum counts per `(timestamp, worker_id)`;
/// - take the median of those sums per worker over the window;
/// - return one entry per `0..n_total_workers` (workers with no
///   matching samples report 0).
///
/// Returns `Err(msg)` immediately if any in-window, in-iface row
/// carries `worker_id >= n_total_workers`. Silently dropping such
/// rows would skew `{a_i}` and produce a false PASS if `--n-workers`
/// is misconfigured; failing fast forces the operator to correct it.
///
/// Returns `iface_filter_active=true` only when the user supplied an
/// iface AND at least one TSV row carried a non-empty iface label.
/// Legacy 3-column input (all `iface == ""`) collapses the filter to
/// inactive even when `iface_arg` is non-empty, matching the
/// bidirectional-2× guard fall-through in `main()`.
pub(crate) fn aggregate_per_worker(
    binding_flows: &[BindingFlowsRow],
    iface_arg: &str,
    n_total_workers: u32,
    warmup_secs: u64,
    final_burst_secs: u64,
    iperf_epoch: u64,
    iperf_total_dur: u64,
) -> Result<AggregateResult, String> {
    let any_iface_label_present = binding_flows.iter().any(|r| !r.iface.is_empty());
    if !iface_arg.is_empty() && !any_iface_label_present && !binding_flows.is_empty() {
        eprintln!(
            "fairness-eval: WARNING — --iface={iface_arg} supplied but TSV rows have no iface label \
             (legacy 3-column input). Filter will drop ALL rows; treating --iface as unset.",
        );
    }
    let iface_filter_active = !iface_arg.is_empty() && any_iface_label_present;

    let (ss_start_ts, ss_end_ts) = steady_window_bounds(
        binding_flows.iter().map(|r| r.timestamp),
        warmup_secs,
        final_burst_secs,
        iperf_epoch,
        iperf_total_dur,
    );

    let mut per_ts_worker: BTreeMap<(u64, u32), u32> = BTreeMap::new();
    for row in binding_flows {
        if row.timestamp < ss_start_ts || row.timestamp > ss_end_ts {
            continue;
        }
        if iface_filter_active && row.iface != iface_arg {
            continue;
        }
        if row.worker_id >= n_total_workers {
            // Silently dropping out-of-range worker IDs would skew {a_i}
            // and produce a false PASS if --n-workers is misconfigured.
            return Err(format!(
                "worker_id={} in TSV exceeds --n-workers={n_total_workers}; \
                 re-run with the correct --n-workers value",
                row.worker_id
            ));
        }
        *per_ts_worker
            .entry((row.timestamp, row.worker_id))
            .or_insert(0) += row.count;
    }

    let distribution_a_i = median_per_worker_zero_filled(&per_ts_worker, n_total_workers);

    Ok(AggregateResult {
        distribution_a_i,
        iface_filter_active,
    })
}

pub(crate) fn aggregate_cos_per_worker(
    cos_flows: &[CosFlowsRow],
    cos_ifindex: i32,
    cos_queue_id: u32,
    n_total_workers: u32,
    warmup_secs: u64,
    final_burst_secs: u64,
    iperf_epoch: u64,
    iperf_total_dur: u64,
) -> Result<Vec<u32>, String> {
    let (ss_start_ts, ss_end_ts) = steady_window_bounds(
        cos_flows.iter().map(|r| r.timestamp),
        warmup_secs,
        final_burst_secs,
        iperf_epoch,
        iperf_total_dur,
    );

    let mut per_ts_worker: BTreeMap<(u64, u32), u32> = BTreeMap::new();
    for row in cos_flows {
        if row.timestamp < ss_start_ts || row.timestamp > ss_end_ts {
            continue;
        }
        if row.ifindex != cos_ifindex || row.queue_id != cos_queue_id {
            continue;
        }
        if row.worker_id >= n_total_workers {
            return Err(format!(
                "worker_id={} in CoS TSV exceeds --n-workers={n_total_workers}; \
                 re-run with the correct --n-workers value",
                row.worker_id
            ));
        }
        *per_ts_worker
            .entry((row.timestamp, row.worker_id))
            .or_insert(0) += row.count;
    }

    Ok(median_per_worker_zero_filled(&per_ts_worker, n_total_workers))
}

/// Per-worker median of the summed active-flow count, zero-filling
/// absent worker samples across the full in-window scrape-timestamp
/// universe (V-5).
///
/// The universe is the set of timestamps present in `per_ts_worker`
/// (the in-window, source-matched rows). A worker with no entry at a
/// timestamp where the source WAS scraped genuinely had 0 active flows
/// there. Median-over-present-samples-only kept a worker whose flows
/// died mid-window "active" (it retained the median of its live head
/// samples), inflating Nₐ and distorting Cstruct. The CoS exporter emits
/// rows only for live flows, so it is the vulnerable source; the binding
/// exporter zero-fills every worker every scrape, so for that source the
/// universe already contains every (ts, worker) and this is a no-op.
///
/// Missing whole scrapes (a Prometheus scrape gap where NO worker on the
/// source emitted) do not appear in the universe, so a scrape gap is not
/// fabricated into spurious zeros.
fn median_per_worker_zero_filled(
    per_ts_worker: &BTreeMap<(u64, u32), u32>,
    n_total_workers: u32,
) -> Vec<u32> {
    let timestamps: std::collections::BTreeSet<u64> =
        per_ts_worker.keys().map(|(ts, _)| *ts).collect();
    (0..n_total_workers)
        .map(|w| {
            if timestamps.is_empty() {
                return 0;
            }
            let mut samples: Vec<u32> = timestamps
                .iter()
                .map(|ts| per_ts_worker.get(&(*ts, w)).copied().unwrap_or(0))
                .collect();
            samples.sort_unstable();
            samples[samples.len() / 2]
        })
        .collect()
}

/// Steady-state window bounds (inclusive, epoch seconds) for the scrape
/// aggregation.
///
/// When the iperf JSON carries a run epoch (`start.timestamp.timesecs`)
/// and a usable duration, the window is anchored to the ACTUAL run
/// interval `[epoch + warmup, epoch + duration - final_burst]`. This
/// excludes stale pre-run / cooldown-era scrapes that sit inside the
/// scrape file but outside the run (V-6). The scrape TSV timestamps and
/// `timesecs` share the same epoch-seconds clock.
///
/// Fallback (no `timesecs`, e.g. synthetic or legacy hand-built input):
/// the scrape-file extent `[min + warmup, max - final_burst]`. This is
/// the pre-V-6 heuristic and can admit stale head samples, but the
/// production harness always emits `timesecs`, so the fallback is only
/// reached by artifacts that never had a run epoch to anchor to.
pub(crate) fn steady_window_bounds(
    timestamps: impl Iterator<Item = u64>,
    warmup_secs: u64,
    final_burst_secs: u64,
    iperf_epoch: u64,
    iperf_total_dur: u64,
) -> (u64, u64) {
    if iperf_epoch > 0 && iperf_total_dur > warmup_secs + final_burst_secs {
        let start = iperf_epoch.saturating_add(warmup_secs);
        let end = iperf_epoch
            .saturating_add(iperf_total_dur)
            .saturating_sub(final_burst_secs);
        return (start, end);
    }
    let mut min_ts = u64::MAX;
    let mut max_ts = 0u64;
    for ts in timestamps {
        min_ts = min_ts.min(ts);
        max_ts = max_ts.max(ts);
    }
    if min_ts == u64::MAX {
        // No rows: degenerate empty window (start > end filters nothing
        // in, matching the pre-V-6 unwrap_or(0) behavior for empty input).
        return (warmup_secs, 0u64.saturating_sub(final_burst_secs));
    }
    (
        min_ts.saturating_add(warmup_secs),
        max_ts.saturating_sub(final_burst_secs),
    )
}

pub(crate) fn max_worker_flow_share(distribution_a_i: &[u32]) -> f64 {
    let total: u32 = distribution_a_i.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let max = distribution_a_i.iter().copied().max().unwrap_or(0);
    max as f64 / total as f64
}

pub(crate) fn direction_multiplier(iface_filter_active: bool) -> u32 {
    if iface_filter_active {
        1
    } else {
        2
    }
}

pub(crate) fn guard_sum_tolerances(expected_sum: u32) -> (u32, u32) {
    let under = ((GUARD_RELATIVE * expected_sum as f64) as u32).max(GUARD_ABSOLUTE);
    let over = expected_sum.saturating_add(GUARD_OVERCOUNT_DIVISOR - 1) / GUARD_OVERCOUNT_DIVISOR;
    (under, over.max(GUARD_ABSOLUTE))
}

pub(crate) fn trim_distribution_to_sum(distribution: &[u32], target_sum: u32) -> Vec<u32> {
    let mut trimmed = distribution.to_vec();
    let mut excess = trimmed.iter().sum::<u32>().saturating_sub(target_sum);
    while excess > 0 {
        let Some((idx, _)) = trimmed
            .iter()
            .enumerate()
            .filter(|(_, count)| **count > 0)
            .max_by_key(|(_, count)| **count)
        else {
            break;
        };
        trimmed[idx] -= 1;
        excess -= 1;
    }
    trimmed
}

#[cfg(test)]
#[path = "per_worker_tests.rs"]
mod tests;
