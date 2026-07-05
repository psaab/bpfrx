use serde::Serialize;

use super::args::Args;

/// Per-flow throughput quantiles (docs/fairness-regimes.md required
/// metric item 1): min, p25, median, p75, max in Mb/s, plus the stream
/// count N of the per-flow set.
#[derive(Debug, Serialize)]
pub(crate) struct PerFlowThroughputQuantiles {
    pub(crate) stream_count: u32,
    pub(crate) min_mbps: f64,
    pub(crate) p25_mbps: f64,
    pub(crate) median_mbps: f64,
    pub(crate) p75_mbps: f64,
    pub(crate) max_mbps: f64,
}

/// Steady-state window explicit timestamps (required metric item 12).
/// `iperf_epoch_*` are wall-clock UNIX seconds (0 when the iperf JSON
/// carried no `timesecs`); `relative_*` are seconds since the run start.
#[derive(Debug, Serialize)]
pub(crate) struct SteadyStateWindow {
    pub(crate) iperf_epoch_start: u64,
    pub(crate) iperf_epoch_end: u64,
    pub(crate) relative_start_sec: f64,
    pub(crate) relative_end_sec: f64,
}

/// Saturation determination supporting time-series (required metric item
/// 6): the per-bucket aggregate throughput series, the Nₐ/Nᵥ-scaled
/// structural cap it is judged against, and the fraction of buckets at
/// or above 95% of that cap.
#[derive(Debug, Serialize)]
pub(crate) struct SaturationSeries {
    pub(crate) structural_cap_bps: u64,
    pub(crate) saturated_bucket_fraction: f64,
    pub(crate) aggregate_buckets_bps: Vec<u64>,
}

/// Compute per-flow throughput quantiles (Mb/s) from the steady-state
/// per-flow mean throughputs (bytes/sec). Nearest-rank percentiles.
pub(crate) fn per_flow_quantiles_mbps(per_flow_bytes_per_sec: &[u64]) -> PerFlowThroughputQuantiles {
    if per_flow_bytes_per_sec.is_empty() {
        return PerFlowThroughputQuantiles {
            stream_count: 0,
            min_mbps: 0.0,
            p25_mbps: 0.0,
            median_mbps: 0.0,
            p75_mbps: 0.0,
            max_mbps: 0.0,
        };
    }
    let mut mbps: Vec<f64> = per_flow_bytes_per_sec
        .iter()
        .map(|&b| b as f64 * 8.0 / 1_000_000.0)
        .collect();
    mbps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = mbps.len();
    let pick = |frac: f64| -> f64 {
        let idx = ((frac * n as f64).ceil() as usize)
            .saturating_sub(1)
            .min(n - 1);
        mbps[idx]
    };
    PerFlowThroughputQuantiles {
        stream_count: n as u32,
        min_mbps: mbps[0],
        p25_mbps: pick(0.25),
        median_mbps: pick(0.5),
        p75_mbps: pick(0.75),
        max_mbps: mbps[n - 1],
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct Report {
    pub(crate) cstruct_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cos_ifindex: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cos_queue_id: Option<u32>,
    pub(crate) distribution_a_i: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) binding_distribution_a_i: Option<Vec<u32>>,
    pub(crate) cstruct_distribution_a_i: Vec<u32>,
    pub(crate) cstruct_adjusted_for_a_i_overcount: bool,
    pub(crate) rss_expectation: String,
    pub(crate) rss_expectation_pass: bool,
    pub(crate) rss_expectation_reason: String,
    pub(crate) max_worker_flow_share: f64,
    pub(crate) n_active: u32,
    pub(crate) n_total_workers: u32,
    pub(crate) cstruct: f64,
    pub(crate) observed_cov: f64,
    pub(crate) gap: f64,
    pub(crate) epsilon: f64,
    pub(crate) saturated: bool,
    /// True when Gate 3 (aggregate throughput) was ENFORCED for this run
    /// (operator passed --expect-saturation). False = aggregate leg is
    /// diagnostic-only for this run (V-3).
    pub(crate) aggregate_throughput_gate_enforced: bool,
    /// Required metric item 1 (per-flow throughput quantiles).
    pub(crate) per_flow_throughput_mbps: PerFlowThroughputQuantiles,
    /// Required metric item 12 (steady-state window timestamps).
    pub(crate) steady_state_window: SteadyStateWindow,
    /// Required metric item 6 (saturation determination time-series).
    pub(crate) saturation_series: SaturationSeries,
    pub(crate) aggregate_mbps: f64,
    pub(crate) iperf_retransmits: u64,
    pub(crate) iperf_reverse: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_cpu_host_total_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_cpu_host_user_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_cpu_host_system_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_cpu_remote_total_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_cpu_remote_user_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_cpu_remote_system_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_sender_cpu_total_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_sender_cpu_user_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iperf_sender_cpu_system_percent: Option<f64>,
    pub(crate) starved_flow_count: u32,
    /// Harness fail-fast guard result: sum(a_i) vs non-starved iperf streams.
    pub(crate) a_i_sum_check_ok: bool,
    pub(crate) a_i_sum: u32,
    pub(crate) iperf_non_starved_streams: u32,
    pub(crate) a_i_sum_under_tolerance: u32,
    pub(crate) a_i_sum_over_tolerance: u32,
    pub(crate) a_i_sum_tolerance: u32,
    /// PASS unless any gate fails.
    pub(crate) verdict: &'static str,
    pub(crate) failure_reasons: Vec<String>,
}

impl Report {
    pub(crate) fn passed(&self) -> bool {
        self.verdict == "PASS"
    }
}

pub(crate) fn emit(report: &Report, _args: &Args) {
    println!("{}", serde_json::to_string_pretty(report).unwrap());
}
