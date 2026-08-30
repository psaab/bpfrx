use std::collections::BTreeMap;

use super::inputs::Iperf3Output;

#[cfg_attr(test, derive(Debug))]
pub(crate) struct Window {
    pub(crate) per_stream_buckets: BTreeMap<u64, Vec<u64>>,
    pub(crate) aggregate_buckets_bps: Vec<u64>,
    /// Per-stream window-mean throughput (bytes/sec) over the ACTIVE flow
    /// set only — streams that produced no steady-state samples are
    /// dropped. This feeds the observed-CoV / Gate-2 input, whose
    /// contract is defined over the active flow set (a starved flow is
    /// caught by Gate 1, not folded into the CoV).
    pub(crate) per_flow_throughputs: Vec<u64>,
    /// Per-stream window-mean throughput (bytes/sec) over EVERY seeded
    /// stream, mapping a stream absent from the steady window to 0. This
    /// is the FULL iperf stream set (seeded from `start.connected[]`),
    /// so the V-9 required per-flow quantiles + stream_count include
    /// starved-at-0 flows rather than silently undercounting them — a
    /// starved flow at 0 Mb/s is exactly the fairness violation a failing
    /// run's per-flow distribution must surface.
    pub(crate) per_flow_throughputs_all: Vec<u64>,
}

pub(crate) fn extract_window(
    iperf: &Iperf3Output,
    warmup_secs: u64,
    final_burst_secs: u64,
) -> Result<Window, String> {
    // Determine the steady-state window: skip first warmup_secs and
    // last final_burst_secs of iperf3 intervals.
    let total_dur = iperf.start.test_start.duration;
    if total_dur <= warmup_secs + final_burst_secs {
        return Err(format!(
            "test duration {total_dur}s ≤ warmup {warmup_secs} + final-burst {final_burst_secs}"
        ));
    }
    let ss_dur = total_dur - warmup_secs - final_burst_secs;
    // The fairness contract requires a ≥60s steady-state window to
    // produce a statistically meaningful CoV measurement. Shorter
    // runs would give a verdict on too few per-second buckets.
    const MIN_STEADY_STATE_SECS: u64 = 60;
    // Boundary/jitter slack for the OBSERVED-sample check below: a run
    // whose declared window is exactly the minimum can lose a bucket or
    // two to mid-point boundary exclusion and sub-second interval
    // alignment.
    const STEADY_STATE_SAMPLE_SLACK_SECS: u64 = 5;
    if ss_dur < MIN_STEADY_STATE_SECS {
        return Err(format!(
            "steady-state window {ss_dur}s < {MIN_STEADY_STATE_SECS}s minimum; use a longer -t or reduce --warmup-secs/--final-burst-secs"
        ));
    }
    let ss_start = warmup_secs as f64;
    let ss_end = (total_dur - final_burst_secs) as f64;

    // Per-stream per-bucket throughput in bytes/sec. Seed the map from
    // `start.connected[]` so streams that contributed zero throughput
    // for the entire steady-state window are still represented (with
    // an empty bucket vec) and correctly counted as starved by
    // starved_flow_count. Without this seeding, streams that sent no
    // data after warmup are silently invisible — Codex round-1+round-2
    // finding #1.
    let mut per_stream_buckets: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for c in &iperf.start.connected {
        per_stream_buckets.entry(c.socket).or_default();
    }
    let mut aggregate_buckets_bps: Vec<u64> = Vec::new();

    for interval in &iperf.intervals {
        // Skip iperf3 `-O` omitted (warmup) intervals; they are not
        // steady-state data (V-7). The harness does not pass -O today,
        // but fairness-eval is a general CLI and must not fold omitted
        // buckets into the CoV window.
        if interval.sum.omitted {
            continue;
        }
        let mut iv_start = f64::INFINITY;
        let mut iv_end = f64::NEG_INFINITY;
        let mut iv_total_bps = 0.0_f64;
        for s in &interval.streams {
            iv_start = iv_start.min(s.start);
            iv_end = iv_end.max(s.end);
            iv_total_bps += s.bits_per_second;
        }
        let mid = (iv_start + iv_end) * 0.5;
        if mid < ss_start || mid >= ss_end {
            continue;
        }
        for s in &interval.streams {
            let bytes = (s.bits_per_second / 8.0) as u64;
            per_stream_buckets.entry(s.socket).or_default().push(bytes);
        }
        aggregate_buckets_bps.push(iv_total_bps as u64);
    }

    // Reject on OBSERVED sample coverage, not the self-reported duration
    // (V-7). A truncated JSON that DECLARES a long run but carries only a
    // handful of non-omitted intervals would otherwise pass the
    // declared-duration gate above and produce a CoV from a few buckets.
    // The contract requires such runs be rejected with an explicit error.
    let observed_buckets = aggregate_buckets_bps.len() as u64;
    if observed_buckets + STEADY_STATE_SAMPLE_SLACK_SECS < MIN_STEADY_STATE_SECS {
        return Err(format!(
            "observed {observed_buckets} in-window 1s buckets < {MIN_STEADY_STATE_SECS}s minimum \
             (declared duration {total_dur}s, but the iperf JSON carries too few non-omitted \
             intervals — truncated or heavily-omitted run); a meaningful CoV needs a full \
             steady-state window"
        ));
    }

    // Per-stream window-mean throughput for the per-flow CoV input.
    //
    // #7206 A1-b5-F3: the divisor is the WINDOW's accepted-interval count, not
    // the count of intervals THIS stream happened to appear in.
    //
    // Dividing by `v.len()` scored a stream present in 1 of 60 accepted
    // intervals at its FULL instantaneous rate, because its single sample was
    // its own mean. A near-total outage therefore produced per-flow
    // throughputs that all looked equal, a CoV near 0, and a PASS on the CoS
    // fairness gate -- a false PASS that can carry a merge decision, which is
    // the reason this row is worth more than its LOW severity label.
    //
    // Dividing by the window count makes an absent interval contribute 0 to
    // that stream's mean, which is the same "absent == 0, don't drop"
    // principle `per_flow_throughputs_all` below applies to fully-absent
    // streams. The two are now consistent about what absence means; they
    // differ only in WHICH absence they cover, which is the documented V-9
    // split.
    //
    // The `!v.is_empty()` filter is deliberately KEPT. A stream absent from
    // EVERY accepted interval is `per_flow_throughputs_all`'s case by the V-9
    // contract, and folding it in here would change the per-flow CoV
    // population as well as the divisor -- two changes wearing one commit.
    //
    // observed_buckets is >= 1 here: the coverage gate above returns Err when
    // it is below MIN_STEADY_STATE_SECS - STEADY_STATE_SAMPLE_SLACK_SECS, so
    // this cannot divide by zero.
    let per_flow_throughputs: Vec<u64> = per_stream_buckets
        .values()
        .filter(|v| !v.is_empty())
        .map(|v| {
            let sum: u64 = v.iter().sum();
            sum / observed_buckets
        })
        .collect();

    // Full-stream-set variant for the V-9 required metric: every seeded
    // stream contributes, with an empty (absent-from-window) stream
    // counted as 0 rather than dropped. Mirrors the V-5 "absent == 0,
    // don't drop" principle so the per-flow quantiles + stream_count
    // reflect the true iperf stream set including starved flows.
    let per_flow_throughputs_all: Vec<u64> = per_stream_buckets
        .values()
        .map(|v| {
            if v.is_empty() {
                0
            } else {
                v.iter().sum::<u64>() / v.len() as u64
            }
        })
        .collect();

    Ok(Window {
        per_stream_buckets,
        aggregate_buckets_bps,
        per_flow_throughputs,
        per_flow_throughputs_all,
    })
}

#[cfg(test)]
mod tests {
    use super::super::inputs::{
        Iperf3Interval, Iperf3IntervalSum, Iperf3Output, Iperf3Start, Iperf3StreamInterval,
        Iperf3TestStart, Iperf3Timestamp,
    };
    use super::extract_window;

    fn interval(socket: u64, start: f64, bps: f64, omitted: bool) -> Iperf3Interval {
        Iperf3Interval {
            streams: vec![Iperf3StreamInterval {
                socket,
                start,
                end: start + 1.0,
                bits_per_second: bps,
            }],
            sum: Iperf3IntervalSum { omitted },
        }
    }

    fn output(duration: u64, intervals: Vec<Iperf3Interval>) -> Iperf3Output {
        Iperf3Output {
            start: Iperf3Start {
                connected: vec![],
                timestamp: Iperf3Timestamp { timesecs: 0 },
                test_start: Iperf3TestStart {
                    duration,
                    num_streams: 1,
                    reverse: 0,
                },
            },
            intervals,
            end: None,
        }
    }

    #[test]
    fn extract_window_skips_omitted_intervals() {
        // V-7: 65 one-second intervals, first 5 flagged omitted. With
        // warmup 0 / final-burst 0 all 65 mid-points fall in [0, 65), but
        // the 5 omitted intervals must not contribute buckets — leaving
        // exactly 60 steady-state buckets.
        let mut intervals = Vec::new();
        for i in 0..65u64 {
            intervals.push(interval(5, i as f64, 1.0e9, i < 5));
        }
        let iperf = output(65, intervals);
        let w = extract_window(&iperf, 0, 0).expect("window");
        assert_eq!(
            w.aggregate_buckets_bps.len(),
            60,
            "omitted intervals must be filtered from the steady-state window"
        );
    }

    #[test]
    fn extract_window_rejects_truncated_interval_set() {
        // V-7: declared 120s clears the ss_dur>=60 declared gate, but
        // only 10 non-omitted intervals are present → observed buckets
        // far below the 60s minimum → explicit reject.
        let mut intervals = Vec::new();
        for i in 0..10u64 {
            intervals.push(interval(5, i as f64, 1.0e9, false));
        }
        let iperf = output(120, intervals);
        let err = extract_window(&iperf, 0, 0).expect_err("truncated run must be rejected");
        assert!(
            err.contains("buckets"),
            "error must cite the observed bucket count: {err}"
        );
    }

    /// One interval carrying MULTIPLE streams, so a per-stream density gap can
    /// be modelled. The single-socket `interval` helper above cannot express
    /// "socket A present, socket B absent" in the same interval, which is the
    /// only shape that reproduces #7206 A1-b5-F3.
    fn multi_interval(entries: &[(u64, f64)], start: f64, omitted: bool) -> Iperf3Interval {
        Iperf3Interval {
            streams: entries
                .iter()
                .map(|(socket, bps)| Iperf3StreamInterval {
                    socket: *socket,
                    start,
                    end: start + 1.0,
                    bits_per_second: *bps,
                })
                .collect(),
            sum: Iperf3IntervalSum { omitted },
        }
    }

    /// #7206 A1-b5-F3 fail-on-revert: a stream present in ONE of sixty accepted
    /// intervals must not be scored at its full instantaneous rate.
    ///
    /// Dividing by the stream's own sample count made its single sample its own
    /// mean, so a near-total outage produced per-flow throughputs that all
    /// looked equal, a CoV near zero, and a PASS on the CoS fairness gate. That
    /// is a FALSE PASS that can carry a merge decision, which is why this row
    /// is worth more than its LOW severity label.
    ///
    /// The assertion is on the RATIO, not on an absolute number: what the fix
    /// establishes is that a 1-of-60 stream scores about 1/60 of a
    /// continuously-present stream at the same instantaneous rate. Pinning a
    /// byte count instead would break on any unrelated change to the window
    /// bounds and would not say what went wrong.
    ///
    /// Revert `sum / observed_buckets` to `sum / v.len() as u64` and the two
    /// means become EQUAL, which is exactly the defect.
    #[test]
    fn extract_window_scores_a_one_of_sixty_stream_by_the_window_7206() {
        const RATE: f64 = 1.0e9;
        let mut intervals = Vec::new();
        for i in 0..60u64 {
            if i == 0 {
                // Socket 7 appears ONCE, at the same instantaneous rate as the
                // always-present socket 5.
                intervals.push(multi_interval(&[(5, RATE), (7, RATE)], i as f64, false));
            } else {
                intervals.push(multi_interval(&[(5, RATE)], i as f64, false));
            }
        }
        let iperf = output(60, intervals);
        let w = extract_window(&iperf, 0, 0).expect("window");

        assert_eq!(
            w.aggregate_buckets_bps.len(),
            60,
            "precondition: the window must hold 60 accepted intervals, or the \
             1-of-60 ratio below is not the ratio being asserted"
        );
        assert_eq!(
            w.per_flow_throughputs.len(),
            2,
            "precondition: both streams must reach the per-flow CoV input; if the \
             sparse stream were dropped the assertion below would compare one \
             stream against itself"
        );

        let mut means = w.per_flow_throughputs.clone();
        means.sort_unstable();
        let (sparse, dense) = (means[0], means[1]);
        assert!(
            sparse * 10 < dense,
            "a stream present in 1 of 60 accepted intervals scored {sparse} against \
             the always-present stream's {dense} at the SAME instantaneous rate. \
             Its single sample was taken as its own mean, so a near-total outage \
             yields a CoV near zero and the CoS fairness gate PASSES on it \
             (#7206 A1-b5-F3)"
        );
    }

    /// CONTROL. Two streams that are BOTH continuously present at the same rate
    /// must still score equal. Without this, a "fix" that scored every stream
    /// at 1/60 would satisfy the cell above and destroy every real comparison.
    #[test]
    fn extract_window_scores_equally_present_streams_equally_7206() {
        const RATE: f64 = 1.0e9;
        let mut intervals = Vec::new();
        for i in 0..60u64 {
            intervals.push(multi_interval(&[(5, RATE), (7, RATE)], i as f64, false));
        }
        let iperf = output(60, intervals);
        let w = extract_window(&iperf, 0, 0).expect("window");
        assert_eq!(w.per_flow_throughputs.len(), 2);
        assert_eq!(
            w.per_flow_throughputs[0], w.per_flow_throughputs[1],
            "two continuously-present streams at the same rate must score equally; \
             a divisor change must not perturb the ordinary case"
        );
    }
}
