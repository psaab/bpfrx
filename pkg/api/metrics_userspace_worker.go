package api

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Prometheus emitters for the userspace dataplane's PER-WORKER runtime and
// COLD-PATH telemetry, plus the two label helpers they share.
// Split out of metrics_userspace.go for the #7700 modularity floor; this is a
// move, not a behaviour change.

// #869: emit per-worker busy/idle runtime counters from a cached
// ProcessStatus snapshot.
func (c *xpfCollector) emitWorkerRuntime(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, w := range status.WorkerRuntime {
		label := strconv.FormatUint(uint64(w.WorkerID), 10)
		toSecs := func(ns uint64) float64 { return float64(ns) / 1e9 }
		ch <- prometheus.MustNewConstMetric(c.workerWallSecs,
			prometheus.CounterValue, toSecs(w.WallNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerActiveSecs,
			prometheus.CounterValue, toSecs(w.ActiveNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerIdleSpinSecs,
			prometheus.CounterValue, toSecs(w.IdleSpinNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerIdleBlockSecs,
			prometheus.CounterValue, toSecs(w.IdleBlockNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerThreadCPUSecs,
			prometheus.CounterValue, toSecs(w.ThreadCPUNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerThreadCPUSecsLast60s,
			prometheus.GaugeValue, toSecs(w.ThreadCPUNS60s), label)
		ch <- prometheus.MustNewConstMetric(c.workerThreadCPUWindowSecs,
			prometheus.GaugeValue, toSecs(w.WindowNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerWorkLoops,
			prometheus.CounterValue, float64(w.WorkLoops), label)
		ch <- prometheus.MustNewConstMetric(c.workerIdleLoops,
			prometheus.CounterValue, float64(w.IdleLoops), label)
		ch <- prometheus.MustNewConstMetric(c.workerCoSQueueLeaseAcquireV8Calls,
			prometheus.CounterValue, float64(w.CoSQueueLeaseAcquireV8Calls), label)
		ch <- prometheus.MustNewConstMetric(c.workerCoSQueueLeaseAcquireV8GrantedBytes,
			prometheus.CounterValue, float64(w.CoSQueueLeaseAcquireV8GrantedBytes), label)
		// #1782 Step-1 cold-start CoS instruments. The wheel counters are
		// emitted unconditionally (always-present series keep rate() and
		// absence-alerts honest); the max is a monotonic high-water mark,
		// hence a gauge. The under-grant family emits all six causes per
		// worker so a cause appearing for the first time has a zero
		// baseline sample to rate() against.
		ch <- prometheus.MustNewConstMetric(c.workerCoSWheelTicksAdvancedTotal,
			prometheus.CounterValue, float64(w.CoSWheelTicksAdvancedTotal), label)
		ch <- prometheus.MustNewConstMetric(c.workerCoSWheelTicksAdvancedMax,
			prometheus.GaugeValue, float64(w.CoSWheelTicksAdvancedMax), label)
		for _, uc := range []struct {
			cause string
			value uint64
		}{
			{"seqlock_give_up", w.CoSQueueLeaseUndergrantSeqlockGiveUp},
			{"cap_zero", w.CoSQueueLeaseUndergrantCapZero},
			{"epoch_rotated", w.CoSQueueLeaseUndergrantEpochRotated},
			{"share_exhausted", w.CoSQueueLeaseUndergrantShareExhausted},
			{"class_cap", w.CoSQueueLeaseUndergrantClassCap},
			{"outstanding_cap", w.CoSQueueLeaseUndergrantOutstandingCap},
		} {
			ch <- prometheus.MustNewConstMetric(c.workerCoSQueueLeaseUndergrant,
				prometheus.CounterValue, float64(uc.value), label, uc.cause)
		}
		ch <- prometheus.MustNewConstMetric(c.workerSessionTableEntries,
			prometheus.GaugeValue, float64(w.SessionTableEntries), label)
		ch <- prometheus.MustNewConstMetric(c.workerSessionTableCapacity,
			prometheus.GaugeValue, float64(w.MaxSessions), label)
		ch <- prometheus.MustNewConstMetric(c.workerNatReverseKeyCollisions,
			prometheus.CounterValue, float64(w.NatReverseKeyCollisions), label)
		ch <- prometheus.MustNewConstMetric(c.workerNatReverseKeyCollisionsDistinctSrc,
			prometheus.CounterValue, float64(w.NatReverseKeyCollisionsDistinctSrc), label)
		// #1861: per-worker install-refusal trio.
		ch <- prometheus.MustNewConstMetric(c.workerSessionCreateDrops,
			prometheus.CounterValue, float64(w.SessionCreateDrops), label)
		ch <- prometheus.MustNewConstMetric(c.workerSessionInstallAdmissionRefused,
			prometheus.CounterValue, float64(w.SessionInstallAdmissionRefused), label)
		ch <- prometheus.MustNewConstMetric(c.workerSessionInstallPartial,
			prometheus.CounterValue, float64(w.SessionInstallPartial), label)
		// #4800: per-worker transit new-flow installs — the skew signal.
		ch <- prometheus.MustNewConstMetric(c.workerNewFlowInstalls,
			prometheus.CounterValue, float64(w.NewFlowInstalls), label)
		var deadValue float64
		if w.Dead {
			deadValue = 1
		}
		ch <- prometheus.MustNewConstMetric(c.workerDead,
			prometheus.GaugeValue, deadValue, label)
		// #1621: cold-path histogram surface (#1612 step-3).
		c.emitWorkerColdPath(ch, label, w)
	}
}

// #1621: emit the cold-path histogram metric families for one worker.
//
// Per plan v2:
//   - bucket counter family with PromQL `le` label so
//     histogram_quantile() works natively (Codex r1 F3 + AGY r1 F6 +
//     Claude SMR F5).
//   - sum_ns + samples counters per (worker, slot).
//   - alias_seen gauge per (worker, slot).
//   - per-worker scalars: sample_phase + wrapper_underflow (counters);
//     wrapper_ns_baseline + ns_per_tsc_q32 (gauges).
//   - clock_source gauge always emitted (Claude SMR r1 F4) so
//     dashboards distinguish "tsc active" from "no data this scrape".
//   - snapshot_failed_total counter (AGY r1 F3 + Codex r1 F5) so
//     operators detect publish-contention starvation.
func (c *xpfCollector) emitWorkerColdPath(
	ch chan<- prometheus.Metric,
	label string,
	w dpuserspace.WorkerRuntimeStatus,
) {
	// #1635: branch on the wire layout version. 0 (or absent) = either
	// no data this scrape OR a pre-#1635 daemon emitting the v1 dense
	// fields; 3 = sparse log-linear per-zone-pair encoding; anything
	// else = forward-compat unknown.
	switch w.ColdPathLayoutVersion {
	case 0, 1:
		c.emitColdPathV1(ch, label, w)
	case 3:
		c.emitColdPathV3(ch, label, w)
		ch <- prometheus.MustNewConstMetric(c.workerColdPathLayoutVersion,
			prometheus.GaugeValue, 1.0, label, "3")
	default:
		ch <- prometheus.MustNewConstMetric(c.workerColdPathLayoutUnknownTotal,
			prometheus.GaugeValue, 1.0, label,
			strconv.FormatUint(uint64(w.ColdPathLayoutVersion), 10))
	}
	c.emitWorkerColdPathScalars(ch, label, w)
}

// emitColdPathV1 emits the legacy 24-bucket pow-2 per-slot metrics from
// the dense v1 fields. Reached only when paired with a pre-#1635 Rust
// daemon (current daemons leave the dense fields empty and emit v3).
func (c *xpfCollector) emitColdPathV1(
	ch chan<- prometheus.Metric,
	label string,
	w dpuserspace.WorkerRuntimeStatus,
) {
	// 24-bucket power-of-two histogram. Bucket 0 covers [0, 1024) ns;
	// bucket i ∈ [1, 22] covers [2^(9+i), 2^(10+i)) ns; bucket 23
	// saturates at any ns ≥ 2^32.
	bucketLe := func(idx int) string {
		if idx == 0 {
			return "1023"
		}
		if idx >= 23 || (10+idx) >= 64 {
			return "+Inf"
		}
		return strconv.FormatUint((uint64(1)<<uint(10+idx))-1, 10)
	}
	for slot := 0; slot < len(w.ColdPathHist); slot++ {
		slotLabel := strconv.Itoa(slot)
		var running uint64
		for b := 0; b < len(w.ColdPathHist[slot]); b++ {
			running += w.ColdPathHist[slot][b]
			ch <- prometheus.MustNewConstMetric(c.workerColdPathBucket,
				prometheus.CounterValue,
				float64(running),
				label, slotLabel, bucketLe(b))
		}
	}
	for slot, samples := range w.ColdPathSamples {
		slotLabel := strconv.Itoa(slot)
		ch <- prometheus.MustNewConstMetric(c.workerColdPathSamples,
			prometheus.CounterValue, float64(samples), label, slotLabel)
		if slot < len(w.ColdPathSumNS) {
			ch <- prometheus.MustNewConstMetric(c.workerColdPathSumNS,
				prometheus.CounterValue,
				float64(w.ColdPathSumNS[slot]),
				label, slotLabel)
		}
		if slot < len(w.ColdPathAliasSeen) {
			alias := 0.0
			if w.ColdPathAliasSeen[slot] {
				alias = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.workerColdPathAliasSeen,
				prometheus.GaugeValue, alias, label, slotLabel)
		}
	}
}

// emitColdPathV3 emits the #1635 sparse per-zone-pair metrics. The
// payload is parallel arrays (one entry per active zone-pair); the
// `from_zone` / `to_zone` labels carry the zone-ids so every active
// pair publishes a SEPARABLE latency distribution with no collision
// exclusion (fixes #1622 F2 + F3). `le` boundaries follow the
// 48-bucket log-linear layout (bucketLeV3).
func (c *xpfCollector) emitColdPathV3(
	ch chan<- prometheus.Metric,
	label string,
	w dpuserspace.WorkerRuntimeStatus,
) {
	n := len(w.ColdPathActiveSamples)
	for i := 0; i < n; i++ {
		fromZone := zoneIDLabel(w.ColdPathActiveZoneFrom, i)
		toZone := zoneIDLabel(w.ColdPathActiveZoneTo, i)
		// Cumulative bucket counts for histogram_quantile().
		if i < len(w.ColdPathActiveBuckets) {
			var running uint64
			buckets := w.ColdPathActiveBuckets[i]
			for b := 0; b < len(buckets); b++ {
				running += buckets[b]
				ch <- prometheus.MustNewConstMetric(c.workerColdPathBucketV3,
					prometheus.CounterValue, float64(running),
					label, fromZone, toZone, bucketLeV3(b))
			}
		}
		ch <- prometheus.MustNewConstMetric(c.workerColdPathSamplesV3,
			prometheus.CounterValue, float64(w.ColdPathActiveSamples[i]),
			label, fromZone, toZone)
		if i < len(w.ColdPathActiveSumNS) {
			ch <- prometheus.MustNewConstMetric(c.workerColdPathSumNSV3,
				prometheus.CounterValue, float64(w.ColdPathActiveSumNS[i]),
				label, fromZone, toZone)
		}
		if i < len(w.ColdPathActiveBuilderCollision) {
			col := 0.0
			if w.ColdPathActiveBuilderCollision[i] {
				col = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.workerColdPathBuilderCollisionV3,
				prometheus.GaugeValue, col, label, fromZone, toZone)
		}
	}
	overflow := 0.0
	if w.ColdPathOverflowActive {
		overflow = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.workerColdPathOverflowActive,
		prometheus.GaugeValue, overflow, label)
}

// emitWorkerColdPathScalars emits the per-worker scalar families shared
// across all layout versions.
func (c *xpfCollector) emitWorkerColdPathScalars(
	ch chan<- prometheus.Metric,
	label string,
	w dpuserspace.WorkerRuntimeStatus,
) {
	// Per-worker scalars.
	ch <- prometheus.MustNewConstMetric(c.workerColdPathSamplePhase,
		prometheus.CounterValue,
		float64(w.ColdPathSamplePhase), label)
	ch <- prometheus.MustNewConstMetric(c.workerColdPathWrapperUnderflow,
		prometheus.CounterValue,
		float64(w.ColdPathWrapperUnderflowCount), label)
	ch <- prometheus.MustNewConstMetric(c.workerColdPathWrapperNSBaseline,
		prometheus.GaugeValue,
		float64(w.ColdPathWrapperNSBaseline), label)
	ch <- prometheus.MustNewConstMetric(c.workerColdPathNSPerTSCQ32,
		prometheus.GaugeValue,
		float64(w.ColdPathNSPerTSCQ32), label)
	// clock_source gauge ALWAYS emitted (Claude SMR r1 F4): even
	// when the worker is uncalibrated (source == ""), so dashboards
	// can distinguish "tsc active" from "no data this scrape".
	src := w.ColdPathClockSource
	if src == "" {
		src = "unset"
	}
	ch <- prometheus.MustNewConstMetric(c.workerColdPathClockSource,
		prometheus.GaugeValue, 1.0, label, src)
	// snapshot_failed counter always emitted so operators can detect
	// transient publish-contention starvation.
	ch <- prometheus.MustNewConstMetric(c.workerColdPathSnapshotFailedTotal,
		prometheus.CounterValue,
		float64(w.ColdPathSnapshotFailed), label)
}

// bucketLeV3 returns the inclusive upper boundary (Prometheus `le`
// label) for #1635 48-bucket log-linear histogram bucket idx:
//   - idx < 32        → (idx+1)*16 - 1   (15, 31, …, 511) — linear band.
//   - 32 ≤ idx ≤ 46   → 2^(10+idx-32) - 1 (1023, 2047, …) — exp band.
//   - idx ≥ 47        → "+Inf"            — saturate band.
//
// Mirrors bucket_upper_bound_ns_48 / bucket_index_for_ns_48 on the Rust
// side; the two MUST agree or histogram_quantile() reads wrong values.
func bucketLeV3(idx int) string {
	const linear = 32
	if idx < linear {
		return strconv.FormatUint(uint64((idx+1)*16-1), 10)
	}
	if idx >= 47 {
		return "+Inf"
	}
	return strconv.FormatUint((uint64(1)<<uint(10+idx-linear))-1, 10)
}

// zoneIDLabel renders the i-th zone-id of a parallel sparse array as a
// label string, or "unknown" if the array is too short (defensive
// against a truncated/mismatched payload).
func zoneIDLabel(ids []uint32, i int) string {
	if i >= len(ids) {
		return "unknown"
	}
	return strconv.FormatUint(uint64(ids[i]), 10)
}
