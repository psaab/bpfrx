package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initColdPathDescriptors() {
	c.workerDead = prometheus.NewDesc(
		"xpf_userspace_worker_dead",
		"1 if the userspace-dp worker thread has panicked and been "+
			"caught by the supervisor; 0 otherwise. Cleared only by "+
			"daemon restart in Phase 1 (#925).",
		[]string{"worker_id"}, nil,
	)
	// === #1621 cold-path histogram surface ===
	c.workerColdPathBucket = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_ns_bucket",
		"Cumulative cold-path policy-eval latency observations per "+
			"worker / zone-pair-slot, bucketed into the #1619 24-bucket "+
			"power-of-two ns histogram. Compatible with PromQL "+
			"histogram_quantile() via the `le` label (#1612 step-3).",
		[]string{"worker_id", "zone_pair_slot", "le"}, nil,
	)
	c.workerColdPathSamples = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_samples_total",
		"Per-worker / zone-pair-slot count of cold-path latency "+
			"samples actually recorded (post sample-mask gate + post "+
			"q32-skip). Use as the denominator for actual sampling rate.",
		[]string{"worker_id", "zone_pair_slot"}, nil,
	)
	c.workerColdPathSumNS = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_sum_ns_total",
		"Per-worker / zone-pair-slot cumulative sum of recorded "+
			"delta_ns values (post baseline subtraction).",
		[]string{"worker_id", "zone_pair_slot"}, nil,
	)
	c.workerColdPathAliasSeen = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_alias_seen",
		"1 if this zone-pair-slot saw two different packed "+
			"(from_zone, to_zone) keys during the current publish "+
			"window — the harness excludes aliased slots from Scale "+
			"Target tables. 0 otherwise.",
		[]string{"worker_id", "zone_pair_slot"}, nil,
	)
	c.workerColdPathSamplePhase = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_sample_phase_total",
		"Per-worker monotonic count of eligible cold-path sampling "+
			"attempts. Increment on every session-miss pass through "+
			"the policy-eval pre-eval gate. Denominator for "+
			"actual_sampling_rate = sum(samples[]) / sample_phase.",
		[]string{"worker_id"}, nil,
	)
	c.workerColdPathWrapperUnderflow = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_wrapper_underflow_count_total",
		"Per-worker monotonic count of samples where raw_ns < "+
			"wrapper_ns_baseline. Indicates baseline drift "+
			"(frequency scaling, OoO jitter, ultra-fast policy_eval).",
		[]string{"worker_id"}, nil,
	)
	c.workerColdPathWrapperNSBaseline = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_wrapper_ns_baseline",
		"Calibrated cost of the sample_tsc_start + sample_tsc_end "+
			"fence pair, measured once per worker post pthread "+
			"affinity at startup. Subtracted from every recorded "+
			"delta_ns on the hot path.",
		[]string{"worker_id"}, nil,
	)
	c.workerColdPathNSPerTSCQ32 = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_ns_per_tsc_q32",
		"Q32 fixed-point ns_per_tsc multiplier from worker startup "+
			"calibration. 0 when TSC unavailable. Operators compare "+
			"across workers to detect calibration anomalies.",
		[]string{"worker_id"}, nil,
	)
	c.workerColdPathClockSource = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_clock_source",
		"1 when this worker's clock source has the value of the "+
			"`source` label. Operators gate Scale Target table "+
			"publication on every worker reporting source='tsc'. "+
			"Always emitted (uncalibrated workers report "+
			"source='unset').",
		[]string{"worker_id", "source"}, nil,
	)
	c.workerColdPathSnapshotFailedTotal = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_snapshot_failed_total",
		"Per-worker monotonic count of snapshot() calls at the "+
			"coordinator status path that exhausted their retry "+
			"budget (publish contention / scheduler preemption). "+
			"Distinguishes 'no data this scrape' from 'transient "+
			"starvation'.",
		[]string{"worker_id"}, nil,
	)
	// === #1635 sparse v3 per-zone-pair cold-path families ===
	c.workerColdPathBucketV3 = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_ns_bucket_v3",
		"Cumulative cold-path policy-eval latency observations per "+
			"worker / (from_zone, to_zone), bucketed into the #1635 "+
			"48-bucket log-linear ns histogram (32 linear 16-ns "+
			"buckets over [0,512) ns + 15 pow-2 buckets + saturate). "+
			"Compatible with PromQL histogram_quantile() via `le`.",
		[]string{"worker_id", "from_zone", "to_zone", "le"}, nil,
	)
	c.workerColdPathSamplesV3 = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_samples_v3_total",
		"Per-worker / (from_zone, to_zone) count of cold-path latency "+
			"samples recorded (#1635 direct slot map).",
		[]string{"worker_id", "from_zone", "to_zone"}, nil,
	)
	c.workerColdPathSumNSV3 = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_sum_ns_v3_total",
		"Per-worker / (from_zone, to_zone) cumulative sum of recorded "+
			"delta_ns (post baseline subtraction).",
		[]string{"worker_id", "from_zone", "to_zone"}, nil,
	)
	c.workerColdPathBuilderCollisionV3 = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_builder_collision_v3",
		"1 if this (from_zone, to_zone) slot saw two distinct packed "+
			"keys — a snapshot-builder bug with the #1635 direct slot "+
			"map; should always be 0. 0 otherwise.",
		[]string{"worker_id", "from_zone", "to_zone"}, nil,
	)
	c.workerColdPathOverflowActive = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_overflow_active",
		"1 if a configured zone-pair could not be assigned a cold-path "+
			"histogram slot — either the 255-slot capacity was "+
			"exhausted OR the pair references a zone-id outside the "+
			"0..=64 direct-table range. 0 otherwise.",
		[]string{"worker_id"}, nil,
	)
	c.workerColdPathLayoutVersion = prometheus.NewDesc(
		"xpf_userspace_worker_cold_path_layout_version",
		"1 when this worker's cold-path wire layout has the value of "+
			"the `version` label (#1635: 3 = sparse log-linear).",
		[]string{"worker_id", "version"}, nil,
	)
	c.workerColdPathLayoutUnknownTotal = prometheus.NewDesc(
		// Gauge-style state indicator (NOT a counter): emitted as a
		// GaugeValue=1 when the version is unknown, so the name must
		// NOT end in `_total` (Copilot code-r4: a `_total` suffix
		// would mislead operators into rate()-ing a state flag).
		"xpf_userspace_worker_cold_path_layout_version_unknown",
		"1 when this worker reported a cold-path wire layout version "+
			"the collector does not understand (forward-compat guard).",
		[]string{"worker_id", "version"}, nil,
	)
}
