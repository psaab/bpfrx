package api

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func newCollector(srv *Server) *xpfCollector {
	return &xpfCollector{
		srv: srv,

		packetsTotal: prometheus.NewDesc(
			"xpf_packets_total",
			"Total packets processed.",
			[]string{"direction"}, nil,
		),
		dropsTotal: prometheus.NewDesc(
			"xpf_drops_total",
			"Total packets dropped.",
			nil, nil,
		),
		sessionsCreatedTotal: prometheus.NewDesc(
			"xpf_sessions_created_total",
			"Total sessions created.",
			nil, nil,
		),
		sessionsClosedTotal: prometheus.NewDesc(
			"xpf_sessions_closed_total",
			"Total sessions closed.",
			nil, nil,
		),
		screenDropsTotal: prometheus.NewDesc(
			"xpf_screen_drops_total",
			"Total packets dropped by screen/IDS checks.",
			nil, nil,
		),
		policyDeniesTotal: prometheus.NewDesc(
			"xpf_policy_denies_total",
			"Total packets denied by policy.",
			nil, nil,
		),
		natAllocFailsTotal: prometheus.NewDesc(
			"xpf_nat_alloc_failures_total",
			"Total NAT port allocation failures.",
			nil, nil,
		),
		hostInboundDeny: prometheus.NewDesc(
			"xpf_host_inbound_denies_total",
			"Total host-inbound traffic denials.",
			nil, nil,
		),
		tcEgressPacketsTotal: prometheus.NewDesc(
			"xpf_tc_egress_packets_total",
			"Total TC egress packets processed.",
			nil, nil,
		),
		syncookieTotal: prometheus.NewDesc(
			"xpf_screen_syncookie_total",
			"SYN cookie counters by type.",
			[]string{"type"}, nil,
		),
		flowCacheTotal: prometheus.NewDesc(
			"xpf_flow_cache_total",
			"Flow cache counters by type (IPv4 + IPv6).",
			[]string{"type"}, nil,
		),
		ifacePacketsTotal: prometheus.NewDesc(
			"xpf_interface_packets_total",
			"Total packets per interface.",
			[]string{"iface", "direction"}, nil,
		),
		ifaceBytesTotal: prometheus.NewDesc(
			"xpf_interface_bytes_total",
			"Total bytes per interface.",
			[]string{"iface", "direction"}, nil,
		),
		zonePacketsTotal: prometheus.NewDesc(
			"xpf_zone_packets_total",
			"Total packets per zone.",
			[]string{"zone", "direction"}, nil,
		),
		zoneBytesTotal: prometheus.NewDesc(
			"xpf_zone_bytes_total",
			"Total bytes per zone.",
			[]string{"zone", "direction"}, nil,
		),
		policyHitsTotal: prometheus.NewDesc(
			"xpf_policy_hits_total",
			"Total policy rule hits.",
			[]string{"from_zone", "to_zone", "rule"}, nil,
		),
		filterHitsTotal: prometheus.NewDesc(
			"xpf_filter_hits_total",
			"Total firewall filter term hits.",
			[]string{"filter", "family", "term"}, nil,
		),
		threeColorPolicerPacketsTotal: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_packets_total",
			"Userspace three-color policer packets by resulting color.",
			[]string{"policer", "color"}, nil,
		),
		threeColorPolicerBytesTotal: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_bytes_total",
			"Userspace three-color policer bytes by resulting color.",
			[]string{"policer", "color"}, nil,
		),
		threeColorPolicerDropsTotal: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_drops_total",
			"Userspace three-color policer packets dropped by policer treatment.",
			[]string{"policer"}, nil,
		),
		threeColorPolicerDropBytes: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_drop_bytes_total",
			"Userspace three-color policer bytes dropped by policer treatment.",
			[]string{"policer"}, nil,
		),
		sessionsActive: prometheus.NewDesc(
			"xpf_sessions_active",
			"Current number of active session entries.",
			nil, nil,
		),
		sessionsEstablished: prometheus.NewDesc(
			"xpf_sessions_established",
			"Current number of established sessions.",
			nil, nil,
		),
		sessionsIPv4: prometheus.NewDesc(
			"xpf_sessions_ipv4",
			"Current number of IPv4 sessions.",
			nil, nil,
		),
		sessionsIPv6: prometheus.NewDesc(
			"xpf_sessions_ipv6",
			"Current number of IPv6 sessions.",
			nil, nil,
		),
		sessionsSNAT: prometheus.NewDesc(
			"xpf_sessions_snat",
			"Current number of SNAT sessions.",
			nil, nil,
		),
		sessionsDNAT: prometheus.NewDesc(
			"xpf_sessions_dnat",
			"Current number of DNAT sessions.",
			nil, nil,
		),
		gcSweepDuration: prometheus.NewDesc(
			"xpf_gc_sweep_duration_seconds",
			"Duration of the last GC sweep in seconds.",
			nil, nil,
		),
		natPoolUsedPorts: prometheus.NewDesc(
			"xpf_nat_pool_used_ports",
			"Number of used ports in a NAT pool.",
			[]string{"pool"}, nil,
		),
		natPoolTotalPorts: prometheus.NewDesc(
			"xpf_nat_pool_total_ports",
			"Total available ports in a NAT pool.",
			[]string{"pool"}, nil,
		),
		natPoolDeterministicInfo: prometheus.NewDesc(
			"xpf_nat_pool_deterministic_info",
			"Deterministic NAT pool configuration (1 = enabled).",
			[]string{"pool", "block_size", "host_count"}, nil,
		),
		userspaceSNATPoolLiveFlows: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_live_flows",
			"Live source NAT pool flow allocations tracked by the userspace dataplane.",
			[]string{"pool", "rule"}, nil,
		),
		userspaceSNATPoolUsedPorts: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_used_ports",
			"Source NAT pool translated ports currently owned by the userspace dataplane allocator.",
			[]string{"pool", "rule"}, nil,
		),
		userspaceSNATPoolPersistentLeases: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_persistent_leases",
			"Persistent source NAT leases retained by the userspace dataplane allocator.",
			[]string{"pool", "rule"}, nil,
		),
		userspaceSNATPoolAllocationsTotal: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_allocations_total",
			"Total new source NAT pool translated tuple allocations by the userspace dataplane.",
			[]string{"pool", "rule"}, nil,
		),
		userspaceSNATPoolReusesTotal: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_reuses_total",
			"Total source NAT pool live or persistent lease reuses by the userspace dataplane.",
			[]string{"pool", "rule"}, nil,
		),
		userspaceSNATPoolExhaustionsTotal: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_exhaustions_total",
			"Total source NAT pool allocator exhaustion events in the userspace dataplane.",
			[]string{"pool", "rule"}, nil,
		),
		dhcpLeasesActive: prometheus.NewDesc(
			"xpf_dhcp_leases_active",
			"Number of active DHCP leases.",
			[]string{"family"}, nil,
		),

		sysCPUUser: prometheus.NewDesc(
			"xpf_system_cpu_user_percent",
			"User CPU utilization percentage.",
			nil, nil,
		),
		sysCPUSystem: prometheus.NewDesc(
			"xpf_system_cpu_system_percent",
			"System CPU utilization percentage.",
			nil, nil,
		),
		sysMemTotal: prometheus.NewDesc(
			"xpf_system_memory_total_bytes",
			"Total system memory in bytes.",
			nil, nil,
		),
		sysMemAvail: prometheus.NewDesc(
			"xpf_system_memory_available_bytes",
			"Available system memory in bytes.",
			nil, nil,
		),
		daemonUptime: prometheus.NewDesc(
			"xpf_daemon_uptime_seconds",
			"Daemon uptime in seconds.",
			nil, nil,
		),
		daemonMemRSS: prometheus.NewDesc(
			"xpf_daemon_memory_rss_bytes",
			"Daemon resident set size in bytes.",
			nil, nil,
		),

		// #709: owner-profile telemetry. Labels:
		//   ifindex:      interface ifindex as string
		//   queue_id:     CoS queue id 0-255
		//   bucket_hi_ns: upper bound of the histogram bucket (ns),
		//                 formatted as the power-of-two.
		// The histogram metrics are counters (monotonic bucket counts
		// in the Rust dataplane); owner/peer pps are gauges since the
		// Rust side re-uses them across the window.
		cosDrainLatencyBucket: prometheus.NewDesc(
			"xpf_cos_drain_latency_ns_bucket",
			"CoS owner-drain latency histogram — power-of-two ns buckets (#709).",
			[]string{"ifindex", "queue_id", "bucket_hi_ns"}, nil,
		),
		cosDrainInvocationsTotal: prometheus.NewDesc(
			"xpf_cos_drain_invocations_total",
			"Total CoS owner-drain invocations per (ifindex, queue_id) (#709).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosRedirectAcquireBucket: prometheus.NewDesc(
			"xpf_cos_redirect_acquire_ns_bucket",
			"CoS redirect-acquire latency histogram — power-of-two ns buckets, sampled 1-in-256 (#709).",
			[]string{"ifindex", "queue_id", "bucket_hi_ns"}, nil,
		),
		cosOwnerPPS: prometheus.NewDesc(
			"xpf_cos_owner_pps",
			"CoS owner-local pps (window accumulator, cleared by operator) (#709).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosPeerPPS: prometheus.NewDesc(
			"xpf_cos_peer_pps",
			"CoS peer-redirected pps (window accumulator, cleared by operator) (#709).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainGuaranteeSentBytes: prometheus.NewDesc(
			"xpf_userspace_cos_drain_guarantee_sent_bytes_total",
			"Bytes sent by this CoS queue during guarantee-phase service (#1369).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainSurplusSentBytes: prometheus.NewDesc(
			"xpf_userspace_cos_drain_surplus_sent_bytes_total",
			"Bytes sent by this CoS queue during surplus-phase service (#1369).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainNonExactSentBytesWhileExactBacklogged: prometheus.NewDesc(
			"xpf_userspace_cos_drain_nonexact_sent_bytes_while_exact_backlogged_total",
			"Non-exact CoS queue bytes sent while at least one exact queue on the same shaped interface still had backlog; non-zero deltas indicate best-effort/uncapped service competing with exact demand (#1369).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowEnforcementEnabled: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_enforcement_enabled",
			"1 when this exact CoS queue's shared v8 lease is configured for opt-in equal-flow suppression (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowEnforced: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_enforced",
			"1 when this exact CoS queue's current shared v8 lease epoch is actively applying equal-flow suppression; 0 when configured but failed open (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowTargetPerFlowBPS: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_target_per_flow_bps",
			"Current Rust-enforced equal-flow per-flow target in bits per second, derived from shared v8 lease grants rather than the measurement-only Go estimator (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowMaxWorkerCapBytes: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_max_worker_cap_bytes",
			"Maximum per-worker bytes-per-epoch cap currently published by the shared v8 equal-flow suppressor (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowCapHitEvents: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_cap_hit_events_total",
			"Acquire calls denied by the opt-in shared v8 equal-flow cap while class capacity remained (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowSuppressedGrantBytes: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_suppressed_grant_bytes_total",
			"Requested queue-lease bytes withheld by the opt-in shared v8 equal-flow suppressor while class capacity remained (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowStaleOrTagMismatchEvents: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_stale_or_tag_mismatch_events_total",
			"Acquire-side stale/tag-mismatch equal-flow cap reads that failed open without overwriting the rotation-published epoch reason (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowFailOpen: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_fail_open",
			"1 for the current bounded fail-open reason on an opt-in shared v8 equal-flow queue; absent for queues without equal-flow enforcement (#1304).",
			[]string{"ifindex", "queue_id", "reason"}, nil,
		),
		// #869: per-worker busy/idle runtime counters.
		workerWallSecs: prometheus.NewDesc(
			"xpf_userspace_worker_wall_seconds_total",
			"Monotonic wall seconds observed by the userspace-dp worker loop (#869).",
			[]string{"worker_id"}, nil,
		),
		workerActiveSecs: prometheus.NewDesc(
			"xpf_userspace_worker_active_seconds_total",
			"Seconds the userspace-dp worker spent processing packets (#869).",
			[]string{"worker_id"}, nil,
		),
		workerIdleSpinSecs: prometheus.NewDesc(
			"xpf_userspace_worker_idle_spin_seconds_total",
			"Seconds the userspace-dp worker spent idle-spinning on empty rings (#869).",
			[]string{"worker_id"}, nil,
		),
		workerIdleBlockSecs: prometheus.NewDesc(
			"xpf_userspace_worker_idle_block_seconds_total",
			"Seconds the userspace-dp worker spent blocked in poll()/sleep (#869).",
			[]string{"worker_id"}, nil,
		),
		workerThreadCPUSecs: prometheus.NewDesc(
			"xpf_userspace_worker_thread_cpu_seconds_total",
			"CLOCK_THREAD_CPUTIME_ID sample for the userspace-dp worker thread (#869).",
			[]string{"worker_id"}, nil,
		),
		workerThreadCPUSecsLast60s: prometheus.NewDesc(
			"xpf_userspace_worker_thread_cpu_seconds_last_60s",
			"CLOCK_THREAD_CPUTIME_ID consumed by the worker thread over the most recent rolling ~60s window (gauge, not counter; 0 until ~60s after worker start).",
			[]string{"worker_id"}, nil,
		),
		workerThreadCPUWindowSecs: prometheus.NewDesc(
			"xpf_userspace_worker_thread_cpu_window_seconds",
			"Wall-clock width of the rolling thread-CPU window matching xpf_userspace_worker_thread_cpu_seconds_last_60s; 0 until ~60s after worker start. Operators compute live CPU% as last_60s / this gauge.",
			[]string{"worker_id"}, nil,
		),
		workerWorkLoops: prometheus.NewDesc(
			"xpf_userspace_worker_work_loops_total",
			"Worker-loop iterations that did useful packet/ring work (#869).",
			[]string{"worker_id"}, nil,
		),
		workerIdleLoops: prometheus.NewDesc(
			"xpf_userspace_worker_idle_loops_total",
			"Worker-loop iterations with no useful work (#869).",
			[]string{"worker_id"}, nil,
		),
		workerCoSQueueLeaseAcquireV8Calls: prometheus.NewDesc(
			"xpf_userspace_worker_cos_queue_lease_acquire_v8_calls_total",
			"V8 CoS queue-lease acquire calls made by this worker (#1240).",
			[]string{"worker_id"}, nil,
		),
		workerCoSQueueLeaseAcquireV8GrantedBytes: prometheus.NewDesc(
			"xpf_userspace_worker_cos_queue_lease_acquire_v8_granted_bytes_total",
			"Bytes granted by v8 CoS queue-lease acquire calls for this worker (#1240).",
			[]string{"worker_id"}, nil,
		),
		workerSessionTableEntries: prometheus.NewDesc(
			"xpf_userspace_worker_session_table_entries",
			"Live session-table entries published by this userspace worker.",
			[]string{"worker_id"}, nil,
		),
		workerSessionTableCapacity: prometheus.NewDesc(
			"xpf_userspace_worker_session_table_capacity",
			"Maximum session-table entries supported by this userspace worker.",
			[]string{"worker_id"}, nil,
		),
		userspaceSessionTableEntries: prometheus.NewDesc(
			"xpf_userspace_session_table_entries",
			"Aggregate live userspace session-table entries across workers.",
			nil, nil,
		),
		userspaceSessionTableCapacity: prometheus.NewDesc(
			"xpf_userspace_session_table_capacity",
			"Aggregate userspace session-table capacity across workers.",
			nil, nil,
		),
		userspaceFlowCacheActiveFlows: prometheus.NewDesc(
			"xpf_userspace_flow_cache_active_flows",
			"Aggregate active userspace flow-cache entries across bindings.",
			nil, nil,
		),
		userspaceFlowCacheCapacity: prometheus.NewDesc(
			"xpf_userspace_flow_cache_capacity",
			"Aggregate userspace flow-cache capacity across bindings.",
			nil, nil,
		),
		userspaceEventStreamFramesTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_frames_total",
			"Daemon-side userspace event-stream frames by direction.",
			[]string{"direction"}, nil,
		),
		userspaceEventStreamProducerFramesTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_producer_frames_total",
			"Userspace helper event-stream producer counters by outcome.",
			[]string{"outcome"}, nil,
		),
		userspaceEventStreamDecodeErrorsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_decode_errors_total",
			"Daemon-side userspace event-stream decode errors.",
			nil, nil,
		),
		userspaceEventStreamSequenceGapsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_sequence_gaps_total",
			"Daemon-side userspace event-stream sequence gaps.",
			nil, nil,
		),
		userspaceEventStreamDataplaneEventsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_dataplane_events_total",
			"Decoded RT_FLOW dataplane events received over the userspace event stream.",
			[]string{"type"}, nil,
		),
		userspaceEventStreamDataplaneDropsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_dataplane_event_drops_total",
			"RT_FLOW dataplane events dropped by the userspace event-stream decoder.",
			[]string{"type"}, nil,
		),
		userspaceEventStreamUnknownDropsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_unknown_frame_drops_total",
			"Userspace event-stream frames dropped because their frame type is unknown.",
			nil, nil,
		),
		workerDead: prometheus.NewDesc(
			"xpf_userspace_worker_dead",
			"1 if the userspace-dp worker thread has panicked and been "+
				"caught by the supervisor; 0 otherwise. Cleared only by "+
				"daemon restart in Phase 1 (#925).",
			[]string{"worker_id"}, nil,
		),
		bindingActiveFlowCount: prometheus.NewDesc(
			"xpf_userspace_binding_active_flow_count",
			"Distinct active flows observed in this binding's flow_cache "+
				"in the last ~650ms (10 epoch ticks × ~65ms debug-state tick; "+
				"snapshot refreshed on each tick). Read by the fairness harness to "+
				"compute the structural CoV ceiling per docs/fairness-regimes.md (#1219).",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		bindingFlowCacheCapacity: prometheus.NewDesc(
			"xpf_userspace_binding_flow_cache_capacity",
			"Flow-cache capacity published by the userspace helper for this binding.",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		bindingTXCompletions: prometheus.NewDesc(
			"xpf_userspace_binding_tx_completions_total",
			"Cumulative AF_XDP TX completions reaped by this binding's owner worker (#1241).",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		bindingTXCompletionRingAvailable: prometheus.NewDesc(
			"xpf_userspace_binding_tx_completion_ring_available",
			"Last sampled AF_XDP TX completion-ring descriptors available before the owner worker drained completions (#1241).",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		bindingTXCompletionRingAvailableMax: prometheus.NewDesc(
			"xpf_userspace_binding_tx_completion_ring_available_max",
			"Maximum sampled AF_XDP TX completion-ring descriptors available in the last debug window (#1241).",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		cosActiveFlowCount: prometheus.NewDesc(
			"xpf_userspace_cos_active_flow_count",
			"Distinct active flows observed for this egress CoS queue on this worker "+
				"in the last ~650ms. This class-specific distribution is the preferred "+
				"fairness harness input for mixed workloads (#1248).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessCstruct: prometheus.NewDesc(
			"xpf_fairness_cstruct",
			"Structural per-flow CoV ceiling for this egress CoS queue, derived from "+
				"xpf_userspace_cos_active_flow_count and the fairness-regimes contract (#1247).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessActiveWorkers: prometheus.NewDesc(
			"xpf_fairness_active_workers",
			"Number of workers with at least one active flow for this egress CoS queue (#1247).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessActiveFlows: prometheus.NewDesc(
			"xpf_fairness_active_flows",
			"Total active flows observed for this egress CoS queue in the current userspace snapshot (#1247).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessMaxWorkerFlowShare: prometheus.NewDesc(
			"xpf_fairness_max_worker_flow_share",
			"Largest fraction of this egress CoS queue's active flows owned by one worker (#1247).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessCoSCountsTruncated: prometheus.NewDesc(
			"xpf_fairness_cos_active_flow_counts_truncated",
			"1 when the userspace CoS active-flow snapshot was truncated before fairness RSS gauges were derived; 0 otherwise (#1247).",
			nil, nil,
		),
		fairnessRSSExpectation: prometheus.NewDesc(
			"xpf_fairness_rss_expectation_configured",
			"1 for each configured opt-in RSS/workload expectation evaluated against this egress CoS queue (#1247).",
			[]string{"ifindex", "queue_id", "kind"}, nil,
		),
		fairnessRSSExpectationValue: prometheus.NewDesc(
			"xpf_fairness_rss_expectation_value",
			"Configured numeric value for RSS/workload expectation kinds that take one, such as active-worker count or threshold (#1265).",
			[]string{"ifindex", "queue_id", "kind"}, nil,
		),
		fairnessRSSSkewViolation: prometheus.NewDesc(
			"xpf_fairness_rss_skew_violation",
			"1 when the configured RSS/workload expectation fails for this egress CoS queue; 0 when it passes (#1247).",
			[]string{"ifindex", "queue_id", "kind"}, nil,
		),
		fairnessSaturated: prometheus.NewDesc(
			"xpf_fairness_saturated",
			"1 when the rolling per-flow byte window is at or above 95% of the configured egress CoS queue transmit rate (#1264).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessObservedCoV: prometheus.NewDesc(
			"xpf_fairness_observed_cov",
			"Rolling observed coefficient of variation across per-flow byte totals for this egress CoS queue (#1264).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessStarvedFlows: prometheus.NewDesc(
			"xpf_fairness_starved_flows",
			"Monotonic count of flows that enter below 1% of the rolling mean per-flow bytes for this egress CoS queue, de-duplicated while the flow remains in the rolling window (#1264).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowEstimateValid: prometheus.NewDesc(
			"xpf_fairness_equal_flow_estimate_valid",
			"1 when the measurement-only equal-flow suppression estimator has at least two currently-active-flow workers with rolling byte samples for this egress CoS queue (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowSampledActiveWorkers: prometheus.NewDesc(
			"xpf_fairness_equal_flow_sampled_active_workers",
			"Currently-active-flow workers with non-zero rolling byte samples in the measurement-only equal-flow suppression estimator (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowUnsampledActiveWorkers: prometheus.NewDesc(
			"xpf_fairness_equal_flow_unsampled_active_workers",
			"Currently-active-flow workers with no rolling byte samples in the measurement-only equal-flow suppression estimator (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowTargetPerFlowBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_target_per_flow_bps",
			"Slowest sampled currently-active worker's observed per-flow bit rate used as the measurement-only equal-flow suppression target for this egress CoS queue; low values may reflect source artifacts such as idle or receiver-limited flows, not only dataplane unfairness (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowObservedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_observed_bps",
			"Observed aggregate bits per second across currently-active-flow workers in the rolling estimator window before hypothetical equal-flow suppression (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowCappedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_capped_bps",
			"Estimated aggregate bits per second across currently-active-flow workers after applying the measurement-only equal-flow suppression cap; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowSuppressedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_suppressed_bps",
			"Estimated currently-active-flow worker bits per second that would be withheld by the measurement-only equal-flow suppression cap; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowThroughputLossRatio: prometheus.NewDesc(
			"xpf_fairness_equal_flow_throughput_loss_ratio",
			"Estimated suppressed_bps / observed_bps ratio for the measurement-only equal-flow suppression cap; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowWorkerObservedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_worker_observed_bps",
			"Observed bits per second for one currently-active-flow worker in the rolling equal-flow suppression estimator (#1304).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessEqualFlowWorkerObservedPerFlowBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_worker_observed_per_flow_bps",
			"Observed per-flow bits per second for one currently-active-flow worker in the rolling equal-flow suppression estimator (#1304).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessEqualFlowWorkerCapBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_worker_cap_bps",
			"Estimated bits-per-second cap for one currently-active-flow worker under measurement-only equal-flow suppression; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessEqualFlowWorkerSuppressedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_worker_suppressed_bps",
			"Estimated bits per second withheld from one currently-active-flow worker by measurement-only equal-flow suppression; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessThroughputWindow: dpuserspace.NewFairnessThroughputWindow(30 * time.Second),
	}
}
