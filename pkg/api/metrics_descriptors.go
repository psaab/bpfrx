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
		neighborPeriodicAge: prometheus.NewDesc(
			"xpf_daemon_neighbor_periodic_last_success_age_seconds",
			"Seconds since each Go periodic neighbor-maintenance phase "+
				"last completed. A monotonically climbing value means that "+
				"phase's guarded goroutine is wedged on a stuck netlink/probe "+
				"syscall (#1780).",
			[]string{"phase"}, nil,
		),
		configPersistDegraded: prometheus.NewDesc(
			"xpf_daemon_config_persist_degraded",
			"1 while the running active configuration failed to persist "+
				"to disk and the background retry has not yet succeeded "+
				"(a daemon restart would load a stale config, #1799); 0 "+
				"when config persistence is healthy.",
			nil, nil,
		),
		ipmonPolicyFailed: prometheus.NewDesc(
			"xpf_ipmon_policy_failed",
			"1 while the services ip-monitoring policy is in FAIL state "+
				"(preferred routes injected); 0 while passing (#1827).",
			[]string{"policy"}, nil,
		),
		ipmonPolicyTransitions: prometheus.NewDesc(
			"xpf_ipmon_policy_transitions_total",
			"Total FAIL/recover state transitions of the services "+
				"ip-monitoring policy (#1827). A steadily climbing value "+
				"indicates a flapping uplink; consider a non-zero hold-down.",
			[]string{"policy"}, nil,
		),
		ipmonRoutesApplied: prometheus.NewDesc(
			"xpf_ipmon_routes_applied",
			"Number of ip-monitoring preferred routes currently applied "+
				"(after winner resolution, #1827).",
			nil, nil,
		),
		ipmonUnresolvedNextHops: prometheus.NewDesc(
			"xpf_ipmon_unresolved_next_hops",
			"Number of ip-monitoring interface-typed preferred routes of "+
				"FAILED policies currently skipped from the overlay "+
				"because the tracked interface unit has no DHCP-learned "+
				"gateway (#1844). Non-zero during a failover means the "+
				"backup uplink's lease is missing and the failover route "+
				"is NOT injected.",
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
		cosLeaseV8RequestedBytes: prometheus.NewDesc(
			"xpf_userspace_cos_lease_v8_requested_bytes_total",
			"Cumulative bytes this worker REQUESTED from this CoS queue's shared v8 lease (every acquire_v8 ask, granted or not). Compare with ..._granted_bytes_total: requested >> granted on a worker = share-bounded asks (mismatch); a worker with near-zero requested while the class undergrants = claim-sampling loss. Step-0 attribution instrument for the honored-realization gap (#1863).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		cosLeaseV8GrantedBytes: prometheus.NewDesc(
			"xpf_userspace_cos_lease_v8_granted_bytes_total",
			"Cumulative bytes this worker was GRANTED by this CoS queue's shared v8 lease. Per-class sum approximates the class's realized guarantee-phase throughput; see ..._requested_bytes_total for the attribution contract (#1863).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		cosAdmissionFlowShareDrops: prometheus.NewDesc(
			"xpf_userspace_cos_admission_flow_share_drops_total",
			"Packets dropped at CoS admission because the flow exceeded its per-flow buffer share (summed across worker instances by the Rust coordinator). Previously wire-only (#710/#718); exported for the #1863 supply-path drop-site attribution.",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosAdmissionBufferDrops: prometheus.NewDesc(
			"xpf_userspace_cos_admission_buffer_drops_total",
			"Packets dropped at CoS admission because the queue's buffer limit was exceeded (summed across worker instances). Previously wire-only (#710/#718); exported for the #1863 supply-path drop-site attribution.",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosAdmissionEcnMarked: prometheus.NewDesc(
			"xpf_userspace_cos_admission_ecn_marked_total",
			"Packets ECN-CE-marked at CoS admission instead of dropped (summed across worker instances). Previously wire-only; exported alongside the admission drop counters (#1863).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosWaterfillPhase1Admissions: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_phase1_admissions_total",
			"Times this CoS queue was admitted by the guarantee-rate waterfill Phase-1 (small-first honored) walk. Combine with phase2_admissions + queued_bytes + *_starvation_parks to diagnose Phase-2 lock-in (#1628).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosWaterfillPhase2Admissions: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_phase2_admissions_total",
			"Times this CoS queue was admitted by the guarantee-rate waterfill Phase-2 (descending residual) walk. Climbing while phase1_admissions stays flat is evidence (not proof) of Phase-2 lock-in for a small class within the Phase-1 budget (#1628).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosWaterfillEligibleVisits: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_eligible_visits_total",
			"Times the guarantee-rate waterfill selector reached this CoS queue eligible (nonempty/runnable/guarantee/exact) and evaluated it (both phases, before the token gate). Low value + high *_starvation_parks = backlogged-but-parked; low + low parks + zero queued = idle on this owner (#1628).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosWaterfillEpochs: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_epochs_total",
			"Completed guarantee-rate waterfill epochs (Phase-1 budget refills) on this CoS interface, summed across workers (#1628).",
			[]string{"ifindex"}, nil,
		),
		cosWaterfillPhase1BudgetBreaks: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_phase1_budget_breaks_total",
			"Times the guarantee-rate waterfill Phase-1 walk broke into Phase 2 because the next ascending queue's cost exceeded the remaining Phase-1 budget, summed across workers. High breaks-per-epoch means Phase 1 routinely exhausts its budget mid-walk (#1628).",
			[]string{"ifindex"}, nil,
		),
		cosWaterfillMinEpochsPerWorker: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_min_epochs_per_worker",
			"Minimum waterfill_epochs across workers/bindings WITH active exact-guarantee backlog on this CoS interface. A worker/binding locked in Phase-2 keeps its epochs frozen, dropping this MIN even while the summed epochs climb; a value of 0 is a hard lock-in (a backlogged binding that completed zero epochs). The gauge is SUPPRESSED (no series) for an idle interface with no active-backlog candidate, so any emitted value — including 0 — is a real lock-in signal and alertable with `< N` (#1628).",
			[]string{"ifindex"}, nil,
		),
		cosEqualFlowEnforcementEnabled: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_enforcement_enabled",
			"1 when this exact CoS queue's shared v8 lease is configured for opt-in equal-flow suppression (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowTargetPolicy: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_target_policy",
			"Info metric (always 1): the equal-flow target policy active on this exact CoS queue's shared v8 lease — policy label is one of slowest | mean | ideal-share (#1746). Sibling of the existing equal-flow gauges; series identity of those gauges is unchanged.",
			[]string{"ifindex", "queue_id", "policy"}, nil,
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
		// #1829 Phase 1: dequeue-time sojourn gauges, MAX-merged
		// across worker instances and across workers (worst
		// instance). The windowed-min gauge is the #1829 Phase-2
		// gate metric.
		cosSojournEwmaNS: prometheus.NewDesc(
			"xpf_userspace_cos_sojourn_ewma_ns",
			"Shift-add EWMA (alpha=1/8) of per-packet queue sojourn measured at dequeue on this CoS queue, ns, MAX-merged across workers. Supporting context only — biased high by scheduler service gaps; gate standing-queue decisions on xpf_userspace_cos_sojourn_windowed_min_ns instead (#1829).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosSojournPeakNS: prometheus.NewDesc(
			"xpf_userspace_cos_sojourn_peak_ns",
			"Lifetime maximum per-packet queue sojourn measured at dequeue on this CoS queue, ns, MAX-merged across workers (#1829).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosSojournWindowedMinNS: prometheus.NewDesc(
			"xpf_userspace_cos_sojourn_windowed_min_ns",
			"Minimum per-packet queue sojourn over the last 1-2 100 ms windows on this CoS queue, ns, MAX-merged across workers (worst instance). CoDel's standing-queue estimator and the #1829 Phase-2 gate metric: a value persistently above codel-target is standing-queue evidence; 0 means no pops in the last ~2 windows (no standing queue).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		// #1830 (g): bucket-vs-flow occupancy gauges. The ratio
		// flows_active / buckets_occupied is meaningful only while the
		// queue is continuously backlogged; see the wire-field docs.
		cosFlowFairBucketsOccupied: prometheus.NewDesc(
			"xpf_userspace_cos_flow_fair_buckets_occupied",
			"Currently occupied (backlogged) SFQ flow-fair buckets on this CoS queue, summed across workers; 0 on idle or non-flow-fair queues. Compare against xpf_userspace_cos_flow_fair_flows_active under sustained backlog: fewer occupied buckets than known concurrent flows indicates SFQ hash collisions shrinking per-flow shares (#1830).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosFlowFairFlowsActive: prometheus.NewDesc(
			"xpf_userspace_cos_flow_fair_flows_active",
			"Flow-cache active-window (~650 ms) distinct flows mapped to this CoS queue, summed across workers. Numerator of the collision ratio against xpf_userspace_cos_flow_fair_buckets_occupied; on idle/bursty queues it naturally exceeds occupied buckets (demand variance, not collision evidence) (#1830).",
			[]string{"ifindex", "queue_id"}, nil,
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
		// #1782 Step-1 cold-start CoS instruments.
		workerCoSWheelTicksAdvancedTotal: prometheus.NewDesc(
			"xpf_userspace_worker_cos_wheel_ticks_advanced_total",
			"Cumulative CoS timer-wheel ticks (50us each) advanced by advance_cos_timer_wheel across this worker's bindings — the O(lag) cold-start catch-up cost, mechanism (i) of the #1782 Step-1 disambiguation.",
			[]string{"worker_id"}, nil,
		),
		workerCoSWheelTicksAdvancedMax: prometheus.NewDesc(
			"xpf_userspace_worker_cos_wheel_ticks_advanced_max",
			"Largest single-call CoS timer-wheel tick advance ever observed on this worker (monotonic high-water mark, never resets). A multi-million-tick value after a cold reproduction pins the #1782 §4(i) wheel catch-up mechanism.",
			[]string{"worker_id"}, nil,
		),
		workerCoSQueueLeaseUndergrant: prometheus.NewDesc(
			"xpf_userspace_worker_cos_queue_lease_undergrant_total",
			"CoS exact-guarantee selector visits where the post-top-up queue tokens still could not cover the head frame, attributed to the v8 acquire shortfall cause (#1782 Step-1 mechanism (ii)); a v8-attributed subset of drain_park_queue_tokens.",
			[]string{"worker_id", "cause"}, nil,
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
		workerNatReverseKeyCollisions: prometheus.NewDesc(
			"xpf_userspace_worker_session_nat_reverse_key_collisions_total",
			"Cumulative NAT reverse-key (nat_reverse_index) 1:N collision "+
				"displacement events on this userspace worker's session table "+
				"(#1758/#1760 latent corruption made observable). Event count, "+
				"not a census: standing collisions after a winner's expiry and "+
				"never-replicated MissingNeighborSeed collisions are not "+
				"counted here — see the shared displacements counter.",
			[]string{"worker_id"}, nil,
		),
		workerSessionCreateDrops: prometheus.NewDesc(
			"xpf_userspace_worker_session_create_drops_total",
			"Cumulative session installs refused at the max_sessions cap on "+
				"this userspace worker's session table (#1861 — previously "+
				"counted internally but never exported). Covers every "+
				"install site (new-flow, reply repair, seed, fabric-return, "+
				"LocalMiss helper, UpsertLocal replicas).",
			[]string{"worker_id"}, nil,
		),
		workerSessionInstallAdmissionRefused: prometheus.NewDesc(
			"xpf_userspace_worker_session_install_admission_refused_total",
			"Cumulative new flows refused (trigger packet dropped, Junos "+
				"parity) by the #1861 forward+reverse pair-admission "+
				"preflight at/near max_sessions on this userspace worker. "+
				"One increment per refused flow, not per missing slot.",
			[]string{"worker_id"}, nil,
		),
		workerSessionInstallPartial: prometheus.NewDesc(
			"xpf_userspace_worker_session_install_partial_total",
			"Post-preflight partial session installs on this userspace "+
				"worker (#1861 release residual arms). Expected to stay 0 "+
				"forever; nonzero means the preflight/install pairing has a "+
				"bug and the dataplane degraded a flow instead of "+
				"half-committing it.",
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
		userspaceNatReverseKeyCollisions: prometheus.NewDesc(
			"xpf_userspace_session_nat_reverse_key_collisions_total",
			"Aggregate NAT reverse-key (nat_reverse_index) 1:N collision "+
				"displacement events across userspace workers (#1758/#1760 "+
				"latent corruption made observable). Event count, not a "+
				"census (replica fanout over-counts; standing and seed-path "+
				"collisions under-count — pair with the shared displacements "+
				"counter). >=1 means at least one real collision occurred "+
				"and is the structural-fix revisit trigger.",
			nil, nil,
		),
		userspaceNatReverseKeySharedDisplacements: prometheus.NewDesc(
			"xpf_userspace_session_nat_reverse_key_shared_displacements_total",
			"Shared-map NAT reverse-key displacement events: a "+
				"publish_shared_session insert displaced a DIFFERENT forward "+
				"session's entry at the same reverse key (#1760 latent 1:N "+
				"reverse-path corruption). The shared map is the choke point "+
				"all transit forward NAT sessions pass through (including "+
				"MissingNeighborSeed installs invisible to the per-worker "+
				"counter). Event count, not a pair census: >=1 means at "+
				"least one real collision occurred; standing collisions "+
				"against an already-unindexed session are not counted.",
			nil, nil,
		),
		userspaceSessionCreateDrops: prometheus.NewDesc(
			"xpf_userspace_session_create_drops_total",
			"Aggregate session installs refused at the max_sessions cap "+
				"across userspace workers (#1861).",
			nil, nil,
		),
		userspaceSessionInstallAdmissionRefused: prometheus.NewDesc(
			"xpf_userspace_session_install_admission_refused_total",
			"Aggregate new flows refused (trigger packet dropped, Junos "+
				"parity) by the #1861 forward+reverse pair-admission "+
				"preflight at/near max_sessions, across userspace workers.",
			nil, nil,
		),
		userspaceSessionInstallPartial: prometheus.NewDesc(
			"xpf_userspace_session_install_partial_total",
			"Aggregate post-preflight partial session installs across "+
				"userspace workers (#1861 release residual arms; expected 0 "+
				"forever — nonzero means a preflight/install pairing bug).",
			nil, nil,
		),
		userspaceSessionPublishErrors: prometheus.NewDesc(
			"xpf_userspace_session_publish_errors_total",
			"Failed USERSPACE_SESSIONS BPF-map publishes across all helper "+
				"paths (worker poll, HA upsert, session-glue, post-reconcile "+
				"replay, activation/reverse prewarm). A failed publish means "+
				"the XDP shim never learns the session key and takes the "+
				"NO_SESSION degraded path (drop in STRICT mode); a rising "+
				"value attributes shim no-session fallbacks to publish "+
				"failures (session map at capacity, stale fd after "+
				"reconcile) (#1789).",
			nil, nil,
		),
		userspaceWorkerCommandQueuePoisonRecoveries: prometheus.NewDesc(
			"xpf_userspace_worker_command_queue_poison_recoveries_total",
			"Worker command-queue mutex poison recoveries across all "+
				"helper producer/consumer sites (worker poll, HA enqueues, "+
				"session replication, activation prewarm, tunnel install, "+
				"cross-binding shaped-TX redirect). A poisoned mutex means "+
				"a worker thread panicked while holding the lock; recovery "+
				"keeps the committed queue and clears the poison so the "+
				"queues keep flowing instead of going permanently deaf. "+
				"A nonzero value indicates a contained worker panic "+
				"occurred (#1807, extends #1790).",
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
		// === #1621 cold-path histogram surface ===
		workerColdPathBucket: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_ns_bucket",
			"Cumulative cold-path policy-eval latency observations per "+
				"worker / zone-pair-slot, bucketed into the #1619 24-bucket "+
				"power-of-two ns histogram. Compatible with PromQL "+
				"histogram_quantile() via the `le` label (#1612 step-3).",
			[]string{"worker_id", "zone_pair_slot", "le"}, nil,
		),
		workerColdPathSamples: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_samples_total",
			"Per-worker / zone-pair-slot count of cold-path latency "+
				"samples actually recorded (post sample-mask gate + post "+
				"q32-skip). Use as the denominator for actual sampling rate.",
			[]string{"worker_id", "zone_pair_slot"}, nil,
		),
		workerColdPathSumNS: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_sum_ns_total",
			"Per-worker / zone-pair-slot cumulative sum of recorded "+
				"delta_ns values (post baseline subtraction).",
			[]string{"worker_id", "zone_pair_slot"}, nil,
		),
		workerColdPathAliasSeen: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_alias_seen",
			"1 if this zone-pair-slot saw two different packed "+
				"(from_zone, to_zone) keys during the current publish "+
				"window — the harness excludes aliased slots from Scale "+
				"Target tables. 0 otherwise.",
			[]string{"worker_id", "zone_pair_slot"}, nil,
		),
		workerColdPathSamplePhase: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_sample_phase_total",
			"Per-worker monotonic count of eligible cold-path sampling "+
				"attempts. Increment on every session-miss pass through "+
				"the policy-eval pre-eval gate. Denominator for "+
				"actual_sampling_rate = sum(samples[]) / sample_phase.",
			[]string{"worker_id"}, nil,
		),
		workerColdPathWrapperUnderflow: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_wrapper_underflow_count_total",
			"Per-worker monotonic count of samples where raw_ns < "+
				"wrapper_ns_baseline. Indicates baseline drift "+
				"(frequency scaling, OoO jitter, ultra-fast policy_eval).",
			[]string{"worker_id"}, nil,
		),
		workerColdPathWrapperNSBaseline: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_wrapper_ns_baseline",
			"Calibrated cost of the sample_tsc_start + sample_tsc_end "+
				"fence pair, measured once per worker post pthread "+
				"affinity at startup. Subtracted from every recorded "+
				"delta_ns on the hot path.",
			[]string{"worker_id"}, nil,
		),
		workerColdPathNSPerTSCQ32: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_ns_per_tsc_q32",
			"Q32 fixed-point ns_per_tsc multiplier from worker startup "+
				"calibration. 0 when TSC unavailable. Operators compare "+
				"across workers to detect calibration anomalies.",
			[]string{"worker_id"}, nil,
		),
		workerColdPathClockSource: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_clock_source",
			"1 when this worker's clock source has the value of the "+
				"`source` label. Operators gate Scale Target table "+
				"publication on every worker reporting source='tsc'. "+
				"Always emitted (uncalibrated workers report "+
				"source='unset').",
			[]string{"worker_id", "source"}, nil,
		),
		workerColdPathSnapshotFailedTotal: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_snapshot_failed_total",
			"Per-worker monotonic count of snapshot() calls at the "+
				"coordinator status path that exhausted their retry "+
				"budget (publish contention / scheduler preemption). "+
				"Distinguishes 'no data this scrape' from 'transient "+
				"starvation'.",
			[]string{"worker_id"}, nil,
		),
		// === #1635 sparse v3 per-zone-pair cold-path families ===
		workerColdPathBucketV3: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_ns_bucket_v3",
			"Cumulative cold-path policy-eval latency observations per "+
				"worker / (from_zone, to_zone), bucketed into the #1635 "+
				"48-bucket log-linear ns histogram (32 linear 16-ns "+
				"buckets over [0,512) ns + 15 pow-2 buckets + saturate). "+
				"Compatible with PromQL histogram_quantile() via `le`.",
			[]string{"worker_id", "from_zone", "to_zone", "le"}, nil,
		),
		workerColdPathSamplesV3: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_samples_v3_total",
			"Per-worker / (from_zone, to_zone) count of cold-path latency "+
				"samples recorded (#1635 direct slot map).",
			[]string{"worker_id", "from_zone", "to_zone"}, nil,
		),
		workerColdPathSumNSV3: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_sum_ns_v3_total",
			"Per-worker / (from_zone, to_zone) cumulative sum of recorded "+
				"delta_ns (post baseline subtraction).",
			[]string{"worker_id", "from_zone", "to_zone"}, nil,
		),
		workerColdPathBuilderCollisionV3: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_builder_collision_v3",
			"1 if this (from_zone, to_zone) slot saw two distinct packed "+
				"keys — a snapshot-builder bug with the #1635 direct slot "+
				"map; should always be 0. 0 otherwise.",
			[]string{"worker_id", "from_zone", "to_zone"}, nil,
		),
		workerColdPathOverflowActive: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_overflow_active",
			"1 if a configured zone-pair could not be assigned a cold-path "+
				"histogram slot — either the 255-slot capacity was "+
				"exhausted OR the pair references a zone-id outside the "+
				"0..=64 direct-table range. 0 otherwise.",
			[]string{"worker_id"}, nil,
		),
		workerColdPathLayoutVersion: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_layout_version",
			"1 when this worker's cold-path wire layout has the value of "+
				"the `version` label (#1635: 3 = sparse log-linear).",
			[]string{"worker_id", "version"}, nil,
		),
		workerColdPathLayoutUnknownTotal: prometheus.NewDesc(
			// Gauge-style state indicator (NOT a counter): emitted as a
			// GaugeValue=1 when the version is unknown, so the name must
			// NOT end in `_total` (Copilot code-r4: a `_total` suffix
			// would mislead operators into rate()-ing a state flag).
			"xpf_userspace_worker_cold_path_layout_version_unknown",
			"1 when this worker reported a cold-path wire layout version "+
				"the collector does not understand (forward-compat guard).",
			[]string{"worker_id", "version"}, nil,
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
		// #1831 (follow-up to #1766): per-binding V_min fairness-throttle
		// counters (#941 work item D / #943), already carried in
		// BindingStatus on the wire but previously unexported.
		bindingVMinThrottles: prometheus.NewDesc(
			"xpf_userspace_binding_v_min_throttles_total",
			"V_min fairness-brake throttle decisions on this binding's "+
				"shared-exact CoS queues: a drain batch early-broke because the "+
				"queue's virtual time ran more than LAG_THRESHOLD ahead of the "+
				"slowest participating peer worker's V_min (#917/#943). Non-zero "+
				"under load confirms the cross-worker brake is engaged; the "+
				"hard-cap-overrides / throttles ratio is the diagnostic for "+
				"LAG_THRESHOLD tuned too tight.",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		bindingVMinThrottleHardCapOverrides: prometheus.NewDesc(
			"xpf_userspace_binding_v_min_throttle_hard_cap_overrides_total",
			"V_MIN_CONSECUTIVE_SKIP_HARD_CAP escape-hatch activations on this "+
				"binding: after that many back-to-back V_min throttle decisions "+
				"the drain force-continues and arms suspension — 'brake too "+
				"tight, escape hatch rescued throughput' (#941 work item D). "+
				"Counted distinctly from (not a subset of) "+
				"xpf_userspace_binding_v_min_throttles_total.",
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
		// #1636 option C: proactive-neighbor-warm telemetry.
		neighborWarmDropsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_warm_drops_total",
			"Proactive neighbor-warm requests dropped because the bounded warmer queue was full (transient saturation under route churn) (#1636).",
			nil, nil,
		),
		neighborWarmDisconnectedTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_warm_disconnected_total",
			"Proactive neighbor-warm requests dropped because the warmer worker thread died; warming is disabled until daemon restart (#1636).",
			nil, nil,
		),
		// #1782 cold-start capture instrumentation.
		negNeighFastFailTotal: prometheus.NewDesc(
			"xpf_userspace_neg_neigh_fast_fail_total",
			"Packets fast-failed by the per-worker neighbor negative cache after a pending_neigh timeout armed the 3s lockout (cold-start H1 amplifier signal) (#1782).",
			nil, nil,
		),
		pendingNeighDuplicateDropsTotal: prometheus.NewDesc(
			"xpf_userspace_pending_neigh_duplicate_drops_total",
			"MissingNeighbor sibling packets recycled because the (egress_ifindex, next_hop) key was already pending in pending_neigh (cold-start H5 sibling-drop signal; excludes the MAX_PENDING_NEIGH capacity-drop case) (#1782).",
			nil, nil,
		),
		dynamicNeighborPresent: prometheus.NewDesc(
			"xpf_userspace_dynamic_neighbor_present",
			"Per-key presence gauge (always 1) dumped from the helper userspace dynamic_neighbors mirror so the cold-start capture harness can grep the pre-connect t0' next-hop membership (the H2 absence fingerprint) (#1782). DEBUG-ONLY: gated behind the helper's XPF_DEBUG_NEIGHBOR_KEYS env var and absent by default — an absent metric family means the dump is disabled, NOT that dynamic_neighbors is empty.",
			[]string{"ifindex", "ip"}, nil,
		),
		// #1769: on-demand neighbor-resolver telemetry — operator-visible
		// signal for the MissingNeighbor negative-cache stuck-state.
		neighborResolverQueueDepth: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_queue_depth",
			"On-demand neighbor-resolver queue depth: dsts queued for a single-key RTM_GETNEIGH after a MissingNeighbor negative-cache fast-fail but not yet processed (gauge) (#1769).",
			nil, nil,
		),
		neighborResolverEnqueueDropsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_enqueue_drops_total",
			"On-demand neighbor-resolver enqueue attempts dropped because the bounded queue was full (transient; the dst still fast-fails this round) (#1769).",
			nil, nil,
		),
		neighborResolverDisconnectedTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_disconnected_total",
			"On-demand neighbor-resolver enqueue attempts dropped because the resolver worker thread died; on-demand resolution is disabled until daemon restart (#1769).",
			nil, nil,
		),
		neighborResolverGetAttemptsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_get_attempts_total",
			"Single-key RTM_GETNEIGH requests issued by the on-demand resolver (after the per-key rate-limit coalesces a SYN storm) (#1769).",
			nil, nil,
		),
		neighborResolverGetResolvedTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_get_resolved_total",
			"On-demand RTM_GETNEIGH replies confirmed REACHABLE/PERMANENT and cached into the dynamic neighbor map (epoch guard passed) (#1769).",
			nil, nil,
		),
		neighborResolverProbeOnStaleTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_probe_on_stale_total",
			"On-demand RTM_GETNEIGH replies in STALE/DELAY/PROBE that triggered a revalidation probe instead of caching the unconfirmed MAC (the live #1769 wedge state) (#1769).",
			nil, nil,
		),
		neighborResolverGetFailuresTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_get_failures_total",
			"On-demand RTM_GETNEIGH attempts with no usable reply (timeout, FAILED, INCOMPLETE, no entry, or recv/parse error) (#1769).",
			nil, nil,
		),
		neighborResolverEpochRejectsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_epoch_rejects_total",
			"Confirmed on-demand inserts skipped because the global neighbor epoch advanced between enqueue and the GET reply (epoch guard rejected a potentially-raced stale insert) (#1769).",
			nil, nil,
		),
		// #1772: neighbor/ARP resolution LATENCY metrics. The two
		// histograms localize where an intermittent slow new connection
		// spends its time: pending-buffer dwell vs resolver GETNEIGH RTT.
		neighborPendingDwellSeconds: prometheus.NewDesc(
			"xpf_userspace_neighbor_pending_dwell_seconds",
			"Histogram of how long a packet sat in the pending-neighbor buffer before its neighbor resolved and it was dispatched (now-queued at the retry-sweep success path). The 3 s blackout class from #1769 lands in the +Inf tail (#1772).",
			nil, nil,
		),
		neighborResolverGetRttSeconds: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_get_rtt_seconds",
			"Histogram of the on-demand resolver single-key RTM_GETNEIGH round-trip time (request sent to reply read) on the resolver thread (#1772).",
			nil, nil,
		),
		neighborPendingTimeoutDropsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_pending_timeout_drops_total",
			"Pending-neighbor packets dropped after exceeding PENDING_NEIGH_TIMEOUT without resolving (never reached a usable neighbor within the window) (#1772).",
			nil, nil,
		),
		neighborPendingMaxDepth: prometheus.NewDesc(
			"xpf_userspace_neighbor_pending_max_depth",
			"High-water mark of the per-binding pending-neighbor queue depth observed at any retry-sweep entry (gauge) (#1772).",
			nil, nil,
		),
		// #1771 §2.6: resolver backoff + §2.5 ENOBUFS/re-dump telemetry.
		neighborResolverGetBackoffAttemptsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_get_backoff_attempts_total",
			"On-demand resolver GET attempts that were backoff RETRIES: the key had already been attempted within the resolver's per-key memory and was re-admitted after the per-key rate-limit window. Subset of get_attempts; a rising rate means the same next-hops keep failing to resolve. Per invariant N1 (#1771 §2.4) these retries keep firing even while the key is negatively cached.",
			nil, nil,
		),
		neighborNetlinkEnobufsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_netlink_enobufs_total",
			"ENOBUFS receives on the neighbor-monitor netlink socket: the kernel dropped RTM_NEWNEIGH/DELNEIGH multicast notifications on rcvbuf overflow (the lost-notification desync class the throttled upsert-only re-dump self-heals) (#1771 §2.5).",
			nil, nil,
		),
		neighborNetlinkRedumpsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_netlink_redumps_total",
			"Throttled (5s) upsert-only neighbor-table re-dumps issued after an ENOBUFS (at least one of the v4/v6 dump requests was sent) (#1771 §2.5).",
			nil, nil,
		),
		neighborNetlinkRedumpUpsertsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_netlink_redump_upserts_total",
			"Dynamic-neighbor entries (re)added by an upsert-only re-dump reply — RTM_NEWNEIGH dump replies whose insert changed the map. Nonzero proves a re-dump repopulated keys that lost multicast events had desynced (#1771 §2.5).",
			nil, nil,
		),
		neighborPendingKeys: prometheus.NewDesc(
			"xpf_userspace_neighbor_pending_keys",
			"Distinct unresolved (egress_ifindex, next_hop) keys currently holding a buffered packet in the per-binding pending_neigh maps, summed across bindings (gauge; refreshed at the ~65ms per-binding debug tick) (#1771 §2.6).",
			nil, nil,
		),
		negNeighKeys: prometheus.NewDesc(
			"xpf_userspace_neg_neigh_keys",
			"Keys currently held in the per-binding negative neighbor caches, summed across bindings (gauge; lazy-TTL upper bound — an expired entry stays counted until its next access) (#1771 §2.6).",
			nil, nil,
		),
	}
}
