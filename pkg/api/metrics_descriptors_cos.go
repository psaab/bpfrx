package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initCoSDescriptors() {
	// #709: owner-profile telemetry. Labels:
	//   ifindex:      interface ifindex as string
	//   queue_id:     CoS queue id 0-255
	//   bucket_hi_ns: upper bound of the histogram bucket (ns),
	//                 formatted as the power-of-two.
	// The histogram metrics are counters (monotonic bucket counts
	// in the Rust dataplane); owner/peer pps are gauges since the
	// Rust side re-uses them across the window.
	c.cosDrainLatencyBucket = prometheus.NewDesc(
		"xpf_cos_drain_latency_ns_bucket",
		"CoS owner-drain latency histogram — power-of-two ns buckets (#709).",
		[]string{"ifindex", "queue_id", "bucket_hi_ns"}, nil,
	)
	c.cosDrainInvocationsTotal = prometheus.NewDesc(
		"xpf_cos_drain_invocations_total",
		"Total CoS owner-drain invocations per (ifindex, queue_id) (#709).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosRedirectAcquireBucket = prometheus.NewDesc(
		"xpf_cos_redirect_acquire_ns_bucket",
		"CoS redirect-acquire latency histogram — power-of-two ns buckets, sampled 1-in-256 (#709).",
		[]string{"ifindex", "queue_id", "bucket_hi_ns"}, nil,
	)
	c.cosOwnerPPS = prometheus.NewDesc(
		"xpf_cos_owner_pps",
		"CoS owner-local pps (window accumulator, cleared by operator) (#709).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosPeerPPS = prometheus.NewDesc(
		"xpf_cos_peer_pps",
		"CoS peer-redirected pps (window accumulator, cleared by operator) (#709).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosDrainGuaranteeSentBytes = prometheus.NewDesc(
		"xpf_userspace_cos_drain_guarantee_sent_bytes_total",
		"Bytes sent by this CoS queue during guarantee-phase service (#1369).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosDrainSurplusSentBytes = prometheus.NewDesc(
		"xpf_userspace_cos_drain_surplus_sent_bytes_total",
		"Bytes sent by this CoS queue during surplus-phase service (#1369).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosDrainNonExactSentBytesWhileExactBacklogged = prometheus.NewDesc(
		"xpf_userspace_cos_drain_nonexact_sent_bytes_while_exact_backlogged_total",
		"Non-exact CoS queue bytes sent while at least one exact queue on the same shaped interface still had backlog; non-zero deltas indicate best-effort/uncapped service competing with exact demand (#1369).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosRootTokenStarvationParks = prometheus.NewDesc(
		"xpf_userspace_cos_root_token_starvation_parks_total",
		"Times this CoS queue was parked at the shaper because the shared ROOT token bucket was empty. A rising delta on a best-effort/mouse queue while a surplus-sharing borrower drains means the borrower is holding the shared root rate — root-surplus arbitration is the surplus-sharing mouse-latency tail cause, not this queue's own bucket (#1642/#1359).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosQueueTokenStarvationParks = prometheus.NewDesc(
		"xpf_userspace_cos_queue_token_starvation_parks_total",
		"Times this CoS queue was parked at the shaper because its OWN per-queue token bucket was empty (this queue is rate-capped, distinct from shared-root starvation above) (#1642/#1359).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosDrainParkRootTokens = prometheus.NewDesc(
		"xpf_userspace_cos_drain_park_root_tokens_total",
		"Drain-loop parks of this CoS queue attributed to insufficient shared ROOT tokens during a batch. Distinct from the shaper-side root_token_starvation_parks: this counts the per-batch drain-loop decision (#760/#1359).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosDrainParkQueueTokens = prometheus.NewDesc(
		"xpf_userspace_cos_drain_park_queue_tokens_total",
		"Drain-loop parks of this CoS queue attributed to insufficient per-queue tokens during a batch (#760/#1359).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosLeaseV8RequestedBytes = prometheus.NewDesc(
		"xpf_userspace_cos_lease_v8_requested_bytes_total",
		"Cumulative bytes this worker REQUESTED from this CoS queue's shared v8 lease (every acquire_v8 ask, granted or not). Compare with ..._granted_bytes_total: requested >> granted on a worker = share-bounded asks (mismatch); a worker with near-zero requested while the class undergrants = claim-sampling loss. Step-0 attribution instrument for the honored-realization gap (#1863).",
		[]string{"ifindex", "queue_id", "worker_id"}, nil,
	)
	c.cosLeaseV8GrantedBytes = prometheus.NewDesc(
		"xpf_userspace_cos_lease_v8_granted_bytes_total",
		"Cumulative bytes this worker was GRANTED by this CoS queue's shared v8 lease. Per-class sum approximates the class's realized guarantee-phase throughput; see ..._requested_bytes_total for the attribution contract (#1863).",
		[]string{"ifindex", "queue_id", "worker_id"}, nil,
	)
	c.cosAdmissionFlowShareDrops = prometheus.NewDesc(
		"xpf_userspace_cos_admission_flow_share_drops_total",
		"Packets dropped at CoS admission because the flow exceeded its per-flow buffer share (summed across worker instances by the Rust coordinator). Previously wire-only (#710/#718); exported for the #1863 supply-path drop-site attribution.",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosAdmissionBufferDrops = prometheus.NewDesc(
		"xpf_userspace_cos_admission_buffer_drops_total",
		"Packets dropped at CoS admission because the queue's buffer limit was exceeded (summed across worker instances). Previously wire-only (#710/#718); exported for the #1863 supply-path drop-site attribution.",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosAdmissionEcnMarked = prometheus.NewDesc(
		"xpf_userspace_cos_admission_ecn_marked_total",
		"Packets ECN-CE-marked at CoS admission instead of dropped (summed across worker instances). Previously wire-only; exported alongside the admission drop counters (#1863).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosWaterfillPhase1Admissions = prometheus.NewDesc(
		"xpf_userspace_cos_waterfill_phase1_admissions_total",
		"Times this CoS queue was admitted by the guarantee-rate waterfill Phase-1 (small-first honored) walk. Combine with phase2_admissions + queued_bytes + *_starvation_parks to diagnose Phase-2 lock-in (#1628).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosWaterfillPhase2Admissions = prometheus.NewDesc(
		"xpf_userspace_cos_waterfill_phase2_admissions_total",
		"Times this CoS queue was admitted by the guarantee-rate waterfill Phase-2 (descending residual) walk. Climbing while phase1_admissions stays flat is evidence (not proof) of Phase-2 lock-in for a small class within the Phase-1 budget (#1628).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosWaterfillEligibleVisits = prometheus.NewDesc(
		"xpf_userspace_cos_waterfill_eligible_visits_total",
		"Times the guarantee-rate waterfill selector reached this CoS queue eligible (nonempty/runnable/guarantee/exact) and evaluated it (both phases, before the token gate). Low value + high *_starvation_parks = backlogged-but-parked; low + low parks + zero queued = idle on this owner (#1628).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosWaterfillPhase1SelectedNoProgress = prometheus.NewDesc(
		"xpf_userspace_cos_waterfill_phase1_selected_no_progress_total",
		"Times this CoS queue was honored by the guarantee-rate waterfill Phase-1 walk but made ZERO TX progress, so its budget debit and honored bit were refunded (hb166 T-2). Climbing here while waterfill_phase1_admissions stays flat = TX-ring pressure eating a small class's guarantee pass (the #1630/#4256 mid-rate-residual signal).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosWaterfillEpochs = prometheus.NewDesc(
		"xpf_userspace_cos_waterfill_epochs_total",
		"Completed guarantee-rate waterfill epochs (Phase-1 budget refills) on this CoS interface, summed across workers (#1628).",
		[]string{"ifindex"}, nil,
	)
	c.cosWaterfillPhase1BudgetBreaks = prometheus.NewDesc(
		"xpf_userspace_cos_waterfill_phase1_budget_breaks_total",
		"Times the guarantee-rate waterfill Phase-1 walk broke into Phase 2 because the next ascending queue's cost exceeded the remaining Phase-1 budget, summed across workers. High breaks-per-epoch means Phase 1 routinely exhausts its budget mid-walk (#1628).",
		[]string{"ifindex"}, nil,
	)
	c.cosWaterfillMinEpochsPerWorker = prometheus.NewDesc(
		"xpf_userspace_cos_waterfill_min_epochs_per_worker",
		"Minimum waterfill_epochs across workers/bindings WITH active exact-guarantee backlog on this CoS interface. A worker/binding locked in Phase-2 keeps its epochs frozen, dropping this MIN even while the summed epochs climb; a value of 0 is a hard lock-in (a backlogged binding that completed zero epochs). The gauge is SUPPRESSED (no series) for an idle interface with no active-backlog candidate, so any emitted value — including 0 — is a real lock-in signal and alertable with `< N` (#1628).",
		[]string{"ifindex"}, nil,
	)
	c.cosEqualFlowEnforcementEnabled = prometheus.NewDesc(
		"xpf_userspace_cos_equal_flow_enforcement_enabled",
		"1 when this exact CoS queue's shared v8 lease is configured for opt-in equal-flow suppression (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosEqualFlowTargetPolicy = prometheus.NewDesc(
		"xpf_userspace_cos_equal_flow_target_policy",
		"Info metric (always 1): the equal-flow target policy active on this exact CoS queue's shared v8 lease — policy label is one of slowest | mean | ideal-share (#1746). Sibling of the existing equal-flow gauges; series identity of those gauges is unchanged.",
		[]string{"ifindex", "queue_id", "policy"}, nil,
	)
	c.cosEqualFlowEnforced = prometheus.NewDesc(
		"xpf_userspace_cos_equal_flow_enforced",
		"1 when this exact CoS queue's current shared v8 lease epoch is actively applying equal-flow suppression; 0 when configured but failed open (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosEqualFlowTargetPerFlowBPS = prometheus.NewDesc(
		"xpf_userspace_cos_equal_flow_target_per_flow_bps",
		"Current Rust-enforced equal-flow per-flow target in bits per second, derived from shared v8 lease grants rather than the measurement-only Go estimator (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosEqualFlowMaxWorkerCapBytes = prometheus.NewDesc(
		"xpf_userspace_cos_equal_flow_max_worker_cap_bytes",
		"Maximum per-worker bytes-per-epoch cap currently published by the shared v8 equal-flow suppressor (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosEqualFlowCapHitEvents = prometheus.NewDesc(
		"xpf_userspace_cos_equal_flow_cap_hit_events_total",
		"Acquire calls denied by the opt-in shared v8 equal-flow cap while class capacity remained (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosEqualFlowSuppressedGrantBytes = prometheus.NewDesc(
		"xpf_userspace_cos_equal_flow_suppressed_grant_bytes_total",
		"Requested queue-lease bytes withheld by the opt-in shared v8 equal-flow suppressor while class capacity remained (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosEqualFlowStaleOrTagMismatchEvents = prometheus.NewDesc(
		"xpf_userspace_cos_equal_flow_stale_or_tag_mismatch_events_total",
		"Acquire-side stale/tag-mismatch equal-flow cap reads that failed open without overwriting the rotation-published epoch reason (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosEqualFlowFailOpen = prometheus.NewDesc(
		"xpf_userspace_cos_equal_flow_fail_open",
		"1 for the current bounded fail-open reason on an opt-in shared v8 equal-flow queue; absent for queues without equal-flow enforcement (#1304).",
		[]string{"ifindex", "queue_id", "reason"}, nil,
	)
	// #1829 Phase 1: dequeue-time sojourn gauges, MAX-merged
	// across worker instances and across workers (worst
	// instance). The windowed-min gauge is the #1829 Phase-2
	// gate metric.
	c.cosSojournEwmaNS = prometheus.NewDesc(
		"xpf_userspace_cos_sojourn_ewma_ns",
		"Shift-add EWMA (alpha=1/8) of per-packet queue sojourn measured at dequeue on this CoS queue, ns, MAX-merged across workers. Supporting context only — biased high by scheduler service gaps; gate standing-queue decisions on xpf_userspace_cos_sojourn_windowed_min_ns instead (#1829).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosSojournPeakNS = prometheus.NewDesc(
		"xpf_userspace_cos_sojourn_peak_ns",
		"Lifetime maximum per-packet queue sojourn measured at dequeue on this CoS queue, ns, MAX-merged across workers (#1829).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosSojournWindowedMinNS = prometheus.NewDesc(
		"xpf_userspace_cos_sojourn_windowed_min_ns",
		"Minimum per-packet queue sojourn over the last 1-2 100 ms windows on this CoS queue, ns, MAX-merged across workers (worst instance). CoDel's standing-queue estimator and the #1829 Phase-2 gate metric: a value persistently above codel-target is standing-queue evidence; 0 means no pops in the last ~2 windows (no standing queue).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	// #1830 (g): bucket-vs-flow occupancy gauges. The ratio
	// flows_active / buckets_occupied is meaningful only while the
	// queue is continuously backlogged; see the wire-field docs.
	c.cosFlowFairBucketsOccupied = prometheus.NewDesc(
		"xpf_userspace_cos_flow_fair_buckets_occupied",
		"Currently occupied (backlogged) SFQ flow-fair buckets on this CoS queue, summed across workers; 0 on idle or non-flow-fair queues. Compare against xpf_userspace_cos_flow_fair_flows_active under sustained backlog: fewer occupied buckets than known concurrent flows indicates SFQ hash collisions shrinking per-flow shares (#1830).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.cosFlowFairFlowsActive = prometheus.NewDesc(
		"xpf_userspace_cos_flow_fair_flows_active",
		"Flow-cache active-window (~650 ms) distinct flows mapped to this CoS queue, summed across workers. Numerator of the collision ratio against xpf_userspace_cos_flow_fair_buckets_occupied; on idle/bursty queues it naturally exceeds occupied buckets (demand variance, not collision evidence) (#1830).",
		[]string{"ifindex", "queue_id"}, nil,
	)
}
