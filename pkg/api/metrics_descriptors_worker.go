package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initWorkerDescriptors() {
	// #869: per-worker busy/idle runtime counters.
	c.workerWallSecs = prometheus.NewDesc(
		"xpf_userspace_worker_wall_seconds_total",
		"Monotonic wall seconds observed by the userspace-dp worker loop (#869).",
		[]string{"worker_id"}, nil,
	)
	c.workerActiveSecs = prometheus.NewDesc(
		"xpf_userspace_worker_active_seconds_total",
		"Seconds the userspace-dp worker spent processing packets (#869).",
		[]string{"worker_id"}, nil,
	)
	c.workerIdleSpinSecs = prometheus.NewDesc(
		"xpf_userspace_worker_idle_spin_seconds_total",
		"Seconds the userspace-dp worker spent idle-spinning on empty rings (#869).",
		[]string{"worker_id"}, nil,
	)
	c.workerIdleBlockSecs = prometheus.NewDesc(
		"xpf_userspace_worker_idle_block_seconds_total",
		"Seconds the userspace-dp worker spent blocked in poll()/sleep (#869).",
		[]string{"worker_id"}, nil,
	)
	c.workerThreadCPUSecs = prometheus.NewDesc(
		"xpf_userspace_worker_thread_cpu_seconds_total",
		"CLOCK_THREAD_CPUTIME_ID sample for the userspace-dp worker thread (#869).",
		[]string{"worker_id"}, nil,
	)
	c.workerThreadCPUSecsLast60s = prometheus.NewDesc(
		"xpf_userspace_worker_thread_cpu_seconds_last_60s",
		"CLOCK_THREAD_CPUTIME_ID consumed by the worker thread over the most recent rolling ~60s window (gauge, not counter; 0 until ~60s after worker start).",
		[]string{"worker_id"}, nil,
	)
	c.workerThreadCPUWindowSecs = prometheus.NewDesc(
		"xpf_userspace_worker_thread_cpu_window_seconds",
		"Wall-clock width of the rolling thread-CPU window matching xpf_userspace_worker_thread_cpu_seconds_last_60s; 0 until ~60s after worker start. Operators compute live CPU% as last_60s / this gauge.",
		[]string{"worker_id"}, nil,
	)
	c.workerWorkLoops = prometheus.NewDesc(
		"xpf_userspace_worker_work_loops_total",
		"Worker-loop iterations that did useful packet/ring work (#869).",
		[]string{"worker_id"}, nil,
	)
	c.workerIdleLoops = prometheus.NewDesc(
		"xpf_userspace_worker_idle_loops_total",
		"Worker-loop iterations with no useful work (#869).",
		[]string{"worker_id"}, nil,
	)
	c.workerCoSQueueLeaseAcquireV8Calls = prometheus.NewDesc(
		"xpf_userspace_worker_cos_queue_lease_acquire_v8_calls_total",
		"V8 CoS queue-lease acquire calls made by this worker (#1240).",
		[]string{"worker_id"}, nil,
	)
	c.workerCoSQueueLeaseAcquireV8GrantedBytes = prometheus.NewDesc(
		"xpf_userspace_worker_cos_queue_lease_acquire_v8_granted_bytes_total",
		"Bytes granted by v8 CoS queue-lease acquire calls for this worker (#1240).",
		[]string{"worker_id"}, nil,
	)
	// #1782 Step-1 cold-start CoS instruments.
	c.workerCoSWheelTicksAdvancedTotal = prometheus.NewDesc(
		"xpf_userspace_worker_cos_wheel_ticks_advanced_total",
		"Cumulative CoS timer-wheel ticks (50us each) advanced by advance_cos_timer_wheel across this worker's bindings — the O(lag) cold-start catch-up cost, mechanism (i) of the #1782 Step-1 disambiguation.",
		[]string{"worker_id"}, nil,
	)
	c.workerCoSWheelTicksAdvancedMax = prometheus.NewDesc(
		"xpf_userspace_worker_cos_wheel_ticks_advanced_max",
		"Largest single-call CoS timer-wheel tick advance ever observed on this worker (monotonic high-water mark, never resets). A multi-million-tick value after a cold reproduction pins the #1782 §4(i) wheel catch-up mechanism.",
		[]string{"worker_id"}, nil,
	)
	c.workerCoSQueueLeaseUndergrant = prometheus.NewDesc(
		"xpf_userspace_worker_cos_queue_lease_undergrant_total",
		"CoS exact-guarantee selector visits where the post-top-up queue tokens still could not cover the head frame, attributed to the v8 acquire shortfall cause (#1782 Step-1 mechanism (ii)); a v8-attributed subset of drain_park_queue_tokens.",
		[]string{"worker_id", "cause"}, nil,
	)
	c.workerSessionTableEntries = prometheus.NewDesc(
		"xpf_userspace_worker_session_table_entries",
		"Live session-table entries published by this userspace worker.",
		[]string{"worker_id"}, nil,
	)
	c.workerSessionTableCapacity = prometheus.NewDesc(
		"xpf_userspace_worker_session_table_capacity",
		"Maximum session-table entries supported by this userspace worker.",
		[]string{"worker_id"}, nil,
	)
	c.workerNatReverseKeyCollisions = prometheus.NewDesc(
		"xpf_userspace_worker_session_nat_reverse_key_collisions_total",
		"Cumulative NAT reverse-key (nat_reverse_index) 1:N collision "+
			"displacement events on this userspace worker's session table "+
			"(#1758/#1760 latent corruption made observable). Event count, "+
			"not a census: standing collisions after a winner's expiry and "+
			"never-replicated MissingNeighborSeed collisions are not "+
			"counted here — see the shared displacements counter.",
		[]string{"worker_id"}, nil,
	)
	c.workerSessionCreateDrops = prometheus.NewDesc(
		"xpf_userspace_worker_session_create_drops_total",
		"Cumulative session installs refused at the max_sessions cap on "+
			"this userspace worker's session table (#1861 — previously "+
			"counted internally but never exported). Covers every "+
			"capped install site (new-flow, reply repair, seed, "+
			"fabric-return, LocalMiss helper). UpsertLocal replicas "+
			"moved to the uncapped sync-family install in #1870 and "+
			"no longer contribute.",
		[]string{"worker_id"}, nil,
	)
	c.workerSessionInstallAdmissionRefused = prometheus.NewDesc(
		"xpf_userspace_worker_session_install_admission_refused_total",
		"Cumulative new flows refused (trigger packet dropped, Junos "+
			"parity) by the #1861 forward+reverse pair-admission "+
			"preflight at/near max_sessions on this userspace worker. "+
			"One increment per refused flow, not per missing slot.",
		[]string{"worker_id"}, nil,
	)
	c.workerNewFlowInstalls = prometheus.NewDesc(
		"xpf_userspace_worker_new_flow_installs_total",
		"Cumulative locally-learned transit forward flows installed on "+
			"this userspace worker — its share of the SNAT-allocate / "+
			"shared-session-publish / sibling-replication new-flow path. "+
			"rate() gives the worker's new-flows/sec; the SPREAD across "+
			"workers separates a genuine cross-worker lock bound from one "+
			"saturated RX queue, which a single aggregate rate cannot. "+
			"Excludes reverse companions, peer-synced imports, promotes "+
			"and local-delivery caches so it stays comparable to the "+
			"offered connection rate (#4800).",
		[]string{"worker_id"}, nil,
	)
	c.workerSessionInstallPartial = prometheus.NewDesc(
		"xpf_userspace_worker_session_install_partial_total",
		"Post-preflight partial session installs on this userspace "+
			"worker (#1861 release residual arms). Expected to stay 0 "+
			"forever; nonzero means the preflight/install pairing has a "+
			"bug and the dataplane degraded a flow instead of "+
			"half-committing it.",
		[]string{"worker_id"}, nil,
	)
}
