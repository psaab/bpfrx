package api

import (
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// xpfCollector implements prometheus.Collector, reading BPF maps on each scrape.
type xpfCollector struct {
	srv *Server
	mu  sync.Mutex

	// Global counters
	packetsTotal         *prometheus.Desc
	dropsTotal           *prometheus.Desc
	sessionsCreatedTotal *prometheus.Desc
	sessionsClosedTotal  *prometheus.Desc
	screenDropsTotal     *prometheus.Desc
	policyDeniesTotal    *prometheus.Desc
	natAllocFailsTotal   *prometheus.Desc
	hostInboundDeny      *prometheus.Desc
	tcEgressPacketsTotal *prometheus.Desc
	syncookieTotal       *prometheus.Desc
	flowCacheTotal       *prometheus.Desc

	// Interface counters
	ifacePacketsTotal *prometheus.Desc
	ifaceBytesTotal   *prometheus.Desc

	// Zone counters
	zonePacketsTotal *prometheus.Desc
	zoneBytesTotal   *prometheus.Desc

	// Policy counters
	policyHitsTotal *prometheus.Desc

	// Filter counters
	filterHitsTotal *prometheus.Desc
	// Userspace three-color policer counters.
	threeColorPolicerPacketsTotal *prometheus.Desc
	threeColorPolicerBytesTotal   *prometheus.Desc
	threeColorPolicerDropsTotal   *prometheus.Desc
	threeColorPolicerDropBytes    *prometheus.Desc

	// Session gauges (from GC)
	sessionsActive      *prometheus.Desc
	sessionsEstablished *prometheus.Desc
	sessionsIPv4        *prometheus.Desc
	sessionsIPv6        *prometheus.Desc
	sessionsSNAT        *prometheus.Desc
	sessionsDNAT        *prometheus.Desc
	gcSweepDuration     *prometheus.Desc

	// NAT pool utilization
	natPoolUsedPorts                  *prometheus.Desc
	natPoolTotalPorts                 *prometheus.Desc
	natPoolDeterministicInfo          *prometheus.Desc
	userspaceSNATPoolLiveFlows        *prometheus.Desc
	userspaceSNATPoolUsedPorts        *prometheus.Desc
	userspaceSNATPoolPersistentLeases *prometheus.Desc
	userspaceSNATPoolAllocationsTotal *prometheus.Desc
	userspaceSNATPoolReusesTotal      *prometheus.Desc
	userspaceSNATPoolExhaustionsTotal *prometheus.Desc

	// DHCP lease gauge
	dhcpLeasesActive *prometheus.Desc

	// System metrics
	sysCPUUser   *prometheus.Desc
	sysCPUSystem *prometheus.Desc
	sysMemTotal  *prometheus.Desc
	sysMemAvail  *prometheus.Desc
	daemonUptime *prometheus.Desc
	daemonMemRSS *prometheus.Desc

	// #1780: per-phase age of the Go periodic neighbor-maintenance loop.
	neighborPeriodicAge *prometheus.Desc

	// #1799: 0/1 gauge — 1 while the running active config failed to
	// persist to disk and the configstore's background retry has not
	// yet succeeded (restart would load a stale config).
	configPersistDegraded *prometheus.Desc

	// #709: CoS owner-profile telemetry (userspace dataplane only).
	// Cardinality estimate per plan §5: num_queues (≤ 64) × num_interfaces
	// (≤ 8) × DRAIN_HIST_BUCKETS (16) = ≤ 8192 series for each of the
	// two histograms. The two gauges (owner_pps, peer_pps) add 512
	// more. Total ≤ 16896 series — within the envelope the plan
	// flagged.
	cosDrainLatencyBucket    *prometheus.Desc
	cosDrainInvocationsTotal *prometheus.Desc
	cosRedirectAcquireBucket *prometheus.Desc
	cosOwnerPPS              *prometheus.Desc
	cosPeerPPS               *prometheus.Desc
	// #1369: queue-scoped drain-phase counters. Unlike the owner
	// latency profile, these are meaningful for non-exact queues
	// too, because they expose whether best-effort/uncapped traffic
	// consumed service while exact queues still had backlog.
	cosDrainGuaranteeSentBytes                    *prometheus.Desc
	cosDrainSurplusSentBytes                      *prometheus.Desc
	cosDrainNonExactSentBytesWhileExactBacklogged *prometheus.Desc
	// #1628: per-class waterfill-selector trace counters. Per-queue
	// (admissions/visits) plus per-interface (epochs/breaks/min-epochs).
	cosWaterfillPhase1Admissions   *prometheus.Desc
	cosWaterfillPhase2Admissions   *prometheus.Desc
	cosWaterfillEligibleVisits     *prometheus.Desc
	cosWaterfillEpochs             *prometheus.Desc
	cosWaterfillPhase1BudgetBreaks *prometheus.Desc
	cosWaterfillMinEpochsPerWorker *prometheus.Desc
	// #1304: Rust-owned opt-in equal-flow enforcement telemetry for
	// shared v8 CoS queue leases. Kept separate from the
	// measurement-only xpf_fairness_equal_flow_* estimator gauges.
	cosEqualFlowEnforcementEnabled       *prometheus.Desc
	cosEqualFlowEnforced                 *prometheus.Desc
	cosEqualFlowTargetPerFlowBPS         *prometheus.Desc
	cosEqualFlowMaxWorkerCapBytes        *prometheus.Desc
	cosEqualFlowCapHitEvents             *prometheus.Desc
	cosEqualFlowSuppressedGrantBytes     *prometheus.Desc
	cosEqualFlowStaleOrTagMismatchEvents *prometheus.Desc
	cosEqualFlowFailOpen                 *prometheus.Desc
	// #869: per-worker busy/idle runtime counters.
	workerWallSecs                           *prometheus.Desc
	workerActiveSecs                         *prometheus.Desc
	workerIdleSpinSecs                       *prometheus.Desc
	workerIdleBlockSecs                      *prometheus.Desc
	workerThreadCPUSecs                      *prometheus.Desc
	workerThreadCPUSecsLast60s               *prometheus.Desc
	workerThreadCPUWindowSecs                *prometheus.Desc
	workerWorkLoops                          *prometheus.Desc
	workerIdleLoops                          *prometheus.Desc
	workerCoSQueueLeaseAcquireV8Calls        *prometheus.Desc
	workerCoSQueueLeaseAcquireV8GrantedBytes *prometheus.Desc
	workerSessionTableEntries                *prometheus.Desc
	workerSessionTableCapacity               *prometheus.Desc
	workerNatReverseKeyCollisions            *prometheus.Desc
	userspaceSessionTableEntries             *prometheus.Desc
	userspaceSessionTableCapacity            *prometheus.Desc
	userspaceNatReverseKeyCollisions         *prometheus.Desc
	// #1789: total failed USERSPACE_SESSIONS BPF-map publishes — the
	// cause-side signal for rising XDP-shim NO_SESSION fallbacks.
	userspaceSessionPublishErrors *prometheus.Desc
	// #1807: worker-command-queue poison recoveries — nonzero means a
	// helper worker panic poisoned a command queue and it was recovered
	// (committed-prefix + clear_poison policy) instead of going deaf.
	userspaceWorkerCommandQueuePoisonRecoveries *prometheus.Desc
	userspaceFlowCacheActiveFlows               *prometheus.Desc
	userspaceFlowCacheCapacity                  *prometheus.Desc
	// #1379: daemon-side userspace event-stream transport counters.
	userspaceEventStreamFramesTotal          *prometheus.Desc
	userspaceEventStreamProducerFramesTotal  *prometheus.Desc
	userspaceEventStreamDecodeErrorsTotal    *prometheus.Desc
	userspaceEventStreamSequenceGapsTotal    *prometheus.Desc
	userspaceEventStreamDataplaneEventsTotal *prometheus.Desc
	userspaceEventStreamDataplaneDropsTotal  *prometheus.Desc
	userspaceEventStreamUnknownDropsTotal    *prometheus.Desc
	// #925 Phase 2: liveness gauge for the supervisor's catch_unwind
	// state. 1 = worker has panicked and the supervisor has caught it;
	// 0 = healthy. Set-only in Phase 1 (cleared by daemon restart).
	workerDead *prometheus.Desc
	// #1621: cold-path latency histogram surface (#1612 step-3).
	// Per worker / zone-pair-slot histogram of policy-eval slow path
	// latency. The 24-bucket power-of-two histogram lives on the
	// dataplane side; we expose it here as a Prometheus-native
	// `_bucket{le="..."}` counter family compatible with PromQL
	// histogram_quantile().
	workerColdPathBucket              *prometheus.Desc
	workerColdPathSamples             *prometheus.Desc
	workerColdPathSumNS               *prometheus.Desc
	workerColdPathAliasSeen           *prometheus.Desc
	workerColdPathSamplePhase         *prometheus.Desc
	workerColdPathWrapperUnderflow    *prometheus.Desc
	workerColdPathWrapperNSBaseline   *prometheus.Desc
	workerColdPathNSPerTSCQ32         *prometheus.Desc
	workerColdPathClockSource         *prometheus.Desc
	workerColdPathSnapshotFailedTotal *prometheus.Desc
	// #1635 sparse v3 per-zone-pair families (from_zone/to_zone labels).
	workerColdPathBucketV3           *prometheus.Desc
	workerColdPathSamplesV3          *prometheus.Desc
	workerColdPathSumNSV3            *prometheus.Desc
	workerColdPathBuilderCollisionV3 *prometheus.Desc
	workerColdPathOverflowActive     *prometheus.Desc
	workerColdPathLayoutVersion      *prometheus.Desc
	workerColdPathLayoutUnknownTotal *prometheus.Desc
	// #1219: snapshot per-binding distinct active flow count for the
	// fairness harness (read by test/incus/fairness-harness.sh ->
	// fairness-eval to compute Cstruct + observed_CoV per
	// docs/fairness-regimes.md). Refreshed at the helper's ~65ms
	// debug-state tick.
	bindingActiveFlowCount   *prometheus.Desc
	bindingFlowCacheCapacity *prometheus.Desc
	// #1241: per-binding AF_XDP TX completion service telemetry.
	// These signals let fairness measurements distinguish scheduler/RSS
	// skew from per-queue completion-ring service asymmetry.
	bindingTXCompletions                *prometheus.Desc
	bindingTXCompletionRingAvailable    *prometheus.Desc
	bindingTXCompletionRingAvailableMax *prometheus.Desc
	// #1248: class-specific active flow distribution by egress CoS
	// queue. This is the production/mixed-workload {a_i} source.
	cosActiveFlowCount *prometheus.Desc
	// #1247: production RSS/workload health gauges derived from the
	// same per-CoS {a_i} snapshot. These expose the structural ceiling
	// without adding packet-path state or global atomics.
	fairnessCstruct                           *prometheus.Desc
	fairnessActiveWorkers                     *prometheus.Desc
	fairnessActiveFlows                       *prometheus.Desc
	fairnessMaxWorkerFlowShare                *prometheus.Desc
	fairnessCoSCountsTruncated                *prometheus.Desc
	fairnessRSSExpectation                    *prometheus.Desc
	fairnessRSSExpectationValue               *prometheus.Desc
	fairnessRSSSkewViolation                  *prometheus.Desc
	fairnessSaturated                         *prometheus.Desc
	fairnessObservedCoV                       *prometheus.Desc
	fairnessStarvedFlows                      *prometheus.Desc
	fairnessEqualFlowEstimateValid            *prometheus.Desc
	fairnessEqualFlowSampledActiveWorkers     *prometheus.Desc
	fairnessEqualFlowUnsampledActiveWorkers   *prometheus.Desc
	fairnessEqualFlowTargetPerFlowBPS         *prometheus.Desc
	fairnessEqualFlowObservedBPS              *prometheus.Desc
	fairnessEqualFlowCappedBPS                *prometheus.Desc
	fairnessEqualFlowSuppressedBPS            *prometheus.Desc
	fairnessEqualFlowThroughputLossRatio      *prometheus.Desc
	fairnessEqualFlowWorkerObservedBPS        *prometheus.Desc
	fairnessEqualFlowWorkerObservedPerFlowBPS *prometheus.Desc
	fairnessEqualFlowWorkerCapBPS             *prometheus.Desc
	fairnessEqualFlowWorkerSuppressedBPS      *prometheus.Desc
	fairnessThroughputWindow                  *dpuserspace.FairnessThroughputWindow
	// #1636 option C: proactive-neighbor-warm telemetry. The only
	// operator-visible signal for the warmer in production builds.
	neighborWarmDropsTotal        *prometheus.Desc
	neighborWarmDisconnectedTotal *prometheus.Desc
	// #1782 cold-start capture instrumentation. negNeighFastFailTotal is
	// the H1 amplifier signal; pendingNeighDuplicateDropsTotal is the H5
	// sibling-drop signal; dynamicNeighborPresent is a per-key presence
	// gauge dumped from the helper's dynamic_neighbors mirror so the
	// capture harness can grep the t0' next-hop membership (H2).
	negNeighFastFailTotal           *prometheus.Desc
	pendingNeighDuplicateDropsTotal *prometheus.Desc
	dynamicNeighborPresent          *prometheus.Desc
	// #1769: on-demand neighbor-resolver telemetry — the operator-visible
	// signal for the MissingNeighbor stuck-state.
	neighborResolverQueueDepth        *prometheus.Desc
	neighborResolverEnqueueDropsTotal *prometheus.Desc
	neighborResolverDisconnectedTotal *prometheus.Desc
	neighborResolverGetAttemptsTotal  *prometheus.Desc
	neighborResolverGetResolvedTotal  *prometheus.Desc
	neighborResolverProbeOnStaleTotal *prometheus.Desc
	neighborResolverGetFailuresTotal  *prometheus.Desc
	neighborResolverEpochRejectsTotal *prometheus.Desc
	// #1772: neighbor/ARP resolution LATENCY histograms + counters.
	neighborPendingDwellSeconds      *prometheus.Desc
	neighborResolverGetRttSeconds    *prometheus.Desc
	neighborPendingTimeoutDropsTotal *prometheus.Desc
	neighborPendingMaxDepth          *prometheus.Desc
	// #1771 §2.6: resolver backoff-retry counter, §2.5 ENOBUFS/re-dump
	// counters, and the pending-keys / negative-keys gauges.
	neighborResolverGetBackoffAttemptsTotal *prometheus.Desc
	neighborNetlinkEnobufsTotal             *prometheus.Desc
	neighborNetlinkRedumpsTotal             *prometheus.Desc
	neighborNetlinkRedumpUpsertsTotal       *prometheus.Desc
	neighborPendingKeys                     *prometheus.Desc
	negNeighKeys                            *prometheus.Desc
}

func (c *xpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packetsTotal
	ch <- c.dropsTotal
	ch <- c.sessionsCreatedTotal
	ch <- c.sessionsClosedTotal
	ch <- c.screenDropsTotal
	ch <- c.policyDeniesTotal
	ch <- c.natAllocFailsTotal
	ch <- c.hostInboundDeny
	ch <- c.tcEgressPacketsTotal
	ch <- c.syncookieTotal
	ch <- c.flowCacheTotal
	ch <- c.ifacePacketsTotal
	ch <- c.ifaceBytesTotal
	ch <- c.zonePacketsTotal
	ch <- c.zoneBytesTotal
	ch <- c.policyHitsTotal
	ch <- c.filterHitsTotal
	ch <- c.threeColorPolicerPacketsTotal
	ch <- c.threeColorPolicerBytesTotal
	ch <- c.threeColorPolicerDropsTotal
	ch <- c.threeColorPolicerDropBytes
	ch <- c.sessionsActive
	ch <- c.sessionsEstablished
	ch <- c.sessionsIPv4
	ch <- c.sessionsIPv6
	ch <- c.sessionsSNAT
	ch <- c.sessionsDNAT
	ch <- c.gcSweepDuration
	ch <- c.natPoolUsedPorts
	ch <- c.natPoolTotalPorts
	ch <- c.natPoolDeterministicInfo
	ch <- c.userspaceSNATPoolLiveFlows
	ch <- c.userspaceSNATPoolUsedPorts
	ch <- c.userspaceSNATPoolPersistentLeases
	ch <- c.userspaceSNATPoolAllocationsTotal
	ch <- c.userspaceSNATPoolReusesTotal
	ch <- c.userspaceSNATPoolExhaustionsTotal
	ch <- c.dhcpLeasesActive
	ch <- c.sysCPUUser
	ch <- c.sysCPUSystem
	ch <- c.sysMemTotal
	ch <- c.sysMemAvail
	ch <- c.daemonUptime
	ch <- c.daemonMemRSS
	ch <- c.neighborPeriodicAge
	ch <- c.configPersistDegraded
	ch <- c.cosDrainLatencyBucket
	ch <- c.cosDrainInvocationsTotal
	ch <- c.cosRedirectAcquireBucket
	ch <- c.cosOwnerPPS
	ch <- c.cosPeerPPS
	ch <- c.cosDrainGuaranteeSentBytes
	ch <- c.cosDrainSurplusSentBytes
	ch <- c.cosDrainNonExactSentBytesWhileExactBacklogged
	ch <- c.cosWaterfillPhase1Admissions
	ch <- c.cosWaterfillPhase2Admissions
	ch <- c.cosWaterfillEligibleVisits
	ch <- c.cosWaterfillEpochs
	ch <- c.cosWaterfillPhase1BudgetBreaks
	ch <- c.cosWaterfillMinEpochsPerWorker
	ch <- c.cosEqualFlowEnforcementEnabled
	ch <- c.cosEqualFlowEnforced
	ch <- c.cosEqualFlowTargetPerFlowBPS
	ch <- c.cosEqualFlowMaxWorkerCapBytes
	ch <- c.cosEqualFlowCapHitEvents
	ch <- c.cosEqualFlowSuppressedGrantBytes
	ch <- c.cosEqualFlowStaleOrTagMismatchEvents
	ch <- c.cosEqualFlowFailOpen
	ch <- c.workerWallSecs
	ch <- c.workerActiveSecs
	ch <- c.workerIdleSpinSecs
	ch <- c.workerIdleBlockSecs
	ch <- c.workerThreadCPUSecs
	ch <- c.workerThreadCPUSecsLast60s
	ch <- c.workerThreadCPUWindowSecs
	ch <- c.workerWorkLoops
	ch <- c.workerIdleLoops
	ch <- c.workerCoSQueueLeaseAcquireV8Calls
	ch <- c.workerCoSQueueLeaseAcquireV8GrantedBytes
	ch <- c.workerSessionTableEntries
	ch <- c.workerSessionTableCapacity
	ch <- c.workerNatReverseKeyCollisions
	ch <- c.userspaceSessionTableEntries
	ch <- c.userspaceSessionTableCapacity
	ch <- c.userspaceNatReverseKeyCollisions
	ch <- c.userspaceSessionPublishErrors
	ch <- c.userspaceWorkerCommandQueuePoisonRecoveries
	ch <- c.userspaceFlowCacheActiveFlows
	ch <- c.userspaceFlowCacheCapacity
	ch <- c.userspaceEventStreamFramesTotal
	ch <- c.userspaceEventStreamProducerFramesTotal
	ch <- c.userspaceEventStreamDecodeErrorsTotal
	ch <- c.userspaceEventStreamSequenceGapsTotal
	ch <- c.userspaceEventStreamDataplaneEventsTotal
	ch <- c.userspaceEventStreamDataplaneDropsTotal
	ch <- c.userspaceEventStreamUnknownDropsTotal
	ch <- c.workerDead
	// #1635: cold-path histogram descriptors. xpfCollector is a CHECKED
	// collector — every Desc emitted by Collect() (via emitWorkerColdPath)
	// MUST be declared here, or promhttp logs a Gather error on every
	// scrape and a HTTPErrorOnError registry returns 500. The v1 +
	// scalar descs were never declared (a latent gap from #1619/#1621);
	// the v3 descs added in #1635 widened it. Declare the whole family.
	ch <- c.workerColdPathBucket
	ch <- c.workerColdPathSamples
	ch <- c.workerColdPathSumNS
	ch <- c.workerColdPathAliasSeen
	ch <- c.workerColdPathSamplePhase
	ch <- c.workerColdPathWrapperUnderflow
	ch <- c.workerColdPathWrapperNSBaseline
	ch <- c.workerColdPathNSPerTSCQ32
	ch <- c.workerColdPathClockSource
	ch <- c.workerColdPathSnapshotFailedTotal
	ch <- c.workerColdPathBucketV3
	ch <- c.workerColdPathSamplesV3
	ch <- c.workerColdPathSumNSV3
	ch <- c.workerColdPathBuilderCollisionV3
	ch <- c.workerColdPathOverflowActive
	ch <- c.workerColdPathLayoutVersion
	ch <- c.workerColdPathLayoutUnknownTotal
	ch <- c.bindingActiveFlowCount
	ch <- c.bindingFlowCacheCapacity
	ch <- c.bindingTXCompletions
	ch <- c.bindingTXCompletionRingAvailable
	ch <- c.bindingTXCompletionRingAvailableMax
	ch <- c.cosActiveFlowCount
	ch <- c.fairnessCstruct
	ch <- c.fairnessActiveWorkers
	ch <- c.fairnessActiveFlows
	ch <- c.fairnessMaxWorkerFlowShare
	ch <- c.fairnessCoSCountsTruncated
	ch <- c.fairnessRSSExpectation
	ch <- c.fairnessRSSExpectationValue
	ch <- c.fairnessRSSSkewViolation
	ch <- c.fairnessSaturated
	ch <- c.fairnessObservedCoV
	ch <- c.fairnessStarvedFlows
	ch <- c.fairnessEqualFlowEstimateValid
	ch <- c.fairnessEqualFlowSampledActiveWorkers
	ch <- c.fairnessEqualFlowUnsampledActiveWorkers
	ch <- c.fairnessEqualFlowTargetPerFlowBPS
	ch <- c.fairnessEqualFlowObservedBPS
	ch <- c.fairnessEqualFlowCappedBPS
	ch <- c.fairnessEqualFlowSuppressedBPS
	ch <- c.fairnessEqualFlowThroughputLossRatio
	ch <- c.fairnessEqualFlowWorkerObservedBPS
	ch <- c.fairnessEqualFlowWorkerObservedPerFlowBPS
	ch <- c.fairnessEqualFlowWorkerCapBPS
	ch <- c.fairnessEqualFlowWorkerSuppressedBPS
	ch <- c.neighborWarmDropsTotal
	ch <- c.neighborWarmDisconnectedTotal
	ch <- c.negNeighFastFailTotal
	ch <- c.pendingNeighDuplicateDropsTotal
	ch <- c.dynamicNeighborPresent
	ch <- c.neighborResolverQueueDepth
	ch <- c.neighborResolverEnqueueDropsTotal
	ch <- c.neighborResolverDisconnectedTotal
	ch <- c.neighborResolverGetAttemptsTotal
	ch <- c.neighborResolverGetResolvedTotal
	ch <- c.neighborResolverProbeOnStaleTotal
	ch <- c.neighborResolverGetFailuresTotal
	ch <- c.neighborResolverEpochRejectsTotal
	ch <- c.neighborPendingDwellSeconds
	ch <- c.neighborResolverGetRttSeconds
	ch <- c.neighborPendingTimeoutDropsTotal
	ch <- c.neighborPendingMaxDepth
	ch <- c.neighborResolverGetBackoffAttemptsTotal
	ch <- c.neighborNetlinkEnobufsTotal
	ch <- c.neighborNetlinkRedumpsTotal
	ch <- c.neighborNetlinkRedumpUpsertsTotal
	ch <- c.neighborPendingKeys
	ch <- c.negNeighKeys
}

func (c *xpfCollector) Collect(ch chan<- prometheus.Metric) {
	// #1799: config-persist health is a control-plane signal — emit it
	// BEFORE the dataplane gate below so the degraded state stays
	// visible even when the dataplane is not loaded.
	if c.srv.configPersistDegradedFn != nil {
		v := 0.0
		if c.srv.configPersistDegradedFn() {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.configPersistDegraded,
			prometheus.GaugeValue, v)
	}

	dp := c.srv.dp
	if dp == nil || !dp.IsLoaded() {
		return
	}

	c.collectGlobalCounters(ch, dp)
	c.collectInterfaceCounters(ch, dp)
	c.collectZoneCounters(ch, dp)
	c.collectPolicyCounters(ch, dp)
	c.collectFilterCounters(ch, dp)
	c.collectSessionGauges(ch, dp)
	c.collectNATPoolMetrics(ch, dp)
	c.collectDHCPMetrics(ch)
	c.collectSystemMetrics(ch)
	c.collectUserspaceStatus(ch, dp)
}

// #709: emit per-bucket counter samples. Bucket index maps to a
// power-of-two ns upper bound; see Rust `bucket_index_for_ns` and
// cosfmt.go `bucketLowerBoundMicros` for the shared layout. Label is
// the upper bound so Prometheus histogram consumers can plot a
// rate()-based le-histogram without needing the Rust-side layout
// inlined in promql.
func emitHistogram(ch chan<- prometheus.Metric, desc *prometheus.Desc, hist []uint64, ifindexLabel, queueLabel string) {
	for i, count := range hist {
		upperNs := bucketUpperBoundNs(i)
		ch <- prometheus.MustNewConstMetric(
			desc,
			prometheus.CounterValue,
			float64(count),
			ifindexLabel,
			queueLabel,
			strconv.FormatUint(upperNs, 10),
		)
	}
}

// #709: upper-bound ns for histogram bucket index `i`. Bucket 0 is
// [0, 1024 ns) — upper bound 1024. Bucket N (N >= 1) is
// [2^(N+9), 2^(N+10)) — upper bound 2^(N+10). Bucket 15 (top bucket)
// saturates at 2^24 and we report upper bound = math.MaxUint64-safe
// value (2^25) as the "+Inf" sentinel.
func bucketUpperBoundNs(i int) uint64 {
	if i <= 0 {
		return 1024
	}
	return uint64(1) << uint(i+10)
}

func policyCounterID(policySetID uint32, ruleIndex int) uint32 {
	return policySetID*dataplane.MaxRulesPerPolicy + uint32(ruleIndex)
}
