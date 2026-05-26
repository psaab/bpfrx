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
	userspaceSessionTableEntries             *prometheus.Desc
	userspaceSessionTableCapacity            *prometheus.Desc
	userspaceFlowCacheActiveFlows            *prometheus.Desc
	userspaceFlowCacheCapacity               *prometheus.Desc
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
	ch <- c.cosDrainLatencyBucket
	ch <- c.cosDrainInvocationsTotal
	ch <- c.cosRedirectAcquireBucket
	ch <- c.cosOwnerPPS
	ch <- c.cosPeerPPS
	ch <- c.cosDrainGuaranteeSentBytes
	ch <- c.cosDrainSurplusSentBytes
	ch <- c.cosDrainNonExactSentBytesWhileExactBacklogged
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
	ch <- c.userspaceSessionTableEntries
	ch <- c.userspaceSessionTableCapacity
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
}

func (c *xpfCollector) Collect(ch chan<- prometheus.Metric) {
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
