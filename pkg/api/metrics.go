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
	frrReloadDegraded   *prometheus.Desc

	// #1799: 0/1 gauge — 1 while the running active config failed to
	// persist to disk and the configstore's background retry has not
	// yet succeeded (restart would load a stale config).
	configPersistDegraded *prometheus.Desc

	// #1827: services ip-monitoring observability. #1844 adds the
	// unresolved interface-typed next-hop gauge (preferred routes of
	// FAILED policies skipped from the overlay for lack of a
	// DHCP-learned gateway).
	ipmonPolicyFailed       *prometheus.Desc
	ipmonPolicyTransitions  *prometheus.Desc
	ipmonRoutesApplied      *prometheus.Desc
	ipmonUnresolvedNextHops *prometheus.Desc

	// #1895: count of RPM next-hop probe pins whose kernel fwmark
	// rule / pinned route failed to install (affected tests hold
	// state instead of probing the default path).
	rpmPinInstallFailures *prometheus.Desc

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
	// #1359: per-queue drain-loop / shaper park-reason counters. The
	// Rust helper already carries these on the CoS snapshot (protocol.go
	// RootTokenStarvationParks / QueueTokenStarvationParks /
	// DrainParkRootTokens / DrainParkQueueTokens) but they were never
	// exported. Surfacing them lets an operator attribute a surplus-
	// sharing mouse-latency tail to ROOT-surplus arbitration (a borrower
	// holds the shared root tokens — *_root_*) versus per-queue token
	// starvation (this queue's own bucket is empty — *_queue_*).
	cosRootTokenStarvationParks  *prometheus.Desc
	cosQueueTokenStarvationParks *prometheus.Desc
	cosDrainParkRootTokens       *prometheus.Desc
	cosDrainParkQueueTokens      *prometheus.Desc
	// #1628: per-class waterfill-selector trace counters. Per-queue
	// (admissions/visits) plus per-interface (epochs/breaks/min-epochs).
	cosWaterfillPhase1Admissions   *prometheus.Desc
	cosWaterfillPhase2Admissions   *prometheus.Desc
	cosWaterfillEligibleVisits     *prometheus.Desc
	cosWaterfillEpochs             *prometheus.Desc
	cosWaterfillPhase1BudgetBreaks *prometheus.Desc
	cosWaterfillMinEpochsPerWorker *prometheus.Desc
	// #1863 Step-0: per-(queue, worker) v8 lease claim-flow counters
	// (requested vs granted bytes) + per-queue admission-path drop
	// counters. The claim-flow pair attributes the honored-realization
	// gap between share/demand mismatch and claim-sampling loss per the
	// registered decision rule (docs/research/1863-realization-gap).
	cosLeaseV8RequestedBytes   *prometheus.Desc
	cosLeaseV8GrantedBytes     *prometheus.Desc
	cosAdmissionFlowShareDrops *prometheus.Desc
	cosAdmissionBufferDrops    *prometheus.Desc
	cosAdmissionEcnMarked      *prometheus.Desc
	// #1304: Rust-owned opt-in equal-flow enforcement telemetry for
	// shared v8 CoS queue leases. Kept separate from the
	// measurement-only xpf_fairness_equal_flow_* estimator gauges.
	cosEqualFlowEnforcementEnabled       *prometheus.Desc
	cosEqualFlowTargetPolicy             *prometheus.Desc
	cosEqualFlowEnforced                 *prometheus.Desc
	cosEqualFlowTargetPerFlowBPS         *prometheus.Desc
	cosEqualFlowMaxWorkerCapBytes        *prometheus.Desc
	cosEqualFlowCapHitEvents             *prometheus.Desc
	cosEqualFlowSuppressedGrantBytes     *prometheus.Desc
	cosEqualFlowStaleOrTagMismatchEvents *prometheus.Desc
	cosEqualFlowFailOpen                 *prometheus.Desc
	// #1829 Phase 1: dequeue-time sojourn gauges. The windowed-min
	// gauge is the Phase-2 gate metric (standing-queue estimator).
	cosSojournEwmaNS        *prometheus.Desc
	cosSojournPeakNS        *prometheus.Desc
	cosSojournWindowedMinNS *prometheus.Desc
	// #1830 (g): bucket-vs-flow occupancy gauges for flow-fair CoS
	// queues (collision-vs-demand unfairness diagnosis).
	cosFlowFairBucketsOccupied *prometheus.Desc
	cosFlowFairFlowsActive     *prometheus.Desc
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
	// #1782 Step-1 cold-start CoS instruments: per-worker timer-wheel
	// tick-advance sum + single-call high-water max (mechanism (i)) and
	// the per-cause v8 queue-lease under-grant family (mechanism (ii)).
	workerCoSWheelTicksAdvancedTotal *prometheus.Desc
	workerCoSWheelTicksAdvancedMax   *prometheus.Desc
	workerCoSQueueLeaseUndergrant    *prometheus.Desc
	workerSessionTableEntries        *prometheus.Desc
	workerSessionTableCapacity       *prometheus.Desc
	workerNatReverseKeyCollisions    *prometheus.Desc
	// #1861: install-refusal trio (per-worker + aggregate).
	workerSessionCreateDrops                *prometheus.Desc
	workerSessionInstallAdmissionRefused    *prometheus.Desc
	workerSessionInstallPartial             *prometheus.Desc
	userspaceSessionCreateDrops             *prometheus.Desc
	userspaceSessionInstallAdmissionRefused *prometheus.Desc
	userspaceSessionInstallPartial          *prometheus.Desc
	userspaceSessionTableEntries            *prometheus.Desc
	userspaceSessionTableCapacity           *prometheus.Desc
	userspaceNatReverseKeyCollisions        *prometheus.Desc
	// #1789: total failed USERSPACE_SESSIONS BPF-map publishes — the
	// cause-side signal for rising XDP-shim NO_SESSION fallbacks.
	userspaceSessionPublishErrors *prometheus.Desc

	// #1760 W3': shared-map NAT reverse-key displacement events (the
	// authoritative collision watch; covers seed installs the per-worker
	// counter cannot see).
	userspaceNatReverseKeySharedDisplacements *prometheus.Desc
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
	// #1831 (follow-up to #1766): per-binding V_min fairness-throttle
	// counters (#941 work item D / #943). Already on the wire in
	// BindingStatus; these export them to Prometheus. v_min_throttles
	// is "fairness brake fired"; hard-cap overrides is "brake too
	// tight, escape hatch rescued throughput" — the ratio is the
	// LAG_THRESHOLD diagnostic.
	bindingVMinThrottles                *prometheus.Desc
	bindingVMinThrottleHardCapOverrides *prometheus.Desc
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
	// #1902: decap-refusal gate at pending_neigh admission (frame/meta
	// pairing defect class — see also #1885/#1873).
	pendingNeighDecapDropsTotal *prometheus.Desc
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
	// #1865: operator-visible WireGuard telemetry — per-tunnel
	// handshake/encap/decap counters + drop reasons from the helper's
	// wg_tunnels status rows. Label sets: {tunnel} (+ role / direction
	// / reason / kind bounded enums). The tunnel label is the tunnel
	// NAME (stable across commits; #1873 ids are not).
	wgHandshakesCompletedTotal              *prometheus.Desc
	wgHandshakeInitiationsCreatedTotal      *prometheus.Desc
	wgHandshakeInitiationBuildFailuresTotal *prometheus.Desc
	wgHandshakeRxDropsTotal                 *prometheus.Desc
	wgHandshakeRequestsArmedTotal           *prometheus.Desc
	wgTransportPacketsTotal                 *prometheus.Desc
	wgTransportBytesTotal                   *prometheus.Desc
	wgKeepalivesReceivedTotal               *prometheus.Desc
	wgTransportDropsTotal                   *prometheus.Desc
	wgSendErrorsTotal                       *prometheus.Desc
	wgSessionConfirmed                      *prometheus.Desc
	wgLastHandshakeTimeSeconds              *prometheus.Desc
	wgRekeysInitiatedTotal                  *prometheus.Desc
	wgKeepalivesSentTotal                   *prometheus.Desc
	wgSessionsExpiredTotal                  *prometheus.Desc
	wgHandshakeAttemptsAbortedTotal         *prometheus.Desc
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
	ch <- c.frrReloadDegraded
	ch <- c.configPersistDegraded
	ch <- c.ipmonPolicyFailed
	ch <- c.ipmonPolicyTransitions
	ch <- c.ipmonRoutesApplied
	ch <- c.ipmonUnresolvedNextHops
	ch <- c.rpmPinInstallFailures
	ch <- c.cosDrainLatencyBucket
	ch <- c.cosDrainInvocationsTotal
	ch <- c.cosRedirectAcquireBucket
	ch <- c.cosOwnerPPS
	ch <- c.cosPeerPPS
	ch <- c.cosDrainGuaranteeSentBytes
	ch <- c.cosDrainSurplusSentBytes
	ch <- c.cosDrainNonExactSentBytesWhileExactBacklogged
	ch <- c.cosRootTokenStarvationParks
	ch <- c.cosQueueTokenStarvationParks
	ch <- c.cosDrainParkRootTokens
	ch <- c.cosDrainParkQueueTokens
	ch <- c.cosWaterfillPhase1Admissions
	ch <- c.cosWaterfillPhase2Admissions
	ch <- c.cosWaterfillEligibleVisits
	ch <- c.cosWaterfillEpochs
	ch <- c.cosWaterfillPhase1BudgetBreaks
	ch <- c.cosWaterfillMinEpochsPerWorker
	ch <- c.cosLeaseV8RequestedBytes
	ch <- c.cosLeaseV8GrantedBytes
	ch <- c.cosAdmissionFlowShareDrops
	ch <- c.cosAdmissionBufferDrops
	ch <- c.cosAdmissionEcnMarked
	ch <- c.cosEqualFlowEnforcementEnabled
	ch <- c.cosEqualFlowTargetPolicy
	ch <- c.cosEqualFlowEnforced
	ch <- c.cosEqualFlowTargetPerFlowBPS
	ch <- c.cosEqualFlowMaxWorkerCapBytes
	ch <- c.cosEqualFlowCapHitEvents
	ch <- c.cosEqualFlowSuppressedGrantBytes
	ch <- c.cosEqualFlowStaleOrTagMismatchEvents
	ch <- c.cosEqualFlowFailOpen
	ch <- c.cosSojournEwmaNS
	ch <- c.cosSojournPeakNS
	ch <- c.cosSojournWindowedMinNS
	ch <- c.cosFlowFairBucketsOccupied
	ch <- c.cosFlowFairFlowsActive
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
	ch <- c.workerCoSWheelTicksAdvancedTotal
	ch <- c.workerCoSWheelTicksAdvancedMax
	ch <- c.workerCoSQueueLeaseUndergrant
	ch <- c.workerSessionTableEntries
	ch <- c.workerSessionTableCapacity
	ch <- c.workerNatReverseKeyCollisions
	ch <- c.workerSessionCreateDrops
	ch <- c.workerSessionInstallAdmissionRefused
	ch <- c.workerSessionInstallPartial
	ch <- c.userspaceSessionCreateDrops
	ch <- c.userspaceSessionInstallAdmissionRefused
	ch <- c.userspaceSessionInstallPartial
	ch <- c.userspaceSessionTableEntries
	ch <- c.userspaceSessionTableCapacity
	ch <- c.userspaceNatReverseKeyCollisions
	ch <- c.userspaceSessionPublishErrors
	ch <- c.userspaceNatReverseKeySharedDisplacements
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
	ch <- c.bindingVMinThrottles
	ch <- c.bindingVMinThrottleHardCapOverrides
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
	ch <- c.pendingNeighDecapDropsTotal
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
	ch <- c.wgHandshakesCompletedTotal
	ch <- c.wgHandshakeInitiationsCreatedTotal
	ch <- c.wgHandshakeInitiationBuildFailuresTotal
	ch <- c.wgHandshakeRxDropsTotal
	ch <- c.wgHandshakeRequestsArmedTotal
	ch <- c.wgTransportPacketsTotal
	ch <- c.wgTransportBytesTotal
	ch <- c.wgKeepalivesReceivedTotal
	ch <- c.wgTransportDropsTotal
	ch <- c.wgSendErrorsTotal
	ch <- c.wgSessionConfirmed
	ch <- c.wgLastHandshakeTimeSeconds
	ch <- c.wgRekeysInitiatedTotal
	ch <- c.wgKeepalivesSentTotal
	ch <- c.wgSessionsExpiredTotal
	ch <- c.wgHandshakeAttemptsAbortedTotal
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

	// #1880: FRR reload-degraded is likewise a control-plane signal
	// (the daemon applies FRR even in config-only mode) — emit it
	// BEFORE the dataplane gate so it never disappears exactly when
	// the fallback path is active.
	if c.srv.frrReloadDegradedFn != nil {
		v := 0.0
		if c.srv.frrReloadDegradedFn() {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.frrReloadDegraded,
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
