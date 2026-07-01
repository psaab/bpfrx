package api

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"

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
	// #3343: per-screen-reason drop counter, labeled by reason. The aggregate
	// xpf_screen_drops_total above cannot answer "which screen fired?"; this
	// labeled series can, now that the userspace bridge populates the per-reason
	// GlobalCtrScreen* counters.
	screenDropsByReasonTotal *prometheus.Desc
	policyDeniesTotal        *prometheus.Desc
	natAllocFailsTotal       *prometheus.Desc
	nat64XlateTotal          *prometheus.Desc
	hostInboundDeny          *prometheus.Desc
	hostInboundKernelDenies  *prometheus.Desc
	tcEgressPacketsTotal     *prometheus.Desc
	syncookieTotal           *prometheus.Desc
	flowCacheTotal           *prometheus.Desc

	// #3345/#3408: monotonic count of counter reads that failed during a
	// scrape, across the global, per-zone, per-policy, and per-filter dataplane
	// collectors AND the kernel-nftables host-inbound collector (#3361). A
	// failed read SKIPS emitting that counter's sample (so a degraded counter
	// bridge does NOT report a misleading 0); this metric is the scrape-error
	// signal an operator alerts on. Persisted on the collector so it accumulates
	// across scrapes like a real counter. #3462: the SAMPLE is emitted last in
	// Collect (emitCounterReadErrors), after all collectors that can bump it, so
	// a failure this scrape is reflected this scrape.
	counterReadErrorsTotal *prometheus.Desc
	counterReadErrors      atomic.Uint64

	// Interface counters
	ifacePacketsTotal *prometheus.Desc
	ifaceBytesTotal   *prometheus.Desc
	// #3464: monotonic count of per-interface counter reads that failed during
	// a scrape. A failed read SKIPS that interface's xpf_interface_* samples
	// (so a degraded counter bridge does NOT report a misleading 0); this
	// metric is the scrape-error signal for interface counters. Kept SEPARATE
	// from counterReadErrorsTotal because interface counters are intentionally
	// out of the #3345 security-counter contract (README "Out of scope"), so
	// an operator can alert on a degraded interface-counter bridge without
	// conflating it with security-counter health. The SAMPLE is emitted last in
	// Collect (emitInterfaceCounterReadErrors), after collectInterfaceCounters,
	// so a failure this scrape is reflected this scrape.
	interfaceCounterReadErrorsTotal *prometheus.Desc
	interfaceCounterReadErrors      atomic.Uint64

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
	sessionScrapeOK     *prometheus.Desc
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

	// DHCP dynamic-DNS metrics (#1387 inc-2)
	dhcpDDNSUpsertsTotal       *prometheus.Desc
	dhcpDDNSDeletesTotal       *prometheus.Desc
	dhcpDDNSReconcileRunsTotal *prometheus.Desc
	dhcpDDNSSkippedTotal       *prometheus.Desc
	dhcpDDNSOwnedRecords       *prometheus.Desc
	dhcpDDNSPTRPending         *prometheus.Desc
	dhcpDDNSDegraded           *prometheus.Desc
	dhcpDDNSLastReconcileTs    *prometheus.Desc
	dhcpDDNSLastReconcileN     *prometheus.Desc

	// Surface A (router/interface-address) DDNS metrics (#2691 P2).
	surfaceADDNSUpsertsTotal *prometheus.Desc
	surfaceADDNSDeletesTotal *prometheus.Desc
	surfaceADDNSSkippedTotal *prometheus.Desc
	surfaceADDNSScopes       *prometheus.Desc
	surfaceADDNSDegraded     *prometheus.Desc

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

	// #3441: 0/1 gauge — 1 while the most recent commit failed to durably
	// write its text rollback-history files (the canonical rollback
	// history; loadRollbackHistory reads them at boot). The commit itself
	// still succeeded — the active config persisted via the #1799 path —
	// so this is an observability signal for a degraded recovery aid, not
	// a forwarding/durability emergency.
	rollbackHistoryDegraded *prometheus.Desc

	// #3261: 0/1 gauge — 1 while the most recently built userspace snapshot
	// carries unrepresentable policy content that the helper integrity
	// preflight rejects (previous-good retained / fresh-boot default-deny —
	// never fail-open). Nonzero means the running dataplane policy is NOT the
	// committed config; edit out the offending application/address and
	// re-commit. Surfaces the deliberate Go/Rust skew (ForwardingSupported=true
	// while the helper rejected the snapshot) so it is observable.
	userspacePolicyContentRejected *prometheus.Desc

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

	// #2157: event-options remediation action observability. Makes the
	// previously-silent loss (drop on held config lock) visible.
	eventActionsCommitted  *prometheus.Desc
	eventActionsRejected   *prometheus.Desc
	eventActionsRetried    *prometheus.Desc
	eventActionsDropped    *prometheus.Desc
	eventAttributesInvalid *prometheus.Desc
	eventActionQueueDepth  *prometheus.Desc

	// #2050: dynamic-address feed staleness. seconds-since-last-success
	// climbs while a feed cannot be refreshed (retain-forever default
	// keeps the last-good snapshot enforced indefinitely); the stale
	// gauge is 1 while a retained snapshot is being served as stale.
	feedSecondsSinceSuccess *prometheus.Desc
	feedStale               *prometheus.Desc

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

	// #2244: total failed dnat_table reverse-SNAT BPF-map publishes — the
	// cause-side signal for dnat_table map-capacity pressure that silently
	// breaks embedded-ICMP NAT reversal (PMTUD / traceroute).
	userspaceDnatPublishErrors *prometheus.Desc

	// #1760 W3': shared-map NAT reverse-key displacement events (the
	// authoritative collision watch; covers seed installs the per-worker
	// counter cannot see).
	userspaceNatReverseKeySharedDisplacements *prometheus.Desc
	// #1807: worker-command-queue poison recoveries — nonzero means a
	// helper worker panic poisoned a command queue and it was recovered
	// (committed-prefix + clear_poison policy) instead of going deaf.
	userspaceWorkerCommandQueuePoisonRecoveries *prometheus.Desc
	// #2315: GRE-decap RFC 6040 §4.2 illegal-combination drops (outer CE
	// over a Not-ECT inner) — nonzero flags a misbehaving tunnel ingress
	// that ECT-marked the outer for un-ECN inner traffic on a congested
	// path.
	userspaceGreDecapEcnIllegalDrops *prometheus.Desc
	// #2317: WG-decap RFC 6040 §4.2 illegal-combination drops (outer CE,
	// captured via recvmsg IP_RECVTOS/IPV6_RECVTCLASS, over a Not-ECT
	// inner) — the WG sibling of the GRE counter above.
	userspaceWgDecapEcnIllegalDrops *prometheus.Desc
	// #2331: native-GRE encap frames dropped because the fully built outer
	// datagram exceeded the resolved transport/egress MTU while the IPv4
	// outer carries DF=1 (the only outer the native builder emits). A
	// DF-set oversized outer cannot be fragmented downstream and would
	// silently blackhole every inner flow with no PMTUD signal.
	userspaceGreEncapDfOversizeDrops *prometheus.Desc
	// #2782: native-GRE decap frames dropped because the Checksum-Present
	// (C) bit was set but the GRE checksum failed to verify (or the header
	// was truncated past the 4-byte Checksum+Reserved1 field). A
	// checksummed peer (e.g. vSRX) now decaps after skipping+validating
	// the checksum (RFC 2784 §2.1 / RFC 2890) instead of being silently
	// blackholed; only a corrupt frame is counted here.
	userspaceGreDecapChecksumInvalidDrops *prometheus.Desc
	// #2472: locally-generated ICMP/RST error replies dropped by the
	// per-reason token-bucket rate limiter (Time Exceeded / PTB / reject).
	userspaceTimeExceededRateLimited *prometheus.Desc
	userspacePacketTooBigRateLimited *prometheus.Desc
	userspaceRejectRateLimited       *prometheus.Desc
	// #3657 (H15/M02) / #3661: source-split reject reply telemetry. The
	// aggregate userspaceRejectRateLimited above stays for back-compat; these
	// expose the #3615 per-BindingStatus sent / TX-frame reply-budget /
	// egress output-filter drop legs plus the #3661 rate-limit drop leg,
	// labeled source=policy|filter, so alerting can attribute reject SUCCESS
	// vs SUPPRESSION to a security policy `then reject` or a firewall-filter
	// `then reject`. The rate-limit bucket is still a single global-per-reason
	// bucket in the helper; #3661 attributes each drop to the reply's source
	// at the consume site (policy+filter sum to the aggregate).
	userspaceRejectSent                *prometheus.Desc
	userspaceRejectReplyBudgetDrops    *prometheus.Desc
	userspaceRejectOutputFilterDrops   *prometheus.Desc
	userspaceRejectRateLimitedBySource *prometheus.Desc
	userspaceFlowCacheActiveFlows      *prometheus.Desc
	userspaceFlowCacheCapacity         *prometheus.Desc
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
	// #2375: distinct-hop capacity-drop gate at pending_neigh admission —
	// a NEW unresolved hop refused because the per-binding map is at
	// MAX_PENDING_NEIGH (the scan/upstream-outage failure mode). Kept
	// separate from pendingNeighDuplicateDropsTotal.
	pendingNeighCapacityDropsTotal *prometheus.Desc
	dynamicNeighborPresent         *prometheus.Desc
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

	// #2464: per-collector NetFlow v9 / IPFIX write-health. A flow-export
	// collector that goes unreachable used to be invisible (every failed
	// UDP write was debug-logged and dropped while the exporter kept
	// counting "exported"). Labels: protocol {netflow-v9,ipfix} and the
	// collector address (bounded — one per configured flow-server).
	flowExportCollectorWriteAttemptsTotal *prometheus.Desc
	flowExportCollectorWriteFailuresTotal *prometheus.Desc
	flowExportCollectorHealthy            *prometheus.Desc
	flowExportCollectorLastSuccessSeconds *prometheus.Desc
	flowExportCollectorLastFailureSeconds *prometheus.Desc
}

func (c *xpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packetsTotal
	ch <- c.dropsTotal
	ch <- c.sessionsCreatedTotal
	ch <- c.sessionsClosedTotal
	ch <- c.screenDropsTotal
	ch <- c.screenDropsByReasonTotal
	ch <- c.policyDeniesTotal
	ch <- c.natAllocFailsTotal
	ch <- c.nat64XlateTotal
	ch <- c.hostInboundDeny
	ch <- c.hostInboundKernelDenies
	ch <- c.tcEgressPacketsTotal
	ch <- c.syncookieTotal
	ch <- c.flowCacheTotal
	ch <- c.counterReadErrorsTotal
	ch <- c.ifacePacketsTotal
	ch <- c.ifaceBytesTotal
	ch <- c.interfaceCounterReadErrorsTotal
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
	ch <- c.sessionScrapeOK
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
	ch <- c.dhcpDDNSUpsertsTotal
	ch <- c.dhcpDDNSDeletesTotal
	ch <- c.dhcpDDNSReconcileRunsTotal
	ch <- c.dhcpDDNSSkippedTotal
	ch <- c.dhcpDDNSOwnedRecords
	ch <- c.dhcpDDNSPTRPending
	ch <- c.dhcpDDNSDegraded
	ch <- c.dhcpDDNSLastReconcileTs
	ch <- c.dhcpDDNSLastReconcileN
	ch <- c.surfaceADDNSUpsertsTotal
	ch <- c.surfaceADDNSDeletesTotal
	ch <- c.surfaceADDNSSkippedTotal
	ch <- c.surfaceADDNSScopes
	ch <- c.surfaceADDNSDegraded
	ch <- c.sysCPUUser
	ch <- c.sysCPUSystem
	ch <- c.sysMemTotal
	ch <- c.sysMemAvail
	ch <- c.daemonUptime
	ch <- c.daemonMemRSS
	ch <- c.neighborPeriodicAge
	ch <- c.frrReloadDegraded
	ch <- c.configPersistDegraded
	ch <- c.rollbackHistoryDegraded
	ch <- c.userspacePolicyContentRejected
	ch <- c.ipmonPolicyFailed
	ch <- c.ipmonPolicyTransitions
	ch <- c.ipmonRoutesApplied
	ch <- c.ipmonUnresolvedNextHops
	ch <- c.rpmPinInstallFailures
	ch <- c.eventActionsCommitted
	ch <- c.eventActionsRejected
	ch <- c.eventActionsRetried
	ch <- c.eventActionsDropped
	ch <- c.eventAttributesInvalid
	ch <- c.eventActionQueueDepth
	ch <- c.feedSecondsSinceSuccess
	ch <- c.feedStale
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
	ch <- c.userspaceDnatPublishErrors
	ch <- c.userspaceNatReverseKeySharedDisplacements
	ch <- c.userspaceWorkerCommandQueuePoisonRecoveries
	ch <- c.userspaceGreDecapEcnIllegalDrops
	ch <- c.userspaceWgDecapEcnIllegalDrops
	ch <- c.userspaceGreEncapDfOversizeDrops
	ch <- c.userspaceGreDecapChecksumInvalidDrops
	ch <- c.userspaceTimeExceededRateLimited
	ch <- c.userspacePacketTooBigRateLimited
	ch <- c.userspaceRejectRateLimited
	ch <- c.userspaceRejectSent
	ch <- c.userspaceRejectReplyBudgetDrops
	ch <- c.userspaceRejectOutputFilterDrops
	ch <- c.userspaceRejectRateLimitedBySource
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
	ch <- c.pendingNeighCapacityDropsTotal
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
	ch <- c.flowExportCollectorWriteAttemptsTotal
	ch <- c.flowExportCollectorWriteFailuresTotal
	ch <- c.flowExportCollectorHealthy
	ch <- c.flowExportCollectorLastSuccessSeconds
	ch <- c.flowExportCollectorLastFailureSeconds
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

	// #3441: rollback-history persistence is likewise a control-plane
	// signal — emit it before the dataplane gate so the degraded state
	// stays visible even when the dataplane is not loaded.
	if c.srv.rollbackHistoryDegradedFn != nil {
		v := 0.0
		if c.srv.rollbackHistoryDegradedFn() {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.rollbackHistoryDegraded,
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

	// #2050: dynamic-address feed staleness is a control-plane signal (the
	// feed manager runs even in config-only mode) — emit it BEFORE the
	// dataplane gate so a frozen enforced address set stays visible when the
	// dataplane is not loaded.
	if c.srv.feedsFn != nil {
		now := time.Now()
		for name, info := range c.srv.feedsFn() {
			secs := -1.0
			if !info.LastSuccess.IsZero() {
				secs = now.Sub(info.LastSuccess).Seconds()
			}
			ch <- prometheus.MustNewConstMetric(c.feedSecondsSinceSuccess,
				prometheus.GaugeValue, secs, name)
			stale := 0.0
			if !info.StaleSince.IsZero() {
				stale = 1
			}
			ch <- prometheus.MustNewConstMetric(c.feedStale,
				prometheus.GaugeValue, stale, name)
		}
	}

	// #2464: per-collector flow-export write-health is a control-plane
	// signal — the exporters run independent of the dataplane — so emit it
	// BEFORE the dataplane gate. A collector that has gone unreachable must
	// stay visible even when the dataplane is not loaded.
	c.collectFlowExportMetrics(ch)

	// #3361: kernel nftables host-inbound DROP counters, per zone/family. The
	// `inet xpf_hostinbound` chain is installed by the daemon INDEPENDENT of
	// dataplane load state (applyConfig runs it even in a config-only / degraded
	// boot), and it actively DROPS host-bound control-plane traffic. So this is a
	// control-plane signal — emit it BEFORE the dataplane gate so the kernel-deny
	// series stays visible exactly in the degraded boot where the dataplane is
	// unloaded but the deny chain is still dropping (the blind spot this metric
	// exists to close). ReadHostInboundDenyCounters reads nft via netlink and has
	// no dataplane dependency.
	c.collectHostInboundKernelDenies(ch)

	dp := c.srv.dp
	if dp == nil || !dp.IsLoaded() {
		return
	}

	c.collectGlobalCounters(ch, dp)
	c.collectInterfaceCounters(ch, dp)
	c.collectPolicyCounters(ch, dp)
	c.collectFilterCounters(ch, dp)
	// #3464: emit the per-interface scrape-error counter AFTER
	// collectInterfaceCounters has run, so a read failure this scrape is
	// reflected in THIS scrape's xpf_interface_counter_read_errors_total. Kept
	// separate from the security-counter total emitted just below.
	c.emitInterfaceCounterReadErrors(ch)
	// #3462: emit the scrape-error counter AFTER global/zone/policy/filter
	// (and the pre-gate host-inbound collector) have run, so a read failure in
	// any of them is reflected in THIS scrape's xpf_counter_read_errors_total
	// rather than lagging a scrape behind.
	c.emitCounterReadErrors(ch)
	c.collectSessionGauges(ch, dp)
	c.collectNATPoolMetrics(ch, dp)
	c.collectDHCPMetrics(ch)
	c.collectDDNSMetrics(ch)
	c.collectSurfaceADDNSMetrics(ch)
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
