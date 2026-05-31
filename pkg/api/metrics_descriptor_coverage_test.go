package api

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/dhcp"
)

// #1726: whole-collector Prometheus descriptor-coverage canary.
//
// xpfCollector is a CHECKED collector: every *prometheus.Desc emitted by
// Collect() MUST be declared in Describe(), or a scrape through a checked
// path errors (the #1635 bug — cold-path histogram descs were emitted but
// not declared, and the cluster smoke masked it). The existing
// TestColdPathDescriptorsAreDescribed guards ONLY the cold-path family by
// driving emitWorkerColdPath directly. This canary generalizes the guard
// to the ENTIRE collector by running the REAL Collect() through a
// prometheus.NewPedanticRegistry() and asserting Gather() returns no
// error.
//
// Why PEDANTIC: a plain prometheus.NewRegistry() does NOT validate that
// every collected metric's descriptor was declared by Describe()
// (client_golang only populates registeredDescIDs / runs the
// "unregistered descriptor" check under NewPedanticRegistry()). Production
// (server.go) uses a plain registry, so the desc-coverage error never
// surfaces via Gather there; #1635 surfaced through promhttp's
// checked-collector logging instead. The pedantic registry is the correct
// TEST instrument for asserting the Describe()⊇Collect() contract.

// descriptorCoverageDP is a fake apiRuntimeDataPlane that also implements
// the optional Status() surface used by collectUserspaceStatus. It embeds
// *dataplane.Manager for the methods we don't care about, and overrides
// the read paths that dataplane.New() answers with a map-missing ERROR
// (the per-family collectors `continue` on error, so without these
// overrides the zone/policy/filter/NAT descriptor families would never be
// exercised — they'd silently fall out of coverage).
type descriptorCoverageDP struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
	apply  *dataplane.ApplyResult
}

func (d *descriptorCoverageDP) IsLoaded() bool { return true }

func (d *descriptorCoverageDP) Status() (dpuserspace.ProcessStatus, error) {
	return d.status, nil
}

func (d *descriptorCoverageDP) LastApplyResult() *dataplane.ApplyResult {
	return d.apply
}

func (d *descriptorCoverageDP) ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error) {
	return dataplane.InterfaceCounterValue{}, nil
}

func (d *descriptorCoverageDP) ReadZoneCounters(uint16, int) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}

func (d *descriptorCoverageDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}

func (d *descriptorCoverageDP) ReadFilterConfig(uint32) (dataplane.FilterConfig, error) {
	return dataplane.FilterConfig{RuleStart: 0}, nil
}

func (d *descriptorCoverageDP) ReadFilterCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}

func (d *descriptorCoverageDP) ReadNATPortCounter(uint32) (uint64, error) {
	return 0, nil
}

// newDescriptorCoverageStore builds a real active config with interfaces,
// zones, zone-pair + global policies (with count), inet + inet6 firewall
// filters, and a source NAT pool — so every config-driven collect path
// (zone/policy/filter/NAT-pool) produces metrics.
func newDescriptorCoverageStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(strings.Join([]string{
		// Zones (zone IDs assigned by the compiler; the fake DP's
		// LastApplyResult supplies the ZoneIDs the collector reads).
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		// Zone-pair policy with count, plus a global policy with count.
		"set security policies from-zone trust to-zone untrust policy allow match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow match application any",
		"set security policies from-zone trust to-zone untrust policy allow then permit",
		"set security policies from-zone trust to-zone untrust policy allow then count",
		"set security policies global policy g1 match source-address any",
		"set security policies global policy g1 match destination-address any",
		"set security policies global policy g1 match application any",
		"set security policies global policy g1 then permit",
		"set security policies global policy g1 then count",
		// inet + inet6 firewall filters (one term each).
		"set firewall family inet filter fin term t1 from protocol tcp",
		"set firewall family inet filter fin term t1 then accept",
		"set firewall family inet6 filter fin6 term t1 from next-header tcp",
		"set firewall family inet6 filter fin6 term t1 then accept",
		// Source NAT pool with addresses so SourcePools is populated.
		"set security nat source pool p1 address 203.0.113.0/24",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone untrust",
		"set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs rule r1 then source-nat pool p1",
	}, "\n")); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// populatedCoverageStatus returns a ProcessStatus that drives EVERY emit*
// path under collectUserspaceStatus to produce at least one metric, so the
// userspace descriptor families (CoS owner-profile, drain-phase,
// waterfill, equal-flow, worker runtime, cold-path v1/v3/scalars/unknown,
// event stream, binding active-flow + TX completion, CoS active-flow,
// three-color policer, source-NAT pool, fairness RSS, neighbor-warm) are
// all covered.
func populatedCoverageStatus() dpuserspace.ProcessStatus {
	ownerID := uint32(0)

	// One CoS interface with one exact, owner-attributed queue that has
	// equal-flow enforcement on and populated drain/waterfill histograms.
	drainHist := make([]uint64, 16)
	drainHist[2] = 5
	redirectHist := make([]uint64, 16)
	redirectHist[1] = 3
	cosIface := dpuserspace.CoSInterfaceStatus{
		Ifindex:                     80,
		InterfaceName:               "ge-0-0-2",
		WaterfillEpochs:             4,
		WaterfillPhase1BudgetBreaks: 1,
		WaterfillMinEpochsPerWorker: 2, // not MaxUint64 → gauge emits
		Queues: []dpuserspace.CoSQueueStatus{
			{
				QueueID:                                    4,
				OwnerWorkerID:                              &ownerID,
				Exact:                                      true,
				DrainLatencyHist:                           drainHist,
				DrainInvocations:                           9,
				RedirectAcquireHist:                        redirectHist,
				OwnerPPS:                                   100,
				PeerPPS:                                    50,
				DrainGuaranteeSentBytes:                    1000,
				DrainSurplusSentBytes:                      200,
				DrainNonExactSentBytesWhileExactBacklogged: 10,
				WaterfillPhase1Admissions:                  3,
				WaterfillPhase2Admissions:                  2,
				WaterfillEligibleVisits:                    7,
				EqualFlowEnforcement:                       true,
				EqualFlowEnforced:                          true,
				EqualFlowTargetPerFlowBPS:                  3200,
				EqualFlowMaxWorkerCapBytes:                 9600,
				EqualFlowCapHitEvents:                      1,
				EqualFlowSuppressedGrantBytes:              64,
				EqualFlowStaleOrTagMismatchEvents:          0,
				EqualFlowFailOpenReason:                    "",
			},
		},
	}

	// Cold-path: one v3 worker (sparse populated + overflow), one
	// unknown-version worker, one v1 dense worker — mirrors the existing
	// cold-path test fixture so all cold-path desc families emit.
	v3Buckets := make([]uint64, 48)
	v3Buckets[6] = 3
	v1Hist := make([][]uint64, 16)
	for i := range v1Hist {
		v1Hist[i] = make([]uint64, 24)
	}
	v1Hist[3][5] = 1
	v1Samples := make([]uint64, 16)
	v1Samples[3] = 1
	v1SumNS := make([]uint64, 16)
	v1SumNS[3] = 100
	v1Alias := make([]bool, 16)
	v1Alias[3] = true

	return dpuserspace.ProcessStatus{
		SessionTableEntries: 12,
		MaxSessions:         1000,
		FlowCacheCapacity:   4096,
		CoSInterfaces:       []dpuserspace.CoSInterfaceStatus{cosIface},
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
			{
				WorkerID:                       0,
				WallNS:                         1e9,
				ActiveNS:                       5e8,
				ColdPathLayoutVersion:          3,
				ColdPathActiveSlotIDs:          []uint32{0},
				ColdPathActiveZoneFrom:         []uint32{1},
				ColdPathActiveZoneTo:           []uint32{2},
				ColdPathActiveSamples:          []uint64{3},
				ColdPathActiveSumNS:            []uint64{300},
				ColdPathActiveBuckets:          [][]uint64{v3Buckets},
				ColdPathActiveBuilderCollision: []bool{false},
				ColdPathOverflowActive:         true,
				ColdPathClockSource:            "tsc",
			},
			{WorkerID: 1, ColdPathLayoutVersion: 99}, // unknown-version path
			{
				WorkerID:              2,
				ColdPathLayoutVersion: 1,
				ColdPathHist:          v1Hist,
				ColdPathSamples:       v1Samples,
				ColdPathSumNS:         v1SumNS,
				ColdPathAliasSeen:     v1Alias,
			},
		},
		Bindings: []dpuserspace.BindingStatus{
			{
				Slot:                         0,
				QueueID:                      4,
				WorkerID:                     0,
				Interface:                    "ge-0-0-2",
				ActiveFlowCount:              7,
				FlowCacheCapacity:            4096,
				TXCompletions:                123,
				TXCompletionRingAvailable:    10,
				TXCompletionRingAvailableMax: 20,
			},
		},
		CoSActiveFlowCounts: []dpuserspace.CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 7},
		},
		ThreeColorPolicerCounters: []dpuserspace.ThreeColorPolicerStatus{
			{
				Name:         "tcm1",
				GreenPackets: 10, GreenBytes: 1000,
				YellowPackets: 2, YellowBytes: 200,
				RedPackets: 1, RedBytes: 100,
				DropPackets: 1, DropBytes: 100,
			},
		},
		SourceNATPools: []dpuserspace.SourceNATPoolStatus{
			{
				PoolName: "p1", RuleName: "r1",
				LiveFlows: 5, UsedPorts: 50, PersistentLeases: 0,
				AllocationsTotal: 100, ReusesTotal: 10, ExhaustionTotal: 0,
			},
		},
		EventStream: &dpuserspace.EventStreamStatus{
			FramesRead: 11, FramesWritten: 7, DecodeErrors: 2, SeqGaps: 1,
			PolicyDenyEvents: 5, ScreenDropEvents: 6, FilterLogEvents: 8,
			PolicyDenyDrops: 1, ScreenDropDrops: 4, FilterLogDrops: 9,
			UnknownFrameDrops: 3,
		},
		EventStreamSent:               101,
		EventStreamDropped:            7,
		NeighborWarmDropsTotal:        2,
		NeighborWarmDisconnectedTotal: 0,
	}
}

func gatheredNames(mfs []*dto.MetricFamily) map[string]bool {
	out := make(map[string]bool, len(mfs))
	for _, mf := range mfs {
		out[mf.GetName()] = true
	}
	return out
}

// TestCollectorDescriptorCoverage is the #1726 whole-collector canary. It
// builds the REAL collector with a fully-wired fake runtime, registers it
// in a PEDANTIC registry, and asserts Gather() returns no error — the
// exact condition that fires when Collect() emits a metric whose
// descriptor is not declared in Describe() (the #1635 class). It also
// asserts representative families from every collect path are present, so
// silently dropping a whole family fails the canary too.
func TestCollectorDescriptorCoverage(t *testing.T) {
	store := newDescriptorCoverageStore(t)
	gc := conntrack.NewGC(nil, time.Minute)
	dhcpMgr, err := dhcp.New(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("dhcp.New: %v", err)
	}
	defer dhcpMgr.Close()

	srv := &Server{
		store:     store,
		gc:        gc,
		dhcp:      dhcpMgr,
		startTime: time.Now(),
	}
	srv.dp = &descriptorCoverageDP{
		Manager: dataplane.New(),
		status:  populatedCoverageStatus(),
		apply: &dataplane.ApplyResult{
			ZoneIDs:   map[string]uint16{"trust": 1, "untrust": 2},
			FilterIDs: map[string]uint32{"inet:fin": 0, "inet6:fin6": 100},
			PoolIDs:   map[string]uint8{"p1": 0},
		},
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(srv))

	mfs, err := reg.Gather()
	if err != nil {
		// The #1635 class manifests as "... with unregistered descriptor ...".
		t.Fatalf("pedantic Gather() returned an error — most likely a metric "+
			"was emitted by Collect() whose descriptor is not declared in "+
			"Describe() (the #1635 class). Add the missing ch <- c.<desc> "+
			"line to Describe(). Error: %v", err)
	}
	if len(mfs) == 0 {
		t.Fatal("collector emitted no metric families — fixture/dp not wired " +
			"(canary would be vacuous)")
	}

	// Positive sentinels: one representative family per collect path, so a
	// future change that drops an entire family (rather than mis-declaring
	// a single desc) also fails this canary.
	names := gatheredNames(mfs)
	for _, want := range []string{
		"xpf_packets_total",        // collectGlobalCounters
		"xpf_zone_packets_total",   // collectZoneCounters
		"xpf_policy_hits_total",    // collectPolicyCounters
		"xpf_filter_hits_total",    // collectFilterCounters
		"xpf_nat_pool_total_ports", // collectNATPoolMetrics
		"xpf_sessions_active",      // collectSessionGauges
		"xpf_dhcp_leases_active",   // collectDHCPMetrics
		"xpf_daemon_uptime_seconds", // collectSystemMetrics
		"xpf_userspace_worker_dead", // emitWorkerRuntime
		"xpf_userspace_worker_cold_path_samples_v3_total", // cold-path v3
		"xpf_cos_drain_invocations_total",                 // CoS owner profile
		"xpf_userspace_three_color_policer_drops_total",   // three-color policer
		"xpf_userspace_source_nat_pool_live_flows",        // userspace SNAT pool
		"xpf_userspace_neighbor_warm_drops_total",         // neighbor-warm
	} {
		if !names[want] {
			t.Errorf("expected metric family %q in gathered output but it was "+
				"absent — its collect path did not emit (coverage gap)", want)
		}
	}
}
