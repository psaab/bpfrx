package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/rpm"
	"golang.org/x/sync/semaphore"
)

// fakeOverlayDP records the actuator's call order against the
// routes-only publish surface.
type fakeOverlayDP struct {
	dataplane.RuntimeDataPlane // nil embed: only the overlay surface is used
	calls                      []string
	publishErr                 error
	publishSkipped             bool // simulate the duplicate-skip (published=false)
	lastOverlay                []config.RouteOverlayEntry
}

func (f *fakeOverlayDP) PublishRouteOverlaySnapshot(cfg *config.Config, overlay []config.RouteOverlayEntry, schedulerState map[string]bool) (bool, error) {
	f.calls = append(f.calls, "publish")
	f.lastOverlay = overlay
	if f.publishErr != nil {
		return false, f.publishErr
	}
	return !f.publishSkipped, nil
}

func (f *fakeOverlayDP) BumpFIBGeneration() uint32 {
	f.calls = append(f.calls, "bump")
	return 1
}

func failedIPMonEngine(t *testing.T) *ipmon.Engine {
	t.Helper()
	e := ipmon.New(nil)
	e.Apply(&config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {
			Name:          "wan-failover",
			MatchRPMProbe: "WAN",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "172.16.80.1"},
			},
		},
	}}, nil)
	e.HandleTransition(rpm.Transition{
		ProbeName: "WAN", TestName: "t", Status: "fail",
		Results: []*rpm.ProbeResult{{ProbeName: "WAN", TestName: "t", LastStatus: "fail"}},
	})
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("engine setup: no overlay after failure")
	}
	return e
}

// TestActuatorPublishesBeforeFIBBump enforces the load-bearing
// ordering (AGY r2-1): BumpFIBGeneration runs ONLY after a successful
// snapshot publish — bumping first would re-resolve established flows
// against the OLD routes and the later snapshot would not
// re-invalidate them.
func TestActuatorPublishesBeforeFIBBump(t *testing.T) {
	dp := &fakeOverlayDP{}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		dp:       dp,
		ipmon:    failedIPMonEngine(t),
	}
	d.actuateRouteOverlayLocked(&config.Config{})

	if len(dp.calls) != 2 || dp.calls[0] != "publish" || dp.calls[1] != "bump" {
		t.Fatalf("calls = %v, want [publish bump]", dp.calls)
	}
	if len(dp.lastOverlay) != 1 || dp.lastOverlay[0].NextHop != "172.16.80.1" {
		t.Fatalf("published overlay = %+v", dp.lastOverlay)
	}
}

// TestActuatorSkipsBumpOnPublishFailure: a failed publish must NOT
// bump — the helper does not have the new routes yet.
func TestActuatorSkipsBumpOnPublishFailure(t *testing.T) {
	dp := &fakeOverlayDP{publishErr: errors.New("socket down")}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		dp:       dp,
		ipmon:    failedIPMonEngine(t),
	}
	d.actuateRouteOverlayLocked(&config.Config{})

	for _, c := range dp.calls {
		if c == "bump" {
			t.Fatalf("calls = %v: FIB generation bumped after failed publish", dp.calls)
		}
	}
}

// TestAssembleFRRConfigCarriesOverlay: the shared constructor injects
// the active overlay as PreferredRoutes, so BOTH the full apply path
// and the actuator render the failover route — the AGY r2-2
// commit-while-failover-active scenario at the FRR consumer.
func TestAssembleFRRConfigCarriesOverlay(t *testing.T) {
	d := &Daemon{ipmon: failedIPMonEngine(t)}
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}},
	}

	fc := d.assembleFRRConfig(cfg, d.ipmonActiveOverlay())
	if len(fc.PreferredRoutes) != 1 || fc.PreferredRoutes[0].NextHop != "172.16.80.1" {
		t.Fatalf("PreferredRoutes = %+v, want active overlay", fc.PreferredRoutes)
	}
	// The config baseline stays present (the overlay shadows it at
	// distance 1; it does not REPLACE config statics in FRR).
	if len(fc.StaticRoutes) != 1 {
		t.Fatalf("StaticRoutes = %+v", fc.StaticRoutes)
	}

	// Standby gating: a gated engine yields a baseline render.
	d.ipmon.SetPublishEnabled(false)
	fc = d.assembleFRRConfig(cfg, d.ipmonActiveOverlay())
	if len(fc.PreferredRoutes) != 0 {
		t.Fatalf("PreferredRoutes = %+v on standby, want none", fc.PreferredRoutes)
	}
}

// TestAssembleFRRConfigForwardingInstanceTable (#1827 PR-2): forwarding
// instances map to InstanceConfig{VRFName: "", TableID: <kernel table>}
// so FRR renders their statics with `table <id>` instead of polluting
// the default table; virtual-router instances keep the VRF rendering.
func TestAssembleFRRConfigForwardingInstanceTable(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "ISP-B", InstanceType: "forwarding", TableID: 100,
			StaticRoutes: []*config.StaticRoute{
				{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.80.1"}}},
			}},
		{Name: "BLUE", InstanceType: "virtual-router", TableID: 101},
	}

	fc := d.assembleFRRConfig(cfg, nil)
	if len(fc.Instances) != 2 {
		t.Fatalf("Instances = %+v, want 2", fc.Instances)
	}
	fwd := fc.Instances[0]
	if fwd.Name != "ISP-B" || fwd.VRFName != "" || fwd.TableID != 100 {
		t.Fatalf("forwarding instance = %+v, want Name=ISP-B VRFName=\"\" TableID=100", fwd)
	}
	vr := fc.Instances[1]
	if vr.Name != "BLUE" || vr.VRFName != "vrf-BLUE" || vr.TableID != 0 {
		t.Fatalf("virtual-router instance = %+v, want Name=BLUE VRFName=vrf-BLUE TableID=0", vr)
	}
}

// TestRPMHAGatingFilter exercises the §4.4 gating scope: only
// policy-referenced or RETH-bound probes are gated, and only while the
// node is secondary for the relevant RG.
func TestRPMHAGatingFilter(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.RPM = &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"t": {Name: "t", Target: "1.1.1.1", DestinationInterface: "reth0.50"},
		}},
		"plain": {Name: "plain", Tests: map[string]*config.RPMTest{
			"t": {Name: "t", Target: "8.8.8.8"},
		}},
	}}
	cfg.Services.IPMonitoring = &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"p": {Name: "p", MatchRPMProbe: "WAN"},
	}}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 1},
	}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{{ID: 0}, {ID: 1}},
	}

	gated := rpmProbeGatingRGs(cfg)
	if len(gated) != 1 {
		t.Fatalf("gated = %+v, want only WAN (policy-referenced + RETH-bound)", gated)
	}
	if rg, ok := gated["WAN"]; !ok || rg != 1 {
		t.Fatalf("gated[WAN] = %d/%v, want RG 1 from the bound RETH", rg, ok)
	}
	if _, ok := gated["plain"]; ok {
		t.Fatal("plain probe must keep run-everywhere behavior")
	}
	if got := lowestDataRG(cfg); got != 1 {
		t.Fatalf("lowestDataRG = %d, want 1", got)
	}
}

// TestCommitOverlayForConfigFiltersStaleEntries (Codex PR #1843
// HIGH-1): the overlay riding an operator commit's own publish is
// filtered against the INCOMING config — removed policies and edited
// preferred-route specs drop out; unrelated commits preserve it.
func TestCommitOverlayForConfigFiltersStaleEntries(t *testing.T) {
	d := &Daemon{ipmon: failedIPMonEngine(t)}

	// Unrelated commit: same policy spec in the incoming config.
	same := &config.Config{}
	same.Services.IPMonitoring = &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {
			Name:          "wan-failover",
			MatchRPMProbe: "WAN",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "172.16.80.1"},
			},
		},
	}}
	if got := d.commitOverlayForConfig(same); len(got) != 1 || got[0].NextHop != "172.16.80.1" {
		t.Fatalf("unrelated commit lost the active overlay: %+v", got)
	}

	// Commit removes the policy → nothing rides the commit.
	if got := d.commitOverlayForConfig(&config.Config{}); got != nil {
		t.Fatalf("removed policy still riding the commit publish: %+v", got)
	}

	// Commit edits the next-hop → the old hop must not ride.
	edited := &config.Config{}
	edited.Services.IPMonitoring = &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {
			Name:          "wan-failover",
			MatchRPMProbe: "WAN",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "172.16.80.2"},
			},
		},
	}}
	if got := d.commitOverlayForConfig(edited); got != nil {
		t.Fatalf("stale next-hop riding the commit publish: %+v", got)
	}
}

// TestActuatorSkipsBumpOnDuplicatePublish (Codex PR #1843 MED): when
// the snapshot publish is a duplicate-skip (content unchanged,
// published=false), the actuator must NOT bump the FIB generation —
// the dataplane routes did not move, so invalidating established-flow
// route caches would be pure churn.
func TestActuatorSkipsBumpOnDuplicatePublish(t *testing.T) {
	dp := &fakeOverlayDP{publishSkipped: true}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		dp:       dp,
		ipmon:    failedIPMonEngine(t),
	}
	d.actuateRouteOverlayLocked(&config.Config{})

	if len(dp.calls) != 1 || dp.calls[0] != "publish" {
		t.Fatalf("calls = %v, want [publish] only (no bump on duplicate-skip)", dp.calls)
	}
}
