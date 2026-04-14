package daemon

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/vrrp"
)

// testLink implements netlink.Link for testing.
type testLink struct {
	attrs netlink.LinkAttrs
}

func (l *testLink) Attrs() *netlink.LinkAttrs { return &l.attrs }
func (l *testLink) Type() string              { return "test" }

// mockLinkByName returns a function that resolves interfaces from a map.
func mockLinkByName(links map[string]*testLink) func(string) (netlink.Link, error) {
	return func(name string) (netlink.Link, error) {
		if l, ok := links[name]; ok {
			return l, nil
		}
		return nil, fmt.Errorf("link not found: %s", name)
	}
}

func newTestLink(name string, up bool) *testLink {
	var state netlink.LinkOperState = netlink.OperDown
	if up {
		state = netlink.OperUp
	}
	return &testLink{
		attrs: netlink.LinkAttrs{Name: name, OperState: state},
	}
}

func TestCheckVIPReadiness_AllUp(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	links := map[string]*testLink{
		"ge-0-0-0": newTestLink("ge-0-0-0", true),
	}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if !ready {
		t.Errorf("should be ready, got reasons: %v", reasons)
	}
}

func TestCheckVIPReadiness_InterfaceDown(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	links := map[string]*testLink{
		"ge-0-0-0": newTestLink("ge-0-0-0", false),
	}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if ready {
		t.Error("should NOT be ready with interface down")
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "down") {
		t.Errorf("unexpected reasons: %v", reasons)
	}
}

func TestCheckVIPReadiness_InterfaceNotFound(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	// Empty links map — interface not found.
	links := map[string]*testLink{}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if ready {
		t.Error("should NOT be ready when interface is missing")
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "not found") {
		t.Errorf("unexpected reasons: %v", reasons)
	}
}

func TestCheckVIPReadiness_NoVIPs(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {
					Name: "ge-0/0/0",
					// No RedundancyGroup, no RETH.
				},
			},
		},
	}

	links := map[string]*testLink{}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if !ready {
		t.Errorf("should be ready with no VIPs, got reasons: %v", reasons)
	}
}

func TestCheckVIPReadiness_WrongRG(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1, // RG 1, not 0
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	links := map[string]*testLink{}

	// Query RG 0 — reth0 is in RG 1, so no VIPs for RG 0.
	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if !ready {
		t.Errorf("should be ready for unrelated RG, got reasons: %v", reasons)
	}
}

func TestCheckVIPReadiness_InterfaceUpViaFlags(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	// Interface with OperDown but FlagUp set — should count as up.
	links := map[string]*testLink{
		"ge-0-0-0": {
			attrs: netlink.LinkAttrs{
				Name:      "ge-0-0-0",
				OperState: netlink.OperDown,
				Flags:     net.FlagUp,
			},
		},
	}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if !ready {
		t.Errorf("should be ready with FlagUp, got reasons: %v", reasons)
	}
}

func TestCheckNoRethTakeoverReadiness_UsesVIPReadinessOnly(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	links := map[string]*testLink{
		"ge-0-0-0": newTestLink("ge-0-0-0", true),
	}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if !ready {
		t.Fatalf("should be ready, got reasons: %v", reasons)
	}
	if len(reasons) != 0 {
		t.Fatalf("unexpected reasons: %v", reasons)
	}
}

func testStoreWithSetConfig(t *testing.T, lines []string) *configstore.Store {
	t.Helper()

	store := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return store
}

func TestTakeoverReadinessForRG_NoRethIgnoresClusterSyncReady(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster no-reth-vrrp",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set interfaces reth0 redundant-ether-options redundancy-group 0",
		"set interfaces reth0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
	})

	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cm.Start(ctx)

	d := &Daemon{
		rgStates:     make(map[int]*rgStateMachine),
		cluster:      cm,
		store:        store,
		vrrpMgr:      vrrp.NewManager(),
		linkByNameFn: mockLinkByName(map[string]*testLink{"ge-0-0-0": newTestLink("ge-0-0-0", true)}),
	}

	if d.cluster.IsSyncReady() {
		t.Fatal("sync should start not ready for this regression test")
	}

	d.reconcileRGState()

	state := d.cluster.GroupState(0)
	if state == nil {
		t.Fatal("expected RG 0 state")
	}
	if !state.Ready {
		t.Fatalf("expected RG 0 ready, got reasons: %v", state.ReadinessReasons)
	}
	for _, reason := range state.ReadinessReasons {
		if strings.Contains(reason, "session sync not ready") {
			t.Fatalf("unexpected session sync gating reason: %v", state.ReadinessReasons)
		}
	}
}

func TestUserspaceRGConfigured(t *testing.T) {
	cfg := &config.Config{
		System: config.SystemConfig{
			DataplaneType: dataplane.TypeUserspace,
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
				},
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 2,
				},
			},
		},
	}

	if !userspaceRGConfigured(cfg, 1) {
		t.Fatal("expected RG 1 configured")
	}
	if !userspaceRGConfigured(cfg, 2) {
		t.Fatal("expected RG 2 configured")
	}
	if userspaceRGConfigured(cfg, 3) {
		t.Fatal("expected RG 3 not configured")
	}
	if userspaceRGConfigured(cfg, 0) {
		t.Fatal("expected RG 0 not configured")
	}
	if userspaceRGConfigured(nil, 1) {
		t.Fatal("expected nil config not configured")
	}
}
