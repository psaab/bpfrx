package cli

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// #6549, CLI twin of pkg/grpcapi's cluster_monitor_weight_6549_test.go: the
// local `show chassis cluster interfaces` renders monitor weights through the
// same three fills as the gRPC path and must likewise report the weight the
// ELECTION APPLIES, not the raw configured one.
//
// An out-of-range weight survives the tolerant Store.Load / Store.SyncApply
// compile (#1960 no-brick) and the runtime bounds it to [0,255]; rendering the
// raw value would claim a monitor contributes -100 while the election
// contributes 0.

// cliMonWeightFakeLink is a netlink.Link carrying caller-chosen attrs.
type cliMonWeightFakeLink struct {
	attrs netlink.LinkAttrs
}

func (l *cliMonWeightFakeLink) Attrs() *netlink.LinkAttrs { return &l.attrs }
func (l *cliMonWeightFakeLink) Type() string              { return "cli-mon-weight-fake" }

// cliMonWeightFakeOps satisfies pkg/routing's (unexported) linkOps
// structurally. An absent name models a PEER-owned interface, which the routing
// sweep skips — that is what routes a configured monitor to the config-only
// peer fill.
type cliMonWeightFakeOps struct {
	links map[string]netlink.Link
}

func (o *cliMonWeightFakeOps) LinkByName(name string) (netlink.Link, error) {
	if l, ok := o.links[name]; ok {
		return l, nil
	}
	return nil, net.UnknownNetworkError("not found: " + name)
}

func (o *cliMonWeightFakeOps) LinkAdd(netlink.Link) error                     { return nil }
func (o *cliMonWeightFakeOps) LinkDel(netlink.Link) error                     { return nil }
func (o *cliMonWeightFakeOps) LinkSetUp(netlink.Link) error                   { return nil }
func (o *cliMonWeightFakeOps) LinkSetDown(netlink.Link) error                 { return nil }
func (o *cliMonWeightFakeOps) LinkSetMaster(netlink.Link, netlink.Link) error { return nil }
func (o *cliMonWeightFakeOps) LinkSetNoMaster(netlink.Link) error             { return nil }
func (o *cliMonWeightFakeOps) LinkSetMTU(netlink.Link, int) error             { return nil }
func (o *cliMonWeightFakeOps) LinkList() ([]netlink.Link, error)              { return nil, nil }
func (o *cliMonWeightFakeOps) AddrAdd(netlink.Link, *netlink.Addr) error      { return nil }
func (o *cliMonWeightFakeOps) AddrDel(netlink.Link, *netlink.Addr) error      { return nil }
func (o *cliMonWeightFakeOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	return nil, nil
}

// cliOutOfRangeMonitorConfig uses the CONTAINER-hierarchical interface-monitor
// spelling: the packed form compiles to ZERO monitors (#6588) and would make
// this test vacuous.
const cliOutOfRangeMonitorConfig = `
chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        control-interface em0;
        fabric-interface fab0;
        reth-count 2;
        redundancy-group 0 {
            node 0 priority 200;
            node 1 priority 100;
            interface-monitor {
                local0 weight -100;
                peer0 weight 100000;
            }
        }
    }
}
`

// cliSyncOutOfRangeMonitors pushes the config through the REAL tolerant
// peer-sync ingress and asserts the raw out-of-range weights actually survive
// it — without that precondition the assertions below would be vacuous.
func cliSyncOutOfRangeMonitors(t *testing.T) *CLI {
	t.Helper()
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	cfg, err := store.SyncApply(cliOutOfRangeMonitorConfig, nil)
	if err != nil {
		t.Fatalf("SyncApply(out-of-range monitor weight): %v", err)
	}
	if cfg == nil || cfg.Chassis.Cluster == nil || len(cfg.Chassis.Cluster.RedundancyGroups) != 1 {
		t.Fatalf("tolerant sync did not compile the chassis cluster: %+v", cfg)
	}
	raw := map[string]int{}
	for _, mon := range cfg.Chassis.Cluster.RedundancyGroups[0].InterfaceMonitors {
		raw[mon.Interface] = mon.Weight
	}
	if raw["local0"] != -100 || raw["peer0"] != 100000 {
		t.Fatalf("precondition: the tolerant path was expected to PRESERVE the "+
			"raw out-of-range weights; got %+v", raw)
	}
	return &CLI{store: store}
}

// TestCLIShowClusterInterfaces_MonitorWeightIsTheEffectiveOne_6549 covers all
// three weight fills.
//
// Fail-on-revert:
//   - restore `Weight: mon.Weight` at either config-only fill in
//     cli_helpers.go and the corresponding row reports -100 / 100000;
//   - restore `Weight: mon.Weight` in pkg/routing/monitor.go and the LIVE row
//     reports -100.
func TestCLIShowClusterInterfaces_MonitorWeightIsTheEffectiveOne_6549(t *testing.T) {
	t.Run("config-only fill (no live routing statuses)", func(t *testing.T) {
		c := cliSyncOutOfRangeMonitors(t)
		// c.routing stays nil: every monitor falls to the config-only fill.
		input := c.buildInterfacesInput()
		assertCLIEffectiveMonitorWeights(t, input.Monitors, map[string]int{
			"local0": 0, "peer0": 255,
		})
	})

	t.Run("live routing statuses + peer config-only fill", func(t *testing.T) {
		c := cliSyncOutOfRangeMonitors(t)

		linux := config.LinuxIfName("local0")
		c.routing = routing.NewManagerWithLinkOpsForTest(&cliMonWeightFakeOps{
			links: map[string]netlink.Link{
				linux: &cliMonWeightFakeLink{attrs: netlink.LinkAttrs{
					Name: linux, OperState: netlink.OperUp,
				}},
			},
		})
		c.cluster = cluster.NewManager(0, 1)

		cfg := c.store.ActiveConfig()
		c.routing.ApplyInterfaceMonitors(cfg.Chassis.Cluster.RedundancyGroups)

		input := c.buildInterfacesInput()
		assertCLIEffectiveMonitorWeights(t, input.Monitors, map[string]int{"local0": 0})
		assertCLIEffectiveMonitorWeights(t, input.PeerMonitors, map[string]int{"peer0": 255})
	})
}

// assertCLIEffectiveMonitorWeights checks that every named monitor is present
// with the effective (bounded) weight, and that no rendered weight escapes
// [0,255].
func assertCLIEffectiveMonitorWeights(t *testing.T, got []cluster.InterfaceMonitorInfo, want map[string]int) {
	t.Helper()
	seen := map[string]bool{}
	for _, m := range got {
		if m.Weight < 0 || m.Weight > 255 {
			t.Errorf("monitor %s rendered weight %d, which escapes the [0,255] "+
				"domain the election applies", m.Interface, m.Weight)
		}
		w, ok := want[m.Interface]
		if !ok {
			continue
		}
		seen[m.Interface] = true
		if m.Weight != w {
			t.Errorf("monitor %s rendered weight %d, want the effective %d — "+
				"the display reports a weight the election does not use",
				m.Interface, m.Weight, w)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("monitor %s missing from the rendered set %+v", name, got)
		}
	}
}
