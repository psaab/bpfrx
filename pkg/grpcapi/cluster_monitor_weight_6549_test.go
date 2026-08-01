package grpcapi

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// #6549: `show chassis cluster interfaces` must report the interface-monitor
// weight the ELECTION APPLIES, not the raw configured one.
//
// An out-of-range weight (`interface-monitor ge-0/0/1 weight -100`) is rejected
// at commit but survives the TOLERANT paths — Store.Load of a persisted config
// and Store.SyncApply of a peer-pushed one, where compileTreeLenient downgrades
// the gate to a warning so a node never bricks (#1960). The runtime then bounds
// it to [0,255]. Rendering the raw value would be an observability lie on
// exactly the config where the operator most needs the truth: the display would
// claim a monitor contributes -100 while the election contributes 0.
//
// buildInterfacesInput fills monitor weights from two sources, and both are
// covered here:
//
//   - the LIVE routing statuses (server_cluster.go, the `if` branch), bounded
//     at their source in pkg/routing/monitor.go;
//   - the config-only FALLBACK fills (the `else` branch for a local monitor
//     with no live status, and the peer branch for a monitor that belongs to
//     the peer node so no local link exists).
//
// The harness drives the REAL tolerant ingress (Store.SyncApply) rather than
// hand-building a compiled config, so the test also proves the weight actually
// survives that path unbounded and has to be handled downstream.

// monWeightFakeLink is a netlink.Link carrying caller-chosen attrs.
type monWeightFakeLink struct {
	attrs netlink.LinkAttrs
}

func (l *monWeightFakeLink) Attrs() *netlink.LinkAttrs { return &l.attrs }
func (l *monWeightFakeLink) Type() string              { return "mon-weight-fake" }

// monWeightFakeOps satisfies pkg/routing's (unexported) linkOps structurally.
// Only LinkByName is meaningful for the interface-monitor sweep; a name that is
// absent models a PEER-owned interface, which routing skips — that is what
// leaves a configured monitor with no live status and routes it to the
// config-only peer fill.
type monWeightFakeOps struct {
	links map[string]netlink.Link
}

func (o *monWeightFakeOps) LinkByName(name string) (netlink.Link, error) {
	if l, ok := o.links[name]; ok {
		return l, nil
	}
	return nil, net.UnknownNetworkError("not found: " + name)
}

func (o *monWeightFakeOps) LinkAdd(netlink.Link) error                     { return nil }
func (o *monWeightFakeOps) LinkDel(netlink.Link) error                     { return nil }
func (o *monWeightFakeOps) LinkSetUp(netlink.Link) error                   { return nil }
func (o *monWeightFakeOps) LinkSetDown(netlink.Link) error                 { return nil }
func (o *monWeightFakeOps) LinkSetMaster(netlink.Link, netlink.Link) error { return nil }
func (o *monWeightFakeOps) LinkSetNoMaster(netlink.Link) error             { return nil }
func (o *monWeightFakeOps) LinkSetMTU(netlink.Link, int) error             { return nil }
func (o *monWeightFakeOps) LinkList() ([]netlink.Link, error)              { return nil, nil }
func (o *monWeightFakeOps) AddrAdd(netlink.Link, *netlink.Addr) error      { return nil }
func (o *monWeightFakeOps) AddrDel(netlink.Link, *netlink.Addr) error      { return nil }
func (o *monWeightFakeOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	return nil, nil
}

// outOfRangeMonitorConfig is a chassis-cluster config carrying an out-of-range
// interface-monitor weight on each of two monitors. `local0` exists as a link
// in the fake netlink surface; `peer0` does not, modelling a peer-owned member.
//
// The CONTAINER-hierarchical spelling is deliberate: the packed form
// (`interface-monitor <if> weight <n>;` directly under redundancy-group)
// compiles to ZERO monitors, a separate defect tracked as #6588. Using it here
// would make this test silently vacuous, which is why syncOutOfRangeMonitors
// asserts the monitors actually compiled before proceeding.
const outOfRangeMonitorConfig = `
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

// syncOutOfRangeMonitors pushes outOfRangeMonitorConfig through the REAL
// tolerant peer-sync ingress and returns the store. It fails the test if the
// lenient compile does not in fact preserve the raw out-of-range weight —
// without that precondition the rest of the test would be vacuous.
func syncOutOfRangeMonitors(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	cfg, err := store.SyncApply(outOfRangeMonitorConfig, nil)
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
			"raw out-of-range weights (that is what makes the display clamp "+
			"necessary); got %+v", raw)
	}
	return &Server{store: store}
}

// TestShowClusterInterfaces_MonitorWeightIsTheEffectiveOne_6549 covers all three
// weight fills.
//
// Fail-on-revert:
//   - restore `Weight: mon.Weight` at either config-only fill in
//     server_cluster.go and the corresponding row reports -100 / 100000;
//   - restore `Weight: mon.Weight` in pkg/routing/monitor.go and the LIVE row
//     reports -100.
func TestShowClusterInterfaces_MonitorWeightIsTheEffectiveOne_6549(t *testing.T) {
	t.Run("config-only fill (no live routing statuses)", func(t *testing.T) {
		s := syncOutOfRangeMonitors(t)
		// s.routing stays nil: every monitor falls to the config-only fill.
		input := s.buildInterfacesInput()
		assertEffectiveMonitorWeights(t, input.Monitors, map[string]int{
			"local0": 0, "peer0": 255,
		})
	})

	t.Run("live routing statuses + peer config-only fill", func(t *testing.T) {
		s := syncOutOfRangeMonitors(t)

		// local0 exists as a link; peer0 does not, so the routing sweep emits
		// a status for local0 only and peer0 falls to the peer config fill.
		linux := config.LinuxIfName("local0")
		s.routing = routing.NewManagerWithLinkOpsForTest(&monWeightFakeOps{
			links: map[string]netlink.Link{
				linux: &monWeightFakeLink{attrs: netlink.LinkAttrs{
					Name: linux, OperState: netlink.OperUp,
				}},
			},
		})
		s.cluster = cluster.NewManager(0, 1)

		cfg := s.store.ActiveConfig()
		s.routing.ApplyInterfaceMonitors(cfg.Chassis.Cluster.RedundancyGroups)

		input := s.buildInterfacesInput()
		assertEffectiveMonitorWeights(t, input.Monitors, map[string]int{"local0": 0})
		assertEffectiveMonitorWeights(t, input.PeerMonitors, map[string]int{"peer0": 255})
	})
}

// assertEffectiveMonitorWeights checks that every named monitor is present with
// the effective (bounded) weight, and that no rendered weight escapes [0,255].
func assertEffectiveMonitorWeights(t *testing.T, got []cluster.InterfaceMonitorInfo, want map[string]int) {
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
