package routing

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// monitorFakeLink is a minimal netlink.Link carrying caller-chosen attrs.
type monitorFakeLink struct {
	attrs netlink.LinkAttrs
}

func (l *monitorFakeLink) Attrs() *netlink.LinkAttrs { return &l.attrs }
func (l *monitorFakeLink) Type() string              { return "monitor-fake" }

// monitorFakeOps satisfies linkOps but only LinkByName is meaningful; the
// interface-monitor path touches nothing else. Unused methods return nil so
// the type still implements the full surface.
type monitorFakeOps struct {
	links map[string]netlink.Link
}

func (o *monitorFakeOps) LinkByName(name string) (netlink.Link, error) {
	if l, ok := o.links[name]; ok {
		return l, nil
	}
	return nil, net.UnknownNetworkError("not found: " + name)
}

func (o *monitorFakeOps) LinkAdd(netlink.Link) error                     { return nil }
func (o *monitorFakeOps) LinkDel(netlink.Link) error                     { return nil }
func (o *monitorFakeOps) LinkSetUp(netlink.Link) error                   { return nil }
func (o *monitorFakeOps) LinkSetDown(netlink.Link) error                 { return nil }
func (o *monitorFakeOps) LinkSetMaster(netlink.Link, netlink.Link) error { return nil }
func (o *monitorFakeOps) LinkSetNoMaster(netlink.Link) error             { return nil }
func (o *monitorFakeOps) LinkSetMTU(netlink.Link, int) error             { return nil }
func (o *monitorFakeOps) LinkList() ([]netlink.Link, error)              { return nil, nil }
func (o *monitorFakeOps) AddrAdd(netlink.Link, *netlink.Addr) error      { return nil }
func (o *monitorFakeOps) AddrDel(netlink.Link, *netlink.Addr) error      { return nil }
func (o *monitorFakeOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	return nil, nil
}

// TestInterfaceMonitor_CarrierState is the #2070 regression: a monitored
// interface that is administratively up but has lost carrier (cable pulled /
// peer link down) MUST report DOWN so the redundancy-group weight is demoted
// and HA failover fires. The pre-fix code OR'd in net.FlagUp (IFF_UP, the
// admin flag), which stays set on carrier loss, so a carrier-down link was
// reported UP and failover was suppressed.
func TestInterfaceMonitor_CarrierState(t *testing.T) {
	const ifName = "ge-0/0/0"
	linuxName := config.LinuxIfName(ifName)

	tests := []struct {
		name      string
		operState netlink.LinkOperState
		flags     net.Flags
		wantUp    bool
	}{
		{
			// Cable pulled: admin-up but no carrier. The bug reported UP here.
			name:      "admin-up carrier-down reports down",
			operState: netlink.OperDown,
			flags:     net.FlagUp,
			wantUp:    false,
		},
		{
			// Peer link down: kernel reports lower-layer-down, IFF_UP still set.
			name:      "admin-up lower-layer-down reports down",
			operState: netlink.OperLowerLayerDown,
			flags:     net.FlagUp,
			wantUp:    false,
		},
		{
			name:      "admin-up carrier-up reports up",
			operState: netlink.OperUp,
			flags:     net.FlagUp,
			wantUp:    true,
		},
		{
			// Admin-down: IFF_UP clear, must report down.
			name:      "admin-down reports down",
			operState: netlink.OperDown,
			flags:     0,
			wantUp:    false,
		},
		{
			// Virtual device with no carrier reporting: OperUnknown falls back
			// to the admin flag (matches pkg/vrrp.linkAttrsUp).
			name:      "operunknown admin-up reports up",
			operState: netlink.OperUnknown,
			flags:     net.FlagUp,
			wantUp:    true,
		},
		{
			name:      "operunknown admin-down reports down",
			operState: netlink.OperUnknown,
			flags:     0,
			wantUp:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ops := &monitorFakeOps{links: map[string]netlink.Link{
				linuxName: &monitorFakeLink{attrs: netlink.LinkAttrs{
					Name:      linuxName,
					OperState: tc.operState,
					Flags:     tc.flags,
				}},
			}}
			mm := &monitorManager{
				ops:           ops,
				monitorStatus: make(map[int][]InterfaceMonitorStatus),
			}

			groups := []*config.RedundancyGroup{{
				ID: 1,
				InterfaceMonitors: []*config.InterfaceMonitor{
					{Interface: ifName, Weight: 100},
				},
			}}
			mm.Apply(groups)

			statuses := mm.monitorStatus[1]
			if len(statuses) != 1 {
				t.Fatalf("expected 1 monitor status, got %d", len(statuses))
			}
			if statuses[0].Up != tc.wantUp {
				t.Errorf("Up = %v, want %v (operstate=%v flags=%v)",
					statuses[0].Up, tc.wantUp, tc.operState, tc.flags)
			}
		})
	}
}
