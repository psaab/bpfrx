// Tests for UserspaceBoundLinuxInterfaces — the authoritative allowlist
// used by the daemon's D3 RSS indirection path (#797 Codex H1).
package userspace

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Zoned dataplane interfaces emit their Linux names; management-zone and
// fxp*/em*/fab*/lo interfaces are filtered out. VLAN units bind on the
// parent physical netdev, so the parent Linux name is what's emitted.
func TestUserspaceBoundLinuxInterfaces_BasicFilter(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.HostName = "fw"
	cfg.System.DataplaneType = "userspace"
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {
			Name:  "fxp0",
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		},
		"ge-0/0/0": {
			Name:  "ge-0/0/0",
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		},
		"ge-0/0/1": {
			Name:  "ge-0/0/1",
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		},
		// zoned but no Units → still emitted at interface level when
		// the zone points directly at the base interface.
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"mgmt":    {Name: "mgmt", Interfaces: []string{"fxp0"}},
		"trust":   {Name: "trust", Interfaces: []string{"ge-0/0/0"}},
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/1"}},
	}

	got := UserspaceBoundLinuxInterfaces(cfg)
	want := []string{"ge-0-0-0", "ge-0-0-1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

// Management / control zones are filtered even on non-fxp/em names
// (matches userspaceSkipsIngressInterface semantics).
func TestUserspaceBoundLinuxInterfaces_MgmtZoneFiltered(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DataplaneType = "userspace"
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"mgmt":    {Name: "mgmt", Interfaces: []string{"ge-0/0/0"}},
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/1"}},
	}

	got := UserspaceBoundLinuxInterfaces(cfg)
	want := []string{"ge-0-0-1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

// Nil / empty / non-userspace configs yield an empty allowlist rather
// than nil-pointer panics or wildcard scans. The D3 path treats an
// empty allowlist as a no-op (Codex H1).
func TestUserspaceBoundLinuxInterfaces_Empty(t *testing.T) {
	if got := UserspaceBoundLinuxInterfaces(nil); len(got) != 0 {
		t.Fatalf("nil cfg: want empty, got %v", got)
	}
	empty := &config.Config{}
	if got := UserspaceBoundLinuxInterfaces(empty); len(got) != 0 {
		t.Fatalf("empty cfg: want empty, got %v", got)
	}
}

// Tunnel interfaces are filtered — userspace-dp does not bind AF_XDP on
// POINTOPOINT tunnel netdevs.
func TestUserspaceBoundLinuxInterfaces_TunnelsFiltered(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DataplaneType = "userspace"
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"gr-0/0/0": {
			Name: "gr-0/0/0",
			Tunnel: &config.TunnelConfig{
				Source:      "10.0.0.1",
				Destination: "10.0.0.2",
			},
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0", "gr-0/0/0"}},
	}

	got := UserspaceBoundLinuxInterfaces(cfg)
	want := []string{"ge-0-0-0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

// #2917 SSOT: a tagged VLAN unit binds its PHYSICAL PARENT netdev, NOT the
// VLAN-suffixed unit netdev. A VLAN sub-interface (ge-0-0-2.80) is a software
// netdev with no hardware RX queues — its tagged frames arrive on the parent
// (ge-0-0-2). The Go allowlist must emit the parent so the D3/RSS path targets
// the same netdev the Rust planner (vlan_child_parent_netdev / replan_queues)
// binds AF_XDP sockets to.
//
// Fail-on-revert: change userspaceBindTargetNetdev back to "always prefer
// ParentLinuxName" and this still passes (the parent IS the target); change it
// to return LinuxName unconditionally and the assertion goes RED — `ge-0-0-2.80`
// would leak into the allowlist while Rust binds `ge-0-0-2`.
func TestUserspaceBoundLinuxInterfaces_VLANUnitBindsParent(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DataplaneType = "userspace"
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
			80: {Number: 80, VlanID: 80},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"ge-0/0/1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/2.80"}},
	}

	got := UserspaceBoundLinuxInterfaces(cfg)
	want := []string{"ge-0-0-1", "ge-0-0-2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for _, name := range got {
		if name == "ge-0-0-2.80" {
			t.Fatalf("VLAN unit netdev `ge-0-0-2.80` must NOT appear in the "+
				"allowlist; the AF_XDP bind target is the parent `ge-0-0-2`: %v", got)
		}
	}
}

// #2917 SSOT: the binding-target helper is the single source of truth and
// mirrors the Rust planner's vlan_child_parent_netdev rule EXACTLY. A VLAN
// child (VLANID != 0 and a distinct parent netdev) binds the parent; a physical
// interface or a non-VLAN unit binds its own netdev. This row-shape table
// covers the three cases the issue enumerates, including the bondless-RETH VLAN
// row shape (a VLAN unit whose LinuxName is the parent netdev's VLAN child).
func TestUserspaceBindTargetNetdev_Contract(t *testing.T) {
	cases := []struct {
		name string
		row  InterfaceSnapshot
		want string
	}{
		{
			name: "physical interface binds itself",
			row:  InterfaceSnapshot{LinuxName: "ge-0-0-2", ParentLinuxName: "", VLANID: 0},
			want: "ge-0-0-2",
		},
		{
			name: "non-VLAN unit 0 binds its own netdev",
			row:  InterfaceSnapshot{LinuxName: "ge-0-0-2", ParentLinuxName: "ge-0-0-2", VLANID: 0},
			want: "ge-0-0-2",
		},
		{
			name: "tagged VLAN unit binds parent",
			row:  InterfaceSnapshot{LinuxName: "ge-0-0-2.80", ParentLinuxName: "ge-0-0-2", VLANID: 80},
			want: "ge-0-0-2",
		},
		{
			name: "bondless RETH VLAN unit binds parent",
			row:  InterfaceSnapshot{LinuxName: "ge-0-0-2.50", ParentLinuxName: "ge-0-0-2", VLANID: 50},
			want: "ge-0-0-2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := userspaceBindTargetNetdev(tc.row); got != tc.want {
				t.Fatalf("userspaceBindTargetNetdev(%+v) = %q, want %q", tc.row, got, tc.want)
			}
		})
	}
}

// #2917 cross-plane parity: UserspaceBoundLinuxInterfaces must be derivable
// entirely from userspaceBindTargetNetdev applied to the bound snapshot rows.
// This proves the allowlist routes through the SSOT helper (and therefore agrees
// with the Rust planner) rather than carrying an independent, drift-prone rule.
// No allowlist entry may be a VLAN-suffixed unit netdev.
func TestUserspaceBoundLinuxInterfaces_MatchesBindTargetSSOT(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DataplaneType = "userspace"
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50},
			80: {Number: 80, VlanID: 80},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"ge-0/0/1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/2.50", "ge-0/0/2.80"}},
	}

	got := UserspaceBoundLinuxInterfaces(cfg)

	// Independently derive the expected set by applying the SSOT helper to every
	// non-skipped zoned snapshot row, exactly as UserspaceBoundLinuxInterfaces
	// must.
	seen := map[string]struct{}{}
	for _, iface := range buildInterfaceSnapshots(cfg) {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		seen[userspaceBindTargetNetdev(iface)] = struct{}{}
	}
	want := make([]string, 0, len(seen))
	for name := range seen {
		want = append(want, name)
	}
	sort.Strings(want)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allowlist diverges from the bind-target SSOT: got %v, want %v", got, want)
	}
	for _, name := range got {
		if strings.Contains(name, ".") {
			t.Fatalf("allowlist must contain only physical parent netdevs, never a "+
				"VLAN-suffixed unit netdev; got %v", got)
		}
	}
}
