// Tests for UserspaceBoundLinuxInterfaces — the authoritative allowlist
// used by the daemon's D3 RSS indirection path (#797 Codex H1).
package userspace

import (
	"reflect"
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
