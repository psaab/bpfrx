// #3698: a configured host-inbound-ENFORCING zone whose non-lifeline interfaces
// have no resolvable address yet (DHCP WAN before its first lease, backup node
// before VIP install) is omitted from host-inbound deny scoping — a transient
// fail-open admit window. AddresslessEnforcingZones is the SSOT that surfaces
// that window so the daemon can log it and the API can export it. These tests
// pin the precise set it reports and are fail-on-revert: drop the detection and
// the addressless WAN stops surfacing; widen it and the scoped / lifeline / no-
// interface zones start surfacing.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func addresslessCfg3698() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		// trust: statically addressed → scoped → NOT reported.
		"ge-0-0-0": {Name: "ge-0-0-0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.1.10/24"}},
		}},
		// wan: DHCP-pending — no static address, no live kernel address in the
		// test → empty address set → reported.
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
		}},
		// mgmt: fxp0 is a lifeline (never host-inbound-denied) → NOT reported even
		// though it has no address.
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
		}},
		// ha: no static address, but a configured VRRP VIP scopes the deny from
		// config on both nodes → scoped → NOT reported.
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, VRRPGroups: map[string]*config.VRRPGroup{
				"10.0.9.1/24": {VirtualAddresses: []string{"10.0.9.1"}},
			}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0-0-0.0"}},
		"wan":   {Name: "wan", Interfaces: []string{"ge-0-0-1.0"}},
		"mgmt":  {Name: "mgmt", Interfaces: []string{"fxp0.0"}},
		"ha":    {Name: "ha", Interfaces: []string{"reth0.0"}},
		// empty: configured zone with NO interfaces → nothing to protect → NOT
		// reported.
		"empty": {Name: "empty"},
	}
	return cfg
}

func TestAddresslessEnforcingZones(t *testing.T) {
	got := AddresslessEnforcingZones(addresslessCfg3698())

	// Exactly one zone is in the fail-open window: wan (DHCP-pending, no address).
	if len(got) != 1 {
		t.Fatalf("AddresslessEnforcingZones = %+v, want exactly 1 (wan)", got)
	}
	if got[0].Zone != "wan" {
		t.Fatalf("reported zone = %q, want wan", got[0].Zone)
	}
	if len(got[0].Interfaces) != 1 || got[0].Interfaces[0] != "ge-0-0-1.0" {
		t.Errorf("wan interfaces = %v, want [ge-0-0-1.0]", got[0].Interfaces)
	}

	// Cross-check: the scoped, lifeline-only, and interface-less zones must NOT
	// appear — the low-noise contract.
	for _, z := range got {
		switch z.Zone {
		case "trust":
			t.Error("trust is statically addressed (scoped) — must not be reported")
		case "mgmt":
			t.Error("mgmt has only the fxp0 lifeline — must not be reported")
		case "ha":
			t.Error("ha is scoped by its VRRP VIP — must not be reported")
		case "empty":
			t.Error("empty has no interfaces — must not be reported")
		}
	}
}

// TestAddresslessEnforcingZonesEmptyConfig guards the nil / no-zone fast paths.
func TestAddresslessEnforcingZonesEmptyConfig(t *testing.T) {
	if got := AddresslessEnforcingZones(nil); got != nil {
		t.Errorf("nil cfg = %v, want nil", got)
	}
	if got := AddresslessEnforcingZones(&config.Config{}); got != nil {
		t.Errorf("no-zone cfg = %v, want nil", got)
	}
}

// TestAddresslessEnforcingZonesHealsOnAddress asserts the window closes once the
// zone's interface gains an address — the self-heal path the daemon relies on to
// clear its state-transition warning.
func TestAddresslessEnforcingZonesHealsOnAddress(t *testing.T) {
	cfg := addresslessCfg3698()
	if len(AddresslessEnforcingZones(cfg)) != 1 {
		t.Fatalf("precondition: wan should be addressless")
	}
	// Simulate the lease landing: give the wan unit an address.
	cfg.Interfaces.Interfaces["ge-0-0-1"].Units[0].Addresses = []string{"203.0.113.5/24"}
	if got := AddresslessEnforcingZones(cfg); len(got) != 0 {
		t.Errorf("after address install = %+v, want empty (window closed)", got)
	}
}
