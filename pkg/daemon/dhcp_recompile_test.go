package daemon

import (
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestDHCPLeaseChangeRequiresRecompile_ManagementOnlyDHCP(t *testing.T) {
	d := &Daemon{
		mgmtVRFInterfaces: map[string]bool{
			"fxp0": true,
		},
	}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"fxp0": {
					Name: "fxp0",
					Units: map[int]*config.InterfaceUnit{
						0: {DHCP: true},
					},
				},
			},
		},
	}

	if d.dhcpLeaseChangeRequiresRecompile(cfg) {
		t.Fatal("management-only DHCP lease refresh should not require dataplane recompile")
	}
}

func TestDHCPLeaseChangeRequiresRecompile_NonManagementDHCP(t *testing.T) {
	d := &Daemon{
		mgmtVRFInterfaces: map[string]bool{
			"fxp0": true,
		},
	}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/2": {
					Name: "ge-0/0/2",
					Units: map[int]*config.InterfaceUnit{
						80: {VlanID: 80, DHCP: true},
					},
				},
			},
		},
	}

	if !d.dhcpLeaseChangeRequiresRecompile(cfg) {
		t.Fatal("dataplane-facing DHCP lease refresh should require dataplane recompile")
	}
}

func TestDHCPLeaseChangeRequiresRecompile_RequiresMgmtMap(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"fxp0": {
					Name: "fxp0",
					Units: map[int]*config.InterfaceUnit{
						0: {DHCP: true},
					},
				},
			},
		},
	}

	if !d.dhcpLeaseChangeRequiresRecompile(cfg) {
		t.Fatal("missing management VRF map should keep recompile path conservative")
	}
}
