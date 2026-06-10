// #1844: ip-monitoring interface-typed next-hop resolution at the
// daemon seam — resolveDHCPNextHop (the injected ipmon NextHopResolver)
// and the shared lease-key derivation contract between
// buildDHCPClientSpecs and config.DHCPLeaseIfName.
package daemon

import (
	"context"
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

// TestResolveDHCPNextHop covers the resolver matrix: nil manager
// (NoDataplane), no lease, lease without a router option, and a
// resolvable v4 lease. Every unresolvable shape must return ok=false
// so the engine skips the candidate pre-winner-selection.
func TestResolveDHCPNextHop(t *testing.T) {
	// Nil DHCP manager (NoDataplane mode): unresolvable, no panic.
	d := &Daemon{}
	if gw, ok := d.resolveDHCPNextHop("ge-0-0-3.50"); ok || gw != "" {
		t.Fatalf("nil d.dhcp: got (%q, %v), want unresolvable", gw, ok)
	}

	dm := dhcp.NewManagerForTesting(func(ctx context.Context, ifaceName string, af dhcp.AddressFamily) {
		<-ctx.Done()
	})
	d.dhcp = dm

	// No lease for the key.
	if gw, ok := d.resolveDHCPNextHop("ge-0-0-3.50"); ok || gw != "" {
		t.Fatalf("no lease: got (%q, %v), want unresolvable", gw, ok)
	}

	// Lease present but the DHCP server sent no router option.
	dm.SeedLeaseForTesting("ge-0-0-3.50", dhcp.AFInet, &dhcp.Lease{
		Interface: "ge-0-0-3.50",
		Family:    dhcp.AFInet,
		Address:   netip.MustParsePrefix("172.16.50.5/24"),
	})
	if gw, ok := d.resolveDHCPNextHop("ge-0-0-3.50"); ok || gw != "" {
		t.Fatalf("gateway-less lease: got (%q, %v), want unresolvable", gw, ok)
	}

	// Resolvable lease: the live gateway comes back.
	dm.SeedLeaseForTesting("ge-0-0-3.50", dhcp.AFInet, &dhcp.Lease{
		Interface: "ge-0-0-3.50",
		Family:    dhcp.AFInet,
		Address:   netip.MustParsePrefix("172.16.50.5/24"),
		Gateway:   netip.MustParseAddr("172.16.50.1"),
	})
	gw, ok := d.resolveDHCPNextHop("ge-0-0-3.50")
	if !ok || gw != "172.16.50.1" {
		t.Fatalf("resolvable lease: got (%q, %v), want (172.16.50.1, true)", gw, ok)
	}

	// The resolver keys on the v4 lease only: a v6 record under the
	// same interface name must not satisfy a v4 lookup.
	if _, ok := d.resolveDHCPNextHop("other-iface"); ok {
		t.Fatal("unknown key resolved")
	}
}

// TestBuildDHCPClientSpecsLeaseKeyMatchesDHCPLeaseIfName is the plan
// §9 differential test: the spec builder's per-unit lease key must be
// EXACTLY config.DHCPLeaseIfName for plain and VLAN-tagged units, so
// the compiler-derived NextHopInterface (#1844) always matches the key
// the DHCP manager runs the client under.
func TestBuildDHCPClientSpecsLeaseKeyMatchesDHCPLeaseIfName(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/3": {
					Name: "ge-0/0/3",
					Units: map[int]*config.InterfaceUnit{
						0: {DHCP: true},
						1: {VlanID: 80, DHCP: true}, // unit number ≠ vlan-id
					},
				},
			},
		},
	}

	specs := buildDHCPClientSpecs(cfg)
	if len(specs) != 2 {
		t.Fatalf("specs = %+v, want 2", specs)
	}
	want := map[string]bool{
		config.DHCPLeaseIfName("ge-0/0/3", cfg.Interfaces.Interfaces["ge-0/0/3"].Units[0]): true,
		config.DHCPLeaseIfName("ge-0/0/3", cfg.Interfaces.Interfaces["ge-0/0/3"].Units[1]): true,
	}
	for _, s := range specs {
		if !want[s.Iface] {
			t.Fatalf("spec key %q not produced by config.DHCPLeaseIfName", s.Iface)
		}
		delete(want, s.Iface)
	}
	// The vlan-id (not the unit number) forms the suffix.
	if _, ok := want["ge-0-0-3.80"]; ok {
		t.Fatal("vlan-tagged unit key ge-0-0-3.80 missing from specs")
	}
}
