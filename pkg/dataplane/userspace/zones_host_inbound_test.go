// #3070: buildZoneSnapshots must carry each zone's host-inbound-traffic
// admission set onto the wire so the dataplane can enforce it for host-bound
// (local-delivery) traffic. Before #3070 only Name+ID were emitted and the
// host-inbound set was silently dropped at this boundary (the security gap).
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildZoneSnapshotsCarriesHostInbound(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name: "wan",
			HostInboundTraffic: &config.HostInboundTraffic{
				SystemServices: []string{"Ping", " GRE "}, // mixed case/space → normalized
				Protocols:      []string{"router-discovery"},
			},
		},
		"lan": {
			Name: "lan",
			HostInboundTraffic: &config.HostInboundTraffic{
				SystemServices: []string{"ssh", "ping"},
			},
		},
		// trust: no host-inbound-traffic stanza → must stay unconfigured.
		"trust": {Name: "trust"},
	}

	snaps := buildZoneSnapshots(cfg)
	byName := make(map[string]ZoneSnapshot, len(snaps))
	for _, z := range snaps {
		byName[z.Name] = z
	}

	wan, ok := byName["wan"]
	if !ok {
		t.Fatal("missing wan zone snapshot")
	}
	if !wan.HostInboundConfigured {
		t.Error("wan: HostInboundConfigured = false, want true")
	}
	// Tokens are lower-cased + trimmed.
	if got, want := wan.HostInboundSystemServices, []string{"ping", "gre"}; !eqStr(got, want) {
		t.Errorf("wan system-services = %v, want %v", got, want)
	}
	if got, want := wan.HostInboundProtocols, []string{"router-discovery"}; !eqStr(got, want) {
		t.Errorf("wan protocols = %v, want %v", got, want)
	}

	lan := byName["lan"]
	if !lan.HostInboundConfigured {
		t.Error("lan: HostInboundConfigured = false, want true")
	}
	if got, want := lan.HostInboundSystemServices, []string{"ssh", "ping"}; !eqStr(got, want) {
		t.Errorf("lan system-services = %v, want %v", got, want)
	}
	if len(lan.HostInboundProtocols) != 0 {
		t.Errorf("lan protocols = %v, want empty", lan.HostInboundProtocols)
	}

	// trust declared no stanza: enforcement stays off (admit-all preserved).
	trust := byName["trust"]
	if trust.HostInboundConfigured {
		t.Error("trust: HostInboundConfigured = true, want false (no stanza)")
	}
	if trust.HostInboundSystemServices != nil || trust.HostInboundProtocols != nil {
		t.Errorf("trust: expected nil host-inbound slices, got services=%v protocols=%v",
			trust.HostInboundSystemServices, trust.HostInboundProtocols)
	}
}

// TestBuildZoneHostInboundViews verifies the per-zone enforcement view used by
// the kernel-nftables primary path (#3070): configured zones resolve their
// firewall-local host addresses, unconfigured zones are omitted, and
// management/cluster-control lifeline interfaces (fxp0/em0/fab*) are excluded
// from the address sets.
func TestBuildZoneHostInboundViews(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24", "2001:db8:50::8/64"}},
		}},
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24"}},
		}},
		"em0": {Name: "em0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.99.0.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name:               "wan",
			Interfaces:         []string{"reth0.50"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}, Protocols: []string{"ospf"}},
		},
		"lan":     {Name: "lan", Interfaces: []string{"reth1.0"}}, // no stanza
		"control": {Name: "control", Interfaces: []string{"em0"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"all"}}},
	}

	views := BuildZoneHostInboundViews(cfg)
	byZone := make(map[string]ZoneHostInboundView, len(views))
	for _, v := range views {
		byZone[v.Zone] = v
	}

	if _, ok := byZone["lan"]; ok {
		t.Error("lan (no host-inbound stanza) must be omitted from views")
	}
	wan, ok := byZone["wan"]
	if !ok {
		t.Fatal("wan view missing")
	}
	if !eqStr(wan.V4Addrs, []string{"172.16.50.8"}) {
		t.Errorf("wan v4 addrs = %v, want [172.16.50.8]", wan.V4Addrs)
	}
	if !eqStr(wan.V6Addrs, []string{"2001:db8:50::8"}) {
		t.Errorf("wan v6 addrs = %v, want [2001:db8:50::8]", wan.V6Addrs)
	}
	if !eqStr(wan.SystemServices, []string{"ssh"}) || !eqStr(wan.Protocols, []string{"ospf"}) {
		t.Errorf("wan tokens services=%v protocols=%v", wan.SystemServices, wan.Protocols)
	}

	// control declares a stanza but its only interface (em0) is a lifeline →
	// the view exists but carries no address (so the daemon emits no deny).
	control, ok := byZone["control"]
	if !ok {
		t.Fatal("control view missing")
	}
	if len(control.V4Addrs) != 0 || len(control.V6Addrs) != 0 {
		t.Errorf("control/em0 lifeline must contribute no addresses, got v4=%v v6=%v",
			control.V4Addrs, control.V6Addrs)
	}
}

// TestBuildZoneHostInboundViewsIncludesVRRPVIP verifies #3172: a zone whose
// RETH unit carries VRRP virtual addresses (VIPs) gets those VIPs into its
// host-inbound destination address set, so the kernel deny is scoped to the VIP
// on BOTH cluster nodes — including the backup, where the VIP is not yet live on
// the kernel interface (and thus absent from the live address snapshot). A
// standalone zone with no VIP is unchanged, and a VIP configured on a lifeline
// interface (em0) is still excluded.
func TestBuildZoneHostInboundViewsIncludesVRRPVIP(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			50: {
				Number:    50,
				VlanID:    50,
				Addresses: []string{"172.16.50.8/24", "2001:db8:50::8/64"},
				VRRPGroups: map[string]*config.VRRPGroup{
					"172.16.50.8/24":    {ID: 50, VirtualAddresses: []string{"172.16.50.1"}},
					"2001:db8:50::8/64": {ID: 51, VirtualAddresses: []string{"2001:db8:50::1"}},
				},
			},
		}},
		// standalone zone interface — no VRRP, must be unchanged.
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24"}},
		}},
		// lifeline (cluster control plane) with a VRRP group — its VIP must NOT
		// be scoped (denying on em0 could break HA).
		"em0": {Name: "em0", Units: map[int]*config.InterfaceUnit{
			0: {
				Number:    0,
				Addresses: []string{"10.99.0.1/24"},
				VRRPGroups: map[string]*config.VRRPGroup{
					"10.99.0.1/24": {ID: 99, VirtualAddresses: []string{"10.99.0.254"}},
				},
			},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name:               "wan",
			Interfaces:         []string{"reth0.50"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
		"lan": {
			Name:               "lan",
			Interfaces:         []string{"reth1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
		"control": {
			Name:               "control",
			Interfaces:         []string{"em0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"all"}},
		},
	}

	views := BuildZoneHostInboundViews(cfg)
	byZone := make(map[string]ZoneHostInboundView, len(views))
	for _, v := range views {
		byZone[v.Zone] = v
	}

	wan, ok := byZone["wan"]
	if !ok {
		t.Fatal("wan view missing")
	}
	// Static interface address first, then the VRRP VIP (#3172). Without the
	// VIP-inclusion the VIP entries are absent and the deny is unscoped for the
	// VIP (fail-open) — this assertion is the fail-on-revert guard.
	if !eqStr(wan.V4Addrs, []string{"172.16.50.8", "172.16.50.1"}) {
		t.Errorf("wan v4 addrs = %v, want [172.16.50.8 172.16.50.1] (static + VIP)", wan.V4Addrs)
	}
	if !eqStr(wan.V6Addrs, []string{"2001:db8:50::8", "2001:db8:50::1"}) {
		t.Errorf("wan v6 addrs = %v, want [2001:db8:50::8 2001:db8:50::1] (static + VIP)", wan.V6Addrs)
	}

	// lan has no VRRP group → byte-identical to pre-#3172 (static only).
	lan, ok := byZone["lan"]
	if !ok {
		t.Fatal("lan view missing")
	}
	if !eqStr(lan.V4Addrs, []string{"10.0.61.1"}) {
		t.Errorf("lan v4 addrs = %v, want [10.0.61.1] (standalone, unchanged)", lan.V4Addrs)
	}
	if len(lan.V6Addrs) != 0 {
		t.Errorf("lan v6 addrs = %v, want empty", lan.V6Addrs)
	}

	// control/em0 is a lifeline → neither its static address nor its VIP is
	// scoped (no deny, can never break HA).
	control, ok := byZone["control"]
	if !ok {
		t.Fatal("control view missing")
	}
	if len(control.V4Addrs) != 0 || len(control.V6Addrs) != 0 {
		t.Errorf("control/em0 lifeline must contribute no addresses (incl. VIP), got v4=%v v6=%v",
			control.V4Addrs, control.V6Addrs)
	}
}

func TestHostInboundLifelineInterface(t *testing.T) {
	for _, name := range []string{"fxp0", "fxp0.0", "em0", "em0.0", "fab0", "fab1", "fab1.0"} {
		if !hostInboundLifelineInterface(name) {
			t.Errorf("%q should be a lifeline interface", name)
		}
	}
	for _, name := range []string{"reth0.50", "reth1", "ge-0/0/0.0", "gr-0/0/0.0"} {
		if hostInboundLifelineInterface(name) {
			t.Errorf("%q must NOT be a lifeline interface", name)
		}
	}
}

func eqStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
