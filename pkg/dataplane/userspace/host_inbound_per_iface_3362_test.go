package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// hostInboundCfg3362 builds a single-zone config with two interfaces: an
// uplink unit carrying an interface-level host-inbound override (ssh), and a
// second unit in the SAME zone with NO override. The zone declares NO
// zone-level stanza — it is host-inbound-ENFORCING solely because of the
// per-interface override (#3362 Junos semantics).
func hostInboundCfg3362() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24"}},
		}},
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name:       "wan",
			Interfaces: []string{"reth0.50", "reth1.0"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"reth0.50": {SystemServices: []string{"ssh"}},
			},
		},
	}
	return cfg
}

// Test_3362_PerInterfaceViewsScopeOverride asserts BuildZoneHostInboundViews
// splits a zone into per-interface effective-token views: the overridden
// interface's address is scoped to the union set (ssh), and the non-overridden
// interface's address lands in an EMPTY-token view (catch-all drop). This is the
// motivating use case — expose ssh on one interface of a zone, deny it on the
// other. Fail-on-revert: without per-interface grouping a single zone-wide view
// (empty zone-level set) would either deny BOTH (over-restrictive) or, before
// the configured-via-interface change, omit the zone entirely (admit-all on
// both) — either way the assertions below fail.
func Test_3362_PerInterfaceViewsScopeOverride(t *testing.T) {
	views := BuildZoneHostInboundViews(hostInboundCfg3362())

	var sshView, dropView *ZoneHostInboundView
	for i := range views {
		v := &views[i]
		if v.Zone != "wan" {
			t.Fatalf("unexpected zone %q in views", v.Zone)
		}
		switch {
		case len(v.SystemServices) == 1 && v.SystemServices[0] == "ssh":
			sshView = v
		case len(v.SystemServices) == 0 && len(v.Protocols) == 0:
			if len(v.V4Addrs) > 0 {
				dropView = v
			}
		}
	}

	if sshView == nil {
		t.Fatal("no view with the ssh override token set")
	}
	if !eqStr(sshView.V4Addrs, []string{"172.16.50.8"}) {
		t.Errorf("ssh view addrs = %v, want [172.16.50.8] (the overridden interface only)", sshView.V4Addrs)
	}
	if dropView == nil {
		t.Fatal("no empty-token (deny) view for the non-overridden interface")
	}
	if !eqStr(dropView.V4Addrs, []string{"10.0.61.1"}) {
		t.Errorf("deny view addrs = %v, want [10.0.61.1] (the non-overridden interface)", dropView.V4Addrs)
	}
}

// Test_3362_UnionWithZoneLevel asserts the effective per-interface set is the
// UNION of the zone-level set and the interface override (Junos additive
// semantics): a zone-level `ping` plus an interface `ssh` yields {ping, ssh} on
// the overridden interface and {ping} on the others.
func Test_3362_UnionWithZoneLevel(t *testing.T) {
	cfg := hostInboundCfg3362()
	cfg.Security.Zones["wan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"ping"}}

	views := BuildZoneHostInboundViews(cfg)
	got := map[string][]string{} // first-address -> services
	for _, v := range views {
		if len(v.V4Addrs) > 0 {
			got[v.V4Addrs[0]] = v.SystemServices
		}
	}
	if !eqStr(got["172.16.50.8"], []string{"ping", "ssh"}) {
		t.Errorf("overridden iface services = %v, want [ping ssh] (union)", got["172.16.50.8"])
	}
	if !eqStr(got["10.0.61.1"], []string{"ping"}) {
		t.Errorf("non-overridden iface services = %v, want [ping] (zone-level only)", got["10.0.61.1"])
	}
}

// Test_3362_WireCarriesEffectiveOverride asserts the per-interface OVERRIDE
// reaches the dataplane wire: the overridden unit's InterfaceSnapshot is marked
// host-inbound-configured with the EFFECTIVE union token set, while the
// non-overridden unit carries none (Rust falls back to the zone-keyed check).
func Test_3362_WireCarriesEffectiveOverride(t *testing.T) {
	cfg := hostInboundCfg3362()
	cfg.Security.Zones["wan"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"ping"}}

	snaps := buildInterfaceSnapshots(cfg)
	byName := map[string]InterfaceSnapshot{}
	for _, s := range snaps {
		byName[s.Name] = s
	}

	over := byName["reth0.50"]
	if !over.HostInboundConfigured {
		t.Fatal("overridden interface reth0.50 must carry host_inbound_configured=true on the wire")
	}
	if !eqStr(over.HostInboundSystemServices, []string{"ping", "ssh"}) {
		t.Errorf("wire effective services = %v, want [ping ssh] (zone ∪ interface)", over.HostInboundSystemServices)
	}

	plain := byName["reth1.0"]
	if plain.HostInboundConfigured {
		t.Error("non-overridden interface reth1.0 must NOT carry a per-interface override (zone-keyed fallback)")
	}
}

// Test_3362_ZoneSnapshotConfiguredViaInterface asserts a zone enforcing
// host-inbound ONLY via an interface override is still marked configured on the
// ZoneSnapshot (so the Rust XSK secondary path fail-closes non-overridden
// interfaces, consistent with the kernel-nft primary path).
func Test_3362_ZoneSnapshotConfiguredViaInterface(t *testing.T) {
	snaps := buildZoneSnapshots(hostInboundCfg3362())
	var wan *ZoneSnapshot
	for i := range snaps {
		if snaps[i].Name == "wan" {
			wan = &snaps[i]
		}
	}
	if wan == nil {
		t.Fatal("wan zone snapshot missing")
	}
	if !wan.HostInboundConfigured {
		t.Fatal("zone configured only via per-interface override must be HostInboundConfigured=true")
	}
	// No zone-level stanza → zone-keyed token set is empty (fail-closed for any
	// interface in the zone without an override).
	if len(wan.HostInboundSystemServices) != 0 || len(wan.HostInboundProtocols) != 0 {
		t.Errorf("zone-keyed tokens = %v/%v, want empty (interface-only config)",
			wan.HostInboundSystemServices, wan.HostInboundProtocols)
	}
}
