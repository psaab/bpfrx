package config

import (
	"strings"
	"testing"
)

func hasWarn4455B(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// TestHostInboundManagedRoutingMismatch covers the #4455 Component B advisory:
// a managed FRR routing protocol (OSPF/OSPFv3/RIP) enabled on an interface whose
// zone omits the matching host-inbound-traffic token warns; supplying the token
// (or `all`, or a per-interface override) silences it; and there is no false
// warning without managed routing or for an out-of-zone interface.
func TestHostInboundManagedRoutingMismatch(t *testing.T) {
	mkZone := func(iface string, zoneProtocols []string) *ZoneConfig {
		z := &ZoneConfig{Interfaces: []string{iface}}
		if zoneProtocols != nil {
			z.HostInboundTraffic = &HostInboundTraffic{Protocols: zoneProtocols}
		}
		return z
	}
	ospfOn := func(iface string) *OSPFConfig {
		return &OSPFConfig{Areas: []*OSPFArea{{Interfaces: []*OSPFInterface{{Name: iface}}}}}
	}

	// (a) OSPF enabled, zone omits `protocols ospf` → warns.
	cfgA := &Config{}
	cfgA.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0", nil)}
	cfgA.Protocols.OSPF = ospfOn("ge-0/0/0.0")
	if w := validateHostInboundManagedRoutingMismatch(cfgA); !hasWarn4455B(w, `protocols ospf is enabled on interface "ge-0/0/0.0" (security zone "trust")`) {
		t.Fatalf("(a) expected OSPF-without-token warning, got %v", w)
	}

	// (b) zone WITH `protocols ospf` → no warning.
	cfgB := &Config{}
	cfgB.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0", []string{"ospf"})}
	cfgB.Protocols.OSPF = ospfOn("ge-0/0/0.0")
	if w := validateHostInboundManagedRoutingMismatch(cfgB); len(w) != 0 {
		t.Fatalf("(b) expected no warning with protocols ospf, got %v", w)
	}

	// (b2) `all` counts as present.
	cfgB2 := &Config{}
	cfgB2.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0", []string{"all"})}
	cfgB2.Protocols.OSPF = ospfOn("ge-0/0/0.0")
	if w := validateHostInboundManagedRoutingMismatch(cfgB2); len(w) != 0 {
		t.Fatalf("(b2) expected no warning with protocols all, got %v", w)
	}

	// (c) per-interface #3362 override supplies the token → no warning.
	cfgC := &Config{}
	zc := mkZone("ge-0/0/0.0", nil)
	zc.InterfaceHostInbound = map[string]*HostInboundTraffic{"ge-0/0/0.0": {Protocols: []string{"ospf"}}}
	cfgC.Security.Zones = map[string]*ZoneConfig{"trust": zc}
	cfgC.Protocols.OSPF = ospfOn("ge-0/0/0.0")
	if w := validateHostInboundManagedRoutingMismatch(cfgC); len(w) != 0 {
		t.Fatalf("(c) expected no warning with per-interface override, got %v", w)
	}

	// (d) RIP + OSPFv3 families warn on missing tokens.
	cfgD := &Config{}
	cfgD.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0", nil)}
	cfgD.Protocols.RIP = &RIPConfig{Interfaces: []string{"ge-0/0/0.0"}}
	cfgD.Protocols.OSPFv3 = &OSPFv3Config{Areas: []*OSPFv3Area{{Interfaces: []*OSPFv3Interface{{Name: "ge-0/0/0.0"}}}}}
	wD := validateHostInboundManagedRoutingMismatch(cfgD)
	if !hasWarn4455B(wD, `protocols rip is enabled`) || !hasWarn4455B(wD, `protocols ospf3 is enabled`) {
		t.Fatalf("(d) expected RIP + OSPFv3 warnings, got %v", wD)
	}

	// (e) no managed routing → no warning.
	cfgE := &Config{}
	cfgE.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0", nil)}
	if w := validateHostInboundManagedRoutingMismatch(cfgE); len(w) != 0 {
		t.Fatalf("(e) expected no warning without managed routing, got %v", w)
	}

	// (f) OSPF on an interface NOT in any zone → no warning (no host-inbound dimension).
	cfgF := &Config{}
	cfgF.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/1.0", nil)}
	cfgF.Protocols.OSPF = ospfOn("ge-0/0/0.0")
	if w := validateHostInboundManagedRoutingMismatch(cfgF); len(w) != 0 {
		t.Fatalf("(f) expected no warning for interface not in any zone, got %v", w)
	}

	// (g) a routing-instance's OSPF is also checked.
	cfgG := &Config{}
	cfgG.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0", nil)}
	cfgG.RoutingInstances = []*RoutingInstanceConfig{{Name: "vr1", OSPF: ospfOn("ge-0/0/0.0")}}
	if w := validateHostInboundManagedRoutingMismatch(cfgG); !hasWarn4455B(w, `protocols ospf is enabled`) {
		t.Fatalf("(g) expected routing-instance OSPF warning, got %v", w)
	}
}
