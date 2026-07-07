package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func sliceHas(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

// TestBuildUnzonedHostInboundAddrs is the #4420 HI-2 fail-on-revert proof for the
// builder: an interface that carries an address but is assigned to NO security
// zone contributes its firewall-local addresses to the unzoned host-inbound deny
// set, a zoned interface's address does NOT, and an unzoned LIFELINE (fab*) is
// excluded so management is never denied. Reverting BuildUnzonedHostInboundAddrs
// (returning nil) turns the "present" assertions RED.
func TestBuildUnzonedHostInboundAddrs(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		// zoned data interface (its addr must NOT appear in the unzoned deny).
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.1.10/24"}},
		}},
		// addressed interface in NO zone — the fail-open HI-2 closes.
		"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24", "2001:db8:99::1/64"}},
		}},
		// addressed LIFELINE in no zone — must be excluded (fab* prefix).
		"fab5": {Name: "fab5", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.5.5.5/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		// no host-inbound stanza => #3405 default-deny still scopes 10.0.1.10.
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0.0"}},
	}

	v4, v6 := BuildUnzonedHostInboundAddrs(cfg)
	if !sliceHas(v4, "192.0.2.1") {
		t.Errorf("unzoned v4 addr 192.0.2.1 missing from unzoned deny set: %v", v4)
	}
	if !sliceHas(v6, "2001:db8:99::1") {
		t.Errorf("unzoned v6 addr 2001:db8:99::1 missing from unzoned deny set: %v", v6)
	}
	if sliceHas(v4, "10.0.1.10") {
		t.Errorf("ZONED addr 10.0.1.10 must not be in the unzoned deny set: %v", v4)
	}
	if sliceHas(v4, "10.5.5.5") {
		t.Errorf("LIFELINE addr 10.5.5.5 must not be in the unzoned deny set: %v", v4)
	}

	// A zone-less / bootstrap config must yield NO unzoned deny (never turns a
	// no-zones box into deny-all host-inbound).
	nozone := &config.Config{}
	nozone.Interfaces.Interfaces = cfg.Interfaces.Interfaces
	if nv4, nv6 := BuildUnzonedHostInboundAddrs(nozone); nv4 != nil || nv6 != nil {
		t.Errorf("zoneless config must yield no unzoned deny, got v4=%v v6=%v", nv4, nv6)
	}
}
