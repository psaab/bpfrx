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
