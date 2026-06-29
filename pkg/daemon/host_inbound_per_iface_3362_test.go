package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Test_3362_NftScopesPerInterfaceOverride is the kernel-nftables PRIMARY-path
// proof for per-interface host-inbound (#3362). Zone "corp" has TWO interfaces,
// no zone-level stanza, and an ssh override on ONLY the uplink (reth0.50):
//   - the uplink address (172.16.50.8) ACCEPTs tcp/22 (ssh) and DROPs the rest;
//   - the other interface (10.0.61.1) gets a catch-all DROP with NO ssh accept.
//
// This is the motivating use case: expose management on one interface of a zone,
// deny it on another. Fail-on-revert: collapse the per-interface grouping (one
// zone-wide view) and either both addresses share one token set (10.0.61.1 would
// wrongly accept ssh) or the zone is omitted entirely — both fail here.
func Test_3362_NftScopesPerInterfaceOverride(t *testing.T) {
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
		"corp": {
			Name:       "corp",
			Interfaces: []string{"reth0.50", "reth1.0"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"reth0.50": {SystemServices: []string{"ssh"}},
			},
		},
	}

	payload := buildHostInboundFilterPayload(buildAndCheckViews(t, cfg))

	mustContain := []string{
		// uplink: ssh admitted + catch-all drop.
		"ip daddr 172.16.50.8 tcp dport 22 accept",
		"ip daddr 172.16.50.8 drop",
		// non-overridden interface: catch-all drop (deny-all).
		"ip daddr 10.0.61.1 drop",
	}
	for _, want := range mustContain {
		if !strings.Contains(payload, want) {
			t.Errorf("payload missing %q\n---\n%s", want, payload)
		}
	}
	// The non-overridden interface must NOT admit ssh.
	if strings.Contains(payload, "ip daddr 10.0.61.1 tcp dport 22 accept") {
		t.Errorf("non-overridden interface 10.0.61.1 must NOT accept ssh:\n%s", payload)
	}
}
