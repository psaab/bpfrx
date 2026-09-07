package dhcprelay

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestComputeDesired_DropsIPv6Server_5557 pins that computeDesired rejects an
// IPv6 server address from a DHCPv4 relay server-group. The relay listener
// binds a udp4 socket, so an IPv6 helper address would be accepted by
// net.ParseIP and then fail silently per-packet at forward time. computeDesired
// must drop it — consistent with the invalid-IP path — so a misconfigured IPv6
// server is surfaced at build time rather than blackholing relayed DISCOVERs.
//
// FAIL-ON-REVERT: remove the `ip.To4() == nil` gate in computeDesired and the
// IPv6 server survives into the relay spec (both spec.servers and the resolved
// UDPAddr list), turning this test RED.
func TestComputeDesired_DropsIPv6Server_5557(t *testing.T) {
	cfg := &config.DHCPRelayConfig{
		ServerGroups: map[string]*config.DHCPRelayServerGroup{
			"sg": {Name: "sg", Servers: []string{"2001:db8::1", "192.0.2.1"}},
		},
		Groups: map[string]*config.DHCPRelayGroup{
			"g": {Name: "g", Interfaces: []string{"ge-0-0-0"}, ActiveServerGroup: "sg"},
		},
	}

	desired := computeDesired(cfg, nil)
	dr, ok := desired["ge-0-0-0"]
	if !ok {
		t.Fatal("computeDesired: no relay entry for ge-0-0-0")
	}

	for _, s := range dr.spec.servers {
		if s == "2001:db8::1" {
			t.Fatalf("IPv6 server survived into relay spec %v (DHCPv4 relay binds udp4)", dr.spec.servers)
		}
	}
	var haveV4 bool
	for _, s := range dr.spec.servers {
		if s == "192.0.2.1" {
			haveV4 = true
		}
	}
	if !haveV4 {
		t.Fatalf("IPv4 server 192.0.2.1 dropped from relay spec %v", dr.spec.servers)
	}

	// The resolved UDPAddr list feeds the udp4 socket directly; it must
	// carry no non-IPv4 address.
	for _, a := range dr.servers {
		if a.IP.To4() == nil {
			t.Fatalf("non-IPv4 UDP addr survived: %v", a.IP)
		}
	}
}
