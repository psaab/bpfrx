package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2980 defense-in-depth: the FRR renderer must never emit an invalid
// router-id. router-id is parsed as a raw string, so a leniently-loaded
// (already-persisted / peer-synced) config may carry a non-IPv4 value.
// FRR/vtysh requires a 32-bit IPv4 dotted-quad router-id for ALL routing
// protocols (including the IPv6 protocols OSPFv3 and BGP) and rejects anything
// else, failing the whole frr-reload. The commit-time gate (pkg/config
// validateRouterIDStrict) hard-rejects on commit; this render guard keeps the
// leniently-loaded bad router-id out of frr.conf entirely.
//
// FAIL-ON-REVERT: without the validRouterID() guard the rendered output
// contains the malformed router-id line, turning this test RED.
func TestGenerateProtocols_InvalidRouterIDSkipped(t *testing.T) {
	m := New()

	ospf := &config.OSPFConfig{RouterID: "not-an-ip"}
	ospfv3 := &config.OSPFv3Config{RouterID: "2001:db8::1"}
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "bogus.id",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.3.1", PeerAS: 65003},
		},
	}

	got := m.generateProtocols(ospf, ospfv3, bgp, nil, nil, "", 0, nil)

	for _, bad := range []string{
		"ospf router-id not-an-ip",
		"ospf6 router-id 2001:db8::1",
		"bgp router-id bogus.id",
	} {
		if strings.Contains(got, bad) {
			t.Errorf("renderer emitted invalid router-id line %q; output:\n%s", bad, got)
		}
	}

	// A valid router-id still renders.
	valid := m.generateProtocols(
		&config.OSPFConfig{RouterID: "10.0.0.1"}, nil, nil, nil, nil, "", 0, nil)
	if !strings.Contains(valid, "ospf router-id 10.0.0.1\n") {
		t.Errorf("renderer dropped a valid OSPF router-id; output:\n%s", valid)
	}
}
