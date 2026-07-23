package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestGenerateProtocols_SanitizesVRFName_5557 is the render-side belt for the
// `router <proto> ... vrf <name>` clauses (FINDING 2, #6393 review). The
// routing-instance name is free text: it is validated at commit, but the
// tolerant load / HA config-sync paths only warn (#1960 no-brick), so a control
// character in the name would otherwise inject a standalone line into the
// managed frr.conf — the same threat fix #5557 closed for the static-route vrf
// clause. generateProtocols feeds vrfName into the OSPF/OSPFv3/BGP/RIP/IS-IS
// `router ... vrf` suffix.
//
// FAIL-ON-REVERT: drop sanitizeFRRValue from the vrfSuffix build in
// generateProtocols (policy_render.go) and the embedded newline reaches
// frr.conf, so `router bgp 65000` renders as a standalone line -> RED.
func TestGenerateProtocols_SanitizesVRFName_5557(t *testing.T) {
	m := New()
	inj := "red\nrouter bgp 65000"
	ospf := &config.OSPFConfig{}
	bgp := &config.BGPConfig{LocalAS: 65001}

	got := m.generateProtocols(ospf, nil, bgp, nil, nil, inj, 0, nil, nil)

	for _, line := range strings.Split(got, "\n") {
		if strings.TrimSpace(line) == "router bgp 65000" {
			t.Fatalf("vrf-name injection rendered a standalone %q line:\n%s", "router bgp 65000", got)
		}
	}
	// The sanitized name (newline -> space) must still ride on the router lines.
	if !strings.Contains(got, "router ospf vrf red router bgp 65000\n") {
		t.Fatalf("router ospf line missing the sanitized vrf name:\n%s", got)
	}
	if !strings.Contains(got, "router bgp 65001 vrf red router bgp 65000\n") {
		t.Fatalf("router bgp line missing the sanitized vrf name:\n%s", got)
	}
}

// TestBFDSection_SanitizesPeerVRFName_5557 is the render-side belt for the
// `bfd` block's `peer <addr> vrf <name>` clause (FINDING 2, #6393 review). The
// BFD peer carries the same free-text routing-instance name and is the third vrf
// interpolation site; it was interpolated unsanitized.
//
// FAIL-ON-REVERT: drop sanitizeFRRValue from the `peer ... vrf` Fprintf in
// bfdSection.render (policy_render.go) and the embedded newline injects a
// standalone `router bgp 65000` line into the bfd block -> RED.
func TestBFDSection_SanitizesPeerVRFName_5557(t *testing.T) {
	s := newBFDSection()
	s.addPeer(bfdPeer{
		address: "10.0.0.1",
		vrfName: "blue\nrouter bgp 65000",
	})
	got := s.render()

	for _, line := range strings.Split(got, "\n") {
		if strings.TrimSpace(line) == "router bgp 65000" {
			t.Fatalf("bfd peer vrf-name injection rendered a standalone %q line:\n%s", "router bgp 65000", got)
		}
	}
	if !strings.Contains(got, " peer 10.0.0.1 vrf blue router bgp 65000\n") {
		t.Fatalf("bfd peer line missing the sanitized vrf name:\n%s", got)
	}
}
