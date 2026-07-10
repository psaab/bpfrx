package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestGenerateProtocols_InvalidClusterIDSkipped_4919 is the render-side
// defense-in-depth for #4919: `protocols bgp cluster-id` is stored verbatim, so
// a leniently-loaded / peer-synced / rolled-back config may carry a malformed
// value. FRR/vtysh accepts only an IPv4 dotted-quad or a 32-bit integer and
// rejects anything else, failing the whole frr-reload; an embedded-newline
// value would additionally inject a standalone frr.conf line. The commit gate
// (config.ValidateBGPClusterID) hard-rejects on commit; this render guard keeps
// a leniently-loaded bad cluster-id out of frr.conf entirely.
//
// FAIL-ON-REVERT: without the validClusterID()/sanitizeFRRValue guard the
// rendered output contains the malformed cluster-id line (and, for the newline
// payload, an injected `router bgp` line) → RED.
func TestGenerateProtocols_InvalidClusterIDSkipped_4919(t *testing.T) {
	m := New()

	for _, bad := range []string{"not.an.ip", "2001:db8::1", "0", "4294967296"} {
		bgp := &config.BGPConfig{LocalAS: 65001, ClusterID: bad}
		got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
		if strings.Contains(got, "cluster-id "+bad) {
			t.Errorf("renderer emitted invalid cluster-id %q; output:\n%s", bad, got)
		}
	}

	// Embedded-newline injection: the whole value is skipped, so no injected
	// standalone command line appears.
	inj := &config.BGPConfig{LocalAS: 65001, ClusterID: "10.0.0.1\n router bgp 65000"}
	got := m.generateProtocols(nil, nil, inj, nil, nil, "", 0, nil, nil)
	for _, line := range strings.Split(got, "\n") {
		if strings.TrimSpace(line) == "router bgp 65000" {
			t.Fatalf("cluster-id injection: rendered a standalone %q line:\n%s", "router bgp 65000", got)
		}
	}

	// Both valid forms still render.
	for _, good := range []string{"10.0.0.1", "5"} {
		bgp := &config.BGPConfig{LocalAS: 65001, ClusterID: good}
		out := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
		if !strings.Contains(out, "bgp cluster-id "+good+"\n") {
			t.Errorf("renderer dropped a valid cluster-id %q; output:\n%s", good, out)
		}
	}
}

// TestGeneratePolicyOptions_InvalidOriginSkipped_4919 is the render-side belt
// for the route-map `then origin` slot: only igp | egp | incomplete are valid
// FRR origins, so a non-control typo (`igpp`) or a leniently-loaded bad value
// is skipped (fail-closed) rather than rendered into a reload-poisoning line.
//
// FAIL-ON-REVERT: without the validBGPOrigin guard the invalid origin renders a
// `set origin igpp` line → RED.
func TestGeneratePolicyOptions_InvalidOriginSkipped_4919(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{Name: "t1", Origin: "igpp", Action: "accept"},
					{Name: "t2", Origin: "igp", Action: "accept"},
				},
			},
		},
	}

	got := m.generatePolicyOptions(po)
	if strings.Contains(got, "set origin igpp") {
		t.Errorf("renderer emitted invalid `set origin igpp`; output:\n%s", got)
	}
	if !strings.Contains(got, "set origin igp\n") {
		t.Errorf("renderer dropped the valid `set origin igp`; output:\n%s", got)
	}
}
