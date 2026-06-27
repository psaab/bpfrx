package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// bgpImportPolicyConfig builds a FullConfig with one BGP neighbor that
// applies importPolicy as an inbound filter. The policy modifies attributes
// on a single matched term but carries NO policy-level default action
// (DefaultAction == ""), so its fall-off-the-end behavior is the protocol
// default — for BGP import/export that is ACCEPT (#2998).
func bgpImportPolicyConfig() *FullConfig {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"BGP-IN": {
				Name: "BGP-IN",
				// Non-terminating set-only term: bump local-pref on a
				// matched prefix, then fall through. No `then accept`/
				// `then reject`, and no policy-level default action.
				Terms: []*config.PolicyTerm{
					{
						Name:               "t1",
						PrefixList:         []string{"customer-routes"},
						HasLocalPreference: true,
						LocalPreference:    200,
					},
				},
				DefaultAction: "",
			},
		},
		PrefixLists: map[string]*config.PrefixList{
			"customer-routes": {Name: "customer-routes", Prefixes: []string{"10.0.0.0/8"}},
		},
	}
	return &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, Import: []string{"BGP-IN"}},
			},
		},
	}
}

// TestBuildManagedSection_BGPPolicyDefaultAccept is the #2998 guard. A BGP
// import/export policy-statement with no explicit policy-level default
// action must render a TERMINATING `permit` sequence so a route that matches
// no term follows the Junos BGP default-ACCEPT instead of being dropped by
// the FRR route-map's implicit deny (a route blackhole vs vSRX).
//
// Fail-on-revert: restoring the old unconditional trailing `deny` for
// DefaultAction == "" makes the route-map end in `route-map BGP-IN deny`,
// which this test rejects (and the `permit` assertion fails) — RED.
func TestBuildManagedSection_BGPPolicyDefaultAccept(t *testing.T) {
	m := New()
	got := m.buildManagedSection(bgpImportPolicyConfig())

	// The route-map must be applied as the inbound filter.
	if !strings.Contains(got, "neighbor 10.0.2.1 route-map BGP-IN in\n") {
		t.Fatalf("missing inbound route-map application, got:\n%s", got)
	}

	// The terminating default sequence for the BGP-context policy must be a
	// PERMIT (BGP default-accept), NOT a deny.
	if !strings.Contains(got, "route-map BGP-IN permit") {
		t.Errorf("BGP policy with no explicit default action must render a terminating permit, got:\n%s", got)
	}
	// The whole route-map must not carry a trailing blanket deny that would
	// blackhole every non-matching inbound route.
	if strings.Contains(got, "route-map BGP-IN deny") {
		t.Errorf("BGP policy with no explicit default action must NOT render a terminating deny (route blackhole), got:\n%s", got)
	}
}

// TestBuildManagedSection_RedistributePolicyDefaultReject proves the
// fail-closed default is preserved OUTSIDE the BGP route-map context. A
// policy-statement used only as an OSPF export (rendered via
// `redistribute ... route-map`) keeps the trailing `deny` — Junos OSPF
// export default is REJECT, and FRR's redistribute would otherwise leak
// every route of that protocol. This is the deliberate fail-closed posture
// the #2998 fix must NOT weaken.
func TestBuildManagedSection_RedistributePolicyDefaultReject(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"OSPF-EXPORT": {
				Name: "OSPF-EXPORT",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromProtocols: []string{"static"}, Action: "accept"},
				},
				DefaultAction: "",
			},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		OSPF: &config.OSPFConfig{
			Areas:  []*config.OSPFArea{{ID: "0.0.0.0"}},
			Export: []string{"OSPF-EXPORT"},
		},
	}
	got := m.buildManagedSection(fc)
	// The terminating default sequence must be deny (fail-closed). The
	// matched term itself renders `route-map OSPF-EXPORT permit 10`; the
	// trailing default lands at the next seq as a deny.
	if !strings.Contains(got, "route-map OSPF-EXPORT deny") {
		t.Errorf("non-BGP (redistribute) policy with no default action must keep the fail-closed trailing deny, got:\n%s", got)
	}
}

// TestBuildManagedSection_ExplicitRejectStaysDeny proves an explicit Junos
// `then reject` policy-level default still renders `deny` even when the
// policy is applied as a BGP route-map — the BGP default-accept fallback
// applies ONLY to the implicit (no-default-action) case, never overriding an
// operator's explicit reject.
func TestBuildManagedSection_ExplicitRejectStaysDeny(t *testing.T) {
	m := New()
	fc := bgpImportPolicyConfig()
	fc.PolicyOptions.PolicyStatements["BGP-IN"].DefaultAction = "reject"
	got := m.buildManagedSection(fc)
	if !strings.Contains(got, "route-map BGP-IN deny") {
		t.Errorf("explicit `then reject` must render a terminating deny even in BGP context, got:\n%s", got)
	}
}

// TestCollectBGPRouteMapPolicies covers the usage classifier directly: a
// defined policy applied as a neighbor import/export (or global default) is
// collected; a bare redistribute token or an undefined ref is not.
func TestCollectBGPRouteMapPolicies(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"IN":     {Name: "IN"},
			"OUT":    {Name: "OUT"},
			"GLOBAL": {Name: "GLOBAL"},
		},
	}
	bgp := &config.BGPConfig{
		Export: []string{"GLOBAL", "connected"}, // GLOBAL defined, connected bare
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.1", Import: []string{"IN"}, Export: []string{"OUT"}},
			{Address: "10.0.0.2"}, // inherits GLOBAL export default
		},
	}
	dst := map[string]bool{}
	collectBGPRouteMapPolicies(bgp, po, dst)

	for _, want := range []string{"IN", "OUT", "GLOBAL"} {
		if !dst[want] {
			t.Errorf("expected %q in BGP route-map set, got %v", want, dst)
		}
	}
	if dst["connected"] {
		t.Errorf("bare redistribute token must NOT be collected as a route-map policy, got %v", dst)
	}
}
