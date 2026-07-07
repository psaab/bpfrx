package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildManagedSection_CrossContextRouteMapNoLeak_4481 is the fail-on-revert
// guard for #4481. A single policy-statement (SHARED) is applied BOTH as a BGP
// route-map in (its trailing default must be PERMIT — Junos BGP default-accept,
// #2998) AND as an OSPF export (redistribute, whose Junos default is REJECT).
//
// FRR route-maps are keyed by NAME — one object shared across use sites — so the
// BGP-context trailing permit would otherwise govern the OSPF redistribute too,
// leaking every static route that the policy's terms do NOT explicitly match
// into OSPF. The fix renders a per-use-site fail-closed alias
// (SHARED-xpf-redist, trailing deny) and points the redistribute at it while the
// BGP neighbor keeps referencing the permit-default base map.
//
// Revert (resolveRedistribute referencing the bare NAME + no alias emitted)
// turns this RED: the redistribute line becomes
// `redistribute static route-map SHARED` (the permit-default map) and the
// fail-closed `route-map SHARED-xpf-redist deny` sequence disappears.
func TestBuildManagedSection_CrossContextRouteMapNoLeak_4481(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"SHARED": {
				Name: "SHARED",
				// Match only a subset of static routes; everything else must
				// fall to the policy default. In BGP context that default is
				// accept (#2998); in the redistribute context it must be the
				// fail-closed deny, NOT the leaked permit.
				Terms: []*config.PolicyTerm{
					{
						Name:          "t1",
						FromProtocols: []string{"static"},
						PrefixList:    []string{"allowed"},
						Action:        "accept",
					},
				},
				DefaultAction: "",
			},
		},
		PrefixLists: map[string]*config.PrefixList{
			"allowed": {Name: "allowed", Prefixes: []string{"10.0.0.0/8"}},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		// BGP neighbor applies SHARED as an inbound filter → SHARED is
		// collected into bgpAcceptDefault → its base route-map gets the
		// #2998 trailing permit.
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, Import: []string{"SHARED"}},
			},
		},
		// OSPF exports the SAME policy → rendered as a redistribute route-map.
		OSPF: &config.OSPFConfig{
			Areas:  []*config.OSPFArea{{ID: "0.0.0.0"}},
			Export: []string{"SHARED"},
		},
	}

	got := m.buildManagedSection(fc)

	// #2998 preserved: the BGP neighbor applies the base map, which keeps its
	// trailing permit (BGP default-accept).
	if !strings.Contains(got, "neighbor 10.0.2.1 route-map SHARED in\n") {
		t.Fatalf("BGP neighbor must still apply the base route-map SHARED, got:\n%s", got)
	}
	if !strings.Contains(got, "route-map SHARED permit ") {
		t.Errorf("base BGP route-map SHARED must keep its #2998 trailing permit, got:\n%s", got)
	}

	// #4481 fix: the OSPF redistribute references the fail-closed per-use-site
	// alias, and that alias carries a trailing deny.
	if !strings.Contains(got, "redistribute static route-map SHARED-xpf-redist\n") {
		t.Errorf("OSPF redistribute must reference the fail-closed alias SHARED-xpf-redist, got:\n%s", got)
	}
	if !strings.Contains(got, "route-map SHARED-xpf-redist deny ") {
		t.Errorf("the redistribute alias must end fail-closed (trailing deny), got:\n%s", got)
	}

	// The leak itself: the redistribute must NOT point at the bare permit-default
	// map SHARED (this exact line appears only when the trailing accept-all
	// leaks into the IGP). Note the alias line above ends "-xpf-redist\n", so it
	// does not match this bare-name form.
	if strings.Contains(got, "redistribute static route-map SHARED\n") {
		t.Errorf("cross-context leak: OSPF redistribute references the BGP permit-default map SHARED, got:\n%s", got)
	}
}
