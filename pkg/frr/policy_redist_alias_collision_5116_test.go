package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// sharedRedistAliasConfig builds a FullConfig where policy-statement SHARED is
// applied BOTH as a BGP route-map in (→ #2998 trailing permit) AND as an OSPF
// export (→ redistribute), so generatePolicyOptions derives the fail-closed
// per-use-site alias SHARED-xpf-redist (#4481). When withOperatorCollision is
// set, an operator policy-statement literally named SHARED-xpf-redist is ALSO
// defined — the #5116 collision.
func sharedRedistAliasConfig(withOperatorCollision bool) *FullConfig {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"SHARED": {
				Name: "SHARED",
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
	if withOperatorCollision {
		// An operator policy-statement whose name is EXACTLY the generated
		// alias. FRR keys route-maps by NAME, so this and the generated alias
		// would fuse into one object.
		po.PolicyStatements["SHARED-xpf-redist"] = &config.PolicyStatement{
			Name: "SHARED-xpf-redist",
			Terms: []*config.PolicyTerm{
				{Name: "leak", FromProtocols: []string{"static"}, Action: "accept"},
			},
			DefaultAction: "accept", // permit-default — the leak vector
		}
	}
	return &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, Import: []string{"SHARED"}},
			},
		},
		OSPF: &config.OSPFConfig{
			Areas:  []*config.OSPFArea{{ID: "0.0.0.0"}},
			Export: []string{"SHARED"},
		},
	}
}

// TestRedistAliasCollisionRefused is the fail-on-revert guard for the #5116
// render-side defense-in-depth. When a generated fail-closed redistribute alias
// (SHARED-xpf-redist) collides with an operator-defined policy-statement of that
// exact name, redistAliasCollision — the check ApplyFull runs before building
// the managed section — must return an error naming the base policy and the
// colliding alias, so the whole apply fails CLOSED instead of emitting a
// route-map FRR would merge (reintroducing the #4481 BGP/IGP leak).
//
// Revert (dropping the collision check) turns this RED: the collision is
// silently accepted and both route-maps render under the same name.
func TestRedistAliasCollisionRefused(t *testing.T) {
	fc := sharedRedistAliasConfig(true)
	err := redistAliasCollision(fc.PolicyOptions, collectAllBGPAcceptDefault(fc))
	if err == nil {
		t.Fatal("redistAliasCollision accepted a base+derived-name collision " +
			"(SHARED + operator SHARED-xpf-redist); expected a fail-closed error (#5116)")
	}
	for _, want := range []string{"SHARED", "SHARED-xpf-redist", "-xpf-redist"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// TestRedistAliasNoCollisionRendersUnchanged is the negative control: with NO
// operator policy of the alias name, redistAliasCollision returns nil and the
// managed section renders the fail-closed alias unchanged (byte-for-byte the
// #4481 behavior). This proves the guard is SURGICAL — it only fires on an
// actual collision and leaves the common path untouched.
func TestRedistAliasNoCollisionRendersUnchanged(t *testing.T) {
	fc := sharedRedistAliasConfig(false)

	if err := redistAliasCollision(fc.PolicyOptions, collectAllBGPAcceptDefault(fc)); err != nil {
		t.Fatalf("redistAliasCollision flagged a non-colliding config: %v", err)
	}

	got := New().buildManagedSection(fc)
	if !strings.Contains(got, "redistribute static route-map SHARED-xpf-redist\n") {
		t.Errorf("OSPF redistribute must reference the fail-closed alias SHARED-xpf-redist, got:\n%s", got)
	}
	if !strings.Contains(got, "route-map SHARED-xpf-redist deny ") {
		t.Errorf("the redistribute alias must still render fail-closed (trailing deny), got:\n%s", got)
	}
}
