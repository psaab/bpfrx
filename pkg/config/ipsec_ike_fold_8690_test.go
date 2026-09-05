package config

import "testing"

// #8690. lane-8015 normalized the security family in 950df1331; these two sites
// were left because a commit gate blocked them, not because of anything about
// the fold:
//
//	security ike   policy <p> proposal-set
//	security ipsec policy <p> proposal-set
//
// They share one (container, head) pair and needed the disarm classified before
// any widening could take them.

// The consequence. A `proposal-set` names the crypto proposals an IPsec policy
// offers; brace-elided it compiled to nothing, so the policy negotiated with a
// different proposal set than the operator wrote — and the gate that would have
// said so was itself suppressed by the drop.
func TestElidedProposalSetReachesThePolicy8690(t *testing.T) {
	const braced = `security { ipsec { policy p1 { proposal-set standard; } } }`
	const elided = `security { ipsec { policy p1 proposal-set standard; } }`
	if braced == elided {
		t.Fatal("the two spellings are identical; this cell compares a config to itself")
	}
	b, e := compileText(t, braced), compileText(t, elided)
	if b == nil || e == nil {
		t.Fatalf("both spellings must compile (braced=%v elided=%v)", b != nil, e != nil)
	}
	get := func(c *Config) string {
		if pol, ok := c.Security.IPsec.Policies["p1"]; ok {
			return pol.ProposalSet
		}
		return ""
	}
	// POSITIVE HALF: without this the comparison can be between two empty
	// strings and passes on a compiler that reads neither spelling.
	if get(b) == "" {
		t.Fatal("the braced spelling carried no proposal-set — the fixture no longer " +
			"demonstrates the field being read, so the assertion below is vacuous")
	}
	if get(e) != get(b) {
		t.Errorf("the brace-elided proposal-set compiled to %q, not %q — the policy offers a "+
			"different proposal set than the operator wrote (#8690)", get(e), get(b))
	}
}

// The pair must stay a PAIR. `proposal-set` under an unrelated container is not
// what was measured, and a head-only rule would admit it.
func TestProposalSetIsScopedToPolicy8690(t *testing.T) {
	if !compactNormalizeInScope("policy", "proposal-set") {
		t.Error("`policy proposal-set` must be admitted — it is the pair these two sites share")
	}
	if compactNormalizeInScope("zzunrelated", "proposal-set") {
		t.Error("`proposal-set` is admitted under an arbitrary container — the scope has " +
			"degenerated to a head-only match (#8690)")
	}
}
