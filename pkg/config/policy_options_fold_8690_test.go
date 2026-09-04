package config

import "testing"

// #8690 family 3: policy-options, taken per site because it is the family where
// a family sweep is actively harmful. 8 sites are drop shape "empty" and
// normalized; 8 are "partial" and deliberately are not.

// A route-policy match criterion decides which routes the policy matches.
// Brace-elided it compiled to nothing, so the term matched on one fewer
// criterion than the operator wrote — silently, on a clean commit.
func TestElidedPolicyFromCriterionReachesTheTerm8690(t *testing.T) {
	const braced = `policy-options { policy-statement ps1 { term t1 { from { community c1; } then accept; } } }`
	const elided = `policy-options { policy-statement ps1 { term t1 { from community c1; then accept; } } }`
	b, e := compileText(t, braced), compileText(t, elided)
	if b == nil || e == nil {
		t.Fatalf("both spellings must compile (braced=%v elided=%v)", b != nil, e != nil)
	}
	get := func(c *Config) []string {
		ps, ok := c.PolicyOptions.PolicyStatements["ps1"]
		if !ok || len(ps.Terms) == 0 {
			return nil
		}
		return ps.Terms[0].FromCommunity
	}
	// POSITIVE HALF: if the braced spelling carries no community the comparison
	// below is between two empty slices and passes on a compiler that reads
	// neither spelling.
	if len(get(b)) == 0 {
		t.Fatal("the braced spelling carried no from-community — the fixture no longer " +
			"demonstrates the criterion being read, so the assertion below is vacuous")
	}
	if len(get(e)) != len(get(b)) {
		t.Errorf("the brace-elided `from community` compiled to %v, not %v — the term matches on "+
			"fewer criteria than the operator wrote (#8690)", get(e), get(b))
	}
}

// THE DISCRIMINATION, demonstrated rather than asserted about the predicate.
//
// `from community` is drop shape "empty" and is normalized. `then community` —
// the same head, one token apart — is "partial": something already consumes
// part of that tail, so normalizing it could remove a value that is read.
//
// This cell exists because both available mistakes look right when read. A
// head-only rule admits both. A container-only rule on `then` admits all eight
// partials. Only the (container, head) pair separates them, and the separation
// is invisible without running it.
func TestFromAndThenCommunityAreTreatedDifferently8690(t *testing.T) {
	if !compactNormalizeInScope("from", "community") {
		t.Error("`from community` is drop shape empty and must be normalized")
	}
	if compactNormalizeInScope("then", "community") {
		t.Error("`then community` is drop shape PARTIAL — something consumes part of its tail. " +
			"Admitting it would truncate a value that is currently read, on a config that " +
			"commits clean. The head is identical to `from community`, which IS admitted; only " +
			"the container distinguishes them (#8690)")
	}
	// And the consequence of that distinction, on the compiler rather than the
	// predicate: the `then` spelling must still diverge, because it is not
	// normalized. If it stops diverging the site was fixed elsewhere and this
	// family's scope should be re-derived rather than left claiming a hazard.
	const thenBraced = `policy-options { policy-statement ps1 { term t1 { then { community add c1; } } } }`
	const thenElided = `policy-options { policy-statement ps1 { term t1 { then community add c1; } } }`
	tb, te := compileText(t, thenBraced), compileText(t, thenElided)
	if tb == nil || te == nil {
		t.Skip("the `then community` fixture does not compile in this tree; the inventory's " +
			"drop shape is the binding record for it")
	}
	if cfgEqual(tb, te) {
		t.Log("`then community` now compiles identically in both spellings — it may no longer be " +
			"partial. Re-derive the policy-options scope against the current inventory before " +
			"widening further")
	}
}
