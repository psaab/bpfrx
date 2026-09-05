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
// #8933 CONSUMED THE ORIGINAL EXAMPLE. This cell used to contrast `from
// community` (shape "empty", admitted) with `then community` (shape "partial",
// excluded) -- the same head, one token apart. #8933 measured that the thing
// consuming `then community`'s tail was the DEFECT (the compiler packing the
// action name into PolicyTerm.Action), not a legitimate reader, and admitted
// all eight `then` actions. Both sides of the old contrast are now admitted, so
// the pair can no longer demonstrate anything.
//
// THE REPLACEMENT IS CHOSEN TO BE DURABLE, which the original was not. Head
// `description` is admitted under `unit` and under `policy`, and excluded under
// an INSTANCE-NAME container (`interfaces <name> description`, shape
// "partial"). That exclusion cannot be dissolved by a later fix the way the
// `then` one was: the predicate is keyed on (container keyword, head) and
// production passes `node.Keys[0]`, which for that site is an arbitrary
// interface name. No static pair can name it (#8921). The discrimination this
// cell exists to demonstrate therefore survives the next widening, which is
// exactly what the `then community` version failed to do.
func TestHeadAloneCannotDecideScope8690(t *testing.T) {
	// Admitted under two different containers...
	for _, kw := range []string{"unit", "policy"} {
		if !compactNormalizeInScope(kw, "description") {
			t.Errorf("`%s description` is admitted and must stay in scope; without it "+
				"the contrast below has only one side and proves nothing", kw)
		}
	}
	// ...and excluded under the instance-name container, where the head is
	// identical and only the container differs.
	if compactNormalizeInScope("xpfname", "description") {
		t.Error("`<instance> description` (interfaces <name> description) is shape " +
			"PARTIAL and must NOT be in scope. A head-only rule admits it along with " +
			"`unit description`, which is the mistake this cell exists to catch (#8690)")
	}
	// The consequence on the compiler, not the predicate: the excluded spelling
	// must still diverge. If it stops, the site was fixed elsewhere and the
	// scope should be re-derived rather than left claiming a hazard -- the
	// lesson #8933 taught about the entry that used to stand here.
	const braced = `interfaces { ge-0/0/0 { description "wan uplink"; } }`
	const elided = `interfaces { ge-0/0/0 description "wan uplink"; }`
	tb, te := compileText(t, braced), compileText(t, elided)
	if tb == nil || te == nil {
		t.Skip("the description fixture does not compile in this tree; the inventory's " +
			"drop shape is the binding record for it")
	}
	if cfgEqual(tb, te) {
		t.Log("`<instance> description` now compiles identically in both spellings — it " +
			"may no longer be partial. Re-derive against the current inventory before " +
			"widening further")
	}
}
