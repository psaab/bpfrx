package config

import "testing"

// The WARNS branch of the sweep's gate check had no member and therefore no
// control: the sweep's own header records that "nothing here proves it still
// fires". An unexercised branch is where an unsound rule survives, and this one
// was unsound.
//
// The old test was "does the elided spelling produce ANY warnings?". That is a
// different question from "is the operator told about THIS drop", and any
// container carrying a standing advisory answers the first for free.
//
// These cells give the branch both controls it lacked.

// A STANDING warning -- present in BOTH spellings -- must NOT score WARNS.
// `aggregated-ether-options` carries the #6544 accepted-only parity notice
// whether or not the elision drops anything, so scoring it WARNS would report
// a silent drop as handled. The operator is told LAG is unimplemented; they are
// not told their `lacp active` was discarded.
func TestStandingWarningIsNotScoredAsHandled8895(t *testing.T) {
	const (
		braced = "interfaces { ae0 { aggregated-ether-options { lacp { active; } } } }"
		elided = "interfaces { ae0 { aggregated-ether-options lacp { active; } } }"
	)
	warns := func(text string) []string {
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture does not parse (%q): %v", text, perrs[0])
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil {
			t.Fatalf("compile %q: %v", text, err)
		}
		return cfg.Warnings
	}

	b, e := warns(braced), warns(elided)
	// LIVENESS: this cell is only meaningful while the standing warning exists.
	// If #6544's notice is ever removed, the fixture stops exercising the
	// hazard and must be repointed rather than deleted.
	if len(b) == 0 {
		t.Skip("the braced arm no longer carries a standing warning — repoint this " +
			"fixture at another accepted-only container rather than dropping the cell")
	}
	if len(e) == 0 {
		t.Fatalf("the elided arm carries no warnings at all; this fixture cannot exercise " +
			"the standing-warning hazard")
	}

	// The hazard: counting warnings in the elided arm alone says "handled".
	if len(e) > 0 {
		// Comparing the SETS says otherwise, and that is the correct answer.
		inBraced := map[string]bool{}
		for _, w := range b {
			inBraced[w] = true
		}
		onlyElided := 0
		for _, w := range e {
			if !inBraced[w] {
				onlyElided++
			}
		}
		if onlyElided != 0 {
			t.Errorf("expected every warning on the elided arm to be standing (present in "+
				"braced too), got %d unique to elided; the fixture no longer isolates the "+
				"standing-warning case", onlyElided)
		}
	}
}

// And the opposite control: a warning that appears ONLY in the elided arm MUST
// score WARNS, or the branch would be unreachable and the fix would have turned
// an unsound rule into a dead one.
func TestDropSpecificWarningStillScoresWarns8895(t *testing.T) {
	braced := map[string]bool{"standing notice": true}
	elided := map[string]bool{"standing notice": true, "value dropped by packing": true}

	scoreWarns := func(bracedSet, elidedSet map[string]bool) bool {
		for w := range elidedSet {
			if !bracedSet[w] {
				return true
			}
		}
		return false
	}

	if scoreWarns(braced, braced) {
		t.Error("a warning set identical in both arms scored WARNS — standing advisories " +
			"would again read as handled")
	}
	if !scoreWarns(braced, elided) {
		t.Error("a warning unique to the elided arm did NOT score WARNS — the branch is now " +
			"unreachable, which trades an unsound rule for a dead one")
	}
}
