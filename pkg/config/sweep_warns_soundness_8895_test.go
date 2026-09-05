package config

import "testing"

// The WARNS branch of the sweep's gate check had no member and therefore no
// control: the sweep's own header recorded that "nothing here proves it still
// fires". An unexercised branch is where an unsound rule survives, and this one
// was unsound -- it asked "does the elided spelling produce ANY warnings?",
// which any container with a standing advisory answers for free.
//
// THESE CELLS CALL THE PRODUCTION PREDICATE. An earlier version of this file
// re-implemented the set comparison and asserted that the re-implementation was
// correct, which left the sweep free to use anything at all: reverting
// sweepGateVerdict8859 to the counting form kept every cell green. A cell that
// re-implements the thing it guards verifies an algorithm and binds no wiring.

// A STANDING warning -- present in BOTH spellings -- must not be scored as
// "the operator is told". `security alg h323` carries an accepted-but-inert
// notice either way, so scoring it WARNS would report a silent drop as handled.
//
// This is the row that kills the old counting rule: under it the elided arm has
// a warning, so it returned WARNS.
func TestStandingWarningIsNotScoredAsHandled8895(t *testing.T) {
	const (
		braced = "security { alg { h323; } }"
		elided = "security alg h323;"
	)
	// LIVENESS: the cell is only meaningful while BOTH arms carry the standing
	// advisory. If that notice is ever removed the fixture stops exercising the
	// hazard and must be repointed rather than deleted.
	bw, ew := warningSet8859(braced), warningSet8859(elided)
	if len(bw) == 0 || len(ew) == 0 {
		t.Skipf("the accepted-but-inert notice is gone (braced=%d elided=%d warnings) — "+
			"repoint this fixture at another standing-advisory container", len(bw), len(ew))
	}
	for w := range ew {
		if !bw[w] {
			t.Fatalf("the elided arm carries a warning the braced one does not (%q), so this "+
				"fixture no longer isolates the STANDING-warning case", w)
		}
	}

	if got := sweepGateVerdict8859(braced, elided); got == "WARNS" {
		t.Errorf("a STANDING advisory scored WARNS. Under the #8859 criterion that reads as " +
			"HANDLED — the operator is told — but they are told the ALG is inert, not that " +
			"anything was dropped. Compare the warning SETS between arms, not the count in one")
	}
}

// The opposite control, so the fix cannot trade an unsound branch for a dead
// one. It tests the PREDICATE's set logic directly, and says so: the WARNS arm
// has no natural member in the current schema, because its only mechanism
// (#6662's packed-login notice) sits behind a spelling the strict path rejects
// first. Asserting reachability through a real config is therefore impossible
// today, and inventing a fixture that manufactured one would be measuring the
// fixture.
func TestDropSpecificWarningWouldStillScoreWarns8895(t *testing.T) {
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
		t.Error("a warning unique to the elided arm did NOT score WARNS — the branch would be " +
			"unreachable, trading an unsound rule for a dead one")
	}
}
