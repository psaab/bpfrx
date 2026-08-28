package cluster

import (
	"testing"
)

// heartbeat_epoch_discriminator_6967_test.go — #6967.
//
// #6967 states an INFORMATION problem: that `refineBootEpoch`'s
// !epochOrderable branch is reached by two situations it "cannot tell apart
// from inside", and that "no predicate over the currently available inputs
// separates them" —
//
//  1. a year-2191 file with a correct clock — corrupt state that SHOULD be
//     healed by writing over it;
//  2. an intact file written by a correctly-clocked predecessor, read by a node
//     whose clock has stepped backward (the issue's own example: 2h) — which
//     MUST NOT be written over.
//
// The premise is false at this head, and it is #6711's `bootEpochPreserveMaxSkew`
// that makes it false: the predicate is "could a real backward step explain this
// gap", and 30 days is where it draws the line. The two situations land on
// OPPOSITE outcomes, in the directions the issue asks for.
//
// WHY THIS TEST EXISTS RATHER THAN A COMMENT. The issue's suggested direction is
// to persist a writer/incarnation tag so the states stop being indistinguishable.
// Adding one would be a SECOND discriminator over an already-discriminated pair:
// for the 2h case it would branch on a condition whose outcome never differs,
// which is a revert wearing the shape of a fix. The only way to know that is to
// measure that the existing discriminator VARIES across the pair — so the
// measurement is a test, not a paragraph, and a future change that collapses the
// two outcomes reds here with the reason attached.
//
// TestBackwardClockStepDoesNotDestroyTheEpochFile6711 already covers the
// stepped-back-clock axis (2h / 1 week preserve, 1 year heals). What it does not
// contain is the other half of #6967's pair — a corrupt value read by a CORRECT
// clock — so on its own it cannot show the two situations are distinguished,
// only that one of them behaves. This adds that half and asserts the contrast
// directly.

// TestCorruptAndBackwardSteppedAreDistinguished_6967 is the discriminator, as a
// contrast rather than as two independent rows.
func TestCorruptAndBackwardSteppedAreDistinguished_6967(t *testing.T) {
	const goodNow = int64(1_800_000_000_000_000_000) // ~2027, a credible clock
	const day = uint64(24 * 60 * 60 * 1_000_000_000)
	const hour = uint64(60 * 60 * 1_000_000_000)

	// Situation 1: a corrupt, far-future persisted value, read by a node whose
	// clock is CORRECT. No backward step is involved at all — which is what
	// distinguishes this cell from the 6711 table, where every row steps the
	// clock back and the "is it garbage" question is entangled with "how far
	// back did we step".
	const corrupt = uint64(7_000_000_000_000_000_000) // ~year 2191
	_, corruptOnDisk, _ := refinedEpochFile(t, corrupt, uint64(goodNow), goodNow)
	if corruptOnDisk == corrupt {
		t.Fatalf("a year-2191 persisted value survived a refinement run under a CORRECT clock "+
			"(file still holds %d). #6669's self-healing property is what stops one bad write "+
			"pinning this node out of its cluster forever, and it depends on this exact case "+
			"being overwritten", corruptOnDisk)
	}

	// Situation 2: an INTACT value written by a correctly-clocked predecessor,
	// read by a node whose clock stepped back 2h — #6967's own example.
	intact := uint64(goodNow)
	backNow := goodNow - int64(2*hour)
	_, intactOnDisk, _ := refinedEpochFile(t, intact, uint64(backNow), backNow)
	if intactOnDisk != intact {
		t.Fatalf("an intact predecessor's epoch was overwritten after a 2h backward clock step "+
			"(file holds %d, want %d). That is the #6711 lockout: the value that keeps this "+
			"node acceptable to its peer is destroyed, so the lockout survives every restart "+
			"instead of ending when the clock is corrected", intactOnDisk, intact)
	}

	// THE CONTRAST, stated as one assertion rather than left implicit in two.
	// #6967's claim is that these two are indistinguishable from inside; they
	// are distinguished, and this is the line that says so.
	if (corruptOnDisk == corrupt) == (intactOnDisk == intact) {
		t.Fatalf("the two situations #6967 calls indistinguishable now land on the SAME "+
			"outcome (corrupt preserved=%v, intact preserved=%v). Whichever way they "+
			"collapsed, one of the two properties is gone: either garbage is no longer healed "+
			"or an intact predecessor is no longer protected",
			corruptOnDisk == corrupt, intactOnDisk == intact)
	}
}

// TestPreserveBandBoundaryIsWhereItSays_6967 pins the discriminator's EDGE.
//
// The contrast above holds for any threshold between 2h and a year, so on its
// own it does not say the band is where the constant claims. These two rows sit
// either side of bootEpochPreserveMaxSkew, which is also the answer to "how big
// is the residual #6967 actually leaves": a backward step beyond 30 days still
// heals over an intact predecessor, and that — not "no predicate exists" — is
// what remains of the issue.
func TestPreserveBandBoundaryIsWhereItSays_6967(t *testing.T) {
	const goodNow = int64(1_800_000_000_000_000_000)
	const day = int64(24 * 60 * 60 * 1_000_000_000)

	// Sanity on the constant itself, so a change to it reaches these rows
	// instead of silently moving what they mean.
	if bootEpochPreserveMaxSkew != uint64(30*day) {
		t.Fatalf("bootEpochPreserveMaxSkew = %d, and these rows are written for 30 days. "+
			"Re-derive the residual on #6967 before changing it: the band IS the predicate "+
			"that separates a corrupt value from an intact predecessor",
			bootEpochPreserveMaxSkew)
	}

	intact := uint64(goodNow)
	for _, tc := range []struct {
		name         string
		stepBackDays int64
		wantPreserve bool
	}{
		{"inside_the_band_preserves", 29, true},
		{"beyond_the_band_heals", 40, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := goodNow - tc.stepBackDays*day
			// Premise: this really does reach the branch under test. Without it a
			// row that stopped being a #6711 shape would pass by not exercising
			// anything.
			if epochOrderable(intact, now) {
				t.Fatalf("fixture: persisted %d is still chainable at %d, so this row never "+
					"reaches the decline-to-chain branch", intact, now)
			}
			_, onDisk, _ := refinedEpochFile(t, intact, uint64(now), now)
			if got := onDisk == intact; got != tc.wantPreserve {
				t.Fatalf("%d-day backward step: preserved=%v, want %v (file holds %d, "+
					"predecessor wrote %d). The band is what separates 'a real backward step "+
					"could explain this' from 'this is garbage'; a row that moved across it "+
					"changes which of #6967's two situations this input belongs to",
					tc.stepBackDays, got, tc.wantPreserve, onDisk, intact)
			}
		})
	}
}
