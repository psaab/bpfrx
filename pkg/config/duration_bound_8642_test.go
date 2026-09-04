package config

import (
	"math"
	"testing"
	"time"
)

// #8642: the shared converters. The bound is the OVERFLOW POINT of the
// arithmetic, and the anti-over-reject rows are as load-bearing as the
// rejection rows — a config knob clamped away from a legitimately large but
// working value is a silent behaviour change wearing the shape of a safety fix.

func TestSecondsToDurationBoundsAtTheOverflowPoint8642(t *testing.T) {
	fb := 7 * time.Second

	// ACCEPT: an ordinary value, and the LARGEST value that does not overflow.
	// The second row is the anti-over-reject boundary — a ceiling one lower
	// would pass every rejection row below while rewriting a working config.
	if got := SecondsToDuration(300, fb); got != 300*time.Second {
		t.Errorf("SecondsToDuration(300) = %v, want 300s", got)
	}
	maxOK := int(MaxDurationSeconds)
	if got := SecondsToDuration(maxOK, fb); got != time.Duration(maxOK)*time.Second {
		t.Errorf("SecondsToDuration(MaxDurationSeconds) = %v, want it ACCEPTED — "+
			"it is the largest value the multiply survives, so rejecting it "+
			"clamps a configuration that works", got)
	}

	// REJECT: one past the overflow point, and the value whose residue is the
	// smallest positive one (512ns), which is what defeats every `<= 0` guard.
	if got := SecondsToDuration(maxOK+1, fb); got != fb {
		t.Errorf("SecondsToDuration(MaxDurationSeconds+1) = %v, want the fallback", got)
	}
	if got := SecondsToDuration(20211507185753197, fb); got != fb {
		t.Errorf("SecondsToDuration(20211507185753197) = %v, want the fallback. "+
			"That value's residue is exactly 512ns — a plausible-looking POSITIVE "+
			"interval that sails through any `<= 0` or `> 0` check", got)
	}
	if got := SecondsToDuration(0, fb); got != fb {
		t.Errorf("SecondsToDuration(0) = %v, want the fallback", got)
	}
	if got := SecondsToDuration(-1, fb); got != fb {
		t.Errorf("SecondsToDuration(-1) = %v, want the fallback", got)
	}
}

func TestMillisToDurationBoundsAtItsOwnOverflowPoint8642(t *testing.T) {
	fb := 11 * time.Millisecond

	if got := MillisToDuration(30, fb); got != 30*time.Millisecond {
		t.Errorf("MillisToDuration(30) = %v, want 30ms", got)
	}
	maxOK := int(MaxDurationMillis)
	if got := MillisToDuration(maxOK, fb); got != time.Duration(maxOK)*time.Millisecond {
		t.Errorf("MillisToDuration(MaxDurationMillis) = %v, want it ACCEPTED", got)
	}
	if got := MillisToDuration(maxOK+1, fb); got != fb {
		t.Errorf("MillisToDuration(MaxDurationMillis+1) = %v, want the fallback", got)
	}

}

// THE UNIT IS NOT INTERCHANGEABLE, and the direction of the difference is the
// opposite of the intuitive one: MILLISECONDS admit 1000x MORE counts before
// overflow (MaxDurationMillis ≈ 9.2e12 vs MaxDurationSeconds ≈ 9.2e9), because
// each count is worth 1000x fewer nanoseconds.
//
// So the dangerous confusion is a SECONDS site bounded at the MILLISECOND
// ceiling: it would accept ~9.2e12 seconds and overflow. Every rejection row in
// the seconds test above still passes under that mistake, which is why this row
// exists separately — and why the two are distinct functions rather than one
// taking a unit parameter.
func TestASecondsKnobIsNotBoundedAtTheMillisecondCeiling8642(t *testing.T) {
	fb := 7 * time.Second

	// PRECONDITION, because this row only discriminates if the ceilings differ
	// in the direction assumed. The first draft of this cell had them backwards
	// and this assertion is what caught it.
	if MaxDurationMillis <= MaxDurationSeconds {
		t.Fatalf("fixture: MaxDurationMillis (%d) must EXCEED MaxDurationSeconds "+
			"(%d)", MaxDurationMillis, MaxDurationSeconds)
	}

	withinMillisPastSeconds := int(MaxDurationSeconds) + 1
	if int64(withinMillisPastSeconds) > MaxDurationMillis {
		t.Fatalf("fixture: %d must be inside the millisecond ceiling",
			withinMillisPastSeconds)
	}
	if got := SecondsToDuration(withinMillisPastSeconds, fb); got != fb {
		t.Errorf("SecondsToDuration(%d) = %v, want the fallback — that value is "+
			"inside MaxDurationMillis but PAST MaxDurationSeconds, so a seconds "+
			"knob bounded at the millisecond ceiling would accept it and overflow",
			withinMillisPastSeconds, got)
	}
}

// The residues this family produces are positive and plausible, which is the
// whole reason the existing guards were blind. Demonstrated rather than
// asserted, so the claim in the header is checkable.
func TestTheOverflowResidueIsSmallAndPositive8642(t *testing.T) {
	// A variable, not a const: the compiler rejects the constant form outright
	// ("overflows int64"), which is exactly the protection the RUNTIME path does
	// not get — the value arrives from strconv.Atoi at run time.
	n := 20211507185753197
	wrapped := time.Duration(n) * time.Second // deliberate: this is the defect
	if wrapped <= 0 {
		t.Fatalf("residue = %v; the premise of this whole sweep is that the wrap "+
			"can be POSITIVE, and a negative one would be caught by the `<= 0` "+
			"guards already present", wrapped)
	}
	if wrapped > time.Millisecond {
		t.Errorf("residue = %v, expected a sub-millisecond value — the hazard is "+
			"that it looks like a plausible fast interval", wrapped)
	}
	if MaxDurationSeconds != int64(math.MaxInt64)/int64(time.Second) {
		t.Error("MaxDurationSeconds is not the overflow point of the arithmetic")
	}
}
