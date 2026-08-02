package main

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #4555: the gate's DECISION, pinned where it is made.
//
// pkg/dataplane can pin the stats parsing and the headroom arithmetic, but
// not what this binary concludes from them — and an earlier test that
// claimed to pin "an unmeasurable stats line must reach the refusal path"
// only re-asserted `Measured() == false` and `HeadroomPct() == 0`, both
// already covered by TestParseShimVerifierStats_Unmeasurable. It would have
// stayed green with `decide` returning 0 for every input, which is exactly
// the failure it names.
//
// `decide` consumes only `Measured()` and `HeadroomPct()`, so the fixtures
// below are built as ShimVerifierStats values rather than parsed from logs;
// which logs produce an unmeasured value is pinned in pkg/dataplane's
// TestParseShimVerifierStats_Unmeasurable.
//
// Every reachable (stats, override) combination is enumerated, including the
// exit-6 override-success arm the build recipe carries an arm for.
func TestShimverifyDecision(t *testing.T) {
	// Above the floor: 947188/1000000 leaves 5.28%, the current object.
	above := dataplane.ShimVerifierStats{ProcessedInsns: 947188, InsnLimit: 1000000}
	// Below it: 990796/1000000 leaves 0.92%, master before #4555.
	below := dataplane.ShimVerifierStats{ProcessedInsns: 990796, InsnLimit: 1000000}
	// No recognisable stats line: Measured() is false.
	unmeasured := dataplane.ShimVerifierStats{}

	if unmeasured.Measured() {
		t.Fatalf("the unmeasured fixture is measured (%+v); the cases below would not exercise the refusal path", unmeasured)
	}
	if above.HeadroomPct() < dataplane.UserspaceShimMinVerifierHeadroomPct {
		t.Fatalf("the above-floor fixture (%.2f%%) is below the floor %.1f%%",
			above.HeadroomPct(), dataplane.UserspaceShimMinVerifierHeadroomPct)
	}
	if below.HeadroomPct() >= dataplane.UserspaceShimMinVerifierHeadroomPct {
		t.Fatalf("the below-floor fixture (%.2f%%) is above the floor %.1f%%",
			below.HeadroomPct(), dataplane.UserspaceShimMinVerifierHeadroomPct)
	}

	for _, tc := range []struct {
		name       string
		stats      dataplane.ShimVerifierStats
		overridden bool
		want       shimverifyDecision
	}{
		{
			name:  "measured above the floor",
			stats: above,
			want:  shimverifyDecision{exit: 0, label: "PASS"},
		},
		{
			name:       "measured above the floor, override exported but not needed",
			stats:      above,
			overridden: true,
			want:       shimverifyDecision{exit: 0, label: "PASS", staleOverrideNote: true},
		},
		{
			name:  "measured below the floor",
			stats: below,
			want:  shimverifyDecision{exit: 4, label: "LOW-HEADROOM"},
		},
		{
			name:       "measured below the floor, overridden",
			stats:      below,
			overridden: true,
			want:       shimverifyDecision{exit: 6, label: "OVERRIDDEN", overrideConsumed: true},
		},
		{
			name:  "unmeasurable",
			stats: unmeasured,
			want:  shimverifyDecision{exit: 5, label: "UNMEASURED-HEADROOM"},
		},
		{
			name:       "unmeasurable, overridden",
			stats:      unmeasured,
			overridden: true,
			want:       shimverifyDecision{exit: 6, label: "OVERRIDDEN", overrideConsumed: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decide(tc.stats, tc.overridden); got != tc.want {
				t.Errorf("decide(%+v, %v) = %+v, want %+v", tc.stats, tc.overridden, got, tc.want)
			}
		})
	}
}

// The property the exit codes exist for, stated on its own rather than left
// to be read off the table above: the ONLY way to exit 0 is a MEASURED
// object above the floor. An unmeasurable one must never pass, overridden or
// not — a gate that switches itself off when the kernel's log format changes
// reproduces the blind spot it exists to close. An overridden install is 6,
// which still installs but stays distinguishable to the recipe and to CI.
func TestShimverifyNeverPassesAnUnmeasuredObject(t *testing.T) {
	for _, stats := range []dataplane.ShimVerifierStats{
		{},
		{ProcessedInsns: 0, InsnLimit: 1000000},
		{ProcessedInsns: 947188, InsnLimit: 0},
	} {
		if stats.Measured() {
			t.Fatalf("fixture %+v is measured", stats)
		}
		for _, overridden := range []bool{false, true} {
			got := decide(stats, overridden)
			if got.exit == 0 {
				t.Errorf("decide(unmeasured %+v, overridden=%v) = exit 0 — an object whose headroom could not be measured passed the gate", stats, overridden)
			}
			if got.label == "PASS" {
				t.Errorf("decide(unmeasured %+v, overridden=%v) reports PASS", stats, overridden)
			}
			if overridden && !got.overrideConsumed {
				t.Errorf("decide(unmeasured %+v, overridden=true) did not record the override as consumed, so the run would install without announcing itself", stats)
			}
		}
	}
}
