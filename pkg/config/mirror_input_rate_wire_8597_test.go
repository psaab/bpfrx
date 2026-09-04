package config

import (
	"math"
	"testing"
)

// #8597 (muse-004 K68) — a port-mirroring `input rate` above the 32-bit wire
// field wrapped, and it wrapped onto a SENTINEL.
//
// `Rate: uint32(inst.InputRate)` is the wire field, at TWO sites
// (pkg/dataplane/userspace/mirrors.go and pkg/dataplane/compiler.go). `rate
// 4294967296` wraps to exactly ZERO, which in that field means MIRROR EVERY
// PACKET: an operator asking for the sparsest possible sample gets a full
// traffic duplicate onto the output interface.
//
// That is worse than the negative case this predicate was written for (#6534).
// A negative rate mirrors nothing while the screen reads "Input rate: all
// packets" — the screen lies. A wrapped zero makes the screen and the behaviour
// AGREE, and both are the opposite of what was asked for.
//
// The sibling knob already had the bound: `forwarding-options sampling` caps
// its own InputRate at math.MaxUint32 (#1977, pkg/dataplane/userspace/flow.go).
// Port mirroring was left out of that sweep.
//
// The fix goes in the SHARED predicate rather than at the two cast sites,
// because `PortMirroringInstanceExcludedReason` is what the snapshot builder
// AND all three show surfaces consult (#6534). Fixing the casts alone would
// drop the instance while three screens still rendered it as armed.

func TestOversizedMirrorInputRateIsExcluded_8597(t *testing.T) {
	for _, tc := range []struct {
		name string
		rate int
		want bool // excluded?
	}{
		{"the wrap-to-zero value", math.MaxUint32 + 1, true},
		{"far above the field", 1 << 40, true},
		{"the field maximum itself", math.MaxUint32, false},
		{"an ordinary rate", 1000, false},
		{"zero means mirror every packet, and is legal", 0, false},
		{"one", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst := &PortMirrorInstance{Output: "ge-0/0/1", InputRate: tc.rate}
			reason := PortMirroringInstanceExcludedReason(inst)
			if (reason != "") != tc.want {
				t.Fatalf("rate %d: excluded=%q, want excluded=%v", tc.rate, reason, tc.want)
			}
			if tc.want && reason != "input rate above the 32-bit wire field" {
				t.Errorf("rate %d excluded for %q; the reason is rendered on three show "+
					"surfaces and must name the actual cause", tc.rate, reason)
			}
		})
	}
}

// TestMirrorRateBoundaryIsTheWireWidth_8597 pins WHY the boundary sits where it
// does, so a future edit cannot move it to a round number.
//
// The discriminator is not "large"; it is "does the uint32 cast change the
// value". This asserts that for every case: an admitted rate must survive the
// cast unchanged, and an excluded one must not.
func TestMirrorRateBoundaryIsTheWireWidth_8597(t *testing.T) {
	for _, rate := range []int{0, 1, 1000, math.MaxUint32 - 1, math.MaxUint32,
		math.MaxUint32 + 1, math.MaxUint32 + 2, 1 << 40} {
		inst := &PortMirrorInstance{Output: "ge-0/0/1", InputRate: rate}
		excluded := PortMirroringInstanceExcludedReason(inst) != ""
		survivesCast := int(uint32(rate)) == rate
		if excluded == survivesCast {
			t.Errorf("rate %d: excluded=%v but uint32 cast %s the value — the predicate "+
				"must exclude exactly the rates the wire field cannot carry",
				rate, excluded, map[bool]string{true: "PRESERVES", false: "CHANGES"}[survivesCast])
		}
	}
}

// TestNegativeMirrorRateStillExcludedForItsOwnReason_8597 is the regression
// guard for #6534: adding the upper bound must not swallow the lower one, and
// the two must keep their distinct messages — the operator reading a show
// surface is told which mistake they made.
func TestNegativeMirrorRateStillExcludedForItsOwnReason_8597(t *testing.T) {
	inst := &PortMirrorInstance{Output: "ge-0/0/1", InputRate: -1}
	if got := PortMirroringInstanceExcludedReason(inst); got != "negative input rate" {
		t.Errorf("negative rate excluded for %q, want \"negative input rate\" (#6534)", got)
	}
	inst = &PortMirrorInstance{Output: "", InputRate: 100}
	if got := PortMirroringInstanceExcludedReason(inst); got != "no output interface configured" {
		t.Errorf("missing output excluded for %q", got)
	}
}
