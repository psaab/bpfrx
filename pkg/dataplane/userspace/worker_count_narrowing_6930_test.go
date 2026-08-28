package userspace

import (
	"math"
	"testing"
)

// worker_count_narrowing_6930_test.go — #6930.
//
// The issue names an overflow in `heartbeatZeroSlots`, a function #6702 has
// since REMOVED — the zero-init bound no longer derives from the worker count
// at all (`heartbeatZeroSlotBound` returns the whole map). That specific
// multiply cannot overflow because it no longer exists.
//
// The ROOT survived one line away. `effectiveWorkers` skips its clamp entirely
// when `maxW == 0` — i.e. whenever the heartbeat Array holds fewer than
// heartbeatSlotsPerWorker entries — and `planUserspaceWorkers` then casts that
// unbounded value with `uint32(w)`. The A6-b01-C1 failure the doc calls fixed
// reproduces at the CAST instead of at the multiply.
//
// THE FIXTURE VALUES ARE COMPUTED, NOT GUESSED. An arithmetic-order bug is
// invisible to any input that does not actually cross the boundary: a
// large-looking worker count that still fits in uint32 passes against fixed and
// unfixed code alike. 1<<32 and 1<<32+5 are the two the code comment itself
// names, chosen because they narrow to 0 and to 5 — one obviously wrong, one
// plausible enough to survive review.

// degenerateHeartbeatCap is below heartbeatSlotsPerWorker (32), which is the
// ONLY condition under which effectiveWorkers skips its clamp. With the shipped
// shim's 4096-entry Array the clamp always binds, which is why this is
// unreachable today — and why the fixture must set it explicitly rather than
// hoping a big worker count is enough.
const degenerateHeartbeatCap = heartbeatSlotsPerWorker - 1

func TestWorkerCountDoesNotNarrowInTheDegenerateCase6930(t *testing.T) {
	if degenerateHeartbeatCap/heartbeatSlotsPerWorker != 0 {
		t.Fatalf("fixture precondition broken: cap %d must yield maxW == 0, or the "+
			"clamp binds and this cell exercises nothing", degenerateHeartbeatCap)
	}

	for _, tc := range []struct {
		name    string
		workers int
		// narrowed is what uint32(w) produces WITHOUT the fix — recorded so the
		// failure message can name the wrong answer rather than just the right one.
		narrowed uint32
	}{
		{"exactly 2^32 narrows to zero", 1 << 32, 0},
		{"2^32+5 narrows to a plausible 5", 1<<32 + 5, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Confirm the input genuinely crosses the boundary — an arithmetic
			// cell whose input does not overflow proves nothing.
			if uint32(tc.workers) != tc.narrowed {
				t.Fatalf("fixture is not exercising the narrowing: uint32(%d) = %d, "+
					"expected %d", tc.workers, uint32(tc.workers), tc.narrowed)
			}

			plan := planUserspaceWorkers(tc.workers, degenerateHeartbeatCap)

			if plan.Workers == tc.narrowed {
				t.Fatalf("plan.Workers = %d — the unbounded worker count narrowed through "+
					"uint32(). The shim is told there are %d workers and %d queues, which "+
					"for 0 means it believes the dataplane has none, and for a small value "+
					"looks like a legal count and sails through every bound (#6930)",
					plan.Workers, plan.Workers, plan.Workers)
			}
			if plan.Workers != math.MaxUint32 {
				t.Fatalf("plan.Workers = %d, want MaxUint32: with no maxW clamp the only "+
					"honest ceiling is the widest value the cast can carry", plan.Workers)
			}
		})
	}
}

// PAIRED CONTROL — the reachable configuration must be untouched. Without it,
// "clamp the worker count" is satisfied by clamping to 1 (or to MaxUint32
// unconditionally), which would misreport every real box.
func TestReachableWorkerCountsAreUnchanged6930(t *testing.T) {
	// The shipped shim declares 4096 entries, so maxW = 128.
	const shippedCap = 4096
	for _, tc := range []struct {
		workers int
		want    uint32
	}{
		{1, 1},         // the floor
		{4, 4},         // a normal box
		{128, 128},     // exactly maxW
		{500, 128},     // above maxW: the existing clamp binds
		{1 << 32, 128}, // huge, but the maxW clamp binds FIRST — no narrowing possible
	} {
		if got := planUserspaceWorkers(tc.workers, shippedCap).Workers; got != tc.want {
			t.Errorf("planUserspaceWorkers(%d, %d).Workers = %d, want %d — the #6930 "+
				"ceiling changed a reachable answer", tc.workers, shippedCap, got, tc.want)
		}
	}
}

// The degenerate case must still report a worker count rather than zero, which
// is the documented intent the fix must not quietly discard.
func TestDegenerateCapStillReportsAWorkerCount6930(t *testing.T) {
	for _, w := range []int{1, 4, 64} {
		if got := planUserspaceWorkers(w, degenerateHeartbeatCap).Workers; got != uint32(w) {
			t.Errorf("with a sub-slot heartbeat Array, planUserspaceWorkers(%d).Workers = "+
				"%d, want %d — the floor-stays-1 intent says report the count, not zero",
				w, got, w)
		}
	}
}
