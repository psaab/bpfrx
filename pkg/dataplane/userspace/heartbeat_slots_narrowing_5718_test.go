package userspace

import "testing"

// TestHeartbeatZeroSlotsClampsBeforeNarrowing_5718 is the #5718 A6-b01-C1
// fail-on-revert.
//
// #6702 blocker 2 MOVED this test's subject rather than retiring it. The
// property is unchanged — the clamp must bind BEFORE the uint32 cast, for
// every int a min-only schema leaf can carry — but the quantity that still
// has that hazard is the WORKER COUNT reported to the shim
// (`plan.Workers`, which feeds ctrl.Workers and ctrl.QueueCount), not the
// heartbeat loop bound. The loop bound is now the Array's own capacity and
// does not read `workers` at all, so it has no narrowing left to test; keeping
// these fixtures pointed at it would have left a green that guards nothing.
// The fixtures below are the originals, verbatim, and they still discriminate:
// a cast-first `effectiveWorkers` reports 0 workers for 1<<32 and 5 for
// 1<<32+5.
//
// effectiveWorkers bounds the reported count into [1, mapCap/perWorker].
// Both clamps must bind for EVERY int the caller can supply. Casting to uint32 first (`uint32(maxInt(workers, 1))`,
// the pre-#5718 shape) discards the high 32 bits BEFORE either clamp sees the
// value, so a worker count above the uint32 range lands somewhere inside the
// legal window and both clamps wave it through:
//
//   - 1<<32 narrows to 0. It is <= maxW, so the high clamp passes it, and the
//     low clamp already ran on the pre-cast value — the function returns 0 and
//     zero-initialises NOTHING, leaving every worker's heartbeat slot holding
//     stale data.
//   - 1<<32+5 narrows to 5, so a config asking for four billion workers
//     silently zeroes five workers' worth of slots.
//
// The existing #4572 test stops at 999999999, which is below the narrowing
// boundary, so it cannot observe either case. `workers` is a min-only schema
// leaf (ValidateIntegerMin(1)) with no upper bound in deriveUserspaceConfig,
// so these values are reachable from config.
func TestHeartbeatZeroSlotsClampsBeforeNarrowing_5718(t *testing.T) {
	const perWorker = uint32(heartbeatSlotsPerWorker)
	// A realistic fixed-size Array capacity: 64 workers' worth of slots.
	const mapCap = uint32(64) * perWorker
	// The clamped WORKER count the Array can carry slots for.
	const maxWorkers = uint32(64)

	tests := []struct {
		name    string
		workers int
		want    uint32
	}{
		{
			// The exact uint32 wrap-to-zero. A cast-first implementation
			// returns 0 here and skips zero-init entirely.
			name:    "one past the uint32 range narrows to zero",
			workers: 1 << 32,
			want:    maxWorkers,
		},
		{
			// Narrows to 5 under a cast-first implementation, which is a
			// legal-looking worker count well under maxW.
			name:    "uint32 range plus five narrows into the legal window",
			workers: 1<<32 + 5,
			want:    maxWorkers,
		},
		{
			// Two full wraps: narrows to 0 again.
			name:    "two full uint32 wraps",
			workers: 2 << 32,
			want:    maxWorkers,
		},
		{
			// The largest int the schema can carry at all.
			name:    "max int",
			workers: int(^uint(0) >> 1),
			want:    maxWorkers,
		},
		// Ordinary values keep their existing behaviour.
		{name: "below the cap", workers: 4, want: 4},
		{name: "at the cap", workers: 64, want: maxWorkers},
		{name: "above the cap", workers: 65, want: maxWorkers},
		{name: "zero coerces to one", workers: 0, want: 1},
		{name: "negative coerces to one", workers: -1, want: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Read through the PLAN — the wiring the ctrl fields actually
			// use — not only the helper it calls.
			got := planUserspaceWorkers(tc.workers, mapCap).Workers
			if got != tc.want {
				t.Fatalf("planUserspaceWorkers(%d, %d).Workers = %d, want %d",
					tc.workers, mapCap, got, tc.want)
			}
			// The two invariants the clamp exists to enforce, asserted
			// independently of the table so neither can be satisfied by a
			// coincidental value.
			if got == 0 {
				t.Fatalf("planUserspaceWorkers(%d, %d).Workers = 0: the shim is told the "+
					"dataplane has no workers and no queues", tc.workers, mapCap)
			}
			if got > maxWorkers {
				t.Fatalf("planUserspaceWorkers(%d, %d).Workers = %d exceeds the %d workers "+
					"the Array can carry heartbeat slots for", tc.workers, mapCap, got, maxWorkers)
			}
		})
	}
}
