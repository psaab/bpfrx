package userspace

import "testing"

// TestHeartbeatZeroSlotsClampsBeforeNarrowing_5718 is the #5718 A6-b01-C1
// fail-on-revert.
//
// heartbeatZeroSlots exists to bound the zero-init loop into
// [1*perWorker, mapCap]. Both clamps must therefore bind for EVERY int the
// caller can supply. Casting to uint32 first (`uint32(maxInt(workers, 1))`,
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
	const maxSlots = mapCap

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
			want:    maxSlots,
		},
		{
			// Narrows to 5 under a cast-first implementation, which is a
			// legal-looking worker count well under maxW.
			name:    "uint32 range plus five narrows into the legal window",
			workers: 1<<32 + 5,
			want:    maxSlots,
		},
		{
			// Two full wraps: narrows to 0 again.
			name:    "two full uint32 wraps",
			workers: 2 << 32,
			want:    maxSlots,
		},
		{
			// The largest int the schema can carry at all.
			name:    "max int",
			workers: int(^uint(0) >> 1),
			want:    maxSlots,
		},
		// Ordinary values keep their existing behaviour.
		{name: "below the cap", workers: 4, want: 4 * perWorker},
		{name: "at the cap", workers: 64, want: maxSlots},
		{name: "above the cap", workers: 65, want: maxSlots},
		{name: "zero coerces to one", workers: 0, want: perWorker},
		{name: "negative coerces to one", workers: -1, want: perWorker},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := heartbeatZeroSlots(tc.workers, mapCap)
			if got != tc.want {
				t.Fatalf("heartbeatZeroSlots(%d, %d) = %d, want %d", tc.workers, mapCap, got, tc.want)
			}
			// The two invariants the function exists to enforce, asserted
			// independently of the table so neither can be satisfied by a
			// coincidental value.
			if got == 0 {
				t.Fatalf("heartbeatZeroSlots(%d, %d) returned 0: no heartbeat slot is "+
					"zero-initialised, so every worker starts on stale data", tc.workers, mapCap)
			}
			if got > mapCap {
				t.Fatalf("heartbeatZeroSlots(%d, %d) = %d exceeds the Array capacity %d",
					tc.workers, mapCap, got, mapCap)
			}
		})
	}
}
