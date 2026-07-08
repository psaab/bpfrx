package userspace

import "testing"

// TestHeartbeatZeroSlots_4572 pins the heartbeat zero-init loop bound.
//
// Regression for #4572: programBootstrapMapsLocked previously looped
// `slot < uint32(cfg.Workers)*2*16`. The negative case (workers -1 ->
// uint32(-1)*32 = 4,294,967,264 iterations) is guarded upstream by
// deriveUserspaceConfig (workers<=0 -> 1). The LIVE hang is a large
// positive value: `workers` is a min-only schema leaf (ValidateIntegerMin(1))
// with no upper cap in deriveUserspaceConfig, so `workers 999999999`
// reaches the loop and uint32(999999999)*32 wraps uint32 to ~1.9B
// iterations of heartbeatMap.Update — an apply hang for hours.
// heartbeatZeroSlots clamps the worker count into
// [1, mapCap/heartbeatSlotsPerWorker], bounding both directions.
func TestHeartbeatZeroSlots_4572(t *testing.T) {
	const mapCap = 4096 // userspace_heartbeat Array max_entries (lib.rs)
	const perWorker = uint32(heartbeatSlotsPerWorker)

	cases := []struct {
		name    string
		workers int
		want    uint32
	}{
		// The bug values: negative / zero must clamp to a single worker's
		// worth of slots, NOT wrap to billions.
		{"negative_one", -1, perWorker},
		{"zero", 0, perWorker},
		{"large_negative", -5_000_000_000, perWorker},
		// Normal values are unchanged (6 workers -> 6*32 = 192).
		{"one", 1, perWorker},
		{"six_unchanged", 6, 6 * perWorker},
		{"cap_exact", mapCap / int(perWorker), mapCap}, // 128 workers -> 4096
		// Absurd positives clamp to the map capacity instead of
		// overrunning the Array or wrapping uint32.
		{"over_cap", 200, mapCap},
		{"huge_positive", 999_999_999, mapCap},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := heartbeatZeroSlots(tc.workers, mapCap)
			if got != tc.want {
				t.Fatalf("heartbeatZeroSlots(%d, %d) = %d, want %d",
					tc.workers, mapCap, got, tc.want)
			}
			// The whole point of the fix: the loop bound is always small
			// enough to run instantly and always within the Array.
			if got > mapCap {
				t.Fatalf("heartbeatZeroSlots(%d, %d) = %d exceeds map "+
					"capacity %d — would index past the Array", tc.workers,
					mapCap, got, mapCap)
			}
		})
	}
}
