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
//
// #6702 blocker 2 RETARGETED this test rather than retiring it. The hazard is
// unchanged and so are its fixtures; what changed is HOW it is closed. The
// bound used to be a worker-derived value clamped into
// [1, mapCap/heartbeatSlotsPerWorker]; it is now the Array's own capacity and
// does not read the worker count at all, because heartbeat slots are indexed
// by BINDING slot and the binding count was never a function of cfg.Workers.
// So this now asserts the STRONGER property the new shape gives for free:
// every one of these worker counts — including the ones that used to wrap —
// yields exactly the same in-range bound. A future edit that reintroduces a
// worker term reds here on the first absurd value.
func TestHeartbeatZeroSlots_4572(t *testing.T) {
	const mapCap = 4096 // userspace_heartbeat Array max_entries (lib.rs)
	const perWorker = uint32(heartbeatSlotsPerWorker)

	// Every case wants the SAME bound: the bound is no longer a function of
	// the worker count. The fixtures are kept verbatim from the pre-#6702
	// table — the values that used to wrap uint32 or clamp are exactly the
	// ones worth keeping, because they are what a reintroduced worker term
	// would move.
	cases := []struct {
		name    string
		workers int
		want    uint32
	}{
		// The #4572 bug values: negative / zero must not wrap to billions.
		{"negative_one", -1, mapCap},
		{"zero", 0, mapCap},
		{"large_negative", -5_000_000_000, mapCap},
		// Ordinary counts.
		{"one", 1, mapCap},
		{"six", 6, mapCap},
		{"cap_exact", mapCap / int(perWorker), mapCap}, // 128 workers
		// Absurd positives must not overrun the Array or wrap uint32.
		{"over_cap", 200, mapCap},
		{"huge_positive", 999_999_999, mapCap},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The bound is read through the PLAN, which is what the
			// zero-init loop actually indexes with — binding the wiring, not
			// just the helper it calls.
			got := planUserspaceWorkers(tc.workers, mapCap).HeartbeatSlots
			if got != tc.want {
				t.Fatalf("planUserspaceWorkers(%d, %d).HeartbeatSlots = %d, want %d",
					tc.workers, mapCap, got, tc.want)
			}
			// The whole point of the fix: the loop bound is always small
			// enough to run instantly and always within the Array.
			if got > mapCap {
				t.Fatalf("planUserspaceWorkers(%d, %d).HeartbeatSlots = %d exceeds map "+
					"capacity %d — would index past the Array", tc.workers,
					mapCap, got, mapCap)
			}
			if got == 0 {
				t.Fatalf("planUserspaceWorkers(%d, %d).HeartbeatSlots = 0: nothing is "+
					"zero-initialised, so every slot starts on the previous load's data",
					tc.workers, mapCap)
			}
		})
	}
}
