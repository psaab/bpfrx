package daemon

import (
	"math"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestClampArchiveIntervalMinutes_5784 pins the product-overflow clamp on the
// `system archival transfer-interval` NewTicker path. transfer-interval is a
// config-MINUTES value multiplied by time.Minute before time.NewTicker; a
// value above config.MaxDurationMinutes overflows int64 nanoseconds to a
// non-positive time.Duration, which time.NewTicker PANICS on (crashing xpfd).
// The schema bounds the leaf to 1..2880 at commit, but the lenient
// Store.Load / peer-sync ingress can carry a pathological value, so the clamp
// is defense-in-depth mirroring clampRPMIntervalSeconds (#5723).
//
// FAIL-ON-REVERT: reverting clampArchiveIntervalMinutes to the raw
// `time.Duration(min) * time.Minute` product makes the pathological cases
// return a NON-POSITIVE Duration, so the `> 0` assertions go RED.
func TestClampArchiveIntervalMinutes_5784(t *testing.T) {
	ceiling := time.Duration(config.MaxDurationMinutes) * time.Minute

	// Valid schema-range intervals pass through unchanged.
	valid := map[int]time.Duration{
		1:    1 * time.Minute,
		60:   60 * time.Minute,
		2880: 2880 * time.Minute, // the schema max
	}
	for in, want := range valid {
		if got := clampArchiveIntervalMinutes(in); got != want {
			t.Errorf("clampArchiveIntervalMinutes(%d) = %v, want %v (valid interval must pass through unchanged)", in, got, want)
		}
	}

	// Non-positive / sub-minimum inputs default to a sane positive minimum.
	for _, in := range []int{0, -1, -5} {
		if got := clampArchiveIntervalMinutes(in); got != time.Minute {
			t.Errorf("clampArchiveIntervalMinutes(%d) = %v, want %v (sub-minimum default)", in, got, time.Minute)
		}
	}

	// Pathological lenient-ingress values: the raw `× time.Minute` product
	// overflows int64-ns to a non-positive Duration. The clamp must instead
	// return a POSITIVE Duration bounded by the ceiling.
	pathological := []int{
		int(config.MaxDurationMinutes) + 1, // just over the overflow threshold
		200_000_000,                        // ~1.5e8+, the issue's crafted magnitude
		math.MaxInt64,                      // the extreme
	}
	for _, in := range pathological {
		// Demonstrate the pre-fix hazard explicitly: the raw product is
		// non-positive for these inputs (this is exactly what reached NewTicker).
		if raw := time.Duration(in) * time.Minute; raw > 0 {
			t.Fatalf("test precondition: expected raw product for %d to overflow non-positive, got %v", in, raw)
		}
		got := clampArchiveIntervalMinutes(in)
		if got <= 0 {
			t.Errorf("clampArchiveIntervalMinutes(%d) = %v; MUST be positive (NewTicker panics on a non-positive interval)", in, got)
		}
		if got > ceiling {
			t.Errorf("clampArchiveIntervalMinutes(%d) = %v; must be bounded by the ceiling %v", in, got, ceiling)
		}
	}

	// The ceiling itself maps to a positive Duration (not the overflow edge).
	if got := clampArchiveIntervalMinutes(int(config.MaxDurationMinutes)); got != ceiling || got <= 0 {
		t.Errorf("clampArchiveIntervalMinutes(MaxDurationMinutes) = %v, want %v (>0)", got, ceiling)
	}

	// End-to-end: a clamped pathological interval constructs a real
	// time.Ticker without panicking (the crash this fix prevents).
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("time.NewTicker panicked on the clamped pathological interval: %v", r)
			}
		}()
		tk := time.NewTicker(clampArchiveIntervalMinutes(math.MaxInt64))
		tk.Stop()
	}()
}
