package rpm

import (
	"math"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestClampRPMIntervalSecondsBoundsOverflow_5723 is the #5723 runtime-clamp
// fail-on-revert guard (defense-in-depth for the lenient HA-sync / on-disk Load
// ingress that downgrades an out-of-range interval to a warning, bypassing the
// schema admission bound). A config-derived RPM interval whose
// time.Duration(sec)*time.Second product overflows int64 nanoseconds must clamp
// to a POSITIVE, time.NewTicker-safe Duration instead of wrapping to a
// non-positive value that panics runProbeLoop.
//
// FAIL-ON-REVERT: revert clampRPMIntervalSeconds to a bare
// `time.Duration(sec)*time.Second` and the overflow cases below return a
// non-positive Duration — the >0 assertion fires RED and the NewTicker probe
// panics.
func TestClampRPMIntervalSecondsBoundsOverflow_5723(t *testing.T) {
	overflowing := []int{
		math.MaxInt64,                      // sec * 1e9 overflows hugely
		math.MaxInt64 / 2,                  // still overflows the *time.Second multiply
		1 << 40,                            // ~1.1e12 s * 1e9 ns overflows int64
		9999999999,                         // ~1e10 s → overflow
		int(config.MaxDurationSeconds) + 1, // one past the safe ceiling
	}
	for _, sec := range overflowing {
		// Sanity: the UNCLAMPED multiply really does overflow to non-positive —
		// this is the bug the clamp prevents.
		if raw := time.Duration(sec) * time.Second; raw > 0 {
			t.Fatalf("test premise broken: time.Duration(%d)*time.Second = %v is still positive", sec, raw)
		}
		got := clampRPMIntervalSeconds(sec)
		if got <= 0 {
			t.Fatalf("clampRPMIntervalSeconds(%d) = %v, want a positive Duration (overflow not bounded — #5723)", sec, got)
		}
		if got != time.Duration(config.MaxDurationSeconds)*time.Second {
			t.Errorf("clampRPMIntervalSeconds(%d) = %v, want clamp to MaxDurationSeconds (%v)",
				sec, got, time.Duration(config.MaxDurationSeconds)*time.Second)
		}
		// The whole point: constructing the probe ticker must not panic.
		mustNotPanicNewTicker(t, got)
	}

	// Normal / boundary values pass through unchanged and stay ticker-safe.
	for _, tc := range []struct {
		sec  int
		want time.Duration
	}{
		{0, time.Second},  // floored (defensive; EffectiveInterval never returns <1)
		{-5, time.Second}, // floored
		{1, time.Second},  // min
		{30, 30 * time.Second},
		{3600, 3600 * time.Second},
		{int(config.MaxDurationSeconds), time.Duration(config.MaxDurationSeconds) * time.Second}, // exact ceiling, no overflow
	} {
		got := clampRPMIntervalSeconds(tc.sec)
		if got != tc.want {
			t.Errorf("clampRPMIntervalSeconds(%d) = %v, want %v", tc.sec, got, tc.want)
		}
		if got <= 0 {
			t.Errorf("clampRPMIntervalSeconds(%d) = %v, want positive", tc.sec, got)
		}
		mustNotPanicNewTicker(t, got)
	}
}

func mustNotPanicNewTicker(t *testing.T, d time.Duration) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("time.NewTicker(%v) panicked (non-positive Duration): %v", d, r)
		}
	}()
	tk := time.NewTicker(d)
	tk.Stop()
}
