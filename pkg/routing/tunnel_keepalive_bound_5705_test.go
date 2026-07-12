package routing

import (
	"testing"
	"time"
)

// TestClampKeepaliveIntervalSec_5705 proves the runtime clamp keeps the
// keepalive interval inside a positive, non-overflowing range so the
// Duration multiply used by keepaliveLoop / keepaliveProbeDeadline can
// never wrap non-positive.
//
// FAIL-ON-REVERT: removing the upper clamp lets a huge interval overflow
// time.Duration(sec)*time.Second into a negative value, so the
// "positive ticker duration" assertion below fires RED (and the live
// path panics time.NewTicker).
func TestClampKeepaliveIntervalSec_5705(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{-5, 1},  // negative → floor 1 (defensive; loop never starts at <=0)
		{0, 1},   // zero → floor 1
		{1, 1},   // in range, unchanged
		{30, 30}, // in range, unchanged
		{maxKeepaliveIntervalSec, maxKeepaliveIntervalSec},
		{maxKeepaliveIntervalSec + 1, maxKeepaliveIntervalSec},
		{10000000000, maxKeepaliveIntervalSec}, // 1e10 s would overflow the ns multiply
		{1 << 62, maxKeepaliveIntervalSec},     // extreme value
	}
	for _, c := range cases {
		if got := clampKeepaliveIntervalSec(c.in); got != c.want {
			t.Fatalf("clampKeepaliveIntervalSec(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestKeepaliveTickerDurationPositive_5705 reproduces the exact multiply
// keepaliveLoop performs to arm its ticker and asserts the result is a
// strictly positive Duration for a value that WOULD overflow int64 ns
// without the clamp. Without the clamp, time.Duration(1e10)*time.Second
// wraps negative and time.NewTicker(d) panics ("non-positive interval").
func TestKeepaliveTickerDurationPositive_5705(t *testing.T) {
	// Runtime (not const) so the intentional overflow is a wrap, not a
	// compile-time "constant overflows int64" error.
	overflowingIntervalSec := 10000000000 // 1e10

	// Demonstrate the bare (pre-fix) multiply actually wraps non-positive.
	raw := time.Duration(overflowingIntervalSec) * time.Second
	if raw > 0 {
		t.Fatalf("test premise invalid: raw multiply %d did not overflow non-positive", raw)
	}

	// The clamped multiply keepaliveLoop now uses must be strictly
	// positive so time.NewTicker does not panic.
	d := time.Duration(clampKeepaliveIntervalSec(overflowingIntervalSec)) * time.Second
	if d <= 0 {
		t.Fatalf("clamped ticker duration = %d, want > 0", d)
	}

	// time.NewTicker panics on a non-positive interval; prove the clamped
	// duration does not.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("time.NewTicker panicked on clamped duration: %v", r)
			}
		}()
		tk := time.NewTicker(d)
		tk.Stop()
	}()
}

// TestKeepaliveProbeDeadlineClamped_5705 confirms keepaliveProbeDeadline
// returns a sane bounded budget (never a bogus sub-deadline produced by
// an overflowed interval) for both normal and overflowing intervals.
func TestKeepaliveProbeDeadlineClamped_5705(t *testing.T) {
	const maxDeadline = 800 * time.Millisecond

	// Overflowing interval: budget must stay within the [1, maxDeadline]
	// envelope, not a wrapped nonsense value.
	got := keepaliveProbeDeadline(10000000000)
	if got <= 0 || got > maxDeadline {
		t.Fatalf("keepaliveProbeDeadline(overflow) = %v, want in (0, %v]", got, maxDeadline)
	}

	// A small interval still yields interval/2 (500ms for 1s).
	if got := keepaliveProbeDeadline(1); got != 500*time.Millisecond {
		t.Fatalf("keepaliveProbeDeadline(1) = %v, want 500ms", got)
	}
}
