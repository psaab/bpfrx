package daemon

import (
	"testing"
	"time"
)

// #1792: the heartbeat-timeout suppression cap must be measured in the
// CLOCK_MONOTONIC domain. The helper takes injected timestamps, so these
// tests pin the boundary semantics that wall-clock steps used to break
// (backward step → suppression stuck on, blocking failover; forward step
// → suppression cut short).
func TestHBSuppressCapExceeded(t *testing.T) {
	const capDur = 5 * time.Second
	base := int64(2_000_000_000_000) // arbitrary monotonic reading

	cases := []struct {
		name  string
		start int64
		now   int64
		want  bool
	}{
		{"just started", base, base, false},
		{"within cap", base, base + (4 * time.Second).Nanoseconds(), false},
		{"exactly cap", base, base + capDur.Nanoseconds(), false},
		{"just past cap", base, base + capDur.Nanoseconds() + 1, true},
		// now < start cannot happen on a correct monotonic clock; the
		// equivalent wall-clock state (backward step after suppression
		// began) used to keep suppression alive for the step duration.
		// In the monotonic domain the helper simply reports not-exceeded
		// and the suppression window proceeds normally.
		{"negative elapsed tolerated", base, base - time.Second.Nanoseconds(), false},
	}
	for _, tc := range cases {
		if got := hbSuppressCapExceeded(tc.start, tc.now, capDur); got != tc.want {
			t.Errorf("%s: hbSuppressCapExceeded(%d, %d, %v) = %v, want %v",
				tc.name, tc.start, tc.now, capDur, got, tc.want)
		}
	}
}

// shouldSuppressPeerHeartbeatTimeout must reset its suppression-start
// state when session sync is unavailable, so a later suppression window
// re-arms from scratch instead of inheriting a stale cap start.
func TestShouldSuppressPeerHeartbeatTimeoutResetsWhenSyncUnavailable(t *testing.T) {
	d := &Daemon{}
	d.hbSuppressStart.Store(123)

	suppress, reason := d.shouldSuppressPeerHeartbeatTimeout()
	if suppress {
		t.Fatalf("suppress = true with nil session sync (reason %q)", reason)
	}
	if got := d.hbSuppressStart.Load(); got != 0 {
		t.Fatalf("hbSuppressStart = %d after sync-unavailable check, want reset to 0", got)
	}
}
