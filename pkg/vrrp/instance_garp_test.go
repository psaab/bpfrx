package vrrp

import (
	"testing"
	"time"
)

// #1792: GARP dampening stores wall-clock UnixNano (time.Unix(0, last)
// carries no monotonic reading), so a backward wall-clock step used to
// make the elapsed time negative and suppress failover GARP bursts for
// the step duration — a traffic blackhole right after becoming MASTER.
// garpDampened clamps: negative elapsed is send-allowed.
func TestGARPDampened(t *testing.T) {
	now := time.Now().UnixNano()

	cases := []struct {
		name string
		last int64
		now  int64
		want bool
	}{
		{"never sent", 0, now, false},
		{"negative sentinel", -1, now, false},
		{"recent burst dampened", now - (100 * time.Millisecond).Nanoseconds(), now, true},
		{"just inside interval", now - minGARPInterval.Nanoseconds() + 1, now, true},
		{"exactly interval", now - minGARPInterval.Nanoseconds(), now, false},
		{"old burst allowed", now - time.Second.Nanoseconds(), now, false},
		// Backward wall-clock step: last is "in the future" relative to
		// now. Must be send-allowed — dampening here would suppress
		// failover GARPs for the duration of the step.
		{"backward step send-allowed", now + (3 * time.Second).Nanoseconds(), now, false},
	}
	for _, tc := range cases {
		if got := garpDampened(tc.last, tc.now); got != tc.want {
			t.Errorf("%s: garpDampened(%d, %d) = %v, want %v",
				tc.name, tc.last, tc.now, got, tc.want)
		}
	}
}
