package dataplane

import "testing"

// TestCurrentSessions verifies the #2428 saturating floor on the
// "Current sessions" gauge derived from the monotonic create/close counters.
//
// fail-on-revert: replacing CurrentSessions's saturating logic with a raw
// `sessNew - sessClosed` makes the underflow case below wrap to ~1.8e19 and
// the assertion fails.
func TestCurrentSessions(t *testing.T) {
	cases := []struct {
		name       string
		sessNew    uint64
		sessClosed uint64
		want       uint64
	}{
		{"balanced empty", 0, 0, 0},
		{"normal positive", 100, 40, 60},
		{"exact zero", 50, 50, 0},
		// #2428: the standby imbalance — close races/structurally exceeds
		// create. A raw u64 subtraction wraps to a huge value; the floor
		// must clamp it to 0.
		{"underflow clamps to zero", 40, 100, 0},
		{"underflow by one", 0, 1, 0},
		{"max underflow", 0, ^uint64(0), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CurrentSessions(tc.sessNew, tc.sessClosed)
			if got != tc.want {
				t.Fatalf("CurrentSessions(%d, %d) = %d, want %d",
					tc.sessNew, tc.sessClosed, got, tc.want)
			}
		})
	}
}
