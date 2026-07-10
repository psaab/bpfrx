package cli

import (
	"strconv"
	"testing"
)

// TestParseShowLogCountCap pins the operand bound for `show log [<name>] N`
// (#5069). Both `show log` paths feed this count straight into `tail -n N` /
// `journalctl -n N` and buffer the whole result via CombinedOutput, so an
// unbounded N would let a view-only (PermView) account force an
// O(retained-log-size) heap allocation and a management stall. parseShowLogCount
// must default to 50, ignore non-positive/unparseable operands, and clamp any N
// above maxTailLines to the cap. Reverting the clamp makes the over-cap cases
// return the raw operand (the pre-fix behavior) and this test fails.
func TestParseShowLogCountCap(t *testing.T) {
	// idx 0 is the journald path (`show log N`); idx 1 is the file path
	// (`show log <name> N`). Both must be bounded identically.
	cases := []struct {
		name string
		args []string
		idx  int
		want int
	}{
		{"journald default (no operand)", []string{}, 0, 50},
		{"journald in-range", []string{"100"}, 0, 100},
		{"journald zero -> default", []string{"0"}, 0, 50},
		{"journald negative -> default", []string{"-7"}, 0, 50},
		{"journald unparseable -> default", []string{"abc"}, 0, 50},
		{"journald exactly cap", []string{strconv.Itoa(maxTailLines)}, 0, maxTailLines},
		{"journald just over cap -> clamp", []string{strconv.Itoa(maxTailLines + 1)}, 0, maxTailLines},
		{"journald huge DoS operand -> clamp", []string{"1000000000"}, 0, maxTailLines},
		{"journald strconv overflow -> default", []string{"99999999999999999999"}, 0, 50},

		{"file default (name only)", []string{"messages"}, 1, 50},
		{"file in-range", []string{"messages", "200"}, 1, 200},
		{"file zero -> default", []string{"messages", "0"}, 1, 50},
		{"file exactly cap", []string{"messages", strconv.Itoa(maxTailLines)}, 1, maxTailLines},
		{"file huge DoS operand -> clamp", []string{"messages", "2000000000"}, 1, maxTailLines},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseShowLogCount(c.args, c.idx)
			if got != c.want {
				t.Errorf("parseShowLogCount(%q, %d) = %d, want %d", c.args, c.idx, got, c.want)
			}
			// The bound is the whole point: the count handed to
			// tail/journalctl must never exceed the operator cap.
			if got > maxTailLines {
				t.Errorf("parseShowLogCount(%q, %d) = %d exceeds cap %d", c.args, c.idx, got, maxTailLines)
			}
		})
	}
}
