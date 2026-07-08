package cli

import "testing"

// #4589 A10-01: `monitor traffic count` only rejected a non-numeric value;
// a negative (`count -1`) reached tcpdump's `-c` as an opaque "invalid
// packet count" error, and an unbounded huge value was silently accepted
// even though it is redundant with the already-supported 0=unlimited mode.
// The sibling `monitor security packet-drop` bounds its count to 1..8192
// (monitor.go); this pins the same bound on `monitor traffic count`,
// keeping 0 as the explicit unlimited mode.
//
// RED-on-revert: without the `n < 0 || n > 8192` guard the negative and
// over-cap cases return a numeric count with nil err.
func TestParseMonitorTrafficCountBounded(t *testing.T) {
	cases := [][]string{
		{"interface", "ge-0-0-0", "count", "-1"},    // negative
		{"interface", "ge-0-0-0", "count", "99999"}, // over the 8192 cap
	}
	for _, args := range cases {
		_, _, count, err := parseMonitorTrafficArgs(args)
		if err == nil {
			t.Errorf("parseMonitorTrafficArgs(%v) = count %q, nil err; want an error (out-of-range count must be rejected)", args, count)
		}
	}
}

// 0 (unlimited) and an in-range positive count still parse, so the bound
// does not regress legitimate captures.
func TestParseMonitorTrafficCountInRangeAccepted(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"interface", "ge-0-0-0", "count", "0"}, "0"},       // explicit unlimited
		{[]string{"interface", "ge-0-0-0", "count", "100"}, "100"},   // in range
		{[]string{"interface", "ge-0-0-0", "count", "8192"}, "8192"}, // boundary
	}
	for _, tc := range tests {
		_, _, count, err := parseMonitorTrafficArgs(tc.args)
		if err != nil {
			t.Errorf("parseMonitorTrafficArgs(%v) unexpected err: %v", tc.args, err)
			continue
		}
		if count != tc.want {
			t.Errorf("parseMonitorTrafficArgs(%v) count=%q, want %q", tc.args, count, tc.want)
		}
	}
}
