package cli

import "testing"

// TestParseMonitorTrafficRejectsKeywordAsInterface is the #4540 regression
// guard for the interface value. `monitor traffic interface matching tcp
// port 80` omits the interface value, so the greedy `interface` case used
// to consume the following grammar keyword `matching` as the interface
// name (iface="matching", filter="") → tcpdump "no such device" or an
// unfiltered capture. The parser must now reject a value that is itself a
// known keyword (or missing entirely) rather than swallow it.
//
// Goes RED on revert: without the guard iface would be "matching" and err
// would be nil.
func TestParseMonitorTrafficRejectsKeywordAsInterface(t *testing.T) {
	cases := [][]string{
		{"interface", "matching", "tcp", "port", "80"}, // keyword swallowed as iface
		{"interface", "count", "20"},                   // count keyword swallowed as iface
		{"interface"},                                  // bare interface, no value at all
	}
	for _, args := range cases {
		iface, _, _, err := parseMonitorTrafficArgs(args)
		if err == nil {
			t.Errorf("parseMonitorTrafficArgs(%v) = iface %q, nil err; want an error (keyword/missing value must not be consumed as the interface name)", args, iface)
		}
		if iface != "" {
			t.Errorf("parseMonitorTrafficArgs(%v) set iface=%q; want empty on rejection", args, iface)
		}
	}
}

// TestParseMonitorTrafficRejectsValuelessCount is the #4540 regression
// guard for the count value. A trailing bare `count` (or a `count`
// immediately followed by another grammar keyword) previously left count
// at its "0" = unlimited default, silently ignoring the operator's intent
// to bound the capture. A non-numeric value used to reach tcpdump's `-c`
// and fail opaquely. The parser must now reject all three.
//
// Goes RED on revert: `count` with no value would return count="0", nil
// err — an unbounded capture the operator did not ask for.
func TestParseMonitorTrafficRejectsValuelessCount(t *testing.T) {
	cases := [][]string{
		{"interface", "ge-0-0-0", "count"},             // bare count, no value
		{"interface", "ge-0-0-0", "count", "matching"}, // keyword swallowed as count
		{"interface", "ge-0-0-0", "count", "abc"},      // non-numeric count
	}
	for _, args := range cases {
		_, _, count, err := parseMonitorTrafficArgs(args)
		if err == nil {
			t.Errorf("parseMonitorTrafficArgs(%v) = count %q, nil err; want an error (value-less/non-numeric count must not silently default to unlimited)", args, count)
		}
	}
}

// TestParseMonitorTrafficNormalCasesStillParse pins the common happy path:
// a real interface name and a real count still parse exactly as before, so
// the #4540 guards do not regress legitimate invocations.
func TestParseMonitorTrafficNormalCasesStillParse(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantIface  string
		wantFilter string
		wantCount  string
	}{
		{
			name:       "interface then matching filter",
			args:       []string{"interface", "ge-0-0-0", "matching", "tcp"},
			wantIface:  "ge-0-0-0",
			wantFilter: "tcp",
			wantCount:  "0",
		},
		{
			name:       "interface with numeric count",
			args:       []string{"interface", "ge-0-0-0", "count", "20"},
			wantIface:  "ge-0-0-0",
			wantFilter: "",
			wantCount:  "20",
		},
		{
			name:       "interface, filter, and count",
			args:       []string{"interface", "ge-0-0-0", "matching", "tcp", "port", "80", "count", "20"},
			wantIface:  "ge-0-0-0",
			wantFilter: "tcp port 80",
			wantCount:  "20",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface, filter, count, err := parseMonitorTrafficArgs(tt.args)
			if err != nil {
				t.Fatalf("parseMonitorTrafficArgs(%v) unexpected error: %v", tt.args, err)
			}
			if iface != tt.wantIface {
				t.Errorf("iface = %q, want %q", iface, tt.wantIface)
			}
			if filter != tt.wantFilter {
				t.Errorf("filter = %q, want %q", filter, tt.wantFilter)
			}
			if count != tt.wantCount {
				t.Errorf("count = %q, want %q", count, tt.wantCount)
			}
		})
	}
}
