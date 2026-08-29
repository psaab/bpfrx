package cli

import (
	"reflect"
	"strings"
	"testing"
)

// TestParseMonitorTrafficMultiTokenFilter is the #4005 regression guard:
// `monitor traffic ... matching "tcp port 80"` must apply the FULL
// multi-token BPF filter, not just the first token. The CLI tokenizer
// (strings.Fields) splits on whitespace and drops shell quotes, so the
// quoted filter arrives as the separate tokens `"tcp`, `port`, `80"`.
// Before the fix the parser read only the first token → the capture
// filtered on `"tcp` (a literal-quote token) and silently dropped
// `port 80`, capturing far more traffic than the operator asked for.
func TestParseMonitorTrafficMultiTokenFilter(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantIface  string
		wantFilter string
		wantCount  string
	}{
		{
			// The headline #4005 case: whitespace-split quoted filter.
			name:       "quoted multi-token filter",
			args:       []string{"interface", "ge-0-0-0", "matching", `"tcp`, "port", `80"`},
			wantIface:  "ge-0-0-0",
			wantFilter: "tcp port 80",
			wantCount:  "0",
		},
		{
			// Bare (unquoted) multi-token filter must also survive whole.
			name:       "bare multi-token filter",
			args:       []string{"interface", "ge-0-0-0", "matching", "tcp", "port", "80"},
			wantIface:  "ge-0-0-0",
			wantFilter: "tcp port 80",
			wantCount:  "0",
		},
		{
			// Single-token filter is unchanged.
			name:       "single-token filter",
			args:       []string{"interface", "ge-0-0-0", "matching", "icmp"},
			wantIface:  "ge-0-0-0",
			wantFilter: "icmp",
			wantCount:  "0",
		},
		{
			// and/or/not boolean operators are preserved verbatim.
			name:       "boolean operators preserved",
			args:       []string{"interface", "ge-0-0-1", "matching", `"host`, "10.0.0.1", "and", "port", `443"`},
			wantIface:  "ge-0-0-1",
			wantFilter: "host 10.0.0.1 and port 443",
			wantCount:  "0",
		},
		{
			name:       "not operator preserved",
			args:       []string{"interface", "ge-0-0-2", "matching", "udp", "and", "not", "port", "53"},
			wantIface:  "ge-0-0-2",
			wantFilter: "udp and not port 53",
			wantCount:  "0",
		},
		{
			// A count following a multi-token filter must NOT be swallowed
			// into the filter — the keyword terminates the greedy match.
			name:       "count after matching not swallowed",
			args:       []string{"interface", "ge-0-0-0", "matching", "tcp", "port", "80", "count", "20"},
			wantIface:  "ge-0-0-0",
			wantFilter: "tcp port 80",
			wantCount:  "20",
		},
		{
			// count before matching still works; filter runs to end.
			name:       "count before matching",
			args:       []string{"interface", "ge-0-0-0", "count", "10", "matching", "tcp", "port", "80"},
			wantIface:  "ge-0-0-0",
			wantFilter: "tcp port 80",
			wantCount:  "10",
		},
		{
			// Single-quoted filter is de-quoted the same as double.
			name:       "single-quoted filter",
			args:       []string{"interface", "ge-0-0-0", "matching", `'udp`, "or", `tcp'`},
			wantIface:  "ge-0-0-0",
			wantFilter: "udp or tcp",
			wantCount:  "0",
		},
		{
			// No matching clause at all: empty filter (capture everything).
			name:       "no filter",
			args:       []string{"interface", "ge-0-0-0", "count", "5"},
			wantIface:  "ge-0-0-0",
			wantFilter: "",
			wantCount:  "5",
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
				t.Errorf("filter = %q, want %q (multi-token truncation regression?)", filter, tt.wantFilter)
			}
			if count != tt.wantCount {
				t.Errorf("count = %q, want %q", count, tt.wantCount)
			}
		})
	}
}

// TestBuildMonitorTrafficArgvFilterReachesTcpdump asserts the full
// multi-token filter reaches the tcpdump invocation as trailing argv
// tokens (the pcap filter expression), matching how tcpdump/libpcap
// consumes a filter. Goes RED on revert — the truncated filter would
// place only `tcp` (or `"tcp`) after the interface flags.
func TestBuildMonitorTrafficArgvFilterReachesTcpdump(t *testing.T) {
	iface, filter, count, err := parseMonitorTrafficArgs(
		[]string{"interface", "ge-0-0-0", "matching", `"tcp`, "port", `80"`, "count", "20"},
	)
	if err != nil {
		t.Fatalf("parseMonitorTrafficArgs unexpected error: %v", err)
	}
	argv := buildMonitorTrafficArgv(iface, filter, count)
	// The filter follows an explicit "--" end-of-options separator (#4524).
	want := []string{"tcpdump", "-i", "ge-0-0-0", "-n", "-l", "-c", "20", "--", "tcp", "port", "80"}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("buildMonitorTrafficArgv =\n  %v\nwant\n  %v", argv, want)
	}

	// The full filter expression must be present as a contiguous trailing
	// run after the "--" separator — assert the joined tail equals the
	// intended BPF filter.
	sep := indexOf(argv, "--")
	if sep < 0 {
		t.Fatalf("argv %v: missing \"--\" end-of-options separator", argv)
	}
	if got := strings.Join(argv[sep+1:], " "); got != "tcp port 80" {
		t.Fatalf("filter tail = %q, want %q", got, "tcp port 80")
	}
}

// TestStripSurroundingQuotes MOVED to quote_strip_7171_test.go when the helper
// moved out of this file to be shared with the commit/annotate comment paths.
// Every case it asserted for #4005 is preserved there verbatim; the move keeps
// the test next to the code rather than leaving it guarding a helper that no
// longer lives here.
