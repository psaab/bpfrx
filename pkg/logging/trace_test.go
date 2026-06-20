package logging

import (
	"net/netip"
	"testing"
)

// TestMatchFiltersProtocol verifies the M8 (#2008) traceoptions packet-filter
// `protocol` match: a filter with protocol set matches only records of that
// protocol, accepts both Junos protocol names and numbers, and an unset
// protocol matches any protocol.
func TestMatchFiltersProtocol(t *testing.T) {
	tests := []struct {
		name        string
		filterProto string // config value (name or number); "" = no protocol filter
		recProto    string // EventRecord.Protocol (as rendered by protoName)
		want        bool
	}{
		{"name-tcp-matches-tcp", "tcp", "TCP", true},
		{"name-tcp-rejects-udp", "tcp", "UDP", false},
		{"name-udp-matches-udp", "udp", "UDP", true},
		{"name-icmp-matches-icmp", "icmp", "ICMP", true},
		{"name-icmp6-matches-icmpv6", "icmp6", "ICMPv6", true},
		{"number-6-matches-tcp", "6", "TCP", true},
		{"number-17-matches-udp", "17", "UDP", true},
		{"number-1-matches-icmp", "1", "ICMP", true},
		{"number-58-matches-icmpv6", "58", "ICMPv6", true},
		{"number-6-rejects-udp", "6", "UDP", false},
		{"unconfigured-matches-tcp", "", "TCP", true},
		{"unconfigured-matches-udp", "", "UDP", true},
		{"uppercase-config-matches", "TCP", "TCP", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := traceFilter{name: "f"}
			if tt.filterProto != "" {
				f.proto = normalizeTraceProto(tt.filterProto)
			}
			tw := &TraceWriter{filters: []traceFilter{f}}
			rec := EventRecord{
				SrcAddr:  "10.0.1.5:1000",
				DstAddr:  "10.0.2.5:80",
				Protocol: tt.recProto,
			}
			if got := tw.matchFilters(rec); got != tt.want {
				t.Errorf("matchFilters(proto-filter=%q, rec=%q) = %v, want %v",
					tt.filterProto, tt.recProto, got, tt.want)
			}
		})
	}
}

// TestMatchFiltersProtocolWithPrefix verifies protocol is ANDed with the
// existing source/destination prefix match: a record matches only when it
// satisfies prefix AND protocol.
func TestMatchFiltersProtocolWithPrefix(t *testing.T) {
	tw := &TraceWriter{
		filters: []traceFilter{{
			name:   "f",
			srcNet: netip.MustParsePrefix("10.0.1.0/24"),
			proto:  normalizeTraceProto("tcp"),
		}},
	}

	cases := []struct {
		src   string
		proto string
		want  bool
	}{
		{"10.0.1.5:1000", "TCP", true},  // prefix + proto both match
		{"10.0.1.5:1000", "UDP", false}, // prefix matches, proto does not
		{"10.0.9.5:1000", "TCP", false}, // proto matches, prefix does not
	}
	for _, c := range cases {
		rec := EventRecord{SrcAddr: c.src, DstAddr: "10.0.2.5:80", Protocol: c.proto}
		if got := tw.matchFilters(rec); got != c.want {
			t.Errorf("matchFilters(src=%s proto=%s) = %v, want %v", c.src, c.proto, got, c.want)
		}
	}
}
