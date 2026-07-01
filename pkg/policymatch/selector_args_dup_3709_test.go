package policymatch

import (
	"strings"
	"testing"
)

// TestParseSelectorArgsRejectsDuplicate is the #3709 RED-on-revert guard for the
// SSOT selector parser shared by all four CLI surfaces + the gRPC test-policy
// bridge. Before it, a DUPLICATE selector (e.g. `source-port 80 source-port
// 443` or `from-zone trust from-zone dmz`) was accepted and silently LAST-won:
// the switch re-assigned the field on the second occurrence, so the simulator
// returned an allow/deny verdict for a DIFFERENT packet than the operator typed.
// The gRPC text topic last-won while REST first-won, so the three surfaces even
// disagreed on WHICH value survived.
//
// FAIL-ON-REVERT: dropping the duplicate guard in takeValue makes every
// want-error case below return nil with the LAST value silently applied,
// flipping the assertions red.
func TestParseSelectorArgsRejectsDuplicate(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string // substring; "" = want no error
	}{
		{"dup from-zone", []string{"from-zone", "trust", "from-zone", "dmz", "to-zone", "untrust"}, "specified more than once"},
		{"dup to-zone", []string{"from-zone", "trust", "to-zone", "untrust", "to-zone", "dmz"}, "specified more than once"},
		{"dup source-port", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "80", "source-port", "443"}, "specified more than once"},
		{"dup destination-port", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port", "80", "destination-port", "443"}, "specified more than once"},
		{"dup protocol", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcp", "protocol", "udp"}, "specified more than once"},
		{"dup source-ip", []string{"from-zone", "trust", "to-zone", "untrust", "source-ip", "10.0.0.1", "source-ip", "10.0.0.2"}, "specified more than once"},
		{"dup destination-ip", []string{"from-zone", "trust", "to-zone", "untrust", "destination-ip", "10.0.0.1", "destination-ip", "10.0.0.2"}, "specified more than once"},
		{"dup icmp-type", []string{"from-zone", "trust", "to-zone", "untrust", "icmp-type", "8", "icmp-type", "0"}, "specified more than once"},
		{"dup icmp-code", []string{"from-zone", "trust", "to-zone", "untrust", "icmp-code", "0", "icmp-code", "1"}, "specified more than once"},
		// A duplicate is an error even when the repeated VALUE is identical —
		// the ambiguity is in the query shape, not the value.
		{"dup identical value", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "443", "source-port", "443"}, "specified more than once"},
		// A single occurrence of each selector is still accepted.
		{"no duplicates", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "80", "destination-port", "443", "protocol", "tcp"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSelectorArgs(tc.args)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ParseSelectorArgs(%v) err = %v, want nil", tc.args, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParseSelectorArgs(%v) err = nil, want %q (silent last-win)", tc.args, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ParseSelectorArgs(%v) err = %v, want substring %q", tc.args, err, tc.wantErr)
			}
		})
	}
}
