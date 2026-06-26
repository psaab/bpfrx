package policymatch

import "testing"

// TestValidateProtocol asserts the #3108 contract for the simulator protocol
// token, the protocol analogue of TestValidatePort/TestParsePort (#3116): an
// empty/whitespace token is "unspecified" (no constraint) and is accepted; a
// known name/alias ("tcp", "udp", "icmp", "ospf") or a numeric value in 0-255
// is accepted; and an unknown name ("notaproto", "tcpp"), an out-of-range
// number ("999"), or other non-resolvable garbage is REJECTED rather than
// silently treated as "any protocol".
//
// FAIL-ON-REVERT: replacing the body with `return nil` (dropping the
// appid.ProtocolNumber gate) flips every want-error case ("notaproto", "tcpp",
// "999", "256", "-1") to nil and turns them red — the exact silent-wildcard
// regression #3108 fixes.
func TestValidateProtocol(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"", false},         // absent -> unspecified, no constraint (unchanged)
		{"   ", false},      // whitespace -> unspecified
		{"tcp", false},      // known name
		{"udp", false},      // known name
		{"icmp", false},     // known name
		{"ospf", false},     // named, non-display protocol
		{"6", false},        // numeric tcp
		{"0", false},        // numeric HOPOPT (valid 0..255)
		{"255", false},      // numeric high bound
		{"notaproto", true}, // unknown name
		{"tcpp", true},      // operator typo
		{"999", true},       // out of range number
		{"256", true},       // one past the 8-bit top
		{"-1", true},        // negative number
		{"any", true},       // no "any" protocol keyword; omit for wildcard
	}
	for _, tc := range cases {
		err := ValidateProtocol(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("ValidateProtocol(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
		}
	}
}
