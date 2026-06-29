package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCustomJunosPingApp_EchoOnly is the #3348 end-to-end fail-on-revert: a
// USER-DEFINED application `mgmt-ping` whose protocol is the junos-ping alias,
// referenced by an allow policy, must permit ICMP echo-request (type 8) ONLY,
// not every ICMP type. Before the compiler attached the echo constraint to the
// alias, the custom app lowered to bare ICMP (ICMPType nil) and the matcher
// treated it as match-ALL ICMP, so timestamp/redirect/etc. were silently
// permitted — the security widening this issue fixes. Reverting the
// compiler_applications.go alias default makes the "denies timestamp" case go
// RED (the matcher permits it).
func TestCustomJunosPingApp_EchoOnly(t *testing.T) {
	cfg := compileFromSet(t, []string{
		"set applications application mgmt-ping protocol junos-ping",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy allow match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow match application mgmt-ping",
		"set security policies from-zone trust to-zone untrust policy allow then permit",
		"set security policies default-policy deny-all",
	})

	tests := []struct {
		name        string
		icmpType    uint8
		wantMatched bool
		wantAction  config.PolicyAction
	}{
		{"echo-request type 8 permitted", 8, true, config.PolicyPermit},
		{"timestamp type 13 denied", 13, false, config.PolicyDeny},
		{"redirect type 5 denied", 5, false, config.PolicyDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ty := tt.icmpType
			q := Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmp", ICMPType: &ty}
			res := Match(cfg, q)
			if res.Matched != tt.wantMatched || res.Action != tt.wantAction {
				t.Fatalf("custom junos-ping app, ICMP type %d: got matched=%v action=%v, want matched=%v action=%v",
					tt.icmpType, res.Matched, res.Action, tt.wantMatched, tt.wantAction)
			}
		})
	}
}
