package policymatch

import "testing"

// #3357: GlobalPolicyAppliesToZonePair governs which scoped/unscoped global
// policies a filtered policy view shows. Its semantics mirror the runtime
// globalScopeMatches: an empty or "any" match-scope axis spans every zone.
func TestGlobalPolicyAppliesToZonePair(t *testing.T) {
	cases := []struct {
		name                                 string
		matchFrom, matchTo, filtFrom, filtTo string
		want                                 bool
	}{
		{"no filter, unscoped", "", "", "", "", true},
		{"no filter, scoped", "trust", "untrust", "", "", true},
		{"filter, unscoped global always applies", "", "", "trust", "untrust", true},
		{"filter, any-scope global always applies", "any", "any", "trust", "untrust", true},
		{"filter, scoped matches", "trust", "untrust", "trust", "untrust", true},
		{"filter, scoped from differs", "dmz", "untrust", "trust", "untrust", false},
		{"filter, scoped to differs", "trust", "dmz", "trust", "untrust", false},
		{"from-only filter, scoped to-only is all-from", "", "untrust", "trust", "", true},
		{"from-only filter, scoped from differs", "dmz", "", "trust", "", false},
		{"to-only filter, scoped from-only is all-to", "trust", "", "", "untrust", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GlobalPolicyAppliesToZonePair(tc.matchFrom, tc.matchTo, tc.filtFrom, tc.filtTo)
			if got != tc.want {
				t.Fatalf("GlobalPolicyAppliesToZonePair(%q,%q,%q,%q) = %v, want %v",
					tc.matchFrom, tc.matchTo, tc.filtFrom, tc.filtTo, got, tc.want)
			}
		})
	}
}
