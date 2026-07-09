package policymatch

import "testing"

// #3357/#4626: GlobalPolicyAppliesToZonePair governs which scoped/unscoped
// global policies a filtered policy view shows. Its semantics mirror the runtime
// globalScopeSetMatches: an empty or "any" match-scope axis spans every zone,
// and a multi-zone scope (#4626) applies when the filter names ANY member.
func TestGlobalPolicyAppliesToZonePair(t *testing.T) {
	cases := []struct {
		name               string
		matchFrom, matchTo []string
		filtFrom, filtTo   string
		want               bool
	}{
		{"no filter, unscoped", nil, nil, "", "", true},
		{"no filter, scoped", []string{"trust"}, []string{"untrust"}, "", "", true},
		{"filter, unscoped global always applies", nil, nil, "trust", "untrust", true},
		{"filter, any-scope global always applies", []string{"any"}, []string{"any"}, "trust", "untrust", true},
		{"filter, scoped matches", []string{"trust"}, []string{"untrust"}, "trust", "untrust", true},
		{"filter, scoped from differs", []string{"dmz"}, []string{"untrust"}, "trust", "untrust", false},
		{"filter, scoped to differs", []string{"trust"}, []string{"dmz"}, "trust", "untrust", false},
		{"from-only filter, scoped to-only is all-from", nil, []string{"untrust"}, "trust", "", true},
		{"from-only filter, scoped from differs", []string{"dmz"}, nil, "trust", "", false},
		{"to-only filter, scoped from-only is all-to", []string{"trust"}, nil, "", "untrust", true},
		// #4626 M03: a multi-zone scope applies when the filter names any member.
		{"multi-zone from matches member", []string{"trust", "dmz"}, []string{"untrust"}, "dmz", "untrust", true},
		{"multi-zone from misses non-member", []string{"trust", "dmz"}, []string{"untrust"}, "wan", "untrust", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GlobalPolicyAppliesToZonePair(tc.matchFrom, tc.matchTo, tc.filtFrom, tc.filtTo)
			if got != tc.want {
				t.Fatalf("GlobalPolicyAppliesToZonePair(%v,%v,%q,%q) = %v, want %v",
					tc.matchFrom, tc.matchTo, tc.filtFrom, tc.filtTo, got, tc.want)
			}
		})
	}
}
