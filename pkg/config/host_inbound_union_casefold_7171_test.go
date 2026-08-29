package config

import "testing"

// TestUnionHostInboundTokensCaseFoldDedup pins the dedup key of
// UnionHostInboundTokens to the CASE-FOLDED token while the rendered value
// keeps the case the operator authored (#7171).
//
// The union deduped on the raw trimmed token, so a zone authoring `ssh` and an
// interface authoring `SSH` produced BOTH entries: one service listed twice, in
// two spellings, on every display surface fed by this union. Every membership
// predicate downstream is case-insensitive, so the duplicate is not an
// admission bug -- it is the display disagreeing with the single service that
// is actually admitted.
//
// Two properties are asserted together because fixing either one alone is a
// regression: fold the key and you must NOT also fold the value (that would
// discard the authored case this function documents itself as preserving).
func TestUnionHostInboundTokensCaseFoldDedup(t *testing.T) {
	for _, tc := range []struct {
		name        string
		zone, iface []string
		want        []string
	}{
		{"cross-level case duplicate", []string{"ssh"}, []string{"SSH"}, []string{"ssh"}},
		{"same-level case duplicate", []string{"ping", "PING"}, nil, []string{"ping"}},
		{"authored case preserved", []string{"SSH"}, []string{"ssh"}, []string{"SSH"}},
		{"mixed spelling", []string{"IKE"}, []string{"ike", "ssh"}, []string{"IKE", "ssh"}},
		{"distinct tokens untouched", []string{"ssh"}, []string{"ping"}, []string{"ssh", "ping"}},
		{"whitespace still trimmed", []string{" ssh "}, []string{"SSH"}, []string{"ssh"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := UnionHostInboundTokens(tc.zone, tc.iface)
			if len(got) != len(tc.want) {
				t.Fatalf("UnionHostInboundTokens(%q,%q) = %q, want %q", tc.zone, tc.iface, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("UnionHostInboundTokens(%q,%q) = %q, want %q", tc.zone, tc.iface, got, tc.want)
				}
			}
		})
	}
}
