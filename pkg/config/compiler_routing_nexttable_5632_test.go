package config

import "testing"

// TestParseNextTableInstanceDottedInstance_5632 pins the next-table identity
// extraction for routing-instance names that themselves contain ".inet".
//
// A Junos next-table target is always "<instance>.<family>.<index>", so the
// family+index suffix is the LAST ".inet" occurrence. The pre-#5632 code used
// strings.Index (FIRST occurrence), which truncated an accepted dotted instance
// name (e.g. "a.inet.b", table "a.inet.b.inet.0") at the embedded ".inet" and
// emitted the wrong next-table instance ("a"), silently redirecting the route
// leak to a different / non-existent routing instance.
//
// Fail-on-revert: swapping strings.LastIndex back to strings.Index turns the
// dotted-instance cases from PASS to FAIL (they resolve to "a" / "test").
func TestParseNextTableInstanceDottedInstance_5632(t *testing.T) {
	cases := []struct {
		name  string
		table string
		want  string
	}{
		// Ordinary single-".inet" targets — Index and LastIndex agree, so these
		// guard against a regression in the common path.
		{"plain-v4", "Comcast-GigabitPro.inet.0", "Comcast-GigabitPro"},
		{"plain-v6", "blue.inet6.0", "blue"},
		{"nonzero-index", "green.inet.2", "green"},
		{"no-suffix", "plain", "plain"},
		// Dotted-instance targets — the #5632 bug cases. strings.Index truncated
		// at the first ".inet"; LastIndex keeps the full instance name.
		{"dotted-instance", "a.inet.b.inet.0", "a.inet.b"},
		{"inet-substring-name", "test.inet2.inet.0", "test.inet2"},
		{"instance-named-like-table", "foo.inet.0.inet.0", "foo.inet.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseNextTableInstance(tc.table); got != tc.want {
				t.Fatalf("parseNextTableInstance(%q) = %q, want %q", tc.table, got, tc.want)
			}
		})
	}
}
