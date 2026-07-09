package nftables

import "testing"

// TestLo0CounterNameRoundTrip is the #4422 contract test for the lo0 named-counter
// encoding shared by the renderer (pkg/daemon) and the Prometheus scraper
// (pkg/api): a bare-safe Junos `then count <name>` must encode to an nft object
// name that parses back to the SAME label. Unlike the host-inbound encoding there
// is no length prefix — the object name is just the prefixed count name.
func TestLo0CounterNameRoundTrip(t *testing.T) {
	cases := []string{
		"ssh-hits",
		"bgp_in",
		"dotted.count",
		"1leading-digit", // legal Junos count name; the prefix guarantees a valid ident
		"a-very_long.count-name",
	}
	for _, name := range cases {
		obj := Lo0CounterName(name)
		got, ok := ParseLo0CounterName(obj)
		if !ok {
			t.Errorf("ParseLo0CounterName(%q) failed for count=%q", obj, name)
			continue
		}
		// Bare-safe names sanitize to themselves, so the round-trip is exact.
		if got != name {
			t.Errorf("round-trip mismatch for %q: got %q, want %q", obj, got, name)
		}
	}
}

// TestParseLo0CounterNameRejectsForeign asserts the scraper silently skips
// objects that are not our lo0 counters (wrong or empty prefix), so a foreign
// counter object in the inet table never mislabels a metric series.
func TestParseLo0CounterNameRejectsForeign(t *testing.T) {
	foreign := []string{
		"",               // empty
		"xpflo0_",        // prefix only, no name
		"xpfhi_ip_3_wan", // a host-inbound deny counter, not lo0
		"someother",      // unrelated object
		"lo0_hits",       // missing the xpf prefix
	}
	for _, name := range foreign {
		if _, ok := ParseLo0CounterName(name); ok {
			t.Errorf("ParseLo0CounterName(%q) = ok, want rejected", name)
		}
	}
}

// TestLo0CounterNameSanitizesExoticBytes mirrors the host-inbound bare-safe
// guarantee (#3578): a Junos count name carrying bytes the nft lexer rejects in a
// bare identifier ([A-Za-z0-9_.-]) must sanitize so the UNQUOTED counter
// declaration parses. The result always begins with the fixed prefix (a letter),
// never a digit.
func TestLo0CounterNameSanitizesExoticBytes(t *testing.T) {
	safe := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'
	}
	for _, name := range []string{"colon:c", "plus+c", "star*c", "a:b+c"} {
		obj := Lo0CounterName(name)
		for i := 0; i < len(obj); i++ {
			if !safe(obj[i]) {
				t.Errorf("Lo0CounterName(%q) = %q has unsafe byte %q at %d", name, obj, obj[i], i)
			}
		}
		if obj[0] >= '0' && obj[0] <= '9' {
			t.Errorf("Lo0CounterName(%q) = %q starts with a digit", name, obj)
		}
	}
}
