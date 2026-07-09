package nftables

import "testing"

// TestHostInboundAcceptCounterNameRoundTrip is the #4759 contract test for the
// accept-counter name encoding shared by the renderer (pkg/daemon) and the
// Prometheus scraper (pkg/api): every fixed type-class key must encode to a name
// that parses back to the SAME key. Dropping or mis-parsing the prefix turns
// this RED, which would mislabel the accept metric.
func TestHostInboundAcceptCounterNameRoundTrip(t *testing.T) {
	for _, typ := range HostInboundAcceptCounterTypes {
		name := HostInboundAcceptCounterName(typ)
		got, ok := ParseHostInboundAcceptCounterName(name)
		if !ok {
			t.Errorf("ParseHostInboundAcceptCounterName(%q) failed for type=%q", name, typ)
			continue
		}
		if got != typ {
			t.Errorf("round-trip mismatch for %q: got type=%q, want %q", name, got, typ)
		}
	}
}

// TestHostInboundAcceptCounterNameNftSafe proves the accept-counter name is a
// BARE nft identifier — nft v1.1.6 requires the counter DECLARATION unquoted
// (`counter <n> {}`), which accepts only [A-Za-z0-9_.-] and no leading digit
// (#3578). The names are fixed compile-time constants, so this is a guard
// against a future key introducing an unsafe byte or a digit-leading key.
func TestHostInboundAcceptCounterNameNftSafe(t *testing.T) {
	safe := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'
	}
	for _, typ := range HostInboundAcceptCounterTypes {
		name := HostInboundAcceptCounterName(typ)
		if name == "" || (name[0] >= '0' && name[0] <= '9') {
			t.Errorf("name %q for type=%q must not be empty or start with a digit", name, typ)
		}
		for i := 0; i < len(name); i++ {
			if !safe(name[i]) {
				t.Errorf("name %q (type=%q) carries an nft-unsafe byte %q at %d",
					name, typ, name[i:i+1], i)
			}
		}
	}
}

// TestParseHostInboundAcceptCounterNameRejectsForeign verifies the scraper
// ignores any object name that is not one of our accept counters — critically a
// `xpfhi_` DENY counter, which shares the `inet xpf_hostinbound` table. The two
// prefixes (`xpfhi_` vs `xpfhia_`) must never cross-parse, or the accept and
// deny series would double-count each other.
func TestParseHostInboundAcceptCounterNameRejectsForeign(t *testing.T) {
	bad := []string{
		"",
		"some_other_counter",
		"xpfhia_",             // prefix only
		"xpfhia_bogus",        // unknown type-class
		"xpfhia_icmp6",        // truncated key
		"xpfhi_ip_3_wan",      // a DENY counter (deny prefix)
		"xpfhi_ip6_3_wan",     // a DENY counter (deny prefix)
		"xpfhia_icmp4_error_", // trailing junk
	}
	for _, name := range bad {
		if _, ok := ParseHostInboundAcceptCounterName(name); ok {
			t.Errorf("ParseHostInboundAcceptCounterName(%q) must be rejected, got ok", name)
		}
	}
	// And the reverse: an accept counter must NOT parse as a deny counter, so the
	// deny scraper skips it (no bogus zone/family series).
	for _, typ := range HostInboundAcceptCounterTypes {
		name := HostInboundAcceptCounterName(typ)
		if _, _, ok := ParseHostInboundDenyCounterName(name); ok {
			t.Errorf("accept counter %q must NOT parse as a deny counter", name)
		}
	}
}
