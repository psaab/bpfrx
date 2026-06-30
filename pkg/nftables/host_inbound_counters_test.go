package nftables

import "testing"

// TestHostInboundDenyCounterNameRoundTrip is the #3361 contract test for the
// named-counter encoding shared by the renderer (pkg/daemon) and the Prometheus
// scraper (pkg/api): every (zone, family) pair must encode to a name that parses
// back to the SAME zone/family, even when the zone name itself contains the '_'
// separator or a '-'. The length prefix is what makes this unambiguous; dropping
// it (or mis-parsing the family/length boundary) turns this RED, which would
// mislabel the kernel-deny metric.
func TestHostInboundDenyCounterNameRoundTrip(t *testing.T) {
	cases := []struct{ zone, family string }{
		{"wan", "ip"},
		{"wan", "ip6"},
		{"untrust", "ip"},
		{"my-zone", "ip6"},
		{"under_score_zone", "ip"}, // zone contains the separator
		{"ip6", "ip"},              // zone equals a family token
		{"ip_4_x", "ip6"},          // zone mimics the encoding shape
		{"", "ip"},                 // empty zone (defensive)
		{"a_very-long_zone-name", "ip6"},
	}
	for _, tc := range cases {
		name := HostInboundDenyCounterName(tc.zone, tc.family)
		zone, family, ok := ParseHostInboundDenyCounterName(name)
		if !ok {
			t.Errorf("ParseHostInboundDenyCounterName(%q) failed for zone=%q family=%q",
				name, tc.zone, tc.family)
			continue
		}
		if zone != tc.zone || family != tc.family {
			t.Errorf("round-trip mismatch for %q: got zone=%q family=%q, want zone=%q family=%q",
				name, zone, family, tc.zone, tc.family)
		}
	}
}

// TestHostInboundDenyCounterNameNftSafe is the #3578 fail-on-revert proof: the
// counter name is declared in the kernel ruleset as a BARE nft identifier
// (`counter <n> {}`), which nft v1.1.6 accepts only for the byte set
// [A-Za-z0-9_.-]. A Junos zone name can legally carry other characters the
// lexer permits (':','+','*','%','=',',','<','>'), so the name MUST sanitize
// them. This asserts (a) every emitted name contains only bare-safe bytes after
// the fixed prefix, (b) it never starts with a digit (the prefix guarantees a
// leading letter), and (c) a sanitized name still parses back to a zone/family
// (the length-preserving mapping keeps the reverse key valid). Reverting the
// sanitization in HostInboundDenyCounterName turns the bare-safe assertion RED.
func TestHostInboundDenyCounterNameNftSafe(t *testing.T) {
	zones := []string{
		"wan", "my-zone", "under_score", "dotted.zone",
		"colon:zone", "plus+zone", "star*zone", "pct%zone",
		"eq=zone", "comma,zone", "lt<zone", "gt>zone",
		"a:b+c*d", // multiple unsafe bytes
	}
	safe := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'
	}
	for _, z := range zones {
		for _, fam := range []string{"ip", "ip6"} {
			name := HostInboundDenyCounterName(z, fam)
			if name == "" || (name[0] >= '0' && name[0] <= '9') {
				t.Errorf("name %q for zone=%q must not be empty or start with a digit", name, z)
			}
			for i := 0; i < len(name); i++ {
				if !safe(name[i]) {
					t.Errorf("name %q (zone=%q) carries an nft-unsafe byte %q at %d",
						name, z, name[i:i+1], i)
				}
			}
			// A sanitized name must still parse back to a zone/family pair (the
			// Prometheus scraper recovers labels from the kernel object name).
			gotZone, gotFam, ok := ParseHostInboundDenyCounterName(name)
			if !ok {
				t.Errorf("ParseHostInboundDenyCounterName(%q) failed (zone=%q)", name, z)
				continue
			}
			if gotFam != fam {
				t.Errorf("family round-trip mismatch for %q: got %q want %q", name, gotFam, fam)
			}
			if len(gotZone) != len(z) {
				t.Errorf("sanitization must be length-preserving: zone %q -> parsed %q", z, gotZone)
			}
		}
	}
}

// TestParseHostInboundDenyCounterNameRejectsForeign verifies the scraper ignores
// any object name that is not one of our host-inbound deny counters, so a foreign
// counter object in the table (or a malformed name) never emits a bogus
// zone/family series.
func TestParseHostInboundDenyCounterNameRejectsForeign(t *testing.T) {
	bad := []string{
		"",
		"some_other_counter",
		"xpfhi_",          // prefix only
		"xpfhi_ip",        // no length/zone
		"xpfhi_tcp_3_wan", // bad family
		"xpfhi_ip_9_wan",  // length mismatch (9 != len("wan"))
		"xpfhi_ip_x_wan",  // non-numeric length
		"xpfhi_ip6_2_wan", // length 2 != len("wan")=3
	}
	for _, name := range bad {
		if _, _, ok := ParseHostInboundDenyCounterName(name); ok {
			t.Errorf("ParseHostInboundDenyCounterName(%q) must be rejected, got ok", name)
		}
	}
}
