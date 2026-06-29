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
