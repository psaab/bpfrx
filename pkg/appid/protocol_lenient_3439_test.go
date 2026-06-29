package appid

import "testing"

// #3439 / Refs #3393 — ProtocolNumberLenient is the filter-side reverse
// used by the session-inspection surfaces. It must accept everything the
// strict ProtocolNumber resolves PLUS any display-only NAME that
// ProtocolName renders but ProtocolNumber deliberately does not reverse
// (notably "ipv6"=41). It must NOT loosen the strict ProtocolNumber SSOT
// (config compilation / policy matching) — that stays one-way.
//
// FAIL-ON-REVERT: dropping the ProtocolName reverse-scan makes the
// "ipv6"/"IPV6" cases go RED (ProtocolNumber alone returns ok=false).
func TestProtocolNumberLenient(t *testing.T) {
	ok := map[string]uint8{
		// Display-only name with no strict reverse — the regression guard.
		"ipv6": 41, "IPV6": 41, "Ipv6": 41,
		// Strict set still resolves.
		"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58,
		"gre": 47, "esp": 50, "ipip": 4, "ospf": 89, "sctp": 132,
		// Numeric.
		"0": 0, "41": 41, "255": 255,
	}
	for name, want := range ok {
		got, gotOK := ProtocolNumberLenient(name)
		if !gotOK || got != want {
			t.Errorf("ProtocolNumberLenient(%q) = (%d, %v), want (%d, true)", name, got, gotOK, want)
		}
	}

	for _, bad := range []string{"", "tcpip", "256", "-1", "bogus"} {
		if n, ok := ProtocolNumberLenient(bad); ok {
			t.Errorf("ProtocolNumberLenient(%q) = (%d, true), want ok=false", bad, n)
		}
	}

	// The strict SSOT is unchanged: "ipv6" stays one-way through
	// ProtocolNumber so the pkg/config acceptance mirror does not drift.
	if n, ok := ProtocolNumber("ipv6"); ok {
		t.Errorf("ProtocolNumber(\"ipv6\") = (%d, true); the strict resolver must stay one-way (#3393)", n)
	}
}
