package appid

import "testing"

// #3439 / #3393 — ProtocolNumberLenient is the filter-side reverse used by
// the session-inspection surfaces. It must accept everything the strict
// ProtocolNumber resolves PLUS any display-only NAME that ProtocolName
// renders. Since #3393 closed the strict round-trip ("ipv6"=41 now reverses
// through ProtocolNumber too), the lenient form equals ProtocolNumber for
// the current tables; the assertions below still pin its acceptance set so a
// future render-only name keeps resolving on the read/filter side.
func TestProtocolNumberLenient(t *testing.T) {
	ok := map[string]uint8{
		// "ipv6"=41 now reverses through the strict resolver too (#3393);
		// the lenient form continues to accept it.
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

	// #3393: the strict resolver now reverses "ipv6" too, so the
	// ProtocolName↔ProtocolNumber round-trip closes for proto 41.
	if n, ok := ProtocolNumber("ipv6"); !ok || n != 41 {
		t.Errorf("ProtocolNumber(\"ipv6\") = (%d, %v), want (41, true) — the strict round-trip must hold (#3393)", n, ok)
	}
}
