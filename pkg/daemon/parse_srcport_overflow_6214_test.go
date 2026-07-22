package daemon

import "testing"

// TestParseSrcPortRejectsOverflow6214 guards against the #6214 uint16
// accumulator overflow in parseSrcPort. Before the fix, digits were
// accumulated directly into a uint16, so a port string above 65535 wrapped
// mod 65536 — "70000" produced 4464 — silently corrupting the source /
// destination port carried in NetFlow v9 / IPFIX flow records.
//
// The fix accumulates into a wider integer and rejects any value above
// 65535 (a real port never exceeds it), returning the 0 "no port" sentinel.
// This test FAILS if parseSrcPort is reverted to the uint16 accumulator
// (it would return 4464 for "70000") and PASSES with the fix.
func TestParseSrcPortRejectsOverflow6214(t *testing.T) {
	// Overflow cases: must NOT silently wrap. The old uint16 accumulator
	// returned addr's numeric port mod 65536; assert we never do that.
	overflow := []struct {
		addr string
		wrap uint16 // value the reverted uint16 accumulator would produce
	}{
		{"1.2.3.4:70000", 4464},   // 70000 mod 65536 == 4464 (the #6214 bug)
		{"1.2.3.4:65536", 0},      // first out-of-range value; wraps to 0
		{"1.2.3.4:99999", 34463},  // 99999 mod 65536 == 34463
		{"1.2.3.4:4294967296", 0}, // 2^32, also overflows a uint32 accumulator
	}
	for _, tc := range overflow {
		got := parseSrcPort(tc.addr)
		if got != 0 {
			t.Errorf("parseSrcPort(%q) = %d, want 0 (out-of-range port must be rejected, not wrapped)", tc.addr, got)
		}
		// Explicit guard on the historical wrap value for clarity: even when
		// the reject sentinel (0) happens to equal the wrap value, the
		// primary port "70000" -> 4464 case above proves the revert fails.
		if tc.wrap != 0 && got == tc.wrap {
			t.Errorf("parseSrcPort(%q) = %d — silently wrapped mod 65536 (the #6214 overflow bug)", tc.addr, tc.wrap)
		}
	}

	// Valid ports (0..65535) must still parse exactly as before.
	valid := []struct {
		addr string
		want uint16
	}{
		{"1.2.3.4:0", 0},
		{"1.2.3.4:80", 80},
		{"1.2.3.4:443", 443},
		{"1.2.3.4:65535", 65535},
		{"[2001:db8::1]:8080", 8080}, // last-colon scan lands on the IPv6 port
		{"no-colon-here", 0},         // absent port -> 0 sentinel
	}
	for _, tc := range valid {
		if got := parseSrcPort(tc.addr); got != tc.want {
			t.Errorf("parseSrcPort(%q) = %d, want %d", tc.addr, got, tc.want)
		}
	}
}
