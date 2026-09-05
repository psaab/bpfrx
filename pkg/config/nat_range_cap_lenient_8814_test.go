package config

import (
	"strings"
	"testing"
)

// #8814: the 256-address cap on a NAT `address <low> to <high>` range was raised
// as a COMPILER error, so it fired on the LENIENT path as well as the strict one
// and a persisted config carrying an oversized range FAILED TO LOAD.
//
// `CompileConfigLenient`'s own doc says it exists "so an upgraded node boots
// through". A braced oversized range could not boot through, on master, before
// any recent change -- #8800 only removed the accident that hid it for the
// packed spelling.
//
// THE CAP IS NOT MOVED OUT OF THE COMPILER, and that is the one place this
// departs from the issue's stated remedy. Measured, the widest legal spelling
// `address 0.0.0.0/32 to 255.255.255.255/32` is 4294967296 addresses, so an
// expansion with no bound would try to allocate 4.29 billion strings on the
// LENIENT path -- the boot path. That trades a load failure for an OOM. The
// bound stays in expandAddressRange; only the ERROR became a recorded fact,
// which is the shape NATPool.PortRangeInvalidSpec and
// FirewallFilterTerm.UnknownFrom already use in this package.
func natPoolText8814(body string) string {
	return "security {\n nat {\n  source {\n   pool p1 {\n    " + body + "\n   }\n  }\n }\n}\n"
}

func proxyARPText8814(body string) string {
	return "security {\n nat {\n  proxy-arp {\n   interface ge-0-0-0 {\n    " + body + "\n   }\n  }\n }\n}\n"
}

func compileBoth8814(t *testing.T, text string) (lenient *Config, lenientErr, strictErr error) {
	t.Helper()
	tl, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	lenient, lenientErr = CompileConfigLenient(tl)
	ts, _ := NewParser(text).Parse()
	_, strictErr = CompileConfig(ts)
	return lenient, lenientErr, strictErr
}

func TestOversizedNATRangeLoadsLenientlyAndRejectsStrictly8814(t *testing.T) {
	for _, tc := range []struct {
		name       string
		text       string
		wantAddrs  int
		wantStrict bool // strict must reject
	}{
		{"257 IPs — one over the cap", natPoolText8814("address 10.0.0.1/32 to 10.0.1.1/32;"), 0, true},
		{"256 IPs — the boundary, unchanged", natPoolText8814("address 10.0.0.1/32 to 10.0.1.0/32;"), 256, false},
		{"2 IPs — ordinary range", natPoolText8814("address 10.0.0.1/32 to 10.0.0.2/32;"), 2, false},
		{"a plain address, no range", natPoolText8814("address 10.0.0.1/32;"), 1, false},
		// The whole domain: what an unbounded expansion would have allocated.
		{"the full IPv4 domain", natPoolText8814("address 0.0.0.0/32 to 255.255.255.255/32;"), 0, true},
		// An oversized range must not take the pool's OTHER addresses with it.
		{"oversized range beside a valid address", natPoolText8814("address 10.9.9.9/32;\n    address 10.0.0.1/32 to 10.0.1.1/32;"), 1, true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg, lerr, serr := compileBoth8814(t, tc.text)
			if lerr != nil {
				t.Fatalf("CompileConfigLenient FAILED: %v\n"+
					"A persisted config must LOAD. This is the guarantee CompileConfigLenient "+
					"exists to provide -- an upgraded node, a peer sync, or a config file with a "+
					"range this build caps must boot through, with the strict path being the "+
					"thing that refuses new operator edits (#8814).", lerr)
			}
			pool := cfg.Security.NAT.SourcePools["p1"]
			if pool == nil {
				t.Fatal("pool p1 absent from the leniently compiled config")
			}
			if got := len(pool.Addresses); got != tc.wantAddrs {
				t.Errorf("pool has %d address(es), want %d — an oversized range must be OMITTED, "+
					"not fatal, and must not remove the pool's other addresses", got, tc.wantAddrs)
			}
			if tc.wantStrict {
				if serr == nil {
					t.Error("strict CompileConfig ACCEPTED an oversized range. The cap moving out of " +
						"the compiler trades toward exactly this failure: an operator can now author " +
						"a range the dataplane cannot expand (#8814)")
				} else if !strings.Contains(serr.Error(), "256") {
					t.Errorf("strict rejection does not name the cap: %v", serr)
				}
			} else if serr != nil {
				t.Errorf("strict CompileConfig rejected a legal config: %v", serr)
			}
		})
	}
}

// The proxy-arp caller of expandAddressRange had the IDENTICAL defect. Measured
// rather than assumed: on master a 257-address proxy-arp range failed
// CompileConfigLenient exactly as the pool case did. A fix that repaired only
// the pool would have left the same invariant broken one call site away.
func TestOversizedProxyARPRangeLoadsLenientlyAndRejectsStrictly8814(t *testing.T) {
	for _, tc := range []struct {
		name       string
		text       string
		wantStrict bool
	}{
		{"257 IPs — one over the cap", proxyARPText8814("address 10.0.0.1/32 to 10.0.1.1/32;"), true},
		{"256 IPs — the boundary, unchanged", proxyARPText8814("address 10.0.0.1/32 to 10.0.1.0/32;"), false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg, lerr, serr := compileBoth8814(t, tc.text)
			if lerr != nil {
				t.Fatalf("CompileConfigLenient FAILED: %v (#8814)", lerr)
			}
			if len(cfg.Security.NAT.ProxyARP) == 0 {
				t.Fatal("proxy-arp entry absent from the leniently compiled config")
			}
			if tc.wantStrict && serr == nil {
				t.Error("strict CompileConfig ACCEPTED an oversized proxy-arp range (#8814)")
			}
			if !tc.wantStrict && serr != nil {
				t.Errorf("strict CompileConfig rejected a legal proxy-arp range: %v", serr)
			}
		})
	}
}

// A SIZE limit is now recorded and survivable; MALFORMED input must still be
// fatal on BOTH paths. The sentinel exists to separate them, and a sentinel that
// swallowed real parse errors would turn this fix into a silent-acceptance bug —
// the class the whole NAT gate family exists to prevent.
func TestMalformedRangesStillFailOnBothPaths8814(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"low > high", "address 10.0.0.9/32 to 10.0.0.1/32;"},
		{"not an IP", "address notanip to 10.0.0.1/32;"},
		{"IPv6 endpoints (unsupported for ranges)", "address 2001:db8::1/128 to 2001:db8::9/128;"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, lerr, serr := compileBoth8814(t, natPoolText8814(tc.body))
			if lerr == nil {
				t.Error("CompileConfigLenient ACCEPTED a malformed range. Malformed input has no safe " +
					"interpretation to fall back to, so it must fail on the tolerant path too — only " +
					"the SIZE limit is recordable (#8814)")
			}
			if serr == nil {
				t.Error("strict CompileConfig accepted a malformed range")
			}
		})
	}
}

// The positive control the issue asks for: a cap that stops rejecting is the
// failure mode this change trades toward, so the strict rejection is asserted
// against a config that must be refused AND the recorded field is checked to be
// empty when it should be — otherwise "strict rejects" could be true for an
// unrelated reason.
func TestTheRecordedFieldIsOnlySetWhenOverCap8814(t *testing.T) {
	cfg, lerr, _ := compileBoth8814(t, natPoolText8814("address 10.0.0.1/32 to 10.0.1.0/32;"))
	if lerr != nil {
		t.Fatalf("lenient: %v", lerr)
	}
	if pool := cfg.Security.NAT.SourcePools["p1"]; pool == nil {
		t.Fatal("pool absent")
	} else if len(pool.OversizedAddressRanges) != 0 {
		t.Errorf("a 256-address range (AT the cap) was recorded as oversized: %v — the boundary is "+
			"inclusive and an off-by-one here would reject configs that are legal today",
			pool.OversizedAddressRanges)
	}
	cfg2, lerr2, _ := compileBoth8814(t, natPoolText8814("address 10.0.0.1/32 to 10.0.1.1/32;"))
	if lerr2 != nil {
		t.Fatalf("lenient: %v", lerr2)
	}
	pool2 := cfg2.Security.NAT.SourcePools["p1"]
	if pool2 == nil || len(pool2.OversizedAddressRanges) != 1 {
		t.Fatalf("a 257-address range was not recorded; without the record the strict gate has "+
			"nothing to reject and the cap silently disappears (got %v)", pool2)
	}
	if !strings.Contains(pool2.OversizedAddressRanges[0], "257") {
		t.Errorf("the recorded spec does not carry the size: %q", pool2.OversizedAddressRanges[0])
	}
}
