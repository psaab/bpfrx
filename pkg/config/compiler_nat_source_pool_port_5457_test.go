// #5457: a source-NAT pool's `port [range]` endpoints were parsed with
// strconv.Atoi, which accepts a leading sign and imposes no value-range or
// order check, so `port range low -1 high 99999` returned (-1, 99999, true) and
// `port range low 5000 high 100` returned (5000, 100, true) (inverted). A
// non-zero out-of-range/reversed value was only caught downstream (the strict
// gate + snapshot builder read the stamped value), and a 0-valued endpoint
// slipped through the parser as the "unconfigured" sentinel and silently widened
// to the default 1024-65535 PAT range. On the tolerant/lenient compile path the
// strict validator downgrades to a warning, so the malformed range must not be
// stamped into the pool at all.
//
// The fix routes every source-pool port endpoint through ParseCanonicalUint and
// enforces 1..65535 with a non-decreasing (low<=high) order check;
// parseSourcePoolPortRange now FAILS CLOSED (ok=false) on any violation. The
// compiler records the raw offending spec in PortRangeInvalidSpec so the strict
// commit gate hard-rejects (operator-visible) and the snapshot builder marks the
// pool unusable on the tolerant path — never installing the defaulted range.
//
// Flat-set syntax MUST be built via ParseSetCommand/SetPath, never NewParser.
package config

import "testing"

// TestParseSourcePoolPortRange_5457 exercises the parser directly. RED-on-revert
// (strconv.Atoi + no range/order check): every reject case returns ok=true.
func TestParseSourcePoolPortRange_5457(t *testing.T) {
	cases := []struct {
		name   string
		toks   []string
		wantLo int
		wantHi int
		wantOK bool
	}{
		// Junos `<low> [to <high>]` shape.
		{"junos-valid", []string{"1024", "to", "2048"}, 1024, 2048, true},
		{"junos-single", []string{"8080"}, 8080, 8080, true},
		{"junos-edge-full", []string{"1", "to", "65535"}, 1, 65535, true},
		{"junos-reversed", []string{"5000", "to", "100"}, 0, 0, false},
		{"junos-zero-low", []string{"0", "to", "100"}, 0, 0, false},
		{"junos-zero-high", []string{"100", "to", "0"}, 0, 0, false},
		{"junos-over-high", []string{"5000", "to", "70000"}, 0, 0, false},
		{"junos-over-single", []string{"99999"}, 0, 0, false},
		{"junos-zero-single", []string{"0"}, 0, 0, false},
		{"junos-neg-single", []string{"-1"}, 0, 0, false},
		{"junos-signed-plus", []string{"+80"}, 0, 0, false},
		{"junos-nonnumeric", []string{"http"}, 0, 0, false},
		{"junos-empty", []string{}, 0, 0, false},
		// Legacy `low <lo> high <hi>` shape.
		{"legacy-valid", []string{"low", "1024", "high", "2048"}, 1024, 2048, true},
		{"legacy-reversed", []string{"low", "5000", "high", "100"}, 0, 0, false},
		{"legacy-neg-low", []string{"low", "-1", "high", "99999"}, 0, 0, false},
		{"legacy-over-high", []string{"low", "5000", "high", "99999"}, 0, 0, false},
		{"legacy-zero-low", []string{"low", "0", "high", "5000"}, 0, 0, false},
		{"legacy-zero-high", []string{"low", "5000", "high", "0"}, 0, 0, false},
		{"legacy-nonnumeric", []string{"low", "abc", "high", "def"}, 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lo, hi, ok := parseSourcePoolPortRange(tc.toks)
			if ok != tc.wantOK {
				t.Fatalf("parseSourcePoolPortRange(%v) ok=%v, want %v (RED-on-revert: strconv.Atoi accepts these)",
					tc.toks, ok, tc.wantOK)
			}
			if ok && (lo != tc.wantLo || hi != tc.wantHi) {
				t.Fatalf("parseSourcePoolPortRange(%v) = %d/%d, want %d/%d",
					tc.toks, lo, hi, tc.wantLo, tc.wantHi)
			}
		})
	}
}

// TestSourceNATPoolPortRangeFailClosed_5457 drives the malformed ranges the
// pre-#5457 parser accepted through the full compiler. STRICT: CompileConfig
// hard-rejects. LENIENT: CompileConfigLenient warns, does NOT stamp the bad
// value (PortLow/PortHigh keep the 1024/65535 default), and sets
// PortRangeInvalidSpec.
func TestSourceNATPoolPortRangeFailClosed_5457(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
	}{
		{"neg-low-over-high", "set security nat source pool p1 port range low -1 high 99999"},
		{"reversed-legacy", "set security nat source pool p1 port range low 5000 high 100"},
		{"reversed-junos", "set security nat source pool p1 port range 5000 to 100"},
		{"zero-low-legacy", "set security nat source pool p1 port range low 0 high 5000"},
		{"zero-high-legacy", "set security nat source pool p1 port range low 5000 high 0"},
		{"zero-single", "set security nat source pool p1 port 0"},
		{"over-single", "set security nat source pool p1 port 99999"},
		{"nonnumeric-single", "set security nat source pool p1 port http"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool := []string{
				"set security nat source pool p1 address 203.0.113.5/32",
				tc.cmd,
			}

			// STRICT path: hard-reject at commit.
			tree := snatPoolTree(t, pool...)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("CompileConfig accepted malformed SNAT pool port %q (want reject)", tc.name)
			}

			// LENIENT path: warn-and-compile, malformed range SKIPPED.
			tree = snatPoolTree(t, pool...)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected %q (want warn-and-compile): %v", tc.name, err)
			}
			if len(cfg.Warnings) == 0 {
				t.Fatalf("CompileConfigLenient produced no warning for %q", tc.name)
			}
			p := cfg.Security.NAT.SourcePools["p1"]
			if p == nil {
				t.Fatalf("pool p1 missing after lenient compile of %q", tc.name)
			}
			if p.PortRangeInvalidSpec == "" {
				t.Fatalf("%q: PortRangeInvalidSpec empty, want the recorded bad spec", tc.name)
			}
			// The bad value must NOT be stamped — the pool keeps the safe default.
			if p.PortLow != 1024 || p.PortHigh != 65535 {
				t.Fatalf("%q: PortLow/PortHigh = %d/%d, want default 1024/65535 (malformed range must not be stamped)",
					tc.name, p.PortLow, p.PortHigh)
			}
		})
	}
}

// TestSourceNATPoolPortValidUnaffected_5457 is the over-reject control: a valid
// explicit range stamps unchanged on the strict path and never sets
// PortRangeInvalidSpec (valid-range behavior preserved bit-for-bit).
func TestSourceNATPoolPortValidUnaffected_5457(t *testing.T) {
	cases := []struct {
		cmd    string
		wantLo int
		wantHi int
	}{
		{"set security nat source pool p1 port range 1024 to 2048", 1024, 2048},
		{"set security nat source pool p1 port range low 1024 high 2048", 1024, 2048},
		{"set security nat source pool p1 port 1024", 1024, 1024},
		{"set security nat source pool p1 port range 1 to 65535", 1, 65535},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			tree := snatPoolTree(t,
				"set security nat source pool p1 address 203.0.113.5/32",
				tc.cmd)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected valid range %q: %v", tc.cmd, err)
			}
			p := cfg.Security.NAT.SourcePools["p1"]
			if p.PortRangeInvalidSpec != "" {
				t.Fatalf("valid range %q set PortRangeInvalidSpec=%q", tc.cmd, p.PortRangeInvalidSpec)
			}
			if p.PortLow != tc.wantLo || p.PortHigh != tc.wantHi {
				t.Fatalf("valid range %q PortLow/PortHigh = %d/%d, want %d/%d",
					tc.cmd, p.PortLow, p.PortHigh, tc.wantLo, tc.wantHi)
			}
		})
	}
}
