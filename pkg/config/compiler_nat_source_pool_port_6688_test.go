// #6688: a source-NAT pool's `port range` tail was read with a >= arity and a
// discarded remainder, so any token the grammar did not consume vanished.
//
// The lexer strips `[`/`]` before the compiler observes anything, so the
// bracketed spelling `port range [ 1000 2000 ]` and a mistyped bare
// `port range 1000 2000` (the `to` separator dropped) both arrive as the token
// slice ["1000","2000"]. The pre-fix parser took toks[0] as BOTH endpoints and
// ignored the rest: a pool the operator sized at 1001 ports compiled to ONE
// port (PortLow == PortHigh == 1000) and committed clean. The same discard let
// an out-of-range or non-numeric second slot ("1000 99999", "1000 notaport")
// commit clean too, because validateSourceNATPoolStrict only ever saw the
// stamped first endpoint.
//
// `port range` is NOT a value list — it is a compound value TAIL with two fixed
// arities (`<low>` / `<low> to <high>` and the legacy `low <lo> high <hi>`).
// Reading ["1000","2000"] as [1000,2000] would invent a two-token
// `range <low> <high>` grammar Junos does not have, and (brackets already gone)
// would silently redefine the mistyped bare form as well. The fix therefore
// FAILS CLOSED on an unconsumed token, routing it through the existing #5457
// PortRangeInvalidSpec channel: hard-reject at strict commit, pool marked
// unusable on the tolerant load / peer-sync path.
//
// Flat-set syntax MUST be built via ParseSetCommand/SetPath, never NewParser.
package config

import (
	"strings"
	"testing"
)

// TestParseSourcePoolPortRangeUnconsumedTail_6688 exercises the parser directly.
// RED-on-revert (`len(toks) >= 4` / `len(toks) >= 3` with the remainder
// discarded): every reject case below returns ok=true, and the two-token case
// returns the one-port range (1000, 1000).
func TestParseSourcePoolPortRangeUnconsumedTail_6688(t *testing.T) {
	cases := []struct {
		name   string
		toks   []string
		wantLo int
		wantHi int
		wantOK bool
	}{
		// The issue's headline case: `port range [ 1000 2000 ]`, which reaches
		// the parser bracket-free and pre-fix compiled a ONE-port pool.
		{"bracket-pair", []string{"1000", "2000"}, 0, 0, false},
		// Unvalidated second slot: pre-fix these committed clean because the
		// slot was never parsed at all.
		{"bracket-over-range-high", []string{"1000", "99999"}, 0, 0, false},
		{"bracket-nonnumeric-high", []string{"1000", "notaport"}, 0, 0, false},
		{"bracket-zero-high", []string{"1000", "0"}, 0, 0, false},
		// Trailing junk after an otherwise well-formed range.
		{"junos-trailing-token", []string{"1000", "to", "2000", "3000"}, 0, 0, false},
		{"junos-trailing-range", []string{"1000", "to", "2000", "to", "3000"}, 0, 0, false},
		{"legacy-trailing-token", []string{"low", "1000", "high", "2000", "extra"}, 0, 0, false},
		// A separator that is not `to` is not the Junos shape either.
		{"junos-wrong-separator", []string{"1000", "through", "2000"}, 0, 0, false},
		// Over-reject controls: every shape the grammar DOES define still parses.
		{"junos-single", []string{"8080"}, 8080, 8080, true},
		{"junos-range", []string{"1024", "to", "2048"}, 1024, 2048, true},
		{"junos-edge-full", []string{"1", "to", "65535"}, 1, 65535, true},
		{"legacy-range", []string{"low", "1024", "high", "2048"}, 1024, 2048, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lo, hi, ok := parseSourcePoolPortRange(tc.toks)
			if ok != tc.wantOK {
				t.Fatalf("parseSourcePoolPortRange(%v) ok=%v, want %v "+
					"(RED-on-revert: the >= arity accepts these and discards the tail)",
					tc.toks, ok, tc.wantOK)
			}
			if lo != tc.wantLo || hi != tc.wantHi {
				t.Fatalf("parseSourcePoolPortRange(%v) = %d/%d, want %d/%d "+
					"(RED-on-revert: the two-token case returns the ONE-port range 1000/1000)",
					tc.toks, lo, hi, tc.wantLo, tc.wantHi)
			}
		})
	}
}

// TestSourceNATPoolPortRangeTailFailsClosed_6688 drives the same specs through
// the whole compiler. STRICT hard-rejects with the operator-visible port-range
// message; LENIENT warns, records the raw spec, and leaves the safe default
// stamped so the tolerant load / peer-sync path installs nothing.
func TestSourceNATPoolPortRangeTailFailsClosed_6688(t *testing.T) {
	cases := []struct {
		name     string
		cmd      string
		wantSpec string
	}{
		{"bracket-pair", "set security nat source pool p1 port range [ 1000 2000 ]", "1000 2000"},
		{"bare-pair-missing-to", "set security nat source pool p1 port range 1000 2000", "1000 2000"},
		{"bracket-over-range-high", "set security nat source pool p1 port range [ 1000 99999 ]", "1000 99999"},
		{"bracket-nonnumeric-high", "set security nat source pool p1 port range [ 1000 notaport ]", "1000 notaport"},
		{"legacy-trailing-token", "set security nat source pool p1 port range low 1000 high 2000 extra", "low 1000 high 2000 extra"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool := []string{
				"set security nat source pool p1 address 203.0.113.5/32",
				tc.cmd,
			}

			// STRICT: hard-reject, and the message must name the offending spec
			// so the operator can see WHICH value was refused.
			tree := snatPoolTree(t, pool...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted %q (pre-fix: compiles a one-port pool)", tc.cmd)
			}
			if !strings.Contains(err.Error(), "port range") ||
				!strings.Contains(err.Error(), tc.wantSpec) {
				t.Fatalf("CompileConfig(%q) error = %v, want the port-range rejection naming %q",
					tc.cmd, err, tc.wantSpec)
			}

			// LENIENT: warn-and-compile, nothing stamped, pool marked unusable.
			tree = snatPoolTree(t, pool...)
			cfg, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("CompileConfigLenient rejected %q (want warn-and-compile): %v", tc.cmd, lerr)
			}
			p := cfg.Security.NAT.SourcePools["p1"]
			if p == nil {
				t.Fatalf("pool p1 missing after lenient compile of %q", tc.cmd)
			}
			if p.PortRangeInvalidSpec != tc.wantSpec {
				t.Fatalf("%q: PortRangeInvalidSpec = %q, want %q "+
					"(RED-on-revert: the tail is discarded, so nothing is recorded)",
					tc.cmd, p.PortRangeInvalidSpec, tc.wantSpec)
			}
			if p.PortLow != 1024 || p.PortHigh != 65535 {
				t.Fatalf("%q: PortLow/PortHigh = %d/%d, want the unstamped default 1024/65535 "+
					"(RED-on-revert: the one-port range 1000/1000 is stamped)",
					tc.cmd, p.PortLow, p.PortHigh)
			}
			if _, _, ok := SourceNATPoolPortRange(p); ok {
				t.Fatalf("%q: SourceNATPoolPortRange reports the pool usable; the "+
					"tolerant path must install nothing for a rejected range", tc.cmd)
			}
		})
	}
}

// TestSourceNATPoolPortRangeSpellingsAgree_6688 is the differential this issue's
// allowlist row in TestSchemaSpellingDifferentialGate stood for, pinned at the
// leaf: every spelling of a two-token `port range` tail must compile to the SAME
// thing. Pre-fix the bracket spellings silently kept one token while the
// repeated spellings replaced the value, which is what the gate detected.
func TestSourceNATPoolPortRangeSpellingsAgree_6688(t *testing.T) {
	spellings := map[string][]string{
		"hier-bracket": {"set security nat source pool p1 port range [ 1000 2000 ]"},
		"flat-bare":    {"set security nat source pool p1 port range 1000 2000"},
	}
	for name, cmds := range spellings {
		t.Run(name, func(t *testing.T) {
			tree := snatPoolTree(t, append([]string{
				"set security nat source pool p1 address 203.0.113.5/32",
			}, cmds...)...)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient(%s): %v", name, err)
			}
			p := cfg.Security.NAT.SourcePools["p1"]
			if p == nil {
				t.Fatalf("%s: pool p1 missing", name)
			}
			if p.PortRangeInvalidSpec != "1000 2000" {
				t.Fatalf("%s: PortRangeInvalidSpec = %q, want %q — every spelling of the "+
					"same two-token tail must reach the same verdict",
					name, p.PortRangeInvalidSpec, "1000 2000")
			}
		})
	}
}

// TestSourceNATPoolPortRangeValidUnaffected_6688 is the over-reject control for
// the arity tightening: the valid grammar, including the single-port and
// no-translation shapes, is untouched.
func TestSourceNATPoolPortRangeValidUnaffected_6688(t *testing.T) {
	cases := []struct {
		cmd    string
		wantLo int
		wantHi int
	}{
		{"set security nat source pool p1 port range 1000 to 2000", 1000, 2000},
		{"set security nat source pool p1 port range low 1000 high 2000", 1000, 2000},
		{"set security nat source pool p1 port range 1000", 1000, 1000},
		{"set security nat source pool p1 port 1000", 1000, 1000},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			tree := snatPoolTree(t,
				"set security nat source pool p1 address 203.0.113.5/32",
				tc.cmd)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected the valid grammar %q: %v", tc.cmd, err)
			}
			p := cfg.Security.NAT.SourcePools["p1"]
			if p.PortRangeInvalidSpec != "" {
				t.Fatalf("%q set PortRangeInvalidSpec=%q", tc.cmd, p.PortRangeInvalidSpec)
			}
			if p.PortLow != tc.wantLo || p.PortHigh != tc.wantHi {
				t.Fatalf("%q PortLow/PortHigh = %d/%d, want %d/%d",
					tc.cmd, p.PortLow, p.PortHigh, tc.wantLo, tc.wantHi)
			}
		})
	}
}
