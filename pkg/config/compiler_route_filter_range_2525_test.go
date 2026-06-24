package config

import (
	"strings"
	"testing"
)

// compileRouteFilterCmd parses a single flat-set route-filter command into a
// tree (per the project's flat-set testing rule: ParseSetCommand + SetPath).
func compileRouteFilterCmd(t *testing.T, cmd string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	path, err := ParseSetCommand(cmd)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	return tree
}

// TestRouteFilterPrefixLengthRangeCompile verifies the #2525 compiler change:
// "prefix-length-range /low-/high" captures the two bounds into
// RouteFilter.RangeLow/RangeHigh (they stayed 0 before the fix — the range was
// silently dropped and the renderer degraded to an open-ended le maxLen).
func TestRouteFilterPrefixLengthRangeCompile(t *testing.T) {
	cases := []struct {
		name     string
		cmd      string
		wantLow  int
		wantHigh int
	}{
		{"v4", "set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 prefix-length-range /16-/24", 16, 24},
		{"v6", "set policy-options policy-statement p term t1 from route-filter 2001:db8::/32 prefix-length-range /48-/64", 48, 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := compileRouteFilterCmd(t, tc.cmd)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			rf := firstRouteFilter(t, cfg)
			if rf.MatchType != "prefix-length-range" {
				t.Errorf("MatchType = %q, want prefix-length-range", rf.MatchType)
			}
			if rf.RangeLow != tc.wantLow || rf.RangeHigh != tc.wantHigh {
				t.Errorf("Range = /%d-/%d, want /%d-/%d (the /low-/high bounds must be parsed, #2525)",
					rf.RangeLow, rf.RangeHigh, tc.wantLow, tc.wantHigh)
			}
		})
	}
}

// TestRouteFilterPrefixLengthRangeBrace covers the brace AST shape: the
// /low-/high token lands at Keys[3].
func TestRouteFilterPrefixLengthRangeBrace(t *testing.T) {
	src := `policy-options {
  policy-statement p {
    term t1 {
      from {
        route-filter 10.0.0.0/8 prefix-length-range /16-/24;
      }
      then accept;
    }
  }
}`
	p := NewParser(src)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rf := firstRouteFilter(t, cfg)
	if rf.RangeLow != 16 || rf.RangeHigh != 24 {
		t.Errorf("Range = /%d-/%d, want /16-/24 (brace parse, #2525)", rf.RangeLow, rf.RangeHigh)
	}
}

// TestRouteFilterThroughRejectedAtCommit verifies the #2525 strict gate: the
// FRR-unsupported "through" match-type is rejected at commit with a clear,
// actionable error. Fail-on-revert: drop the validateRouteFilterMatchTypesStrict
// call (or its through arm) and CompileConfig succeeds — this test fails.
func TestRouteFilterThroughRejectedAtCommit(t *testing.T) {
	tree := compileRouteFilterCmd(t,
		"set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 through 10.1.0.0/16")
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit reject for `through`, got nil")
	}
	if !strings.Contains(err.Error(), "through") || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("error %q does not name the unsupported `through` match-type", err)
	}
}

// TestRouteFilterThroughLenientWarn verifies the #1960 tolerant-path downgrade:
// the lenient compile (load / peer-sync) accepts a stored `through` and records
// a warning instead of failing, so an already-persisted config still boots.
func TestRouteFilterThroughLenientWarn(t *testing.T) {
	tree := compileRouteFilterCmd(t,
		"set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 through 10.1.0.0/16")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on `through`: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "route-filter match-type") && strings.Contains(w, "through") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a downgraded `through` warning, got: %v", cfg.Warnings)
	}
}

// TestRouteFilterPrefixLengthRangeValidation verifies the #2525 semantic gate
// on the /low-/high bounds: inverted, out-of-family-range, below-base, and
// malformed ranges are rejected at commit; a well-formed range commits.
func TestRouteFilterPrefixLengthRangeValidation(t *testing.T) {
	cases := []struct {
		name      string
		cmd       string
		wantError bool
		errSubstr string
	}{
		{
			name:      "valid",
			cmd:       "set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 prefix-length-range /16-/24",
			wantError: false,
		},
		{
			name:      "inverted",
			cmd:       "set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 prefix-length-range /24-/16",
			wantError: true,
			errSubstr: "inverted",
		},
		{
			name:      "out_of_range_v4",
			cmd:       "set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 prefix-length-range /16-/40",
			wantError: true,
			errSubstr: "exceeds the address-family maximum",
		},
		{
			name:      "below_base",
			cmd:       "set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 prefix-length-range /4-/24",
			wantError: true,
			errSubstr: "less specific than the base prefix",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := compileRouteFilterCmd(t, tc.cmd)
			_, err := CompileConfig(tree)
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected commit reject, got nil")
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("error %q does not contain %q", err, tc.errSubstr)
				}
			} else if err != nil {
				t.Fatalf("valid range must compile: %v", err)
			}
		})
	}
}

// TestRouteFilterMatchTypesStrictUnaffected confirms the new gate does not
// reject the existing match-types (exact/longer/orlonger/upto).
func TestRouteFilterMatchTypesStrictUnaffected(t *testing.T) {
	cmds := []string{
		"set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 exact",
		"set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 longer",
		"set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 orlonger",
		"set policy-options policy-statement p term t1 from route-filter 10.0.0.0/8 upto /24",
	}
	for _, cmd := range cmds {
		tree := compileRouteFilterCmd(t, cmd)
		if _, err := CompileConfig(tree); err != nil {
			t.Errorf("compile of %q must succeed: %v", cmd, err)
		}
	}
}
