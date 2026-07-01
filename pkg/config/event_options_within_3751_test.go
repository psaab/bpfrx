package config

import (
	"strings"
	"testing"
)

// Tests for #3751: event-options `within <seconds> { trigger (on|until)
// <count>; }` numeric validation. Before the fix compileEventOptions dropped
// the strconv.Atoi error and coerced a typo to 0, and the engine treated a 0
// threshold as an unconditional match — a typo silently turned a
// threshold-gated remediation into an ALWAYS-FIRE one (fail-open). The strict
// commit path (CompileConfig) now hard-rejects a bad within/trigger numeric,
// a within with no trigger, an unknown trigger keyword, and a within carrying
// both `on` and `until`; the tolerant load path (CompileConfigLenient) warns.
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath, never NewParser
// (the parser merges newline-separated set lines into one giant node).

// buildEventWithinFlat builds a config tree from flat `set ...` lines.
func buildEventWithinFlat(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		keys, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(keys); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestEventWithinValidAcceptedAtCommit proves a well-formed within/trigger
// clause still commits — both trigger on and trigger until, in both AST
// shapes. This is the guard that the new strict gate is not over-rejecting.
func TestEventWithinValidAcceptedAtCommit(t *testing.T) {
	// Hierarchical (NewParser) — two clauses, on and until, in range.
	hier := `event-options {
    policy P {
        events ping_test_failed;
        within 30 {
            trigger on 3;
        }
        within 25 {
            trigger until 4;
        }
    }
}`
	p := NewParser(hier)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a valid hierarchical within/trigger: %v", err)
	}

	// Flat set — on and until.
	for _, trig := range []string{"trigger on 3", "trigger until 4"} {
		flat := buildEventWithinFlat(t,
			"set event-options policy P within 60 "+trig,
		)
		if _, err := CompileConfig(flat); err != nil {
			t.Fatalf("CompileConfig rejected a valid flat within 60 %s: %v", trig, err)
		}
	}
}

// TestEventWithinRejectedAtCommit is the RED-on-revert core: every malformed
// within/trigger numeric must be a strict-commit hard error. Reverting the
// gate (validateEventOptionsWithinAST) makes CompileConfig ACCEPT these
// (coercing the value to 0), so every subtest goes RED.
func TestEventWithinRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		// substrings the error must contain (policy name + a value/keyword)
		want []string
	}{
		{
			// H11 — non-numeric within seconds.
			name: "within non-numeric",
			cmds: []string{"set event-options policy P within bogus trigger on 3"},
			want: []string{"P", "bogus", "time-interval"},
		},
		{
			// H11 — non-numeric trigger count.
			name: "trigger count non-numeric",
			cmds: []string{"set event-options policy P within 60 trigger on typo"},
			want: []string{"P", "typo", "on"},
		},
		{
			// H12 — negative within.
			name: "within negative",
			cmds: []string{"set event-options policy P within -5 trigger on 3"},
			want: []string{"P", "time-interval", "range"},
		},
		{
			// zero within (a 0 window is the coerced-typo value itself).
			name: "within zero",
			cmds: []string{"set event-options policy P within 0 trigger on 3"},
			want: []string{"P", "range"},
		},
		{
			// H12 — huge within (past the 86400 cap / duration-overflow guard).
			name: "within huge",
			cmds: []string{"set event-options policy P within 99999999999 trigger on 3"},
			want: []string{"P", "range"},
		},
		{
			// zero trigger count.
			name: "trigger count zero",
			cmds: []string{"set event-options policy P within 60 trigger on 0"},
			want: []string{"P", "on", "range"},
		},
		{
			// negative trigger count.
			name: "trigger count negative",
			cmds: []string{"set event-options policy P within 60 trigger until -1"},
			want: []string{"P", "until", "range"},
		},
		{
			// within clause with no trigger — gates nothing → fail-open.
			name: "within no trigger",
			cmds: []string{"set event-options policy P within 60"},
			want: []string{"P", "trigger"},
		},
		{
			// unknown trigger keyword (Junos `after` — unsupported here).
			name: "trigger unknown keyword",
			cmds: []string{"set event-options policy P within 60 trigger after 3"},
			want: []string{"P", "after"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildEventWithinFlat(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a malformed within/trigger (%v); want a strict reject", tc.cmds)
			}
			for _, sub := range tc.want {
				if !strings.Contains(err.Error(), sub) {
					t.Fatalf("reject error %q missing expected substring %q", err.Error(), sub)
				}
			}
		})
	}
}

// TestEventWithinBothOnUntilRejected is H13: a single within clause carrying
// BOTH trigger on and trigger until is contradictory (the engine ANDs them
// into a narrow one-count band). Strict commit must reject it. Tested in both
// AST shapes.
func TestEventWithinBothOnUntilRejected(t *testing.T) {
	// Flat set — trigger on 3 then trigger until 5 land as sibling children.
	flat := buildEventWithinFlat(t,
		"set event-options policy P within 60 trigger on 3",
		"set event-options policy P within 60 trigger until 5",
	)
	_, err := CompileConfig(flat)
	if err == nil {
		t.Fatal("CompileConfig accepted a within clause with both trigger on and until; want reject (H13)")
	}
	for _, sub := range []string{"P", "on", "until"} {
		if !strings.Contains(err.Error(), sub) {
			t.Fatalf("H13 reject error %q missing %q", err.Error(), sub)
		}
	}

	// Hierarchical — trigger on 3 until 5 collapse onto one trigger leaf.
	hier := `event-options {
    policy P {
        within 60 {
            trigger on 3 until 5;
        }
    }
}`
	p := NewParser(hier)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted hierarchical trigger on N until M; want reject (H13)")
	}
}

// TestEventWithinLenientDowngradesToWarning proves the tolerant load /
// peer-sync path (CompileConfigLenient) does NOT reject a malformed clause an
// older binary may have persisted — it downgrades to a cfg.Warnings entry so
// the node still boots (#1960 fail-closed-on-load doctrine). The engine then
// fails CLOSED on the leftover 0 threshold (TestWithin_ZeroThreshold_...).
func TestEventWithinLenientDowngradesToWarning(t *testing.T) {
	tree := buildEventWithinFlat(t,
		"set event-options policy P within bogus trigger on 3",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a malformed within on the tolerant path: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "within") && strings.Contains(w, "P") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient path did not emit a within warning; warnings=%v", cfg.Warnings)
	}
}
