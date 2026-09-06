package config

import (
	"strings"
	"testing"
)

// #8971 item 2: a trailing token on a `then` action was SILENTLY DISCARDED.
//
//	then { count c1 c2; }      count="c1"       c2 DISCARDED, warnings=0
//	then { dscp af11 af21; }   dscp="af11"      af21 DISCARDED
//	then { accept extra1; }    action="accept"  extra1 DISCARDED
//
// Each arm of the children walk reads `child.Keys[1]` and ignores `Keys[2:]`.
// The LEAF path already recorded an unrecognised token in UnknownActions
// (#2399) precisely so the strict gate could refuse the typo — so which
// behaviour the operator got depended on which SPELLING they used, which is the
// asymmetry this closes.
func TestThenActionTrailingTokenIsRefused8971(t *testing.T) {
	compile := func(t *testing.T, body string) (*ConfigTree, error) {
		t.Helper()
		root, perrs := NewParser(`firewall { family inet { filter F { term t1 { ` + body + ` } } } }`).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		tr := &ConfigTree{Children: root.Children}
		_, err := CompileConfig(tr)
		return tr, err
	}
	for _, tc := range []struct {
		name       string
		body       string
		wantRefuse bool
		token      string
	}{
		// THE DEFECT, at an args:1 action and at an args:0 one.
		{"count with a trailing token", "then { count c1 c2; }", true, "c2"},
		{"dscp with a trailing token", "then { dscp af11 af21; } then { accept; }", true, "af21"},
		{"accept with a trailing token", "then { accept extra1; }", true, "extra1"},

		// CONTROLS. Over-refusing here would reject ordinary filters, and each
		// of these is a spelling the tree tests elsewhere.
		{"count then accept", "then { count c1; accept; }", false, ""},
		{"dscp then accept", "then { dscp af11; accept; }", false, ""},
		// The #9153 packed run must still compile: that fix SPLITS the run into
		// separate actions, so nothing here is a trailing token.
		{"a packed run (#9153)", "then count c1 log discard;", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := compile(t, tc.body)
			if (err != nil) != tc.wantRefuse {
				t.Fatalf("refused=%v, want %v (err=%v)", err != nil, tc.wantRefuse, err)
			}
			if !tc.wantRefuse {
				return
			}
			// The refusal must NAME the token. "unknown action" without it
			// sends the operator to re-read a line that is mostly correct.
			if !strings.Contains(err.Error(), tc.token) {
				t.Errorf("the refusal does not name %q: %v", tc.token, err)
			}
			// #1960: the tolerant path warns rather than refusing, and the
			// warning is what tells the operator about an already-persisted one.
			lc, lerr := CompileConfigLenient(tr)
			if lerr != nil {
				t.Fatalf("the LENIENT path rejected — a persisted config would fail to load: %v", lerr)
			}
			if len(lc.Warnings) == 0 {
				t.Error("the lenient path accepted the trailing token with NO warning — silent " +
					"is the state #8971 is about")
			}
		})
	}
}

// TestThenActionArityComesFromTheSchema8971 pins that the arity is READ rather
// than listed. A hand-kept list of `then` actions and their arities would be a
// second place to remember, and the first thing anyone would forget when adding
// an action.
func TestThenActionArityComesFromTheSchema8971(t *testing.T) {
	then := filterThenSchema8971()
	if then == nil || len(then.children) == 0 {
		t.Fatal("the `then` schema did not resolve — thenActionExtras8971 then reports nothing " +
			"for every action, and every row above would pass vacuously")
	}
	// Spot-check both arities the walk depends on, so a schema change that
	// flips one is visible here rather than as a mysterious acceptance.
	for name, wantArgs := range map[string]int{
		"accept": 0, "discard": 0, "log": 0,
		"count": 1, "dscp": 1, "policer": 1,
	} {
		act := resolveSchemaChild(then, name)
		if act == nil {
			t.Errorf("`then %s` is not declared", name)
			continue
		}
		if act.args != wantArgs {
			t.Errorf("`then %s` args = %d, want %d — the extras scan starts at 1+args, so this "+
				"changes which tokens are reported", name, act.args, wantArgs)
		}
	}
}
