package config

import (
	"fmt"
	"strings"
	"testing"
)

// #6697 — every CoS `code-points` reader read the leaf node's own tail and
// never its CHILDREN, so the hierarchical BLOCK spelling
//
//	loss-priority low { code-points { ef; af11; } }
//
// compiled to NOTHING. Not a truncated list: the compiler stores a classifier
// only when it has at least one entry, so the whole classifier went missing
// while `show class-of-service` rendered the authored config back intact and
// the interface binding succeeded.
//
// That distinction is why every assertion below separates PRESENT-with-N-values
// from ABSENT. A test that only asserted "the entry has 2 code points" would
// pass vacuously against a classifier that never compiled at all — the exact
// shape that let this hide, and the reason the issue's own count was wrong
// twice before it was measured.
//
// The five families this reaches (the issue title names two):
//
//	classifiers   dscp / ieee-802.1 / inet-precedence   -> a LIST of code points
//	rewrite-rules dscp / ieee-802.1                     -> ONE code point
//
// The rewrite direction writes exactly one code point per (forwarding-class,
// loss-priority) entry, so its assertion is the scalar value, not a list. Its
// `code-points` leaf is an accepted ALIAS of the Junos `code-point` leaf; both
// spellings are covered, including the inline `loss-priority low code-point
// ef;` form Junos itself emits, which compiled to nothing before this fix.

// cpFamily describes one code-point-bearing CoS family: how to author it and
// how to read back what compiled.
type cpFamily struct {
	name string
	// stanza renders `class-of-service { ... }` around a loss-priority body.
	stanza func(body string) string
	// setPath is the flat-set prefix up to and including the loss-priority.
	setPath string
	// leaf is the code-point leaf keyword (`code-points`, or `code-point` for
	// the scalar rewrite spelling).
	leaf string
	// read returns the compiled code points and whether the rule/classifier
	// compiled AT ALL. The two are reported separately on purpose.
	read func(cfg *Config) (values []uint8, present bool)
	v1   uint8
	v2   uint8
	t1   string
	t2   string
}

func cpClassifierStanza(family string) func(string) string {
	return func(body string) string {
		return fmt.Sprintf(
			"class-of-service { classifiers { %s cp-cl { forwarding-class voice { loss-priority low %s } } } }",
			family, body)
	}
}

func cpRewriteStanza(family string) func(string) string {
	return func(body string) string {
		return fmt.Sprintf(
			"class-of-service { rewrite-rules { %s cp-rw { forwarding-class voice { loss-priority low %s } } } }",
			family, body)
	}
}

func cpFamilies() []cpFamily {
	return []cpFamily{
		{
			name:    "classifiers dscp",
			stanza:  cpClassifierStanza("dscp"),
			setPath: "class-of-service classifiers dscp cp-cl forwarding-class voice loss-priority low",
			leaf:    "code-points",
			t1:      "ef", t2: "af11", v1: 46, v2: 10,
			read: func(cfg *Config) ([]uint8, bool) {
				c := cfg.ClassOfService.DSCPClassifiers["cp-cl"]
				if c == nil || len(c.Entries) == 0 {
					return nil, false
				}
				return c.Entries[0].DSCPValues, true
			},
		},
		{
			name:    "classifiers ieee-802.1",
			stanza:  cpClassifierStanza("ieee-802.1"),
			setPath: "class-of-service classifiers ieee-802.1 cp-cl forwarding-class voice loss-priority low",
			leaf:    "code-points",
			t1:      "3", t2: "5", v1: 3, v2: 5,
			read: func(cfg *Config) ([]uint8, bool) {
				c := cfg.ClassOfService.IEEE8021Classifiers["cp-cl"]
				if c == nil || len(c.Entries) == 0 {
					return nil, false
				}
				return c.Entries[0].CodePoints, true
			},
		},
		{
			name:    "classifiers inet-precedence",
			stanza:  cpClassifierStanza("inet-precedence"),
			setPath: "class-of-service classifiers inet-precedence cp-cl forwarding-class voice loss-priority low",
			leaf:    "code-points",
			t1:      "3", t2: "5", v1: 3, v2: 5,
			read: func(cfg *Config) ([]uint8, bool) {
				c := cfg.ClassOfService.INetPrecedenceClassifierDefs["cp-cl"]
				if c == nil || len(c.Entries) == 0 {
					return nil, false
				}
				return c.Entries[0].Precedences, true
			},
		},
		{
			name:    "rewrite-rules dscp code-points",
			stanza:  cpRewriteStanza("dscp"),
			setPath: "class-of-service rewrite-rules dscp cp-rw forwarding-class voice loss-priority low",
			leaf:    "code-points",
			t1:      "ef", t2: "af11", v1: 46, v2: 10,
			read: func(cfg *Config) ([]uint8, bool) {
				r := cfg.ClassOfService.DSCPRewriteRules["cp-rw"]
				if r == nil || len(r.Entries) == 0 {
					return nil, false
				}
				return []uint8{r.Entries[0].DSCPValue}, true
			},
		},
		{
			name:    "rewrite-rules dscp code-point",
			stanza:  cpRewriteStanza("dscp"),
			setPath: "class-of-service rewrite-rules dscp cp-rw forwarding-class voice loss-priority low",
			leaf:    "code-point",
			t1:      "ef", t2: "af11", v1: 46, v2: 10,
			read: func(cfg *Config) ([]uint8, bool) {
				r := cfg.ClassOfService.DSCPRewriteRules["cp-rw"]
				if r == nil || len(r.Entries) == 0 {
					return nil, false
				}
				return []uint8{r.Entries[0].DSCPValue}, true
			},
		},
		{
			name:    "rewrite-rules ieee-802.1 code-points",
			stanza:  cpRewriteStanza("ieee-802.1"),
			setPath: "class-of-service rewrite-rules ieee-802.1 cp-rw forwarding-class voice loss-priority low",
			leaf:    "code-points",
			t1:      "3", t2: "5", v1: 3, v2: 5,
			read: func(cfg *Config) ([]uint8, bool) {
				r := cfg.ClassOfService.IEEE8021RewriteRules["cp-rw"]
				if r == nil || len(r.Entries) == 0 {
					return nil, false
				}
				return []uint8{r.Entries[0].PCPValue}, true
			},
		},
		{
			name:    "rewrite-rules ieee-802.1 code-point",
			stanza:  cpRewriteStanza("ieee-802.1"),
			setPath: "class-of-service rewrite-rules ieee-802.1 cp-rw forwarding-class voice loss-priority low",
			leaf:    "code-point",
			t1:      "3", t2: "5", v1: 3, v2: 5,
			read: func(cfg *Config) ([]uint8, bool) {
				r := cfg.ClassOfService.IEEE8021RewriteRules["cp-rw"]
				if r == nil || len(r.Entries) == 0 {
					return nil, false
				}
				return []uint8{r.Entries[0].PCPValue}, true
			},
		},
	}
}

// isRewrite reports whether a family installs ONE code point rather than a list.
func (f cpFamily) isRewrite() bool { return strings.HasPrefix(f.name, "rewrite-rules") }

// cpForwardingClasses defines the forwarding class every stanza references, so
// a missing entry is never explained away by an undefined-reference warning.
const cpForwardingClasses = "class-of-service { forwarding-classes { queue 5 voice; } }"

func cpCompileHier(t *testing.T, stanza string) *Config {
	t.Helper()
	p := NewParser(cpForwardingClasses + "\n" + stanza)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", stanza, errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile %q: %v", stanza, err)
	}
	return cfg
}

func cpCompileSetCmds(t *testing.T, cmds []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range append([]string{"set class-of-service forwarding-classes queue 5 voice"}, cmds...) {
		path, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile %v: %v", cmds, err)
	}
	return cfg
}

// cpCheck is the assertion every case funnels through. It reports ABSENT and
// WRONG-VALUES as distinct failures: "the classifier compiled with the wrong
// code points" and "no classifier compiled at all" are different defects and
// the #6697 one is the second.
func cpCheck(t *testing.T, what string, cfg *Config, f cpFamily, want []uint8) {
	t.Helper()
	got, present := f.read(cfg)
	if !present {
		t.Fatalf("%s: %s compiled NO rule at all — the whole classifier/rewrite-rule is absent, "+
			"not merely missing a code point (want %v)", what, f.name, want)
	}
	if len(got) != len(want) {
		t.Fatalf("%s: %s compiled %d code point(s) %v, want %d %v",
			what, f.name, len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: %s compiled code points %v, want %v", what, f.name, got, want)
		}
	}
}

// TestCoSCodePointsCompileIdenticallyInEverySpelling authors the same code
// points in each of the five spellings the Junos grammar admits and requires
// the same compiled result from all of them.
//
// The ONE-value row is not redundant with the TWO-value row: it localises a
// regression. A reader that reads no children reds only the block rows; a
// reader that keeps just the first value reds only the two-value rows.
func TestCoSCodePointsCompileIdenticallyInEverySpelling(t *testing.T) {
	for _, f := range cpFamilies() {
		f := f
		t.Run(strings.NewReplacer(" ", "_", ".", "").Replace(f.name), func(t *testing.T) {
			// A rewrite-rule entry installs exactly ONE code point, so its
			// two-value expectation stays the FIRST value; a classifier
			// accumulates both.
			wantOne := []uint8{f.v1}
			wantTwo := []uint8{f.v1, f.v2}
			if f.isRewrite() {
				wantTwo = []uint8{f.v1}
			}

			cpCheck(t, "A-hier-bracket x1", cpCompileHier(t,
				f.stanza(fmt.Sprintf("{ %s [ %s ]; }", f.leaf, f.t1))), f, wantOne)
			cpCheck(t, "A-hier-bracket x2", cpCompileHier(t,
				f.stanza(fmt.Sprintf("{ %s [ %s %s ]; }", f.leaf, f.t1, f.t2))), f, wantTwo)

			// B — the hierarchical BLOCK spelling. This is the #6697 defect:
			// before the fix BOTH of these compiled nothing at all.
			cpCheck(t, "B-hier-block x1", cpCompileHier(t,
				f.stanza(fmt.Sprintf("{ %s { %s; } }", f.leaf, f.t1))), f, wantOne)
			cpCheck(t, "B-hier-block x2", cpCompileHier(t,
				f.stanza(fmt.Sprintf("{ %s { %s; %s; } }", f.leaf, f.t1, f.t2))), f, wantTwo)

			cpCheck(t, "C-hier-repeat x1", cpCompileHier(t,
				f.stanza(fmt.Sprintf("{ %s %s; }", f.leaf, f.t1))), f, wantOne)
			cpCheck(t, "C-hier-repeat x2", cpCompileHier(t,
				f.stanza(fmt.Sprintf("{ %s %s; %s %s; }", f.leaf, f.t1, f.leaf, f.t2))), f, wantTwo)

			// F — the inline spelling Junos itself emits, with the code point on
			// the loss-priority statement rather than in a block (#1809). The
			// two rewrite readers missed this one as well, so the canonical
			// `loss-priority low code-point ef;` compiled to nothing.
			cpCheck(t, "F-hier-inline x1", cpCompileHier(t,
				f.stanza(fmt.Sprintf("%s %s;", f.leaf, f.t1))), f, wantOne)

			cpCheck(t, "D-set-bracket x1", cpCompileSetCmds(t,
				[]string{fmt.Sprintf("set %s %s [ %s ]", f.setPath, f.leaf, f.t1)}), f, wantOne)
			cpCheck(t, "D-set-bracket x2", cpCompileSetCmds(t,
				[]string{fmt.Sprintf("set %s %s [ %s %s ]", f.setPath, f.leaf, f.t1, f.t2)}), f, wantTwo)

			cpCheck(t, "E-set-repeat x1", cpCompileSetCmds(t,
				[]string{fmt.Sprintf("set %s %s %s", f.setPath, f.leaf, f.t1)}), f, wantOne)
			if !f.isRewrite() {
				// A repeated flat-set on a scalar leaf REPLACES (last write
				// wins), which is correct and not a code-point question.
				cpCheck(t, "E-set-repeat x2", cpCompileSetCmds(t, []string{
					fmt.Sprintf("set %s %s %s", f.setPath, f.leaf, f.t1),
					fmt.Sprintf("set %s %s %s", f.setPath, f.leaf, f.t2),
				}), f, wantTwo)
			}
		})
	}
}

// TestCoSCodePointsBlockSpellingRejectsInvalidTokens closes the GATE ESCAPE
// half of #6697. Each reader's per-value domain check lives on its read path,
// so a shape the reader did not look at was not merely dropped — it committed
// CLEAN. `code-points { totally-bogus; }` was accepted where the identical
// token in `code-points [ totally-bogus ]` was rejected.
//
// Each case is paired with the bracket spelling of the SAME token as a control,
// so an ACCEPT only counts as an escape beside a REJECT of the same value.
func TestCoSCodePointsBlockSpellingRejectsInvalidTokens(t *testing.T) {
	cases := []struct {
		name    string
		family  cpFamily
		token   string
		wantErr string
	}{
		{"dscp classifier typo", cpFamilies()[0], "totally-bogus", "not a valid DSCP alias"},
		{"dscp classifier out of range", cpFamilies()[0], "99", "out of range"},
		{"ieee classifier typo", cpFamilies()[1], "bogus", "not a valid 0..7 value"},
		{"ieee classifier out of range", cpFamilies()[1], "9", "out of range"},
		{"inet-precedence out of range", cpFamilies()[2], "9", "out of range"},
		{"dscp rewrite typo", cpFamilies()[3], "totally-bogus", "not a valid DSCP alias"},
		{"ieee rewrite out of range", cpFamilies()[5], "9", "out of range"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(strings.ReplaceAll(tc.name, " ", "_"), func(t *testing.T) {
			f := tc.family
			compile := func(body string) error {
				p := NewParser(cpForwardingClasses + "\n" + f.stanza(body))
				tree, errs := p.Parse()
				if len(errs) > 0 {
					t.Fatalf("parse %q: %v", body, errs)
				}
				_, err := CompileConfig(tree)
				return err
			}
			// Control: the bracket spelling must reject this token.
			bracketErr := compile(fmt.Sprintf("{ %s [ %s ]; }", f.leaf, tc.token))
			if bracketErr == nil {
				t.Fatalf("control failed: bracket spelling ACCEPTED %q for %s — "+
					"the block-spelling assertion below would be meaningless",
					tc.token, f.name)
			}
			if !strings.Contains(bracketErr.Error(), tc.wantErr) {
				t.Fatalf("control: bracket rejection for %q = %v, want it to contain %q",
					tc.token, bracketErr, tc.wantErr)
			}
			// The escape: the block spelling must reject it the same way.
			blockErr := compile(fmt.Sprintf("{ %s { %s; } }", f.leaf, tc.token))
			if blockErr == nil {
				t.Fatalf("GATE ESCAPE: block spelling %s { %s; } committed CLEAN for %s "+
					"while the bracket spelling rejected the same token (%v)",
					f.leaf, tc.token, f.name, bracketErr)
			}
			if !strings.Contains(blockErr.Error(), tc.wantErr) {
				t.Fatalf("block rejection for %q = %v, want it to contain %q",
					tc.token, blockErr, tc.wantErr)
			}
		})
	}
}
