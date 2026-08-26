package ipsec

import (
	"fmt"
	"strings"
	"testing"
)

// swanctl_doc_selftest_6824_test.go -- #6824.
//
// The structural checker is only worth having if it FAILS on the shapes a
// containment assertion cannot see. These are its own tests: each feeds a
// document that `strings.Contains` would accept and requires the checker to
// reject it.
//
// Without these, a parser bug turns every structural assertion built on it into
// a vacuous pass -- the instrument-that-cannot-fail problem, one layer down.

// capturingTB records the checker's failures instead of failing the suite.
//
// Fatalf must ABORT, as *testing.T's does, or a checker that Fatalf's and then
// continues would exercise code paths the real one never reaches -- so it panics
// with a sentinel that checkerRejects recovers.
type capturingTB struct{ msgs []string }

type swanctlFatal struct{}

func (c *capturingTB) Helper() {}
func (c *capturingTB) Errorf(format string, args ...any) {
	c.msgs = append(c.msgs, fmt.Sprintf(format, args...))
}
func (c *capturingTB) Fatalf(format string, args ...any) {
	c.msgs = append(c.msgs, fmt.Sprintf(format, args...))
	panic(swanctlFatal{})
}

// checkerRejects drives the checker over doc and reports whether it complained,
// along with what it said.
func checkerRejects(doc string, body func(swanctlTB, *swanctlNode)) (bool, string) {
	tb := &capturingTB{}
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(swanctlFatal); !ok {
					panic(r)
				}
			}
		}()
		root := parseSwanctlDoc(tb, doc)
		if body != nil {
			body(tb, root)
		}
	}()
	return len(tb.msgs) > 0, strings.Join(tb.msgs, "; ")
}

// TestStructuralCheckerCatchesWhatContainmentCannot_6824 is the sensitivity
// suite, and every case is chosen because `strings.Contains` accepts it.
func TestStructuralCheckerCatchesWhatContainmentCannot_6824(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		why  string
	}{
		{
			name: "unbalanced-open-section",
			doc:  "connections {\n  tun {\n    remote_addrs = 203.0.113.1\n",
			why:  "a truncated render leaves sections open; Contains still finds the address",
		},
		{
			name: "closing-brace-with-nothing-open",
			doc:  "connections {\n}\n}\n",
			why:  "an extra close silently reparents everything after it",
		},
		{
			name: "duplicate-section-under-one-parent",
			doc:  "connections {\n  tun {\n    remote_addrs = 1.1.1.1\n  }\n  tun {\n    remote_addrs = 2.2.2.2\n  }\n}\n",
			why:  "two sections with one name: one wins, the other is lost, Contains sees both",
		},
		{
			name: "unrecognised-line-shape",
			doc:  "connections {\n  tun {\n    this is not a setting\n  }\n}\n",
			why:  "a shape no structural test describes must fail rather than be skipped",
		},
		{
			name: "empty-section-name",
			doc:  "connections {\n   {\n  }\n}\n",
			why:  "a section opened with no name is a render bug, not a nesting level",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rejected, why := checkerRejects(c.doc, nil)
			if !rejected {
				t.Errorf("the checker ACCEPTED %s -- %s", c.name, c.why)
			} else {
				t.Logf("rejected as expected: %s", why)
			}
		})
	}
}

// TestStructuralCheckerCatchesADuplicateSetting_6824 is separated because it
// fires from setting() rather than from the parse, and it is the single case
// most invisible to containment: the key is present, twice.
func TestStructuralCheckerCatchesADuplicateSetting_6824(t *testing.T) {
	// Duplicate rejection is claimed as a PARSE invariant, so it must fire
	// without setting() being called at all -- otherwise a path-only test stays
	// green on a document with a duplicated, unqueried key.
	dupOnly := "connections {\n  tun {\n    remote_addrs = 1.1.1.1\n    remote_addrs = 2.2.2.2\n  }\n}\n"
	if rejected, _ := checkerRejects(dupOnly, nil); !rejected {
		t.Error("parsing alone accepted a duplicated setting; the invariant is only " +
			"enforced when setting() happens to be called, which a path-only test does not do")
	}

	doc := "connections {\n  tun {\n    remote_addrs = 1.1.1.1\n    remote_addrs = 2.2.2.2\n  }\n}\n"
	if !strings.Contains(doc, "remote_addrs = 1.1.1.1") {
		t.Fatal("fixture does not contain the value a containment assertion would look for")
	}
	rejected, why := checkerRejects(doc, func(tb swanctlTB, root *swanctlNode) {
		root.at(tb, "connections", "tun").setting(tb, "remote_addrs")
	})
	if !rejected {
		t.Error("the checker accepted a section declaring remote_addrs twice; a " +
			"containment assertion accepts it too, which is the point")
	} else {
		t.Logf("rejected as expected: %s", why)
	}
}

// TestStructuralCheckerAcceptsAWellFormedDocument_6824 is the paired positive
// control. Without it, every cell above is satisfied by a checker that rejects
// EVERYTHING -- which would be useless in the opposite direction and would look
// identical in a pass/fail table.
func TestStructuralCheckerAcceptsAWellFormedDocument_6824(t *testing.T) {
	doc := "# comment\n\nconnections {\n  tun {\n    remote_addrs = 203.0.113.1\n" +
		"    local {\n      auth = psk\n    }\n  }\n}\n"
	root := parseSwanctlDoc(t, doc)
	tun := root.at(t, "connections", "tun")
	if got := tun.setting(t, "remote_addrs"); got != "203.0.113.1" {
		t.Errorf("remote_addrs = %q, want 203.0.113.1", got)
	}
	if got := tun.at(t, "local").setting(t, "auth"); got != "psk" {
		t.Errorf("local.auth = %q, want psk", got)
	}
	// And the nesting is real: auth belongs to `local`, not to `tun`.
	tun.hasNoSetting(t, "auth")
}

// TestStructuralCheckerDistinguishesNestingFromContainment_6824 is the argument
// for this whole file, expressed as a test.
//
// Both documents contain the byte sequence `remote_addrs = 203.0.113.1`, so a
// containment assertion cannot tell them apart. In the second, the setting sits
// under the WRONG connection -- the render bug the old assertions were blind to.
func TestStructuralCheckerDistinguishesNestingFromContainment_6824(t *testing.T) {
	const want = "remote_addrs = 203.0.113.1"
	right := "connections {\n  tun {\n    " + want + "\n  }\n  other {\n  }\n}\n"
	wrong := "connections {\n  tun {\n  }\n  other {\n    " + want + "\n  }\n}\n"

	if !strings.Contains(right, want) || !strings.Contains(wrong, want) {
		t.Fatal("both fixtures must satisfy containment, or the comparison is not the one being made")
	}

	if got := parseSwanctlDoc(t, right).at(t, "connections", "tun").setting(t, "remote_addrs"); got != "203.0.113.1" {
		t.Fatalf("correctly-nested document: got %q", got)
	}
	rejected, why := checkerRejects(wrong, func(tb swanctlTB, root *swanctlNode) {
		root.at(tb, "connections", "tun").setting(tb, "remote_addrs")
	})
	if !rejected {
		t.Error("the checker accepted remote_addrs nested under the WRONG connection; " +
			"that is exactly the class strings.Contains cannot see")
	} else {
		t.Logf("rejected as expected: %s", why)
	}
}

// TestStructuralCheckerRefusesAmbiguousShapes_6824 is the cancellation case,
// and it went through two wrong answers before this one.
//
// Two line shapes cannot be told apart from the line alone: one starting '#'
// and ending '{', and one containing '=' and ending '{'. The first version of
// the parser GUESSED at each, and the guesses cancelled -- a fake open from one
// closed by a real brace from the other, leaving a balanced document and a tree
// missing a section the renderer emitted.
//
// The second version guessed BETTER (a section opener carries no '='; a comment
// is neither a section nor a setting) and was still wrong, because reversing
// which half is misread reproduces the cancellation exactly:
//
//	connections {
//	  # metadata {          <- read as a section, since it ends in a brace
//	  vpn=prod {            <- read as a setting, since it contains '='
//	    remote_addrs = 1.1.1.1
//	  }
//	}
//
// A parser that guesses can cancel its guesses. A parser that REFUSES cannot,
// which is why both shapes are now hard failures. Neither is reachable from
// this renderer, so refusing costs nothing and removes the whole class.
func TestStructuralCheckerRefusesAmbiguousShapes_6824(t *testing.T) {
	for _, c := range []struct{ name, doc, why string }{
		{
			name: "setting whose value ends in a brace",
			doc:  "connections {\n  a {\n    local_ts = 10.0.0.0/24 {\n  }\n}\n",
			why:  "section-or-setting",
		},
		{
			name: "comment that also opens a section",
			doc:  "connections {\n  # metadata {\n}\n",
			why:  "comment-or-section",
		},
		{
			name: "the CANCELLING pair, in the order that defeated the second version",
			doc: "connections {\n  # metadata {\n  vpn=prod {\n" +
				"    remote_addrs = 1.1.1.1\n  }\n}\n",
			why: "both halves together: the braces balance, so only a refusal catches it",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			rejected, why := checkerRejects(c.doc, nil)
			if !rejected {
				t.Errorf("the checker ACCEPTED an ambiguous shape (%s). Guessing at these "+
					"is how two misreads cancel into a balanced document with a wrong "+
					"tree.", c.why)
			} else {
				t.Logf("refused as expected: %s", why)
			}
		})
	}

	// PAIRED CONTROL. The refusals above are satisfied by a parser that rejects
	// everything, which would be useless in the other direction and identical
	// in a pass/fail table. An ordinary comment and an ordinary section must
	// still parse.
	root := parseSwanctlDoc(t, "# xpf managed config - do not edit\n\nconnections {\n"+
		"  tun {\n    remote_addrs = 203.0.113.1\n  }\n}\n")
	root.at(t, "connections", "tun").requireSetting(t, "remote_addrs", "203.0.113.1")
	if names := root.childNames(); len(names) != 1 {
		t.Errorf("top-level sections = %v, want exactly [connections]; the refusals must "+
			"not turn an ordinary comment into a section", names)
	}
}
