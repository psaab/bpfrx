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
