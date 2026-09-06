// #9065: the semantics of the shared modifier/selector split.
//
// These are UNIT cells on purpose. The integration gate in cmd/cli binds the
// WIRING — that each dispatcher calls this rather than re-deriving a positional
// ladder — and it is the right shape for that. It is the WRONG shape for the
// helper's own semantics: measured, breaking this function so that no word is
// ever a modifier (or none is ever a selector) makes every affected command
// fall into its "unexpected argument" arm, and a gate whose predicate is
// "carried OR refused" scores that as a clean board. Both mutations SURVIVED
// the integration gate and are killed here.
//
// That is the general lesson and it is why these live in this package: a
// shared helper's contract is guarded where the helper is, not by hoping a
// downstream integration notices.

package cmdtree

import (
	"reflect"
	"testing"
)

func splitFixture9065() map[string]*Node {
	return map[string]*Node{
		"detail":    {Desc: "detail"},
		"extensive": {Desc: "extensive"},
		"terse":     {Desc: "terse"},
	}
}

func TestSplitModifiersIsPositionIndependent9065(t *testing.T) {
	children := splitFixture9065()
	for _, tc := range []struct {
		name string
		args []string
	}{
		// The whole point: the same command in either order must split the
		// same way. A positional ladder is exactly what cannot do this, and it
		// is the defect class #9065 closes.
		{"selector first", []string{"ge-0/0/1", "detail"}},
		{"modifier first", []string{"detail", "ge-0/0/1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SplitModifiers(children, tc.args)
			if got.Selector != "ge-0/0/1" {
				t.Errorf("Selector = %q, want %q — a non-keyword word is the operator's "+
					"value wherever it sits", got.Selector, "ge-0/0/1")
			}
			if !reflect.DeepEqual(got.Modifiers, []string{"detail"}) {
				t.Errorf("Modifiers = %v, want [detail]", got.Modifiers)
			}
			if len(got.Extra) != 0 {
				t.Errorf("Extra = %v, want none", got.Extra)
			}
		})
	}
}

// A declared keyword must NEVER be bound as the selector. This is the half
// that made `show interfaces ge-0/0/1 extensive` send Filter="extensive".
func TestSplitModifiersNeverBindsAKeywordAsSelector9065(t *testing.T) {
	got := SplitModifiers(splitFixture9065(), []string{"detail", "terse"})
	if got.Selector != "" {
		t.Fatalf("Selector = %q: every word given is a declared keyword, so there is "+
			"no selector. Binding one is how a modifier overwrote an interface name.",
			got.Selector)
	}
	if len(got.Modifiers) != 2 {
		t.Fatalf("Modifiers = %v, want both keywords", got.Modifiers)
	}
}

// And the inverse half: a non-keyword must never be silently swallowed as a
// modifier. Without this, breaking the split so that everything is a modifier
// would drop the operator's value with no trace.
func TestSplitModifiersNeverDropsAValue9065(t *testing.T) {
	got := SplitModifiers(splitFixture9065(), []string{"ge-0/0/1"})
	if got.Selector != "ge-0/0/1" {
		t.Fatalf("a lone non-keyword must be the Selector; got Selector=%q Modifiers=%v",
			got.Selector, got.Modifiers)
	}
	if len(got.Modifiers) != 0 {
		t.Fatalf("a non-keyword must not become a modifier; got %v", got.Modifiers)
	}
}

// A SECOND value goes to Extra rather than replacing the first. Silently
// overwriting is the exact shape of the bug: the last word won and the
// operator was told nothing.
func TestSplitModifiersSecondValueIsReported9065(t *testing.T) {
	got := SplitModifiers(splitFixture9065(), []string{"ge-0/0/1", "ge-0/0/2", "detail"})
	if got.Selector != "ge-0/0/1" {
		t.Errorf("Selector = %q, want the FIRST value", got.Selector)
	}
	if !reflect.DeepEqual(got.Extra, []string{"ge-0/0/2"}) {
		t.Errorf("Extra = %v, want [ge-0/0/2] — a second value must be reported so the "+
			"caller can refuse, not silently discarded", got.Extra)
	}
}

// An abbreviation resolves to the CANONICAL modifier, because operators
// abbreviate and the rest of the tree lets them.
func TestSplitModifiersResolvesAbbreviations9065(t *testing.T) {
	got := SplitModifiers(splitFixture9065(), []string{"ge-0/0/1", "det"})
	if !reflect.DeepEqual(got.Modifiers, []string{"detail"}) {
		t.Fatalf("Modifiers = %v, want [detail] — `det` is an unambiguous prefix",
			got.Modifiers)
	}
	if got.Selector != "ge-0/0/1" {
		t.Fatalf("Selector = %q, want ge-0/0/1", got.Selector)
	}
}

// An AMBIGUOUS abbreviation is neither a modifier nor a selector. Treating it
// as a selector would bind `show security zones det` to a zone named "det" —
// the silent mis-binding this file exists to prevent.
func TestSplitModifiersReportsAmbiguity9065(t *testing.T) {
	children := map[string]*Node{"detail": {}, "destination": {}}
	got := SplitModifiers(children, []string{"de"})
	if !reflect.DeepEqual(got.Ambiguous, []string{"de"}) {
		t.Fatalf("Ambiguous = %v, want [de]", got.Ambiguous)
	}
	if got.Selector != "" {
		t.Fatalf("an ambiguous keyword must NOT become the selector; got %q", got.Selector)
	}
}

// SplitModifiersAt resolves a real tree path, and reports a bad path rather
// than returning an empty split a caller might read as "no modifiers".
func TestSplitModifiersAtPathResolution9065(t *testing.T) {
	got, ok := SplitModifiersAt([]string{"show", "interfaces"}, []string{"ge-0/0/1", "detail"})
	if !ok {
		t.Fatal("`show interfaces` must resolve in the operational tree")
	}
	if got.Selector != "ge-0/0/1" || !got.Has("detail") {
		t.Fatalf("split = %+v, want selector ge-0/0/1 with modifier detail", got)
	}
	if _, ok := SplitModifiersAt([]string{"show", "nosuchnode"}, nil); ok {
		t.Fatal("an unknown path must report ok=false, not an empty split — a caller " +
			"that read the empty split as `no modifiers` would reinstate the bug")
	}
}
