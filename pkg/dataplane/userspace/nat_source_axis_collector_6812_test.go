package userspace

import (
	"reflect"
	"testing"
	"time"
)

// #6812 round 11: the collector's own probe.
//
// Round 10 claimed a two-way dichotomy — a field is SWEPT or it STOPS the test.
// A switch-for-switch probe found a third outcome, SILENTLY SKIPPED, in four
// field forms. These are those four forms, asserted directly rather than
// through a NAT fixture, because the property belongs to the collector and not
// to any one fixture.
//
// The fifth outcome, STOPS THE TEST, needs no case here: the kind switch ends
// in a `default` that calls t.Fatalf, so a kind the collector does not handle
// cannot be skipped — that is a property of the language, not of a list. The
// four below are the ones where a HANDLED kind used to emit a PARTIAL column,
// which is the dangerous shape: it reads as coverage.
func collectAxisColumns6812(t *testing.T, v any) map[string]string {
	t.Helper()
	out := map[string]string{}
	collectAxisKeys6812(t, "", reflect.ValueOf(v), true, 0, func(col, key string) {
		if _, dup := out[col]; dup {
			t.Fatalf("column %q emitted twice", col)
		}
		out[col] = key
	})
	return out
}

type axisProbeDeep6812 struct {
	Gamma string
}

type axisProbePointee6812 struct {
	Alpha  string
	Beta   int
	Deeper *axisProbeDeep6812
}

type axisProbePtr6812 struct {
	P *axisProbePointee6812
}

// TestCollectorEnumeratesANilPointeesFields_6812 is the case that matters,
// because it is the one round 10 claimed to close. Every fixture pointer being
// nil must not hide the pointee's fields: adding a field to a type no fixture
// ever populates has to produce a column, or "a new field cannot be silently
// omitted" is false.
func TestCollectorEnumeratesANilPointeesFields_6812(t *testing.T) {
	cols := collectAxisColumns6812(t, axisProbePtr6812{})
	for _, want := range []string{"P.nil", "P.Alpha", "P.Beta"} {
		if _, ok := cols[want]; !ok {
			t.Fatalf("a NIL pointer emitted no %q column (got %v). Round 10 emitted only "+
				"`.nil` here, so a field added to the pointee type changed nothing at all — "+
				"which is exactly the closure claim being false.", want, keysOf6812(cols))
		}
	}
	// The pointee's own columns must be ABSENT-tagged, not a fabricated zero:
	// an absent value and a present zero are different states.
	if got := cols["P.Alpha"]; got != axisAbsentKey6812 {
		t.Fatalf("nil pointee field key = %q, want the absent marker %q — a fabricated zero "+
			"would collide with a pointee that really carries the zero value",
			got, axisAbsentKey6812)
	}
	// TRANSITIVE, not one indirection deep (#6812 round 12). The schema walk
	// recurses through a nil pointee's OWN pointer fields, bounded only by the
	// depth cap, so a field added two indirections behind an always-nil gateway
	// still produces a column. What is NOT transitive is GUARDEDNESS: every
	// column under an absent gateway is constant, so each is a registered blind
	// spot. "A new field cannot be silently omitted" holds all the way down; "a
	// sort keyed through this pointer is guarded" holds nowhere below the
	// gateway.
	if _, ok := cols["P.Deeper.Gamma"]; !ok {
		t.Fatalf("the schema walk stopped at ONE indirection: no P.Deeper.Gamma column "+
			"(got %v). A field two pointers deep behind an always-nil gateway would then "+
			"be silently omitted.", keysOf6812(cols))
	}
	if _, ok := cols["P.Deeper.nil"]; !ok {
		t.Fatalf("no P.Deeper.nil gateway column (got %v)", keysOf6812(cols))
	}

	live := collectAxisColumns6812(t, axisProbePtr6812{P: &axisProbePointee6812{}})
	if live["P.Alpha"] == axisAbsentKey6812 {
		t.Fatal("a PRESENT pointee with a zero field encoded as absent; the two states must " +
			"be distinguishable or a nil-vs-zero sort is invisible")
	}
}

// TestCollectorSeesPastTheFirstSliceElement_6812: round 10 emitted `.len` and
// `[0]`, so a change to any later element was invisible. `.all` is total.
func TestCollectorSeesPastTheFirstSliceElement_6812(t *testing.T) {
	type probe struct{ B []byte }
	a := collectAxisColumns6812(t, probe{B: []byte{7, 1, 2}})
	b := collectAxisColumns6812(t, probe{B: []byte{7, 9, 2}})
	if a["B.len"] != b["B.len"] || a["B[0]"] != b["B[0]"] {
		t.Fatal("probe is malformed: the two byte slices must agree on length and first " +
			"element, or this test does not isolate the elements past [0]")
	}
	if a["B.all"] == b["B.all"] {
		t.Fatalf("[]byte{7,1,2} and []byte{7,9,2} produced the same B.all key %q — every "+
			"element past the first is invisible", a["B.all"])
	}
	// nil and empty are different states and both must be visible.
	nilCols := collectAxisColumns6812(t, probe{})
	emptyCols := collectAxisColumns6812(t, probe{B: []byte{}})
	if nilCols["B.nil"] == emptyCols["B.nil"] {
		t.Fatal("a nil slice and an empty slice produced the same key; a comparator can " +
			"distinguish them, so the sweep must too")
	}
}

// TestCollectorSeesMapContents_6812 is the reviewer's concrete counterexample:
// three one-entry maps keyed {N:2}, {N:0}, {N:1} used to emit only `M.len=1`,
// so a comparator keying on the sole key reordered them while the sweep stayed
// green.
func TestCollectorSeesMapContents_6812(t *testing.T) {
	type key struct{ N int }
	type probe struct{ M map[key]string }
	seen := map[string][]int{}
	for _, n := range []int{2, 0, 1} {
		cols := collectAxisColumns6812(t, probe{M: map[key]string{{N: n}: "v"}})
		if cols["M.len"] == "" {
			t.Fatal("no M.len column")
		}
		seen[cols["M.entries"]] = append(seen[cols["M.entries"]], n)
	}
	if len(seen) != 3 {
		t.Fatalf("three one-entry maps keyed {N:2}, {N:0}, {N:1} produced %d distinct "+
			"M.entries keys, want 3 — the map's CONTENTS are invisible and only its "+
			"length is swept: %v", len(seen), seen)
	}
	// An empty map still enumerates its key/value SCHEMA, so a field added to
	// the key type is caught the same way a nil pointee's is.
	empty := collectAxisColumns6812(t, probe{M: map[key]string{}})
	if _, ok := empty["M{key}.N"]; !ok {
		t.Fatalf("an EMPTY map emitted no key-schema column (got %v)", keysOf6812(empty))
	}
}

// TestCollectorDeclaresANilInterface_6812: a nil interface genuinely cannot be
// enumerated — the dynamic type is not knowable from the static one. That is a
// fine answer, but it has to be DECLARED so the registry forces someone to
// justify it, not silently skipped.
func TestCollectorDeclaresANilInterface_6812(t *testing.T) {
	type probe struct{ I any }
	cols := collectAxisColumns6812(t, probe{})
	if _, ok := cols["I.dynamic-UNENCODED"]; !ok {
		t.Fatalf("a nil interface emitted no UNENCODED declaration (got %v); an "+
			"unenumerable payload must announce itself rather than pass as covered",
			keysOf6812(cols))
	}
	live := collectAxisColumns6812(t, probe{I: 7})
	if _, ok := live["I.dynamic-type"]; !ok {
		t.Fatalf("a populated interface emitted no dynamic-type column (got %v); a change "+
			"of concrete type is itself an axis", keysOf6812(live))
	}
}

// TestCollectorOrdersTimeChronologically_6812: walking time.Time as a plain
// struct yields wall/ext/loc columns whose lexicographic order is not
// chronological — a column that looks swept but cannot see the ordering a
// comparator would actually use.
func TestCollectorOrdersTimeChronologically_6812(t *testing.T) {
	type probe struct{ T time.Time }
	early := collectAxisColumns6812(t, probe{T: time.Unix(1000, 0).UTC()})
	late := collectAxisColumns6812(t, probe{T: time.Unix(2000, 0).UTC()})
	if len(early) != 1 || len(late) != 1 {
		t.Fatalf("time.Time produced %v columns, want exactly one ordered column",
			keysOf6812(early))
	}
	if !(early["T"] < late["T"]) {
		t.Fatalf("time ordering is not chronological: %q !< %q", early["T"], late["T"])
	}
}

func keysOf6812(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
