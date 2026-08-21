package userspace

import (
	"reflect"
	"strings"
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

// TestCollectorEnumeratesAPopulatedMapsSchema_6812 is the round-13 half of the
// test above, and the reason it exists is that the test above is the shape of
// blindness this collector keeps reproducing: it asked about the EMPTY map,
// which was the case round 11 repaired, and never about the POPULATED one.
//
// A populated map used to return before emitting `{key}` / `{value}`, so a
// field added to a populated map's value type produced NO column — the SILENTLY
// SKIPPED outcome the file header claims round 11 removed, surviving in the one
// shape nobody probed. Latent: no map is swept by a NAT fixture today.
//
// Two properties, and the second is the one the round-12 "closure at FIELD
// granularity, by construction" sentence actually needs:
//
//  1. the column SET is a function of the TYPE, not of the value. Otherwise a
//     fixture mixing an empty and a populated map of one type emits the schema
//     columns for the empty slot only, the sweep back-fills the missing slot
//     with "", and the resulting column VARIES across slots — reading as
//     guarded when nothing was compared;
//  2. adding a field to the value type of a POPULATED map produces a new
//     column, exactly as it does for a slice.
func TestCollectorEnumeratesAPopulatedMapsSchema_6812(t *testing.T) {
	type key struct{ N int }
	type val struct{ A string }
	type probe struct{ M map[key]val }

	empty := collectAxisColumns6812(t, probe{M: map[key]val{}})
	full := collectAxisColumns6812(t, probe{M: map[key]val{{N: 1}: {A: "x"}}})

	for _, want := range []string{"M{key}.N", "M{value}.A"} {
		if _, ok := full[want]; !ok {
			t.Fatalf("a POPULATED map emitted no %q column (got %v). A field added to the "+
				"value type of a populated map would then change nothing at all — silently "+
				"skipped, which is the outcome this collector claims not to have.",
				want, keysOf6812(full))
		}
	}
	if len(empty) != len(full) {
		t.Fatalf("the map column SET depends on the VALUE, not the type: empty map emits "+
			"%d columns %v, populated map emits %d %v. A fixture holding both then "+
			"manufactures a column that varies across slots without anything being "+
			"compared.", len(empty), keysOf6812(empty), len(full), keysOf6812(full))
	}
	for c := range empty {
		if _, ok := full[c]; !ok {
			t.Fatalf("column %q exists for an empty map and not for a populated one", c)
		}
	}
	// The schema keys stay ABSENT even when populated: a map has no canonical
	// first entry to project, unlike a slice's [0]. Content coverage is
	// `.entries`, which is total.
	if got := full["M{value}.A"]; got != axisAbsentKey6812 {
		t.Fatalf("populated map value-schema key = %q, want the absent marker %q — "+
			"projecting SOME entry would depend on map iteration order", got, axisAbsentKey6812)
	}

	// (2), measured rather than argued: widening the value type adds a column.
	type valWide struct {
		A string
		B string
	}
	type probeWide struct{ M map[key]valWide }
	wide := collectAxisColumns6812(t, probeWide{M: map[key]valWide{{N: 1}: {A: "x"}}})
	if _, ok := wide["M{value}.B"]; !ok {
		t.Fatalf("adding field B to a POPULATED map's value type produced no M{value}.B "+
			"column (got %v)", keysOf6812(wide))
	}
	if len(wide) != len(full)+1 {
		t.Fatalf("widening the value type by one field changed the column count by %d, "+
			"want 1: %v -> %v", len(wide)-len(full), keysOf6812(full), keysOf6812(wide))
	}
}

// TestAxisEncodingIsInjective_6812 measures the property `.all` and `.entries`
// are SOLD on: that they are total over contents, so no difference in a
// sequence can be invisible to a caller that embeds them.
//
// It was false until round 13. axisEncodeValue6812 joined columns as
// `name=key\x1e` with the key written RAW, so a string field carrying the
// record separator plus a forged `NAME=\x01` boundary re-partitioned the
// record. The counterexample below is the reviewer's, verbatim: two DIFFERENT
// one-element slices whose `.all` keys were byte-identical.
//
// SCOPE, because it is the difference between a live bug and a latent one:
// single-column element types ([]string, []byte) were already injective — one
// column, length-prefixed by axisEncodeSeq6812 — and the only multi-column
// swept slice elements are fixture-constant, so no NAT config reaches this
// today. The claim was still false as written, and a claim that holds only
// because today's fixtures do not reach it is the shape this collector has
// been caught on repeatedly.
func TestAxisEncodingIsInjective_6812(t *testing.T) {
	type elem struct{ A, B string }
	type probe struct{ S []elem }

	// Forged so that, unescaped, the two flatten to the same byte string:
	//   A=\x01x\x1eB=\x01y\x1e  +  B=\x01z\x1e
	//   A=\x01x\x1e             +  B=\x01y\x1eB=\x01z\x1e
	left := collectAxisColumns6812(t, probe{S: []elem{{A: "x\x1eB=\x01y", B: "z"}}})
	right := collectAxisColumns6812(t, probe{S: []elem{{A: "x", B: "y\x1eB=\x01z"}}})
	if left["S[0].A"] == right["S[0].A"] {
		t.Fatal("probe is malformed: the two elements must actually differ")
	}
	if left["S.all"] == right["S.all"] {
		t.Fatalf("two DIFFERENT slices produced the same S.all key %q. `.all` is not "+
			"injective, so a change to the slice can be invisible to any column that "+
			"embeds it — which is the whole reason `.all` exists.", left["S.all"])
	}

	// The same forgery through a map entry: the \x1f between an entry's key and
	// value encoding is only unambiguous while neither side can contain one.
	type mprobe struct{ M map[elem]elem }
	ml := collectAxisColumns6812(t, mprobe{M: map[elem]elem{{A: "p\x1fq"}: {A: "r"}}})
	mr := collectAxisColumns6812(t, mprobe{M: map[elem]elem{{A: "p"}: {A: "q\x1fr"}}})
	if ml["M.entries"] == mr["M.entries"] {
		t.Fatalf("two DIFFERENT maps produced the same M.entries key %q — the unit "+
			"separator inside an entry is ambiguous", ml["M.entries"])
	}

	// The escape must be reversible in principle, i.e. it must not itself
	// collide: a literal escape byte and an escaped separator are different.
	esc := collectAxisColumns6812(t, probe{S: []elem{{A: "\x1c" + "R"}}})
	sep := collectAxisColumns6812(t, probe{S: []elem{{A: "\x1e"}}})
	if esc["S.all"] == sep["S.all"] {
		t.Fatalf("a literal %q and an escaped separator encode identically (%q) — the "+
			"escape byte is not itself escaped, so decoding is ambiguous",
			"\x1cR", esc["S.all"])
	}

	// A value with no structural byte must be untouched, so the escape cannot
	// churn keys for the ordinary case.
	plain := collectAxisColumns6812(t, probe{S: []elem{{A: "plain", B: "value"}}})
	if got, want := plain["S[0].A"], axisPresentTag6812+"plain"; got != want {
		t.Fatalf("leaf key = %q, want %q — leaf columns are compared whole, never joined, "+
			"so they must not be escaped", got, want)
	}
	if !strings.Contains(plain["S.all"], "plain") {
		t.Fatalf("S.all = %q does not contain the unescaped ordinary value", plain["S.all"])
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
