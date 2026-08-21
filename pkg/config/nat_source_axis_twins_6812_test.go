package config

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// axisTwinGolden6812 is the ONE artifact both packages compare against.
const axisTwinGolden6812 = "testdata/axis_collector_twins_6812.golden"

// #6812 round 11: the TWINS' AGREEMENT.
//
// collectAxisKeys6812 is duplicated across pkg/config and
// pkg/dataplane/userspace — a Go test helper cannot be shared across packages
// without exporting it from production, and paying production API surface for
// test convenience is the wrong trade. The risk that buys is drift: two copies
// of one switch that quietly stop matching.
//
// The property needed is not ONE COPY, it is THE TWO COPIES DO NOT DISAGREE.
// This file binds that directly. axisTwinProbe6812 is defined identically in
// both packages and exercises every kind the collector handles — including the
// four forms round 11 repaired. Each package fingerprints its collector's
// output over that probe and compares to ONE checked-in golden, so a change to
// either copy alone reds, naming the column that differs.
//
// A deliberate divergence is still allowed. It just has to be declared here, by
// regenerating the golden with a reason, instead of appearing silently.

type axisTwinNested6812 struct {
	Label string
	Count uint16
}

type axisTwinProbe6812 struct {
	Str        string
	Bool       bool
	Int        int
	Uint       uint32
	Nested     axisTwinNested6812
	PtrNil     *axisTwinNested6812
	PtrLive    *axisTwinNested6812
	IfaceNil   any
	IfaceLive  any
	SliceNil   []string
	SliceEmpty []string
	SliceFull  []axisTwinNested6812
	Bytes      []byte
	Arr        [2]uint8
	MapNil     map[axisTwinNested6812]string
	MapEmpty   map[axisTwinNested6812]string
	MapFull    map[axisTwinNested6812]string
	// SliceSep carries the RECORD SEPARATOR inside a multi-column element,
	// so the golden binds axisEscapeKey6812 across the two copies too
	// (#6812 round 13). Without it the behavioural half of the twins
	// agreement is blind to an escaping divergence — the probe reaches no
	// value carrying a structural byte, and a probe-bounded test cannot see
	// what the probe does not reach.
	SliceSep []axisTwinNested6812
	When     time.Time
}

// axisTwinProbeValue6812 must be byte-identical in both packages: the golden is
// a function of this value AND of the collector, so a difference in either side
// has to be visible as a difference in the fingerprint.
func axisTwinProbeValue6812() axisTwinProbe6812 {
	return axisTwinProbe6812{
		Str:        "s",
		Bool:       true,
		Int:        -3,
		Uint:       9,
		Nested:     axisTwinNested6812{Label: "n", Count: 1},
		PtrLive:    &axisTwinNested6812{Label: "p", Count: 2},
		IfaceLive:  int64(7),
		SliceEmpty: []string{},
		SliceFull:  []axisTwinNested6812{{Label: "a", Count: 3}, {Label: "b", Count: 4}},
		Bytes:      []byte{1, 2, 3},
		Arr:        [2]uint8{5, 6},
		MapEmpty:   map[axisTwinNested6812]string{},
		MapFull: map[axisTwinNested6812]string{
			{Label: "k1", Count: 1}: "v1",
			{Label: "k2", Count: 2}: "v2",
		},
		SliceSep: []axisTwinNested6812{{Label: "x\x1eB=\x01y", Count: 8}},
		When:     time.Unix(1700000000, 0).UTC(),
	}
}

// axisTwinFingerprint6812 renders the collector's whole output as one canonical
// text: every column, sorted, with its key escaped so the present/absent tags
// survive a diff.
func axisTwinFingerprint6812(t *testing.T) string {
	t.Helper()
	cols := map[string]string{}
	collectAxisKeys6812(t, "", reflect.ValueOf(axisTwinProbeValue6812()), true, 0,
		func(col, key string) {
			if _, dup := cols[col]; dup {
				t.Fatalf("column %q emitted twice", col)
			}
			cols[col] = key
		})
	names := make([]string, 0, len(cols))
	for c := range cols {
		names = append(names, c)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, c := range names {
		fmt.Fprintf(&b, "%s\t%q\n", c, cols[c])
	}
	return b.String()
}

func TestAxisCollectorTwinsAgree_6812(t *testing.T) {
	got := axisTwinFingerprint6812(t)
	want, err := os.ReadFile(axisTwinGolden6812)
	if err != nil {
		t.Fatalf("reading the twin-agreement golden: %v\n\nThis package's collector "+
			"produced:\n%s", err, got)
	}
	if got == string(want) {
		return
	}
	gotLines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	wantLines := strings.Split(strings.TrimRight(string(want), "\n"), "\n")
	inGot := map[string]bool{}
	for _, l := range gotLines {
		inGot[l] = true
	}
	inWant := map[string]bool{}
	for _, l := range wantLines {
		inWant[l] = true
	}
	var onlyHere, onlyGolden []string
	for _, l := range gotLines {
		if !inWant[l] {
			onlyHere = append(onlyHere, l)
		}
	}
	for _, l := range wantLines {
		if !inGot[l] {
			onlyGolden = append(onlyGolden, l)
		}
	}
	t.Fatalf("this package's collector DISAGREES with the twin-agreement golden — the "+
		"two copies of collectAxisKeys6812 have drifted.\nONLY HERE (%d):\n%s\nONLY IN THE "+
		"GOLDEN (%d):\n%s\nIf the divergence is deliberate, say so: change BOTH copies and "+
		"regenerate %s with the reason in the commit message.",
		len(onlyHere), strings.Join(onlyHere, "\n"), len(onlyGolden),
		strings.Join(onlyGolden, "\n"), axisTwinGolden6812)
}

// TestAxisCollectorTwinsAreTextuallyIdentical_6812 is the second half of the
// agreement, and it catches what the probe cannot: a divergence on a path the
// probe does not reach. The behavioural test above is only as good as
// axisTwinProbe6812's coverage; this one is indifferent to coverage because it
// compares the marked region byte for byte.
//
// Only the package clause may differ, and that is not inside the region.
func TestAxisCollectorTwinsAreTextuallyIdentical_6812(t *testing.T) {
	const (
		begin = "// BEGIN SHARED COLLECTOR (#6812 round 11)."
		end   = "// END SHARED COLLECTOR (#6812 round 11)."
	)
	region := func(path string) string {
		t.Helper()
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		s := string(src)
		i := strings.Index(s, begin)
		j := strings.Index(s, end)
		if i < 0 || j < 0 || j <= i {
			t.Fatalf("%s carries no BEGIN/END SHARED COLLECTOR markers (begin=%d end=%d). "+
				"The markers are what makes the twins comparable; do not remove them.",
				path, i, j)
		}
		return s[i : j+len(end)]
	}
	a := region("nat_source_axis_sweep_6812_test.go")
	b := region("../dataplane/userspace/nat_source_axis_sweep_6812_test.go")
	if a == b {
		return
	}
	al := strings.Split(a, "\n")
	bl := strings.Split(b, "\n")
	for i := 0; i < len(al) && i < len(bl); i++ {
		if al[i] != bl[i] {
			t.Fatalf("the two copies of the shared collector differ at region line %d:\n"+
				"  pkg/config:              %q\n  pkg/dataplane/userspace: %q\n"+
				"Splice the block rather than hand-editing one side. If the divergence is "+
				"deliberate, move the differing code OUT of the marked region and say why.",
				i+1, al[i], bl[i])
		}
	}
	t.Fatalf("the two copies of the shared collector have different lengths: pkg/config %d "+
		"lines, pkg/dataplane/userspace %d lines", len(al), len(bl))
}
